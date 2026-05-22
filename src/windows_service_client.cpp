#include "windows_service_client.h"

#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>

#include <string>

#include "service_constants.h"

extern "C" {
#include "infoguard_service_rpc.h"
}

handle_t InfoGuardServiceRpcBinding = nullptr;

namespace {

std::wstring GetLastErrorMessage(const DWORD error_code) {
    LPWSTR buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    if (length == 0 || buffer == nullptr) {
        return L"Win32 error " + std::to_wstring(error_code);
    }

    std::wstring result(buffer, length);
    LocalFree(buffer);

    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
        result.pop_back();
    }

    return result;
}

class ScopedServiceHandle {
public:
    explicit ScopedServiceHandle(SC_HANDLE handle = nullptr) : handle_(handle) {
    }

    ~ScopedServiceHandle() {
        if (handle_ != nullptr) {
            CloseServiceHandle(handle_);
        }
    }

    ScopedServiceHandle(const ScopedServiceHandle&) = delete;
    ScopedServiceHandle& operator=(const ScopedServiceHandle&) = delete;

    SC_HANDLE get() const {
        return handle_;
    }

private:
    SC_HANDLE handle_;
};

class ScopedRpcString {
public:
    explicit ScopedRpcString(RPC_WSTR value = nullptr) : value_(value) {
    }

    ~ScopedRpcString() {
        if (value_ != nullptr) {
            RpcStringFreeW(&value_);
        }
    }

    RPC_WSTR* put() {
        return &value_;
    }

    RPC_WSTR get() const {
        return value_;
    }

private:
    RPC_WSTR value_;
};

class ScopedRpcBinding {
public:
    ~ScopedRpcBinding() {
        if (InfoGuardServiceRpcBinding != nullptr) {
            RpcBindingFree(&InfoGuardServiceRpcBinding);
            InfoGuardServiceRpcBinding = nullptr;
        }
    }
};

bool QueryServiceStatusState(
    SC_HANDLE service,
    DWORD* current_state,
    std::wstring* error_message) {
    SERVICE_STATUS_PROCESS status = {};
    DWORD bytes_needed = 0;
    if (QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytes_needed) == FALSE) {
        if (error_message != nullptr) {
            *error_message = L"QueryServiceStatusEx failed: " + GetLastErrorMessage(GetLastError());
        }
        return false;
    }

    *current_state = status.dwCurrentState;
    return true;
}

bool QueryServiceProcessId(SC_HANDLE service, DWORD* process_id, std::wstring* error_message) {
    SERVICE_STATUS_PROCESS status = {};
    DWORD bytes_needed = 0;
    if (QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytes_needed) == FALSE) {
        if (error_message != nullptr) {
            *error_message = L"QueryServiceStatusEx failed: " + GetLastErrorMessage(GetLastError());
        }
        return false;
    }

    *process_id = status.dwProcessId;
    return true;
}

bool GetParentProcessId(DWORD* parent_process_id, std::wstring* error_message) {
    const DWORD current_process_id = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        if (error_message != nullptr) {
            *error_message = L"CreateToolhelp32Snapshot failed: " + GetLastErrorMessage(GetLastError());
        }
        return false;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    bool found = false;
    if (Process32FirstW(snapshot, &entry) != FALSE) {
        do {
            if (entry.th32ProcessID == current_process_id) {
                *parent_process_id = entry.th32ParentProcessID;
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry) != FALSE);
    }

    CloseHandle(snapshot);

    if (!found || *parent_process_id == 0) {
        if (error_message != nullptr) {
            *error_message = L"Unable to determine the parent process.";
        }
        return false;
    }

    return true;
}

bool CreateRpcBinding(std::wstring* error_message) {
    ScopedRpcString binding_string;

    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(service_constants::kRpcProtocolSequence)),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(service_constants::kRpcEndpoint)),
        nullptr,
        binding_string.put());
    if (status != RPC_S_OK) {
        *error_message = L"RpcStringBindingComposeW failed with status " + std::to_wstring(status) + L".";
        return false;
    }

    status = RpcBindingFromStringBindingW(binding_string.get(), &InfoGuardServiceRpcBinding);
    if (status != RPC_S_OK) {
        *error_message = L"RpcBindingFromStringBindingW failed with status " + std::to_wstring(status) + L".";
        return false;
    }

    return true;
}

void FreeRpcString(wchar_t** value) {
    if (value != nullptr && *value != nullptr) {
        midl_user_free(*value);
        *value = nullptr;
    }
}

void FreeRpcUserInfo(InfoGuardRpcUserInfo* user_info) {
    if (user_info == nullptr) {
        return;
    }

    FreeRpcString(&user_info->username);
    FreeRpcString(&user_info->fullName);
    FreeRpcString(&user_info->role);
}

void FreeRpcLicenseInfo(InfoGuardRpcLicenseInfo* license_info) {
    if (license_info == nullptr) {
        return;
    }

    FreeRpcString(&license_info->deviceId);
    FreeRpcString(&license_info->activatedAt);
    FreeRpcString(&license_info->expiresAt);
}

RpcCallStatus MapRpcStatus(const DWORD status) {
    switch (status) {
    case ERROR_SUCCESS:
        return RpcCallStatus::Success;
    case ERROR_NOT_FOUND:
        return RpcCallStatus::NotFound;
    case ERROR_ACCESS_DENIED:
    case ERROR_LOGON_FAILURE:
        return RpcCallStatus::AccessDenied;
    case RPC_S_CALL_FAILED:
    case RPC_S_SERVER_UNAVAILABLE:
        return RpcCallStatus::Unavailable;
    default:
        return RpcCallStatus::Failed;
    }
}

DWORD CallStopServiceRpc() {
    DWORD exception_code = RPC_S_OK;

    RpcTryExcept {
        InfoGuardRpcStopService();
    }
    RpcExcept(1) {
        exception_code = RPC_S_CALL_FAILED;
    }
    RpcEndExcept

    return exception_code;
}

DWORD CallGetCurrentUserRpc(InfoGuardRpcUserInfo* user_info, wchar_t** error_message) {
    DWORD exception_code = RPC_S_OK;
    long status = ERROR_GEN_FAILURE;

    RpcTryExcept {
        status = InfoGuardRpcGetCurrentUser(user_info, error_message);
    }
    RpcExcept(1) {
        exception_code = RPC_S_CALL_FAILED;
    }
    RpcEndExcept

    return exception_code == RPC_S_OK ? static_cast<DWORD>(status) : exception_code;
}

DWORD CallLoginRpc(
    wchar_t* username,
    wchar_t* password,
    InfoGuardRpcUserInfo* user_info,
    wchar_t** error_message) {
    DWORD exception_code = RPC_S_OK;
    long status = ERROR_GEN_FAILURE;

    RpcTryExcept {
        status = InfoGuardRpcLogin(username, password, user_info, error_message);
    }
    RpcExcept(1) {
        exception_code = RPC_S_CALL_FAILED;
    }
    RpcEndExcept

    return exception_code == RPC_S_OK ? static_cast<DWORD>(status) : exception_code;
}

DWORD CallLogoutRpc(wchar_t** error_message) {
    DWORD exception_code = RPC_S_OK;
    long status = ERROR_GEN_FAILURE;

    RpcTryExcept {
        status = InfoGuardRpcLogout(error_message);
    }
    RpcExcept(1) {
        exception_code = RPC_S_CALL_FAILED;
    }
    RpcEndExcept

    return exception_code == RPC_S_OK ? static_cast<DWORD>(status) : exception_code;
}

DWORD CallGetActiveLicenseRpc(InfoGuardRpcLicenseInfo* license_info, wchar_t** error_message) {
    DWORD exception_code = RPC_S_OK;
    long status = ERROR_GEN_FAILURE;

    RpcTryExcept {
        status = InfoGuardRpcGetActiveLicense(license_info, error_message);
    }
    RpcExcept(1) {
        exception_code = RPC_S_CALL_FAILED;
    }
    RpcEndExcept

    return exception_code == RPC_S_OK ? static_cast<DWORD>(status) : exception_code;
}

DWORD CallActivateProductRpc(
    wchar_t* activation_code,
    InfoGuardRpcLicenseInfo* license_info,
    wchar_t** error_message) {
    DWORD exception_code = RPC_S_OK;
    long status = ERROR_GEN_FAILURE;

    RpcTryExcept {
        status = InfoGuardRpcActivateProduct(activation_code, license_info, error_message);
    }
    RpcExcept(1) {
        exception_code = RPC_S_CALL_FAILED;
    }
    RpcEndExcept

    return exception_code == RPC_S_OK ? static_cast<DWORD>(status) : exception_code;
}

std::wstring TakeRpcMessage(wchar_t** rpc_message) {
    std::wstring result;
    if (rpc_message != nullptr && *rpc_message != nullptr) {
        result = *rpc_message;
        FreeRpcString(rpc_message);
    }
    return result;
}

void CopyUserInfo(const InfoGuardRpcUserInfo& rpc_user, AuthenticatedUserInfo* user) {
    user->user_id = static_cast<unsigned long long>(rpc_user.userId);
    user->username = rpc_user.username == nullptr ? L"" : rpc_user.username;
    user->full_name = rpc_user.fullName == nullptr ? L"" : rpc_user.fullName;
    user->role = rpc_user.role == nullptr ? L"" : rpc_user.role;
}

void CopyLicenseInfo(const InfoGuardRpcLicenseInfo& rpc_license, ActiveLicenseInfo* license) {
    license->blocked = rpc_license.blocked != FALSE;
    license->device_id = rpc_license.deviceId == nullptr ? L"" : rpc_license.deviceId;
    license->activated_at = rpc_license.activatedAt == nullptr ? L"" : rpc_license.activatedAt;
    license->expires_at = rpc_license.expiresAt == nullptr ? L"" : rpc_license.expiresAt;
}

}  // namespace

WindowsServiceClient::ServiceState WindowsServiceClient::QueryServiceState(std::wstring* error_message) const {
    ScopedServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.get() == nullptr) {
        if (error_message != nullptr) {
            *error_message = L"OpenSCManager failed: " + GetLastErrorMessage(GetLastError());
        }
        return ServiceState::Missing;
    }

    ScopedServiceHandle service(OpenServiceW(scm.get(), service_constants::kServiceName, SERVICE_QUERY_STATUS));
    if (service.get() == nullptr) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            if (error_message != nullptr) {
                *error_message = L"The Windows service is not installed.";
            }
            return ServiceState::Missing;
        }

        if (error_message != nullptr) {
            *error_message = L"OpenService failed: " + GetLastErrorMessage(GetLastError());
        }
        return ServiceState::Other;
    }

    DWORD state = 0;
    if (!QueryServiceStatusState(service.get(), &state, error_message)) {
        return ServiceState::Other;
    }

    switch (state) {
    case SERVICE_STOPPED:
        return ServiceState::Stopped;
    case SERVICE_START_PENDING:
        return ServiceState::StartPending;
    case SERVICE_RUNNING:
        return ServiceState::Running;
    case SERVICE_STOP_PENDING:
        return ServiceState::StopPending;
    default:
        return ServiceState::Other;
    }
}

bool WindowsServiceClient::WaitUntilRunning(const unsigned long timeout_ms, std::wstring* error_message) const {
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;

    for (;;) {
        const ServiceState state = QueryServiceState(error_message);
        if (state == ServiceState::Running) {
            return true;
        }

        if (state == ServiceState::Stopped || state == ServiceState::Missing) {
            if (error_message != nullptr && error_message->empty()) {
                *error_message = L"Service stopped before reaching the running state.";
            }
            return false;
        }

        if (GetTickCount64() >= deadline) {
            if (error_message != nullptr) {
                *error_message = L"Timed out while waiting for the Windows service to reach the running state.";
            }
            return false;
        }

        Sleep(250);
    }
}

bool WindowsServiceClient::StartServiceAndWait(std::wstring* error_message) const {
    ScopedServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.get() == nullptr) {
        *error_message = L"OpenSCManager failed: " + GetLastErrorMessage(GetLastError());
        return false;
    }

    ScopedServiceHandle service(OpenServiceW(
        scm.get(),
        service_constants::kServiceName,
        SERVICE_START | SERVICE_QUERY_STATUS));
    if (service.get() == nullptr) {
        *error_message = L"OpenService failed: " + GetLastErrorMessage(GetLastError());
        return false;
    }

    if (StartServiceW(service.get(), 0, nullptr) == FALSE) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            *error_message = L"StartService failed: " + GetLastErrorMessage(error);
            return false;
        }
    }

    return WaitUntilRunning(15000, error_message);
}

bool WindowsServiceClient::IsParentServiceProcess(std::wstring* error_message) const {
    DWORD parent_process_id = 0;
    if (!GetParentProcessId(&parent_process_id, error_message)) {
        return false;
    }

    ScopedServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (scm.get() == nullptr) {
        if (error_message != nullptr) {
            *error_message = L"OpenSCManager failed: " + GetLastErrorMessage(GetLastError());
        }
        return false;
    }

    ScopedServiceHandle service(OpenServiceW(scm.get(), service_constants::kServiceName, SERVICE_QUERY_STATUS));
    if (service.get() == nullptr) {
        if (error_message != nullptr) {
            *error_message = L"OpenService failed: " + GetLastErrorMessage(GetLastError());
        }
        return false;
    }

    DWORD service_process_id = 0;
    if (!QueryServiceProcessId(service.get(), &service_process_id, error_message)) {
        return false;
    }

    if (service_process_id == 0) {
        if (error_message != nullptr) {
            *error_message = L"The Windows service does not have an active process ID.";
        }
        return false;
    }

    return parent_process_id == service_process_id;
}

WindowsServiceClient::StartupDecision WindowsServiceClient::PrepareForGuiLaunch(std::wstring* error_message) const {
    const ServiceState state = QueryServiceState(error_message);

    if (state == ServiceState::Missing) {
        if (error_message != nullptr && error_message->empty()) {
            *error_message = L"The Windows service is not installed.";
        }
        return StartupDecision::ExitWithError;
    }

    if (state == ServiceState::Stopped) {
        if (!StartServiceAndWait(error_message)) {
            return StartupDecision::ExitWithError;
        }
        return StartupDecision::ExitAfterServiceStart;
    }

    if (state == ServiceState::StartPending) {
        if (!WaitUntilRunning(15000, error_message)) {
            return StartupDecision::ExitWithError;
        }
        return StartupDecision::ExitAfterServiceStart;
    }

    if (state != ServiceState::Running) {
        if (error_message != nullptr && error_message->empty()) {
            *error_message = L"The Windows service is not in a usable state.";
        }
        return StartupDecision::ExitWithError;
    }

    if (!IsParentServiceProcess(error_message)) {
        return StartupDecision::ExitBecauseParentMismatch;
    }

    return StartupDecision::ContinueLaunch;
}

bool WindowsServiceClient::RequestServiceStop(std::wstring* error_message) const {
    ScopedRpcBinding rpc_binding;
    if (!CreateRpcBinding(error_message)) {
        return false;
    }

    const DWORD rpc_result = CallStopServiceRpc();
    if (rpc_result != RPC_S_OK) {
        *error_message = L"RPC stop request failed with code " + std::to_wstring(rpc_result) + L".";
        return false;
    }

    return true;
}

UserQueryResult WindowsServiceClient::GetCurrentUser() const {
    UserQueryResult result;
    ScopedRpcBinding rpc_binding;
    if (!CreateRpcBinding(&result.message)) {
        result.status = RpcCallStatus::Unavailable;
        return result;
    }

    InfoGuardRpcUserInfo rpc_user = {};
    wchar_t* rpc_message = nullptr;
    const DWORD status = CallGetCurrentUserRpc(&rpc_user, &rpc_message);

    result.status = MapRpcStatus(status);
    result.message = TakeRpcMessage(&rpc_message);
    if (status == ERROR_SUCCESS) {
        CopyUserInfo(rpc_user, &result.user);
    }

    FreeRpcUserInfo(&rpc_user);
    return result;
}

UserQueryResult WindowsServiceClient::Login(const std::wstring& username, const std::wstring& password) const {
    UserQueryResult result;
    ScopedRpcBinding rpc_binding;
    if (!CreateRpcBinding(&result.message)) {
        result.status = RpcCallStatus::Unavailable;
        return result;
    }

    InfoGuardRpcUserInfo rpc_user = {};
    wchar_t* rpc_message = nullptr;
    std::wstring mutable_username = username;
    std::wstring mutable_password = password;
    const DWORD status = CallLoginRpc(
        mutable_username.data(),
        mutable_password.data(),
        &rpc_user,
        &rpc_message);

    result.status = MapRpcStatus(status);
    result.message = TakeRpcMessage(&rpc_message);
    if (status == ERROR_SUCCESS) {
        CopyUserInfo(rpc_user, &result.user);
    }

    FreeRpcUserInfo(&rpc_user);
    return result;
}

RpcCallStatus WindowsServiceClient::Logout(std::wstring* error_message) const {
    ScopedRpcBinding rpc_binding;
    if (!CreateRpcBinding(error_message)) {
        return RpcCallStatus::Unavailable;
    }

    wchar_t* rpc_message = nullptr;
    const DWORD status = CallLogoutRpc(&rpc_message);
    *error_message = TakeRpcMessage(&rpc_message);
    return MapRpcStatus(status);
}

LicenseQueryResult WindowsServiceClient::GetActiveLicense() const {
    LicenseQueryResult result;
    ScopedRpcBinding rpc_binding;
    if (!CreateRpcBinding(&result.message)) {
        result.status = RpcCallStatus::Unavailable;
        return result;
    }

    InfoGuardRpcLicenseInfo rpc_license = {};
    wchar_t* rpc_message = nullptr;
    const DWORD status = CallGetActiveLicenseRpc(&rpc_license, &rpc_message);

    result.status = MapRpcStatus(status);
    result.message = TakeRpcMessage(&rpc_message);
    if (status == ERROR_SUCCESS) {
        CopyLicenseInfo(rpc_license, &result.license);
    }

    FreeRpcLicenseInfo(&rpc_license);
    return result;
}

LicenseQueryResult WindowsServiceClient::ActivateProduct(const std::wstring& activation_code) const {
    LicenseQueryResult result;
    ScopedRpcBinding rpc_binding;
    if (!CreateRpcBinding(&result.message)) {
        result.status = RpcCallStatus::Unavailable;
        return result;
    }

    InfoGuardRpcLicenseInfo rpc_license = {};
    wchar_t* rpc_message = nullptr;
    std::wstring mutable_code = activation_code;
    const DWORD status = CallActivateProductRpc(mutable_code.data(), &rpc_license, &rpc_message);

    result.status = MapRpcStatus(status);
    result.message = TakeRpcMessage(&rpc_message);
    if (status == ERROR_SUCCESS) {
        CopyLicenseInfo(rpc_license, &result.license);
    }

    FreeRpcLicenseInfo(&rpc_license);
    return result;
}
