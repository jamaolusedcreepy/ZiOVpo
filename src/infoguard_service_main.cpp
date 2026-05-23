#include <windows.h>
#include <winsvc.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <aclapi.h>

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "service_session_manager.h"
#include "service_constants.h"

extern "C" {
#include "infoguard_service_rpc.h"
}

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Wtsapi32.lib")

namespace {

struct ChildProcessInfo {
    HANDLE process_handle = nullptr;
    DWORD process_id = 0;
};

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

std::wstring GetModulePath() {
    std::wstring buffer(MAX_PATH, L'\0');

    for (;;) {
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            return {};
        }

        if (length < buffer.size() - 1) {
            buffer.resize(length);
            return buffer;
        }

        buffer.resize(buffer.size() * 2);
    }
}

std::wstring GetDirectoryName(const std::wstring& path) {
    const std::wstring::size_type position = path.find_last_of(L"\\/");
    return position == std::wstring::npos ? L"." : path.substr(0, position);
}

std::wstring QuoteArgument(const std::wstring& argument) {
    return L"\"" + argument + L"\"";
}

wchar_t* DuplicateRpcString(const std::wstring& value) {
    const std::size_t bytes = (value.size() + 1) * sizeof(wchar_t);
    auto* copy = static_cast<wchar_t*>(midl_user_allocate(bytes));
    if (copy == nullptr) {
        return nullptr;
    }

    memcpy(copy, value.c_str(), bytes);
    return copy;
}

void ResetRpcUserInfo(InfoGuardRpcUserInfo* user_info) {
    if (user_info == nullptr) {
        return;
    }

    user_info->userId = 0;
    user_info->username = nullptr;
    user_info->fullName = nullptr;
    user_info->role = nullptr;
}

void ResetRpcLicenseInfo(InfoGuardRpcLicenseInfo* license_info) {
    if (license_info == nullptr) {
        return;
    }

    license_info->blocked = FALSE;
    license_info->deviceId = nullptr;
    license_info->activatedAt = nullptr;
    license_info->expiresAt = nullptr;
}

void ResetRpcAvBasesInfo(InfoGuardRpcAvBasesInfo* bases_info) {
    if (bases_info == nullptr) {
        return;
    }

    bases_info->loaded = FALSE;
    bases_info->releaseDate = nullptr;
    bases_info->recordCount = 0;
}

void ResetRpcScanResult(InfoGuardRpcScanResult* scan_result) {
    if (scan_result == nullptr) {
        return;
    }

    scan_result->malicious = FALSE;
    scan_result->directoryScan = FALSE;
    scan_result->scannedObjectCount = 0;
    scan_result->infectedObjectCount = 0;
    scan_result->targetPath = nullptr;
    scan_result->detectedPath = nullptr;
    scan_result->detectedThreatName = nullptr;
    scan_result->objectType = nullptr;
    scan_result->summary = nullptr;
}

bool GrantInteractiveUsersStartAccess(SC_HANDLE service, std::wstring* error_message) {
    DWORD required_size = 0;
    QueryServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, nullptr, 0, &required_size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required_size == 0) {
        *error_message = L"QueryServiceObjectSecurity sizing failed: " + GetLastErrorMessage(GetLastError());
        return false;
    }

    std::vector<BYTE> security_descriptor_buffer(required_size);
    auto* security_descriptor =
        reinterpret_cast<PSECURITY_DESCRIPTOR>(security_descriptor_buffer.data());
    if (QueryServiceObjectSecurity(
            service,
            DACL_SECURITY_INFORMATION,
            security_descriptor,
            required_size,
            &required_size) == FALSE) {
        *error_message = L"QueryServiceObjectSecurity failed: " + GetLastErrorMessage(GetLastError());
        return false;
    }

    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    PACL existing_dacl = nullptr;
    if (GetSecurityDescriptorDacl(
            security_descriptor,
            &dacl_present,
            &existing_dacl,
            &dacl_defaulted) == FALSE) {
        *error_message = L"GetSecurityDescriptorDacl failed: " + GetLastErrorMessage(GetLastError());
        return false;
    }
    (void)dacl_defaulted;

    BYTE interactive_sid_buffer[SECURITY_MAX_SID_SIZE] = {};
    DWORD interactive_sid_size = sizeof(interactive_sid_buffer);
    if (CreateWellKnownSid(
            WinInteractiveSid,
            nullptr,
            interactive_sid_buffer,
            &interactive_sid_size) == FALSE) {
        *error_message = L"CreateWellKnownSid failed: " + GetLastErrorMessage(GetLastError());
        return false;
    }

    EXPLICIT_ACCESSW access = {};
    access.grfAccessPermissions = SERVICE_START | SERVICE_QUERY_STATUS | READ_CONTROL;
    access.grfAccessMode = GRANT_ACCESS;
    access.grfInheritance = NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(interactive_sid_buffer);

    PACL updated_dacl = nullptr;
    const DWORD acl_result = SetEntriesInAclW(
        1,
        &access,
        dacl_present ? existing_dacl : nullptr,
        &updated_dacl);
    if (acl_result != ERROR_SUCCESS) {
        *error_message = L"SetEntriesInAclW failed: " + GetLastErrorMessage(acl_result);
        return false;
    }

    SECURITY_DESCRIPTOR updated_security_descriptor = {};
    if (InitializeSecurityDescriptor(&updated_security_descriptor, SECURITY_DESCRIPTOR_REVISION) == FALSE) {
        LocalFree(updated_dacl);
        *error_message = L"InitializeSecurityDescriptor failed: " + GetLastErrorMessage(GetLastError());
        return false;
    }

    if (SetSecurityDescriptorDacl(&updated_security_descriptor, TRUE, updated_dacl, FALSE) == FALSE) {
        LocalFree(updated_dacl);
        *error_message = L"SetSecurityDescriptorDacl failed: " + GetLastErrorMessage(GetLastError());
        return false;
    }

    const BOOL result =
        SetServiceObjectSecurity(service, DACL_SECURITY_INFORMATION, &updated_security_descriptor);
    LocalFree(updated_dacl);

    if (result == FALSE) {
        *error_message = L"SetServiceObjectSecurity failed: " + GetLastErrorMessage(GetLastError());
        return false;
    }

    return true;
}

class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE handle = nullptr) : handle_(handle) {
    }

    ~ScopedHandle() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    HANDLE get() const {
        return handle_;
    }

    HANDLE* put() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
        handle_ = nullptr;
        return &handle_;
    }

    HANDLE release() {
        HANDLE handle = handle_;
        handle_ = nullptr;
        return handle;
    }

private:
    HANDLE handle_;
};

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

class ServiceHost {
public:
    static ServiceHost& Instance() {
        static ServiceHost instance;
        return instance;
    }

    static void WINAPI ServiceMain(DWORD, LPWSTR*) {
        Instance().RunService();
    }

    static DWORD WINAPI ServiceHandlerEx(
        DWORD control,
        DWORD event_type,
        LPVOID event_data,
        LPVOID context) {
        return static_cast<ServiceHost*>(context)->HandleServiceControl(control, event_type, event_data);
    }

    int RunDispatcher() {
        SERVICE_TABLE_ENTRYW service_table[] = {
            {const_cast<LPWSTR>(service_constants::kServiceName), &ServiceHost::ServiceMain},
            {nullptr, nullptr},
        };

        if (StartServiceCtrlDispatcherW(service_table) == FALSE) {
            return static_cast<int>(GetLastError());
        }

        return 0;
    }

    bool InstallService(std::wstring* error_message) {
        ScopedServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
        if (scm.get() == nullptr) {
            *error_message = L"OpenSCManager failed: " + GetLastErrorMessage(GetLastError());
            return false;
        }

        const std::wstring module_path = GetModulePath();
        const std::wstring binary_path = QuoteArgument(module_path);

        ScopedServiceHandle service(CreateServiceW(
            scm.get(),
            service_constants::kServiceName,
            service_constants::kServiceDisplayName,
            SERVICE_CHANGE_CONFIG | READ_CONTROL | WRITE_DAC,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binary_path.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr));
        if (service.get() == nullptr) {
            const DWORD error = GetLastError();
            if (error == ERROR_SERVICE_EXISTS) {
                *error_message = L"Service is already installed.";
            } else {
                *error_message = L"CreateService failed: " + GetLastErrorMessage(error);
            }
            return false;
        }

        SERVICE_DESCRIPTIONW description = {
            const_cast<LPWSTR>(service_constants::kServiceDescription),
        };
        ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, &description);

        if (!GrantInteractiveUsersStartAccess(service.get(), error_message)) {
            DeleteService(service.get());
            return false;
        }

        return true;
    }

    bool UninstallService(std::wstring* error_message) {
        ScopedServiceHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (scm.get() == nullptr) {
            *error_message = L"OpenSCManager failed: " + GetLastErrorMessage(GetLastError());
            return false;
        }

        ScopedServiceHandle service(OpenServiceW(
            scm.get(),
            service_constants::kServiceName,
            DELETE));
        if (service.get() == nullptr) {
            *error_message = L"OpenService failed: " + GetLastErrorMessage(GetLastError());
            return false;
        }

        if (DeleteService(service.get()) == FALSE) {
            *error_message = L"DeleteService failed: " + GetLastErrorMessage(GetLastError());
            return false;
        }

        return true;
    }

    void ScheduleRpcStop() {
        if (stop_requested_.exchange(true)) {
            return;
        }

        HANDLE thread = CreateThread(nullptr, 0, &ServiceHost::RpcStopThread, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }

private:
    ServiceHost() = default;

    static DWORD WINAPI RpcStopThread(LPVOID) {
        Sleep(200);
        RpcMgmtStopServerListening(nullptr);
        RpcServerUnregisterIf(nullptr, nullptr, FALSE);
        return 0;
    }

    void RunService() {
        status_handle_ = RegisterServiceCtrlHandlerExW(
            service_constants::kServiceName,
            &ServiceHost::ServiceHandlerEx,
            this);
        if (status_handle_ == nullptr) {
            return;
        }

        module_directory_ = GetDirectoryName(GetModulePath());
        client_path_ = module_directory_ + L"\\" + service_constants::kClientExecutableName;

        ReportStatus(SERVICE_START_PENDING, 0, NO_ERROR, 3000);

        std::wstring bases_error;
        if (!session_manager_.InitializeAntivirusStorage(module_directory_, &bases_error)) {
            ReportStatus(SERVICE_STOPPED, 0, ERROR_GEN_FAILURE, 0);
            return;
        }

        const RPC_STATUS init_status = InitializeRpcServer();
        if (init_status != RPC_S_OK) {
            ReportStatus(SERVICE_STOPPED, 0, init_status, 0);
            return;
        }

        session_manager_.Start();
        ReportStatus(SERVICE_RUNNING, SERVICE_ACCEPT_SESSIONCHANGE, NO_ERROR, 0);
        LaunchForExistingSessions();

        const RPC_STATUS listen_status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
        (void)listen_status;

        ReportStatus(SERVICE_STOP_PENDING, 0, NO_ERROR, 3000);
        session_manager_.Stop();
        TerminateAllChildProcesses();
        ReportStatus(SERVICE_STOPPED, 0, NO_ERROR, 0);
    }

public:
    long RpcGetCurrentUser(
        InfoGuardRpcUserInfo* user_info,
        wchar_t** error_message) {
        ResetRpcUserInfo(user_info);
        if (error_message != nullptr) {
            *error_message = nullptr;
        }

        ServiceAuthenticatedUserInfo service_user;
        std::wstring message;
        const DWORD result = session_manager_.GetCurrentUser(&service_user, &message);
        if (result != ERROR_SUCCESS) {
            if (error_message != nullptr) {
                *error_message = DuplicateRpcString(message);
            }
            return static_cast<long>(result);
        }

        user_info->userId = static_cast<hyper>(service_user.user_id);
        user_info->username = DuplicateRpcString(service_user.username);
        user_info->fullName = DuplicateRpcString(service_user.full_name);
        user_info->role = DuplicateRpcString(service_user.role);
        return ERROR_SUCCESS;
    }

    long RpcLogin(
        const std::wstring& username,
        const std::wstring& password,
        InfoGuardRpcUserInfo* user_info,
        wchar_t** error_message) {
        ResetRpcUserInfo(user_info);
        if (error_message != nullptr) {
            *error_message = nullptr;
        }

        ServiceAuthenticatedUserInfo service_user;
        std::wstring message;
        const DWORD result = session_manager_.Login(username, password, &service_user, &message);
        if (result != ERROR_SUCCESS) {
            if (error_message != nullptr) {
                *error_message = DuplicateRpcString(message);
            }
            return static_cast<long>(result);
        }

        user_info->userId = static_cast<hyper>(service_user.user_id);
        user_info->username = DuplicateRpcString(service_user.username);
        user_info->fullName = DuplicateRpcString(service_user.full_name);
        user_info->role = DuplicateRpcString(service_user.role);
        return ERROR_SUCCESS;
    }

    long RpcLogout(wchar_t** error_message) {
        if (error_message != nullptr) {
            *error_message = nullptr;
        }

        std::wstring message;
        const DWORD result = session_manager_.Logout(&message);
        if (result != ERROR_SUCCESS && error_message != nullptr) {
            *error_message = DuplicateRpcString(message);
        }

        return static_cast<long>(result);
    }

    long RpcGetActiveLicense(
        InfoGuardRpcLicenseInfo* license_info,
        wchar_t** error_message) {
        ResetRpcLicenseInfo(license_info);
        if (error_message != nullptr) {
            *error_message = nullptr;
        }

        ServiceActiveLicenseInfo service_license;
        std::wstring message;
        const DWORD result = session_manager_.GetActiveLicense(&service_license, &message);
        if (result != ERROR_SUCCESS) {
            if (error_message != nullptr) {
                *error_message = DuplicateRpcString(message);
            }
            return static_cast<long>(result);
        }

        license_info->blocked = service_license.blocked ? TRUE : FALSE;
        license_info->deviceId = DuplicateRpcString(service_license.device_id);
        license_info->activatedAt = DuplicateRpcString(service_license.activated_at);
        license_info->expiresAt = DuplicateRpcString(service_license.expires_at);
        return ERROR_SUCCESS;
    }

    long RpcActivateProduct(
        const std::wstring& activation_code,
        InfoGuardRpcLicenseInfo* license_info,
        wchar_t** error_message) {
        ResetRpcLicenseInfo(license_info);
        if (error_message != nullptr) {
            *error_message = nullptr;
        }

        ServiceActiveLicenseInfo service_license;
        std::wstring message;
        const DWORD result = session_manager_.ActivateProduct(activation_code, &service_license, &message);
        if (result != ERROR_SUCCESS) {
            if (error_message != nullptr) {
                *error_message = DuplicateRpcString(message);
            }
            return static_cast<long>(result);
        }

        license_info->blocked = service_license.blocked ? TRUE : FALSE;
        license_info->deviceId = DuplicateRpcString(service_license.device_id);
        license_info->activatedAt = DuplicateRpcString(service_license.activated_at);
        license_info->expiresAt = DuplicateRpcString(service_license.expires_at);
        return ERROR_SUCCESS;
    }

    long RpcGetAntivirusBasesInfo(
        InfoGuardRpcAvBasesInfo* bases_info,
        wchar_t** error_message) {
        ResetRpcAvBasesInfo(bases_info);
        if (error_message != nullptr) {
            *error_message = nullptr;
        }

        ServiceAntivirusBasesInfo service_bases;
        std::wstring message;
        const DWORD result = session_manager_.GetAntivirusBasesInfo(&service_bases, &message);
        if (result != ERROR_SUCCESS) {
            if (error_message != nullptr) {
                *error_message = DuplicateRpcString(message);
            }
            return static_cast<long>(result);
        }

        bases_info->loaded = service_bases.loaded ? TRUE : FALSE;
        bases_info->releaseDate = DuplicateRpcString(service_bases.release_date);
        bases_info->recordCount = static_cast<hyper>(service_bases.record_count);
        return ERROR_SUCCESS;
    }

    long RpcScanFile(
        const std::wstring& file_path,
        InfoGuardRpcScanResult* scan_result,
        wchar_t** error_message) {
        ResetRpcScanResult(scan_result);
        if (error_message != nullptr) {
            *error_message = nullptr;
        }

        ServiceScanResultInfo service_result;
        std::wstring message;
        const DWORD result = session_manager_.ScanFile(file_path, &service_result, &message);
        if (result != ERROR_SUCCESS) {
            if (error_message != nullptr) {
                *error_message = DuplicateRpcString(message);
            }
            return static_cast<long>(result);
        }

        scan_result->malicious = service_result.malicious ? TRUE : FALSE;
        scan_result->directoryScan = service_result.directory_scan ? TRUE : FALSE;
        scan_result->scannedObjectCount = static_cast<hyper>(service_result.scanned_object_count);
        scan_result->infectedObjectCount = static_cast<hyper>(service_result.infected_object_count);
        scan_result->targetPath = DuplicateRpcString(service_result.target_path);
        scan_result->detectedPath = DuplicateRpcString(service_result.detected_path);
        scan_result->detectedThreatName = DuplicateRpcString(service_result.detected_threat_name);
        scan_result->objectType = DuplicateRpcString(service_result.object_type);
        scan_result->summary = DuplicateRpcString(service_result.summary);
        return ERROR_SUCCESS;
    }

    long RpcScanDirectory(
        const std::wstring& directory_path,
        InfoGuardRpcScanResult* scan_result,
        wchar_t** error_message) {
        ResetRpcScanResult(scan_result);
        if (error_message != nullptr) {
            *error_message = nullptr;
        }

        ServiceScanResultInfo service_result;
        std::wstring message;
        const DWORD result = session_manager_.ScanDirectory(directory_path, &service_result, &message);
        if (result != ERROR_SUCCESS) {
            if (error_message != nullptr) {
                *error_message = DuplicateRpcString(message);
            }
            return static_cast<long>(result);
        }

        scan_result->malicious = service_result.malicious ? TRUE : FALSE;
        scan_result->directoryScan = service_result.directory_scan ? TRUE : FALSE;
        scan_result->scannedObjectCount = static_cast<hyper>(service_result.scanned_object_count);
        scan_result->infectedObjectCount = static_cast<hyper>(service_result.infected_object_count);
        scan_result->targetPath = DuplicateRpcString(service_result.target_path);
        scan_result->detectedPath = DuplicateRpcString(service_result.detected_path);
        scan_result->detectedThreatName = DuplicateRpcString(service_result.detected_threat_name);
        scan_result->objectType = DuplicateRpcString(service_result.object_type);
        scan_result->summary = DuplicateRpcString(service_result.summary);
        return ERROR_SUCCESS;
    }

private:
    DWORD HandleServiceControl(DWORD control, DWORD event_type, LPVOID event_data) {
        switch (control) {
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;

        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            return NO_ERROR;

        case SERVICE_CONTROL_SESSIONCHANGE:
            HandleSessionChange(event_type, event_data);
            return NO_ERROR;

        default:
            return NO_ERROR;
        }
    }

    void HandleSessionChange(DWORD event_type, LPVOID event_data) {
        const auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(event_data);
        if (notification == nullptr) {
            return;
        }

        const DWORD session_id = notification->dwSessionId;

        switch (event_type) {
        case WTS_SESSION_LOGON:
        case WTS_CONSOLE_CONNECT:
        case WTS_REMOTE_CONNECT:
        case WTS_SESSION_UNLOCK:
        case WTS_SESSION_DESKTOP_READY:
            LaunchForSession(session_id);
            break;

        case WTS_SESSION_LOGOFF:
            RemoveChildProcess(session_id, true);
            break;

        default:
            break;
        }
    }

    RPC_STATUS InitializeRpcServer() {
        RPC_STATUS status = RpcServerUseProtseqEpW(
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(service_constants::kRpcProtocolSequence)),
            RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(service_constants::kRpcEndpoint)),
            nullptr);
        if (status != RPC_S_OK) {
            return status;
        }

        status = RpcServerRegisterIf2(
            InfoGuardServiceRpc_v1_0_s_ifspec,
            nullptr,
            nullptr,
            0,
            RPC_C_LISTEN_MAX_CALLS_DEFAULT,
            static_cast<unsigned int>(-1),
            nullptr);
        return status;
    }

    void LaunchForExistingSessions() {
        WTS_SESSION_INFOW* sessions = nullptr;
        DWORD count = 0;

        if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count) == FALSE) {
            return;
        }

        for (DWORD index = 0; index < count; ++index) {
            if (sessions[index].SessionId != 0) {
                LaunchForSession(sessions[index].SessionId);
            }
        }

        WTSFreeMemory(sessions);
    }

    void RemoveExitedChildProcesses() {
        std::lock_guard<std::mutex> guard(child_processes_mutex_);

        for (auto iterator = child_processes_.begin(); iterator != child_processes_.end();) {
            DWORD exit_code = STILL_ACTIVE;
            if (GetExitCodeProcess(iterator->second.process_handle, &exit_code) == FALSE || exit_code != STILL_ACTIVE) {
                CloseHandle(iterator->second.process_handle);
                iterator = child_processes_.erase(iterator);
            } else {
                ++iterator;
            }
        }
    }

    bool LaunchForSession(const DWORD session_id) {
        if (session_id == 0) {
            return false;
        }

        RemoveExitedChildProcesses();

        {
            std::lock_guard<std::mutex> guard(child_processes_mutex_);
            const auto iterator = child_processes_.find(session_id);
            if (iterator != child_processes_.end()) {
                return true;
            }
        }

        ScopedHandle user_token;
        if (WTSQueryUserToken(session_id, user_token.put()) == FALSE) {
            return false;
        }

        LPVOID environment = nullptr;
        CreateEnvironmentBlock(&environment, user_token.get(), FALSE);

        STARTUPINFOW startup_info = {};
        startup_info.cb = sizeof(startup_info);
        startup_info.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
        startup_info.dwFlags = STARTF_USESHOWWINDOW;
        startup_info.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION process_information = {};
        std::wstring command_line =
            QuoteArgument(client_path_) + L" " + service_constants::kHiddenArgument;

        const BOOL started = CreateProcessAsUserW(
            user_token.get(),
            client_path_.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_UNICODE_ENVIRONMENT,
            environment,
            module_directory_.c_str(),
            &startup_info,
            &process_information);

        if (environment != nullptr) {
            DestroyEnvironmentBlock(environment);
        }

        if (started == FALSE) {
            return false;
        }

        CloseHandle(process_information.hThread);

        std::lock_guard<std::mutex> guard(child_processes_mutex_);
        child_processes_[session_id] = ChildProcessInfo{
            process_information.hProcess,
            process_information.dwProcessId,
        };
        return true;
    }

    void RemoveChildProcess(const DWORD session_id, const bool terminate) {
        std::lock_guard<std::mutex> guard(child_processes_mutex_);
        const auto iterator = child_processes_.find(session_id);
        if (iterator == child_processes_.end()) {
            return;
        }

        if (terminate) {
            TerminateProcess(iterator->second.process_handle, 0);
            WaitForSingleObject(iterator->second.process_handle, 2000);
        }

        CloseHandle(iterator->second.process_handle);
        child_processes_.erase(iterator);
    }

    void TerminateAllChildProcesses() {
        std::lock_guard<std::mutex> guard(child_processes_mutex_);

        for (auto& [session_id, child] : child_processes_) {
            (void)session_id;
            TerminateProcess(child.process_handle, 0);
            WaitForSingleObject(child.process_handle, 2000);
            CloseHandle(child.process_handle);
        }

        child_processes_.clear();
    }

    void ReportStatus(
        DWORD current_state,
        DWORD controls_accepted,
        DWORD win32_exit_code,
        DWORD wait_hint) {
        service_status_.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        service_status_.dwCurrentState = current_state;
        service_status_.dwControlsAccepted = controls_accepted;
        service_status_.dwWin32ExitCode = win32_exit_code;
        service_status_.dwWaitHint = wait_hint;
        service_status_.dwCheckPoint =
            (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED) ? 0 : ++checkpoint_;

        SetServiceStatus(status_handle_, &service_status_);
    }

    SERVICE_STATUS_HANDLE status_handle_ = nullptr;
    SERVICE_STATUS service_status_ = {};
    DWORD checkpoint_ = 0;
    std::wstring module_directory_;
    std::wstring client_path_;
    std::mutex child_processes_mutex_;
    std::map<DWORD, ChildProcessInfo> child_processes_;
    std::atomic_bool stop_requested_ = false;
    ServiceSessionManager session_manager_;
};

}  // namespace

void InfoGuardRpcStopService() {
    ServiceHost::Instance().ScheduleRpcStop();
}

long InfoGuardRpcGetCurrentUser(InfoGuardRpcUserInfo* userInfo, wchar_t** errorMessage) {
    return ServiceHost::Instance().RpcGetCurrentUser(userInfo, errorMessage);
}

long InfoGuardRpcLogin(
    wchar_t* username,
    wchar_t* password,
    InfoGuardRpcUserInfo* userInfo,
    wchar_t** errorMessage) {
    return ServiceHost::Instance().RpcLogin(
        username == nullptr ? L"" : username,
        password == nullptr ? L"" : password,
        userInfo,
        errorMessage);
}

long InfoGuardRpcLogout(wchar_t** errorMessage) {
    return ServiceHost::Instance().RpcLogout(errorMessage);
}

long InfoGuardRpcGetActiveLicense(InfoGuardRpcLicenseInfo* licenseInfo, wchar_t** errorMessage) {
    return ServiceHost::Instance().RpcGetActiveLicense(licenseInfo, errorMessage);
}

long InfoGuardRpcActivateProduct(
    wchar_t* activationCode,
    InfoGuardRpcLicenseInfo* licenseInfo,
    wchar_t** errorMessage) {
    return ServiceHost::Instance().RpcActivateProduct(
        activationCode == nullptr ? L"" : activationCode,
        licenseInfo,
        errorMessage);
}

long InfoGuardRpcGetAntivirusBasesInfo(
    InfoGuardRpcAvBasesInfo* basesInfo,
    wchar_t** errorMessage) {
    return ServiceHost::Instance().RpcGetAntivirusBasesInfo(basesInfo, errorMessage);
}

long InfoGuardRpcScanFile(
    wchar_t* filePath,
    InfoGuardRpcScanResult* scanResult,
    wchar_t** errorMessage) {
    return ServiceHost::Instance().RpcScanFile(
        filePath == nullptr ? L"" : filePath,
        scanResult,
        errorMessage);
}

long InfoGuardRpcScanDirectory(
    wchar_t* directoryPath,
    InfoGuardRpcScanResult* scanResult,
    wchar_t** errorMessage) {
    return ServiceHost::Instance().RpcScanDirectory(
        directoryPath == nullptr ? L"" : directoryPath,
        scanResult,
        errorMessage);
}

int wmain(const int argc, wchar_t* argv[]) {
    std::wstring error_message;

    if (argc > 1) {
        const std::wstring command = argv[1];

        if (command == L"--install") {
            if (ServiceHost::Instance().InstallService(&error_message)) {
                return 0;
            }

            MessageBoxW(nullptr, error_message.c_str(), L"InfoGuard Service", MB_ICONERROR | MB_OK);
            return 1;
        }

        if (command == L"--uninstall") {
            if (ServiceHost::Instance().UninstallService(&error_message)) {
                return 0;
            }

            MessageBoxW(nullptr, error_message.c_str(), L"InfoGuard Service", MB_ICONERROR | MB_OK);
            return 1;
        }
    }

    return ServiceHost::Instance().RunDispatcher();
}
