#include "service_session_manager.h"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <sstream>

namespace {

constexpr unsigned long long kFileTimeTicksPerSecond = 10000000ull;
constexpr unsigned long long kRefreshSafetySeconds = 60ull;

unsigned long long NowFileTime() {
    FILETIME file_time = {};
    GetSystemTimeAsFileTime(&file_time);

    ULARGE_INTEGER value = {};
    value.LowPart = file_time.dwLowDateTime;
    value.HighPart = file_time.dwHighDateTime;
    return value.QuadPart;
}

unsigned long long SecondsToFileTimeTicks(const unsigned long long seconds) {
    return seconds * kFileTimeTicksPerSecond;
}

std::uint64_t ComputeFnv1a64(const std::wstring& value) {
    constexpr std::uint64_t kOffsetBasis = 14695981039346656037ull;
    constexpr std::uint64_t kPrime = 1099511628211ull;

    std::uint64_t hash = kOffsetBasis;
    for (const wchar_t character : value) {
        hash ^= static_cast<std::uint64_t>(character);
        hash *= kPrime;
    }

    return hash;
}

std::wstring ToUpperHex(const std::uint64_t value) {
    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setw(16) << std::setfill(L'0') << value;
    return stream.str();
}

std::wstring GetComputerIdentity() {
    DWORD size = 0;
    GetComputerNameExW(ComputerNameDnsHostname, nullptr, &size);
    if (size == 0) {
        return L"localhost";
    }

    std::wstring buffer(size, L'\0');
    if (GetComputerNameExW(ComputerNameDnsHostname, buffer.data(), &size) == FALSE || size == 0) {
        return L"localhost";
    }

    buffer.resize(size);
    return buffer;
}

DWORD MapLoginError(const std::wstring& error_message) {
    if (error_message.find(L"Invalid username or password") != std::wstring::npos) {
        return ERROR_LOGON_FAILURE;
    }
    return ERROR_BAD_NET_RESP;
}

DWORD MapLicenseError(const std::wstring& error_message, bool not_found) {
    if (not_found || error_message.find(L"No active license") != std::wstring::npos) {
        return ERROR_NOT_FOUND;
    }
    if (error_message.find(L"another device") != std::wstring::npos ||
        error_message.find(L"blocked") != std::wstring::npos) {
        return ERROR_ACCESS_DENIED;
    }
    return ERROR_BAD_NET_RESP;
}

}  // namespace

ServiceSessionManager::ServiceSessionManager()
    : device_id_(GetDeviceId()) {
}

ServiceSessionManager::~ServiceSessionManager() {
    Stop();
}

void ServiceSessionManager::Start() {
    std::lock_guard<std::mutex> guard(mutex_);
    if (worker_thread_.joinable()) {
        return;
    }

    stop_requested_ = false;
    worker_thread_ = std::thread(&ServiceSessionManager::WorkerLoop, this);
}

void ServiceSessionManager::Stop() {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        stop_requested_ = true;
    }

    condition_variable_.notify_all();

    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

DWORD ServiceSessionManager::GetCurrentUser(
    ServiceAuthenticatedUserInfo* user_info,
    std::wstring* error_message) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!authenticated_) {
        *error_message = L"No authenticated user is currently stored in the Windows service.";
        return ERROR_NOT_FOUND;
    }

    CopyUserInfoLocked(user_info);
    error_message->clear();
    return ERROR_SUCCESS;
}

DWORD ServiceSessionManager::Login(
    const std::wstring& username,
    const std::wstring& password,
    ServiceAuthenticatedUserInfo* user_info,
    std::wstring* error_message) {
    BackendTokenBundle tokens;
    if (!backend_api_client_.Login(username, password, &tokens, error_message)) {
        return MapLoginError(*error_message);
    }

    {
        std::lock_guard<std::mutex> guard(mutex_);
        tokens_ = tokens;
        authenticated_ = true;
        ClearTicketLocked();
        CopyUserInfoLocked(user_info);
    }

    condition_variable_.notify_all();
    error_message->clear();
    return ERROR_SUCCESS;
}

DWORD ServiceSessionManager::Logout(std::wstring* error_message) {
    std::wstring refresh_token;

    {
        std::lock_guard<std::mutex> guard(mutex_);
        refresh_token = tokens_.refresh_token;
        ClearAuthStateLocked();
    }

    condition_variable_.notify_all();

    std::wstring ignored_error;
    if (!refresh_token.empty()) {
        backend_api_client_.Logout(refresh_token, &ignored_error);
    }

    error_message->clear();
    return ERROR_SUCCESS;
}

DWORD ServiceSessionManager::GetActiveLicense(
    ServiceActiveLicenseInfo* license_info,
    std::wstring* error_message) {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!authenticated_) {
            *error_message = L"No authenticated user is currently stored in the Windows service.";
            return ERROR_NOT_FOUND;
        }

        const unsigned long long now = NowFileTime();
        if (has_ticket_ && now < ComputeTicketRefreshDueLocked()) {
            CopyLicenseInfoLocked(license_info);
            error_message->clear();
            return ERROR_SUCCESS;
        }
    }

    const DWORD refresh_result = RefreshCurrentLicenseState(true, error_message);
    if (refresh_result != ERROR_SUCCESS) {
        return refresh_result;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    CopyLicenseInfoLocked(license_info);
    error_message->clear();
    return ERROR_SUCCESS;
}

DWORD ServiceSessionManager::ActivateProduct(
    const std::wstring& activation_code,
    ServiceActiveLicenseInfo* license_info,
    std::wstring* error_message) {
    std::wstring access_token;
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!authenticated_) {
            *error_message = L"No authenticated user is currently stored in the Windows service.";
            return ERROR_NOT_FOUND;
        }
        access_token = tokens_.access_token;
    }

    BackendTicketInfo ticket;
    bool license_missing = false;
    if (!backend_api_client_.ActivateLicense(
            access_token,
            activation_code,
            device_id_,
            &ticket,
            error_message,
            &license_missing)) {
        return MapLicenseError(*error_message, license_missing);
    }

    {
        std::lock_guard<std::mutex> guard(mutex_);
        ticket_ = ticket;
        has_ticket_ = true;
        CopyLicenseInfoLocked(license_info);
    }

    condition_variable_.notify_all();
    error_message->clear();
    return ERROR_SUCCESS;
}

void ServiceSessionManager::WorkerLoop() {
    for (;;) {
        enum class Operation {
            None,
            RefreshTokens,
            RefreshLicense,
        };

        Operation operation = Operation::None;
        std::wstring refresh_token;
        std::wstring access_token;

        {
            std::unique_lock<std::mutex> lock(mutex_);

            while (!stop_requested_) {
                if (!authenticated_) {
                    condition_variable_.wait(lock, [this] { return stop_requested_ || authenticated_; });
                    continue;
                }

                const unsigned long long now = NowFileTime();
                const unsigned long long token_due = ComputeTokenRefreshDueLocked();
                const unsigned long long license_due = ComputeTicketRefreshDueLocked();

                unsigned long long next_due = token_due;
                if (license_due != 0 && (next_due == 0 || license_due < next_due)) {
                    next_due = license_due;
                }

                if (next_due == 0) {
                    condition_variable_.wait(lock, [this] { return stop_requested_ || !authenticated_ || has_ticket_; });
                    continue;
                }

                if (now < next_due) {
                    const unsigned long long wait_ticks = next_due - now;
                    const auto wait_duration = std::chrono::milliseconds(static_cast<long long>(wait_ticks / 10000ull));
                    condition_variable_.wait_for(lock, wait_duration, [this] { return stop_requested_ || !authenticated_; });
                    continue;
                }

                if (token_due != 0 && now >= token_due) {
                    operation = Operation::RefreshTokens;
                    refresh_token = tokens_.refresh_token;
                    break;
                }

                if (license_due != 0 && now >= license_due) {
                    operation = Operation::RefreshLicense;
                    access_token = tokens_.access_token;
                    break;
                }

                condition_variable_.wait_for(lock, std::chrono::seconds(1));
            }

            if (stop_requested_) {
                return;
            }
        }

        if (operation == Operation::RefreshTokens) {
            BackendTokenBundle refreshed_tokens;
            std::wstring ignored_error;
            if (!backend_api_client_.Refresh(refresh_token, &refreshed_tokens, &ignored_error)) {
                std::lock_guard<std::mutex> guard(mutex_);
                ClearAuthStateLocked();
                continue;
            }

            {
                std::lock_guard<std::mutex> guard(mutex_);
                tokens_ = refreshed_tokens;
            }

            condition_variable_.notify_all();
            continue;
        }

        if (operation == Operation::RefreshLicense) {
            BackendTicketInfo refreshed_ticket;
            std::wstring ignored_error;
            bool license_missing = false;
            if (!backend_api_client_.GetCurrentLicense(
                    access_token,
                    device_id_,
                    &refreshed_ticket,
                    &ignored_error,
                    &license_missing)) {
                std::lock_guard<std::mutex> guard(mutex_);
                if (license_missing || (has_ticket_ && NowFileTime() >= ticket_.expires_at)) {
                    ClearTicketLocked();
                }
                continue;
            }

            {
                std::lock_guard<std::mutex> guard(mutex_);
                ticket_ = refreshed_ticket;
                has_ticket_ = true;
            }

            condition_variable_.notify_all();
        }
    }
}

void ServiceSessionManager::ClearAuthStateLocked() {
    tokens_ = BackendTokenBundle{};
    authenticated_ = false;
    ClearTicketLocked();
}

void ServiceSessionManager::ClearTicketLocked() {
    ticket_ = BackendTicketInfo{};
    has_ticket_ = false;
}

void ServiceSessionManager::CopyUserInfoLocked(ServiceAuthenticatedUserInfo* user_info) const {
    user_info->user_id = tokens_.user.user_id;
    user_info->username = tokens_.user.username;
    user_info->full_name = tokens_.user.full_name;
    user_info->role = tokens_.user.role;
}

void ServiceSessionManager::CopyLicenseInfoLocked(ServiceActiveLicenseInfo* license_info) const {
    license_info->blocked = ticket_.blocked;
    license_info->device_id = ticket_.device_id;
    license_info->activated_at = ticket_.activated_at_text;
    license_info->expires_at = ticket_.expires_at_text;
}

unsigned long long ServiceSessionManager::ComputeTokenRefreshDueLocked() const {
    if (!authenticated_ || tokens_.access_expires_at == 0 || tokens_.refresh_expires_at == 0) {
        return 0;
    }

    const unsigned long long safety_ticks = SecondsToFileTimeTicks(kRefreshSafetySeconds);
    const unsigned long long access_due =
        tokens_.access_expires_at > safety_ticks ? tokens_.access_expires_at - safety_ticks : 1;
    const unsigned long long refresh_due =
        tokens_.refresh_expires_at > safety_ticks ? tokens_.refresh_expires_at - safety_ticks : 1;

    return std::min(access_due, refresh_due);
}

unsigned long long ServiceSessionManager::ComputeTicketRefreshDueLocked() const {
    if (!has_ticket_ || ticket_.server_date == 0 || ticket_.expires_at == 0) {
        return 0;
    }

    const unsigned long long safety_ticks = SecondsToFileTimeTicks(kRefreshSafetySeconds);
    const unsigned long long issued_due = ticket_.server_date +
        SecondsToFileTimeTicks(ticket_.ticket_lifetime_seconds);
    const unsigned long long ticket_due = issued_due > safety_ticks ? issued_due - safety_ticks : 1;
    const unsigned long long expiry_due =
        ticket_.expires_at > safety_ticks ? ticket_.expires_at - safety_ticks : 1;

    return std::min(ticket_due, expiry_due);
}

DWORD ServiceSessionManager::RefreshCurrentLicenseState(
    const bool allow_license_missing,
    std::wstring* error_message) {
    std::wstring access_token;

    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!authenticated_) {
            *error_message = L"No authenticated user is currently stored in the Windows service.";
            return ERROR_NOT_FOUND;
        }

        access_token = tokens_.access_token;
    }

    BackendTicketInfo ticket;
    bool license_missing = false;
    if (!backend_api_client_.GetCurrentLicense(
            access_token,
            device_id_,
            &ticket,
            error_message,
            &license_missing)) {
        if (license_missing) {
            std::lock_guard<std::mutex> guard(mutex_);
            ClearTicketLocked();
            return allow_license_missing ? ERROR_NOT_FOUND : ERROR_ACCESS_DENIED;
        }
        return MapLicenseError(*error_message, false);
    }

    {
        std::lock_guard<std::mutex> guard(mutex_);
        ticket_ = ticket;
        has_ticket_ = true;
    }

    condition_variable_.notify_all();
    return ERROR_SUCCESS;
}

std::wstring ServiceSessionManager::GetDeviceId() const {
    return L"DEV-" + ToUpperHex(ComputeFnv1a64(GetComputerIdentity()));
}
