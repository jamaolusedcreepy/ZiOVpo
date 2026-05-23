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
constexpr unsigned long long kDefaultBasesUpdateIntervalSeconds = 30ull;

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

unsigned long long GetBasesUpdateIntervalSeconds() {
    wchar_t buffer[32] = {};
    const DWORD size = GetEnvironmentVariableW(L"INFOGUARD_AV_UPDATE_INTERVAL_SECONDS", buffer, static_cast<DWORD>(std::size(buffer)));
    if (size == 0 || size >= std::size(buffer)) {
        return kDefaultBasesUpdateIntervalSeconds;
    }

    try {
        const unsigned long long value = std::stoull(buffer);
        return value == 0 ? kDefaultBasesUpdateIntervalSeconds : value;
    } catch (...) {
        return kDefaultBasesUpdateIntervalSeconds;
    }
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
    : device_id_(GetDeviceId()),
      bases_update_interval_seconds_(GetBasesUpdateIntervalSeconds()) {
}

ServiceSessionManager::~ServiceSessionManager() {
    Stop();
}

bool ServiceSessionManager::InitializeAntivirusStorage(
    const std::wstring& service_module_directory,
    std::wstring* error_message) {
    if (antivirus_engine_.InitializeStorage(service_module_directory, error_message)) {
        return true;
    }

    std::vector<std::uint8_t> downloaded_package;
    std::wstring update_error;
    if (!backend_api_client_.DownloadAntivirusBasesPackage(&downloaded_package, &update_error)) {
        return false;
    }

    if (!antivirus_engine_.UpdateBasesFromPackage(downloaded_package, error_message)) {
        return false;
    }

    error_message->clear();
    return true;
}

void ServiceSessionManager::Start() {
    std::lock_guard<std::mutex> guard(mutex_);
    if (worker_thread_.joinable()) {
        return;
    }

    stop_requested_ = false;
    next_bases_update_due_ = NowFileTime() + SecondsToFileTimeTicks(bases_update_interval_seconds_);
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

    if (const DWORD load_result = EnsureBasesLoaded(error_message); load_result != ERROR_SUCCESS) {
        return load_result;
    }

    condition_variable_.notify_all();
    error_message->clear();
    return ERROR_SUCCESS;
}

DWORD ServiceSessionManager::GetAntivirusBasesInfo(
    ServiceAntivirusBasesInfo* bases_info,
    std::wstring* error_message) {
    const AntivirusBasesInfo info = antivirus_engine_.GetBasesInfo();
    if (!info.loaded) {
        *error_message = L"Antivirus bases are not currently loaded in the Windows service.";
        return ERROR_NOT_READY;
    }

    bases_info->loaded = info.loaded;
    bases_info->release_date = info.release_date;
    bases_info->record_count = info.record_count;
    error_message->clear();
    return ERROR_SUCCESS;
}

DWORD ServiceSessionManager::ScanFile(
    const std::wstring& file_path,
    ServiceScanResultInfo* scan_result,
    std::wstring* error_message) {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!authenticated_ || !has_ticket_) {
            *error_message = L"An active license ticket is required before antivirus scanning can start.";
            return ERROR_NOT_FOUND;
        }

        if (ticket_.blocked) {
            *error_message = L"The active license is blocked. Antivirus scanning is unavailable.";
            return ERROR_ACCESS_DENIED;
        }
    }

    const DWORD load_result = EnsureBasesLoaded(error_message);
    if (load_result != ERROR_SUCCESS) {
        return load_result;
    }

    ScanResultInfo engine_result;
    const DWORD scan_status = antivirus_engine_.ScanFile(file_path, &engine_result, error_message);
    if (scan_status != ERROR_SUCCESS) {
        return scan_status;
    }

    scan_result->malicious = engine_result.malicious;
    scan_result->directory_scan = engine_result.directory_scan;
    scan_result->scanned_object_count = engine_result.scanned_object_count;
    scan_result->infected_object_count = engine_result.infected_object_count;
    scan_result->target_path = engine_result.target_path;
    scan_result->detected_path = engine_result.detected_path;
    scan_result->detected_threat_name = engine_result.detected_threat_name;
    scan_result->object_type = engine_result.object_type;
    scan_result->summary = engine_result.summary;
    error_message->clear();
    return ERROR_SUCCESS;
}

DWORD ServiceSessionManager::ScanDirectory(
    const std::wstring& directory_path,
    ServiceScanResultInfo* scan_result,
    std::wstring* error_message) {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!authenticated_ || !has_ticket_) {
            *error_message = L"An active license ticket is required before antivirus scanning can start.";
            return ERROR_NOT_FOUND;
        }

        if (ticket_.blocked) {
            *error_message = L"The active license is blocked. Antivirus scanning is unavailable.";
            return ERROR_ACCESS_DENIED;
        }
    }

    const DWORD load_result = EnsureBasesLoaded(error_message);
    if (load_result != ERROR_SUCCESS) {
        return load_result;
    }

    ScanResultInfo engine_result;
    const DWORD scan_status = antivirus_engine_.ScanDirectory(directory_path, &engine_result, error_message);
    if (scan_status != ERROR_SUCCESS) {
        return scan_status;
    }

    scan_result->malicious = engine_result.malicious;
    scan_result->directory_scan = engine_result.directory_scan;
    scan_result->scanned_object_count = engine_result.scanned_object_count;
    scan_result->infected_object_count = engine_result.infected_object_count;
    scan_result->target_path = engine_result.target_path;
    scan_result->detected_path = engine_result.detected_path;
    scan_result->detected_threat_name = engine_result.detected_threat_name;
    scan_result->object_type = engine_result.object_type;
    scan_result->summary = engine_result.summary;
    error_message->clear();
    return ERROR_SUCCESS;
}

void ServiceSessionManager::WorkerLoop() {
    for (;;) {
        enum class Operation {
            None,
            RefreshTokens,
            RefreshLicense,
            UpdateBases,
        };

        Operation operation = Operation::None;
        std::wstring refresh_token;
        std::wstring access_token;

        {
            std::unique_lock<std::mutex> lock(mutex_);

            while (!stop_requested_) {
                const unsigned long long now = NowFileTime();
                const unsigned long long token_due = authenticated_ ? ComputeTokenRefreshDueLocked() : 0;
                const unsigned long long license_due = authenticated_ ? ComputeTicketRefreshDueLocked() : 0;
                const unsigned long long bases_due = ComputeBasesUpdateDueLocked();

                unsigned long long next_due = token_due;
                if (license_due != 0 && (next_due == 0 || license_due < next_due)) {
                    next_due = license_due;
                }
                if (bases_due != 0 && (next_due == 0 || bases_due < next_due)) {
                    next_due = bases_due;
                }

                if (next_due == 0) {
                    condition_variable_.wait(lock, [this] { return stop_requested_; });
                    continue;
                }

                if (now < next_due) {
                    const unsigned long long wait_ticks = next_due - now;
                    const auto wait_duration = std::chrono::milliseconds(static_cast<long long>(wait_ticks / 10000ull));
                    condition_variable_.wait_for(lock, wait_duration, [this] { return stop_requested_; });
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

                if (bases_due != 0 && now >= bases_due) {
                    operation = Operation::UpdateBases;
                    next_bases_update_due_ = now + SecondsToFileTimeTicks(bases_update_interval_seconds_);
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

            std::wstring ignored_load_error;
            EnsureBasesLoaded(&ignored_load_error);
            condition_variable_.notify_all();
            continue;
        }

        if (operation == Operation::UpdateBases) {
            std::wstring ignored_error;
            TryUpdateAntivirusBases(&ignored_error);
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

unsigned long long ServiceSessionManager::ComputeBasesUpdateDueLocked() const {
    return next_bases_update_due_;
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

    if (const DWORD load_result = EnsureBasesLoaded(error_message); load_result != ERROR_SUCCESS) {
        return load_result;
    }

    condition_variable_.notify_all();
    return ERROR_SUCCESS;
}

DWORD ServiceSessionManager::EnsureBasesLoaded(std::wstring* error_message) {
    const AntivirusBasesInfo info = antivirus_engine_.GetBasesInfo();
    if (info.loaded) {
        error_message->clear();
        return ERROR_SUCCESS;
    }

    if (!antivirus_engine_.LoadBasesFromStorage(error_message)) {
        return ERROR_NOT_READY;
    }

    error_message->clear();
    return ERROR_SUCCESS;
}

bool ServiceSessionManager::TryUpdateAntivirusBases(std::wstring* error_message) {
    std::vector<std::uint8_t> downloaded_package;
    if (!backend_api_client_.DownloadAntivirusBasesPackage(&downloaded_package, error_message)) {
        return false;
    }

    return antivirus_engine_.UpdateBasesFromPackage(downloaded_package, error_message);
}

std::wstring ServiceSessionManager::GetDeviceId() const {
    return L"DEV-" + ToUpperHex(ComputeFnv1a64(GetComputerIdentity()));
}
