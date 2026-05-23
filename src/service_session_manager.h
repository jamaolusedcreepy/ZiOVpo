#pragma once

#include <windows.h>

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include "backend_api_client.h"

struct ServiceAuthenticatedUserInfo {
    unsigned long long user_id = 0;
    std::wstring username;
    std::wstring full_name;
    std::wstring role;
};

struct ServiceActiveLicenseInfo {
    bool blocked = false;
    std::wstring device_id;
    std::wstring activated_at;
    std::wstring expires_at;
};

class ServiceSessionManager {
public:
    ServiceSessionManager();
    ~ServiceSessionManager();

    void Start();
    void Stop();

    DWORD GetCurrentUser(ServiceAuthenticatedUserInfo* user_info, std::wstring* error_message);
    DWORD Login(
        const std::wstring& username,
        const std::wstring& password,
        ServiceAuthenticatedUserInfo* user_info,
        std::wstring* error_message);
    DWORD Logout(std::wstring* error_message);
    DWORD GetActiveLicense(ServiceActiveLicenseInfo* license_info, std::wstring* error_message);
    DWORD ActivateProduct(const std::wstring& activation_code, ServiceActiveLicenseInfo* license_info, std::wstring* error_message);

private:
    void WorkerLoop();
    void ClearAuthStateLocked();
    void ClearTicketLocked();
    void CopyUserInfoLocked(ServiceAuthenticatedUserInfo* user_info) const;
    void CopyLicenseInfoLocked(ServiceActiveLicenseInfo* license_info) const;
    unsigned long long ComputeTokenRefreshDueLocked() const;
    unsigned long long ComputeTicketRefreshDueLocked() const;
    DWORD RefreshCurrentLicenseState(bool allow_license_missing, std::wstring* error_message);
    std::wstring GetDeviceId() const;

    BackendApiClient backend_api_client_;
    std::wstring device_id_;
    std::mutex mutex_;
    std::condition_variable condition_variable_;
    std::thread worker_thread_;
    bool stop_requested_ = false;
    bool authenticated_ = false;
    bool has_ticket_ = false;
    BackendTokenBundle tokens_;
    BackendTicketInfo ticket_;
};
