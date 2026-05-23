#pragma once

#include <windows.h>

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include "antivirus_engine.h"
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

struct ServiceAntivirusBasesInfo {
    bool loaded = false;
    std::wstring release_date;
    unsigned long long record_count = 0;
};

struct ServiceScanResultInfo {
    bool malicious = false;
    bool directory_scan = false;
    unsigned long long scanned_object_count = 0;
    unsigned long long infected_object_count = 0;
    std::wstring target_path;
    std::wstring detected_path;
    std::wstring detected_threat_name;
    std::wstring object_type;
    std::wstring summary;
};

class ServiceSessionManager {
public:
    ServiceSessionManager();
    ~ServiceSessionManager();

    bool InitializeAntivirusStorage(const std::wstring& service_module_directory, std::wstring* error_message);
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
    DWORD GetAntivirusBasesInfo(ServiceAntivirusBasesInfo* bases_info, std::wstring* error_message);
    DWORD ScanFile(
        const std::wstring& file_path,
        ServiceScanResultInfo* scan_result,
        std::wstring* error_message);
    DWORD ScanDirectory(
        const std::wstring& directory_path,
        ServiceScanResultInfo* scan_result,
        std::wstring* error_message);

private:
    void WorkerLoop();
    void ClearAuthStateLocked();
    void ClearTicketLocked();
    void CopyUserInfoLocked(ServiceAuthenticatedUserInfo* user_info) const;
    void CopyLicenseInfoLocked(ServiceActiveLicenseInfo* license_info) const;
    unsigned long long ComputeTokenRefreshDueLocked() const;
    unsigned long long ComputeTicketRefreshDueLocked() const;
    unsigned long long ComputeBasesUpdateDueLocked() const;
    DWORD RefreshCurrentLicenseState(bool allow_license_missing, std::wstring* error_message);
    DWORD EnsureBasesLoaded(std::wstring* error_message);
    bool TryUpdateAntivirusBases(std::wstring* error_message);
    std::wstring GetDeviceId() const;

    AntivirusEngine antivirus_engine_;
    BackendApiClient backend_api_client_;
    std::wstring device_id_;
    std::mutex mutex_;
    std::condition_variable condition_variable_;
    std::thread worker_thread_;
    bool stop_requested_ = false;
    bool authenticated_ = false;
    bool has_ticket_ = false;
    unsigned long long bases_update_interval_seconds_ = 300;
    unsigned long long next_bases_update_due_ = 0;
    BackendTokenBundle tokens_;
    BackendTicketInfo ticket_;
};
