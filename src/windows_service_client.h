#pragma once

#include <string>

struct AuthenticatedUserInfo {
    unsigned long long user_id = 0;
    std::wstring username;
    std::wstring full_name;
    std::wstring role;
};

struct ActiveLicenseInfo {
    bool blocked = false;
    std::wstring device_id;
    std::wstring activated_at;
    std::wstring expires_at;
};

struct AntivirusBasesInfoClient {
    bool loaded = false;
    std::wstring release_date;
    unsigned long long record_count = 0;
};

struct AntivirusScanInfo {
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

enum class RpcCallStatus {
    Success,
    NotFound,
    AccessDenied,
    Unavailable,
    Failed,
};

struct UserQueryResult {
    RpcCallStatus status = RpcCallStatus::Failed;
    AuthenticatedUserInfo user;
    std::wstring message;
};

struct LicenseQueryResult {
    RpcCallStatus status = RpcCallStatus::Failed;
    ActiveLicenseInfo license;
    std::wstring message;
};

struct BasesQueryResult {
    RpcCallStatus status = RpcCallStatus::Failed;
    AntivirusBasesInfoClient bases;
    std::wstring message;
};

struct ScanQueryResult {
    RpcCallStatus status = RpcCallStatus::Failed;
    AntivirusScanInfo scan;
    std::wstring message;
};

class WindowsServiceClient {
public:
    enum class StartupDecision {
        ContinueLaunch,
        ExitAfterServiceStart,
        ExitBecauseParentMismatch,
        ExitWithError,
    };

    StartupDecision PrepareForGuiLaunch(std::wstring* error_message) const;
    bool RequestServiceStop(std::wstring* error_message) const;

    UserQueryResult GetCurrentUser() const;
    UserQueryResult Login(const std::wstring& username, const std::wstring& password) const;
    RpcCallStatus Logout(std::wstring* error_message) const;
    LicenseQueryResult GetActiveLicense() const;
    LicenseQueryResult ActivateProduct(const std::wstring& activation_code) const;
    BasesQueryResult GetAntivirusBasesInfo() const;
    ScanQueryResult ScanFile(const std::wstring& file_path) const;
    ScanQueryResult ScanDirectory(const std::wstring& directory_path) const;

private:
    enum class ServiceState {
        Missing,
        Stopped,
        StartPending,
        Running,
        StopPending,
        Other,
    };

    ServiceState QueryServiceState(std::wstring* error_message = nullptr) const;
    bool StartServiceAndWait(std::wstring* error_message) const;
    bool WaitUntilRunning(unsigned long timeout_ms, std::wstring* error_message) const;
    bool IsParentServiceProcess(std::wstring* error_message = nullptr) const;
};
