#pragma once

#include <string>

#include "windows_service_client.h"

struct ClientStateSnapshot {
    bool authenticated = false;
    std::wstring username;
    std::wstring full_name;
    std::wstring role;
    bool has_license = false;
    bool license_blocked = false;
    bool antivirus_unlocked = false;
    bool bases_loaded = false;
    unsigned long long bases_record_count = 0;
    std::wstring bases_release_date;
    std::wstring device_id;
    std::wstring activated_at;
    std::wstring expires_at;
    std::wstring message;
};

class LicenseService {
public:
    ClientStateSnapshot RefreshSnapshot() const;
    UserQueryResult Login(const std::wstring& username, const std::wstring& password) const;
    RpcCallStatus Logout(std::wstring* error_message) const;
    LicenseQueryResult ActivateProduct(const std::wstring& activation_code) const;
    BasesQueryResult GetAntivirusBasesInfo() const;
    ScanQueryResult ScanFile(const std::wstring& file_path) const;
    ScanQueryResult ScanDirectory(const std::wstring& directory_path) const;
    std::wstring BuildStatusText(const ClientStateSnapshot& snapshot) const;

private:
    WindowsServiceClient service_client_;
};
