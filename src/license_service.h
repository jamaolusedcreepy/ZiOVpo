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
    std::wstring BuildStatusText(const ClientStateSnapshot& snapshot) const;

private:
    WindowsServiceClient service_client_;
};
