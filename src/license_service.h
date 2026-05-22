#pragma once

#include <string>

#include "server_api_client.h"

struct UserProfile {
    std::wstring username;
    std::wstring binding_id;
};

struct LicenseInfo {
    std::wstring license_code;
    std::wstring plan_name;
    bool is_active = false;
};

class LicenseService {
public:
    UserProfile GetCurrentUser() const;
    LicenseInfo GetLicenseForUser(const UserProfile& user) const;
    std::wstring BuildStatusText() const;

private:
    std::wstring BuildServerStatusText(
        const UserProfile& local_user,
        const LicenseInfo& local_license,
        const ServerLicenseSnapshot& snapshot) const;

    ServerApiClient server_api_client_;
};
