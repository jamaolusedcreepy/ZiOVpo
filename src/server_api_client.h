#pragma once

#include <string>

struct ServerLicenseSnapshot {
    bool server_reachable = false;
    bool authenticated = false;
    std::wstring api_base_url;
    std::wstring authenticated_username;
    std::wstring full_name;
    std::wstring role;
    std::wstring token_type;
    std::wstring license_key;
    unsigned long long certificate_number = 0;
    bool license_active = false;
    std::wstring error_message;
};

class ServerApiClient {
public:
    ServerLicenseSnapshot FetchSnapshot() const;
};
