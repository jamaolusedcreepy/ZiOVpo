#pragma once

#include <string>
#include <vector>

struct BackendUserInfo {
    unsigned long long user_id = 0;
    std::wstring username;
    std::wstring full_name;
    std::wstring role;
};

struct BackendTokenBundle {
    std::wstring access_token;
    std::wstring refresh_token;
    unsigned long long access_expires_at = 0;
    unsigned long long refresh_expires_at = 0;
    BackendUserInfo user;
};

struct BackendTicketInfo {
    unsigned long long server_date = 0;
    unsigned long long ticket_lifetime_seconds = 0;
    unsigned long long activated_at = 0;
    unsigned long long expires_at = 0;
    unsigned long long user_id = 0;
    std::wstring device_id;
    std::wstring activated_at_text;
    std::wstring expires_at_text;
    bool blocked = false;
    std::wstring signature;
};

class BackendApiClient {
public:
    bool Login(
        const std::wstring& username,
        const std::wstring& password,
        BackendTokenBundle* tokens,
        std::wstring* error_message) const;

    bool Refresh(
        const std::wstring& refresh_token,
        BackendTokenBundle* tokens,
        std::wstring* error_message) const;

    bool Logout(
        const std::wstring& refresh_token,
        std::wstring* error_message) const;

    bool GetCurrentLicense(
        const std::wstring& access_token,
        const std::wstring& device_id,
        BackendTicketInfo* ticket,
        std::wstring* error_message,
        bool* license_missing = nullptr) const;

    bool ActivateLicense(
        const std::wstring& access_token,
        const std::wstring& activation_code,
        const std::wstring& device_id,
        BackendTicketInfo* ticket,
        std::wstring* error_message,
        bool* license_missing = nullptr) const;

    bool DownloadAntivirusBasesPackage(
        std::vector<std::uint8_t>* package_bytes,
        std::wstring* error_message) const;
};
