#include "license_service.h"

#include <windows.h>

#include <cstdint>
#include <iomanip>
#include <sstream>

namespace {

std::wstring GetCurrentWindowsUserName() {
    wchar_t buffer[256] = {};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));

    if (GetUserNameW(buffer, &size) != FALSE && size > 1) {
        return std::wstring(buffer);
    }

    return L"unknown-user";
}

std::uint64_t ComputeFnv1a64(const std::wstring& value) {
    constexpr std::uint64_t kOffsetBasis = 14695981039346656037ull;
    constexpr std::uint64_t kPrime = 1099511628211ull;

    std::uint64_t hash = kOffsetBasis;
    for (wchar_t character : value) {
        hash ^= static_cast<std::uint64_t>(character);
        hash *= kPrime;
    }

    return hash;
}

std::wstring ToUpperHex(std::uint64_t value) {
    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setw(16) << std::setfill(L'0') << value;
    return stream.str();
}

}  // namespace

UserProfile LicenseService::GetCurrentUser() const {
    const std::wstring username = GetCurrentWindowsUserName();
    const std::wstring binding_id = L"USER-" + ToUpperHex(ComputeFnv1a64(username));

    return UserProfile{username, binding_id};
}

LicenseInfo LicenseService::GetLicenseForUser(const UserProfile& user) const {
    const std::uint64_t user_hash = ComputeFnv1a64(user.username);
    const std::wstring license_code = L"LIC-" + ToUpperHex(user_hash ^ 0xA55AA55AF0F00F0Full);

    return LicenseInfo{
        license_code,
        L"Student Demo",
        true,
    };
}

std::wstring LicenseService::BuildStatusText() const {
    const UserProfile user = GetCurrentUser();
    const LicenseInfo license = GetLicenseForUser(user);
    const ServerLicenseSnapshot snapshot = server_api_client_.FetchSnapshot();

    if (snapshot.server_reachable && snapshot.authenticated) {
        return BuildServerStatusText(user, license, snapshot);
    }

    std::wostringstream stream;
    stream << L"Client mode\r\n"
           << L"-----------\r\n"
           << L"Server integration: unavailable\r\n"
           << L"Reason: " << (snapshot.error_message.empty() ? L"Unknown error" : snapshot.error_message) << L"\r\n\r\n"
           << L"Local user profile\r\n"
           << L"------------------\r\n"
           << L"Username: " << user.username << L"\r\n"
           << L"Binding ID: " << user.binding_id << L"\r\n\r\n"
           << L"Local license stub\r\n"
           << L"------------------\r\n"
           << L"License code: " << license.license_code << L"\r\n"
           << L"Plan: " << license.plan_name << L"\r\n"
           << L"Status: " << (license.is_active ? L"Active" : L"Inactive") << L"\r\n\r\n"
           << L"Hint: start the backend and set INFOGUARD_API_USERNAME / INFOGUARD_API_PASSWORD to view server data.";

    return stream.str();
}

std::wstring LicenseService::BuildServerStatusText(
    const UserProfile& local_user,
    const LicenseInfo& local_license,
    const ServerLicenseSnapshot& snapshot) const {
    std::wostringstream stream;
    stream << L"Client mode\r\n"
           << L"-----------\r\n"
           << L"Server integration: connected\r\n"
           << L"API base URL: " << snapshot.api_base_url << L"\r\n"
           << L"Token type: " << (snapshot.token_type.empty() ? L"Bearer" : snapshot.token_type) << L"\r\n\r\n"
           << L"Authenticated server user\r\n"
           << L"-------------------------\r\n"
           << L"Username: " << snapshot.authenticated_username << L"\r\n"
           << L"Full name: " << snapshot.full_name << L"\r\n"
           << L"Role: " << snapshot.role << L"\r\n\r\n"
           << L"Server license\r\n"
           << L"--------------\r\n"
           << L"License code: " << (snapshot.license_key.empty() ? L"(none returned)" : snapshot.license_key) << L"\r\n"
           << L"Certificate number: " << snapshot.certificate_number << L"\r\n"
           << L"Status: " << (snapshot.license_active ? L"Active" : L"Inactive") << L"\r\n\r\n"
           << L"Local Windows user\r\n"
           << L"------------------\r\n"
           << L"Username: " << local_user.username << L"\r\n"
           << L"Binding ID: " << local_user.binding_id << L"\r\n\r\n"
           << L"Fallback local stub\r\n"
           << L"-------------------\r\n"
           << L"License code: " << local_license.license_code << L"\r\n"
           << L"Plan: " << local_license.plan_name << L"\r\n"
           << L"Status: " << (local_license.is_active ? L"Active" : L"Inactive");

    return stream.str();
}
