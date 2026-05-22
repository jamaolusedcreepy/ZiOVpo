#include "license_service.h"

#include <sstream>

ClientStateSnapshot LicenseService::RefreshSnapshot() const {
    ClientStateSnapshot snapshot;

    const UserQueryResult user_result = service_client_.GetCurrentUser();
    if (user_result.status != RpcCallStatus::Success) {
        snapshot.message = user_result.message.empty()
            ? L"Sign in to unlock product activation and antivirus functionality."
            : user_result.message;
        return snapshot;
    }

    snapshot.authenticated = true;
    snapshot.username = user_result.user.username;
    snapshot.full_name = user_result.user.full_name;
    snapshot.role = user_result.user.role;

    const LicenseQueryResult license_result = service_client_.GetActiveLicense();
    if (license_result.status != RpcCallStatus::Success) {
        snapshot.message = license_result.status == RpcCallStatus::NotFound
            ? L"No active license ticket is available. Activate the product to continue."
            : (license_result.message.empty() ? L"Unable to retrieve the current license state." : license_result.message);
        return snapshot;
    }

    snapshot.has_license = true;
    snapshot.license_blocked = license_result.license.blocked;
    snapshot.device_id = license_result.license.device_id;
    snapshot.activated_at = license_result.license.activated_at;
    snapshot.expires_at = license_result.license.expires_at;
    snapshot.antivirus_unlocked = !snapshot.license_blocked;
    snapshot.message = snapshot.license_blocked
        ? L"The active license is blocked. Antivirus functionality remains disabled."
        : L"The product is activated. Antivirus functionality is unlocked.";
    return snapshot;
}

UserQueryResult LicenseService::Login(const std::wstring& username, const std::wstring& password) const {
    return service_client_.Login(username, password);
}

RpcCallStatus LicenseService::Logout(std::wstring* error_message) const {
    return service_client_.Logout(error_message);
}

LicenseQueryResult LicenseService::ActivateProduct(const std::wstring& activation_code) const {
    return service_client_.ActivateProduct(activation_code);
}

std::wstring LicenseService::BuildStatusText(const ClientStateSnapshot& snapshot) const {
    std::wostringstream stream;
    stream << L"Account status\r\n"
           << L"--------------\r\n";

    if (!snapshot.authenticated) {
        stream << L"Signed in: no\r\n"
               << L"Antivirus functionality: blocked\r\n\r\n"
               << L"Action required\r\n"
               << L"---------------\r\n"
               << (snapshot.message.empty()
                       ? L"Use the authentication form below to sign in."
                       : snapshot.message);
        return stream.str();
    }

    stream << L"Signed in: yes\r\n"
           << L"Username: " << snapshot.username << L"\r\n"
           << L"Full name: " << snapshot.full_name << L"\r\n"
           << L"Role: " << snapshot.role << L"\r\n\r\n"
           << L"License status\r\n"
           << L"--------------\r\n";

    if (!snapshot.has_license) {
        stream << L"Activation state: not activated\r\n"
               << L"Antivirus functionality: blocked\r\n\r\n"
               << L"Action required\r\n"
               << L"---------------\r\n"
               << (snapshot.message.empty()
                       ? L"Enter an activation code to request a license ticket from the Windows service."
                       : snapshot.message);
        return stream.str();
    }

    stream << L"Activation state: active\r\n"
           << L"Device ID: " << snapshot.device_id << L"\r\n"
           << L"Activated at: " << snapshot.activated_at << L"\r\n"
           << L"Expires at: " << snapshot.expires_at << L"\r\n"
           << L"Blocked: " << (snapshot.license_blocked ? L"yes" : L"no") << L"\r\n"
           << L"Antivirus functionality: " << (snapshot.antivirus_unlocked ? L"unlocked" : L"blocked") << L"\r\n\r\n"
           << L"Current state\r\n"
           << L"-------------\r\n"
           << (snapshot.message.empty() ? L"Status synchronized with the Windows service." : snapshot.message);
    return stream.str();
}
