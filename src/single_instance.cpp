#include "single_instance.h"

#include <sddl.h>
#include <windows.h>

#include <vector>

namespace {

std::wstring GetCurrentUserIdentifier() {
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE) {
        return L"fallback";
    }

    DWORD required_size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &required_size);
    if (required_size == 0) {
        CloseHandle(token);
        return L"fallback";
    }

    std::vector<BYTE> buffer(required_size);
    if (GetTokenInformation(token, TokenUser, buffer.data(), required_size, &required_size) == FALSE) {
        CloseHandle(token);
        return L"fallback";
    }

    CloseHandle(token);

    const TOKEN_USER* token_user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR sid_string = nullptr;
    if (ConvertSidToStringSidW(token_user->User.Sid, &sid_string) == FALSE || sid_string == nullptr) {
        return L"fallback";
    }

    const std::wstring result = sid_string;
    LocalFree(sid_string);
    return result;
}

}  // namespace

SingleInstanceGuard::SingleInstanceGuard(std::wstring app_id)
    : mutex_name_(L"Local\\" + app_id + L"_" + GetCurrentUserIdentifier()) {
}

SingleInstanceGuard::~SingleInstanceGuard() {
    if (mutex_ != nullptr) {
        CloseHandle(mutex_);
    }
}

bool SingleInstanceGuard::Acquire() {
    mutex_ = CreateMutexW(nullptr, FALSE, mutex_name_.c_str());
    if (mutex_ == nullptr) {
        return false;
    }

    const DWORD last_error = GetLastError();
    return last_error != ERROR_ALREADY_EXISTS && last_error != ERROR_ACCESS_DENIED;
}
