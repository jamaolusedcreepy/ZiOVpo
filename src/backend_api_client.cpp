#include "backend_api_client.h"

#include <windows.h>
#include <winhttp.h>

#include <cctype>
#include <cwctype>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr wchar_t kDefaultBaseUrl[] = L"https://localhost:8443";
constexpr wchar_t kUserAgent[] = L"InfoGuardService/0.3";
constexpr unsigned long long kFileTimeTicksPerSecond = 10000000ull;

struct HttpResponse {
    bool transport_ok = false;
    DWORD status_code = 0;
    std::string body;
    std::wstring error_message;
};

std::wstring GetEnvironmentValue(const wchar_t* name, const wchar_t* fallback) {
    const DWORD required_size = GetEnvironmentVariableW(name, nullptr, 0);
    if (required_size == 0) {
        return std::wstring(fallback);
    }

    std::wstring value(required_size, L'\0');
    GetEnvironmentVariableW(name, value.data(), required_size);
    value.resize(required_size - 1);
    return value;
}

bool GetEnvironmentFlag(const wchar_t* name, bool fallback) {
    const std::wstring value = GetEnvironmentValue(name, fallback ? L"1" : L"0");
    if (value.empty()) {
        return fallback;
    }

    const wchar_t first = static_cast<wchar_t>(towupper(value.front()));
    return first == L'1' || first == L'Y' || first == L'T';
}

std::string ToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    std::string result(size > 0 ? size : 0, '\0');

    if (size > 0) {
        WideCharToMultiByte(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            result.data(),
            size,
            nullptr,
            nullptr);
    }

    return result;
}

std::wstring FromUtf8(const std::string& value) {
    if (value.empty()) {
        return {};
    }

    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(size, L'\0');

    if (size > 0) {
        MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    }

    return result;
}

std::wstring GetLastErrorMessage(DWORD error_code) {
    LPWSTR buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    if (length == 0 || buffer == nullptr) {
        std::wostringstream stream;
        stream << L"Win32 error " << error_code;
        return stream.str();
    }

    std::wstring result(buffer, length);
    LocalFree(buffer);

    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
        result.pop_back();
    }

    return result;
}

std::string EscapeJsonString(const std::wstring& value) {
    std::string utf8 = ToUtf8(value);
    std::string result;
    result.reserve(utf8.size() + 8);

    for (const unsigned char character : utf8) {
        switch (character) {
        case '\\':
            result += "\\\\";
            break;
        case '"':
            result += "\\\"";
            break;
        case '\b':
            result += "\\b";
            break;
        case '\f':
            result += "\\f";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            result.push_back(static_cast<char>(character));
            break;
        }
    }

    return result;
}

bool CrackUrl(const std::wstring& url, std::wstring* host, INTERNET_PORT* port, std::wstring* path, bool* secure) {
    std::wstring mutable_url = url;

    URL_COMPONENTSW components = {};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);

    if (WinHttpCrackUrl(mutable_url.data(), 0, 0, &components) == FALSE) {
        return false;
    }

    *host = std::wstring(components.lpszHostName, components.dwHostNameLength);
    *port = components.nPort;
    *path = std::wstring(components.lpszUrlPath, components.dwUrlPathLength);
    if (components.dwExtraInfoLength > 0) {
        path->append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    if (path->empty()) {
        *path = L"/";
    }

    *secure = components.nScheme == INTERNET_SCHEME_HTTPS;
    return true;
}

class ScopedInternetHandle {
public:
    explicit ScopedInternetHandle(HINTERNET handle = nullptr) : handle_(handle) {
    }

    ~ScopedInternetHandle() {
        if (handle_ != nullptr) {
            WinHttpCloseHandle(handle_);
        }
    }

    ScopedInternetHandle(const ScopedInternetHandle&) = delete;
    ScopedInternetHandle& operator=(const ScopedInternetHandle&) = delete;

    HINTERNET get() const {
        return handle_;
    }

private:
    HINTERNET handle_;
};

std::wstring GetBaseUrl() {
    return GetEnvironmentValue(L"INFOGUARD_API_URL", kDefaultBaseUrl);
}

bool IsInsecureTlsEnabled() {
    return GetEnvironmentFlag(L"INFOGUARD_API_INSECURE_TLS", true);
}

HttpResponse SendRequest(
    const std::wstring& method,
    const std::wstring& url,
    const std::wstring& headers,
    const std::string& body) {
    HttpResponse response;

    std::wstring host;
    std::wstring path;
    INTERNET_PORT port = 0;
    bool secure = false;

    if (!CrackUrl(url, &host, &port, &path, &secure)) {
        response.error_message = L"Unable to parse server URL.";
        return response;
    }

    ScopedInternetHandle session(WinHttpOpen(
        kUserAgent,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0));
    if (session.get() == nullptr) {
        response.error_message = L"WinHttpOpen failed: " + GetLastErrorMessage(GetLastError());
        return response;
    }

    WinHttpSetTimeouts(session.get(), 2000, 2000, 5000, 5000);

    ScopedInternetHandle connection(WinHttpConnect(session.get(), host.c_str(), port, 0));
    if (connection.get() == nullptr) {
        response.error_message = L"WinHttpConnect failed: " + GetLastErrorMessage(GetLastError());
        return response;
    }

    ScopedInternetHandle request(WinHttpOpenRequest(
        connection.get(),
        method.c_str(),
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        secure ? WINHTTP_FLAG_SECURE : 0));
    if (request.get() == nullptr) {
        response.error_message = L"WinHttpOpenRequest failed: " + GetLastErrorMessage(GetLastError());
        return response;
    }

    if (secure && IsInsecureTlsEnabled()) {
        DWORD security_flags =
            SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags));
    }

    if (!headers.empty()) {
        if (WinHttpAddRequestHeaders(
                request.get(),
                headers.c_str(),
                static_cast<DWORD>(-1),
                WINHTTP_ADDREQ_FLAG_ADD) == FALSE) {
            response.error_message = L"WinHttpAddRequestHeaders failed: " + GetLastErrorMessage(GetLastError());
            return response;
        }
    }

    if (WinHttpSendRequest(
            request.get(),
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
            static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()),
            0) == FALSE) {
        response.error_message = L"WinHttpSendRequest failed: " + GetLastErrorMessage(GetLastError());
        return response;
    }

    if (WinHttpReceiveResponse(request.get(), nullptr) == FALSE) {
        response.error_message = L"WinHttpReceiveResponse failed: " + GetLastErrorMessage(GetLastError());
        return response;
    }

    response.transport_ok = true;

    DWORD status_code = 0;
    DWORD status_code_size = sizeof(status_code);
    WinHttpQueryHeaders(
        request.get(),
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status_code,
        &status_code_size,
        WINHTTP_NO_HEADER_INDEX);
    response.status_code = status_code;

    for (;;) {
        DWORD available_size = 0;
        if (WinHttpQueryDataAvailable(request.get(), &available_size) == FALSE) {
            response.error_message = L"WinHttpQueryDataAvailable failed: " + GetLastErrorMessage(GetLastError());
            return response;
        }

        if (available_size == 0) {
            break;
        }

        std::vector<char> buffer(available_size);
        DWORD bytes_read = 0;
        if (WinHttpReadData(request.get(), buffer.data(), available_size, &bytes_read) == FALSE) {
            response.error_message = L"WinHttpReadData failed: " + GetLastErrorMessage(GetLastError());
            return response;
        }

        response.body.append(buffer.data(), bytes_read);
    }

    return response;
}

std::size_t FindValueStart(std::string_view json, const std::string& key) {
    const std::string token = "\"" + key + "\"";
    const std::size_t key_position = json.find(token);
    if (key_position == std::string_view::npos) {
        return std::string_view::npos;
    }

    const std::size_t colon_position = json.find(':', key_position + token.size());
    if (colon_position == std::string_view::npos) {
        return std::string_view::npos;
    }

    std::size_t value_position = colon_position + 1;
    while (value_position < json.size() && std::isspace(static_cast<unsigned char>(json[value_position])) != 0) {
        ++value_position;
    }

    return value_position;
}

bool ExtractJsonString(std::string_view json, const std::string& key, std::string* value) {
    const std::size_t position_start = FindValueStart(json, key);
    if (position_start == std::string_view::npos || position_start >= json.size() || json[position_start] != '"') {
        return false;
    }

    std::size_t position = position_start + 1;
    std::string result;

    while (position < json.size()) {
        const char character = json[position++];
        if (character == '\\') {
            if (position >= json.size()) {
                return false;
            }

            const char escaped = json[position++];
            switch (escaped) {
            case '"':
            case '\\':
            case '/':
                result.push_back(escaped);
                break;
            case 'b':
                result.push_back('\b');
                break;
            case 'f':
                result.push_back('\f');
                break;
            case 'n':
                result.push_back('\n');
                break;
            case 'r':
                result.push_back('\r');
                break;
            case 't':
                result.push_back('\t');
                break;
            default:
                return false;
            }
            continue;
        }

        if (character == '"') {
            *value = result;
            return true;
        }

        result.push_back(character);
    }

    return false;
}

bool ExtractJsonBool(std::string_view json, const std::string& key, bool* value) {
    const std::size_t position = FindValueStart(json, key);
    if (position == std::string_view::npos) {
        return false;
    }

    if (json.substr(position, 4) == "true") {
        *value = true;
        return true;
    }

    if (json.substr(position, 5) == "false") {
        *value = false;
        return true;
    }

    return false;
}

bool ExtractJsonUnsignedLongLong(std::string_view json, const std::string& key, unsigned long long* value) {
    const std::size_t position = FindValueStart(json, key);
    if (position == std::string_view::npos) {
        return false;
    }

    std::size_t end_position = position;
    while (end_position < json.size() && std::isdigit(static_cast<unsigned char>(json[end_position])) != 0) {
        ++end_position;
    }

    if (end_position == position) {
        return false;
    }

    try {
        *value = std::stoull(std::string(json.substr(position, end_position - position)));
        return true;
    } catch (...) {
        return false;
    }
}

bool ParseIso8601Utc(const std::wstring& value, unsigned long long* file_time) {
    if (value.size() < 20) {
        return false;
    }

    SYSTEMTIME system_time = {};
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;

    if (swscanf_s(
            value.c_str(),
            L"%4d-%2d-%2dT%2d:%2d:%2d",
            &year,
            &month,
            &day,
            &hour,
            &minute,
            &second) != 6) {
        return false;
    }

    system_time.wYear = static_cast<WORD>(year);
    system_time.wMonth = static_cast<WORD>(month);
    system_time.wDay = static_cast<WORD>(day);
    system_time.wHour = static_cast<WORD>(hour);
    system_time.wMinute = static_cast<WORD>(minute);
    system_time.wSecond = static_cast<WORD>(second);

    FILETIME ft = {};
    if (SystemTimeToFileTime(&system_time, &ft) == FALSE) {
        return false;
    }

    ULARGE_INTEGER large = {};
    large.LowPart = ft.dwLowDateTime;
    large.HighPart = ft.dwHighDateTime;
    *file_time = large.QuadPart;
    return true;
}

std::wstring BuildErrorMessage(const HttpResponse& response, const wchar_t* fallback_prefix) {
    if (!response.error_message.empty()) {
        return response.error_message;
    }

    std::string backend_message;
    if (ExtractJsonString(response.body, "message", &backend_message) && !backend_message.empty()) {
        return FromUtf8(backend_message);
    }

    std::wostringstream stream;
    stream << fallback_prefix << L" HTTP status " << response.status_code << L".";
    return stream.str();
}

bool ParseTokenResponse(
    const HttpResponse& response,
    BackendTokenBundle* tokens,
    std::wstring* error_message) {
    std::string access_token;
    std::string refresh_token;
    std::string access_expires_at;
    std::string refresh_expires_at;
    std::string username;
    std::string full_name;
    std::string role;
    unsigned long long user_id = 0;

    if (!ExtractJsonString(response.body, "accessToken", &access_token) || access_token.empty()) {
        *error_message = L"Backend response did not contain accessToken.";
        return false;
    }

    if (!ExtractJsonString(response.body, "refreshToken", &refresh_token) || refresh_token.empty()) {
        *error_message = L"Backend response did not contain refreshToken.";
        return false;
    }

    if (!ExtractJsonString(response.body, "accessTokenExpiresAt", &access_expires_at) ||
        !ExtractJsonString(response.body, "refreshTokenExpiresAt", &refresh_expires_at) ||
        !ExtractJsonUnsignedLongLong(response.body, "id", &user_id) ||
        !ExtractJsonString(response.body, "username", &username) ||
        !ExtractJsonString(response.body, "fullName", &full_name) ||
        !ExtractJsonString(response.body, "role", &role)) {
        *error_message = L"Backend response did not contain the expected authentication payload.";
        return false;
    }

    const std::wstring access_expires_w = FromUtf8(access_expires_at);
    const std::wstring refresh_expires_w = FromUtf8(refresh_expires_at);

    if (!ParseIso8601Utc(access_expires_w, &tokens->access_expires_at) ||
        !ParseIso8601Utc(refresh_expires_w, &tokens->refresh_expires_at)) {
        *error_message = L"Unable to parse JWT expiration timestamps.";
        return false;
    }

    tokens->access_token = FromUtf8(access_token);
    tokens->refresh_token = FromUtf8(refresh_token);
    tokens->user.user_id = user_id;
    tokens->user.username = FromUtf8(username);
    tokens->user.full_name = FromUtf8(full_name);
    tokens->user.role = FromUtf8(role);
    return true;
}

bool ParseTicketResponse(
    const HttpResponse& response,
    BackendTicketInfo* ticket,
    std::wstring* error_message) {
    std::string server_date;
    std::string activated_at;
    std::string expires_at;
    std::string device_id;
    std::string signature;
    unsigned long long ticket_lifetime_seconds = 0;
    unsigned long long user_id = 0;
    bool blocked = false;

    if (!ExtractJsonString(response.body, "serverDate", &server_date) ||
        !ExtractJsonUnsignedLongLong(response.body, "ticketLifetimeSeconds", &ticket_lifetime_seconds) ||
        !ExtractJsonString(response.body, "licenseActivatedAt", &activated_at) ||
        !ExtractJsonString(response.body, "licenseExpiresAt", &expires_at) ||
        !ExtractJsonUnsignedLongLong(response.body, "userId", &user_id) ||
        !ExtractJsonString(response.body, "deviceId", &device_id) ||
        !ExtractJsonBool(response.body, "blocked", &blocked) ||
        !ExtractJsonString(response.body, "signature", &signature)) {
        *error_message = L"Backend response did not contain the expected license ticket payload.";
        return false;
    }

    ticket->ticket_lifetime_seconds = ticket_lifetime_seconds;
    ticket->user_id = user_id;
    ticket->device_id = FromUtf8(device_id);
    ticket->activated_at_text = FromUtf8(activated_at);
    ticket->expires_at_text = FromUtf8(expires_at);
    ticket->blocked = blocked;
    ticket->signature = FromUtf8(signature);

    if (!ParseIso8601Utc(FromUtf8(server_date), &ticket->server_date) ||
        !ParseIso8601Utc(ticket->activated_at_text, &ticket->activated_at) ||
        !ParseIso8601Utc(ticket->expires_at_text, &ticket->expires_at)) {
        *error_message = L"Unable to parse license ticket timestamps.";
        return false;
    }

    return true;
}

std::wstring BuildAuthorizationHeader(const std::wstring& access_token) {
    return L"Authorization: Bearer " + access_token + L"\r\n";
}

}  // namespace

bool BackendApiClient::Login(
    const std::wstring& username,
    const std::wstring& password,
    BackendTokenBundle* tokens,
    std::wstring* error_message) const {
    const std::string body = std::string("{\"username\":\"") +
        EscapeJsonString(username) +
        "\",\"password\":\"" +
        EscapeJsonString(password) +
        "\"}";

    const HttpResponse response = SendRequest(
        L"POST",
        GetBaseUrl() + L"/api/auth/login",
        L"Content-Type: application/json\r\n",
        body);

    if (!response.transport_ok) {
        *error_message = response.error_message;
        return false;
    }

    if (response.status_code != 200) {
        *error_message = BuildErrorMessage(response, L"Authentication failed with");
        return false;
    }

    return ParseTokenResponse(response, tokens, error_message);
}

bool BackendApiClient::Refresh(
    const std::wstring& refresh_token,
    BackendTokenBundle* tokens,
    std::wstring* error_message) const {
    const std::string body = std::string("{\"refreshToken\":\"") +
        EscapeJsonString(refresh_token) +
        "\"}";

    const HttpResponse response = SendRequest(
        L"POST",
        GetBaseUrl() + L"/api/auth/refresh",
        L"Content-Type: application/json\r\n",
        body);

    if (!response.transport_ok) {
        *error_message = response.error_message;
        return false;
    }

    if (response.status_code != 200) {
        *error_message = BuildErrorMessage(response, L"Token refresh failed with");
        return false;
    }

    return ParseTokenResponse(response, tokens, error_message);
}

bool BackendApiClient::Logout(
    const std::wstring& refresh_token,
    std::wstring* error_message) const {
    const std::string body = std::string("{\"refreshToken\":\"") +
        EscapeJsonString(refresh_token) +
        "\"}";

    const HttpResponse response = SendRequest(
        L"POST",
        GetBaseUrl() + L"/api/auth/logout",
        L"Content-Type: application/json\r\n",
        body);

    if (!response.transport_ok) {
        *error_message = response.error_message;
        return false;
    }

    if (response.status_code != 200) {
        *error_message = BuildErrorMessage(response, L"Logout failed with");
        return false;
    }

    return true;
}

bool BackendApiClient::GetCurrentLicense(
    const std::wstring& access_token,
    const std::wstring& device_id,
    BackendTicketInfo* ticket,
    std::wstring* error_message,
    bool* license_missing) const {
    if (license_missing != nullptr) {
        *license_missing = false;
    }

    const HttpResponse response = SendRequest(
        L"GET",
        GetBaseUrl() + L"/api/licenses/current?deviceId=" + device_id,
        BuildAuthorizationHeader(access_token),
        "");

    if (!response.transport_ok) {
        *error_message = response.error_message;
        return false;
    }

    if (response.status_code == 404) {
        if (license_missing != nullptr) {
            *license_missing = true;
        }
        *error_message = BuildErrorMessage(response, L"No active license is available.");
        return false;
    }

    if (response.status_code != 200) {
        *error_message = BuildErrorMessage(response, L"License status request failed with");
        return false;
    }

    return ParseTicketResponse(response, ticket, error_message);
}

bool BackendApiClient::ActivateLicense(
    const std::wstring& access_token,
    const std::wstring& activation_code,
    const std::wstring& device_id,
    BackendTicketInfo* ticket,
    std::wstring* error_message,
    bool* license_missing) const {
    if (license_missing != nullptr) {
        *license_missing = false;
    }

    const std::string body = std::string("{\"licenseKey\":\"") +
        EscapeJsonString(activation_code) +
        "\",\"deviceId\":\"" +
        EscapeJsonString(device_id) +
        "\"}";

    const HttpResponse response = SendRequest(
        L"POST",
        GetBaseUrl() + L"/api/licenses/activate",
        BuildAuthorizationHeader(access_token) + L"Content-Type: application/json\r\n",
        body);

    if (!response.transport_ok) {
        *error_message = response.error_message;
        return false;
    }

    if (response.status_code == 404) {
        if (license_missing != nullptr) {
            *license_missing = true;
        }
        *error_message = BuildErrorMessage(response, L"Activation failed:");
        return false;
    }

    if (response.status_code != 200) {
        *error_message = BuildErrorMessage(response, L"Activation failed with");
        return false;
    }

    return ParseTicketResponse(response, ticket, error_message);
}
