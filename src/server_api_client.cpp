#include "server_api_client.h"

#include <windows.h>
#include <winhttp.h>

#include <cctype>
#include <cstdint>
#include <cwctype>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr wchar_t kDefaultBaseUrl[] = L"https://localhost:8443";
constexpr wchar_t kDefaultUsername[] = L"admin";
constexpr wchar_t kDefaultPassword[] = L"Admin23358!";
constexpr wchar_t kUserAgent[] = L"InfoGuardTrayApp/0.1";

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

    HINTERNET release() {
        HINTERNET handle = handle_;
        handle_ = nullptr;
        return handle;
    }

private:
    HINTERNET handle_;
};

HttpResponse SendRequest(
    const std::wstring& method,
    const std::wstring& url,
    const std::wstring& headers,
    const std::string& body,
    bool insecure_tls) {
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

    WinHttpSetTimeouts(session.get(), 1000, 1000, 3000, 3000);

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

    if (secure && insecure_tls) {
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
    std::size_t position = FindValueStart(json, key);
    if (position == std::string_view::npos || position >= json.size() || json[position] != '"') {
        return false;
    }

    ++position;
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

}  // namespace

ServerLicenseSnapshot ServerApiClient::FetchSnapshot() const {
    ServerLicenseSnapshot snapshot;

    if (!GetEnvironmentFlag(L"INFOGUARD_API_ENABLED", true)) {
        snapshot.error_message = L"Server integration is disabled by INFOGUARD_API_ENABLED=0.";
        return snapshot;
    }

    snapshot.api_base_url = GetEnvironmentValue(L"INFOGUARD_API_URL", kDefaultBaseUrl);
    const std::wstring username = GetEnvironmentValue(L"INFOGUARD_API_USERNAME", kDefaultUsername);
    const std::wstring password = GetEnvironmentValue(L"INFOGUARD_API_PASSWORD", kDefaultPassword);
    const bool insecure_tls = GetEnvironmentFlag(L"INFOGUARD_API_INSECURE_TLS", false);

    const HttpResponse ping_response = SendRequest(
        L"GET",
        snapshot.api_base_url + L"/api/public/ping",
        L"",
        "",
        insecure_tls);
    if (!ping_response.transport_ok || ping_response.status_code != 200) {
        snapshot.error_message = ping_response.error_message.empty()
            ? L"Server ping failed with HTTP status " + std::to_wstring(ping_response.status_code) + L"."
            : ping_response.error_message;
        return snapshot;
    }

    snapshot.server_reachable = true;

    const std::string login_body = std::string("{\"username\":\"") +
        EscapeJsonString(username) +
        "\",\"password\":\"" +
        EscapeJsonString(password) +
        "\"}";

    const HttpResponse login_response = SendRequest(
        L"POST",
        snapshot.api_base_url + L"/api/auth/login",
        L"Content-Type: application/json\r\n",
        login_body,
        insecure_tls);
    if (!login_response.transport_ok) {
        snapshot.error_message = login_response.error_message;
        return snapshot;
    }

    if (login_response.status_code != 200) {
        snapshot.error_message =
            L"Authentication failed with HTTP status " + std::to_wstring(login_response.status_code) + L".";
        return snapshot;
    }

    std::string access_token;
    if (!ExtractJsonString(login_response.body, "accessToken", &access_token) || access_token.empty()) {
        snapshot.error_message = L"Authentication succeeded, but no accessToken was returned.";
        return snapshot;
    }

    snapshot.authenticated = true;

    const std::wstring authorization_header = L"Authorization: Bearer " + FromUtf8(access_token) + L"\r\n";
    const HttpResponse bootstrap_response = SendRequest(
        L"GET",
        snapshot.api_base_url + L"/api/client/bootstrap",
        authorization_header,
        "",
        insecure_tls);
    if (!bootstrap_response.transport_ok) {
        snapshot.error_message = bootstrap_response.error_message;
        return snapshot;
    }

    if (bootstrap_response.status_code != 200) {
        snapshot.error_message =
            L"Bootstrap request failed with HTTP status " + std::to_wstring(bootstrap_response.status_code) + L".";
        return snapshot;
    }

    std::string string_value;
    if (ExtractJsonString(bootstrap_response.body, "apiBaseUrl", &string_value)) {
        snapshot.api_base_url = FromUtf8(string_value);
    }
    if (ExtractJsonString(bootstrap_response.body, "username", &string_value)) {
        snapshot.authenticated_username = FromUtf8(string_value);
    }
    if (ExtractJsonString(bootstrap_response.body, "fullName", &string_value)) {
        snapshot.full_name = FromUtf8(string_value);
    }
    if (ExtractJsonString(bootstrap_response.body, "role", &string_value)) {
        snapshot.role = FromUtf8(string_value);
    }
    if (ExtractJsonString(bootstrap_response.body, "tokenType", &string_value)) {
        snapshot.token_type = FromUtf8(string_value);
    }
    if (ExtractJsonString(bootstrap_response.body, "licenseKey", &string_value)) {
        snapshot.license_key = FromUtf8(string_value);
    }

    ExtractJsonUnsignedLongLong(bootstrap_response.body, "certificateNumber", &snapshot.certificate_number);
    ExtractJsonBool(bootstrap_response.body, "active", &snapshot.license_active);

    return snapshot;
}
