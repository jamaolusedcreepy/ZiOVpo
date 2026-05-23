#pragma once

namespace service_constants {

inline constexpr wchar_t kServiceName[] = L"InfoGuardService";
inline constexpr wchar_t kServiceDisplayName[] = L"InfoGuard Session Service";
inline constexpr wchar_t kServiceDescription[] =
    L"Launches the InfoGuard tray client inside user terminal sessions and exposes an RPC control endpoint.";
inline constexpr wchar_t kServiceExecutableName[] = L"InfoGuardService.exe";
inline constexpr wchar_t kClientExecutableName[] = L"InfoGuardTrayApp.exe";
inline constexpr wchar_t kRpcProtocolSequence[] = L"ncalrpc";
inline constexpr wchar_t kRpcEndpoint[] = L"InfoGuardServiceControl";
inline constexpr wchar_t kHiddenArgument[] = L"--hidden";

}  // namespace service_constants
