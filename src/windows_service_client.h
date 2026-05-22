#pragma once

#include <string>

class WindowsServiceClient {
public:
    enum class StartupDecision {
        ContinueLaunch,
        ExitAfterServiceStart,
        ExitBecauseParentMismatch,
        ExitWithError,
    };

    StartupDecision PrepareForGuiLaunch(std::wstring* error_message) const;
    bool RequestServiceStop(std::wstring* error_message) const;

private:
    enum class ServiceState {
        Missing,
        Stopped,
        StartPending,
        Running,
        StopPending,
        Other,
    };

    ServiceState QueryServiceState(std::wstring* error_message = nullptr) const;
    bool StartServiceAndWait(std::wstring* error_message) const;
    bool WaitUntilRunning(unsigned long timeout_ms, std::wstring* error_message) const;
    bool IsParentServiceProcess(std::wstring* error_message = nullptr) const;
};
