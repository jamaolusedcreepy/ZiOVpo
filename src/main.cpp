#include <windows.h>
#include <shellapi.h>

#include <string>

#include "single_instance.h"
#include "tray_application.h"
#include "windows_service_client.h"

namespace {

bool StartsHidden() {
    int argument_count = 0;
    LPWSTR* arguments = CommandLineToArgvW(GetCommandLineW(), &argument_count);
    if (arguments == nullptr) {
        return false;
    }

    bool hidden = false;
    for (int index = 1; index < argument_count; ++index) {
        const std::wstring value = arguments[index];
        if (value == L"--hidden" || value == L"/hidden" || value == L"-hidden") {
            hidden = true;
            break;
        }
    }

    LocalFree(arguments);
    return hidden;
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
    WindowsServiceClient service_client;
    std::wstring error_message;
    switch (service_client.PrepareForGuiLaunch(&error_message)) {
    case WindowsServiceClient::StartupDecision::ContinueLaunch:
        break;

    case WindowsServiceClient::StartupDecision::ExitAfterServiceStart:
    case WindowsServiceClient::StartupDecision::ExitBecauseParentMismatch:
        return 0;

    case WindowsServiceClient::StartupDecision::ExitWithError:
        MessageBoxW(
            nullptr,
            error_message.empty() ? L"Failed to prepare the Windows service." : error_message.c_str(),
            L"InfoGuard Tray Application",
            MB_ICONERROR | MB_OK);
        return 1;
    }

    SingleInstanceGuard single_instance(L"InfoGuardTrayApp");
    if (!single_instance.Acquire()) {
        return 0;
    }

    TrayApplication app(instance, StartsHidden());
    if (!app.Initialize(show_command)) {
        return 1;
    }

    return app.Run();
}
