#include <windows.h>
#include <shellapi.h>

#include <string>

#include "single_instance.h"
#include "tray_application.h"

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
