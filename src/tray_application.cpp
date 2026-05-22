#include "tray_application.h"

#include <shellapi.h>
#include <windows.h>

#include "windows_service_client.h"

namespace {

constexpr wchar_t kWindowTitle[] = L"InfoGuard Tray Application";
constexpr wchar_t kTooltipText[] = L"InfoGuard Tray Application";
constexpr wchar_t kMenuFile[] = L"\u0424\u0430\u0439\u043b";
constexpr wchar_t kMenuOpen[] = L"\u041e\u0442\u043a\u0440\u044b\u0442\u044c";
constexpr wchar_t kMenuExit[] = L"\u0412\u044b\u0445\u043e\u0434";

}  // namespace

TrayApplication::TrayApplication(HINSTANCE instance, bool start_hidden)
    : instance_(instance), start_hidden_(start_hidden) {
}

bool TrayApplication::Initialize(int show_command) {
    taskbar_created_message_ = RegisterWindowMessageW(L"TaskbarCreated");
    icon_ = LoadIconW(nullptr, IDI_APPLICATION);

    if (!CreateMainWindow()) {
        return false;
    }

    if (!AddTrayIcon()) {
        DestroyWindow(window_);
        window_ = nullptr;
        return false;
    }

    if (!start_hidden_) {
        ShowMainWindow(show_command);
    }

    return true;
}

int TrayApplication::Run() const {
    MSG message = {};

    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return static_cast<int>(message.wParam);
}

bool TrayApplication::CreateMainWindow() {
    WNDCLASSEXW window_class = {};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = &TrayApplication::WindowProc;
    window_class.hInstance = instance_;
    window_class.lpszClassName = kWindowClassName;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.hIcon = icon_;
    window_class.hIconSm = icon_;
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    if (RegisterClassExW(&window_class) == 0) {
        return false;
    }

    window_ = CreateWindowExW(
        0,
        kWindowClassName,
        kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        620,
        380,
        nullptr,
        nullptr,
        instance_,
        this);

    if (window_ == nullptr) {
        return false;
    }

    CreateMainMenu();
    UpdateStatusText();
    return true;
}

void TrayApplication::CreateMainMenu() const {
    HMENU menu_bar = CreateMenu();
    HMENU file_menu = CreatePopupMenu();

    AppendMenuW(file_menu, MF_STRING, kCommandFileExit, kMenuExit);
    AppendMenuW(menu_bar, MF_POPUP, reinterpret_cast<UINT_PTR>(file_menu), kMenuFile);

    SetMenu(window_, menu_bar);
    DrawMenuBar(window_);
}

bool TrayApplication::AddTrayIcon() {
    NOTIFYICONDATAW notify_data = {};
    notify_data.cbSize = sizeof(notify_data);
    notify_data.hWnd = window_;
    notify_data.uID = kTrayIconId;
    notify_data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    notify_data.uCallbackMessage = kTrayCallbackMessage;
    notify_data.hIcon = icon_;

    lstrcpynW(
        notify_data.szTip,
        kTooltipText,
        static_cast<int>(sizeof(notify_data.szTip) / sizeof(notify_data.szTip[0])));

    if (Shell_NotifyIconW(NIM_ADD, &notify_data) == FALSE) {
        return false;
    }

    notify_data.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &notify_data);
    tray_icon_added_ = true;
    return true;
}

void TrayApplication::RemoveTrayIcon() {
    if (!tray_icon_added_) {
        return;
    }

    NOTIFYICONDATAW notify_data = {};
    notify_data.cbSize = sizeof(notify_data);
    notify_data.hWnd = window_;
    notify_data.uID = kTrayIconId;

    Shell_NotifyIconW(NIM_DELETE, &notify_data);
    tray_icon_added_ = false;
}

void TrayApplication::ShowMainWindow(int show_command) {
    UpdateStatusText();
    const int effective_show_command =
        (IsIconic(window_) != FALSE || show_command == SW_SHOWMINIMIZED) ? SW_RESTORE : SW_SHOW;
    ShowWindow(window_, effective_show_command);
    SetForegroundWindow(window_);
}

void TrayApplication::HideMainWindow() const {
    ShowWindow(window_, SW_HIDE);
}

void TrayApplication::ShowTrayMenu() {
    POINT cursor_position = {};
    GetCursorPos(&cursor_position);

    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, kCommandOpen, kMenuOpen);
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kCommandTrayExit, kMenuExit);

    SetForegroundWindow(window_);
    TrackPopupMenu(
        menu,
        TPM_BOTTOMALIGN | TPM_LEFTALIGN | TPM_RIGHTBUTTON,
        cursor_position.x,
        cursor_position.y,
        0,
        window_,
        nullptr);
    PostMessageW(window_, WM_NULL, 0, 0);

    DestroyMenu(menu);
}

void TrayApplication::UpdateStatusText() const {
    if (status_label_ == nullptr) {
        return;
    }

    const std::wstring text = license_service_.BuildStatusText();
    SetWindowTextW(status_label_, text.c_str());
}

void TrayApplication::HandleExitCommand() {
    WindowsServiceClient service_client;
    std::wstring error_message;
    if (!service_client.RequestServiceStop(&error_message)) {
        const wchar_t* message =
            error_message.empty() ? L"Failed to stop the Windows service." : error_message.c_str();
        MessageBoxW(window_, message, kWindowTitle, MB_ICONERROR | MB_OK);
        return;
    }

    RequestExit();
}

void TrayApplication::RequestExit() {
    exit_requested_ = true;
    DestroyWindow(window_);
}

LRESULT TrayApplication::HandleMessage(UINT message, WPARAM w_param, LPARAM l_param) {
    if (message == taskbar_created_message_) {
        tray_icon_added_ = false;
        AddTrayIcon();
        return 0;
    }

    switch (message) {
    case WM_NCCREATE:
        return TRUE;

    case WM_CREATE:
        status_label_ = CreateWindowExW(
            0,
            L"STATIC",
            L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            20,
            20,
            560,
            280,
            window_,
            nullptr,
            instance_,
            nullptr);

        if (status_label_ != nullptr) {
            SendMessageW(
                status_label_,
                WM_SETFONT,
                reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),
                TRUE);
        }

        UpdateStatusText();
        return 0;

    case WM_SIZE:
        if (status_label_ != nullptr) {
            const int width = LOWORD(l_param);
            const int height = HIWORD(l_param);
            const int control_width = width > 40 ? width - 40 : 1;
            const int control_height = height > 40 ? height - 40 : 1;
            MoveWindow(status_label_, 20, 20, control_width, control_height, TRUE);
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(w_param)) {
        case kCommandOpen:
            ShowMainWindow();
            return 0;

        case kCommandTrayExit:
        case kCommandFileExit:
            HandleExitCommand();
            return 0;

        default:
            break;
        }
        break;

    case kTrayCallbackMessage:
        switch (LOWORD(l_param)) {
        case WM_LBUTTONUP:
        case NIN_SELECT:
            ShowMainWindow();
            return 0;

        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowTrayMenu();
            return 0;

        default:
            break;
        }
        return 0;

    case WM_CLOSE:
        if (!exit_requested_) {
            HideMainWindow();
            return 0;
        }
        break;

    case WM_DESTROY:
        RemoveTrayIcon();
        PostQuitMessage(0);
        return 0;

    default:
        break;
    }

    return DefWindowProcW(window_, message, w_param, l_param);
}

LRESULT CALLBACK TrayApplication::WindowProc(HWND window, UINT message, WPARAM w_param, LPARAM l_param) {
    TrayApplication* app = nullptr;

    if (message == WM_NCCREATE) {
        const CREATESTRUCTW* create_struct = reinterpret_cast<const CREATESTRUCTW*>(l_param);
        app = static_cast<TrayApplication*>(create_struct->lpCreateParams);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
        app->window_ = window;
    } else {
        app = reinterpret_cast<TrayApplication*>(GetWindowLongPtrW(window, GWLP_USERDATA));
    }

    if (app != nullptr) {
        return app->HandleMessage(message, w_param, l_param);
    }

    return DefWindowProcW(window, message, w_param, l_param);
}
