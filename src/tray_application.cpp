#include "tray_application.h"

#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <windows.h>

#include <array>

namespace {

constexpr wchar_t kWindowTitle[] = L"InfoGuard Tray Application";
constexpr wchar_t kTooltipText[] = L"InfoGuard Tray Application";
constexpr wchar_t kMenuFile[] = L"\u0424\u0430\u0439\u043b";
constexpr wchar_t kMenuOpen[] = L"\u041e\u0442\u043a\u0440\u044b\u0442\u044c";
constexpr wchar_t kMenuExit[] = L"\u0412\u044b\u0445\u043e\u0434";
constexpr wchar_t kLoginButtonText[] = L"Sign In";
constexpr wchar_t kLogoutButtonText[] = L"Sign Out";
constexpr wchar_t kActivateButtonText[] = L"Activate";
constexpr wchar_t kScanFileButtonText[] = L"Scan File";
constexpr wchar_t kScanFolderButtonText[] = L"Scan Folder";

void ApplyDefaultGuiFont(HWND control) {
    if (control != nullptr) {
        SendMessageW(
            control,
            WM_SETFONT,
            reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)),
            TRUE);
    }
}

std::wstring GetWindowTextValue(HWND control) {
    const int length = GetWindowTextLengthW(control);
    std::wstring value(length, L'\0');
    if (length > 0) {
        GetWindowTextW(control, value.data(), length + 1);
    }
    return value;
}

std::wstring SelectFilePath(HWND owner_window) {
    std::array<wchar_t, MAX_PATH> file_buffer = {};
    OPENFILENAMEW dialog = {};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = owner_window;
    dialog.lpstrFilter = L"All files\0*.*\0";
    dialog.lpstrFile = file_buffer.data();
    dialog.nMaxFile = static_cast<DWORD>(file_buffer.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    dialog.lpstrTitle = L"Select a file for antivirus scanning";

    if (GetOpenFileNameW(&dialog) == FALSE) {
        return {};
    }

    return file_buffer.data();
}

std::wstring SelectFolderPath(HWND owner_window) {
    BROWSEINFOW browse = {};
    browse.hwndOwner = owner_window;
    browse.lpszTitle = L"Select a folder for antivirus scanning";
    browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_USENEWUI | BIF_NEWDIALOGSTYLE;

    PIDLIST_ABSOLUTE item_list = SHBrowseForFolderW(&browse);
    if (item_list == nullptr) {
        return {};
    }

    std::array<wchar_t, MAX_PATH> path_buffer = {};
    const BOOL success = SHGetPathFromIDListW(item_list, path_buffer.data());
    CoTaskMemFree(item_list);
    return success == FALSE ? std::wstring{} : std::wstring(path_buffer.data());
}

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

    RefreshUiState();

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
        760,
        520,
        nullptr,
        nullptr,
        instance_,
        this);

    if (window_ == nullptr) {
        return false;
    }

    CreateMainMenu();
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

void TrayApplication::CreateControls() {
    status_label_ = CreateWindowExW(
        0,
        L"STATIC",
        L"",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20,
        20,
        700,
        220,
        window_,
        nullptr,
        instance_,
        nullptr);

    username_label_ = CreateWindowExW(
        0,
        L"STATIC",
        L"Username",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20,
        260,
        100,
        20,
        window_,
        nullptr,
        instance_,
        nullptr);

    username_edit_ = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        20,
        284,
        260,
        24,
        window_,
        reinterpret_cast<HMENU>(kCommandLogin + 100),
        instance_,
        nullptr);

    password_label_ = CreateWindowExW(
        0,
        L"STATIC",
        L"Password",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20,
        320,
        100,
        20,
        window_,
        nullptr,
        instance_,
        nullptr);

    password_edit_ = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
        20,
        344,
        260,
        24,
        window_,
        reinterpret_cast<HMENU>(kCommandLogin + 101),
        instance_,
        nullptr);

    login_button_ = CreateWindowExW(
        0,
        L"BUTTON",
        kLoginButtonText,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        20,
        382,
        120,
        30,
        window_,
        reinterpret_cast<HMENU>(kCommandLogin),
        instance_,
        nullptr);

    logout_button_ = CreateWindowExW(
        0,
        L"BUTTON",
        kLogoutButtonText,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        160,
        382,
        120,
        30,
        window_,
        reinterpret_cast<HMENU>(kCommandLogout),
        instance_,
        nullptr);

    activation_label_ = CreateWindowExW(
        0,
        L"STATIC",
        L"Activation code",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        320,
        260,
        140,
        20,
        window_,
        nullptr,
        instance_,
        nullptr);

    activation_edit_ = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        320,
        284,
        240,
        24,
        window_,
        reinterpret_cast<HMENU>(kCommandActivate + 100),
        instance_,
        nullptr);

    activate_button_ = CreateWindowExW(
        0,
        L"BUTTON",
        kActivateButtonText,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        320,
        382,
        120,
        30,
        window_,
        reinterpret_cast<HMENU>(kCommandActivate),
        instance_,
        nullptr);

    scan_file_button_ = CreateWindowExW(
        0,
        L"BUTTON",
        kScanFileButtonText,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        320,
        344,
        120,
        28,
        window_,
        reinterpret_cast<HMENU>(kCommandScanFile),
        instance_,
        nullptr);

    scan_folder_button_ = CreateWindowExW(
        0,
        L"BUTTON",
        kScanFolderButtonText,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        456,
        344,
        120,
        28,
        window_,
        reinterpret_cast<HMENU>(kCommandScanFolder),
        instance_,
        nullptr);

    ApplyDefaultGuiFont(status_label_);
    ApplyDefaultGuiFont(username_label_);
    ApplyDefaultGuiFont(username_edit_);
    ApplyDefaultGuiFont(password_label_);
    ApplyDefaultGuiFont(password_edit_);
    ApplyDefaultGuiFont(login_button_);
    ApplyDefaultGuiFont(logout_button_);
    ApplyDefaultGuiFont(activation_label_);
    ApplyDefaultGuiFont(activation_edit_);
    ApplyDefaultGuiFont(activate_button_);
    ApplyDefaultGuiFont(scan_file_button_);
    ApplyDefaultGuiFont(scan_folder_button_);
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
    RefreshUiState();
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

void TrayApplication::RefreshUiState() {
    state_snapshot_ = license_service_.RefreshSnapshot();
    UpdateStatusText();
    UpdateControlVisibility();
}

void TrayApplication::UpdateStatusText() const {
    if (status_label_ == nullptr) {
        return;
    }

    std::wstring text = license_service_.BuildStatusText(state_snapshot_);
    if (!last_scan_summary_.empty()) {
        text += L"\r\n\r\nLast scan result\r\n----------------\r\n";
        text += last_scan_summary_;
    }

    SetWindowTextW(status_label_, text.c_str());
}

void TrayApplication::UpdateControlVisibility() const {
    const bool show_auth_controls = !state_snapshot_.authenticated;
    const bool show_activation_controls = state_snapshot_.authenticated && !state_snapshot_.has_license;
    const bool show_logout = state_snapshot_.authenticated;
    const bool show_scan_controls = state_snapshot_.has_license;
    const bool antivirus_enabled = state_snapshot_.antivirus_unlocked;

    ShowWindow(username_label_, show_auth_controls ? SW_SHOW : SW_HIDE);
    ShowWindow(username_edit_, show_auth_controls ? SW_SHOW : SW_HIDE);
    ShowWindow(password_label_, show_auth_controls ? SW_SHOW : SW_HIDE);
    ShowWindow(password_edit_, show_auth_controls ? SW_SHOW : SW_HIDE);
    ShowWindow(login_button_, show_auth_controls ? SW_SHOW : SW_HIDE);

    ShowWindow(logout_button_, show_logout ? SW_SHOW : SW_HIDE);
    ShowWindow(activation_label_, show_activation_controls ? SW_SHOW : SW_HIDE);
    ShowWindow(activation_edit_, show_activation_controls ? SW_SHOW : SW_HIDE);
    ShowWindow(activate_button_, show_activation_controls ? SW_SHOW : SW_HIDE);
    ShowWindow(scan_file_button_, show_scan_controls ? SW_SHOW : SW_HIDE);
    ShowWindow(scan_folder_button_, show_scan_controls ? SW_SHOW : SW_HIDE);
    EnableWindow(scan_file_button_, antivirus_enabled ? TRUE : FALSE);
    EnableWindow(scan_folder_button_, antivirus_enabled ? TRUE : FALSE);
}

void TrayApplication::LayoutControls(const int width, const int height) const {
    if (status_label_ == nullptr) {
        return;
    }

    const int control_width = width > 40 ? width - 40 : 1;
    const int status_height = height > 240 ? height - 240 : 180;

    MoveWindow(status_label_, 20, 20, control_width, status_height, TRUE);

    const int lower_top = status_height + 40;
    MoveWindow(username_label_, 20, lower_top, 120, 20, TRUE);
    MoveWindow(username_edit_, 20, lower_top + 24, 260, 24, TRUE);
    MoveWindow(password_label_, 20, lower_top + 60, 120, 20, TRUE);
    MoveWindow(password_edit_, 20, lower_top + 84, 260, 24, TRUE);
    MoveWindow(login_button_, 20, lower_top + 122, 120, 30, TRUE);
    MoveWindow(logout_button_, 160, lower_top + 122, 120, 30, TRUE);

    MoveWindow(activation_label_, 320, lower_top, 160, 20, TRUE);
    MoveWindow(activation_edit_, 320, lower_top + 24, 260, 24, TRUE);
    MoveWindow(scan_file_button_, 320, lower_top + 84, 120, 28, TRUE);
    MoveWindow(scan_folder_button_, 456, lower_top + 84, 120, 28, TRUE);
    MoveWindow(activate_button_, 320, lower_top + 122, 120, 30, TRUE);
}

void TrayApplication::HandleLoginCommand() {
    const std::wstring username = GetWindowTextValue(username_edit_);
    const std::wstring password = GetWindowTextValue(password_edit_);

    const UserQueryResult result = license_service_.Login(username, password);
    if (result.status != RpcCallStatus::Success) {
        const wchar_t* message = result.message.empty() ? L"Unable to sign in." : result.message.c_str();
        MessageBoxW(window_, message, kWindowTitle, MB_ICONERROR | MB_OK);
        RefreshUiState();
        return;
    }

    SetWindowTextW(password_edit_, L"");
    last_scan_summary_.clear();
    RefreshUiState();
}

void TrayApplication::HandleLogoutCommand() {
    std::wstring error_message;
    const RpcCallStatus status = license_service_.Logout(&error_message);
    if (status != RpcCallStatus::Success && status != RpcCallStatus::NotFound) {
        MessageBoxW(
            window_,
            error_message.empty() ? L"Unable to sign out." : error_message.c_str(),
            kWindowTitle,
            MB_ICONERROR | MB_OK);
        return;
    }

    last_scan_summary_.clear();
    RefreshUiState();
}

void TrayApplication::HandleActivateCommand() {
    const std::wstring activation_code = GetWindowTextValue(activation_edit_);
    const LicenseQueryResult result = license_service_.ActivateProduct(activation_code);
    if (result.status != RpcCallStatus::Success) {
        const wchar_t* message = result.message.empty() ? L"Activation failed." : result.message.c_str();
        MessageBoxW(window_, message, kWindowTitle, MB_ICONERROR | MB_OK);
        RefreshUiState();
        return;
    }

    SetWindowTextW(activation_edit_, L"");
    last_scan_summary_.clear();
    RefreshUiState();
}

void TrayApplication::HandleScanFileCommand() {
    const std::wstring file_path = SelectFilePath(window_);
    if (file_path.empty()) {
        return;
    }

    const ScanQueryResult result = license_service_.ScanFile(file_path);
    if (result.status != RpcCallStatus::Success) {
        MessageBoxW(
            window_,
            result.message.empty() ? L"File scan failed." : result.message.c_str(),
            kWindowTitle,
            MB_ICONERROR | MB_OK);
        return;
    }

    last_scan_summary_ = result.scan.summary;
    UpdateStatusText();
    MessageBoxW(
        window_,
        result.scan.summary.c_str(),
        result.scan.malicious ? L"Threat Detected" : L"File Scan Complete",
        MB_OK | (result.scan.malicious ? MB_ICONWARNING : MB_ICONINFORMATION));
}

void TrayApplication::HandleScanFolderCommand() {
    const std::wstring directory_path = SelectFolderPath(window_);
    if (directory_path.empty()) {
        return;
    }

    const ScanQueryResult result = license_service_.ScanDirectory(directory_path);
    if (result.status != RpcCallStatus::Success) {
        MessageBoxW(
            window_,
            result.message.empty() ? L"Directory scan failed." : result.message.c_str(),
            kWindowTitle,
            MB_ICONERROR | MB_OK);
        return;
    }

    last_scan_summary_ = result.scan.summary;
    UpdateStatusText();
    MessageBoxW(
        window_,
        result.scan.summary.c_str(),
        result.scan.malicious ? L"Threat Detected" : L"Directory Scan Complete",
        MB_OK | (result.scan.malicious ? MB_ICONWARNING : MB_ICONINFORMATION));
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
        CreateControls();
        RefreshUiState();
        SetTimer(window_, kStateRefreshTimerId, 15000, nullptr);
        return 0;

    case WM_SIZE:
        LayoutControls(LOWORD(l_param), HIWORD(l_param));
        return 0;

    case WM_TIMER:
        if (w_param == kStateRefreshTimerId) {
            RefreshUiState();
            return 0;
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(w_param)) {
        case kCommandOpen:
            ShowMainWindow();
            return 0;

        case kCommandTrayExit:
        case kCommandFileExit:
            HandleExitCommand();
            return 0;

        case kCommandLogin:
            HandleLoginCommand();
            return 0;

        case kCommandActivate:
            HandleActivateCommand();
            return 0;

        case kCommandLogout:
            HandleLogoutCommand();
            return 0;

        case kCommandScanFile:
            HandleScanFileCommand();
            return 0;

        case kCommandScanFolder:
            HandleScanFolderCommand();
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
        KillTimer(window_, kStateRefreshTimerId);
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
