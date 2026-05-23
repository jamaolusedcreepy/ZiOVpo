#pragma once

#include <windows.h>

#include "license_service.h"

class TrayApplication {
public:
    TrayApplication(HINSTANCE instance, bool start_hidden);

    bool Initialize(int show_command);
    int Run() const;

private:
    inline static constexpr UINT kTrayIconId = 1;
    inline static constexpr UINT kTrayCallbackMessage = WM_APP + 1;
    inline static constexpr UINT_PTR kCommandOpen = 1001;
    inline static constexpr UINT_PTR kCommandTrayExit = 1002;
    inline static constexpr UINT_PTR kCommandFileExit = 1003;
    inline static constexpr UINT_PTR kCommandLogin = 1004;
    inline static constexpr UINT_PTR kCommandActivate = 1005;
    inline static constexpr UINT_PTR kCommandLogout = 1006;
    inline static constexpr UINT_PTR kStateRefreshTimerId = 2001;
    inline static constexpr wchar_t kWindowClassName[] = L"InfoGuardTrayAppWindow";

    static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM w_param, LPARAM l_param);

    bool CreateMainWindow();
    void CreateMainMenu() const;
    void CreateControls();
    bool AddTrayIcon();
    void RemoveTrayIcon();
    void ShowMainWindow(int show_command = SW_SHOWNORMAL);
    void HideMainWindow() const;
    void ShowTrayMenu();
    void RefreshUiState();
    void UpdateStatusText() const;
    void UpdateControlVisibility() const;
    void LayoutControls(int width, int height) const;
    void HandleLoginCommand();
    void HandleLogoutCommand();
    void HandleActivateCommand();
    void HandleExitCommand();
    void RequestExit();
    LRESULT HandleMessage(UINT message, WPARAM w_param, LPARAM l_param);

    HINSTANCE instance_;
    HWND window_ = nullptr;
    HWND status_label_ = nullptr;
    HWND username_label_ = nullptr;
    HWND username_edit_ = nullptr;
    HWND password_label_ = nullptr;
    HWND password_edit_ = nullptr;
    HWND login_button_ = nullptr;
    HWND logout_button_ = nullptr;
    HWND activation_label_ = nullptr;
    HWND activation_edit_ = nullptr;
    HWND activate_button_ = nullptr;
    HWND antivirus_button_ = nullptr;
    HICON icon_ = nullptr;
    UINT taskbar_created_message_ = 0;
    bool start_hidden_ = false;
    bool tray_icon_added_ = false;
    bool exit_requested_ = false;
    LicenseService license_service_;
    ClientStateSnapshot state_snapshot_;
};
