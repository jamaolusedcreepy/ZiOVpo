# InfoGuard Client + Service + Server

Repository with two parts for the assignment:

- Windows client on pure Win32 API
- Windows service on pure Win32 API + Windows RPC over ALPC
- Java backend on Spring Boot with PostgreSQL, JWT authentication, role-based authorization, HTTPS, and user-license binding

## Repository layout

- `src/`, `rpc/`, and `CMakeLists.txt`: Win32 client + Windows service
- `server/`: Java backend
- `.github/workflows/build.yml`: CI for both parts

## Client features

- tray icon on startup
- left-click on tray icon opens the main window
- right-click on tray icon opens a context menu with `Open` and `Exit`
- tray icon is restored after Explorer/taskbar recreation
- hidden startup mode via `--hidden`
- closing the main window hides it instead of exiting
- main menu `File -> Exit`
- single-instance launch guard per Windows user via a named mutex
- client checks the Windows service state on startup
- when the service is stopped, the client starts it, waits for `Running`, and exits
- the client continues to run only when launched by the Windows service
- tray `Exit` and main menu `File -> Exit` stop the Windows service over Windows RPC / ALPC
- authentication form backed by the Windows service
- product activation form backed by the Windows service
- periodic license-state polling through the Windows service
- antivirus functionality is blocked until sign-in and activation succeed
- displays antivirus base release date and record count
- can scan a selected file through the Windows service
- can scan a selected directory through the Windows service

## Windows service features

- Windows service executable: `InfoGuardService.exe`
- launches `InfoGuardTrayApp.exe --hidden` in every user terminal session except session `0`
- tracks new logons and reconnect/unlock events through `SERVICE_CONTROL_SESSIONCHANGE`
- ignores SCM `Stop` and `Shutdown` controls
- hosts a Windows RPC server over `ncalrpc` (ALPC)
- stores JWT access/refresh tokens only in memory
- refreshes JWT access/refresh tokens based on their expiration times
- stores the active license ticket only in memory
- refreshes the active license ticket based on ticket lifetime and expiration
- exposes RPC methods for current user, sign-in, sign-out, current license, activation, and service stop
- loads in-memory antivirus bases after a valid license ticket appears
- keeps antivirus signatures in a `std::map` keyed by the first 8 bytes of a signature
- verifies a signature hash and a record integrity signature before reporting a detection
- scans individual files and directories through RPC without exposing JWTs or tickets to the GUI
- terminates all launched tray clients when the service stops

## Server features

- PostgreSQL integration via Spring Data JPA + Flyway
- authentication with JWT access and refresh tokens
- authorization with `ADMIN` and `USER` roles
- HTTPS with a development certificate whose serial number is `23358`
- seeded administrator account on first launch
- user creation API and license creation API
- license activation, current-ticket check, and renewal flows
- signed `TicketResponse` payload for the Windows service

## Build the Windows binaries

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release --target InfoGuardTrayApp InfoGuardService
```

Client executable:

```text
build\Release\InfoGuardTrayApp.exe
```

Service executable:

```text
build\Release\InfoGuardService.exe
```

Hidden startup mode:

```powershell
.\build\Release\InfoGuardTrayApp.exe --hidden
```

Service-to-server integration uses these optional environment variables:

```text
INFOGUARD_API_URL=https://localhost:8443
INFOGUARD_API_INSECURE_TLS=1
```

`INFOGUARD_API_INSECURE_TLS=1` is convenient for local development because the Windows service runs under a system account and talks to the local self-signed HTTPS endpoint.

## Install and verify the Windows service

Service installation must be done from an elevated PowerShell:

```powershell
.\build\Release\InfoGuardService.exe --install
Start-Service InfoGuardService
```

Recommended verification flow for assignment 2.2:

1. Build `InfoGuardService.exe` and `InfoGuardTrayApp.exe`
2. Install the service from elevated PowerShell
3. Start the service and verify that the tray client appears in the current user session without showing its main window
4. Log in with another Windows user session if available and verify that the tray client appears there as well
5. Stop the service from the tray client menu `Exit` or from the main window `File -> Exit`
6. Verify that the tray client disappears because the service terminates all launched GUI processes

Important behavior:

- launching `InfoGuardTrayApp.exe` manually while the service is stopped should start the service, wait for `Running`, and then exit
- launching `InfoGuardTrayApp.exe` manually while the service is already running should exit because its parent process is not the Windows service
- if you update from an older build, reinstall the service so the new security settings for interactive users are applied

## Verify the 2.3 flow

1. Start PostgreSQL and the Java backend on `https://localhost:8443`
2. Build `InfoGuardTrayApp.exe` and `InfoGuardService.exe`
3. Install or restart the Windows service so it uses the current build
4. Start the Windows service and open the tray window
5. The main window should show the sign-in form when no user is authenticated
6. Sign in with a server user, for example `admin / Admin23358!`
7. If no active license ticket exists, the activation form should remain visible and antivirus functionality should stay blocked
8. Activate a product code for the current user
9. After activation, the main window should show the license expiration time and antivirus functionality should switch to `unlocked`
10. Leave the app open for a while or reopen the main window to verify that state is refreshed through the service timer

## Verify the 2.4 flow

1. Complete the 2.3 flow until the product is activated
2. Restart the Windows service if needed so the current `InfoGuardService.exe` build is active
3. Open the tray window and verify that it shows:
   - antivirus bases release date
   - antivirus bases record count
4. Click `Scan File` and select one of the demo files:
   - clean sample: [samples/antivirus/clean/clean_script.ps1](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/samples/antivirus/clean/clean_script.ps1>)
   - infected PowerShell sample: [samples/antivirus/infected/demo_malicious.ps1](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/samples/antivirus/infected/demo_malicious.ps1>)
   - infected PE-like sample: [samples/antivirus/infected/demo_malicious_pe.exe](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/samples/antivirus/infected/demo_malicious_pe.exe>)
5. Verify that the clean sample reports no threats and the infected samples report a threat name
6. Click `Scan Folder` and select [samples/antivirus](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/samples/antivirus>)
7. Verify that the directory scan reports the scanned-file count, infected-file count, and sample infected paths

## Build the server

```powershell
cd server
.\mvnw.cmd test
.\mvnw.cmd package
```

Server artifact:

```text
server\target\server-0.0.1-SNAPSHOT.jar
```

Detailed server setup, HTTPS, PostgreSQL, and API examples are described in [server/README.md](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/server/README.md>).

## Client requirement checklist

1. Tray icon on startup: `TrayApplication::AddTrayIcon`
2. Left-click opens the main window: `WM_LBUTTONUP` / `NIN_SELECT`
3. Right-click opens the tray context menu: `WM_RBUTTONUP` / `WM_CONTEXTMENU`
4. `Open` menu item shows the main window: `kCommandOpen`
5. `Exit` menu item terminates the app: `kCommandTrayExit`
6. Tray icon is restored after taskbar recreation: `TaskbarCreated`
7. Hidden startup mode: `--hidden`
8. Closing the main window keeps the app running in background: `WM_CLOSE`
9. Main menu contains `File -> Exit`: `CreateMainMenu`
10. Single instance per Windows user: `SingleInstanceGuard`
11. Pipeline build with CMake/MSBuild: `.github/workflows/build.yml`
12. Build artifact is the ready-to-run executable: `InfoGuardTrayApp.exe`
13. Current authenticated user is requested from the Windows service at startup: `LicenseService::RefreshSnapshot`
14. Authentication form is shown while signed out: `TrayApplication::UpdateControlVisibility`
15. Activation form is shown while no ticket is available: `TrayApplication::UpdateControlVisibility`
16. Antivirus functionality unlocks after a valid ticket is present: `LicenseService::RefreshSnapshot`
17. License state is polled periodically: `WM_TIMER` + `RefreshUiState`
18. Antivirus bases release date and record count are shown after activation: `LicenseService::BuildStatusText`
19. File scan is available from the main window: `TrayApplication::HandleScanFileCommand`
20. Directory scan is available from the main window: `TrayApplication::HandleScanFolderCommand`

## Windows service requirement checklist

1. Launch client in every terminal session except `0`: `WTSEnumerateSessionsW` + `CreateProcessAsUserW`
2. Launch client for new user logons: `SERVICE_CONTROL_SESSIONCHANGE`
3. Ignore `Stop` / `Shutdown`: service status accepts only `SERVICE_ACCEPT_SESSIONCHANGE`
4. Run until RPC server is stopped: `RpcServerListen`
5. Expose RPC interface over ALPC: `ncalrpc` endpoint in `rpc/infoguard_service_rpc.idl`
6. Keep tokens and tickets only in memory: `ServiceSessionManager`
7. Refresh JWT and ticket according to their lifetimes: `ServiceSessionManager::WorkerLoop`
8. Stop all launched tray clients on service shutdown: `TerminateAllChildProcesses`
9. Load antivirus bases after activation: `ServiceSessionManager::EnsureBasesLoaded`
10. Keep AV bases in a `std::map` keyed by signature prefix: `AntivirusEngine`
11. Scan a file through the engine and expose it over RPC: `AntivirusEngine::ScanFile` + `InfoGuardRpcScanFile`
12. Scan a directory through the engine and expose it over RPC: `AntivirusEngine::ScanDirectory` + `InfoGuardRpcScanDirectory`
13. Expose antivirus base information over RPC: `InfoGuardRpcGetAntivirusBasesInfo`
