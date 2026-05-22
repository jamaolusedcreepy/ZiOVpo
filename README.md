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
- backend integration over HTTPS using WinHTTP
- server login and license bootstrap with fallback to the local demo stub when the backend is unavailable

## Windows service features

- Windows service executable: `InfoGuardService.exe`
- launches `InfoGuardTrayApp.exe --hidden` in every user terminal session except session `0`
- tracks new logons and reconnect/unlock events through `SERVICE_CONTROL_SESSIONCHANGE`
- ignores SCM `Stop` and `Shutdown` controls
- hosts a Windows RPC server over `ncalrpc` (ALPC)
- exposes an RPC method for the client to stop the service
- terminates all launched tray clients when the service stops

## Server features

- PostgreSQL integration via Spring Data JPA + Flyway
- authentication with JWT access and refresh tokens
- authorization with `ADMIN` and `USER` roles
- HTTPS with a development certificate whose serial number is `23358`
- seeded administrator account on first launch
- user creation API and license binding API
- endpoint prepared for future Win32 client integration: `/api/client/bootstrap`

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

Client-to-server integration uses these optional environment variables:

```text
INFOGUARD_API_ENABLED=1
INFOGUARD_API_URL=https://localhost:8443
INFOGUARD_API_USERNAME=admin
INFOGUARD_API_PASSWORD=Admin23358!
INFOGUARD_API_INSECURE_TLS=0
```

If the local certificate is already trusted, keep `INFOGUARD_API_INSECURE_TLS=0`. For a temporary local demo without importing the certificate, you may set `INFOGUARD_API_INSECURE_TLS=1`.

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

## End-to-end check

1. Start the Java backend on `https://localhost:8443`
2. Build and install the Windows service
3. Optionally set `INFOGUARD_API_USERNAME` and `INFOGUARD_API_PASSWORD` for the server user you want to show in the client session
4. Start the Windows service
5. Open the tray window from the client that was launched by the service
6. The main window should show `Server integration: connected`, the authenticated server username, role, and the server-issued license

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

## Windows service requirement checklist

1. Launch client in every terminal session except `0`: `WTSEnumerateSessionsW` + `CreateProcessAsUserW`
2. Launch client for new user logons: `SERVICE_CONTROL_SESSIONCHANGE`
3. Ignore `Stop` / `Shutdown`: service status accepts only `SERVICE_ACCEPT_SESSIONCHANGE`
4. Run until RPC server is stopped: `RpcServerListen`
5. Expose RPC interface over ALPC: `ncalrpc` endpoint in `rpc/infoguard_service_rpc.idl`
6. Stop all launched tray clients on service shutdown: `TerminateAllChildProcesses`
