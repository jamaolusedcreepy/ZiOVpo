# InfoGuard Client + Server

Repository with two parts for the assignment:

- Windows client on pure Win32 API
- Java backend on Spring Boot with PostgreSQL, JWT authentication, role-based authorization, HTTPS, and user-license binding

## Repository layout

- `src/` and `CMakeLists.txt`: Win32 client
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
- backend integration over HTTPS using WinHTTP
- server login and license bootstrap with fallback to the local demo stub when the backend is unavailable

## Server features

- PostgreSQL integration via Spring Data JPA + Flyway
- authentication with JWT access and refresh tokens
- authorization with `ADMIN` and `USER` roles
- HTTPS with a development certificate whose serial number is `23358`
- seeded administrator account on first launch
- user creation API and license binding API
- endpoint prepared for future Win32 client integration: `/api/client/bootstrap`

## Build the client

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

Client executable:

```text
build\Release\InfoGuardTrayApp.exe
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
2. Optionally set `INFOGUARD_API_USERNAME` and `INFOGUARD_API_PASSWORD` for the server user you want to show in the client
3. Start the Windows client
4. Open the tray window
5. The main window should show `Server integration: connected`, the authenticated server username, role, and the server-issued license

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
