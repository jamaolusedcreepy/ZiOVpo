# InfoGuardServer

Minimal backend for the course work:

- Java 21
- Spring Boot 3.5.14
- Spring Security
- JWT access/refresh
- role model `ADMIN` / `USER`
- PostgreSQL
- Flyway migrations
- HTTPS with a development certificate whose serial number is `23358`

## What the server does

- creates a bootstrap administrator at first start
- stores users in a relational database
- stores licenses bound to users
- issues JWT access and refresh tokens
- restricts `/api/admin/**` endpoints to administrators
- exposes a small bootstrap endpoint for the future Win32 client

## Quick start

### 1. Start PostgreSQL

If Docker Desktop is installed:

```powershell
cd server
docker compose up -d
```

This starts PostgreSQL on `localhost:5432` with:

- database: `infoguard_db`
- user: `infoguard`
- password: `infoguard`

### 2. Generate the HTTPS certificate

```powershell
cd server
powershell -ExecutionPolicy Bypass -File .\scripts\generate-dev-certificate.ps1
```

Files will be created in `src/main/resources/certs/`:

- `infoguard-dev.p12`
- `infoguard-dev.cer`

The generated certificate uses serial number `23358`.

The generated PKCS12 keystore contains one private-key entry with alias `1`, so the default server configuration uses `APP_SSL_KEY_ALIAS=1`.

If the browser warns that `https://localhost:8443` is unsafe, trust the generated development certificate for the current Windows user:

```powershell
cd server
powershell -ExecutionPolicy Bypass -File .\scripts\trust-dev-certificate.ps1
```

After import, fully close and reopen the browser.

### 3. Run tests and build

```powershell
cd server
.\mvnw.cmd test
.\mvnw.cmd package
```

### 4. Start the server

```powershell
cd server
.\mvnw.cmd spring-boot:run
```

By default the API starts at:

```text
https://localhost:8443
```

If port `8443` is already occupied, either stop the old Java process or run on another port:

```powershell
$env:APP_SERVER_PORT=8444
.\mvnw.cmd spring-boot:run
```

## Default bootstrap admin

- username: `admin`
- password: `Admin23358!`

Change these values through environment variables before production-like use:

- `APP_BOOTSTRAP_ADMIN_USERNAME`
- `APP_BOOTSTRAP_ADMIN_PASSWORD`
- `APP_JWT_SECRET`

## Main endpoints

### Public

- `GET /api/public/ping`

### Authentication

- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`

### Administration

- `GET /api/admin/users`
- `POST /api/admin/users`

### Licenses

- `GET /api/licenses/me`

### Client bootstrap

- `GET /api/client/bootstrap`

## Postman

Ready-made Postman files are included:

- [server/postman/InfoGuardServer.postman_collection.json](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/server/postman/InfoGuardServer.postman_collection.json>)
- [server/postman/InfoGuardServer.local.postman_environment.json](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/server/postman/InfoGuardServer.local.postman_environment.json>)

Recommended order in Postman:

1. `Public / Ping`
2. `Authentication / Login Admin`
3. `Admin / List Users`
4. `Admin / Create User`
5. `Authentication / Login Current User`
6. `Licenses / My Licenses`
7. `Client / Bootstrap`

If Postman rejects the self-signed certificate, either trust the local certificate with `trust-dev-certificate.ps1` or temporarily disable SSL certificate verification in Postman settings for local development.

## Example requests

### Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "Admin23358!"
}
```

### Create user as admin

```http
POST /api/admin/users
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "username": "student1",
  "password": "Student23358!",
  "fullName": "Student User",
  "role": "USER"
}
```

### Refresh token

```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "<refresh-token>"
}
```

## Environment variables

Useful overrides from [src/main/resources/application.yml](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/server/src/main/resources/application.yml>):

- `APP_DB_URL`
- `APP_DB_USERNAME`
- `APP_DB_PASSWORD`
- `APP_SERVER_PORT`
- `APP_SSL_ENABLED`
- `APP_SSL_KEYSTORE`
- `APP_SSL_KEYSTORE_PASSWORD`
- `APP_SSL_KEY_ALIAS`
- `APP_JWT_ISSUER`
- `APP_JWT_SECRET`
- `APP_JWT_ACCESS_TTL`
- `APP_JWT_REFRESH_TTL`

## How it connects to the Win32 client

The current client already has a local user/license presentation layer. The server exposes `/api/client/bootstrap`, `/api/auth/login`, and `/api/licenses/me`, so the next client iteration can:

1. authenticate the user,
2. store access/refresh tokens,
3. fetch bound licenses from the backend,
4. display server-backed license status in the main window.
