# InfoGuardServer

Backend for the course work:

- Java 21
- Spring Boot 3.5.14
- Spring Security
- JWT access/refresh
- signed license tickets
- role model `ADMIN` / `USER`
- PostgreSQL
- Flyway migrations
- HTTPS with a development certificate whose serial number is `23358`

## What the server does

- creates a bootstrap administrator at first start
- stores users in a relational database
- stores activation codes and activated licenses bound to users/devices
- issues JWT access and refresh tokens
- issues signed `TicketResponse` payloads for active licenses
- serves a signed binary antivirus-bases package for Windows-service updates
- restricts `/api/admin/**` endpoints to administrators
- supports create / activate / check / renew license flows

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
- `GET /api/public/antivirus/bases`

### Authentication

- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`

### Administration

- `GET /api/admin/users`
- `POST /api/admin/users`
- `POST /api/admin/licenses`
- `POST /api/admin/licenses/{licenseId}/renew`

### Licenses

- `GET /api/licenses/me`
- `GET /api/licenses/current?deviceId=...`
- `POST /api/licenses/activate`

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
7. `Licenses / Activate`
8. `Licenses / Current Ticket`

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

### Activate a product code for the current user

```http
POST /api/licenses/activate
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "licenseKey": "LIC-23358-ABCDEF123456",
  "deviceId": "DEV-23358-DEMO"
}
```

### Check the current signed ticket

```http
GET /api/licenses/current?deviceId=DEV-23358-DEMO
Authorization: Bearer <access-token>
```

### Refresh token

```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "<refresh-token>"
}
```

### Download antivirus bases package

```http
GET /api/public/antivirus/bases
Accept: application/octet-stream
```

The response is a compact binary package with:

- manifest header
- UTF-8 release date
- serialized antivirus records
- manifest signature

The backend currently serves a package with release date `2026-05-24` and `3` records. The Windows service uses it for scheduled antivirus-base updates.

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
- `APP_LICENSE_CERTIFICATE_BASE`
- `APP_LICENSE_DEFAULT_VALID_DAYS`
- `APP_LICENSE_TICKET_LIFETIME`
- `APP_LICENSE_TICKET_SIGNATURE_SECRET`

## How it connects to the Win32 service

The Windows service now talks to the backend over HTTPS and keeps all JWT tokens and license tickets in memory. The Win32 GUI never receives raw JWTs or raw ticket payloads. The service uses:

1. `POST /api/auth/login`
2. `POST /api/auth/refresh`
3. `POST /api/auth/logout`
4. `GET /api/licenses/current?deviceId=...`
5. `POST /api/licenses/activate`
6. `GET /api/public/antivirus/bases`
