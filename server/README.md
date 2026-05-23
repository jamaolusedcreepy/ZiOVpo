# InfoGuardServer

Backend для курсовой работы:

- Java 21
- Spring Boot 3.5.14
- Spring Security
- JWT access/refresh
- подписанные лицензионные тикеты
- ролевая модель `ADMIN` / `USER`
- PostgreSQL
- миграции Flyway
- HTTPS с dev-сертификатом, у которого серийный номер `23358`

## Что делает сервер

- создаёт bootstrap-администратора при первом запуске
- хранит пользователей в реляционной базе данных
- хранит коды активации и активированные лицензии, привязанные к пользователям и устройствам
- выдаёт JWT access и refresh токены
- выдаёт подписанные `TicketResponse` для активных лицензий
- раздаёт подписанный бинарный пакет антивирусных баз для обновления Windows-службы
- ограничивает `/api/admin/**` только администраторами
- поддерживает сценарии создания, активации, проверки и продления лицензий

## Быстрый старт

### 1. Запустить PostgreSQL

Если установлен Docker Desktop:

```powershell
cd server
docker compose up -d
```

Это поднимет PostgreSQL на `localhost:5432` с параметрами:

- база данных: `infoguard_db`
- пользователь: `infoguard`
- пароль: `infoguard`

### 2. Сгенерировать HTTPS-сертификат

```powershell
cd server
powershell -ExecutionPolicy Bypass -File .\scripts\generate-dev-certificate.ps1
```

Файлы будут созданы в `src/main/resources/certs/`:

- `infoguard-dev.p12`
- `infoguard-dev.cer`

Сгенерированный сертификат использует серийный номер `23358`.

Сгенерированный PKCS12 keystore содержит одну private-key запись с alias `1`, поэтому стандартная конфигурация сервера использует `APP_SSL_KEY_ALIAS=1`.

Если браузер предупреждает, что `https://localhost:8443` небезопасен, доверь сгенерированный dev-сертификат для текущего пользователя Windows:

```powershell
cd server
powershell -ExecutionPolicy Bypass -File .\scripts\trust-dev-certificate.ps1
```

После импорта полностью закрой и заново открой браузер.

### 3. Запустить тесты и собрать проект

```powershell
cd server
.\mvnw.cmd test
.\mvnw.cmd package
```

### 4. Запустить сервер

```powershell
cd server
.\mvnw.cmd spring-boot:run
```

По умолчанию API стартует на:

```text
https://localhost:8443
```

Если порт `8443` уже занят, останови старый Java-процесс или запусти сервер на другом порту:

```powershell
$env:APP_SERVER_PORT=8444
.\mvnw.cmd spring-boot:run
```

## Bootstrap-администратор по умолчанию

- логин: `admin`
- пароль: `Admin23358!`

Перед использованием в условиях, похожих на production, поменяй эти значения через переменные окружения:

- `APP_BOOTSTRAP_ADMIN_USERNAME`
- `APP_BOOTSTRAP_ADMIN_PASSWORD`
- `APP_JWT_SECRET`

## Основные эндпоинты

### Публичные

- `GET /api/public/ping`
- `GET /api/public/antivirus/bases`

### Аутентификация

- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/auth/me`

### Администрирование

- `GET /api/admin/users`
- `POST /api/admin/users`
- `POST /api/admin/licenses`
- `POST /api/admin/licenses/{licenseId}/renew`

### Лицензии

- `GET /api/licenses/me`
- `GET /api/licenses/current?deviceId=...`
- `POST /api/licenses/activate`

### Инициализация клиента

- `GET /api/client/bootstrap`

## Postman

В репозитории уже лежат готовые Postman-файлы:

- [server/postman/InfoGuardServer.postman_collection.json](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/server/postman/InfoGuardServer.postman_collection.json>)
- [server/postman/InfoGuardServer.local.postman_environment.json](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/server/postman/InfoGuardServer.local.postman_environment.json>)

Рекомендуемый порядок запросов в Postman:

1. `Public / Ping`
2. `Authentication / Login Admin`
3. `Admin / List Users`
4. `Admin / Create User`
5. `Authentication / Login Current User`
6. `Licenses / My Licenses`
7. `Licenses / Activate`
8. `Licenses / Current Ticket`

Если Postman не принимает self-signed сертификат, либо доверь локальный сертификат через `trust-dev-certificate.ps1`, либо временно отключи проверку SSL certificate verification в настройках Postman для локальной разработки.

## Примеры запросов

### Вход

```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "Admin23358!"
}
```

### Создание пользователя администратором

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

### Активация кода продукта для текущего пользователя

```http
POST /api/licenses/activate
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "licenseKey": "LIC-23358-ABCDEF123456",
  "deviceId": "DEV-23358-DEMO"
}
```

### Проверка текущего подписанного тикета

```http
GET /api/licenses/current?deviceId=DEV-23358-DEMO
Authorization: Bearer <access-token>
```

### Обновление токена

```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "<refresh-token>"
}
```

### Загрузка пакета антивирусных баз

```http
GET /api/public/antivirus/bases
Accept: application/octet-stream
```

В ответ сервер возвращает компактный бинарный пакет, который содержит:

- заголовок манифеста
- дату выпуска в UTF-8
- сериализованные антивирусные записи
- подпись манифеста

Сейчас backend отдает пакет с датой выпуска `2026-05-24` и `3` записями. Windows-служба использует его для плановых обновлений антивирусных баз.

## Переменные окружения

Полезные override-параметры из [src/main/resources/application.yml](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/server/src/main/resources/application.yml>):

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

## Как сервер связан с Win32-службой

Теперь Windows-служба общается с backend по HTTPS и хранит все JWT-токены и лицензионные тикеты только в памяти. Win32 GUI никогда не получает ни сырые JWT, ни сырой payload тикета. Служба использует:

1. `POST /api/auth/login`
2. `POST /api/auth/refresh`
3. `POST /api/auth/logout`
4. `GET /api/licenses/current?deviceId=...`
5. `POST /api/licenses/activate`
6. `GET /api/public/antivirus/bases`
