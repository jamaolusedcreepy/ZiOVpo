# InfoGuard Client + Service + Server

Репозиторий с тремя частями учебного проекта:

- Windows-клиент на чистом Win32 API
- Windows-служба на чистом Win32 API + Windows RPC over ALPC
- Java backend на Spring Boot с PostgreSQL, JWT-аутентификацией, ролевой авторизацией, HTTPS и привязкой лицензии к пользователю

## Структура репозитория

- `src/`, `rpc/` и `CMakeLists.txt`: Win32-клиент + Windows-служба
- `server/`: Java backend
- `.github/workflows/build.yml`: CI для обеих частей
- `installer/`: Inno Setup-скрипт для сборки установщика Windows

## Возможности клиента

- добавляет иконку в трей при запуске
- левый клик по иконке в трее открывает главное окно
- правый клик по иконке в трее открывает контекстное меню с пунктами `Open` и `Exit`
- иконка в трее восстанавливается после пересоздания Explorer/панели задач
- поддерживается скрытый запуск через `--hidden`
- закрытие главного окна скрывает его вместо завершения приложения
- главное меню содержит `File -> Exit`
- защита от второго запуска для одного пользователя Windows через именованный mutex
- клиент проверяет состояние Windows-службы при запуске
- если служба остановлена, клиент запускает её, дожидается состояния `Running` и завершает свою работу
- клиент продолжает работать только в том случае, если запущен Windows-службой
- пункт `Exit` в трее и `File -> Exit` в главном меню останавливают Windows-службу через Windows RPC / ALPC
- форма аутентификации работает через Windows-службу
- форма активации продукта работает через Windows-службу
- состояние лицензии периодически опрашивается через Windows-службу
- функциональность антивируса заблокирована до успешного входа и активации
- отображаются дата выпуска антивирусных баз и количество записей
- можно запустить сканирование выбранного файла через Windows-службу
- можно запустить сканирование выбранной директории через Windows-службу

## Возможности Windows-службы

- исполняемый файл службы: `InfoGuardService.exe`
- запускает `InfoGuardTrayApp.exe --hidden` во всех пользовательских терминальных сессиях, кроме сессии `0`
- отслеживает новые входы в систему, переподключения и разблокировки через `SERVICE_CONTROL_SESSIONCHANGE`
- игнорирует команды SCM `Stop` и `Shutdown`
- поднимает сервер Windows RPC поверх `ncalrpc` (ALPC)
- хранит JWT access/refresh токены только в оперативной памяти
- обновляет JWT access/refresh токены с учётом сроков их действия
- хранит активный лицензионный тикет только в оперативной памяти
- обновляет активный лицензионный тикет на основе времени жизни тикета и срока действия лицензии
- предоставляет RPC-методы для получения текущего пользователя, входа, выхода, активной лицензии, активации продукта и остановки службы
- хранит антивирусные базы на диске в компактном подписанном бинарном формате
- загружает антивирусные базы с диска при запуске службы
- восстанавливает антивирусные базы из резервной копии, если активный манифест повреждён
- возвращается к встроенным базам по умолчанию, если нет ни рабочей активной копии, ни резервной копии
- хранит антивирусные сигнатуры в `std::map`, где ключом являются первые 8 байтов сигнатуры
- проверяет хеш сигнатуры и подпись целостности записи перед фиксацией обнаружения
- сканирует отдельные файлы и директории через RPC, не передавая JWT или тикеты в GUI
- периодически загружает обновлённые антивирусные базы с Java backend по HTTPS
- завершает все запущенные клиентские процессы при остановке службы

## Возможности сервера

- интеграция с PostgreSQL через Spring Data JPA + Flyway
- аутентификация на основе JWT access и refresh токенов
- авторизация с ролями `ADMIN` и `USER`
- HTTPS с dev-сертификатом, у которого серийный номер `23358`
- автоматическое создание администратора при первом запуске
- API для создания пользователей и лицензий
- сценарии активации лицензии, проверки текущего тикета и продления лицензии
- подписанный `TicketResponse` для Windows-службы

## Сборка Windows-бинарников

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release --target InfoGuardTrayApp InfoGuardService
```

Исполняемый файл клиента:

```text
build\Release\InfoGuardTrayApp.exe
```

Исполняемый файл службы:

```text
build\Release\InfoGuardService.exe
```

Скрытый режим запуска:

```powershell
.\build\Release\InfoGuardTrayApp.exe --hidden
```

Для интеграции службы с сервером можно использовать такие необязательные переменные окружения:

```text
INFOGUARD_API_URL=https://localhost:8443
INFOGUARD_API_INSECURE_TLS=1
INFOGUARD_AV_UPDATE_INTERVAL_SECONDS=30
```

`INFOGUARD_API_INSECURE_TLS=1` удобно для локальной разработки, потому что Windows-служба работает от системной учётной записи и обращается к локальному self-signed HTTPS endpoint.
`INFOGUARD_AV_UPDATE_INTERVAL_SECONDS` переопределяет стандартный интервал обновления. По умолчанию служба проверяет новые базы каждые `30` секунд.

Важно для задания 2.6: Windows-бинарники собираются со статически подключённым MSVC runtime, поэтому отдельный пакет VC++ Redistributable для запуска клиента и службы не требуется. Инсталлятор устанавливает только собственные артефакты приложения и использует встроенные компоненты Windows.

## Сборка инсталлятора

Локально инсталлятор собирается через Inno Setup 6 после сборки `Release`-бинарников:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release --target InfoGuardTrayApp InfoGuardService
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" "installer\InfoGuardInstaller.iss"
```

Если Inno Setup был установлен через `winget` только для текущего пользователя, вместо пути из `Program Files (x86)` может использоваться:

```powershell
& "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe" "installer\InfoGuardInstaller.iss"
```

Готовый инсталлятор будет находиться здесь:

```text
build\installer\InfoGuardAntivirusSetup.exe
```

## Установка и проверка Windows-службы

Устанавливать службу нужно из PowerShell с правами администратора:

```powershell
.\build\Release\InfoGuardService.exe --install
Start-Service InfoGuardService
```

Рекомендуемый сценарий проверки задания 2.2:

1. Собрать `InfoGuardService.exe` и `InfoGuardTrayApp.exe`
2. Установить службу из elevated PowerShell
3. Запустить службу и убедиться, что клиент в трее появился в текущей пользовательской сессии без показа главного окна
4. Если есть возможность, войти под другим пользователем Windows и убедиться, что там тоже появился клиент в трее
5. Остановить службу через `Exit` в меню клиента или через `File -> Exit` в главном окне
6. Убедиться, что иконка клиента исчезает, потому что служба завершает все запущенные GUI-процессы

Важное поведение:

- ручной запуск `InfoGuardTrayApp.exe`, когда служба остановлена, должен запустить службу, дождаться состояния `Running` и завершиться
- ручной запуск `InfoGuardTrayApp.exe`, когда служба уже работает, должен завершиться, потому что родительским процессом не является Windows-служба
- если обновляешься с более старой сборки, переустанови службу, чтобы применились новые настройки безопасности для интерактивных пользователей

## Проверка сценария 2.3

1. Запустить PostgreSQL и Java backend на `https://localhost:8443`
2. Собрать `InfoGuardTrayApp.exe` и `InfoGuardService.exe`
3. Установить или перезапустить Windows-службу, чтобы она использовала текущую сборку
4. Запустить Windows-службу и открыть окно клиента из трея
5. В главном окне должна появиться форма входа, если пользователь ещё не аутентифицирован
6. Выполнить вход под серверным пользователем, например `admin / Admin23358!`
7. Если активного лицензионного тикета нет, форма активации должна остаться видимой, а функциональность антивируса должна быть заблокирована
8. Активировать код продукта для текущего пользователя
9. После активации в главном окне должен появиться срок действия лицензии, а функциональность антивируса должна перейти в состояние `unlocked`
10. Оставить приложение открытым на некоторое время или заново открыть главное окно, чтобы убедиться, что состояние обновляется таймером службы

## Проверка сценария 2.4

1. Пройти сценарий 2.3 до успешной активации продукта
2. При необходимости перезапустить Windows-службу, чтобы использовалась актуальная сборка `InfoGuardService.exe`
3. Открыть окно клиента из трея и убедиться, что оно показывает:
   - дату выпуска антивирусных баз
   - количество записей в антивирусных базах
4. Нажать `Scan File` и выбрать один из demo-файлов:
   - чистый пример: [samples/antivirus/clean/clean_script.ps1](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/samples/antivirus/clean/clean_script.ps1>)
   - заражённый PowerShell-пример: [samples/antivirus/infected/demo_malicious.ps1](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/samples/antivirus/infected/demo_malicious.ps1>)
   - заражённый PE-подобный пример: [samples/antivirus/infected/demo_malicious_pe.exe](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/samples/antivirus/infected/demo_malicious_pe.exe>)
5. Убедиться, что для чистого файла угроз нет, а для заражённых файлов показывается имя угрозы
6. Нажать `Scan Folder` и выбрать [samples/antivirus](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/samples/antivirus>)
7. Убедиться, что сканирование директории показывает количество проверенных файлов, количество заражённых файлов и пути к обнаруженным заражённым примерам

## Проверка сценария 2.5

1. Запустить backend на `https://localhost:8443`
2. Перезапустить Windows-службу, чтобы она заново создала локальное хранилище антивирусных баз
3. Убедиться, что служба создала каталог `build\Release\avbases\` с файлами:
   - `antivirus-bases.default.bin`
   - `antivirus-bases.active.bin`
4. Активировать продукт и открыть окно клиента из трея
5. Убедиться, что изначально загруженные встроенные базы показывают:
   - дату выпуска `2026-05-23`
   - количество записей `2`
6. Подождать около 30 секунд и обновить состояние окна или открыть его заново
7. Убедиться, что базы переключились на пакет, полученный с backend:
   - дата выпуска `2026-05-24`
   - количество записей `3`
8. До планового обновления файл [samples/antivirus/update-only/demo_updated_malicious.ps1](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/samples/antivirus/update-only/demo_updated_malicious.ps1>) не должен детектироваться
9. После планового обновления этот же файл должен детектироваться как `Demo.Update.PowerShell.23358`
10. Для проверки восстановления остановить службу, повредить `build\Release\avbases\antivirus-bases.active.bin`, затем снова запустить службу и убедиться, что она восстанавливает базы из резервной копии или заново создаёт встроенные базы по умолчанию

## Проверка сценария 2.6

1. Собрать `InfoGuardTrayApp.exe`, `InfoGuardService.exe` и `build\installer\InfoGuardAntivirusSetup.exe`
2. Запустить инсталлятор от имени администратора
3. Убедиться, что в каталог установки скопированы оба исполняемых файла приложения
4. Убедиться, что служба `InfoGuardService` зарегистрирована с типом запуска `Automatic`
5. После установки проверить, что служба запущена, а клиент появился в пользовательской сессии
6. Открыть `Apps & features` или штатный деинсталлятор InfoGuard и удалить приложение
7. Убедиться, что инсталлятор останавливает процессы `InfoGuardService.exe` и `InfoGuardTrayApp.exe`, удаляет службу из SCM и удаляет каталог установки вместе с `avbases`
8. В GitHub Actions убедиться, что workflow публикует артефакт `InfoGuard-windows-installer`

## Сборка сервера

```powershell
cd server
.\mvnw.cmd test
.\mvnw.cmd package
```

Артефакт сервера:

```text
server\target\server-0.0.1-SNAPSHOT.jar
```

Подробная настройка сервера, HTTPS, PostgreSQL и примеры API описаны в [server/README.md](</C:/Users/musht/Documents/Codex/2026-05-22/2-1-gitlab-merge-request-github/server/README.md>).

## Чек-лист требований к клиенту

1. Иконка в трее при запуске: `TrayApplication::AddTrayIcon`
2. Левый клик открывает главное окно: `WM_LBUTTONUP` / `NIN_SELECT`
3. Правый клик открывает контекстное меню трея: `WM_RBUTTONUP` / `WM_CONTEXTMENU`
4. Пункт `Open` показывает главное окно: `kCommandOpen`
5. Пункт `Exit` завершает приложение: `kCommandTrayExit`
6. Иконка в трее восстанавливается после пересоздания панели задач: `TaskbarCreated`
7. Скрытый режим запуска: `--hidden`
8. Закрытие главного окна оставляет приложение работать в фоне: `WM_CLOSE`
9. Главное меню содержит `File -> Exit`: `CreateMainMenu`
10. Один экземпляр на пользователя Windows: `SingleInstanceGuard`
11. Сборка через pipeline на CMake/MSBuild: `.github/workflows/build.yml`
12. Артефакт сборки - готовый к запуску исполняемый файл: `InfoGuardTrayApp.exe`
13. При запуске запрашивается текущий аутентифицированный пользователь из Windows-службы: `LicenseService::RefreshSnapshot`
14. Пока пользователь не вошёл, показывается форма аутентификации: `TrayApplication::UpdateControlVisibility`
15. Пока нет тикета лицензии, показывается форма активации: `TrayApplication::UpdateControlVisibility`
16. После появления валидного тикета функциональность антивируса разблокируется: `LicenseService::RefreshSnapshot`
17. Состояние лицензии периодически опрашивается: `WM_TIMER` + `RefreshUiState`
18. После активации показываются дата выпуска баз и количество записей: `LicenseService::BuildStatusText`
19. Сканирование файла доступно из главного окна: `TrayApplication::HandleScanFileCommand`
20. Сканирование директории доступно из главного окна: `TrayApplication::HandleScanFolderCommand`
21. После обновления баз дата выпуска и количество записей могут измениться без переустановки клиента: `WM_TIMER` + `RefreshUiState`

## Чек-лист требований к Windows-службе

1. Запуск клиента во всех терминальных сессиях, кроме `0`: `WTSEnumerateSessionsW` + `CreateProcessAsUserW`
2. Запуск клиента при новых входах пользователей: `SERVICE_CONTROL_SESSIONCHANGE`
3. Игнорирование `Stop` / `Shutdown`: статус службы принимает только `SERVICE_ACCEPT_SESSIONCHANGE`
4. Работа до остановки RPC-сервера: `RpcServerListen`
5. RPC-интерфейс поверх ALPC: endpoint `ncalrpc` в `rpc/infoguard_service_rpc.idl`
6. Хранение токенов и тикетов только в памяти: `ServiceSessionManager`
7. Обновление JWT и тикета по срокам их действия: `ServiceSessionManager::WorkerLoop`
8. Остановка всех запущенных клиентов при завершении службы: `TerminateAllChildProcesses`
9. Загрузка антивирусных баз с диска при старте службы: `ServiceSessionManager::InitializeAntivirusStorage`
10. Хранение AV-баз в `std::map` с ключом по префиксу сигнатуры: `AntivirusEngine`
11. Сканирование файла через движок и публикация через RPC: `AntivirusEngine::ScanFile` + `InfoGuardRpcScanFile`
12. Сканирование директории через движок и публикация через RPC: `AntivirusEngine::ScanDirectory` + `InfoGuardRpcScanDirectory`
13. RPC-интерфейс для получения информации об антивирусных базах: `InfoGuardRpcGetAntivirusBasesInfo`
14. Сохранение антивирусных баз на диск в компактном подписанном формате манифеста: `AntivirusEngine::InitializeStorage`
15. Восстановление активных баз из backup/default при запуске: `AntivirusEngine::LoadBasesFromStorage`
16. Пропуск записей с неверными подписями без потери остальных записей пакета: `ParsePackageBytes`
17. Периодическая загрузка обновлённых баз с backend: `ServiceSessionManager::WorkerLoop` + `BackendApiClient::DownloadAntivirusBasesPackage`
18. Инсталлятор регистрирует службу на автозапуск при загрузке ОС: `installer/InfoGuardInstaller.iss` + `InfoGuardService.exe --install-silent`
19. Деинсталлятор останавливает и удаляет службу, а также удаляет рабочий каталог `avbases`: `installer/InfoGuardInstaller.iss`
