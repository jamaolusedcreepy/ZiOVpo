#define AppId "{{A0D301A7-6F0B-46C9-B0A8-233580000026}"
#define AppName "InfoGuard Antivirus"
#define AppVersion "0.2.6"
#define AppPublisher "InfoGuard"
#define AppExeName "InfoGuardTrayApp.exe"
#define ServiceExeName "InfoGuardService.exe"
#define ServiceName "InfoGuardService"

#ifndef BuildOutputDir
  #define BuildOutputDir "..\build\Release"
#endif

#ifndef InstallerOutputDir
  #define InstallerOutputDir "..\build\installer"
#endif

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\InfoGuard
DefaultGroupName=InfoGuard
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
OutputDir={#InstallerOutputDir}
OutputBaseFilename=InfoGuardAntivirusSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
CloseApplications=no
RestartApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "{#BuildOutputDir}\InfoGuardTrayApp.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildOutputDir}\InfoGuardService.exe"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\avbases"

[Icons]
Name: "{group}\InfoGuard Antivirus"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\InfoGuard Antivirus"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[UninstallDelete]
Type: filesandordirs; Name: "{app}\avbases"

[Code]
function ExecLogged(const FileName: string; const Parameters: string; const RequiredExitCode: Integer; const FailureMessage: string): Boolean;
var
  ResultCode: Integer;
begin
  Log(Format('Running: %s %s', [FileName, Parameters]));
  if not Exec(FileName, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if FailureMessage <> '' then
      RaiseException(FailureMessage);
    Result := False;
    Exit;
  end;

  Log(Format('Exit code: %d', [ResultCode]));
  if (RequiredExitCode >= 0) and (ResultCode <> RequiredExitCode) then
  begin
    if FailureMessage <> '' then
      RaiseException(Format('%s (exit code %d)', [FailureMessage, ResultCode]));
    Result := False;
    Exit;
  end;

  Result := True;
end;

function QueryCommandExitCode(const CommandLine: string; var ResultCode: Integer): Boolean;
begin
  Result := Exec(
    ExpandConstant('{cmd}'),
    '/C ' + CommandLine,
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode);
end;

function ServiceExists: Boolean;
var
  ResultCode: Integer;
begin
  if not QueryCommandExitCode('sc.exe query "{#ServiceName}" >NUL 2>&1', ResultCode) then
  begin
    Result := False;
    Exit;
  end;

  Result := ResultCode = 0;
end;

procedure WaitForServiceDeletion;
var
  Attempt: Integer;
begin
  for Attempt := 0 to 19 do
  begin
    if not ServiceExists then
      Exit;

    Sleep(500);
  end;

  if ServiceExists then
    RaiseException('Timed out while waiting for the old InfoGuard Windows service registration to be removed.');
end;

procedure StopInfoGuardProcesses;
var
  ResultCode: Integer;
begin
  Log('Stopping running InfoGuard tray processes.');
  Exec(ExpandConstant('{cmd}'), '/C taskkill /F /IM "InfoGuardTrayApp.exe"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  Log('Stopping the InfoGuard Windows service process if it is running.');
  Exec(
    ExpandConstant('{cmd}'),
    '/C taskkill /F /FI "SERVICES eq {#ServiceName}"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode);
end;

procedure RemoveInfoGuardService;
var
  ResultCode: Integer;
  ServiceExe: string;
begin
  StopInfoGuardProcesses;

  if not ServiceExists then
  begin
    Log('The InfoGuard Windows service is not currently registered.');
    Exit;
  end;

  ServiceExe := ExpandConstant('{app}\{#ServiceExeName}');
  if FileExists(ServiceExe) then
  begin
    Log('Removing the InfoGuard Windows service through the service executable.');
    Exec(ServiceExe, '--uninstall-silent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  Log('Ensuring the service is deleted from SCM.');
  Exec(
    ExpandConstant('{cmd}'),
    '/C sc.exe delete "{#ServiceName}"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode);

  WaitForServiceDeletion;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  RemoveInfoGuardService;
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ServiceExe: string;
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;

  ServiceExe := ExpandConstant('{app}\{#ServiceExeName}');
  if not FileExists(ServiceExe) then
    RaiseException('InfoGuard service executable was not found after installation.');

  ExecLogged(
    ServiceExe,
    '--install-silent',
    0,
    'Failed to register the InfoGuard Windows service.');

  Log('Starting the InfoGuard Windows service.');
  if Exec(
    ExpandConstant('{cmd}'),
    '/C sc.exe start "{#ServiceName}"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode) then
  begin
    Log(Format('Service start exit code: %d', [ResultCode]));
    if (ResultCode <> 0) and (ResultCode <> 1056) then
      RaiseException(Format('Failed to start the InfoGuard Windows service. Exit code: %d', [ResultCode]));
  end
  else
    RaiseException('Failed to execute the start command for the InfoGuard Windows service.');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RemoveInfoGuardService;
end;
