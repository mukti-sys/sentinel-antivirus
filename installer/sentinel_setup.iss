; ==============================================================================
;                  Inno Setup Script for Sentinel Antivirus
; ==============================================================================
; To compile into a single Sentinel_Setup_v2.0.exe:
;   iscc.exe installer\sentinel_setup.iss
; ==============================================================================

#define MyAppName "Sentinel Antivirus"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "mukti-sys"
#define MyAppURL "https://github.com/mukti-sys/sentinel-antivirus"
#define MyAppExeName "sentinel_gui.exe"
#define MyServiceExe "sentinel_service.exe"
#define MyTrayExe "sentinel_tray.exe"

[Setup]
AppId={{D54823AA-6E61-46B2-9F1C-D1372E5BC3A9}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=Sentinel_Setup_v2.0
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startservice"; Description: "Start Sentinel Antivirus background protection immediately"; GroupDescription: "Service Options:"; Flags: checkedonce

[Files]
Source: "..\dist\Sentinel\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName} Dashboard"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
; Auto-start tray app on user login
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SentinelAntivirusTray"; ValueData: """{app}\{#MyTrayExe}"""; Flags: uninsdeletevalue

[Run]
; Register & start Windows Service
Filename: "sc.exe"; Parameters: "create SentinelService binPath= """"{app}\{#MyServiceExe}"""" start= auto DisplayName= ""Sentinel Antivirus Core Protection Service"""; Flags: runhidden
Filename: "sc.exe"; Parameters: "failure SentinelService reset= 86400 actions= restart/5000/restart/10000/restart/30000"; Flags: runhidden
Filename: "net.exe"; Parameters: "start SentinelService"; Tasks: startservice; Flags: runhidden
; Launch Tray companion
Filename: "{app}\{#MyTrayExe}"; Description: "Launch Sentinel System Tray Shield"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Disarm canaries, stop service, remove service
Filename: "{app}\sentinel_cli.exe"; Parameters: "canaries --disarm"; Flags: runhidden
Filename: "net.exe"; Parameters: "stop SentinelService"; Flags: runhidden
Filename: "sc.exe"; Parameters: "delete SentinelService"; Flags: runhidden
Filename: "taskkill.exe"; Parameters: "/F /IM {#MyTrayExe} /IM {#MyAppExeName}"; Flags: runhidden
