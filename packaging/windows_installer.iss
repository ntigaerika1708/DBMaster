; Inno Setup — instalador do VaultDB (Windows)
; Compilar (a partir da raiz, após gerar dist\VaultDB.exe):
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\windows_installer.iss /DMyAppVersion=2.2.1
; Saída: out\VaultDB-Setup-<versao>.exe

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif

[Setup]
AppId={{B2D8F1A4-6C3E-4E2A-9F7B-VAULTDB000001}
AppName=VaultDB Security Suite
AppVersion={#MyAppVersion}
AppPublisher=VaultDB
DefaultDirName={autopf}\VaultDB
DefaultGroupName=VaultDB
DisableProgramGroupPage=yes
OutputDir=..\out
OutputBaseFilename=VaultDB-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline

[Languages]
Name: "pt"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\dist\VaultDB.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\VaultDB Security Suite"; Filename: "{app}\VaultDB.exe"
Name: "{group}\{cm:UninstallProgram,VaultDB}"; Filename: "{uninstallexe}"
Name: "{userdesktop}\VaultDB"; Filename: "{app}\VaultDB.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\VaultDB.exe"; Description: "Iniciar o VaultDB agora"; Flags: nowait postinstall skipifsilent
