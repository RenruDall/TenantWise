; TenantWise installer (Inno Setup 6). Per-user install: no admin rights needed.
; Build: iscc /DAppVersion=1.0.0 installer\TenantWise.iss   (after building src\TenantWise.App in Release)
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{0339420D-CACC-4B40-95DA-18E64074DF36}
AppName=TenantWise
AppVersion={#AppVersion}
AppVerName=TenantWise {#AppVersion}
AppPublisher=Michael Ladurner
AppCopyright=© 2026 Michael Ladurner · Apache License 2.0
AppPublisherURL=https://github.com/RenruDall/TenantWise
AppSupportURL=https://github.com/RenruDall/TenantWise/issues
AppUpdatesURL=https://github.com/RenruDall/TenantWise/releases
; Product name and version inside the setup file (code signing needs them)
VersionInfoVersion={#AppVersion}
VersionInfoProductName=TenantWise
VersionInfoProductVersion={#AppVersion}
VersionInfoCompany=Michael Ladurner
VersionInfoCopyright=© 2026 Michael Ladurner · Apache License 2.0
VersionInfoDescription=TenantWise Setup
DefaultDirName={localappdata}\Programs\TenantWise
DefaultGroupName=TenantWise
DisableProgramGroupPage=yes
DisableDirPage=yes
UsePreviousAppDir=no
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=TenantWise-Setup-{#AppVersion}
SetupIconFile=..\src\TenantWise.App\tenantwise.ico
UninstallDisplayIcon={app}\TenantWise.exe
UninstallDisplayName=TenantWise
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; Flags: unchecked

[Files]
Source: "..\src\TenantWise.App\bin\Release\net48\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion; Excludes: "*.pdb"
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\NOTICE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion

; Earlier test builds were called Rootline: remove that program folder and its shortcuts.
[InstallDelete]
Type: filesandordirs; Name: "{localappdata}\Programs\Rootline"
Type: files; Name: "{autoprograms}\Rootline.lnk"
Type: files; Name: "{autodesktop}\Rootline.lnk"

[Icons]
Name: "{autoprograms}\TenantWise"; Filename: "{app}\TenantWise.exe"
Name: "{autodesktop}\TenantWise"; Filename: "{app}\TenantWise.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\TenantWise.exe"; Description: "Open TenantWise"; Flags: nowait postinstall skipifsilent

[Code]
// TenantWise shows its window with Microsoft Edge WebView2 (part of Windows 11 and most Windows 10 PCs).
function WebView2Installed(): Boolean;
var v: String;
begin
  Result := RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', v) and (v <> '') and (v <> '0.0.0.0');
  if not Result then
    Result := RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', v) and (v <> '') and (v <> '0.0.0.0');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var code: Integer;
begin
  if (CurStep = ssPostInstall) and (not WebView2Installed()) and (not WizardSilent()) then
    if MsgBox('TenantWise needs the Microsoft Edge WebView2 Runtime, which is missing on this PC.' + #13#10 + #13#10 +
              'Open the Microsoft download page now?', mbConfirmation, MB_YESNO) = IDYES then
      ShellExec('open', 'https://go.microsoft.com/fwlink/p/?LinkId=2124703', '', '', SW_SHOWNORMAL, ewNoWait, code);
end;
