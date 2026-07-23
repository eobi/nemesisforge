; Nemesis Red Zero-Day for Windows — Inno Setup installer.
; Build (on Windows, after build_portable.ps1 has staged the bundle under stage\):
;   iscc installer.iss
; Sign (Authenticode EV, matching Nemesis Blue):
;   signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /a ^
;     Output\NemesisRedZeroDaySetup.exe
[Setup]
AppName=Nemesis Red Zero-Day
AppVersion=0.1.0
AppPublisher=Nemesis Labs
DefaultDirName={autopf}\NemesisRedZeroDay
DefaultGroupName=Nemesis Red Zero-Day
OutputBaseFilename=NemesisRedZeroDaySetup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
DisableProgramGroupPage=yes
[Files]
; stage\ is produced by build_portable.ps1 (embedded Python + forge + frida + nrzd.cmd)
Source: "%TEMP%\nrzd-stage\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs
[Icons]
Name: "{group}\Nemesis Red Zero-Day (console)"; Filename: "{cmd}"; \
  Parameters: "/k ""cd /d {app} && nrzd.cmd --help"""
Name: "{group}\Runbook"; Filename: "{app}\RUNBOOK.md"
[Run]
Filename: "{cmd}"; Parameters: "/k ""cd /d {app} && nrzd.cmd --help"""; \
  Description: "Open the Nemesis Red Zero-Day console"; Flags: postinstall skipifsilent
