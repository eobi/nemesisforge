# Build "Nemesis Red Zero-Day for Windows" as a self-contained portable bundle.
#
# WHY a separate Windows package: the Red Docker (Linux) does VA + PT +
# source/Linux-component zero-day, but a Linux container cannot run Windows GUI
# desktop apps (FastStone, TextMaker, Power PDF, Acrobat). Windows desktop-binary
# zero-day therefore ships as this native Windows bundle. Target apps are always
# operator-supplied under their own licence; nothing is shipped here but the engine.
#
# Output: dist\NemesisRedZeroDay-portable.zip  = embedded Python + the engine +
# frida (first-chance crash detection + coverage). Extract and run nrzd.cmd.
#
# Run on Windows:  powershell -ExecutionPolicy Bypass -File build_portable.ps1
param(
  [string]$PyVersion = "3.12.7",
  [string]$Out = "dist"
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent (Split-Path -Parent $here)          # repo root
$stage = Join-Path $env:TEMP "nrzd-stage"
Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $stage | Out-Null

Write-Host "[1/5] embeddable Python $PyVersion"
$emb = "python-$PyVersion-embed-amd64.zip"
curl.exe -sL "https://www.python.org/ftp/python/$PyVersion/$emb" -o (Join-Path $stage $emb)
Expand-Archive (Join-Path $stage $emb) -DestinationPath (Join-Path $stage "python") -Force
# The embeddable distro disables site-packages by default; re-enable it so pip works.
$pth = Get-ChildItem (Join-Path $stage "python") -Filter "python*._pth" | Select-Object -First 1
(Get-Content $pth.FullName) -replace '#import site', 'import site' | Set-Content $pth.FullName
Add-Content $pth.FullName "Lib\site-packages"
$py = Join-Path $stage "python\python.exe"

Write-Host "[2/5] pip + frida"
curl.exe -sL https://bootstrap.pypa.io/get-pip.py -o (Join-Path $stage "get-pip.py")
& $py (Join-Path $stage "get-pip.py") --no-warn-script-location
& $py -m pip install --no-warn-script-location frida

Write-Host "[3/5] engine"
Copy-Item (Join-Path $root "forge") (Join-Path $stage "python\forge") -Recurse -Force

Write-Host "[4/5] launcher + docs + seeds"
Copy-Item (Join-Path $here "nrzd.cmd") (Join-Path $stage "nrzd.cmd") -Force
Copy-Item (Join-Path $root "docs\WINDOWS_VM_RUNBOOK.md") (Join-Path $stage "RUNBOOK.md") -Force

Write-Host "[5/5] zip"
New-Item -ItemType Directory -Force (Join-Path $here $Out) | Out-Null
$zip = Join-Path $here "$Out\NemesisRedZeroDay-portable.zip"
Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -Force
Write-Host "built $zip"
Write-Host "For the signed installer: keep this stage dir and run  iscc installer.iss  then signtool."
