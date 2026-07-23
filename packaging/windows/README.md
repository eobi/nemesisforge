# Nemesis Red Zero-Day for Windows

The Windows desktop-binary zero-day scanner. Separate from the Red Docker (which
does VA + PT + source/Linux-component zero-day on Linux) because a Linux container
cannot run Windows GUI apps. Point it at an operator-supplied, licensed Windows
file-parser (FastStone, TextMaker, Power PDF, Acrobat, …) in a disposable VM and it
fuzzes → detects (first-chance exceptions, catching SEH-swallowed faults) →
native-verifies → grades exploitability (write-what-where) → assembles a
coordinated-disclosure packet. Only proven, novel bugs are reported.

## What ships
The engine only. **Target apps are never shipped** — install your own licensed copy.

## Two delivery forms
- **Portable zip** (recommended for disposable VMs): `build_portable.ps1` produces
  `dist\NemesisRedZeroDay-portable.zip` = embedded Python + the engine + frida.
  Extract, then run `nrzd.cmd`.
- **Signed installer**: after staging with `build_portable.ps1`, `iscc installer.iss`
  builds `NemesisRedZeroDaySetup.exe`; sign it with Authenticode EV (Nemesis Labs).

## Build (on a Windows machine)
```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\build_portable.ps1
# → packaging\windows\dist\NemesisRedZeroDay-portable.zip
```

## Run
```powershell
nrzd --exe "C:\Program Files\FastStone Image Viewer\FSViewer.exe" `
     --seeds seeds\a.tga --suffix .tga --tries 800 --timeout 2
```
See `RUNBOOK.md` (bundled) for the full walkthrough, coverage modes, and safety.

## Safety
Fuzz only software you own or are authorised to test, in a disposable VM snapshot.
Every third-party finding goes through coordinated disclosure.
