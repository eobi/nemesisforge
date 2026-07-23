@echo off
REM Nemesis Red Zero-Day for Windows — launcher.
REM Runs the zero-day hunt against an operator-supplied Windows binary.
REM Example:
REM   nrzd --exe "C:\Program Files\FastStone Image Viewer\FSViewer.exe" ^
REM        --seeds seeds\a.tga --suffix .tga --tries 800 --timeout 2
"%~dp0python\python.exe" -m forge.windows_hunt %*
