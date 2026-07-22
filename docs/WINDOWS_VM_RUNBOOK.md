# Windows VM runbook — run a desktop-binary zero-day hunt end to end

This is the checklist for running the Phase-2 Windows path on a disposable Windows VM
(AWS EC2 Windows, or any Windows 10/11 host). It gets you from a fresh VM to a proof-ladder
finding against a closed file-parser (FastStone, TextMaker, Power PDF, Acrobat).

> Safety: fuzz only the operator's **own licensed install**, on a **disposable VM snapshot**.
> Never point it at software you are not authorized to test. Ship no app binaries.

---

## 1. Provision the VM
- AWS EC2 Windows Server 2022 (or Windows 10/11), 4+ vCPU, 8+ GB RAM.
- Take a **snapshot** before fuzzing so you can roll back a corrupted app state.
- RDP in (or WinRM/SSH for headless driving).

## 2. Install prerequisites (PowerShell)
```powershell
# Python 3.12
winget install -e --id Python.Python.3.12
# The engine
git clone <NemesisForge remote> C:\forge ; cd C:\forge
py -3.12 -m pip install -e .          # or: pip install -r requirements
# Coverage-guided mode (optional, for M1). argv-mode works without it.
py -3.12 -m pip install frida
```

## 3. Install the target app (operator's own license)
Install the app normally, then note the exe path, e.g.:
- FastStone: `C:\Program Files\FastStone Image Viewer\FSViewer.exe`
- TextMaker: `C:\Program Files\SoftMaker\Office ...\textmaker.exe`
- Power PDF / Acrobat: their install path.

## 4. Prepare seeds
A handful of small, valid files of the format the app parses (the smaller the better for speed):
```
C:\forge\seeds\a.tga   b.pcx   c.bmp        # images (FastStone)
C:\forge\seeds\a.pdf                          # PDF (Power PDF / Acrobat)
C:\forge\seeds\a.tmd   b.docx                 # office (TextMaker)
```

## 5. Run the hunt

### FastStone (image) — the fastest win
```powershell
py -3.12 -m forge.windows_hunt `
  --exe "C:\Program Files\FastStone Image Viewer\FSViewer.exe" `
  --seeds C:\forge\seeds\a.tga C:\forge\seeds\b.pcx `
  --suffix .tga --argv-template "{file}" --tries 800 --timeout 15
```

### TextMaker (office)
```powershell
py -3.12 -m forge.windows_hunt `
  --exe "C:\Program Files\SoftMaker\...\textmaker.exe" `
  --seeds C:\forge\seeds\a.tmd --suffix .tmd --tries 800
```

### PDF (Power PDF / Acrobat)
```powershell
py -3.12 -m forge.windows_hunt --exe "<...>.exe" `
  --seeds C:\forge\seeds\a.pdf --suffix .pdf --tries 800 --timeout 25
```

Flags:
- `--argv-template` how the file is passed (default `{file}` = `App.exe <file>`). Use e.g.
  `"/o {file}"` if the app needs a switch.
- `--coverage auto` (default) goes coverage-guided when `frida` is installed; `off` forces argv-mode.
- `--tries` inputs per campaign; `--timeout` seconds per input (GUI apps need a few seconds).
- `--json` for machine-readable output.

## 6. Read the result
The tool prints the proof ladder + finding count and writes artifacts to `runs\<job_id>\`:
- a native-reproduced crashing input file,
- the crash class (from the NTSTATUS exception),
- (with the exploitability oracle) the faulting-instruction primitive grade.

A **clean run reports nothing** — the engine never invents findings.

## 7. What runs where (honest state)
- **argv-mode (tested):** mutate a seed → open with the app → catch the Windows exception →
  `native-verify` replays it → `exploitability` grades it. Finds the shallow header/field
  overflows typical of these parsers (the FastStone class). Works today on the VM.
- **coverage-guided (M1, validate live):** with `frida` installed, `--coverage auto` arms
  Stalker around the parse and keeps coverage-adding inputs to reach deep code. The driver is
  best-effort and degrades to argv-mode on any instrumentation error — validate + tune it on
  the VM (spawn/attach/crash-callback specifics vary by app).

## 8. Next (M2+)
- **Persistent in-process harness:** hook the decoder entry (from RE) and loop without
  restarting the app → 100–1000× throughput. Per format.
- **WinDbg-fed exploitability:** attach cdb for the exact faulting instruction + registers →
  automate the write-what-where proof (the FastStone arbitrary-write, done by the engine).
- **DynamoRIO/WinAFL coverage backend** as the primary engine for big apps (Acrobat).
