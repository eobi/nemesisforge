"""Web layer — the visibility plane's front door.

Serves the live agent-tree UI and streams the event bus over SSE, plus a small
API to kick off a lab job and read its findings. Deliberately thin: all the real
state lives on the event bus + the per-job artifact store; this just exposes it.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from .events import bus_for
from .job import lab_job, run_job

_UI = Path(__file__).resolve().parent.parent / "ui" / "index.html"
_RUNS = Path(__file__).resolve().parent.parent / "runs"

app = FastAPI(title="Nemesis Forge")

# Lab harnesses to demo the fleet end-to-end without an LLM or a real repo.
PRESETS: dict[str, dict] = {
    "heap-overflow": {
        "label": "Heap buffer overflow (unchecked memcpy)",
        "harness": r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void){ char*b=malloc(1); char in[256]; long n=read(0,in,sizeof(in));
 if(n<0)n=0; memcpy(b,in,(unsigned long)n); int r=b[0]; free(b); return r; }
""",
    },
    "use-after-free": {
        "label": "Use-after-free (read freed heap)",
        "harness": r"""
#include <stdlib.h>
#include <unistd.h>
int main(void){ char*b=malloc(32); char in[64]; long n=read(0,in,sizeof(in));
 free(b); if(n>1){ return b[0]; } return 0; }
""",
    },
    "clean": {
        "label": "Clean program (no bug — proves we don't invent findings)",
        "harness": r"""
#include <unistd.h>
int main(void){ char in[16]; long n=read(0,in,sizeof(in)); return (int)(n>0?in[0]:0); }
""",
    },
    # libFuzzer (LLVMFuzzerTestOneInput) presets — auto-routed to the real
    # coverage-guided engine. The "guarded" one is the Phase-G headline: a bug
    # behind a 4-byte magic that a blind length-sweep never reaches but a
    # coverage-guided fuzzer discovers by climbing coverage.
    "libfuzzer-guarded": {
        "label": "Guarded heap overflow (libFuzzer — needs coverage to reach)",
        "harness": r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
  if(size>=4 && data[0]=='F' && data[1]=='U' && data[2]=='Z' && data[3]=='Z'){
    char *b = malloc(4);
    memcpy(b, data, size);            /* heap-buffer-overflow when size>4 */
    volatile int r = b[0]; (void)r; free(b);
  }
  return 0;
}
""",
    },
    "libfuzzer-parser": {
        "label": "Length-field parser confusion (libFuzzer)",
        "harness": r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
/* first byte = declared length; trusts it over the real buffer size */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
  if(size<1) return 0;
  unsigned want = data[0];
  char *buf = malloc(16);
  memcpy(buf, data+1, want);          /* OOB read+write when want>15 */
  volatile int r = buf[0]; (void)r; free(buf);
  return 0;
}
""",
    },
}

# job_id → JobContext (so /api/job/{id} can read ladder/findings live)
_JOBS: dict[str, object] = {}


class ScanReq(BaseModel):
    mode: str = "preset"              # how to point at the asset (see MODES)
    preset: str = "heap-overflow"
    ref: str | None = None           # binary path (mode=binary)
    harness: str | None = None       # custom C harness (mode=harness)
    provider: str | None = None      # LLM brain: portal selection
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None


# Input modes — how you point Forge at an asset.
MODES = [
    {"id": "preset", "label": "Lab asset (built-in vulnerable target)",
     "input": "preset"},
    {"id": "harness", "label": "Custom C harness (paste source)", "input": "code"},
    {"id": "binary", "label": "Binary / firmware (path on disk)", "input": "path"},
    {"id": "repo", "label": "Source repo (git URL) — needs harness synth",
     "input": "url", "status": "beta"},
    {"id": "device", "label": "Android device (adb) — needs a device",
     "input": "serial", "status": "beta"},
]


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _UI.read_text()


@app.get("/api/presets")
def api_presets() -> dict:
    return {"presets": [{"id": k, "label": v["label"]} for k, v in PRESETS.items()]}


@app.get("/api/providers")
def api_providers() -> dict:
    from .llm import list_providers
    return {"providers": list_providers()}


@app.get("/api/modes")
def api_modes() -> dict:
    return {"modes": MODES}


@app.post("/api/scan")
async def api_scan(req: ScanReq) -> dict:
    from .llm import make_client
    from .job import binary_lab_job
    job_id = f"forge-{uuid.uuid4().hex[:10]}"

    if req.mode == "binary" and req.ref:
        ctx, discovery, oracles, escalation = binary_lab_job(
            job_id, req.ref, artifacts_root=_RUNS, name=req.ref.split("/")[-1])
        llm = make_client(req.provider, req.model, req.api_key, req.base_url)
        harness = ""
    else:                                # preset | harness (source path)
        if req.mode == "harness" and req.harness:
            harness, name = req.harness, "custom-harness"
        else:
            harness = (PRESETS.get(req.preset) or PRESETS["heap-overflow"])["harness"]
            name = req.preset
        ctx, discovery, oracles, escalation, llm = lab_job(
            job_id, harness, artifacts_root=_RUNS, name=name,
            provider=req.provider, model=req.model, api_key=req.api_key,
            base_url=req.base_url)

    _JOBS[job_id] = ctx
    asyncio.create_task(run_job(ctx, discovery=discovery, oracles=oracles,
                                escalation=escalation, llm=llm, harness=harness))
    return {"job_id": job_id}


@app.get("/api/runs")
def api_runs() -> dict:
    """History: every past run's metadata, newest first."""
    runs = []
    if _RUNS.exists():
        for d in _RUNS.iterdir():
            mpath = d / "metadata.json"
            if mpath.exists():
                try:
                    runs.append(json.loads(mpath.read_text()))
                except Exception:
                    pass
    runs.sort(key=lambda r: r.get("job_id", ""), reverse=True)
    return {"runs": runs[:100]}


@app.get("/api/job/{job_id}/stream")
async def api_stream(job_id: str) -> StreamingResponse:
    bus = bus_for(job_id)

    async def gen():
        async for ev in bus.stream():
            yield f"data: {json.dumps(ev.to_dict())}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/job/{job_id}")
def api_job(job_id: str) -> dict:
    ctx = _JOBS.get(job_id)
    findings_path = _RUNS / job_id / "findings.json"
    findings = json.loads(findings_path.read_text()) if findings_path.exists() else []
    board = ctx.ladder.board() if ctx is not None else []
    return {"job_id": job_id, "findings": findings, "board": board}
