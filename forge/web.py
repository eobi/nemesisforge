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
}

# job_id → JobContext (so /api/job/{id} can read ladder/findings live)
_JOBS: dict[str, object] = {}


class ScanReq(BaseModel):
    preset: str = "heap-overflow"
    harness: str | None = None


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _UI.read_text()


@app.get("/api/presets")
def api_presets() -> dict:
    return {"presets": [{"id": k, "label": v["label"]} for k, v in PRESETS.items()]}


@app.post("/api/scan")
async def api_scan(req: ScanReq) -> dict:
    harness = req.harness or (PRESETS.get(req.preset) or PRESETS["heap-overflow"])["harness"]
    job_id = f"forge-{uuid.uuid4().hex[:10]}"
    ctx, discovery, oracles, escalation = lab_job(job_id, harness,
                                                  artifacts_root=_RUNS, name=req.preset)
    _JOBS[job_id] = ctx
    # fire-and-stream: the run drives the bus the UI is already watching
    asyncio.create_task(run_job(ctx, discovery=discovery, oracles=oracles,
                                escalation=escalation))
    return {"job_id": job_id}


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
