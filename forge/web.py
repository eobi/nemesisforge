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

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from . import audit, auth
from .events import bus_for
from .job import lab_job, run_job

_UI = Path(__file__).resolve().parent.parent / "ui" / "index.html"
_RUNS = Path(__file__).resolve().parent.parent / "runs"

app = FastAPI(title="Nemesis Forge")

# Wire the audit trail + health tracker to the event bus, and surface the login
# credential if one had to be generated (so a fresh deploy is never wide open).
audit.install(_RUNS / "audit.jsonl")


@app.on_event("startup")
def _announce_auth() -> None:
    if auth.enabled():
        gen = auth.ensure_default_password()
        if gen:
            print(f"[forge] no FORGE_USERS/FORGE_PASSWORD set — "
                  f"login: admin / {gen}")
    else:
        print("[forge] AUTH DISABLED (FORGE_AUTH=off)")


def current_user(request: Request) -> str:
    """Auth dependency: resolve the session cookie to a username, else 401."""
    if not auth.enabled():
        return "anonymous"
    user = auth.verify_token(request.cookies.get(auth.COOKIE, ""))
    if not user:
        raise HTTPException(401, "authentication required")
    return user


class LoginReq(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def api_login(req: LoginReq, response: Response, request: Request) -> dict:
    ip = request.client.host if request.client else "?"
    if not auth.enabled() or auth.verify_credentials(req.username, req.password):
        token = auth.make_token(req.username or "anonymous")
        response.set_cookie(auth.COOKIE, token, httponly=True, samesite="lax",
                            max_age=86400)
        audit.audit() and audit.audit().record(
            "login", actor=req.username, ok=True, ip=ip)
        return {"ok": True, "user": req.username}
    audit.audit() and audit.audit().record(
        "login_failed", actor=req.username, ok=False, ip=ip)
    raise HTTPException(401, "invalid credentials")


@app.post("/api/logout")
def api_logout(response: Response) -> dict:
    response.delete_cookie(auth.COOKIE)
    return {"ok": True}


@app.get("/api/me")
def api_me(user: str = Depends(current_user)) -> dict:
    return {"user": user, "auth": auth.enabled()}


@app.get("/api/health")
def api_health(user: str = Depends(current_user)) -> dict:
    return audit.HEALTH.summary()


@app.get("/api/audit")
def api_audit(user: str = Depends(current_user), limit: int = 200) -> dict:
    log = audit.audit()
    return {"entries": log.recent(limit) if log else []}


_SCOUT_CACHE: dict = {}


@app.get("/api/scout")
def api_scout(user: str = Depends(current_user), limit: int = 15,
              refresh: bool = False) -> dict:
    """Ranked UNDER-FUZZED candidate targets (proposals — a human authorizes each)."""
    from . import scout as _scout
    if refresh or "result" not in _SCOUT_CACHE:
        res = _scout.scout(limit=limit, cache_dir=_RUNS / "_scout")
        _SCOUT_CACHE["result"] = res
        if audit.audit():
            audit.audit().record("scout", actor=user,
                                 found=len(res.get("targets", [])))
    return _SCOUT_CACHE["result"]

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
    ref: str | None = None           # binary path (mode=binary) OR git ref (mode=repo)
    url: str | None = None           # git URL (mode=repo)
    harness: str | None = None       # custom C harness (mode=harness)
    provider: str | None = None      # LLM brain: portal selection
    model: str | None = None
    api_key: str | None = None
    base_url: str | None = None
    fuzz_time: int | None = None     # per-target fuzz budget (repo mode)
    max_targets: int | None = None   # how many sinks to harness (repo mode)
    campaign_minutes: int | None = None  # deep campaign per harness (Phase L)
    diff_ref: str | None = None      # continuous mode: hunt functions changed since
    seed_commit: str | None = None   # L3: variant-hunt from this repo's fix commit
    seed_patch: str | None = None    # L3: variant-hunt from a supplied patch diff
    sanitizer: str | None = None     # e.g. "address" (only real corruption) vs +undefined


# Input modes — how you point Forge at an asset.
MODES = [
    {"id": "preset", "label": "Lab asset (built-in vulnerable target)",
     "input": "preset"},
    {"id": "harness", "label": "Custom C harness (paste source)", "input": "code"},
    {"id": "binary", "label": "Binary / firmware (path on disk)", "input": "path"},
    {"id": "repo", "label": "Source repo (git URL) — LLM synthesizes harnesses",
     "input": "url"},
    {"id": "device", "label": "Android device (adb) — needs a device",
     "input": "serial", "status": "beta"},
]


_UIDIR = Path(__file__).resolve().parent.parent / "ui"


def _page(name: str) -> str:
    return (_UIDIR / name).read_text()


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _page("console.html")


@app.get("/activity", response_class=HTMLResponse)
def page_activity() -> str:
    return _page("activity.html")


@app.get("/history", response_class=HTMLResponse)
def page_history() -> str:
    return _page("history.html")


@app.get("/run/{job_id}", response_class=HTMLResponse)
def page_run(job_id: str) -> str:
    return _page("run.html")


@app.get("/health", response_class=HTMLResponse)
def page_health() -> str:
    return _page("health.html")


@app.get("/hunt", response_class=HTMLResponse)
def page_hunt() -> str:
    return _page("hunt.html")


@app.get("/app.css")
def app_css() -> Response:
    return Response(_page("app.css"), media_type="text/css")


@app.get("/app.js")
def app_js() -> Response:
    return Response(_page("app.js"), media_type="application/javascript")


@app.get("/api/presets")
def api_presets(user: str = Depends(current_user)) -> dict:
    return {"presets": [{"id": k, "label": v["label"]} for k, v in PRESETS.items()]}


@app.get("/api/providers")
def api_providers(user: str = Depends(current_user)) -> dict:
    from .llm import list_providers
    return {"providers": list_providers()}


@app.get("/api/modes")
def api_modes(user: str = Depends(current_user)) -> dict:
    return {"modes": MODES}


@app.post("/api/scan")
async def api_scan(req: ScanReq, user: str = Depends(current_user)) -> dict:
    from .llm import make_client
    from .job import binary_lab_job
    job_id = f"forge-{uuid.uuid4().hex[:10]}"
    target_desc = req.url or req.ref or req.preset or req.mode
    log = audit.audit()
    if log:
        log.record("scan", actor=user, job_id=job_id, mode=req.mode,
                   target=target_desc, provider=req.provider)

    if req.mode == "repo" and req.url:
        from .job import repo_job
        try:
            ctx, discovery, oracles, escalation, llm = repo_job(
                job_id, req.url, ref=req.ref or None, artifacts_root=_RUNS,
                diff_ref=req.diff_ref or None, seed_commit=req.seed_commit or None,
                seed_patch=req.seed_patch or "", sanitizer=req.sanitizer or None,
                max_targets=req.max_targets or 3, fuzz_time=req.fuzz_time or 30,
                campaign_minutes=req.campaign_minutes or 0,
                provider=req.provider, model=req.model, api_key=req.api_key,
                base_url=req.base_url)
        except Exception as e:
            raise HTTPException(400, f"repo ingestion failed: {e}")
        harness = ""
    elif req.mode == "binary" and req.ref:
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
def api_runs(user: str = Depends(current_user)) -> dict:
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
async def api_stream(job_id: str, user: str = Depends(current_user)
                     ) -> StreamingResponse:
    bus = bus_for(job_id)

    async def gen():
        async for ev in bus.stream():
            yield f"data: {json.dumps(ev.to_dict())}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/job/{job_id}")
def api_job(job_id: str, user: str = Depends(current_user)) -> dict:
    ctx = _JOBS.get(job_id)
    d = _RUNS / job_id
    findings_path = d / "findings.json"
    findings = json.loads(findings_path.read_text()) if findings_path.exists() else []
    meta = {}
    if (d / "metadata.json").exists():
        try:
            meta = json.loads((d / "metadata.json").read_text())
        except Exception:
            meta = {}
    board = ctx.ladder.board() if ctx is not None else meta.get("board", [])
    return {"job_id": job_id, "findings": findings, "board": board,
            "meta": meta, "running": _is_running(job_id, meta)}


@app.get("/api/job/{job_id}/events")
def api_job_events(job_id: str, user: str = Depends(current_user),
                   limit: int = 100000) -> dict:
    """The full checkpoint timeline of a run — durable (persisted per event in
    real time), so any job is loadable end-to-end even after it finishes."""
    ep = audit.events()
    evs = ep.load(job_id, limit=limit) if ep else []
    return {"job_id": job_id, "events": evs, "running": _is_running(job_id)}


def _is_running(job_id: str, meta: dict | None = None) -> bool:
    if meta is None:
        p = _RUNS / job_id / "metadata.json"
        meta = json.loads(p.read_text()) if p.exists() else {}
    return job_id in audit.HEALTH._active_jobs or meta.get("status") == "running"


@app.get("/api/jobs")
def api_jobs(user: str = Depends(current_user), limit: int = 200) -> dict:
    """Every run — live + historical — for the Activity + History pages."""
    jobs = []
    if _RUNS.exists():
        for dd in _RUNS.iterdir():
            mp = dd / "metadata.json"
            if not mp.exists():
                continue
            try:
                m = json.loads(mp.read_text())
            except Exception:
                continue
            m["running"] = _is_running(m.get("job_id", dd.name), m)
            m["has_events"] = (dd / "events.jsonl").exists()
            jobs.append(m)
    jobs.sort(key=lambda r: r.get("job_id", ""), reverse=True)
    running = [j for j in jobs if j.get("running")]
    return {"jobs": jobs[:limit], "running": running,
            "counts": {"total": len(jobs), "running": len(running)}}
