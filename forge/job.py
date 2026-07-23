"""Job runner — assembles the fleet for one engagement and runs it to findings.

Brackets a run with JOB_START / JOB_DONE on the event bus (so the UI knows when
to stop streaming), routes discovery + oracles through the Coordinator, and
persists findings to the per-job artifact store. `lab_job` is the LLM-free
end-to-end used for Phase-A demos/tests: a SourceTarget + a fuzzing discovery
agent + the sanitizer oracle.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, is_dataclass
from functools import partial
from pathlib import Path
from typing import Callable, Optional

from . import fuzzengine
from .agents.fuzz_discovery import FuzzDiscoveryAgent
from .agents.libfuzzer_discovery import LibFuzzerDiscoveryAgent
from .context import JobContext
from .coordinator import Coordinator
from .events import EventType
from .ladder import Finding
from .oracles.base import Oracle
from .oracles.controllability import ControllabilityOracle
from .oracles.sanitizer import SanitizerOracle
from .targets.source import SourceTarget


def _jsonable(obj):
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if hasattr(obj, "value"):            # enums
        return obj.value
    return obj


def _persist(ctx: JobContext, findings: list[Finding]) -> None:
    out = ctx.artifacts / "findings.json"
    out.write_text(json.dumps([_jsonable(f) for f in findings], indent=2,
                              default=str))


def _meta(ctx: JobContext, **kw) -> None:
    """Persist run metadata for the history view."""
    path = ctx.artifacts / "metadata.json"
    cur = {}
    if path.exists():
        try:
            cur = json.loads(path.read_text())
        except Exception:
            cur = {}
    cur.update(kw)
    path.write_text(json.dumps(cur, default=str))


async def run_job(ctx: JobContext, *, discovery: list[Callable],
                  oracles: list[Oracle], escalation: list[Oracle] | None = None,
                  llm=None, harness: str = "") -> list[Finding]:
    tname = getattr(ctx.target, "name", "") or ctx.job_id
    ttype = getattr(ctx.target, "target_type", "")
    llm_name = getattr(llm, "model", None) if getattr(llm, "available", False) else None
    ctx.bus.append(EventType.JOB_START, target=tname, target_type=ttype, llm=llm_name)
    _meta(ctx, job_id=ctx.job_id, target=tname, target_type=ttype, llm=llm_name,
          status="running")
    findings: list[Finding] = []
    try:
        coord = Coordinator(ctx, discovery=discovery, oracles=oracles,
                            escalation=escalation, llm=llm, harness=harness,
                            patch=getattr(ctx, "enable_patch", False))
        findings = await coord.execute() or []
        # governance: collapse duplicate bugs, classify novelty vs a persistent
        # known-crash corpus (so only GENUINELY new bugs read as candidates), never
        # auto-labeling a zero-day.
        from .dedup import dedupe
        from .knowncrashes import KnownCrashes
        findings, removed = dedupe(findings)
        if removed:
            ctx.bus.append(EventType.LOG,
                           text=f"deduped {removed} duplicate finding(s)")
        corpus = KnownCrashes(ctx.artifacts.parent / "known_crashes.json")
        from . import cve_check
        lib = getattr(getattr(ctx, "repo", None), "root", None)
        libname = lib.name if lib else getattr(ctx.target, "name", "")
        for f in findings:
            f.novelty = corpus.classify(f)
            # Cross-check against real advisories — NEVER auto-claim "novel". Attach
            # the verdict + the exact queries a human must run to confirm a 0-day.
            cr = (f.verdict.evidence or {}).get("crash", {})
            top = (cr.get("frames") or [{}])[0]
            ver = cve_check.assess(library=libname,
                                   function=top.get("func", ""),
                                   bug_type=cr.get("bug_type", ""))
            f.artifacts["novelty_verification"] = ver
            if ver["status"] == cve_check.KNOWN:
                f.novelty = "n-day"          # matched a real advisory
        corpus.save()
        # API-misuse triage: a proven crash can be the HARNESS's fault (mis-sized
        # buffer, attacker data as a size/filename param, invalid API combo) rather
        # than a library bug. Flag those so an artifact never reads as a zero-day
        # candidate (what adpcm-xq turned out to be). Annotates + de-rates only;
        # never deletes a finding — a human still decides.
        from . import misuse_triage
        await misuse_triage.review(ctx, findings, llm)
        unver = sum(1 for f in findings if f.novelty == "candidate")
        if findings:
            ctx.bus.append(EventType.LOG,
                           text=f"novelty: {unver} UNVERIFIED candidate(s) "
                                f"(require CVE cross-check — never auto-0day), "
                                f"{len(findings) - unver} known/n-day")
    except Exception as e:               # a job must fail loud but clean
        ctx.bus.append(EventType.ERROR, error=f"{type(e).__name__}: {e}")
    _persist(ctx, findings)
    top = max((int(f.rung) for f in findings), default=0)
    _meta(ctx, status="done", findings=len(findings),
          vendor_ready=sum(1 for f in findings if f.vendor_shippable),
          top_rung=top)
    ctx.bus.append(
        EventType.JOB_DONE,
        findings=len(findings),
        reportable=sum(1 for f in findings if f.reportable),
        vendor_ready=sum(1 for f in findings if f.vendor_shippable),
        board=ctx.ladder.board(),
    )
    return findings


def _dict_from(harness: str, root: Path, job_id: str) -> Optional[Path]:
    """Cheap structure hint: seed a libFuzzer dictionary from quoted string /
    magic-byte literals in the harness so it clears guards faster."""
    import re
    toks = set(re.findall(r'"([ -~]{2,32})"', harness))
    toks |= {t for t in re.findall(r"'([ -~]{2,8})'", harness)}
    if not toks:
        return None
    d = root / job_id / "fuzz.dict"
    d.parent.mkdir(parents=True, exist_ok=True)
    d.write_text("\n".join(f'kw{i}="{t}"' for i, t in enumerate(sorted(toks))))
    return d


def lab_job(job_id: str, harness: str, *, artifacts_root: Optional[Path] = None,
            name: str = "lab-target", max_tries: int = 8, escalate: bool = True,
            fuzz_time: int = 20,
            provider: Optional[str] = None, model: Optional[str] = None,
            api_key: Optional[str] = None, base_url: Optional[str] = None):
    """Assemble the end-to-end: fuzz + (optional) LLM brain → sanitizer-prove →
    escalate (+ LLM synthesis) toward a controlled primitive.

    Discovery auto-routes: an `LLVMFuzzerTestOneInput` harness on a machine with a
    libFuzzer-capable clang runs the real coverage-guided engine; otherwise the
    legacy length-sweep fuzzer (so it always degrades, never breaks).

    Returns (ctx, discovery, oracles, escalation, llm). With a provider selected,
    the LLM brain runs alongside the fuzzer and LLM synthesis aids escalation;
    without one it's NullLLM and the deterministic pipeline is unchanged.
    """
    from .llm import make_client
    root = artifacts_root or (Path.cwd() / "runs")
    target = SourceTarget(root / job_id / "work", name=name)
    ctx = JobContext(job_id, target=target, artifacts_root=root)

    if "LLVMFuzzerTestOneInput" in harness and fuzzengine.find_libfuzzer_clang():
        discovery = [partial(LibFuzzerDiscoveryAgent, harness=harness,
                             corpus_dir=root / job_id / "corpus",
                             dict_path=_dict_from(harness, root, job_id),
                             max_total_time=fuzz_time)]
    else:
        discovery = [partial(FuzzDiscoveryAgent, harness=harness, max_tries=max_tries)]

    oracles: list[Oracle] = [SanitizerOracle()]
    escalation: list[Oracle] = [ControllabilityOracle()] if escalate else []
    llm = make_client(provider, model, api_key, base_url)
    return ctx, discovery, oracles, escalation, llm


def repo_job(job_id: str, url: str, *, ref: Optional[str] = None,
             diff_ref: Optional[str] = None, seed_commit: Optional[str] = None,
             seed_patch: str = "", sanitizer: Optional[str] = None,
             artifacts_root: Optional[Path] = None, max_targets: int = 3,
             fuzz_time: int = 30, campaign_minutes: int = 0, escalate: bool = True,
             use_build_system: bool = True, use_symbolic: bool = True,
             ensemble: bool = False, patch: bool = False,
             reach_hints: Optional[set] = None,
             provider: Optional[str] = None, model: Optional[str] = None,
             api_key: Optional[str] = None, base_url: Optional[str] = None):
    """Point Forge at a real open-source repo by URL: clone → the LLM synthesizes
    coverage-validated fuzz harnesses for its untrusted-input entry points → the
    libFuzzer engine fuzzes each → the sanitizer oracle proves every crash.

    Returns (ctx, discovery, oracles, escalation, llm). Needs a model (harness
    synthesis is the LLM's job) and a libFuzzer-capable clang."""
    from .agents.variant_hunter import VariantHunterAgent
    from .ingest import repo as _repo
    from .llm import make_client

    root = artifacts_root or (Path.cwd() / "runs")
    repo_name = re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1]) or "repo"
    info = _repo.clone(url, root / job_id / repo_name, ref=ref)
    # Reachability directing (asset-context speedup): when the caller passes the
    # function-name hints for the surface the live asset exposes, prioritize the
    # matching entry-point sources so harness synthesis aims at the reachable
    # decoders first. Inert by default (None) and never prunes to nothing.
    if reach_hints:
        from .ingest.reachability import focus_sources
        info.sources = focus_sources(info.sources, reach_hints, info.root)
    target = SourceTarget(root / job_id / "work", name=repo_name)
    ctx = JobContext(job_id, target=target, artifacts_root=root)
    ctx.repo = info                                  # for the visibility layer
    ctx.enable_patch = patch                         # Phase 3B: PoV-gated patcher
    # Phase N: build the repo with its OWN build system (make/cmake/autotools) +
    # our instrumentation, then link every harness against the resulting archive.
    # This is how OSS-Fuzz reaches HARD, multi-file targets a file-by-file compile
    # can't — exactly where fresh zero-days survive. Best-effort and time-boxed: if
    # the build system needs external deps or an exotic setup, we log and fall back
    # to the file-by-file path (source.build keeps a per-build fallback too).
    ctx.build_system = {"attempted": False, "ok": False}
    if use_build_system:
        from .ingest.build_system import build_library
        cc = fuzzengine.find_libfuzzer_clang()
        if cc:
            prod = build_library(Path(info.root), compiler=cc,
                                 sanitizer=(sanitizer or "address"), timeout=300)
            ctx.build_system = {"attempted": True, "ok": bool(prod.ok),
                                "system": prod.system,
                                "archives": len(prod.archives)}
            if prod.ok and prod.link_inputs():   # archive OR loose objects (cmake
                target.extra_link_objects = prod.link_inputs()   # often emits .o)
                bdir = Path(info.root) / "_forge_build"
                target.extra_include_dirs = [Path(info.root)] + (
                    [bdir] if bdir.exists() else [])
    ctx.no_auto_strategist = True                    # variant-hunter IS the LLM tier
    # Phase L: seed the fuzzer from the repo's OWN test/sample inputs (huge cold-
    # start coverage win), and persist the corpus per-target so campaigns compound.
    ctx.seed_files = _repo.harvest_seeds(info.root)
    if campaign_minutes:
        ctx.budget.deadline_s = max(ctx.budget.deadline_s,
                                    campaign_minutes * 60 + 600)
    corpus_root = root / "_corpora" / repo_name      # STABLE across runs → resumes
    llm = make_client(provider, model, api_key, base_url)
    # Continuous mode (Phase K): if a diff ref is given, hunt only the functions
    # changed since it — catch a regression the day the commit lands.
    ctx.llm = llm                        # so run_job/misuse-triage can reach it even
                                         # if a caller doesn't thread llm into run_job
    changed = _repo.changed_functions(info.root, diff_ref) if diff_ref else None
    # Phase L3: seed variant analysis from a real bug-fix patch (its own commit, or
    # a diff supplied from ANOTHER repo — a fix in lib A often has a twin in lib B).
    patch = seed_patch or (_repo.patch_diff(info.root, seed_commit)
                           if seed_commit else "")
    # The reasoning tier (Phase I): understand the code, rank reachable sinks, and
    # AIM harness synthesis + fuzzing where a bug most likely hides. It spawns
    # harness-synth sub-agents, so it subsumes the plain-synth path.
    vh = dict(max_targets=max_targets, fuzz_time=fuzz_time,
              campaign_minutes=campaign_minutes, changed_functions=changed,
              seed_patch=patch, corpus_root=corpus_root, symbolic=use_symbolic)
    if sanitizer:                          # e.g. "address" — hunt real corruption,
        vh["sanitizer"] = sanitizer        # not benign UB that halts the fuzzer early
    # Multi-lens: the dynamic fuzzer + a SOURCE-code static-analysis lens run in
    # parallel — static flags leads on paths the fuzzer can't reach, and corroborates
    # dynamic crashes.
    from .agents.static_analysis import StaticAnalysisAgent
    discovery = [partial(VariantHunterAgent, repo=info, llm=llm, **vh),
                 partial(StaticAnalysisAgent, repo=info)]
    if ensemble:
        # ATLANTIS-style N-version programming: a second, deliberately ORTHOGONAL
        # strategy so no single blind spot correlates. The primary is conservative
        # (its configured sanitizer, low false-positive noise); the risky variant
        # widens the sanitizer set to also flag UB-adjacent corruption that the
        # address-only run halts on early. run_job's `dedupe` merges overlapping
        # crashes; each finding is tagged by its agent name ("variant-hunter" vs
        # "variant-hunter-risky") so we can see which strategy landed it.
        vh_risky = dict(vh, sanitizer="address,undefined")
        discovery.insert(1, partial(VariantHunterAgent, repo=info, llm=llm,
                                    name="variant-hunter-risky", **vh_risky))
    oracles: list[Oracle] = [SanitizerOracle()]
    escalation: list[Oracle] = [ControllabilityOracle()] if escalate else []
    return ctx, discovery, oracles, escalation, llm


def zeroday_repo_job(job_id: str, artifact, *, reach_hints=None,
                     seed_patch: str = "", seed_commit: Optional[str] = None,
                     diff_ref: Optional[str] = None,
                     artifacts_root: Optional[Path] = None,
                     ensemble: bool = True, patch: bool = False,
                     campaign_minutes: int = 0,
                     provider: Optional[str] = None, model: Optional[str] = None,
                     api_key: Optional[str] = None, base_url: Optional[str] = None):
    """The asset-pointed zero-day campaign assembler: a resolved OSS-source
    artifact (from `forge.ingest.resolve`) → a directed, verifier-gated hunt.

    It stacks the asset-context speedups on top of Forge's existing repo hunt:
      - **version-exact pin:** clone at `artifact.ref` (the exact running version),
        so patch-seeding targets the *specific* missing fixes, not a generic corpus;
      - **reachability directing:** `reach_hints` (from `reachability.reachable_hints`
        on the asset's exposure) prioritizes the entry-point sources the asset
        actually exposes, pruning the search before fuzzing;
      - **patch-seeded variant hunting:** `seed_patch`/`seed_commit`/`diff_ref` feed
        the variant hunter a known fix to find un-patched twins;
      - **ensemble ON by default:** orthogonal strategies so no single blind spot stalls.

    Thin, additive wrapper over `repo_job` (reuses its whole pipeline + the
    escalation oracles). Only OSS-source artifacts route here; binary artifacts go
    through `binary_lab_job` (native-verify + exploitability). Raises a clear error
    for a non-source artifact so a caller can dispatch correctly."""
    kind = getattr(artifact, "kind", None)
    if kind != "source":
        raise ValueError(
            f"zeroday_repo_job needs a resolved SOURCE artifact; got kind={kind!r}. "
            f"Route binaries through binary_lab_job, packages via the Phase-1 fetch.")
    url = getattr(artifact, "locator", "")
    ref = getattr(artifact, "ref", "") or None
    hints = set(reach_hints) if reach_hints else None
    return repo_job(
        job_id, url, ref=ref, diff_ref=diff_ref, seed_commit=seed_commit,
        seed_patch=seed_patch, artifacts_root=artifacts_root,
        campaign_minutes=campaign_minutes, ensemble=ensemble, patch=patch,
        reach_hints=hints, provider=provider, model=model, api_key=api_key,
        base_url=base_url)


def binary_lab_job(job_id: str, binary_path: str, *,
                   artifacts_root: Optional[Path] = None,
                   name: str = "binary-target", max_tries: int = 8
                   ) -> tuple[JobContext, list[Callable], list[Oracle], list[Oracle]]:
    """Assemble a job for a closed-source binary: fuzz it concretely → prove the
    crash by signal → (symbolic escalation lights up if angr is present)."""
    from .oracles.binary_crash import BinaryCrashOracle
    from .oracles.native_verify import NativeVerifyOracle
    from .oracles.exploitability import ExploitabilityOracle
    from .oracles.symbolic import SymbolicOracle
    from .targets.binary import BinaryTarget
    from .agents.binary_recon import BinaryReconAgent

    root = artifacts_root or (Path.cwd() / "runs")
    target = BinaryTarget(binary_path, name=name)
    ctx = JobContext(job_id, target=target, artifacts_root=root)
    # Multi-lens on binaries too: the RE lens (imports/strings triage) flags sink
    # functions in parallel with the concrete fuzzer, and corroborates a crash that
    # lands in a flagged routine.
    discovery = [partial(FuzzDiscoveryAgent, harness="", bug_class="binary_crash",
                         max_tries=max_tries),
                 partial(BinaryReconAgent, binary=Path(binary_path))]
    # NativeVerifyOracle handles the distinct `instrumented_crash` class a
    # coverage-guided (Frida/QEMU) discovery agent emits — it never shadows the
    # BinaryCrashOracle. ExploitabilityOracle joins the escalation tier: after a
    # fault is proven it grades the faulting instruction into a primitive (rung 4).
    oracles: list[Oracle] = [BinaryCrashOracle(), NativeVerifyOracle()]
    escalation: list[Oracle] = [SymbolicOracle(), ExploitabilityOracle()]
    return ctx, discovery, oracles, escalation


def windows_hunt_job(job_id: str, exe_path: str, *, name: str,
                     seeds: Optional[list] = None,
                     argv_template: Optional[list] = None,
                     input_suffix: str = "", coverage: str = "auto",
                     artifacts_root: Optional[Path] = None,
                     max_tries: int = 300, timeout: float = 20.0
                     ) -> tuple[JobContext, list[Callable], list[Oracle], list[Oracle]]:
    """Assemble a Windows desktop-binary hunt (Phase 2): a `WindowsBinaryTarget`
    driven by the `WindowsFuzzer` in argv/file mode, coverage-guided when a Frida
    backend is available. A crash climbs the same ladder: binary-crash proves the
    fault, native-verify discards instrumentation artifacts, exploitability grades
    the faulting instruction into a primitive. Runs on the native Windows agent.

    coverage: "auto" (use Frida if importable, else argv-mode), "frida", or "off".
    Returns (ctx, discovery, oracles, escalation)."""
    from .targets.windows import WindowsBinaryTarget
    from .agents.windows_fuzzer import WindowsFuzzer
    from .oracles.binary_crash import BinaryCrashOracle
    from .oracles.native_verify import NativeVerifyOracle
    from .oracles.exploitability import ExploitabilityOracle

    root = artifacts_root or (Path.cwd() / "runs")
    target = WindowsBinaryTarget(exe_path, name=name, argv_template=argv_template,
                                 input_suffix=input_suffix)
    ctx = JobContext(job_id, target=target, artifacts_root=root)

    # Reliable crash detection via first-chance exceptions (catches SEH-swallowed
    # access-violations that exit 0). Set on the target so BOTH discovery and
    # oracle verification observe the crash the same way — fixing the native-verify
    # contradiction where a real SEH crash was refuted as an artifact. This is the
    # crash SIGNAL and is independent of the coverage setting (so `coverage=off`
    # still catches SEH crashes); degrades to exit-code detection without frida.
    from .targets.binary_cov import FridaExceptionObserver
    _obs = FridaExceptionObserver(target)
    if _obs.available():
        target.crash_observer = _obs

    # Coverage backend for the fuzz-feedback loop. drcov (DynamoRIO) is preferred
    # — module-relative blocks (ASLR-safe), all threads — with Frida-Stalker as the
    # fallback. Crash detection is the observer's job, not the coverage backend's.
    backend = None
    if coverage in ("auto", "drcov"):
        from .targets.win_coverage import DrcovCoverage
        db = DrcovCoverage(target)
        if db.available():
            backend = db
    if backend is None and coverage in ("auto", "frida"):
        from .targets.binary_cov import FridaStalkerCoverage
        fb = FridaStalkerCoverage(target)
        backend = fb if fb.available() else None
    discovery = [partial(WindowsFuzzer, seeds=seeds, coverage=backend,
                         max_tries=max_tries, timeout=timeout)]
    oracles: list[Oracle] = [BinaryCrashOracle(), NativeVerifyOracle()]
    escalation: list[Oracle] = [ExploitabilityOracle()]
    return ctx, discovery, oracles, escalation
