"""CVE-patch variant hunt: seed from a known bug-fix patch, hunt un-patched twins
of the SAME pattern in a target library (Big Sleep's method).

Usage: python scripts/variant_hunt.py <git-url> <minutes>
Seeds from the CWPack short-read / unchecked-length fix.
"""
import asyncio, sys, uuid, time, json
from pathlib import Path
from forge.config import load_env
load_env()
from forge.job import repo_job, run_job

# The CWPack bug + fix as the seed pattern: an input-derived length/count drives a
# buffer operation without validating it against the bytes ACTUALLY available, so a
# short read / oversized declared length advances the cursor past the buffer end.
CWPACK_SEED = r"""--- a/goodies/basic-contexts/basic_contexts.c
+++ b/goodies/basic-contexts/basic_contexts.c
@@ handle_stream_unpack_underflow: refill the unpack buffer @@
     unsigned long l = fread(uc->end, 1, suc->buffer_length - remains, suc->file);
-    if (!l)                       /* BUG: only a ZERO read is treated as short */
+    uc->end += l;
+    /* A SHORT read (0 < l < more) was wrongly treated as success, so the parser
+       advanced `current` past `end`; the next refill computed remains = end -
+       current as a huge unsigned value and called memmove with it (heap OOB).
+       PATTERN: a length/count from untrusted input drives a buffer op WITHOUT
+       checking it against the bytes actually available. FIX: require the
+       requested bytes to be present before returning success. */
+    if ((unsigned long)(uc->end - uc->current) < more)
     {
         if (feof(suc->file)) return CWP_RC_END_OF_INPUT;
         suc->uc.err_no = ferror(suc->file);
         return CWP_RC_ERROR_IN_HANDLER;
     }
-    uc->end += l;
     return CWP_RC_OK;
"""


async def main():
    url = sys.argv[1]
    mins = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    jid = "variant-" + uuid.uuid4().hex[:8]
    root = Path.cwd() / "runs"
    name = url.rstrip("/").split("/")[-1]
    print(f"[{time.strftime('%H:%M:%S')}] VARIANT HUNT on {name} seeded from CWPack "
          f"unchecked-length pattern (job={jid}, {mins}min)", flush=True)
    ctx, discovery, oracles, escalation, llm = repo_job(
        jid, url, artifacts_root=root, max_targets=5, fuzz_time=120,
        campaign_minutes=mins, sanitizer="address,undefined", seed_patch=CWPACK_SEED,
        use_build_system=True, use_symbolic=False,
        provider=__import__("os").environ.get("FORGE_PROVIDER","openai"), model=__import__("os").environ.get("FORGE_MODEL","gpt-5.1"))
    print(f"[{time.strftime('%H:%M:%S')}] {name} link="
          f"{'obj:'+str(len(ctx.target.extra_link_objects)) if ctx.target.extra_link_objects else 'file-by-file'} "
          f"libs={len(ctx.repo.library or [])}", flush=True)
    findings = await run_job(ctx, discovery=discovery, oracles=oracles,
                             escalation=escalation)
    print(f"\n[{time.strftime('%H:%M:%S')}] {name} DONE: {len(findings)} finding(s)",
          flush=True)
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(vars(f))
        print(name, json.dumps({k: d.get(k) for k in
              ("title", "rung", "bug_type", "novelty", "function")}, default=str),
              flush=True)
    print(f"{name} artifacts:", root / jid, flush=True)


if __name__ == "__main__":
    asyncio.run(main())
