# Launch posts

One rule across all of them: **lead with the retraction, not the feature list.**
Researchers have seen a hundred "autonomous AI vulnerability finder" posts this year.
The thing none of them ship is a finding the tool told the author to throw away.

---

## LinkedIn

> I open sourced my vulnerability discovery engine today. It ships with a finding it
> told me to throw away.
>
> Last week it reported a 6.85 GB allocation in a JBIG2 decoder from a 55-byte input.
> Looked real. Then I ran the engine's own native-replay oracle against it: the library
> checks that allocation and recovers cleanly. What my fuzzer had flagged was its own
> resource policy, not a defect in the target. The retraction is in the repository, with
> the reason.
>
> That is the whole design. An LLM fleet proposes; eight deterministic oracles prove. A
> model may propose a candidate at any rung of an exploitability ladder, and may certify
> none of them. Certification comes only from oracles that are deterministic, independent
> of the proposer, and reproducible by someone who does not trust you.
>
> Why bother: in the largest published AI discovery effort to date, 23,019 candidates
> produced 126 CVEs. Of 1,061 publicly attributed AI-assisted discoveries, 14 (1.3%) were
> confirmed exploited in the wild, which is almost exactly the rate for vulnerabilities
> generally. AI raised the volume. It did not raise the value. Meanwhile curl ended its
> bug bounty in February because only 5% of reported vulnerabilities were real.
>
> Detection is cheap now. Trust is not.
>
> MIT, standard library only, no server. Every command runs with no API key, because the
> half that certifies a finding never needed a model:
>
> python -m forge lab examples/harness_trunc.c --fuzz-time 30
>
> That finds a real heap overflow in under ten seconds on a clean clone, and then prints
> what it did NOT establish.
>
> github.com/eobi/nemesisforge
>
> Would genuinely like it broken. If an oracle certifies something it should not, that is
> the bug report I most want.

---

## X / Twitter (thread)

**1/**
> I open sourced my vulnerability discovery engine.
>
> It ships with a finding it told me to throw away.
>
> github.com/eobi/nemesisforge

**2/**
> Last week: 55-byte input, 6.85 GB allocation in a JBIG2 decoder. Looked like a finding.
>
> Ran the native-replay oracle. The library checks that malloc and recovers. What my
> fuzzer flagged was its own -rss_limit_mb, not a bug in the target.
>
> The retraction is in the repo, with the reason.

**3/**
> The design in one line: an LLM proposes, eight deterministic oracles prove.
>
> A model may propose a candidate at any rung. It may certify none of them.

**4/**
> Why this matters right now:
>
> 23,019 candidates -> 126 CVEs
> 14 of 1,061 AI-assisted findings (1.3%) confirmed exploited
>
> which is the same rate as vulnerabilities generally.
>
> AI raised the volume. It did not raise the value.

**5/**
> curl ended its bug bounty in February. 20% of reports AI-generated, 5% of reported
> vulns real. libxml2 dropped embargoed reports. Node.js raised its signal floor.
>
> Detection is cheap. Trust is not.

**6/**
> MIT. Standard library only. No server. No API key needed, because the half that
> certifies never needed a model.
>
> python -m forge lab examples/harness_trunc.c --fuzz-time 30
>
> Real heap overflow in seconds, then it prints what it did NOT establish.

**7/**
> Please break it.
>
> If an oracle certifies something it should not, that is the bug report I most want.
>
> github.com/eobi/nemesisforge

---

## Mastodon (infosec.exchange)

> Open sourced my vuln discovery engine today. It ships with a finding it told me to
> throw away.
>
> 55-byte input, 6.85 GB allocation in a JBIG2 decoder. Then native replay: the library
> handles it fine. My fuzzer had flagged its own resource policy. Retraction is in the
> repo with the reason.
>
> LLM proposes, eight deterministic oracles prove. A model may propose at any rung and
> certify none of them.
>
> MIT, stdlib only, runs with no API key.
>
> github.com/eobi/nemesisforge
>
> #infosec #fuzzing #vulnerability #opensource

---

## Bluesky

> Open sourced my vulnerability discovery engine. It ships with a finding it told me to
> throw away.
>
> An LLM proposes; eight deterministic oracles prove. A model may propose at any rung of
> the exploitability ladder and certify none of them.
>
> Every command runs with no API key.
>
> github.com/eobi/nemesisforge

---

## Hacker News (Show HN)

**Title:** `Show HN: Nemesis Forge – an LLM proposes, deterministic oracles prove`

**Text:**
> I built this because of a problem I kept hitting in my own research: a fuzzer gives you
> a thousand crashes and no way to tell which few matter, and a model asked to judge its
> own findings is confident and wrong in a way nothing downstream can detect.
>
> So the engine is built around one constraint: a model may propose a candidate at any
> rung of an exploitability ladder, and may certify none of them. Certification comes from
> eight deterministic oracles, each of which is independent of the proposer and
> reproducible by a third party. Findings are reported at the rung the evidence reaches
> and every one states what was not established.
>
> The repository ships a finding I withdrew. It reported a 6.85 GB allocation in a JBIG2
> decoder from 55 bytes; native replay showed the library checks that allocation and
> recovers, so what the fuzzer flagged was its own resource limit. I kept the retraction
> because an engine that only ever confirms is not one worth trusting.
>
> Honest scope: discovery is not the contribution. It drives libFuzzer on source targets
> and degrades to a bounded mutation loop without one. The oracle side is the part I
> think is new.
>
> MIT, standard library only for the core, no server, and every command runs without an
> API key. On a clean clone `python -m forge lab examples/harness_trunc.c --fuzz-time 30`
> finds a real heap overflow in under ten seconds.
>
> I would like it broken. If an oracle certifies something it should not, please tell me.

---

## Reddit r/netsec

**Title:** `Nemesis Forge: vulnerability discovery where the model proposes and deterministic oracles certify (MIT)`

Use the Hacker News body, lightly trimmed. r/netsec dislikes marketing tone and rewards
a concrete technical claim in the first sentence. Lead with the oracle constraint, not
with "I built a tool".

---

## Where else, and what each expects

| Venue | Worth it | Read this first |
|---|---|---|
| **Hacker News (Show HN)** | high | Post once, then answer every comment for the first three hours. That is where the value is, not the votes. |
| **r/netsec** | high | Strict on self-promotion. Technical claim in sentence one, no marketing register. |
| **Mastodon infosec.exchange** | high | Real security research community, low noise, and posts persist. |
| **r/ReverseEngineering** | medium | Frame around the oracle and operand-provenance work, not the LLM. |
| **lobste.rs** | high if you have an invite | Same audience quality as HN, smaller. |
| **Fuzzing Discord / OSS-Fuzz community** | high | These are the people who will actually find its limits. |
| **X / Twitter** | medium | Tag nobody in the first post. Let it stand on the retraction line. |
| **LinkedIn** | medium | Different audience: hiring managers and industry, not researchers. Worth it for that reason. |
| **Zenodo** | do this | Cut a release and enable the integration; it mints a DOI so the work is citable. |
| **oss-security mailing list** | **no** | That list is for vulnerability disclosure, not tool announcements. Posting there would read as noise. |

---

## Things not to say

- **Do not call it a zero-day finder.** No CVE was assigned to the CWPack finding.
- **Do not call it a coverage-guided fuzzer.** It drives libFuzzer on source targets. Claiming
  the technique rather than the integration is exactly the overclaim the project argues against.
- **Do not hide the star count or the age.** It is days old with no external users. Saying so
  costs nothing and buys the credibility the rest of the post depends on.
