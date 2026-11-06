---
name: bb-critical
description: Bug bounty critical-hunt phases (04b + 05b) — orchestrator-driven browser walk plus 3–4 concurrent subagents hunting for 10 confirmed-critical findings. Use when you want to focus exclusively on Critical severity bugs.
sources:
  - bug-bounty-hunting-prompts/phases/phase-04b-browser-walk.md
  - bug-bounty-hunting-prompts/phases/phase-05b-critical.md
argument-hint: "<target_display>"
allowed-tools: Bash, Read, Write, WebFetch
---

# Bug Bounty Critical Hunt (Phases 04b + 05b)

Focused hunt for Critical-severity findings. Orchestrator drives authenticated browser while 3–4 background subagents investigate server-side leads in parallel.

**Stop condition:** 10 CONFIRMED-CRITICAL distinct findings, each with working PoC and clear impact, deduplicated against prior reports.

## Role: Orchestrator

You browse first, serially, and fan out background subagents for deeper investigation as the walk exposes leads. You own ONE authenticated Chrome (CDP) the entire phase. Browsing is the discovery engine; subagents are the investigation engine.

```bash
# Browser lease lifecycle
BROWSER_PREFIX="${YOUR_LEASE_OWNER_PREFIX}:${YOUR_LEASE_CYCLE}:"
BROWSER_OWNER="${BROWSER_PREFIX}browser"
ACQ=$(python3 browser-lease.py acquire --owner "$BROWSER_OWNER" --role critical \
  --origins-file "$YOUR_TARGET_ROOT/raw/scope-hosts.txt")
BROWSER_PROFILE=$(echo "$ACQ" | grep -oE '^[0-9]+' | head -1)
BROWSER_CDP=$((YOUR_CDP_BASE_PORT + BROWSER_PROFILE))
```

## Stage A: Serial Authenticated Browser Walk

Drive Chrome via CDP. Walk every menu, form, upload surface, settings, integration, and multi-step flow end-to-end.

### Upload Surfaces First (Highest Critical Yield)

For every upload surface (profile pic, avatar, document, attachment, image, import):

| Test | Method | Critical Path |
|------|--------|--------------|
| Oversize file | >10MB, >100MB upload | Server crash / path disclosure |
| Bad MIME + good extension | `Content-Type: image/jpeg` for `.php` | Server-side execution |
| `x.php.png` trick | Double extension | Extension bypass → RCE |
| Path-traversal filename | `../../etc/passwd` | Write to arbitrary path |
| SVG/HTML content render | Upload SVG with `<script>`, HTML with meta-redirect | Stored XSS |
| EXIF injection | EXIF GPS/Comment field with XSS payload | Stored XSS via metadata |
| File processor abuse | Pandoc, ffmpeg, ImageMagick triggers | SSRF / LFI / RCE |

### Browser-Dependent Critical Classes (YOU must test these, not subagents)

- **UI-reachable IDOR / access-control** — test every resource-access endpoint from two accounts
- **OAuth / SAML / SSO flow** — walk every step, intercept tokens, test state parameter
- **DOM XSS** — sources: URL params, postMessage, document.write, innerHTML, eval
- **postMessage** — missing origin validation, type confusion, prototype pollution
- **CSRF** — missing tokens, predictable tokens, weak SameSite, CORS + state change
- **Clickjacking** — X-Frame-Options missing on sensitive actions

### Browser Coverage Tracking

```jsonl
// raw/browser/coverage.jsonl — append before testing, terminal event after
{"url": "/settings/integrations", "surface": "webhook-config", "auth_state": "authed", "actions": ["test-webhook-url"], "status": "pending"}
{"url": "/settings/integrations", "surface": "webhook-config", "auth_state": "authed", "actions": ["ssrf-via-webhook"], "status": "confirmed", "report": "REPORT-01.md"}
```

Browser coverage is mandatory. A promising lead does not satisfy coverage. Subagent fan-out supplements the walk, it does not replace it.

## Stage B: Subagent Fan-Out

The moment the walk exposes a server-side lead, spawn a background subagent while you keep walking.

**Cap concurrent subagents at 3–4.**

### Delegate ONLY Stateless / Session-Independent Work:

```
SSRF     — URL/webhook/integration/image-fetch fields
Injection — SQLi/NoSQLi/cmd/LDAP/XPath/SSTI on params the walk reaches
Redirect — open redirect leads
Deser    — Java/PHP/Python deserialization
RCE      — template processor, image processor, document converter
Infra    — cloud metadata, admin/staging/dev hosts, secrets in JS/source-maps
Upload   — thumbnail/AV/pandoc/ffmpeg server-side processing
Logic    — race conditions on money/counter/claim flows, idempotency abuse
```

### Session Safety Rule (Critical)

**Subagents MUST NOT touch your CDP Chrome.** Each subagent gets copied credentials (cookies/tokens from `sensitive/`) and drives its own curl/scripts/OOB listener. Concurrent navigation on your session corrupts the browser walk.

### Subagent Brief Template

```
Target: <target_display>
Lead: <surface>, <URL/field>, <class>
Credentials: (copied from sensitive/)
Phase raw root: <path>
Technique ref: ref-<class>-techniques.md
Return: structured verdict only (confirmed/dead, severity, evidence path, impact)
Do NOT write reports.
```

## Lead Ledger (Compaction-Safe)

```jsonl
// Append BEFORE spawning — single source of truth
{"id": "lead-001", "surface": "/api/images/process", "url": "POST /api/images/process", "class": "ssrf", "status": "dispatched", "agent": "subagent-1", "report": null}
```

**Dedup against own ledger before spawning.** On compaction, re-read ledger to recover in-flight state.

## Research Search Control

Manage as a changing portfolio of mechanism families, not a fixed assignment:

```jsonl
// raw/approaches.jsonl
{"family": "ssrf", "mechanism": "webhook-url-fetch", "surface": "/settings/integrations", "status": "active", "evidence": "raw/responses/ssrf-01.json", "next_test": "cloud-metadata"}
{"family": "auth-bypass", "mechanism": "jwt-alg-none", "surface": "/api/v1/", "status": "unexplored", "blocker": null}
```

- Keep multiple incompatible routes alive across rounds
- If multiple agents converge on one family, redirect to underexplored family
- When approach stalls, mark blocked; reopen only with materially new mechanism
- 3–4 agent limit is concurrency, not total rounds

## Memory & Hunt Files (Compaction-Safe)

One file per angle, written BEFORE testing:

```markdown
// hunt/phase-NN-<slug>.md
Angle: SSRF via webhook URL
Hypothesis: webhook URL is fetched server-side without allowlist
Tried: (ref raw/responses/ssrf-01.json)
Result: 169.254.169.254 returns AWS metadata
Status: CONFIRMED-CRITICAL
```

**Rules:**
- Write the file when picking the angle, before testing
- Never start a second angle while the first has no file
- Use next free local NN: `phase-NN-<slug>.md`
- Extend PARTIAL/CONFIRMED in place, never reopen a dead file

## Report Rules

You are the **only report writer**. Subagents return verdicts only.

```bash
stamp_report "$REPORT_PATH" "<found by: subagent identity>"
```

- Write for every CONFIRMED MEDIUM-or-above
- Drop Low/Info into hunt log only when it chains to something higher
- Use next free `REPORT-NN.md` in `reports/`
- Format per `report-format.md`; Severity is one bare uppercase word
- Deduplicate against all existing reports before writing

## Skip

- **CORS** — low yield, never pays. Note only credentialed CORS read of real secrets.
- **Low-impact oracles** — username/email enumeration, timing side-channels: don't chase standalone; note only if it chains to ATO or mass data exposure.

## Critical Finding Adversarial Check

Before marking any finding `CONFIRMED-CRITICAL`, spawn an independent adversarial subagent to try to disprove:
- Prerequisite reachability (can a real attacker actually obtain X?)
- Reproducibility (does it work on a fresh session?)
- Scope (is the affected asset in-scope?)
- Impact (is the stated impact actually achievable end-to-end?)

## Stop Condition

Ten CONFIRMED-CRITICAL distinct findings, each with:
- Working PoC
- Clear concrete impact (not theoretical)
- Deduplicated against prior reports from earlier phases
