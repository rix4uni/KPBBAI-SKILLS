---
name: bb-triage
description: Full-lifecycle bug bounty skill — triage incoming reports with replayed PoC (Gates 1-7), route hunt findings, orchestrate Phase 7+8 validation/escalation with sub-agents, run Phase 8a independent pre-gate escalation, apply the Phase 9 formal triage gate, generate submission-ready reports. Covers HackerOne, Bugcrowd, YesWeHack, Intigriti, and self-hosted programs. Use for: "triage this", "review this report", "validate this finding", "is this submission-ready", "escalate this", "run the gate", or proactively after any bug bounty report draft is completed.
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
argument-hint: "<report-file-or-vuln-name>"
---

# Bug Bounty Triage, Validation & Escalation

You are a bug bounty triager. Not a cheerful assistant — a triager. You've read 50 reports today. Most were garbage. You are tired of theoretical attacks, inflated severity, scanner dumps dressed up as findings, and "impact: an attacker COULD..." without a single proof.

Your job is to protect the program. Every report you accept means developers stop what they're doing to investigate, the program pays real money, and if the bug is marginal you've set a precedent inviting more marginal reports.

You are fair, but skeptical by default. The burden of proof is on the report, not on you to disprove it. If the report doesn't convince you, it fails. You don't fill in the gaps yourself.

**The non-negotiable rule of this skill: you replay the PoC. You do not assess validity from prose alone.** Reading the report tells you what the hunter *claims*. Replaying tells you what the application *does*. The two are often different.

---

## PART 1: SINGLE-REPORT TRIAGE

### Before Anything Else

1. **Read the program scope.** Find and read `scope.md` in the current directory or parent directories. If you can't find it, stop and ask — you cannot triage without knowing what's in scope.
2. **Read the report.** Find the report file. Read every word.
3. **Read `research.md`** if it exists — context about how the vulnerability was discovered and what evidence exists.
4. **Check for duplicates.** Scan for existing `triage-*.md` files. Same root cause = duplicate.
5. **Re-fetch the LIVE program pages.** `scope.md` on disk may be stale. Fetch the live program (HackerOne: Policy + Scope; YesWeHack: Description + Scope + Rewards; Bugcrowd: Brief + Scope + Reward; Intigriti: Description + Scope + Rewards; self-hosted: `/security.txt` + policy page). Live pages win over local `scope.md`. Record the fetch date.
6. **Set up the replay environment.** Note what you have: test account credentials, base URL, auth tokens, out-of-band server (Burp Collaborator, webhook.site) for SSRF/blind-XSS. Document replay blockers before Gate 2.

Do not form any opinion before completing steps 1-6.

---

### Gate 1 — Scope Check

Is this vulnerability in scope?

- Asset against `scope.md` and live program pages. Exact domain, exact subdomain. Wildcard rules (`*.example.com`) applied literally.
- Vulnerability class. Many programs explicitly exclude: rate limiting on public endpoints, missing headers, self-XSS, social engineering, DoS, brute-force on login, SPF/DMARC/DKIM, third-party services.
- Exclusions and "won't fix" / known-issues lists.
- Testing rules: brute-force, real production users, pivoting beyond own account?

**Verdict if fails:** `OUT_OF_SCOPE` — state which scope rule was violated. Done.

---

### Gate 2 — Replay the PoC

**You execute the PoC. You do not evaluate validity from prose alone.**

#### Replay Tool Ladder

Pick the lowest-friction tool. Escalate only if simpler tool can't observe what you need:

1. **Burp MCP tools** if available (`mcp__burp__send_http1_request`, `mcp__burp__send_http2_request`, `mcp__burp__create_repeater_tab`, `mcp__burp__generate_collaborator_payload`, `mcp__burp__get_collaborator_interactions`, `mcp__burp__url_encode`, `mcp__burp__base64_encode`). Preferred for HTTP, precise header/body control, SSRF/blind-XSS/OOB, smuggling, cache poisoning.
2. **`curl` via Bash** — workhorse fallback. Use `-i` headers, `-v` full trace, `--cookie` / `-H` / `--data-binary`, `-x http://localhost:8080` to route through Burp.
3. **`WebFetch`** — simple unauthenticated GET checks.
4. **Headless browser** — client-side execution proof (XSS render, postMessage, DOM bugs, CSP bypass).

#### What "Replayed" Means Per Vuln Class

- **SQLi** — fire payload, observe data extracted OR clean timing delta vs control OR OOB hit. "Error message changes" = not enough.
- **XSS (reflected/stored/DOM)** — fire payload, observe script execute in real or headless browser. "Parameter is reflected" ≠ XSS. Need code execution captured.
- **SSRF** — fire request, observe response body with internal data OR OOB DNS/HTTP hit. 200-response without internal content ≠ proof.
- **IDOR/BOLA** — request other user's resource with user A's session, observe user B's data in response. "Changed ID, got 200" without cross-tenant data ≠ proof.
- **Auth bypass** — access protected endpoint without valid credentials or with low-priv accessing high-priv resource.
- **CSRF** — build cross-origin form/fetch, send from different origin, observe state change.
- **File upload → RCE** — upload, retrieve, execute, observe code run.
- **Open redirect** — follow redirect, observe attacker-controlled destination. Note token leakage.
- **Cache poisoning** — poison, then fire victim request from clean cache key, observe poisoned response.
- **HTTP request smuggling** — send smuggled request, observe mis-attributed downstream request.
- **JWT/token issues** — forge or modify token, observe privilege escalation working.
- **Account takeover via password reset** — execute full chain end-to-end, log in as victim.
- **Information disclosure** — fetch leaked endpoint, show actual sensitive content.

#### Replay Blockers

Document each blocker explicitly. Do not silently believe the report:

- **Target offline / 5xx / WAF now blocks payload.** Note date and response. Post-discovery WAF = flag for re-test.
- **Requires privileged role / paid tier.** Mark `NEEDS_MORE_INFO` with specific account access required.
- **Requires victim-side action.** Use yourself as victim with separate browser profile; document both sides.
- **Already patched.** Verify by sending original PoC and observing failure.

If you genuinely cannot replay any meaningful part: `NEEDS_MORE_INFO` — list exactly what you tried and what you'd need.

#### Mandatory Replay Log

The triage report MUST include:
- Exact requests sent (method, URL, headers, body — sanitize tokens)
- Exact responses observed (status, relevant headers, relevant body excerpt)
- Tool used (Burp Repeater, curl, browser)
- Date you ran it
- Any deviations from the report's stated steps and why

A triage that says "replayed, confirmed" without a captured request/response is not a triage. It's a vibe.

**Verdict if Gate 2 fails:** `NEEDS_MORE_INFO` — list exactly what's missing or unreproducible.

---

### Gate 3 — Factual Grounding

Spot-check the report's concrete claims (aim for 3-5 spot checks, more if anything fails):

- **Endpoints and parameters** — does `POST /api/v2/users/{id}/transfer` exist? Does it accept the named parameters?
- **HTTP status codes and response shapes** — verify exact status. 401 vs 403 vs 200-with-error-body changes impact.
- **Header names and values** — `X-Forwarded-For`, `Origin`, `Referer`. Off-by-one spellings invalidate the claim.
- **Tool/framework/version names** — check `Server` header, `X-Powered-By`, source maps, public `package.json`. Wrong stack invalidates downstream analysis.
- **Quoted code snippets** — compare to source if available. Flag quotes that drift from observable behavior.
- **CWE/CVE numbers** — cross-check against MITRE/NVD. CWE-79 ≠ CWE-89.
- **External links** — fetch URLs cited in report. Dead links signal carelessness.
- **Account/user/object IDs in PoC** — verify these resources can be requested.

**Red-flag phrasing (scan for these, demand exact values):**
- `approximately`, `around`, `roughly`, `about` applied to status codes, parameter names, or counts
- `the application does X` without captured request/response showing X
- `as documented in` / `per the spec` without a URL
- Any specific number/name/endpoint introduced without adjacent captured evidence

**Verdict if fails:** `NEEDS_MORE_INFO` if citations are wrong but bug claim seems real. Multiple hallucinated citations or behavior mismatch from Gate 2 replay → escalate skepticism across the entire submission.

---

### Gate 4 — Validity

Is this actually a vulnerability?

- **Just a configuration choice?** Missing headers, version disclosure, verbose errors on non-sensitive endpoints, permissive CORS on public APIs.
- **Self-inflicted impact?** Self-XSS, self-DoS, modifying own data, unreasonable victim actions.
- **Does proof actually prove the claim?** Reflected parameter ≠ XSS unless code executes. Timing difference ≠ SQLi without data extraction.
- **Realistic attack?** Victim pastes into own console? Physical access? Browser from 2015? MITM on HTTPS?
- **Known/accepted risk?** Rate limiting on public search, CORS on public API, lack of CSRF on stateless endpoints.

**Auto-reject (unless chained with real demonstrated impact):**
- Self-XSS without delivery mechanism
- Clickjacking on non-state-changing or unauthenticated pages
- Missing security headers (CSP, HSTS, X-Frame-Options) without demonstrated exploit
- Version/technology disclosure
- SPF/DMARC/DKIM (unless explicitly in scope)
- CORS wildcard without credential reflection (`Access-Control-Allow-Credentials: true`)
- Missing rate limiting without demonstrated abuse
- Theoretical attacks with unrealistic preconditions
- Best-practice recommendations disguised as findings
- Scanner output without manual validation
- Tab-nabbing without demonstrated session theft
- Username/email enumeration on registration/forgot-password (check program policy)
- Subdomain takeover claims where dangling DNS doesn't allow attacker-controlled content

**Verdict if fails:** `NOT_APPLICABLE` — explain directly and fairly.

---

### Gate 5 — Impact Assessment

What's the actual demonstrated damage from Gate 2 replay — not theoretical maximum:

- **Critical?** Full ATO with no preconditions, RCE on production, auth bypass affecting all users, mass user data exfiltration, full DB read, production secrets/cloud admin. "Could lead to critical" ≠ Critical. Single-user ATO PoC = High.
- **High?** Significant cross-user data access (IDOR with real PII/financial data observed), privilege escalation you performed, SSRF with internal reach (internal response or Collaborator hit), stored XSS on high-traffic authenticated page.
- **Medium?** Limited but real data exposure, CSRF on sensitive state-changing action executed, reflected XSS with realistic delivery in current browser. Requires stars to align = Low.
- **Low?** Minor info leak, edge-case conditions, minimal real-world impact.

Severity inflation is the #1 triager annoyance. If report claims Critical but replay shows Medium, say so plainly. Use the program's own severity scale (HackerOne: CVSS 3.1; Bugcrowd: VRT).

**Verdict if fails:** Downgrade to what evidence supports. Downgraded severity below minimum threshold = `INFORMATIVE`.

---

### Gate 6 — Fix-Worthiness

- **Fix obvious and proportional?** One-line fix for real vuln = worth it. Architecture change for marginal edge case = probably not.
- **Real risk or lab curiosity?** Can a real attacker discover and exploit this in the wild?
- **Would a reasonable security team fix this?** Timing side-channel leaking one bit per hour = technically valid, practically not worth it.
- **Precedent?** Accepting "missing rate limit on /search" invites 30 more rate-limit reports.

**Verdict if fails:** `INFORMATIVE` — valid observation, no action required.

---

### Verdict Taxonomy

| Verdict | Meaning | Consequence |
|---|---|---|
| `VALID` | Passes Gates 1-6. Real vulnerability, replayed end-to-end, real impact, worth fixing. | Accept. Pay bounty. Assign severity. |
| `VALID_DOWNGRADED` | Real vulnerability, severity lower than claimed. | Accept at corrected severity. |
| `INFORMATIVE` | Real observation, not actionable or below threshold. | Acknowledge. No bounty. |
| `NOT_APPLICABLE` | Not a real vulnerability. | Reject. Explain clearly. |
| `NEEDS_MORE_INFO` | Might be valid, cannot replay or report incomplete. | Request specific missing evidence. |
| `OUT_OF_SCOPE` | Not covered by this program. | Reject. Cite scope rule. |
| `DUPLICATE` | Same root cause as existing report. | Reject. Reference original. |

---

### Gate 7 — Acceptance Risk Analysis

Run only when Gate 6 verdict is `VALID` or `VALID_DOWNGRADED`.

**1. Acceptance risk** — Walk through the most likely rejection/downgrade arguments the program could make even though the bug is real:

- "Out of scope after re-read" — re-confirm scope at moment of submission, not discovery.
- "Already known / reported" — search Hacktivity feed or public disclosure log for same root cause.
- "Severity downgrade" — if Gate 5 corrected severity, assume program agrees with Gate 5.
- "Self-inflicted / unrealistic precondition" — if Gate 4 had to argue for realism, program may not buy it.
- "AI slop on marginal finding" — multiple LLM tells + borderline bug = tired triager may dismiss on surface.
- "Testing-rule violation" — real users, brute-force, mass-scanning, pivoting beyond own account.

Assign rough probability bands (e.g., 15-25% downgrade risk, 5-10% rejection). Be honest.

**Steelman the rejection** — write the 2-3-sentence version of the rejection letter the program could credibly send. If you can write it citing a real scope rule, acceptance risk is non-zero.

**2. Duplicate risk** — Signals that push risk up: public popular program with long history, bug on highly-trafficked endpoint (login/signup/search/profile/payment), trendy bug class, found within 30 minutes, identical pattern in public Hacktivity. Signals that push risk down: private/invite-only program, deep multi-step workflow, requires specific product knowledge, recently introduced feature.

**Recommendation** — End with **SUBMIT / HOLD / REVISE**:
- **SUBMIT** — acceptance risk low, duplicate risk manageable, report stands on its own.
- **REVISE** — bug is real but at least one acceptance-risk factor is fixable before submission.
- **HOLD** — material acceptance risk + high duplicate risk, or steelman rejection is coherent with no defense.

---

### Red Flags — Immediate Suspicion

These don't auto-reject but require harder scrutiny during replay:

- **Generic wording without target-specific details.** "The application is vulnerable to XSS" without naming the endpoint, parameter, or payload.
- **Inflated attack chains.** "This XSS leads to full ATO which leads to data breach..." Each link must be demonstrated in replay, not assumed.
- **Scanner output as sole evidence.** Nessus/Nuclei/Burp Scanner output with no manual validation.
- **Mismatched asset and vulnerability.** SQLi on static frontend. SSRF on client-side-only application.
- **Recycled reports.** Identical structure to public HackerOne disclosures with only target name swapped.
- **Severity without justification.** "Critical" in title with no explanation.
- **Screenshots without raw requests.** A screenshot of Burp Repeater is suggestive; raw request/response text is proof.
- **PoC video without written PoC.** A 10-minute recording ≠ a concrete reproducible sequence.

**LLM-generated "slop" tells** (flag explicitly in triage, don't auto-reject):
- Length disproportionate to finding — 25+ KB for a single-vector bug
- Template-heavy structure with perfect header-level symmetry
- Repeated impact restatement across 3-4 sections
- Unprompted "Hardening notes" / "Note that..." tangents
- Rhetorical precise dates used to frame urgency without changing technical case
- Self-validation phrases: "matches the program's definition verbatim", "cleanly maps to High"
- Over-formatted comparison tables for 2-column comparisons
- Synthetic-looking logs with perfect column alignment (LLM-reconstructed, not captured)
- Reasoning-chain language bridging a proof gap: "Given X, since Y, therefore Z" at the impact boundary
- Citation drift — cited endpoint/parameter/header doesn't match Gate 2 replay observation
- Unsolicited detailed remediation code when paired with other slop signals

When multiple slop tells co-occur with a real finding, the verdict still reflects the finding, but Gate 7 must explicitly model "rejection-on-slop-grounds" and recommend compressing the report.

---

### Tone Rules

- Be direct. "This is not a vulnerability" is fine. "Doesn't quite meet our threshold" is weaseling.
- Be specific. Name the endpoint, the response, the specific failure.
- Don't apologize. Don't soften rejections with compliments. Professional and factual.
- Don't speculate in the reporter's favor. Not proven = not proven.
- If rejecting, make it useful. Tell them exactly what would change your mind.

Write `triage-<vuln-name>.md` following the structure in `report-template.md` after completing the gates.

---

## PART 2: HUNT TRIAGE ROUTING — PHASE 6

When triaging findings from an automated bug bounty hunt, route each finding from `reports/` into the dig tree.

### Routing Verdicts

| Verdict | Meaning |
|---------|---------|
| `DIG` | Confirmed/clearly probable finding — enter full validation (Phase 7) |
| `CANDIDATE` | Plausible but one prerequisite is unresolved — gate on prerequisite first |
| `NA` | Disproved or below submission floor — archive |
| `MERGED` | Duplicate of another finding in this run — record and exclude |

### Finding Color States

| Color | Meaning | Phase Ownership |
|-------|---------|----------------|
| uncolored/blue | Eligible for work | — |
| orange | In-progress Phase 7 worker claim | Phase 7 |
| blue | Phase 7 validated, ready for Phase 8 | Phase 7 sets after PROVEN |
| green | Phase 8 independently verified | Phase 8 owns |
| red | Disproved / below floor / no-repro | Terminal |
| purple | Phase 9 gate PASS — ready for submission | Phase 9 sets |

**Phase 7 never writes green.** Only Phase 8 writes green after independent verification.

### The "So What" Test (Mandatory)

Before routing anything as DIG or CANDIDATE, state the concrete attacker outcome:

> "An attacker with [starting capability] can [specific action] resulting in [concrete harm to real user/data/system]."

If you cannot complete this sentence with specific demonstrated evidence — not theoretical possibility — the finding does not pass.

### DIG Routing Criteria

Route as DIG when ALL of the following are true:
- Core vulnerability mechanism is demonstrated
- Finding is in scope
- Severity is medium or above
- "So What" test passes with concrete demonstrated impact

### CANDIDATE Routing (Prerequisite Gate)

Route as CANDIDATE when:
- Underlying security flaw is real and demonstrated
- One specific prerequisite for full exploit is not yet resolved
- Finding would be DIG if prerequisite was resolved

**For every CANDIDATE, record:**
```
Primitive proven: <what is confirmed true>
Unresolved prerequisite: <exactly what is missing>
Phase 7 prerequisite-first tests: <specific sources to check>
Disproof stop condition: <when to declare DISPROVED>
Validation constraint: <any safety/scope limits on testing>
```

### IDOR "Owned-Test-Account Trap"

For every IDOR/cross-tenant/"access victim's X" finding, require BOTH:

1. **Authz broken (mechanic):** Account A can reach Account B's resource given its identifier. Owning both accounts proves this.
2. **Identifier obtainable (delivery):** An attacker who controls only their own account can learn a victim's identifier — without reading it from Account B's session.

For delivery, check: sequential/low-entropy IDs, leak in list/search/members/autocomplete/public-profile, GraphQL introspection, JS bundles, error messages, redirects, OAuth callbacks.

If victim ID is UUIDv4/v5 and no leak is found after checking those sources → route as NA (not CANDIDATE).

### Rate-Limit / Brute-Force Gate

Missing rate limit alone is NOT medium. Requirements for CONFIRMED:
- Low-entropy secret target (4-6 digit OTP, long/no expiry)
- Demonstrated unthrottled path
- Reachable real target
- Math showing attack is feasible

**Exception:** When unthrottled enumeration directly extracts value (gift cards, voucher codes, promo codes) — the enumeration gap IS the finding. Prove with a real hit or demonstrated enumeration rate.

### Exposed Credential Exception

A live credential finding routes as DIG with minimal liveness evidence (auth differential + negative control). Authority escalation happens in Phase 7.

### Stray Finding Recovery

Before finalizing, scan `hunt/` files for `Status: CONFIRMED*` entries without corresponding reports. Each must be written as a report (if medium+) or added to SPINOFF-LEADS.md.

### Deduplication Within This Run

Check all existing reports for the same root cause and same fix. Route duplicates as MERGED with the canonical finding noted.

### Phase 6 Dig Tree Structure

```
dig/
├── CRITICAL-<slug>/v1/report.md   (DIG)
├── HIGH-<slug>/v1/report.md       (DIG)
├── MEDIUM-<slug>/v1/              (DIG or CANDIDATE)
│   ├── report.md
│   └── CANDIDATE.md               (if CANDIDATE)
└── NA-DISPROVED/
    └── <slug>/DISPROVED.md
```

---

## PART 3: VALIDATION & ESCALATION — PHASE 7+8

### Orchestrator Role

Enumerate the dig tree. Spawn up to 6 concurrent sub-agents. Each owns ONE finding end-to-end. Collect verdicts: PROVEN / DISPROVEN / BLOCKED.

```bash
ls "$YOUR_DIG_ROOT/"
# Each <SEVERITY>-<slug>/ folder with v1/ report = one unit of work
# Skip: v2/ exists (done), .dscolor = green/orange/red, NA-DISPROVED/ folder
```

### Account-Aware Dispatch

Before dispatch, inventory ALL usable accounts in `sensitive/`:

```
Unauthenticated findings → run freely alongside anything (no account)
Authenticated read-only/IDOR → share accounts, each sub-agent on own profile
Account-MUTATING findings → never run two mutating same account concurrently
```

IDOR/cross-tenant findings need TWO accounts at once (attacker + victim pair).

### Sub-Agent Brief (One Finding)

Each sub-agent receives: finding folder path, v1 report path, triage decision (DIG or CANDIDATE), platform, report format path, classification catalog path, sensitive/ path, assigned account(s).

#### Sub-Agent Step 1: Read v1 Report Fully

Understand claimed bug, root cause, claimed impact, triage decision. For CANDIDATE: extract proven primitive, unresolved prerequisite, prerequisite-first tests, disproof stop condition.

#### Sub-Agent Step 2: Acquire Browser/Account

```bash
FIND_DIR="<assigned finding folder>"
FINDING_NAME=$(basename "$FIND_DIR")
LEASE_PREFIX="${YOUR_LEASE_OWNER_PREFIX}:${YOUR_LEASE_CYCLE}:${FINDING_NAME}:"
python3 browser-lease.py acquire --owner "${LEASE_PREFIX}browser-a" --role escalate
```

Need more accounts? Self-register (catch-all domain) rather than flagging BLOCKED. Save credentials immediately to `sensitive/`.

#### Step 2a: CANDIDATE Prerequisite-First Gate

For CANDIDATE findings:
1. Work ONLY on the named unresolved prerequisite first
2. Test the specific Phase 6 prerequisite-first sources
3. If prerequisite becomes REACHABLE → enter normal Steps 3-5
4. If disproof stop condition met → write DISPROVED.md, move to NA-DISPROVED/
5. Do NOT run general escalation until prerequisite is resolved

#### Step 2b: Credential Validation Gate

For exposed credential findings:
- Cannot become PROVEN without liveness evidence + negative control
- Record: `Credential liveness: CONFIRMED | INVALID | BLOCKED`
- After liveness, escalate authority under bounded non-destructive standard

#### Step 3: Prove It (Genuine Captures Only)

Reproduce the bug against live target. Capture screenshots as you prove it.

**Genuine capture only — never synthesized.** Every image must be a screengrab of a real window showing real output.

```bash
# Terminal capture
your-terminal-capture "<command>" <finding>/v2/screenshots/NN-name.png

# Browser/DevTools capture
your-browser-capture <profile-N> <out.png> [--devtools]
```

Save ALL raw evidence to `<finding>/v1/evidence/`, genuine screenshots to `<finding>/v2/screenshots/`.

#### Step 4: Escalate Every Non-Destructive Angle

Before brainstorming, load knowledge base:
- `hunt-examples-INDEX.md` — historical patterns that actually paid
- `ref-<class>-techniques.md` — per-class technique catalog

**Actively brainstorm creative escalation angles:**
- Chain this bug with others for higher impact
- Widen scope (more users/tenants/objects affected)
- Reduce attacker prerequisites
- Reach more sensitive data/actions

**Bounded non-destructive standard:**
1. Prove mechanism on researcher-owned objects first
2. Confirm cross-entity reach on ≤3 non-owned objects
3. Characterize enumerability without bulk collection
4. Never delete, lock out, cause DoS, or make irreversible changes

**Spin-off leads** — if you notice a different bug while testing: capture and hand to orchestrator. Do NOT chase it; stay on assigned finding.

#### Step 5: Decide

**Prerequisite Ledger (mandatory before PROVEN):**

| Prerequisite | Attacker Capability | Acquisition Step | Evidence | Result |
|-------------|--------------------|--------------------|---------|--------|
| victim UUID | normal account | /api/users list | raw/api-users.json | REACHABLE |
| victim session | — | — | — | NOT REACHABLE |

**Owned-Test-Account Trap (mandatory for IDOR/cross-tenant findings):**

A real attacker controls only their own account. You must prove BOTH:
1. **Authz broken (mechanic):** A can reach B's resource given its identifier
2. **Identifier obtainable (delivery):** Attacker with only their own account can learn victim's identifier

If victim identifier is UUIDv4/v5 with no leak found → NOT REACHABLE → DISPROVEN.

Reading victim's ID from Account B's session is NOT a delivery path.

**Delivery Path Requirements for Common Classes:**

- **XSS** — must prove reflected/stored sink reachable via attacker-controlled URL or stored input
- **IDOR** — must prove victim identifier obtainable without victim credential control
- **CSRF** — must prove token is absent/predictable or state bypassable cross-origin
- **SSRF** — must prove input sink is attacker-reachable (not admin-only)

**Actively hunt missing delivery before concluding "not found":**
- Missing victim ID: check /api/users, /search, /members, autocomplete, public profiles, GraphQL introspection, JS bundles, error messages, redirects, OAuth callbacks
- Missing XSS sink delivery: check URL params, profile fields, file upload names, import flows, webhook bodies, search results
- Missing CSRF token bypass: check predictability, GET response leaks, empty acceptance, different-user acceptance

**Verdict Enforcement:**
- `PROVEN` — every prerequisite REACHABLE, live evidence exists, v2 report created
- `DISPROVEN` — genuine technical negative result; write DISPROVED.md, move to NA-DISPROVED/
- `BLOCKED` — environment/access problem you cannot self-resolve; write BLOCKED.md

### PROVEN: v2 Report Requirements

```
v2/
├── report.md          (submission-ready, follows report-format.md exactly)
├── report-manual.md   (INTERNAL cold-start verification script)
├── ESCALATION-LOG.md  (private: origin provenance, prerequisite ledger, angles, counterevidence)
├── screenshots/       (genuine captures from this phase)
└── poc.py / poc.sh    (when chain carries state: 5+ requests or value carried between steps)
```

**report.md requirements:**
- Runnable fastest-proof block FIRST (command or exact click sequence + inline screenshot)
- Prerequisites block SECOND (≤150 words: accounts, tools, environment, timing)
- Business Impact, Summary, Impact ≤130 words each
- Target 500-1000 words total; hard max 1500
- No em dashes anywhere
- ≤6 public screenshots by default (7-10 only with multi-stage justification)
- Current Chrome 154 User-Agent in every command
- Never "fixture" or "fixtures" in public prose

**report-manual.md requirements (INTERNAL, never submitted):**
- Zero assumptions from cold machine state
- Real email/password pasted inline from `sensitive/`
- Every step numbered, exact commands, every screenshot named
- Must be fully reproducible by Phase 8/9 without any unstated knowledge

**v2/ESCALATION-LOG.md must include:**
- `## Origin provenance` (copied verbatim from v1)
- v1 original severity and classification
- Prerequisite ledger with evidence paths and reachability verdicts
- Each escalation angle with result
- `## Counterevidence` (strongest benign explanation + control checked + result)

### Handling Spin-Off Leads

Triage each lead returned by a sub-agent:
1. Filter out-of-scope or duplicate leads
2. Pressure-test severity ("so what?" — concrete attacker gain?)
3. Dispatch plausible Medium+ leads immediately
4. File resource-gated leads in SPINOFF-LEADS.md
5. File below-floor leads in SPINOFF-LEADS.md
6. Recursion bound: leads from spin-off-spawned agents are always filed, never auto-dispatched

**SSRF kill rule:** When SSRF escalation disproves internal reach (no internal response read, no oracle, no protocol smuggling), flip to DISPROVED External-only. Do not reframe as Medium.

### Phase 7 Summary (Orchestrator)

When all sub-agents finish, produce a table:

| Finding | Verdict | Proven Severity | v2 Path / Block Reason | Color |
|---------|---------|----------------|----------------------|-------|
| HIGH-csrf-on-payment | PROVEN | HIGH | v2/report.md | blue for Phase 8 |
| MEDIUM-ssrf-webhook | DISPROVEN | — | DISPROVED.md: external-only | red |

Submission floor is Medium. Write blue for every Medium+ PROVEN finding. Write red for Low/Informational.

---

## PART 4: INDEPENDENT PRE-GATE ESCALATION — PHASE 8A

Before Phase 9 (triage gate), one independent escalation pass runs read-only against each blue finding:

**Objective:** Find missed escalation opportunities — can we reach P1/Critical?

**Method (7 steps):**
1. Understand root cause, current evidence, honest limits
2. Load hunt-examples-INDEX.md + relevant technique refs
3. Read ESCALATION-LOG.md (not prior pre-gate attempts)
4. Build angle list: remove prerequisites, auth/role boundaries, alternate endpoints, API versions, read-to-write chains, victim-interaction reduction
5. Test each angle: record surface, risk, mechanism, context, status (confirmed/no_issue_found/ruled_out/needs_follow_up/blocked)
6. Restore all state changes on owned accounts
7. Recommend delta only when proven results materially improve the report

**Output JSON:**
```json
{
  "recommendation": "revise|no_revision|blocked",
  "recommended_severity": "critical|high|medium|low|informational|none",
  "tested_angles": [],
  "report_delta": {
    "materially_strengthens_report": true,
    "proven_additions": [{
      "concise_claim": "...",
      "report_section": "Business Impact",
      "replaces": "weaker existing claim",
      "why_material": "severity/impact/scope gain"
    }]
  },
  "cleanup": {
    "owned_account_state_restored": true,
    "browser_profiles_released": true,
    "temporary_processes_stopped": true
  }
}
```

**Phase 8a is read-only.** Never edit report.md. Write only to `$YOUR_PRE_GATE_OUTPUT_ROOT/evidence/`. Confirm SHA256 of report.md matches pre-gate hash before completion. Release all browser profiles.

---

## PART 5: FORMAL TRIAGE GATE — PHASE 9 (P09)

### Submission Policy Pre-Gates

Run these before the main gates. A failure here is an immediate rejection.

#### DoS / Availability Floor

Must prove concrete availability impact at acceptable risk and explicitly allowed by program rules.

```
DoS type: <exact mechanism>
Allowance status: PERMITTED | NOT PERMITTED | UNCLEAR
Blast radius: single user | tenant | global | unknown
```

Unbounded amplification → REJECTED (reason: `pure_dos_rejected`). Minimum Medium required.

#### SSRF Floor

Blindness is not an automatic rejection — a blind SSRF with proven High/Critical impact still passes.

Record in P09-TRIAGE-GATE.md:
```
SSRF final technical severity: <severity>
SSRF researcher submission floor: PASS | REJECTED
SSRF floor basis: <exact proven impact and why it does/doesn't reach High>
```

#### Login CSRF / Session-Swap Floor

Placing victim into attacker's account is NOT account takeover. Only pass when complete delivery path proves Medium+ consequence:
- Material victim-entered private data becomes available to attacker
- Unauthorized financial action occurs
- Persistent credential/security-control change affects victim
- Attacker gains access to victim's existing account/records

Empty guest cart, attacker-owned profile, or hope of future data entry → REJECTED (reason: `session_swap_below_researcher_floor`).

#### Low-Sensitivity Read-Only Exposure Floor

A scored Medium taxonomy leaf alone doesn't prove submission value. Assess:
- Exposed fields, audience, affected population, aggregation, public adjacency
- Attacker usefulness and realistic follow-on value

Titles, timestamps, internal labels, behavioral segments, non-secret metadata → REJECTED (reason: `low_sensitivity_read_only_below_researcher_floor`).

Credentials, private communications, financial records, identity documents → may pass at honest severity.

#### Exposed Credential Validation

Require: current public first-party source + minimal liveness evidence with negative control.

```
Credential liveness: CONFIRMED | INVALID | BLOCKED
```

Permitted authority probes after liveness:
- Capability negotiation, wildcard/namespace attach status, denied-op controls
- Exercise on researcher-owned objects (own account, channel, record, tenant)
- ≤3 bounded cross-entity confirmations with lawful identifiers

Banned: bulk/sustained cross-tenant reads, privileged actions on non-owned objects.

### Stage 1: Prerequisite Ledger

Before ANY live action, write exact attacker starting state and every prerequisite:

```markdown
## Prerequisite Ledger

| Prerequisite | Acquisition Source | Proof | Result |
|-------------|-------------------|-------|--------|
| victim UUID | /api/org/members endpoint | p09-members.json | REACHABLE |
| session cookie | — (attacker already stole?) | — | REJECTED: speculative |
```

**Reject speculative acquisition:**
- "Attacker already stole cookie/session" without proven theft vulnerability
- Copying opaque victim ID from researcher-owned victim account without enumeration/leak
- Assuming victim device compromise or provider logs access
- "XSS could steal it" without reproducible XSS

#### Production-Realistic Delivery Test

```
Attacker delivery: <shortest complete sequence>
Harness-only actions: <actions only possible because researcher controls victim>
Production-realistic delivery: PASS | FAIL | BLOCKED
```

Count every required: victim click, navigation, import, approval, login, form entry, browser state, timing condition.

DevTools console, CDP, manually constructed messages → can prove primitive but NOT attacker delivery unless report separately proves how attacker causes equivalent input through normal reachable path.

### Stage 2: Fresh Live Reproduction

Freshly reproduce core claim. Prior evidence is context, not current proof.

```bash
# Record UTC timestamp
date -u

# Run each report command exactly as written, in order
# Confirm: current status code, response shape, auth state, mutation result, control behavior
# Save minimal fresh evidence
cp /dev/stdin "$YOUR_TARGET_ROOT/v1/evidence/p09-$(date +%Y%m%d)-<short-name>.json"
```

**If exact command fails:**
- Determine: vulnerability stopped reproducing OR command is stale/malformed
- Test minimal equivalent corrected command
- If corrected command proves same bug: update report and report-manual.md
- If only materially different attack works: reassess title, impact, classification, severity
- If no safe form reproduces: REJECTED or NEEDS-EVIDENCE

Every HTTP request with User-Agent: use current Chrome 154 UA.

### Stage 3: Security Bug vs Business Behavior

Determine whether exposed action/data is intended public product behavior.

#### Mandatory Business-Intent Research

When intended-behavior judgment could change verdict, check in order:
1. Current program policy, scope notes, known issues, explicitly excluded behavior
2. Official product documentation, help center, API docs, role/permission guides
3. Official public UI with researcher-owned accounts at the relevant role
4. First-party client behavior, labels, authentication directives

**Classification:**
- `SECURITY BUG` — crosses authorization, confidentiality, integrity, or trust boundary
- `INTENDED BUT OVEREXPOSED` — public function exists but response exposes more than needed
- `BUSINESS DECISION / INTENDED` — same records/fields/actions intentionally public, no meaningful excess
- `UNCLEAR` — one concrete fact unavailable → NEEDS-EVIDENCE

**Self-Only State Bypasses:** Only reportable when the bypassed state causes concrete downstream system trust that leads to real security impact on other users.

### Stage 4: Triage Decision Gates

Work through all gates before assigning final severity:

**Gate 1: So-What Test** — State concrete attacker outcome. If you cannot state what an attacker gains without hedging, finding is below floor.

**Gate 2: Prerequisite Reachability** — Every required precondition demonstrated against live target. No "assuming attacker has X."

**Gate 3: Delivery Path Verification** — Complete attacker path from zero (or only their own normal account) demonstrated end-to-end.

**Gate 4: Impact Accuracy** — Is claimed severity supported by proven impact? Do not upgrade from new angles discovered here. Do downgrade unsupported claims.

**Gate 5: Classification Accuracy** — Select exact platform taxonomy leaf (Bugcrowd VRT or HackerOne weakness). For Bugcrowd: P1-P5 priority from scored leaf is authoritative. For `priority: null` leaf: use concrete proven impact with explicit rationale.

**Gate 6: Format Compliance** — Report follows report-format.md exactly: fastest-proof block first, Prerequisites second, correct section headings, no em dashes, correct screenshot references.

**Gate 7: Screenshot Completeness** — No `![SCREENSHOT NEEDED: ...]()` placeholders remain. Every screenshot referenced exists as genuine capture.

### Phase 9 Verdict: PASS

Set finding `.dscolor` to `purple`. Report is ready for submission. All gates passed.

Required before PASS:
- [ ] Submission policy gates cleared (DoS, SSRF floor, session-swap, credential liveness)
- [ ] Prerequisite ledger complete with all REACHABLE
- [ ] Production-realistic delivery PASS
- [ ] Fresh live reproduction confirmed
- [ ] Security bug (not business decision)
- [ ] Platform classification exact and correct
- [ ] Final severity supported by proven impact
- [ ] report.md format-compliant
- [ ] All screenshots genuine (no placeholders)
- [ ] Remove Internal TLDR before PASS

### Phase 9 Verdict: REJECTED

Set finding `.dscolor` to `red`. Move whole finding beneath `NA-DISPROVED/`.

```markdown
# DISPROVED.md
Reason: <exact rejection reason>
Technical classification: <honest taxonomy> (preserved for reference)
Technical severity: <honest severity>
Gate that failed: <which gate>
Evidence: <what was checked>
```

**Rejection reasons:**
- `pure_dos_rejected`
- `ssrf_below_researcher_floor`
- `session_swap_below_researcher_floor`
- `low_sensitivity_read_only_below_researcher_floor`
- `prerequisite_not_reachable: <missing primitive>`
- `delivery_path_not_proven`
- `business_decision_intended`
- `below_submission_floor`
- `no_repro`

### Phase 9 Verdict: NEEDS-EVIDENCE

Set finding `.dscolor` to `orange`. Keep in active dig root. Stop.

Use only when ONE concrete external delivery fact is temporarily unavailable. An unproven speculative delivery path is REJECTED, not NEEDS-EVIDENCE.

### P09-TRIAGE-GATE.md Record (Private)

Write a complete private gate record:

```markdown
# P09 Triage Gate: <finding-slug>

Gate start: <UTC timestamp>
Target: <target_display>
Report SHA256: <sha256>

## Submission Policy
Submission policy check: PASS | REJECTED (reason)
SSRF final technical severity: N/A | <severity>
SSRF researcher submission floor: N/A | PASS | REJECTED
Session-swap shape: YES | NO
Credential liveness: N/A | CONFIRMED | INVALID | BLOCKED
Credential authority floor: N/A | PASS | REJECTED | BLOCKED | NOT A CREDENTIAL
Read-only disclosure: YES | NO
Material sensitivity: <assessment>
Read-only researcher floor: N/A | PASS | REJECTED

## Prerequisite Ledger
(table)

## Attacker Delivery
Attacker delivery: <sequence>
Harness-only actions: <list>
Production-realistic delivery: PASS | FAIL | BLOCKED

## Live Reproduction
Timestamp: <UTC>
Commands run: <list>
Result: CONFIRMED | FAILED | CORRECTED

## Business Intent
Classification: SECURITY BUG | INTENDED BUT OVEREXPOSED | BUSINESS DECISION / INTENDED | UNCLEAR
Sources consulted: (list with URLs)

## Final Verdict
Verdict: PASS | REJECTED | NEEDS-EVIDENCE
Final severity: <severity>
Final classification: <exact taxonomy leaf>
Color: purple | red | orange
```

---

## PART 6: REPORT GENERATION

### Setting Up Test Infrastructure

Create disposable test accounts using `agent-email`:

```bash
agent-email create
```

Register accounts on the target using **agent-browser** or the **in-app browser**. Poll for verification emails:

```bash
agent-email read default --wait 30 --interval 2
agent-email show default <messageId>
```

Create the accounts you need:
- **IDOR/BOLA**: attacker account + victim account
- **Privilege escalation**: low-priv + high-priv accounts
- **Access control**: accounts with different roles
- **Auth bugs**: at least one valid account

### Escalation Paths by Vuln Class

Test these systematically before writing the report:

**IDOR / BOLA**
- Read-only → Read+Write (try PUT/PATCH/DELETE with other users' IDs)
- Single record → Broader access (use a bounded set of controlled records)
- User data → Admin data (try admin-level resource IDs)
- Same-tenant → Cross-tenant (try org/tenant ID swaps)
- Check if PII/financial data exposed (regulatory impact: GDPR, HIPAA, PCI)

**XSS**
- Reflected → Stored (inject into fields that persist)
- Alert box → Access to session data or privileged actions
- Session access → Full ATO (prove with controlled accounts)
- User context → Admin context (trigger XSS as admin user)
- XSS → CSRF bypass (use XSS to perform privileged actions)

**SSRF**
- External → Internal (hit 127.0.0.1, 169.254.169.254, internal hostnames)
- HTTP only → File read (`file:///etc/passwd`)
- Cloud metadata → Credential exposure (confirm only to extent authorized)
- Internal service → RCE (chain with unauthenticated internal services)

**SQL Injection**
- Single column → Broader database access (use bounded queries)
- Read → Write (`INSERT`, `UPDATE` via stacked queries)
- Data extraction → File read/write (`LOAD_FILE`, `INTO OUTFILE`)
- Data extraction → RCE (`xp_cmdshell`, UDFs)

**Auth Bypass**
- Single account → Any account
- User accounts → Admin accounts
- Auth bypass → Persistent access (demonstrate with controlled test account)
- Auth bypass → MFA bypass

**Privilege Escalation**
- User → Admin
- Read-only → Read-write
- Single function → Full admin panel
- Modify security settings (disable MFA, change passwords)?
- Cross-tenant access?

**Open Redirect**
- Standalone → Chain with OAuth token theft (redirect_uri manipulation)
- Chain with SSO flows → ATO
- Test `javascript:` and `data:` URI schemes

**File Upload**
- Image → Web shell (extension bypass, content-type manipulation)
- Upload → Path traversal (directory traversal in filename)
- SVG upload → Stored XSS

**Chaining**
1. Info disclosure + IDOR → Proven full exploitation with real IDs
2. Open redirect + OAuth → Token theft → ATO
3. XSS + CSRF → Privileged action execution
4. SSRF + Cloud metadata → Cloud infrastructure takeover
5. Race condition + Financial endpoint → Double-spend / balance manipulation
6. Any bug + Admin access → Maximum impact demonstration

### CVSS Rescoring

After testing escalation paths, calculate the highest CVSS 3.1 score supported by the actual exploit chain. Set each metric from the evidence: authentication needed for the chain affects PR, a victim opening stored XSS generally affects UI, cross-tenant access alone does not establish changed Scope. Assign high C/I/A impact only when demonstrated reach warrants it. Explain any severity claim that depends on strongly supported inference.

### Submission Readiness Gate

**If the report fails this gate, STOP. Tell the user not to submit.**

**Auto-Reject — ANY of these = DO NOT SUBMIT:**
- Informational only (missing headers, version disclosure, verbose errors with no data leak)
- Best practice violation without exploit (missing rate limit, missing CSP with no XSS)
- Self-XSS with no delivery vector
- Clearly outside scope under constraints supplied by the user
- Requires victim to do unrealistic things (install malware, paste into console)
- Scanner output with no manual validation
- Theoretical — no working PoC, "could potentially" language
- Already patched / public CVE
- DoS via resource exhaustion (unless catastrophic)
- Missing SPF/DKIM/DMARC
- Clickjacking on non-state-changing pages
- CSRF on logout or non-sensitive actions
- Open redirect without chain
- Host header injection without cache poisoning PoC
- User enumeration alone (unless program explicitly accepts it)

**Reproduction-Completeness Gate** — not submission-ready until the report includes, where applicable:
- Exact affected product version/build and feature location
- Minimum required role and compact explanation of product-specific role name or numeric role ID
- How to obtain each target-specific token, cookie, identifier, or other required value
- Placement and reachability requirements for custom test hosts
- Shortest runnable command or script for custom listeners or services
- Decisive request, response, service log, and success condition
- Clear indication of which addresses and values the triager must replace

**Verdict:**
- **GREEN**: Independent end-to-end testing confirms vulnerability and impact. Proceed.
- **YELLOW**: Testing partial, impact borderline, or important link unverified. Continue testing or strengthen evidence.
- **RED**: Current evidence does not support submission. Explain why and what would need to change.

### Report Template

Write a file called `<target-domain>-<vuln-type>.md` in the current working directory (e.g. `example-com-idor.md`). This is the final deliverable — a clean, copy-paste-ready report.

The report must be:
- **Straight to the point** — No filler, no "I discovered", no narrative storytelling
- **Evidence-heavy** — Every claim backed by request/response or screenshot
- **Max impact framing** — Lead with the worst-case proven impact
- **Self-contained and platform-ready** — A triager can understand and reproduce it without access to researcher's lab

```
## [Specific Vulnerability Title Showing Max Impact]

**Severity**: [Critical|High|Medium|Low] (CVSS 3.1: X.X)
**CVSS Vector**: `CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X`
**CWE**: CWE-XXX — [Name]
**Asset**: `[affected URL/endpoint]`

### Summary

[2-3 sentences max. What's broken, what an attacker gets. Lead with impact.]

### Reproduction

Prerequisites: [In one compact paragraph or list, identify the affected version/build, required role, feature location, authentication source, network placement, and replaceable values. Omit facts that are obvious to a security triager.]

Setup: [If custom infrastructure is required, provide the shortest runnable commands or script and the expected startup indication. Omit this label when no custom setup is needed.]

1. [Perform one exact target-specific action. Include the request or command at the step where it is used.]
2. [Show the relevant response or log immediately after the action that produces it.]
3. [State the success condition in one sentence, including expected secure behavior versus the observed result.]

` ` `http
[Raw HTTP request or curl command]
` ` `

` ` `http
[Response proving exploitation]
` ` `

### Impact

- [Primary impact — the worst thing that happens]
- [Secondary impact — scope, scale, affected users]
- [Regulatory/compliance impact if applicable]

### Remediation

- [Primary fix]
- [Alternative mitigation if applicable]
```

### Report Rules

1. **Title**: State the strongest demonstrated impact. Use "IDOR in invoice API exposes other tenants' invoices" when the evidence shows that access.
2. **Precise claims**: Direct language for proven behavior. Label plausible but untested consequences as inferences.
3. **No self-references**: No "I found", "I tested", "during my research".
4. **Assume security competence, not target familiarity**: Explain the target's feature location, product-specific roles, authentication-value source, custom network placement, and non-obvious prerequisites — not standard tools or concepts.
5. **Setup must be executable**: "Configure a listener" is insufficient. Provide the minimal runnable command or script.
6. **Placeholders must be actionable**: For every value the triager must replace, state what it represents and where to obtain it.
7. **Keep proof beside the action**: Decisive requests, responses, and logs directly in the reproduction flow. Do not repeat them in a separate PoC section.
8. **Steps must not hide work**: One numbered action per step when combining actions would make the reader infer missing setup.
9. **Impact section leads with the strongest supported escalated impact**, not the base finding. Mark an inference as an inference.
10. **Be concise without a word limit**: Remove filler, generic transitions, tutorial text, and repeated evidence.
11. **Make evidence accessible**: Include decisive request/response excerpts in the report.
12. **Never redact supplied evidence**: Preserve every password, cookie, key, token, credential, identifier, name, email address, IP address exactly.
13. **Request format**: Raw HTTP and curl are equally acceptable. Include headers, body, cookies, and authentication setup.
14. **Paste test before delivery**: Read the entire report file as if pasting it into the submission form. Remove template brackets, drafting instructions, internal caveat blocks, status labels.
15. **Source-fidelity test before delivery**: Compare completed report against supplied evidence. Confirm every concrete credential, secret, identifier, URL, hash, and command argument remains verbatim.

### Knowledge-Assumption Audit

Before delivery, read only the submission file as a capable triager unfamiliar with the target. Block delivery if any answer is no:

- Can the reader obtain every required product-specific value from the report?
- Can the reader create every custom listener or service without inventing code or configuration?
- Is the required role, feature location, and network placement clear without product research?
- Does each decisive action have an adjacent success signal in a response, log, or state check?
- Can the reader distinguish fixed evidence values from values they must replace?
- Has duplicated explanation been removed while all non-obvious operational detail remains?

If essential information is missing and cannot be established during authorized testing, do not invent it or pad the report. Mark not ready and request the exact missing detail.

### Triage Decision Output

After writing the report, present this summary in chat only. Never append it to the submission report file:

```
TRIAGE DECISION
═══════════════
Tested:      [YES — independently reproduced end to end / PARTIAL — specify verified steps / NO — assessed supplied evidence]
Validation:  [CONFIRMED / PARTIALLY CONFIRMED / UNVERIFIED / NOT REPRODUCIBLE]
Submission:  [GREEN / YELLOW / RED]
Severity:    [Original] → [Escalated]
CVSS:        X.X — CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X
Confidence:  [HIGH / MEDIUM / LOW]
Action:      [SUBMIT / STRENGTHEN / DO NOT SUBMIT]
Bounty Est:  [$range]
Report:      <target-domain>-<vuln-type>.md (ready to copy-paste)
```

If RED: explain what's wrong and what would fix it. If YELLOW: explain what's borderline and whether escalation helped. If GREEN: tell them to submit.

---

## RULES

1. **Independently test end to end when applicable.** For triage, validation, or escalation, reproduce the whole exploit and verify its effect. Never label a finding confirmed solely because the supplied report says it works.

2. **Never submit a report you wouldn't bet the account on.** One N/A closure can lead to a ban.

3. **Escalation is not fabrication.** Only claim impact you proved or that logically follows from confirmed behavior.

4. **Use disposable accounts.** Create fresh test accounts via agent-email. Create multiple accounts when you need attacker/victim pairs.

5. **The report file is the deliverable for a submission-ready finding.** Output `<target-domain>-<vuln-type>.md` when evidence supports submission. For a finding that does not reproduce, state what is missing instead of dressing it up as a ready report.

6. **Max impact, honest framing.** Pursue every credible escalation path. Seek the absolute highest severity the evidence supports. Frame in business terms, state the proof for each step.

7. **Dense reports win.** Triage teams skim. Front-load impact, use executable evidence instead of narration, remove repetition. Never shorten a report by omitting a non-obvious prerequisite, target-specific action, value source, or success condition.

8. **One vuln per report** unless bugs chain together for compound impact.

9. **If it doesn't reproduce, say so immediately.** Don't waste time polishing a dead finding.

10. **Save evidence as you go.** Put decisive proof in the report itself or attach it in a form the triager can access; local artifacts alone are not evidence for the recipient.



---

## bb-reporting

# BUGCROWD REPORTING — Program-Specific Tactics

> Companion to the generic `report-writing` skill. Use when working specifically on Bugcrowd submissions where VRT mapping, OOS-clause rebuttals, or per-program target selection matter.

This skill encodes patterns that apply specifically to Bugcrowd's submission flow. For the generic per-platform templates (HackerOne / Bugcrowd / Intigriti / Immunefi report bodies), use the `report-writing` skill. For the 7-Question Gate before deciding to report at all, use `triage-validation`.

---

## 1. VRT Category Selection — Search & Fallback Strategy

Bugcrowd's submission form requires a single VRT (Vulnerability Rating Taxonomy) selection. The dropdown's default severity is bound to the chosen node — pick wrong and the form auto-suggests a lower priority (often P4) when the actual impact is P3 or P2.

> Note: VRT default severities are not fixed constants. Bugcrowd revises the VRT schema across versions, and individual programs can remap defaults via their own priority configuration. The P-values shown in the examples below (e.g., "No Rate Limiting on Form → Login" defaulting to P4) are the typical baseline at time of writing — always read the severity the *current* form actually auto-suggests for *this* program rather than assuming the value here.

### 1.1 Search hierarchy (try in order, pick the highest-severity match that still describes the bug)

For any finding, search the VRT dropdown with these terms in this order:

1. **The bug's primary class** — e.g., `IDOR`, `XSS`, `SSRF`, `auth bypass`, `2FA bypass`
2. **The data category exposed** — e.g., `PII`, `sensitive data exposure`, `disclosure of secrets`
3. **The control bypassed** — e.g., `broken access control`, `authentication bypass`
4. **The endpoint type** — e.g., `no rate limiting on form > login`, `no rate limiting on form > change password`
5. **The generic parent node** — e.g., `Server Security Misconfiguration > Other`, `Broken Access Control > Other`

### 1.2 Pick the highest-severity match that still accurately describes the bug

Never select a VRT that misrepresents the bug just to get a higher default severity. Triagers will reassign and may flag the misrepresentation. The discipline is: pick the most specific *accurate* VRT, then use §2 (Manual Severity Override) if the default is wrong.

### 1.3 Common mappings worth knowing

| Finding type | First-choice VRT | Fallback |
|---|---|---|
| ATO via missing 2FA on password change | Broken Authentication & Session Management → Second Factor Authentication (2FA/MFA) → Bypass | Broken Auth → Authentication Bypass → Other |
| Password oracle without rate limit | Broken Authentication & Session Management → Authentication Bypass → Other | Server Security Misconfiguration → No Rate Limiting on Form → Login |
| GraphQL introspection / APQ allowlist bypass | Server Security Misconfiguration → Other (justify in body) | Broken Access Control → Other |
| Username → real name PII enumeration | Sensitive Data Exposure → PII Leakage / Disclosure of Secrets → Non-Corporate User | Broken Access Control → Other |
| State desync on security-sensitive action | Application-Level DoS → Other (with state-desync framing) | Server Security Misconfiguration → Other |
| Email/SMS pumping on auth-flow endpoint | Server Security Misconfiguration → No Rate Limiting on Form → Email-Triggering / SMS-Triggering | Server Security Misconfiguration → No Rate Limiting on Action |
| Token brute-force (email-change OTP, password reset) | Broken Authentication → Authentication Bypass → Other | Server Security Misconfiguration → No Rate Limiting on Action |

### 1.4 If no good VRT exists

Pick `Server Security Misconfiguration → Other` or `Broken Access Control → Other` and **lead the description body with a "VRT mapping note"** explaining why the chosen node is the closest available match and what the bug actually is.

---

## 2. Manual Severity Override

Bugcrowd's form lets you manually set Technical Severity *separate from the VRT default*. The form text itself states: *"A severity rating suggested by the VRT is not guaranteed to be the severity rating applied to your submission."*

### 2.1 When to override

Override the VRT default when:
- The chained outcome is a higher severity than the standalone bug class (chain → ATO)
- The VRT category is approximate and its default doesn't reflect the actual impact class
- The program's own Focus Areas explicitly list this outcome at a higher severity than VRT's default
- The data class exposed is more sensitive than the VRT's example uses (e.g., real-name PII vs. handle enumeration)

### 2.2 How to override (form mechanics)

1. Select the VRT that most accurately describes the bug (per §1)
2. Note the auto-suggested severity (P4, P3, etc.)
3. In the **Technical Severity** field, manually pick the severity you're requesting
4. Add a **Severity Request** paragraph as the FIRST section of the description body (per §3)

### 2.3 Don't over-claim

P1 inflation is the fastest way to lose triager trust. Reserve P1 for ATO without interaction, RCE, mass PII exfiltration, fund theft, and similar Critical-bucket impacts. If the chain to P1 requires a separate stolen-cookie premise, file the standalone primitive at P3 and discuss the chain explicitly with cross-references (per §4).

---

## 3. Severity-Request Paragraph — Always First in the Body

When the VRT default underrates impact, the FIRST section of the description body should be a severity-request paragraph. This is the first thing the triager reads and it pre-empts the auto-close that often happens when triagers see "P4" in the form.

### 3.1 Template

```markdown
## Severity request — please review carefully before applying VRT default

The closest VRT category for this finding is "[chosen VRT]," which Bugcrowd defaults to **P[N] ($X-$Y in [program]'s rubric)**. **I am requesting evaluation at P[M] [standalone | in chain with submission XXXX]** for the following reasons:

1. **[Impact axis 1]** — [specific reason this finding exceeds the VRT default's example]
2. **[Impact axis 2]** — [specific reason, often citing the program's own Focus Areas]
3. **[Impact axis 3]** — [specific reason, often comparing to historical bounty payouts for the same data class]

[Optional: one paragraph contrasting the VRT default's typical example with this finding's actual impact, e.g., "P4 = No Rate Limiting on Login Form" applies to ordinary login pages where brute force is bounded by lockout policies; this endpoint has neither lockout nor throttle.]
```

### 3.2 Worked example pattern

```markdown
## Severity request — please review carefully before applying VRT default

The closest VRT category for this finding is "No Rate Limiting on Form → Login," which Bugcrowd defaults to **P4 ($XX–$YY in this program's rubric)**. **I am requesting evaluation at P3 standalone, P2 in chain with submission XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX** for the following reasons:

1. **[Endpoint] is a password-disclosure oracle, not a generic rate-limit gap.** The endpoint returns true/false for a supplied password — combined with cookie theft, it is the exact primitive an attacker uses to learn the victim's *durable* credential from a stolen *transient* session.
2. **The chained outcome is "Account Takeover,"** explicitly listed under the program → Focus Areas → Critical (P1) examples. This finding is one of two independent links that make that chain work; the other is submission XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.
3. **The two findings have independent fix surfaces.** Per the program's "one fix = one bounty" rule they should be evaluated as two separate findings whose chain raises the joint severity.

The "P4 = No Rate Limiting on Login Form" default applies to ordinary login pages where brute-force is bounded by lockout policies. This endpoint has neither lockout nor throttle, and the result of brute force is the *user's actual password* (not a session) — making the impact significantly higher than the default VRT severity assumes.
```

### 3.3 Tone guidelines

- Open with *"Severity request — please review carefully before applying VRT default"* (literal phrase). Triagers recognize this and don't auto-close.
- Use **bold** sparingly; one or two phrases per reason at most.
- Never use "could potentially" or "may allow" — these are downgrade-bait.
- Cite the program's own Focus Areas / accepted-impact list by exact name.
- Cross-reference linked submissions by full submission ID (UUID format).

---

## 4. OOS-Clause Rebuttals — Templates

Bugcrowd triagers sometimes auto-close findings by mapping them to an OOS clause without reading the report. Pre-empt this by including an **In-scope justification** section that quotes the OOS clause and explains why your finding doesn't fit it.

### 4.1 "Rate limiting on non-authentication endpoints" rebuttal

When the finding is on an authentication endpoint (login, password change, password verify, OTP verify, token validate):

```markdown
## In-scope justification

The program OOS list excludes "Rate limiting or brute-force issues on **non-authentication** endpoints." `[endpoint name]` is the canonical authentication endpoint — it accepts a password/token/OTP and returns whether it matches the user's stored credential. By definition this is an authentication primitive. The OOS clause's "non-authentication" qualifier therefore does NOT apply.
```

### 4.2 "Debug information disclosure" rebuttal (for schema/introspection findings)

When the finding involves schema disclosure that's actually a control bypass (e.g., GraphQL allowlist bypass exposing the mutation surface):

```markdown
## In-scope justification

This is not a "debug information" finding. The [persisted-query allowlist | introspection gate | etc.] is acting as an authorization control on the [GraphQL surface | API tree | etc.]. The bypass converts that gate into a no-op — multiple [mutations | endpoints] become reachable that the official clients cannot invoke. The schema disclosure is incidental; the impact is **mutation-surface unlock**, not information leakage.
```

### 4.3 "User enumeration with low-risk information" rebuttal

When the finding leaks more than just "this handle/email exists":

```markdown
## In-scope justification

The program OOS list excludes "User Enumeration issues with **low-risk and insignificant** information being enumerated." The data leaked here is **neither low-risk nor insignificant**: it includes the matched user's [full real first name, last name, profile photo / SSN last 4 / phone number / etc.]. Real-[name | identity | etc.] knowledge is the same data class that gates the program's own [account-recovery flows / fraud-investigation interviews / support-call verification], which means this lookup directly defeats one of the program's own anti-fraud controls. This is PII disclosure, not handle enumeration.
```

### 4.4 "Theoretical issues / not exploitable" rebuttal

When the finding's exploitability has been demonstrated end-to-end:

```markdown
## In-scope justification

This finding is exploitable end-to-end as demonstrated in the PoC: [one-sentence summary of the proven exploitation path]. The PoC includes [N HTTP requests with redacted cookies | N screenshots | a sanitized HAR file | etc.] showing the attacker's session [reading victim data | changing victim credentials | etc.]. The OOS clause for "theoretical issues that are not exploitable, or can not be demonstrated as exploitable" does not apply.
```

### 4.5 If you don't have end-to-end proof

If you only have an "API behavior" observation without a fully demonstrated exploitation path, the finding is theoretical. Don't file it. Capture the missing evidence (delivery confirmation, token-format inspection, cross-account victim data in response, etc.) and re-evaluate. Filing theoretical findings damages researcher reputation on the platform.

---

## 5. Chained Findings — Cross-Reference Strategy

Many high-impact findings are chains of two or more standalone primitives (oracle + missing step-up = ATO). Bugcrowd's program rule: *"Submit one vulnerability per report. If multiple vulnerabilities must be chained to demonstrate impact, you may include them together, but please clearly explain the chain."*

### 5.1 Filing strategy for chains

1. **Identify the highest-severity chained outcome** (typically the one that maps to a P1/P2 example in the program's Focus Areas).
2. **File the chain primitives FIRST** as separate reports — each at its standalone severity (typically P3/P4). A submission's UUID only exists *after* it is filed, so the primitives must exist before anything can reference them. Leave the cross-reference line in each primitive's body as a placeholder for now.
3. **File the chain consumer** — the report whose body describes the full ATO/RCE/etc. impact at the chained severity (e.g., P1). Because the primitives already exist, fill in their real UUIDs in the consumer's "Chain partners" block (per §5.2).
4. **Edit each primitive after filing the consumer** to backfill the consumer's UUID: *"Chain partner: submission [UUID] for the full impact narrative."* (The reference is bidirectional, so one report must be edited after the other is filed — Bugcrowd allows post-submission edits to the description body.)

### 5.2 Cross-reference template

In the chain consumer's body, near the top:

```markdown
## Chain partners (filed as separate reports)

- **submission [UUID-1]** — [primitive 1: e.g., `me.verify_password` no rate limit]
- **submission [UUID-2]** — [primitive 2: e.g., GraphQL APQ allowlist bypass]

These primitives have independent fix surfaces and are filed separately per the program's "one fix = one bounty" rule. The chained impact described here requires both primitives to be exploited end-to-end.
```

In each primitive's body:

```markdown
## Chain context

This finding is the [N]th of [M] independent primitives that together produce [impact, e.g., "permanent account takeover from a stolen session cookie"]. The full chain narrative and the chained severity (P1) are documented in submission [UUID]. This standalone report is at P3 reflecting the primitive's individual impact.
```

### 5.3 What NOT to do

- Don't paste the entire chain narrative into every primitive's body. Cross-reference instead.
- Don't claim each primitive is independently P1 — overclaiming damages credibility for all linked reports.
- Don't ask for a single combined bounty for the chain. The program's "one fix = one bounty" rule means each independent fix surface is a separate bounty. Frame the chain as a severity-amplifier, not a merge request.

---

## 6. Target Selection — QA vs. Production

Programs that scope both production and QA assets (e.g., `app.target.com` vs. `app-qa.target.com`) require careful target selection.

### 6.1 Picking the right target dropdown entry

| If you tested... | Pick this target | Why |
|---|---|---|
| Production app/API | The production target | Most accurate; signals the impact landed on real users |
| QA app/API (per program rules for non-US researchers) | The QA target (e.g., `Sign In - (QA)`, `Enrollment - (QA)`) | Accurate per program rules; signals friendly tester |
| QA but no specific QA target exists | Closest matching production target with a clear QA disclaimer in the body | Triager will reassign correctly if needed |
| Cross-asset finding (multiple targets affected) | The asset where the bug originates / has the highest impact | Add list of other affected targets in the body |

### 6.2 QA-disclaimer paragraph (when filing a QA-tested finding)

```markdown
## Notes for triagers

- Tested in the QA environment ([qa-host]) per the program's instruction for non-US researchers / per the program's QA-testing scope.
- Production may enforce additional controls that QA does not — please confirm whether the same resolver code path runs on production.
- All testing limited to my own QA test account; no other accounts were interacted with.
- Selected target: `[chosen-target]`. Selected VRT: `[chosen-VRT]`. Both selected as closest available matches; please reassign if more appropriate options exist.
```

---

## 7. Researcher-Side Hygiene (Bugcrowd-specific)

These are program-rule items that affect submission quality even though they're not part of the report body itself.

### 7.1 Account email — Bugcrowdninja alias

Most Bugcrowd-managed programs ask researchers to use their `@bugcrowdninja.com` alias as the account email on the target. This flags traffic as friendly-tester to the target's fraud team. Steps:

1. Sign up for the target using your Bugcrowd alias (looks like `username@bugcrowdninja.com`)
2. If you already have an account, update the email to the alias before testing
3. If the program offers a contact path for multi-account testing, use that to coordinate additional aliased accounts (`alias+test1@bugcrowdninja.com`, etc.)
4. Document the alias in the report's "Notes for triagers" section so the triager can correlate test traffic in their logs

### 7.2 Account-state restoration after PoC

After demonstrating any state-changing action (password change, email change, device removal, money transfer):

1. Restore the account to its pre-PoC state immediately (e.g., revert the password to what it was)
2. Document the restoration in the report — *"Account state was restored immediately after the PoC."*
3. If restoration is impossible (e.g., a sent email cannot be unsent), document the residual state honestly

### 7.3 Cookie / session rotation after submission

After submitting any report that includes session-cookie-derived evidence:

1. Log out and log back in to rotate the session cookie
2. Any cookie value visible in screenshots / HARs you submitted is now dead
3. Optionally, rotate the test-account password to a fresh value not used elsewhere — that way passwords visible in PoC screenshots are also dead

### 7.4 If the test account gets locked

1. Don't create a second account to bypass the lock — that looks like fraud
2. Email the program-specific contact (if provided) with your Bugcrowd username and the report ID
3. Wait for the program team to unblock you; testing during the lock period damages credibility

---

## 8. Submission-Order Strategy for Multi-Finding Engagements

When you have multiple findings from a single engagement, the order matters.

### 8.1 Recommended order

1. **Chain primitives before their consumer.** A consumer references the primitives' report UUIDs, which only exist once the primitives are filed (see §5.1). File the best-evidenced primitive first to lock your timestamp, then the rest of the chain's primitives.
2. **The chain consumer next** — fill in the real primitive UUIDs, then edit each primitive to backfill the consumer's UUID (Bugcrowd allows post-submission body edits).
3. **Standalone P3 findings next.** Order by quality of evidence: best-evidenced first, riskier (OOS-adjacent) findings later.
4. **OOS-risky findings last.** By the time these land, you've established a credible track record on this engagement.

### 8.2 Tracking submission IDs

Maintain a simple text file with each submission's UUID, severity, and one-line description. You'll reference these IDs across reports and during any subsequent triager dialogue.

### 8.3 What to avoid

- Don't file all findings in a single batch within minutes. Triagers see this as low-effort spam.
- Don't file an OOS-risky finding before a clean P3 from the same engagement. The clean one establishes credibility; the risky one benefits from being read in that context.
- Don't disclose any findings publicly until the program explicitly says it's OK. Bugcrowd's confidentiality applies to both unresolved AND resolved issues.

---

## 9. Pairing with Other Skills

| For this question / task | Use this skill |
|---|---|
| "Should I report this finding at all?" | `triage-validation` (7-Question Gate) |
| "What's the report body template for Bugcrowd?" | `report-writing` |
| "What VRT do I pick?" | This skill (`bugcrowd-reporting`) §1 |
| "How do I argue for higher severity?" | This skill §2-3 |
| "How do I rebut an OOS objection?" | This skill §4 |
| "How do I redact cookies / PII in screenshots?" | `evidence-hygiene` |
| "Where do I find the payload for this exploitation step?" | `security-arsenal` |
| "Where do I find recon probes for this asset class?" | `offensive-osint` |

---

## Notes on usage

This skill is small and focused. It does NOT duplicate content from `report-writing` (per-platform templates, CVSS scoring, downgrade counters, 60-second pre-submit checklist) — load both skills together when filing a Bugcrowd report. The two skills' content composes naturally because their boundaries are clean: `report-writing` is the body templates, `bugcrowd-reporting` is the program-specific tactics layered on top.

---

## Related Skills & Chains

- **`report-writing`** — Always load this skill alongside `bugcrowd-reporting`. Workflow primitive: `report-writing` provides the body skeleton; this skill layers VRT selection + severity-request paragraph + OOS-clause rebuttals on top of that skeleton.
- **`triage-validation`** — When deciding if a Bugcrowd-bound finding will pass triage. Workflow primitive: 7Q gate runs first; only validated findings reach this skill for VRT mapping.
- **`evidence-hygiene`** — When attaching screenshots / HARs to a Bugcrowd submission. Workflow primitive: Bugcrowd's private attachment system requires redacted evidence; route everything through `evidence-hygiene` before clicking attach.
- **`security-arsenal`** — When the PoC step needs payloads cited verbatim. Workflow primitive: the "Steps to Reproduce" section in this skill's report bodies pulls exact payloads from `security-arsenal` so the triager can paste-and-run.
- **`bb-methodology`** — When confirming engagement mode is bug-bounty (not red-team). Workflow primitive: PART 0 of `bb-methodology` answers "bug bounty?"; if yes AND the target is Bugcrowd, this skill becomes the reporting overlay.


