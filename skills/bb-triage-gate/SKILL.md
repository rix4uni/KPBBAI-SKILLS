---
name: bb-triage-gate
description: Bug bounty Phase 9 triage gate — act as brutally honest first-line platform triager for one report. Apply researcher submission policy, reproduce live, verify prerequisites, classify security bug vs intended behavior, assign platform classification and severity. Run after Phase 8a for each blue finding.
sources:
  - bug-bounty-hunting-prompts/phases/phase-09-triage-gate.md
argument-hint: "<finding_vN_path>"
allowed-tools: Bash, Read, Write, WebFetch
---

# Bug Bounty Triage Gate (Phase 9)

Act as brutally honest first-line platform triager. Apply researcher submission policy, reproduce live, verify prerequisites, then produce a final PASS or REJECT verdict.

**Role:** Independent verification, convergence, and formatting — NOT another escalation phase. Do not brainstorm, delegate, or pursue new escalation angles.

## Finding Color Contract

| Color | Action |
|-------|--------|
| `blue` | Keep while work is active |
| `purple` | Set after valid PASS (report, classification, severity, folder prefix all pass) |
| `red` | Set for REJECTED → move to NA-DISPROVED/ |
| `orange` | Set for NEEDS-EVIDENCE → stop, keep in active dig root |

## Stage 0: Researcher Submission Policy

Apply BEFORE any live action. These are hard rejections regardless of severity.

### Pure DoS Rejection

Reject immediately when highest claimed/proven impact is ONLY availability loss/degradation:
- Account lockout, forced logout, login denial
- Application/endpoint/tenant DoS
- Crash, hang, restart, resource exhaustion
- Rate-limit bypass whose only outcome is availability denial
- Email/SMS/notification flooding with no other impact

**Exception:** Continue only when non-DoS impact (unauthorized data access, state change, privilege gain, ATO) is independently proven.

### SSRF Researcher Floor

P09 is the final gatekeeper: submit SSRF only when final severity is High or Critical.

| Final SSRF Severity | Verdict |
|--------------------|---------|
| Critical | PASS |
| High | PASS |
| Medium | REJECTED (reason: ssrf_below_researcher_floor) |
| Low/Info | REJECTED |

Blindness is not an automatic rejection — a blind SSRF with proven High/Critical impact still passes.

Record in P09-TRIAGE-GATE.md:
```
SSRF final technical severity: <severity>
SSRF researcher submission floor: PASS | REJECTED
SSRF floor basis: <exact proven impact and why it does/doesn't reach High>
```

### Login CSRF / Session-Swap Floor

Placing victim into attacker's account is NOT account takeover. Only pass when complete delivery path proves Medium+ consequence:
- Material victim-entered private data becomes available to attacker
- Unauthorized financial action occurs
- Persistent credential/security-control change affects victim
- Attacker gains access to victim's existing account/records

Empty guest cart, attacker-owned profile, or hope of future data entry → REJECTED (reason: session_swap_below_researcher_floor).

### Low-Sensitivity Read-Only Exposure Floor

A scored Medium taxonomy leaf alone doesn't prove submission value. Assess:
- Exposed fields, audience, affected population, aggregation, public adjacency
- Attacker usefulness and realistic follow-on value

Titles, timestamps, internal labels, behavioral segments, non-secret metadata → REJECTED (reason: low_sensitivity_read_only_below_researcher_floor).

Credentials, private communications, financial records, identity documents → may pass at honest severity.

### Exposed Credential Validation

Require: current public first-party source + minimal liveness evidence with negative control.

```
Credential liveness: CONFIRMED | INVALID | BLOCKED
```

Permitted authority probes after liveness:
- Capability negotiation, wildcard/namespace attach status, denied-op controls
- Exercise on researcher-owned objects (own account, channel, record, tenant)
- ≤3 bounded cross-entity confirmations with lawful identifiers

Banned: bulk/sustained cross-tenant reads, privileged actions on non-owned objects.

## Stage 1: Prerequisite Ledger

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

### Production-Realistic Delivery Test

Prove complete delivery path for external attacker — not just the vulnerable primitive:

```
Attacker delivery: <shortest complete sequence>
Harness-only actions: <actions only possible because researcher controls victim>
Production-realistic delivery: PASS | FAIL | BLOCKED
```

Count every required: victim click, navigation, import, approval, login, form entry, browser state, timing condition.

DevTools console, CDP, manually constructed messages → can prove primitive but NOT attacker delivery unless report separately proves how attacker causes equivalent input through normal reachable path.

## Stage 2: Fresh Live Reproduction

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

## Stage 3: Security Bug vs Business Behavior

Determine whether exposed action/data is intended public product behavior.

### Mandatory Business-Intent Research

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

## Stage 4: Triage Decision Gates

Work through all gates before assigning final severity:

### Gate 1: So-What Test
State the concrete attacker outcome. If you cannot state what an attacker gains without hedging, finding is below floor.

### Gate 2: Prerequisite Reachability
Every required precondition demonstrated against live target. No "assuming attacker has X."

### Gate 3: Delivery Path Verification
Complete attacker path from zero (or only their own normal account) demonstrated end-to-end.

### Gate 4: Impact Accuracy
Is claimed severity supported by proven impact? Do not upgrade from new angles discovered here. Do downgrade unsupported claims.

### Gate 5: Classification Accuracy
Select exact platform taxonomy leaf (Bugcrowd VRT or HackerOne weakness). For Bugcrowd: P1-P5 priority from scored leaf is authoritative for severity. For `priority: null` leaf: use concrete proven impact with explicit rationale.

### Gate 6: Format Compliance
Report follows report-format.md exactly: fastest-proof block first, Prerequisites second, correct section headings, no em dashes, correct screenshot references.

### Gate 7: Screenshot Completeness
No `![SCREENSHOT NEEDED: ...]()` placeholders remain. Every screenshot referenced exists as genuine capture. P09 re-captures anything whose command it corrects.

## Verdict: PASS

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

## Verdict: REJECTED

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

## Verdict: NEEDS-EVIDENCE

Set finding `.dscolor` to `orange`. Keep in active dig root. Stop.

Use only when ONE concrete external delivery fact is temporarily unavailable. An unproven speculative delivery path is REJECTED, not NEEDS-EVIDENCE.

## P09-TRIAGE-GATE.md Record

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
