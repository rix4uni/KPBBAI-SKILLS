---
name: bb-validate
description: Bug bounty Phase 7+8+8a validation — orchestrator spawns up to 6 concurrent subagents to validate DIG/CANDIDATE findings, run escalation, capture screenshots, and produce submission-ready v2 reports. Also covers Phase 8a independent pre-gate escalation.
sources:
  - bug-bounty-hunting-prompts/phases/phase-07-validate-escalate.md
  - bug-bounty-hunting-prompts/phases/phase-08-verify-escalate.md
  - bug-bounty-hunting-prompts/phases/phase-08a-independent-escalation.md
argument-hint: "<target_display> <dig_tree_path>"
allowed-tools: Bash, Read, Write, WebFetch
---

# Bug Bounty Validation & Escalation (Phases 7 + 8 + 8a)

Validate every DIG and CANDIDATE finding from triage, escalate to maximum demonstrable impact, and produce submission-ready v2 reports.

## Orchestrator Role

Enumerate the dig tree. Spawn up to 6 concurrent subagents. Each owns ONE finding end-to-end. Collect verdicts: PROVEN / DISPROVEN / BLOCKED.

```bash
# Enumerate findings
ls "$YOUR_DIG_ROOT/"
# Each <SEVERITY>-<slug>/ folder with v1/ report = one unit of work
# Skip: v2/ exists (done), .dscolor = green/orange/red, NA-DISPROVED/ folder
```

## Finding Color States

| Color | Meaning | Phase Ownership |
|-------|---------|----------------|
| uncolored/blue/purple | Eligible for work | — |
| orange | In-progress P07 worker claim | P07 |
| blue | P07 validated, ready for P08 | P07 sets after PROVEN |
| green | P08 independently verified | P08 owns |
| red | Disproved / below floor / no-repro | Terminal |

**P07 never writes green.** Only P08 writes green after independent verification.

## Dispatch: Account-Aware Scheduling

Before dispatch, inventory ALL usable accounts in `sensitive/`:

```
Unauthenticated findings → run freely alongside anything (no account)
Authenticated read-only/IDOR → share accounts, each sub-agent on own profile
Account-MUTATING findings → never run two mutating same account concurrently
```

IDOR/cross-tenant findings need TWO accounts at once (attacker + victim pair).

## Sub-Agent Brief (One Finding)

Each subagent receives:
- finding folder path, v1 report path
- triage decision (DIG or CANDIDATE)
- platform, report format path, classification catalog path
- sensitive/ path
- assigned account(s) for mutation work

### Sub-Agent Step 1: Read v1 Report Fully

Understand claimed bug, root cause, claimed impact, triage decision. For CANDIDATE, extract: proven primitive, unresolved prerequisite, prerequisite-first tests, disproof stop condition.

### Sub-Agent Step 2: Acquire Browser/Account

```bash
FIND_DIR="<assigned finding folder>"
FINDING_NAME=$(basename "$FIND_DIR")
LEASE_PREFIX="${YOUR_LEASE_OWNER_PREFIX}:${YOUR_LEASE_CYCLE}:${FINDING_NAME}:"
# Acquire profile with finding-scoped owner
python3 browser-lease.py acquire --owner "${LEASE_PREFIX}browser-a" --role escalate
```

**Need more accounts?** Self-register additional accounts (catch-all domain) rather than flagging BLOCKED. Save credentials immediately to sensitive/ under reserved label.

### CANDIDATE Prerequisite-First Gate (Step 2a)

For CANDIDATE findings:
1. Work ONLY on the named unresolved prerequisite first
2. Test the specific P06 prerequisite-first sources
3. If prerequisite becomes REACHABLE → enter normal Steps 3–5
4. If disproof stop condition met → write DISPROVED.md, move to NA-DISPROVED/
5. Do NOT run general escalation until prerequisite is resolved

### Credential Validation Gate (Step 2b)

For exposed credential findings:
- Cannot become PROVEN without liveness evidence + negative control
- Record: `Credential liveness: CONFIRMED | INVALID | BLOCKED`
- After liveness, escalate authority under bounded non-destructive standard

### Step 3: Prove It (Genuine Captures Only)

Reproduce the bug against live target. Capture screenshots as you prove it.

**Genuine capture only — never synthesized.** Every image must be a screengrab of a real window showing real output.

```bash
# Terminal capture
your-terminal-capture "<command>" <finding>/v2/screenshots/NN-name.png

# Browser/DevTools capture  
your-browser-capture <profile-N> <out.png> [--devtools]
```

Save ALL raw evidence to `<finding>/v1/evidence/`, genuine screenshots to `<finding>/v2/screenshots/`.

### Step 4: Escalate Every Non-Destructive Angle

Before brainstorming, load knowledge base:
- `hunt-examples-INDEX.md` — historical patterns that actually paid
- `ref-<class>-techniques.md` — per-class technique catalog (ssrf, auth, access-control, graphql, injection, file-upload, exposed-secrets, etc.)

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

**Spin-off leads** — if you notice a different bug while testing: capture it and hand to orchestrator. Do NOT chase it; stay on assigned finding.

### Step 5: Decide

**Prerequisite Ledger (mandatory before PROVEN):**

| Prerequisite | Attacker Capability | Acquisition Step | Evidence | Result |
|-------------|--------------------|--------------------|---------|--------|
| victim UUID | normal account | /api/users list | raw/api-users.json | REACHABLE |
| victim session | — | — | — | NOT REACHABLE |

**Owned-Test-Account Trap (mandatory for IDOR/cross-tenant findings):**

A real attacker controls only their own account. You must prove BOTH:
1. **Authz broken (mechanic):** A can reach B's resource given its identifier (owning both accounts proves this)
2. **Identifier obtainable (delivery):** An attacker with only their own account can learn a victim's identifier

If victim identifier is UUIDv4/v5 with no leak found → NOT REACHABLE → DISPROVEN.

Reading victim's ID from Account B's session is NOT a delivery path.

**Delivery Path Requirements for Common Classes:**

- **XSS** — must prove reflected/stored sink reachable via attacker-controlled URL or stored input
- **IDOR** — must prove victim identifier is obtainable without victim credential control
- **CSRF** — must prove token is absent/predictable or state is bypassable cross-origin
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
- Target 500–1000 words total; hard max 1500
- No em dashes anywhere
- ≤6 public screenshots by default (7–10 only with multi-stage justification)
- Current Chrome 154 User-Agent in every command
- Never "fixture" or "fixtures" in public prose

**report-manual.md requirements (INTERNAL, never submitted):**
- Zero assumptions from cold machine state
- Real email/password pasted inline from sensitive/ (it's private)
- Every step numbered, exact commands, every screenshot named
- Must be fully reproducible by P08/P09 without any unstated knowledge

**v2/ESCALATION-LOG.md must include:**
- `## Origin provenance` (copied verbatim from v1)
- v1 original severity and classification
- Prerequisite ledger with evidence paths and reachability verdicts
- Each escalation angle with result
- `## Counterevidence` (strongest benign explanation + control checked + result)

## Handling Spin-Off Leads

Triage each lead returned by a subagent:
1. Filter out-of-scope or duplicate leads
2. Pressure-test severity ("so what?" — concrete attacker gain?)
3. Dispatch plausible Medium+ leads immediately
4. File resource-gated leads in SPINOFF-LEADS.md
5. File below-floor leads in SPINOFF-LEADS.md
6. Recursion bound: leads from spin-off-spawned agents are always filed, never auto-dispatched

**SSRF kill rule:** When SSRF escalation disproves internal reach (no internal response read, no oracle, no protocol smuggling), flip to DISPROVED External-only. Do not reframe as Medium.

## Phase 7 Summary (Orchestrator)

When all subagents finish, produce a table:

| Finding | Verdict | Proven Severity | v2 Path / Block Reason | Color |
|---------|---------|----------------|----------------------|-------|
| HIGH-csrf-on-payment | PROVEN | HIGH | v2/report.md | blue for P08 |
| MEDIUM-ssrf-webhook | DISPROVEN | — | DISPROVED.md: external-only | red |

Submission floor is Medium. Write blue for every Medium+ PROVEN finding. Write red for Low/Informational.

## Phase 8a: Independent Pre-Gate Escalation

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
  "tested_angles": [...],
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
