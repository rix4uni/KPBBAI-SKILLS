---
name: bb-closeout
description: Bug bounty Phase 3 closeout — coverage audit, missing report detection, Stage C chain confirmation, orphan exclusion, report SHA capture, and workspace cleanup. Run after the vulnerability sweep is complete.
sources:
  - bug-bounty-hunting-prompts/phases/phase-03-closeout.md
argument-hint: "<target_display>"
allowed-tools: Bash, Read, Write
---

# Bug Bounty Closeout (Phase 3)

Audit coverage completeness, confirm all chains, capture report digests, and prepare for triage handoff.

## Coverage Audit

Run the coverage matrix audit script to identify gaps:

```bash
python3 coverage_matrix.py \
  --target "$YOUR_TARGET_ROOT" \
  --matrix raw/endpoints.json \
  --reports reports/ \
  --output raw/coverage-audit.json
```

**Coverage matrix must show:**
- Every 47 test class has at least one verdict
- No endpoint class is marked `pending` without a blocker recorded
- All Stage B subagent verdicts are incorporated

## Missing Report Detection

Scan for findings that have evidence but no corresponding report:

```bash
# Check hunt/ files with CONFIRMED-CRITICAL or CONFIRMED status
grep -l "Status: CONFIRMED" "$YOUR_TARGET_ROOT/hunt/"*.md | while read f; do
  slug=$(basename "$f" .md)
  if ! ls "$YOUR_TARGET_ROOT/reports/REPORT-"*"-${slug}.md" 2>/dev/null; then
    echo "MISSING REPORT: $slug"
  fi
done
```

Stray findings from hunt/ logs that have no report must be either:
1. Written as a report (if confirmed medium+)
2. Recorded in SPINOFF-LEADS.md (if below floor or needs more work)

## Stage C Chain Confirmation

For every partial/candidate chain identified during Stage B:

1. Load chain evidence from `raw/leads.jsonl`
2. Confirm each edge end-to-end against live target
3. Prove complete attacker delivery path
4. Upgrade severity to chain's maximum demonstrated impact

**Chain Confirmation Checklist:**
- [ ] All intermediate steps confirmed live (not just hypothetical)
- [ ] Attacker delivery path proven without victim account control
- [ ] No step relies on "attacker already has X" without proof X is obtainable
- [ ] Chain impact stated as concrete attacker outcome

## Orphan Exclusion Categories

Findings that MUST NOT be included in final reports:

| Category | Exclusion Reason |
|----------|-----------------|
| `duplicate` | Same root cause, same fix as another report |
| `policy-excluded` | Program explicitly excludes this class |
| `third-party` | Affects a third-party provider, not in-scope asset |
| `parser-artifact` | False positive from automated scanner, no manual confirmation |
| `below-floor` | Low/Informational with no escalation path |

Move orphans to `NA-DISPROVED/` with reason recorded in DISPROVED.md.

## Report Validation

Each report in `reports/` must pass:

1. **Severity field** — bare uppercase word: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
2. **Impact field** — concrete attacker outcome (not "attacker can..."; state what actually happens)
3. **Reproduction** — numbered steps, starts from attacker starting state
4. **Prerequisites** — accounts, tools, timing windows
5. **Evidence** — real screenshots/responses, no fabricated output
6. **Provenance block** — `Found by`, phase, model, timestamp

## Report SHA Digest Capture

After all reports are finalized:

```bash
# Capture SHA256 for each report
for report in "$YOUR_TARGET_ROOT/reports/REPORT-"*.md; do
  sha256=$(sha256sum "$report" | cut -d' ' -f1)
  slug=$(basename "$report" .md)
  echo "$slug: $sha256" >> "$YOUR_TARGET_ROOT/raw/report-digests.txt"
done
```

SHA digests are used by later phases (Phase 7, Phase 10) to verify report integrity.

## CLOSEOUT.md Format

Write a closeout summary:

```markdown
# Closeout: <target_display>
Date: <ISO timestamp>

## Coverage Summary
- Total endpoints tested: N
- Coverage matrix rows completed: 47/47 (or N/47 with blockers listed)
- Blocked rows: <list with reasons>

## Reports
- CONFIRMED-CRITICAL: N (report slugs)
- CONFIRMED-HIGH: N
- CONFIRMED-MEDIUM: N
- Below floor / archived: N

## Chains
- Confirmed chains: <list>
- Partial chains in SPINOFF-LEADS.md: <list>

## Orphans Excluded
- <slug>: <reason>

## Blockers for Later Phases
- <blocker>: <what's needed>
```

## Browser Profile Release

Release all browser profiles acquired during Phases 0–3:

```bash
# Release all profiles with phase prefix
browser-profile-command release-prefix "$BROWSER_PREFIX"
```

## Handoff to Triage (Phase 6)

Phase 3 is complete and ready for triage when:
- [ ] `raw/coverage-audit.json` shows no unresolved `pending` rows
- [ ] All CONFIRMED medium+ findings have reports
- [ ] `reports/` contains only valid, format-passing reports
- [ ] `raw/report-digests.txt` exists with SHA256 for each report
- [ ] `CLOSEOUT.md` written with full summary
- [ ] All browser profiles released
- [ ] No orphaned hunt/ files without report or SPINOFF-LEADS entry

Phase 6 (triage) consumes the reports/ directory and routes each finding to DIG / CANDIDATE / NA / MERGED.
