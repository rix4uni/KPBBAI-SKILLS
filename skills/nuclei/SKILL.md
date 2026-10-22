---
name: nuclei
description: Validate Nuclei findings and eliminate false positives before the user treats them as real vulnerabilities. Use when a Nuclei scan output exists and needs triage, when results must be split into CONFIRMED, TARGET-SPECIFIC FALSE POSITIVE, and TEMPLATE-LEVEL FALSE POSITIVE, when a template's matcher logic must be audited, or when building a global template ignore list (false_positive_templates.txt). Covers running/parsing Nuclei JSONL output, locating and reading the actual YAML template, judging what the matcher really proves, safe re-testing of suspicious findings, and the final validation report.
metadata:
  opencode/slash: "true"
---

# Nuclei False-Positive Validation

Validate Nuclei results against the actual HTTP responses and the actual YAML templates. A Nuclei match is a hypothesis, not a finding.

Core rule: **never globally suppress a template because one target failed validation.** Distinguish template-level unreliability from target-specific mismatch.

Only test targets the user is authorized to test. Validation is read-only and non-destructive: no shells, no file writes, no data modification, no brute force, no exploitation beyond a benign proof of the template's own claim. If a check would be destructive, stop and mark INCONCLUSIVE.

## Artifacts

Create a working directory per run and never modify the original scan output or `~/nuclei-templates`:

```bash
OUTDIR="./nuclei-validation/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
cp scan.txt "$OUTDIR/scan.original.txt"   # original stays untouched
```

Expected files:

| File | Purpose |
|---|---|
| `scan.original.txt` | untouched raw scan output |
| `scan.jsonl` | machine-parseable findings |
| `groups.txt` | findings grouped by template ID |
| `templates/` | copies of read templates (never edit originals) |
| `validation.log` | request/response evidence per check |
| `false_positive_templates.txt` | global ignore list (project root, not inside nuclei-templates) |
| `report.md` | final report |

## Phase 0 — Preconditions

```bash
command -v nuclei jq curl
nuclei -version
ls -d ~/nuclei-templates || echo "MISSING: run nuclei -update-templates"
```

If the user already has results, do not re-run the full scan; parse the existing output and use targeted re-tests. If asked to run the scan itself, add machine-readable output while keeping the original command's scope:

```bash
nuclei -duc -silent -severity critical,high,medium \
  -tags "cve2026,cve2025,cve2024,cve2023,cve2022,cve2021,cve2020,cve2019,cve2018,default-login,apache,joomla,kubernetes,vmware,atlassian,phpinfo,springboot,spring,struts,tomcat,weblogic,jboss,activemq,elasticsearch,swagger,graphql,gitlab,jenkins,grafana,confluence,jira,nginx,laravel,drupal,magento,thinkphp,phpmyadmin,fortinet,fortios,fortigate,ivanti,citrix,sonicwall,paloaltonetworks,zimbra,sharepoint,react,php,flask,django,codeigniter,symfony,springcloud" \
  -l targets.txt -jsonl -o "$OUTDIR/scan.jsonl" | tee "$OUTDIR/scan.original.txt"
```

Do not add `-irr` to the primary scan. Use it only for targeted re-tests, because it records full requests/responses.

## Phase 1 — Run and parse

Parse every result into: template ID, severity, protocol/type, target host, matched URL/path, matcher name, extracted values, and any other metadata.

```bash
jq -c '{id:."template-id", sev:.info.severity, proto:.type, host:.host,
        matched:."matched-at", matcher:."matcher-name",
        extracted:."extracted-results", ts:timestamp,
        ip:ip, port:port, scheme:scheme, url:url}' "$OUTDIR/scan.jsonl" \
  > "$OUTDIR/findings.normalized.jsonl"
```

Group by template ID, keeping every target (never collapse duplicates silently):

```bash
jq -r '."template-id"' "$OUTDIR/scan.jsonl" | sort | uniq -c | sort -rn > "$OUTDIR/template-counts.txt"

jq -r '[."template-id", ."matched-at"] | @tsv' "$OUTDIR/scan.jsonl" \
  | sort -k1,1 > "$OUTDIR/groups.tsv"
```

Present the grouping, for example:

```text
CVE-2012-1823
    http://target1:3187/index.php
    http://target2/index.php
CVE-2024-23897
    http://target3:8080
```

Deduplicate template work: **analyze each unique template ID once**. Do not re-derive matcher logic per target.

## Phase 2 — Locate the template

```bash
TID='CVE-2012-1823'
TPATH=$(find ~/nuclei-templates -type f -iname "*${TID}*.yaml" -print -quit)
echo "$TPATH"
cp "$TPATH" "$OUTDIR/templates/"
```

Read the **complete** file. If multiple templates share a name fragment, confirm the `id:` field matches the finding's template ID; if not, keep searching:

```bash
grep -rl "^id: ${TID}$" ~/nuclei-templates --include='*.yaml' | head
```

Record for each template: `id`, `info` (name, author, severity, description, reference, tags, classification/CVE/CWE), affected products, and every request field (method, path, query, headers, body, payloads, variables, DSL), plus matchers, matcher-condition, negative matchers, extractors, redirect behavior, protocol, version-detection logic, and response conditions.

## Phase 3 — What does the matcher actually prove?

Answer these before validating any target:

1. Does it only detect that a URL/path exists?
2. Does it only detect a version string or banner?
3. Does it require a specific response body, header, or status?
4. Does it check the version is actually in the vulnerable range?
5. Does it send a vulnerability-specific request, or a generic one?
6. Does the match prove exploitability, or merely a possible condition?
7. Is the matcher too broad (single keyword, generic error, 200-only, `contains` on a common word)?
8. Could a healthy/unrelated app return the same response?
9. Is a negative matcher missing (e.g. no `!contains` for the patched banner, no `!status` for a login redirect)?
10. Would a WAF, reverse proxy, or default page satisfy it?

Common unreliable patterns to flag:

- Matcher is a generic word (`"Index of /"`, `"phpinfo"`, `"Jenkins"`, `"Apache"`) without product-specific context.
- Status-code-only matcher, or `contains: "200"` against a reflective page.
- Version parsed from a header/banner with no range check, or checked with a broken regex.
- Payload reflected back in an error page or 404 body and matched as proof of execution.
- Soft-404: every path returns 200 with the same template.
- Detects a panel/login page and calls it an unauthenticated vuln.
- CVE template that only fingerprints the product version, without the CVE-specific request/response.
- Multi-matcher template where `condition: or` lets a trivial fingerprint satisfy the whole check.
- Template expects a distinctive string that is also in the product's public docs/default error output.
- Extracted value treated as proof (a version string is not a vulnerability).

## Phase 4 — Validate targets

Pick representative targets per template (at minimum: the first, the one with the oddest response, and any target whose result looks suspicious). Send safe requests that reproduce what the template sent.

```bash
TARGET='http://host:port/path'
curl -sS -k --max-time 15 -D "$OUTDIR/hdr.txt" -o "$OUTDIR/body.txt" "$TARGET"
head -20 "$OUTDIR/hdr.txt"; head -60 "$OUTDIR/body.txt"
```

Only use `-k` when the scan itself was HTTPS/TLS-broken; note it in the log. Use `-L` only if the template follows redirects, and log the chain (`-w '%{url_effective} %{http_code}\n'`) so a login redirect is not mistaken for a hit.

For POST/JSON/header-based templates, replay the exact method, path, headers, and body from the YAML — nothing more. Compare:

- status code vs. what the matcher requires;
- body/header evidence vs. the exact matcher strings;
- version/product vs. the vulnerable range;
- negative conditions (is the patched behavior present?);
- whether a benign sanity check shows the claimed behavior is real (e.g. a read-only endpoint returning expected data).

Also test a **control**: a path that should not match. If the control matches too, the matcher is too broad.

Log each check:

```bash
printf '%s\t%s\t%s\t%s\n' "$TID" "$TARGET" "$STATUS" "$VERDICT" >> "$OUTDIR/validation.log"
```

Verdicts:

- **CONFIRMED** — strong evidence the target satisfies the template's vulnerability condition (vulnerable version **and** the CVE-specific response, or a benign exploit proof with the expected unique output).
- **FALSE POSITIVE** — matcher fires but the vulnerability condition is not met.
- **INCONCLUSIVE** — insufficient evidence, blocked response, auth required, or unsafe to test.

## Phase 5 — Classify template-level vs target-level

**A) TEMPLATE_FALSE_POSITIVE** — the detection logic itself is unreliable: it matches unrelated software, relies on a generic keyword/banner/status, lacks a version or negative condition, or cannot distinguish vulnerable from patched. Prove this with at least two independent signals, e.g. the same matcher firing on a control/healthy target, or the YAML containing no CVE-specific check. Then all findings from that template are suppressed.

**B) TARGET_SPECIFIC_FALSE_POSITIVE** — template is sound (specific request + specific evidence), but this target is not vulnerable (wrong version, patched, different product, decoy page). Discard only that target; keep the template active.

Gray area: if the template is sound but the run produced only ambiguous results on many targets, classify findings INCONCLUSIVE, not template-level.

## Phase 6 — Global suppression

Only after Phase 5 evidence, append template IDs (never paths) to the ignore file:

```bash
printf '%s\n' "$TID" >> false_positive_templates.txt
sort -u -o false_positive_templates.txt false_positive_templates.txt
```

Then filter the final report:

```bash
grep -v -F -f false_positive_templates.txt "$OUTDIR/template-counts.txt"
jq -c --rawfile ignore false_positive_templates.txt \
  'select(."template-id" as $id | ($ignore | split("\n") | index($id) | not))' \
  "$OUTDIR/findings.normalized.jsonl" > "$OUTDIR/findings.suppressed.jsonl"
```

Requirements before adding an ID:

- The template was read in full.
- The flaw is in the matcher/request logic, not one target's state.
- Evidence is recorded in `validation.log` / `report.md`.
- The ID is not added merely because a target was unreachable.

Do not edit, move, or delete anything under `~/nuclei-templates`.

## Phase 7 — Re-test suspicious findings

Reproduce with the exact template and inspect what matched:

```bash
nuclei -u "$TARGET" -t "$TPATH" -silent -jsonl -irr -o "$OUTDIR/retest.jsonl"
jq '{matched:."matched-at", matcher:."matcher-name", extracted:."extracted-results",
     req:.request, res:.response}' "$OUTDIR/retest.jsonl"
```

Determine, in order: (1) exact request sent, (2) exact response received, (3) which matcher was true, (4) why it was true, (5) whether that condition demonstrates the vulnerability. Cross-check `-debug` output only if needed. Do not trust `extracted-results` as proof.

## Phase 8 — Output

Write `report.md` in exactly this shape:

```text
==================================================
NUCLEI VALIDATION SUMMARY
==================================================

Templates analyzed: X

Confirmed findings: X
Target-specific false positives: X
Template-level false positives: X
Inconclusive findings: X

--------------------------------------------------
CONFIRMED
--------------------------------------------------

[TEMPLATE]
TARGET
REASON

--------------------------------------------------
TARGET-SPECIFIC FALSE POSITIVES
--------------------------------------------------

[TEMPLATE]
TARGET
WHY IT IS FALSE POSITIVE

--------------------------------------------------
TEMPLATE-LEVEL FALSE POSITIVES
--------------------------------------------------

[TEMPLATE]
TEMPLATE PATH
WHY THE TEMPLATE IS UNRELIABLE
WHAT MATCHER CAUSED THE FALSE POSITIVE

--------------------------------------------------
GLOBAL IGNORE LIST
--------------------------------------------------

CVE-XXXX-XXXX
CVE-YYYY-YYYY
```

Include INCONCLUSIVE entries (target, what blocked validation, what would resolve it). End the chat reply with the exact list of template IDs to ignore globally and a one-line reason for each.

## Rules

- Never assume a result is correct because Nuclei reported it.
- Read the YAML before deciding; never judge by filename or ID alone.
- Validate against the real response, not the template's description.
- Never mark CONFIRMED from a banner, version string, or generic keyword alone.
- Never globally suppress on a single failed target.
- Prefer INCONCLUSIVE over guessing.
- Keep the original scan output and `~/nuclei-templates` untouched.
- Keep `false_positive_templates.txt` separate from scan artifacts.
- Stay within authorized scope; perform no destructive exploitation.
