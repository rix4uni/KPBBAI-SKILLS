---
name: iis
description: Validate IIS 8.3 short filename enumeration (Shortscan) results and separate real application files from ASP.NET/IIS defaults and soft-404 noise. Use when Shortscan output exists or the user asks to analyze IIS tilde / short-name findings, reconstruct original filenames from 8.3 names, validate candidate paths over HTTP, or build shortscan_ignore.txt. Covers parsing complete Shortscan output, framework-default filtering, confidence-scored name reconstruction, soft-404 baselines, safe validation, and the final classification report.
metadata:
  opencode/slash: "true"
---

# IIS Short Filename Enumeration Validation

Shortscan proves that an IIS server leaks 8.3 short names. It does **not** prove that an interesting file exists, and a `200 OK` does not prove a reconstructed name is real. Treat every short name as evidence, every reconstructed name as a hypothesis, and every validated URL as a separate claim.

Only test targets the user is authorized to assess. Validation is read-only: GET/HEAD only, no credentials, no uploads, no writes, no destructive payloads. If a check would change state, stop and mark INCONCLUSIVE.

## Artifacts

```bash
OUTDIR="./iis-validation/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"/{templates,bodies,headers}
```

Keep the raw scan untouched. Expected files:

| File | Purpose |
|---|---|
| `shortscan.original.txt` | untouched human output |
| `shortscan.jsonl` | optional JSON pass for parsing |
| `findings.tsv` | normalized per-file rows |
| `shortscan_ignore.txt` | global default filter (project root) |
| `validation.log` | URL, status, baseline delta, verdict |
| `report.md` | final report |

`shortscan_ignore.txt` lives in the project root, next to the report — never inside the target or tool directories.

## Phase 0 — Preconditions

```bash
command -v shortscan curl jq
shortscan --help >/dev/null
test -s httpx.txt || echo "MISSING httpx.txt"
```

Never re-run a scan the user already has; parse the existing output and use targeted requests. If asked to run it, preserve the original command:

```bash
cat httpx.txt \
  | sort -t'[' -k3,3nr \
  | grep -aE "IIS|IIS Windows Server|Microsoft-IIS|Windows Server" \
  | awk '{print $1}' \
  | shortscan | tee "$OUTDIR/shortscan.original.txt"
```

Do not alter the pipeline. Run it once and keep the output.

## Phase 1 — Parse complete output

Shortscan human output uses one row per discovered name:

```text
SHORTNAME            POSSIBLE?NAME                 /path/URL
```

`?` marks characters Shortscan could not determine. Use `--fullurl` when re-running a specific target if paths are truncated.

For machine parsing, re-run the same URLs with JSON (read-only, safe) or scan a small list:

```bash
printf '%s\n' "$TARGET" > "$OUTDIR/targets.txt"
shortscan -o json @"$OUTDIR/targets.txt" > "$OUTDIR/shortscan.jsonl"
```

For many targets, feed the same filtered URL list to the JSON pass instead of re-filtering by hand.

JSON records:

```json
{"type":"status","url":"...","server":"...","vulnerable":true}
{"type":"result","fullmatch":true,"baseurl":"...","shortfile":"WEB","shortext":".CON","shorttilde":"~1","partname":"WEB.CON?","fullname":"WEB.CONFIG"}
{"type":"statistics","requests":0,"retries":0,"sentbytes":0,"receivedbytes":0}
```

Normalize each finding:

```bash
jq -c 'select(.type=="result")' "$OUTDIR/shortscan.jsonl" \
  | jq -c '{url:.baseurl, short:(.shortfile + .shorttilde + .shortext),
            part:.partname, full:.fullname, fullmatch:.fullmatch}' \
  > "$OUTDIR/findings.normalized.jsonl"

jq -r '[.baseurl, (.shortfile + .shorttilde + .shortext), .partname, .fullname, (.fullmatch|tostring)] | @tsv' \
  "$OUTDIR/shortscan.jsonl" | sort -u > "$OUTDIR/findings.tsv"
```

Fields to record per result: URL, short filename, possible/partial name, extension, whether it is a directory, whether Shortscan reconstructed the full name (`fullmatch`/`fullname`), whether the original is unknown (`?` remaining), and whether it is a known default.

Deduplicate identical `(host, shortname, path)` rows. Group by host, then by directory.

## Phase 2 — Remove known defaults

Always ignore these ASP.NET/IIS framework resources and every nested occurrence:

```text
ASPNET_CLIENT
SYSTEM_WEB
2_0_50~1
4_0_30~1
```

Example: `/ASPNET_CLIENT/`, `/ASPNET_CLIENT/SYSTEM_WEB/`, `/ASPNET_CLIENT/SYSTEM_WEB/2_0_50~1`, `/ASPNET_CLIENT/SYSTEM_WEB/4_0_30~1` are all default framework content.

Treat other obvious framework/default resources as low value unless the response exposes application-specific content: `_VTI_*` (FrontPage/SharePoint metadata), `BIN`, `APP_CODE`, `APP_DATA`, `APP_BROWSERS`, `APP_GLOBALRESOURCES`, `APP_LOCALRESOURCES`, `APP_THEMES`, `APP_WEBREFERENCES`, `IISSTART`, `WELCOME`, `PRINTING`, `SCRIPTS`, `IMAGES` (when purely static), `FAVICON`, `GLOBAL~1.ASA` **only if** it is the compiled ASP.NET global (no application evidence).

Rule: defaults are filtered by path/shape, not by a single substring. `/APP_DATA/` is default; `/APP_DATA_BACKUP/` is not automatically default.

Maintain the ignore file without destroying prior entries:

```bash
test -f shortscan_ignore.txt || printf '%s\n' ASPNET_CLIENT SYSTEM_WEB '2_0_50~1' '4_0_30~1' > shortscan_ignore.txt
```

Never add an application-specific name to this file just because it was uninteresting on one target.

## Phase 3 — What 8.3 actually tells you

Windows generates `PREFIX~N.EXT`:

- `PREFIX` is up to the first **6** valid characters of the long name (spaces and dots removed).
- `~N` is a collision/ordinal suffix, not part of the name.
- `EXT` is up to 3 characters, uppercased.

Consequences:

- `LOGIN~1.ASP` does **not** prove `LOGIN.ASPX`. It proves an 8.3 entry whose prefix begins `LOGIN` and whose extension begins `ASP`.
- A tilde can mean the long name is simply long **or** that two names collide. `LOGIN~1` may be `LOGINPAGE.ASPX`, or `LOGIN.ASPX` colliding with an existing `LOGIN.ASP`.
- `~2` means a second colliding name, not a second copy of the same file.
- Extensions are ambiguous:

| Short ext | Possible real extensions |
|---|---|
| `.ASP` | `.asp`, `.aspx`, `.ascx`, `.ashx`, `.asmx`, `.asax`, `.aspq` |
| `.HTM` | `.htm`, `.html`, `.xhtml` (rare) |
| `.CON` | `.config`, `.conf` |
| `.MAS` | `.master` |
| `.ASA` | `.asa`, `.asax` |
| `.TXT` | `.txt` |
| `.JPG` | `.jpg`, `.jpeg` |
| `.ZIP` | `.zip` |

- Directories have no extension (e.g. `ADMIN~1`). IIS is case-insensitive, so case in a candidate is cosmetic.

Only Shortscan's `fullmatch=true` / non-empty `fullname` is a **reconstruction**, and even that is a hypothesis until HTTP validation.

## Phase 4 — Reconstruct candidates and score them

Generate a small, ranked candidate set per short name. Do not fabricate a single name and present it as fact.

```text
SHOWRE~1.ASP  -> SHOWREPORT.ASPX (prefix match, app naming)
              -> SHOWREPORTS.ASPX
              -> SHOWRESULTS.ASP  (only if directory context supports it)
LOGIN~1.ASP   -> LOGIN.ASPX
              -> LOGINPAGE.ASPX
DEFAUL~1.ASP  -> DEFAULT.ASPX
```

Confidence rubric:

| Confidence | Criteria |
|---|---|
| **HIGH** | Shortscan `fullname` complete (no `?`) **and** HTTP validation shows a distinct response vs. baseline; or the partial name is fully determined and validated. |
| **MEDIUM** | Shortscan partial has ≤1 unknown character; prefix + extension fit common app conventions; directory siblings support it; response is distinct but not definitive. |
| **LOW** | Generic `~1` with several plausible long names; extension ambiguous; no distinct HTTP evidence. Prefer INCONCLUSIVE over asserting. |

Do not raise confidence from plausibility alone. A convincing word (`ADMIN`, `BACKUP`, `CONFIG`) is prioritization, not proof.

## Phase 5 — Safe HTTP validation

For each interesting candidate, request the exact path with a normal, unauthenticated GET (HEAD only as a supplementary check):

```bash
BASE="http://host:port"          # scheme exactly as scanned
CAND="$BASE/SHOWREPORT.ASPX"
curl -sS --max-time 15 -D "$OUTDIR/headers/cand.hdr" -o "$OUTDIR/bodies/cand.body" \
  -w 'status=%{http_code} size=%{size_download} type=%{content_type} redirect=%{redirect_url}\n' "$CAND"
```

Check: status, redirect target, `Content-Type`, `Content-Length`, title, body, whether it differs from the site's 404, and whether it looks like a real application endpoint.

A `200` alone is **not** confirmation. Do not send credentials, do not POST, do not upload, do not run commands. If a path only reveals itself after auth, record INCONCLUSIVE.

## Phase 6 — Soft-404 baseline (mandatory)

Before trusting any candidate, establish how the app handles nonexistent paths — including per-directory behavior:

```bash
RAND="nx-$(date +%s)-$RANDOM"
curl -sS --max-time 15 -o "$OUTDIR/bodies/control.body" -D "$OUTDIR/headers/control.hdr" \
  -w 'CONTROL status=%{http_code} size=%{size_download} type=%{content_type}\n' \
  "$BASE/$RAND"

# same-directory control for nested candidates
curl -sS --max-time 15 -o "$OUTDIR/bodies/control-dir.body" \
  "$BASE/SOMEDIR/$RAND"
```

Normalize volatile content before comparing (dates, request IDs, CSRF tokens, ad/analytics blocks):

```bash
norm() { tr -d '\r' < "$1" | sed -E 's/[0-9a-f]{16,}/<HEX>/g; s/[0-9]{2}:[0-9]{2}:[0-9]{2}/<TIME>/g'; }
sha256sum <(norm "$OUTDIR/bodies/control.body") <(norm "$OUTDIR/bodies/cand.body")
```

Verdict rules:

- Candidate status/size/title/body hash ≈ control → **soft-404**, not confirmation.
- Control `404` + candidate `200` with distinct body/title/type → strong evidence.
- Control `200` (custom error) + candidate `200` with clearly larger/different body and a real page title → medium evidence; corroborate with a second candidate or a directory listing.
- Candidate redirects to `/login`, `/error`, or the home page → not evidence of the file; record as such.
- Candidate returns `403`/`401` → the resource may exist but access is denied: INCONCLUSIVE, not CONFIRMED.
- IIS may return `404` with a custom body, or `200` with an error page. Always compare content, not just status.

Log every check:

```bash
printf '%s\t%s\t%s\t%s\t%s\n' "$SHORT" "$CAND" "$STATUS" "$SIZE" "$VERDICT" >> "$OUTDIR/validation.log"
```

## Phase 7 — Directory structure

Shortscan may recurse into discovered directories. Ignore the default hierarchy from Phase 2. For non-default directories:

- Request the directory with and without a trailing slash.
- Compare against a same-directory control path.
- If the directory is browseable, a listing is strong corroboration for filenames inside it.
- If `/SOMETHING~1/` resolves to a real application area, validate its children separately; do not infer child names from the parent.

## Phase 8 — Classify every result

Exactly one label per finding:

1. **DEFAULT / IGNORE** — known framework/default resource.
2. **SHORT-NAME DETECTED** — enumeration worked; the original name is unresolved (`?` remains).
3. **LIKELY APPLICATION FILE** — strong contextual evidence (naming, siblings, distinct response) but not fully validated.
4. **CONFIRMED FILE** — reconstructed name/path independently validated against the soft-404 baseline.
5. **INCONCLUSIVE** — insufficient evidence, blocked, auth-gated, or unstable responses.
6. **FALSE POSITIVE** — explained by defaults, soft-404, WAF/error page, or a non-interesting condition.

Global suppression applies only to default/framework patterns. Never suppress an application-specific name because one target's validation failed.

## Phase 9 — Prioritize interesting functionality

High-signal words: `LOGIN`, `SIGNOUT`, `SIGNOU`, `AUTH`, `ADMIN`, `REPORT(S)`, `PATIENT`, `USER`, `ACCOUNT`, `PASSWORD`, `CONFIG`, `UPLOAD`, `DOWNLOAD`, `BACKUP`, `API`, `DEBUG`, `TEST`, `DATABASE`, `GLOBAL`, `PAYMENT`, `RECEIPT`, `RESULT`, `CHANGE`, `SEARCH`, `EXPORT`, `IMPORT`, `PROFILE`, `SETTINGS`.

These words only set review order. They do not imply vulnerability, and a match is not proof the file exists.

## Phase 10 — Global default filter

`shortscan_ignore.txt` starts with the four mandatory defaults. Add a pattern only when it is clearly standard framework/default content across targets. Never add `LOGIN`, `REPORT`, `ADMIN`, or any app-specific stem because one host returned a soft-404. Keep patterns uppercase, one per line, `sort -u` on update:

```bash
sort -u -o shortscan_ignore.txt shortscan_ignore.txt
```

## Phase 11 — Final report

Write `report.md`:

```text
==================================================
IIS SHORTSCAN VALIDATION
==================================================

Target:
<target>

URLs scanned:
<X>

Shortscan findings:
<X>

Ignored default/framework findings:
<X>

Potential application-specific findings:
<X>

Confirmed filenames:
<X>

Inconclusive:
<X>

--------------------------------------------------
IGNORED DEFAULTS
--------------------------------------------------

ASPNET_CLIENT
SYSTEM_WEB
2_0_50~1
4_0_30~1

--------------------------------------------------
INTERESTING FINDINGS
--------------------------------------------------

Short Name:
SHOWRE~1.ASP

Possible Name:
SHOWREPORT.ASPX

Confidence:
HIGH

URL:
https://example.com/SHOWREPORT.ASPX

Validation:
Confirmed / Likely / Inconclusive / False Positive

Evidence:
<short-name derivation, soft-404 comparison, status/size/title/content-type>

--------------------------------------------------
```

Include a separate INCONCLUSIVE section listing each unresolved short name, what blocked validation, and what would resolve it. End the chat reply with the confirmed/likely list and the exact global ignore patterns.

## Rules

1. Never trust "Vulnerable: Yes!" as a file finding.
2. Never treat an AI-generated filename as confirmed without HTTP validation.
3. Never conflate an 8.3 short name with the original filename.
4. Always establish and compare against a nonexistent-path baseline, including per-directory baselines.
5. Ignore the listed ASP.NET/IIS defaults and nested variants.
6. Do not report framework files as application findings.
7. Preserve the original Shortscan output; never modify the target.
8. Perform no destructive testing, credential submission, or data modification.
9. Clearly separate: detected short name → guessed filename → validated filename.
10. If the original name cannot be determined reliably, say so and use INCONCLUSIVE.
11. Do not fabricate filenames to make a report look complete.
