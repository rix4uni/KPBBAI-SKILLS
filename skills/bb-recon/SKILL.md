---
name: bb-recon
description: Bug bounty Phase 0 recon — live host discovery, shallow browser map, JS download, operation-candidates seeding. Use at the start of any bug bounty engagement before access setup or vulnerability testing.
sources:
  - bug-bounty-hunting-prompts/phases/phase-00-recon.md
argument-hint: "<target_display> <scope_wildcard_or_host>"
allowed-tools: Bash, Read, Write, WebFetch
---

# Bug Bounty Recon (Phase 0)

Seed the target workspace with live hosts, a shallow route map, JS files, and an operation-candidates ledger before any vulnerability testing begins.

## Workspace Initialization

```bash
YOUR_TARGET_ROOT="$YOUR_WORKSPACE_ROOT/<target_norm>"
mkdir -p "$YOUR_TARGET_ROOT/raw"/{browser,evidence,requests,responses,payloads,scripts}
mkdir -p "$YOUR_TARGET_ROOT/hunt" "$YOUR_TARGET_ROOT/reports" "$YOUR_TARGET_ROOT/sensitive"
```

## Step 1: Live Host Discovery

Enumerate subdomains and filter to live HTTP(S) hosts. Cap at 200 wildcard scope hosts, 10 live hosts per wildcard scope entry.

```bash
# Subdomain enumeration (subfinder or equivalent)
subfinder -d <apex_domain> -silent | \
  httpx -silent -status-code -title -tech-detect \
  -o "$YOUR_TARGET_ROOT/raw/scope-hosts.txt"

# Limit to 200 hosts per wildcard apex, 10 per sub-scope
# Output: scope-hosts.txt  (one live URL per line)
```

**Output:** `raw/scope-hosts.txt` — operational host list used by all later phases.

## Step 2: Functional Sibling Classification

For each live host, classify its role relative to the primary target:

```
raw/functional-sibling-hosts.tsv
Columns: host | role | confidence | evidence
Roles: auth | api | account-mgmt | billing | cdn | static | admin | staging | unknown
```

Evidence-backed first-party functional siblings (auth, account, API, billing hosts) are **in-scope surface** even when not explicitly named in the program scope, unless explicitly excluded.

## Step 3: Shallow Browser Map (3–6 Routes)

Drive a headless or CDP browser. For each live in-scope host, map 3–6 unique routes:

```
raw/recon-shapes.txt
Format: METHOD URL content_type auth_required notes
```

Goals:
- Identify app framework, auth scheme, API style (REST / GraphQL / gRPC)
- Surface upload endpoints, OAuth/SAML flows, integrations
- Note high-value surfaces: file upload, payment, admin, settings, webhooks

## Step 4: JS File Download (up to 20 per host)

```bash
# Download JS bundles for secret/API key/route extraction
grep -E '\.js($|\?)' "$YOUR_TARGET_ROOT/raw/recon-shapes.txt" | \
  head -20 | while read url; do
    wget -q -P "$YOUR_TARGET_ROOT/raw/js/" "$url"
  done
```

Scan for:
- Hardcoded API keys, tokens, secrets
- Internal endpoints not visible in UI
- Source maps revealing original file structure

## Step 5: Threat Model & Operation Candidates

Seed `raw/threat-model.json` and `raw/operation-candidates.jsonl`:

```json
// threat-model.json skeleton
{
  "target": "<target_display>",
  "auth_schemes": [],
  "trust_boundaries": [],
  "high_value_surfaces": [],
  "attacker_states": ["unauth", "authenticated_user", "authenticated_admin"],
  "scope_notes": ""
}
```

```jsonl
// operation-candidates.jsonl — one line per interesting operation
{"route": "/api/users", "method": "GET", "auth": true, "class": ["idor", "unauth-access"], "priority": "high"}
```

## Output Artifacts

| File | Purpose |
|------|---------|
| `raw/scope-hosts.txt` | Live in-scope host list (all later phases read this) |
| `raw/functional-sibling-hosts.tsv` | Host role classification |
| `raw/recon-shapes.txt` | Shallow route map |
| `raw/js/` | Downloaded JS bundles |
| `raw/threat-model.json` | Attack surface model |
| `raw/operation-candidates.jsonl` | High-value operation seeds |
| `raw/api-contract-candidates.jsonl` | API contract hints |

## UNAUTH Lane — No-Account Findings

Even before account setup (Phase 1), recon can directly yield critical findings. Prioritize:

1. **Secrets in JS bundles** — API keys, tokens, internal URLs
2. **Exposed unauthenticated services** — `.git`, `.env`, backup files, admin panels
3. **Unauthenticated API / BOLA** — public endpoints returning private data
4. **Auth bypass on pre-auth endpoints** — registration, password reset, OAuth callback
5. **CI/supply chain** — exposed CI configs, dependency confusion vectors

## Finish Criteria

Phase 0 is complete when:
- `raw/scope-hosts.txt` has at least 1 live host
- `raw/recon-shapes.txt` has at least 3 routes
- `raw/threat-model.json` exists
- `raw/operation-candidates.jsonl` has at least 5 entries
