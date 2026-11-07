---
name: recon-workflow
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

---

## From hack-skills: API Recon & Documentation Discovery

### JS Mining for Endpoints
```bash
# Download and extract endpoints from JS bundles
gau target.com | grep "\.js$" | sort -u > js-urls.txt
waybackurls target.com | grep "\.js$" >> js-urls.txt
cat js-urls.txt | xargs -I{} curl -s {} | grep -Eo '["'\''`][/][a-zA-Z0-9_/-]+["'\''`]' | sort -u
# or use LinkFinder:
python3 linkfinder.py -i https://target.com/app.js -o cli
```

### Common API Documentation Paths
```
/swagger.json            /swagger.yaml
/swagger-ui.html         /api-docs
/openapi.json            /openapi.yaml
/api/v1/swagger.json     /api/swagger.json
/v1/api-docs             /v2/api-docs
/v3/api-docs             /.well-known/openapi
/graphql                 /graphql/playground
/graphiql                /api/graphql
```

### API Version Drift Testing
```
/api/v1/users   → check if /api/v2/ exposes same but with less auth
/api/mobile/v1/ → mobile endpoints often have weaker auth checks
/internal/api/  → internal routes sometimes reachable externally
/api/admin/     → admin endpoints with different ACL
```

### Parameter Discovery
```bash
arjun -u https://target.com/endpoint -oJ arjun-results.json
x8 -u "https://target.com/page" -w /path/to/params.txt -o x8-results.txt
```

---

## From hack-skills: Subdomain Enumeration & Full Recon Commands

### Subdomain Enumeration
```bash
subfinder -d target.com -all -o subfinder-out.txt
amass enum -passive -d target.com -o amass-out.txt
# Mass DNS resolution:
cat all-subs.txt | massdns -r resolvers.txt -t A -o S -w massdns-out.txt
# Probe live hosts:
cat massdns-out.txt | dnsx -resp -a -o live-hosts.txt
# HTTP probe:
cat live-hosts.txt | httpx -sc -title -tech-detect -o httpx-out.txt
```

### Port Scan
```bash
nmap -iL live-hosts.txt -p 80,443,8080,8443,8888,3000,4443,9090,9200,6379,27017 --open -oA nmap-out
```

### Tech Fingerprinting
```
Cookies: PHPSESSID (PHP), JSESSIONID (Java), ASP.NET_SessionId (.NET)
Headers: X-Powered-By, X-Generator, X-Drupal-Cache, X-WordPress-Cache
Meta generators: <meta name="generator" content="WordPress 6.x">
Error pages: stack traces leak framework/version
```

### Endpoint Discovery
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -o ffuf-out.json
feroxbuster -u https://target.com -w wordlist.txt --depth 3 -o ferox-out.txt
```

### GitHub Dorks
```
org:target "password" OR "secret" OR "api_key"
site:github.com "target.com" "api_key"
site:github.com "target.com" extension:env
site:github.com inurl:target.com "Authorization: Bearer"
```

### Zseano's Parameter→Vulnerability Mapping
```
?redirect=   ?url=   ?next=   → Open Redirect
?file=   ?path=   ?include= → LFI/Path Traversal
?id=   ?user=   ?uid=       → IDOR/BOLA
?template=   ?view=          → SSTI
?query=   ?search=            → SQLi / XSS
?callback=   ?jsonp=          → JSONP XSS
?src=   ?img=   ?url=         → SSRF
```

### Nuclei Automation
```bash
nuclei -l live-hosts.txt -t cves/ -t exposures/ -t misconfigurations/ -severity medium,high,critical -o nuclei-out.txt
# Target-specific:
nuclei -u https://target.com -t fuzzing-templates/
```

### Java Middleware Fingerprint Matrix
```
Tomcat:         /manager/html  → HTTP 401 with "Apache Tomcat" in header
JBoss:          /jmx-console/  /web-console/
WebLogic:       /console/      T3 on :7001
Spring Boot:    /actuator      /actuator/env  /actuator/heapdump
Jenkins:        /jenkins/      /hudson/  "X-Jenkins" header
```

### Spring Boot Actuator Exploitation Priority
```
/actuator/env         → environment variables (secrets, credentials)
/actuator/heapdump    → JVM heap dump (search for passwords)
/actuator/mappings    → all routes including hidden admin endpoints
/actuator/loggers     → may allow setting debug level to leak data
/actuator/beans       → Spring bean definitions
```

### Version Control & Backup File Leak Checklist
```
/.git/config          /.git/HEAD           /.git/COMMIT_EDITMSG
/.svn/entries         /.hg/hgrc
/backup.zip           /backup.tar.gz       /backup.sql
/db.sql               /dump.sql            /database.sql
/.env                 /.env.backup         /.env.prod
/config.php.bak       /wp-config.php.bak   /web.config.bak
/robots.txt (look for disallowed paths)
/sitemap.xml (enumerate hidden routes)
```

