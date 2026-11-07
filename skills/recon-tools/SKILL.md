---
name: recon-tools
description: Recon tool execution — subdomain enumeration, Shodan, nuclei scanning, URL crawling, source leak discovery, JS analysis. Run automatically at the start of every hunt.
metadata:
  author: zebbern
  version: "1.1"
---

# Recon Tools — Execute Automatically

## Execution Rules

Run all phases below without asking. Do not say "would you like me to run subfinder?" — run it. Do not say "should I crawl the URLs?" — crawl them. Report results as each phase completes, then immediately move to the next.

**Automatic trigger order:**
1. Subdomain enum + httpx probe → always first
2. Source leak quick wins (Phase 1 of source-leak section) → run in parallel with subdomain enum, takes 30 seconds
3. Shodan org recon on target domain → run while subfinder runs
4. Nuclei on live hosts → run after httpx confirms live hosts
5. URL crawling → run automatically after httpx (not on-request, always)
6. JS analysis and source map extraction → run after crawling
---

# Shodan Reconnaissance and Pentesting

## Purpose

Provide systematic methodologies for leveraging Shodan as a reconnaissance tool during penetration testing engagements. This skill covers the Shodan web interface, command-line interface (CLI), REST API, search filters, on-demand scanning, and network monitoring capabilities for discovering exposed services, vulnerable systems, and IoT devices.

## Inputs / Prerequisites

- **Shodan Account**: Free or paid account at shodan.io
- **API Key**: Obtained from Shodan account dashboard
- **Target Information**: IP addresses, domains, or network ranges to investigate
- **Shodan CLI**: Python-based command-line tool installed
- **Authorization**: Written permission for reconnaissance on target networks

## Outputs / Deliverables

- **Asset Inventory**: List of discovered hosts, ports, and services
- **Vulnerability Report**: Identified CVEs and exposed vulnerable services
- **Banner Data**: Service banners revealing software versions
- **Network Mapping**: Geographic and organizational distribution of assets
- **Screenshot Gallery**: Visual reconnaissance of exposed interfaces
- **Exported Data**: JSON/CSV files for further analysis

## Core Workflow

### 1. Setup and Configuration

#### Install Shodan CLI
```bash
# Using pip
pip install shodan

# Or easy_install
easy_install shodan

# On BlackArch/Arch Linux
sudo pacman -S python-shodan
```

#### Initialize API Key
```bash
# Set your API key
shodan init YOUR_API_KEY

# Verify setup
shodan info
# Output: Query credits available: 100
#         Scan credits available: 100
```

#### Check Account Status
```bash
# View credits and plan info
shodan info

# Check your external IP
shodan myip

# Check CLI version
shodan version
```

### 2. Basic Host Reconnaissance

#### Query Single Host
```bash
# Get all information about an IP
shodan host 1.1.1.1

# Example output:
# 1.1.1.1
# Hostnames: one.one.one.one
# Country: Australia
# Organization: Mountain View Communications
# Number of open ports: 3
# Ports:
#   53/udp
#   80/tcp
#   443/tcp
```

#### Check if Host is Honeypot
```bash
# Get honeypot probability score
shodan honeyscore 192.168.1.100

# Output: Not a honeypot
#         Score: 0.3
```

### 3. Search Queries

#### Basic Search (Free)
```bash
# Simple keyword search (no credits consumed)
shodan search apache

# Specify output fields
shodan search --fields ip_str,port,os smb
```

#### Filtered Search (1 Credit)
```bash
# Product-specific search
shodan search product:mongodb

# Search with multiple filters
shodan search product:nginx country:US city:"New York"
```

#### Count Results
```bash
# Get result count without consuming credits
shodan count openssh
# Output: 23128

shodan count openssh 7
# Output: 219
```

#### Download Results
```bash
# Download 1000 results (default)
shodan download results.json.gz "apache country:US"

# Download specific number of results
shodan download --limit 5000 results.json.gz "nginx"

# Download all available results
shodan download --limit -1 all_results.json.gz "query"
```

#### Parse Downloaded Data
```bash
# Extract specific fields from downloaded data
shodan parse --fields ip_str,port,hostnames results.json.gz

# Filter by specific criteria
shodan parse --fields location.country_code3,ip_str -f port:22 results.json.gz

# Export to CSV format
shodan parse --fields ip_str,port,org --separator , results.json.gz > results.csv
```

### 4. Search Filters Reference

#### Network Filters
```
ip:1.2.3.4                  # Specific IP address
net:192.168.0.0/24          # Network range (CIDR)
hostname:example.com        # Hostname contains
port:22                     # Specific port
asn:AS15169                 # Autonomous System Number
```

#### Geographic Filters
```
country:US                  # Two-letter country code
country:"United States"     # Full country name
city:"San Francisco"        # City name
state:CA                    # State/region
postal:94102                # Postal/ZIP code
geo:37.7,-122.4             # Lat/long coordinates
```

#### Organization Filters
```
org:"Google"                # Organization name
isp:"Comcast"               # ISP name
```

#### Service/Product Filters
```
product:nginx               # Software product
version:1.14.0              # Software version
os:"Windows Server 2019"    # Operating system
http.title:"Dashboard"      # HTTP page title
http.html:"login"           # HTML content
http.status:200             # HTTP status code
ssl.cert.subject.cn:*.example.com  # SSL certificate
ssl:true                    # Has SSL enabled
```

#### Vulnerability Filters
```
vuln:CVE-2019-0708          # Specific CVE
has_vuln:true               # Has any vulnerability
```

#### Screenshot Filters
```
has_screenshot:true         # Has screenshot available
screenshot.label:webcam     # Screenshot type
```

### 5. On-Demand Scanning

#### Submit Scan
```bash
# Scan single IP (1 credit per IP)
shodan scan submit 192.168.1.100

# Scan with verbose output (shows scan ID)
shodan scan submit --verbose 192.168.1.100

# Scan and save results
shodan scan submit --filename scan_results.json.gz 192.168.1.100
```

#### Monitor Scan Status
```bash
# List recent scans
shodan scan list

# Check specific scan status
shodan scan status SCAN_ID

# Download scan results later
shodan download --limit -1 results.json.gz scan:SCAN_ID
```

#### Available Scan Protocols
```bash
# List available protocols/modules
shodan scan protocols
```

### 6. Statistics and Analysis

#### Get Search Statistics
```bash
# Default statistics (top 10 countries, orgs)
shodan stats nginx

# Custom facets
shodan stats --facets domain,port,asn --limit 5 nginx

# Save to CSV
shodan stats --facets country,org -O stats.csv apache
```

### 7. Network Monitoring

#### Setup Alerts (Web Interface)
```
1. Navigate to Monitor Dashboard
2. Add IP, range, or domain to monitor
3. Configure notification service (email, Slack, webhook)
4. Select trigger events (new service, vulnerability, etc.)
5. View dashboard for exposed services
```

### 8. REST API Usage

#### Direct API Calls
```bash
# Get API info
curl -s "https://api.shodan.io/api-info?key=YOUR_KEY" | jq

# Host lookup
curl -s "https://api.shodan.io/shodan/host/1.1.1.1?key=YOUR_KEY" | jq

# Search query
curl -s "https://api.shodan.io/shodan/host/search?key=YOUR_KEY&query=apache" | jq
```

#### Python Library
```python
import shodan

api = shodan.Shodan('YOUR_API_KEY')

# Search
results = api.search('apache')
print(f'Results found: {results["total"]}')
for result in results['matches']:
    print(f'IP: {result["ip_str"]}')

# Host lookup
host = api.host('1.1.1.1')
print(f'IP: {host["ip_str"]}')
print(f'Organization: {host.get("org", "n/a")}')
for item in host['data']:
    print(f'Port: {item["port"]}')
```

## Quick Reference

### Essential CLI Commands

| Command | Description | Credits |
|---------|-------------|---------|
| `shodan init KEY` | Initialize API key | 0 |
| `shodan info` | Show account info | 0 |
| `shodan myip` | Show your IP | 0 |
| `shodan host IP` | Host details | 0 |
| `shodan count QUERY` | Result count | 0 |
| `shodan search QUERY` | Basic search | 0* |
| `shodan download FILE QUERY` | Save results | 1/100 results |
| `shodan parse FILE` | Extract data | 0 |
| `shodan stats QUERY` | Statistics | 1 |
| `shodan scan submit IP` | On-demand scan | 1/IP |
| `shodan honeyscore IP` | Honeypot check | 0 |

*Filters consume 1 credit per query

### Common Search Queries

| Purpose | Query |
|---------|-------|
| Find webcams | `webcam has_screenshot:true` |
| MongoDB databases | `product:mongodb` |
| Redis servers | `product:redis` |
| Elasticsearch | `product:elastic port:9200` |
| Default passwords | `"default password"` |
| Vulnerable RDP | `port:3389 vuln:CVE-2019-0708` |
| Industrial systems | `port:502 modbus` |
| Cisco devices | `product:cisco` |
| Open VNC | `port:5900 authentication disabled` |
| Exposed FTP | `port:21 anonymous` |
| WordPress sites | `http.component:wordpress` |
| Printers | `"HP-ChaiSOE" port:80` |
| Cameras (RTSP) | `port:554 has_screenshot:true` |
| Jenkins servers | `X-Jenkins port:8080` |
| Docker APIs | `port:2375 product:docker` |

### Useful Filter Combinations

| Scenario | Query |
|---------|-------|
| Target org recon | `org:"Company Name"` |
| Domain enumeration | `hostname:example.com` |
| Network range scan | `net:192.168.0.0/24` |
| SSL cert search | `ssl.cert.subject.cn:*.target.com` |
| Vulnerable servers | `vuln:CVE-2021-44228 country:US` |
| Exposed admin panels | `http.title:"admin" port:443` |
| Database exposure | `port:3306,5432,27017,6379` |

### Credit System

| Action | Credit Type | Cost |
|--------|-------------|------|
| Basic search | Query | 0 (no filters) |
| Filtered search | Query | 1 |
| Download 100 results | Query | 1 |
| Generate report | Query | 1 |
| Scan 1 IP | Scan | 1 |
| Network monitoring | Monitored IPs | Depends on plan |

## Constraints and Limitations

### Operational Boundaries
- Rate limited to 1 request per second
- Scan results not immediate (asynchronous)
- Cannot re-scan same IP within 24 hours (non-Enterprise)
- Free accounts have limited credits
- Some data requires paid subscription

### Data Freshness
- Shodan crawls continuously but data may be days/weeks old
- On-demand scans provide current data but cost credits
- Historical data available with paid plans

### Legal Requirements
- Only perform reconnaissance on authorized targets
- Passive reconnaissance generally legal but verify jurisdiction
- Active scanning (scan submit) requires authorization
- Document all reconnaissance activities

## Examples

### Example 1: Organization Reconnaissance
```bash
# Find all hosts belonging to target organization
shodan search 'org:"Target Company"'

# Get statistics on their infrastructure
shodan stats --facets port,product,country 'org:"Target Company"'

# Download detailed data
shodan download target_data.json.gz 'org:"Target Company"'

# Parse for specific info
shodan parse --fields ip_str,port,product target_data.json.gz
```

### Example 2: Vulnerable Service Discovery
```bash
# Find hosts vulnerable to BlueKeep (RDP CVE)
shodan search 'vuln:CVE-2019-0708 country:US'

# Find exposed Elasticsearch with no auth
shodan search 'product:elastic port:9200 -authentication'

# Find Log4j vulnerable systems
shodan search 'vuln:CVE-2021-44228'
```

### Example 3: IoT Device Discovery
```bash
# Find exposed webcams
shodan search 'webcam has_screenshot:true country:US'

# Find industrial control systems
shodan search 'port:502 product:modbus'

# Find exposed printers
shodan search '"HP-ChaiSOE" port:80'

# Find smart home devices
shodan search 'product:nest'
```

### Example 4: SSL/TLS Certificate Analysis
```bash
# Find hosts with specific SSL cert
shodan search 'ssl.cert.subject.cn:*.example.com'

# Find expired certificates
shodan search 'ssl.cert.expired:true org:"Company"'

# Find self-signed certificates
shodan search 'ssl.cert.issuer.cn:self-signed'
```

### Example 5: Python Automation Script
```python
#!/usr/bin/env python3
import shodan
import json

API_KEY = 'YOUR_API_KEY'
api = shodan.Shodan(API_KEY)

def recon_organization(org_name):
    """Perform reconnaissance on an organization"""
    try:
        # Search for organization
        query = f'org:"{org_name}"'
        results = api.search(query)
        
        print(f"[*] Found {results['total']} hosts for {org_name}")
        
        # Collect unique IPs and ports
        hosts = {}
        for result in results['matches']:
            ip = result['ip_str']
            port = result['port']
            product = result.get('product', 'unknown')
            
            if ip not in hosts:
                hosts[ip] = []
            hosts[ip].append({'port': port, 'product': product})
        
        # Output findings
        for ip, services in hosts.items():
            print(f"\n[+] {ip}")
            for svc in services:
                print(f"    - {svc['port']}/tcp ({svc['product']})")
        
        return hosts
        
    except shodan.APIError as e:
        print(f"Error: {e}")
        return None

if __name__ == '__main__':
    recon_organization("Target Company")
```

### Example 6: Network Range Assessment
```bash
# Scan a /24 network range
shodan search 'net:192.168.1.0/24'

# Get port distribution
shodan stats --facets port 'net:192.168.1.0/24'

# Find specific vulnerabilities in range
shodan search 'net:192.168.1.0/24 vuln:CVE-2021-44228'

# Export all data for range
shodan download network_scan.json.gz 'net:192.168.1.0/24'
```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| No API Key Configured | Key not initialized | Run `shodan init YOUR_API_KEY` then verify with `shodan info` |
| Query Credits Exhausted | Monthly credits consumed | Use credit-free queries (no filters), wait for reset, or upgrade |
| Host Recently Crawled | Cannot re-scan IP within 24h | Use `shodan host IP` for existing data, or wait 24 hours |
| Rate Limit Exceeded | >1 request/second | Add `time.sleep(1)` between API requests |
| Empty Search Results | Too specific or syntax error | Use quotes for phrases: `'org:"Company Name"'`; broaden criteria |
| Downloaded File Won't Parse | Corrupted or wrong format | Verify with `gunzip -t file.gz`, re-download with `--limit` |



---

## subdomain-enumeration

# Subdomain Enumeration

Collect publicly discoverable hostnames for one exact root domain using only `subfinder` and `subdog`, then port-scan every discovered host with `naabu`, then probe every naabu-confirmed host with `httpx`.

Subdomain discovery is passive; the naabu port scan and httpx probe that follow it are active and are required final steps, not optional extras. Do not invoke any other reconnaissance or enumeration tool. The single exception is URL crawling: when the user asks for URL crawling, run both `katana` and `urlflux` against the httpx output. Standard shell utilities may be used only to create files, normalize output, filter the exact domain, deduplicate, sort, and count results.

Report hostnames as passive discoveries unless naabu has actually confirmed them live. httpx is used only to probe the naabu-confirmed hosts, not to discover new ones. Do not add takeover or vulnerability conclusions.

## Workflow

Set the target without a scheme, port, path, or wildcard:

```bash
TARGET="example.com"
ESCAPED_TARGET="example\\.com"
OUTDIR="./recon/$TARGET"
TMPDIR="$OUTDIR/.tmp"
mkdir -p "$TMPDIR"
```

Check that all four required tools are available:

```bash
command -v subfinder subdog naabu httpx
```

Run Subfinder:

```bash
echo "$TARGET" | subfinder -duc -silent -all | unew "$TMPDIR/subfinder.raw"
```

Run SubDog:

```bash
echo "$TARGET" | subdog --silent --source all | unew "$TMPDIR/subdog.raw"
```

Merge, normalize, scope-filter, and deduplicate their output:

```bash
cat "$TMPDIR/subfinder.raw" "$TMPDIR/subdog.raw" \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/\.$//' \
  | grep -aE "^([A-Za-z0-9_-]+\\.)*$ESCAPED_TARGET$" \
  | unew "$OUTDIR/allsubs.txt"
```

Count the final results:

```bash
wc -l "$OUTDIR/allsubs.txt"
```

Port scan every discovered host with naabu. This step is required — do not skip it or present results before it completes:

```bash
cat "$OUTDIR/allsubs.txt" | naabu -duc -silent | unew "$OUTDIR/naabu.txt"
```

Count the live hosts naabu confirmed:

```bash
wc -l "$OUTDIR/naabu.txt"
```

Probe every naabu-confirmed host with httpx. This step is required — always run this exact command, do not skip it:

```bash
cat "$OUTDIR/naabu.txt" | httpx -duc -silent -nc -sc -title -cl -ct | sort -t'[' -k3,3nr | unew -el -i "$OUTDIR/httpx.txt"
```

Count the httpx-probed hosts:

```bash
wc -l "$OUTDIR/httpx.txt"
```



---

## url-crawling

## URL crawling

Run this section automatically after httpx completes — do not wait for the user to ask. Run **both** katana and urlflux; neither is optional.

Check that the two crawling tools are available:

```bash
command -v katana urlflux
```

Run katana:

```bash
cat "$OUTDIR/httpx.txt" | katana -duc -silent -nc -jc -concurrency 10 -parallelism 10 -depth 7 -timeout 30 -aff | unew "$TMPDIR/katana.raw"
```

Run urlflux:

```bash
cat "$OUTDIR/httpx.txt" | urlflux --silent | unew "$TMPDIR/urlflux.raw"
```

Merge and deduplicate both crawlers into a single URL list:

```bash
cat "$TMPDIR/katana.raw" "$TMPDIR/urlflux.raw" | unew "$OUTDIR/urls.txt"
```

Count the crawled URLs:

```bash
wc -l "$OUTDIR/urls.txt"
```

Report the subdomain line count, the naabu-confirmed host count, the httpx-probed host count, the crawled URL count (only if crawling was requested), and the corresponding output paths. Do not add takeover or vulnerability conclusions.


---

## nuclei

# Nuclei False-Positive Validation

Validate Nuclei results against the actual HTTP responses and the actual YAML templates. A Nuclei match is a hypothesis, not a finding.

Core rule: **never globally suppress a template because one target failed validation.** Distinguish template-level unreliability from target-specific mismatch.

Only test targets the user is authorized to test. Validation is read-only and non-destructive: no shells, no file writes, no data modification, no brute force, no exploitation beyond a benign proof of the template's own claim. If a check would be destructive, stop and mark INCONCLUSIVE.

## Artifacts

Create a working directory per run and never modify the original scan output or `~/nuclei-templates`:

```bash
OUTDIR="./nuclei-validation/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
cp scan.txt "$OUTDIR/scan.original.txt"   # original stays untouched
```

Expected files:

| File | Purpose |
|---|---|
| `scan.original.txt` | untouched raw scan output |
| `scan.jsonl` | machine-parseable findings |
| `groups.txt` | findings grouped by template ID |
| `templates/` | copies of read templates (never edit originals) |
| `validation.log` | request/response evidence per check |
| `false_positive_templates.txt` | global ignore list (project root, not inside nuclei-templates) |
| `report.md` | final report |

## Phase 0 — Preconditions

```bash
command -v nuclei jq curl
nuclei -version
ls -d ~/nuclei-templates || echo "MISSING: run nuclei -update-templates"
```

If scan results already exist in the workspace, parse them and use targeted re-tests instead of re-running the full scan. Otherwise run the scan now:

```bash
nuclei -duc -silent -severity critical,high,medium \
  -tags "cve2026,cve2025,cve2024,cve2023,cve2022,cve2021,cve2020,cve2019,cve2018,default-login,apache,joomla,kubernetes,vmware,atlassian,phpinfo,springboot,spring,struts,tomcat,weblogic,jboss,activemq,elasticsearch,swagger,graphql,gitlab,jenkins,grafana,confluence,jira,nginx,laravel,drupal,magento,thinkphp,phpmyadmin,fortinet,fortios,fortigate,ivanti,citrix,sonicwall,paloaltonetworks,zimbra,sharepoint,react,php,flask,django,codeigniter,symfony,springcloud" \
  -l targets.txt -jsonl -o "$OUTDIR/scan.jsonl" | tee "$OUTDIR/scan.original.txt"
```

Do not add `-irr` to the primary scan. Use it only for targeted re-tests, because it records full requests/responses.

## Phase 1 — Run and parse

Parse every result into: template ID, severity, protocol/type, target host, matched URL/path, matcher name, extracted values, and any other metadata.

```bash
jq -c '{id:."template-id", sev:.info.severity, proto:.type, host:.host,
        matched:."matched-at", matcher:."matcher-name",
        extracted:."extracted-results", ts:timestamp,
        ip:ip, port:port, scheme:scheme, url:url}' "$OUTDIR/scan.jsonl" \
  > "$OUTDIR/findings.normalized.jsonl"
```

Group by template ID, keeping every target (never collapse duplicates silently):

```bash
jq -r '."template-id"' "$OUTDIR/scan.jsonl" | sort | uniq -c | sort -rn > "$OUTDIR/template-counts.txt"

jq -r '[."template-id", ."matched-at"] | @tsv' "$OUTDIR/scan.jsonl" \
  | sort -k1,1 > "$OUTDIR/groups.tsv"
```

Present the grouping, for example:

```text
CVE-2012-1823
    http://target1:3187/index.php
    http://target2/index.php
CVE-2024-23897
    http://target3:8080
```

Deduplicate template work: **analyze each unique template ID once**. Do not re-derive matcher logic per target.

## Phase 2 — Locate the template

```bash
TID='CVE-2012-1823'
TPATH=$(find ~/nuclei-templates -type f -iname "*${TID}*.yaml" -print -quit)
echo "$TPATH"
cp "$TPATH" "$OUTDIR/templates/"
```

Read the **complete** file. If multiple templates share a name fragment, confirm the `id:` field matches the finding's template ID; if not, keep searching:

```bash
grep -rl "^id: ${TID}$" ~/nuclei-templates --include='*.yaml' | head
```

Record for each template: `id`, `info` (name, author, severity, description, reference, tags, classification/CVE/CWE), affected products, and every request field (method, path, query, headers, body, payloads, variables, DSL), plus matchers, matcher-condition, negative matchers, extractors, redirect behavior, protocol, version-detection logic, and response conditions.

## Phase 3 — What does the matcher actually prove?

Answer these before validating any target:

1. Does it only detect that a URL/path exists?
2. Does it only detect a version string or banner?
3. Does it require a specific response body, header, or status?
4. Does it check the version is actually in the vulnerable range?
5. Does it send a vulnerability-specific request, or a generic one?
6. Does the match prove exploitability, or merely a possible condition?
7. Is the matcher too broad (single keyword, generic error, 200-only, `contains` on a common word)?
8. Could a healthy/unrelated app return the same response?
9. Is a negative matcher missing (e.g. no `!contains` for the patched banner, no `!status` for a login redirect)?
10. Would a WAF, reverse proxy, or default page satisfy it?

Common unreliable patterns to flag:

- Matcher is a generic word (`"Index of /"`, `"phpinfo"`, `"Jenkins"`, `"Apache"`) without product-specific context.
- Status-code-only matcher, or `contains: "200"` against a reflective page.
- Version parsed from a header/banner with no range check, or checked with a broken regex.
- Payload reflected back in an error page or 404 body and matched as proof of execution.
- Soft-404: every path returns 200 with the same template.
- Detects a panel/login page and calls it an unauthenticated vuln.
- CVE template that only fingerprints the product version, without the CVE-specific request/response.
- Multi-matcher template where `condition: or` lets a trivial fingerprint satisfy the whole check.
- Template expects a distinctive string that is also in the product's public docs/default error output.
- Extracted value treated as proof (a version string is not a vulnerability).

## Phase 4 — Validate targets

Pick representative targets per template (at minimum: the first, the one with the oddest response, and any target whose result looks suspicious). Send safe requests that reproduce what the template sent.

```bash
TARGET='http://host:port/path'
curl -sS -k --max-time 15 -D "$OUTDIR/hdr.txt" -o "$OUTDIR/body.txt" "$TARGET"
head -20 "$OUTDIR/hdr.txt"; head -60 "$OUTDIR/body.txt"
```

Only use `-k` when the scan itself was HTTPS/TLS-broken; note it in the log. Use `-L` only if the template follows redirects, and log the chain (`-w '%{url_effective} %{http_code}\n'`) so a login redirect is not mistaken for a hit.

For POST/JSON/header-based templates, replay the exact method, path, headers, and body from the YAML — nothing more. Compare:

- status code vs. what the matcher requires;
- body/header evidence vs. the exact matcher strings;
- version/product vs. the vulnerable range;
- negative conditions (is the patched behavior present?);
- whether a benign sanity check shows the claimed behavior is real (e.g. a read-only endpoint returning expected data).

Also test a **control**: a path that should not match. If the control matches too, the matcher is too broad.

Log each check:

```bash
printf '%s\t%s\t%s\t%s\n' "$TID" "$TARGET" "$STATUS" "$VERDICT" >> "$OUTDIR/validation.log"
```

Verdicts:

- **CONFIRMED** — strong evidence the target satisfies the template's vulnerability condition (vulnerable version **and** the CVE-specific response, or a benign exploit proof with the expected unique output).
- **FALSE POSITIVE** — matcher fires but the vulnerability condition is not met.
- **INCONCLUSIVE** — insufficient evidence, blocked response, auth required, or unsafe to test.

## Phase 5 — Classify template-level vs target-level

**A) TEMPLATE_FALSE_POSITIVE** — the detection logic itself is unreliable: it matches unrelated software, relies on a generic keyword/banner/status, lacks a version or negative condition, or cannot distinguish vulnerable from patched. Prove this with at least two independent signals, e.g. the same matcher firing on a control/healthy target, or the YAML containing no CVE-specific check. Then all findings from that template are suppressed.

**B) TARGET_SPECIFIC_FALSE_POSITIVE** — template is sound (specific request + specific evidence), but this target is not vulnerable (wrong version, patched, different product, decoy page). Discard only that target; keep the template active.

Gray area: if the template is sound but the run produced only ambiguous results on many targets, classify findings INCONCLUSIVE, not template-level.

## Phase 6 — Global suppression

Only after Phase 5 evidence, append template IDs (never paths) to the ignore file:

```bash
printf '%s\n' "$TID" >> false_positive_templates.txt
sort -u -o false_positive_templates.txt false_positive_templates.txt
```

Then filter the final report:

```bash
grep -v -F -f false_positive_templates.txt "$OUTDIR/template-counts.txt"
jq -c --rawfile ignore false_positive_templates.txt \
  'select(."template-id" as $id | ($ignore | split("\n") | index($id) | not))' \
  "$OUTDIR/findings.normalized.jsonl" > "$OUTDIR/findings.suppressed.jsonl"
```

Requirements before adding an ID:

- The template was read in full.
- The flaw is in the matcher/request logic, not one target's state.
- Evidence is recorded in `validation.log` / `report.md`.
- The ID is not added merely because a target was unreachable.

Do not edit, move, or delete anything under `~/nuclei-templates`.

## Phase 7 — Re-test suspicious findings

Reproduce with the exact template and inspect what matched:

```bash
nuclei -u "$TARGET" -t "$TPATH" -silent -jsonl -irr -o "$OUTDIR/retest.jsonl"
jq '{matched:."matched-at", matcher:."matcher-name", extracted:."extracted-results",
     req:.request, res:.response}' "$OUTDIR/retest.jsonl"
```

Determine, in order: (1) exact request sent, (2) exact response received, (3) which matcher was true, (4) why it was true, (5) whether that condition demonstrates the vulnerability. Cross-check `-debug` output only if needed. Do not trust `extracted-results` as proof.

## Phase 8 — Output

Write `report.md` in exactly this shape:

```text
==================================================
NUCLEI VALIDATION SUMMARY
==================================================

Templates analyzed: X

Confirmed findings: X
Target-specific false positives: X
Template-level false positives: X
Inconclusive findings: X

--------------------------------------------------
CONFIRMED
--------------------------------------------------

[TEMPLATE]
TARGET
REASON

--------------------------------------------------
TARGET-SPECIFIC FALSE POSITIVES
--------------------------------------------------

[TEMPLATE]
TARGET
WHY IT IS FALSE POSITIVE

--------------------------------------------------
TEMPLATE-LEVEL FALSE POSITIVES
--------------------------------------------------

[TEMPLATE]
TEMPLATE PATH
WHY THE TEMPLATE IS UNRELIABLE
WHAT MATCHER CAUSED THE FALSE POSITIVE

--------------------------------------------------
GLOBAL IGNORE LIST
--------------------------------------------------

CVE-XXXX-XXXX
CVE-YYYY-YYYY
```

Include INCONCLUSIVE entries (target, what blocked validation, what would resolve it). End the chat reply with the exact list of template IDs to ignore globally and a one-line reason for each.

## Rules

- Never assume a result is correct because Nuclei reported it.
- Read the YAML before deciding; never judge by filename or ID alone.
- Validate against the real response, not the template's description.
- Never mark CONFIRMED from a banner, version string, or generic keyword alone.
- Never globally suppress on a single failed target.
- Prefer INCONCLUSIVE over guessing.
- Keep the original scan output and `~/nuclei-templates` untouched.
- Keep `false_positive_templates.txt` separate from scan artifacts.
- Stay within authorized scope; perform no destructive exploitation.



---

## scanning-tools

# Security Scanning Tools

## Purpose

Master essential security scanning tools for network discovery, vulnerability assessment, web application testing, wireless security, and compliance validation. This skill covers tool selection, configuration, and practical usage across different scanning categories.

## Prerequisites

### Required Environment
- Linux-based system (Kali Linux recommended)
- Network access to target systems
- Proper authorization for scanning activities

### Required Knowledge
- Basic networking concepts (TCP/IP, ports, protocols)
- Understanding of common vulnerabilities
- Familiarity with command-line interfaces

## Outputs and Deliverables

1. **Network Discovery Reports** - Identified hosts, ports, and services
2. **Vulnerability Assessment Reports** - CVEs, misconfigurations, risk ratings
3. **Web Application Security Reports** - OWASP Top 10 findings
4. **Compliance Reports** - CIS benchmarks, PCI-DSS, HIPAA checks

## Core Workflow

### Phase 1: Network Scanning Tools

#### Nmap (Network Mapper)

Primary tool for network discovery and security auditing:

```bash
# Host discovery
nmap -sn 192.168.1.0/24              # Ping scan (no port scan)
nmap -sL 192.168.1.0/24              # List scan (DNS resolution)
nmap -Pn 192.168.1.100               # Skip host discovery

# Port scanning techniques
nmap -sS 192.168.1.100               # TCP SYN scan (stealth)
nmap -sT 192.168.1.100               # TCP connect scan
nmap -sU 192.168.1.100               # UDP scan
nmap -sA 192.168.1.100               # ACK scan (firewall detection)

# Port specification
nmap -p 80,443 192.168.1.100         # Specific ports
nmap -p- 192.168.1.100               # All 65535 ports
nmap -p 1-1000 192.168.1.100         # Port range
nmap --top-ports 100 192.168.1.100   # Top 100 common ports

# Service and OS detection
nmap -sV 192.168.1.100               # Service version detection
nmap -O 192.168.1.100                # OS detection
nmap -A 192.168.1.100                # Aggressive (OS, version, scripts)

# Timing and performance
nmap -T0 192.168.1.100               # Paranoid (slowest, IDS evasion)
nmap -T4 192.168.1.100               # Aggressive (faster)
nmap -T5 192.168.1.100               # Insane (fastest)

# NSE Scripts
nmap --script=vuln 192.168.1.100     # Vulnerability scripts
nmap --script=http-enum 192.168.1.100  # Web enumeration
nmap --script=smb-vuln* 192.168.1.100  # SMB vulnerabilities
nmap --script=default 192.168.1.100  # Default script set

# Output formats
nmap -oN scan.txt 192.168.1.100      # Normal output
nmap -oX scan.xml 192.168.1.100      # XML output
nmap -oG scan.gnmap 192.168.1.100    # Grepable output
nmap -oA scan 192.168.1.100          # All formats
```

#### Masscan

High-speed port scanning for large networks:

```bash
# Basic scanning
masscan -p80 192.168.1.0/24 --rate=1000
masscan -p80,443,8080 192.168.1.0/24 --rate=10000

# Full port range
masscan -p0-65535 192.168.1.0/24 --rate=5000

# Large-scale scanning
masscan 0.0.0.0/0 -p443 --rate=100000 --excludefile exclude.txt

# Output formats
masscan -p80 192.168.1.0/24 -oG results.gnmap
masscan -p80 192.168.1.0/24 -oJ results.json
masscan -p80 192.168.1.0/24 -oX results.xml

# Banner grabbing
masscan -p80 192.168.1.0/24 --banners
```

### Phase 2: Vulnerability Scanning Tools

#### Nessus

Enterprise-grade vulnerability assessment:

```bash
# Start Nessus service
sudo systemctl start nessusd

# Access web interface
# https://localhost:8834

# Command-line (nessuscli)
nessuscli scan --create --name "Internal Scan" --targets 192.168.1.0/24
nessuscli scan --list
nessuscli scan --launch <scan_id>
nessuscli report --format pdf --output report.pdf <scan_id>
```

Key Nessus features:
- Comprehensive CVE detection
- Compliance checks (PCI-DSS, HIPAA, CIS)
- Custom scan templates
- Credentialed scanning for deeper analysis
- Regular plugin updates

#### OpenVAS (Greenbone)

Open-source vulnerability scanning:

```bash
# Install OpenVAS
sudo apt install openvas
sudo gvm-setup

# Start services
sudo gvm-start

# Access web interface (Greenbone Security Assistant)
# https://localhost:9392

# Command-line operations
gvm-cli socket --xml "<get_version/>"
gvm-cli socket --xml "<get_tasks/>"

# Create and run scan
gvm-cli socket --xml '
<create_target>
  <name>Test Target</name>
  <hosts>192.168.1.0/24</hosts>
</create_target>'
```

### Phase 3: Web Application Scanning Tools

#### Burp Suite

Comprehensive web application testing:

```
# Proxy configuration
1. Set browser proxy to 127.0.0.1:8080
2. Import Burp CA certificate for HTTPS
3. Add target to scope

# Key modules:
- Proxy: Intercept and modify requests
- Spider: Crawl web applications
- Scanner: Automated vulnerability detection
- Intruder: Automated attacks (fuzzing, brute-force)
- Repeater: Manual request manipulation
- Decoder: Encode/decode data
- Comparer: Compare responses
```

Core testing workflow:
1. Configure proxy and scope
2. Spider the application
3. Analyze sitemap
4. Run active scanner
5. Manual testing with Repeater/Intruder
6. Review findings and generate report

#### OWASP ZAP

Open-source web application scanner:

```bash
# Start ZAP
zaproxy

# Automated scan from CLI
zap-cli quick-scan https://target.com

# Full scan
zap-cli spider https://target.com
zap-cli active-scan https://target.com

# Generate report
zap-cli report -o report.html -f html

# API mode
zap.sh -daemon -port 8080 -config api.key=<your_key>
```

ZAP automation:
```bash
# Docker-based scanning
docker run -t owasp/zap2docker-stable zap-full-scan.py \
  -t https://target.com -r report.html

# Baseline scan (passive only)
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://target.com -r report.html
```

#### Nikto

Web server vulnerability scanner:

```bash
# Basic scan
nikto -h https://target.com

# Scan specific port
nikto -h target.com -p 8080

# Scan with SSL
nikto -h target.com -ssl

# Multiple targets
nikto -h targets.txt

# Output formats
nikto -h target.com -o report.html -Format html
nikto -h target.com -o report.xml -Format xml
nikto -h target.com -o report.csv -Format csv

# Tuning options
nikto -h target.com -Tuning 123456789  # All tests
nikto -h target.com -Tuning x          # Exclude specific tests
```

### Phase 4: Wireless Scanning Tools

#### Aircrack-ng Suite

Wireless network penetration testing:

```bash
# Check wireless interface
airmon-ng

# Enable monitor mode
sudo airmon-ng start wlan0

# Scan for networks
sudo airodump-ng wlan0mon

# Capture specific network
sudo airodump-ng -c <channel> --bssid <target_bssid> -w capture wlan0mon

# Deauthentication attack
sudo aireplay-ng -0 10 -a <bssid> wlan0mon

# Crack WPA handshake
aircrack-ng -w wordlist.txt -b <bssid> capture*.cap

# Crack WEP
aircrack-ng -b <bssid> capture*.cap
```

#### Kismet

Passive wireless detection:

```bash
# Start Kismet
kismet

# Specify interface
kismet -c wlan0

# Access web interface
# http://localhost:2501

# Detect hidden networks
# Kismet passively collects all beacon frames
# including those from hidden SSIDs
```

### Phase 5: Malware and Exploit Scanning

#### ClamAV

Open-source antivirus scanning:

```bash
# Update virus definitions
sudo freshclam

# Scan directory
clamscan -r /path/to/scan

# Scan with verbose output
clamscan -r -v /path/to/scan

# Move infected files
clamscan -r --move=/quarantine /path/to/scan

# Remove infected files
clamscan -r --remove /path/to/scan

# Scan specific file types
clamscan -r --include='\.exe$|\.dll$' /path/to/scan

# Output to log
clamscan -r -l scan.log /path/to/scan
```

#### Metasploit Vulnerability Validation

Validate vulnerabilities with exploitation:

```bash
# Start Metasploit
msfconsole

# Database setup
msfdb init
db_status

# Import Nmap results
db_import /path/to/nmap_scan.xml

# Vulnerability scanning
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 192.168.1.0/24
run

# Auto exploitation
vulns                           # View vulnerabilities
analyze                         # Suggest exploits
```

### Phase 6: Cloud Security Scanning

#### Prowler (AWS)

AWS security assessment:

```bash
# Install Prowler
pip install prowler

# Basic scan
prowler aws

# Specific checks
prowler aws -c iam s3 ec2

# Compliance framework
prowler aws --compliance cis_aws

# Output formats
prowler aws -M html json csv

# Specific region
prowler aws -f us-east-1

# Assume role
prowler aws -R arn:aws:iam::123456789012:role/ProwlerRole
```

#### ScoutSuite (Multi-cloud)

Multi-cloud security auditing:

```bash
# Install ScoutSuite
pip install scoutsuite

# AWS scan
scout aws

# Azure scan
scout azure --cli

# GCP scan
scout gcp --user-account

# Generate report
scout aws --report-dir ./reports
```

### Phase 7: Compliance Scanning

#### Lynis

Security auditing for Unix/Linux:

```bash
# Run audit
sudo lynis audit system

# Quick scan
sudo lynis audit system --quick

# Specific profile
sudo lynis audit system --profile server

# Output report
sudo lynis audit system --report-file /tmp/lynis-report.dat

# Check specific section
sudo lynis show profiles
sudo lynis audit system --tests-from-group malware
```

#### OpenSCAP

Security compliance scanning:

```bash
# List available profiles
oscap info /usr/share/xml/scap/ssg/content/ssg-<distro>-ds.xml

# Run scan with profile
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss \
  --report report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

# Generate fix script
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_pci-dss \
  --output remediation.sh \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
```

### Phase 8: Scanning Methodology

Structured scanning approach:

1. **Planning**
   - Define scope and objectives
   - Obtain proper authorization
   - Select appropriate tools

2. **Discovery**
   - Host discovery (Nmap ping sweep)
   - Port scanning
   - Service enumeration

3. **Vulnerability Assessment**
   - Automated scanning (Nessus/OpenVAS)
   - Web application scanning (Burp/ZAP)
   - Manual verification

4. **Analysis**
   - Correlate findings
   - Eliminate false positives
   - Prioritize by severity

5. **Reporting**
   - Document findings
   - Provide remediation guidance
   - Executive summary

### Phase 9: Tool Selection Guide

Choose the right tool for each scenario:

| Scenario | Recommended Tools |
|----------|-------------------|
| Network Discovery | Nmap, Masscan |
| Vulnerability Assessment | Nessus, OpenVAS |
| Web App Testing | Burp Suite, ZAP, Nikto |
| Wireless Security | Aircrack-ng, Kismet |
| Malware Detection | ClamAV, YARA |
| Cloud Security | Prowler, ScoutSuite |
| Compliance | Lynis, OpenSCAP |
| Protocol Analysis | Wireshark, tcpdump |

### Phase 10: Reporting and Documentation

Generate professional reports:

```bash
# Nmap XML to HTML
xsltproc nmap-output.xml -o report.html

# OpenVAS report export
gvm-cli socket --xml '<get_reports report_id="<id>" format_id="<pdf_format>"/>'

# Combine multiple scan results
# Use tools like Faraday, Dradis, or custom scripts

# Executive summary template:
# 1. Scope and methodology
# 2. Key findings summary
# 3. Risk distribution chart
# 4. Critical vulnerabilities
# 5. Remediation recommendations
# 6. Detailed technical findings
```

## Quick Reference

### Nmap Cheat Sheet

| Scan Type | Command |
|-----------|---------|
| Ping Scan | `nmap -sn <target>` |
| Quick Scan | `nmap -T4 -F <target>` |
| Full Scan | `nmap -p- <target>` |
| Service Scan | `nmap -sV <target>` |
| OS Detection | `nmap -O <target>` |
| Aggressive | `nmap -A <target>` |
| Vuln Scripts | `nmap --script=vuln <target>` |
| Stealth Scan | `nmap -sS -T2 <target>` |

### Common Ports Reference

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MySQL |
| 3389 | RDP |

## Constraints and Limitations

### Legal Considerations
- Always obtain written authorization
- Respect scope boundaries
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Technical Limitations
- Some scans may trigger IDS/IPS alerts
- Heavy scanning can impact network performance
- False positives require manual verification
- Encrypted traffic may limit analysis

### Best Practices
- Start with non-intrusive scans
- Gradually increase scan intensity
- Document all scanning activities
- Validate findings before reporting

## Troubleshooting

### Scan Not Detecting Hosts

**Solutions:**
1. Try different discovery methods: `nmap -Pn` or `nmap -sn -PS/PA/PU`
2. Check firewall rules blocking ICMP
3. Use TCP SYN scan: `nmap -PS22,80,443`
4. Verify network connectivity

### Slow Scan Performance

**Solutions:**
1. Increase timing: `nmap -T4` or `-T5`
2. Reduce port range: `--top-ports 100`
3. Use Masscan for initial discovery
4. Disable DNS resolution: `-n`

### Web Scanner Missing Vulnerabilities

**Solutions:**
1. Authenticate to access protected areas
2. Increase crawl depth
3. Add custom injection points
4. Use multiple tools for coverage
5. Perform manual testing



---

## source-leak

# HUNT-SOURCE-LEAK — Source Code & Build Artifact Leakage

## Crown Jewel Targets

Source map exposing TypeScript source = see all API routes, auth logic, secrets. Swagger/OpenAPI JSON = complete API surface map.

**Highest-value findings:**
- **`.js.map` source maps** — reconstruct full TypeScript/ES6 source code → find hardcoded API keys, internal endpoints, auth logic bypasses
- **`swagger.json` / `openapi.json`** — complete REST API specification with all endpoints, parameters, auth schemes, and internal route names
- **`.env` / `.env.production`** — APP_KEY, DB_PASSWORD, API_KEY, SECRET_KEY in plaintext
- **`.git/` exposure** — `git clone` the entire source history → all past hardcoded secrets
- **`asset-manifest.json` / `_next/static/`** — all JS bundle paths → systematic source map discovery
- **`build-info` / `info.json`** — git commit hash, build timestamp, dependency versions → CVE targeting

---

## Phase 1 — Quick Wins (Run First)

```bash
# These 10 requests take <30 seconds and often yield Critical findings
for PATH in \
  "/.env" \
  "/.env.production" \
  "/.env.local" \
  "/.git/HEAD" \
  "/swagger.json" \
  "/api/swagger.json" \
  "/v1/swagger.json" \
  "/openapi.json" \
  "/api/openapi.json" \
  "/api-docs"; do
  STATUS=$(curl -s -o /tmp/sl_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] HIT: https://$TARGET$PATH"
    head -5 /tmp/sl_test
    echo "---"
  fi
done
```

---

## Phase 2 — Source Map Discovery

> **Always resolve the CURRENT build hash before testing, and again before
> re-verifying.** Bundle filenames are content-hashed, so they rotate on every
> deploy. A `.map` URL recorded yesterday can 404 today while the map is still
> fully exposed under a new name. **A 404 at the old URL is not remediation** —
> it is a new build.
>
> ```bash
> # ALWAYS derive the hash live, never reuse a recorded URL
> HASH=$(curl -s "https://$TARGET/" | grep -oE 'main\.[a-f0-9]+\.js' | head -1)
> curl -s -o /dev/null -w '%{http_code} %{size_download} %{content_type}\n' \
>   "https://$TARGET/static/js/${HASH}.map"
> ```
>
> **Lesson from an authorized engagement.** A large production map was found at
> `main.<hashA>.js.map`. On re-verification that URL returned a small HTML
> soft-404 and the finding was nearly closed as fixed. The bundle had rotated to
> `main.<hashB>.js` — and the map was still published at `main.<hashB>.js.map`,
> same size. Nothing had been remediated.
>
> Tell the client this explicitly in the report: **redeploying does not fix source
> map exposure.** Only `GENERATE_SOURCEMAP=false` (or stripping `.map` at deploy)
> plus a CDN purge closes it. A team that redeploys and re-checks the old link
> will wrongly declare victory.
>
> Same rule applies to any content-hashed artifact: chunk files, CSS maps,
> `asset-manifest.json`, and staging equivalents.

```bash
# Step 1: Get asset manifest to find all JS bundle paths
curl -s "https://$TARGET/asset-manifest.json" | python3 -m json.tool 2>/dev/null
curl -s "https://$TARGET/static/js/main.*.js" 2>/dev/null | head -3

# Next.js
BUILD_ID=$(curl -s https://$TARGET/ | grep -oP '"buildId":"\K[^"]+')
curl -s "https://$TARGET/_next/static/$BUILD_ID/_buildManifest.js" | head -5

# Step 2: For each JS bundle, check for source map reference at end of file
for JS_URL in $(curl -s https://$TARGET/ | grep -oP 'src="[^"]*\.js"' | sed 's/src="//;s/"//'); do
  LAST_LINE=$(curl -s "https://$TARGET$JS_URL" | tail -1)
  echo "$LAST_LINE" | grep -q "sourceMappingURL" && echo "[+] Source map: $JS_URL"
done

# Step 3: Download and reconstruct source from .map files
JS_URL="https://$TARGET/static/js/main.abc123.js"
MAP_URL="${JS_URL}.map"
curl -s "$MAP_URL" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
sources = data.get('sources', [])
contents = data.get('sourcesContent', [])
for i, (src, content) in enumerate(zip(sources, contents)):
    if content:
        path = '/tmp/sourcemap_extract/' + src.replace('../','').replace('./',''). replace('webpack://','')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        print(f'[+] Extracted: {src}')
"

# Step 4: Grep extracted source for secrets
grep -r "API_KEY\|SECRET\|PASSWORD\|TOKEN\|PRIVATE" /tmp/sourcemap_extract/ 2>/dev/null
grep -r "process\.env\." /tmp/sourcemap_extract/ 2>/dev/null | grep -v "NEXT_PUBLIC_" | head -20
grep -r "http://internal\|localhost\|127\.0\.0\.1\|10\.\|172\.\|192\.168" /tmp/sourcemap_extract/ 2>/dev/null | head -20
```

---

## Phase 3 — Swagger / OpenAPI Discovery

```bash
# Common paths
SWAGGER_PATHS=(
  "/swagger.json" "/swagger.yaml" "/swagger/"
  "/api/swagger.json" "/api/swagger.yaml"
  "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
  "/openapi.json" "/openapi.yaml"
  "/api/openapi.json" "/api-docs" "/api-docs.json"
  "/api/v1/swagger.json" "/api/v2/swagger.json"
  "/rest/swagger.json" "/rest/api-docs"
  "/.well-known/openapi.json"
  "/graphql/schema.json"
)

for PATH in "${SWAGGER_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/swagger_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH"
    # Extract all API paths from swagger
    python3 -c "
import sys, json
try:
    d = json.load(open('/tmp/swagger_test'))
    paths = list(d.get('paths', {}).keys())
    print(f'Endpoints: {len(paths)}')
    print('\n'.join(sorted(paths)))
except: pass
" | head -50
  fi
done
```

---

## Phase 4 — .git Exposure

```bash
# Check if .git directory is accessible
curl -s "https://$TARGET/.git/HEAD" | grep -q "ref:" && echo "[+] .git exposed!"

# If exposed, reconstruct repo
# Tool: git-dumper
pip3 install git-dumper
git-dumper "https://$TARGET/.git/" /tmp/dumped-repo/

# Grep for secrets in all git history
cd /tmp/dumped-repo && \
  git log --all --oneline 2>/dev/null | head -20
  git grep -i "password\|secret\|api_key\|token" $(git rev-list --all) 2>/dev/null | head -30

# trufflehog on git history
trufflehog git file:///tmp/dumped-repo/ 2>/dev/null | head -50
```

---

## Phase 5 — Forgotten Files & Debug Endpoints

```bash
# Build artifacts and debug files
DEBUG_PATHS=(
  "/build-info.json" "/build/build-info.json"
  "/info" "/actuator/info" "/api/info"
  "/version" "/api/version" "/_version"
  "/health" "/status" "/ping"
  "/robots.txt" "/security.txt" "/.well-known/security.txt"
  "/sitemap.xml" "/manifest.json" "/browserconfig.xml"
  "/crossdomain.xml" "/clientaccesspolicy.xml"
  "/phpinfo.php" "/info.php" "/test.php"
  "/server-status" "/server-info" "/.htaccess"
  "/web.config" "/applicationHost.config"
  "/WEB-INF/web.xml" "/META-INF/MANIFEST.MF"
  "/package.json" "/composer.json" "/Gemfile"
  "/Dockerfile" "/docker-compose.yml" "/.dockerenv"
)

for PATH in "${DEBUG_PATHS[@]}"; do
  STATUS=$(curl -s -o /tmp/debug_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH ($STATUS, $(wc -c < /tmp/debug_test) bytes)"
    head -3 /tmp/debug_test
    echo "---"
  fi
done
```

---

## Phase 6 — .DS_Store File Listing

```bash
# .DS_Store files on macOS-deployed web servers reveal directory structure
curl -s "https://$TARGET/.DS_Store" | xxd | head -10

# Parse .DS_Store to extract filenames
pip3 install ds_store
python3 -c "
from ds_store import DSStore
with DSStore.open('/tmp/ds_store_test', 'r') as d:
    for entry in d:
        print(entry.filename)
"

# Recursive .DS_Store enumeration
# Tool: https://github.com/lijiejie/ds_store_exp
python3 ds_store_exp.py "https://$TARGET/"
```

---

## Phase 7 — webpack Chunk Analysis

```bash
# Download and analyze webpack chunks for hardcoded values
# Find chunk files
curl -s https://$TARGET/ | grep -oP '"[^"]*\.chunk\.js"' | tr -d '"' | while read chunk; do
  echo "Analyzing: $chunk"
  curl -s "https://$TARGET$chunk" | \
    grep -oE '"(api_key|apiKey|secret|password|token|key)"\s*:\s*"[^"]+"' | head -5
done

# Also grep for internal hostnames
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oE '"(https?://[^"]*internal[^"]*|http://[^"]*localhost[^"]*)"' | sort -u

# Check for Base64-encoded secrets
curl -s "https://$TARGET/static/js/main.*.js" | \
  grep -oP '"[A-Za-z0-9+/]{30,}={0,2}"' | while read b64; do
  DECODED=$(echo "$b64" | tr -d '"' | base64 -d 2>/dev/null)
  echo "$DECODED" | grep -iE "key|secret|password|token" && echo "  B64: $b64"
done
```

---

## Chain Table

| Source leak finding | Chain to | Impact |
|--------------------|----------|--------|
| Source map with API key | Use key directly → API access | High/Critical |
| Source map with auth logic | Find auth bypass route | Critical |
| Swagger → internal endpoints | Test undocumented admin routes | High |
| .git exposed | Full source history → all past secrets | Critical |
| build-info with git hash | CVE targeting exact version | High |
| .env with DB_PASSWORD | Direct database access | Critical |

---

## Tools

```bash
# git-dumper (reconstruct exposed .git)
pip3 install git-dumper
git-dumper "https://target.com/.git/" /tmp/repo/

# sourcemap-explorer (visualize what's in bundles)
npm install -g source-map-explorer
source-map-explorer main.js

# unwebpack-sourcemap (extract all source files)
npm install -g unwebpack-sourcemap

# trufflehog (secret scanning)
trufflehog filesystem /tmp/repo/
```

---

## Validation

✅ Source map: reconstructed TypeScript source contains API endpoints or hardcoded secrets
✅ Swagger: JSON contains internal endpoints not visible in UI
✅ .git exposed: git-dumper successfully clones repo, secrets in history
✅ .env exposed: DATABASE_URL, API_KEY, SECRET_KEY visible in plaintext

**Severity:**
- .env with credentials: Critical
- .git with secrets in history: Critical
- Source map with secrets: High
- Swagger with internal routes: Medium-High
- robots.txt only: Informational


