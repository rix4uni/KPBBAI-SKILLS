---
name: bb-codereview
description: Evidence-driven, critical-first source code security audit of a repository, local directory, archive, installer/binary, or browser extension. Use when the user asks for a security audit, source code review, vulnerability research, CVE/dependency review, hardcoded-secret hunt, or code review of a GitHub URL, .zip/.tar, .exe/.msi, Chrome Web Store extension, or project name. Covers safe acquisition and extraction, language detection, taint tracing to RCE/deserialization/command-injection/SSRF/path-traversal sinks, backup and cloud-storage review, dependency CVEs, safe PoCs, and the security_audit_report.md / security_findings.json / audit_coverage.md deliverables.
metadata:
  opencode/slash: "true"
---

# Source Code Security Review

## AUTONOMOUS OPERATION

Run all phases (0 → 1 → findings → report) without asking permission between them. Do not ask "should I look at the auth code?" — look at it. Do not ask "should I continue to Phase 2?" — continue.

- When you find a dangerous function: trace the full source-to-sink path immediately, then report it.
- When you find hardcoded credentials: test reachability (what service, is it live?) without asking.
- Only stop when: (1) the input type is genuinely ambiguous (e.g., multiple repos match a bare name — list them and ask once), or (2) a confirmed finding requires a destructive PoC you should not run unilaterally.

---

Act as a senior product security researcher. Audit the actual code. Never rely on the README, badges, prior issues, or scanner output as proof. A dangerous function is a lead, not a finding; a finding requires a traced source-to-sink path and a justified impact.

Authorized testing only. Default to read-only analysis. Never run untrusted binaries, never exfiltrate data, never touch production, never use discovered credentials against real services, and never run DoS tests against external hosts. Preserve original inputs untouched.

## Phase 0 — Intake and acquisition

Resolve `$ARGUMENTS` into a readable source tree before reviewing. Create an isolated workspace and never overwrite the user's file:

```bash
WORK="./security-audit/$(basename "${TARGET:-target}")-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$WORK"/{extracted,evidence,patches,audit-tests}
```

Classify the input:

### A. GitHub / Git URL

```bash
git clone --quiet "$URL" "$WORK/src"
cd "$WORK/src"
git rev-parse HEAD | tee "$WORK/commit.txt"
git log -10 --oneline
git branch -a
git status --short
```

Record the full commit hash. If the working directory already contains the checkout, audit it in place instead of cloning again.

### B. Bare project name (e.g. `karpenter-provider-aws`)

1. Check for a local directory of that name first.
2. Otherwise resolve the repository without guessing an owner:

```bash
gh search repos "$NAME" --limit 5 --json fullName,url,description 2>/dev/null
```

Clone the exact resolved URL, and state which owner/repo was chosen.

### C. Directory or file on disk

If the path is already readable source, use it directly. If it is an archive/installer/binary, go to D.

### D. Archive / installer / binary extraction (static only)

List before extracting. Reject entries containing absolute paths or `..` so extraction cannot escape the workspace. Extract inside the disposable workspace, never at `/`.

```bash
file "$INPUT"
case "$INPUT" in
  *.zip|*.jar|*.whl|*.apk|*.nupkg) unzip -l "$INPUT" | head -50; 7z x -y -o"$WORK/extracted" "$INPUT" ;;
  *.tar|*.tar.gz|*.tgz|*.tar.bz2|*.tar.xz) tar -tf "$INPUT" | head -50; tar -xf "$INPUT" -C "$WORK/extracted" ;;
  *.7z|*.rar) 7z l "$INPUT" | head -50; 7z x -y -o"$WORK/extracted" "$INPUT" ;;
  *.deb) dpkg-deb -x "$INPUT" "$WORK/extracted" ;;
  *.rpm) rpm2cpio "$INPUT" | cpio -idm -D "$WORK/extracted" ;;
  *.exe|*.msi) 7z l "$INPUT" | head -80; 7z x -y -o"$WORK/extracted" "$INPUT" ;;
esac
```

If extraction is incomplete, identify the packer and use the matching static extractor — **never execute the sample**:

| Type | Detection | Static extraction |
|---|---|---|
| NSIS / Inno Setup | `strings` shows NSIS/Inno | `7z x`, `innoextract` |
| PyInstaller | `PyInstaller` in strings | `pyinstxtractor-ng`, then decompile `.pyc` |
| .NET | `mscoree`, `BSJB` | `ilspycmd`, `dnSpy` (static) |
| Electron | `app.asar`, `resources/` | `npx @electron/asar extract app.asar app` |
| Go | `Go build ID` | `strings`, `go version -m` |
| Generic | — | `binwalk -e`, `strings -n 6`, entropy/carving |

If the input is an Electron `.exe`, extract `resources/app.asar`, then audit its `package.json` and JavaScript. For Windows installers, audit bundled scripts, updater logic, service definitions, and embedded URLs/keys.

### E. Chrome Web Store / extension URL

Extract the 32-char extension ID from the URL path, then download the CRX and strip its header:

```bash
ID="<id-from-url>"
curl -sSL -o "$WORK/ext.crx" \
  "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0.0.0&acceptformat=crx2,crx3&x=id%3D${ID}%26uc"
python3 - "$WORK/ext.crx" "$WORK/ext.zip" <<'PY'
import struct, sys
d = open(sys.argv[1], 'rb').read()
if d[:4] == b'Cr24':
    ver = struct.unpack('<I', d[4:8])[0]
    hdr = 12 + struct.unpack('<I', d[8:12])[0] if ver == 3 else \
          16 + struct.unpack('<I', d[8:12])[0] + struct.unpack('<I', d[12:16])[0]
    d = d[hdr:]
open(sys.argv[2], 'wb').write(d)
PY
unzip -q "$WORK/ext.zip" -d "$WORK/extracted"
```

Audit `manifest.json` (permissions, `host_permissions`, content scripts, `externally_connectable`, CSP), background/service-worker code, `eval`/`new Function`/remote script loading, message handlers, storage of secrets, and every network destination.

### F. Container image / package registry

```bash
docker save IMAGE -o "$WORK/image.tar" && tar -xf "$WORK/image.tar" -C "$WORK/extracted"
# or: crane export IMAGE "$WORK/rootfs.tar"
```

State that the environment may not support this and fall back to static metadata.

## Phase 1 — Repository discovery (do this before findings)

Your first substantive reply must describe the repository, its trust boundaries, and the critical areas you are about to examine — then examine them. Do not reply with a generic checklist.

Map the project:

```bash
find . -maxdepth 3 -type f -not -path './.git/*' | sort | head -200
find . -type f -not -path './.git/*' | sed -n 's/.*\.\([A-Za-z0-9_+-]*\)$/\1/p' | sort | uniq -c | sort -rn | head -25
```

If `cloc` exists, use it; otherwise the extension histogram above is the language detector.

Read the manifests and lockfiles that actually exist:

```text
pyproject.toml setup.py setup.cfg requirements*.txt Pipfile* poetry.lock uv.lock tox.ini
package.json package-lock.json yarn.lock pnpm-lock.yaml tsconfig.json
go.mod go.sum Cargo.toml Cargo.lock pom.xml build.gradle* gradle.lockfile
composer.json composer.lock Gemfile Gemfile.lock *.gemspec
*.csproj packages.lock.json Directory.Packages.props
Dockerfile* docker-compose*.yml .github/workflows/* .gitlab-ci.yml Makefile CMakeLists.txt
*.service *.timer *.conf *.yaml *.yml
```

Establish and record:

1. Supported language/runtime versions.
2. Framework and runtime architecture (library, CLI, daemon, worker, web app, plugin, desktop app).
3. Entry points (`main`, CLI parsers, HTTP handlers, message consumers, file watchers, cron).
4. Background workers, scheduled tasks, updaters, installers, and service wrappers.
5. Configuration loading and precedence.
6. Privileges the process runs under and whether it installs a privileged service.
7. Native extensions, external executables, FFI, shell-outs.
8. Trust boundaries: network, storage, database, local files, IPC, archive/manifest input, plugin input.
9. Whether an HTTP API or authentication layer actually exists — do not invent one.

Maintain `audit_coverage.md` from the start: components reviewed, findings, rejected leads, open questions.

## Phase 2 — Critical-first hunting

Investigate in this order. Do not jump to low-impact style issues.

### 2.1 Code execution primitives

```bash
grep -rInE --exclude-dir={.git,node_modules,vendor,dist,build,venv,.venv} \
  '\b(eval|exec|compile|__import__|importlib\.import_module|runpy\.(run_module|run_path)|globals|locals|getattr|setattr)\s*\(' .
```

For each hit: who controls the argument, what validation exists, what privileges does the process hold, and is the path remote, stored, config-driven, or local-admin-only? Dynamic plugin loading and template compilation are equivalent sinks.

### 2.2 Deserialization

```bash
grep -rInE --exclude-dir={.git,node_modules,vendor,dist,build} \
  '(pickle\.(load|loads)|cPickle|dill|cloudpickle|shelve\.open|marshal\.loads|yaml\.(load|unsafe_load|full_load)|jsonpickle|joblib\.load|torch\.load)' .
```

Also inspect PHP `unserialize`, Java `ObjectInputStream`/XStream/SnakeYAML, .NET `BinaryFormatter`/`TypeNameHandling`, Ruby `Marshal.load`/`YAML.load`, Node `node-serialize`/`funcster`.

Distinguish: safe JSON → safe `yaml.safe_load` → unsafe object construction → pickle of locally trusted state → pickle of data from remote storage/backups/DB. Only the last categories are candidate findings. Check signing/HMAC integrity and who can write the object.

### 2.3 Command execution

```bash
grep -rInE --exclude-dir={.git,node_modules,vendor,dist,build} \
  '(os\.(system|popen|execv|execve|spawn)|subprocess\.(Popen|run|call|check_call|check_output)|shell\s*=\s*True|child_process|exec\.Command|Runtime\.getRuntime|ProcessBuilder|system\(|shell_exec|passthru)' .
```

Trace every argv element. `shell=False` does not prevent argument injection (leading `-` options, `--config`, `--output`, `@file`, URL parsing tricks) or executable hijack via `PATH`. Check whether DB names, object keys, backup names, hostnames, or config values become arguments. Flag credentials passed in argv (visible in process listings).

### 2.4 Filesystem, archives, restore

```bash
grep -rInE --exclude-dir={.git,node_modules,vendor,dist,build} \
  '(open\(|os\.(open|remove|unlink|rename|replace|chmod|chown|makedirs|mkdir)|shutil\.(copy|copy2|move|rmtree)|pathlib|tempfile|tarfile|zipfile|extractall|extract\()' .
```

Check: canonicalization (`realpath`, `resolve`, `commonpath` not `commonprefix`), `..`, absolute paths, Windows separators, symlink/hardlink traversal, TOCTOU between check and write, archive entries with `../`, link targets, permissions, predictable temp names, cleanup of secrets. For backup/restore code, treat storage keys, manifests, and archive entry names as attacker-influenced if the store or another principal can write them.

### 2.5 SSRF and network

```bash
grep -rInE --exclude-dir={.git,node_modules,vendor,dist,build} \
  '(requests\.(get|post|put|request)|urlopen|httpx|aiohttp|socket\.(create_connection|socket)|ftplib|paramiko|verify\s*=\s*False)' .
```

Trace every URL/host/port/proxy/redirect. Distinguish admin-only config from attacker-influenced values (backup metadata, object keys, webhook URLs, redirects, DNS). Check loopback/private/link-local/metadata ranges, IPv4/IPv6 parsing, redirects, DNS rebinding, credential forwarding, and TLS verification.

### 2.6 Auth, authorization, privilege

Only if the project implements a service/API. Look for missing checks on privileged routes, spoofable identity headers (`X-Forwarded-*`, `X-User`, `X-Admin`), JWT verification (`alg:none`, missing signature, key confusion), session fixation, CSRF on state-changing routes, and service-to-service trust without authentication. For daemons/CLIs, map which local principal can trigger privileged operations.

### 2.7 Secrets and credentials

```bash
grep -rInE --exclude-dir={.git,node_modules,vendor,dist,build} \
  '(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|token|bearer|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|github_pat_|xox[baprs]-|-----BEGIN [A-Z ]*PRIVATE KEY-----)' . \
  | grep -viE '(example|dummy|placeholder|changeme|test|fake|sample|redacted|<[^>]+>)'
grep -rInE --exclude-dir={.git,node_modules,vendor,dist,build} \
  '(postgres(ql)?|mysql|mongodb|redis|amqp)://[^[:space:]/]+:[^[:space:]@]+@' .
grep -rInE --exclude-dir={.git,node_modules,vendor,dist,build} \
  '\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' . | head -50
```

If available, run `trufflehog filesystem . --no-update --json` (do not let it upload or contact external validators). Classify each hit: active secret vs test placeholder vs example. Never use a found credential against a real service; recommend rotation and safe verification.

### 2.8 Backup / restore / cloud storage

For backup products and any project with remote storage:

- Trace backup create → compress → encrypt → upload → download → verify → restore.
- Check whether manifests/metadata are authenticated, not merely checksummed. A checksum fetched from the same attacker-writable store provides no authenticity.
- Check archive extraction destinations and link handling during restore.
- Check retention/deletion authorization: can an untrusted party delete or overwrite backups?
- Check object-key/path construction, endpoint configuration, TLS verification, credential scopes, redirects, multipart handling, and cross-tenant key reuse.
- Distinguish repository defects from deployment misconfiguration.

### 2.9 Language-specific hotspots

| Language | High-signal sinks |
|---|---|
| Python | `pickle`, `yaml.load`, `eval/exec`, `subprocess(shell=True)`, `tarfile.extractall`, `tempfile.mktemp`, `importlib`, `jinja2.Template`, `requests(verify=False)` |
| JavaScript/TS | `child_process`, `vm`, `new Function`, dynamic `require`, prototype pollution (`__proto__`, `constructor[prototype]`), `eval`, unsafe `innerHTML` |
| Go | `os/exec`, `text/template`, `archive/tar`, `filepath.Join` with user input, `net/http` redirects, `unsafe` |
| Java | `Runtime.exec`, `ProcessBuilder`, `ObjectInputStream`, XStream/SnakeYAML, SpEL/JNDI, `XMLDecoder` |
| PHP | `system/exec/shell_exec/passthru`, `eval/assert`, `include/require` with variables, `unserialize`, `preg_replace /e` |
| Ruby | `eval`, `send`, `system/backticks`, `Marshal.load`, `YAML.load`, `constantize` |
| C#/.NET | `BinaryFormatter`, `TypeNameHandling.All`, `Process.Start`, `XmlDocument` with resolver enabled |
| C/C++ | `system/popen`, `strcpy/sprintf`, format strings, integer overflows on sizes |

### 2.10 SQL

Inspect query construction. f-strings near SQL are not automatically injection; prove that input changes query structure. Parameterized values are safe; dynamic identifiers/`ORDER BY`/table names need allowlists. Check subprocess `psql` invocations and credentials in args.

## Phase 3 — Taint tracing

For every candidate, write the path explicitly:

```text
Untrusted source (HTTP field, storage object, archive entry, DB row, config, argv, IPC)
    ↓ transformation / decoding
Validation or sanitization (and whether it is bypassable)
    ↓ intermediate calls
Security-sensitive sink
    ↓
Impact (RCE, file write, credential disclosure, SSRF, integrity loss)
```

Examine the full function, its callers, wrappers, and alternate entry points. Verify that a control actually executes on the path (not just exists nearby). Look for a second route to the same sink that skips the control.

## Phase 4 — Dependencies and CVEs

Identify declared and locked versions. Then, where tooling/network allow:

```bash
pip-audit -r requirements.txt          # Python
osv-scanner -r .                      # multi-ecosystem
npm audit --omit=dev                  # Node
govulncheck ./...                     # Go
cargo audit                           # Rust
composer audit                        # PHP
bundle audit check --update           # Ruby
```

If a tool is absent, query OSV for exact versions instead of guessing:

```bash
curl -sS https://api.osv.dev/v1/query -d '{"package":{"name":"<pkg>","ecosystem":"PyPI"},"version":"<ver>"}' | jq .
```

For each CVE establish: affected range, fixed version, vulnerable function, whether the application calls it, whether attacker input reaches it, deployment prerequisites, and patch availability. Separate **applicable**, **potentially applicable**, **not applicable**, and **unverified environment**. Do not report every outdated dependency.

## Phase 5 — Git history

```bash
git log --oneline --all --grep='security\|CVE\|RCE\|injection\|pickle\|traversal\|symlink\|permission\|TLS\|credential\|race\|restore'
git log -p -- <sensitive-file> | head -200
```

Inspect actual diffs, not just messages. Check whether a security fix was reverted, incomplete, or bypassable via another path, and whether the current checkout includes it. An old CVE is not present merely because it once affected the project.

## Phase 6 — Safe validation

Use the weakest test that proves the mechanism:

- Unit test calling the vulnerable helper with a synthetic payload.
- Local mock HTTP/storage server for SSRF or remote-data paths.
- Temporary directory for traversal/archive tests.
- Isolated DB/container for SQL or restore tests.
- Harmless markers (`id`, `echo marker`, a temp file path) — no reverse shells, no downloads, no persistence.
- For RCE, prove input reaches the execution primitive without launching an interactive shell.

Never test external infrastructure, never run the untrusted binary, never submit credentials. If a test is unsafe or impossible, record it as unverified and explain what is missing.

## Phase 7 — Severity

CVSS 3.1 (state the version). Rate by demonstrated impact and prerequisites, not by function name.

- **Critical** — unauthenticated RCE, host compromise, critical infrastructure/credential compromise, or a demonstrably exploitable dependency path.
- **High** — authenticated RCE, arbitrary file write → escalation, major backup-data access, SSRF to sensitive services, serious auth bypass/privilege escalation.
- **Medium** — limited traversal/SSRF/disclosure, meaningful DoS, sensitive operational info exposure.
- **Low** — limited info exposure, defense-in-depth gaps, minor misconfiguration.

Explain every rating and the assumptions behind it.

## Phase 8 — Deliverables

Create these in the audit workspace root (never silently edit project source):

### `security_audit_report.md`

```markdown
# Security Audit — <project>
- Repository:
- Audited commit:
- Audit date:
- Language / runtime:
- Environment:

## Executive summary
## Scope and method
## Findings (Critical → High → Medium → Low)
## Dependency vulnerabilities
## Unverified candidates
## Attack surfaces investigated
## Tools and tests actually executed
## Areas not examined / limitations
## Recommended remediation order
```

### `security_findings.json`

Valid JSON, evidence only, `null` where unknown:

```json
{
  "id": "PYSEC-001",
  "title": "...",
  "severity": "Critical|High|Medium|Low",
  "confidence": "Confirmed|High|Moderate|Low",
  "cwe": ["CWE-..."],
  "cvss": null,
  "affected_file": "path/to/file",
  "affected_lines": {"start": 1, "end": 10},
  "affected_function": "name",
  "vulnerability_type": "...",
  "attacker_controlled_input": "...",
  "vulnerable_operation": "...",
  "attack_prerequisites": [],
  "impact": [],
  "proof_of_concept": "...",
  "remediation": "...",
  "references": [],
  "status": "Confirmed|Probable|Unverified"
}
```

### `audit_coverage.md`

Table of areas — code execution, deserialization, subprocesses, filesystem, backup/restore, network/SSRF, cloud storage, credentials, crypto, SQL, concurrency, dependencies, authn/authz, tests — with files reviewed, what was done, and limitations. Never claim full coverage when components are unreviewed.

### `patches/` and `audit-tests/`

Only for confirmed issues. Minimal diffs plus a test that fails before and passes after. Explain compatibility impact. Do not modify originals.

### Finding format in the report

For each finding include: ID, severity, confidence, CWE, CVSS, file/lines/function, vulnerability class, executive summary, smallest vulnerable excerpt, root cause, source-to-sink trace, preconditions, realistic exploitation scenario, safe PoC, impact, severity justification, remediation, regression test, verified references.

## Rules

1. Never fabricate a finding, CVE, line number, exploit, or scan result.
2. Read complete functions and callers; no one-line verdicts.
3. Do not report `pickle`/`eval`/`subprocess` merely for existing — prove reachability and impact.
4. A checksum is not authenticity; a 200 is not a vulnerability; a banner is not confirmation.
5. Account for soft-404s, fail-open handlers, and checks that run after the sink.
6. Prefer INCONCLUSIVE over an unsupported guess; state unresolved questions.
7. Do not stop after the first critical finding — map independent surfaces and keep auditing.
8. Do not modify the audited source during discovery; keep patches separate.
9. Never execute untrusted binaries or extracted payloads; static analysis only.
10. Clearly separate demonstrated behavior from assumptions.


---

## [OWASP Top 10 Code Review Checklist (zebbern)] Additional Techniques

# OWASP Top 10 Code Security Review Checklist

A systematic security review based on the OWASP Top 10 (2021) standard. Each item includes: vulnerability description, typical vulnerable code, inspection checkpoints, and remediation examples. Designed for security-focused code review of web applications.

## Usage

Provide the code files or code snippets to review, and specify which OWASP categories to check (or request a full review) to receive an item-by-item audit report.

**Example prompts:**
- "Check this code for SQL injection risks"
- "Run a full OWASP Top 10 security review on this project"
- "Does this API endpoint have any SSRF vulnerabilities?"

---

## Quick Reference

| ID | Category | Key Check |
|----|----------|-----------|
| A01 | Broken Access Control | Does every endpoint verify the current user's identity? Can users access others' data by changing IDs? |
| A02 | Cryptographic Failures | Are passwords hashed with bcrypt/argon2? Are secrets hardcoded? |
| A03 | Injection | String-concatenated SQL? `shell=True`? Unescaped template output? |
| A04 | Insecure Design | Is rate limiting in place? Can critical workflows be bypassed? |
| A05 | Security Misconfiguration | DEBUG enabled? Stack traces in error pages? Default credentials? |
| A06 | Vulnerable Components | Any CVEs from `pip audit` / `npm audit`? |
| A07 | Authentication Failures | Is JWT signature verified? Can tokens be revoked? Is MFA available? |
| A08 | Integrity Failures | Any `pickle.loads` deserializing untrusted data? |
| A09 | Logging & Monitoring Failures | Are plaintext passwords in logs? Are failed logins recorded? |
| A10 | SSRF | Are user-supplied URLs filtered against internal IPs? |

---

## Review Process SOP

**Core principle: prefer false positives over missed true positives.**

1. **Define scope** â€” Identify the files, modules, or code snippets to review
2. **Full coverage check** â€” Scan through A01-A10 sequentially. **Every item must appear in the report** (mark items with no findings as pass). The default behavior is to only report issues found â€” this process requires full coverage to ensure nothing is missed
3. **Risk classification** â€” Label each finding:
   - RED High: Directly exploitable (RCE, SQL injection, SSRF reaching internal networks, plaintext password storage)
   - YELLOW Medium: Exploitable under specific conditions (missing rate limiting, weak password policy, static tokens)
   - GREEN Low: Defense-in-depth gap with no direct exploitation path (missing security headers, insufficient logging)
4. **Every finding must include ready-to-use fix code** (actual code, not just a description). Reference specific `file:line_number`
5. **Output the review report** â€” Use the template below, findings sorted by severity descending, with a prioritized remediation list at the end

---

## A01:2021 â€” Broken Access Control

**Risk:** Users can access other users' data or perform unauthorized operations.

**Checkpoints:**
- [ ] Does every API endpoint enforce authorization?
- [ ] Are there IDOR vulnerabilities (Insecure Direct Object References) â€” can users access others' data by modifying ID parameters?
- [ ] Do admin interfaces verify roles?
- [ ] Is access control enforced server-side (not just by hiding UI elements)?
- [ ] Is the CORS policy overly permissive?

### Vulnerable Code Example

```python
# âŒ Vulnerable: No authorization check â€” any user can view others' orders by changing user_id
@app.route("/api/orders/<user_id>")
def get_orders(user_id):
    orders = db.query(f"SELECT * FROM orders WHERE user_id = {user_id}")
    return jsonify(orders)
```

### Remediation Example

```python
# âœ… Fixed: Verify the authenticated user can only access their own data
@app.route("/api/orders")
@login_required
def get_orders():
    current_user_id = get_current_user().id
    orders = db.query("SELECT * FROM orders WHERE user_id = %s", (current_user_id,))
    return jsonify(orders)
```

---

## A02:2021 â€” Cryptographic Failures

**Risk:** Sensitive data (passwords, credit card numbers, personal information) is unencrypted or uses weak cryptographic algorithms.

**Checkpoints:**
- [ ] Are passwords stored using secure hashing (bcrypt/scrypt/argon2) rather than MD5/SHA1?
- [ ] Is HTTPS enforced for sensitive data in transit?
- [ ] Are encryption keys hardcoded in the source code?
- [ ] Are deprecated cryptographic algorithms in use (DES, RC4, MD5)?
- [ ] Are sensitive database fields encrypted at rest?

### Vulnerable Code Example

```python
# âŒ Vulnerable: MD5 for password storage, hardcoded secret key
import hashlib

SECRET_KEY = "my-secret-key-123"

def save_password(password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    db.save(hashed)
```

### Remediation Example

```python
# âœ… Fixed: bcrypt for password hashing, secret key from environment variable
import bcrypt
import os

SECRET_KEY = os.environ["SECRET_KEY"]

def save_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    db.save(hashed)
```

---

## A03:2021 â€” Injection

**Risk:** User input is concatenated directly into SQL, OS commands, LDAP queries, etc., allowing attackers to execute arbitrary queries or commands.

**Checkpoints:**
- [ ] Do SQL queries use parameterized queries / ORM (not string concatenation)?
- [ ] Are there `os.system()` or `subprocess.call(shell=True)` calls that concatenate user input?
- [ ] Does template rendering properly escape user input (preventing XSS)?
- [ ] Are special characters filtered in LDAP / XPath / NoSQL queries?
- [ ] Are unfiltered user inputs logged directly (log injection)?

### SQL Injection â€” Vulnerable Code

```python
# âŒ Vulnerable: String-concatenated SQL â€” attacker can input ' OR 1=1 --
@app.route("/api/user")
def get_user():
    username = request.args.get("username")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    result = db.execute(query)
    return jsonify(result)
```

### SQL Injection â€” Remediation

```python
# âœ… Fixed: Parameterized query
@app.route("/api/user")
def get_user():
    username = request.args.get("username")
    result = db.execute(
        "SELECT * FROM users WHERE username = %s",
        (username,)
    )
    return jsonify(result)
```

### Command Injection â€” Vulnerable Code

```python
# âŒ Vulnerable: User input concatenated directly into shell command
import os

def ping_host(host):
    os.system(f"ping -c 4 {host}")
```

### Command Injection â€” Remediation

```python
# âœ… Fixed: Use subprocess with list arguments, shell disabled
import subprocess
import re

def ping_host(host):
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        raise ValueError("Invalid hostname")
    subprocess.run(["ping", "-c", "4", host], check=True)
```

---

## A04:2021 â€” Insecure Design

**Risk:** Business logic design flaws that cannot be fixed by a perfect implementation.

**Checkpoints:**
- [ ] Do critical operations have rate limiting?
- [ ] Can the password reset flow be abused (username enumeration, verification code brute-force)?
- [ ] Do sensitive operations (payments, transfers) require secondary confirmation?
- [ ] Are there batch operation endpoints with no upper limit?
- [ ] Can business workflows be executed out of order (e.g., skipping payment to complete an order)?

### Vulnerable Code Example

```python
# âŒ Vulnerable: No attempt limit on verification code â€” can be brute-forced
@app.route("/api/verify-code", methods=["POST"])
def verify_code():
    code = request.json["code"]
    stored_code = session.get("verification_code")
    if code == stored_code:
        return jsonify({"status": "verified"})
    return jsonify({"status": "invalid"}), 400
```

### Remediation Example

```python
# âœ… Fixed: Added attempt limit and expiration
@app.route("/api/verify-code", methods=["POST"])
def verify_code():
    attempts = session.get("verify_attempts", 0)
    if attempts >= 5:
        return jsonify({"error": "Too many attempts, please request a new code"}), 429

    code = request.json["code"]
    stored = session.get("verification_code")
    expire_at = session.get("code_expire_at", 0)

    if time.time() > expire_at:
        return jsonify({"error": "Verification code has expired"}), 400

    session["verify_attempts"] = attempts + 1

    if code == stored:
        session.pop("verify_attempts", None)
        return jsonify({"status": "verified"})
    return jsonify({"status": "invalid"}), 400
```

---

## A05:2021 â€” Security Misconfiguration

**Risk:** Applications or servers use default configurations, enable unnecessary features, or expose sensitive information in error messages.

**Checkpoints:**
- [ ] Is DEBUG mode disabled in production?
- [ ] Do error pages leak stack traces, database versions, etc.?
- [ ] Are default credentials still in use?
- [ ] Do HTTP responses include security headers (X-Frame-Options, Content-Security-Policy, etc.)?
- [ ] Are unnecessary HTTP methods (PUT, DELETE, TRACE) disabled?
- [ ] Is directory listing disabled?

### Vulnerable Code Example

```python
# âŒ Vulnerable: DEBUG enabled in production, leaking sensitive information
app = Flask(__name__)
app.config["DEBUG"] = True
app.config["SECRET_KEY"] = "default-secret"

@app.errorhandler(500)
def error_handler(e):
    return jsonify({"error": str(e), "traceback": traceback.format_exc()}), 500
```

### Remediation Example

```python
# âœ… Fixed: Configuration from environment variables, DEBUG off in production
import os

app = Flask(__name__)
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]

@app.errorhandler(500)
def error_handler(e):
    app.logger.error(f"Internal error: {e}")
    return jsonify({"error": "Internal server error, please try again later"}), 500
```

---

## A06:2021 â€” Vulnerable and Outdated Components

**Risk:** Using third-party libraries or framework versions with known vulnerabilities.

**Checkpoints:**
- [ ] Do dependencies have known CVEs (scan with `pip audit`, `npm audit`, `snyk`, etc.)?
- [ ] Are there dependencies that haven't been updated in a long time?
- [ ] Are any unmaintained libraries in use?
- [ ] Are lock files (package-lock.json / requirements.txt) under version control?
- [ ] Is there an automated dependency update mechanism (Dependabot, etc.)?

### Scan Commands

```bash
# Python projects
pip audit

# Node.js projects
npm audit

# General scanning
# Use open-source tools like trivy or grype to scan container/project dependencies
```

### Remediation Guidance

```bash
# Update vulnerable packages
pip install --upgrade package_name

# Auto-fix npm vulnerabilities
npm audit fix

# Pin dependency versions to prevent implicit upgrades
pip freeze > requirements.txt
```

---

## A07:2021 â€” Identification and Authentication Failures

**Risk:** Authentication mechanisms have flaws that allow brute-force attacks, credential stuffing, or session hijacking.

**Checkpoints:**
- [ ] Is there a login failure rate limit (account lockout / delay)?
- [ ] Is the password policy reasonable (minimum length, complexity requirements)?
- [ ] Are session tokens invalidated on logout?
- [ ] Are session IDs sufficiently random and unpredictable?
- [ ] Is MFA supported for sensitive operations?
- [ ] Are JWT tokens validated for signature and expiration?

### Vulnerable Code Example

```python
# âŒ Vulnerable: JWT signature not verified, accepts alg=none
import jwt

def verify_token(token):
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload
```

### Remediation Example

```python
# âœ… Fixed: Enforce signature and expiration verification, specify algorithm
import jwt
import os

JWT_SECRET = os.environ["JWT_SECRET"]

def verify_token(token):
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "sub"]}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired")
    except jwt.InvalidTokenError:
        raise AuthError("Invalid token")
```

---

## A08:2021 â€” Software and Data Integrity Failures

**Risk:** Failure to verify the integrity of software updates, critical data, or CI/CD pipelines, enabling supply chain attacks or data tampering.

**Checkpoints:**
- [ ] Does deserialization use unsafe methods (e.g., Python's `pickle.loads` on untrusted data)?
- [ ] Does the CI/CD pipeline have integrity verification?
- [ ] Do third-party CDN resources use SRI (Subresource Integrity)?
- [ ] Are modifications to critical configuration files audit-logged?
- [ ] Does the auto-update mechanism verify signatures?

### Vulnerable Code Example

```python
# âŒ Vulnerable: Deserializing untrusted data â€” can lead to remote code execution
import pickle

@app.route("/api/import", methods=["POST"])
def import_data():
    data = pickle.loads(request.data)
    process(data)
    return "OK"
```

### Remediation Example

```python
# âœ… Fixed: Use a safe data format (JSON), refuse to deserialize arbitrary objects
import json

@app.route("/api/import", methods=["POST"])
def import_data():
    try:
        data = json.loads(request.data)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON format"}), 400
    process(data)
    return "OK"
```

---

## A09:2021 â€” Security Logging and Monitoring Failures

**Risk:** Lack of security event logging and monitoring, preventing timely detection and response to attacks.

**Checkpoints:**
- [ ] Are login successes and failures logged?
- [ ] Are sensitive operations (permission changes, data deletion) audit-logged?
- [ ] Are passwords, tokens, or other sensitive data accidentally included in logs?
- [ ] Are logs tamper-resistant (centralized storage, append-only writes)?
- [ ] Are alerts configured for anomalous behavior (e.g., burst of failed logins)?

### Vulnerable Code Example

```python
# âŒ Vulnerable: No logging on login failure, and plaintext password in logs
def login(username, password):
    user = db.get_user(username)
    if not user or not check_password(password, user.password_hash):
        print(f"Login failed for {username} with password {password}")
        return None
    return create_session(user)
```

### Remediation Example

```python
# âœ… Fixed: Log security events without logging sensitive data
import logging

security_logger = logging.getLogger("security")

def login(username, password):
    user = db.get_user(username)
    if not user or not check_password(password, user.password_hash):
        security_logger.warning(
            "Login failed",
            extra={"username": username, "ip": request.remote_addr}
        )
        return None
    security_logger.info(
        "Login successful",
        extra={"username": username, "ip": request.remote_addr}
    )
    return create_session(user)
```

---

## A10:2021 â€” Server-Side Request Forgery (SSRF)

**Risk:** The application accepts user-provided URLs and makes server-side requests, allowing attackers to access internal network resources or cloud metadata.

**Checkpoints:**
- [ ] Are there features that accept user-supplied URLs and make server-side requests (image fetching, URL previews, webhook callbacks)?
- [ ] Is the URL protocol restricted (allow only http/https)?
- [ ] Are internal IP ranges filtered (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)?
- [ ] Is the cloud metadata address blocked (169.254.169.254)?
- [ ] Is there protection against DNS rebinding attacks?

### Vulnerable Code Example

```python
# âŒ Vulnerable: Directly requesting user-supplied URL â€” can access internal network and cloud metadata
import requests

@app.route("/api/fetch-url")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text
```

### Remediation Example

```python
# âœ… Fixed: Validate URL protocol and target address, block internal network access
import requests
import ipaddress
from urllib.parse import urlparse
import socket

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return False
    except (socket.gaierror, ValueError):
        return False
    return True

@app.route("/api/fetch-url")
def fetch_url():
    url = request.args.get("url")
    if not is_safe_url(url):
        return jsonify({"error": "Access to this address is not allowed"}), 403
    response = requests.get(url, timeout=10, allow_redirects=False)
    return response.text
```

---

## Review Report Template

After completing the review, output a report in the following format. **All 10 items must appear** â€” mark items with no findings as pass:

```
# OWASP Top 10 Security Review Report

## Review Summary
- Scope: [list of files/modules]
- Date: [date]
- Risk summary: RED High x | YELLOW Medium x | GREEN Low x | PASS No findings x

## Findings (sorted by severity, descending)

### [Severity] [OWASP ID] â€” [Issue Title]
- **Location:** [file:line_number]
- **Description:** [issue description]
- **Impact:** [potential consequences]
- **Fix:** (ready-to-use code, not just a description)

### PASS A0X â€” [Category] â€” No issues found

## Remediation Priority
1. [Most urgent fix â€” rationale]
2. [Next priority â€” rationale]
3. ...
```

---

## Recommended Open-Source Security Tools

| Tool | Language | Purpose |
|------|----------|---------|
| `bandit` | Python | Python code security scanning |
| `semgrep` | Multi-language | Rule-based code scanning |
| `eslint-plugin-security` | JavaScript | JS security rules |
| `npm audit` / `pip audit` | JS / Python | Dependency vulnerability scanning |
| `trivy` | Multi-language | Container and dependency scanning |
| `sqlmap` | â€” | SQL injection detection |
| `OWASP ZAP` | â€” | Web application dynamic scanning |

> **Note:** This checklist is a supplementary review tool and does not replace professional penetration testing. For high-security systems, combine automated scanning + manual code audit + penetration testing.

