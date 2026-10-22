---
name: code-review
description: Evidence-driven, critical-first source code security audit of a repository, local directory, archive, installer/binary, or browser extension. Use when the user asks for a security audit, source code review, vulnerability research, CVE/dependency review, hardcoded-secret hunt, or code review of a GitHub URL, .zip/.tar, .exe/.msi, Chrome Web Store extension, or project name. Covers safe acquisition and extraction, language detection, taint tracing to RCE/deserialization/command-injection/SSRF/path-traversal sinks, backup and cloud-storage review, dependency CVEs, safe PoCs, and the security_audit_report.md / security_findings.json / audit_coverage.md deliverables.
metadata:
  opencode/slash: "true"
---

# Source Code Security Review

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
