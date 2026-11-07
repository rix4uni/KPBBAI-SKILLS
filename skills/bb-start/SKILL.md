---
name: bb-start
description: Entry point router for every bug bounty hunt. Read this FIRST. Analyzes target context and tells you exactly which skills to load — prevents wasting time reading irrelevant skills.
---

# Bug Bounty Hunt Router — Read This First

You are starting a bug bounty hunt. Do NOT load any other skill until you have read this file completely and built your skill list from the decision trees below.

## How This Works

This skill library has 41 skills organized with a prefix system. Each prefix tells you the category:

| Prefix | Category | Load when |
|---|---|---|
| `vuln-` | Vulnerability hunting | Target has that specific attack surface |
| `recon-` | Reconnaissance | Gathering info, mapping the target |
| `exploit-` | Exploitation | Escalating a confirmed finding to full impact |
| `mobile-` | Mobile app testing | Target is an Android or iOS application |
| `cloud-` | Cloud infrastructure attack | Target runs on AWS / GCP / Azure |
| `infra-attack` | On-prem infrastructure | Target has VPN, VMware, Kubernetes, internal services |
| `platform-` | Tech-stack specific | Target runs a specific framework or enterprise product |
| `bb-` | Bug bounty process | Workflow, methodology, reporting, triage |
| `web3-` | Blockchain / smart contracts | Target is DeFi, NFT, or crypto protocol |

**Rule**: Never load more than what the target's attack surface justifies. A web app with no cloud exposure does not need `cloud-attack`. A simple REST API does not need `mobile-android`.

---

## Step 1 — Always Load These First (Every Hunt)

```
bb-triage         ← Validate the target is in-scope and worth hunting
recon-workflow    ← Recon methodology and what to map first
recon-tools       ← Actual tools: subfinder, nuclei, shodan, JS analysis, source leak
```

Run recon first. What you find during recon determines everything below.

---

## Step 2 — Load Based on What You Find During Recon

Work through each category. If the target has that surface, add those skills to your list.

### Authentication & Access

| If you see | Load |
|---|---|
| Login page, registration, password reset, MFA, SSO | `vuln-auth` |
| JWT tokens in requests | `vuln-auth` (contains full JWT section) |
| 401 / 403 responses on endpoints | `vuln-auth` (contains 401/403 bypass) |
| OAuth / SAML flows | `vuln-auth` (contains OAuth, SAML, ATO sections) |
| Rate limiting on login | `vuln-auth` (contains brute force and CAPTCHA bypass) |
| Okta / SSO identity provider | `platform-okta` |

### Input Handling — Reflected / Stored

| If you see | Load |
|---|---|
| Any parameter reflected in HTML response | `vuln-xss` |
| Template engines (Jinja2, Freemarker, Thymeleaf, Pebble, Twig) | `vuln-ssi` |
| Expression language in responses (`${...}`, `#{...}`) | `vuln-ssi` |
| LDAP queries / directory services | `vuln-ssi` (contains LDAP injection) |
| XSLT transformations | `vuln-ssi` (contains XSLT injection) |
| CSP headers present | `vuln-xss` (contains CSP bypass section) |
| DOMPurify used client-side | `vuln-xss` (contains DOMPurify bypass section) |

### Database Interaction

| If you see | Load |
|---|---|
| SQL errors, numeric IDs, search filters | `vuln-sqli` |
| MongoDB, Redis, CouchDB, ElasticSearch | `vuln-nosql` |
| JSON query parameters, `$where`, `$regex` patterns | `vuln-nosql` |

### File / Path Operations

| If you see | Load |
|---|---|
| File upload functionality | `vuln-file-upload` |
| Path parameters, `../`, file preview endpoints | `vuln-path-traversal` |
| XML input accepted anywhere | `vuln-xxe` |
| File includes, LFI indicators | `vuln-path-traversal` |

### Server-Side Request Handling

| If you see | Load |
|---|---|
| Server fetches URLs you provide (webhooks, PDF gen, image import) | `vuln-ssrf` |
| URL parameter that server visits | `vuln-ssrf` |
| Open redirect (`redirect=`, `next=`, `url=`) | `vuln-open-redirect` |
| User lands on URL you control | `vuln-open-redirect` |

### API Endpoints

| If you see | Load |
|---|---|
| REST API (any) | `vuln-api` |
| Undocumented endpoints, shadow routes, v1/v2 endpoints | `vuln-api` |
| GraphQL endpoint (`/graphql`, `/api/graphql`) | `vuln-graphql` |
| gRPC, WebSocket, SPA with token auth | `vuln-api` |

### Access Control / Object References

| If you see | Load |
|---|---|
| IDs in URL or body you can manipulate (user IDs, resource IDs) | `vuln-idor` |
| Multi-tenant app, user roles, admin vs regular user | `vuln-idor` |
| Business workflows with order/state/price manipulation | `vuln-business-logic` |
| Coupon codes, referral systems, payment flows | `vuln-business-logic` |
| Multi-step processes (checkout, approval flows) | `vuln-business-logic` |

### HTTP Protocol Level

| If you see | Load |
|---|---|
| Load balancers, CDN, reverse proxies in front of target | `vuln-http` |
| Caching headers (`X-Cache`, `Cache-Control`, `Vary`) | `vuln-http` |
| Transfer-Encoding or Content-Length desync possible | `vuln-http` |
| Host header reflected in response or used for routing | `vuln-http` |
| HTTP/2 endpoint | `vuln-http` |
| URL parameters duplicated or server-parsed differently | `vuln-http` |

### Stateful / Timing Attacks

| If you see | Load |
|---|---|
| Concurrent operations on same resource (order, transfer, vote) | `vuln-race-condition` |
| Token generation with timing dependencies | `vuln-race-condition` |

### Serialization

| If you see | Load |
|---|---|
| Java serialization headers (`ac ed 00 05`) | `vuln-deserialization` |
| PHP `O:` serialized strings | `vuln-deserialization` |
| Python pickle, Ruby Marshal | `vuln-deserialization` |
| .NET ViewState | `vuln-deserialization` |

### JavaScript / Client-Side

| If you see | Load |
|---|---|
| Node.js backend | `vuln-prototype-pollution` |
| Client-side JS with object merge / deep clone functions | `vuln-prototype-pollution` |
| NPM packages, `package.json` exposed | `vuln-supply-chain` |
| CI/CD pipelines, GitHub Actions, build scripts | `vuln-supply-chain` |

### Forms / State Changes

| If you see | Load |
|---|---|
| Any state-changing POST without CSRF token | `vuln-csrf` |
| SameSite=None cookies | `vuln-csrf` |

---

## Step 3 — Load Based on Target Platform / Technology

| Target runs | Load |
|---|---|
| WordPress | `platform-frameworks` (contains WordPress section) |
| Laravel | `platform-frameworks` (contains Laravel section) |
| Node.js / Express | `platform-frameworks` (contains Node.js section) |
| Next.js | `platform-frameworks` (contains Next.js section) |
| Spring Boot | `platform-frameworks` (contains Spring Boot section) |
| IIS / ASP.NET | `platform-frameworks` (contains ASP.NET + IIS sections) |
| SharePoint | `platform-sharepoint` |
| Okta / SAML SSO | `platform-okta` |

---

## Step 4 — Load Based on Target Infrastructure

| Target infrastructure | Load |
|---|---|
| AWS (S3, EC2, Lambda, IAM, metadata endpoint) | `cloud-attack` |
| GCP / Azure | `cloud-attack` |
| Cloud IAM misconfig | `cloud-attack` |
| Kubernetes cluster | `infra-attack` |
| VPN endpoint (Cisco, Palo Alto, Fortinet) | `infra-attack` |
| VMware vCenter | `infra-attack` |

---

## Step 5 — Mobile Apps

| If target is | Load |
|---|---|
| Android APK / Play Store app | `mobile-android` |
| iOS IPA / App Store app | `mobile-ios` |

---

## Step 6 — Web3 / Blockchain

| If target is | Load |
|---|---|
| Smart contract / Solidity | `web3-audit` |
| DeFi protocol, DEX, lending | `web3-audit` |
| NFT platform | `web3-audit` |
| Meme coin / token contract | `web3-audit` |

---

## Step 7 — After Finding a Vulnerability

| Situation | Load |
|---|---|
| Confirmed RCE / command execution | `exploit-rce` |
| Got shell / initial access | `exploit-post` |
| Need to validate finding OR write report | `bb-triage` (contains full report writing section) |

---

## Support Skills — Load On Demand

Do NOT load these at the start. Load only when specifically needed:

| Skill | Load when |
|---|---|
| `pentest-tools` | Need Burp Suite config, specific tool syntax, Metasploit modules, JS analysis commands |
| `security-arsenal` | Need a quick reference for a technique not covered elsewhere |
| `bb-techniques` | Need advanced BB techniques AND community tips/tricks (merged) |
| `bb-codereview` | Have source code access and doing a code review |
| `bb-hunting` | Running a systematic full-scope hunt without a specific target surface |
| `ctf-techniques` | Target is a CTF challenge (heap, crypto, steganography) — not normal BB |

---

## Skill Load Order for a Typical Web App Hunt

```
Phase 1 — Recon
  → bb-triage
  → recon-workflow
  → recon-tools

Phase 2 — Surface Mapping (from recon findings)
  → vuln-auth          (if login exists)
  → vuln-api           (if API found)
  → vuln-idor          (if user resources)
  → vuln-xss           (if input reflection)
  → vuln-sqli          (if database interaction)
  → vuln-ssrf          (if URL handling)
  → vuln-file-upload   (if upload exists)

Phase 3 — Deep Exploitation
  → vuln-business-logic  (after understanding app logic)
  → vuln-http            (if proxies/CDN present)
  → vuln-race-condition  (if multi-step flows)

Phase 4 — Escalation
  → exploit-rce        (if RCE confirmed)
  → exploit-post       (if shell obtained)

Phase 5 — Reporting
  → bb-triage          (validate finding + write Bugcrowd-format report)
```

---

## Quick Reference — Full Skill List

```
ENTRY POINT
  bb-start              ← this file (always first)

BUG BOUNTY PROCESS (bb-)
  bb-triage             ← always load — validates targets + writes reports
  bb-workflow           ← full BB engagement workflow + phases
  bb-techniques         ← advanced BB techniques + community tips
  bb-hunting            ← systematic hunt system
  bb-codereview         ← source code review

RECON (recon-)
  recon-workflow        ← recon methodology
  recon-tools           ← subfinder, shodan, nuclei, scanning, source leak

VULNERABILITIES (vuln-)
  vuln-auth             ← auth bypass, JWT, OAuth, MFA, session, brute force
  vuln-api              ← REST API, shadow API, SPA, gRPC, WebSocket
  vuln-graphql          ← GraphQL introspection, injection, auth bypass
  vuln-xss              ← reflected/stored/DOM XSS, CSP bypass, DOMPurify
  vuln-sqli             ← SQL injection (all types)
  vuln-nosql            ← MongoDB, Redis, NoSQL injection
  vuln-ssrf             ← SSRF, cloud metadata, internal services
  vuln-idor             ← IDOR, BOLA, privilege escalation via IDs
  vuln-csrf             ← CSRF, SameSite bypass
  vuln-xxe              ← XXE, out-of-band XXE
  vuln-ssi              ← SSTI, EL injection, XSLT, LDAP injection
  vuln-file-upload      ← insecure file upload, extension bypass
  vuln-path-traversal   ← path traversal, LFI, file read
  vuln-open-redirect    ← open redirect, URL manipulation
  vuln-race-condition   ← race conditions, TOCTOU
  vuln-deserialization  ← Java/PHP/Python/Ruby/NET deserialization
  vuln-business-logic   ← logic flaws, price manipulation, workflow abuse
  vuln-http             ← request smuggling, cache poison, host header, HPP, HTTP/2
  vuln-prototype-pollution ← JS prototype pollution, Node.js
  vuln-supply-chain     ← dependency confusion, CI/CD, npm attacks

EXPLOITATION (exploit-)
  exploit-rce           ← RCE techniques, shell payloads, cmdi
  exploit-post          ← post-exploitation, privilege escalation

MOBILE (mobile-)
  mobile-android        ← Android APK, ADB, Frida, SSL pinning
  mobile-ios            ← iOS IPA, Objection, SSL pinning bypass

CLOUD (cloud-)
  cloud-attack          ← AWS, GCP, Azure, IAM, cloud misconfig
  infra-attack          ← Kubernetes, VPN, VMware vCenter

PLATFORM (platform-)
  platform-frameworks   ← WordPress, Laravel, Node.js, Next.js, Spring, IIS, ASP.NET
  platform-sharepoint   ← SharePoint attack surface
  platform-okta         ← Okta SSO attacks

WEB3 (web3-)
  web3-audit            ← smart contracts, DeFi, NFT, meme coins

TOOLS & REFERENCE
  pentest-tools         ← Burp Suite, Metasploit, pentest commands, JS analyzer
  security-arsenal      ← general security reference
  ctf-techniques        ← CTF only: heap, crypto, steganography
```
