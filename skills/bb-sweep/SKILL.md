---
name: bb-sweep
description: Bug bounty Phase 2 vulnerability sweep — 47-row coverage matrix across 36 endpoint-scoped and 9 target-scoped test classes. Stage A (serial browser), Stage B (parallel subagents), Stage C (chain analysis). Use after access setup.
sources:
  - bug-bounty-hunting-prompts/phases/phase-02-sweep.md
argument-hint: "<target_display>"
allowed-tools: Bash, Read, Write, WebFetch
---

# Bug Bounty Vulnerability Sweep (Phase 2)

Systematic coverage of every vulnerability class against the target's endpoint catalog. Three-stage model: serial browser walk → parallel stateless subagents → chain analysis.

## 47-Row Coverage Matrix

### Endpoint-Scoped Classes (36 rows)

| Class | Description | Priority |
|-------|-------------|---------|
| `ssrf` | Server-Side Request Forgery | Critical |
| `ssti` | Server-Side Template Injection | Critical |
| `xxe` | XML External Entity | Critical |
| `deser` | Deserialization | Critical |
| `jndi` | JNDI injection (Log4Shell family) | Critical |
| `lfi` | Local File Inclusion | High |
| `redirect` | Open redirect | Medium |
| `upload` | File upload abuse | High |
| `idor` | Insecure Direct Object Reference | High |
| `idor-x` | Cross-tenant IDOR | Critical |
| `unauth-access` | Unauthenticated access to auth'd resource | High |
| `id-walk` | ID enumeration / BOLA | High |
| `path-bypass` | Path traversal / normalization bypass | High |
| `method-override` | HTTP method override | Medium |
| `api-version` | API version downgrade | Medium |
| `func-level` | Function-level authorization bypass | High |
| `graphql-authz` | GraphQL authorization bypass | High |
| `jwt` | JWT vulnerabilities (alg:none, weak secret) | High |
| `session` | Session management flaws | High |
| `oauth` | OAuth/OIDC misconfiguration | High |
| `pwreset` | Password reset flaws | High |
| `token-leak` | Token/secret leakage | High |
| `siwe` | Sign-In with Ethereum / Web3 auth | Medium |
| `preauth-bypass` | Pre-authentication bypass | Critical |
| `numeric` | Integer overflow / numeric validation | Medium |
| `massassign` | Mass assignment | Medium |
| `race` | Race condition | High |
| `idempotency` | Idempotency abuse | Medium |
| `workflow` | Workflow state bypass | Medium |
| `method-swap` | HTTP method swap | Low |
| `entitlement` | Entitlement/plan bypass | High |
| `domxss` | DOM-based XSS | High |
| `cswsh` | Cross-Site WebSocket Hijacking | Medium |
| `cache` | Cache poisoning / deception | High |
| `header-inj` | Header injection | Medium |
| `second-order` | Second-order injection | High |

### Target-Scoped Infrastructure Classes (9 rows)

| Class | Description |
|-------|-------------|
| `api-abuse` | API abuse / rate limit bypass |
| `injection` | SQLi, NoSQLi, Command injection |
| `secrets-in-js` | Hardcoded secrets in JS/source-maps |
| `exposed-endpoints` | Admin/staging/dev hosts exposed |
| `csp-misconfig` | CSP/cookie misconfiguration |
| `git-exposure` | Exposed `.git`, `.env`, backups |
| `subdomain-takeover` | Subdomain takeover |
| `cors-creds` | Credentialed CORS read of secrets |
| `supply-chain` | Dependency confusion, CI exposure |

## Stage A: Controller-Serial Browser Walk

The orchestrator drives ONE authenticated Chrome via CDP. All browser-dependent classes must be tested here — do NOT delegate browser state to subagents.

**Controller-Order Sequence (5 Steps):**
1. Map all authenticated routes → `raw/endpoints.json`
2. Test upload surfaces first (profile pic, avatar, attachments, imports)
3. Walk OAuth/SAML/SSO flows end-to-end
4. Test all forms, settings, integrations
5. Check DOM XSS / postMessage / CSRF

**Upload Surface Tests (every upload endpoint):**
- Oversize file (>10MB, >100MB)
- Bad MIME type / extension mismatch
- `x.php.png` trick (double extension)
- Path-traversal filename (`../../etc/passwd`)
- SVG / HTML content render (XSS via upload)
- EXIF injection in image metadata

**Skip in Stage A:** Pure CORS (low yield). Low-impact oracles only if they chain.

## Stage B: Parallel Subagent Fan-Out

When Stage A exposes a stateless server-side lead, dispatch a background subagent immediately while the browser walk continues. Cap at 3–4 concurrent subagents.

**4 Subagent Bundle Types:**

**Bundle 1 — Exposure:**
- Secrets in JS/source-maps
- Exposed `.git`/`.env`/backups
- Admin/staging/dev host discovery
- CSP/cookie misconfiguration

**Bundle 2 — Infra + Protocol:**
- Cloud metadata SSRF (169.254.169.254)
- SSRF via webhook/integration/image-fetch
- XXE on XML-accepting endpoints
- Deserialization (Java, PHP, Python pickle)
- JNDI injection

**Bundle 3 — Server Input A (Injection):**
- SQLi (error-based, blind, time-based)
- NoSQLi (MongoDB operator injection)
- Command injection
- SSTI (Jinja2, Twig, Freemarker)
- LFI / path traversal

**Bundle 4 — Server Input B (Auth/Logic):**
- JWT algorithm confusion / weak secret
- OAuth callback substitution / state fixation
- Password reset token predictability
- Race conditions on money/counter flows
- Entitlement/plan bypass via API

**Subagent Safety Rule:** Subagents MUST NOT touch the orchestrator's CDP Chrome. Each subagent uses copied cookies/tokens from `sensitive/` and drives its own curl/scripts. Never share browser profiles between orchestrator and subagents.

## Stage C: Chain Analysis

After Stage A and Stage B complete, synthesize partial findings into chains:

**Chain Types to Build:**
- `SSRF → internal service → data extraction`
- `Open redirect → OAuth token theft → ATO`
- `Upload XSS → stored attack → admin compromise`
- `IDOR + secret leak → account takeover`
- `Race condition + entitlement bypass → privilege escalation`

For each chain:
- Confirm each edge end-to-end against live target
- Prove attacker delivery path (not just mechanic)
- Escalate severity to chain's highest impact class

## Bidirectional Cross-Account Matrix

For every IDOR / access-control class, test both directions:

```
Account A (attacker) → Account B's resources: [ ] tested
Account B (attacker) → Account A's resources: [ ] tested
Unauthenticated      → Account A's resources: [ ] tested
Unauthenticated      → Account B's resources: [ ] tested
```

## Lead Ledger (Compaction-Safe)

```jsonl
// raw/leads.jsonl — append BEFORE spawning subagent
{"id": "lead-001", "surface": "/api/files", "class": "ssrf", "status": "dispatched", "agent": "subagent-1", "report": null}
```

## UNAUTH Lane Priorities

When testing without accounts:
1. Secrets in JS bundles → immediate Critical report if live
2. Exposed unauth services → map full scope
3. Unauth API / BOLA → enumerate object IDs
4. Auth bypass on pre-auth endpoints → registration, password reset, OAuth
5. CI/supply chain → package.json, .github/workflows, .circleci

## Endpoints Catalog

Query/update the shared endpoint catalog throughout:
```bash
# List untested endpoints
endpoints list --untested

# Get endpoint history
endpoints get '/api/users/{id}'

# Mark test result
endpoints append --json '{"shape": "/api/files/{id}", "class": "idor", "verdict": "CONFIRMED"}'
```

## Stop Condition

Stage B is complete when all 47 coverage matrix rows have a verdict (CONFIRMED / NO-ISSUE / BLOCKED) for at least one representative endpoint in that class.
