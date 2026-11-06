---
name: bb-access
description: Bug bounty Phase 1 account setup — create two test accounts (A and B), build the resource graph, and dispatch parallel registrar + walker subagents. Use after recon before any vulnerability sweep.
sources:
  - bug-bounty-hunting-prompts/phases/phase-01-access.md
argument-hint: "<target_display> <platform: hackerone|bugcrowd>"
allowed-tools: Bash, Read, Write, WebFetch
---

# Bug Bounty Access Setup (Phase 1)

Create authenticated test infrastructure (Accounts A + B), enumerate the resource graph, and seed the coverage ledger for all later phases.

## Authentication Modes

| Mode | Condition | Capability |
|------|-----------|-----------|
| **RICH** | 2 accounts + surface walk | Full cross-account IDOR, authenticated sweep |
| **PARTIAL** | 1 account or thin walk | Limited IDOR, half coverage matrix |
| **UNAUTH** | No account possible | 31 no-account findings including 13 criticals |

## 5-Profile Native Signup Ladder

Attempt signup in this order, stopping at first success:

1. **Catch-all domain** — unique address per account: `a1@catch-all-domain.com`, `b1@...`
2. **Catch-all domain variant** — different catch-all if first is blocked
3. **Google social fallback** — OAuth signup via Google test account
4. **Platform alias** — HackerOne/Bugcrowd alias email domain if supported
5. **Manual registration** — flag BLOCKED if all paths fail (payment/phone/KYC wall)

```bash
# Account creation pattern
ACCOUNT_A_EMAIL="a1-$(date +%s)@your-catchall.com"
ACCOUNT_B_EMAIL="b1-$(date +%s)@your-catchall.com"
```

## Account Setup Requirements

For each account (A and B):
- Complete full registration flow
- Verify email address
- Enroll TOTP/MFA if offered (save seed to sensitive/)
- Reach minimal operational state (can log in, access core features)
- Save credentials immediately: `sensitive/SENSITIVE-FINDINGS.md`

```markdown
## Account A
Email: <email>
Password: <password>
Login URL: <url>
Account ID: <id>
Member ID: <id>
Profile: browser-profile-N
Created: <timestamp>
```

## SMS OTP Handling

- Use virtual number service documented in resource guide
- Record number and OTP service details in sensitive/
- If SMS wall is unavoidable and no virtual number works, flag BLOCKED

## Resource Graph Building

After both accounts are created, enumerate all resource categories:

```
raw/resource-graph.json
{
  "tenant_account": {"A": {...}, "B": {...}},
  "primary_business_object": {"A": [...], "B": [...]},
  "workflow_instance": {"A": [...], "B": [...]},
  "upload_attachment": {"A": [...], "B": [...]},
  "invitation_member": {"A": [...], "B": [...]},
  "subscription_order_entitlement": {"A": {...}, "B": {...}},
  "status_transition": []
}
```

**7 Resource Categories:**
1. `tenant_account` — the account/org/workspace itself
2. `primary_business_object` — core items (projects, documents, repos)
3. `workflow_instance` — transient work items (tasks, issues, PRs)
4. `upload_attachment` — files, images, attachments
5. `invitation_member` — org members, invitations, roles
6. `subscription_order_entitlement` — plans, billing, features
7. `status_transition` — state machine transitions (draft→publish, etc.)

## Step 7: Parallel Dispatch

After resource graph is built, spawn two subagents simultaneously:

**Registrar subagent** — creates additional objects, seeds cross-account test state:
- Create a primary business object as Account A
- Share or invite Account B as collaborator
- Record all resulting resource IDs

**Walker subagent** — authenticated browser walk for quick surface mapping:
- Log in as Account A, map all reachable routes
- Note OAuth/SSO/SAML flows, upload surfaces, payment/billing pages
- Append routes to `raw/operation-candidates.jsonl`

## Sensitive Data Storage

**Never commit `sensitive/` to git.**

```markdown
# sensitive/SENSITIVE-FINDINGS.md
## Account A
Email: ...
Password: ...
Session Cookie: ...
Account/Org ID: ...
Browser Profile: N
CDP Port: BASE+N

## Account B
(same format)

## Cross-Account Test Objects
Object type | A's ID | B's ID
...
```

## UNAUTH Lane — 31 No-Account Findings

When account creation fails completely, the UNAUTH lane still provides productive coverage. 13 criticals are reachable with zero authentication:

**Critical (no account needed):**
- Exposed admin panel (no auth)
- API returning all users' PII without auth
- Password reset token not expiring / predictable
- Account takeover via OAuth misconfiguration
- Pre-authentication SSRF
- Exposed secrets in JS bundles
- GraphQL introspection + sensitive data
- Unauthenticated RCE via file processor
- IDOR on signup/invitation flow
- Subdomain takeover on critical asset
- Authentication bypass via path confusion
- SQL injection on login/search endpoint
- Exposed internal API without auth

## Finish Criteria

Phase 1 is complete when:
- Both accounts exist and can log in
- sensitive/SENSITIVE-FINDINGS.md contains credentials for both
- Resource graph is populated for all 7 categories
- Parallel subagents (registrar + walker) have reported verdicts
- raw/operation-candidates.jsonl has ≥20 entries
