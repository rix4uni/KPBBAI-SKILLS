---
name: web3-audit
description: Comprehensive Web3 bug bounty hunting methodology. Hunter mindset, bug validation template, 10 attacker questions per function, 10 bug classes with grep patterns (accounting desync 28%, access control 19%, incomplete paths 17%, off-by-one, oracle, ERC4626, reentrancy, flash loans, signature replay, proxy/upgrade), 10-block grep arsenal, protocol-specific patterns, 2025 new patterns, Trail of Bits and SlowMist research methodologies, and MCP tooling for Claude Code. Use when hunting any DeFi/Web3 protocol.
argument-hint: "[protocol name, scope URL, or contract path]"
allowed-tools: Bash, Read, Glob, Grep
---

# WEB3 BUG BOUNTY HUNTING — COMPLETE METHODOLOGY

---

## PART 1: HUNTER MINDSET

**Core question:** What can I STEAL, FREEZE, or DESTROY — and what do I END UP WITH?

### Bug Validation Template (Apply Before Any PoC Work)
```
I am an attacker. I will:
1. SETUP:   What do I need? (wallet, capital, any whitelisted permissions?)
2. CALL:    Exact transactions, exact order, exact function names
3. RESULT:  What do I end up with that I didn't start with?
4. COST:    Gas + capital + flash loan fee + any other expense
5. DETECT:  Can anyone stop or reverse this?
6. NET ROI: I gained X at cost of Y. Is Y << X?

If you can't fill in steps 2 and 3 → it's not a real bug. STOP. Move on.
```

### 10 Attacker Questions Per External Function
1. What if `amount = 0`? Does anything revert or silently pass?
2. What if I call this function twice in the same block?
3. What if I call this before `initialize()` is called?
4. What if I front-run this transaction?
5. What if the external call fails? Does state get half-updated?
6. What if the token has fee-on-transfer? Does `amount received ≠ amount sent`?
7. What if I pass `address(0)` or a malicious contract as an address param?
8. What if I pass `type(uint256).max` as a numeric param?
9. Can I combine this with a flash loan? (zero-cost capital changes the math)
10. **Does a sibling function lack the same modifier this function has?**

> Question #10 explains 19% of all Critical findings. If `vote()` has `onlyRole(VOTER)`, check `poke()`, `reset()`, `harvest()` — the missing modifier IS the bug.

### 6 Triager Counter-Questions (Disprove Your Own Finding)
1. Is there an upstream check I missed that actually prevents this?
2. Is this documented intended behavior (whitepaper, NatSpec, design decision)?
3. Does exploitation require admin/privileged access? (Usually invalid)
4. Is the economic cost to exploit greater than the gain?
5. Was this flagged in a prior audit as "acknowledged" or "risk accepted"?
6. Is the "sensitive" data already publicly visible in the web UI?

**One YES = KILL. Move on.**

### Workflow Rules
- **5-Minute Rule:** If stuck on same function 5 min with no attack path → STOP. Add to low-priority list.
- **Depth Over Breadth:** One protocol for 3-5 days > ten protocols in a week.
- **Inconsistency Is Proof:** `functionA()` has check, `functionB()` doesn't → THAT IS THE REPORT.

---

## PART 2: TARGET SCORING

**Score < 6 → skip.**

| Criterion | Points | How to Check |
|---|---|---|
| Max bounty ≥ $50K | +2 | Immunefi program page |
| TVL > $1M | +2 | DeFiLlama |
| Program launched < 30 days ago | +2 | Immunefi "new" filter |
| Custom math (AMM/vault/lending) | +1 | Read scope contracts |
| Recent code changes | +1 | `git log --oneline -20` |
| Prior audits available to study | +1 | Program page / GitHub |
| In-scope includes smart contracts | +1 | Scope section |
| Protocol type you know well | +1 | Your specialization |
| Source code public/readable | +1 | GitHub / Etherscan verified |

---

## PART 3: 30-MINUTE RECON PROTOCOL

### Step 1 — Immunefi Page (5 min)
```
Note:
- ALL in-scope contract addresses + GitHub links
- Out-of-scope list (DO NOT report these)
- Primacy of Impact: YES/NO
- Max bounty amounts by severity
- Time on Immunefi (newer = fewer duplicates)
```

### Step 2 — Clone + Setup (5 min)
```bash
git clone <target-repo>
cd <target-repo>
git log --oneline -20       # Recent changes = freshest bugs
forge build                 # Must compile clean
forge test                  # Note failures
forge coverage              # Untested code = priority review
```

### Step 3 — Read ALL Prior Audit Reports (15 min)
```
For each finding, note status:
  Fixed → Skip
  Acknowledged / Risk Accepted → ⚡ START HERE ⚡
    Developer knows but chose not to fix.
    Variants, escalations, related paths = in-scope and uncovered.
  Partially Fixed → Verify ALL attack paths are closed

Find: GitHub repo, protocol docs, Immunefi page, Google "[protocol] audit report"
```

### Step 4 — Crown Jewels (2 min)
```
"Worst thing an attacker could do?"
Work backward from impact to code:
- "Steal deposits" → withdrawal functions, access control on transfer
- "Mint infinite tokens" → mint functions, who calls them, what checks
- "Freeze all funds" → emergency functions, time locks, role assignments
- "Steal all rewards" → reward distribution, distributor role, harvest functions
```

### Step 5 — Architecture + Fund Flow (3 min)
```
Draw money flow:
  User USDC → deposit() → [Protocol Vault] → [External Protocol (Aave/Compound)]
                                           → yield accumulates
  [Reward Distributor] → Users via claim/harvest

Find WHERE VALUE ACCUMULATES. That contract = highest priority.

Key state variables:
- Total deposited / total assets / total shares
- Per-user balance tracking (how is it updated?)
- Reward accumulator (index, per-share, per-second?)
- Role assignments (owner, admin, governance, distributor)
- Time locks (timestamps, epochs, cooldowns)
```

### Step 6 — Static Analysis (5 min)
```bash
slither . --exclude-low --filter-paths "test|lib|node_modules"
aderyn . --output report.md
# Note HIGH/CRITICAL only. Tools catch ~30-40% of bugs.
```

---

## PART 4: 10 BUG CLASSES (Sorted by Frequency)

### Bug Class 1: Accounting State Desynchronization (28% of Criticals)
> Value is received or withdrawn but internal accounting isn't updated to match.

**4 Variants:**
1. **Phantom Yield:** Protocol counts rewards before they exist → user claims before accrual
2. **Fast Path Skips State Update:** `repayMax()` skips `_update()` that normal `repay()` calls
3. **Rewards to Wrong Accumulator:** Different accumulator updated for same pool → imbalance
4. **Wrong Update Order:** Balance updated after interest calculation → uses stale balance

**Grep:**
```bash
grep -rn "totalSupply\|totalShares\|totalAssets\|totalBorrow" contracts/ -A5
# Find: does every function that changes value ALSO update these?
grep -rn "function.*withdraw\|function.*deposit\|function.*repay\|function.*borrow" contracts/ -A20
# Manual: compare state updates across similar functions
```

---

### Bug Class 2: Access Control (19% of Criticals, $953M in 2024)
> Function can be called by attacker that should be restricted.

**5 Variants:**
1. **Missing modifier on sibling function:** `vote()` has `onlyVoter`, `poke()` doesn't
2. **Wrong check (existence vs ownership):** `require(balances[token] > 0)` instead of `require(owner[token] == msg.sender)`
3. **Tautology in require:** `require(role == ADMIN || role != ADMIN)` — always true
4. **Silent modifier (`if` instead of `require`):** Modifier uses `if` → silently does nothing instead of reverting
5. **Uninitialized proxy:** `initialize()` not called on implementation → anyone calls it

**Grep:**
```bash
grep -rn "function.*external\|function.*public" contracts/ | grep -v "view\|pure"
# Count: compare vs. functions with modifiers
grep -rn "modifier\b" contracts/ -A5 | grep "if ("
# Red flag: modifier uses if instead of require
grep -rn "function initialize\b" contracts/ -A5
grep -rn "_disableInitializers()" contracts/
```

**Roles Audit Checklist:**
```bash
grep -rn "onlyOwner\|onlyRole\|onlyAdmin\|onlyGov" contracts/ | sort | uniq
grep -rn "AccessControl\|Ownable\|hasRole" contracts/
grep -rn "grantRole\|revokeRole\|transferOwnership" contracts/
# Map: who can assign each role? Can attacker reach these?
```

---

### Bug Class 3: Incomplete Code Path (17% of Criticals)
> Operation partially executes — state updated for part A but not part B.

**5 Variants:**
1. **Update without refund:** Cancel() deletes order but doesn't return tokens
2. **Partial fill token stuck:** Unfilled portion stays in contract with no claim mechanism
3. **Queue entry deleted on failure:** Message deleted from queue even when execution fails
4. **SafeApprove without cleanup:** `safeApprove` fails if previous approval non-zero
5. **Mint skips receipt check:** `mint()` doesn't verify shares received match deposit

**Grep:**
```bash
grep -rn "function update_\|function cancel\|function refund\|function remove\|function delete" contracts/ -A15
# Manual: does the function update ALL relevant state variables?
grep -rn "function.*Order\|function.*Position\|function.*Bid\|function.*Offer" contracts/ -A20
# Pattern: compare cancel/remove against create — same state vars touched?
```

---

### Bug Class 4: Off-by-One & Boundary Conditions (22% of Highs)
> Wrong side of `<` vs `<=`, wrong period start/end, loop runs extra or one less iteration.

**6 Boundary Locations:**
1. Period/epoch: start vs end, inclusive vs exclusive
2. Time-based locks: `block.timestamp > unlockTime` vs `>= unlockTime`
3. Loop break: `i < length` vs `i <= length`
4. Array index: 0-indexed off-by-one
5. Amount/balance: `> 0` vs `>= minAmount`
6. Rounding: floor vs ceiling, favor protocol or user

**Mental Test:** For every `<`, `<=`, `>`, `>=`:
- What if the value is EXACTLY the boundary?
- What if it's one above or below?

**Grep:**
```bash
grep -rn "period\|epoch\|round.*[<>][^=]" contracts/
grep -rn "block\.timestamp.*[<>][^=]\|[<>][^=].*block\.timestamp" contracts/
grep -rn "\.length - 1\b\|i < length\|i <= length" contracts/
```

---

### Bug Class 5: Oracle / Price Manipulation (12% of Criticals)
> Protocol reads manipulable price source → attacker controls price used for calculation.

**Chainlink Bugs:**
```solidity
// A: Missing staleness check
(,int price,,uint updatedAt,) = oracle.latestRoundData();
require(block.timestamp - updatedAt < 1 hours, "Stale price");  // REQUIRED

// B: Missing sequencer check (L2 deployments)
// If sequencer is down, Chainlink data is stale — feeds don't update
// Must check sequencer uptime feed separately

// C: latestAnswer() deprecated — use latestRoundData() + staleness check
```

**Pyth Bugs:**
```solidity
// Confidence interval too wide = price range is unreliable
require(price.conf * 10 < uint64(price.price), "Low confidence");
// Hardcoded staleness threshold: use dynamic based on asset volatility
```

**AMM Spot Price (Most Dangerous):**
```solidity
// VULNERABLE: flash-loan manipulable
(uint112 r0, uint112 r1,) = pair.getReserves();  // Uniswap V2
uint160 sqrtPriceX96 = slot0.sqrtPriceX96;        // Uniswap V3

// SAFE: use TWAP
uint32[] memory secondsAgo = new uint32[](2);
secondsAgo[0] = 1800; secondsAgo[1] = 0;
(int56[] memory tickCumulatives,) = pool.observe(secondsAgo);
// Compute time-weighted price from tick cumulatives
```

**Grep:**
```bash
grep -rn "latestRoundData\|latestAnswer\|getReserves\|slot0\b" contracts/
grep -rn "sequencerUptimeFeed\|answeredInRound\|roundId" contracts/
grep -rn "\.conf\b\|confidence" contracts/
```

---

### Bug Class 6: ERC4626 Vault Bugs
> Share price, deposit/withdrawal rounding, and direct token donations create attack vectors.

**4 Core Bugs:**
1. **First depositor inflation:** 1-wei + donate → victim gets 0 shares
2. **Share transfer missing stake migration:** `transfer()` moves shares but not staking position
3. **Rounding direction:** Deposits must round DOWN (fewer shares to user), withdrawals round UP (more assets required from user)
4. **Donation attack:** Direct `token.transfer()` to vault inflates `totalAssets` → share price jumps

**Vault Checklist:**
```bash
grep -rn "convertToShares\|convertToAssets\|previewDeposit\|previewWithdraw" contracts/
grep -rn "totalAssets()\|_totalAssets\b" contracts/
# Check: is totalAssets() using balanceOf(this) (vulnerable) or tracked var (safe)?
grep -rn "\.balanceOf(address(this))" contracts/
# If used for accounting = donation attack vector
```

---

### Bug Class 7: Reentrancy ($300M+ all-time, $35.7M in 2024)
> External call before state update → attacker re-enters and exploits inconsistent state.

**4 Variants:**
1. **Classic CEI violation:** `.call{value}()` before state update
2. **Cross-function:** `nonReentrant` on `withdraw()` but not `claim()` — shared state
3. **Read-only ($70M Curve):** View function reads stale state during callback (ERC777 hook)
4. **Cross-contract:** Protocol A calls Protocol B which calls back into Protocol A

**Grep:**
```bash
grep -rn "\.call{value\|\.transfer(\|safeTransfer\|safeTransferFrom" contracts/ -B5
# Check: state variables updated AFTER these calls = vulnerable
grep -rn "nonReentrant" contracts/
# Missing on functions that share storage with nonReentrant functions = cross-function reentrancy
```

---

### Bug Class 8: Flash Loan Attacks (83% of eligible exploits use flash loans)
> Zero-cost capital enables attacks that would otherwise be economically infeasible.

**3 Flash Loan Patterns:**
1. **Oracle manipulation:** Borrow → dump one side of pair → read manipulated price → profit → repay
2. **Governance attack:** Borrow tokens → vote on proposal → execute → repay (all in 1 tx)
3. **Liquidity manipulation:** Borrow from protocol's own pool → distort reserves → self-trade

**Flash Loan Providers (sorted by cost):**
```
Balancer V2:    0% fee — Vault.flashLoan(receiver, tokens, amounts, userData)
Morpho:        ~0% fee — flashLoan(token, amount, data)
Aave V3:       0.05% fee — flashLoan(receiver, assets, amounts, modes, params, referral)
Uniswap V2:    0.3%  fee — pair.swap(amount0, amount1, to, data) — callback uniswapV2Call
```

**Checklist:**
```bash
grep -rn "latestRoundData\|getReserves\|slot0\b" contracts/
# Any spot price read = flash loan attack surface
grep -rn "governance\|vote\|proposal\|quorum" contracts/
# Governance token borrowed in flash loan = voting power manipulation
grep -rn "flashLoan\|flash_loan\|onFlashLoan\|uniswapV2Call\|pancakeCall" contracts/
# Is protocol itself a flash loan provider? Can it be used to attack itself?
```

---

### Bug Class 9: Signature Replay
> Signed messages reused across chains, contracts, or time windows.

**3 Variants:**
1. **Cross-chain:** Signature without chainId → replay on Ethereum + Arbitrum + Optimism
2. **Same-chain replay:** No nonce → same signature reusable indefinitely
3. **EIP-2612 Permit Frontrun DoS:** Attacker sees permit in mempool, frontruns → nonce consumed → victim reverts

**Signature Checklist:**
```
□ Does signature include chainId?
□ Does signature include contract address?
□ Does signature include nonce (nonces[user]++)?
□ Does signature include deadline?
□ Is OpenZeppelin ECDSA used (not raw ecrecover)?
□ Are signatures used as mapping keys? (malleability attack via s value)
□ Is permit() wrapped in try/catch in compound functions?
□ Is DOMAIN_SEPARATOR computed at runtime (not hardcoded)?
```

**Grep:**
```bash
grep -rn "ecrecover\|ECDSA\.recover" contracts/
grep -rn "chainId\|block\.chainid\|DOMAIN_SEPARATOR" contracts/
grep -rn "nonces\[\|nonce\b" contracts/
grep -rn "try.*permit\|catch.*permit" contracts/
```

---

### Bug Class 10: Proxy / Upgrade Bugs
> Uninitialized implementations, storage collisions, and unprotected upgrade paths.

**4 Variants:**
1. **Uninitialized implementation:** `initialize()` callable by anyone on impl contract directly
2. **Storage collision:** New variable added BEFORE existing ones in upgrade → overwrites
3. **UUPS without `_authorizeUpgrade` protection:** Anyone calls `upgradeTo(malicious)`
4. **Reinitializer not protected:** `reinitializer(2)` has no access control → resets state

**Proxy Checklist:**
```
□ Is _disableInitializers() in implementation constructor?
□ Does initialize() have initializer modifier?
□ Does _authorizeUpgrade() have onlyOwner/onlyRole?
□ New storage variables ONLY appended at end (no slot collision)?
□ __gap arrays reserved for future vars?
□ DOMAIN_SEPARATOR recalculated at runtime?
□ No selfdestruct calls?
```

**Grep:**
```bash
grep -rn "function initialize\b" contracts/ -A5
grep -rn "_disableInitializers()" contracts/
grep -rn "_authorizeUpgrade" contracts/ -A3
grep -rn "__gap\|ERC1967Storage" contracts/
```

---

## PART 5: 10-BLOCK GREP ARSENAL

### Block 1 — Access Control (Tier 1: highest value)
```bash
grep -rn "function.*external\|function.*public" contracts/ | grep -v "view\|pure\|returns"
grep -rn "selfdestruct\|delegatecall\|\.call(" contracts/
grep -rn "\.call(" contracts/ | grep -v "staticcall\|view\|//\|test"
```

### Block 2 — Reentrancy
```bash
grep -rn "\.call{value\|\.transfer(\|\.send(" contracts/ -B5
grep -rn "nonReentrant\|ReentrancyGuard" contracts/
grep -rn "\.call(" contracts/ -B2 | grep -v "staticcall"
```

### Block 3 — Oracle / Price
```bash
grep -rn "latestRoundData\|latestAnswer\|getReserves\b\|slot0\b\|observe(" contracts/
grep -rn "sequencerUptimeFeed\|answeredInRound\b" contracts/
grep -rn "\.price\b\|getPrice\|fetchPrice\|updatePrice" contracts/
```

### Block 4 — Arithmetic
```bash
grep -rn "unchecked {" contracts/ -A10
grep -rn "SafeMath\|\.div(\|\.mul(" contracts/
grep -rn "/ total\|/ shares\|/ supply\|/ assets" contracts/
grep -rn "\* price\|price \*\|\.price \*" contracts/
```

### Block 5 — Input Validation
```bash
grep -rn "require(" contracts/ | grep -v "msg\.sender\|balance\|amount\|onlyOwner"
grep -rn "address(0)\|require.*!= address(0)" contracts/
grep -rn "\.length == 0\|params\.length\|args\.length" contracts/
```

### Block 6 — Token Handling
```bash
grep -rn "safeTransfer\|safeTransferFrom\|transfer(" contracts/
grep -rn "\.balanceOf(address(this))\|balanceOf(this)" contracts/
grep -rn "IERC20.*transfer\|ERC20.*transferFrom" contracts/ -B2 -A2
# Check: is returned bool checked?
```

### Block 7 — ERC4626 / Vault
```bash
grep -rn "convertToShares\|convertToAssets\|previewDeposit\|previewWithdraw\|previewRedeem" contracts/
grep -rn "totalAssets()\|_totalAssets\b\|totalSupply()" contracts/
grep -rn "ERC4626\|IERC4626\|BaseVault" contracts/
```

### Block 8 — Proxy / Upgrade
```bash
grep -rn "function initialize\b\|initializer\b\|reinitializer" contracts/ -A5
grep -rn "_disableInitializers\|_authorizeUpgrade\|upgradeTo\|upgradeToAndCall" contracts/
grep -rn "UUPSUpgradeable\|TransparentUpgradeableProxy\|BeaconProxy" contracts/
```

### Block 9 — Signatures / Replay
```bash
grep -rn "ecrecover\|ECDSA\.recover\|SignatureChecker" contracts/
grep -rn "nonces\[\|nonces\.\|_useNonce\b" contracts/
grep -rn "DOMAIN_SEPARATOR\|block\.chainid\|chainId\b" contracts/
grep -rn "permit(" contracts/ | grep -v "//\|IERC20Permit\|interface"
```

### Block 10 — State Completeness
```bash
grep -rn "function cancel\|function remove\|function delete\|function close\b" contracts/ -A20
grep -rn "delete [a-z].*\[" contracts/  # Does delete update all relevant mappings?
grep -rn "pop()\|\.length--" contracts/
```

---

## PART 6: PROTOCOL-SPECIFIC PATTERNS

### Yield Aggregator
```bash
grep -rn "harvest\|compound\|reinvest\|autoCompound" contracts/ -A10
grep -rn "lastHarvest\|lastCompound\|lastUpdate" contracts/
grep -rn "pendingRewards\|claimable\|earned()" contracts/
# Check: reward index updated before every deposit/withdraw?
```

### Lending Protocol
```bash
grep -rn "liquidate\|liquidation\|isLiquidatable\|canLiquidate" contracts/
grep -rn "healthFactor\|collateralFactor\|ltv\b" contracts/
grep -rn "accrueInterest\|updateInterest\|interestRate" contracts/
# Check: is accrueInterest() called before every borrow/repay/liquidate?
```

### AMM / DEX
```bash
grep -rn "swap\|swapExact\|getAmountOut\|getAmountIn" contracts/ -A10
grep -rn "k = \|invariant\|reserve0\|reserve1\|_update(" contracts/
grep -rn "fee\|feeTo\|protocolFee" contracts/
# Check: is K preserved after swap? Any flash swap callback reentrancy?
```

### Staking / Restaking
```bash
grep -rn "stake\|unstake\|slash\|slashing\|delegate\|undelegate" contracts/
grep -rn "rewardPerToken\|rewardRate\|lastUpdateTime" contracts/
grep -rn "withdrawalQueue\|queuedWithdrawal\|pendingWithdrawal" contracts/
# Check: multi-field withdrawal queue updated atomically?
```

---

## PART 7: 2025 NEW HIGH-VALUE PATTERNS

```bash
# ERC4626 near-empty vault (first depositor inflation)
grep -rn "totalAssets()\|totalSupply()" contracts/
# If both can be 0 simultaneously → first depositor inflation

# EIP-2612 permit frontrun DoS
grep -rn "permit(" contracts/ | grep -v "try\|catch"
# Absent try/catch = vulnerable to DoS

# Decimal precision mismatch (6-decimal USDC vs 18-decimal token)
grep -rn "1e18\|1e6\|decimals()\|DECIMALS" contracts/
grep -rn "\* 1e18\|/ 1e18\|\* 10 \*\* 18" contracts/

# Streaming / continuous precision loss
grep -rn "perSecond\|ratePerSecond\|streamRate\|flowRate" contracts/

# Withdrawal queue multi-field invariant
grep -rn "withdrawalQueue\|queue\b" contracts/ -A10
# Check: all 3+ fields updated atomically (amount + timestamp + status)

# Try/catch DoS liveness
grep -rn "try\b.*catch\b" contracts/ -A5
# If try/catch swallows external call failure → operation proceeds even when it shouldn't
```

---

## PART 8: RESEARCH METHODOLOGIES

### Trail of Bits Approach
**Tools:** Slither / Echidna / Medusa / Manticore / Halmos

```bash
# Slither — fast, broad
slither . --detect all --exclude informational,optimization
slither . --detect reentrancy-eth,reentrancy-benign,unprotected-upgrade
slither-check-upgradeability . ProxyContract ImplementationContract

# Echidna — property fuzzer
# invariant_*.sol: define properties that must always hold
echidna . --contract TestContract --config echidna.yaml --test-mode assertion

# Medusa — coverage-guided fuzzer
medusa fuzz --config medusa.json

# Halmos — symbolic execution
halmos --contract MyTest --function testSymbolic
```

**6-Step ToB Audit:**
1. Manual code review (architecture + logic)
2. Slither static analysis
3. Echidna invariant testing
4. Symbolic execution on critical paths (Halmos/Manticore)
5. Test suite review (coverage + quality)
6. Report writeup

**Key Bug Classes (ToB Focus):**
- Reentrancy: classic + cross-function + read-only
- Rounding: favor attacker direction (1 wei × 1000 iterations = significant)
- Weak Fiat-Shamir (ZK): hash of public inputs doesn't bind all params
- Access control gaps: incorrect use of msg.sender vs tx.origin
- Unsafe upgrades: missing gap, storage collision
- Signature replay: missing nonce or chainId
- DeFi: liquidity math, oracle manipulation, L2 bridge trust assumptions

**"Risk Accepted" Hunt Strategy:**
1. Find all prior audits for target protocol
2. Compile every "Risk Accepted" / "Acknowledged" finding
3. For each: find variant, escalation, or related path that IS exploitable
4. These findings are pre-validated as interesting by the original auditors

### SlowMist Learning Roadmap

**Phase 1: Foundation (Weeks 1-4)**
```
Ethernaut 30 challenges (all of them)
Resources:
- SWC Registry (smartcontractsecurity.github.io/SWC-registry/)
- DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)
- Rekt.news (every exploit, understand the root cause)
```

**Phase 2: DeFi & Real Hacks (Weeks 5-10)**
```
Read source code of Tier-1 protocols:
- Uniswap V2 + V3 (AMM math, flash swaps, Oracle)
- Aave V3 (collateral, liquidation, flash loans, aTokens)
- Compound V2 + V3 (cTokens, interest accrual, governance)
- ERC4626 (share math, rounding, extension patterns)

Study 10 priority exploits:
- Cream Finance ($130M) — flash loan oracle
- Euler Finance ($197M) — donation attack + liquidation math
- Nomad Bridge ($200M) — message validity check zero
- Beanstalk ($182M) — flash loan governance
- Mango Markets ($117M) — oracle price manipulation
- Curve (read-only reentrancy, $70M)
- Penpie ($27M) — reentrancy in multi-reward
- Rari Capital ($80M) — reentrancy cross-protocol
- Wormhole ($320M) — uninitialized proxy
- Ronin ($625M) — validator compromise
```

**Phase 3: EVM Internals**
```
Storage layout: slots, packing, mappings (keccak256(key . slot))
Key opcodes: SLOAD/SSTORE gas, DELEGATECALL context, STATICCALL restrictions
Proxy patterns: EIP-1967, EIP-1822 (UUPS), Transparent, Beacon, Diamond
Symbolic execution: Manticore / Halmos for path exploration
```

---

## PART 9: MCP TOOLING (CLAUDE CODE INTEGRATION)

```json
// Add to ~/.claude/mcp.json:
{
  "mcpServers": {
    "audit": {
      "command": "npx",
      "args": ["solidity-audit-mcp"]
    }
  }
}
```

**10 MCP Tools:**
```
analyze_contract(contractPath, analyzers)   — full pipeline: Slither + Aderyn + Slang
get_contract_info(contractPath)             — attack surface map (functions, payable, delegatecall)
check_vulnerabilities(contractPath, detectors) — 86 SWC pattern detectors
explain_finding(findingId, context)         — root cause + PoC + remediation for any finding
generate_invariants(contractPath, protocol) — Foundry invariant tests for vault/lending/amm
diff_audit(old, new)                        — audit only changed functions in upgrades
run_slither(contractPath, detectors)        — direct Slither run
run_aderyn(contractPath)                    — direct Aderyn run
optimize_gas(contractPath)                  — storage packing, loop, calldata suggestions
get_swc_info(swcId)                         — SWC registry entry with examples
```

**19 Built-in Finding Explainers:**
SWC-107 (Reentrancy), SWC-112 (Delegatecall untrusted callee), CUSTOM-017 (Missing access control), CUSTOM-018 (ERC-7702 unprotected initializer), CUSTOM-004 (Oracle/flash loan), CUSTOM-032 (ERC-4337 paymaster drain), SWC-101 (Integer overflow), SWC-104 (Unchecked return), SWC-115 (tx.origin), CUSTOM-001 (Array length mismatch), CUSTOM-011 (Signature without replay protection), CUSTOM-029 (Merkle double-claim), SWC-116 (Timestamp dependence), CUSTOM-005 (Zero address), CUSTOM-013 (abi.encodePacked hash collision), CUSTOM-015 (Division before multiplication), CUSTOM-016 (Permit without deadline), SWC-100 (Default visibility), SWC-103 (Floating pragma)

---

## BUG CLASS QUICK REFERENCE

| Rank | Class | % Criticals | Flash Loan? | First Grep |
|---|---|---|---|---|
| 1 | Accounting Desync | 28% | No | `totalSupply\|totalShares\|totalAssets` |
| 2 | Access Control | 19% | No | `function.*external` without modifier |
| 3 | Incomplete Path | 17% | Sometimes | `function update_\|function cancel` |
| 4 | Off-By-One | 22% Highs | No | `period\|epoch\|round.*[<>][^=]` |
| 5 | Oracle Manipulation | 12% | Yes | `latestRoundData\|getReserves\|slot0` |
| 6 | ERC4626 Vaults | Varies | Yes | `convertToShares\|totalAssets()` |
| 7 | Reentrancy | 8% | Sometimes | `\.call{value\|safeTransfer` before state |
| 8 | Flash Loan | 83% use it | Yes | Any spot price or governance vote |
| 9 | Signature Replay | 3% | No | `ecrecover\|ECDSA.recover` |
| 10 | Proxy/Upgrade | 2% | No | `function initialize\|_authorizeUpgrade` |


---

## From hack-skills: Smart Contract Vulnerability Patterns

### Reentrancy Variants

```
Classic (CEI violation):
  withdraw() → external call before state update
  → attacker re-enters withdraw() before balance zeroed

Cross-Function Reentrancy:
  withdraw() → external call (balance not zeroed)
  → attacker calls transfer() (reads stale balance)
  → both withdraw() and transfer() succeed on same balance

Read-Only Reentrancy:
  Protocol removes liquidity → callback occurs mid-state-change
  → third-party protocol reads stale intermediate price (inflated)
  → profit from miscalculated collateral/borrow amounts
  Real: Curve pool get_virtual_price() during remove_liquidity()
```

**Fix order**: Checks → Effects → Interactions (CEI) + ReentrancyGuard on all public functions.

### Integer Overflow (Pre-Solidity 0.8)

```solidity
uint8(255) + 1 == 0    // silent overflow
uint8(0) - 1 == 255    // underflow → huge balance

// Attack: balances[attacker] -= amount where amount > balance → huge balance
// Post-0.8 risk: unchecked{} blocks reintroduce overflow
// Also: (a * b) / c where a*b overflows before division
```

### Delegatecall Storage Collision

```
Proxy slot 0: owner         ← critical auth variable
Impl slot 0: someVariable   ← innocuous-seeming variable

Attacker calls implementation function that writes slot 0
→ overwrites proxy's owner → becomes proxy owner
```

**Find**: `cast selectors <bytecode>` for function selector collisions (4-byte prefix).

### tx.origin Authentication Bypass

```solidity
// Vulnerable:
require(tx.origin == owner);  // phishing contract inherits tx.origin

// Safe:
require(msg.sender == owner);
```

### Signature Replay Attacks

```
Missing nonce: same signature reused multiple times (transfer replayed)
Cross-chain replay: same contract on multiple chains, signature valid on all
  Fix: include block.chainid in EIP-712 domain separator

ecrecover returns address(0) on invalid sig → passes address(0) == owner check
  Fix: require(signer != address(0))
```

### Randomness Manipulation

```
block.timestamp: miner manipulates ±15s
blockhash(block.number-1): known at execution time
block.prevrandao: post-merge, known beacon chain value

Commit-reveal abuse: attacker refuses to reveal unfavorable outcome
  Fix: enforce reveal timeout + deposit bond
```

### CREATE2 Pre-deployment Exploitation

```
Predict contract address → approve tokens to that address before deployment
Deploy malicious contract at predicted address → drain approved tokens

Also: metamorphic contracts (pre-EIP-6780):
CREATE2 → selfdestruct → CREATE2 with same salt but DIFFERENT initCode
→ proxy approvals/state stays, but implementation is now malicious
```

### Flash Loan Attack Checklist

```
✓ Does contract use AMM spot price (getReserves()) as oracle? → vulnerable
✓ Does governance vote snapshot balance at vote time or proposal creation? → flash loan risk
✓ Does first depositor set share price that causes rounding to 0? → inflation attack
✓ Are ERC4626 vaults initialized with minimum liquidity? → inflation attack
✓ Does any external call happen before state update? → reentrancy risk
```
