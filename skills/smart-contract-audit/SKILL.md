---
name: smart-contract-audit
description: Smart contract security audit reference. Target evaluation scorecard, full attack surface mindmap (DEX/AMM/Lending/Bridge/Vault/ZK), 10-step audit methodology, OWASP Smart Contract Top 10, 2024-2025 high-value bug classes, grep quick-hits, Foundry PoC setup, Immunefi rules and submission format, non-EVM chains (Solana/CosmWasm/Move), payout benchmarks, and tools reference. Use when evaluating or auditing any DeFi/Web3 protocol for bug bounties.
argument-hint: "[protocol name or scope URL]"
allowed-tools: Bash, Read, Glob, Grep
---

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
