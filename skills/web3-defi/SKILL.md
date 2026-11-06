---
name: web3-defi
description: DeFi meme coin, Solana token, and DEX/LP security patterns. Meme coin bug classes (hidden mint 35%, honeypot 25%, fee manipulation 20%, LP lock bypass, bonding curve, authority retention, fake renounce, sandwich amplification), Solana SPL token authority matrix, Token-2022 extension risks (transfer hook, permanent delegate, transfer fee), pump.fun bonding curve analysis, DEX pool creation sniping, liquidity removal attacks, sandwich amplification bugs. Use when auditing meme coins, Solana tokens, or DEX contracts.
argument-hint: "[token contract address or protocol name]"
allowed-tools: Bash, Read, Glob, Grep
---

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
