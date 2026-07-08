// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { IPaymaster } from "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import { BasePaymaster } from "@account-abstraction/contracts/core/BasePaymaster.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { _packValidationData } from "@account-abstraction/contracts/core/Helpers.sol";
import { StarzipWallet } from "./StarzipWallet.sol";

/**
 * @title VerifyingPaymaster
 * @notice Policy-storage gas sponsorship paymaster: each wallet's sponsorship policy lives in
 *         this contract's OWN storage keyed by `userOp.sender`. No per-userOp backend signature
 *         and no external registry read during validation (strict ERC-7562 public-bundler safe).
 * @dev Inherits BasePaymaster (Ownable2Step). Non-proxy, non-upgradeable — `entryPoint` is
 *      immutable; migration = fresh deploy at a new address. Storage slot table (subclass
 *      storage starts at slot 2; slots 0-1 are Ownable/Ownable2Step):
 *        slot 2: policyManager (address, 20B) | paused (bool, 1B)          — packed
 *        slot 3: globalDailyCapCeiling (uint128) | globalDailyBudget (uint128)
 *        slot 4: globalSpentToday (uint128) | globalLastSpentDay (uint32)
 *        slot 5: walletPolicy mapping base   (entry at keccak256(sender, 5))
 *        slot 6: businessAllowlist mapping base (entry at keccak256(target, 6))
 *        slot 7: maxSponsoredOpCost (uint128)
 *
 *      ERC-7562: `_validatePaymasterUserOp` NEVER reads `block.timestamp`/`block.number` and
 *      NEVER writes storage — all it does is a RAW check against stored day-indexed counters,
 *      deferring genuinely time-dependent decisions to the EntryPoint via `validAfter`. All day
 *      rollover + accrual happens in `_postOp` (execution phase, where the clock is allowed).
 *
 *      SECURITY — budget/cap are SOFT breakers, the deposit is the HARD cap:
 *      `globalDailyBudget` and every wallet's `dailyCap` are evaluated in `_validatePaymasterUserOp`
 *      against storage as it stood at the START of the bundle — ERC-7562 forbids writing storage
 *      during validation, so these counters cannot be checked atomically per-op within a single
 *      `handleOps` bundle. A single permissionless bundle can therefore push total sponsorship for
 *      that block past `globalDailyBudget` (bounded only by how many sponsorable ops a bundler
 *      chooses to include). These are best-effort spend breakers, NOT an EVM-enforced ceiling.
 *      The ONLY EVM-enforced hard cap on this paymaster's total loss is its EntryPoint **deposit**
 *      (`BasePaymaster.getDeposit`/`deposit`/`withdrawTo`) — once exhausted, the EntryPoint itself
 *      reverts sponsorship (AA31), no matter what the soft breakers say. Operators MUST size the
 *      deposit as the acceptable MAX DAILY LOSS (not as a convenience buffer) and MUST NOT
 *      naively auto-refill the deposit on a timer without breaker-health monitoring (e.g. alerting
 *      if `globalSpentToday` is repeatedly saturating `globalDailyBudget`) — auto-refilling a
 *      drained deposit defeats the one hard ceiling this contract actually has.
 */
contract VerifyingPaymaster is BasePaymaster {
    // ============ Constants ============
    /// @dev Empirically derived. Measured via `PostOpGasProbe` +
    ///      test/VerifyingPaymaster.postOpGas.test.ts: a direct call to `postOp` as the very
    ///      FIRST storage-touching op on a fresh paymaster instance — i.e. `walletPolicy[sender]`
    ///      and the global spent/day slot are both genuinely cold, AND the CALL into the
    ///      paymaster itself is cold (strictly worse than the real handleOps flow, where
    ///      `_validatePaymasterUserOp` already warms those slots earlier in the same
    ///      transaction) — measured **74,378 gas** for a fresh wallet on a fresh global-day.
    ///      Set here at 90,000 for a ~15.6k / ~21% margin above that worst-case measurement. A
    ///      higher floor is strictly safer (it only means a userOp must forward more
    ///      `paymasterPostOpGasLimit`, not that `_postOp` actually costs more) — if `_postOp`'s
    ///      logic ever changes, re-run the probe test and re-derive this constant.
    uint128 public constant MIN_POSTOP_GAS = 90_000;

    /// @dev Mirrors StarzipWallet.MAX_BATCH_SIZE — caps the executeBatch decode loop.
    uint256 private constant MAX_BATCH_SIZE = 32;

    // ============ Structs ============
    struct WalletPolicy {
        // entry slot n (packed, 23 bytes)
        bool sponsored;
        bool sponsorPersonal; // false => business-only
        bool vip; // owner-granted unlimited; bypasses dailyCap, NOT global budget
        uint32 lastSpentDay; // set in postOp only
        // @dev SOFT breaker only (see contract header): checked in
        //      _validatePaymasterUserOp against pre-bundle storage, not atomically re-checked
        //      per-op within one handleOps bundle. Gas-cost wei; must be >0 for a non-vip wallet
        //      to be sponsored. The EntryPoint deposit — not this cap — is the hard loss ceiling.
        uint128 dailyCap;
        // entry slot n+1
        uint128 spentToday; // set in postOp only
    }

    // ============ State Variables ============
    // slot 2 (packed)
    address public policyManager;
    bool public paused;

    // slot 3 (packed)
    uint128 public globalDailyCapCeiling;
    /// @dev SOFT breaker only (see contract header): checked in
    ///      _validatePaymasterUserOp against pre-bundle storage, not atomically re-checked
    ///      per-op within one handleOps bundle — a single bundle can push total sponsorship past
    ///      this figure. `0` = global sponsorship disabled (safe default). The EntryPoint
    ///      deposit — not this budget — is the EVM-enforced hard cap on total paymaster loss;
    ///      size the deposit as the acceptable max daily loss, not this budget.
    uint128 public globalDailyBudget;

    // slot 4 (packed)
    uint128 public globalSpentToday;
    uint32 public globalLastSpentDay;

    // slot 5
    mapping(address => WalletPolicy) private walletPolicy;

    // slot 6
    mapping(address => bool) public businessAllowlist;

    // slot 7
    /// @dev Per-op cap on `maxCost`: bounds how much of the EntryPoint
    ///      deposit a single op can reserve, independent of the (soft) budget/cap breakers above.
    ///      `0` = disabled (no per-op cap).
    uint128 public maxSponsoredOpCost;

    // ============ Events ============
    event PolicyManagerChanged(address indexed previousManager, address indexed newManager);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event GlobalDailyBudgetSet(uint128 budget);
    event GlobalDailyCapCeilingSet(uint128 ceiling);
    event MaxSponsoredOpCostSet(uint128 cost);
    event SponsoredSet(address indexed wallet, bool sponsored);
    event DailyCapSet(address indexed wallet, uint128 cap);
    event SponsorPersonalSet(address indexed wallet, bool sponsorPersonal);
    event VipSet(address indexed wallet, bool vip);
    event BusinessTargetSet(address indexed target, bool allowed);
    event GasSponsored(
        address indexed wallet,
        uint256 actualGasCost,
        uint128 walletSpentTodayAfter,
        uint128 globalSpentTodayAfter
    );

    // ============ Errors ============
    error ZeroAddress();
    error NotPolicyManager();
    error NotOwnerOrPolicyManager();
    error CapExceedsCeiling();
    error ZeroCapNotAllowed();

    // ============ Modifiers ============
    modifier onlyPolicyManager() {
        if (msg.sender != policyManager) revert NotPolicyManager();
        _;
    }

    /// @param _policyManager Hot backend key; owner may rotate it later via {setPolicyManager}.
    /// @dev Starts `paused = true` (safe bring-up) and `globalDailyBudget = 0` (disabled) until
    ///      the owner explicitly provisions them — see deploy-aa.ts bring-up order.
    constructor(IEntryPoint _entryPoint, address _policyManager) BasePaymaster(_entryPoint) {
        if (_policyManager == address(0)) revert ZeroAddress();
        policyManager = _policyManager;
        paused = true;
    }

    // ============ Owner (cold) ============
    function setPolicyManager(address m) external onlyOwner {
        if (m == address(0)) revert ZeroAddress();
        address prev = policyManager;
        policyManager = m;
        emit PolicyManagerChanged(prev, m);
    }

    function setGlobalDailyCapCeiling(uint128 ceiling) external onlyOwner {
        globalDailyCapCeiling = ceiling;
        emit GlobalDailyCapCeilingSet(ceiling);
    }

    /// @dev `budget == 0` disables all global sponsorship (hard decline all) — safe default.
    function setGlobalDailyBudget(uint128 budget) external onlyOwner {
        globalDailyBudget = budget;
        emit GlobalDailyBudgetSet(budget);
    }

    /// @dev `cost == 0` disables the per-op cap (no limit). See {maxSponsoredOpCost}.
    function setMaxSponsoredOpCost(uint128 cost) external onlyOwner {
        maxSponsoredOpCost = cost;
        emit MaxSponsoredOpCostSet(cost);
    }

    /// @notice VIP: per-wallet unlimited (bypasses `dailyCap`, but NOT the global budget).
    function setSponsoredUnlimited(address wallet, bool on) external onlyOwner {
        if (wallet == address(0)) revert ZeroAddress();
        walletPolicy[wallet].vip = on;
        emit VipSet(wallet, on);
    }

    function setBusinessTarget(address target, bool allowed) external onlyOwner {
        if (target == address(0)) revert ZeroAddress();
        businessAllowlist[target] = allowed;
        emit BusinessTargetSet(target, allowed);
    }

    function setBusinessTargets(address[] calldata targets, bool allowed) external onlyOwner {
        uint256 len = targets.length;
        for (uint256 i = 0; i < len; ) {
            address target = targets[i];
            if (target == address(0)) revert ZeroAddress();
            businessAllowlist[target] = allowed;
            emit BusinessTargetSet(target, allowed);
            unchecked {
                ++i;
            }
        }
    }

    /// @dev Only the owner can resume sponsorship after a pause (policyManager cannot).
    function unpause() external onlyOwner {
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ============ PolicyManager (hot) ============
    function setSponsored(address wallet, bool on) external onlyPolicyManager {
        if (wallet == address(0)) revert ZeroAddress();
        walletPolicy[wallet].sponsored = on;
        emit SponsoredSet(wallet, on);
    }

    /// @dev `cap` must be in `1..globalDailyCapCeiling` — `0` is "not provisioned".
    function setDailyCap(address wallet, uint128 cap) external onlyPolicyManager {
        if (wallet == address(0)) revert ZeroAddress();
        if (cap == 0) revert ZeroCapNotAllowed();
        if (cap > globalDailyCapCeiling) revert CapExceedsCeiling();
        walletPolicy[wallet].dailyCap = cap;
        emit DailyCapSet(wallet, cap);
    }

    function setSponsorPersonal(address wallet, bool on) external onlyPolicyManager {
        if (wallet == address(0)) revert ZeroAddress();
        walletPolicy[wallet].sponsorPersonal = on;
        emit SponsorPersonalSet(wallet, on);
    }

    function setSponsoredBatch(address[] calldata wallets, bool on) external onlyPolicyManager {
        uint256 len = wallets.length;
        for (uint256 i = 0; i < len; ) {
            address wallet = wallets[i];
            if (wallet == address(0)) revert ZeroAddress();
            walletPolicy[wallet].sponsored = on;
            emit SponsoredSet(wallet, on);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Kill-switch: owner OR policyManager can stop the bleeding immediately.
    ///         Only the owner can {unpause}.
    function pause() external {
        if (msg.sender != owner() && msg.sender != policyManager) revert NotOwnerOrPolicyManager();
        paused = true;
        emit Paused(msg.sender);
    }

    // ============ Views ============
    function getPolicy(address wallet) external view returns (WalletPolicy memory) {
        return walletPolicy[wallet];
    }

    /// @dev Off-chain convenience: MAY use block.timestamp since this is a plain view call,
    ///      never invoked by the EntryPoint during validation.
    function effectiveSpentToday(address wallet) external view returns (uint128) {
        WalletPolicy storage p = walletPolicy[wallet];
        uint32 today = uint32(block.timestamp / 1 days);
        return p.lastSpentDay == today ? p.spentToday : 0;
    }

    // ============ Paymaster Logic ============
    /**
     * @dev Timestamp-free sponsorship decision. Two outcomes:
     *      HARD_DECLINE (sigFail=true, clock-independent policy/config "no") or SPONSOR
     *      (sigFail=false, non-empty context so `_postOp` always accrues, `validAfter` may be
     *      future to defer a time-dependent cap/budget decision to the EntryPoint's clock).
     *      MUST NOT read block.timestamp/block.number and MUST NOT write storage (ERC-7562).
     */
    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /*userOpHash*/,
        uint256 maxCost
    ) internal view override returns (bytes memory context, uint256 validationData) {
        if (paused) {
            return ("", _packValidationData(true, 0, 0));
        }

        uint128 postOpGas = uint128(
            bytes16(userOp.paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET:PAYMASTER_DATA_OFFSET])
        );
        if (postOpGas < MIN_POSTOP_GAS) {
            return ("", _packValidationData(true, 0, 0));
        }

        // per-op cap: bounds how much of the deposit a single op can reserve,
        // independent of the (soft) per-wallet/global breakers checked below.
        if (maxSponsoredOpCost != 0 && maxCost > maxSponsoredOpCost) {
            return ("", _packValidationData(true, 0, 0));
        }

        address sender = userOp.sender;
        WalletPolicy memory p = walletPolicy[sender];

        if (!p.sponsored) {
            return ("", _packValidationData(true, 0, 0));
        }
        if (!p.sponsorPersonal && !_extractBusinessOk(userOp.callData)) {
            return ("", _packValidationData(true, 0, 0));
        }
        if (globalDailyBudget == 0) {
            return ("", _packValidationData(true, 0, 0));
        }
        if (!p.vip && p.dailyCap == 0) {
            return ("", _packValidationData(true, 0, 0));
        }

        // --- time-dependent caps: RAW check vs stored counters, NO block.timestamp ---
        uint48 validAfter = 0;

        // per-wallet cap (skipped for VIP; VIP still hits the global check below)
        if (!p.vip) {
            if (uint256(p.spentToday) + maxCost > uint256(p.dailyCap)) {
                uint48 candidate = uint48((uint256(p.lastSpentDay) + 1) * 1 days);
                if (candidate > validAfter) validAfter = candidate;
            }
        }

        // global budget applies to ALL sponsored ops, INCLUDING VIP
        if (uint256(globalSpentToday) + maxCost > uint256(globalDailyBudget)) {
            uint48 candidate = uint48((uint256(globalLastSpentDay) + 1) * 1 days);
            if (candidate > validAfter) validAfter = candidate;
        }

        context = abi.encode(sender); // non-empty ALWAYS => postOp accrues (incl. VIP)
        return (context, _packValidationData(false, 0, validAfter));
    }

    /**
     * @dev Day rollover + accrual (execution phase; block.timestamp allowed here). Runs for both
     *      `opSucceeded` and `opReverted` (both pay gas — see IPaymaster.PostOpMode). No external
     *      calls => no reentrancy guard needed.
     */
    function _postOp(
        IPaymaster.PostOpMode /*mode*/,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 /*actualUserOpFeePerGas*/
    ) internal override {
        address sender = abi.decode(context, (address));
        uint32 today = uint32(block.timestamp / 1 days);

        WalletPolicy memory p = walletPolicy[sender];
        if (p.lastSpentDay != today) {
            p.spentToday = 0;
            p.lastSpentDay = today;
        }
        p.spentToday += uint128(actualGasCost);
        walletPolicy[sender] = p;

        if (globalLastSpentDay != today) {
            globalSpentToday = 0;
            globalLastSpentDay = today;
        }
        globalSpentToday += uint128(actualGasCost);

        emit GasSponsored(sender, actualGasCost, p.spentToday, globalSpentToday);
    }

    /**
     * @dev Defensive decode of the wallet's exec surface (never revert; malformed => false).
     *      Returns true iff the op is a recognizable business call whose target(s) are ALL
     *      allowlisted. Every calldata slice is bounds-checked BEFORE slicing — an out-of-range
     *      Solidity slice reverts, which in validation would be a hard AA33; we must avoid that.
     *      Reads only `businessAllowlist` (self storage) + calldata.
     */
    function _extractBusinessOk(bytes calldata callData) internal view returns (bool) {
        if (callData.length < 4) return false;
        bytes4 sel = bytes4(callData[0:4]);

        if (sel == StarzipWallet.execute.selector) {
            if (callData.length < 36) return false;
            address target = address(uint160(uint256(bytes32(callData[4:36]))));
            return businessAllowlist[target];
        }

        if (sel == StarzipWallet.executeBatch.selector) {
            // executeBatch(address[] dest, uint256[] values, bytes[] funcs)
            // head = sel(4) + 3 offset words(96) => min length 100 before following any offset
            if (callData.length < 100) return false;
            uint256 offDest = uint256(bytes32(callData[4:36])); // offset relative to callData[4]
            if (offDest > callData.length - 36) return false; // room for a length word
            uint256 lenPos = 4 + offDest; // no overflow: offDest bounded above
            if (lenPos + 32 > callData.length) return false;
            uint256 n = uint256(bytes32(callData[lenPos:lenPos + 32]));
            if (n == 0 || n > MAX_BATCH_SIZE) return false; // also caps loop + arithmetic
            uint256 dataStart = lenPos + 32;
            if (dataStart + n * 32 > callData.length) return false; // n<=32 => no overflow
            for (uint256 i = 0; i < n; ) {
                bytes32 w = bytes32(callData[dataStart + i * 32:dataStart + i * 32 + 32]);
                address target = address(uint160(uint256(w)));
                if (!businessAllowlist[target]) return false;
                unchecked {
                    ++i;
                }
            }
            return true;
        }

        return false; // unknown selector => not a business call
    }
}
