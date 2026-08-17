// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title ITimelockedBeacon
 * @notice Interface for a beacon that stages implementation upgrades behind a fixed
 *         timelock, instead of executing them immediately.
 * @dev WHY THIS EXISTS:
 *
 *      `contracts/UpgradeableBeacon.sol:56` exposes:
 *          function upgradeTo(address newImplementation) public virtual onlyOwner
 *      with NO staging and NO delay — a single transaction from the beacon owner
 *      immediately rewrites the implementation that every `BeaconProxy` instance
 *      delegates to (`UpgradeableBeacon.sol:42-44,56-58,67-73`). Because every
 *      ERC20V1 token is deployed as a `BeaconProxy` against this same beacon, one
 *      untimelocked `upgradeTo` call swaps the logic of EVERY token held in the
 *      TradeSettlementV1 escrow at once.
 *
 *      This directly defeats the ledger-based owner-drain guard:
 *      `TradeSettlementV1.recoverStuckTokens` (contracts/trade/TradeSettlementV1.sol:922-930)
 *      keys recovery on `IERC20(_token).balanceOf(address(this)) - totalTracked[_token]`,
 *      i.e. it trusts a live external call back into the token contract. A beacon owner
 *      can (1) `upgradeTo` a malicious implementation that reports an inflated
 *      `balanceOf(address(this))` for the escrow, then (2) call `recoverStuckTokens` to
 *      drain the "recoverable" delta the forged balance now implies — all in ordinary
 *      transactions, with no on-chain trace distinguishing it from a legitimate upgrade.
 *      TradeSettlementV1 already timelocks its OWN upgrades 48h
 *      (`UPGRADE_TIMELOCK_DELAY`, `requestUpgrade`/`cancelUpgrade`/`_authorizeUpgrade`,
 *      TradeSettlementV1.sol:72,209-210,257-259,928-966) precisely so an owner-compromise
 *      window is observable and cancellable before it takes effect; the asset layer
 *      (the beacon) currently has no equivalent, so that settlement-side protection is
 *      only as strong as the beacon's weakest link.
 *
 *      This interface defines the staged-upgrade surface a conforming beacon must expose:
 *      `requestUpgrade` stages a candidate implementation and starts the clock,
 *      `upgradeTo` only succeeds inside the execution window
 *      `[upgradeReadyAt, upgradeReadyAt + UPGRADE_GRACE_PERIOD]` AND with an argument matching
 *      the staged address, and `cancelUpgrade` lets the owner (or a future multisig) abort a
 *      staged upgrade observed to be malicious before it can execute.
 *
 *      THE GRACE PERIOD IS PART OF THE GUARANTEE. Without an expiry a matured
 *      staging stays armed forever: an owner stages quietly, lets the 48h pass while nobody is
 *      watching, and fires months later in a single transaction at a moment of their choosing.
 *      That degrades the timelock from "no upgrade without 48h of live notice" to "one 48h
 *      announcement, ever". Expiry forces an unused staging to be re-staged, which emits a fresh
 *      `UpgradeRequested` and restarts the clock, so every execution is preceded by a recent,
 *      observable announcement.
 *
 *      Staging is also cleared when ownership actually changes hands, so an incoming owner
 *      never inherits an armed payload staged by their predecessor.
 *
 *      STATUS: implemented by `contracts/UpgradeableBeacon.sol` (both the ERC20V1 beacon and
 *      the TokenVestingWallet beacon are instances of it). An earlier "interface only, the
 *      beacon is NOT modified" scope limit no longer holds. The config-only mitigation (moving
 *      the beacon owner from the deployer EOA to a multisig) remains tracked separately and is
 *      complementary: the timelock makes
 *      an owner-compromise window observable and cancellable, the multisig makes it harder to
 *      reach in the first place.
 */
interface ITimelockedBeacon {
    /// @notice Fixed delay between `requestUpgrade` and the earliest allowed `upgradeTo`.
    function UPGRADE_TIMELOCK_DELAY() external view returns (uint256);

    /// @notice How long a matured staging stays executable before it expires and must be re-staged.
    function UPGRADE_GRACE_PERIOD() external view returns (uint256);

    /// @notice Implementation currently staged for upgrade, or address(0) if none is pending.
    function pendingImplementation() external view returns (address);

    /// @notice Timestamp at which the staged implementation becomes upgradeable (0 if none pending).
    function upgradeReadyAt() external view returns (uint256);

    /**
     * @notice Stage `newImplementation` for upgrade; it becomes executable once
     *         `UPGRADE_TIMELOCK_DELAY` has elapsed.
     * @param newImplementation Address of the new implementation contract (must have code).
     */
    function requestUpgrade(address newImplementation) external;

    /// @notice Cancel a pending staged upgrade.
    function cancelUpgrade() external;

    /**
     * @notice Execute a previously staged upgrade.
     * @dev Must revert unless `newImplementation` equals the currently staged
     *      `pendingImplementation` and `block.timestamp` lies within
     *      `[upgradeReadyAt, upgradeReadyAt + UPGRADE_GRACE_PERIOD]`.
     * @param newImplementation Address of the new implementation contract.
     */
    function upgradeTo(address newImplementation) external;

    /// @notice Emitted when an upgrade is staged via `requestUpgrade`.
    event UpgradeRequested(address indexed newImplementation, uint256 readyAt);

    /// @notice Emitted when a staged upgrade stops being armed: via `cancelUpgrade`, or because
    ///         ownership changed hands and the staging was dropped with it.
    event UpgradeCancelled(address indexed cancelledImplementation);

    /// @dev `newImplementation` is not a deployed contract (zero address or no code).
    error BeaconInvalidImplementation(address implementation);

    /// @dev `upgradeTo`/`cancelUpgrade` called with no staged implementation, or the
    ///      argument to `upgradeTo` does not match the staged implementation.
    error NoPendingUpgrade();

    /// @dev `upgradeTo` called before `upgradeReadyAt` has elapsed.
    error UpgradeNotReady();

    /// @dev `upgradeTo` called after the staging's execution window closed
    ///      (`upgradeReadyAt + UPGRADE_GRACE_PERIOD`). Re-stage to get a fresh window — and a
    ///      fresh public announcement.
    error UpgradeExpired();
}
