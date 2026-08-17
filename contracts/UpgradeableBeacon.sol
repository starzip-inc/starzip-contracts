// contracts/UpgradeableBeacon.sol
// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/proxy/beacon/IBeacon.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "./interfaces/ITimelockedBeacon.sol";

/**
 * @dev This contract is used in conjunction with one or more instances of {BeaconProxy} to determine their
 * implementation contract, which is where they will delegate all function calls.
 *
 * An owner is able to change the implementation the beacon points to, thus upgrading the proxies that use this beacon.
 *
 * Security:
 *  - Uses Ownable2Step to prevent accidental ownership transfers.
 *  - Upgrades are 48h timelocked (see {ITimelockedBeacon}): `requestUpgrade` stages a
 *    candidate, `upgradeTo` may only execute the staged candidate inside the window
 *    `[upgradeReadyAt, upgradeReadyAt + UPGRADE_GRACE_PERIOD]`, and `cancelUpgrade` aborts a
 *    staged upgrade. Staging is single-use — it is cleared when consumed. Without this, a single
 *    owner transaction rewrote the logic of EVERY BeaconProxy at once, including tokens escrowed
 *    in TradeSettlementV1, whose `recoverStuckTokens` guard trusts a live
 *    `balanceOf(address(this))` call into that very token.
 *    TradeSettlementV1 already timelocks its own upgrades 48h; this closes the same gap
 *    one layer down, at the asset itself.
 *  - The staging EXPIRES. A matured-but-unused staging used to stay armed
 *    indefinitely, so an owner could pre-arm a malicious implementation, sit out the 48h while
 *    the chain was quiet, and fire it in one transaction years later. The timelock then only
 *    guaranteed "one 48h announcement, ever", not "48h of live notice before every upgrade".
 *  - Ownership handover clears the staging: a new owner never inherits an
 *    armed payload — with a running clock — staged by the outgoing one.
 *
 *  The constructor's initial implementation is NOT timelocked — at construction there are no
 *  proxies pointing at this beacon yet, so there is nothing to protect.
 */
contract UpgradeableBeacon is IBeacon, ITimelockedBeacon, Ownable2Step {
    /// @inheritdoc ITimelockedBeacon
    uint256 public constant UPGRADE_TIMELOCK_DELAY = 48 hours;

    /// @inheritdoc ITimelockedBeacon
    /// @dev 7 days. Chosen as the shortest window that never forces a re-stage for purely
    ///      calendar reasons: a staging matures 48h after the request, and a human/multisig
    ///      release process must be able to execute it across a weekend plus the following
    ///      business week without the request going stale. Longer buys nothing — it only extends
    ///      how long a hostile payload can sit armed. Total armed lifetime is therefore bounded at
    ///      48h + 7d = 9 days, after which execution requires a new `requestUpgrade` and hence a
    ///      new public `UpgradeRequested` announcement.
    uint256 public constant UPGRADE_GRACE_PERIOD = 7 days;

    address private _implementation;

    /// @inheritdoc ITimelockedBeacon
    address public pendingImplementation;

    /// @inheritdoc ITimelockedBeacon
    uint256 public upgradeReadyAt;

    /**
     * @dev Emitted when the implementation returned by the beacon is changed.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Sets the address of the initial implementation, and the initial owner who can upgrade the beacon.
     */
    constructor(address implementation_, address initialOwner) Ownable(initialOwner) {
        _setImplementation(implementation_);
    }

    /**
     * @dev Returns the current implementation address.
     */
    function implementation() public view virtual returns (address) {
        return _implementation;
    }

    /**
     * @dev Stages `newImplementation` for upgrade. It becomes executable via {upgradeTo}
     *      once `UPGRADE_TIMELOCK_DELAY` has elapsed, and stops being executable
     *      `UPGRADE_GRACE_PERIOD` after that. Re-staging overwrites any previously staged
     *      candidate and restarts the clock.
     *
     * Emits an {UpgradeRequested} event.
     *
     * Requirements:
     *
     * - msg.sender must be the owner of the contract.
     * - `newImplementation` must be a contract.
     */
    function requestUpgrade(address newImplementation) external virtual onlyOwner {
        if (newImplementation.code.length == 0) {
            revert BeaconInvalidImplementation(newImplementation);
        }
        pendingImplementation = newImplementation;
        upgradeReadyAt = block.timestamp + UPGRADE_TIMELOCK_DELAY;
        emit UpgradeRequested(newImplementation, upgradeReadyAt);
    }

    /**
     * @dev Cancels the staged upgrade, so an upgrade observed to be malicious can be aborted
     *      inside the timelock window.
     *
     * Emits an {UpgradeCancelled} event.
     *
     * Requirements:
     *
     * - msg.sender must be the owner of the contract.
     * - an upgrade must be staged.
     */
    function cancelUpgrade() external virtual onlyOwner {
        if (pendingImplementation == address(0)) {
            revert NoPendingUpgrade();
        }
        emit UpgradeCancelled(pendingImplementation);
        pendingImplementation = address(0);
        upgradeReadyAt = 0;
    }

    /**
     * @dev Executes a previously staged upgrade. The staging is single-use: it is cleared
     *      here, so a second `upgradeTo` requires a fresh `requestUpgrade` (and a fresh 48h).
     *      It is also time-boxed: once `UPGRADE_GRACE_PERIOD` past maturity it expires and can
     *      no longer be executed at all — see the contract header.
     *
     * Emits an {Upgraded} event.
     *
     * Requirements:
     *
     * - msg.sender must be the owner of the contract.
     * - `newImplementation` must equal the staged {pendingImplementation}.
     * - `block.timestamp` must be within `[upgradeReadyAt, upgradeReadyAt + UPGRADE_GRACE_PERIOD]`.
     */
    function upgradeTo(address newImplementation) public virtual onlyOwner {
        if (pendingImplementation == address(0) || newImplementation != pendingImplementation) {
            revert NoPendingUpgrade();
        }
        if (block.timestamp < upgradeReadyAt) {
            revert UpgradeNotReady();
        }
        if (block.timestamp > upgradeReadyAt + UPGRADE_GRACE_PERIOD) {
            revert UpgradeExpired();
        }
        pendingImplementation = address(0);
        upgradeReadyAt = 0;
        _setImplementation(newImplementation);
    }

    /**
     * @dev Clears any staged upgrade whenever ownership actually moves.
     *
     *      `Ownable2Step.transferOwnership` only nominates; ownership changes here, on
     *      `acceptOwnership` (and on `renounceOwnership`). Without this, a staged implementation
     *      — and its already-running clock — survived the handover, so an incoming owner could
     *      execute a payload they never staged and may not have been told about. Clearing it
     *      makes the incoming owner re-stage, restarting the 48h notice under their own key.
     *
     *      Emits {UpgradeCancelled} so the drop is observable off-chain, exactly like an explicit
     *      {cancelUpgrade}.
     *
     *      No-ops when nothing is staged, which is also the case during construction.
     */
    function _transferOwnership(address newOwner) internal virtual override {
        if (pendingImplementation != address(0)) {
            emit UpgradeCancelled(pendingImplementation);
            pendingImplementation = address(0);
            upgradeReadyAt = 0;
        }
        super._transferOwnership(newOwner);
    }

    /**
     * @dev Sets the implementation contract address for this beacon
     *
     * Requirements:
     *
     * - `newImplementation` must be a contract.
     */
    function _setImplementation(address newImplementation) private {
        if (newImplementation.code.length == 0) {
            revert BeaconInvalidImplementation(newImplementation);
        }
        _implementation = newImplementation;
        emit Upgraded(newImplementation);
    }
}
