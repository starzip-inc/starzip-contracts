// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @dev Test-only mock for hard-revert reproduction.
 *
 *      Implements the ITokenVestingWallet interface that LaunchpadV1._triggerOwnerVesting
 *      calls. `startVesting()` unconditionally reverts with a recognizable message,
 *      simulating a broken vesting wallet implementation behind a rotated beacon.
 *
 *      Invariant under test: if startVesting fails → finalizeLaunchpad reverts atomically
 *      and ownerVestingTrigger[id] stays false (no soft-fail / partial state).
 *
 *      Deployment pattern in tests:
 *        1. Deploy MaliciousVestingWallet impl.
 *        2. Deploy a new UpgradeableBeacon pointing to this impl.
 *        3. Queue + execute vestingWalletBeacon change on TokenFactory (2-day timelock).
 *        4. issueToken → the BeaconProxy clone's logic is now MaliciousVestingWallet.
 *        5. createLaunchpad → finalizeLaunchpad → expect hard revert.
 */
contract MaliciousVestingWallet {
    // ── ITokenVestingWallet minimal surface ────────────────────────────────────

    /// @notice Always reverts — simulates a broken startVesting implementation.
    function startVesting(uint64 /*startTimestamp*/, uint64 /*duration_*/) external pure {
        revert("MaliciousVestingWallet: startVesting always reverts");
    }

    /// @notice Returns a non-zero duration so _triggerOwnerVesting passes the
    ///         pre-check (`dur > 0`) before calling startVesting.
    function duration() external pure returns (uint64) {
        return 365 days;
    }

    /// @notice Required by BeaconProxy: must be callable as initializer.
    ///         Does nothing — the beacon clone path calls initialize() on first use.
    function initialize(
        address /*beneficiary*/,
        address /*launchpad_*/,
        address /*token_*/,
        uint64 /*duration_*/,
        uint64 /*cliff_*/
    ) external {
        // Intentionally empty — malicious impl ignores init.
    }

    /// @dev Catch-all so the contract can receive any unexpected calls.
    fallback() external payable {}
    receive() external payable {}
}
