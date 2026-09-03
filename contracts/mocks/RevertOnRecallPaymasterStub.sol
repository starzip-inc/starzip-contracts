// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title RevertOnRecallPaymasterStub
 * @notice Stands in as a `StarzipWallet`'s `canonicalPaymaster` whose `revokeSponsorshipOnUpgrade()`
 *         SUCCEEDS on the first call and REVERTS on every call after that.
 * @dev SSA-01: `StarzipWallet.requestUpgrade` is fail-closed, so an always-reverting stub can no
 *      longer reach a staged upgrade. This stub lets the staging-time call succeed while still
 *      failing `_authorizeUpgrade`'s later fallback call to the same function.
 */
contract RevertOnRecallPaymasterStub {
    error AlwaysRevertsAfterFirstCall();

    bool public called;

    function revokeSponsorshipOnUpgrade() external {
        if (called) revert AlwaysRevertsAfterFirstCall();
        called = true;
    }

    // F7: StarzipWallet's constructor staticcalls this selector to validate canonicalPaymaster.
    function getPolicy(address) external pure returns (bytes32) {
        return bytes32(0);
    }
}
