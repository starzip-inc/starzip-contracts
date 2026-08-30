// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title RevertingPaymasterStub
 * @notice Stands in as a `StarzipWallet`'s `canonicalPaymaster` that always REVERTS on
 *         `revokeSponsorshipOnUpgrade()`.
 * @dev Used to prove `StarzipWallet._authorizeUpgrade`'s chosen behaviour (docs/audits review,
 *      2026-08-30, `fix/mainnet-deploy-and-certik-verification`): a failed or unreachable
 *      paymaster revoke-push must never block an already-timelocked, owner-authorized upgrade —
 *      the alternative (reverting the upgrade on a failed push) would let a misconfigured, paused,
 *      or replaced paymaster permanently brick every wallet naming it, which is worse than the
 *      stale-sponsorship state the push exists to prevent. See
 *      test/StarzipWallet.test.ts, "Review hardening" ->
 *      "_authorizeUpgrade proceeds even when the paymaster revoke call reverts".
 */
contract RevertingPaymasterStub {
    error AlwaysReverts();

    function revokeSponsorshipOnUpgrade() external pure {
        revert AlwaysReverts();
    }
}
