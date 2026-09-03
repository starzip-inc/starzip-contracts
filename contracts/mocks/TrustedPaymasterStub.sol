// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title TrustedPaymasterStub
 * @notice Minimal stand-in for a genuine `StarzipWallet` that answers `trustedPaymaster()`
 *         honestly, for tests that need a wallet-shaped address to HAVE CODE without deploying a
 *         real, full `StarzipWallet` instance.
 * @dev Audit F-1 option (b) (2026-08-30, team-lead-directed — security-r2.md §2.3):
 *      `VerifyingPaymaster._requireTrustedPaymaster` no longer waves a codeless address through
 *      (see that function's own NatSpec, "FOURTH REVISION") — it now REVERTS (`WalletNotDeployed`)
 *      on one. Several test suites drive `setSponsored`/`setSponsoredUnlimited` against SYNTHETIC,
 *      fixed addresses purely to set up different `walletPolicy` storage shapes for gas/invariant
 *      measurement (e.g. `test/VerifyingPaymaster.postOpGas.test.ts`, whose whole point is
 *      measuring `_postOp`'s cold-SSTORE cost under each policy shape, not testing wallet
 *      deployment at all) — those addresses were never meant to be real `StarzipWallet` instances,
 *      and forcing them to become one would change what those tests actually measure. This stub
 *      restores exactly the pre-(b) admissibility of such an address (deploy one instance
 *      pointing at the real paymaster, then copy its runtime code onto the target address via
 *      `hardhat_setCode` — the JSON-RPC equivalent of Foundry's `vm.etch`, used the same way in
 *      `test/PaymasterInvariants.t.sol`) without reintroducing the removed carve-out on the
 *      production contract itself.
 *
 *      SSA-01: `_requireTrustedPaymaster` also staticcalls
 *      `pendingImplementation()`/`hasBeenUpgraded()` and fails closed if either call fails, so both
 *      are answered here as "no upgrade ever staged or executed".
 */
contract TrustedPaymasterStub {
    address public immutable trustedPaymaster;

    constructor(address _trustedPaymaster) {
        trustedPaymaster = _trustedPaymaster;
    }

    function pendingImplementation() external pure returns (address) {
        return address(0);
    }

    function hasBeenUpgraded() external pure returns (bool) {
        return false;
    }
}
