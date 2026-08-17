// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IPassthroughEntryPointLike {
    function callExecute(address account, address dest, uint256 value, bytes calldata func) external;
    function callExecuteBatch(
        address account,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata funcs
    ) external;
}

/**
 * @dev Test-only mock for StarzipWallet `nonReentrant` coverage.
 *
 *      When `execute`d by a StarzipWallet that is wired to a `PassthroughEntryPoint` (see that
 *      contract), this contract calls straight back into that SAME entry point to invoke
 *      `execute`/`executeBatch` on the SAME wallet again, still mid-call — exactly the reentrant
 *      shape `nonReentrant` (`ReentrancyGuardTransient`) exists to block. The nested call's revert
 *      is swallowed so the test can read the OUTER call's own success/failure (via the wallet's
 *      `Executed` event / a non-reverting transaction) independently of whether the reentry itself
 *      was blocked (read back from `reenterBlocked`/`reenterAttempted` after the fact).
 */
contract ReentrantExecuteTrigger {
    bool public reenterAttempted;
    bool public reenterBlocked;

    function reenterExecute(address entryPoint, address wallet) external {
        reenterAttempted = true;
        try IPassthroughEntryPointLike(entryPoint).callExecute(wallet, wallet, 0, "") {
            reenterBlocked = false;
        } catch {
            reenterBlocked = true;
        }
    }

    function reenterExecuteBatch(address entryPoint, address wallet) external {
        reenterAttempted = true;
        address[] memory dest = new address[](1);
        dest[0] = wallet;
        uint256[] memory values = new uint256[](1);
        bytes[] memory funcs = new bytes[](1);
        funcs[0] = "";
        try IPassthroughEntryPointLike(entryPoint).callExecuteBatch(wallet, dest, values, funcs) {
            reenterBlocked = false;
        } catch {
            reenterBlocked = true;
        }
    }
}
