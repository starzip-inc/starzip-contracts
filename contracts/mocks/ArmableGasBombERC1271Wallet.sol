// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title ArmableGasBombERC1271Wallet
 * @notice Test-only ERC-1271 wallet that is CHEAP until `arm()` is called and a gas bomb after.
 *         Pins the SSA-17 attack sequence itself: estimate the batch while the wallet answers
 *         cheaply, arm it, then execute with that unchanged estimate.
 * @dev NOT for production. Always returns the ERC-1271 INVALID sentinel, never the magic value —
 *      the attack never needed its own item to settle, only to cost more than it was measured at.
 */
contract ArmableGasBombERC1271Wallet {
    bool public armed;

    /// @notice Flip from cheap to gas-burning. Called between estimation and execution.
    function arm() external {
        armed = true;
    }

    /// @notice Cheap (one SLOAD, immediate return) while disarmed; burns to ~5000 gas once armed.
    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        if (armed) {
            // solhint-disable-next-line no-empty-blocks
            while (gasleft() > 5000) {}
        }
        return 0xffffffff;
    }
}
