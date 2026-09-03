// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title GasBombERC1271Wallet
 * @notice Test-only ERC-1271 wallet whose `isValidSignature` burns almost all of whatever gas it
 *         is forwarded before returning. Pins SSA-17.
 * @dev NOT for production. Always returns the ERC-1271 INVALID sentinel, never the magic value.
 */
contract GasBombERC1271Wallet {
    /// @notice Burns gas down to ~5000 remaining, then returns "invalid".
    function isValidSignature(bytes32, bytes calldata) external view returns (bytes4) {
        // solhint-disable-next-line no-empty-blocks
        while (gasleft() > 5000) {}
        return 0xffffffff;
    }
}
