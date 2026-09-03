// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title GarbageTailERC1271Wallet
 * @notice Test-only ERC-1271 wallet. Pins F5: returns exactly 32 bytes whose first 4 bytes are
 *         the correct magic value but whose trailing 28 bytes are non-zero garbage.
 * @dev NOT for production.
 */
contract GarbageTailERC1271Wallet {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes32) {
        return 0x1626ba7e00000000000000000000000000000000000000000000000000001234;
    }
}
