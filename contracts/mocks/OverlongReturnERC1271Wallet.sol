// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title OverlongReturnERC1271Wallet
 * @notice Test-only ERC-1271 wallet. Pins F5: returns 64 bytes — a correctly zero-padded magic
 *         value word followed by a second, extraneous word.
 * @dev NOT for production.
 */
contract OverlongReturnERC1271Wallet {
    // Two static bytes32 returns ABI-encode as raw concatenated words (no offset/length header),
    // unlike `returns (bytes memory)` which would wrap this in a dynamic-type header and no longer
    // return the raw 64 bytes described above.
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes32, bytes32) {
        return (bytes32(bytes4(0x1626ba7e)), bytes32(uint256(0xdead)));
    }
}
