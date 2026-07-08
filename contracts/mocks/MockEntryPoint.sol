// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @dev Minimal mock EntryPoint for testing AA contracts.
 *      Supports IERC165 interface check required by BasePaymaster.
 */
contract MockEntryPoint {
    // IEntryPoint interfaceId that BasePaymaster checks
    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }

    // Minimal getNonce for UserOperationService tests
    function getNonce(address, uint192) external pure returns (uint256) {
        return 0;
    }
}
