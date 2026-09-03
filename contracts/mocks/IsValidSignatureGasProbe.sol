// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @dev Test-only gas probe for ERC1271_GAS_STIPEND derivation (F6). Measures the EXACT gas
 *      consumed by a target wallet's `isValidSignature(bytes32,bytes)`, mirroring the STATICCALL
 *      `TradeSettlementV1._isValidERC1271SignatureStipended` makes.
 */
contract IsValidSignatureGasProbe {
    function measure(address wallet, bytes32 hash, bytes calldata signature)
        external
        view
        returns (uint256 gasUsed)
    {
        uint256 gasBefore = gasleft();
        (bool ok, ) = wallet.staticcall(abi.encodeWithSignature("isValidSignature(bytes32,bytes)", hash, signature));
        gasUsed = gasBefore - gasleft();
        require(ok, "call failed");
    }
}
