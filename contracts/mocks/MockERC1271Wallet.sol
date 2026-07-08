// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title MockERC1271Wallet
 * @notice Test-only ERC-1271 smart-contract wallet. Validates signatures against a single owner
 *         EOA key and can execute arbitrary calls (to deposit into / interact with contracts as
 *         a contract account). Used by the TradeSettlement signature tests to exercise the
 *         SignatureChecker (ERC-1271) authorization path.
 * @dev NOT for production. Deployed only in tests.
 */
contract MockERC1271Wallet {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    /// @notice ERC-1271 signature validation: returns the magic value iff `signature` is a valid
    ///         ECDSA signature over `hash` by `owner`.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) {
            return MAGICVALUE;
        }
        return 0xffffffff;
    }

    /// @notice Execute an arbitrary call from this wallet (e.g. approve + deposit).
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok, "MockERC1271Wallet: call failed");
        return ret;
    }
}
