// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ERC1967Proxy } from "../ERC1967Proxy.sol";
import { StarzipWallet } from "./StarzipWallet.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { Create2 } from "@openzeppelin/contracts/utils/Create2.sol";

/**
 * @title StarzipWalletFactory
 * @notice CREATE2 factory for deterministic StarzipWallet deployment
 * @dev Non-proxy (stateless). Deploys StarzipWallet implementation once in constructor.
 */
contract StarzipWalletFactory {
    // ============ Immutable ============
    StarzipWallet public immutable accountImplementation;
    IEntryPoint public immutable entryPoint;

    // ============ Events ============
    /// @dev `owners` is the same `abi.encode`d owner-blob array `StarzipWallet.initialize`
    ///      accepts — each element is `abi.encode(address)` (32 bytes) for an EOA-style owner, or
    ///      `abi.encode(bytes32 x, bytes32 y)` (64 bytes) for a P-256 passkey owner. This is the
    ///      full initial owner set, not a single first owner — see {StarzipWallet-initialize}'s
    ///      NatSpec for why a wallet must not be born with only one owner.
    event AccountCreated(address indexed account, bytes[] owners, uint256 salt);

    constructor(IEntryPoint _entryPoint, address _canonicalPaymaster) {
        entryPoint = _entryPoint;
        accountImplementation = new StarzipWallet(_entryPoint, _canonicalPaymaster);
    }

    // ============ Factory ============
    /**
     * @notice Deploy (or return the existing) wallet for `(owners, salt)`.
     * @dev `owners` must be non-empty, and each element exactly 32 bytes
     *      (`abi.encode(address)`) or 64 bytes (`abi.encode(bytes32 x, bytes32 y)`) —
     *      `StarzipWallet.initialize` enforces the array-non-empty and per-element shape/validity
     *      (non-zero address / on-curve passkey) checks; this factory does not duplicate that
     *      validation, it only predicts and deploys. The full owner set is part of the initcode
     *      (via `initData`, which participates in the CREATE2 address hash — see {getAddress}),
     *      so the counterfactual address stays bound to the FULL owner set, not just one key: two
     *      calls that differ only in a later element of `owners` predict and deploy to different
     *      addresses, exactly as differing in `firstOwner` always did.
     */
    function createAccount(bytes[] calldata owners, uint256 salt) external returns (address) {
        address predicted = getAddress(owners, salt);
        if (predicted.code.length > 0) return predicted;

        bytes memory initData = abi.encodeCall(StarzipWallet.initialize, (owners));

        ERC1967Proxy proxy = new ERC1967Proxy{ salt: bytes32(salt) }(address(accountImplementation), initData);

        emit AccountCreated(address(proxy), owners, salt);
        return address(proxy);
    }

    /**
     * @dev SSA-16: rejects every owner set `createAccount` (via `StarzipWallet.initialize` ->
     *      `_registerOwner`) would reject, so a counterfactual address is never predicted for an
     *      undeployable set. Shape/value checks come from {StarzipWallet-validateOwnerBytes};
     *      `_registerOwner`'s storage-backed `isOwnerBytes` duplicate check has no equivalent in a
     *      `view` call against a not-yet-deployed account, so duplicates are caught pairwise here.
     */
    function getAddress(bytes[] calldata owners, uint256 salt) public view returns (address) {
        if (owners.length == 0) revert StarzipWallet.InvalidArrayLength();
        for (uint256 i = 0; i < owners.length; ) {
            accountImplementation.validateOwnerBytes(owners[i]);
            for (uint256 j = 0; j < i; ) {
                if (keccak256(owners[i]) == keccak256(owners[j])) revert StarzipWallet.AlreadyOwner();
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        bytes memory initData = abi.encodeCall(StarzipWallet.initialize, (owners));

        bytes memory proxyBytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(accountImplementation), initData)
        );

        return Create2.computeAddress(bytes32(salt), keccak256(proxyBytecode));
    }
}
