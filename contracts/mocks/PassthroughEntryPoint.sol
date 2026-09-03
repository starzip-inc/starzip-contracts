// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";

interface IExecutableAccount {
    function execute(address dest, uint256 value, bytes calldata func) external;
    function executeBatch(address[] calldata dest, uint256[] calldata values, bytes[] calldata funcs) external;
    /// @dev SSA-18 (StarzipWallet.sol): needed to prime the `ownerEpoch` transient snapshot.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}

/**
 * @dev Test-only mock for StarzipWallet `nonReentrant` coverage.
 *
 *      A minimal stand-in "EntryPoint" with NO reentrancy protection of its own — used to test
 *      StarzipWallet's OWN `nonReentrant` guard on `execute`/`executeBatch` IN ISOLATION from the
 *      REAL `EntryPoint`'s separate `nonReentrant` on `handleOps` (see the account-abstraction
 *      package's core/EntryPoint.sol). That guard blocks any nested `handleOps` call before it
 *      ever reaches the wallet, which would mask whether StarzipWallet's OWN guard does anything
 *      at all if this contract were the real EntryPoint.
 *
 *      A StarzipWallet deployed with THIS contract's address as its immutable `entryPoint`
 *      exercises the exact same `onlyEntryPoint` + `nonReentrant`-gated `execute`/`executeBatch`
 *      code as production (`onlyEntryPoint` only compares `msg.sender == address(entryPoint)` — it
 *      does not require the entry point to be the canonical ERC-4337 singleton, or even implement
 *      its full interface). Only the ERC-4337 SIGNATURE validation machinery around
 *      `execute`/`executeBatch` is skipped, which is irrelevant to what a reentrancy-guard test is
 *      checking.
 *
 *      SSA-18: `execute`/`executeBatch` revert `OwnerSetChanged()` unless the wallet's own
 *      `validateUserOp` ran earlier in the same transaction, so `callExecute`/`callExecuteBatch`
 *      prime it with a throwaway op and `missingAccountFunds = 0` (which keeps the one external
 *      call inside `validateUserOp` unreachable). `validateUserOp` never reverts on a bad
 *      signature and carries no `nonReentrant` modifier, so priming does not affect the guard
 *      under test.
 */
contract PassthroughEntryPoint {
    function callExecute(IExecutableAccount account, address dest, uint256 value, bytes calldata func) external {
        account.validateUserOp(_dummyUserOp(), bytes32(0), 0);
        account.execute(dest, value, func);
    }

    function callExecuteBatch(
        IExecutableAccount account,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata funcs
    ) external {
        account.validateUserOp(_dummyUserOp(), bytes32(0), 0);
        account.executeBatch(dest, values, funcs);
    }

    /// @dev Every field is inert; an empty `signature` decodes as malformed
    ///      (`_decodeSignatureWrapper` requires >= 128 bytes) rather than reverting.
    function _dummyUserOp() private pure returns (PackedUserOperation memory) {
        return
            PackedUserOperation({
                sender: address(0),
                nonce: 0,
                initCode: "",
                callData: "",
                accountGasLimits: bytes32(0),
                preVerificationGas: 0,
                gasFees: bytes32(0),
                paymasterAndData: "",
                signature: ""
            });
    }
}
