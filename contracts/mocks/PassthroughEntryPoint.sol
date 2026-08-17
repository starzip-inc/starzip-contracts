// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IExecutableAccount {
    function execute(address dest, uint256 value, bytes calldata func) external;
    function executeBatch(address[] calldata dest, uint256[] calldata values, bytes[] calldata funcs) external;
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
 *      its full interface). Only the ERC-4337 validation machinery around `execute`/`executeBatch`
 *      is skipped, which is irrelevant to what a reentrancy-guard test is checking.
 */
contract PassthroughEntryPoint {
    function callExecute(IExecutableAccount account, address dest, uint256 value, bytes calldata func) external {
        account.execute(dest, value, func);
    }

    function callExecuteBatch(
        IExecutableAccount account,
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata funcs
    ) external {
        account.executeBatch(dest, values, funcs);
    }
}
