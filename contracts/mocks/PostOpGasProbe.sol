// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { IPaymaster } from "@account-abstraction/contracts/interfaces/IPaymaster.sol";

/**
 * @dev Test-only "fake EntryPoint" used to empirically measure `VerifyingPaymaster._postOp`'s
 *      worst-case (cold) gas cost, for deriving `MIN_POSTOP_GAS`.
 *
 *      Satisfies `BasePaymaster`'s constructor-time ERC165 interface check
 *      (`supportsInterface` unconditionally true) so a `VerifyingPaymaster` can be deployed with
 *      this contract's address as its immutable `entryPoint`. `measurePostOpGas` then calls
 *      `IPaymaster.postOp` directly (satisfying `_requireFromEntryPoint`, since `msg.sender` is
 *      this contract) and reports the EXACT gas consumed by that call via `gasleft()` deltas —
 *      i.e. precisely what a real EntryPoint would forward as `paymasterPostOpGasLimit`.
 *
 *      Calling `postOp` here as the very FIRST storage-touching op on a freshly deployed
 *      paymaster gives every slot `_postOp` reads/writes (walletPolicy[sender], the global
 *      spent/day slot) a genuinely COLD access — a strictly worse (higher-gas) case than the
 *      real handleOps flow, where `_validatePaymasterUserOp` already warms those slots earlier
 *      in the same transaction. Using this stricter number to size `MIN_POSTOP_GAS` is
 *      conservative by construction.
 */
contract PostOpGasProbe {
    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }

    function measurePostOpGas(
        address paymaster,
        IPaymaster.PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external returns (uint256 gasUsed) {
        uint256 gasBefore = gasleft();
        IPaymaster(paymaster).postOp(mode, context, actualGasCost, actualUserOpFeePerGas);
        gasUsed = gasBefore - gasleft();
    }
}
