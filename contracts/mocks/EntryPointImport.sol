// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

// Test-only: subclass the canonical ERC-4337 EntryPoint v0.8 so Hardhat emits a
// deployable artifact ("TestEntryPoint") for E2E tests (real handleOps flow).
// Not used by production contracts.
import { EntryPoint } from "@account-abstraction/contracts/core/EntryPoint.sol";

contract TestEntryPoint is EntryPoint {}
