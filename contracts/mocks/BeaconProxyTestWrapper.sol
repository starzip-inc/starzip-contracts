// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

/**
 * @dev Test-only re-export so Hardhat generates a `BeaconProxy` artifact.
 *      OZ's `BeaconProxy` is referenced inline by `TokenFactory.issueToken`
 *      via `new BeaconProxy{salt: ...}(...)`, which compiles but does not
 *      produce a standalone artifact. Tests that need to deploy a
 *      `TokenVestingWallet` clone outside the factory go through this file.
 */
contract BeaconProxyTestWrapper is BeaconProxy {
    constructor(address beacon, bytes memory data) payable BeaconProxy(beacon, data) {}
}
