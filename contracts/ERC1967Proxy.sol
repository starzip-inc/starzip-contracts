// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ERC1967Proxy as OZProxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title ERC1967Proxy
 * @notice Re-export of OpenZeppelin's ERC1967Proxy for use in this project
 */
contract ERC1967Proxy is OZProxy {
    constructor(address implementation, bytes memory _data) OZProxy(implementation, _data) {}
}