// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ERC1967Proxy} from "../ERC1967Proxy.sol";
import {StarzipWallet} from "./StarzipWallet.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

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
    event AccountCreated(address indexed account, bytes32 pubKeyX, bytes32 pubKeyY, uint256 salt);

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        accountImplementation = new StarzipWallet(_entryPoint);
    }

    // ============ Factory ============
    function createAccount(
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        address owner,
        uint256 salt
    ) external returns (address) {
        address predicted = getAddress(pubKeyX, pubKeyY, owner, salt);
        if (predicted.code.length > 0) return predicted;

        bytes memory initData = abi.encodeCall(
            StarzipWallet.initialize,
            (pubKeyX, pubKeyY, owner)
        );

        ERC1967Proxy proxy = new ERC1967Proxy{salt: bytes32(salt)}(
            address(accountImplementation),
            initData
        );

        emit AccountCreated(address(proxy), pubKeyX, pubKeyY, salt);
        return address(proxy);
    }

    function getAddress(
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        address owner,
        uint256 salt
    ) public view returns (address) {
        bytes memory initData = abi.encodeCall(
            StarzipWallet.initialize,
            (pubKeyX, pubKeyY, owner)
        );

        bytes memory proxyBytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(accountImplementation), initData)
        );

        return Create2.computeAddress(bytes32(salt), keccak256(proxyBytecode));
    }
}
