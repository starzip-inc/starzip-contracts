// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ERC1967Proxy } from "../ERC1967Proxy.sol";

/**
 * @dev Test-only stand-in for `TokenFactory` in the role ERC20V1 actually uses it for:
 *      the `launchpad` pointer, which is both the mint authority (`onlyLaunchpad`) and the
 *      platform registry consulted by `_isPlatform` (blacklist carve-out, pause carve-out).
 *
 *      Exists because a factory-issued token cannot exercise either edge:
 *        - `TokenFactory` locks `maxSupply == totalSupply` right after the issuance mint, so
 *          there is no reachable post-issuance mint to observe under pause;
 *        - `TokenFactory.isPlatformContract` never reverts, so the fail-closed `catch` in
 *          `_isPlatform` is unreachable through it.
 *
 *      `deployToken` deploys the ERC1967Proxy from THIS contract so the token records
 *      `launchpad == address(this)`. `owner()` exists because `ERC20V1.initialize` calls it.
 */
contract MockPlatformRegistry {
    /// @dev When true, `isPlatformContract` reverts — drives ERC20V1's fail-closed `catch`.
    bool public shouldRevert;

    mapping(address => bool) public platform;

    error RegistryUnavailable();

    function deployToken(address impl, bytes calldata initData) external returns (address token) {
        return address(new ERC1967Proxy(impl, initData));
    }

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    function setPlatform(address who, bool ok) external {
        platform[who] = ok;
    }

    function owner() external view returns (address) {
        return address(this);
    }

    function isPlatformContract(address, address who) external view returns (bool) {
        if (shouldRevert) revert RegistryUnavailable();
        return platform[who];
    }

    /// @dev Lets the test drive `ERC20V1.mint` (onlyLaunchpad == this contract).
    function mint(address token, address to, uint256 amount) external {
        IMintable(token).mint(to, amount);
    }
}

interface IMintable {
    function mint(address to, uint256 amount) external;
}
