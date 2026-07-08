// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

contract USDT is ERC20, Ownable2Step {
    uint8 private _decimals;

    constructor(
        address initialOwner,
        uint8 decimals_
    ) ERC20("USDT", "Tether USD") Ownable(initialOwner) {
        _decimals = decimals_;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * This is configurable during contract deployment.
     */
    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}