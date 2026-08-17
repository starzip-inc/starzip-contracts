// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title MockNoDecimalsToken
 * @notice A minimal ERC20-shaped token that deliberately does NOT implement `decimals()`.
 * @dev Used by the TradeSettlement multi-quote tests to prove that listing a quote asset is
 *      fail-closed: `setQuoteAsset` must revert QuoteDecimalsUnavailable rather than silently
 *      assuming 18 decimals. It has no fallback function, so the `decimals()` staticcall reverts.
 */
contract MockNoDecimalsToken is IERC20 {
    string public name = "NoDecimals";
    string public symbol = "NODEC";

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
