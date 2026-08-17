// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";

/**
 * @title MockFeeOnTransferToken
 * @notice Test-only ERC20 that burns a fixed basis-point fee on every transfer, so the recipient
 *         receives strictly less than the requested amount.
 * @dev Exists to exercise the case where a settlement credits the REQUESTED amount instead of the
 *      measured balance delta over-reports its liabilities on the very first deposit of a token
 *      like this, which breaks the solvency invariant and permanently bricks recoverStuckTokens.
 *
 *      It also implements EIP-2612 so `depositWithPermit` can be tested on the ONE token
 *      shape where the two features interact — a permit authorizes `_amount`, but the measured
 *      delta credits less than that. Without a permit-capable fee-on-transfer token there is no
 *      way to show the permit path did not quietly regress to crediting the requested amount.
 */
contract MockFeeOnTransferToken is ERC20, ERC20Permit {
    uint256 public constant BASIS_POINTS = 10000;

    /// @notice Fee in basis points burned on each transfer (e.g. 100 = 1%).
    uint256 public immutable feeBps;

    constructor(string memory name_, string memory symbol_, uint256 _feeBps) ERC20(name_, symbol_) ERC20Permit(name_) {
        // BASIS_POINTS itself is allowed: a token that consumes the entire transfer is the
        // degenerate case a measured-delta credit must still handle (credit 0 -> reject).
        require(_feeBps <= BASIS_POINTS, "fee too high");
        feeBps = _feeBps;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /**
     * @notice Burn `amount` from `from` with no allowance check.
     * @dev Simulates a token that removes value from a holder out-of-band (negative rebase, issuer
     *      seizure, blacklist burn). Used to drive the settlement's tracked liability ABOVE its real
     *      balance, which is the state where an unguarded `balanceOf - totalTracked` panics 0x11.
     */
    function burnFrom(address from, uint256 amount) external {
        _burn(from, amount);
    }

    /// @dev Mint/burn (from == 0 || to == 0) pass through untaxed; only real transfers are taxed.
    function _update(address from, address to, uint256 value) internal override {
        if (from == address(0) || to == address(0) || feeBps == 0) {
            super._update(from, to, value);
            return;
        }
        uint256 fee = (value * feeBps) / BASIS_POINTS;
        super._update(from, to, value - fee);
        super._update(from, address(0), fee); // burn the fee
    }
}
