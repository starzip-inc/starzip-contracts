// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @dev Test-only malicious ERC20 implementation used by the beacon-timelock regression
 *      test. Installed behind a `BeaconProxy` it reports an arbitrarily inflated `balanceOf`,
 *      which is precisely what defeats `TradeSettlementV1.recoverStuckTokens`' excess-only
 *      guard (`balanceOf(address(this)) - totalTracked[token]`): the forged balance invents
 *      "recoverable excess" out of nothing over funds users actually deposited.
 *
 *      It exists so the regression test proves a REAL attack is blocked, not a symbolic one:
 *      with the 48h timelock on `UpgradeableBeacon`, installing this in a single transaction
 *      is impossible, and the staged swap is observable and cancellable for 48h first.
 */
contract MaliciousTokenImpl {
    uint256 public constant FORGED_BALANCE = type(uint128).max;

    function balanceOf(address) external pure returns (uint256) {
        return FORGED_BALANCE;
    }
}
