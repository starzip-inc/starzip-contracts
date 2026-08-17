// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockHostileStablecoin
 * @notice Test-only ERC20 that reproduces the ISSUER powers real fiat-backed stablecoins hold over
 *         their own token: a global pause, a per-address blacklist, and a transfer path that can be
 *         made to fail without reverting.
 * @dev WHY THIS EXISTS. `contracts/USDT.sol` is a 27-line OZ ERC20 with a mint
 *      function — it can never fail a transfer, so with it as the only escrow-asset mock the entire
 *      "the payment asset turned against us" branch of TradeSettlementV1 is untestable. Every
 *      exit in that contract (`withdrawToken`, `batchWithdraw`, `emergencyWithdrawFor`) ends in a
 *      `safeTransfer` of the quote asset, so all three fail TOGETHER the moment the issuer decides
 *      they should, and TradeSettlementV1 holds no lever that reopens them (the quote pointer is
 *      immutable). This mock is what makes that assertable instead of asserted.
 *
 *      MODELLING NOTES — each lever mirrors a power that is live on mainnet today:
 *        - `setPaused`   → Tether/Circle contract-wide pause. Reverts every transfer, including the
 *                          settlement's own outbound ones. No carve-outs.
 *        - `setBlacklisted` → USDC `blacklist(address)` / USDT `addBlackList(address)`. Applied to
 *                          the SETTLEMENT address it freezes every user at once; applied to ONE
 *                          user it freezes only that user's exit, which is the sanctions case.
 *        - `setSilentFailure` → the legacy "returns false instead of reverting" shape. Kept because
 *                          it is the only failure mode that could, under a naive `transfer()` call,
 *                          debit the ledger while moving nothing. TradeSettlementV1 uses SafeERC20,
 *                          so it must revert instead — this mock is how that is proven rather than
 *                          assumed.
 *
 *      Mint and every lever are intentionally PERMISSIONLESS (no Ownable): this is a fixture, and
 *      access control on it would only add setup noise to the tests that flip the levers.
 */
contract MockHostileStablecoin is ERC20 {
    /// @notice Global transfer freeze (issuer pause).
    bool public paused;

    /// @notice Per-address freeze. Blocks transfers where the address is EITHER side.
    mapping(address => bool) public blacklisted;

    /// @notice When true, `transfer`/`transferFrom` move nothing and return false (no revert).
    bool public silentFailure;

    uint8 private immutable _DECIMALS;

    error HostilePaused();
    error HostileBlacklisted(address account);

    event PausedSet(bool paused);
    event BlacklistSet(address indexed account, bool blacklisted);
    event SilentFailureSet(bool silentFailure);

    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_) {
        _DECIMALS = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _DECIMALS;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function setPaused(bool _paused) external {
        paused = _paused;
        emit PausedSet(_paused);
    }

    function setBlacklisted(address account, bool _blacklisted) external {
        blacklisted[account] = _blacklisted;
        emit BlacklistSet(account, _blacklisted);
    }

    function setSilentFailure(bool _silentFailure) external {
        silentFailure = _silentFailure;
        emit SilentFailureSet(_silentFailure);
    }

    /// @dev Returns false WITHOUT moving funds when `silentFailure` is set; otherwise normal.
    function transfer(address to, uint256 value) public override returns (bool) {
        if (silentFailure) return false;
        return super.transfer(to, value);
    }

    /// @dev Same silent-failure shape as `transfer`, and it also skips the allowance spend.
    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        if (silentFailure) return false;
        return super.transferFrom(from, to, value);
    }

    /**
     * @dev Mint/burn (`from`/`to` == 0) deliberately bypass the gates so a test can fund an account
     *      while the token is already hostile. Only real transfers are gated.
     */
    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0)) {
            if (paused) revert HostilePaused();
            if (blacklisted[from]) revert HostileBlacklisted(from);
            if (blacklisted[to]) revert HostileBlacklisted(to);
        }
        super._update(from, to, value);
    }
}
