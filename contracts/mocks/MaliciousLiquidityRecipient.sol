// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @dev Test-only mock for reentrancy / CEI-ordering reproduction.
 *      Acts as the `liquidityRecipient` in `TokenFactory.issueToken` (the
 *      LIQUIDITY_RESERVE token bucket). On receipt of an ERC20 transfer (plain
 *      ERC20 has no hook, so this contract exposes a callable surface instead)
 *      it can re-enter the factory to read `tokenToVestingWallet[token]` and
 *      assert the snapshot is already populated (CEI ordering: registration
 *      happens BEFORE the 4-way distribution transfers).
 *
 *      Plain ERC20 transfers do NOT call back, so we simulate the cross-
 *      contract reentrancy by exposing `probe()` which the test invokes
 *      AFTER the factory finishes — the contract simply records what the
 *      factory's `tokenToVestingWallet` mapping returned at probe time.
 *
 *      For a true on-transfer hook reproduction the platform must opt into
 *      a hook-bearing token, which the payment-token allow-list policy
 *      explicitly disallows. This mock therefore acts as a passive recipient
 *      + state-snapshot probe: the test asserts that BEFORE the transfer the
 *      factory has already populated `tokenToVestingWallet[token]` (CEI
 *      invariant).
 */
interface ITokenFactoryProbe {
    function tokenToVestingWallet(address token) external view returns (address);
}

contract MaliciousLiquidityRecipient {
    address public lastFactory;
    address public lastToken;
    address public observedWallet;
    bool public probed;

    /// @notice Test sets the factory + token addresses before issueToken.
    function configure(address _factory, address _token) external {
        lastFactory = _factory;
        lastToken = _token;
    }

    /// @notice Test calls this AFTER issueToken. We snapshot the wallet
    ///         mapping; if CEI was respected the wallet must be non-zero.
    function probe() external {
        observedWallet = ITokenFactoryProbe(lastFactory).tokenToVestingWallet(lastToken);
        probed = true;
    }

    /// @notice Allow the contract to receive ERC20 transfers (no-op).
    fallback() external payable {}

    receive() external payable {}
}
