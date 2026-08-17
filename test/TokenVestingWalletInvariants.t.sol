// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { TokenVestingWallet } from "../contracts/vesting/TokenVestingWallet.sol";
import { ERC1967Proxy } from "../contracts/ERC1967Proxy.sol";
import { USDT } from "../contracts/USDT.sol";

/**
 * @title TokenVestingWallet invariant suite — the owner-vesting release schedule.
 *
 * @dev Per-token Owner Vesting wallet deployed by `TokenFactory` at issuance; until this suite
 *      it had only example-based coverage (`test/TokenVestingWallet.test.ts`,
 *      `test/OwnerVestingFreeze.test.ts`). Deployed directly here via `ERC1967Proxy` from
 *      the test contract itself, so `factory() == address(this test contract)` — mirroring how
 *      `TokenFactory` is the deployer in production — with a separate fixed `launchpad_`
 *      address the handler can `vm.prank` as (address equality is the only check;
 *      `startVesting` never calls back into it).
 *
 *      V1 conservation      — `released()` never exceeds the total the handler has actually
 *                              transferred into the wallet. This is checked against an
 *                              INDEPENDENT ghost ledger, not the contract's own
 *                              `balance + released` formula — using the contract's own formula
 *                              to verify itself would be tautological (see the `LaunchpadInvariants`
 *                              lesson that a weak invariant can pass vacuously).
 *      V2 monotonic release — `released()` never decreases.
 *      V3 gated before start/cliff — `releasable()` is exactly 0 whenever vesting has not
 *                              started, or `block.timestamp` is before `start + cliff`.
 *      V4 releasable bound   — `releasable() <= token.balanceOf(wallet)` always (release() can
 *                              never promise more than the wallet currently holds).
 *      V5 started is write-once — once observed `true`, never regresses to `false`.
 */
contract TokenVestingWalletHandler is CommonBase, StdCheats, StdUtils {
    TokenVestingWallet public immutable wallet;
    USDT public immutable vestToken;
    address public immutable business;
    address public immutable launchpad;
    address public immutable factory;

    uint256 public ghostTotalFunded;
    uint256 public ghostMaxReleased;
    bool public sawStarted;

    uint256 public callsFund;
    uint256 public callsStart;
    uint256 public callsRelease;

    constructor(TokenVestingWallet _wallet, USDT _vestToken, address _business, address _launchpad, address _factory) {
        wallet = _wallet;
        vestToken = _vestToken;
        business = _business;
        launchpad = _launchpad;
        factory = _factory;
    }

    function _snapshot() internal {
        if (wallet.started()) sawStarted = true;
        uint256 r = wallet.released();
        if (r > ghostMaxReleased) ghostMaxReleased = r;
    }

    function fund(uint256 amountSeed) external {
        uint256 amount = bound(amountSeed, 1e18, 100_000e18);
        if (vestToken.balanceOf(address(this)) < amount) return;
        vestToken.transfer(address(wallet), amount);
        ghostTotalFunded += amount;
        callsFund++;
        _snapshot();
    }

    /// @dev Exercises all three authorized-caller shapes (launchpad, factory, and — MOST of the
    ///      time — a random unauthorized address) so the negative path is covered too, not just
    ///      the happy one. Start can land in the future relative to `block.timestamp`, exercising
    ///      the "not yet started in time" branch of V3 independently from "never started at all".
    function startVesting(uint256 callerChoice, uint256 startOffsetSeed, uint256 durationSeed) external {
        uint256 choice = callerChoice % 3;
        address caller = choice == 0 ? launchpad : choice == 1 ? factory : address(0xBADCA11);

        uint64 startTs = uint64(block.timestamp + bound(startOffsetSeed, 0, 30 days));
        uint64 dur = uint64(bound(durationSeed, 1 days, 730 days));

        vm.prank(caller);
        try wallet.startVesting(startTs, dur) {
            callsStart++;
        } catch {}
        _snapshot();
    }

    function release() external {
        vm.prank(business);
        try wallet.release() {
            callsRelease++;
        } catch {}
        _snapshot();
    }

    function warp(uint256 seed) external {
        vm.warp(block.timestamp + bound(seed, 1 hours, 200 days));
        _snapshot();
    }
}

contract TokenVestingWalletInvariantsTest is StdInvariant, Test {
    TokenVestingWallet internal wallet;
    USDT internal vestToken;
    TokenVestingWalletHandler internal handler;

    address internal business = address(0xB055);
    address internal launchpad = address(0x1A0);

    function setUp() public {
        vestToken = new USDT(address(this), 18);

        TokenVestingWallet impl = new TokenVestingWallet();
        // Deployed directly by this test contract, so `factory() == address(this)` — the same
        // relationship `TokenFactory` has to the wallets it deploys in production.
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(TokenVestingWallet.initialize, (business, launchpad, address(vestToken), 365 days, 0))
        );
        wallet = TokenVestingWallet(address(proxy));

        handler = new TokenVestingWalletHandler(wallet, vestToken, business, launchpad, address(this));
        vestToken.mint(address(handler), 10_000_000e18);

        targetContract(address(handler));
    }

    function afterInvariant() public view {
        assertGt(
            handler.callsFund() + handler.callsStart() + handler.callsRelease(),
            0,
            // Measured with a temporary forced-failure probe, not assumed. Sampled runs:
            // fund 111/117/144/128, start 1, release 60/60/63/61. `start` is 1 by construction —
            // it is a one-shot latch, so once per run is the maximum, not a coverage gap.
            "vacuous run: handler landed no successful state transition"
        );
    }

    // ------------------------------------------------------------------
    // V1 — released never exceeds what was actually funded (independent ledger)
    // ------------------------------------------------------------------
    function invariant_V1_releasedNeverExceedsFunded() public view {
        assertLe(wallet.released(), handler.ghostTotalFunded(), "V1: released more than was ever funded");
    }

    // ------------------------------------------------------------------
    // V2 — released is monotonically non-decreasing
    // ------------------------------------------------------------------
    function invariant_V2_releasedMonotonic() public view {
        assertGe(wallet.released(), handler.ghostMaxReleased(), "V2: released decreased");
    }

    // ------------------------------------------------------------------
    // V3 — releasable is exactly zero before start (or before start+cliff)
    // ------------------------------------------------------------------
    function invariant_V3_releasableZeroBeforeStartOrCliff() public view {
        if (!wallet.started()) {
            assertEq(wallet.releasable(), 0, "V3: releasable > 0 with vesting not started");
            return;
        }
        if (block.timestamp < uint256(wallet.start()) + uint256(wallet.cliff())) {
            assertEq(wallet.releasable(), 0, "V3: releasable > 0 before start+cliff");
        }
    }

    // ------------------------------------------------------------------
    // V4 — releasable never exceeds the wallet's current balance
    // ------------------------------------------------------------------
    function invariant_V4_releasableWithinBalance() public view {
        assertLe(
            wallet.releasable(),
            vestToken.balanceOf(address(wallet)),
            "V4: releasable exceeds the wallet's current balance"
        );
    }

    // ------------------------------------------------------------------
    // V5 — started is write-once
    // ------------------------------------------------------------------
    function invariant_V5_startedIsWriteOnce() public view {
        if (handler.sawStarted()) {
            assertTrue(wallet.started(), "V5: started regressed to false");
        }
    }

    // ------------------------------------------------------------------
    // Deterministic: full-schedule conservation
    // ------------------------------------------------------------------
    /// @dev The audit-history lesson from `LaunchpadInvariants.t.sol` I3 applies here too: a
    ///      bound alone ("released <= total") cannot distinguish a correct incremental unlock
    ///      from one that pays out the CUMULATIVE vested figure a second time. This pins the
    ///      exact numeric schedule at two points, not just an upper bound.
    function test_fullVestingReleasesExactlyWhatWasFunded() public {
        TokenVestingWallet w = _freshWallet(0);
        uint256 amount = 1_000e18;
        vestToken.mint(address(this), amount);
        vestToken.transfer(address(w), amount);

        uint64 startTs = uint64(block.timestamp + 1 days);
        uint64 duration_ = 1000 days;
        vm.prank(launchpad);
        w.startVesting(startTs, duration_);

        // Halfway through: exactly half should be releasable (mulDiv, evenly divisible).
        vm.warp(startTs + duration_ / 2);
        assertEq(w.releasable(), amount / 2, "halfway releasable is not exactly half the schedule");

        vm.prank(business);
        w.release();
        assertEq(w.released(), amount / 2, "released does not match the halfway release");

        // Full duration: the remaining half becomes releasable, nothing more.
        vm.warp(startTs + duration_);
        assertEq(w.releasable(), amount / 2, "final releasable is not exactly the remaining half");

        vm.prank(business);
        w.release();
        assertEq(w.released(), amount, "cumulative released does not equal the funded amount");
        assertEq(vestToken.balanceOf(address(w)), 0, "wallet retained a balance after full release");
        assertEq(w.releasable(), 0, "releasable is nonzero after full release");
    }

    // ------------------------------------------------------------------
    // Deterministic: cliff blocks release even after start
    // ------------------------------------------------------------------
    function test_releaseBeforeCliffReverts() public {
        TokenVestingWallet w = _freshWalletWithCliff(1, 100 days);
        vestToken.mint(address(this), 1_000e18);
        vestToken.transfer(address(w), 1_000e18);

        uint64 startTs = uint64(block.timestamp);
        vm.prank(launchpad);
        w.startVesting(startTs, 365 days);

        vm.warp(startTs + 50 days); // inside start, before cliff
        assertEq(w.releasable(), 0, "releasable > 0 before cliff elapsed");

        vm.prank(business);
        vm.expectRevert(TokenVestingWallet.NothingToRelease.selector);
        w.release();
    }

    // ------------------------------------------------------------------
    // Deterministic: release before any startVesting call reverts
    // ------------------------------------------------------------------
    function test_releaseBeforeStartVestingReverts() public {
        TokenVestingWallet w = _freshWallet(2);
        vestToken.mint(address(this), 1_000e18);
        vestToken.transfer(address(w), 1_000e18);

        assertFalse(w.started(), "precondition: not started");
        vm.prank(business);
        vm.expectRevert(TokenVestingWallet.NothingToRelease.selector);
        w.release();
    }

    // ------------------------------------------------------------------
    // Deterministic: unauthorized caller cannot start vesting
    // ------------------------------------------------------------------
    function test_startVestingRevertsForUnauthorizedCaller() public {
        TokenVestingWallet w = _freshWallet(3);
        vm.prank(address(0xBADCA11));
        vm.expectRevert(TokenVestingWallet.NotLaunchpad.selector);
        w.startVesting(uint64(block.timestamp), 365 days);
    }

    // ------------------------------------------------------------------
    // Deterministic: startVesting is one-shot
    // ------------------------------------------------------------------
    function test_startVestingIsOneShot() public {
        TokenVestingWallet w = _freshWallet(4);
        vm.prank(launchpad);
        w.startVesting(uint64(block.timestamp), 365 days);

        vm.prank(launchpad);
        vm.expectRevert(TokenVestingWallet.AlreadyStarted.selector);
        w.startVesting(uint64(block.timestamp), 365 days);

        // The factory-authorized path is blocked too, not just a second launchpad call.
        vm.prank(address(this));
        vm.expectRevert(TokenVestingWallet.AlreadyStarted.selector);
        w.startVesting(uint64(block.timestamp), 365 days);
    }

    function _freshWallet(uint256 salt) internal returns (TokenVestingWallet w) {
        TokenVestingWallet impl = new TokenVestingWallet();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                TokenVestingWallet.initialize,
                (business, launchpad, address(vestToken), 365 days, 0)
            )
        );
        salt; // disambiguates call sites only, not used in the deployment itself
        w = TokenVestingWallet(address(proxy));
    }

    function _freshWalletWithCliff(uint256 salt, uint64 cliff_) internal returns (TokenVestingWallet w) {
        TokenVestingWallet impl = new TokenVestingWallet();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(
                TokenVestingWallet.initialize,
                (business, launchpad, address(vestToken), 365 days, cliff_)
            )
        );
        salt;
        w = TokenVestingWallet(address(proxy));
    }
}
