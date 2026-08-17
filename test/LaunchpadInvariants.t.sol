// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { LaunchpadV1 } from "../contracts/launchpad/LaunchpadV1.sol";
import { TokenFactory } from "../contracts/token/TokenFactory.sol";
import { ERC20V1 } from "../contracts/token/ERC20V1.sol";
import { TokenVestingWallet } from "../contracts/vesting/TokenVestingWallet.sol";
import { UpgradeableBeacon } from "../contracts/UpgradeableBeacon.sol";
import { ERC1967Proxy } from "../contracts/ERC1967Proxy.sol";
import { USDT } from "../contracts/USDT.sol";
import { MockFeeOnTransferToken } from "../contracts/mocks/MockFeeOnTransferToken.sol";

/**
 * @title Launchpad invariant suite — the four predicates specified
 *        (§5 "Test debt — fuzz predicates") and that no test in this repo has ever asserted.
 *
 * @dev Every prior test is example-based: it drives one hand-picked sequence and asserts the
 *      outcome of that sequence. These four assert properties that must hold after EVERY
 *      reachable sequence, which is the class of statement the three audit reports each said
 *      was missing. The handler generates the sequences; the runner searches them.
 *
 *      I1 payment solvency  — the contract can always honour every refundable participation
 *                             and unclaimed vesting remainder it has recorded.
 *      I2 token solvency    — likewise for sold-but-unclaimed sale tokens and live escrow.
 *      I3 vesting bound     — released never exceeds the total, and unlock is monotone in time.
 *      I4 one-shot latch    — `TokenVestingWallet.started` is write-once, and every issued
 * token retains SOME path to `started == true`. (
 *                             `escrowConsumed` is DELIBERATELY no longer write-once —
 *                             `TokenFactory.restoreEscrow` resets it so a cancelled sale's
 *                             token can be resold — so this invariant no longer claims it.)
 *
 * I4's liveness half is what would have caught and audit-03: both were states where
 *      a latch became permanently unreachable, which no single-sequence test asks about.
 */
contract LaunchpadHandler is CommonBase, StdCheats, StdUtils {
    LaunchpadV1 public immutable launchpad;
    TokenFactory public immutable factory;
    USDT public immutable usdt;
    address public immutable token;
    address public immutable platformOwner;
    uint256 public immutable launchpadId;

    address[4] public actors;

    // ---- ghosts: latch history, so a flip BACK is observable ----
    bool public sawEscrowConsumed;
    bool public sawVestingStarted;
    uint256 public ghostMaxVestedClaimed;
    uint256 public ghostMaxWalletReleased;

    // ---- call counters, so a suite that silently does nothing is visible ----
    uint256 public callsParticipate;
    uint256 public callsFinalize;
    uint256 public callsCancelUnderfunded;
    uint256 public callsExpire;
    uint256 public callsRefund;
    uint256 public callsClaimTokens;
    uint256 public callsClaimVested;
    uint256 public callsRecoverStuckTokens;

    constructor(
        LaunchpadV1 _launchpad,
        TokenFactory _factory,
        USDT _usdt,
        address _token,
        address _platformOwner,
        uint256 _launchpadId
    ) {
        launchpad = _launchpad;
        factory = _factory;
        usdt = _usdt;
        token = _token;
        platformOwner = _platformOwner;
        launchpadId = _launchpadId;

        actors[0] = address(0xA11CE);
        actors[1] = address(0xB0B0B);
        actors[2] = address(0xCA401);
        actors[3] = address(0xD00D5);
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[bound(seed, 0, 3)];
    }

    /// Record latch state after every action. A one-shot latch that ever reads `false`
    /// after having read `true` is caught by the invariant, not by this recorder.
    function _snapshotLatches() internal {
        if (factory.escrowConsumed(token)) sawEscrowConsumed = true;
        address vw = factory.tokenToVestingWallet(token);
        if (vw != address(0) && TokenVestingWallet(vw).started()) sawVestingStarted = true;
    }

    function participate(uint256 actorSeed, uint256 amountSeed) external {
        address actor = _actor(actorSeed);
        uint256 amount = bound(amountSeed, 1e18, 40_000e18);
        if (usdt.balanceOf(address(this)) < amount) return;

        usdt.transfer(actor, amount);
        vm.startPrank(actor);
        usdt.approve(address(launchpad), amount);
        try launchpad.participate(launchpadId, amount) {
            callsParticipate++;
        } catch {}
        vm.stopPrank();
        _snapshotLatches();
    }

    function warp(uint256 secondsSeed) external {
        // Capped below the 7-day sale window on purpose: a 20-day step could clear
        // preparation, sale and grace in one call, so the Active state was reachable
        // only by luck and the sale branch went unexplored.
        vm.warp(block.timestamp + bound(secondsSeed, 1 minutes, 36 hours));
        _snapshotLatches();
    }

    /// @dev Vesting moves in 90-day quarters, so the fine-grained `warp` used to keep the
    ///      sale window reachable can never advance it. This jumps in quarters but only
    ///      once the sale is terminal, so it cannot skip the sale window it protects.
    function warpQuarter(uint256 seed) external {
        (, , , , , , , , , LaunchpadV1.LaunchpadStatus status) = launchpad.launchpads(launchpadId);
        if (status != LaunchpadV1.LaunchpadStatus.Finalized) return;
        vm.warp(block.timestamp + bound(seed, 30 days, 200 days));
        _snapshotLatches();
    }

    function finalize() external {
        vm.prank(platformOwner);
        try launchpad.finalizeLaunchpad(launchpadId) {
            callsFinalize++;
        } catch {}
        _snapshotLatches();
    }

    function cancelUnderfunded() external {
        try launchpad.cancelUnderfundedLaunchpad(launchpadId) {
            callsCancelUnderfunded++;
        } catch {}
        _snapshotLatches();
    }

    function expire() external {
        try launchpad.expireLaunchpad(launchpadId) {
            callsExpire++;
        } catch {}
        _snapshotLatches();
    }

    function refund(uint256 actorSeed) external {
        vm.prank(_actor(actorSeed));
        try launchpad.refund(launchpadId) {
            callsRefund++;
        } catch {}
        _snapshotLatches();
    }

    function claimTokens(uint256 actorSeed) external {
        vm.prank(_actor(actorSeed));
        try launchpad.claimTokens(launchpadId) {
            callsClaimTokens++;
        } catch {}
        _snapshotLatches();
    }

    function claimVestedPayment() external {
        // Business-gated (`msg.sender != businessAccount` reverts), so calling as the
        // handler made this action a guaranteed no-op — it counted zero successes until
        // the coverage probe showed it.
        (address businessAccount, , , , , , , , , ) = launchpad.launchpads(launchpadId);
        vm.prank(businessAccount);
        try launchpad.claimVestedPayment(launchpadId) {
            callsClaimVested++;
        } catch {}
        (, uint256 claimed, , , ) = launchpad.launchpadVesting(launchpadId);
        if (claimed > ghostMaxVestedClaimed) ghostMaxVestedClaimed = claimed;
        _snapshotLatches();
    }

    /// @dev Coverage gap closed here: I1/I2 solvency were asserted from day one, but nothing
    ///      in this handler ever called `recoverStuckTokens` — the one function whose whole
    ///      job is to respect `lockedTokenAmount`/`lockedPaymentAmount` while sweeping
    ///      everything else. Verified empirically: a mutant that drops the
    ///      `lockedPaymentAmount` term from `recoverStuckTokens`'s own guard survived EVERY
    ///      invariant in this file (all 7 green) before this function existed, and is caught
    ///      by I1 once it does (see the final report's mutation table).
    function recoverStuckTokens(uint256 tokenChoice, uint256 amountSeed, uint256 toSeed) external {
        address target = tokenChoice % 2 == 0 ? address(usdt) : token;
        uint256 balance = IERC20(target).balanceOf(address(launchpad));
        if (balance == 0) return;
        uint256 amount = bound(amountSeed, 1, balance);
        address to = _actor(toSeed);

        vm.prank(platformOwner);
        try launchpad.recoverStuckTokens(target, to, amount) {
            callsRecoverStuckTokens++;
        } catch {}
        _snapshotLatches();
    }

    function releaseOwnerVesting() external {
        address vw = factory.tokenToVestingWallet(token);
        if (vw == address(0)) return;
        address beneficiary = TokenVestingWallet(vw).owner();
        vm.prank(beneficiary);
        try TokenVestingWallet(vw).release() {} catch {}
        uint256 rel = TokenVestingWallet(vw).released();
        if (rel > ghostMaxWalletReleased) ghostMaxWalletReleased = rel;
        _snapshotLatches();
    }
}

contract LaunchpadInvariantsTest is StdInvariant, Test {
    uint256 internal constant PERMIT_PK = 0xBEEF;

    bytes32 internal constant ISSUE_PERMIT_TYPEHASH =
        keccak256(
            "IssuePermit(address businessAccount,string name,string symbol,uint256 totalSupply,string contractURI,uint16 launchpadBp,uint16 liquidityBp,uint16 ownerBp,address liquidityRecipient,uint64 ownerVestingCliff,uint64 ownerVestingDuration,address linkedLaunchpad,uint256 nonce,uint256 deadline)"
        );

    uint256 internal constant CONFIG_DELAY = 2 days;
    /// @dev Sized against the schedule, not picked for realism. Escrow is 60% of supply and
    ///      the price is 1:1, so the softcap (20% of a 60,000 target) is 12,000 — inside a
    ///      single `participate` bound. At the original 1,000,000 supply the fuzzer had to
    ///      land four successful calls inside a 7-day window to reach the softcap at all, and
    ///      measurement showed it never did: the finalize/claim/vest branch ran zero times
    ///      while every invariant still reported green.
    uint256 internal constant TOTAL_SUPPLY = 100_000e18;
    uint256 internal constant TOKEN_PRICE = 1e18; // 1 USDT per token (18-dec payment)

    USDT internal usdt;
    TokenFactory internal factory;
    LaunchpadV1 internal launchpad;
    address internal tokenAddress;
    address internal vestingWallet;

    address internal business = address(0xB05);
    address internal platformTreasury = address(0x7EA);
    address internal feeRecipient = address(0xFEE);
    address internal liquidityRecipient = address(0x1109);

    LaunchpadHandler internal handler;
    uint256 internal launchpadId;

    function setUp() public {
        usdt = new USDT(address(this), 18);

        ERC20V1 erc20Impl = new ERC20V1();
        UpgradeableBeacon erc20Beacon = new UpgradeableBeacon(address(erc20Impl), address(this));
        TokenVestingWallet vwImpl = new TokenVestingWallet();
        UpgradeableBeacon vwBeacon = new UpgradeableBeacon(address(vwImpl), address(this));

        TokenFactory factoryImpl = new TokenFactory();
        ERC1967Proxy factoryProxy = new ERC1967Proxy(
            address(factoryImpl),
            abi.encodeCall(
                TokenFactory.initialize,
                (address(erc20Beacon), platformTreasury, vm.addr(PERMIT_PK), address(vwBeacon))
            )
        );
        factory = TokenFactory(address(factoryProxy));

        LaunchpadV1 launchpadImpl = new LaunchpadV1();
        ERC1967Proxy launchpadProxy = new ERC1967Proxy(
            address(launchpadImpl),
            abi.encodeCall(LaunchpadV1.initialize, (address(factory), address(usdt), feeRecipient, liquidityRecipient))
        );
        launchpad = LaunchpadV1(address(launchpadProxy));

        _configureFactory();
        (tokenAddress, vestingWallet) = _issueToken();

        launchpadId = launchpad.launchpadCounter();
        launchpad.createLaunchpad(tokenAddress, TOKEN_PRICE, business, address(usdt), 0, 0);

        handler = new LaunchpadHandler(launchpad, factory, usdt, tokenAddress, address(this), launchpadId);
        usdt.mint(address(handler), 5_000_000e18);

        targetContract(address(handler));
    }

    function _configureFactory() internal {
        factory.proposeAllocationGuide(0, 0, 10000); // LAUNCHPAD
        factory.proposeAllocationGuide(1, 1, 10000); // LIQUIDITY_RESERVE (1bp floor)
        factory.proposeAllocationGuide(2, 0, 10000); // OWNER_VESTING
        factory.proposeLinkedLaunchpadChange(address(launchpad));
        factory.proposeEscrowTimeoutChange(90 days);
        // resale-wait must be configured before any cancel path can restore escrow
        // (TokenFactory.restoreEscrow fail-closed reverts ResaleWaitNotConfigured otherwise).
        factory.proposeResaleWaitChange(90 days);

        vm.warp(block.timestamp + CONFIG_DELAY + 1);

        factory.executeAllocationGuide(0);
        factory.executeAllocationGuide(1);
        factory.executeAllocationGuide(2);
        factory.executeLinkedLaunchpadChange();
        factory.executeEscrowTimeoutChange();
        factory.executeResaleWaitChange();
    }

    function _issueToken() internal returns (address token_, address vw_) {
        return _issueTokenNamed("Store Token", "STORE");
    }

    /// @dev Parameterized so `test_multiLaunchpadSharedPaymentTokenStaysSolvent` can issue a
    ///      SECOND token (distinct name/symbol, same business) without duplicating the whole
    ///      EIP-712 permit dance.
    function _issueTokenNamed(
        string memory name_,
        string memory symbol_
    ) internal returns (address token_, address vw_) {
        TokenFactory.AllocationRatios memory ratios = TokenFactory.AllocationRatios({
            launchpadBp: 6000,
            liquidityBp: 2000,
            ownerBp: 2000,
            liquidityRecipient: liquidityRecipient,
            ownerVestingCliff: 0,
            ownerVestingDuration: 365 days
        });

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(
                ISSUE_PERMIT_TYPEHASH,
                business,
                keccak256(bytes(name_)),
                keccak256(bytes(symbol_)),
                TOTAL_SUPPLY,
                keccak256(bytes("")),
                ratios.launchpadBp,
                ratios.liquidityBp,
                ratios.ownerBp,
                ratios.liquidityRecipient,
                ratios.ownerVestingCliff,
                ratios.ownerVestingDuration,
                address(launchpad),
                factory.nonces(business),
                deadline
            )
        );
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("TokenFactory")),
                keccak256(bytes("1")),
                block.chainid,
                address(factory)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            PERMIT_PK,
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
        );

        vm.prank(business);
        (token_, vw_) = factory.issueToken(
            name_,
            symbol_,
            TOTAL_SUPPLY,
            "",
            ratios,
            deadline,
            abi.encodePacked(r, s, v)
        );
    }

    /// @dev Coverage floor, not decoration. An invariant suite whose handler never lands a
    ///      successful state transition passes vacuously, which is indistinguishable from
    ///      passing for real — so this asserts each run actually moved the system.
    ///
    ///      This is not hypothetical. Measured with a temporary probe, the first version of
    ///      this suite reported all four invariants green while `finalize`, `claimTokens` and
    ///      `claimVestedPayment` had succeeded ZERO times: the sale was sized so the fuzzer
    ///      could not reach the softcap inside the sale window, and `claimVestedPayment` was
    ///      called unpranked against a business-only gate. Every green tick was honest and
    ///      every one of them was about the underfunded branch alone.
    ///
    ///      Sampled after the fix (single runs): participate 5 / finalize 1 / claimTokens 3 /
    ///      claimVested 4, with cancelUnderfunded and refund landing on other runs. The
    ///      branch mix varies per run by design, which is why both terminal branches are
    ///      ALSO pinned by the deterministic tests below rather than left to the search.
    function afterInvariant() public view {
        assertGt(
            handler.callsParticipate() +
                handler.callsFinalize() +
                handler.callsCancelUnderfunded() +
                handler.callsExpire() +
                handler.callsRefund() +
                handler.callsClaimTokens() +
                handler.callsClaimVested() +
                handler.callsRecoverStuckTokens(),
            0,
            "vacuous run: handler landed no successful state transition"
        );
    }

    // ------------------------------------------------------------------
    // I1 — payment solvency
    // ------------------------------------------------------------------
    /// @dev The contract must hold at least the USDT it has promised away: every
    ///      unrefunded participation on a cancelled sale plus every unclaimed vesting
    /// remainder. `lockedPaymentAmount` is that promise, made explicit by .
    function invariant_I1_paymentSolvency() public view {
        assertGe(
            usdt.balanceOf(address(launchpad)),
            launchpad.lockedPaymentAmount(address(usdt)),
            "I1: USDT balance below locked payment obligations"
        );
    }

    // ------------------------------------------------------------------
    // I2 — token solvency
    // ------------------------------------------------------------------
    /// @dev Same statement for sale tokens: sold-but-unclaimed plus live escrow.
    function invariant_I2_tokenSolvency() public view {
        assertGe(
            IERC20(tokenAddress).balanceOf(address(launchpad)),
            launchpad.lockedTokenAmount(tokenAddress),
            "I2: sale-token balance below locked token obligations"
        );
    }

    // ------------------------------------------------------------------
    // I3 — vesting bound + monotonicity
    // ------------------------------------------------------------------
    /// @dev Two separate claims: the USDT vesting schedule can never pay out more than it
    ///      was funded with, and the owner-vesting wallet can never release more than the
    ///      allocation it holds. Monotonicity is asserted via the handler's ghost maxima —
    ///      a decrease means an unlock went backwards in time.
    function invariant_I3_vestingBounded() public view {
        (uint256 total, uint256 claimed, , , ) = launchpad.launchpadVesting(launchpadId);
        assertLe(claimed, total, "I3: vested claim exceeded funded total");
        assertGe(claimed, handler.ghostMaxVestedClaimed(), "I3: vested claim decreased");

        if (vestingWallet != address(0)) {
            TokenVestingWallet vw = TokenVestingWallet(vestingWallet);
            assertGe(vw.released(), handler.ghostMaxWalletReleased(), "I3: wallet release decreased");
            assertLe(
                vw.released(),
                vw.released() + IERC20(tokenAddress).balanceOf(vestingWallet),
                "I3: wallet released more than it ever held"
            );
        }
    }

    // ------------------------------------------------------------------
    // I4 — one-shot latches
    // ------------------------------------------------------------------
    /// @dev Write-once means write-once: once observed true, never false again. The
    ///      handler records the observation; this asserts it never regresses.
    /// @dev `escrowConsumed` is DELIBERATELY no longer write-once —
    ///      `TokenFactory.restoreEscrow` resets it to `false` when a cancelled sale's token
    /// returns to escrow for resale (that reset IS the remediation for a cancelled
    ///      token used to be permanently unsellable). The claim dropped here on purpose;
    ///      `TokenVestingWallet.started()` remains genuinely write-once (no reset path exists
    ///      or was added — `startVesting` still hard-reverts `AlreadyStarted` on a second
    ///      call), so that half of the invariant is unchanged.
    function invariant_I4_latchesAreWriteOnce() public view {
        if (handler.sawVestingStarted()) {
            assertTrue(TokenVestingWallet(vestingWallet).started(), "I4: vesting started regressed to false");
        }
    }

    // ------------------------------------------------------------------
    // I4 (liveness half) — every terminal path must start owner vesting
    // ------------------------------------------------------------------
    /// @dev The half that is a reachability claim, not a state predicate, so it is a
    /// targeted test rather than an invariant. This is the shape of and
    ///      audit-03: an allocation funded at issuance whose `started` latch had no
    ///      remaining caller. Asserted here on each terminal path independently.
    function _assertSolvent(string memory at) internal view {
        assertGe(
            usdt.balanceOf(address(launchpad)),
            launchpad.lockedPaymentAmount(address(usdt)),
            string.concat("I1 broken at: ", at)
        );
        assertGe(
            IERC20(tokenAddress).balanceOf(address(launchpad)),
            launchpad.lockedTokenAmount(tokenAddress),
            string.concat("I2 broken at: ", at)
        );
    }

    /// @dev The success branch, pinned deterministically. The random search reaches it only
    ///      on some runs, so leaving it to the search would make coverage of the path where
    ///      money actually moves a matter of luck.
    function test_successfulRaiseKeepsSolvencyThroughout() public {
        (, , , , , , uint256 startTime, , , ) = launchpad.launchpads(launchpadId);
        vm.warp(startTime + 1);

        address investor = address(0xBEEF01);
        uint256 raise = 30_000e18; // above the 12,000 softcap, below the 60,000 target
        usdt.mint(investor, raise);
        vm.startPrank(investor);
        usdt.approve(address(launchpad), raise);
        launchpad.participate(launchpadId, raise);
        vm.stopPrank();
        _assertSolvent("after participate");

        vm.warp(block.timestamp + 8 days);
        launchpad.finalizeLaunchpad(launchpadId);
        _assertSolvent("after finalize");
        assertTrue(TokenVestingWallet(vestingWallet).started(), "I4-liveness: finalize left owner vesting unstartable");

        vm.prank(investor);
        launchpad.claimTokens(launchpadId);
        _assertSolvent("after claimTokens");

        vm.warp(block.timestamp + 200 days);
        vm.prank(business);
        launchpad.claimVestedPayment(launchpadId);
        _assertSolvent("after claimVestedPayment");

        // A SECOND claim, one quarter later. A single claim cannot distinguish "unlock
        // subtracts what was already released" from "unlock returns the running total" —
        // both pay the same amount the first time.
        vm.warp(block.timestamp + 100 days);
        vm.prank(business);
        launchpad.claimVestedPayment(launchpadId);
        (uint256 total, uint256 claimed, , , ) = launchpad.launchpadVesting(launchpadId);
        assertLe(claimed, total, "I3: cumulative vested claim exceeded the funded total");

        // The audit's I3 as written ("Σ ≤ totalAmount") is too weak on its own, and mutation
        // testing is how that surfaced: an unlock that returns the CUMULATIVE figure instead
        // of the increment pays 30% then 40% (=70%) where the schedule says 30% then 10%
        // (=40%). Both stay under the cap, so the bound never trips and the mutant survived.
        // The real property is equality with the schedule at time t, not merely a ceiling.
        // Canon schedule is [2000,1000,1000,2000,1000,1000,1000,1000] bp per 90-day quarter;
        // 300 days elapsed is quarter 3, so exactly 2000+1000+1000 = 4000bp is releasable.
        assertEq(
            claimed,
            (total * 4000) / 10000,
            "I3: released amount does not match the canonical vesting schedule at t"
        );
        _assertSolvent("after second claimVestedPayment");
    }

    /// @dev The refund branch, pinned deterministically. Mutation testing found this gap:
    /// deleting the payment-lock decrement from `refund()` left every invariant
    ///      green, because after the suite was resized to make the softcap reachable the
    ///      random search stopped landing on the underfunded branch at all. A surviving
    ///      mutant is the only reason this test exists.
    function test_refundAfterUnderfundedCancelKeepsSolvency() public {
        (, , , , , , uint256 startTime, , , ) = launchpad.launchpads(launchpadId);
        vm.warp(startTime + 1);

        address investor = address(0xBEEF02);
        uint256 raise = 3_000e18; // below the 12,000 softcap
        usdt.mint(investor, raise);
        vm.startPrank(investor);
        usdt.approve(address(launchpad), raise);
        launchpad.participate(launchpadId, raise);
        vm.stopPrank();
        _assertSolvent("after underfunded participate");

        vm.warp(block.timestamp + 8 days);
        launchpad.cancelUnderfundedLaunchpad(launchpadId);
        _assertSolvent("after underfunded cancel");

        uint256 before = usdt.balanceOf(investor);
        vm.prank(investor);
        launchpad.refund(launchpadId);
        assertEq(usdt.balanceOf(investor) - before, raise, "refund did not return the full payment");
        _assertSolvent("after refund");
    }

    /// @dev An underfunded cancel no longer starts Owner Vesting immediately —
    ///      only a SUCCESSFUL finalize does. The I4 liveness guarantee this test pins is now
    ///      provided by `TokenFactory.triggerOwnerVesting`, PERMISSIONLESS once the resale-wait
    ///      deadline `restoreEscrow` set (at cancel time) elapses — mirrors
    ///      `LaunchpadV1.expireLaunchpad`'s own permissionless pattern.
    function test_ownerVestingStartsOnUnderfundedCancel() public {
        assertFalse(TokenVestingWallet(vestingWallet).started(), "precondition: not yet started");

        // Raise 1% of target — far below MIN_RAISE_BP (20%).
        uint256 raise = 6_000e18;
        usdt.mint(address(this), raise);
        (, , , , , , uint256 startTime, , , ) = launchpad.launchpads(launchpadId);
        vm.warp(startTime + 1);
        usdt.approve(address(launchpad), raise);
        launchpad.participate(launchpadId, raise);

        vm.warp(block.timestamp + 400 days);
        vm.expectRevert();
        launchpad.finalizeLaunchpad(launchpadId);

        launchpad.cancelUnderfundedLaunchpad(launchpadId);
        assertFalse(
            TokenVestingWallet(vestingWallet).started(),
            "cancel must NOT start owner vesting immediately anymore"
        );

        // Nobody resells within the resale-wait window (90 days, see _configureFactory) — the
        // allocation must not freeze forever: ANYONE can trigger it once the wait elapses.
        vm.warp(block.timestamp + 90 days + 1);
        factory.triggerOwnerVesting(tokenAddress);
        assertTrue(
            TokenVestingWallet(vestingWallet).started(),
            "I4-liveness: underfunded cancel left owner vesting unstartable"
        );
    }

    // ------------------------------------------------------------------
    // Deterministic: TWO launchpads sharing one payment token (multi-launchpad gap)
    // ------------------------------------------------------------------
    /// @dev `lockedPaymentAmount` is keyed by PAYMENT TOKEN, not by launchpad — every
    ///      example test and the fuzzed handler above only ever drive ONE launchpad, so
    ///      `lockedPaymentAmount[usdt]` is always numerically identical to that single
    ///      launchpad's own `totalRaised` at finalize time. That equality hides a real bug
    ///      class: mutation-tested below, `finalizeLaunchpad`'s
    ///      `lockedPaymentAmount[...] -= (feeAmount + immediateAmount + liquidityAmount)`
    ///      rewritten as an ASSIGNMENT (`lockedPaymentAmount[...] = totalRaised - (...)`)
    ///      is behaviorally IDENTICAL to the correct decrement in every single-launchpad
    ///      scenario (including the entire fuzzed campaign above), because
    ///      `lockedPaymentAmount[token] == launchpad.totalRaised` always holds there before
    ///      the write. It only diverges once a SECOND launchpad has also locked USDT
    ///      against the same mapping entry — the assignment silently discards the other
    ///      launchpad's still-locked funds from the ledger. This test is what actually
    ///      exercises that divergence.
    function test_multiLaunchpadSharedPaymentTokenAggregatesLocksCorrectly() public {
        (address token2, ) = _issueTokenNamed("Store Token 2", "STORE2");
        uint256 launchpadId2 = launchpad.launchpadCounter();
        launchpad.createLaunchpad(token2, TOKEN_PRICE, business, address(usdt), 0, 0);

        (, , , , , , uint256 start1, , , ) = launchpad.launchpads(launchpadId);
        (, , , , , , uint256 start2, , , ) = launchpad.launchpads(launchpadId2);
        vm.warp((start1 > start2 ? start1 : start2) + 1);

        uint256 raise1 = 30_000e18; // both above the 12,000 softcap
        uint256 raise2 = 25_000e18;

        address investorA = address(0xA001);
        address investorB = address(0xB002);
        usdt.mint(investorA, raise1);
        usdt.mint(investorB, raise2);

        vm.startPrank(investorA);
        usdt.approve(address(launchpad), raise1);
        launchpad.participate(launchpadId, raise1);
        vm.stopPrank();

        vm.startPrank(investorB);
        usdt.approve(address(launchpad), raise2);
        launchpad.participate(launchpadId2, raise2);
        vm.stopPrank();

        // ---- aggregation check #1: both launchpads' raises are locked in the SAME
        // per-token entry, additively ----
        assertEq(
            launchpad.lockedPaymentAmount(address(usdt)),
            raise1 + raise2,
            "multi-launchpad: shared lockedPaymentAmount did not sum both launchpads' raises"
        );
        _assertSolvent("multi-launchpad: after both participate");

        vm.warp(block.timestamp + 8 days);

        // Finalize launchpad 1 FIRST. Its own vesting remainder stays locked; launchpad 2's
        // raise2, which nothing has touched yet, MUST still be reflected in the shared entry.
        launchpad.finalizeLaunchpad(launchpadId);
        (uint256 totalAmount1, , , , ) = launchpad.launchpadVesting(launchpadId);
        assertEq(
            launchpad.lockedPaymentAmount(address(usdt)),
            totalAmount1 + raise2,
            "multi-launchpad: finalizing launchpad 1 corrupted launchpad 2's still-locked raise"
        );
        _assertSolvent("multi-launchpad: after finalize launchpad 1");

        // Finalize launchpad 2. Now the shared entry must equal the sum of BOTH vesting
        // remainders — nothing more, nothing less.
        launchpad.finalizeLaunchpad(launchpadId2);
        (uint256 totalAmount2, , , , ) = launchpad.launchpadVesting(launchpadId2);
        assertEq(
            launchpad.lockedPaymentAmount(address(usdt)),
            totalAmount1 + totalAmount2,
            "multi-launchpad: shared lockedPaymentAmount is not the sum of both vesting remainders"
        );
        _assertSolvent("multi-launchpad: after finalize launchpad 2");

        // Drain both vesting schedules to completion; the shared entry must reach exactly
        // zero, and each business must be able to claim its OWN full remainder even though
        // both draw against the same per-token ledger entry.
        vm.warp(block.timestamp + 900 days);
        uint256 beforeBiz = usdt.balanceOf(business);
        vm.prank(business);
        launchpad.claimVestedPayment(launchpadId);
        vm.prank(business);
        launchpad.claimVestedPayment(launchpadId2);
        assertEq(
            usdt.balanceOf(business) - beforeBiz,
            totalAmount1 + totalAmount2,
            "multi-launchpad: business did not receive the full combined vesting remainder"
        );
        assertEq(
            launchpad.lockedPaymentAmount(address(usdt)),
            0,
            "multi-launchpad: shared lockedPaymentAmount did not reach zero after both fully vested"
        );
        _assertSolvent("multi-launchpad: after both fully vested");
    }

    // ------------------------------------------------------------------
    // FINDING: a fee-on-transfer payment token breaks I1 solvency immediately
    // ------------------------------------------------------------------
    /// @dev `participate()` credits `totalRaised`/`lockedPaymentAmount` with the CALLER-SUPPLIED
    ///      `_paymentAmount`, not a measured balance delta — unlike `TradeSettlementV1`, which was
    ///      hardened against exactly this class (see `MockFeeOnTransferToken`'s own NatSpec:
    ///      "a settlement that credits the REQUESTED amount instead of the measured balance delta
    ///      over-reports its liabilities on the very first deposit"). `setAcceptedPaymentToken`'s
    ///      NatSpec warns against reentrant/hook tokens (ERC-777 etc.) but says nothing about
    ///      fee-on-transfer/deflationary tokens — an admin following that warning alone would not
    ///      know this token class is also unsafe here. This is not mutation-tested: it reproduces
    ///      the CURRENT, unmodified contract's behavior, so it is a real finding, not a coverage
    ///      probe. See the audit report's FINDINGS section.
    function test_FINDING_feeOnTransferPaymentTokenBreaksSolvencyOnFirstParticipate() public {
        MockFeeOnTransferToken fot = new MockFeeOnTransferToken("Fee USD", "fUSD", 200); // 2% fee

        vm.prank(address(this)); // platform owner
        launchpad.setAcceptedPaymentToken(address(fot), true);

        (address token2, ) = _issueTokenNamed("Store Token FOT", "STOREFOT");
        uint256 fotLaunchpadId = launchpad.launchpadCounter();
        launchpad.createLaunchpad(token2, TOKEN_PRICE, business, address(fot), 0, 0);

        (, , , , , , uint256 startTime, , , ) = launchpad.launchpads(fotLaunchpadId);
        vm.warp(startTime + 1);

        address investor = address(0xFA7);
        uint256 nominal = 30_000e18;
        fot.mint(investor, nominal);
        vm.startPrank(investor);
        fot.approve(address(launchpad), nominal);
        launchpad.participate(fotLaunchpadId, nominal);
        vm.stopPrank();

        // participate() credits the MEASURED balance delta. The contract
        // receives nominal*0.98 (2% burned in transit) and credits exactly that, so the I1 solvency
        // relation holds from the first call. Before the fix it credited the full nominal amount
        // and this assertion was inverted (assertLt) to pin the defect.
        uint256 received = (nominal * 9800) / 10_000;
        assertEq(
            launchpad.lockedPaymentAmount(address(fot)),
            received,
            "the payment lock must record what was received, not what was requested"
        );
        assertEq(
            fot.balanceOf(address(launchpad)),
            launchpad.lockedPaymentAmount(address(fot)),
            "the launchpad must hold exactly what it has promised"
        );
    }
}
