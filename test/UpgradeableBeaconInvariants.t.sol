// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

import { UpgradeableBeacon } from "../contracts/UpgradeableBeacon.sol";

/**
 * @title UpgradeableBeacon invariant suite — the 48h staged-upgrade timelock every ERC20V1 and
 *        TokenVestingWallet BeaconProxy instance trusts.
 *
 * @dev `test/UpgradeableBeaconTimelock.test.ts` already has thorough example-based boundary
 *      coverage (the exact 48h/7-day edges, ownership-handover clearing, access control — see
 *      its ~590 lines). What was missing is the STATEFUL dimension: arbitrary sequences of
 *      request/cancel/upgrade/transfer-ownership/warp, which is where a state-desync bug would
 *      actually show up. This suite adds that; it deliberately does not re-pin the boundary
 *      cases the existing suite already owns.
 *
 *      U1 staging pair agrees — `pendingImplementation` and `upgradeReadyAt` are set and
 *                                cleared together; a half-set staging is either stuck or
 *                                forgeable.
 *      U2 implementation provenance — `implementation()` only ever equals the constructor's
 *                                initial value or a value that was, at some point, staged via
 *                                `requestUpgrade`. A mutation that lets `upgradeTo` write an
 *                                arbitrary address would show up here.
 *      U3 execution window (inline) — checked at the moment of each successful `upgradeTo`
 *                                call inside the handler itself (mirroring
 *                                `WalletFactoryHandler.createAccount`'s inline `require`):
 *                                the executed address must be the one staged, and
 *                                `block.timestamp` must lie in `[upgradeReadyAt, upgradeReadyAt
 *                                + UPGRADE_GRACE_PERIOD]`. A dedicated "never staged" candidate
 *                                is reserved so a mismatch probe can never accidentally pass by
 *                                having been legitimately staged earlier in the same campaign.
 */
contract DummyBeaconImpl {
    uint256 public immutable tag;

    constructor(uint256 _tag) {
        tag = _tag;
    }
}

contract BeaconHandler is CommonBase, StdCheats, StdUtils {
    UpgradeableBeacon public immutable beacon;
    address[3] public candidates;
    address public immutable neverStaged;
    address[3] public ownerCandidates;

    mapping(address => bool) public wasStaged;

    uint256 public callsRequest;
    uint256 public callsCancel;
    uint256 public callsUpgrade;
    uint256 public callsTransferOwnership;

    constructor(
        UpgradeableBeacon _beacon,
        address[3] memory _candidates,
        address _neverStaged,
        address[3] memory _ownerCandidates
    ) {
        beacon = _beacon;
        candidates = _candidates;
        neverStaged = _neverStaged;
        ownerCandidates = _ownerCandidates;
    }

    function _owner() internal view returns (address) {
        return beacon.owner();
    }

    function requestUpgrade(uint256 seed) external {
        address cand = candidates[bound(seed, 0, 2)];
        vm.prank(_owner());
        try beacon.requestUpgrade(cand) {
            callsRequest++;
            wasStaged[cand] = true;
        } catch {}
    }

    function cancelUpgrade() external {
        vm.prank(_owner());
        try beacon.cancelUpgrade() {
            callsCancel++;
        } catch {}
    }

    /// @dev One call in five deliberately probes with `neverStaged` instead of the real
    ///      pending candidate — an address that `requestUpgrade` never touches anywhere in
    ///      this suite, so `wasStaged[neverStaged]` is false for the entire campaign under
    ///      correct code. If `upgradeTo`'s mismatch check is ever weakened, this is the call
    ///      that lands the mutant, not just the general U2 invariant re-scanning afterwards.
    function upgradeTo(uint256 seed) external {
        address pending = beacon.pendingImplementation();
        if (pending == address(0)) return;

        bool probeMismatch = seed % 5 == 0;
        address target = probeMismatch ? neverStaged : pending;
        uint256 readyAt = beacon.upgradeReadyAt();

        vm.prank(_owner());
        try beacon.upgradeTo(target) {
            callsUpgrade++;
            require(!probeMismatch, "U3 probe: a never-staged implementation was executed");
            require(block.timestamp >= readyAt, "U3: executed before the timelock matured");
            require(
                block.timestamp <= readyAt + beacon.UPGRADE_GRACE_PERIOD(),
                "U3: executed after the grace window expired"
            );
        } catch {}
    }

    function transferOwnershipFlow(uint256 seed) external {
        address newOwner = ownerCandidates[bound(seed, 0, 2)];
        address cur = _owner();
        if (newOwner == cur) return;

        vm.prank(cur);
        try beacon.transferOwnership(newOwner) {
            vm.prank(newOwner);
            beacon.acceptOwnership();
            callsTransferOwnership++;
        } catch {}
    }

    function warp(uint256 seed) external {
        vm.warp(block.timestamp + bound(seed, 1 hours, 10 days));
    }
}

contract UpgradeableBeaconInvariantsTest is StdInvariant, Test {
    UpgradeableBeacon internal beacon;
    DummyBeaconImpl internal initialImpl;
    BeaconHandler internal handler;

    address internal initialOwner = address(0xB0EA);

    function setUp() public {
        initialImpl = new DummyBeaconImpl(0);
        beacon = new UpgradeableBeacon(address(initialImpl), initialOwner);

        address[3] memory candidates = [
            address(new DummyBeaconImpl(1)),
            address(new DummyBeaconImpl(2)),
            address(new DummyBeaconImpl(3))
        ];
        address neverStaged = address(new DummyBeaconImpl(999));
        address[3] memory ownerCandidates = [initialOwner, address(0xB0EA2), address(0xB0EA3)];

        handler = new BeaconHandler(beacon, candidates, neverStaged, ownerCandidates);
        targetContract(address(handler));
    }

    function afterInvariant() public view {
        assertGt(
            handler.callsRequest() +
                handler.callsUpgrade() +
                handler.callsCancel() +
                handler.callsTransferOwnership(),
            0,
            // Measured with a temporary forced-failure probe, not assumed. Sampled runs:
            // request 108/90, upgrade 2/1, cancel 42/29, transferOwnership 79/74.
            // `upgrade` is the thin one — a staged upgrade only executes if the fuzzer happens to
            // warp into the live window, so the executed path is pinned by the deterministic tests
            // below rather than left to chance.
            "vacuous run: handler landed no successful state transition"
        );
    }

    // ------------------------------------------------------------------
    // U1 — staging pair agrees
    // ------------------------------------------------------------------
    function invariant_U1_stagingPairAgrees() public view {
        if (beacon.pendingImplementation() == address(0)) {
            assertEq(beacon.upgradeReadyAt(), 0, "U1: cleared pending left a live clock");
        } else {
            assertGt(beacon.upgradeReadyAt(), 0, "U1: pending upgrade with no clock");
        }
    }

    // ------------------------------------------------------------------
    // U2 — implementation only ever moves to a legitimately staged value
    // ------------------------------------------------------------------
    function invariant_U2_implementationHasProvenance() public view {
        address impl = beacon.implementation();
        if (impl != address(initialImpl)) {
            assertTrue(handler.wasStaged(impl), "U2: implementation is a value that was never staged");
        }
    }

    // ------------------------------------------------------------------
    // Deterministic — the executed-upgrade path, which the search reaches only 1-2 times a run.
    // ------------------------------------------------------------------

    /// @dev One beacon governs every issued ERC20V1, so a swap here rewrites every token at once
    ///     . The window is the containment: both ends are pinned here rather than
    /// assumed, because a one-sided timelock is the defect this contract already carries
    ///      the fix for.
    function test_upgradeWindowBoundsAreEnforcedOnBothSides() public {
        DummyBeaconImpl next = new DummyBeaconImpl(77);

        vm.prank(initialOwner);
        beacon.requestUpgrade(address(next));
        uint256 readyAt = beacon.upgradeReadyAt();

        // Too early.
        vm.warp(readyAt - 1);
        vm.prank(initialOwner);
        vm.expectRevert();
        beacon.upgradeTo(address(next));
        assertEq(beacon.implementation(), address(initialImpl), "early upgrade went through");

        // Too late — past maturity + grace.
        vm.warp(readyAt + beacon.UPGRADE_GRACE_PERIOD() + 1);
        vm.prank(initialOwner);
        vm.expectRevert();
        beacon.upgradeTo(address(next));
        assertEq(beacon.implementation(), address(initialImpl), "expired staging went through");
    }

    /// @dev And the legitimate path still works, at the last second of the window, clearing both
    ///      staging fields behind it.
    function test_upgradeExecutesInsideTheWindowAndClearsTheStaging() public {
        DummyBeaconImpl next = new DummyBeaconImpl(88);

        vm.prank(initialOwner);
        beacon.requestUpgrade(address(next));
        uint256 readyAt = beacon.upgradeReadyAt();

        vm.warp(readyAt + beacon.UPGRADE_GRACE_PERIOD());
        vm.prank(initialOwner);
        beacon.upgradeTo(address(next));

        assertEq(beacon.implementation(), address(next), "in-window upgrade did not take effect");
        assertEq(beacon.pendingImplementation(), address(0), "staging not cleared");
        assertEq(beacon.upgradeReadyAt(), 0, "clock not cleared");
    }

    /// @dev an incoming owner must not inherit a payload armed by their predecessor.
    ///
    ///      Both steps are pinned because getting this wrong is easy in either direction. The
    ///      beacon is Ownable2Step and the clearing lives in `_transferOwnership`, which runs on
    ///      ACCEPTANCE, not on nomination — so a staging surviving `transferOwnership` is correct
    ///      behaviour, and a test that asserted otherwise would be wrong rather than the contract.
    ///      (This test did assert otherwise on its first run.)
    function test_ownershipHandoverClearsAnArmedStagingOnAcceptance() public {
        address incoming = address(0xB0EA2);
        DummyBeaconImpl next = new DummyBeaconImpl(99);

        vm.prank(initialOwner);
        beacon.requestUpgrade(address(next));
        assertEq(beacon.pendingImplementation(), address(next), "precondition: staged");

        // Step 1 — nomination alone changes nothing. The predecessor still owns the beacon, so
        // their staging is still theirs.
        vm.prank(initialOwner);
        beacon.transferOwnership(incoming);
        assertEq(beacon.owner(), initialOwner, "nomination moved ownership");
        assertEq(
            beacon.pendingImplementation(),
            address(next),
            "nomination cleared a staging that is still the current owner's"
        );

        // Step 2 — acceptance is where ownership actually moves, and the payload must not follow.
        vm.prank(incoming);
        beacon.acceptOwnership();
        assertEq(beacon.owner(), incoming, "acceptance did not move ownership");
        assertEq(beacon.pendingImplementation(), address(0), "staging survived the handover");
        assertEq(beacon.upgradeReadyAt(), 0, "clock survived the handover");
    }
}
