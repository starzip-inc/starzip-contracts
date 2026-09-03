// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";
import { StdAssertions } from "forge-std/StdAssertions.sol";

import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { IPaymaster } from "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import { VerifyingPaymaster } from "../contracts/wallet/VerifyingPaymaster.sol";
import { MockEntryPoint } from "../contracts/mocks/MockEntryPoint.sol";
import { StarzipWallet } from "../contracts/wallet/StarzipWallet.sol";

/**
 * @title VerifyingPaymaster invariant suite — the spend accounting and C-B were about.
 *
 * @dev The AA stack was audited and remediated but had zero property coverage, and it is the one
 *      part of this system that cannot be fixed after the fact: the factory's implementation is
 * immutable and the wallets have no guardian. (the daily cap bypassed on every date
 *      rollover) was found by an arithmetic lens that four review lanes had not run — this is that
 *      lens, running continuously.
 *
 *      `postOp` and `validatePaymasterUserOp` are external behind `_requireFromEntryPoint`, so the
 *      handler drives the real accounting path by pranking the EntryPoint. No bundler needed.
 *
 *      A1 VIP implies a cap   — `setSponsoredUnlimited` refuses VIP while `dailyCap == 0`.
 *                               "Unlimited" must mean unlimited PER OP, never unlimited per day.
 *      A2 latch is one-way    — once the cumulative latch revokes sponsorship, a date rollover must
 *                               NOT restore it. Only an explicit `setSponsored(true)` may. This is
 * the C-B remediation, and was exactly a stale-day bypass.
 *      A3 per-wallet spend    — `spentToday` never decreases while `lastSpentDay` is unchanged.
 *      A4 global spend        — same for the global counter.
 */
contract TrustedPaymasterStub {
    address public immutable trustedPaymaster;

    constructor(address _trustedPaymaster) {
        trustedPaymaster = _trustedPaymaster;
    }

    // SSA-01: `_requireTrustedPaymaster` also staticcalls these and fails closed if either call
    // itself fails. Same stub as contracts/mocks/TrustedPaymasterStub.sol.
    function pendingImplementation() external pure returns (address) {
        return address(0);
    }

    function hasBeenUpgraded() external pure returns (bool) {
        return false;
    }
}

contract PaymasterHandler is CommonBase, StdCheats, StdUtils, StdAssertions {
    VerifyingPaymaster public immutable paymaster;
    address public immutable entryPoint;
    address public immutable policyManager;
    address public immutable paymasterOwner;
    /// @dev SSA-02 (2026-08-31 follow-up): `validate()` used to build a bare 52-byte
    ///      `paymasterAndData`, which now unconditionally declines at the NEW per-op signature
    ///      check — BEFORE `sponsored`/postOpGas/maxCost/self-target are ever reached (see that
    ///      check's position in `_validatePaymasterUserOp`, right after `paused`). That made every
    ///      B2/B3/B4/B6 inline assert below trivially true for the WRONG reason (the missing
    ///      signature, not the guard each one claims to isolate), and made B5's `!sigFail` branch
    ///      dead code. `validate()` now signs for real with this key, so the ONLY thing that can
    ///      still decline an otherwise-eligible op is the actual guard under test.
    uint256 internal immutable sponsorSignerPk;

    address[3] public wallets;

    // ---- ghosts ----
    mapping(address => bool) public sawLatchRevoke;
    mapping(address => uint32) public ghostDay;
    mapping(address => uint128) public ghostSpent;
    uint32 public ghostGlobalDay;
    uint128 public ghostGlobalSpent;
    /// @dev / invariant_A2b: records the latch's INPUT (`min(dailyCap, ceiling)`) as it stood
    ///      right after the most recent successful `postOp` for this wallet — i.e. exactly what
    ///      `_postOp`'s own `latchCap` used to decide whether to revoke. Recording the INPUT rather
    ///      than the outcome is what makes this un-starvable by a latch-disabling mutation: unlike
    ///      the rejected "recompute from the CURRENT ceiling" predicate, this value is never moved
    ///      by a LATER `setGlobalCeiling` call, so lowering the ceiling after a legitimate spend can
    ///      never manufacture a false positive (see invariant_A2b's own NatSpec).
    mapping(address => uint128) public ghostLatchCapAtPostOp;

    uint256 public callsPostOp;
    uint256 public callsSetSponsored;
    uint256 public callsSetCap;
    uint256 public callsLatched;
    uint256 public callsValidate;
    /// @dev Outcome of the most recent `validate()` call — exposed so a directed test can assert
    ///      the POSITIVE direction too (an otherwise-eligible op is genuinely ADMITTED), which the
    ///      inline B1-B7 asserts below do not check on their own (they only assert "IF declined-
    ///      condition THEN sigFail", never "IF nothing declines it THEN NOT sigFail").
    bool public lastValidateSigFail;
    /// @dev SSA-02 follow-up: count of `validate()` calls that were genuinely ADMITTED
    ///      (`!sigFail`). Before the signing fix this was structurally always 0 — `validate()`
    ///      could never reach the SPONSOR branch at all, which is exactly what made B5 dead code.
    ///      `afterInvariant` below asserts this is nonzero, so a regression that makes `validate()`
    ///      unable to ever admit an op (e.g. the signing logic breaking again) fails LOUD instead
    ///      of silently going back to vacuous B2-B6/dead-B5.
    uint256 public callsValidateAdmitted;

    constructor(
        VerifyingPaymaster _paymaster,
        address _entryPoint,
        address _policyManager,
        address _owner,
        uint256 _sponsorSignerPk
    ) {
        paymaster = _paymaster;
        entryPoint = _entryPoint;
        policyManager = _policyManager;
        paymasterOwner = _owner;
        sponsorSignerPk = _sponsorSignerPk;
        wallets[0] = address(0xAA01);
        wallets[1] = address(0xAA02);
        wallets[2] = address(0xAA03);
        TrustedPaymasterStub stub = new TrustedPaymasterStub(address(_paymaster));
        bytes memory stubCode = address(stub).code;
        for (uint256 i = 0; i < 3; i++) {
            vm.etch(wallets[i], stubCode);
        }
    }

    function _wallet(uint256 seed) internal view returns (address) {
        return wallets[seed % 3];
    }

    /// The real accounting path: EntryPoint calls postOp with the gas actually burned.
    function postOp(uint256 walletSeed, uint256 gasCostSeed) external {
        address w = _wallet(walletSeed);
        uint256 gasCost = bound(gasCostSeed, 1, 5e15);

        bool sponsoredBefore = paymaster.getPolicy(w).sponsored;

        vm.prank(entryPoint);
        try paymaster.postOp(
            IPaymaster.PostOpMode.opSucceeded,
            abi.encode(w, uint128(0)),
            gasCost,
            0
        ) {
            callsPostOp++;
            VerifyingPaymaster.WalletPolicy memory p = paymaster.getPolicy(w);
            if (sponsoredBefore && !p.sponsored) {
                sawLatchRevoke[w] = true;
                callsLatched++;
            }
            _recordSpend(w);
            // invariant_A2b: record the latch's INPUT immediately after the call, before any other
            // handler function can move `dailyCap`/`globalDailyCapCeiling` — this is exactly the
            // `latchCap` value `_postOp` itself just used to decide `p.sponsored`, so the ghost is
            // never stale in a way that matters (re-recorded on every successful postOp).
            uint128 ceiling = paymaster.globalDailyCapCeiling();
            ghostLatchCapAtPostOp[w] = p.dailyCap < ceiling ? p.dailyCap : ceiling;
        } catch {}
    }

    function _recordSpend(address w) internal {
        VerifyingPaymaster.WalletPolicy memory p = paymaster.getPolicy(w);
        if (p.lastSpentDay != ghostDay[w]) {
            ghostDay[w] = p.lastSpentDay;
            ghostSpent[w] = 0;
        }
        if (p.spentToday > ghostSpent[w]) ghostSpent[w] = p.spentToday;

        uint32 gd = paymaster.globalLastSpentDay();
        if (gd != ghostGlobalDay) {
            ghostGlobalDay = gd;
            ghostGlobalSpent = 0;
        }
        uint128 gs = paymaster.globalSpentToday();
        if (gs > ghostGlobalSpent) ghostGlobalSpent = gs;
    }

    function setSponsored(uint256 walletSeed, bool on) external {
        address w = _wallet(walletSeed);
        vm.prank(policyManager);
        try paymaster.setSponsored(w, on) {
            callsSetSponsored++;
            if (on) {
                // An explicit re-grant is the ONLY legitimate way out of the latch.
                sawLatchRevoke[w] = false;
                // ...and it also zeroes `spentToday`/`lastSpentDay` on purpose (a
                // decided tradeoff buying same-day recovery, pinned by
                // test/VerifyingPaymaster.spendcap.test.ts). A3 failed on exactly this before the
                // ghost modelled it — the invariant rediscovered without being told about it.
                // Note what is NOT reset here: `globalSpentToday`. That omission is deliberate and
                // is the only thing bounding a blind re-sponsor loop, which is why A4 below is the
                // load-bearing one.
                ghostSpent[w] = 0;
                ghostDay[w] = 0;
            }
        } catch {}
    }

    function setDailyCap(uint256 walletSeed, uint256 capSeed) external {
        address w = _wallet(walletSeed);
        vm.prank(policyManager);
        try paymaster.setDailyCap(w, uint128(bound(capSeed, 0, 1e17))) {
            callsSetCap++;
        } catch {}
    }

    /// @dev Item 5: granting VIP (`on == true`) now ALSO resets `spentToday`/`lastSpentDay`
    /// on-chain, mirroring `setSponsored`'s reset above. Without a matching ghost reset
    ///      here, `invariant_A3` would compare a freshly-zeroed on-chain `spentToday` against a
    ///      STALE `ghostSpent[w]` and fail — see the M5e mutation proof in the directed test below.
    function setSponsoredUnlimited(uint256 walletSeed, bool on) external {
        address w = _wallet(walletSeed);
        vm.prank(paymasterOwner);
        try paymaster.setSponsoredUnlimited(w, on) {
            if (on) {
                ghostSpent[w] = 0;
                ghostDay[w] = 0;
            }
        } catch {}
    }

    /// @dev lets the validation-phase fuzz below reach the SPONSORED success path (no
    ///      handler wrapper ever populates `businessAllowlist`/`selfSelectorAllowlist`, so without
    ///      this every non-`sponsorPersonal` op declines at the business gate before B4/B5/B7 can
    ///      ever be exercised against a genuinely-admitted op). Owner-only in the real contract;
    ///      always pranked as the owner here since the owner can both grant and revoke.
    function setSponsorPersonalH(uint256 walletSeed, bool on) external {
        vm.prank(paymasterOwner);
        try paymaster.setSponsorPersonal(_wallet(walletSeed), on) {} catch {}
    }

    /// @dev B1 needs `paused` to actually vary — nothing else in this handler ever pauses the
    ///      paymaster, which would leave B1 permanently vacuous.
    function togglePause(uint256 seed) external {
        vm.prank(paymasterOwner);
        if (seed % 2 == 0) {
            try paymaster.pause() {} catch {}
        } else {
            try paymaster.unpause() {} catch {}
        }
    }

    function setGlobalCeiling(uint256 seed) external {
        vm.prank(paymasterOwner);
        try paymaster.setGlobalDailyCapCeiling(uint128(bound(seed, 0, 1e17))) {} catch {}
    }

    function setGlobalBudget(uint256 seed) external {
        vm.prank(paymasterOwner);
        try paymaster.setGlobalDailyBudget(uint128(bound(seed, 0, 1e18))) {} catch {}
    }

    /// Day rollovers are the whole point: was a bypass that reopened on every UTC date change.
    function warpDays(uint256 seed) external {
        vm.warp(block.timestamp + bound(seed, 1 hours, 3 days));
    }

    /// @dev the fuzz suite used to be structurally blind to the ENTIRE validation phase — no
    ///      handler function ever called `validatePaymasterUserOp`, so 4 mutations inside
    ///      `_validatePaymasterUserOp`/`_extractBusinessOk` survived the invariant suite 8/8 while
    ///      the TypeScript suite caught every one. Wires it in directly (pranking the EntryPoint,
    ///      same as `postOp` above) and asserts B1-B7 INLINE right after the call — a failing
    ///      assert here fails the run at the exact offending sequence, stronger and simpler than a
    ///      ghost. `validatePaymasterUserOp` MUST NEVER revert (ERC-7562), so B7 is the `catch`
    ///      branch itself.
    function validate(
        uint256 walletSeed,
        uint256 verGasSeed,
        uint256 callGasSeed,
        uint256 pmValGasSeed,
        uint256 pmPostGasSeed,
        uint256 preVerGasSeed,
        uint256 feeSeed,
        uint256 maxCostSeed,
        uint256 shapeSeed
    ) external {
        address w = _wallet(walletSeed);

        uint128 verGas = uint128(bound(verGasSeed, 0, 500_000));
        uint128 callGas = uint128(bound(callGasSeed, 0, 500_000));
        uint128 pmValGas = uint128(bound(pmValGasSeed, 0, 200_000));
        // Bounded ACROSS the MIN_POSTOP_GAS (90,000) boundary on purpose — B3 needs both sides.
        uint128 pmPostGas = uint128(bound(pmPostGasSeed, 0, 180_000));
        uint256 preVerGas = bound(preVerGasSeed, 0, 200_000);
        uint128 fee = uint128(bound(feeSeed, 0, 3_000_000_000)); // spans the 1 gwei production cap
        // Spans `maxSponsoredOpCost` (0.0007 ether, set in setUp) both sides.
        uint256 maxCost = bound(maxCostSeed, 0, 0.002 ether);

        bool selfTargeted = shapeSeed % 5 == 4;
        bytes memory callData = _buildCallData(w, shapeSeed);

        PackedUserOperation memory op = PackedUserOperation({
            sender: w,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32((uint256(verGas) << 128) | uint256(callGas)),
            preVerificationGas: preVerGas,
            gasFees: bytes32((uint256(fee) << 128) | uint256(fee)),
            paymasterAndData: abi.encodePacked(address(paymaster), pmValGas, pmPostGas),
            // SSA-02: `minSigLen == 0` is hard-declined, so this pairs with `minSigLen = 1`
            // below. This handler fuzzes the paymaster's own guards, never wallet-side signature
            // content.
            signature: hex"00"
        });

        // SSA-02 (2026-08-31 follow-up): sign for real, the same way the positive control test
        // does — preimage from the contract's own `getHash`, no expiry window. Without this, EVERY
        // call here declined at the signature check alone (before `sponsored`/postOpGas/maxCost/
        // self-target are ever reached), making B2/B3/B4/B6 pass for the wrong reason and B5 dead
        // code. Signed unconditionally (not just when the fuzzed fields would otherwise admit the
        // op) so the ONLY thing that can still decline an eligible op is the guard under test.
        //
        // SSA-02 time-window follow-up (2026-08-31, second pass): `_validatePaymasterUserOp` now
        // HARD-DECLINES `validUntil == 0` (fail-open default blocked — an unbounded window must be
        // requested explicitly). `0` here used to mean "no expiry window" to the EntryPoint
        // (`Helpers.sol` substituted `type(uint48).max`); it must now be spelled out, or every call
        // through this handler declines at the validUntil check alone, for the same reason the
        // pre-existing comment above describes for a missing signature.
        uint48 validUntil = type(uint48).max;
        uint48 validAfter = 0;
        // SSA-02: `getHash` also covers `minSigLen`. `1` is the smallest value that satisfies the
        // floor while keeping the length check a no-op against the 1-byte placeholder above.
        uint16 minSigLen = 1;
        bytes32 hash = paymaster.getHash(op, validUntil, validAfter, minSigLen);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sponsorSignerPk, MessageHashUtils.toEthSignedMessageHash(hash));
        op.paymasterAndData = abi.encodePacked(
            address(paymaster),
            pmValGas,
            pmPostGas,
            validUntil,
            validAfter,
            minSigLen,
            abi.encodePacked(r, s, v)
        );

        bool pausedBefore = paymaster.paused();
        VerifyingPaymaster.WalletPolicy memory pBefore = paymaster.getPolicy(w);
        uint128 opCostCapBefore = paymaster.maxSponsoredOpCost();
        uint128 minPostOpGas = paymaster.MIN_POSTOP_GAS();

        vm.prank(entryPoint);
        try paymaster.validatePaymasterUserOp(op, bytes32(0), maxCost) returns (
            bytes memory context,
            uint256 validationData
        ) {
            callsValidate++;
            bool sigFail = address(uint160(validationData)) == address(1);
            lastValidateSigFail = sigFail;

            // B1 — paused => sigFail.
            if (pausedBefore) {
                assertTrue(sigFail, "B1: a paused paymaster admitted an op");
            }
            // B2 — !sponsored => sigFail.
            if (!pBefore.sponsored) {
                assertTrue(sigFail, "B2: an unsponsored wallet's op was admitted");
            }
            // B3 — postOpGas < MIN_POSTOP_GAS => sigFail.
            if (pmPostGas < minPostOpGas) {
                assertTrue(sigFail, "B3: an op below MIN_POSTOP_GAS was admitted");
            }
            // B4 (post item 1) — maxCost > maxSponsoredOpCost => sigFail, including at cap 0.
            if (maxCost > uint256(opCostCapBefore)) {
                assertTrue(sigFail, "B4: an op above maxSponsoredOpCost was admitted");
            }
            // B6 (post item 4) — a self-targeted call is never admitted on a non-sponsorPersonal
            // wallet unless its selector is self-allowlisted; no handler wrapper ever populates
            // `selfSelectorAllowlist`, so this direction always holds here.
            if (selfTargeted && !pBefore.sponsorPersonal) {
                assertTrue(sigFail, "B6: an unallowlisted self-call was admitted");
            }
            // B5 — not sigFail => non-empty context (so postOp always accrues, incl. VIP).
            if (!sigFail) {
                callsValidateAdmitted++;
                assertTrue(context.length > 0, "B5: a sponsored op returned an empty context");
            }
        } catch {
            // B7 — must NEVER revert (ERC-7562); any calldata shape must decline, not revert.
            assertTrue(false, "B7: validatePaymasterUserOp reverted instead of declining");
        }
    }

    /// @dev A small, deterministic set of callData shapes: well-formed `execute` to a foreign
    ///      target, well-formed `executeBatch`, truncated (< 100 bytes), garbage (unrecognized
    ///      selector), and self-targeted `execute` (`target == sender`).
    function _buildCallData(address sender, uint256 shapeSeed) internal pure returns (bytes memory) {
        uint256 shape = shapeSeed % 5;
        bytes memory addOwner = abi.encodeWithSelector(StarzipWallet.addOwnerAddress.selector, address(0xC0FFEE));

        if (shape == 0) {
            return abi.encodeWithSelector(StarzipWallet.execute.selector, address(0xB0B0), uint256(0), addOwner);
        } else if (shape == 1) {
            address[] memory dests = new address[](2);
            dests[0] = address(0xB0B0);
            dests[1] = address(0xB0B1);
            uint256[] memory values = new uint256[](2);
            bytes[] memory funcs = new bytes[](2);
            funcs[0] = addOwner;
            funcs[1] = addOwner;
            return abi.encodeWithSelector(StarzipWallet.executeBatch.selector, dests, values, funcs);
        } else if (shape == 2) {
            // Truncated: < 100 bytes, hits `_extractBusinessOk`'s early bounds-check decline.
            return abi.encodePacked(StarzipWallet.execute.selector, uint256(1));
        } else if (shape == 3) {
            // Garbage: a selector that matches neither `execute` nor `executeBatch`.
            return abi.encodeWithSelector(bytes4(0xdeadbeef));
        } else {
            return abi.encodeWithSelector(StarzipWallet.execute.selector, sender, uint256(0), addOwner);
        }
    }
}

contract PaymasterInvariantsTest is StdInvariant, Test {
    VerifyingPaymaster internal paymaster;
    MockEntryPoint internal entryPoint;
    PaymasterHandler internal handler;

    address internal policyManager = address(0xB001);
    /// @dev SSA-02's per-op signer. This suite fuzzes the spend accounting directly via
    ///      `PaymasterHandler.validate()`, which never supplies a valid per-op signature — every
    ///      call there declines at the new signature check regardless of any OTHER guard (see
    ///      that function's own comment). `test_B1234_positiveControl_eligibleOpIsSponsored`
    ///      below is the one test that DOES need to reach the SPONSOR branch, so this must be a
    ///      key the test actually holds, not an arbitrary non-zero address.
    uint256 internal constant SPONSOR_SIGNER_PK = 0xB002B002B002B002B002B002B002B002B002B002B002B002B002B002B002B0;
    address internal sponsorSigner;

    function setUp() public {
        sponsorSigner = vm.addr(SPONSOR_SIGNER_PK);
        entryPoint = new MockEntryPoint();
        paymaster = new VerifyingPaymaster(
            IEntryPoint(address(entryPoint)),
            policyManager,
            address(0),
            sponsorSigner
        );
        // unpause() now refuses while any of the three per-op caps is unprovisioned
        // (0). Provisioned here at the SAME production values the deploy script ships
        // (MAX_SPONSORED_OP_COST / MAX_SPONSORED_FEE_PER_GAS / MAX_SPONSORED_PREVERIFICATION_GAS)
        // rather than arbitrary non-zero numbers, so item 6's future validation-phase handler
        // exercises B4 against the real deployed profile, not a fixture-only one.
        paymaster.setMaxSponsoredOpCost(0.0007 ether);
        paymaster.setMaxSponsoredFeePerGas(1 gwei);
        paymaster.setMaxSponsoredPreVerificationGas(60_000);
        paymaster.unpause();
        paymaster.setGlobalDailyCapCeiling(1e16);
        paymaster.setGlobalDailyBudget(1e17);

        handler = new PaymasterHandler(paymaster, address(entryPoint), policyManager, address(this), SPONSOR_SIGNER_PK);

        // Seed one sponsored wallet with a cap so the latch is reachable from run one.
        vm.startPrank(policyManager);
        paymaster.setDailyCap(address(0xAA01), 1e14);
        paymaster.setSponsored(address(0xAA01), true);
        vm.stopPrank();

        targetContract(address(handler));
    }

    function afterInvariant() public view {
        assertGt(
            handler.callsPostOp() + handler.callsSetSponsored() + handler.callsSetCap(),
            0,
            "vacuous run: handler landed no successful state transition"
        );
        // Added, then removed: this used to assert `callsLatched() > 0` here, on
        // the same reasoning as the comment above — that a latch-DISABLING mutation would otherwise
        // starve `invariant_A2`'s `sawLatchRevoke[w]` precondition and pass vacuously. The reasoning
        // for WHY a guard was needed was correct; the guard itself was wrong in kind. Whether the
        // latch fires in a GIVEN run is a property of the random call sequence (which wallet gets
        // picked, whether `setSponsored`/`setGlobalCeiling` moves the threshold out of reach before
        // enough spend accrues, whether `warpDays` resets `spentToday` first) — not a property of
        // the contract. CI hit exactly that: a run that spent its budget unsponsoring wallets and
        // pushing `globalDailyCapCeiling` high enough that `latchCap` was never crossed, red-lining a
        // correct contract on an unlucky seed. A test that can fail with nothing wrong trains people
        // to ignore red CI, which is worse than not having it.
        //
        // The mutation this was defending against (deleting/disabling the latch in `_postOp`) is
        // still caught, deterministically, by two things that do NOT depend on the fuzzer happening
        // to observe an outcome:
        //   - `invariant_A2b_latchFiresAtTheRecordedThreshold`, which keys off the latch's own
        //     RECORDED INPUT (`ghostLatchCapAtPostOp`) rather than whether a revoke was ever seen;
        //   - `test_cumulativeSpendRevokesSponsorship`, a directed test that drives the exact
        //     threshold-crossing sequence unconditionally.
        // Do not re-add a `callsLatched() > 0` (or similarly-shaped "did the campaign happen to reach
        // state X") assertion here — if the concern resurfaces, make it a deterministic/directed
        // check like the two above, not a property of the random walk.
        // guard the validation-phase fuzz entry point (`validate`) against being a no-op in
        // this run — B1-B7 are asserted inline inside it, so if it never actually ran, those
        // properties were silently unexercised rather than checked-and-passed.
        assertGt(handler.callsValidate(), 0, "vacuous: validate() was never reached in this run");
    }

    function _postOp(address w, uint256 gasCost) internal {
        vm.prank(address(entryPoint));
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, abi.encode(w, uint128(0)), gasCost, 0);
    }

    /// @dev A2 alone cannot see a MISSING latch: with no revoke ever observed its precondition is
    ///      never met and it passes vacuously. Deleting the latch is the mutation that matters, so
    ///      the latch's existence is pinned here rather than left to the search.
    function test_cumulativeSpendRevokesSponsorship() public {
        address w = address(0xAA01); // seeded: cap 1e14, sponsored
        assertTrue(paymaster.getPolicy(w).sponsored, "precondition: sponsored");

        _postOp(w, 6e13);
        assertTrue(paymaster.getPolicy(w).sponsored, "revoked below the cap");

        _postOp(w, 6e13); // cumulative 1.2e14 > cap 1e14
        assertFalse(paymaster.getPolicy(w).sponsored, "C-B: latch did not revoke past the cap");
    }

    /// @dev : the latch threshold must be `min(dailyCap, globalDailyCapCeiling)`, the same
    ///      figure validation enforces. Using the raw stored cap would mean lowering the ceiling
    ///      loosens the latch by exactly the factor it tightens validation by.
    function test_latchThresholdFollowsTheCeilingNotTheStoredCap() public {
        address w = address(0xAA02);
        vm.startPrank(policyManager);
        paymaster.setDailyCap(w, 1e14);
        paymaster.setSponsored(w, true);
        vm.stopPrank();

        paymaster.setGlobalDailyCapCeiling(1e13); // now BELOW the stored per-wallet cap

        _postOp(w, 2e13); // over the ceiling, under the stored cap
        assertFalse(paymaster.getPolicy(w).sponsored, "latch used the raw dailyCap instead of the ceiling");
    }

    /// @dev was a stale-day bypass: the cap reopened on every UTC date change. A revoked wallet
    ///      must stay revoked across any number of rollovers.
    function test_dayRolloverDoesNotRestoreSponsorship() public {
        address w = address(0xAA01);
        _postOp(w, 2e14); // straight past the cap
        assertFalse(paymaster.getPolicy(w).sponsored, "precondition: revoked");

        vm.warp(block.timestamp + 3 days);
        _postOp(w, 1);
        assertFalse(paymaster.getPolicy(w).sponsored, "a date rollover restored sponsorship");
    }

    /// @dev resets the per-wallet counter on re-sponsor by design. What it must NOT reset is
    ///      the global counter — that omission is the only thing bounding a blind re-sponsor loop.
    function test_reSponsorResetsWalletCounterButNotTheGlobalOne() public {
        address w = address(0xAA01);
        _postOp(w, 5e13);
        uint128 globalBefore = paymaster.globalSpentToday();
        assertGt(globalBefore, 0, "precondition: global accrued");

        vm.prank(policyManager);
        paymaster.setSponsored(w, true);

        assertEq(paymaster.getPolicy(w).spentToday, 0, "wallet counter was not reset");
        assertEq(paymaster.globalSpentToday(), globalBefore, "containment: the global counter was reset too");
    }

    /// A1 — "unlimited" must mean unlimited per OP, never per day.
    function invariant_A1_vipImpliesNonZeroCap() public view {
        for (uint256 i = 0; i < 3; i++) {
            VerifyingPaymaster.WalletPolicy memory p = paymaster.getPolicy(handler.wallets(i));
            if (p.vip) {
                assertGt(p.dailyCap, 0, "A1: VIP wallet with a zero daily cap");
            }
        }
    }

    /// A2 — the C-B latch is one-way. A date rollover must never restore sponsorship; only an
    /// explicit policyManager re-grant may. was precisely a stale-day bypass, so this is
    ///      the property that class of bug violates.
    function invariant_A2_latchIsOneWayAcrossDayRollovers() public view {
        for (uint256 i = 0; i < 3; i++) {
            address w = handler.wallets(i);
            if (handler.sawLatchRevoke(w)) {
                assertFalse(
                    paymaster.getPolicy(w).sponsored,
                    "A2: sponsorship came back without an explicit setSponsored(true)"
                );
            }
        }
    }

    /// A2b — the state-derived replacement, over RECORDED INPUTS rather than the latch's
    ///      outcome. `ghostLatchCapAtPostOp[w]` is the `min(dailyCap, ceiling)` that `_postOp`
    ///      itself used the last time it actually ran for `w` — re-recorded on every successful
    ///      `postOp`, so it is never stale in a way that matters. This is deliberately NOT the
    ///      predicate the first draft of the audit proposed (recomputing `latchCap` from the
    ///      CURRENT `globalDailyCapCeiling`): that version false-positives the instant the handler
    ///      lowers the ceiling after a legitimate spend under a higher one (`setGlobalDailyCapCeiling`
    ///      deliberately does not reclamp per-wallet storage), which the fuzzer finds on essentially
    ///      any run — see `test_loweringCeilingAfterSpendDoesNotFalsePositiveA2b` below for the
    ///      directed proof that THIS version does not have that problem, and
    ///      `invariant_A2_latchIsOneWayAcrossDayRollovers` (kept, not replaced) for the one-way
    ///      property this predicate cannot see on its own (mutation M6b).
    function invariant_A2b_latchFiresAtTheRecordedThreshold() public view {
        for (uint256 i = 0; i < 3; i++) {
            address w = handler.wallets(i);
            VerifyingPaymaster.WalletPolicy memory p = paymaster.getPolicy(w);
            uint128 recordedCap = handler.ghostLatchCapAtPostOp(w);
            if (p.spentToday > recordedCap) {
                assertFalse(
                    p.sponsored,
                    "A2b: spentToday exceeds the recorded latch threshold but the wallet is still sponsored"
                );
            }
        }
    }

    /// A3 — per-wallet spend is monotone within a day. A counter that can go backwards is a cap
    ///      that can be re-used.
    function invariant_A3_walletSpendMonotoneWithinDay() public view {
        for (uint256 i = 0; i < 3; i++) {
            address w = handler.wallets(i);
            VerifyingPaymaster.WalletPolicy memory p = paymaster.getPolicy(w);
            if (p.lastSpentDay == handler.ghostDay(w)) {
                assertGe(p.spentToday, handler.ghostSpent(w), "A3: spentToday decreased within a day");
            }
        }
    }

    /// A4 — same for the global budget counter.
    function invariant_A4_globalSpendMonotoneWithinDay() public view {
        if (paymaster.globalLastSpentDay() == handler.ghostGlobalDay()) {
            assertGe(
                paymaster.globalSpentToday(),
                handler.ghostGlobalSpent(),
                "A4: globalSpentToday decreased within a day"
            );
        }
    }

    /// @dev Shared eligible-wallet setup for the B1-B4 directed tests below. Grants
    ///      `sponsorPersonal` so the business/self gate is BYPASSED — without this, every
    ///      `validate()` call declines at the business gate regardless of any other property
    ///      (nothing in this handler ever populates `businessAllowlist`/`selfSelectorAllowlist`),
    ///      which makes `sigFail == true` trivially true and any single mutated guard
    ///      UNDETECTABLE by comparing only "declined vs not". This is not hypothetical: a full
    ///      256-run fuzz campaign against the raw (unguarded-by-directed-tests) B1 mutation below
    ///      did not fail — confirmed by hand before adding these. Each test isolates exactly ONE
    ///      guard: the op is otherwise fully eligible (sponsored, sponsorPersonal, cap/budget/fee
    ///      all within bounds), so when UNMUTATED it declines for the one stated reason, and when
    ///      that guard is mutated away it must be genuinely ADMITTED, not declined for some
    ///      unrelated reason.
    function _makeWalletZeroEligible() internal {
        handler.setSponsorPersonalH(0, true); // wallets[0] == 0xAA01
    }

    /// @dev Same idea as `_makeWalletZeroEligible`, but for an ARBITRARY wallet index and
    ///      deliberately WITHOUT calling `setSponsored` — used by B2, where the property under
    ///      test IS the sponsored check, so everything else must be provisioned around it.
    function _makeEligibleExceptSponsorship(uint256 walletSeed) internal {
        handler.setSponsorPersonalH(walletSeed, true);
        handler.setDailyCap(walletSeed, 1e14);
    }

    uint256 internal constant GOOD_MAX_COST = 1e14; // well under maxSponsoredOpCost (0.0007 ether)
    uint256 internal constant GOOD_FEE = 1e9; // == maxSponsoredFeePerGas (1 gwei), at the boundary
    uint256 internal constant GOOD_POST_GAS = 100_000; // > MIN_POSTOP_GAS (90,000)

    /// @dev B1 — paused => sigFail, on an op that is otherwise fully eligible.
    function test_B1_pausedOpIsDeclined() public {
        _makeWalletZeroEligible();
        paymaster.pause();
        handler.validate(0, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, GOOD_MAX_COST, 0);
    }

    /// @dev B2 — !sponsored => sigFail. Wallet index 2 (0xAA03) is made eligible on every OTHER
    ///      axis and deliberately never sponsored, so this isolates the sponsored check alone.
    function test_B2_unsponsoredOpIsDeclined() public {
        _makeEligibleExceptSponsorship(2);
        handler.validate(2, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, GOOD_MAX_COST, 0);
    }

    /// @dev B3 — postOpGas < MIN_POSTOP_GAS => sigFail.
    function test_B3_belowMinPostOpGasIsDeclined() public {
        _makeWalletZeroEligible();
        handler.validate(0, 100_000, 100_000, 50_000, 0, 50_000, GOOD_FEE, GOOD_MAX_COST, 0);
    }

    /// @dev B4 (post item 1) — maxCost > maxSponsoredOpCost => sigFail, including at cap 0. The
    ///      wallet's OWN dailyCap is raised well above 0.002 ether first — otherwise the unrelated
    ///      per-wallet `dailyCap` check (`maxCost > effectiveDailyCap`) declines the same op for a
    ///      different reason and this test would pass even with maxSponsoredOpCost's guard gutted
    ///      (confirmed by hand: it did, before this fix).
    function test_B4_aboveMaxSponsoredOpCostIsDeclined() public {
        _makeWalletZeroEligible();
        handler.setDailyCap(0, 1e16); // == globalDailyCapCeiling set in setUp
        handler.validate(0, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, 0.002 ether, 0);
    }

    /// @dev Positive control for the four tests above: with NOTHING declining it, the SAME
    ///      otherwise-eligible op must actually be SPONSORED. Without this, an over-tightened
    ///      guard (e.g. `validate` always declining) would make B1-B4 pass for the wrong reason.
    ///
    ///      SSA-02 (2026-08-31): unlike B1-B4, this one cannot go through
    ///      `PaymasterHandler.validate()` — that helper only ever builds a bare 52-byte
    ///      `paymasterAndData`, which now unconditionally declines at the NEW per-op signature
    ///      check (added right after the `paused` check, before `sponsored`/postOpGas/maxCost —
    ///      see `_validatePaymasterUserOp`'s SSA-02 NatSpec), so it can never reach the SPONSOR
    ///      branch this test exists to prove is reachable. This builds the identical op shape by
    ///      hand and signs it with `SPONSOR_SIGNER_PK`, deriving the preimage from the contract's
    ///      own `getHash` (not a hand-reconstructed one) so this test cannot drift from what
    ///      `_validatePaymasterUserOp` actually checks.
    function test_B1234_positiveControl_eligibleOpIsSponsored() public {
        _makeWalletZeroEligible();
        address w = handler.wallets(0); // == address(0xAA01)

        uint128 verGas = 100_000;
        uint128 callGas = 100_000;
        uint128 pmValGas = 50_000;
        uint128 pmPostGas = uint128(GOOD_POST_GAS);
        uint256 preVerGas = 50_000;
        uint128 fee = uint128(GOOD_FEE);
        uint256 maxCost = GOOD_MAX_COST;

        // Mirrors `PaymasterHandler._buildCallData`'s shape 0 (shapeSeed == 0): a well-formed
        // `execute` to a foreign target.
        bytes memory addOwner = abi.encodeWithSelector(StarzipWallet.addOwnerAddress.selector, address(0xC0FFEE));
        bytes memory callData = abi.encodeWithSelector(StarzipWallet.execute.selector, address(0xB0B0), uint256(0), addOwner);

        PackedUserOperation memory op = PackedUserOperation({
            sender: w,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32((uint256(verGas) << 128) | uint256(callGas)),
            preVerificationGas: preVerGas,
            gasFees: bytes32((uint256(fee) << 128) | uint256(fee)),
            paymasterAndData: abi.encodePacked(address(paymaster), pmValGas, pmPostGas),
            // SSA-02: 1-byte placeholder pairing with `minSigLen = 1` below — see
            // `PaymasterHandler.validate()`.
            signature: hex"00"
        });

        // SSA-02 time-window follow-up (2026-08-31): `validUntil == 0` is now hard-declined (see
        // the analogous fix in `PaymasterHandler.validate()` above) — this positive control must
        // sign an EXPLICIT unlimited window, not the omitted default, or it declines at the
        // validUntil check before ever reaching the branch it means to test.
        uint48 validUntil = type(uint48).max;
        uint48 validAfter = 0;
        // SSA-02: see `PaymasterHandler.validate()`.
        uint16 minSigLen = 1;
        bytes32 hash = paymaster.getHash(op, validUntil, validAfter, minSigLen);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SPONSOR_SIGNER_PK, MessageHashUtils.toEthSignedMessageHash(hash));
        bytes memory signature = abi.encodePacked(r, s, v);
        op.paymasterAndData = abi.encodePacked(address(paymaster), pmValGas, pmPostGas, validUntil, validAfter, minSigLen, signature);

        vm.prank(address(entryPoint));
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(op, bytes32(0), maxCost);
        bool sigFail = address(uint160(validationData)) == address(1);
        assertFalse(sigFail, "positive control: an eligible op must be sponsored, not declined");
    }

    /// @dev SSA-02 follow-up (2026-08-31): unlike the positive control above (which hand-builds its
    ///      own op, independent of `PaymasterHandler.validate()`), THIS test drives `validate()`
    ///      itself — the exact function the invariant fuzz campaign calls — and confirms it can
    ///      reach the SPONSOR branch now that it signs for real. Before the signing fix this was
    ///      IMPOSSIBLE: every `validate()` call declined at the signature check alone, regardless of
    ///      parameters, which made B2/B3/B4/B6's inline asserts pass for the wrong reason (the
    ///      missing signature, not the guard each one names) and made B5's `!sigFail` branch dead
    ///      code. Deterministic, not fuzz-luck-dependent — the directed alternative to a "did the
    ///      random campaign happen to hit this" assertion.
    function test_handlerValidateCanReachAdmission() public {
        _makeWalletZeroEligible();
        assertEq(handler.callsValidateAdmitted(), 0, "precondition: no admission recorded yet");

        handler.validate(0, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, GOOD_MAX_COST, 0);

        assertFalse(
            handler.lastValidateSigFail(),
            "handler.validate() must be able to reach the SPONSOR branch on an eligible op"
        );
        assertEq(
            handler.callsValidateAdmitted(),
            1,
            "the callsValidateAdmitted ghost must track this admission (restores B5 reachability)"
        );
    }

    /// @dev SSA-02 follow-up (2026-08-31): B2/B3/B4 (above, pre-existing) each isolate exactly ONE
    ///      guard via `_makeWalletZeroEligible`/`_makeEligibleExceptSponsorship` plus ONE bad
    ///      parameter — see each test's own docstring. That isolation claim depends entirely on
    ///      `validate()` being ABLE to admit the op when nothing is wrong (proven by
    ///      `test_handlerValidateCanReachAdmission` above) — otherwise "sigFail" is trivially true
    ///      for every call and proves nothing. This test cross-checks B2 concretely: the SAME
    ///      wallet/parameters as `test_B2_unsponsoredOpIsDeclined`, but WITH sponsorship granted,
    ///      must flip from declined to admitted — demonstrating the earlier decline really was
    ///      caused by `!sponsored`, not by a missing signature.
    function test_B2_isolationProof_grantingSponsorshipFlipsTheSameOpToAdmitted() public {
        _makeEligibleExceptSponsorship(2); // wallet 2 == 0xAA03, matches test_B2's own setup exactly
        handler.validate(2, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, GOOD_MAX_COST, 0);
        assertTrue(handler.lastValidateSigFail(), "precondition: unsponsored declines, matching test_B2");

        // `vm.prank` only covers the VERY NEXT external call — resolve `wallets(2)` first so it
        // does not itself consume the prank meant for `setSponsored`.
        address w2 = handler.wallets(2);
        vm.prank(policyManager);
        paymaster.setSponsored(w2, true);

        handler.validate(2, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, GOOD_MAX_COST, 0);
        assertFalse(
            handler.lastValidateSigFail(),
            "B2 isolation: the ONLY thing that changed was sponsorship, so the SAME op must now be admitted"
        );
    }

    /// @dev SSA-02 follow-up: same isolation proof for B3 — the SAME wallet/op only differs in
    ///      pmPostGas (0, i.e. below MIN_POSTOP_GAS, vs GOOD_POST_GAS).
    function test_B3_isolationProof_raisingPostOpGasFlipsTheSameOpToAdmitted() public {
        _makeWalletZeroEligible();
        handler.validate(0, 100_000, 100_000, 50_000, 0, 50_000, GOOD_FEE, GOOD_MAX_COST, 0);
        assertTrue(handler.lastValidateSigFail(), "precondition: postOpGas=0 declines, matching test_B3");

        handler.validate(0, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, GOOD_MAX_COST, 0);
        assertFalse(
            handler.lastValidateSigFail(),
            "B3 isolation: the ONLY thing that changed was postOpGas, so the SAME op must now be admitted"
        );
    }

    /// @dev SSA-02 follow-up: same isolation proof for B4 — the SAME wallet/op only differs in
    ///      maxCost (above vs at/below maxSponsoredOpCost).
    function test_B4_isolationProof_loweringMaxCostFlipsTheSameOpToAdmitted() public {
        _makeWalletZeroEligible();
        handler.setDailyCap(0, 1e16); // == globalDailyCapCeiling, matching test_B4's own setup
        handler.validate(0, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, 0.002 ether, 0);
        assertTrue(handler.lastValidateSigFail(), "precondition: maxCost above the cap declines, matching test_B4");

        handler.validate(0, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, GOOD_MAX_COST, 0);
        assertFalse(
            handler.lastValidateSigFail(),
            "B4 isolation: the ONLY thing that changed was maxCost, so the SAME op must now be admitted"
        );
    }

    /// @dev SSA-02 follow-up: isolation proof for B6 — an unallowlisted self-target declines while
    ///      `sponsorPersonal` is off, and the SAME op is admitted once `sponsorPersonal` is granted
    ///      (the escape hatch `_makeWalletZeroEligible` normally grants up front; here it is proven
    ///      as a BEFORE/AFTER flip instead of only ever exercised already-open).
    function test_B6_isolationProof_grantingSponsorPersonalFlipsSelfTargetedOpToAdmitted() public {
        // Deliberately NOT `_makeEligibleExceptSponsorship`/`_makeWalletZeroEligible` — both grant
        // sponsorPersonal up front, which is exactly the guard this test needs to start OFF.
        address w1 = handler.wallets(1); // wallet 1 == 0xAA02
        vm.startPrank(policyManager);
        paymaster.setDailyCap(w1, 1e14);
        paymaster.setSponsored(w1, true);
        vm.stopPrank();

        // shapeSeed % 5 == 4 => self-targeted (see _buildCallData); sponsorPersonal still OFF.
        handler.validate(1, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, GOOD_MAX_COST, 4);
        assertTrue(handler.lastValidateSigFail(), "precondition: unallowlisted self-target declines, matching B6");

        // Owner-only; the test contract itself is the paymaster's owner (it deployed it in setUp).
        paymaster.setSponsorPersonal(w1, true);

        handler.validate(1, 100_000, 100_000, 50_000, GOOD_POST_GAS, 50_000, GOOD_FEE, GOOD_MAX_COST, 4);
        assertFalse(
            handler.lastValidateSigFail(),
            "B6 isolation: the ONLY thing that changed was sponsorPersonal, so the SAME self-targeted op must now be admitted"
        );
    }

    /// @dev M6c (must PASS, no false positive): the exact sequence the first-draft predicate
    ///      got wrong — spend under a HIGH ceiling (no latch, still sponsored), then LOWER the
    ///      ceiling below the already-accrued `spentToday`. `setGlobalDailyCapCeiling`'s own NatSpec
    ///      says lowering the ceiling deliberately does NOT reclamp per-wallet storage, so this is
    ///      legitimate, unlatched state — `invariant_A2b` must NOT fire on it, because it recorded
    ///      the threshold at the time of the LAST postOp (under the high ceiling), not the current
    ///      one. Directed rather than left to the fuzzer, so this direction is proven on every run.
    function test_loweringCeilingAfterSpendDoesNotFalsePositiveA2b() public {
        address w = address(0xAA02);
        vm.startPrank(policyManager);
        paymaster.setDailyCap(w, 1e14);
        paymaster.setSponsored(w, true);
        vm.stopPrank();
        paymaster.setGlobalDailyCapCeiling(1e17); // high ceiling — well above dailyCap

        // Drive this through the HANDLER's own postOp wrapper so ghostLatchCapAtPostOp is recorded
        // exactly like the fuzz run would record it (min(1e14, 1e17) == 1e14).
        handler.postOp(1, 6e13); // wallets[1 % 3] == wallets[1] == w; under the 1e14 cap, no latch
        assertTrue(paymaster.getPolicy(w).sponsored, "precondition: not latched under the high ceiling");
        assertEq(handler.ghostLatchCapAtPostOp(w), 1e14, "precondition: recorded threshold is dailyCap, not the ceiling");

        // Now lower the ceiling BELOW the already-accrued spentToday. Per-wallet storage is
        // untouched (as-designed), so on-chain spentToday (6e13) now exceeds the CURRENT ceiling
        // (1e13) even though the wallet is correctly still sponsored.
        paymaster.setGlobalDailyCapCeiling(1e13);
        assertTrue(paymaster.getPolicy(w).spentToday > paymaster.globalDailyCapCeiling(), "precondition: current ceiling now below spentToday");
        assertTrue(paymaster.getPolicy(w).sponsored, "precondition: still legitimately sponsored");

        // The recorded-input predicate must not care — it never re-reads the CURRENT ceiling.
        invariant_A2b_latchFiresAtTheRecordedThreshold();
    }

    /// @dev The exact sequence that fails on
    ///      ORDINARY runs, not just unlucky seeds — `setUp()` has no `vm.warp`, so
    ///      `block.timestamp / 1 days == 0` for the whole first simulated day, and `lastSpentDay`
    ///      after a VIP grant is ALSO 0, so `invariant_A3`'s day guard is TAKEN here, not skipped.
    ///      postOp (accrue) -> setSponsoredUnlimited(true) (VIP grant, item 5 resets the on-chain
    ///      counters) -> the exact predicate `invariant_A3` evaluates must still hold. Without a
    ///      matching ghost reset in the handler's `setSponsoredUnlimited` wrapper, `ghostSpent[w]`
    ///      stays stale at the pre-grant value while on-chain `spentToday` is freshly 0, and
    ///      `assertGe(0, staleValue)` fails.
    function test_vipGrantAtDayZeroResetsGhostSpendTracking() public {
        address w = address(0xAA01); // seeded in setUp: dailyCap 1e14, sponsored
        assertEq(block.timestamp / 1 days, 0, "precondition: still simulated day 0");

        handler.postOp(0, 5e13); // wallets[0 % 3] == wallets[0] == w
        assertEq(paymaster.getPolicy(w).spentToday, 5e13, "precondition: spend accrued");
        assertEq(handler.ghostSpent(w), 5e13, "precondition: ghost tracked the spend");

        handler.setSponsoredUnlimited(0, true); // grants VIP; item 5 resets spentToday/lastSpentDay
        assertEq(paymaster.getPolicy(w).spentToday, 0, "item 5: the VIP grant must reset spentToday");
        assertTrue(paymaster.getPolicy(w).vip, "sanity: the grant actually took (dailyCap was non-zero)");

        // The exact predicate invariant_A3 evaluates.
        VerifyingPaymaster.WalletPolicy memory p = paymaster.getPolicy(w);
        if (p.lastSpentDay == handler.ghostDay(w)) {
            assertGe(p.spentToday, handler.ghostSpent(w), "A3: a VIP grant looked like spend went backwards");
        }
    }
}
