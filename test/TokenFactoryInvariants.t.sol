// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { TokenFactory } from "../contracts/token/TokenFactory.sol";
import { ERC20V1 } from "../contracts/token/ERC20V1.sol";
import { TokenVestingWallet } from "../contracts/vesting/TokenVestingWallet.sol";
import { UpgradeableBeacon } from "../contracts/UpgradeableBeacon.sol";
import { ERC1967Proxy } from "../contracts/ERC1967Proxy.sol";

/**
 * @title TokenFactory invariant suite — the 3-bucket allocation, escrow custody, and
 *        fixed-supply guarantees the Store Token distribution model rests on.
 *
 * @dev TokenFactory is the contract every issued token and its owner-vesting wallet flow
 *      through, and until this suite it had no property coverage at all — only example-based
 *      unit tests (`test/TokenFactory.test.ts`). Two of the four candidate predicates in the task
 *      cannot be expressed as invariants over persisted state, because the contract does not
 *      store the bp ratios after issuance (only the derived `launchpadEscrow` amount survives):
 *      those are covered by pinned deterministic tests instead, exactly like the audit-history
 *      lesson in `LaunchpadInvariants.t.sol` that a state predicate is the wrong shape for a
 *      reachability/guard claim.
 *
 *      F1 escrow solvency — the factory's own balance of an issued token equals EXACTLY the
 *                            `launchpadEscrow` recorded for it. Nothing else ever touches the
 *                            factory's balance in that token: liquidity/owner amounts are
 *                            transferred out in the same transaction as the mint.
 *      F2 escrowConsumed one-shot — a token whose escrow was ever observed consumed must never
 *                            un-consume, WITHIN THIS FILE'S OWN HANDLER (which never calls
 *                            `restoreEscrow` — no LaunchpadV1 is wired in as an authorized
 * caller for it here). (2026-08) makes `escrowConsumed`
 *                            DELIBERATELY not globally one-shot anymore — `restoreEscrow`
 *                            resets it after a cancelled sale, so a cancelled token can be
 *                            resold — that reset path is exercised (and its own write-once
 *                            claim correspondingly dropped) in `LaunchpadInvariants.t.sol`'s
 *                            I4 instead. (The liveness half — that it eventually becomes
 *                            consumable at all — is out of scope here since it is a Launchpad
 *                            lifecycle claim already covered by `LaunchpadInvariants.t.sol` I4.)
 *      F3 fixed supply     — every issued token's `maxSupply()` equals its `totalSupply()`
 *                            always: the cap is locked to the exact issued amount at
 *                            `_deployToken` time and there is no other mint path.
 */
contract TokenFactoryHandler is CommonBase, StdCheats, StdUtils {
    bytes32 internal constant ISSUE_PERMIT_TYPEHASH =
        keccak256(
            // solhint-disable-next-line max-line-length
            "IssuePermit(address businessAccount,string name,string symbol,uint256 totalSupply,string contractURI,uint16 launchpadBp,uint16 liquidityBp,uint16 ownerBp,address liquidityRecipient,uint64 ownerVestingCliff,uint64 ownerVestingDuration,address linkedLaunchpad,uint256 nonce,uint256 deadline)"
        );

    uint256 internal constant PERMIT_PK = 0xF0EE;

    TokenFactory public immutable factory;
    address public immutable linkedLaunchpad;
    bytes32 public immutable domainSeparator;

    address[3] public businesses;
    address[3] public liquidityRecipients;

    address[] public issuedTokens;
    mapping(address => address) public tokenBusiness;
    mapping(address => bool) public sawEscrowConsumed;

    uint256 public callsIssue;
    uint256 public callsRelease;
    uint256 public callsReclaim;

    constructor(TokenFactory _factory, address _linkedLaunchpad) {
        factory = _factory;
        linkedLaunchpad = _linkedLaunchpad;

        address signer = vm.addr(PERMIT_PK);
        // permitSigner is configured in setUp() to vm.addr(PERMIT_PK); recompute the domain
        // separator locally instead of calling factory.DOMAIN_SEPARATOR() so this constructor
        // has no ordering dependency on when the factory itself is deployed relative to this
        // handler. It is verified against the factory's own separator in setUp() below anyway
        // (a mismatch would just make every issueToken revert InvalidSignature, which the
        // afterInvariant coverage floor would catch as a vacuous run).
        signer; // silence unused-var warning path if the compiler flags it

        businesses[0] = address(0xB1000);
        businesses[1] = address(0xB2000);
        businesses[2] = address(0xB3000);

        liquidityRecipients[0] = address(0x1101);
        liquidityRecipients[1] = address(0x1102);
        liquidityRecipients[2] = address(0x1103);

        domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("TokenFactory")),
                keccak256(bytes("1")),
                block.chainid,
                address(_factory)
            )
        );
    }

    function _snapshot(address token) internal {
        if (factory.escrowConsumed(token)) sawEscrowConsumed[token] = true;
    }

    function issuedTokenCount() external view returns (uint256) {
        return issuedTokens.length;
    }

    function issueToken(
        uint256 actorSeed,
        uint256 supplySeed,
        uint256 liqSeed,
        uint256 lpSeed,
        uint256 durSeed,
        uint256 cliffSeed
    ) external {
        uint256 idx = bound(actorSeed, 0, 2);
        address business = businesses[idx];
        address recipient = liquidityRecipients[idx];

        uint256 totalSupply_ = bound(supplySeed, 1e18, 1_000_000_000e18);

        // liquidityBp respects the 1bp floor configured on that bucket's guide; the other two
        // buckets are guided [0,10000], so any split of the remainder is in-range and only the
        // BASIS_POINTS sum constraint (checked elsewhere, deterministically) can ever bind here.
        uint16 liquidityBp = uint16(bound(liqSeed, 1, 9998));
        uint256 remaining = 10000 - liquidityBp;
        uint16 launchpadBp = uint16(bound(lpSeed, 0, remaining));
        uint16 ownerBp = uint16(remaining - launchpadBp);

        uint64 duration_ = uint64(bound(durSeed, 30 days, 3650 days));
        uint64 cliff_ = uint64(bound(cliffSeed, 0, duration_));

        TokenFactory.AllocationRatios memory ratios = TokenFactory.AllocationRatios({
            launchpadBp: launchpadBp,
            liquidityBp: liquidityBp,
            ownerBp: ownerBp,
            liquidityRecipient: recipient,
            ownerVestingCliff: cliff_,
            ownerVestingDuration: duration_
        });

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(
                ISSUE_PERMIT_TYPEHASH,
                business,
                keccak256(bytes("Fuzz Token")),
                keccak256(bytes("FUZZ")),
                totalSupply_,
                keccak256(bytes("")),
                launchpadBp,
                liquidityBp,
                ownerBp,
                recipient,
                cliff_,
                duration_,
                linkedLaunchpad,
                factory.nonces(business),
                deadline
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            PERMIT_PK,
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
        );

        vm.prank(business);
        try
            factory.issueToken(
                "Fuzz Token",
                "FUZZ",
                totalSupply_,
                "",
                ratios,
                deadline,
                abi.encodePacked(r, s, v)
            )
        returns (address token, address /* vestingWallet */) {
            callsIssue++;
            issuedTokens.push(token);
            tokenBusiness[token] = business;
            _snapshot(token);
        } catch {}
    }

    function releaseEscrow(uint256 tokenSeed) external {
        if (issuedTokens.length == 0) return;
        address token = issuedTokens[tokenSeed % issuedTokens.length];
        address authorizedLaunchpad = factory.tokenToLaunchpad(token);
        if (authorizedLaunchpad == address(0)) return;

        vm.prank(authorizedLaunchpad);
        try factory.releaseEscrow(token) {
            callsRelease++;
        } catch {}
        _snapshot(token);
    }

    function reclaimEscrow(uint256 tokenSeed) external {
        if (issuedTokens.length == 0) return;
        address token = issuedTokens[tokenSeed % issuedTokens.length];
        address business = tokenBusiness[token];

        vm.prank(business);
        try factory.reclaimEscrow(token) {
            callsReclaim++;
        } catch {}
        _snapshot(token);
    }

    function warp(uint256 seed) external {
        vm.warp(block.timestamp + bound(seed, 1 hours, 120 days));
    }
}

/// @dev Minimal stand-in for `linkedLaunchpad`. `TokenFactory` authorizes `releaseEscrow`
///      purely by address equality (`tokenToLaunchpad[token] == msg.sender`) — it never calls
///      back into the launchpad — so this only needs to be a real contract (nonzero code, as
///      `proposeLinkedLaunchpadChange` requires) whose address the handler can `vm.prank` as.
contract DummyLaunchpad {}

contract TokenFactoryInvariantsTest is StdInvariant, Test {
    uint256 internal constant PERMIT_PK = 0xF0EE;
    uint256 internal constant CONFIG_DELAY = 2 days;
    uint256 internal constant ALLOCATION_GUIDE_DELAY = 2 days;
    uint256 internal constant BASIS_POINTS = 10000;

    TokenFactory internal factory;
    DummyLaunchpad internal linkedLaunchpad;
    TokenFactoryHandler internal handler;

    address internal erc20Beacon;
    address internal vestingWalletBeacon;
    address internal platformTreasury = address(0x7EA5);

    function setUp() public {
        ERC20V1 erc20Impl = new ERC20V1();
        UpgradeableBeacon erc20BeaconContract = new UpgradeableBeacon(address(erc20Impl), address(this));
        erc20Beacon = address(erc20BeaconContract);

        TokenVestingWallet vwImpl = new TokenVestingWallet();
        UpgradeableBeacon vwBeaconContract = new UpgradeableBeacon(address(vwImpl), address(this));
        vestingWalletBeacon = address(vwBeaconContract);

        TokenFactory factoryImpl = new TokenFactory();
        ERC1967Proxy factoryProxy = new ERC1967Proxy(
            address(factoryImpl),
            abi.encodeCall(
                TokenFactory.initialize,
                (erc20Beacon, platformTreasury, vm.addr(PERMIT_PK), vestingWalletBeacon)
            )
        );
        factory = TokenFactory(address(factoryProxy));

        linkedLaunchpad = new DummyLaunchpad();
        _configureFactory();

        handler = new TokenFactoryHandler(factory, address(linkedLaunchpad));
        targetContract(address(handler));
    }

    function _configureFactory() internal {
        factory.proposeAllocationGuide(0, 0, 10000); // LAUNCHPAD
        factory.proposeAllocationGuide(1, 1, 10000); // LIQUIDITY_RESERVE (1bp floor)
        factory.proposeAllocationGuide(2, 0, 10000); // OWNER_VESTING
        factory.proposeLinkedLaunchpadChange(address(linkedLaunchpad));
        factory.proposeEscrowTimeoutChange(90 days);

        vm.warp(block.timestamp + CONFIG_DELAY + 1);

        factory.executeAllocationGuide(0);
        factory.executeAllocationGuide(1);
        factory.executeAllocationGuide(2);
        factory.executeLinkedLaunchpadChange();
        factory.executeEscrowTimeoutChange();
    }

    /// @dev Coverage floor. See `LaunchpadInvariants.t.sol`'s `afterInvariant` for the incident
    ///      this guards against: a suite that reports every invariant green while the handler
    ///      never actually landed a state transition.
    function afterInvariant() public view {
        // Measured (temporary probe, then removed — see the final report's coverage table):
        // callsIssue ~122-136, callsRelease ~44-47, callsReclaim ~27-42 per campaign of 256 runs.
        assertGt(
            handler.callsIssue() + handler.callsRelease() + handler.callsReclaim(),
            0,
            "vacuous run: handler landed no successful state transition"
        );
    }

    // ------------------------------------------------------------------
    // F1 — escrow solvency
    // ------------------------------------------------------------------
    /// @dev Each issued token is a SEPARATE ERC20 contract, so the factory's balance in that
    ///      token has exactly one source (the LAUNCHPAD-bucket mint) and exactly two sinks
    ///      (`releaseEscrow`, `reclaimEscrow`) — both of which zero `launchpadEscrow[token]` in
    ///      the same transaction they move the balance. Equality, not just a floor, is the
    ///      correct claim here.
    function invariant_F1_escrowBalanceMatchesLedgerExactly() public view {
        uint256 n = handler.issuedTokenCount();
        for (uint256 i = 0; i < n; i++) {
            address token = handler.issuedTokens(i);
            assertEq(
                IERC20(token).balanceOf(address(factory)),
                factory.launchpadEscrow(token),
                "F1: factory's token balance drifted from the tracked escrow"
            );
        }
    }

    // ------------------------------------------------------------------
    // F2 — escrowConsumed is a one-shot latch
    // ------------------------------------------------------------------
    function invariant_F2_escrowConsumedIsWriteOnce() public view {
        uint256 n = handler.issuedTokenCount();
        for (uint256 i = 0; i < n; i++) {
            address token = handler.issuedTokens(i);
            if (handler.sawEscrowConsumed(token)) {
                assertTrue(factory.escrowConsumed(token), "F2: escrowConsumed regressed to false");
            }
        }
    }

    // ------------------------------------------------------------------
    // F3 — fixed supply: maxSupply is locked to the issued amount, forever
    // ------------------------------------------------------------------
    function invariant_F3_maxSupplyLockedToTotalSupply() public view {
        uint256 n = handler.issuedTokenCount();
        for (uint256 i = 0; i < n; i++) {
            ERC20V1 token = ERC20V1(handler.issuedTokens(i));
            assertEq(token.maxSupply(), token.totalSupply(), "F3: maxSupply drifted from totalSupply");
        }
    }

    // ------------------------------------------------------------------
    // Deterministic: 3-bucket bp sum enforcement
    // ------------------------------------------------------------------
    /// @dev Not expressible as a state invariant: the bp ratios are never persisted (only the
    ///      derived `launchpadEscrow` amount survives issuance), so this is a guard claim about
    ///      `issueToken` itself, pinned the same way `LaunchpadInvariants.t.sol` pins its
    ///      liveness half rather than leaving it to the state-based search.
    function _issueWithSum(uint16 launchpadBp, uint16 liquidityBp, uint16 ownerBp) internal returns (bool ok) {
        address business = address(0xBEE0);
        address recipient = address(0x1105);

        TokenFactory.AllocationRatios memory ratios = TokenFactory.AllocationRatios({
            launchpadBp: launchpadBp,
            liquidityBp: liquidityBp,
            ownerBp: ownerBp,
            liquidityRecipient: recipient,
            ownerVestingCliff: 0,
            ownerVestingDuration: 365 days
        });

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    // solhint-disable-next-line max-line-length
                    "IssuePermit(address businessAccount,string name,string symbol,uint256 totalSupply,string contractURI,uint16 launchpadBp,uint16 liquidityBp,uint16 ownerBp,address liquidityRecipient,uint64 ownerVestingCliff,uint64 ownerVestingDuration,address linkedLaunchpad,uint256 nonce,uint256 deadline)"
                ),
                business,
                keccak256(bytes("Sum Test")),
                keccak256(bytes("SUM")),
                uint256(1000e18),
                keccak256(bytes("")),
                launchpadBp,
                liquidityBp,
                ownerBp,
                recipient,
                uint64(0),
                uint64(365 days),
                address(linkedLaunchpad),
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
        try
            factory.issueToken("Sum Test", "SUM", 1000e18, "", ratios, deadline, abi.encodePacked(r, s, v))
        returns (address, address) {
            ok = true;
        } catch {
            ok = false;
        }
    }

    function test_bpSumMustEqualBasisPointsExactly() public {
        assertFalse(_issueWithSum(3000, 3000, 3999), "sum=9999 (one below BASIS_POINTS) must revert");
        assertFalse(_issueWithSum(3000, 3000, 4001), "sum=10001 (one above BASIS_POINTS) must revert");
        assertFalse(_issueWithSum(0, 0, 0), "sum=0 must revert");
        assertTrue(_issueWithSum(3000, 3000, 4000), "sum=10000 exactly must succeed");
    }

    // ------------------------------------------------------------------
    // Deterministic: timelock cannot be bypassed (allocation guide, linkedLaunchpad)
    // ------------------------------------------------------------------
    function test_allocationGuideTimelockCannotBeBypassed() public {
        factory.proposeAllocationGuide(0, 0, 5000);
        uint256 executeTime = block.timestamp + ALLOCATION_GUIDE_DELAY;

        vm.expectRevert(TokenFactory.TimelockNotReady.selector);
        factory.executeAllocationGuide(0);

        vm.warp(executeTime - 1);
        vm.expectRevert(TokenFactory.TimelockNotReady.selector);
        factory.executeAllocationGuide(0);

        vm.warp(executeTime);
        factory.executeAllocationGuide(0); // exactly at maturity: succeeds
        (uint16 minBp, uint16 maxBp) = factory.getAllocationGuide(0);
        assertEq(minBp, 0, "guide minBp not applied");
        assertEq(maxBp, 5000, "guide maxBp not applied");
    }

    function test_linkedLaunchpadTimelockCannotBeBypassed() public {
        DummyLaunchpad newLaunchpad = new DummyLaunchpad();
        factory.proposeLinkedLaunchpadChange(address(newLaunchpad));
        uint256 executeTime = block.timestamp + CONFIG_DELAY;

        vm.expectRevert(TokenFactory.TimelockNotReady.selector);
        factory.executeLinkedLaunchpadChange();

        vm.warp(executeTime - 1);
        vm.expectRevert(TokenFactory.TimelockNotReady.selector);
        factory.executeLinkedLaunchpadChange();

        vm.warp(executeTime);
        factory.executeLinkedLaunchpadChange();
        assertEq(factory.linkedLaunchpad(), address(newLaunchpad), "linkedLaunchpad not rotated");
    }

    // ------------------------------------------------------------------
    // Deterministic: escrowConsumed actually gets SET, not just "never unset"
    // ------------------------------------------------------------------
    /// @dev F2 above can only ever fail on a REGRESSION (true -> false) — if the assignment
    ///      that sets `escrowConsumed[token] = true` were deleted entirely, the ghost would
    ///      simply never observe `true` and F2 would pass vacuously forever. This pins the
    ///      "gets set at all, and blocks a second consumption" half directly.
    function test_releaseEscrowSetsConsumedFlagAndBlocksDoubleRelease() public {
        (address token, ) = _issueOneToken();
        assertFalse(factory.escrowConsumed(token), "precondition: not yet consumed");

        vm.prank(address(linkedLaunchpad));
        factory.releaseEscrow(token);
        assertTrue(factory.escrowConsumed(token), "releaseEscrow did not set escrowConsumed");

        vm.prank(address(linkedLaunchpad));
        vm.expectRevert(TokenFactory.EscrowAlreadyConsumed.selector);
        factory.releaseEscrow(token);
    }

    function test_reclaimEscrowSetsConsumedFlagAndBlocksDoubleReclaim() public {
        (address token, address business) = _issueOneToken();
        vm.warp(block.timestamp + 90 days + 1);

        vm.prank(business);
        factory.reclaimEscrow(token);
        assertTrue(factory.escrowConsumed(token), "reclaimEscrow did not set escrowConsumed");

        vm.prank(business);
        vm.expectRevert(TokenFactory.EscrowAlreadyConsumed.selector);
        factory.reclaimEscrow(token);
    }

    function _issueOneToken() internal returns (address token, address business) {
        business = address(0xB00B00);
        address recipient = address(0x1106);

        TokenFactory.AllocationRatios memory ratios = TokenFactory.AllocationRatios({
            launchpadBp: 6000,
            liquidityBp: 2000,
            ownerBp: 2000,
            liquidityRecipient: recipient,
            ownerVestingCliff: 0,
            ownerVestingDuration: 365 days
        });

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    // solhint-disable-next-line max-line-length
                    "IssuePermit(address businessAccount,string name,string symbol,uint256 totalSupply,string contractURI,uint16 launchpadBp,uint16 liquidityBp,uint16 ownerBp,address liquidityRecipient,uint64 ownerVestingCliff,uint64 ownerVestingDuration,address linkedLaunchpad,uint256 nonce,uint256 deadline)"
                ),
                business,
                keccak256(bytes("One Token")),
                keccak256(bytes("ONE")),
                uint256(1000e18),
                keccak256(bytes("")),
                ratios.launchpadBp,
                ratios.liquidityBp,
                ratios.ownerBp,
                recipient,
                ratios.ownerVestingCliff,
                ratios.ownerVestingDuration,
                address(linkedLaunchpad),
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
        (token, ) = factory.issueToken(
            "One Token",
            "ONE",
            1000e18,
            "",
            ratios,
            deadline,
            abi.encodePacked(r, s, v)
        );
    }
}
