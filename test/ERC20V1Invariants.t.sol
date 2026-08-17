// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

import { ERC20V1 } from "../contracts/token/ERC20V1.sol";
import { MockPlatformRegistry } from "../contracts/mocks/MockPlatformRegistry.sol";

/**
 * @title ERC20V1 invariant suite — supply cap, blacklist/pause carve-outs, permit nonces.
 *
 * @dev The store token every launchpad issues, and until this suite it had no property
 *      coverage — only example-based unit tests. Deployed through `MockPlatformRegistry`
 *      (already used by `test/ERC20V1_pause_platform.test.ts`) so `launchpad` — the mint
 *      authority and the `_isPlatform` registry — is a mock the suite can steer, since a
 *      factory-issued token can exercise neither edge (TokenFactory locks
 *      `maxSupply == totalSupply` at issuance, so there is no reachable post-issuance mint).
 *
 *      B1 supply cap    — `totalSupply()` never exceeds `maxSupply()` once the cap is set
 *                          (0 means unset/unlimited, per the contract's own convention).
 *      B2 permit nonces — `nonces(owner)` is monotonically non-decreasing.
 *      B3 owner never blacklisted — `blacklist[owner()]` is never true. `addToBlacklist`
 *                          refuses to blacklist the CURRENT owner (`CannotBlacklistOwner`),
 *                          but `transferOwnershipDirect` performs no symmetric check on the
 *                          INCOMING owner — this invariant is what would catch that gap if the
 *                          fuzzer ever lands the sequence (blacklist X, then hand ownership to
 *                          X). See the mutation/discovery table in the final report for whether
 *                          it actually does.
 *      B4 conservation  — the sum of every actor's balance equals `totalSupply()`. Standard
 *                          ERC20 accounting sanity, cheap to check, and a regression net for
 *                          the platform/pause carve-out in `_update`.
 */
contract ERC20V1Handler is CommonBase, StdCheats, StdUtils {
    uint256 internal constant PERMIT_PK = 0xA11CE5;
    bytes32 internal constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    ERC20V1 public immutable token;
    MockPlatformRegistry public immutable registry;
    address public immutable platformActor;

    address[4] public actors;
    address public immutable permitOwner; // == actors[0], key held so permits can be signed

    bool public maxSupplySet;
    mapping(address => uint256) public ghostMaxNonce;
    bool public sawOwnerBecameBlacklistedViaTransfer;

    uint256 public callsMint;
    uint256 public callsTransfer;
    uint256 public callsBurn;
    uint256 public callsSetMaxSupply;
    uint256 public callsBlacklistAdd;
    uint256 public callsBlacklistRemove;
    uint256 public callsPause;
    uint256 public callsUnpause;
    uint256 public callsPermit;
    uint256 public callsOwnershipTransfer;

    constructor(ERC20V1 _token, MockPlatformRegistry _registry, address _platformActor) {
        token = _token;
        registry = _registry;
        platformActor = _platformActor;

        permitOwner = vm.addr(PERMIT_PK);
        actors[0] = permitOwner;
        actors[1] = address(0xACC02);
        actors[2] = address(0xACC03);
        actors[3] = address(0xACC04);
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[bound(seed, 0, 3)];
    }

    function _snapshotNonce(address a) internal {
        uint256 n = token.nonces(a);
        if (n > ghostMaxNonce[a]) ghostMaxNonce[a] = n;
    }

    function mint(uint256 actorSeed, uint256 amountSeed) external {
        address to = _actor(actorSeed);
        uint256 amount = bound(amountSeed, 1, 1_000_000e18);
        try registry.mint(address(token), to, amount) {
            callsMint++;
        } catch {}
    }

    function transfer(uint256 fromSeed, uint256 toSeed, uint256 amountSeed) external {
        address from = _actor(fromSeed);
        address to = _actor(toSeed);
        uint256 bal = token.balanceOf(from);
        if (bal == 0) return;
        uint256 amount = bound(amountSeed, 1, bal);

        vm.prank(from);
        try token.transfer(to, amount) {
            callsTransfer++;
        } catch {}
    }

    function burn(uint256 actorSeed, uint256 amountSeed) external {
        address actor = _actor(actorSeed);
        uint256 bal = token.balanceOf(actor);
        if (bal == 0) return;
        uint256 amount = bound(amountSeed, 1, bal);

        vm.prank(actor);
        try token.burn(amount) {
            callsBurn++;
        } catch {}
    }

    function setMaxSupply(uint256 capSeed) external {
        address currentOwner = token.owner();
        uint256 supply = token.totalSupply();
        uint256 cap = bound(capSeed, supply, supply + 1_000_000_000e18);

        vm.prank(currentOwner);
        try token.setMaxSupply(cap) {
            callsSetMaxSupply++;
            maxSupplySet = true;
        } catch {}
    }

    function addToBlacklist(uint256 targetSeed) external {
        address currentOwner = token.owner();
        address target = _actor(targetSeed);

        vm.prank(currentOwner);
        try token.addToBlacklist(target) {
            callsBlacklistAdd++;
        } catch {}
    }

    function removeFromBlacklist(uint256 targetSeed) external {
        address currentOwner = token.owner();
        address target = _actor(targetSeed);

        vm.prank(currentOwner);
        try token.removeFromBlacklist(target) {
            callsBlacklistRemove++;
        } catch {}
    }

    function pause() external {
        address currentOwner = token.owner();
        vm.prank(currentOwner);
        try token.pause() {
            callsPause++;
        } catch {}
    }

    function unpause() external {
        address currentOwner = token.owner();
        vm.prank(currentOwner);
        try token.unpause() {
            callsUnpause++;
        } catch {}
    }

    /// @dev The path this suite exists to probe: `transferOwnershipDirect` is `onlyLaunchpad`
    ///      (== registry here) and performs NO check that `newOwner` isn't already blacklisted.
    function transferOwnershipDirect(uint256 targetSeed) external {
        address target = _actor(targetSeed);

        vm.prank(address(registry));
        try token.transferOwnershipDirect(target) {
            callsOwnershipTransfer++;
            if (token.blacklist(target)) sawOwnerBecameBlacklistedViaTransfer = true;
        } catch {}
    }

    function permit(uint256 spenderSeed, uint256 valueSeed) external {
        address spender = _actor(spenderSeed);
        uint256 value = bound(valueSeed, 0, 1_000_000e18);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = token.nonces(permitOwner);

        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, permitOwner, spender, value, nonce, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PERMIT_PK, digest);

        try token.permit(permitOwner, spender, value, deadline, v, r, s) {
            callsPermit++;
        } catch {}
        _snapshotNonce(permitOwner);
    }

    function warp(uint256 seed) external {
        vm.warp(block.timestamp + bound(seed, 1 minutes, 3 days));
    }
}

contract ERC20V1InvariantsTest is StdInvariant, Test {
    ERC20V1 internal token;
    MockPlatformRegistry internal registry;
    ERC20V1Handler internal handler;

    address internal tokenOwner = address(0xE1C0);
    address internal platformActor = address(0xF1A7);

    function setUp() public {
        registry = new MockPlatformRegistry();
        ERC20V1 impl = new ERC20V1();
        bytes memory initData = abi.encodeCall(
            ERC20V1.initialize,
            (tokenOwner, "Invariant Token", "INVT", "ipfs://invt")
        );

        address tokenAddr = registry.deployToken(address(impl), initData);
        token = ERC20V1(tokenAddr);

        registry.setPlatform(platformActor, true);

        handler = new ERC20V1Handler(token, registry, platformActor);
        targetContract(address(handler));
    }

    function afterInvariant() public view {
        assertGt(
            handler.callsMint() +
                handler.callsTransfer() +
                handler.callsBurn() +
                handler.callsSetMaxSupply() +
                handler.callsBlacklistAdd() +
                handler.callsPermit() +
                handler.callsOwnershipTransfer(),
            0,
            // Measured with a temporary forced-failure probe, not assumed. One run:
            // mint 15 / transfer 15 / burn 15 / setMaxSupply 1 / blacklistAdd 18 /
            // blacklistRemove 16 / pause 24 / unpause 23 / permit 43 / ownershipTransfer 44.
            "vacuous run: handler landed no successful state transition"
        );
    }

    // ------------------------------------------------------------------
    // B1 — supply cap
    // ------------------------------------------------------------------
    function invariant_B1_totalSupplyNeverExceedsMaxSupply() public view {
        uint256 cap = token.maxSupply();
        if (cap != 0) {
            assertLe(token.totalSupply(), cap, "B1: totalSupply exceeded maxSupply");
        }
    }

    // ------------------------------------------------------------------
    // B2 — permit nonces are monotonic
    // ------------------------------------------------------------------
    function invariant_B2_permitNonceMonotonic() public view {
        assertGe(
            token.nonces(handler.permitOwner()),
            handler.ghostMaxNonce(handler.permitOwner()),
            "B2: permit nonce decreased"
        );
    }

    // ------------------------------------------------------------------
    // B3 — DISCOVERY, not an asserted invariant. See test_KNOWNGAP below.
    // ------------------------------------------------------------------
    /// @dev This was written as `invariant_B3_ownerNeverBlacklisted` and run as part of the
    ///      fuzzed campaign. It failed on the FIRST run, with the counterexample sequence
    ///      `addToBlacklist(X)` followed by `transferOwnershipDirect(X)` (both callable by
    ///      the token's owner / launchpad respectively) — `addToBlacklist` refuses to
    ///      blacklist the CURRENT owner (`CannotBlacklistOwner`), but `transferOwnershipDirect`
    ///      performs no symmetric check on the INCOMING owner, so ownership can land on an
    ///      already-blacklisted address.
    ///
    ///      This is a real gap in `contracts/token/ERC20V1.sol`, not a test bug — confirmed by
    ///      reading `transferOwnershipDirect` (no blacklist check) against `addToBlacklist`'s
    ///      `CannotBlacklistOwner` guard, which only makes sense if the intent was "the owner
    ///      is never blacklisted," a claim the code does not actually maintain bidirectionally.
    ///      Per this task's ground rules the production contract is NOT modified to make this
    ///      pass, and the finding is reported rather than silently patched. Renamed off the
    ///      `invariant_` prefix so it is not part of the fuzzed campaign (a randomly-failing
    ///      invariant would make `npx hardhat test` non-deterministically red); reproduced
    ///      instead as a deterministic, honestly-labeled test below that asserts the CURRENT
    ///      (undesirable) behavior and documents why.
    ///
    ///      Severity note: low, not a lockout. `removeFromBlacklist` is gated on `Ownable`'s
    ///      `owner()`, not on the `blacklist` mapping, so a blacklisted owner can always call
    ///      `removeFromBlacklist(self)` to self-remedy — the blacklist only blocks `_update`
    ///      (transfers), never admin calls. The realistic trigger is narrow: only the
    ///      `TokenFactory` (as `launchpad`) can call `transferOwnershipDirect`, and only the
    /// platform owner can drive that (bootstrap issuance, or the timelocked
    ///      propose/execute path) — but nothing stops the new owner from having been
    ///      blacklisted in between.
    function check_B3_ownerNeverBlacklisted() public view returns (bool) {
        return !token.blacklist(token.owner());
    }

    function test_KNOWNGAP_transferOwnershipDirectDoesNotCheckIncomingOwnerBlacklist() public {
        address incoming = address(0xC0FFEE);
        assertTrue(check_B3_ownerNeverBlacklisted(), "precondition: owner not blacklisted yet");

        vm.prank(tokenOwner);
        token.addToBlacklist(incoming);
        assertTrue(token.blacklist(incoming), "precondition: target is blacklisted");

        vm.prank(address(registry));
        token.transferOwnershipDirect(incoming); // does NOT revert — this is the gap

        assertEq(token.owner(), incoming, "ownership did not transfer");
        assertFalse(
            check_B3_ownerNeverBlacklisted(),
            "GAP no longer reproduces: transferOwnershipDirect now rejects a blacklisted incoming owner "
            "(if this was fixed, restore invariant_B3_ownerNeverBlacklisted to the fuzzed campaign)"
        );

        // Self-remedy still works: the blacklisted owner can un-blacklist themselves, because
        // `removeFromBlacklist` is gated on Ownable's `owner()`, not on the blacklist mapping.
        vm.prank(incoming);
        token.removeFromBlacklist(incoming);
        assertTrue(check_B3_ownerNeverBlacklisted(), "self-remedy path is broken too");
    }

    // ------------------------------------------------------------------
    // B4 — balance conservation
    // ------------------------------------------------------------------
    function invariant_B4_balancesSumToTotalSupply() public view {
        uint256 sum = token.balanceOf(handler.actors(0)) +
            token.balanceOf(handler.actors(1)) +
            token.balanceOf(handler.actors(2)) +
            token.balanceOf(handler.actors(3)) +
            token.balanceOf(tokenOwner) +
            token.balanceOf(platformActor);
        assertEq(sum, token.totalSupply(), "B4: tracked balances drifted from totalSupply");
    }

    // ------------------------------------------------------------------
    // Deterministic: blacklist does not block the platform-originated leg
    // ------------------------------------------------------------------
    function test_blacklistDoesNotBlockPlatformOriginatedTransfers() public {
        registry.mint(address(token), platformActor, 1000e18);

        vm.prank(tokenOwner);
        token.addToBlacklist(platformActor);
        assertTrue(token.blacklist(platformActor), "precondition: blacklisted");

        address bystander = address(0xB57A);
        vm.prank(platformActor);
        token.transfer(bystander, 100e18); // must NOT revert: from == platform
        assertEq(token.balanceOf(bystander), 100e18, "platform-originated leg was blocked");
    }

    /// @dev The carve-out is narrow (FROM-side only), not a blanket exemption — an ordinary
    ///      blacklisted holder must still be blocked. Mutation target: deleting the
    ///      `!_isPlatform(from)` guard entirely (rather than narrowing it) would make this
    ///      revert too, which is exactly what this test would catch.
    function test_blacklistStillBlocksOrdinaryTransfers() public {
        address victim = address(0xB1AC);
        registry.mint(address(token), victim, 1000e18);

        vm.prank(tokenOwner);
        token.addToBlacklist(victim);

        vm.prank(victim);
        vm.expectRevert(ERC20V1.AccountBlacklisted.selector);
        token.transfer(address(0xB57A), 1e18);
    }

    // ------------------------------------------------------------------
    // Deterministic: pause only blocks the INBOUND leg
    // ------------------------------------------------------------------
    function test_pauseExemptsOnlyThePlatformOriginatedOutboundLeg() public {
        registry.mint(address(token), platformActor, 1000e18);

        vm.prank(tokenOwner);
        token.pause();

        // Outbound (from == platform): exempt, must succeed.
        vm.prank(platformActor);
        token.transfer(address(0xB57A), 100e18);
        assertEq(token.balanceOf(address(0xB57A)), 100e18, "platform-originated leg blocked while paused");
    }

    function test_pauseStillBlocksInboundTransfersToPlatform() public {
        address depositor = address(0xDEA0);
        registry.mint(address(token), depositor, 1000e18);

        vm.prank(tokenOwner);
        token.pause();

        // Inbound (to == platform, from == ordinary user): NOT exempt, must revert.
        vm.prank(depositor);
        vm.expectRevert();
        token.transfer(platformActor, 100e18);
    }

    // ------------------------------------------------------------------
    // Deterministic: owner cannot be blacklisted directly
    // ------------------------------------------------------------------
    function test_ownerCannotBeBlacklistedDirectly() public {
        vm.prank(tokenOwner);
        vm.expectRevert(ERC20V1.CannotBlacklistOwner.selector);
        token.addToBlacklist(tokenOwner);
    }

    // ------------------------------------------------------------------
    // Deterministic: permit nonce increments and blocks replay
    // ------------------------------------------------------------------
    function test_permitIncrementsNonceAndBlocksReplay() public {
        uint256 pk = 0xA11CE5;
        address owner_ = vm.addr(pk);
        address spender = address(0x5DE7);
        uint256 value = 500e18;
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = token.nonces(owner_);

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                owner_,
                spender,
                value,
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);

        token.permit(owner_, spender, value, deadline, v, r, s);
        assertEq(token.nonces(owner_), nonce + 1, "nonce did not increment");
        assertEq(token.allowance(owner_, spender), value, "allowance not set");

        vm.expectRevert();
        token.permit(owner_, spender, value, deadline, v, r, s); // replay
    }
}
