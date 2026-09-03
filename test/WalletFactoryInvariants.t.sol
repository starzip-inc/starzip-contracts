// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";
import { StdInvariant } from "forge-std/StdInvariant.sol";
import { CommonBase } from "forge-std/Base.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { StdUtils } from "forge-std/StdUtils.sol";

import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { Create2 } from "@openzeppelin/contracts/utils/Create2.sol";

import { StarzipWallet } from "../contracts/wallet/StarzipWallet.sol";
import { StarzipWalletFactory } from "../contracts/wallet/StarzipWalletFactory.sol";
import { MockEntryPoint } from "../contracts/mocks/MockEntryPoint.sol";
import { ERC1967Proxy } from "../contracts/ERC1967Proxy.sol";

/**
 * @title StarzipWallet / Factory invariants — address prediction, idempotency, upgrade staging.
 *
 * @dev The factory's `accountImplementation` is immutable and recovery is now just "have a second
 *      owner" (no guardian, no on-chain recovery protocol — see StarzipWallet.sol's contract-level
 *      NatSpec), so this is the part of the system that cannot be repaired after users are
 *      onboarded. Both contracts were audited and remediated; neither had any property coverage.
 *
 *      F1 prediction     — `getAddress` must equal what `createAccount` produces, always. A drift
 *                          here means counterfactual addresses (which users fund BEFORE deployment)
 *                          point somewhere the factory will never deploy.
 *      F2 idempotency    — a second `createAccount` returns the same account and must NOT
 *                          re-initialize it. Re-initialization would silently reset the owner set
 *                          of a live wallet from an unauthenticated call.
 *      F3 implementation — every created account points at the factory's immutable implementation.
 *      W1 staging pair   — `pendingImplementation` and `upgradeRequestedAt` are set and cleared
 *                          together; a half-set staging is a stuck or forgeable upgrade.
 *      W2 owner-set churn — adding an owner cancels any pending upgrade (incident response).
 */
contract WalletFactoryHandler is CommonBase, StdCheats, StdUtils {
    StarzipWalletFactory public immutable factory;
    address public immutable altImplementation;
    address public immutable secondImplementation;

    address[] public created;
    mapping(address => bool) public isCreated;

    /// Creation parameters, kept so F1 can re-derive the prediction instead of assuming it.
    /// V2: `initialize` now takes the FULL initial owner set, not
    /// one `bytes firstOwner` — renamed and retyped to match. Solidity's auto-getter for
    /// `mapping(address => bytes[])` indexes a single element rather than returning the whole
    /// array, so this stays internal and {getCreatedOwners} is the explicit accessor.
    mapping(address => bytes[]) internal createdOwners;
    mapping(address => uint256) public createdSalt;

    /// Which implementations were ever legitimately staged for a given wallet. F3 uses this
    /// instead of a fixed allowlist, so "installed something that was never staged" is visible.
    mapping(address => mapping(address => bool)) public stagedFor;

    uint256 public callsCreate;
    uint256 public callsRequestUpgrade;
    uint256 public callsExecuteUpgrade;
    uint256 public callsAddOwner;
    uint256 public callsRemoveOwner;
    uint256 public callsCancel;

    constructor(StarzipWalletFactory _factory, address _altImplementation, address _secondImplementation) {
        factory = _factory;
        altImplementation = _altImplementation;
        secondImplementation = _secondImplementation;
    }

    /// Valid secp256r1 points are required by `initialize`, so the fuzzer picks from a small set of
    /// known-good keys rather than random words (which would make every creation revert).
    function _key(uint256 seed) internal pure returns (bytes32 x, bytes32 y) {
        // Generator point of P-256 and two of its multiples — all on-curve.
        if (seed % 3 == 0) {
            x = bytes32(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296);
            y = bytes32(0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5);
        } else if (seed % 3 == 1) {
            x = bytes32(0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978);
            y = bytes32(0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1);
        } else {
            x = bytes32(0x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C);
            y = bytes32(0x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032);
        }
    }

    /// @dev Deterministic-but-varied EOA-style (32-byte) owner, mirroring `_key`'s approach for
    ///      passkeys: pick from a small set of known-valid addresses rather than a random word (a
    ///      zero address would make `_registerOwner` revert every time for that branch).
    function _addressOwner(uint256 seed) internal pure returns (bytes memory) {
        address[3] memory addrs = [
            address(0x1111111111111111111111111111111111111111),
            address(0x2222222222222222222222222222222222222222),
            address(0x3333333333333333333333333333333333333333)
        ];
        return abi.encode(addrs[seed % 3]);
    }

    function createAccount(uint256 keySeed, uint256 saltSeed) external {
        (bytes32 x, bytes32 y) = _key(keySeed);
        uint256 salt = bound(saltSeed, 0, 8);
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(x, y);

        address predicted = factory.getAddress(owners, salt);
        try factory.createAccount(owners, salt) returns (address a) {
            callsCreate++;
            require(a == predicted, "F1 violated at creation time");
            if (!isCreated[a]) {
                isCreated[a] = true;
                created.push(a);
                createdOwners[a] = owners;
                createdSalt[a] = salt;
            }
        } catch {}
    }

    function requestUpgrade(uint256 walletSeed, uint256 implSeed) external {
        if (created.length == 0) return;
        address w = created[walletSeed % created.length];
        address target = implSeed % 2 == 0 ? altImplementation : secondImplementation;
        vm.prank(w); // onlySelf
        try StarzipWallet(payable(w)).requestUpgrade(target) {
            callsRequestUpgrade++;
            stagedFor[w][target] = true;
        } catch {}
    }

    /// @dev Without this, F3 was vacuous: nothing in the handler could ever change an account's
    ///      implementation, so "every account points at the factory implementation" was true by
    ///      construction rather than by any guard. An independent review pass caught it.
    ///      Executing upgrades is what gives F3 something to be wrong about.
    function executeUpgrade(uint256 walletSeed, uint256 implSeed) external {
        if (created.length == 0) return;
        address w = created[walletSeed % created.length];
        // Half the time aim at something that was never staged — that is the case
        // `NotPendingImplementation` exists to reject, and F3 is what notices if it does not.
        address target = implSeed % 2 == 0 ? altImplementation : secondImplementation;
        vm.prank(w);
        try StarzipWallet(payable(w)).upgradeToAndCall(target, "") {
            callsExecuteUpgrade++;
        } catch {}
    }

    function cancelUpgrade(uint256 walletSeed) external {
        if (created.length == 0) return;
        address w = created[walletSeed % created.length];
        vm.prank(w);
        try StarzipWallet(payable(w)).cancelUpgrade() {
            callsCancel++;
        } catch {}
    }

    /// @dev No more "rotate" primitive — a passkey is just one owner among possibly several (see
    ///      StarzipWallet.sol's multi-owner NatSpec). This exercises the closest equivalent
    ///      incident-response action: registering an ADDITIONAL owner, which W2 asserts also
    ///      cancels any pending upgrade staging, exactly like the old rotation did. MIXES 32-byte
    ///      address owners in with 64-byte passkey owners (the
    ///      handler previously only ever created passkey owners, so the address-owner branch of
    ///      {StarzipWallet-_registerOwner}/{_verifyOwnerSignature} had zero property coverage).
    function addOwner(uint256 walletSeed, uint256 keySeed, uint256 kindSeed) external {
        if (created.length == 0) return;
        address w = created[walletSeed % created.length];
        vm.prank(w);
        if (kindSeed % 2 == 0) {
            (bytes32 x, bytes32 y) = _key(keySeed);
            try StarzipWallet(payable(w)).addOwnerPublicKey(x, y) {
                callsAddOwner++;
            } catch {}
        } else {
            address a = abi.decode(_addressOwner(keySeed), (address));
            try StarzipWallet(payable(w)).addOwnerAddress(a) {
                callsAddOwner++;
            } catch {}
        }
    }

    /// @dev the handler previously exercised ADDS only, never
    ///      REMOVES — so nothing could ever falsify `ownerCount == |live ownerAtIndex slots|`.
    ///      Picks an index in `[0, nextOwnerIndex)` from the seed and lets `NoSuchOwner` /
    ///      `LastOwner` / `OwnerMismatch` reject anything not currently removable — the wallet's
    ///      own stored bytes are read back and passed as `expectedOwner`, so this never needs to
    ///      independently track what SHOULD be at that index.
    function removeOwner(uint256 walletSeed, uint256 indexSeed) external {
        if (created.length == 0) return;
        address w = created[walletSeed % created.length];
        uint256 nextIdx = StarzipWallet(payable(w)).nextOwnerIndex();
        if (nextIdx == 0) return;
        uint256 index = indexSeed % nextIdx;
        bytes memory expected = StarzipWallet(payable(w)).ownerAtIndex(index);
        vm.prank(w);
        try StarzipWallet(payable(w)).removeOwnerAtIndex(index, expected) {
            callsRemoveOwner++;
        } catch {}
    }

    function warp(uint256 seed) external {
        vm.warp(block.timestamp + bound(seed, 1 hours, 10 days));
    }

    function createdCount() external view returns (uint256) {
        return created.length;
    }

    function getCreatedOwners(address w) external view returns (bytes[] memory) {
        return createdOwners[w];
    }
}

contract WalletFactoryInvariantsTest is StdInvariant, Test {
    /// ERC-1967 implementation slot.
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    MockEntryPoint internal entryPoint;
    StarzipWalletFactory internal factory;
    StarzipWallet internal altImplementation;
    StarzipWallet internal secondImplementation;
    WalletFactoryHandler internal handler;

    function setUp() public {
        entryPoint = new MockEntryPoint();
        factory = new StarzipWalletFactory(IEntryPoint(address(entryPoint)), address(0));
        altImplementation = new StarzipWallet(IEntryPoint(address(entryPoint)), address(0));
        secondImplementation = new StarzipWallet(IEntryPoint(address(entryPoint)), address(0));

        handler = new WalletFactoryHandler(factory, address(altImplementation), address(secondImplementation));
        targetContract(address(handler));
    }

    function afterInvariant() public view {
        assertGt(handler.callsCreate(), 0, "vacuous run: no account was ever created");
    }

    /// F1 — counterfactual addresses are funded BEFORE deployment, so a drift between what
    ///      `getAddress` promises and where the factory actually deploys strands real money. The
    ///      prediction is re-derived here from the recorded creation parameters; asserting only
    ///      that the account has code (the first version of this) proved nothing at all.
    function invariant_F1_predictionMatchesDeployment() public view {
        uint256 n = handler.createdCount();
        for (uint256 i = 0; i < n; i++) {
            address w = handler.created(i);
            assertEq(
                factory.getAddress(handler.getCreatedOwners(w), handler.createdSalt(w)),
                w,
                "F1: getAddress no longer predicts where this account actually lives"
            );
        }
    }

    /// the handler previously had `addOwner` but no
    /// `removeOwnerAtIndex`, so `ownerCount` could only ever grow — this invariant was true by
    /// construction, not because {StarzipWallet-removeOwnerAtIndex} keeps the two in sync. With
    /// `removeOwner` now wired into the handler, this asserts the real definition: `ownerCount`
    /// must equal the number of NON-EMPTY slots in `ownerAtIndex[0, nextOwnerIndex)`.
    function invariant_ownerCountMatchesLiveSlots() public view {
        uint256 n = handler.createdCount();
        for (uint256 i = 0; i < n; i++) {
            StarzipWallet w = StarzipWallet(payable(handler.created(i)));
            uint256 nextIdx = w.nextOwnerIndex();
            uint256 live = 0;
            for (uint256 j = 0; j < nextIdx; j++) {
                if (w.ownerAtIndex(j).length != 0) live++;
            }
            assertEq(
                w.ownerCount(),
                live,
                "ownerCount must equal |{i < nextOwnerIndex : ownerAtIndex[i].length != 0}|"
            );
        }
    }

    /// F3 — an account only ever runs the factory's implementation or one that was actually staged
    ///      for THAT account. A fixed allowlist would not have caught anything; the point is that
    ///      installing an implementation which was never staged must be impossible, which is what
    ///      `NotPendingImplementation` is for.
    function invariant_F3_accountsOnlyRunStagedImplementations() public view {
        uint256 n = handler.createdCount();
        address factoryImpl = address(factory.accountImplementation());
        for (uint256 i = 0; i < n; i++) {
            address w = handler.created(i);
            address stored = address(uint160(uint256(vm.load(w, IMPL_SLOT))));
            if (stored == factoryImpl) continue;
            assertTrue(
                handler.stagedFor(w, stored),
                "F3: an implementation was installed that was never staged for this account"
            );
        }
    }

    /// W1 — the two staging fields move together. A half-set staging is either a stuck upgrade or
    ///      one that can be finalized without a matching request.
    function invariant_W1_upgradeStagingFieldsAgree() public view {
        uint256 n = handler.createdCount();
        for (uint256 i = 0; i < n; i++) {
            StarzipWallet w = StarzipWallet(payable(handler.created(i)));
            if (w.pendingImplementation() == address(0)) {
                assertEq(w.upgradeRequestedAt(), 0, "W1: cleared pending left a live clock");
            } else {
                assertGt(w.upgradeRequestedAt(), 0, "W1: pending upgrade with no clock");
            }
        }
    }

    // ------------------------------------------------------------------
    // Deterministic
    // ------------------------------------------------------------------

    function _newWallet() internal returns (StarzipWallet w) {
        bytes32 x = bytes32(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296);
        bytes32 y = bytes32(0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5);
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(x, y);
        address predicted = factory.getAddress(owners, 42);
        address a = factory.createAccount(owners, 42);
        assertEq(a, predicted, "F1: prediction did not match deployment");
        w = StarzipWallet(payable(a));
    }

    /// F2 — a second creation must return the same account and must NOT re-initialize it. If it
    ///      did, anyone could reset a live wallet's entire owner set by calling the factory again.
    function test_createAccountIsIdempotentAndDoesNotReinitialize() public {
        StarzipWallet w = _newWallet();

        bytes memory ownerBefore = w.ownerAtIndex(0);
        uint256 countBefore = w.ownerCount();

        bytes32 x = bytes32(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296);
        bytes32 y = bytes32(0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5);
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(x, y);
        address again = factory.createAccount(owners, 42);

        assertEq(again, address(w), "F2: second creation returned a different address");
        assertEq(w.ownerAtIndex(0), ownerBefore, "F2: owner slot 0 changed on re-creation");
        assertEq(w.ownerCount(), countBefore, "F2: owner count changed on re-creation");
    }

    /// W2 — registering an additional owner cancels a pending upgrade. This is the
    ///      incident-response property: a staging queued before a fresh owner is added (e.g. in
    ///      response to a suspected compromise) must not survive that owner-set change.
    function test_addingOwnerCancelsPendingUpgrade() public {
        StarzipWallet w = _newWallet();

        vm.prank(address(w));
        w.requestUpgrade(address(altImplementation));
        assertEq(w.pendingImplementation(), address(altImplementation), "precondition: staged");

        bytes32 x2 = bytes32(0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978);
        bytes32 y2 = bytes32(0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1);
        vm.prank(address(w));
        w.addOwnerPublicKey(x2, y2);

        assertEq(w.pendingImplementation(), address(0), "W2: adding an owner left the staging armed");
        assertEq(w.upgradeRequestedAt(), 0, "W2: adding an owner left the clock running");
    }

    /// @dev for the wallet. Before the fix this same scenario SUCCEEDED — a staging armed today
    ///      executed 365 days later — because `_authorizeUpgrade` bounded only the near side. The
    ///      settlement and the beacon had already been given the far bound; the wallet had not.
    function test_staleUpgradeStagingExpires() public {
        StarzipWallet w = _newWallet();

        vm.prank(address(w));
        w.requestUpgrade(address(altImplementation));

        vm.warp(block.timestamp + 365 days);

        vm.prank(address(w));
        vm.expectRevert(StarzipWallet.UpgradeExpired.selector);
        w.upgradeToAndCall(address(altImplementation), "");

        // And the wallet is untouched — still running the factory implementation.
        assertEq(
            address(uint160(uint256(vm.load(address(w), IMPL_SLOT)))),
            address(factory.accountImplementation()),
            "expired staging still replaced the implementation"
        );
    }

    /// @dev The other half: the fix must not break the legitimate path. Executing inside the
    ///      window still works, and the boundaries are pinned rather than assumed — one second
    ///      before maturity is TimelockActive, the last second of the window still executes.
    function test_upgradeStillExecutesInsideTheWindow() public {
        StarzipWallet w = _newWallet();

        vm.prank(address(w));
        w.requestUpgrade(address(altImplementation));
        uint256 requestedAt = w.upgradeRequestedAt();

        vm.warp(requestedAt + w.UPGRADE_TIMELOCK() - 1);
        vm.prank(address(w));
        vm.expectRevert(StarzipWallet.TimelockActive.selector);
        w.upgradeToAndCall(address(altImplementation), "");

        // Last second that is still inside the window.
        vm.warp(requestedAt + w.UPGRADE_TIMELOCK() + w.UPGRADE_GRACE_PERIOD());
        vm.prank(address(w));
        w.upgradeToAndCall(address(altImplementation), "");

        assertEq(
            address(uint160(uint256(vm.load(address(w), IMPL_SLOT)))),
            address(altImplementation),
            "a staging inside its window failed to execute"
        );
        assertEq(w.pendingImplementation(), address(0), "staging not cleared after execution");
        assertEq(w.upgradeRequestedAt(), 0, "clock not cleared after execution");
    }

    // ------------------------------------------------------------------
    // SSA-16 — `getAddress` must apply the same owner-set validation `createAccount` (via
    // `StarzipWallet.initialize` -> `_registerOwner`) applies, before predicting a CREATE2
    // address, so no fundable-but-never-deployable address is ever handed out.
    // ------------------------------------------------------------------

    function test_SSA16_getAddressRevertsOnEmptyOwners() public {
        bytes[] memory owners = new bytes[](0);
        vm.expectRevert(StarzipWallet.InvalidArrayLength.selector);
        factory.getAddress(owners, 100);
    }

    function test_SSA16_getAddressRevertsOnDuplicateOwners() public {
        bytes memory a = abi.encode(address(0x1234567890123456789012345678901234567890));
        bytes[] memory owners = new bytes[](2);
        owners[0] = a;
        owners[1] = a;
        vm.expectRevert(StarzipWallet.AlreadyOwner.selector);
        factory.getAddress(owners, 101);
    }

    function test_SSA16_getAddressRevertsOnZeroAddressOwner() public {
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(address(0));
        vm.expectRevert(StarzipWallet.ZeroAddress.selector);
        factory.getAddress(owners, 102);
    }

    function test_SSA16_getAddressRevertsOnInvalidOwnerBytesLength() public {
        bytes[] memory owners = new bytes[](1);
        owners[0] = hex"1234"; // neither 32 (address) nor 64 (P-256 key) bytes
        vm.expectRevert(StarzipWallet.InvalidOwnerBytesLength.selector);
        factory.getAddress(owners, 103);
    }

    /// A 32-byte blob whose upper 96 bits are non-zero bare-reverts inside
    /// `validateOwnerBytes`'s `abi.decode(ownerBytes, (address))` (solc's address-cleanup check),
    /// with no named error — hence `expectRevert()` with no selector.
    function test_SSA16_getAddressRevertsOnDirtyEncodedAddress() public {
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encodePacked(bytes32(type(uint256).max)); // top 12 bytes non-zero
        vm.expectRevert();
        factory.getAddress(owners, 104);
    }

    function test_SSA16_getAddressRevertsOnInvalidPublicKey() public {
        bytes[] memory owners = new bytes[](1);
        // Off-curve garbage — not the generator point or any of its known-good multiples.
        owners[0] = abi.encode(bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert(StarzipWallet.InvalidPublicKey.selector);
        factory.getAddress(owners, 105);
    }

    /// createAccount's and getAddress's accepted sets must be identical: every input `getAddress`
    /// rejects above must also be rejected by `createAccount`, with the same error.
    function test_SSA16_createAccountRejectsEverythingGetAddressRejects() public {
        vm.expectRevert(StarzipWallet.InvalidArrayLength.selector);
        factory.createAccount(new bytes[](0), 200);

        bytes memory a = abi.encode(address(0x1234567890123456789012345678901234567890));
        bytes[] memory dup = new bytes[](2);
        dup[0] = a;
        dup[1] = a;
        vm.expectRevert(StarzipWallet.AlreadyOwner.selector);
        factory.createAccount(dup, 201);

        bytes[] memory zero = new bytes[](1);
        zero[0] = abi.encode(address(0));
        vm.expectRevert(StarzipWallet.ZeroAddress.selector);
        factory.createAccount(zero, 202);

        bytes[] memory badLen = new bytes[](1);
        badLen[0] = hex"1234";
        vm.expectRevert(StarzipWallet.InvalidOwnerBytesLength.selector);
        factory.createAccount(badLen, 203);

        bytes[] memory offCurve = new bytes[](1);
        offCurve[0] = abi.encode(bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert(StarzipWallet.InvalidPublicKey.selector);
        factory.createAccount(offCurve, 204);
    }

    /// REGRESSION — the SSA-16 validation must not change the CREATE2 address predicted for a
    /// valid owner set. The expected address is recomputed here from `accountImplementation()`,
    /// `owners` and `salt` rather than by calling `getAddress` twice, so it stays independent of
    /// the nonce `accountImplementation` deployed at in a given run. Measured against the
    /// pre-SSA-16 commit (6664bb3): this owner set and `salt = 42` predicted
    /// `0xd2cfa90b4c78b147B2bBeB5195a36Dc606F182F5` there and still does.
    function test_SSA16_validOwnerAddressPredictionUnchanged() public view {
        bytes32 x = bytes32(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296);
        bytes32 y = bytes32(0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5);
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(x, y);
        uint256 salt = 42;

        bytes memory initData = abi.encodeCall(StarzipWallet.initialize, (owners));
        bytes memory proxyBytecode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(factory.accountImplementation()), initData)
        );
        address expected = Create2.computeAddress(bytes32(salt), keccak256(proxyBytecode), address(factory));

        address predicted = factory.getAddress(owners, salt);
        assertEq(
            predicted,
            expected,
            "SSA-16 fix must not change the CREATE2 address predicted for a valid owner set"
        );
    }
}
