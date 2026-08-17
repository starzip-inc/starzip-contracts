// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { WebAuthn } from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import { IAccount } from "@account-abstraction/contracts/interfaces/IAccount.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { ERC7739Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/signers/draft-ERC7739Upgradeable.sol";
import { ERC7739Utils } from "@openzeppelin/contracts/utils/cryptography/draft-ERC7739Utils.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import { ERC721Holder } from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import { ERC1155Holder } from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";

/**
 * @title StarzipWallet
 * @notice ERC-4337 smart wallet with a Coinbase-Smart-Wallet-style multi-owner model (UUPS upgradeable)
 * @dev Uses OpenZeppelin's WebAuthn library for on-chain Passkey signature validation, and OZ's
 *      `ECDSA` library for plain secp256k1 (EOA-style) owner keys. EntryPoint v0.8 compatible
 *      (PackedUserOperation).
 *
 *      MULTI-OWNER MODEL (replaces the earlier single-passkey / guardian-recovery design):
 *      - Any number of owners may control this wallet CONCURRENTLY, each with EQUAL, independent
 *        authority — there is no quorum, no guardian, and no recovery session. An owner is either
 *        an EOA-style address (32 bytes: `abi.encode(address)`) or a P-256 passkey (64 bytes:
 *        `abi.encode(bytes32 x, bytes32 y)`) — see {ownerAtIndex}.
 *      - "Use": a userOp (or ERC-1271 approval) names WHICH owner is signing via a
 *        `SignatureWrapper{ownerIndex, signatureData}` (see {_verifyOwnerSignature}), and the
 *        wallet dispatches to ECDSA recovery or WebAuthn/P-256 verification accordingly.
 *      - "Manage": {addOwnerAddress} / {addOwnerPublicKey} / {removeOwnerAtIndex} are `onlySelf`
 *        (must arrive as an owner-signed userOp routed EntryPoint -> {execute} -> address(this)),
 *        exactly like every other administrative function in this contract. There is still NO
 *        operator path: the StarZip platform cannot add, remove, or act as an owner.
 *      - RECOVERY IS NO LONGER AN ON-CHAIN PROTOCOL. It is now simply "you have a second owner":
 *        a user who registers two owners (e.g. a passkey plus a backup EOA, or two passkeys
 *        synced across an authenticator's own cloud backup) can lose one and still control the
 *        wallet via the other, with zero additional on-chain machinery, timelock, or quorum. This
 *        deliberately replaces the guardian-recovery design that shipped earlier: that design's
 *        M-of-N guardian set produced a chain of defects — replayable bearer approvals, an
 *        approval-count ratchet that permanently bricked a wallet once all N guardians had ever
 *        signed, and a first-guardian timelock carve-out that let one blind-signed userOp install
 *        a backdoor. None of that machinery exists here to have equivalent bugs in.
 *
 *      {removeOwnerAtIndex} MATCHES the reference `coinbase/smart-wallet` `MultiOwnable`
 *      implementation it is modeled on, not diverges from it: upstream's `removeOwnerAtIndex`
 *      opens with the identical guard (`if (ownerCount() == 1) { revert LastOwner(); }` — same
 *      condition, same error name). We copied that guard; we did not improve on it.
 *
 *      The real divergence runs the OTHER way: upstream additionally ships a SEPARATE function,
 *      `removeLastOwner`, gated on `ownerCount() <= 1`, that exists specifically so a wallet CAN be
 *      deliberately retired. THIS WALLET OMITS IT — there is no equivalent function here. The
 *      consequence is a known, accepted one, not a bug: a StarZip wallet can never be voluntarily
 *      retired on-chain; it is permanently owned by whoever holds its last remaining key for as
 *      long as that key exists. Adding a `removeLastOwner` equivalent is a product decision this
 *      file does not make unilaterally. This file's owner-set logic is otherwise an independent
 *      implementation of upstream's idea, not vendored code.
 */
contract StarzipWallet is
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardTransient,
    ERC721Holder,
    ERC1155Holder,
    ERC7739Upgradeable,
    IAccount
{
    using MessageHashUtils for bytes32;

    // ============ Constants ============
    uint256 private constant SIG_VALIDATION_SUCCESS = 0;
    uint256 private constant SIG_VALIDATION_FAILED = 1;
    uint256 public constant UPGRADE_TIMELOCK = 48 hours;
    /// @dev Applied here to match `TradeSettlementV1` and `UpgradeableBeacon`: a matured
    ///      staging must also EXPIRE. Without an upper bound, "48h timelock" really means "48h
    ///      notice, once, forever" — a request signed during a momentary owner-key compromise stays
    ///      armed indefinitely and the attacker picks the moment to fire it, long after the user
    ///      has stopped looking and after the wallet has become worth taking. Because an upgrade
    ///      replaces the wallet's code, firing it does not steal a balance: it takes the account,
    ///      including everything that arrives afterwards.
    ///
    ///      NOTE: adding a fresh owner or removing the compromised one DOES cancel any
    ///      pending staging (both {addOwnerAddress}/{addOwnerPublicKey} and {removeOwnerAtIndex}
    ///      call {_cancelPendingUpgradeOnOwnerChange} — see their NatSpec) — but ONLY IF an honest
    ///      owner still holds a signing key and acts before the attacker does. `removeOwnerAtIndex`
    ///      carries NO timelock (unlike upgrades) and any registered owner may remove any OTHER
    ///      owner, so the attacker holding the compromised key can win the race outright: a single
    ///      `executeBatch([removeOwnerAtIndex(honestOwner), requestUpgrade(evil)])` removes every
    ///      other owner and arms the upgrade in ONE atomic, silently-authorized op (order matters —
    ///      removing first means the hygiene cancel fires on a stage that does not exist yet, so
    ///      the request placed second stays armed). After that op lands, the honest owner holds no
    ///      key at all and cannot add, remove, or cancel anything — the "defence" this constant's
    ///      comment used to describe as available is gone. This is a genuine residual, not merely
    ///      a documentation gap: see {_cancelPendingUpgradeOnOwnerChange}'s own NatSpec for the
    ///      batch-ordering footgun this shares a root cause with, and {removeOwnerAtIndex}'s
    ///      NatSpec for the accept/reject decision on whether to change removal's authorization
    ///      model in response (decision: NOT changed in this pass — see there for why). Total
    ///      armed lifetime, when an upgrade request DOES survive to maturity, is 48h + 7d, after
    ///      which execution needs a fresh request and therefore a fresh public
    ///      {UpgradeRequested} event.
    uint256 public constant UPGRADE_GRACE_PERIOD = 7 days;
    /// @dev Duplicated, unpinned, in `VerifyingPaymaster.MAX_BATCH_SIZE` (that file's own comment
    ///      notes the mirror) — two separate `constant` declarations, not one shared source, so
    ///      changing this value without also updating the paymaster's copy silently desynchronizes
    ///      them (MINOR — recorded, not fixed).
    ///
    ///      FAIL-CLOSED TODAY, not fail-open: the paymaster's copy bounds only its OWN calldata
    ///      parser when deciding whether to sponsor an `executeBatch` op
    ///      (`VerifyingPaymaster.sol:1071`) — it never gates execution itself. This contract's own
    ///      `BatchTooLarge` check (see {executeBatch}) is the sole real enforcement of batch size
    ///      and is unaffected by whatever the paymaster's copy says. A divergence between the two
    ///      constants therefore degrades to a sponsorship mismatch (a valid batch wrongly denied
    ///      sponsorship, or an over-large batch parsed as sponsorable that then reverts on-chain
    ///      anyway against THIS constant), never an executed batch larger than this contract
    ///      actually allows. Re-verify this direction of reasoning if either constant's role
    ///      changes.
    uint256 private constant MAX_BATCH_SIZE = 32;

    /// @dev EIP-712 domain of the WALLET ITSELF, used only by the ERC-7739 defensive rehashing
    ///      (see {_rawSignatureValidation}). Returned as constants via the {_EIP712Name} /
    ///      {_EIP712Version} overrides so `EIP712Upgradeable`'s namespaced storage is NEVER read
    ///      or written in this contract's normal operation: `initialize` keeps its current
    ///      signature, and already-deployed wallets inherit the same domain after an upgrade
    ///      (a storage-backed name would have been empty for them and silently split the domain
    ///      in two). Changing either string is a signature-breaking change.
    ///
    ///      On OZ's `contracts-upgradeable` package, version **5.5.0 — THE
    ///      VERSION THIS PARAGRAPH'S REASONING DEPENDS ON; re-check it on the next OZ upgrade** — calling
    ///      `__EIP712_init` here would NOT make `eip712Domain()` revert: `EIP712Upgradeable
    ///      .__EIP712_init_unchained` (`EIP712Upgradeable.sol:71-79`) ends by EXPLICITLY ZEROING
    ///      `$._hashedName` and `$._hashedVersion` — the exact two fields `eip712Domain()`'s
    ///      `require($._hashedName == 0 && $._hashedVersion == 0, "EIP712: Uninitialized")` tests.
    ///      Calling `__EIP712_init` is therefore inert on this OZ version. It is doubly inert here
    ///      regardless, because this wallet's non-empty {_EIP712Name}/{_EIP712Version} overrides
    ///      mean `_EIP712NameHash`/`_EIP712VersionHash` never read that storage at all.
    ///
    ///      THE HAZARD IS REAL, the stated cause was just wrong. Demonstrated by writing raw to
    ///      `EIP712StorageLocation` (`0xa16a...d100`) directly — bypassing every public function —
    ///      rather than via `__EIP712_init`: `eip712Domain()` then reverts `"EIP712: Uninitialized"`,
    ///      and {isValidSignature} reverts with it (it calls `eip712Domain()` unconditionally),
    ///      which `SignatureChecker.isValidERC1271SignatureNow`'s `staticcall` swallows as
    ///      `success=false` -> `false` — i.e. every wallet's ERC-1271 order signature would start
    ///      failing `TradeSettlementV1` verification silently, with no revert reason pointing at
    ///      the cause. The ACTUAL triggers are (1) a raw write to this ERC-7201 namespace by some
    ///      future code path — none exists today, this is a "must never be introduced" invariant,
    ///      not a live one — or (2) an OpenZeppelin major-version change that restores pre-5.5.0
    ///      `__EIP712_init` semantics (where the hashed fields were written non-zero directly
    ///      instead of being reset to zero). INVARIANT A FUTURE UPGRADE MUST NOT VIOLATE: never
    ///      write directly to the EIP712 namespaced slot, and re-derive this reasoning — do not
    ///      assume it still holds — against whichever OZ version that upgrade pins. See the
    ///      {eip712Domain} non-revert invariant test.
    string private constant EIP712_NAME = "StarzipWallet";
    string private constant EIP712_VERSION = "1";

    // ============ Immutable ============
    IEntryPoint public immutable entryPoint;

    // ============ State Variables ============
    /// @dev An owner is identified purely by its ENCODING, never by an address type slot: exactly
    ///      32 bytes (`abi.encode(address)`, an EOA-style secp256k1 key) or exactly 64 bytes
    ///      (`abi.encode(bytes32 x, bytes32 y)`, a P-256 passkey public key). Any other length is
    ///      rejected at registration time (see {_registerOwner}) and can therefore never appear
    ///      here — {_verifyOwnerSignature}'s length dispatch is exhaustive by construction, not by
    ///      a runtime fallback. Indices are never reused after {removeOwnerAtIndex}: `nextOwnerIndex`
    ///      only ever increases, so an index that named owner A yesterday can never silently name
    ///      owner B tomorrow (the removed slot instead reads back as the empty `bytes` that
    ///      {_verifyOwnerSignature} treats as "unregistered").
    mapping(uint256 => bytes) public ownerAtIndex;
    /// @dev Reverse index: is this exact encoded owner CURRENTLY registered (at any index)? Used
    ///      only to reject re-adding an owner that is already present (see {_registerOwner}) — it
    ///      does not itself grant any authority; {ownerAtIndex} plus {_verifyOwnerSignature} is the
    ///      sole path from a signature to acceptance.
    mapping(bytes => bool) public isOwnerBytes;
    /// @dev Next slot {_registerOwner} will write to. Monotonically increasing — never decremented
    ///      by {removeOwnerAtIndex} — so indices are stable identifiers, not array positions.
    uint256 public nextOwnerIndex;
    /// @dev Number of CURRENTLY registered owners (adds increment, removes decrement). The sole
    ///      purpose of tracking this separately from `nextOwnerIndex` is {removeOwnerAtIndex}'s
    ///      `ownerCount == 1` guard: an empty owner set is a permanently locked wallet (no
    ///      signature can ever again pass {_verifyOwnerSignature}), so removal of the LAST owner is
    ///      refused outright. This is a deliberate divergence from the reference
    ///      `coinbase/smart-wallet` `MultiOwnable`, which allows exactly that and ships the footgun.
    uint256 public ownerCount;

    address public pendingImplementation; // upgrade flow (onlySelf-gated)
    uint256 public upgradeRequestedAt; // upgrade flow

    // ============ Storage Gap ============
    // Full redesign — this contract has never had a real mainnet deployment (the AA factory has
    // deployed exactly one opBNB-testnet wallet, an empty test account with an immutable
    // `accountImplementation`, so onboarding a new design means a new factory and new
    // counterfactual addresses regardless — see the deploy notes accompanying this change), so
    // storage is free to be laid out cleanly rather than threaded around a legacy slot numbering.
    // 44 reserved slots leaves headroom comparable to this codebase's other UUPS contracts
    // (e.g. `ERC20V1`'s `uint256[50] __gap`) for whatever this wallet's owner-set model grows next
    // (per-owner metadata, a session-key allowance table, etc.) without ever touching the slots
    // above.
    uint256[44] private __gap;

    // ============ Events ============
    event Executed(address indexed target, uint256 value, bytes data);
    event BatchExecuted(uint256 count);
    event AddOwner(uint256 indexed index, bytes owner);
    event RemoveOwner(uint256 indexed index, bytes owner);
    event UpgradeRequested(address indexed newImplementation, uint256 readyAt);
    event UpgradeCancelled(address indexed cancelledImplementation);

    // ============ Errors ============
    error OnlyEntryPoint();
    error OnlySelf();
    error InvalidArrayLength();
    error BatchTooLarge();
    error ZeroAddress();
    error InvalidPublicKey();
    error InvalidOwnerBytesLength();
    error AlreadyOwner();
    error NoSuchOwner();
    error OwnerMismatch();
    error LastOwner();
    error TimelockActive();
    error UpgradeExpired();
    error NoUpgradePending();
    error NotPendingImplementation();
    error InvalidImplementation();
    error ExecutionFailed(uint256 index);

    // ============ Modifiers ============
    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) revert OnlyEntryPoint();
        _;
    }

    /**
     * @dev Restricts to owner-authorized self-calls (EntryPoint -> execute -> address(this)).
     *      Every administrative function in this contract is gated this way — there is no
     *      operator, no owner-EOA fast path, and no way for the StarZip platform or any third
     *      party to act as, add, or remove an owner. Whichever registered owner (address or
     *      passkey) signed the outer userOp is the one whose authority this call runs under.
     *
     *      INVARIANT A FUTURE UPGRADE MUST NOT VIOLATE: no future
     *      version may introduce a chain-agnostic execution path for the administrative functions
     *      gated by this modifier (`addOwnerAddress`, `addOwnerPublicKey`, `removeOwnerAtIndex`,
     *      `upgradeToAndCall`). Upstream `coinbase/smart-wallet`'s Code4rena H-01 (High) — replay
     *      of an owner-removal userOp across every chain a counterfactual wallet exists on — is
     *      reachable ONLY because upstream ships `executeWithoutChainIdValidation` plus a
     *      `canSkipChainIdValidation` allowlist covering exactly this same function set. We are
     *      safe from H-01 because that feature is simply ABSENT here, not because of anything
     *      `expectedOwner`-related — every execution path in this contract goes through either
     *      `execute`/`executeBatch` (`onlyEntryPoint`, chain-bound via `userOpHash`) or this
     *      modifier (reachable only through one of those two, so chain-bound transitively). This
     *      file declares its upstream lineage in three places, so a maintainer may reasonably port
     *      more of `MultiOwnable` into it — this is the one piece that must not come back. See
     *      test/StarzipWallet_publicAuditMap.test.ts, "C4 H-01".
     */
    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
    }

    // ============ Initialization ============
    /**
     * @notice Register the wallet's INITIAL owner set. Additional owners can still be added later
     *         via {addOwnerAddress} / {addOwnerPublicKey}, each an `onlySelf` call authorized by
     *         an already-registered owner.
     * @dev Registers EVERY element of `owners`, not just one. By product decision, recovery IS
     *      simply "you have a second owner" (see the contract-level NatSpec), and a second owner
     *      is registered AT ISSUANCE — so a wallet could previously be BORN into the single state
     *      the multi-owner recovery model has no way to recover from (a lost/compromised sole
     *      owner with nobody else registered yet). {_registerOwner} remains the single choke
     *      point: every element here passes the exact same length/on-curve checks
     *      {addOwnerAddress}/{addOwnerPublicKey} enforce for an owner added later — this function
     *      adds no parallel validation path. Reverts `InvalidArrayLength` for an empty array (a
     *      wallet MUST be born with at least one owner); a duplicate element reverts `AlreadyOwner`
     *      (inherited from {_registerOwner}, which is not disabled here).
     * @param owners Each element is `abi.encode(address)` (32 bytes) for an EOA-style owner, or
     *        `abi.encode(bytes32 x, bytes32 y)` (64 bytes) for a P-256 passkey owner. Any other
     *        length reverts (`InvalidOwnerBytesLength`). Order determines index assignment
     *        (`owners[0]` becomes index 0, etc. — see {ownerAtIndex}).
     */
    function initialize(bytes[] calldata owners) external initializer {
        if (owners.length == 0) revert InvalidArrayLength();
        for (uint256 i = 0; i < owners.length; ) {
            _registerOwner(owners[i]);
            unchecked {
                ++i;
            }
        }
    }

    // ============ ERC-4337 ============
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        validationData = _validateSignature(userOp, userOpHash);

        if (missingAccountFunds > 0) {
            (bool success, ) = payable(msg.sender).call{ value: missingAccountFunds }("");
            (success); // ignore failure (EntryPoint will handle)
        }
    }

    // ============ Execution ============
    /**
     * @dev Unrestricted by design: any target, any selector, gated only by an owner-signed userOp.
     *
     *      WHY THERE IS NO ON-CHAIN CALL POLICY. A phished userOp can call anything, e.g.
     *      `execute(settlement, registerSessionKey(attacker, maxDuration))`. None of the on-chain
     *      answers work:
     *      (1) A target/selector allowlist would have to enumerate every token, dApp and protocol
     *          the user will ever touch. Wrong or stale entries brick a non-custodial wallet that
     *          has no operator and no admin — a self-inflicted permanent DoS strictly worse than
     *          the risk it covers.
     *      (2) An OPT-IN restriction mode is worth exactly zero against this threat: the toggle can
     *          only be `onlySelf`, i.e. reachable by the very owner signature that is assumed
     *          compromised, and {executeBatch} lets the attacker put `disableRestrictions()` and
     *          the malicious call in ONE op. Making the toggle timelocked instead just converts it
     *          into footgun (1).
     *      (3) The wallet cannot classify "sensitive" on-chain. `registerSessionKey` is not more
     *          dangerous than `transfer(attacker, balance)`; any selector list encoding that
     *          judgement is allowlist (1) under another name.
     *      What IS done instead: every call is logged ({Executed}, from BOTH entry points — see
     *      {executeBatch}), and the ERC-1271 surface is domain-bound via ERC-7739 (see
     *      {_rawSignatureValidation}). The residual — a user approving a userOp whose intent they
     *      cannot read — is an ERC-4337 signer-UI problem (the challenge is an opaque `userOpHash`
     *      by construction), not something this contract can decide. The signing client MUST decode
     *      `callData` and render target + function + arguments before prompting.
     *
     *      DIAGNOSTIC GAP (MINOR, recorded not fixed): unlike
     *      {executeBatch} (see its `if (result.length > 0) { ... } revert ExecutionFailed(i);`
     *      guard), this function has no empty-returndata fallback. If `dest.call` reverts with
     *      EMPTY returndata, `result.length == 0` and `assembly { revert(add(result, 32),
     *      mload(result)) }` re-reverts with a zero-length reason — observable as
     *      `FailedOpWithRevert(_, "AA23 reverted", "0x")`, indistinguishable from the outside from
     *      the exact class of unhelpful, reason-less revert the index-bounds fixes elsewhere in this
     *      file (see {_verifyPasskeyOwner}) exist specifically to eliminate. This is a diagnostics
     *      quality gap, not a security one — `execute` still correctly fails the userOp either way,
     *      and no funds or authority are at stake — but it is real, and a small follow-up mirroring
     *      {executeBatch}'s existing pattern would close it cheaply. NOT changed in this pass
     *      (documentation-only).
     */
    function execute(address dest, uint256 value, bytes calldata func) external onlyEntryPoint nonReentrant {
        (bool success, bytes memory result) = dest.call{ value: value }(func);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        emit Executed(dest, value, func);
    }

    /**
     * @dev Emits one {Executed} per inner call IN ADDITION to {BatchExecuted}.
     *      Observability: `execute` has always logged (target, value, calldata), but
     *      `executeBatch` used to log only a count — so any caller could suppress the per-call
     *      audit trail simply by wrapping a single call in a 1-element batch. Emitting the same
     *      event from both entry points removes that blind spot and lets one indexer subscription
     *      see every call this wallet ever makes. This is deliberately NOT a policy check: the
     *      wallet cannot tell on-chain which targets are "sensitive" (see the call-policy note on
     *      {execute}); it can only guarantee that nothing happens off the record.
     *
     *      QUALIFIED: that guarantee holds only of THIS
     *      implementation, exactly as written today — it is not a structural property of the
     *      contract's design. It depends on every value-moving external call continuing to route
     *      through {execute}/{executeBatch} and on neither `emit Executed` ever being removed or
     *      made conditional. A future version that adds another external-call path, or drops either
     *      emit, would silently break the "nothing happens off the record" property with no other
     *      symptom to catch it.
     */
    function executeBatch(
        address[] calldata dest,
        uint256[] calldata values,
        bytes[] calldata funcs
    ) external onlyEntryPoint nonReentrant {
        if (dest.length == 0 || dest.length != values.length || dest.length != funcs.length)
            revert InvalidArrayLength();
        if (dest.length > MAX_BATCH_SIZE) revert BatchTooLarge();
        for (uint256 i = 0; i < dest.length; ) {
            (bool success, bytes memory result) = dest[i].call{ value: values[i] }(funcs[i]);
            if (!success) {
                if (result.length > 0) {
                    assembly {
                        revert(add(result, 32), mload(result))
                    }
                }
                revert ExecutionFailed(i);
            }
            emit Executed(dest[i], values[i], funcs[i]);
            unchecked {
                ++i;
            }
        }
        emit BatchExecuted(dest.length);
    }

    // ============ Admin: Owner Set (Coinbase-Smart-Wallet-style multi-owner) ============
    /**
     * @notice Add an EOA-style (secp256k1) owner.
     * @dev `onlySelf` — an already-registered owner authorizes adding a new one. Reverts
     *      `ZeroAddress` for `address(0)` and `AlreadyOwner` if this exact address is already
     *      registered (at any index). Clears any pending upgrade staging — see the hygiene note
     *      on {_cancelPendingUpgradeOnOwnerChange}.
     */
    function addOwnerAddress(address owner) external onlySelf {
        if (owner == address(0)) revert ZeroAddress();
        _registerOwner(abi.encode(owner));
        _cancelPendingUpgradeOnOwnerChange();
    }

    /**
     * @notice Add a P-256 passkey owner.
     * @dev `onlySelf`. Reverts `InvalidPublicKey` for any point not on the P-256 curve (see
     *      {_registerOwner} for the on-curve rationale, shared with {initialize}) and
     *      `AlreadyOwner` if this exact (x, y) is already registered. Clears any pending upgrade
     *      staging — see {_cancelPendingUpgradeOnOwnerChange}.
     */
    function addOwnerPublicKey(bytes32 x, bytes32 y) external onlySelf {
        _registerOwner(abi.encode(x, y));
        _cancelPendingUpgradeOnOwnerChange();
    }

    /**
     * @notice Remove the owner registered at `index`.
     * @dev `onlySelf`. `expectedOwner` must byte-for-byte match what is CURRENTLY stored at
     *      `index` (`OwnerMismatch` otherwise) — this guards against index drift: a signing UI
     *      that last refreshed the owner list before a concurrent add/remove cannot accidentally
     *      remove a different owner than the one the user was shown and confirmed. `NoSuchOwner`
     *      if `index` is empty (never written, or already removed).
     *
     *      `LastOwner` — MUST revert when `ownerCount == 1`. An empty owner set can never again
     *      produce a passing signature (see {_verifyOwnerSignature}), i.e. it is a permanently
     *      locked wallet with no recovery path, since recovery in this design IS the owner set
     *      (see the contract-level NatSpec). This guard is IDENTICAL to the reference
     *      `coinbase/smart-wallet` `MultiOwnable`'s `removeOwnerAtIndex` — same condition, same
     *      error name; we did NOT diverge here. What this contract
     *      omits is upstream's SEPARATE `removeLastOwner` function (gated `ownerCount() <= 1`), the
     *      deliberate escape hatch that lets a wallet be intentionally retired — there is no
     *      equivalent here, so a StarZip wallet can never be voluntarily retired.
     *
     *      RESIDUAL (evaluated, NOT changed in this pass): any
     *      owner may remove any OTHER owner instantly, with no timelock. Combined with
     *      {executeBatch}, whichever key acts first wins outright — see
     *      {UPGRADE_GRACE_PERIOD}'s NatSpec for the exact atomic-removal-then-upgrade sequence
     *      this enables. Two divergences were considered and rejected for THIS pass:
     *        (a) restrict removal to self-removal only (an owner may remove only the owner that
     *            signed the current op) — rejected: it also removes the legitimate incident-
     *            response case this function exists for (owner B pruning a KNOWN-compromised
     *            owner A that can no longer sign for itself, e.g. a stolen/wiped device), which is
     *            a real capability loss, not just a smaller attack surface.
     *        (b) a short timelock on removal (symmetric to {UPGRADE_TIMELOCK}) — NOT implemented
     *            here: it is a genuine new state machine (per-pending-removal storage, a
     *            cancel/expire path, and its own interaction with {LastOwner} and the upgrade
     *            timelock's own hygiene-cancel), i.e. new attack surface that has not itself gone
     *            through review, on a contract with zero real deployments (so there is no
     *            migration cost to doing it properly in a dedicated follow-up instead of rushing
     *            it into this pass). Upstream `coinbase/smart-wallet` `MultiOwnable` has this
     *            identical instant-removal property and makes NO safety claim about it, ships NO
     *            upgrade timelock at all — this contract's actual gap was the (now-corrected)
     *            NatSpec claiming a defence that a first-mover attacker can foreclose, not the
     *            underlying removal authorization model itself.
     */
    function removeOwnerAtIndex(uint256 index, bytes calldata expectedOwner) external onlySelf {
        if (ownerCount == 1) revert LastOwner();
        bytes memory stored = ownerAtIndex[index];
        if (stored.length == 0) revert NoSuchOwner();
        if (keccak256(stored) != keccak256(expectedOwner)) revert OwnerMismatch();
        delete ownerAtIndex[index];
        isOwnerBytes[stored] = false;
        unchecked {
            --ownerCount;
        }
        emit RemoveOwner(index, stored);
        _cancelPendingUpgradeOnOwnerChange();
    }

    /**
     * @notice Return every CURRENTLY registered owner, compacted (no gaps for removed slots).
     * @dev Read-only convenience: without it, a
     *      UI had to scan `ownerAtIndex[0..nextOwnerIndex)` one `eth_call` at a time and skip the
     *      empty (removed) entries itself. Not part of any signature-verification path — that
     *      remains {ownerAtIndex} + {_verifyOwnerSignature}, unaffected by this function. O(n) in
     *      `nextOwnerIndex`; fine for a view/eth_call, not used on-chain by anything else here.
     */
    function getOwners() external view returns (bytes[] memory owners) {
        owners = new bytes[](ownerCount);
        uint256 found = 0;
        uint256 n = nextOwnerIndex;
        for (uint256 i = 0; i < n; ) {
            bytes memory o = ownerAtIndex[i];
            if (o.length != 0) {
                owners[found] = o;
                unchecked {
                    ++found;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Shared validation + registration path for {initialize}, {addOwnerAddress}, and
     *      {addOwnerPublicKey} — a single choke point means every owner ever written to
     *      {ownerAtIndex} has already passed the SAME length/shape checks, so
     *      {_verifyOwnerSignature}'s length-based dispatch never has to handle a third case.
     *
     *      Length dispatch: exactly 32 bytes is decoded as `address` and rejected if zero; exactly
     *      64 bytes is decoded as `(bytes32 x, bytes32 y)` and rejected if not a valid point on the
     *      P-256 curve (`P256.isValidPublicKey`).
     *
     *      WHY THE ON-CURVE CHECK MATTERS (it is NOT safe to delete for gas): OZ's
     *      `P256.verify` (reached via `WebAuthn.verify` from {_verifyPasskeyOwner}) ALSO calls
     *      `isValidPublicKey` on every verification attempt, unconditionally, before doing any
     *      curve arithmetic — `P256.sol`'s `_tryVerifyNative` and `verifySolidity` both gate on it
     *      first, so an off-curve `(x, y)` is rejected there regardless of what was ever stored.
     *      Given that independent library-level gate, a registered off-curve key genuinely can only
     *      brick that owner slot, not enable a hijack, on the OZ version this contract currently
     *      depends on. The check here remains load-bearing anyway: it gives a clean, immediate,
     *      named-error failure (`InvalidPublicKey`) instead of a silently-dead owner slot that only
     *      fails, unhelpfully, the first time someone tries to use it, and it is a second,
     *      independent line of defense should a future OZ version ever stop validating on-curve
     *      internally. Upstream `coinbase/smart-wallet` performs NO on-curve check on any add path
     *      — this is a place this wallet is genuinely stronger than the reference implementation,
     *      not merely different from it.
     *
     *      Any OTHER length reverts `InvalidOwnerBytesLength` — this is what makes
     *      {ownerAtIndex}'s two-length dispatch exhaustive everywhere else in this contract.
     *
     *      UNDOCUMENTED BARE REVERT (upstream Cantina-Dec 3.1.3, see
     *      test/StarzipWallet_publicAuditMap.test.ts): the 32-byte branch's ONLY
     *      explicit check above is "is it zero" (`ZeroAddress`). A 32-byte blob whose top 12 bytes
     *      are non-zero — not a clean `abi.encode(address)` — is ALSO rejected, but only as an
     *      incidental side effect of `abi.decode(ownerBytes, (address))`'s own padding validation:
     *      solc emits an address-cleanup check that does a bare `revert(0, 0)` on dirty padding —
     *      no named error, no revert reason. Nobody wrote that check; it comes free with the
     *      decode. It is nonetheless load-bearing: {_verifyOwnerSignature} performs the identical
     *      `abi.decode(ownerBytes, (address))` on the READ path, so if a dirty-high-bits blob could
     *      ever be stored, every signature check naming that index would REVERT instead of
     *      returning `SIG_VALIDATION_FAILED` — the write path's incidental decode is the only thing
     *      keeping the read path's decode total. This falsifies any blanket claim that every
     *      rejection in this contract carries its own named error; this one does not.
     */
    function _registerOwner(bytes memory ownerBytes) internal {
        if (ownerBytes.length == 32) {
            if (abi.decode(ownerBytes, (address)) == address(0)) revert ZeroAddress();
        } else if (ownerBytes.length == 64) {
            (bytes32 x, bytes32 y) = abi.decode(ownerBytes, (bytes32, bytes32));
            if (!P256.isValidPublicKey(x, y)) revert InvalidPublicKey();
        } else {
            revert InvalidOwnerBytesLength();
        }
        if (isOwnerBytes[ownerBytes]) revert AlreadyOwner();

        uint256 index = nextOwnerIndex;
        ownerAtIndex[index] = ownerBytes;
        isOwnerBytes[ownerBytes] = true;
        unchecked {
            nextOwnerIndex = index + 1;
            ++ownerCount;
        }
        emit AddOwner(index, ownerBytes);
    }

    /**
     * @dev Incident-response hygiene, extended from the single-passkey design's `changePasskey`
     *      (which cancelled a pending upgrade on rotation) to every owner-set mutation: adding or
     *      removing an owner cancels any pending upgrade staging, so a staging queued by a
     *      since-compromised (now-removed) owner — or queued moments before a fresh backup owner
     *      is added in response to a suspected compromise — cannot be finalized later by whichever
     *      key requested it.
     *
     *      FOOTGUN (recorded, not fixed): this hygiene applies
     *      inside a SINGLE {executeBatch} too, in call order, because both {requestUpgrade} and
     *      {addOwnerAddress}/{addOwnerPublicKey}/{removeOwnerAtIndex} are ordinary inner calls of
     *      one owner-signed op. `executeBatch([requestUpgrade(evil), addOwnerPublicKey(backup)])`
     *      silently cancels the just-staged upgrade in the SAME transaction that requested it —
     *      the caller sees `UpgradeRequested` immediately followed by `UpgradeCancelled` in one
     *      receipt, which looks like a bug from the outside but is this function firing exactly as
     *      designed. Reordering the batch (`addOwner` first, `requestUpgrade` second) avoids it.
     *      This is a signer-UI/client footgun, not a security hole — the WORST case is a
     *      legitimate upgrade silently failing to arm, never an unauthorized one succeeding.
     */
    function _cancelPendingUpgradeOnOwnerChange() internal {
        if (pendingImplementation != address(0)) {
            emit UpgradeCancelled(pendingImplementation);
            pendingImplementation = address(0);
            upgradeRequestedAt = 0;
        }
    }

    // ============ Admin: Upgrade Timelock (owner self-call + timelock) ============
    function requestUpgrade(address newImplementation) external onlySelf {
        if (newImplementation == address(0)) revert ZeroAddress();
        if (newImplementation.code.length == 0) revert InvalidImplementation();
        pendingImplementation = newImplementation;
        upgradeRequestedAt = block.timestamp;
        emit UpgradeRequested(newImplementation, block.timestamp + UPGRADE_TIMELOCK);
    }

    function cancelUpgrade() external onlySelf {
        if (pendingImplementation == address(0)) revert NoUpgradePending();
        address cancelled = pendingImplementation;
        pendingImplementation = address(0);
        upgradeRequestedAt = 0;
        emit UpgradeCancelled(cancelled);
    }

    // ============ ERC-1271 / ERC-7739 ============
    /**
     * @dev ERC-1271 is `isValidSignature` below, which implements ONLY the ERC-7739 `TypedDataSign`
     *      workflow (`assertion ‖ APP_DOMAIN_SEPARATOR ‖ contentsHash ‖ contentsDescr ‖ uint16(len)`)
     *      — see that function for the full rationale, including why the `PersonalSign` workflow is
     *      deliberately NOT implemented (an ERC-7739 spec deviation, recorded there).
     *
     *      WHY TypedDataSign (blind-signing mitigation): a plain ERC-1271 wallet approves any
     *      32-byte hash at face value, so a malicious dApp can present a settlement-order digest or
     *      a Permit2 digest as a "sign in" challenge and the user has no way to tell. For a
     *      WELL-FORMED `contentsDescr` (one {isValidSignature} accepts — see its degenerate-descr note for the
     *      precise boundary), `TypedDataSign` forces the signing owner to sign a digest that is
     *      itself built from BOTH the requesting app's domain separator and this wallet's own
     *      domain, so an assertion produced for app A's digest cannot also satisfy app B's, and one
     *      produced under wallet W's domain cannot satisfy wallet W''s. The wallet still cannot
     *      render the contents — that remains the signer UI's job — but replay across domains, the
     *      part that is actually solvable on-chain, is closed for well-formed envelopes.
     *
     *      BREAKING: this changes the ERC-1271 signature FORMAT. It is introduced pre-deployment
     *      precisely because it cannot be introduced later without invalidating every integration.
     *
     *      NOT the userOp path: {_validateSignature} is deliberately untouched. ERC-4337 challenges
     *      are `userOpHash`, computed by the EntryPoint over the op itself, so they are already
     *      domain-bound and must NOT be rewrapped (the bundler/EntryPoint would never produce a
     *      7739 envelope).
     */
    function _rawSignatureValidation(bytes32 hash, bytes calldata signature) internal view override returns (bool) {
        // Same owner-verification dispatch as the 4337 path (see {_verifyOwnerSignature}) => ERC-1271
        // enforces the identical rule the userOp path enforces for whichever owner the wrapper
        // names — UV required for a passkey owner (WebAuthn), low-S ECDSA recovery for an
        // address owner: an off-chain approval is never cheaper to produce than a userOp approval.
        return _verifyOwnerSignature(hash, signature);
    }

    /**
     * @notice Integrators MUST sign orders via `eth_signTypedData` using the FULL EIP-712 type
     *         string in `contentsDescr` (e.g. `"Order(address account,...)"`) — NEVER just the bare
     *         type NAME (`"Order"`). `personal_sign` is not supported and returns `0xffffffff`.
     * @dev This is a FULL REIMPLEMENTATION of
     *      the `TypedDataSign` half of {ERC7739Upgradeable-isValidSignature} (mirroring OZ's
     *      private, hence not directly callable, `_isValidNestedTypedDataSignature` — OZ's
     *      contracts-upgradeable package, utils/cryptography/signers/
     *      draft-ERC7739Upgradeable.sol:66-103), NOT a narrowing filter layered on top of
     *      `super.isValidSignature`.
     *
     *      EARLIER MISTAKE (kept as a record so it is not repeated): the first version of this
     *      fix called `super.isValidSignature` as an acceptance oracle and then tried to tell, after
     *      the fact, whether its OR of `TypedDataSign` / `PersonalSign` had passed via the
     *      `TypedDataSign` branch by checking `hash == appSeparator.toTypedDataHash(contentsHash)`.
     *      That check is VACUOUS for any real EIP-712 digest: `toTypedDataHash(a, c) ==
     *      keccak256(0x1901 ‖ a ‖ c)` is exactly the shape every EIP-712 digest already has, and
     *      `appSeparator` / `contentsHash` are public values an attacker can read off the target
     *      app — no preimage is needed. An attacker who tricks the victim into
     *      `personal_sign`-ing a REAL order digest, then appends the (public) `appSeparator ‖
     *      contentsHash ‖ contentsDescr ‖ len` suffix to that bare assertion, produces a signature
     *      that (a) OZ's `PersonalSign` branch accepts, because it passes the ENTIRE signature
     *      buffer to `_rawSignatureValidation` and `WebAuthn.tryDecodeAuth` tolerates trailing
     *      bytes after a well-formed assertion, and (b) the old narrowing check waved through,
     *      because the identity it tested holds by construction whenever `hash` is already a real
     *      EIP-712 digest of that `appSeparator` / `contentsHash` pair. FIX: stop calling `super`
     *      as an oracle; verify the owner directly against the reconstructed nested digest using
     *      ONLY the decoded inner signature slice (see step 4 below) — that binding is what
     *      actually closes this, not any post-hoc structural inference.
     *
     *      A FOLLOW-ON GAP, since closed (CRITICAL): an intermediate fix gated `contentsDescr` on
     *      `bytes(contentsDescr).length == 0` before feeding it into
     *      {ERC7739Utils-typedDataSignStructHash}. That gate rejects only the EMPTY string —
     *      `typedDataSignStructHash` actually short-circuits to `bytes32(0)` (WITHOUT ever hashing
     *      in `contentsHash` or `domainBytes`) whenever `decodeContentsDescr` yields an EMPTY
     *      `contentsName`, for a broader class of NON-empty strings too — see OZ's contracts
     *      package, utils/cryptography/draft-ERC7739Utils.sol:169-207 `decodeContentsDescr`.
     *
     *      `decodeContentsDescr` picks a mode from the LAST byte of `contentsDescr`:
     *        - IMPLICIT (last byte is `)`): scans FORWARD for the first `(`; name = everything
     *          before it. Empty if that `(` is at index 0, or a forbidden byte
     *          (space/comma/`(`/`)`/`\0`) is hit before any `(` is found (every implicit-mode
     *          string ends in the forbidden byte `)`, so this loop always terminates).
     *        - EXPLICIT (last byte is anything else): scans BACKWARD for the LAST `)` in the
     *          string; name = everything after it. Empty if a forbidden byte is hit scanning
     *          backward before any `)` is found — INCLUDING the case where the string contains no
     *          `)` at all, in which case the scan simply exhausts the string. `"Order"` (bare type
     *          NAME instead of full type STRING — the single most likely frontend integration
     *          mistake) collapses exactly this way: it has neither a `)` nor a forbidden byte
     *          anywhere, so the backward scan runs off the front and returns empty.
     *
     *      DO NOT special-case on string shape as a "fast reject" (e.g. "no trailing `)`" or
     *      "starts with `("` imply degenerate) — an EARLIER version of this very comment did that
     *      and was WRONG, refuted by direct execution. Whenever explicit mode finds a `)` at all,
     *      the resulting name is PROVABLY non-empty (the branch requires the last byte to not be
     *      `)`, so there is always >=1 byte after any `)` explicit mode finds) — meaning strings
     *      that look nothing like `Name(Type)` can still bind correctly. Verified by direct
     *      execution (isValidSignature returns `0x1626ba7e`, contentsHash/domainBytes correctly
     *      bound) for: `")Order"` (name=`"Order"`, type=`")"`), `"Order(address a)Order"`
     *      (name=`"Order"`, type=`"Order(address a)"`), `"(foo)X"` (name=`"X"`, type=`"(foo)"`),
     *      `"()X"` (name=`"X"`, type=`"()"`), `"Order(uint256 a)Name"` (name=`"Name"`,
     *      type=`"Order(uint256 a)"`) — see test/StarzipWallet_personalsign.test.ts's
     *      "explicit mode" tests. The ONLY correct collapse test is the one this function performs:
     *      compute `structHash` and compare to `bytes32(0)`.
     *
     *      IMPACT when it collapses: the nested digest becomes
     *      `appSeparator.toTypedDataHash(bytes32(0))` — a CONSTANT depending on neither
     *      `contentsHash` (the specific order) nor `domainBytes` (this wallet's own
     *      name/version/chainId/verifyingContract/salt). A single signature an owner ever produced
     *      under a degenerate descr for a given app domain becomes a universal key: it authorizes
     *      ANY `contentsHash` (any order — any amount, nonce, side) under that app domain,
     *      replayable without limit, AND — because `domainBytes` never enters the hash either —
     *      accepted by ANY wallet that owner also controls, regardless of that wallet's own
     *      address. Removing that owner (see {removeOwnerAtIndex}) does not revoke an
     *      already-produced signature (removal only stops NEW signatures from that key). Executed
     *      proof, reproduced against both the original and the intermediate fix — both vulnerable;
     *      the CURRENT test/StarzipWallet_personalsign.test.ts degenerate-descr suite pins the corrected
     *      (rejecting) behavior instead: 7 degenerate-descr strings all collapsed, one signature
     *      authorized two different orders, the same signature was accepted by two different
     *      wallets, and a `settleOrders` E2E succeeded and drained.
     *
     *      FIX: gate on the STRUCT HASH itself (computed once, reused for the final digest below),
     *      not on a proxy for it. `structHash == bytes32(0)` is the precise, complete condition
     *      under which OZ's struct-hash function refuses to bind `contentsHash`/`domainBytes` —
     *      checking it directly subsumes the old length check entirely: no well-formed
     *      `contentsDescr` (non-empty `contentsName`) ever produces `structHash == 0`.
     *
     *      RESIDUAL (accepted, NOT closed on-chain — recorded so it isn't rediscovered as a "new"
     *      finding): any `contentsDescr` that decodes to a real, non-empty `contentsName`/
     *      `contentsType` is treated as valid by this check, EVEN IF its human-readable text does
     *      not honestly describe `contentsHash`'s actual contents — or is
     *      internally nonsensical relative to the visible string, as the explicit-mode examples
     *      above show (`")Order"` decodes to name=`"Order"`, type=`")"`, which a human reading the
     *      raw string would not expect). This wallet only verifies that `contentsDescr` participates
     *      STRUCTURALLY in the signed hash (so a degenerate/absent descr can no longer forge a
     *      signature for arbitrary content); it cannot verify that descr's text is an honest,
     *      internally-consistent label. That remains a signer-UI / client-trust problem, same as the
     *      wallet's inability to render `execute`'s calldata (see the call-policy note on {execute}).
     *
     *      Workflow (identical inputs/outputs to OZ's private helper, reimplemented on the PUBLIC
     *      `ERC7739Utils` library so it is independently auditable against node_modules):
     *      1. ERC-7739 support probe (`0x7739…7739` + empty signature) -> `0x77390001`, unchanged.
     *      2. Decode `signature` as `innerSignature ‖ appSeparator ‖ contentsHash ‖ contentsDescr ‖
     *         uint16(len)` via {ERC7739Utils-decodeTypedDataSig}. Require `hash ==
     *         appSeparator.toTypedDataHash(contentsHash)` (the caller-supplied `hash` IS the app's
     *         digest, by definition of how any ERC-1271 caller invokes this function).
     *      3. Compute `structHash = ERC7739Utils.typedDataSignStructHash(contentsDescr,
     *         contentsHash, domainBytes)` from this wallet's OWN domain (`eip712Domain()`). Reject
     *         if `structHash == 0` (the degenerate-descr gate above).
     *      4. Verify the owner named by `innerSignature`'s `SignatureWrapper.ownerIndex` against
     *         `appSeparator.toTypedDataHash(structHash)` using ONLY `innerSignature` — the decoded
     *         prefix, NOT the full `signature` buffer. THE ACTUAL load-bearing protections are
     *         (i) reconstructing this digest from THIS WALLET'S OWN domain (`eip712Domain()`, never
     *         attacker-supplied) combined with `appSeparator` / `structHash` decoded from the
     *         signature, and (ii) never implementing (nor OR-ing in) the `PersonalSign` workflow,
     *         which binds a DIFFERENT, weaker digest that drops the requesting app's domain
     *         entirely. Using `innerSignature` instead of the full `signature` buffer here is
     *         DEFENSE IN DEPTH ONLY for the passkey/WebAuthn branch, not what closes round 1's
     *         exploit: verified by mutation testing — substituting `signature` for `innerSignature`
     *         on this line compiles, and EVERY test in both test/StarzipWallet_erc1271.test.ts and
     *         test/StarzipWallet_personalsign.test.ts still passes (0 failures). The reason:
     *         `WebAuthn.tryDecodeAuth` decodes from offset 0, so when the inner slice decodes
     *         successfully, the full buffer decodes to the IDENTICAL `WebAuthnAuth` struct — the
     *         appended suffix bytes fall after the struct's declared dynamic-field boundaries and
     *         are never read. What genuinely cannot be satisfied by a mismatched envelope is the
     *         CHALLENGE inside that struct (`_validateChallenge` requires `clientDataJSON` to
     *         encode this exact nested digest) — and that digest is exactly (i)+(ii) above,
     *         independent of which buffer was sliced.
     *
     *      ERC-7739 SPEC DEVIATION (recorded, not silently non-compliant): ERC-7739 says "If the
     *      signature contains the correct data to reconstruct the hash, the isValidSignature
     *      function MUST perform the TypedDataSign workflow. Otherwise, the isValidSignature
     *      function MUST perform the PersonalSign workflow." This wallet implements ONLY the
     *      TypedDataSign workflow — when a signature does not decode as (a well-formed)
     *      TypedDataSign, it returns `0xffffffff` instead of attempting PersonalSign verification.
     *      This product has no PersonalSign use case (every integration — TradeSettlementV1 orders,
     *      session-key auths — signs typed data), and this wallet's ERC-1271 approvals are
     *      UNBOUNDED: TradeSettlementV1 Path A (`_authorizeOrderSig`) applies NO session-key spend
     *      cap to an account's own signature, so a single accepted opaque-hash approval is a
     *      full-balance drain, not a capped one. INTEROPERABILITY COST: a dApp/library that expects
     *      ERC-7739 wallets to answer `personal_sign`-style challenges will get `0xffffffff` from
     *      this wallet and must use `eth_signTypedData` (TypedDataSign) instead — see the notice
     *      tag above.
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4) {
        if (hash == 0x7739773977397739773977397739773977397739773977397739773977397739 && signature.length == 0) {
            return bytes4(0x77390001);
        }

        (
            bytes calldata innerSignature,
            bytes32 appSeparator,
            bytes32 contentsHash,
            string calldata contentsDescr
        ) = ERC7739Utils.decodeTypedDataSig(signature);
        if (hash != appSeparator.toTypedDataHash(contentsHash)) {
            return bytes4(0xffffffff);
        }

        (
            ,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,

        ) = eip712Domain();
        bytes32 structHash = ERC7739Utils.typedDataSignStructHash(
            contentsDescr,
            contentsHash,
            abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt)
        );
        // Degenerate-descr gate: a degenerate contentsDescr collapses structHash to 0 regardless of
        // contentsHash/domainBytes — see the NatSpec above for the full mechanism and impact.
        if (structHash == bytes32(0)) {
            return bytes4(0xffffffff);
        }
        bool valid = _rawSignatureValidation(appSeparator.toTypedDataHash(structHash), innerSignature);
        return valid ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    /// @dev Constant EIP-712 domain — see {EIP712_NAME}. Never touches EIP712 storage.
    function _EIP712Name() internal pure override returns (string memory) {
        return EIP712_NAME;
    }

    /// @dev Constant EIP-712 domain — see {EIP712_VERSION}. Never touches EIP712 storage.
    function _EIP712Version() internal pure override returns (string memory) {
        return EIP712_VERSION;
    }

    // ============ Internal: signature dispatch ============
    /**
     * @dev Off-chain / ABI documentation for the encoding {_decodeSignatureWrapper} parses:
     *      `userOp.signature` and the ERC-1271 `signature` argument are `abi.encode` of THIS
     *      struct as the sole top-level argument, i.e.
     *      `abi.encode(SignatureWrapper({ownerIndex: ..., signatureData: ...}))`. `signatureData`
     *      is itself either a 65-byte secp256k1 `(r, s, v)` signature (for a 32-byte / address
     *      owner) or an `abi.encode`d `WebAuthn.WebAuthnAuth` assertion (for a 64-byte / passkey
     *      owner) — see {_verifyOwnerSignature}.
     */
    struct SignatureWrapper {
        uint256 ownerIndex;
        bytes signatureData;
    }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256) {
        return _verifyOwnerSignature(userOpHash, userOp.signature) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    /**
     * @dev Decode `signature` as `abi.encode(SignatureWrapper)` WITHOUT `abi.decode` — `abi.decode`
     *      can only materialize a dynamic `bytes` field into MEMORY, but the passkey branch of
     *      {_verifyOwnerSignature} must hand `signatureData` to `WebAuthn.tryDecodeAuth` as
     *      CALLDATA (that function's signature requires it — see its own doc). This mirrors the
     *      same calldata-preservation technique {isValidSignature}'s ERC-7739 decode already uses
     *      for exactly the same reason.
     *
     *      Fixed 128-byte head, per the standard Solidity ABI encoding of a lone dynamic-tuple
     *      argument (verified against `abi.encode(SignatureWrapper(...))`'s actual output):
     *        [0:32)    = 0x20 (offset to the tuple's own data — constant for a lone dynamic arg)
     *        [32:64)   = ownerIndex
     *        [64:96)   = 0x40 (offset, relative to byte 32, to signatureData's length word —
     *                    constant for this fixed 2-field struct)
     *        [96:128)  = signatureData.length
     *        [128:...) = signatureData bytes
     *      Both constant offset words are checked, so this function never accepts an
     *      equivalent-but-differently-offset ABI blob. NOTE: this does NOT mean the ONE
     *      canonical encoding is the only thing accepted
     *      — verified by direct execution, trailing bytes appended AFTER byte
     *      `128 + signatureData.length` are silently ignored (never read, never included in
     *      `signatureData`) and the input still validates normally. This function only pins the
     *      HEAD layout and the declared `signatureData` slice; it does not assert that
     *      `signature.length == 128 + signatureData.length` exactly. Harmless on its own — see
     *      {isValidSignature}'s NatSpec for why an accepted-with-trailing-garbage buffer cannot
     *      be turned into a cross-context replay by itself — but recorded here so a future reader
     *      does not rely on "canonical-only" as an invariant this function actually enforces.
     *
     *      Declines (returns `ok = false`) rather than reverting for any input too short to
     *      possibly be well-formed, or whose declared `signatureData` length would run past the
     *      buffer — this is required so the caller (validateUserOp's dispatch,
     *      {_verifyOwnerSignature}) can return `SIG_VALIDATION_FAILED` / `0xffffffff` instead of
     *      reverting, matching this wallet's existing "malformed input is a failed verification,
     *      not an exception" posture (see {_verifyPasskey}'s own such note, inherited unchanged).
     */
    function _decodeSignatureWrapper(
        bytes calldata signature
    ) internal pure returns (bool ok, uint256 ownerIndex, bytes calldata signatureData) {
        if (signature.length < 128) return (false, 0, signature[0:0]);
        if (uint256(bytes32(signature[0:32])) != 0x20 || uint256(bytes32(signature[64:96])) != 0x40) {
            return (false, 0, signature[0:0]);
        }
        ownerIndex = uint256(bytes32(signature[32:64]));
        uint256 len = uint256(bytes32(signature[96:128]));
        // `len` is attacker-controlled calldata. The
        // previous form (`128 + len > signature.length`) is checked arithmetic, so any
        // `len >= 2**256 - 128` panics (0x11) instead of declining — confirmed on-chain as
        // `FailedOpWithRevert(0, "AA23 reverted", Panic 0x11)`, which validateUserOp must NEVER
        // do (see this function's own "declines rather than reverting" NatSpec above). Rewritten
        // as a subtraction, which cannot itself overflow/underflow: `signature.length >= 128` is
        // already established by the length check at the top of this function.
        if (len > signature.length - 128) return (false, 0, signature[0:0]);
        signatureData = signature[128:128 + len];
        ok = true;
    }

    /**
     * @dev Single owner-signature verifier shared by the ERC-4337 path ({_validateSignature}) and
     *      the ERC-1271/7739 path ({_rawSignatureValidation}): decode the `SignatureWrapper`,
     *      look up the named owner, and dispatch on its ENCODED LENGTH (exhaustive — see
     *      {_registerOwner}, which is the only path that ever writes {ownerAtIndex} and enforces
     *      exactly 32 or 64 bytes):
     *        - 32 bytes (EOA-style address owner): ECDSA-recover `digest` with
     *          `ECDSA.tryRecoverCalldata` (OZ's `ECDSA` — REJECTS malleable/high-`s` signatures
     *          internally, so low-S is enforced for free) and compare to the stored address.
     *        - 64 bytes (P-256 passkey owner): delegate to {_verifyPasskeyOwner}, the same
     *          WebAuthn/P-256 verification path this wallet has always used, now parameterized by
     *          WHICH owner's (x, y) to check against instead of a single wallet-wide key.
     *        - 0 bytes (unregistered `ownerIndex` — never written, or since removed): returns
     *          `false` WITHOUT reverting. This is the requirement that a
     *          nonexistent-owner signature produce `SIG_VALIDATION_FAILED` / `0xffffffff`, not a
     *          revert, from both {validateUserOp} and {isValidSignature} — an EntryPoint
     *          simulation must be able to observe "this signature does not authorize" as a normal
     *          negative result, not a thrown exception.
     *      Any other stored length is unreachable (see {_registerOwner}), so there is no `else`
     *      branch to fall through to — the length dispatch above is exhaustive by construction.
     */
    function _verifyOwnerSignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        (bool decodedOk, uint256 ownerIndex, bytes calldata signatureData) = _decodeSignatureWrapper(signature);
        if (!decodedOk) return false;

        bytes memory ownerBytes = ownerAtIndex[ownerIndex];
        if (ownerBytes.length == 32) {
            address ownerAddr = abi.decode(ownerBytes, (address));
            (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecoverCalldata(digest, signatureData);
            return err == ECDSA.RecoverError.NoError && recovered == ownerAddr;
        }
        if (ownerBytes.length == 64) {
            (bytes32 x, bytes32 y) = abi.decode(ownerBytes, (bytes32, bytes32));
            return _verifyPasskeyOwner(digest, signatureData, x, y);
        }
        return false;
    }

    /**
     * @dev WebAuthn/P-256 verifier for a SINGLE named owner's (x, y) — the exact same verification
     *      this wallet has always performed, now taking the key to check against as a parameter
     *      instead of reading a single wallet-wide `publicKeyX`/`publicKeyY`. Decode the WebAuthn
     *      assertion and verify it against `(x, y)` with `challenge` and requireUV = true (the
     *      4-arg {WebAuthn.verify} overload). Does not revert for ordinary malformed input (a bad
     *      assertion is a failed verification, not an exception, which is required inside 4337
     *      validation and desirable for ERC-1271).
     *
     *      A crafted `typeIndex` used to reach OZ's
     *      `WebAuthn.verify` -> `_validateExpectedTypeHash` unbounded. With a 37+-byte
     *      `authenticatorData` (required — {WebAuthn-verify}'s leading
     *      `authenticatorData.length > 36 &&` short-circuits `_validateExpectedTypeHash` entirely
     *      otherwise), `typeIndex = type(uint256).max` did NOT revert (`add(typeIndex, 20)` wraps
     *      to `19` and the subsequent `mload` lands back inside already-allocated memory, so the
     *      type-string comparison just failed cleanly -> `false`, observed on-chain as EntryPoint
     *      `FailedOp(0, "AA24 signature error")` for the userOp path), while `typeIndex = 2**255`
     *      DID revert (`add` does not wrap there — 2**255 plus a small pointer stays under
     *      2**256 — so `mload` was asked to read from a genuinely huge address, and the resulting
     *      memory-expansion gas cost, not an arithmetic overflow/panic, exhausted the call;
     *      observed on-chain as EntryPoint `FailedOpWithRevert(0, "AA23 reverted", "0x")`) — a
     *      direct contradiction of this function's own "declines rather than reverting" posture
     *      (an earlier version of this comment additionally claimed "never reverts"
     *      unconditionally, and separately mis-attributed the mechanism to "arithmetic overflow",
     *      both also false). FIX: bound `typeIndex` against `clientDataJSON`'s actual length
     *      BEFORE calling into `WebAuthn.verify` (see the check immediately below) — this closes
     *      the revert without touching `WebAuthn.sol` itself, since a well-formed assertion's
     *      `typeIndex` always points strictly inside `clientDataJSON` by construction.
     *
     *      HISTORY (an earlier defense-in-depth check, since REMOVED — recorded so it is not
     *      re-added without re-deriving the justification): that check required
     *      `_signature.length` to exactly equal the canonical `abi.encode` length recomputed from
     *      the decoded dynamic fields, closing the general "valid assertion + trailing garbage"
     *      class the original exploit relied on. It was removed because: (1) it contributed
     *      NOTHING beyond what {isValidSignature}'s fixes already close cryptographically —
     *      a mutation-matrix comparison confirmed the PROBE-A exploit stays blocked with this length
     *      check removed entirely, because `isValidSignature` now verifies the owner directly
     *      against the correctly reconstructed digest (built from THIS WALLET'S OWN domain, never
     *      the OR'd-in PersonalSign workflow's weaker one) — see {isValidSignature}'s NatSpec for
     *      the mutation-tested attribution of what is and is not load-bearing there; (2) it cost
     *      +654 gas per ERC-1271 verification for zero closed attack surface; (3) it touched the
     *      ERC-4337 money path (`_validateSignature` -> here), which was explicitly out of scope
     *      for that change. It was also NOT canonical-encoding-strict as its NatSpec claimed — a
     *      non-canonical encoding with swapped dynamic-field tail order but equal total length
     *      still passed it, so the claim was inaccurate on top of being unnecessary. Removed rather
     *      than fixed, per the above cost/benefit.
     */
    function _verifyPasskeyOwner(
        bytes32 _challenge,
        bytes calldata _signature,
        bytes32 x,
        bytes32 y
    ) internal view returns (bool) {
        // Gracefully reject malformed assertions instead of reverting (see the caveat above).
        (bool ok, WebAuthn.WebAuthnAuth calldata auth) = WebAuthn.tryDecodeAuth(_signature);
        if (!ok) return false;
        // `tryDecodeAuth` accepts any `typeIndex`
        // (it is just a `uint256` field, not range-checked against `clientDataJSON`). OZ's
        // `WebAuthn.verify` -> `_validateExpectedTypeHash` reads `clientDataJSON` at that offset
        // via raw assembly `mload`, and `typeIndex = 2**255` reverts the whole call on
        // memory-expansion gas (confirmed on-chain: `FailedOpWithRevert(0, "AA23 reverted",
        // "0x")`) rather than returning `false` — the same "decline, never revert" posture this
        // function documents above (the `type(uint256).max` case happens to wrap harmlessly and
        // was previously the only one exercised). Bounding `typeIndex` against the actual
        // `clientDataJSON` length before it ever reaches OZ's assembly closes this without
        // touching `WebAuthn.sol` itself: a well-formed assertion's `typeIndex` always points
        // strictly inside `clientDataJSON` (it names the offset of `"type":"webauthn.get"`
        // inside that JSON string), so this can never reject a legitimate payload.
        if (auth.typeIndex > bytes(auth.clientDataJSON).length) return false;
        // `challengeIndex` is the OTHER attacker-controlled index into `clientDataJSON`, left
        // unbounded by the bound above, which only covered `typeIndex`. OZ's `WebAuthn._validateChallenge` computes
        // `challengeIndex + bytes(expectedChallenge).length` (`"challenge":"` + base64url(32-byte
        // challenge) + `"` = 57 bytes) in CHECKED Solidity arithmetic before calling
        // `Bytes.slice`, so any `challengeIndex >= type(uint256).max - 56` overflows that
        // addition and Panics (0x11) — the identical "decline, never revert" violation as the
        // typeIndex case, just via checked-arithmetic overflow instead of memory-expansion gas.
        // Bounding it against `clientDataJSON`'s actual length before it ever reaches OZ's code
        // closes this the same way: a well-formed assertion's `challengeIndex` always points
        // strictly inside `clientDataJSON`, so this can never reject a legitimate payload.
        if (auth.challengeIndex > bytes(auth.clientDataJSON).length) return false;
        return WebAuthn.verify(abi.encodePacked(_challenge), auth, x, y);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlySelf {
        if (pendingImplementation == address(0)) revert NoUpgradePending();
        if (newImplementation != pendingImplementation) revert NotPendingImplementation();
        if (block.timestamp < upgradeRequestedAt + UPGRADE_TIMELOCK) revert TimelockActive();
        // Bound the far side too. See UPGRADE_GRACE_PERIOD.
        if (block.timestamp > upgradeRequestedAt + UPGRADE_TIMELOCK + UPGRADE_GRACE_PERIOD) {
            revert UpgradeExpired();
        }
        pendingImplementation = address(0);
        upgradeRequestedAt = 0;
    }

    // ============ Token Receiver ============
    // ERC721Holder / ERC1155Holder (both @custom:stateless — zero storage-layout impact, safe
    // across the UUPS boundary) let this wallet be the recipient of safeTransferFrom / _safeMint,
    // e.g. the platform's own StarGenesis NFT. Without the onERC721Received / onERC1155Received /
    // onERC1155BatchReceived callbacks they provide, any safe transfer into the wallet reverts.

    receive() external payable {}
}
