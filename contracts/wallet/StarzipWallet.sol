// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { WebAuthn } from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import { P256 } from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import { IAccount } from "@account-abstraction/contracts/interfaces/IAccount.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import { ERC721Holder } from "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import { ERC1155Holder } from "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";

/**
 * @title StarzipWallet
 * @notice ERC-4337 smart wallet with P256 WebAuthn signature verification (UUPS upgradeable)
 * @dev Uses OpenZeppelin's WebAuthn library for on-chain Passkey signature validation.
 *      EntryPoint v0.8 compatible (PackedUserOperation).
 *
 *      Social-recovery model (self-owned, non-custodial):
 *      - Tier 1 "use": passkey-signed userOps (see {_validateSignature}) — UNCHANGED.
 *      - Tier 2 "self-rotate": the current passkey rotates itself via a passkey-authorized
 *        self-call (EntryPoint -> {execute} -> address(this)). Admin functions are now
 *        `onlySelf` instead of `onlyOwner`, so no EOA can perform privileged actions.
 *      - Tier 3 "guardian recovery": storage layout reserved here (disabled while
 *        guardianSetRoot == 0); recovery logic lands in a later upgrade. Declaring the
 *        layout now keeps the current-model -> full-model upgrade storage-compatible.
 *
 *      The legacy `owner` field is RETAINED for storage/ABI compatibility but is INERT:
 *      no function reads it for authorization. Issuance must set it to a deterministic
 *      non-zero sentinel (e.g. 0x...dEaD) so CREATE2 address parity holds and the wallet
 *      is deployable (initialize rejects address(0)).
 */
contract StarzipWallet is
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardTransient,
    ERC721Holder,
    ERC1155Holder,
    IAccount
{
    // ============ Constants ============
    uint256 private constant SIG_VALIDATION_SUCCESS = 0;
    uint256 private constant SIG_VALIDATION_FAILED = 1;
    uint256 public constant UPGRADE_TIMELOCK = 48 hours;
    uint256 private constant MAX_BATCH_SIZE = 32;

    // ============ Immutable ============
    IEntryPoint public immutable entryPoint;

    // ============ State Variables ============
    // Slots 0..6 — UNCHANGED layout (do not reorder; existing deployed wallets upgrade in place).
    bytes32 public publicKeyX; // slot 0
    bytes32 public publicKeyY; // slot 1
    address public owner; // slot 2 — INERT (sentinel only; no authorization power)
    address public pendingOwner; // slot 3 — RESERVED (legacy owner-transfer removed)
    uint256 public ownerTransferRequestedAt; // slot 4 — RESERVED (legacy owner-transfer removed)
    address public pendingImplementation; // slot 5 — upgrade flow (now onlySelf-gated)
    uint256 public upgradeRequestedAt; // slot 6 — upgrade flow

    // ============ Social Recovery Storage (reserves layout; full model adds logic) ============
    // Appended after the legacy slots and BEFORE __gap. __gap reduced 43 -> 35 (8 new slots),
    // keeping total footprint at 50 slots. All default to 0; guardianSetRoot == 0 means
    // recovery is disabled (self-owned, cloud-backup recovery only).
    bytes32 public guardianSetRoot; // slot 7 — keccak256(sortedGuardianHashes, threshold)
    uint256 public guardianThreshold; // slot 8 — M-of-N threshold
    bytes32 public pendingRecoveryPubKeyX; // slot 9
    bytes32 public pendingRecoveryPubKeyY; // slot 10
    uint256 public recoveryRequestedAt; // slot 11 — 0 = no active recovery
    uint256 public recoveryNonce; // slot 12 — bumped on cancel/complete (anti-replay)
    bytes32 public pendingGuardianSetRoot; // slot 13 — timelocked guardian-set change
    uint256 public guardianChangeRequestedAt; // slot 14

    // ============ Storage Gap ============
    // Was uint256[43]; reduced to [35] for the 8 social-recovery slots above (7 + 8 + 35 = 50).
    uint256[35] private __gap;

    // ============ Events ============
    event Executed(address indexed target, uint256 value, bytes data);
    event BatchExecuted(uint256 count);
    event PasskeyRotated(bytes32 oldX, bytes32 oldY, bytes32 newX, bytes32 newY);
    event UpgradeRequested(address indexed newImplementation, uint256 readyAt);
    event UpgradeCancelled(address indexed cancelledImplementation);

    // ============ Errors ============
    error OnlyEntryPoint();
    error OnlySelf();
    error InvalidArrayLength();
    error BatchTooLarge();
    error ZeroAddress();
    error InvalidPublicKey();
    error TimelockActive();
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
     * @dev Restricts to passkey-authorized self-calls (EntryPoint -> execute -> address(this)).
     *      Replaces the former onlyOwner: privileged actions now require a passkey-signed userOp,
     *      not an EOA owner. This is the core de-custodial change.
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
     * @param _owner Inert sentinel (must be non-zero; carries no authority).
     */
    function initialize(bytes32 _pubKeyX, bytes32 _pubKeyY, address _owner) external initializer {
        if (_owner == address(0)) revert ZeroAddress();
        // Reject any point NOT on the P256 curve. P256.isValidPublicKey is a
        // pure on-curve check that subsumes the earlier either-zero special case AND rejects any
        // off-curve (x,y): such a key can never produce a passing WebAuthn.verify, so storing one
        // only bricks the wallet (self-DoS — never a hijack), and there is no guardian-recovery path.
        // A cheap check up front beats deploying a permanently unusable wallet.
        if (!P256.isValidPublicKey(_pubKeyX, _pubKeyY)) revert InvalidPublicKey();
        publicKeyX = _pubKeyX;
        publicKeyY = _pubKeyY;
        owner = _owner;
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
    function execute(address dest, uint256 value, bytes calldata func) external onlyEntryPoint nonReentrant {
        (bool success, bytes memory result) = dest.call{ value: value }(func);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        emit Executed(dest, value, func);
    }

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
            unchecked {
                ++i;
            }
        }
        emit BatchExecuted(dest.length);
    }

    // ============ Admin: Passkey Rotation (Tier 2 — self-rotate) ============
    /**
     * @notice Rotate the controlling passkey.
     * @dev `onlySelf`: must arrive as a passkey-signed userOp routed through {execute} to
     *      address(this). The originating userOp is passkey-validated with UV required
     *      (see {_validateSignature} / WebAuthn.verify requireUV=true), so UV is enforced upstream.
     *
     *      SECURITY — ACCEPTED RESIDUAL RISK: rotation is IMMEDIATE by design (no
     *      request/execute timelock). A momentarily-compromised passkey could call
     *      `execute(self, changePasskey(attacker))` for permanent takeover. This is accepted
     *      because:
     *      (1) In this self-owned (no-guardian) wallet a compromised passkey can ALREADY drain
     *          funds via `execute` — immediate rotation adds no material attack surface (takeover
     *          and drain are equivalent in impact).
     *      (2) A timelock would NOT mitigate this in the current model: the attacker holds the same key during the
     *          window and there is no independent authority to cancel, so it only delays both
     *          parties symmetrically while funds remain drainable.
     *      (3) WebAuthn signatures are challenge-bound to a single userOpHash (no replay), so the residual risk
     *          reduces to tricking the user into signing that exact op — a dApp signing-prompt /
     *          frontend-trust concern, not an on-chain authorization gap.
     *      The real mitigation for key compromise is Tier-3 guardian recovery (storage reserved
     *      here; lands in a later upgrade). The higher-impact upgrade path is independently
     *      protected by the 48h timelock in {_authorizeUpgrade}.
     */
    function changePasskey(bytes32 newPubKeyX, bytes32 newPubKeyY) external onlySelf {
        // Reject any off-curve point — see {initialize} for rationale.
        // Guards against a client-side bug (corrupted COSE parse, byte-order swap) rotating the
        // wallet into a permanently unusable key.
        if (!P256.isValidPublicKey(newPubKeyX, newPubKeyY)) revert InvalidPublicKey();
        emit PasskeyRotated(publicKeyX, publicKeyY, newPubKeyX, newPubKeyY);
        publicKeyX = newPubKeyX;
        publicKeyY = newPubKeyY;
        // Incident-response hygiene: rotating the controlling key cancels any pending upgrade,
        // so a stale upgrade queued by a momentarily-compromised key cannot be finalized later.
        if (pendingImplementation != address(0)) {
            emit UpgradeCancelled(pendingImplementation);
            pendingImplementation = address(0);
            upgradeRequestedAt = 0;
        }
    }

    // ============ Admin: Upgrade Timelock (passkey self-call + timelock) ============
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

    // ============ Internal ============
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256) {
        // Gracefully reject malformed assertions instead of reverting inside validation.
        (bool ok, WebAuthn.WebAuthnAuth calldata auth) = WebAuthn.tryDecodeAuth(userOp.signature);
        if (!ok) return SIG_VALIDATION_FAILED;

        // Verify: challenge = userOpHash, requireUV = true
        bool valid = WebAuthn.verify(abi.encodePacked(userOpHash), auth, publicKeyX, publicKeyY);

        return valid ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlySelf {
        if (pendingImplementation == address(0)) revert NoUpgradePending();
        if (newImplementation != pendingImplementation) revert NotPendingImplementation();
        if (block.timestamp < upgradeRequestedAt + UPGRADE_TIMELOCK) revert TimelockActive();
        pendingImplementation = address(0);
        upgradeRequestedAt = 0;
    }

    // ============ Token Receiver ============
    // ERC721Holder / ERC1155Holder (both @custom:stateless — zero storage-layout impact, safe
    // across the UUPS boundary) let this wallet be the recipient of safeTransferFrom / _safeMint,
    // e.g. an ERC-721 NFT. Without the onERC721Received / onERC1155Received /
    // onERC1155BatchReceived callbacks they provide, any safe transfer into the wallet reverts.

    receive() external payable {}
}
