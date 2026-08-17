// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import "./ERC20V1.sol";

/**
 * @title TokenFactory
 * @notice StarZip token issuance factory (Store Token distribution model).
 * @dev UUPS upgradeable. Single canonical line, clean redeploy. The
 *      allocation model is 3-way, carve-free, with supply locked at issuance
 *      via `ERC20V1.setMaxSupply` (no infinite-mint surface).
 *
 * 3-way allocation per issued token (permit-baked bp, admin min/max guides):
 *   - LAUNCHPAD          : held in ESCROW by this factory (not transferred to
 *                           the business) until `LaunchpadV1.createLaunchpad`
 *                           pulls it via `releaseEscrow`.
 *   - LIQUIDITY_RESERVE   : token-side market-making / liquidity reserve.
 *                           NOT the same concept as `LaunchpadV1.liquidityRecipient`,
 *                           which is the *fund* (USDT) liquidity recipient.
 *   - OWNER_VESTING       : routed to a per-token `TokenVestingWallet` clone,
 *                           released only after `LaunchpadV1.finalizeLaunchpad`
 *                           triggers `startVesting`.
 *
 * All bp values / escrow timeout / timelock delays are placeholders (0 or
 * conservative defaults) configured post-deploy via timelocked setters —
 * no economic constants are hardcoded in this contract.
 */
contract TokenFactory is
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    ReentrancyGuard,
    PausableUpgradeable,
    EIP712Upgradeable
{
    using SafeERC20 for IERC20;

    // ============ Constants (structural rails only — no economic values) ============
    uint256 public constant BASIS_POINTS = 10000;
    uint256 public constant MAX_NAME_LENGTH = 64;
    uint256 public constant MAX_SYMBOL_LENGTH = 16;
    uint256 public constant MAX_URI_LENGTH = 512;

    uint256 public constant MAX_DAILY_ISSUANCE = 20;
    uint256 public constant MAX_SUPPLY_PER_TOKEN = 1_000_000_000 * 1e18;

    uint256 public constant CONFIG_DELAY = 2 days;
    uint256 public constant ALLOCATION_GUIDE_DELAY = 2 days;

    /// @dev Timelock delay for staged UUPS upgrades.
    uint256 public constant UPGRADE_TIMELOCK_DELAY = 48 hours;

    /// @dev A staged upgrade is executable only inside
    ///      `[upgradeReadyAt, upgradeReadyAt + UPGRADE_GRACE_PERIOD]`. Matches TradeSettlementV1
    ///      and UpgradeableBeacon; without it the 48h notice is a one-time announcement rather than
    ///      a standing requirement.
    uint256 public constant UPGRADE_GRACE_PERIOD = 7 days;

    uint8 public constant ALLOCATION_BUCKET_COUNT = 3;
    uint8 public constant BUCKET_LAUNCHPAD = 0;
    uint8 public constant BUCKET_LIQUIDITY_RESERVE = 1;
    uint8 public constant BUCKET_OWNER_VESTING = 2;

    /// @notice admin cannot set LiquidityReserve.minBp = 0 (must always carve some floor)
    uint16 public constant LIQUIDITY_RESERVE_MIN_BP_FLOOR = 1;

    uint64 public constant MIN_OWNER_VESTING_DURATION = 30 days;
    uint64 public constant MAX_OWNER_VESTING_DURATION = 3650 days;

    /// @dev Structural sanity rails for the escrow reclaim timeout. The
    ///      actual value defaults to 0 (placeholder) and is configured post-deploy
    ///      via the timelocked `propose/executeEscrowTimeoutChange` pair.
    uint256 public constant MIN_ESCROW_TIMEOUT = 1 hours;
    uint256 public constant MAX_ESCROW_TIMEOUT = 180 days;

    bytes32 public constant ISSUE_PERMIT_TYPEHASH =
        keccak256(
            // solhint-disable-next-line max-line-length
            "IssuePermit(address businessAccount,string name,string symbol,uint256 totalSupply,string contractURI,uint16 launchpadBp,uint16 liquidityBp,uint16 ownerBp,address liquidityRecipient,uint64 ownerVestingCliff,uint64 ownerVestingDuration,address linkedLaunchpad,uint256 nonce,uint256 deadline)"
        );

    // ============ Structs ============

    struct AllocationGuide {
        uint16 minBp;
        uint16 maxBp;
    }

    struct AllocationRatios {
        uint16 launchpadBp;
        uint16 liquidityBp;
        uint16 ownerBp;
        address liquidityRecipient;
        uint64 ownerVestingCliff;
        uint64 ownerVestingDuration;
    }

    // ============ State ============

    address public erc20Beacon;
    address public platformTreasury;
    address public tradeSettlement;
    address public vestingWalletBeacon;

    uint256 public tokenCounter;
    bool public autoListOnExchange;
    address public permitSigner;

    mapping(address => uint256) public nonces;

    mapping(address => bool) public isIssuedToken;
    mapping(address => address) public tokenToBusiness;
    mapping(address => uint256) public tokenIssuedAt;
    mapping(uint256 => address) public tokenById;

    mapping(uint256 => uint256) public dailyIssuanceCount;

    /// @notice Per-token Owner Vesting wallet lookup.
    mapping(address => address) public tokenToVestingWallet;

    /// @notice Active min/max BP guide per allocation bucket.
    mapping(uint8 => AllocationGuide) public allocationGuides;
    mapping(uint8 => uint256) public allocationGuideUpdateTime;
    mapping(uint8 => AllocationGuide) public pendingAllocationGuides;

    /// @notice The single LaunchpadV1 address authorized to trigger Owner Vesting
    ///         AND to call `releaseEscrow` (this reuses the existing timelocked
    ///         pointer — no separate authorization channel).
    address public linkedLaunchpad;
    address public pendingLinkedLaunchpad;
    uint256 public linkedLaunchpadChangeTime;

    // ---- Timelock pendings (2-day) ----
    address public pendingBeacon;
    uint256 public beaconChangeTime;

    address public pendingTreasury;
    uint256 public treasuryChangeTime;

    address public pendingPermitSigner;
    uint256 public permitSignerChangeTime;

    address public pendingVestingWalletBeacon;
    uint256 public vestingWalletBeaconChangeTime;

    // ============ LAUNCHPAD bucket escrow ============

    /// @notice Amount of the LAUNCHPAD bucket held in custody by this factory for a
    ///         given token, awaiting `releaseEscrow` (via `linkedLaunchpad.createLaunchpad`)
    ///         or `reclaimEscrow` (business, after timeout). Zeroed once consumed.
    mapping(address => uint256) public launchpadEscrow;

    /// @notice Timestamp after which the business may `reclaimEscrow` if the launchpad
    ///         was never created for this token. `issuedAt + escrowTimeoutSeconds`.
    mapping(address => uint256) public escrowDeadline;

    /// @notice Consumption flag: true after `releaseEscrow` or `reclaimEscrow` succeeds, false
    ///         again after `restoreEscrow` re-funds it. Blocks double-release / double-reclaim
    ///         and (transitively, via `releaseEscrow`) a second `createLaunchpad` while a sale
    ///         is live for the same token.
    /// @dev NOT one-shot anymore: `restoreEscrow` clears this back to
    ///      `false` when a cancelled launchpad returns its unsold `saleAmount` to escrow,
    ///      making the token resellable — see {restoreEscrow}'s own doc comment.
    mapping(address => bool) public escrowConsumed;

    /// @notice Reclaim timeout applied to newly-issued tokens (placeholder 0 — see
    ///         `MIN_ESCROW_TIMEOUT`/`MAX_ESCROW_TIMEOUT`). Timelocked setter below.
    uint256 public escrowTimeoutSeconds;
    uint256 public pendingEscrowTimeoutSeconds;
    uint256 public escrowTimeoutChangeTime;

    // ---- setTradeSettlement 2-day timelock (appended) ----
    address public pendingTradeSettlement;
    uint256 public tradeSettlementChangeTime;
    // ---- Timelocked UUPS upgrade staging (appended) ----
    address public pendingImplementation;
    uint256 public upgradeReadyAt;

    /// @notice Per-token launchpad binding captured at issuance. Escrow release and
    ///         blacklist exemptions resolve through this immutable workflow binding,
    ///         not the mutable global `linkedLaunchpad` pointer.
    mapping(address => address) public tokenToLaunchpad;

    /// @notice Trade settlement endpoints remain authorized after rotation so they
    ///         can complete withdrawals for balances deposited before the change.
    mapping(address => bool) public authorizedTradeSettlements;

    /// @notice Resale-wait timeout applied when `restoreEscrow` returns a cancelled sale's
    ///         unsold LAUNCHPAD-bucket tokens to escrow: the token cannot be
    ///         resold via `LaunchpadV1.createLaunchpad` until `block.timestamp` clears the
    ///         `escrowDeadline` that call sets (`restoreEscrow`-time + `resaleWaitSeconds`).
    ///         Same fail-closed/timelocked pattern as `escrowTimeoutSeconds` (placeholder 0
    ///         until configured; `restoreEscrow` reverts while unset — see that function) and
    ///         reuses its `MIN_ESCROW_TIMEOUT`/`MAX_ESCROW_TIMEOUT` structural bounds: both are
    ///         "how long a token sits in this factory's custody before someone can act on it"
    ///         knobs.
    uint256 public resaleWaitSeconds;
    uint256 public pendingResaleWaitSeconds;
    uint256 public resaleWaitChangeTime;

    /// @notice True once `restoreEscrow` has ever re-funded `token`'s escrow — gates
    ///         `releaseEscrow`'s resale-wait check (see that function). A token's FIRST sale
    ///         still releases immediately after issuance (no wait — matches the earlier
    ///         behavior); only a RESALE (this flag true) must wait out `escrowDeadline`.
    ///         Never cleared back to `false` once set: after a token's first cancellation,
    ///         every subsequent cycle for it is a resale by definition.
    mapping(address => bool) public escrowIsResale;

    // ============ Storage Gap ============
    // Reserved storage slots for future upgrades — do not reorder or reuse.
    // Resale-wait change (this change): consumed 4 further slots (`resaleWaitSeconds` +
    // `pendingResaleWaitSeconds` + `resaleWaitChangeTime` + `escrowIsResale`) from the same
    // gap — [23] -> [19]. Fresh-redeploy premise (see LaunchpadV1's own gap comment) — not an
    // append-only constraint on an already-live proxy.
    uint256[19] private __gap; // was [25]; -2 (timelocked upgrade staging) -4 (resale wait)

    // ============ Events ============

    event TokenIssued(
        uint256 indexed tokenId,
        address indexed tokenAddress,
        address indexed businessAccount,
        address vestingWallet,
        uint16 launchpadBp,
        uint16 liquidityBp,
        uint16 ownerBp,
        address liquidityRecipient,
        uint64 ownerVestingCliff,
        uint64 ownerVestingDuration,
        uint256 totalSupply
    );

    event PlatformTreasuryUpdated(address indexed oldTreasury, address indexed newTreasury);
    event Erc20BeaconUpdated(address indexed oldBeacon, address indexed newBeacon);
    event TradeSettlementUpdated(address indexed oldSettlement, address indexed newSettlement);
    event AutoListOnExchangeUpdated(bool oldValue, bool newValue);
    event PermitSignerUpdated(address indexed oldSigner, address indexed newSigner);
    event AutoListFailed(address indexed tokenAddress, bytes reason);

    event BeaconChangeProposed(address indexed newBeacon, uint256 executeTime);
    event BeaconChangeExecuted(address indexed oldBeacon, address indexed newBeacon);
    event BeaconChangeCancelled(address indexed cancelledBeacon);

    event TreasuryChangeProposed(address indexed newTreasury, uint256 executeTime);
    event TreasuryChangeExecuted(address indexed oldTreasury, address indexed newTreasury);
    event TreasuryChangeCancelled(address indexed cancelledTreasury);

    event PermitSignerChangeProposed(address indexed newSigner, uint256 executeTime);
    event PermitSignerChangeExecuted(address indexed oldSigner, address indexed newSigner);
    event PermitSignerChangeCancelled(address indexed cancelledSigner);

    event AllocationGuideProposed(uint8 indexed bucket, uint16 minBp, uint16 maxBp, uint256 executeTime);
    event AllocationGuideExecuted(
        uint8 indexed bucket,
        uint16 oldMinBp,
        uint16 oldMaxBp,
        uint16 newMinBp,
        uint16 newMaxBp
    );
    event AllocationGuideCancelled(uint8 indexed bucket);

    event VestingWalletDeployed(address indexed token, address indexed wallet, uint256 ownerAllocationAmount);
    event VestingWalletBeaconUpdated(address indexed oldBeacon, address indexed newBeacon);
    event LinkedLaunchpadUpdated(address indexed oldLaunchpad, address indexed newLaunchpad);

    event LinkedLaunchpadChangeProposed(address indexed newLaunchpad, uint256 executeTime);
    event LinkedLaunchpadChangeExecuted(address indexed oldLaunchpad, address indexed newLaunchpad);
    event LinkedLaunchpadChangeCancelled(address indexed cancelledLaunchpad);

    event VestingWalletBeaconChangeProposed(address indexed newBeacon, uint256 executeTime);
    event VestingWalletBeaconChangeExecuted(address indexed oldBeacon, address indexed newBeacon);
    event VestingWalletBeaconChangeCancelled(address indexed cancelledBeacon);

    // Escrow events
    event LaunchpadEscrowFunded(address indexed token, uint256 amount, uint256 deadline);
    event LaunchpadEscrowReleased(address indexed token, address indexed launchpad, uint256 amount);
    event LaunchpadEscrowReclaimed(address indexed token, address indexed business, uint256 amount);
    /// @dev A cancelled sale's unsold tokens returning to escrow, resale-eligible after
    ///      `deadline`.
    event LaunchpadEscrowRestored(address indexed token, address indexed launchpad, uint256 amount, uint256 deadline);
    /// @dev Permissionless (`triggerOwnerVesting`) Owner Vesting start, distinct from the
    ///      ordinary `reclaimEscrow`-triggered path — same wallet, different caller/trigger.
    event OwnerVestingTriggeredOnTimeout(address indexed token, address indexed vestingWallet);

    event EscrowTimeoutChangeProposed(uint256 newTimeoutSeconds, uint256 executeTime);
    event EscrowTimeoutChangeExecuted(uint256 oldTimeoutSeconds, uint256 newTimeoutSeconds);
    event EscrowTimeoutChangeCancelled(uint256 cancelledTimeoutSeconds);

    event ResaleWaitChangeProposed(uint256 newWaitSeconds, uint256 executeTime);
    event ResaleWaitChangeExecuted(uint256 oldWaitSeconds, uint256 newWaitSeconds);
    event ResaleWaitChangeCancelled(uint256 cancelledWaitSeconds);

    // setTradeSettlement 2-day timelock events
    event TradeSettlementChangeProposed(address indexed newSettlement, uint256 executeTime);
    event TradeSettlementChangeExecuted(address indexed oldSettlement, address indexed newSettlement);
    event TradeSettlementChangeCancelled(address indexed cancelledSettlement);

    // Timelocked upgrade events
    event UpgradeRequested(address indexed newImplementation, uint256 readyAt);
    event UpgradeCancelled(address indexed cancelledImplementation);

    // ============ Errors ============

    error ZeroAddress();
    error ZeroAmount();
    error StringTooLong();
    error EmptyString();
    error TokenIssuanceFailed();
    error InvalidImplementation();
    error InvalidSignature();
    error ExpiredDeadline();
    error SignerNotSet();
    error DailyLimitExceeded();
    error SupplyLimitExceeded();
    error TimelockNotReady();
    error NoPendingChange();

    error AllocationSumInvalid(uint256 actual);
    error AllocationOutOfRange(uint8 bucket);
    error AllocationGuidesNotInitialized();
    error LiquidityReserveMinimumRequired();
    error InvalidAllocationGuide();
    error LiquidityRecipientInvalid();
    error VestingDurationInvalid();
    error VestingWalletDeployFailed();
    error InvalidBucket();
    error NoPendingAllocationGuide();
    error LinkedLaunchpadNotSet();

    // Escrow errors
    error NotLinkedLaunchpad();
    error EscrowAlreadyConsumed();
    error NoEscrowForToken();
    error EscrowTimeoutNotElapsed();
    error NotEscrowBusiness();
    error InvalidEscrowTimeout();
    /// @dev Fail-closed: a token carrying a LAUNCHPAD escrow bucket cannot be issued while
    ///      `escrowTimeoutSeconds` is still 0 (unset) — otherwise escrowDeadline == issuedAt and the
    ///      business could reclaimEscrow immediately, bypassing custody. Ops must configure the
    ///      timeout (>= MIN_ESCROW_TIMEOUT via the timelocked setter) first.
    error EscrowTimeoutNotConfigured();

    // Resale errors
    /// @dev Fail-closed, same shape as `EscrowTimeoutNotConfigured`: `restoreEscrow` refuses to
    ///      re-fund escrow while `resaleWaitSeconds` is still 0 (unset) — otherwise the returned
    ///      token would be resale-eligible immediately, defeating the mandated wait period.
    error ResaleWaitNotConfigured();
    error InvalidResaleWait();
    /// @dev `restoreEscrow`'s own balanceBefore/After guard — the measured transferFrom delta
    ///      did not match the caller-declared `amount` (mirrors `LaunchpadV1.createLaunchpad`'s
    ///      `EscrowAmountMismatch` on the release leg).
    error EscrowRestoreMismatch();

    // setTradeSettlement timelock error
    error TradeSettlementAlreadySet();

    // Timelocked upgrade errors
    error NoPendingUpgrade();
    error ImplementationMismatch();
    error UpgradeNotReady();

    /// @dev The staged upgrade matured more than UPGRADE_GRACE_PERIOD ago and is stale.
    error UpgradeExpired();

    /// @dev Ownership renouncement is disabled — see {renounceOwnership}.
    error RenounceDisabled();

    /// @dev An issued token belongs to the business that issued it. The platform has no
    ///      path to move it — `transferTokenOwnership` exists only to say so out loud to
    ///      callers holding an old ABI.
    error TokenOwnershipIsBusinessOwned();

    // ============ Modifiers ============

    modifier validAddress(address _addr) {
        if (_addr == address(0)) revert ZeroAddress();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ============ Initialization ============

    /**
     * @notice Single clean initializer. `allocationGuides`, `linkedLaunchpad`,
     *         and `escrowTimeoutSeconds` all default to zero/unset and MUST be configured
     *         via their respective timelocked setters before `issueToken` can succeed
     *         (fail-closed: `AllocationGuidesNotInitialized` / `LinkedLaunchpadNotSet`).
     */
    function initialize(
        address _erc20Beacon,
        address _platformTreasury,
        address _permitSigner,
        address _vestingWalletBeacon
    )
        public
        initializer
        validAddress(_erc20Beacon)
        validAddress(_platformTreasury)
        validAddress(_permitSigner)
        validAddress(_vestingWalletBeacon)
    {
        if (_vestingWalletBeacon.code.length == 0) revert InvalidImplementation();

        __Ownable_init(msg.sender);
        __Pausable_init();
        __EIP712_init("TokenFactory", "1");

        erc20Beacon = _erc20Beacon;
        platformTreasury = _platformTreasury;
        permitSigner = _permitSigner;
        vestingWalletBeacon = _vestingWalletBeacon;
        autoListOnExchange = true;
    }

    // ============ Core: issueToken ============

    /**
     * @notice Issue a new token with permit-baked 3-way allocation + Owner Vesting wallet
     *         + LAUNCHPAD-bucket escrow.
     * @dev Steps:
     *      1. Permit verification (EIP-712)
     *      2. Sum + range validation per bucket against `allocationGuides`
     *      3. Recipient validation (default-deny self-deal)
     *      4. Daily / supply limits
     *      5. Deploy ERC20 BeaconProxy
     *      6. Deploy `TokenVestingWallet` BeaconProxy via CREATE2
     *      7. Register token + vesting wallet (CEI: before token transfers)
     *      8. Distribute LIQUIDITY_RESERVE / OWNER_VESTING; LAUNCHPAD bucket
     *         stays in factory custody as escrow (NOT transferred to business)
     *      9. Auto-list on TradeSettlement (non-blocking)
     *     10. Transfer ERC20 ownership to business (AFTER distribution settles)
     *     11. Emit TokenIssued
     */
    function issueToken(
        string memory _name,
        string memory _symbol,
        uint256 _totalSupply,
        string memory _contractURI,
        AllocationRatios calldata _ratios,
        uint256 _deadline,
        bytes memory _signature
    ) external nonReentrant whenNotPaused returns (address tokenAddress, address vestingWallet) {
        address businessAccount = msg.sender;

        // ---- 1. Permit verification ----
        if (permitSigner == address(0)) revert SignerNotSet();
        if (block.timestamp > _deadline) revert ExpiredDeadline();
        if (vestingWalletBeacon == address(0)) revert InvalidImplementation();

        address currentLinkedLaunchpad = linkedLaunchpad;
        if (currentLinkedLaunchpad == address(0)) revert LinkedLaunchpadNotSet();

        uint256 currentNonce = nonces[businessAccount];
        bytes32 structHash = keccak256(
            abi.encode(
                ISSUE_PERMIT_TYPEHASH,
                businessAccount,
                keccak256(bytes(_name)),
                keccak256(bytes(_symbol)),
                _totalSupply,
                keccak256(bytes(_contractURI)),
                _ratios.launchpadBp,
                _ratios.liquidityBp,
                _ratios.ownerBp,
                _ratios.liquidityRecipient,
                _ratios.ownerVestingCliff,
                _ratios.ownerVestingDuration,
                currentLinkedLaunchpad,
                currentNonce,
                _deadline
            )
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        if (ECDSA.recover(hash, _signature) != permitSigner) revert InvalidSignature();
        nonces[businessAccount] = currentNonce + 1;

        // ---- 2. Sum + range validation ----
        _validateRatios(_ratios);

        // ---- 3. Recipient validation (self-deal default-deny) ----
        if (_ratios.liquidityRecipient == address(0)) revert LiquidityRecipientInvalid();
        if (_ratios.liquidityRecipient == businessAccount) revert LiquidityRecipientInvalid();
        if (_ratios.liquidityRecipient == address(this)) revert LiquidityRecipientInvalid();

        if (
            _ratios.ownerVestingDuration < MIN_OWNER_VESTING_DURATION ||
            _ratios.ownerVestingDuration > MAX_OWNER_VESTING_DURATION
        ) {
            revert VestingDurationInvalid();
        }

        // ---- 4. Validate inputs + daily/supply limits ----
        if (_totalSupply == 0) revert ZeroAmount();
        if (bytes(_name).length == 0 || bytes(_symbol).length == 0) revert EmptyString();
        if (bytes(_name).length > MAX_NAME_LENGTH) revert StringTooLong();
        if (bytes(_symbol).length > MAX_SYMBOL_LENGTH) revert StringTooLong();
        if (bytes(_contractURI).length > MAX_URI_LENGTH) revert StringTooLong();

        if (_totalSupply > MAX_SUPPLY_PER_TOKEN) revert SupplyLimitExceeded();
        uint256 today = block.timestamp / 1 days;
        if (dailyIssuanceCount[today] >= MAX_DAILY_ISSUANCE) revert DailyLimitExceeded();
        unchecked {
            dailyIssuanceCount[today]++;
        }

        // ---- 5. Deploy ERC20 BeaconProxy ----
        tokenAddress = _deployToken(_name, _symbol, _contractURI, _totalSupply);

        uint256 tokenId;
        unchecked {
            tokenId = tokenCounter++;
        }

        // ---- 6. Deploy vesting wallet (CREATE2) ----
        vestingWallet = _deployVestingWallet(
            businessAccount,
            tokenAddress,
            tokenId,
            _ratios.ownerVestingDuration,
            _ratios.ownerVestingCliff
        );

        // ---- 7. Register token + vesting wallet (CEI: BEFORE token transfers) ----
        isIssuedToken[tokenAddress] = true;
        tokenToBusiness[tokenAddress] = businessAccount;
        tokenIssuedAt[tokenAddress] = block.timestamp;
        tokenById[tokenId] = tokenAddress;
        tokenToVestingWallet[tokenAddress] = vestingWallet;
        tokenToLaunchpad[tokenAddress] = currentLinkedLaunchpad;

        // ---- 8. 3-way distribution ----
        uint256 liquidityAmount = Math.mulDiv(_totalSupply, _ratios.liquidityBp, BASIS_POINTS);
        uint256 ownerAmount = Math.mulDiv(_totalSupply, _ratios.ownerBp, BASIS_POINTS);
        // Rounding remainder rolls into the LAUNCHPAD bucket (largest typically).
        uint256 launchpadAmount = _totalSupply - liquidityAmount - ownerAmount;

        if (liquidityAmount > 0) {
            IERC20(tokenAddress).safeTransfer(_ratios.liquidityRecipient, liquidityAmount);
        }
        if (ownerAmount > 0) {
            IERC20(tokenAddress).safeTransfer(vestingWallet, ownerAmount);
        }

        // LAUNCHPAD bucket stays in factory custody as escrow — NOT transferred
        // to the business. Consumed via `releaseEscrow` (createLaunchpad) or `reclaimEscrow`
        // (timeout, business); may be re-funded by `restoreEscrow` if a launchpad created
        // against it is later cancelled, making the token resale-eligible.
        if (launchpadAmount > 0) {
            // Fail-closed: without a configured timeout, escrowDeadline == block.timestamp and the
            // business could reclaimEscrow the LAUNCHPAD bucket immediately, defeating escrow custody.
            if (escrowTimeoutSeconds == 0) revert EscrowTimeoutNotConfigured();
            uint256 deadline = block.timestamp + escrowTimeoutSeconds;
            launchpadEscrow[tokenAddress] = launchpadAmount;
            escrowDeadline[tokenAddress] = deadline;
            emit LaunchpadEscrowFunded(tokenAddress, launchpadAmount, deadline);
        } else {
            // launchpadAmount == 0 only when launchpadBp == 0 exactly — mulDiv's floor rounding
            // can only roll MORE into this remainder, never produce a false zero for
            // launchpadBp > 0 (covered by "rounding cannot produce a zero launchpadAmount for
            // launchpadBp > 0" in the TokenFactory suite). With no LAUNCHPAD bucket funded, no escrow ever exists
            // for this token, so neither `LaunchpadV1.createLaunchpad` (requires escrowAmount > 0)
            // nor this contract's own `reclaimEscrow` (requires launchpadEscrow[token] > 0) can
            // ever run for it — those are the ONLY two callers of `startVesting` on this token's
            // wallet. Without this branch, a funded OWNER_VESTING allocation would be stranded in
            // the deferred (`start == type(uint64).max`) state permanently — an ops footgun, not
            // an attacker-reachable path. Start the wallet immediately instead: this factory is
            // already its registered `factory()` authority (set to msg.sender == this contract at
            // `initialize` time, a few lines above via `_deployVestingWallet`), the same
            // authorization channel `reclaimEscrow` uses for its own equivalent trigger.
            ITokenVestingWallet(vestingWallet).startVesting(uint64(block.timestamp), _ratios.ownerVestingDuration);

            // Considered and deliberately NOT applied here. Setting `escrowConsumed = true` in
            // this branch would make `getEscrowInfo` read more honestly for a token that can never
            // launch — but it also changes which error `reclaimEscrow` reverts with, from
            // `NoEscrowForToken` to `EscrowAlreadyConsumed`, because the consumed check runs first.
            // That is a downstream-visible selector change (collector / member / frontend all decode
            // these) in exchange for a cosmetic reporting improvement, and `amount == 0` already
            // answers "can this token still launch?" on its own. Not worth the break.
        }

        emit VestingWalletDeployed(tokenAddress, vestingWallet, ownerAmount);

        // ---- 9. Auto-list on TradeSettlement (non-blocking) ----
        if (autoListOnExchange && tradeSettlement != address(0)) {
            try ITradeSettlement(tradeSettlement).setSupportedToken(tokenAddress, true) {
                // success
            } catch (bytes memory reason) {
                emit AutoListFailed(tokenAddress, reason);
            }
        }

        // ---- 10. Transfer ERC20 ownership to business (AFTER distribution settles) ----
        ERC20V1(tokenAddress).transferOwnershipDirect(businessAccount);

        // ---- 11. Emit event ----
        emit TokenIssued(
            tokenId,
            tokenAddress,
            businessAccount,
            vestingWallet,
            _ratios.launchpadBp,
            _ratios.liquidityBp,
            _ratios.ownerBp,
            _ratios.liquidityRecipient,
            _ratios.ownerVestingCliff,
            _ratios.ownerVestingDuration,
            _totalSupply
        );
    }

    // ============ Escrow release / reclaim ============

    /**
     * @notice Release the LAUNCHPAD-bucket escrow for `token` to its issuance-time launchpad.
     * @dev The per-token binding is immutable for the workflow. The current global
     *      `linkedLaunchpad` is only the default for newly issued tokens.
     *      Reverts `EscrowAlreadyConsumed` on a second call while escrow is already
     *      consumed, which transitively blocks a second `createLaunchpad` while a sale is
     *      live for it — NOT one-shot forever anymore: `restoreEscrow` can re-fund escrow
     *      after a cancelled sale, making a further `releaseEscrow` call possible again.
     *
     * Resale wait: a token's FIRST release (fresh issuance) is immediate, same as
     *      always. A RESALE (escrow re-funded by `restoreEscrow` — see `escrowIsResale`)
     *      instead reverts `EscrowTimeoutNotElapsed` until `block.timestamp` clears the
     *      `escrowDeadline` `restoreEscrow` set — that IS the mandated resale-wait period.
     * @return amount The amount released.
     */
    function releaseEscrow(address token) external nonReentrant returns (uint256 amount) {
        if (msg.sender != _launchpadForToken(token)) revert NotLinkedLaunchpad();
        if (escrowConsumed[token]) revert EscrowAlreadyConsumed();
        amount = launchpadEscrow[token];
        if (amount == 0) revert NoEscrowForToken();
        if (escrowIsResale[token] && block.timestamp < escrowDeadline[token]) {
            revert EscrowTimeoutNotElapsed();
        }

        escrowConsumed[token] = true;
        launchpadEscrow[token] = 0;
        escrowDeadline[token] = 0; // clear the whole escrow record, not two thirds of it

        IERC20(token).safeTransfer(msg.sender, amount);

        emit LaunchpadEscrowReleased(token, msg.sender, amount);
    }

    /**
     * @notice Reclaim the LAUNCHPAD-bucket escrow back to the issuing business after
     *         the reclaim timeout has elapsed and no `createLaunchpad` has consumed it.
     * @dev Callable by the token's registered business account (`tokenToBusiness`) or
     *      the platform owner.
     */
    function reclaimEscrow(address token) external nonReentrant {
        address business = tokenToBusiness[token];
        if (msg.sender != business && msg.sender != owner()) revert NotEscrowBusiness();
        if (escrowConsumed[token]) revert EscrowAlreadyConsumed();

        uint256 amount = launchpadEscrow[token];
        if (amount == 0) revert NoEscrowForToken();
        if (block.timestamp < escrowDeadline[token]) revert EscrowTimeoutNotElapsed();

        escrowConsumed[token] = true;
        launchpadEscrow[token] = 0;
        escrowDeadline[token] = 0; // clear the whole escrow record, not two thirds of it

        // No launch will ever finalize this token now, so the launchpad's Owner Vesting
        // trigger can never fire. Start the funded owner vesting wallet directly (the
        // factory is authorized via the wallet's stored `factory` binding) so the owner
        // allocation is not permanently frozen in the deferred/unstarted state.
        //
        // Guard: `started()` may already be true here — e.g. a prior cancelled sale's
        // `triggerOwnerVesting` timeout fired before this reclaim did. `startVesting` itself
        // hard-reverts on a second call (`AlreadyStarted`, no reset path), so without this
        // guard a legitimate reclaim would revert.
        address vestingWallet = tokenToVestingWallet[token];
        if (vestingWallet != address(0) && !ITokenVestingWallet(vestingWallet).started()) {
            uint64 vestingDuration = ITokenVestingWallet(vestingWallet).duration();
            ITokenVestingWallet(vestingWallet).startVesting(uint64(block.timestamp), vestingDuration);
        }

        IERC20(token).safeTransfer(business, amount);

        emit LaunchpadEscrowReclaimed(token, business, amount);
    }

    /**
     * @notice Restore a cancelled sale's unsold LAUNCHPAD-bucket `saleAmount` tokens to this
     *         factory's escrow, resale-eligible via a future `LaunchpadV1.createLaunchpad`
     *         once `resaleWaitSeconds` elapses (a cancelled sale's token
     *         used to be permanently unsellable: `escrowConsumed` never reset, and
     *         `TokenVestingWallet.startVesting` has no reset path once fired).
     * @dev Callable only by `token`'s authorized launchpad workflow (`_launchpadForToken`,
     *      the same authorization channel `releaseEscrow` uses). Pulls `amount` from the
     *      caller via `transferFrom` — the caller must `approve` this factory first — and
     *      verifies the REAL balance delta before crediting the ledger, mirroring
     *      `LaunchpadV1.createLaunchpad`'s own balanceBefore/After discipline on the release
     *      leg so `launchpadEscrow` can never diverge from the tokens this factory actually
     *      holds.
     * @return deadline The new resale-wait deadline (`block.timestamp + resaleWaitSeconds`).
     */
    function restoreEscrow(address token, uint256 amount) external nonReentrant returns (uint256 deadline) {
        if (msg.sender != _launchpadForToken(token)) revert NotLinkedLaunchpad();
        if (amount == 0) revert NoEscrowForToken();
        if (resaleWaitSeconds == 0) revert ResaleWaitNotConfigured();

        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = IERC20(token).balanceOf(address(this)) - balanceBefore;
        if (received != amount) revert EscrowRestoreMismatch();

        deadline = block.timestamp + resaleWaitSeconds;
        launchpadEscrow[token] += received;
        escrowDeadline[token] = deadline;
        escrowConsumed[token] = false;
        escrowIsResale[token] = true;

        emit LaunchpadEscrowRestored(token, msg.sender, received, deadline);
    }

    /**
     * @notice Permissionlessly start `token`'s Owner Vesting wallet once its LAUNCHPAD escrow
     *         has sat unconsumed past `escrowDeadline` — mirrors
     *         `LaunchpadV1.expireLaunchpad`'s permissionless pattern, applied here because
     *         `LaunchpadV1` no longer triggers Owner Vesting on ANY cancel path (only on a
     *         successful `finalizeLaunchpad`): a business that cancels a sale and never
     *         returns (whether the escrow was ever consumed, or restored after a cancel and
     *         never resold) must not freeze the funded owner allocation forever.
     * @dev No-ops (does not revert) if vesting already started, so a caller can call this
     *      speculatively without needing to check state first.
     */
    function triggerOwnerVesting(address token) external nonReentrant {
        address vestingWallet = tokenToVestingWallet[token];
        if (vestingWallet == address(0)) revert NoEscrowForToken();
        if (ITokenVestingWallet(vestingWallet).started()) return;

        if (escrowConsumed[token]) revert EscrowAlreadyConsumed();
        uint256 deadline = escrowDeadline[token];
        if (deadline == 0 || block.timestamp <= deadline) revert EscrowTimeoutNotElapsed();

        uint64 vestingDuration = ITokenVestingWallet(vestingWallet).duration();
        ITokenVestingWallet(vestingWallet).startVesting(uint64(block.timestamp), vestingDuration);

        emit OwnerVestingTriggeredOnTimeout(token, vestingWallet);
    }

    // ============ Internal Helpers ============

    /// @dev Resolve the authoritative launchpad for a token's workflow: the immutable
    ///      issuance-time binding, never the mutable global `linkedLaunchpad` pointer.
    function _launchpadForToken(address token) internal view returns (address authorizedLaunchpad) {
        authorizedLaunchpad = tokenToLaunchpad[token];
        if (authorizedLaunchpad != address(0)) return authorizedLaunchpad;

        // Upgrade compatibility for tokens issued before tokenToLaunchpad existed:
        // their vesting wallet retains the authoritative issuance-time launchpad.
        address vestingWallet = tokenToVestingWallet[token];
        if (vestingWallet != address(0)) {
            try ITokenVestingWallet(vestingWallet).launchpad() returns (address walletLaunchpad) {
                return walletLaunchpad;
            } catch {}
        }
    }

    function _validateRatios(AllocationRatios calldata _ratios) internal view {
        uint256 sumBp = uint256(_ratios.launchpadBp) + uint256(_ratios.liquidityBp) + uint256(_ratios.ownerBp);
        if (sumBp != BASIS_POINTS) revert AllocationSumInvalid(sumBp);

        AllocationGuide memory lpG = allocationGuides[BUCKET_LAUNCHPAD];
        AllocationGuide memory liqG = allocationGuides[BUCKET_LIQUIDITY_RESERVE];
        AllocationGuide memory ownG = allocationGuides[BUCKET_OWNER_VESTING];

        if (lpG.maxBp == 0 || liqG.maxBp == 0 || ownG.maxBp == 0) {
            revert AllocationGuidesNotInitialized();
        }

        if (_ratios.launchpadBp < lpG.minBp || _ratios.launchpadBp > lpG.maxBp) {
            revert AllocationOutOfRange(BUCKET_LAUNCHPAD);
        }
        if (_ratios.liquidityBp < liqG.minBp || _ratios.liquidityBp > liqG.maxBp) {
            revert AllocationOutOfRange(BUCKET_LIQUIDITY_RESERVE);
        }
        if (_ratios.ownerBp < ownG.minBp || _ratios.ownerBp > ownG.maxBp) {
            revert AllocationOutOfRange(BUCKET_OWNER_VESTING);
        }
    }

    function _deployToken(
        string memory _name,
        string memory _symbol,
        string memory _contractURI,
        uint256 _totalSupply
    ) internal returns (address) {
        if (erc20Beacon == address(0)) revert ZeroAddress();
        if (erc20Beacon.code.length == 0) revert TokenIssuanceFailed();

        bytes memory data = abi.encodeWithSignature(
            "initialize(address,string,string,string)",
            address(this),
            _name,
            _symbol,
            _contractURI
        );

        address proxyAddress;
        try new BeaconProxy(erc20Beacon, data) returns (BeaconProxy proxy) {
            proxyAddress = address(proxy);
        } catch {
            revert TokenIssuanceFailed();
        }

        ERC20V1 tokenContract = ERC20V1(proxyAddress);

        if (tokenContract.owner() != address(this)) revert TokenIssuanceFailed();

        tokenContract.mint(address(this), _totalSupply);

        if (IERC20(proxyAddress).balanceOf(address(this)) < _totalSupply) {
            revert TokenIssuanceFailed();
        }

        // Fixed-supply model: lock the on-chain supply cap to the issued
        // amount NOW, while the factory still owns the token. The whole `_totalSupply` was minted
        // just above, so setting `maxSupply == totalSupply` leaves ZERO headroom — after this, no
        // one can ever inflate supply (the only mint path, `mint`, is onlyLaunchpad and gated by
        // this same cap). `setMaxSupply` is one-shot (`MaxSupplyAlreadySet`) and requires
        // `_maxSupply >= totalSupply()`, both satisfied here. Store-token supply is immutable.
        tokenContract.setMaxSupply(_totalSupply);

        return proxyAddress;
    }

    /**
     * @dev Deploy a per-token `TokenVestingWallet` BeaconProxy via CREATE2. The
     *      wallet's `launchpad_` field is bound to `linkedLaunchpad` so that only
     *      the platform's `LaunchpadV1` can call `startVesting`.
     */
    function _deployVestingWallet(
        address _businessAccount,
        address _tokenAddress,
        uint256 _tokenId,
        uint64 _duration,
        uint64 _cliff
    ) internal returns (address wallet) {
        if (linkedLaunchpad == address(0)) revert LinkedLaunchpadNotSet();

        bytes memory data = abi.encodeWithSignature(
            "initialize(address,address,address,uint64,uint64)",
            _businessAccount,
            linkedLaunchpad,
            _tokenAddress,
            _duration,
            _cliff
        );

        bytes32 salt = keccak256(abi.encode(_businessAccount, _tokenId));
        try new BeaconProxy{ salt: salt }(vestingWalletBeacon, data) returns (BeaconProxy proxy) {
            wallet = address(proxy);
        } catch {
            revert VestingWalletDeployFailed();
        }
    }

    // ============ View Functions ============

    function getTokenInfo(
        address _tokenAddress
    ) external view returns (address businessAccount, uint256 issuedAt, bool isIssued) {
        return (tokenToBusiness[_tokenAddress], tokenIssuedAt[_tokenAddress], isIssuedToken[_tokenAddress]);
    }

    function getTokenCount() external view returns (uint256) {
        return tokenCounter;
    }

    /// @notice True if `who` is platform infra for `token` — used by ERC20V1._update to exempt
    ///         protocol distribution/withdrawal legs from the business blacklist. View-only.
    function isPlatformContract(address token, address who) external view returns (bool) {
        if (who == address(0)) return false;
        if (who == address(this)) return true; // TokenFactory (issuance/escrow legs)
        if (who == _launchpadForToken(token)) return true; // issuance-time LaunchpadV1
        if (who == tradeSettlement || authorizedTradeSettlements[who]) return true; // current or historical settlement
        if (who == tokenToVestingWallet[token]) return true; // this token's vesting wallet
        return false;
    }

    function version() external pure returns (uint256) {
        return 1;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function getRemainingDailyQuota() external view returns (uint256 remaining) {
        uint256 today = block.timestamp / 1 days;
        uint256 issued = dailyIssuanceCount[today];
        return issued >= MAX_DAILY_ISSUANCE ? 0 : MAX_DAILY_ISSUANCE - issued;
    }

    function getTodayIssuanceCount() external view returns (uint256 count) {
        uint256 today = block.timestamp / 1 days;
        return dailyIssuanceCount[today];
    }

    function getAllocationGuide(uint8 bucket) external view returns (uint16 minBp, uint16 maxBp) {
        AllocationGuide memory g = allocationGuides[bucket];
        return (g.minBp, g.maxBp);
    }

    function getEscrowInfo(address token) external view returns (uint256 amount, uint256 deadline, bool consumed) {
        return (launchpadEscrow[token], escrowDeadline[token], escrowConsumed[token]);
    }

    // ============ Admin Functions ============

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // ============ Timelock: Allocation Guide ============

    function proposeAllocationGuide(uint8 bucket, uint16 minBp, uint16 maxBp) external onlyOwner {
        if (bucket >= ALLOCATION_BUCKET_COUNT) revert InvalidBucket();
        if (minBp > maxBp) revert InvalidAllocationGuide();
        if (maxBp > BASIS_POINTS) revert InvalidAllocationGuide();
        if (maxBp == 0) revert InvalidAllocationGuide();
        if (bucket == BUCKET_LIQUIDITY_RESERVE && minBp < LIQUIDITY_RESERVE_MIN_BP_FLOOR) {
            revert LiquidityReserveMinimumRequired();
        }

        pendingAllocationGuides[bucket] = AllocationGuide({ minBp: minBp, maxBp: maxBp });
        uint256 executeTime = block.timestamp + ALLOCATION_GUIDE_DELAY;
        allocationGuideUpdateTime[bucket] = executeTime;

        emit AllocationGuideProposed(bucket, minBp, maxBp, executeTime);
    }

    function executeAllocationGuide(uint8 bucket) external onlyOwner {
        if (bucket >= ALLOCATION_BUCKET_COUNT) revert InvalidBucket();
        uint256 executeTime = allocationGuideUpdateTime[bucket];
        if (executeTime == 0) revert NoPendingAllocationGuide();
        if (block.timestamp < executeTime) revert TimelockNotReady();

        AllocationGuide memory pending = pendingAllocationGuides[bucket];
        if (pending.maxBp == 0) revert NoPendingAllocationGuide();

        AllocationGuide memory old = allocationGuides[bucket];
        allocationGuides[bucket] = pending;

        delete pendingAllocationGuides[bucket];
        delete allocationGuideUpdateTime[bucket];

        emit AllocationGuideExecuted(bucket, old.minBp, old.maxBp, pending.minBp, pending.maxBp);
    }

    function cancelAllocationGuide(uint8 bucket) external onlyOwner {
        if (bucket >= ALLOCATION_BUCKET_COUNT) revert InvalidBucket();
        if (allocationGuideUpdateTime[bucket] == 0) revert NoPendingAllocationGuide();

        delete pendingAllocationGuides[bucket];
        delete allocationGuideUpdateTime[bucket];

        emit AllocationGuideCancelled(bucket);
    }

    // ============ Timelock: Vesting Wallet Beacon (2-day) ============

    function proposeVestingWalletBeaconChange(address _newBeacon) external onlyOwner validAddress(_newBeacon) {
        if (_newBeacon.code.length == 0) revert InvalidImplementation();
        pendingVestingWalletBeacon = _newBeacon;
        vestingWalletBeaconChangeTime = block.timestamp + CONFIG_DELAY;
        emit VestingWalletBeaconChangeProposed(_newBeacon, vestingWalletBeaconChangeTime);
    }

    function executeVestingWalletBeaconChange() external onlyOwner {
        if (pendingVestingWalletBeacon == address(0)) revert NoPendingChange();
        if (block.timestamp < vestingWalletBeaconChangeTime) revert TimelockNotReady();

        address oldBeacon = vestingWalletBeacon;
        vestingWalletBeacon = pendingVestingWalletBeacon;
        pendingVestingWalletBeacon = address(0);
        vestingWalletBeaconChangeTime = 0;

        emit VestingWalletBeaconChangeExecuted(oldBeacon, vestingWalletBeacon);
        emit VestingWalletBeaconUpdated(oldBeacon, vestingWalletBeacon);
    }

    function cancelVestingWalletBeaconChange() external onlyOwner {
        if (pendingVestingWalletBeacon == address(0)) revert NoPendingChange();
        address cancelled = pendingVestingWalletBeacon;
        pendingVestingWalletBeacon = address(0);
        vestingWalletBeaconChangeTime = 0;
        emit VestingWalletBeaconChangeCancelled(cancelled);
    }

    // ============ Timelock: Linked Launchpad (2-day) ============

    function proposeLinkedLaunchpadChange(address _newLaunchpad) external onlyOwner validAddress(_newLaunchpad) {
        if (_newLaunchpad.code.length == 0) revert InvalidImplementation();
        pendingLinkedLaunchpad = _newLaunchpad;
        linkedLaunchpadChangeTime = block.timestamp + CONFIG_DELAY;
        emit LinkedLaunchpadChangeProposed(_newLaunchpad, linkedLaunchpadChangeTime);
    }

    function executeLinkedLaunchpadChange() external onlyOwner {
        if (pendingLinkedLaunchpad == address(0)) revert NoPendingChange();
        if (block.timestamp < linkedLaunchpadChangeTime) revert TimelockNotReady();

        address oldLaunchpad = linkedLaunchpad;
        linkedLaunchpad = pendingLinkedLaunchpad;
        pendingLinkedLaunchpad = address(0);
        linkedLaunchpadChangeTime = 0;

        emit LinkedLaunchpadChangeExecuted(oldLaunchpad, linkedLaunchpad);
        emit LinkedLaunchpadUpdated(oldLaunchpad, linkedLaunchpad);
    }

    function cancelLinkedLaunchpadChange() external onlyOwner {
        if (pendingLinkedLaunchpad == address(0)) revert NoPendingChange();
        address cancelled = pendingLinkedLaunchpad;
        pendingLinkedLaunchpad = address(0);
        linkedLaunchpadChangeTime = 0;
        emit LinkedLaunchpadChangeCancelled(cancelled);
    }

    // ============ Timelock: Escrow Timeout (2-day) ============

    function proposeEscrowTimeoutChange(uint256 _newTimeoutSeconds) external onlyOwner {
        if (_newTimeoutSeconds < MIN_ESCROW_TIMEOUT || _newTimeoutSeconds > MAX_ESCROW_TIMEOUT) {
            revert InvalidEscrowTimeout();
        }
        pendingEscrowTimeoutSeconds = _newTimeoutSeconds;
        escrowTimeoutChangeTime = block.timestamp + CONFIG_DELAY;
        emit EscrowTimeoutChangeProposed(_newTimeoutSeconds, escrowTimeoutChangeTime);
    }

    function executeEscrowTimeoutChange() external onlyOwner {
        if (escrowTimeoutChangeTime == 0) revert NoPendingChange();
        if (block.timestamp < escrowTimeoutChangeTime) revert TimelockNotReady();

        uint256 oldTimeout = escrowTimeoutSeconds;
        escrowTimeoutSeconds = pendingEscrowTimeoutSeconds;
        pendingEscrowTimeoutSeconds = 0;
        escrowTimeoutChangeTime = 0;

        emit EscrowTimeoutChangeExecuted(oldTimeout, escrowTimeoutSeconds);
    }

    function cancelEscrowTimeoutChange() external onlyOwner {
        if (escrowTimeoutChangeTime == 0) revert NoPendingChange();
        uint256 cancelled = pendingEscrowTimeoutSeconds;
        pendingEscrowTimeoutSeconds = 0;
        escrowTimeoutChangeTime = 0;
        emit EscrowTimeoutChangeCancelled(cancelled);
    }

    // ============ Timelock: Resale Wait (2-day) ============

    /// @notice Propose `resaleWaitSeconds` (the wait `restoreEscrow` imposes before a
    ///         cancelled sale's returned token becomes resale-eligible). Same structural
    ///         bounds as `proposeEscrowTimeoutChange` — see {resaleWaitSeconds}'s doc comment.
    function proposeResaleWaitChange(uint256 _newWaitSeconds) external onlyOwner {
        if (_newWaitSeconds < MIN_ESCROW_TIMEOUT || _newWaitSeconds > MAX_ESCROW_TIMEOUT) {
            revert InvalidResaleWait();
        }
        pendingResaleWaitSeconds = _newWaitSeconds;
        resaleWaitChangeTime = block.timestamp + CONFIG_DELAY;
        emit ResaleWaitChangeProposed(_newWaitSeconds, resaleWaitChangeTime);
    }

    function executeResaleWaitChange() external onlyOwner {
        if (resaleWaitChangeTime == 0) revert NoPendingChange();
        if (block.timestamp < resaleWaitChangeTime) revert TimelockNotReady();

        uint256 oldWait = resaleWaitSeconds;
        resaleWaitSeconds = pendingResaleWaitSeconds;
        pendingResaleWaitSeconds = 0;
        resaleWaitChangeTime = 0;

        emit ResaleWaitChangeExecuted(oldWait, resaleWaitSeconds);
    }

    function cancelResaleWaitChange() external onlyOwner {
        if (resaleWaitChangeTime == 0) revert NoPendingChange();
        uint256 cancelled = pendingResaleWaitSeconds;
        pendingResaleWaitSeconds = 0;
        resaleWaitChangeTime = 0;
        emit ResaleWaitChangeCancelled(cancelled);
    }

    // ============ Timelock: Beacon Change ============

    function proposeBeaconChange(address _newBeacon) external onlyOwner validAddress(_newBeacon) {
        if (_newBeacon.code.length == 0) revert InvalidImplementation();
        pendingBeacon = _newBeacon;
        beaconChangeTime = block.timestamp + CONFIG_DELAY;
        emit BeaconChangeProposed(_newBeacon, beaconChangeTime);
    }

    function executeBeaconChange() external onlyOwner {
        if (pendingBeacon == address(0)) revert NoPendingChange();
        if (block.timestamp < beaconChangeTime) revert TimelockNotReady();

        address oldBeacon = erc20Beacon;
        erc20Beacon = pendingBeacon;
        pendingBeacon = address(0);
        beaconChangeTime = 0;

        emit BeaconChangeExecuted(oldBeacon, erc20Beacon);
    }

    function cancelBeaconChange() external onlyOwner {
        if (pendingBeacon == address(0)) revert NoPendingChange();
        address cancelled = pendingBeacon;
        pendingBeacon = address(0);
        beaconChangeTime = 0;
        emit BeaconChangeCancelled(cancelled);
    }

    // ============ Timelock: Treasury Change ============

    function proposeTreasuryChange(address _newTreasury) external onlyOwner validAddress(_newTreasury) {
        pendingTreasury = _newTreasury;
        treasuryChangeTime = block.timestamp + CONFIG_DELAY;
        emit TreasuryChangeProposed(_newTreasury, treasuryChangeTime);
    }

    function executeTreasuryChange() external onlyOwner {
        if (pendingTreasury == address(0)) revert NoPendingChange();
        if (block.timestamp < treasuryChangeTime) revert TimelockNotReady();

        address oldTreasury = platformTreasury;
        platformTreasury = pendingTreasury;
        pendingTreasury = address(0);
        treasuryChangeTime = 0;

        emit TreasuryChangeExecuted(oldTreasury, platformTreasury);
    }

    function cancelTreasuryChange() external onlyOwner {
        if (pendingTreasury == address(0)) revert NoPendingChange();
        address cancelled = pendingTreasury;
        pendingTreasury = address(0);
        treasuryChangeTime = 0;
        emit TreasuryChangeCancelled(cancelled);
    }

    // ============ Timelock: Permit Signer Change ============

    function proposePermitSignerChange(address _newSigner) external onlyOwner validAddress(_newSigner) {
        pendingPermitSigner = _newSigner;
        permitSignerChangeTime = block.timestamp + CONFIG_DELAY;
        emit PermitSignerChangeProposed(_newSigner, permitSignerChangeTime);
    }

    function executePermitSignerChange() external onlyOwner {
        if (pendingPermitSigner == address(0)) revert NoPendingChange();
        if (block.timestamp < permitSignerChangeTime) revert TimelockNotReady();

        address oldSigner = permitSigner;
        permitSigner = pendingPermitSigner;
        pendingPermitSigner = address(0);
        permitSignerChangeTime = 0;

        emit PermitSignerChangeExecuted(oldSigner, permitSigner);
    }

    function cancelPermitSignerChange() external onlyOwner {
        if (pendingPermitSigner == address(0)) revert NoPendingChange();
        address cancelled = pendingPermitSigner;
        pendingPermitSigner = address(0);
        permitSignerChangeTime = 0;
        emit PermitSignerChangeCancelled(cancelled);
    }

    // ============ Non-Critical Admin Functions ============

    /// @notice Bootstrap-only immediate wiring (from address(0)); all later CHANGES are timelocked.
    function setTradeSettlement(address _newSettlement) external onlyOwner {
        if (tradeSettlement != address(0)) revert TradeSettlementAlreadySet();
        tradeSettlement = _newSettlement;
        emit TradeSettlementUpdated(address(0), _newSettlement);
    }

    /// @notice Propose a change to `tradeSettlement` (economic/security-sensitive — 2-day timelock).
    /// @dev Intentionally omits `validAddress` so a change TO address(0) (disable auto-list) is
    ///      expressible; emptiness is tracked by the time sentinel (`tradeSettlementChangeTime`),
    ///      not the address.
    function proposeTradeSettlementChange(address _newSettlement) external onlyOwner {
        pendingTradeSettlement = _newSettlement;
        tradeSettlementChangeTime = block.timestamp + CONFIG_DELAY;
        emit TradeSettlementChangeProposed(_newSettlement, tradeSettlementChangeTime);
    }

    function executeTradeSettlementChange() external onlyOwner {
        if (tradeSettlementChangeTime == 0) revert NoPendingChange();
        if (block.timestamp < tradeSettlementChangeTime) revert TimelockNotReady();

        address oldSettlement = tradeSettlement;
        if (oldSettlement != address(0)) {
            authorizedTradeSettlements[oldSettlement] = true;
        }
        tradeSettlement = pendingTradeSettlement;
        pendingTradeSettlement = address(0);
        tradeSettlementChangeTime = 0;

        emit TradeSettlementChangeExecuted(oldSettlement, tradeSettlement);
        emit TradeSettlementUpdated(oldSettlement, tradeSettlement);
    }

    function cancelTradeSettlementChange() external onlyOwner {
        if (tradeSettlementChangeTime == 0) revert NoPendingChange();
        address cancelled = pendingTradeSettlement;
        pendingTradeSettlement = address(0);
        tradeSettlementChangeTime = 0;
        emit TradeSettlementChangeCancelled(cancelled);
    }

    function setAutoListOnExchange(bool _autoList) external onlyOwner {
        bool oldValue = autoListOnExchange;
        autoListOnExchange = _autoList;
        emit AutoListOnExchangeUpdated(oldValue, _autoList);
    }

    /**
     * @notice DEPRECATED — this selector always reverts. It transfers nothing and changes
     *         no state.
     * @dev The platform cannot move an issued token's ownership at all. An issued token
     *      belongs to the business that issued it: `issueToken` hands ownership over at
     *      mint time and nothing here takes it back.
     *
     *      This previously existed as an immediate transfer, then as a 2-day-timelocked
     *      propose/execute/cancel flow. Both were seizure paths — they moved a business's
     *      token to an address the platform chose, without that business's consent, and
     *      the timelock only bought the business advance notice of it. Both are gone.
     *
     *      The selector is kept as a loud revert so a caller that still has it in an old
     *      ABI gets a readable reason instead of an opaque "no matching function". A
     *      business that wants to move its own token calls `transferOwnership` /
     *      `acceptOwnership` on the token itself — `ERC20V1` is `Ownable2Step`, and that
     *      path never routed through this contract.
     *
     *      Both parameters are intentionally unnamed/unused — nothing is read or written.
     */
    function transferTokenOwnership(address, address) external pure {
        revert TokenOwnershipIsBusinessOwned();
    }

    /**
     * @notice Stage a UUPS upgrade to `newImpl`; it becomes executable after UPGRADE_TIMELOCK_DELAY.
     */
    function requestUpgrade(address newImpl) external onlyOwner {
        if (newImpl == address(0)) revert ZeroAddress();
        if (newImpl.code.length == 0) revert InvalidImplementation();
        pendingImplementation = newImpl;
        upgradeReadyAt = block.timestamp + UPGRADE_TIMELOCK_DELAY;
        emit UpgradeRequested(newImpl, upgradeReadyAt);
    }

    /**
     * @notice Cancel a pending staged upgrade.
     */
    function cancelUpgrade() external onlyOwner {
        if (pendingImplementation == address(0)) revert NoPendingUpgrade();
        emit UpgradeCancelled(pendingImplementation);
        pendingImplementation = address(0);
        upgradeReadyAt = 0;
    }

    /**
     * @dev Timelocked upgrade authorizer. The staged implementation must match, the timelock must
     *      have elapsed, and the staging must not have expired. The staging is single-use
     *      (cleared here).
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        if (pendingImplementation == address(0)) revert NoPendingUpgrade();
        if (newImplementation != pendingImplementation) revert ImplementationMismatch();
        if (block.timestamp < upgradeReadyAt) revert UpgradeNotReady();
        if (block.timestamp > upgradeReadyAt + UPGRADE_GRACE_PERIOD) revert UpgradeExpired();
        if (newImplementation.code.length == 0) revert InvalidImplementation();
        pendingImplementation = address(0);
        upgradeReadyAt = 0;
    }

    /**
     * @dev Ownership handover drops any armed upgrade staging.
     *
     *      Ownership actually moves here, on `acceptOwnership` (and on `renounceOwnership`), not on
     *      the nomination. Without this an incoming owner inherits a matured implementation staged
     *      by their predecessor and can install it with zero fresh notice. Clearing forces a
     *      re-stage under the new key, restarting the 48h notice.
     *
     *      There is no per-token ownership-transfer staging to sweep here — the platform has no
     *      path to move an issued token's ownership at all (see `transferTokenOwnership` above).
     */
    function _transferOwnership(address newOwner) internal virtual override {
        if (pendingImplementation != address(0)) {
            emit UpgradeCancelled(pendingImplementation);
            pendingImplementation = address(0);
            upgradeReadyAt = 0;
        }
        super._transferOwnership(newOwner);
    }

    /**
     * @notice Renouncing ownership is permanently disabled.
     * @dev Every lever this factory owns — the ERC20 and vesting-wallet beacons, the treasury, the
     *      permit signer, the linked launchpad, the escrow timeout, and its own implementation —
     *      is `onlyOwner` and timelocked. An ownerless factory freezes all of them permanently
     *      while continuing to issue tokens against whatever configuration was last set. Ownership
     *      moves only via the 2-step transfer, which always leaves a live owner.
     */
    function renounceOwnership() public view override onlyOwner {
        revert RenounceDisabled();
    }
}

/**
 * @title ITradeSettlement
 * @notice Minimal interface for the auto-list call.
 */
interface ITradeSettlement {
    function setSupportedToken(address _token, bool _status) external;
}

/**
 * @title ITokenVestingWallet
 * @notice Minimal interface used by LaunchpadV1 for the finalize-time trigger.
 */
interface ITokenVestingWallet {
    function startVesting(uint64 startTimestamp, uint64 duration_) external;
    function duration() external view returns (uint64);
    function launchpad() external view returns (address);
    function started() external view returns (bool);
}
