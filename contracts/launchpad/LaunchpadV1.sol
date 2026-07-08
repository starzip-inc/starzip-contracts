// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title LaunchpadV1
 * @notice StarZip Launchpad — token fundraising against `TokenFactory`-escrowed
 *         LAUNCHPAD-bucket tokens, using a 4-bucket / Owner-Vesting /
 *         non-uniform-USDT-vesting design.
 *
 * Key behaviors:
 *   - `createLaunchpad` does not accept an arbitrary `_saleAmount` transferred
 *         from the business. The sale amount is DERIVED from `TokenFactory.launchpadEscrow`
 *         and pulled via `releaseEscrow` (this contract must be the factory's
 *         `linkedLaunchpad`). One-shot consumption blocks a second launchpad for the
 *         same token.
 *   - `finalizeLaunchpad` splits the post-fee raised amount 3 ways — immediate
 *         (business), liquidity (fund liquidity recipient — distinct from
 *         `TokenFactory`'s token-side LIQUIDITY_RESERVE bucket), and vesting (existing
 *         per-launchpad USDT vesting flow). All rates are placeholder/setter, timelocked
 *         (economic-sensitive).
 *
 * Vesting is triggered on finalize: the non-uniform 8-period USDT vesting schedule is
 * snapshotted, and the Owner Vesting trigger hook fires.
 */
contract LaunchpadV1 is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuard, PausableUpgradeable {
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;

    // ============ Constants ============
    uint256 public constant BASIS_POINTS = 10000;
    uint256 public constant MAX_FEE_RATE = 1000; // Max 10%
    uint256 public constant MIN_TOKEN_PRICE = 1e12;
    uint256 public constant MAX_BATCH_SIZE = 100;
    uint256 public constant MAX_PURCHASE_PER_USER = 1000000 * 1e18;
    uint256 public constant MIN_PREPARATION_TIME = 1 hours;
    uint256 public constant MAX_PREPARATION_TIME = 30 days;
    uint256 public constant MIN_LAUNCHPAD_DURATION = 1 days;
    uint256 public constant MAX_LAUNCHPAD_DURATION = 90 days;
    uint256 public constant MIN_VESTING_QUARTER = 30 days;
    uint256 public constant MAX_VESTING_QUARTER = 365 days;
    uint256 public constant MAX_LOCKUP_DURATION = 730 days;

    uint256 public constant MIN_VESTING_INTERVAL = 7 days;
    uint256 public constant MAX_VESTING_INTERVAL = 365 days;
    uint256 public constant MIN_VESTING_DURATION = 30 days;
    uint256 public constant MAX_VESTING_DURATION = 3650 days;

    /// @notice Number of vesting periods enforced when a non-uniform schedule is set.
    uint256 public constant VESTING_PERIOD_COUNT = 8;

    /// @dev Economic-sensitive setter timelock.
    uint256 public constant CONFIG_DELAY = 2 days;

    /// @notice Grace after endTime before a stuck launchpad may be permissionlessly refunded/expired.
    ///         Production value; there is no test-scale override (constant, not a setter).
    uint256 public constant REFUND_GRACE = 14 days;

    /// @dev Timelock delay for staged UUPS upgrades.
    uint256 public constant UPGRADE_TIMELOCK_DELAY = 48 hours;

    // ============ State ============

    uint256 public launchpadFeeRate;
    uint256 public preparationTime;
    uint256 public launchpadDuration;
    uint256 public vestingQuarterDuration;

    address public feeRecipient;
    address public tokenFactory;

    /// @dev Global default 8-period USDT vesting schedule, read at finalize-time as a
    ///      fallback when no per-launchpad override is set. NEVER read at claim-time
    ///      (snapshot semantics).
    uint256[8] public vestingSchedule;
    uint256 public launchpadCounter;

    mapping(address => bool) public acceptedPaymentTokens;
    mapping(address => uint256) public lockedTokenAmount;
    mapping(address => uint256) public lockedPaymentAmount;

    // ============ Enums ============
    enum LaunchpadStatus {
        NotStarted,
        Preparing,
        Active,
        Ended,
        Finalized,
        Cancelled
    }

    // ============ Structs ============
    struct LaunchpadInfo {
        address businessAccount;
        address tokenAddress;
        address paymentToken;
        uint256 saleAmount;
        uint256 soldAmount;
        uint256 tokenPrice;
        uint256 startTime;
        uint256 endTime;
        uint256 totalRaised;
        LaunchpadStatus status;
    }

    struct ParticipantInfo {
        uint256 paymentAmount;
        uint256 tokenAmount;
        uint256 claimedAmount;
        bool refunded;
    }

    struct VestingInfo {
        uint256 totalAmount;
        uint256 claimedAmount;
        uint256 startTime;
        uint256 lockupDuration;
        uint256 vestingDuration;
        uint256 vestingInterval;
        address paymentToken;
    }

    struct PendingVestingConfig {
        uint256 vestingDuration;
        uint256 vestingInterval;
        bool isSet;
    }

    struct InvestorVestingConfig {
        uint256 lockupDuration;
        uint256 vestingDuration;
        uint256 vestingInterval;
        bool isSet;
    }

    /// @notice Per-launchpad override of the raised-funds 3-way split.
    ///         Snapshotted at finalize time (falls back to the global default rates
    ///         if unset). Sum of the three bp values MUST equal `BASIS_POINTS`.
    struct FundSplitConfig {
        uint256 immediateBp;
        uint256 liquidityBp;
        uint256 vestingBp;
        bool isSet;
    }

    mapping(uint256 => LaunchpadInfo) public launchpads;
    mapping(uint256 => mapping(address => ParticipantInfo)) public participants;
    mapping(uint256 => VestingInfo) public launchpadVesting;
    mapping(uint256 => EnumerableSet.AddressSet) private _launchpadParticipants;
    mapping(uint256 => uint256) public pendingLockupDuration;
    mapping(uint256 => PendingVestingConfig) public pendingVestingConfig;
    mapping(uint256 => uint256) public investorLockupDuration;
    mapping(uint256 => InvestorVestingConfig) public investorVestingConfig;
    mapping(uint256 => uint256) public investorVestingStartTime;

    /// @notice Snapshot of the active non-uniform USDT vesting schedule per launchpad.
    /// @dev All-zero entry is impossible once finalized with `totalRaised > 0` (the
    ///      global default is non-zero), so all-zero unambiguously means "not yet
    ///      finalized with proceeds".
    mapping(uint256 => uint256[8]) public launchpadVestingSchedule;

    /// @notice One-shot guard for the Owner Vesting trigger on finalize.
    mapping(uint256 => bool) public ownerVestingTrigger;

    /// @notice Per-launchpad snapshot of the Owner Vesting wallet at `createLaunchpad` time.
    mapping(uint256 => address) public launchpadOwnerVestingWallet;

    // ---- Raised-funds 3-way split ----

    /// @notice Global default rates for the raised-funds 3-way split (placeholder —
    ///         defaults to 100% vesting / 0% immediate / 0% liquidity, i.e. behaviorally
    ///         identical to the original vesting-only flow, until configured via timelock).
    uint256 public immediateRate;
    uint256 public liquidityRate;
    uint256 public vestingRate;

    /// @notice Recipient of the "liquidity" portion of raised (USDT) funds. Distinct
    ///         from `TokenFactory`'s token-side LIQUIDITY_RESERVE bucket recipient.
    address public liquidityRecipient;

    mapping(uint256 => FundSplitConfig) public pendingFundSplitConfig;

    uint256 public pendingImmediateRate;
    uint256 public pendingLiquidityRate;
    uint256 public pendingVestingRate;
    uint256 public fundSplitChangeTime;

    address public pendingLiquidityRecipient;
    uint256 public liquidityRecipientChangeTime;

    // ---- Timelocked UUPS upgrade staging (appended) ----
    address public pendingImplementation;
    uint256 public upgradeReadyAt;

    // ============ Storage Gap ============
    uint256[33] private __gap; // was [35]; -2 (timelocked upgrade staging adds 2 full slots; payment-lock and finalize-window guard add no storage)

    // ============ Events ============
    event LaunchpadCreated(
        uint256 indexed launchpadId,
        address indexed businessAccount,
        address indexed tokenAddress,
        address paymentToken,
        uint256 saleAmount,
        uint256 tokenPrice
    );
    event LaunchpadStarted(uint256 indexed launchpadId, uint256 startTime);
    event LaunchpadFinalized(
        uint256 indexed launchpadId,
        uint256 totalRaised,
        uint256 soldAmount,
        uint256 unsoldAmount
    );
    event LaunchpadCancelled(uint256 indexed launchpadId, uint256 timestamp);
    event TokenPurchased(
        uint256 indexed launchpadId,
        address indexed buyer,
        uint256 paymentAmount,
        uint256 tokenAmount
    );
    event TokensClaimed(uint256 indexed launchpadId, address indexed user, uint256 amount);
    event VestingClaimed(address indexed businessAccount, uint256 amount);
    event Refunded(uint256 indexed launchpadId, address indexed user, uint256 amount);

    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);
    event TokenFactoryUpdated(address indexed oldFactory, address indexed newFactory);
    event PaymentTokenUpdated(address indexed token, bool status);
    event FeeRateUpdated(uint256 oldRate, uint256 newRate);
    event PreparationTimeUpdated(uint256 oldTime, uint256 newTime);
    event LaunchpadDurationUpdated(uint256 oldDuration, uint256 newDuration);
    event VestingQuarterDurationUpdated(uint256 oldDuration, uint256 newDuration);
    event VestingScheduleUpdated(uint256[8] oldSchedule, uint256[8] newSchedule);
    event LaunchpadScheduleUpdated(
        uint256 indexed launchpadId,
        uint256 oldStartTime,
        uint256 oldEndTime,
        uint256 newStartTime,
        uint256 newEndTime
    );
    event LockupDurationUpdated(uint256 indexed launchpadId, uint256 oldDuration, uint256 newDuration);
    event VestingConfigUpdated(uint256 indexed launchpadId, uint256 vestingDuration, uint256 vestingInterval);
    event InvestorLockupUpdated(uint256 indexed launchpadId, uint256 oldDuration, uint256 newDuration);
    event InvestorVestingConfigUpdated(
        uint256 indexed launchpadId,
        uint256 lockupDuration,
        uint256 vestingDuration,
        uint256 vestingInterval
    );

    event LaunchpadVestingScheduleSet(uint256 indexed launchpadId, uint256[8] schedule);
    event VestingScheduleSnapshot(uint256 indexed launchpadId, uint256[8] schedule);
    event OwnerVestingStarted(
        uint256 indexed launchpadId,
        address indexed token,
        address indexed vestingWallet,
        uint64 startTime,
        uint64 duration
    );

    // Fund-split events
    event FundSplitSet(uint256 indexed launchpadId, uint256 immediateBp, uint256 liquidityBp, uint256 vestingBp);
    event FundSplitApplied(
        uint256 indexed launchpadId,
        uint256 immediateAmount,
        uint256 liquidityAmount,
        uint256 vestingAmount
    );
    event FundSplitChangeProposed(uint256 immediateBp, uint256 liquidityBp, uint256 vestingBp, uint256 executeTime);
    event FundSplitChangeExecuted(uint256 immediateBp, uint256 liquidityBp, uint256 vestingBp);
    event FundSplitChangeCancelled();
    event LiquidityRecipientChangeProposed(address indexed newRecipient, uint256 executeTime);
    event LiquidityRecipientChangeExecuted(address indexed oldRecipient, address indexed newRecipient);
    event LiquidityRecipientChangeCancelled(address indexed cancelledRecipient);

    // Escrow-derived creation event
    event LaunchpadEscrowConsumed(uint256 indexed launchpadId, address indexed tokenAddress, uint256 amount);

    // timelocked upgrade events
    event UpgradeRequested(address indexed newImplementation, uint256 readyAt);
    event UpgradeCancelled(address indexed cancelledImplementation);

    // ============ Errors ============
    error ZeroAddress();
    error InvalidLaunchpadId();
    error LaunchpadNotActive();
    error LaunchpadNotEnded();
    error AlreadyFinalized();
    error NoTokensToClaim();
    error NoVestingFound();
    error NothingToClaim();
    error InvalidAmount();
    error ExceedsSaleAmount();
    error InvalidFeeRate();
    error InvalidVestingSchedule();
    error AlreadyRefunded();
    error RefundNotAvailable();
    error PaymentTokenNotAccepted();
    error InvalidTokenDecimals();
    error TokenPriceTooLow();
    error ExceedsPurchaseLimit();
    error InvalidDuration();
    error InvalidPreparationTime();
    error InvalidVestingDuration();
    error BatchTooLarge();
    error NoParticipantsToRefund();
    error InvalidImplementation();
    error TokenNotFromFactory();
    error NotTokenIssuer();
    error TokenLockedInActiveLaunchpad();
    error InvalidSchedule();
    error LaunchpadAlreadyStarted();
    error NotBusinessOrOwner();
    error StartTimeTooEarly();
    error InvalidVestingInterval();
    error DeprecatedFunction();

    // Vesting-schedule errors
    error InvalidVestingScheduleSum();
    error VestingPeriodCountInvalid();
    error VestingWalletNotConfigured();

    // Escrow / fund-split / timelock errors
    error NoEscrowAvailable();
    error EscrowAmountMismatch();
    error InvalidFundSplit();
    error TimelockNotReady();
    error NoPendingChange();

    // refund liveness
    error FinalizeWindowClosed();

    // timelocked UUPS upgrade
    error NoPendingUpgrade();
    error ImplementationMismatch();
    error UpgradeNotReady();

    // ============ Modifiers ============
    modifier validAddress(address _addr) {
        if (_addr == address(0)) revert ZeroAddress();
        _;
    }

    modifier validLaunchpadId(uint256 _launchpadId) {
        if (_launchpadId >= launchpadCounter) revert InvalidLaunchpadId();
        _;
    }

    modifier validPaymentToken(address _token) {
        if (!acceptedPaymentTokens[_token]) revert PaymentTokenNotAccepted();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ============ Initialization ============

    /**
     * @notice Initializer.
     * @dev The raised-funds 3-way split defaults to (0, 0, 10000) — i.e. behaviorally
     *      identical to "100% vesting, 0% immediate, 0% liquidity" — until the platform
     *      configures the real split via the timelocked `propose/executeFundSplitChange`.
     *      This avoids hardcoding the eventual 40/10/50 economic decision.
     */
    function initialize(
        address _tokenFactory,
        address _defaultPaymentToken,
        address _feeRecipient
    ) public initializer validAddress(_tokenFactory) validAddress(_defaultPaymentToken) validAddress(_feeRecipient) {
        __Ownable_init(msg.sender);
        __Pausable_init();

        tokenFactory = _tokenFactory;
        feeRecipient = _feeRecipient;

        acceptedPaymentTokens[_defaultPaymentToken] = true;
        emit PaymentTokenUpdated(_defaultPaymentToken, true);

        launchpadFeeRate = 300; // 3%
        preparationTime = 12 hours;
        launchpadDuration = 7 days;
        vestingQuarterDuration = 90 days;
        vestingSchedule = [2000, 1000, 1000, 2000, 1000, 1000, 1000, 1000];

        // Placeholder default: sum == 10000, all in "vesting" (matches the original behavior).
        immediateRate = 0;
        liquidityRate = 0;
        vestingRate = BASIS_POINTS;
    }

    // ============ Core Functions ============

    /**
     * @notice Create a new launchpad against the token's `TokenFactory`-escrowed
     *         LAUNCHPAD bucket. The sale amount is DERIVED from the escrow,
     *         not an arbitrary caller-supplied amount, and this contract MUST be the
     *         factory's current `linkedLaunchpad` to pull it via `releaseEscrow`.
     * @dev One-shot per token: `TokenFactory.releaseEscrow` reverts on a second call
     *      for the same token (`EscrowAlreadyConsumed`), so a second `createLaunchpad`
     *      for the same token is impossible.
     */
    function createLaunchpad(
        address _tokenAddress,
        uint256 _tokenPrice,
        address _businessAccount,
        address _paymentToken,
        uint256 _startTime,
        uint256 _endTime
    )
        external
        whenNotPaused
        validAddress(_tokenAddress)
        validAddress(_businessAccount)
        validPaymentToken(_paymentToken)
    {
        if (_tokenPrice == 0) revert InvalidAmount();
        if (_tokenPrice < MIN_TOKEN_PRICE) revert TokenPriceTooLow();

        // Authenticate against the factory-recorded issuer, never the caller-supplied
        // _businessAccount. The token MUST come from the factory, _businessAccount MUST equal
        // the real issuer, and the caller must be the platform owner or that same issuer.
        // (When tokenFactory is unset, getTokenInfo() reverts on the zero-address call — the
        //  correct fail-closed behavior: no launchpad can exist without a factory.)
        (address issuer, , bool isIssued) = ITokenFactory(tokenFactory).getTokenInfo(_tokenAddress);
        if (!isIssued) revert TokenNotFromFactory();
        if (_businessAccount != issuer) revert NotTokenIssuer();
        if (msg.sender != owner() && msg.sender != issuer) revert NotBusinessOrOwner();

        // ---- Derive saleAmount from the factory escrow and pull it in ----
        uint256 escrowAmount = ITokenFactory(tokenFactory).launchpadEscrow(_tokenAddress);
        if (escrowAmount == 0) revert NoEscrowAvailable();

        uint256 balanceBefore = IERC20(_tokenAddress).balanceOf(address(this));
        uint256 released = ITokenFactory(tokenFactory).releaseEscrow(_tokenAddress);
        if (released != escrowAmount) revert EscrowAmountMismatch();
        uint256 balanceAfter = IERC20(_tokenAddress).balanceOf(address(this));
        if (balanceAfter - balanceBefore != released) revert EscrowAmountMismatch();

        uint256 launchpadId = launchpadCounter++;

        LaunchpadInfo storage launchpad = launchpads[launchpadId];
        launchpad.businessAccount = _businessAccount;
        launchpad.tokenAddress = _tokenAddress;
        launchpad.paymentToken = _paymentToken;
        launchpad.saleAmount = released;
        launchpad.tokenPrice = _tokenPrice;
        launchpad.status = LaunchpadStatus.Preparing;

        if (_startTime == 0) {
            launchpad.startTime = block.timestamp + preparationTime;
        } else {
            if (_startTime < block.timestamp + MIN_PREPARATION_TIME) revert StartTimeTooEarly();
            launchpad.startTime = _startTime;
        }

        if (_endTime == 0) {
            launchpad.endTime = launchpad.startTime + launchpadDuration;
        } else {
            if (_endTime <= launchpad.startTime) revert InvalidSchedule();
            uint256 duration = _endTime - launchpad.startTime;
            if (duration < MIN_LAUNCHPAD_DURATION || duration > MAX_LAUNCHPAD_DURATION) {
                revert InvalidDuration();
            }
            launchpad.endTime = _endTime;
        }

        // Snapshot the Owner Vesting wallet for this launchpad. address(0) is the
        // sentinel for tokens with no owner allocation — Owner Vesting trigger is
        // skipped on finalize.
        address vw = ITokenFactory(tokenFactory).tokenToVestingWallet(_tokenAddress);
        if (vw != address(0)) {
            launchpadOwnerVestingWallet[launchpadId] = vw;
        }

        lockedTokenAmount[_tokenAddress] += released;

        emit LaunchpadEscrowConsumed(launchpadId, _tokenAddress, released);
        emit LaunchpadCreated(launchpadId, _businessAccount, _tokenAddress, _paymentToken, released, _tokenPrice);
    }

    function participate(
        uint256 _launchpadId,
        uint256 _paymentAmount
    ) external nonReentrant whenNotPaused validLaunchpadId(_launchpadId) {
        if (_paymentAmount == 0) revert InvalidAmount();

        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (block.timestamp < launchpad.startTime) revert LaunchpadNotActive();
        if (block.timestamp > launchpad.endTime) revert LaunchpadNotActive();
        if (launchpad.status != LaunchpadStatus.Active && launchpad.status != LaunchpadStatus.Preparing) {
            revert LaunchpadNotActive();
        }

        if (launchpad.status == LaunchpadStatus.Preparing && block.timestamp >= launchpad.startTime) {
            launchpad.status = LaunchpadStatus.Active;
            emit LaunchpadStarted(_launchpadId, block.timestamp);
        }

        uint8 paymentDecimals = IERC20Metadata(launchpad.paymentToken).decimals();
        if (paymentDecimals < 6 || paymentDecimals > 18) revert InvalidTokenDecimals();

        uint256 scaleFactor = 10 ** (36 - paymentDecimals);
        uint256 tokenAmount = Math.mulDiv(_paymentAmount, scaleFactor, launchpad.tokenPrice);

        if (launchpad.soldAmount + tokenAmount > launchpad.saleAmount) {
            revert ExceedsSaleAmount();
        }

        IERC20(launchpad.paymentToken).safeTransferFrom(msg.sender, address(this), _paymentAmount);

        _launchpadParticipants[_launchpadId].add(msg.sender);
        ParticipantInfo storage participant = participants[_launchpadId][msg.sender];
        participant.paymentAmount += _paymentAmount;
        participant.tokenAmount += tokenAmount;

        if (participant.tokenAmount > MAX_PURCHASE_PER_USER) revert ExceedsPurchaseLimit();

        launchpad.totalRaised += _paymentAmount;
        launchpad.soldAmount += tokenAmount;

        // lock the raised USDT so recoverStuckTokens cannot reach it while Active.
        lockedPaymentAmount[launchpad.paymentToken] += _paymentAmount;

        emit TokenPurchased(_launchpadId, msg.sender, _paymentAmount, tokenAmount);
    }

    /**
     * @notice Finalize launchpad after end time or sold out.
     * @dev Post-fee proceeds are split 3 ways (immediate / liquidity /
     *      vesting) instead of 100% flowing into the USDT vesting schedule. Also
     *      snapshots the non-uniform vesting schedule and triggers Owner Vesting
     *      exactly once (hard-revert on failure).
     */
    function finalizeLaunchpad(uint256 _launchpadId) external onlyOwner nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        bool timeEnded = block.timestamp > launchpad.endTime;
        bool soldOut = launchpad.soldAmount >= launchpad.saleAmount;

        if (!timeEnded && !soldOut) revert LaunchpadNotEnded();

        // once the refund window opens, the owner can no longer finalize — the launchpad is
        // refund-only (expireLaunchpad + claimRefundAfterTimeout/refund). Eliminates the
        // finalize-vs-timeout-refund race. Early sold-out finalize (before endTime) is unaffected.
        if (block.timestamp > launchpad.endTime + REFUND_GRACE) revert FinalizeWindowClosed();

        if (launchpad.status == LaunchpadStatus.Active) {
            // Normal case
        } else if (launchpad.status == LaunchpadStatus.Preparing && timeEnded) {
            // No participation but time ended
        } else {
            revert AlreadyFinalized();
        }

        uint256 unsoldAmount = launchpad.saleAmount - launchpad.soldAmount;

        if (launchpad.totalRaised > 0) {
            uint8 paymentDecimals = IERC20Metadata(launchpad.paymentToken).decimals();
            if (paymentDecimals < 6 || paymentDecimals > 18) revert InvalidTokenDecimals();

            uint256 feeAmount = Math.mulDiv(launchpad.totalRaised, launchpadFeeRate, BASIS_POINTS);
            if (feeAmount > 0) {
                IERC20(launchpad.paymentToken).safeTransfer(feeRecipient, feeAmount);
            }

            uint256 remainingAmount = launchpad.totalRaised - feeAmount;

            // ---- 3-way split of the post-fee remainder ----
            FundSplitConfig storage splitConfig = pendingFundSplitConfig[_launchpadId];
            uint256 immediateBp;
            uint256 liquidityBp;
            if (splitConfig.isSet) {
                immediateBp = splitConfig.immediateBp;
                liquidityBp = splitConfig.liquidityBp;
            } else {
                immediateBp = immediateRate;
                liquidityBp = liquidityRate;
            }

            uint256 immediateAmount = Math.mulDiv(remainingAmount, immediateBp, BASIS_POINTS);
            uint256 liquidityAmount = Math.mulDiv(remainingAmount, liquidityBp, BASIS_POINTS);
            // Remainder rolls into vesting so the 3-way split always sums exactly.
            uint256 vestingRemainder = remainingAmount - immediateAmount - liquidityAmount;

            if (immediateAmount > 0) {
                IERC20(launchpad.paymentToken).safeTransfer(launchpad.businessAccount, immediateAmount);
            }
            if (liquidityAmount > 0) {
                if (liquidityRecipient == address(0)) revert ZeroAddress();
                IERC20(launchpad.paymentToken).safeTransfer(liquidityRecipient, liquidityAmount);
            }

            emit FundSplitApplied(_launchpadId, immediateAmount, liquidityAmount, vestingRemainder);

            uint256 decimalDiff = 10 ** (18 - paymentDecimals);
            uint256 vestingAmount = vestingRemainder * decimalDiff; // Convert to 18 decimals for vesting

            PendingVestingConfig storage vestingConfig = pendingVestingConfig[_launchpadId];
            uint256 vestDuration;
            uint256 vestInterval;

            if (vestingConfig.isSet) {
                vestDuration = vestingConfig.vestingDuration;
                vestInterval = vestingConfig.vestingInterval;
            } else {
                vestDuration = vestingQuarterDuration * 8;
                vestInterval = vestingQuarterDuration;
            }

            launchpadVesting[_launchpadId] = VestingInfo({
                totalAmount: vestingAmount,
                claimedAmount: 0,
                startTime: block.timestamp,
                lockupDuration: pendingLockupDuration[_launchpadId],
                vestingDuration: vestDuration,
                vestingInterval: vestInterval,
                paymentToken: launchpad.paymentToken
            });

            // the whole totalRaised was locked at participate(); release only the
            // portion leaving now (fee + immediate + liquidity). The remainder (==
            // vestingRemainder) stays locked and is drawn down by claimVestedPayment.
            lockedPaymentAmount[launchpad.paymentToken] -= (feeAmount + immediateAmount + liquidityAmount);

            _snapshotVestingSchedule(_launchpadId);
        }

        launchpad.status = LaunchpadStatus.Finalized;
        investorVestingStartTime[_launchpadId] = block.timestamp;

        if (unsoldAmount > 0) {
            IERC20(launchpad.tokenAddress).safeTransfer(launchpad.businessAccount, unsoldAmount);
        }

        // only unsold tokens leave the lock here; sold-but-unclaimed tokens stay
        // LOCKED until each investor calls claimTokens (decremented there).
        lockedTokenAmount[launchpad.tokenAddress] -= unsoldAmount;

        emit LaunchpadFinalized(_launchpadId, launchpad.totalRaised, launchpad.soldAmount, unsoldAmount);

        _triggerOwnerVesting(_launchpadId, launchpad.tokenAddress);
    }

    /**
     * @notice Owner-only cancellation of a Preparing launchpad.
     */
    function cancelLaunchpad(uint256 _launchpadId) external onlyOwner nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status != LaunchpadStatus.Preparing) {
            revert LaunchpadNotActive();
        }

        launchpad.status = LaunchpadStatus.Cancelled;

        lockedTokenAmount[launchpad.tokenAddress] -= launchpad.saleAmount;

        IERC20(launchpad.tokenAddress).safeTransfer(launchpad.businessAccount, launchpad.saleAmount);

        emit LaunchpadCancelled(_launchpadId, block.timestamp);
    }

    /**
     * @notice Permissionlessly expire a launchpad the owner never finalized/cancelled, returning
     *         the escrowed sale tokens to the issuer and enabling refund()/batchRefund().
     * @dev Callable by ANYONE once block.timestamp > endTime + REFUND_GRACE. Transitions to the
     *      terminal Cancelled state. No tokens were ever distributed (claimTokens requires
     *      Finalized), so the full saleAmount returns to the issuer and every paymentAmount stays
     *      refundable. Mirrors cancelLaunchpad's token-lock accounting (-= saleAmount).
     */
    function expireLaunchpad(uint256 _launchpadId) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status != LaunchpadStatus.Active && launchpad.status != LaunchpadStatus.Preparing) {
            revert LaunchpadNotActive();
        }
        if (block.timestamp <= launchpad.endTime + REFUND_GRACE) revert RefundNotAvailable();

        launchpad.status = LaunchpadStatus.Cancelled;

        uint256 saleAmount = launchpad.saleAmount;
        lockedTokenAmount[launchpad.tokenAddress] -= saleAmount; // consistency (no finalize ran)
        if (saleAmount > 0) {
            IERC20(launchpad.tokenAddress).safeTransfer(launchpad.businessAccount, saleAmount);
        }
        emit LaunchpadCancelled(_launchpadId, block.timestamp);
    }

    function claimTokens(uint256 _launchpadId) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];
        ParticipantInfo storage participant = participants[_launchpadId][msg.sender];

        if (launchpad.status != LaunchpadStatus.Finalized) revert LaunchpadNotEnded();
        if (participant.tokenAmount <= participant.claimedAmount) revert NoTokensToClaim();

        uint256 claimableAmount = _calculateClaimableTokens(_launchpadId, msg.sender);
        if (claimableAmount == 0) revert NothingToClaim();

        participant.claimedAmount += claimableAmount;

        // release the lock for exactly the tokens leaving, preserving
        // lockedTokenAmount[token] >= sum of unclaimed sold tokens for that token.
        lockedTokenAmount[launchpad.tokenAddress] -= claimableAmount;

        IERC20(launchpad.tokenAddress).safeTransfer(msg.sender, claimableAmount);

        emit TokensClaimed(_launchpadId, msg.sender, claimableAmount);
    }

    function refund(uint256 _launchpadId) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];
        ParticipantInfo storage participant = participants[_launchpadId][msg.sender];

        if (launchpad.status != LaunchpadStatus.Cancelled) revert RefundNotAvailable();
        if (participant.refunded) revert AlreadyRefunded();
        if (participant.paymentAmount == 0) revert InvalidAmount();

        participant.refunded = true;
        // release the payment lock for exactly the funds leaving.
        lockedPaymentAmount[launchpad.paymentToken] -= participant.paymentAmount;
        IERC20(launchpad.paymentToken).safeTransfer(msg.sender, participant.paymentAmount);

        emit Refunded(_launchpadId, msg.sender, participant.paymentAmount);
    }

    /**
     * @notice Permissionless per-investor USDT refund from a launchpad the owner never
     *         finalized/cancelled, once block.timestamp > endTime + REFUND_GRACE.
     * @dev Does not change launchpad status (many investors call independently). Shares
     *      participant.refunded with refund()/batchRefund() ⇒ no double refund. Decrements the
     *      payment lock.
     */
    function claimRefundAfterTimeout(
        uint256 _launchpadId
    ) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];
        ParticipantInfo storage participant = participants[_launchpadId][msg.sender];

        if (launchpad.status != LaunchpadStatus.Active && launchpad.status != LaunchpadStatus.Preparing) {
            revert RefundNotAvailable();
        }
        if (block.timestamp <= launchpad.endTime + REFUND_GRACE) revert RefundNotAvailable();
        if (participant.refunded) revert AlreadyRefunded();
        if (participant.paymentAmount == 0) revert InvalidAmount();

        participant.refunded = true;
        lockedPaymentAmount[launchpad.paymentToken] -= participant.paymentAmount;
        IERC20(launchpad.paymentToken).safeTransfer(msg.sender, participant.paymentAmount);

        emit Refunded(_launchpadId, msg.sender, participant.paymentAmount);
    }

    function batchRefund(
        uint256 _launchpadId,
        address[] calldata _participants
    ) external onlyOwner nonReentrant validLaunchpadId(_launchpadId) {
        if (_participants.length == 0) revert NoParticipantsToRefund();
        if (_participants.length > MAX_BATCH_SIZE) revert BatchTooLarge();

        LaunchpadInfo storage launchpad = launchpads[_launchpadId];
        if (launchpad.status != LaunchpadStatus.Cancelled) revert RefundNotAvailable();

        for (uint256 i = 0; i < _participants.length; ) {
            ParticipantInfo storage pInfo = participants[_launchpadId][_participants[i]];

            if (!pInfo.refunded && pInfo.paymentAmount > 0) {
                pInfo.refunded = true;
                // release the payment lock for exactly the funds leaving.
                lockedPaymentAmount[launchpad.paymentToken] -= pInfo.paymentAmount;
                IERC20(launchpad.paymentToken).safeTransfer(_participants[i], pInfo.paymentAmount);
                emit Refunded(_launchpadId, _participants[i], pInfo.paymentAmount);
            }
            unchecked {
                ++i;
            }
        }
    }

    function claimVestedPayment(uint256 _launchpadId) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (msg.sender != launchpad.businessAccount) revert NoVestingFound();

        VestingInfo storage vesting = launchpadVesting[_launchpadId];

        if (vesting.totalAmount == 0) revert NoVestingFound();
        if (vesting.claimedAmount >= vesting.totalAmount) revert NothingToClaim();

        uint256 claimableAmount = _calculateClaimableVesting(_launchpadId);
        if (claimableAmount == 0) revert NothingToClaim();

        vesting.claimedAmount += claimableAmount;

        uint8 paymentDecimals = IERC20Metadata(vesting.paymentToken).decimals();
        if (paymentDecimals < 6 || paymentDecimals > 18) revert InvalidTokenDecimals();
        uint256 claimableInPaymentDecimals = claimableAmount / (10 ** (18 - paymentDecimals));

        lockedPaymentAmount[vesting.paymentToken] -= claimableInPaymentDecimals;

        IERC20(vesting.paymentToken).safeTransfer(msg.sender, claimableInPaymentDecimals);

        emit VestingClaimed(msg.sender, claimableAmount);
    }

    // ============ Internal Functions ============

    function _snapshotVestingSchedule(uint256 _launchpadId) internal {
        uint256[8] storage perLaunchpad = launchpadVestingSchedule[_launchpadId];

        bool hasOverride = (perLaunchpad[0] |
            perLaunchpad[1] |
            perLaunchpad[2] |
            perLaunchpad[3] |
            perLaunchpad[4] |
            perLaunchpad[5] |
            perLaunchpad[6] |
            perLaunchpad[7]) != 0;

        uint256[8] memory snapshot;
        if (hasOverride) {
            for (uint256 i = 0; i < 8; ) {
                snapshot[i] = perLaunchpad[i];
                unchecked {
                    ++i;
                }
            }
        } else {
            for (uint256 i = 0; i < 8; ) {
                snapshot[i] = vestingSchedule[i];
                perLaunchpad[i] = snapshot[i];
                unchecked {
                    ++i;
                }
            }
        }

        emit VestingScheduleSnapshot(_launchpadId, snapshot);
    }

    function _triggerOwnerVesting(uint256 _launchpadId, address _tokenAddress) internal {
        address vw = launchpadOwnerVestingWallet[_launchpadId];
        if (vw == address(0)) return;
        if (ownerVestingTrigger[_launchpadId]) return;

        address current = ITokenFactory(tokenFactory).tokenToVestingWallet(_tokenAddress);
        if (current != vw) revert VestingWalletNotConfigured();

        uint64 dur = ITokenVestingWallet(vw).duration();
        uint64 nowTs = uint64(block.timestamp);

        ITokenVestingWallet(vw).startVesting(nowTs, dur);

        ownerVestingTrigger[_launchpadId] = true;
        emit OwnerVestingStarted(_launchpadId, _tokenAddress, vw, nowTs, dur);
    }

    function _calculateClaimableVesting(uint256 _launchpadId) internal view returns (uint256) {
        uint256[8] storage sched = launchpadVestingSchedule[_launchpadId];
        bool isNonUniform = (sched[0] | sched[1] | sched[2] | sched[3] | sched[4] | sched[5] | sched[6] | sched[7]) !=
            0;

        if (!isNonUniform) {
            return _calculateClaimableVestingLinear(_launchpadId);
        }

        VestingInfo storage vesting = launchpadVesting[_launchpadId];
        if (vesting.totalAmount == 0) return 0;
        if (vesting.vestingInterval == 0) return 0;

        if (block.timestamp < vesting.startTime + vesting.lockupDuration) {
            return 0;
        }

        uint256 vestingStartTime = vesting.startTime + vesting.lockupDuration;
        uint256 elapsed = block.timestamp - vestingStartTime;

        if (elapsed >= vesting.vestingDuration) {
            return vesting.totalAmount > vesting.claimedAmount ? vesting.totalAmount - vesting.claimedAmount : 0;
        }

        uint256 currentPeriod = elapsed / vesting.vestingInterval;
        if (currentPeriod > VESTING_PERIOD_COUNT) currentPeriod = VESTING_PERIOD_COUNT;

        uint256 unlockedBp;
        for (uint256 i = 0; i < currentPeriod; ) {
            unlockedBp += sched[i];
            unchecked {
                ++i;
            }
        }

        uint256 totalUnlocked = Math.mulDiv(vesting.totalAmount, unlockedBp, BASIS_POINTS);

        return totalUnlocked > vesting.claimedAmount ? totalUnlocked - vesting.claimedAmount : 0;
    }

    function _calculateClaimableVestingLinear(uint256 _launchpadId) internal view returns (uint256) {
        VestingInfo storage vesting = launchpadVesting[_launchpadId];

        if (vesting.totalAmount == 0) return 0;
        if (vesting.vestingInterval == 0) return 0;

        if (block.timestamp < vesting.startTime + vesting.lockupDuration) {
            return 0;
        }

        uint256 vestingStartTime = vesting.startTime + vesting.lockupDuration;
        uint256 elapsed = block.timestamp - vestingStartTime;

        if (elapsed >= vesting.vestingDuration) {
            return vesting.totalAmount > vesting.claimedAmount ? vesting.totalAmount - vesting.claimedAmount : 0;
        }

        uint256 totalPeriods = vesting.vestingDuration / vesting.vestingInterval;
        if (totalPeriods == 0) totalPeriods = 1;

        uint256 remainder = vesting.vestingDuration % vesting.vestingInterval;
        if (remainder > 0) {
            totalPeriods += 1;
        }

        uint256 currentPeriod = elapsed / vesting.vestingInterval;
        if (currentPeriod > totalPeriods) currentPeriod = totalPeriods;

        uint256 totalUnlocked = Math.mulDiv(vesting.totalAmount, currentPeriod, totalPeriods);

        return totalUnlocked > vesting.claimedAmount ? totalUnlocked - vesting.claimedAmount : 0;
    }

    function _calculateClaimableTokens(uint256 _launchpadId, address _investor) internal view returns (uint256) {
        ParticipantInfo storage participant = participants[_launchpadId][_investor];
        InvestorVestingConfig storage config = investorVestingConfig[_launchpadId];

        uint256 totalTokens = participant.tokenAmount;
        uint256 claimed = participant.claimedAmount;

        if (totalTokens <= claimed) return 0;

        if (!config.isSet) {
            return totalTokens - claimed;
        }

        uint256 startTime = investorVestingStartTime[_launchpadId];
        if (block.timestamp < startTime + config.lockupDuration) {
            return 0;
        }

        if (config.vestingDuration == 0 || config.vestingInterval == 0) {
            return totalTokens - claimed;
        }

        uint256 vestingStart = startTime + config.lockupDuration;
        uint256 elapsed = block.timestamp - vestingStart;

        if (elapsed >= config.vestingDuration) {
            return totalTokens - claimed;
        }

        uint256 totalPeriods = config.vestingDuration / config.vestingInterval;
        if (totalPeriods == 0) totalPeriods = 1;

        uint256 remainder = config.vestingDuration % config.vestingInterval;
        if (remainder > 0) {
            totalPeriods += 1;
        }

        uint256 currentPeriod = elapsed / config.vestingInterval;
        if (currentPeriod > totalPeriods) currentPeriod = totalPeriods;

        uint256 totalUnlocked = Math.mulDiv(totalTokens, currentPeriod, totalPeriods);

        return totalUnlocked > claimed ? totalUnlocked - claimed : 0;
    }

    // ============ View Functions ============

    function getClaimableTokens(
        uint256 _launchpadId,
        address _investor
    ) external view validLaunchpadId(_launchpadId) returns (uint256) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];
        if (launchpad.status != LaunchpadStatus.Finalized) return 0;
        return _calculateClaimableTokens(_launchpadId, _investor);
    }

    function getInvestorVestingConfig(
        uint256 _launchpadId
    ) external view validLaunchpadId(_launchpadId) returns (InvestorVestingConfig memory) {
        return investorVestingConfig[_launchpadId];
    }

    function getLaunchpadInfo(uint256 _launchpadId) external view returns (LaunchpadInfo memory) {
        return launchpads[_launchpadId];
    }

    function getParticipantInfo(
        uint256 _launchpadId,
        address _participant
    ) external view returns (ParticipantInfo memory) {
        return participants[_launchpadId][_participant];
    }

    function getVestingInfo(
        uint256 _launchpadId
    ) external view validLaunchpadId(_launchpadId) returns (VestingInfo memory) {
        return launchpadVesting[_launchpadId];
    }

    function getClaimableVesting(uint256 _launchpadId) external view validLaunchpadId(_launchpadId) returns (uint256) {
        return _calculateClaimableVesting(_launchpadId);
    }

    function getLaunchpadVestingSchedule(
        uint256 _launchpadId
    ) external view validLaunchpadId(_launchpadId) returns (uint256[8] memory) {
        return launchpadVestingSchedule[_launchpadId];
    }

    function getCurrentVestingPeriod(
        uint256 _launchpadId
    ) external view validLaunchpadId(_launchpadId) returns (uint256) {
        VestingInfo storage vesting = launchpadVesting[_launchpadId];
        if (vesting.totalAmount == 0 || vesting.vestingInterval == 0) return 0;

        if (block.timestamp < vesting.startTime + vesting.lockupDuration) {
            return 0;
        }

        uint256 vestingStartTime = vesting.startTime + vesting.lockupDuration;
        uint256 elapsed = block.timestamp - vestingStartTime;
        uint256 totalPeriods = vesting.vestingDuration / vesting.vestingInterval;
        uint256 currentPeriod = elapsed / vesting.vestingInterval;

        return currentPeriod > totalPeriods ? totalPeriods : currentPeriod;
    }

    function getVestingScheduleInfo(
        uint256 _launchpadId
    )
        external
        view
        validLaunchpadId(_launchpadId)
        returns (uint256 totalPeriods, uint256 amountPerPeriod, uint256 currentPeriod, uint256 totalUnlocked)
    {
        VestingInfo storage vesting = launchpadVesting[_launchpadId];
        if (vesting.totalAmount == 0 || vesting.vestingInterval == 0) {
            return (0, 0, 0, 0);
        }

        totalPeriods = vesting.vestingDuration / vesting.vestingInterval;
        if (totalPeriods == 0) totalPeriods = 1;

        amountPerPeriod = vesting.totalAmount / totalPeriods;

        if (block.timestamp < vesting.startTime + vesting.lockupDuration) {
            return (totalPeriods, amountPerPeriod, 0, 0);
        }

        uint256 vestingStartTime = vesting.startTime + vesting.lockupDuration;
        uint256 elapsed = block.timestamp - vestingStartTime;
        currentPeriod = elapsed / vesting.vestingInterval;
        if (currentPeriod > totalPeriods) currentPeriod = totalPeriods;

        totalUnlocked = Math.mulDiv(vesting.totalAmount, currentPeriod, totalPeriods);
    }

    function getCurrentQuarter(uint256 _launchpadId) external view validLaunchpadId(_launchpadId) returns (uint256) {
        _launchpadId;
        revert DeprecatedFunction();
    }

    function getAllQuarterlyVestingAmounts(
        uint256 _launchpadId
    ) external view validLaunchpadId(_launchpadId) returns (uint256[8] memory) {
        _launchpadId;
        revert DeprecatedFunction();
    }

    function getParticipantCount(uint256 _launchpadId) external view validLaunchpadId(_launchpadId) returns (uint256) {
        return _launchpadParticipants[_launchpadId].length();
    }

    function getParticipants(
        uint256 _launchpadId,
        uint256 _offset,
        uint256 _limit
    ) external view validLaunchpadId(_launchpadId) returns (address[] memory) {
        EnumerableSet.AddressSet storage participantSet = _launchpadParticipants[_launchpadId];
        uint256 total = participantSet.length();

        if (_offset >= total) return new address[](0);

        uint256 end = _offset + _limit;
        if (end > total) end = total;

        uint256 resultLength = end - _offset;
        address[] memory result = new address[](resultLength);

        for (uint256 i = 0; i < resultLength; i++) {
            result[i] = participantSet.at(_offset + i);
        }

        return result;
    }

    function isParticipant(
        uint256 _launchpadId,
        address _user
    ) external view validLaunchpadId(_launchpadId) returns (bool) {
        return _launchpadParticipants[_launchpadId].contains(_user);
    }

    function version() external pure returns (uint256) {
        return 1;
    }

    // ============ Admin Functions ============

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function setFeeRecipient(address _feeRecipient) external onlyOwner validAddress(_feeRecipient) {
        address oldRecipient = feeRecipient;
        feeRecipient = _feeRecipient;
        emit FeeRecipientUpdated(oldRecipient, _feeRecipient);
    }

    function setTokenFactory(address _tokenFactory) external onlyOwner {
        address oldFactory = tokenFactory;
        tokenFactory = _tokenFactory;
        emit TokenFactoryUpdated(oldFactory, _tokenFactory);
    }

    /**
     * @notice Toggle the accepted-payment-token allow-list.
     * @dev Tokens that implement transfer hooks (ERC-777, ERC-1363, callback-on-transfer
     *      ERC-20 variants) MUST NOT be added — they expose `participate`,
     *      `claimVestedPayment`, and the vesting math to reentrant calls. Allow-list
     *      MUST be limited to vetted, hook-free stablecoins (USDT, USDC, vetted
     *      equivalents).
     */
    function setAcceptedPaymentToken(address _token, bool _status) external onlyOwner validAddress(_token) {
        acceptedPaymentTokens[_token] = _status;
        emit PaymentTokenUpdated(_token, _status);
    }

    function setLaunchpadFeeRate(uint256 _newRate) external onlyOwner {
        if (_newRate > MAX_FEE_RATE) revert InvalidFeeRate();
        uint256 oldRate = launchpadFeeRate;
        launchpadFeeRate = _newRate;
        emit FeeRateUpdated(oldRate, _newRate);
    }

    function setPreparationTime(uint256 _newTime) external onlyOwner {
        if (_newTime < MIN_PREPARATION_TIME || _newTime > MAX_PREPARATION_TIME) {
            revert InvalidPreparationTime();
        }
        uint256 oldTime = preparationTime;
        preparationTime = _newTime;
        emit PreparationTimeUpdated(oldTime, _newTime);
    }

    function setLaunchpadDuration(uint256 _newDuration) external onlyOwner {
        if (_newDuration < MIN_LAUNCHPAD_DURATION || _newDuration > MAX_LAUNCHPAD_DURATION) {
            revert InvalidDuration();
        }
        uint256 oldDuration = launchpadDuration;
        launchpadDuration = _newDuration;
        emit LaunchpadDurationUpdated(oldDuration, _newDuration);
    }

    function setVestingQuarterDuration(uint256 _newDuration) external onlyOwner {
        if (_newDuration < MIN_VESTING_QUARTER || _newDuration > MAX_VESTING_QUARTER) {
            revert InvalidVestingDuration();
        }
        uint256 oldDuration = vestingQuarterDuration;
        vestingQuarterDuration = _newDuration;
        emit VestingQuarterDurationUpdated(oldDuration, _newDuration);
    }

    /**
     * @notice Set the global default vesting schedule (sum-of-BPs == 10000).
     * @dev This value is read at finalize-time as a fallback when no per-launchpad
     *      override is configured. It is NEVER read at claim-time.
     */
    function setVestingSchedule(uint256[8] memory _newSchedule) external onlyOwner {
        uint256 total = 0;
        for (uint256 i = 0; i < 8; i++) {
            total += _newSchedule[i];
        }
        if (total != BASIS_POINTS) revert InvalidVestingSchedule();

        uint256[8] memory oldSchedule = vestingSchedule;
        vestingSchedule = _newSchedule;
        emit VestingScheduleUpdated(oldSchedule, _newSchedule);
    }

    /**
     * @notice Set a non-uniform vesting schedule for a specific launchpad (Preparing only).
     * @dev Sum must equal `BASIS_POINTS` (10000). Schedule is enforced over exactly
     *      `VESTING_PERIOD_COUNT` (8) periods — `vestingDuration / vestingInterval` MUST
     *      equal 8 at finalize, otherwise call `setLaunchpadVesting` first.
     */
    function setLaunchpadVestingSchedule(
        uint256 _launchpadId,
        uint256[8] memory _schedule
    ) external validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (msg.sender != launchpad.businessAccount && msg.sender != owner()) {
            revert NotBusinessOrOwner();
        }

        if (launchpad.status != LaunchpadStatus.Preparing || block.timestamp >= launchpad.startTime) {
            revert LaunchpadAlreadyStarted();
        }

        uint256 total = 0;
        for (uint256 i = 0; i < 8; i++) {
            total += _schedule[i];
        }
        if (total != BASIS_POINTS) revert InvalidVestingScheduleSum();

        uint256[8] storage stored = launchpadVestingSchedule[_launchpadId];
        for (uint256 i = 0; i < 8; i++) {
            stored[i] = _schedule[i];
        }

        emit LaunchpadVestingScheduleSet(_launchpadId, _schedule);
    }

    function updateLaunchpadSchedule(
        uint256 _launchpadId,
        uint256 _newStartTime,
        uint256 _newEndTime
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status != LaunchpadStatus.Preparing) {
            revert LaunchpadAlreadyStarted();
        }
        if (block.timestamp >= launchpad.startTime) {
            revert LaunchpadAlreadyStarted();
        }

        uint256 oldStartTime = launchpad.startTime;
        uint256 oldEndTime = launchpad.endTime;

        if (_newStartTime != 0) {
            if (_newStartTime < block.timestamp + MIN_PREPARATION_TIME) {
                revert StartTimeTooEarly();
            }
            launchpad.startTime = _newStartTime;
        }

        if (_newEndTime != 0) {
            if (_newEndTime <= launchpad.startTime) {
                revert InvalidSchedule();
            }
            launchpad.endTime = _newEndTime;
        }

        uint256 duration = launchpad.endTime - launchpad.startTime;
        if (duration < MIN_LAUNCHPAD_DURATION || duration > MAX_LAUNCHPAD_DURATION) {
            revert InvalidDuration();
        }

        emit LaunchpadScheduleUpdated(_launchpadId, oldStartTime, oldEndTime, launchpad.startTime, launchpad.endTime);
    }

    function setLaunchpadLockup(uint256 _launchpadId, uint256 _lockupDuration) external validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (msg.sender != launchpad.businessAccount && msg.sender != owner()) {
            revert NotBusinessOrOwner();
        }

        if (launchpad.status != LaunchpadStatus.Preparing || block.timestamp >= launchpad.startTime) {
            revert LaunchpadAlreadyStarted();
        }

        if (_lockupDuration > MAX_LOCKUP_DURATION) {
            revert InvalidDuration();
        }

        uint256 oldDuration = pendingLockupDuration[_launchpadId];
        pendingLockupDuration[_launchpadId] = _lockupDuration;

        emit LockupDurationUpdated(_launchpadId, oldDuration, _lockupDuration);
    }

    function updateLaunchpadLockup(
        uint256 _launchpadId,
        uint256 _lockupDuration
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status == LaunchpadStatus.Finalized || launchpad.status == LaunchpadStatus.Cancelled) {
            revert AlreadyFinalized();
        }

        if (_lockupDuration > MAX_LOCKUP_DURATION) {
            revert InvalidDuration();
        }

        uint256 oldDuration = pendingLockupDuration[_launchpadId];
        pendingLockupDuration[_launchpadId] = _lockupDuration;

        emit LockupDurationUpdated(_launchpadId, oldDuration, _lockupDuration);
    }

    /**
     * @notice Configure the per-launchpad USDT vesting (duration + interval).
     * @dev `vestingDuration / vestingInterval` MUST equal `VESTING_PERIOD_COUNT` (8) so
     *      the non-uniform 8-slot schedule maps cleanly onto the per-period unlock math.
     */
    function setLaunchpadVesting(
        uint256 _launchpadId,
        uint256 _vestingDuration,
        uint256 _vestingInterval
    ) external validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (msg.sender != launchpad.businessAccount && msg.sender != owner()) {
            revert NotBusinessOrOwner();
        }

        if (launchpad.status != LaunchpadStatus.Preparing || block.timestamp >= launchpad.startTime) {
            revert LaunchpadAlreadyStarted();
        }

        if (_vestingDuration < MIN_VESTING_DURATION || _vestingDuration > MAX_VESTING_DURATION) {
            revert InvalidVestingDuration();
        }

        if (_vestingInterval < MIN_VESTING_INTERVAL || _vestingInterval > MAX_VESTING_INTERVAL) {
            revert InvalidVestingInterval();
        }

        if (_vestingInterval > _vestingDuration) {
            revert InvalidVestingInterval();
        }

        if (_vestingDuration / _vestingInterval != VESTING_PERIOD_COUNT) {
            revert VestingPeriodCountInvalid();
        }

        pendingVestingConfig[_launchpadId] = PendingVestingConfig({
            vestingDuration: _vestingDuration,
            vestingInterval: _vestingInterval,
            isSet: true
        });

        emit VestingConfigUpdated(_launchpadId, _vestingDuration, _vestingInterval);
    }

    /**
     * @notice Owner-only update of an existing launchpad's vesting configuration.
     */
    function updateLaunchpadVesting(
        uint256 _launchpadId,
        uint256 _vestingDuration,
        uint256 _vestingInterval
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status == LaunchpadStatus.Finalized || launchpad.status == LaunchpadStatus.Cancelled) {
            revert AlreadyFinalized();
        }

        if (_vestingDuration < MIN_VESTING_DURATION || _vestingDuration > MAX_VESTING_DURATION) {
            revert InvalidVestingDuration();
        }

        if (_vestingInterval < MIN_VESTING_INTERVAL || _vestingInterval > MAX_VESTING_INTERVAL) {
            revert InvalidVestingInterval();
        }

        if (_vestingInterval > _vestingDuration) {
            revert InvalidVestingInterval();
        }

        if (_vestingDuration / _vestingInterval != VESTING_PERIOD_COUNT) {
            revert VestingPeriodCountInvalid();
        }

        pendingVestingConfig[_launchpadId] = PendingVestingConfig({
            vestingDuration: _vestingDuration,
            vestingInterval: _vestingInterval,
            isSet: true
        });

        emit VestingConfigUpdated(_launchpadId, _vestingDuration, _vestingInterval);
    }

    function setInvestorVesting(
        uint256 _launchpadId,
        uint256 _lockupDuration,
        uint256 _vestingDuration,
        uint256 _vestingInterval
    ) external validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (msg.sender != launchpad.businessAccount && msg.sender != owner()) {
            revert NotBusinessOrOwner();
        }

        if (launchpad.status != LaunchpadStatus.Preparing || block.timestamp >= launchpad.startTime) {
            revert LaunchpadAlreadyStarted();
        }

        if (_lockupDuration > MAX_LOCKUP_DURATION) {
            revert InvalidDuration();
        }

        if (_vestingDuration > 0) {
            if (_vestingDuration < MIN_VESTING_DURATION || _vestingDuration > MAX_VESTING_DURATION) {
                revert InvalidVestingDuration();
            }
            if (_vestingInterval < MIN_VESTING_INTERVAL || _vestingInterval > MAX_VESTING_INTERVAL) {
                revert InvalidVestingInterval();
            }
            if (_vestingInterval > _vestingDuration) {
                revert InvalidVestingInterval();
            }
        }

        investorVestingConfig[_launchpadId] = InvestorVestingConfig({
            lockupDuration: _lockupDuration,
            vestingDuration: _vestingDuration,
            vestingInterval: _vestingInterval,
            isSet: true
        });

        emit InvestorVestingConfigUpdated(_launchpadId, _lockupDuration, _vestingDuration, _vestingInterval);
    }

    function updateInvestorVesting(
        uint256 _launchpadId,
        uint256 _lockupDuration,
        uint256 _vestingDuration,
        uint256 _vestingInterval
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status == LaunchpadStatus.Finalized || launchpad.status == LaunchpadStatus.Cancelled) {
            revert AlreadyFinalized();
        }

        if (_lockupDuration > MAX_LOCKUP_DURATION) {
            revert InvalidDuration();
        }

        if (_vestingDuration > 0) {
            if (_vestingDuration < MIN_VESTING_DURATION || _vestingDuration > MAX_VESTING_DURATION) {
                revert InvalidVestingDuration();
            }
            if (_vestingInterval < MIN_VESTING_INTERVAL || _vestingInterval > MAX_VESTING_INTERVAL) {
                revert InvalidVestingInterval();
            }
            if (_vestingInterval > _vestingDuration) {
                revert InvalidVestingInterval();
            }
        }

        investorVestingConfig[_launchpadId] = InvestorVestingConfig({
            lockupDuration: _lockupDuration,
            vestingDuration: _vestingDuration,
            vestingInterval: _vestingInterval,
            isSet: true
        });

        emit InvestorVestingConfigUpdated(_launchpadId, _lockupDuration, _vestingDuration, _vestingInterval);
    }

    // ============ Raised-funds 3-way split — per-launchpad + global ============

    /**
     * @notice Set a per-launchpad override for the raised-funds 3-way split
     *         (Preparing only, before start). Sum of the three bp values MUST equal
     *         `BASIS_POINTS`.
     */
    function setLaunchpadFundSplit(
        uint256 _launchpadId,
        uint256 _immediateBp,
        uint256 _liquidityBp,
        uint256 _vestingBp
    ) external validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (msg.sender != launchpad.businessAccount && msg.sender != owner()) {
            revert NotBusinessOrOwner();
        }
        if (launchpad.status != LaunchpadStatus.Preparing || block.timestamp >= launchpad.startTime) {
            revert LaunchpadAlreadyStarted();
        }
        if (_immediateBp + _liquidityBp + _vestingBp != BASIS_POINTS) revert InvalidFundSplit();

        pendingFundSplitConfig[_launchpadId] = FundSplitConfig({
            immediateBp: _immediateBp,
            liquidityBp: _liquidityBp,
            vestingBp: _vestingBp,
            isSet: true
        });

        emit FundSplitSet(_launchpadId, _immediateBp, _liquidityBp, _vestingBp);
    }

    /**
     * @notice Owner-only update of an existing launchpad's fund-split override.
     */
    function updateLaunchpadFundSplit(
        uint256 _launchpadId,
        uint256 _immediateBp,
        uint256 _liquidityBp,
        uint256 _vestingBp
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status == LaunchpadStatus.Finalized || launchpad.status == LaunchpadStatus.Cancelled) {
            revert AlreadyFinalized();
        }
        if (_immediateBp + _liquidityBp + _vestingBp != BASIS_POINTS) revert InvalidFundSplit();

        pendingFundSplitConfig[_launchpadId] = FundSplitConfig({
            immediateBp: _immediateBp,
            liquidityBp: _liquidityBp,
            vestingBp: _vestingBp,
            isSet: true
        });

        emit FundSplitSet(_launchpadId, _immediateBp, _liquidityBp, _vestingBp);
    }

    /**
     * @notice Propose a change to the GLOBAL default raised-funds 3-way split
     *         (economic-sensitive — 2-day timelock).
     */
    function proposeFundSplitChange(uint256 _immediateBp, uint256 _liquidityBp, uint256 _vestingBp) external onlyOwner {
        if (_immediateBp + _liquidityBp + _vestingBp != BASIS_POINTS) revert InvalidFundSplit();
        pendingImmediateRate = _immediateBp;
        pendingLiquidityRate = _liquidityBp;
        pendingVestingRate = _vestingBp;
        fundSplitChangeTime = block.timestamp + CONFIG_DELAY;
        emit FundSplitChangeProposed(_immediateBp, _liquidityBp, _vestingBp, fundSplitChangeTime);
    }

    function executeFundSplitChange() external onlyOwner {
        if (fundSplitChangeTime == 0) revert NoPendingChange();
        if (block.timestamp < fundSplitChangeTime) revert TimelockNotReady();

        immediateRate = pendingImmediateRate;
        liquidityRate = pendingLiquidityRate;
        vestingRate = pendingVestingRate;
        fundSplitChangeTime = 0;

        emit FundSplitChangeExecuted(immediateRate, liquidityRate, vestingRate);
    }

    function cancelFundSplitChange() external onlyOwner {
        if (fundSplitChangeTime == 0) revert NoPendingChange();
        fundSplitChangeTime = 0;
        pendingImmediateRate = 0;
        pendingLiquidityRate = 0;
        pendingVestingRate = 0;
        emit FundSplitChangeCancelled();
    }

    /**
     * @notice Propose a change to the fund liquidity recipient (economic-sensitive —
     *         2-day timelock). Distinct from `TokenFactory`'s token-side
     *         LIQUIDITY_RESERVE bucket recipient.
     */
    function proposeLiquidityRecipientChange(address _newRecipient) external onlyOwner validAddress(_newRecipient) {
        pendingLiquidityRecipient = _newRecipient;
        liquidityRecipientChangeTime = block.timestamp + CONFIG_DELAY;
        emit LiquidityRecipientChangeProposed(_newRecipient, liquidityRecipientChangeTime);
    }

    function executeLiquidityRecipientChange() external onlyOwner {
        if (pendingLiquidityRecipient == address(0)) revert NoPendingChange();
        if (block.timestamp < liquidityRecipientChangeTime) revert TimelockNotReady();

        address oldRecipient = liquidityRecipient;
        liquidityRecipient = pendingLiquidityRecipient;
        pendingLiquidityRecipient = address(0);
        liquidityRecipientChangeTime = 0;

        emit LiquidityRecipientChangeExecuted(oldRecipient, liquidityRecipient);
    }

    function cancelLiquidityRecipientChange() external onlyOwner {
        if (pendingLiquidityRecipient == address(0)) revert NoPendingChange();
        address cancelled = pendingLiquidityRecipient;
        pendingLiquidityRecipient = address(0);
        liquidityRecipientChangeTime = 0;
        emit LiquidityRecipientChangeCancelled(cancelled);
    }

    /// @dev `nonReentrant` as defense-in-depth against non-standard ERC20 hooks.
    function recoverStuckTokens(
        address _token,
        address _to,
        uint256 _amount
    ) external onlyOwner nonReentrant validAddress(_token) validAddress(_to) {
        if (_amount == 0) revert InvalidAmount();

        uint256 lockedAmount = lockedTokenAmount[_token] + lockedPaymentAmount[_token];

        uint256 balance = IERC20(_token).balanceOf(address(this));
        if (_amount > balance - lockedAmount) revert TokenLockedInActiveLaunchpad();

        IERC20(_token).safeTransfer(_to, _amount);
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

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        if (pendingImplementation == address(0)) revert NoPendingUpgrade();
        if (newImplementation != pendingImplementation) revert ImplementationMismatch();
        if (block.timestamp < upgradeReadyAt) revert UpgradeNotReady();
        if (newImplementation.code.length == 0) revert InvalidImplementation();
        pendingImplementation = address(0);
        upgradeReadyAt = 0;
    }
}

/**
 * @title ITokenFactory
 * @notice Interface for the canonical `TokenFactory` (4-bucket / escrow / vesting-wallet).
 */
interface ITokenFactory {
    function getTokenInfo(
        address _tokenAddress
    ) external view returns (address businessAccount, uint256 issuedAt, bool isIssued);
    function tokenToVestingWallet(address token) external view returns (address);
    function launchpadEscrow(address token) external view returns (uint256);
    function releaseEscrow(address token) external returns (uint256);
}

/**
 * @title ITokenVestingWallet
 * @notice Minimal interface for the finalize-time Owner Vesting trigger.
 */
interface ITokenVestingWallet {
    function startVesting(uint64 startTimestamp, uint64 duration_) external;
    function duration() external view returns (uint64);
}
