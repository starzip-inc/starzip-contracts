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
import { LaunchpadMathLib } from "./LaunchpadMathLib.sol";

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
 *         `linkedLaunchpad`). Consumption blocks a second launchpad for the same token
 *         WHILE a sale is live — but not forever: a cancelled sale (`cancelLaunchpad`/
 *         `expireLaunchpad`/`cancelUnderfundedLaunchpad`) returns its unsold `saleAmount`
 *         to `TokenFactory` escrow via `restoreEscrow`, making the token resale-eligible
 *         again after `TokenFactory.resaleWaitSeconds` elapses.
 *   - `finalizeLaunchpad` splits the post-fee raised amount 3 ways — immediate
 *         (business), liquidity (fund liquidity recipient — distinct from
 *         `TokenFactory`'s token-side LIQUIDITY_RESERVE bucket), and vesting (existing
 *         per-launchpad USDT vesting flow). Defaults are set at `initialize` to the
 *         canonical tokenomics split (see that function's NatSpec); every rate
 *         (fee/immediate/liquidity/vesting) and the liquidity recipient itself is
 *         changeable only via a 2-day timelocked propose/execute (economic-sensitive).
 *
 * Vesting is admin-configurable (period count, per-period bp, T+0-or-cliff-first — see
 * {VestingScheduleConfig}) for both the business (USDT) and participant (token) sides, sharing
 * one mechanism (`LaunchpadMathLib.claimableAmount`). The business schedule is fixed at
 * `createLaunchpad` time (not finalize — see {_launchpadVestingSchedule}'s doc comment for the
 * defect this closes); the vested USDT amount itself, and the Owner Vesting trigger hook, fire
 * on finalize.
 */
contract LaunchpadV1 is Initializable, UUPSUpgradeable, Ownable2StepUpgradeable, ReentrancyGuard, PausableUpgradeable {
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;

    // ============ Constants ============
    uint256 public constant BASIS_POINTS = 10000;
    uint256 public constant MAX_FEE_RATE = 1000; // Max 10%
    uint256 public constant MIN_TOKEN_PRICE = 1e12;
    /// @dev m-1 (adversarial review): bounds the overflow vector on
    ///      `_targetRaiseAmount`'s `Math.mulDiv(saleAmount, tokenPrice, scaleFactor)` —
    ///      an unbounded `tokenPrice` could make the result not fit in 256 bits,
    ///      permanently reverting `finalizeLaunchpad` for that launchpad (escrow is
    ///      still recoverable via `expireLaunchpad`, hence MINOR not HIGH, even in the
    ///      cross-contract-reliance edge case noted below).
    ///
    ///      This is a COMPLETE closure, not just a practical mitigation, GIVEN this
    ///      contract's actual operating constraint: `saleAmount` is never
    ///      caller-supplied — it always comes from `TokenFactory.releaseEscrow`,
    ///      i.e. it is a real ERC20V1 balance, capped by
    ///      `TokenFactory.MAX_SUPPLY_PER_TOKEN == 1e27` (~2^89.7). Independently
    ///      verified: with `scaleFactor` at its worst case (1e18, `paymentDecimals ==
    ///      18`) and `tokenPrice` at this cap (1e36), the `saleAmount` value that
    ///      would actually trigger overflow is `2^256 * 1e18 / 1e36 ≈ 2^196.2` — about
    ///      32 orders of magnitude above the real 2^89.7 ceiling TokenFactory enforces.
    ///      This closure is cross-contract: it holds only as long as
    ///      `MAX_SUPPLY_PER_TOKEN` isn't raised past ~2^196 (astronomically unlikely,
    ///      but this contract cannot enforce that on its own — TokenFactory/ERC20V1's
    ///      concern, not this one's).
    uint256 public constant MAX_TOKEN_PRICE = 1e36;
    uint256 public constant MAX_BATCH_SIZE = 100;
    uint256 public constant MAX_PURCHASE_PER_USER = 1000000 * 1e18;
    uint256 public constant MIN_PREPARATION_TIME = 1 hours;
    uint256 public constant MAX_PREPARATION_TIME = 30 days;
    uint256 public constant MIN_LAUNCHPAD_DURATION = 1 days;
    uint256 public constant MAX_LAUNCHPAD_DURATION = 90 days;
    uint256 public constant MAX_LOCKUP_DURATION = 730 days;

    uint256 public constant MIN_VESTING_INTERVAL = 7 days;
    uint256 public constant MAX_VESTING_INTERVAL = 365 days;
    uint256 public constant MIN_VESTING_DURATION = 30 days;
    uint256 public constant MAX_VESTING_DURATION = 3650 days;

    /// @notice Admin-configurable vesting schedule period-count bounds (business USDT and
    ///         participant token schedules alike — see {VestingScheduleConfig}). Replaces the
    ///         former fixed `VESTING_PERIOD_COUNT == 8` constant: schedules of any length in
    ///         [MIN_VESTING_PERIODS, MAX_VESTING_PERIODS] are now valid, so a launchpad can be
    ///         configured for e.g. the 8-quarter business default, a 5-period/12-month business
    ///         schedule, or a 10-period monthly participant schedule, all through the same
    ///         mechanism. Upper-bounded to keep the per-period bp-summing loop
    ///         (`LaunchpadMathLib`) gas-bounded.
    uint256 public constant MIN_VESTING_PERIODS = 1;
    uint256 public constant MAX_VESTING_PERIODS = 24;

    /// @dev Economic-sensitive setter timelock.
    uint256 public constant CONFIG_DELAY = 2 days;

    /// @notice Grace after endTime before a stuck launchpad may be permissionlessly refunded/expired.
    ///         Production value; there is no test-scale override (constant, not a setter).
    uint256 public constant REFUND_GRACE = 14 days;

    /// @dev Timelock delay for staged UUPS upgrades.
    uint256 public constant UPGRADE_TIMELOCK_DELAY = 48 hours;

    /// @dev A staged upgrade is executable only inside
    ///      `[upgradeReadyAt, upgradeReadyAt + UPGRADE_GRACE_PERIOD]`. Without an upper bound the
    ///      48h notice degrades from "48h of live notice before every upgrade" to "one
    ///      announcement, ever" — an owner could arm during a quiet period and fire years later in
    ///      a single transaction. Matches TradeSettlementV1 and UpgradeableBeacon.
    uint256 public constant UPGRADE_GRACE_PERIOD = 7 days;

    /// @notice Softcap: `finalizeLaunchpad` reverts (`LaunchpadUnderfunded`) instead of
    ///         distributing funds if `totalRaised` is below the launchpad's OWN softcap bp
    ///         (see {launchpadSoftcapBp}, snapshotted at `createLaunchpad` time from
    ///         {softcapBp}) of the target raise (`saleAmount * tokenPrice`, see
    ///         `_targetRaiseAmount`). `>=` counts as MET (not `>`). Use
    ///         `cancelUnderfundedLaunchpad` to move an underfunded raise into
    ///         `Cancelled`/`refund()`.
    /// @dev THIS IS A FLOOR, NOT THE LIVE VALUE — read it as "the lowest {softcapBp} may ever be
    ///      set to", not "the softcap itself". The actual per-sale threshold is the mutable
    ///      {softcapBp} (owner-adjustable via {setSoftcapBp}), snapshotted into
    ///      {launchpadSoftcapBp} at creation so a later change here never reaches back into an
    ///      already-created sale — same pattern as {_defaultVestingSchedule}/
    ///      {_launchpadVestingSchedule}.
    ///
    ///      HISTORY: this value used to be the softcap OUTRIGHT (a plain `constant`, no mutable
    ///      state at all — a fixed 20%, explicitly not an adjustable governance parameter). The
    ///      product decision was later reversed: the softcap must be admin-adjustable, so
    ///      participants can see a raised bar going into a sale, but the 20% floor stays hard —
    ///      no admin action can ever move a sale's threshold below it. `MIN_RAISE_BP` therefore
    ///      keeps doing exactly the job it always did (a fixed 20% minimum, part of the audited
    ///      surface), just as a floor UNDER a mutable value now instead of being the value
    ///      itself. `initialize` seeds `softcapBp = MIN_RAISE_BP`, so an operator who never calls
    ///      `setSoftcapBp` gets exactly the original fixed-20% behavior, unchanged.
    uint256 public constant MIN_RAISE_BP = 2000;

    // ============ State ============

    uint256 public launchpadFeeRate;
    uint256 public preparationTime;
    uint256 public launchpadDuration;

    address public feeRecipient;
    address public tokenFactory;

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
        address paymentToken;
    }

    /// @notice Admin-configurable vesting shape shared by the business (USDT) and participant
    ///         (token) vesting paths — the single mechanism behind both: "one lump released at
    ///         a fixed cadence start, then N periods, each an independently configured bp share
    ///         of the total, summing to `BASIS_POINTS`."
    /// @dev `bps.length` IS the period count (replaces the former fixed `VESTING_PERIOD_COUNT`).
    ///      `firstPeriodAtZero == true` unlocks `bps[0]` at T+0 (vesting start, i.e. right after
    ///      `lockupDuration` elapses) instead of after one full `vestingInterval` — this is what
    ///      lets the participant schedule model "first tranche at listing" while the business
    ///      schedule keeps its legacy "first tranche after one full quarter" shape
    ///      (`firstPeriodAtZero == false`). See `LaunchpadMathLib.claimableAmount`.
    struct VestingScheduleConfig {
        uint256 vestingInterval;
        bool firstPeriodAtZero;
        uint256[] bps;
    }

    /// @notice Per-launchpad participant (purchased-token) vesting override.
    /// @dev When `isSet == false`, claims resolve through the SAME {LaunchpadMathLib.claimableAmount}
    ///      mechanism as a configured schedule, fed a fixed one-period/100%-at-T+0 schedule in
    ///      memory (never written to storage) — see `_calculateClaimableTokens`. This reproduces
    ///      today's "100% immediately claimable" default exactly, but as an explicit parameterization
    ///      of the general vesting formula rather than a distinct bypass branch (closes the prior
    ///      fail-open: there is no longer a code path that skips the vesting math entirely).
    struct InvestorVestingConfig {
        uint256 lockupDuration;
        VestingScheduleConfig schedule;
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
    mapping(uint256 => uint256) public investorLockupDuration;
    mapping(uint256 => InvestorVestingConfig) private investorVestingConfig;
    mapping(uint256 => uint256) public investorVestingStartTime;

    /// @notice Global default business (USDT) vesting schedule — read only at `createLaunchpad`
    ///         time (never at finalize) to seed {_launchpadVestingSchedule}. See
    ///         `setDefaultVestingSchedule`/`_snapshotDefaultVestingSchedule`.
    VestingScheduleConfig private _defaultVestingSchedule;

    /// @notice Per-launchpad snapshot of the business (USDT) vesting schedule, taken at
    ///         `createLaunchpad` time (copied from {_defaultVestingSchedule}) and overwritable
    ///         only pre-start via `setLaunchpadVestingSchedule`/`updateLaunchpadVestingSchedule`.
    /// @dev This used to be populated lazily at FINALIZE time as a fallback read of the
    ///      then-current global default, which meant changing the global default mid-sale (e.g.
    ///      while preparing a second, unrelated launchpad) retroactively changed an
    ///      already-in-flight sale's schedule. Snapshotting unconditionally at creation instead
    ///      means later global-default changes never propagate to an already-created launchpad.
    mapping(uint256 => VestingScheduleConfig) private _launchpadVestingSchedule;

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

    /// @notice Factories authorized for token workflows. Rotated-out factories remain
    ///         authorized so tokens issued by them can consume escrow and finalize.
    mapping(address => bool) public authorizedTokenFactories;

    /// @notice Factory binding captured for each sale at creation.
    mapping(uint256 => address) public launchpadTokenFactory;

    address public pendingTokenFactory;
    uint256 public tokenFactoryChangeTime;

    /// @notice Timelocked global `launchpadFeeRate` change (economic-sensitive — 2-day
    ///         timelock via `propose/execute/cancelLaunchpadFeeRateChange`). Added to
    ///         close the same "owner hot key can move a live economic parameter
    ///         mid-sale" defect class closed for per-launchpad params — this
    ///         is the GLOBAL rate, previously changeable instantly via the now-removed
    ///         `setLaunchpadFeeRate`.
    uint256 public pendingLaunchpadFeeRate;
    uint256 public launchpadFeeRateChangeTime;

    /// @notice Live default softcap (minimum-raise) bp — see {MIN_RAISE_BP}'s doc comment for
    ///         the floor it can never go below. Admin-adjustable via {setSoftcapBp}, seeded to
    ///         `MIN_RAISE_BP` at `initialize`. Read ONLY at `createLaunchpad` time to seed
    ///         {launchpadSoftcapBp} — never read again afterward, so a later change here never
    ///         retroactively moves an already-created sale's threshold (same snapshot pattern as
    ///         {_defaultVestingSchedule}).
    uint256 public softcapBp;

    /// @notice Per-launchpad softcap snapshot, taken at `createLaunchpad` time. The SINGLE
    ///         value both `finalizeLaunchpad` and `cancelUnderfundedLaunchpad` read (via
    ///         {_softcapBpFor}) — load-bearing, not just tidy: if the two consumers read this
    ///         independently and one drifted to reading the live {softcapBp} instead of this
    ///         snapshot, an admin raising the softcap mid-sale could make BOTH
    ///         `finalizeLaunchpad` (`totalRaised < requiredRaise`) and
    ///         `cancelUnderfundedLaunchpad` (`totalRaised >= requiredRaise`) revert for the same
    ///         launchpad — funds locked, reachable from neither exit.
    mapping(uint256 => uint256) public launchpadSoftcapBp;

    // ============ Storage Gap ============
    // Admin-configurable vesting schedule change (this change): storage was reorganized —
    // `vestingQuarterDuration`/`vestingSchedule` (uint256[8])/`launchpadVestingSchedule`
    // (uint256[8] per launchpad)/`PendingVestingConfig`/`pendingVestingConfig` were replaced by
    // {VestingScheduleConfig} (`_defaultVestingSchedule` + `_launchpadVestingSchedule`), and
    // `InvestorVestingConfig` grew a nested {VestingScheduleConfig}. This is NOT an append-only
    // change to prior deployments — it ships via a FRESH redeploy (no in-place UUPS upgrade of a
    // proxy with existing launchpads), so the append-only slot-preservation constraint that
    // motivated the exact `[29] -> [27]` accounting below does not apply here. `__gap` size is
    // therefore an arbitrary reserved buffer for whatever this contract's NEXT change appends, not
    // a computed complement of anything above.
    //
    // Admin-adjustable softcap change (this change): consumed 2 further slots (`softcapBp` +
    // `launchpadSoftcapBp`) from the same gap, same fresh-redeploy premise — [27] -> [25].
    uint256[25] private __gap;

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

    /// @dev Emitted IN ADDITION to {LaunchpadCancelled} by `expireLaunchpad`, so indexers can
    ///      tell a timeout apart from an owner's deliberate cancel without decoding calldata.
    event LaunchpadExpired(uint256 indexed launchpadId, uint256 timestamp);
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
    event TokenFactoryChangeProposed(address indexed newFactory, uint256 executeTime);
    event TokenFactoryChangeCancelled(address indexed cancelledFactory);
    event PaymentTokenUpdated(address indexed token, bool status);
    event FeeRateUpdated(uint256 oldRate, uint256 newRate);
    event LaunchpadFeeRateChangeProposed(uint256 newRate, uint256 executeTime);
    event LaunchpadFeeRateChangeCancelled(uint256 cancelledRate);
    event PreparationTimeUpdated(uint256 oldTime, uint256 newTime);
    event LaunchpadDurationUpdated(uint256 oldDuration, uint256 newDuration);
    event VestingScheduleUpdated(uint256[] oldBps, uint256[] newBps);
    event LaunchpadScheduleUpdated(
        uint256 indexed launchpadId,
        uint256 oldStartTime,
        uint256 oldEndTime,
        uint256 newStartTime,
        uint256 newEndTime
    );
    event LockupDurationUpdated(uint256 indexed launchpadId, uint256 oldDuration, uint256 newDuration);
    event InvestorLockupUpdated(uint256 indexed launchpadId, uint256 oldDuration, uint256 newDuration);
    event InvestorVestingConfigUpdated(
        uint256 indexed launchpadId,
        uint256 lockupDuration,
        uint256 vestingInterval,
        uint256[] bps,
        bool firstPeriodAtZero
    );

    event LaunchpadVestingScheduleSet(
        uint256 indexed launchpadId,
        uint256 vestingInterval,
        uint256[] bps,
        bool firstPeriodAtZero
    );
    event VestingScheduleSnapshot(uint256 indexed launchpadId, uint256[] bps);
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

    // Softcap (minimum-raise). `finalizeLaunchpad` no longer auto-cancels underfunded
    // raises (it reverts — see the `LaunchpadUnderfunded` error below); this event now fires
    // only from the dedicated permissionless `cancelUnderfundedLaunchpad`.
    event LaunchpadUnderfundedCancelled(uint256 indexed launchpadId, uint256 totalRaised, uint256 requiredRaise);

    /// @notice `softcapBp` changed via {setSoftcapBp} — a plain onlyOwner setter (no
    ///         propose/execute/timelock; see that function's own doc comment for why), so this
    ///         is the only event marking a softcap-default change.
    event SoftcapBpUpdated(uint256 oldBp, uint256 newBp);

    // Timelocked upgrade events
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
    /// @dev {setSoftcapBp} reverts with this outside `[MIN_RAISE_BP, BASIS_POINTS]`.
    error InvalidSoftcapBp();
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

    // m-1 (adversarial review)
    error TokenPriceTooHigh();

    // Timelocked UUPS upgrade
    error NoPendingUpgrade();
    error ImplementationMismatch();
    error UpgradeNotReady();

    /// @dev The staged upgrade matured more than UPGRADE_GRACE_PERIOD ago and is stale.
    error UpgradeExpired();

    /// @dev Ownership renouncement is disabled — see {renounceOwnership}.
    error RenounceDisabled();

    /// @dev `finalizeLaunchpad` reverts with this instead of silently succeeding into
    ///      `Cancelled` when `totalRaised` is below the softcap — see
    ///      `finalizeLaunchpad`'s doc comment. Use `cancelUnderfundedLaunchpad` to move
    ///      the raise into `Cancelled`/refund instead.
    error LaunchpadUnderfunded(uint256 raised, uint256 required);
    /// @dev `cancelUnderfundedLaunchpad` reverts with this if the raise actually cleared
    ///      the softcap — that outcome belongs to `finalizeLaunchpad`, not this function.
    error LaunchpadNotUnderfunded();

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
     * @dev The raised-funds split is set to match the canonical tokenomics spec:
     *        - Starzip subscription fee:  5%  of TOTAL raised, deducted first
     *        - Initial LP seeding:        10% of TOTAL raised
     *        - Business residual:         85% of TOTAL raised, itself split:
     *            - 20% of the 85% (= 17% of TOTAL) released immediately at listing
     *            - 80% of the 85% (= 68% of TOTAL) vests quarterly (~2 years, existing
     *              per-launchpad USDT vesting flow)
     *
     *      This contract deducts the fee FIRST (`launchpadFeeRate` against the total),
     *      then splits the REMAINDER (95% of total) via `immediateRate`/`liquidityRate`/
     *      `vestingRate`, three bp values that sum to `BASIS_POINTS` AGAINST THAT
     *      REMAINDER — not against the total. Because 10%, 17%, and 68% of TOTAL do not
     *      divide evenly into integer bp of a 95%-of-total remainder, the values below
     *      are the nearest-integer-bp approximation, not an exact match:
     *        - liquidityBp = round(10/95 * 10000) = 1053 -> 10.0035% of total (+0.0035pp)
     *        - immediateBp = round(17/95 * 10000) = 1789 -> 16.9955% of total (-0.0045pp)
     *        - vestingBp   = 10000 - liquidityBp - immediateBp = 7158 -> 68.0010% of
     *          total (+0.0010pp)
     *      The three deltas net to zero (+0.0035 - 0.0045 + 0.0010 = 0.0000pp), but each
     *      individual bucket is off the clean canonical percentage by a fraction of a
     *      basis point. This is the closest achievable integer-bp approximation given
     *      this contract's fee-first-then-split-remainder order of operations, NOT an
     *      exact reproduction of the spec's clean 5/10/17/68 total-based split.
     *
     *      `_liquidityRecipient` is set atomically here, not left to the post-deploy
     *      timelocked `propose/executeLiquidityRecipientChange`: with `liquidityRate >
     *      0` (as configured below), `finalizeLaunchpad` reverts on EVERY launchpad
     *      while `liquidityRecipient == address(0)` — deploying with a live liquidity
     *      rate and no recipient configured bricks every finalize.
     */
    function initialize(
        address _tokenFactory,
        address _defaultPaymentToken,
        address _feeRecipient,
        address _liquidityRecipient
    )
        public
        initializer
        validAddress(_tokenFactory)
        validAddress(_defaultPaymentToken)
        validAddress(_feeRecipient)
        validAddress(_liquidityRecipient)
    {
        __Ownable_init(msg.sender);
        __Pausable_init();

        tokenFactory = _tokenFactory;
        authorizedTokenFactories[_tokenFactory] = true;
        feeRecipient = _feeRecipient;

        acceptedPaymentTokens[_defaultPaymentToken] = true;
        emit PaymentTokenUpdated(_defaultPaymentToken, true);

        launchpadFeeRate = 500; // 5% — canonical Starzip subscription fee, see NatSpec above
        preparationTime = 12 hours;
        launchpadDuration = 7 days;

        // Default business (USDT) vesting schedule — identical shape/values to the former fixed
        // 8-quarter schedule (`vestingQuarterDuration = 90 days` + `vestingSchedule` bp array),
        // now expressed through {VestingScheduleConfig} so it is admin-adjustable (period count,
        // per-period bp, T+0-or-not) instead of hardcoded. `firstPeriodAtZero: false` preserves
        // the legacy behavior of the first tranche arriving after one full quarter, not at
        // listing. This is a behavioral-default regression guard: an admin who never calls
        // `setDefaultVestingSchedule` gets exactly today's schedule.
        _defaultVestingSchedule.vestingInterval = 90 days;
        _defaultVestingSchedule.firstPeriodAtZero = false;
        _defaultVestingSchedule.bps = [2000, 1000, 1000, 2000, 1000, 1000, 1000, 1000];

        // Raised-funds 3-way split of the POST-FEE remainder — nearest-integer-bp
        // approximation of the canonical 10%/17%/68%-of-total split; see NatSpec above
        // for the exact rounding delta.
        immediateRate = 1789; // ~16.9955% of total (canonical: 17%)
        liquidityRate = 1053; // ~10.0035% of total (canonical: 10%)
        vestingRate = 7158; // ~68.0010% of total (canonical: 68%)

        liquidityRecipient = _liquidityRecipient;

        // Softcap default seeded to the floor — an operator who never calls `setSoftcapBp`
        // gets exactly the original fixed-20% behavior. See MIN_RAISE_BP's doc comment.
        softcapBp = MIN_RAISE_BP;
    }

    // ============ Core Functions ============

    /**
     * @notice Create a new launchpad against the token's `TokenFactory`-escrowed
     *         LAUNCHPAD bucket. The sale amount is DERIVED from the escrow,
     *         not an arbitrary caller-supplied amount, and this contract MUST be the
     *         factory's current `linkedLaunchpad` to pull it via `releaseEscrow`.
     * @dev `TokenFactory.releaseEscrow` reverts on a second call for the same token while
     *      escrow is already consumed (`EscrowAlreadyConsumed`), so a second `createLaunchpad`
     *      for the same token is impossible WHILE a sale for it is live or was ever finalized.
     *      It IS possible again after a cancelled sale's `restoreEscrow` re-funds escrow and
     *      `TokenFactory.resaleWaitSeconds` elapses (see the contract-level NatSpec).
     *      `nonReentrant`: this function pulls funds via `TokenFactory.releaseEscrow` and, for
     *      a resold token, that escrow may itself have been re-funded through a second
     *      fund-movement leg (`restoreEscrow`) — hardening against a reentrant path through
     *      either leg even though neither is currently reachable from an untrusted token
     *      (factory-issued ERC20V1 has no transfer hooks).
     */
    // Slither false positive, and the flagged expression is the mitigation rather than the bug: the
    // `balanceAfter - balanceBefore != released` comparison exists precisely to detect a token that
    // moved a different amount than the factory reported. Slither reports the pre-call balance read
    // as "stale". `_tokenAddress` is additionally constrained to a factory-issued ERC20V1
    // BeaconProxy (no transfer hooks) and `releaseEscrow` is itself `nonReentrant` and one-shot, so
    // there is no reentrant path into this function at all.
    // slither-disable-next-line reentrancy-balance
    function createLaunchpad(
        address _tokenAddress,
        uint256 _tokenPrice,
        address _businessAccount,
        address _paymentToken,
        uint256 _startTime,
        uint256 _endTime
    )
        external
        nonReentrant
        whenNotPaused
        validAddress(_tokenAddress)
        validAddress(_businessAccount)
        validPaymentToken(_paymentToken)
    {
        if (_tokenPrice == 0) revert InvalidAmount();
        if (_tokenPrice < MIN_TOKEN_PRICE) revert TokenPriceTooLow();
        if (_tokenPrice > MAX_TOKEN_PRICE) revert TokenPriceTooHigh();

        // Resolve the token's immutable issuance-time factory from the token itself, never
        // the mutable default `tokenFactory` pointer. Rotated-out factories remain authorized
        // so in-flight sales for their tokens can still be created and finalized.
        address factory;
        try IFactoryIssuedToken(_tokenAddress).launchpad() returns (address issuingFactory) {
            factory = issuingFactory;
        } catch {
            revert TokenNotFromFactory();
        }
        if (factory != tokenFactory && !authorizedTokenFactories[factory]) revert TokenNotFromFactory();

        // Authenticate against the factory-recorded issuer, never the caller-supplied
        // _businessAccount. The token MUST come from the factory, _businessAccount MUST equal
        // the real issuer, and the caller must be the platform owner or that same issuer.
        (address issuer, , bool isIssued) = ITokenFactory(factory).getTokenInfo(_tokenAddress);
        if (!isIssued) revert TokenNotFromFactory();
        if (_businessAccount != issuer) revert NotTokenIssuer();
        if (msg.sender != owner() && msg.sender != issuer) revert NotBusinessOrOwner();

        // ---- Derive saleAmount from the factory escrow and pull it in ----
        uint256 escrowAmount = ITokenFactory(factory).launchpadEscrow(_tokenAddress);
        if (escrowAmount == 0) revert NoEscrowAvailable();

        uint256 balanceBefore = IERC20(_tokenAddress).balanceOf(address(this));
        uint256 released = ITokenFactory(factory).releaseEscrow(_tokenAddress);
        if (released != escrowAmount) revert EscrowAmountMismatch();
        uint256 balanceAfter = IERC20(_tokenAddress).balanceOf(address(this));
        if (balanceAfter - balanceBefore != released) revert EscrowAmountMismatch();

        uint256 launchpadId = launchpadCounter++;
        launchpadTokenFactory[launchpadId] = factory;

        // Snapshot the business vesting schedule NOW, not at finalize — see
        // {_launchpadVestingSchedule}'s own doc comment for why finalize-time was wrong.
        _snapshotDefaultVestingSchedule(launchpadId);

        // Snapshot the softcap NOW too, same reasoning — see {launchpadSoftcapBp}'s doc comment.
        launchpadSoftcapBp[launchpadId] = softcapBp;

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
        address vw = ITokenFactory(factory).tokenToVestingWallet(_tokenAddress);
        if (vw != address(0)) {
            launchpadOwnerVestingWallet[launchpadId] = vw;
        }

        // Refuse a sale whose softcap target degenerates to zero. `_targetRaiseAmount`
        // floors, so `released * _tokenPrice < 10**(36 - decimals)` yields a target of 0, which
        // makes `totalRaised >= requiredRaise` vacuously true — the softcap silently stops
        // existing and `cancelUnderfundedLaunchpad` becomes permanently unreachable. Rejecting at
        // creation is the only place this can be caught, since both consumers read it after the
        // sale has already taken money.
        {
            uint8 targetDecimals = _validatedDecimals(_paymentToken);
            if (Math.mulDiv(released, _tokenPrice, 10 ** (36 - targetDecimals)) == 0) revert InvalidAmount();
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

        uint8 paymentDecimals = _validatedDecimals(launchpad.paymentToken);

        // Credit the MEASURED balance delta, never the requested amount. A deflationary /
        // fee-on-transfer / negative-rebase payment token delivers less than `_paymentAmount`, and
        // crediting the request would make `lockedPaymentAmount` exceed the real balance from the
        // very first participation — after which refund, batchRefund, claimRefundAfterTimeout and
        // finalizeLaunchpad ALL revert on insufficient balance and every participant's funds are
        // stranded. `createLaunchpad` already measures its escrow pull this way (see the
        // balanceBefore/balanceAfter guard below the escrow release) and TradeSettlementV1 credits
        // measured deltas throughout; `participate` was the one fund-entry point that did not.
        // The allowlist is the first line of defence, but it is a plain onlyOwner setter with no
        // timelock and USDT-family contracts ship a dormant fee switch, so do not rely on it.
        IERC20 paymentToken = IERC20(launchpad.paymentToken);
        uint256 balanceBefore = paymentToken.balanceOf(address(this));
        paymentToken.safeTransferFrom(msg.sender, address(this), _paymentAmount);
        uint256 received = paymentToken.balanceOf(address(this)) - balanceBefore;
        if (received == 0) revert InvalidAmount();

        uint256 scaleFactor = 10 ** (36 - paymentDecimals);
        uint256 tokenAmount = Math.mulDiv(received, scaleFactor, launchpad.tokenPrice);

        if (launchpad.soldAmount + tokenAmount > launchpad.saleAmount) {
            revert ExceedsSaleAmount();
        }

        _launchpadParticipants[_launchpadId].add(msg.sender);
        ParticipantInfo storage participant = participants[_launchpadId][msg.sender];
        participant.paymentAmount += received;
        participant.tokenAmount += tokenAmount;

        if (participant.tokenAmount > MAX_PURCHASE_PER_USER) revert ExceedsPurchaseLimit();

        launchpad.totalRaised += received;
        launchpad.soldAmount += tokenAmount;

        // Lock the raised USDT so recoverStuckTokens cannot reach it while Active.
        lockedPaymentAmount[launchpad.paymentToken] += received;

        emit TokenPurchased(_launchpadId, msg.sender, received, tokenAmount);
    }

    /**
     * @notice Finalize launchpad after end time or sold out.
     * @dev Post-fee proceeds are split 3 ways (immediate / liquidity /
     *      vesting) instead of 100% flowing into the USDT vesting schedule. Also
     *      triggers Owner Vesting exactly once (hard-revert on failure). The vesting
     *      SCHEDULE itself is no longer snapshotted here — it was fixed at
     *      `createLaunchpad` time (see {_launchpadVestingSchedule}); this function only
     *      determines the vested USDT AMOUNT and start time.
     *
     *      Softcap gate: if `totalRaised` is below this launchpad's OWN softcap bp
     *      (snapshotted at `createLaunchpad` time — see {launchpadSoftcapBp}/
     *      {_softcapBpFor}) of the target raise (`saleAmount * tokenPrice`), this
     *      function REVERTS with `LaunchpadUnderfunded` — it distributes nothing and
     *      changes no state. This makes "`finalizeLaunchpad`
     *      succeeded" imply "`status == Finalized`" unconditionally: there is no longer
     *      a code path where a successful `finalizeLaunchpad` call leaves the launchpad
     *      `Cancelled`. Exactly at the threshold (`totalRaised * BASIS_POINTS ==
     *      targetRaise * _softcapBpFor(_launchpadId)`) counts as MET (softcap check is
     *      `>=`, not `>`) and finalizes normally.
     *
     *      An underfunded raise is moved into `Cancelled` (enabling
     *      `refund()`/`batchRefund()` for investors and returning the escrowed
     *      `saleAmount` to the business) via the separate, permissionless
     *      `cancelUnderfundedLaunchpad` — see that function's doc comment for why it is
     *      permissionless and how it interacts with `expireLaunchpad`.
     */
    function finalizeLaunchpad(uint256 _launchpadId) external onlyOwner nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        bool timeEnded = block.timestamp > launchpad.endTime;
        bool soldOut = launchpad.soldAmount >= launchpad.saleAmount;

        if (!timeEnded && !soldOut) revert LaunchpadNotEnded();

        // Once the refund window opens, the owner can no longer finalize — the launchpad is
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

        uint8 paymentDecimals = _validatedDecimals(launchpad.paymentToken);

        // Softcap check, evaluated unconditionally on every finalize call
        // (including totalRaised == 0 — this decimals check and the mulDiv below both
        // run regardless of whether any USDT was ever raised, unlike the fee/split
        // logic further down which is gated on `totalRaised > 0`). Reads THIS
        // launchpad's own snapshot (see {_softcapBpFor}), never the live `softcapBp` —
        // load-bearing, see {launchpadSoftcapBp}'s doc comment for the fund-lock a
        // divergent read here would reopen.
        uint256 targetRaise = _targetRaiseAmount(launchpad.saleAmount, launchpad.tokenPrice, paymentDecimals);
        uint256 requiredRaise = Math.mulDiv(targetRaise, _softcapBpFor(_launchpadId), BASIS_POINTS);
        if (launchpad.totalRaised < requiredRaise) {
            revert LaunchpadUnderfunded(launchpad.totalRaised, requiredRaise);
        }

        uint256 unsoldAmount = launchpad.saleAmount - launchpad.soldAmount;

        if (launchpad.totalRaised > 0) {
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

            // The vesting SCHEDULE (interval/bps/firstPeriodAtZero) was already fixed at
            // createLaunchpad time — see {_launchpadVestingSchedule}. Only the amount/start/
            // lockup are determined here.
            launchpadVesting[_launchpadId] = VestingInfo({
                totalAmount: vestingAmount,
                claimedAmount: 0,
                startTime: block.timestamp,
                lockupDuration: pendingLockupDuration[_launchpadId],
                paymentToken: launchpad.paymentToken
            });

            // The whole totalRaised was locked at participate(); release only the
            // portion leaving now (fee + immediate + liquidity). The remainder (==
            // vestingRemainder) stays locked and is drawn down by claimVestedPayment.
            lockedPaymentAmount[launchpad.paymentToken] -= (feeAmount + immediateAmount + liquidityAmount);
        }

        launchpad.status = LaunchpadStatus.Finalized;
        investorVestingStartTime[_launchpadId] = block.timestamp;

        if (unsoldAmount > 0) {
            IERC20(launchpad.tokenAddress).safeTransfer(launchpad.businessAccount, unsoldAmount);
        }

        // Only unsold tokens leave the lock here; sold-but-unclaimed tokens stay
        // LOCKED until each investor calls claimTokens (decremented there).
        lockedTokenAmount[launchpad.tokenAddress] -= unsoldAmount;

        emit LaunchpadFinalized(_launchpadId, launchpad.totalRaised, launchpad.soldAmount, unsoldAmount);

        _triggerOwnerVesting(_launchpadId, launchpad.tokenAddress);
    }

    /**
     * @notice Owner-only cancellation of a Preparing launchpad.
     */
    /// @dev Shared by `cancelLaunchpad`/`expireLaunchpad`/`_cancelUnderfundedLaunchpad` —
    ///      previously each of those 3 sites inlined its own copy of "flip to Cancelled, release
    ///      the token lock, return `saleAmount`". Factored out for EIP-170 headroom (single copy,
    ///      shared via JUMP — no cross-contract call).
    ///
    ///      `saleAmount` no longer goes to `launchpad.businessAccount` — it is
    ///      approved + returned to `TokenFactory` escrow via `restoreEscrow` (which does its own
    ///      balanceBefore/After verification on the pull, mirroring `createLaunchpad`'s guard on
    ///      the release leg), making the token resale-eligible after `resaleWaitSeconds`. Owner
    ///      Vesting is deliberately NOT triggered here anymore — see `_triggerOwnerVesting`'s own
    ///      callers: only `finalizeLaunchpad` (a SUCCESSFUL sale) starts it now.
    ///      `saleAmount` is always `> 0` here — `createLaunchpad` only ever sets it from a
    ///      nonzero `released` escrow amount — so the restore call is unconditional (the former
    ///      zero-guard distinction between callers no longer applies).
    function _releaseSaleTokensOnCancel(
        uint256 _launchpadId,
        LaunchpadInfo storage launchpad
    ) internal returns (uint256 saleAmount) {
        launchpad.status = LaunchpadStatus.Cancelled;
        saleAmount = launchpad.saleAmount;
        lockedTokenAmount[launchpad.tokenAddress] -= saleAmount;
        if (saleAmount > 0) {
            address factory = launchpadTokenFactory[_launchpadId];
            if (factory == address(0)) factory = tokenFactory;
            IERC20(launchpad.tokenAddress).approve(factory, saleAmount);
            ITokenFactory(factory).restoreEscrow(launchpad.tokenAddress, saleAmount);
        }
    }

    function cancelLaunchpad(uint256 _launchpadId) external onlyOwner nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status != LaunchpadStatus.Preparing) {
            revert LaunchpadNotActive();
        }

        _releaseSaleTokensOnCancel(_launchpadId, launchpad);

        emit LaunchpadCancelled(_launchpadId, block.timestamp);
    }

    /**
     * @notice Permissionlessly expire a launchpad the owner never finalized/cancelled, returning
     *         the escrowed sale tokens to `TokenFactory` escrow (resale-eligible after
     *         `resaleWaitSeconds`) and enabling refund()/batchRefund().
     * @dev Callable by ANYONE once block.timestamp > endTime + REFUND_GRACE. Transitions to the
     *      terminal Cancelled state. No tokens were ever distributed (claimTokens requires
     *      Finalized), so the full saleAmount returns to escrow and every paymentAmount stays
     *      refundable. Mirrors cancelLaunchpad's token-lock accounting (-= saleAmount).
     */
    function expireLaunchpad(uint256 _launchpadId) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status != LaunchpadStatus.Active && launchpad.status != LaunchpadStatus.Preparing) {
            revert LaunchpadNotActive();
        }
        if (block.timestamp <= launchpad.endTime + REFUND_GRACE) revert RefundNotAvailable();

        // Consistency (no finalize ran): lock release matches cancelLaunchpad's accounting.
        _releaseSaleTokensOnCancel(_launchpadId, launchpad);

        // `LaunchpadCancelled` alone made a timeout indistinguishable from an owner's
        // deliberate cancel of a prepared sale — materially different states for the launchpad and
        // member backends, and previously separable only by decoding calldata. Kept alongside the
        // original event so existing indexers do not break, matching how
        // `cancelUnderfundedLaunchpad` already emits its own marker in addition.
        emit LaunchpadCancelled(_launchpadId, block.timestamp);
        emit LaunchpadExpired(_launchpadId, block.timestamp);
    }

    /**
     * @notice Permissionlessly cancel a launchpad whose sale ended below the
     *         softcap, returning the escrowed `saleAmount` to `TokenFactory` escrow
     *         (resale-eligible after `resaleWaitSeconds`) and enabling
     *         `refund()`/`batchRefund()` for every investor.
     * @dev Split out of `finalizeLaunchpad`: that function now REVERTS (does not
     *      auto-cancel) when underfunded, so this is the only path that moves an
     *      underfunded raise into `Cancelled`. Callable by anyone once
     *      `block.timestamp > endTime`, no `REFUND_GRACE` wait required — unlike
     *      `expireLaunchpad`, this does not depend on the owner going silent, only on
     *      the sale being over and under the floor.
     *
     *      PERMISSIONLESS BY DESIGN: whether the softcap was met is a deterministic
     *      comparison of two on-chain numbers (`totalRaised` vs `requiredRaise`) with no
     *      judgment call left once the sale window has closed — gating this behind
     *      `onlyOwner` would only add a liveness dependency (investors waiting on the
     *      owner to call, or otherwise falling back on `expireLaunchpad`'s 14-day
     *      `REFUND_GRACE`) for a purely mechanical outcome. This also matches the
     *      platform's documented policy more closely than an owner-gated path would: an
     *      underfunded raise is refunded in full, automatically, with no CS/ops intervention.
     *
     *      INTERACTION WITH `expireLaunchpad`: both are permissionless terminal paths
     *      into `Cancelled` and both share this contract's single `nonReentrant` guard,
     *      so they cannot execute concurrently; whichever lands first flips `status` to
     *      `Cancelled` and the second call reverts on the `Active`/`Preparing` status
     *      check below (or `expireLaunchpad`'s equivalent) — no double-execution, no
     *      double-refund-of-escrow. Neither path makes the other redundant: this
     *      function only ever succeeds when underfunded (a well-funded but
     *      never-finalized raise is REJECTED below via `LaunchpadNotUnderfunded`, and
     *      must still fall back on `expireLaunchpad`'s 14-day backstop), while
     *      `expireLaunchpad` covers every stalled raise regardless of funding level, at
     *      the cost of the longer wait. `expireLaunchpad` therefore remains the backstop
     *      of last resort — including for an underfunded raise nobody bothers to call
     *      this function on.
     *
     *      A `Preparing` launchpad with zero participants and an elapsed `endTime`
     *      still routes here correctly: `totalRaised` is 0 and `requiredRaise` is
     *      positive, so the underfunded check is satisfied and cancellation proceeds
     *      exactly like every other zero-raise sale.
     *
     *      `requiredRaise` positivity is enforced at creation, NOT implied by
     *      `saleAmount`/`tokenPrice` being positive — an earlier version of this comment
     *      claimed the latter and was wrong. `_targetRaiseAmount` floors, so a sale small
     *      enough that `saleAmount * tokenPrice < 10**(36 - paymentDecimals)` produced
     *      `requiredRaise == 0`, which made `totalRaised >= requiredRaise` vacuously true
     *      and this permissionless fast-cancel permanently unreachable — leaving only the
     *      14-day `expireLaunchpad` backstop, and silently voiding the softcap that this
     *      launchpad's snapshotted bp (see {launchpadSoftcapBp}) documents as applying
     *      unconditionally. `createLaunchpad` now rejects such a sale outright, so the
     *      degenerate case cannot be created.
     *
     *      A launchpad still in `Preparing`
     *      BEFORE its sale has started cannot reach here at all: `endTime > startTime`
     *      always holds, so `block.timestamp > endTime` cannot be true before the sale
     *      has even started.
     *
     *      Reentrancy/CEI: shares the exact same internal helper
     *      (`_cancelUnderfundedLaunchpad`) `finalizeLaunchpad` used to call on this
     *      path — status flips to `Cancelled` before the token transfer and the
     *      Owner-Vesting external call, and this function itself carries the
     *      `nonReentrant` guard (the helper has none of its own), so the CEI ordering
     *      that was already true for the old finalize-embedded call is preserved
     *      unchanged at this new entry point.
     *
     *      COMPLEMENTARITY WITH `finalizeLaunchpad`: both compute `requiredRaise` from
     *      the exact same `_softcapBpFor(_launchpadId)` snapshot (via the shared
     *      internal helper, not two independent mapping reads), so for any
     *      `softcapBp` value ever set, `totalRaised < requiredRaise` here and
     *      `totalRaised < requiredRaise` in `finalizeLaunchpad` are the exact same
     *      boolean — one of the two functions always succeeds, never both revert. See
     *      {launchpadSoftcapBp}'s doc comment for the fund-lock this structurally
     *      rules out.
     */
    function cancelUnderfundedLaunchpad(uint256 _launchpadId) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        if (launchpad.status != LaunchpadStatus.Active && launchpad.status != LaunchpadStatus.Preparing) {
            revert LaunchpadNotActive();
        }
        if (block.timestamp <= launchpad.endTime) revert LaunchpadNotEnded();

        uint8 paymentDecimals = _validatedDecimals(launchpad.paymentToken);

        uint256 targetRaise = _targetRaiseAmount(launchpad.saleAmount, launchpad.tokenPrice, paymentDecimals);
        uint256 requiredRaise = Math.mulDiv(targetRaise, _softcapBpFor(_launchpadId), BASIS_POINTS);
        if (launchpad.totalRaised >= requiredRaise) revert LaunchpadNotUnderfunded();

        emit LaunchpadUnderfundedCancelled(_launchpadId, launchpad.totalRaised, requiredRaise);
        _cancelUnderfundedLaunchpad(_launchpadId, launchpad);
    }

    function claimTokens(uint256 _launchpadId) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];
        ParticipantInfo storage participant = participants[_launchpadId][msg.sender];

        if (launchpad.status != LaunchpadStatus.Finalized) revert LaunchpadNotEnded();
        if (participant.tokenAmount <= participant.claimedAmount) revert NoTokensToClaim();

        uint256 claimableAmount = _calculateClaimableTokens(_launchpadId, msg.sender);
        if (claimableAmount == 0) revert NothingToClaim();

        participant.claimedAmount += claimableAmount;

        // Release the lock for exactly the tokens leaving, preserving
        // lockedTokenAmount[token] >= sum of unclaimed sold tokens for that token.
        lockedTokenAmount[launchpad.tokenAddress] -= claimableAmount;

        IERC20(launchpad.tokenAddress).safeTransfer(msg.sender, claimableAmount);

        emit TokensClaimed(_launchpadId, msg.sender, claimableAmount);
    }

    /// @dev Shared payout core for `refund`/`claimRefundAfterTimeout`/`batchRefund` — previously
    ///      each of those 3 sites inlined its own copy of "mark refunded, release the payment
    ///      lock, transfer, emit". Factored out for EIP-170 headroom (single copy, shared via JUMP
    ///      — no cross-contract call). Behavior unchanged: same statements, same order, same event.
    function _payoutRefund(
        uint256 _launchpadId,
        LaunchpadInfo storage launchpad,
        ParticipantInfo storage participant,
        address _to
    ) internal {
        participant.refunded = true;
        // Release the payment lock for exactly the funds leaving.
        lockedPaymentAmount[launchpad.paymentToken] -= participant.paymentAmount;
        IERC20(launchpad.paymentToken).safeTransfer(_to, participant.paymentAmount);

        emit Refunded(_launchpadId, _to, participant.paymentAmount);
    }

    function refund(uint256 _launchpadId) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];
        ParticipantInfo storage participant = participants[_launchpadId][msg.sender];

        if (launchpad.status != LaunchpadStatus.Cancelled) revert RefundNotAvailable();
        if (participant.refunded) revert AlreadyRefunded();
        if (participant.paymentAmount == 0) revert InvalidAmount();

        _payoutRefund(_launchpadId, launchpad, participant, msg.sender);
    }

    /**
     * @notice Permissionless per-investor USDT refund from a launchpad the owner never
     *         finalized/cancelled, once block.timestamp > endTime + REFUND_GRACE.
     * @dev Does not change launchpad status (many investors call independently). Shares
     *      participant.refunded with refund()/batchRefund() ⇒ no double refund. Decrements the
     *      payment lock.
     */
    function claimRefundAfterTimeout(uint256 _launchpadId) external nonReentrant validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];
        ParticipantInfo storage participant = participants[_launchpadId][msg.sender];

        if (launchpad.status != LaunchpadStatus.Active && launchpad.status != LaunchpadStatus.Preparing) {
            revert RefundNotAvailable();
        }
        if (block.timestamp <= launchpad.endTime + REFUND_GRACE) revert RefundNotAvailable();
        if (participant.refunded) revert AlreadyRefunded();
        if (participant.paymentAmount == 0) revert InvalidAmount();

        _payoutRefund(_launchpadId, launchpad, participant, msg.sender);
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
                _payoutRefund(_launchpadId, launchpad, pInfo, _participants[i]);
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

        uint8 paymentDecimals = _validatedDecimals(vesting.paymentToken);
        uint256 claimableInPaymentDecimals = claimableAmount / (10 ** (18 - paymentDecimals));

        lockedPaymentAmount[vesting.paymentToken] -= claimableInPaymentDecimals;

        IERC20(vesting.paymentToken).safeTransfer(msg.sender, claimableInPaymentDecimals);

        emit VestingClaimed(msg.sender, claimableAmount);
    }

    // ============ Internal Functions ============

    /// @dev Shared by `createLaunchpad`/`participate`/`finalizeLaunchpad`/
    ///      `cancelUnderfundedLaunchpad`/`claimVestedPayment` — previously each of those 5 sites
    ///      inlined its own copy of "fetch `decimals()`, reject outside `[6, 18]`". Factored out
    ///      for EIP-170 headroom (single copy, shared via JUMP — no cross-contract call, so unlike
    ///      a library extraction this is a pure win). Behavior unchanged: same condition, same
    ///      revert, same external `decimals()` call.
    function _validatedDecimals(address _token) internal view returns (uint8) {
        uint8 tokenDecimals = IERC20Metadata(_token).decimals();
        if (tokenDecimals < 6 || tokenDecimals > 18) revert InvalidTokenDecimals();
        return tokenDecimals;
    }

    /// @dev Shared by `finalizeLaunchpad`/`cancelUnderfundedLaunchpad` — THE single reader of
    ///      {launchpadSoftcapBp} both go through. This is load-bearing, not just a JUMP-sharing
    ///      tidy-up: see {launchpadSoftcapBp}'s doc comment for the fund-lock a divergent read
    ///      (one call site reading the snapshot, the other reading the live {softcapBp}) would
    ///      reopen — routing both through this one function makes that divergence structurally
    ///      impossible to reintroduce by accident.
    function _softcapBpFor(uint256 _launchpadId) internal view returns (uint256) {
        return launchpadSoftcapBp[_launchpadId];
    }

    /// @dev Called ONCE, from `createLaunchpad`, unconditionally copying the CURRENT
    ///      global default into this launchpad's own slot. Unlike the former finalize-time
    ///      version, there is no "hasOverride" branch here — at creation time no per-launchpad
    ///      override can exist yet, so this is always a plain copy. A later
    ///      `setLaunchpadVestingSchedule`/`updateLaunchpadVestingSchedule` call (Preparing,
    ///      pre-start) simply overwrites what this wrote; a later change to the GLOBAL default
    ///      never reaches back into an already-created launchpad.
    function _snapshotDefaultVestingSchedule(uint256 _launchpadId) internal {
        uint256[] memory bps = _defaultVestingSchedule.bps;
        VestingScheduleConfig storage dst = _launchpadVestingSchedule[_launchpadId];
        dst.vestingInterval = _defaultVestingSchedule.vestingInterval;
        dst.firstPeriodAtZero = _defaultVestingSchedule.firstPeriodAtZero;
        dst.bps = bps;

        emit VestingScheduleSnapshot(_launchpadId, bps);
    }

    /// @dev Shared validation for every schedule setter (global default, per-launchpad business
    ///      override, per-launchpad participant override): period count in bounds, bps sum to
    ///      exactly `BASIS_POINTS`, interval in bounds, and — only when there's more than one
    ///      period, since a single-period ("cliff then lump") schedule has no real "duration" to
    ///      bound — the derived `vestingInterval * periodCount` duration in bounds.
    function _validateSchedule(VestingScheduleConfig memory _schedule) internal pure {
        uint256 periodCount = _schedule.bps.length;
        if (periodCount < MIN_VESTING_PERIODS || periodCount > MAX_VESTING_PERIODS) {
            revert VestingPeriodCountInvalid();
        }

        uint256 sum;
        for (uint256 i = 0; i < periodCount; ) {
            sum += _schedule.bps[i];
            unchecked {
                ++i;
            }
        }
        if (sum != BASIS_POINTS) revert InvalidVestingScheduleSum();

        if (_schedule.vestingInterval < MIN_VESTING_INTERVAL || _schedule.vestingInterval > MAX_VESTING_INTERVAL) {
            revert InvalidVestingInterval();
        }

        if (periodCount > 1) {
            uint256 duration = _schedule.vestingInterval * periodCount;
            if (duration < MIN_VESTING_DURATION || duration > MAX_VESTING_DURATION) {
                revert InvalidVestingDuration();
            }
        }
    }

    /// @dev Only `finalizeLaunchpad` calls this now (a cancel/expire no longer triggers
    ///      Owner Vesting — see {_releaseSaleTokensOnCancel}'s doc comment). The `started()`
    ///      guard below is still required even so: a RESOLD token's Owner Vesting wallet may
    ///      already have been started by `TokenFactory.reclaimEscrow` or
    ///      `TokenFactory.triggerOwnerVesting` while the token sat unconsumed in escrow between
    ///      sales — `startVesting` itself has no reset path (`AlreadyStarted`, hard-revert), so
    ///      without this guard a resold token's successful `finalizeLaunchpad` could revert here.
    function _triggerOwnerVesting(uint256 _launchpadId, address _tokenAddress) internal {
        address vw = launchpadOwnerVestingWallet[_launchpadId];
        if (vw == address(0)) return;
        if (ownerVestingTrigger[_launchpadId]) return;

        address factory = launchpadTokenFactory[_launchpadId];
        // Upgrade compatibility for sales created before per-sale factory snapshots.
        if (factory == address(0)) factory = tokenFactory;
        address current = ITokenFactory(factory).tokenToVestingWallet(_tokenAddress);
        if (current != vw) revert VestingWalletNotConfigured();

        uint64 dur = ITokenVestingWallet(vw).duration();
        uint64 nowTs = uint64(block.timestamp);

        if (!ITokenVestingWallet(vw).started()) {
            ITokenVestingWallet(vw).startVesting(nowTs, dur);
            emit OwnerVestingStarted(_launchpadId, _tokenAddress, vw, nowTs, dur);
        }

        ownerVestingTrigger[_launchpadId] = true;
    }

    /**
     * @notice The USDT/stablecoin amount that would be raised if `saleAmount`
     *         tokens sold at `tokenPrice`, in the payment token's own decimals.
     * @dev Exact inverse of the `participate()` conversion (`tokenAmount =
     *      paymentAmount * scaleFactor / tokenPrice`), so this is consistent with the
     *      same rounding direction investors experience: `Math.mulDiv` floors both
     *      here and in `participate()`, so summing floored `tokenAmount`s up to
     *      exactly `saleAmount` (i.e. `soldOut`) requires `totalRaised >=` this
     *      function's result (the true fully-sold raise is never LESS than the
     *      floored target). Consequently `soldOut` always implies the softcap is met
     *      (this holds for any bp value `<= BASIS_POINTS`; every valid `softcapBp` stays
     *      within that range — {setSoftcapBp} bounds it to `[MIN_RAISE_BP,
     *      BASIS_POINTS]`). This specific claim was independently
     *      fuzzed by an adversarial code-review pass (400,000
     *      random trials, 0 counterexamples reported — not re-run by this session)
     *      and is additionally pinned by the "soldOut always satisfies the softcap"
     *      test in this repo.
     *
     *      NOT extracted to `LaunchpadMathLib` alongside the vesting math: measured
     *      empirically (this same change) — moving this 2-line function plus the
     *      finalize-time fee/3-way-split arithmetic to external library calls INCREASED
     *      `LaunchpadV1`'s deployed size (24,112 -> 24,268 bytes) rather than shrinking
     *      it. `Math.mulDiv` stays embedded in this contract regardless (it is still
     *      used directly in `participate()`, deliberately never moved — see that
     *      function's own reasoning), so extracting these small, few-line, many-
     *      parameter call sites only added ABI-encode/decode overhead without removing
     *      anything already paid for. Reverted; left inline.
     */
    function _targetRaiseAmount(
        uint256 _saleAmount,
        uint256 _tokenPrice,
        uint8 _paymentDecimals
    ) internal pure returns (uint256) {
        uint256 scaleFactor = 10 ** (36 - _paymentDecimals);
        return Math.mulDiv(_saleAmount, _tokenPrice, scaleFactor);
    }

    /**
     * @notice Route an under-raised launchpad into the existing terminal
     *         `Cancelled` state instead of distributing funds.
     * @dev Mirrors `cancelLaunchpad`/`expireLaunchpad` exactly: the FULL `saleAmount`
     *      (not just the unsold remainder) returns to `TokenFactory` escrow — the sale is
     *      voided outright, so sold-but-unclaimed tokens never become claimable
     *      (`claimTokens` requires `Finalized`). `lockedPaymentAmount` is untouched
     *      here because no funds have left the contract yet (finalize takes no fee /
     *      immediate / liquidity / vesting cut on this path) — every participant's
     *      `paymentAmount` stays exactly as locked as `participate()` left it, ready
     *      for `refund()`/`batchRefund()`/`claimRefundAfterTimeout` to release.
     */
    function _cancelUnderfundedLaunchpad(uint256 _launchpadId, LaunchpadInfo storage launchpad) internal {
        _releaseSaleTokensOnCancel(_launchpadId, launchpad);

        emit LaunchpadCancelled(_launchpadId, block.timestamp);
    }

    /// @dev Body extracted to `LaunchpadMathLib.claimableAmount` for EIP-170 headroom (that
    ///      library's own NatSpec has the full rationale + the sharing guarantee). This is now a
    ///      storage-to-memory read plus a DELEGATECALL into the library, and it is the SAME
    ///      library function {_calculateClaimableTokens} below calls for the participant side —
    ///      one mechanism, two callers.
    function _calculateClaimableVesting(uint256 _launchpadId) internal view returns (uint256) {
        VestingInfo storage vesting = launchpadVesting[_launchpadId];
        VestingScheduleConfig storage schedule = _launchpadVestingSchedule[_launchpadId];
        uint256[] memory bps = schedule.bps;
        return
            LaunchpadMathLib.claimableAmount(
                vesting.totalAmount,
                vesting.claimedAmount,
                vesting.startTime,
                vesting.lockupDuration,
                schedule.vestingInterval,
                bps,
                schedule.firstPeriodAtZero,
                block.timestamp
            );
    }

    /// @dev Body extracted to `LaunchpadMathLib.claimableAmount` for EIP-170 headroom — the SAME
    ///      library function {_calculateClaimableVesting} above calls for the business side.
    ///      `config.isSet == false` no longer skips the vesting math (the prior fail-open): it now
    ///      feeds the SAME formula a fixed one-period/100%-at-T+0 schedule kept only in memory
    ///      (never written to storage), reproducing today's "100% immediately claimable" default
    ///      exactly, but as an explicit parameterization rather than a bypass branch.
    function _calculateClaimableTokens(uint256 _launchpadId, address _investor) internal view returns (uint256) {
        ParticipantInfo storage participant = participants[_launchpadId][_investor];
        InvestorVestingConfig storage config = investorVestingConfig[_launchpadId];

        uint256 totalTokens = participant.tokenAmount;
        uint256 claimed = participant.claimedAmount;

        if (totalTokens <= claimed) return 0;

        if (!config.isSet) {
            uint256[] memory defaultBps = new uint256[](1);
            defaultBps[0] = BASIS_POINTS;
            return
                LaunchpadMathLib.claimableAmount(
                    totalTokens,
                    claimed,
                    investorVestingStartTime[_launchpadId],
                    0, // lockupDuration
                    1, // vestingInterval — irrelevant for a 1-period, firstPeriodAtZero schedule
                    defaultBps,
                    true, // firstPeriodAtZero
                    block.timestamp
                );
        }

        uint256[] memory bps = config.schedule.bps;
        return
            LaunchpadMathLib.claimableAmount(
                totalTokens,
                claimed,
                investorVestingStartTime[_launchpadId],
                config.lockupDuration,
                config.schedule.vestingInterval,
                bps,
                config.schedule.firstPeriodAtZero,
                block.timestamp
            );
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

    /// @notice Per-launchpad business (USDT) vesting schedule, fixed at `createLaunchpad` time
    ///         (see {_launchpadVestingSchedule}).
    function getLaunchpadVestingSchedule(
        uint256 _launchpadId
    ) external view validLaunchpadId(_launchpadId) returns (VestingScheduleConfig memory) {
        return _launchpadVestingSchedule[_launchpadId];
    }

    /// @notice Global default business (USDT) vesting schedule — read by `createLaunchpad` to
    ///         seed each new launchpad's own schedule; never read again after that.
    function getDefaultVestingSchedule() external view returns (VestingScheduleConfig memory) {
        return _defaultVestingSchedule;
    }

    /// @dev Body extracted to `LaunchpadMathLib.currentVestingPeriod` for EIP-170 headroom.
    function getCurrentVestingPeriod(
        uint256 _launchpadId
    ) external view validLaunchpadId(_launchpadId) returns (uint256) {
        VestingInfo storage vesting = launchpadVesting[_launchpadId];
        VestingScheduleConfig storage schedule = _launchpadVestingSchedule[_launchpadId];
        return
            LaunchpadMathLib.currentVestingPeriod(
                vesting.totalAmount,
                vesting.startTime,
                vesting.lockupDuration,
                schedule.vestingInterval,
                schedule.firstPeriodAtZero,
                schedule.bps.length,
                block.timestamp
            );
    }

    /// @dev Body extracted to `LaunchpadMathLib.vestingScheduleInfo` for EIP-170 headroom.
    ///      This view and the claim path (`_calculateClaimableVesting`) MUST agree — they used
    ///      to disagree, with this view reporting a linear fraction while claims used the real bp
    ///      schedule. Both now resolve
    ///      through the exact same library function's internal bp-summing helper; see
    ///      `LaunchpadMathLib`'s own NatSpec for the sharing guarantee. Behavior unchanged.
    function getVestingScheduleInfo(
        uint256 _launchpadId
    )
        external
        view
        validLaunchpadId(_launchpadId)
        returns (uint256 totalPeriods, uint256 amountPerPeriod, uint256 currentPeriod, uint256 totalUnlocked)
    {
        VestingInfo storage vesting = launchpadVesting[_launchpadId];
        VestingScheduleConfig storage schedule = _launchpadVestingSchedule[_launchpadId];
        uint256[] memory bps = schedule.bps;
        return
            LaunchpadMathLib.vestingScheduleInfo(
                vesting.totalAmount,
                vesting.startTime,
                vesting.lockupDuration,
                schedule.vestingInterval,
                bps,
                schedule.firstPeriodAtZero,
                block.timestamp
            );
    }

    // `getCurrentQuarter(uint256)` and `getAllQuarterlyVestingAmounts(uint256)` were removed here.
    // They had been reduced to bodies that only `revert DeprecatedFunction()` when the quarterly
    // model was replaced by the per-launchpad bp schedule, so they moved no state and returned no
    // data — a caller on either selector reverted then and reverts now, just with the EVM's
    // no-such-function revert instead of a named error. They were deleted to buy contract-size
    // headroom: LaunchpadV1's deployed bytecode sits close enough to the 24,576-byte EIP-170 limit
    // that carrying dead selectors is no longer free. Use `getVestingScheduleInfo` /
    // `getLaunchpadVestingSchedule` instead.

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

    function setTokenFactory(address _tokenFactory) external onlyOwner validAddress(_tokenFactory) {
        if (_tokenFactory.code.length == 0) revert InvalidImplementation();
        pendingTokenFactory = _tokenFactory;
        tokenFactoryChangeTime = block.timestamp + CONFIG_DELAY;
        emit TokenFactoryChangeProposed(_tokenFactory, tokenFactoryChangeTime);
    }

    function executeTokenFactoryChange() external onlyOwner {
        address newFactory = pendingTokenFactory;
        if (newFactory == address(0)) revert NoPendingChange();
        if (block.timestamp < tokenFactoryChangeTime) revert TimelockNotReady();

        address oldFactory = tokenFactory;
        authorizedTokenFactories[oldFactory] = true;
        authorizedTokenFactories[newFactory] = true;
        tokenFactory = newFactory;
        pendingTokenFactory = address(0);
        tokenFactoryChangeTime = 0;
        emit TokenFactoryUpdated(oldFactory, newFactory);
    }

    function cancelTokenFactoryChange() external onlyOwner {
        address cancelled = pendingTokenFactory;
        if (cancelled == address(0)) revert NoPendingChange();
        pendingTokenFactory = address(0);
        tokenFactoryChangeTime = 0;
        emit TokenFactoryChangeCancelled(cancelled);
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

    /**
     * @notice Propose a change to the GLOBAL `launchpadFeeRate` (economic-sensitive —
     *         2-day timelock).
     * @dev This used to be an instant `onlyOwner` setter, yet `finalizeLaunchpad`
     *      live-reads `launchpadFeeRate` — an owner hot key could raise the fee right
     *      before finalizing an in-flight sale, the same defect class already closed
     *      for per-launchpad parameters. This mirrors the existing
     *      `proposeFundSplitChange`/`executeFundSplitChange`/`cancelFundSplitChange`
     *      convention rather than inventing a new one.
     */
    function proposeLaunchpadFeeRateChange(uint256 _newRate) external onlyOwner {
        if (_newRate > MAX_FEE_RATE) revert InvalidFeeRate();
        pendingLaunchpadFeeRate = _newRate;
        launchpadFeeRateChangeTime = block.timestamp + CONFIG_DELAY;
        emit LaunchpadFeeRateChangeProposed(_newRate, launchpadFeeRateChangeTime);
    }

    function executeLaunchpadFeeRateChange() external onlyOwner {
        if (launchpadFeeRateChangeTime == 0) revert NoPendingChange();
        if (block.timestamp < launchpadFeeRateChangeTime) revert TimelockNotReady();

        uint256 oldRate = launchpadFeeRate;
        launchpadFeeRate = pendingLaunchpadFeeRate;
        pendingLaunchpadFeeRate = 0;
        launchpadFeeRateChangeTime = 0;
        emit FeeRateUpdated(oldRate, launchpadFeeRate);
    }

    function cancelLaunchpadFeeRateChange() external onlyOwner {
        if (launchpadFeeRateChangeTime == 0) revert NoPendingChange();
        uint256 cancelled = pendingLaunchpadFeeRate;
        pendingLaunchpadFeeRate = 0;
        launchpadFeeRateChangeTime = 0;
        emit LaunchpadFeeRateChangeCancelled(cancelled);
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

    /**
     * @notice Set the global default business (USDT) vesting schedule.
     * @dev Merges the former separate `setVestingQuarterDuration`/`setVestingSchedule` into one
     *      call — interval, per-period bps, and the T+0 flag are one config, not two independently
     *      mutable knobs that could drift out of sync. Validated by {_validateSchedule}. This
     *      value is read ONLY at `createLaunchpad` time (see {_snapshotDefaultVestingSchedule});
     *      it is NEVER read again afterward, including at finalize or claim time — see the
     *      note on {_launchpadVestingSchedule}.
     */
    function setDefaultVestingSchedule(VestingScheduleConfig calldata _schedule) external onlyOwner {
        _validateSchedule(_schedule);

        uint256[] memory oldBps = _defaultVestingSchedule.bps;
        _defaultVestingSchedule.vestingInterval = _schedule.vestingInterval;
        _defaultVestingSchedule.firstPeriodAtZero = _schedule.firstPeriodAtZero;
        _defaultVestingSchedule.bps = _schedule.bps;

        emit VestingScheduleUpdated(oldBps, _schedule.bps);
    }

    /**
     * @dev m-4-style shared validation+write core for
     *      `setLaunchpadVestingSchedule`/`updateLaunchpadVestingSchedule` — see
     *      `_writeLaunchpadLockup` for the rationale (same defect class, same fix shape).
     *      Merges the former separate `setLaunchpadVesting` (duration/interval) and
     *      `setLaunchpadVestingSchedule` (bp array) into one call, for the same reason as
     *      {setDefaultVestingSchedule}.
     */
    function _writeLaunchpadVestingSchedule(
        uint256 _launchpadId,
        LaunchpadInfo storage launchpad,
        VestingScheduleConfig calldata _schedule
    ) internal {
        _requirePreparingBeforeStart(launchpad);
        _validateSchedule(_schedule);

        VestingScheduleConfig storage dst = _launchpadVestingSchedule[_launchpadId];
        dst.vestingInterval = _schedule.vestingInterval;
        dst.firstPeriodAtZero = _schedule.firstPeriodAtZero;
        dst.bps = _schedule.bps;

        emit LaunchpadVestingScheduleSet(
            _launchpadId,
            _schedule.vestingInterval,
            _schedule.bps,
            _schedule.firstPeriodAtZero
        );
    }

    /**
     * @notice Set a per-launchpad override of the business (USDT) vesting schedule (Preparing
     *         only, before start). Sum of `_schedule.bps` MUST equal `BASIS_POINTS`.
     * @dev Overwrites the create-time snapshot taken by {_snapshotDefaultVestingSchedule} — see
     * That function's own doc comment for the fix this ordering closes.
     */
    function setLaunchpadVestingSchedule(
        uint256 _launchpadId,
        VestingScheduleConfig calldata _schedule
    ) external validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        _requireBusinessOrOwner(launchpad);
        _writeLaunchpadVestingSchedule(_launchpadId, launchpad, _schedule);
    }

    /**
     * @notice Owner-only update of an existing launchpad's business vesting schedule override.
     * @dev Same Preparing + pre-start gate as `setLaunchpadVestingSchedule` — per-launchpad
     *      parameters in this contract have never used `CONFIG_DELAY`; see
     *      `updateLaunchpadFundSplit`'s doc comment for the full convention rationale.
     */
    function updateLaunchpadVestingSchedule(
        uint256 _launchpadId,
        VestingScheduleConfig calldata _schedule
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        _writeLaunchpadVestingSchedule(_launchpadId, launchpads[_launchpadId], _schedule);
    }

    function updateLaunchpadSchedule(
        uint256 _launchpadId,
        uint256 _newStartTime,
        uint256 _newEndTime
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        // Logically identical to the original two separate `if` blocks (status != Preparing OR
        // timestamp >= startTime, same revert, nothing observable happens between the two checks)
        // — now routed through the same shared gate every other per-launchpad setter uses.
        _requirePreparingBeforeStart(launchpad);

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

    /// @dev Shared by every per-launchpad setter below (`setLaunchpadVestingSchedule`,
    ///      `_writeLaunchpadLockup`, `_writeLaunchpadVesting`, `_writeInvestorVesting`,
    ///      `_writeLaunchpadFundSplit`) — previously this exact 3-line gate was duplicated
    ///      5 times as separate inline `if` blocks, each compiled as its own bytecode copy.
    ///      Factored out for EIP-170 headroom (single copy, shared via JUMP — no cross-contract
    ///      call, no ABI-encode overhead, so unlike a library extraction this is a pure win).
    ///      Behavior unchanged: same condition, same revert.
    function _requirePreparingBeforeStart(LaunchpadInfo storage launchpad) internal view {
        if (launchpad.status != LaunchpadStatus.Preparing || block.timestamp >= launchpad.startTime) {
            revert LaunchpadAlreadyStarted();
        }
    }

    /// @dev Shared by every per-launchpad `set*` entry point below — previously this exact
    ///      3-line check was duplicated 5 times. Same rationale/shape as
    ///      {_requirePreparingBeforeStart}. Behavior unchanged: same condition, same revert.
    function _requireBusinessOrOwner(LaunchpadInfo storage launchpad) internal view {
        if (msg.sender != launchpad.businessAccount && msg.sender != owner()) {
            revert NotBusinessOrOwner();
        }
    }

    /**
     * @dev m-4 (adversarial review): shared validation+write core for
     *      `setLaunchpadLockup`/`updateLaunchpadLockup` — the two differ ONLY in who
     *      may call them (business-or-owner vs owner-only), enforced by each caller
     *      BEFORE reaching here. Consolidating the duplicated pre-start-gate +
     *      MAX_LOCKUP_DURATION validation (previously ~14 lines x2, and the exact kind
     *      of duplication that let the guard fix land on one copy and not
     *      the other) removes the risk of the two copies drifting apart again, without
     *      changing either function's external ABI (signature/selector/modifiers
     *      unchanged).
     */
    function _writeLaunchpadLockup(
        uint256 _launchpadId,
        LaunchpadInfo storage launchpad,
        uint256 _lockupDuration
    ) internal {
        _requirePreparingBeforeStart(launchpad);

        if (_lockupDuration > MAX_LOCKUP_DURATION) {
            revert InvalidDuration();
        }

        uint256 oldDuration = pendingLockupDuration[_launchpadId];
        pendingLockupDuration[_launchpadId] = _lockupDuration;

        emit LockupDurationUpdated(_launchpadId, oldDuration, _lockupDuration);
    }

    function setLaunchpadLockup(uint256 _launchpadId, uint256 _lockupDuration) external validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        _requireBusinessOrOwner(launchpad);

        _writeLaunchpadLockup(_launchpadId, launchpad, _lockupDuration);
    }

    /**
     * @dev Restricted to
     *      Preparing + before start, identical to `setLaunchpadLockup`. Previously
     *      only blocked Finalized/Cancelled, so the owner could retroactively change
     *      an already-purchasing investor's lockup mid-Active-sale. Same convention
     *      rationale as `updateLaunchpadFundSplit`/`updateInvestorVesting`:
     *      per-launchpad parameters use the pre-start gate, not `CONFIG_DELAY`.
     * @dev m-5 (adversarial review, off-chain decoder impact — RECORDED here for
     *      anyone maintaining a revert-reason decoder): this function's revert
     *      selector for "too late to change this" changed from `AlreadyFinalized()`
     *      to `LaunchpadAlreadyStarted()` as part of this same fix. Same change
     *      applies to `updateLaunchpadVestingSchedule`, `updateInvestorVesting`, and
     *      `updateLaunchpadFundSplit` below.
     */
    function updateLaunchpadLockup(
        uint256 _launchpadId,
        uint256 _lockupDuration
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        _writeLaunchpadLockup(_launchpadId, launchpads[_launchpadId], _lockupDuration);
    }

    /**
     * @dev m-4 (adversarial review): shared validation+write core for
     *      `setInvestorVesting`/`updateInvestorVesting` — see `_writeLaunchpadLockup`
     *      for the rationale (same defect class, same fix shape). Validated by the same
     *      {_validateSchedule} the business-side setters use — one mechanism, both sides.
     */
    function _writeInvestorVesting(
        uint256 _launchpadId,
        LaunchpadInfo storage launchpad,
        uint256 _lockupDuration,
        VestingScheduleConfig calldata _schedule
    ) internal {
        _requirePreparingBeforeStart(launchpad);

        if (_lockupDuration > MAX_LOCKUP_DURATION) {
            revert InvalidDuration();
        }

        _validateSchedule(_schedule);

        InvestorVestingConfig storage config = investorVestingConfig[_launchpadId];
        config.lockupDuration = _lockupDuration;
        config.schedule.vestingInterval = _schedule.vestingInterval;
        config.schedule.firstPeriodAtZero = _schedule.firstPeriodAtZero;
        config.schedule.bps = _schedule.bps;
        config.isSet = true;

        emit InvestorVestingConfigUpdated(
            _launchpadId,
            _lockupDuration,
            _schedule.vestingInterval,
            _schedule.bps,
            _schedule.firstPeriodAtZero
        );
    }

    /**
     * @notice Configure the per-launchpad participant (purchased-token) vesting: a cliff
     *         (`_lockupDuration`) followed by `_schedule` (sum-of-bps == `BASIS_POINTS`).
     */
    function setInvestorVesting(
        uint256 _launchpadId,
        uint256 _lockupDuration,
        VestingScheduleConfig calldata _schedule
    ) external validLaunchpadId(_launchpadId) {
        LaunchpadInfo storage launchpad = launchpads[_launchpadId];

        _requireBusinessOrOwner(launchpad);

        _writeInvestorVesting(_launchpadId, launchpad, _lockupDuration, _schedule);
    }

    /**
     * @dev Restricted to Preparing + before start, identical to
     *      `setInvestorVesting`. Previously this only blocked Finalized/Cancelled, so
     *      the owner could call it while Active and retroactively impose up to a
     *      730-day lockup on tokens investors had already purchased
     *      (`investorVestingStartTime` is set at finalize, and
     *      `_calculateClaimableTokens` reads `investorVestingConfig` live — no
     *      snapshot protects already-sold participants). Same convention rationale as
     *      `updateLaunchpadFundSplit`: per-launchpad parameters use the
     *      pre-start gate, not `CONFIG_DELAY`.
     */
    function updateInvestorVesting(
        uint256 _launchpadId,
        uint256 _lockupDuration,
        VestingScheduleConfig calldata _schedule
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        _writeInvestorVesting(_launchpadId, launchpads[_launchpadId], _lockupDuration, _schedule);
    }

    // ============ Raised-funds 3-way split — per-launchpad + global ============

    /**
     * @dev m-4 (adversarial review): shared validation+write core for
     *      `setLaunchpadFundSplit`/`updateLaunchpadFundSplit` — see
     *      `_writeLaunchpadLockup` for the rationale (same defect class, same fix
     *      shape). Sum of the three bp values MUST equal `BASIS_POINTS`.
     */
    function _writeLaunchpadFundSplit(
        uint256 _launchpadId,
        LaunchpadInfo storage launchpad,
        uint256 _immediateBp,
        uint256 _liquidityBp,
        uint256 _vestingBp
    ) internal {
        _requirePreparingBeforeStart(launchpad);
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

        _requireBusinessOrOwner(launchpad);
        _writeLaunchpadFundSplit(_launchpadId, launchpad, _immediateBp, _liquidityBp, _vestingBp);
    }

    /**
     * @notice Owner-only update of an existing launchpad's fund-split override.
     * @dev Restricted to Preparing + before start, identical to
     *      `setLaunchpadFundSplit`. The per-launchpad override is live-read at
     *      finalize time (see `finalizeLaunchpad`), so allowing this while
     *      Active/Ended would let a single hot key change the raised-funds split
     *      mid-sale — contradicting this contract's own "all rates are timelocked"
     *      documentation (see the contract-level NatSpec above). Per-launchpad
     *      parameters in this contract have never used `CONFIG_DELAY` (that's
     *      reserved for GLOBAL economic settings — see `proposeFundSplitChange`
     *      etc.); every other per-launchpad setter (`setLaunchpadVestingSchedule`,
     *      `setLaunchpadLockup`, `setInvestorVesting`, `setLaunchpadFundSplit`)
     *      uses this same pre-start gate, so this matches existing convention rather
     *      than introducing a new one.
     */
    function updateLaunchpadFundSplit(
        uint256 _launchpadId,
        uint256 _immediateBp,
        uint256 _liquidityBp,
        uint256 _vestingBp
    ) external onlyOwner validLaunchpadId(_launchpadId) {
        _writeLaunchpadFundSplit(_launchpadId, launchpads[_launchpadId], _immediateBp, _liquidityBp, _vestingBp);
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

        // Clear every pending field, matching cancelFundSplitChange. Leaving the three bp
        // values set made off-chain readers show a pending change that no longer exists; the time
        // sentinel alone is enough to block re-execution but is not what integrators read.
        pendingImmediateRate = 0;
        pendingLiquidityRate = 0;
        pendingVestingRate = 0;
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
     * @notice Set the GLOBAL default softcap (minimum-raise) bp. Read only at
     *         `createLaunchpad` time (see {launchpadSoftcapBp}) — never retroactive to an
     *         already-created sale.
     * @dev Floor-bounded by `MIN_RAISE_BP` (adjustable, but never below 20% — see that
     *      constant's doc comment); upper-bounded by `BASIS_POINTS` to preserve `_targetRaiseAmount`'s
     *      "soldOut always satisfies the softcap" proof for every settable value.
     *
     *      NO propose/execute timelock, unlike `launchpadFeeRate`/the fund split: those apply
     *      to funds ALREADY raised mid-sale, so a hot-key change there could move value out
     *      from under an in-flight sale. This value is snapshotted BEFORE a sale can accept any
     *      participation at all (`createLaunchpad` time), so a change here can never reach back
     *      into an already-created sale — same reasoning, same no-timelock pattern as
     *      `setDefaultVestingSchedule`.
     */
    function setSoftcapBp(uint256 _bp) external onlyOwner {
        if (_bp < MIN_RAISE_BP || _bp > BASIS_POINTS) revert InvalidSoftcapBp();
        uint256 oldBp = softcapBp;
        softcapBp = _bp;
        emit SoftcapBpUpdated(oldBp, _bp);
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
        // Guard the subtraction. If the ledger ever exceeds the real balance the bare
        // `balance - lockedAmount` panics 0x11, which turns a diagnosable insolvency into an opaque
        // arithmetic panic and makes the declared error unreachable in exactly the case an operator
        // would be investigating.
        if (balance < lockedAmount || _amount > balance - lockedAmount) revert TokenLockedInActiveLaunchpad();

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
     *      `Ownable2StepUpgradeable.transferOwnership` only nominates; ownership actually moves
     *      here, on `acceptOwnership` (and on `renounceOwnership`). Without this, an armed
     *      implementation — clock still running — survived the handover, so an incoming owner
     *      could execute a payload staged by their predecessor, possibly without knowing it
     *      existed. Clearing forces the new owner to re-stage under their own key, which restarts
     *      the 48h notice and re-publishes the target.
     *
     *      Emits the ordinary {UpgradeCancelled} event so the drop is observable by the same
     *      monitoring that watches explicit cancellations. No-ops when nothing is staged,
     *      including during `initialize`.
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
     * @dev `finalizeLaunchpad` is `onlyOwner` and has no permissionless alternative for a
     *      SUCCESSFUL sale, so an ownerless contract can only ever refund — every funded in-flight
     *      launchpad would be forced to `Cancelled` once `REFUND_GRACE` elapsed. With a single-key
     *      owner and no multisig, one call would strand every live sale irreversibly. Ownership
     *      moves only via the 2-step transfer, which always leaves a live owner.
     */
    function renounceOwnership() public view override onlyOwner {
        revert RenounceDisabled();
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
    /// @dev Returns a cancelled sale's unsold tokens to factory escrow for resale.
    function restoreEscrow(address token, uint256 amount) external returns (uint256 deadline);
}

/**
 * @title IFactoryIssuedToken
 * @notice Minimal interface to read a token's immutable issuance-time factory binding.
 * @dev ERC20V1 stores the deploying TokenFactory in its `launchpad` slot at init.
 */
interface IFactoryIssuedToken {
    function launchpad() external view returns (address);
}

/**
 * @title ITokenVestingWallet
 * @notice Minimal interface for the finalize-time Owner Vesting trigger.
 */
interface ITokenVestingWallet {
    function startVesting(uint64 startTimestamp, uint64 duration_) external;
    function duration() external view returns (uint64);
    /// @dev Guard: `_triggerOwnerVesting` checks this before calling `startVesting` — a
    ///      resold token's wallet may already have been started via `TokenFactory` while it sat
    ///      unconsumed in escrow between sales.
    function started() external view returns (bool);
}
