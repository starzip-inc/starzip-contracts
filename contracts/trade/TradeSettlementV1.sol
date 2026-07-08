// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title TradeSettlementV1
 * @notice Off-chain orderbook trade settlement contract (signature-based, NON-CUSTODIAL).
 * @dev UUPS upgradeable contract. Live proxy — storage layout is append-only.
 *
 *      Signature-based non-custodial transformation:
 *        - PRIMARY settlement is `settleOrders`: the operator submits two EIP-712-signed
 *          Orders (buy + sell); every balance debit is authorized by the debited account's
 *          own signature (EOA/ERC-1271 via SignatureChecker) or a registered session key.
 *          The operator can only match pre-signed intents — it can never mint an unsigned debit.
 *        - Users self-custody: withdrawUsdt / withdrawToken / batchWithdraw are restored as
 *          direct msg.sender-scoped exits and are NOT pause-gated (pause must not re-custody).
 *        - Legacy unsigned/weak operator debit paths are hard-disabled in code:
 *          settleTrade / batchSettleTrades / settleTradeWithSignatures / settleTradeSecure
 *          unconditionally revert LegacySettlementDisabled.
 *        - batchSettleNetDeltas (unsigned operator debit path) is OFF by default via
 *          netDeltaSettlementEnabled (default false); owner may re-enable if ever needed.
 *        - withdrawFor (operator-triggered exit) is removed (reverts WithdrawFunctionDisabled).
 *          emergencyWithdrawFor (owner backstop, seize-TO-USER only) is the sole residual
 *          owner-power debit path.
 *        - Upgrades are 48h timelocked (requestUpgrade / cancelUpgrade + _authorizeUpgrade).
 *
 * Closed-world debit invariant: every `balances[...] -=` / `= 0` is one of
 *   (a) msg.sender-scoped user withdrawal,
 *   (b) authorized by the debited account's EIP-712-signed Order (or its session key) in
 *       settleOrders,
 *   (c) emergencyWithdrawFor (owner backstop, funds always -> _user).
 */
contract TradeSettlementV1 is
    Initializable,
    UUPSUpgradeable,
    Ownable2StepUpgradeable,
    ReentrancyGuard,
    PausableUpgradeable,
    EIP712Upgradeable
{
    using SafeERC20 for IERC20;

    // ============ Constants ============
    uint256 public constant BASIS_POINTS = 10000;
    uint256 public constant MAX_FEE_RATE = 100; // Max 1%
    uint256 public constant SIGNATURE_VALIDITY_PERIOD = 1 hours;
    // Legacy: bounds batchSettleTrades/batchWithdraw. NetDelta path uses MAX_NET_DELTAS instead.
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant MAX_WITHDRAWAL_DELAY = 7 days;
    uint256 public constant MIN_TRADE_AMOUNT = 1e18; // Minimum trade amount (1 USDT with 18 decimals)
    uint256 public constant MAX_TRADE_TIMESTAMP_DIFF = 1 hours; // Maximum trade timestamp difference

    // Operator permission abuse prevention constants
    uint256 public constant MAX_SINGLE_TRADE_AMOUNT = 1000000 * 1e18; // 1M USDT per trade (18 decimals)
    uint256 public constant OPERATOR_CHANGE_DELAY = 24 hours; // Timelock for operator changes

    // Maximum NetDelta rows per batchSettleNetDeltas call.
    // Independent of MAX_BATCH_SIZE (50) which bounds the legacy batchSettleTrades(Trade[]) path.
    uint256 public constant MAX_NET_DELTAS = 200;

    // Timelock delay for UUPS upgrades. Only upgrades performed AFTER the
    // migration are timelocked; the migration upgrade itself installs under the prior authorizer.
    uint256 public constant UPGRADE_TIMELOCK_DELAY = 48 hours;

    // EIP-712 Type Hash for legacy Trade struct (retained for ABI compat; legacy paths disabled)
    bytes32 public constant TRADE_TYPEHASH =
        keccak256(
            "Trade(address maker,address taker,address token,uint256 tokenAmount,uint256 usdtAmount,uint256 makerFee,uint256 takerFee,uint256 timestamp,bytes32 tradeId)"
        );

    // EIP-712 Type Hash for a signed Order (primary settlement path)
    bytes32 public constant ORDER_TYPEHASH =
        keccak256(
            "Order(address account,address token,bool isBuy,uint256 tokenAmount,uint256 usdtAmount,uint256 maxFeeRate,uint256 nonce,uint256 expiry)"
        );

    // EIP-712 Type Hash for a relayed session-key authorization
    bytes32 public constant SESSION_KEY_TYPEHASH =
        keccak256("SessionKeyAuth(address account,address sessionKey,uint256 validUntil,uint256 nonce)");

    // ============ State Variables ============
    address public launchpad;
    IERC20 public usdt;
    address public feeRecipient;
    uint256 public tradeFeeRate; // Trade fee in basis points

    // Operators (trade settlement authority)
    mapping(address => bool) public operators;

    // User balances: user => token => balance
    mapping(address => mapping(address => uint256)) public balances;

    // Trade nonce (duplicate prevention): tradeId => executed
    mapping(bytes32 => bool) public executedTrades;

    // Supported tokens (only tokens issued from Launchpad)
    mapping(address => bool) public supportedTokens;

    // Withdrawal delay (security)
    uint256 public withdrawalDelay;
    mapping(address => uint256) public lastDepositTime;

    // Operator change timelock
    struct PendingOperatorChange {
        address operator;
        bool status;
        uint256 executeAfter;
    }
    mapping(bytes32 => PendingOperatorChange) public pendingOperatorChanges;

    // NetDelta-based settlement storage.
    mapping(bytes32 => bool) public processedSettlements; // settlementId => processed
    mapping(address => uint256) public feeAccrued; // token => cumulative fee credited (monotonic)
    mapping(address => uint256) public batchAmountCap; // token => per-call absolute-sum cap

    // Legacy operator-callable settlement gate (retained; the four
    // legacy entrypoints now revert unconditionally regardless of this stored value).
    bool public legacySettlementDisabled;

    // ============ Storage Layout (live-proxy, append-only) ============
    // WARNING: append-only storage — never reorder or remove existing slots.
    // The following state variables are appended AFTER legacySettlementDisabled and BEFORE __gap
    // (7 new FULL slots; netDeltaSettlementEnabled packs into the legacySettlementDisabled
    // slot and consumes 0 full slots).
    //
    // | Slot delta | Variable                                                                  |
    // |------------|---------------------------------------------------------------------------|
    // | +0 (packed)| bool netDeltaSettlementEnabled  (packs w/ legacySettlementDisabled slot)   |
    // | +1 full    | mapping(address=>mapping(address=>uint256)) sessionKeyValidUntil           |
    // | +1 full    | mapping(address=>uint256) sessionKeyRegNonce                               |
    // | +1 full    | mapping(bytes32=>uint256) orderFilled                                      |
    // | +1 full    | mapping(bytes32=>bool) orderCancelled                                      |
    // | +1 full    | address pendingImplementation                                             |
    // | +1 full    | uint256 upgradeReadyAt                                                     |
    // | +1 full    | uint256 netDeltaEnableReadyAt (net-delta enable timelock)                  |
    // total new full slots = 7. No reinitializer: every new default
    // (false / empty mapping / address(0) / 0) is the SAFE value. EIP-712 domain unchanged.

    // Net-delta unsigned operator debit path is DISABLED by default. Owner may
    // re-enable via setNetDeltaSettlementEnabled if the net-delta flow is ever needed again.
    bool public netDeltaSettlementEnabled;

    // Session keys. sessionKeyValidUntil[account][key] = unix ts until which `key` may sign
    // Orders on behalf of `account`. 0 = not authorized / revoked.
    mapping(address => mapping(address => uint256)) public sessionKeyValidUntil;
    // Per-account monotonic nonce for relayed session-key registration (registerSessionKeyWithSig).
    mapping(address => uint256) public sessionKeyRegNonce;
    // Cumulative filled token amount per order hash (partial-fill accounting for settleOrders).
    mapping(bytes32 => uint256) public orderFilled;
    // Order cancellation flags keyed by order hash.
    mapping(bytes32 => bool) public orderCancelled;
    // Timelocked-upgrade staging.
    address public pendingImplementation;
    uint256 public upgradeReadyAt;
    // net-delta enable timelock (appended after upgradeReadyAt).
    uint256 public netDeltaEnableReadyAt;

    // ============ Storage Gap ============
    uint256[37] private __gap; // was [38]; -1 (netDeltaEnableReadyAt) — append-only; see above

    // ============ Structs ============
    struct Trade {
        address maker; // Seller
        address taker; // Buyer
        address token; // Trade token
        uint256 tokenAmount; // Token quantity
        uint256 usdtAmount; // USDT amount
        uint256 makerFee; // Maker fee
        uint256 takerFee; // Taker fee
        uint256 timestamp; // Trade time
        bytes32 tradeId; // Unique trade ID
    }

    // NetDelta — calldata-only struct for batchSettleNetDeltas.
    struct NetDelta {
        address user;
        address token;
        int256 amount;
    }

    // Signed Order (primary settlement path). `isBuy` distinguishes the buy side (pays USDT,
    // receives token) from the sell side (delivers token, receives USDT). `nonce` differentiates
    // otherwise-identical orders so they hash distinctly; partial fills are tracked by order hash.
    struct Order {
        address account;
        address token;
        bool isBuy;
        uint256 tokenAmount;
        uint256 usdtAmount;
        uint256 maxFeeRate;
        uint256 nonce;
        uint256 expiry;
    }

    // Relayed session-key authorization payload.
    struct SessionKeyAuth {
        address account;
        address sessionKey;
        uint256 validUntil;
        uint256 nonce;
    }

    // ============ Events ============
    event Deposited(address indexed user, address indexed token, uint256 amount);
    event Withdrawn(address indexed user, address indexed token, uint256 amount);
    event TradeSettled(
        bytes32 indexed tradeId,
        address indexed maker,
        address indexed taker,
        address token,
        uint256 tokenAmount,
        uint256 usdtAmount,
        uint256 makerFee,
        uint256 takerFee
    );
    event OperatorUpdated(address indexed operator, bool status);
    event TokenSupported(address indexed token, bool status);
    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);
    event TradeFeeRateUpdated(uint256 oldRate, uint256 newRate);
    event WithdrawalDelayUpdated(uint256 oldDelay, uint256 newDelay);
    event EmergencyWithdraw(address indexed user, address indexed token, uint256 amount);
    event LaunchpadUpdated(address indexed oldLaunchpad, address indexed newLaunchpad);
    event UsdtUpdated(address indexed oldUsdt, address indexed newUsdt);

    // Operator timelock events
    event OperatorChangeQueued(bytes32 indexed changeId, address indexed operator, bool status, uint256 executeAfter);
    event OperatorChangeExecuted(bytes32 indexed changeId, address indexed operator, bool status);
    event OperatorChangeCancelled(bytes32 indexed changeId);

    // NetDelta settlement events
    event Settlement(bytes32 indexed settlementId, uint256 deltaCount, uint256 blockNumber);
    event BatchAmountCapUpdated(address indexed token, uint256 oldCap, uint256 newCap);

    // Legacy settlement gate event
    event LegacySettlementDisabledUpdated(bool oldValue, bool newValue);

    // Signature-based settlement events
    event OrdersSettled(
        bytes32 indexed settlementId,
        bytes32 indexed buyOrderHash,
        bytes32 indexed sellOrderHash,
        uint256 fillTokenAmount,
        uint256 fillUsdtAmount,
        uint256 totalFee
    );
    event OrderCancelled(address indexed account, bytes32 indexed orderHash);
    event SessionKeyRegistered(address indexed account, address indexed sessionKey, uint256 validUntil);
    event SessionKeyRevoked(address indexed account, address indexed sessionKey);
    event NetDeltaSettlementEnabledUpdated(bool enabled);
    event UpgradeRequested(address indexed newImplementation, uint256 readyAt);
    event UpgradeCancelled(address indexed cancelledImplementation);
    event NetDeltaEnableRequested(uint256 readyAt);

    // ============ Errors ============
    error ZeroAddress();
    error ZeroAmount();
    error InsufficientBalance();
    error InvalidTrade();
    error TradeAlreadyExecuted();
    error NotOperator();
    error UnsupportedToken();
    error WithdrawalTooEarly();
    error InvalidFeeRate();
    error InvalidSignature();
    error SignatureExpired();
    error ExcessiveFee();
    error BatchTooLarge();
    error ExcessiveWithdrawalDelay();
    error SelfTradingNotAllowed();
    error TradeAmountTooSmall();
    error InvalidTradeTimestamp();
    error InvalidTradeId();
    error FutureTimestamp();
    error TradeExpired();
    error InvalidSignatureLength();
    error InvalidImplementation();

    // Additional errors for operator abuse prevention
    error TradeAmountTooLarge();
    error OperatorChangeNotFound();
    error OperatorChangeTooEarly();
    error OperatorChangeAlreadyExists();

    // NetDelta settlement errors
    error SettlementAlreadyProcessed();
    error EmptyDeltas();
    error TooManyDeltas();
    /// @dev Reverts when batchAmountCap[token] == 0, whether explicitly disabled by owner or never configured.
    error BatchCapNotSet();
    error BatchCapExceeded();
    error InvalidDelta();
    error FeeRecipientNegativeDelta();

    // Legacy settlement gate error
    error LegacySettlementDisabled();

    // User self-withdrawal disabled (superseded — retained for ABI compat)
    error WithdrawalsOperatorGated();

    // Signature-based non-custodial errors
    error NetDeltaSettlementDisabled();
    error WithdrawFunctionDisabled();
    error OrderExpired();
    error OrderIsCancelled();
    error PriceNotCrossed();
    error OrderOverfill();
    error SessionKeyNotAuthorized();
    error InvalidRegistrationNonce();
    error NoPendingUpgrade();
    error UpgradeNotReady();
    error ImplementationMismatch();
    error SideMismatch();
    error TokenMismatch();

    // net-delta enable timelock
    error NetDeltaEnableNotReady();

    // ============ Modifiers ============
    modifier onlyOperator() {
        if (!operators[msg.sender]) revert NotOperator();
        _;
    }

    modifier validAddress(address _addr) {
        if (_addr == address(0)) revert ZeroAddress();
        _;
    }

    modifier validAmount(uint256 _amount) {
        if (_amount == 0) revert ZeroAmount();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ============ Initialization ============

    /**
     * @notice Initialize the trade settlement contract
     * @param _launchpad Launchpad contract address
     * @param _usdt USDT token address
     * @param _feeRecipient Fee recipient address
     */
    function initialize(
        address _launchpad,
        address _usdt,
        address _feeRecipient
    ) public initializer validAddress(_launchpad) validAddress(_usdt) validAddress(_feeRecipient) {
        __Ownable_init(msg.sender);
        __Pausable_init();
        __EIP712_init("StarZipTradeSettlement", "1"); // EIP-712 domain separator

        launchpad = _launchpad;
        usdt = IERC20(_usdt);
        feeRecipient = _feeRecipient;

        tradeFeeRate = 30; // 0.3%
        withdrawalDelay = 0; // No default delay

        // Owner is default operator
        operators[msg.sender] = true;
    }

    // ============ Deposit Functions ============

    /**
     * @notice Deposit USDT
     * @param _amount Amount to deposit
     */
    function depositUsdt(uint256 _amount) external nonReentrant whenNotPaused validAmount(_amount) {
        usdt.safeTransferFrom(msg.sender, address(this), _amount);
        balances[msg.sender][address(usdt)] += _amount;
        lastDepositTime[msg.sender] = block.timestamp;

        emit Deposited(msg.sender, address(usdt), _amount);
    }

    /**
     * @notice Deposit tokens
     * @param _token Token address
     * @param _amount Amount to deposit
     */
    function depositToken(
        address _token,
        uint256 _amount
    ) external nonReentrant whenNotPaused validAddress(_token) validAmount(_amount) {
        if (!supportedTokens[_token]) revert UnsupportedToken();

        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        balances[msg.sender][_token] += _amount;
        lastDepositTime[msg.sender] = block.timestamp;

        emit Deposited(msg.sender, _token, _amount);
    }

    // ============ Withdrawal Functions (direct self-custody) ============

    /**
     * @notice Withdraw USDT to msg.sender (direct, self-custodial).
     * @dev NOT `whenNotPaused` — users must always be able to exit; pausing must
     *      never re-custody funds. Honors the withdrawal delay. CEI: debit before transfer.
     * @param _amount Amount to withdraw.
     */
    function withdrawUsdt(uint256 _amount) external nonReentrant validAmount(_amount) {
        _checkWithdrawalDelay(msg.sender);
        if (balances[msg.sender][address(usdt)] < _amount) revert InsufficientBalance();
        balances[msg.sender][address(usdt)] -= _amount;
        usdt.safeTransfer(msg.sender, _amount);
        emit Withdrawn(msg.sender, address(usdt), _amount);
    }

    /**
     * @notice Withdraw an arbitrary token to msg.sender (direct, self-custodial).
     * @dev NOT gated on supportedTokens (a delisted token must still be exitable)
     *      and NOT `whenNotPaused`. Honors the withdrawal delay. CEI: debit before transfer.
     * @param _token Token to withdraw.
     * @param _amount Amount to withdraw.
     */
    function withdrawToken(
        address _token,
        uint256 _amount
    ) external nonReentrant validAddress(_token) validAmount(_amount) {
        _checkWithdrawalDelay(msg.sender);
        if (balances[msg.sender][_token] < _amount) revert InsufficientBalance();
        balances[msg.sender][_token] -= _amount;
        IERC20(_token).safeTransfer(msg.sender, _amount);
        emit Withdrawn(msg.sender, _token, _amount);
    }

    /**
     * @notice Withdraw the full msg.sender balance of each listed token in one call.
     * @dev msg.sender-scoped full-balance exits, CEI per token, bounded by
     *      MAX_BATCH_SIZE, NOT `whenNotPaused`. Zero-balance entries are skipped.
     * @param _tokens Tokens to fully withdraw.
     */
    function batchWithdraw(address[] calldata _tokens) external nonReentrant {
        if (_tokens.length > MAX_BATCH_SIZE) revert BatchTooLarge();
        _checkWithdrawalDelay(msg.sender);
        for (uint256 i = 0; i < _tokens.length; ) {
            address token = _tokens[i];
            uint256 bal = balances[msg.sender][token];
            if (bal > 0) {
                balances[msg.sender][token] = 0; // CEI: zero before transfer
                IERC20(token).safeTransfer(msg.sender, bal);
                emit Withdrawn(msg.sender, token, bal);
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice DISABLED: operator-triggered withdrawal removed.
     * @dev Non-custodial model: users exit via withdrawUsdt/withdrawToken/batchWithdraw;
     *      owner backstop remains emergencyWithdrawFor. Retained for ABI compat.
     */
    function withdrawFor(address /*_user*/, address /*_token*/, uint256 /*_amount*/) external pure {
        revert WithdrawFunctionDisabled();
    }

    // ============ Trade Settlement Functions ============

    /**
     * @notice DISABLED: unsigned/weak legacy operator debit path. Reverts unconditionally.
     * @dev Retained for ABI compat only. Use settleOrders.
     */
    function settleTrade(Trade calldata /*_trade*/) external pure {
        revert LegacySettlementDisabled();
    }

    /**
     * @notice DISABLED: unsigned/weak legacy operator debit path. Reverts unconditionally.
     * @dev Retained for ABI compat only. Use settleOrders.
     */
    function batchSettleTrades(Trade[] calldata /*_trades*/) external pure {
        revert LegacySettlementDisabled();
    }

    /**
     * @notice DISABLED: unsigned/weak legacy operator debit path. Reverts unconditionally.
     * @dev Retained for ABI compat only. Use settleOrders.
     */
    function settleTradeWithSignatures(
        Trade calldata /*_trade*/,
        bytes calldata /*_makerSignature*/,
        bytes calldata /*_takerSignature*/
    ) external pure {
        revert LegacySettlementDisabled();
    }

    /**
     * @notice DISABLED: unsigned/weak legacy operator debit path. Reverts unconditionally.
     * @dev Retained for ABI compat only. Use settleOrders.
     */
    function settleTradeSecure(
        Trade calldata /*_trade*/,
        bytes calldata /*_makerSignature*/,
        bytes calldata /*_takerSignature*/
    ) external pure {
        revert LegacySettlementDisabled();
    }

    /**
     * @notice PRIMARY settlement: match one signed buy Order against one signed sell Order.
     * @dev Every debit is authorized by the debited account's EIP-712 signature (EOA or ERC-1271
     *      via SignatureChecker) or a registered session key. Balance-only — makes NO external
     *      calls. Checks -> Effects. Token and USDT are conserved (nothing minted or lost).
     * @param buyOrder Buy-side signed order (pays USDT, receives token).
     * @param buySig Buyer's signature over buyOrder (or a session-key signature).
     * @param sellOrder Sell-side signed order (delivers token, receives USDT).
     * @param sellSig Seller's signature over sellOrder (or a session-key signature).
     * @param fillTokenAmount Token amount to move buyer<-seller this fill.
     * @param fillUsdtAmount USDT notional to move seller<-buyer this fill.
     * @param buyerFee USDT fee charged on the buyer (on top of fillUsdtAmount).
     * @param sellerFee USDT fee deducted from the seller's proceeds.
     * @param settlementId Unique id minted by trade-server; replay-protected.
     */
    function settleOrders(
        Order calldata buyOrder,
        bytes calldata buySig,
        Order calldata sellOrder,
        bytes calldata sellSig,
        uint256 fillTokenAmount,
        uint256 fillUsdtAmount,
        uint256 buyerFee,
        uint256 sellerFee,
        bytes32 settlementId
    ) external onlyOperator nonReentrant whenNotPaused {
        // 1. Replay protection
        if (processedSettlements[settlementId]) revert SettlementAlreadyProcessed();
        processedSettlements[settlementId] = true;

        // 2. Structural checks
        if (!buyOrder.isBuy || sellOrder.isBuy) revert SideMismatch();
        if (buyOrder.token != sellOrder.token) revert TokenMismatch();
        if (!supportedTokens[buyOrder.token]) revert UnsupportedToken();
        if (buyOrder.account == sellOrder.account) revert SelfTradingNotAllowed();

        // 3. Per-order expiry + cancellation
        bytes32 buyHash = _hashOrder(buyOrder);
        bytes32 sellHash = _hashOrder(sellOrder);
        if (block.timestamp > buyOrder.expiry) revert OrderExpired();
        if (block.timestamp > sellOrder.expiry) revert OrderExpired();
        if (orderCancelled[buyHash]) revert OrderIsCancelled();
        if (orderCancelled[sellHash]) revert OrderIsCancelled();

        // 4. Signature authorization (both sides)
        _authorizeOrderSig(buyOrder, buySig);
        _authorizeOrderSig(sellOrder, sellSig);

        // 5. Fill sanity
        if (fillTokenAmount == 0) revert ZeroAmount();
        if (fillUsdtAmount < MIN_TRADE_AMOUNT) revert TradeAmountTooSmall();
        if (fillUsdtAmount > MAX_SINGLE_TRADE_AMOUNT) revert TradeAmountTooLarge();

        // 6. Price crossing (full-precision products via mulDiv-by-1)
        // Buyer: effective price <= limit  => fillUsdt * buyTokenAmt <= buyUsdtAmt * fillToken
        if (
            Math.mulDiv(fillUsdtAmount, buyOrder.tokenAmount, 1) > Math.mulDiv(buyOrder.usdtAmount, fillTokenAmount, 1)
        ) {
            revert PriceNotCrossed();
        }
        // Seller: effective price >= limit => fillUsdt * sellTokenAmt >= sellUsdtAmt * fillToken
        if (
            Math.mulDiv(fillUsdtAmount, sellOrder.tokenAmount, 1) <
            Math.mulDiv(sellOrder.usdtAmount, fillTokenAmount, 1)
        ) {
            revert PriceNotCrossed();
        }

        // 7. Partial-fill accounting
        if (orderFilled[buyHash] + fillTokenAmount > buyOrder.tokenAmount) revert OrderOverfill();
        if (orderFilled[sellHash] + fillTokenAmount > sellOrder.tokenAmount) revert OrderOverfill();
        orderFilled[buyHash] += fillTokenAmount;
        orderFilled[sellHash] += fillTokenAmount;

        // 8. Fee ceilings on the FILL notional, capped by MAX_FEE_RATE and per-order maxFeeRate
        uint256 maxBuyFee = Math.mulDiv(fillUsdtAmount, Math.min(MAX_FEE_RATE, buyOrder.maxFeeRate), BASIS_POINTS);
        if (buyerFee > maxBuyFee) revert ExcessiveFee();
        uint256 maxSellFee = Math.mulDiv(fillUsdtAmount, Math.min(MAX_FEE_RATE, sellOrder.maxFeeRate), BASIS_POINTS);
        if (sellerFee > maxSellFee) revert ExcessiveFee();

        // 9. Balance settlement (no transfers). 0.8 underflow on insufficient balance => order fails.
        address token = buyOrder.token;
        address usdtAddr = address(usdt);
        uint256 totalFee = buyerFee + sellerFee;

        balances[sellOrder.account][token] -= fillTokenAmount;
        balances[sellOrder.account][usdtAddr] += (fillUsdtAmount - sellerFee);
        balances[buyOrder.account][usdtAddr] -= (fillUsdtAmount + buyerFee);
        balances[buyOrder.account][token] += fillTokenAmount;
        balances[feeRecipient][usdtAddr] += totalFee;
        feeAccrued[usdtAddr] += totalFee;

        // 10. Emit
        emit OrdersSettled(settlementId, buyHash, sellHash, fillTokenAmount, fillUsdtAmount, totalFee);
    }

    /**
     * @notice Cancel an order so it can never be settled (self-service, signer-authenticated).
     * @param order The order to cancel. Caller MUST be order.account.
     */
    function cancelOrder(Order calldata order) external {
        require(msg.sender == order.account, "not order account");
        bytes32 orderHash = _hashOrder(order);
        orderCancelled[orderHash] = true;
        emit OrderCancelled(order.account, orderHash);
    }

    /**
     * @notice Settle a batch of net-delta balance updates produced by the off-chain orderbook.
     * @dev Operator-only entrypoint. This is an UNSIGNED
     *      operator debit path, so it is DISABLED by default (netDeltaSettlementEnabled == false)
     *      and reverts NetDeltaSettlementDisabled until an owner explicitly re-enables it. All
     *      prior behavior (replay protection, per-token caps, fee accrual) is retained.
     * @param _settlementId Unique id minted by trade-server. Reverts on duplicate.
     * @param _deltas Array of (user, token, signed amount) rows. 1..MAX_NET_DELTAS.
     */
    function batchSettleNetDeltas(
        bytes32 _settlementId,
        NetDelta[] calldata _deltas
    ) external onlyOperator nonReentrant whenNotPaused {
        // safe-by-default — unsigned operator debit path is OFF unless owner enables.
        if (!netDeltaSettlementEnabled) revert NetDeltaSettlementDisabled();

        // ----- Checks -----
        if (_deltas.length == 0) revert EmptyDeltas();
        if (_deltas.length > MAX_NET_DELTAS) revert TooManyDeltas();
        if (processedSettlements[_settlementId]) revert SettlementAlreadyProcessed();

        // ----- Effects (pre-loop): mark settlementId consumed before any mutation. -----
        processedSettlements[_settlementId] = true;

        // ----- Pass 1: validate each delta + aggregate per-token absolute-sum for cap check -----
        address[] memory seenTokens = new address[](_deltas.length);
        uint256[] memory tokenAbsSum = new uint256[](_deltas.length);
        uint256 seenCount = 0;

        address feeRecipientCached = feeRecipient; // single SLOAD reused across the loop

        for (uint256 i = 0; i < _deltas.length; ) {
            NetDelta calldata d = _deltas[i];

            if (d.user == address(0)) revert InvalidDelta();
            if (d.amount == 0) revert InvalidDelta();
            if (d.amount == type(int256).min) revert InvalidDelta();

            if (!supportedTokens[d.token]) revert UnsupportedToken();

            if (d.user == feeRecipientCached && d.amount < 0) revert FeeRecipientNegativeDelta();

            uint256 absAmt = _abs(d.amount);
            bool found = false;
            for (uint256 j = 0; j < seenCount; ) {
                if (seenTokens[j] == d.token) {
                    tokenAbsSum[j] += absAmt;
                    found = true;
                    break;
                }
                unchecked {
                    ++j;
                }
            }
            if (!found) {
                seenTokens[seenCount] = d.token;
                tokenAbsSum[seenCount] = absAmt;
                unchecked {
                    ++seenCount;
                }
            }

            unchecked {
                ++i;
            }
        }

        // ----- Per-token cap enforcement -----
        for (uint256 k = 0; k < seenCount; ) {
            uint256 cap = batchAmountCap[seenTokens[k]];
            if (cap == 0) revert BatchCapNotSet();
            if (tokenAbsSum[k] > cap) revert BatchCapExceeded();
            unchecked {
                ++k;
            }
        }

        // ----- Pass 2: apply deltas to balances + feeAccrued -----
        for (uint256 i = 0; i < _deltas.length; ) {
            NetDelta calldata d = _deltas[i];
            if (d.amount > 0) {
                uint256 amt = uint256(d.amount);
                balances[d.user][d.token] += amt;
                if (d.user == feeRecipientCached) {
                    feeAccrued[d.token] += amt;
                }
            } else {
                uint256 amt = _abs(d.amount);
                balances[d.user][d.token] -= amt; // 0.8 underflow auto-reverts on insufficient balance
            }
            unchecked {
                ++i;
            }
        }

        // ----- Interactions: NONE (balance-only; no ERC20 transfers) -----

        emit Settlement(_settlementId, _deltas.length, block.number);
    }

    // ============ Session Keys ============

    /**
     * @notice Register a session key for msg.sender (self-service).
     * @param sessionKey Address whose ECDSA signatures may authorize orders for msg.sender.
     * @param validUntil Unix timestamp (must be in the future) until which the key is valid.
     */
    function registerSessionKey(address sessionKey, uint256 validUntil) external {
        if (sessionKey == address(0)) revert ZeroAddress();
        if (validUntil <= block.timestamp) revert SessionKeyNotAuthorized();
        sessionKeyValidUntil[msg.sender][sessionKey] = validUntil;
        emit SessionKeyRegistered(msg.sender, sessionKey, validUntil);
    }

    /**
     * @notice Register a session key on behalf of `a.account` via that account's EIP-712 signature.
     * @dev Relayer-friendly. Replay-protected by a per-account monotonic registration nonce.
     * @param a Session-key authorization payload.
     * @param sig `a.account`'s signature over the SessionKeyAuth digest (EOA or ERC-1271).
     */
    function registerSessionKeyWithSig(SessionKeyAuth calldata a, bytes calldata sig) external {
        if (a.sessionKey == address(0)) revert ZeroAddress();
        if (a.validUntil <= block.timestamp) revert SessionKeyNotAuthorized();
        if (a.nonce != sessionKeyRegNonce[a.account]) revert InvalidRegistrationNonce();
        if (!SignatureChecker.isValidSignatureNow(a.account, _hashSessionKeyAuth(a), sig)) revert InvalidSignature();

        sessionKeyRegNonce[a.account]++;
        sessionKeyValidUntil[a.account][a.sessionKey] = a.validUntil;
        emit SessionKeyRegistered(a.account, a.sessionKey, a.validUntil);
    }

    /**
     * @notice Revoke a session key for msg.sender. NEVER pausable — always available.
     * @param sessionKey Key to revoke.
     */
    function revokeSessionKey(address sessionKey) external {
        sessionKeyValidUntil[msg.sender][sessionKey] = 0;
        emit SessionKeyRevoked(msg.sender, sessionKey);
    }

    // ============ Internal Functions ============

    /**
     * @dev Authorize an order's signature. Path A: SignatureChecker (EOA ecrecover OR ERC-1271).
     *      Path B: a registered, unexpired session key (malleability-safe via ECDSA.tryRecover).
     *      Reverts InvalidSignature if neither path validates.
     */
    function _authorizeOrderSig(Order calldata order, bytes calldata sig) internal view {
        bytes32 orderHash = _hashOrder(order);

        // Path A: EOA (ecrecover) OR ERC-1271 contract wallet.
        if (SignatureChecker.isValidSignatureNow(order.account, orderHash, sig)) return;

        // Path B: registered session key. tryRecover rejects high-s malleability + bad length.
        (address rec, ECDSA.RecoverError err, ) = ECDSA.tryRecover(orderHash, sig);
        if (err == ECDSA.RecoverError.NoError && rec != address(0)) {
            uint256 vu = sessionKeyValidUntil[order.account][rec];
            if (vu != 0 && block.timestamp <= vu) return;
        }

        revert InvalidSignature();
    }

    /**
     * @dev EIP-712 typed-data hash for an Order.
     */
    function _hashOrder(Order calldata order) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        ORDER_TYPEHASH,
                        order.account,
                        order.token,
                        order.isBuy,
                        order.tokenAmount,
                        order.usdtAmount,
                        order.maxFeeRate,
                        order.nonce,
                        order.expiry
                    )
                )
            );
    }

    /**
     * @dev EIP-712 typed-data hash for a SessionKeyAuth payload.
     */
    function _hashSessionKeyAuth(SessionKeyAuth calldata a) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(abi.encode(SESSION_KEY_TYPEHASH, a.account, a.sessionKey, a.validUntil, a.nonce))
            );
    }

    function _checkWithdrawalDelay(address _user) internal view {
        if (withdrawalDelay > 0) {
            if (block.timestamp < lastDepositTime[_user] + withdrawalDelay) {
                revert WithdrawalTooEarly();
            }
        }
    }

    /**
     * @dev Absolute value of a signed int256 as uint256. CALLER must ensure x != type(int256).min.
     */
    function _abs(int256 x) private pure returns (uint256) {
        return x >= 0 ? uint256(x) : uint256(-x);
    }

    // ============ View Functions ============

    /**
     * @notice Get user balance for a token
     */
    function getBalance(address _user, address _token) external view returns (uint256) {
        return balances[_user][_token];
    }

    /**
     * @notice Check if trade has been executed (legacy Trade path)
     */
    function isTradeExecuted(bytes32 _tradeId) external view returns (bool) {
        return executedTrades[_tradeId];
    }

    /**
     * @notice Calculate fee for an amount
     */
    function calculateFee(uint256 _amount) external view returns (uint256) {
        return (_amount * tradeFeeRate) / BASIS_POINTS;
    }

    /**
     * @notice Contract version
     * @return Version number
     */
    function version() external pure returns (uint256) {
        return 1;
    }

    /**
     * @notice Check if a legacy Trade is valid before submission (view helper, legacy struct).
     */
    function validateTrade(Trade calldata _trade) external view returns (bool isValid, string memory reason) {
        if (_trade.maker == address(0) || _trade.taker == address(0)) {
            return (false, "Invalid maker or taker address");
        }
        if (_trade.maker == _trade.taker) {
            return (false, "Self-trading not allowed");
        }
        if (_trade.token == address(0)) {
            return (false, "Invalid token address");
        }
        if (_trade.tokenAmount == 0 || _trade.usdtAmount == 0) {
            return (false, "Zero amount not allowed");
        }
        if (_trade.usdtAmount < MIN_TRADE_AMOUNT) {
            return (false, "Trade amount too small");
        }
        if (_trade.tradeId == bytes32(0)) {
            return (false, "Invalid trade ID");
        }
        if (_trade.timestamp > block.timestamp + 5 minutes) {
            return (false, "Future timestamp");
        }
        if (block.timestamp > _trade.timestamp + MAX_TRADE_TIMESTAMP_DIFF) {
            return (false, "Trade expired");
        }
        if (!supportedTokens[_trade.token]) {
            return (false, "Unsupported token");
        }
        if (executedTrades[_trade.tradeId]) {
            return (false, "Trade already executed");
        }

        uint256 maxAllowedFee = (_trade.usdtAmount * MAX_FEE_RATE) / BASIS_POINTS;
        if (_trade.makerFee > maxAllowedFee) {
            return (false, "Maker fee too high");
        }
        if (_trade.takerFee > maxAllowedFee) {
            return (false, "Taker fee too high");
        }

        uint256 takerTotalPayment = _trade.usdtAmount + _trade.takerFee;
        if (balances[_trade.maker][_trade.token] < _trade.tokenAmount) {
            return (false, "Insufficient maker token balance");
        }
        if (balances[_trade.taker][address(usdt)] < takerTotalPayment) {
            return (false, "Insufficient taker USDT balance");
        }

        return (true, "");
    }

    // ============ Admin Functions ============

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    // immediate setOperator REMOVED. Operators change only via
    // queueOperatorChange -> (OPERATOR_CHANGE_DELAY) -> executeOperatorChange.

    /**
     * @notice Queue an operator status change with timelock
     */
    function queueOperatorChange(
        address _operator,
        bool _status
    ) external onlyOwner validAddress(_operator) returns (bytes32) {
        bytes32 changeId = keccak256(abi.encode(_operator, _status, block.timestamp));

        if (pendingOperatorChanges[changeId].executeAfter != 0) {
            revert OperatorChangeAlreadyExists();
        }

        uint256 executeAfter = block.timestamp + OPERATOR_CHANGE_DELAY;

        pendingOperatorChanges[changeId] = PendingOperatorChange({
            operator: _operator,
            status: _status,
            executeAfter: executeAfter
        });

        emit OperatorChangeQueued(changeId, _operator, _status, executeAfter);
        return changeId;
    }

    /**
     * @notice Execute a queued operator change after timelock expires
     */
    function executeOperatorChange(bytes32 _changeId) external onlyOwner {
        PendingOperatorChange storage change = pendingOperatorChanges[_changeId];

        if (change.executeAfter == 0) revert OperatorChangeNotFound();
        if (block.timestamp < change.executeAfter) revert OperatorChangeTooEarly();

        address operator = change.operator;
        bool status = change.status;

        delete pendingOperatorChanges[_changeId];

        operators[operator] = status;

        emit OperatorChangeExecuted(_changeId, operator, status);
        emit OperatorUpdated(operator, status);
    }

    /**
     * @notice Cancel a pending operator change
     */
    function cancelOperatorChange(bytes32 _changeId) external onlyOwner {
        if (pendingOperatorChanges[_changeId].executeAfter == 0) {
            revert OperatorChangeNotFound();
        }

        delete pendingOperatorChanges[_changeId];
        emit OperatorChangeCancelled(_changeId);
    }

    /**
     * @notice Set supported token status
     */
    function setSupportedToken(address _token, bool _status) external onlyOwner validAddress(_token) {
        supportedTokens[_token] = _status;
        emit TokenSupported(_token, _status);
    }

    /**
     * @notice Set fee recipient
     */
    function setFeeRecipient(address _feeRecipient) external onlyOwner validAddress(_feeRecipient) {
        address oldRecipient = feeRecipient;
        feeRecipient = _feeRecipient;
        emit FeeRecipientUpdated(oldRecipient, _feeRecipient);
    }

    /**
     * @notice Set trade fee rate
     */
    function setTradeFeeRate(uint256 _newRate) external onlyOwner {
        if (_newRate > MAX_FEE_RATE) revert InvalidFeeRate();
        uint256 oldRate = tradeFeeRate;
        tradeFeeRate = _newRate;
        emit TradeFeeRateUpdated(oldRate, _newRate);
    }

    /**
     * @notice Set withdrawal delay
     */
    function setWithdrawalDelay(uint256 _delay) external onlyOwner {
        if (_delay > MAX_WITHDRAWAL_DELAY) revert ExcessiveWithdrawalDelay();
        uint256 oldDelay = withdrawalDelay;
        withdrawalDelay = _delay;
        emit WithdrawalDelayUpdated(oldDelay, _delay);
    }

    /**
     * @notice Set launchpad address
     */
    function setLaunchpad(address _launchpad) external onlyOwner validAddress(_launchpad) {
        address oldLaunchpad = launchpad;
        launchpad = _launchpad;
        emit LaunchpadUpdated(oldLaunchpad, _launchpad);
    }

    /**
     * @notice Set USDT address
     */
    function setUsdt(address _usdt) external onlyOwner validAddress(_usdt) {
        address oldUsdt = address(usdt);
        usdt = IERC20(_usdt);
        emit UsdtUpdated(oldUsdt, _usdt);
    }

    /**
     * @notice Set per-token absolute-sum cap for batchSettleNetDeltas
     */
    function setBatchAmountCap(address _token, uint256 _cap) external onlyOwner validAddress(_token) {
        uint256 oldCap = batchAmountCap[_token];
        batchAmountCap[_token] = _cap;
        emit BatchAmountCapUpdated(_token, oldCap, _cap);
    }

    /**
     * @notice Enable or disable the four legacy operator-callable settlement entrypoints (retained).
     * @dev The four legacy entrypoints revert unconditionally regardless of this flag; the
     *      setter is retained for storage/ABI continuity.
     */
    function setLegacySettlementDisabled(bool _disabled) external onlyOwner {
        bool oldValue = legacySettlementDisabled;
        legacySettlementDisabled = _disabled;
        emit LegacySettlementDisabledUpdated(oldValue, _disabled);
    }

    /// @notice Stage enabling the unsigned net-delta operator settlement path (48h timelock).
    function requestEnableNetDelta() external onlyOwner {
        netDeltaEnableReadyAt = block.timestamp + UPGRADE_TIMELOCK_DELAY;
        emit NetDeltaEnableRequested(netDeltaEnableReadyAt);
    }

    /**
     * @notice Enable/disable the unsigned net-delta operator settlement path.
     * @dev Enabling requires a matured requestEnableNetDelta(); disabling is immediate and clears
     *      any pending request. Default remains OFF.
     * @param _enabled New value for the net-delta settlement gate.
     */
    function setNetDeltaSettlementEnabled(bool _enabled) external onlyOwner {
        if (_enabled) {
            if (netDeltaEnableReadyAt == 0 || block.timestamp < netDeltaEnableReadyAt) {
                revert NetDeltaEnableNotReady();
            }
            netDeltaEnableReadyAt = 0; // consume
        } else {
            netDeltaEnableReadyAt = 0; // disabling clears any pending enable
        }
        netDeltaSettlementEnabled = _enabled;
        emit NetDeltaSettlementEnabledUpdated(_enabled);
    }

    /**
     * @notice Emergency withdrawal for a user (Owner only).
     * @dev DOCUMENTED RESIDUAL OWNER POWER: this is the sole remaining owner-triggered debit path.
     *      It is a force-exit-TO-USER — funds ALWAYS go to `_user` (the debited account), never to
     *      the owner or any third party, so it cannot be used to steal. It is NOT timelock-bounded
     *      (immediate) by design, as the user backstop. It is the only debit site in this contract
     *      that is neither msg.sender-scoped nor authorized by the debited account's Order signature.
     * @param _user User address (debited AND the transfer recipient).
     * @param _token Token address.
     */
    function emergencyWithdrawFor(
        address _user,
        address _token
    ) external onlyOwner validAddress(_user) validAddress(_token) {
        uint256 amount = balances[_user][_token];
        if (amount == 0) revert ZeroAmount();

        balances[_user][_token] = 0;
        IERC20(_token).safeTransfer(_user, amount);

        emit EmergencyWithdraw(_user, _token, amount);
    }

    /**
     * @notice Recover stuck tokens that are not USDT or supported tokens (emergency only)
     */
    function recoverStuckTokens(
        address _token,
        address _to,
        uint256 _amount
    ) external onlyOwner validAddress(_token) validAddress(_to) validAmount(_amount) {
        if (_token == address(usdt)) revert UnsupportedToken();
        if (supportedTokens[_token]) revert UnsupportedToken();
        IERC20(_token).safeTransfer(_to, _amount);
    }

    // ============ Timelocked Upgrade ============

    /**
     * @notice Stage a UUPS upgrade to `newImpl`; it becomes executable after UPGRADE_TIMELOCK_DELAY.
     * @param newImpl New implementation address (must be a deployed contract).
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
     * @dev Timelocked upgrade authorizer. The staged implementation must match and the
     *      timelock must have elapsed; the staging is single-use (cleared here).
     *      NOTE: the migration upgrade itself installs under the PRIOR (non-timelocked)
     *      authorizer — expected. Only subsequent upgrades pass through this gate.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        if (pendingImplementation == address(0)) revert NoPendingUpgrade();
        if (newImplementation != pendingImplementation) revert ImplementationMismatch();
        if (block.timestamp < upgradeReadyAt) revert UpgradeNotReady();
        pendingImplementation = address(0);
        upgradeReadyAt = 0;
    }
}
