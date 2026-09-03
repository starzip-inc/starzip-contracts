// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
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
 *        - Users self-custody: withdrawToken / batchWithdraw are direct msg.sender-scoped exits
 *          and are NOT pause-gated (pause must not re-custody). They are also not gated on
 *          supportedTokens / quoteAssets, so a delisted asset always stays exitable. There is an
 *          OPTIONAL per-asset withdrawal RATE limit (off by default) — a speed limit, never a
 *          confiscation: the allowance refills on a pure clock schedule with no transaction and no
 *          owner cooperation, every enabled limit is floored by a constant so the owner cannot
 *          throttle it toward zero, and emergencyWithdrawFor ignores it entirely. See
 *          _consumeWithdrawalAllowance for the full argument and for what the control honestly
 *          does NOT cover (splitting across accounts).
 *        - Settlement is MULTI-QUOTE: the quote (payment) asset is carried per-Order and must be
 *          registered in the `quoteAssets` registry, whose per-asset decimals/min/max replace the
 *          former 18-decimal-hardcoded MIN_TRADE_AMOUNT / MAX_SINGLE_TRADE_AMOUNT constants.
 *          There is NO single `usdt` pointer (its repoint/desync bug class is gone by construction).
 *        - Legacy unsigned/weak operator debit paths (settleTrade / batchSettleTrades /
 *          settleTradeWithSignatures / settleTradeSecure / batchSettleNetDeltas) and the
 *          operator-triggered withdrawFor are REMOVED entirely (dead-code removal; not present in
 *          this ABI). There is NO operator entrypoint that debits an account without that
 *          account's own signature — not disabled-by-default, not timelocked-behind-a-flag:
 *          absent. emergencyWithdrawFor (owner backstop, seize-TO-USER only) is the sole residual
 *          owner-power debit path.
 *        - Upgrades are 48h timelocked (requestUpgrade / cancelUpgrade + _authorizeUpgrade), and
 *          so is recoverStuckTokens (requestRecover -> 48h -> recoverStuckTokens). Both stagings
 *          EXPIRE a further 7 days after maturity and are dropped when ownership changes
 *          hands, so a staging cannot be pre-armed and fired at an arbitrary later moment,
 *          nor inherited by an incoming owner.
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
    ReentrancyGuardTransient,
    PausableUpgradeable,
    EIP712Upgradeable
{
    using SafeERC20 for IERC20;

    // ============ Constants ============
    uint256 public constant BASIS_POINTS = 10000;
    /// @dev Per-SIDE ceiling: 1% of the fill notional for the buyer AND 1% for the seller, so a
    ///      single fill can move up to 2% of notional to `feeRecipient`. Do not quote this as
    ///      "max 1% per trade".
    uint256 public constant MAX_FEE_RATE = 100;
    uint256 public constant SIGNATURE_VALIDITY_PERIOD = 1 hours;
    // Bounds batchWithdraw.
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant MAX_WITHDRAWAL_DELAY = 7 days;

    // SSA-17: 500,000 -> 700,000. Derivation: 373,402 gas (measured, one genuine two-leg fill) +
    // 2 x ERC1271_GAS_STIPEND (worst case spends it twice per item) + ~10% margin.
    uint256 public constant ITEM_GAS_BUDGET = 700_000;

    // SSA-17 / F6: gas stipend for the ERC-1271 `isValidSignature` staticcall in
    // `_authorizeOrderSig`, replacing SignatureChecker's unbounded forward. Measured directly
    // (test/TradeSettlementV1_f6_erc1271GasStipend.test.ts, not `validateUserOp` on a different
    // path): StarzipWallet.isValidSignature worst case (passkey/WebAuthn owner) = 45,406 gas, EOA
    // owner = 36,682 gas. 120,000 is ~2.64x the measured worst case (~164% margin).
    uint256 private constant ERC1271_GAS_STIPEND = 120_000;

    // Length of one withdrawal-rate-limit accounting window. A CONSTANT, never an owner
    // parameter: throughput is limit/window, so a settable window is a second, unsealed knob for
    // strangling withdrawals (lengthening it to 365 days would divide every configured limit's
    // effective rate by 365 without touching the limit itself, defeating the floor below).
    uint256 public constant WITHDRAWAL_WINDOW = 1 days;

    // Length of one session-key spend window. A CONSTANT for the same reason WITHDRAWAL_WINDOW is,
    // with the sign flipped: throughput is cap/window, so a settable window would let whoever sets
    // it multiply a key's effective spend rate without the ACCOUNT ever re-signing a higher cap.
    // Deliberately NOT a per-key field either — by product decision the user-settable knobs are
    // the per-window cap and the per-order cap; the period is not one of them, and adding it to
    // SessionKeyAuth would put a rate multiplier in the payload a relayer submits.
    uint256 public constant SESSION_KEY_WINDOW = 1 days;

    // Sealed FLOOR on any enabled per-asset withdrawal limit, in WHOLE QUOTE UNITS
    // (decimals-agnostic; the absolute floor for asset `q` is MIN_WITHDRAWAL_LIMIT_UNITS *
    // 10**decimals(q)). This is the mirror image of MAX_TRADE_UNITS: that constant seals how far the
    // owner may RAISE a per-fill ceiling, this one seals how far the owner may LOWER a withdrawal
    // rate. Without it `setDailyWithdrawalLimit(token, 1)` would be an unannounced, untimelocked
    // freeze of every holder of that asset — i.e. a re-custody switch, which is exactly what this
    // contract's non-custodial promise forbids.
    //
    // VALUE DERIVATION: MAX_TRADE_UNITS / 100. The per-fill notional ceiling (1,000,000 whole quote
    // units) is the largest position this contract will let a single settlement create, so pinning
    // the daily exit floor at 1% of it bounds the worst-case full exit of a maximally-sized position
    // at 100 windows (100 days) and any ordinary retail position (<= 10,000 units, ~$10k for a
    // stablecoin) at a SINGLE window. Lower would let the owner make large balances practically
    // immovable; higher would make the control useless for the small-account case it is meant to
    // protect.
    uint256 public constant MIN_WITHDRAWAL_LIMIT_UNITS = 10_000;

    // Per-trade notional ceiling, expressed in WHOLE QUOTE UNITS (decimals-agnostic). The absolute
    // ceiling for a quote asset `q` is MAX_TRADE_UNITS * 10**decimals(q). This is a CONSTANT on
    // purpose: setQuoteLimits lets the owner tighten a quote asset's min/max but can never raise
    // the max past this ceiling, so the per-fill notional bound cannot be unlocked by any owner
    // action.
    //
    // SCOPE — do not overstate this: the bound is PER FILL. There is no aggregate or rate limit,
    // so N consecutive settlements of 1,000,000 each are accepted (verified by probe).
    // It is not a cap on what a compromised operator can move in total; what actually bounds that
    // is that every debit must be signed by the debited account (settleOrders) and, for session
    // keys, metered against sessionKeySpendCap.
    uint256 public constant MAX_TRADE_UNITS = 1_000_000;

    // Operator permission abuse prevention constants
    uint256 public constant OPERATOR_CHANGE_DELAY = 24 hours; // Timelock for operator changes

    // Timelock delay for UUPS upgrades. Only upgrades performed AFTER the
    // migration are timelocked; the migration upgrade itself installs under the prior authorizer.
    uint256 public constant UPGRADE_TIMELOCK_DELAY = 48 hours;

    // How long a MATURED upgrade staging stays executable. Without an expiry the staging
    // stayed armed forever, so the owner could stage quietly, let the 48h pass unobserved and fire
    // months later in one transaction — the timelock then only guaranteed "one 48h announcement,
    // ever", not "48h of live notice before every upgrade". 7 days is the shortest window that
    // never forces a re-stage for calendar reasons (maturity + a weekend + the following business
    // week for a multisig release process); anything longer only extends how long a hostile
    // payload sits armed. Armed lifetime is therefore bounded at 48h + 7d = 9 days, after which
    // execution needs a fresh requestUpgrade and hence a fresh public UpgradeRequested.
    uint256 public constant UPGRADE_GRACE_PERIOD = 7 days;

    // Timelock delay for recoverStuckTokens. Deliberately equal to UPGRADE_TIMELOCK_DELAY but
    // declared separately — the two powers are unrelated and must be tunable independently without
    // one silently repricing the other.
    uint256 public constant RECOVER_TIMELOCK_DELAY = 48 hours;

    // Execution window for a matured recovery staging. Separate constant from
    // UPGRADE_GRACE_PERIOD for the same independence reason as the delays above, and the sharper
    // hazard here is what actually sets the value: the excess is recomputed at EXECUTION, so a
    // staging made while excess was 0 used to remain a standing claim on any excess that appeared
    // later (a rebase or a reward distribution) — recoverable in the very block it appeared, with
    // no notice at the moment the funds existed. Bounding the claim at 7 days past maturity keeps
    // the staged sweep tied to the balance state it was announced against, while still leaving an
    // ops-realistic window to execute a legitimate one.
    uint256 public constant RECOVER_GRACE_PERIOD = 7 days;

    // NOTE: there is deliberately NO ceiling on session-key lifetime. A `MAX_SESSION_KEY_TTL`
    // of 7 days was removed by product decision — an account may set `validUntil` as far out as it
    // likes, including `type(uint256).max` for a key that never expires.
    //
    // WHY IT WAS THERE, AND WHY IT IS NOT ANY MORE. Its premise was that one leaked session key
    // drains the account's whole settlement balance. It does not: `settleOrders` is `onlyOperator`
    // (see its modifier), so a stolen key cannot submit its own fills — it can only place orders
    // that this platform's matching engine then crosses at book prices. The 7-day figure was never
    // derived from anything; a bound was recommended, the specific number was not.
    //
    // WHAT A SESSION KEY CANNOT DO, and it is the same thing dYdX and Hyperliquid rely on for their
    // long-lived agent/API wallets: it CANNOT WITHDRAW. `withdrawUsdt`, `withdrawToken` and
    // `batchWithdraw` are all `msg.sender`-scoped and `emergencyWithdrawFor` is `onlyOwner` with a
    // locked destination, so the key can trade the account's balance but never move it off this
    // contract. `revokeSessionKey` is also never pausable — an account can always kill a key.
    //
    // 🔴 WHAT IT CAN STILL DO, and this is NOT bounded by the operator being honest. A stolen key
    // signs an order AND the limit price on it. So: sign "sell 1000 BASE for 1 USDT total" as the
    // victim, post the opposite side from another address you control, and let the two cross. The
    // engine is doing its ordinary job; the operator submits honestly; every on-chain check passes,
    // because each order is inside *its own* signed limit, `buyer != seller` holds (two distinct
    // addresses), and the fill is within min/max trade amount. This contract has no notion of a fair
    // price — it compares a signed limit against itself.
    //
    // So the ONLY on-chain bound on a leaked key is `sessionKeySpendCap` (per token, cumulative,
    // never reset — a cap of 0 makes the key unusable, which is the correct fail-closed default).
    // Everything else that stops this lives off chain: a price band at matching time, self-trade
    // prevention across distinct addresses, and detection. A "merely buggy" matching engine is
    // enough here — it does not have to be malicious.
    //
    // RESIDUAL RISK, recorded so it is not rediscovered as a surprise: with no expiry, a key that
    // leaks and is never noticed stays live until it is revoked or its cap is exhausted. The expiry
    // used to be the dead-man's switch for exactly that, and nothing replaced it on chain.
    //
    // 🔴 AND THE KEY IS NOT HELD BY THE USER. The session
    // key that signs orders lives on the PLATFORM's servers, not on the user's device — that is how
    // "register once, never see a wallet popup again" is achieved. Two consequences the per-account
    // framing above would otherwise hide:
    //
    //   1. "session key leak" means "platform server compromise", so it is not one careless user —
    //      EVERY user with a registered key is exposed in the same instant. Aggregate exposure is
    //      `cap x number of users`, and `cap` is chosen by the platform, not by the account.
    //   2. between registration and revocation the platform holds standing unilateral authority to
    //      trade any registered user's balance, now with no expiry. It still cannot WITHDRAW those
    //      funds. Whether "non-custodial" remains an accurate description of that arrangement is a
    //      product/compliance question, not a Solidity one, and it is flagged here because removing
    //      the TTL is what made the authority permanent.
    //
    // So size the cap as "what the platform accepts losing PER USER if its own key store is
    // breached", multiply by the user count before signing that off, and never set it to
    // type(uint256).max.
    //
    // Separately: a compromised OPERATOR is an additional exposure — it picks which two orders are
    // crossed. Every privileged role here, operator included, is currently the same single
    // EOA, so moving that key to a multisig is worth doing. It is not what makes the above
    // exploitable, though, and no session-key TTL ever addressed either problem.

    // EIP-712 Type Hash for a signed Order (primary settlement path)
    bytes32 public constant ORDER_TYPEHASH =
        keccak256(
            "Order(address account,address baseToken,address quoteToken,bool isBuy,uint256 baseAmount,uint256 quoteAmount,uint256 maxFeeRate,uint256 nonce,uint256 expiry)"
        );

    // EIP-712 Type Hash for a relayed session-key authorization.
    // `deadline` bounds how long the SIGNATURE may sit unsubmitted — distinct from
    // `validUntil`, which bounds how long the KEY is usable once registered. `tokens`/`caps` carry
    // the per-asset spend caps so a relayed registration is never cap-less (the caps are
    // fail-closed, so an auth with empty arrays registers a key that can spend nothing).
    // `orderCaps` is parallel to both and carries the per-ORDER ceiling for the same asset; it is a
    // signed field rather than an owner setting because it is the account's own answer to "how big a
    // single order may this key sign", which is a different question from "how much per day".
    bytes32 public constant SESSION_KEY_TYPEHASH =
        keccak256(
            "SessionKeyAuth(address account,address sessionKey,uint256 validUntil,uint256 deadline,address[] tokens,uint256[] caps,uint256[] orderCaps,uint256 nonce)"
        );

    // ============ State Variables ============

    // slot 0
    address public feeRecipient;

    // slot 1 — narrow auto-listing role (typically TokenFactory). Authorized for
    // setSupportedToken and NOTHING else — deliberately not the owner, so the factory never
    // acquires emergencyWithdrawFor / recoverStuckTokens / upgrade authority.
    address public lister;

    // slot 2/3 — Timelocked-upgrade staging.
    address public pendingImplementation;
    uint256 public upgradeReadyAt;

    // slot 4 — Withdrawal delay.
    //
    // NOT a security control, and must not be counted as one. It gates on lastDepositTime[user]
    // [token], which settleOrders never writes, so any locked position is freed by trading it for
    // another asset and withdrawing that: two colluding accounts can round-trip out of a 7-day
    // lock in a single settlement (verified by probe). Writing the clock on settlement
    // credit was rejected: it costs two SSTOREs per fill and lets a counterparty grief a victim's
    // withdrawal clock with dust fills. Treat this purely as UX friction against fat-finger
    // deposit/withdraw loops. Current policy value: 0 (disabled).
    uint256 public withdrawalDelay;

    // slot 5 — Operators (trade settlement authority)
    mapping(address => bool) public operators;

    // slot 6 — User balances: user => token => balance
    mapping(address => mapping(address => uint256)) public balances;

    // slot 7 — Solvency accumulator: totalTracked[T] MUST always equal Σ_user balances[u][T].
    // Maintained at every balances mutation site (deposits/withdrawals/emergencyWithdrawFor;
    // settleOrders is a no-op here since it is zero-sum per token). Used by recoverStuckTokens to
    // compute the excess (non-user-owed) balance that is safe to sweep.
    mapping(address => uint256) private totalTracked;

    // slot 8 — Supported tokens (base asset set; only tokens issued from Launchpad)
    mapping(address => bool) public supportedTokens;

    // slot 9 — Quote-asset (payment asset) registry. `decimals` is cached at first listing from
    // IERC20Metadata.decimals() and is FAIL-CLOSED: an asset whose decimals cannot be read is not
    // listable at all (no 18 fallback — a fallback silently reintroduces the 18-decimal
    // hardcoding this registry exists to remove). min/max are absolute token amounts derived from
    // that decimals value; see setQuoteAsset / setQuoteLimits.
    // NOT packed (3 slots) on purpose: listing happens once per asset, so the gas saving rounds to
    // zero while downcasting would add review surface.
    struct QuoteAsset {
        bool listed;
        uint8 decimals;
        uint256 minTradeAmount;
        uint256 maxTradeAmount;
    }
    mapping(address => QuoteAsset) public quoteAssets;

    // slot 10 — per-(user, token) withdrawal-delay clock. Keyed by token so depositing one
    // token no longer relocks withdrawals of every other token the user holds.
    mapping(address => mapping(address => uint256)) public lastDepositTime;

    // slot 11 — Operator change timelock
    struct PendingOperatorChange {
        address operator;
        bool status;
        uint256 executeAfter;
    }
    mapping(bytes32 => PendingOperatorChange) public pendingOperatorChanges;

    // slot 12 — Settlement replay guard for settleOrders. Retained after the net-delta removal:
    // settleOrders is its only writer now, not merely a co-owner of it.
    mapping(bytes32 => bool) public processedSettlements; // settlementId => processed

    // slot 13
    mapping(address => uint256) public feeAccrued; // token => cumulative fee credited (monotonic)

    // slot 14 — Cumulative filled token amount per order hash (partial-fill accounting for
    // settleOrders).
    mapping(bytes32 => uint256) public orderFilled;

    // slot 15 — Order cancellation flags keyed by order hash.
    mapping(bytes32 => bool) public orderCancelled;

    // slot 16 — Session keys. sessionKeyValidUntil[account][key] = unix ts until which `key` may
    // sign Orders on behalf of `account`. 0 = not authorized / revoked.
    mapping(address => mapping(address => uint256)) public sessionKeyValidUntil;

    // slot 17 — per-(account, sessionKey, token) spend allowance, FAIL-CLOSED. A cap of 0
    // (the default) means the key cannot move that asset at all, so registering a key grants
    // nothing until the account funds it per-asset via setSessionKeyCap / a signed SessionKeyAuth.
    //
    // The cap is a PER-WINDOW allowance for that triple, refilling every SESSION_KEY_WINDOW. It
    // was cumulative-for-life until a product decision made it auto-reset per period, so that no
    // re-signature is needed: removing the key's TTL had made cap exhaustion the new expiry — a
    // lifetime cap means the wallet popup the TTL removal deleted comes straight back the day a
    // key spends its budget. Bounded to uint192 by the setters so the window
    // counter's downcast is safe.
    //
    // What this costs, stated rather than discovered later: the lifetime bound on a LEAKED key is
    // gone. A stolen key now drains `cap` per window forever instead of `cap` once, so the loss
    // bound is cap × (windows until the user revokes), not cap. Revocation is the only stop — which
    // is why `sessionKeyOrderCap` exists alongside it (capping the per-order size bounds how fast a
    // single window's budget can be burned) and why the ANOMALY DETECTION the trade server owns
    // (flag unusual session-key activity, notify the user, prompt revocation) is load-bearing,
    // not a nice-to-have.
    //
    // Crucially the cap is keyed by the asset that is actually DEBITED on each leg, not by the
    // quote asset: the sell leg debits `baseToken`. A quote-only cap leaves the sell leg completely
    // unbound, because an attacker holding the key signs `sell 1,000,000 BASE for 0.01 USDT` — the
    // price check passes (it is the victim's own signed limit) while the quote notional is dust.
    //
    // SEMANTICS — this is a maximum LOSS bound, not a maximum trading volume. A leaked key can
    // spend the whole cap for nothing in return (`buy 1 wei of base for <cap> quote`), so the
    // right user-facing wording is "most this key can cost me", never "how much this key may
    // trade". Note also that the seller-side fee is deducted from the seller's proceeds and is
    // therefore not metered against any cap; it is bounded indirectly by the base cap that limits
    // how much can be sold at all.
    mapping(address => mapping(address => mapping(address => uint256))) public sessionKeySpendCap;

    // slot 18 — amount spent IN THE CURRENT WINDOW per (account, sessionKey, token).
    // Accumulated per FILL (not per order) so a partially-filled order only consumes what it
    // actually moved. Same fixed-window derivation as `withdrawalWindows`: a stale `windowId` means
    // the allowance already refilled, so a refill costs no transaction and no write.
    mapping(address => mapping(address => mapping(address => SpendWindow))) public sessionKeySpendWindows;

    // slot 19 — Per-account monotonic nonce for relayed session-key registration
    // (registerSessionKeyWithSig). Bumped by consumption, by revokeSessionKey and by
    // invalidateSessionKeyAuths — see those functions for the rationale.
    mapping(address => uint256) public sessionKeyRegNonce;

    // slot 20 — staged recoverStuckTokens parameters, as keccak256(abi.encode(token, to,
    // amount)). Stored as a HASH rather than three fields so the executed call must match the
    // staged one on EVERY argument (a per-field staging invites a `_to`-only substitution at
    // execution time, which is precisely the power the timelock exists to remove). 0 = nothing
    // staged; single-use (cleared on execute and on cancel).
    bytes32 public pendingRecoverHash;

    // slot 21 — earliest timestamp the staged recovery may execute. 0 when nothing is staged.
    uint256 public recoverReadyAt;

    // slot 22 — per-account order-nonce floor. Every Order whose `nonce` is strictly below
    // this value is unsettleable, so one SSTORE invalidates an unbounded number of open orders.
    //
    // WHY THIS EXISTS ALONGSIDE `orderCancelled`: hash-keyed cancellation costs one COLD SSTORE per
    // order, so cancelling N orders costs O(N) and has no upper bound. That made `cancelOrder`
    // impossible to gas-sponsor (an unbounded, attacker-chosen cost), which in turn left a user
    // holding no native token with NO on-chain escape from a censoring operator — the exact
    // scenario the signed-order design exists to survive. This mapping makes bulk invalidation
    // O(1) and constant-cost, hence sponsorable. `orderCancelled` is retained for precise,
    // single-order cancellation.
    //
    // OFF-CHAIN CONTRACT: this reinterprets `Order.nonce`. It remains a plain field of the signed
    // struct — the contract never assigns, increments or requires uniqueness of it — but the floor
    // is only useful if the order server issues nonces that are non-decreasing per account.
    mapping(address => uint256) public minOrderNonce;

    // slot 23 — per-ASSET withdrawal rate limit, in absolute token amounts of that asset.
    // 0 (the default, and the value every asset ships with) means NO LIMIT — deliberately NOT
    // "zero allowance". Making 0 the disabled state means the naive strangle input
    // (`setDailyWithdrawalLimit(t, 0)`) is the LOOSENING direction and a total freeze is simply not
    // expressible: every other value is floored at MIN_WITHDRAWAL_LIMIT_UNITS * 10**decimals.
    //
    // QUOTE ASSETS ONLY, by construction — the setter requires a cached `quoteAssets[t].decimals`.
    // Two reasons, and neither is "base tokens don't matter":
    //   1. The floor above is decimals-denominated, and the only decimals this contract trusts are
    //      the ones cached fail-closed at setQuoteAsset time. Base tokens have no such cache, and
    //      reading `decimals()` inside a withdrawal would put an EXTERNAL CALL TO AN UNTRUSTED TOKEN
    //      on the exit path: a token that starts reverting (or burns the gas stipend) would brick
    //      its own holders' withdrawals. A fail-closed read is acceptable when listing an asset; it
    //      is never acceptable on the way out.
    //   2. Base tokens are auto-listed in unbounded number by `lister` (TokenFactory), so per-asset
    //      limit curation for them is not operationally real. Value also exits in the quote leg:
    //      base tokens are launchpad equity that must be SOLD (a signed, capped settlement) before
    //      it becomes money.
    // The honest cost of (1)+(2): an attacker who ends up holding base tokens can withdraw them at
    // full speed. This control does not claim otherwise.
    mapping(address => uint256) public dailyWithdrawalLimit;

    // slot 24 — per-(user, asset) consumption of the current window. ONE slot, both fields
    // packed, written with a single whole-struct store — so an enabled limit costs exactly one
    // SSTORE per (user, token) per withdrawal (plus the one cold SLOAD of the limit above), and a
    // disabled limit costs that SLOAD and nothing else. `used` is uint192 because the setter caps
    // any enabled limit at type(uint192).max and `used` is never written above the limit.
    //
    // FIXED WINDOW, not rolling. `windowId = block.timestamp / WITHDRAWAL_WINDOW` is a pure
    // function of the clock, so the reset needs no bookkeeping transaction and no per-user epoch
    // anchor. A true rolling window needs either the full timestamped withdrawal history (unbounded
    // storage, unbounded gas) or K sub-buckets (K SLOADs + up to K SSTOREs per withdrawal) — a
    // 5-20x gas increase on the exit path to remove ONE artifact: at a window boundary a user may
    // spend the limit at T-1 and again at T, i.e. up to 2x the limit within two blocks. For a
    // speed-bump whose purpose is buying operators detection time, paying that on every honest
    // withdrawal forever to halve one burst is the wrong trade; the burst is documented and the
    // limit should be sized as "2x this is survivable".
    // Shared with `sessionKeySpendWindows` (slot 18): the two rate limits are the same mechanism
    // pointed at different budgets, so they use one struct rather than two identical ones. The
    // window LENGTH is not part of the struct — each site divides by its own constant.
    struct SpendWindow {
        uint64 windowId;
        uint192 used;
    }
    mapping(address => mapping(address => SpendWindow)) public withdrawalWindows;

    // slot 25 — per-(account, sessionKey, token) ceiling on a SINGLE order, alongside the per-window
    // budget in slot 17. Fail-closed like the window cap: 0 means the key cannot sign any order in
    // that asset, so a key is unusable until the account funds BOTH caps.
    //
    // Checked against the order's maximum possible debit at authorization time — once per order, on
    // calldata only, with no per-order storage. That works because the signed order already bounds
    // the sum of its own fills: step 7 caps Σ fillBase at `baseAmount`, and the step 6 price check
    // makes each fill's quote proportional to its base, so Σ fillQuote ≤ `quoteAmount`. Metering
    // per fill instead would need a slot per order hash to remember the running total.
    mapping(address => mapping(address => mapping(address => uint256))) public sessionKeyOrderCap;

    mapping(address => mapping(address => uint256)) public sessionKeyGeneration;

    mapping(address => mapping(address => mapping(address => uint256))) private sessionKeyCapGeneration;

    // ============ Storage Gap ============
    // Append-only rules, binding once this contract is deployed at its (fresh, clean-redeploy)
    // proxy address:
    //   1. Existing slots are never reordered or removed.
    //   2. New state goes directly above __gap; __gap shrinks by the same slot count.
    //   3. Changing a mapping's key structure is ALSO a layout change (same slot number, but
    //      every value lives at a different derived location) and is forbidden post-deployment —
    //      the `lastDepositTime` key-arity change in this commit is only possible because nothing
    //      has been deployed yet.
    //   4. A storage-layout snapshot is committed and diffed in CI against this baseline.
    //
    // The net-delta removal freed exactly 2 slots (`netDeltaEnableReadyAt`, `batchAmountCap`;
    // `netDeltaSettlementEnabled` was packed into slot 0 and freed none) and the recovery
    // timelock's pendingRecoverHash/recoverReadyAt consumed exactly 2. `minOrderNonce` then
    // appended one slot (22) and took it out of the gap (50 -> 49), per rule 2 above. The
    // withdrawal rate limit then appended two
    // more (`dailyWithdrawalLimit` 23, `withdrawalWindows` 24) and took them out of the gap
    // (49 -> 47). The session-key window change appended `sessionKeyOrderCap` (25) for one more
    // (47 -> 46); re-typing slot 18 from uint256 to SpendWindow cost no slot, since both fields
    // pack into the one it already had. Total footprint is therefore unchanged at slots 0–71.
    uint256[44] private __gap;

    // ============ Structs ============
    // Signed Order (primary settlement path). `isBuy` distinguishes the buy side (pays quote,
    // receives base) from the sell side (delivers base, receives quote). `nonce` differentiates
    // otherwise-identical orders so they hash distinctly; partial fills are tracked by order hash.
    // Field order MUST stay byte-identical to ORDER_TYPEHASH's typestring (and to _hashOrder's
    // abi.encode argument order).
    struct Order {
        address account;
        address baseToken;
        address quoteToken;
        bool isBuy;
        uint256 baseAmount;
        uint256 quoteAmount;
        uint256 maxFeeRate;
        uint256 nonce;
        uint256 expiry;
    }

    // One fill: the two signed orders, their signatures, the amounts, and the settlement id.
    // NOT an EIP-712 payload — nothing signs a Settlement. It exists so a batch can be passed as an
    // array (nine loose parameters cannot be) and so the single and batched entrypoints can share
    // one body. The signed objects inside it are the Orders, exactly as before.
    struct Settlement {
        Order buyOrder;
        bytes buySig;
        Order sellOrder;
        bytes sellSig;
        uint256 fillBaseAmount;
        uint256 fillQuoteAmount;
        uint256 buyerFee;
        uint256 sellerFee;
        bytes32 settlementId;
    }

    // Relayed session-key authorization payload. Field order MUST stay byte-identical to
    // SESSION_KEY_TYPEHASH's typestring (and to _hashSessionKeyAuth's abi.encode argument order).
    struct SessionKeyAuth {
        address account;
        address sessionKey;
        uint256 validUntil;
        uint256 deadline;
        address[] tokens;
        uint256[] caps;
        uint256[] orderCaps;
        uint256 nonce;
    }

    // ============ Events ============
    event Deposited(address indexed user, address indexed token, uint256 amount);
    event Withdrawn(address indexed user, address indexed token, uint256 amount);
    event OperatorUpdated(address indexed operator, bool status);
    event TokenSupported(address indexed token, bool status);
    event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);
    event WithdrawalDelayUpdated(uint256 oldDelay, uint256 newDelay);
    /// @dev An asset's per-window withdrawal rate limit changed. `newLimit == 0` means the
    ///      limit was switched OFF (unlimited), not set to zero allowance.
    event WithdrawalLimitUpdated(address indexed token, uint256 oldLimit, uint256 newLimit);
    event EmergencyWithdraw(address indexed user, address indexed token, uint256 amount);

    // Operator timelock events
    event OperatorChangeQueued(bytes32 indexed changeId, address indexed operator, bool status, uint256 executeAfter);
    event OperatorChangeExecuted(bytes32 indexed changeId, address indexed operator, bool status);
    event OperatorChangeCancelled(bytes32 indexed changeId);

    // Quote-asset registry events (no on-chain enumeration exists — downstream indexers/collectors
    // reconstruct the live quote roster from these).
    event QuoteAssetUpdated(
        address indexed token,
        bool listed,
        uint8 decimals,
        uint256 minTradeAmount,
        uint256 maxTradeAmount
    );
    event QuoteLimitsUpdated(address indexed token, uint256 minTradeAmount, uint256 maxTradeAmount);

    // Signature-based settlement events.
    // NOTE on topics: EVM allows only 3 indexed fields. `quoteToken` is indexed because it is the
    // market-level subscription filter and, without it, a consumer cannot tell from the log alone
    // WHICH asset a fill settled in. `settlementId` gave up its topic slot to make room: it is
    // minted by the submitter (who already knows it) and remains queryable on-chain via
    // `processedSettlements(id)`, whereas the two order hashes are the join keys an indexer needs
    // symmetric topic access to.
    event OrdersSettled(
        bytes32 settlementId,
        bytes32 indexed buyOrderHash,
        bytes32 indexed sellOrderHash,
        address indexed quoteToken,
        uint256 fillBaseAmount,
        uint256 fillQuoteAmount,
        uint256 totalFee
    );
    /// @dev One item of a `settleOrdersBatch` reverted and was skipped. `reason` is the raw revert
    ///      data, decodable into the same custom error a single-item settle would have thrown.
    ///      The item settled NOTHING — its state changes, `processedSettlements` included, rolled
    ///      back with it — so the same `settlementId` may be resubmitted once its cause is fixed.
    ///      Absence of this event for an id in a batch that ran means that id settled.
    event SettlementFailed(bytes32 indexed settlementId, uint256 index, bytes reason);
    event OrderCancelled(address indexed account, bytes32 indexed orderHash);
    /// @dev Every Order of `account` with `nonce < newMinNonce` is now unsettleable. This is
    ///      the ONLY signal of a bulk cancellation — the individual orders emit nothing, and there
    ///      is no per-hash state to read, so an indexer must apply the floor to its own open-order
    ///      book rather than expect an OrderCancelled per order.
    event OrdersInvalidatedBelow(address indexed account, uint256 newMinNonce);
    event SessionKeyRegistered(address indexed account, address indexed sessionKey, uint256 validUntil);
    event SessionKeyRevoked(address indexed account, address indexed sessionKey);
    /// @dev Per-asset spend allowance for a session key. Emitted on every cap write, whether
    ///      from setSessionKeyCap or from a relayed SessionKeyAuth.
    /// @dev `cap` is the per-SESSION_KEY_WINDOW budget, `orderCap` the ceiling on one order. Both
    ///      are always written together, so one event carries both.
    event SessionKeyCapUpdated(
        address indexed account,
        address indexed sessionKey,
        address indexed token,
        uint256 cap,
        uint256 orderCap
    );
    /// @dev Every unsubmitted SessionKeyAuth signed by `account` is now stale.
    event SessionKeyAuthsInvalidated(address indexed account, uint256 newNonce);
    /// @dev The narrow auto-listing role changed.
    event ListerUpdated(address indexed oldLister, address indexed newLister);
    event UpgradeRequested(address indexed newImplementation, uint256 readyAt);
    event UpgradeCancelled(address indexed cancelledImplementation);
    /// @dev A stuck-token recovery was staged. Carries the plaintext parameters (only their
    ///      hash is stored) so watchers can see WHAT is about to leave and to WHERE during the 48h.
    event RecoverRequested(address indexed token, address indexed to, uint256 amount, uint256 readyAt);
    event RecoverCancelled(bytes32 cancelledRecoverHash);
    event StuckTokensRecovered(address indexed token, address indexed to, uint256 amount);

    // ============ Errors ============
    error ZeroAddress();
    error ZeroAmount();
    /// @dev Carries WHICH account was short of WHICH asset. The debit sites in settleOrders
    ///      previously fell through to the compiler's checked-subtraction `panic 0x11`, which is
    ///      indistinguishable from a compiler bug and names neither the side nor the asset — the
    ///      same defect already fixed in recoverStuckTokens (NothingToRecover).
    error InsufficientBalance(address account, address token);
    error NotOperator();
    error UnsupportedToken();
    error WithdrawalTooEarly();
    /// @dev batchWithdraw's per-token variant of WithdrawalTooEarly — never a silent skip.
    error WithdrawalTooEarlyForToken(address token);
    error InvalidSignature();
    error SignatureExpired();
    error ExcessiveFee();
    error BatchTooLarge();
    error ExcessiveWithdrawalDelay();
    /// @dev This withdrawal would push the caller's consumption of `token` past its per-window
    ///      limit. Carries `remaining` (0 once exhausted) and `resetAt`, the exact unix timestamp at
    ///      which the allowance refills — so a rejected caller is told WHEN, not merely "no".
    error WithdrawalLimitExceeded(address token, uint256 requested, uint256 remaining, uint256 resetAt);
    /// @dev The requested limit is below the sealed floor (MIN_WITHDRAWAL_LIMIT_UNITS whole
    ///      units of the asset) or above type(uint192).max. Note 0 is always accepted — it disables.
    error InvalidWithdrawalLimit();
    error SelfTradingNotAllowed();
    error TradeAmountTooSmall();
    error InvalidSignatureLength();
    error InvalidImplementation();

    // Additional errors for operator abuse prevention
    error TradeAmountTooLarge();
    error OperatorChangeNotFound();
    error OperatorChangeTooEarly();
    error OperatorChangeAlreadyExists();

    // Settlement errors
    error SettlementAlreadyProcessed();

    // Signature-based non-custodial errors
    error OrderExpired();
    error OrderIsCancelled();
    /// @dev The order's nonce is below its account's `minOrderNonce` floor — bulk-invalidated.
    ///      Distinct from OrderIsCancelled so an operator can tell a per-hash cancel from a sweep.
    error OrderNonceBelowFloor(address account, uint256 nonce, uint256 minNonce);
    /// @dev invalidateOrdersBelow must strictly increase the floor. A non-increasing write is
    ///      rejected rather than ignored, so a replayed or stale invalidation transaction can never
    ///      LOWER the floor and resurrect orders the account already killed.
    error MinOrderNonceNotIncreasing();
    error ReservedOrderNonce(address account, uint256 nonce);
    error PriceNotCrossed();
    error OrderOverfill();
    error SessionKeyNotAuthorized();
    error InvalidRegistrationNonce();
    /// @dev An operator, the feeRecipient or the owner may never act as a session key —
    ///      checked BOTH at registration and at use, because the privileged sets are mutable and a
    ///      key registered while innocent can be promoted to operator afterwards.
    error ForbiddenSessionKey();
    /// @dev This fill would push the key's cumulative spend of the DEBITED asset past its cap
    ///      (cap 0 = never allowed).
    /// @dev `remaining` is what is left of the per-window budget for `token`, and `resetAt` is when
    ///      it refills — both included so a client can say "wait until X" instead of only "denied".
    error SessionKeyCapExceeded(address token, uint256 remaining, uint256 resetAt);
    /// @dev The order's maximum debit exceeds the per-order ceiling. Distinct from the window error
    ///      on purpose: this one never clears by waiting, the order must be smaller.
    error SessionKeyOrderCapExceeded(address token, uint256 maxDebit, uint256 orderCap);
    /// @dev SessionKeyAuth.tokens and .caps have different lengths.
    error ArrayLengthMismatch();
    error DuplicateSessionKeyToken(address token);
    /// @dev `settleOrdersSelf` reached by anything other than this contract's own batch loop.
    error OnlySelf();
    /// @dev The item at `index` reverted with no return data, i.e. it ran out of gas. The batch is
    ///      aborted rather than continuing, so that a gas estimate can never settle on an amount
    ///      that quietly swallows every item. Send more gas or send a smaller batch.
    error BatchOutOfGas(uint256 index);
    error ItemOutOfGas(uint256 index);
    /// @dev SSA-17: this item's own remaining gas cannot guarantee `ERC1271_GAS_STIPEND` reaches
    ///      the ERC-1271 callee under EIP-150's 63/64 rule. Signals an underfunded batch, not an
    ///      invalid item — `settleOrdersBatch` routes this selector through the same branch as an
    ///      empty-returndata out-of-gas.
    error InsufficientGasForSigCheck();
    /// @dev SSA-17: the ERC-1271 staticcall reverted with no return data despite receiving the full
    ///      `ERC1271_GAS_STIPEND`. Kept distinct from `InvalidSignature` because the raw
    ///      (success, returndata) pair cannot distinguish "callee ran out of gas" from
    ///      "callee returned false".
    error Erc1271VerificationStarved();
    /// @dev A per-window session-key cap above type(uint192).max, which `SpendWindow.used` cannot
    ///      hold. See `_writeSessionKeyCaps`.
    error InvalidSessionKeyCap();
    /// @dev Caller is neither owner() nor lister.
    error NotAuthorizedLister();
    error NoPendingUpgrade();
    error UpgradeNotReady();
    /// @dev The staged upgrade matured more than UPGRADE_GRACE_PERIOD ago and is no longer
    ///      executable. Re-stage to obtain a fresh window — and a fresh public announcement.
    error UpgradeExpired();
    error ImplementationMismatch();
    error SideMismatch();
    /// @dev buyOrder.baseToken != sellOrder.baseToken.
    error TokenMismatch();

    // ---- Multi-quote errors ----
    /// @dev THEFT-CRITICAL: buyOrder.quoteToken != sellOrder.quoteToken.
    ///      Empirically verified by mutation probe, NOT by inspection: removing this
    ///      check does NOT break solvency. Every balance leg below is written against a single
    ///      `quoteAddr = buyOrder.quoteToken`; `sellOrder.quoteToken` is never read by the balance
    ///      math, so each token still nets to zero and `Σ balances == balanceOf` survives.
    ///      What breaks is the SELLER: they are paid in the BUYER's quote asset, and the price-cross
    ///      check (step 6) compares raw amounts with no decimals normalisation across assets. A
    ///      seller asking >= 1000e6 USDC is therefore satisfied by 2e16 raw of an 18-dec asset —
    ///      about $0.02 — while delivering the full base amount. One mismatched pair is enough to
    ///      strip a seller, so this check is load-bearing; the reason is value extraction, not mint.
    error QuoteMismatch();
    /// @dev baseToken == quoteToken. Aggregates still net to zero (I1 holds) but the per-account
    ///      outcome is nonsense, so this is a distinct error from QuoteMismatch by design.
    error BaseQuoteCollision();
    /// @dev The order's quoteToken is not listed in the quoteAssets registry.
    error UnsupportedQuote();
    /// @dev IERC20Metadata.decimals() is missing/reverting/undecodable — the asset is NOT listable.
    ///      Deliberately fail-closed: there is no 18-decimal fallback.
    error QuoteDecimalsUnavailable();
    /// @dev decimals() outside the supported 2..30 range.
    error InvalidQuoteDecimals();
    /// @dev setQuoteLimits arguments violate the hard bounds (see setQuoteLimits).
    error InvalidQuoteLimits();

    /// @dev recoverStuckTokens: _amount exceeds the token's excess (non-user-owed) balance.
    error NothingToRecover();

    // ---- recoverStuckTokens timelock ----
    /// @dev No staged recovery exists (never requested, already executed, or cancelled).
    error NoPendingRecover();
    /// @dev A recovery is staged but RECOVER_TIMELOCK_DELAY has not elapsed yet.
    error RecoverNotReady();
    /// @dev The staged recovery matured more than RECOVER_GRACE_PERIOD ago. It is dead — in
    ///      particular it can no longer be pointed at excess that only appeared after it was
    ///      announced. Re-stage against the current balance state.
    error RecoverExpired();
    /// @dev The (token, to, amount) triple does not hash to the staged one — an exact match on all
    ///      three is required, so the 48h window cannot be repurposed for a different sweep.
    error RecoverParamsMismatch();

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

    /// @dev Hoists `_deposit`'s
    ///      `supportedTokens`/`quoteAssets` gate so it runs on BOTH deposit entry points BEFORE
    ///      either makes any external call on caller-supplied `_token`. LOAD-BEARING ORDERING —
    ///      this is not cosmetic: {depositWithPermit} makes an external call to `_token`
    ///      (`try IERC20Permit(_token).permit(...)`) before the transfer leg, and the paymaster's
    ///      (target, selector) allowlist (VerifyingPaymaster.sol) only ever inspects the OUTER
    ///      target/selector, never this inner argument — so an unsupported `_token` used to reach
    ///      that external call unchecked, letting a sponsored-but-business-gated wallet point it
    ///      at an attacker-deployed gas burner and have the paymaster billed for the burn (see
    ///      test/VerifyingPaymaster.k1poc.test.ts). Applying this modifier BEFORE the function
    ///      body means an unsupported token now reverts here, before {depositWithPermit} ever
    ///      constructs the `try` call, so the burner is never reached. `_deposit` keeps its own
    ///      copy of this same check (defense-in-depth for any future entry point that forgets the
    ///      modifier) — do not remove either copy. If you ever move this modifier to run AFTER a
    ///      new entry point's external call, the gas-burner path reopens for that entry point.
    modifier onlySupportedToken(address _token) {
        if (!supportedTokens[_token] && !quoteAssets[_token].listed) revert UnsupportedToken();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ============ Initialization ============

    /**
     * @notice Initialize the trade settlement contract.
     * @dev There is deliberately no USDT (or any other) quote pointer: quote assets are registered
     *      via setQuoteAsset after deployment.
     * @param _feeRecipient Fee recipient address.
     * @param _lister Address allowed to auto-list base tokens (typically TokenFactory). May be
     *        address(0) at deploy time — the factory usually does not exist yet — and set later
     *        via setLister.
     */
    function initialize(address _feeRecipient, address _lister) public initializer validAddress(_feeRecipient) {
        __Ownable_init(msg.sender);
        __Pausable_init();
        __EIP712_init("StarZipTradeSettlement", "1"); // EIP-712 domain separator

        feeRecipient = _feeRecipient;
        lister = _lister;

        withdrawalDelay = 0; // No default delay

        // NO operator is seeded here. Operator changes are 24h-timelocked
        // (queueOperatorChange -> executeOperatorChange), and a deploy-time carve-out made that
        // timelock conditional on when you asked: the deployer became an operator with zero notice,
        // and — because the deployer is also the initial owner — could keep that power indefinitely
        // while every LATER grant was announced 24h in advance. The contract therefore initializes
        // with an EMPTY operator set: settleOrders reverts NotOperator until the first operator has
        // gone through the full queue -> 24h -> execute path; the operator is queued as a separate
        // post-deploy step.
    }

    // ============ Deposit Functions ============

    /**
     * @notice Deposit tokens (base assets AND quote assets share this single entrypoint).
     * @dev The gate spans BOTH registries: quote assets (USDT/USDC) are not members of
     *      `supportedTokens` (the base-asset set), so checking only that set would make quote
     *      deposits — i.e. every buy-side deposit — impossible.
     *
     *      MEASURED DELTA: the credit is the contract's actual balance change, not
     *      `_amount`. Crediting the requested amount breaks I1 (totalTracked == Σ balances) on the
     *      very FIRST deposit of any fee-on-transfer / rebasing token, which turns withdrawals into
     *      first-come-first-served and bricks `recoverStuckTokens` permanently (its subtraction
     *      panics once tracked exceeds the real balance). The `nonReentrant` guard is what makes
     *      the measurement sound: it blocks an ERC777-style transfer callback from re-entering and
     *      taking the delta twice.
     * @param _token Token address
     * @param _amount Amount to pull from msg.sender. The CREDITED amount may be lower.
     */
    function depositToken(
        address _token,
        uint256 _amount
    ) external nonReentrant whenNotPaused validAddress(_token) validAmount(_amount) onlySupportedToken(_token) {
        _deposit(_token, _amount);
    }

    /**
     * @notice Deposit in ONE transaction using an EIP-2612 permit instead of a prior `approve`.
     * @dev WHY THIS EXISTS: `depositToken` requires a prior `approve`, which is a call to the
     *      TOKEN, not to this contract, so it sits outside any paymaster policy scoped to this
     *      address. Folding the approval into a signature removes that separate on-chain
     *      transaction entirely: a user can authorize the pull and deposit in ONE call instead of
     *      two.
     *
     *      CURRENT REALITY (this is no longer a zero-BNB path): this used to hold —
     *      `depositWithPermit` was itself sponsored, so folding out the `approve` leg did make the
     *      whole first deposit a single SPONSORABLE call. The paymaster remediation de-sponsored
     *      it: `depositWithPermit`
     *      is deliberately EXCLUDED from `SPONSORED.TradeSettlementV1` because its external call
     *      into a caller-supplied `_token` used to run before the token-listing gate. So today the
     *      permit path still removes the separate `approve` transaction (a real UX win — one
     *      signature instead of two on-chain txs), but the resulting `depositWithPermit` call
     *      itself is gas-sponsored by NOBODY — the caller pays for it like any other unsponsored
     *      call. There is currently no zero-BNB first deposit anywhere in this contract's surface.
     *
     *      PERMIT FAILURE IS NON-FATAL, BY DESIGN. The permit is executed in try/catch and a revert
     *      is swallowed, then the ordinary transfer path runs. Two distinct cases motivate this:
     *        (a) FRONT-RUNNING — permits are public. Anyone can lift the signature from the mempool
     *            and submit `permit` alone; the nonce is consumed and the victim's own transaction
     *            then reverts on a replayed permit even though the allowance it wanted now EXISTS.
     *            Swallowing turns that griefing vector into a no-op.
     *        (b) NON-PERMIT TOKENS — real-world USDT/USDC deployments vary by chain on whether
     *            EIP-2612 exists at all. A missing `permit` selector reverts (no matching function,
     *            or a fallback that reverts) and is caught identically.
     *      In BOTH cases the deposit then succeeds if and only if a sufficient allowance already
     *      exists, and otherwise reverts inside `safeTransferFrom` with the token's own
     *      insufficient-allowance error. The failure is therefore never silent — it is just
     *      attributed to the transfer rather than to the permit.
     *
     *      COROLLARY — there is NO on-chain permit-support probe here, and callers must not read
     *      one into a successful call: a token with a non-reverting fallback "succeeds" at `permit`
     *      while granting nothing. Off-chain support detection must be done off-chain (static call
     *      `DOMAIN_SEPARATOR()` / `nonces(address)` and check the allowance actually moved), not
     *      inferred from this function.
     * @param _token Token to deposit. Must be a listed base or quote asset.
     * @param _amount Amount to pull. The CREDITED amount may be lower (measured delta, see below).
     * @param _deadline EIP-2612 permit deadline.
     * @param v Permit signature v.
     * @param r Permit signature r.
     * @param s Permit signature s.
     */
    function depositWithPermit(
        address _token,
        uint256 _amount,
        uint256 _deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant whenNotPaused validAddress(_token) validAmount(_amount) onlySupportedToken(_token) {
        // solhint-disable-next-line no-empty-blocks
        try IERC20Permit(_token).permit(msg.sender, address(this), _amount, _deadline, v, r, s) {} catch {
            // Deliberately ignored — see the NatSpec above. The transfer below is the real gate.
        }
        _deposit(_token, _amount);
    }

    /**
     * @dev Shared deposit body for depositToken / depositWithPermit. Assumes the caller applied
     *      `nonReentrant` + `whenNotPaused` + the address/amount guards; the reentrancy guard in
     *      particular is what makes the measured delta sound (see depositToken's NatSpec).
     *      The `onlySupportedToken` modifier on BOTH entry points already enforces this
     *      check before either function makes any external call on `_token` — this copy is
     *      defense-in-depth for a future caller of `_deposit` that forgets the modifier, not the
     *      primary gate. Do not delete it on the theory the modifier makes it redundant.
     */
    function _deposit(address _token, uint256 _amount) private {
        if (!supportedTokens[_token] && !quoteAssets[_token].listed) revert UnsupportedToken();

        uint256 balanceBefore = IERC20(_token).balanceOf(address(this));
        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        uint256 credited = IERC20(_token).balanceOf(address(this)) - balanceBefore;
        if (credited == 0) revert ZeroAmount();

        balances[msg.sender][_token] += credited;
        totalTracked[_token] += credited;
        lastDepositTime[msg.sender][_token] = block.timestamp;

        // The REAL credit, not the requested amount — indexers reconcile balances off this event,
        // so emitting `_amount` under a fee-bearing token would desync them from the ledger.
        emit Deposited(msg.sender, _token, credited);
    }

    // ============ Withdrawal Functions (direct self-custody) ============

    /**
     * @notice Withdraw an arbitrary token to msg.sender (direct, self-custodial).
     * @dev NOT gated on supportedTokens / quoteAssets (a delisted asset must still be exitable)
     *      and NOT `whenNotPaused`. Honors the withdrawal delay and the per-asset withdrawal
     *      rate limit. CEI: debit before transfer.
     *      This is the sole withdrawal entrypoint for both base and quote assets: there is no
     *      asset-specific variant keyed off a mutable pointer that an owner could repoint.
     * @param _token Token to withdraw.
     * @param _amount Amount to withdraw.
     */
    function withdrawToken(
        address _token,
        uint256 _amount
    ) external nonReentrant validAddress(_token) validAmount(_amount) {
        _checkWithdrawalDelay(msg.sender, _token);
        if (balances[msg.sender][_token] < _amount) revert InsufficientBalance(msg.sender, _token);
        _consumeWithdrawalAllowance(msg.sender, _token, _amount);
        balances[msg.sender][_token] -= _amount;
        totalTracked[_token] -= _amount;
        IERC20(_token).safeTransfer(msg.sender, _amount);
        emit Withdrawn(msg.sender, _token, _amount);
    }

    /**
     * @notice Withdraw the full msg.sender balance of each listed token in one call.
     * @dev msg.sender-scoped full-balance exits, CEI per token, bounded by
     *      MAX_BATCH_SIZE, NOT `whenNotPaused`. Zero-balance entries are skipped.
     *
     *      Each asset is metered against its OWN limit and its OWN
     *      `withdrawalWindows[msg.sender][token]` counter; there is no shared budget, so one
     *      rate-limited asset in the list never consumes another's allowance. A token whose full
     *      balance exceeds its remaining allowance REVERTS the whole batch (carrying `remaining`
     *      and `resetAt`) rather than silently clamping: `batchWithdraw` means "empty these", and
     *      an entrypoint that quietly moves less than the caller's whole balance while emitting a
     *      successful Withdrawn is exactly the kind of silent partial exit a self-custody path must
     *      not have. Callers that want the allowed portion use `withdrawToken(token, remaining)`.
     * @param _tokens Tokens to fully withdraw.
     */
    function batchWithdraw(address[] calldata _tokens) external nonReentrant {
        if (_tokens.length > MAX_BATCH_SIZE) revert BatchTooLarge();
        for (uint256 i = 0; i < _tokens.length; ) {
            address token = _tokens[i];
            uint256 bal = balances[msg.sender][token];
            if (bal > 0) {
                // Per-token delay check — a violation reverts the whole batch (never a
                // silent skip), keyed independently of every other token's deposit clock.
                if (_withdrawalDelayNotElapsed(msg.sender, token)) revert WithdrawalTooEarlyForToken(token);
                _consumeWithdrawalAllowance(msg.sender, token, bal);
                balances[msg.sender][token] = 0; // CEI: zero before transfer
                totalTracked[token] -= bal;
                IERC20(token).safeTransfer(msg.sender, bal);
                emit Withdrawn(msg.sender, token, bal);
            }
            unchecked {
                ++i;
            }
        }
    }

    // ============ Trade Settlement Functions ============

    /**
     * @notice PRIMARY settlement: match one signed buy Order against one signed sell Order.
     * @dev Every debit is authorized by the debited account's EIP-712 signature (EOA or ERC-1271
     *      via SignatureChecker) or a registered session key. Balance-only — makes NO external
     *      calls. Checks -> Effects. Token and USDT are conserved (nothing minted or lost).
     *
     *      The nine former parameters now travel inside `Settlement` — see that struct for the
     *      field-by-field meaning. Nothing about what is signed or checked changed with the
     *      wrapping; `settleOrdersBatch` needed an array, and an array of nine loose parameters is
     *      not expressible.
     * @param s The fill: both signed orders, both signatures, the amounts, and the settlement id.
     */
    function settleOrders(Settlement calldata s) external onlyOperator nonReentrant whenNotPaused {
        _settleOne(s);
    }

    /**
     * @notice Settle up to MAX_BATCH_SIZE fills in one transaction, isolating per-item failures.
     * @dev The throughput entrypoint. Its reason for existing is NOT gas: on an L2 the calldata for
     *      each order and its two signatures still ships either way, and the isolating self-call
     *      below adds a fresh call frame per item. What it removes is the OPERATOR NONCE
     *      bottleneck — one EOA can only land transactions sequentially, so N separate settlements
     *      serialize into N block slots, and the trade server's "50 fills or 1 second" pacing is
     *      unreachable that way. (The other half of that fix, multiple settlement keys, is trade's.)
     *
     *      PER-ITEM ISOLATION: each fill runs in its own call frame via `settleOrdersSelf`, so one
     *      bad item — a stale balance, a cancelled order, an exhausted session-key budget — reverts
     *      alone and its state changes (including its `processedSettlements` mark) roll back with
     *      it. That item stays retryable; the rest of the batch settles. Failures surface as
     *      `SettlementFailed` events rather than reverting the transaction, because a batch that
     *      dies on its worst item is exactly what a per-item design is meant to prevent.
     *
     *      SOLVENCY IS UNCHANGED. Isolation is per item and so is the zero-sum argument: each
     *      `_settleOne` conserves every token it touches on its own (step 9), so a batch conserves
     *      them whatever subset of its items succeeds. There is no cross-item netting here and no
     *      unsigned aggregate — the removed `batchSettleNetDeltas` was a different thing and is not
     *      coming back.
     *
     *      OUT OF GAS IS NOT A SKIPPABLE FAILURE, and the distinction is load-bearing. EIP-150
     *      leaves this frame 1/64 of its gas when a sub-call reverts, so a starved item would
     *      otherwise be caught and "recorded" like any other bad item — and because this function
     *      then returns successfully, `eth_estimateGas` binary-searches straight to the cheapest
     *      gas at which every item runs out and gets swallowed. The transaction would succeed,
     *      settle NOTHING, and emit a full set of failure events, which is the worst of the three
     *      possible outcomes: an operator that believes it settled a batch it did not.
     *
     *      So an item that reverts with EMPTY return data reverts the whole batch. Every genuine
     *      rejection inside `_settleOne` is a custom error and therefore carries data; a bare
     *      revert can only be exhaustion. Bubbling it up is what makes gas estimation converge on
     *      an amount that actually settles, and what stops silent under-settlement in production.
     * @param items Fills to settle, in order. Bounded by MAX_BATCH_SIZE.
     */
    function settleOrdersBatch(Settlement[] calldata items) external onlyOperator nonReentrant whenNotPaused {
        uint256 n = items.length;
        if (n > MAX_BATCH_SIZE) revert BatchTooLarge();

        for (uint256 i = 0; i < n; ) {
            // solhint-disable-next-line no-empty-blocks
            try this.settleOrdersSelf{gas: ITEM_GAS_BUDGET}(items[i]) {
                // Success is already reported by _settleOne's OrdersSettled event.
            } catch (bytes memory reason) {
                // Empty return data means the item was starved, not rejected — see the note above.
                // Skipping it here is what would let a whole batch evaporate under a gas estimate
                // that only ever measured the swallowing.
                // The raw revert data is forwarded so the operator can decode the same custom error
                // it would have seen from a single-item settle — collapsing every failure into a
                // flag would make a batch strictly harder to debug than the calls it replaces.
                //
                // SSA-17: `InsufficientGasForSigCheck` reverts WITH data (a bare selector) but
                // means the batch was underfunded, not that the item is invalid, so it takes the
                // same branch as an empty-returndata out-of-gas. `Erc1271VerificationStarved` is
                // deliberately NOT included — that one is a genuine per-item failure.
                bool starvedFrame = reason.length == 0 ||
                    (reason.length == 4 && bytes4(reason) == InsufficientGasForSigCheck.selector);
                if (starvedFrame) {
                    if (gasleft() >= ITEM_GAS_BUDGET / 63) {
                        emit SettlementFailed(
                            items[i].settlementId,
                            i,
                            abi.encodeWithSelector(ItemOutOfGas.selector, i)
                        );
                    } else {
                        revert BatchOutOfGas(i);
                    }
                } else {
                    emit SettlementFailed(items[i].settlementId, i, reason);
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Internal-only trampoline that gives `settleOrdersBatch` a revert boundary per item.
     * @dev NOT an operator entrypoint: `msg.sender` must be this contract, so the only way in is
     *      the loop above, which is itself `onlyOperator`, `nonReentrant` and `whenNotPaused`.
     *      Deliberately carries none of those modifiers itself — re-applying `nonReentrant` here
     *      would trip the guard the batch already holds (it is transient, not per-frame), and
     *      re-checking the pause state would just re-read a flag the batch already gated on.
     *
     *      Safe to leave unguarded because `_settleOne` is balance-only: it makes no external calls
     *      and moves no tokens, so there is nothing here for a reentrant caller to interleave with
     *      even if it could reach this function, which it cannot.
     * @param s The fill to settle.
     */
    function settleOrdersSelf(Settlement calldata s) external {
        if (msg.sender != address(this)) revert OnlySelf();
        _settleOne(s);
    }

    /// @dev The settlement body, shared by the single and batched entrypoints so the two can never
    ///      drift apart. Every access-control and reentrancy concern is handled by the callers
    ///      above; this function assumes it has been authorized.
    function _settleOne(Settlement calldata s) internal {
        // Calldata aliases: these are pointers into `s`, not copies, so the logic below reads
        // exactly what the single-fill version always read.
        Order calldata buyOrder = s.buyOrder;
        bytes calldata buySig = s.buySig;
        Order calldata sellOrder = s.sellOrder;
        bytes calldata sellSig = s.sellSig;
        uint256 fillBaseAmount = s.fillBaseAmount;
        uint256 fillQuoteAmount = s.fillQuoteAmount;
        uint256 buyerFee = s.buyerFee;
        uint256 sellerFee = s.sellerFee;
        bytes32 settlementId = s.settlementId;

        // 1. Replay protection
        if (processedSettlements[settlementId]) revert SettlementAlreadyProcessed();
        processedSettlements[settlementId] = true;

        // 2. Structural checks — these run BEFORE signature verification on purpose: the quote
        //    agreement below is a solvency precondition of the zero-sum argument in step 9, not a
        //    convenience check, so it must not sit behind any other validation.
        if (!buyOrder.isBuy || sellOrder.isBuy) revert SideMismatch();
        if (buyOrder.baseToken != sellOrder.baseToken) revert TokenMismatch();
        // ANTI-THEFT: both legs must settle in the SAME quote asset. The balance math below uses
        // buyOrder.quoteToken for every leg, so a mismatch does NOT break solvency — it pays the
        // seller in the buyer's asset while step 6's price check compares raw amounts across two
        // different decimal scales, letting a ~$0.02 fill satisfy a 1000-USDC floor. See the
        // QuoteMismatch NatSpec: verified by mutation probe, not assumed.
        if (buyOrder.quoteToken != sellOrder.quoteToken) revert QuoteMismatch();
        // CORRECTNESS: base == quote nets to zero in aggregate (I1 survives) but scrambles the
        // per-account result. Note this is a PER-ORDER check — a global base/quote disjointness
        // rule would permanently forbid legitimate USDC/USDT pairs.
        if (buyOrder.baseToken == buyOrder.quoteToken) revert BaseQuoteCollision();
        QuoteAsset memory quote = quoteAssets[buyOrder.quoteToken];
        if (!quote.listed) revert UnsupportedQuote();
        if (!supportedTokens[buyOrder.baseToken]) revert UnsupportedToken();
        if (buyOrder.account == sellOrder.account) revert SelfTradingNotAllowed();

        // 3. Per-order expiry + cancellation
        bytes32 buyHash = _hashOrder(buyOrder);
        bytes32 sellHash = _hashOrder(sellOrder);
        if (block.timestamp > buyOrder.expiry) revert OrderExpired();
        if (block.timestamp > sellOrder.expiry) revert OrderExpired();
        if (orderCancelled[buyHash]) revert OrderIsCancelled();
        if (orderCancelled[sellHash]) revert OrderIsCancelled();
        if (buyOrder.nonce == type(uint256).max) revert ReservedOrderNonce(buyOrder.account, buyOrder.nonce);
        if (sellOrder.nonce == type(uint256).max) revert ReservedOrderNonce(sellOrder.account, sellOrder.nonce);

        // Bulk invalidation floor. Checked here, next to the per-hash cancellation flags,
        // because it is the same class of check (the account withdrew its authorization) and must
        // bind BEFORE any balance moves. A floor raised after an order was signed retroactively
        // kills it — that is the point: it is the gas-cheap mass-cancel a censored user can afford.
        uint256 buyFloor = minOrderNonce[buyOrder.account];
        if (buyOrder.nonce < buyFloor) revert OrderNonceBelowFloor(buyOrder.account, buyOrder.nonce, buyFloor);
        uint256 sellFloor = minOrderNonce[sellOrder.account];
        if (sellOrder.nonce < sellFloor) revert OrderNonceBelowFloor(sellOrder.account, sellOrder.nonce, sellFloor);

        // 4. Signature authorization (both sides). A nonzero return means the leg was authorized by
        //    a session key rather than the account itself, and must be charged against that key's
        //    per-asset budget in step 8b.
        address buyKey = _authorizeOrderSig(buyOrder, buySig);
        address sellKey = _authorizeOrderSig(sellOrder, sellSig);
        // 4b. Per-order ceiling. Bound to the ORDER, so it is checked here (once, off calldata)
        //     rather than in step 8b where the per-window budget is metered per fill.
        _assertOrderWithinKeyCap(buyOrder, buyKey);
        _assertOrderWithinKeyCap(sellOrder, sellKey);

        // 5. Fill sanity. The notional bounds come from the quote asset's own registry entry, so
        //    they scale with that asset's decimals (a 6-decimal quote is bounded at 0.01/1M in
        //    ITS units, not at 1e18 raw).
        if (fillBaseAmount == 0) revert ZeroAmount();
        if (fillQuoteAmount < quote.minTradeAmount) revert TradeAmountTooSmall();
        if (fillQuoteAmount > quote.maxTradeAmount) revert TradeAmountTooLarge();

        // 6. Price crossing (full-precision products via mulDiv-by-1). Both sides are ratios of
        // (quote per base), so the comparison is decimals-agnostic and needs no scaling.
        // Buyer: effective price <= limit  => fillQuote * buyBaseAmt <= buyQuoteAmt * fillBase
        if (
            Math.mulDiv(fillQuoteAmount, buyOrder.baseAmount, 1) > Math.mulDiv(buyOrder.quoteAmount, fillBaseAmount, 1)
        ) {
            revert PriceNotCrossed();
        }
        // Seller: effective price >= limit => fillQuote * sellBaseAmt >= sellQuoteAmt * fillBase
        if (
            Math.mulDiv(fillQuoteAmount, sellOrder.baseAmount, 1) <
            Math.mulDiv(sellOrder.quoteAmount, fillBaseAmount, 1)
        ) {
            revert PriceNotCrossed();
        }

        // 7. Partial-fill accounting
        if (orderFilled[buyHash] + fillBaseAmount > buyOrder.baseAmount) revert OrderOverfill();
        if (orderFilled[sellHash] + fillBaseAmount > sellOrder.baseAmount) revert OrderOverfill();
        orderFilled[buyHash] += fillBaseAmount;
        orderFilled[sellHash] += fillBaseAmount;

        // 8. Fee ceilings on the FILL notional, capped by MAX_FEE_RATE and per-order maxFeeRate.
        //    A rate applied to a quote-denominated notional is itself decimals-agnostic.
        uint256 maxBuyFee = Math.mulDiv(fillQuoteAmount, Math.min(MAX_FEE_RATE, buyOrder.maxFeeRate), BASIS_POINTS);
        if (buyerFee > maxBuyFee) revert ExcessiveFee();
        uint256 maxSellFee = Math.mulDiv(fillQuoteAmount, Math.min(MAX_FEE_RATE, sellOrder.maxFeeRate), BASIS_POINTS);
        if (sellerFee > maxSellFee) revert ExcessiveFee();

        // 8b. Session-key spend caps. Charged on the asset each side actually GIVES UP, per
        //     fill, after every amount is final and before any balance moves (Effects, no external
        //     calls). Capping the quote notional alone would leave the sell leg unbounded: a leaked
        //     key signs `sell <huge> BASE for <dust> quote` — its own signed limit price, so the
        //     cross check passes — and the base tokens leave while the quote-denominated charge
        //     stays under any sane cap.
        _chargeSessionKey(buyOrder.account, buyKey, buyOrder.quoteToken, fillQuoteAmount + buyerFee);
        _chargeSessionKey(sellOrder.account, sellKey, sellOrder.baseToken, fillBaseAmount);

        // 9. Balance settlement (no transfers).
        // totalTracked is NOT touched here: this leg set is algebraically zero-sum per token
        // (seller -fillBase / buyer +fillBase cancel on `base`; seller +(fillQuote-sellerFee) /
        // buyer -(fillQuote+buyerFee) / feeRecipient +totalFee cancel on `quoteAddr`), so
        // Σ_user balances[u][T] is unchanged and totalTracked[T] stays valid without an update.
        // This holds per-token for ANY number of listed quote assets because the ledgers are
        // independent per token — but ONLY because step 2 forced base != quote and Q_buy == Q_sell.
        //
        // Both debits are bounds-checked EXPLICITLY into InsufficientBalance(account, token)
        // instead of relying on 0.8's checked subtraction. An under-funded fill is an ordinary,
        // frequently-hit operator condition (the trade server matched against a stale balance), not
        // an invariant violation, and `panic 0x11` tells the operator neither which side was short
        // nor which asset. The current balance is loaded once and reused for the write, so this
        // costs a comparison rather than an extra SLOAD.
        address base = buyOrder.baseToken;
        address quoteAddr = buyOrder.quoteToken;
        uint256 totalFee = buyerFee + sellerFee;

        uint256 sellerBase = balances[sellOrder.account][base];
        if (sellerBase < fillBaseAmount) revert InsufficientBalance(sellOrder.account, base);
        balances[sellOrder.account][base] = sellerBase - fillBaseAmount;

        uint256 buyerQuoteDebit = fillQuoteAmount + buyerFee;
        uint256 buyerQuote = balances[buyOrder.account][quoteAddr];
        if (buyerQuote < buyerQuoteDebit) revert InsufficientBalance(buyOrder.account, quoteAddr);
        balances[buyOrder.account][quoteAddr] = buyerQuote - buyerQuoteDebit;

        balances[sellOrder.account][quoteAddr] += (fillQuoteAmount - sellerFee);
        balances[buyOrder.account][base] += fillBaseAmount;
        balances[feeRecipient][quoteAddr] += totalFee;
        feeAccrued[quoteAddr] += totalFee;

        // 10. Emit
        emit OrdersSettled(settlementId, buyHash, sellHash, quoteAddr, fillBaseAmount, fillQuoteAmount, totalFee);
    }

    /**
     * @notice Cancel ONE order so it can never be settled (self-service, signer-authenticated).
     * @dev Precision cancel. Cost is O(1) per call but one COLD SSTORE per order, so cancelling an
     *      entire book is O(N) and unbounded — that is why this entrypoint is NOT gas-sponsorable
     *      and why `invalidateOrdersBelow` exists. Use this when a single order must die and the
     *      rest of the account's book must survive.
     * @param order The order to cancel. Caller MUST be order.account.
     */
    function cancelOrder(Order calldata order) external {
        require(msg.sender == order.account, "not order account");
        bytes32 orderHash = _hashOrder(order);
        orderCancelled[orderHash] = true;
        emit OrderCancelled(order.account, orderHash);
    }

    /**
     * @notice Invalidate EVERY order of msg.sender whose nonce is below `newMinNonce`, in one
     *         constant-cost write.
     * @dev THE CENSORSHIP ESCAPE HATCH. msg.sender-scoped, one slot per account, never pausable,
     *      and its cost does not depend on how many orders it kills — which is exactly what makes
     *      it safe to gas-sponsor. `cancelOrder`'s per-hash SSTORE is unbounded and attacker-chosen
     *      in aggregate, so sponsoring it was never possible; a user holding no native token was
     *      therefore left with no on-chain way to withdraw authorization from a censoring operator.
     *      This closes that, and it is the only cancellation primitive that should appear on a
     *      paymaster allowlist.
     *
     *      MONOTONIC ONLY. Lowering the floor would resurrect orders the account already killed, so
     *      a non-increasing write reverts rather than no-ops: a stale or replayed invalidation
     *      transaction landing late must never be able to undo a later one.
     *
     *      NOT PAUSE-GATED, deliberately, for the same reason withdrawals are not: pause must never
     *      remove a user's ability to revoke their own authorizations.
     *
     *      OFF-CHAIN REQUIREMENT: this is only a usable kill switch if the order server issues
     *      per-account nonces that are non-decreasing over time. The contract does not and cannot
     *      enforce that — `Order.nonce` is just a signed field it compares — so an order source
     *      that mints random nonces makes the floor meaningless (a "cancelled" random nonce may
     *      land above any floor the user sets).
     * @param newMinNonce New floor. Orders with `nonce < newMinNonce` become unsettleable forever.
     */
    function invalidateOrdersBelow(uint256 newMinNonce) external {
        if (newMinNonce <= minOrderNonce[msg.sender]) revert MinOrderNonceNotIncreasing();
        minOrderNonce[msg.sender] = newMinNonce;
        emit OrdersInvalidatedBelow(msg.sender, newMinNonce);
    }

    // ============ Session Keys ============

    /**
     * @notice Register a session key for msg.sender (self-service), atomically setting its
     *         per-asset spend caps in the same transaction.
     * @dev Caps are still fail-closed: an empty `tokens`/`caps` pair (or an omitted asset) leaves
     *      that asset's cap at its default of 0. But unlike the old two-call flow — register, then
     *      a SEPARATE `setSessionKeyCap` per asset — a caller that wants a usable key now does it
     *      in one transaction, structurally ruling out the "registered but every trade fails
     *      because the cap tx hasn't landed yet" state a two-tx flow could leave a frontend in.
     *      `setSessionKeyCap` remains available afterward for adjusting an already-registered key's
     *      budget without touching `validUntil`.
     * @param sessionKey Address whose ECDSA signatures may authorize orders for msg.sender.
     * @param validUntil Unix timestamp (must be in the future) until which the key is valid. There
     *        is no upper bound — `type(uint256).max` registers a key that never expires. See the
     *        note above `sessionKeyValidUntil` for why the old 7-day ceiling was removed and what
     *        bounds a leaked key instead.
     * @param tokens Assets to budget in the same call as registration (parallel to `caps`).
     * @param caps Per-window spend cap for each `tokens[i]`, same semantics as `setSessionKeyCap`.
     * @param orderCaps Per-order ceiling for each `tokens[i]`, same semantics as `setSessionKeyCap`.
     */
    function registerSessionKey(
        address sessionKey,
        uint256 validUntil,
        address[] calldata tokens,
        uint256[] calldata caps,
        uint256[] calldata orderCaps
    ) external {
        if (sessionKey == address(0)) revert ZeroAddress();
        if (validUntil <= block.timestamp) revert SessionKeyNotAuthorized();
        if (tokens.length != caps.length || tokens.length != orderCaps.length) revert ArrayLengthMismatch();
        _assertNoDuplicateTokens(tokens);
        _assertKeyAllowed(sessionKey);
        sessionKeyValidUntil[msg.sender][sessionKey] = validUntil;
        // Bump on every (re-)registration, not just on revoke, so a token omitted from this call
        // reverts to its fail-closed default of 0 instead of keeping a stale cap.
        ++sessionKeyGeneration[msg.sender][sessionKey];

        for (uint256 i = 0; i < tokens.length; ) {
            _writeSessionKeyCaps(msg.sender, sessionKey, tokens[i], caps[i], orderCaps[i]);
            unchecked {
                ++i;
            }
        }

        emit SessionKeyRegistered(msg.sender, sessionKey, validUntil);

        uint256 newNonce = _bumpSessionKeyRegNonce(msg.sender);
        emit SessionKeyAuthsInvalidated(msg.sender, newNonce);
    }

    /**
     * @notice Set how much of `token` a session key may spend on msg.sender's behalf — per window
     *         and per single order.
     * @dev msg.sender-scoped: only the account itself can widen (or zero out) its own key's budget.
     *      Both caps are set together because a key needs both to trade, and setting them in
     *      separate transactions leaves a window where one is stale.
     *
     *      Takes effect immediately, including for the CURRENT window: lowering `cap` below what
     *      this window already consumed leaves the key at 0 remaining until the next window rather
     *      than reverting anything, matching `setDailyWithdrawalLimit`.
     * @param sessionKey Session key being budgeted.
     * @param token Asset the budget applies to — the asset actually DEBITED on the relevant leg
     *        (quote for a buy, base for a sell).
     * @param cap Maximum this key may move of `token` per SESSION_KEY_WINDOW. 0 disables the asset.
     * @param orderCap Maximum a SINGLE order signed by this key may debit. 0 disables the asset.
     */
    function setSessionKeyCap(address sessionKey, address token, uint256 cap, uint256 orderCap) external {
        if (sessionKey == address(0)) revert ZeroAddress();
        _writeSessionKeyCaps(msg.sender, sessionKey, token, cap, orderCap);
        uint256 newNonce = _bumpSessionKeyRegNonce(msg.sender);
        emit SessionKeyAuthsInvalidated(msg.sender, newNonce);
    }

    /**
     * @dev Shared cap writer for the three entry points that set them (self-service registration,
     *      relayed registration, and the standalone setter) so the uint192 bound below cannot be
     *      enforced in two places and forgotten in the third.
     *
     *      `cap` is bounded to uint192 because `SpendWindow.used` is that wide and `_chargeSessionKey`
     *      downcasts into it after checking against this cap. Without the bound a cap above
     *      type(uint192).max would let `used` wrap and silently reset the budget mid-window.
     *      `orderCap` needs no such bound — it is only ever compared, never stored narrowed.
     */
    function _writeSessionKeyCaps(
        address account,
        address sessionKey,
        address token,
        uint256 cap,
        uint256 orderCap
    ) internal {
        if (token == address(0)) revert ZeroAddress();
        if (cap > type(uint192).max) revert InvalidSessionKeyCap();
        sessionKeySpendCap[account][sessionKey][token] = cap;
        sessionKeyOrderCap[account][sessionKey][token] = orderCap;
        sessionKeyCapGeneration[account][sessionKey][token] = sessionKeyGeneration[account][sessionKey];
        emit SessionKeyCapUpdated(account, sessionKey, token, cap, orderCap);
    }

    function _assertNoDuplicateTokens(address[] calldata tokens) internal pure {
        uint256 n = tokens.length;
        for (uint256 i = 0; i < n; ) {
            for (uint256 j = i + 1; j < n; ) {
                if (tokens[i] == tokens[j]) revert DuplicateSessionKeyToken(tokens[i]);
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Register a session key on behalf of `a.account` via that account's EIP-712 signature.
     * @dev Relayer-friendly. Replay-protected by a per-account monotonic registration nonce, and
     *      bounded in wall-clock time by `a.deadline`: without it a signed-but-unsubmitted
     *      authorization stays live indefinitely and can resurrect a key the user believed revoked.
     *      Registers the per-asset caps atomically so a relayed registration is never a cap-less
     *      one — but note the caps are still fail-closed, so an auth carrying empty arrays yields a
     *      key that can move nothing.
     * @param a Session-key authorization payload.
     * @param sig `a.account`'s signature over the SessionKeyAuth digest (EOA or ERC-1271).
     */
    function registerSessionKeyWithSig(SessionKeyAuth calldata a, bytes calldata sig) external {
        if (a.sessionKey == address(0)) revert ZeroAddress();
        if (a.validUntil <= block.timestamp) revert SessionKeyNotAuthorized();
        if (block.timestamp > a.deadline) revert SignatureExpired();
        if (a.tokens.length != a.caps.length || a.tokens.length != a.orderCaps.length) revert ArrayLengthMismatch();
        if (a.nonce != sessionKeyRegNonce[a.account]) revert InvalidRegistrationNonce();
        if (!SignatureChecker.isValidSignatureNow(a.account, _hashSessionKeyAuth(a), sig)) revert InvalidSignature();
        _assertNoDuplicateTokens(a.tokens);
        _assertKeyAllowed(a.sessionKey);

        sessionKeyRegNonce[a.account]++;
        sessionKeyValidUntil[a.account][a.sessionKey] = a.validUntil;
        // See the matching comment in registerSessionKey.
        ++sessionKeyGeneration[a.account][a.sessionKey];

        for (uint256 i = 0; i < a.tokens.length; ) {
            _writeSessionKeyCaps(a.account, a.sessionKey, a.tokens[i], a.caps[i], a.orderCaps[i]);
            unchecked {
                ++i;
            }
        }

        emit SessionKeyRegistered(a.account, a.sessionKey, a.validUntil);
    }

    /**
     * @notice Revoke a session key for msg.sender. NEVER pausable — always available.
     * @dev This ALSO bumps the account's registration nonce, invalidating every unsubmitted
     *      SessionKeyAuth. Without that, revoking is not final — a relayer (or the key holder)
     *      holding an older signed authorization simply re-submits it and the key comes back. The
     *      cost is that an in-flight legitimate registration is invalidated too and must be
     *      re-signed; that is a small liveness price for making "revoke" actually mean revoke.
     *      Note `sessionKeySpendWindows` is deliberately NOT cleared: a key re-registered inside the
     *      same window resumes with that window's budget already consumed, so revoke-and-reregister
     *      is not a way to refill early. It does refill at the next boundary like any other window.
     * @param sessionKey Key to revoke.
     */
    function revokeSessionKey(address sessionKey) external {
        sessionKeyValidUntil[msg.sender][sessionKey] = 0;
        ++sessionKeyGeneration[msg.sender][sessionKey];
        uint256 newNonce = _bumpSessionKeyRegNonce(msg.sender);
        emit SessionKeyRevoked(msg.sender, sessionKey);
        emit SessionKeyAuthsInvalidated(msg.sender, newNonce);
    }

    /**
     * @notice Invalidate every SessionKeyAuth msg.sender has signed but not yet had submitted.
     * @dev Kill switch: one transaction, no per-key enumeration, never pausable. Does not
     *      touch already-registered keys (use revokeSessionKey for those).
     */
    function invalidateSessionKeyAuths() external {
        uint256 newNonce = _bumpSessionKeyRegNonce(msg.sender);
        emit SessionKeyAuthsInvalidated(msg.sender, newNonce);
    }

    function _bumpSessionKeyRegNonce(address account) internal returns (uint256 newNonce) {
        newNonce = uint256(
            keccak256(abi.encodePacked(account, block.timestamp, block.prevrandao, sessionKeyRegNonce[account]))
        );
        sessionKeyRegNonce[account] = newNonce;
    }

    function effectiveSessionKeySpendCap(address account, address sessionKey, address token)
        public
        view
        returns (uint256)
    {
        if (sessionKeyCapGeneration[account][sessionKey][token] != sessionKeyGeneration[account][sessionKey]) {
            return 0;
        }
        return sessionKeySpendCap[account][sessionKey][token];
    }

    function effectiveSessionKeyOrderCap(address account, address sessionKey, address token)
        public
        view
        returns (uint256)
    {
        if (sessionKeyCapGeneration[account][sessionKey][token] != sessionKeyGeneration[account][sessionKey]) {
            return 0;
        }
        return sessionKeyOrderCap[account][sessionKey][token];
    }

    // ============ Internal Functions ============

    /**
     * @dev Authorize an order's signature. Path A: SignatureChecker (EOA ecrecover OR ERC-1271).
     *      Path B: a registered, unexpired session key (malleability-safe via ECDSA.tryRecover).
     *      Reverts InvalidSignature if neither path validates.
     * @return sessionKey The session key that authorized the order, or address(0) when the account
     *         signed directly (Path A). The caller uses this to charge the per-key spend cap; a
     *         zero return means "no cap applies", which is correct because the account's own
     *         signature is unbounded by construction.
     */
    function _authorizeOrderSig(Order calldata order, bytes calldata sig) internal view returns (address sessionKey) {
        bytes32 orderHash = _hashOrder(order);

        // Path A: EOA (ecrecover) OR ERC-1271 contract wallet.
        // Path B: registered session key. tryRecover rejects high-s malleability + bad length.
        (address rec, ECDSA.RecoverError err, ) = ECDSA.tryRecover(orderHash, sig);
        if (err == ECDSA.RecoverError.NoError && rec != address(0)) {
            uint256 vu = sessionKeyValidUntil[order.account][rec];
            if (vu != 0 && block.timestamp <= vu) {
                // Re-check the privileged sets AT USE TIME, not just at registration. The
                // operator set is mutable (queueOperatorChange -> executeOperatorChange), so a key
                // that was legitimate when registered can later be promoted to operator — at which
                // point one address would both sign the order legs and submit the settlement,
                // reconstituting exactly the unilateral power the signed-order design removes. A
                // registration-time-only check leaves that path open for every already-registered
                // key.
                _assertKeyAllowed(rec);
                return rec;
            }
        }

        if (_isValidSignatureNowStipended(order.account, orderHash, sig)) return address(0);

        revert InvalidSignature();
    }

    /**
     * @dev SSA-17. Drop-in for `SignatureChecker.isValidSignatureNow`, used only by
     *      `_authorizeOrderSig`: identical for an EOA `signer`, but a contract `signer`'s ERC-1271
     *      `isValidSignature` is called through `_isValidERC1271SignatureStipended` with a bounded
     *      gas stipend instead of `SignatureChecker`'s unbounded forward.
     * @param signer The order account being authorized.
     * @param hash The order digest.
     * @param signature The signature bytes to verify against `signer`.
     */
    function _isValidSignatureNowStipended(address signer, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool)
    {
        if (signer.code.length == 0) {
            (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(hash, signature);
            return err == ECDSA.RecoverError.NoError && recovered == signer;
        }
        return _isValidERC1271SignatureStipended(signer, hash, signature);
    }

    /**
     * @dev SSA-17: an ERC-1271 `isValidSignature` staticcall bounded to `ERC1271_GAS_STIPEND`, so
     *      an attacker-controlled wallet cannot burn one item's `ITEM_GAS_BUDGET` and starve the
     *      rest of the batch.
     * @param account An address already confirmed to have code (see `_isValidSignatureNowStipended`).
     * @return isValid True iff `account` returned the ERC-1271 magic value within the stipend.
     */
    function _isValidERC1271SignatureStipended(address account, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool isValid)
    {
        if (account.code.length == 0) return false;

        // EIP-150: a sub-call only ever receives floor(gas, 63/64) of what THIS frame currently
        // holds. If this frame doesn't hold enough to guarantee the callee sees the FULL stipend,
        // fail loudly here (non-empty revert data) rather than silently forwarding less than
        // intended and risking a starved callee being misread as "invalid".
        uint256 g = gasleft();
        if (g - g / 64 < ERC1271_GAS_STIPEND) revert InsufficientGasForSigCheck();

        (bool ok, bytes memory ret) = account.staticcall{gas: ERC1271_GAS_STIPEND}(
            abi.encodeCall(IERC1271.isValidSignature, (hash, signature))
        );

        // F5: OZ SignatureChecker-identical strictness — full 32-byte compare of returndata.
        if (ok && ret.length >= 32 && abi.decode(ret, (bytes32)) == bytes32(IERC1271.isValidSignature.selector)) {
            return true;
        }
        if (!ok && ret.length == 0) revert Erc1271VerificationStarved();
        return false;
    }

    /**
     * @dev Reject any address that already holds settlement-side power. Applied at
     *      registration AND at use (see _authorizeOrderSig).
     */
    function _assertKeyAllowed(address key) internal view {
        if (operators[key] || key == feeRecipient || key == owner()) revert ForbiddenSessionKey();
    }

    /**
     * @dev Charge one fill against a session key's per-asset budget. No-op when `sessionKey`
     *      is address(0) (the account signed the order itself).
     *
     *      `token` MUST be the asset actually debited on this leg — quote for the buy side, base
     *      for the sell side. Fail-closed: the default cap of 0 rejects any nonzero amount.
     *      Effects-only (no external call), invoked after every fill check and before any balance
     *      mutation, and charged per FILL so partial fills consume exactly what they moved.
     *
     *      The budget refills every SESSION_KEY_WINDOW. Same fixed-window derivation (and the same
     *      documented boundary artifact — up to 2x the cap across two adjacent blocks) as
     *      `_consumeWithdrawalAllowance`; size the cap as "2x this is survivable".
     *
     *      Unlike the withdrawal limit, a cap of 0 here is NOT "unrestricted" — it is "this key may
     *      not move this asset". Session keys are fail-closed by construction and that must not
     *      invert just because the counter learned to reset.
     */
    function _chargeSessionKey(address account, address sessionKey, address token, uint256 amount) internal {
        if (sessionKey == address(0)) return;

        uint256 cap = effectiveSessionKeySpendCap(account, sessionKey, token);
        SpendWindow memory w = sessionKeySpendWindows[account][sessionKey][token];
        uint64 currentWindow = uint64(block.timestamp / SESSION_KEY_WINDOW);
        // A stale window id means the budget already refilled; deriving it from the clock is what
        // makes that true without a write.
        uint256 used = w.windowId == currentWindow ? w.used : 0;
        uint256 newUsed = used + amount;

        if (newUsed > cap) {
            // Saturating: `used` can exceed `cap` after a mid-window cap reduction by the account.
            uint256 remaining = cap > used ? cap - used : 0;
            revert SessionKeyCapExceeded(token, remaining, (uint256(currentWindow) + 1) * SESSION_KEY_WINDOW);
        }

        // One SSTORE — both fields share a slot. The downcast is safe: `newUsed <= cap` was just
        // enforced and every setter caps `cap` at type(uint192).max.
        sessionKeySpendWindows[account][sessionKey][token] = SpendWindow(currentWindow, uint192(newUsed));
    }

    /**
     * @dev Enforce the per-ORDER ceiling for a session-key-authorized leg. No-op when the account
     *      signed the order itself — an account's own signature is unbounded by construction.
     *
     *      Bounds the order's MAXIMUM possible debit, not this fill's: `quoteAmount` plus the
     *      largest fee the order itself permits on the buy side, `baseAmount` on the sell side (the
     *      seller's fee comes out of proceeds, so it never debits base). Checking the maximum once
     *      is equivalent to metering every fill — see `sessionKeyOrderCap` for why the sum of an
     *      order's fills cannot exceed it — and costs one SLOAD per order rather than a slot.
     *
     *      This is what makes the per-window cap a real bound on a leaked key rather than a
     *      formality: without it a stolen key spends the entire window budget in one order, and the
     *      only remaining question is how fast the user revokes.
     */
    function _assertOrderWithinKeyCap(Order calldata order, address sessionKey) internal view {
        if (sessionKey == address(0)) return;

        address token;
        uint256 maxDebit;
        if (order.isBuy) {
            token = order.quoteToken;
            maxDebit =
                order.quoteAmount +
                Math.mulDiv(order.quoteAmount, Math.min(MAX_FEE_RATE, order.maxFeeRate), BASIS_POINTS);
        } else {
            token = order.baseToken;
            maxDebit = order.baseAmount;
        }

        uint256 orderCap = effectiveSessionKeyOrderCap(order.account, sessionKey, token);
        if (maxDebit > orderCap) revert SessionKeyOrderCapExceeded(token, maxDebit, orderCap);
    }

    /**
     * @dev EIP-712 typed-data hash for an Order.
     */
    function _hashOrder(Order calldata order) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    // Argument order MUST match ORDER_TYPEHASH's typestring byte-for-byte.
                    abi.encode(
                        ORDER_TYPEHASH,
                        order.account,
                        order.baseToken,
                        order.quoteToken,
                        order.isBuy,
                        order.baseAmount,
                        order.quoteAmount,
                        order.maxFeeRate,
                        order.nonce,
                        order.expiry
                    )
                )
            );
    }

    /**
     * @dev EIP-712 typed-data hash for a SessionKeyAuth payload.
     *
     *      Dynamic arrays hash as `keccak256` of their TIGHTLY PACKED encoded elements — that is
     *      EIP-712's rule for `address[]`/`uint256[]`, and it is what viem/ethers `signTypedData`
     *      produce. Using `abi.encode` here instead would splice in ABI offset/length words, so
     *      every server-side signature would recover to a different address and revert.
     */
    function _hashSessionKeyAuth(SessionKeyAuth calldata auth) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    // Argument order MUST match SESSION_KEY_TYPEHASH's typestring byte-for-byte.
                    abi.encode(
                        SESSION_KEY_TYPEHASH,
                        auth.account,
                        auth.sessionKey,
                        auth.validUntil,
                        auth.deadline,
                        keccak256(abi.encodePacked(auth.tokens)),
                        keccak256(abi.encodePacked(auth.caps)),
                        keccak256(abi.encodePacked(auth.orderCaps)),
                        auth.nonce
                    )
                )
            );
    }

    /// @dev Shared predicate so withdrawUsdt/withdrawToken (revert WithdrawalTooEarly) and
    ///      batchWithdraw (revert WithdrawalTooEarlyForToken(token)) evaluate the identical
    ///      per-(user,token) delay without duplicating the comparison.
    function _withdrawalDelayNotElapsed(address _user, address _token) internal view returns (bool) {
        return withdrawalDelay > 0 && block.timestamp < lastDepositTime[_user][_token] + withdrawalDelay;
    }

    function _checkWithdrawalDelay(address _user, address _token) internal view {
        if (_withdrawalDelayNotElapsed(_user, _token)) revert WithdrawalTooEarly();
    }

    /**
     * @dev Meter one withdrawal of `_amount` of `_token` by `_user` against that asset's
     *      per-window rate limit, and record it. No-op (single cold SLOAD) when the asset has no
     *      limit configured, which is the default for every asset.
     *
     *      IT IS A SPEED LIMIT, NEVER A CONFISCATION — the four questions, answered:
     *
     *      1. WHEN EXACTLY DOES A THROTTLED USER GET THE REST OUT?
     *         At `resetAt = (block.timestamp / WITHDRAWAL_WINDOW + 1) * WITHDRAWAL_WINDOW` — an
     *         absolute unix timestamp, derived from the chain clock alone, returned by both this
     *         function's revert and the `remainingWithdrawalAllowance` view. At that instant the
     *         window id changes, `used` is treated as 0 (no transaction, no owner action and no
     *         cooperation from anyone is required to make that happen), and a full `limit` is
     *         available again. A balance B therefore fully exits within `ceil(B / limit)` windows,
     *         and `limit` is floored by a constant, so that count is bounded and computable in
     *         advance. There is no state this contract can enter in which a credited balance stops
     *         being withdrawable — only one in which it takes more days.
     *
     *      2. CAN THE OWNER LOWER THE LIMIT TO CAGE A USER? No, on four independent counts:
     *         (a) a total freeze is not expressible — 0 means UNLIMITED, so the obvious hostile
     *             input is the loosening direction;
     *         (b) every nonzero limit is floored at MIN_WITHDRAWAL_LIMIT_UNITS whole units by a
     *             CONSTANT, so minimum throughput is not an owner parameter (same sealing pattern
     *             as `setQuoteLimits`, which cannot raise a max past MAX_TRADE_UNITS);
     *         (c) WITHDRAWAL_WINDOW is a constant too, closing the alternative attack of leaving
     *             the limit alone and stretching the window until the RATE is negligible;
     *         (d) lowering the limit mid-window can only stop FURTHER withdrawals in the window it
     *             lands in; it never claws back or invalidates what already left, and the
     *             `remaining` computation below saturates at 0 instead of reverting on the
     *             `used > limit` state such a change creates.
     *         What the owner CAN still do is slow a large holder to the floor rate. That is a real
     *         residual power and the reason the floor is a constant with a written derivation
     *         rather than a tunable.
     *
     *      3. IS `emergencyWithdrawFor` SUBJECT TO THIS? NO — deliberately, and it must stay that
     *         way. It is the owner backstop that force-exits a user's ENTIRE balance to that user's
     *         own address, and it is what guarantees the rate limit can never compose with an
     *         operational emergency into a trap: whatever the limits say, there is always a
     *         standing path that returns 100% of a balance in one transaction. Metering it would
     *         subordinate the backstop to the very control it backstops. It grants an attacker
     *         nothing either — the recipient is hardcoded to the debited account, so "bypassing"
     *         the limit with it only hands the funds to their owner.
     *
     *      4. IS IT BYPASSED BY SPLITTING ACROSS ACCOUNTS? YES, TRIVIALLY. The counter is keyed by
     *         (user, token), so N accounts get N times the throughput and account creation is free.
     *         State plainly what this control therefore does and does not do:
     *           - IT DOES bound the blast radius and the SPEED of a single compromised account:
     *             one leaked EOA, one leaked session key or one phished signature cannot be turned
     *             into an instant, one-transaction emptying of that account.
     *           - IT DOES NOT bound total protocol outflow. An attacker who has already spread
     *             value across many accounts withdraws from all of them in parallel at full rate.
     *             What actually bounds THAT is upstream and unchanged: every debit in
     *             `settleOrders` requires the debited account's own signature, and session keys are
     *             additionally metered by `sessionKeySpendCap`. This is a detection window on top
     *             of that, not a substitute for it.
     *         A GLOBAL per-token cap would close the split, and is rejected: a shared budget makes
     *         one whale's legitimate exit deny every other user's, converting a compromise of
     *         nobody into a denial-of-exit for everybody, and hands the owner a single switch that
     *         throttles all holders at once — the re-custody power (a) through (c) exist to remove.
     */
    function _consumeWithdrawalAllowance(address _user, address _token, uint256 _amount) internal {
        uint256 limit = dailyWithdrawalLimit[_token];
        if (limit == 0) return; // Not configured: this asset is unrestricted.

        SpendWindow memory w = withdrawalWindows[_user][_token];
        uint64 currentWindow = uint64(block.timestamp / WITHDRAWAL_WINDOW);
        // A stale window id means the allowance already refilled; no write was needed to make that
        // true, which is the whole point of deriving the window from the clock.
        uint256 used = w.windowId == currentWindow ? w.used : 0;
        uint256 newUsed = used + _amount;

        if (newUsed > limit) {
            // Saturating: `used` can exceed `limit` after a mid-window limit reduction (see (d)).
            uint256 remaining = limit > used ? limit - used : 0;
            uint256 resetAt = (uint256(currentWindow) + 1) * WITHDRAWAL_WINDOW;
            revert WithdrawalLimitExceeded(_token, _amount, remaining, resetAt);
        }

        // Single whole-struct store: both fields share one slot, so this is exactly one SSTORE.
        // The downcast is safe — `newUsed <= limit` was just enforced and the setter caps every
        // enabled limit at type(uint192).max.
        withdrawalWindows[_user][_token] = SpendWindow(currentWindow, uint192(newUsed));
    }

    /**
     * @dev Read a quote asset's decimals, fail-closed. Any failure — no such function, a revert,
     *      or a return value that does not decode as uint8 — reverts QuoteDecimalsUnavailable
     *      rather than assuming a default.
     */
    function _readQuoteDecimals(address _token) private view returns (uint8) {
        try IERC20Metadata(_token).decimals() returns (uint8 d) {
            return d;
        } catch {
            revert QuoteDecimalsUnavailable();
        }
    }

    // ============ View Functions ============

    /**
     * @notice Get user balance for a token
     */
    function getBalance(address _user, address _token) external view returns (uint256) {
        return balances[_user][_token];
    }

    /**
     * @notice How much more of `_token` `_user` may withdraw in the current window, and when
     *         that allowance next refills.
     * @dev The frontend contract for a throttled withdrawal: on `WithdrawalLimitExceeded` a client
     *      reads this to offer "withdraw `remaining` now" and to show the exact refill time. When
     *      the asset has no limit configured, `remaining` is type(uint256).max (unrestricted).
     * @param _user Account to query.
     * @param _token Asset to query.
     * @return remaining Withdrawable amount left in this window (capped by the caller's balance
     *         separately — this is the RATE budget, not a balance).
     * @return resetAt Unix timestamp at which `remaining` returns to the full limit. 0 when
     *         unrestricted.
     */
    function remainingWithdrawalAllowance(
        address _user,
        address _token
    ) external view returns (uint256 remaining, uint256 resetAt) {
        uint256 limit = dailyWithdrawalLimit[_token];
        if (limit == 0) return (type(uint256).max, 0);

        uint64 currentWindow = uint64(block.timestamp / WITHDRAWAL_WINDOW);
        SpendWindow memory w = withdrawalWindows[_user][_token];
        uint256 used = w.windowId == currentWindow ? w.used : 0;
        remaining = limit > used ? limit - used : 0;
        resetAt = (uint256(currentWindow) + 1) * WITHDRAWAL_WINDOW;
    }

    /**
     * @notice Contract version
     * @return Version number
     */
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

    // Immediate setOperator is intentionally removed. Operators change only via
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
     * @notice Set supported (base-asset) token status.
     * @dev Callable by the owner OR the narrow `lister` role. Without this, TokenFactory's
     *      auto-list call always failed (the factory is not the owner) and NO token could ever be
     *      listed, which hard-blocks both `depositToken` and `settleOrders`.
     *
     *      The signature is FROZEN at `setSupportedToken(address,bool)` — `TokenFactory`'s
     *      `ITradeSettlement` calls exactly this selector, and the factory cannot be redeployed in
     *      lockstep. Changing it re-breaks auto-listing.
     *
     *      Granting listing rights this way, rather than making the factory the owner, is
     *      deliberate: ownership would also hand it `emergencyWithdrawFor`, `recoverStuckTokens`
     *      and upgrade authority.
     */
    function setSupportedToken(address _token, bool _status) external validAddress(_token) {
        if (msg.sender != owner() && msg.sender != lister) revert NotAuthorizedLister();
        supportedTokens[_token] = _status;
        emit TokenSupported(_token, _status);
    }

    /**
     * @notice Set the address authorized to auto-list base tokens (typically TokenFactory).
     * @dev The role's ONLY power is setSupportedToken. address(0) disables it (owner-only listing).
     */
    function setLister(address _lister) external onlyOwner {
        address oldLister = lister;
        lister = _lister;
        emit ListerUpdated(oldLister, _lister);
    }

    /**
     * @notice List or delist a quote (payment) asset.
     * @dev On the FIRST listing of an asset the decimals are read from IERC20Metadata and cached,
     *      and min/max are derived from them (min = 0.01 quote, max = MAX_TRADE_UNITS quote).
     *      Reading decimals is fail-closed: an asset that does not expose them is not listable,
     *      because falling back to 18 would silently reinstate exactly the decimals assumption
     *      this registry removes. Delisting only clears `listed` — cached decimals and any
     *      owner-tuned limits survive, so relisting does not silently reset them. Delisting also
     *      never affects withdrawals: `withdrawToken`/`batchWithdraw` consult no registry.
     * @param _token Quote asset address.
     * @param _listed New listing status.
     */
    function setQuoteAsset(address _token, bool _listed) external onlyOwner validAddress(_token) {
        QuoteAsset storage q = quoteAssets[_token];

        // decimals == 0 means "never successfully listed": a listed asset always has decimals >= 2.
        if (_listed && q.decimals == 0) {
            uint8 d = _readQuoteDecimals(_token);
            if (d < 2 || d > 30) revert InvalidQuoteDecimals();
            uint256 unit = 10 ** d;
            q.decimals = d;
            q.minTradeAmount = unit / 100;
            q.maxTradeAmount = MAX_TRADE_UNITS * unit;
        }

        q.listed = _listed;
        emit QuoteAssetUpdated(_token, _listed, q.decimals, q.minTradeAmount, q.maxTradeAmount);
    }

    /**
     * @notice Override a listed quote asset's per-trade min/max notional, within hard bounds.
     * @dev The MAXIMUM ceiling is the constant MAX_TRADE_UNITS * 10**decimals, so no owner action
     *      can widen the per-trade defense line against a compromised operator. Raising the
     *      minimum is not a new power (the owner already holds `pause()`), which is why only the
     *      max side is sealed by a constant.
     * @param _token Quote asset (must have been listed at least once).
     * @param _newMin New minimum fill notional. Nonzero and at most 100 whole quote units.
     * @param _newMax New maximum fill notional. At least _newMin and at most the constant ceiling.
     */
    function setQuoteLimits(address _token, uint256 _newMin, uint256 _newMax) external onlyOwner {
        QuoteAsset storage q = quoteAssets[_token];
        if (q.decimals == 0) revert UnsupportedQuote();

        uint256 unit = 10 ** q.decimals;
        // Floor the minimum too. Only sealing the max leaves the owner free to drop the minimum to
        // 1 raw unit, which silently disables the dust-fill guard the minimum exists for.
        if (_newMin == 0 || _newMin < unit / 10_000 || _newMin > unit * 100) revert InvalidQuoteLimits();
        if (_newMax < _newMin || _newMax > MAX_TRADE_UNITS * unit) revert InvalidQuoteLimits();

        q.minTradeAmount = _newMin;
        q.maxTradeAmount = _newMax;
        emit QuoteLimitsUpdated(_token, _newMin, _newMax);
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
     * @notice Set withdrawal delay
     */
    function setWithdrawalDelay(uint256 _delay) external onlyOwner {
        if (_delay > MAX_WITHDRAWAL_DELAY) revert ExcessiveWithdrawalDelay();
        uint256 oldDelay = withdrawalDelay;
        withdrawalDelay = _delay;
        emit WithdrawalDelayUpdated(oldDelay, _delay);
    }

    /**
     * @notice Set (or disable) the per-window withdrawal rate limit for one quote asset.
     * @dev Ships DISABLED for every asset and does not change any behaviour until an owner calls
     *      this — the policy VALUE is a product decision (PRD:Settlement open question), this is
     *      only the mechanism. See `_consumeWithdrawalAllowance` for the full non-custodial
     *      argument; the parts this function is responsible for enforcing are:
     *        - `_limit == 0` disables the limit (unrestricted). Always accepted, so the control can
     *          always be switched back off in one transaction.
     *        - any nonzero `_limit` must be at least MIN_WITHDRAWAL_LIMIT_UNITS whole units of the
     *          asset. This constant floor is what stops the owner from turning a rate limit into a
     *          freeze, and it is the reason this setter needs no timelock: the worst reachable
     *          state is the floor rate, not zero.
     *        - `_limit` must fit in uint192, the width `WithdrawalWindow.used` is packed into.
     *      QUOTE ASSETS ONLY: `_token` must have been listed at least once via `setQuoteAsset`, so
     *      that its decimals are already cached fail-closed and the floor above is meaningful.
     *      Base tokens are intentionally out of scope — see the `dailyWithdrawalLimit` field
     *      comment for why reading their decimals on the exit path is unacceptable.
     *
     *      Lowering (or raising) the limit takes effect immediately for the CURRENT window; it
     *      cannot retroactively invalidate withdrawals that already settled, and a reduction below
     *      what a user already spent this window leaves them at 0 remaining until the next window
     *      rather than reverting anything.
     * @param _token Quote asset to rate-limit (must have been listed at least once).
     * @param _limit Absolute token amount withdrawable per WITHDRAWAL_WINDOW per account. 0 = off.
     */
    function setDailyWithdrawalLimit(address _token, uint256 _limit) external onlyOwner {
        QuoteAsset storage q = quoteAssets[_token];
        if (q.decimals == 0) revert UnsupportedQuote();

        if (_limit != 0) {
            if (_limit < MIN_WITHDRAWAL_LIMIT_UNITS * (10 ** q.decimals)) revert InvalidWithdrawalLimit();
            if (_limit > type(uint192).max) revert InvalidWithdrawalLimit();
        }

        uint256 oldLimit = dailyWithdrawalLimit[_token];
        dailyWithdrawalLimit[_token] = _limit;
        emit WithdrawalLimitUpdated(_token, oldLimit, _limit);
    }

    /**
     * @notice Emergency withdrawal for a user (Owner only).
     * @dev Sole remaining owner-triggered debit path, by design. It is a force-exit-TO-USER —
     *      funds ALWAYS go to `_user` (the debited account), never to the owner or any third
     *      party. It is NOT timelock-bounded (immediate) by design, as the user backstop. It is
     *      the only debit site in this contract that is neither msg.sender-scoped nor authorized
     *      by the debited account's Order signature.
     *
     *      It is also EXEMPT from the per-asset withdrawal rate limit, deliberately. This is
     *      the standing guarantee that the rate limit can never become a cage — whatever any limit
     *      is set to, a full balance can always be returned to its owner in one transaction. A
     *      metered backstop would be defeated by the control it exists to backstop. The exemption
     *      is not an exfiltration path: `_user` is both the debited account and the hardcoded
     *      recipient, so using it to "skip" the limit only delivers the funds to their owner.
     * @param _user User address (debited AND the transfer recipient).
     * @param _token Token address.
     */
    function emergencyWithdrawFor(
        address _user,
        address _token
    ) external onlyOwner nonReentrant validAddress(_user) validAddress(_token) {
        uint256 amount = balances[_user][_token];
        if (amount == 0) revert ZeroAmount();

        balances[_user][_token] = 0;
        totalTracked[_token] -= amount;
        IERC20(_token).safeTransfer(_user, amount);

        emit EmergencyWithdraw(_user, _token, amount);
    }

    /**
     * @notice Stage a stuck-token recovery; executable in
     *         `[recoverReadyAt, recoverReadyAt + RECOVER_GRACE_PERIOD]`.
     * @dev The excess this sweeps is not always dust: under a rebasing or reward-bearing token the
     *      surplus above `totalTracked` IS the depositors' accrued yield, and an immediate
     *      recoverStuckTokens let the owner move it to an arbitrary address in one unannounced
     *      transaction. Staging publishes (token, to, amount) 48h ahead of execution.
     *
     *      WHAT THAT NOTICE IS AND IS NOT. It is a 48h
     *      warning that a sweep of up to `_amount` of `_token` is armed. It is NOT a guarantee
     *      that users are warned 48h before their own funds become sweepable, because the excess
     *      is measured at EXECUTION, not at staging: before the grace period existed, a staging
     *      made when the excess was 0 stayed armed indefinitely and could be fired in the very
     *      block a later rebase or donation created excess — at which point no fresh notice had
     *      gone out at all. `RECOVER_GRACE_PERIOD` bounds that: a staging dies 7 days after it
     *      matures, so a sweep can only reach excess that exists within ~9 days of its
     *      announcement, and anything later requires a new, publicly observable requestRecover.
     *      Within the live window the exit is real — withdrawToken/batchWithdraw are not
     *      pause-gated, so users cannot be locked in behind them.
     *
     *      Staging is single-slot: a second requestRecover overwrites the first (and restarts the
     *      clock) rather than queueing, so there is never more than one armed sweep. It is also
     *      dropped if ownership changes hands.
     * @param _token Token to recover.
     * @param _to Recipient. Must match EXACTLY at execution.
     * @param _amount Amount to recover. Must match EXACTLY at execution.
     */
    function requestRecover(
        address _token,
        address _to,
        uint256 _amount
    ) external onlyOwner validAddress(_token) validAddress(_to) validAmount(_amount) {
        pendingRecoverHash = keccak256(abi.encode(_token, _to, _amount));
        recoverReadyAt = block.timestamp + RECOVER_TIMELOCK_DELAY;
        emit RecoverRequested(_token, _to, _amount, recoverReadyAt);
    }

    /**
     * @notice Cancel the staged stuck-token recovery.
     */
    function cancelRecover() external onlyOwner {
        bytes32 staged = pendingRecoverHash;
        if (staged == bytes32(0)) revert NoPendingRecover();
        pendingRecoverHash = bytes32(0);
        recoverReadyAt = 0;
        emit RecoverCancelled(staged);
    }

    /**
     * @notice Recover tokens stuck in this contract that are NOT owed to any user (emergency only).
     * @dev Requires a matured, UNEXPIRED `requestRecover(_token, _to, _amount)` staged with
     *      byte-identical arguments, and consumes it (single-use — a second sweep needs a second
     *      48h wait). "Unexpired" means within RECOVER_GRACE_PERIOD of maturity; a staging
     *      that sat unused past that is dead and cannot be repurposed against excess that showed
     *      up later.
     *
     *      Keyed on the real token balance + the tracked liability, never on mutable flags
     *      (e.g. `supportedTokens[_token]` / `quoteAssets[_token].listed`) — so recovery is immune
     *      to any owner registry game. Only the excess balance above totalTracked
     *      (e.g. accidental direct transfers, dust, rebase surplus) is recoverable; user-owed funds
     *      are untouchable. The excess is (re)computed HERE, at execution, not at staging: the
     *      staged amount is a ceiling the owner committed to publicly, and it still has to clear
     *      the live solvency check.
     *
     *      The `bal <= tracked` case is checked EXPLICITLY rather than left to the checked
     *      subtraction. A shortfall is exactly what a fee-on-transfer deposit produces, and the
     *      bare subtraction reverted with panic 0x11 — an undiagnosable, permanent failure that
     *      looks identical to a compiler bug. `NothingToRecover` names the condition instead.
     */
    function recoverStuckTokens(
        address _token,
        address _to,
        uint256 _amount
    ) external onlyOwner nonReentrant validAddress(_token) validAddress(_to) validAmount(_amount) {
        if (pendingRecoverHash == bytes32(0)) revert NoPendingRecover();
        if (pendingRecoverHash != keccak256(abi.encode(_token, _to, _amount))) {
            revert RecoverParamsMismatch();
        }
        if (block.timestamp < recoverReadyAt) revert RecoverNotReady();
        if (block.timestamp > recoverReadyAt + RECOVER_GRACE_PERIOD) revert RecoverExpired();

        // Consume the staging BEFORE the transfer (CEI): single-use, and never re-entrant-replayable.
        pendingRecoverHash = bytes32(0);
        recoverReadyAt = 0;

        uint256 bal = IERC20(_token).balanceOf(address(this));
        uint256 tracked = totalTracked[_token];
        if (bal <= tracked) revert NothingToRecover();
        if (_amount > bal - tracked) revert NothingToRecover();
        IERC20(_token).safeTransfer(_to, _amount);

        emit StuckTokensRecovered(_token, _to, _amount);
    }

    // ============ Timelocked Upgrade ============

    /**
     * @notice Stage a UUPS upgrade to `newImpl`; executable in
     *         `[upgradeReadyAt, upgradeReadyAt + UPGRADE_GRACE_PERIOD]`.
     * @dev The staging expires. It used to stay armed forever once matured, which let an
     *      owner pre-arm an implementation and fire it in a single transaction at an arbitrary
     *      later moment — reducing the timelock to a one-off announcement. Missing the window
     *      costs only a re-stage, and that re-stage is itself the fresh public notice.
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
     * @dev Timelocked upgrade authorizer. The staged implementation must match, the timelock must
     *      have elapsed and the staging must not have expired; the staging is single-use
     *      (cleared here).
     *      NOTE: the migration upgrade itself installs under the PRIOR (non-timelocked)
     *      authorizer — expected. Only subsequent upgrades pass through this gate.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        if (pendingImplementation == address(0)) revert NoPendingUpgrade();
        if (newImplementation != pendingImplementation) revert ImplementationMismatch();
        if (block.timestamp < upgradeReadyAt) revert UpgradeNotReady();
        if (block.timestamp > upgradeReadyAt + UPGRADE_GRACE_PERIOD) revert UpgradeExpired();
        pendingImplementation = address(0);
        upgradeReadyAt = 0;
    }

    /**
     * @dev Ownership handover drops BOTH stagings (upgrade and recovery).
     *
     *      `Ownable2StepUpgradeable.transferOwnership` only nominates; ownership actually moves
     *      here, on `acceptOwnership` (and on `renounceOwnership`). Without this, an armed
     *      implementation or an armed sweep — clocks still running — survived the handover, so an
     *      incoming owner could execute a payload staged by their predecessor, possibly without
     *      knowing it existed. Clearing forces the new owner to re-stage under their own key,
     *      which restarts the 48h notice and re-publishes the parameters.
     *
     *      Emits the ordinary {UpgradeCancelled} / {RecoverCancelled} events so the drop is
     *      observable by the same monitoring that watches explicit cancellations. No-ops for
     *      whichever staging is empty, including during `initialize`.
     */
    function _transferOwnership(address newOwner) internal virtual override {
        if (pendingImplementation != address(0)) {
            emit UpgradeCancelled(pendingImplementation);
            pendingImplementation = address(0);
            upgradeReadyAt = 0;
        }
        bytes32 stagedRecover = pendingRecoverHash;
        if (stagedRecover != bytes32(0)) {
            pendingRecoverHash = bytes32(0);
            recoverReadyAt = 0;
            emit RecoverCancelled(stagedRecover);
        }
        super._transferOwnership(newOwner);
    }
}
