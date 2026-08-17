// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {CommonBase} from "forge-std/Base.sol";
import {StdCheats} from "forge-std/StdCheats.sol";
import {StdUtils} from "forge-std/StdUtils.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {TradeSettlementV1} from "../contracts/trade/TradeSettlementV1.sol";
import {ERC1967Proxy} from "../contracts/ERC1967Proxy.sol";
import {USDT} from "../contracts/USDT.sol";

/**
 * @title TradeSettlementV1 invariant suite — solvency, accounting integrity, conservation.
 *
 * @dev The settlement is the contract that actually holds user funds (16,000 USDT on the live
 *      testnet proxy) and it had zero invariant coverage. An earlier review named
 *      `totalTracked[T] == Σ_user balances[u][T]` as invariant I1 and the source comment at
 *      slot 7 states it as a MUST — but `totalTracked` is `private` with no getter, so no test
 *      in this repo has ever checked it. It is read here through a storage probe, and the probe
 *      itself is verified against a known deposit before anything relies on it.
 *
 *      S1 solvency     — the contract holds at least what it owes. This IS the non-custodial
 *                        claim: if it ever fails, withdrawals become first-come-first-served.
 *      S2 accounting   — `totalTracked` equals the sum of user balances. Drift here is what
 *                        turns `recoverStuckTokens` into a depositor-funds drain.
 *      S3 conservation — Σ balances == Σ deposited − Σ withdrawn. `settleOrders` moves value
 *                        between accounts and must never create or destroy it; fees are a
 *                        transfer to `feeRecipient`, not an emission.
 */
contract SettlementHandler is CommonBase, StdCheats, StdUtils {
    TradeSettlementV1 public immutable settlement;
    USDT public immutable base;
    USDT public immutable quote;
    address public immutable operator;
    address public immutable feeRecipient;

    uint256[3] public actorPks;
    address[3] public actors;

    // ---- ghosts: the conservation ledger ----
    mapping(address => uint256) public ghostDeposited;
    mapping(address => uint256) public ghostWithdrawn;

    uint256 public nonceCounter;

    // ---- ghosts for the audit's feeMonotonic / replayOneShot properties ----
    mapping(address => uint256) public ghostMaxFeeAccrued;
    bytes32[] public consumedSettlementIds;

    uint256 public callsDeposit;
    uint256 public callsWithdraw;
    uint256 public callsSettle;
    uint256 public callsBatchWithdraw;
    uint256 public callsInvalidate;

    constructor(
        TradeSettlementV1 _settlement,
        USDT _base,
        USDT _quote,
        address _operator,
        address _feeRecipient,
        uint256[3] memory _pks
    ) {
        settlement = _settlement;
        base = _base;
        quote = _quote;
        operator = _operator;
        feeRecipient = _feeRecipient;
        actorPks = _pks;
        for (uint256 i = 0; i < 3; i++) {
            actors[i] = vm.addr(_pks[i]);
        }
    }

    function _actorIndex(uint256 seed) internal pure returns (uint256) {
        return seed % 3;
    }

    function _token(uint256 seed) internal view returns (USDT) {
        return seed % 2 == 0 ? base : quote;
    }

    function deposit(uint256 actorSeed, uint256 tokenSeed, uint256 amountSeed) external {
        address actor = actors[_actorIndex(actorSeed)];
        USDT token = _token(tokenSeed);
        uint256 amount = bound(amountSeed, 1e16, 100_000e18);

        // The handler is pre-funded rather than minting: USDT is Ownable2Step, so handing it
        // ownership only sets pendingOwner and every mint here reverted. That made the whole
        // suite land zero successful transitions — caught by the coverage floor on the first run.
        if (token.balanceOf(address(this)) < amount) return;
        token.transfer(actor, amount);
        vm.startPrank(actor);
        token.approve(address(settlement), amount);
        try settlement.depositToken(address(token), amount) {
            callsDeposit++;
            ghostDeposited[address(token)] += amount;
        } catch {}
        vm.stopPrank();
    }

    function withdraw(uint256 actorSeed, uint256 tokenSeed, uint256 amountSeed) external {
        address actor = actors[_actorIndex(actorSeed)];
        USDT token = _token(tokenSeed);
        uint256 held = settlement.balances(actor, address(token));
        if (held == 0) return;
        uint256 amount = bound(amountSeed, 1, held);

        vm.prank(actor);
        try settlement.withdrawToken(address(token), amount) {
            callsWithdraw++;
            ghostWithdrawn[address(token)] += amount;
        } catch {}
    }

    function batchWithdraw(uint256 actorSeed) external {
        address actor = actors[_actorIndex(actorSeed)];
        uint256 heldBase = settlement.balances(actor, address(base));
        uint256 heldQuote = settlement.balances(actor, address(quote));
        if (heldBase == 0 && heldQuote == 0) return;

        address[] memory tokens = new address[](2);
        tokens[0] = address(base);
        tokens[1] = address(quote);

        vm.prank(actor);
        try settlement.batchWithdraw(tokens) {
            callsBatchWithdraw++;
            ghostWithdrawn[address(base)] += heldBase;
            ghostWithdrawn[address(quote)] += heldQuote;
        } catch {}
    }

    function warp(uint256 seed) external {
        vm.warp(block.timestamp + bound(seed, 1 minutes, 12 hours));
    }

    /// @dev The gas-cheap mass cancel. Raising the floor by exactly one keeps already-signed
    ///      low-nonce orders killable without stopping the search from settling later ones.
    function raiseNonceFloor(uint256 actorSeed) external {
        address actor = actors[_actorIndex(actorSeed)];
        uint256 next = settlement.minOrderNonce(actor) + 1;
        vm.prank(actor);
        try settlement.invalidateOrdersBelow(next) {
            callsInvalidate++;
        } catch {}
    }

    /// @dev A real two-sided fill with both legs EIP-712 signed by their accounts. Sized from
    ///      the parties' actual balances so the fuzzer produces settlements that clear rather
    ///      than a stream of insufficient-balance reverts.
    function settle(uint256 buyerSeed, uint256 sellerSeed, uint256 sizeSeed) external {
        uint256 bi = _actorIndex(buyerSeed);
        uint256 si = _actorIndex(sellerSeed);
        if (bi == si) return;

        address buyer = actors[bi];
        address seller = actors[si];

        uint256 buyerQuote = settlement.balances(buyer, address(quote));
        uint256 sellerBase = settlement.balances(seller, address(base));
        if (buyerQuote < 1e17 || sellerBase < 1e17) return;

        uint256 fillQuote = bound(sizeSeed, 1e16, buyerQuote > 1e18 ? 1e18 : buyerQuote);
        uint256 fillBase = fillQuote > sellerBase ? sellerBase : fillQuote;
        if (fillBase == 0) return;

        uint256 fee = fillQuote / 1000; // 0.1%, under the 1% maxFeeRate below

        TradeSettlementV1.Order memory buyOrder = TradeSettlementV1.Order({
            account: buyer,
            baseToken: address(base),
            quoteToken: address(quote),
            isBuy: true,
            baseAmount: fillBase,
            quoteAmount: fillQuote,
            maxFeeRate: 100,
            // Derived from the CURRENT floor, not a global counter. With a counter, the fuzzer's
            // ~90 raiseNonceFloor calls per run outran it and starved settlement to zero on some
            // campaigns — measured, not guessed. Signing above the live floor keeps the search
            // productive; the "floor kills an ALREADY-signed order" case is pinned deterministically.
            nonce: settlement.minOrderNonce(buyer) + 1,
            expiry: block.timestamp + 30 minutes
        });
        TradeSettlementV1.Order memory sellOrder = TradeSettlementV1.Order({
            account: seller,
            baseToken: address(base),
            quoteToken: address(quote),
            isBuy: false,
            baseAmount: fillBase,
            quoteAmount: fillQuote,
            maxFeeRate: 100,
            nonce: settlement.minOrderNonce(seller) + 1,
            expiry: block.timestamp + 30 minutes
        });
        nonceCounter++;

        bytes memory buySig = _sign(actorPks[bi], buyOrder);
        bytes memory sellSig = _sign(actorPks[si], sellOrder);
        bytes32 settlementId = keccak256(abi.encode(nonceCounter, block.timestamp));

        vm.prank(operator);
        try
            settlement.settleOrders(
            TradeSettlementV1.Settlement(buyOrder,
                buySig,
                sellOrder,
                sellSig,
                fillBase,
                fillQuote,
                fee,
                fee,
                settlementId)
        )
        {
            callsSettle++;
            consumedSettlementIds.push(settlementId);
        } catch {}

        _recordFees();
    }

    function _recordFees() internal {
        uint256 f = settlement.feeAccrued(address(quote));
        if (f > ghostMaxFeeAccrued[address(quote)]) ghostMaxFeeAccrued[address(quote)] = f;
        uint256 b = settlement.feeAccrued(address(base));
        if (b > ghostMaxFeeAccrued[address(base)]) ghostMaxFeeAccrued[address(base)] = b;
    }

    function consumedCount() external view returns (uint256) {
        return consumedSettlementIds.length;
    }

    function _sign(
        uint256 pk,
        TradeSettlementV1.Order memory order
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                settlement.ORDER_TYPEHASH(),
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
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparator(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _domainSeparator() internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, , ) = settlement
            .eip712Domain();
        return
            keccak256(
                abi.encode(
                    keccak256(
                        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                    ),
                    keccak256(bytes(name)),
                    keccak256(bytes(version)),
                    chainId,
                    verifying
                )
            );
    }
}

contract TradeSettlementInvariantsTest is StdInvariant, Test {
    /// @dev Declared `private` at slot 7 by the source comment that also states the invariant it
    ///      is supposed to satisfy. Read via storage rather than trusted — see
    ///      `test_totalTrackedProbeIsSound`, which pins this derivation against a real deposit so
    ///      a slot change breaks the probe loudly instead of making the invariant vacuously true.
    uint256 internal constant TOTAL_TRACKED_SLOT = 7;

    TradeSettlementV1 internal settlement;
    USDT internal base;
    USDT internal quote;
    SettlementHandler internal handler;

    address internal feeRecipient = address(0xFEE);
    address internal lister = address(0x115);
    address internal operator = address(0x09E);

    uint256[3] internal pks = [uint256(0xA1), uint256(0xA2), uint256(0xA3)];

    function setUp() public {
        base = new USDT(address(this), 18);
        quote = new USDT(address(this), 18);

        TradeSettlementV1 impl = new TradeSettlementV1();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl),
            abi.encodeCall(TradeSettlementV1.initialize, (feeRecipient, lister))
        );
        settlement = TradeSettlementV1(address(proxy));

        settlement.setSupportedToken(address(base), true);
        settlement.setQuoteAsset(address(quote), true);

        // the operator set starts EMPTY on purpose, so this has to go through the full
        // 24h timelock even in a test. A suite that could not settle would silently cover nothing.
        bytes32 changeId = settlement.queueOperatorChange(operator, true);
        vm.warp(block.timestamp + settlement.OPERATOR_CHANGE_DELAY() + 1);
        settlement.executeOperatorChange(changeId);

        handler = new SettlementHandler(settlement, base, quote, operator, feeRecipient, pks);
        base.mint(address(handler), 10_000_000e18);
        quote.mint(address(handler), 10_000_000e18);

        targetContract(address(handler));
    }

    function _totalTracked(address token) internal view returns (uint256) {
        bytes32 slot = keccak256(abi.encode(token, uint256(TOTAL_TRACKED_SLOT)));
        return uint256(vm.load(address(settlement), slot));
    }

    function _sumBalances(address token) internal view returns (uint256 total) {
        for (uint256 i = 0; i < 3; i++) {
            total += settlement.balances(handler.actors(i), token);
        }
        total += settlement.balances(feeRecipient, token);
    }

    /// @dev Verifies the instrument before any invariant leans on it. If `totalTracked` ever
    ///      moves off slot 7, this fails rather than letting S2 pass by reading zeros forever.
    function test_totalTrackedProbeIsSound() public {
        address user = address(0xD3B0);
        uint256 amount = 12_345e18;
        base.mint(user, amount);

        assertEq(_totalTracked(address(base)), 0, "probe: expected zero before any deposit");

        vm.startPrank(user);
        base.approve(address(settlement), amount);
        settlement.depositToken(address(base), amount);
        vm.stopPrank();

        assertEq(
            _totalTracked(address(base)),
            amount,
            "probe: slot 7 does not hold totalTracked - S2 would be vacuous"
        );
        assertEq(_totalTracked(address(quote)), 0, "probe: wrong token key derivation");
    }

    function afterInvariant() public view {
        // Measured, not assumed — a sample run landed deposit 113 / withdraw 41 / settle 5 /
        // batchWithdraw 48, so settlements do clear under the search. After `raiseNonceFloor` was
        // added, settle counts were re-measured (5 / 2 / 16 / 5 / 3 across campaigns) because the
        // first version of that action starved settlement to zero on some runs.
        //
        // Requiring `callsSettle > 0` HERE was tried and reverted: afterInvariant runs after
        // every run, and an individual run legitimately may never fund two counterparties on
        // opposite sides, so the assertion failed reproducibly on correct code. A coverage
        // floor that cries wolf is worse than none, so the settle path is guaranteed by
        // `test_settlementConservesValue` below instead of by this floor.
        assertGt(
            handler.callsDeposit() +
                handler.callsWithdraw() +
                handler.callsSettle() +
                handler.callsBatchWithdraw(),
            0,
            "vacuous run: handler landed no successful state transition"
        );
    }

    function _signOrder(
        uint256 pk,
        TradeSettlementV1.Order memory order
    ) internal view returns (bytes memory) {
        (, string memory name, string memory version, uint256 chainId, address verifying, , ) = settlement
            .eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                settlement.ORDER_TYPEHASH(),
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
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            pk,
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash))
        );
        return abi.encodePacked(r, s, v);
    }

    /// @dev A real two-sided fill, pinned deterministically. The random search reaches settlement
    ///      on most runs but not every run, so without this the property that matters most for
    ///      S3 — that a settlement moves value without creating it — would be covered by luck.
    function test_settlementConservesValue() public {
        address buyer = vm.addr(pks[0]);
        address seller = vm.addr(pks[1]);
        uint256 quoteDeposit = 1_000e18;
        uint256 baseDeposit = 500e18;

        quote.mint(buyer, quoteDeposit);
        base.mint(seller, baseDeposit);

        vm.startPrank(buyer);
        quote.approve(address(settlement), quoteDeposit);
        settlement.depositToken(address(quote), quoteDeposit);
        vm.stopPrank();

        vm.startPrank(seller);
        base.approve(address(settlement), baseDeposit);
        settlement.depositToken(address(base), baseDeposit);
        vm.stopPrank();

        uint256 fillBase = 100e18;
        uint256 fillQuote = 200e18;
        uint256 fee = fillQuote / 1000;

        TradeSettlementV1.Order memory buyOrder = TradeSettlementV1.Order({
            account: buyer,
            baseToken: address(base),
            quoteToken: address(quote),
            isBuy: true,
            baseAmount: fillBase,
            quoteAmount: fillQuote,
            maxFeeRate: 100,
            nonce: 1,
            expiry: block.timestamp + 30 minutes
        });
        TradeSettlementV1.Order memory sellOrder = TradeSettlementV1.Order({
            account: seller,
            baseToken: address(base),
            quoteToken: address(quote),
            isBuy: false,
            baseAmount: fillBase,
            quoteAmount: fillQuote,
            maxFeeRate: 100,
            nonce: 2,
            expiry: block.timestamp + 30 minutes
        });

        // Signatures FIRST: `_signOrder` reads eip712Domain()/ORDER_TYPEHASH() off the
        // settlement, and evaluating that inside the call arguments consumes the one-shot
        // vm.prank before settleOrders is reached — which surfaces as NotOperator().
        bytes memory buySig = _signOrder(pks[0], buyOrder);
        bytes memory sellSig = _signOrder(pks[1], sellOrder);

        vm.prank(operator);
        settlement.settleOrders(
            TradeSettlementV1.Settlement(buyOrder,
            buySig,
            sellOrder,
            sellSig,
            fillBase,
            fillQuote,
            fee,
            fee,
            keccak256("settlement-1"))
        );

        // The fill actually happened — otherwise every assertion below passes trivially.
        assertEq(settlement.balances(buyer, address(base)), fillBase, "buyer did not receive base");
        assertEq(
            settlement.balances(feeRecipient, address(quote)),
            fee * 2,
            "fee recipient was not credited both legs"
        );
        // S4 is a monotonicity property, so it cannot see a fee that is never accrued at all —
        // assertGe(0, 0) passes. The absolute value is pinned here instead.
        assertEq(settlement.feeAccrued(address(quote)), fee * 2, "feeAccrued was not credited");
        assertTrue(
            settlement.processedSettlements(keccak256("settlement-1")),
            "settlementId was not marked consumed"
        );

        // S3 — value moved, none was created or destroyed, fees included.
        assertEq(_sumBalances(address(base)), baseDeposit, "S3: base total changed on settle");
        assertEq(_sumBalances(address(quote)), quoteDeposit, "S3: quote total changed on settle");

        // S2 — settleOrders deliberately does not touch totalTracked, which is only correct
        //      because the leg set is zero-sum per token. That is the claim being checked.
        assertEq(_totalTracked(address(base)), baseDeposit, "S2: base accumulator drifted");
        assertEq(_totalTracked(address(quote)), quoteDeposit, "S2: quote accumulator drifted");

        // S1 — still solvent for both assets.
        assertGe(base.balanceOf(address(settlement)), _sumBalances(address(base)), "S1: base");
        assertGe(quote.balanceOf(address(settlement)), _sumBalances(address(quote)), "S1: quote");
    }

    // ------------------------------------------------------------------
    // Cancel-vs-settle ordering. Not a contract defect — a semantic the
    // off-chain side now depends on, which nothing here pinned.
    // ------------------------------------------------------------------

    struct Pair {
        TradeSettlementV1.Order buyOrder;
        TradeSettlementV1.Order sellOrder;
        uint256 fillBase;
        uint256 fillQuote;
        uint256 fee;
        address buyer;
        address seller;
    }

    function _matchedPair() internal returns (Pair memory p) {
        p.buyer = vm.addr(pks[0]);
        p.seller = vm.addr(pks[1]);
        quote.mint(p.buyer, 1_000e18);
        base.mint(p.seller, 500e18);

        vm.startPrank(p.buyer);
        quote.approve(address(settlement), 1_000e18);
        settlement.depositToken(address(quote), 1_000e18);
        vm.stopPrank();

        vm.startPrank(p.seller);
        base.approve(address(settlement), 500e18);
        settlement.depositToken(address(base), 500e18);
        vm.stopPrank();

        p.fillBase = 100e18;
        p.fillQuote = 200e18;
        p.fee = p.fillQuote / 1000;

        p.buyOrder = TradeSettlementV1.Order({
            account: p.buyer,
            baseToken: address(base),
            quoteToken: address(quote),
            isBuy: true,
            baseAmount: p.fillBase,
            quoteAmount: p.fillQuote,
            maxFeeRate: 100,
            nonce: 5,
            expiry: block.timestamp + 30 minutes
        });
        p.sellOrder = TradeSettlementV1.Order({
            account: p.seller,
            baseToken: address(base),
            quoteToken: address(quote),
            isBuy: false,
            baseAmount: p.fillBase,
            quoteAmount: p.fillQuote,
            maxFeeRate: 100,
            nonce: 6,
            expiry: block.timestamp + 30 minutes
        });
    }

    function _settle(Pair memory p, bytes32 id) internal {
        bytes memory buySig = _signOrder(pks[0], p.buyOrder);
        bytes memory sellSig = _signOrder(pks[1], p.sellOrder);
        vm.prank(operator);
        settlement.settleOrders(
            TradeSettlementV1.Settlement(p.buyOrder,
            buySig,
            p.sellOrder,
            sellSig,
            p.fillBase,
            p.fillQuote,
            p.fee,
            p.fee,
            id)
        );
    }

    /// @dev A per-hash cancel that lands before the operator's settlement wins, and the settlement
    ///      moves nothing. The check sits at :858, deliberately before any balance write — this
    ///      pins that position. Move the cancel check below the balance math and this test is the
    ///      only thing in the repo that notices.
    function test_cancelBeforeSettleBlocksTheFillAndMovesNothing() public {
        Pair memory p = _matchedPair();
        uint256 buyerQuoteBefore = settlement.balances(p.buyer, address(quote));
        uint256 sellerBaseBefore = settlement.balances(p.seller, address(base));

        vm.prank(p.seller);
        settlement.cancelOrder(p.sellOrder);

        bytes memory buySig = _signOrder(pks[0], p.buyOrder);
        bytes memory sellSig = _signOrder(pks[1], p.sellOrder);
        vm.prank(operator);
        vm.expectRevert(); // OrderIsCancelled
        settlement.settleOrders(
            TradeSettlementV1.Settlement(p.buyOrder,
            buySig,
            p.sellOrder,
            sellSig,
            p.fillBase,
            p.fillQuote,
            p.fee,
            p.fee,
            keccak256("cancel-race"))
        );

        assertEq(settlement.balances(p.buyer, address(quote)), buyerQuoteBefore, "buyer quote moved");
        assertEq(settlement.balances(p.seller, address(base)), sellerBaseBefore, "seller base moved");
        assertEq(settlement.balances(p.buyer, address(base)), 0, "buyer received base anyway");
        assertEq(settlement.balances(feeRecipient, address(quote)), 0, "fee was taken anyway");
    }

    /// @dev The buy leg's cancel flag is a separate check (`:858`) from the sell leg's (`:859`),
    ///      so it gets its own test for the same reason the floor checks do.
    function test_cancelBeforeSettleBlocksTheFill_buyLeg() public {
        Pair memory p = _matchedPair();
        uint256 sellerBaseBefore = settlement.balances(p.seller, address(base));

        vm.prank(p.buyer);
        settlement.cancelOrder(p.buyOrder);

        bytes memory buySig = _signOrder(pks[0], p.buyOrder);
        bytes memory sellSig = _signOrder(pks[1], p.sellOrder);
        vm.prank(operator);
        vm.expectRevert(); // OrderIsCancelled on the buy leg
        settlement.settleOrders(
            TradeSettlementV1.Settlement(p.buyOrder,
            buySig,
            p.sellOrder,
            sellSig,
            p.fillBase,
            p.fillQuote,
            p.fee,
            p.fee,
            keccak256("cancel-race-buy"))
        );

        assertEq(settlement.balances(p.seller, address(base)), sellerBaseBefore, "seller base moved");
        assertEq(settlement.balances(feeRecipient, address(quote)), 0, "fee was taken anyway");
    }

    /// @dev Same for the gas-cheap bulk path. This is the one the paymaster sponsors, so it is the
    ///      one an account can fire for free — which is exactly why the ordering has to hold.
    function test_nonceFloorRaiseBlocksAlreadySignedOrders() public {
        Pair memory p = _matchedPair();
        uint256 sellerBaseBefore = settlement.balances(p.seller, address(base));

        vm.prank(p.buyer);
        settlement.invalidateOrdersBelow(p.buyOrder.nonce + 1);

        bytes memory buySig = _signOrder(pks[0], p.buyOrder);
        bytes memory sellSig = _signOrder(pks[1], p.sellOrder);
        vm.prank(operator);
        vm.expectRevert(); // OrderNonceBelowFloor
        settlement.settleOrders(
            TradeSettlementV1.Settlement(p.buyOrder,
            buySig,
            p.sellOrder,
            sellSig,
            p.fillBase,
            p.fillQuote,
            p.fee,
            p.fee,
            keccak256("floor-race"))
        );

        assertEq(settlement.balances(p.seller, address(base)), sellerBaseBefore, "seller base moved");
        assertEq(settlement.balances(p.buyer, address(base)), 0, "buyer received base anyway");
    }

    /// @dev The sell leg has its own floor check (`:867`) and needs its own test. Mutation testing
    ///      is why this exists: with only the buy-side case above, deleting the sell-leg check
    ///      left the whole suite green. Two symmetric guards need two tests, not one.
    function test_nonceFloorRaiseBlocksAlreadySignedOrders_sellLeg() public {
        Pair memory p = _matchedPair();
        uint256 buyerQuoteBefore = settlement.balances(p.buyer, address(quote));

        vm.prank(p.seller);
        settlement.invalidateOrdersBelow(p.sellOrder.nonce + 1);

        bytes memory buySig = _signOrder(pks[0], p.buyOrder);
        bytes memory sellSig = _signOrder(pks[1], p.sellOrder);
        vm.prank(operator);
        vm.expectRevert(); // OrderNonceBelowFloor on the sell leg
        settlement.settleOrders(
            TradeSettlementV1.Settlement(p.buyOrder,
            buySig,
            p.sellOrder,
            sellSig,
            p.fillBase,
            p.fillQuote,
            p.fee,
            p.fee,
            keccak256("floor-race-sell"))
        );

        assertEq(settlement.balances(p.buyer, address(quote)), buyerQuoteBefore, "buyer quote moved");
        assertEq(settlement.balances(p.buyer, address(base)), 0, "buyer received base anyway");
    }

    /// @dev The consequence that is easy to get wrong off-chain: `processedSettlements[id] = true`
    ///      is written at :831, BEFORE the cancel checks — but a later revert rolls it back, so a
    ///      settlement that failed does NOT consume its id. An off-chain worker that treats
    ///      `SettlementAlreadyProcessed` as "the chain did it" must not assume the converse:
    ///      a reverted settlement leaves the id free, and re-submitting it is not a replay.
    function test_revertedSettlementDoesNotConsumeItsSettlementId() public {
        Pair memory p = _matchedPair();
        bytes32 id = keccak256("rollback-check");

        vm.prank(p.seller);
        settlement.cancelOrder(p.sellOrder);

        bytes memory buySig = _signOrder(pks[0], p.buyOrder);
        bytes memory sellSig = _signOrder(pks[1], p.sellOrder);
        vm.prank(operator);
        vm.expectRevert();
        settlement.settleOrders(
            TradeSettlementV1.Settlement(p.buyOrder,
            buySig,
            p.sellOrder,
            sellSig,
            p.fillBase,
            p.fillQuote,
            p.fee,
            p.fee,
            id)
        );

        assertFalse(
            settlement.processedSettlements(id),
            "a reverted settlement consumed its settlementId"
        );

        // And the id is genuinely reusable: the same id settles once the blocker is gone.
        p.sellOrder.nonce = 7; // a fresh, uncancelled order
        _settle(p, id);
        assertTrue(settlement.processedSettlements(id), "id did not settle on retry");
    }

    /// S1 — the non-custodial guarantee, stated as arithmetic.
    function invariant_S1_solvency() public view {
        assertGe(
            base.balanceOf(address(settlement)),
            _sumBalances(address(base)),
            "S1: base balance below what the ledger owes"
        );
        assertGe(
            quote.balanceOf(address(settlement)),
            _sumBalances(address(quote)),
            "S1: quote balance below what the ledger owes"
        );
    }

    /// S2 — the accumulator the source comment calls a MUST, checked for the first time.
    function invariant_S2_totalTrackedMatchesLedger() public view {
        assertEq(
            _totalTracked(address(base)),
            _sumBalances(address(base)),
            "S2: totalTracked drifted from the sum of base balances"
        );
        assertEq(
            _totalTracked(address(quote)),
            _sumBalances(address(quote)),
            "S2: totalTracked drifted from the sum of quote balances"
        );
    }

    /// S4 — `feeAccrued` is documented as monotonic (write-only, never reset). Audit §6 property 3.
    function invariant_S4_feeAccruedMonotonic() public view {
        assertGe(
            settlement.feeAccrued(address(quote)),
            handler.ghostMaxFeeAccrued(address(quote)),
            "S4: feeAccrued went backwards on quote"
        );
        assertGe(
            settlement.feeAccrued(address(base)),
            handler.ghostMaxFeeAccrued(address(base)),
            "S4: feeAccrued went backwards on base"
        );
    }

    /// S5 — a consumed settlementId never becomes replayable. Audit §6 property 5.
    function invariant_S5_settlementIdsNeverUnconsumed() public view {
        uint256 n = handler.consumedCount();
        for (uint256 i = 0; i < n; i++) {
            assertTrue(
                settlement.processedSettlements(handler.consumedSettlementIds(i)),
                "S5: a consumed settlementId flipped back to replayable"
            );
        }
    }

    /// S3 — settlement moves value, it never mints it. Fees are a transfer to feeRecipient,
    ///      which is inside the sum, so a fee must not change the total either.
    function invariant_S3_conservation() public view {
        assertEq(
            _sumBalances(address(base)) + handler.ghostWithdrawn(address(base)),
            handler.ghostDeposited(address(base)),
            "S3: base value created or destroyed"
        );
        assertEq(
            _sumBalances(address(quote)) + handler.ghostWithdrawn(address(quote)),
            handler.ghostDeposited(address(quote)),
            "S3: quote value created or destroyed"
        );
    }
}
