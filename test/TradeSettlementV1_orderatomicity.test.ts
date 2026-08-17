/**
 * TradeSettlementV1 — ORDER ATOMICITY / trust-boundary tests.
 *
 * PRD:Trade advertises GTC / IOC / FOK order types. `ORDER_TYPEHASH` has no order-type field and
 * the signed `Order` struct has no execution-style flag, so NONE of those three words means
 * anything on-chain. This file pins that boundary from both directions:
 *
 *   NEGATIVE (§1) — the contract does not implement FOK or IOC. An order a user signed intending
 *   "all 100 or nothing" is settled at 1 base by the operator and the transaction SUCCEEDS; the
 *   99-base residual then stays live and is fillable in a later, unrelated settlement. Neither
 *   outcome is reachable under the semantics the user was shown.
 *
 *   POSITIVE (§2) — the envelope the contract DOES enforce, one assertion each, so the trust
 *   boundary documented in the audit (§10) has a test behind every claim rather than a reading of
 *   the source. Everything a user is actually protected by lives in this list: size, price, time,
 *   revocation, fee ceiling, replay. Order TYPE is not in it.
 *
 * Consequence for the threat model: a compromised or buggy matching engine cannot mis-price, over-
 * fill or replay, but it CAN legally give a user an execution style they did not sign — and the
 * only party that can detect that is the off-chain engine itself.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import {
  parseUnits,
  encodeFunctionData,
  keccak256,
  toBytes,
  zeroAddress,
  parseEventLogs,
  type Hex,
} from "viem";
import { signTypedData } from "viem/accounts";

describe("TradeSettlementV1 — order atomicity trust boundary", function () {
  const ALICE_KEY: Hex = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
  const BOB_KEY: Hex = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";

  const ORDER_TYPES = {
    Order: [
      { name: "account", type: "address" },
      { name: "baseToken", type: "address" },
      { name: "quoteToken", type: "address" },
      { name: "isBuy", type: "bool" },
      { name: "baseAmount", type: "uint256" },
      { name: "quoteAmount", type: "uint256" },
      { name: "maxFeeRate", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "expiry", type: "uint256" },
    ],
  } as const;

  type Order = {
    account: `0x${string}`;
    baseToken: `0x${string}`;
    quoteToken: `0x${string}`;
    isBuy: boolean;
    baseAmount: bigint;
    quoteAmount: bigint;
    maxFeeRate: bigint;
    nonce: bigint;
    expiry: bigint;
  };

  const sid = (seed: string): Hex => keccak256(toBytes(`ts11-${seed}`));

  const FUND = parseUnits("100000", 18);

  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, operator, alice, bob, feeRecipient] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const base = await viem.deployContract("USDT", [owner.account.address, 18]);
    const quote = await viem.deployContract("USDT", [owner.account.address, 18]);

    const impl = await viem.deployContract("TradeSettlementV1", []);
    const initData = encodeFunctionData({
      abi: impl.abi,
      functionName: "initialize",
      args: [feeRecipient.account.address, zeroAddress],
    });
    const proxy = await viem.deployContract("ERC1967Proxy", [impl.address, initData]);
    const settlement = await viem.getContractAt("TradeSettlementV1", proxy.address);

    const queueHash = await settlement.write.queueOperatorChange([operator.account.address, true]);
    const receipt = await publicClient.waitForTransactionReceipt({ hash: queueHash });
    const queued = parseEventLogs({
      abi: settlement.abi,
      logs: receipt.logs,
      eventName: "OperatorChangeQueued",
    });
    const changeId = (queued[0] as unknown as { args: { changeId: Hex } }).args.changeId;
    await time.increase(24n * 60n * 60n + 1n);
    await settlement.write.executeOperatorChange([changeId]);

    await settlement.write.setSupportedToken([base.address, true]);
    await settlement.write.setQuoteAsset([quote.address, true]);

    for (const trader of [alice, bob]) {
      for (const token of [base, quote]) {
        await token.write.mint([trader.account.address, FUND]);
        await token.write.approve([settlement.address, FUND], { account: trader.account });
        await settlement.write.depositToken([token.address, FUND], { account: trader.account });
      }
    }

    const expiry = (await time.latest()) + 3600n;
    return { settlement, base, quote, owner, operator, alice, bob, feeRecipient, chainId, expiry };
  }

  type Fixture = Awaited<ReturnType<typeof deployFixture>>;

  /**
   * alice BUYS `baseAmount` base at a limit of `quoteAmount` total, bob SELLS the same size at the
   * same limit. Both legs carry the identical nonce/expiry so the pair is a plain crossed match.
   */
  async function buildPair(
    f: Fixture,
    opts: {
      baseAmount: bigint;
      quoteAmount: bigint;
      nonce: bigint;
      expiry?: bigint;
      maxFeeRate?: bigint;
    },
  ) {
    const { alice, bob, chainId, settlement, base, quote } = f;
    const common = {
      baseToken: base.address,
      quoteToken: quote.address,
      baseAmount: opts.baseAmount,
      quoteAmount: opts.quoteAmount,
      maxFeeRate: opts.maxFeeRate ?? 0n,
      nonce: opts.nonce,
      expiry: opts.expiry ?? f.expiry,
    };
    const buyOrder: Order = { account: alice.account.address, isBuy: true, ...common };
    const sellOrder: Order = { account: bob.account.address, isBuy: false, ...common };
    const domain = {
      name: "StarZipTradeSettlement",
      version: "1",
      chainId,
      verifyingContract: settlement.address,
    } as const;
    const buySig = await signTypedData({
      privateKey: ALICE_KEY,
      domain,
      types: ORDER_TYPES,
      primaryType: "Order",
      message: buyOrder,
    });
    const sellSig = await signTypedData({
      privateKey: BOB_KEY,
      domain,
      types: ORDER_TYPES,
      primaryType: "Order",
      message: sellOrder,
    });
    return { buyOrder, buySig, sellOrder, sellSig };
  }

  const bal = (f: Fixture, u: `0x${string}`, t: `0x${string}`) =>
    f.settlement.read.getBalance([u, t]) as Promise<bigint>;

  // =====================================================================
  // 1 — What the contract does NOT enforce: order type.
  // =====================================================================
  describe("1 — FOK / IOC semantics do not exist on-chain", function () {
    it("has no order-type field in the signed Order at all", async function () {
      const f = await loadFixture(deployFixture);
      const fields = ORDER_TYPES.Order.map((x) => x.name);
      // The EIP-712 typestring the contract verifies against is exactly these 9 fields; a signature
      // over anything else fails. There is nowhere to put "FOK".
      assert.deepStrictEqual(fields, [
        "account",
        "baseToken",
        "quoteToken",
        "isBuy",
        "baseAmount",
        "quoteAmount",
        "maxFeeRate",
        "nonce",
        "expiry",
      ]);
      // Round-trip proof that this typestring is the one the contract accepts: a settlement over it
      // succeeds, so the 9 fields above ARE the complete signed payload.
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount: parseUnits("1", 18),
        quoteAmount: parseUnits("10", 18),
        nonce: 1n,
      });
      await f.settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: parseUnits("1", 18),
            fillQuoteAmount: parseUnits("10", 18),
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: sid("typestring"),
          },
        ],
        { account: f.operator.account },
      );
    });

    it("FOK NOT ENFORCED: an all-or-nothing order is legally settled at 1% of its size", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, base, quote, operator, alice } = f;

      // The user's intent: buy 100 base for 1000 quote, ALL OR NOTHING.
      const baseAmount = parseUnits("100", 18);
      const quoteAmount = parseUnits("1000", 18);
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount,
        quoteAmount,
        nonce: 2n,
      });

      // The operator submits a 1-base dust fill instead. Nothing rejects it.
      const dustBase = parseUnits("1", 18);
      const dustQuote = parseUnits("10", 18);
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: dustBase,
            fillQuoteAmount: dustQuote,
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: sid("fok-dust"),
          },
        ],
        { account: operator.account },
      );

      assert.strictEqual(
        await bal(f, alice.account.address, base.address),
        FUND + dustBase,
        "buyer received a 1-base position they signed an all-or-nothing order for",
      );
      assert.strictEqual(
        await bal(f, alice.account.address, quote.address),
        FUND - dustQuote,
        "and paid only the dust notional",
      );
    });

    it("IOC NOT ENFORCED: the unfilled residual stays live and is filled in a LATER settlement", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, base, operator, alice } = f;

      const baseAmount = parseUnits("100", 18);
      const quoteAmount = parseUnits("1000", 18);
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount,
        quoteAmount,
        nonce: 3n,
      });

      // Fill 1: 10 base. Under IOC the remaining 90 should be dead the instant this returns.
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: parseUnits("10", 18),
            fillQuoteAmount: parseUnits("100", 18),
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: sid("ioc-1"),
          },
        ],
        { account: operator.account },
      );

      // Time passes; the same signatures are still valid.
      await time.increase(600n);

      // Fill 2 against the SAME orders: accepted. The residual was never cancelled.
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: parseUnits("90", 18),
            fillQuoteAmount: parseUnits("900", 18),
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: sid("ioc-2"),
          },
        ],
        { account: operator.account },
      );

      assert.strictEqual(
        await bal(f, alice.account.address, base.address),
        FUND + baseAmount,
        "the 'immediate-or-cancel' order filled fully across two independent transactions",
      );
    });
  });

  // =====================================================================
  // 2 — What the contract DOES enforce (the real user-side envelope).
  // =====================================================================
  describe("2 — the enforced envelope", function () {
    it("SIZE: cumulative fills may never exceed the signed baseAmount", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const baseAmount = parseUnits("100", 18);
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount,
        quoteAmount: parseUnits("1000", 18),
        nonce: 4n,
      });

      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: parseUnits("60", 18),
            fillQuoteAmount: parseUnits("600", 18),
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: sid("overfill-1"),
          },
        ],
        { account: operator.account },
      );
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("41", 18),
              fillQuoteAmount: parseUnits("410", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: sid("overfill-2"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "OrderOverfill",
      );
    });

    it("PRICE: a fill worse than the signed limit reverts PriceNotCrossed", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 5n,
      });
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: parseUnits("101", 18),
              // buyer's limit is 10/base; 10.1 is over it
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: sid("price"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "PriceNotCrossed",
      );
    });

    it("TIME: an expired order reverts OrderExpired", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 6n,
      });
      await time.increase(3601n);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: parseUnits("100", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: sid("expired"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "OrderExpired",
      );
    });

    it("REVOCATION (single): cancelOrder kills exactly that order", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 7n,
      });
      await settlement.write.cancelOrder([buyOrder], { account: alice.account });
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: parseUnits("100", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: sid("cancelled"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "OrderIsCancelled",
      );
    });

    it("REVOCATION (bulk): invalidateOrdersBelow kills every order under the new floor", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 8n,
      });
      await settlement.write.invalidateOrdersBelow([9n], { account: alice.account });
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: parseUnits("100", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: sid("floored"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "OrderNonceBelowFloor",
      );
    });

    it("FEE: a fee above the order's signed maxFeeRate reverts ExcessiveFee", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 9n,
        maxFeeRate: 0n,
      });
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: parseUnits("100", 18),
              buyerFee: 1n,
              // maxFeeRate == 0 => any nonzero fee is excessive
              sellerFee: 0n,
              settlementId: sid("fee"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "ExcessiveFee",
      );
    });

    it("REPLAY: the same settlementId can never be reused", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 10n,
      });
      const args = {
        buyOrder,
        buySig,
        sellOrder,
        sellSig,
        fillBaseAmount: parseUnits("10", 18),
        fillQuoteAmount: parseUnits("100", 18),
        buyerFee: 0n,
        sellerFee: 0n,
        settlementId: sid("replay"),
      } as const;
      await settlement.write.settleOrders([args], { account: operator.account });
      await assertions.revertWithCustomError(
        settlement.write.settleOrders([args], { account: operator.account }),
        settlement,
        "SettlementAlreadyProcessed",
      );
    });
  });
});
