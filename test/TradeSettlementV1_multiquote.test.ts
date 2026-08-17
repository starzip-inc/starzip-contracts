/**
 * TradeSettlementV1 — MULTI-QUOTE acceptance tests.
 *
 * The multi-quote feature (per-Order `quoteToken`, the `quoteAssets` registry, fail-closed decimals,
 * derived + owner-tunable min/max, `QuoteMismatch`/`BaseQuoteCollision` guards, and the gate expansion
 * on `depositToken`) shipped in the current working tree with ZERO tests exercising it: the pre-existing
 * suites only migrated their ABI calls to the new 9-field `Order` shape and kept using a single 18-dec
 * USDT as the only ever-listed quote asset. `grep -ril "QuoteMismatch|BaseQuoteCollision|
 * QuoteDecimalsUnavailable|InvalidQuoteLimits|USDC" test/` was empty before this file. This file closes
 * that gap against the 9 acceptance criteria below.
 *
 * IMPORTANT — mutation-verification finding (criterion 3): removing the `QuoteMismatch` guard and
 * settling a genuinely mismatched pair does NOT break the naive `Σ_user balances[u][T] == T.balanceOf`
 * check for EITHER quote token in isolation. Reading the shipped `settleOrders` code shows why: all four
 * balance legs (seller credit, buyer debit, fee credit) are written using a SINGLE `quoteAddr =
 * buyOrder.quoteToken` — `sellOrder.quoteToken` is never referenced in the balance math. That keeps each
 * single token's ledger net-zero even with a mismatched pair, so it stays "solvent" by that narrow
 * definition. What ACTUALLY breaks (confirmed empirically — see the mutation-verification report in the
 * task's final summary, not committed here since it requires an intentionally-broken contract build) is
 * VALUE integrity: the seller's own price limit (`sellOrder.quoteAmount`) is denominated in their chosen
 * quote asset's decimals, but the crossing-check compares raw, untagged numbers with no decimals
 * normalization against `fillQuoteAmount` (which is bounded by the REGISTRY of `buyOrder.quoteToken`,
 * not the seller's). A mismatched pair (e.g. buyer quotes in 18-dec USDT, seller quotes in 6-dec USDC)
 * lets an operator pick a `fillQuoteAmount` that is simultaneously (a) large enough in raw-number terms
 * to trivially satisfy the seller's 6-dec-denominated price floor and (b) tiny in actual 18-dec USDT
 * value — so the seller sells 100 real base tokens and is credited ~0.02 USDT instead of the ~1000 USDC
 * they priced for. `Σ balances == balanceOf` never notices because the seller genuinely IS credited
 * exactly what was debited from the buyer, in the buyer's asset — the check that is solvency-critical is
 * NOT "does the ledger balance", it's "does the seller receive the asset/value they actually signed for".
 * The test below therefore proves the guard's necessity via the value-extraction angle, not a naive
 * solvency-equality angle (which would pass trivially and prove nothing).
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
import { privateKeyToAccount, signTypedData } from "viem/accounts";
import { deploySimpleTokenFixture } from "./tokenFactoryHelpers.js";

describe("TradeSettlementV1 — multi-quote acceptance", function () {
  const TOTAL_SUPPLY = parseUnits("1000000", 18);
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

  const KEYS: Record<number, Hex> = {
    0: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // owner
    1: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", // operator
    2: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", // alice
    3: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", // bob
  };
  const ALICE_KEY = KEYS[2];
  const BOB_KEY = KEYS[3];

  function settlementId(seed: string): Hex {
    return keccak256(toBytes(`mq-${seed}`));
  }

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

  async function signOrder(
    pk: Hex,
    order: Order,
    chainId: number,
    verifyingContract: `0x${string}`,
  ) {
    return signTypedData({
      privateKey: pk,
      domain: { name: "StarZipTradeSettlement", version: "1", chainId, verifyingContract },
      types: ORDER_TYPES,
      primaryType: "Order",
      message: order,
    });
  }

  type Actor = { account: { address: `0x${string}` } };

  // Reused from TradeSettlementV1_invariants.test.ts: Σ_actors getBalance(actor,token) must equal
  // token.balanceOf(settlement). Deliberately does NOT subtract feeAccrued (fees already live inside
  // balances[feeRecipient][T]).
  async function assertSolvent(settlement: any, token: any, actors: Actor[], label: string) {
    let sumLedgered = 0n;
    for (const actor of actors) {
      sumLedgered += (await settlement.read.getBalance([
        actor.account.address,
        token.address,
      ])) as bigint;
    }
    const onChain = (await token.read.balanceOf([settlement.address])) as bigint;
    assert.strictEqual(
      sumLedgered,
      onChain,
      `I1 solvency broke (${label}): Σ_user balances[u][T] (${sumLedgered}) != T.balanceOf(settlement) (${onChain})`,
    );
  }

  // `contracts/USDT.sol` takes `decimals_` in its constructor and is owner-mintable — reused as-is for
  // BOTH the 18-dec "USDT" quote and the 6-dec "USDC" quote (per task instructions: confirm reusability
  // before writing a new mock). Also reused as a plain unregistered ERC20 ("randomToken") for the
  // unsupported-deposit negative case.
  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, operator, alice, bob, feeRecipient, charlie] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]); // 18-dec quote
    const usdc = await viem.deployContract("USDT", [owner.account.address, 6]); // 6-dec quote (reused mock)
    const randomToken = await viem.deployContract("USDT", [owner.account.address, 18]); // never registered

    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);
    const { token: lpToken } = await deploySimpleTokenFixture({
      viem,
      deployer: owner,
      business: alice,
      neutralRecipient: owner,
      publicClient,
      chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      permitSignerAddress: permitSigner.address,
      platformTreasuryAddress: owner.account.address,
      totalSupply: TOTAL_SUPPLY,
      name: "LaunchpadToken",
      symbol: "LPT",
    });

    const settlementImpl = await viem.deployContract("TradeSettlementV1", []);
    const initData = encodeFunctionData({
      abi: settlementImpl.abi,
      functionName: "initialize",
      args: [feeRecipient.account.address, zeroAddress],
    });
    const settlementProxy = await viem.deployContract("ERC1967Proxy", [
      settlementImpl.address,
      initData,
    ]);
    const settlement = await viem.getContractAt("TradeSettlementV1", settlementProxy.address);

    // Wire operator via the 24h timelock (same pattern as every other TradeSettlementV1 test file).
    const queueHash = await settlement.write.queueOperatorChange([operator.account.address, true]);
    const queueReceipt = await publicClient.waitForTransactionReceipt({ hash: queueHash });
    const queuedEvents = parseEventLogs({
      abi: settlement.abi,
      logs: queueReceipt.logs,
      eventName: "OperatorChangeQueued",
    });
    const operatorChangeId = (queuedEvents[0] as unknown as { args: { changeId: Hex } }).args
      .changeId;
    await time.increase(24n * 60n * 60n + 1n);
    await settlement.write.executeOperatorChange([operatorChangeId]);

    await settlement.write.setSupportedToken([lpToken.address, true]);
    await settlement.write.setQuoteAsset([usdt.address, true]);
    await settlement.write.setQuoteAsset([usdc.address, true]);

    // Fund + deposit alice/bob with BOTH quote assets and the base asset so any of them can act as
    // buyer or seller in either quote market. USDC funding is generous (2,000,000 USDC) to cover the
    // MAX_TRADE_UNITS*unit == 1,000,000 USDC boundary test.
    const usdtAmt = parseUnits("10000", 18);
    const usdcAmt = parseUnits("2000000", 6);
    for (const trader of [alice, bob]) {
      await usdt.write.mint([trader.account.address, usdtAmt]);
      await usdt.write.approve([settlement.address, usdtAmt], { account: trader.account });
      await settlement.write.depositToken([usdt.address, usdtAmt], { account: trader.account });

      await usdc.write.mint([trader.account.address, usdcAmt]);
      await usdc.write.approve([settlement.address, usdcAmt], { account: trader.account });
      await settlement.write.depositToken([usdc.address, usdcAmt], { account: trader.account });
    }

    const tokenDepositAmt = parseUnits("1000", 18);
    await lpToken.write.transfer([bob.account.address, tokenDepositAmt], {
      account: alice.account,
    });
    await lpToken.write.approve([settlement.address, tokenDepositAmt], { account: alice.account });
    await lpToken.write.approve([settlement.address, tokenDepositAmt], { account: bob.account });
    await settlement.write.depositToken([lpToken.address, tokenDepositAmt], {
      account: alice.account,
    });
    await settlement.write.depositToken([lpToken.address, tokenDepositAmt], {
      account: bob.account,
    });

    const now = await time.latest();
    const expiry = now + 3600n;

    return {
      settlement,
      usdt,
      usdc,
      randomToken,
      lpToken,
      owner,
      operator,
      alice,
      bob,
      charlie,
      feeRecipient,
      publicClient,
      chainId,
      expiry,
      viem,
    };
  }

  // Generic matched-pair builder: alice buys `baseAmount` of `baseToken` for `quoteAmount` of
  // `quoteToken` from bob (or overridden accounts), at a 1:1 baseAmount:quoteAmount price ratio unless
  // overridden per-side. `nonce` must be unique per test to avoid cross-test overfill collisions (each
  // test uses loadFixture so state does not leak, but keeping nonces distinct documents intent).
  async function buildPair(
    f: Awaited<ReturnType<typeof deployFixture>>,
    opts: {
      baseToken: `0x${string}`;
      buyQuoteToken: `0x${string}`;
      sellQuoteToken?: `0x${string}`; // defaults to buyQuoteToken (matched); override to force a mismatch
      baseAmount: bigint;
      buyQuoteAmount: bigint;
      sellQuoteAmount?: bigint;
      nonce: bigint;
      buyer?: { account: { address: `0x${string}` } };
      seller?: { account: { address: `0x${string}` } };
    },
  ) {
    const { alice, bob, chainId, settlement, expiry } = f;
    const buyer = opts.buyer ?? alice;
    const seller = opts.seller ?? bob;
    const buyerKey = buyer === alice ? ALICE_KEY : BOB_KEY;
    const sellerKey = seller === bob ? BOB_KEY : ALICE_KEY;

    const buyOrder: Order = {
      account: buyer.account.address,
      baseToken: opts.baseToken,
      quoteToken: opts.buyQuoteToken,
      isBuy: true,
      baseAmount: opts.baseAmount,
      quoteAmount: opts.buyQuoteAmount,
      maxFeeRate: 0n,
      nonce: opts.nonce,
      expiry,
    };
    const sellOrder: Order = {
      account: seller.account.address,
      baseToken: opts.baseToken,
      quoteToken: opts.sellQuoteToken ?? opts.buyQuoteToken,
      isBuy: false,
      baseAmount: opts.baseAmount,
      quoteAmount: opts.sellQuoteAmount ?? opts.buyQuoteAmount,
      maxFeeRate: 0n,
      nonce: opts.nonce,
      expiry,
    };
    const buySig = await signOrder(buyerKey, buyOrder, chainId, settlement.address);
    const sellSig = await signOrder(sellerKey, sellOrder, chainId, settlement.address);
    return { buyOrder, buySig, sellOrder, sellSig };
  }

  // =====================================================================
  // 1. 6-dec USDC happy path + min/max boundary reverts
  // =====================================================================
  describe("1 — 6-dec USDC quote asset", function () {
    it("settles a normal-sized fill against a 6-dec USDC quote", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdc, lpToken, operator, alice, bob, feeRecipient } = f;

      // Price: 10 USDC per base token. 100 base tokens => 1000 USDC == 1000e6 raw.
      const baseAmount = parseUnits("100", 18);
      const quoteAmount = parseUnits("1000", 6);
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseToken: lpToken.address,
        buyQuoteToken: usdc.address,
        baseAmount,
        buyQuoteAmount: quoteAmount,
        nonce: 1n,
      });

      const bal = (u: `0x${string}`, t: `0x${string}`) =>
        settlement.read.getBalance([u, t]) as Promise<bigint>;
      const a0 = await bal(alice.account.address, usdc.address);
      const b0 = await bal(bob.account.address, usdc.address);
      const f0 = await bal(feeRecipient.account.address, usdc.address);

      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: baseAmount,
            fillQuoteAmount: quoteAmount,
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: settlementId("usdc-happy"),
          },
        ],
        { account: operator.account },
      );

      assert.strictEqual(
        await bal(alice.account.address, usdc.address),
        a0 - quoteAmount,
        "buyer USDC debited",
      );
      assert.strictEqual(
        await bal(bob.account.address, usdc.address),
        b0 + quoteAmount,
        "seller USDC credited",
      );
      assert.strictEqual(
        await bal(feeRecipient.account.address, usdc.address),
        f0,
        "no fee charged",
      );

      // If any 18-decimal-hardcoded constant (the pre-multiquote MIN_TRADE_AMOUNT = 1e18 /
      // MAX_SINGLE_TRADE_AMOUNT = 1e6*1e18) still gated this path, `quoteAmount` here (1000e6 = 1e9)
      // would be BELOW that old 1e18 minimum and this settlement would have reverted
      // TradeAmountTooSmall. It succeeding proves the bound now comes from quoteAssets[usdc], which is
      // derived from usdc's OWN (6) decimals, not a hardcoded 18.
    });

    it("settles exactly AT the derived minimum (0.01 USDC = 10_000 raw) and reverts one unit below it", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdc, lpToken, operator } = f;
      const q = (await settlement.read.quoteAssets([usdc.address])) as [
        boolean,
        number,
        bigint,
        bigint,
      ];
      const min = q[2];
      assert.strictEqual(
        min,
        10_000n,
        "derived min must be unit/100 = 1e6/100 = 10_000 raw for 6-dec USDC",
      );

      // AT the minimum: succeeds.
      {
        const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
          baseToken: lpToken.address,
          buyQuoteToken: usdc.address,
          baseAmount: min,
          buyQuoteAmount: min,
          nonce: 2n,
        });
        await settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: min,
              fillQuoteAmount: min,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("usdc-min-exact"),
            },
          ],
          { account: operator.account },
        );
      }

      // ONE below the minimum: reverts TradeAmountTooSmall.
      {
        const belowMin = min - 1n;
        const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
          baseToken: lpToken.address,
          buyQuoteToken: usdc.address,
          baseAmount: min, // order size stays >= fill; only the FILL is below min
          buyQuoteAmount: min,
          nonce: 3n,
        });
        await assertions.revertWithCustomError(
          settlement.write.settleOrders(
            [
              {
                buyOrder: buyOrder,
                buySig: buySig,
                sellOrder: sellOrder,
                sellSig: sellSig,
                fillBaseAmount: belowMin,
                fillQuoteAmount: belowMin,
                buyerFee: 0n,
                sellerFee: 0n,
                settlementId: settlementId("usdc-min-under"),
              },
            ],
            { account: operator.account },
          ),
          settlement,
          "TradeAmountTooSmall",
        );
      }
    });

    it("settles exactly AT the derived maximum (MAX_TRADE_UNITS USDC) and reverts one unit above it", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdc, lpToken, operator } = f;
      const q = (await settlement.read.quoteAssets([usdc.address])) as [
        boolean,
        number,
        bigint,
        bigint,
      ];
      const max = q[3];
      const maxTradeUnits = (await settlement.read.MAX_TRADE_UNITS()) as bigint;
      assert.strictEqual(
        max,
        maxTradeUnits * 10n ** 6n,
        "derived max must be MAX_TRADE_UNITS * unit",
      );

      // AT the maximum: succeeds (base-fill amount is numerically == max but is denominated in an
      // 18-decimal token, so it is a tiny fraction of one lpToken — trivially available).
      {
        const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
          baseToken: lpToken.address,
          buyQuoteToken: usdc.address,
          baseAmount: max,
          buyQuoteAmount: max,
          nonce: 4n,
        });
        await settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: max,
              fillQuoteAmount: max,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("usdc-max-exact"),
            },
          ],
          { account: operator.account },
        );
      }

      // ONE above the maximum: reverts TradeAmountTooLarge.
      {
        const aboveMax = max + 1n;
        const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
          baseToken: lpToken.address,
          buyQuoteToken: usdc.address,
          baseAmount: aboveMax,
          buyQuoteAmount: aboveMax,
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
                fillBaseAmount: aboveMax,
                fillQuoteAmount: aboveMax,
                buyerFee: 0n,
                sellerFee: 0n,
                settlementId: settlementId("usdc-max-over"),
              },
            ],
            { account: operator.account },
          ),
          settlement,
          "TradeAmountTooLarge",
        );
      }
    });
  });

  // =====================================================================
  // 2. Dual quote assets listed simultaneously — both stay solvent
  // =====================================================================
  describe("2 — USDT (18-dec) and USDC (6-dec) listed simultaneously", function () {
    it("a USDT-quoted fill and a USDC-quoted fill both settle; Σ balances == balanceOf holds for BOTH assets", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, usdc, lpToken, operator, alice, bob, feeRecipient, owner } = f;
      const ACTORS: Actor[] = [alice, bob, feeRecipient, owner];

      await assertSolvent(settlement, usdt, ACTORS, "baseline usdt");
      await assertSolvent(settlement, usdc, ACTORS, "baseline usdc");

      // Leg 1: USDT-quoted trade.
      const usdtBase = parseUnits("50", 18);
      const usdtQuote = parseUnits("500", 18);
      {
        const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
          baseToken: lpToken.address,
          buyQuoteToken: usdt.address,
          baseAmount: usdtBase,
          buyQuoteAmount: usdtQuote,
          nonce: 10n,
        });
        await settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: usdtBase,
              fillQuoteAmount: usdtQuote,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("dual-usdt"),
            },
          ],
          { account: operator.account },
        );
      }
      await assertSolvent(settlement, usdt, ACTORS, "after USDT-quoted fill");
      await assertSolvent(settlement, lpToken, ACTORS, "after USDT-quoted fill (base)");
      // USDC ledger must be completely untouched by a USDT-quoted trade.
      await assertSolvent(settlement, usdc, ACTORS, "after USDT-quoted fill (usdc untouched)");

      // Leg 2: USDC-quoted trade (roles reversed: bob buys, alice sells, so both parties still have
      // enough base-token balance for their respective sides).
      const usdcBase = parseUnits("30", 18);
      const usdcQuote = parseUnits("300", 6);
      {
        const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
          baseToken: lpToken.address,
          buyQuoteToken: usdc.address,
          baseAmount: usdcBase,
          buyQuoteAmount: usdcQuote,
          nonce: 11n,
          buyer: bob,
          seller: alice,
        });
        await settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: usdcBase,
              fillQuoteAmount: usdcQuote,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("dual-usdc"),
            },
          ],
          { account: operator.account },
        );
      }
      await assertSolvent(settlement, usdc, ACTORS, "after USDC-quoted fill");
      await assertSolvent(settlement, lpToken, ACTORS, "after USDC-quoted fill (base)");
      // USDT ledger must still be solvent (unaffected by the USDC-quoted trade).
      await assertSolvent(settlement, usdt, ACTORS, "after USDC-quoted fill (usdt still solvent)");
    });
  });

  // =====================================================================
  // 3. Quote mismatch — QuoteMismatch, + mutation-verification (see file-header comment)
  // =====================================================================
  describe("3 — quote mismatch is rejected (SOLVENCY-CRITICAL guard)", function () {
    it("buyOrder.quoteToken != sellOrder.quoteToken reverts QuoteMismatch and settles nothing", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, usdc, lpToken, operator, alice, bob } = f;

      const bal = (u: `0x${string}`, t: `0x${string}`) =>
        settlement.read.getBalance([u, t]) as Promise<bigint>;
      const aliceUsdtBefore = await bal(alice.account.address, usdt.address);
      const bobUsdcBefore = await bal(bob.account.address, usdc.address);

      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseToken: lpToken.address,
        buyQuoteToken: usdt.address, // buyer pays in USDT
        sellQuoteToken: usdc.address, // seller expects USDC — MISMATCH
        baseAmount: parseUnits("100", 18),
        buyQuoteAmount: parseUnits("1000", 18),
        sellQuoteAmount: parseUnits("1000", 6),
        nonce: 20n,
      });

      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("mismatch"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "QuoteMismatch",
      );

      // Nothing moved.
      assert.strictEqual(await bal(alice.account.address, usdt.address), aliceUsdtBefore);
      assert.strictEqual(await bal(bob.account.address, usdc.address), bobUsdcBefore);
      assert.strictEqual(
        await settlement.read.processedSettlements([settlementId("mismatch")]),
        false,
      );
    });

    // MUTATION VERIFICATION (task acceptance criterion 3) was performed manually against a build with
    // the `if (buyOrder.quoteToken != sellOrder.quoteToken) revert QuoteMismatch();` line disabled
    // (contracts/trade/TradeSettlementV1.sol, then-line ~524), then reverted via `cp` backup/restore —
    // see the task's final report for the full before/after evidence. Summary: with the guard removed,
    // the SAME mismatched pair as the test above no longer reverts. The naive per-token
    // `Σ balances == balanceOf` check does NOT catch the resulting breakage (both quote tokens stay
    // individually net-zero because settleOrders' balance math only ever references
    // `buyOrder.quoteToken`, never `sellOrder.quoteToken` — see file-header comment for the full
    // algebra). What DOES break, empirically confirmed: the seller is credited in the BUYER's quote
    // asset instead of their own, at a raw-number fill amount that satisfies the seller's own
    // (differently-scaled) price floor while being worth a negligible fraction of it — i.e. the guard
    // is critical to prevent the operator from extracting a seller's real base-token collateral for
    // near-zero real payment, not to prevent a literal token-minted-from-nowhere insolvency as the
    // contract's current NatSpec on `QuoteMismatch` and the plan doc's §1.4 algebra describe. That
    // NatSpec/plan claim does not match the shipped single-`quoteAddr` implementation and should be
    // corrected as a follow-up (flagged in the task report; out of scope for this test-only pass).
    it("value-integrity regression guard: a matched-quote fill can NEVER credit a party in an asset other than the order's own quoteToken", async function () {
      // Without exercising the mutated build (contracts/*.sol changes are out of scope for this test
      // file), this test pins the CURRENT, guarded behavior as a regression anchor: every successful
      // settlement credits/debits both parties in exactly ONE shared quoteToken, which by construction
      // (QuoteMismatch enforced) is what BOTH orders signed for.
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, usdc, lpToken, operator, alice, bob } = f;
      const baseAmount = parseUnits("10", 18);
      const quoteAmount = parseUnits("100", 6);
      const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, {
        baseToken: lpToken.address,
        buyQuoteToken: usdc.address,
        baseAmount,
        buyQuoteAmount: quoteAmount,
        nonce: 21n,
      });
      const bal = (u: `0x${string}`, t: `0x${string}`) =>
        settlement.read.getBalance([u, t]) as Promise<bigint>;
      const bobUsdtBefore = await bal(bob.account.address, usdt.address);
      const bobUsdcBefore = await bal(bob.account.address, usdc.address);

      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: baseAmount,
            fillQuoteAmount: quoteAmount,
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: settlementId("value-integrity"),
          },
        ],
        { account: operator.account },
      );

      // Seller (bob) is credited in usdc (both orders' agreed quoteToken) — NOT usdt.
      assert.strictEqual(await bal(bob.account.address, usdc.address), bobUsdcBefore + quoteAmount);
      assert.strictEqual(
        await bal(bob.account.address, usdt.address),
        bobUsdtBefore,
        "usdt must be untouched",
      );
    });
  });

  // =====================================================================
  // 4. baseToken == quoteToken — BaseQuoteCollision
  // =====================================================================
  describe("4 — base/quote collision is rejected", function () {
    it("buyOrder.baseToken == buyOrder.quoteToken reverts BaseQuoteCollision", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, operator, alice, bob, chainId, expiry } = f;

      // baseToken == quoteToken == usdt for BOTH orders — this check runs BEFORE the quote-listed /
      // supportedTokens checks in the contract, so usdt need not even be registered as a base asset
      // for this specific revert to fire first.
      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: usdt.address,
        quoteToken: usdt.address,
        isBuy: true,
        baseAmount: parseUnits("10", 18),
        quoteAmount: parseUnits("10", 18),
        maxFeeRate: 0n,
        nonce: 30n,
        expiry,
      };
      const sellOrder: Order = { ...buyOrder, account: bob.account.address, isBuy: false };
      const buySig = await signOrder(ALICE_KEY, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);

      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: parseUnits("10", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("collision"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "BaseQuoteCollision",
      );
    });
  });

  // =====================================================================
  // 5. decimals()-less token cannot be listed as a quote asset — fail-closed, no 18 fallback
  // =====================================================================
  describe("5 — quote listing is fail-closed on missing decimals()", function () {
    it("setQuoteAsset on a token with no decimals() reverts QuoteDecimalsUnavailable; no 18-decimal fallback occurs", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner, viem } = f;
      const noDecimals = await viem.deployContract("MockNoDecimalsToken", []);

      await assertions.revertWithCustomError(
        settlement.write.setQuoteAsset([noDecimals.address, true], { account: owner.account }),
        settlement,
        "QuoteDecimalsUnavailable",
      );

      // Prove there is no silent 18-decimal fallback: the registry entry must remain fully unset.
      const q = (await settlement.read.quoteAssets([noDecimals.address])) as [
        boolean,
        number,
        bigint,
        bigint,
      ];
      assert.deepStrictEqual(
        [q[0], q[1], q[2], q[3]],
        [false, 0, 0n, 0n],
        "a failed listing attempt must leave the registry entry entirely unset (no partial/fallback write)",
      );
    });
  });

  // =====================================================================
  // 6. depositToken gate: quote assets are depositable even though NOT in supportedTokens; a totally
  //    unregistered asset is not.
  // =====================================================================
  describe("6 — depositToken gate spans both registries", function () {
    it("a listed QUOTE asset (not in supportedTokens) can be deposited", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdc, charlie } = f;
      assert.strictEqual(await settlement.read.supportedTokens([usdc.address]), false);
      assert.strictEqual((await settlement.read.quoteAssets([usdc.address]))[0], true);

      const amount = parseUnits("50", 6);
      await usdc.write.mint([charlie.account.address, amount]);
      await usdc.write.approve([settlement.address, amount], { account: charlie.account });
      await settlement.write.depositToken([usdc.address, amount], { account: charlie.account });

      assert.strictEqual(
        (await settlement.read.getBalance([charlie.account.address, usdc.address])) as bigint,
        amount,
      );
    });

    it("an asset in NEITHER registry cannot be deposited", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, randomToken, charlie } = f;
      assert.strictEqual(await settlement.read.supportedTokens([randomToken.address]), false);
      assert.strictEqual((await settlement.read.quoteAssets([randomToken.address]))[0], false);

      const amount = parseUnits("50", 18);
      await randomToken.write.mint([charlie.account.address, amount]);
      await randomToken.write.approve([settlement.address, amount], { account: charlie.account });
      await assertions.revertWithCustomError(
        settlement.write.depositToken([randomToken.address, amount], { account: charlie.account }),
        settlement,
        "UnsupportedToken",
      );
    });
  });

  // =====================================================================
  // 7. Delisted quote asset stays withdrawable (non-custodial preserved)
  // =====================================================================
  describe("7 — delisting a quote asset never blocks withdrawal", function () {
    it("setQuoteAsset(usdc, false) still lets a depositor withdrawToken(usdc) in full", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdc, owner, alice } = f;

      const balBefore = (await settlement.read.getBalance([
        alice.account.address,
        usdc.address,
      ])) as bigint;
      assert.ok(balBefore > 0n, "fixture must have alice's USDC deposited");

      await settlement.write.setQuoteAsset([usdc.address, false], { account: owner.account });
      assert.strictEqual((await settlement.read.quoteAssets([usdc.address]))[0], false);

      const ercBefore = (await usdc.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.withdrawToken([usdc.address, balBefore], { account: alice.account });

      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdc.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await usdc.read.balanceOf([alice.account.address])) as bigint,
        ercBefore + balBefore,
      );
    });
  });

  // =====================================================================
  // 8. pause() never blocks withdrawal of quote (or base) assets — non-custodial preserved
  // =====================================================================
  describe("8 — pause() does not re-custody quote assets", function () {
    it("withdrawToken(usdt) / withdrawToken(usdc) / batchWithdraw([usdt,usdc,lpToken]) all succeed while paused", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, usdc, lpToken, owner, bob } = f;
      await settlement.write.pause({ account: owner.account });
      assert.strictEqual(await settlement.read.paused(), true);

      const usdtBal = (await settlement.read.getBalance([
        bob.account.address,
        usdt.address,
      ])) as bigint;
      const usdtErcBefore = (await usdt.read.balanceOf([bob.account.address])) as bigint;
      await settlement.write.withdrawToken([usdt.address, usdtBal], { account: bob.account });
      assert.strictEqual(
        (await usdt.read.balanceOf([bob.account.address])) as bigint,
        usdtErcBefore + usdtBal,
      );

      const usdcBal = (await settlement.read.getBalance([
        bob.account.address,
        usdc.address,
      ])) as bigint;
      const usdcErcBefore = (await usdc.read.balanceOf([bob.account.address])) as bigint;
      await settlement.write.withdrawToken([usdc.address, usdcBal], { account: bob.account });
      assert.strictEqual(
        (await usdc.read.balanceOf([bob.account.address])) as bigint,
        usdcErcBefore + usdcBal,
      );

      // batchWithdraw drains whatever remains (lpToken, both quote balances now 0 but listing them is
      // harmless — zero-balance entries are skipped).
      const lpBal = (await settlement.read.getBalance([
        bob.account.address,
        lpToken.address,
      ])) as bigint;
      const lpErcBefore = (await lpToken.read.balanceOf([bob.account.address])) as bigint;
      await settlement.write.batchWithdraw([[usdt.address, usdc.address, lpToken.address]], {
        account: bob.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, lpToken.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await lpToken.read.balanceOf([bob.account.address])) as bigint,
        lpErcBefore + lpBal,
      );
    });
  });

  // =====================================================================
  // 9. setQuoteLimits — hard ceiling (MAX_TRADE_UNITS * unit) cannot be raised past; min boundary too
  // =====================================================================
  describe("9 — setQuoteLimits hard bounds", function () {
    it("max ceiling: exactly MAX_TRADE_UNITS*unit succeeds; ceiling+1 reverts InvalidQuoteLimits", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdc, owner } = f;
      const maxTradeUnits = (await settlement.read.MAX_TRADE_UNITS()) as bigint;
      const unit = 10n ** 6n;
      const ceiling = maxTradeUnits * unit;

      // The minimum has its own floor (unit / 10_000), so this uses the lowest LEGAL minimum
      // rather than 1 raw unit — the assertion under test here is the max ceiling.
      const minFloor = unit / 10_000n;

      await settlement.write.setQuoteLimits([usdc.address, minFloor, ceiling], {
        account: owner.account,
      });
      const q1 = (await settlement.read.quoteAssets([usdc.address])) as [
        boolean,
        number,
        bigint,
        bigint,
      ];
      assert.strictEqual(q1[3], ceiling);

      await assertions.revertWithCustomError(
        settlement.write.setQuoteLimits([usdc.address, minFloor, ceiling + 1n], {
          account: owner.account,
        }),
        settlement,
        "InvalidQuoteLimits",
      );
    });

    it("min floor: the owner cannot drop the minimum below unit/10_000 (dust-fill guard stays armed)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdc, owner } = f;
      const unit = 10n ** 6n;
      const minFloor = unit / 10_000n; // 100 raw = 0.0001 USDC
      const ceiling = ((await settlement.read.MAX_TRADE_UNITS()) as bigint) * unit;

      // exactly at the floor is accepted
      await settlement.write.setQuoteLimits([usdc.address, minFloor, ceiling], {
        account: owner.account,
      });
      const q = (await settlement.read.quoteAssets([usdc.address])) as [
        boolean,
        number,
        bigint,
        bigint,
      ];
      assert.strictEqual(q[2], minFloor);

      // one raw unit below the floor — and 1 wei, the value that used to be accepted — are refused
      for (const badMin of [minFloor - 1n, 1n]) {
        await assertions.revertWithCustomError(
          settlement.write.setQuoteLimits([usdc.address, badMin, ceiling], {
            account: owner.account,
          }),
          settlement,
          "InvalidQuoteLimits",
        );
      }
    });

    it("min boundary: 0 reverts, unit*100 succeeds, unit*100+1 reverts; max < min reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdc, owner } = f;
      const unit = 10n ** 6n;
      const maxTradeUnits = (await settlement.read.MAX_TRADE_UNITS()) as bigint;
      const ceiling = maxTradeUnits * unit;

      // min == 0 -> revert regardless of max.
      await assertions.revertWithCustomError(
        settlement.write.setQuoteLimits([usdc.address, 0n, ceiling], { account: owner.account }),
        settlement,
        "InvalidQuoteLimits",
      );

      // min == unit*100 (the hard ceiling on the min side) -> succeeds.
      await settlement.write.setQuoteLimits([usdc.address, unit * 100n, ceiling], {
        account: owner.account,
      });
      const q = (await settlement.read.quoteAssets([usdc.address])) as [
        boolean,
        number,
        bigint,
        bigint,
      ];
      assert.strictEqual(q[2], unit * 100n);

      // min == unit*100 + 1 -> reverts.
      await assertions.revertWithCustomError(
        settlement.write.setQuoteLimits([usdc.address, unit * 100n + 1n, ceiling], {
          account: owner.account,
        }),
        settlement,
        "InvalidQuoteLimits",
      );

      // max < min -> reverts.
      await assertions.revertWithCustomError(
        settlement.write.setQuoteLimits([usdc.address, 1000n, 999n], { account: owner.account }),
        settlement,
        "InvalidQuoteLimits",
      );
    });

    it("setQuoteLimits on a never-listed token reverts UnsupportedQuote", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, randomToken, owner } = f;
      await assertions.revertWithCustomError(
        settlement.write.setQuoteLimits([randomToken.address, 1n, 1000n], {
          account: owner.account,
        }),
        settlement,
        "UnsupportedQuote",
      );
    });
  });
});
