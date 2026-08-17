/**
 * TradeSettlementV1 — SPINE INVARIANT tests (pre-refactor safety net).
 *
 * Purpose: land the invariant net BEFORE the storage-reorder (S2) / multi-quote (S3) refactor
 * stages, so that refactor lands regressions against a net that actually proves something
 * (mutation-verified, not just green-by-construction). The gaps this file closes:
 *   - I1 solvency (Σ_user balances[u][T] == T.balanceOf(settlement)) was never asserted
 *     against the real ERC20 balance — only the internal ledger reshuffling to itself, which is
 *     true by construction and proves nothing about backing.
 * - batchSettleNetDeltas' signed-Σ==0 defense was only exercised with a balanced
 *     fixture, which masks that an unpaired credit is equally accepted by the (missing) check.
 *     SUPERSEDED: the whole unsigned-operator net-delta path was deleted, so §4 below no longer
 *     tests the guard — it asserts the ENTRYPOINT's absence from the ABI, which is what the
 *     non-custodial model actually requires and what a "re-add it behind a default-off flag"
 *     regression would trip over.
 * - recoverStuckTokens' totalTracked-based excess computation had no indirect probe tying
 *     it to a full mixed-operation sequence.
 *
 * IMPORTANT: solvency must be computed as EQUALITY against balanceOf, and must NOT subtract
 * feeAccrued — fees already live inside balances[feeRecipient][T]; subtracting double-counts
 * (audit §3 "Negative results", feeAccrued note).
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

describe("TradeSettlementV1 — SPINE INVARIANTS (I1 solvency, zero-sum, non-custodial)", function () {
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
    return keccak256(toBytes(`inv-${seed}`));
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

  // Mirrors TradeSettlementV1_security.test.ts's deployFixture: same actors, same wiring
  // (operator timelock, supported tokens, batch caps, alice/bob USDT + lpToken deposits).
  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, operator, alice, bob, feeRecipient, charlie] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);

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

    await settlement.write.setQuoteAsset([usdt.address, true]);
    await settlement.write.setSupportedToken([lpToken.address, true]);

    const depositAmt = parseUnits("10000", 18);
    await usdt.write.mint([alice.account.address, depositAmt]);
    await usdt.write.mint([bob.account.address, depositAmt]);
    await usdt.write.approve([settlement.address, depositAmt], { account: alice.account });
    await usdt.write.approve([settlement.address, depositAmt], { account: bob.account });
    await settlement.write.depositToken([usdt.address, depositAmt], { account: alice.account });
    await settlement.write.depositToken([usdt.address, depositAmt], { account: bob.account });

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
      settlementImpl,
      usdt,
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

  type Actor = { account: { address: `0x${string}` } };

  // ===== I1 helper: Σ_actors getBalance(actor, token) must equal token.balanceOf(settlement). =====
  // Reusable across every mutation site named in the task (deposit / settleOrders / withdraw /
  // emergencyWithdrawFor / batchWithdraw). Deliberately does NOT subtract feeAccrued (audit note:
  // fees already live inside balances[feeRecipient][T]; subtracting would double-count).
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

  // recoverStuckTokens is now request -> 48h -> execute, with the staged (token, to,
  // amount) required to match EXACTLY. Every probe below still asserts what it always asserted
  // (excess-only recovery); it just has to walk the staging first.
  const RECOVER_DELAY = 48n * 60n * 60n + 1n;
  async function stageRecover(
    settlement: any,
    owner: any,
    token: `0x${string}`,
    to: `0x${string}`,
    amount: bigint,
  ) {
    await settlement.write.requestRecover([token, to, amount], { account: owner.account });
    await time.increase(RECOVER_DELAY);
  }

  // =====================================================================
  // 1. I1 solvency invariant across every named mutation site
  // =====================================================================
  describe("I1 — solvency (Σ balances == balanceOf) at every mutation site", function () {
    it("holds after deposit / settleOrders / withdraw / emergencyWithdrawFor / batchWithdraw, in sequence", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, operator, owner, alice, bob, feeRecipient } = f;
      const ACTORS: Actor[] = [alice, bob, feeRecipient, owner];

      // Baseline (post-fixture-setup).
      await assertSolvent(settlement, usdt, ACTORS, "baseline usdt");
      await assertSolvent(settlement, lpToken, ACTORS, "baseline lpToken");

      // ---- depositUsdt / depositToken ----
      const extraUsdt = parseUnits("500", 18);
      await usdt.write.mint([alice.account.address, extraUsdt]);
      await usdt.write.approve([settlement.address, extraUsdt], { account: alice.account });
      await settlement.write.depositToken([usdt.address, extraUsdt], { account: alice.account });
      await assertSolvent(settlement, usdt, ACTORS, "after depositUsdt");

      const extraToken = parseUnits("200", 18);
      await lpToken.write.transfer([bob.account.address, extraToken], { account: alice.account });
      await lpToken.write.approve([settlement.address, extraToken], { account: bob.account });
      await settlement.write.depositToken([lpToken.address, extraToken], { account: bob.account });
      await assertSolvent(settlement, lpToken, ACTORS, "after depositToken");

      // ---- settleOrders (4-leg zero-sum path; intentionally does NOT touch totalTracked) ----
      const fillTokenAmount = parseUnits("10", 18);
      const fillUsdtAmount = parseUnits("100", 18);
      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: true,
        baseAmount: fillTokenAmount,
        quoteAmount: fillUsdtAmount,
        maxFeeRate: 100n,
        nonce: 1n,
        expiry: f.expiry,
      };
      const sellOrder: Order = {
        account: bob.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: false,
        baseAmount: fillTokenAmount,
        quoteAmount: fillUsdtAmount,
        maxFeeRate: 100n,
        nonce: 1n,
        expiry: f.expiry,
      };
      const buySig = await signOrder(ALICE_KEY, buyOrder, f.chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, f.chainId, settlement.address);
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: fillTokenAmount,
            fillQuoteAmount: fillUsdtAmount,
            buyerFee: parseUnits("1", 18),
            sellerFee: parseUnits("1", 18),
            settlementId: settlementId("i1-settle"),
          },
        ],
        { account: operator.account },
      );
      await assertSolvent(settlement, usdt, ACTORS, "after settleOrders");
      await assertSolvent(settlement, lpToken, ACTORS, "after settleOrders");

      // ---- withdrawUsdt / withdrawToken (partial) ----
      const aliceUsdtBal = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      await settlement.write.withdrawToken([usdt.address, aliceUsdtBal / 4n], {
        account: alice.account,
      });
      await assertSolvent(settlement, usdt, ACTORS, "after withdrawUsdt");

      const bobTokenBal = (await settlement.read.getBalance([
        bob.account.address,
        lpToken.address,
      ])) as bigint;
      await settlement.write.withdrawToken([lpToken.address, bobTokenBal / 4n], {
        account: bob.account,
      });
      await assertSolvent(settlement, lpToken, ACTORS, "after withdrawToken");

      // ---- emergencyWithdrawFor (owner backstop, seize-TO-USER only) ----
      const bobUsdtBal = (await settlement.read.getBalance([
        bob.account.address,
        usdt.address,
      ])) as bigint;
      assert.ok(bobUsdtBal > 0n, "bob must have a nonzero USDT ledger balance to force-exit");
      await settlement.write.emergencyWithdrawFor([bob.account.address, usdt.address], {
        account: owner.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, usdt.address])) as bigint,
        0n,
      );
      await assertSolvent(settlement, usdt, ACTORS, "after emergencyWithdrawFor");
      await assertSolvent(settlement, lpToken, ACTORS, "after emergencyWithdrawFor (untouched)");

      // ---- batchWithdraw (full-balance exit across both tokens) ----
      await settlement.write.batchWithdraw([[usdt.address, lpToken.address]], {
        account: alice.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        0n,
      );
      await assertSolvent(settlement, usdt, ACTORS, "after batchWithdraw");
      await assertSolvent(settlement, lpToken, ACTORS, "after batchWithdraw");
    });
  });

  // =====================================================================
  // 2. I1-b — totalTracked integrity, probed indirectly via recoverStuckTokens
  //    (totalTracked is `private`; this is the only observable window into it).
  // =====================================================================
  describe("I1-b — totalTracked stays exact (indirect probe via recoverStuckTokens)", function () {
    it("recoverStuckTokens(T, x>0, 1) reverts when only user deposits back the balance (no excess)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, owner, charlie } = f;

      // Fixture has ONLY user deposits behind usdt — balanceOf(settlement) == totalTracked exactly.
      // Any nonzero recovery attempt must revert: there is no excess to sweep. The staging is
      // fully matured first, so NothingToRecover here proves the excess check (not the timelock)
      // is what stops it.
      await stageRecover(settlement, owner, usdt.address, charlie.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );
    });

    it("a raw donation (direct ERC20 transfer, bypassing depositToken) is recoverable for EXACTLY its amount, no more", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, owner, alice } = f;
      const donation = parseUnits("13", 18);

      // Direct transfer bypasses balances[]/totalTracked entirely — simulates accidental dust.
      await lpToken.write.transfer([settlement.address, donation], { account: alice.account });

      // Boundary: donation+1 must revert (would reach into user-owed funds / totalTracked).
      await stageRecover(settlement, owner, lpToken.address, owner.account.address, donation + 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens(
          [lpToken.address, owner.account.address, donation + 1n],
          { account: owner.account },
        ),
        settlement,
        "NothingToRecover",
      );

      // Exactly `donation` succeeds.
      const ownerBefore = (await lpToken.read.balanceOf([owner.account.address])) as bigint;
      await stageRecover(settlement, owner, lpToken.address, owner.account.address, donation);
      await settlement.write.recoverStuckTokens(
        [lpToken.address, owner.account.address, donation],
        { account: owner.account },
      );
      assert.strictEqual(
        (await lpToken.read.balanceOf([owner.account.address])) as bigint,
        ownerBefore + donation,
      );

      // Excess now fully swept — even amount==1 reverts.
      await stageRecover(settlement, owner, lpToken.address, owner.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([lpToken.address, owner.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );
    });

    // This is the probe that specifically pins withdrawToken's `totalTracked[_token] -=` site.
    // assertSolvent (Σ balances == balanceOf) does NOT catch a missing decrement here: both the
    // ledger and the real ERC20 balance drop correctly on withdrawal, so that equality still
    // holds. Only totalTracked (private) would silently over-report the liability, which
    // recoverStuckTokens' `balanceOf(this) - totalTracked[_token]` subtraction turns into an
    // underflow (Panic 0x11) instead of the expected clean `NothingToRecover` revert — a
    // DIFFERENT failure mode that this assertion is specific enough to catch.
    it("totalTracked stays exact after a partial withdrawToken (indirect probe via recoverStuckTokens)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, owner, bob } = f;

      const bobBal = (await settlement.read.getBalance([
        bob.account.address,
        lpToken.address,
      ])) as bigint;
      assert.ok(bobBal > 0n, "fixture must have bob's lpToken deposited");

      await settlement.write.withdrawToken([lpToken.address, bobBal / 3n], {
        account: bob.account,
      });

      // If totalTracked was decremented in lockstep with the real transfer-out, balanceOf(this)
      // == totalTracked exactly and recoverStuckTokens(1) reverts NothingToRecover (no excess).
      // If the decrement is missing, totalTracked over-reports the liability and the subtraction
      // underflows instead — a different revert this specific assertion will NOT accept.
      await stageRecover(settlement, owner, lpToken.address, owner.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([lpToken.address, owner.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );
    });
  });

  // =====================================================================
  // 3. zero-sum(settleOrders) — Σ ledgered balances per token unchanged across a fill
  //    (fees included: the fee leg is credited to feeRecipient, which is in the actor set).
  // =====================================================================
  describe("zero-sum — settleOrders never changes the aggregate ledger per token", function () {
    it("Σ_actors balances[actor][usdt] and Σ_actors balances[actor][lpToken] are each unchanged before vs after a fill with fees", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, operator, owner, alice, bob, feeRecipient } = f;
      const ACTORS: Actor[] = [alice, bob, feeRecipient, owner];

      async function sumOf(token: any): Promise<bigint> {
        let total = 0n;
        for (const actor of ACTORS) {
          total += (await settlement.read.getBalance([
            actor.account.address,
            token.address,
          ])) as bigint;
        }
        return total;
      }

      const usdtSumBefore = await sumOf(usdt);
      const tokenSumBefore = await sumOf(lpToken);

      const fillTokenAmount = parseUnits("25", 18);
      const fillUsdtAmount = parseUnits("250", 18);
      // MAX_FEE_RATE (contract constant) caps fees at 1% of fillUsdtAmount == 2.5e18 regardless of
      // order.maxFeeRate (effective cap is min(MAX_FEE_RATE, order.maxFeeRate)). Keep both fees
      // comfortably under that ceiling.
      const buyerFee = parseUnits("2", 18);
      const sellerFee = parseUnits("2", 18);
      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: true,
        baseAmount: fillTokenAmount,
        quoteAmount: fillUsdtAmount,
        maxFeeRate: 100n, // == MAX_FEE_RATE (1%); effective cap is min(this, MAX_FEE_RATE)
        nonce: 7n,
        expiry: f.expiry,
      };
      const sellOrder: Order = {
        account: bob.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: false,
        baseAmount: fillTokenAmount,
        quoteAmount: fillUsdtAmount,
        maxFeeRate: 100n,
        nonce: 7n,
        expiry: f.expiry,
      };
      const buySig = await signOrder(ALICE_KEY, buyOrder, f.chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, f.chainId, settlement.address);

      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: fillTokenAmount,
            fillQuoteAmount: fillUsdtAmount,
            buyerFee: buyerFee,
            sellerFee: sellerFee,
            settlementId: settlementId("zerosum-fee"),
          },
        ],
        { account: operator.account },
      );

      const usdtSumAfter = await sumOf(usdt);
      const tokenSumAfter = await sumOf(lpToken);

      assert.strictEqual(
        usdtSumAfter,
        usdtSumBefore,
        "Σ_actors balances[*][usdt] must be unchanged by settleOrders (fees included, feeRecipient in actor set)",
      );
      assert.strictEqual(
        tokenSumAfter,
        tokenSumBefore,
        "Σ_actors balances[*][lpToken] must be unchanged by settleOrders",
      );

      // Sanity: the fee actually moved (proves the test isn't vacuously true because fees were 0).
      const feeRecipientUsdt = (await settlement.read.getBalance([
        feeRecipient.account.address,
        usdt.address,
      ])) as bigint;
      assert.strictEqual(feeRecipientUsdt, buyerFee + sellerFee);
    });
  });

  // =====================================================================
  // 4. CLOSED BY DELETION — the unsigned operator settlement path is ABSENT
  //    The former regression here exercised batchSettleNetDeltas' signed-Σ==0 defense. That
  //    defense is gone because the thing it defended is gone: under the confirmed dYdX-style
  //    non-custodial model, an operator entrypoint that debits an account without that account's
  //    signature must not exist — not disabled-by-default, not flag-gated, ABSENT. The assertion
  //    therefore moves from "the guard rejects an unbalanced batch" to "the ABI exposes no such
  //    entrypoint (nor its enable/cap controls) at all", which is the stronger claim and the one
  //    that cannot silently regress if someone re-adds the function behind a default-off flag.
  // =====================================================================
  describe("unsigned operator debit path absent from the ABI", function () {
    const REMOVED_FUNCTIONS = [
      "batchSettleNetDeltas",
      "netDeltaSettlementEnabled",
      "netDeltaEnableReadyAt",
      "requestEnableNetDelta",
      "setNetDeltaSettlementEnabled",
      "batchAmountCap",
      "setBatchAmountCap",
      "MAX_NET_DELTAS",
    ];
    const REMOVED_EVENTS = [
      "Settlement",
      "BatchAmountCapUpdated",
      "NetDeltaSettlementEnabledUpdated",
      "NetDeltaEnableRequested",
    ];
    const REMOVED_ERRORS = [
      "NetDeltaSettlementDisabled",
      "NetDeltaEnableNotReady",
      "EmptyDeltas",
      "TooManyDeltas",
      "BatchCapNotSet",
      "BatchCapExceeded",
      "InvalidDelta",
      "FeeRecipientNegativeDelta",
      "UnbalancedSettlement",
    ];

    it("batchSettleNetDeltas and every net-delta control are gone from the compiled ABI", async function () {
      const { settlement } = await loadFixture(deployFixture);
      const abi = settlement.abi as { type: string; name?: string }[];

      for (const name of REMOVED_FUNCTIONS) {
        assert.ok(
          !abi.some((entry) => entry.type === "function" && entry.name === name),
          `ABI still exposes function ${name}() — the unsigned operator settlement path must be ` +
            `deleted, not merely disabled`,
        );
      }
      for (const name of REMOVED_EVENTS) {
        assert.ok(
          !abi.some((entry) => entry.type === "event" && entry.name === name),
          `ABI still exposes event ${name} from the deleted net-delta path`,
        );
      }
      for (const name of REMOVED_ERRORS) {
        assert.ok(
          !abi.some((entry) => entry.type === "error" && entry.name === name),
          `ABI still exposes error ${name} from the deleted net-delta path`,
        );
      }
    });

    it("the NetDelta struct type is gone — no ABI entry mentions it", async function () {
      const { settlement } = await loadFixture(deployFixture);
      const abi = settlement.abi as {
        inputs?: { type: string; internalType?: string }[];
      }[];
      for (const entry of abi) {
        for (const input of entry.inputs ?? []) {
          assert.ok(
            !(input.internalType ?? "").includes("NetDelta"),
            `ABI still references the NetDelta struct (${input.internalType})`,
          );
        }
      }
    });

    it("settleOrders is the ONLY settlement entrypoint left that writes processedSettlements", async function () {
      const { settlement } = await loadFixture(deployFixture);
      const abi = settlement.abi as { type: string; name?: string; stateMutability?: string }[];
      const settleFns = abi
        .filter(
          (entry) =>
            entry.type === "function" &&
            entry.stateMutability !== "view" &&
            entry.stateMutability !== "pure" &&
            /settle/i.test(entry.name ?? ""),
        )
        .map((entry) => entry.name);
      // The guard is "no settlement path appeared that this list does not account for", so the
      // list must be exhaustive and every member must be justified:
      //   settleOrders      — operator-only, both legs signature-authorized
      //   settleOrdersBatch — operator-only, loops the same body per item
      //   settleOrdersSelf  — reverts OnlySelf for every caller except this contract's own batch
      // All three funnel into `_settleOne`, so none can debit an account that did not sign. The
      // legacy unsigned paths are pinned absent separately by REMOVED_FUNCTIONS above.
      assert.deepStrictEqual(
        settleFns.sort(),
        ["settleOrders", "settleOrdersBatch", "settleOrdersSelf"],
        `unexpected settlement entrypoints on the ABI: ${settleFns.join(", ")}`,
      );
    });
  });

  // =====================================================================
  // 5. Non-custodial guarantee — exits work regardless of pause / delist
  // =====================================================================
  describe("non-custodial guarantee — withdrawals survive pause and delisting", function () {
    it("withdrawUsdt / withdrawToken / batchWithdraw all succeed WHILE PAUSED", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, owner, alice } = f;
      await settlement.write.pause({ account: owner.account });

      const usdtBal = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      const usdtErcBefore = (await usdt.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.withdrawToken([usdt.address, usdtBal / 2n], {
        account: alice.account,
      });
      assert.strictEqual(
        (await usdt.read.balanceOf([alice.account.address])) as bigint,
        usdtErcBefore + usdtBal / 2n,
      );

      const tokenBal = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;
      const tokenErcBefore = (await lpToken.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.withdrawToken([lpToken.address, tokenBal / 2n], {
        account: alice.account,
      });
      assert.strictEqual(
        (await lpToken.read.balanceOf([alice.account.address])) as bigint,
        tokenErcBefore + tokenBal / 2n,
      );

      // batchWithdraw drains whatever remains of both tokens, still while paused.
      const usdtErcBefore2 = (await usdt.read.balanceOf([alice.account.address])) as bigint;
      const tokenErcBefore2 = (await lpToken.read.balanceOf([alice.account.address])) as bigint;
      const usdtRemaining = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      const tokenRemaining = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;
      await settlement.write.batchWithdraw([[usdt.address, lpToken.address]], {
        account: alice.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await usdt.read.balanceOf([alice.account.address])) as bigint,
        usdtErcBefore2 + usdtRemaining,
      );
      assert.strictEqual(
        (await lpToken.read.balanceOf([alice.account.address])) as bigint,
        tokenErcBefore2 + tokenRemaining,
      );
    });

    it("withdrawToken succeeds after the token is delisted (setSupportedToken(T,false))", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, owner, bob } = f;
      await settlement.write.setSupportedToken([lpToken.address, false], {
        account: owner.account,
      });

      const bal = (await settlement.read.getBalance([
        bob.account.address,
        lpToken.address,
      ])) as bigint;
      assert.ok(bal > 0n);
      const ercBefore = (await lpToken.read.balanceOf([bob.account.address])) as bigint;
      await settlement.write.withdrawToken([lpToken.address, bal], { account: bob.account });
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, lpToken.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await lpToken.read.balanceOf([bob.account.address])) as bigint,
        ercBefore + bal,
      );
    });
  });
});
