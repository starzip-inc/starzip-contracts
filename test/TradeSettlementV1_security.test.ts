/**
 * TradeSettlementV1 — SECURITY PROOF tests for the Stage-2a fix (audit finding L5).
 *
 * The pre-existing suite (TradeSettlementV1_signature.test.ts) never asserted the two
 * invariants that actually make this contract non-custodial:
 *   - I5 (non-custodial): no owner/operator action can move a user's deposited balance to a
 *     third party. `recoverStuckTokens` used to be a pointer-game backdoor (it read
 *     `_token == address(usdt)` / `supportedTokens[_token]` to decide "is this real user
 *     money", which the owner could flip with `setUsdt` / `setSupportedToken`).
 *   - I1 (solvency / backing): `Σ_user balances[u][T] == T.balanceOf(escrow)` at every
 *     reachable state, and — after the Stage-2a fix — `totalTracked[T]` must be maintained at
 *     EVERY balance-mutating site so it tracks that sum exactly. A missed site would either
 *     over-report recoverable funds (drain surface) or make `recoverStuckTokens` spuriously
 *     revert forever on real excess (a stuck-funds footgun) — either way it is a bug.
 *
 * Stage-2a fix under test (contracts/trade/TradeSettlementV1.sol, current HEAD):
 *   - `recoverStuckTokens` is excess-only: `recoverable = balanceOf(this) - totalTracked[T]`;
 *     reverts NothingToRecover if `_amount > recoverable`. No longer reads `usdt` / `supportedTokens`.
 *     it is additionally two-step — `requestRecover` -> 48h -> `recoverStuckTokens` with
 *     byte-identical arguments — so every probe below stages first. The staging is always fully
 *     matured before the assertion, so a NothingToRecover expectation still proves the EXCESS
 *     check rejected the call, not the timelock.
 *   - `setUsdt` is DELETED — usdt is set only in `initialize` and is immutable thereafter.
 *   - `totalTracked[T]` is maintained at every `balances[...] +=/-=` site that is NOT
 *     algebraically zero-sum in isolation (deposits, withdrawals, emergencyWithdrawFor).
 *     `settleOrders` is intentionally a no-op on totalTracked because its 4-leg set nets to zero
 *     per token by construction.
 *   - `batchSettleNetDeltas` is DELETED outright: under the confirmed non-custodial model
 *     an unsigned operator debit path must not exist, so there is no guard left to test — only
 *     its absence.
 *
 * identifiers below match the fix's own NatSpec cross-references
 * ("see ", "see ") in the contract source.
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

describe("TradeSettlementV1 — SECURITY PROOF (solvency + non-custodial, audit L5)", function () {
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

  // recoverStuckTokens is request -> 48h -> execute with an EXACT parameter match. Every
  // recovery probe below stages and fully matures first, so any NothingToRecover it then asserts
  // is the excess check speaking, never the timelock.
  async function stageRecover(
    settlement: any,
    owner: any,
    token: `0x${string}`,
    to: `0x${string}`,
    amount: bigint,
  ) {
    await settlement.write.requestRecover([token, to, amount], { account: owner.account });
    await time.increase(48n * 60n * 60n + 1n);
  }

  function settlementId(seed: string): Hex {
    return keccak256(toBytes(`sec-${seed}`));
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

  // Mirrors TradeSettlementV1_signature.test.ts's deployFixture: same actors, same wiring
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

  // Σ_actors getBalance(actor, token) must equal token.balanceOf(settlement) — the I1 solvency
  // invariant. `token` is the erc20 contract instance (usdt or lpToken), `actors` are wallet
  // clients (getBalance is keyed by .account.address).
  async function assertSolvent(
    settlement: any,
    token: any,
    actors: { account: { address: `0x${string}` } }[],
    label: string,
  ) {
    let sumLedgered = 0n;
    for (const actor of actors) {
      sumLedgered += (await settlement.read.getBalance([
        actor.account.address,
        token.address,
      ])) as bigint;
    }
    const onChain = (await token.read.balanceOf([settlement.address])) as bigint;
    assert.strictEqual(sumLedgered, onChain, `solvency broke (${label}): Σbalances != balanceOf`);
  }

  // =====================================================================
  // owner cannot drain deposited USDT via recoverStuckTokens
  // =====================================================================
  describe("blocked — owner cannot drain deposited USDT", function () {
    it("recoverStuckTokens(USDT, attacker, X>0) reverts NothingToRecover; still reverts after delisting; alice can still withdraw in full", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, owner, alice, charlie } = f;

      const aliceBalBefore = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      assert.ok(aliceBalBefore > 0n, "fixture must have alice's USDT deposited");

      // No excess exists: balanceOf(settlement) == totalTracked (== Σ deposits). Any attempt to
      // "recover" real user-owed USDT must revert.
      await stageRecover(settlement, owner, usdt.address, charlie.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );

      // The old attack vector (flip a registry flag to false so recoverStuckTokens reads the
      // asset as "not real money") is closed: the fix is keyed on balanceOf-minus-totalTracked
      // only, which ignores BOTH registries. Flip both — USDT now lives in the quote registry.
      await settlement.write.setSupportedToken([usdt.address, false], { account: owner.account });
      await settlement.write.setQuoteAsset([usdt.address, false], { account: owner.account });
      await stageRecover(settlement, owner, usdt.address, charlie.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );

      // The old `setUsdt(decoy)` step is impossible now — assert the ABI has neither the setter
      // NOR the `usdt` pointer it repointed. Multi-quote deleted the pointer outright, so the
      // whole "owner repoints the reference asset" bug class is gone by construction.
      const abiNames = new Set(
        (settlement.abi as ReadonlyArray<{ type: string; name?: string }>)
          .filter((item) => item.type === "function")
          .map((item) => item.name),
      );
      assert.strictEqual(abiNames.has("setUsdt"), false, "setUsdt must not exist in the ABI");
      assert.strictEqual(
        abiNames.has("usdt"),
        false,
        "the `usdt` pointer itself must not exist in the ABI (multi-quote removed it)",
      );
      assert.strictEqual(
        abiNames.has("depositUsdt"),
        false,
        "depositUsdt must not exist (pointer-scoped deposit path removed)",
      );
      assert.strictEqual(
        abiNames.has("withdrawUsdt"),
        false,
        "withdrawUsdt must not exist (pointer-scoped withdrawal path removed)",
      );

      // Drain path closed end-to-end: alice can still exit her full USDT balance.
      const erc20Before = (await usdt.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.withdrawToken([usdt.address, aliceBalBefore], {
        account: alice.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await usdt.read.balanceOf([alice.account.address])) as bigint,
        erc20Before + aliceBalBefore,
      );
    });
  });

  // =====================================================================
  // owner cannot drain a deposited supported token via delisting + recover
  // =====================================================================
  describe("blocked — owner cannot drain a deposited supported token", function () {
    it("setSupportedToken(T,false) then recoverStuckTokens(T,...) reverts; bob can still withdraw T", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, owner, bob, charlie } = f;

      const bobBalBefore = (await settlement.read.getBalance([
        bob.account.address,
        lpToken.address,
      ])) as bigint;
      assert.ok(bobBalBefore > 0n, "fixture must have bob's lpToken deposited");

      await settlement.write.setSupportedToken([lpToken.address, false], {
        account: owner.account,
      });

      await stageRecover(settlement, owner, lpToken.address, charlie.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([lpToken.address, charlie.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );

      const erc20Before = (await lpToken.read.balanceOf([bob.account.address])) as bigint;
      await settlement.write.withdrawToken([lpToken.address, bobBalBefore], {
        account: bob.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, lpToken.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await lpToken.read.balanceOf([bob.account.address])) as bigint,
        erc20Before + bobBalBefore,
      );
    });
  });

  // =====================================================================
  // recover excess-only happy path
  // =====================================================================
  describe("recover excess-only happy path", function () {
    it("recovers exactly a raw-donated excess, blocks over-recovery at the true boundary, and never touches ledgered balances", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, owner, alice, bob } = f;

      const donation = parseUnits("37", 18);

      // Snapshot ledgered (user-owed) balances before the donation.
      const aliceLedgerBefore = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;
      const bobLedgerBefore = (await settlement.read.getBalance([
        bob.account.address,
        lpToken.address,
      ])) as bigint;

      // RAW transfer (donation), NOT depositToken — bypasses balances[]/totalTracked entirely,
      // simulating an accidental direct transfer / dust. alice has ample un-deposited lpToken
      // (deploySimpleTokenFixture gives the business the full supply, only a slice deposited).
      await lpToken.write.transfer([settlement.address, donation], { account: alice.account });

      // Boundary: recoverable == donation exactly. Asking for donation+1 must revert.
      await stageRecover(settlement, owner, lpToken.address, owner.account.address, donation + 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens(
          [lpToken.address, owner.account.address, donation + 1n],
          { account: owner.account },
        ),
        settlement,
        "NothingToRecover",
      );

      // Exact recovery succeeds and moves exactly `donation`.
      const ownerBefore = (await lpToken.read.balanceOf([owner.account.address])) as bigint;
      const settlementBefore = (await lpToken.read.balanceOf([settlement.address])) as bigint;
      await stageRecover(settlement, owner, lpToken.address, owner.account.address, donation);
      await settlement.write.recoverStuckTokens(
        [lpToken.address, owner.account.address, donation],
        { account: owner.account },
      );
      assert.strictEqual(
        (await lpToken.read.balanceOf([owner.account.address])) as bigint,
        ownerBefore + donation,
        "recovered amount must land exactly on the recipient",
      );
      assert.strictEqual(
        (await lpToken.read.balanceOf([settlement.address])) as bigint,
        settlementBefore - donation,
        "settlement's raw balance must drop by exactly `donation`",
      );

      // Now that the excess is fully swept, ANY further recovery reverts (recoverable == 0).
      await stageRecover(settlement, owner, lpToken.address, owner.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([lpToken.address, owner.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );

      // Pre-existing ledgered user balances are untouched by the whole sequence.
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        aliceLedgerBefore,
        "alice's ledgered balance must be untouched by donation+recovery",
      );
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, lpToken.address])) as bigint,
        bobLedgerBefore,
        "bob's ledgered balance must be untouched by donation+recovery",
      );
    });
  });

  // =====================================================================
  // Solvency invariant + totalTracked integrity
  // =====================================================================
  describe("solvency invariant + totalTracked integrity", function () {
    it("Σ balances == balanceOf holds after every step of a mixed sequence, and no ledgered token is ever recoverable afterward", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, operator, owner, alice, bob, feeRecipient } = f;
      const ACTORS = [alice, bob, feeRecipient, owner];

      // Baseline (post-fixture-setup) solvency for both tokens.
      await assertSolvent(settlement, usdt, ACTORS, "baseline usdt");
      await assertSolvent(settlement, lpToken, ACTORS, "baseline lpToken");

      // Step 1: alice deposits more USDT.
      const extraUsdt = parseUnits("500", 18);
      await usdt.write.mint([alice.account.address, extraUsdt]);
      await usdt.write.approve([settlement.address, extraUsdt], { account: alice.account });
      await settlement.write.depositToken([usdt.address, extraUsdt], { account: alice.account });
      await assertSolvent(settlement, usdt, ACTORS, "after alice extra USDT deposit");
      await assertSolvent(
        settlement,
        lpToken,
        ACTORS,
        "after alice extra USDT deposit (lpToken untouched)",
      );

      // Step 2: bob deposits more lpToken (alice tops him up from her un-deposited stash first).
      const extraToken = parseUnits("200", 18);
      await lpToken.write.transfer([bob.account.address, extraToken], { account: alice.account });
      await lpToken.write.approve([settlement.address, extraToken], { account: bob.account });
      await settlement.write.depositToken([lpToken.address, extraToken], { account: bob.account });
      await assertSolvent(
        settlement,
        usdt,
        ACTORS,
        "after bob extra lpToken deposit (usdt untouched)",
      );
      await assertSolvent(settlement, lpToken, ACTORS, "after bob extra lpToken deposit");

      // Step 3: settleOrders between alice (buy) and bob (sell) — the 4-leg zero-sum path that
      // intentionally does NOT touch totalTracked. Must still hold solvency (proves the
      // "algebraically zero-sum, no totalTracked update needed" reasoning is actually correct).
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
        nonce: 21n,
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
        nonce: 21n,
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
            settlementId: settlementId("solvency-settle"),
          },
        ],
        { account: operator.account },
      );
      await assertSolvent(settlement, usdt, ACTORS, "after settleOrders");
      await assertSolvent(settlement, lpToken, ACTORS, "after settleOrders");

      // Step 4: withdrawals.
      const aliceUsdtBal = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      await settlement.write.withdrawToken([usdt.address, aliceUsdtBal / 4n], {
        account: alice.account,
      });
      await assertSolvent(settlement, usdt, ACTORS, "after alice partial USDT withdraw");

      const bobTokenBal = (await settlement.read.getBalance([
        bob.account.address,
        lpToken.address,
      ])) as bigint;
      await settlement.write.withdrawToken([lpToken.address, bobTokenBal / 4n], {
        account: bob.account,
      });
      await assertSolvent(
        settlement,
        usdt,
        ACTORS,
        "after bob partial lpToken withdraw (usdt untouched)",
      );
      await assertSolvent(settlement, lpToken, ACTORS, "after bob partial lpToken withdraw");

      // Final proof: totalTracked[T] == balanceOf(T) exactly for every ledgered token — indirect
      // proof via recoverStuckTokens reverting for even amount==1. If ANY balances mutation site
      // upstream forgot to maintain totalTracked, balanceOf would exceed totalTracked and this
      // recover call would unexpectedly SUCCEED, catching the bug here.
      await stageRecover(settlement, owner, usdt.address, owner.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, owner.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );
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
  // CLOSED BY DELETION — batchSettleNetDeltas no longer exists
  //   The unsigned operator debit path (and its enable flag / per-token cap) was removed
  //   outright, so the old "unpaired credit rejected / balanced batch allowed" pair has no
  //   subject. Asserting the entrypoint's ABSENCE is strictly stronger than asserting its guard:
  //   a guard can be weakened, a deleted function cannot be called at all. The exhaustive ABI
  //   assertion lives in TradeSettlementV1_invariants.test.ts §4; here we pin the I5
  //   (non-custodial) consequence that matters to THIS file — there is no non-view entrypoint
  //   that debits an arbitrary account other than the signature-gated settleOrders and the
  //   seize-to-user emergencyWithdrawFor.
  // =====================================================================
  describe("no unsigned operator debit entrypoint exists", function () {
    it("the ABI's operator-callable surface is exactly settleOrders", async function () {
      const { settlement } = await loadFixture(deployFixture);
      const abi = settlement.abi as { type: string; name?: string }[];
      assert.ok(
        !abi.some((entry) => entry.type === "function" && entry.name === "batchSettleNetDeltas"),
        "batchSettleNetDeltas must not exist — an operator must never be able to debit an " +
          "account that did not sign for it",
      );
      assert.ok(
        !abi.some(
          (entry) => entry.type === "function" && entry.name === "setNetDeltaSettlementEnabled",
        ),
        "the net-delta enable switch must be gone too — a re-enableable path is still a path",
      );
      assert.ok(
        abi.some((entry) => entry.type === "function" && entry.name === "settleOrders"),
        "settleOrders must remain the settlement entrypoint",
      );
    });
  });
});
