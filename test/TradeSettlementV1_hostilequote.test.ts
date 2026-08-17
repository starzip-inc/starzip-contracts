/**
 * TradeSettlementV1 — HOSTILE / FROZEN QUOTE-ASSET behaviour.
 *
 * WHY THIS FILE EXISTS. The remediation deleted `setUsdt`, which made the payment-asset
 * binding immutable and closed an owner drain. The cost of that trade is when the payment
 * asset itself turns hostile — the issuer pauses it, blacklists the settlement contract, or
 * blacklists one user — TradeSettlementV1 has NO lever that reopens the exit. `withdrawToken`,
 * `batchWithdraw` and `emergencyWithdrawFor` all terminate in a `safeTransfer` of that same asset,
 * so they fail together, and the only remaining escape is a 48h-timelocked upgrade.
 *
 * Before this file the repo could not even construct that state: `contracts/USDT.sol` is a 27-line
 * OZ ERC20 whose transfers cannot fail. `contracts/mocks/MockHostileStablecoin.sol` supplies the
 * three issuer levers (pause / blacklist / silent-false transfer) and this suite PINS the observed
 * behaviour of each, including the results that are NOT intuitive:
 *
 *   1. `settleOrders` keeps working at full speed while every exit is frozen, because it makes no
 *      external call — the ledger is pure storage. Trading continues over funds nobody can redeem.
 * Same shape as (ERC20V1 pause), now confirmed for the QUOTE side.
 *   2. That same property is also the only user-side escape hatch: a blacklisted user can trade out
 *      of the frozen asset into a healthy one and withdraw that instead.
 *   3. `setQuoteAsset(q,false)` stops new deposits and new trades in the frozen asset but does NOT
 *      restore withdrawals (withdrawals consult no registry) — it is a containment lever, not a fix.
 *   4. Per-token ledgers make the blast radius exactly one asset: a second quote asset is fully
 *      unaffected. The one leak is `batchWithdraw`, where a single hostile entry reverts the whole
 *      array and takes the healthy tokens in that call down with it.
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

describe("TradeSettlementV1 — hostile / frozen quote asset", function () {
  const KEYS: Record<string, Hex> = {
    owner: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    operator: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    alice: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    bob: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  };

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

  const sid = (seed: string): Hex => keccak256(toBytes(`tl5-${seed}`));

  const BASE_FUND = parseUnits("1000", 18);
  const QUOTE_FUND = parseUnits("10000", 18);

  /**
   * base  — an ordinary healthy ERC20 acting as the listed BASE asset.
   * husd  — MockHostileStablecoin, listed as a quote asset. The asset that goes hostile.
   * safe  — an ordinary healthy ERC20, listed as a SECOND quote asset. The blast-radius control.
   */
  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, operator, alice, bob, feeRecipient] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const base = await viem.deployContract("USDT", [owner.account.address, 18]);
    const safe = await viem.deployContract("USDT", [owner.account.address, 18]);
    const husd = await viem.deployContract("MockHostileStablecoin", ["Hostile USD", "HUSD", 18]);

    const impl = await viem.deployContract("TradeSettlementV1", []);
    const initData = encodeFunctionData({
      abi: impl.abi,
      functionName: "initialize",
      args: [feeRecipient.account.address, zeroAddress],
    });
    const proxy = await viem.deployContract("ERC1967Proxy", [impl.address, initData]);
    const settlement = await viem.getContractAt("TradeSettlementV1", proxy.address);

    // Operator via the 24h timelock (initialize seeds no operator).
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
    await settlement.write.setQuoteAsset([husd.address, true]);
    await settlement.write.setQuoteAsset([safe.address, true]);

    for (const trader of [alice, bob]) {
      await base.write.mint([trader.account.address, BASE_FUND]);
      await base.write.approve([settlement.address, BASE_FUND], { account: trader.account });
      await settlement.write.depositToken([base.address, BASE_FUND], { account: trader.account });

      await husd.write.mint([trader.account.address, QUOTE_FUND]);
      await husd.write.approve([settlement.address, QUOTE_FUND], { account: trader.account });
      await settlement.write.depositToken([husd.address, QUOTE_FUND], { account: trader.account });

      await safe.write.mint([trader.account.address, QUOTE_FUND]);
      await safe.write.approve([settlement.address, QUOTE_FUND], { account: trader.account });
      await settlement.write.depositToken([safe.address, QUOTE_FUND], { account: trader.account });
    }

    // Spare, undeposited HUSD so deposit-while-hostile can be attempted without re-minting.
    const SPARE = parseUnits("100", 18);
    await husd.write.mint([alice.account.address, SPARE]);
    await husd.write.approve([settlement.address, SPARE], { account: alice.account });

    const expiry = (await time.latest()) + 3600n;

    return {
      settlement,
      base,
      husd,
      safe,
      owner,
      operator,
      alice,
      bob,
      feeRecipient,
      publicClient,
      chainId,
      expiry,
      spare: SPARE,
    };
  }

  type Fixture = Awaited<ReturnType<typeof deployFixture>>;

  /** alice BUYS `baseAmount` base for `quoteAmount` of `quoteToken` from bob (1:1 limit, no fee). */
  async function buildPair(
    f: Fixture,
    opts: {
      quoteToken: `0x${string}`;
      baseAmount: bigint;
      quoteAmount: bigint;
      nonce: bigint;
      buyerKey?: Hex;
      sellerKey?: Hex;
      buyer?: `0x${string}`;
      seller?: `0x${string}`;
    },
  ) {
    const { alice, bob, chainId, settlement, expiry, base } = f;
    const buyer = opts.buyer ?? alice.account.address;
    const seller = opts.seller ?? bob.account.address;
    const common = {
      baseToken: base.address,
      quoteToken: opts.quoteToken,
      baseAmount: opts.baseAmount,
      quoteAmount: opts.quoteAmount,
      maxFeeRate: 0n,
      nonce: opts.nonce,
      expiry,
    };
    const buyOrder: Order = { account: buyer, isBuy: true, ...common };
    const sellOrder: Order = { account: seller, isBuy: false, ...common };
    const domain = {
      name: "StarZipTradeSettlement",
      version: "1",
      chainId,
      verifyingContract: settlement.address,
    } as const;
    const buySig = await signTypedData({
      privateKey: opts.buyerKey ?? KEYS.alice,
      domain,
      types: ORDER_TYPES,
      primaryType: "Order",
      message: buyOrder,
    });
    const sellSig = await signTypedData({
      privateKey: opts.sellerKey ?? KEYS.bob,
      domain,
      types: ORDER_TYPES,
      primaryType: "Order",
      message: sellOrder,
    });
    return { buyOrder, buySig, sellOrder, sellSig };
  }

  /** Settle one full fill of a freshly built pair. Returns nothing; throws on revert. */
  async function settle(
    f: Fixture,
    opts: {
      quoteToken: `0x${string}`;
      baseAmount: bigint;
      quoteAmount: bigint;
      nonce: bigint;
      seed: string;
      buyer?: `0x${string}`;
      seller?: `0x${string}`;
      buyerKey?: Hex;
      sellerKey?: Hex;
    },
  ) {
    const { buyOrder, buySig, sellOrder, sellSig } = await buildPair(f, opts);
    return f.settlement.write.settleOrders(
      [
        {
          buyOrder: buyOrder,
          buySig: buySig,
          sellOrder: sellOrder,
          sellSig: sellSig,
          fillBaseAmount: opts.baseAmount,
          fillQuoteAmount: opts.quoteAmount,
          buyerFee: 0n,
          sellerFee: 0n,
          settlementId: sid(opts.seed),
        },
      ],
      { account: f.operator.account },
    );
  }

  const bal = (f: Fixture, u: `0x${string}`, t: `0x${string}`) =>
    f.settlement.read.getBalance([u, t]) as Promise<bigint>;

  // =====================================================================
  // 0 — Control: with a healthy quote asset everything works.
  // =====================================================================
  describe("0 — control (healthy HUSD)", function () {
    it("deposits, settles and withdraws normally before any lever is flipped", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice } = f;

      await settle(f, {
        quoteToken: husd.address,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 1n,
        seed: "control",
      });

      const before = await bal(f, alice.account.address, husd.address);
      await settlement.write.withdrawToken([husd.address, parseUnits("500", 18)], {
        account: alice.account,
      });
      assert.strictEqual(
        await bal(f, alice.account.address, husd.address),
        before - parseUnits("500", 18),
        "control withdrawal must debit the ledger",
      );
    });
  });

  // =====================================================================
  // 1 — Issuer blacklists the SETTLEMENT contract (system-wide freeze).
  // =====================================================================
  describe("1 — issuer blacklists the settlement contract", function () {
    it("freezes withdrawToken, batchWithdraw AND emergencyWithdrawFor simultaneously", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice, owner } = f;
      await husd.write.setBlacklisted([settlement.address, true]);

      const ledgerBefore = await bal(f, alice.account.address, husd.address);

      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([husd.address, parseUnits("1", 18)], {
          account: alice.account,
        }),
        husd,
        "HostileBlacklisted",
      );
      await assertions.revertWithCustomError(
        settlement.write.batchWithdraw([[husd.address]], { account: alice.account }),
        husd,
        "HostileBlacklisted",
      );
      await assertions.revertWithCustomError(
        settlement.write.emergencyWithdrawFor([alice.account.address, husd.address], {
          account: owner.account,
        }),
        husd,
        "HostileBlacklisted",
      );

      // No partial state: all three revert atomically, the ledger is untouched.
      assert.strictEqual(
        await bal(f, alice.account.address, husd.address),
        ledgerBefore,
        "a failed exit must never debit the ledger",
      );
    });

    it("blocks new deposits of the frozen asset", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice, spare } = f;
      await husd.write.setBlacklisted([settlement.address, true]);

      await assertions.revertWithCustomError(
        settlement.write.depositToken([husd.address, spare], { account: alice.account }),
        husd,
        "HostileBlacklisted",
      );
    });

    it("KEEPS SETTLING at full size while every exit is frozen (settleOrders makes no external call)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, base, alice, bob } = f;
      await husd.write.setBlacklisted([settlement.address, true]);

      const baseAmount = parseUnits("100", 18);
      const quoteAmount = parseUnits("1000", 18);
      const aliceQuote0 = await bal(f, alice.account.address, husd.address);
      const bobQuote0 = await bal(f, bob.account.address, husd.address);

      // No revert: the ledger is pure storage, so the issuer's freeze does not reach it.
      await settle(f, {
        quoteToken: husd.address,
        baseAmount,
        quoteAmount,
        nonce: 10n,
        seed: "frozen-settle",
      });

      assert.strictEqual(
        await bal(f, alice.account.address, husd.address),
        aliceQuote0 - quoteAmount,
        "buyer debited in the frozen asset",
      );
      assert.strictEqual(
        await bal(f, bob.account.address, husd.address),
        bobQuote0 + quoteAmount,
        "seller credited in the frozen asset",
      );

      // The credit is real ledger value that the seller CANNOT redeem — this is the hazard.
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([husd.address, quoteAmount], { account: bob.account }),
        husd,
        "HostileBlacklisted",
      );

      // And the base leg the buyer received IS redeemable, since `base` is healthy.
      await settlement.write.withdrawToken([base.address, baseAmount], { account: alice.account });
    });

    it("leaves a second, healthy quote asset completely unaffected (per-token ledgers)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, safe, alice, bob } = f;
      await husd.write.setBlacklisted([settlement.address, true]);

      // Trade in `safe`.
      await settle(f, {
        quoteToken: safe.address,
        baseAmount: parseUnits("50", 18),
        quoteAmount: parseUnits("500", 18),
        nonce: 20n,
        seed: "safe-unaffected",
      });

      // Withdraw `safe` — both single and batch.
      await settlement.write.withdrawToken([safe.address, parseUnits("100", 18)], {
        account: bob.account,
      });
      await settlement.write.batchWithdraw([[safe.address]], { account: alice.account });
      assert.strictEqual(
        await bal(f, alice.account.address, safe.address),
        0n,
        "healthy asset fully withdrawable while the other asset is frozen",
      );
    });

    it("batchWithdraw is the ONE cross-asset leak: a hostile entry reverts the healthy ones with it", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, safe, alice } = f;
      await husd.write.setBlacklisted([settlement.address, true]);

      const safeBefore = await bal(f, alice.account.address, safe.address);

      // Mixed array: reverts wholly, so the HEALTHY token is not withdrawn either.
      await assertions.revertWithCustomError(
        settlement.write.batchWithdraw([[safe.address, husd.address]], { account: alice.account }),
        husd,
        "HostileBlacklisted",
      );
      assert.strictEqual(
        await bal(f, alice.account.address, safe.address),
        safeBefore,
        "healthy token stays locked when batched with a hostile one",
      );

      // Workaround is purely client-side: omit the hostile token from the array.
      await settlement.write.batchWithdraw([[safe.address]], { account: alice.account });
      assert.strictEqual(await bal(f, alice.account.address, safe.address), 0n);
    });
  });

  // =====================================================================
  // 2 — Issuer blacklists ONE USER (sanctions case).
  // =====================================================================
  describe("2 — issuer blacklists a single user", function () {
    it("freezes only that user's exit; other users are unaffected", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice, bob } = f;
      await husd.write.setBlacklisted([alice.account.address, true]);

      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([husd.address, parseUnits("1", 18)], {
          account: alice.account,
        }),
        husd,
        "HostileBlacklisted",
      );
      await settlement.write.withdrawToken([husd.address, parseUnits("1", 18)], {
        account: bob.account,
      });
    });

    it("defeats the owner backstop too — emergencyWithdrawFor cannot rescue a blacklisted user", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice, owner } = f;
      await husd.write.setBlacklisted([alice.account.address, true]);

      // The transfer is destination-locked to `_user`, so the owner cannot route around the ban.
      await assertions.revertWithCustomError(
        settlement.write.emergencyWithdrawFor([alice.account.address, husd.address], {
          account: owner.account,
        }),
        husd,
        "HostileBlacklisted",
      );
    });

    it("ESCAPE HATCH: a blacklisted user trades out of the frozen asset and withdraws the proceeds", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, base, alice } = f;
      await husd.write.setBlacklisted([alice.account.address, true]);

      const baseAmount = parseUnits("100", 18);
      const quoteAmount = parseUnits("1000", 18);
      const baseBefore = await bal(f, alice.account.address, base.address);

      // alice spends frozen HUSD and receives healthy base — settleOrders never touches the token.
      await settle(f, {
        quoteToken: husd.address,
        baseAmount,
        quoteAmount,
        nonce: 30n,
        seed: "escape-hatch",
      });

      await settlement.write.withdrawToken([base.address, baseBefore + baseAmount], {
        account: alice.account,
      });
      assert.strictEqual(
        await bal(f, alice.account.address, base.address),
        0n,
        "blacklisted user exited via the base asset",
      );
    });
  });

  // =====================================================================
  // 3 — Issuer PAUSES the whole token.
  // =====================================================================
  describe("3 — issuer pauses the quote asset", function () {
    it("freezes all three exits and deposits, while settlement continues", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice, owner, spare } = f;
      await husd.write.setPaused([true]);

      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([husd.address, parseUnits("1", 18)], {
          account: alice.account,
        }),
        husd,
        "HostilePaused",
      );
      await assertions.revertWithCustomError(
        settlement.write.batchWithdraw([[husd.address]], { account: alice.account }),
        husd,
        "HostilePaused",
      );
      await assertions.revertWithCustomError(
        settlement.write.emergencyWithdrawFor([alice.account.address, husd.address], {
          account: owner.account,
        }),
        husd,
        "HostilePaused",
      );
      await assertions.revertWithCustomError(
        settlement.write.depositToken([husd.address, spare], { account: alice.account }),
        husd,
        "HostilePaused",
      );

      await settle(f, {
        quoteToken: husd.address,
        baseAmount: parseUnits("10", 18),
        quoteAmount: parseUnits("100", 18),
        nonce: 40n,
        seed: "paused-settle",
      });
    });

    it("is fully reversible: unpausing restores every exit with the ledger intact", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice } = f;

      const before = await bal(f, alice.account.address, husd.address);
      await husd.write.setPaused([true]);
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([husd.address, before], { account: alice.account }),
        husd,
        "HostilePaused",
      );
      await husd.write.setPaused([false]);

      await settlement.write.withdrawToken([husd.address, before], { account: alice.account });
      assert.strictEqual(
        await bal(f, alice.account.address, husd.address),
        0n,
        "no ledger corruption survives the freeze — only liveness was lost",
      );
      assert.strictEqual(
        (await husd.read.balanceOf([alice.account.address])) as bigint,
        before + f.spare,
        "user received the real tokens once the freeze lifted",
      );
    });
  });

  // =====================================================================
  // 4 — Token fails SILENTLY (returns false instead of reverting).
  // =====================================================================
  describe("4 — quote asset returns false instead of reverting", function () {
    it("SafeERC20 converts the silent failure into a revert — no ledger debit without a transfer", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice } = f;
      await husd.write.setSilentFailure([true]);

      const ledgerBefore = await bal(f, alice.account.address, husd.address);
      const walletBefore = (await husd.read.balanceOf([alice.account.address])) as bigint;

      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([husd.address, parseUnits("100", 18)], {
          account: alice.account,
        }),
        settlement,
        "SafeERC20FailedOperation",
      );
      await assertions.revertWithCustomError(
        settlement.write.batchWithdraw([[husd.address]], { account: alice.account }),
        settlement,
        "SafeERC20FailedOperation",
      );

      assert.strictEqual(
        await bal(f, alice.account.address, husd.address),
        ledgerBefore,
        "ledger must not be debited when the token silently refuses the transfer",
      );
      assert.strictEqual(
        (await husd.read.balanceOf([alice.account.address])) as bigint,
        walletBefore,
        "and the user received nothing",
      );
    });
  });

  // =====================================================================
  // 5 — Containment levers actually available to the operator (runbook input).
  // =====================================================================
  describe("5 — containment levers", function () {
    it("setQuoteAsset(q,false) stops new deposits and new trades in the frozen asset", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice, spare } = f;
      await settlement.write.setQuoteAsset([husd.address, false]);

      await assertions.revertWithCustomError(
        settlement.write.depositToken([husd.address, spare], { account: alice.account }),
        settlement,
        "UnsupportedToken",
      );
      await assertions.revertWithCustomError(
        settle(f, {
          quoteToken: husd.address,
          baseAmount: parseUnits("10", 18),
          quoteAmount: parseUnits("100", 18),
          nonce: 50n,
          seed: "delisted-settle",
        }),
        settlement,
        "UnsupportedQuote",
      );
    });

    it("delisting does NOT restore withdrawals — it is containment, not a fix", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice } = f;
      await husd.write.setPaused([true]);
      await settlement.write.setQuoteAsset([husd.address, false]);

      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([husd.address, parseUnits("1", 18)], {
          account: alice.account,
        }),
        husd,
        "HostilePaused",
      );
    });

    it("a DELISTED asset stays withdrawable once the token itself is healthy again", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice } = f;
      await husd.write.setPaused([true]);
      await settlement.write.setQuoteAsset([husd.address, false]);
      await husd.write.setPaused([false]);

      const before = await bal(f, alice.account.address, husd.address);
      await settlement.write.withdrawToken([husd.address, before], { account: alice.account });
      assert.strictEqual(await bal(f, alice.account.address, husd.address), 0n);
    });

    it("OPS TRAP: delisting the QUOTE registry alone does not stop deposits of a dual-listed asset", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, alice, spare } = f;

      // An asset that is in BOTH registries (quote + base) passes `_deposit`'s OR-gate on either
      // membership, so a one-sided delist leaves the deposit door open.
      await settlement.write.setSupportedToken([husd.address, true]);
      await settlement.write.setQuoteAsset([husd.address, false]);

      await settlement.write.depositToken([husd.address, spare], { account: alice.account });

      // Both registries must be cleared for containment to hold.
      await settlement.write.setSupportedToken([husd.address, false]);
      await husd.write.mint([alice.account.address, spare]);
      await husd.write.approve([settlement.address, spare], { account: alice.account });
      await assertions.revertWithCustomError(
        settlement.write.depositToken([husd.address, spare], { account: alice.account }),
        settlement,
        "UnsupportedToken",
      );
    });

    it("NO UPGRADE CAN FIX A BLACKLIST: the from-side ban binds the settlement ADDRESS, not its code", async function () {
      const f = await loadFixture(deployFixture);
      const { husd, alice, bob } = f;

      // The gate is on `_update(from, ...)`, so it applies to every outbound path a holder has —
      // `transfer` AND a third party's `transferFrom` against a granted allowance alike. A new
      // TradeSettlementV1 implementation runs at the SAME address and is therefore the same
      // blacklisted `from`: replacing the code cannot move a single unit out. Recovery of a
      // permanently blacklisted balance is an ISSUER action (unfreeze, or burn-and-reissue), and
      // the 48h upgrade path exists to re-credit the ledger afterwards — not to force the transfer.
      await husd.write.approve([bob.account.address, parseUnits("1", 18)], {
        account: alice.account,
      });
      await husd.write.setBlacklisted([alice.account.address, true]);

      await assertions.revertWithCustomError(
        husd.write.transfer([bob.account.address, parseUnits("1", 18)], { account: alice.account }),
        husd,
        "HostileBlacklisted",
      );
      await assertions.revertWithCustomError(
        husd.write.transferFrom([alice.account.address, bob.account.address, parseUnits("1", 18)], {
          account: bob.account,
        }),
        husd,
        "HostileBlacklisted",
      );
    });

    it("settlement pause() halts trading and deposits but never withdrawals", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, husd, safe, alice, spare } = f;
      await settlement.write.pause();

      await assertions.revertWithCustomError(
        settlement.write.depositToken([husd.address, spare], { account: alice.account }),
        settlement,
        "EnforcedPause",
      );
      await assertions.revertWithCustomError(
        settle(f, {
          quoteToken: safe.address,
          baseAmount: parseUnits("10", 18),
          quoteAmount: parseUnits("100", 18),
          nonce: 60n,
          seed: "settlement-paused",
        }),
        settlement,
        "EnforcedPause",
      );

      // Exits remain open — pause must never trap users.
      await settlement.write.withdrawToken([safe.address, parseUnits("1", 18)], {
        account: alice.account,
      });
    });
  });
});
