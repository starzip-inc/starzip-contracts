/**
 * TradeSettlementV1 — per-asset withdrawal RATE limit.
 *
 * The contract had a withdrawal DELAY (timing) but no withdrawal AMOUNT cap. This suite covers the mechanism that was
 * added for it — deliberately mechanism only, with the policy VALUE left at its shipped default of
 * 0 (disabled) for every asset.
 *
 * The suite is organised around the property the feature must not break: this is a SPEED LIMIT, not
 * a confiscation. Concretely it proves, on-chain rather than by reading the NatSpec:
 *   - default-off is a true no-op (every pre-existing withdrawal path behaves identically);
 *   - a throttled balance is always fully recoverable, and the refill happens on the pure clock with
 *     no transaction and no owner cooperation;
 *   - the owner cannot lower a limit into a freeze (constant floor, and 0 means UNLIMITED so the
 *     obvious hostile input loosens rather than tightens);
 *   - `emergencyWithdrawFor` — the owner backstop that force-exits a balance TO ITS OWNER — ignores
 *     the limit entirely;
 *   - per-asset counters are independent inside `batchWithdraw`.
 * It also PINS the two honest limitations rather than hiding them: the fixed-window boundary burst
 * (up to 2x the limit across two adjacent blocks) and the fact that base tokens are out of scope.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import { parseUnits, encodeFunctionData, zeroAddress } from "viem";

describe("TradeSettlementV1 withdrawal rate limit", function () {
  const WINDOW = 86400n; // WITHDRAWAL_WINDOW
  const MIN_UNITS = 10_000n; // MIN_WITHDRAWAL_LIMIT_UNITS
  const UINT192_MAX = (1n << 192n) - 1n;
  const MAX_UINT256 = (1n << 256n) - 1n;

  // Deposits are deliberately far larger than any limit used below, so every rejection in this file
  // is attributable to the RATE limit and never to an insufficient balance.
  const USDT_DEPOSIT = parseUnits("100000", 18);
  const USDC_DEPOSIT = parseUnits("100000", 6);
  const BASE_DEPOSIT = parseUnits("100000", 18);

  /**
   * Minimal fixture: no settlement, no orders. lives entirely on the deposit/withdraw path, so
   * balances are created by direct deposits and no operator is wired at all (settleOrders is never
   * called here). `contracts/USDT.sol` is reused as-is for all three assets — it takes `decimals_` in
   * its constructor and is owner-mintable — as the 18-dec quote, the 6-dec quote and the base token.
   */
  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, alice, bob, feeRecipient] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]); // 18-dec quote
    const usdc = await viem.deployContract("USDT", [owner.account.address, 6]); // 6-dec quote
    const baseTok = await viem.deployContract("USDT", [owner.account.address, 18]); // base asset

    const settlementImpl = await viem.deployContract("TradeSettlementV1", []);
    const initData = encodeFunctionData({
      abi: settlementImpl.abi,
      functionName: "initialize",
      args: [feeRecipient.account.address, zeroAddress],
    });
    const proxy = await viem.deployContract("ERC1967Proxy", [settlementImpl.address, initData]);
    const settlement = await viem.getContractAt("TradeSettlementV1", proxy.address);

    await settlement.write.setQuoteAsset([usdt.address, true]);
    await settlement.write.setQuoteAsset([usdc.address, true]);
    await settlement.write.setSupportedToken([baseTok.address, true]);

    for (const trader of [alice, bob]) {
      await usdt.write.mint([trader.account.address, USDT_DEPOSIT]);
      await usdt.write.approve([settlement.address, USDT_DEPOSIT], { account: trader.account });
      await settlement.write.depositToken([usdt.address, USDT_DEPOSIT], {
        account: trader.account,
      });

      await usdc.write.mint([trader.account.address, USDC_DEPOSIT]);
      await usdc.write.approve([settlement.address, USDC_DEPOSIT], { account: trader.account });
      await settlement.write.depositToken([usdc.address, USDC_DEPOSIT], {
        account: trader.account,
      });

      await baseTok.write.mint([trader.account.address, BASE_DEPOSIT]);
      await baseTok.write.approve([settlement.address, BASE_DEPOSIT], { account: trader.account });
      await settlement.write.depositToken([baseTok.address, BASE_DEPOSIT], {
        account: trader.account,
      });
    }

    return { settlement, usdt, usdc, baseTok, owner, alice, bob, feeRecipient, publicClient };
  }

  const usdtFloor = MIN_UNITS * 10n ** 18n;
  const usdcFloor = MIN_UNITS * 10n ** 6n;

  /** Absolute unix timestamp at which the CURRENT window's allowance refills. */
  function resetAtFor(now: bigint): bigint {
    return (now / WINDOW + 1n) * WINDOW;
  }

  // ==========================================================================================
  // 1. Default 0 = disabled. Every pre-existing behaviour must be bit-identical.
  // ==========================================================================================
  describe("default (limit 0) — no behavioural change", function () {
    it("ships disabled for every asset, quote and base alike", async function () {
      const { settlement, usdt, usdc, baseTok } = await loadFixture(deployFixture);
      for (const t of [usdt, usdc, baseTok]) {
        assert.strictEqual(await settlement.read.dailyWithdrawalLimit([t.address]), 0n);
      }
    });

    it("reports an unrestricted allowance (max uint256, resetAt 0)", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      const [remaining, resetAt] = (await settlement.read.remainingWithdrawalAllowance([
        alice.account.address,
        usdt.address,
      ])) as [bigint, bigint];
      assert.strictEqual(remaining, MAX_UINT256);
      assert.strictEqual(resetAt, 0n);
    });

    it("withdrawToken still exits the FULL balance in one call", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      await settlement.write.withdrawToken([usdt.address, USDT_DEPOSIT], {
        account: alice.account,
      });
      assert.strictEqual(
        await settlement.read.getBalance([alice.account.address, usdt.address]),
        0n,
      );
      assert.strictEqual(await usdt.read.balanceOf([alice.account.address]), USDT_DEPOSIT);
    });

    it("batchWithdraw still empties every asset, and writes no window state", async function () {
      const { settlement, usdt, usdc, baseTok, alice } = await loadFixture(deployFixture);
      await settlement.write.batchWithdraw([[usdt.address, usdc.address, baseTok.address]], {
        account: alice.account,
      });
      for (const [t, amt] of [
        [usdt, USDT_DEPOSIT],
        [usdc, USDC_DEPOSIT],
        [baseTok, BASE_DEPOSIT],
      ] as const) {
        assert.strictEqual(
          await settlement.read.getBalance([alice.account.address, t.address]),
          0n,
        );
        assert.strictEqual(await t.read.balanceOf([alice.account.address]), amt);
        // The disabled path must not touch the accounting slot at all.
        const w = (await settlement.read.withdrawalWindows([alice.account.address, t.address])) as [
          bigint,
          bigint,
        ];
        assert.deepStrictEqual(w, [0n, 0n]);
      }
    });
  });

  // ==========================================================================================
  // 2. setDailyWithdrawalLimit — the sealed floor is what stops a limit becoming a freeze.
  // ==========================================================================================
  describe("setDailyWithdrawalLimit", function () {
    it("only the owner may set it", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      await assertions.revert(
        settlement.write.setDailyWithdrawalLimit([usdt.address, usdtFloor], {
          account: alice.account,
        }),
      );
    });

    it("rejects a limit BELOW the sealed floor — the owner cannot strangle withdrawals", async function () {
      const { settlement, usdt, usdc } = await loadFixture(deployFixture);
      // 1 wei: the naive strangle. Rejected.
      await assertions.revertWithCustomError(
        settlement.write.setDailyWithdrawalLimit([usdt.address, 1n]),
        settlement,
        "InvalidWithdrawalLimit",
      );
      // Exactly one unit below the floor: still rejected, in BOTH decimal scales.
      await assertions.revertWithCustomError(
        settlement.write.setDailyWithdrawalLimit([usdt.address, usdtFloor - 1n]),
        settlement,
        "InvalidWithdrawalLimit",
      );
      await assertions.revertWithCustomError(
        settlement.write.setDailyWithdrawalLimit([usdc.address, usdcFloor - 1n]),
        settlement,
        "InvalidWithdrawalLimit",
      );
    });

    it("accepts EXACTLY the floor, scaled per asset decimals", async function () {
      const { settlement, usdt, usdc } = await loadFixture(deployFixture);
      await settlement.write.setDailyWithdrawalLimit([usdt.address, usdtFloor]);
      await settlement.write.setDailyWithdrawalLimit([usdc.address, usdcFloor]);
      assert.strictEqual(await settlement.read.dailyWithdrawalLimit([usdt.address]), usdtFloor);
      assert.strictEqual(await settlement.read.dailyWithdrawalLimit([usdc.address]), usdcFloor);
    });

    it("rejects a limit wider than the uint192 the counter is packed into", async function () {
      const { settlement, usdt } = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        settlement.write.setDailyWithdrawalLimit([usdt.address, UINT192_MAX + 1n]),
        settlement,
        "InvalidWithdrawalLimit",
      );
      await settlement.write.setDailyWithdrawalLimit([usdt.address, UINT192_MAX]);
      assert.strictEqual(await settlement.read.dailyWithdrawalLimit([usdt.address]), UINT192_MAX);
    });

    it("0 always disables (the escape from any limit is one owner tx, never blocked by the floor)", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      await settlement.write.setDailyWithdrawalLimit([usdt.address, usdtFloor]);
      await settlement.write.setDailyWithdrawalLimit([usdt.address, 0n]);
      assert.strictEqual(await settlement.read.dailyWithdrawalLimit([usdt.address]), 0n);
      // Unrestricted again: the whole balance leaves in one call.
      await settlement.write.withdrawToken([usdt.address, USDT_DEPOSIT], {
        account: alice.account,
      });
      assert.strictEqual(
        await settlement.read.getBalance([alice.account.address, usdt.address]),
        0n,
      );
    });

    it("is QUOTE-ASSET ONLY — a base token has no cached decimals, so no floor can be enforced", async function () {
      const { settlement, baseTok } = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        settlement.write.setDailyWithdrawalLimit([baseTok.address, parseUnits("10000", 18)]),
        settlement,
        "UnsupportedQuote",
      );
      // Honest scope: base-token withdrawals are consequently NOT rate-limited.
      assert.strictEqual(await settlement.read.dailyWithdrawalLimit([baseTok.address]), 0n);
    });

    it("emits WithdrawalLimitUpdated with the old and new values", async function () {
      const { settlement, usdt, publicClient } = await loadFixture(deployFixture);
      await settlement.write.setDailyWithdrawalLimit([usdt.address, usdtFloor]);
      const hash = await settlement.write.setDailyWithdrawalLimit([usdt.address, usdtFloor * 2n]);
      await publicClient.waitForTransactionReceipt({ hash });
      const events = await settlement.getEvents.WithdrawalLimitUpdated();
      const last = events[events.length - 1] as unknown as {
        args: { token: string; oldLimit: bigint; newLimit: bigint };
      };
      assert.strictEqual(last.args.oldLimit, usdtFloor);
      assert.strictEqual(last.args.newLimit, usdtFloor * 2n);
    });
  });

  // ==========================================================================================
  // 3. Enforcement + window boundaries.
  // ==========================================================================================
  describe("enforcement", function () {
    it("allows EXACTLY the limit and rejects limit+1 in the same window", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      const limit = usdtFloor;
      await settlement.write.setDailyWithdrawalLimit([usdt.address, limit]);

      // limit + 1 up front: rejected.
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([usdt.address, limit + 1n], { account: alice.account }),
        settlement,
        "WithdrawalLimitExceeded",
      );
      // Exactly the limit: accepted.
      await settlement.write.withdrawToken([usdt.address, limit], { account: alice.account });
      assert.strictEqual(await usdt.read.balanceOf([alice.account.address]), limit);

      // One wei more in the same window: rejected, and the allowance reads as exhausted.
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([usdt.address, 1n], { account: alice.account }),
        settlement,
        "WithdrawalLimitExceeded",
      );
      const [remaining] = (await settlement.read.remainingWithdrawalAllowance([
        alice.account.address,
        usdt.address,
      ])) as [bigint, bigint];
      assert.strictEqual(remaining, 0n);
    });

    it("accumulates across several withdrawals inside one window", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      const limit = usdtFloor;
      await settlement.write.setDailyWithdrawalLimit([usdt.address, limit]);

      const third = limit / 3n;
      await settlement.write.withdrawToken([usdt.address, third], { account: alice.account });
      await settlement.write.withdrawToken([usdt.address, third], { account: alice.account });
      const [remaining] = (await settlement.read.remainingWithdrawalAllowance([
        alice.account.address,
        usdt.address,
      ])) as [bigint, bigint];
      assert.strictEqual(remaining, limit - 2n * third);

      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([usdt.address, remaining + 1n], { account: alice.account }),
        settlement,
        "WithdrawalLimitExceeded",
      );
      await settlement.write.withdrawToken([usdt.address, remaining], { account: alice.account });
    });

    it("is per-ACCOUNT: exhausting alice's allowance leaves bob's untouched", async function () {
      const { settlement, usdt, alice, bob } = await loadFixture(deployFixture);
      const limit = usdtFloor;
      await settlement.write.setDailyWithdrawalLimit([usdt.address, limit]);
      await settlement.write.withdrawToken([usdt.address, limit], { account: alice.account });

      // The documented bypass: a second account has a full, independent budget. Pinned as a fact,
      // not an aspiration — this control bounds ONE account's exit speed, never total outflow.
      await settlement.write.withdrawToken([usdt.address, limit], { account: bob.account });
      assert.strictEqual(await usdt.read.balanceOf([bob.account.address]), limit);
    });

    it("refills at the exact window boundary, with no transaction and no owner action", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      const limit = usdtFloor;
      await settlement.write.setDailyWithdrawalLimit([usdt.address, limit]);
      await settlement.write.withdrawToken([usdt.address, limit], { account: alice.account });

      const now = await time.latest();
      const resetAt = resetAtFor(now);
      const [, reportedResetAt] = (await settlement.read.remainingWithdrawalAllowance([
        alice.account.address,
        usdt.address,
      ])) as [bigint, bigint];
      assert.strictEqual(reportedResetAt, resetAt, "view must report the exact refill timestamp");

      // One second BEFORE the boundary: still throttled.
      await time.setNextBlockTimestamp(resetAt - 1n);
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([usdt.address, 1n], { account: alice.account }),
        settlement,
        "WithdrawalLimitExceeded",
      );

      // AT the boundary: full allowance back, purely because the clock moved. No reset tx was sent
      // and the owner did nothing — that is what makes the limit a delay rather than a freeze.
      await time.setNextBlockTimestamp(resetAt);
      await settlement.write.withdrawToken([usdt.address, limit], { account: alice.account });
      assert.strictEqual(await usdt.read.balanceOf([alice.account.address]), limit * 2n);
    });

    it("a throttled balance is fully recoverable in ceil(balance/limit) windows", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      // 100,000 USDT at the 10,000/window floor => exactly 10 windows, and nothing is ever lost.
      const limit = usdtFloor;
      await settlement.write.setDailyWithdrawalLimit([usdt.address, limit]);
      const windows = USDT_DEPOSIT / limit;
      assert.strictEqual(USDT_DEPOSIT % limit, 0n);

      for (let i = 0n; i < windows; i++) {
        await settlement.write.withdrawToken([usdt.address, limit], { account: alice.account });
        if (i + 1n < windows) {
          await time.setNextBlockTimestamp(resetAtFor(await time.latest()));
        }
      }
      assert.strictEqual(
        await settlement.read.getBalance([alice.account.address, usdt.address]),
        0n,
      );
      assert.strictEqual(await usdt.read.balanceOf([alice.account.address]), USDT_DEPOSIT);
    });

    it("DOCUMENTED ARTIFACT: the fixed window permits a 2x burst across the boundary", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      const limit = usdtFloor;
      await settlement.write.setDailyWithdrawalLimit([usdt.address, limit]);

      const boundary = resetAtFor(await time.latest());
      // Spend the whole limit one second before the boundary...
      await time.setNextBlockTimestamp(boundary - 1n);
      await settlement.write.withdrawToken([usdt.address, limit], { account: alice.account });
      // ...and the whole limit again one second later. 2x the limit in two adjacent blocks. This is
      // the price of a 1-SSTORE fixed window (a rolling window would cost K slots per withdrawal);
      // size any policy limit as "2x this is survivable".
      await time.setNextBlockTimestamp(boundary);
      await settlement.write.withdrawToken([usdt.address, limit], { account: alice.account });
      assert.strictEqual(await usdt.read.balanceOf([alice.account.address]), limit * 2n);
    });

    it("a mid-window reduction saturates remaining at 0 instead of underflowing", async function () {
      const { settlement, usdt, alice } = await loadFixture(deployFixture);
      const wide = usdtFloor * 3n;
      await settlement.write.setDailyWithdrawalLimit([usdt.address, wide]);
      await settlement.write.withdrawToken([usdt.address, usdtFloor * 2n], {
        account: alice.account,
      });

      // Owner tightens to the floor — below what alice already spent this window.
      await settlement.write.setDailyWithdrawalLimit([usdt.address, usdtFloor]);
      const [remaining] = (await settlement.read.remainingWithdrawalAllowance([
        alice.account.address,
        usdt.address,
      ])) as [bigint, bigint];
      assert.strictEqual(remaining, 0n, "must saturate, not revert/underflow");
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([usdt.address, 1n], { account: alice.account }),
        settlement,
        "WithdrawalLimitExceeded",
      );

      // Nothing was clawed back, and the next window still delivers the (floored) allowance.
      assert.strictEqual(await usdt.read.balanceOf([alice.account.address]), usdtFloor * 2n);
      await time.setNextBlockTimestamp(resetAtFor(await time.latest()));
      await settlement.write.withdrawToken([usdt.address, usdtFloor], { account: alice.account });
    });

    it("does not restrict a base token (out of scope, and unsettable by construction)", async function () {
      const { settlement, usdt, baseTok, alice } = await loadFixture(deployFixture);
      await settlement.write.setDailyWithdrawalLimit([usdt.address, usdtFloor]);
      await settlement.write.withdrawToken([baseTok.address, BASE_DEPOSIT], {
        account: alice.account,
      });
      assert.strictEqual(await baseTok.read.balanceOf([alice.account.address]), BASE_DEPOSIT);
    });
  });

  // ==========================================================================================
  // 4. emergencyWithdrawFor — the owner backstop must NOT be metered.
  // ==========================================================================================
  describe("emergencyWithdrawFor exemption", function () {
    it("returns the FULL balance to the user even with the allowance exhausted", async function () {
      const { settlement, usdt, owner, alice } = await loadFixture(deployFixture);
      const limit = usdtFloor;
      await settlement.write.setDailyWithdrawalLimit([usdt.address, limit]);
      await settlement.write.withdrawToken([usdt.address, limit], { account: alice.account });
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([usdt.address, 1n], { account: alice.account }),
        settlement,
        "WithdrawalLimitExceeded",
      );

      const stillOwed = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      assert.ok(stillOwed > limit, "precondition: far more owed than one window's allowance");

      // Backstop fires for the WHOLE remainder, in one transaction, with no window accounting.
      await settlement.write.emergencyWithdrawFor([alice.account.address, usdt.address], {
        account: owner.account,
      });
      assert.strictEqual(
        await settlement.read.getBalance([alice.account.address, usdt.address]),
        0n,
      );
      // Funds went to the USER, not the owner: the exemption is not an exfiltration path.
      assert.strictEqual(await usdt.read.balanceOf([alice.account.address]), USDT_DEPOSIT);
      assert.strictEqual(await usdt.read.balanceOf([owner.account.address]), 0n);
    });

    it("does not consume the user's window allowance", async function () {
      const { settlement, usdt, owner, alice } = await loadFixture(deployFixture);
      const limit = usdtFloor * 5n;
      await settlement.write.setDailyWithdrawalLimit([usdt.address, limit]);
      await settlement.write.emergencyWithdrawFor([alice.account.address, usdt.address], {
        account: owner.account,
      });
      const [remaining] = (await settlement.read.remainingWithdrawalAllowance([
        alice.account.address,
        usdt.address,
      ])) as [bigint, bigint];
      assert.strictEqual(remaining, limit);
      const w = (await settlement.read.withdrawalWindows([
        alice.account.address,
        usdt.address,
      ])) as [bigint, bigint];
      assert.deepStrictEqual(w, [0n, 0n]);
    });
  });

  // ==========================================================================================
  // 5. batchWithdraw — per-asset counters, no shared budget.
  // ==========================================================================================
  describe("batchWithdraw", function () {
    it("meters each asset against its OWN limit and counter", async function () {
      const { settlement, usdt, usdc, baseTok, alice } = await loadFixture(deployFixture);
      // Both quote assets limited well ABOVE their deposited balances, so a correct implementation
      // clears the batch; a shared budget (or a decimals mix-up) would not.
      await settlement.write.setDailyWithdrawalLimit([usdt.address, USDT_DEPOSIT]);
      await settlement.write.setDailyWithdrawalLimit([usdc.address, USDC_DEPOSIT]);

      await settlement.write.batchWithdraw([[usdt.address, usdc.address, baseTok.address]], {
        account: alice.account,
      });
      assert.strictEqual(await usdt.read.balanceOf([alice.account.address]), USDT_DEPOSIT);
      assert.strictEqual(await usdc.read.balanceOf([alice.account.address]), USDC_DEPOSIT);
      assert.strictEqual(await baseTok.read.balanceOf([alice.account.address]), BASE_DEPOSIT);

      // Each counter recorded only its own asset's amount.
      const wUsdt = (await settlement.read.withdrawalWindows([
        alice.account.address,
        usdt.address,
      ])) as [bigint, bigint];
      const wUsdc = (await settlement.read.withdrawalWindows([
        alice.account.address,
        usdc.address,
      ])) as [bigint, bigint];
      assert.strictEqual(wUsdt[1], USDT_DEPOSIT);
      assert.strictEqual(wUsdc[1], USDC_DEPOSIT);
    });

    it("spending one asset's allowance does not reduce another's", async function () {
      const { settlement, usdt, usdc, alice } = await loadFixture(deployFixture);
      await settlement.write.setDailyWithdrawalLimit([usdt.address, usdtFloor]);
      await settlement.write.setDailyWithdrawalLimit([usdc.address, usdcFloor]);
      await settlement.write.withdrawToken([usdt.address, usdtFloor], { account: alice.account });

      const [remUsdc] = (await settlement.read.remainingWithdrawalAllowance([
        alice.account.address,
        usdc.address,
      ])) as [bigint, bigint];
      assert.strictEqual(remUsdc, usdcFloor);
      await settlement.write.withdrawToken([usdc.address, usdcFloor], { account: alice.account });
    });

    it("reverts the WHOLE batch rather than silently clamping one asset", async function () {
      const { settlement, usdt, usdc, alice } = await loadFixture(deployFixture);
      await settlement.write.setDailyWithdrawalLimit([usdt.address, USDT_DEPOSIT]); // fits
      await settlement.write.setDailyWithdrawalLimit([usdc.address, usdcFloor]); // does NOT fit

      await assertions.revertWithCustomError(
        settlement.write.batchWithdraw([[usdt.address, usdc.address]], { account: alice.account }),
        settlement,
        "WithdrawalLimitExceeded",
      );
      // Atomic: the usdt leg rolled back too, so no partial exit happened silently.
      assert.strictEqual(
        await settlement.read.getBalance([alice.account.address, usdt.address]),
        USDT_DEPOSIT,
      );
      assert.strictEqual(await usdt.read.balanceOf([alice.account.address]), 0n);

      // The documented remedy: take the allowed portion via withdrawToken.
      await settlement.write.withdrawToken([usdc.address, usdcFloor], { account: alice.account });
      assert.strictEqual(await usdc.read.balanceOf([alice.account.address]), usdcFloor);
    });
  });
});
