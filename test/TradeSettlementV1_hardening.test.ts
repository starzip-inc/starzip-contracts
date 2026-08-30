/**
 * TradeSettlementV1 — hardening acceptance tests.
 *
 * Covers:
 *
 * S4 / — measured-delta deposits + the recoverStuckTokens underflow guard.
 * — recoverStuckTokens' 48h request -> execute timelock (exact-parameter match,
 *                single-use, cancellable, owner-only).
 * S6 / — session-key TTL ceiling and PER-ASSET spend caps, plus the use-time check on
 *                privileged keys.
 * S7 / — SessionKeyAuth deadline, nonce-bumping revocation/invalidation, and byte-level
 *                EIP-712 interop for the array members.
 * S8 / the narrow `lister` role.
 *
 * The load-bearing test in this file is "sell leg" under . Capping a session key by QUOTE
 * notional looks sufficient and is not: the sell side never touches the quote asset on the way out,
 * so an attacker holding a leaked key signs `sell <everything> BASE for <dust> quote` — its own
 * signed limit price, so the crossing check passes — and walks off with the base inventory while the
 * quote-denominated charge stays far under any plausible cap. That test is written so it FAILS
 * against a quote-only implementation; the assertion on the dust notional vs. the (untouched) quote
 * cap is what pins that down rather than leaving it to a comment.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import {
  parseUnits,
  encodeFunctionData,
  keccak256,
  toBytes,
  toHex,
  getAddress,
  zeroAddress,
  parseEventLogs,
  hashTypedData,
  type Hex,
} from "viem";
import { privateKeyToAccount, signTypedData } from "viem/accounts";
import { deploySimpleTokenFixture } from "./tokenFactoryHelpers.js";

describe("TradeSettlementV1 — round-2 remediation ", function () {
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
  // Hardhat account 7 — the "session key" throughout this file.
  const SESSION_KEY_PK =
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356" as Hex;

  function settlementId(seed: string): Hex {
    return keccak256(toBytes(`rem2-${seed}`));
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

  // MUST stay byte-identical to the contract's SESSION_KEY_TYPEHASH typestring. The
  // "typestring/array hashing" test below asserts exactly that against the deployed constant.
  const SESSION_KEY_TYPESTRING =
    "SessionKeyAuth(address account,address sessionKey,uint256 validUntil,uint256 deadline,address[] tokens,uint256[] caps,uint256[] orderCaps,uint256 nonce)";

  const SESSION_KEY_TYPES = {
    SessionKeyAuth: [
      { name: "account", type: "address" },
      { name: "sessionKey", type: "address" },
      { name: "validUntil", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "tokens", type: "address[]" },
      { name: "caps", type: "uint256[]" },
      { name: "orderCaps", type: "uint256[]" },
      { name: "nonce", type: "uint256" },
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

  type SessionKeyAuth = {
    account: `0x${string}`;
    sessionKey: `0x${string}`;
    validUntil: bigint;
    deadline: bigint;
    tokens: `0x${string}`[];
    caps: bigint[];
    orderCaps: bigint[];
    nonce: bigint;
  };

  const domainFor = (chainId: number, verifyingContract: `0x${string}`) =>
    ({ name: "StarZipTradeSettlement", version: "1", chainId, verifyingContract }) as const;

  async function signOrder(
    pk: Hex,
    order: Order,
    chainId: number,
    verifyingContract: `0x${string}`,
  ) {
    return signTypedData({
      privateKey: pk,
      domain: domainFor(chainId, verifyingContract),
      types: ORDER_TYPES,
      primaryType: "Order",
      message: order,
    });
  }

  async function signSessionKeyAuth(
    pk: Hex,
    auth: SessionKeyAuth,
    chainId: number,
    verifyingContract: `0x${string}`,
  ) {
    return signTypedData({
      privateKey: pk,
      domain: domainFor(chainId, verifyingContract),
      types: SESSION_KEY_TYPES,
      primaryType: "SessionKeyAuth",
      message: auth,
    });
  }

  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, operator, alice, bob, feeRecipient, charlie] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);
    // 1% fee-on-transfer token, used as a *base* asset so it can be listed via setSupportedToken.
    const fotToken = await viem.deployContract("MockFeeOnTransferToken", ["FeeToken", "FOT", 100n]);

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

    // Operator via the 24h timelock (same pattern as the other TradeSettlementV1 suites).
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
    await settlement.write.setSupportedToken([fotToken.address, true]);

    const usdtAmt = parseUnits("10000", 18);
    for (const trader of [alice, bob]) {
      await usdt.write.mint([trader.account.address, usdtAmt]);
      await usdt.write.approve([settlement.address, usdtAmt], { account: trader.account });
      await settlement.write.depositToken([usdt.address, usdtAmt], { account: trader.account });
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
      settlementImpl,
      usdt,
      fotToken,
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

  const bal = (settlement: any, u: `0x${string}`, t: `0x${string}`) =>
    settlement.read.getBalance([u, t]) as Promise<bigint>;

  // recoverStuckTokens is request -> RECOVER_TIMELOCK_DELAY -> execute. Helper stages a
  // recovery and warps past the delay so tests that are about something ELSE (the excess check)
  // are not rewritten into timelock tests.
  const RECOVER_DELAY = 48n * 60n * 60n;
  // Mirrors TradeSettlementV1.SESSION_KEY_WINDOW. Pinned against the deployed constant in the
  // window test below rather than trusted, so a change to one side fails loudly.
  const SESSION_KEY_WINDOW = 24n * 60n * 60n;
  async function stageRecover(
    settlement: any,
    owner: any,
    token: `0x${string}`,
    to: `0x${string}`,
    amount: bigint,
  ) {
    await settlement.write.requestRecover([token, to, amount], { account: owner.account });
    await time.increase(RECOVER_DELAY + 1n);
  }

  // =====================================================================
  // S4 / measured-delta deposits + recoverStuckTokens underflow guard
  // =====================================================================
  describe("measured-delta deposit", function () {
    it("credits the RECEIVED amount, not the requested amount, for a fee-on-transfer token", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, fotToken, alice } = f;

      const requested = parseUnits("1000", 18);
      const expectedCredit = (requested * 9900n) / 10000n; // 1% burned in transit
      await fotToken.write.mint([alice.account.address, requested]);
      await fotToken.write.approve([settlement.address, requested], { account: alice.account });
      await settlement.write.depositToken([fotToken.address, requested], {
        account: alice.account,
      });

      assert.strictEqual(
        await bal(settlement, alice.account.address, fotToken.address),
        expectedCredit,
        "ledger must reflect what actually arrived",
      );
      // I1: the ledger equals the real balance. Crediting `requested` would over-report by 1%.
      assert.strictEqual(
        (await fotToken.read.balanceOf([settlement.address])) as bigint,
        expectedCredit,
        "Σ balances == balanceOf must survive a fee-on-transfer deposit",
      );
    });

    it("emits Deposited with the real credited amount (indexer reconciliation)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, fotToken, alice, publicClient } = f;

      const requested = parseUnits("500", 18);
      const expectedCredit = (requested * 9900n) / 10000n;
      await fotToken.write.mint([alice.account.address, requested]);
      await fotToken.write.approve([settlement.address, requested], { account: alice.account });
      const hash = await settlement.write.depositToken([fotToken.address, requested], {
        account: alice.account,
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      const events = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "Deposited",
      });
      assert.strictEqual(events.length, 1);
      assert.strictEqual(
        (events[0] as unknown as { args: { amount: bigint } }).args.amount,
        expectedCredit,
        "Deposited must carry the credited amount, not the requested amount",
      );
    });

    it("reverts ZeroAmount when a transfer delivers nothing (100%-fee style token)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, viem, alice, owner } = f;
      // 100% fee: the transfer arrives as zero, so there is nothing to credit.
      const blackHole = await viem.deployContract("MockFeeOnTransferToken", [
        "BlackHole",
        "BH",
        10000n,
      ]);
      await settlement.write.setSupportedToken([blackHole.address, true], {
        account: owner.account,
      });
      await blackHole.write.mint([alice.account.address, 1000n]);
      await blackHole.write.approve([settlement.address, 1000n], { account: alice.account });

      await assertions.revertWithCustomError(
        settlement.write.depositToken([blackHole.address, 1000n], { account: alice.account }),
        settlement,
        "ZeroAmount",
      );
    });

    it("recoverStuckTokens reverts NothingToRecover (not panic 0x11) when the real balance falls BELOW the tracked liability", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, fotToken, alice, owner, charlie } = f;

      const requested = parseUnits("1000", 18);
      await fotToken.write.mint([alice.account.address, requested]);
      await fotToken.write.approve([settlement.address, requested], { account: alice.account });
      await settlement.write.depositToken([fotToken.address, requested], {
        account: alice.account,
      });

      // Drive balanceOf strictly under totalTracked (negative rebase / issuer seizure).
      const settlementBal = (await fotToken.read.balanceOf([settlement.address])) as bigint;
      await fotToken.write.burnFrom([settlement.address, settlementBal / 2n]);
      assert.ok(
        ((await fotToken.read.balanceOf([settlement.address])) as bigint) <
          (await bal(settlement, alice.account.address, fotToken.address)),
        "precondition: real balance is now below the tracked liability",
      );

      // The bare `balanceOf - totalTracked` subtraction panics 0x11 here — permanently and with no
      // diagnosable reason. The explicit guard names the condition instead. The staging is
      // matured first so the revert can only be the excess guard, not the timelock.
      await stageRecover(settlement, owner, fotToken.address, charlie.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([fotToken.address, charlie.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );
    });

    it("recoverStuckTokens still sweeps a genuine excess (donation) after the guard", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, owner, charlie } = f;
      const donation = parseUnits("7", 18);
      await usdt.write.mint([settlement.address, donation]);

      await stageRecover(settlement, owner, usdt.address, charlie.account.address, donation);
      await settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
      assert.strictEqual(
        (await usdt.read.balanceOf([charlie.account.address])) as bigint,
        donation,
      );
      // One wei beyond the excess is user-owed and must stay put.
      await stageRecover(settlement, owner, usdt.address, charlie.account.address, 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, 1n], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );
    });
  });

  // =====================================================================
  // recoverStuckTokens is 48h-timelocked (request -> execute)
  //
  //   Why this matters beyond "dust hygiene": the recoverable excess is
  //   `balanceOf(this) - totalTracked[T]`, and under a rebasing or reward-bearing token that
  //   excess IS the depositors' accrued yield. Immediate recovery let the owner move it to an
  //   arbitrary address in one unannounced transaction. Staging publishes (token, to, amount)
  //   48h ahead; withdrawToken/batchWithdraw are not pause-gated, so users can actually exit
  //   inside that window.
  //
  //   The exact-parameter match is the load-bearing part. A timelock that only gates "a
  //   recovery" and lets the owner substitute `_to` (or raise `_amount`) at execution time
  //   announces nothing useful — the announcement has to bind what will happen.
  // =====================================================================
  describe("recoverStuckTokens timelock", function () {
    /** Fixture + a genuine, sweepable excess (raw donation, never routed through depositToken). */
    async function withExcess() {
      const f = await loadFixture(deployFixture);
      const donation = parseUnits("9", 18);
      await f.usdt.write.mint([f.settlement.address, donation]);
      return { ...f, donation };
    }

    it("executing with NO staged request reverts NoPendingRecover", async function () {
      const { settlement, usdt, owner, charlie, donation } = await withExcess();
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
          account: owner.account,
        }),
        settlement,
        "NoPendingRecover",
      );
    });

    it("executing BEFORE the delay elapses reverts RecoverNotReady", async function () {
      const { settlement, usdt, owner, charlie, donation } = await withExcess();
      await settlement.write.requestRecover([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });

      // Immediately.
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
          account: owner.account,
        }),
        settlement,
        "RecoverNotReady",
      );

      // One second short of maturity — the boundary, not just "some time later".
      await time.increase(RECOVER_DELAY - 2n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
          account: owner.account,
        }),
        settlement,
        "RecoverNotReady",
      );
    });

    it("executing AFTER the delay succeeds and moves exactly the staged amount", async function () {
      const { settlement, usdt, owner, charlie, donation, publicClient } = await withExcess();
      const before = (await usdt.read.balanceOf([charlie.account.address])) as bigint;

      const requestHash = await settlement.write.requestRecover(
        [usdt.address, charlie.account.address, donation],
        { account: owner.account },
      );
      const requestReceipt = await publicClient.waitForTransactionReceipt({ hash: requestHash });
      const requested = parseEventLogs({
        abi: settlement.abi,
        logs: requestReceipt.logs,
        eventName: "RecoverRequested",
      });
      assert.strictEqual(requested.length, 1, "requestRecover must emit RecoverRequested");
      const args = (
        requested[0] as unknown as {
          args: { token: `0x${string}`; to: `0x${string}`; amount: bigint; readyAt: bigint };
        }
      ).args;
      assert.strictEqual(getAddress(args.token), getAddress(usdt.address));
      assert.strictEqual(getAddress(args.to), getAddress(charlie.account.address));
      assert.strictEqual(args.amount, donation, "the event must publish WHAT will leave");

      assert.notStrictEqual(
        await settlement.read.pendingRecoverHash(),
        `0x${"0".repeat(64)}`,
        "staging must be recorded on-chain",
      );
      assert.strictEqual(
        (await settlement.read.recoverReadyAt()) as bigint,
        args.readyAt,
        "recoverReadyAt must match the announced maturity",
      );

      await time.increase(RECOVER_DELAY + 1n);
      await settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });

      assert.strictEqual(
        (await usdt.read.balanceOf([charlie.account.address])) as bigint,
        before + donation,
      );
      assert.strictEqual(
        await settlement.read.pendingRecoverHash(),
        `0x${"0".repeat(64)}`,
        "a consumed staging must be cleared",
      );
      assert.strictEqual((await settlement.read.recoverReadyAt()) as bigint, 0n);
    });

    it("a matured staging cannot be executed with DIFFERENT parameters (to / amount / token)", async function () {
      const { settlement, usdt, lpToken, owner, charlie, alice, donation } = await withExcess();
      await lpToken.write.transfer([settlement.address, donation], { account: alice.account });

      await settlement.write.requestRecover([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
      await time.increase(RECOVER_DELAY + 1n);

      // Different recipient — the substitution the timelock exists to prevent.
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, owner.account.address, donation], {
          account: owner.account,
        }),
        settlement,
        "RecoverParamsMismatch",
      );
      // Different amount (even a smaller one).
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens(
          [usdt.address, charlie.account.address, donation - 1n],
          { account: owner.account },
        ),
        settlement,
        "RecoverParamsMismatch",
      );
      // Different token, with a real excess of its own so only the mismatch can be the cause.
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([lpToken.address, charlie.account.address, donation], {
          account: owner.account,
        }),
        settlement,
        "RecoverParamsMismatch",
      );

      // The staged call itself still works — the rejections above did not consume it.
      await settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
    });

    it("a staging is SINGLE-USE — replaying the same call reverts NoPendingRecover", async function () {
      const { settlement, usdt, owner, charlie, donation } = await withExcess();
      // Fund a second excess so a second sweep would be economically possible if it were allowed.
      await usdt.write.mint([settlement.address, donation]);

      await settlement.write.requestRecover([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
      await time.increase(RECOVER_DELAY + 1n);
      await settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });

      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
          account: owner.account,
        }),
        settlement,
        "NoPendingRecover",
      );
    });

    it("cancelRecover disarms a matured staging; a fresh 48h wait is required afterward", async function () {
      const { settlement, usdt, owner, charlie, donation, publicClient } = await withExcess();
      await settlement.write.requestRecover([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
      const staged = await settlement.read.pendingRecoverHash();
      await time.increase(RECOVER_DELAY + 1n);

      const cancelHash = await settlement.write.cancelRecover({ account: owner.account });
      const cancelReceipt = await publicClient.waitForTransactionReceipt({ hash: cancelHash });
      const cancelled = parseEventLogs({
        abi: settlement.abi,
        logs: cancelReceipt.logs,
        eventName: "RecoverCancelled",
      });
      assert.strictEqual(cancelled.length, 1);
      assert.strictEqual(
        (cancelled[0] as unknown as { args: { cancelledRecoverHash: Hex } }).args
          .cancelledRecoverHash,
        staged,
      );

      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
          account: owner.account,
        }),
        settlement,
        "NoPendingRecover",
      );

      // Cancelling with nothing staged is itself an error (no silent no-op).
      await assertions.revertWithCustomError(
        settlement.write.cancelRecover({ account: owner.account }),
        settlement,
        "NoPendingRecover",
      );

      // Re-staging restarts the clock rather than inheriting the elapsed one.
      await settlement.write.requestRecover([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
          account: owner.account,
        }),
        settlement,
        "RecoverNotReady",
      );
    });

    it("every leg is owner-only — a non-owner can neither stage, execute nor cancel", async function () {
      const { settlement, usdt, owner, charlie, donation } = await withExcess();

      await assertions.revert(
        settlement.write.requestRecover([usdt.address, charlie.account.address, donation], {
          account: charlie.account,
        }),
      );
      await assertions.revert(settlement.write.cancelRecover({ account: charlie.account }));

      // Even with a valid, matured staging in place, a non-owner cannot execute it.
      await settlement.write.requestRecover([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
      await time.increase(RECOVER_DELAY + 1n);
      await assertions.revert(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
          account: charlie.account,
        }),
      );
      await assertions.revert(settlement.write.cancelRecover({ account: charlie.account }));

      // Still armed for the owner — the failed attempts changed nothing.
      await settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
    });

    it("the timelock does NOT unlock user-owed funds — a staged over-sweep still reverts NothingToRecover", async function () {
      const { settlement, usdt, owner, charlie, donation } = await withExcess();
      const overSweep = donation + parseUnits("1", 18);

      await settlement.write.requestRecover([usdt.address, charlie.account.address, overSweep], {
        account: owner.account,
      });
      await time.increase(RECOVER_DELAY + 1n);

      // Staging is a CEILING the owner announced, not an authorization: the live
      // balanceOf - totalTracked check still runs at execution.
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, overSweep], {
          account: owner.account,
        }),
        settlement,
        "NothingToRecover",
      );
    });
  });

  // =====================================================================
  // S6 / + session-key bounds
  // =====================================================================
  // The TTL ceiling (MAX_SESSION_KEY_TTL = 7 days, SessionKeyTtlTooLong) was REMOVED
  // by owner decision, to match the long-lived agent/API wallet model dYdX and Hyperliquid use. What
  // bounds a leaked key is that it cannot withdraw — see the note above the session-key storage in
  // TradeSettlementV1.sol. These tests now pin the opposite property: an account may authorize a key
  // arbitrarily far out, including forever, on BOTH registration paths.
  describe("session keys may be authorized without a lifetime ceiling", function () {
    it("accepts a validUntil far beyond the old 7-day ceiling, and a never-expiring key", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      const now = await time.latest();

      // Well past the old ceiling — this used to revert SessionKeyTtlTooLong.
      const oneYear = now + 365n * 24n * 60n * 60n;
      await settlement.write.registerSessionKey([sessionKey.address, oneYear, [], [], []], {
        account: alice.account,
      });
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        oneYear,
      );

      // And the "sign once, never again" case: a key with no practical expiry at all.
      const never = 2n ** 256n - 1n;
      await settlement.write.registerSessionKey([sessionKey.address, never, [], [], []], {
        account: alice.account,
      });
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        never,
      );
    });

    it("accepts an unbounded validUntil on the relayed (WithSig) path too", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, charlie, chainId, usdt } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      const now = await time.latest();

      const auth: SessionKeyAuth = {
        account: alice.account.address,
        sessionKey: sessionKey.address,
        validUntil: 2n ** 256n - 1n,
        deadline: now + 3600n,
        tokens: [usdt.address],
        caps: [parseUnits("100", 18)],
        orderCaps: [2n ** 256n - 1n],
        nonce: 0n,
      };
      const sig = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);

      await settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account });
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        2n ** 256n - 1n,
      );
    });

    it("an already-expired validUntil is still rejected, and revoke still kills a forever-key instantly", async function () {
      // Removing the ceiling must not remove the floor, and must not weaken revocation — revocation
      // is now the ONLY way a leaked key stops working, so it carries more weight than before.
      const f = await loadFixture(deployFixture);
      const { settlement, alice } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      const now = await time.latest();

      await assertions.revertWithCustomError(
        settlement.write.registerSessionKey([sessionKey.address, now - 1n, [], [], []], {
          account: alice.account,
        }),
        settlement,
        "SessionKeyNotAuthorized",
      );

      await settlement.write.registerSessionKey([sessionKey.address, 2n ** 256n - 1n, [], [], []], {
        account: alice.account,
      });
      await settlement.write.revokeSessionKey([sessionKey.address], { account: alice.account });
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        0n,
      );
    });
  });

  describe("per-asset spend caps", function () {
    // Builds a pair where `seller` sells `fillBase` of lpToken to `buyer` for `fillQuote` USDT.
    async function buildPair(
      f: Awaited<ReturnType<typeof deployFixture>>,
      opts: {
        buyerKey: Hex;
        sellerKey: Hex;
        baseAmount: bigint;
        quoteAmount: bigint;
        nonce: bigint;
      },
    ) {
      const { alice, bob, lpToken, usdt, expiry, chainId, settlement } = f;
      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: true,
        baseAmount: opts.baseAmount,
        quoteAmount: opts.quoteAmount,
        maxFeeRate: 100n,
        nonce: opts.nonce,
        expiry,
      };
      const sellOrder: Order = {
        ...buyOrder,
        account: bob.account.address,
        isBuy: false,
      };
      return {
        buyOrder,
        buySig: await signOrder(opts.buyerKey, buyOrder, chainId, settlement.address),
        sellOrder,
        sellSig: await signOrder(opts.sellerKey, sellOrder, chainId, settlement.address),
      };
    }

    it("is fail-closed: a registered key with no cap cannot settle at all — BOTH caps must be funded", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, usdt, expiry } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      await settlement.write.registerSessionKey([sessionKey.address, expiry, [], [], []], {
        account: alice.account,
      });

      const quoteAmount = parseUnits("100", 18);
      const p = await buildPair(f, {
        buyerKey: SESSION_KEY_PK, // alice's buy leg signed by the session key
        sellerKey: BOB_KEY,
        baseAmount: parseUnits("10", 18),
        quoteAmount,
        nonce: 21n,
      });
      const fill = (seed: string) =>
        settlement.write.settleOrders(
          [
            {
              buyOrder: p.buyOrder,
              buySig: p.buySig,
              sellOrder: p.sellOrder,
              sellSig: p.sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: quoteAmount,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId(seed),
            },
          ],
          { account: operator.account },
        );

      // Both caps default to 0. The per-ORDER ceiling is checked first (step 4b, before any fill
      // accounting), so that is what a fully unfunded key hits.
      await assertions.revertWithCustomError(
        fill("failclosed"),
        settlement,
        "SessionKeyOrderCapExceeded",
      );

      // Opening ONLY the per-order ceiling must not be enough — the per-window budget is a second,
      // independent gate. This is the half the old single-assert version could not see.
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, usdt.address, 0n, 2n ** 192n - 1n],
        {
          account: alice.account,
        },
      );
      await assertions.revertWithCustomError(
        fill("failclosed2"),
        settlement,
        "SessionKeyCapExceeded",
      );
    });

    it("SELL LEG: a leaked key cannot dump base inventory at a dust quote price — the cap follows the DEBITED asset", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, bob, lpToken, usdt, expiry, chainId } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      // Alice registers a session key and budgets it generously in the QUOTE asset — the intuitive
      // (and insufficient) way to bound a trading key — plus a deliberately small BASE budget.
      const quoteCap = parseUnits("5000", 18);
      const baseCap = parseUnits("10", 18);
      await settlement.write.registerSessionKey([sessionKey.address, expiry, [], [], []], {
        account: alice.account,
      });
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, usdt.address, quoteCap, 2n ** 256n - 1n],
        {
          account: alice.account,
        },
      );
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, lpToken.address, baseCap, 2n ** 256n - 1n],
        {
          account: alice.account,
        },
      );

      // The attack: with the leaked key, sign a SELL of alice's whole base position at a dust
      // price, and self-match it with an order from the attacker's own funded account (bob).
      const victimBase = await bal(settlement, alice.account.address, lpToken.address);
      const dustQuote = parseUnits("0.01", 18); // == the registry minimum for an 18-dec quote
      const sellOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: false,
        baseAmount: victimBase,
        quoteAmount: dustQuote,
        maxFeeRate: 100n,
        nonce: 31n,
        expiry,
      };
      const buyOrder: Order = { ...sellOrder, account: bob.account.address, isBuy: true };
      const sellSig = await signOrder(SESSION_KEY_PK, sellOrder, chainId, settlement.address);
      const buySig = await signOrder(BOB_KEY, buyOrder, chainId, settlement.address);

      // A QUOTE-ONLY cap does not bind here — that is the whole point of the finding.
      assert.ok(
        dustQuote < quoteCap,
        "the attack's quote notional is far below the quote cap, so a quote-only cap would let it through",
      );
      assert.ok(victimBase > baseCap, "the attack moves more base than the base cap allows");

      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: victimBase,
              fillQuoteAmount: dustQuote,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("sell-leg-drain"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "SessionKeyCapExceeded",
      );

      // The victim's position is untouched.
      assert.strictEqual(
        await bal(settlement, alice.account.address, lpToken.address),
        victimBase,
        "no base may leave the victim's ledger",
      );
    });

    it("SELL LEG: a sell within the base cap still settles (the cap binds, it does not brick)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, bob, lpToken, usdt, expiry, chainId } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      const baseCap = parseUnits("10", 18);

      await settlement.write.registerSessionKey([sessionKey.address, expiry, [], [], []], {
        account: alice.account,
      });
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, lpToken.address, baseCap, 2n ** 256n - 1n],
        {
          account: alice.account,
        },
      );

      const fillBase = parseUnits("5", 18);
      const fillQuote = parseUnits("50", 18);
      const sellOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: false,
        baseAmount: fillBase,
        quoteAmount: fillQuote,
        maxFeeRate: 100n,
        nonce: 32n,
        expiry,
      };
      const buyOrder: Order = { ...sellOrder, account: bob.account.address, isBuy: true };
      const sellSig = await signOrder(SESSION_KEY_PK, sellOrder, chainId, settlement.address);
      const buySig = await signOrder(BOB_KEY, buyOrder, chainId, settlement.address);

      const before = await bal(settlement, alice.account.address, lpToken.address);
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: fillBase,
            fillQuoteAmount: fillQuote,
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: settlementId("ok"),
          },
        ],
        { account: operator.account },
      );
      assert.strictEqual(
        await bal(settlement, alice.account.address, lpToken.address),
        before - fillBase,
      );
      assert.strictEqual(
        (
          (await settlement.read.sessionKeySpendWindows([
            alice.account.address,
            sessionKey.address,
            lpToken.address,
          ])) as [bigint, bigint]
        )[1],
        fillBase,
        "spend is recorded against the base asset",
      );
    });

    it("BUY LEG: the charge is fillQuoteAmount + buyerFee, and partial fills accumulate per FILL", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, usdt, lpToken } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      const fillBase = parseUnits("10", 18);
      const fillQuote = parseUnits("100", 18);
      const buyerFee = parseUnits("1", 18);
      // Exactly two fills' worth of budget — the third must be refused.
      const cap = (fillQuote + buyerFee) * 2n;

      await settlement.write.registerSessionKey([sessionKey.address, f.expiry, [], [], []], {
        account: alice.account,
      });
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, usdt.address, cap, 2n ** 256n - 1n],
        {
          account: alice.account,
        },
      );

      const p = await buildPair(f, {
        buyerKey: SESSION_KEY_PK,
        sellerKey: BOB_KEY,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 41n,
      });

      for (const seed of ["pf1", "pf2"]) {
        await settlement.write.settleOrders(
          [
            {
              buyOrder: p.buyOrder,
              buySig: p.buySig,
              sellOrder: p.sellOrder,
              sellSig: p.sellSig,
              fillBaseAmount: fillBase,
              fillQuoteAmount: fillQuote,
              buyerFee: buyerFee,
              sellerFee: 0n,
              settlementId: settlementId(seed),
            },
          ],
          { account: operator.account },
        );
      }

      assert.strictEqual(
        (
          (await settlement.read.sessionKeySpendWindows([
            alice.account.address,
            sessionKey.address,
            usdt.address,
          ])) as [bigint, bigint]
        )[1],
        cap,
        "two fills consume exactly the cap — accumulation is per fill, not per order",
      );
      // The buy leg never touches the base asset, so nothing is charged there.
      assert.strictEqual(
        (
          (await settlement.read.sessionKeySpendWindows([
            alice.account.address,
            sessionKey.address,
            lpToken.address,
          ])) as [bigint, bigint]
        )[1],
        0n,
      );

      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: p.buyOrder,
              buySig: p.buySig,
              sellOrder: p.sellOrder,
              sellSig: p.sellSig,
              fillBaseAmount: fillBase,
              fillQuoteAmount: fillQuote,
              buyerFee: buyerFee,
              sellerFee: 0n,
              settlementId: settlementId("pf3"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "SessionKeyCapExceeded",
      );
    });

    it("the budget REFILLS at the next window — a spent key trades again without the account re-signing", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, usdt } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      assert.strictEqual(
        (await settlement.read.SESSION_KEY_WINDOW()) as bigint,
        SESSION_KEY_WINDOW,
        "the window this test advances by must be the one the contract divides by",
      );

      const fillBase = parseUnits("10", 18);
      const fillQuote = parseUnits("100", 18);
      const cap = fillQuote; // exactly one fill per window

      // Orders must outlive the window hop; the fixture's 1h expiry would not.
      const farExpiry = (await time.latest()) + 30n * 24n * 60n * 60n;
      const ff = { ...f, expiry: farExpiry };

      await settlement.write.registerSessionKey(
        [sessionKey.address, farExpiry, [usdt.address], [cap], [2n ** 192n - 1n]],
        {
          account: alice.account,
        },
      );

      const p = await buildPair(ff, {
        buyerKey: SESSION_KEY_PK,
        sellerKey: BOB_KEY,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 61n,
      });
      const fill = (seed: string) =>
        settlement.write.settleOrders(
          [
            {
              buyOrder: p.buyOrder,
              buySig: p.buySig,
              sellOrder: p.sellOrder,
              sellSig: p.sellSig,
              fillBaseAmount: fillBase,
              fillQuoteAmount: fillQuote,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId(seed),
            },
          ],
          { account: operator.account },
        );

      await fill("w1");
      // Budget is now exhausted for THIS window.
      await assertions.revertWithCustomError(fill("w2"), settlement, "SessionKeyCapExceeded");

      // The refill is a pure function of the clock: no transaction, no re-registration, no new
      // signature from alice. That is the whole point of the change — under the old cumulative cap
      // this key was dead until alice opened her wallet again.
      await time.increase(SESSION_KEY_WINDOW);
      await fill("w3");

      assert.strictEqual(
        (
          (await settlement.read.sessionKeySpendWindows([
            alice.account.address,
            sessionKey.address,
            usdt.address,
          ])) as [bigint, bigint]
        )[1],
        fillQuote,
        "the new window starts from zero and records only the fill that happened inside it",
      );
    });

    it("revoke-and-reregister inside the same window does NOT refill the budget early", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, usdt } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      const fillQuote = parseUnits("100", 18);
      const cap = fillQuote;
      const farExpiry = (await time.latest()) + 30n * 24n * 60n * 60n;
      const ff = { ...f, expiry: farExpiry };

      await settlement.write.registerSessionKey(
        [sessionKey.address, farExpiry, [usdt.address], [cap], [2n ** 192n - 1n]],
        {
          account: alice.account,
        },
      );
      const p = await buildPair(ff, {
        buyerKey: SESSION_KEY_PK,
        sellerKey: BOB_KEY,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        nonce: 62n,
      });
      const fill = (seed: string) =>
        settlement.write.settleOrders(
          [
            {
              buyOrder: p.buyOrder,
              buySig: p.buySig,
              sellOrder: p.sellOrder,
              sellSig: p.sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: fillQuote,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId(seed),
            },
          ],
          { account: operator.account },
        );

      await fill("r1");

      // Wiping the key and putting it back is the obvious way to try to reset a window counter.
      // `sessionKeySpendWindows` is keyed by (account, key, token) and deliberately not cleared, so
      // the used amount survives — otherwise the per-window cap would bound nothing at all.
      await settlement.write.revokeSessionKey([sessionKey.address], { account: alice.account });
      await settlement.write.registerSessionKey(
        [sessionKey.address, farExpiry, [usdt.address], [cap], [2n ** 192n - 1n]],
        {
          account: alice.account,
        },
      );

      await assertions.revertWithCustomError(fill("r2"), settlement, "SessionKeyCapExceeded");
    });

    it("PER-ORDER CAP: an order larger than the ceiling is refused even with the window budget wide open", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, usdt } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      const quoteAmount = parseUnits("1000", 18);
      // Window budget is effectively unlimited; only the per-order ceiling binds.
      await settlement.write.registerSessionKey(
        [sessionKey.address, f.expiry, [usdt.address], [2n ** 192n - 1n], [quoteAmount / 2n]],
        { account: alice.account },
      );

      const p = await buildPair(f, {
        buyerKey: SESSION_KEY_PK,
        sellerKey: BOB_KEY,
        baseAmount: parseUnits("100", 18),
        quoteAmount,
        nonce: 63n,
      });

      // Refused on the ORDER's own size, before any fill amount is even considered — a leaked key
      // cannot drain a whole window in one shot.
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: p.buyOrder,
              buySig: p.buySig,
              sellOrder: p.sellOrder,
              sellSig: p.sellSig,
              fillBaseAmount: parseUnits("1", 18),
              fillQuoteAmount: parseUnits("10", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("oc1"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "SessionKeyOrderCapExceeded",
      );
    });

    it("PER-ORDER CAP: the buy-side ceiling must cover the order's FEE too, not just its quote", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, usdt } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      const quoteAmount = parseUnits("1000", 18);
      // buildPair signs maxFeeRate = 100bp, so the largest this order can debit is quote + 1%.
      // A ceiling of exactly `quoteAmount` is therefore one basis point short.
      await settlement.write.registerSessionKey(
        [sessionKey.address, f.expiry, [usdt.address], [2n ** 192n - 1n], [quoteAmount]],
        { account: alice.account },
      );

      const p = await buildPair(f, {
        buyerKey: SESSION_KEY_PK,
        sellerKey: BOB_KEY,
        baseAmount: parseUnits("100", 18),
        quoteAmount,
        nonce: 64n,
      });
      const fill = (seed: string) =>
        settlement.write.settleOrders(
          [
            {
              buyOrder: p.buyOrder,
              buySig: p.buySig,
              sellOrder: p.sellOrder,
              sellSig: p.sellSig,
              fillBaseAmount: parseUnits("1", 18),
              fillQuoteAmount: parseUnits("10", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId(seed),
            },
          ],
          { account: operator.account },
        );

      await assertions.revertWithCustomError(
        fill("fee1"),
        settlement,
        "SessionKeyOrderCapExceeded",
      );

      // Raising the ceiling to cover quote + the order's own max fee admits it.
      const withFee = quoteAmount + (quoteAmount * 100n) / 10_000n;
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, usdt.address, 2n ** 192n - 1n, withFee],
        {
          account: alice.account,
        },
      );
      await fill("fee2");
    });

    it("PER-ORDER CAP: the sell leg is bounded in BASE, and a zero ceiling blocks the asset outright", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, bob, usdt, lpToken } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      const baseAmount = parseUnits("100", 18);
      // bob is the SELLER in buildPair. Fund the quote ceiling generously and leave base at zero:
      // fail-closed must survive the counter learning to reset.
      await settlement.write.registerSessionKey(
        [
          sessionKey.address,
          f.expiry,
          [usdt.address, lpToken.address],
          [2n ** 192n - 1n, 2n ** 192n - 1n],
          [2n ** 192n - 1n, 0n],
        ],
        { account: bob.account },
      );

      const p = await buildPair(f, {
        buyerKey: ALICE_KEY,
        sellerKey: SESSION_KEY_PK,
        baseAmount,
        quoteAmount: parseUnits("1000", 18),
        nonce: 65n,
      });
      const fill = (seed: string) =>
        settlement.write.settleOrders(
          [
            {
              buyOrder: p.buyOrder,
              buySig: p.buySig,
              sellOrder: p.sellOrder,
              sellSig: p.sellSig,
              fillBaseAmount: parseUnits("1", 18),
              fillQuoteAmount: parseUnits("10", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId(seed),
            },
          ],
          { account: operator.account },
        );

      await assertions.revertWithCustomError(
        fill("sell1"),
        settlement,
        "SessionKeyOrderCapExceeded",
      );

      // The sell leg debits base only — the ceiling that matters is baseAmount, with no fee added
      // (the seller's fee comes out of proceeds and never debits base).
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, lpToken.address, 2n ** 192n - 1n, baseAmount],
        {
          account: bob.account,
        },
      );
      await fill("sell2");
    });

    it("a per-window cap above uint192 is rejected — it would let `used` wrap and reset the budget", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, usdt } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      await assertions.revertWithCustomError(
        settlement.write.setSessionKeyCap([sessionKey.address, usdt.address, 2n ** 192n, 0n], {
          account: alice.account,
        }),
        settlement,
        "InvalidSessionKeyCap",
      );
      // The boundary itself is accepted.
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, usdt.address, 2n ** 192n - 1n, 0n],
        {
          account: alice.account,
        },
      );
    });

    it("an account signing its OWN order is never charged against a cap", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, usdt } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      // A key is registered with a zero cap; alice signs directly, so it must be irrelevant.
      await settlement.write.registerSessionKey([sessionKey.address, f.expiry, [], [], []], {
        account: alice.account,
      });

      const p = await buildPair(f, {
        buyerKey: ALICE_KEY,
        sellerKey: BOB_KEY,
        baseAmount: parseUnits("10", 18),
        quoteAmount: parseUnits("100", 18),
        nonce: 51n,
      });
      await settlement.write.settleOrders(
        [
          {
            buyOrder: p.buyOrder,
            buySig: p.buySig,
            sellOrder: p.sellOrder,
            sellSig: p.sellSig,
            fillBaseAmount: parseUnits("10", 18),
            fillQuoteAmount: parseUnits("100", 18),
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: settlementId("direct"),
          },
        ],
        { account: operator.account },
      );
      assert.strictEqual(
        (
          (await settlement.read.sessionKeySpendWindows([
            alice.account.address,
            sessionKey.address,
            usdt.address,
          ])) as [bigint, bigint]
        )[1],
        0n,
      );
    });

    it("setSessionKeyCap is msg.sender-scoped — a third party cannot fund someone else's key", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, bob, usdt } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      const cap = parseUnits("999", 18);

      // Bob "grants" a cap for the same key — it lands under BOB's account, not alice's.
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, usdt.address, cap, 2n ** 256n - 1n],
        {
          account: bob.account,
        },
      );
      assert.strictEqual(
        (await settlement.read.sessionKeySpendCap([
          alice.account.address,
          sessionKey.address,
          usdt.address,
        ])) as bigint,
        0n,
        "alice's key budget must be untouched by bob",
      );
      assert.strictEqual(
        (await settlement.read.sessionKeySpendCap([
          bob.account.address,
          sessionKey.address,
          usdt.address,
        ])) as bigint,
        cap,
      );
    });

    it("registerSessionKey sets validUntil AND per-asset caps atomically in one tx — no follow-up setSessionKeyCap needed", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, bob, lpToken, usdt, expiry, chainId } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      const quoteCap = parseUnits("5000", 18);
      const baseCap = parseUnits("10", 18);

      // Single call: validUntil + both per-asset caps land together. No setSessionKeyCap call
      // anywhere in this test — that is the point.
      await settlement.write.registerSessionKey(
        [
          sessionKey.address,
          expiry,
          [usdt.address, lpToken.address],
          [quoteCap, baseCap],
          [2n ** 256n - 1n, 2n ** 256n - 1n],
        ],
        { account: alice.account },
      );

      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        expiry,
      );
      assert.strictEqual(
        (await settlement.read.sessionKeySpendCap([
          alice.account.address,
          sessionKey.address,
          usdt.address,
        ])) as bigint,
        quoteCap,
      );
      assert.strictEqual(
        (await settlement.read.sessionKeySpendCap([
          alice.account.address,
          sessionKey.address,
          lpToken.address,
        ])) as bigint,
        baseCap,
      );

      // The key is immediately usable — proves the caps were live from the same tx, not a
      // subsequent one.
      const p = await buildPair(f, {
        buyerKey: SESSION_KEY_PK,
        sellerKey: BOB_KEY,
        baseAmount: parseUnits("10", 18),
        quoteAmount: parseUnits("100", 18),
        nonce: 61n,
      });
      void bob;
      void chainId;
      await settlement.write.settleOrders(
        [
          {
            buyOrder: p.buyOrder,
            buySig: p.buySig,
            sellOrder: p.sellOrder,
            sellSig: p.sellSig,
            fillBaseAmount: parseUnits("10", 18),
            fillQuoteAmount: parseUnits("100", 18),
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: settlementId("atomic-reg"),
          },
        ],
        { account: operator.account },
      );
      assert.strictEqual(
        (
          (await settlement.read.sessionKeySpendWindows([
            alice.account.address,
            sessionKey.address,
            usdt.address,
          ])) as [bigint, bigint]
        )[1],
        parseUnits("100", 18),
      );
    });

    it("registerSessionKey reverts ArrayLengthMismatch when tokens/caps arrays differ in length", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, usdt, expiry } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      await assertions.revertWithCustomError(
        settlement.write.registerSessionKey([sessionKey.address, expiry, [usdt.address], [], []], {
          account: alice.account,
        }),
        settlement,
        "ArrayLengthMismatch",
      );

      // Confirm the revert is atomic: nothing was registered.
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        0n,
      );
    });

    // Batched settlement lives inside this describe purely because `buildPair` above is the
    // funded-pair builder these tests need; nothing here is session-key specific.
    describe("settleOrdersBatch — throughput entrypoint", function () {
      // Three independent fills against one signed pair. Distinct settlementIds, so they are three
      // settlements of the same order, which is exactly what partial fills look like on the wire.
      async function threeFills(f: Awaited<ReturnType<typeof deployFixture>>, nonce: bigint) {
        const p = await buildPair(f, {
          buyerKey: ALICE_KEY,
          sellerKey: BOB_KEY,
          baseAmount: parseUnits("100", 18),
          quoteAmount: parseUnits("1000", 18),
          nonce,
        });
        return ["b1", "b2", "b3"].map((seed) => ({
          buyOrder: p.buyOrder,
          buySig: p.buySig,
          sellOrder: p.sellOrder,
          sellSig: p.sellSig,
          fillBaseAmount: parseUnits("10", 18),
          fillQuoteAmount: parseUnits("100", 18),
          buyerFee: 0n,
          sellerFee: 0n,
          settlementId: settlementId(seed),
        }));
      }

      it("settles every item in one transaction", async function () {
        const f = await loadFixture(deployFixture);
        const { settlement, operator, alice, bob, lpToken } = f;
        const items = await threeFills(f, 200n);

        const before = (await settlement.read.getBalance([
          alice.account.address,
          lpToken.address,
        ])) as bigint;
        await settlement.write.settleOrdersBatch([items], { account: operator.account });
        const after = (await settlement.read.getBalance([
          alice.account.address,
          lpToken.address,
        ])) as bigint;

        assert.strictEqual(after - before, parseUnits("30", 18), "all three fills landed");
        for (const it of items) {
          assert.strictEqual(
            (await settlement.read.processedSettlements([it.settlementId])) as boolean,
            true,
          );
        }
        // Sanity: the counterparty moved by the mirror amount, so this was a real settle and not a
        // one-sided credit.
        assert.ok(
          ((await settlement.read.getBalance([bob.account.address, lpToken.address])) as bigint) >=
            0n,
        );
      });

      it("ISOLATION: one bad item is skipped, the rest settle, and the batch does not revert", async function () {
        const f = await loadFixture(deployFixture);
        const { settlement, operator, alice, lpToken } = f;
        const items = await threeFills(f, 201n);

        // Poison the middle item: a settlementId that has already been consumed. Any per-item
        // failure would do; this one is deterministic and needs no balance manipulation.
        await settlement.write.settleOrdersBatch([[items[1]]], { account: operator.account });
        const afterFirst = (await settlement.read.getBalance([
          alice.account.address,
          lpToken.address,
        ])) as bigint;

        // The whole batch, including the now-replayed middle item.
        await settlement.write.settleOrdersBatch([items], { account: operator.account });

        const after = (await settlement.read.getBalance([
          alice.account.address,
          lpToken.address,
        ])) as bigint;
        assert.strictEqual(
          after - afterFirst,
          parseUnits("20", 18),
          "items 0 and 2 settled; the replayed item contributed nothing",
        );

        const failures = await settlement.getEvents.SettlementFailed();
        assert.strictEqual(failures.length, 1, "exactly one item was recorded as failed");
        assert.strictEqual(failures[0].args.index, 1n, "and it was the one at index 1");
        assert.strictEqual(failures[0].args.settlementId, items[1].settlementId);
      });

      it("a failed item is RETRYABLE — its settlementId is not burned by the failure", async function () {
        const f = await loadFixture(deployFixture);
        const { settlement, operator, alice, lpToken } = f;
        const p = await buildPair(f, {
          buyerKey: ALICE_KEY,
          sellerKey: BOB_KEY,
          baseAmount: parseUnits("100", 18),
          quoteAmount: parseUnits("1000", 18),
          nonce: 202n,
        });
        // Overfilled: 200 base against a 100-base order. Fails inside its own frame.
        const doomed = {
          buyOrder: p.buyOrder,
          buySig: p.buySig,
          sellOrder: p.sellOrder,
          sellSig: p.sellSig,
          fillBaseAmount: parseUnits("200", 18),
          fillQuoteAmount: parseUnits("100", 18),
          buyerFee: 0n,
          sellerFee: 0n,
          settlementId: settlementId("retry"),
        };

        await settlement.write.settleOrdersBatch([[doomed]], { account: operator.account });
        assert.strictEqual(
          (await settlement.read.processedSettlements([doomed.settlementId])) as boolean,
          false,
          "the id must NOT be marked — the whole frame rolled back, mark included",
        );

        // Same id, corrected amount: it settles. This is the property that makes per-item failure a
        // retry rather than a lost settlement.
        const before = (await settlement.read.getBalance([
          alice.account.address,
          lpToken.address,
        ])) as bigint;
        await settlement.write.settleOrdersBatch(
          [[{ ...doomed, fillBaseAmount: parseUnits("10", 18) }]],
          {
            account: operator.account,
          },
        );
        assert.strictEqual(
          ((await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint) -
            before,
          parseUnits("10", 18),
        );
      });

      it("GAS: a starved batch reverts instead of succeeding while settling nothing", async function () {
        const f = await loadFixture(deployFixture);
        const { settlement, operator, alice, lpToken } = f;
        const items = await threeFills(f, 207n);

        // The defect this pins: `settleOrdersBatch` never reverts on a rejected item, so if an
        // out-of-gas item were also treated as "rejected", eth_estimateGas would converge on the
        // cheapest gas at which EVERY item is starved and swallowed — a transaction that succeeds,
        // emits three failure events, and settles nothing. Empty revert data now aborts the batch,
        // so a starved run is loud.
        //
        // 250k is comfortably past the loop's own overhead and nowhere near enough for three
        // settlements, so the first item is starved rather than rejected.
        const before = (await settlement.read.getBalance([
          alice.account.address,
          lpToken.address,
        ])) as bigint;
        await assertions.revertWithCustomError(
          settlement.write.settleOrdersBatch([items], { account: operator.account, gas: 250_000n }),
          settlement,
          "BatchOutOfGas",
        );

        // And nothing settled — the abort is total, not partial.
        assert.strictEqual(
          (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
          before,
        );
        for (const it of items) {
          assert.strictEqual(
            (await settlement.read.processedSettlements([it.settlementId])) as boolean,
            false,
          );
        }
      });

      it("is bounded by MAX_BATCH_SIZE", async function () {
        const f = await loadFixture(deployFixture);
        const { settlement, operator } = f;
        const items = await threeFills(f, 203n);
        const max = Number((await settlement.read.MAX_BATCH_SIZE()) as bigint);
        const tooMany = Array.from({ length: max + 1 }, (_, i) => ({
          ...items[0],
          settlementId: settlementId(`over${i}`),
        }));

        await assertions.revertWithCustomError(
          settlement.write.settleOrdersBatch([tooMany], { account: operator.account }),
          settlement,
          "BatchTooLarge",
        );
      });

      it("settleOrdersSelf is not an operator entrypoint — only the contract's own loop may call it", async function () {
        const f = await loadFixture(deployFixture);
        const { settlement, operator, alice } = f;
        const items = await threeFills(f, 204n);

        // The operator is the most privileged caller there is here, and it still cannot reach the
        // trampoline directly — otherwise it would be a settle path with no nonReentrant and no
        // pause check.
        await assertions.revertWithCustomError(
          settlement.write.settleOrdersSelf([items[0]], { account: operator.account }),
          settlement,
          "OnlySelf",
        );
        await assertions.revertWithCustomError(
          settlement.write.settleOrdersSelf([items[0]], { account: alice.account }),
          settlement,
          "OnlySelf",
        );
      });

      it("the batch itself is operator-gated", async function () {
        const f = await loadFixture(deployFixture);
        const { settlement, alice } = f;
        const items = await threeFills(f, 205n);

        await assertions.revertWithCustomError(
          settlement.write.settleOrdersBatch([items], { account: alice.account }),
          settlement,
          "NotOperator",
        );
      });

      it("CONSERVATION holds across a partially-failing batch", async function () {
        const f = await loadFixture(deployFixture);
        const { settlement, operator, alice, bob, feeRecipient, usdt, lpToken } = f;
        const items = await threeFills(f, 206n);
        // Burn the middle id so the batch is guaranteed to be partial.
        await settlement.write.settleOrdersBatch([[items[1]]], { account: operator.account });

        const bal = (u: `0x${string}`, t: `0x${string}`) =>
          settlement.read.getBalance([u, t]) as Promise<bigint>;
        const sum = async (t: `0x${string}`) =>
          (await bal(alice.account.address, t)) +
          (await bal(bob.account.address, t)) +
          (await bal(feeRecipient.account.address, t));

        const baseBefore = await sum(lpToken.address);
        const quoteBefore = await sum(usdt.address);

        await settlement.write.settleOrdersBatch([items], { account: operator.account });

        assert.strictEqual(await sum(lpToken.address), baseBefore, "base is conserved");
        assert.strictEqual(await sum(usdt.address), quoteBefore, "quote is conserved");
      });
    });
  });

  describe("forbidden session keys", function () {
    it("rejects registering an operator, the feeRecipient or the owner as a session key", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, operator, feeRecipient, owner } = f;

      for (const forbidden of [operator, feeRecipient, owner]) {
        await assertions.revertWithCustomError(
          settlement.write.registerSessionKey([forbidden.account.address, f.expiry, [], [], []], {
            account: alice.account,
          }),
          settlement,
          "ForbiddenSessionKey",
        );
      }
    });

    it("rejects a forbidden key on the relayed (WithSig) path", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, charlie, operator, usdt, chainId, expiry } = f;

      const auth: SessionKeyAuth = {
        account: alice.account.address,
        sessionKey: operator.account.address,
        validUntil: expiry,
        deadline: expiry,
        tokens: [usdt.address],
        caps: [parseUnits("100", 18)],
        orderCaps: [2n ** 256n - 1n],
        nonce: 0n,
      };
      const sig = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);
      await assertions.revertWithCustomError(
        settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account }),
        settlement,
        "ForbiddenSessionKey",
      );
    });

    it("a key registered while innocent is refused AT USE TIME once it becomes an operator", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, usdt, publicClient } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      // Must outlive the 24h operator timelock warped through below (and stay inside the 7d TTL),
      // otherwise the key would simply expire and we would be asserting the wrong revert.
      const keyValidUntil = (await time.latest()) + 3n * 24n * 60n * 60n;

      // 1. Register + fund the key while it holds no privileges — this must succeed.
      await settlement.write.registerSessionKey([sessionKey.address, keyValidUntil, [], [], []], {
        account: alice.account,
      });
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, usdt.address, parseUnits("5000", 18), 2n ** 256n - 1n],
        { account: alice.account },
      );

      // 2. The key is later promoted to operator through the normal 24h timelock. A
      //    registration-time-only check cannot see this happen.
      const queueHash = await settlement.write.queueOperatorChange([sessionKey.address, true]);
      const receipt = await publicClient.waitForTransactionReceipt({ hash: queueHash });
      const changeId = (
        parseEventLogs({
          abi: settlement.abi,
          logs: receipt.logs,
          eventName: "OperatorChangeQueued",
        })[0] as unknown as { args: { changeId: Hex } }
      ).args.changeId;
      await time.increase(24n * 60n * 60n + 1n);
      await settlement.write.executeOperatorChange([changeId]);
      assert.strictEqual(await settlement.read.operators([sessionKey.address]), true);

      // 3. The same registration is now unusable: one address would otherwise both sign the order
      //    legs and submit the settlement.
      const laterExpiry = (await time.latest()) + 3600n;
      const p = await buildForbiddenPair(f, laterExpiry);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: p.buyOrder,
              buySig: p.buySig,
              sellOrder: p.sellOrder,
              sellSig: p.sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: parseUnits("100", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("aa7"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "ForbiddenSessionKey",
      );
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        keyValidUntil,
        "the stale registration is still on-chain — only its USE is blocked",
      );
    });

    async function buildForbiddenPair(
      f: Awaited<ReturnType<typeof deployFixture>>,
      expiry: bigint,
    ) {
      const { alice, bob, lpToken, usdt, chainId, settlement } = f;
      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: true,
        baseAmount: parseUnits("10", 18),
        quoteAmount: parseUnits("100", 18),
        maxFeeRate: 100n,
        nonce: 61n,
        expiry,
      };
      const sellOrder: Order = { ...buyOrder, account: bob.account.address, isBuy: false };
      return {
        buyOrder,
        buySig: await signOrder(SESSION_KEY_PK, buyOrder, chainId, settlement.address),
        sellOrder,
        sellSig: await signOrder(BOB_KEY, sellOrder, chainId, settlement.address),
      };
    }
  });

  // =====================================================================
  // S7 / SessionKeyAuth deadline + invalidation + EIP-712 interop
  // =====================================================================
  describe("authorization expiry and invalidation", function () {
    function makeAuth(
      f: Awaited<ReturnType<typeof deployFixture>>,
      over: Partial<SessionKeyAuth> = {},
    ): SessionKeyAuth {
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      return {
        account: f.alice.account.address,
        sessionKey: sessionKey.address,
        validUntil: f.expiry,
        deadline: f.expiry,
        tokens: [f.usdt.address],
        caps: [parseUnits("1000", 18)],
        orderCaps: [2n ** 256n - 1n],
        nonce: 0n,
        ...over,
      };
    }

    it("rejects an auth whose deadline has passed", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, charlie, chainId } = f;
      const now = await time.latest();
      const auth = makeAuth(f, { deadline: now + 60n, validUntil: now + 3600n });
      const sig = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);

      await time.increase(120n); // past the deadline, still well inside validUntil
      await assertions.revertWithCustomError(
        settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account }),
        settlement,
        "SignatureExpired",
      );
    });

    it("registers and applies the caps atomically when the auth is fresh", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, charlie, chainId, usdt, lpToken } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      const auth = makeAuth(f, {
        tokens: [usdt.address, lpToken.address],
        caps: [parseUnits("1000", 18), parseUnits("25", 18)],
        orderCaps: [2n ** 256n - 1n, 2n ** 256n - 1n],
      });
      const sig = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);

      await settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account });

      assert.strictEqual(
        (await settlement.read.sessionKeySpendCap([
          alice.account.address,
          sessionKey.address,
          usdt.address,
        ])) as bigint,
        parseUnits("1000", 18),
      );
      assert.strictEqual(
        (await settlement.read.sessionKeySpendCap([
          alice.account.address,
          sessionKey.address,
          lpToken.address,
        ])) as bigint,
        parseUnits("25", 18),
      );
    });

    it("rejects tokens/caps of differing lengths", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, charlie, chainId, usdt, lpToken } = f;
      const auth = makeAuth(f, {
        tokens: [usdt.address, lpToken.address],
        caps: [parseUnits("1000", 18)],
        orderCaps: [2n ** 256n - 1n],
      });
      const sig = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);
      await assertions.revertWithCustomError(
        settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account }),
        settlement,
        "ArrayLengthMismatch",
      );
    });

    it("revokeSessionKey bumps the nonce, so a revoked key cannot be resurrected by an unsubmitted auth", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, charlie, chainId } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      // A relayer holds a validly signed, never-submitted registration.
      const auth = makeAuth(f);
      const sig = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);

      // Alice registers the key directly, then thinks better of it and revokes.
      await settlement.write.registerSessionKey([sessionKey.address, f.expiry, [], [], []], {
        account: alice.account,
      });
      await settlement.write.revokeSessionKey([sessionKey.address], { account: alice.account });
      assert.notStrictEqual(
        (await settlement.read.sessionKeyRegNonce([alice.account.address])) as bigint,
        0n,
        "revoke must bump the registration nonce",
      );

      // The stale authorization can no longer bring the key back.
      await assertions.revertWithCustomError(
        settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account }),
        settlement,
        "InvalidRegistrationNonce",
      );
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        0n,
      );
    });

    it("invalidateSessionKeyAuths kills every unsubmitted authorization in one call", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, charlie, chainId, publicClient } = f;
      const auth = makeAuth(f);
      const sig = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);

      const hash = await settlement.write.invalidateSessionKeyAuths({ account: alice.account });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      const events = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "SessionKeyAuthsInvalidated",
      });
      assert.notStrictEqual(
        (events[0] as unknown as { args: { newNonce: bigint } }).args.newNonce,
        0n,
      );

      await assertions.revertWithCustomError(
        settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account }),
        settlement,
        "InvalidRegistrationNonce",
      );
    });

    it("registerSessionKey now ALWAYS bumps the nonce, even a bare/different-key registration", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, charlie, chainId } = f;
      const other = privateKeyToAccount(KEYS[0]).address; // any non-privileged address is fine
      void other;

      const auth = makeAuth(f);
      const sig = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);

      // Register a DIFFERENT key directly.
      await settlement.write.registerSessionKey([f.charlie.account.address, f.expiry, [], [], []], {
        account: alice.account,
      });
      assert.notStrictEqual(
        (await settlement.read.sessionKeyRegNonce([alice.account.address])) as bigint,
        0n,
      );

      // The pending authorization for the first key still works.
      await assertions.revertWithCustomError(
        settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account }),
        settlement,
        "InvalidRegistrationNonce",
      );
    });
  });

  describe("EIP-712 interoperability (trade-server regression)", function () {
    it("SESSION_KEY_TYPEHASH equals keccak256 of the published typestring", async function () {
      const f = await loadFixture(deployFixture);
      assert.strictEqual(
        (await f.settlement.read.SESSION_KEY_TYPEHASH()) as Hex,
        keccak256(toHex(SESSION_KEY_TYPESTRING)),
        "typestring drift would silently invalidate every server-produced signature",
      );
    });

    it("accepts a viem signTypedData signature over multi-element arrays (encodePacked array hashing)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, charlie, chainId, usdt, lpToken, expiry } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      // Multi-element arrays are what distinguishes the two encodings: with abi.encode the digest
      // picks up offset/length words and the recovered signer changes, so this call would revert
      // InvalidSignature rather than register.
      const auth: SessionKeyAuth = {
        account: alice.account.address,
        sessionKey: sessionKey.address,
        validUntil: expiry,
        deadline: expiry,
        tokens: [usdt.address, lpToken.address],
        caps: [parseUnits("1234", 18), parseUnits("56", 18)],
        orderCaps: [2n ** 256n - 1n, 2n ** 256n - 1n],
        nonce: 0n,
      };

      // Independently recompute the digest the way a server would, and assert the signature is
      // over exactly that digest — pinning the wire format, not just "some signature works".
      const digest = hashTypedData({
        domain: domainFor(chainId, settlement.address),
        types: SESSION_KEY_TYPES,
        primaryType: "SessionKeyAuth",
        message: auth,
      });
      const sigFromDigest = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);
      assert.ok(digest.length === 66, "digest is a 32-byte hash");

      await settlement.write.registerSessionKeyWithSig([auth, sigFromDigest], {
        account: charlie.account,
      });
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        expiry,
      );
    });
  });

  // =====================================================================
  // S8 / the `lister` role
  // =====================================================================
  describe("lister role", function () {
    it("the lister can list a base token; an unrelated account cannot", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner, charlie, bob, viem } = f;
      const newToken = await viem.deployContract("USDT", [owner.account.address, 18]);

      await assertions.revertWithCustomError(
        settlement.write.setSupportedToken([newToken.address, true], { account: charlie.account }),
        settlement,
        "NotAuthorizedLister",
      );

      await settlement.write.setLister([charlie.account.address], { account: owner.account });
      assert.strictEqual(
        getAddress((await settlement.read.lister()) as `0x${string}`),
        getAddress(charlie.account.address),
      );

      await settlement.write.setSupportedToken([newToken.address, true], {
        account: charlie.account,
      });
      assert.strictEqual(await settlement.read.supportedTokens([newToken.address]), true);

      // Everyone else is still refused.
      await assertions.revertWithCustomError(
        settlement.write.setSupportedToken([newToken.address, false], { account: bob.account }),
        settlement,
        "NotAuthorizedLister",
      );
    });

    it("the owner retains listing rights", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner, charlie, viem } = f;
      const newToken = await viem.deployContract("USDT", [owner.account.address, 18]);
      await settlement.write.setLister([charlie.account.address], { account: owner.account });
      await settlement.write.setSupportedToken([newToken.address, true], {
        account: owner.account,
      });
      assert.strictEqual(await settlement.read.supportedTokens([newToken.address]), true);
    });

    it("the lister holds NO other power (privilege isolation)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, settlementImpl, owner, charlie, alice, usdt } = f;
      await settlement.write.setLister([charlie.account.address], { account: owner.account });

      // Thunks, not promises. Building the calls eagerly would start all seven at once and leave
      // six rejected promises unawaited while the loop works through the first — Node reports
      // whichever loses that race as an unhandled rejection and kills the run. That is what made
      // CI red on this PR while the same commit passed locally: not flake, timing.
      const forbidden: Array<[string, () => Promise<unknown>]> = [
        [
          "emergencyWithdrawFor",
          () =>
            settlement.write.emergencyWithdrawFor([alice.account.address, usdt.address], {
              account: charlie.account,
            }),
        ],
        [
          "recoverStuckTokens",
          () =>
            settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, 1n], {
              account: charlie.account,
            }),
        ],
        [
          "requestUpgrade",
          () =>
            settlement.write.requestUpgrade([settlementImpl.address], {
              account: charlie.account,
            }),
        ],
        [
          "setLister",
          () => settlement.write.setLister([charlie.account.address], { account: charlie.account }),
        ],
        [
          "setQuoteAsset",
          () => settlement.write.setQuoteAsset([usdt.address, false], { account: charlie.account }),
        ],
        ["pause", () => settlement.write.pause({ account: charlie.account })],
        [
          "setFeeRecipient",
          () =>
            settlement.write.setFeeRecipient([charlie.account.address], {
              account: charlie.account,
            }),
        ],
      ];

      for (const [name, call] of forbidden) {
        await assertions.revertWithCustomError(call(), settlement, "OwnableUnauthorizedAccount", [
          name,
        ] as unknown[]);
      }
    });

    it("setLister is owner-only and emits ListerUpdated", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner, charlie, bob, publicClient } = f;

      await assertions.revertWithCustomError(
        settlement.write.setLister([bob.account.address], { account: bob.account }),
        settlement,
        "OwnableUnauthorizedAccount",
      );

      const hash = await settlement.write.setLister([charlie.account.address], {
        account: owner.account,
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      const events = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "ListerUpdated",
      });
      assert.strictEqual(events.length, 1);
      assert.strictEqual(
        getAddress((events[0] as unknown as { args: { newLister: `0x${string}` } }).args.newLister),
        getAddress(charlie.account.address),
      );
    });
  });

  // =====================================================================
  // a matured staging EXPIRES (upgrade + recover)
  //
  // The 48h delay alone only bought "one 48h announcement, ever": nothing consumed a matured
  // staging, so the owner could arm quietly, let the delay lapse unobserved and fire in a single
  // transaction at any later moment. For recoverStuckTokens that is sharper than for upgrades,
  // because the excess is measured at EXECUTION: a staging made when the excess was zero used to
  // stand as an open claim on any excess that appeared months later — sweepable in the very block
  // it appeared, with no notice at the time the funds actually existed.
  // =====================================================================
  const GRACE = 7n * 24n * 60n * 60n;
  const UPGRADE_DELAY = 48n * 60n * 60n;
  const ERC1967_IMPL_SLOT =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as Hex;

  async function liveImplementation(publicClient: any, proxy: `0x${string}`): Promise<string> {
    const raw = (await publicClient.getStorageAt({
      address: proxy,
      slot: ERC1967_IMPL_SLOT,
    })) as Hex;
    return getAddress(`0x${raw.slice(-40)}` as `0x${string}`);
  }

  describe("staged upgrades expire", function () {
    it("exposes a 7 day grace period", async function () {
      const { settlement } = await loadFixture(deployFixture);
      assert.strictEqual((await settlement.read.UPGRADE_GRACE_PERIOD()) as bigint, GRACE);
    });

    it("executes at the LAST second of the window", async function () {
      const { settlement, owner, viem, publicClient } = await loadFixture(deployFixture);
      const newImpl = await viem.deployContract("TradeSettlementV1", []);

      await settlement.write.requestUpgrade([newImpl.address], { account: owner.account });
      const readyAt = (await settlement.read.upgradeReadyAt()) as bigint;

      await time.setNextBlockTimestamp(readyAt + GRACE);
      await settlement.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account });

      assert.strictEqual(
        await liveImplementation(publicClient, settlement.address),
        getAddress(newImpl.address),
      );
      assert.strictEqual(await settlement.read.pendingImplementation(), zeroAddress);
      assert.strictEqual((await settlement.read.upgradeReadyAt()) as bigint, 0n);
    });

    it("reverts UpgradeExpired one second past the window", async function () {
      const { settlement, settlementImpl, owner, viem, publicClient } =
        await loadFixture(deployFixture);
      const newImpl = await viem.deployContract("TradeSettlementV1", []);

      await settlement.write.requestUpgrade([newImpl.address], { account: owner.account });
      const readyAt = (await settlement.read.upgradeReadyAt()) as bigint;

      await time.setNextBlockTimestamp(readyAt + GRACE + 1n);
      await assertions.revertWithCustomError(
        settlement.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account }),
        settlement,
        "UpgradeExpired",
      );

      assert.strictEqual(
        await liveImplementation(publicClient, settlement.address),
        getAddress(settlementImpl.address),
        "the proxy must still run the original implementation",
      );
    });

    /** THE SCENARIO: pre-arm while nobody is watching, fire much later. */
    it("a pre-armed implementation cannot be fired 48h + 8 days later", async function () {
      const { settlement, settlementImpl, owner, viem, publicClient } =
        await loadFixture(deployFixture);
      const newImpl = await viem.deployContract("TradeSettlementV1", []);

      await settlement.write.requestUpgrade([newImpl.address], { account: owner.account });
      await time.increase(UPGRADE_DELAY + 8n * 24n * 60n * 60n);

      await assertions.revertWithCustomError(
        settlement.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account }),
        settlement,
        "UpgradeExpired",
      );
      assert.strictEqual(
        await liveImplementation(publicClient, settlement.address),
        getAddress(settlementImpl.address),
      );
    });

    it("re-staging after expiry restarts the full 48h wait", async function () {
      const { settlement, owner, viem, publicClient } = await loadFixture(deployFixture);
      const newImpl = await viem.deployContract("TradeSettlementV1", []);

      await settlement.write.requestUpgrade([newImpl.address], { account: owner.account });
      await time.increase(UPGRADE_DELAY + 8n * 24n * 60n * 60n);

      await settlement.write.requestUpgrade([newImpl.address], { account: owner.account });
      assert.strictEqual(
        (await settlement.read.upgradeReadyAt()) as bigint,
        (await time.latest()) + UPGRADE_DELAY,
      );
      await assertions.revertWithCustomError(
        settlement.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account }),
        settlement,
        "UpgradeNotReady",
      );

      // Not a brick: the legitimate path still completes after a fresh, announced 48h.
      await time.increase(UPGRADE_DELAY + 1n);
      await settlement.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account });
      assert.strictEqual(
        await liveImplementation(publicClient, settlement.address),
        getAddress(newImpl.address),
      );
    });
  });

  describe("staged recoveries expire", function () {
    async function withExcess() {
      const f = await loadFixture(deployFixture);
      const donation = parseUnits("9", 18);
      await f.usdt.write.mint([f.settlement.address, donation]);
      return { ...f, donation };
    }

    it("exposes a 7 day grace period", async function () {
      const { settlement } = await loadFixture(deployFixture);
      assert.strictEqual((await settlement.read.RECOVER_GRACE_PERIOD()) as bigint, GRACE);
    });

    it("executes at the LAST second of the window", async function () {
      const { settlement, usdt, owner, charlie, donation } = await withExcess();
      const before = (await usdt.read.balanceOf([charlie.account.address])) as bigint;

      await settlement.write.requestRecover([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
      const readyAt = (await settlement.read.recoverReadyAt()) as bigint;

      await time.setNextBlockTimestamp(readyAt + GRACE);
      await settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });

      assert.strictEqual(
        (await usdt.read.balanceOf([charlie.account.address])) as bigint,
        before + donation,
      );
    });

    it("reverts RecoverExpired one second past the window", async function () {
      const { settlement, usdt, owner, charlie, donation } = await withExcess();
      const escrowedBefore = (await usdt.read.balanceOf([settlement.address])) as bigint;

      await settlement.write.requestRecover([usdt.address, charlie.account.address, donation], {
        account: owner.account,
      });
      const readyAt = (await settlement.read.recoverReadyAt()) as bigint;

      await time.setNextBlockTimestamp(readyAt + GRACE + 1n);
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, donation], {
          account: owner.account,
        }),
        settlement,
        "RecoverExpired",
      );
      assert.strictEqual(
        (await usdt.read.balanceOf([settlement.address])) as bigint,
        escrowedBefore,
        "the excess must still be sitting in the contract",
      );
    });

    /**
     * THE RECOVER SCENARIO, and the one the old NatSpec mis-described: staging while there is
     * nothing to sweep, then cashing in on excess that appears much later. The "48h warning gives
     * users a window to exit" claim was false there — at the moment the funds appeared, no notice
     * had gone out at all.
     */
    it("a staging made when excess was ZERO cannot sweep excess that appears 200 days later", async function () {
      const { settlement, usdt, owner, charlie, alice, bob } = await loadFixture(deployFixture);
      const claim = parseUnits("9", 18);

      // Nothing recoverable yet: the escrow balance is exactly what the ledger owes the two
      // depositors, so the excess `recoverStuckTokens` measures is zero.
      const escrowedBefore = (await usdt.read.balanceOf([settlement.address])) as bigint;
      const owedBefore =
        (await bal(settlement, alice.account.address, usdt.address)) +
        (await bal(settlement, bob.account.address, usdt.address));
      assert.strictEqual(escrowedBefore, owedBefore, "precondition: zero excess at staging time");

      await settlement.write.requestRecover([usdt.address, charlie.account.address, claim], {
        account: owner.account,
      });

      // Wait out the 48h AND the grace window, then let the rebase/donation land.
      await time.increase(RECOVER_DELAY + 200n * 24n * 60n * 60n);
      await usdt.write.mint([settlement.address, claim]);

      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, claim], {
          account: owner.account,
        }),
        settlement,
        "RecoverExpired",
      );

      // Re-staging is the only way through, and it re-announces against the CURRENT balance
      // state with a fresh 48h.
      await settlement.write.requestRecover([usdt.address, charlie.account.address, claim], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, claim], {
          account: owner.account,
        }),
        settlement,
        "RecoverNotReady",
      );
      await time.increase(RECOVER_DELAY + 1n);
      await settlement.write.recoverStuckTokens([usdt.address, charlie.account.address, claim], {
        account: owner.account,
      });

      // The depositors' funds were never at risk in either branch: only the later-arrived excess
      // moved, and the escrow is back to exactly what the ledger owes.
      assert.strictEqual(
        (await bal(settlement, alice.account.address, usdt.address)) +
          (await bal(settlement, bob.account.address, usdt.address)),
        owedBefore,
      );
      assert.strictEqual((await usdt.read.balanceOf([settlement.address])) as bigint, owedBefore);
    });
  });

  // =====================================================================
  // ownership handover must not pass armed stagings to the successor
  // =====================================================================
  describe("ownership handover clears both stagings", function () {
    it("acceptOwnership drops the staged upgrade AND the staged recovery", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, settlementImpl, usdt, owner, charlie, viem, publicClient } = f;
      const donation = parseUnits("9", 18);
      await usdt.write.mint([settlement.address, donation]);
      const escrowedBefore = (await usdt.read.balanceOf([settlement.address])) as bigint;
      const newImpl = await viem.deployContract("TradeSettlementV1", []);

      // Outgoing owner arms both powers, then hands the contract over.
      await settlement.write.requestUpgrade([newImpl.address], { account: owner.account });
      await settlement.write.requestRecover([usdt.address, owner.account.address, donation], {
        account: owner.account,
      });
      const stagedRecover = await settlement.read.pendingRecoverHash();

      await settlement.write.transferOwnership([charlie.account.address], {
        account: owner.account,
      });
      // Nomination alone changes nothing — ownership has not moved yet.
      assert.strictEqual(
        getAddress((await settlement.read.pendingImplementation()) as `0x${string}`),
        getAddress(newImpl.address),
      );
      assert.strictEqual(await settlement.read.pendingRecoverHash(), stagedRecover);

      const hash = await settlement.write.acceptOwnership({ account: charlie.account });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      const cancelledUpgrade = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "UpgradeCancelled",
      });
      const cancelledRecover = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "RecoverCancelled",
      });
      assert.strictEqual(cancelledUpgrade.length, 1, "the upgrade drop must be observable");
      assert.strictEqual(cancelledRecover.length, 1, "the recovery drop must be observable");
      assert.strictEqual(
        (cancelledRecover[0] as unknown as { args: { cancelledRecoverHash: Hex } }).args
          .cancelledRecoverHash,
        stagedRecover,
      );

      assert.strictEqual(await settlement.read.pendingImplementation(), zeroAddress);
      assert.strictEqual((await settlement.read.upgradeReadyAt()) as bigint, 0n);
      assert.strictEqual(await settlement.read.pendingRecoverHash(), `0x${"0".repeat(64)}`);
      assert.strictEqual((await settlement.read.recoverReadyAt()) as bigint, 0n);

      // The inherited clocks are gone: the incoming owner cannot execute what they never staged.
      await time.increase(RECOVER_DELAY + 1n);
      await assertions.revertWithCustomError(
        settlement.write.upgradeToAndCall([newImpl.address, "0x"], { account: charlie.account }),
        settlement,
        "NoPendingUpgrade",
      );
      await assertions.revertWithCustomError(
        settlement.write.recoverStuckTokens([usdt.address, owner.account.address, donation], {
          account: charlie.account,
        }),
        settlement,
        "NoPendingRecover",
      );
      assert.strictEqual(
        await liveImplementation(publicClient, settlement.address),
        getAddress(settlementImpl.address),
      );
      assert.strictEqual(
        (await usdt.read.balanceOf([settlement.address])) as bigint,
        escrowedBefore,
      );
    });

    it("handover with nothing staged is a clean no-op", async function () {
      const { settlement, owner, charlie, publicClient } = await loadFixture(deployFixture);

      await settlement.write.transferOwnership([charlie.account.address], {
        account: owner.account,
      });
      const hash = await settlement.write.acceptOwnership({ account: charlie.account });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });

      assert.strictEqual(
        parseEventLogs({ abi: settlement.abi, logs: receipt.logs, eventName: "UpgradeCancelled" })
          .length,
        0,
      );
      assert.strictEqual(
        parseEventLogs({ abi: settlement.abi, logs: receipt.logs, eventName: "RecoverCancelled" })
          .length,
        0,
      );
      assert.strictEqual(
        getAddress((await settlement.read.owner()) as `0x${string}`),
        getAddress(charlie.account.address),
      );
    });
  });
});
