/**
 * VerifyingPaymaster v2 (policy-storage) tests.
 * Per-wallet sponsorship policy lives in the paymaster's OWN storage keyed by userOp.sender —
 * no backend signature, no external registry read during validation. Runtime decisions
 * (ON/OFF, business-only gating, per-wallet cap, global budget, pause, gas floor, defensive
 * calldata decode) are exercised end-to-end through a real EntryPoint v0.8 `handleOps` path
 * (TestEntryPoint), since `_validatePaymasterUserOp` MUST NOT read block.timestamp and the
 * cap/budget deferral semantics only show up when the EntryPoint itself evaluates `validAfter`.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  getAddress,
  zeroAddress,
  parseEther,
  parseEventLogs,
  hexToBytes,
  type Address,
  type Hex,
} from "viem";
import { loadFixture, getConnection, time, assertions } from "./helpers.js";
import {
  passkeyPubCoords,
  packU128Pair,
  buildExecuteCallData,
  buildExecuteBatchCallData,
  paymasterAndDataFor,
  craftedBatchCallData,
  execWithPaymaster,
  computeMaxCost,
} from "./aa-helpers.js";

// Deterministic P-256 test keys (NOT for production). Scalars < n. Reused from StarzipWallet.test.ts.
const PASSKEY_PRIV_A = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const PASSKEY_PRIV_B = hexToBytes(
  "0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464" as Hex,
);

const OWNER_SENTINEL = "0x000000000000000000000000000000000000dEaD" as Address;
const SALT_A = 501n;
const SALT_B = 502n;

// Standard userOp gas profile for paymaster tests: modest, fixed values so EntryPoint's
// deterministic maxCost = (verificationGasLimit + callGasLimit + paymasterVerificationGasLimit +
// paymasterPostOpGasLimit + preVerificationGas) * maxFeePerGas (EntryPoint._getRequiredPrefund)
// can be pinned EXACTLY — cap/budget boundary tests rely on this instead of guessed margins.
const VER_GAS = 150_000n;
const CALL_GAS = 150_000n;
const PRE_VER_GAS = 50_000n;
const PM_VAL_GAS = 100_000n;
const PM_POST_GAS = 100_000n; // > MIN_POSTOP_GAS (90_000, see VerifyingPaymaster.sol M-1 derivation)
const MAX_FEE_PER_GAS = 1_000_000_000n; // 1 gwei

const ACCOUNT_GAS_LIMITS = packU128Pair(VER_GAS, CALL_GAS);
const GAS_FEES = packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS);

// The EXACT maxCost EntryPoint will compute for a userOp built with the fields above.
const MAX_COST = computeMaxCost({
  verificationGasLimit: VER_GAS,
  callGasLimit: CALL_GAS,
  paymasterVerificationGasLimit: PM_VAL_GAS,
  paymasterPostOpGasLimit: PM_POST_GAS,
  preVerificationGas: PRE_VER_GAS,
  maxFeePerGas: MAX_FEE_PER_GAS,
});

async function deployFixture() {
  const { viem } = await getConnection();
  const [deployer, ownerWallet, policyManagerWallet, beneficiary, stranger] =
    await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();

  const entryPoint = await viem.deployContract("TestEntryPoint", []);
  const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address]);

  const { x: PK_X_A, y: PK_Y_A } = passkeyPubCoords(PASSKEY_PRIV_A);
  const { x: PK_X_B, y: PK_Y_B } = passkeyPubCoords(PASSKEY_PRIV_B);

  await factory.write.createAccount([PK_X_A, PK_Y_A, OWNER_SENTINEL, SALT_A], {
    account: deployer.account,
  });
  const walletAAddr = (await factory.read.getAddress([
    PK_X_A,
    PK_Y_A,
    OWNER_SENTINEL,
    SALT_A,
  ])) as Address;
  const walletA = await viem.getContractAt("StarzipWallet", walletAAddr);

  await factory.write.createAccount([PK_X_B, PK_Y_B, OWNER_SENTINEL, SALT_B], {
    account: deployer.account,
  });
  const walletBAddr = (await factory.read.getAddress([
    PK_X_B,
    PK_Y_B,
    OWNER_SENTINEL,
    SALT_B,
  ])) as Address;
  const walletB = await viem.getContractAt("StarzipWallet", walletBAddr);

  // Deploy as `ownerWallet` so Ownable2Step's owner() != policyManager (distinct hot/cold roles).
  const paymaster = await viem.deployContract(
    "VerifyingPaymaster",
    [entryPoint.address, policyManagerWallet.account.address],
    { client: { wallet: ownerWallet } },
  );

  // Fund the paymaster's EntryPoint deposit generously (deposit is the hard ceiling on drain).
  const depositHash = await deployer.sendTransaction({
    to: paymaster.address,
    value: parseEther("10"),
    data: "0xd0e30db0" as Hex, // deposit() selector
  });
  await publicClient.waitForTransactionReceipt({ hash: depositHash });

  // A little native ETH on each wallet for the self-paid-fallback / opReverted-with-value tests.
  for (const addr of [walletAAddr, walletBAddr]) {
    const fundHash = await deployer.sendTransaction({ to: addr, value: parseEther("2") });
    await publicClient.waitForTransactionReceipt({ hash: fundHash });
  }

  return {
    viem,
    publicClient,
    entryPoint,
    factory,
    paymaster,
    walletA,
    walletAAddr,
    walletB,
    walletBAddr,
    deployer,
    owner: ownerWallet,
    policyManager: policyManagerWallet,
    beneficiary,
    stranger,
  };
}

type Ctx = Awaited<ReturnType<typeof deployFixture>>;

async function ownerWrite(ctx: Ctx, fn: string, args: unknown[] = [], value = 0n): Promise<void> {
  const hash = await (ctx.paymaster.write as any)[fn](args, { account: ctx.owner.account, value });
  await ctx.publicClient.waitForTransactionReceipt({ hash });
}

async function pmWrite(ctx: Ctx, fn: string, args: unknown[] = []): Promise<void> {
  const hash = await (ctx.paymaster.write as any)[fn](args, { account: ctx.policyManager.account });
  await ctx.publicClient.waitForTransactionReceipt({ hash });
}

// Comfortable global config + per-wallet provisioning so a sponsored op just works, unless the
// test overrides one of the knobs itself afterwards.
async function setupHappyPath(
  ctx: Ctx,
  wallet: Address,
  opts: { dailyCap?: bigint; sponsorPersonal?: boolean } = {},
): Promise<void> {
  await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
  await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
  await pmWrite(ctx, "setSponsored", [wallet, true]);
  if (opts.sponsorPersonal) await pmWrite(ctx, "setSponsorPersonal", [wallet, true]);
  if (opts.dailyCap !== undefined) await pmWrite(ctx, "setDailyCap", [wallet, opts.dailyCap]);
  await ownerWrite(ctx, "unpause");
}

function opSucceeded(receipt: any, entryPointAbi: any): boolean {
  const ev = parseEventLogs({
    abi: entryPointAbi,
    logs: receipt.logs,
    eventName: "UserOperationEvent",
  });
  return ev.length > 0 && (ev[0] as any).args.success === true;
}

// Submit a passkey-signed userOp sponsored by the paymaster, using the fixed standard gas
// profile (so EntryPoint's maxCost == MAX_COST unless postGas/valGas is overridden).
async function submitSponsored(
  ctx: Ctx,
  params: {
    walletAddr: Address;
    passkeyPriv: Uint8Array;
    callData: Hex;
    postGas?: bigint;
    valGas?: bigint;
  },
) {
  return execWithPaymaster({
    publicClient: ctx.publicClient,
    entryPoint: ctx.entryPoint,
    walletAddr: params.walletAddr,
    callData: params.callData,
    paymasterAndData: paymasterAndDataFor(
      ctx.paymaster.address,
      params.valGas ?? PM_VAL_GAS,
      params.postGas ?? PM_POST_GAS,
    ),
    passkeyPriv: params.passkeyPriv,
    submitter: ctx.deployer,
    beneficiary: ctx.beneficiary.account.address,
    accountGasLimits: ACCOUNT_GAS_LIMITS,
    preVerificationGas: PRE_VER_GAS,
    gasFees: GAS_FEES,
  });
}

describe("VerifyingPaymaster (policy-storage)", function () {
  // ============ Roles / deploy / pause ============
  describe("Roles / deploy / pause", function () {
    it("constructor sets policyManager, rejects zero-address, and starts paused", async function () {
      const ctx = await loadFixture(deployFixture);
      assert.strictEqual(
        getAddress((await ctx.paymaster.read.policyManager()) as string),
        getAddress(ctx.policyManager.account.address),
      );
      assert.strictEqual(await ctx.paymaster.read.paused(), true);

      await assertions.revertWithCustomError(
        ctx.viem.deployContract("VerifyingPaymaster", [ctx.entryPoint.address, zeroAddress]),
        null,
        "ZeroAddress",
      );
    });

    it("owner is deployer (Ownable2Step); setPolicyManager is owner-only + emits", async function () {
      const ctx = await loadFixture(deployFixture);
      assert.strictEqual(
        getAddress((await ctx.paymaster.read.owner()) as string),
        getAddress(ctx.owner.account.address),
      );

      await assertions.revert(
        ctx.paymaster.write.setPolicyManager([ctx.stranger.account.address], {
          account: ctx.stranger.account,
        }),
      );

      const hash = await ctx.paymaster.write.setPolicyManager([ctx.stranger.account.address], {
        account: ctx.owner.account,
      });
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
      const ev = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "PolicyManagerChanged",
      })[0] as any;
      assert.strictEqual(getAddress(ev.args.newManager), getAddress(ctx.stranger.account.address));
    });

    it("pause() allowed for owner AND policyManager, reverts for a stranger; unpause() owner-only", async function () {
      const ctx = await loadFixture(deployFixture);

      let hash = await ctx.paymaster.write.pause([], { account: ctx.policyManager.account });
      await ctx.publicClient.waitForTransactionReceipt({ hash });
      assert.strictEqual(await ctx.paymaster.read.paused(), true);

      hash = await ctx.paymaster.write.unpause([], { account: ctx.owner.account });
      await ctx.publicClient.waitForTransactionReceipt({ hash });
      assert.strictEqual(await ctx.paymaster.read.paused(), false);

      hash = await ctx.paymaster.write.pause([], { account: ctx.owner.account });
      await ctx.publicClient.waitForTransactionReceipt({ hash });
      assert.strictEqual(await ctx.paymaster.read.paused(), true);

      await assertions.revertWithCustomError(
        ctx.paymaster.write.pause([], { account: ctx.stranger.account }),
        ctx.paymaster,
        "NotOwnerOrPolicyManager",
      );

      await assertions.revert(
        ctx.paymaster.write.unpause([], { account: ctx.policyManager.account }),
      );
    });

    it("while paused, an otherwise-sponsorable op is HARD-declined; after unpause, sponsored", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, parseEther("1")]);
      // still paused (constructor default) — do NOT unpause yet.

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
      );

      await ownerWrite(ctx, "unpause");
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
    });
  });

  // ============ Admin access control / provisioning gate (M2) / ceiling ============
  describe("Admin access control / provisioning gate / ceiling", function () {
    it("hot setters revert NotPolicyManager for a non-manager", async function () {
      const ctx = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setSponsored([ctx.walletAAddr, true], {
          account: ctx.stranger.account,
        }),
        ctx.paymaster,
        "NotPolicyManager",
      );
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setDailyCap([ctx.walletAAddr, 1n], { account: ctx.stranger.account }),
        ctx.paymaster,
        "NotPolicyManager",
      );
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setSponsorPersonal([ctx.walletAAddr, true], {
          account: ctx.stranger.account,
        }),
        ctx.paymaster,
        "NotPolicyManager",
      );
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setSponsoredBatch([[ctx.walletAAddr], true], {
          account: ctx.stranger.account,
        }),
        ctx.paymaster,
        "NotPolicyManager",
      );
    });

    it("allowlist + VIP + budget/ceiling setters are owner-only", async function () {
      const ctx = await loadFixture(deployFixture);
      await assertions.revert(
        ctx.paymaster.write.setBusinessTarget([ctx.stranger.account.address, true], {
          account: ctx.stranger.account,
        }),
      );
      await assertions.revert(
        ctx.paymaster.write.setSponsoredUnlimited([ctx.walletAAddr, true], {
          account: ctx.stranger.account,
        }),
      );
      await assertions.revert(
        ctx.paymaster.write.setGlobalDailyBudget([1n], { account: ctx.stranger.account }),
      );
      await assertions.revert(
        ctx.paymaster.write.setGlobalDailyCapCeiling([1n], { account: ctx.stranger.account }),
      );
    });

    it("setDailyCap(0) -> ZeroCapNotAllowed; > ceiling -> CapExceedsCeiling; 1..ceiling ok", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);

      await assertions.revertWithCustomError(
        ctx.paymaster.write.setDailyCap([ctx.walletAAddr, 0n], {
          account: ctx.policyManager.account,
        }),
        ctx.paymaster,
        "ZeroCapNotAllowed",
      );
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setDailyCap([ctx.walletAAddr, parseEther("2")], {
          account: ctx.policyManager.account,
        }),
        ctx.paymaster,
        "CapExceedsCeiling",
      );
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, parseEther("1")]); // == ceiling, ok
    });

    it("sponsored=true but dailyCap==0 (non-VIP) => HARD-declined (M2)", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "unpause");
      // dailyCap never set -> 0

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
      );
    });

    it("globalDailyBudget==0 => every op HARD-declined (safe default)", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      // budget left at its 0 default
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, parseEther("1")]);
      await ownerWrite(ctx, "unpause");

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
      );
    });
  });

  // ============ Gas floor (B2) ============
  describe("Gas floor (B2)", function () {
    it("paymasterPostOpGasLimit < MIN_POSTOP_GAS => HARD-declined; >= MIN_POSTOP_GAS => sponsored", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, {
        sponsorPersonal: true,
        dailyCap: parseEther("1"),
      });

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      const minPostOpGas = (await ctx.paymaster.read.MIN_POSTOP_GAS()) as bigint;

      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
          postGas: minPostOpGas - 1n,
        }),
      );

      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
        postGas: minPostOpGas,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
    });
  });

  // ============ Per-op maxCost cap (M-2 mitigation) ============
  describe("Per-op maxCost cap (M-2 mitigation)", function () {
    it("maxSponsoredOpCost==0 (default): disabled, no per-op limit", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, {
        sponsorPersonal: true,
        dailyCap: parseEther("1"),
      });
      assert.strictEqual((await ctx.paymaster.read.maxSponsoredOpCost()) as bigint, 0n);

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
    });

    it("setMaxSponsoredOpCost is owner-only and emits MaxSponsoredOpCostSet", async function () {
      const ctx = await loadFixture(deployFixture);
      await assertions.revert(
        ctx.paymaster.write.setMaxSponsoredOpCost([MAX_COST], { account: ctx.stranger.account }),
      );

      const hash = await ctx.paymaster.write.setMaxSponsoredOpCost([MAX_COST], {
        account: ctx.owner.account,
      });
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
      const ev = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "MaxSponsoredOpCostSet",
      })[0] as any;
      assert.strictEqual(ev.args.cost, MAX_COST);
      assert.strictEqual((await ctx.paymaster.read.maxSponsoredOpCost()) as bigint, MAX_COST);
    });

    it("maxCost > cap => HARD-declined; maxCost == cap => sponsored", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, {
        sponsorPersonal: true,
        dailyCap: parseEther("1"),
      });
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [MAX_COST - 1n]);

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
      );

      await ownerWrite(ctx, "setMaxSponsoredOpCost", [MAX_COST]);
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
    });
  });

  // ============ Sponsorship decision + defensive decode ============
  describe("Sponsorship decision + defensive decode", function () {
    it("ON/OFF: sponsored=false declines; sponsored=true proceeds", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, parseEther("1")]);
      await ownerWrite(ctx, "unpause");
      // sponsored never set -> false

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
      );

      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
    });

    it("sponsorPersonal=false: business-in-allowlist sponsored, out-of-allowlist declined", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") }); // sponsorPersonal left false

      const businessTarget = ctx.stranger.account.address;
      await ownerWrite(ctx, "setBusinessTarget", [businessTarget, true]);

      const okCallData = buildExecuteCallData(ctx.walletA.abi, businessTarget, 0n);
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: okCallData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));

      const notAllowed = ctx.beneficiary.account.address;
      const badCallData = buildExecuteCallData(ctx.walletA.abi, notAllowed, 0n);
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: badCallData,
        }),
      );
    });

    it("sponsorPersonal=true: any target is sponsored", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, {
        sponsorPersonal: true,
        dailyCap: parseEther("1"),
      });

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.beneficiary.account.address, 0n);
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
    });

    it("executeBatch: all-in-allowlist sponsored; mixed declined; personal sponsors regardless", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });

      const t1 = ctx.stranger.account.address;
      const t2 = ctx.beneficiary.account.address;
      await ownerWrite(ctx, "setBusinessTargets", [[t1, t2], true]);

      const allInCallData = buildExecuteBatchCallData(
        ctx.walletA.abi,
        [t1, t2],
        [0n, 0n],
        ["0x", "0x"],
      );
      const r1 = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: allInCallData,
      });
      assert.ok(opSucceeded(r1, ctx.entryPoint.abi));

      // remove t2 from the allowlist -> mixed batch
      await ownerWrite(ctx, "setBusinessTarget", [t2, false]);
      const mixedCallData = buildExecuteBatchCallData(
        ctx.walletA.abi,
        [t1, t2],
        [0n, 0n],
        ["0x", "0x"],
      );
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: mixedCallData,
        }),
      );

      // sponsorPersonal=true skips the allowlist check entirely -> same mixed batch now sponsored
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      const r3 = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: mixedCallData,
      });
      assert.ok(opSucceeded(r3, ctx.entryPoint.abi));
    });

    it("crafted calldata declines cleanly (AA34), never hard-reverts (AA33)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") }); // sponsorPersonal=false

      const variants = ["unknownSelector", "short", "badOffset", "oversizedN"] as const;
      for (const variant of variants) {
        const callData = craftedBatchCallData(variant);
        await assert.rejects(
          submitSponsored(ctx, {
            walletAddr: ctx.walletAAddr,
            passkeyPriv: PASSKEY_PRIV_A,
            callData,
          }),
          (error: unknown) => {
            const msg = String(error);
            assert.ok(
              !msg.includes("AA33"),
              `must not hard-revert (AA33) for variant "${variant}": ${msg.slice(0, 300)}`,
            );
            return true;
          },
        );
      }
    });

    it("soft-fail fallback: a declined op re-submitted without paymasterAndData succeeds self-paid", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await ownerWrite(ctx, "unpause");
      // NOT sponsored -> paymaster path declines

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
      );

      // resubmit WITHOUT paymasterAndData (self-paid, using the wallet's own funded balance)
      const receipt = await execWithPaymaster({
        publicClient: ctx.publicClient,
        entryPoint: ctx.entryPoint,
        walletAddr: ctx.walletAAddr,
        callData,
        paymasterAndData: "0x",
        passkeyPriv: PASSKEY_PRIV_A,
        submitter: ctx.deployer,
        beneficiary: ctx.beneficiary.account.address,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
    });
  });

  // ============ Per-wallet cap + validAfter deferral ============
  describe("Per-wallet cap + validAfter deferral", function () {
    it("within cap: sponsored; spentToday accrues actualGasCost", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, {
        sponsorPersonal: true,
        dailyCap: parseEther("1"),
      });

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));

      const ev = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "GasSponsored",
      })[0] as any;
      assert.ok(ev.args.walletSpentTodayAfter > 0n);

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAAddr])) as any;
      assert.strictEqual(policy.spentToday, ev.args.walletSpentTodayAfter);
    });

    it("over cap same day => deferred (not due); after rollover, sponsored + spentToday reset", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [MAX_COST]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]); // generous — not the bottleneck
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, MAX_COST]); // == this profile's exact maxCost
      await ownerWrite(ctx, "unpause");

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);

      // op1: spentToday(0) + MAX_COST > dailyCap(MAX_COST)? false -> succeeds (boundary).
      const r1 = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(r1, ctx.entryPoint.abi));

      // op2, same day: spentToday(actual>0) + MAX_COST > dailyCap(MAX_COST) -> true -> deferred (AA32).
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
      );

      // advance a full UTC day -> validAfter is now in the past -> succeeds, spentToday resets.
      await time.increase(86_400n);
      const r3 = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(r3, ctx.entryPoint.abi));

      const ev3 = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: r3.logs,
        eventName: "GasSponsored",
      })[0] as any;
      assert.ok(
        ev3.args.walletSpentTodayAfter <= MAX_COST,
        "spentToday must reset, not accumulate across the day boundary",
      );
    });

    it("stale-day path: exhausted on day D, advance a day, sponsored immediately (no lockout)", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [MAX_COST]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, MAX_COST]);
      await ownerWrite(ctx, "unpause");

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);

      // establish lastSpentDay = D
      const r1 = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(r1, ctx.entryPoint.abi));

      // do NOT touch the wallet again on day D; jump straight to day D+1.
      await time.increase(86_400n);

      const r2 = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(
        opSucceeded(r2, ctx.entryPoint.abi),
        "stale-day exhaustion must not permanently lock out",
      );
    });
  });

  // ============ Global budget + VIP accrual ============
  describe("Global budget + VIP accrual", function () {
    it("two wallets each within their own cap but together exceeding globalDailyBudget => deferred, then rollover succeeds", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [MAX_COST]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [MAX_COST]); // shared ceiling == one op's maxCost
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, MAX_COST]);
      await pmWrite(ctx, "setSponsored", [ctx.walletBAddr, true]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletBAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletBAddr, MAX_COST]);
      await ownerWrite(ctx, "unpause");

      const callDataA = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      const callDataB = buildExecuteCallData(ctx.walletB.abi, ctx.walletBAddr, 0n);

      // wallet A: globalSpentToday(0) + MAX_COST > budget(MAX_COST)? false -> succeeds.
      const rA = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: callDataA,
      });
      assert.ok(opSucceeded(rA, ctx.entryPoint.abi));

      // wallet B: globalSpentToday(actualA>0) + MAX_COST > budget(MAX_COST) -> deferred, even
      // though wallet B is comfortably within its OWN per-wallet dailyCap.
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletBAddr,
          passkeyPriv: PASSKEY_PRIV_B,
          callData: callDataB,
        }),
      );

      await time.increase(86_400n);
      const rB2 = await submitSponsored(ctx, {
        walletAddr: ctx.walletBAddr,
        passkeyPriv: PASSKEY_PRIV_B,
        callData: callDataB,
      });
      assert.ok(opSucceeded(rB2, ctx.entryPoint.abi));
    });

    it("VIP: sponsored ignoring dailyCap (even 0); globalSpentToday still increases", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "unpause");
      // dailyCap left at 0 -- VIP bypasses the M2 provisioning gate entirely.

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));

      const ev = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "GasSponsored",
      })[0] as any;
      assert.ok(
        ev.args.globalSpentTodayAfter > 0n,
        "VIP op must still accrue to the global ledger",
      );
    });

    it("VIP op that would cross globalDailyBudget is still deferred (bounded by global, not per-wallet)", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyBudget", [MAX_COST]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "unpause");

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      const r1 = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(r1, ctx.entryPoint.abi));

      // second VIP op, same day: globalSpentToday(actual>0) + MAX_COST > budget(MAX_COST) -> deferred.
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
      );
    });
  });

  // ============ Accounting invariants ============
  describe("Accounting invariants", function () {
    it("sponsorship debits the paymaster's EntryPoint deposit; wallet's own balance is untouched", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, {
        sponsorPersonal: true,
        dailyCap: parseEther("1"),
      });

      const depositBefore = (await ctx.entryPoint.read.balanceOf([
        ctx.paymaster.address,
      ])) as bigint;
      const walletBalBefore = await ctx.publicClient.getBalance({ address: ctx.walletAAddr });

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));

      const depositAfter = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;
      const walletBalAfter = await ctx.publicClient.getBalance({ address: ctx.walletAAddr });

      assert.ok(depositAfter < depositBefore, "paymaster deposit must decrease");
      assert.strictEqual(walletBalAfter, walletBalBefore, "wallet's own balance must be untouched");
    });

    it("opReverted path still accrues gas cost", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });

      // allowlist a target with no receive()/fallback so the inner call (and wallet.execute) reverts.
      await ownerWrite(ctx, "setBusinessTarget", [ctx.factory.address, true]);
      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.factory.address, 1n);

      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.strictEqual(opSucceeded(receipt, ctx.entryPoint.abi), false, "inner call must fail");

      const ev = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "GasSponsored",
      })[0] as any;
      assert.ok(ev, "postOp must still run on opReverted");
      assert.ok(ev.args.walletSpentTodayAfter > 0n, "opReverted must still accrue gas cost");
    });
  });
});
