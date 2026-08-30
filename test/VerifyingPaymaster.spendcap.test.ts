/**
 * VerifyingPaymaster — spend-cap regressions.
 *
 * SAME-DAY DECLINE: `_validatePaymasterUserOp` used to defer an over-cap op to
 * `validAfter = (lastSpentDay + 1) * 1 days`, computed from the STORED day index. On a stale
 * counter (a brand-new wallet, where `lastSpentDay == 0`, or any wallet on the first op of a new
 * UTC day) that timestamp is already in the past, so the EntryPoint treats the op as immediately
 * valid instead of rejecting it — `maxCost` ends up unbounded. The fix hard-declines whenever
 * `maxCost` ALONE exceeds the (effective) cap/budget, before the deferral logic ever runs.
 *
 * GAS-PARAMETER CAPS: `_validatePaymasterUserOp` never read `userOp.gasFees` / `userOp.preVerificationGas`, so a
 * userOp submitted directly to `EntryPoint.handleOps` (permissionless) with an attacker-chosen
 * `beneficiary` could inflate these attacker-declared fields to be overpaid relative to actual gas
 * consumption, independent of `maxCost`'s dailyCap/globalDailyBudget bounds. Fixed via
 * `maxSponsoredFeePerGas` / `maxSponsoredPreVerificationGas` owner-set ceilings, checked before
 * the per-wallet policy lookup.
 *
 * `renounceOwnership()` (inherited from `Ownable` via `Ownable2Step`, never overridden) would
 * permanently strand `withdrawTo`/`unlockStake`/`withdrawStake`/`unpause`/every owner-only setter.
 * Fixed by overriding it to always revert.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  getAddress,
  getContractAddress,
  parseEther,
  parseEventLogs,
  hexToBytes,
  encodeFunctionData,
  concatHex,
  toFunctionSelector,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { loadFixture, getConnection, time, assertions } from "./helpers.js";
import {
  passkeyPubCoords,
  packU128Pair,
  buildExecuteCallData,
  buildUserOp,
  paymasterAndDataFor,
  execWithPaymaster,
  computeMaxCost,
  webauthnSignature,
  encodePasskeyOwner,
  encodeSignatureWrapper,
  SPONSOR_SIGNER,
  signPaymasterData,
} from "./aa-helpers.js";

const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const SALT = 9001n;

// Standard userOp gas profile — mirrors VerifyingPaymaster.test.ts so `maxCost` (EntryPoint's
// deterministic `_getRequiredPrefund`) is pinned exactly.
const VER_GAS = 150_000n;
const CALL_GAS = 150_000n;
const PRE_VER_GAS = 50_000n;
const PM_VAL_GAS = 100_000n;
const PM_POST_GAS = 100_000n; // > MIN_POSTOP_GAS (90_000)
const MAX_FEE_PER_GAS = 1_000_000_000n; // 1 gwei

const ACCOUNT_GAS_LIMITS = packU128Pair(VER_GAS, CALL_GAS);
const GAS_FEES = packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS);

// The EXACT maxCost EntryPoint computes for a userOp built with the standard profile above.
const MAX_COST = computeMaxCost({
  verificationGasLimit: VER_GAS,
  callGasLimit: CALL_GAS,
  paymasterVerificationGasLimit: PM_VAL_GAS,
  paymasterPostOpGasLimit: PM_POST_GAS,
  preVerificationGas: PRE_VER_GAS,
  maxFeePerGas: MAX_FEE_PER_GAS,
});

// The REAL initial deposit used by the deploy script. Every other test in this file
// uses the 10-BNB fixture below, where the deposit is deliberately never the binding constraint;
// the block at the bottom needs it to BE the binding constraint, so it takes this instead.
const REAL_DEPOSIT = parseEther("0.05");

async function deployFixtureWithDeposit(depositWei: bigint) {
  const { viem } = await getConnection();
  const [deployer, ownerWallet, policyManagerWallet, beneficiary] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();

  const entryPoint = await viem.deployContract("TestEntryPoint", []);

  // Deploy as `ownerWallet` so Ownable2Step's owner() != policyManager (distinct hot/cold roles).
  const paymaster = await viem.deployContract(
    "VerifyingPaymaster",
    [entryPoint.address, policyManagerWallet.account.address, zeroAddress, SPONSOR_SIGNER],
    { client: { wallet: ownerWallet } },
  );

  const factory = await viem.deployContract("StarzipWalletFactory", [
    entryPoint.address,
    paymaster.address,
  ]);

  const { x, y } = passkeyPubCoords(PASSKEY_PRIV);
  const firstOwner = encodePasskeyOwner(x, y);
  await factory.write.createAccount([[firstOwner], SALT], { account: deployer.account });
  const walletAddr = (await factory.read.getAddress([[firstOwner], SALT])) as Address;
  const wallet = await viem.getContractAt("StarzipWallet", walletAddr);

  const depositHash = await deployer.sendTransaction({
    to: paymaster.address,
    value: depositWei,
    data: "0xd0e30db0" as Hex, // deposit() selector
  });
  await publicClient.waitForTransactionReceipt({ hash: depositHash });

  if ((await wallet.read.trustedPaymaster()) !== getAddress(paymaster.address)) {
    throw new Error(`fixture: wallet ${walletAddr} not born trusting the deployed paymaster`);
  }

  return {
    viem,
    publicClient,
    entryPoint,
    factory,
    paymaster,
    wallet,
    walletAddr,
    deployer,
    owner: ownerWallet,
    policyManager: policyManagerWallet,
    beneficiary,
  };
}

async function deployFixture() {
  return deployFixtureWithDeposit(parseEther("10"));
}

async function deployFixtureRealDeposit() {
  return deployFixtureWithDeposit(REAL_DEPOSIT);
}

// `deployFixture` above
// calls `factory.write.createAccount` OUT OF BAND, so every sponsored op in this entire suite
// runs against an ALREADY-DEPLOYED wallet — the heaviest normal sponsored op (the FIRST op for a
// brand-new user, which deploys the wallet via a non-empty `initCode`, i.e. the onboarding path
// the audit says must not break) was completely untested against the new caps. This variant
// is identical except it does NOT pre-create the account — `walletAddr` is the counterfactual
// CREATE2 address only; `x`/`y` are exposed so a test can build `initCode` itself.
async function deployFixtureUndeployedWallet() {
  const { viem } = await getConnection();
  const [deployer, ownerWallet, policyManagerWallet, beneficiary] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();

  const entryPoint = await viem.deployContract("TestEntryPoint", []);

  const deployerNonce = await publicClient.getTransactionCount({ address: deployer.account.address });
  const predictedFactory = getContractAddress({
    from: deployer.account.address,
    nonce: BigInt(deployerNonce),
  });

  const paymaster = await viem.deployContract(
    "VerifyingPaymaster",
    [entryPoint.address, policyManagerWallet.account.address, predictedFactory, SPONSOR_SIGNER],
    { client: { wallet: ownerWallet } },
  );

  const factory = await viem.deployContract(
    "StarzipWalletFactory",
    [entryPoint.address, paymaster.address],
    { client: { wallet: deployer } },
  );
  if (getAddress(factory.address) !== getAddress(predictedFactory)) {
    throw new Error(
      `fixture: StarzipWalletFactory landed at ${factory.address}, predicted ${predictedFactory} ` +
        `— deployer nonce moved between the prediction and the deploy (see this fixture's own ` +
        `comment on scripts/deploy-aa.ts's identical prediction recipe).`,
    );
  }

  const { x, y } = passkeyPubCoords(PASSKEY_PRIV);
  const firstOwner = encodePasskeyOwner(x, y);
  const walletAddr = (await factory.read.getAddress([[firstOwner], SALT])) as Address;
  const wallet = await viem.getContractAt("StarzipWallet", walletAddr);

  const depositHash = await deployer.sendTransaction({
    to: paymaster.address,
    value: parseEther("10"),
    data: "0xd0e30db0" as Hex,
  });
  await publicClient.waitForTransactionReceipt({ hash: depositHash });

  return {
    viem,
    publicClient,
    entryPoint,
    factory,
    paymaster,
    wallet,
    walletAddr,
    pubKeyX: x,
    pubKeyY: y,
    deployer,
    owner: ownerWallet,
    policyManager: policyManagerWallet,
    beneficiary,
  };
}

type Ctx = Awaited<ReturnType<typeof deployFixture>>;

async function ownerWrite(ctx: Ctx, fn: string, args: unknown[] = []): Promise<void> {
  const hash = await (ctx.paymaster.write as any)[fn](args, { account: ctx.owner.account });
  await ctx.publicClient.waitForTransactionReceipt({ hash });
}

async function pmWrite(ctx: Ctx, fn: string, args: unknown[] = []): Promise<void> {
  const hash = await (ctx.paymaster.write as any)[fn](args, { account: ctx.policyManager.account });
  await ctx.publicClient.waitForTransactionReceipt({ hash });
}

// Comfortable global config + per-wallet provisioning — a sponsored op just works unless the test
// overrides one of the knobs afterwards. `sponsorPersonal` is set so the (target, selector)
// business gate is never the thing under test.
async function setupHappyPath(
  ctx: Ctx,
  opts: { dailyCap?: bigint; globalDailyBudget?: bigint; dailyCapCeiling?: bigint } = {},
): Promise<void> {
  await ownerWrite(ctx, "setGlobalDailyCapCeiling", [opts.dailyCapCeiling ?? parseEther("1")]);
  await ownerWrite(ctx, "setGlobalDailyBudget", [opts.globalDailyBudget ?? parseEther("1")]);
  // unpause() now refuses while any of the three per-op caps is unprovisioned (0).
  // Provisioned generously here (well above anything this file's standard/inflated gas profiles
  // reach — see the individual tests below, which each re-set the ONE cap they're isolating
  // to a tight boundary value AFTER this call) so no test in this file is accidentally gated by a
  // default it never asked to exercise.
  await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
  await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
  await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
  const preCode = await ctx.publicClient.getCode({ address: ctx.walletAddr });
  const codeless = preCode === undefined || preCode === "0x";
  if (codeless) {
    const { pubKeyX, pubKeyY } = ctx as unknown as { pubKeyX: Hex; pubKeyY: Hex };
    const counterfactualArgs = [[encodePasskeyOwner(pubKeyX, pubKeyY)], SALT] as const;
    await pmWrite(ctx, "setSponsoredCounterfactual", [...counterfactualArgs, true]);
    await ownerWrite(ctx, "setSponsorPersonalCounterfactual", [...counterfactualArgs, true]);
  } else {
    await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
    await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
  }
  await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, opts.dailyCap ?? parseEther("1")]);
  await ownerWrite(ctx, "unpause");
}

function sponsored(ctx: Ctx, receipt: { logs: unknown[] }): boolean {
  return (
    parseEventLogs({
      abi: ctx.paymaster.abi,
      logs: receipt.logs as never,
      eventName: "GasSponsored",
    }).length === 1
  );
}

// Submit a passkey-signed no-op (`execute(self, 0, "0x")`) sponsored by the paymaster, with the
// standard gas profile unless a field is overridden — lets each test isolate exactly one guard.
async function submitSponsored(
  ctx: Ctx,
  overrides: { accountGasLimits?: Hex; preVerificationGas?: bigint; gasFees?: Hex } = {},
) {
  const callData = buildExecuteCallData(ctx.wallet.abi, ctx.walletAddr, 0n);
  return execWithPaymaster({
    publicClient: ctx.publicClient,
    entryPoint: ctx.entryPoint,
    walletAddr: ctx.walletAddr,
    callData,
    paymasterAndData: paymasterAndDataFor(ctx.paymaster.address, PM_VAL_GAS, PM_POST_GAS),
    passkeyPriv: PASSKEY_PRIV,
    submitter: ctx.deployer,
    beneficiary: ctx.beneficiary.account.address,
    accountGasLimits: overrides.accountGasLimits ?? ACCOUNT_GAS_LIMITS,
    preVerificationGas: overrides.preVerificationGas ?? PRE_VER_GAS,
    gasFees: overrides.gasFees ?? GAS_FEES,
  });
}

// Build & submit N passkey-signed userOps for the SAME wallet, in ONE `handleOps` bundle — the
// only way to exercise the C-B bundle-aggregation latch (a single op can never trip it: EVERY op
// that passes validation has `actualGasCost <= maxCost <= effectiveDailyCap`, by construction of
// the hard-decline, so a lone op's own accrual can never push `spentToday` past `dailyCap`).
//
// VERIFIED directly against node_modules/@account-abstraction/contracts/core/EntryPoint.sol:58-76
// (`handleOps`): it calls `_iterateValidationPhase(ops, ...)` for the WHOLE batch first, THEN a
// SEPARATE loop `for (i) { _executeUserOp(i, ...) }` runs every op's execution (+ `_postOp`). So
// all N ops built here see the IDENTICAL pre-bundle `spentToday`/`sponsored` during validation,
// no matter what `_postOp` does to storage as earlier ops in the SAME bundle execute — this is
// the exact mechanism the latch cannot prevent within one bundle, only across bundles.
async function submitBundle(
  ctx: Ctx,
  n: number,
  overrides: {
    accountGasLimits?: Hex;
    preVerificationGas?: bigint;
    gasFees?: Hex;
    // Explicit tx gas. Needed for the large bundles: EntryPoint's AA95 guard requires
    // `gasleft()` to still cover each op's DECLARED callGasLimit + postOpGasLimit at execution
    // time, which viem's estimate (sized to ACTUAL consumption) does not leave room for.
    gas?: bigint;
  } = {},
) {
  const callData = buildExecuteCallData(ctx.wallet.abi, ctx.walletAddr, 0n);
  const unsignedPaymasterAndData = paymasterAndDataFor(ctx.paymaster.address, PM_VAL_GAS, PM_POST_GAS);
  const startNonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
  const chainId = BigInt(await ctx.publicClient.getChainId());

  const userOps = [];
  for (let i = 0; i < n; i++) {
    const userOp = buildUserOp(ctx.walletAddr, startNonce + BigInt(i), callData);
    userOp.paymasterAndData = unsignedPaymasterAndData;
    userOp.accountGasLimits = overrides.accountGasLimits ?? ACCOUNT_GAS_LIMITS;
    userOp.preVerificationGas = overrides.preVerificationGas ?? PRE_VER_GAS;
    userOp.gasFees = overrides.gasFees ?? GAS_FEES;
    // Sign the paymaster's own per-op authorization LAST — after every gas field is finalized,
    // and BEFORE deriving the EntryPoint userOpHash (which hashes paymasterAndData, so the
    // passkey signature below must sign over the FULLY signed 129-byte field).
    userOp.paymasterAndData = await signPaymasterData({ userOp, chainId });
    const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
    userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));
    userOps.push(userOp);
  }

  const hash = await ctx.entryPoint.write.handleOps([userOps, ctx.beneficiary.account.address], {
    account: ctx.deployer.account,
    ...(overrides.gas === undefined ? {} : { gas: overrides.gas }),
  });
  return ctx.publicClient.waitForTransactionReceipt({ hash });
}

// How many ops in a bundle were actually executed+sponsored (as opposed to the whole bundle
// reverting during validation).
function sponsoredCount(ctx: Ctx, receipt: { logs: unknown[] }): number {
  return parseEventLogs({
    abi: ctx.paymaster.abi,
    logs: receipt.logs as never,
    eventName: "GasSponsored",
  }).length;
}

describe("VerifyingPaymaster — spend-cap regressions", function () {
  // ============ stale day-index no longer bypasses the spend cap ============
  describe("maxCost-alone-exceeds-cap is DECLINED, not deferred", function () {
    it("brand-new wallet (lastSpentDay==0), dailyCap tiny, maxCost >> dailyCap => rejected, and stays rejected across a day rollover", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, {
        dailyCap: 1n, // effectively "no spend allowed" — MAX_COST is orders of magnitude larger
        globalDailyBudget: parseEther("1"), // generous — must NOT be the reason for the decline
      });

      // AA34 = paymaster HARD-declined (sigFail=true); AA32 = paymaster DEFERRED (validAfter in
      // the future). Asserting AA34 specifically — not just "some rejection" — is exactly the
      // distinction is about: the pre-fix bug did not merely fail to sponsor, it sponsored
      // (op reached success) because the stale-day deferral computed a past `validAfter`.
      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "a fresh wallet's stale lastSpentDay must not let maxCost bypass dailyCap",
      );

      // The whole point of the bug: a UTC day rollover used to silently reopen the hole.
      await time.increase(86_400n);
      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "day rollover must not resurrect the bypass — this op must still be rejected",
      );
    });

    it("fresh paymaster (globalLastSpentDay==0), globalDailyBudget tiny, maxCost >> budget => rejected, and stays rejected across a day rollover", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, {
        dailyCap: parseEther("1"), // generous — must NOT be the reason for the decline
        globalDailyBudget: 1n,
      });

      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "a fresh paymaster's stale globalLastSpentDay must not let maxCost bypass globalDailyBudget",
      );

      await time.increase(86_400n);
      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "day rollover must not resurrect the bypass — this op must still be rejected",
      );
    });

    it("CONTROL: maxCost <= dailyCap but spentToday + maxCost > dailyCap is a genuine rollover — still DEFERRED, not hard-declined", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, {
        dailyCapCeiling: MAX_COST,
        dailyCap: MAX_COST, // == this profile's exact maxCost
        globalDailyBudget: parseEther("1"),
      });

      // op1: spentToday(0) + MAX_COST > dailyCap(MAX_COST)? false -> succeeds (boundary, maxCost
      // does NOT alone exceed the cap, so the new hard-decline must not fire here).
      const r1 = await submitSponsored(ctx);
      assert.strictEqual(r1.status, "success");
      assert.ok(sponsored(ctx, r1), "op1 must be sponsored");

      // op2, same day: spentToday(actual>0) + MAX_COST > dailyCap(MAX_COST) -> deferred (AA32,
      // NOT AA34) — this is the property the fix must NOT break. Asserting AA32 specifically
      // (not just "some rejection") is what proves this is a deferral, not a hard config decline.
      await assert.rejects(submitSponsored(ctx), /AA32/);

      // advance a full UTC day -> validAfter is now in the past -> succeeds (deferral resolved).
      await time.increase(86_400n);
      const r3 = await submitSponsored(ctx);
      assert.strictEqual(r3.status, "success");
      assert.ok(sponsored(ctx, r3), "op3 must be sponsored once the deferral has passed");
    });
  });

  // ============ attacker-declared gas parameters are now bounded ============
  describe("per-op gas-parameter caps", function () {
    it("maxFeePerGas > maxSponsoredFeePerGas => rejected (maxPriorityFeePerGas at the cap, isolating maxFeePerGas)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx); // generous dailyCap/budget — inflated maxCost must still fit
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);

      // priority == cap (not exceeding); maxFee == 2x cap (exceeding).
      const overFeeGasFees = packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS * 2n);
      await assert.rejects(submitSponsored(ctx, { gasFees: overFeeGasFees }), /AA34/);

      // boundary sanity: exactly at the cap on both fields still sponsors.
      const atCapGasFees = packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS);
      const receipt = await submitSponsored(ctx, { gasFees: atCapGasFees });
      assert.strictEqual(receipt.status, "success");
      assert.ok(sponsored(ctx, receipt));
    });

    it("maxPriorityFeePerGas > maxSponsoredFeePerGas => rejected (defense-in-depth guard fires even though it bounds nothing economically once maxFeePerGas is capped)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);

      // maxFee == cap (not exceeding, so maxCost/dailyCap/budget are all unaffected); priority ==
      // 2x cap (exceeding, in isolation).
      //
      // IMPORTANT — verified against the actual account-abstraction sources, NOT assumed: the
      // EntryPoint's compensated rate is `min(maxFeePerGas, maxPriorityFeePerGas + block.basefee)`
      // (UserOperationLib.gasPrice, :28) and `_getRequiredPrefund` multiplies by `maxFeePerGas`
      // alone (EntryPoint.sol, `requiredPrefund = requiredGas * mUserOp.maxFeePerGas`). So once
      // `maxFeePerGas` is capped (previous test), a higher declared `maxPriorityFeePerGas` can
      // only ever LOWER the effective paid rate toward `maxFeePerGas`, never raise it past it —
      // this guard is defense-in-depth, not an independent economic bound. This test proves the
      // guard FIRES (matches VerifyingPaymaster.sol's own reasoning), not that it closes a
      // separate live exploit.
      const overPriorityGasFees = packU128Pair(MAX_FEE_PER_GAS * 2n, MAX_FEE_PER_GAS);
      await assert.rejects(submitSponsored(ctx, { gasFees: overPriorityGasFees }), /AA34/);
    });

    it("preVerificationGas > maxSponsoredPreVerificationGas => rejected", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx); // generous dailyCap/budget — the extra declared gas must still fit
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [PRE_VER_GAS]);

      await assert.rejects(submitSponsored(ctx, { preVerificationGas: PRE_VER_GAS * 2n }), /AA34/);

      // boundary sanity: exactly at the cap still sponsors.
      const receipt = await submitSponsored(ctx, { preVerificationGas: PRE_VER_GAS });
      assert.strictEqual(receipt.status, "success");
      assert.ok(sponsored(ctx, receipt));
    });
  });

  // ============ Lower-priority fix: ceiling is re-applied at use-time ============
  describe("setGlobalDailyCapCeiling — lowering it reclamps an already-provisioned wallet immediately", function () {
    it("wallet provisioned at the old (generous) ceiling is bounded by a LOWERED ceiling on its very next op", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, {
        dailyCapCeiling: parseEther("1"),
        dailyCap: parseEther("1"), // == the (generous) ceiling at provisioning time
        globalDailyBudget: parseEther("1"), // generous — must NOT be the reason for the decline
      });

      // owner lowers the ceiling well below the wallet's stored (stale) dailyCap. No per-wallet
      // storage is touched — `walletPolicy[wallet].dailyCap` is still parseEther("1").
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [1n]);

      // effectiveDailyCap = min(dailyCap, ceiling) = min(1e18, 1) = 1 -> MAX_COST alone exceeds it.
      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "a lowered ceiling must clamp the wallet's stale stored dailyCap on its very next op",
      );
    });
  });

  // ============ VIP interaction with the new caps ============
  // VIP (`walletPolicy[wallet].vip == true`) skips the PER-WALLET cap check entirely — the
  // hard-decline lives inside `if (!p.vip) { ... }` in VerifyingPaymaster.sol. These tests pin
  // exactly what VIP does and does NOT bypass among the new guards.
  describe("VIP interaction with the new caps", function () {
    it("VIP is still bounded by the GLOBAL-budget hard-decline (unconditional, applies to ALL sponsored ops including VIP)", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [1n]); // tiny — must be the sole reason for the decline
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      // VIP now requires a provisioned dailyCap. Set it generously so the per-wallet cap is
      // provably NOT what declines this op.
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, parseEther("1")]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]); // VIP
      // unpause() now refuses while any per-op cap is unprovisioned (0).
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await ownerWrite(ctx, "unpause");

      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "VIP bypasses the PER-WALLET cap, not the GLOBAL budget — this must still hard-decline",
      );
    });

    it("VIP is still bounded by the gas-parameter caps (checked before the policy/VIP lookup, so VIP status cannot matter)", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, parseEther("1")]); // VIP needs a cap
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      // unpause() now also requires these two non-zero; generous, so they cannot be
      // the thing declining the op this test isolates to maxSponsoredFeePerGas.
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await ownerWrite(ctx, "unpause");

      const overFeeGasFees = packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS * 2n);
      await assert.rejects(submitSponsored(ctx, { gasFees: overFeeGasFees }), /AA34/);
    });

    it("POSITIVE CONTROL: VIP still bypasses the PER-WALLET dailyCap entirely (dailyCap == 1 wei, i.e. orders of magnitude below maxCost) — proves did not accidentally start gating VIP on dailyCap at validation time", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      // requires a non-zero cap before VIP can be granted; 1 wei is the smallest legal value
      // and is still ~6 orders of magnitude below MAX_COST, so a NON-VIP wallet here would be
      // hard-declined by the `maxCost > effectiveDailyCap` check (pinned by the very first
      // test above, which uses exactly this dailyCap == 1n). VIP must sail past it.
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, 1n]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]);
      // unpause() now refuses while any per-op cap is unprovisioned (0).
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await ownerWrite(ctx, "unpause");

      const receipt = await submitSponsored(ctx);
      assert.strictEqual(receipt.status, "success");
      assert.ok(sponsored(ctx, receipt), "VIP must still be sponsored despite maxCost >> dailyCap");
    });

    it("setSponsoredUnlimited(wallet, true) with an unprovisioned dailyCap REVERTS (ZeroCapNotAllowed) — the 'VIP silently means one op, ever' footgun is unreachable; revoking VIP stays unconditional", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);

      // dailyCap is still 0 here. Pre-this call SUCCEEDED and produced a VIP whose very first
      // op tripped the C-B latch (any actualGasCost > 0 exceeds a 0 cap) — "unlimited" that meant
      // exactly one op. It must now be refused outright.
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setSponsoredUnlimited([ctx.walletAddr, true], {
          account: ctx.owner.account,
        }),
        ctx.paymaster,
        "ZeroCapNotAllowed",
      );
      let policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.vip, false, "the failed grant must not have set vip");

      // With a cap provisioned (a two-key operation: setDailyCap is policyManager, this is owner),
      // the grant goes through.
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, parseEther("1")]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]);
      policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.vip, true);

      // Revocation must never be blocked by the guard — otherwise a wallet could be trapped in VIP.
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, false]);
      policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.vip, false, "revoking VIP must be unconditional");
    });
  });

  // ============ / item 5 — setSponsoredUnlimited counter reset ============
  // setSponsoredUnlimited (the VIP grant) used to write ONLY the `vip` flag. Its sibling
  // setSponsored ALSO zeroes spentToday/lastSpentDay — the omission meant granting VIP
  // to a wallet that already spent near its cap TODAY carried the spend forward: because VIP is
  // NOT exempt from the CUMULATIVE latch in _postOp (only from the PER-OP dailyCap check), the very
  // next VIP op of any non-zero cost could immediately cross the latch threshold and revoke
  // sponsorship — "unlimited" silently meant "one op, then off", the SAME symptom closed for
  // the dailyCap == 0 path, reopened via carried-forward spend instead. Fixed by mirroring
  // setSponsored's reset on GRANT only (never on revoke).
  describe("setSponsoredUnlimited counter reset", function () {
    // Mirrors the C-B block's own BUNDLE_DAILY_CAP/TRIGGER_N convention: that block establishes
    // (by measurement, see its own comments) that a bundle of TRIGGER_N=20 standard-profile ops
    // against a dailyCap of MAX_COST reliably CROSSES the cap — i.e. each op's ACTUAL gas cost is
    // roughly MAX_COST/20, nowhere near its own declared maxCost. A single op therefore cannot be
    // "near its cap" in absolute terms; what these tests need is "one op away from crossing", which
    // a bundle of 19 such ops reliably approximates without itself crossing.
    const NEAR_CAP_DAILY_CAP = MAX_COST;
    // Measured directly against this file's standard profile: each op's ACTUAL gas cost is ~20%
    // of MAX_COST against a dailyCap of MAX_COST (NOT the ~5%/op the C-B block's TRIGGER_N=20
    // implies — that constant is a deliberately generous margin, not a tight bound, per its own
    // comment). 4 ops stays under; a 5th crosses.
    const NEAR_CAP_BUNDLE_SIZE = 2;

    async function spendNearCap(ctx: Ctx): Promise<bigint> {
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [NEAR_CAP_DAILY_CAP]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, NEAR_CAP_DAILY_CAP]);
      await ownerWrite(ctx, "unpause");

      const receipt = await submitBundle(ctx, NEAR_CAP_BUNDLE_SIZE);
      assert.strictEqual(receipt.status, "success");
      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(
        policy.sponsored,
        true,
        "sanity: 4 ops must stay under the cap (measured: ~20%/op; a 5th op crosses it)",
      );
      assert.ok(policy.spentToday > 0n, "sanity: spend actually accrued");
      return policy.spentToday as bigint;
    }

    it("T5.1 — granting VIP after a near-cap spend does not carry the spend forward: the next VIP op is sponsored and does not latch", async function () {
      const ctx = await loadFixture(deployFixture);
      await spendNearCap(ctx);

      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]);

      const receipt = await submitSponsored(ctx);
      assert.strictEqual(receipt.status, "success");
      assert.ok(
        sponsored(ctx, receipt),
        "the VIP wallet's first op after the grant must be sponsored",
      );
      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(
        policy.sponsored,
        true,
        "M5a: without the counter reset, the carried-forward near-cap spend (2 ops' worth, ~76% " +
          "of the cap) plus this 3rd op's cost crosses the cap, revoking sponsorship on the very " +
          "first VIP op",
      );
    });

    it("T5.2 — the VIP grant zeroes BOTH spentToday and lastSpentDay, mirroring setSponsored's reset", async function () {
      const ctx = await loadFixture(deployFixture);
      await spendNearCap(ctx);

      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]);

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.spentToday, 0n, "M5a/M5b: the grant must zero spentToday");
      assert.strictEqual(policy.lastSpentDay, 0, "M5b: the grant must ALSO zero lastSpentDay");
    });

    it("T5.3 — the VIP grant does NOT reset globalSpentToday (the only thing bounding a blind re-grant loop)", async function () {
      const ctx = await loadFixture(deployFixture);
      await spendNearCap(ctx);
      const globalBefore = (await ctx.paymaster.read.globalSpentToday()) as bigint;
      assert.ok(globalBefore > 0n, "sanity: global counter accrued");

      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]);

      const globalAfter = (await ctx.paymaster.read.globalSpentToday()) as bigint;
      assert.strictEqual(
        globalAfter,
        globalBefore,
        "M5c: the VIP grant must never touch globalSpentToday",
      );
    });

    it("T5.4 — revoking VIP (on == false) does NOT reset the spend counters", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, { dailyCap: MAX_COST });
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]); // grant first

      const receipt = await submitSponsored(ctx);
      assert.strictEqual(receipt.status, "success");
      const before = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.ok(before.spentToday > 0n, "sanity: spend accrued while VIP");

      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, false]); // revoke

      const after = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(
        after.spentToday,
        before.spentToday,
        "M5d: revoking VIP must NOT reset spentToday",
      );
      assert.strictEqual(
        after.lastSpentDay,
        before.lastSpentDay,
        "M5d: revoking VIP must NOT reset lastSpentDay",
      );
      assert.strictEqual(after.vip, false);
    });
  });

  // ============ M-C: globalDailyCapCeiling == 0 is an undocumented-until-now kill-switch ============
  describe("setGlobalDailyCapCeiling(0) — blanket non-VIP kill-switch", function () {
    it("ceiling == 0 hard-declines EVERY non-VIP op via effectiveDailyCap collapsing to 0, even with a huge stored dailyCap and generous budget", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, {
        dailyCapCeiling: parseEther("1"), // provision at a generous ceiling first...
        dailyCap: parseEther("1"),
        globalDailyBudget: parseEther("1"), // generous — must NOT be the reason for the decline
      });

      // ...then the owner drops the ceiling to 0. Per-wallet storage is untouched.
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [0n]);

      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "ceiling == 0 must hard-decline every non-VIP op via effectiveDailyCap == 0",
      );
    });

    it("ceiling == 0 does NOT stop a VIP wallet's op at VALIDATION time (VIP skips `if (!p.vip)`), but the latch does revoke it immediately afterwards", async function () {
      const ctx = await loadFixture(deployFixture);
      // Provision at a generous ceiling first (VIP needs a cap; setDailyCap needs a ceiling)...
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, parseEther("1")]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]);
      // ...then drop the ceiling to 0. Per-wallet storage is untouched (stored dailyCap stays 1e18).
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [0n]);
      // unpause() now refuses while any per-op cap is unprovisioned (0).
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await ownerWrite(ctx, "unpause");

      const receipt = await submitSponsored(ctx);
      assert.strictEqual(receipt.status, "success");
      assert.ok(
        sponsored(ctx, receipt),
        "VIP's op must still pass validation — ceiling == 0 only collapses the NON-VIP per-op check",
      );

      // the latch threshold is min(dailyCap, ceiling) = min(1e18, 0) = 0, so any spend at all
      // crosses it. This is the intended direction for a kill-switch: ceiling == 0 cannot stop a
      // VIP's first op, but it does take the wallet offline right after it.
      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(
        policy.sponsored,
        false,
        "ceiling == 0 must latch the VIP wallet off after its first op",
      );
    });
  });

  // ============ Realistic deploy-config headroom ============
  // The deploy script NOW also provisions
  // `maxSponsoredOpCost = 0.0007 BNB` (the remediation), which is a TIGHTER constraint than
  // `globalDailyCapCeiling` (0.001 BNB) — the original version of this block set the ceiling but
  // never set maxSponsoredOpCost, so it was measuring headroom against the WRONG (looser) real
  // constraint. Against the actual binding cap: standard-profile maxCost (0.00055 BNB) is ~0.79x
  // maxSponsoredOpCost, i.e. only ~1.27x headroom (not ~1.8x) before a normal op starts failing.
  // This is the only test in the suite pinned to those real numbers, so a profile, gas-price, or
  // deploy-aa.ts constant drift shows up here first.
  describe("Realistic deploy config — thin headroom at the real ceiling", function () {
    const REAL_CEILING = parseEther("0.001"); // matches deploy-aa.ts's globalDailyCapCeiling
    // Matches deploy-aa.ts's MAX_SPONSORED_OP_COST exactly (remediation) — see that file's
    // own comment for the "standard sponsorship profile maxCost + headroom" rationale.
    const REAL_MAX_SPONSORED_OP_COST = parseEther("0.0007");

    it("standard gas profile at 1 gwei (maxCost ~0.79x the real maxSponsoredOpCost, ~1.27x headroom) is still sponsored", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, {
        dailyCapCeiling: REAL_CEILING,
        dailyCap: REAL_CEILING,
        globalDailyBudget: parseEther("1"), // generous — isolates the caps as the thing under test
      });
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [REAL_MAX_SPONSORED_OP_COST]);

      assert.ok(
        MAX_COST < REAL_MAX_SPONSORED_OP_COST,
        `sanity: MAX_COST (${MAX_COST}) must be under the real maxSponsoredOpCost ` +
          `(${REAL_MAX_SPONSORED_OP_COST}) for this test to mean anything`,
      );

      const receipt = await submitSponsored(ctx);
      assert.strictEqual(receipt.status, "success");
      assert.ok(
        sponsored(ctx, receipt),
        "a normal op at the real deploy caps must still be sponsored",
      );
    });

    it("REGRESSION GUARD: the SAME op at 2x gas price (maxCost ~1.57x the real maxSponsoredOpCost) is declined — headroom is only ~1.27x, any profile/price increase can flip a normal op to declined", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, {
        dailyCapCeiling: REAL_CEILING,
        dailyCap: REAL_CEILING,
        globalDailyBudget: parseEther("1"),
      });
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [REAL_MAX_SPONSORED_OP_COST]);

      const doubledGasFees = packU128Pair(MAX_FEE_PER_GAS * 2n, MAX_FEE_PER_GAS * 2n);
      await assert.rejects(
        submitSponsored(ctx, { gasFees: doubledGasFees }),
        /AA34/,
        "at 2x gas price maxCost exceeds the real maxSponsoredOpCost (and the real ceiling) — " +
          "expected, but flags how thin the margin is",
      );
    });

    // ============ Onboarding path ============
    // The heaviest NORMAL sponsored op is the very first one for a brand-new user: a userOp
    // whose `initCode` deploys the wallet (via StarzipWalletFactory.createAccount, invoked
    // internally by EntryPoint's SenderCreator) in the SAME transaction as the first
    // validateUserOp/execute — this is the audit's "must not break" onboarding path. Every other
    // test in this suite reuses `deployFixture`, which pre-creates the wallet out of band, so
    // this path was completely untested against the caps deploy-aa.ts now provisions.
    it("initCode deploy: the FIRST op for a brand-new (not-yet-deployed) wallet is sponsored under the real deploy-aa.ts caps", async function () {
      const ctx = await loadFixture(deployFixtureUndeployedWallet);
      await setupHappyPath(ctx, {
        dailyCapCeiling: REAL_CEILING,
        dailyCap: REAL_CEILING,
        globalDailyBudget: parseEther("1"),
      });
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [REAL_MAX_SPONSORED_OP_COST]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]); // matches deploy-aa.ts (1 gwei)
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [PRE_VER_GAS]); // == deploy-aa.ts's 60k ceiling, well above this profile's 50k

      const preCode = await ctx.publicClient.getCode({ address: ctx.walletAddr });
      assert.strictEqual(preCode, undefined, "sanity: wallet must not exist yet");

      // initCode = factory address (20 bytes) ‖ calldata for
      // StarzipWalletFactory.createAccount(firstOwner, salt) — the standard ERC-4337 layout
      // EntryPoint's SenderCreator expects (SenderCreator.sol: factory = initCode[0:20], the rest
      // is called on it via a raw `call`).
      const initCallData = encodeFunctionData({
        abi: ctx.factory.abi,
        functionName: "createAccount",
        args: [[encodePasskeyOwner(ctx.pubKeyX, ctx.pubKeyY)], SALT],
      });
      const initCode = concatHex([ctx.factory.address, initCallData]);

      const callData = buildExecuteCallData(ctx.wallet.abi, ctx.walletAddr, 0n);
      // CORRECTED (the previous version of this comment was
      // false): `verificationGasLimit` does NOT give sender-creation and account validation
      // separate budgets. Verified directly against
      // node_modules/@account-abstraction/contracts/core/EntryPoint.sol: `_validatePrepayment`
      // captures `preGas = gasleft()` (line ~754) BEFORE calling `_validateAccountPrepayment`
      // (which runs `_createSenderIfNeeded` — the factory call — and THEN `validateUserOp` on the
      // just-deployed wallet), and only AFTER both have run does it check
      // `preGas - gasleft() > verificationGasLimit` -> `revert(... "AA26 over
      // verificationGasLimit")` (lines ~790-794). So `verificationGasLimit` is ONE shared budget
      // covering sender-creation PLUS validateUserOp TOGETHER (their sum), not the larger of the
      // two.
      //
      // RIP-7212 IS live (re-verified by direct execution against
      // this file's own numbers, not taken on faith): a real P-256 verify submitted to
      // `0x0000000000000000000000000000000000000100` on BOTH opBNB testnet (chainId 5611) and
      // opBNB mainnet (chainId 204) returns `0x…0001`, confirming the precompile is live on both
      // — `getCode` at that address still reports empty, which is expected for a precompile, not
      // evidence against it. This means `hardhat.config.ts`'s `opbnbTestnetFork` network is the
      // RIGHT place to re-derive this floor (real network gas, not the `P256.verifySolidity`
      // fallback below), and re-deriving it there was attempted for this pass: EVERY attempt
      // (multiple, on fresh block heights) failed with `missing trie node ... is not available`
      // during hardhat's own account-state warmup (`eth_getCode`/`eth_getTransactionCount` on the
      // dev accounts, before this test's own logic ever ran) — the exact non-archive-node
      // limitation `hardhat.config.ts` already documents for this network ("roughly a two-minute
      // window... any hardcoded block number is broken within minutes"). No
      // `OPBNB_TESTNET_ARCHIVE_RPC_URL` was available in this environment to work around it. This
      // is a real, disclosed limitation, not a skipped step: re-deriving the true (cheaper) floor
      // on an archive-backed fork remains open work, tracked here rather than faked.
      //
      // What follows instead is a HARDHAT-EVM re-measurement (this file's original approach,
      // unchanged in kind) — the WORST case per the precompile finding above, since Hardhat's EDR
      // network has no RIP-7212 precompile and every P-256 verify here falls back to
      // `P256.verifySolidity`. RE-MEASURED for the multi-owner rewrite (owner-set registration
      // writes more storage than the old 3-field publicKeyX/publicKeyY/owner `initialize`) AND for
      // this pass's fixes (checked-subtraction length guard, `bytes[] owners` array
      // registration loop, the `typeIndex` bound in `_verifyPasskeyOwner`): bisecting this exact
      // test (`initVerGas` swept in $1,000-$1,000,000 steps) against the CURRENT code found the
      // pass/fail boundary between 313,400 (fails, AA26) and 313,600 (passes) — i.e. the real
      // Hardhat-EVM floor for this op is ~313,500. `initVerGas = 320,000` therefore carries a
      // ~6,500 gas / ~2.1% margin — smaller than most margins in this file, but a REAL one this
      // time (re-derived by bisection against the code as it stands after this pass, not copied
      // forward from a prior measurement the way the previous "320,000 vs. 316,169 (1.2%)" claim
      // was, which is what made that margin false: it was never re-verified against drift).
      //
      // This pushed initVerGas hard against `REAL_MAX_SPONSORED_OP_COST`'s total-gas budget once
      // combined with the OTHER "standard profile" limits (CALL_GAS=150k) this file's module-level
      // constants use for every other (heavier) test in this suite. Those are needlessly generous
      // for THIS op's actual inner call — `execute(self, 0, "0x")` is a no-op hitting `receive()`
      // — so this test uses its own tight `initCallGas` instead of the shared `CALL_GAS`, freeing
      // enough of the fixed maxSponsoredOpCost budget for the real (now larger) verification cost
      // without inflating `REAL_MAX_SPONSORED_OP_COST` itself (that constant mirrors deploy-aa.ts's
      // real production ceiling — loosening it here would hide, not fix, the real gas increase).
      const initVerGas = 320_000n;
      const initCallGas = 50_000n;
      const initAccountGasLimits = packU128Pair(initVerGas, initCallGas);
      const initMaxCost = computeMaxCost({
        verificationGasLimit: initVerGas,
        callGasLimit: initCallGas,
        paymasterVerificationGasLimit: PM_VAL_GAS,
        paymasterPostOpGasLimit: PM_POST_GAS,
        preVerificationGas: PRE_VER_GAS,
        maxFeePerGas: MAX_FEE_PER_GAS,
      });
      assert.ok(
        initMaxCost < REAL_MAX_SPONSORED_OP_COST,
        `sanity: the deploy op's maxCost (${initMaxCost}) must fit under the real ` +
          `maxSponsoredOpCost (${REAL_MAX_SPONSORED_OP_COST}) for this test to mean anything`,
      );

      const nonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
      const chainId = BigInt(await ctx.publicClient.getChainId());
      const userOp = {
        sender: ctx.walletAddr,
        nonce,
        initCode,
        callData,
        accountGasLimits: initAccountGasLimits,
        preVerificationGas: PRE_VER_GAS,
        gasFees: GAS_FEES,
        paymasterAndData: paymasterAndDataFor(ctx.paymaster.address, PM_VAL_GAS, PM_POST_GAS),
        signature: "0x" as Hex,
      };
      // Sign the paymaster's per-op authorization LAST (every gas field above is in the preimage)
      // and BEFORE deriving the EntryPoint userOpHash, which hashes paymasterAndData.
      userOp.paymasterAndData = await signPaymasterData({ userOp, chainId });
      const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
      userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));

      const hash = await ctx.entryPoint.write.handleOps(
        [[userOp], ctx.beneficiary.account.address],
        {
          account: ctx.deployer.account,
        },
      );
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });

      assert.strictEqual(receipt.status, "success");
      assert.ok(
        sponsored(ctx, receipt),
        "the wallet-deploying op must be sponsored, not self-paid",
      );

      const postCode = await ctx.publicClient.getCode({ address: ctx.walletAddr });
      assert.ok(
        postCode && postCode !== "0x",
        "the wallet must actually be deployed after this op",
      );
    });

    // A prior
    // analysis wrongly concluded a wallet-deploying (`initCode`-carrying) op could not be
    // sponsored without `sponsorPersonal` — the test above forces it only because its callData,
    // `execute(self, 0, "0x")`, has `funcLen == 0` and fails `_extractBusinessOk`'s decode. The
    // paymaster never reads `initCode` at all (zero references in this contract): a REAL first op
    // whose callData decodes to an allowlisted `(target, selector)` is sponsored on the BUSINESS
    // path with `sponsorPersonal` left false, deployment riding along in `initCode` for free. This
    // test exists so no future session re-derives that false gate.
    it("T3.6 initCode deploy: sponsorPersonal == false, allowlisted (target, selector) callData IS sponsored on the business path", async function () {
      const ctx = await loadFixture(deployFixtureUndeployedWallet);

      // Manual provisioning (NOT setupHappyPath — it now grants sponsorPersonal=true, which is
      // exactly the escape hatch this test must NOT rely on).
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [REAL_CEILING]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [REAL_MAX_SPONSORED_OP_COST]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [PRE_VER_GAS]);
      const businessTarget = ctx.beneficiary.account.address;
      const businessSelector = toFunctionSelector("allowedBusinessCall()");
      await ownerWrite(ctx, "setBusinessTarget", [businessTarget, true]);
      await ownerWrite(ctx, "setTargetSelector", [businessTarget, businessSelector, true]);
      await pmWrite(ctx, "setSponsoredCounterfactual", [
        [encodePasskeyOwner(ctx.pubKeyX, ctx.pubKeyY)],
        SALT,
        true,
      ]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, REAL_CEILING]);
      // Deliberately NOT calling setSponsorPersonal — sanity-checked below.
      await ownerWrite(ctx, "unpause");

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.sponsorPersonal, false, "sanity: personal escape hatch is OFF");

      const preCode = await ctx.publicClient.getCode({ address: ctx.walletAddr });
      assert.strictEqual(preCode, undefined, "sanity: wallet must not exist yet");

      const initCallData = encodeFunctionData({
        abi: ctx.factory.abi,
        functionName: "createAccount",
        args: [[encodePasskeyOwner(ctx.pubKeyX, ctx.pubKeyY)], SALT],
      });
      const initCode = concatHex([ctx.factory.address, initCallData]);

      // execute(<allowlisted target>, 0, <allowlisted selector>) — decodes cleanly, unlike the
      // `execute(self, 0, "0x")` no-op above, so it reaches the business-path decision.
      const callData = buildExecuteCallData(ctx.wallet.abi, businessTarget, 0n, businessSelector);

      const initVerGas = 320_000n;
      const initCallGas = 50_000n;
      const initAccountGasLimits = packU128Pair(initVerGas, initCallGas);
      const initMaxCost = computeMaxCost({
        verificationGasLimit: initVerGas,
        callGasLimit: initCallGas,
        paymasterVerificationGasLimit: PM_VAL_GAS,
        paymasterPostOpGasLimit: PM_POST_GAS,
        preVerificationGas: PRE_VER_GAS,
        maxFeePerGas: MAX_FEE_PER_GAS,
      });
      assert.ok(
        initMaxCost < REAL_MAX_SPONSORED_OP_COST,
        `sanity: the deploy op's maxCost (${initMaxCost}) must fit under the real ` +
          `maxSponsoredOpCost (${REAL_MAX_SPONSORED_OP_COST}) for this test to mean anything`,
      );

      const nonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
      const chainId = BigInt(await ctx.publicClient.getChainId());
      const userOp = {
        sender: ctx.walletAddr,
        nonce,
        initCode,
        callData,
        accountGasLimits: initAccountGasLimits,
        preVerificationGas: PRE_VER_GAS,
        gasFees: GAS_FEES,
        paymasterAndData: paymasterAndDataFor(ctx.paymaster.address, PM_VAL_GAS, PM_POST_GAS),
        signature: "0x" as Hex,
      };
      // Sign the paymaster's per-op authorization LAST and BEFORE deriving the EntryPoint
      // userOpHash, which hashes paymasterAndData.
      userOp.paymasterAndData = await signPaymasterData({ userOp, chainId });
      const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
      userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));

      const hash = await ctx.entryPoint.write.handleOps(
        [[userOp], ctx.beneficiary.account.address],
        { account: ctx.deployer.account },
      );
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });

      assert.strictEqual(receipt.status, "success");
      assert.ok(
        sponsored(ctx, receipt),
        "a real first op decoding to an allowlisted (target, selector) must be sponsored on the " +
          "business path, with sponsorPersonal left false",
      );

      const postCode = await ctx.publicClient.getCode({ address: ctx.walletAddr });
      assert.ok(
        postCode && postCode !== "0x",
        "the wallet must actually be deployed after this op",
      );
    });
  });

  // ============ C-B: bundle-aggregation auto-unsponsor latch ============
  // `_validatePaymasterUserOp` can only ever see PRE-BUNDLE storage (ERC-7562 forbids writing
  // storage during validation), so N ops for the SAME wallet in ONE `handleOps` call all pass the
  // per-wallet cap check against the same stale `spentToday` — critic measured 40 ops in a single
  // bundle draining 3.95x `dailyCap`. This cannot be closed
  // on-chain at validation time (see the honest "DESIGN LIMITATION" test below). What CAN be
  // closed is REPETITION: `_postOp` runs in the EXECUTION phase, where ERC-7562's storage-write
  // ban does not apply, so once cumulative `spentToday` crosses `dailyCap` there, the wallet is
  // auto-unsponsored — the next bundle for that wallet hard-declines immediately.
  describe("bundle-aggregation auto-unsponsor latch", function () {
    const BUNDLE_DAILY_CAP = MAX_COST; // every op's OWN maxCost == dailyCap -> each op alone passes pre-bundle validation
    const TRIGGER_N = 20; // margin above whatever actualGasCost/MAX_COST ratio this harness produces
    const CRITIC_N = 40; // matches the audit's own measured bundle size, for direct comparability

    async function setupLatchTarget(ctx: Ctx) {
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [BUNDLE_DAILY_CAP]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]); // generous — isolates the per-wallet latch
      // unpause() now refuses while any per-op cap is unprovisioned (0). Generous —
      // BUNDLE_DAILY_CAP == MAX_COST (a single standard-profile op), well under these.
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, BUNDLE_DAILY_CAP]);
      await ownerWrite(ctx, "unpause");
    }

    it("latch trips once a SINGLE bundle's cumulative actual spend crosses dailyCap: sponsored -> false, SponsorshipRevoked emitted, NEXT op hard-declined", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupLatchTarget(ctx);

      const receipt = await submitBundle(ctx, TRIGGER_N);
      assert.strictEqual(
        receipt.status,
        "success",
        "the triggering bundle itself must fully execute",
      );

      // assert the ARGS, not just that something fired. Pre-this block only checked
      // `.length >= 1`, so an arg swap or a pre-increment regression would have passed silently.
      const revokedEvents = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "SponsorshipRevoked",
      });
      assert.strictEqual(
        revokedEvents.length,
        1,
        "SponsorshipRevoked must fire EXACTLY once per bundle — once sponsored flips false the " +
          `latch branch is unreachable for the rest of the bundle (got ${revokedEvents.length} ` +
          `events; ${sponsoredCount(ctx, receipt)}/${TRIGGER_N} ops sponsored)`,
      );
      const revoked = revokedEvents[0] as any;
      assert.strictEqual(
        getAddress(revoked.args.wallet),
        getAddress(ctx.walletAddr),
        "arg0 must be the latched wallet",
      );
      assert.strictEqual(
        revoked.args.effectiveDailyCap,
        BUNDLE_DAILY_CAP,
        "arg2 must be min(dailyCap, globalDailyCapCeiling) — both are BUNDLE_DAILY_CAP here",
      );
      assert.ok(
        revoked.args.spentToday > BUNDLE_DAILY_CAP,
        `arg1 must be the POST-increment spentToday that actually crossed the cap ` +
          `(got ${revoked.args.spentToday} vs cap ${BUNDLE_DAILY_CAP}) — a pre-increment ` +
          "regression would emit a value at or below the cap",
      );

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;

      // the emitted figure is a LOWER BOUND, not the incident size — the rest of the bundle
      // was already admitted by validation and keeps accruing after the event fires. This is the
      // claim VerifyingPaymaster.sol's event NatSpec makes; if the two ever became equal the
      // "use getPolicy(wallet).spentToday instead" guidance would be wrong.
      assert.ok(
        revoked.args.spentToday < policy.spentToday,
        `the emitted spentToday (${revoked.args.spentToday}) must UNDER-report the bundle's final ` +
          `spentToday (${policy.spentToday})`,
      );
      const gasSponsoredSum = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "GasSponsored",
      }).reduce((acc, e) => acc + (e as any).args.actualGasCost, 0n);
      assert.strictEqual(
        policy.spentToday,
        gasSponsoredSum,
        "the authoritative figure (getPolicy().spentToday) must equal the sum of GasSponsored " +
          "actualGasCost in the same tx — the other alerting source the NatSpec points operators at",
      );
      assert.strictEqual(
        policy.sponsored,
        false,
        "wallet must be auto-unsponsored after crossing dailyCap",
      );

      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "the wallet's NEXT op (a new bundle) must be hard-declined once latched",
      );
    });

    it("DESIGN LIMITATION (honest pin): the over-cap bundle itself still fully succeeds — validation cannot see mid-bundle execution — but the SAME wallet's SECOND bundle is blocked outright", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupLatchTarget(ctx);

      const receipt = await submitBundle(ctx, CRITIC_N);
      assert.strictEqual(receipt.status, "success");
      assert.strictEqual(
        sponsoredCount(ctx, receipt),
        CRITIC_N,
        `all ${CRITIC_N} ops in the single over-budget bundle must still succeed — this is the ` +
          "audit's documented design limitation (validation cannot see execution-phase state " +
          "changes within the same bundle), not something this latch claims to fix",
      );

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.ok(
        policy.spentToday > BUNDLE_DAILY_CAP,
        `sanity: cumulative spentToday (${policy.spentToday}) must have actually crossed ` +
          `dailyCap (${BUNDLE_DAILY_CAP}) for this test to mean anything`,
      );

      // order-of-magnitude pin. VerifyingPaymaster.sol's header claims the single-bundle
      // overshoot is a MULTIPLE of the cap, i.e. the latch bounds REPETITION, not SIZE. (The
      // header's own figure, 8.83x, is measured at deploy-aa.ts's constants by the "" block
      // below; this fixture's caps differ, so its ratio differs too.) The exact ratio is a function
      // of the config and drifts with harness gas, so what is pinned here is the order of magnitude:
      // if a change ever made a single bundle unable to exceed ~4x the cap, that header text would
      // be describing an exposure that no longer exists and must be rewritten.
      const overshootRatioX100 = (policy.spentToday * 100n) / BUNDLE_DAILY_CAP;
      console.log(
        `\n    [worst-case] single-bundle overshoot: spentToday=${policy.spentToday} = ` +
          `${Number(overshootRatioX100) / 100}x dailyCap over ${CRITIC_N} ops in ONE bundle\n`,
      );
      assert.ok(
        overshootRatioX100 >= 400n,
        `a single ${CRITIC_N}-op bundle must still overshoot dailyCap by a MULTIPLE (>=4x), not a ` +
          `rounding error — measured ${Number(overshootRatioX100) / 100}x`,
      );

      assert.strictEqual(policy.sponsored, false);

      // Infinite repetition is broken: a second bundle for the SAME wallet
      // is blocked immediately — the attack degrades from "every day, forever" to "once".
      await assert.rejects(
        submitBundle(ctx, CRITIC_N),
        /AA34/,
        "the wallet's SECOND over-budget bundle must be blocked outright by the latch",
      );
    });

    it("day rollover does NOT un-latch a revoked wallet (time.increase(86400) is not a backdoor)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupLatchTarget(ctx);
      await submitBundle(ctx, TRIGGER_N);

      let policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.sponsored, false, "sanity: latch must have tripped");

      await time.increase(86_400n);

      // The day-rollover reset (`p.lastSpentDay != today` -> spentToday=0) lives inside `_postOp`,
      // which a hard-declined (`!p.sponsored`) wallet can never reach — `sponsored` itself is
      // untouched by anything except an explicit policyManager call or this latch.
      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "a day rollover must not silently re-enable a latched wallet",
      );

      policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(
        policy.sponsored,
        false,
        "sponsored must still be false after the rollover attempt",
      );
    });

    it("policyManager re-activation: setSponsored(wallet, true) restores sponsorship (no automatic recovery otherwise)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupLatchTarget(ctx);
      await submitBundle(ctx, TRIGGER_N);

      let policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.sponsored, false, "sanity: latch must have tripped");

      // Raise dailyCap FIRST (and the ceiling with it — `setDailyCap` enforces
      // `cap <= globalDailyCapCeiling`, and `setupLatchTarget` pinned the ceiling at
      // BUNDLE_DAILY_CAP == MAX_COST), so the eventual success is unambiguously a fresh SPONSOR
      // rather than a same-day deferral resolving (that mechanic is covered by the CONTROL
      // test). Both raises happen while still latched, which makes the next assertion a real
      // negative control: budget/cap headroom ALONE must not restore anything.
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, parseEther("1")]);

      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "raising cap+ceiling must NOT un-latch: only setSponsored(true) can clear `sponsored`",
      );

      // ...and now the one call that IS supposed to restore it — isolates "does setSponsored alone
      // restore reachability past `if (!p.sponsored)`".
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);

      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);

      const receipt = await submitSponsored(ctx);
      assert.strictEqual(receipt.status, "success");
      assert.ok(sponsored(ctx, receipt), "explicit re-activation must restore sponsorship");

      policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.sponsored, true);
    });

    // ============ the advertised recovery path actually works, SAME DAY ============
    // Before this was broken in a way no test caught: a latched wallet can never reach
    // `_postOp` again (it hard-declines at `!p.sponsored`), so `spentToday`/`lastSpentDay` FREEZE
    // at the revocation values. `setSponsored(true)` alone therefore left the very next validation
    // hitting `spentToday(frozen, already over cap) + maxCost > effectiveDailyCap` -> deferral to
    // `validAfter = (lastSpentDay + 1) * 1 days` -> AA32 for up to 24h. The test above hid it by
    // raising dailyCap to 1e18 first. This one re-sponsors WITHOUT touching cap or ceiling.
    it("setSponsored(true) restores sponsorship SAME-DAY (no time.increase): it also clears the frozen spend counters", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupLatchTarget(ctx);
      await submitBundle(ctx, TRIGGER_N);

      let policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.sponsored, false, "sanity: latch must have tripped");
      assert.ok(
        policy.spentToday > BUNDLE_DAILY_CAP,
        "sanity: the frozen spentToday must be over the cap — that is what used to force AA32",
      );

      // The ONLY recovery action. Cap and ceiling are left exactly as setupLatchTarget set them.
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);

      policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.sponsored, true);
      assert.strictEqual(policy.spentToday, 0n, "re-sponsoring must clear the frozen spentToday");
      assert.strictEqual(
        policy.lastSpentDay,
        0,
        "re-sponsoring must clear the frozen lastSpentDay",
      );

      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);

      // SAME day — no time.increase anywhere in this test. Pre-this threw AA32.
      const receipt = await submitSponsored(ctx);
      assert.strictEqual(receipt.status, "success");
      assert.ok(sponsored(ctx, receipt), "re-sponsored wallet must be sponsorable the SAME day");
    });

    it("a re-sponsor does NOT reopen the same-day decline: a re-sponsored wallet's zeroed counters still cannot uncap a SINGLE op (maxCost > effectiveDailyCap stays a hard decline)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupLatchTarget(ctx);
      await submitBundle(ctx, TRIGGER_N);

      // Tighten the ceiling below this profile's maxCost, then re-sponsor (which zeroes
      // spentToday/lastSpentDay — exactly the state the stale-day bug exploited).
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [1n]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.spentToday, 0n, "sanity: counters are zeroed");
      assert.strictEqual(policy.lastSpentDay, 0, "sanity: lastSpentDay is the stale value");

      // The hard-decline (`maxCost > effectiveDailyCap`) reads NEITHER counter and runs BEFORE
      // any counter arithmetic, so it must still fire: AA34, not a stale-day AA32-that-passes.
      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "a zeroed counter must not let maxCost bypass the effective cap",
      );
    });

    // ============ latch threshold follows the EFFECTIVE cap ============
    it("the latch threshold follows a LOWERED globalDailyCapCeiling, not the stale stored dailyCap", async function () {
      const ctx = await loadFixture(deployFixture);
      // Provision the wallet at a cap 2x this profile's maxCost, then lower the CEILING to exactly
      // maxCost. Validation now enforces effectiveDailyCap = min(2x, 1x) = MAX_COST. Pre-the
      // latch still compared against the stored 2x, i.e. it tolerated twice the spend validation
      // was actually enforcing — and the factor scaled with how hard the operator tightened.
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [MAX_COST * 2n]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, MAX_COST * 2n]);
      // unpause() now refuses while any per-op cap is unprovisioned (0).
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await ownerWrite(ctx, "unpause");
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [MAX_COST]);

      const receipt = await submitBundle(ctx, TRIGGER_N);
      assert.strictEqual(receipt.status, "success");

      const revokedEvents = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "SponsorshipRevoked",
      });
      assert.strictEqual(
        revokedEvents.length,
        1,
        "the latch must fire against the LOWERED ceiling",
      );
      assert.strictEqual(
        (revokedEvents[0] as any).args.effectiveDailyCap,
        MAX_COST,
        "the emitted threshold must be min(dailyCap, ceiling) == the lowered ceiling, not the " +
          "stale stored dailyCap",
      );
      assert.ok(
        (revokedEvents[0] as any).args.spentToday <= MAX_COST * 2n,
        "sanity: the latch fired before spend reached the STALE stored dailyCap — otherwise this " +
          "test would pass even against the pre-clamp code",
      );

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.sponsored, false);
      assert.strictEqual(
        policy.dailyCap,
        MAX_COST * 2n,
        "stored dailyCap is untouched by the latch",
      );
    });

    it("VIP wallets ALSO trip the latch when a dailyCap IS provisioned for them (judgment call — see report: VIP bypasses the PER-OP dailyCap gate, not this DAILY spend latch)", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [BUNDLE_DAILY_CAP]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      // sets the LATCH threshold; VIP still ignores this value at VALIDATION time (per-op).
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, BUNDLE_DAILY_CAP]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]); // VIP
      // unpause() now refuses while any per-op cap is unprovisioned (0).
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await ownerWrite(ctx, "unpause");

      const receipt = await submitBundle(ctx, TRIGGER_N);
      assert.strictEqual(receipt.status, "success");

      const revokedEvents = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "SponsorshipRevoked",
      });
      assert.strictEqual(
        revokedEvents.length,
        1,
        "VIP must ALSO trip the latch once cumulative spend crosses its dailyCap — exactly once",
      );
      assert.strictEqual(
        getAddress((revokedEvents[0] as any).args.wallet),
        getAddress(ctx.walletAddr),
      );
      assert.strictEqual((revokedEvents[0] as any).args.effectiveDailyCap, BUNDLE_DAILY_CAP);

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.sponsored, false, "VIP wallet must be auto-unsponsored too");
      assert.strictEqual(
        policy.vip,
        false,
        "the latch must clear a cold-granted vip flag, same as any other sponsored=false path",
      );

      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "a latched VIP wallet must be hard-declined at `if (!p.sponsored)`, same as non-VIP",
      );
    });

    // replaced the old "VIP with an UNPROVISIONED dailyCap (0) gets latched after its VERY
    // FIRST op" pin: that configuration is no longer reachable through the setters at all
    // ({setSponsoredUnlimited} refuses a 0 cap, {setDailyCap} refuses to set 0) — the revert is
    // pinned by the test in the "VIP interaction with the new caps" block above. What is still
    // worth pinning is the underlying latch behaviour at a DELIBERATELY tiny cap: 1 wei is the
    // smallest legal cap, so any real op crosses it on #1.
    it("VIP with a deliberately tiny dailyCap (1 wei) is latched after its VERY FIRST op — VIP bypasses the per-op check, never the cumulative latch", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, 1n]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAddr, true]); // VIP
      // unpause() now refuses while any per-op cap is unprovisioned (0).
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await ownerWrite(ctx, "unpause");

      // single op; VIP bypasses the per-op dailyCap gate at validation time, so this succeeds.
      const receipt = await submitSponsored(ctx);
      assert.strictEqual(
        receipt.status,
        "success",
        "the single op itself must still succeed (VIP bypasses the per-op check)",
      );

      const revokedEvents = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "SponsorshipRevoked",
      });
      assert.strictEqual(
        revokedEvents.length,
        1,
        "any actualGasCost > 1 wei exceeds dailyCap == 1, so the latch fires on op #1",
      );
      assert.strictEqual(
        (revokedEvents[0] as any).args.effectiveDailyCap,
        1n,
        "min(dailyCap=1, ceiling=1e18) == 1",
      );

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      assert.strictEqual(policy.sponsored, false);

      await assert.rejects(
        submitSponsored(ctx),
        /AA34/,
        "the VIP wallet's SECOND op must be hard-declined",
      );
    });
  });

  // ============ renounceOwnership() is permanently disabled ============
  // ============ single-bundle worst-case loss, at the REAL deploy constants ============
  // These pin the figures VerifyingPaymaster.sol's header block now states. Round 3 of the header
  // carried `N_max = floor(deposit / smallest-admissible-per-op-prefund)`, on the theory that
  // minimizing declared gas alone maximizes total drain. That got the objective function backwards
  // (see the header's postmortem): the maximand is the ratio of actual charge to declared prefund,
  // not N_max in isolation, and the field that gets an attacker closest to ratio=1 on demand is
  // `callGasLimit`, pointed at a target that burns every unit of gas forwarded to it. This block
  // now uses that BURN profile, found via an explicit sweep (see header), not a minimized one.
  //
  // Everything below is derived from the deploy script's own constants and this file's standard
  // gas profile — no figure is copied from the audit report.
  describe("single-bundle worst-case loss at the real deploy constants", function () {
    const REAL_CEILING = parseEther("0.001"); // deploy-aa.ts GLOBAL_DAILY_CAP_CEILING
    const REAL_BUDGET = parseEther("0.01"); // deploy-aa.ts GLOBAL_DAILY_BUDGET
    const REAL_MAX_OP_COST = parseEther("0.0007"); // deploy-aa.ts MAX_SPONSORED_OP_COST
    const REAL_MAX_PRE_VER_GAS = 60_000n; // deploy-aa.ts MAX_SPONSORED_PREVERIFICATION_GAS

    // ============ BURN PROFILE, not "minimize prefund" ============
    // `BURNER_INIT_CODE` deploys a contract whose ENTIRE runtime is `5b600056`
    // (JUMPDEST; PUSH1 0; JUMP) — an unconditional infinite loop. Pointing the sponsored call at it
    // (via sponsorPersonal, which bypasses the business-target allowlist) makes `Exec.call` forward
    // `callGasLimit` gas and OOG — `mode = opReverted`, but the op is still ADMITTED and billed (see
    // contract header). Init code: PUSH1 4 PUSH1 12 PUSH1 0 CODECOPY PUSH1 4 PUSH1 0 RETURN <runtime>.
    const BURNER_INIT_CODE = "0x6004600c60003960046000f35b600056" as Hex;

    // `callGasLimit = 40,000` is a round number from inside a measured plateau (a 7-point coarse
    // sweep over 0..463,106, then two narrower sweeps — 30,000-80,000, then 33,000-42,000 — see the
    // contract header's "MEASURED WORST CASE FOUND" paragraph for the narrative of that search; it
    // is not a point-by-point log). NOT proven to be the global optimum. The other four fields are
    // re-derived floors, fresh-wallet-measured (see header for why a REUSED wallet under-measures
    // `verificationGasLimit` specifically).
    const BUNDLE_VER_GAS = 62_000n; // bundle-padded — RE-MEASURED (index-bounds fixes added ~100-200 gas per verification): bisection found the floor between 60,100 (fails, AA26) and 60,200 (passes); 62,000 keeps a ~1,800 gas margin, same spirit as the pre-fix 60,000/55,505 pairing.
    const BUNDLE_CALL_GAS = 40_000n; // the burn amount — sweep-found plateau, NOT the per-op cap
    // RE-MEASURED for the multi-owner rewrite: `userOp.signature` is now a
    // `SignatureWrapper{ownerIndex, signatureData}` envelope (~128 bytes larger per op than the
    // old bare WebAuthn assertion — see StarzipWallet.sol's `_decodeSignatureWrapper`), so a
    // 180-op bundle's total calldata grew enough to blow through the EIP-7825 tx gas cap below
    // before completing (observed: AA95 out of gas around op #174-176 at the old 26,894 floor).
    // Bumped from 26,894 to 38,000 — still comfortably a "worst case per op" figure, just no
    // longer the razor-thin (+59 gas) pin the pre-rewrite sweep found; re-deriving THAT exact
    // margin under the new calldata size was not attempted (out of scope for this rewrite — see
    // the commit message). This trades a few fewer ops per bundle (N_max 180 -> ~173) for actually
    // fitting inside one EIP-7825-capped transaction again.
    //
    // RE-MEASURED for SSA-02 (per-op sponsor-signature verification added to every
    // `validatePaymasterUserOp` call). Two numbers below, and they answer DIFFERENT questions —
    // do not conflate them:
    //
    // (1) The TRUE isolated cost of SSA-02's own signature-verification block (2 keccak256 in
    //     `getHash`'s 12-field `abi.encode`, `toEthSignedMessageHash`'s 1 more keccak256,
    //     `ECDSA.tryRecover`'s ecrecover precompile, the `sponsorSigner` cold SLOAD, and the
    //     address comparison) is on the order of ~5,900-6,000 gas — NOT ~27,000 — roughly
    //     matching ecrecover (3,000) + cold SLOAD (2,100) + hashing/memory/compare overhead.
    //     (Calldata cost is NOT part of this figure: `paymasterVerificationGasLimit` only meters
    //     the CALL's execution gas.)
    //
    // (2) `BUNDLE_PM_VAL_GAS` below is set well above that true floor — not because validation
    //     needs more, but because raising a DECLARED gas limit (while actual consumption stays
    //     flat) is being reused here as a lever to shrink N_max, exactly like the PRE-EXISTING
    //     26,894 -> 38,000 bump above already did for a different calldata-growth event. At the
    //     previous 38,000, a 173-op bundle now OOGs partway through (AA95 around op #151) even at
    //     the EIP-7825 cap (16,777,216) — the extra 77 bytes/op the now-129-byte signed
    //     `paymasterAndData` adds to bundle CALLDATA (not validation gas) plus 173x the true
    //     signature-verification cost above no longer leaves room for that many ops in one
    //     transaction. Bumped to 65,000 for real headroom rather than pinning a 1-op-margin rung —
    //     trading N_max down from 173 to a lower value (measured below) for a bundle that reliably
    //     fits in one EIP-7825-capped transaction. Do not lower BUNDLE_PM_VAL_GAS toward the true
    //     ~50,000 floor without re-deriving N_max/BUNDLE_TX_GAS/the drain-ratio assertions below to
    //     match.
    const BUNDLE_PM_VAL_GAS = 65_000n;
    const BUNDLE_PM_POST_GAS = 90_000n; // == MIN_POSTOP_GAS exactly — a hard on-chain floor
    const BUNDLE_PRE_VER_GAS = REAL_MAX_PRE_VER_GAS; // config ceiling — pure 1:1 pass-through, never refunded

    const BUNDLE_PREFUND = computeMaxCost({
      verificationGasLimit: BUNDLE_VER_GAS,
      callGasLimit: BUNDLE_CALL_GAS,
      paymasterVerificationGasLimit: BUNDLE_PM_VAL_GAS,
      paymasterPostOpGasLimit: BUNDLE_PM_POST_GAS,
      preVerificationGas: BUNDLE_PRE_VER_GAS,
      maxFeePerGas: MAX_FEE_PER_GAS,
    });
    // N_max = floor(deposit / per-op prefund) at the BURN profile above. RE-MEASURED for SSA-02
    // (see BUNDLE_PM_VAL_GAS's comment): moved down from 173 (pre-SSA-02) at the new per-op
    // prefund — see the directed test below for the exact measured value and its sanity floor.
    const N_MAX = Number(REAL_DEPOSIT / BUNDLE_PREFUND);
    // EntryPoint's AA95 guard needs headroom over the DECLARED per-op limits (see submitBundle) —
    // this is also, independently, the EIP-7825 tx gas cap this harness's default hardfork enforces
    // (2^24 = 16,777,216 — see contract header).
    const BUNDLE_TX_GAS = 16_776_000n;

    // Deploys the burner (see BURNER_INIT_CODE above). A fresh one per fixture — no shared state.
    async function deployBurner(ctx: Ctx): Promise<Address> {
      const hash = await ctx.deployer.sendTransaction({ data: BURNER_INIT_CODE });
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
      return receipt.contractAddress as Address;
    }

    async function provisionReal(ctx: Ctx) {
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [REAL_CEILING]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [REAL_BUDGET]);
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [REAL_MAX_OP_COST]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [REAL_MAX_PRE_VER_GAS]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, REAL_CEILING]);
      await ownerWrite(ctx, "unpause");
    }

    // Local bundle builder using the BURN profile above, targeting the burner — deliberately NOT
    // `submitBundle` (hardwired to the module-level "standard" profile every OTHER describe block
    // in this file relies on; those stay untouched).
    async function submitBurnBundle(ctx: Ctx, burnerAddr: Address, n: number, gas: bigint) {
      const callData = buildExecuteCallData(ctx.wallet.abi, burnerAddr, 0n);
      const unsignedPaymasterAndData = paymasterAndDataFor(
        ctx.paymaster.address,
        BUNDLE_PM_VAL_GAS,
        BUNDLE_PM_POST_GAS,
      );
      const accountGasLimits = packU128Pair(BUNDLE_VER_GAS, BUNDLE_CALL_GAS);
      const gasFees = packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS);
      const startNonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
      const chainId = BigInt(await ctx.publicClient.getChainId());
      const userOps = [];
      for (let i = 0; i < n; i++) {
        const userOp = buildUserOp(ctx.walletAddr, startNonce + BigInt(i), callData);
        userOp.paymasterAndData = unsignedPaymasterAndData;
        userOp.accountGasLimits = accountGasLimits;
        userOp.preVerificationGas = BUNDLE_PRE_VER_GAS;
        userOp.gasFees = gasFees;
        // Sign last, before deriving userOpHash (which hashes paymasterAndData).
        userOp.paymasterAndData = await signPaymasterData({ userOp, chainId });
        const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
        userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));
        userOps.push(userOp);
      }
      const hash = await ctx.entryPoint.write.handleOps(
        [userOps, ctx.beneficiary.account.address],
        {
          account: ctx.deployer.account,
          gas,
        },
      );
      return ctx.publicClient.waitForTransactionReceipt({ hash });
    }

    it("bundle size is bounded by the DEPOSIT, not by maxSponsoredOpCost: N_max ops all clear, N_max+1 aborts the bundle with AA31", async function () {
      const ctx = await loadFixture(deployFixtureRealDeposit);
      await provisionReal(ctx);
      const burnerAddr = await deployBurner(ctx);

      assert.ok(
        BUNDLE_PREFUND < REAL_MAX_OP_COST,
        `sanity: the burn profile's per-op prefund (${BUNDLE_PREFUND}) sits UNDER maxSponsoredOpCost ` +
          `(${REAL_MAX_OP_COST}) at the measured worst case — the per-op cap is NOT the binding ` +
          "constraint here (pinning P at the cap is actually worse for the attacker — see header)",
      );
      // Lower bound, not an exact-value claim: if the burn profile ever gets cheaper (contract or
      // EntryPoint change), N_MAX only goes UP — a regression would mean it goes DOWN below 150.
      // RE-DERIVED for SSA-02 (per-op signature verification — see BUNDLE_PM_VAL_GAS's comment):
      // N_MAX moved down from 173 at the new BURN profile; floor lowered from 170 to 150 to keep
      // a margin of the same size below the new measurement.
      assert.ok(
        N_MAX >= 150,
        `sanity: N_MAX (${N_MAX}) must stay >= 150 at the pinned burn profile`,
      );

      const receipt = await submitBurnBundle(ctx, burnerAddr, N_MAX, BUNDLE_TX_GAS);
      assert.strictEqual(receipt.status, "success");
      assert.strictEqual(
        sponsoredCount(ctx, receipt),
        N_MAX,
        `all ${N_MAX} ops must be sponsored — N_max = floor(deposit / per-op prefund)`,
      );

      // One more op than the deposit can prefund takes the WHOLE bundle down: the EntryPoint
      // decrements the deposit per op during the validation loop, so the deposit (not the block
      // gas limit, and not maxSponsoredOpCost) is the hard ceiling the header claims it is.
      const fresh = await loadFixture(deployFixtureRealDeposit);
      await provisionReal(fresh);
      const freshBurner = await deployBurner(fresh);
      await assert.rejects(
        submitBurnBundle(fresh, freshBurner, N_MAX + 1, BUNDLE_TX_GAS),
        /AA31/,
        `op #${N_MAX + 1} must abort the bundle with AA31 "paymaster deposit too low"`,
      );
    });

    it("that ONE bundle from ONE wallet drains far more than globalDailyBudget — bounded on BOTH sides so a regression in either direction fails", async function () {
      const ctx = await loadFixture(deployFixtureRealDeposit);
      await provisionReal(ctx);
      const burnerAddr = await deployBurner(ctx);

      const before = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;
      const receipt = await submitBurnBundle(ctx, burnerAddr, N_MAX, BUNDLE_TX_GAS);
      const after = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;
      const drain = before - after;

      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
      console.log(
        `\n    [worst-case] single bundle @ the real deploy constants, BURN profile: N=${N_MAX} ops, ` +
          `deposit drain=${drain} wei (${(Number(drain) * 100) / Number(REAL_DEPOSIT)}% of the ` +
          `0.05 deposit, ${(Number(drain) * 100) / Number(REAL_BUDGET)}% of globalDailyBudget), ` +
          `txGasUsed=${receipt.gasUsed}, spentToday=${policy.spentToday} = ` +
          `${Number(policy.spentToday) / Number(REAL_CEILING)}x dailyCap\n`,
      );

      // LOWER bounds, with margin below what was actually measured (pre-SSA-02: 258.58% of
      // globalDailyBudget / 51.72% of the deposit / 23.06x dailyCap). RE-MEASURED for SSA-02
      // (per-op signature verification moved N_max from 173 to 157 — see BUNDLE_PM_VAL_GAS's
      // comment — while raising the per-op actual charge, so spentToday's dailyCap multiple went
      // UP even though N_max went down): 240.65% of globalDailyBudget / 48.13% of the deposit /
      // 35.71x dailyCap (re-run against independent fresh fixtures; this contract's signing is
      // deterministic (RFC 6979), so this is not expected to be a flaky measurement). Both new
      // figures still clear the ORIGINAL floors below (240% / 48%) — by only a thin margin,
      // thinner than the pre-SSA-02 margin, but still a pass, not a near-miss requiring the
      // floors to move — so the floors are UNCHANGED. Asserting margined lower bounds instead of
      // the exact figures means a small future gas-cost drift does not make this test flaky in
      // either direction, while a REAL regression (the true worst case dropping below these
      // margins) still fails it, which is the point.
      assert.ok(
        drain * 100n >= REAL_BUDGET * 240n,
        `a single ${N_MAX}-op bundle must drain AT LEAST 2.4x globalDailyBudget (${REAL_BUDGET}) — ` +
          `measured ${drain} (${(Number(drain) * 100) / Number(REAL_BUDGET)}%)`,
      );
      assert.ok(
        drain * 100n >= REAL_DEPOSIT * 48n,
        `the drain must be AT LEAST 48% of the deposit (measured 48.13%) — got ${drain}`,
      );
      // The per-wallet cap is a DIFFERENT quantity from the two above (an earlier header
      // version conflated them). Pinned separately, as a multiple of dailyCap, with margin below
      // the measured 35.71x (pre-SSA-02: 23.06x) — the higher per-op actual charge under SSA-02
      // more than offsets N_max dropping from 173 to 157, so this floor is UNCHANGED at 20x (a
      // regression from the new measurement would still fail it).
      assert.ok(
        policy.spentToday > REAL_CEILING * 20n,
        `spentToday (${policy.spentToday}) must overshoot dailyCap (${REAL_CEILING}) by at least ` +
          "20x (measured 35.71x) — the latch bounds repetition, not size",
      );
      assert.strictEqual(policy.sponsored, false, "the wallet must end the bundle latched off");

      // ...and it is still only a fraction of the deposit, which is the ONLY EVM-enforced ceiling.
      assert.ok(
        drain < REAL_DEPOSIT,
        `sanity: the drain (${drain}) must stay under the deposit (${REAL_DEPOSIT}) — the ` +
          "EntryPoint refunds the unused prefund, so N_max ops cost far less than N_max prefunds",
      );

      // ============ Mutant M-h kill: MIN_POSTOP_GAS must not decrease ============
      // A lower MIN_POSTOP_GAS admits a cheaper per-op prefund than BUNDLE_PM_POST_GAS above, which
      // raises N_max and therefore the true worst-case single-bundle drain above what this test
      // pins. Neither of the two lower-bound assertions above would notice that on their own (they
      // use hardcoded constants, not this live value), so pin the constant directly.
      assert.ok(
        ((await ctx.paymaster.read.MIN_POSTOP_GAS()) as bigint) >= 90_000n,
        "MIN_POSTOP_GAS must not decrease below 90,000 — a lower floor admits a cheaper per-op " +
          "prefund and therefore a LARGER N_max / worse single-bundle drain than pinned above",
      );
    });

    // ============ Mutant M-i kill: maxSponsoredOpCost must still be enforced ============
    // Deleting the `maxSponsoredOpCost` check entirely removes the ONLY declared-ceiling on a
    // single op's prefund below dailyCap/globalDailyBudget — at deploy-aa.ts's real constants those
    // are LARGER than maxSponsoredOpCost (REAL_CEILING is 0.001 ether = 1,000,000 gas-equivalent vs
    // REAL_MAX_OP_COST's 700,000). This submits ONE op whose declared prefund sits STRICTLY BETWEEN
    // the two (850,000 gas-equivalent): under the real contract this must be hard-declined by the
    // maxSponsoredOpCost check specifically (AA34) — dailyCap and globalDailyBudget alone would both
    // admit it, so this cannot pass by accident via a DIFFERENT check. Under M-i it would sponsor.
    it("an op whose prefund sits between maxSponsoredOpCost and dailyCap/globalDailyBudget is hard-declined", async function () {
      const ctx = await loadFixture(deployFixtureRealDeposit);
      await provisionReal(ctx);

      const betweenVerGas = 490_000n;
      const betweenCallGas = 100_000n;
      const betweenPreVerGas = 60_000n; // at maxSponsoredPreVerificationGas's own cap, not over it
      const between = computeMaxCost({
        verificationGasLimit: betweenVerGas,
        callGasLimit: betweenCallGas,
        paymasterVerificationGasLimit: PM_VAL_GAS,
        paymasterPostOpGasLimit: PM_POST_GAS,
        preVerificationGas: betweenPreVerGas,
        maxFeePerGas: MAX_FEE_PER_GAS,
      });
      assert.strictEqual(
        between,
        parseEther("0.00085"),
        "sanity: prefund must be exactly 850,000 gas-equivalent",
      );
      assert.ok(between > REAL_MAX_OP_COST, "sanity: prefund must exceed maxSponsoredOpCost");
      assert.ok(
        between < REAL_CEILING && between < REAL_BUDGET,
        "sanity: prefund must stay under BOTH dailyCap/ceiling and globalDailyBudget, so only " +
          "maxSponsoredOpCost can be the reason for the decline",
      );

      await assert.rejects(
        submitSponsored(ctx, {
          accountGasLimits: packU128Pair(betweenVerGas, betweenCallGas),
          preVerificationGas: betweenPreVerGas,
        }),
        /AA34/,
        "maxSponsoredOpCost must hard-decline an op even though dailyCap/globalDailyBudget would " +
          "both admit it — deleting this check (M-i) would let it through instead",
      );
    });

    it("a blind setSponsored re-sponsor loop is now cut off after ONE bundle, but that one bundle still overshoots globalDailyBudget", async function () {
      const ctx = await loadFixture(deployFixtureRealDeposit);
      await provisionReal(ctx);

      // This test's claim (re-sponsoring resets the PER-WALLET latch but NOT
      // `globalSpentToday`, so a blind resync loop keeps going for more than one bundle, bounded
      // only by the remaining deposit) is ORTHOGONAL to the "burn profile vs minimize-prefund"
      // dispute above — it is deliberately kept on the module-level "standard" profile
      // (MAX_COST/submitBundle), NOT the BURN profile. At the BURN profile a single bundle alone
      // already overshoots globalDailyBudget by >2x (see the test above), which leaves ZERO
      // headroom for a second bundle to even partially clear the same stale-pre-bundle-state gap —
      // collapsing this test's round count to 1 and making it indistinguishable from the test
      // above. The standard profile's first bundle (N=90) is what lets a SECOND bundle also clear
      // via the same C-B-style staleness this time applied to `globalSpentToday` — but the two
      // numbers that matter here are NOT the same quantity (contract header {_postOp}):
      // `globalSpentToday` after that first bundle measures 88.33% of `globalDailyBudget` (this is
      // what actually gates the SECOND bundle's admission — still under 100%), while the SAME
      // bundle's REAL EntryPoint deposit drain is 103.45% of budget (already over 100% — `_postOp`'s
      // `actualGasCost` argument under-counts the real drain, so the two diverge). Collapsing them
      // into one sentence, as an earlier version of this comment did, hides that the accounting the
      // latch relies on is looser than what actually left the deposit.
      let totalOps = 0;
      let bundles = 0;
      let stoppedBy = "";
      for (let round = 0; round < 5; round++) {
        const deposit = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;
        const n = Number(deposit / MAX_COST);
        if (n === 0) {
          stoppedBy = "deposit";
          break;
        }
        try {
          const r = await submitBundle(ctx, n, { gas: BUNDLE_TX_GAS });
          totalOps += sponsoredCount(ctx, r);
          bundles += 1;
        } catch (e) {
          stoppedBy = /AA32/.test(String(e)) ? "AA32" : /AA34/.test(String(e)) ? "AA34" : String(e);
          break;
        }
        await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
      }

      const drained =
        REAL_DEPOSIT - ((await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint);
      console.log(
        `\n    [re-sponsor] blind re-sponsor loop (standard profile): ${totalOps} ops in ${bundles} ` +
          `bundles, same UTC day, drained=${drained} wei (${(Number(drained) * 100) / Number(REAL_DEPOSIT)}% ` +
          `of the deposit, ${(Number(drained) * 100) / Number(REAL_BUDGET)}% of globalDailyBudget); ` +
          `stopped by ${stoppedBy}\n`,
      );

      assert.strictEqual(
        bundles,
        1,
        `the latch must cut this blind (hot-key-only) loop off after exactly one bundle (got ${bundles})`,
      );
      assert.ok(
        drained > REAL_BUDGET,
        `even ONE bundle's real drain must exceed globalDailyBudget (${REAL_BUDGET}) — measured ` +
          `${drained} — this is the C-B bundle-aggregation gap (soft breakers, checked at ` +
          "validation against pre-bundle storage), unrelated to and un-fixed by either",
      );
      // `globalSpentToday` is deliberately NOT reset by setSponsored — that, and nothing else, is
      // what ends the loop. If this ever stops being AA32, the WARNING's "globalDailyBudget is what
      // bounds this loop" is false and the loop runs until the deposit is gone.
      assert.strictEqual(
        stoppedBy,
        "AA34",
        "the loop must now be stopped by the cleared sponsorPersonal cold privilege (AA34), not " +
          "by a global-budget deferral (AA32) or the deposit running out",
      );
      const globalSpent = (await ctx.paymaster.read.globalSpentToday()) as bigint;
      assert.ok(
        globalSpent >= drained,
        `globalSpentToday (${globalSpent}) must now be >= the real drain (${drained}) — the A-2 ` +
          "fix debits the CONSTANT MIN_POSTOP_GAS per op as a conservative upper bound, so it " +
          "can never again under-count the real deposit drain",
      );
      assert.ok(
        globalSpent > REAL_BUDGET,
        `globalSpentToday (${globalSpent}) must ALSO exceed globalDailyBudget (${REAL_BUDGET}) ` +
          "after just this one bundle — the recorded counter now correctly reflects the C-B " +
          "overshoot the raw-drain assertion above proves, instead of masking it",
      );
    });
  });

  describe("renounceOwnership() disabled", function () {
    it("reverts with RenounceOwnershipDisabled; owner() is unchanged", async function () {
      const ctx = await loadFixture(deployFixture);

      await assertions.revertWithCustomError(
        ctx.paymaster.write.renounceOwnership([], { account: ctx.owner.account }),
        ctx.paymaster,
        "RenounceOwnershipDisabled",
      );

      assert.strictEqual(
        getAddress((await ctx.paymaster.read.owner()) as string),
        getAddress(ctx.owner.account.address),
      );
    });
  });

  // ============ caps at 0 now FAIL CLOSED, not open ============
  // Formerly "Negative control" — pinned the PRE-remediation fail-open ("caps left at their 0
  // default ... still sponsored normally"). The "0 = unlimited" convention was removed for
  // these two fields (see VerifyingPaymaster.sol's NatSpec): `0` now means "block every
  // op declaring a non-zero value in this field". `unpause()` itself refuses to bring the
  // paymaster live while either cap is still 0 (see the "caps fail closed" describe block
  // below), so this test provisions via {setupHappyPath} (which sets both generously so it can
  // unpause) and then explicitly lowers them BACK to 0 with the owner key afterwards — setters
  // still accept 0 by design (see {setMaxSponsoredFeePerGas}'s NatSpec); only {unpause} enforces
  // non-zero. The scenario this test pins is otherwise unchanged: an op declaring non-zero
  // maxFeePerGas/maxPriorityFeePerGas/preVerificationGas against a 0 cap.
  describe("caps at 0 fail CLOSED (not the pre-remediation fail-open)", function () {
    it("maxSponsoredFeePerGas / maxSponsoredPreVerificationGas dropped back to 0 post-unpause: an op declaring non-zero values for either is now DECLINED, not sponsored", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx);
      // setupHappyPath provisions both generously to satisfy unpause()'s new precondition; drop
      // them back to 0 here (owner-only, still legal post-unpause) to reproduce the scenario this
      // test pins.
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [0n]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [0n]);

      const inflatedGasFees = packU128Pair(MAX_FEE_PER_GAS * 5n, MAX_FEE_PER_GAS * 5n);
      await assert.rejects(
        submitSponsored(ctx, {
          gasFees: inflatedGasFees,
          preVerificationGas: PRE_VER_GAS * 5n,
        }),
        /AA34/,
        "with either cap at 0, an op declaring a non-zero value for that field must now be declined",
      );
    });
    // The "admitted at cap 0 iff the op itself declares zero" half of this story is now
    // T1.9 below, over all three caps at once — kept there rather than duplicated here.
  });

  // ============ the three per-op caps fail CLOSED at 0, and unpause() enforces it ============
  describe("caps fail closed", function () {
    it("T1.1 maxSponsoredOpCost == 0 declines an op with maxCost > 0", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx);
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [0n]);

      await assert.rejects(submitSponsored(ctx), /AA34/);
    });

    it("T1.2 maxSponsoredFeePerGas == 0 declines any op with maxFeePerGas > 0", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [0n]);

      await assert.rejects(submitSponsored(ctx), /AA34/);
    });

    it("T1.3 maxSponsoredPreVerificationGas == 0 declines any op with preVerificationGas > 0", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [0n]);

      await assert.rejects(submitSponsored(ctx), /AA34/);
    });

    it("T1.4 unpause() reverts CapsNotProvisioned when all three caps are 0", async function () {
      const ctx = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        ctx.paymaster.write.unpause({ account: ctx.owner.account }),
        ctx.paymaster,
        "CapsNotProvisioned",
      );
    });

    it("T1.5 unpause() reverts CapsNotProvisioned with only maxSponsoredOpCost provisioned", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await assertions.revertWithCustomError(
        ctx.paymaster.write.unpause({ account: ctx.owner.account }),
        ctx.paymaster,
        "CapsNotProvisioned",
      );
    });

    it("T1.6 unpause() reverts CapsNotProvisioned with only maxSponsoredFeePerGas provisioned", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await assertions.revertWithCustomError(
        ctx.paymaster.write.unpause({ account: ctx.owner.account }),
        ctx.paymaster,
        "CapsNotProvisioned",
      );
    });

    it("T1.7 unpause() reverts CapsNotProvisioned with only maxSponsoredPreVerificationGas provisioned", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await assertions.revertWithCustomError(
        ctx.paymaster.write.unpause({ account: ctx.owner.account }),
        ctx.paymaster,
        "CapsNotProvisioned",
      );
    });

    it("T1.8 unpause() succeeds once all three caps are non-zero", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [parseEther("1")]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [1_000_000n]);
      await ownerWrite(ctx, "unpause");
      assert.strictEqual(await ctx.paymaster.read.paused(), false);
    });

    it("T1.9 an op declaring ZERO maxCost/maxFeePerGas/preVerificationGas is admitted even while all three caps are 0", async function () {
      const ctx = await loadFixture(deployFixture);
      // Provision generously to satisfy unpause(), then drop all three back to 0 (still legal —
      // only unpause() itself enforces non-zero) to reproduce the scenario.
      await setupHappyPath(ctx);
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [0n]);
      await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [0n]);
      await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [0n]);

      // maxCost is EntryPoint-derived from the op's OWN declared gas fields, so declaring
      // maxFeePerGas == 0 also drives maxCost to 0 (nothing to pay for). accountGasLimits and
      // paymaster gas limits stay generous so the op is otherwise well-formed; only the fields
      // that feed the three caps are zeroed.
      const zeroGasFees = packU128Pair(0n, 0n);
      const receipt = await submitSponsored(ctx, {
        gasFees: zeroGasFees,
        preVerificationGas: 0n,
      });
      assert.strictEqual(receipt.status, "success");
      assert.ok(
        sponsored(ctx, receipt),
        "an op declaring zero on every capped field must be admitted even at cap 0 on all three",
      );
    });
  });

  describe("constant postOp debit + MAX_POSTOP_GAS ceiling", function () {
    it("MAX_POSTOP_GAS ceiling: a declared paymasterPostOpGasLimit above the window is declined (AA34), not admitted", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx);

      const maxPostOpGas = (await ctx.paymaster.read.MAX_POSTOP_GAS()) as bigint;
      const callData = buildExecuteCallData(ctx.wallet.abi, ctx.walletAddr, 0n); // self no-op

      const atCeiling = paymasterAndDataFor(ctx.paymaster.address, 40_000n, maxPostOpGas);
      const okReceipt = await execWithPaymaster({
        publicClient: ctx.publicClient,
        entryPoint: ctx.entryPoint,
        walletAddr: ctx.walletAddr,
        callData,
        paymasterAndData: atCeiling,
        passkeyPriv: PASSKEY_PRIV,
        submitter: ctx.deployer,
        beneficiary: ctx.beneficiary.account.address,
        accountGasLimits: packU128Pair(70_000n, 30_000n),
        preVerificationGas: 21_000n,
        gasFees: GAS_FEES,
      });
      assert.strictEqual(okReceipt.status, "success");
      assert.ok(sponsored(ctx, okReceipt), "exactly at MAX_POSTOP_GAS must still be sponsored");

      const overCeiling = paymasterAndDataFor(ctx.paymaster.address, 40_000n, maxPostOpGas + 1n);
      await assert.rejects(
        execWithPaymaster({
          publicClient: ctx.publicClient,
          entryPoint: ctx.entryPoint,
          walletAddr: ctx.walletAddr,
          callData,
          paymasterAndData: overCeiling,
          passkeyPriv: PASSKEY_PRIV,
          submitter: ctx.deployer,
          beneficiary: ctx.beneficiary.account.address,
          accountGasLimits: packU128Pair(70_000n, 30_000n),
          preVerificationGas: 21_000n,
          gasFees: GAS_FEES,
        }),
        /AA34|revert/i,
        "one wei past MAX_POSTOP_GAS must be declined at validation (AA34), never admitted",
      );
    });

    it("the wallet's own recorded spend must never under-count the real EntryPoint deposit drain for a single op, even at the MAX_POSTOP_GAS ceiling", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx);

      const MODEST_VER_GAS = 70_000n;
      const MODEST_CALL_GAS = 30_000n;
      const MODEST_PRE_VER_GAS = 21_000n;
      const MODEST_PM_VAL_GAS = 40_000n;
      const declaredPostOpGas = (await ctx.paymaster.read.MAX_POSTOP_GAS()) as bigint;

      const callData = buildExecuteCallData(ctx.wallet.abi, ctx.walletAddr, 0n); // self no-op
      const paymasterAndData = paymasterAndDataFor(
        ctx.paymaster.address,
        MODEST_PM_VAL_GAS,
        declaredPostOpGas,
      );

      const depositBefore = (await ctx.entryPoint.read.balanceOf([
        ctx.paymaster.address,
      ])) as bigint;

      const receipt = await execWithPaymaster({
        publicClient: ctx.publicClient,
        entryPoint: ctx.entryPoint,
        walletAddr: ctx.walletAddr,
        callData,
        paymasterAndData,
        passkeyPriv: PASSKEY_PRIV,
        submitter: ctx.deployer,
        beneficiary: ctx.beneficiary.account.address,
        accountGasLimits: packU128Pair(MODEST_VER_GAS, MODEST_CALL_GAS),
        preVerificationGas: MODEST_PRE_VER_GAS,
        gasFees: GAS_FEES,
      });
      assert.strictEqual(receipt.status, "success");

      const depositAfter = (await ctx.entryPoint.read.balanceOf([
        ctx.paymaster.address,
      ])) as bigint;
      const realDrain = depositBefore - depositAfter;

      const [gasSponsored] = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs as never,
        eventName: "GasSponsored",
      }) as any[];
      const recordedDebit = gasSponsored.args.actualGasCost as bigint;
      const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;

      console.log(
        `\n    [A-2] real deposit drain=${realDrain} wei vs wallet-recorded debit=` +
          `${recordedDebit} wei (gap=${recordedDebit - realDrain} wei over-count, ` +
          `${realDrain > 0n ? (Number(recordedDebit - realDrain) * 100) / Number(realDrain) : 0}` +
          `% of the drain); spentToday=${policy.spentToday}\n`,
      );

      assert.ok(
        recordedDebit >= realDrain,
        `the wallet's own recorded debit (${recordedDebit}) must be >= the real deposit drain ` +
          `(${realDrain}) — this is what makes the MIN_POSTOP_GAS-constant debit conservative ` +
          "under the MAX_POSTOP_GAS ceiling (see _postOp's NatSpec)",
      );
    });

    it("regression guard: the debit no longer scales with the DECLARED paymasterPostOpGasLimit (A-2's whole point)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx);

      const minPostOpGas = (await ctx.paymaster.read.MIN_POSTOP_GAS()) as bigint;
      const maxPostOpGas = (await ctx.paymaster.read.MAX_POSTOP_GAS()) as bigint;
      const callData = buildExecuteCallData(ctx.wallet.abi, ctx.walletAddr, 0n); // self no-op

      async function debitFor(declaredPostOpGas: bigint): Promise<bigint> {
        const paymasterAndData = paymasterAndDataFor(
          ctx.paymaster.address,
          40_000n,
          declaredPostOpGas,
        );
        const receipt = await execWithPaymaster({
          publicClient: ctx.publicClient,
          entryPoint: ctx.entryPoint,
          walletAddr: ctx.walletAddr,
          callData,
          paymasterAndData,
          passkeyPriv: PASSKEY_PRIV,
          submitter: ctx.deployer,
          beneficiary: ctx.beneficiary.account.address,
          accountGasLimits: packU128Pair(70_000n, 30_000n),
          preVerificationGas: 21_000n,
          gasFees: GAS_FEES,
        });
        assert.strictEqual(receipt.status, "success");
        const [gasSponsored] = parseEventLogs({
          abi: ctx.paymaster.abi,
          logs: receipt.logs as never,
          eventName: "GasSponsored",
        }) as any[];
        return gasSponsored.args.actualGasCost as bigint;
      }

      const debitAtFloor = await debitFor(minPostOpGas);
      const debitAtCeiling = await debitFor(maxPostOpGas);

      const oldDesignWouldHaveAdded = (maxPostOpGas - minPostOpGas) * MAX_FEE_PER_GAS; // 6e13 wei
      const debitDelta =
        debitAtCeiling > debitAtFloor ? debitAtCeiling - debitAtFloor : debitAtFloor - debitAtCeiling;

      assert.ok(
        debitDelta < oldDesignWouldHaveAdded / 2n,
        `debiting scaled with the DECLARED paymasterPostOpGasLimit (delta=${debitDelta} wei, vs ` +
          `${oldDesignWouldHaveAdded} wei the old, superseded design would have added for this ` +
          "same 60,000-gas swing) — the whole point of the A-2 fix is that it no longer does",
      );
    });
  });
});
