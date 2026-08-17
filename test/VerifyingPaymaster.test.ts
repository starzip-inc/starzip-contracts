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
  toFunctionSelector,
  encodeFunctionData,
  type Address,
  type Hex,
  type Abi,
} from "viem";
import { loadFixture, getConnection, time, assertions } from "./helpers.js";
import {
  passkeyPubCoords,
  packU128Pair,
  buildExecuteCallData,
  buildExecuteBatchCallData,
  paymasterAndDataFor,
  craftedBatchCallData,
  craftedSelectorCallData,
  execWithPaymaster,
  computeMaxCost,
  encodePasskeyOwner,
  encodeAddressOwner,
} from "./aa-helpers.js";

// Deterministic P-256 test keys (NOT for production). Scalars < n. Reused from StarzipWallet.test.ts.
const PASSKEY_PRIV_A = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const PASSKEY_PRIV_B = hexToBytes(
  "0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464" as Hex,
);

const SALT_A = 501n;
const SALT_B = 502n;

// Real TradeSettlementV1 selectors, used to reproduce the abuse scenario: `cancelOrder` is an
// unbounded cold-SSTORE primitive that used to be sponsored for free purely because the settlement
// contract was target-allowlisted. Declared as literal signatures so this test does not depend on
// TradeSettlementV1's ABI (which is being reshaped independently).
// NOTE: what this pair models is "an allowed function vs. cancelOrder on the same target", not
// the deploy policy. `settleOrders` is in fact NOT sponsored on any network (it is operator-only
// and the operator funds its own gas — see the deploy config); it is used here
// only because it is a real, recognisable settlement selector. Kept byte-accurate to the shipped
// ABI so it cannot quietly become a signature that does not exist.
// The nine parameters now travel inside one `Settlement` struct, so the whole list is wrapped in
// an extra tuple — that outer pair of parens is the batch refactor, not a typo.
const SETTLE_SELECTOR = toFunctionSelector(
  "settleOrders(((address,address,address,bool,uint256,uint256,uint256,uint256,uint256),bytes," +
    "(address,address,address,bool,uint256,uint256,uint256,uint256,uint256),bytes," +
    "uint256,uint256,uint256,uint256,bytes32))",
);
const CANCEL_ORDER_SELECTOR = toFunctionSelector(
  "cancelOrder((address,address,address,bool,uint256,uint256,uint256,uint256,uint256))",
);
// Generic stand-ins for "some allowed function" / "some other function on the same target".
const SEL_ALLOWED = toFunctionSelector("allowedBusinessCall()");
const SEL_OTHER = toFunctionSelector("someOtherCall()");

// Standard userOp gas profile for paymaster tests: modest, fixed values so EntryPoint's
// deterministic maxCost = (verificationGasLimit + callGasLimit + paymasterVerificationGasLimit +
// paymasterPostOpGasLimit + preVerificationGas) * maxFeePerGas (EntryPoint._getRequiredPrefund)
// can be pinned EXACTLY — cap/budget boundary tests rely on this instead of guessed margins.
const VER_GAS = 150_000n;
const CALL_GAS = 150_000n;
const PRE_VER_GAS = 50_000n;
const PM_VAL_GAS = 100_000n;
const PM_POST_GAS = 100_000n; // > MIN_POSTOP_GAS (90_000, see VerifyingPaymaster.sol MIN_POSTOP_GAS derivation)
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
  const firstOwnerA = encodePasskeyOwner(PK_X_A, PK_Y_A);
  const firstOwnerB = encodePasskeyOwner(PK_X_B, PK_Y_B);

  await factory.write.createAccount([[firstOwnerA], SALT_A], {
    account: deployer.account,
  });
  const walletAAddr = (await factory.read.getAddress([[firstOwnerA], SALT_A])) as Address;
  const walletA = await viem.getContractAt("StarzipWallet", walletAAddr);

  await factory.write.createAccount([[firstOwnerB], SALT_B], {
    account: deployer.account,
  });
  const walletBAddr = (await factory.read.getAddress([[firstOwnerB], SALT_B])) as Address;
  const walletB = await viem.getContractAt("StarzipWallet", walletBAddr);

  // Deploy as `ownerWallet` so Ownable2Step's owner() != policyManager (distinct hot/cold roles).
  const paymaster = await viem.deployContract(
    "VerifyingPaymaster",
    [entryPoint.address, policyManagerWallet.account.address],
    { client: { wallet: ownerWallet } },
  );

  // unpause() now refuses while any of the three per-op caps is unprovisioned (0).
  // Provisioned once here, generously, so every test in this file that calls `unpause()` (via
  // this fixture) inherits non-zero caps without having to know about them; tests that isolate
  // maxSponsoredOpCost specifically (below) override it afterwards. This file never inflates
  // maxFeePerGas/preVerificationGas past the standard profile, so those two defaults are never
  // the thing under test.
  let hash = await paymaster.write.setMaxSponsoredOpCost([parseEther("1")], {
    account: ownerWallet.account,
  });
  await publicClient.waitForTransactionReceipt({ hash });
  hash = await paymaster.write.setMaxSponsoredFeePerGas([MAX_FEE_PER_GAS], {
    account: ownerWallet.account,
  });
  await publicClient.waitForTransactionReceipt({ hash });
  hash = await paymaster.write.setMaxSponsoredPreVerificationGas([1_000_000n], {
    account: ownerWallet.account,
  });
  await publicClient.waitForTransactionReceipt({ hash });

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
  if (opts.sponsorPersonal) await ownerWrite(ctx, "setSponsorPersonal", [wallet, true]);
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
  // ============ Roles / deploy / pause (M4) ============
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
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
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
        ctx.paymaster.write.setSponsoredBatch([[ctx.walletAAddr], true], {
          account: ctx.stranger.account,
        }),
        ctx.paymaster,
        "NotPolicyManager",
      );
    });

    // ============ — setSponsorPersonal: cold to GRANT, hot to REVOKE ============
    // Before this fix the whole function was onlyPolicyManager (hot), so the hot key alone could
    // void BOTH cold-key allowlists (businessAllowlist, targetSelectorAllowlist) for any wallet —
    // see the function's NatSpec in VerifyingPaymaster.sol. Mirrors setSponsoredUnlimited's
    // asymmetry and pause()'s shape: a kill direction (revoke) must never require the slow key.
    describe("setSponsorPersonal cold-grant / hot-revoke asymmetry", function () {
      it("T3.1 policyManager CANNOT grant (on == true)", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setSponsorPersonal([ctx.walletAAddr, true], {
            account: ctx.policyManager.account,
          }),
          ctx.paymaster,
          "OwnableUnauthorizedAccount",
        );
      });

      it("T3.2 owner CAN grant (on == true)", async function () {
        const ctx = await loadFixture(deployFixture);
        await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
        const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAAddr])) as any;
        assert.strictEqual(policy.sponsorPersonal, true);
      });

      it("T3.3 policyManager CAN revoke (on == false)", async function () {
        const ctx = await loadFixture(deployFixture);
        await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
        await pmWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, false]);
        const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAAddr])) as any;
        assert.strictEqual(policy.sponsorPersonal, false);
      });

      it("T3.4 owner CAN revoke (on == false)", async function () {
        const ctx = await loadFixture(deployFixture);
        await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
        await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, false]);
        const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAAddr])) as any;
        assert.strictEqual(policy.sponsorPersonal, false);
      });

      it("T3.5 a stranger can do neither", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setSponsorPersonal([ctx.walletAAddr, true], {
            account: ctx.stranger.account,
          }),
          ctx.paymaster,
          "OwnableUnauthorizedAccount",
        );
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setSponsorPersonal([ctx.walletAAddr, false], {
            account: ctx.stranger.account,
          }),
          ctx.paymaster,
          "NotOwnerOrPolicyManager",
        );
      });

      // T3.6 (an initCode op sponsored on the business path with sponsorPersonal == false) lives
      // in VerifyingPaymaster.spendcap.test.ts, next to the existing initCode-deploy fixture
      // (deployFixtureUndeployedWallet) that this file does not have.
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
      await assertions.revert(
        ctx.paymaster.write.setTargetSelector([ctx.stranger.account.address, SEL_ALLOWED, true], {
          account: ctx.stranger.account,
        }),
      );
      await assertions.revert(
        ctx.paymaster.write.setTargetSelectors(
          [ctx.stranger.account.address, [SEL_ALLOWED], true],
          { account: ctx.stranger.account },
        ),
      );
      // the hot policyManager key must NOT reach the selector allowlist either
      await assertions.revert(
        ctx.paymaster.write.setTargetSelector([ctx.stranger.account.address, SEL_ALLOWED, true], {
          account: ctx.policyManager.account,
        }),
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
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
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
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
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

  // ============ Per-op maxCost cap (mitigation) ============
  describe("Per-op maxCost cap (mitigation)", function () {
    it("maxSponsoredOpCost==0 (fails CLOSED, not the pre-remediation 'disabled, no per-op limit'): an op with maxCost > 0 is declined", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, {
        sponsorPersonal: true,
        dailyCap: parseEther("1"),
      });
      // deployFixture provisions maxSponsoredOpCost generously so unpause() succeeds; drop it
      // back to 0 here (owner-only, still legal post-unpause — only unpause() itself enforces
      // non-zero) to reproduce the scenario this test pins.
      await ownerWrite(ctx, "setMaxSponsoredOpCost", [0n]);
      assert.strictEqual((await ctx.paymaster.read.maxSponsoredOpCost()) as bigint, 0n);

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
        /AA34/,
        "maxSponsoredOpCost==0 must now decline any op with maxCost > 0",
      );
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

  // ============ Sponsorship decision + defensive decode (m1) ============
  describe("Sponsorship decision + defensive decode (m1)", function () {
    it("ON/OFF: sponsored=false declines; sponsored=true proceeds", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
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
      await ownerWrite(ctx, "setTargetSelector", [businessTarget, SEL_ALLOWED, true]);

      const okCallData = buildExecuteCallData(ctx.walletA.abi, businessTarget, 0n, SEL_ALLOWED);
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: okCallData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));

      // Same (allowlisted) selector, but a target that is NOT in businessAllowlist.
      const notAllowed = ctx.beneficiary.account.address;
      await ownerWrite(ctx, "setTargetSelector", [notAllowed, SEL_ALLOWED, true]);
      const badCallData = buildExecuteCallData(ctx.walletA.abi, notAllowed, 0n, SEL_ALLOWED);
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
      await ownerWrite(ctx, "setTargetSelector", [t1, SEL_ALLOWED, true]);
      await ownerWrite(ctx, "setTargetSelector", [t2, SEL_ALLOWED, true]);

      const allInCallData = buildExecuteBatchCallData(
        ctx.walletA.abi,
        [t1, t2],
        [0n, 0n],
        [SEL_ALLOWED, SEL_ALLOWED],
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
        [SEL_ALLOWED, SEL_ALLOWED],
      );
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: mixedCallData,
        }),
      );

      // sponsorPersonal=true skips the allowlist check entirely -> same mixed batch now sponsored
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      const r3 = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: mixedCallData,
      });
      assert.ok(opSucceeded(r3, ctx.entryPoint.abi));
    });

    it("crafted calldata declines cleanly (AA34), never hard-reverts (AA33) (m1)", async function () {
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

  // ============ (target, selector) sponsorship policy ============
  describe("(target, selector) sponsorship policy", function () {
    // Assert the op is refused WITHOUT a hard AA33 (validation-phase revert). A hard revert would
    // mean the bundler drops the userOp instead of the paymaster simply declining to sponsor it.
    async function assertSoftDeclined(p: Promise<unknown>, label: string): Promise<void> {
      await assert.rejects(p, (error: unknown) => {
        const msg = String(error);
        assert.ok(!msg.includes("AA33"), `must not hard-revert (AA33) for ${label}: ${msg}`);
        return true;
      });
    }

    it("setTargetSelector: rejects zero target, flips state, emits TargetSelectorUpdated", async function () {
      const ctx = await loadFixture(deployFixture);
      const target = ctx.stranger.account.address;

      await assertions.revertWithCustomError(
        ctx.paymaster.write.setTargetSelector([zeroAddress, SEL_ALLOWED, true], {
          account: ctx.owner.account,
        }),
        ctx.paymaster,
        "ZeroAddress",
      );

      assert.strictEqual(
        await ctx.paymaster.read.targetSelectorAllowlist([target, SEL_ALLOWED]),
        false,
      );

      const hash = await ctx.paymaster.write.setTargetSelector([target, SEL_ALLOWED, true], {
        account: ctx.owner.account,
      });
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
      const ev = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "TargetSelectorUpdated",
      })[0] as any;
      assert.strictEqual(getAddress(ev.args.target), getAddress(target));
      assert.strictEqual(ev.args.selector, SEL_ALLOWED);
      assert.strictEqual(ev.args.allowed, true);
      assert.strictEqual(
        await ctx.paymaster.read.targetSelectorAllowlist([target, SEL_ALLOWED]),
        true,
      );
    });

    it("setTargetSelectors: batch sets each pair, emits per-entry + batch events", async function () {
      const ctx = await loadFixture(deployFixture);
      const target = ctx.stranger.account.address;

      const hash = await ctx.paymaster.write.setTargetSelectors(
        [target, [SETTLE_SELECTOR, SEL_ALLOWED], true],
        { account: ctx.owner.account },
      );
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });

      const perEntry = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "TargetSelectorUpdated",
      });
      assert.strictEqual(perEntry.length, 2, "one TargetSelectorUpdated per entry");

      const batchEv = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "TargetSelectorsBatchUpdated",
      })[0] as any;
      assert.strictEqual(batchEv.args.count, 2n);
      assert.strictEqual(batchEv.args.allowed, true);

      assert.strictEqual(
        await ctx.paymaster.read.targetSelectorAllowlist([target, SETTLE_SELECTOR]),
        true,
      );
      assert.strictEqual(
        await ctx.paymaster.read.targetSelectorAllowlist([target, SEL_ALLOWED]),
        true,
      );
      // an unlisted selector on the same target stays false
      assert.strictEqual(
        await ctx.paymaster.read.targetSelectorAllowlist([target, CANCEL_ORDER_SELECTOR]),
        false,
      );
    });

    it("allowlisted (target, selector) is sponsored; a DIFFERENT selector on the SAME target soft-declines (AA34)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") }); // business path
      const target = ctx.stranger.account.address;
      await ownerWrite(ctx, "setBusinessTarget", [target, true]);
      await ownerWrite(ctx, "setTargetSelector", [target, SEL_ALLOWED, true]);

      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: buildExecuteCallData(ctx.walletA.abi, target, 0n, SEL_ALLOWED),
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));

      // same allowlisted target, selector never listed => declined, and NOT via AA33
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: buildExecuteCallData(ctx.walletA.abi, target, 0n, SEL_OTHER),
        }),
        "unlisted selector on an allowlisted target",
      );
    });

    it("abuse: settlement target allowlisted, settleOrders sponsored, cancelOrder is NOT", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });

      // Stand-in for the TradeSettlementV1 proxy: a contract with no matching function, so the
      // inner call reverts either way — what is under test is the paymaster's SPONSORSHIP decision.
      const settlement = ctx.factory.address;
      await ownerWrite(ctx, "setBusinessTarget", [settlement, true]);
      await ownerWrite(ctx, "setTargetSelectors", [settlement, [SETTLE_SELECTOR], true]);

      // settleOrders: sponsored — the paymaster pays even though the inner call reverts.
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: buildExecuteCallData(ctx.walletA.abi, settlement, 0n, SETTLE_SELECTOR),
      });
      const sponsored = parseEventLogs({
        abi: ctx.paymaster.abi,
        logs: receipt.logs,
        eventName: "GasSponsored",
      });
      assert.strictEqual(sponsored.length, 1, "settleOrders must still be sponsored");

      // cancelOrder (unbounded cold-SSTORE primitive): target is allowlisted, selector is not.
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: buildExecuteCallData(ctx.walletA.abi, settlement, 0n, CANCEL_ORDER_SELECTOR),
        }),
        "cancelOrder on an allowlisted settlement target",
      );

      // and de-listing settleOrders closes it too (no residual target-only sponsorship)
      await ownerWrite(ctx, "setTargetSelectors", [settlement, [SETTLE_SELECTOR], false]);
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: buildExecuteCallData(ctx.walletA.abi, settlement, 0n, SETTLE_SELECTOR),
        }),
        "de-listed settleOrders",
      );
    });

    it("executeBatch: all pairs allowed sponsored; one unlisted SELECTOR declines the whole batch", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });

      const t1 = ctx.stranger.account.address;
      const t2 = ctx.beneficiary.account.address;
      await ownerWrite(ctx, "setBusinessTargets", [[t1, t2], true]);
      await ownerWrite(ctx, "setTargetSelector", [t1, SEL_ALLOWED, true]);
      await ownerWrite(ctx, "setTargetSelector", [t2, SEL_ALLOWED, true]);

      const okBatch = buildExecuteBatchCallData(
        ctx.walletA.abi,
        [t1, t2],
        [0n, 0n],
        [SEL_ALLOWED, SEL_ALLOWED],
      );
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: okBatch,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));

      // both targets still allowlisted; only the SECOND element's selector is unlisted
      const mixedBatch = buildExecuteBatchCallData(
        ctx.walletA.abi,
        [t1, t2],
        [0n, 0n],
        [SEL_ALLOWED, SEL_OTHER],
      );
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: mixedBatch,
        }),
        "batch with one unlisted selector",
      );

      // ...and the first element too (all-must-pass is order-independent)
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: buildExecuteBatchCallData(
            ctx.walletA.abi,
            [t1, t2],
            [0n, 0n],
            [SEL_OTHER, SEL_ALLOWED],
          ),
        }),
        "batch whose first element selector is unlisted",
      );
    });

    it("executeBatch with dest.length != funcs.length declines cleanly", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });

      const t1 = ctx.stranger.account.address;
      const t2 = ctx.beneficiary.account.address;
      await ownerWrite(ctx, "setBusinessTargets", [[t1, t2], true]);
      await ownerWrite(ctx, "setTargetSelector", [t1, SEL_ALLOWED, true]);
      await ownerWrite(ctx, "setTargetSelector", [t2, SEL_ALLOWED, true]);

      // 2 dests / 2 values but only 1 func — the paymaster cannot pair them, so it must decline.
      const mismatched = buildExecuteBatchCallData(
        ctx.walletA.abi,
        [t1, t2],
        [0n, 0n],
        [SEL_ALLOWED],
      );
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: mismatched,
        }),
        "dest/funcs length mismatch",
      );
    });

    it("crafted selector-path calldata declines cleanly (AA34), never hard-reverts (AA33)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });

      // Target AND every selector it could plausibly carry are allowlisted, so any decline can
      // only come from the defensive decode itself, not from the policy lookup.
      const target = ctx.stranger.account.address;
      await ownerWrite(ctx, "setBusinessTarget", [target, true]);
      await ownerWrite(ctx, "setTargetSelectors", [
        target,
        ["0x00000000", SEL_ALLOWED, SEL_OTHER, SETTLE_SELECTOR],
        true,
      ]);

      const variants = [
        "shortHead",
        "funcOffsetOutOfRange",
        "emptyFunc",
        "shortFunc",
        "truncatedFunc",
        "batchFuncOffsetOutOfRange",
      ] as const;
      for (const variant of variants) {
        await assertSoftDeclined(
          submitSponsored(ctx, {
            walletAddr: ctx.walletAAddr,
            passkeyPriv: PASSKEY_PRIV_A,
            callData: craftedSelectorCallData(variant, target),
          }),
          `variant "${variant}"`,
        );
      }
    });

    it("sponsorPersonal=true bypasses the selector policy (documented escape hatch)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, {
        sponsorPersonal: true,
        dailyCap: parseEther("1"),
      });

      // neither the target nor the selector is allowlisted
      const target = ctx.stranger.account.address;
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData: buildExecuteCallData(ctx.walletA.abi, target, 0n, CANCEL_ORDER_SELECTOR),
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
    });
  });

  // ============ selfSelectorAllowlist — item 4 (lost-passkey rotation, add-only) ============
  // Wallet-administration calls arrive as execute(sender, 0, <selector, args>) — the wallet
  // calling ITSELF (StarzipWallet's onlySelf). businessAllowlist/targetSelectorAllowlist can
  // never sponsor this (a wallet's own address is per-user and cannot be meaningfully
  // allowlisted as a "business target"), so this is a SEPARATE, REPLACEMENT allowlist consulted
  // only when target == sender — see VerifyingPaymaster.sol's header "SELF-CALL GATE IS A
  // SEPARATE, REPLACEMENT ALLOWLIST" note. Rev-1 -> rev-2 fix: the per-element `target == sender`
  // check MUST live INSIDE the executeBatch decode loop, never hoisted — T4.3/T4.4 below are the
  // corrected shape that actually kills a hoist (see the plan's §2.4).
  describe("selfSelectorAllowlist — item 4 (lost-passkey rotation, add-only)", function () {
    const ADD_OWNER_ADDRESS_SEL = toFunctionSelector("addOwnerAddress(address)");
    const ADD_OWNER_PUBKEY_SEL = toFunctionSelector("addOwnerPublicKey(bytes32,bytes32)");
    const REQUEST_UPGRADE_SEL = toFunctionSelector("requestUpgrade(address)");
    const CANCEL_UPGRADE_SEL = toFunctionSelector("cancelUpgrade()");
    const UPGRADE_TO_AND_CALL_SEL = toFunctionSelector("upgradeToAndCall(address,bytes)");

    function addOwnerAddressCallData(walletAbi: Abi, newOwner: Address): Hex {
      return encodeFunctionData({
        abi: walletAbi,
        functionName: "addOwnerAddress",
        args: [newOwner],
      });
    }
    function addOwnerPublicKeyCallData(walletAbi: Abi, x: Hex, y: Hex): Hex {
      return encodeFunctionData({
        abi: walletAbi,
        functionName: "addOwnerPublicKey",
        args: [x, y],
      });
    }

    async function assertSoftDeclined(p: Promise<unknown>, label: string): Promise<void> {
      await assert.rejects(p, (error: unknown) => {
        const msg = String(error);
        assert.ok(!msg.includes("AA33"), `must not hard-revert (AA33) for ${label}: ${msg}`);
        return true;
      });
    }

    it("T4.1 execute(self, 0, addOwnerAddress(x)) is sponsored, and the owner is actually added", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") }); // sponsorPersonal=false
      await ownerWrite(ctx, "setSelfSelector", [ADD_OWNER_ADDRESS_SEL, true]);

      const newOwner = ctx.stranger.account.address;
      assert.strictEqual(
        await ctx.walletA.read.isOwnerBytes([encodeAddressOwner(newOwner)]),
        false,
      );

      const callData = buildExecuteCallData(
        ctx.walletA.abi,
        ctx.walletAAddr,
        0n,
        addOwnerAddressCallData(ctx.walletA.abi, newOwner),
      );
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
      assert.strictEqual(
        await ctx.walletA.read.isOwnerBytes([encodeAddressOwner(newOwner)]),
        true,
        "addOwnerAddress must have actually executed, not just been sponsored",
      );
    });

    it("T4.2 execute(self, 0, addOwnerPublicKey(x,y)) is sponsored the same way", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });
      await ownerWrite(ctx, "setSelfSelector", [ADD_OWNER_PUBKEY_SEL, true]);

      const { x, y } = passkeyPubCoords(PASSKEY_PRIV_B);
      const callData = buildExecuteCallData(
        ctx.walletA.abi,
        ctx.walletAAddr,
        0n,
        addOwnerPublicKeyCallData(ctx.walletA.abi, x, y),
      );
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));
      assert.strictEqual(
        await ctx.walletA.read.isOwnerBytes([encodePasskeyOwner(x, y)]),
        true,
        "addOwnerPublicKey must have actually executed",
      );
    });

    it("T4.3 execute(burner, 0, addOwnerAddress(x)) — self-allowlisted selector on a FOREIGN target — DECLINES", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });
      await ownerWrite(ctx, "setSelfSelector", [ADD_OWNER_ADDRESS_SEL, true]);

      // `burner` is neither `sender` nor business-allowlisted — the ONLY thing that could sponsor
      // this call is if `target == sender` were evaluated wrong (e.g. always true, or ignored).
      const burner = ctx.beneficiary.account.address;
      const callData = buildExecuteCallData(
        ctx.walletA.abi,
        burner,
        0n,
        addOwnerAddressCallData(ctx.walletA.abi, ctx.stranger.account.address),
      );
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
        "self-allowlisted selector called on a foreign target via execute",
      );
    });

    it("T4.4 executeBatch([self.addOwnerAddress, burner.addOwnerAddress]) — SAME selector on a foreign target — DECLINES (M4d)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });
      await ownerWrite(ctx, "setSelfSelector", [ADD_OWNER_ADDRESS_SEL, true]);

      // Under a HOISTED `target == sender` check (computed once from element 0 and reused), this
      // batch would be sponsored: element 2's `target` (burner) is skipped by the business check
      // under the hoist and its selector reads `selfSelectorAllowlist[addOwnerAddress] == true` —
      // sponsoring a call into arbitrary, unvetted code that merely answers the same 4-byte
      // selector. This is the shape re-opened; the per-element check below must catch it.
      const burner = ctx.beneficiary.account.address;
      const callData = buildExecuteBatchCallData(
        ctx.walletA.abi,
        [ctx.walletAAddr, burner],
        [0n, 0n],
        [
          addOwnerAddressCallData(ctx.walletA.abi, ctx.stranger.account.address),
          addOwnerAddressCallData(ctx.walletA.abi, ctx.walletBAddr),
        ],
      );
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
        "batch: element 1 self-allowlisted, element 2 SAME selector on a foreign target",
      );
    });

    it("T4.4b executeBatch([self.addOwnerAddress, unallowlistedTarget.someOtherCall]) — DECLINES (control, rev-1 shape)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });
      await ownerWrite(ctx, "setSelfSelector", [ADD_OWNER_ADDRESS_SEL, true]);

      const burner = ctx.beneficiary.account.address;
      const callData = buildExecuteBatchCallData(
        ctx.walletA.abi,
        [ctx.walletAAddr, burner],
        [0n, 0n],
        [addOwnerAddressCallData(ctx.walletA.abi, ctx.stranger.account.address), SEL_OTHER],
      );
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
        "batch: self element ok, second element a DIFFERENT unlisted selector on a foreign target",
      );
    });

    it("T4.5 executeBatch([self.addOwnerAddress, business.SEL_ALLOWED]) — both allowlisted — sponsored", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });
      await ownerWrite(ctx, "setSelfSelector", [ADD_OWNER_ADDRESS_SEL, true]);

      const businessTarget = ctx.stranger.account.address;
      await ownerWrite(ctx, "setBusinessTarget", [businessTarget, true]);
      await ownerWrite(ctx, "setTargetSelector", [businessTarget, SEL_ALLOWED, true]);

      const newOwner = ctx.beneficiary.account.address;
      const callData = buildExecuteBatchCallData(
        ctx.walletA.abi,
        [ctx.walletAAddr, businessTarget],
        [0n, 0n],
        [addOwnerAddressCallData(ctx.walletA.abi, newOwner), SEL_ALLOWED],
      );
      const receipt = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi), "self + business mix must sponsor");
      assert.strictEqual(await ctx.walletA.read.isOwnerBytes([encodeAddressOwner(newOwner)]), true);
    });

    it("T4.6 the upgrade surface can never be self-sponsored: setSelfSelector reverts ForbiddenSelfSelector (M4c), and requestUpgrade declines", async function () {
      const ctx = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setSelfSelector([REQUEST_UPGRADE_SEL, true], {
          account: ctx.owner.account,
        }),
        ctx.paymaster,
        "ForbiddenSelfSelector",
      );
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setSelfSelector([CANCEL_UPGRADE_SEL, true], {
          account: ctx.owner.account,
        }),
        ctx.paymaster,
        "ForbiddenSelfSelector",
      );
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setSelfSelector([UPGRADE_TO_AND_CALL_SEL, true], {
          account: ctx.owner.account,
        }),
        ctx.paymaster,
        "ForbiddenSelfSelector",
      );
      // batch form must refuse identically
      await assertions.revertWithCustomError(
        ctx.paymaster.write.setSelfSelectors([[REQUEST_UPGRADE_SEL], true], {
          account: ctx.owner.account,
        }),
        ctx.paymaster,
        "ForbiddenSelfSelector",
      );

      // Since it can never be listed, execute(self, 0, requestUpgrade(impl)) declines — the op
      // never reaches the inner call, so the argument's validity does not matter here.
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });
      const callData = buildExecuteCallData(
        ctx.walletA.abi,
        ctx.walletAAddr,
        0n,
        encodeFunctionData({
          abi: ctx.walletA.abi,
          functionName: "requestUpgrade",
          args: [ctx.walletBAddr],
        }),
      );
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
        "requestUpgrade on self, never self-allowlistable",
      );
    });

    it("T4.7 removeOwnerAtIndex is NOT self-sponsored by default (add-only exclusion) — execute(self, 0, removeOwnerAtIndex(...)) declines", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });
      // Unlike the upgrade selectors, does NOT forbid this at the setter level — the
      // exclusion is a PROVISIONING decision (deploy-aa.ts's SELF_SPONSORED never includes it;
      // see that file's own comment), pinned here at the level that matters regardless of who
      // sets what: with the selector simply never allowlisted (the shipped default), the call
      // must decline.
      const callData = buildExecuteCallData(
        ctx.walletA.abi,
        ctx.walletAAddr,
        0n,
        encodeFunctionData({
          abi: ctx.walletA.abi,
          functionName: "removeOwnerAtIndex",
          args: [0n, "0x" as Hex],
        }),
      );
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
        "removeOwnerAtIndex on self, never self-allowlisted by default",
      );
    });

    it("T4.8 a self-call with an UNLISTED selector is declined", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });
      // addOwnerAddress is never allowlisted in this test — only addOwnerPublicKey is exercised
      // here, and it is not listed either.
      const callData = buildExecuteCallData(
        ctx.walletA.abi,
        ctx.walletAAddr,
        0n,
        addOwnerAddressCallData(ctx.walletA.abi, ctx.stranger.account.address),
      );
      await assertSoftDeclined(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
        "self-call with a never-allowlisted selector",
      );
    });

    it("T4.9 malformed self-call calldata declines cleanly (AA34), never hard-reverts (AA33)", async function () {
      const ctx = await loadFixture(deployFixture);
      await setupHappyPath(ctx, ctx.walletAAddr, { dailyCap: parseEther("1") });
      await ownerWrite(ctx, "setSelfSelector", [ADD_OWNER_ADDRESS_SEL, true]);

      const variants = [
        "shortHead",
        "funcOffsetOutOfRange",
        "emptyFunc",
        "shortFunc",
        "truncatedFunc",
        "batchFuncOffsetOutOfRange",
      ] as const;
      for (const variant of variants) {
        await assertSoftDeclined(
          submitSponsored(ctx, {
            walletAddr: ctx.walletAAddr,
            passkeyPriv: PASSKEY_PRIV_A,
            // target == walletAAddr (self) for every variant, so the self branch is what is
            // actually exercised by the malformed decode.
            callData: craftedSelectorCallData(variant, ctx.walletAAddr),
          }),
          `self-call variant "${variant}"`,
        );
      }
    });

    it("T4.10 setSelfSelector / setSelfSelectors are owner-only; policyManager and a stranger both revert", async function () {
      const ctx = await loadFixture(deployFixture);
      await assertions.revert(
        ctx.paymaster.write.setSelfSelector([ADD_OWNER_ADDRESS_SEL, true], {
          account: ctx.policyManager.account,
        }),
      );
      await assertions.revert(
        ctx.paymaster.write.setSelfSelector([ADD_OWNER_ADDRESS_SEL, true], {
          account: ctx.stranger.account,
        }),
      );
      await assertions.revert(
        ctx.paymaster.write.setSelfSelectors([[ADD_OWNER_ADDRESS_SEL], true], {
          account: ctx.policyManager.account,
        }),
      );
      // owner CAN, and the read-back reflects it
      await ownerWrite(ctx, "setSelfSelector", [ADD_OWNER_ADDRESS_SEL, true]);
      assert.strictEqual(
        await ctx.paymaster.read.selfSelectorAllowlist([ADD_OWNER_ADDRESS_SEL]),
        true,
      );
    });
  });

  // ============ Per-wallet cap + validAfter deferral (B1) ============
  describe("Per-wallet cap + validAfter deferral (B1)", function () {
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
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
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
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
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

  // ============ Global budget (M1) + VIP accrual (M3) ============
  describe("Global budget (M1) + VIP accrual (M3)", function () {
    it("two wallets each within their own cap but together exceeding globalDailyBudget => deferred, then rollover succeeds", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [MAX_COST]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [MAX_COST]); // shared ceiling == one op's maxCost
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, MAX_COST]);
      await pmWrite(ctx, "setSponsored", [ctx.walletBAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletBAddr, true]);
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

    it("VIP: sponsored ignoring dailyCap (1 wei, i.e. far below maxCost); globalSpentToday still increases", async function () {
      const ctx = await loadFixture(deployFixture);
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [parseEther("1")]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      // setSponsoredUnlimited now requires a non-zero dailyCap (a 0 cap made the C-B
      // latch fire on the VIP's very first op, so "unlimited" silently meant one op). 1 wei is the
      // smallest legal cap and still ~6 orders of magnitude below MAX_COST, so this keeps the
      // property under test: VIP ignores the PER-OP dailyCap gate at validation time.
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, 1n]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "unpause");

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
      await ownerWrite(ctx, "setGlobalDailyCapCeiling", [parseEther("1")]);
      await ownerWrite(ctx, "setGlobalDailyBudget", [MAX_COST]);
      await pmWrite(ctx, "setSponsored", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "setSponsorPersonal", [ctx.walletAAddr, true]);
      // Generous per-wallet cap (requires a non-zero one for VIP anyway) so the C-B latch is
      // provably NOT what blocks op #2 — the GLOBAL budget must be the sole reason. That "provably"
      // is carried by the /AA32/ matcher below, not by this comment: a bare assert.rejects() also
      // passes when the latch hard-declines op #2 with AA34, which is exactly the cause this test
      // claims to have ruled out (mutating dailyCap to 1 wei kept an unmatched assertion green).
      await pmWrite(ctx, "setDailyCap", [ctx.walletAAddr, parseEther("1")]);
      await ownerWrite(ctx, "setSponsoredUnlimited", [ctx.walletAAddr, true]);
      await ownerWrite(ctx, "unpause");

      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
      const r1 = await submitSponsored(ctx, {
        walletAddr: ctx.walletAAddr,
        passkeyPriv: PASSKEY_PRIV_A,
        callData,
      });
      assert.ok(opSucceeded(r1, ctx.entryPoint.abi));

      // second VIP op, same day: globalSpentToday(actual>0) + MAX_COST > budget(MAX_COST) ->
      // DEFERRED (AA32), not hard-declined (AA34) — asserting AA32 specifically is what pins the
      // "the global budget is the sole reason" claim above, mirroring the CONTROL test in
      // test/VerifyingPaymaster.spendcap.test.ts.
      await assert.rejects(
        submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        }),
        /AA32/,
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

      // allowlist a target with no receive()/fallback and a selector it does not implement, so the
      // inner call (and wallet.execute) reverts while the op is still sponsored.
      await ownerWrite(ctx, "setBusinessTarget", [ctx.factory.address, true]);
      await ownerWrite(ctx, "setTargetSelector", [ctx.factory.address, SEL_OTHER, true]);
      const callData = buildExecuteCallData(ctx.walletA.abi, ctx.factory.address, 1n, SEL_OTHER);

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

  // ============ Item 6c — zero-coverage surfaces ============
  describe("Item 6c — zero-coverage surfaces", function () {
    describe("setSponsoredBatch — must not diverge from setSponsored", function () {
      it("grants sponsorship AND resets both counters for EVERY wallet in the batch", async function () {
        const ctx = await loadFixture(deployFixture);
        await setupHappyPath(ctx, ctx.walletAAddr, {
          sponsorPersonal: true,
          dailyCap: parseEther("1"),
        });
        await setupHappyPath(ctx, ctx.walletBAddr, {
          sponsorPersonal: true,
          dailyCap: parseEther("1"),
        });

        const callDataA = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
        const callDataB = buildExecuteCallData(ctx.walletB.abi, ctx.walletBAddr, 0n);
        await submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData: callDataA,
        });
        await submitSponsored(ctx, {
          walletAddr: ctx.walletBAddr,
          passkeyPriv: PASSKEY_PRIV_B,
          callData: callDataB,
        });

        let policyA = (await ctx.paymaster.read.getPolicy([ctx.walletAAddr])) as any;
        let policyB = (await ctx.paymaster.read.getPolicy([ctx.walletBAddr])) as any;
        assert.ok(policyA.spentToday > 0n, "sanity: A accrued spend");
        assert.ok(policyB.spentToday > 0n, "sanity: B accrued spend");

        const hash = await ctx.paymaster.write.setSponsoredBatch(
          [[ctx.walletAAddr, ctx.walletBAddr], true],
          { account: ctx.policyManager.account },
        );
        await ctx.publicClient.waitForTransactionReceipt({ hash });

        policyA = (await ctx.paymaster.read.getPolicy([ctx.walletAAddr])) as any;
        policyB = (await ctx.paymaster.read.getPolicy([ctx.walletBAddr])) as any;
        for (const [label, p] of [
          ["A", policyA],
          ["B", policyB],
        ] as const) {
          assert.strictEqual(p.sponsored, true, `${label}: must be sponsored`);
          assert.strictEqual(
            p.spentToday,
            0n,
            `${label}: batch grant must reset spentToday, same as setSponsored`,
          );
          assert.strictEqual(
            p.lastSpentDay,
            0,
            `${label}: batch grant must reset lastSpentDay, same as setSponsored`,
          );
        }
      });

      it("a zero address MID-ARRAY reverts the WHOLE call — no partial state change", async function () {
        const ctx = await loadFixture(deployFixture);
        const before = (await ctx.paymaster.read.getPolicy([ctx.walletAAddr])) as any;

        await assertions.revertWithCustomError(
          ctx.paymaster.write.setSponsoredBatch(
            [[ctx.walletAAddr, zeroAddress, ctx.walletBAddr], true],
            { account: ctx.policyManager.account },
          ),
          ctx.paymaster,
          "ZeroAddress",
        );

        const after = (await ctx.paymaster.read.getPolicy([ctx.walletAAddr])) as any;
        assert.strictEqual(
          after.sponsored,
          before.sponsored,
          "the whole call must revert, including state for the earlier array element",
        );
      });
    });

    describe("effectiveSpentToday — off-chain convenience view", function () {
      it("returns spentToday for the SAME day, and 0 after a midnight rollover", async function () {
        const ctx = await loadFixture(deployFixture);
        await setupHappyPath(ctx, ctx.walletAAddr, {
          sponsorPersonal: true,
          dailyCap: parseEther("1"),
        });
        const callData = buildExecuteCallData(ctx.walletA.abi, ctx.walletAAddr, 0n);
        await submitSponsored(ctx, {
          walletAddr: ctx.walletAAddr,
          passkeyPriv: PASSKEY_PRIV_A,
          callData,
        });

        const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAAddr])) as any;
        assert.ok(policy.spentToday > 0n, "sanity: spend accrued");
        assert.strictEqual(
          await ctx.paymaster.read.effectiveSpentToday([ctx.walletAAddr]),
          policy.spentToday,
          "same day: must return the raw spentToday",
        );

        await time.increase(86_400n);
        assert.strictEqual(
          await ctx.paymaster.read.effectiveSpentToday([ctx.walletAAddr]),
          0n,
          "after a midnight rollover: must return 0 without needing a transaction",
        );
      });
    });

    describe("ZeroAddress reverts — every owner/policyManager setter", function () {
      it("setPolicyManager(0) reverts", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setPolicyManager([zeroAddress], { account: ctx.owner.account }),
          ctx.paymaster,
          "ZeroAddress",
        );
      });

      it("setSponsoredUnlimited(0, ...) reverts", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setSponsoredUnlimited([zeroAddress, true], {
            account: ctx.owner.account,
          }),
          ctx.paymaster,
          "ZeroAddress",
        );
      });

      it("setBusinessTarget(0, ...) reverts", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setBusinessTarget([zeroAddress, true], {
            account: ctx.owner.account,
          }),
          ctx.paymaster,
          "ZeroAddress",
        );
      });

      it("setBusinessTargets([...,0,...], ...) reverts", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setBusinessTargets(
            [[ctx.stranger.account.address, zeroAddress], true],
            { account: ctx.owner.account },
          ),
          ctx.paymaster,
          "ZeroAddress",
        );
      });

      it("setTargetSelectors(0, ...) reverts", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setTargetSelectors([zeroAddress, [SEL_ALLOWED], true], {
            account: ctx.owner.account,
          }),
          ctx.paymaster,
          "ZeroAddress",
        );
      });

      it("setSponsored(0, ...) reverts", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setSponsored([zeroAddress, true], {
            account: ctx.policyManager.account,
          }),
          ctx.paymaster,
          "ZeroAddress",
        );
      });

      it("setDailyCap(0, ...) reverts", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setDailyCap([zeroAddress, 1n], {
            account: ctx.policyManager.account,
          }),
          ctx.paymaster,
          "ZeroAddress",
        );
      });

      it("setSponsorPersonal(0, ...) reverts", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revertWithCustomError(
          ctx.paymaster.write.setSponsorPersonal([zeroAddress, true], {
            account: ctx.owner.account,
          }),
          ctx.paymaster,
          "ZeroAddress",
        );
      });
    });

    describe("Inherited owner surface — withdrawTo / addStake / unlockStake / withdrawStake", function () {
      it("withdrawTo: non-owner reverts; owner moves the deposit and getDeposit() drops by exactly that amount", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revert(
          ctx.paymaster.write.withdrawTo([ctx.stranger.account.address, 1n], {
            account: ctx.stranger.account,
          }),
        );

        const depositBefore = (await ctx.paymaster.read.getDeposit()) as bigint;
        const amount = parseEther("1");
        const strangerBalBefore = await ctx.publicClient.getBalance({
          address: ctx.stranger.account.address,
        });

        const hash = await ctx.paymaster.write.withdrawTo([ctx.stranger.account.address, amount], {
          account: ctx.owner.account,
        });
        await ctx.publicClient.waitForTransactionReceipt({ hash });

        const depositAfter = (await ctx.paymaster.read.getDeposit()) as bigint;
        const strangerBalAfter = await ctx.publicClient.getBalance({
          address: ctx.stranger.account.address,
        });
        assert.strictEqual(
          depositBefore - depositAfter,
          amount,
          "getDeposit() must drop by exactly the withdrawn amount",
        );
        assert.strictEqual(
          strangerBalAfter - strangerBalBefore,
          amount,
          "the withdrawal target must receive exactly that amount",
        );
      });

      it("addStake: non-owner reverts; owner stakes and the stake is reflected on the EntryPoint", async function () {
        const ctx = await loadFixture(deployFixture);
        await assertions.revert(
          ctx.paymaster.write.addStake([86_400], {
            account: ctx.stranger.account,
            value: parseEther("1"),
          }),
        );

        await ownerWrite(ctx, "addStake", [86_400], parseEther("1"));

        const info = (await ctx.entryPoint.read.getDepositInfo([ctx.paymaster.address])) as any;
        assert.strictEqual(info.stake, parseEther("1"));
        assert.strictEqual(info.staked, true);
      });

      it("unlockStake / withdrawStake: non-owner reverts on both; owner can unlock, wait the delay, and withdraw the stake — the undocumented 4th fleet-wide kill switch", async function () {
        const ctx = await loadFixture(deployFixture);
        await ownerWrite(ctx, "addStake", [86_400], parseEther("1"));

        await assertions.revert(ctx.paymaster.write.unlockStake({ account: ctx.stranger.account }));

        await ownerWrite(ctx, "unlockStake");
        let info = (await ctx.entryPoint.read.getDepositInfo([ctx.paymaster.address])) as any;
        assert.strictEqual(info.staked, false, "unlockStake must un-stake the paymaster");

        await assertions.revert(
          ctx.paymaster.write.withdrawStake([ctx.stranger.account.address], {
            account: ctx.stranger.account,
          }),
        );
        // withdrawStake before the delay elapses must revert too.
        await assertions.revert(
          ctx.paymaster.write.withdrawStake([ctx.owner.account.address], {
            account: ctx.owner.account,
          }),
        );

        await time.increase(86_400n + 1n);

        const balBefore = await ctx.publicClient.getBalance({ address: ctx.owner.account.address });
        const hash = await ctx.paymaster.write.withdrawStake([ctx.owner.account.address], {
          account: ctx.owner.account,
        });
        const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
        const balAfter = await ctx.publicClient.getBalance({ address: ctx.owner.account.address });

        info = (await ctx.entryPoint.read.getDepositInfo([ctx.paymaster.address])) as any;
        assert.strictEqual(info.stake, 0n, "the stake must be fully withdrawn");
        const gasCost = receipt.gasUsed * receipt.effectiveGasPrice;
        assert.strictEqual(
          balAfter - balBefore + gasCost,
          parseEther("1"),
          "the owner must receive exactly the withdrawn stake",
        );
      });
    });
  });
});
