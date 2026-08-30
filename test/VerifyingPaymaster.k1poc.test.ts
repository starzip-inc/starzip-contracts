/**
 * SPONSORED-GAS-BURN REGRESSION GUARD (originally a proof of concept from an adversarial
 * verification pass; converted to a regression test once the fix below landed).
 *
 * ORIGINAL CLAIM (now CLOSED): an ordinary business-gated wallet (sponsorPersonal = FALSE, i.e.
 * subject to the full (target, selector) allowlist) could trigger the SAME gas-burn mechanism
 * the VerifyingPaymaster.sol header documents (see its "SINGLE-BUNDLE WORST-CASE LOSS" block) —
 * even though that header's own tests (VerifyingPaymaster.spendcap.test.ts, "single-bundle
 * worst-case loss") only exercise the burn via `sponsorPersonal = true`, which bypasses the
 * business-target allowlist entirely and points `execute()` directly at a raw burner contract.
 *
 * WHY a business-gated wallet could ALSO reach this: `_extractBusinessOk` (VerifyingPaymaster.sol)
 * validates only the inner call's (target, 4-byte selector) pair, never its ARGUMENTS.
 * TradeSettlementV1.depositWithPermit(address _token, ...) used to make an EXTERNAL call to
 * attacker-supplied `_token` (`try IERC20Permit(_token).permit(...) {} catch {}`) BEFORE the
 * `supportedTokens`/`quoteAssets` gate that lives downstream in `_deposit`. So `_token` could be an
 * arbitrary attacker-deployed contract, and the (target, selector) allowlist — which only ever
 * looks at the OUTER target (TradeSettlementV1) and OUTER selector (depositWithPermit) — never saw
 * or restricted it.
 *
 * THE FIX: TWO INDEPENDENT LAYERS, both present in this test file on purpose —
 *   (2a) the deploy config excludes `depositWithPermit` from TradeSettlementV1's sponsored
 *        selectors entirely — the deploy-time mitigation. This test file deliberately does NOT exercise that exclusion: its OWN
 *        `provisionRealNonPrivileged` below still allowlists `depositWithPermit` locally, so the
 *        REGRESSION test below proves layer (2b), the contract-level fix, independent of whether
 *        a future deploy config re-adds the selector.
 *   (2b) contracts/trade/TradeSettlementV1.sol's new `onlySupportedToken` modifier runs on BOTH
 *        `depositToken` and `depositWithPermit`, BEFORE either makes any external call on
 *        `_token` — so an unsupported/unlisted `_token` now reverts before `depositWithPermit`
 *        ever constructs its `try permit(...)` call, and the burner is never reached.
 * MUTATION TEST: moving the
 * `onlySupportedToken` check back below the `try permit(...)` call must make the REGRESSION test
 * below fail again, reproducing the original EXPLOIT numbers. Verified by hand during this
 * conversion.
 *
 * CONTROL: `depositToken` is sponsored on the SAME target and was NEVER vulnerable — its shared
 * body already checked `supportedTokens[_token]` before any external call to `_token`. It remains
 * here as the baseline "cheap revert" cost against which the REGRESSION test's measurement is
 * compared — after the fix, both selectors now revert at essentially the SAME cost, which is
 * exactly the claim under test.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseEther,
  parseEventLogs,
  hexToBytes,
  encodeFunctionData,
  toFunctionSelector,
  zeroAddress,
  getAddress,
  type Address,
  type Hex,
} from "viem";
import { loadFixture, getConnection } from "./helpers.js";
import {
  passkeyPubCoords,
  packU128Pair,
  buildExecuteCallData,
  paymasterAndDataFor,
  execWithPaymaster,
  computeMaxCost,
  encodePasskeyOwner,
  SPONSOR_SIGNER,
} from "./aa-helpers.js";

const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const SALT = 12345n;

const MAX_FEE_PER_GAS = 1_000_000_000n; // 1 gwei, matches deploy-aa.ts / spendcap test's profile

// The deploy script's REAL constants (see the spendcap worst-case-loss block).
const REAL_DEPOSIT = parseEther("0.05");
const REAL_CEILING = parseEther("0.001");
const REAL_BUDGET = parseEther("0.01");
const REAL_MAX_OP_COST = parseEther("0.0007");
const REAL_MAX_PRE_VER_GAS = 60_000n;

// Same unconditional-infinite-loop burner as VerifyingPaymaster.spendcap.test.ts's block:
// runtime `5b600056` = JUMPDEST; PUSH1 0; JUMP. Ignores calldata/selector entirely, so it burns
// gas identically whether called as a raw target OR as `permit(...)` through depositWithPermit.
const BURNER_INIT_CODE = "0x6004600c60003960046000f35b600056" as Hex;

const DEPOSIT_WITH_PERMIT_SIG = "depositWithPermit(address,uint256,uint256,uint8,bytes32,bytes32)";
const DEPOSIT_TOKEN_SIG = "depositToken(address,uint256)";

async function deployFixture() {
  const { viem } = await getConnection();
  const [deployer, ownerWallet, policyManagerWallet, beneficiary, feeRecipient] =
    await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();

  const entryPoint = await viem.deployContract("TestEntryPoint", []);

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
    value: REAL_DEPOSIT,
    data: "0xd0e30db0" as Hex, // deposit() selector
  });
  await publicClient.waitForTransactionReceipt({ hash: depositHash });

  // Real TradeSettlementV1, proxied and initialized exactly as the deploy script / production
  // would, so this is not a mock standing in for the real gate ordering.
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
    settlement,
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
  const hash = await (ctx.paymaster.write as any)[fn](args, {
    account: ctx.policyManager.account,
  });
  await ctx.publicClient.waitForTransactionReceipt({ hash });
}

// Mirrors deploy-aa.ts's real config, sponsors the wallet as an ORDINARY business wallet
// (sponsorPersonal left at its default FALSE — never set true anywhere in this file), and
// allowlists TradeSettlementV1 for BOTH depositWithPermit and depositToken, exactly as
// the deploy script does today.
async function provisionRealNonPrivileged(ctx: Ctx) {
  await ownerWrite(ctx, "setGlobalDailyCapCeiling", [REAL_CEILING]);
  await ownerWrite(ctx, "setGlobalDailyBudget", [REAL_BUDGET]);
  await ownerWrite(ctx, "setMaxSponsoredOpCost", [REAL_MAX_OP_COST]);
  await ownerWrite(ctx, "setMaxSponsoredFeePerGas", [MAX_FEE_PER_GAS]);
  await ownerWrite(ctx, "setMaxSponsoredPreVerificationGas", [REAL_MAX_PRE_VER_GAS]);
  await ownerWrite(ctx, "setBusinessTargets", [[ctx.settlement.address], true]);
  await ownerWrite(ctx, "setTargetSelectors", [
    ctx.settlement.address,
    [toFunctionSelector(DEPOSIT_WITH_PERMIT_SIG), toFunctionSelector(DEPOSIT_TOKEN_SIG)],
    true,
  ]);
  await pmWrite(ctx, "setSponsored", [ctx.walletAddr, true]);
  await pmWrite(ctx, "setDailyCap", [ctx.walletAddr, REAL_CEILING]);
  // Deliberately NOT calling setSponsorPersonal — the wallet stays business-gated.
  await ownerWrite(ctx, "unpause");
}

async function deployBurner(ctx: Ctx): Promise<Address> {
  const hash = await ctx.deployer.sendTransaction({ data: BURNER_INIT_CODE });
  const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
  return receipt.contractAddress as Address;
}

function userOpEvent(ctx: Ctx, receipt: { logs: unknown[] }) {
  const events = parseEventLogs({
    abi: ctx.entryPoint.abi,
    logs: receipt.logs as never,
    eventName: "UserOperationEvent",
  });
  return events[0] as unknown as {
    args: { success: boolean; actualGasCost: bigint; actualGasUsed: bigint };
  };
}

describe("regression — business-gated (sponsorPersonal=false) depositWithPermit gas-burn CLOSED (was K-1 PoC)", function () {
  it("SANITY: wallet is genuinely NOT sponsorPersonal — a call to a NON-allowlisted target is declined", async function () {
    const ctx = await loadFixture(deployFixture);
    await provisionRealNonPrivileged(ctx);
    const burnerAddr = await deployBurner(ctx);

    const policy = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
    assert.strictEqual(policy.sponsorPersonal, false, "sponsorPersonal must be false in this PoC");

    // A direct execute() at the burner (not businessAllowlist'd) must be declined at validation —
    // proves the (target, selector) gate is actually active for this wallet, not vacuously true.
    const callData = buildExecuteCallData(ctx.wallet.abi, burnerAddr, 0n);
    await assert.rejects(
      execWithPaymaster({
        publicClient: ctx.publicClient,
        entryPoint: ctx.entryPoint,
        walletAddr: ctx.walletAddr,
        callData,
        paymasterAndData: paymasterAndDataFor(ctx.paymaster.address, 100_000n, 100_000n),
        passkeyPriv: PASSKEY_PRIV,
        submitter: ctx.deployer,
        beneficiary: ctx.beneficiary.account.address,
        accountGasLimits: packU128Pair(150_000n, 150_000n),
        preVerificationGas: 50_000n,
        gasFees: packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS),
      }),
      /AA33|AA34/,
      "direct call to a non-allowlisted burner must be declined for a non-sponsorPersonal wallet",
    );
  });

  it("REGRESSION (was EXPLOIT): depositWithPermit(burner, ...) through the ALLOWLISTED (target, selector) pair now DECLINES the burner before it ever runs, and is billed no more than the CONTROL baseline", async function () {
    const ctx = await loadFixture(deployFixture);
    await provisionRealNonPrivileged(ctx);
    const burnerAddr = await deployBurner(ctx);

    const deadline = 9_999_999_999n;
    const depositWithPermitCalldata = encodeFunctionData({
      abi: ctx.settlement.abi,
      functionName: "depositWithPermit",
      args: [
        burnerAddr,
        1n,
        deadline,
        27,
        `0x${"11".repeat(32)}` as Hex,
        `0x${"22".repeat(32)}` as Hex,
      ],
    });
    const innerCallData = buildExecuteCallData(
      ctx.wallet.abi,
      ctx.settlement.address,
      0n,
      depositWithPermitCalldata,
    );

    // SAME gas profile as the original EXPLOIT test, deliberately unchanged, so this measurement
    // is a true before/after comparison rather than a differently-shaped one. Pre-fix, this
    // profile let the burner's infinite loop consume callGasLimit; post-fix, `onlySupportedToken`
    // (contracts/trade/TradeSettlementV1.sol) reverts before `depositWithPermit` ever reaches the
    // `try permit(...)` call, so the burner never executes and this generous callGasLimit goes
    // almost entirely unused (and is refunded — see the contract header's block on refunds).
    const verGas = 150_000n;
    const callGas = 300_000n;
    const pmValGas = 100_000n;
    const pmPostGas = 100_000n;
    const preVerGas = 50_000n;

    const prefund = computeMaxCost({
      verificationGasLimit: verGas,
      callGasLimit: callGas,
      paymasterVerificationGasLimit: pmValGas,
      paymasterPostOpGasLimit: pmPostGas,
      preVerificationGas: preVerGas,
      maxFeePerGas: MAX_FEE_PER_GAS,
    });
    assert.ok(
      prefund <= REAL_MAX_OP_COST,
      `sanity: this op's prefund (${prefund}) must clear maxSponsoredOpCost (${REAL_MAX_OP_COST})`,
    );

    const depositBefore = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;

    const receipt = await execWithPaymaster({
      publicClient: ctx.publicClient,
      entryPoint: ctx.entryPoint,
      walletAddr: ctx.walletAddr,
      callData: innerCallData,
      paymasterAndData: paymasterAndDataFor(ctx.paymaster.address, pmValGas, pmPostGas),
      passkeyPriv: PASSKEY_PRIV,
      submitter: ctx.deployer,
      beneficiary: ctx.beneficiary.account.address,
      accountGasLimits: packU128Pair(verGas, callGas),
      preVerificationGas: preVerGas,
      gasFees: packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS),
    });
    assert.strictEqual(receipt.status, "success", "the bundle tx itself must land (op admitted)");

    const depositAfter = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;
    const drain = depositBefore - depositAfter;
    const evt = userOpEvent(ctx, receipt);

    console.log(
      `\n    [regression] business-gated depositWithPermit, post-fix: op success=` +
        `${evt.args.success}, actualGasCost=${evt.args.actualGasCost} wei, prefund=${prefund} ` +
        `wei (ratio ${(Number(evt.args.actualGasCost) * 100) / Number(prefund)}%), deposit ` +
        `drain=${drain} wei (${(Number(drain) * 100) / Number(REAL_DEPOSIT)}% of the 0.05 ` +
        `deposit), declared callGasLimit=${callGas}. PRE-FIX this same profile measured ` +
        `actualGasCost=484633000000000 wei (69.23% of prefund) — see the CONTROL test's own log ` +
        `for that number's provenance.\n`,
    );

    // The op is still admitted and billed — reverting never stops billing (see the contract
    // header's `postOpReverted` note) — but it must now revert CHEAPLY, before the burner's loop
    // ever runs, for a wallet that is NOT sponsorPersonal, via a call that passed the (target,
    // selector) allowlist. This is the same shape asserted for CONTROL below; asserting it here
    // too is the regression proof — pre-fix this assertion FAILED (see MUTATION M2b in the file
    // header comment: reverting the `onlySupportedToken` reorder reproduces that failure).
    assert.strictEqual(evt.args.success, false, "the userOp must have REVERTED (opReverted)");
    assert.ok(
      evt.args.actualGasCost > 0n,
      "a reverted op must still have been billed a nonzero actualGasCost",
    );
    // THE CORE REGRESSION CLAIM: the burn must NOT have consumed a large share of the declared
    // callGasLimit's worth of prefund — measured post-fix at ~35.1% (essentially identical to
    // CONTROL's own ~35.1%, both driven by EntryPoint v0.8's unused-gas penalty, not by the
    // burner). 50% is the same conservative ceiling CONTROL asserts below, kept identical so the
    // two tests are directly comparable; print the exact ratio above for the real number. Before
    // the fix this ratio measured 69.23%, comfortably above this ceiling — this assertion is what
    // FAILS under M2b.
    assert.ok(
      evt.args.actualGasCost * 100n < prefund * 50n,
      `actualGasCost (${evt.args.actualGasCost}) must be LESS than 50% of prefund (${prefund}) — ` +
        "a value at or above that threshold means the burner's infinite loop is being reached " +
        "again, i.e. the gas-burn path has regressed",
    );

    // And the wallet's deposit/permit state on TradeSettlementV1 must show NOTHING went through —
    // this was a pure gas-burn, not an actual (even if unwanted) deposit.
    const balance = (await ctx.settlement.read.balances([ctx.walletAddr, burnerAddr])) as bigint;
    assert.strictEqual(balance, 0n, "no deposit state must have been written — the call reverted");
  });

  it("CONTROL: the SAME burner through the SAME allowlisted target via depositToken (not depositWithPermit) reverts CHEAPLY — no external call reaches the burner", async function () {
    const ctx = await loadFixture(deployFixture);
    await provisionRealNonPrivileged(ctx);
    const burnerAddr = await deployBurner(ctx);

    const depositTokenCalldata = encodeFunctionData({
      abi: ctx.settlement.abi,
      functionName: "depositToken",
      args: [burnerAddr, 1n],
    });
    const innerCallData = buildExecuteCallData(
      ctx.wallet.abi,
      ctx.settlement.address,
      0n,
      depositTokenCalldata,
    );

    const verGas = 150_000n;
    const callGas = 300_000n; // same generous budget as the REGRESSION test above
    const pmValGas = 100_000n;
    const pmPostGas = 100_000n;
    const preVerGas = 50_000n;

    const prefund = computeMaxCost({
      verificationGasLimit: verGas,
      callGasLimit: callGas,
      paymasterVerificationGasLimit: pmValGas,
      paymasterPostOpGasLimit: pmPostGas,
      preVerificationGas: preVerGas,
      maxFeePerGas: MAX_FEE_PER_GAS,
    });

    const receipt = await execWithPaymaster({
      publicClient: ctx.publicClient,
      entryPoint: ctx.entryPoint,
      walletAddr: ctx.walletAddr,
      callData: innerCallData,
      paymasterAndData: paymasterAndDataFor(ctx.paymaster.address, pmValGas, pmPostGas),
      passkeyPriv: PASSKEY_PRIV,
      submitter: ctx.deployer,
      beneficiary: ctx.beneficiary.account.address,
      accountGasLimits: packU128Pair(verGas, callGas),
      preVerificationGas: preVerGas,
      gasFees: packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS),
    });
    assert.strictEqual(receipt.status, "success");

    const evt = userOpEvent(ctx, receipt);
    console.log(
      `\n    [K-1 control] depositToken burn attempt: success=${evt.args.success}, ` +
        `actualGasCost=${evt.args.actualGasCost} wei, prefund=${prefund} wei ` +
        `(ratio ${(Number(evt.args.actualGasCost) * 100) / Number(prefund)}%)\n`,
    );

    assert.strictEqual(
      evt.args.success,
      false,
      "depositToken(burner, 1) must revert (UnsupportedToken)",
    );
    // NOTE: EntryPoint v0.8's `_getUnusedGasPenalty` charges a penalty on UNUSED declared gas
    // limits regardless of whether anything burns (anti-griefing-by-over-declaration), so even
    // this cheap revert is not billed near-zero at a generously-declared callGasLimit=300,000 —
    // that penalty alone accounts for the bulk of what IS billed here. depositToken's
    // `supportedTokens`/`quoteAssets` check (the `onlySupportedToken` modifier, item 2b) has
    // always run BEFORE any external call to `_token`, so the burner's infinite loop never
    // executed on this path — depositToken was never vulnerable to .
    //
    // PRE-FIX, this same profile isolated the burn as the DELTA against the (then-named) EXPLOIT
    // test: 484,633,000,000,000 wei (69.23%) vs this test's ~245,728,000,000,000 wei (~35.1%) — a
    // ~34-point gap attributable to depositWithPermit reaching the attacker's contract.
    // POST-FIX, the REGRESSION test above measures ~245,719,000,000,000 wei (~35.1%) — the SAME
    // baseline as this CONTROL, within noise (~0.004%) — i.e. the delta has collapsed to ~0,
    // which is exactly item 2b's claim.
    console.log(
      `\n    [K-1 control] same callGasLimit=300000 as the REGRESSION test: control billed ` +
        `${evt.args.actualGasCost} wei (${(Number(evt.args.actualGasCost) * 100) / Number(prefund)}%) ` +
        `— pre-fix the (then-)EXPLOIT test billed 484633000000000 wei (69.23%) at this same ` +
        `profile; post-fix it billed ~the same as this CONTROL (see the REGRESSION test's own log)\n`,
    );
    assert.ok(
      evt.args.actualGasCost * 100n < prefund * 50n,
      `CONTROL, at the SAME declared gas profile as the REGRESSION test, must still bill LESS ` +
        `than the pre-fix EXPLOIT's 69.23% ratio (50% margin kept for the unused-gas-penalty ` +
        `baseline) — got ${(Number(evt.args.actualGasCost) * 100) / Number(prefund)}%`,
    );
  });
});
