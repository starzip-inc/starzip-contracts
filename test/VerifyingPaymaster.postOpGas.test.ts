/**
 * Empirical `_postOp` cold-path gas measurement (Finding the MIN_POSTOP_GAS floor must be
 * proven, not guessed). Uses a fake "EntryPoint" (`PostOpGasProbe`) that calls
 * `VerifyingPaymaster.postOp` directly and reports the exact `gasleft()` delta — i.e. precisely
 * what a real EntryPoint forwards as `paymasterPostOpGasLimit`. Calling `postOp` as the very
 * first storage-touching op on a freshly deployed paymaster makes every slot `_postOp` touches
 * (walletPolicy[sender], the global spent/day slot) genuinely cold — a strictly worse (more
 * expensive) case than the real handleOps flow, where `_validatePaymasterUserOp` already warms
 * those slots earlier in the same transaction. See contracts/mocks/PostOpGasProbe.sol.
 *
 * The original version of this file measured ONLY
 * `FRESH_WALLET` — a never-provisioned address, so `p.sponsored == false` and the latch branch
 * (`p.sponsored && p.spentToday > effectiveDailyCap` -> extra SSTORE + LOG2) was DEAD in the only
 * test guarding `MIN_POSTOP_GAS`, even though that constant's own NatSpec instructs re-deriving it
 * whenever `_postOp` changes. Every reachable `_postOp` branch is now measured here.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { encodeAbiParameters, getAddress, pad, parseEther, toHex, type Address } from "viem";
import { loadFixture, getConnection } from "./helpers.js";

const FRESH_WALLET = getAddress(pad(toHex(0xc0ffeen), { size: 20 }));
const SPONSORED_WALLET = getAddress(pad(toHex(0xbeef01n), { size: 20 }));
const LATCHING_WALLET = getAddress(pad(toHex(0xbeef02n), { size: 20 }));
const VIP_LATCHING_WALLET = getAddress(pad(toHex(0xbeef03n), { size: 20 }));

const ACTUAL_GAS_COST = 123_456n;
const ACTUAL_USER_OP_FEE_PER_GAS = 1_000_000_000n;

async function deployFixture() {
  const { viem } = await getConnection();
  const publicClient = await viem.getPublicClient();
  const [deployer, policyManagerWallet] = await viem.getWalletClients();

  const probe = await viem.deployContract("PostOpGasProbe", []);
  const paymaster = await viem.deployContract("VerifyingPaymaster", [
    probe.address,
    policyManagerWallet.account.address,
  ]);

  const ownerWrite = async (fn: string, args: unknown[]) => {
    const hash = await (paymaster.write as any)[fn](args, { account: deployer.account });
    await publicClient.waitForTransactionReceipt({ hash });
  };
  const pmWrite = async (fn: string, args: unknown[]) => {
    const hash = await (paymaster.write as any)[fn](args, {
      account: policyManagerWallet.account,
    });
    await publicClient.waitForTransactionReceipt({ hash });
  };

  await ownerWrite("setGlobalDailyCapCeiling", [parseEther("1")]);

  // sponsored, cap far above ACTUAL_GAS_COST -> accrual only, latch branch NOT taken.
  await pmWrite("setSponsored", [SPONSORED_WALLET, true]);
  await pmWrite("setDailyCap", [SPONSORED_WALLET, parseEther("1")]);

  // sponsored, cap of 1 wei -> latch branch taken (extra SSTORE flipping `sponsored` + LOG2).
  await pmWrite("setSponsored", [LATCHING_WALLET, true]);
  await pmWrite("setDailyCap", [LATCHING_WALLET, 1n]);

  // same, plus vip — the latch does not exempt VIP, so this must take the branch too.
  await pmWrite("setSponsored", [VIP_LATCHING_WALLET, true]);
  await pmWrite("setDailyCap", [VIP_LATCHING_WALLET, 1n]);
  await ownerWrite("setSponsoredUnlimited", [VIP_LATCHING_WALLET, true]);

  return { viem, probe, paymaster, deployer };
}

type Ctx = Awaited<ReturnType<typeof deployFixture>>;

async function measure(ctx: Ctx, wallet: Address): Promise<bigint> {
  const context = encodeAbiParameters([{ type: "address" }], [wallet]);
  // opSucceeded=0; `_postOp` ignores `mode` so the cost is identical for opReverted.
  const { result } = (await ctx.probe.simulate.measurePostOpGas([
    ctx.paymaster.address,
    0,
    context,
    ACTUAL_GAS_COST,
    ACTUAL_USER_OP_FEE_PER_GAS,
  ])) as { result: bigint };
  return result;
}

describe("VerifyingPaymaster._postOp — empirical cold-path gas", function () {
  it("every reachable _postOp branch stays under MIN_POSTOP_GAS, and the unprovisioned wallet remains the worst case", async function () {
    const ctx = await loadFixture(deployFixture);

    const unprovisioned = await measure(ctx, FRESH_WALLET);
    const sponsoredNotLatched = await measure(ctx, SPONSORED_WALLET);
    const latched = await measure(ctx, LATCHING_WALLET);
    const vipLatched = await measure(ctx, VIP_LATCHING_WALLET);

    const minPostOpGas = (await ctx.paymaster.read.MIN_POSTOP_GAS()) as bigint;
    console.log(
      `\n    [postOp] cold-path gas vs MIN_POSTOP_GAS (${minPostOpGas}):\n` +
        `      unprovisioned (!sponsored, latch branch not taken): ${unprovisioned}\n` +
        `      sponsored, under cap (latch branch not taken):      ${sponsoredNotLatched}\n` +
        `      sponsored, over cap (LATCH FIRES: SSTORE + LOG2):   ${latched}\n` +
        `      VIP, over cap (LATCH FIRES — VIP is not exempt):    ${vipLatched}\n` +
        `      headroom under the worst case: ${minPostOpGas - unprovisioned} gas\n`,
    );

    for (const [label, measured] of [
      ["unprovisioned", unprovisioned],
      ["sponsored-not-latched", sponsoredNotLatched],
      ["latched", latched],
      ["vip-latched", vipLatched],
    ] as const) {
      assert.ok(
        measured < minPostOpGas,
        `MIN_POSTOP_GAS (${minPostOpGas}) must exceed the ${label} cold-path gas (${measured})`,
      );
    }

    // The latch branch costs strictly MORE than the same wallet without it — if this ever stops
    // holding, the branch is no longer being exercised and this test has gone blind again.
    assert.ok(
      latched > sponsoredNotLatched,
      `the latch branch must cost more than the plain-accrual path (${latched} vs ` +
        `${sponsoredNotLatched}) — otherwise this test is not actually reaching it`,
    );

    // MIN_POSTOP_GAS is derived from the unprovisioned case; that must remain the ceiling.
    assert.ok(
      unprovisioned > latched && unprovisioned > sponsoredNotLatched && unprovisioned > vipLatched,
      "the unprovisioned (fully cold, no prior SSTOREs to the policy slot) case must remain the " +
        "worst case MIN_POSTOP_GAS is sized against",
    );
  });
});
