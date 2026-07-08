/**
 * Empirical `_postOp` cold-path gas measurement (Finding M-1 — the MIN_POSTOP_GAS floor must be
 * proven, not guessed). Uses a fake "EntryPoint" (`PostOpGasProbe`) that calls
 * `VerifyingPaymaster.postOp` directly and reports the exact `gasleft()` delta — i.e. precisely
 * what a real EntryPoint forwards as `paymasterPostOpGasLimit`. Calling `postOp` as the very
 * first storage-touching op on a freshly deployed paymaster makes every slot `_postOp` touches
 * (walletPolicy[sender], the global spent/day slot) genuinely cold — a strictly worse (more
 * expensive) case than the real handleOps flow, where `_validatePaymasterUserOp` already warms
 * those slots earlier in the same transaction. See contracts/mocks/PostOpGasProbe.sol.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { encodeAbiParameters, getAddress, pad, toHex } from "viem";
import { loadFixture, getConnection } from "./helpers.js";

const FRESH_WALLET = getAddress(pad(toHex(0xc0ffeen), { size: 20 }));

async function deployFixture() {
  const { viem } = await getConnection();
  const [deployer, policyManagerWallet] = await viem.getWalletClients();

  const probe = await viem.deployContract("PostOpGasProbe", []);
  const paymaster = await viem.deployContract("VerifyingPaymaster", [
    probe.address,
    policyManagerWallet.account.address,
  ]);

  return { viem, probe, paymaster, deployer };
}

describe("VerifyingPaymaster._postOp — empirical cold-path gas (M-1)", function () {
  it("measures the cold-path gas of a FIRST sponsored op for a fresh wallet on a fresh global-day", async function () {
    const ctx = await loadFixture(deployFixture);

    const context = encodeAbiParameters([{ type: "address" }], [FRESH_WALLET]);
    const actualGasCost = 123_456n;
    const actualUserOpFeePerGas = 1_000_000_000n;

    // opSucceeded=0; `_postOp` ignores `mode` so the cost is identical for opReverted.
    const { result: measured } = (await ctx.probe.simulate.measurePostOpGas([
      ctx.paymaster.address,
      0,
      context,
      actualGasCost,
      actualUserOpFeePerGas,
    ])) as { result: bigint };

    console.log(
      `\n    [M-1] _postOp cold-path gas (fresh wallet, fresh global-day, direct call): ${measured} gas\n`,
    );

    const minPostOpGas = (await ctx.paymaster.read.MIN_POSTOP_GAS()) as bigint;
    assert.ok(
      measured < minPostOpGas,
      `MIN_POSTOP_GAS (${minPostOpGas}) must exceed the measured cold-path gas (${measured}) with margin`,
    );
  });
});
