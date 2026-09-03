/**
 * F7: `StarzipWallet`'s constructor validates `canonicalPaymaster` before storing it as
 * `immutable`. Without this, a wrong address (EOA, codeless, or a contract that doesn't answer
 * this interface) can never be corrected post-deploy, and SSA-01's `requestUpgrade` (fail-closed
 * on a failed `revokeSponsorshipOnUpgrade()` push) would then permanently brick every upgrade on
 * every wallet naming it.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { zeroAddress, getAddress, pad, toHex } from "viem";
import { getConnection, assertions } from "./helpers.js";
import { SPONSOR_SIGNER } from "./aa-helpers.js";

describe("StarzipWallet — F7: canonicalPaymaster validated at construction", function () {
  it("rejects an EOA as canonicalPaymaster", async function () {
    const { viem } = await getConnection();
    const [deployer] = await viem.getWalletClients();
    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    await assertions.revertWithCustomError(
      viem.deployContract("StarzipWallet", [entryPoint.address, deployer.account.address]),
      null,
      "InvalidPaymaster",
    );
  });

  it("rejects a codeless address", async function () {
    const { viem } = await getConnection();
    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    const codelessAddress = getAddress(pad(toHex(0xc0ffeen), { size: 20 }));
    await assertions.revertWithCustomError(
      viem.deployContract("StarzipWallet", [entryPoint.address, codelessAddress]),
      null,
      "InvalidPaymaster",
    );
  });

  it("rejects a contract that doesn't implement getPolicy(address) at all", async function () {
    const { viem } = await getConnection();
    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    const notAPaymaster = await viem.deployContract("GasBombERC1271Wallet", []);
    await assertions.revertWithCustomError(
      viem.deployContract("StarzipWallet", [entryPoint.address, notAPaymaster.address]),
      null,
      "InvalidPaymaster",
    );
  });

  it("accepts address(0) — no-paymaster deployment", async function () {
    const { viem } = await getConnection();
    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    const wallet = await viem.deployContract("StarzipWallet", [entryPoint.address, zeroAddress]);
    assert.strictEqual(getAddress(await wallet.read.canonicalPaymaster()), getAddress(zeroAddress));
  });

  it("accepts a real, deployed VerifyingPaymaster as canonicalPaymaster", async function () {
    const { viem } = await getConnection();
    const [, policyManagerWallet] = await viem.getWalletClients();
    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    const paymaster = await viem.deployContract("VerifyingPaymaster", [
      entryPoint.address,
      policyManagerWallet.account.address,
      zeroAddress,
      SPONSOR_SIGNER,
    ]);
    const wallet = await viem.deployContract("StarzipWallet", [entryPoint.address, paymaster.address]);
    assert.strictEqual(
      getAddress(await wallet.read.canonicalPaymaster()),
      getAddress(paymaster.address),
    );
  });
});
