/**
 * Audit Finding 03 — Unfinalized launches permanently freeze owner allocations.
 *
 * The owner vesting wallet is funded at issuance but only releases once `startVesting`
 * flips `started`. Every terminal non-finalization path (permissionless expiry, owner
 * cancellation, escrow reclamation) must not leave the funded allocation permanently
 * unstarted and unreleasable.
 *
 * (2026-08): cancel/expire no longer start Owner Vesting IMMEDIATELY — a cancelled
 * sale's `saleAmount` now returns to `TokenFactory` escrow (resale-eligible), and Owner
 * Vesting is triggered by `finalizeLaunchpad` (success) ONLY. The freeze this file guards
 * against is instead closed by:
 *   - `TokenFactory.triggerOwnerVesting` — PERMISSIONLESS, once `escrowDeadline` elapses
 *     (the same resale-wait deadline `restoreEscrow` sets on cancel).
 *   - `TokenFactory.reclaimEscrow`       — business/owner-gated, same timeout, also starts
 *     the wallet directly (factory-authorized) as a side effect.
 *
 * PoC ported from the audit doc, inverted to assert the FIXED (freeze-proof) behavior.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { encodeFunctionData, getAddress, parseUnits, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { assertions, getConnection, time } from "./helpers.js";
import {
  buildRatios,
  configureDefaultAllocationGuides,
  deployTokenFactoryCore,
  setEscrowTimeout,
  setResaleWait,
  setLinkedLaunchpad,
  issueTokenWithRatios,
} from "./tokenFactoryHelpers.js";

const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const DAY = 24n * 60n * 60n;
const REFUND_GRACE = 14n * DAY;
const OWNER_VESTING_DURATION = 30n * DAY;

async function deployLaunchpadProxy(viem: any, args: readonly unknown[]): Promise<any> {
  const implMathLib = await viem.deployContract("LaunchpadMathLib", []);
  const impl = await viem.deployContract("LaunchpadV1", [], {
    libraries: { LaunchpadMathLib: implMathLib.address },
  });
  const initData = encodeFunctionData({ abi: impl.abi, functionName: "initialize", args });
  const proxy = await viem.deployContract("ERC1967Proxy", [impl.address, initData]);
  return viem.getContractAt("LaunchpadV1", proxy.address);
}

async function bootstrap() {
  const { viem } = await getConnection();
  const [owner, business, other, investor, platformTreasury, feeRecipient] =
    await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();
  const chainId = await publicClient.getChainId();
  const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);

  const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);
  const { tokenFactory } = await deployTokenFactoryCore(
    viem,
    owner,
    platformTreasury.account.address as Address,
    permitSigner.address,
  );
  await configureDefaultAllocationGuides(tokenFactory, owner);

  const launchpad = await deployLaunchpadProxy(viem, [
    tokenFactory.address,
    usdt.address,
    feeRecipient.account.address,
    platformTreasury.account.address,
  ]);
  await setLinkedLaunchpad(tokenFactory, owner, launchpad.address);
  await setEscrowTimeout(tokenFactory, owner, 7n * DAY);
  await setResaleWait(tokenFactory, owner, 7n * DAY);
  await launchpad.write.setPreparationTime([3600n], { account: owner.account });
  await launchpad.write.setLaunchpadDuration([DAY], { account: owner.account });

  const ratios = buildRatios({
    launchpadBp: 7000,
    liquidityBp: 1000,
    ownerBp: 2000,
    liquidityRecipient: platformTreasury.account.address,
    ownerVestingCliff: 0n,
    ownerVestingDuration: OWNER_VESTING_DURATION,
  });
  const issued = await issueTokenWithRatios({
    tokenFactory,
    business,
    publicClient,
    chainId,
    permitPrivateKey: TEST_PRIVATE_KEY,
    linkedLaunchpad: launchpad.address,
    name: "FrozenOwnerAllocation",
    symbol: "FOA",
    totalSupply: parseUnits("1000000", 18),
    ratios,
  });

  const token = await viem.getContractAt("ERC20V1", issued.tokenAddress);
  const vestingWallet = await viem.getContractAt("TokenVestingWallet", issued.vestingWallet);
  const fundedOwnerAllocation = (await token.read.balanceOf([issued.vestingWallet])) as bigint;
  assert.ok(fundedOwnerAllocation > 0n, "issuance funded the owner vesting wallet");
  assert.strictEqual(await vestingWallet.read.started(), false);
  assert.strictEqual(
    getAddress(await vestingWallet.read.factory()),
    getAddress(tokenFactory.address),
  );

  return {
    viem,
    owner,
    business,
    other,
    investor,
    usdt,
    tokenFactory,
    launchpad,
    token,
    vestingWallet,
    issued,
    fundedOwnerAllocation,
  };
}

describe("Audit-03: terminal launch paths start the funded owner vesting wallet", () => {
  it("permissionless expiry does NOT start owner vesting immediately, but TokenFactory.triggerOwnerVesting does once the resale-wait deadline elapses", async () => {
    const ctx = await bootstrap();
    const {
      owner,
      business,
      other,
      investor,
      usdt,
      tokenFactory,
      launchpad,
      token,
      vestingWallet,
      issued,
      fundedOwnerAllocation,
    } = ctx;

    await launchpad.write.createLaunchpad(
      [issued.tokenAddress, parseUnits("1", 18), business.account.address, usdt.address, 0n, 0n],
      { account: business.account },
    );

    await usdt.write.mint([investor.account.address, parseUnits("100", 18)], {
      account: owner.account,
    });
    await usdt.write.approve([launchpad.address, parseUnits("100", 18)], {
      account: investor.account,
    });
    const created = (await launchpad.read.getLaunchpadInfo([0n])) as {
      startTime: bigint;
      endTime: bigint;
    };
    await time.increaseTo(created.startTime);
    await launchpad.write.participate([0n, parseUnits("100", 18)], { account: investor.account });
    const active = (await launchpad.read.getLaunchpadInfo([0n])) as {
      endTime: bigint;
      saleAmount: bigint;
    };

    // Once the grace window closes, finalize is unavailable; only the terminal expiry path remains.
    await time.increaseTo(active.endTime + REFUND_GRACE + 1n);
    await assertions.revertWithCustomError(
      launchpad.write.finalizeLaunchpad([0n], { account: owner.account }),
      launchpad,
      "FinalizeWindowClosed",
    );

    // An unrelated external account executes the supported terminal failure path.
    await launchpad.write.expireLaunchpad([0n], { account: other.account });
    assert.strictEqual((await launchpad.read.getLaunchpadInfo([0n])).status, 5); // Cancelled

    // expiry does NOT start owner vesting anymore — only a SUCCESSFUL finalize does.
    assert.strictEqual(await launchpad.read.ownerVestingTrigger([0n]), false);
    assert.strictEqual(await vestingWallet.read.started(), false);

    // Not yet — the resale-wait deadline restoreEscrow just set hasn't elapsed.
    await assertions.revertWithCustomError(
      tokenFactory.write.triggerOwnerVesting([issued.tokenAddress], { account: other.account }),
      tokenFactory,
      "EscrowTimeoutNotElapsed",
    );

    // A business that abandons the sale must not freeze the allocation forever: ANYONE can
    // trigger it once the wait elapses (mirrors expireLaunchpad's own permissionless pattern).
    await time.increase(7n * DAY + 1n);
    await tokenFactory.write.triggerOwnerVesting([issued.tokenAddress], { account: other.account });
    assert.strictEqual(await vestingWallet.read.started(), true);

    // After the full duration the owner allocation is fully releasable to the business.
    await time.increase(OWNER_VESTING_DURATION + 1n);
    assert.strictEqual(await vestingWallet.read.releasable(), fundedOwnerAllocation);

    const before = (await token.read.balanceOf([business.account.address])) as bigint;
    await vestingWallet.write.release([], { account: business.account });
    const after = (await token.read.balanceOf([business.account.address])) as bigint;
    assert.strictEqual(after - before, fundedOwnerAllocation);
    assert.strictEqual(await token.read.balanceOf([issued.vestingWallet]), 0n);
  });

  it("owner cancellation of a Preparing launch does NOT start owner vesting immediately, but reclaimEscrow does once the resale-wait deadline elapses", async () => {
    const ctx = await bootstrap();
    const {
      owner,
      business,
      usdt,
      tokenFactory,
      launchpad,
      vestingWallet,
      issued,
      fundedOwnerAllocation,
      token,
    } = ctx;

    await launchpad.write.createLaunchpad(
      [issued.tokenAddress, parseUnits("1", 18), business.account.address, usdt.address, 0n, 0n],
      { account: business.account },
    );
    // Still Preparing (no participation, before startTime).
    assert.strictEqual((await launchpad.read.getLaunchpadInfo([0n])).status, 1);

    await launchpad.write.cancelLaunchpad([0n], { account: owner.account });
    assert.strictEqual((await launchpad.read.getLaunchpadInfo([0n])).status, 5); // Cancelled

    // cancellation does NOT start owner vesting anymore.
    assert.strictEqual(await launchpad.read.ownerVestingTrigger([0n]), false);
    assert.strictEqual(await vestingWallet.read.started(), false);

    // The cancelled sale's tokens are sitting in TokenFactory escrow again (resale-eligible
    // after the wait) — the business can reclaim them (and, as a side effect, start Owner
    // Vesting) once that same deadline elapses.
    await time.increase(7n * DAY + 1n);
    await tokenFactory.write.reclaimEscrow([issued.tokenAddress], { account: business.account });
    assert.strictEqual(await vestingWallet.read.started(), true);

    await time.increase(OWNER_VESTING_DURATION + 1n);
    assert.strictEqual(await vestingWallet.read.releasable(), fundedOwnerAllocation);
    await vestingWallet.write.release([], { account: business.account });
    assert.strictEqual(await token.read.balanceOf([issued.vestingWallet]), 0n);
  });

  it("escrow reclamation starts the owner vesting wallet directly via the factory", async () => {
    const ctx = await bootstrap();
    const { business, tokenFactory, vestingWallet, issued, fundedOwnerAllocation, token } = ctx;

    // No launchpad is ever created; wait out the escrow timeout and reclaim.
    await time.increase(7n * DAY + 1n);
    assert.strictEqual(await vestingWallet.read.started(), false);

    await tokenFactory.write.reclaimEscrow([issued.tokenAddress], { account: business.account });

    // FIX: reclaim started the funded owner vesting wallet (factory-authorized).
    assert.strictEqual(await vestingWallet.read.started(), true);

    await time.increase(OWNER_VESTING_DURATION + 1n);
    assert.strictEqual(await vestingWallet.read.releasable(), fundedOwnerAllocation);
    const before = (await token.read.balanceOf([business.account.address])) as bigint;
    await vestingWallet.write.release([], { account: business.account });
    const after = (await token.read.balanceOf([business.account.address])) as bigint;
    assert.strictEqual(after - before, fundedOwnerAllocation);
  });
});
