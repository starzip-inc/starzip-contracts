import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseUnits,
  getAddress,
  encodeFunctionData,
  zeroAddress,
  parseEventLogs,
  Address,
  Hex,
} from "viem";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import { privateKeyToAccount } from "viem/accounts";
import {
  deployTokenFactoryCore,
  configureDefaultAllocationGuides,
  setLinkedLaunchpad,
  setEscrowTimeout,
  setResaleWait,
  issueTokenWithRatios,
  buildRatios,
} from "./tokenFactoryHelpers.js";

// Test private key for permit signing (DO NOT USE IN PRODUCTION) — Hardhat account #0, same
// key used throughout LaunchpadV1.test.ts / TokenFactory.test.ts.
const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

interface LaunchpadInfo {
  businessAccount: Address;
  tokenAddress: Address;
  paymentToken: Address;
  saleAmount: bigint;
  soldAmount: bigint;
  tokenPrice: bigint;
  startTime: bigint;
  endTime: bigint;
  totalRaised: bigint;
  status: number;
}

/**
 * Regression coverage for the fund-holding security-fix batch: upgrade grace-period expiry,
 * ownership handover clearing a staged upgrade, renounceOwnership disabled, the vesting-wallet
 * legacy shim gated on $.factory, expireLaunchpad's extra event, escrowDeadline zeroed on
 * consumption, and executeFundSplitChange zeroing its pending fields. This file does not modify
 * any contract.
 *
 * The token-ownership-transfer grace-period expiry no longer applies: the platform's
 * propose/execute/cancel path to move an issued token's ownership was removed entirely
 * rather than kept and grace-bounded. See
 * TokenFactory.test.ts's "No platform seizure path for an issued token's ownership" describe
 * block for the replacement coverage.
 *
 * Every test below was verified RED against the pre-fix code by temporarily restoring the
 * affected file to its pre-fix (git HEAD) content, running this file, and confirming the
 * specific assertion failed for the expected reason — then restoring the fixed file byte-for-
 * byte. The one exception (the `cancelLaunchpad` half of the pair) is called out inline:
 * `cancelLaunchpad` was never touched by this diff, so there is no fix to revert for it; it is
 * included as a baseline/asymmetry guard, not as proof of a fix.
 *
 * Fixture setup mirrors LaunchpadV1.test.ts / TokenFactory.test.ts (real TokenFactory + real
 * LaunchpadV1 pair, GATE-0 3-bucket issuance flow) rather than importing their fixtures, since
 * neither file exports its fixture function.
 */
describe("Fund-holding remediation", function () {
  const TOKEN_PRICE = parseUnits("1", 18);
  const TOTAL_SUPPLY = parseUnits("1000000", 18);
  const UPGRADE_TIMELOCK_DELAY = 48n * 60n * 60n;
  const UPGRADE_GRACE_PERIOD = 7n * 24n * 60n * 60n;
  const CONFIG_DELAY = 2n * 24n * 60n * 60n; // both LaunchpadV1 and TokenFactory use 2 days
  const REFUND_GRACE = 14n * 24n * 60n * 60n;

  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, business, user1, user2, feeRecipient, platformTreasury] =
      await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);
    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);

    const {
      tokenFactory,
      erc20Beacon: beacon,
      vestingWalletBeacon,
    } = await deployTokenFactoryCore(
      viem,
      owner,
      platformTreasury.account.address,
      permitSigner.address,
    );
    await configureDefaultAllocationGuides(tokenFactory, owner);

    const launchpadImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
    const launchpadImpl = await viem.deployContract("LaunchpadV1", [], {
      libraries: { LaunchpadMathLib: launchpadImplMathLib.address },
    });
    const initData = encodeFunctionData({
      abi: launchpadImpl.abi,
      functionName: "initialize",
      args: [
        tokenFactory.address,
        usdt.address,
        feeRecipient.account.address,
        platformTreasury.account.address,
      ],
    });
    const proxy = await viem.deployContract("ERC1967Proxy", [launchpadImpl.address, initData]);
    const launchpad = await viem.getContractAt("LaunchpadV1", proxy.address);

    await setLinkedLaunchpad(tokenFactory, owner, launchpad.address);
    // Escrow timeout must be set before issuing a token with a LAUNCHPAD bucket (fail-closed).
    await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n);
    // resale-wait must be set before any cancel path can restore escrow.
    await setResaleWait(tokenFactory, owner, 7n * 24n * 60n * 60n);

    return {
      launchpad,
      tokenFactory,
      usdt,
      beacon,
      vestingWalletBeacon,
      owner,
      business,
      user1,
      user2,
      feeRecipient,
      platformTreasury,
      publicClient,
      chainId,
      viem,
    };
  }

  /** Issue a token (LAUNCHPAD-bucket-heavy) WITHOUT creating a launchpad for it. */
  async function issueTokenOnly(fixture: Awaited<ReturnType<typeof deployFixture>>) {
    const { tokenFactory, launchpad, business, platformTreasury, publicClient, chainId } = fixture;

    const ratios = buildRatios({
      launchpadBp: 9999,
      liquidityBp: 1,
      ownerBp: 0,
      liquidityRecipient: platformTreasury.account.address,
    });

    return issueTokenWithRatios({
      tokenFactory,
      business,
      publicClient,
      chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: launchpad.address,
      name: "TestToken",
      symbol: "TT",
      totalSupply: TOTAL_SUPPLY,
      contractURI: "https://example.com/metadata",
      ratios,
    });
  }

  /** Issue a token and immediately create a launchpad for it (Preparing state, id 0). */
  async function issueTokenAndCreateLaunchpad(fixture: Awaited<ReturnType<typeof deployFixture>>) {
    const { launchpad, business, usdt } = fixture;
    const { tokenAddress, vestingWallet } = await issueTokenOnly(fixture);

    await launchpad.write.createLaunchpad(
      [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
      { account: business.account },
    );

    return { tokenAddress, vestingWallet };
  }

  // =====================================================================
  // a staged UUPS upgrade expires UPGRADE_GRACE_PERIOD after upgradeReadyAt
  // =====================================================================
  describe("staged upgrade expires after UPGRADE_GRACE_PERIOD", function () {
    it("LaunchpadV1: upgrade still succeeds exactly at upgradeReadyAt + UPGRADE_GRACE_PERIOD", async function () {
      const { launchpad, owner, viem } = await loadFixture(deployFixture);
      const newImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const newImpl = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: newImplMathLib.address },
      });

      await launchpad.write.requestUpgrade([newImpl.address], { account: owner.account });
      const readyAt = (await launchpad.read.upgradeReadyAt()) as bigint;

      // `time.increaseTo(X)` itself mines a block AT timestamp X, so the upgrade tx that
      // follows lands one second later — target boundary-1 so the tx itself lands exactly on
      // upgradeReadyAt + UPGRADE_GRACE_PERIOD.
      await time.increaseTo(readyAt + UPGRADE_GRACE_PERIOD - 1n);
      await launchpad.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account });

      assert.strictEqual(await launchpad.read.pendingImplementation(), zeroAddress);
    });

    it("LaunchpadV1: upgrade reverts UpgradeExpired once past upgradeReadyAt + UPGRADE_GRACE_PERIOD", async function () {
      const { launchpad, owner, viem } = await loadFixture(deployFixture);
      const newImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const newImpl = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: newImplMathLib.address },
      });

      await launchpad.write.requestUpgrade([newImpl.address], { account: owner.account });
      const readyAt = (await launchpad.read.upgradeReadyAt()) as bigint;

      await time.increaseTo(readyAt + UPGRADE_GRACE_PERIOD + 1n);
      await assertions.revertWithCustomError(
        launchpad.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account }),
        launchpad,
        "UpgradeExpired",
      );
      // The failed attempt did not consume the staging — it just stays stale/unexecutable.
      assert.strictEqual(
        getAddress((await launchpad.read.pendingImplementation()) as Address),
        getAddress(newImpl.address),
      );
    });

    it("TokenFactory: upgrade still succeeds exactly at upgradeReadyAt + UPGRADE_GRACE_PERIOD", async function () {
      const { tokenFactory, owner, viem } = await loadFixture(deployFixture);
      const newImpl = await viem.deployContract("TokenFactory", []);

      await tokenFactory.write.requestUpgrade([newImpl.address], { account: owner.account });
      const readyAt = (await tokenFactory.read.upgradeReadyAt()) as bigint;

      // See the LaunchpadV1 boundary test above for why this targets boundary-1.
      await time.increaseTo(readyAt + UPGRADE_GRACE_PERIOD - 1n);
      await tokenFactory.write.upgradeToAndCall([newImpl.address, "0x"], {
        account: owner.account,
      });

      assert.strictEqual(await tokenFactory.read.pendingImplementation(), zeroAddress);
    });

    it("TokenFactory: upgrade reverts UpgradeExpired once past upgradeReadyAt + UPGRADE_GRACE_PERIOD", async function () {
      const { tokenFactory, owner, viem } = await loadFixture(deployFixture);
      const newImpl = await viem.deployContract("TokenFactory", []);

      await tokenFactory.write.requestUpgrade([newImpl.address], { account: owner.account });
      const readyAt = (await tokenFactory.read.upgradeReadyAt()) as bigint;

      await time.increaseTo(readyAt + UPGRADE_GRACE_PERIOD + 1n);
      await assertions.revertWithCustomError(
        tokenFactory.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account }),
        tokenFactory,
        "UpgradeExpired",
      );
    });
  });

  // =====================================================================
  // ownership handover clears a staged upgrade
  // =====================================================================
  describe("ownership handover clears a staged upgrade", function () {
    it("LaunchpadV1: acceptOwnership clears the staged upgrade, emits UpgradeCancelled, and the new owner cannot execute it", async function () {
      const { launchpad, owner, user1, viem, publicClient } = await loadFixture(deployFixture);
      const newImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const newImpl = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: newImplMathLib.address },
      });

      await launchpad.write.requestUpgrade([newImpl.address], { account: owner.account });
      await launchpad.write.transferOwnership([user1.account.address], { account: owner.account });

      // Nomination alone changes nothing — ownership has not moved yet.
      assert.strictEqual(
        getAddress((await launchpad.read.pendingImplementation()) as Address),
        getAddress(newImpl.address),
      );

      const hash = await launchpad.write.acceptOwnership([], { account: user1.account });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      const cancelled = parseEventLogs({
        abi: launchpad.abi,
        logs: receipt.logs,
        eventName: "UpgradeCancelled",
      });
      assert.strictEqual(cancelled.length, 1, "the upgrade drop must be observable");

      assert.strictEqual(await launchpad.read.pendingImplementation(), zeroAddress);
      assert.strictEqual((await launchpad.read.upgradeReadyAt()) as bigint, 0n);

      // The new owner inherited nothing — must re-stage under their own key.
      await time.increase(UPGRADE_TIMELOCK_DELAY + 1n);
      await assertions.revertWithCustomError(
        launchpad.write.upgradeToAndCall([newImpl.address, "0x"], { account: user1.account }),
        launchpad,
        "NoPendingUpgrade",
      );
    });

    it("TokenFactory: acceptOwnership clears the staged upgrade, emits UpgradeCancelled, and the new owner cannot execute it", async function () {
      const { tokenFactory, owner, user1, viem, publicClient } = await loadFixture(deployFixture);
      const newImpl = await viem.deployContract("TokenFactory", []);

      await tokenFactory.write.requestUpgrade([newImpl.address], { account: owner.account });
      await tokenFactory.write.transferOwnership([user1.account.address], {
        account: owner.account,
      });

      assert.strictEqual(
        getAddress((await tokenFactory.read.pendingImplementation()) as Address),
        getAddress(newImpl.address),
      );

      const hash = await tokenFactory.write.acceptOwnership([], { account: user1.account });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      const cancelled = parseEventLogs({
        abi: tokenFactory.abi,
        logs: receipt.logs,
        eventName: "UpgradeCancelled",
      });
      assert.strictEqual(cancelled.length, 1, "the upgrade drop must be observable");

      assert.strictEqual(await tokenFactory.read.pendingImplementation(), zeroAddress);
      assert.strictEqual((await tokenFactory.read.upgradeReadyAt()) as bigint, 0n);

      await time.increase(UPGRADE_TIMELOCK_DELAY + 1n);
      await assertions.revertWithCustomError(
        tokenFactory.write.upgradeToAndCall([newImpl.address, "0x"], { account: user1.account }),
        tokenFactory,
        "NoPendingUpgrade",
      );
    });
  });

  // =====================================================================
  // renounceOwnership is permanently disabled
  // =====================================================================
  describe("renounceOwnership is permanently disabled", function () {
    it("LaunchpadV1: renounceOwnership reverts RenounceDisabled; ownership still moves via the 2-step transfer", async function () {
      const { launchpad, owner, user1 } = await loadFixture(deployFixture);

      await assertions.revertWithCustomError(
        launchpad.write.renounceOwnership([], { account: owner.account }),
        launchpad,
        "RenounceDisabled",
      );
      assert.strictEqual(await launchpad.read.owner(), getAddress(owner.account.address));

      await launchpad.write.transferOwnership([user1.account.address], { account: owner.account });
      await launchpad.write.acceptOwnership([], { account: user1.account });
      assert.strictEqual(await launchpad.read.owner(), getAddress(user1.account.address));
    });

    it("TokenFactory: renounceOwnership reverts RenounceDisabled; ownership still moves via the 2-step transfer", async function () {
      const { tokenFactory, owner, user1 } = await loadFixture(deployFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.renounceOwnership([], { account: owner.account }),
        tokenFactory,
        "RenounceDisabled",
      );
      assert.strictEqual(await tokenFactory.read.owner(), getAddress(owner.account.address));

      await tokenFactory.write.transferOwnership([user1.account.address], {
        account: owner.account,
      });
      await tokenFactory.write.acceptOwnership([], { account: user1.account });
      assert.strictEqual(await tokenFactory.read.owner(), getAddress(user1.account.address));
    });
  });

  // =====================================================================
  // TokenVestingWallet.startVesting legacy shim gated on $.factory == address(0)
  // =====================================================================
  describe("TokenVestingWallet.startVesting legacy shim is gated on $.factory", function () {
    it("a caller matching the launchpad's ROTATED tokenFactory pointer, but not this wallet's own immutable factory, is rejected — while the real launchpad still activates the wallet normally", async function () {
      const fixture = await loadFixture(deployFixture);
      const { launchpad, owner, beacon, usdt, viem } = fixture;
      const { vestingWallet } = await issueTokenAndCreateLaunchpad(fixture);
      const wallet = await viem.getContractAt("TokenVestingWallet", vestingWallet);

      // Sanity: this (new) wallet's own factory binding is the real, original TokenFactory —
      // the condition gates on.
      assert.strictEqual(await wallet.read.factory(), getAddress(fixture.tokenFactory.address));
      assert.strictEqual(await wallet.read.started(), false);

      // Rotate LaunchpadV1's tokenFactory pointer away from the real factory, to an unrelated
      // deployed contract (`beacon` — any contract with code works; setTokenFactory requires
      // code.length > 0). This is the "owner rotates tokenFactory via the 2-day-timelocked
      // setTokenFactory -> executeTokenFactoryChange" precondition the task description calls
      // out as how the old hole was reached.
      await launchpad.write.setTokenFactory([beacon.address], { account: owner.account });
      await time.increase(CONFIG_DELAY);
      await launchpad.write.executeTokenFactoryChange([], { account: owner.account });
      assert.strictEqual(await launchpad.read.tokenFactory(), getAddress(beacon.address));

      // Impersonate the rotated-to address directly. Pre-fix, the shim resolved authority from
      // `ILaunchpadBinding(launchpad).tokenFactory()` (now `beacon`) instead of this wallet's
      // own `$.factory` binding, so a call from this exact address used to succeed.
      const testClient = await viem.getTestClient();
      await testClient.impersonateAccount({ address: beacon.address });
      await testClient.setBalance({ address: beacon.address, value: parseUnits("1", 18) });
      const attackerClient = await viem.getWalletClient(beacon.address);
      const walletAsAttacker = await viem.getContractAt("TokenVestingWallet", vestingWallet, {
        client: { wallet: attackerClient },
      });

      const ts = await time.latest();
      await assertions.revertWithCustomError(
        walletAsAttacker.write.startVesting([ts, 1000n]),
        wallet,
        "NotLaunchpad",
      );
      await testClient.stopImpersonatingAccount({ address: beacon.address });
      assert.strictEqual(await wallet.read.started(), false);

      // Legitimate caller still works: the REAL launchpad (msg.sender == $.launchpad) bypasses
      // this gate entirely (the shim only runs when the caller is neither $.launchpad nor
      // $.factory). (2026-08): cancelLaunchpad no longer triggers Owner Vesting at all
      // (only a SUCCESSFUL finalizeLaunchpad does now — see that change's own remediation), so
      // this proves the intended-caller path through `finalizeLaunchpad` instead — buying out
      // the full `saleAmount` (soldOut) lets it finalize immediately without waiting endTime.
      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await usdt.write.mint([fixture.user1.account.address, info.saleAmount], {
        account: owner.account,
      });
      await usdt.write.approve([launchpad.address, info.saleAmount], {
        account: fixture.user1.account,
      });
      // The earlier setTokenFactory rotation (2-day CONFIG_DELAY) already pushed chain time
      // past this launchpad's 12h-out startTime — only advance if it somehow hasn't.
      const nowTs = await time.latest();
      if (nowTs < info.startTime) await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, info.saleAmount], { account: fixture.user1.account });
      await launchpad.write.finalizeLaunchpad([0n], { account: owner.account });
      assert.strictEqual(await wallet.read.started(), true);
    });
  });

  // =====================================================================
  // expireLaunchpad is distinguishable from an owner's deliberate cancel
  // =====================================================================
  describe("expireLaunchpad marks its terminal state distinctly from an owner cancel", function () {
    it("expireLaunchpad emits BOTH LaunchpadCancelled and LaunchpadExpired", async function () {
      const fixture = await loadFixture(deployFixture);
      const { launchpad, publicClient } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.endTime + REFUND_GRACE + 1n);

      const hash = await launchpad.write.expireLaunchpad([0n]);
      const receipt = await publicClient.waitForTransactionReceipt({ hash });

      const cancelledLogs = parseEventLogs({
        abi: launchpad.abi,
        logs: receipt.logs,
        eventName: "LaunchpadCancelled",
      });
      const expiredLogs = parseEventLogs({
        abi: launchpad.abi,
        logs: receipt.logs,
        eventName: "LaunchpadExpired",
      });
      assert.strictEqual(cancelledLogs.length, 1, "LaunchpadCancelled must still fire");
      assert.strictEqual(expiredLogs.length, 1, "LaunchpadExpired must fire alongside it");
    });

    // NOTE (per the task's red/green standard): this half of the pair is NOT independently
    // red-provable against this diff — cancelLaunchpad's code was never touched by it, so there
    // is no fix to revert here. It is included to pin the intentional asymmetry (documented in
    // the contract's own comment) as a regression guard against a future change
    // accidentally copying the LaunchpadExpired emit into cancelLaunchpad too, not as proof of
    // this batch's fix. Reverting the whole file to pre-fix HEAD (see report) leaves this
    // specific test green, exactly as expected, confirming the claim empirically.
    it("cancelLaunchpad emits ONLY LaunchpadCancelled, never LaunchpadExpired (baseline asymmetry guard, not a fix regression test)", async function () {
      const fixture = await loadFixture(deployFixture);
      const { launchpad, owner, publicClient } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);
      // Still Preparing (cancelLaunchpad's precondition) — no time travel needed.

      const hash = await launchpad.write.cancelLaunchpad([0n], { account: owner.account });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });

      const cancelledLogs = parseEventLogs({
        abi: launchpad.abi,
        logs: receipt.logs,
        eventName: "LaunchpadCancelled",
      });
      const expiredLogs = parseEventLogs({
        abi: launchpad.abi,
        logs: receipt.logs,
        eventName: "LaunchpadExpired",
      });
      assert.strictEqual(cancelledLogs.length, 1);
      assert.strictEqual(expiredLogs.length, 0);
    });
  });

  // =====================================================================
  // escrow consumption fully zeroes the escrow record (not just amount/consumed)
  // =====================================================================
  describe("escrow consumption zeroes escrowDeadline too", function () {
    it("releaseEscrow (triggered by createLaunchpad) zeroes escrowDeadline", async function () {
      const fixture = await loadFixture(deployFixture);
      const { tokenFactory } = fixture;
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(fixture);

      const [amount, deadline, consumed] = (await tokenFactory.read.getEscrowInfo([
        tokenAddress,
      ])) as [bigint, bigint, boolean];
      assert.strictEqual(amount, 0n);
      assert.strictEqual(consumed, true);
      assert.strictEqual(deadline, 0n);
    });

    it("reclaimEscrow zeroes escrowDeadline", async function () {
      const fixture = await loadFixture(deployFixture);
      const { tokenFactory, owner, business } = fixture;
      await setEscrowTimeout(tokenFactory, owner, 3600n); // MIN_ESCROW_TIMEOUT (1 hour)
      const { tokenAddress } = await issueTokenOnly(fixture);

      await time.increase(3601n);
      await tokenFactory.write.reclaimEscrow([tokenAddress], { account: business.account });

      const [amount, deadline, consumed] = (await tokenFactory.read.getEscrowInfo([
        tokenAddress,
      ])) as [bigint, bigint, boolean];
      assert.strictEqual(amount, 0n);
      assert.strictEqual(consumed, true);
      assert.strictEqual(deadline, 0n);
    });
  });

  // =====================================================================
  // executeFundSplitChange zeroes the pending fields, not just the time sentinel
  // =====================================================================
  describe("executeFundSplitChange zeroes pendingImmediateRate/pendingLiquidityRate/pendingVestingRate", function () {
    it("all three pending fields read back zero after execute (only fundSplitChangeTime was cleared before this fix)", async function () {
      const { launchpad, owner } = await loadFixture(deployFixture);

      await launchpad.write.proposeFundSplitChange([4000n, 1000n, 5000n], {
        account: owner.account,
      });
      await time.increase(CONFIG_DELAY);
      await launchpad.write.executeFundSplitChange([], { account: owner.account });

      assert.strictEqual(await launchpad.read.immediateRate(), 4000n);
      assert.strictEqual(await launchpad.read.liquidityRate(), 1000n);
      assert.strictEqual(await launchpad.read.vestingRate(), 5000n);

      assert.strictEqual((await launchpad.read.pendingImmediateRate()) as bigint, 0n);
      assert.strictEqual((await launchpad.read.pendingLiquidityRate()) as bigint, 0n);
      assert.strictEqual((await launchpad.read.pendingVestingRate()) as bigint, 0n);
    });
  });
});
