/**
 * SSA-01 / SSA-18 remediation tests.
 *
 * SSA-01: sponsorship is revoked synchronously with `requestUpgrade` (staging), not only at
 * `_authorizeUpgrade` (execution, up to 48h later). See StarzipWallet.sol's `requestUpgrade`.
 *
 * SSA-18: `execute`/`executeBatch` revert `OwnerSetChanged()` if the owner set changed since this
 * op's own `validateUserOp` ran. See StarzipWallet.sol's `OWNER_EPOCH_TRANSIENT_SLOT` /
 * `_requireUnchangedOwnerEpoch`.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseEther,
  zeroAddress,
  parseEventLogs,
  encodeFunctionData,
  getAddress,
  hexToBytes,
  type Hex,
  type Address,
} from "viem";
import { loadFixture, getConnection, assertions } from "./helpers.js";
import {
  passkeyPubCoords,
  webauthnSignature,
  buildUserOp,
  encodePasskeyOwner,
  encodeSignatureWrapper,
  paymasterAndDataFor,
  signPaymasterData,
  SPONSOR_SIGNER,
} from "./aa-helpers.js";

const PASSKEY_PRIV_A = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const PASSKEY_PRIV_B = hexToBytes(
  "0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464" as Hex,
);
const { x: PK_X_A, y: PK_Y_A } = passkeyPubCoords(PASSKEY_PRIV_A);
const { x: PK_X_B, y: PK_Y_B } = passkeyPubCoords(PASSKEY_PRIV_B);

function opSucceeded(receipt: any, entryPointAbi: any, index = 0): boolean {
  const ev = parseEventLogs({ abi: entryPointAbi, logs: receipt.logs, eventName: "UserOperationEvent" });
  return ev.length > index && (ev[index] as any).args.success === true;
}

// ================================================================================================
// SSA-01: sponsorship locked at STAGING time
// ================================================================================================
describe("SSA-01: sponsorship revoked at requestUpgrade (staging), not only at execution", function () {
  async function fixture() {
    const { viem } = await getConnection();
    const [deployer, ownerWallet, policyManagerWallet, beneficiary] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    const paymaster = await viem.deployContract(
      "VerifyingPaymaster",
      [entryPoint.address, policyManagerWallet.account.address, zeroAddress, SPONSOR_SIGNER],
      { client: { wallet: ownerWallet } },
    );
    const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, paymaster.address]);

    const firstOwner = encodePasskeyOwner(PK_X_A, PK_Y_A);
    const salt = 424242n;
    await factory.write.createAccount([[firstOwner], salt], { account: deployer.account });
    const walletAddr = (await factory.read.getAddress([[firstOwner], salt])) as Address;
    const account = await viem.getContractAt("StarzipWallet", walletAddr);
    await deployer.sendTransaction({ to: walletAddr, value: parseEther("2") });

    async function ownerWrite(fn: string, args: unknown[] = []): Promise<void> {
      const hash = await (paymaster.write as any)[fn](args, { account: ownerWallet.account });
      await publicClient.waitForTransactionReceipt({ hash });
    }
    async function pmWrite(fn: string, args: unknown[] = []): Promise<void> {
      const hash = await (paymaster.write as any)[fn](args, { account: policyManagerWallet.account });
      await publicClient.waitForTransactionReceipt({ hash });
    }

    await ownerWrite("setMaxSponsoredOpCost", [parseEther("1")]);
    // 200 gwei — must exceed buildUserOp's default maxFeePerGas (100 gwei), which sponsoredNoopOp
    // below does not override (see VerifyingPaymaster.test.ts's own fixture: it caps at 1 gwei
    // ONLY because it explicitly overrides gasFees to match — this fixture does not).
    await ownerWrite("setMaxSponsoredFeePerGas", [200_000_000_000n]);
    await ownerWrite("setMaxSponsoredPreVerificationGas", [1_000_000n]);
    await ownerWrite("setGlobalDailyCapCeiling", [parseEther("1")]);
    await ownerWrite("setGlobalDailyBudget", [parseEther("1")]);
    await pmWrite("setSponsored", [walletAddr, true]);
    await pmWrite("setDailyCap", [walletAddr, parseEther("1")]);
    // sponsorPersonal bypasses the business-target allowlist entirely — irrelevant to what SSA-01
    // is testing (the sponsorship LATCH itself), so the simplest sponsorable shape is used.
    await ownerWrite("setSponsorPersonal", [walletAddr, true]);
    await ownerWrite("unpause");

    const depositHash = await deployer.sendTransaction({
      to: paymaster.address,
      value: parseEther("10"),
      data: "0xd0e30db0" as Hex, // deposit()
    });
    await publicClient.waitForTransactionReceipt({ hash: depositHash });

    const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address, zeroAddress]);

    return {
      viem,
      publicClient,
      entryPoint,
      paymaster,
      account,
      walletAddr,
      deployer,
      beneficiary,
      newImpl,
    };
  }

  async function sponsoredNoopOp(ctx: any, nonce: bigint) {
    const callData = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "execute",
      args: [ctx.walletAddr, 0n, "0x"],
    });
    const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
    // postOpGas must be within [MIN_POSTOP_GAS, MAX_POSTOP_GAS] = [90_000, 150_000].
    userOp.paymasterAndData = paymasterAndDataFor(ctx.paymaster.address, 200_000n, 100_000n);
    const chainId = BigInt(await ctx.publicClient.getChainId());
    userOp.paymasterAndData = await signPaymasterData({ userOp, chainId });
    const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
    userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV_A));
    return userOp;
  }

  async function requestUpgradeOp(ctx: any, nonce: bigint) {
    const inner = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "requestUpgrade",
      args: [ctx.newImpl.address],
    });
    const callData = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "execute",
      args: [ctx.walletAddr, 0n, inner],
    });
    const userOp = buildUserOp(ctx.walletAddr, nonce, callData); // self-funded, no paymaster
    const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
    userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV_A));
    return userOp;
  }

  it("BASELINE: sponsoredNoopOp succeeds on a fresh wallet with no upgrade ever staged", async function () {
    const ctx = await loadFixture(fixture);
    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const op = await sponsoredNoopOp(ctx, n0);
    const hash = await ctx.entryPoint.write.handleOps([[op], ctx.beneficiary.account.address], {
      account: ctx.deployer.account,
    });
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
    assert.ok(opSucceeded(receipt, ctx.entryPoint.abi), "baseline sponsored op must succeed");
  });

  it("REGRESSION: a sponsored op submitted AFTER requestUpgrade has been mined is hard-declined, sponsored flips to false", async function () {
    const ctx = await loadFixture(fixture);
    const before = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
    assert.strictEqual(before.sponsored, true, "precondition: wallet starts sponsored");
    const depositBefore = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;

    // TX1: requestUpgrade alone, mined on its own.
    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const op0 = await requestUpgradeOp(ctx, n0);
    const h0 = await ctx.entryPoint.write.handleOps([[op0], ctx.beneficiary.account.address], {
      account: ctx.deployer.account,
    });
    const r0 = await ctx.publicClient.waitForTransactionReceipt({ hash: h0 });
    assert.ok(opSucceeded(r0, ctx.entryPoint.abi), "requestUpgrade itself must succeed");

    const afterStage = (await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any;
    assert.strictEqual(
      afterStage.sponsored,
      false,
      "STATE, not reason: sponsorship must already be false immediately after requestUpgrade lands, " +
        "before the 48h timelock and before any upgradeToAndCall",
    );

    // TX2 (later, separate transaction): the same wallet's own sponsored op must now be declined.
    const n1 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const op1 = await sponsoredNoopOp(ctx, n1);
    await assert.rejects(
      ctx.entryPoint.write.handleOps([[op1], ctx.beneficiary.account.address], {
        account: ctx.deployer.account,
      }),
      "a sponsored op for a wallet with a staged upgrade must hard-decline, not merely warn",
    );

    const depositAfter = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;
    assert.strictEqual(
      depositAfter,
      depositBefore,
      "the paymaster deposit must be untouched by the declined op",
    );
    assert.strictEqual(
      ((await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any).sponsored,
      false,
      "still false after the decline",
    );
  });

  it("setSponsored(wallet, true) is rejected while an upgrade is staged; cancelUpgrade then lets it succeed", async function () {
    const ctx = await loadFixture(fixture);
    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const op0 = await requestUpgradeOp(ctx, n0);
    const h0 = await ctx.entryPoint.write.handleOps([[op0], ctx.beneficiary.account.address], {
      account: ctx.deployer.account,
    });
    await ctx.publicClient.waitForTransactionReceipt({ hash: h0 });
    assert.notStrictEqual(
      await ctx.account.read.pendingImplementation(),
      zeroAddress,
      "precondition: the upgrade is actually staged",
    );

    const policyManager = (await ctx.viem.getWalletClients())[2];
    await assert.rejects(
      ctx.paymaster.write.setSponsored([ctx.walletAddr, true], { account: policyManager.account }),
      /WalletUpgradePending/,
      "setSponsored(wallet, true) must be refused while an upgrade is staged, even after the " +
        "timelock matures — this is exactly the manual-recovery step CertiK's revived attack " +
        "bundle relies on: requestUpgrade already staged -> setSponsored(true) -> " +
        "upgradeToAndCall -> sponsored ops against the malicious implementation",
    );
    assert.strictEqual(
      ((await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any).sponsored,
      false,
      "sponsorship must remain false — the rejected setSponsored call must not have partially applied",
    );

    // Now cancel the staged upgrade — pendingImplementation clears, and the SAME setSponsored
    // call that was just refused now succeeds normally.
    const cancelInner = encodeFunctionData({ abi: ctx.account.abi, functionName: "cancelUpgrade" });
    const cancelCallData = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "execute",
      args: [ctx.walletAddr, 0n, cancelInner],
    });
    const n1 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const cancelOp = buildUserOp(ctx.walletAddr, n1, cancelCallData);
    const cancelHash = (await ctx.entryPoint.read.getUserOpHash([cancelOp])) as Hex;
    cancelOp.signature = encodeSignatureWrapper(0n, webauthnSignature(cancelHash, PASSKEY_PRIV_A));
    const hCancel = await ctx.entryPoint.write.handleOps(
      [[cancelOp], ctx.beneficiary.account.address],
      { account: ctx.deployer.account },
    );
    await ctx.publicClient.waitForTransactionReceipt({ hash: hCancel });
    assert.strictEqual(await ctx.account.read.pendingImplementation(), zeroAddress);

    const hRestore = await ctx.paymaster.write.setSponsored([ctx.walletAddr, true], {
      account: policyManager.account,
    });
    await ctx.publicClient.waitForTransactionReceipt({ hash: hRestore });
    assert.strictEqual(
      ((await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any).sponsored,
      true,
      "after cancelUpgrade clears pendingImplementation, setSponsored(true) restores sponsorship normally",
    );
  });

  it("STRUCTURAL LIMIT: op0=requestUpgrade + op1=sponsored op in the SAME bundle both still succeed — EntryPoint validates the whole bundle before executing any of it, so only the cross-transaction window is closed", async function () {
    const ctx = await loadFixture(fixture);
    const depositBefore = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;

    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const op0 = await requestUpgradeOp(ctx, n0);
    const op1 = await sponsoredNoopOp(ctx, n0 + 1n);

    const hash = await ctx.entryPoint.write.handleOps(
      [[op0, op1], ctx.beneficiary.account.address],
      { account: ctx.deployer.account },
    );
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
    assert.ok(opSucceeded(receipt, ctx.entryPoint.abi, 0), "op0 (requestUpgrade) succeeds");
    assert.ok(
      opSucceeded(receipt, ctx.entryPoint.abi, 1),
      "op1 (sponsored) ALSO succeeds in the same bundle — EntryPoint._iterateValidationPhase " +
        "validates every op before emitting BeforeExecution and running any of them, so op1's " +
        "paymaster validation reads `sponsored == true` regardless of what op0 does later in the " +
        "SAME transaction's execution loop. This is a structural property of handleOps, not a gap " +
        "in this fix specifically.",
    );
    const depositAfter = (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;
    assert.ok(depositAfter < depositBefore, "the paymaster deposit was in fact spent on op1");
    // But the state is correctly flipped for the NEXT transaction, closing the real window.
    assert.strictEqual(
      ((await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any).sponsored,
      false,
    );
  });

  it("cancelUpgrade does NOT restore sponsorship on its own — setSponsored(true) is required (no on-chain self-restore path)", async function () {
    const ctx = await loadFixture(fixture);
    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const op0 = await requestUpgradeOp(ctx, n0);
    let hash = await ctx.entryPoint.write.handleOps([[op0], ctx.beneficiary.account.address], {
      account: ctx.deployer.account,
    });
    await ctx.publicClient.waitForTransactionReceipt({ hash });
    assert.strictEqual(
      ((await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any).sponsored,
      false,
    );

    // cancelUpgrade, self-funded (also not sponsorable — same forbidden-self-selector reasoning
    // as requestUpgrade), and check the restoration-signal event.
    const cancelInner = encodeFunctionData({ abi: ctx.account.abi, functionName: "cancelUpgrade" });
    const cancelCallData = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "execute",
      args: [ctx.walletAddr, 0n, cancelInner],
    });
    const n1 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const cancelOp = buildUserOp(ctx.walletAddr, n1, cancelCallData);
    const cancelHash = (await ctx.entryPoint.read.getUserOpHash([cancelOp])) as Hex;
    cancelOp.signature = encodeSignatureWrapper(0n, webauthnSignature(cancelHash, PASSKEY_PRIV_A));
    hash = await ctx.entryPoint.write.handleOps([[cancelOp], ctx.beneficiary.account.address], {
      account: ctx.deployer.account,
    });
    const cancelReceipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
    assert.ok(opSucceeded(cancelReceipt, ctx.entryPoint.abi), "cancelUpgrade must succeed");

    const restoreEv = parseEventLogs({
      abi: ctx.account.abi,
      logs: cancelReceipt.logs,
      eventName: "SponsorshipRestoreRequested",
    })[0] as any;
    assert.ok(restoreEv, "cancelUpgrade must emit SponsorshipRestoreRequested as the restore signal");
    assert.strictEqual(getAddress(restoreEv.args.wallet), getAddress(ctx.walletAddr));

    assert.strictEqual(
      ((await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any).sponsored,
      false,
      "cancelUpgrade alone must NOT flip sponsored back to true — there is no on-chain auto-restore",
    );

    // Only after the backend calls setSponsored(true) does a sponsored op work again.
    const hash2 = await ctx.paymaster.write.setSponsored([ctx.walletAddr, true], {
      account: (await ctx.viem.getWalletClients())[2].account,
    });
    await ctx.publicClient.waitForTransactionReceipt({ hash: hash2 });
    assert.strictEqual(
      ((await ctx.paymaster.read.getPolicy([ctx.walletAddr])) as any).sponsored,
      true,
    );
  });
});

// ================================================================================================
// SSA-01 follow-up: requestUpgrade's OWN revoke call is fail-closed, not merely logged
// ================================================================================================
// Forces `ok == false` on `requestUpgrade`'s revoke call via an always-reverting paymaster stub,
// and pins that the whole staging op reverts (`RevokeSponsorshipFailed()`) rather than merely
// logging the failure.
describe("SSA-01 follow-up: requestUpgrade's revoke call is fail-closed (RevokeSponsorshipFailed)", function () {
  async function fixture() {
    const { viem } = await getConnection();
    const [deployer, beneficiary] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    // Always reverts on revokeSponsorshipOnUpgrade() — forces `ok == false` on requestUpgrade's
    // primary revoke call deterministically, the same effect a tightly-limited callGasLimit /
    // EIP-150 starve would have on a REAL paymaster's inner call.
    const revertingPaymaster = await viem.deployContract("RevertingPaymasterStub", []);
    const factory = await viem.deployContract("StarzipWalletFactory", [
      entryPoint.address,
      revertingPaymaster.address,
    ]);
    const firstOwner = encodePasskeyOwner(PK_X_A, PK_Y_A);
    const salt = 909090n;
    await factory.write.createAccount([[firstOwner], salt], { account: deployer.account });
    const walletAddr = (await factory.read.getAddress([[firstOwner], salt])) as Address;
    const account = await viem.getContractAt("StarzipWallet", walletAddr);
    await deployer.sendTransaction({ to: walletAddr, value: parseEther("2") });
    const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address, zeroAddress]);

    return {
      viem,
      publicClient,
      entryPoint,
      account,
      walletAddr,
      deployer,
      beneficiary,
      newImpl,
      revertingPaymaster,
    };
  }

  async function requestUpgradeOp(ctx: any, nonce: bigint) {
    const inner = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "requestUpgrade",
      args: [ctx.newImpl.address],
    });
    const callData = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "execute",
      args: [ctx.walletAddr, 0n, inner],
    });
    const userOp = buildUserOp(ctx.walletAddr, nonce, callData); // self-funded, no paymaster
    const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
    userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV_A));
    return userOp;
  }

  it("precondition: this wallet names the always-reverting stub as its trusted paymaster", async function () {
    const ctx = await loadFixture(fixture);
    assert.strictEqual(
      getAddress(await ctx.account.read.trustedPaymaster()),
      getAddress(ctx.revertingPaymaster.address),
    );
  });

  it("requestUpgrade against an always-reverting paymaster reverts the whole staging op — no pendingImplementation is ever set", async function () {
    const ctx = await loadFixture(fixture);
    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const op = await requestUpgradeOp(ctx, n0);

    const hash = await ctx.entryPoint.write.handleOps([[op], ctx.beneficiary.account.address], {
      account: ctx.deployer.account,
    });
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });

    // Matches the SSA-18 execution-phase-revert pattern: the FAILING op's own revert does not
    // revert the surrounding handleOps transaction — EntryPoint just marks that op as failed.
    assert.strictEqual(
      receipt.status,
      "success",
      "the bundle transaction itself is not reverted",
    );
    assert.strictEqual(
      opSucceeded(receipt, ctx.entryPoint.abi),
      false,
      "requestUpgrade's op must FAIL now that a failed revoke is fail-closed, not merely logged",
    );

    const revertEv = parseEventLogs({
      abi: ctx.entryPoint.abi,
      logs: receipt.logs,
      eventName: "UserOperationRevertReason",
    })[0] as any;
    assert.ok(revertEv, "EntryPoint must emit UserOperationRevertReason for the failed op");

    // Fail-closed: the revert unwinds every state change and event, so a failed revoke leaves no
    // trace of a staged upgrade.
    assert.strictEqual(
      await ctx.account.read.pendingImplementation(),
      zeroAddress,
      "no upgrade must ever be staged when the primary revoke call failed",
    );
    assert.strictEqual(
      (await ctx.account.read.upgradeRequestedAt()) as bigint,
      0n,
      "upgradeRequestedAt must also be rolled back — the whole op reverted",
    );

    // Mutation evidence: with `if (!ok) revert RevokeSponsorshipFailed();` removed, this test
    // observed opSucceeded === true, pendingImplementation === newImpl.address,
    // upgradeRequestedAt !== 0n, and a PaymasterUpgradeNotification(revertingPaymaster, false).
  });

  it("cancelUpgrade after a successfully-staged upgrade continues to work (no regression to the ordinary path)", async function () {
    const ctx = await loadFixture(fixture);
    // Use a paymaster that succeeds so this test can reach a real staged upgrade, proving the
    // fail-closed change above does not affect the ordinary (paymaster healthy) path at all.
    const { viem } = await getConnection();
    const [deployer2] = await viem.getWalletClients();
    const healthyFactory = await viem.deployContract("StarzipWalletFactory", [
      ctx.entryPoint.address,
      zeroAddress, // trustedPaymaster() == address(0): silent no-op path, not fail-closed
    ]);
    const owner = encodePasskeyOwner(PK_X_A, PK_Y_A);
    await healthyFactory.write.createAccount([[owner], 111222n], { account: deployer2.account });
    const walletAddr = (await healthyFactory.read.getAddress([[owner], 111222n])) as Address;
    const account = await viem.getContractAt("StarzipWallet", walletAddr);
    await deployer2.sendTransaction({ to: walletAddr, value: parseEther("2") });

    const inner = encodeFunctionData({
      abi: account.abi,
      functionName: "requestUpgrade",
      args: [ctx.newImpl.address],
    });
    const callData = encodeFunctionData({
      abi: account.abi,
      functionName: "execute",
      args: [walletAddr, 0n, inner],
    });
    const n0 = (await ctx.entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
    const userOp = buildUserOp(walletAddr, n0, callData);
    const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
    userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV_A));
    const hash = await ctx.entryPoint.write.handleOps(
      [[userOp], ctx.beneficiary.account.address],
      { account: ctx.deployer.account },
    );
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
    assert.ok(
      opSucceeded(receipt, ctx.entryPoint.abi),
      "trustedPaymaster() == address(0) must remain a silent no-op, not a new revert path",
    );
    assert.strictEqual(await account.read.pendingImplementation(), getAddress(ctx.newImpl.address));
  });
});

// ================================================================================================
// SSA-18: owner epoch, execution-time check
// ================================================================================================
describe("SSA-18: OwnerSetChanged() blocks same-bundle execution after an owner removal has run", function () {
  async function fixture() {
    const { viem } = await getConnection();
    const [deployer, beneficiary, recipient] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, zeroAddress]);

    const ownerA = encodePasskeyOwner(PK_X_A, PK_Y_A); // index 0
    const ownerB = encodePasskeyOwner(PK_X_B, PK_Y_B); // index 1
    const salt = 777777n;
    await factory.write.createAccount([[ownerA, ownerB], salt], { account: deployer.account });
    const walletAddr = (await factory.read.getAddress([[ownerA, ownerB], salt])) as Address;
    const account = await viem.getContractAt("StarzipWallet", walletAddr);
    await deployer.sendTransaction({ to: walletAddr, value: parseEther("2") });

    return { viem, publicClient, entryPoint, account, walletAddr, deployer, beneficiary, recipient, ownerA };
  }

  async function removeAOp(ctx: any, nonce: bigint) {
    const inner = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "removeOwnerAtIndex",
      args: [0n, ctx.ownerA],
    });
    const callData = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "execute",
      args: [ctx.walletAddr, 0n, inner],
    });
    const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
    const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
    // Signed by B (ownerIndex=1) — B removes A.
    userOp.signature = encodeSignatureWrapper(1n, webauthnSignature(userOpHash, PASSKEY_PRIV_B));
    return userOp;
  }

  async function transferOp(ctx: any, nonce: bigint, value: bigint) {
    const callData = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "execute",
      args: [ctx.recipient.account.address, value, "0x"],
    });
    const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
    const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
    // Signed by A (ownerIndex=0) — A's own transfer, validated while A was still an owner.
    userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV_A));
    return userOp;
  }

  it("REGRESSION: in handleOps([opRemoveA(B-signed), opTransfer(A-signed)]), A's transfer reverts OwnerSetChanged; the bundle itself is not reverted", async function () {
    const ctx = await loadFixture(fixture);
    assert.strictEqual((await ctx.account.read.ownerCount()) as bigint, 2n, "precondition: 2 owners");
    const recipientBalBefore = (await ctx.publicClient.getBalance({
      address: ctx.recipient.account.address,
    })) as bigint;

    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const opRemoveA = await removeAOp(ctx, n0);
    const opTransfer = await transferOp(ctx, n0 + 1n, parseEther("0.1"));

    const hash = await ctx.entryPoint.write.handleOps(
      [[opRemoveA, opTransfer], ctx.beneficiary.account.address],
      { account: ctx.deployer.account },
    );
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });

    assert.ok(opSucceeded(receipt, ctx.entryPoint.abi, 0), "opRemoveA must succeed");
    assert.strictEqual((await ctx.account.read.ownerCount()) as bigint, 1n, "A is in fact removed");
    assert.strictEqual(
      opSucceeded(receipt, ctx.entryPoint.abi, 1),
      false,
      "opTransfer must FAIL (not silently move funds) once A has been removed earlier in this bundle",
    );

    const revertEv = parseEventLogs({
      abi: ctx.entryPoint.abi,
      logs: receipt.logs,
      eventName: "UserOperationRevertReason",
    })[0] as any;
    assert.ok(revertEv, "EntryPoint must emit UserOperationRevertReason for opTransfer");
    // OwnerSetChanged() selector — 4-byte custom error, no args.
    const OWNER_SET_CHANGED_SELECTOR = (ctx.account.abi as any[]).find(
      (e: any) => e.type === "error" && e.name === "OwnerSetChanged",
    );
    assert.ok(OWNER_SET_CHANGED_SELECTOR, "ABI must declare OwnerSetChanged()");

    const recipientBalAfter = (await ctx.publicClient.getBalance({
      address: ctx.recipient.account.address,
    })) as bigint;
    assert.strictEqual(
      recipientBalAfter,
      recipientBalBefore,
      "no asset must have moved — opTransfer's execution reverted",
    );

    // The bundle transaction itself is NOT reverted (opRemoveA's effects are permanent).
    assert.strictEqual(
      await ctx.publicClient.getTransactionReceipt({ hash }).then((r) => r.status),
      "success",
    );
  });

  it("REGRESSION: a 2-op bundle with NO owner change still succeeds end to end", async function () {
    const ctx = await loadFixture(fixture);
    const recipientBalBefore = (await ctx.publicClient.getBalance({
      address: ctx.recipient.account.address,
    })) as bigint;

    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const opTransfer1 = await transferOp(ctx, n0, parseEther("0.05"));
    const opTransfer2 = await transferOp(ctx, n0 + 1n, parseEther("0.05"));

    const hash = await ctx.entryPoint.write.handleOps(
      [[opTransfer1, opTransfer2], ctx.beneficiary.account.address],
      { account: ctx.deployer.account },
    );
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });

    assert.ok(opSucceeded(receipt, ctx.entryPoint.abi, 0), "first transfer must succeed");
    assert.ok(opSucceeded(receipt, ctx.entryPoint.abi, 1), "second transfer must ALSO succeed — no owner change happened, so the epoch check must be a no-op here");

    const recipientBalAfter = (await ctx.publicClient.getBalance({
      address: ctx.recipient.account.address,
    })) as bigint;
    assert.strictEqual(
      recipientBalAfter - recipientBalBefore,
      parseEther("0.1"),
      "both transfers must have actually moved funds",
    );
  });

  it("a single-op bundle (validateUserOp always precedes execute for that op) is unaffected by the epoch check", async function () {
    const ctx = await loadFixture(fixture);
    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const op = await transferOp(ctx, n0, parseEther("0.01"));
    const hash = await ctx.entryPoint.write.handleOps([[op], ctx.beneficiary.account.address], {
      account: ctx.deployer.account,
    });
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
    assert.ok(opSucceeded(receipt, ctx.entryPoint.abi), "ordinary single op must succeed");
  });
});
