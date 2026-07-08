/**
 * StarzipWallet v1 (social-recovery, self-owned) tests.
 * Admin actions are `onlySelf`: privileged ops must arrive as passkey-signed userOps routed
 * EntryPoint -> execute -> address(this). No EOA owner authority (owner is an inert sentinel).
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseEther,
  getAddress,
  hexToBytes,
  encodeFunctionData,
  parseEventLogs,
  zeroAddress,
  type Hex,
  type Address,
} from "viem";
import { loadFixture, getConnection, time, assertions } from "./helpers.js";
import { passkeyPubCoords, webauthnSignature, buildUserOp, execViaPasskey } from "./aa-helpers.js";

// Deterministic P-256 test keys (NOT for production). Scalars < n.
const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const NEW_PASSKEY_PRIV = hexToBytes(
  "0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464" as Hex,
);
const { x: PK_X, y: PK_Y } = passkeyPubCoords(PASSKEY_PRIV);
const { x: NEW_PK_X, y: NEW_PK_Y } = passkeyPubCoords(NEW_PASSKEY_PRIV);

// Off-curve, non-zero point: a valid X paired with a MISMATCHED valid Y is not on the P256
// curve (only ±Y(X) are), yet neither coordinate is zero — so it slips past an either-zero check
// but must be rejected by the on-curve P256.isValidPublicKey guard.
const OFFCURVE_X = NEW_PK_X;
const OFFCURVE_Y = PK_Y;

// Inert owner sentinel (must be a non-zero deterministic value; 0xdEaD recommended).
const OWNER_SENTINEL = "0x000000000000000000000000000000000000dEaD" as Address;
const ZERO_BYTES32 = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;
const SALT = 100n;
const UPGRADE_TIMELOCK = 48n * 60n * 60n;
const ERC1967_IMPL_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as Hex;

async function deployFixture() {
  const { viem } = await getConnection();
  const [deployer, beneficiary, stranger] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();

  const entryPoint = await viem.deployContract("TestEntryPoint", []);
  const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address]);

  await factory.write.createAccount([PK_X, PK_Y, OWNER_SENTINEL, SALT], {
    account: deployer.account,
  });
  const walletAddr = (await factory.read.getAddress([PK_X, PK_Y, OWNER_SENTINEL, SALT])) as Address;
  const account = await viem.getContractAt("StarzipWallet", walletAddr);

  // prefund so the wallet can pay EntryPoint prefund
  await deployer.sendTransaction({ to: walletAddr, value: parseEther("2") });

  return {
    viem,
    publicClient,
    entryPoint,
    factory,
    account,
    walletAddr,
    deployer,
    beneficiary,
    stranger,
  };
}

function opSucceeded(receipt: any, entryPointAbi: any): boolean {
  const ev = parseEventLogs({
    abi: entryPointAbi,
    logs: receipt.logs,
    eventName: "UserOperationEvent",
  });
  return ev.length > 0 && (ev[0] as any).args.success === true;
}

// Route an inner self-call (e.g. changePasskey) through the passkey + EntryPoint.
async function selfCall(ctx: any, innerCalldata: Hex, priv: Uint8Array = PASSKEY_PRIV) {
  return execViaPasskey({
    publicClient: ctx.publicClient,
    entryPoint: ctx.entryPoint,
    walletAbi: ctx.account.abi,
    walletAddr: ctx.walletAddr,
    target: ctx.walletAddr,
    innerCalldata,
    passkeyPriv: priv,
    submitter: ctx.deployer,
    beneficiary: ctx.beneficiary.account.address,
  });
}

describe("StarzipWallet v1 (social-recovery, self-owned)", function () {
  // ============ Initialization ============
  describe("Initialization", function () {
    it("stores passkey coords and inert owner sentinel", async function () {
      const { account } = await loadFixture(deployFixture);
      assert.strictEqual(await account.read.publicKeyX(), PK_X);
      assert.strictEqual(await account.read.publicKeyY(), PK_Y);
      assert.strictEqual(
        getAddress((await account.read.owner()) as string),
        getAddress(OWNER_SENTINEL),
      );
    });

    it("reserves social-recovery storage at zero (recovery disabled)", async function () {
      const { account } = await loadFixture(deployFixture);
      assert.strictEqual(await account.read.guardianSetRoot(), ZERO_BYTES32);
      assert.strictEqual((await account.read.guardianThreshold()) as bigint, 0n);
      assert.strictEqual((await account.read.recoveryRequestedAt()) as bigint, 0n);
      assert.strictEqual((await account.read.recoveryNonce()) as bigint, 0n);
      assert.strictEqual(await account.read.pendingGuardianSetRoot(), ZERO_BYTES32);
    });

    it("rejects zero owner sentinel (must be non-zero, deployable)", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);
      await assertions.revert(
        factory.write.createAccount([PK_X, PK_Y, zeroAddress, 999n], { account: deployer.account }),
      );
    });

    it("rejects (0,0) passkey at init", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);
      await assertions.revert(
        factory.write.createAccount([ZERO_BYTES32, ZERO_BYTES32, OWNER_SENTINEL, 998n], {
          account: deployer.account,
        }),
      );
    });

    it("rejects an EITHER-zero (on-axis) passkey coordinate at init: (x,0) and (0,y) (L-3)", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        factory.write.createAccount([PK_X, ZERO_BYTES32, OWNER_SENTINEL, 996n], {
          account: deployer.account,
        }),
        null,
        "InvalidPublicKey",
      );
      await assertions.revertWithCustomError(
        factory.write.createAccount([ZERO_BYTES32, PK_Y, OWNER_SENTINEL, 997n], {
          account: deployer.account,
        }),
        null,
        "InvalidPublicKey",
      );
    });

    it("rejects an OFF-CURVE (non-zero) passkey at init", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);
      // Both coords non-zero, but (NEW_PK_X, PK_Y) is not a point on the P256 curve.
      await assertions.revertWithCustomError(
        factory.write.createAccount([OFFCURVE_X, OFFCURVE_Y, OWNER_SENTINEL, 995n], {
          account: deployer.account,
        }),
        null,
        "InvalidPublicKey",
      );
    });

    it("rejects reinitialization", async function () {
      const { account, deployer } = await loadFixture(deployFixture);
      await assertions.revert(
        account.write.initialize([PK_X, PK_Y, OWNER_SENTINEL], { account: deployer.account }),
      );
    });
  });

  // ============ onlySelf enforcement (no EOA authority) ============
  describe("onlySelf enforcement", function () {
    it("rejects changePasskey from any EOA (incl. owner sentinel holder is irrelevant)", async function () {
      const { account, deployer, stranger } = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        account.write.changePasskey([NEW_PK_X, NEW_PK_Y], { account: deployer.account }),
        account,
        "OnlySelf",
      );
      await assertions.revertWithCustomError(
        account.write.changePasskey([NEW_PK_X, NEW_PK_Y], { account: stranger.account }),
        account,
        "OnlySelf",
      );
    });

    it("rejects requestUpgrade / cancelUpgrade from EOA", async function () {
      const { account, deployer } = await loadFixture(deployFixture);
      const impl = "0x1111111111111111111111111111111111111111" as Address;
      await assertions.revertWithCustomError(
        account.write.requestUpgrade([impl], { account: deployer.account }),
        account,
        "OnlySelf",
      );
      await assertions.revertWithCustomError(
        account.write.cancelUpgrade([], { account: deployer.account }),
        account,
        "OnlySelf",
      );
    });

    it("rejects execute / executeBatch from non-entrypoint", async function () {
      const { account, deployer } = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        account.write.execute([deployer.account.address, 0n, "0x"], { account: deployer.account }),
        account,
        "OnlyEntryPoint",
      );
      await assertions.revertWithCustomError(
        account.write.executeBatch([[deployer.account.address], [0n], ["0x"]], {
          account: deployer.account,
        }),
        account,
        "OnlyEntryPoint",
      );
    });
  });

  // ============ Tier 1: passkey signature gating ============
  describe("Passkey signature validation", function () {
    it("rejects a userOp signed by the WRONG passkey (AA24)", async function () {
      const { publicClient, entryPoint, account, walletAddr, deployer, beneficiary } =
        await loadFixture(deployFixture);
      // no-op callData: execute(self, 0, "0x") -> hits receive()
      const callData = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [walletAddr, 0n, "0x"],
      });
      const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(walletAddr, nonce, callData);
      const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
      // sign with the NEW (wrong) passkey, but the wallet stores PK_X/PK_Y
      userOp.signature = webauthnSignature(userOpHash, NEW_PASSKEY_PRIV);
      await assert.rejects(
        entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
          account: deployer.account,
        }),
      );
    });

    it("accepts a userOp signed by the CORRECT passkey", async function () {
      const ctx = await loadFixture(deployFixture);
      // no-op self-call succeeds (receive)
      const receipt = await selfCall(ctx, "0x");
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi), "userOp should succeed");
    });
  });

  // ============ Tier 2: passkey self-rotation ============
  describe("Self passkey rotation (Tier 2)", function () {
    it("rotates passkey via passkey self-call, and the NEW passkey can then sign", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account } = ctx;

      const rotateCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "changePasskey",
        args: [NEW_PK_X, NEW_PK_Y],
      });
      const receipt = await selfCall(ctx, rotateCalldata, PASSKEY_PRIV);
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi), "rotation op should succeed");
      assert.strictEqual(await account.read.publicKeyX(), NEW_PK_X);
      assert.strictEqual(await account.read.publicKeyY(), NEW_PK_Y);

      // The NEW passkey now controls the wallet: a no-op signed by it must succeed.
      const receipt2 = await selfCall(ctx, "0x", NEW_PASSKEY_PRIV);
      assert.ok(opSucceeded(receipt2, ctx.entryPoint.abi), "new passkey should control the wallet");

      // The OLD passkey no longer controls it.
      const noopCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [ctx.walletAddr, 0n, "0x"],
      });
      const nonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(ctx.walletAddr, nonce, noopCalldata);
      const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
      userOp.signature = webauthnSignature(userOpHash, PASSKEY_PRIV); // old key
      await assert.rejects(
        ctx.entryPoint.write.handleOps([[userOp], ctx.beneficiary.account.address], {
          account: ctx.deployer.account,
        }),
      );
    });

    it("self-call changePasskey to (0,0) fails the op (passkey unchanged)", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account } = ctx;
      const badCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "changePasskey",
        args: [ZERO_BYTES32, ZERO_BYTES32],
      });
      const receipt = await selfCall(ctx, badCalldata, PASSKEY_PRIV);
      assert.strictEqual(
        opSucceeded(receipt, ctx.entryPoint.abi),
        false,
        "(0,0) rotation must fail",
      );
      assert.strictEqual(await account.read.publicKeyX(), PK_X); // unchanged
    });

    it("self-call changePasskey to an EITHER-zero coordinate fails the op: (x,0) and (0,y) (L-3)", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account } = ctx;

      const xZeroY = encodeFunctionData({
        abi: account.abi,
        functionName: "changePasskey",
        args: [NEW_PK_X, ZERO_BYTES32],
      });
      const r1 = await selfCall(ctx, xZeroY, PASSKEY_PRIV);
      assert.strictEqual(opSucceeded(r1, ctx.entryPoint.abi), false, "(x,0) rotation must fail");
      assert.strictEqual(await account.read.publicKeyX(), PK_X); // unchanged

      const zeroXY = encodeFunctionData({
        abi: account.abi,
        functionName: "changePasskey",
        args: [ZERO_BYTES32, NEW_PK_Y],
      });
      const r2 = await selfCall(ctx, zeroXY, PASSKEY_PRIV);
      assert.strictEqual(opSucceeded(r2, ctx.entryPoint.abi), false, "(0,y) rotation must fail");
      assert.strictEqual(await account.read.publicKeyY(), PK_Y); // unchanged
    });

    it("self-call changePasskey to an OFF-CURVE (non-zero) point fails the op", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account } = ctx;
      const offCurve = encodeFunctionData({
        abi: account.abi,
        functionName: "changePasskey",
        args: [OFFCURVE_X, OFFCURVE_Y], // both non-zero, but not on the P256 curve
      });
      const r = await selfCall(ctx, offCurve, PASSKEY_PRIV);
      assert.strictEqual(
        opSucceeded(r, ctx.entryPoint.abi),
        false,
        "off-curve rotation must fail (would brick the wallet)",
      );
      assert.strictEqual(await account.read.publicKeyX(), PK_X); // unchanged
      assert.strictEqual(await account.read.publicKeyY(), PK_Y); // unchanged
    });
  });

  // ============ Upgrade: passkey self-call + timelock ============
  describe("Upgrade (passkey self-call + 48h timelock)", function () {
    it("request -> timelock -> upgrade succeeds via passkey self-call", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, walletAddr, publicClient, viem, entryPoint } = ctx;

      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address]);

      // request upgrade (self-call)
      const reqCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "requestUpgrade",
        args: [newImpl.address],
      });
      const r1 = await selfCall(ctx, reqCalldata);
      assert.ok(opSucceeded(r1, entryPoint.abi));
      assert.strictEqual(
        getAddress((await account.read.pendingImplementation()) as string),
        getAddress(newImpl.address),
      );

      // too early -> upgrade op fails (timelock)
      const upCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "upgradeToAndCall",
        args: [newImpl.address, "0x"],
      });
      const rEarly = await selfCall(ctx, upCalldata);
      assert.strictEqual(
        opSucceeded(rEarly, entryPoint.abi),
        false,
        "upgrade before timelock must fail",
      );

      // advance past timelock, then upgrade
      await time.increase(UPGRADE_TIMELOCK + 1n);
      const r2 = await selfCall(ctx, upCalldata);
      assert.ok(opSucceeded(r2, entryPoint.abi), "upgrade after timelock should succeed");

      const raw = (await publicClient.getStorageAt({
        address: walletAddr,
        slot: ERC1967_IMPL_SLOT,
      })) as Hex;
      const implAddr = getAddress(("0x" + raw.slice(26)) as Hex);
      assert.strictEqual(implAddr, getAddress(newImpl.address));
    });

    it("cancelUpgrade via passkey self-call clears pending", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address]);

      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
      );
      assert.notStrictEqual(await account.read.pendingImplementation(), zeroAddress);

      const r = await selfCall(
        ctx,
        encodeFunctionData({ abi: account.abi, functionName: "cancelUpgrade", args: [] }),
      );
      assert.ok(opSucceeded(r, entryPoint.abi));
      assert.strictEqual(await account.read.pendingImplementation(), zeroAddress);
    });
  });

  // ============ Receive ETH ============
  describe("Receive ETH", function () {
    it("receives ETH", async function () {
      const { account, deployer, publicClient, walletAddr } = await loadFixture(deployFixture);
      const balBefore = await publicClient.getBalance({ address: walletAddr });
      const hash = await deployer.sendTransaction({ to: walletAddr, value: parseEther("1") });
      await publicClient.waitForTransactionReceipt({ hash });
      const balAfter = await publicClient.getBalance({ address: walletAddr });
      assert.strictEqual(balAfter - balBefore, parseEther("1"));
    });
  });

  // ============ Token receiver ============
  describe("Token receiver (ERC721 / ERC1155 holder)", function () {
    it("receives an ERC721 via _safeMint", async function () {
      const { viem, walletAddr, deployer } = await loadFixture(deployFixture);
      const nft = await viem.deployContract("MockERC721", []);
      // _safeMint runs the onERC721Received acceptance check on the contract recipient.
      await nft.write.safeMint([walletAddr, 1n], { account: deployer.account });
      assert.strictEqual(
        getAddress((await nft.read.ownerOf([1n])) as string),
        getAddress(walletAddr),
      );
    });

    it("receives an ERC721 via safeTransferFrom", async function () {
      const { viem, walletAddr, deployer } = await loadFixture(deployFixture);
      const nft = await viem.deployContract("MockERC721", []);
      await nft.write.mint([deployer.account.address, 2n], { account: deployer.account }); // unsafe seed
      await nft.write.safeTransferFrom([deployer.account.address, walletAddr, 2n], {
        account: deployer.account,
      });
      assert.strictEqual(
        getAddress((await nft.read.ownerOf([2n])) as string),
        getAddress(walletAddr),
      );
    });

    it("control: _safeMint to a no-receiver contract (factory) reverts — proves the check is real", async function () {
      const { viem, factory, deployer } = await loadFixture(deployFixture);
      const nft = await viem.deployContract("MockERC721", []);
      await assertions.revert(
        nft.write.safeMint([factory.address, 3n], { account: deployer.account }),
      );
    });

    it("receives ERC1155 single and batch mints", async function () {
      const { viem, walletAddr, deployer } = await loadFixture(deployFixture);
      const multi = await viem.deployContract("MockERC1155", []);
      await multi.write.mint([walletAddr, 1n, 100n], { account: deployer.account });
      assert.strictEqual((await multi.read.balanceOf([walletAddr, 1n])) as bigint, 100n);

      await multi.write.mintBatch([walletAddr, [2n, 3n], [5n, 7n]], { account: deployer.account });
      assert.strictEqual((await multi.read.balanceOf([walletAddr, 2n])) as bigint, 5n);
      assert.strictEqual((await multi.read.balanceOf([walletAddr, 3n])) as bigint, 7n);
    });

    it("advertises IERC1155Receiver + ERC165 via supportsInterface", async function () {
      const { account } = await loadFixture(deployFixture);
      assert.strictEqual(await account.read.supportsInterface(["0x4e2312e0"]), true); // IERC1155Receiver
      assert.strictEqual(await account.read.supportsInterface(["0x01ffc9a7"]), true); // IERC165
      assert.strictEqual(await account.read.supportsInterface(["0xffffffff"]), false);
    });
  });

  // ============ Review hardening (triple-review P1/P2) ============
  describe("Review hardening", function () {
    const R1 = "0x00000000000000000000000000000000000000A1" as Address;
    const R2 = "0x00000000000000000000000000000000000000A2" as Address;

    async function submitBatch(ctx: any, dests: Address[], values: bigint[], funcs: Hex[]) {
      const callData = encodeFunctionData({
        abi: ctx.account.abi,
        functionName: "executeBatch",
        args: [dests, values, funcs],
      });
      const nonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
      const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
      userOp.signature = webauthnSignature(userOpHash, PASSKEY_PRIV);
      const hash = await ctx.entryPoint.write.handleOps(
        [[userOp], ctx.beneficiary.account.address],
        { account: ctx.deployer.account },
      );
      return ctx.publicClient.waitForTransactionReceipt({ hash });
    }

    it("upgrade timelock boundary: fails at T-1, succeeds exactly at T", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address]);

      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
      );
      const requestedAt = (await account.read.upgradeRequestedAt()) as bigint;
      const upCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "upgradeToAndCall",
        args: [newImpl.address, "0x"],
      });

      // pin the handleOps block timestamp exactly to T-1 (must fail)
      await time.setNextBlockTimestamp(requestedAt + UPGRADE_TIMELOCK - 1n);
      const rEarly = await selfCall(ctx, upCalldata);
      assert.strictEqual(opSucceeded(rEarly, entryPoint.abi), false, "must fail at T-1");

      // pin the handleOps block timestamp exactly to T (must succeed)
      await time.setNextBlockTimestamp(requestedAt + UPGRADE_TIMELOCK);
      const rOk = await selfCall(ctx, upCalldata);
      assert.ok(opSucceeded(rOk, entryPoint.abi), "must succeed exactly at T");
    });

    it("emits PasskeyRotated(old,new) and UpgradeRequested(readyAt = now + 48h)", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;

      const rotR = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "changePasskey",
          args: [NEW_PK_X, NEW_PK_Y],
        }),
        PASSKEY_PRIV,
      );
      const pr = parseEventLogs({
        abi: account.abi,
        logs: rotR.logs,
        eventName: "PasskeyRotated",
      })[0] as any;
      assert.strictEqual(pr.args.oldX, PK_X);
      assert.strictEqual(pr.args.newX, NEW_PK_X);
      assert.strictEqual(pr.args.newY, NEW_PK_Y);

      // request upgrade with the NEW key; assert readyAt == upgradeRequestedAt + 48h
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address]);
      const reqR = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
        NEW_PASSKEY_PRIV,
      );
      const ur = parseEventLogs({
        abi: account.abi,
        logs: reqR.logs,
        eventName: "UpgradeRequested",
      })[0] as any;
      const requestedAt = (await account.read.upgradeRequestedAt()) as bigint;
      assert.strictEqual(ur.args.readyAt as bigint, requestedAt + UPGRADE_TIMELOCK);
    });

    it("changePasskey cancels a pending upgrade (P1-2 incident-response)", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address]);

      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
      );
      assert.notStrictEqual(await account.read.pendingImplementation(), zeroAddress);

      const rotR = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "changePasskey",
          args: [NEW_PK_X, NEW_PK_Y],
        }),
        PASSKEY_PRIV,
      );
      assert.ok(opSucceeded(rotR, entryPoint.abi));
      assert.strictEqual(
        await account.read.pendingImplementation(),
        zeroAddress,
        "rotation must clear pending upgrade",
      );
      assert.strictEqual((await account.read.upgradeRequestedAt()) as bigint, 0n);
      const cancelled = parseEventLogs({
        abi: account.abi,
        logs: rotR.logs,
        eventName: "UpgradeCancelled",
      });
      assert.strictEqual(
        cancelled.length,
        1,
        "UpgradeCancelled must be emitted on rotation-clears-upgrade",
      );
    });

    it("requestUpgrade to a non-contract (EOA) fails the op (P2-A)", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint, stranger } = ctx;
      const r = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [stranger.account.address],
        }),
      );
      assert.strictEqual(opSucceeded(r, entryPoint.abi), false, "EOA impl must be rejected");
      assert.strictEqual(await account.read.pendingImplementation(), zeroAddress);
    });

    it("implementation contract cannot be initialized (disabled initializers)", async function () {
      const { factory, viem, deployer } = await loadFixture(deployFixture);
      const implAddr = (await factory.read.accountImplementation()) as Address;
      const impl = await viem.getContractAt("StarzipWallet", implAddr);
      await assertions.revert(
        impl.write.initialize([PK_X, PK_Y, OWNER_SENTINEL], { account: deployer.account }),
      );
    });

    it("owner sentinel and guardian/recovery slots stay untouched across a full admin lifecycle", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address]);

      // rotate, request+cancel upgrade, then request+execute upgrade
      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "changePasskey",
          args: [NEW_PK_X, NEW_PK_Y],
        }),
        PASSKEY_PRIV,
      );
      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
        NEW_PASSKEY_PRIV,
      );
      await selfCall(
        ctx,
        encodeFunctionData({ abi: account.abi, functionName: "cancelUpgrade", args: [] }),
        NEW_PASSKEY_PRIV,
      );

      // owner sentinel never changed
      assert.strictEqual(
        getAddress((await account.read.owner()) as string),
        getAddress(OWNER_SENTINEL),
      );
      // guardian/recovery storage never written by any v1 path
      assert.strictEqual(await account.read.guardianSetRoot(), ZERO_BYTES32);
      assert.strictEqual((await account.read.guardianThreshold()) as bigint, 0n);
      assert.strictEqual((await account.read.recoveryRequestedAt()) as bigint, 0n);
      assert.strictEqual((await account.read.recoveryNonce()) as bigint, 0n);
      assert.strictEqual(await account.read.pendingGuardianSetRoot(), ZERO_BYTES32);
      assert.strictEqual((await account.read.guardianChangeRequestedAt()) as bigint, 0n);
    });

    it("executeBatch happy path: multiple inner calls + BatchExecuted", async function () {
      const ctx = await loadFixture(deployFixture);
      const r = await submitBatch(ctx, [R1, R2], [1n, 1n], ["0x", "0x"]);
      assert.ok(opSucceeded(r, ctx.entryPoint.abi));
      assert.strictEqual(await ctx.publicClient.getBalance({ address: R1 }), 1n);
      assert.strictEqual(await ctx.publicClient.getBalance({ address: R2 }), 1n);
      const be = parseEventLogs({
        abi: ctx.account.abi,
        logs: r.logs,
        eventName: "BatchExecuted",
      })[0] as any;
      assert.strictEqual(be.args.count as bigint, 2n);
    });

    it("executeBatch is atomic: a failing inner call rolls back the whole batch", async function () {
      const ctx = await loadFixture(deployFixture);
      // second call sends ETH to the factory (no receive) -> empty revert -> ExecutionFailed
      const r = await submitBatch(ctx, [R1, ctx.factory.address], [1n, 1n], ["0x", "0x"]);
      assert.strictEqual(
        opSucceeded(r, ctx.entryPoint.abi),
        false,
        "batch with a failing call must fail",
      );
      assert.strictEqual(
        await ctx.publicClient.getBalance({ address: R1 }),
        0n,
        "first transfer must be rolled back",
      );
    });

    it("executeBatch rejects oversized (>32) and empty/mismatched arrays", async function () {
      const ctx = await loadFixture(deployFixture);
      const big = Array.from({ length: 33 }, () => R1) as Address[];
      const bigVals = Array.from({ length: 33 }, () => 0n);
      const bigFuncs = Array.from({ length: 33 }, () => "0x" as Hex);
      const rBig = await submitBatch(ctx, big, bigVals, bigFuncs);
      assert.strictEqual(opSucceeded(rBig, ctx.entryPoint.abi), false, "oversized batch must fail");

      const rEmpty = await submitBatch(ctx, [], [], []);
      assert.strictEqual(opSucceeded(rEmpty, ctx.entryPoint.abi), false, "empty batch must fail");
    });
  });
});
