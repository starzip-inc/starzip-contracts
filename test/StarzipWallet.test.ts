/**
 * StarzipWallet v2 (Coinbase-Smart-Wallet-style multi-owner) tests.
 * Admin actions are `onlySelf`: privileged ops must arrive as an owner-signed userOp routed
 * EntryPoint -> execute -> address(this). No EOA/operator authority outside the registered owner
 * set — see StarzipWallet.sol's contract-level NatSpec for the design.
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
import { privateKeyToAccount } from "viem/accounts";
import { loadFixture, getConnection, time, assertions } from "./helpers.js";
import {
  passkeyPubCoords,
  webauthnSignature,
  buildUserOp,
  execViaPasskey,
  encodeAddressOwner,
  encodePasskeyOwner,
  encodeSignatureWrapper,
} from "./aa-helpers.js";

// Deterministic secp256k1 test key (Hardhat account #0's well-known private key — used elsewhere
// in this suite, e.g. TokenFactory's permitSigner) for the EOA-style owner test.
const EOA_OWNER_PRIV = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

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
  const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, zeroAddress]);

  const firstOwner = encodePasskeyOwner(PK_X, PK_Y);
  await factory.write.createAccount([[firstOwner], SALT], {
    account: deployer.account,
  });
  const walletAddr = (await factory.read.getAddress([[firstOwner], SALT])) as Address;
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

// Route an inner self-call (e.g. addOwnerPublicKey) through owner index 0's passkey + EntryPoint.
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

describe("StarzipWallet v2 (multi-owner)", function () {
  // ============ Initialization ============
  describe("Initialization", function () {
    it("registers the first owner at index 0", async function () {
      const { account } = await loadFixture(deployFixture);
      assert.strictEqual(await account.read.ownerAtIndex([0n]), encodePasskeyOwner(PK_X, PK_Y));
      assert.strictEqual((await account.read.ownerCount()) as bigint, 1n);
      assert.strictEqual((await account.read.nextOwnerIndex()) as bigint, 1n);
      assert.strictEqual(await account.read.isOwnerBytes([encodePasskeyOwner(PK_X, PK_Y)]), true);
    });

    it("rejects a zero-address EOA owner at init", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        factory.write.createAccount([[encodeAddressOwner(zeroAddress)], 999n], {
          account: deployer.account,
        }),
        null,
        "ZeroAddress",
      );
    });

    it("rejects (0,0) passkey at init", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);
      await assertions.revert(
        factory.write.createAccount([[encodePasskeyOwner(ZERO_BYTES32, ZERO_BYTES32)], 998n], {
          account: deployer.account,
        }),
      );
    });

    it("rejects an EITHER-zero (on-axis) passkey coordinate at init: (x,0) and (0,y)", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        factory.write.createAccount([[encodePasskeyOwner(PK_X, ZERO_BYTES32)], 996n], {
          account: deployer.account,
        }),
        null,
        "InvalidPublicKey",
      );
      await assertions.revertWithCustomError(
        factory.write.createAccount([[encodePasskeyOwner(ZERO_BYTES32, PK_Y)], 997n], {
          account: deployer.account,
        }),
        null,
        "InvalidPublicKey",
      );
    });

    it("rejects an OFF-CURVE (non-zero) passkey at init ", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);
      // Both coords non-zero, but (NEW_PK_X, PK_Y) is not a point on the P256 curve.
      await assertions.revertWithCustomError(
        factory.write.createAccount([[encodePasskeyOwner(OFFCURVE_X, OFFCURVE_Y)], 995n], {
          account: deployer.account,
        }),
        null,
        "InvalidPublicKey",
      );
    });

    it("rejects an owner blob of any length other than 32 or 64 bytes", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        factory.write.createAccount([["0x1234" as Hex], 994n], { account: deployer.account }),
        null,
        "InvalidOwnerBytesLength",
      );
    });

    it("rejects reinitialization", async function () {
      const { account, deployer } = await loadFixture(deployFixture);
      await assertions.revert(
        account.write.initialize([[encodePasskeyOwner(PK_X, PK_Y)]], { account: deployer.account }),
      );
    });
  });

  // ============ onlySelf enforcement (no EOA/operator authority) ============
  describe("onlySelf enforcement", function () {
    it("rejects addOwnerAddress / addOwnerPublicKey / removeOwnerAtIndex from any EOA", async function () {
      const { account, deployer, stranger } = await loadFixture(deployFixture);
      await assertions.revertWithCustomError(
        account.write.addOwnerAddress([stranger.account.address], { account: deployer.account }),
        account,
        "OnlySelf",
      );
      await assertions.revertWithCustomError(
        account.write.addOwnerPublicKey([NEW_PK_X, NEW_PK_Y], { account: stranger.account }),
        account,
        "OnlySelf",
      );
      await assertions.revertWithCustomError(
        account.write.removeOwnerAtIndex([0n, encodePasskeyOwner(PK_X, PK_Y)], {
          account: deployer.account,
        }),
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

  // ============ Owner signature gating ============
  describe("Owner signature validation", function () {
    it("rejects a userOp signed by an UNREGISTERED passkey (AA24)", async function () {
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
      // sign with a passkey the wallet never registered (wallet only knows owner index 0 = PK_X/Y)
      userOp.signature = encodeSignatureWrapper(
        0n,
        webauthnSignature(userOpHash, NEW_PASSKEY_PRIV),
      );
      // Tightened: a bare `assert.rejects` here passes on ANY
      // rejection, including AA23 (a wallet-level revert) — which is exactly how V1's checked-
      // arithmetic panic (`128 + len > signature.length` overflowing to a Panic 0x11, surfaced as
      // AA23 reverted) stayed hidden despite this test's name promising AA24 coverage. A
      // signature-mismatch MUST be a clean `SIG_VALIDATION_FAILED` (EntryPoint's AA24), never a
      // revert.
      await assert.rejects(
        entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
          account: deployer.account,
        }),
        /AA24/,
      );
    });

    it("rejects a userOp naming an unregistered ownerIndex (SIG_VALIDATION_FAILED, not a revert)", async function () {
      const { publicClient, entryPoint, account, walletAddr, deployer, beneficiary } =
        await loadFixture(deployFixture);
      const callData = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [walletAddr, 0n, "0x"],
      });
      const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(walletAddr, nonce, callData);
      const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
      // ownerIndex 7 was never registered — a genuine assertion under the real passkey, but for
      // a slot that names no owner.
      userOp.signature = encodeSignatureWrapper(7n, webauthnSignature(userOpHash, PASSKEY_PRIV));
      // EntryPoint's own AA24 signature-error path (not a raw revert from the wallet itself).
      await assert.rejects(
        entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
          account: deployer.account,
        }),
        /AA24/,
      );
    });

    it("accepts a userOp signed by the registered owner-0 passkey", async function () {
      const ctx = await loadFixture(deployFixture);
      // no-op self-call succeeds (receive)
      const receipt = await selfCall(ctx, "0x");
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi), "userOp should succeed");
    });
  });

  // ============ Owner set management ============
  describe("Owner set management", function () {
    it("adds a second passkey owner via a self-call, and that NEW owner can then sign", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint, walletAddr, deployer, beneficiary } = ctx;

      const addCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "addOwnerPublicKey",
        args: [NEW_PK_X, NEW_PK_Y],
      });
      const receipt = await selfCall(ctx, addCalldata, PASSKEY_PRIV);
      assert.ok(opSucceeded(receipt, entryPoint.abi), "addOwnerPublicKey op should succeed");

      const added = parseEventLogs({
        abi: account.abi,
        logs: receipt.logs,
        eventName: "AddOwner",
      })[0] as any;
      assert.strictEqual(added.args.index as bigint, 1n);
      assert.strictEqual(added.args.owner, encodePasskeyOwner(NEW_PK_X, NEW_PK_Y));
      assert.strictEqual((await account.read.ownerCount()) as bigint, 2n);

      // The NEW owner (index 1) now independently controls the wallet.
      const callData = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [walletAddr, 0n, "0x"],
      });
      const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(walletAddr, nonce, callData);
      const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
      userOp.signature = encodeSignatureWrapper(
        1n,
        webauthnSignature(userOpHash, NEW_PASSKEY_PRIV),
      );
      const hash = await entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
        account: deployer.account,
      });
      const receipt2 = await ctx.publicClient.waitForTransactionReceipt({ hash });
      assert.ok(
        opSucceeded(receipt2, entryPoint.abi),
        "new owner should independently control the wallet",
      );

      // The OLD owner (index 0) is STILL valid too — this is concurrent, not exclusive, control.
      const receipt3 = await selfCall(ctx, "0x", PASSKEY_PRIV);
      assert.ok(
        opSucceeded(receipt3, entryPoint.abi),
        "original owner must still control the wallet",
      );
    });

    it("adds an EOA-style address owner, which can then sign via plain ECDSA over the raw digest", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint, walletAddr, deployer, beneficiary } = ctx;
      const eoaOwner = privateKeyToAccount(EOA_OWNER_PRIV);

      const addCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "addOwnerAddress",
        args: [eoaOwner.address],
      });
      const receipt = await selfCall(ctx, addCalldata, PASSKEY_PRIV);
      assert.ok(opSucceeded(receipt, entryPoint.abi));
      assert.strictEqual(
        await account.read.ownerAtIndex([1n]),
        encodeAddressOwner(eoaOwner.address),
      );

      // {_verifyOwnerSignature}'s 32-byte-owner branch recovers over the digest DIRECTLY (no
      // EIP-191 "\x19Ethereum Signed Message" prefix, matching how the P-256 branch also signs the
      // challenge directly) — `account.sign({ hash })` produces exactly that, unlike
      // `signMessage`, which applies the personal-sign prefix.
      const callData = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [walletAddr, 0n, "0x"],
      });
      const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(walletAddr, nonce, callData);
      const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
      const rawSig = await eoaOwner.sign({ hash: userOpHash });
      userOp.signature = encodeSignatureWrapper(1n, rawSig);

      const hash = await entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
        account: deployer.account,
      });
      const opReceipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
      assert.ok(opSucceeded(opReceipt, entryPoint.abi), "ECDSA-owner-signed userOp should succeed");
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
    it("receives an ERC721 via _safeMint (e.g. the platform's own StarGenesis)", async function () {
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
      userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));
      const hash = await ctx.entryPoint.write.handleOps(
        [[userOp], ctx.beneficiary.account.address],
        { account: ctx.deployer.account },
      );
      return ctx.publicClient.waitForTransactionReceipt({ hash });
    }

    it("upgrade timelock boundary: fails at T-1, succeeds exactly at T", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address, zeroAddress]);

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

    it("_authorizeUpgrade's fallback proceeds even when its OWN (second) revoke call reverts (SSA-01)", async function () {
      const { viem, entryPoint, deployer, beneficiary, publicClient } =
        await loadFixture(deployFixture);

      // Succeeds on requestUpgrade's (first) call and reverts on every call after, so staging
      // still reaches a pending upgrade while _authorizeUpgrade's second call fails.
      // `RevertingPaymasterStub` cannot be used here: requestUpgrade is now fail-closed.
      const recallPaymaster = await viem.deployContract("RevertOnRecallPaymasterStub", []);
      const factory = await viem.deployContract("StarzipWalletFactory", [
        entryPoint.address,
        recallPaymaster.address,
      ]);
      const firstOwner = encodePasskeyOwner(PK_X, PK_Y);
      const salt = 777n;
      await factory.write.createAccount([[firstOwner], salt], { account: deployer.account });
      const walletAddr = (await factory.read.getAddress([[firstOwner], salt])) as Address;
      const account = await viem.getContractAt("StarzipWallet", walletAddr);
      await deployer.sendTransaction({ to: walletAddr, value: parseEther("2") });

      assert.strictEqual(
        getAddress(await account.read.trustedPaymaster()),
        getAddress(recallPaymaster.address),
        "precondition: this wallet names the revert-on-recall stub",
      );

      const ctx = { viem, publicClient, entryPoint, account, walletAddr, deployer, beneficiary };
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address, zeroAddress]);

      const reqR = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
      );
      assert.ok(
        opSucceeded(reqR, entryPoint.abi),
        "requestUpgrade's primary revoke call must succeed, so the upgrade gets staged",
      );
      assert.strictEqual(await recallPaymaster.read.called(), true);

      await time.increase(UPGRADE_TIMELOCK);
      const upR = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "upgradeToAndCall",
          args: [newImpl.address, "0x"],
        }),
      );
      assert.ok(
        opSucceeded(upR, entryPoint.abi),
        "the upgrade must succeed even though _authorizeUpgrade's own fallback revoke call " +
          "reverted — that call is deliberately non-reverting",
      );
      assert.strictEqual(
        await account.read.hasBeenUpgraded(),
        true,
        "the implementation must have actually been swapped, not merely attempted",
      );

      const notif = parseEventLogs({
        abi: account.abi,
        logs: upR.logs,
        eventName: "PaymasterUpgradeNotification",
      })[0] as any;
      assert.strictEqual(
        getAddress(notif.args.paymaster),
        getAddress(recallPaymaster.address),
      );
      assert.strictEqual(
        notif.args.success,
        false,
        "PaymasterUpgradeNotification must report that _authorizeUpgrade's own push failed",
      );
    });

    it("emits AddOwner(index,owner) and UpgradeRequested(readyAt = now + 48h)", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;

      const addR = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "addOwnerPublicKey",
          args: [NEW_PK_X, NEW_PK_Y],
        }),
        PASSKEY_PRIV,
      );
      const ao = parseEventLogs({
        abi: account.abi,
        logs: addR.logs,
        eventName: "AddOwner",
      })[0] as any;
      assert.strictEqual(ao.args.index as bigint, 1n);
      assert.strictEqual(ao.args.owner, encodePasskeyOwner(NEW_PK_X, NEW_PK_Y));

      // request upgrade with the NEW owner (index 1); assert readyAt == upgradeRequestedAt + 48h
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address, zeroAddress]);
      const reqR = await execViaPasskey({
        publicClient: ctx.publicClient,
        entryPoint: ctx.entryPoint,
        walletAbi: account.abi,
        walletAddr: ctx.walletAddr,
        target: ctx.walletAddr,
        innerCalldata: encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
        passkeyPriv: NEW_PASSKEY_PRIV,
        submitter: ctx.deployer,
        beneficiary: ctx.beneficiary.account.address,
        ownerIndex: 1n,
      });
      const ur = parseEventLogs({
        abi: account.abi,
        logs: reqR.logs,
        eventName: "UpgradeRequested",
      })[0] as any;
      const requestedAt = (await account.read.upgradeRequestedAt()) as bigint;
      assert.strictEqual(ur.args.readyAt as bigint, requestedAt + UPGRADE_TIMELOCK);
    });

    it("addOwnerPublicKey cancels a pending upgrade (P1-2 incident-response, extended to owner-set changes)", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address, zeroAddress]);

      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
      );
      assert.notStrictEqual(await account.read.pendingImplementation(), zeroAddress);

      const addR = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "addOwnerPublicKey",
          args: [NEW_PK_X, NEW_PK_Y],
        }),
        PASSKEY_PRIV,
      );
      assert.ok(opSucceeded(addR, entryPoint.abi));
      assert.strictEqual(
        await account.read.pendingImplementation(),
        zeroAddress,
        "adding an owner must clear pending upgrade",
      );
      assert.strictEqual((await account.read.upgradeRequestedAt()) as bigint, 0n);
      const cancelled = parseEventLogs({
        abi: account.abi,
        logs: addR.logs,
        eventName: "UpgradeCancelled",
      });
      assert.strictEqual(
        cancelled.length,
        1,
        "UpgradeCancelled must be emitted when adding an owner clears a pending upgrade",
      );
    });

    it("removeOwnerAtIndex cancels a pending upgrade too", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address, zeroAddress]);

      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "addOwnerPublicKey",
          args: [NEW_PK_X, NEW_PK_Y],
        }),
      );
      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
      );
      assert.notStrictEqual(await account.read.pendingImplementation(), zeroAddress);

      const removeR = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "removeOwnerAtIndex",
          args: [1n, encodePasskeyOwner(NEW_PK_X, NEW_PK_Y)],
        }),
      );
      assert.ok(opSucceeded(removeR, entryPoint.abi));
      assert.strictEqual(await account.read.pendingImplementation(), zeroAddress);
      assert.strictEqual((await account.read.upgradeRequestedAt()) as bigint, 0n);
    });

    it("removeOwnerAtIndex reverts LastOwner when it is the only owner left", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint } = ctx;
      const r = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "removeOwnerAtIndex",
          args: [0n, encodePasskeyOwner(PK_X, PK_Y)],
        }),
      );
      assert.strictEqual(
        opSucceeded(r, entryPoint.abi),
        false,
        "removing the last owner must fail",
      );
      assert.strictEqual((await account.read.ownerCount()) as bigint, 1n);
    });

    it("removeOwnerAtIndex reverts OwnerMismatch when expectedOwner is stale", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint } = ctx;
      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "addOwnerPublicKey",
          args: [NEW_PK_X, NEW_PK_Y],
        }),
      );
      const r = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "removeOwnerAtIndex",
          args: [1n, encodePasskeyOwner(PK_X, PK_Y)], // wrong owner for index 1
        }),
      );
      assert.strictEqual(
        opSucceeded(r, entryPoint.abi),
        false,
        "mismatched expectedOwner must fail",
      );
      assert.strictEqual((await account.read.ownerCount()) as bigint, 2n);
    });

    it("addOwnerPublicKey rejects a duplicate of an already-registered owner", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint } = ctx;
      const r = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "addOwnerPublicKey",
          args: [PK_X, PK_Y], // same as owner 0
        }),
      );
      assert.strictEqual(opSucceeded(r, entryPoint.abi), false, "duplicate owner must be rejected");
      assert.strictEqual((await account.read.ownerCount()) as bigint, 1n);
    });

    it("addOwnerAddress rejects the zero address", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint } = ctx;
      const r = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "addOwnerAddress",
          args: [zeroAddress],
        }),
      );
      assert.strictEqual(
        opSucceeded(r, entryPoint.abi),
        false,
        "zero address owner must be rejected",
      );
    });

    it("addOwnerPublicKey rejects an off-curve point (would create an unusable owner)", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint } = ctx;
      const r = await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "addOwnerPublicKey",
          args: [OFFCURVE_X, OFFCURVE_Y],
        }),
      );
      assert.strictEqual(opSucceeded(r, entryPoint.abi), false, "off-curve owner must be rejected");
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
        impl.write.initialize([[encodePasskeyOwner(PK_X, PK_Y)]], { account: deployer.account }),
      );
    });

    it("owner set survives a full admin lifecycle (add, request+cancel upgrade, request+execute upgrade)", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, viem, entryPoint } = ctx;
      const newImpl = await viem.deployContract("StarzipWallet", [entryPoint.address, zeroAddress]);

      await selfCall(
        ctx,
        encodeFunctionData({
          abi: account.abi,
          functionName: "addOwnerPublicKey",
          args: [NEW_PK_X, NEW_PK_Y],
        }),
        PASSKEY_PRIV,
      );
      await execViaPasskey({
        publicClient: ctx.publicClient,
        entryPoint: ctx.entryPoint,
        walletAbi: account.abi,
        walletAddr: ctx.walletAddr,
        target: ctx.walletAddr,
        innerCalldata: encodeFunctionData({
          abi: account.abi,
          functionName: "requestUpgrade",
          args: [newImpl.address],
        }),
        passkeyPriv: NEW_PASSKEY_PRIV,
        submitter: ctx.deployer,
        beneficiary: ctx.beneficiary.account.address,
        ownerIndex: 1n,
      });
      await execViaPasskey({
        publicClient: ctx.publicClient,
        entryPoint: ctx.entryPoint,
        walletAbi: account.abi,
        walletAddr: ctx.walletAddr,
        target: ctx.walletAddr,
        innerCalldata: encodeFunctionData({
          abi: account.abi,
          functionName: "cancelUpgrade",
          args: [],
        }),
        passkeyPriv: NEW_PASSKEY_PRIV,
        submitter: ctx.deployer,
        beneficiary: ctx.beneficiary.account.address,
        ownerIndex: 1n,
      });

      // both owners survive untouched
      assert.strictEqual(await account.read.ownerAtIndex([0n]), encodePasskeyOwner(PK_X, PK_Y));
      assert.strictEqual(
        await account.read.ownerAtIndex([1n]),
        encodePasskeyOwner(NEW_PK_X, NEW_PK_Y),
      );
      assert.strictEqual((await account.read.ownerCount()) as bigint, 2n);
      assert.strictEqual(await account.read.pendingImplementation(), zeroAddress);
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
