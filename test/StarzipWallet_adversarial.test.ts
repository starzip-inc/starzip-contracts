/**
 * StarzipWallet — adversarial-review remediation coverage.
 *
 * Pins the behaviours the review flagged as passing today even though the code was wrong (or
 * whose NatSpec claim was wrong) — see contracts/wallet/StarzipWallet.sol's fix comments and
 * Every test here has been paired with a mutation
 * (recorded in the executor's final report, not re-derived from this file) proving it is not
 * vacuous: the mutation was applied to a BACKUP copy of StarzipWallet.sol, the test was re-run and
 * observed to fail, then the backup was restored — `git checkout --` was never used, per the
 * review's explicit instruction not to risk uncommitted work.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseEther,
  hexToBytes,
  encodeFunctionData,
  parseEventLogs,
  concatHex,
  encodeAbiParameters,
  sha256,
  pad,
  toHex,
  hashStruct,
  hashTypedData,
  zeroAddress,
  type Hex,
  type Address,
} from "viem";
import { p256 } from "@noble/curves/p256";
import { loadFixture, getConnection } from "./helpers.js";
import {
  base64url,
  passkeyPubCoords,
  webauthnSignature,
  buildUserOp,
  execViaPasskey,
  encodeAddressOwner,
  encodePasskeyOwner,
  encodeSignatureWrapper,
  domainSeparator,
  erc7739TypedDataSig,
  WALLET_EIP712_NAME,
  WALLET_EIP712_VERSION,
  type Eip712Domain,
} from "./aa-helpers.js";

const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const SECOND_PASSKEY_PRIV = hexToBytes(
  "0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464" as Hex,
);
const { x: PK_X, y: PK_Y } = passkeyPubCoords(PASSKEY_PRIV);
const { x: PK2_X, y: PK2_Y } = passkeyPubCoords(SECOND_PASSKEY_PRIV);

const SALT = 31415n;
const ERC1271_MAGIC = "0x1626ba7e";
const ERC1271_INVALID = "0xffffffff";

async function deployFixture() {
  const { viem } = await getConnection();
  const [deployer, beneficiary] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();
  const chainId = await publicClient.getChainId();

  const entryPoint = await viem.deployContract("TestEntryPoint", []);
  const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address]);

  const firstOwner = encodePasskeyOwner(PK_X, PK_Y);
  await factory.write.createAccount([[firstOwner], SALT], { account: deployer.account });
  const walletAddr = (await factory.read.getAddress([[firstOwner], SALT])) as Address;
  const account = await viem.getContractAt("StarzipWallet", walletAddr);
  await deployer.sendTransaction({ to: walletAddr, value: parseEther("2") });

  const walletDomain: Eip712Domain = {
    name: WALLET_EIP712_NAME,
    version: WALLET_EIP712_VERSION,
    chainId,
    verifyingContract: walletAddr,
  };

  return {
    viem,
    publicClient,
    entryPoint,
    factory,
    account,
    walletAddr,
    deployer,
    beneficiary,
    chainId,
    walletDomain,
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

async function selfCall(
  ctx: any,
  innerCalldata: Hex,
  priv: Uint8Array = PASSKEY_PRIV,
  ownerIndex = 0n,
) {
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
    ownerIndex,
  });
}

// Submit a no-op userOp (execute(self, 0, "0x")) with a HAND-CONSTRUCTED raw signature buffer,
// bypassing encodeSignatureWrapper — needed to build malformed SignatureWrapper encodings the
// helper cannot express.
async function submitWithRawSignature(ctx: any, rawSignature: Hex) {
  const callData = encodeFunctionData({
    abi: ctx.account.abi,
    functionName: "execute",
    args: [ctx.walletAddr, 0n, "0x"],
  });
  const nonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
  const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
  userOp.signature = rawSignature;
  return ctx.entryPoint.write.handleOps([[userOp], ctx.beneficiary.account.address], {
    account: ctx.deployer.account,
  });
}

const word = (v: bigint): Hex => pad(toHex(v), { size: 32 });

// ============================================================================================
// Round-2 helpers. Kept local rather than added to aa-helpers.ts
// so that the round-2 probes cannot perturb the 800+ tests that depend on that shared module.
// ============================================================================================

/** Everything viem knows about a rejected tx, flattened — the EntryPoint's `AA__` code lives on
 *  `.details`, NOT on `.message`, and sometimes only on a nested `.cause`. */
function failureText(e: unknown): string {
  const parts: string[] = [];
  let cur = e as Record<string, unknown> | undefined;
  for (let depth = 0; depth < 8 && cur; depth++) {
    for (const key of ["details", "shortMessage", "message", "reason"]) {
      const v = cur[key];
      if (typeof v === "string") parts.push(v);
    }
    cur = cur.cause as Record<string, unknown> | undefined;
  }
  return parts.join(" | ");
}

/** A clean decline = the account returned SIG_VALIDATION_FAILED and the EntryPoint reported
 *  `FailedOp(_, "AA24 signature error")`. Anything else (notably `FailedOpWithRevert(_, "AA23
 *  reverted", ...)`) means `validateUserOp` THREW, which it must never do. */
function isCleanDecline(e: unknown): boolean {
  return /AA24 signature error/.test(failureText(e));
}

function describeFailure(e: unknown): string {
  const t = failureText(e);
  const m = t.match(/FailedOpWithRevert\([^)]*\)|FailedOp\([^)]*\)/);
  return m ? m[0] : t.slice(0, 220);
}

function assertCleanDecline(e: unknown, label: string): void {
  assert.ok(
    isCleanDecline(e),
    `${label}: validateUserOp must DECLINE (EntryPoint "AA24 signature error"), never revert. Got: ${describeFailure(e)}`,
  );
}

/**
 * A real, correctly-signed WebAuthn assertion over `challenge`, with `challengeIndex` / `typeIndex`
 * overridable. `webauthnSignature` in aa-helpers.ts always derives both from the JSON, so it cannot
 * express the attacker-controlled values these probes need — the whole point is that OZ's
 * `WebAuthn.WebAuthnAuth` carries them as free `uint256` fields that nothing range-checks.
 */
function passkeyAssertion(
  challenge: Hex,
  priv: Uint8Array,
  opts: { challengeIndex?: bigint; typeIndex?: bigint } = {},
): Hex {
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${base64url(hexToBytes(challenge))}","origin":"https://starzip.io"}`;
  const challengeIndex = opts.challengeIndex ?? BigInt(clientDataJSON.indexOf('"challenge":"'));
  const typeIndex = opts.typeIndex ?? BigInt(clientDataJSON.indexOf('"type":"webauthn.get"'));
  // 37 bytes (> 36) so WebAuthn.verify does NOT short-circuit before the index checks — without
  // this the payload never reaches the code under test.
  const authenticatorData = concatHex([sha256(toHex("starzip.io")), "0x05", "0x00000000"]);
  const msgHash = sha256(concatHex([authenticatorData, sha256(toHex(clientDataJSON))]));
  const sig = p256.sign(hexToBytes(msgHash), priv, { lowS: true });
  return encodeAbiParameters(
    [
      { name: "r", type: "bytes32" },
      { name: "s", type: "bytes32" },
      { name: "challengeIndex", type: "uint256" },
      { name: "typeIndex", type: "uint256" },
      { name: "authenticatorData", type: "bytes" },
      { name: "clientDataJSON", type: "string" },
    ],
    [
      pad(toHex(sig.r), { size: 32 }),
      pad(toHex(sig.s), { size: 32 }),
      challengeIndex,
      typeIndex,
      authenticatorData,
      clientDataJSON,
    ],
  );
}

/** Send `execute(self, 0, "")` with a caller-built signature; resolves to the receipt, rejects
 *  with whatever the EntryPoint threw. */
async function sendOp(ctx: any, makeSignature: (userOpHash: Hex) => Hex) {
  const callData = encodeFunctionData({
    abi: ctx.account.abi,
    functionName: "execute",
    args: [ctx.walletAddr, 0n, "0x"],
  });
  const nonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
  const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
  const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
  userOp.signature = makeSignature(userOpHash);
  const hash = await ctx.entryPoint.write.handleOps([[userOp], ctx.beneficiary.account.address], {
    account: ctx.deployer.account,
  });
  return ctx.publicClient.waitForTransactionReceipt({ hash });
}

const submitWithPasskeyAssertion = (
  ctx: any,
  opts: { challengeIndex?: bigint; typeIndex?: bigint },
  ownerIndex = 0n,
) =>
  sendOp(ctx, (h) => encodeSignatureWrapper(ownerIndex, passkeyAssertion(h, PASSKEY_PRIV, opts)));

const submitSigned = (ctx: any, priv: Uint8Array, ownerIndex: bigint) =>
  sendOp(ctx, (h) => encodeSignatureWrapper(ownerIndex, webauthnSignature(h, priv)));

const MAIL_TYPES = {
  Mail: [
    { name: "to", type: "address" },
    { name: "contents", type: "string" },
  ],
} as const;
const MAIL_DESCR = "Mail(address to,string contents)";
const MAIL_MESSAGE = {
  to: "0x00000000000000000000000000000000000000a1" as Address,
  contents: "hi",
};
const APP_VERIFYING_CONTRACT = "0x000000000000000000000000000000000000aaaa" as Address;

/** A well-formed ERC-7739 TypedDataSign envelope whose INNER signature slot is whatever `sign`
 *  returns — so probes can put a short/malformed wrapper inside a long, otherwise-valid envelope. */
function buildErc1271Payload(ctx: any, sign: (digest: Hex) => Hex): { digest: Hex; sig: Hex } {
  const appDomain: Eip712Domain = {
    name: "ExampleApp",
    version: "1",
    chainId: ctx.chainId,
    verifyingContract: APP_VERIFYING_CONTRACT,
  };
  const appSeparator = domainSeparator(appDomain);
  const contentsHash = hashStruct({
    data: MAIL_MESSAGE,
    primaryType: "Mail",
    types: MAIL_TYPES,
  });
  const digest = hashTypedData({
    domain: appDomain,
    types: MAIL_TYPES,
    primaryType: "Mail",
    message: MAIL_MESSAGE,
  });
  const sig = erc7739TypedDataSig({
    appSeparator,
    contentsHash,
    contentsDescr: MAIL_DESCR,
    walletDomain: ctx.walletDomain,
    sign,
  });
  return { digest, sig };
}

/**
 * A 4-owner wallet wired to `PassthroughEntryPoint`, so owner-set state-machine probes can drive
 * `onlySelf` admin calls WITHOUT producing a passkey assertion per step. The code under test
 * (`onlyEntryPoint` + `execute` + `onlySelf`) is byte-for-byte the production path; only the
 * 4337 validation the other suites already cover is skipped. See PassthroughEntryPoint's NatSpec.
 */
async function passthroughOwnerFixture() {
  const { viem } = await getConnection();
  const [deployer] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();
  const pep = await viem.deployContract("PassthroughEntryPoint", []);
  const factory = await viem.deployContract("StarzipWalletFactory", [pep.address]);
  const salt = 20260811n;
  const initialOwners: Hex[] = [
    encodePasskeyOwner(PK_X, PK_Y),
    encodeAddressOwner("0x00000000000000000000000000000000000000a1" as Address),
    encodeAddressOwner("0x00000000000000000000000000000000000000a2" as Address),
    encodeAddressOwner("0x00000000000000000000000000000000000000a3" as Address),
  ];
  await factory.write.createAccount([initialOwners, salt], { account: deployer.account });
  const walletAddr = (await factory.read.getAddress([initialOwners, salt])) as Address;
  const w = await viem.getContractAt("StarzipWallet", walletAddr);
  const self = (data: Hex) =>
    pep.write.callExecute([walletAddr, walletAddr, 0n, data], { account: deployer.account });
  const selfBatch = (datas: Hex[]) =>
    pep.write.callExecuteBatch(
      [walletAddr, datas.map(() => walletAddr), datas.map(() => 0n), datas],
      { account: deployer.account },
    );
  return {
    viem,
    publicClient,
    pep,
    factory,
    w,
    walletAddr,
    deployer,
    salt,
    initialOwners,
    self,
    selfBatch,
  };
}

describe("StarzipWallet — adversarial review", function () {
  // ============ V1 + malformed SignatureWrapper matrix ============
  describe("_decodeSignatureWrapper — malformed input declines, never reverts (V1)", function () {
    it("V1: signatureData.length == type(uint256).max declines with AA24, NOT a Panic/AA23 revert", async function () {
      const ctx = await loadFixture(deployFixture);
      // head: offset=0x20, ownerIndex=0, offset=0x40, len=2**256-1 (no data follows — a genuine
      // attacker-controlled overflow attempt, not a truncated-but-plausible length).
      const raw = concatHex([word(0x20n), word(0n), word(0x40n), word(2n ** 256n - 1n)]);
      await assert.rejects(
        submitWithRawSignature(ctx, raw),
        /AA24/,
        "an astronomically large declared signatureData length must decline cleanly (AA24), " +
          "never revert the whole userOp (the pre-fix bug produced AA23 Panic 0x11 here)",
      );
    });

    it("declines a signature with a corrupted head offset word, even though the rest of the buffer is a real, valid assertion (canonical head-word pinning)", async function () {
      const ctx = await loadFixture(deployFixture);
      const callData = encodeFunctionData({
        abi: ctx.account.abi,
        functionName: "execute",
        args: [ctx.walletAddr, 0n, "0x"],
      });
      const nonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
      const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
      const good = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));
      // Corrupt byte 31 of the FIRST head word (the "offset to the tuple's own data" word, which
      // must be exactly 0x20) while leaving everything else — including a real, validly-signed
      // WebAuthn assertion for owner 0 — untouched.
      const corrupted = ("0x21" + good.slice(4)) as Hex;
      userOp.signature = corrupted;
      await assert.rejects(
        ctx.entryPoint.write.handleOps([[userOp], ctx.beneficiary.account.address], {
          account: ctx.deployer.account,
        }),
        /AA24/,
        "a non-canonical head offset must decline even when the rest of the buffer would " +
          "otherwise validate — this is what proves the offset check itself is load-bearing",
      );
    });

    it("declines a truncated buffer whose declared signatureData length runs past the actual bytes (no overflow involved)", async function () {
      const ctx = await loadFixture(deployFixture);
      // head declares len=1000, but only 40 bytes of "data" follow (total 168 bytes) — well short
      // of 128+1000, and nowhere near an overflow, so this exercises the ordinary bounds check,
      // not the V1 overflow specifically.
      const raw = concatHex([
        word(0x20n),
        word(0n),
        word(0x40n),
        word(1000n),
        ("0x" + "ab".repeat(40)) as Hex,
      ]);
      await assert.rejects(submitWithRawSignature(ctx, raw), /AA24/);
    });

    it("ACCEPTS trailing garbage bytes appended after a well-formed signatureData slice (corrected NatSpec claim: this is NOT rejected)", async function () {
      const ctx = await loadFixture(deployFixture);
      const callData = encodeFunctionData({
        abi: ctx.account.abi,
        functionName: "execute",
        args: [ctx.walletAddr, 0n, "0x"],
      });
      const nonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
      const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
      const good = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));
      // Append 64 bytes of garbage AFTER the declared signatureData — never read by the decoder,
      // per its own (corrected) NatSpec.
      userOp.signature = concatHex([good, ("0x" + "ff".repeat(64)) as Hex]);
      const hash = await ctx.entryPoint.write.handleOps(
        [[userOp], ctx.beneficiary.account.address],
        {
          account: ctx.deployer.account,
        },
      );
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
      assert.ok(
        opSucceeded(receipt, ctx.entryPoint.abi),
        "trailing bytes after signatureData must be silently ignored, not rejected",
      );
    });
  });

  // ============ per-call Executed from executeBatch ============
  describe("executeBatch emits one Executed per inner call (observability)", function () {
    const R1 = "0x00000000000000000000000000000000000000B1" as Address;
    const R2 = "0x00000000000000000000000000000000000000b2" as Address;

    it("emits Executed(R1,1,0x) and Executed(R2,1,0x) — not just BatchExecuted(2)", async function () {
      const ctx = await loadFixture(deployFixture);
      const callData = encodeFunctionData({
        abi: ctx.account.abi,
        functionName: "executeBatch",
        args: [
          [R1, R2],
          [1n, 1n],
          ["0x", "0x"],
        ],
      });
      const nonce = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
      const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
      userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));
      const hash = await ctx.entryPoint.write.handleOps(
        [[userOp], ctx.beneficiary.account.address],
        {
          account: ctx.deployer.account,
        },
      );
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
      assert.ok(opSucceeded(receipt, ctx.entryPoint.abi));

      const executed = parseEventLogs({
        abi: ctx.account.abi,
        logs: receipt.logs,
        eventName: "Executed",
      }) as any[];
      assert.strictEqual(executed.length, 2, "expected one Executed per inner call");
      assert.strictEqual(executed[0].args.target.toLowerCase(), R1.toLowerCase());
      assert.strictEqual(executed[0].args.value, 1n);
      assert.strictEqual(executed[1].args.target.toLowerCase(), R2.toLowerCase());
      assert.strictEqual(executed[1].args.value, 1n);

      const batch = parseEventLogs({
        abi: ctx.account.abi,
        logs: receipt.logs,
        eventName: "BatchExecuted",
      }) as any[];
      assert.strictEqual(batch.length, 1);
      assert.strictEqual(batch[0].args.count, 2n);
    });
  });

  // ============ nonReentrant on execute / executeBatch ============
  // Uses `PassthroughEntryPoint` (a mock with NO reentrancy protection of its own) instead of the
  // real EntryPoint: the real `EntryPoint.handleOps` has its OWN `nonReentrant` guard, which blocks
  // any nested `handleOps` call before it ever reaches the wallet — testing through it would only
  // prove the ERC-4337 infra's guard works, not StarzipWallet's OWN modifier (the actual mutation
  // target here). See PassthroughEntryPoint.sol's NatSpec for the full rationale.
  describe("nonReentrant blocks a nested self-call mid-execution of the outer op", function () {
    async function passthroughFixture() {
      const { viem } = await getConnection();
      const [deployer] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();

      const pep = await viem.deployContract("PassthroughEntryPoint", []);
      const factory = await viem.deployContract("StarzipWalletFactory", [pep.address]);
      const owner = encodePasskeyOwner(PK_X, PK_Y);
      await factory.write.createAccount([[owner], SALT], { account: deployer.account });
      const walletAddr = (await factory.read.getAddress([[owner], SALT])) as Address;
      const account = await viem.getContractAt("StarzipWallet", walletAddr);
      const trigger = await viem.deployContract("ReentrantExecuteTrigger", []);

      return { viem, publicClient, pep, factory, account, walletAddr, deployer, trigger };
    }

    it("execute(): a nested execute() triggered mid-call is blocked by the WALLET's own guard", async function () {
      const { pep, account, walletAddr, deployer, trigger, publicClient } =
        await loadFixture(passthroughFixture);

      const triggerCalldata = encodeFunctionData({
        abi: trigger.abi,
        functionName: "reenterExecute",
        args: [pep.address, walletAddr],
      });
      // Outer call: an EOA drives PassthroughEntryPoint.callExecute, which itself calls
      // wallet.execute(trigger, 0, reenterExecute(...)) — msg.sender to the wallet is `pep`,
      // satisfying onlyEntryPoint exactly like the real EntryPoint would.
      const hash = await pep.write.callExecute([walletAddr, trigger.address, 0n, triggerCalldata], {
        account: deployer.account,
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      assert.strictEqual(
        receipt.status,
        "success",
        "the OUTER execute() call must still complete normally",
      );

      const executed = parseEventLogs({
        abi: account.abi,
        logs: receipt.logs,
        eventName: "Executed",
      }) as any[];
      assert.strictEqual(
        executed.length,
        1,
        "only the OUTER execute() may emit Executed — the nested one must never complete",
      );

      assert.strictEqual(
        await trigger.read.reenterAttempted(),
        true,
        "sanity: the reentry attempt must actually have been made",
      );
      assert.strictEqual(
        await trigger.read.reenterBlocked(),
        true,
        "the nested execute() call must have been blocked by the wallet's own nonReentrant guard",
      );
    });

    it("executeBatch(): a nested executeBatch() triggered mid-call is blocked by the WALLET's own guard", async function () {
      const { pep, account, walletAddr, deployer, trigger, publicClient } =
        await loadFixture(passthroughFixture);

      const triggerCalldata = encodeFunctionData({
        abi: trigger.abi,
        functionName: "reenterExecuteBatch",
        args: [pep.address, walletAddr],
      });
      const hash = await pep.write.callExecuteBatch(
        [walletAddr, [trigger.address], [0n], [triggerCalldata]],
        { account: deployer.account },
      );
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      assert.strictEqual(
        receipt.status,
        "success",
        "the OUTER executeBatch() call must still complete normally",
      );

      const batchExecuted = parseEventLogs({
        abi: account.abi,
        logs: receipt.logs,
        eventName: "BatchExecuted",
      }) as any[];
      assert.strictEqual(
        batchExecuted.length,
        1,
        "only the OUTER executeBatch() may emit BatchExecuted",
      );

      assert.strictEqual(await trigger.read.reenterAttempted(), true);
      assert.strictEqual(
        await trigger.read.reenterBlocked(),
        true,
        "the nested executeBatch() call must have been blocked by the wallet's own nonReentrant guard",
      );
    });
  });

  // ============ Owner removal: signing capability, both paths ============
  describe("a removed owner cannot sign, via either path (4337 and ERC-1271)", function () {
    async function twoOwnerFixture() {
      const ctx = await deployFixture();
      const addCalldata = encodeFunctionData({
        abi: ctx.account.abi,
        functionName: "addOwnerPublicKey",
        args: [PK2_X, PK2_Y],
      });
      const r = await selfCall(ctx, addCalldata, PASSKEY_PRIV, 0n);
      assert.ok(opSucceeded(r, ctx.entryPoint.abi), "precondition: second owner must be added");
      return ctx;
    }

    it("4337: a userOp signed by the just-removed owner's key is SIG_VALIDATION_FAILED (AA24), not accepted", async function () {
      const ctx = await loadFixture(twoOwnerFixture);
      const { account, entryPoint, walletAddr, deployer, beneficiary } = ctx;

      const removeCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "removeOwnerAtIndex",
        args: [0n, encodePasskeyOwner(PK_X, PK_Y)],
      });
      // owner 1 (the surviving key) authorizes removing owner 0.
      const removeR = await selfCall(ctx, removeCalldata, SECOND_PASSKEY_PRIV, 1n);
      assert.ok(opSucceeded(removeR, entryPoint.abi), "precondition: removal must succeed");
      assert.strictEqual((await account.read.ownerCount()) as bigint, 1n);

      const callData = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [walletAddr, 0n, "0x"],
      });
      const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(walletAddr, nonce, callData);
      const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
      // Signed with the REMOVED owner's real key, still naming ownerIndex 0.
      userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));
      await assert.rejects(
        entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
          account: deployer.account,
        }),
        /AA24/,
      );
    });

    it("ERC-1271: a wrapper signed by the just-removed owner's key returns 0xffffffff, not the magic value", async function () {
      const ctx = await loadFixture(twoOwnerFixture);
      const { account, walletDomain, chainId } = ctx;

      const removeCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "removeOwnerAtIndex",
        args: [0n, encodePasskeyOwner(PK_X, PK_Y)],
      });
      const removeR = await selfCall(ctx, removeCalldata, SECOND_PASSKEY_PRIV, 1n);
      assert.ok(opSucceeded(removeR, ctx.entryPoint.abi));

      const appDomain: Eip712Domain = {
        name: "ExampleApp",
        version: "1",
        chainId,
        verifyingContract: "0x000000000000000000000000000000000000aaaa" as Address,
      };
      const MAIL_TYPES = {
        Mail: [
          { name: "to", type: "address" },
          { name: "contents", type: "string" },
        ],
      } as const;
      const MAIL_DESCR = "Mail(address to,string contents)";
      const MAIL_MESSAGE = {
        to: "0x00000000000000000000000000000000000000a1" as Address,
        contents: "hi",
      };
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = hashStruct({
        data: MAIL_MESSAGE,
        primaryType: "Mail",
        types: MAIL_TYPES,
      });
      const digest = hashTypedData({
        domain: appDomain,
        types: MAIL_TYPES,
        primaryType: "Mail",
        message: MAIL_MESSAGE,
      });

      const sig = erc7739TypedDataSig({
        appSeparator,
        contentsHash,
        contentsDescr: MAIL_DESCR,
        walletDomain,
        sign: (d) => encodeSignatureWrapper(0n, webauthnSignature(d, PASSKEY_PRIV)),
      });
      assert.strictEqual(
        await account.read.isValidSignature([digest, sig]),
        ERC1271_INVALID,
        "a removed owner's ERC-1271 wrapper must no longer validate",
      );
    });
  });

  describe("re-adding a previously removed owner works (new index, same bytes)", function () {
    it("removes owner 0, re-adds the SAME passkey bytes at a NEW index, and that new index can sign", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint, walletAddr, deployer, beneficiary } = ctx;

      const addCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "addOwnerPublicKey",
        args: [PK2_X, PK2_Y],
      });
      const addR = await selfCall(ctx, addCalldata, PASSKEY_PRIV, 0n);
      assert.ok(opSucceeded(addR, entryPoint.abi));

      const removeCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "removeOwnerAtIndex",
        args: [0n, encodePasskeyOwner(PK_X, PK_Y)],
      });
      const removeR = await selfCall(ctx, removeCalldata, SECOND_PASSKEY_PRIV, 1n);
      assert.ok(opSucceeded(removeR, entryPoint.abi));
      assert.strictEqual((await account.read.ownerCount()) as bigint, 1n);
      assert.strictEqual(
        (await account.read.isOwnerBytes([encodePasskeyOwner(PK_X, PK_Y)])) as boolean,
        false,
      );

      // Re-register the SAME (x, y) bytes that used to be owner 0 — authorized by the surviving
      // owner (index 1).
      const reAddCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "addOwnerPublicKey",
        args: [PK_X, PK_Y],
      });
      const reAddR = await selfCall(ctx, reAddCalldata, SECOND_PASSKEY_PRIV, 1n);
      assert.ok(
        opSucceeded(reAddR, entryPoint.abi),
        "re-adding a previously removed owner must succeed",
      );

      const added = parseEventLogs({
        abi: account.abi,
        logs: reAddR.logs,
        eventName: "AddOwner",
      })[0] as any;
      assert.strictEqual(
        added.args.index as bigint,
        2n,
        "the re-added owner must land at a NEW index",
      );
      assert.strictEqual((await account.read.ownerCount()) as bigint, 2n);

      // The re-added owner (now at index 2) can sign again with the SAME original key.
      const callData = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [walletAddr, 0n, "0x"],
      });
      const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(walletAddr, nonce, callData);
      const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
      userOp.signature = encodeSignatureWrapper(2n, webauthnSignature(userOpHash, PASSKEY_PRIV));
      const hash = await entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
        account: deployer.account,
      });
      const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
      assert.ok(
        opSucceeded(receipt, entryPoint.abi),
        "the re-added owner must be able to sign again",
      );
    });
  });

  // ==========================================================================================
  // (CRITICAL) — `challengeIndex` is the UNFIXED SIBLING of the V1/V3 "never revert" bugs.
  //
  // V3 bounded `auth.typeIndex` against `clientDataJSON.length` (StarzipWallet.sol:925) but left
  // `auth.challengeIndex` — the OTHER attacker-controlled index into the same string — completely
  // unbounded. OZ's `WebAuthn._validateChallenge` (node_modules/@openzeppelin/contracts/utils/
  // cryptography/WebAuthn.sol:145-157) computes
  //     Bytes.slice(bytes(clientDataJSON), challengeIndex, challengeIndex + expectedChallenge.length)
  // in CHECKED arithmetic. `expectedChallenge` is `"challenge":"` (13) + base64url(32 bytes) (43)
  // + `"` (1) = 57 bytes, so any `challengeIndex >= 2**256 - 57` overflows the `+ 57` and panics
  // (0x11) — observed on-chain as `FailedOpWithRevert(0, "AA23 reverted",
  // "0x4e487b71..0011")`, byte-for-byte the same failure mode round 1 found in the wrapper decode.
  //
  // Reaching it needs a well-formed PREFIX (authenticatorData.length > 36 and a `typeIndex` that
  // really points at `"type":"webauthn.get"`), because `verify` short-circuits on those first —
  // which is why a naive random fuzz does NOT find it. Everything needed is public.
  //
  // FIX (one line, mirroring the V3 fix directly above it in _verifyPasskeyOwner):
  //     if (auth.challengeIndex > bytes(auth.clientDataJSON).length) return false;
  // ==========================================================================================
  describe("WebAuthn index bounds — challengeIndex must decline, never revert", function () {
    const CHALLENGE_PREFIX_LEN = 57n; // '"challenge":"' + 43 base64url chars + '"'
    const MAX = 2n ** 256n;

    it("challengeIndex = type(uint256).max on an otherwise VALID assertion must decline (AA24), not revert the op", async function () {
      const ctx = await loadFixture(deployFixture);
      await assert.rejects(
        submitWithPasskeyAssertion(ctx, { challengeIndex: MAX - 1n }),
        (e: unknown) => {
          assertCleanDecline(e, "challengeIndex = type(uint256).max");
          return true;
        },
      );
    });

    it("challengeIndex = 2**256 - 57 (the exact lower edge of the overflow band) must decline, not revert", async function () {
      const ctx = await loadFixture(deployFixture);
      await assert.rejects(
        submitWithPasskeyAssertion(ctx, { challengeIndex: MAX - CHALLENGE_PREFIX_LEN }),
        (e: unknown) => {
          assertCleanDecline(e, "challengeIndex = 2**256 - 57");
          return true;
        },
      );
    });

    it("challengeIndex = 2**256 - 58 (one below the band) already declines cleanly — pins where the band starts", async function () {
      const ctx = await loadFixture(deployFixture);
      await assert.rejects(
        submitWithPasskeyAssertion(ctx, { challengeIndex: MAX - CHALLENGE_PREFIX_LEN - 1n }),
        (e: unknown) => {
          assertCleanDecline(e, "challengeIndex = 2**256 - 58");
          return true;
        },
      );
    });

    it("ERC-1271: the same overflowing challengeIndex must return 0xffffffff, not revert the staticcall", async function () {
      const ctx = await loadFixture(deployFixture);
      const { digest, sig } = buildErc1271Payload(ctx, (d) =>
        encodeSignatureWrapper(0n, passkeyAssertion(d, PASSKEY_PRIV, { challengeIndex: MAX - 1n })),
      );
      // ERC-1271 REQUIRES a bytes4 return. A revert here is a spec violation on top of the DoS:
      // `SignatureChecker.isValidERC1271SignatureNow` swallows it as `false`, so a caller that
      // uses it directly (or reads the return in an `eth_call`) sees an exception instead.
      const result = await ctx.account.read.isValidSignature([digest, sig]);
      assert.strictEqual(result, ERC1271_INVALID);
    });

    it("V3 REGRESSION GUARD: an out-of-range typeIndex still declines cleanly (this bound is currently the ONLY one of the two that exists)", async function () {
      const ctx = await loadFixture(deployFixture);
      // 2**255 is the value the V3 NatSpec records as having hard-reverted on memory expansion
      // before the bound was added; type(uint256).max wrapped harmlessly even then. Both must
      // decline now.
      for (const typeIndex of [2n ** 255n, MAX - 1n, 9999n]) {
        await assert.rejects(submitWithPasskeyAssertion(ctx, { typeIndex }), (e: unknown) => {
          assertCleanDecline(e, `typeIndex = ${typeIndex}`);
          return true;
        });
      }
    });

    it("neither bound rejects a LEGITIMATE assertion (the fix must not cost availability)", async function () {
      const ctx = await loadFixture(deployFixture);
      const receipt = await submitWithPasskeyAssertion(ctx, {});
      assert.ok(
        opSucceeded(receipt, ctx.entryPoint.abi),
        "a real assertion, with the real typeIndex/challengeIndex, must still validate",
      );
    });

    it("index sweep: NO challengeIndex/typeIndex pair may ever hard-revert validateUserOp", async function () {
      const ctx = await loadFixture(deployFixture);
      // Deliberately biased to REACH `_validateChallenge`: `typeIndex` is left at its real value
      // for the challengeIndex rows, because `WebAuthn.verify` short-circuits on the type check
      // first. An unbiased random fuzz never gets past that and reports a false all-clear.
      const rows: { label: string; challengeIndex?: bigint; typeIndex?: bigint }[] = [
        { label: "ci=0", challengeIndex: 0n },
        { label: "ci=1", challengeIndex: 1n },
        { label: "ci=len-1", challengeIndex: 105n },
        { label: "ci=2**64", challengeIndex: 2n ** 64n },
        { label: "ci=2**128", challengeIndex: 2n ** 128n },
        { label: "ci=2**255", challengeIndex: 2n ** 255n },
        { label: "ci=2**256-1000", challengeIndex: MAX - 1000n },
        { label: "ci=2**256-58", challengeIndex: MAX - 58n },
        { label: "ci=2**256-57", challengeIndex: MAX - 57n },
        { label: "ci=2**256-2", challengeIndex: MAX - 2n },
        { label: "ci=2**256-1", challengeIndex: MAX - 1n },
        { label: "ti=2**255", typeIndex: 2n ** 255n },
        { label: "ti=2**256-1", typeIndex: MAX - 1n },
        { label: "both max", challengeIndex: MAX - 1n, typeIndex: MAX - 1n },
      ];
      const hardReverts: string[] = [];
      for (const row of rows) {
        try {
          await submitWithPasskeyAssertion(ctx, row);
          hardReverts.push(`${row.label}: ACCEPTED (a forged assertion validated!)`);
        } catch (e: unknown) {
          if (!isCleanDecline(e)) hardReverts.push(`${row.label}: ${describeFailure(e)}`);
        }
      }
      assert.deepStrictEqual(
        hardReverts,
        [],
        "every index value must produce SIG_VALIDATION_FAILED (AA24); a hard revert here is the " +
          "round-1 defect class recurring",
      );
    });
  });

  // ==========================================================================================
  // the V1 `len > signature.length - 128` rewrite, re-derived on EVERY path into the
  // decoder. The subtraction is only safe because `signature.length >= 128` is established at the
  // top of the SAME function against the SAME buffer. The ERC-1271/ERC-7739 path is the one where
  // that could plausibly have been violated: there the outer `signature` argument is long, but
  // what actually reaches `_decodeSignatureWrapper` is `innerSignature`, a SHORTER calldata slice
  // carved out by `ERC7739Utils.decodeTypedDataSig`. If the length check had been applied to the
  // outer buffer and the slice taken from the inner one, `signature.length - 128` would underflow.
  // ==========================================================================================
  describe("_decodeSignatureWrapper length arithmetic, on every entry path", function () {
    it("a 128-byte buffer declaring len=0 declines cleanly (exact boundary of the subtraction — underflow would be Panic 0x11)", async function () {
      const ctx = await loadFixture(deployFixture);
      const raw = concatHex([word(0x20n), word(0n), word(0x40n), word(0n)]);
      await assert.rejects(submitWithRawSignature(ctx, raw), (e: unknown) => {
        assertCleanDecline(e, "128-byte buffer, len=0");
        return true;
      });
    });

    it("a 128-byte buffer declaring len=1 (one byte past the end) declines cleanly", async function () {
      const ctx = await loadFixture(deployFixture);
      const raw = concatHex([word(0x20n), word(0n), word(0x40n), word(1n)]);
      await assert.rejects(submitWithRawSignature(ctx, raw), (e: unknown) => {
        assertCleanDecline(e, "128-byte buffer, len=1");
        return true;
      });
    });

    it("ERC-1271: an inner signature SHORTER than 128 bytes inside a LONG 7739 envelope returns 0xffffffff (the slice, not the envelope, must drive the length check)", async function () {
      const ctx = await loadFixture(deployFixture);
      // 65 bytes — a bare ECDSA signature, i.e. what an integrator would send if they forgot the
      // SignatureWrapper. The full envelope is 65 + 32 + 32 + descr + 2 = well over 128 bytes, so
      // a decoder that measured the OUTER buffer would sail past its own guard.
      const { digest, sig } = buildErc1271Payload(ctx, () => ("0x" + "11".repeat(65)) as Hex);
      assert.strictEqual(await ctx.account.read.isValidSignature([digest, sig]), ERC1271_INVALID);
    });

    it("ERC-1271: an inner signature of EXACTLY 128 bytes declaring len=type(uint256).max returns 0xffffffff", async function () {
      const ctx = await loadFixture(deployFixture);
      const inner = concatHex([word(0x20n), word(0n), word(0x40n), word(2n ** 256n - 1n)]);
      const { digest, sig } = buildErc1271Payload(ctx, () => inner);
      assert.strictEqual(await ctx.account.read.isValidSignature([digest, sig]), ERC1271_INVALID);
    });

    it("ERC-1271: a zero-length inner signature returns 0xffffffff", async function () {
      const ctx = await loadFixture(deployFixture);
      const { digest, sig } = buildErc1271Payload(ctx, () => "0x" as Hex);
      assert.strictEqual(await ctx.account.read.isValidSignature([digest, sig]), ERC1271_INVALID);
    });
  });

  // ==========================================================================================
  // (MAJOR) — `StarzipWalletFactory.getAddress` predicts addresses that `createAccount` can
  // NEVER deploy. The factory's own NatSpec says it "does not duplicate that validation, it only
  // predicts and deploys" — but in a counterfactual-address wallet, PREDICTING is the dangerous
  // half: the user is told an address and funds it BEFORE any deployment happens. Because the
  // owner set is baked into the CREATE2 initcode hash, an address predicted from a rejected owner
  // set has exactly one possible initcode, and that initcode always reverts. Anything sent there
  // is unrecoverable — there is no second chance with a corrected owner set at the same address.
  //
  // The realistic trigger is the duplicate: a client that re-registers an authenticator the user
  // has already registered builds `[P, P]`, gets a plausible address back, and shows it.
  // ==========================================================================================
  describe("factory prediction vs. deployability", function () {
    const DUP = encodeAddressOwner("0x00000000000000000000000000000000000000a1" as Address);

    // Each row: an owner set `createAccount` rejects, and the error it rejects with.
    const UNDEPLOYABLE: { label: string; owners: Hex[]; error: string }[] = [
      { label: "duplicate element [A,A]", owners: [DUP, DUP], error: "AlreadyOwner" },
      { label: "empty array []", owners: [], error: "InvalidArrayLength" },
      { label: "zero address", owners: [encodeAddressOwner(zeroAddress)], error: "ZeroAddress" },
      {
        label: "33-byte element",
        owners: [("0x" + "11".repeat(33)) as Hex],
        error: "InvalidOwnerBytesLength",
      },
      { label: "empty element", owners: ["0x" as Hex], error: "InvalidOwnerBytesLength" },
      {
        label: "off-curve passkey",
        owners: [("0x" + "22".repeat(64)) as Hex],
        error: "InvalidPublicKey",
      },
    ];

    it("every rejected owner set is rejected at the SINGLE _registerOwner choke point, with its own named error", async function () {
      const ctx = await loadFixture(deployFixture);
      for (const row of UNDEPLOYABLE) {
        await assert.rejects(
          ctx.factory.write.createAccount([row.owners, 4242n], { account: ctx.deployer.account }),
          new RegExp(row.error),
          `${row.label} must be rejected with ${row.error}`,
        );
      }
    });

    it("a 32-byte element with DIRTY high bits (not a clean abi.encode(address)) is rejected too — so it can never reach _verifyOwnerSignature's abi.decode", async function () {
      const ctx = await loadFixture(deployFixture);
      // abi.decode(bytes, (address)) reverts on non-zero padding. If such a blob could ever be
      // STORED, every later signature check naming that index would revert instead of returning
      // SIG_VALIDATION_FAILED. `_registerOwner` decoding it at write time is what makes the read
      // path total; this test pins that.
      const dirty = ("0x" + "ff".repeat(32)) as Hex;
      await assert.rejects(
        ctx.factory.write.createAccount([[dirty], 4243n], { account: ctx.deployer.account }),
        "a 32-byte owner blob with dirty padding must never be registered",
      );
    });

    it("KNOWN GAP (extends GAP-1 to the whole family): getAddress predicts a fundable address for EVERY owner set createAccount rejects", async function () {
      const ctx = await loadFixture(deployFixture);
      // test/StarzipWallet_issueToken_e2e.test.ts's "GAP-1" already pins this for ONE input
      // (owner == address(0)). It is not a one-off: `getAddress` runs NO owner-set validation at
      // all, so the same silence covers the whole rejected family below — including
      // `[A, A]`, the only member a correct-looking client can hit by accident (re-registering an
      // authenticator the user already registered).
      //
      // Why it costs money rather than just being untidy: this is a counterfactual-address
      // wallet. The address is handed to the user and FUNDED BEFORE any deployment. The owner set
      // is baked into the CREATE2 initcode hash, so an address predicted from a rejected owner set
      // has exactly one possible initcode and that initcode always reverts — the address can never
      // be deployed with a corrected owner set, and anything sent there is unrecoverable.
      //
      // THIS TEST DELIBERATELY ASSERTS THE CURRENT (permissive) BEHAVIOUR. If validation is ever
      // added to `getAddress` — or a `validateOwners()` view is added and made mandatory for
      // clients — INVERT this test rather than deleting it. Measured cost of adding the validation
      // directly to `getAddress`, for whoever makes that call: it breaks exactly two existing
      // tests, both of which feed it deliberately-invalid input
      // (StarzipWalletFactory.test.ts's differing-second-owner case passes `[first, first]`, and
      // GAP-1 itself passes `owner == address(0)`).
      for (const row of UNDEPLOYABLE) {
        const predicted = (await ctx.factory.read.getAddress([row.owners, 4242n])) as Address;
        assert.match(predicted, /^0x[0-9a-fA-F]{40}$/, `${row.label} still predicts an address`);
        assert.strictEqual(
          await ctx.publicClient.getCode({ address: predicted }),
          undefined,
          `${row.label}: nothing is deployed there, and nothing ever can be`,
        );
        await assert.rejects(
          ctx.factory.write.createAccount([row.owners, 4242n], { account: ctx.deployer.account }),
          new RegExp(row.error),
          `${row.label}: the address getAddress just returned is permanently undeployable`,
        );
      }
    });

    it("the FULL owner set (and its ORDER) is bound into the CREATE2 address", async function () {
      const ctx = await loadFixture(deployFixture);
      const a = encodeAddressOwner("0x00000000000000000000000000000000000000a1" as Address);
      const b = encodeAddressOwner("0x00000000000000000000000000000000000000a2" as Address);
      const ab = (await ctx.factory.read.getAddress([[a, b], 7n])) as Address;
      const ba = (await ctx.factory.read.getAddress([[b, a], 7n])) as Address;
      const aOnly = (await ctx.factory.read.getAddress([[a], 7n])) as Address;
      assert.notStrictEqual(ab, ba, "[A,B] and [B,A] must not collide");
      assert.notStrictEqual(ab, aOnly, "a subset must not collide with its superset");
      // Order sensitivity is a CLIENT contract, not just an implementation detail: restoring a
      // wallet from a backed-up owner list in a different order silently yields a DIFFERENT,
      // empty wallet rather than an error.
      const deployed = await ctx.factory.write.createAccount([[a, b], 7n], {
        account: ctx.deployer.account,
      });
      await ctx.publicClient.waitForTransactionReceipt({ hash: deployed });
      assert.ok((await ctx.publicClient.getCode({ address: ab })) !== undefined);
      assert.strictEqual(
        await ctx.publicClient.getCode({ address: ba }),
        undefined,
        "the reversed-order address must still be empty",
      );
    });

    it("the 'already deployed' short-circuit returns the wallet's CURRENT owner set, which may no longer match the owners argument", async function () {
      const { viem } = await getConnection();
      const ctx = await loadFixture(passthroughOwnerFixture);
      const stillRequested = ctx.initialOwners;
      // The wallet has since dropped owner index 1 through a normal owner-authorized removal.
      await ctx.self(
        encodeFunctionData({
          abi: ctx.w.abi,
          functionName: "removeOwnerAtIndex",
          args: [1n, stillRequested[1]],
        }),
      );
      assert.strictEqual(
        (await ctx.w.read.isOwnerBytes([stillRequested[1]])) as boolean,
        false,
        "precondition: the second owner is gone",
      );
      const { result } = await ctx.factory.simulate.createAccount([stillRequested, ctx.salt], {
        account: ctx.deployer.account,
      });
      assert.strictEqual(
        (result as string).toLowerCase(),
        ctx.walletAddr.toLowerCase(),
        "createAccount returns the existing wallet unchanged",
      );
      // Caller beware: a successful createAccount is NOT a guarantee that `owners` are the
      // wallet's owners. Only getOwners() answers that.
      const live = (await ctx.w.read.getOwners()) as Hex[];
      assert.strictEqual(live.length, stillRequested.length - 1);
      assert.ok(
        !live.includes(stillRequested[1]),
        "the requested owner set names an owner the returned wallet no longer has",
      );
      void viem;
    });
  });

  // ==========================================================================================
  // `getOwners()` COMPACTS; `removeOwnerAtIndex` and `SignatureWrapper.ownerIndex` do NOT.
  // After any removal the two numbering schemes diverge. The question is whether that divergence
  // can be turned into removing/authorising the WRONG owner. It cannot — `expectedOwner` is a
  // byte-for-byte equality check, so a mismatched pair always reverts rather than acting on the
  // wrong slot. Recorded as REFUTED, with the residual (a confusing revert, and a signature that
  // silently fails to validate) pinned so it is not re-raised as a security issue.
  // ==========================================================================================
  describe("getOwners() compaction vs. sparse storage indices", function () {
    it("compacted positions diverge from storage indices after a middle removal", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);
      await ctx.self(
        encodeFunctionData({
          abi: ctx.w.abi,
          functionName: "removeOwnerAtIndex",
          args: [1n, ctx.initialOwners[1]],
        }),
      );
      const list = (await ctx.w.read.getOwners()) as Hex[];
      assert.deepStrictEqual(list, [
        ctx.initialOwners[0],
        ctx.initialOwners[2],
        ctx.initialOwners[3],
      ]);
      assert.strictEqual((await ctx.w.read.ownerAtIndex([1n])) as Hex, "0x", "slot 1 is now empty");
      assert.strictEqual(
        (await ctx.w.read.ownerAtIndex([2n])) as Hex,
        list[1],
        "the owner at compacted position 1 actually lives at storage index 2",
      );
      assert.strictEqual(
        (await ctx.w.read.nextOwnerIndex()) as bigint,
        4n,
        "indices are never reused",
      );
      assert.strictEqual((await ctx.w.read.ownerCount()) as bigint, BigInt(list.length));
    });

    it("REFUTED: feeding a compacted position to removeOwnerAtIndex can never remove the WRONG owner — expectedOwner forces a revert", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);
      await ctx.self(
        encodeFunctionData({
          abi: ctx.w.abi,
          functionName: "removeOwnerAtIndex",
          args: [1n, ctx.initialOwners[1]],
        }),
      );
      const list = (await ctx.w.read.getOwners()) as Hex[];
      const before = (await ctx.w.read.ownerCount()) as bigint;
      // A naive UI walks the compacted list and calls removeOwnerAtIndex(position, list[position]).
      // Position 1 and 2 both name a DIFFERENT slot than the owner they carry.
      for (const position of [1n, 2n]) {
        await assert.rejects(
          ctx.self(
            encodeFunctionData({
              abi: ctx.w.abi,
              functionName: "removeOwnerAtIndex",
              args: [position, list[Number(position)]],
            }),
          ),
          /NoSuchOwner|OwnerMismatch/,
          `compacted position ${position} must not silently remove storage index ${position}`,
        );
      }
      assert.strictEqual((await ctx.w.read.ownerCount()) as bigint, before, "nothing was removed");
    });

    it("a compacted position used as SignatureWrapper.ownerIndex simply fails to validate (footgun, not a hole)", async function () {
      const ctx = await loadFixture(deployFixture);
      // Add a second passkey, remove owner 0, so the surviving passkey is at compacted position 0
      // but storage index 1.
      const add = encodeFunctionData({
        abi: ctx.account.abi,
        functionName: "addOwnerPublicKey",
        args: [PK2_X, PK2_Y],
      });
      assert.ok(opSucceeded(await selfCall(ctx, add, PASSKEY_PRIV, 0n), ctx.entryPoint.abi));
      const remove = encodeFunctionData({
        abi: ctx.account.abi,
        functionName: "removeOwnerAtIndex",
        args: [0n, encodePasskeyOwner(PK_X, PK_Y)],
      });
      assert.ok(
        opSucceeded(await selfCall(ctx, remove, SECOND_PASSKEY_PRIV, 1n), ctx.entryPoint.abi),
      );
      const list = (await ctx.account.read.getOwners()) as Hex[];
      assert.deepStrictEqual(list, [encodePasskeyOwner(PK2_X, PK2_Y)], "one owner, at position 0");

      // Signing as "owner 0" (its compacted position) fails; storage index 1 succeeds.
      await assert.rejects(submitSigned(ctx, SECOND_PASSKEY_PRIV, 0n), (e: unknown) => {
        assertCleanDecline(e, "compacted position used as ownerIndex");
        return true;
      });
      assert.ok(
        opSucceeded(await submitSigned(ctx, SECOND_PASSKEY_PRIV, 1n), ctx.entryPoint.abi),
        "the STORAGE index is the one SignatureWrapper.ownerIndex means",
      );
    });

    it("getOwners().length == ownerCount survives heavy add/remove churn (a desync would make getOwners revert or pad with empties)", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);
      for (let i = 0; i < 12; i++) {
        const extra = ("0x" + (0x1000 + i).toString(16).padStart(40, "0")) as Address;
        await ctx.self(
          encodeFunctionData({ abi: ctx.w.abi, functionName: "addOwnerAddress", args: [extra] }),
        );
        await ctx.self(
          encodeFunctionData({
            abi: ctx.w.abi,
            functionName: "removeOwnerAtIndex",
            args: [BigInt(4 + i), encodeAddressOwner(extra)],
          }),
        );
      }
      const list = (await ctx.w.read.getOwners()) as Hex[];
      assert.strictEqual((await ctx.w.read.nextOwnerIndex()) as bigint, 16n);
      assert.strictEqual((await ctx.w.read.ownerCount()) as bigint, 4n);
      assert.strictEqual(list.length, 4);
      assert.ok(
        list.every((o) => o !== "0x"),
        "no empty slot may leak into getOwners()",
      );
      assert.deepStrictEqual(list, ctx.initialOwners);
    });
  });

  // ==========================================================================================
  // cross-owner interference in the no-quorum, no-timelock model. All of these are
  // ACCEPTED behaviour per removeOwnerAtIndex's NatSpec; they are pinned here so that the day
  // someone adds a removal timelock or a self-only restriction, the blast radius is visible.
  // ==========================================================================================
  describe("cross-owner interference (accepted residuals, pinned)", function () {
    it("LastOwner cannot be defeated by draining the owner set inside ONE executeBatch", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);
      const rm = (i: number) =>
        encodeFunctionData({
          abi: ctx.w.abi,
          functionName: "removeOwnerAtIndex",
          args: [BigInt(i), ctx.initialOwners[i]],
        });
      await assert.rejects(
        ctx.selfBatch([rm(1), rm(2), rm(3), rm(0)]),
        /LastOwner/,
        "a batch must not be able to reach an ownerless (permanently locked) wallet",
      );
      assert.strictEqual(
        (await ctx.w.read.ownerCount()) as bigint,
        4n,
        "the batch rolled back whole",
      );

      // ...and the same holds one call at a time.
      await ctx.self(rm(1));
      await ctx.self(rm(2));
      await ctx.self(rm(3));
      assert.strictEqual((await ctx.w.read.ownerCount()) as bigint, 1n);
      await assert.rejects(ctx.self(rm(0)), /LastOwner/);
    });

    it("the documented first-mover attack really does leave the upgrade ARMED: batch [removeOwner(other), requestUpgrade(evil)]", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);
      const evil = ctx.factory.address; // any address with code
      const rmOther = encodeFunctionData({
        abi: ctx.w.abi,
        functionName: "removeOwnerAtIndex",
        args: [1n, ctx.initialOwners[1]],
      });
      const req = encodeFunctionData({
        abi: ctx.w.abi,
        functionName: "requestUpgrade",
        args: [evil],
      });
      await ctx.selfBatch([rmOther, req]);
      assert.strictEqual(
        ((await ctx.w.read.pendingImplementation()) as Address).toLowerCase(),
        evil.toLowerCase(),
        "removal-then-request survives the hygiene cancel because the cancel fires on a staging " +
          "that does not exist yet — exactly as UPGRADE_GRACE_PERIOD's NatSpec describes",
      );
      assert.strictEqual((await ctx.w.read.ownerCount()) as bigint, 3n);
    });

    it("the reverse order silently disarms it: batch [requestUpgrade(x), addOwner(y)] ends with NO pending upgrade", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);
      const req = encodeFunctionData({
        abi: ctx.w.abi,
        functionName: "requestUpgrade",
        args: [ctx.factory.address],
      });
      const add = encodeFunctionData({
        abi: ctx.w.abi,
        functionName: "addOwnerAddress",
        args: ["0x00000000000000000000000000000000000000b1" as Address],
      });
      await ctx.selfBatch([req, add]);
      assert.strictEqual(
        (await ctx.w.read.pendingImplementation()) as Address,
        zeroAddress,
        "the batch-ordering footgun on _cancelPendingUpgradeOnOwnerChange is real and worst-case " +
          "benign: a legitimate upgrade fails to arm, never an illegitimate one arming",
      );
    });

    it("a stale index reverts NoSuchOwner and a wrong expectedOwner at a LIVE index reverts OwnerMismatch (racing removals cannot cross)", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);
      await ctx.self(
        encodeFunctionData({
          abi: ctx.w.abi,
          functionName: "removeOwnerAtIndex",
          args: [1n, ctx.initialOwners[1]],
        }),
      );
      await assert.rejects(
        ctx.self(
          encodeFunctionData({
            abi: ctx.w.abi,
            functionName: "removeOwnerAtIndex",
            args: [1n, ctx.initialOwners[1]],
          }),
        ),
        /NoSuchOwner/,
        "a second signer racing the same removal must not fall through onto another slot",
      );
      await assert.rejects(
        ctx.self(
          encodeFunctionData({
            abi: ctx.w.abi,
            functionName: "removeOwnerAtIndex",
            args: [2n, ctx.initialOwners[1]],
          }),
        ),
        /OwnerMismatch/,
      );
      assert.strictEqual((await ctx.w.read.ownerCount()) as bigint, 3n);
    });
  });
});
