/**
 * StarzipWallet — PUBLIC-AUDIT MAP.
 *
 * Maps the published findings of the four public audits of `coinbase/smart-wallet` — the reference
 * design this wallet's multi-owner model is an INDEPENDENT REIMPLEMENTATION of (see
 * StarzipWallet.sol's contract-level NatSpec) — onto our own code:
 *
 *   - Code4rena, March 2024              (findings cited as "C4 <id>")
 *   - Cantina, April 2024                (cited as "Cantina-Apr <section>")
 *   - Cantina, December 2023             (cited as "Cantina-Dec <section>")
 *   - Certora formal verification, Feb 2024 (cited as "Certora <id>")
 *
 * Every test title starts with the upstream finding ID it maps. A finding lands in one of four
 * buckets, and the test says which:
 *   (a) STRUCTURALLY ABSENT — we never built the feature the finding attaches to (C4 H-01's
 *       `executeWithoutChainIdValidation` is the headline case). The test pins the ABSENCE, so the
 *       day someone adds the feature back the guard fires.
 *   (b) CLOSED — we have the check upstream lacked. The test proves the check exists AND (for the
 *       tests marked LOAD-BEARING) that removing it actually breaks something.
 *   (c) RESIDUAL — applies to us, accepted, pinned so it is not rediscovered as "new".
 *   (d) DIVERGENT — we deliberately do the opposite (C4 L-01's owner cap).
 *
 * MUTATION-TESTED. Every test marked LOAD-BEARING was paired with a single-line mutation of
 * contracts/wallet/StarzipWallet.sol (or StarzipWalletFactory.sol) applied to the WORKING TREE with a
 * `cp` backup taken first, recompiled, re-run, and restored by `cp` — `git checkout` / `git
 * restore` / `git stash` were never used, because the tree carries uncommitted work. The OBSERVED
 * effect of each mutation is recorded in the comment block above the test it belongs to, so a
 * future reader can tell a real guard from a vacuous assertion without re-deriving it.
 *
 * Several tests use a deliberate "try / prove the consequence / then fail" shape: on clean code
 * they simply assert the guard holds, but if the guard is ever removed they first EXERCISE the
 * resulting broken behaviour and put the observed EntryPoint error (or return value) into the
 * assertion message. That is what makes the mutation runs self-documenting.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";
import {
  parseEther,
  hexToBytes,
  encodeFunctionData,
  parseEventLogs,
  concatHex,
  encodeAbiParameters,
  sha256,
  keccak256,
  stringToHex,
  pad,
  toHex,
  hashStruct,
  hashTypedData,
  zeroAddress,
  type Hex,
  type Address,
} from "viem";
import { p256 } from "@noble/curves/p256";
import { loadFixture, getConnection, time } from "./helpers.js";
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

const WALLET_SOURCE_PATH = new URL("../contracts/wallet/StarzipWallet.sol", import.meta.url).pathname;

const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const SECOND_PASSKEY_PRIV = hexToBytes(
  "0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464" as Hex,
);
const { x: PK_X, y: PK_Y } = passkeyPubCoords(PASSKEY_PRIV);
const { x: PK2_X, y: PK2_Y } = passkeyPubCoords(SECOND_PASSKEY_PRIV);

const SALT = 8112026n;
const ERC1271_MAGIC = "0x1626ba7e";
const ERC1271_INVALID = "0xffffffff";

/** RIP-7212 / EIP-7212 P-256 verification precompile address. */
const P256_PRECOMPILE = "0x0000000000000000000000000000000000000100" as Address;

const word = (v: bigint): Hex => pad(toHex(v), { size: 32 });

/** viem reports "no code" as `undefined` on some paths and `"0x"` on others. Normalize. */
const isEmptyCode = (code: Hex | undefined): boolean => code === undefined || code === "0x";

/**
 * Strip Solidity comments so a source-scanning assertion counts CODE, not prose. Without this,
 * every structural guard below is defeated by the file's own (very extensive) NatSpec — e.g.
 * `P256.isValidPublicKey` appears twice in StarzipWallet.sol, once at :444 inside `_registerOwner`'s
 * doc comment and once at :455 as the actual check. Counting raw text would have made the C4 L-04
 * choke-point assertion depend on how the function happens to be documented.
 */
const stripComments = (src: string): string =>
  src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

// ============================================================================================
// Fixtures
// ============================================================================================

/** Single passkey owner (index 0) on a REAL EntryPoint v0.8 — the money path. */
async function deployFixture() {
  const { viem } = await getConnection();
  const [deployer, beneficiary] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();
  const chainId = await publicClient.getChainId();

  const entryPoint = await viem.deployContract("TestEntryPoint", []);
  const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, zeroAddress]);

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

/**
 * 4-owner wallet on `PassthroughEntryPoint`, so owner-set state-machine probes can drive
 * `onlySelf` admin calls without producing a passkey assertion per step. Same shape the
 * adversarial suite uses, and for the same reason (see PassthroughEntryPoint's
 * NatSpec): the code under test — `onlyEntryPoint` + `execute` + `onlySelf` — is byte-for-byte
 * the production path, only the 4337 validation other suites already cover is skipped.
 */
async function passthroughOwnerFixture() {
  const { viem } = await getConnection();
  const [deployer] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();
  const pep = await viem.deployContract("PassthroughEntryPoint", []);
  const factory = await viem.deployContract("StarzipWalletFactory", [pep.address, zeroAddress]);
  const salt = 811202601n;
  const initialOwners: Hex[] = [
    encodePasskeyOwner(PK_X, PK_Y),
    encodeAddressOwner("0x00000000000000000000000000000000000000c1" as Address),
    encodeAddressOwner("0x00000000000000000000000000000000000000c2" as Address),
    encodeAddressOwner("0x00000000000000000000000000000000000000c3" as Address),
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

/** Passthrough entry point + the reentrancy trigger mock (C4 L-05). */
async function reentrancyFixture() {
  const { viem } = await getConnection();
  const [deployer] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();
  const pep = await viem.deployContract("PassthroughEntryPoint", []);
  const factory = await viem.deployContract("StarzipWalletFactory", [pep.address, zeroAddress]);
  const owner = encodePasskeyOwner(PK_X, PK_Y);
  await factory.write.createAccount([[owner], SALT], { account: deployer.account });
  const walletAddr = (await factory.read.getAddress([[owner], SALT])) as Address;
  const account = await viem.getContractAt("StarzipWallet", walletAddr);
  const trigger = await viem.deployContract("ReentrantExecuteTrigger", []);
  return { viem, publicClient, pep, factory, account, walletAddr, deployer, trigger };
}

// ============================================================================================
// Shared probe helpers (kept local so they cannot perturb the 800+ tests that depend on
// aa-helpers.ts — same policy the adversarial suite adopted).
// ============================================================================================

function opSucceeded(receipt: any, entryPointAbi: any): boolean {
  const ev = parseEventLogs({
    abi: entryPointAbi,
    logs: receipt.logs,
    eventName: "UserOperationEvent",
  });
  return ev.length > 0 && (ev[0] as any).args.success === true;
}

/** Everything viem knows about a rejected tx, flattened — the EntryPoint's `AA__` code lives on
 *  `.details`, not `.message`, and sometimes only on a nested `.cause`. */
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

function describeFailure(e: unknown): string {
  const t = failureText(e);
  const m = t.match(/FailedOpWithRevert\([^)]*\)|FailedOp\([^)]*\)/);
  return m ? m[0] : t.slice(0, 240);
}

/** A clean decline = `SIG_VALIDATION_FAILED` surfaced as `FailedOp(_, "AA24 signature error")`.
 *  `FailedOpWithRevert(_, "AA23 reverted", ...)` means `validateUserOp` THREW, which it must never
 *  do — that distinction is the entire point of the Cantina-Dec 3.1.3 and 3.1.5 tests below. */
const isCleanDecline = (e: unknown): boolean => /AA24 signature error/.test(failureText(e));

function assertCleanDecline(e: unknown, label: string): void {
  assert.ok(
    isCleanDecline(e),
    `${label}: validateUserOp must DECLINE (EntryPoint "AA24 signature error"), never revert. Got: ${describeFailure(e)}`,
  );
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

/**
 * A real, correctly-signed WebAuthn assertion, with `authenticatorData`'s LENGTH overridable —
 * `webauthnSignature` in aa-helpers.ts always emits the canonical 37 bytes, so it cannot express
 * the 36-byte payload Cantina-Dec 3.1.5 is about.
 */
function passkeyAssertionWithAuthDataLen(
  challenge: Hex,
  priv: Uint8Array,
  authDataLen: number,
): Hex {
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${base64url(hexToBytes(challenge))}","origin":"https://starzip.io"}`;
  const challengeIndex = BigInt(clientDataJSON.indexOf('"challenge":"'));
  const typeIndex = BigInt(clientDataJSON.indexOf('"type":"webauthn.get"'));
  // Canonical layout is rpIdHash(32) ‖ flags(1) ‖ signCount(4) = 37. Truncate/extend the trailing
  // signCount field to hit `authDataLen` exactly, keeping rpIdHash + flags intact so the payload
  // is otherwise indistinguishable from a genuine assertion.
  const full = concatHex([sha256(toHex("starzip.io")), "0x05", "0x00000000"]);
  const authenticatorData = ("0x" + full.slice(2, 2 + authDataLen * 2)) as Hex;
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

/**
 * A well-formed ERC-7739 `TypedDataSign` envelope over a fixed `Mail` struct.
 * `walletDomainOverride` lets a probe build the envelope under a DIFFERENT wallet domain than the
 * real one — which is exactly how the C4 H-01 chain-binding tests distinguish "the wallet's domain
 * really carries chainId" from "the wallet accepts anything".
 */
function buildErc1271Payload(
  ctx: any,
  sign: (digest: Hex) => Hex,
  walletDomainOverride?: Eip712Domain,
): { digest: Hex; sig: Hex } {
  const appDomain: Eip712Domain = {
    name: "ExampleApp",
    version: "1",
    chainId: ctx.chainId,
    verifyingContract: APP_VERIFYING_CONTRACT,
  };
  const appSeparator = domainSeparator(appDomain);
  const contentsHash = hashStruct({ data: MAIL_MESSAGE, primaryType: "Mail", types: MAIL_TYPES });
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
    walletDomain: walletDomainOverride ?? ctx.walletDomain,
    sign,
  });
  return { digest, sig };
}

// ---- EntryPoint v0.8 userOpHash reconstruction (C4 H-01) -------------------------------------
// EntryPoint.getUserOpHash = MessageHashUtils.toTypedDataHash(getDomainSeparatorV4(),
// userOp.hash()), with the domain EIP712("ERC4337", "1") bound to (chainId, entryPoint). We
// recompute BOTH halves in TypeScript so a hash can be re-derived for a DIFFERENT chainId — and
// the reconstruction is self-checked against the live contract before it is trusted (see the
// test), so a wrong reimplementation fails loudly instead of silently proving nothing.
const PACKED_USEROP_TYPEHASH = keccak256(
  stringToHex(
    "PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)",
  ),
);

function userOpStructHash(op: ReturnType<typeof buildUserOp>): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [
        PACKED_USEROP_TYPEHASH,
        op.sender,
        op.nonce,
        keccak256(op.initCode),
        keccak256(op.callData),
        op.accountGasLimits,
        op.preVerificationGas,
        op.gasFees,
        keccak256(op.paymasterAndData),
      ],
    ),
  );
}

const toTypedDataHash = (separator: Hex, structHash: Hex): Hex =>
  keccak256(concatHex(["0x1901", separator, structHash]));

/** The EntryPoint's own EIP-712 domain separator for an arbitrary chainId. */
const entryPointSeparator = (chainId: number | bigint, entryPointAddr: Address): Hex =>
  domainSeparator({ name: "ERC4337", version: "1", chainId, verifyingContract: entryPointAddr });

// ============================================================================================

describe("StarzipWallet — public-audit map (coinbase/smart-wallet findings)", function () {
  // ==========================================================================================
  // C4 H-01 — CROSS-CHAIN REPLAY OF OWNER REMOVAL. Bucket: (a) STRUCTURALLY ABSENT.
  //
  // Upstream severity came entirely from `executeWithoutChainIdValidation`, a DELIBERATELY
  // chain-agnostic signing path Coinbase added so one signature could rotate owners on every
  // chain a counterfactual wallet exists on. Its digest omitted chainId by design, so a
  // `removeOwnerAtIndex` op signed once replayed everywhere — including chains the user had not
  // deployed to yet.
  //
  // We never built that path. Every execution in this wallet goes through `execute`/`executeBatch`,
  // both `onlyEntryPoint`, and the EntryPoint v0.8 challenge is `userOpHash` =
  // toTypedDataHash(EIP712("ERC4337","1", chainId, entryPoint), userOp.hash()) — chainId is inside
  // the domain separator, so the same signature cannot be valid on two chains. The ERC-1271
  // surface is bound a second time through the WALLET's own domain.
  // ==========================================================================================
  describe("C4 H-01: cross-chain replay of owner removal", function () {
    it("C4 H-01: the wallet exposes no chain-agnostic execution path", async function () {
      const { account, walletAddr, deployer, publicClient } = await loadFixture(deployFixture);

      const fns = (account.abi as any[]).filter((e) => e.type === "function");
      const stateChanging = fns.filter(
        (f) => f.stateMutability !== "view" && f.stateMutability !== "pure",
      );

      // 1) No function even NAMED like upstream's chain-agnostic path. This is the documentation-
      //    drift guard: if anyone ever ports `executeWithoutChainIdValidation` (or a rebrand of
      //    it) into this wallet, this fires before it reaches review.
      const suspicious = fns
        .map((f) => f.name as string)
        .filter((n) => /withoutChainId|chainAgnostic|crossChain|replayable/i.test(n));
      assert.deepStrictEqual(
        suspicious,
        [],
        "no function may advertise chain-agnostic execution — that IS C4 H-01's root cause",
      );

      // 2) The full state-changing surface is enumerated and classified. A new entry here is a
      //    deliberate decision, not an accident: the test fails until someone classifies it.
      const ENTRYPOINT_GATED = ["execute", "executeBatch", "validateUserOp"];
      const SELF_GATED = [
        "addOwnerAddress",
        "addOwnerPublicKey",
        "cancelUpgrade",
        "removeOwnerAtIndex",
        "requestUpgrade",
        "upgradeToAndCall",
      ];
      const INITIALIZER = ["initialize"];
      const RECEIVER_CALLBACKS = [
        "onERC721Received",
        "onERC1155Received",
        "onERC1155BatchReceived",
      ];
      const classified = [
        ...ENTRYPOINT_GATED,
        ...SELF_GATED,
        ...INITIALIZER,
        ...RECEIVER_CALLBACKS,
      ];
      const unclassified = stateChanging
        .map((f) => f.name as string)
        .filter((n) => !classified.includes(n));
      assert.deepStrictEqual(
        unclassified,
        [],
        "every state-changing selector must be classified; an unclassified one may be a new execution path",
      );

      // 3) The ONLY functions that forward attacker-chosen calldata to an arbitrary target are
      //    execute/executeBatch, and both are onlyEntryPoint — i.e. reachable only behind a
      //    chain-bound userOpHash. Called directly by an EOA they revert.
      await assert.rejects(
        account.write.execute([walletAddr, 0n, "0x"], { account: deployer.account }),
        /OnlyEntryPoint/,
        "execute must be onlyEntryPoint",
      );
      await assert.rejects(
        account.write.executeBatch([[walletAddr], [0n], ["0x"]], { account: deployer.account }),
        /OnlyEntryPoint/,
        "executeBatch must be onlyEntryPoint",
      );

      // 4) upgradeToAndCall also carries a `bytes` payload, but UUPS routes it through
      //    _authorizeUpgrade, which is onlySelf — so it is not a second execution entry point.
      await assert.rejects(
        account.write.upgradeToAndCall([account.address, "0x"], { account: deployer.account }),
        /OnlySelf/,
        "upgradeToAndCall must be onlySelf-gated via _authorizeUpgrade",
      );

      // 5) Sanity that we probed a live wallet, not an empty address.
      assert.ok(!isEmptyCode(await publicClient.getCode({ address: walletAddr })));
    });

    it("C4 H-01: a removeOwnerAtIndex userOp signed for one chainId fails on another", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, entryPoint, walletAddr, deployer, beneficiary, chainId, publicClient } = ctx;

      // Give the wallet a second owner so removeOwnerAtIndex(0, ...) is not blocked by LastOwner —
      // the op under test has to be a genuinely EXECUTABLE owner removal, exactly the operation
      // C4 H-01 replayed upstream.
      const addCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "addOwnerPublicKey",
        args: [PK2_X, PK2_Y],
      });
      assert.ok(opSucceeded(await selfCall(ctx, addCalldata, PASSKEY_PRIV, 0n), entryPoint.abi));

      const removeCalldata = encodeFunctionData({
        abi: account.abi,
        functionName: "removeOwnerAtIndex",
        args: [1n, encodePasskeyOwner(PK2_X, PK2_Y)],
      });
      const callData = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [walletAddr, 0n, removeCalldata],
      });
      const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(walletAddr, nonce, callData);

      // --- Self-check the reconstruction BEFORE trusting it to prove anything. -----------------
      const onChainSeparator = (await entryPoint.read.getDomainSeparatorV4()) as Hex;
      const localSeparator = entryPointSeparator(chainId, entryPoint.address);
      assert.strictEqual(
        localSeparator,
        onChainSeparator,
        "reconstruction check: our EIP712('ERC4337','1') separator must match the live EntryPoint's",
      );
      const structHash = userOpStructHash(userOp);
      const realHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
      assert.strictEqual(
        toTypedDataHash(localSeparator, structHash),
        realHash,
        "reconstruction check: toTypedDataHash(sep, userOp.hash()) must equal getUserOpHash()",
      );

      // --- The actual claim: re-derive the SAME op's hash as it would be on a different chain. --
      const otherChainId = BigInt(chainId) + 1n;
      const otherHash = toTypedDataHash(
        entryPointSeparator(otherChainId, entryPoint.address),
        structHash,
      );
      assert.notStrictEqual(
        otherHash,
        realHash,
        "chainId must actually change the challenge — otherwise nothing below proves anything",
      );

      // A signature produced for the OTHER chain's hash does not validate here.
      userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(otherHash, PASSKEY_PRIV));
      await assert.rejects(
        entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
          account: deployer.account,
        }),
        (e: unknown) => {
          assertCleanDecline(e, `owner-removal op signed for chainId ${otherChainId}`);
          return true;
        },
      );
      assert.strictEqual(
        (await account.read.ownerCount()) as bigint,
        2n,
        "the cross-chain-signed removal must NOT have taken effect",
      );

      // Control: the identical op signed for THIS chain does execute. Without this, the test above
      // would also pass against a wallet that rejects everything.
      const nonce2 = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const good = buildUserOp(walletAddr, nonce2, callData);
      const goodHash = (await entryPoint.read.getUserOpHash([good])) as Hex;
      good.signature = encodeSignatureWrapper(0n, webauthnSignature(goodHash, PASSKEY_PRIV));
      const h = await entryPoint.write.handleOps([[good], beneficiary.account.address], {
        account: deployer.account,
      });
      assert.ok(
        opSucceeded(await publicClient.waitForTransactionReceipt({ hash: h }), entryPoint.abi),
      );
      assert.strictEqual((await account.read.ownerCount()) as bigint, 1n);
    });

    // ------------------------------------------------------------------------------------------
    // LOAD-BEARING. Mutation: StarzipWallet.sol:720 — inside isValidSignature's
    //   abi.encode(keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt)
    // replace `chainId` with a hardcoded `uint256(1)`.
    //
    // OBSERVED (clean, this test PASSES):
    //   - assertion built with walletDomain.chainId = 31337 (the real chain) -> 0x1626ba7e
    //   - assertion built with walletDomain.chainId = 1     (a foreign chain) -> 0xffffffff
    //
    // OBSERVED (mutated, this test FAILS). It failed on its FIRST assertion:
    //     AssertionError: the wallet's ERC-1271 domain must carry the REAL chainId
    //       - Expected: 0x1626ba7e
    //       + Received: 0xffffffff
    //   i.e. the wallet stopped honouring assertions minted for its own chain. A direct probe run
    //   under the same mutation confirmed the full inversion, which the failing test could not
    //   reach because it aborts at the first assertion:
    //       realChain=31337, assertion built for chainId 31337 -> 0xffffffff  (REJECTED)
    //       realChain=31337, assertion built for chainId 1     -> 0x1626ba7e  (ACCEPTED)
    //   So the domain is no longer chain-bound: an assertion an owner signs for mainnet (chainId 1)
    //   is honoured by this wallet's deployment on every other chain at the same counterfactual
    //   address — which is exactly C4 H-01's cross-chain replay, moved onto the ERC-1271 surface.
    //
    //   WORTH RECORDING SEPARATELY: the same probe read `eip712Domain().chainId` and got 31337 —
    //   the CORRECT value — because `eip712Domain()` is untouched by this mutation and only
    //   `isValidSignature`'s local re-encoding of the domain was changed. The wallet would
    //   therefore ADVERTISE a chain-bound domain while VERIFYING against a different one, so no
    //   integrator or block explorer inspecting `eip712Domain()` could detect the divergence. That
    //   is an argument for keeping these two tests behavioural rather than trusting the accessor.
    // RESTORED: yes, by `cp /tmp/szbak/StarzipWallet.sol.orig`, recompiled, test re-run GREEN.
    // ------------------------------------------------------------------------------------------
    it("C4 H-01: ERC-1271 assertions are chain-bound through the wallet's OWN domain", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, chainId, walletAddr } = ctx;

      // Baseline: an assertion built under the wallet's REAL domain is accepted.
      const real = buildErc1271Payload(ctx, (d) =>
        encodeSignatureWrapper(0n, webauthnSignature(d, PASSKEY_PRIV)),
      );
      assert.strictEqual(
        await account.read.isValidSignature([real.digest, real.sig]),
        ERC1271_MAGIC,
        "the wallet's ERC-1271 domain must carry the REAL chainId",
      );

      // The same owner, the same app, the same order — but the nested digest was built under
      // chainId 1 instead of this chain. It must NOT validate.
      const foreignDomain: Eip712Domain = {
        name: WALLET_EIP712_NAME,
        version: WALLET_EIP712_VERSION,
        chainId: 1,
        verifyingContract: walletAddr,
      };
      const foreign = buildErc1271Payload(
        ctx,
        (d) => encodeSignatureWrapper(0n, webauthnSignature(d, PASSKEY_PRIV)),
        foreignDomain,
      );
      assert.strictEqual(
        await account.read.isValidSignature([foreign.digest, foreign.sig]),
        ERC1271_INVALID,
        "an assertion minted under a FOREIGN chainId must be rejected — this is the ERC-1271 half " +
          "of C4 H-01's chain-binding requirement",
      );

      // And the domain the wallet reports really is this chain's.
      const domain = (await account.read.eip712Domain()) as any[];
      assert.strictEqual(
        domain[3] as bigint,
        BigInt(chainId),
        "eip712Domain().chainId must be live",
      );
      assert.notStrictEqual(
        BigInt(chainId),
        1n,
        "sanity: the test chain must not itself be chainId 1",
      );
    });

    it("C4 H-01: indices are never reused, so an index can never silently name a different owner", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);

      // Upstream's severity was amplified because a stale signature could act on an index whose
      // MEANING had changed. Here `nextOwnerIndex` only ever increases (StarzipWallet.sol:139-141),
      // and `expectedOwner` is a byte-for-byte equality check (:400) — the adversarial
      // suite already pins the drift-revert side of that ("a stale index reverts NoSuchOwner and a
      // wrong expectedOwner at a LIVE index reverts OwnerMismatch"). This pins the complementary
      // structural fact: the slot is never recycled in the first place.
      const removedIndex = 1n;
      await ctx.self(
        encodeFunctionData({
          abi: ctx.w.abi,
          functionName: "removeOwnerAtIndex",
          args: [removedIndex, ctx.initialOwners[1]],
        }),
      );
      assert.strictEqual((await ctx.w.read.ownerAtIndex([removedIndex])) as Hex, "0x");

      const fresh = "0x00000000000000000000000000000000000000d9" as Address;
      const receipt = await ctx.publicClient.waitForTransactionReceipt({
        hash: await ctx.self(
          encodeFunctionData({ abi: ctx.w.abi, functionName: "addOwnerAddress", args: [fresh] }),
        ),
      });
      const added = parseEventLogs({
        abi: ctx.w.abi,
        logs: receipt.logs,
        eventName: "AddOwner",
      })[0] as any;

      assert.strictEqual(
        added.args.index as bigint,
        4n,
        "the new owner must land at a NEW index (4), not refill 1",
      );
      assert.notStrictEqual(added.args.index as bigint, removedIndex);
      assert.strictEqual(
        (await ctx.w.read.ownerAtIndex([removedIndex])) as Hex,
        "0x",
        "the vacated index must STAY empty — reuse is what would let a stale signature name a new owner",
      );
      assert.strictEqual((await ctx.w.read.nextOwnerIndex()) as bigint, 5n);

      // And the empty slot declines rather than reverting when named in a signature.
      assert.strictEqual((await ctx.w.read.isOwnerBytes([ctx.initialOwners[1]])) as boolean, false);
    });
  });

  // ==========================================================================================
  // C4 L-01 / Cantina-Dec 3.3.7 — NATSPEC CLAIMS AN OWNER CAP THE CODE DOES NOT ENFORCE.
  // Bucket: (d) DIVERGENT.
  //
  // Upstream `MultiOwnable` used a `uint8 ownerIndex`, so the owner set silently capped at 255
  // while the docs said otherwise. Ours is `uint256 nextOwnerIndex` (StarzipWallet.sol:141) —
  // there is NO cap at all, by construction. The finding therefore inverts: the risk is not a
  // hidden ceiling, it is the ABSENCE of one (see NEW-1 below, which is the consequence).
  // ==========================================================================================
  describe("C4 L-01 / Cantina-Dec 3.3.7: owner-count cap", function () {
    it("C4 L-01: no 255-owner ceiling exists — owner #256 registers and can sign", async function () {
      const { viem } = await getConnection();
      const [deployer, beneficiary] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const entryPoint = await viem.deployContract("TestEntryPoint", []);
      const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, zeroAddress]);

      // 257 owners: index 0 = passkey A, indices 1..255 = distinct EOAs, index 256 = passkey B.
      // 256 is chosen deliberately — it is the first index a `uint8` cursor CANNOT represent, so
      // an accidental narrowing anywhere in the owner-set code makes this test fail.
      //
      // HOW THEY ARE REGISTERED, and why it is not one `initialize` call: MEASURED at ~74k gas per
      // owner, 257 owners is ~19M, over Hardhat EDR's 16,777,216 block cap — and the provider
      // rejects on a MULTIPLIED estimate, so a single `createAccount` is refused from ~96 owners up
      // (observed: n=64 succeeds at 4,944,246; n=96 is refused before executing). So the wallet is
      // born with 33 owners via `initialize` and grown to 257 through owner-signed
      // `executeBatch([addOwnerAddress, ...])` userOps of at most MAX_BATCH_SIZE (32) — the
      // PRODUCTION add path, on a REAL EntryPoint v0.8, which if anything makes this stronger
      // evidence than one mega-initialize would have been.
      const FILLER = (i: number) =>
        encodeAddressOwner(("0x" + i.toString(16).padStart(40, "0")) as Address);

      const initialOwners: Hex[] = [encodePasskeyOwner(PK_X, PK_Y)];
      for (let i = 1; i <= 32; i++) initialOwners.push(FILLER(i));

      const salt = 25620260811n;
      await factory.write.createAccount([initialOwners, salt], { account: deployer.account });
      const walletAddr = (await factory.read.getAddress([initialOwners, salt])) as Address;
      const account = await viem.getContractAt("StarzipWallet", walletAddr);
      // Generously funded: each op's EntryPoint prefund is
      // (verificationGasLimit + callGasLimit + preVerificationGas) * maxFeePerGas, which at the
      // raised call gas below is ~0.8 ETH reserved per op (mostly refunded, but it must be
      // available up front).
      await deployer.sendTransaction({ to: walletAddr, value: parseEther("100") });
      assert.strictEqual((await account.read.ownerCount()) as bigint, 33n);

      /** One owner-signed `executeBatch` userOp adding `addrs` as owners. */
      async function addOwnersBatch(addrs: Address[]) {
        const funcs = addrs.map((a) =>
          encodeFunctionData({ abi: account.abi, functionName: "addOwnerAddress", args: [a] }),
        );
        const callData = encodeFunctionData({
          abi: account.abi,
          functionName: "executeBatch",
          args: [addrs.map(() => walletAddr), addrs.map(() => 0n), funcs],
        });
        const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
        const op = buildUserOp(walletAddr, nonce, callData);
        // 32 registrations is ~2.1M, above buildUserOp's 2M default callGasLimit.
        op.accountGasLimits = concatHex([
          pad(toHex(1_000_000n), { size: 16 }),
          pad(toHex(6_000_000n), { size: 16 }),
        ]);
        const opHash = (await entryPoint.read.getUserOpHash([op])) as Hex;
        op.signature = encodeSignatureWrapper(0n, webauthnSignature(opHash, PASSKEY_PRIV));
        const h = await entryPoint.write.handleOps([[op], beneficiary.account.address], {
          account: deployer.account,
        });
        const r = await publicClient.waitForTransactionReceipt({ hash: h });
        assert.ok(
          opSucceeded(r, entryPoint.abi),
          `batch adding ${addrs.length} owners must succeed`,
        );
      }

      // Indices 33..255 — 223 fillers, in batches of at most MAX_BATCH_SIZE (32).
      const remaining: Address[] = [];
      for (let i = 33; i <= 255; i++) {
        remaining.push(("0x" + i.toString(16).padStart(40, "0")) as Address);
      }
      assert.strictEqual(remaining.length, 223);
      for (let i = 0; i < remaining.length; i += 32)
        await addOwnersBatch(remaining.slice(i, i + 32));
      assert.strictEqual(
        (await account.read.ownerCount()) as bigint,
        256n,
        "indices 0..255 filled",
      );

      // Index 256 — the first index a uint8 cursor cannot represent — is passkey B.
      const addPasskey = encodeFunctionData({
        abi: account.abi,
        functionName: "addOwnerPublicKey",
        args: [PK2_X, PK2_Y],
      });
      const addR = await execViaPasskey({
        publicClient,
        entryPoint,
        walletAbi: account.abi,
        walletAddr,
        target: walletAddr,
        innerCalldata: addPasskey,
        passkeyPriv: PASSKEY_PRIV,
        submitter: deployer,
        beneficiary: beneficiary.account.address,
        ownerIndex: 0n,
      });
      assert.ok(opSucceeded(addR, entryPoint.abi), "adding owner #256 must succeed");
      const addedIndex = (
        parseEventLogs({ abi: account.abi, logs: addR.logs, eventName: "AddOwner" })[0] as any
      ).args.index as bigint;
      assert.strictEqual(addedIndex, 256n, "the 257th owner must land at index 256");

      assert.strictEqual(
        (await account.read.ownerCount()) as bigint,
        257n,
        "all 257 owners registered",
      );
      assert.strictEqual((await account.read.nextOwnerIndex()) as bigint, 257n);
      assert.strictEqual(
        (await account.read.ownerAtIndex([256n])) as Hex,
        encodePasskeyOwner(PK2_X, PK2_Y),
        "index 256 — one past a uint8 cursor's range — holds the owner we put there",
      );

      // The real claim: owner #256 is not merely STORED, it can AUTHORIZE.
      const callData = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [walletAddr, 0n, "0x"],
      });
      const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(walletAddr, nonce, callData);
      const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
      userOp.signature = encodeSignatureWrapper(
        256n,
        webauthnSignature(userOpHash, SECOND_PASSKEY_PRIV),
      );
      const hash = await entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
        account: deployer.account,
      });
      assert.ok(
        opSucceeded(await publicClient.waitForTransactionReceipt({ hash }), entryPoint.abi),
        "owner index 256 must be able to sign — upstream's uint8 cap does not exist here",
      );
    });

    it("C4 L-01: no NatSpec in the file claims a cap", async function () {
      // Documentation-drift guard. Upstream's finding WAS a docs-vs-code mismatch; the only way we
      // reproduce it is by someone writing a cap into the comments that the code never enforces.
      const src = readFileSync(WALLET_SOURCE_PATH, "utf8");
      const commentLines = src
        .split("\n")
        .map((l, i) => ({ n: i + 1, text: l }))
        .filter(({ text }) => /^\s*(\/\/|\*|\/\*)/.test(text));

      // Phrases that would assert a maximum number of OWNERS. Deliberately does not match
      // MAX_BATCH_SIZE / batch wording, which is a real, enforced limit on a different thing.
      const CAP_CLAIM =
        /\b(max(imum)?|at most|up to|no more than|limit(ed)? to|cap(ped)?)\b[^.\n]{0,60}\bowners?\b|\bowners?\b[^.\n]{0,40}\b(cap(ped)?|ceiling|max(imum)?)\b/i;
      const offenders = commentLines
        .filter(({ text }) => CAP_CLAIM.test(text))
        .map(({ n, text }) => `${n}: ${text.trim()}`);

      assert.deepStrictEqual(
        offenders,
        [],
        "no comment may claim an owner-count cap — the code enforces none (nextOwnerIndex is uint256). " +
          "If a cap is ever ADDED to the code, update this guard rather than deleting it.",
      );

      // Positive half: the storage really is uint256, so no cap can be hiding in a narrow type.
      assert.match(
        src,
        /uint256 public nextOwnerIndex;/,
        "nextOwnerIndex must remain uint256 — a narrowing is exactly upstream's uint8 bug",
      );
    });
  });

  // ==========================================================================================
  // NEW-1 (NOT an upstream finding — discovered while mapping C4 L-01). Bucket: (c) RESIDUAL,
  // newly reported.
  //
  // `getOwners()` (StarzipWallet.sol:418-434) loops `0..nextOwnerIndex` and performs one SLOAD per
  // index, INCLUDING indices vacated by `removeOwnerAtIndex` — the loop is driven by
  // `nextOwnerIndex`, which only ever increases, not by `ownerCount`. Combined with C4 L-01's
  // deliberate absence of any owner cap, an attacker holding ONE compromised owner key can inflate
  // `nextOwnerIndex` without bound (add owner, remove owner, repeat — the wallet's own funds pay
  // the gas) until `getOwners()` costs more than any `eth_call` gas budget a node will serve.
  //
  // Impact is availability, not authority: signature verification is O(1) (`ownerAtIndex[i]`
  // direct lookup), so the wallet still WORKS — but every UI that enumerates owners to render
  // "who controls this wallet" goes blind, which is precisely the screen a user would consult
  // after suspecting a compromise. The function's own NatSpec says "O(n) in nextOwnerIndex; fine
  // for a view/eth_call" — that is the claim under test, and it holds only while n is bounded,
  // which nothing enforces.
  // ==========================================================================================
  describe("NEW-1: getOwners() is unbounded because the owner set is", function () {
    it("NEW-1: getOwners() gas grows linearly in nextOwnerIndex and becomes uncallable", async function () {
      const { viem } = await getConnection();
      const [deployer] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const entryPoint = await viem.deployContract("TestEntryPoint", []);
      const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, zeroAddress]);

      // Capped at 56 owners per wallet. MEASURED, not assumed: `createAccount` costs ~74k gas per
      // owner (n=4 => 475,835 ... n=64 => 4,944,246), and Hardhat's EDR block gas cap here is
      // 16,777,216, which the provider compares against a MULTIPLIED estimate — empirically n=64
      // still goes through and n=96 is rejected outright ("transaction gas limit (18606132) is
      // greater than the cap (16777216)") before executing. 56 keeps a comfortable margin. A 7x
      // span over four points is ample to establish linearity, which is the claim here.
      const COUNTS = [8, 24, 40, 56];
      const measurements: { n: number; gas: bigint }[] = [];
      for (const n of COUNTS) {
        const owners: Hex[] = [];
        for (let i = 1; i <= n; i++) {
          owners.push(
            encodeAddressOwner(("0x" + (i + n * 4096).toString(16).padStart(40, "0")) as Address),
          );
        }
        const salt = BigInt(900000 + n);
        await factory.write.createAccount([owners, salt], { account: deployer.account });
        const addr = (await factory.read.getAddress([owners, salt])) as Address;
        const w = await viem.getContractAt("StarzipWallet", addr);
        assert.strictEqual((await w.read.ownerCount()) as bigint, BigInt(n));
        const gas = await publicClient.estimateContractGas({
          address: addr,
          abi: w.abi,
          functionName: "getOwners",
          args: [],
          account: deployer.account.address,
        });
        measurements.push({ n, gas });
      }

      // --- Linearity ---------------------------------------------------------------------------
      const first = measurements[0];
      const last = measurements[measurements.length - 1];
      const slope = Number(last.gas - first.gas) / (last.n - first.n); // gas per owner
      const intercept = Number(first.gas) - slope * first.n;

      // Every intermediate point must sit on the line through the endpoints. A super-linear term
      // would show up here; so would a constant-cost (cached/paged) implementation.
      for (const m of measurements) {
        const predicted = intercept + slope * m.n;
        const relErr = Math.abs(Number(m.gas) - predicted) / Number(m.gas);
        assert.ok(
          relErr < 0.05,
          `getOwners() must be LINEAR in nextOwnerIndex: n=${m.n} measured ${m.gas}, ` +
            `line predicts ${Math.round(predicted)} (rel. err ${(relErr * 100).toFixed(2)}%)`,
        );
      }

      // Slope band. Dominated by one COLD SLOAD (2100) per index plus memory/array work; the band
      // is wide enough to survive ordinary codegen drift but narrow enough that a change of
      // ALGORITHM (e.g. iterating a packed array, or paging) breaks it and forces a re-read.
      assert.ok(
        slope > 1000 && slope < 12000,
        `per-owner slope should be a few thousand gas; measured ${slope.toFixed(0)} gas/owner ` +
          `(measurements: ${measurements.map((m) => `${m.n}=>${m.gas}`).join(", ")})`,
      );

      // --- Extrapolation (stated, not asserted as an absolute failure count) ---------------------
      // A generous public `eth_call` budget is 50,000,000 gas (most nodes serve far less; the
      // common default is 50M on Erigon/Nethermind, 30M-equivalent on many hosted providers).
      const CALL_BUDGET = 50_000_000;
      const breakEven = Math.floor((CALL_BUDGET - intercept) / slope);
      // We do NOT drive the wallet to `breakEven` owners in a test — at ~45k gas to register each
      // one that is billions of gas of setup. The linear fit above is the evidence; this is the
      // conclusion drawn from it.
      assert.ok(
        breakEven > 0 && breakEven < 200_000,
        `extrapolated break-even (${breakEven} indices) should be a concrete, reachable number — ` +
          `slope=${slope.toFixed(0)} gas/owner, intercept=${Math.round(intercept)}`,
      );
      // Reachability sanity: registering that many owners costs on the order of breakEven * ~45k
      // gas. At opBNB's fees this is cheap; the point of the assertion is that the number is
      // ORDINARY, not astronomically out of reach.
      assert.ok(
        breakEven < 100_000,
        `getOwners() becomes uncallable at roughly ${breakEven} indices under a ${CALL_BUDGET} gas ` +
          `eth_call budget — an attacker with one compromised owner key can reach that by repeated ` +
          `add/remove, since nextOwnerIndex never decreases and no owner cap exists (C4 L-01)`,
      );
    });

    it("NEW-1: the cost is driven by nextOwnerIndex, not ownerCount — removed owners keep charging", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);
      const baseline = await ctx.publicClient.estimateContractGas({
        address: ctx.walletAddr,
        abi: ctx.w.abi,
        functionName: "getOwners",
        args: [],
        account: ctx.deployer.account.address,
      });
      assert.strictEqual((await ctx.w.read.ownerCount()) as bigint, 4n);
      assert.strictEqual((await ctx.w.read.nextOwnerIndex()) as bigint, 4n);

      // Inflate nextOwnerIndex while leaving ownerCount UNCHANGED — the exact primitive an attacker
      // holding one owner key has. Each iteration is an ordinary, fully authorized add+remove.
      const CHURN = 30;
      for (let i = 0; i < CHURN; i++) {
        const extra = ("0x" + (0x9000 + i).toString(16).padStart(40, "0")) as Address;
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

      assert.strictEqual((await ctx.w.read.ownerCount()) as bigint, 4n, "ownerCount is unchanged");
      assert.strictEqual(
        (await ctx.w.read.nextOwnerIndex()) as bigint,
        BigInt(4 + CHURN),
        "nextOwnerIndex grew by the churn count and can never come back down",
      );

      const inflated = await ctx.publicClient.estimateContractGas({
        address: ctx.walletAddr,
        abi: ctx.w.abi,
        functionName: "getOwners",
        args: [],
        account: ctx.deployer.account.address,
      });
      assert.ok(
        inflated > baseline,
        `getOwners() must cost MORE after churn even though ownerCount is identical ` +
          `(baseline ${baseline}, after ${CHURN} add/remove pairs ${inflated}) — this is what makes ` +
          `the DoS reachable without ever growing the real owner set`,
      );
      // The result is still CORRECT — this is availability-only, not a correctness bug.
      const list = (await ctx.w.read.getOwners()) as Hex[];
      assert.deepStrictEqual(
        list,
        ctx.initialOwners,
        "the answer stays right; only the cost grows",
      );
    });
  });

  // ==========================================================================================
  // C4 L-04 — PASSKEY VALIDATION PRESENT IN `initialize` BUT MISSING ON THE PUBLIC ADD PATHS.
  // Bucket: (b) CLOSED, by construction.
  //
  // Upstream validated the P-256 point in one place and not the other. We funnel `initialize`,
  // `addOwnerAddress` and `addOwnerPublicKey` through the SINGLE `_registerOwner` choke point
  // (StarzipWallet.sol:450-469), which is exactly the structural answer to this finding — so the
  // interesting test is not "does each path check" but "is it genuinely ONE check".
  // ==========================================================================================
  describe("C4 L-04: passkey/address validation on every add path", function () {
    // An off-curve point: 64 bytes that are not a valid P-256 public key.
    const OFF_CURVE_X = pad("0x22", { size: 32 });
    const OFF_CURVE_Y = pad("0x22", { size: 32 });
    const OFF_CURVE_BLOB = encodePasskeyOwner(OFF_CURVE_X, OFF_CURVE_Y);

    it("C4 L-04: every add path rejects an off-curve P-256 key", async function () {
      const ctx = await loadFixture(deployFixture);

      // Path 1 — initialize, via the factory (the counterfactual-deployment path).
      await assert.rejects(
        ctx.factory.write.createAccount([[OFF_CURVE_BLOB], 771n], {
          account: ctx.deployer.account,
        }),
        /InvalidPublicKey/,
        "initialize must reject an off-curve passkey",
      );

      // Path 2 — addOwnerPublicKey on a LIVE wallet (the post-deployment path).
      const pt = await loadFixture(passthroughOwnerFixture);
      await assert.rejects(
        pt.self(
          encodeFunctionData({
            abi: pt.w.abi,
            functionName: "addOwnerPublicKey",
            args: [OFF_CURVE_X, OFF_CURVE_Y],
          }),
        ),
        /InvalidPublicKey/,
        "addOwnerPublicKey must reject an off-curve passkey",
      );
      assert.strictEqual((await pt.w.read.ownerCount()) as bigint, 4n, "nothing was registered");

      // Control: a genuine on-curve key IS accepted on the same path, so the rejection above is
      // discriminating rather than a blanket refusal.
      await pt.self(
        encodeFunctionData({
          abi: pt.w.abi,
          functionName: "addOwnerPublicKey",
          args: [PK2_X, PK2_Y],
        }),
      );
      assert.strictEqual((await pt.w.read.ownerCount()) as bigint, 5n);
    });

    it("C4 L-04: every add path rejects address(0)", async function () {
      const ctx = await loadFixture(deployFixture);

      await assert.rejects(
        ctx.factory.write.createAccount([[encodeAddressOwner(zeroAddress)], 772n], {
          account: ctx.deployer.account,
        }),
        /ZeroAddress/,
        "initialize must reject address(0)",
      );

      const pt = await loadFixture(passthroughOwnerFixture);
      await assert.rejects(
        pt.self(
          encodeFunctionData({
            abi: pt.w.abi,
            functionName: "addOwnerAddress",
            args: [zeroAddress],
          }),
        ),
        /ZeroAddress/,
        "addOwnerAddress must reject address(0)",
      );
      assert.strictEqual((await pt.w.read.ownerCount()) as bigint, 4n);

      // NOTE (honest scoping, established by mutation — see the load-bearing test below): unlike
      // the P-256 check, the address(0) rejection is NOT a single choke point. `addOwnerAddress`
      // carries its OWN `if (owner == address(0)) revert ZeroAddress();` at StarzipWallet.sol:342
      // IN ADDITION to `_registerOwner`'s at :452, so deleting either one alone leaves the other
      // covering both paths. That duplication is harmless (both revert the same error) but it does
      // mean C4 L-04's "one place validates, another does not" shape is avoided here by redundancy
      // on the address side and by centralization on the passkey side.
    });

    // ------------------------------------------------------------------------------------------
    // LOAD-BEARING. Mutation: DELETE StarzipWallet.sol:455
    //   `if (!P256.isValidPublicKey(x, y)) revert InvalidPublicKey();`
    // (the `(bytes32 x, bytes32 y) = abi.decode(...)` line above it is left in place; solc emits
    // only unused-local-variable warnings).
    //
    // OBSERVED (clean): both the initialize path and the addOwnerPublicKey path reject with
    //   InvalidPublicKey; this test and "C4 L-04: every add path rejects an off-curve P-256 key"
    //   both PASS.
    // OBSERVED (mutated): ONE deleted line broke BOTH paths in the SAME run —
    //   * "C4 L-04: every add path rejects an off-curve P-256 key" failed at its first assertion
    //     ("initialize must reject an off-curve passkey"): the promise RESOLVED, i.e. a wallet was
    //     deployed with an off-curve key registered as owner 0.
    //   * this test failed too, at the initialize assertion, for the same reason.
    //   Both tests abort at their `initialize` assertion, so a separate probe was run under the
    //   same mutation to confirm the OTHER path independently. It measured:
    //     initialize(off-curve)         -> ACCEPTED. ownerCount=1, ownerAtIndex[0]=0x2222..2222
    //     addOwnerPublicKey(off-curve)  -> ACCEPTED. ownerCount=3, ownerAtIndex[2]=0x2222..2222
    //   So one deleted line really does open both entry points, and the off-curve owner is
    //   genuinely persisted, not merely waved through.
    //   As the NatSpec at :444-446 predicts, the result is unusable rather than exploitable: no
    //   WebAuthn assertion can ever verify against an off-curve point, so the slot is bricked, not
    //   hijackable. The cost of the missing check is therefore a permanently dead owner slot —
    //   and, on the `initialize` path, a permanently dead WALLET if it was the only owner.
    // RESTORED: yes; recompiled; both tests re-run GREEN.
    // ------------------------------------------------------------------------------------------
    it("C4 L-04: the P256 on-curve check is a single load-bearing choke point", async function () {
      const ctx = await loadFixture(deployFixture);
      const pt = await loadFixture(passthroughOwnerFixture);

      // Both paths must reject, and (per the mutation recorded above) they must do so BECAUSE OF
      // THE SAME LINE — deleting :455 breaks both of these assertions together.
      await assert.rejects(
        ctx.factory.write.createAccount([[OFF_CURVE_BLOB], 773n], {
          account: ctx.deployer.account,
        }),
        /InvalidPublicKey/,
        "initialize path: the on-curve check at StarzipWallet.sol:455 must fire",
      );
      await assert.rejects(
        pt.self(
          encodeFunctionData({
            abi: pt.w.abi,
            functionName: "addOwnerPublicKey",
            args: [OFF_CURVE_X, OFF_CURVE_Y],
          }),
        ),
        /InvalidPublicKey/,
        "addOwnerPublicKey path: the SAME check at StarzipWallet.sol:455 must fire",
      );

      // Structural half of the claim: there is exactly one on-curve check in the file, and
      // `_registerOwner` is the only writer of `ownerAtIndex`. Together these are what make the
      // mutation above break two paths at once rather than one.
      const code = stripComments(readFileSync(WALLET_SOURCE_PATH, "utf8"));
      const curveChecks = code.match(/P256\.isValidPublicKey/g) ?? [];
      assert.strictEqual(
        curveChecks.length,
        1,
        "the on-curve check must exist EXACTLY once IN CODE — a second copy is C4 L-04's drift risk " +
          "returning. (The identifier also appears once in _registerOwner's NatSpec at :444, which " +
          "is why this counts stripped source rather than raw text.)",
      );
      const writers = code.match(/ownerAtIndex\[[^\]]+\]\s*=/g) ?? [];
      assert.strictEqual(
        writers.length,
        1,
        "`ownerAtIndex` must have exactly one writer (_registerOwner) — that is what makes the check total",
      );
    });
  });

  // ==========================================================================================
  // C4 L-05 / Certora L-1 — DENCUN/EVM OPCODES UNSUPPORTED ON THE TARGET L2.
  // Bucket: (b) CLOSED (empirically, off-chain).
  //
  // We compile for `evmVersion: "cancun"` and `execute`/`executeBatch` use
  // `ReentrancyGuardTransient`, i.e. EIP-1153 TSTORE/TLOAD. If the target chain did not implement
  // 1153, every `execute` would revert — a total wallet brick, not a subtle bug.
  //
  // ALREADY PROVEN OFF-CHAIN, DO NOT RE-PROBE: `eth_call` with state-override against the live
  // public RPCs established that opBNB testnet (5611) AND opBNB mainnet (204) both support
  // TSTORE/TLOAD and MCOPY, with a discriminating negative control (undefined opcode 0x0c errors
  // as expected, so the positive results are not a permissive-RPC artifact). What is left for this
  // suite is the FUNCTIONAL half: that the guard, given a working 1153, actually blocks reentrancy.
  // ==========================================================================================
  describe("C4 L-05 / Certora L-1: EIP-1153 transient-storage reentrancy guard", function () {
    // ------------------------------------------------------------------------------------------
    // LOAD-BEARING. Mutation: StarzipWallet.sol:287 — remove the `nonReentrant` modifier from
    //   `function execute(address dest, uint256 value, bytes calldata func) external onlyEntryPoint nonReentrant`
    //
    // OBSERVED (clean): this test PASSES — reenterAttempted == true, reenterBlocked == true, and
    //   exactly ONE Executed event (the outer call).
    // OBSERVED (mutated): FAILED, as designed, at
    //     "the nested execute() must be blocked by the WALLET's own nonReentrant guard, not by
    //      the EntryPoint's"
    //     Expected values to be strictly equal: false !== true
    //   i.e. `reenterBlocked` came back FALSE — the nested `execute` SUCCEEDED mid-call. The test
    //   aborts at that assertion, so a probe re-ran the same scenario under the same mutation to
    //   check the event trail independently and measured:
    //     reenterAttempted=true  reenterBlocked=false  ExecutedEvents=2
    //   TWO Executed events, so the reentrant call really ran to completion rather than merely
    //   being mis-reported by the trigger mock.
    // RESTORED: yes; recompiled; re-run GREEN.
    //
    // Why PassthroughEntryPoint and not the real one: `EntryPoint.handleOps` has its OWN
    // `nonReentrant`, which blocks a nested `handleOps` before it ever reaches the wallet. Testing
    // through it would prove the 4337 infra works and tell us nothing about StarzipWallet's own
    // modifier — the mutation above would NOT have failed. See PassthroughEntryPoint's NatSpec.
    // ------------------------------------------------------------------------------------------
    it("C4 L-05: nonReentrant (EIP-1153 transient storage) actually blocks reentrancy", async function () {
      const { pep, account, walletAddr, deployer, trigger, publicClient } =
        await loadFixture(reentrancyFixture);

      const triggerCalldata = encodeFunctionData({
        abi: trigger.abi,
        functionName: "reenterExecute",
        args: [pep.address, walletAddr],
      });
      const hash = await pep.write.callExecute([walletAddr, trigger.address, 0n, triggerCalldata], {
        account: deployer.account,
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      assert.strictEqual(receipt.status, "success", "the OUTER execute() must complete normally");

      assert.strictEqual(
        await trigger.read.reenterAttempted(),
        true,
        "sanity: the reentry must actually have been attempted, or the test proves nothing",
      );
      assert.strictEqual(
        await trigger.read.reenterBlocked(),
        true,
        "the nested execute() must be blocked by the WALLET's own nonReentrant guard, not by the EntryPoint's",
      );

      const executed = parseEventLogs({
        abi: account.abi,
        logs: receipt.logs,
        eventName: "Executed",
      }) as any[];
      assert.strictEqual(
        executed.length,
        1,
        "exactly one Executed (the outer call) — a second one means the reentrant call ran",
      );
    });

    // The fork variant needs an archive endpoint. It is `it.skip`-ed unless the env var is set, so
    // the default `npx hardhat test` never touches the network, never hangs, and never fails
    // because a public RPC is rate-limiting.
    const FORK_RPC = process.env.OPBNB_TESTNET_ARCHIVE_RPC_URL;
    const forkIt = FORK_RPC ? it : it.skip;
    forkIt(
      "C4 L-05: nonReentrant holds against REAL opBNB testnet state (opbnbTestnetFork)",
      async function () {
        // SKIPPED BY DEFAULT: `OPBNB_TESTNET_ARCHIVE_RPC_URL` is unset in this environment, so
        // there is no archive endpoint to fork from. The public opBNB testnet RPC serves roughly a
        // two-minute state window, which is not
        // enough to make a fork test reproducible. The 1153/MCOPY support this test would confirm
        // has ALREADY been established empirically via `eth_call` state-override against both
        // opBNB testnet (5611) and mainnet (204) — this test would add the functional guard check
        // on top of real chain state, not the opcode-availability fact itself.
        const hre = (await import("hardhat")).default;
        const conn = await hre.network.connect({ network: "opbnbTestnetFork" });
        const { viem } = conn;
        const [deployer] = await viem.getWalletClients();
        const publicClient = await viem.getPublicClient();
        assert.strictEqual(await publicClient.getChainId(), 5611, "must be forking opBNB testnet");

        const pep = await viem.deployContract("PassthroughEntryPoint", []);
        const factory = await viem.deployContract("StarzipWalletFactory", [pep.address, zeroAddress]);
        const owner = encodePasskeyOwner(PK_X, PK_Y);
        await factory.write.createAccount([[owner], SALT], { account: deployer.account });
        const walletAddr = (await factory.read.getAddress([[owner], SALT])) as Address;
        const trigger = await viem.deployContract("ReentrantExecuteTrigger", []);

        const triggerCalldata = encodeFunctionData({
          abi: trigger.abi,
          functionName: "reenterExecute",
          args: [pep.address, walletAddr],
        });
        const hash = await pep.write.callExecute(
          [walletAddr, trigger.address, 0n, triggerCalldata],
          {
            account: deployer.account,
          },
        );
        await publicClient.waitForTransactionReceipt({ hash });
        assert.strictEqual(await trigger.read.reenterAttempted(), true);
        assert.strictEqual(
          await trigger.read.reenterBlocked(),
          true,
          "the transient-storage guard must work against real opBNB state too",
        );
      },
    );
  });

  // ==========================================================================================
  // C4 N-03 — COMMENTS ASSERTING A SCENARIO IS IMPOSSIBLE WHEN THE CODE DOES NOT PREVENT IT.
  // Bucket: (b) CLOSED for one claim, (c) RESIDUAL-but-true for the other.
  //
  // Two documented invariants in StarzipWallet.sol are load-bearing enough that a comment alone is
  // not adequate evidence. Both get execution proof here.
  // ==========================================================================================
  describe("C4 N-03: documented invariants, proven by execution", function () {
    // ------------------------------------------------------------------------------------------
    // LOAD-BEARING — and the highest-value mutation in this file after Cantina-Dec 3.1.3.
    //
    // The claim (StarzipWallet.sol:102-116): the wallet must NEVER call `__EIP712_init`, because
    // `EIP712Upgradeable.eip712Domain()` carries
    //   require($._hashedName == 0 && $._hashedVersion == 0, "EIP712: Uninitialized")
    // (node_modules/@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol:58)
    // and therefore starts REVERTING once that storage is written. `isValidSignature` calls
    // `eip712Domain()` unconditionally (:708-716), so the revert would propagate to EVERY ERC-1271
    // check — and `SignatureChecker.isValidERC1271SignatureNow` swallows a reverted staticcall as
    // `success = false`, so integrators (TradeSettlementV1 order verification) would see silent
    // universal signature failure with no revert reason pointing anywhere near the cause.
    //
    // The wallet avoids the storage entirely by overriding `_EIP712Name`/`_EIP712Version` as pure
    // constants (:732-739). Nothing in the type system enforces that, hence this test.
    //
    // TWO mutations were run here, and the FIRST ONE REFUTED THE NATSPEC. Recorded in full,
    // because the refutation is a finding in its own right.
    //
    // MUTATION 4 (the one the NatSpec names): add `__EIP712_init("StarzipWallet", "1");` as the
    //   first statement of `initialize`. It compiles — `initializer` sets `_initializing`, which
    //   satisfies `__EIP712_init`'s `onlyInitializing`.
    //   OBSERVED: **NO BEHAVIOURAL CHANGE AT ALL.** `eip712Domain()` returned normally
    //   (fields=0x0f, name="StarzipWallet", version="1", chainId=31337) and a valid 7739 assertion
    //   still returned 0x1626ba7e. This test failed ONLY on its source-scan guard at the very end.
    //   ROOT CAUSE — the NatSpec's mechanism is wrong for the pinned OZ version. Its claim is that
    //   `__EIP712_init` makes `$._hashedName` non-zero and so trips
    //   `require($._hashedName == 0 && $._hashedVersion == 0, "EIP712: Uninitialized")`. But in
    //   OZ v5.5.0, `__EIP712_init_unchained`
    //   (contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol:71-79) writes the STRINGS
    //   and then EXPLICITLY ZEROES the hashed fields — the source comment there reads
    //   "Reset prior values in storage if upgrading":
    //       $._name = name; $._version = version;
    //       $._hashedName = 0; $._hashedVersion = 0;
    //   Direct storage read of the EIP712 namespace (0xa16a46d9...d100) after the mutated
    //   `initialize` confirmed it: slot+0 (_hashedName) = 0, slot+1 (_hashedVersion) = 0,
    //   slot+2 (_name) = "StarzipWallet", slot+3 (_version) = "1". The `require` guards LEGACY
    //   pre-5.0 storage, not anything `__EIP712_init` can produce today. The mutation is also inert
    //   for verification, because this wallet overrides `_EIP712Name()`/`_EIP712Version()` to
    //   return non-empty constants, so `_EIP712NameHash()` (EIP712Upgradeable.sol:169-183) takes
    //   its `bytes(name).length > 0` branch and never consults `$._hashedName`.
    //
    // MUTATION 4b (what it takes to ACTUALLY break the invariant): dirty the storage directly —
    //   add to `initialize`
    //       assembly { sstore(0xa16a46d94261c7517cc8ff89f61c0ce93598e3c849801011dee649a6a557d100, 1) }
    //   OBSERVED: this test FAILED with the message it constructs for that case, and BOTH predicted
    //   consequences were confirmed in the same run:
    //     * eip712Domain() reverted: "reverted with reason string 'EIP712: Uninitialized'"
    //     * isValidSignature, for an assertion that returned 0x1626ba7e on clean code, REVERTED
    //       (propagating the same string) rather than returning a bytes4.
    //   Four other tests in this file failed as collateral, all for the same reason — which is the
    //   point: every ERC-1271 path in the wallet goes through eip712Domain().
    //   NOTE the precise failure shape, which the NatSpec also states loosely: isValidSignature
    //   does NOT "return 0xffffffff" — it REVERTS. It becomes `false` only once
    //   `SignatureChecker.isValidERC1271SignatureNow` swallows the reverted staticcall. A caller
    //   that invokes `isValidSignature` directly gets an exception.
    //
    // CONCLUSION: the invariant ("never touch EIP712 storage") is REAL and this test is
    // load-bearing against it — but StarzipWallet.sol:108-116 documents an UNREACHABLE trigger for
    // it. See the report's finding NEW-2. The behavioural assertions below are kept because
    // mutation 4b proves they fire; the source-scan guard is kept because it is what actually
    // catches the (harmless-today, but still unwanted) `__EIP712_init` call.
    // RESTORED: yes, after each of 4 and 4b; recompiled; re-run GREEN both times.
    // ------------------------------------------------------------------------------------------
    it("C4 N-03: eip712Domain() must never revert — the wallet must never touch EIP712 storage", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account, chainId, walletAddr } = ctx;

      // Build a KNOWN-GOOD assertion first, so that if the domain read fails we can immediately
      // demonstrate the downstream ERC-1271 consequence rather than merely reporting the revert.
      const { digest, sig } = buildErc1271Payload(ctx, (d) =>
        encodeSignatureWrapper(0n, webauthnSignature(d, PASSKEY_PRIV)),
      );

      let domain: any[] | undefined;
      let domainError = "";
      try {
        domain = (await account.read.eip712Domain()) as any[];
      } catch (e) {
        domainError = failureText(e).slice(0, 240);
      }

      if (domain === undefined) {
        // The invariant is broken. Prove the CONSEQUENCE before failing, so the failure message
        // carries the evidence rather than just the symptom.
        let erc1271Result: string;
        try {
          erc1271Result = (await account.read.isValidSignature([digest, sig])) as string;
        } catch (e) {
          erc1271Result = `REVERTED(${failureText(e).slice(0, 120)})`;
        }
        assert.fail(
          `C4 N-03 INVARIANT BROKEN: eip712Domain() reverted (${domainError}) and isValidSignature ` +
            `now yields ${erc1271Result} for a previously-VALID assertion. Something wrote a non-zero ` +
            `value into EIP712Upgradeable's namespaced storage (0xa16a46d9...d100), which trips OZ's ` +
            `require($._hashedName == 0 && $._hashedVersion == 0, "EIP712: Uninitialized"). ` +
            `isValidSignature (StarzipWallet.sol:708-716) calls eip712Domain() unconditionally, so every ` +
            `ERC-1271 integration now fails silently — SignatureChecker swallows the reverted staticcall ` +
            `as false. NOTE: calling __EIP712_init is NOT how this happens on OZ v5.5.0 (it zeroes those ` +
            `fields); see this test's comment block for the measured mechanism.`,
        );
      }

      assert.strictEqual(
        domain[1] as string,
        WALLET_EIP712_NAME,
        "domain name must be the constant",
      );
      assert.strictEqual(
        domain[2] as string,
        WALLET_EIP712_VERSION,
        "domain version must be the constant",
      );
      assert.strictEqual(domain[3] as bigint, BigInt(chainId));
      assert.strictEqual((domain[4] as string).toLowerCase(), walletAddr.toLowerCase());

      // The downstream consequence the invariant exists to protect: ERC-1271 keeps working.
      assert.strictEqual(
        await account.read.isValidSignature([digest, sig]),
        ERC1271_MAGIC,
        "a valid 7739 assertion must verify — this is what breaks the instant eip712Domain() reverts",
      );

      // Structural guard: no CALL to __EIP712_init anywhere in the file. The identifier appears
      // several times in the NatSpec (that is where the invariant is documented), so this must
      // count stripped source — a raw-text search would be permanently red.
      const code = stripComments(readFileSync(WALLET_SOURCE_PATH, "utf8"));
      assert.deepStrictEqual(
        code.match(/__EIP712_init\s*\(/g) ?? [],
        [],
        "__EIP712_init must never be CALLED (mentions inside comments are fine and expected)",
      );
    });

    it("C4 N-03: _cancelPendingUpgradeOnOwnerChange can only CLEAR a staging, never arm one", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);

      // The claim at StarzipWallet.sol:488: "the WORST case is a legitimate upgrade silently
      // failing to arm, never an unauthorized one succeeding". The adversarial suite
      // already proves the CLEAR direction (batch [requestUpgrade, addOwner] ends disarmed). This
      // proves the complementary direction the comment actually asserts: with nothing pending, no
      // owner-set mutation can bring a staging into existence.
      assert.strictEqual((await ctx.w.read.pendingImplementation()) as Address, zeroAddress);

      const mutations: { label: string; data: Hex }[] = [
        {
          label: "addOwnerAddress",
          data: encodeFunctionData({
            abi: ctx.w.abi,
            functionName: "addOwnerAddress",
            args: ["0x00000000000000000000000000000000000000e1" as Address],
          }),
        },
        {
          label: "addOwnerPublicKey",
          data: encodeFunctionData({
            abi: ctx.w.abi,
            functionName: "addOwnerPublicKey",
            args: [PK2_X, PK2_Y],
          }),
        },
        {
          label: "removeOwnerAtIndex",
          data: encodeFunctionData({
            abi: ctx.w.abi,
            functionName: "removeOwnerAtIndex",
            args: [1n, ctx.initialOwners[1]],
          }),
        },
      ];

      for (const m of mutations) {
        const receipt = await ctx.publicClient.waitForTransactionReceipt({
          hash: await ctx.self(m.data),
        });
        assert.strictEqual(
          (await ctx.w.read.pendingImplementation()) as Address,
          zeroAddress,
          `${m.label} must leave pendingImplementation at address(0)`,
        );
        assert.strictEqual(
          (await ctx.w.read.upgradeRequestedAt()) as bigint,
          0n,
          `${m.label} must leave upgradeRequestedAt at 0`,
        );
        const armed = parseEventLogs({
          abi: ctx.w.abi,
          logs: receipt.logs,
          eventName: "UpgradeRequested",
        }) as any[];
        assert.strictEqual(armed.length, 0, `${m.label} must never emit UpgradeRequested`);
      }

      // Same, but all three in ONE batch — the ordering footgun documented at :479-486 applies to
      // the CLEAR direction only; it cannot be turned into an ARM.
      const ctx2 = await loadFixture(passthroughOwnerFixture);
      await ctx2.selfBatch([mutations[0].data, mutations[1].data, mutations[2].data]);
      assert.strictEqual(
        (await ctx2.w.read.pendingImplementation()) as Address,
        zeroAddress,
        "a batch of owner-set mutations must not conjure a pending upgrade either",
      );
    });
  });

  // ==========================================================================================
  // Certora M-1 — `createAccount` WITH AN EMPTY OWNERS ARRAY CREATES A FRONTRUNNABLE /
  // STEALABLE UNINITIALIZED ACCOUNT. Bucket: (b) CLOSED.
  //
  // Upstream's factory would deploy an account with no owners; anyone could then claim it. Our
  // guard is `if (owners.length == 0) revert InvalidArrayLength();` at StarzipWallet.sol:238 —
  // note it lives in `initialize`, not in the factory (StarzipWalletFactory.sol's NatSpec says so
  // explicitly), so the revert happens DURING proxy construction and nothing is left behind.
  // ==========================================================================================
  describe("Certora M-1: empty owner set at creation", function () {
    it("Certora M-1: createAccount([], salt) reverts and deploys NOTHING", async function () {
      const { factory, deployer, publicClient } = await loadFixture(deployFixture);
      const salt = 991n;

      const predicted = (await factory.read.getAddress([[], salt])) as Address;
      assert.match(predicted, /^0x[0-9a-fA-F]{40}$/);
      assert.ok(isEmptyCode(await publicClient.getCode({ address: predicted })), "empty before");

      await assert.rejects(
        factory.write.createAccount([[], salt], { account: deployer.account }),
        /InvalidArrayLength/,
        "an empty owner set must be refused",
      );

      // The half that actually matters: the revert happens inside the proxy CONSTRUCTOR, so there
      // is no half-deployed, ownerless proxy sitting at the predicted address for someone to claim.
      assert.ok(
        isEmptyCode(await publicClient.getCode({ address: predicted })),
        "nothing may be deployed at the predicted address after the failed createAccount",
      );
    });

    // ------------------------------------------------------------------------------------------
    // LOAD-BEARING. Mutation: DELETE StarzipWallet.sol:238
    //   `if (owners.length == 0) revert InvalidArrayLength();`
    //
    // OBSERVED (clean): this test PASSES (createAccount([], salt) reverts InvalidArrayLength).
    // OBSERVED (mutated): FAILED, with this test's own constructed message, which carries the
    //   measured behaviour of the resulting account:
    //     "Certora M-1 GUARD REMOVED: createAccount([], salt) DEPLOYED a wallet at 0x... with
    //      ownerCount=0, nextOwnerIndex=0. ERC-1271 on it returns 0xffffffff; a userOp naming
    //      owner 0 fails with FailedOp(0, "AA24 signature error"); addOwnerAddress from an EOA
    //      reverts OnlySelf. The account is permanently bricked AND fundable."
    //   Every clause was verified in that run, not asserted speculatively:
    //     * a real ERC1967Proxy WAS deployed (non-empty code at the predicted address),
    //     * ownerCount == 0 and nextOwnerIndex == 0,
    //     * a well-formed 7739 assertion by a real passkey returned 0xffffffff (no owner to match),
    //     * a passkey-signed userOp naming ownerIndex 0 was declined AA24 (ownerAtIndex[0] is
    //       empty, so `_verifyOwnerSignature` returns false — it declines rather than reverting,
    //       which is correct behaviour and also means the EntryPoint gives no hint that the account
    //       is ownerless),
    //     * `addOwnerAddress` / `addOwnerPublicKey` / `removeOwnerAtIndex` are all `onlySelf`, and
    //       reaching `onlySelf` requires an owner-signed userOp, which by construction cannot
    //       exist — so the owner set can NEVER be populated after the fact.
    //   NOTE this differs from upstream's finding in outcome: our ownerless account is UNCLAIMABLE
    //   (bricked), not STEALABLE, because we have no unauthenticated `initialize`-style claim path.
    //   The loss is still total for anyone who funded the counterfactual address.
    // RESTORED: yes; recompiled; re-run GREEN.
    // ------------------------------------------------------------------------------------------
    it("Certora M-1: the empty-owner-set guard is load-bearing", async function () {
      const ctx = await loadFixture(deployFixture);
      const { factory, deployer, publicClient, viem, entryPoint, beneficiary, chainId } = ctx;
      const salt = 992n;
      const predicted = (await factory.read.getAddress([[], salt])) as Address;

      let deployedAnyway = false;
      try {
        const h = await factory.write.createAccount([[], salt], { account: deployer.account });
        await publicClient.waitForTransactionReceipt({ hash: h });
        deployedAnyway = true;
      } catch {
        /* expected on clean code */
      }

      if (deployedAnyway) {
        // GUARD REMOVED. Measure the resulting account and put the evidence in the failure.
        const w = await viem.getContractAt("StarzipWallet", predicted);
        const code = await publicClient.getCode({ address: predicted });
        const ownerCount = (await w.read.ownerCount()) as bigint;
        const nextIdx = (await w.read.nextOwnerIndex()) as bigint;

        const probeCtx = { ...ctx, account: w, walletAddr: predicted, chainId };
        const { digest, sig } = buildErc1271Payload(
          probeCtx,
          (d) => encodeSignatureWrapper(0n, webauthnSignature(d, PASSKEY_PRIV)),
          {
            name: WALLET_EIP712_NAME,
            version: WALLET_EIP712_VERSION,
            chainId,
            verifyingContract: predicted,
          },
        );
        let erc1271: string;
        try {
          erc1271 = (await w.read.isValidSignature([digest, sig])) as string;
        } catch (e) {
          erc1271 = `REVERTED(${failureText(e).slice(0, 100)})`;
        }

        await deployer.sendTransaction({ to: predicted, value: parseEther("1") });
        let userOpOutcome = "ACCEPTED (!!)";
        try {
          await sendOp({ ...probeCtx, entryPoint, deployer, beneficiary, publicClient }, (h2) =>
            encodeSignatureWrapper(0n, webauthnSignature(h2, PASSKEY_PRIV)),
          );
        } catch (e) {
          userOpOutcome = describeFailure(e);
        }

        let adminOutcome = "SUCCEEDED (!!)";
        try {
          await w.write.addOwnerAddress([deployer.account.address], { account: deployer.account });
        } catch (e) {
          adminOutcome = describeFailure(e);
        }

        assert.fail(
          `Certora M-1 GUARD REMOVED: createAccount([], salt) DEPLOYED a wallet at ${predicted} ` +
            `(code length ${code ? (code.length - 2) / 2 : 0} bytes) with ownerCount=${ownerCount}, ` +
            `nextOwnerIndex=${nextIdx}. ERC-1271 returns ${erc1271}; a userOp naming owner 0 fails with ` +
            `${userOpOutcome}; addOwnerAddress from an EOA fails with ${adminOutcome}. ` +
            `The account is permanently bricked AND fundable — no owner can ever be added because every ` +
            `add path is onlySelf and onlySelf requires an owner signature that cannot exist.`,
        );
      }

      // Clean behaviour: refused, and nothing deployed.
      assert.ok(
        isEmptyCode(await publicClient.getCode({ address: predicted })),
        "the guard must prevent any deployment at the empty-owner-set address",
      );
    });
  });

  // ==========================================================================================
  // Cantina-Dec 3.1.2 — THE IMPLEMENTATION CONTRACT CAN BE INITIALIZED. Bucket: (b) CLOSED.
  //
  // The factory deploys ONE StarzipWallet implementation in its constructor
  // (StarzipWalletFactory.sol:30) and every wallet is an ERC1967Proxy delegating to it. If that
  // implementation could itself be initialized, whoever did so would own the logic contract — and
  // because this wallet is UUPS, an owner of the IMPLEMENTATION can reach `upgradeToAndCall` on it
  // directly and `selfdestruct`-equivalent it out from under every proxy. `_disableInitializers()`
  // in the constructor (StarzipWallet.sol:213) is the guard.
  // ==========================================================================================
  describe("Cantina-Dec 3.1.2: implementation initialization", function () {
    // ------------------------------------------------------------------------------------------
    // LOAD-BEARING. Mutation: DELETE StarzipWallet.sol:213 `_disableInitializers();`
    //
    // OBSERVED (clean): this test PASSES — the direct `initialize` on
    //   `factory.accountImplementation()` reverts `InvalidInitialization()`.
    // OBSERVED (mutated): FAILED with this test's constructed message —
    //     "Cantina-Dec 3.1.2 GUARD REMOVED: initialize() SUCCEEDED on the implementation at 0x...
    //      It now reports ownerCount=1, ownerAtIndex[0]=<our passkey blob>, i.e. the logic contract
    //      behind every proxy has an attacker-controlled owner."
    //   Confirmed in that run: the implementation's own storage was written (ownerCount 0 -> 1) by
    //   an arbitrary EOA calling `initialize` directly. Note the proxies' storage is unaffected
    //   (they delegate, so they keep their own slots) — the exposure is that the implementation
    //   itself becomes an owned UUPS contract, which is precisely upstream's finding.
    // RESTORED: yes; recompiled; re-run GREEN.
    // ------------------------------------------------------------------------------------------
    it("Cantina-Dec 3.1.2: the implementation cannot be initialized", async function () {
      const { factory, deployer, viem } = await loadFixture(deployFixture);
      const implAddr = (await factory.read.accountImplementation()) as Address;
      const impl = await viem.getContractAt("StarzipWallet", implAddr);

      assert.strictEqual(
        (await impl.read.ownerCount()) as bigint,
        0n,
        "precondition: the implementation starts with no owners",
      );

      let initialized = false;
      try {
        await impl.write.initialize([[encodePasskeyOwner(PK_X, PK_Y)]], {
          account: deployer.account,
        });
        initialized = true;
      } catch (e) {
        assert.match(
          failureText(e),
          /InvalidInitialization/,
          `expected InvalidInitialization from _disableInitializers(); got: ${describeFailure(e)}`,
        );
      }

      if (initialized) {
        assert.fail(
          `Cantina-Dec 3.1.2 GUARD REMOVED: initialize() SUCCEEDED on the implementation at ${implAddr}. ` +
            `It now reports ownerCount=${await impl.read.ownerCount()}, ` +
            `ownerAtIndex[0]=${await impl.read.ownerAtIndex([0n])} — the logic contract behind every ` +
            `proxy has an attacker-controlled owner, and this wallet is UUPS.`,
        );
      }

      assert.strictEqual(
        (await impl.read.ownerCount()) as bigint,
        0n,
        "the implementation's storage must remain untouched",
      );
    });
  });

  // ==========================================================================================
  // Cantina-Dec 3.1.3 — OWNER `bytes` CAN BE DECODED IN UNEXPECTED WAYS.
  // Bucket: (b) CLOSED — but by an INCIDENTAL mechanism, which is why it gets the most careful
  // treatment in this file. THIS IS OUR OWN FINDING, not a straight port of upstream's.
  //
  // `_registerOwner`'s 32-byte branch (StarzipWallet.sol:451-452) is
  //     if (abi.decode(ownerBytes, (address)) == address(0)) revert ZeroAddress();
  // The only EXPLICIT check there is "is it zero". A 32-byte blob whose top 12 bytes are non-zero
  // (dirty high bits — not a clean `abi.encode(address)`) is rejected too, but ONLY as a side
  // effect of `abi.decode`'s padding validation: solc emits an address cleanup check that
  // `revert(0, 0)`s on dirty padding. Nobody wrote that check; it comes free with the decode.
  //
  // It is nevertheless LOAD-BEARING, and this is the part worth stating precisely:
  // `_verifyOwnerSignature` performs the SAME `abi.decode(ownerBytes, (address))` at
  // StarzipWallet.sol:846, on the READ path, inside `validateUserOp`. If a dirty-high-bits blob
  // could ever be STORED, then every signature check naming that index would REVERT instead of
  // returning `SIG_VALIDATION_FAILED` — violating this contract's documented "malformed input is a
  // failed verification, not an exception" posture (:793-796, :862-864) and turning a declined
  // signature into an EntryPoint-level `FailedOpWithRevert(_, "AA23 reverted", ...)`.
  //
  // In other words: the write path's incidental decode is the ONLY thing making the read path's
  // decode total. That coupling is undocumented in the source.
  // ==========================================================================================
  describe("Cantina-Dec 3.1.3: owner bytes decoded in unexpected ways", function () {
    // Top 12 bytes non-zero -> not a clean abi.encode(address).
    const DIRTY_HIGH_BITS = ("0x" + "ff".repeat(32)) as Hex;
    // A subtler one: only ONE dirty byte, in the highest position. Same class, less obvious.
    const DIRTY_ONE_BYTE = ("0x01" + "00".repeat(11) + "cc".repeat(20)) as Hex;

    it("Cantina-Dec 3.1.3: a 32-byte owner blob with dirty high bits is rejected at registration", async function () {
      const { factory, deployer } = await loadFixture(deployFixture);

      // `initialize` (via the factory) is the ONLY path that accepts a raw `bytes` owner blob.
      // `addOwnerAddress` takes a typed `address`, so the ABI encoder cleans the high bits before
      // the call ever reaches the contract — it structurally cannot carry dirty bits. That is why
      // this finding has exactly one reachable entry point in our design.
      const observed: { label: string; text: string }[] = [];
      for (const [label, blob] of [
        ["all-0xff", DIRTY_HIGH_BITS],
        ["single high byte", DIRTY_ONE_BYTE],
      ] as const) {
        let text = "DID NOT REVERT";
        try {
          await factory.write.createAccount([[blob], 8811n], { account: deployer.account });
        } catch (e) {
          text = failureText(e);
        }
        observed.push({ label, text });
        assert.notStrictEqual(
          text,
          "DID NOT REVERT",
          `${label}: a dirty 32-byte owner blob must be rejected`,
        );
      }

      // RECORDED EXACT REVERT SHAPE (this is the part the finding asks us to pin, because it tells
      // a future reader that nobody wrote this check):
      //   It is NOT a named custom error. `ZeroAddress`, `InvalidOwnerBytesLength`,
      //   `InvalidPublicKey` and `AlreadyOwner` all fail to appear in the revert data — the blob is
      //   exactly 32 bytes long, so the length dispatch sends it into the address branch, and it is
      //   not zero, so the explicit `ZeroAddress` check does not fire either. What reverts is
      //   solc's own ABI-decoder validator for `address`, which does a BARE `revert(0, 0)` with
      //   EMPTY return data. viem therefore surfaces it as a plain execution revert with no decoded
      //   reason.
      for (const { label, text } of observed) {
        for (const named of [
          "ZeroAddress",
          "InvalidOwnerBytesLength",
          "InvalidPublicKey",
          "AlreadyOwner",
        ]) {
          assert.ok(
            !new RegExp(named).test(text),
            `${label}: the rejection must NOT be the named error ${named} — it is an unnamed ` +
              `ABI-decoder revert, and pinning that is the point of this test. Got: ${text.slice(0, 200)}`,
          );
        }
      }

      // Control: the SAME 20 low bytes, correctly zero-padded, ARE accepted. This proves the
      // rejection is about the padding, not about the address value.
      const clean = encodeAddressOwner(("0x" + "cc".repeat(20)) as Address);
      await factory.write.createAccount([[clean], 8812n], { account: deployer.account });
      const addr = (await factory.read.getAddress([[clean], 8812n])) as Address;
      const { viem } = await getConnection();
      const w = await viem.getContractAt("StarzipWallet", addr);
      assert.strictEqual((await w.read.ownerCount()) as bigint, 1n);
      assert.strictEqual((await w.read.ownerAtIndex([0n])) as Hex, clean);
    });

    // ------------------------------------------------------------------------------------------
    // LOAD-BEARING — THE SINGLE MOST IMPORTANT MUTATION IN THIS FILE.
    //
    // Mutation: rewrite `_registerOwner`'s 32-byte branch (StarzipWallet.sol:451-452) so it does
    // NOT `abi.decode`, reading the word directly instead:
    //     if (ownerBytes.length == 32) {
    //         bytes32 rawOwnerWord;
    //         assembly { rawOwnerWord := mload(add(ownerBytes, 32)) }
    //         if (rawOwnerWord == bytes32(0)) revert ZeroAddress();
    //     } else if (...)
    // This preserves the stated intent of the line ("reject the zero owner") EXACTLY, and is the
    // kind of "harmless" gas optimization a future contributor could plausibly make. It removes
    // only the incidental padding validation.
    //
    // OBSERVED (clean): this test PASSES. The dirty blob is refused at `createAccount`, so the
    //   userOp half of the test is never reached.
    // OBSERVED (mutated): FAILED, and the failure carried the measured EntryPoint error, which is
    //   the whole point of the finding:
    //     "Cantina-Dec 3.1.3 GUARD REMOVED: a dirty-high-bits owner was REGISTERED at index 0 of
    //      0x.... Naming it in a userOp produced FailedOpWithRevert(0, "AA23 reverted", "0x") —
    //      validateUserOp REVERTED instead of declining."
    //
    //   EXACT EntryPoint ERROR, BOTH STATES (the report asked for these explicitly):
    //     * CLEAN, dirty owner:      unreachable — registration itself reverts first (bare
    //                                ABI-decoder `revert(0,0)`, no named error, empty return data).
    //     * CLEAN, unregistered idx: FailedOp(0, "AA24 signature error")   <- correct decline
    //     * MUTATED, dirty owner:    FailedOpWithRevert(0, "AA23 reverted", "0x")  <- the violation
    //
    //   The AA23 form is materially worse than AA24 for a 4337 account: a bundler simulating the
    //   op sees a THROWN validation rather than a returned failure, which by ERC-7562 rules gets
    //   the ACCOUNT reputation-penalized/banned rather than the op merely dropped. And because the
    //   dirty owner sits in storage permanently, EVERY op naming that index reverts forever — the
    //   wallet is not just unable to use that owner, it becomes a bundler-hostile sender.
    // RESTORED: yes; recompiled; re-run GREEN.
    // ------------------------------------------------------------------------------------------
    it("Cantina-Dec 3.1.3: the dirty-bits rejection is load-bearing for the never-revert posture", async function () {
      const ctx = await loadFixture(deployFixture);
      const { factory, deployer, publicClient, viem, entryPoint, beneficiary, chainId } = ctx;
      const salt = 8813n;

      let registered = false;
      try {
        const h = await factory.write.createAccount([[DIRTY_HIGH_BITS], salt], {
          account: deployer.account,
        });
        await publicClient.waitForTransactionReceipt({ hash: h });
        registered = true;
      } catch {
        /* expected on clean code: solc's address decoder reverts */
      }

      if (registered) {
        // GUARD REMOVED. Demonstrate the consequence on the READ path and report the exact error.
        const addr = (await factory.read.getAddress([[DIRTY_HIGH_BITS], salt])) as Address;
        const w = await viem.getContractAt("StarzipWallet", addr);
        const stored = (await w.read.ownerAtIndex([0n])) as Hex;
        await deployer.sendTransaction({ to: addr, value: parseEther("1") });

        let outcome = "ACCEPTED (!!) — a dirty-bits owner validated a signature";
        try {
          await sendOp(
            {
              account: w,
              walletAddr: addr,
              entryPoint,
              deployer,
              beneficiary,
              publicClient,
              chainId,
            },
            (h2) => encodeSignatureWrapper(0n, webauthnSignature(h2, PASSKEY_PRIV)),
          );
        } catch (e) {
          outcome = describeFailure(e);
        }

        assert.fail(
          `Cantina-Dec 3.1.3 GUARD REMOVED: a dirty-high-bits owner was REGISTERED at index 0 of ${addr} ` +
            `(stored bytes ${stored}). Naming it in a userOp produced ${outcome}. ` +
            `Expected the contract's documented posture instead: FailedOp(_, "AA24 signature error"). ` +
            `An AA23 revert from validateUserOp is a bundler-reputation event under ERC-7562, and the ` +
            `dirty owner is permanent, so every future op naming that index reverts forever.`,
        );
      }

      // Clean behaviour: nothing was registered, and the address stays undeployable.
      const predicted = (await factory.read.getAddress([[DIRTY_HIGH_BITS], salt])) as Address;
      assert.ok(
        isEmptyCode(await publicClient.getCode({ address: predicted })),
        "a wallet with a dirty-high-bits owner must never come into existence",
      );

      // Positive control on the SAME machinery: an unregistered ownerIndex on a HEALTHY wallet
      // declines with AA24 rather than reverting. This is the behaviour the write-path decode is
      // protecting, stated as an executable claim rather than only in a comment.
      await assert.rejects(
        sendOp(ctx, (h2) => encodeSignatureWrapper(99n, webauthnSignature(h2, PASSKEY_PRIV))),
        (e: unknown) => {
          assertCleanDecline(e, "unregistered ownerIndex on a healthy wallet");
          return true;
        },
      );
    });
  });

  // ==========================================================================================
  // Cantina-Dec 3.1.4 — `entryPoint` CANNOT BE CHANGED. Bucket: (b) CLOSED by construction.
  // Ours is `IEntryPoint public immutable entryPoint;` (StarzipWallet.sol:121), set once in the
  // constructor. Being immutable it lives in CODE, not storage, so it also survives a UUPS upgrade
  // only if the new implementation is constructed with the same value — worth pinning.
  // ==========================================================================================
  describe("Cantina-Dec 3.1.4: entryPoint immutability", function () {
    it("Cantina-Dec 3.1.4: entryPoint() matches the factory's and no setter selector exists", async function () {
      const { account, entryPoint, factory } = await loadFixture(deployFixture);

      assert.strictEqual(
        ((await account.read.entryPoint()) as Address).toLowerCase(),
        entryPoint.address.toLowerCase(),
        "the wallet must point at the EntryPoint its factory was built for",
      );
      assert.strictEqual(
        ((await factory.read.entryPoint()) as Address).toLowerCase(),
        entryPoint.address.toLowerCase(),
      );

      const fns = (account.abi as any[]).filter((e) => e.type === "function");
      const setters = fns
        .map((f) => f.name as string)
        .filter((n) => /^(set|update|change|configure)/i.test(n) && /entry\s*point/i.test(n));
      assert.deepStrictEqual(setters, [], "no entryPoint setter may exist");

      // Stronger: NO state-changing function mentions entryPoint at all, and the accessor is view.
      const accessor = fns.find((f) => f.name === "entryPoint");
      assert.ok(accessor, "entryPoint() accessor must exist");
      assert.strictEqual(accessor.stateMutability, "view");
      assert.strictEqual(accessor.inputs.length, 0, "the accessor must take no arguments");

      // And the declaration really is `immutable` (storage-backed would be settable by an upgrade
      // without changing the ABI at all, so the ABI check above cannot see that on its own).
      const src = readFileSync(WALLET_SOURCE_PATH, "utf8");
      assert.match(
        src,
        /IEntryPoint\s+public\s+immutable\s+entryPoint;/,
        "entryPoint must be declared immutable — a storage variable would be silently upgradeable",
      );
    });
  });

  // ==========================================================================================
  // Cantina-Dec 3.1.5 — `authenticatorData` LENGTH MUST BE >= 37. Bucket: (b) CLOSED upstream of
  // us, in OZ: `WebAuthn.verify` short-circuits on `auth.authenticatorData.length > 36`
  // (node_modules/@openzeppelin/contracts/utils/cryptography/WebAuthn.sol). What matters for THIS
  // contract is not that the short payload is rejected but HOW: it must DECLINE, not revert, on
  // both the 4337 path and the ERC-1271 path — the same posture Cantina-Dec 3.1.3 above is about.
  // ==========================================================================================
  describe("Cantina-Dec 3.1.5: authenticatorData length", function () {
    it("Cantina-Dec 3.1.5: a 36-byte authenticatorData DECLINES, it does not revert", async function () {
      const ctx = await loadFixture(deployFixture);

      // 4337 path: AA24 (clean decline), never AA23 (a thrown validateUserOp).
      await assert.rejects(
        sendOp(ctx, (h) =>
          encodeSignatureWrapper(0n, passkeyAssertionWithAuthDataLen(h, PASSKEY_PRIV, 36)),
        ),
        (e: unknown) => {
          assertCleanDecline(e, "36-byte authenticatorData (userOp path)");
          return true;
        },
      );

      // ERC-1271 path: must RETURN 0xffffffff. A reverted staticcall here would be an ERC-1271
      // spec violation on top of the failure, because the standard requires a bytes4 return.
      const { digest, sig } = buildErc1271Payload(ctx, (d) =>
        encodeSignatureWrapper(0n, passkeyAssertionWithAuthDataLen(d, PASSKEY_PRIV, 36)),
      );
      assert.strictEqual(
        await ctx.account.read.isValidSignature([digest, sig]),
        ERC1271_INVALID,
        "ERC-1271 must RETURN 0xffffffff for a 36-byte authenticatorData, not revert",
      );

      // Boundary control: 37 bytes — one more — is the canonical length and DOES validate. Without
      // this the test above would also pass against a wallet that rejects all passkey assertions.
      const good = await sendOp(ctx, (h) =>
        encodeSignatureWrapper(0n, passkeyAssertionWithAuthDataLen(h, PASSKEY_PRIV, 37)),
      );
      assert.ok(
        opSucceeded(good, ctx.entryPoint.abi),
        "37 bytes (rpIdHash|flags|signCount) is the canonical length and must validate",
      );
    });
  });

  // ==========================================================================================
  // Cantina-Apr 3.2.2 — WEBAUTHN FAILS ON NETWORKS WITHOUT THE REQUIRED PRECOMPILE.
  // Bucket: (b) CLOSED — no hard dependency exists.
  //
  // OZ's `P256.verify` tries the RIP-7212 precompile at 0x100 and falls back to a pure-Solidity
  // implementation when it is absent (node_modules/@openzeppelin/contracts/utils/cryptography/
  // P256.sol:61-64, `_tryVerifyNative` then `verifySolidity`). Separately, the precompile IS live
  // on both opBNB chains — but that is a convenience, not a requirement, and the strongest
  // available proof of that is to run the wallet on a chain where 0x100 is definitively empty.
  // The local Hardhat EDR chain is exactly such a chain.
  // ==========================================================================================
  describe("Cantina-Apr 3.2.2: RIP-7212 precompile dependence", function () {
    it("Cantina-Apr 3.2.2: passkey verification works with NO precompile at 0x100", async function () {
      const ctx = await loadFixture(deployFixture);

      // 1) Establish the precondition: there is genuinely nothing at 0x100 on this chain.
      const code = await ctx.publicClient.getCode({ address: P256_PRECOMPILE });
      assert.ok(
        isEmptyCode(code),
        `precondition: 0x...0100 must be EMPTY for this test to prove anything (got ${code})`,
      );

      // 2) A real passkey userOp still validates -> OZ's pure-Solidity fallback carried it.
      const receipt = await sendOp(ctx, (h) =>
        encodeSignatureWrapper(0n, webauthnSignature(h, PASSKEY_PRIV)),
      );
      assert.ok(
        opSucceeded(receipt, ctx.entryPoint.abi),
        "a passkey-signed userOp must validate with no P-256 precompile present",
      );

      // 3) And so does the ERC-1271 surface, which runs the same verifier.
      const { digest, sig } = buildErc1271Payload(ctx, (d) =>
        encodeSignatureWrapper(0n, webauthnSignature(d, PASSKEY_PRIV)),
      );
      assert.strictEqual(await ctx.account.read.isValidSignature([digest, sig]), ERC1271_MAGIC);

      // 4) Discriminating negative: a WRONG key still fails on the fallback path, so (2) is not
      //    "the verifier is a no-op when the precompile is missing".
      await assert.rejects(
        sendOp(ctx, (h) => encodeSignatureWrapper(0n, webauthnSignature(h, SECOND_PASSKEY_PRIV))),
        (e: unknown) => {
          assertCleanDecline(e, "wrong passkey with no precompile");
          return true;
        },
      );
    });
  });

  // ==========================================================================================
  // Cantina-Apr 3.2.4 — SIGNATURES NEVER EXPIRE. Bucket: (c) RESIDUAL — APPLIES TO US.
  // Pinned rather than fixed. See the test comment for the full statement of the residual.
  // ==========================================================================================
  describe("Cantina-Apr 3.2.4: signature expiry", function () {
    it("Cantina-Apr 3.2.4: RESIDUAL — an ERC-1271 assertion stays valid forever", async function () {
      const ctx = await loadFixture(deployFixture);
      const { account } = ctx;

      const { digest, sig } = buildErc1271Payload(ctx, (d) =>
        encodeSignatureWrapper(0n, webauthnSignature(d, PASSKEY_PRIV)),
      );
      assert.strictEqual(await account.read.isValidSignature([digest, sig]), ERC1271_MAGIC);

      const TEN_YEARS = 10n * 365n * 24n * 60n * 60n;
      await time.increase(TEN_YEARS);

      assert.strictEqual(
        await account.read.isValidSignature([digest, sig]),
        ERC1271_MAGIC,
        "an ERC-1271 assertion is still valid ten years later — this is the residual, pinned",
      );

      // THE RESIDUAL, STATED PRECISELY (so it is not re-raised as a new finding, and so that the
      // day someone adds expiry the blast radius is visible):
      //
      // 1. This wallet imposes NO time bound of its own on ERC-1271. `isValidSignature`
      //    (StarzipWallet.sol:693) reads no clock; the ERC-7739 envelope carries no deadline field.
      //    Any deadline is the APP's to put inside `contents` and enforce itself — TradeSettlementV1
      //    does exactly that with its own order `deadline`, which is why this is a residual rather
      //    than a live hole for our own integration.
      // 2. The 4337 path has the same property by a different route: `_validateSignature`
      //    (:756-761) returns SIG_VALIDATION_SUCCESS = 0, which in ERC-4337's packed
      //    `validationData` encoding means validAfter = 0 and validUntil = 0 (= "no expiry"). The
      //    wallet never returns a time range. Replay of the OP itself is still prevented by the
      //    EntryPoint nonce — it is the ERC-1271 surface that has no equivalent.
      // 3. THE ONLY REVOCATION IS REMOVING THE OWNER (`removeOwnerAtIndex`, :396), and that is
      //    forward-looking in one specific sense worth being exact about: it stops the removed key
      //    producing NEW assertions, and it also invalidates already-produced ones, because
      //    `_verifyOwnerSignature` looks the owner up at verification time (:844) — an emptied slot
      //    returns false. The adversarial suite proves that. What CANNOT be revoked is an assertion
      //    already CONSUMED by an app that recorded its result.
      // 4. Consequence for incident response: there is no "sign out everywhere" primitive short of
      //    removing the owner, which also removes its ability to authorize the removal of anything
      //    else. A user who suspects one key is exposed must have a SECOND owner already registered
      //    (which is the wallet's entire recovery model — see the contract-level NatSpec).
      const domain = (await account.read.eip712Domain()) as any[];
      assert.strictEqual(
        domain[1] as string,
        WALLET_EIP712_NAME,
        "sanity: still the same wallet, later",
      );
    });
  });

  // ==========================================================================================
  // Cantina-Apr 3.2.5 — INCONSISTENT OWNER ORDERING. Bucket: (c) RESIDUAL, acknowledged upstream
  // as informational. Largely covered already by the adversarial suite's "the FULL owner set (and
  // its ORDER) is bound into the CREATE2 address"; this adds the single crisp statement of it.
  // ==========================================================================================
  describe("Cantina-Apr 3.2.5: owner ordering", function () {
    it("Cantina-Apr 3.2.5: the same owner SET in two different ORDERS yields two DIFFERENT wallets", async function () {
      const { factory } = await loadFixture(deployFixture);
      const a = encodeAddressOwner("0x00000000000000000000000000000000000000f1" as Address);
      const b = encodePasskeyOwner(PK_X, PK_Y);
      // Coinbase acknowledged this as INFORMATIONAL: the owner set is part of the CREATE2 initcode,
      // so ordering is inherently address-relevant. The practical cost is a client contract, not a
      // vulnerability — restoring a wallet from a backed-up owner list in a different order yields
      // a different, EMPTY wallet rather than an error. Our factory NatSpec
      // (StarzipWalletFactory.sol:40-44) states this explicitly.
      assert.notStrictEqual(
        (await factory.read.getAddress([[a, b], 55n])) as Address,
        (await factory.read.getAddress([[b, a], 55n])) as Address,
        "[A,B] and [B,A] must be different addresses",
      );
    });
  });

  // ==========================================================================================
  // Cantina-Dec 3.3.3 — `removeOwnerAtIndex` SHOULD REVERT ON AN EMPTY INDEX. Bucket: (b) CLOSED.
  // We revert `NoSuchOwner` (StarzipWallet.sol:399). The adversarial suite covers the racing-removal
  // case; this is the direct, minimal assertion the finding asks for.
  // ==========================================================================================
  describe("Cantina-Dec 3.3.3: removeOwnerAtIndex on an empty index", function () {
    it("Cantina-Dec 3.3.3: removing a never-written index reverts NoSuchOwner", async function () {
      const ctx = await loadFixture(passthroughOwnerFixture);

      // Never written: index 9 (nextOwnerIndex is 4).
      assert.strictEqual((await ctx.w.read.nextOwnerIndex()) as bigint, 4n);
      assert.strictEqual((await ctx.w.read.ownerAtIndex([9n])) as Hex, "0x");
      await assert.rejects(
        ctx.self(
          encodeFunctionData({
            abi: ctx.w.abi,
            functionName: "removeOwnerAtIndex",
            args: [9n, ctx.initialOwners[0]],
          }),
        ),
        /NoSuchOwner/,
        "a never-written index must revert NoSuchOwner, not silently succeed",
      );

      // Already removed: index 1, removed once, then removed again.
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
        "a previously-emptied index must revert NoSuchOwner too",
      );

      assert.strictEqual(
        (await ctx.w.read.ownerCount()) as bigint,
        3n,
        "exactly one removal took effect",
      );
    });
  });
});
