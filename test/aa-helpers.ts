/**
 * Shared ERC-4337 + WebAuthn(P-256) test helpers for StarzipWallet.
 * Builds real WebAuthn assertions and routes passkey-signed userOps through a real EntryPoint v0.8.
 */
import {
  encodeAbiParameters,
  encodeFunctionData,
  pad,
  toHex,
  toFunctionSelector,
  hexToBytes,
  concatHex,
  sha256,
  keccak256,
  stringToHex,
  type Hex,
  type Address,
  type Abi,
} from "viem";
import { p256 } from "@noble/curves/p256";

// ============ Owner-set encoding (StarzipWallet multi-owner model) ============

/** `abi.encode(address)` — a 32-byte EOA-style owner, as {StarzipWallet-initialize} /
 *  {StarzipWallet-addOwnerAddress} expect. */
export function encodeAddressOwner(owner: Address): Hex {
  return encodeAbiParameters([{ type: "address" }], [owner]);
}

/** `abi.encode(bytes32 x, bytes32 y)` — a 64-byte P-256 passkey owner, as
 *  {StarzipWallet-initialize} / {StarzipWallet-addOwnerPublicKey} expect. */
export function encodePasskeyOwner(x: Hex, y: Hex): Hex {
  return encodeAbiParameters([{ type: "bytes32" }, { type: "bytes32" }], [x, y]);
}

/**
 * `abi.encode(SignatureWrapper({ownerIndex, signatureData}))` — the format
 * `StarzipWallet._decodeSignatureWrapper` parses for BOTH `userOp.signature` and the ERC-1271
 * `signature` argument (via the ERC-7739 envelope's `innerSignature` slot). Matches the
 * lone-dynamic-tuple ABI encoding StarzipWallet.sol's decoder documents byte-for-byte (a leading
 * 0x20 tuple offset, then the struct's own [ownerIndex][offset][len][data] layout).
 */
export function encodeSignatureWrapper(ownerIndex: bigint, signatureData: Hex): Hex {
  return encodeAbiParameters(
    [
      {
        type: "tuple",
        components: [
          { name: "ownerIndex", type: "uint256" },
          { name: "signatureData", type: "bytes" },
        ],
      },
    ],
    [{ ownerIndex, signatureData }],
  );
}

// base64url, no padding — matches OZ Base64.encodeURL.
export function base64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// pack two uint128 into bytes32: (hi << 128) | lo  (PackedUserOperation gas packing).
export function packU128Pair(hi: bigint, lo: bigint): Hex {
  return pad(toHex((hi << 128n) | lo), { size: 32 });
}

// Public key coordinates (bytes32 x, y) for a P-256 private key.
export function passkeyPubCoords(priv: Uint8Array): { x: Hex; y: Hex } {
  const pub = p256.getPublicKey(priv, false); // 0x04 || X(32) || Y(32)
  return {
    x: pad(toHex(pub.slice(1, 33)), { size: 32 }),
    y: pad(toHex(pub.slice(33, 65)), { size: 32 }),
  };
}

/**
 * Build a real WebAuthn assertion over `userOpHash` and abi.encode it as
 * OZ WebAuthn.WebAuthnAuth (the exact struct StarzipWallet._validateSignature decodes).
 * flags default to UP|UV = 0x05 (requireUV satisfied); P-256 low-s.
 * `flags` is overridable so tests can prove the UV requirement is enforced (e.g. "0x01" = UP only).
 */
export function webauthnSignature(userOpHash: Hex, priv: Uint8Array, flags: Hex = "0x05"): Hex {
  const challengeB64 = base64url(hexToBytes(userOpHash));
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${challengeB64}","origin":"https://starzip.io"}`;
  const typeIndex = BigInt(clientDataJSON.indexOf('"type":"webauthn.get"'));
  const challengeIndex = BigInt(clientDataJSON.indexOf('"challenge":"'));

  const rpIdHash = sha256(toHex("starzip.io"));
  const authenticatorData = concatHex([rpIdHash, flags, "0x00000000"]); // rpIdHash(32)|flags|signCount = 37 bytes

  const clientDataHash = sha256(toHex(clientDataJSON));
  const msgHash = sha256(concatHex([authenticatorData, clientDataHash]));

  const sig = p256.sign(hexToBytes(msgHash), priv, { lowS: true });
  const r = pad(toHex(sig.r), { size: 32 });
  const s = pad(toHex(sig.s), { size: 32 });

  // Flat 6-field encoding (NO wrapping tuple/offset) — this is the layout OZ
  // WebAuthn.tryDecodeAuth expects (struct head starts at byte 0). Equivalent to
  // Solidity abi.encode(r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON).
  return encodeAbiParameters(
    [
      { name: "r", type: "bytes32" },
      { name: "s", type: "bytes32" },
      { name: "challengeIndex", type: "uint256" },
      { name: "typeIndex", type: "uint256" },
      { name: "authenticatorData", type: "bytes" },
      { name: "clientDataJSON", type: "string" },
    ],
    [r, s, challengeIndex, typeIndex, authenticatorData, clientDataJSON],
  );
}

// ============ ERC-7739 (nested/defensive ERC-1271 signatures) ============

export type Eip712Domain = {
  name: string;
  version: string;
  chainId: number | bigint;
  verifyingContract: Address;
};

/** StarzipWallet's OWN EIP-712 domain — must mirror StarzipWallet.EIP712_NAME / EIP712_VERSION. */
export const WALLET_EIP712_NAME = "StarzipWallet";
export const WALLET_EIP712_VERSION = "1";

const EIP712_DOMAIN_TYPEHASH = keccak256(
  stringToHex("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
);

/** keccak256(abi.encode(EIP712Domain typehash, name, version, chainId, verifyingContract)). */
export function domainSeparator(d: Eip712Domain): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "address" },
      ],
      [
        EIP712_DOMAIN_TYPEHASH,
        keccak256(stringToHex(d.name)),
        keccak256(stringToHex(d.version)),
        BigInt(d.chainId),
        d.verifyingContract,
      ],
    ),
  );
}

// MessageHashUtils.toTypedDataHash: keccak256(0x1901 ‖ separator ‖ structHash)
const toTypedDataHash = (separator: Hex, structHash: Hex): Hex =>
  keccak256(concatHex(["0x1901", separator, structHash]));

/**
 * The digest a wallet actually signs for an ERC-7739 `TypedDataSign` wrapper:
 *
 *   TypedDataSign(<ContentsName> contents,string name,string version,uint256 chainId,
 *                 address verifyingContract,bytes32 salt)<ContentsType>
 *
 * struct-hashed with the ACCOUNT's domain fields inline, then sealed under the APP's domain
 * separator. Mirrors ERC7739Utils.typedDataSignStructHash + MessageHashUtils.toTypedDataHash.
 */
export function erc7739TypedDataDigest(params: {
  appSeparator: Hex;
  contentsHash: Hex;
  /** Full EIP-712 type string of the contents, implicit mode (starts with the type name, ends in `)`). */
  contentsDescr: string;
  walletDomain: Eip712Domain;
  salt?: Hex;
}): Hex {
  const { appSeparator, contentsHash, contentsDescr, walletDomain } = params;
  const contentsName = contentsDescr.slice(0, contentsDescr.indexOf("("));
  const typedDataSignTypehash = keccak256(
    stringToHex(
      `TypedDataSign(${contentsName} contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)${contentsDescr}`,
    ),
  );
  const domainBytes = encodeAbiParameters(
    [
      { type: "bytes32" },
      { type: "bytes32" },
      { type: "uint256" },
      { type: "address" },
      { type: "bytes32" },
    ],
    [
      keccak256(stringToHex(walletDomain.name)),
      keccak256(stringToHex(walletDomain.version)),
      BigInt(walletDomain.chainId),
      walletDomain.verifyingContract,
      params.salt ?? pad("0x00", { size: 32 }),
    ],
  );
  const structHash = keccak256(concatHex([typedDataSignTypehash, contentsHash, domainBytes]));
  return toTypedDataHash(appSeparator, structHash);
}

/**
 * Pack an ERC-7739 `TypedDataSign` signature:
 *   innerSignature ‖ APP_DOMAIN_SEPARATOR ‖ contentsHash ‖ contentsDescr ‖ uint16(len(contentsDescr))
 * (ERC7739Utils.encodeTypedDataSig).
 */
export function encodeErc7739TypedDataSig(params: {
  innerSignature: Hex;
  appSeparator: Hex;
  contentsHash: Hex;
  contentsDescr: string;
}): Hex {
  const descrHex = stringToHex(params.contentsDescr);
  // uint16 length field must be the BYTE length of the UTF-8-encoded descr, not
  // `contentsDescr.length` (JS string length = UTF-16 code units — coincides with byte length only
  // for ASCII; a non-ASCII descr would silently mis-encode). Derive it from `descrHex` itself
  // (`0x` + 2 hex chars per byte) so it's always consistent with what's actually appended.
  const descrByteLength = (descrHex.length - 2) / 2;
  return concatHex([
    params.innerSignature,
    params.appSeparator,
    params.contentsHash,
    descrHex,
    pad(toHex(descrByteLength), { size: 2 }),
  ]);
}

/**
 * One-shot: produce the wrapped ERC-1271 signature a StarzipWallet now requires for an app's
 * EIP-712 struct. `sign` receives the nested digest (so tests can plug in any signer, or a
 * deliberately wrong one).
 */
export function erc7739TypedDataSig(params: {
  appSeparator: Hex;
  contentsHash: Hex;
  contentsDescr: string;
  walletDomain: Eip712Domain;
  sign: (digest: Hex) => Hex;
}): Hex {
  const digest = erc7739TypedDataDigest(params);
  return encodeErc7739TypedDataSig({
    innerSignature: params.sign(digest),
    appSeparator: params.appSeparator,
    contentsHash: params.contentsHash,
    contentsDescr: params.contentsDescr,
  });
}

const PERSONAL_SIGN_TYPEHASH = keccak256(stringToHex("PersonalSign(bytes prefixed)"));

/**
 * ERC-7739 `PersonalSign` path: the raw hash is nested under the WALLET's own domain (no app
 * domain involved) and the assertion is submitted unwrapped.
 */
export function erc7739PersonalSig(params: {
  hash: Hex;
  walletDomain: Eip712Domain;
  sign: (digest: Hex) => Hex;
}): Hex {
  const structHash = keccak256(concatHex([PERSONAL_SIGN_TYPEHASH, params.hash]));
  return params.sign(toTypedDataHash(domainSeparator(params.walletDomain), structHash));
}

export type PackedUserOp = {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  accountGasLimits: Hex;
  preVerificationGas: bigint;
  gasFees: Hex;
  paymasterAndData: Hex;
  signature: Hex;
};

// A PackedUserOperation with sane default gas for local tests.
export function buildUserOp(sender: Address, nonce: bigint, callData: Hex): PackedUserOp {
  return {
    sender,
    nonce,
    initCode: "0x",
    callData,
    accountGasLimits: packU128Pair(2_000_000n, 2_000_000n), // verificationGasLimit | callGasLimit
    preVerificationGas: 200_000n,
    gasFees: packU128Pair(1_000_000_000n, 100_000_000_000n), // maxPriorityFeePerGas | maxFeePerGas
    paymasterAndData: "0x",
    signature: "0x",
  };
}

/**
 * Submit a passkey-signed userOp whose callData is `wallet.execute(target, 0, innerCalldata)`,
 * routed through a real EntryPoint v0.8. Returns the handleOps receipt.
 */
export async function execViaPasskey(params: {
  publicClient: any;
  entryPoint: any; // viem contract for (Test)EntryPoint
  walletAbi: Abi;
  walletAddr: Address;
  target: Address;
  innerCalldata: Hex;
  passkeyPriv: Uint8Array;
  submitter: any; // wallet client that sends handleOps
  beneficiary: Address;
  /** Index of the signing passkey in the wallet's owner set. Defaults to 0 (the first/only owner
   *  in every single-owner fixture). */
  ownerIndex?: bigint;
}) {
  const {
    publicClient,
    entryPoint,
    walletAbi,
    walletAddr,
    target,
    innerCalldata,
    passkeyPriv,
    submitter,
    beneficiary,
    ownerIndex = 0n,
  } = params;

  const callData = encodeFunctionData({
    abi: walletAbi,
    functionName: "execute",
    args: [target, 0n, innerCalldata],
  });
  const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
  const userOp = buildUserOp(walletAddr, nonce, callData);
  const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
  userOp.signature = encodeSignatureWrapper(ownerIndex, webauthnSignature(userOpHash, passkeyPriv));

  const hash = await entryPoint.write.handleOps([[userOp], beneficiary], {
    account: submitter.account,
  });
  return publicClient.waitForTransactionReceipt({ hash });
}

// ============ VerifyingPaymaster (policy-storage) helpers ============

// Pack a single uint128 into its 16-byte big-endian representation.
function packU128(v: bigint): Hex {
  return pad(toHex(v), { size: 16 });
}

/**
 * Build `paymasterAndData` for the policy-storage VerifyingPaymaster:
 * addr(20) | validationGas(16) | postOpGas(16) | empty data — exactly PAYMASTER_DATA_OFFSET
 * (52) bytes, matching UserOperationLib's paymaster field layout.
 */
export function paymasterAndDataFor(pm: Address, valGas: bigint, postGas: bigint): Hex {
  return concatHex([pm, packU128(valGas), packU128(postGas)]);
}

// Build callData for wallet.execute(target, value, data) — used for both the business path
// (target in the paymaster's businessAllowlist) and the personal path (target not allowlisted).
export function buildExecuteCallData(
  walletAbi: Abi,
  target: Address,
  value: bigint,
  data: Hex = "0x",
): Hex {
  return encodeFunctionData({
    abi: walletAbi,
    functionName: "execute",
    args: [target, value, data],
  });
}

// Build callData for wallet.executeBatch(dests, values, funcs).
export function buildExecuteBatchCallData(
  walletAbi: Abi,
  dests: Address[],
  values: bigint[],
  funcs: Hex[],
): Hex {
  return encodeFunctionData({
    abi: walletAbi,
    functionName: "executeBatch",
    args: [dests, values, funcs],
  });
}

const EXECUTE_BATCH_SELECTOR = toFunctionSelector("executeBatch(address[],uint256[],bytes[])");

/**
 * Malformed `executeBatch` calldata variants for exercising the paymaster's defensive
 * `_extractBusinessOk` decode (m1): every variant must decline cleanly, never revert.
 * - "unknownSelector": 4 bytes, no recognizable selector.
 * - "short": valid selector but shorter than the 100-byte minimum head.
 * - "badOffset": valid length, but the `dest` array offset points out of bounds.
 * - "oversizedN": valid head + offset, but the announced array length exceeds MAX_BATCH_SIZE (32).
 */
export function craftedBatchCallData(
  variant: "unknownSelector" | "short" | "badOffset" | "oversizedN",
): Hex {
  switch (variant) {
    case "unknownSelector":
      return "0xdeadbeef";
    case "short":
      // selector + 1 word (36 bytes total) — below the 100-byte minimum head.
      return concatHex([EXECUTE_BATCH_SELECTOR, pad(toHex(0n), { size: 32 })]);
    case "badOffset": {
      // 3 head words (dest/values/funcs offsets), dest offset way out of range.
      const head = concatHex([
        EXECUTE_BATCH_SELECTOR,
        pad(toHex(999_999n), { size: 32 }), // bogus dest offset
        pad(toHex(0n), { size: 32 }),
        pad(toHex(0n), { size: 32 }),
      ]);
      return concatHex([head, pad(toHex(0n), { size: 32 })]); // pad past the 100-byte floor
    }
    case "oversizedN": {
      // dest offset = 96 -> length word lands right after the 3-word head (the normal layout),
      // but the announced length (33) exceeds MAX_BATCH_SIZE (32) with no backing element data.
      const head = concatHex([
        EXECUTE_BATCH_SELECTOR,
        pad(toHex(96n), { size: 32 }),
        pad(toHex(0n), { size: 32 }),
        pad(toHex(0n), { size: 32 }),
      ]);
      const n = pad(toHex(33n), { size: 32 });
      return concatHex([head, n]);
    }
  }
}

const EXECUTE_SELECTOR = toFunctionSelector("execute(address,uint256,bytes)");

/**
 * Malformed / adversarial calldata variants aimed specifically at the (target, inner selector)
 * decode added for . Every variant must decline cleanly (AA34), never hard-revert
 * (AA33), because `_extractBusinessOk` now follows the `bytes func` offset as well.
 * All of them use `target` as dest so the decline can only come from the selector-side decode.
 * - "shortHead": valid `execute` selector but shorter than the 100-byte minimum head.
 * - "funcOffsetOutOfRange": full head, but the `func` offset points out of bounds.
 * - "emptyFunc": well-formed `execute` whose `func` is empty (no selector to check).
 * - "shortFunc": `func` length 3 — too short to carry a 4-byte selector.
 * - "truncatedFunc": `func` announces 64 bytes but only 32 are actually present.
 * - "batchFuncOffsetOutOfRange": well-formed `executeBatch` head/arrays, but the single `funcs`
 *   element offset points out of bounds.
 */
export function craftedSelectorCallData(
  variant:
    | "shortHead"
    | "funcOffsetOutOfRange"
    | "emptyFunc"
    | "shortFunc"
    | "truncatedFunc"
    | "batchFuncOffsetOutOfRange",
  target: Address,
): Hex {
  const word = (v: bigint | Address): Hex =>
    pad(typeof v === "bigint" ? toHex(v) : v, { size: 32 });

  switch (variant) {
    case "shortHead":
      // selector + dest + value only (68 bytes) — below the 100-byte minimum head.
      return concatHex([EXECUTE_SELECTOR, word(target), word(0n)]);
    case "funcOffsetOutOfRange":
      return concatHex([
        EXECUTE_SELECTOR,
        word(target),
        word(0n),
        word(999_999n), // bogus `func` offset
        word(0n), // padding past the 100-byte floor
      ]);
    case "emptyFunc":
      return concatHex([EXECUTE_SELECTOR, word(target), word(0n), word(96n), word(0n)]);
    case "shortFunc":
      return concatHex([
        EXECUTE_SELECTOR,
        word(target),
        word(0n),
        word(96n),
        word(3n), // func length 3 < 4
        word(0n),
      ]);
    case "truncatedFunc":
      return concatHex([
        EXECUTE_SELECTOR,
        word(target),
        word(0n),
        word(96n),
        word(64n), // announces 64 bytes of func...
        word(0n), // ...but only 32 follow
      ]);
    case "batchFuncOffsetOutOfRange":
      // dest @rel 96 (len 1), values @rel 160 (len 1), funcs @rel 224 (len 1, bogus element offset)
      return concatHex([
        EXECUTE_BATCH_SELECTOR,
        word(96n),
        word(160n),
        word(224n),
        word(1n),
        word(target), // dest
        word(1n),
        word(0n), // values
        word(1n),
        word(999_999n), // funcs: one element, offset out of range
      ]);
  }
}

/**
 * Submit a passkey-signed userOp with an arbitrary `paymasterAndData` + `callData`, routed
 * through a real EntryPoint v0.8. Unlike {execViaPasskey}, this does not assume the callData
 * shape and does not swallow a revert — callers assert success/failure via `opSucceeded` (for
 * sponsored ops) or by catching the rejected promise (for HARD_DECLINE / deferred ops, which
 * revert the whole handleOps call at the EntryPoint level — AA34/AA32).
 * `accountGasLimits`/`preVerificationGas`/`gasFees` override {buildUserOp}'s defaults so callers
 * can pin the EntryPoint's `maxCost` (= requiredGas * maxFeePerGas, see
 * EntryPoint._getRequiredPrefund) to an exact, precomputed value for cap/budget boundary tests.
 */
export async function execWithPaymaster(params: {
  publicClient: any;
  entryPoint: any;
  walletAddr: Address;
  callData: Hex;
  paymasterAndData: Hex;
  passkeyPriv: Uint8Array;
  submitter: any;
  beneficiary: Address;
  accountGasLimits?: Hex;
  preVerificationGas?: bigint;
  gasFees?: Hex;
  /** Index of the signing passkey in the wallet's owner set. Defaults to 0 (the first/only owner
   *  in every single-owner fixture). */
  ownerIndex?: bigint;
}) {
  const {
    publicClient,
    entryPoint,
    walletAddr,
    callData,
    paymasterAndData,
    passkeyPriv,
    submitter,
    beneficiary,
    accountGasLimits,
    preVerificationGas,
    gasFees,
    ownerIndex = 0n,
  } = params;

  const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
  const userOp = buildUserOp(walletAddr, nonce, callData);
  userOp.paymasterAndData = paymasterAndData;
  if (accountGasLimits) userOp.accountGasLimits = accountGasLimits;
  if (preVerificationGas !== undefined) userOp.preVerificationGas = preVerificationGas;
  if (gasFees) userOp.gasFees = gasFees;
  const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
  userOp.signature = encodeSignatureWrapper(ownerIndex, webauthnSignature(userOpHash, passkeyPriv));

  const hash = await entryPoint.write.handleOps([[userOp], beneficiary], {
    account: submitter.account,
  });
  return publicClient.waitForTransactionReceipt({ hash });
}

/**
 * Replicates EntryPoint's exact `_getRequiredPrefund` formula:
 *   maxCost = (verificationGasLimit + callGasLimit + paymasterVerificationGasLimit +
 *              paymasterPostOpGasLimit + preVerificationGas) * maxFeePerGas
 * Lets tests pin per-wallet/global cap thresholds to an EXACT value instead of guessing margins.
 */
export function computeMaxCost(params: {
  verificationGasLimit: bigint;
  callGasLimit: bigint;
  paymasterVerificationGasLimit: bigint;
  paymasterPostOpGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
}): bigint {
  const {
    verificationGasLimit,
    callGasLimit,
    paymasterVerificationGasLimit,
    paymasterPostOpGasLimit,
    preVerificationGas,
    maxFeePerGas,
  } = params;
  const requiredGas =
    verificationGasLimit +
    callGasLimit +
    paymasterVerificationGasLimit +
    paymasterPostOpGasLimit +
    preVerificationGas;
  return requiredGas * maxFeePerGas;
}
