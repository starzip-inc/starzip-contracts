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
  type Hex,
  type Address,
  type Abi,
} from "viem";
import { p256 } from "@noble/curves/p256";

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
 * flags = UP|UV = 0x05 (requireUV satisfied); P-256 low-s.
 */
export function webauthnSignature(userOpHash: Hex, priv: Uint8Array): Hex {
  const challengeB64 = base64url(hexToBytes(userOpHash));
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${challengeB64}","origin":"https://starzip.io"}`;
  const typeIndex = BigInt(clientDataJSON.indexOf('"type":"webauthn.get"'));
  const challengeIndex = BigInt(clientDataJSON.indexOf('"challenge":"'));

  const rpIdHash = sha256(toHex("starzip.io"));
  const authenticatorData = concatHex([rpIdHash, "0x05", "0x00000000"]); // rpIdHash(32)|flags|signCount = 37 bytes

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
  } = params;

  const callData = encodeFunctionData({
    abi: walletAbi,
    functionName: "execute",
    args: [target, 0n, innerCalldata],
  });
  const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
  const userOp = buildUserOp(walletAddr, nonce, callData);
  const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
  userOp.signature = webauthnSignature(userOpHash, passkeyPriv);

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
 * `_extractBusinessOk` decode: every variant must decline cleanly, never revert.
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
  } = params;

  const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
  const userOp = buildUserOp(walletAddr, nonce, callData);
  userOp.paymasterAndData = paymasterAndData;
  if (accountGasLimits) userOp.accountGasLimits = accountGasLimits;
  if (preVerificationGas !== undefined) userOp.preVerificationGas = preVerificationGas;
  if (gasFees) userOp.gasFees = gasFees;
  const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
  userOp.signature = webauthnSignature(userOpHash, passkeyPriv);

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
