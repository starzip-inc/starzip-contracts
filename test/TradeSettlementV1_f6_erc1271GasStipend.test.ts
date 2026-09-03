/**
 * F6: empirical basis for `TradeSettlementV1.ERC1271_GAS_STIPEND`.
 *
 * The prior comment cited 55,505 gas as the "measured floor of a passkey StarzipWallet's
 * isValidSignature", but that number was actually `validateUserOp`'s measured cost
 * (VerifyingPaymaster.sol:111) — a different function on a different call path. This file
 * measures the ACTUAL target: `StarzipWallet.isValidSignature`, called the same way
 * `TradeSettlementV1._isValidERC1271SignatureStipended` calls it (a bounded STATICCALL), for both
 * a passkey (P-256 / WebAuthn) owner and an EOA owner — the worst case is the basis for the
 * stipend.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { zeroAddress, keccak256, toBytes, hexToBytes, type Hex, type Address } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { getConnection } from "./helpers.js";
import {
  passkeyPubCoords,
  webauthnSignature,
  encodeSignatureWrapper,
  encodePasskeyOwner,
  encodeAddressOwner,
  domainSeparator,
  erc7739TypedDataDigest,
  encodeErc7739TypedDataSig,
  WALLET_EIP712_NAME,
  WALLET_EIP712_VERSION,
  type Eip712Domain,
} from "./aa-helpers.js";

const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const { x: PK_X, y: PK_Y } = passkeyPubCoords(PASSKEY_PRIV);
const EOA_OWNER_PRIV = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

const SALT = 313131n;
const ERC1271_MAGIC = "0x1626ba7e";
const GENERIC_APP_ADDR = "0x000000000000000000000000000000000000cafe" as Address;

async function deployWallet(viem: any, ownerBlob: Hex) {
  const publicClient = await viem.getPublicClient();
  const chainId = await publicClient.getChainId();
  const [deployer] = await viem.getWalletClients();

  const entryPoint = await viem.deployContract("TestEntryPoint", []);
  const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, zeroAddress]);
  await factory.write.createAccount([[ownerBlob], SALT], { account: deployer.account });
  const walletAddr = (await factory.read.getAddress([[ownerBlob], SALT])) as Address;
  const account = await viem.getContractAt("StarzipWallet", walletAddr);

  const walletDomain: Eip712Domain = {
    name: WALLET_EIP712_NAME,
    version: WALLET_EIP712_VERSION,
    chainId,
    verifyingContract: walletAddr,
  };
  return { walletAddr, account, walletDomain };
}

function buildDigestAndDescr() {
  const appDomain = { name: "GenericApp", version: "1", chainId: 0, verifyingContract: GENERIC_APP_ADDR };
  const contentsDescr = "GenericMsg(bytes32 contentsHash)";
  const contentsHash = keccak256(toBytes("f6-gas-measurement"));
  return { appDomain, contentsDescr, contentsHash };
}

async function deployFixture() {
  const { viem } = await getConnection();
  const probe = await viem.deployContract("IsValidSignatureGasProbe", []);

  const passkeyOwnerBlob = encodePasskeyOwner(PK_X, PK_Y);
  const passkeyWallet = await deployWallet(viem, passkeyOwnerBlob);

  const eoaOwner = privateKeyToAccount(EOA_OWNER_PRIV);
  const eoaWallet = await deployWallet(viem, encodeAddressOwner(eoaOwner.address));

  return { viem, probe, passkeyWallet, eoaWallet, eoaOwner };
}

async function measureIsValidSignatureGas(
  probe: any,
  wallet: { walletDomain: Eip712Domain; walletAddr: Address; account: any },
  sign: (digest: Hex) => Promise<Hex>,
): Promise<{ gasUsed: bigint; result: Hex }> {
  const { appDomain, contentsDescr, contentsHash } = buildDigestAndDescr();
  const appSeparator = domainSeparator(appDomain);
  const digest = erc7739TypedDataDigest({
    appSeparator,
    contentsHash,
    contentsDescr,
    walletDomain: wallet.walletDomain,
  });
  const innerSig = await sign(digest);
  const sig = encodeErc7739TypedDataSig({
    innerSignature: innerSig,
    appSeparator,
    contentsHash,
    contentsDescr,
  });
  const hash = keccak256(`0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex);

  // Sanity: the wallet itself must accept this signature (proves the probe measures a REAL
  // successful validation, not a rejection short-circuit).
  const direct = (await wallet.account.read.isValidSignature([hash, sig])) as Hex;
  assert.strictEqual(direct, ERC1271_MAGIC, "precondition: signature must be valid");

  const gasUsed = (await probe.read.measure([wallet.walletAddr, hash, sig])) as bigint;
  return { gasUsed, result: direct };
}

describe("F6: empirical isValidSignature gas for ERC1271_GAS_STIPEND", function () {
  it("measures StarzipWallet.isValidSignature gas for a passkey (P-256/WebAuthn) owner and an EOA owner", async function () {
    const { probe, passkeyWallet, eoaWallet, eoaOwner } = await deployFixture();

    const passkey = await measureIsValidSignatureGas(probe, passkeyWallet, async (digest) =>
      encodeSignatureWrapper(0n, webauthnSignature(digest, PASSKEY_PRIV)),
    );
    const eoa = await measureIsValidSignatureGas(probe, eoaWallet, async (digest) =>
      encodeSignatureWrapper(0n, await eoaOwner.sign({ hash: digest })),
    );

    console.log(
      `\n    [F6] StarzipWallet.isValidSignature measured gas:\n` +
        `      passkey (P-256/WebAuthn) owner: ${passkey.gasUsed}\n` +
        `      EOA owner:                     ${eoa.gasUsed}\n`,
    );

    // Passkey verification (P256VERIFY precompile + ERC-7739 nested-digest reconstruction) is the
    // structurally more expensive path; EOA ECDSA recovery is cheap. This is the worst-case basis
    // ERC1271_GAS_STIPEND must be derived from.
    assert.ok(
      passkey.gasUsed > eoa.gasUsed,
      "passkey verification is expected to be the more expensive of the two owner types",
    );

    // ERC1271_GAS_STIPEND pin: see TradeSettlementV1.sol's derivation comment. This tripwire
    // fails loudly if a future change to StarzipWallet.isValidSignature (or its owner-set shape)
    // pushes the measured worst case past the stipend the settlement contract budgets for.
    const ERC1271_GAS_STIPEND = 120_000n;
    assert.ok(
      passkey.gasUsed < ERC1271_GAS_STIPEND,
      `measured worst-case isValidSignature gas (${passkey.gasUsed}) must stay under ` +
        `ERC1271_GAS_STIPEND (${ERC1271_GAS_STIPEND}) — re-derive the constant if this ever fails`,
    );
  });
});
