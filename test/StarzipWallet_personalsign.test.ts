/**
 * StarzipWallet — remediation: only the ERC-7739 `TypedDataSign` workflow is accepted;
 * `PersonalSign` is not.
 *
 * BACKGROUND: `draft-ERC7739Upgradeable.sol`'s stock `isValidSignature` ORs two independent
 * acceptance branches — `TypedDataSign` (binds the requesting app's domain separator) and
 * `PersonalSign` (binds ONLY the wallet's own domain; the caller-supplied 32-byte `hash` passes
 * through unmodified). This product has no PersonalSign use case (every integration signs typed
 * data), and the PersonalSign branch reopens exactly the blind-signing hole ERC-7739 exists to
 * close: a malicious dApp can compute a `TradeSettlementV1` order digest, present it to the victim
 * as an opaque "login challenge," and — if the victim's client signs it via `personal_sign` — the
 * resulting wrapper validates. `TradeSettlementV1._authorizeOrderSig` Path A returns
 * `sessionKey = address(0)` for ERC-1271 approvals, so NO session-key spend cap applies — full
 * settlement balance is exposed.
 *
 * ROUND 1 OF THIS FIX WAS WRONG (kept here as a record, not a warning label to future readers —
 * see StarzipWallet.sol's isValidSignature NatSpec for the full account). It called
 * `super.isValidSignature` as an acceptance oracle and then tried to infer, after the fact, which
 * OR'd branch had validated by checking `hash == appSeparator.toTypedDataHash(contentsHash)`. That
 * check is VACUOUS for a real EIP-712 digest: `toTypedDataHash(a, c) == keccak256(0x1901‖a‖c)` is
 * exactly what every EIP-712 digest already looks like, and `appSeparator`/`contentsHash` are
 * public data an attacker can read off the target app. An attacker could phish a PersonalSign
 * signature over a REAL order digest, then simply APPEND the (public) `appSeparator ‖ contentsHash
 * ‖ contentsDescr ‖ uint16(len)` suffix to the bare assertion — `WebAuthn.tryDecodeAuth` tolerates
 * trailing bytes after a well-formed assertion, so this still decoded, OZ's PersonalSign branch
 * (which hands the ENTIRE signature buffer to `_rawSignatureValidation`) still validated it, and
 * round 1's "narrowing" check passed too, because the identity it tested is definitionally true for
 * `hash`'s own real domain/struct-hash pair. Net: round 1 left the exact same exploit open against
 * exactly the high-value digests (settlement orders, Permit2) it was meant to close, for the cost of
 * appending ~98 bytes. This file's "appended envelope" tests exist specifically to catch a
 * regression back to that shape of bug.
 *
 * THE ACTUAL FIX (round 2, refined round 3): `isValidSignature` no longer calls
 * `super.isValidSignature` at all. It reimplements the `TypedDataSign` workflow directly (mirroring
 * OZ's private `_isValidNestedTypedDataSignature` on the PUBLIC `ERC7739Utils` library) and verifies
 * the passkey against a NESTED DIGEST RECONSTRUCTED FROM THIS WALLET'S OWN DOMAIN
 * (`eip712Domain()`, never attacker-supplied) combined with the `appSeparator`/`structHash` decoded
 * from the signature.
 *
 * WHAT IS ACTUALLY LOAD-BEARING (round-3 correction — mutation-verified, not assumed): the digest
 * reconstruction above, and never implementing (nor OR-ing in) the `PersonalSign` workflow — which
 * binds a DIFFERENT, weaker digest that drops the requesting app's domain entirely. Using the
 * decoded INNER signature slice (rather than the full `signature` buffer) when verifying the
 * passkey is DEFENSE IN DEPTH ONLY. An earlier version of this comment (and of
 * StarzipWallet.sol's NatSpec) claimed the inner-slice restriction itself was "the load-bearing
 * difference from round 1" — that claim was FALSE and has been corrected: mutation-testing
 * StarzipWallet.sol (substituting the full `signature` buffer for the inner slice at the
 * `_rawSignatureValidation` call site) still compiles, and EVERY test in this file and in
 * StarzipWallet_erc1271.test.ts still passes — 0 failures, PROBE A included. The reason: `WebAuthn`
 * decodes from offset 0, so a slice that decodes successfully makes the FULL buffer decode to the
 * SAME `WebAuthnAuth` struct (the appended suffix bytes fall after the struct's own dynamic-field
 * boundaries and are simply never read). What genuinely cannot be satisfied by a mismatched
 * envelope is the CHALLENGE inside that struct — `WebAuthn`'s `_validateChallenge` requires
 * `clientDataJSON` to encode EXACTLY the correctly-reconstructed nested digest — and that digest is
 * exactly the two load-bearing properties above, independent of which buffer was sliced.
 * `_verifyPasskey`'s round-2 length check (rejecting signature buffers with bytes beyond what the
 * decoded struct accounts for) was REMOVED in round 3 for the same reason: it also closed nothing
 * PROBE A needed closed (same mutation-testing method), while adding gas cost and reject surface to
 * the ERC-4337 money path.
 *
 * PROVEN CORRECTNESS CLAIM (verified, not assumed): the passkey is verified against a digest that is
 * bound to the requesting app's domain, this wallet's own domain, AND the exact contents hash — so an
 * assertion produced under a different envelope cannot also validate here. This file does not claim
 * the underlying reason is "keccak256 preimage resistance on attacker bytes" (that claim was false in
 * round 1 for exactly the reason above) — the guarantee comes from the passkey signature having to
 * cover the actual reconstructed digest, verified with WebAuthn's own challenge-binding.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseUnits,
  parseEther,
  encodeFunctionData,
  encodeAbiParameters,
  hashStruct,
  keccak256,
  toBytes,
  toHex,
  pad,
  concatHex,
  zeroAddress,
  parseEventLogs,
  hexToBytes,
  stringToHex,
  type Hex,
  type Address,
} from "viem";
import { signTypedData } from "viem/accounts";
import { loadFixture, getConnection, time } from "./helpers.js";
import {
  passkeyPubCoords,
  webauthnSignature,
  execViaPasskey,
  domainSeparator,
  erc7739TypedDataSig,
  erc7739PersonalSig,
  encodeErc7739TypedDataSig,
  encodeSignatureWrapper,
  encodePasskeyOwner,
  buildUserOp,
  WALLET_EIP712_NAME,
  WALLET_EIP712_VERSION,
  type Eip712Domain,
} from "./aa-helpers.js";

const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const { x: PK_X, y: PK_Y } = passkeyPubCoords(PASSKEY_PRIV);

// Owner index 0 is the wallet's sole owner in every fixture in this file.
const ownerSig = (priv: Uint8Array) => (d: Hex) =>
  encodeSignatureWrapper(0n, webauthnSignature(d, priv));

const SALT = 9191n;
const ERC1271_MAGIC = "0x1626ba7e";
const ERC1271_INVALID = "0xffffffff";
const ERC7739_PROBE_HASH =
  "0x7739773977397739773977397739773977397739773977397739773977397739" as Hex;
const ERC7739_PROBE_ANSWER = "0x77390001";

// Hardhat default key for wallet client index 2 (bob), used as the EOA counterparty / session key.
const BOB_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;

const ORDER_TYPES = {
  Order: [
    { name: "account", type: "address" },
    { name: "baseToken", type: "address" },
    { name: "quoteToken", type: "address" },
    { name: "isBuy", type: "bool" },
    { name: "baseAmount", type: "uint256" },
    { name: "quoteAmount", type: "uint256" },
    { name: "maxFeeRate", type: "uint256" },
    { name: "nonce", type: "uint256" },
    { name: "expiry", type: "uint256" },
  ],
} as const;
// Byte-identical to TradeSettlementV1.ORDER_TYPEHASH's typestring — this is what the frontend
// must put in the ERC-7739 `contentsDescr` field, and what an attacker would ALSO know (it's
// public), which is exactly why round 1's "narrowing" check was not a real defense.
const ORDER_DESCR =
  "Order(address account,address baseToken,address quoteToken,bool isBuy,uint256 baseAmount," +
  "uint256 quoteAmount,uint256 maxFeeRate,uint256 nonce,uint256 expiry)";

const SESSION_KEY_TYPES = {
  SessionKeyAuth: [
    { name: "account", type: "address" },
    { name: "sessionKey", type: "address" },
    { name: "validUntil", type: "uint256" },
    { name: "deadline", type: "uint256" },
    { name: "tokens", type: "address[]" },
    { name: "caps", type: "uint256[]" },
    { name: "orderCaps", type: "uint256[]" },
    { name: "nonce", type: "uint256" },
  ],
} as const;
const SESSION_KEY_DESCR =
  "SessionKeyAuth(address account,address sessionKey,uint256 validUntil,uint256 deadline," +
  "address[] tokens,uint256[] caps,uint256[] orderCaps,uint256 nonce)";

type Order = {
  account: Address;
  baseToken: Address;
  quoteToken: Address;
  isBuy: boolean;
  baseAmount: bigint;
  quoteAmount: bigint;
  maxFeeRate: bigint;
  nonce: bigint;
  expiry: bigint;
};

describe("StarzipWallet — only the ERC-7739 TypedDataSign workflow is accepted", function () {
  // --------------------------------------------------------------
  // Wallet-only fixture (unit tests) — mirrors StarzipWallet_erc1271.test.ts walletFixture.
  // --------------------------------------------------------------
  async function walletFixture() {
    const { viem } = await getConnection();
    const [deployer, beneficiary] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, zeroAddress]);
    const firstOwner = encodePasskeyOwner(PK_X, PK_Y);
    await factory.write.createAccount([[firstOwner], SALT], {
      account: deployer.account,
    });
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

  // --------------------------------------------------------------
  // E2E fixture — mirrors StarzipWallet_erc1271.test.ts settlementFixture.
  // --------------------------------------------------------------
  async function settlementFixture() {
    const base = await walletFixture();
    const { viem, publicClient, entryPoint, account, walletAddr, deployer, beneficiary } = base;
    const [owner, operator, bob, feeRecipient] = await viem.getWalletClients();
    const chainId = await publicClient.getChainId();

    const quoteToken = await viem.deployContract("USDT", [owner.account.address, 18]);
    const baseToken = await viem.deployContract("USDT", [owner.account.address, 18]);

    const settlementImpl = await viem.deployContract("TradeSettlementV1", []);
    const initData = encodeFunctionData({
      abi: settlementImpl.abi,
      functionName: "initialize",
      args: [feeRecipient.account.address, zeroAddress],
    });
    const settlementProxy = await viem.deployContract("ERC1967Proxy", [
      settlementImpl.address,
      initData,
    ]);
    const settlement = await viem.getContractAt("TradeSettlementV1", settlementProxy.address);

    const queueHash = await settlement.write.queueOperatorChange([operator.account.address, true]);
    const queueReceipt = await publicClient.waitForTransactionReceipt({ hash: queueHash });
    const changeId = (
      parseEventLogs({
        abi: settlement.abi,
        logs: queueReceipt.logs,
        eventName: "OperatorChangeQueued",
      })[0] as unknown as { args: { changeId: Hex } }
    ).args.changeId;
    await time.increase(24n * 60n * 60n + 1n);
    await settlement.write.executeOperatorChange([changeId]);

    await settlement.write.setQuoteAsset([quoteToken.address, true]);
    await settlement.write.setSupportedToken([baseToken.address, true]);

    const walletQuote = parseUnits("5000", 18);
    await quoteToken.write.mint([walletAddr, walletQuote]);
    const asWallet = (target: Address, innerCalldata: Hex) =>
      execViaPasskey({
        publicClient,
        entryPoint,
        walletAbi: account.abi,
        walletAddr,
        target,
        innerCalldata,
        passkeyPriv: PASSKEY_PRIV,
        submitter: deployer,
        beneficiary: beneficiary.account.address,
      });
    await asWallet(
      quoteToken.address,
      encodeFunctionData({
        abi: quoteToken.abi,
        functionName: "approve",
        args: [settlement.address, walletQuote],
      }),
    );
    await asWallet(
      settlement.address,
      encodeFunctionData({
        abi: settlement.abi,
        functionName: "depositToken",
        args: [quoteToken.address, walletQuote],
      }),
    );

    const bobBase = parseUnits("1000", 18);
    await baseToken.write.mint([bob.account.address, bobBase]);
    await baseToken.write.approve([settlement.address, bobBase], { account: bob.account });
    await settlement.write.depositToken([baseToken.address, bobBase], { account: bob.account });

    const expiry = (await time.latest()) + 3600n;

    return {
      ...base,
      settlement,
      quoteToken,
      baseToken,
      owner,
      operator,
      bob,
      feeRecipient,
      chainId,
      expiry,
    };
  }

  const domainFor = (chainId: number, verifyingContract: Address) =>
    ({
      name: "StarZipTradeSettlement",
      version: "1",
      chainId,
      verifyingContract,
    }) as const;

  // Arbitrary "some other app" verifyingContract — shared across the and explicit-mode suites.
  const GENERIC_APP_ADDR = "0x000000000000000000000000000000000000cafe" as Address;

  // Build the critic's PROBE-A attack: a bare PersonalSign assertion over `hash`, with the REAL
  // (public) appSeparator/contentsHash/contentsDescr of some app's typed-data struct appended after
  // it — exactly the byte layout ERC7739Utils.decodeTypedDataSig expects for a TypedDataSign
  // envelope, EXCEPT the "inner signature" portion was never actually produced for that nested
  // digest; it's a signature over an unrelated PersonalSign digest, with a disguise appended.
  function buildDisguisedPersonalSig(params: {
    hash: Hex;
    walletDomain: Eip712Domain;
    appSeparator: Hex;
    contentsHash: Hex;
    contentsDescr: string;
  }): Hex {
    const bareAssertion = erc7739PersonalSig({
      hash: params.hash,
      walletDomain: params.walletDomain,
      sign: ownerSig(PASSKEY_PRIV),
    });
    return encodeErc7739TypedDataSig({
      innerSignature: bareAssertion,
      appSeparator: params.appSeparator,
      contentsHash: params.contentsHash,
      contentsDescr: params.contentsDescr,
    });
  }

  // --------------------------------------------------------------
  // 1. Core regression — bare PersonalSign (no disguise) must fail.
  // --------------------------------------------------------------
  describe("bare PersonalSign envelope (no TypedDataSign disguise)", function () {
    it("rejects a PersonalSign envelope over an arbitrary opaque hash", async function () {
      const { account, walletDomain } = await loadFixture(walletFixture);
      const V = keccak256(toBytes("harvested login challenge"));
      const sig = erc7739PersonalSig({
        hash: V,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });
      assert.strictEqual(await account.read.isValidSignature([V, sig]), ERC1271_INVALID);
    });
  });

  // --------------------------------------------------------------
  // 2. Core regression — critic PROBE A: PersonalSign DISGUISED as TypedDataSign via an appended
  //    appSeparator/contentsHash/contentsDescr suffix built from a REAL order digest. This is the
  //    exact construction that bypassed round 1.
  // --------------------------------------------------------------
  describe("PROBE A: PersonalSign disguised as TypedDataSign (round-1 regression guard)", function () {
    it("rejects isValidSignature(orderDigest, disguisedSig) — must be 0xffffffff, not 0x1626ba7e", async function () {
      const f = await loadFixture(settlementFixture);
      const {
        account,
        settlement,
        quoteToken,
        baseToken,
        walletAddr,
        chainId,
        expiry,
        walletDomain,
      } = f;

      const buyOrder: Order = {
        account: walletAddr,
        baseToken: baseToken.address,
        quoteToken: quoteToken.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      const appDomain = domainFor(chainId, settlement.address);
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = hashStruct({ data: buyOrder, primaryType: "Order", types: ORDER_TYPES });
      // orderDigest == exactly appSeparator.toTypedDataHash(contentsHash) — this IS the definitional
      // shape of every EIP-712 digest, which is why round 1's identity check was vacuous here.
      const orderDigest = keccak256(
        `0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex,
      );

      const disguisedSig = buildDisguisedPersonalSig({
        hash: orderDigest,
        walletDomain,
        appSeparator,
        contentsHash,
        contentsDescr: ORDER_DESCR,
      });

      assert.strictEqual(
        await account.read.isValidSignature([orderDigest, disguisedSig]),
        ERC1271_INVALID,
        "a disguised PersonalSign-over-a-real-order-digest must not validate",
      );
    });
  });

  // --------------------------------------------------------------
  // 3. E2E — settleOrders must revert for the disguised (PROBE A) signature.
  // --------------------------------------------------------------
  describe("E2E: settleOrders reverts for a PROBE-A disguised order signature", function () {
    it("reverts InvalidSignature — the disguised-PersonalSign-as-order-approval path is closed", async function () {
      const f = await loadFixture(settlementFixture);
      const { settlement, quoteToken, baseToken, walletAddr, operator, bob, chainId, expiry } = f;
      const { walletDomain } = f;

      const fillBase = parseUnits("100", 18);
      const fillQuote = parseUnits("1000", 18);
      const buyOrder: Order = {
        account: walletAddr,
        baseToken: baseToken.address,
        quoteToken: quoteToken.address,
        isBuy: true,
        baseAmount: fillBase,
        quoteAmount: fillQuote,
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      const sellOrder: Order = { ...buyOrder, account: bob.account.address, isBuy: false };

      const appDomain = domainFor(chainId, settlement.address);
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = hashStruct({ data: buyOrder, primaryType: "Order", types: ORDER_TYPES });
      const orderDigest = keccak256(
        `0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex,
      );

      const buySig = buildDisguisedPersonalSig({
        hash: orderDigest,
        walletDomain,
        appSeparator,
        contentsHash,
        contentsDescr: ORDER_DESCR,
      });
      const sellSig = await signTypedData({
        privateKey: BOB_KEY,
        domain: appDomain,
        types: ORDER_TYPES,
        primaryType: "Order",
        message: sellOrder,
      });

      await assert.rejects(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: fillBase,
              fillQuoteAmount: fillQuote,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: keccak256(toBytes("m1-probeA-blocked")),
            },
          ],
          { account: operator.account },
        ),
        /InvalidSignature/,
      );
    });
  });

  // --------------------------------------------------------------
  // 4. _verifyPasskey and trailing-garbage-padded assertions — round 2 added a length check here
  //    that rejected these; round 3 REMOVED it (critic mutation-matrix finding: it contributed
  //    nothing to blocking PROBE A — the isValidSignature reimplementation alone already blocks it
  //    cryptographically — while costing +654 gas per ERC-1271 verification and adding a reject
  //    surface to the ERC-4337 money path against round-1's own "don't touch it" instruction). These
  //    tests now pin the CURRENT (post-removal) behavior: a genuine signature padded with trailing
  //    garbage still validates, because WebAuthn's own decode tolerates it and the underlying
  //    signature is real — padding a genuine signature grants an attacker no new forgery capability,
  //    since they needed that genuine signature over the exact digest already. This is intentional,
  //    not a regression; see _verifyPasskey's NatSpec "HISTORY" note for the full record.
  // --------------------------------------------------------------
  describe("_verifyPasskey: trailing-garbage padding is harmless (length check removed round 3)", function () {
    it("a genuine TypedDataSign envelope whose inner assertion has appended garbage still validates", async function () {
      const f = await loadFixture(settlementFixture);
      const {
        account,
        settlement,
        quoteToken,
        baseToken,
        walletAddr,
        chainId,
        expiry,
        walletDomain,
      } = f;

      const buyOrder: Order = {
        account: walletAddr,
        baseToken: baseToken.address,
        quoteToken: quoteToken.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      const appDomain = domainFor(chainId, settlement.address);
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = hashStruct({ data: buyOrder, primaryType: "Order", types: ORDER_TYPES });
      const orderDigest = keccak256(
        `0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex,
      );

      const goodSig = erc7739TypedDataSig({
        appSeparator,
        contentsHash,
        contentsDescr: ORDER_DESCR,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });
      assert.strictEqual(
        await account.read.isValidSignature([orderDigest, goodSig]),
        ERC1271_MAGIC,
        "control: unmodified envelope validates",
      );

      // Splice 16 garbage bytes into the middle of the encoded inner signature (right before the
      // appended appSeparator/contentsHash/contentsDescr/len suffix). decodeTypedDataSig slices
      // purely from the END of the buffer, so this garbage becomes part of "innerSignature" as far
      // as decoding goes.
      const suffixBytes = 32 + 32 + ORDER_DESCR.length + 2; // appSeparator + contentsHash + descr + len16
      const suffixHexChars = suffixBytes * 2;
      const innerHexEnd = goodSig.length - suffixHexChars;
      const innerHex = goodSig.slice(0, innerHexEnd);
      const suffixHex = goodSig.slice(innerHexEnd);
      const garbage = "deadbeef".repeat(4); // 16 bytes of garbage
      const taintedSig = (innerHex + garbage + suffixHex) as Hex;

      assert.strictEqual(
        await account.read.isValidSignature([orderDigest, taintedSig]),
        ERC1271_MAGIC,
        "padding a GENUINE inner signature is harmless — the underlying assertion is still real, " +
          "still challenge-bound to the correct digest, and grants no new forgery capability",
      );
    });

    it("a userOp whose genuine passkey signature has appended garbage still validates (4337 path, matches HEAD)", async function () {
      const { entryPoint, account, walletAddr, deployer, beneficiary, publicClient } =
        await loadFixture(walletFixture);
      const callData = encodeFunctionData({
        abi: account.abi,
        functionName: "execute",
        args: [walletAddr, 0n, "0x"],
      });
      const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
      const userOp = buildUserOp(walletAddr, nonce, callData);
      const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
      const goodSig = webauthnSignature(userOpHash, PASSKEY_PRIV);
      // Pad the RAW inner WebAuthn assertion (inside SignatureWrapper.signatureData) with garbage
      // before wrapping — matches the pre-rewrite test's intent: trailing bytes inside the genuine
      // assertion are harmless because WebAuthn.tryDecodeAuth ignores them.
      userOp.signature = encodeSignatureWrapper(
        0n,
        concatHex([goodSig, "0xdeadbeefdeadbeef"]) as Hex,
      );
      // Does NOT reject — matches HEAD (pre-) behavior exactly, restored by removing round 2's
      // length check. userOpHash is already EntryPoint-domain-bound; padding an otherwise-genuine
      // signature is cosmetic, not a forgery vector.
      const hash = await entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
        account: deployer.account,
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      assert.strictEqual(receipt.status, "success");
    });
  });

  // --------------------------------------------------------------
  // (CRITICAL, round 3) — a degenerate `contentsDescr` collapses
  // ERC7739Utils.typedDataSignStructHash to bytes32(0) WITHOUT ever hashing in `contentsHash` or
  // `domainBytes` (wallet's own name/version/chainId/verifyingContract/salt). The nested digest then
  // becomes the CONSTANT `appSeparator.toTypedDataHash(bytes32(0))` — a single signature over that
  // constant becomes a universal key: it authorizes ANY order under that app domain, on ANY wallet
  // sharing the passkey, unlimited replay. `"Order"` (bare type NAME instead of the full type
  // STRING) is the single most likely frontend integration mistake and collapses exactly like this.
  // --------------------------------------------------------------
  describe("degenerate contentsDescr collapses the nested digest to a universal key", function () {
    // Strings that OZ's ERC7739Utils.decodeContentsDescr decodes to an EMPTY contentsName, making
    // typedDataSignStructHash short-circuit to bytes32(0) regardless of contentsHash/domainBytes.
    const DEGENERATE_DESCRS = [
      "Order", // bare type NAME — the realistic frontend bug
      "x",
      "(foo)",
      " ",
      ",",
      "Order(address a", // no closing paren
      "Order(address a) ", // trailing space after a well-formed-looking close
    ];

    // The nested digest a passkey signs when contentsDescr degenerates: toTypedDataHash(appSeparator,
    // bytes32(0)) — independent of contentsHash and of this wallet's own domain.
    function degenerateNestedDigest(appSeparator: Hex): Hex {
      return keccak256(`0x1901${appSeparator.slice(2)}${"0".repeat(64)}` as Hex);
    }

    function buildDegenerateSig(params: {
      innerSignature?: Hex;
      appSeparator: Hex;
      contentsHash: Hex;
      contentsDescr: string;
    }): Hex {
      const innerSignature =
        params.innerSignature ??
        encodeSignatureWrapper(
          0n,
          webauthnSignature(degenerateNestedDigest(params.appSeparator), PASSKEY_PRIV),
        );
      return encodeErc7739TypedDataSig({
        innerSignature,
        appSeparator: params.appSeparator,
        contentsHash: params.contentsHash,
        contentsDescr: params.contentsDescr,
      });
    }

    for (const descr of DEGENERATE_DESCRS) {
      it(`rejects degenerate contentsDescr=${JSON.stringify(descr)}`, async function () {
        const { account, chainId } = await loadFixture(walletFixture);
        const appDomain = {
          name: "GenericApp",
          version: "1",
          chainId,
          verifyingContract: GENERIC_APP_ADDR,
        };
        const appSeparator = domainSeparator(appDomain);
        const contentsHash = keccak256(toBytes(`arbitrary contents for ${descr}`));
        const hash = keccak256(`0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex);
        const sig = buildDegenerateSig({ appSeparator, contentsHash, contentsDescr: descr });
        assert.strictEqual(
          await account.read.isValidSignature([hash, sig]),
          ERC1271_INVALID,
          `descr=${JSON.stringify(descr)} must not collapse the digest to a universal key`,
        );
      });
    }

    it("positive control: a well-formed contentsDescr still validates (structHash != 0)", async function () {
      const { account, walletDomain, chainId } = await loadFixture(walletFixture);
      const appDomain = {
        name: "GenericApp",
        version: "1",
        chainId,
        verifyingContract: GENERIC_APP_ADDR,
      };
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = keccak256(toBytes("well-formed contents"));
      const hash = keccak256(`0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex);
      const sig = erc7739TypedDataSig({
        appSeparator,
        contentsHash,
        contentsDescr: "GenericMsg(bytes32 contentsHash)",
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });
      assert.strictEqual(await account.read.isValidSignature([hash, sig]), ERC1271_MAGIC);
    });

    it("(b1) one degenerate-descr signature no longer authorizes two different orders", async function () {
      const f = await loadFixture(settlementFixture);
      const { account, settlement, baseToken, quoteToken, walletAddr, chainId, expiry } = f;
      const appDomain = domainFor(chainId, settlement.address);
      const appSeparator = domainSeparator(appDomain);
      // ONE underlying assertion, signed once over the appSeparator-only constant digest.
      const innerSignature = encodeSignatureWrapper(
        0n,
        webauthnSignature(degenerateNestedDigest(appSeparator), PASSKEY_PRIV),
      );

      const orderA: Order = {
        account: walletAddr,
        baseToken: baseToken.address,
        quoteToken: quoteToken.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      const orderB: Order = {
        ...orderA,
        baseAmount: parseUnits("999", 18),
        quoteAmount: parseUnits("1", 18),
        nonce: 77n,
      };
      const contentsHashA = hashStruct({ data: orderA, primaryType: "Order", types: ORDER_TYPES });
      const contentsHashB = hashStruct({ data: orderB, primaryType: "Order", types: ORDER_TYPES });
      const hashA = keccak256(`0x1901${appSeparator.slice(2)}${contentsHashA.slice(2)}` as Hex);
      const hashB = keccak256(`0x1901${appSeparator.slice(2)}${contentsHashB.slice(2)}` as Hex);
      const sigA = buildDegenerateSig({
        innerSignature,
        appSeparator,
        contentsHash: contentsHashA,
        contentsDescr: "Order",
      });
      const sigB = buildDegenerateSig({
        innerSignature,
        appSeparator,
        contentsHash: contentsHashB,
        contentsDescr: "Order",
      });

      assert.strictEqual(
        await account.read.isValidSignature([hashA, sigA]),
        ERC1271_INVALID,
        "order A",
      );
      assert.strictEqual(
        await account.read.isValidSignature([hashB, sigB]),
        ERC1271_INVALID,
        "order B (same underlying signature bytes as order A)",
      );
    });

    it("(b2) the same degenerate-descr signature is no longer accepted by two different wallets sharing the passkey", async function () {
      const f = await loadFixture(walletFixture);
      const { viem, factory, deployer, chainId } = f;
      const wallet1 = f.account;
      const SALT2 = 9192n;
      await factory.write.createAccount([[encodePasskeyOwner(PK_X, PK_Y)], SALT2], {
        account: deployer.account,
      });
      const walletAddr2 = (await factory.read.getAddress([
        [encodePasskeyOwner(PK_X, PK_Y)],
        SALT2,
      ])) as Address;
      const wallet2 = await viem.getContractAt("StarzipWallet", walletAddr2);

      const appDomain = {
        name: "GenericApp",
        version: "1",
        chainId,
        verifyingContract: GENERIC_APP_ADDR,
      };
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = keccak256(toBytes("cross-wallet replay attempt"));
      const hash = keccak256(`0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex);
      const sig = buildDegenerateSig({ appSeparator, contentsHash, contentsDescr: "Order" });

      assert.strictEqual(
        await wallet1.read.isValidSignature([hash, sig]),
        ERC1271_INVALID,
        "wallet1",
      );
      assert.strictEqual(
        await wallet2.read.isValidSignature([hash, sig]),
        ERC1271_INVALID,
        "wallet2 (would have been a cross-wallet replay of the exact same signature pre-fix)",
      );
    });

    it("(b3) positive control: a well-formed descr binds per-wallet (cross-wallet replay still fails)", async function () {
      const f = await loadFixture(walletFixture);
      const { viem, factory, deployer, chainId, walletDomain: wallet1Domain } = f;
      const wallet1 = f.account;
      const SALT2 = 9193n;
      await factory.write.createAccount([[encodePasskeyOwner(PK_X, PK_Y)], SALT2], {
        account: deployer.account,
      });
      const walletAddr2 = (await factory.read.getAddress([
        [encodePasskeyOwner(PK_X, PK_Y)],
        SALT2,
      ])) as Address;
      const wallet2 = await viem.getContractAt("StarzipWallet", walletAddr2);

      const appDomain = {
        name: "GenericApp",
        version: "1",
        chainId,
        verifyingContract: GENERIC_APP_ADDR,
      };
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = keccak256(toBytes("well-formed per-wallet binding"));
      const hash = keccak256(`0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex);
      const sig = erc7739TypedDataSig({
        appSeparator,
        contentsHash,
        contentsDescr: "GenericMsg(bytes32 contentsHash)",
        walletDomain: wallet1Domain,
        sign: ownerSig(PASSKEY_PRIV),
      });

      assert.strictEqual(
        await wallet1.read.isValidSignature([hash, sig]),
        ERC1271_MAGIC,
        "wallet1 (signed for)",
      );
      assert.strictEqual(
        await wallet2.read.isValidSignature([hash, sig]),
        ERC1271_INVALID,
        "wallet2 (different domain — well-formed descr correctly binds it out)",
      );
    });

    it("(b4) E2E: settleOrders reverts for a degenerate-descr ('Order' bare type name) buy signature", async function () {
      const f = await loadFixture(settlementFixture);
      const { settlement, quoteToken, baseToken, walletAddr, operator, bob, chainId, expiry } = f;

      const fillBase = parseUnits("100", 18);
      const fillQuote = parseUnits("1000", 18);
      const buyOrder: Order = {
        account: walletAddr,
        baseToken: baseToken.address,
        quoteToken: quoteToken.address,
        isBuy: true,
        baseAmount: fillBase,
        quoteAmount: fillQuote,
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      const sellOrder: Order = { ...buyOrder, account: bob.account.address, isBuy: false };

      const appDomain = domainFor(chainId, settlement.address);
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = hashStruct({ data: buyOrder, primaryType: "Order", types: ORDER_TYPES });
      const buySig = buildDegenerateSig({ appSeparator, contentsHash, contentsDescr: "Order" });
      const sellSig = await signTypedData({
        privateKey: BOB_KEY,
        domain: appDomain,
        types: ORDER_TYPES,
        primaryType: "Order",
        message: sellOrder,
      });

      await assert.rejects(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: fillBase,
              fillQuoteAmount: fillQuote,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: keccak256(toBytes("c1-degenerate-descr-blocked")),
            },
          ],
          { account: operator.account },
        ),
        /InvalidSignature/,
      );
    });

    it("replay negative control: a well-formed envelope does not validate against a DIFFERENT contentsHash", async function () {
      const { account, walletDomain, chainId } = await loadFixture(walletFixture);
      const appDomain = {
        name: "GenericApp",
        version: "1",
        chainId,
        verifyingContract: GENERIC_APP_ADDR,
      };
      const appSeparator = domainSeparator(appDomain);
      const contentsHashA = keccak256(toBytes("contents A"));
      const contentsHashB = keccak256(toBytes("contents B"));
      const sigA = erc7739TypedDataSig({
        appSeparator,
        contentsHash: contentsHashA,
        contentsDescr: "GenericMsg(bytes32 contentsHash)",
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });
      const hashB = keccak256(`0x1901${appSeparator.slice(2)}${contentsHashB.slice(2)}` as Hex);
      assert.strictEqual(
        await account.read.isValidSignature([hashB, sigA]),
        ERC1271_INVALID,
        "well-formed envelope for contents A must not validate contents B",
      );
    });
  });

  // --------------------------------------------------------------
  // "explicit mode" (Major 2, round 3 critic finding) — draft-ERC7739Utils.sol:169-207
  // `decodeContentsDescr` has TWO modes selected by the LAST byte of `contentsDescr`. A descr NOT
  // ending in `)` still binds correctly via EXPLICIT mode (name read from the BACK, up to the last
  // `)`) as long as some `)` exists before a forbidden byte would be hit scanning backward — the
  // resulting name is provably non-empty whenever explicit mode succeeds. This suite's coverage was
  // previously 100% implicit-mode (every real descr in this codebase ends in `)`); this closes that
  // gap with a genuine positive case, guarding against a future "fast reject anything not ending in
  // `)`" optimization silently breaking legitimate explicit-mode integrations.
  // --------------------------------------------------------------
  describe("explicit mode: a contentsDescr NOT ending in ')' can still validate correctly", function () {
    // Mirrors ERC7739Utils.typedDataSignStructHash, taking the ALREADY-DECODED (contentsName,
    // contentsType) pair directly rather than deriving contentsName via `descr.indexOf("(")`
    // (which is only correct for implicit mode — see aa-helpers.ts's erc7739TypedDataDigest, which
    // is implicit-mode-only and must NOT be reused here).
    function nestedDigestForDecodedPair(params: {
      appSeparator: Hex;
      contentsHash: Hex;
      contentsName: string;
      contentsType: string;
      walletDomain: Eip712Domain;
    }): Hex {
      const typedDataSignTypehash = keccak256(
        stringToHex(
          `TypedDataSign(${params.contentsName} contents,string name,string version,uint256 chainId,` +
            `address verifyingContract,bytes32 salt)${params.contentsType}`,
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
          keccak256(stringToHex(params.walletDomain.name)),
          keccak256(stringToHex(params.walletDomain.version)),
          BigInt(params.walletDomain.chainId),
          params.walletDomain.verifyingContract,
          pad("0x00", { size: 32 }),
        ],
      );
      const structHash = keccak256(
        concatHex([typedDataSignTypehash, params.contentsHash, domainBytes]),
      );
      return keccak256(concatHex(["0x1901", params.appSeparator, structHash]));
    }

    // Hand-traced against draft-ERC7739Utils.sol:180-196's explicit-mode backward scan, then
    // verified by direct execution (each row below independently confirmed to return 0x1626ba7e).
    const EXPLICIT_MODE_CASES = [
      { descr: ")Order", contentsName: "Order", contentsType: ")" },
      { descr: "Order(address a)Order", contentsName: "Order", contentsType: "Order(address a)" },
      { descr: "(foo)X", contentsName: "X", contentsType: "(foo)" },
      { descr: "()X", contentsName: "X", contentsType: "()" },
      { descr: "Order(uint256 a)Name", contentsName: "Name", contentsType: "Order(uint256 a)" },
    ];

    for (const c of EXPLICIT_MODE_CASES) {
      it(`descr=${JSON.stringify(c.descr)} (last byte != ')') validates via explicit mode, name=${JSON.stringify(c.contentsName)}`, async function () {
        const { account, walletDomain, chainId } = await loadFixture(walletFixture);
        const appDomain = {
          name: "GenericApp",
          version: "1",
          chainId,
          verifyingContract: GENERIC_APP_ADDR,
        };
        const appSeparator = domainSeparator(appDomain);
        const contentsHash = keccak256(toBytes(`explicit-mode contents for ${c.descr}`));
        const hash = keccak256(`0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex);
        const digest = nestedDigestForDecodedPair({
          appSeparator,
          contentsHash,
          contentsName: c.contentsName,
          contentsType: c.contentsType,
          walletDomain,
        });
        const sig = encodeErc7739TypedDataSig({
          innerSignature: encodeSignatureWrapper(0n, webauthnSignature(digest, PASSKEY_PRIV)),
          appSeparator,
          contentsHash,
          contentsDescr: c.descr,
        });
        assert.strictEqual(
          await account.read.isValidSignature([hash, sig]),
          ERC1271_MAGIC,
          `explicit-mode descr=${JSON.stringify(c.descr)} must validate — it is NOT degenerate ` +
            "despite not ending in ')'",
        );
      });
    }
  });

  // --------------------------------------------------------------
  // eip712Domain() non-revert invariant (round-3 critic finding). EIP712Upgradeable.eip712Domain()
  // (node_modules/@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol:129)
  // `require($._hashedName == 0 && $._hashedVersion == 0, "EIP712: Uninitialized")` — this wallet
  // deliberately never calls `__EIP712_init` (see EIP712_NAME/EIP712_VERSION's NatSpec), so that
  // storage stays zero and this require always passes today. If a FUTURE upgrade ever called
  // `__EIP712_init`, this require would flip to permanently reverting, which would make
  // isValidSignature revert for EVERY input (it calls eip712Domain() unconditionally), which
  // SignatureChecker's staticcall swallows as a clean `false` — every wallet's ERC-1271 order
  // signature would silently stop verifying, with no revert reason pointing at the cause. This test
  // pins the current (correct) non-reverting state so any future violation is caught immediately.
  // --------------------------------------------------------------
  describe("eip712Domain() non-revert invariant", function () {
    it("does not revert, and returns this wallet's own domain", async function () {
      const { account, walletAddr, chainId } = await loadFixture(walletFixture);
      const d = (await account.read.eip712Domain()) as [
        Hex,
        string,
        string,
        bigint,
        Address,
        Hex,
        bigint[],
      ];
      assert.strictEqual(d[1], WALLET_EIP712_NAME);
      assert.strictEqual(d[2], WALLET_EIP712_VERSION);
      assert.strictEqual(d[3], BigInt(chainId));
      assert.strictEqual(d[4].toLowerCase(), walletAddr.toLowerCase());
    });
  });

  // --------------------------------------------------------------
  // 5. Negative controls — behavior that must NOT break.
  // --------------------------------------------------------------
  describe("negative controls", function () {
    it("still settles a normal TypedDataSign-wrapped order", async function () {
      const f = await loadFixture(settlementFixture);
      const { settlement, quoteToken, baseToken, walletAddr, operator, bob, chainId, expiry } = f;
      const { walletDomain } = f;

      const fillBase = parseUnits("100", 18);
      const fillQuote = parseUnits("1000", 18);
      const buyOrder: Order = {
        account: walletAddr,
        baseToken: baseToken.address,
        quoteToken: quoteToken.address,
        isBuy: true,
        baseAmount: fillBase,
        quoteAmount: fillQuote,
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      const sellOrder: Order = { ...buyOrder, account: bob.account.address, isBuy: false };
      const appDomain = domainFor(chainId, settlement.address);

      const buySig = erc7739TypedDataSig({
        appSeparator: domainSeparator(appDomain),
        contentsHash: hashStruct({ data: buyOrder, primaryType: "Order", types: ORDER_TYPES }),
        contentsDescr: ORDER_DESCR,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });
      const sellSig = await signTypedData({
        privateKey: BOB_KEY,
        domain: appDomain,
        types: ORDER_TYPES,
        primaryType: "Order",
        message: sellOrder,
      });

      const bal = (u: Address, t: Address) => settlement.read.getBalance([u, t]) as Promise<bigint>;
      const w0b = await bal(walletAddr, baseToken.address);

      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: fillBase,
            fillQuoteAmount: fillQuote,
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: keccak256(toBytes("m1-typeddata-still-works")),
          },
        ],
        { account: operator.account },
      );

      assert.strictEqual(await bal(walletAddr, baseToken.address), w0b + fillBase, "wallet base");
    });

    it("still answers the ERC-7739 support probe with 0x77390001", async function () {
      const { account } = await loadFixture(walletFixture);
      assert.strictEqual(
        await account.read.isValidSignature([ERC7739_PROBE_HASH, "0x"]),
        ERC7739_PROBE_ANSWER,
      );
    });

    it("still registers a session key via registerSessionKeyWithSig (TypedDataSign envelope)", async function () {
      const f = await loadFixture(settlementFixture);
      const { settlement, walletAddr, quoteToken, bob, expiry, walletDomain, chainId } = f;

      const cap = parseUnits("500", 18);
      const auth = {
        account: walletAddr,
        sessionKey: bob.account.address,
        validUntil: expiry,
        deadline: expiry,
        tokens: [quoteToken.address] as Address[],
        caps: [cap],
        orderCaps: [2n ** 256n - 1n],
        nonce: 0n,
      };
      const appDomain = domainFor(chainId, settlement.address);
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = hashStruct({
        data: auth,
        primaryType: "SessionKeyAuth",
        types: SESSION_KEY_TYPES,
      });
      const sig = erc7739TypedDataSig({
        appSeparator,
        contentsHash,
        contentsDescr: SESSION_KEY_DESCR,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });

      await settlement.write.registerSessionKeyWithSig([auth, sig], { account: bob.account });

      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([walletAddr, bob.account.address])) as bigint,
        expiry,
      );
    });

    it("still exposes the wallet's own EIP-712 domain via eip712Domain() (ERC-5267)", async function () {
      const { account, walletAddr, chainId } = await loadFixture(walletFixture);
      const d = (await account.read.eip712Domain()) as [
        Hex,
        string,
        string,
        bigint,
        Address,
        Hex,
        bigint[],
      ];
      assert.strictEqual(d[1], WALLET_EIP712_NAME);
      assert.strictEqual(d[2], WALLET_EIP712_VERSION);
      assert.strictEqual(d[3], BigInt(chainId));
      assert.strictEqual(d[4].toLowerCase(), walletAddr.toLowerCase());
    });
  });
});
