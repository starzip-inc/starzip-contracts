/**
 * StarzipWallet — ERC-1271 hardened with ERC-7739 defensive rehashing.
 *
 * Why this file exists: before `isValidSignature` was added, `StarzipWallet` had NO ERC-1271 entry
 * point (and no fallback), so `SignatureChecker.isValidSignatureNow(wallet, ...)` always returned
 * false. That killed `TradeSettlementV1._authorizeOrderSig` Path A and `registerSessionKeyWithSig`
 * for every passkey wallet — a session key was the ONLY way an AA account could trade, while an EOA
 * could simply sign. The requirement is that
 * EOA and AA accounts behave identically.
 *
 * BREAKING FORMAT CHANGE (this round): the wallet no longer honours a bare passkey assertion over
 * a raw 32-byte hash. `isValidSignature` reimplements ONLY the ERC-7739 `TypedDataSign` workflow
 * (app digest) directly — it does NOT delegate to (or narrow the result of) OpenZeppelin's stock
 * `ERC7739Upgradeable.isValidSignature`, which additionally offers a `PersonalSign` workflow that
 * binds ONLY this wallet's own domain and lets the caller-supplied hash pass through unmodified.
 * That workflow is simply never implemented here (see
 * test/StarzipWallet_personalsign.test.ts — including a recorded round-1 remediation attempt that
 * tried to filter OZ's combined result post hoc and was itself bypassable), because this product has
 * no PersonalSign use case and the workflow would otherwise reopen exactly the blind-signing hole
 * ERC-7739 was adopted to close. For the implemented `TypedDataSign` path, the passkey is verified
 * against a digest built from BOTH the requesting app's domain separator and this wallet's own
 * domain, so a "log in" signature harvested by a malicious dApp is structurally unusable against
 * TradeSettlementV1 (or Permit2, or any other domain).
 *
 * REGRESSION EVIDENCE — the two integration tests below ("settles a passkey-signed order …" and
 * "registers a session key …") reverted with `InvalidSignature` before ERC-1271 existed. They are
 * preserved here verbatim in intent, re-expressed in the new wrapped format: they still prove that
 * a factory-deployed passkey wallet trades and delegates with no session key and no EOA.
 *
 * Coverage:
 *   - ERC-7739 wrapped typed-data assertion                    -> 0x1626ba7e
 *   - the SAME assertion presented unwrapped (old format)      -> 0xffffffff  (breaking change pin)
 *   - wrapper signed by the wrong passkey                      -> 0xffffffff
 *   - malformed / truncated signature bytes                    -> 0xffffffff (no revert)
 *   - wrapper minted for ANOTHER app's domain                  -> 0xffffffff (cross-app replay)
 *   - wrapper minted for ANOTHER wallet's domain               -> 0xffffffff (cross-account replay)
 *   - assertion without the UV flag                            -> 0xffffffff (UV parity with 4337)
 *   - ERC-7739 support probe (0x7739… + empty sig)             -> 0x77390001
 * - `PersonalSign` nested path -> 0xffffffff (blocked)
 *   - end-to-end: factory-deployed wallet trades on TradeSettlementV1 with NO session key
 *   - end-to-end: registerSessionKeyWithSig authorized by the wallet's passkey
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseEther,
  parseUnits,
  encodeFunctionData,
  hashTypedData,
  hashStruct,
  keccak256,
  toBytes,
  zeroAddress,
  parseEventLogs,
  hexToBytes,
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
  erc7739TypedDataDigest,
  erc7739PersonalSig,
  encodePasskeyOwner,
  encodeSignatureWrapper,
  WALLET_EIP712_NAME,
  WALLET_EIP712_VERSION,
  type Eip712Domain,
} from "./aa-helpers.js";

// Owner index 0 is the wallet's sole owner in every fixture in this file.
const ownerSig = (priv: Uint8Array) => (d: Hex) =>
  encodeSignatureWrapper(0n, webauthnSignature(d, priv));

// Deterministic P-256 test keys (NOT for production). Scalars < n.
const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const OTHER_PASSKEY_PRIV = hexToBytes(
  "0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464" as Hex,
);
const { x: PK_X, y: PK_Y } = passkeyPubCoords(PASSKEY_PRIV);

const SALT = 4242n;
const ERC1271_MAGIC = "0x1626ba7e";
const ERC1271_INVALID = "0xffffffff";
// ERC-7739 support probe: this exact hash with an empty signature must answer 0x77390001.
const ERC7739_PROBE_HASH =
  "0x7739773977397739773977397739773977397739773977397739773977397739" as Hex;
const ERC7739_PROBE_ANSWER = "0x77390001";

// Hardhat default key for wallet client index 2 (bob), used for the EOA counterparty's EIP-712 sig.
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
// must put in the ERC-7739 `contentsDescr` field.
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
// Byte-identical to TradeSettlementV1.SESSION_KEY_TYPEHASH's typestring.
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

describe("StarzipWallet — ERC-1271 / ERC-7739", function () {
  // --------------------------------------------------------------
  // Wallet-only fixture (unit tests)
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

  // A stand-in "app" that asks the wallet to sign typed data (any dApp / Permit2 / settlement).
  const MAIL_TYPES = {
    Mail: [
      { name: "to", type: "address" },
      { name: "contents", type: "string" },
    ],
  } as const;
  const MAIL_DESCR = "Mail(address to,string contents)";
  const MAIL_MESSAGE = {
    to: "0x00000000000000000000000000000000000000a1" as Address,
    contents: "hello",
  };
  const appDomainFor = (chainId: number, verifyingContract: Address): Eip712Domain => ({
    name: "ExampleApp",
    version: "1",
    chainId,
    verifyingContract,
  });
  const APP_A = "0x000000000000000000000000000000000000aaaa" as Address;
  const APP_B = "0x000000000000000000000000000000000000bbbb" as Address;

  const mailContentsHash = () =>
    hashStruct({ data: MAIL_MESSAGE, primaryType: "Mail", types: MAIL_TYPES });
  const mailDigest = (domain: Eip712Domain) =>
    hashTypedData({ domain, types: MAIL_TYPES, primaryType: "Mail", message: MAIL_MESSAGE });

  describe("isValidSignature (ERC-7739 nested)", function () {
    it("returns the ERC-1271 magic value for a wrapped typed-data assertion", async function () {
      const { account, chainId, walletDomain } = await loadFixture(walletFixture);
      const appDomain = appDomainFor(chainId, APP_A);
      const appSeparator = domainSeparator(appDomain);
      const contentsHash = mailContentsHash();

      // Sanity: the hash an app hands to isValidSignature IS toTypedDataHash(appSep, contentsHash).
      // ERC-7739 relies on this identity, so pin it rather than assume it.
      assert.strictEqual(
        mailDigest(appDomain),
        keccak256(`0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex),
        "app digest decomposition",
      );

      const sig = erc7739TypedDataSig({
        appSeparator,
        contentsHash,
        contentsDescr: MAIL_DESCR,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });
      assert.strictEqual(
        await account.read.isValidSignature([mailDigest(appDomain), sig]),
        ERC1271_MAGIC,
      );
    });

    it("REJECTS a bare assertion over the raw hash (pre-7739 format is no longer honoured)", async function () {
      const { account, chainId } = await loadFixture(walletFixture);
      const digest = mailDigest(appDomainFor(chainId, APP_A));
      // Exactly what the old wallet accepted: challenge == the app digest, no envelope.
      const rawSig = webauthnSignature(digest, PASSKEY_PRIV);
      assert.strictEqual(
        await account.read.isValidSignature([digest, rawSig]),
        ERC1271_INVALID,
        "raw-hash blind signature must not validate",
      );
      // Same for an arbitrary opaque hash — the blind-signing surface is closed, not narrowed.
      const opaque = keccak256(toBytes("erc1271-blind"));
      assert.strictEqual(
        await account.read.isValidSignature([opaque, webauthnSignature(opaque, PASSKEY_PRIV)]),
        ERC1271_INVALID,
        "opaque raw hash",
      );
    });

    it("returns 0xffffffff for a wrapper signed by a different passkey", async function () {
      const { account, chainId, walletDomain } = await loadFixture(walletFixture);
      const appDomain = appDomainFor(chainId, APP_A);
      const sig = erc7739TypedDataSig({
        appSeparator: domainSeparator(appDomain),
        contentsHash: mailContentsHash(),
        contentsDescr: MAIL_DESCR,
        walletDomain,
        sign: ownerSig(OTHER_PASSKEY_PRIV),
      });
      assert.strictEqual(
        await account.read.isValidSignature([mailDigest(appDomain), sig]),
        ERC1271_INVALID,
      );
    });

    it("returns 0xffffffff (no revert) for malformed signature bytes", async function () {
      const { account, chainId, walletDomain } = await loadFixture(walletFixture);
      const appDomain = appDomainFor(chainId, APP_A);
      const digest = mailDigest(appDomain);

      // (a) undecodable garbage
      assert.strictEqual(
        await account.read.isValidSignature([digest, "0xdeadbeef"]),
        ERC1271_INVALID,
        "garbage bytes",
      );
      // (b) empty signature (and NOT the 7739 probe hash, so no 0x77390001)
      assert.strictEqual(
        await account.read.isValidSignature([digest, "0x"]),
        ERC1271_INVALID,
        "empty bytes",
      );
      // (c) well-formed envelope whose inner assertion is truncated
      const good = erc7739TypedDataSig({
        appSeparator: domainSeparator(appDomain),
        contentsHash: mailContentsHash(),
        contentsDescr: MAIL_DESCR,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });
      assert.strictEqual(
        await account.read.isValidSignature([digest, good.slice(0, good.length - 64) as Hex]),
        ERC1271_INVALID,
        "truncated envelope",
      );
      // (d) valid envelope, but the trailing contentsDescr length word is corrupted
      const badLen = (good.slice(0, good.length - 4) + "ffff") as Hex;
      assert.strictEqual(
        await account.read.isValidSignature([digest, badLen]),
        ERC1271_INVALID,
        "corrupted descriptor length",
      );
    });

    it("rejects a wrapper minted for ANOTHER app's domain (no cross-app replay)", async function () {
      const { account, chainId, walletDomain } = await loadFixture(walletFixture);
      const domainA = appDomainFor(chainId, APP_A);
      const domainB = appDomainFor(chainId, APP_B);
      const contentsHash = mailContentsHash();

      const sigForB = erc7739TypedDataSig({
        appSeparator: domainSeparator(domainB),
        contentsHash,
        contentsDescr: MAIL_DESCR,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });

      // Valid where it was minted...
      assert.strictEqual(
        await account.read.isValidSignature([mailDigest(domainB), sigForB]),
        ERC1271_MAGIC,
        "valid at app B",
      );
      // ...and inert everywhere else. This is precisely the blind-signing mitigation: an assertion
      // harvested by app B cannot be replayed as an app-A (e.g. settlement) approval.
      assert.strictEqual(
        await account.read.isValidSignature([mailDigest(domainA), sigForB]),
        ERC1271_INVALID,
        "must not validate at app A",
      );
    });

    it("rejects a wrapper bound to ANOTHER wallet's domain (no cross-account replay)", async function () {
      const { account, chainId } = await loadFixture(walletFixture);
      const appDomain = appDomainFor(chainId, APP_A);
      const sig = erc7739TypedDataSig({
        appSeparator: domainSeparator(appDomain),
        contentsHash: mailContentsHash(),
        contentsDescr: MAIL_DESCR,
        // same passkey, but the envelope names a DIFFERENT account as verifyingContract
        walletDomain: {
          name: WALLET_EIP712_NAME,
          version: WALLET_EIP712_VERSION,
          chainId,
          verifyingContract: "0x000000000000000000000000000000000000cccc" as Address,
        },
        sign: ownerSig(PASSKEY_PRIV),
      });
      assert.strictEqual(
        await account.read.isValidSignature([mailDigest(appDomain), sig]),
        ERC1271_INVALID,
      );
    });

    it("keeps the userOp UV requirement (wrapped assertion without the UV flag is rejected)", async function () {
      const { account, chainId, walletDomain } = await loadFixture(walletFixture);
      const appDomain = appDomainFor(chainId, APP_A);
      const wrap = (flags?: Hex) =>
        erc7739TypedDataSig({
          appSeparator: domainSeparator(appDomain),
          contentsHash: mailContentsHash(),
          contentsDescr: MAIL_DESCR,
          walletDomain,
          sign: (d) => encodeSignatureWrapper(0n, webauthnSignature(d, PASSKEY_PRIV, flags)),
        });
      const digest = mailDigest(appDomain);
      assert.strictEqual(
        await account.read.isValidSignature([digest, wrap("0x01")]), // UP set, UV clear
        ERC1271_INVALID,
      );
      // sanity: same envelope WITH UV is accepted -> the flag is the only difference
      assert.strictEqual(await account.read.isValidSignature([digest, wrap()]), ERC1271_MAGIC);
    });

    it("answers the ERC-7739 support probe (0x7739… + empty signature -> 0x77390001)", async function () {
      const { account } = await loadFixture(walletFixture);
      assert.strictEqual(
        await account.read.isValidSignature([ERC7739_PROBE_HASH, "0x"]),
        ERC7739_PROBE_ANSWER,
      );
    });

    it("rejects the PersonalSign nested path (blocked, no app-domain binding)", async function () {
      // Deviates from this file's "doc comments only" edit scope: this assertion tests production
      // behavior the fix deliberately reverses (PersonalSign used to validate here; it must not
      // anymore), so leaving it asserting the old ERC1271_MAGIC outcome would make this suite red
      // against the intended fix. See test/StarzipWallet_personalsign.test.ts for the full
      // regression/E2E/negative-control coverage; this is kept here only so the file's own
      // "PersonalSign nested path" coverage line (see header) stays accurate.
      const { account, walletDomain } = await loadFixture(walletFixture);
      const hash = keccak256(toBytes("sign-in nonce 12345"));
      const sig = erc7739PersonalSig({
        hash,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });
      assert.strictEqual(await account.read.isValidSignature([hash, sig]), ERC1271_INVALID);
    });

    it("exposes the wallet's own EIP-712 domain via eip712Domain() (ERC-5267)", async function () {
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
  // Integration: passkey wallet trades on TradeSettlementV1 WITHOUT a session key
  // --------------------------------------------------------------
  async function settlementFixture() {
    const base = await walletFixture();
    const { viem, publicClient, entryPoint, account, walletAddr, deployer, beneficiary } = base;
    const [owner, operator, bob, feeRecipient] = await viem.getWalletClients();
    const chainId = await publicClient.getChainId();

    // quote asset (18-dec USDT stand-in) + base asset (a second ERC20)
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

    // operator wiring goes through the 24h queue -> execute timelock
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

    // Fund the AA wallet's quote balance — approve + deposit are executed BY the wallet, each as a
    // passkey-signed userOp through a real EntryPoint (the wallet has no EOA that can act for it).
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
    assert.strictEqual(
      (await settlement.read.getBalance([walletAddr, quoteToken.address])) as bigint,
      walletQuote,
      "AA wallet quote deposit",
    );

    // Fund bob (EOA counterparty) with base tokens
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

  describe("TradeSettlementV1 integration (Path A for AA accounts)", function () {
    it("settles a passkey-signed order from a factory-deployed wallet — no session key involved", async function () {
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
      const sellOrder: Order = {
        account: bob.account.address,
        baseToken: baseToken.address,
        quoteToken: quoteToken.address,
        isBuy: false,
        baseAmount: fillBase,
        quoteAmount: fillQuote,
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };

      // The AA account signs the EIP-712 order with its PASSKEY, wrapped per ERC-7739 — settlement
      // authorizes it through SignatureChecker -> StarzipWallet.isValidSignature.
      const appDomain = domainFor(chainId, settlement.address);
      const buySig = erc7739TypedDataSig({
        appSeparator: domainSeparator(appDomain),
        contentsHash: hashStruct({
          data: buyOrder,
          primaryType: "Order",
          types: ORDER_TYPES,
        }),
        contentsDescr: ORDER_DESCR,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });

      // Counterparty is a plain EOA (ecrecover path) — proving EOA/AA parity in one settlement.
      const sellSig = await signTypedData({
        privateKey: BOB_KEY,
        domain: appDomain,
        types: ORDER_TYPES,
        primaryType: "Order",
        message: sellOrder,
      });

      const bal = (u: Address, t: Address) => settlement.read.getBalance([u, t]) as Promise<bigint>;
      const w0q = await bal(walletAddr, quoteToken.address);
      const w0b = await bal(walletAddr, baseToken.address);
      const b0q = await bal(bob.account.address, quoteToken.address);
      const b0b = await bal(bob.account.address, baseToken.address);

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
            settlementId: keccak256(toBytes("aa-1271-settle")),
          },
        ],
        { account: operator.account },
      );

      assert.strictEqual(await bal(walletAddr, baseToken.address), w0b + fillBase, "wallet base");
      assert.strictEqual(
        await bal(walletAddr, quoteToken.address),
        w0q - fillQuote,
        "wallet quote",
      );
      assert.strictEqual(
        await bal(bob.account.address, baseToken.address),
        b0b - fillBase,
        "bob base",
      );
      assert.strictEqual(
        await bal(bob.account.address, quoteToken.address),
        b0q + fillQuote,
        "bob quote",
      );
      // the wallet never registered a session key
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([walletAddr, bob.account.address])) as bigint,
        0n,
      );
    });

    it("rejects an order signed for a DIFFERENT app domain (harvested login signature)", async function () {
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

      // A malicious dApp made the user sign the SAME order struct under ITS OWN domain.
      const evilDomain = { name: "EvilDapp", version: "1", chainId, verifyingContract: APP_B };
      const buySig = erc7739TypedDataSig({
        appSeparator: domainSeparator(evilDomain),
        contentsHash: hashStruct({ data: buyOrder, primaryType: "Order", types: ORDER_TYPES }),
        contentsDescr: ORDER_DESCR,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });
      const sellSig = await signTypedData({
        privateKey: BOB_KEY,
        domain: domainFor(chainId, settlement.address),
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
              settlementId: keccak256(toBytes("aa-1271-crossdomain")),
            },
          ],
          { account: operator.account },
        ),
        /InvalidSignature/,
      );
    });

    it("registers a session key via registerSessionKeyWithSig authorized by the wallet's passkey", async function () {
      const f = await loadFixture(settlementFixture);
      const { settlement, walletAddr, quoteToken, bob, chainId, expiry, walletDomain } = f;

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

      // Cross-check the helper against viem's own digest computation before relying on it.
      assert.strictEqual(
        keccak256(`0x1901${appSeparator.slice(2)}${contentsHash.slice(2)}` as Hex),
        hashTypedData({
          domain: appDomain,
          types: SESSION_KEY_TYPES,
          primaryType: "SessionKeyAuth",
          message: auth,
        }),
        "SessionKeyAuth digest decomposition",
      );

      const sig = erc7739TypedDataSig({
        appSeparator,
        contentsHash,
        contentsDescr: SESSION_KEY_DESCR,
        walletDomain,
        sign: ownerSig(PASSKEY_PRIV),
      });

      // Relayed by an unrelated account — authority comes purely from the passkey assertion.
      await settlement.write.registerSessionKeyWithSig([auth, sig], { account: bob.account });

      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([walletAddr, bob.account.address])) as bigint,
        expiry,
      );
      assert.strictEqual((await settlement.read.sessionKeyRegNonce([walletAddr])) as bigint, 1n);
      assert.strictEqual(
        (await settlement.read.sessionKeySpendCap([
          walletAddr,
          bob.account.address,
          quoteToken.address,
        ])) as bigint,
        cap,
      );
      // The nested digest is what the passkey actually attested to — record it so the frontend
      // contract (docs) has a fixture to reproduce.
      assert.notStrictEqual(
        erc7739TypedDataDigest({
          appSeparator,
          contentsHash,
          contentsDescr: SESSION_KEY_DESCR,
          walletDomain,
        }),
        hashTypedData({
          domain: appDomain,
          types: SESSION_KEY_TYPES,
          primaryType: "SessionKeyAuth",
          message: auth,
        }),
        "nested digest must differ from the plain app digest",
      );
    });
  });
});
