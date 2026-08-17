/**
 * TradeSettlementV1 — V1.3 signature-based NON-CUSTODIAL settlement.
 *
 * Covers the V1.3 transformation surface:
 *   - settleOrders: happy 2-order settle (exact balances, fees, conservation), dual-sig required,
 *     ERC-1271 order account (SignatureChecker path), session keys (direct + WithSig, revoke,
 *     expire, negative "session key cannot withdraw/register/revoke"), registration-nonce replay,
 *     settlement replay, price-not-crossed / overfill / partial-fill sum, expiry / cancel,
 *     self-trade / side / token / unsupported / excessive-fee, insufficient-balance (settlementId
 *     NOT marked).
 *   - Restored direct self-custodial withdrawals: withdrawUsdt / withdrawToken / batchWithdraw
 *     (CEI, withdrawal-delay honored, works WHILE PAUSED, delisted-token exit).
 *   - Removed paths: legacy settleTrade* / withdrawFor AND batchSettleNetDeltas (with its enable
 *     flag, per-token cap and NetDelta struct) are fully deleted — not present in this ABI, so
 *     they are asserted ABSENT rather than asserted-disabled.
 *   - Timelocked upgrade round-trip + storage-preservation upgrade.
 *   - Retained coverage: operator timelock, emergencyWithdrawFor.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import {
  parseUnits,
  getAddress,
  encodeFunctionData,
  keccak256,
  toBytes,
  zeroAddress,
  parseEventLogs,
  toFunctionSelector,
  type Hex,
} from "viem";
import { privateKeyToAccount, signTypedData } from "viem/accounts";
import { deploySimpleTokenFixture } from "./tokenFactoryHelpers.js";

describe("TradeSettlementV1 — V1.3 signature-based non-custodial", function () {
  const TOTAL_SUPPLY = parseUnits("1000000", 18);
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

  // Hardhat default account private keys (deterministic mnemonic). Index maps to getWalletClients().
  const KEYS: Record<number, Hex> = {
    0: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // owner
    1: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", // operator
    2: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", // alice
    3: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", // bob
  };
  const ALICE_KEY = KEYS[2];
  const BOB_KEY = KEYS[3];
  const WALLET_OWNER_KEY =
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e" as Hex; // acct 6
  const SESSION_KEY_PK =
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356" as Hex; // acct 7

  function settlementId(seed: string): Hex {
    return keccak256(toBytes(`v20-${seed}`));
  }

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

  type SessionKeyAuth = {
    account: `0x${string}`;
    sessionKey: `0x${string}`;
    validUntil: bigint;
    deadline: bigint;
    tokens: `0x${string}`[];
    caps: bigint[];
    orderCaps: bigint[];
    nonce: bigint;
  };

  type Order = {
    account: `0x${string}`;
    baseToken: `0x${string}`;
    quoteToken: `0x${string}`;
    isBuy: boolean;
    baseAmount: bigint;
    quoteAmount: bigint;
    maxFeeRate: bigint;
    nonce: bigint;
    expiry: bigint;
  };

  async function signOrder(
    pk: Hex,
    order: Order,
    chainId: number,
    verifyingContract: `0x${string}`,
  ) {
    return signTypedData({
      privateKey: pk,
      domain: { name: "StarZipTradeSettlement", version: "1", chainId, verifyingContract },
      types: ORDER_TYPES,
      primaryType: "Order",
      message: order,
    });
  }

  async function signSessionKeyAuth(
    pk: Hex,
    auth: SessionKeyAuth,
    chainId: number,
    verifyingContract: `0x${string}`,
  ) {
    return signTypedData({
      privateKey: pk,
      domain: { name: "StarZipTradeSettlement", version: "1", chainId, verifyingContract },
      types: SESSION_KEY_TYPES,
      primaryType: "SessionKeyAuth",
      message: auth,
    });
  }

  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, operator, alice, bob, feeRecipient, charlie] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);

    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);
    const { token: lpToken, tokenFactory } = await deploySimpleTokenFixture({
      viem,
      deployer: owner,
      business: alice,
      neutralRecipient: owner,
      publicClient,
      chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      permitSignerAddress: permitSigner.address,
      platformTreasuryAddress: owner.account.address,
      totalSupply: TOTAL_SUPPLY,
      name: "LaunchpadToken",
      symbol: "LPT",
    });

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

    // immediate setOperator was removed — operators are now wired via the
    // queueOperatorChange -> (24h OPERATOR_CHANGE_DELAY) -> executeOperatorChange timelock.
    // This warp happens BEFORE `expiry` is computed below so existing expiry assertions
    // (relative to `time.latest()` at fixture-build time) stay valid.
    const queueHash = await settlement.write.queueOperatorChange([operator.account.address, true]);
    const queueReceipt = await publicClient.waitForTransactionReceipt({ hash: queueHash });
    const queuedEvents = parseEventLogs({
      abi: settlement.abi,
      logs: queueReceipt.logs,
      eventName: "OperatorChangeQueued",
    });
    const operatorChangeId = (queuedEvents[0] as unknown as { args: { changeId: Hex } }).args
      .changeId;
    await time.increase(24n * 60n * 60n + 1n);
    await settlement.write.executeOperatorChange([operatorChangeId]);

    await settlement.write.setQuoteAsset([usdt.address, true]);
    await settlement.write.setSupportedToken([lpToken.address, true]);

    // Fund alice + bob with USDT deposits
    const depositAmt = parseUnits("10000", 18);
    await usdt.write.mint([alice.account.address, depositAmt]);
    await usdt.write.mint([bob.account.address, depositAmt]);
    await usdt.write.approve([settlement.address, depositAmt], { account: alice.account });
    await usdt.write.approve([settlement.address, depositAmt], { account: bob.account });
    await settlement.write.depositToken([usdt.address, depositAmt], { account: alice.account });
    await settlement.write.depositToken([usdt.address, depositAmt], { account: bob.account });

    // Fund alice + bob with lpToken deposits (alice holds the business allocation)
    const tokenDepositAmt = parseUnits("1000", 18);
    await lpToken.write.transfer([bob.account.address, tokenDepositAmt], {
      account: alice.account,
    });
    await lpToken.write.approve([settlement.address, tokenDepositAmt], { account: alice.account });
    await lpToken.write.approve([settlement.address, tokenDepositAmt], { account: bob.account });
    await settlement.write.depositToken([lpToken.address, tokenDepositAmt], {
      account: alice.account,
    });
    await settlement.write.depositToken([lpToken.address, tokenDepositAmt], {
      account: bob.account,
    });

    const now = await time.latest();
    const expiry = now + 3600n;

    return {
      settlement,
      settlementImpl,
      usdt,
      lpToken,
      tokenFactory,
      owner,
      operator,
      alice,
      bob,
      charlie,
      feeRecipient,
      publicClient,
      chainId,
      expiry,
      viem,
    };
  }

  // Build a matched pair: alice buys `fillToken` for `fillUsdt`, bob sells. Returns signed orders.
  async function buildMatchedPair(
    f: Awaited<ReturnType<typeof deployFixture>>,
    over?: Partial<Order>,
  ) {
    const { alice, bob, lpToken, expiry, chainId, settlement } = f;
    const buyOrder: Order = {
      account: alice.account.address,
      baseToken: lpToken.address,
      quoteToken: f.usdt.address,
      isBuy: true,
      baseAmount: parseUnits("100", 18),
      quoteAmount: parseUnits("1000", 18),
      maxFeeRate: 100n,
      nonce: 1n,
      expiry,
      ...over,
    };
    const sellOrder: Order = {
      account: bob.account.address,
      baseToken: lpToken.address,
      quoteToken: f.usdt.address,
      isBuy: false,
      baseAmount: parseUnits("100", 18),
      quoteAmount: parseUnits("1000", 18),
      maxFeeRate: 100n,
      nonce: 1n,
      expiry,
    };
    const buySig = await signOrder(ALICE_KEY, buyOrder, chainId, settlement.address);
    const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);
    return { buyOrder, buySig, sellOrder, sellSig };
  }

  // =====================================================================
  // settleOrders — happy path + conservation
  // =====================================================================
  describe("settleOrders happy path", function () {
    it("moves exact balances, credits fees, conserves token + USDT", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, operator, alice, bob, feeRecipient } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);

      const fillToken = parseUnits("100", 18);
      const fillUsdt = parseUnits("1000", 18);
      const buyerFee = parseUnits("5", 18);
      const sellerFee = parseUnits("5", 18);

      const bal = (u: `0x${string}`, t: `0x${string}`) =>
        settlement.read.getBalance([u, t]) as Promise<bigint>;

      const a0u = await bal(alice.account.address, usdt.address);
      const a0t = await bal(alice.account.address, lpToken.address);
      const b0u = await bal(bob.account.address, usdt.address);
      const b0t = await bal(bob.account.address, lpToken.address);
      const f0u = await bal(feeRecipient.account.address, usdt.address);
      const feeAccrued0 = (await settlement.read.feeAccrued([usdt.address])) as bigint;

      // conservation snapshot: total token + total usdt across the 3 parties
      const totalTokenBefore = a0t + b0t;
      const totalUsdtBefore = a0u + b0u + f0u;

      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: fillToken,
            fillQuoteAmount: fillUsdt,
            buyerFee: buyerFee,
            sellerFee: sellerFee,
            settlementId: settlementId("happy"),
          },
        ],
        { account: operator.account },
      );

      const a1u = await bal(alice.account.address, usdt.address);
      const a1t = await bal(alice.account.address, lpToken.address);
      const b1u = await bal(bob.account.address, usdt.address);
      const b1t = await bal(bob.account.address, lpToken.address);
      const f1u = await bal(feeRecipient.account.address, usdt.address);

      assert.strictEqual(a1u, a0u - (fillUsdt + buyerFee), "buyer usdt");
      assert.strictEqual(a1t, a0t + fillToken, "buyer token");
      assert.strictEqual(b1u, b0u + (fillUsdt - sellerFee), "seller usdt");
      assert.strictEqual(b1t, b0t - fillToken, "seller token");
      assert.strictEqual(f1u, f0u + buyerFee + sellerFee, "fee recipient usdt");
      assert.strictEqual(
        (await settlement.read.feeAccrued([usdt.address])) as bigint,
        feeAccrued0 + buyerFee + sellerFee,
        "feeAccrued",
      );

      // conservation: totals unchanged
      assert.strictEqual(a1t + b1t, totalTokenBefore, "token conserved");
      assert.strictEqual(a1u + b1u + f1u, totalUsdtBefore, "usdt conserved");

      assert.strictEqual(await settlement.read.processedSettlements([settlementId("happy")]), true);
      assert.strictEqual(
        (await settlement.read.orderFilled([keccak256(toBytes("x"))])) as bigint,
        0n,
      );
    });

    it("partial fills accumulate to the order size and reject overfill", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);

      const half = parseUnits("50", 18);
      const halfUsdt = parseUnits("500", 18);

      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: half,
            fillQuoteAmount: halfUsdt,
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: settlementId("pf1"),
          },
        ],
        { account: operator.account },
      );
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: half,
            fillQuoteAmount: halfUsdt,
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: settlementId("pf2"),
          },
        ],
        { account: operator.account },
      );

      // third fill (price-crossing: 1 token for 10 usdt) would exceed tokenAmount (100) -> OrderOverfill
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("1", 18),
              fillQuoteAmount: parseUnits("10", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("pf3"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "OrderOverfill",
      );
    });
  });

  // =====================================================================
  // Signature authorization
  // =====================================================================
  describe("signature authorization", function () {
    it("requires a valid buy signature", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { buyOrder, sellOrder, sellSig } = await buildMatchedPair(f);
      // sign buyOrder with the WRONG key (bob signs alice's order)
      const badBuySig = await signOrder(BOB_KEY, buyOrder, f.chainId, settlement.address);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: badBuySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("badbuy"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "InvalidSignature",
      );
    });

    it("requires a valid sell signature", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { buyOrder, buySig, sellOrder } = await buildMatchedPair(f);
      const badSellSig = await signOrder(ALICE_KEY, sellOrder, f.chainId, settlement.address);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: badSellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("badsell"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "InvalidSignature",
      );
    });

    it("accepts an ERC-1271 contract-wallet order account (SignatureChecker path)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, operator, bob, viem, chainId, expiry } = f;
      const walletOwner = privateKeyToAccount(WALLET_OWNER_KEY);

      // Deploy ERC-1271 wallet, fund its USDT settlement balance via execute()
      const wallet = await viem.deployContract("MockERC1271Wallet", [walletOwner.address]);
      const fundAmt = parseUnits("2000", 18);
      await usdt.write.mint([wallet.address, fundAmt]);
      await wallet.write.execute([
        usdt.address,
        encodeFunctionData({
          abi: usdt.abi,
          functionName: "approve",
          args: [settlement.address, fundAmt],
        }),
      ]);
      await wallet.write.execute([
        settlement.address,
        encodeFunctionData({
          abi: settlement.abi,
          functionName: "depositToken",
          args: [usdt.address, fundAmt],
        }),
      ]);

      const buyOrder: Order = {
        account: wallet.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      const sellOrder: Order = {
        account: bob.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: false,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      // wallet owner EOA signs; SignatureChecker -> wallet.isValidSignature -> magic value
      const buySig = await signOrder(WALLET_OWNER_KEY, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);

      const walletTokenBefore = (await settlement.read.getBalance([
        wallet.address,
        lpToken.address,
      ])) as bigint;
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: parseUnits("100", 18),
            fillQuoteAmount: parseUnits("1000", 18),
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: settlementId("erc1271"),
          },
        ],
        { account: operator.account },
      );
      assert.strictEqual(
        (await settlement.read.getBalance([wallet.address, lpToken.address])) as bigint,
        walletTokenBefore + parseUnits("100", 18),
      );
    });
  });

  // =====================================================================
  // Session keys
  // =====================================================================
  describe("session keys", function () {
    it("registerSessionKey (direct): session key can sign an order that settles", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, operator, alice, bob, chainId, expiry } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      await settlement.write.registerSessionKey([sessionKey.address, expiry, [], [], []], {
        account: alice.account,
      });
      // caps are fail-closed, so a registered key still needs an explicit per-asset budget.
      // Alice is the BUYER here, so the debited asset is the quote asset (USDT).
      await settlement.write.setSessionKeyCap(
        [sessionKey.address, f.usdt.address, parseUnits("5000", 18), 2n ** 256n - 1n],
        { account: alice.account },
      );

      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 7n,
        expiry,
      };
      const sellOrder: Order = {
        ...buyOrder,
        account: bob.account.address,
        isBuy: false,
        nonce: 7n,
      };
      const buySig = await signOrder(SESSION_KEY_PK, buyOrder, chainId, settlement.address); // session-signed
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);

      const aliceTokenBefore = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: parseUnits("100", 18),
            fillQuoteAmount: parseUnits("1000", 18),
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: settlementId("sk-direct"),
          },
        ],
        { account: operator.account },
      );
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        aliceTokenBefore + parseUnits("100", 18),
      );
    });

    it("registerSessionKeyWithSig (relayed): registers via signature, replay reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, charlie, chainId, expiry } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      const auth: SessionKeyAuth = {
        account: alice.account.address,
        sessionKey: sessionKey.address,
        validUntil: expiry,
        deadline: expiry,
        tokens: [f.usdt.address],
        caps: [parseUnits("5000", 18)],
        orderCaps: [2n ** 256n - 1n],
        nonce: 0n,
      };
      const sig = await signSessionKeyAuth(ALICE_KEY, auth, chainId, settlement.address);

      // relayed by charlie (not alice)
      await settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account });
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        expiry,
      );
      assert.strictEqual(
        (await settlement.read.sessionKeyRegNonce([alice.account.address])) as bigint,
        1n,
      );

      // replay same payload (nonce now 1) -> InvalidRegistrationNonce
      await assertions.revertWithCustomError(
        settlement.write.registerSessionKeyWithSig([auth, sig], { account: charlie.account }),
        settlement,
        "InvalidRegistrationNonce",
      );
    });

    it("revoked session key is rejected", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, operator, alice, bob, chainId, expiry } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      await settlement.write.registerSessionKey([sessionKey.address, expiry, [], [], []], {
        account: alice.account,
      });
      await settlement.write.revokeSessionKey([sessionKey.address], { account: alice.account });

      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 9n,
        expiry,
      };
      const sellOrder: Order = { ...buyOrder, account: bob.account.address, isBuy: false };
      const buySig = await signOrder(SESSION_KEY_PK, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);

      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("sk-revoked"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "InvalidSignature",
      );
    });

    it("expired session key is rejected", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, operator, alice, bob, chainId } = f;
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);

      const now = await time.latest();
      const shortValidUntil = now + 100n;
      await settlement.write.registerSessionKey([sessionKey.address, shortValidUntil, [], [], []], {
        account: alice.account,
      });
      await time.increase(200n); // past validUntil

      const laterExpiry = (await time.latest()) + 3600n;
      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 11n,
        expiry: laterExpiry,
      };
      const sellOrder: Order = { ...buyOrder, account: bob.account.address, isBuy: false };
      const buySig = await signOrder(SESSION_KEY_PK, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);

      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("sk-expired"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "InvalidSignature",
      );
    });

    it("session key holder cannot withdraw/register/revoke on behalf of the account", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, alice } = f;
      const { viem } = f;
      const [, , , , , , sessionSigner] = await viem.getWalletClients(); // acct 6 unused; get a wallet client for acct 7
      // Use a dedicated wallet client whose key is the session key (acct 7).
      const clients = await viem.getWalletClients();
      const skClient = clients[7];
      const sessionKey = privateKeyToAccount(SESSION_KEY_PK);
      assert.strictEqual(getAddress(skClient.account.address), getAddress(sessionKey.address));

      // alice authorizes the session key
      const now = await time.latest();
      await settlement.write.registerSessionKey([sessionKey.address, now + 3600n, [], [], []], {
        account: alice.account,
      });

      // (a) session key cannot withdraw alice's funds — withdraw is msg.sender-scoped.
      // skClient has no balance -> InsufficientBalance (proves no cross-account withdraw power).
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([usdt.address, parseUnits("1", 18)], {
          account: skClient.account,
        }),
        settlement,
        "InsufficientBalance",
      );

      // (b) session key "registering" only affects its OWN mapping, not alice's.
      await settlement.write.registerSessionKey([alice.account.address, now + 3600n, [], [], []], {
        account: skClient.account,
      });
      // alice's authorization of skClient is unchanged; skClient did NOT gain the ability to
      // authorize keys for alice.
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          skClient.account.address,
          alice.account.address,
        ])) as bigint,
        now + 3600n,
      );

      // (c) revoke by session key only touches its own keys, not alice's session keys.
      await settlement.write.revokeSessionKey([sessionKey.address], { account: skClient.account });
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          sessionKey.address,
        ])) as bigint,
        now + 3600n,
        "alice's authorization of the session key must be untouched by the session key's own revoke",
      );
      void sessionSigner;
    });
  });

  // =====================================================================
  // settleOrders revert matrix
  // =====================================================================
  describe("settleOrders revert matrix", function () {
    it("settlement replay (duplicate settlementId) reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);
      const id = settlementId("dup");
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: parseUnits("50", 18),
            fillQuoteAmount: parseUnits("500", 18),
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: id,
          },
        ],
        { account: operator.account },
      );
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("10", 18),
              fillQuoteAmount: parseUnits("100", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: id,
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "SettlementAlreadyProcessed",
      );
    });

    it("price not crossed reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      // buyer willing to pay 1000 for 100 (price 10); ask fill of 100 token for 2000 usdt (price 20) -> too expensive for buyer
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("2000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("nocross"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "PriceNotCrossed",
      );
    });

    it("expired order reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, chainId } = f;
      const now = await time.latest();
      const { buyOrder, sellOrder } = await buildMatchedPair(f, { expiry: now + 100n });
      // re-sign buy with the short expiry; sell keeps default expiry
      const buySig = await signOrder(ALICE_KEY, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);
      await time.increase(200n);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("expired"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "OrderExpired",
      );
    });

    it("cancelled order reverts; cancelOrder is signer-gated", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, bob } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);

      // bob cannot cancel alice's order
      await assertions.revert(settlement.write.cancelOrder([buyOrder], { account: bob.account }));
      // alice cancels her own order
      await settlement.write.cancelOrder([buyOrder], { account: alice.account });

      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("cancelled"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "OrderIsCancelled",
      );
    });

    it("side mismatch reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, chainId } = f;
      // both isBuy=false
      const { sellOrder, sellSig } = await buildMatchedPair(f);
      const badBuy: Order = { ...sellOrder, account: f.alice.account.address, isBuy: false };
      const badBuySig = await signOrder(ALICE_KEY, badBuy, chainId, settlement.address);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: badBuy,
              buySig: badBuySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("side"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "SideMismatch",
      );
    });

    it("token mismatch reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, usdt, chainId } = f;
      const { buyOrder, sellOrder, sellSig } = await buildMatchedPair(f);
      const mismatchedBuy: Order = { ...buyOrder, baseToken: usdt.address };
      const buySig = await signOrder(ALICE_KEY, mismatchedBuy, chainId, settlement.address);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: mismatchedBuy,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("tokmismatch"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "TokenMismatch",
      );
    });

    it("unsupported token reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, owner, lpToken } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);
      await settlement.write.setSupportedToken([lpToken.address, false], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("unsupported"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "UnsupportedToken",
      );
    });

    it("self-trade reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, lpToken, chainId, expiry } = f;
      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      const sellOrder: Order = { ...buyOrder, isBuy: false, nonce: 2n };
      const buySig = await signOrder(ALICE_KEY, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(ALICE_KEY, sellOrder, chainId, settlement.address);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("self"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "SelfTradingNotAllowed",
      );
    });

    it("excessive fee reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);
      // maxFee = 1000 * min(100,100)/10000 = 10; charge 11 -> ExcessiveFee
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: parseUnits("11", 18),
              sellerFee: 0n,
              settlementId: settlementId("fee"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "ExcessiveFee",
      );
    });

    it("insufficient balance reverts InsufficientBalance (a named error, not panic) and settlementId is NOT marked", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, chainId, expiry, alice, bob, lpToken } = f;
      // seller (bob) only has 1000 token; ask a fill of 5000 token. this must name the
      // condition (InsufficientBalance) rather than fall through to the compiler's panic 0x11.
      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: f.usdt.address,
        isBuy: true,
        baseAmount: parseUnits("5000", 18),
        quoteAmount: parseUnits("50000", 18),
        maxFeeRate: 100n,
        nonce: 3n,
        expiry,
      };
      const sellOrder: Order = {
        ...buyOrder,
        account: bob.account.address,
        isBuy: false,
        nonce: 3n,
      };
      const buySig = await signOrder(ALICE_KEY, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);
      const id = settlementId("insufficient");
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("5000", 18),
              fillQuoteAmount: parseUnits("50000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: id,
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "InsufficientBalance",
      );
      assert.strictEqual(
        await settlement.read.processedSettlements([id]),
        false,
        "settlementId must NOT be marked when the settlement reverts",
      );
    });

    // has TWO debit sites (seller's base, buyer's quote) and they are separate guards. The
    // test above trips the seller leg — which short-circuits before the buyer leg is ever
    // evaluated — so a missing check on the BUYER side would sail through it unnoticed. This one
    // gives the seller ample base so the only possible shortfall is the buyer's quote balance.
    it("a BUYER-side quote shortfall also reverts InsufficientBalance (second debit site)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, chainId, expiry, alice, bob, lpToken, usdt } = f;

      // alice holds 10_000 USDT; ask her to pay 20_000 for 500 base that bob (1_000) can deliver.
      const fillBase = parseUnits("500", 18);
      const fillQuote = parseUnits("20000", 18);
      const buyOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: true,
        baseAmount: fillBase,
        quoteAmount: fillQuote,
        maxFeeRate: 100n,
        nonce: 41n,
        expiry,
      };
      const sellOrder: Order = { ...buyOrder, account: bob.account.address, isBuy: false };
      const buySig = await signOrder(ALICE_KEY, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);

      const sellerBase = (await settlement.read.getBalance([
        bob.account.address,
        lpToken.address,
      ])) as bigint;
      assert.ok(sellerBase >= fillBase, "precondition: the SELLER must be able to deliver");
      const buyerQuote = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      assert.ok(buyerQuote < fillQuote, "precondition: only the BUYER is short");

      const id = settlementId("insufficient-buyer");
      await assertions.revertWithCustomError(
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
              settlementId: id,
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "InsufficientBalance",
      );
      assert.strictEqual(await settlement.read.processedSettlements([id]), false);
      // And nothing moved — the seller's base was debited before the buyer check, so a missing
      // revert-on-shortfall would have left the seller short with no counter-credit.
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, lpToken.address])) as bigint,
        sellerBase,
      );
    });

    it("non-operator caller cannot settle", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, charlie } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);
      await assertions.revert(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: parseUnits("100", 18),
              fillQuoteAmount: parseUnits("1000", 18),
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: settlementId("nonop"),
            },
          ],
          { account: charlie.account },
        ),
      );
    });
  });

  // =====================================================================
  // Restored direct self-custodial withdrawals
  // =====================================================================
  describe("direct self-custodial withdrawals", function () {
    it("withdrawUsdt debits balance and transfers to msg.sender (CEI)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, alice } = f;
      const amount = parseUnits("100", 18);
      const before = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      const erc20Before = (await usdt.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.withdrawToken([usdt.address, amount], { account: alice.account });
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        before - amount,
      );
      assert.strictEqual(
        (await usdt.read.balanceOf([alice.account.address])) as bigint,
        erc20Before + amount,
      );
    });

    it("withdrawToken works and withdrawing more than balance reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, alice } = f;
      const bal = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;
      await settlement.write.withdrawToken([lpToken.address, bal], { account: alice.account });
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        0n,
      );
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([lpToken.address, 1n], { account: alice.account }),
        settlement,
        "InsufficientBalance",
      );
    });

    it("delisted-token exit still works (withdrawToken not gated on supportedTokens)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, alice, owner } = f;
      await settlement.write.setSupportedToken([lpToken.address, false], {
        account: owner.account,
      });
      const bal = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;
      assert.ok(bal > 0n);
      const erc20Before = (await lpToken.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.withdrawToken([lpToken.address, bal], { account: alice.account });
      assert.strictEqual(
        (await lpToken.read.balanceOf([alice.account.address])) as bigint,
        erc20Before + bal,
      );
    });

    it("withdrawals work WHILE PAUSED (pause must not re-custody)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, alice, owner } = f;
      await settlement.write.pause({ account: owner.account });
      const amount = parseUnits("50", 18);
      const erc20Before = (await usdt.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.withdrawToken([usdt.address, amount], { account: alice.account });
      assert.strictEqual(
        (await usdt.read.balanceOf([alice.account.address])) as bigint,
        erc20Before + amount,
      );
    });

    it("batchWithdraw drains full balances of listed tokens", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, alice } = f;
      const uBal = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      const tBal = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;
      const uErc = (await usdt.read.balanceOf([alice.account.address])) as bigint;
      const tErc = (await lpToken.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.batchWithdraw([[usdt.address, lpToken.address]], {
        account: alice.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await usdt.read.balanceOf([alice.account.address])) as bigint,
        uErc + uBal,
      );
      assert.strictEqual(
        (await lpToken.read.balanceOf([alice.account.address])) as bigint,
        tErc + tBal,
      );
    });

    it("withdrawal delay is honored", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, alice, owner } = f;
      await settlement.write.setWithdrawalDelay([1000n], { account: owner.account });
      // fresh deposit resets lastDepositTime
      const amount = parseUnits("100", 18);
      await usdt.write.mint([alice.account.address, amount]);
      await usdt.write.approve([settlement.address, amount], { account: alice.account });
      await settlement.write.depositToken([usdt.address, amount], { account: alice.account });
      // immediate withdraw -> too early
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([usdt.address, amount], { account: alice.account }),
        settlement,
        "WithdrawalTooEarly",
      );
      await time.increase(1001n);
      await settlement.write.withdrawToken([usdt.address, amount], { account: alice.account });
    });

    // lastDepositTime is
    // now keyed per (user, token). Before this fix a single lastDepositTime[user] meant ANY
    // deposit (of any token) relocked withdrawals of EVERY token the user held. This proves the
    // fix: a fresh USDT deposit must NOT relock an already-unlocked BASE (lpToken) withdrawal.
    it("a fresh USDT deposit does not relock an already-unlocked BASE token withdrawal", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, alice, charlie, owner } = f;
      await settlement.write.setWithdrawalDelay([3600n], { account: owner.account });

      // charlie deposits lpToken (BASE) now, then time moves well past the delay.
      const baseAmt = parseUnits("10", 18);
      await lpToken.write.transfer([charlie.account.address, baseAmt], {
        account: alice.account,
      });
      await lpToken.write.approve([settlement.address, baseAmt], { account: charlie.account });
      await settlement.write.depositToken([lpToken.address, baseAmt], {
        account: charlie.account,
      });
      await time.increase(3601n);

      // charlie deposits USDT (quote) right before withdrawing — this is the fresh clock.
      const quoteAmt = parseUnits("10", 18);
      await usdt.write.mint([charlie.account.address, quoteAmt]);
      await usdt.write.approve([settlement.address, quoteAmt], { account: charlie.account });
      await settlement.write.depositToken([usdt.address, quoteAmt], { account: charlie.account });

      // BASE (lpToken) withdrawal succeeds immediately — its own clock is long past the delay
      // and is untouched by the USDT deposit.
      await settlement.write.withdrawToken([lpToken.address, baseAmt], {
        account: charlie.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([charlie.account.address, lpToken.address])) as bigint,
        0n,
      );

      // USDT withdrawal, by contrast, is too early — its own clock just started.
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([usdt.address, quoteAmt], { account: charlie.account }),
        settlement,
        "WithdrawalTooEarly",
      );
    });

    it("batchWithdraw reverts the WHOLE batch with WithdrawalTooEarlyForToken (no silent skip)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, alice, charlie, owner } = f;
      await settlement.write.setWithdrawalDelay([3600n], { account: owner.account });

      // charlie's lpToken deposit is old (past delay); usdt deposit is fresh (locked).
      const baseAmt = parseUnits("10", 18);
      await lpToken.write.transfer([charlie.account.address, baseAmt], {
        account: alice.account,
      });
      await lpToken.write.approve([settlement.address, baseAmt], { account: charlie.account });
      await settlement.write.depositToken([lpToken.address, baseAmt], {
        account: charlie.account,
      });
      await time.increase(3601n);

      const quoteAmt = parseUnits("10", 18);
      await usdt.write.mint([charlie.account.address, quoteAmt]);
      await usdt.write.approve([settlement.address, quoteAmt], { account: charlie.account });
      await settlement.write.depositToken([usdt.address, quoteAmt], { account: charlie.account });

      // batchWithdraw must revert entirely (not silently skip the locked token) and must not
      // move the unlocked lpToken leg either.
      await assertions.revertWithCustomError(
        settlement.write.batchWithdraw([[lpToken.address, usdt.address]], {
          account: charlie.account,
        }),
        settlement,
        "WithdrawalTooEarlyForToken",
      );
      assert.strictEqual(
        (await settlement.read.getBalance([charlie.account.address, lpToken.address])) as bigint,
        baseAmt,
      );
      assert.strictEqual(
        (await settlement.read.getBalance([charlie.account.address, usdt.address])) as bigint,
        quoteAmt,
      );
    });
  });

  // =====================================================================
  // blacklist-exempt platform legs — settlement withdraw bypasses the
  // business blacklist (from == registered TradeSettlement), but an ordinary
  // blacklisted user's deposit (from == that user, an non-platform leg) is
  // still blocked.
  // =====================================================================
  describe("blacklist-exempt platform legs (settlement)", function () {
    it("blacklisted user's withdrawToken succeeds (platform from-bypass); their depositToken still reverts", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, tokenFactory, owner, alice, bob } = f;

      // Wire TradeSettlement into the token's factory registry (bootstrap — tradeSettlement
      // starts at address(0) in this fixture). Required for _isPlatform(settlement) == true.
      await tokenFactory.write.setTradeSettlement([settlement.address], { account: owner.account });

      // Give bob some lpToken OUTSIDE settlement before blacklisting (alice is the token
      // owner/business here), then blacklist bob.
      const freshAmount = parseUnits("50", 18);
      await lpToken.write.transfer([bob.account.address, freshAmount], { account: alice.account });
      await lpToken.write.addToBlacklist([bob.account.address], { account: alice.account });

      // bob already holds a settlement balance (deposited in the fixture, pre-blacklist).
      // withdrawToken: from == settlement (registered platform), to == bob (blacklisted) —
      // bypasses the blacklist (platform-originated leg).
      const withdrawAmount = parseUnits("10", 18);
      const before = (await lpToken.read.balanceOf([bob.account.address])) as bigint;
      await settlement.write.withdrawToken([lpToken.address, withdrawAmount], {
        account: bob.account,
      });
      const after = (await lpToken.read.balanceOf([bob.account.address])) as bigint;
      assert.strictEqual(after - before, withdrawAmount);

      // depositToken: from == bob (blacklisted, ordinary user, NOT platform) — still blocked.
      await lpToken.write.approve([settlement.address, freshAmount], { account: bob.account });
      await assertions.revertWithCustomError(
        settlement.write.depositToken([lpToken.address, freshAmount], { account: bob.account }),
        lpToken,
        "AccountBlacklisted",
      );
    });
  });

  // =====================================================================
  // Removed paths — asserted ABSENT, not asserted-disabled
  //   BLOCKER-1/BLOCKER-2 previously tested that batchSettleNetDeltas reverted while its
  //   default-off flag was set. That is no longer the right assertion: the path is deleted
  //  , and "reverts today" is exactly what a flag flip undoes. What must hold forever is
  //   that no such entrypoint EXISTS on the deployed ABI.
  // =====================================================================
  describe("removed paths", function () {
    it("batchSettleNetDeltas + its enable flag + its cap are absent from the ABI", async function () {
      const { settlement } = await loadFixture(deployFixture);
      const abi = settlement.abi as { type: string; name?: string }[];
      for (const name of [
        "batchSettleNetDeltas",
        "netDeltaSettlementEnabled",
        "netDeltaEnableReadyAt",
        "requestEnableNetDelta",
        "setNetDeltaSettlementEnabled",
        "batchAmountCap",
        "setBatchAmountCap",
        "MAX_NET_DELTAS",
      ]) {
        assert.ok(
          !abi.some((entry) => entry.type === "function" && entry.name === name),
          `${name} must not exist on the ABI — the unsigned operator debit path is deleted`,
        );
      }
    });

    it("calling batchSettleNetDeltas by raw selector hits no function (empty revert)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator } = f;
      const { viem } = await getConnection();
      const publicClient = await viem.getPublicClient();
      // keccak256("batchSettleNetDeltas(bytes32,(address,address,int256)[])")[:4] under the OLD
      // ABI. A raw call to a selector with no matching function falls through to the (absent)
      // fallback and reverts — proving the dispatcher has no branch for it, which an ABI-shape
      // assertion alone cannot show.
      const selector = toFunctionSelector(
        "function batchSettleNetDeltas(bytes32,(address,address,int256)[])",
      );
      await assert.rejects(
        publicClient.call({
          account: operator.account.address,
          to: settlement.address,
          data: selector,
        }),
      );
    });
  });

  // =====================================================================
  // Timelocked upgrade
  // =====================================================================
  describe("timelocked upgrade", function () {
    const DELAY = 48n * 60n * 60n;

    async function deployNewImpl(f: Awaited<ReturnType<typeof deployFixture>>) {
      return f.viem.deployContract("TradeSettlementV1", []);
    }

    it("request -> early upgrade reverts -> advance 48h -> succeeds", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner } = f;
      const newImpl = await deployNewImpl(f);

      await settlement.write.requestUpgrade([newImpl.address], { account: owner.account });
      assert.strictEqual(
        getAddress((await settlement.read.pendingImplementation()) as `0x${string}`),
        getAddress(newImpl.address),
      );

      // early -> UpgradeNotReady
      await assertions.revertWithCustomError(
        settlement.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account }),
        settlement,
        "UpgradeNotReady",
      );

      await time.increase(DELAY + 1n);
      await settlement.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account });
      // pending cleared (single-use)
      assert.strictEqual(
        getAddress((await settlement.read.pendingImplementation()) as `0x${string}`),
        getAddress(zeroAddress),
      );
      // Pre-existing stale expectation unrelated to this remediation pass — version() is a
      // hardcoded constant (1) in the contract; there is no version-2+ implementation.
      assert.strictEqual((await settlement.read.version()) as bigint, 1n);
    });

    it("mismatch reverts ImplementationMismatch", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner } = f;
      const implA = await deployNewImpl(f);
      const implB = await deployNewImpl(f);
      await settlement.write.requestUpgrade([implA.address], { account: owner.account });
      await time.increase(DELAY + 1n);
      await assertions.revertWithCustomError(
        settlement.write.upgradeToAndCall([implB.address, "0x"], { account: owner.account }),
        settlement,
        "ImplementationMismatch",
      );
    });

    it("cancelUpgrade clears the pending request", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner } = f;
      const impl = await deployNewImpl(f);
      await settlement.write.requestUpgrade([impl.address], { account: owner.account });
      await settlement.write.cancelUpgrade({ account: owner.account });
      assert.strictEqual(
        getAddress((await settlement.read.pendingImplementation()) as `0x${string}`),
        getAddress(zeroAddress),
      );
      await time.increase(DELAY + 1n);
      await assertions.revertWithCustomError(
        settlement.write.upgradeToAndCall([impl.address, "0x"], { account: owner.account }),
        settlement,
        "NoPendingUpgrade",
      );
    });

    it("upgrade without a request reverts NoPendingUpgrade", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner } = f;
      const impl = await deployNewImpl(f);
      await assertions.revertWithCustomError(
        settlement.write.upgradeToAndCall([impl.address, "0x"], { account: owner.account }),
        settlement,
        "NoPendingUpgrade",
      );
    });

    it("cancelUpgrade without a pending request reverts NoPendingUpgrade", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner } = f;
      await assertions.revertWithCustomError(
        settlement.write.cancelUpgrade({ account: owner.account }),
        settlement,
        "NoPendingUpgrade",
      );
    });

    it("preserves storage across the upgrade (balances/operators/supportedTokens/processedSettlements) + new mappings empty", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, operator, owner, alice, bob } = f;

      // seed processedSettlements + orderFilled via a real settleOrders
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);
      const sid = settlementId("preserve");
      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: parseUnits("100", 18),
            fillQuoteAmount: parseUnits("1000", 18),
            buyerFee: parseUnits("5", 18),
            sellerFee: parseUnits("5", 18),
            settlementId: sid,
          },
        ],
        { account: operator.account },
      );

      const aliceUsdt = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      const bobToken = (await settlement.read.getBalance([
        bob.account.address,
        lpToken.address,
      ])) as bigint;

      // upgrade
      const newImpl = await f.viem.deployContract("TradeSettlementV1", []);
      await settlement.write.requestUpgrade([newImpl.address], { account: owner.account });
      await time.increase(DELAY + 1n);
      await settlement.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account });

      // preserved
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        aliceUsdt,
      );
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, lpToken.address])) as bigint,
        bobToken,
      );
      assert.strictEqual(await settlement.read.operators([operator.account.address]), true);
      assert.strictEqual(await settlement.read.supportedTokens([lpToken.address]), true);
      // Quote registry survives too (listed + cached decimals + derived limits).
      const q = (await settlement.read.quoteAssets([usdt.address])) as [
        boolean,
        number,
        bigint,
        bigint,
      ];
      assert.deepStrictEqual(
        [q[0], q[1]],
        [true, 18],
        "quoteAssets entry must survive the upgrade",
      );
      assert.strictEqual(await settlement.read.processedSettlements([sid]), true);

      // new mappings read empty for unrelated keys
      assert.strictEqual(
        (await settlement.read.sessionKeyValidUntil([
          alice.account.address,
          bob.account.address,
        ])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await settlement.read.sessionKeyRegNonce([alice.account.address])) as bigint,
        0n,
      );
    });
  });

  // =====================================================================
  // Retained coverage: operator timelock + emergency withdraw
  // =====================================================================
  describe("retained admin coverage", function () {
    it("emergencyWithdrawFor (owner backstop) force-exits to the user", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, owner, alice } = f;
      const bal = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      const erc20Before = (await usdt.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.emergencyWithdrawFor([alice.account.address, usdt.address], {
        account: owner.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        0n,
      );
      assert.strictEqual(
        (await usdt.read.balanceOf([alice.account.address])) as bigint,
        erc20Before + bal,
      );
    });

    it("operator timelock queue/execute produces a working operator", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner, charlie, publicClient } = f;
      const queueHash = await settlement.write.queueOperatorChange(
        [charlie.account.address, true],
        {
          account: owner.account,
        },
      );
      const receipt = await publicClient.waitForTransactionReceipt({ hash: queueHash });
      const events = await publicClient.getContractEvents({
        address: settlement.address,
        abi: settlement.abi,
        eventName: "OperatorChangeQueued",
        fromBlock: receipt.blockNumber,
        toBlock: receipt.blockNumber,
      });
      const changeId = (events[0] as unknown as { args: { changeId: Hex } }).args.changeId;
      await time.increase(24n * 60n * 60n + 1n);
      await settlement.write.executeOperatorChange([changeId], { account: owner.account });
      assert.strictEqual(await settlement.read.operators([charlie.account.address]), true);
    });

    it("executeOperatorChange before the 24h OPERATOR_CHANGE_DELAY reverts OperatorChangeTooEarly", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner, charlie, publicClient } = f;
      const queueHash = await settlement.write.queueOperatorChange(
        [charlie.account.address, true],
        { account: owner.account },
      );
      const receipt = await publicClient.waitForTransactionReceipt({ hash: queueHash });
      const events = await publicClient.getContractEvents({
        address: settlement.address,
        abi: settlement.abi,
        eventName: "OperatorChangeQueued",
        fromBlock: receipt.blockNumber,
        toBlock: receipt.blockNumber,
      });
      const changeId = (events[0] as unknown as { args: { changeId: Hex } }).args.changeId;

      // No time advance — still inside the 24h delay.
      await assertions.revertWithCustomError(
        settlement.write.executeOperatorChange([changeId], { account: owner.account }),
        settlement,
        "OperatorChangeTooEarly",
      );
      assert.strictEqual(await settlement.read.operators([charlie.account.address]), false);
    });
  });
});
