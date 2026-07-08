/**
 * TradeSettlementV1 — signature-based NON-CUSTODIAL settlement.
 *
 * Covers the signature-based transformation surface:
 *   - settleOrders: happy 2-order settle (exact balances, fees, conservation), dual-sig required,
 *     ERC-1271 order account (SignatureChecker path), session keys (direct + WithSig, revoke,
 *     expire, negative "session key cannot withdraw/register/revoke"), registration-nonce replay,
 *     settlement replay, price-not-crossed / overfill / partial-fill sum, expiry / cancel,
 *     self-trade / side / token / unsupported / excessive-fee, insufficient-balance (settlementId
 *     NOT marked).
 *   - Restored direct self-custodial withdrawals: withdrawUsdt / withdrawToken / batchWithdraw
 *     (CEI, withdrawal-delay honored, works WHILE PAUSED, delisted-token exit).
 *   - Disabled paths: batchSettleNetDeltas reverts by default, legacy settleTrade* revert,
 *     withdrawFor reverts. (Plus batchSettleNetDeltas works once owner enables it.)
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
  type Hex,
} from "viem";
import { privateKeyToAccount, signTypedData } from "viem/accounts";
import { deploySimpleTokenFixture } from "./tokenFactoryHelpers.js";

describe("TradeSettlementV1 — signature-based non-custodial", function () {
  const TOTAL_SUPPLY = parseUnits("1000000", 18);
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
  const BIG_CAP = parseUnits("1000000000", 18);

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
      { name: "token", type: "address" },
      { name: "isBuy", type: "bool" },
      { name: "tokenAmount", type: "uint256" },
      { name: "usdtAmount", type: "uint256" },
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
      { name: "nonce", type: "uint256" },
    ],
  } as const;

  type Order = {
    account: `0x${string}`;
    token: `0x${string}`;
    isBuy: boolean;
    tokenAmount: bigint;
    usdtAmount: bigint;
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
    auth: { account: `0x${string}`; sessionKey: `0x${string}`; validUntil: bigint; nonce: bigint },
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
      args: [owner.account.address, usdt.address, feeRecipient.account.address],
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

    await settlement.write.setSupportedToken([usdt.address, true]);
    await settlement.write.setSupportedToken([lpToken.address, true]);
    await settlement.write.setBatchAmountCap([usdt.address, BIG_CAP]);
    await settlement.write.setBatchAmountCap([lpToken.address, BIG_CAP]);

    // Fund alice + bob with USDT deposits
    const depositAmt = parseUnits("10000", 18);
    await usdt.write.mint([alice.account.address, depositAmt]);
    await usdt.write.mint([bob.account.address, depositAmt]);
    await usdt.write.approve([settlement.address, depositAmt], { account: alice.account });
    await usdt.write.approve([settlement.address, depositAmt], { account: bob.account });
    await settlement.write.depositUsdt([depositAmt], { account: alice.account });
    await settlement.write.depositUsdt([depositAmt], { account: bob.account });

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
      token: lpToken.address,
      isBuy: true,
      tokenAmount: parseUnits("100", 18),
      usdtAmount: parseUnits("1000", 18),
      maxFeeRate: 100n,
      nonce: 1n,
      expiry,
      ...over,
    };
    const sellOrder: Order = {
      account: bob.account.address,
      token: lpToken.address,
      isBuy: false,
      tokenAmount: parseUnits("100", 18),
      usdtAmount: parseUnits("1000", 18),
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
          buyOrder,
          buySig,
          sellOrder,
          sellSig,
          fillToken,
          fillUsdt,
          buyerFee,
          sellerFee,
          settlementId("happy"),
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
        [buyOrder, buySig, sellOrder, sellSig, half, halfUsdt, 0n, 0n, settlementId("pf1")],
        { account: operator.account },
      );
      await settlement.write.settleOrders(
        [buyOrder, buySig, sellOrder, sellSig, half, halfUsdt, 0n, 0n, settlementId("pf2")],
        { account: operator.account },
      );

      // third fill (price-crossing: 1 token for 10 usdt) would exceed tokenAmount (100) -> OrderOverfill
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("1", 18),
            parseUnits("10", 18),
            0n,
            0n,
            settlementId("pf3"),
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
            buyOrder,
            badBuySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("badbuy"),
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
            buyOrder,
            buySig,
            sellOrder,
            badSellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("badsell"),
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
        encodeFunctionData({ abi: settlement.abi, functionName: "depositUsdt", args: [fundAmt] }),
      ]);

      const buyOrder: Order = {
        account: wallet.address,
        token: lpToken.address,
        isBuy: true,
        tokenAmount: parseUnits("100", 18),
        usdtAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 1n,
        expiry,
      };
      const sellOrder: Order = {
        account: bob.account.address,
        token: lpToken.address,
        isBuy: false,
        tokenAmount: parseUnits("100", 18),
        usdtAmount: parseUnits("1000", 18),
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
          buyOrder,
          buySig,
          sellOrder,
          sellSig,
          parseUnits("100", 18),
          parseUnits("1000", 18),
          0n,
          0n,
          settlementId("erc1271"),
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

      await settlement.write.registerSessionKey([sessionKey.address, expiry], {
        account: alice.account,
      });

      const buyOrder: Order = {
        account: alice.account.address,
        token: lpToken.address,
        isBuy: true,
        tokenAmount: parseUnits("100", 18),
        usdtAmount: parseUnits("1000", 18),
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
          buyOrder,
          buySig,
          sellOrder,
          sellSig,
          parseUnits("100", 18),
          parseUnits("1000", 18),
          0n,
          0n,
          settlementId("sk-direct"),
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

      const auth = {
        account: alice.account.address,
        sessionKey: sessionKey.address,
        validUntil: expiry,
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

      await settlement.write.registerSessionKey([sessionKey.address, expiry], {
        account: alice.account,
      });
      await settlement.write.revokeSessionKey([sessionKey.address], { account: alice.account });

      const buyOrder: Order = {
        account: alice.account.address,
        token: lpToken.address,
        isBuy: true,
        tokenAmount: parseUnits("100", 18),
        usdtAmount: parseUnits("1000", 18),
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
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("sk-revoked"),
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
      await settlement.write.registerSessionKey([sessionKey.address, shortValidUntil], {
        account: alice.account,
      });
      await time.increase(200n); // past validUntil

      const laterExpiry = (await time.latest()) + 3600n;
      const buyOrder: Order = {
        account: alice.account.address,
        token: lpToken.address,
        isBuy: true,
        tokenAmount: parseUnits("100", 18),
        usdtAmount: parseUnits("1000", 18),
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
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("sk-expired"),
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
      await settlement.write.registerSessionKey([sessionKey.address, now + 3600n], {
        account: alice.account,
      });

      // (a) session key cannot withdraw alice's funds — withdraw is msg.sender-scoped.
      // skClient has no balance -> InsufficientBalance (proves no cross-account withdraw power).
      await assertions.revertWithCustomError(
        settlement.write.withdrawUsdt([parseUnits("1", 18)], { account: skClient.account }),
        settlement,
        "InsufficientBalance",
      );

      // (b) session key "registering" only affects its OWN mapping, not alice's.
      await settlement.write.registerSessionKey([alice.account.address, now + 3600n], {
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
          buyOrder,
          buySig,
          sellOrder,
          sellSig,
          parseUnits("50", 18),
          parseUnits("500", 18),
          0n,
          0n,
          id,
        ],
        { account: operator.account },
      );
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("10", 18),
            parseUnits("100", 18),
            0n,
            0n,
            id,
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
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("2000", 18),
            0n,
            0n,
            settlementId("nocross"),
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
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("expired"),
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
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("cancelled"),
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
            badBuy,
            badBuySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("side"),
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
      const mismatchedBuy: Order = { ...buyOrder, token: usdt.address };
      const buySig = await signOrder(ALICE_KEY, mismatchedBuy, chainId, settlement.address);
      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            mismatchedBuy,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("tokmismatch"),
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
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("unsupported"),
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
        token: lpToken.address,
        isBuy: true,
        tokenAmount: parseUnits("100", 18),
        usdtAmount: parseUnits("1000", 18),
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
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("self"),
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
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            parseUnits("11", 18),
            0n,
            settlementId("fee"),
          ],
          { account: operator.account },
        ),
        settlement,
        "ExcessiveFee",
      );
    });

    it("insufficient balance reverts and settlementId is NOT marked", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, chainId, expiry, alice, bob, lpToken } = f;
      // seller (bob) only has 1000 token; ask a fill of 5000 token -> underflow revert
      const buyOrder: Order = {
        account: alice.account.address,
        token: lpToken.address,
        isBuy: true,
        tokenAmount: parseUnits("5000", 18),
        usdtAmount: parseUnits("50000", 18),
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
      await assertions.revert(
        settlement.write.settleOrders(
          [
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("5000", 18),
            parseUnits("50000", 18),
            0n,
            0n,
            id,
          ],
          { account: operator.account },
        ),
      );
      assert.strictEqual(
        await settlement.read.processedSettlements([id]),
        false,
        "settlementId must NOT be marked when the settlement reverts",
      );
    });

    it("non-operator caller cannot settle", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, charlie } = f;
      const { buyOrder, buySig, sellOrder, sellSig } = await buildMatchedPair(f);
      await assertions.revert(
        settlement.write.settleOrders(
          [
            buyOrder,
            buySig,
            sellOrder,
            sellSig,
            parseUnits("100", 18),
            parseUnits("1000", 18),
            0n,
            0n,
            settlementId("nonop"),
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
      await settlement.write.withdrawUsdt([amount], { account: alice.account });
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
      await settlement.write.withdrawUsdt([amount], { account: alice.account });
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
      await settlement.write.depositUsdt([amount], { account: alice.account });
      // immediate withdraw -> too early
      await assertions.revertWithCustomError(
        settlement.write.withdrawUsdt([amount], { account: alice.account }),
        settlement,
        "WithdrawalTooEarly",
      );
      await time.increase(1001n);
      await settlement.write.withdrawUsdt([amount], { account: alice.account });
    });
  });

  // =====================================================================
  // Blacklist-exempt platform legs — settlement withdraw bypasses the
  // business blacklist (from == registered TradeSettlement), but an ordinary
  // blacklisted user's deposit (from == that user, an non-platform leg) is
  // still blocked.
  // =====================================================================
  describe("Blacklist-exempt platform legs (settlement)", function () {
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
  // Disabled paths (legacy/net-delta/withdrawFor)
  // =====================================================================
  describe("disabled paths", function () {
    it("batchSettleNetDeltas reverts by default (netDeltaSettlementEnabled == false)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, operator, alice } = f;
      assert.strictEqual(await settlement.read.netDeltaSettlementEnabled(), false);
      await assertions.revertWithCustomError(
        settlement.write.batchSettleNetDeltas(
          [
            settlementId("nd"),
            [{ user: alice.account.address, token: usdt.address, amount: parseUnits("1", 18) }],
          ],
          { account: operator.account },
        ),
        settlement,
        "NetDeltaSettlementDisabled",
      );
    });

    it("setNetDeltaSettlementEnabled(true) without a matured request reverts NetDeltaEnableNotReady", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, owner } = f;
      // No requestEnableNetDelta() at all.
      await assertions.revertWithCustomError(
        settlement.write.setNetDeltaSettlementEnabled([true], { account: owner.account }),
        settlement,
        "NetDeltaEnableNotReady",
      );

      // Requested but not yet matured (48h timelock).
      await settlement.write.requestEnableNetDelta([], { account: owner.account });
      await assertions.revertWithCustomError(
        settlement.write.setNetDeltaSettlementEnabled([true], { account: owner.account }),
        settlement,
        "NetDeltaEnableNotReady",
      );
    });

    it("batchSettleNetDeltas works once owner enables it", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, operator, owner, alice, bob } = f;
      // Enabling net-delta now requires a matured requestEnableNetDelta() (48h timelock).
      await settlement.write.requestEnableNetDelta([], { account: owner.account });
      await time.increase(48n * 60n * 60n + 1n);
      await settlement.write.setNetDeltaSettlementEnabled([true], { account: owner.account });
      const aliceBefore = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      const amt = parseUnits("100", 18);
      await settlement.write.batchSettleNetDeltas(
        [
          settlementId("nd-on"),
          [
            { user: bob.account.address, token: usdt.address, amount: -amt },
            { user: alice.account.address, token: usdt.address, amount: amt },
          ],
        ],
        { account: operator.account },
      );
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        aliceBefore + amt,
      );
    });

    it("legacy settleTrade / batchSettleTrades / settleTradeSecure revert LegacySettlementDisabled", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, lpToken } = f;
      const dummyTrade = {
        maker: f.alice.account.address,
        taker: f.bob.account.address,
        token: lpToken.address,
        tokenAmount: parseUnits("1", 18),
        usdtAmount: parseUnits("1", 18),
        makerFee: 0n,
        takerFee: 0n,
        timestamp: await time.latest(),
        tradeId: settlementId("legacy"),
      };
      await assertions.revertWithCustomError(
        settlement.write.settleTrade([dummyTrade], { account: operator.account }),
        settlement,
        "LegacySettlementDisabled",
      );
      await assertions.revertWithCustomError(
        settlement.write.batchSettleTrades([[dummyTrade]], { account: operator.account }),
        settlement,
        "LegacySettlementDisabled",
      );
      await assertions.revertWithCustomError(
        settlement.write.settleTradeSecure([dummyTrade, "0x", "0x"], { account: operator.account }),
        settlement,
        "LegacySettlementDisabled",
      );
      await assertions.revertWithCustomError(
        settlement.write.settleTradeWithSignatures([dummyTrade, "0x", "0x"], {
          account: operator.account,
        }),
        settlement,
        "LegacySettlementDisabled",
      );
    });

    it("withdrawFor reverts WithdrawFunctionDisabled", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, operator, alice } = f;
      await assertions.revertWithCustomError(
        settlement.write.withdrawFor([alice.account.address, usdt.address, parseUnits("1", 18)], {
          account: operator.account,
        }),
        settlement,
        "WithdrawFunctionDisabled",
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
          buyOrder,
          buySig,
          sellOrder,
          sellSig,
          parseUnits("100", 18),
          parseUnits("1000", 18),
          parseUnits("5", 18),
          parseUnits("5", 18),
          sid,
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
      assert.strictEqual(await settlement.read.supportedTokens([usdt.address]), true);
      assert.strictEqual(await settlement.read.processedSettlements([sid]), true);

      // new mappings read empty for unrelated keys; net-delta still disabled
      assert.strictEqual(await settlement.read.netDeltaSettlementEnabled(), false);
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
