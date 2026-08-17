/**
 * TradeSettlementV1 — audit remainder: .
 *
 * `initialize` no longer seeds the deployer as an operator. Operator grants are
 *          24h-timelocked, and the init carve-out made that timelock conditional on WHEN you asked:
 *          the deployer got the power with zero notice while every later grant was announced. The
 *          test that matters here is the paired one — the SAME signed order set reverts
 *          `NotOperator` at t=0 and settles after queue -> 24h -> execute — because it isolates the
 *          operator grant as the only difference. A "settleOrders reverts" test alone would pass
 *          against a contract that was simply broken.
 *
 * `invalidateOrdersBelow` — nonce-floor bulk cancellation. This is a CENSORSHIP escape
 *          hatch, not a convenience: `cancelOrder` costs one cold SSTORE per order hash, so killing
 *          a book is O(N) with no bound, which is why it could never be gas-sponsored — and a user
 *          with no native balance therefore had no on-chain way to withdraw authorization from an
 *          operator that refuses to settle for them. The load-bearing assertion below is the GAS
 *          one: two accounts invalidate wildly different numbers of open orders and must burn
 *          IDENTICAL gas. A test that only checked "below-floor orders revert" would pass against
 *          an O(N) loop implementation and prove nothing about sponsorability, which is the entire
 *          point of the change.
 *
 * `depositWithPermit` — EIP-2612 approval folded into the deposit. `depositToken` was
 *          sponsorable but the `approve` in front of it is a call to the TOKEN, outside any
 *          paymaster policy scoped to the settlement, so a zero-native-balance user could be
 *          sponsored for a deposit they still could not make. The subtle tests here are the two
 *          that justify the try/catch: a FRONT-RUN permit (nonce already consumed by a third
 *          party, signature now dead, allowance nevertheless present) must still deposit, and a
 *          fee-on-transfer token must still credit the MEASURED delta rather than the amount the
 *          permit authorized.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import {
  parseUnits,
  encodeFunctionData,
  keccak256,
  toBytes,
  zeroAddress,
  parseEventLogs,
  type Hex,
} from "viem";
import { privateKeyToAccount, signTypedData } from "viem/accounts";
import { deploySimpleTokenFixture } from "./tokenFactoryHelpers.js";

describe("TradeSettlementV1", function () {
  const TOTAL_SUPPLY = parseUnits("1000000", 18);
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

  const ALICE_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;
  const BOB_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex;

  const ONE_DAY = 24n * 60n * 60n;
  const LP_TOKEN_NAME = "LaunchpadToken";

  function settlementId(seed: string): Hex {
    return keccak256(toBytes(`eh-${seed}`));
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

  const PERMIT_TYPES = {
    Permit: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
      { name: "value", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  } as const;

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

  /**
   * Sign an EIP-2612 Permit and split it into (v, r, s). The domain `name` MUST be the token's own
   * name — for ERC20V1 that is what `__ERC20Permit_init(_name)` bound at initialize, so a wrong
   * name here recovers a different signer and the permit silently no-ops through the try/catch.
   */
  async function signPermit(params: {
    pk: Hex;
    tokenName: string;
    tokenAddress: `0x${string}`;
    owner: `0x${string}`;
    spender: `0x${string}`;
    value: bigint;
    nonce: bigint;
    deadline: bigint;
    chainId: number;
  }): Promise<{ v: number; r: Hex; s: Hex }> {
    const sig = await signTypedData({
      privateKey: params.pk,
      domain: {
        name: params.tokenName,
        version: "1",
        chainId: params.chainId,
        verifyingContract: params.tokenAddress,
      },
      types: PERMIT_TYPES,
      primaryType: "Permit",
      message: {
        owner: params.owner,
        spender: params.spender,
        value: params.value,
        nonce: params.nonce,
        deadline: params.deadline,
      },
    });
    return {
      r: `0x${sig.slice(2, 66)}` as Hex,
      s: `0x${sig.slice(66, 130)}` as Hex,
      v: parseInt(sig.slice(130, 132), 16),
    };
  }

  /**
   * Deploy the settlement WITHOUT any operator, but with tokens listed and alice/bob funded and
   * deposited. the whole claim is that this state is unusable for settlement, so the fixture
   * must otherwise be complete — anything else missing would confound the assertion.
   *
   * Order expiry is 30 days so the same signed orders survive the 24h operator timelock warp.
   */
  async function deployNoOperatorFixture() {
    const { viem } = await getConnection();
    const [owner, operator, alice, bob, feeRecipient, charlie] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);
    // 1% fee-on-transfer AND EIP-2612-capable — the only shape where permit and measured-delta
    // interact (see the file header).
    const fotToken = await viem.deployContract("MockFeeOnTransferToken", ["FeeToken", "FOT", 100n]);

    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);
    const { token: lpToken } = await deploySimpleTokenFixture({
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
      name: LP_TOKEN_NAME,
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

    // NOTE: no queueOperatorChange here — that is the point of this fixture.
    await settlement.write.setQuoteAsset([usdt.address, true]);
    await settlement.write.setSupportedToken([lpToken.address, true]);
    await settlement.write.setSupportedToken([fotToken.address, true]);

    const usdtAmt = parseUnits("10000", 18);
    for (const trader of [alice, bob]) {
      await usdt.write.mint([trader.account.address, usdtAmt]);
      await usdt.write.approve([settlement.address, usdtAmt], { account: trader.account });
      await settlement.write.depositToken([usdt.address, usdtAmt], { account: trader.account });
    }

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
    const expiry = now + 30n * ONE_DAY;

    return {
      settlement,
      usdt,
      fotToken,
      lpToken,
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

  /** Grant `operator` the operator role through the real 24h timelock. No shortcut helper exists. */
  async function grantOperator(
    f: Awaited<ReturnType<typeof deployNoOperatorFixture>>,
    who: `0x${string}`,
  ) {
    const { settlement, publicClient } = f;
    const queueHash = await settlement.write.queueOperatorChange([who, true]);
    const receipt = await publicClient.waitForTransactionReceipt({ hash: queueHash });
    const changeId = (
      parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "OperatorChangeQueued",
      })[0] as unknown as { args: { changeId: Hex } }
    ).args.changeId;
    await time.increase(ONE_DAY + 1n);
    await settlement.write.executeOperatorChange([changeId]);
    return changeId;
  }

  /** The same fixture with the operator already granted through the timelock. */
  async function deployFixture() {
    const f = await deployNoOperatorFixture();
    await grantOperator(f, f.operator.account.address);
    return f;
  }

  /**
   * alice buys `baseAmount` lpToken from bob at 1:1 in USDT, zero fees. `buyNonce`/`sellNonce` are
   * independent so a nonce floor can be applied to exactly one side.
   */
  async function buildPair(
    f: Awaited<ReturnType<typeof deployNoOperatorFixture>>,
    opts: { baseAmount: bigint; buyNonce: bigint; sellNonce: bigint },
  ) {
    const { alice, bob, chainId, settlement, expiry, lpToken, usdt } = f;
    const buyOrder: Order = {
      account: alice.account.address,
      baseToken: lpToken.address,
      quoteToken: usdt.address,
      isBuy: true,
      baseAmount: opts.baseAmount,
      quoteAmount: opts.baseAmount,
      maxFeeRate: 0n,
      nonce: opts.buyNonce,
      expiry,
    };
    const sellOrder: Order = {
      ...buyOrder,
      account: bob.account.address,
      isBuy: false,
      nonce: opts.sellNonce,
    };
    return {
      buyOrder,
      sellOrder,
      buySig: await signOrder(ALICE_KEY, buyOrder, chainId, settlement.address),
      sellSig: await signOrder(BOB_KEY, sellOrder, chainId, settlement.address),
    };
  }

  function settleArgs(pair: Awaited<ReturnType<typeof buildPair>>, fillBase: bigint, id: Hex) {
    return {
      buyOrder: pair.buyOrder,
      buySig: pair.buySig,
      sellOrder: pair.sellOrder,
      sellSig: pair.sellSig,
      fillBaseAmount: fillBase,
      fillQuoteAmount: fillBase,
      buyerFee: 0n,
      sellerFee: 0n,
      settlementId: id,
    } as const;
  }

  // ==========================================================================================
  // no operator exists until the 24h timelock has actually run
  // ==========================================================================================
  describe("initialize seeds NO operator", function () {
    it("the deployer/owner is not an operator immediately after initialize", async function () {
      const { settlement, owner, operator, alice } = await loadFixture(deployNoOperatorFixture);

      // The deployer is both msg.sender of initialize and the owner, i.e. exactly the address the
      // removed carve-out used to privilege.
      assert.strictEqual(
        await settlement.read.operators([owner.account.address]),
        false,
        "the deploying owner must NOT be an operator — the initialize carve-out is removed",
      );
      assert.strictEqual(await settlement.read.operators([operator.account.address]), false);
      assert.strictEqual(await settlement.read.operators([alice.account.address]), false);
    });

    it("settleOrders reverts NotOperator for the owner even with a fully valid signed pair", async function () {
      const f = await loadFixture(deployNoOperatorFixture);
      const pair = await buildPair(f, {
        baseAmount: parseUnits("100", 18),
        buyNonce: 1n,
        sellNonce: 1n,
      });

      // Submitted by the OWNER — the address that used to be an operator for free.
      await assertions.revertWithCustomError(
        f.settlement.write.settleOrders(
          [settleArgs(pair, parseUnits("100", 18), settlementId("ts13-owner"))],
          {
            account: f.owner.account,
          },
        ),
        f.settlement,
        "NotOperator",
      );
    });

    it("a queued operator change cannot be executed before OPERATOR_CHANGE_DELAY", async function () {
      const { settlement, operator, publicClient } = await loadFixture(deployNoOperatorFixture);

      const queueHash = await settlement.write.queueOperatorChange([
        operator.account.address,
        true,
      ]);
      const receipt = await publicClient.waitForTransactionReceipt({ hash: queueHash });
      const changeId = (
        parseEventLogs({
          abi: settlement.abi,
          logs: receipt.logs,
          eventName: "OperatorChangeQueued",
        })[0] as unknown as { args: { changeId: Hex } }
      ).args.changeId;

      // One second short of the delay.
      await time.increase(ONE_DAY - 10n);
      await assertions.revertWithCustomError(
        settlement.write.executeOperatorChange([changeId]),
        settlement,
        "OperatorChangeTooEarly",
      );
      assert.strictEqual(await settlement.read.operators([operator.account.address]), false);
    });

    it("the IDENTICAL order pair that reverted NotOperator settles once the 24h grant completes", async function () {
      const f = await loadFixture(deployNoOperatorFixture);
      const fillBase = parseUnits("100", 18);
      const pair = await buildPair(f, { baseAmount: fillBase, buyNonce: 2n, sellNonce: 2n });
      const id = settlementId("ts13-paired");

      // Before: no operator exists at all, so nobody can settle.
      await assertions.revertWithCustomError(
        f.settlement.write.settleOrders([settleArgs(pair, fillBase, id)], {
          account: f.operator.account,
        }),
        f.settlement,
        "NotOperator",
      );

      await grantOperator(f, f.operator.account.address);
      assert.strictEqual(await f.settlement.read.operators([f.operator.account.address]), true);

      // After: same orders, same signatures, same settlementId — only the grant changed.
      await f.settlement.write.settleOrders([settleArgs(pair, fillBase, id)], {
        account: f.operator.account,
      });

      assert.strictEqual(
        (await f.settlement.read.getBalance([
          f.alice.account.address,
          f.lpToken.address,
        ])) as bigint,
        parseUnits("1000", 18) + fillBase,
      );
      // The owner is STILL not an operator — the grant was scoped to the operator address only.
      assert.strictEqual(await f.settlement.read.operators([f.owner.account.address]), false);
    });
  });

  // ==========================================================================================
  // invalidateOrdersBelow
  // ==========================================================================================
  describe("invalidateOrdersBelow (O(1) bulk cancellation)", function () {
    it("starts at zero and records a monotonically raised floor", async function () {
      const { settlement, alice } = await loadFixture(deployFixture);

      assert.strictEqual(await settlement.read.minOrderNonce([alice.account.address]), 0n);
      await settlement.write.invalidateOrdersBelow([50n], { account: alice.account });
      assert.strictEqual(await settlement.read.minOrderNonce([alice.account.address]), 50n);
      await settlement.write.invalidateOrdersBelow([51n], { account: alice.account });
      assert.strictEqual(await settlement.read.minOrderNonce([alice.account.address]), 51n);
    });

    it("is msg.sender-scoped — raising alice's floor does not touch bob's", async function () {
      const { settlement, alice, bob } = await loadFixture(deployFixture);

      await settlement.write.invalidateOrdersBelow([500n], { account: alice.account });
      assert.strictEqual(await settlement.read.minOrderNonce([alice.account.address]), 500n);
      assert.strictEqual(await settlement.read.minOrderNonce([bob.account.address]), 0n);
    });

    it("rejects a non-increasing floor (equal and lower both revert)", async function () {
      const { settlement, alice } = await loadFixture(deployFixture);

      await settlement.write.invalidateOrdersBelow([100n], { account: alice.account });

      // Equal — a replayed invalidation must not be treated as a fresh one.
      await assertions.revertWithCustomError(
        settlement.write.invalidateOrdersBelow([100n], { account: alice.account }),
        settlement,
        "MinOrderNonceNotIncreasing",
      );
      // Lower — this is the dangerous one: it would RESURRECT orders alice already killed.
      await assertions.revertWithCustomError(
        settlement.write.invalidateOrdersBelow([99n], { account: alice.account }),
        settlement,
        "MinOrderNonceNotIncreasing",
      );
      // Zero, i.e. an attempt to clear the floor entirely.
      await assertions.revertWithCustomError(
        settlement.write.invalidateOrdersBelow([0n], { account: alice.account }),
        settlement,
        "MinOrderNonceNotIncreasing",
      );
      assert.strictEqual(await settlement.read.minOrderNonce([alice.account.address]), 100n);
    });

    it("emits OrdersInvalidatedBelow — the only signal an indexer gets for a bulk cancel", async function () {
      const { settlement, alice, publicClient } = await loadFixture(deployFixture);

      const hash = await settlement.write.invalidateOrdersBelow([777n], { account: alice.account });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      const events = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "OrdersInvalidatedBelow",
      }) as unknown as { args: { account: `0x${string}`; newMinNonce: bigint } }[];

      assert.strictEqual(events.length, 1);
      assert.strictEqual(events[0].args.account.toLowerCase(), alice.account.address.toLowerCase());
      assert.strictEqual(events[0].args.newMinNonce, 777n);
    });

    it("a below-floor BUY order is unsettleable afterwards", async function () {
      const f = await loadFixture(deployFixture);
      const fillBase = parseUnits("10", 18);
      const pair = await buildPair(f, { baseAmount: fillBase, buyNonce: 5n, sellNonce: 5n });

      // Alice signed order #5, then sweeps everything below #10.
      await f.settlement.write.invalidateOrdersBelow([10n], { account: f.alice.account });

      await assertions.revertWithCustomError(
        f.settlement.write.settleOrders([settleArgs(pair, fillBase, settlementId("v6-buy"))], {
          account: f.operator.account,
        }),
        f.settlement,
        "OrderNonceBelowFloor",
      );
    });

    it("a below-floor SELL order is unsettleable afterwards (the floor is checked on both legs)", async function () {
      const f = await loadFixture(deployFixture);
      const fillBase = parseUnits("10", 18);
      // Buy nonce is high enough to clear any floor; only the SELLER sweeps.
      const pair = await buildPair(f, { baseAmount: fillBase, buyNonce: 9999n, sellNonce: 5n });

      await f.settlement.write.invalidateOrdersBelow([10n], { account: f.bob.account });

      await assertions.revertWithCustomError(
        f.settlement.write.settleOrders([settleArgs(pair, fillBase, settlementId("v6-sell"))], {
          account: f.operator.account,
        }),
        f.settlement,
        "OrderNonceBelowFloor",
      );
    });

    it("an order AT the floor still settles (the bound is strict `<`, so floor N kills, not N)", async function () {
      const f = await loadFixture(deployFixture);
      const fillBase = parseUnits("10", 18);
      const pair = await buildPair(f, { baseAmount: fillBase, buyNonce: 10n, sellNonce: 10n });

      await f.settlement.write.invalidateOrdersBelow([10n], { account: f.alice.account });
      await f.settlement.write.invalidateOrdersBelow([10n], { account: f.bob.account });

      await f.settlement.write.settleOrders(
        [settleArgs(pair, fillBase, settlementId("v6-at-floor"))],
        {
          account: f.operator.account,
        },
      );
      assert.strictEqual(
        (await f.settlement.read.getBalance([
          f.alice.account.address,
          f.lpToken.address,
        ])) as bigint,
        parseUnits("1000", 18) + fillBase,
      );
    });

    it("an order ABOVE the floor still settles, so a sweep does not brick the account", async function () {
      const f = await loadFixture(deployFixture);
      const fillBase = parseUnits("10", 18);
      const pair = await buildPair(f, { baseAmount: fillBase, buyNonce: 42n, sellNonce: 42n });

      await f.settlement.write.invalidateOrdersBelow([10n], { account: f.alice.account });
      await f.settlement.write.invalidateOrdersBelow([10n], { account: f.bob.account });

      await f.settlement.write.settleOrders(
        [settleArgs(pair, fillBase, settlementId("v6-above"))],
        {
          account: f.operator.account,
        },
      );
      assert.strictEqual(
        (await f.settlement.read.getBalance([f.bob.account.address, f.lpToken.address])) as bigint,
        parseUnits("1000", 18) - fillBase,
      );
    });

    it("works while the contract is PAUSED — revoking your own authorization is never pausable", async function () {
      const f = await loadFixture(deployFixture);
      await f.settlement.write.pause({ account: f.owner.account });

      await f.settlement.write.invalidateOrdersBelow([5n], { account: f.alice.account });
      assert.strictEqual(await f.settlement.read.minOrderNonce([f.alice.account.address]), 5n);
    });

    it("GAS IS INDEPENDENT OF ON-CHAIN ORDER HISTORY: an account with a busy book pays the same as an empty one", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, bob, publicClient, lpToken, usdt, expiry, operator } = f;

      // Give BOB real on-chain per-order state — the state a per-order cancellation scheme would
      // have to touch: five `orderCancelled` slots plus an `orderFilled` slot from a real fill.
      // Alice gets none. Both then sweep with the SAME argument, so calldata cost is identical and
      // any gas difference could only come from the sweep doing per-order work.
      for (let i = 0; i < 5; i++) {
        await settlement.write.cancelOrder(
          [
            {
              account: bob.account.address,
              baseToken: lpToken.address,
              quoteToken: usdt.address,
              isBuy: false,
              baseAmount: parseUnits("1", 18),
              quoteAmount: parseUnits("1", 18),
              maxFeeRate: 0n,
              nonce: 300n + BigInt(i),
              expiry,
            },
          ],
          { account: bob.account },
        );
      }
      const fillBase = parseUnits("5", 18);
      const pair = await buildPair(f, { baseAmount: fillBase, buyNonce: 400n, sellNonce: 400n });
      await settlement.write.settleOrders(
        [settleArgs(pair, fillBase, settlementId("v6-gas-fill"))],
        {
          account: operator.account,
        },
      );

      const aliceHash = await settlement.write.invalidateOrdersBelow([1000n], {
        account: alice.account,
      });
      const bobHash = await settlement.write.invalidateOrdersBelow([1000n], {
        account: bob.account,
      });
      const aliceGas = (await publicClient.waitForTransactionReceipt({ hash: aliceHash })).gasUsed;
      const bobGas = (await publicClient.waitForTransactionReceipt({ hash: bobHash })).gasUsed;

      assert.strictEqual(
        aliceGas,
        bobGas,
        `invalidateOrdersBelow must not scale with an account's order history: empty book = ` +
          `${aliceGas}, 5 cancels + 1 fill = ${bobGas}`,
      );

      // Absolute ceiling, so a future implementation cannot creep into loop territory without
      // failing here. One cold SSTORE (20k) + 21k intrinsic + an event sits well under this.
      assert.ok(
        aliceGas < 60_000n,
        `invalidateOrdersBelow burned ${aliceGas} gas — too expensive to sponsor reliably`,
      );
    });

    it("GAS IS INDEPENDENT OF MAGNITUDE: sweeping 5 vs 5,000,000 nonces differs only by calldata bytes", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, bob, publicClient } = f;

      // Cancun calldata pricing: 4 gas per zero byte, 16 per non-zero byte, over the 32-byte word
      // the uint256 argument occupies. That is the ONLY legitimate source of difference between
      // these two calls; execution cost must be identical.
      function calldataGas(value: bigint): bigint {
        const hex = value.toString(16).padStart(64, "0");
        let gas = 0n;
        for (let i = 0; i < 64; i += 2) {
          gas += hex.slice(i, i + 2) === "00" ? 4n : 16n;
        }
        return gas;
      }

      const aliceHash = await settlement.write.invalidateOrdersBelow([5n], {
        account: alice.account,
      });
      const bobHash = await settlement.write.invalidateOrdersBelow([5_000_000n], {
        account: bob.account,
      });
      const aliceGas = (await publicClient.waitForTransactionReceipt({ hash: aliceHash })).gasUsed;
      const bobGas = (await publicClient.waitForTransactionReceipt({ hash: bobHash })).gasUsed;

      assert.strictEqual(
        aliceGas - calldataGas(5n),
        bobGas - calldataGas(5_000_000n),
        `killing 5 orders (${aliceGas} gas) and 5,000,000 orders (${bobGas} gas) must cost the ` +
          `same once the calldata encoding of the argument is netted out`,
      );
    });

    it("cancelOrder by contrast scales with the number of orders — which is why it is not the sponsored path", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, alice, publicClient, lpToken, usdt, expiry } = f;

      async function cancelN(n: number, nonceBase: bigint): Promise<bigint> {
        let total = 0n;
        for (let i = 0; i < n; i++) {
          const order: Order = {
            account: alice.account.address,
            baseToken: lpToken.address,
            quoteToken: usdt.address,
            isBuy: true,
            baseAmount: parseUnits("1", 18),
            quoteAmount: parseUnits("1", 18),
            maxFeeRate: 0n,
            nonce: nonceBase + BigInt(i),
            expiry,
          };
          const hash = await settlement.write.cancelOrder([order], { account: alice.account });
          total += (await publicClient.waitForTransactionReceipt({ hash })).gasUsed;
        }
        return total;
      }

      const gasFor2 = await cancelN(2, 1000n);
      const gasFor8 = await cancelN(8, 2000n);

      // Not a tight assertion — the point is only that the cost is UNBOUNDED in N, so no paymaster
      // can price it, whereas invalidateOrdersBelow above is a single fixed write.
      assert.ok(
        gasFor8 > gasFor2 * 3n,
        `cancelOrder should scale ~linearly in N: 2 orders = ${gasFor2}, 8 orders = ${gasFor8}`,
      );
    });
  });

  // ==========================================================================================
  // depositWithPermit
  // ==========================================================================================
  describe("depositWithPermit (gasless first deposit)", function () {
    it("deposits with NO prior approve, using only an EIP-2612 signature", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, alice, chainId } = f;

      // Precondition that makes the test meaningful: the allowance really is zero.
      assert.strictEqual(
        (await lpToken.read.allowance([alice.account.address, settlement.address])) as bigint,
        0n,
        "fixture leaked an allowance — the permit path would not be exercised",
      );

      const amount = parseUnits("250", 18);
      const deadline = (await time.latest()) + 3600n;
      const before = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;

      const { v, r, s } = await signPermit({
        pk: ALICE_KEY,
        tokenName: LP_TOKEN_NAME,
        tokenAddress: lpToken.address,
        owner: alice.account.address,
        spender: settlement.address,
        value: amount,
        nonce: (await lpToken.read.nonces([alice.account.address])) as bigint,
        deadline,
        chainId,
      });

      await settlement.write.depositWithPermit([lpToken.address, amount, deadline, v, r, s], {
        account: alice.account,
      });

      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        before + amount,
      );
      // The permit was consumed exactly once.
      assert.strictEqual((await lpToken.read.nonces([alice.account.address])) as bigint, 1n);
    });

    it("an EXPIRED permit reverts the deposit (no allowance ever materializes)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, alice, chainId } = f;

      const amount = parseUnits("100", 18);
      const deadline = (await time.latest()) - 1n; // already in the past
      const before = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;

      const { v, r, s } = await signPermit({
        pk: ALICE_KEY,
        tokenName: LP_TOKEN_NAME,
        tokenAddress: lpToken.address,
        owner: alice.account.address,
        spender: settlement.address,
        value: amount,
        nonce: (await lpToken.read.nonces([alice.account.address])) as bigint,
        deadline,
        chainId,
      });

      // NOTE ON THE ERROR SURFACED: the permit's own ERC2612ExpiredSignature is SWALLOWED by the
      // try/catch, so what the caller sees is the ERC20 allowance failure from safeTransferFrom.
      // The deposit still fails closed — that is the property under test — but off-chain callers
      // must not expect to distinguish "permit expired" from "permit malformed" by error name.
      await assertions.revert(
        settlement.write.depositWithPermit([lpToken.address, amount, deadline, v, r, s], {
          account: alice.account,
        }),
      );

      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        before,
        "an expired permit must not credit anything",
      );
      assert.strictEqual((await lpToken.read.nonces([alice.account.address])) as bigint, 0n);
    });

    it("SURVIVES A FRONT-RUN: a third party consuming the permit does not brick the deposit", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, alice, bob, chainId } = f;

      const amount = parseUnits("300", 18);
      const deadline = (await time.latest()) + 3600n;
      const { v, r, s } = await signPermit({
        pk: ALICE_KEY,
        tokenName: LP_TOKEN_NAME,
        tokenAddress: lpToken.address,
        owner: alice.account.address,
        spender: settlement.address,
        value: amount,
        nonce: (await lpToken.read.nonces([alice.account.address])) as bigint,
        deadline,
        chainId,
      });

      // Bob lifts alice's signature out of the mempool and submits the bare permit himself. The
      // nonce is now consumed, so alice's own transaction would revert inside `permit` — but the
      // allowance it wanted EXISTS. Reverting here would be pure griefing.
      await lpToken.write.permit(
        [alice.account.address, settlement.address, amount, deadline, v, r, s],
        {
          account: bob.account,
        },
      );
      assert.strictEqual((await lpToken.read.nonces([alice.account.address])) as bigint, 1n);

      const before = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;

      await settlement.write.depositWithPermit([lpToken.address, amount, deadline, v, r, s], {
        account: alice.account,
      });

      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        before + amount,
        "the front-run permit must not prevent the deposit — this is why the permit is try/catch'd",
      );
    });

    it("MEASURED DELTA survives the permit path: a fee-on-transfer token credits what ARRIVED", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, fotToken, alice, chainId, publicClient } = f;

      const amount = parseUnits("1000", 18);
      const expectedCredit = (amount * 9900n) / 10000n; // 1% burned in transit
      await fotToken.write.mint([alice.account.address, amount]);

      const deadline = (await time.latest()) + 3600n;
      const { v, r, s } = await signPermit({
        pk: ALICE_KEY,
        tokenName: "FeeToken",
        tokenAddress: fotToken.address,
        owner: alice.account.address,
        spender: settlement.address,
        value: amount,
        nonce: (await fotToken.read.nonces([alice.account.address])) as bigint,
        deadline,
        chainId,
      });

      const hash = await settlement.write.depositWithPermit(
        [fotToken.address, amount, deadline, v, r, s],
        { account: alice.account },
      );
      const receipt = await publicClient.waitForTransactionReceipt({ hash });

      // The permit authorized `amount`; the ledger must record only what actually arrived.
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, fotToken.address])) as bigint,
        expectedCredit,
      );
      const deposited = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "Deposited",
      }) as unknown as { args: { amount: bigint } }[];
      assert.strictEqual(deposited[0].args.amount, expectedCredit);

      // I1: the tracked liability equals the real balance, which is the whole reason measures.
      assert.strictEqual(
        (await fotToken.read.balanceOf([settlement.address])) as bigint,
        expectedCredit,
      );
    });

    it("a token WITHOUT permit still deposits when an allowance already exists (permit failure is non-fatal)", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, alice } = f;

      // `contracts/USDT.sol` has no EIP-2612 `permit`, so the call reverts and is swallowed.
      const amount = parseUnits("500", 18);
      await usdt.write.mint([alice.account.address, amount]);
      await usdt.write.approve([settlement.address, amount], { account: alice.account });

      const before = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;
      const deadline = (await time.latest()) + 3600n;
      const junk = `0x${"11".repeat(32)}` as Hex;

      await settlement.write.depositWithPermit([usdt.address, amount, deadline, 27, junk, junk], {
        account: alice.account,
      });

      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        before + amount,
      );
    });

    it("a token WITHOUT permit and WITHOUT an allowance reverts — the function is not a bypass", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, alice } = f;

      const amount = parseUnits("500", 18);
      await usdt.write.mint([alice.account.address, amount]);
      assert.strictEqual(
        (await usdt.read.allowance([alice.account.address, settlement.address])) as bigint,
        0n,
      );

      const deadline = (await time.latest()) + 3600n;
      const junk = `0x${"11".repeat(32)}` as Hex;
      const before = (await settlement.read.getBalance([
        alice.account.address,
        usdt.address,
      ])) as bigint;

      await assertions.revert(
        settlement.write.depositWithPermit([usdt.address, amount, deadline, 27, junk, junk], {
          account: alice.account,
        }),
      );
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, usdt.address])) as bigint,
        before,
      );
    });

    it("keeps depositToken's gates: unlisted token reverts UnsupportedToken, and pause blocks it", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, lpToken, alice, owner, chainId, viem } = f;

      // Unlisted asset — the permit path must not bypass the registry gate.
      const stranger = await viem.deployContract("USDT", [owner.account.address, 18]);
      const deadline = (await time.latest()) + 3600n;
      const junk = `0x${"11".repeat(32)}` as Hex;
      await assertions.revertWithCustomError(
        settlement.write.depositWithPermit(
          [stranger.address, parseUnits("1", 18), deadline, 27, junk, junk],
          { account: alice.account },
        ),
        settlement,
        "UnsupportedToken",
      );

      // Paused — deposits are inbound legs and stay pause-gated (unlike withdrawals).
      await settlement.write.pause({ account: owner.account });
      const amount = parseUnits("10", 18);
      const { v, r, s } = await signPermit({
        pk: ALICE_KEY,
        tokenName: LP_TOKEN_NAME,
        tokenAddress: lpToken.address,
        owner: alice.account.address,
        spender: settlement.address,
        value: amount,
        nonce: (await lpToken.read.nonces([alice.account.address])) as bigint,
        deadline,
        chainId,
      });
      await assertions.revertWithCustomError(
        settlement.write.depositWithPermit([lpToken.address, amount, deadline, v, r, s], {
          account: alice.account,
        }),
        settlement,
        "EnforcedPause",
      );
    });
  });
});
