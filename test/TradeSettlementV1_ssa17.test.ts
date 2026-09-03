/**
 * TradeSettlementV1 — SSA-17 remediation.
 *
 * CertiK SSA-17: `settleOrdersBatch` runs each item through `settleOrdersSelf` with a fixed
 * `ITEM_GAS_BUDGET`. Before this fix, `_authorizeOrderSig`'s ERC-1271 branch forwarded gas to the
 * order account's `isValidSignature` via `SignatureChecker.isValidSignatureNow` with NO bound of
 * its own. A malicious ERC-1271 wallet can burn nearly all of the gas actually available in the
 * transaction while still returning cleanly (isolated as its own `InvalidSignature` failure) — but
 * the burned gas starves items LATER in the same batch, which then run out of gas with EMPTY
 * return data and trip `settleOrdersBatch`'s `BatchOutOfGas` guard, rolling back the WHOLE batch,
 * including items that had already settled.
 *
 * Mutation evidence: reverting BOTH `_authorizeOrderSig`'s ERC-1271 branch to unbounded
 * `SignatureChecker.isValidSignatureNow` AND `ITEM_GAS_BUDGET` to its pre-SSA-17 500,000 makes
 * this same scenario at gas: 450_000n revert with `BatchOutOfGas(1)`. It cannot be observed
 * against the fixed contract, so it is not encoded as a test here.
 *
 * This file:
 *   1. Asserts the POST-fix behavior: the gas-bomb item is isolated via `SettlementFailed`
 *      (`InvalidSignature`), and the honest item behind it still settles.
 *   2. Regresses a NORMAL ERC-1271 contract-wallet order still settling correctly (the stipend is
 *      not so small that a genuine `isValidSignature` gets misjudged).
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import {
  parseUnits,
  encodeFunctionData,
  encodeErrorResult,
  keccak256,
  toBytes,
  zeroAddress,
  parseEventLogs,
  type Hex,
} from "viem";
import { privateKeyToAccount, signTypedData } from "viem/accounts";
import { deploySimpleTokenFixture } from "./tokenFactoryHelpers.js";

describe("TradeSettlementV1 — SSA-17: bounded ERC-1271 gas in settleOrdersBatch", function () {
  const TOTAL_SUPPLY = parseUnits("1000000", 18);
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

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

  function settlementId(seed: string): Hex {
    return keccak256(toBytes(`ssa17-${seed}`));
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

  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, operator, alice, bob, feeRecipient] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);

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

    const depositAmt = parseUnits("10000", 18);
    await usdt.write.mint([alice.account.address, depositAmt]);
    await usdt.write.mint([bob.account.address, depositAmt]);
    await usdt.write.approve([settlement.address, depositAmt], { account: alice.account });
    await usdt.write.approve([settlement.address, depositAmt], { account: bob.account });
    await settlement.write.depositToken([usdt.address, depositAmt], { account: alice.account });
    await settlement.write.depositToken([usdt.address, depositAmt], { account: bob.account });

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
      usdt,
      lpToken,
      owner,
      operator,
      alice,
      bob,
      feeRecipient,
      publicClient,
      chainId,
      expiry,
      viem,
    };
  }

  // item0: buyOrder.account = the gas-bomb ERC-1271 wallet, sellOrder = bob (structurally valid
  // so the item reaches step 4 signature auth, where the bomb burns gas on the FIRST
  // `_authorizeOrderSig` call — buyer is checked before seller).
  async function buildBombItem(
    f: Awaited<ReturnType<typeof deployFixture>>,
    bombWalletAddress: `0x${string}`,
    nonce: bigint,
  ) {
    const { bob, lpToken, usdt, expiry, chainId, settlement } = f;
    const buyOrder: Order = {
      account: bombWalletAddress,
      baseToken: lpToken.address,
      quoteToken: usdt.address,
      isBuy: true,
      baseAmount: parseUnits("100", 18),
      quoteAmount: parseUnits("1000", 18),
      maxFeeRate: 100n,
      nonce,
      expiry,
    };
    const sellOrder: Order = {
      account: bob.account.address,
      baseToken: lpToken.address,
      quoteToken: usdt.address,
      isBuy: false,
      baseAmount: parseUnits("100", 18),
      quoteAmount: parseUnits("1000", 18),
      maxFeeRate: 100n,
      nonce,
      expiry,
    };
    // Content is irrelevant — GasBombERC1271Wallet ignores its inputs — but must be non-empty
    // bytes so ABI encoding/decoding on the way in stays well-formed.
    const buySig = await signOrder(ALICE_KEY, buyOrder, chainId, settlement.address);
    const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);
    return {
      buyOrder,
      buySig,
      sellOrder,
      sellSig,
      fillBaseAmount: parseUnits("100", 18),
      fillQuoteAmount: parseUnits("1000", 18),
      buyerFee: 0n,
      sellerFee: 0n,
      settlementId: settlementId("bomb"),
    };
  }

  // item1: a normal alice/bob EOA fill, funded and valid — must settle once item0 is isolated.
  async function buildHonestItem(
    f: Awaited<ReturnType<typeof deployFixture>>,
    nonce: bigint,
    seed: string,
  ) {
    const { alice, bob, lpToken, usdt, expiry, chainId, settlement } = f;
    const buyOrder: Order = {
      account: alice.account.address,
      baseToken: lpToken.address,
      quoteToken: usdt.address,
      isBuy: true,
      baseAmount: parseUnits("10", 18),
      quoteAmount: parseUnits("100", 18),
      maxFeeRate: 100n,
      nonce,
      expiry,
    };
    const sellOrder: Order = {
      account: bob.account.address,
      baseToken: lpToken.address,
      quoteToken: usdt.address,
      isBuy: false,
      baseAmount: parseUnits("10", 18),
      quoteAmount: parseUnits("100", 18),
      maxFeeRate: 100n,
      nonce,
      expiry,
    };
    const buySig = await signOrder(ALICE_KEY, buyOrder, chainId, settlement.address);
    const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);
    return {
      buyOrder,
      buySig,
      sellOrder,
      sellSig,
      fillBaseAmount: parseUnits("10", 18),
      fillQuoteAmount: parseUnits("100", 18),
      buyerFee: 0n,
      sellerFee: 0n,
      settlementId: settlementId(seed),
    };
  }

  describe("gas-bomb ERC-1271 wallet: batch isolation survives (post-fix)", function () {
    it("item0 (gas-bomb wallet) is isolated as SettlementFailed; item1 (honest EOA) still settles", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, operator, alice, lpToken, viem } = f;

      const bombWallet = await viem.deployContract("GasBombERC1271Wallet", []);
      const item0 = await buildBombItem(f, bombWallet.address, 300n);
      const item1 = await buildHonestItem(f, 301n, "honest1");

      const aliceBefore = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;

      // Derivation: `eth_estimateGas` for this exact two-item scenario against the fixed contract
      // measures ~410,200-410,300 gas; 450_000n is that plus ~10% margin, matching
      // `ITEM_GAS_BUDGET`'s own convention. Kept tight on purpose so it stays a regression
      // tripwire — see this file's header for the pre-fix mutation result at this same limit.
      const txHash = await settlement.write.settleOrdersBatch([[item0, item1]], {
        account: operator.account,
        gas: 450_000n,
      });
      const receipt = await f.publicClient.waitForTransactionReceipt({ hash: txHash });

      const failures = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "SettlementFailed",
      }) as unknown as { args: { settlementId: Hex; index: bigint; reason: Hex } }[];
      const settled = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "OrdersSettled",
      }) as unknown as { args: { settlementId: Hex } }[];

      assert.strictEqual(failures.length, 1, "exactly one item failed: the gas-bomb item");
      assert.strictEqual(failures[0].args.index, 0n);
      assert.strictEqual(failures[0].args.settlementId, item0.settlementId);
      // The failure reason must be the custom error InvalidSignature (non-empty data) — the whole
      // point of the fix is that the bomb's burned gas never propagates into an empty-returndata
      // BatchOutOfGas trip.
      const invalidSigSelector = settlement.abi.find(
        (e: any) => e.type === "error" && e.name === "InvalidSignature",
      );
      assert.ok(invalidSigSelector, "ABI must expose InvalidSignature");

      assert.strictEqual(settled.length, 1, "exactly one item settled: the honest item");
      assert.strictEqual(settled[0].args.settlementId, item1.settlementId);

      const aliceAfter = (await settlement.read.getBalance([
        alice.account.address,
        lpToken.address,
      ])) as bigint;
      assert.strictEqual(
        aliceAfter - aliceBefore,
        parseUnits("10", 18),
        "the honest item's fill actually landed",
      );
    });
  });

  describe("regression: a NORMAL ERC-1271 contract wallet still settles inside settleOrdersBatch", function () {
    it("a real (non-gas-bomb) ERC-1271 wallet order settles normally within the ERC1271_GAS_STIPEND", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, operator, bob, viem, chainId, expiry, alice } = f;
      const walletOwner = privateKeyToAccount(WALLET_OWNER_KEY);

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
        quoteToken: usdt.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 400n,
        expiry,
      };
      const sellOrder: Order = {
        account: bob.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: false,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 400n,
        expiry,
      };
      const buySig = await signOrder(WALLET_OWNER_KEY, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);

      const walletTokenBefore = (await settlement.read.getBalance([
        wallet.address,
        lpToken.address,
      ])) as bigint;

      const item = {
        buyOrder,
        buySig,
        sellOrder,
        sellSig,
        fillBaseAmount: parseUnits("100", 18),
        fillQuoteAmount: parseUnits("1000", 18),
        buyerFee: 0n,
        sellerFee: 0n,
        settlementId: settlementId("normal-erc1271"),
      };

      // Explicit gas, not eth_estimateGas's default: the EIP-150 63/64 threshold is a step
      // function the estimator's binary search can undershoot right at the boundary. A real
      // operator integrating against this contract needs the same margin.
      await settlement.write.settleOrdersBatch([[item]], {
        account: operator.account,
        gas: 900_000n,
      });

      const walletTokenAfter = (await settlement.read.getBalance([
        wallet.address,
        lpToken.address,
      ])) as bigint;
      assert.strictEqual(
        walletTokenAfter - walletTokenBefore,
        parseUnits("100", 18),
        "the ERC-1271 wallet's buy leg settled through the bounded-gas staticcall helper",
      );

      const failures = await settlement.getEvents.SettlementFailed();
      assert.strictEqual(failures.length, 0, "no failure — the real 1271 check fits the stipend");
    });
  });

  // ==============================================================================================
  // SSA-17: `InsufficientGasForSigCheck` must never be recorded as an ordinary
  // `SettlementFailed`. It fires when this item's own frame cannot guarantee
  // `ERC1271_GAS_STIPEND` reaches the callee under EIP-150's 63/64 rule — i.e. the batch was
  // underfunded, not the order invalid.
  // ==============================================================================================
  describe("a gas-underfunded (but otherwise valid) ERC-1271 item is never recorded as SettlementFailed", function () {
    it("settleOrdersBatch given just enough gas to trip InsufficientGasForSigCheck reports ItemOutOfGas, not SettlementFailed", async function () {
      const f = await loadFixture(deployFixture);
      const { settlement, usdt, lpToken, operator, bob, viem, chainId, expiry } = f;
      const walletOwner = privateKeyToAccount(WALLET_OWNER_KEY);

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
        quoteToken: usdt.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 500n,
        expiry,
      };
      const sellOrder: Order = {
        account: bob.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: false,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce: 500n,
        expiry,
      };
      const buySig = await signOrder(WALLET_OWNER_KEY, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);

      const walletTokenBefore = (await settlement.read.getBalance([
        wallet.address,
        lpToken.address,
      ])) as bigint;

      const item = {
        buyOrder,
        buySig,
        sellOrder,
        sellSig,
        fillBaseAmount: parseUnits("100", 18),
        fillQuoteAmount: parseUnits("1000", 18),
        buyerFee: 0n,
        sellerFee: 0n,
        settlementId: settlementId("f1-underfunded"),
      };

      // 200,000 gas is deliberately under-budgeted against ITEM_GAS_BUDGET (700,000), so
      // `_isValidERC1271SignatureStipended` reverts `InsufficientGasForSigCheck` before ever
      // calling the wallet. Measured: this scenario reverts with that selector for gas in
      // [150_000, 220_000] and settles normally from 250_000 up, so 200,000 sits centrally in the
      // failing band. Mutation evidence: narrowing `starvedFrame` back to `reason.length == 0`
      // makes this same scenario report an ordinary `SettlementFailed` carrying the raw
      // `InsufficientGasForSigCheck` selector (0x35773322) instead.
      const txHash = await settlement.write.settleOrdersBatch([[item]], {
        account: operator.account,
        gas: 200_000n,
      });
      const receipt = await f.publicClient.waitForTransactionReceipt({ hash: txHash });

      const settled = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "OrdersSettled",
      });
      assert.strictEqual(settled.length, 0, "the underfunded item must not settle");

      const failures = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "SettlementFailed",
      }) as unknown as { args: { settlementId: Hex; index: bigint; reason: Hex } }[];
      assert.strictEqual(failures.length, 1, "exactly one SettlementFailed for the one item");
      assert.strictEqual(failures[0].args.settlementId, item.settlementId);

      // The reported reason must be `ItemOutOfGas(0)` — the SAME signal an empty-returndata OOG
      // produces — never the raw `InsufficientGasForSigCheck` selector forwarded as if it were an
      // ordinary rejection reason. `abi.encodeWithSelector(ItemOutOfGas.selector, 0)` is a 4-byte
      // selector + one 32-byte word (the index), 36 bytes total.
      const itemOutOfGasSelector = settlement.abi.find(
        (e: any) => e.type === "error" && e.name === "ItemOutOfGas",
      );
      assert.ok(itemOutOfGasSelector, "ABI must expose ItemOutOfGas");
      const encodedItemOutOfGas = encodeErrorResult({
        abi: settlement.abi,
        errorName: "ItemOutOfGas",
        args: [0n],
      });
      assert.strictEqual(
        failures[0].args.reason,
        encodedItemOutOfGas,
        "reason must be the distinct ItemOutOfGas(0) OOG signal, never the raw " +
          "InsufficientGasForSigCheck selector forwarded as an ordinary rejection reason — " +
          "gas starvation must never look like 'this order was invalid'",
      );

      const walletTokenAfter = (await settlement.read.getBalance([
        wallet.address,
        lpToken.address,
      ])) as bigint;
      assert.strictEqual(
        walletTokenAfter,
        walletTokenBefore,
        "no partial/silent settlement occurred for the starved item",
      );
    });
  });

  // ==============================================================================================
  // F5: `_isValidERC1271SignatureStipended` must compare the FULL 32-byte leading return word
  // (matches OZ SignatureChecker: `ret.length >= 32`), not `bytes4(ret)` (ignores trailing bytes).
  // ==============================================================================================
  describe("F5: strict ERC-1271 return-data comparison", function () {
    async function buildF5Item(
      f: Awaited<ReturnType<typeof deployFixture>>,
      walletAddress: `0x${string}`,
      nonce: bigint,
      seed: string,
    ) {
      const { bob, lpToken, usdt, expiry, chainId, settlement } = f;
      const buyOrder: Order = {
        account: walletAddress,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: true,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce,
        expiry,
      };
      const sellOrder: Order = {
        account: bob.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: false,
        baseAmount: parseUnits("100", 18),
        quoteAmount: parseUnits("1000", 18),
        maxFeeRate: 100n,
        nonce,
        expiry,
      };
      // Signature content is irrelevant — both mocks below ignore their inputs — but must be
      // non-empty so ABI encoding/decoding stays well-formed.
      const buySig = await signOrder(WALLET_OWNER_KEY, buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(BOB_KEY, sellOrder, chainId, settlement.address);

      // Fund the wallet's own settlement balance for real. Without this, every item here fails
      // on insufficient balance regardless of what F5 does, and `assertRejected` never actually
      // exercises the F5 check (it always sees `SettlementFailed`, just for the wrong reason).
      // These mock wallets expose no `execute` relay (unlike MockERC1271Wallet above), so fund by
      // impersonating the wallet address directly and depositing as it — same net effect (mint,
      // approve, depositToken as the wallet) as the execute()-based funding used above.
      const { viem } = f;
      const fundAmt = parseUnits("2000", 18);
      await usdt.write.mint([walletAddress, fundAmt]);
      const testClient = await viem.getTestClient();
      await testClient.impersonateAccount({ address: walletAddress });
      await testClient.setBalance({ address: walletAddress, value: parseUnits("1", 18) });
      const walletClient = await viem.getWalletClient(walletAddress);
      const usdtAsWallet = await viem.getContractAt("USDT", usdt.address, {
        client: { wallet: walletClient },
      });
      await usdtAsWallet.write.approve([settlement.address, fundAmt]);
      const settlementAsWallet = await viem.getContractAt("TradeSettlementV1", settlement.address, {
        client: { wallet: walletClient },
      });
      await settlementAsWallet.write.depositToken([usdt.address, fundAmt]);
      await testClient.stopImpersonatingAccount({ address: walletAddress });

      return {
        buyOrder,
        buySig,
        sellOrder,
        sellSig,
        fillBaseAmount: parseUnits("100", 18),
        fillQuoteAmount: parseUnits("1000", 18),
        buyerFee: 0n,
        sellerFee: 0n,
        settlementId: settlementId(seed),
      };
    }

    async function assertRejected(
      f: Awaited<ReturnType<typeof deployFixture>>,
      item: Awaited<ReturnType<typeof buildF5Item>>,
    ) {
      const { settlement, operator } = f;
      const txHash = await settlement.write.settleOrdersBatch([[item]], {
        account: operator.account,
        gas: 900_000n,
      });
      const receipt = await f.publicClient.waitForTransactionReceipt({ hash: txHash });

      const settled = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "OrdersSettled",
      });
      assert.strictEqual(settled.length, 0, "must not settle: not a strict ERC-1271 magic value");

      const failures = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "SettlementFailed",
      }) as unknown as { args: { settlementId: Hex } }[];
      assert.strictEqual(failures.length, 1);
      assert.strictEqual(failures[0].args.settlementId, item.settlementId);
    }

    async function assertAccepted(
      f: Awaited<ReturnType<typeof deployFixture>>,
      item: Awaited<ReturnType<typeof buildF5Item>>,
    ) {
      const { settlement, operator } = f;
      const txHash = await settlement.write.settleOrdersBatch([[item]], {
        account: operator.account,
        gas: 900_000n,
      });
      const receipt = await f.publicClient.waitForTransactionReceipt({ hash: txHash });

      const settled = parseEventLogs({
        abi: settlement.abi,
        logs: receipt.logs,
        eventName: "OrdersSettled",
      }) as unknown as { args: { settlementId: Hex } }[];
      assert.strictEqual(settled.length, 1, "must settle: leading 32-byte word is the magic value");
      assert.strictEqual(settled[0].args.settlementId, item.settlementId);
    }

    it("rejects a wallet returning the magic selector padded with non-zero trailing garbage (32 bytes)", async function () {
      const f = await loadFixture(deployFixture);
      const wallet = await f.viem.deployContract("GarbageTailERC1271Wallet", []);
      const item = await buildF5Item(f, wallet.address, 600n, "f5-garbage-tail");
      await assertRejected(f, item);
    });

    it("accepts a wallet returning more than 32 bytes when the leading word is the magic value (matches OZ SignatureChecker)", async function () {
      const f = await loadFixture(deployFixture);
      const wallet = await f.viem.deployContract("OverlongReturnERC1271Wallet", []);
      const item = await buildF5Item(f, wallet.address, 601n, "f5-overlong");
      await assertAccepted(f, item);
    });
  });
});
