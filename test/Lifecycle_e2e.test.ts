/**
 * Lifecycle_e2e.test.ts — full store-token lifecycle across TokenFactory -> LaunchpadV1 ->
 * TradeSettlementV1, wired with REAL deployed contracts end-to-end (no mocks; `USDT.sol` test
 * stablecoin reused per this repo's existing convention). Motivation: `grep -l createLaunchpad`
 * and `grep -l settleOrders` across `test/` never intersected before this file — every
 * contract has dense unit coverage (690 tests), but nothing chained a store token through its
 * entire real path (issue -> raise -> finalize -> claim -> list -> trade -> withdraw), which is
 * exactly the path today's audit remediation touched (softcap revert-not-cancel, the
 * permissionless underfunded-cancel split, and the immediate vesting start — see the
 * per-scenario docstrings below for exactly which remediation each one pins).
 *
 * Every fixture/helper here is reused from `test/tokenFactoryHelpers.ts` and mirrors the exact
 * setup patterns already used in `test/LaunchpadV1.test.ts`, `test/TokenFactory.test.ts`, and
 * `test/TradeSettlementV1_multiquote.test.ts` (operator timelock wiring, EIP-712 Order signing,
 * softcap fixture shape) — no contract code is modified by this file.
 *
 * Scenarios:
 *   A — happy path (softcap cleared): issueToken -> createLaunchpad -> multi-investor
 *       participate -> finalizeLaunchpad (succeeds) -> claimTokens -> claimVestedPayment ->
 *       list the token on TradeSettlementV1 -> deposit -> settleOrders -> withdrawToken.
 *   B — softcap miss: participate under 20% -> finalizeLaunchpad reverts LaunchpadUnderfunded
 *       -> a permissionless third party calls cancelUnderfundedLaunchpad -> business recovers
 *       the FULL escrowed saleAmount -> investor refund() recovers the full paymentAmount.
 *   C — the listing trap the trade session found by running the stack locally: a base token
 *       registered ONLY via setQuoteAsset (never setSupportedToken) accepts deposits fine
 *       (`_deposit` accepts `supportedTokens[t] || quoteAssets[t].listed`) but can never settle
 *       (`settleOrders` unconditionally requires `supportedTokens[baseToken]`) — deposit
 *       succeeds, settlement permanently reverts UnsupportedToken.
 * D — launchpadBp == 0 funds no escrow, so LaunchpadV1/TokenFactory's only two
 *       startVesting() callers can never run for that token — issueToken starts the Owner
 *       Vesting wallet immediately instead, and this walks that wallet through release().
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseUnits,
  encodeFunctionData,
  keccak256,
  toBytes,
  zeroAddress,
  parseEventLogs,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount, signTypedData } from "viem/accounts";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import {
  deployTokenFactoryCore,
  configureDefaultAllocationGuides,
  setLinkedLaunchpad,
  setEscrowTimeout,
  setResaleWait,
  issueTokenWithRatios,
  buildRatios,
  deploySimpleTokenFixture,
} from "./tokenFactoryHelpers.js";

// The same literal Hardhat default-mnemonic private keys hardcoded across every
// TradeSettlementV1_*.test.ts file in this repo (0=account0, 1=account1, ...) — verified there
// to correspond positionally to `viem.getWalletClients()`'s default account order, reused as-is
// so Order signatures resolve to whichever wallet client sits at that index in each fixture.
const KEYS: Record<number, Hex> = {
  0: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  1: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  2: "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  3: "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
};

const TOTAL_SUPPLY = parseUnits("1000000", 18);
const TOKEN_PRICE = parseUnits("1", 18); // 1 USDT per token (both 18-dec)

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

async function signOrder(pk: Hex, order: Order, chainId: number, verifyingContract: Address) {
  return signTypedData({
    privateKey: pk,
    domain: { name: "StarZipTradeSettlement", version: "1", chainId, verifyingContract },
    types: ORDER_TYPES,
    primaryType: "Order",
    message: order,
  });
}

function sid(seed: string): Hex {
  return keccak256(toBytes(`lifecycle-${seed}`));
}

/** Queue + advance 24h + execute an operator grant — identical to every other
 *  TradeSettlementV1 test file's setup (queueOperatorChange -> OPERATOR_CHANGE_DELAY -> execute). */
async function grantOperator(settlement: any, operatorAddress: Address, publicClient: any) {
  const hash = await settlement.write.queueOperatorChange([operatorAddress, true]);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const events = parseEventLogs({
    abi: settlement.abi,
    logs: receipt.logs,
    eventName: "OperatorChangeQueued",
  });
  const changeId = (events[0] as unknown as { args: { changeId: Hex } }).args.changeId;
  await time.increase(24n * 60n * 60n + 1n);
  await settlement.write.executeOperatorChange([changeId]);
}

describe("Lifecycle e2e — TokenFactory -> LaunchpadV1 -> TradeSettlementV1", function () {
  // =====================================================================================
  // Scenario A — happy path, softcap cleared
  // =====================================================================================
  describe("Scenario A — issue -> raise (over softcap) -> finalize -> claim -> vest -> list -> trade -> withdraw", function () {
    async function deployFixture() {
      const { viem } = await getConnection();
      const [owner, operator, investor1, investor2, business, feeRecipient, platformTreasury] =
        await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const chainId = await publicClient.getChainId();

      const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);
      const permitSigner = privateKeyToAccount(KEYS[0]);

      const { tokenFactory } = await deployTokenFactoryCore(
        viem,
        owner,
        platformTreasury.account.address,
        permitSigner.address,
      );
      await configureDefaultAllocationGuides(tokenFactory, owner);

      const launchpadImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const launchpadImpl = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: launchpadImplMathLib.address },
      });
      const launchpadInitData = encodeFunctionData({
        abi: launchpadImpl.abi,
        functionName: "initialize",
        args: [
          tokenFactory.address,
          usdt.address,
          feeRecipient.account.address,
          platformTreasury.account.address,
        ],
      });
      const launchpadProxy = await viem.deployContract("ERC1967Proxy", [
        launchpadImpl.address,
        launchpadInitData,
      ]);
      const launchpad = await viem.getContractAt("LaunchpadV1", launchpadProxy.address);

      await setLinkedLaunchpad(tokenFactory, owner, launchpad.address);
      await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n);
      await setResaleWait(tokenFactory, owner, 7n * 24n * 60n * 60n);
      await launchpad.write.setPreparationTime([3600n]); // 1 hour
      await launchpad.write.setLaunchpadDuration([86400n]); // 1 day

      const settlementImpl = await viem.deployContract("TradeSettlementV1", []);
      const settlementInitData = encodeFunctionData({
        abi: settlementImpl.abi,
        functionName: "initialize",
        args: [feeRecipient.account.address, zeroAddress],
      });
      const settlementProxy = await viem.deployContract("ERC1967Proxy", [
        settlementImpl.address,
        settlementInitData,
      ]);
      const settlement = await viem.getContractAt("TradeSettlementV1", settlementProxy.address);
      await grantOperator(settlement, operator.account.address, publicClient);

      const fundAmount = parseUnits("1000000", 18);
      await usdt.write.mint([investor1.account.address, fundAmount]);
      await usdt.write.mint([investor2.account.address, fundAmount]);
      await usdt.write.approve([launchpad.address, fundAmount], { account: investor1.account });
      await usdt.write.approve([launchpad.address, fundAmount], { account: investor2.account });

      return {
        viem,
        publicClient,
        chainId,
        owner,
        operator,
        investor1,
        investor2,
        business,
        feeRecipient,
        platformTreasury,
        usdt,
        tokenFactory,
        launchpad,
        settlement,
      };
    }

    it("moves the correct balances at every step of the real lifecycle", async function () {
      const f = await loadFixture(deployFixture);
      const {
        viem,
        publicClient,
        chainId,
        owner,
        operator,
        investor1,
        investor2,
        business,
        feeRecipient,
        platformTreasury,
        usdt,
        tokenFactory,
        launchpad,
        settlement,
      } = f;

      // ---- 1. issueToken: LAUNCHPAD 90% / LIQUIDITY_RESERVE 10% / OWNER 0% ----
      const ratios = buildRatios({
        launchpadBp: 9000,
        liquidityBp: 1000,
        ownerBp: 0,
        liquidityRecipient: platformTreasury.account.address,
      });
      const { tokenAddress } = await issueTokenWithRatios({
        tokenFactory,
        business,
        publicClient,
        chainId,
        permitPrivateKey: KEYS[0],
        linkedLaunchpad: launchpad.address,
        name: "LifecycleToken",
        symbol: "LFC",
        totalSupply: TOTAL_SUPPLY,
        ratios,
      });
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      const saleAmount = (TOTAL_SUPPLY * 9000n) / 10000n; // 900,000e18 — escrowed
      const liquidityAmount = (TOTAL_SUPPLY * 1000n) / 10000n; // 100,000e18

      // Bucket distribution happened at issuance, before any launchpad interaction.
      assert.strictEqual(
        await token.read.balanceOf([platformTreasury.account.address]),
        liquidityAmount,
        "LIQUIDITY_RESERVE bucket reached its recipient at issuance",
      );
      assert.strictEqual(
        await token.read.balanceOf([tokenFactory.address]),
        saleAmount,
        "LAUNCHPAD bucket stays escrowed in the factory until createLaunchpad",
      );

      // ---- 2. createLaunchpad: saleAmount pulled from escrow, not caller-supplied ----
      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );
      assert.strictEqual(
        await token.read.balanceOf([tokenFactory.address]),
        0n,
        "escrow fully released to the launchpad",
      );
      assert.strictEqual(await token.read.balanceOf([launchpad.address]), saleAmount);

      const info0 = (await launchpad.read.getLaunchpadInfo([0n])) as { startTime: bigint };
      await time.increaseTo(info0.startTime);

      // ---- 3. participate: two investors raise well above the 20% softcap ----
      const invest1 = parseUnits("300000", 18);
      const invest2 = parseUnits("200000", 18);
      await launchpad.write.participate([0n, invest1], { account: investor1.account });
      await launchpad.write.participate([0n, invest2], { account: investor2.account });

      const totalRaised = invest1 + invest2; // 500,000e18 (~55.6% of the 900,000e18 target)
      const targetRaise = saleAmount; // TOKEN_PRICE == 1e18, 18-dec USDT => scaleFactor cancels
      const requiredRaise = (targetRaise * 2000n) / 10000n; // MIN_RAISE_BP == 2000
      assert.ok(totalRaised > requiredRaise, "fixture actually clears the softcap");

      const p1 = (await launchpad.read.getParticipantInfo([0n, investor1.account.address])) as {
        tokenAmount: bigint;
      };
      const p2 = (await launchpad.read.getParticipantInfo([0n, investor2.account.address])) as {
        tokenAmount: bigint;
      };
      assert.strictEqual(p1.tokenAmount, invest1, "1:1 price => tokenAmount == paymentAmount");
      assert.strictEqual(p2.tokenAmount, invest2);

      // ---- 4. finalizeLaunchpad: succeeds (softcap cleared), 3-way split + unsold return ----
      const info1 = (await launchpad.read.getLaunchpadInfo([0n])) as { endTime: bigint };
      await time.increaseTo(info1.endTime + 1n);

      const feeRecipientUsdtBefore = (await usdt.read.balanceOf([
        feeRecipient.account.address,
      ])) as bigint;
      const businessTokenBefore = (await token.read.balanceOf([
        business.account.address,
      ])) as bigint;
      const businessUsdtBeforeFinalize = (await usdt.read.balanceOf([
        business.account.address,
      ])) as bigint;
      // deployTokenFactoryCore-based fixtures in this file wire liquidityRecipient ==
      // platformTreasury at launchpad initialize (see the launchpadInitData args above).
      const liquidityUsdtBefore = (await usdt.read.balanceOf([
        platformTreasury.account.address,
      ])) as bigint;

      await launchpad.write.finalizeLaunchpad([0n]);

      const finalized = (await launchpad.read.getLaunchpadInfo([0n])) as { status: number };
      assert.strictEqual(finalized.status, 4, "Finalized");

      const feeRate = (await launchpad.read.launchpadFeeRate()) as bigint;
      const fee = (totalRaised * feeRate) / 10000n; // launchpadFeeRate default 5% (canonical)
      assert.strictEqual(
        (await usdt.read.balanceOf([feeRecipient.account.address])) as bigint,
        feeRecipientUsdtBefore + fee,
        "5% fee reached feeRecipient",
      );

      const unsoldAmount = saleAmount - totalRaised; // soldAmount == totalRaised at this price
      assert.strictEqual(
        (await token.read.balanceOf([business.account.address])) as bigint,
        businessTokenBefore + unsoldAmount,
        "unsold escrowed tokens returned to the business immediately at finalize",
      );

      // Canonical default split (from LaunchpadV1.initialize): the post-fee remainder is
      // split 3 ways — immediate (business), liquidity (platformTreasury here), and
      // vesting (the remainder, matching finalizeLaunchpad's own rounding).
      const remaining = totalRaised - fee;
      const immediateRate = (await launchpad.read.immediateRate()) as bigint;
      const liquidityRate = (await launchpad.read.liquidityRate()) as bigint;
      const expectedImmediate = (remaining * immediateRate) / 10000n;
      const expectedLiquidity = (remaining * liquidityRate) / 10000n;
      const vestingRemainder = remaining - expectedImmediate - expectedLiquidity;

      assert.strictEqual(
        (await usdt.read.balanceOf([business.account.address])) as bigint,
        businessUsdtBeforeFinalize + expectedImmediate,
        "immediate USDT share reached the business",
      );
      assert.strictEqual(
        (await usdt.read.balanceOf([platformTreasury.account.address])) as bigint,
        liquidityUsdtBefore + expectedLiquidity,
        "liquidity USDT share reached the liquidity recipient",
      );

      const vesting = (await launchpad.read.getVestingInfo([0n])) as { totalAmount: bigint };
      assert.strictEqual(vesting.totalAmount, vestingRemainder);

      // ---- 5. claimTokens: each investor receives exactly their purchased amount ----
      const inv1TokenBefore = (await token.read.balanceOf([investor1.account.address])) as bigint;
      const inv2TokenBefore = (await token.read.balanceOf([investor2.account.address])) as bigint;
      await launchpad.write.claimTokens([0n], { account: investor1.account });
      await launchpad.write.claimTokens([0n], { account: investor2.account });
      assert.strictEqual(
        (await token.read.balanceOf([investor1.account.address])) as bigint,
        inv1TokenBefore + invest1,
      );
      assert.strictEqual(
        (await token.read.balanceOf([investor2.account.address])) as bigint,
        inv2TokenBefore + invest2,
      );

      // ---- 6. claimVestedPayment: business draws the first unlocked USDT tranche ----
      const launchpadSchedule = (await launchpad.read.getLaunchpadVestingSchedule([0n])) as {
        vestingInterval: bigint;
      };
      await time.increase(launchpadSchedule.vestingInterval + 1n); // clears period-0 (2000bp / 20%) of 8
      const businessUsdtBefore = (await usdt.read.balanceOf([business.account.address])) as bigint;
      await launchpad.write.claimVestedPayment([0n], { account: business.account });
      const firstTranche = (vestingRemainder * 2000n) / 10000n; // 97,000e18
      assert.strictEqual(
        (await usdt.read.balanceOf([business.account.address])) as bigint,
        businessUsdtBefore + firstTranche,
        "first vesting quarter (20%) paid out via claimVestedPayment",
      );

      // ---- 7. list the token on TradeSettlementV1: setSupportedToken (base) + setQuoteAsset ----
      await settlement.write.setSupportedToken([tokenAddress, true]);
      await settlement.write.setQuoteAsset([usdt.address, true]);

      // ---- 8. investor1 deposits base token (sells), investor2 deposits USDT (buys) ----
      const tradeBaseAmount = parseUnits("10000", 18);
      const tradeQuoteAmount = parseUnits("10000", 18);

      await token.write.approve([settlement.address, tradeBaseAmount], {
        account: investor1.account,
      });
      await settlement.write.depositToken([tokenAddress, tradeBaseAmount], {
        account: investor1.account,
      });
      await usdt.write.approve([settlement.address, tradeQuoteAmount], {
        account: investor2.account,
      });
      await settlement.write.depositToken([usdt.address, tradeQuoteAmount], {
        account: investor2.account,
      });

      assert.strictEqual(
        (await settlement.read.getBalance([investor1.account.address, tokenAddress])) as bigint,
        tradeBaseAmount,
      );
      assert.strictEqual(
        (await settlement.read.getBalance([investor2.account.address, usdt.address])) as bigint,
        tradeQuoteAmount,
      );

      // ---- 9. settleOrders: investor2 buys tradeBaseAmount from investor1 at a 1:1 price ----
      const now = await time.latest();
      const expiry = now + 3600n;
      const buyOrder: Order = {
        account: investor2.account.address,
        baseToken: tokenAddress,
        quoteToken: usdt.address,
        isBuy: true,
        baseAmount: tradeBaseAmount,
        quoteAmount: tradeQuoteAmount,
        maxFeeRate: 0n,
        nonce: 1n,
        expiry,
      };
      const sellOrder: Order = {
        account: investor1.account.address,
        baseToken: tokenAddress,
        quoteToken: usdt.address,
        isBuy: false,
        baseAmount: tradeBaseAmount,
        quoteAmount: tradeQuoteAmount,
        maxFeeRate: 0n,
        nonce: 1n,
        expiry,
      };
      const buySig = await signOrder(KEYS[3], buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(KEYS[2], sellOrder, chainId, settlement.address);

      await settlement.write.settleOrders(
        [
          {
            buyOrder: buyOrder,
            buySig: buySig,
            sellOrder: sellOrder,
            sellSig: sellSig,
            fillBaseAmount: tradeBaseAmount,
            fillQuoteAmount: tradeQuoteAmount,
            buyerFee: 0n,
            sellerFee: 0n,
            settlementId: sid("a-trade"),
          },
        ],
        { account: operator.account },
      );

      assert.strictEqual(
        (await settlement.read.getBalance([investor2.account.address, tokenAddress])) as bigint,
        tradeBaseAmount,
        "buyer credited the full base amount",
      );
      assert.strictEqual(
        (await settlement.read.getBalance([investor1.account.address, tokenAddress])) as bigint,
        0n,
        "seller's base-token balance fully debited",
      );
      assert.strictEqual(
        (await settlement.read.getBalance([investor1.account.address, usdt.address])) as bigint,
        tradeQuoteAmount,
        "seller credited the full quote amount (0 fee)",
      );
      assert.strictEqual(
        (await settlement.read.getBalance([investor2.account.address, usdt.address])) as bigint,
        0n,
      );

      // ---- 10. withdrawToken: investor1 self-custody-exits the USDT it just earned ----
      const inv1ExternalUsdtBefore = (await usdt.read.balanceOf([
        investor1.account.address,
      ])) as bigint;
      await settlement.write.withdrawToken([usdt.address, tradeQuoteAmount], {
        account: investor1.account,
      });
      assert.strictEqual(
        (await usdt.read.balanceOf([investor1.account.address])) as bigint,
        inv1ExternalUsdtBefore + tradeQuoteAmount,
        "withdrawn USDT actually left the contract to investor1's wallet",
      );
      assert.strictEqual(
        (await settlement.read.getBalance([investor1.account.address, usdt.address])) as bigint,
        0n,
      );
    });
  });

  // =====================================================================================
  // Scenario B — softcap miss: revert, permissionless cancel, full refund round-trip
  // =====================================================================================
  describe("Scenario B — under 20% raised: finalize reverts, cancelUnderfundedLaunchpad + refund make investors whole", function () {
    async function deployFixture() {
      const { viem } = await getConnection();
      const [owner, investor1, business, feeRecipient, platformTreasury, thirdParty] =
        await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const chainId = await publicClient.getChainId();

      const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);
      const permitSigner = privateKeyToAccount(KEYS[0]);

      const { tokenFactory } = await deployTokenFactoryCore(
        viem,
        owner,
        platformTreasury.account.address,
        permitSigner.address,
      );
      await configureDefaultAllocationGuides(tokenFactory, owner);

      const launchpadImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const launchpadImpl = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: launchpadImplMathLib.address },
      });
      const launchpadInitData = encodeFunctionData({
        abi: launchpadImpl.abi,
        functionName: "initialize",
        args: [
          tokenFactory.address,
          usdt.address,
          feeRecipient.account.address,
          platformTreasury.account.address,
        ],
      });
      const launchpadProxy = await viem.deployContract("ERC1967Proxy", [
        launchpadImpl.address,
        launchpadInitData,
      ]);
      const launchpad = await viem.getContractAt("LaunchpadV1", launchpadProxy.address);

      await setLinkedLaunchpad(tokenFactory, owner, launchpad.address);
      await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n);
      await setResaleWait(tokenFactory, owner, 7n * 24n * 60n * 60n);
      await launchpad.write.setPreparationTime([3600n]);
      await launchpad.write.setLaunchpadDuration([86400n]);

      const fundAmount = parseUnits("1000000", 18);
      await usdt.write.mint([investor1.account.address, fundAmount]);
      await usdt.write.approve([launchpad.address, fundAmount], { account: investor1.account });

      return {
        viem,
        publicClient,
        chainId,
        owner,
        investor1,
        business,
        feeRecipient,
        platformTreasury,
        thirdParty,
        usdt,
        tokenFactory,
        launchpad,
      };
    }

    it("business recovers the FULL escrowed saleAmount and the investor's refund exactly matches pre-participation balance", async function () {
      const {
        viem,
        publicClient,
        chainId,
        business,
        investor1,
        platformTreasury,
        thirdParty,
        usdt,
        tokenFactory,
        launchpad,
      } = await loadFixture(deployFixture);

      const ratios = buildRatios({
        launchpadBp: 9000,
        liquidityBp: 1000,
        ownerBp: 0,
        liquidityRecipient: platformTreasury.account.address,
      });
      const { tokenAddress } = await issueTokenWithRatios({
        tokenFactory,
        business,
        publicClient,
        chainId,
        permitPrivateKey: KEYS[0],
        linkedLaunchpad: launchpad.address,
        name: "UnderfundedToken",
        symbol: "UFT",
        totalSupply: TOTAL_SUPPLY,
        ratios,
      });
      const token = await viem.getContractAt("ERC20V1", tokenAddress);
      const saleAmount = (TOTAL_SUPPLY * 9000n) / 10000n; // 900,000e18

      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );

      const info0 = (await launchpad.read.getLaunchpadInfo([0n])) as { startTime: bigint };
      await time.increaseTo(info0.startTime);

      // 100,000e18 out of a 900,000e18 target == 11.1% — under the 20% MIN_RAISE_BP floor.
      const paymentAmount = parseUnits("100000", 18);
      const investor1UsdtBaseline = (await usdt.read.balanceOf([
        investor1.account.address,
      ])) as bigint;
      await launchpad.write.participate([0n, paymentAmount], { account: investor1.account });
      assert.strictEqual(
        (await usdt.read.balanceOf([investor1.account.address])) as bigint,
        investor1UsdtBaseline - paymentAmount,
      );

      const info1 = (await launchpad.read.getLaunchpadInfo([0n])) as { endTime: bigint };
      await time.increaseTo(info1.endTime + 1n);

      // finalizeLaunchpad no longer auto-cancels underfunded raises — it reverts and changes
      // nothing (this IS the audit remediation the e2e gap is checking).
      await assertions.revertWithCustomError(
        launchpad.write.finalizeLaunchpad([0n]),
        launchpad,
        "LaunchpadUnderfunded",
      );
      const midInfo = (await launchpad.read.getLaunchpadInfo([0n])) as { status: number };
      assert.strictEqual(midInfo.status, 2, "reverted finalize left status untouched (Active)");

      const businessTokenBefore = (await token.read.balanceOf([
        business.account.address,
      ])) as bigint;

      // Permissionless: an unrelated third party (neither owner/business/investor) cancels it.
      await launchpad.write.cancelUnderfundedLaunchpad([0n], { account: thirdParty.account });

      const cancelled = (await launchpad.read.getLaunchpadInfo([0n])) as { status: number };
      assert.strictEqual(cancelled.status, 5, "Cancelled");

      // FULL escrowed saleAmount (not merely the unsold remainder) returns to
      // TokenFactory escrow, NOT the business — the sale is voided outright but the token
      // stays resale-eligible (via a later createLaunchpad) after resaleWaitSeconds elapses.
      assert.strictEqual(
        (await token.read.balanceOf([business.account.address])) as bigint,
        businessTokenBefore,
        "business is not credited directly — the token returns to factory escrow instead",
      );
      const [escrowAmount, , consumed] = (await tokenFactory.read.getEscrowInfo([
        tokenAddress,
      ])) as [bigint, bigint, boolean];
      assert.strictEqual(
        escrowAmount,
        saleAmount,
        "the FULL saleAmount (not merely the unsold portion) is restored to escrow",
      );
      assert.strictEqual(consumed, false);

      // Investor refund() pays back exactly the participation amount — no fee/vesting cut was
      // ever taken on an underfunded raise.
      await launchpad.write.refund([0n], { account: investor1.account });
      assert.strictEqual(
        (await usdt.read.balanceOf([investor1.account.address])) as bigint,
        investor1UsdtBaseline,
        "investor's USDT balance after refund exactly matches its pre-participation baseline",
      );

      // claimTokens is unreachable from Cancelled — nothing was ever distributed.
      await assertions.revertWithCustomError(
        launchpad.write.claimTokens([0n], { account: investor1.account }),
        launchpad,
        "LaunchpadNotEnded",
      );
    });
  });

  // =====================================================================================
  // Scenario C — the listing trap: quote-only registration deposits fine, settles never
  // =====================================================================================
  describe("Scenario C — base token listed ONLY via setQuoteAsset (never setSupportedToken): deposit succeeds, settleOrders reverts forever", function () {
    async function deployFixture() {
      const { viem } = await getConnection();
      const [owner, operator, alice, bob, feeRecipient] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const chainId = await publicClient.getChainId();

      const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);
      const permitSigner = privateKeyToAccount(KEYS[0]);

      const { token: lpToken } = await deploySimpleTokenFixture({
        viem,
        deployer: owner,
        business: alice,
        neutralRecipient: owner,
        publicClient,
        chainId,
        permitPrivateKey: KEYS[0],
        permitSignerAddress: permitSigner.address,
        platformTreasuryAddress: owner.account.address,
        totalSupply: TOTAL_SUPPLY,
        name: "MisListedToken",
        symbol: "MLT",
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
      await grantOperator(settlement, operator.account.address, publicClient);

      // Correctly list the quote asset...
      await settlement.write.setQuoteAsset([usdt.address, true]);
      // ...but for the BASE token, make the exact mistake the trade session found in the wild:
      // register it via setQuoteAsset instead of setSupportedToken. Deliberately never call
      // setSupportedToken(lpToken, true) anywhere in this fixture.
      await settlement.write.setQuoteAsset([lpToken.address, true]);

      const usdtAmt = parseUnits("10000", 18);
      await usdt.write.mint([bob.account.address, usdtAmt]);
      await usdt.write.approve([settlement.address, usdtAmt], { account: bob.account });
      await settlement.write.depositToken([usdt.address, usdtAmt], { account: bob.account });

      return {
        viem,
        publicClient,
        chainId,
        owner,
        operator,
        alice,
        bob,
        feeRecipient,
        usdt,
        lpToken,
        settlement,
      };
    }

    it("depositToken succeeds for the mis-listed base token, settleOrders reverts UnsupportedToken", async function () {
      const { chainId, operator, alice, bob, usdt, lpToken, settlement } =
        await loadFixture(deployFixture);

      // Sanity: the mistake really did register it as a QUOTE asset, not a base (supported) one.
      const q = (await settlement.read.quoteAssets([lpToken.address])) as [boolean, ...unknown[]];
      assert.strictEqual(q[0], true, "listed as a quote asset");
      assert.strictEqual(
        (await settlement.read.supportedTokens([lpToken.address])) as boolean,
        false,
        "never listed as a supported (base) asset",
      );

      // ---- deposit succeeds (this is the trap: `_deposit` accepts EITHER registry) ----
      const depositAmount = parseUnits("1000", 18);
      await lpToken.write.approve([settlement.address, depositAmount], { account: alice.account });
      await settlement.write.depositToken([lpToken.address, depositAmount], {
        account: alice.account,
      });
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, lpToken.address])) as bigint,
        depositAmount,
        "deposit of the mis-listed base token succeeded",
      );
      assert.strictEqual(
        (await lpToken.read.balanceOf([settlement.address])) as bigint,
        depositAmount,
      );

      // ---- settlement can NEVER clear: settleOrders unconditionally requires
      //      supportedTokens[baseToken], which this token never got ----
      const now = await time.latest();
      const expiry = now + 3600n;
      const amt = parseUnits("100", 18);
      const buyOrder: Order = {
        account: bob.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: true,
        baseAmount: amt,
        quoteAmount: amt,
        maxFeeRate: 0n,
        nonce: 1n,
        expiry,
      };
      const sellOrder: Order = {
        account: alice.account.address,
        baseToken: lpToken.address,
        quoteToken: usdt.address,
        isBuy: false,
        baseAmount: amt,
        quoteAmount: amt,
        maxFeeRate: 0n,
        nonce: 1n,
        expiry,
      };
      const buySig = await signOrder(KEYS[3], buyOrder, chainId, settlement.address);
      const sellSig = await signOrder(KEYS[2], sellOrder, chainId, settlement.address);

      await assertions.revertWithCustomError(
        settlement.write.settleOrders(
          [
            {
              buyOrder: buyOrder,
              buySig: buySig,
              sellOrder: sellOrder,
              sellSig: sellSig,
              fillBaseAmount: amt,
              fillQuoteAmount: amt,
              buyerFee: 0n,
              sellerFee: 0n,
              settlementId: sid("c-trap"),
            },
          ],
          { account: operator.account },
        ),
        settlement,
        "UnsupportedToken",
      );

      // The deposited balance is not gone — it is simply stuck in the settlement ledger for
      // trading purposes; self-custody exit (withdrawToken, not gated on either registry) still
      // works, which is what actually saves the depositor here, not settlement.
      const aliceExternalBefore = (await lpToken.read.balanceOf([alice.account.address])) as bigint;
      await settlement.write.withdrawToken([lpToken.address, depositAmount], {
        account: alice.account,
      });
      assert.strictEqual(
        (await lpToken.read.balanceOf([alice.account.address])) as bigint,
        aliceExternalBefore + depositAmount,
        "withdrawToken (self-custody exit) still recovers the stuck deposit",
      );
    });
  });

  // =====================================================================================
  // Scenario D — launchpadBp == 0 starts the Owner Vesting wallet immediately
  // =====================================================================================
  describe("Scenario D — launchpadBp == 0 skips escrow and does not strand the Owner Vesting wallet", function () {
    async function deployFixture() {
      const { viem } = await getConnection();
      const [owner, business, platformTreasury] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const chainId = await publicClient.getChainId();

      const permitSigner = privateKeyToAccount(KEYS[0]);
      const { tokenFactory } = await deployTokenFactoryCore(
        viem,
        owner,
        platformTreasury.account.address,
        permitSigner.address,
      );
      await configureDefaultAllocationGuides(tokenFactory, owner);

      // No real launchpad interaction happens in this scenario (launchpadBp == 0 => no escrow
      // is ever funded => createLaunchpad can never run for this token), so a placeholder
      // linkedLaunchpad address is enough — mirrors deploySimpleTokenFixture's own convention.
      const linkedLaunchpadPlaceholder = tokenFactory.address;
      await setLinkedLaunchpad(tokenFactory, owner, linkedLaunchpadPlaceholder);
      await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n);
      await setResaleWait(tokenFactory, owner, 7n * 24n * 60n * 60n);

      return {
        viem,
        publicClient,
        chainId,
        owner,
        business,
        platformTreasury,
        tokenFactory,
        linkedLaunchpadPlaceholder,
      };
    }

    it("starts the funded owner vesting wallet at issuance and the business can release() after the duration elapses", async function () {
      const {
        viem,
        publicClient,
        chainId,
        business,
        platformTreasury,
        tokenFactory,
        linkedLaunchpadPlaceholder,
      } = await loadFixture(deployFixture);

      const ratios = buildRatios({
        launchpadBp: 0,
        liquidityBp: 9000,
        ownerBp: 1000,
        liquidityRecipient: platformTreasury.account.address,
      });
      const { tokenAddress, vestingWallet } = await issueTokenWithRatios({
        tokenFactory,
        business,
        publicClient,
        chainId,
        permitPrivateKey: KEYS[0],
        linkedLaunchpad: linkedLaunchpadPlaceholder,
        name: "ValOneToken",
        symbol: "VAL1",
        totalSupply: TOTAL_SUPPLY,
        ratios,
      });

      // No LAUNCHPAD bucket was ever funded — confirms the precondition.
      assert.strictEqual(await tokenFactory.read.launchpadEscrow([tokenAddress]), 0n);

      const wallet = await viem.getContractAt("TokenVestingWallet", vestingWallet);
      assert.strictEqual(
        await wallet.read.started(),
        true,
        "issueToken started the wallet immediately instead of leaving it deferred",
      );
      assert.notStrictEqual(
        await wallet.read.start(),
        2n ** 64n - 1n,
        "start() is not the type(uint64).max deferred sentinel",
      );

      const token = await viem.getContractAt("ERC20V1", tokenAddress);
      const ownerAmount = (TOTAL_SUPPLY * 1000n) / 10000n; // 100,000e18
      assert.strictEqual(await token.read.balanceOf([vestingWallet]), ownerAmount);

      const duration = (await wallet.read.duration()) as bigint;
      await time.increase(duration + 1n);

      const businessTokenBefore = (await token.read.balanceOf([
        business.account.address,
      ])) as bigint;
      await wallet.write.release([], { account: business.account });
      assert.strictEqual(
        (await token.read.balanceOf([business.account.address])) as bigint,
        businessTokenBefore + ownerAmount,
        "business actually receives the full owner allocation via release()",
      );
      assert.strictEqual(await token.read.balanceOf([vestingWallet]), 0n);
    });
  });
});
