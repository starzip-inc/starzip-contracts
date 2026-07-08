import { describe, it } from "node:test";
import assert from "node:assert";
import { parseUnits, getAddress, encodeFunctionData, zeroAddress, Address, Hex } from "viem";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import { privateKeyToAccount } from "viem/accounts";
import {
  deployTokenFactoryCore,
  configureDefaultAllocationGuides,
  setLinkedLaunchpad,
  setEscrowTimeout,
  issueTokenWithRatios,
  buildRatios,
} from "./tokenFactoryHelpers.js";

// Test private key for permit signing (DO NOT USE IN PRODUCTION)
const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

interface LaunchpadInfo {
  businessAccount: Address;
  tokenAddress: Address;
  paymentToken: Address;
  saleAmount: bigint;
  soldAmount: bigint;
  tokenPrice: bigint;
  startTime: bigint;
  endTime: bigint;
  totalRaised: bigint;
  status: number;
}

interface ParticipantInfo {
  paymentAmount: bigint;
  tokenAmount: bigint;
  claimedAmount: bigint;
  refunded: boolean;
}

/**
 * LaunchpadV1 — createLaunchpad now derives `saleAmount`
 * from the TokenFactory-escrowed LAUNCHPAD bucket (no caller-supplied amount / no
 * approve+transferFrom), and finalizeLaunchpad splits the post-fee raise 3 ways
 * (immediate/liquidity/vesting) plus triggers the per-token Owner Vesting wallet.
 * This file owns the Launchpad-side business logic; TokenFactory's own escrow/
 * bucket/timelock unit tests live in TokenFactory.test.ts (this file wires a REAL
 * TokenFactory + REAL LaunchpadV1 pair, matching production).
 */
describe("LaunchpadV1", function () {
  const TOKEN_PRICE = parseUnits("1", 18); // 1 USDT per token
  const TOTAL_SUPPLY = parseUnits("1000000", 18); // 1M tokens

  async function deployLaunchpadFixture() {
    const { viem } = await getConnection();
    const [owner, business, user1, user2, feeRecipient, platformTreasury] =
      await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);
    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);

    const {
      tokenFactory,
      erc20Beacon: beacon,
      vestingWalletBeacon,
    } = await deployTokenFactoryCore(
      viem,
      owner,
      platformTreasury.account.address,
      permitSigner.address,
    );
    await configureDefaultAllocationGuides(tokenFactory, owner);

    const launchpadImpl = await viem.deployContract("LaunchpadV1", []);
    const initData = encodeFunctionData({
      abi: launchpadImpl.abi,
      functionName: "initialize",
      args: [tokenFactory.address, usdt.address, feeRecipient.account.address],
    });
    const proxy = await viem.deployContract("ERC1967Proxy", [launchpadImpl.address, initData]);
    const launchpad = await viem.getContractAt("LaunchpadV1", proxy.address);

    await setLinkedLaunchpad(tokenFactory, owner, launchpad.address);
    // Escrow timeout must be set before issuing a token with a LAUNCHPAD bucket (fail-closed).
    await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n);

    await usdt.write.mint([user1.account.address, parseUnits("1000000", 18)]);
    await usdt.write.mint([user2.account.address, parseUnits("1000000", 18)]);
    await usdt.write.approve([launchpad.address, parseUnits("1000000", 18)], {
      account: user1.account,
    });
    await usdt.write.approve([launchpad.address, parseUnits("1000000", 18)], {
      account: user2.account,
    });

    return {
      launchpad,
      tokenFactory,
      usdt,
      beacon,
      vestingWalletBeacon,
      owner,
      business,
      user1,
      user2,
      feeRecipient,
      platformTreasury,
      publicClient,
      chainId,
      viem,
    };
  }

  /**
   * Issue a token whose LAUNCHPAD bucket is ~99.99% of totalSupply (escrowed) and
   * LIQUIDITY_RESERVE is the remaining 0.01% (routed to `platformTreasury` — the
   * `liqG.minBp` floor forbids 0), then call `createLaunchpad` (saleAmount derived
   * from the escrow, no approve/transferFrom needed).
   */
  async function issueTokenAndCreateLaunchpad(
    fixture: Awaited<ReturnType<typeof deployLaunchpadFixture>>,
    overrides?: { ownerBp?: number; startTime?: bigint; endTime?: bigint },
  ) {
    const {
      tokenFactory,
      launchpad,
      business,
      usdt,
      platformTreasury,
      publicClient,
      chainId,
      viem,
    } = fixture;

    const ownerBp = overrides?.ownerBp ?? 0;
    const launchpadBp = 9999 - ownerBp;
    const ratios = buildRatios({
      launchpadBp,
      liquidityBp: 1,
      ownerBp,
      liquidityRecipient: platformTreasury.account.address,
    });

    const { tokenAddress, vestingWallet } = await issueTokenWithRatios({
      tokenFactory,
      business,
      publicClient,
      chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: launchpad.address,
      name: "TestToken",
      symbol: "TT",
      totalSupply: TOTAL_SUPPLY,
      contractURI: "https://example.com/metadata",
      ratios,
    });

    const saleAmount = (TOTAL_SUPPLY * BigInt(launchpadBp)) / 10000n;
    const token = await viem.getContractAt("ERC20V1", tokenAddress);

    await launchpad.write.createLaunchpad(
      [
        tokenAddress,
        TOKEN_PRICE,
        business.account.address,
        usdt.address,
        overrides?.startTime ?? 0n,
        overrides?.endTime ?? 0n,
      ],
      { account: business.account },
    );

    return { tokenAddress, saleAmount, vestingWallet, token };
  }

  describe("Initialization", function () {
    it("should initialize correctly", async function () {
      const { launchpad, tokenFactory, feeRecipient, owner } =
        await loadFixture(deployLaunchpadFixture);

      assert.strictEqual(await launchpad.read.owner(), getAddress(owner.account.address));
      assert.strictEqual(await launchpad.read.tokenFactory(), getAddress(tokenFactory.address));
      assert.strictEqual(
        await launchpad.read.feeRecipient(),
        getAddress(feeRecipient.account.address),
      );
      assert.strictEqual(await launchpad.read.launchpadFeeRate(), 300n); // 3%
    });

    it("should reject zero addresses in initialize", async function () {
      const { usdt, feeRecipient, viem } = await loadFixture(deployLaunchpadFixture);

      const launchpadImpl = await viem.deployContract("LaunchpadV1", []);
      const initDataZeroFactory = encodeFunctionData({
        abi: launchpadImpl.abi,
        functionName: "initialize",
        args: [zeroAddress, usdt.address, feeRecipient.account.address],
      });

      await assertions.revert(
        viem.deployContract("ERC1967Proxy", [launchpadImpl.address, initDataZeroFactory]),
      );
    });
  });

  describe("Create Launchpad (escrow-derived saleAmount)", function () {
    it("derives saleAmount from the factory escrow and marks it consumed", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, tokenFactory } = fixture;

      const { tokenAddress, saleAmount } = await issueTokenAndCreateLaunchpad(fixture);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(info.tokenAddress, getAddress(tokenAddress));
      assert.strictEqual(info.saleAmount, saleAmount);
      assert.strictEqual(info.tokenPrice, TOKEN_PRICE);
      assert.strictEqual(info.status, 1); // Preparing

      const [, , consumed] = (await tokenFactory.read.getEscrowInfo([tokenAddress])) as [
        bigint,
        bigint,
        boolean,
      ];
      assert.strictEqual(consumed, true);
      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), saleAmount);
    });

    it("the launchpad actually holds the escrowed tokens (no approve/transferFrom needed)", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, viem } = fixture;

      const { tokenAddress, saleAmount } = await issueTokenAndCreateLaunchpad(fixture);
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      assert.strictEqual(await token.read.balanceOf([launchpad.address]), saleAmount);
    });

    it("should reject a caller who is neither the business nor the owner", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const {
        launchpad,
        tokenFactory,
        business,
        usdt,
        platformTreasury,
        publicClient,
        chainId,
        user1,
      } = fixture;

      const ratios = buildRatios({
        launchpadBp: 9999,
        liquidityBp: 1,
        ownerBp: 0,
        liquidityRecipient: platformTreasury.account.address,
      });
      const { tokenAddress } = await issueTokenWithRatios({
        tokenFactory,
        business,
        publicClient,
        chainId,
        permitPrivateKey: TEST_PRIVATE_KEY,
        linkedLaunchpad: launchpad.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        ratios,
      });

      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
          { account: user1.account },
        ),
        launchpad,
        "NotBusinessOrOwner",
      );
    });

    it("should reject invalid token price", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, tokenFactory, business, usdt, platformTreasury, publicClient, chainId } =
        fixture;

      const ratios = buildRatios({
        launchpadBp: 9999,
        liquidityBp: 1,
        ownerBp: 0,
        liquidityRecipient: platformTreasury.account.address,
      });
      const { tokenAddress } = await issueTokenWithRatios({
        tokenFactory,
        business,
        publicClient,
        chainId,
        permitPrivateKey: TEST_PRIVATE_KEY,
        linkedLaunchpad: launchpad.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        ratios,
      });

      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, 0n, business.account.address, usdt.address, 0n, 0n],
          { account: business.account },
        ),
        launchpad,
        "InvalidAmount",
      );
    });

    it("should reject a token not issued by TokenFactory", async function () {
      const { launchpad, usdt, business, viem, owner } = await loadFixture(deployLaunchpadFixture);

      const randomToken = await viem.deployContract("USDT", [owner.account.address, 18]);

      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [randomToken.address, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
          { account: business.account },
        ),
        launchpad,
        "TokenNotFromFactory",
      );
    });

    it("should reject a second createLaunchpad for the same token (escrow already consumed)", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, business, usdt } = fixture;

      const { tokenAddress } = await issueTokenAndCreateLaunchpad(fixture);

      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
          { account: business.account },
        ),
        launchpad,
        "NoEscrowAvailable",
      );
    });

    it("should reject an unaccepted payment token", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const {
        launchpad,
        tokenFactory,
        business,
        platformTreasury,
        publicClient,
        chainId,
        viem,
        owner,
      } = fixture;

      const ratios = buildRatios({
        launchpadBp: 9999,
        liquidityBp: 1,
        ownerBp: 0,
        liquidityRecipient: platformTreasury.account.address,
      });
      const { tokenAddress } = await issueTokenWithRatios({
        tokenFactory,
        business,
        publicClient,
        chainId,
        permitPrivateKey: TEST_PRIVATE_KEY,
        linkedLaunchpad: launchpad.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        ratios,
      });

      const otherPaymentToken = await viem.deployContract("USDT", [owner.account.address, 18]);

      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, TOKEN_PRICE, business.account.address, otherPaymentToken.address, 0n, 0n],
          { account: business.account },
        ),
        launchpad,
        "PaymentTokenNotAccepted",
      );
    });

    // C-1: createLaunchpad must authenticate against the factory-recorded issuer, never the
    // caller-supplied _businessAccount. Fail-before/pass-after exploit repro: prior to the fix,
    // an attacker front-running the real issuer's createLaunchpad with _businessAccount ==
    // attacker would become launchpad.businessAccount, later pocketing the issuer's escrow.
    it("[C-1] should reject an attacker claiming _businessAccount = attacker on a victim's issued token", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, tokenFactory, business, usdt, platformTreasury, publicClient, chainId, user1 } =
        fixture;

      const ratios = buildRatios({
        launchpadBp: 9999,
        liquidityBp: 1,
        ownerBp: 0,
        liquidityRecipient: platformTreasury.account.address,
      });
      const { tokenAddress } = await issueTokenWithRatios({
        tokenFactory,
        business,
        publicClient,
        chainId,
        permitPrivateKey: TEST_PRIVATE_KEY,
        linkedLaunchpad: launchpad.address,
        name: "VictimToken",
        symbol: "VIC",
        totalSupply: TOTAL_SUPPLY,
        ratios,
      });

      // Attacker (user1) front-runs with _businessAccount = themselves, not the real issuer.
      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, TOKEN_PRICE, user1.account.address, usdt.address, 0n, 0n],
          { account: user1.account },
        ),
        launchpad,
        "NotTokenIssuer",
      );

      // Happy path unchanged: the real issuer (business) still succeeds.
      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );
      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(info.businessAccount, getAddress(business.account.address));
    });

    it("[C-1] should reject the owner passing a _businessAccount that isn't the real issuer", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, tokenFactory, business, usdt, platformTreasury, publicClient, chainId, user1, owner } =
        fixture;

      const ratios = buildRatios({
        launchpadBp: 9999,
        liquidityBp: 1,
        ownerBp: 0,
        liquidityRecipient: platformTreasury.account.address,
      });
      const { tokenAddress } = await issueTokenWithRatios({
        tokenFactory,
        business,
        publicClient,
        chainId,
        permitPrivateKey: TEST_PRIVATE_KEY,
        linkedLaunchpad: launchpad.address,
        name: "VictimToken2",
        symbol: "VIC2",
        totalSupply: TOTAL_SUPPLY,
        ratios,
      });

      // Owner (platform admin) calls createLaunchpad but passes the WRONG _businessAccount
      // (user1, not the real issuer `business`) — must still revert NotTokenIssuer.
      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, TOKEN_PRICE, user1.account.address, usdt.address, 0n, 0n],
          { account: owner.account },
        ),
        launchpad,
        "NotTokenIssuer",
      );
    });
  });

  describe("Participate in Launchpad", function () {
    async function createLaunchpadFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]); // 1 hour
      const { tokenAddress, saleAmount } = await issueTokenAndCreateLaunchpad(base);
      return { ...base, tokenAddress, saleAmount };
    }

    it("should allow participation after start time", async function () {
      const { launchpad, user1 } = await loadFixture(createLaunchpadFixture);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);

      const paymentAmount = parseUnits("100", 18);
      await launchpad.write.participate([0n, paymentAmount], { account: user1.account });

      const participant = (await launchpad.read.getParticipantInfo([
        0n,
        user1.account.address,
      ])) as ParticipantInfo;
      assert.strictEqual(participant.paymentAmount, paymentAmount);
      assert.strictEqual(participant.tokenAmount, paymentAmount); // 1:1 at TOKEN_PRICE == 1e18
    });

    it("should reject participation before start time", async function () {
      const { launchpad, user1 } = await loadFixture(createLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.participate([0n, parseUnits("100", 18)], { account: user1.account }),
        launchpad,
        "LaunchpadNotActive",
      );
    });

    it("should reject participation after end time", async function () {
      const { launchpad, user1 } = await loadFixture(createLaunchpadFixture);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.endTime + 1n);

      await assertions.revertWithCustomError(
        launchpad.write.participate([0n, parseUnits("100", 18)], { account: user1.account }),
        launchpad,
        "LaunchpadNotActive",
      );
    });

    it("should reject zero amount", async function () {
      const { launchpad, user1 } = await loadFixture(createLaunchpadFixture);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);

      await assertions.revertWithCustomError(
        launchpad.write.participate([0n, 0n], { account: user1.account }),
        launchpad,
        "InvalidAmount",
      );
    });

    it("should reject exceeding the sale amount", async function () {
      const { launchpad, user1, saleAmount } = await loadFixture(createLaunchpadFixture);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);

      await assertions.revertWithCustomError(
        launchpad.write.participate([0n, saleAmount + 1n], { account: user1.account }),
        launchpad,
        "ExceedsSaleAmount",
      );
    });
  });

  describe("Finalize Launchpad (3-way fund split + owner-vesting trigger)", function () {
    async function participatedLaunchpadFixture(ownerBp?: number) {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]); // 1 hour
      await base.launchpad.write.setLaunchpadDuration([86400n]); // 1 day
      const { tokenAddress, saleAmount, vestingWallet } = await issueTokenAndCreateLaunchpad(base, {
        ownerBp,
      });

      const info = (await base.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);

      await base.launchpad.write.participate([0n, parseUnits("1000", 18)], {
        account: base.user1.account,
      });
      await base.launchpad.write.participate([0n, parseUnits("500", 18)], {
        account: base.user2.account,
      });

      return { ...base, tokenAddress, saleAmount, vestingWallet };
    }

    it("should finalize after end time", async function () {
      const { launchpad } = await participatedLaunchpadFixture();

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.endTime + 1n);
      await launchpad.write.finalizeLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 4); // Finalized
    });

    it("returns unsold tokens to business immediately (documented behavior — no re-vesting)", async function () {
      const { launchpad, business, viem, tokenAddress } = await participatedLaunchpadFixture();

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.endTime + 1n);

      const token = await viem.getContractAt("ERC20V1", tokenAddress);
      const before = (await token.read.balanceOf([business.account.address])) as bigint;

      await launchpad.write.finalizeLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      const unsoldAmount = finalizedInfo.saleAmount - finalizedInfo.soldAmount;
      const after = (await token.read.balanceOf([business.account.address])) as bigint;
      assert.strictEqual(after - before, unsoldAmount);
    });

    it("should reject finalize before end time (unless sold out)", async function () {
      const { launchpad } = await participatedLaunchpadFixture();

      await assertions.revertWithCustomError(
        launchpad.write.finalizeLaunchpad([0n]),
        launchpad,
        "LaunchpadNotEnded",
      );
    });

    it("default fund split (unconfigured) routes 100% of post-fee proceeds to vesting", async function () {
      const { launchpad, feeRecipient, usdt } = await participatedLaunchpadFixture();

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.endTime + 1n);

      const feeBalanceBefore = (await usdt.read.balanceOf([
        feeRecipient.account.address,
      ])) as bigint;
      await launchpad.write.finalizeLaunchpad([0n]);
      const feeBalanceAfter = (await usdt.read.balanceOf([feeRecipient.account.address])) as bigint;

      const totalRaised = parseUnits("1500", 18);
      const feeRate = (await launchpad.read.launchpadFeeRate()) as bigint;
      const expectedFee = (totalRaised * feeRate) / 10000n;
      assert.strictEqual(feeBalanceAfter - feeBalanceBefore, expectedFee);

      const vesting = (await launchpad.read.getVestingInfo([0n])) as { totalAmount: bigint };
      const remaining = totalRaised - expectedFee;
      assert.strictEqual(vesting.totalAmount, remaining); // 18-decimal USDT: no decimal conversion
    });

    it("applies a configured 40/10/50 immediate/liquidity/vesting fund split", async function () {
      const base = await deployLaunchpadFixture();
      const { launchpad, business, feeRecipient, platformTreasury, usdt, owner, user1, user2 } =
        base;
      await launchpad.write.setPreparationTime([3600n]);
      await launchpad.write.setLaunchpadDuration([86400n]);

      // Timelocked liquidity-recipient change FIRST (advances chain time 2 days), THEN
      // createLaunchpad (so its startTime is computed relative to the already-advanced
      // clock and stays in the future).
      await launchpad.write.proposeLiquidityRecipientChange([platformTreasury.account.address], {
        account: owner.account,
      });
      await time.increase(2n * 24n * 60n * 60n);
      await launchpad.write.executeLiquidityRecipientChange([], { account: owner.account });

      await issueTokenAndCreateLaunchpad(base);

      // Per-launchpad fund-split override MUST be set while still Preparing (before startTime).
      await launchpad.write.setLaunchpadFundSplit([0n, 4000n, 1000n, 5000n], {
        account: business.account,
      });

      const infoBefore = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(infoBefore.startTime);
      await launchpad.write.participate([0n, parseUnits("1000", 18)], { account: user1.account });
      await launchpad.write.participate([0n, parseUnits("500", 18)], { account: user2.account });

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.endTime + 1n);

      const businessBefore = (await usdt.read.balanceOf([business.account.address])) as bigint;
      const liquidityBefore = (await usdt.read.balanceOf([
        platformTreasury.account.address,
      ])) as bigint;

      await launchpad.write.finalizeLaunchpad([0n]);

      const totalRaised = parseUnits("1500", 18);
      const feeRate = (await launchpad.read.launchpadFeeRate()) as bigint;
      const remaining = totalRaised - (totalRaised * feeRate) / 10000n;
      const expectedImmediate = (remaining * 4000n) / 10000n;
      const expectedLiquidity = (remaining * 1000n) / 10000n;
      const expectedVesting = remaining - expectedImmediate - expectedLiquidity;

      const businessAfter = (await usdt.read.balanceOf([business.account.address])) as bigint;
      const liquidityAfter = (await usdt.read.balanceOf([
        platformTreasury.account.address,
      ])) as bigint;

      assert.strictEqual(businessAfter - businessBefore, expectedImmediate);
      assert.strictEqual(liquidityAfter - liquidityBefore, expectedLiquidity);

      const vesting = (await launchpad.read.getVestingInfo([0n])) as { totalAmount: bigint };
      assert.strictEqual(vesting.totalAmount, expectedVesting);
      void feeRecipient;
    });

    it("triggers Owner Vesting exactly once on finalize (idempotent-by-construction)", async function () {
      const { launchpad, tokenAddress, vestingWallet, viem } =
        await participatedLaunchpadFixture(1000); // 10% OWNER bucket this time

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.endTime + 1n);

      const wallet = await viem.getContractAt("TokenVestingWallet", vestingWallet);
      assert.strictEqual(await wallet.read.started(), false);

      await launchpad.write.finalizeLaunchpad([0n]);

      assert.strictEqual(await launchpad.read.ownerVestingTrigger([0n]), true);
      assert.strictEqual(await wallet.read.started(), true);
      void tokenAddress;
    });

    it("snapshots the vesting schedule at finalize time (per-launchpad override wins)", async function () {
      const base = await deployLaunchpadFixture();
      const { launchpad, business, user1, user2 } = base;
      await launchpad.write.setPreparationTime([3600n]);
      await launchpad.write.setLaunchpadDuration([86400n]);
      await issueTokenAndCreateLaunchpad(base);

      // Preparing-only per-launchpad schedule override — must sum to 10000.
      const customSchedule = [5000n, 0n, 0n, 5000n, 0n, 0n, 0n, 0n] as unknown as bigint[];
      await launchpad.write.setLaunchpadVestingSchedule([0n, customSchedule], {
        account: business.account,
      });

      const infoBefore = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(infoBefore.startTime);
      await launchpad.write.participate([0n, parseUnits("1000", 18)], { account: user1.account });
      await launchpad.write.participate([0n, parseUnits("500", 18)], { account: user2.account });

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.endTime + 1n);
      await launchpad.write.finalizeLaunchpad([0n]);

      const snapshot = (await launchpad.read.getLaunchpadVestingSchedule([0n])) as bigint[];
      assert.deepStrictEqual(
        snapshot.map((v) => v.toString()),
        customSchedule.map((v) => v.toString()),
      );
    });
  });

  describe("Claim Tokens", function () {
    async function finalizedLaunchpadFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await base.launchpad.write.setLaunchpadDuration([86400n]);
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(base);

      const info = (await base.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await base.launchpad.write.participate([0n, parseUnits("1000", 18)], {
        account: base.user1.account,
      });

      await time.increaseTo(info.endTime + 1n);
      await base.launchpad.write.finalizeLaunchpad([0n]);

      return { ...base, tokenAddress };
    }

    it("should allow claiming tokens after finalization", async function () {
      const { launchpad, user1, viem, tokenAddress } = await loadFixture(finalizedLaunchpadFixture);
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      await launchpad.write.claimTokens([0n], { account: user1.account });

      assert.strictEqual(
        await token.read.balanceOf([user1.account.address]),
        parseUnits("1000", 18),
      );
    });

    it("should reject double claiming", async function () {
      const { launchpad, user1 } = await loadFixture(finalizedLaunchpadFixture);

      await launchpad.write.claimTokens([0n], { account: user1.account });
      await assertions.revertWithCustomError(
        launchpad.write.claimTokens([0n], { account: user1.account }),
        launchpad,
        "NoTokensToClaim",
      );
    });

    it("should reject claiming for non-participant", async function () {
      const { launchpad, user2 } = await loadFixture(finalizedLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.claimTokens([0n], { account: user2.account }),
        launchpad,
        "NoTokensToClaim",
      );
    });
  });

  describe("C-2: recoverStuckTokens cannot drain sold-but-unclaimed tokens", function () {
    async function partialSaleFinalizedFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await base.launchpad.write.setLaunchpadDuration([86400n]);
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(base);

      const info = (await base.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      const soldAmount = parseUnits("1000", 18);
      await base.launchpad.write.participate([0n, soldAmount], { account: base.user1.account });

      await time.increaseTo(info.endTime + 1n);
      await base.launchpad.write.finalizeLaunchpad([0n]);

      return { ...base, tokenAddress, soldAmount };
    }

    // Fail-before/pass-after exploit repro: prior to the fix, finalize decremented the
    // FULL saleAmount from the lock (not just unsoldAmount), so the sold-but-unclaimed
    // tokens were unlocked and recoverStuckTokens could drain them.
    it("[C-2] recoverStuckTokens reverts on the sold-but-unclaimed balance after a partial-sale finalize", async function () {
      const { launchpad, owner, tokenAddress, soldAmount } = await loadFixture(
        partialSaleFinalizedFixture,
      );

      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), soldAmount);

      await assertions.revertWithCustomError(
        launchpad.write.recoverStuckTokens([tokenAddress, owner.account.address, soldAmount], {
          account: owner.account,
        }),
        launchpad,
        "TokenLockedInActiveLaunchpad",
      );
    });

    it("[C-2] investors can still claimTokens; the lock drains to zero as claims happen", async function () {
      const { launchpad, user1, viem, tokenAddress, soldAmount } = await loadFixture(
        partialSaleFinalizedFixture,
      );
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      await launchpad.write.claimTokens([0n], { account: user1.account });

      assert.strictEqual(await token.read.balanceOf([user1.account.address]), soldAmount);
      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), 0n);
    });
  });

  describe("Payment-lock + refund liveness", function () {
    async function activeParticipatedFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await base.launchpad.write.setLaunchpadDuration([86400n]);
      const { tokenAddress, saleAmount } = await issueTokenAndCreateLaunchpad(base);

      const info = (await base.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      const paymentAmount = parseUnits("1000", 18);
      await base.launchpad.write.participate([0n, paymentAmount], { account: base.user1.account });

      return { ...base, tokenAddress, saleAmount, paymentAmount, endTime: info.endTime };
    }

    const REFUND_GRACE = 14n * 24n * 60n * 60n;

    // Fail-before/pass-after exploit repro: prior to the fix, lockedPaymentAmount was only
    // credited at finalize, so in-flight `participate()` USDT was untracked and
    // recoverStuckTokens treated it as free.
    it("recoverStuckTokens cannot drain in-flight raised USDT while Active", async function () {
      const { launchpad, owner, usdt, paymentAmount } = await loadFixture(
        activeParticipatedFixture,
      );

      assert.strictEqual(await launchpad.read.lockedPaymentAmount([usdt.address]), paymentAmount);

      await assertions.revertWithCustomError(
        launchpad.write.recoverStuckTokens([usdt.address, owner.account.address, paymentAmount], {
          account: owner.account,
        }),
        launchpad,
        "TokenLockedInActiveLaunchpad",
      );
    });

    it("claimRefundAfterTimeout is RefundNotAvailable before grace, refunds after grace, and blocks double refund", async function () {
      const { launchpad, usdt, user1, paymentAmount, endTime } = await loadFixture(
        activeParticipatedFixture,
      );

      await assertions.revertWithCustomError(
        launchpad.write.claimRefundAfterTimeout([0n], { account: user1.account }),
        launchpad,
        "RefundNotAvailable",
      );

      await time.increaseTo(endTime + REFUND_GRACE + 1n);

      const before = (await usdt.read.balanceOf([user1.account.address])) as bigint;
      await launchpad.write.claimRefundAfterTimeout([0n], { account: user1.account });
      const after = (await usdt.read.balanceOf([user1.account.address])) as bigint;

      assert.strictEqual(after - before, paymentAmount);
      assert.strictEqual(await launchpad.read.lockedPaymentAmount([usdt.address]), 0n);

      await assertions.revertWithCustomError(
        launchpad.write.claimRefundAfterTimeout([0n], { account: user1.account }),
        launchpad,
        "AlreadyRefunded",
      );
    });

    it("expireLaunchpad transitions to terminal Cancelled, returns escrow to the issuer, and a later finalize gets FinalizeWindowClosed (not AlreadyFinalized)", async function () {
      const { launchpad, business, viem, tokenAddress, saleAmount, endTime } = await loadFixture(
        activeParticipatedFixture,
      );
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      // Before grace: not yet expirable.
      await assertions.revertWithCustomError(
        launchpad.write.expireLaunchpad([0n]),
        launchpad,
        "RefundNotAvailable",
      );

      await time.increaseTo(endTime + REFUND_GRACE + 1n);

      const before = (await token.read.balanceOf([business.account.address])) as bigint;
      await launchpad.write.expireLaunchpad([0n]);
      const after = (await token.read.balanceOf([business.account.address])) as bigint;
      assert.strictEqual(after - before, saleAmount);
      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), 0n);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(info.status, 5); // Cancelled

      // the finalize-window guard runs BEFORE the status check, so a
      // finalize attempted after expireLaunchpad (still past endTime+REFUND_GRACE) must
      // revert FinalizeWindowClosed, NOT AlreadyFinalized.
      await assertions.revertWithCustomError(
        launchpad.write.finalizeLaunchpad([0n]),
        launchpad,
        "FinalizeWindowClosed",
      );
    });

    it("finalizeLaunchpad reverts FinalizeWindowClosed once past endTime + REFUND_GRACE", async function () {
      const { launchpad, endTime } = await loadFixture(activeParticipatedFixture);

      await time.increaseTo(endTime + REFUND_GRACE + 1n);

      await assertions.revertWithCustomError(
        launchpad.write.finalizeLaunchpad([0n]),
        launchpad,
        "FinalizeWindowClosed",
      );
    });
  });

  describe("Blacklist-exempt platform legs (claimTokens)", function () {
    async function finalizedLaunchpadFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await base.launchpad.write.setLaunchpadDuration([86400n]);
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(base);

      const info = (await base.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await base.launchpad.write.participate([0n, parseUnits("1000", 18)], {
        account: base.user1.account,
      });

      await time.increaseTo(info.endTime + 1n);
      await base.launchpad.write.finalizeLaunchpad([0n]);

      return { ...base, tokenAddress };
    }

    it("business blacklisting the investor does NOT block claimTokens (platform from-bypass)", async function () {
      const { launchpad, business, user1, viem, tokenAddress } = await loadFixture(
        finalizedLaunchpadFixture,
      );
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      await token.write.addToBlacklist([user1.account.address], { account: business.account });

      await launchpad.write.claimTokens([0n], { account: user1.account });
      assert.strictEqual(
        await token.read.balanceOf([user1.account.address]),
        parseUnits("1000", 18),
      );
    });

    it("business blacklisting the LaunchpadV1 address does NOT block claimTokens (platform from-bypass)", async function () {
      const { launchpad, business, user1, viem, tokenAddress } = await loadFixture(
        finalizedLaunchpadFixture,
      );
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      await token.write.addToBlacklist([launchpad.address], { account: business.account });

      await launchpad.write.claimTokens([0n], { account: user1.account });
      assert.strictEqual(
        await token.read.balanceOf([user1.account.address]),
        parseUnits("1000", 18),
      );
    });
  });

  describe("Vesting (USDT, business claim)", function () {
    async function finalizedLaunchpadFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await base.launchpad.write.setLaunchpadDuration([86400n]);
      await base.launchpad.write.setVestingQuarterDuration([2592000n]); // 30 days
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(base);

      const info = (await base.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await base.launchpad.write.participate([0n, parseUnits("1000", 18)], {
        account: base.user1.account,
      });

      await time.increaseTo(info.endTime + 1n);
      await base.launchpad.write.finalizeLaunchpad([0n]);

      return { ...base, tokenAddress };
    }

    it("should allow claiming vested payment after first quarter", async function () {
      const { launchpad, usdt, business } = await loadFixture(finalizedLaunchpadFixture);

      const quarterDuration = (await launchpad.read.vestingQuarterDuration()) as bigint;
      await time.increase(quarterDuration);

      const before = (await usdt.read.balanceOf([business.account.address])) as bigint;
      await launchpad.write.claimVestedPayment([0n], { account: business.account });
      const after = (await usdt.read.balanceOf([business.account.address])) as bigint;

      assert.ok(after - before > 0n);
    });

    it("should reject claiming before any vesting unlocks", async function () {
      const { launchpad, business } = await loadFixture(finalizedLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.claimVestedPayment([0n], { account: business.account }),
        launchpad,
        "NothingToClaim",
      );
    });

    it("should reject a non-business caller", async function () {
      const { launchpad, user1 } = await loadFixture(finalizedLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.claimVestedPayment([0n], { account: user1.account }),
        launchpad,
        "NoVestingFound",
      );
    });
  });

  describe("Cancel Launchpad", function () {
    it("should allow cancelling a preparing launchpad", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(fixture);

      await fixture.launchpad.write.cancelLaunchpad([0n]);

      const info = (await fixture.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(info.status, 5); // Cancelled
      void tokenAddress;
    });

    it("should return the escrowed tokens to business after cancellation", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { tokenAddress, saleAmount } = await issueTokenAndCreateLaunchpad(fixture);
      const token = await fixture.viem.getContractAt("ERC20V1", tokenAddress);

      assert.strictEqual(await token.read.balanceOf([fixture.business.account.address]), 0n);

      await fixture.launchpad.write.cancelLaunchpad([0n]);

      assert.strictEqual(
        await token.read.balanceOf([fixture.business.account.address]),
        saleAmount,
      );
      assert.strictEqual(await fixture.launchpad.read.lockedTokenAmount([tokenAddress]), 0n);
    });

    it("should reject cancelling an Active launchpad", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      await fixture.launchpad.write.setPreparationTime([3600n]);
      await issueTokenAndCreateLaunchpad(fixture);

      const info = (await fixture.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      // Status only flips Preparing -> Active inside `participate()` — time alone
      // does not transition it.
      await fixture.launchpad.write.participate([0n, parseUnits("10", 18)], {
        account: fixture.user1.account,
      });

      await assertions.revertWithCustomError(
        fixture.launchpad.write.cancelLaunchpad([0n]),
        fixture.launchpad,
        "LaunchpadNotActive",
      );
    });
  });

  describe("Refund", function () {
    async function cancelledWithParticipantsFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await issueTokenAndCreateLaunchpad(base);

      const info = (await base.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await base.launchpad.write.participate([0n, parseUnits("1000", 18)], {
        account: base.user1.account,
      });

      // cancelLaunchpad only works from Preparing — go back before start via a fresh
      // launchpad instead: cancel requires Preparing status, but participate flips it
      // to Active. Use owner.write.cancelLaunchpad while still Preparing is impossible
      // once Active, so this fixture demonstrates refund is unreachable post-Active —
      // documented via the "should reject" test below instead.
      return { ...base };
    }

    it("cancelLaunchpad is Preparing-only — refund path requires cancelling before any participation", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, user1 } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);

      await launchpad.write.cancelLaunchpad([0n]);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(info.status, 5); // Cancelled

      // No participants (cancelled pre-start) — refund has nothing to pay out.
      await assertions.revertWithCustomError(
        launchpad.write.refund([0n], { account: user1.account }),
        launchpad,
        "InvalidAmount",
      );
    });

    it("batchRefund reverts RefundNotAvailable when the launchpad is not Cancelled", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, user1 } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);

      await assertions.revertWithCustomError(
        launchpad.write.batchRefund([0n, [user1.account.address]]),
        launchpad,
        "RefundNotAvailable",
      );
      void cancelledWithParticipantsFixture;
    });
  });

  describe("Admin Functions", function () {
    it("should update fee rate", async function () {
      const { launchpad } = await loadFixture(deployLaunchpadFixture);
      await launchpad.write.setLaunchpadFeeRate([500n]);
      assert.strictEqual(await launchpad.read.launchpadFeeRate(), 500n);
    });

    it("should reject fee rate above maximum", async function () {
      const { launchpad } = await loadFixture(deployLaunchpadFixture);
      await assertions.revertWithCustomError(
        launchpad.write.setLaunchpadFeeRate([1001n]),
        launchpad,
        "InvalidFeeRate",
      );
    });

    it("should pause and unpause", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad } = fixture;

      await launchpad.write.pause();
      await assertions.revert(issueTokenAndCreateLaunchpad(fixture));

      await launchpad.write.unpause();
      await issueTokenAndCreateLaunchpad(fixture);
      assert.strictEqual(await launchpad.read.launchpadCounter(), 1n);
    });

    it("should reject non-owner admin calls", async function () {
      const { launchpad, user1 } = await loadFixture(deployLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.setLaunchpadFeeRate([500n], { account: user1.account }),
        launchpad,
        "OwnableUnauthorizedAccount",
      );
      await assertions.revertWithCustomError(
        launchpad.write.pause([], { account: user1.account }),
        launchpad,
        "OwnableUnauthorizedAccount",
      );
    });
  });

  describe("Raised-funds 3-way split — guardrails", function () {
    it("should reject a per-launchpad fund split that doesn't sum to 10000", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, business } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);

      await assertions.revertWithCustomError(
        launchpad.write.setLaunchpadFundSplit([0n, 4000n, 1000n, 4999n], {
          account: business.account,
        }),
        launchpad,
        "InvalidFundSplit",
      );
    });

    it("should reject a global fund-split proposal that doesn't sum to 10000", async function () {
      const { launchpad, owner } = await loadFixture(deployLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.proposeFundSplitChange([4000n, 1000n, 4999n], { account: owner.account }),
        launchpad,
        "InvalidFundSplit",
      );
    });

    it("global fund-split change is timelocked (2 days) and rejects early execution", async function () {
      const { launchpad, owner } = await loadFixture(deployLaunchpadFixture);

      await launchpad.write.proposeFundSplitChange([4000n, 1000n, 5000n], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        launchpad.write.executeFundSplitChange([], { account: owner.account }),
        launchpad,
        "TimelockNotReady",
      );

      await time.increase(2n * 24n * 60n * 60n);
      await launchpad.write.executeFundSplitChange([], { account: owner.account });

      assert.strictEqual(await launchpad.read.immediateRate(), 4000n);
      assert.strictEqual(await launchpad.read.liquidityRate(), 1000n);
      assert.strictEqual(await launchpad.read.vestingRate(), 5000n);
    });

    it("liquidity recipient change is timelocked (2 days)", async function () {
      const { launchpad, owner, user1 } = await loadFixture(deployLaunchpadFixture);

      await launchpad.write.proposeLiquidityRecipientChange([user1.account.address], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        launchpad.write.executeLiquidityRecipientChange([], { account: owner.account }),
        launchpad,
        "TimelockNotReady",
      );

      await time.increase(2n * 24n * 60n * 60n);
      await launchpad.write.executeLiquidityRecipientChange([], { account: owner.account });
      assert.strictEqual(
        await launchpad.read.liquidityRecipient(),
        getAddress(user1.account.address),
      );
    });
  });

  describe("Investor Token Vesting (optional per-launchpad config)", function () {
    it("investors claim 100% immediately when no investor vesting config is set", async function () {
      const fixture = await deployLaunchpadFixture();
      await fixture.launchpad.write.setPreparationTime([3600n]);
      await fixture.launchpad.write.setLaunchpadDuration([86400n]);
      await issueTokenAndCreateLaunchpad(fixture);

      const info = (await fixture.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await fixture.launchpad.write.participate([0n, parseUnits("1000", 18)], {
        account: fixture.user1.account,
      });

      await time.increaseTo(info.endTime + 1n);
      await fixture.launchpad.write.finalizeLaunchpad([0n]);

      const claimable = (await fixture.launchpad.read.getClaimableTokens([
        0n,
        fixture.user1.account.address,
      ])) as bigint;
      assert.strictEqual(claimable, parseUnits("1000", 18));
    });

    it("setInvestorVesting locks claims until the lockup elapses", async function () {
      const fixture = await deployLaunchpadFixture();
      const { launchpad, business, user1 } = fixture;
      await launchpad.write.setPreparationTime([3600n]);
      await launchpad.write.setLaunchpadDuration([86400n]);
      await issueTokenAndCreateLaunchpad(fixture);

      await launchpad.write.setInvestorVesting([0n, 30n * 24n * 60n * 60n, 0n, 0n], {
        account: business.account,
      });

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, parseUnits("1000", 18)], { account: user1.account });

      await time.increaseTo(info.endTime + 1n);
      await launchpad.write.finalizeLaunchpad([0n]);

      // Still inside the 30-day lockup — nothing claimable yet.
      const claimableBefore = (await launchpad.read.getClaimableTokens([
        0n,
        user1.account.address,
      ])) as bigint;
      assert.strictEqual(claimableBefore, 0n);

      await time.increase(30n * 24n * 60n * 60n + 1n);
      const claimableAfter = (await launchpad.read.getClaimableTokens([
        0n,
        user1.account.address,
      ])) as bigint;
      assert.strictEqual(claimableAfter, parseUnits("1000", 18));
    });
  });

  describe("View Functions", function () {
    it("getParticipants / getParticipantCount / isParticipant", async function () {
      const fixture = await deployLaunchpadFixture();
      await fixture.launchpad.write.setPreparationTime([3600n]);
      await issueTokenAndCreateLaunchpad(fixture);

      const info = (await fixture.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await fixture.launchpad.write.participate([0n, parseUnits("100", 18)], {
        account: fixture.user1.account,
      });

      assert.strictEqual(await fixture.launchpad.read.getParticipantCount([0n]), 1n);
      assert.strictEqual(
        await fixture.launchpad.read.isParticipant([0n, fixture.user1.account.address]),
        true,
      );
      assert.strictEqual(
        await fixture.launchpad.read.isParticipant([0n, fixture.user2.account.address]),
        false,
      );

      const participants = (await fixture.launchpad.read.getParticipants([
        0n,
        0n,
        10n,
      ])) as Address[];
      assert.strictEqual(participants.length, 1);
      assert.strictEqual(getAddress(participants[0]), getAddress(fixture.user1.account.address));
    });

    it("deprecated view functions revert DeprecatedFunction", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      await issueTokenAndCreateLaunchpad(fixture);

      await assertions.revertWithCustomError(
        (fixture.launchpad.read as any).getCurrentQuarter([0n]),
        fixture.launchpad,
        "DeprecatedFunction",
      );
    });
  });

  describe("Timelocked UUPS Upgrade", function () {
    const DELAY = 48n * 60n * 60n;

    it("requestUpgrade -> immediate upgrade reverts UpgradeNotReady -> after 48h succeeds", async function () {
      const { launchpad, owner, viem } = await loadFixture(deployLaunchpadFixture);
      const newImpl = await viem.deployContract("LaunchpadV1", []);

      await launchpad.write.requestUpgrade([newImpl.address], { account: owner.account });
      assert.strictEqual(
        getAddress((await launchpad.read.pendingImplementation()) as Address),
        getAddress(newImpl.address),
      );

      await assertions.revertWithCustomError(
        launchpad.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account }),
        launchpad,
        "UpgradeNotReady",
      );

      await time.increase(DELAY + 1n);
      await launchpad.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account });

      assert.strictEqual(
        getAddress((await launchpad.read.pendingImplementation()) as Address),
        getAddress(zeroAddress),
      );
    });

    it("mismatched implementation reverts ImplementationMismatch", async function () {
      const { launchpad, owner, viem } = await loadFixture(deployLaunchpadFixture);
      const implA = await viem.deployContract("LaunchpadV1", []);
      const implB = await viem.deployContract("LaunchpadV1", []);

      await launchpad.write.requestUpgrade([implA.address], { account: owner.account });
      await time.increase(DELAY + 1n);

      await assertions.revertWithCustomError(
        launchpad.write.upgradeToAndCall([implB.address, "0x"], { account: owner.account }),
        launchpad,
        "ImplementationMismatch",
      );
    });

    it("upgrade without a request reverts NoPendingUpgrade", async function () {
      const { launchpad, owner, viem } = await loadFixture(deployLaunchpadFixture);
      const impl = await viem.deployContract("LaunchpadV1", []);

      await assertions.revertWithCustomError(
        launchpad.write.upgradeToAndCall([impl.address, "0x"], { account: owner.account }),
        launchpad,
        "NoPendingUpgrade",
      );
    });

    it("cancelUpgrade clears the pending request", async function () {
      const { launchpad, owner, viem } = await loadFixture(deployLaunchpadFixture);
      const impl = await viem.deployContract("LaunchpadV1", []);

      await launchpad.write.requestUpgrade([impl.address], { account: owner.account });
      await launchpad.write.cancelUpgrade({ account: owner.account });

      assert.strictEqual(
        getAddress((await launchpad.read.pendingImplementation()) as Address),
        getAddress(zeroAddress),
      );

      await time.increase(DELAY + 1n);
      await assertions.revertWithCustomError(
        launchpad.write.upgradeToAndCall([impl.address, "0x"], { account: owner.account }),
        launchpad,
        "NoPendingUpgrade",
      );
    });
  });
});
