import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseUnits,
  getAddress,
  encodeFunctionData,
  toFunctionSelector,
  zeroAddress,
  Address,
  Hex,
} from "viem";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import { privateKeyToAccount } from "viem/accounts";
import {
  deployTokenFactoryCore,
  configureDefaultAllocationGuides,
  setLinkedLaunchpad,
  setEscrowTimeout,
  setResaleWait,
  issueTokenWithRatios,
  buildRatios,
} from "./tokenFactoryHelpers.js";

// resale-wait cooldown used across cancel/expire/resale fixtures below.
const RESALE_WAIT_SECONDS = 3n * 24n * 60n * 60n; // 3 days

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
 * LaunchpadV1: createLaunchpad now derives `saleAmount`
 * from the TokenFactory-escrowed LAUNCHPAD bucket (O2, no caller-supplied amount / no
 * approve+transferFrom), and finalizeLaunchpad splits the post-fee raise 3 ways
 * (immediate/liquidity/vesting — O3) plus triggers the per-token Owner Vesting wallet
 * (O4b). This file owns the Launchpad-side business logic; TokenFactory's own escrow/
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

    const launchpadImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
    const launchpadImpl = await viem.deployContract("LaunchpadV1", [], {
      libraries: { LaunchpadMathLib: launchpadImplMathLib.address },
    });
    const initData = encodeFunctionData({
      abi: launchpadImpl.abi,
      functionName: "initialize",
      args: [
        tokenFactory.address,
        usdt.address,
        feeRecipient.account.address,
        platformTreasury.account.address,
      ],
    });
    const proxy = await viem.deployContract("ERC1967Proxy", [launchpadImpl.address, initData]);
    const launchpad = await viem.getContractAt("LaunchpadV1", proxy.address);

    await setLinkedLaunchpad(tokenFactory, owner, launchpad.address);
    // Escrow timeout must be set before issuing a token with a LAUNCHPAD bucket (fail-closed).
    await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n);
    // resale-wait must be set before any cancel/expire path can restore escrow
    // (TokenFactory.restoreEscrow fail-closed reverts ResaleWaitNotConfigured otherwise).
    await setResaleWait(tokenFactory, owner, RESALE_WAIT_SECONDS);

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
   *
   * `launchpadBp` is independently overridable (decoupled from `ownerBp`, default
   * `9999 - ownerBp` preserves the original behavior) so -affected fixtures can
   * shrink `saleAmount` to something a small USDT participation can actually clear
   * the softcap floor (20%) of, without touching the shared
   * `tokenFactoryHelpers.ts` (that file belongs to the TokenFactory/vesting work, out
   * of scope here) — `configureDefaultAllocationGuides` already leaves every bucket's
   * guide permissive (0..10000 / 1..10000), so any split summing to 10000 with
   * `liquidityBp >= 1` is valid.
   *
   * m-8 (adversarial review): the shrink is inherently a test-fixture artifact, not a
   * realistic distribution — a fixed 1000-1500 USDT test participation can never
   * clear even a 20% floor against this contract's realistic ~9999/1 launchpad/
   * liquidity split (saleAmount would be ~999,900 USDT, requiring a ~200,000 USDT
   * participation to clear 20%, which would ripple into every hardcoded totalRaised
   * assertion in these fixtures). Each override below is sized to the SMALLEST shrink
   * that clears the CURRENT 20% floor with a comfortable (>25%) margin — bigger
   * (closer to realistic) than the 30%-floor-era values this review flagged, but full
   * 9999/1 realism is not achievable here without bumping participation amounts.
   */
  async function issueTokenAndCreateLaunchpad(
    fixture: Awaited<ReturnType<typeof deployLaunchpadFixture>>,
    overrides?: { ownerBp?: number; launchpadBp?: number; startTime?: bigint; endTime?: bigint },
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
    const launchpadBp = overrides?.launchpadBp ?? 9999 - ownerBp;
    const liquidityBp = 10000 - launchpadBp - ownerBp;
    const ratios = buildRatios({
      launchpadBp,
      liquidityBp,
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
      const { launchpad, tokenFactory, feeRecipient, platformTreasury, owner } =
        await loadFixture(deployLaunchpadFixture);

      assert.strictEqual(await launchpad.read.owner(), getAddress(owner.account.address));
      assert.strictEqual(await launchpad.read.tokenFactory(), getAddress(tokenFactory.address));
      assert.strictEqual(
        await launchpad.read.feeRecipient(),
        getAddress(feeRecipient.account.address),
      );
      assert.strictEqual(await launchpad.read.launchpadFeeRate(), 500n); // 5% — canonical tokenomics spec
      // Canonical raised-funds split (post-fee remainder bp) — see LaunchpadV1.initialize
      // NatSpec for the fee-first-then-split-remainder rounding derivation.
      assert.strictEqual(await launchpad.read.immediateRate(), 1789n); // ~16.9955% of total
      assert.strictEqual(await launchpad.read.liquidityRate(), 1053n); // ~10.0035% of total
      assert.strictEqual(await launchpad.read.vestingRate(), 7158n); // ~68.0010% of total
      assert.strictEqual(
        await launchpad.read.liquidityRecipient(),
        getAddress(platformTreasury.account.address),
      );
    });

    it("should reject zero addresses in initialize", async function () {
      const { usdt, feeRecipient, platformTreasury, viem } =
        await loadFixture(deployLaunchpadFixture);

      const launchpadImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const launchpadImpl = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: launchpadImplMathLib.address },
      });
      const initDataZeroFactory = encodeFunctionData({
        abi: launchpadImpl.abi,
        functionName: "initialize",
        args: [
          zeroAddress,
          usdt.address,
          feeRecipient.account.address,
          platformTreasury.account.address,
        ],
      });

      await assertions.revert(
        viem.deployContract("ERC1967Proxy", [launchpadImpl.address, initDataZeroFactory]),
      );

      const initDataZeroLiquidityRecipient = encodeFunctionData({
        abi: launchpadImpl.abi,
        functionName: "initialize",
        args: [
          launchpadImpl.address, // any non-zero placeholder — this call must revert regardless
          usdt.address,
          feeRecipient.account.address,
          zeroAddress,
        ],
      });

      await assertions.revert(
        viem.deployContract("ERC1967Proxy", [
          launchpadImpl.address,
          initDataZeroLiquidityRecipient,
        ]),
      );
    });
  });

  describe("Create Launchpad (O2 — escrow-derived saleAmount)", function () {
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

    it("[m-1] should reject a token price above MAX_TOKEN_PRICE (unbounded price could overflow _targetRaiseAmount's mulDiv at finalize, adversarial review)", async function () {
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

      const maxPrice = (await launchpad.read.MAX_TOKEN_PRICE()) as bigint;

      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, maxPrice + 1n, business.account.address, usdt.address, 0n, 0n],
          { account: business.account },
        ),
        launchpad,
        "TokenPriceTooHigh",
      );

      // Exactly at the cap is accepted.
      await launchpad.write.createLaunchpad(
        [tokenAddress, maxPrice, business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );
      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(info.tokenPrice, maxPrice);
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

    // createLaunchpad must authenticate against the factory-recorded issuer, never the
    // caller-supplied _businessAccount. Fail-before/pass-after exploit repro: prior to the fix,
    // an attacker front-running the real issuer's createLaunchpad with _businessAccount ==
    // attacker would become launchpad.businessAccount, later pocketing the issuer's escrow.
    it("should reject an attacker claiming _businessAccount = attacker on a victim's issued token", async function () {
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

    it("should reject the owner passing a _businessAccount that isn't the real issuer", async function () {
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

  describe("Finalize Launchpad (O3 — 3-way fund split + owner-vesting trigger)", function () {
    async function participatedLaunchpadFixture(ownerBp?: number) {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]); // 1 hour
      await base.launchpad.write.setLaunchpadDuration([86400n]); // 1 day
      // MIN_RAISE_BP is 2000 (20%) — shrink saleAmount to 4000 USDT
      // (launchpadBp: 40, independent of ownerBp) so the 1500 USDT raised below
      // clears the floor (37.5%) instead of finalize auto-cancelling for underfunding.
      const { tokenAddress, saleAmount, vestingWallet } = await issueTokenAndCreateLaunchpad(base, {
        ownerBp,
        launchpadBp: 40,
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

    it("default fund split (from initialize) applies the canonical fee + 3-way split", async function () {
      const { launchpad, feeRecipient, business, platformTreasury, usdt } =
        await participatedLaunchpadFixture();

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.endTime + 1n);

      const feeBalanceBefore = (await usdt.read.balanceOf([
        feeRecipient.account.address,
      ])) as bigint;
      const businessBalanceBefore = (await usdt.read.balanceOf([
        business.account.address,
      ])) as bigint;
      // deployLaunchpadFixture sets liquidityRecipient == platformTreasury (see that fixture).
      const liquidityBalanceBefore = (await usdt.read.balanceOf([
        platformTreasury.account.address,
      ])) as bigint;

      await launchpad.write.finalizeLaunchpad([0n]);

      const feeBalanceAfter = (await usdt.read.balanceOf([feeRecipient.account.address])) as bigint;
      const businessBalanceAfter = (await usdt.read.balanceOf([
        business.account.address,
      ])) as bigint;
      const liquidityBalanceAfter = (await usdt.read.balanceOf([
        platformTreasury.account.address,
      ])) as bigint;

      const totalRaised = parseUnits("1500", 18);
      const feeRate = (await launchpad.read.launchpadFeeRate()) as bigint;
      const expectedFee = (totalRaised * feeRate) / 10000n;
      assert.strictEqual(feeBalanceAfter - feeBalanceBefore, expectedFee);

      const remaining = totalRaised - expectedFee;
      const immediateRate = (await launchpad.read.immediateRate()) as bigint;
      const liquidityRate = (await launchpad.read.liquidityRate()) as bigint;
      const expectedImmediate = (remaining * immediateRate) / 10000n;
      const expectedLiquidity = (remaining * liquidityRate) / 10000n;
      // Matches finalizeLaunchpad's own rounding: the remainder (not a separately
      // computed vestingRate share) rolls into vesting so the 3-way split sums exactly.
      const expectedVesting = remaining - expectedImmediate - expectedLiquidity;

      assert.strictEqual(businessBalanceAfter - businessBalanceBefore, expectedImmediate);
      assert.strictEqual(liquidityBalanceAfter - liquidityBalanceBefore, expectedLiquidity);

      const vesting = (await launchpad.read.getVestingInfo([0n])) as { totalAmount: bigint };
      assert.strictEqual(vesting.totalAmount, expectedVesting); // 18-decimal USDT: no decimal conversion
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

      // MIN_RAISE_BP is 2000 (20%) — shrink saleAmount to 4000 USDT so
      // the 1500 USDT raised below (37.5%) clears the floor.
      await issueTokenAndCreateLaunchpad(base, { launchpadBp: 40 });

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

    it("snapshots the business vesting schedule at CREATE time (per-launchpad override, set pre-start, still wins)", async function () {
      const base = await deployLaunchpadFixture();
      const { launchpad, business, user1, user2 } = base;
      await launchpad.write.setPreparationTime([3600n]);
      await launchpad.write.setLaunchpadDuration([86400n]);
      // shrink saleAmount to 4000 USDT so the 1500 USDT raised below (37.5%)
      // clears the 20% floor and finalize actually reaches Finalized.
      await issueTokenAndCreateLaunchpad(base, { launchpadBp: 40 });

      // Preparing-only per-launchpad schedule override — bps must sum to 10000.
      const customSchedule = {
        vestingInterval: 30n * 24n * 60n * 60n,
        firstPeriodAtZero: false,
        bps: [5000n, 5000n],
      };
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

      const snapshot = (await launchpad.read.getLaunchpadVestingSchedule([0n])) as {
        vestingInterval: bigint;
        firstPeriodAtZero: boolean;
        bps: bigint[];
      };
      assert.strictEqual(snapshot.vestingInterval, customSchedule.vestingInterval);
      assert.strictEqual(snapshot.firstPeriodAtZero, false);
      assert.deepStrictEqual(snapshot.bps, customSchedule.bps);
    });

    it("fix: changing the GLOBAL default schedule after a launchpad is created does NOT change that launchpad's already-snapshotted schedule", async function () {
      const base = await deployLaunchpadFixture();
      const { launchpad, owner } = base;
      await launchpad.write.setPreparationTime([3600n]);
      await launchpad.write.setLaunchpadDuration([86400n]);

      const defaultBefore = (await launchpad.read.getDefaultVestingSchedule()) as {
        vestingInterval: bigint;
        firstPeriodAtZero: boolean;
        bps: bigint[];
      };

      // No per-launchpad override — this launchpad relies entirely on whatever the
      // global default is AT CREATE TIME.
      await issueTokenAndCreateLaunchpad(base, { launchpadBp: 40 });

      // Now change the GLOBAL default (e.g. while preparing an unrelated second sale) —
      // this must NOT retroactively change launchpad 0's already-snapshotted schedule.
      await launchpad.write.setDefaultVestingSchedule(
        [{ vestingInterval: 7n * 24n * 60n * 60n, firstPeriodAtZero: true, bps: [10000n] }],
        { account: owner.account },
      );

      const snapshot = (await launchpad.read.getLaunchpadVestingSchedule([0n])) as {
        vestingInterval: bigint;
        firstPeriodAtZero: boolean;
        bps: bigint[];
      };
      assert.strictEqual(snapshot.vestingInterval, defaultBefore.vestingInterval);
      assert.strictEqual(snapshot.firstPeriodAtZero, defaultBefore.firstPeriodAtZero);
      assert.deepStrictEqual(snapshot.bps, defaultBefore.bps);
    });
  });

  describe("Claim Tokens", function () {
    async function finalizedLaunchpadFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await base.launchpad.write.setLaunchpadDuration([86400n]);
      // MIN_RAISE_BP is 2000 (20%) — shrink saleAmount to 3000 USDT so
      // the 1000 USDT raised below (33.3%) clears the floor.
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(base, { launchpadBp: 30 });

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

  describe("recoverStuckTokens cannot drain sold-but-unclaimed tokens", function () {
    async function partialSaleFinalizedFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await base.launchpad.write.setLaunchpadDuration([86400n]);
      // MIN_RAISE_BP is 2000 (20%) — shrink saleAmount to 4000 USDT so
      // the 1000 USDT raised below (25%) clears the floor while still leaving an
      // unsold remainder (this test is specifically about a PARTIAL sale).
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(base, { launchpadBp: 40 });

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
    it("recoverStuckTokens reverts on the sold-but-unclaimed balance after a partial-sale finalize", async function () {
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

    it("investors can still claimTokens; the lock drains to zero as claims happen", async function () {
      const { launchpad, user1, viem, tokenAddress, soldAmount } = await loadFixture(
        partialSaleFinalizedFixture,
      );
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      await launchpad.write.claimTokens([0n], { account: user1.account });

      assert.strictEqual(await token.read.balanceOf([user1.account.address]), soldAmount);
      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), 0n);
    });
  });

  describe("payment-lock + refund liveness", function () {
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
      const { launchpad, owner, usdt, paymentAmount } =
        await loadFixture(activeParticipatedFixture);

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
      const { launchpad, usdt, user1, paymentAmount, endTime } =
        await loadFixture(activeParticipatedFixture);

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

    it("expireLaunchpad transitions to terminal Cancelled, returns escrow to TokenFactory (resale-eligible, not to the business), and a later finalize gets FinalizeWindowClosed (not AlreadyFinalized)", async function () {
      const { launchpad, business, tokenFactory, viem, tokenAddress, saleAmount, endTime } =
        await loadFixture(activeParticipatedFixture);
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      // Before grace: not yet expirable.
      await assertions.revertWithCustomError(
        launchpad.write.expireLaunchpad([0n]),
        launchpad,
        "RefundNotAvailable",
      );

      await time.increaseTo(endTime + REFUND_GRACE + 1n);

      const businessBefore = (await token.read.balanceOf([business.account.address])) as bigint;
      await launchpad.write.expireLaunchpad([0n]);
      const businessAfter = (await token.read.balanceOf([business.account.address])) as bigint;
      // the token no longer goes to the business on cancel — it returns to
      // TokenFactory escrow so it can be resold after resaleWaitSeconds elapses.
      assert.strictEqual(businessAfter - businessBefore, 0n);
      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), 0n);

      const [escrowAmount, , consumed] = (await tokenFactory.read.getEscrowInfo([
        tokenAddress,
      ])) as [bigint, bigint, boolean];
      assert.strictEqual(escrowAmount, saleAmount);
      assert.strictEqual(consumed, false);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(info.status, 5); // Cancelled

      // Critic MINOR-2: the finalize-window guard runs BEFORE the status check, so a
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

  describe("blacklist-exempt platform legs (claimTokens)", function () {
    async function finalizedLaunchpadFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await base.launchpad.write.setLaunchpadDuration([86400n]);
      // MIN_RAISE_BP is 2000 (20%) — shrink saleAmount to 3000 USDT so
      // the 1000 USDT raised below (33.3%) clears the floor.
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(base, { launchpadBp: 30 });

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
      const { launchpad, business, user1, viem, tokenAddress } =
        await loadFixture(finalizedLaunchpadFixture);
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      await token.write.addToBlacklist([user1.account.address], { account: business.account });

      await launchpad.write.claimTokens([0n], { account: user1.account });
      assert.strictEqual(
        await token.read.balanceOf([user1.account.address]),
        parseUnits("1000", 18),
      );
    });

    it("business blacklisting the LaunchpadV1 address does NOT block claimTokens (platform from-bypass)", async function () {
      const { launchpad, business, user1, viem, tokenAddress } =
        await loadFixture(finalizedLaunchpadFixture);
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
      // 30-day interval, same 8-period shape as the canonical default — read at
      // createLaunchpad time (below), not at finalize.
      await base.launchpad.write.setDefaultVestingSchedule([
        {
          vestingInterval: 2592000n, // 30 days
          firstPeriodAtZero: false,
          bps: [2000n, 1000n, 1000n, 2000n, 1000n, 1000n, 1000n, 1000n],
        },
      ]);
      // MIN_RAISE_BP is 2000 (20%) — shrink saleAmount to 3000 USDT so
      // the 1000 USDT raised below (33.3%) clears the floor.
      const { tokenAddress } = await issueTokenAndCreateLaunchpad(base, { launchpadBp: 30 });

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

      // Read the per-launchpad SNAPSHOT (not the global default) — this is what actually
      // governs claim timing for this sale.
      const snapshot = (await launchpad.read.getLaunchpadVestingSchedule([0n])) as {
        vestingInterval: bigint;
      };
      await time.increase(snapshot.vestingInterval);

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

    it("returns the escrowed tokens to TokenFactory escrow (not the business) after cancellation, resale-eligible after resaleWaitSeconds", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { tokenAddress, saleAmount } = await issueTokenAndCreateLaunchpad(fixture);
      const token = await fixture.viem.getContractAt("ERC20V1", tokenAddress);

      assert.strictEqual(await token.read.balanceOf([fixture.business.account.address]), 0n);

      const cancelTx = fixture.launchpad.write.cancelLaunchpad([0n]);
      await cancelTx;
      const cancelTimestamp = await time.latest();

      // the business is NOT credited — the token goes back into TokenFactory
      // escrow instead, not to the business's own wallet.
      assert.strictEqual(await token.read.balanceOf([fixture.business.account.address]), 0n);
      assert.strictEqual(await token.read.balanceOf([fixture.tokenFactory.address]), saleAmount);
      assert.strictEqual(await fixture.launchpad.read.lockedTokenAmount([tokenAddress]), 0n);

      const [escrowAmount, deadline, consumed] = (await fixture.tokenFactory.read.getEscrowInfo([
        tokenAddress,
      ])) as [bigint, bigint, boolean];
      assert.strictEqual(escrowAmount, saleAmount);
      assert.strictEqual(consumed, false);
      assert.strictEqual(deadline, cancelTimestamp + RESALE_WAIT_SECONDS);
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

  describe("resale of a cancelled sale's token", function () {
    it("[core evidence] cancel -> permissionless Owner Vesting trigger (business abandons) -> wait -> resale -> finalize succeeds — the pre-fix lock (finalize reverting AlreadyStarted) does not reproduce", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, tokenFactory, business, user1, usdt, viem } = fixture;

      // Sale #1: 5% OWNER bucket so the vesting wallet actually holds something.
      const { tokenAddress, saleAmount, vestingWallet } = await issueTokenAndCreateLaunchpad(
        fixture,
        { launchpadBp: 30, ownerBp: 500 },
      );
      const wallet = await viem.getContractAt("TokenVestingWallet", vestingWallet);

      // Sale #1 is cancelled while still Preparing — the business walks away.
      await launchpad.write.cancelLaunchpad([0n]);
      assert.strictEqual(await wallet.read.started(), false);

      // Nobody resells right away and the business never comes back: once the resale-wait
      // deadline elapses, ANYONE can unfreeze the funded Owner Vesting allocation —
      // reproducing the exact "sale #1 cancel -> vesting started" state the pre-fix bug
      // relied on, but through the permissionless TokenFactory path instead of an immediate
      // LaunchpadV1-triggered start.
      await time.increase(RESALE_WAIT_SECONDS + 1n);
      await tokenFactory.write.triggerOwnerVesting([tokenAddress], { account: user1.account });
      assert.strictEqual(await wallet.read.started(), true);

      // Sale #2 (resale): a fresh createLaunchpad for the SAME token now succeeds — the
      // escrow TokenFactory holds was restored and the wait has elapsed.
      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );
      const info1 = (await launchpad.read.getLaunchpadInfo([1n])) as LaunchpadInfo;
      assert.strictEqual(info1.saleAmount, saleAmount);

      // lockedTokenAmount must reflect the SAME real balance movement as the escrow pull —
      // back up to saleAmount again, and the token itself sits entirely in the launchpad now
      // (TokenFactory's escrow balance for this token is back to zero).
      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), saleAmount);
      const token = await viem.getContractAt("ERC20V1", tokenAddress);
      assert.strictEqual(await token.read.balanceOf([tokenFactory.address]), 0n);
      assert.strictEqual(await token.read.balanceOf([launchpad.address]), saleAmount);

      await time.increaseTo(info1.startTime);
      // 20% of MIN_RAISE_BP floor on a 3000 USDT target == 600 USDT; 1000 clears it comfortably.
      await launchpad.write.participate([1n, parseUnits("1000", 18)], { account: user1.account });

      const info1Active = (await launchpad.read.getLaunchpadInfo([1n])) as LaunchpadInfo;
      await time.increaseTo(info1Active.endTime + 1n);

      // THE critical assertion: finalize must NOT revert AlreadyStarted even though this
      // token's Owner Vesting wallet was already started by the earlier permissionless
      // trigger — `_triggerOwnerVesting`'s `started()` guard is what makes this succeed.
      await launchpad.write.finalizeLaunchpad([1n]);

      const finalized = (await launchpad.read.getLaunchpadInfo([1n])) as LaunchpadInfo;
      assert.strictEqual(finalized.status, 4); // Finalized
      assert.strictEqual(await launchpad.read.ownerVestingTrigger([1n]), true);
    });

    it("resale is rejected before resaleWaitSeconds elapses; succeeds once it does", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, business, usdt } = fixture;

      const { tokenAddress } = await issueTokenAndCreateLaunchpad(fixture, { launchpadBp: 30 });
      await launchpad.write.cancelLaunchpad([0n]);

      // Immediately after cancel: still locked.
      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
          { account: business.account },
        ),
        launchpad,
        "EscrowTimeoutNotElapsed",
      );

      // Still locked 1 second before the deadline. `time.increaseTo(X)` itself mines a block AT
      // timestamp X, so the write tx that follows lands one second later — target boundary-2 so
      // the createLaunchpad tx itself lands exactly on deadline-1 (see the analogous comment in
      // FundHolding.test.ts's upgrade-grace boundary test for this same quirk).
      const [, deadline] = (await fixture.tokenFactory.read.getEscrowInfo([tokenAddress])) as [
        bigint,
        bigint,
        boolean,
      ];
      await time.increaseTo(deadline - 2n);
      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
          { account: business.account },
        ),
        launchpad,
        "EscrowTimeoutNotElapsed",
      );

      // Exactly at (and past) the deadline: resale succeeds.
      await time.increaseTo(deadline);
      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );
      const info1 = (await launchpad.read.getLaunchpadInfo([1n])) as LaunchpadInfo;
      assert.strictEqual(info1.status, 1); // Preparing
    });

    it("a resold sale can itself exit via expireLaunchpad and cancelUnderfundedLaunchpad, restoring escrow again each time", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, tokenFactory, business, user1, usdt } = fixture;
      const REFUND_GRACE = 14n * 24n * 60n * 60n;

      const { tokenAddress, saleAmount } = await issueTokenAndCreateLaunchpad(fixture, {
        launchpadBp: 30,
      });
      await launchpad.write.cancelLaunchpad([0n]);
      await time.increase(RESALE_WAIT_SECONDS + 1n);

      // Resale #1 (launchpad id 1), then let it expire via the permissionless timeout path.
      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );
      const info1 = (await launchpad.read.getLaunchpadInfo([1n])) as LaunchpadInfo;
      await time.increaseTo(info1.endTime + REFUND_GRACE + 1n);
      await launchpad.write.expireLaunchpad([1n]);

      const [escrowAfterExpire, , consumedAfterExpire] = (await tokenFactory.read.getEscrowInfo([
        tokenAddress,
      ])) as [bigint, bigint, boolean];
      assert.strictEqual(escrowAfterExpire, saleAmount);
      assert.strictEqual(consumedAfterExpire, false);
      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), 0n);

      // Resale #2 (launchpad id 2), underfunded this time, exits via cancelUnderfundedLaunchpad.
      await time.increase(RESALE_WAIT_SECONDS + 1n);
      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );
      const info2 = (await launchpad.read.getLaunchpadInfo([2n])) as LaunchpadInfo;
      await time.increaseTo(info2.startTime);
      await launchpad.write.participate([2n, parseUnits("1", 18)], { account: user1.account }); // far under the 20% floor
      await time.increaseTo(info2.endTime + 1n);
      await launchpad.write.cancelUnderfundedLaunchpad([2n]);

      const [escrowAfterUnderfunded, , consumedAfterUnderfunded] =
        (await tokenFactory.read.getEscrowInfo([tokenAddress])) as [bigint, bigint, boolean];
      assert.strictEqual(escrowAfterUnderfunded, saleAmount);
      assert.strictEqual(consumedAfterUnderfunded, false);
      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), 0n);

      // Investor refund still pays out normally on the underfunded exit.
      await launchpad.write.refund([2n], { account: user1.account });
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
    it("should update fee rate via the timelocked propose/execute flow", async function () {
      const { launchpad } = await loadFixture(deployLaunchpadFixture);
      // Default from initialize() is already 500n (5%, canonical) — propose a
      // different value so this test actually exercises a change.
      await launchpad.write.proposeLaunchpadFeeRateChange([700n]);
      await time.increase(2n * 24n * 60n * 60n);
      await launchpad.write.executeLaunchpadFeeRateChange();
      assert.strictEqual(await launchpad.read.launchpadFeeRate(), 700n);
    });

    it("fee rate change is timelocked (2 days) and rejects early execution", async function () {
      const { launchpad, owner } = await loadFixture(deployLaunchpadFixture);

      await launchpad.write.proposeLaunchpadFeeRateChange([700n], { account: owner.account });
      await assertions.revertWithCustomError(
        launchpad.write.executeLaunchpadFeeRateChange([], { account: owner.account }),
        launchpad,
        "TimelockNotReady",
      );

      await time.increase(2n * 24n * 60n * 60n);
      await launchpad.write.executeLaunchpadFeeRateChange([], { account: owner.account });
      assert.strictEqual(await launchpad.read.launchpadFeeRate(), 700n);
    });

    it("should reject fee rate above maximum", async function () {
      const { launchpad } = await loadFixture(deployLaunchpadFixture);
      await assertions.revertWithCustomError(
        launchpad.write.proposeLaunchpadFeeRateChange([1001n]),
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
        launchpad.write.proposeLaunchpadFeeRateChange([500n], { account: user1.account }),
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

  describe("O3: raised-funds 3-way split — guardrails", function () {
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

  describe("softcap (minimum-raise) gate on finalize", function () {
    // DESIGN HISTORY (see MIN_RAISE_BP's own doc comment in the contract for the full
    // story): an earlier version of this change made the softcap governance-settable
    // (propose/execute, 2-day timelock) + per-launchpad snapshot. A later product decision
    // reverted that to a plain `constant`, to keep the audited
    // surface narrow. The owner subsequently reversed THAT decision in turn
    // The softcap is admin-adjustable again via {setSoftcapBp} — a
    // single onlyOwner setter, no timelock (justified in that function's own doc
    // comment) — but `MIN_RAISE_BP` (2000 = 20%) now acts as a hard, permanent FLOOR
    // {setSoftcapBp} cannot go below. `softcapBp` (the live default) is seeded to
    // `MIN_RAISE_BP` at `initialize`, so an operator who never calls the setter gets
    // exactly the pre-2026-08 fixed-20% behavior — every test below that doesn't touch
    // `setSoftcapBp` exercises that unchanged default path. What remains covered below
    // is the softcap's own BEHAVIOR (boundary, under/over-raise, soldOut,
    // zero-participation, owner-vesting invariant on the auto-cancel path) PLUS the new
    // admin-adjustability surface (floor enforcement, snapshot-not-live-read,
    // finalize/cancelUnderfundedLaunchpad complementarity at a non-default value).
    async function createLaunchpadFixture(ownerBp?: number) {
      const base = await deployLaunchpadFixture();
      const { launchpad } = base;
      await launchpad.write.setPreparationTime([3600n]);
      await launchpad.write.setLaunchpadDuration([86400n]);

      const { tokenAddress, saleAmount, vestingWallet } = await issueTokenAndCreateLaunchpad(base, {
        ownerBp,
      });

      const minRaiseBp = (await launchpad.read.MIN_RAISE_BP()) as bigint;

      // TOKEN_PRICE == 1e18 and USDT here is 18-decimal, so scaleFactor == tokenPrice
      // and targetRaise == saleAmount numerically (see _targetRaiseAmount). Confirmed
      // divisible by 10000 for this fixture's saleAmount, so the threshold below is an
      // EXACT integer with no rounding slop. Uses MIN_RAISE_BP (not a fresh
      // `softcapBp()` read) because every fixture caller here relies on the default
      // (never-configured) softcap, which `initialize` seeds to exactly MIN_RAISE_BP.
      const targetRaise = saleAmount;
      const requiredRaise = (targetRaise * minRaiseBp) / 10000n;

      return { ...base, tokenAddress, saleAmount, targetRaise, requiredRaise, vestingWallet };
    }

    it("MIN_RAISE_BP is 2000 (20%), a constant floor; softcapBp is the live, admin-adjustable default seeded to it", async function () {
      const { launchpad } = await loadFixture(deployLaunchpadFixture);
      assert.strictEqual(await launchpad.read.MIN_RAISE_BP(), 2000n);
      assert.strictEqual(await launchpad.read.softcapBp(), 2000n);
    });

    it("setSoftcapBp rejects any value below the MIN_RAISE_BP floor (20%)", async function () {
      const { launchpad } = await loadFixture(deployLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.setSoftcapBp([1999n]),
        launchpad,
        "InvalidSoftcapBp",
      );
      // Unchanged by the rejected call.
      assert.strictEqual(await launchpad.read.softcapBp(), 2000n);

      // The floor value itself is still accepted (>=, not >).
      await launchpad.write.setSoftcapBp([2000n]);
      assert.strictEqual(await launchpad.read.softcapBp(), 2000n);
    });

    it("setSoftcapBp rejects a value above BASIS_POINTS (100%)", async function () {
      const { launchpad } = await loadFixture(deployLaunchpadFixture);
      await assertions.revertWithCustomError(
        launchpad.write.setSoftcapBp([10001n]),
        launchpad,
        "InvalidSoftcapBp",
      );
    });

    it("setSoftcapBp is onlyOwner", async function () {
      const { launchpad, user1 } = await loadFixture(deployLaunchpadFixture);
      await assertions.revert(launchpad.write.setSoftcapBp([2500n], { account: user1.account }));
    });

    it("admin raises the softcap to 25%: a launchpad created AFTER the change is judged at 25%, not 20%", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad } = fixture;

      await launchpad.write.setSoftcapBp([2500n]);
      assert.strictEqual(await launchpad.read.softcapBp(), 2500n);

      const { tokenAddress: tokenAddress2, saleAmount: saleAmount2 } =
        await issueTokenAndCreateLaunchpad(fixture, { launchpadBp: 9999 });
      void tokenAddress2;

      assert.strictEqual(await launchpad.read.launchpadSoftcapBp([1n]), 2500n);

      // saleAmount2/tokenPrice/decimals mirror launchpad 0's fixture shape (TOKEN_PRICE ==
      // 1e18, 18-decimal USDT), so targetRaise == saleAmount2 numerically, same as fixture 0.
      const requiredRaise2 = (saleAmount2 * 2500n) / 10000n;

      const info = (await launchpad.read.getLaunchpadInfo([1n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);

      // 1 wei under the NEW 25% floor: finalize must reject even though this comfortably
      // clears the OLD 20% floor.
      await launchpad.write.participate([1n, requiredRaise2 - 1n], {
        account: fixture.user1.account,
      });
      await time.increaseTo(info.endTime + 1n);
      await assertions.revertWithCustomError(
        launchpad.write.finalizeLaunchpad([1n]),
        launchpad,
        "LaunchpadUnderfunded",
      );
      await launchpad.write.cancelUnderfundedLaunchpad([1n]);
      const finalized2 = (await launchpad.read.getLaunchpadInfo([1n])) as LaunchpadInfo;
      assert.strictEqual(finalized2.status, 5); // Cancelled
    });

    it("SNAPSHOT: raising the global softcap AFTER a launchpad is created does not change that launchpad's own threshold", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, requiredRaise } = fixture;

      // Launchpad 0 was created while softcapBp == 2000 (20%).
      assert.strictEqual(await launchpad.read.launchpadSoftcapBp([0n]), 2000n);

      // Raise the GLOBAL default well past what launchpad 0 will raise.
      await launchpad.write.setSoftcapBp([9000n]); // 90%

      // Launchpad 0's own snapshot is untouched by the global change.
      assert.strictEqual(await launchpad.read.launchpadSoftcapBp([0n]), 2000n);

      // Participation that clears the ORIGINAL 20% floor (and would NOT clear the new
      // 90% global default) still finalizes normally — proving the live 90% default
      // never reached back into this already-created sale.
      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, requiredRaise], { account: user1.account });
      await time.increaseTo(info.endTime + 1n);
      await launchpad.write.finalizeLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 4); // Finalized, not blocked by the new global default
    });

    it("COMPLEMENTARITY at a non-default softcap: finalizeLaunchpad and cancelUnderfundedLaunchpad remain exactly complementary after an admin change", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1 } = fixture;

      await launchpad.write.setSoftcapBp([4000n]); // 40%, well above the 20% default
      const { saleAmount: saleAmount2 } = await issueTokenAndCreateLaunchpad(fixture, {
        launchpadBp: 9999,
      });
      const requiredRaise2 = (saleAmount2 * 4000n) / 10000n;

      const info = (await launchpad.read.getLaunchpadInfo([1n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);

      // Exactly AT the 40% threshold: finalize succeeds, cancelUnderfundedLaunchpad
      // (if tried first) would have reverted LaunchpadNotUnderfunded.
      await launchpad.write.participate([1n, requiredRaise2], { account: user1.account });
      await time.increaseTo(info.endTime + 1n);
      await assertions.revertWithCustomError(
        launchpad.write.cancelUnderfundedLaunchpad([1n]),
        launchpad,
        "LaunchpadNotUnderfunded",
      );
      await launchpad.write.finalizeLaunchpad([1n]);
      const finalized = (await launchpad.read.getLaunchpadInfo([1n])) as LaunchpadInfo;
      assert.strictEqual(finalized.status, 4); // Finalized
    });

    it("[boundary] exactly 20% raised finalizes normally (softcap MET, >= not >)", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, requiredRaise } = fixture;

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, requiredRaise], { account: user1.account });

      await time.increaseTo(info.endTime + 1n);
      await launchpad.write.finalizeLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 4); // Finalized, NOT Cancelled
    });

    it("[boundary] 1 wei under 20%: finalizeLaunchpad reverts LaunchpadUnderfunded (status unchanged), cancelUnderfundedLaunchpad then cancels", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, requiredRaise } = fixture;

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, requiredRaise - 1n], { account: user1.account });

      await time.increaseTo(info.endTime + 1n);
      await assertions.revertWithCustomError(
        launchpad.write.finalizeLaunchpad([0n]),
        launchpad,
        "LaunchpadUnderfunded",
      );

      // NEW INVARIANT: a reverted finalizeLaunchpad changes nothing — status stays
      // exactly where participate() left it (Active), never silently Cancelled.
      const midInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(midInfo.status, 2); // Active, unchanged by the reverted call

      await launchpad.write.cancelUnderfundedLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 5); // Cancelled, NOT Finalized
    });

    it("under-raised (15%): finalizeLaunchpad reverts LaunchpadUnderfunded; cancelUnderfundedLaunchpad returns the FULL escrowed saleAmount to TokenFactory escrow (not just unsold, not to the business), and investor refund() actually pays out", async function () {
      const fixture = await createLaunchpadFixture();
      const {
        launchpad,
        tokenFactory,
        business,
        user1,
        usdt,
        viem,
        tokenAddress,
        saleAmount,
        targetRaise,
      } = fixture;
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      const paymentAmount = (targetRaise * 1500n) / 10000n; // 15% — under the 20% floor
      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, paymentAmount], { account: user1.account });

      assert.strictEqual(await launchpad.read.lockedPaymentAmount([usdt.address]), paymentAmount);

      const businessTokenBefore = (await token.read.balanceOf([
        business.account.address,
      ])) as bigint;

      await time.increaseTo(info.endTime + 1n);

      await assertions.revertWithCustomError(
        launchpad.write.finalizeLaunchpad([0n]),
        launchpad,
        "LaunchpadUnderfunded",
      );
      // finalize's revert left everything untouched — the escrow/lock state below is
      // exactly what participate() set, not something finalize partially mutated.
      assert.strictEqual(await launchpad.read.lockedPaymentAmount([usdt.address]), paymentAmount);

      await launchpad.write.cancelUnderfundedLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 5); // Cancelled

      // full saleAmount (not just the unsold remainder) returns to TokenFactory escrow,
      // NOT the business — the sale is voided outright, mirroring cancelLaunchpad/
      // expireLaunchpad, but resale-eligible after resaleWaitSeconds instead of gone to the
      // business immediately.
      const businessTokenAfter = (await token.read.balanceOf([business.account.address])) as bigint;
      assert.strictEqual(businessTokenAfter - businessTokenBefore, 0n);
      assert.strictEqual(await launchpad.read.lockedTokenAmount([tokenAddress]), 0n);
      const [escrowAmount, , consumed] = (await tokenFactory.read.getEscrowInfo([
        tokenAddress,
      ])) as [bigint, bigint, boolean];
      assert.strictEqual(escrowAmount, saleAmount);
      assert.strictEqual(consumed, false);

      // No fee/immediate/liquidity/vesting cut was taken — the full paymentAmount is
      // still locked and refund() pays it back in full.
      assert.strictEqual(await launchpad.read.lockedPaymentAmount([usdt.address]), paymentAmount);

      const investorBefore = (await usdt.read.balanceOf([user1.account.address])) as bigint;
      await launchpad.write.refund([0n], { account: user1.account });
      const investorAfter = (await usdt.read.balanceOf([user1.account.address])) as bigint;

      assert.strictEqual(investorAfter - investorBefore, paymentAmount);
      assert.strictEqual(await launchpad.read.lockedPaymentAmount([usdt.address]), 0n);

      // The sold-but-never-claimed tokens are moot: claimTokens is unreachable from
      // Cancelled (requires Finalized).
      await assertions.revertWithCustomError(
        launchpad.write.claimTokens([0n], { account: user1.account }),
        launchpad,
        "LaunchpadNotEnded",
      );
    });

    it("[I4] under-raised cancelUnderfundedLaunchpad does NOT start Owner Vesting anymore (only a SUCCESSFUL finalize does) — TokenFactory.triggerOwnerVesting closes the freeze instead", async function () {
      const fixture = await createLaunchpadFixture(1000); // 10% OWNER bucket this time
      const { launchpad, tokenFactory, viem, vestingWallet, tokenAddress, user1, requiredRaise } =
        fixture;

      const wallet = await viem.getContractAt("TokenVestingWallet", vestingWallet);
      assert.strictEqual(await wallet.read.started(), false);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, requiredRaise - 1n], { account: user1.account }); // under the floor

      await time.increaseTo(info.endTime + 1n);
      await assertions.revertWithCustomError(
        launchpad.write.finalizeLaunchpad([0n]),
        launchpad,
        "LaunchpadUnderfunded",
      );
      await launchpad.write.cancelUnderfundedLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 5); // Cancelled (underfunded)

      // cancel (underfunded or otherwise) no longer triggers Owner Vesting.
      assert.strictEqual(await launchpad.read.ownerVestingTrigger([0n]), false);
      assert.strictEqual(await wallet.read.started(), false);

      // The freeze this test used to guard against is now closed permissionlessly through
      // TokenFactory instead, once the resale-wait deadline restoreEscrow set elapses.
      await time.increase(RESALE_WAIT_SECONDS + 1n);
      await tokenFactory.write.triggerOwnerVesting([tokenAddress], { account: user1.account });
      assert.strictEqual(await wallet.read.started(), true);
    });

    it("cancelUnderfundedLaunchpad is PERMISSIONLESS — an unrelated third party (neither owner, business, nor investor) can cancel", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, requiredRaise, platformTreasury } = fixture;

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, requiredRaise - 1n], { account: user1.account });

      await time.increaseTo(info.endTime + 1n);

      // platformTreasury is not the owner, not the business, not an investor — a pure
      // third party. If this were still onlyOwner it would revert here.
      await launchpad.write.cancelUnderfundedLaunchpad([0n], { account: platformTreasury.account });

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 5); // Cancelled
    });

    it("cancelUnderfundedLaunchpad reverts LaunchpadNotEnded before endTime", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, requiredRaise } = fixture;

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, requiredRaise - 1n], { account: user1.account });

      // endTime has not passed yet.
      await assertions.revertWithCustomError(
        launchpad.write.cancelUnderfundedLaunchpad([0n]),
        launchpad,
        "LaunchpadNotEnded",
      );
    });

    it("cancelUnderfundedLaunchpad reverts LaunchpadNotUnderfunded when the softcap was actually met (that raise belongs to finalizeLaunchpad, not this function)", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, requiredRaise } = fixture;

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, requiredRaise], { account: user1.account }); // exactly MET

      await time.increaseTo(info.endTime + 1n);
      await assertions.revertWithCustomError(
        launchpad.write.cancelUnderfundedLaunchpad([0n]),
        launchpad,
        "LaunchpadNotUnderfunded",
      );

      // The well-funded raise is untouched and still finalizes normally.
      await launchpad.write.finalizeLaunchpad([0n]);
      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 4); // Finalized
    });

    it("cancelUnderfundedLaunchpad and expireLaunchpad do not double-execute: whichever lands first blocks the other via the status guard", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, requiredRaise } = fixture;

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, requiredRaise - 1n], { account: user1.account }); // under the floor

      // Past endTime but also past expireLaunchpad's REFUND_GRACE, so both permissionless
      // paths are simultaneously eligible.
      const REFUND_GRACE = 14n * 24n * 60n * 60n;
      await time.increaseTo(info.endTime + REFUND_GRACE + 1n);

      await launchpad.write.cancelUnderfundedLaunchpad([0n]);
      const afterFirst = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(afterFirst.status, 5); // Cancelled

      // expireLaunchpad's own status guard (Active/Preparing only) now blocks it —
      // no double token-return, no double owner-vesting trigger.
      await assertions.revertWithCustomError(
        launchpad.write.expireLaunchpad([0n]),
        launchpad,
        "LaunchpadNotActive",
      );
    });

    it("over-raised (60%): finalizes normally, distributes funds per the normal fund-split path", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, usdt, feeRecipient, targetRaise } = fixture;

      const paymentAmount = (targetRaise * 6000n) / 10000n; // 60% — clears the 20% floor
      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, paymentAmount], { account: user1.account });

      const feeBefore = (await usdt.read.balanceOf([feeRecipient.account.address])) as bigint;

      await time.increaseTo(info.endTime + 1n);
      await launchpad.write.finalizeLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 4); // Finalized

      const feeAfter = (await usdt.read.balanceOf([feeRecipient.account.address])) as bigint;
      const feeRate = (await launchpad.read.launchpadFeeRate()) as bigint;
      assert.strictEqual(feeAfter - feeBefore, (paymentAmount * feeRate) / 10000n);
    });

    it("soldOut always satisfies the softcap (rounding direction guarantees totalRaised >= targetRaise when fully sold)", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, user2, saleAmount } = fixture;

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);

      const half = saleAmount / 2n;
      await launchpad.write.participate([0n, half], { account: user1.account });
      await launchpad.write.participate([0n, saleAmount - half], { account: user2.account });

      // Sold out — finalize is callable immediately, well before endTime.
      await launchpad.write.finalizeLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 4); // Finalized, not Cancelled
      assert.strictEqual(finalizedInfo.soldAmount, saleAmount);
    });

    it("a zero-participation launchpad past endTime: finalizeLaunchpad reverts LaunchpadUnderfunded instead of Finalizing-with-nothing; cancelUnderfundedLaunchpad (permissionless, Preparing status, before it ever started selling) still cancels it", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad } = fixture;

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      // Never participated in, so status is still Preparing even past endTime.
      const preInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(preInfo.status, 1); // Preparing

      await time.increaseTo(info.endTime + 1n);
      await assertions.revertWithCustomError(
        launchpad.write.finalizeLaunchpad([0n]),
        launchpad,
        "LaunchpadUnderfunded",
      );

      await launchpad.write.cancelUnderfundedLaunchpad([0n]);

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 5); // Cancelled (0 raised < any positive floor)
    });

    it("new invariant: finalizeLaunchpad succeeding always implies status == Finalized (no code path leaves a successful call in Cancelled)", async function () {
      const fixture = await createLaunchpadFixture();
      const { launchpad, user1, requiredRaise } = fixture;

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, requiredRaise], { account: user1.account }); // exactly MET

      await time.increaseTo(info.endTime + 1n);
      await launchpad.write.finalizeLaunchpad([0n]); // succeeds

      const finalizedInfo = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      assert.strictEqual(finalizedInfo.status, 4); // Finalized — the only status a successful call can leave
    });
  });

  describe("per-launchpad overrides guarded to Preparing + pre-start (no mid-sale hot-key changes)", function () {
    async function activeLaunchpadFixture() {
      const base = await deployLaunchpadFixture();
      await base.launchpad.write.setPreparationTime([3600n]);
      await base.launchpad.write.setLaunchpadDuration([86400n]);
      await issueTokenAndCreateLaunchpad(base);

      const info = (await base.launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      // Flip Preparing -> Active (status only transitions inside participate()).
      await base.launchpad.write.participate([0n, parseUnits("10", 18)], {
        account: base.user1.account,
      });

      return { ...base };
    }

    it("updateLaunchpadFundSplit reverts LaunchpadAlreadyStarted once the launchpad is Active (was: applied instantly, live-read at finalize)", async function () {
      const { launchpad, owner } = await loadFixture(activeLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.updateLaunchpadFundSplit([0n, 4000n, 1000n, 5000n], {
          account: owner.account,
        }),
        launchpad,
        "LaunchpadAlreadyStarted",
      );
    });

    it("updateLaunchpadFundSplit still works pre-start (Preparing, before startTime)", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, owner } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);

      await launchpad.write.updateLaunchpadFundSplit([0n, 4000n, 1000n, 5000n], {
        account: owner.account,
      });

      // Public mapping-to-struct getter unpacks to positional outputs (not a single
      // named tuple), so viem decodes it as an array, not an object.
      const split = (await launchpad.read.pendingFundSplitConfig([0n])) as [
        bigint,
        bigint,
        bigint,
        boolean,
      ];
      assert.strictEqual(split[0], 4000n); // immediateBp
      assert.strictEqual(split[1], 1000n); // liquidityBp
      assert.strictEqual(split[2], 5000n); // vestingBp
      assert.strictEqual(split[3], true); // isSet
    });

    it("updateInvestorVesting reverts LaunchpadAlreadyStarted once the launchpad is Active (was: retroactively imposed lockup on already-purchased tokens)", async function () {
      const { launchpad, owner } = await loadFixture(activeLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.updateInvestorVesting(
          [
            0n,
            730n * 24n * 60n * 60n,
            { vestingInterval: 365n * 24n * 60n * 60n, firstPeriodAtZero: true, bps: [10000n] },
          ],
          { account: owner.account },
        ),
        launchpad,
        "LaunchpadAlreadyStarted",
      );
    });

    it("updateInvestorVesting still works pre-start (Preparing, before startTime)", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, owner } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);

      await launchpad.write.updateInvestorVesting(
        [
          0n,
          30n * 24n * 60n * 60n,
          { vestingInterval: 7n * 24n * 60n * 60n, firstPeriodAtZero: true, bps: [10000n] },
        ],
        { account: owner.account },
      );

      const config = (await launchpad.read.getInvestorVestingConfig([0n])) as {
        lockupDuration: bigint;
        schedule: { vestingInterval: bigint; firstPeriodAtZero: boolean; bps: bigint[] };
        isSet: boolean;
      };
      assert.strictEqual(config.lockupDuration, 30n * 24n * 60n * 60n);
      assert.strictEqual(config.isSet, true);
      assert.strictEqual(config.schedule.firstPeriodAtZero, true);
      assert.deepStrictEqual(config.schedule.bps, [10000n]);
    });

    it("updateLaunchpadLockup reverts LaunchpadAlreadyStarted once the launchpad is Active (was: only blocked Finalized/Cancelled)", async function () {
      const { launchpad, owner } = await loadFixture(activeLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.updateLaunchpadLockup([0n, 100n * 24n * 60n * 60n], {
          account: owner.account,
        }),
        launchpad,
        "LaunchpadAlreadyStarted",
      );
    });

    it("updateLaunchpadLockup still works pre-start (Preparing, before startTime)", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, owner } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);

      await launchpad.write.updateLaunchpadLockup([0n, 100n * 24n * 60n * 60n], {
        account: owner.account,
      });

      assert.strictEqual(await launchpad.read.pendingLockupDuration([0n]), 100n * 24n * 60n * 60n);
    });

    it("updateLaunchpadVestingSchedule reverts LaunchpadAlreadyStarted once the launchpad is Active (was: only blocked Finalized/Cancelled)", async function () {
      const { launchpad, owner } = await loadFixture(activeLaunchpadFixture);

      await assertions.revertWithCustomError(
        launchpad.write.updateLaunchpadVestingSchedule(
          [
            0n,
            {
              vestingInterval: 30n * 24n * 60n * 60n,
              firstPeriodAtZero: false,
              bps: [5000n, 3000n, 2000n, 0n, 0n, 0n, 0n, 0n],
            },
          ],
          { account: owner.account },
        ),
        launchpad,
        "LaunchpadAlreadyStarted",
      );
    });

    it("updateLaunchpadVestingSchedule still works pre-start (Preparing, before startTime)", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      const { launchpad, owner } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);

      const schedule = {
        vestingInterval: 30n * 24n * 60n * 60n,
        firstPeriodAtZero: false,
        bps: [5000n, 5000n],
      };
      await launchpad.write.updateLaunchpadVestingSchedule([0n, schedule], {
        account: owner.account,
      });

      const config = (await launchpad.read.getLaunchpadVestingSchedule([0n])) as {
        vestingInterval: bigint;
        firstPeriodAtZero: boolean;
        bps: bigint[];
      };
      assert.strictEqual(config.vestingInterval, schedule.vestingInterval);
      assert.strictEqual(config.firstPeriodAtZero, false);
      assert.deepStrictEqual(config.bps, schedule.bps);
    });
  });

  describe("Investor Token Vesting (optional per-launchpad config)", function () {
    it("investors claim 100% immediately when no investor vesting config is set", async function () {
      const fixture = await deployLaunchpadFixture();
      await fixture.launchpad.write.setPreparationTime([3600n]);
      await fixture.launchpad.write.setLaunchpadDuration([86400n]);
      // MIN_RAISE_BP is 2000 (20%) — shrink saleAmount to 3000 USDT so
      // the 1000 USDT raised below (33.3%) clears the floor.
      await issueTokenAndCreateLaunchpad(fixture, { launchpadBp: 30 });

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
      // MIN_RAISE_BP is 2000 (20%) — shrink saleAmount to 3000 USDT so
      // the 1000 USDT raised below (33.3%) clears the floor.
      await issueTokenAndCreateLaunchpad(fixture, { launchpadBp: 30 });

      await launchpad.write.setInvestorVesting(
        [
          0n,
          30n * 24n * 60n * 60n,
          { vestingInterval: 7n * 24n * 60n * 60n, firstPeriodAtZero: true, bps: [10000n] },
        ],
        { account: business.account },
      );

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

  describe("Admin-configurable vesting schedule (variable period count / T+0 / bp-sum validation)", function () {
    it("default behavioral regression: business default equals the pre-existing 8-quarter split (untouched config behaves exactly as before)", async function () {
      const fixture = await deployLaunchpadFixture();
      const { launchpad } = fixture;

      const def = (await launchpad.read.getDefaultVestingSchedule()) as {
        vestingInterval: bigint;
        firstPeriodAtZero: boolean;
        bps: bigint[];
      };
      assert.strictEqual(def.vestingInterval, 90n * 24n * 60n * 60n);
      assert.strictEqual(def.firstPeriodAtZero, false);
      assert.deepStrictEqual(def.bps, [2000n, 1000n, 1000n, 2000n, 1000n, 1000n, 1000n, 1000n]);
    });

    it("a variable period count unlocks EXACTLY on that count — not the old fixed 8 (business, 3 periods)", async function () {
      const fixture = await deployLaunchpadFixture();
      const { launchpad, business, user1 } = fixture;
      await launchpad.write.setPreparationTime([3600n]);
      await launchpad.write.setLaunchpadDuration([86400n]);
      await issueTokenAndCreateLaunchpad(fixture, { launchpadBp: 30 });

      const schedule = {
        vestingInterval: 10n * 24n * 60n * 60n,
        firstPeriodAtZero: false,
        bps: [3000n, 3000n, 4000n], // 3 periods, sums to BASIS_POINTS
      };
      await launchpad.write.setLaunchpadVestingSchedule([0n, schedule], {
        account: business.account,
      });

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, parseUnits("1000", 18)], { account: user1.account });
      await time.increaseTo(info.endTime + 1n);
      await launchpad.write.finalizeLaunchpad([0n]);

      const vesting = (await launchpad.read.getVestingInfo([0n])) as { totalAmount: bigint };
      const total = vesting.totalAmount;

      // Nothing unlocked yet.
      assert.strictEqual(await launchpad.read.getClaimableVesting([0n]), 0n);

      // After 1 interval: only period 1 (30%) unlocked.
      await time.increase(schedule.vestingInterval);
      assert.strictEqual(
        (await launchpad.read.getClaimableVesting([0n])) as bigint,
        (total * 3000n) / 10000n,
      );

      // After 3 intervals total: fully unlocked — the schedule has exactly 3 periods,
      // not the old hardcoded 8, so nothing is withheld waiting for periods 4-8.
      await time.increase(schedule.vestingInterval * 2n);
      assert.strictEqual(await launchpad.read.getClaimableVesting([0n]), total);

      // Further elapsed time changes nothing — confirms the period count is capped at 3,
      // not silently continuing to accrue.
      await time.increase(schedule.vestingInterval * 5n);
      assert.strictEqual(await launchpad.read.getClaimableVesting([0n]), total);
    });

    it("firstPeriodAtZero releases the first tranche at T+0, no waiting for a full interval (participant, listing-time release)", async function () {
      const fixture = await deployLaunchpadFixture();
      const { launchpad, business, user1 } = fixture;
      await launchpad.write.setPreparationTime([3600n]);
      await launchpad.write.setLaunchpadDuration([86400n]);
      await issueTokenAndCreateLaunchpad(fixture, { launchpadBp: 30 });

      const bps = Array(10).fill(1000n) as bigint[]; // 10 x 10% monthly
      await launchpad.write.setInvestorVesting(
        [
          0n,
          0n, // no cliff
          { vestingInterval: 30n * 24n * 60n * 60n, firstPeriodAtZero: true, bps },
        ],
        { account: business.account },
      );

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as LaunchpadInfo;
      await time.increaseTo(info.startTime);
      await launchpad.write.participate([0n, parseUnits("1000", 18)], { account: user1.account });
      await time.increaseTo(info.endTime + 1n);
      await launchpad.write.finalizeLaunchpad([0n]);

      // Immediately at finalize (T+0): the first tranche (10%) is already claimable —
      // this is the behavior firstPeriodAtZero exists to express (vs. the legacy
      // business shape, which waits a full interval for period 1).
      const claimable = (await launchpad.read.getClaimableTokens([
        0n,
        user1.account.address,
      ])) as bigint;
      assert.strictEqual(claimable, parseUnits("100", 18));
    });

    it("rejects a schedule whose bps don't sum to BASIS_POINTS — global default, per-launchpad business, and per-launchpad investor alike", async function () {
      const fixture = await deployLaunchpadFixture();
      const { launchpad, owner, business } = fixture;
      await issueTokenAndCreateLaunchpad(fixture);

      const badSchedule = {
        vestingInterval: 30n * 24n * 60n * 60n,
        firstPeriodAtZero: false,
        bps: [5000n, 4000n], // sums to 9000, not 10000
      };

      await assertions.revertWithCustomError(
        launchpad.write.setDefaultVestingSchedule([badSchedule], { account: owner.account }),
        launchpad,
        "InvalidVestingScheduleSum",
      );

      await assertions.revertWithCustomError(
        launchpad.write.setLaunchpadVestingSchedule([0n, badSchedule], {
          account: business.account,
        }),
        launchpad,
        "InvalidVestingScheduleSum",
      );

      await assertions.revertWithCustomError(
        launchpad.write.setInvestorVesting([0n, 0n, badSchedule], { account: business.account }),
        launchpad,
        "InvalidVestingScheduleSum",
      );
    });

    it("rejects a schedule with more periods than MAX_VESTING_PERIODS", async function () {
      const fixture = await deployLaunchpadFixture();
      const { launchpad, owner } = fixture;

      const maxPeriods = (await launchpad.read.MAX_VESTING_PERIODS()) as bigint;
      const tooMany = new Array(Number(maxPeriods) + 1).fill(0n) as bigint[];
      tooMany[0] = 10000n; // sum is valid — isolates the period-count check specifically

      await assertions.revertWithCustomError(
        launchpad.write.setDefaultVestingSchedule(
          [{ vestingInterval: 30n * 24n * 60n * 60n, firstPeriodAtZero: false, bps: tooMany }],
          { account: owner.account },
        ),
        launchpad,
        "VestingPeriodCountInvalid",
      );
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

    // The quarterly-model views (`getCurrentQuarter`, `getAllQuarterlyVestingAmounts`) were first
    // reduced to `revert DeprecatedFunction()` and are now removed outright to reclaim contract-size
    // headroom. What callers must be able to rely on is unchanged and is what this pins: neither
    // selector returns data. It reverts at the dispatcher now rather than in a named-error body,
    // so assert on the call failing rather than on a specific custom error.
    it("removed quarterly-model view selectors do not return data", async function () {
      const fixture = await loadFixture(deployLaunchpadFixture);
      await issueTokenAndCreateLaunchpad(fixture);

      // Selectors derived, not transcribed — keeping the signature here means this test breaks if
      // someone reintroduces the function under a different shape.
      for (const signature of [
        "function getCurrentQuarter(uint256)",
        "function getAllQuarterlyVestingAmounts(uint256)",
      ] as const) {
        const selector = toFunctionSelector(signature);
        await assert.rejects(
          fixture.publicClient.call({
            to: fixture.launchpad.address,
            data: `${selector}${"0".repeat(64)}` as `0x${string}`,
          }),
          `${signature} must not be callable`,
        );
      }
    });
  });

  describe("Timelocked UUPS Upgrade", function () {
    const DELAY = 48n * 60n * 60n;

    it("requestUpgrade -> immediate upgrade reverts UpgradeNotReady -> after 48h succeeds", async function () {
      const { launchpad, owner, viem } = await loadFixture(deployLaunchpadFixture);
      const newImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const newImpl = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: newImplMathLib.address },
      });

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
      const implAMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const implA = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: implAMathLib.address },
      });
      const implBMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const implB = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: implBMathLib.address },
      });

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
      const implMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const impl = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: implMathLib.address },
      });

      await assertions.revertWithCustomError(
        launchpad.write.upgradeToAndCall([impl.address, "0x"], { account: owner.account }),
        launchpad,
        "NoPendingUpgrade",
      );
    });

    it("cancelUpgrade clears the pending request", async function () {
      const { launchpad, owner, viem } = await loadFixture(deployLaunchpadFixture);
      const implMathLib = await viem.deployContract("LaunchpadMathLib", []);
      const impl = await viem.deployContract("LaunchpadV1", [], {
        libraries: { LaunchpadMathLib: implMathLib.address },
      });

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
