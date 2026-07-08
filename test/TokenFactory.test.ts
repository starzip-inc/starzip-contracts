import { describe, it } from "node:test";
import assert from "node:assert";
import { parseUnits, getAddress, encodeFunctionData, zeroAddress, Address, Hex } from "viem";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import { privateKeyToAccount } from "viem/accounts";
import {
  deployTokenFactoryCore,
  configureDefaultAllocationGuides,
  setAllocationGuide,
  setLinkedLaunchpad,
  setEscrowTimeout,
  issueTokenWithRatios,
  signIssuePermit,
  buildRatios,
  BUCKET_LAUNCHPAD,
  BUCKET_LIQUIDITY_RESERVE,
  BUCKET_OWNER_VESTING,
  ALLOCATION_GUIDE_DELAY,
  CONFIG_DELAY,
} from "./tokenFactoryHelpers.js";

describe("TokenFactory (3-bucket / escrow / owner-vesting-wallet)", function () {
  const TOTAL_SUPPLY = parseUnits("1000000", 18); // 1M tokens

  // Test private key for permit signing (DO NOT USE IN PRODUCTION) — Hardhat account #0.
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

  /**
   * Deploys the TokenFactory core + a REAL LaunchpadV1 wired as `linkedLaunchpad`
   * (genuine escrow release / owner-vesting-trigger integration, not a stub), with
   * permissive allocation guides pre-configured for all 3 buckets.
   */
  async function deployTokenFactoryFixture() {
    const { viem } = await getConnection();
    const [owner, business, platformTreasury, user1] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);
    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);

    const {
      tokenFactory,
      erc20Impl,
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
    const launchpadInitData = encodeFunctionData({
      abi: launchpadImpl.abi,
      functionName: "initialize",
      args: [tokenFactory.address, usdt.address, platformTreasury.account.address],
    });
    const launchpadProxy = await viem.deployContract("ERC1967Proxy", [
      launchpadImpl.address,
      launchpadInitData,
    ]);
    const launchpad = await viem.getContractAt("LaunchpadV1", launchpadProxy.address);

    await setLinkedLaunchpad(tokenFactory, owner, launchpad.address);
    // Escrow timeout must be configured before issuing tokens with a LAUNCHPAD bucket
    // (fail-closed guard EscrowTimeoutNotConfigured). 7 days is a representative default;
    // tests that exercise reclaim timing override it via setEscrowTimeout.
    await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n);

    return {
      tokenFactory,
      launchpad,
      usdt,
      beacon,
      erc20Impl,
      vestingWalletBeacon,
      owner,
      business,
      platformTreasury,
      user1,
      publicClient,
      permitSigner,
      chainId,
      viem,
    };
  }

  // Default permissive ratios: 10% LAUNCHPAD (escrowed), 90% LIQUIDITY_RESERVE, 0% OWNER.
  // LIQUIDITY_RESERVE routed to `recipient` (never the business account).
  function defaultRatios(recipient: Address) {
    return buildRatios({
      launchpadBp: 1000,
      liquidityBp: 9000,
      ownerBp: 0,
      liquidityRecipient: recipient,
    });
  }

  async function issueDefault(
    fx: Awaited<ReturnType<typeof deployTokenFactoryFixture>>,
    overrides?: {
      ratios?: ReturnType<typeof buildRatios>;
      name?: string;
      symbol?: string;
      business?: any;
    },
  ) {
    const business = overrides?.business ?? fx.business;
    const ratios = overrides?.ratios ?? defaultRatios(fx.platformTreasury.account.address);
    return issueTokenWithRatios({
      tokenFactory: fx.tokenFactory,
      business,
      publicClient: fx.publicClient,
      chainId: fx.chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: fx.launchpad.address,
      name: overrides?.name ?? "TestToken",
      symbol: overrides?.symbol ?? "TT",
      totalSupply: TOTAL_SUPPLY,
      contractURI: "https://example.com/metadata",
      ratios,
    });
  }

  describe("Initialization", function () {
    it("should initialize correctly", async function () {
      const { tokenFactory, beacon, vestingWalletBeacon, platformTreasury, owner, permitSigner } =
        await loadFixture(deployTokenFactoryFixture);

      assert.strictEqual(await tokenFactory.read.owner(), getAddress(owner.account.address));
      assert.strictEqual(await tokenFactory.read.erc20Beacon(), getAddress(beacon.address));
      assert.strictEqual(
        await tokenFactory.read.vestingWalletBeacon(),
        getAddress(vestingWalletBeacon.address),
      );
      assert.strictEqual(
        await tokenFactory.read.platformTreasury(),
        getAddress(platformTreasury.account.address),
      );
      assert.strictEqual(await tokenFactory.read.autoListOnExchange(), true);
      assert.strictEqual(await tokenFactory.read.permitSigner(), getAddress(permitSigner.address));
    });

    it("should reject zero beacon address", async function () {
      const { platformTreasury, permitSigner, vestingWalletBeacon, viem } =
        await loadFixture(deployTokenFactoryFixture);

      const tokenFactoryImpl = await viem.deployContract("TokenFactory", []);
      const initData = encodeFunctionData({
        abi: tokenFactoryImpl.abi,
        functionName: "initialize",
        args: [
          zeroAddress,
          platformTreasury.account.address,
          permitSigner.address,
          vestingWalletBeacon.address,
        ],
      });

      await assertions.revert(
        viem.deployContract("ERC1967Proxy", [tokenFactoryImpl.address, initData]),
      );
    });

    it("should reject zero permitSigner address", async function () {
      const { beacon, platformTreasury, vestingWalletBeacon, viem } =
        await loadFixture(deployTokenFactoryFixture);

      const tokenFactoryImpl = await viem.deployContract("TokenFactory", []);
      const initData = encodeFunctionData({
        abi: tokenFactoryImpl.abi,
        functionName: "initialize",
        args: [
          beacon.address,
          platformTreasury.account.address,
          zeroAddress,
          vestingWalletBeacon.address,
        ],
      });

      await assertions.revert(
        viem.deployContract("ERC1967Proxy", [tokenFactoryImpl.address, initData]),
      );
    });

    it("should reject zero vestingWalletBeacon address", async function () {
      const { beacon, platformTreasury, permitSigner, viem } =
        await loadFixture(deployTokenFactoryFixture);

      const tokenFactoryImpl = await viem.deployContract("TokenFactory", []);
      const initData = encodeFunctionData({
        abi: tokenFactoryImpl.abi,
        functionName: "initialize",
        args: [beacon.address, platformTreasury.account.address, permitSigner.address, zeroAddress],
      });

      await assertions.revert(
        viem.deployContract("ERC1967Proxy", [tokenFactoryImpl.address, initData]),
      );
    });

    it("should reject non-contract vestingWalletBeacon address", async function () {
      const { beacon, platformTreasury, permitSigner, user1, viem } =
        await loadFixture(deployTokenFactoryFixture);

      const tokenFactoryImpl = await viem.deployContract("TokenFactory", []);
      const initData = encodeFunctionData({
        abi: tokenFactoryImpl.abi,
        functionName: "initialize",
        args: [
          beacon.address,
          platformTreasury.account.address,
          permitSigner.address,
          user1.account.address,
        ],
      });

      await assertions.revert(
        viem.deployContract("ERC1967Proxy", [tokenFactoryImpl.address, initData]),
      );
    });

    it("should fail-closed (AllocationGuidesNotInitialized) when guides are unset", async function () {
      // Fresh factory with NO allocation guides configured.
      const { viem } = await getConnection();
      const [owner, business, platformTreasury] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const chainId = await publicClient.getChainId();
      const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);

      const { tokenFactory, erc20Beacon } = await deployTokenFactoryCore(
        viem,
        owner,
        platformTreasury.account.address,
        permitSigner.address,
      );
      await setLinkedLaunchpad(tokenFactory, owner, erc20Beacon.address);

      const ratios = defaultRatios(platformTreasury.account.address);
      const deadline = (await time.latest()) + 3600n;
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "",
        ratios,
        linkedLaunchpad: erc20Beacon.address,
        nonce,
        deadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          ["TestToken", "TT", TOTAL_SUPPLY, "", ratios, deadline, signature],
          { account: business.account },
        ),
        tokenFactory,
        "AllocationGuidesNotInitialized",
      );
    });

    it("should fail-closed (LinkedLaunchpadNotSet) when linkedLaunchpad is unset", async function () {
      const { viem } = await getConnection();
      const [owner, business, platformTreasury] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const chainId = await publicClient.getChainId();
      const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);

      const { tokenFactory } = await deployTokenFactoryCore(
        viem,
        owner,
        platformTreasury.account.address,
        permitSigner.address,
      );
      await configureDefaultAllocationGuides(tokenFactory, owner);
      // linkedLaunchpad intentionally left unset.

      const ratios = defaultRatios(platformTreasury.account.address);
      const deadline = (await time.latest()) + 3600n;
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "",
        ratios,
        linkedLaunchpad: zeroAddress,
        nonce,
        deadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          ["TestToken", "TT", TOTAL_SUPPLY, "", ratios, deadline, signature],
          { account: business.account },
        ),
        tokenFactory,
        "LinkedLaunchpadNotSet",
      );
    });
  });

  describe("Issue Token (EIP-712 Signature)", function () {
    it("should issue token successfully with valid signature and distribute buckets correctly", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business, platformTreasury, viem } = fx;

      const { tokenAddress, vestingWallet } = await issueDefault(fx);

      assert.strictEqual(await tokenFactory.read.getTokenCount(), 1n);
      assert.notStrictEqual(tokenAddress, zeroAddress);

      const tokenInfo = (await tokenFactory.read.getTokenInfo([tokenAddress])) as [
        Address,
        bigint,
        boolean,
      ];
      const [businessAccount, issuedAt, isIssued] = tokenInfo;
      assert.strictEqual(businessAccount, getAddress(business.account.address));
      assert.ok(issuedAt > 0n);
      assert.strictEqual(isIssued, true);

      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      // 10% LAUNCHPAD -> escrow (factory custody, NOT transferred anywhere).
      const launchpadAmount = (TOTAL_SUPPLY * 1000n) / 10000n;
      assert.strictEqual(await token.read.balanceOf([tokenFactory.address]), launchpadAmount);
      const [escrowAmount, , consumed] = (await tokenFactory.read.getEscrowInfo([
        tokenAddress,
      ])) as [bigint, bigint, boolean];
      assert.strictEqual(escrowAmount, launchpadAmount);
      assert.strictEqual(consumed, false);

      // 90% LIQUIDITY_RESERVE -> platformTreasury (this fixture's recipient).
      const liquidityAmount = (TOTAL_SUPPLY * 9000n) / 10000n;
      assert.strictEqual(
        await token.read.balanceOf([platformTreasury.account.address]),
        liquidityAmount,
      );

      // 0% OWNER_VESTING -> vesting wallet holds nothing, but is still deployed.
      assert.notStrictEqual(vestingWallet, zeroAddress);
      assert.strictEqual(await token.read.balanceOf([vestingWallet]), 0n);

      // Bucket amounts sum to totalSupply exactly (rounding remainder rolls into LAUNCHPAD).
      assert.strictEqual(launchpadAmount + liquidityAmount, TOTAL_SUPPLY);

      // Token ownership transferred to business.
      assert.strictEqual(await token.read.owner(), getAddress(business.account.address));
    });

    it("locks maxSupply to totalSupply at issuance (fixed-supply, closes Finding 2)", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { business, viem } = fx;

      const { tokenAddress } = await issueDefault(fx);
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      // Cap is locked to the exact issued amount → zero mint headroom (maxSupply == totalSupply),
      // so no one — not even the new (business) owner — can ever inflate supply post-issuance.
      assert.strictEqual((await token.read.maxSupply()) as bigint, TOTAL_SUPPLY);
      assert.strictEqual((await token.read.totalSupply()) as bigint, TOTAL_SUPPLY);

      // The one-shot cap is already consumed: even the new (business) owner cannot raise it.
      await assertions.revertWithCustomError(
        token.write.setMaxSupply([TOTAL_SUPPLY * 2n], { account: business.account }),
        token,
        "MaxSupplyAlreadySet",
      );
    });

    it("should emit TokenIssued event with full bucket ratios", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, publicClient } = fx;

      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const { hash } = await issueDefault(fx, { ratios });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });

      const tokenIssuedEvent = receipt.logs.find(
        (log) => log.address.toLowerCase() === tokenFactory.address.toLowerCase(),
      );
      assert.ok(tokenIssuedEvent, "TokenIssued event should be emitted");
    });

    it("should increment nonce after successful issuance", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business } = fx;

      const nonceBefore = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      assert.strictEqual(nonceBefore, 0n);

      await issueDefault(fx);

      const nonceAfter = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      assert.strictEqual(nonceAfter, 1n);
    });

    it("should reject invalid signature", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business } = fx;

      const deadline = (await time.latest()) + 3600n;
      const invalidSignature = ("0x" + "00".repeat(65)) as Hex;
      const ratios = defaultRatios(fx.platformTreasury.account.address);

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          ["TestToken", "TT", TOTAL_SUPPLY, "", ratios, deadline, invalidSignature],
          { account: business.account },
        ),
        tokenFactory,
        "InvalidSignature",
      );
    });

    it("should reject expired deadline", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business, chainId } = fx;

      const expiredDeadline = (await time.latest()) - 1n;
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline: expiredDeadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          ["TestToken", "TT", TOTAL_SUPPLY, "", ratios, expiredDeadline, signature],
          { account: business.account },
        ),
        tokenFactory,
        "ExpiredDeadline",
      );
    });

    it("should reject signature from wrong signer", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business, chainId } = fx;

      const wrongPrivateKey =
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
      const deadline = (await time.latest()) + 3600n;
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const wrongSignature = await signIssuePermit({
        privateKey: wrongPrivateKey,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          ["TestToken", "TT", TOTAL_SUPPLY, "", ratios, deadline, wrongSignature],
          { account: business.account },
        ),
        tokenFactory,
        "InvalidSignature",
      );
    });

    it("should reject replay attack (reusing same signature)", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business, chainId } = fx;

      const deadline = (await time.latest()) + 3600n;
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline,
      });

      await tokenFactory.write.issueToken(
        ["TestToken", "TT", TOTAL_SUPPLY, "", ratios, deadline, signature],
        { account: business.account },
      );

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          ["TestToken", "TT", TOTAL_SUPPLY, "", ratios, deadline, signature],
          { account: business.account },
        ),
        tokenFactory,
        "InvalidSignature",
      );
    });

    it("should reject zero total supply", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business, chainId } = fx;
      const deadline = (await time.latest()) + 3600n;
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: 0n,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(["TestToken", "TT", 0n, "", ratios, deadline, signature], {
          account: business.account,
        }),
        tokenFactory,
        "ZeroAmount",
      );
    });

    it("should reject empty name", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business, chainId } = fx;
      const deadline = (await time.latest()) + 3600n;
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "",
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(["", "TT", TOTAL_SUPPLY, "", ratios, deadline, signature], {
          account: business.account,
        }),
        tokenFactory,
        "EmptyString",
      );
    });

    it("should reject name too long", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business, chainId } = fx;
      const deadline = (await time.latest()) + 3600n;
      const longName = "A".repeat(65); // MAX_NAME_LENGTH is 64
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: longName,
        symbol: "TT",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          [longName, "TT", TOTAL_SUPPLY, "", ratios, deadline, signature],
          {
            account: business.account,
          },
        ),
        tokenFactory,
        "StringTooLong",
      );
    });

    it("should reject when paused", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, owner } = fx;

      await tokenFactory.write.pause([], { account: owner.account });

      await assertions.revert(issueDefault(fx));
    });

    it("should reject vesting duration below minimum", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const ratios = buildRatios({
        launchpadBp: 1000,
        liquidityBp: 9000,
        ownerBp: 0,
        liquidityRecipient: fx.platformTreasury.account.address,
        ownerVestingDuration: 1n, // below MIN_OWNER_VESTING_DURATION (30 days)
      });

      await assertions.revertWithCustomError(
        issueDefault(fx, { ratios }),
        fx.tokenFactory,
        "VestingDurationInvalid",
      );
    });

    it("should reject liquidityRecipient == businessAccount (self-deal guard)", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const ratios = buildRatios({
        launchpadBp: 1000,
        liquidityBp: 9000,
        ownerBp: 0,
        liquidityRecipient: fx.business.account.address,
      });

      await assertions.revertWithCustomError(
        issueDefault(fx, { ratios }),
        fx.tokenFactory,
        "LiquidityRecipientInvalid",
      );
    });
  });

  describe("Allocation invariants", function () {
    it("should reject bucket sum != 10000", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const ratios = buildRatios({
        launchpadBp: 1000,
        liquidityBp: 8000, // sum = 9000
        ownerBp: 0,
        liquidityRecipient: fx.platformTreasury.account.address,
      });

      await assertions.revertWithCustomError(
        issueDefault(fx, { ratios }),
        fx.tokenFactory,
        "AllocationSumInvalid",
      );
    });

    it("should reject a bucket bp outside its configured guide range", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, owner } = fx;

      // Tighten the LAUNCHPAD guide to [2000, 3000].
      await setAllocationGuide(tokenFactory, owner, BUCKET_LAUNCHPAD, 2000, 3000);

      const ratios = buildRatios({
        launchpadBp: 1000, // below the new minBp
        liquidityBp: 9000,
        ownerBp: 0,
        liquidityRecipient: fx.platformTreasury.account.address,
      });

      await assertions.revertWithCustomError(
        issueDefault(fx, { ratios }),
        fx.tokenFactory,
        "AllocationOutOfRange",
      );
    });

    it("should enforce the LIQUIDITY_RESERVE minimum bp floor on the guide setter", async function () {
      const { tokenFactory, owner } = await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.proposeAllocationGuide([BUCKET_LIQUIDITY_RESERVE, 0, 10000], {
          account: owner.account,
        }),
        tokenFactory,
        "LiquidityReserveMinimumRequired",
      );
    });

    it("rounding remainder rolls into the LAUNCHPAD bucket", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, viem } = fx;

      // 1 wei odd totalSupply with bp splits that don't divide evenly.
      const oddSupply = TOTAL_SUPPLY + 1n;
      const ratios = buildRatios({
        launchpadBp: 3334,
        liquidityBp: 3333,
        ownerBp: 3333,
        liquidityRecipient: fx.platformTreasury.account.address,
      });

      const { tokenAddress } = await issueTokenWithRatios({
        tokenFactory,
        business: fx.business,
        publicClient: fx.publicClient,
        chainId: fx.chainId,
        permitPrivateKey: TEST_PRIVATE_KEY,
        linkedLaunchpad: fx.launchpad.address,
        name: "OddToken",
        symbol: "ODD",
        totalSupply: oddSupply,
        ratios,
      });

      const token = await viem.getContractAt("ERC20V1", tokenAddress);
      const liquidityAmount = (oddSupply * 3333n) / 10000n;
      const escrowAmount = (await tokenFactory.read.launchpadEscrow([tokenAddress])) as bigint;

      // Total minted == oddSupply exactly (no dust lost or created).
      assert.strictEqual(await token.read.totalSupply(), oddSupply);
      assert.strictEqual(
        escrowAmount +
          liquidityAmount +
          (await token.read.balanceOf([
            (await tokenFactory.read.tokenToVestingWallet([tokenAddress])) as Address,
          ])),
        oddSupply,
      );
    });
  });

  describe("LAUNCHPAD bucket escrow", function () {
    it("factory holds the LAUNCHPAD bucket in custody after issuance", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, viem } = fx;
      const { tokenAddress } = await issueDefault(fx);

      const token = await viem.getContractAt("ERC20V1", tokenAddress);
      const expectedEscrow = (TOTAL_SUPPLY * 1000n) / 10000n;

      assert.strictEqual(await token.read.balanceOf([tokenFactory.address]), expectedEscrow);
      const [amount, deadline, consumed] = (await tokenFactory.read.getEscrowInfo([
        tokenAddress,
      ])) as [bigint, bigint, boolean];
      assert.strictEqual(amount, expectedEscrow);
      assert.ok(deadline > 0n);
      assert.strictEqual(consumed, false);
    });

    it("createLaunchpad releases the escrow to the linkedLaunchpad and derives saleAmount", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, launchpad, usdt, business } = fx;
      const { tokenAddress } = await issueDefault(fx);

      const expectedEscrow = (TOTAL_SUPPLY * 1000n) / 10000n;

      await launchpad.write.createLaunchpad(
        [tokenAddress, parseUnits("1", 18), business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );

      const [, , consumed] = (await tokenFactory.read.getEscrowInfo([tokenAddress])) as [
        bigint,
        bigint,
        boolean,
      ];
      assert.strictEqual(consumed, true);
      assert.strictEqual(await tokenFactory.read.launchpadEscrow([tokenAddress]), 0n);

      const info = (await launchpad.read.getLaunchpadInfo([0n])) as { saleAmount: bigint };
      assert.strictEqual(info.saleAmount, expectedEscrow);
    });

    it("blocks a second createLaunchpad for the same token (escrow already consumed)", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { launchpad, usdt, business } = fx;
      const { tokenAddress } = await issueDefault(fx);

      await launchpad.write.createLaunchpad(
        [tokenAddress, parseUnits("1", 18), business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );

      // LaunchpadV1 checks `launchpadEscrow(token) == 0` BEFORE calling `releaseEscrow`,
      // so the second call surfaces `NoEscrowAvailable` (LaunchpadV1) rather than
      // `EscrowAlreadyConsumed` (TokenFactory) — both guard the same one-shot invariant:
      // a token's LAUNCHPAD bucket can only ever be consumed once.
      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, parseUnits("1", 18), business.account.address, usdt.address, 0n, 0n],
          { account: business.account },
        ),
        launchpad,
        "NoEscrowAvailable",
      );
    });

    it("releaseEscrow reverts NotLinkedLaunchpad when called by a non-linked address", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business } = fx;
      const { tokenAddress } = await issueDefault(fx);

      await assertions.revertWithCustomError(
        tokenFactory.write.releaseEscrow([tokenAddress], { account: business.account }),
        tokenFactory,
        "NotLinkedLaunchpad",
      );
    });

    it("reclaimEscrow reverts EscrowTimeoutNotElapsed before the configured timeout", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, owner, business } = fx;

      await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n); // 7 days
      const { tokenAddress } = await issueDefault(fx);

      await assertions.revertWithCustomError(
        tokenFactory.write.reclaimEscrow([tokenAddress], { account: business.account }),
        tokenFactory,
        "EscrowTimeoutNotElapsed",
      );
    });

    it("reclaimEscrow succeeds after the timeout elapses and returns tokens to the business", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, owner, business, viem } = fx;

      await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n); // 7 days
      const { tokenAddress } = await issueDefault(fx);
      const expectedEscrow = (TOTAL_SUPPLY * 1000n) / 10000n;

      await time.increase(7n * 24n * 60n * 60n + 1n);

      await tokenFactory.write.reclaimEscrow([tokenAddress], { account: business.account });

      const token = await viem.getContractAt("ERC20V1", tokenAddress);
      assert.strictEqual(await token.read.balanceOf([business.account.address]), expectedEscrow);
      assert.strictEqual(await tokenFactory.read.launchpadEscrow([tokenAddress]), 0n);

      const [, , consumed] = (await tokenFactory.read.getEscrowInfo([tokenAddress])) as [
        bigint,
        bigint,
        boolean,
      ];
      assert.strictEqual(consumed, true);
    });

    it("reclaimEscrow reverts EscrowAlreadyConsumed after createLaunchpad has consumed it", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, owner, launchpad, usdt, business } = fx;

      await setEscrowTimeout(tokenFactory, owner, 3600n); // MIN_ESCROW_TIMEOUT (1 hour)
      const { tokenAddress } = await issueDefault(fx);

      await launchpad.write.createLaunchpad(
        [tokenAddress, parseUnits("1", 18), business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );

      await time.increase(3601n);

      await assertions.revertWithCustomError(
        tokenFactory.write.reclaimEscrow([tokenAddress], { account: business.account }),
        tokenFactory,
        "EscrowAlreadyConsumed",
      );
    });

    it("reclaimEscrow reverts NotEscrowBusiness for an unrelated caller", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, owner, user1 } = fx;

      await setEscrowTimeout(tokenFactory, owner, 3600n);
      const { tokenAddress } = await issueDefault(fx);
      await time.increase(3601n);

      await assertions.revertWithCustomError(
        tokenFactory.write.reclaimEscrow([tokenAddress], { account: user1.account }),
        tokenFactory,
        "NotEscrowBusiness",
      );
    });

    it("reclaimEscrow is callable by the platform owner too", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, owner, business, viem } = fx;

      await setEscrowTimeout(tokenFactory, owner, 3600n);
      const { tokenAddress } = await issueDefault(fx);
      await time.increase(3601n);

      await tokenFactory.write.reclaimEscrow([tokenAddress], { account: owner.account });

      const token = await viem.getContractAt("ERC20V1", tokenAddress);
      const expectedEscrow = (TOTAL_SUPPLY * 1000n) / 10000n;
      assert.strictEqual(await token.read.balanceOf([business.account.address]), expectedEscrow);
    });
  });

  describe("Owner Vesting wallet", function () {
    it("deploys a vesting wallet on every issuance and routes the OWNER bucket to it", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, launchpad, viem } = fx;

      const ratios = buildRatios({
        launchpadBp: 1000,
        liquidityBp: 8000,
        ownerBp: 1000,
        liquidityRecipient: fx.platformTreasury.account.address,
      });
      const { tokenAddress, vestingWallet } = await issueDefault(fx, { ratios });

      assert.strictEqual(
        await tokenFactory.read.tokenToVestingWallet([tokenAddress]),
        getAddress(vestingWallet),
      );

      const token = await viem.getContractAt("ERC20V1", tokenAddress);
      const ownerAmount = (TOTAL_SUPPLY * 1000n) / 10000n;
      assert.strictEqual(await token.read.balanceOf([vestingWallet]), ownerAmount);

      const wallet = await viem.getContractAt("TokenVestingWallet", vestingWallet);
      assert.strictEqual(await wallet.read.launchpad(), getAddress(launchpad.address));
      assert.strictEqual(await wallet.read.owner(), getAddress(fx.business.account.address));
      assert.strictEqual(await wallet.read.started(), false);
    });
  });

  describe("Multiple Tokens", function () {
    it("should issue multiple tokens by different businesses", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, user1, viem } = fx;

      await issueDefault(fx, { name: "Token1", symbol: "TK1" });
      await issueDefault(fx, { name: "Token2", symbol: "TK2", business: user1 });

      assert.strictEqual(await tokenFactory.read.getTokenCount(), 2n);

      const token1 = (await tokenFactory.read.tokenById([0n])) as Address;
      const token2 = (await tokenFactory.read.tokenById([1n])) as Address;

      assert.notStrictEqual(token1, token2);
      const token1Contract = await viem.getContractAt("ERC20V1", token1);
      const token2Contract = await viem.getContractAt("ERC20V1", token2);
      assert.strictEqual(
        await token1Contract.read.owner(),
        getAddress(fx.business.account.address),
      );
      assert.strictEqual(await token2Contract.read.owner(), getAddress(user1.account.address));
    });

    it("should allow same business to issue multiple tokens", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business } = fx;

      await issueDefault(fx, { name: "Token1", symbol: "TK1" });
      await issueDefault(fx, { name: "Token2", symbol: "TK2" });
      await issueDefault(fx, { name: "Token3", symbol: "TK3" });

      assert.strictEqual(await tokenFactory.read.getTokenCount(), 3n);
      assert.strictEqual(await tokenFactory.read.nonces([business.account.address]), 3n);
    });
  });

  describe("Admin Functions", function () {
    it("should toggle auto-list on exchange", async function () {
      const { tokenFactory, owner } = await loadFixture(deployTokenFactoryFixture);

      assert.strictEqual(await tokenFactory.read.autoListOnExchange(), true);
      await tokenFactory.write.setAutoListOnExchange([false], { account: owner.account });
      assert.strictEqual(await tokenFactory.read.autoListOnExchange(), false);
      await tokenFactory.write.setAutoListOnExchange([true], { account: owner.account });
      assert.strictEqual(await tokenFactory.read.autoListOnExchange(), true);
    });

    it("should pause and unpause", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, owner } = fx;

      await tokenFactory.write.pause([], { account: owner.account });
      await assertions.revert(issueDefault(fx));

      await tokenFactory.write.unpause([], { account: owner.account });
      await issueDefault(fx);

      assert.strictEqual(await tokenFactory.read.getTokenCount(), 1n);
    });

    it("should reject non-owner admin calls", async function () {
      const { tokenFactory, user1 } = await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.setAutoListOnExchange([false], { account: user1.account }),
        tokenFactory,
        "OwnableUnauthorizedAccount",
      );
      await assertions.revertWithCustomError(
        tokenFactory.write.proposePermitSignerChange([user1.account.address], {
          account: user1.account,
        }),
        tokenFactory,
        "OwnableUnauthorizedAccount",
      );
      await assertions.revertWithCustomError(
        tokenFactory.write.pause([], { account: user1.account }),
        tokenFactory,
        "OwnableUnauthorizedAccount",
      );
    });
  });

  describe("Token Ownership Transfer (Admin)", function () {
    it("should allow admin to transfer token ownership", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, user1, owner, viem } = fx;

      const { tokenAddress } = await issueDefault(fx);
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      assert.strictEqual(await token.read.owner(), getAddress(fx.business.account.address));

      await tokenFactory.write.transferTokenOwnership([tokenAddress, user1.account.address], {
        account: owner.account,
      });

      assert.strictEqual(await token.read.owner(), getAddress(user1.account.address));
    });

    it("should reject non-owner admin calls for token ownership transfer", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { user1, tokenFactory } = fx;

      const { tokenAddress } = await issueDefault(fx);

      await assertions.revertWithCustomError(
        tokenFactory.write.transferTokenOwnership([tokenAddress, user1.account.address], {
          account: user1.account,
        }),
        tokenFactory,
        "OwnableUnauthorizedAccount",
      );
    });

    it("should reject transferring non-issued token", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business, viem, owner } = fx;

      const randomToken = await viem.deployContract("USDT", [owner.account.address, 18]);

      await assertions.revertWithCustomError(
        tokenFactory.write.transferTokenOwnership([randomToken.address, business.account.address], {
          account: owner.account,
        }),
        tokenFactory,
        "TokenIssuanceFailed",
      );
    });
  });

  describe("EIP-712 Domain", function () {
    it("should return correct domain separator", async function () {
      const { tokenFactory } = await loadFixture(deployTokenFactoryFixture);

      const domainSeparator = await tokenFactory.read.DOMAIN_SEPARATOR();
      assert.ok(domainSeparator, "Domain separator should exist");
      assert.ok((domainSeparator as string).startsWith("0x"), "Should be hex string");
    });
  });

  describe("Version", function () {
    it("should return version 1", async function () {
      const { tokenFactory } = await loadFixture(deployTokenFactoryFixture);
      assert.strictEqual(await tokenFactory.read.version(), 1n);
    });
  });

  describe("Security Limits", function () {
    it("should reject supply exceeding MAX_SUPPLY_PER_TOKEN", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const MAX_SUPPLY_PER_TOKEN = parseUnits("1000000000", 18);
      const exceedingSupply = MAX_SUPPLY_PER_TOKEN + 1n;

      const { tokenFactory, business, chainId } = fx;
      const deadline = (await time.latest()) + 3600n;
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "TestToken",
        symbol: "TT",
        totalSupply: exceedingSupply,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          ["TestToken", "TT", exceedingSupply, "", ratios, deadline, signature],
          {
            account: business.account,
          },
        ),
        tokenFactory,
        "SupplyLimitExceeded",
      );
    });

    it("should allow supply at exactly MAX_SUPPLY_PER_TOKEN", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const MAX_SUPPLY_PER_TOKEN = parseUnits("1000000000", 18);

      const { tokenFactory, business, chainId } = fx;
      const deadline = (await time.latest()) + 3600n;
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "MaxSupplyToken",
        symbol: "MST",
        totalSupply: MAX_SUPPLY_PER_TOKEN,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline,
      });

      await tokenFactory.write.issueToken(
        ["MaxSupplyToken", "MST", MAX_SUPPLY_PER_TOKEN, "", ratios, deadline, signature],
        { account: business.account },
      );

      assert.strictEqual(await tokenFactory.read.getTokenCount(), 1n);
    });

    it("should track daily issuance count", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory } = fx;

      assert.strictEqual(await tokenFactory.read.getTodayIssuanceCount(), 0n);
      assert.strictEqual(await tokenFactory.read.getRemainingDailyQuota(), 20n);

      await issueDefault(fx, { name: "Token1", symbol: "TK1" });
      assert.strictEqual(await tokenFactory.read.getTodayIssuanceCount(), 1n);
      assert.strictEqual(await tokenFactory.read.getRemainingDailyQuota(), 19n);

      await issueDefault(fx, { name: "Token2", symbol: "TK2" });
      assert.strictEqual(await tokenFactory.read.getTodayIssuanceCount(), 2n);
      assert.strictEqual(await tokenFactory.read.getRemainingDailyQuota(), 18n);
    });

    it("should reject when daily limit exceeded", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, business, user1, chainId } = fx;
      const MAX_DAILY_ISSUANCE = 20;

      for (let i = 0; i < MAX_DAILY_ISSUANCE; i++) {
        const issuer = i % 2 === 0 ? business : user1;
        await issueDefault(fx, { name: `Token${i}`, symbol: `TK${i}`, business: issuer });
      }

      assert.strictEqual(
        await tokenFactory.read.getTodayIssuanceCount(),
        BigInt(MAX_DAILY_ISSUANCE),
      );
      assert.strictEqual(await tokenFactory.read.getRemainingDailyQuota(), 0n);

      const deadline = (await time.latest()) + 3600n;
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: TEST_PRIVATE_KEY,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "ExcessToken",
        symbol: "EXT",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          ["ExcessToken", "EXT", TOTAL_SUPPLY, "", ratios, deadline, signature],
          {
            account: business.account,
          },
        ),
        tokenFactory,
        "DailyLimitExceeded",
      );
    });

    it("should reset daily limit after day passes", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory } = fx;

      await issueDefault(fx, { name: "TodayToken", symbol: "TDY" });
      assert.strictEqual(await tokenFactory.read.getTodayIssuanceCount(), 1n);

      await time.increase(86400n);

      assert.strictEqual(await tokenFactory.read.getTodayIssuanceCount(), 0n);
      assert.strictEqual(await tokenFactory.read.getRemainingDailyQuota(), 20n);

      await issueDefault(fx, { name: "TomorrowToken", symbol: "TMR" });
      assert.strictEqual(await tokenFactory.read.getTodayIssuanceCount(), 1n);
    });
  });

  describe("Timelock: Beacon Change", function () {
    it("should propose beacon change", async function () {
      const { tokenFactory, owner, viem } = await loadFixture(deployTokenFactoryFixture);

      const newErc20Impl = await viem.deployContract("ERC20V1", []);
      const newBeacon = await viem.deployContract("UpgradeableBeacon", [
        newErc20Impl.address,
        owner.account.address,
      ]);

      await tokenFactory.write.proposeBeaconChange([newBeacon.address], { account: owner.account });

      assert.strictEqual(await tokenFactory.read.pendingBeacon(), getAddress(newBeacon.address));
      assert.ok(((await tokenFactory.read.beaconChangeTime()) as bigint) > 0n);
    });

    it("should execute beacon change after timelock delay", async function () {
      const { tokenFactory, owner, viem } = await loadFixture(deployTokenFactoryFixture);

      const newErc20Impl = await viem.deployContract("ERC20V1", []);
      const newBeacon = await viem.deployContract("UpgradeableBeacon", [
        newErc20Impl.address,
        owner.account.address,
      ]);

      await tokenFactory.write.proposeBeaconChange([newBeacon.address], { account: owner.account });

      await assertions.revertWithCustomError(
        tokenFactory.write.executeBeaconChange([], { account: owner.account }),
        tokenFactory,
        "TimelockNotReady",
      );

      await time.increase(CONFIG_DELAY);
      await tokenFactory.write.executeBeaconChange([], { account: owner.account });

      assert.strictEqual(await tokenFactory.read.erc20Beacon(), getAddress(newBeacon.address));
      assert.strictEqual(await tokenFactory.read.pendingBeacon(), zeroAddress);
      assert.strictEqual(await tokenFactory.read.beaconChangeTime(), 0n);
    });

    it("should cancel pending beacon change", async function () {
      const { tokenFactory, owner, beacon, viem } = await loadFixture(deployTokenFactoryFixture);

      const newErc20Impl = await viem.deployContract("ERC20V1", []);
      const newBeacon = await viem.deployContract("UpgradeableBeacon", [
        newErc20Impl.address,
        owner.account.address,
      ]);

      await tokenFactory.write.proposeBeaconChange([newBeacon.address], { account: owner.account });
      await tokenFactory.write.cancelBeaconChange([], { account: owner.account });

      assert.strictEqual(await tokenFactory.read.pendingBeacon(), zeroAddress);
      assert.strictEqual(await tokenFactory.read.beaconChangeTime(), 0n);
      assert.strictEqual(await tokenFactory.read.erc20Beacon(), getAddress(beacon.address));
    });

    it("should reject execute/cancel when no pending change", async function () {
      const { tokenFactory, owner } = await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.executeBeaconChange([], { account: owner.account }),
        tokenFactory,
        "NoPendingChange",
      );
      await assertions.revertWithCustomError(
        tokenFactory.write.cancelBeaconChange([], { account: owner.account }),
        tokenFactory,
        "NoPendingChange",
      );
    });

    it("should reject non-contract address for beacon", async function () {
      const { tokenFactory, owner, user1 } = await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.proposeBeaconChange([user1.account.address], { account: owner.account }),
        tokenFactory,
        "InvalidImplementation",
      );
    });

    it("should reject non-owner calls", async function () {
      const { tokenFactory, user1, beacon } = await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.proposeBeaconChange([beacon.address], { account: user1.account }),
        tokenFactory,
        "OwnableUnauthorizedAccount",
      );
      await assertions.revertWithCustomError(
        tokenFactory.write.executeBeaconChange([], { account: user1.account }),
        tokenFactory,
        "OwnableUnauthorizedAccount",
      );
      await assertions.revertWithCustomError(
        tokenFactory.write.cancelBeaconChange([], { account: user1.account }),
        tokenFactory,
        "OwnableUnauthorizedAccount",
      );
    });
  });

  describe("Timelock: Treasury Change", function () {
    it("should propose, execute and cancel a treasury change", async function () {
      const { tokenFactory, owner, user1, platformTreasury } =
        await loadFixture(deployTokenFactoryFixture);

      await tokenFactory.write.proposeTreasuryChange([user1.account.address], {
        account: owner.account,
      });
      assert.strictEqual(
        await tokenFactory.read.pendingTreasury(),
        getAddress(user1.account.address),
      );

      await assertions.revertWithCustomError(
        tokenFactory.write.executeTreasuryChange([], { account: owner.account }),
        tokenFactory,
        "TimelockNotReady",
      );

      await time.increase(CONFIG_DELAY);
      await tokenFactory.write.executeTreasuryChange([], { account: owner.account });

      assert.strictEqual(
        await tokenFactory.read.platformTreasury(),
        getAddress(user1.account.address),
      );
      assert.strictEqual(await tokenFactory.read.pendingTreasury(), zeroAddress);
      void platformTreasury;
    });

    it("should reject non-owner calls", async function () {
      const { tokenFactory, user1, platformTreasury } =
        await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.proposeTreasuryChange([platformTreasury.account.address], {
          account: user1.account,
        }),
        tokenFactory,
        "OwnableUnauthorizedAccount",
      );
    });
  });

  describe("Timelock: PermitSigner Change", function () {
    it("should propose, execute and allow issuing with the new signer", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, owner } = fx;

      const newSignerPrivateKey =
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
      const newSigner = privateKeyToAccount(newSignerPrivateKey);

      await tokenFactory.write.proposePermitSignerChange([newSigner.address], {
        account: owner.account,
      });
      await time.increase(CONFIG_DELAY);
      await tokenFactory.write.executePermitSignerChange([], { account: owner.account });

      assert.strictEqual(await tokenFactory.read.permitSigner(), getAddress(newSigner.address));

      const { business, chainId } = fx;
      const deadline = (await time.latest()) + 3600n;
      const ratios = defaultRatios(fx.platformTreasury.account.address);
      const nonce = (await tokenFactory.read.nonces([business.account.address])) as bigint;
      const signature = await signIssuePermit({
        privateKey: newSignerPrivateKey,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: business.account.address,
        name: "NewSignerToken",
        symbol: "NST",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "",
        ratios,
        linkedLaunchpad: fx.launchpad.address,
        nonce,
        deadline,
      });

      await tokenFactory.write.issueToken(
        ["NewSignerToken", "NST", TOTAL_SUPPLY, "", ratios, deadline, signature],
        { account: business.account },
      );

      assert.strictEqual(await tokenFactory.read.getTokenCount(), 1n);
    });
  });

  describe("Timelock: Vesting Wallet Beacon", function () {
    it("should propose, execute and cancel a vesting wallet beacon change", async function () {
      const { tokenFactory, owner, viem, vestingWalletBeacon } =
        await loadFixture(deployTokenFactoryFixture);

      const newImpl = await viem.deployContract("TokenVestingWallet", []);
      const newBeacon = await viem.deployContract("UpgradeableBeacon", [
        newImpl.address,
        owner.account.address,
      ]);

      await tokenFactory.write.proposeVestingWalletBeaconChange([newBeacon.address], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        tokenFactory.write.executeVestingWalletBeaconChange([], { account: owner.account }),
        tokenFactory,
        "TimelockNotReady",
      );

      await time.increase(CONFIG_DELAY);
      await tokenFactory.write.executeVestingWalletBeaconChange([], { account: owner.account });
      assert.strictEqual(
        await tokenFactory.read.vestingWalletBeacon(),
        getAddress(newBeacon.address),
      );

      // Cancel path on a second proposal.
      const anotherImpl = await viem.deployContract("TokenVestingWallet", []);
      const anotherBeacon = await viem.deployContract("UpgradeableBeacon", [
        anotherImpl.address,
        owner.account.address,
      ]);
      await tokenFactory.write.proposeVestingWalletBeaconChange([anotherBeacon.address], {
        account: owner.account,
      });
      await tokenFactory.write.cancelVestingWalletBeaconChange([], { account: owner.account });
      assert.strictEqual(
        await tokenFactory.read.vestingWalletBeacon(),
        getAddress(newBeacon.address),
      );
      void vestingWalletBeacon;
    });
  });

  describe("Timelock: Linked Launchpad", function () {
    it("should propose, execute and cancel a linkedLaunchpad change", async function () {
      const { tokenFactory, owner, viem, launchpad } = await loadFixture(deployTokenFactoryFixture);

      const newLaunchpadImpl = await viem.deployContract("LaunchpadV1", []);

      await tokenFactory.write.proposeLinkedLaunchpadChange([newLaunchpadImpl.address], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        tokenFactory.write.executeLinkedLaunchpadChange([], { account: owner.account }),
        tokenFactory,
        "TimelockNotReady",
      );

      await time.increase(CONFIG_DELAY);
      await tokenFactory.write.executeLinkedLaunchpadChange([], { account: owner.account });
      assert.strictEqual(
        await tokenFactory.read.linkedLaunchpad(),
        getAddress(newLaunchpadImpl.address),
      );
      void launchpad;
    });

    it("should reject non-contract address", async function () {
      const { tokenFactory, owner, user1 } = await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.proposeLinkedLaunchpadChange([user1.account.address], {
          account: owner.account,
        }),
        tokenFactory,
        "InvalidImplementation",
      );
    });
  });

  describe("Timelock: Escrow Timeout", function () {
    it("should propose, execute and cancel an escrow timeout change", async function () {
      const { tokenFactory, owner } = await loadFixture(deployTokenFactoryFixture);

      await tokenFactory.write.proposeEscrowTimeoutChange([3n * 24n * 60n * 60n], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        tokenFactory.write.executeEscrowTimeoutChange([], { account: owner.account }),
        tokenFactory,
        "TimelockNotReady",
      );

      await time.increase(CONFIG_DELAY);
      await tokenFactory.write.executeEscrowTimeoutChange([], { account: owner.account });
      assert.strictEqual(await tokenFactory.read.escrowTimeoutSeconds(), 3n * 24n * 60n * 60n);

      await tokenFactory.write.proposeEscrowTimeoutChange([5n * 24n * 60n * 60n], {
        account: owner.account,
      });
      await tokenFactory.write.cancelEscrowTimeoutChange([], { account: owner.account });
      assert.strictEqual(await tokenFactory.read.escrowTimeoutSeconds(), 3n * 24n * 60n * 60n);
    });

    it("should reject a timeout outside [MIN_ESCROW_TIMEOUT, MAX_ESCROW_TIMEOUT]", async function () {
      const { tokenFactory, owner } = await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.proposeEscrowTimeoutChange([0n], { account: owner.account }),
        tokenFactory,
        "InvalidEscrowTimeout",
      );
      await assertions.revertWithCustomError(
        tokenFactory.write.proposeEscrowTimeoutChange([181n * 24n * 60n * 60n], {
          account: owner.account,
        }),
        tokenFactory,
        "InvalidEscrowTimeout",
      );
    });
  });

  describe("Timelock: Allocation Guide", function () {
    it("should propose, execute and cancel an allocation guide change", async function () {
      const { tokenFactory, owner } = await loadFixture(deployTokenFactoryFixture);

      await tokenFactory.write.proposeAllocationGuide([BUCKET_OWNER_VESTING, 500, 2000], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        tokenFactory.write.executeAllocationGuide([BUCKET_OWNER_VESTING], {
          account: owner.account,
        }),
        tokenFactory,
        "TimelockNotReady",
      );

      await time.increase(ALLOCATION_GUIDE_DELAY);
      await tokenFactory.write.executeAllocationGuide([BUCKET_OWNER_VESTING], {
        account: owner.account,
      });

      const [minBp, maxBp] = (await tokenFactory.read.getAllocationGuide([
        BUCKET_OWNER_VESTING,
      ])) as [number, number];
      assert.strictEqual(minBp, 500);
      assert.strictEqual(maxBp, 2000);

      await tokenFactory.write.proposeAllocationGuide([BUCKET_OWNER_VESTING, 0, 3000], {
        account: owner.account,
      });
      await tokenFactory.write.cancelAllocationGuide([BUCKET_OWNER_VESTING], {
        account: owner.account,
      });
      const [minBp2, maxBp2] = (await tokenFactory.read.getAllocationGuide([
        BUCKET_OWNER_VESTING,
      ])) as [number, number];
      assert.strictEqual(minBp2, 500);
      assert.strictEqual(maxBp2, 2000);
    });

    it("should reject an invalid guide (minBp > maxBp, or maxBp > BASIS_POINTS)", async function () {
      const { tokenFactory, owner } = await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.proposeAllocationGuide([BUCKET_OWNER_VESTING, 5000, 1000], {
          account: owner.account,
        }),
        tokenFactory,
        "InvalidAllocationGuide",
      );
      await assertions.revertWithCustomError(
        tokenFactory.write.proposeAllocationGuide([BUCKET_OWNER_VESTING, 0, 10001], {
          account: owner.account,
        }),
        tokenFactory,
        "InvalidAllocationGuide",
      );
    });

    it("should reject an out-of-range bucket index", async function () {
      const { tokenFactory, owner } = await loadFixture(deployTokenFactoryFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.proposeAllocationGuide([3, 0, 10000], { account: owner.account }),
        tokenFactory,
        "InvalidBucket",
      );
    });
  });

  describe("setTradeSettlement timelock + isPlatformContract registry", function () {
    it("bootstrap setTradeSettlement (from address(0)) works; a second immediate call reverts TradeSettlementAlreadySet", async function () {
      const { tokenFactory, owner, user1 } = await loadFixture(deployTokenFactoryFixture);

      await tokenFactory.write.setTradeSettlement([user1.account.address], {
        account: owner.account,
      });
      assert.strictEqual(await tokenFactory.read.tradeSettlement(), getAddress(user1.account.address));

      await assertions.revertWithCustomError(
        tokenFactory.write.setTradeSettlement([user1.account.address], { account: owner.account }),
        tokenFactory,
        "TradeSettlementAlreadySet",
      );
    });

    it("proposeTradeSettlementChange -> executeTradeSettlementChange is timelocked (2 days); early execute reverts", async function () {
      const { tokenFactory, owner, user1 } = await loadFixture(deployTokenFactoryFixture);

      await tokenFactory.write.setTradeSettlement([user1.account.address], {
        account: owner.account,
      });

      const newSettlement = privateKeyToAccount(
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
      );

      await tokenFactory.write.proposeTradeSettlementChange([newSettlement.address], {
        account: owner.account,
      });
      await assertions.revertWithCustomError(
        tokenFactory.write.executeTradeSettlementChange([], { account: owner.account }),
        tokenFactory,
        "TimelockNotReady",
      );

      await time.increase(CONFIG_DELAY);
      await tokenFactory.write.executeTradeSettlementChange([], { account: owner.account });
      assert.strictEqual(
        await tokenFactory.read.tradeSettlement(),
        getAddress(newSettlement.address),
      );

      // cancel path
      await tokenFactory.write.proposeTradeSettlementChange([user1.account.address], {
        account: owner.account,
      });
      await tokenFactory.write.cancelTradeSettlementChange([], { account: owner.account });
      assert.strictEqual(
        await tokenFactory.read.tradeSettlement(),
        getAddress(newSettlement.address),
      );
    });

    it("isPlatformContract recognizes the factory itself, linkedLaunchpad, tradeSettlement, and this token's vesting wallet — not an arbitrary address", async function () {
      const fx = await loadFixture(deployTokenFactoryFixture);
      const { tokenFactory, launchpad, owner, user1 } = fx;

      const { tokenAddress, vestingWallet } = await issueDefault(fx);

      await tokenFactory.write.setTradeSettlement([user1.account.address], {
        account: owner.account,
      });

      assert.strictEqual(
        await tokenFactory.read.isPlatformContract([tokenAddress, tokenFactory.address]),
        true,
      );
      assert.strictEqual(
        await tokenFactory.read.isPlatformContract([tokenAddress, launchpad.address]),
        true,
      );
      assert.strictEqual(
        await tokenFactory.read.isPlatformContract([tokenAddress, user1.account.address]),
        true,
      );
      assert.strictEqual(
        await tokenFactory.read.isPlatformContract([tokenAddress, vestingWallet]),
        true,
      );

      // index 4: distinct from owner(0)/business(1)/platformTreasury(2)/user1(3, == tradeSettlement above).
      const clients = await fx.viem.getWalletClients();
      const unrelatedAccount = clients[4];
      assert.strictEqual(
        await tokenFactory.read.isPlatformContract([tokenAddress, unrelatedAccount.account.address]),
        false,
      );
    });
  });

  describe("Timelocked UUPS Upgrade", function () {
    const DELAY = 48n * 60n * 60n;

    it("requestUpgrade -> immediate upgrade reverts UpgradeNotReady -> after 48h succeeds", async function () {
      const { tokenFactory, owner, viem } = await loadFixture(deployTokenFactoryFixture);
      const newImpl = await viem.deployContract("TokenFactory", []);

      await tokenFactory.write.requestUpgrade([newImpl.address], { account: owner.account });
      assert.strictEqual(
        getAddress((await tokenFactory.read.pendingImplementation()) as Address),
        getAddress(newImpl.address),
      );

      await assertions.revertWithCustomError(
        tokenFactory.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account }),
        tokenFactory,
        "UpgradeNotReady",
      );

      await time.increase(DELAY + 1n);
      await tokenFactory.write.upgradeToAndCall([newImpl.address, "0x"], { account: owner.account });

      assert.strictEqual(
        getAddress((await tokenFactory.read.pendingImplementation()) as Address),
        getAddress(zeroAddress),
      );
    });

    it("mismatched implementation reverts ImplementationMismatch", async function () {
      const { tokenFactory, owner, viem } = await loadFixture(deployTokenFactoryFixture);
      const implA = await viem.deployContract("TokenFactory", []);
      const implB = await viem.deployContract("TokenFactory", []);

      await tokenFactory.write.requestUpgrade([implA.address], { account: owner.account });
      await time.increase(DELAY + 1n);

      await assertions.revertWithCustomError(
        tokenFactory.write.upgradeToAndCall([implB.address, "0x"], { account: owner.account }),
        tokenFactory,
        "ImplementationMismatch",
      );
    });

    it("upgrade without a request reverts NoPendingUpgrade", async function () {
      const { tokenFactory, owner, viem } = await loadFixture(deployTokenFactoryFixture);
      const impl = await viem.deployContract("TokenFactory", []);

      await assertions.revertWithCustomError(
        tokenFactory.write.upgradeToAndCall([impl.address, "0x"], { account: owner.account }),
        tokenFactory,
        "NoPendingUpgrade",
      );
    });

    it("cancelUpgrade clears the pending request", async function () {
      const { tokenFactory, owner, viem } = await loadFixture(deployTokenFactoryFixture);
      const impl = await viem.deployContract("TokenFactory", []);

      await tokenFactory.write.requestUpgrade([impl.address], { account: owner.account });
      await tokenFactory.write.cancelUpgrade({ account: owner.account });

      assert.strictEqual(
        getAddress((await tokenFactory.read.pendingImplementation()) as Address),
        getAddress(zeroAddress),
      );

      await time.increase(DELAY + 1n);
      await assertions.revertWithCustomError(
        tokenFactory.write.upgradeToAndCall([impl.address, "0x"], { account: owner.account }),
        tokenFactory,
        "NoPendingUpgrade",
      );
    });
  });
});
