import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseUnits,
  encodeFunctionData,
  zeroAddress,
  Address,
  keccak256,
  toBytes,
  encodePacked,
  Hex,
  getAddress,
} from "viem";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import { privateKeyToAccount, signTypedData } from "viem/accounts";
import {
  deployTokenFactoryCore,
  configureDefaultAllocationGuides,
  setLinkedLaunchpad,
  setEscrowTimeout,
  issueTokenWithRatios,
  signIssuePermit,
  buildRatios,
} from "./tokenFactoryHelpers.js";

// Type definition for launchpad info (same as LaunchpadV1.test.ts)
interface LaunchpadInfo {
  tokenAddress: Address;
  businessAccount: Address;
  paymentToken: Address;
  tokenPrice: bigint;
  saleAmount: bigint;
  soldAmount: bigint;
  totalRaised: bigint;
  startTime: bigint;
  endTime: bigint;
  status: number;
  businessVerified: boolean;
}

/**
 * Security Test Suite
 *
 * Tests for vulnerabilities and attack scenarios:
 * 1. Access Control attacks
 * 2. Reentrancy protection
 * 3. EIP-712 signature verification
 * 4. Ownable2Step ownership transfer
 * 5. Blacklist owner protection
 * 6. Gas optimization (locked amount tracking)
 */

describe("Security Tests", function () {
  const PLATFORM_ALLOCATION_RATE = 1000n; // 10%
  const TOKEN_PRICE = parseUnits("1", 18);
  const TOTAL_SUPPLY = parseUnits("1000000", 18);

  // Test private key for signing (DO NOT USE IN PRODUCTION)
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

  async function deploySecurityFixture() {
    const { viem } = await getConnection();
    const [owner, attacker, business, user1, user2, feeRecipient, platformTreasury] =
      await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    // Deploy USDT
    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);

    // Deploy TokenFactory core (ERC20V1 beacon + TokenVestingWallet beacon + proxy)
    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);
    const {
      tokenFactory,
      erc20Beacon: beacon,
      erc20Impl,
    } = await deployTokenFactoryCore(
      viem,
      owner,
      platformTreasury.account.address,
      permitSigner.address,
    );
    await configureDefaultAllocationGuides(tokenFactory, owner);

    // Deploy LaunchpadV1
    const launchpadImpl = await viem.deployContract("LaunchpadV1", []);
    const launchpadInitData = encodeFunctionData({
      abi: launchpadImpl.abi,
      functionName: "initialize",
      args: [tokenFactory.address, usdt.address, feeRecipient.account.address],
    });
    const launchpadProxy = await viem.deployContract("ERC1967Proxy", [
      launchpadImpl.address,
      launchpadInitData,
    ]);
    const launchpad = await viem.getContractAt("LaunchpadV1", launchpadProxy.address);

    // Wire the real LaunchpadV1 as the factory's linkedLaunchpad — required
    // before issueToken can succeed at all, since the vesting wallet deploy needs it.
    await setLinkedLaunchpad(tokenFactory, owner, launchpad.address);
    // Escrow timeout must be set before issuing a token with a LAUNCHPAD bucket (fail-closed).
    await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n);

    // Mint USDT
    await usdt.write.mint([user1.account.address, parseUnits("1000000", 18)]);
    await usdt.write.mint([attacker.account.address, parseUnits("1000000", 18)]);

    const publicClient2 = publicClient;
    const chainId = await publicClient.getChainId();

    // Issue a token with a fixed 10% LAUNCHPAD bucket (= 100,000 of TOTAL_SUPPLY, the
    // exact `saleAmount` this file's tests hardcoded) via the business account
    // of the caller's choice. LIQUIDITY_RESERVE is routed to `platformTreasury` (a
    // neutral EOA, never used as `businessAccount` in this file).
    async function issueSimpleToken(
      business: { account: { address: Address } },
      name: string,
      symbol: string,
    ) {
      const ratios = buildRatios({
        launchpadBp: 1000,
        liquidityBp: 9000,
        ownerBp: 0,
        liquidityRecipient: platformTreasury.account.address,
      });
      return issueTokenWithRatios({
        tokenFactory,
        business: business as any,
        publicClient: publicClient2,
        chainId,
        permitPrivateKey: TEST_PRIVATE_KEY,
        linkedLaunchpad: launchpad.address,
        name,
        symbol,
        totalSupply: TOTAL_SUPPLY,
        contractURI: "https://example.com/meta.json",
        ratios,
      });
    }

    return {
      usdt,
      beacon,
      tokenFactory,
      launchpad,
      erc20Impl,
      owner,
      attacker,
      business,
      user1,
      user2,
      feeRecipient,
      platformTreasury,
      publicClient,
      permitSigner,
      viem,
      chainId,
      issueSimpleToken,
    };
  }

  describe("Access Control Tests", function () {
    it("should reject unauthorized launchpad creation for another business", async function () {
      const { launchpad, attacker, business, usdt, issueSimpleToken } =
        await loadFixture(deploySecurityFixture);

      // A REAL issued token (business is the factory-recorded issuer) is required to reach
      // the caller-authorization check (createLaunchpad now authenticates _businessAccount
      // against the factory-recorded issuer FIRST — C-1). Attacker passes the correct
      // _businessAccount (the true issuer) but is neither owner nor that issuer themselves.
      const { tokenAddress } = await issueSimpleToken(business, "BusinessToken", "BTK");

      await assertions.revertWithCustomError(
        launchpad.write.createLaunchpad(
          [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
          { account: attacker.account },
        ),
        launchpad,
        "NotBusinessOrOwner",
      );
    });

    it("should allow business to create their own launchpad", async function () {
      const { launchpad, business, usdt, viem, issueSimpleToken } =
        await loadFixture(deploySecurityFixture);

      // Issue token for business first (LAUNCHPAD bucket = 10% = 100,000, escrowed by
      // the factory — no approve/transfer needed, createLaunchpad derives it).
      const { tokenAddress } = await issueSimpleToken(business, "BusinessToken", "BTK");
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      // Business creates launchpad for themselves (should succeed) — saleAmount is
      // derived from the factory escrow, not caller-supplied.
      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, business.account.address, usdt.address, 0n, 0n],
        { account: business.account },
      );

      // Verify launchpad was created
      const launchpadInfo = (await launchpad.read.launchpads([0n])) as [
        string,
        string,
        string,
        bigint,
        bigint,
        bigint,
        bigint,
        bigint,
        bigint,
        number,
      ];
      assert.strictEqual(launchpadInfo[0], getAddress(business.account.address));
    });

    it("should reject unauthorized fee rate change", async function () {
      const { launchpad, attacker } = await loadFixture(deploySecurityFixture);

      await assertions.revertWithCustomError(
        launchpad.write.setLaunchpadFeeRate([500n], { account: attacker.account }),
        launchpad,
        "OwnableUnauthorizedAccount",
      );
    });

    it("should reject unauthorized pause", async function () {
      const { launchpad, attacker } = await loadFixture(deploySecurityFixture);

      await assertions.revertWithCustomError(
        launchpad.write.pause([], { account: attacker.account }),
        launchpad,
        "OwnableUnauthorizedAccount",
      );
    });

    it("should reject unauthorized TokenFactory permit signer change", async function () {
      const { tokenFactory, attacker, user1 } = await loadFixture(deploySecurityFixture);

      await assertions.revertWithCustomError(
        tokenFactory.write.proposePermitSignerChange([user1.account.address], {
          account: attacker.account,
        }),
        tokenFactory,
        "OwnableUnauthorizedAccount",
      );
    });
  });

  describe("Ownable2Step Tests", function () {
    it("UpgradeableBeacon requires 2-step ownership transfer", async function () {
      const { beacon, owner, attacker } = await loadFixture(deploySecurityFixture);

      // Step 1: Initiate transfer
      await beacon.write.transferOwnership([attacker.account.address], { account: owner.account });

      // Owner is still the original owner
      const currentOwner = (await beacon.read.owner()) as Address;
      assert.strictEqual(currentOwner.toLowerCase(), owner.account.address.toLowerCase());

      // Pending owner is set
      const pendingOwner = (await beacon.read.pendingOwner()) as Address;
      assert.strictEqual(pendingOwner.toLowerCase(), attacker.account.address.toLowerCase());

      // Step 2: Accept ownership
      await beacon.write.acceptOwnership([], { account: attacker.account });

      // Now attacker is owner
      const newOwner = (await beacon.read.owner()) as Address;
      assert.strictEqual(newOwner.toLowerCase(), attacker.account.address.toLowerCase());
    });

    it("USDT requires 2-step ownership transfer", async function () {
      const { usdt, owner, user1 } = await loadFixture(deploySecurityFixture);

      // Step 1: Initiate transfer
      await usdt.write.transferOwnership([user1.account.address], { account: owner.account });

      // Owner is still the original owner
      const currentOwner = (await usdt.read.owner()) as Address;
      assert.strictEqual(currentOwner.toLowerCase(), owner.account.address.toLowerCase());

      // Step 2: Accept ownership
      await usdt.write.acceptOwnership([], { account: user1.account });

      const newOwner = (await usdt.read.owner()) as Address;
      assert.strictEqual(newOwner.toLowerCase(), user1.account.address.toLowerCase());
    });

    it("should reject ownership acceptance from non-pending owner", async function () {
      const { beacon, owner, attacker, user1 } = await loadFixture(deploySecurityFixture);

      // Initiate transfer to user1
      await beacon.write.transferOwnership([user1.account.address], { account: owner.account });

      // Attacker tries to accept (should fail)
      await assertions.revertWithCustomError(
        beacon.write.acceptOwnership([], { account: attacker.account }),
        beacon,
        "OwnableUnauthorizedAccount",
      );
    });
  });

  describe("EIP-712 Signature Tests", function () {
    // Any bp split summing to 10000; the signature-rejection tests below never reach
    // the distribution logic, so the exact values are irrelevant.
    function dummyRatios(recipient: Address) {
      return buildRatios({
        launchpadBp: 1000,
        liquidityBp: 9000,
        ownerBp: 0,
        liquidityRecipient: recipient,
      });
    }

    it("should reject token issuance with invalid signature", async function () {
      const { tokenFactory, attacker, platformTreasury } = await loadFixture(deploySecurityFixture);

      // Deadline must be relative to chain time (not wall-clock `Date.now()`) — the
      // fixture already advanced the chain ~10 days via the allocation-guide/
      // linkedLaunchpad timelocks, so a wall-clock deadline would already be expired.
      const deadline = (await time.latest()) + 3600n;
      const invalidSignature = ("0x" + "00".repeat(65)) as Hex;
      const ratios = dummyRatios(platformTreasury.account.address);

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          [
            "Test Token",
            "TEST",
            TOTAL_SUPPLY,
            "https://example.com/meta.json",
            ratios,
            deadline,
            invalidSignature,
          ],
          { account: attacker.account },
        ),
        tokenFactory,
        "InvalidSignature",
      );
    });

    it("should reject token issuance with expired deadline", async function () {
      const { tokenFactory, attacker, platformTreasury } = await loadFixture(deploySecurityFixture);

      const expiredDeadline = (await time.latest()) - 3600n; // 1 hour ago (chain time)
      const invalidSignature = ("0x" + "00".repeat(65)) as Hex;
      const ratios = dummyRatios(platformTreasury.account.address);

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          [
            "Test Token",
            "TEST",
            TOTAL_SUPPLY,
            "https://example.com/meta.json",
            ratios,
            expiredDeadline,
            invalidSignature,
          ],
          { account: attacker.account },
        ),
        tokenFactory,
        "ExpiredDeadline",
      );
    });

    it("should reject signature from wrong signer", async function () {
      const { tokenFactory, attacker, launchpad, chainId, platformTreasury } =
        await loadFixture(deploySecurityFixture);

      const deadline = (await time.latest()) + 3600n;
      const nonce = (await tokenFactory.read.nonces([attacker.account.address])) as bigint;
      const ratios = dummyRatios(platformTreasury.account.address);

      // Sign with a different private key (not the permitSigner)
      const signature = await signIssuePermit({
        privateKey: "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex,
        chainId,
        verifyingContract: tokenFactory.address,
        businessAccount: attacker.account.address,
        name: "Test Token",
        symbol: "TEST",
        totalSupply: TOTAL_SUPPLY,
        contractURI: "https://example.com/meta.json",
        ratios,
        linkedLaunchpad: launchpad.address,
        nonce,
        deadline,
      });

      await assertions.revertWithCustomError(
        tokenFactory.write.issueToken(
          [
            "Test Token",
            "TEST",
            TOTAL_SUPPLY,
            "https://example.com/meta.json",
            ratios,
            deadline,
            signature,
          ],
          { account: attacker.account },
        ),
        tokenFactory,
        "InvalidSignature",
      );
    });
  });

  describe("Blacklist Owner Protection Tests", function () {
    it("should prevent owner from being blacklisted via addToBlacklist", async function () {
      const { owner, viem, issueSimpleToken } = await loadFixture(deploySecurityFixture);

      // Issue a token first (owner is the business account here)
      const { tokenAddress } = await issueSimpleToken(owner, "Test Token", "TEST");
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      // Token owner is now the business account (owner)
      const tokenOwner = (await token.read.owner()) as Address;
      assert.strictEqual(tokenOwner.toLowerCase(), owner.account.address.toLowerCase());

      // Try to blacklist the owner - should revert
      await assertions.revertWithCustomError(
        token.write.addToBlacklist([owner.account.address], { account: owner.account }),
        token,
        "CannotBlacklistOwner",
      );
    });

    it("should prevent owner from being blacklisted via batchAddToBlacklist", async function () {
      const { owner, user1, viem, issueSimpleToken } = await loadFixture(deploySecurityFixture);

      // Issue a token (owner is the business account here)
      const { tokenAddress } = await issueSimpleToken(owner, "Test Token", "TEST");
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      // Try batch blacklist including owner
      // The M-3 fix should skip the owner silently
      await token.write.batchAddToBlacklist([[owner.account.address, user1.account.address]], {
        account: owner.account,
      });

      // Owner should NOT be blacklisted
      const isOwnerBlacklisted = await token.read.blacklist([owner.account.address]);
      assert.strictEqual(isOwnerBlacklisted, false, "Owner should not be blacklisted");

      // User1 SHOULD be blacklisted
      const isUser1Blacklisted = await token.read.blacklist([user1.account.address]);
      assert.strictEqual(isUser1Blacklisted, true, "User1 should be blacklisted");
    });
  });

  describe("Launchpad Locked Amount Tests", function () {
    // The LAUNCHPAD bucket is fixed at 10% of TOTAL_SUPPLY in `issueSimpleToken` —
    // exactly the `saleAmount` these tests hardcoded. `createLaunchpad`
    // now derives it from the factory escrow (no approve/transfer needed).
    const saleAmount = parseUnits("100000", 18);

    it("should track locked token amounts correctly", async function () {
      const { launchpad, owner, usdt, viem, issueSimpleToken } =
        await loadFixture(deploySecurityFixture);

      const { tokenAddress } = await issueSimpleToken(owner, "Test Token", "TEST");
      const token = await viem.getContractAt("ERC20V1", tokenAddress);

      // Create launchpad — saleAmount is derived from the factory escrow.
      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, owner.account.address, usdt.address, 0n, 0n],
        { account: owner.account },
      );

      // Check locked amount
      const lockedAmount = await launchpad.read.lockedTokenAmount([tokenAddress]);
      assert.strictEqual(lockedAmount, saleAmount, "Locked amount should equal sale amount");

      // Try to recover more than available (should fail)
      const tokenBalance = await token.read.balanceOf([launchpad.address]);
      await assertions.revertWithCustomError(
        launchpad.write.recoverStuckTokens([tokenAddress, owner.account.address, tokenBalance], {
          account: owner.account,
        }),
        launchpad,
        "TokenLockedInActiveLaunchpad",
      );
    });

    it("should unlock tokens after finalization", async function () {
      const { launchpad, owner, usdt, viem, issueSimpleToken } =
        await loadFixture(deploySecurityFixture);

      const { tokenAddress } = await issueSimpleToken(owner, "Test Token", "TEST");

      // Set shorter durations for testing (MIN values)
      await launchpad.write.setPreparationTime([3600n], { account: owner.account }); // 1 hour (MIN)
      await launchpad.write.setLaunchpadDuration([86400n], { account: owner.account }); // 1 day (MIN)

      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, owner.account.address, usdt.address, 0n, 0n],
        { account: owner.account },
      );

      // Get launchpad info and fast forward past end time
      const launchpadInfo = (await launchpad.read.getLaunchpadInfo([0n])) as {
        startTime: bigint;
        endTime: bigint;
      };

      // Calculate how much time to advance: (endTime - current) + 1 second
      const currentTime = await time.latest();
      const timeToAdvance = launchpadInfo.endTime - currentTime + 1n;

      // Move time past end by increasing the calculated duration
      await time.increase(timeToAdvance);

      // Finalize
      await launchpad.write.finalizeLaunchpad([0n], { account: owner.account });

      // Locked amount should be 0
      const lockedAmount = await launchpad.read.lockedTokenAmount([tokenAddress]);
      assert.strictEqual(lockedAmount, 0n, "Locked amount should be 0 after finalization");
    });

    it("should unlock tokens after cancellation", async function () {
      const { launchpad, owner, usdt, issueSimpleToken } = await loadFixture(deploySecurityFixture);

      const { tokenAddress } = await issueSimpleToken(owner, "Test Token", "TEST");

      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, owner.account.address, usdt.address, 0n, 0n],
        { account: owner.account },
      );

      // Cancel launchpad (only works in Preparing state)
      await launchpad.write.cancelLaunchpad([0n], { account: owner.account });

      // Locked amount should be 0
      const lockedAmount = await launchpad.read.lockedTokenAmount([tokenAddress]);
      assert.strictEqual(lockedAmount, 0n, "Locked amount should be 0 after cancellation");
    });
  });

  describe("Finalize Status Consistency Tests", function () {
    it("should set Finalized status even with zero totalRaised", async function () {
      const { launchpad, owner, usdt, issueSimpleToken } = await loadFixture(deploySecurityFixture);

      const { tokenAddress } = await issueSimpleToken(owner, "Test Token", "TEST");

      // Set shorter durations
      await launchpad.write.setPreparationTime([3600n], { account: owner.account });
      await launchpad.write.setLaunchpadDuration([86400n], { account: owner.account });

      await launchpad.write.createLaunchpad(
        [tokenAddress, TOKEN_PRICE, owner.account.address, usdt.address, 0n, 0n],
        { account: owner.account },
      );

      // Get launchpad info and fast forward past end time WITHOUT any participation
      const launchpadInfo = (await launchpad.read.getLaunchpadInfo([0n])) as {
        startTime: bigint;
        endTime: bigint;
      };

      // Calculate how much time to advance: (endTime - current) + 1 second
      const currentTime = await time.latest();
      const timeToAdvance = launchpadInfo.endTime - currentTime + 1n;

      // Move time past end by increasing the calculated duration
      await time.increase(timeToAdvance);

      // Finalize with zero totalRaised
      await launchpad.write.finalizeLaunchpad([0n], { account: owner.account });

      // Check status is Finalized (not Ended)
      const finalInfo = (await launchpad.read.getLaunchpadInfo([0n])) as { status: number };
      // LaunchpadStatus.Finalized = 4
      assert.strictEqual(
        finalInfo.status,
        4,
        "Status should be Finalized (4) even with zero totalRaised",
      );
    });
  });
});
