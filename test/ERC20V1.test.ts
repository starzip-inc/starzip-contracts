import { describe, it } from "node:test";
import assert from "node:assert";
import { parseUnits, getAddress, Hex } from "viem";
import { loadFixture, getConnection, assertions } from "./helpers.js";
import { privateKeyToAccount } from "viem/accounts";
import {
  deployTokenFactoryCore,
  configureDefaultAllocationGuides,
  setLinkedLaunchpad,
  issueTokenWithRatios,
  buildRatios,
} from "./tokenFactoryHelpers.js";

describe("ERC20V1", function () {
  const TOTAL_SUPPLY = parseUnits("1000000", 18);
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

  async function deployTokenFixture() {
    const { viem } = await getConnection();
    const [owner, business, user1, user2] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    // Permit signer
    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);

    // Deploy the TokenFactory core (ERC20V1 beacon + TokenVestingWallet beacon + proxy),
    // wire permissive allocation guides + a linkedLaunchpad placeholder (the erc20Beacon
    // itself — a real contract address; these tests never exercise escrow/vesting-trigger).
    const { tokenFactory, erc20Beacon: beacon } = await deployTokenFactoryCore(
      viem,
      owner,
      owner.account.address,
      permitSigner.address,
    );
    await configureDefaultAllocationGuides(tokenFactory, owner);
    await setLinkedLaunchpad(tokenFactory, owner, beacon.address);

    // Issue one token. The entire LIQUIDITY_RESERVE bucket (100%, self-deal guard blocks
    // routing it directly to businessAccount at issuance time) is forwarded to `business`,
    // mirroring the "business holds ~90%+ immediately" assumption this file relies
    // on. Supply is fixed at issuance (TokenFactory locks `maxSupply == totalSupply`
    // immediately after minting) — there is no post-issuance mint path, so test accounts
    // that need a balance are funded via a plain `transfer` from `business`.
    const ratios = buildRatios({
      launchpadBp: 0,
      liquidityBp: 10000,
      ownerBp: 0,
      liquidityRecipient: owner.account.address,
    });
    const { tokenAddress } = await issueTokenWithRatios({
      tokenFactory,
      business,
      publicClient,
      chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: beacon.address,
      name: "TestToken",
      symbol: "TT",
      totalSupply: TOTAL_SUPPLY,
      contractURI: "https://example.com/metadata",
      ratios,
    });
    const token = await viem.getContractAt("ERC20V1", tokenAddress);

    const forwardAmount = (await token.read.balanceOf([owner.account.address])) as bigint;
    if (forwardAmount > 0n) {
      await token.write.transfer([business.account.address, forwardAmount], {
        account: owner.account,
      });
    }

    // Fund an arbitrary test account from the business's balance (supply is fixed —
    // there is no mint path available outside issuance).
    async function fundAccount(to: `0x${string}`, amount: bigint): Promise<void> {
      await token.write.transfer([to, amount], { account: business.account });
    }

    // owner = deployer (wallet #0) = TokenFactory owner
    // tokenOwner = business (wallet #1) = token owner after issuance
    return {
      token,
      beacon,
      tokenFactory,
      owner,
      tokenOwner: business,
      user1,
      user2,
      publicClient,
      viem,
      fundAccount,
    };
  }

  describe("Initialization", function () {
    it("should initialize correctly", async function () {
      const { token, tokenOwner, tokenFactory } = await loadFixture(deployTokenFixture);

      assert.strictEqual(await token.read.name(), "TestToken");
      assert.strictEqual(await token.read.symbol(), "TT");
      assert.strictEqual(await token.read.owner(), getAddress(tokenOwner.account.address));
      // launchpad is set to TokenFactory (msg.sender during initialize)
      assert.strictEqual(await token.read.launchpad(), getAddress(tokenFactory.address));
    });

    it("should have 18 decimals", async function () {
      const { token } = await loadFixture(deployTokenFixture);
      assert.strictEqual(await token.read.decimals(), 18);
    });
  });

  describe("Minting", function () {
    // Fixed-supply model: mint() is onlyLaunchpad (factory-only, used exclusively for the
    // initial issuance mint). There is no owner-initiated mint path anymore (the
    // mintWithApproval subsystem was removed once supply is locked at issuance).
    it("should reject minting by token owner (business)", async function () {
      const { token, tokenOwner, user1 } = await loadFixture(deployTokenFixture);

      await assertions.revertWithCustomError(
        token.write.mint([user1.account.address, parseUnits("1000", 18)], {
          account: tokenOwner.account,
        }),
        token,
        "NotLaunchpad",
      );
    });

    it("should reject minting by non-owner", async function () {
      const { token, user1, user2 } = await loadFixture(deployTokenFixture);

      await assertions.revert(
        token.write.mint([user2.account.address, parseUnits("1000", 18)], {
          account: user1.account,
        }),
      );
    });
  });

  describe("Max Supply", function () {
    it("is locked to totalSupply at issuance (fixed-supply)", async function () {
      const { token } = await loadFixture(deployTokenFixture);

      assert.strictEqual(await token.read.maxSupply(), TOTAL_SUPPLY);
      assert.strictEqual(await token.read.totalSupply(), TOTAL_SUPPLY);
    });

    it("should reject setting max supply again (already locked at issuance)", async function () {
      const { token, tokenOwner } = await loadFixture(deployTokenFixture);

      await assertions.revertWithCustomError(
        token.write.setMaxSupply([parseUnits("2000000", 18)], { account: tokenOwner.account }),
        token,
        "MaxSupplyAlreadySet",
      );
    });
  });

  describe("Blacklist", function () {
    it("should add to blacklist", async function () {
      const { token, tokenOwner, user1 } = await loadFixture(deployTokenFixture);

      // addToBlacklist uses onlyOwner (token owner)
      await token.write.addToBlacklist([user1.account.address], { account: tokenOwner.account });

      assert.strictEqual(await token.read.blacklist([user1.account.address]), true);
    });

    it("should remove from blacklist", async function () {
      const { token, tokenOwner, user1 } = await loadFixture(deployTokenFixture);

      // blacklist functions use onlyOwner (token owner)
      await token.write.addToBlacklist([user1.account.address], { account: tokenOwner.account });
      await token.write.removeFromBlacklist([user1.account.address], {
        account: tokenOwner.account,
      });

      assert.strictEqual(await token.read.blacklist([user1.account.address]), false);
    });

    it("should block transfers from blacklisted address", async function () {
      const { tokenOwner, user1, user2, fundAccount, token } =
        await loadFixture(deployTokenFixture);

      await fundAccount(user1.account.address, parseUnits("1000", 18));
      // addToBlacklist uses onlyOwner (token owner)
      await token.write.addToBlacklist([user1.account.address], { account: tokenOwner.account });

      await assertions.revertWithCustomError(
        token.write.transfer([user2.account.address, parseUnits("100", 18)], {
          account: user1.account,
        }),
        token,
        "AccountBlacklisted",
      );
    });

    it("should block transfers to blacklisted address", async function () {
      const { tokenOwner, user1, user2, fundAccount, token } =
        await loadFixture(deployTokenFixture);

      await fundAccount(user1.account.address, parseUnits("1000", 18));
      // addToBlacklist uses onlyOwner (token owner)
      await token.write.addToBlacklist([user2.account.address], { account: tokenOwner.account });

      await assertions.revertWithCustomError(
        token.write.transfer([user2.account.address, parseUnits("100", 18)], {
          account: user1.account,
        }),
        token,
        "AccountBlacklisted",
      );
    });

    it("should batch add to blacklist", async function () {
      const { token, tokenOwner, user1, user2 } = await loadFixture(deployTokenFixture);

      // batchAddToBlacklist uses onlyOwner (token owner)
      await token.write.batchAddToBlacklist([[user1.account.address, user2.account.address]], {
        account: tokenOwner.account,
      });

      assert.strictEqual(await token.read.blacklist([user1.account.address]), true);
      assert.strictEqual(await token.read.blacklist([user2.account.address]), true);
    });

    it("should batch remove from blacklist", async function () {
      const { token, tokenOwner, user1, user2 } = await loadFixture(deployTokenFixture);

      // batch blacklist functions use onlyOwner (token owner)
      await token.write.batchAddToBlacklist([[user1.account.address, user2.account.address]], {
        account: tokenOwner.account,
      });
      await token.write.batchRemoveFromBlacklist([[user1.account.address, user2.account.address]], {
        account: tokenOwner.account,
      });

      assert.strictEqual(await token.read.blacklist([user1.account.address]), false);
      assert.strictEqual(await token.read.blacklist([user2.account.address]), false);
    });
  });

  describe("Burning", function () {
    it("should allow holder to burn their tokens", async function () {
      const { user1, fundAccount, token } = await loadFixture(deployTokenFixture);

      await fundAccount(user1.account.address, parseUnits("1000", 18));

      await token.write.burn([parseUnits("100", 18)], { account: user1.account });

      assert.strictEqual(
        await token.read.balanceOf([user1.account.address]),
        parseUnits("900", 18),
      );
    });

    it("should reject burning zero amount", async function () {
      const { user1, fundAccount, token } = await loadFixture(deployTokenFixture);

      await fundAccount(user1.account.address, parseUnits("1000", 18));

      await assertions.revertWithCustomError(
        token.write.burn([0n], { account: user1.account }),
        token,
        "ZeroAmount",
      );
    });

    it("should reject burning by blacklisted user", async function () {
      const { tokenOwner, user1, fundAccount, token } = await loadFixture(deployTokenFixture);

      await fundAccount(user1.account.address, parseUnits("1000", 18));
      // addToBlacklist uses onlyOwner (token owner)
      await token.write.addToBlacklist([user1.account.address], { account: tokenOwner.account });

      await assertions.revertWithCustomError(
        token.write.burn([parseUnits("100", 18)], { account: user1.account }),
        token,
        "AccountBlacklisted",
      );
    });
  });

  describe("Pausable", function () {
    it("should pause transfers", async function () {
      const { tokenOwner, user1, user2, fundAccount, token } =
        await loadFixture(deployTokenFixture);

      await fundAccount(user1.account.address, parseUnits("1000", 18));
      // pause requires onlyOwner (token owner)
      await token.write.pause([], { account: tokenOwner.account });

      await assertions.revert(
        token.write.transfer([user2.account.address, parseUnits("100", 18)], {
          account: user1.account,
        }),
      );
    });

    it("should unpause transfers", async function () {
      const { tokenOwner, user1, user2, fundAccount, token } =
        await loadFixture(deployTokenFixture);

      await fundAccount(user1.account.address, parseUnits("1000", 18));
      // pause/unpause requires onlyOwner (token owner)
      await token.write.pause([], { account: tokenOwner.account });
      await token.write.unpause([], { account: tokenOwner.account });

      await token.write.transfer([user2.account.address, parseUnits("100", 18)], {
        account: user1.account,
      });

      assert.strictEqual(
        await token.read.balanceOf([user2.account.address]),
        parseUnits("100", 18),
      );
    });
  });

  describe("Contract URI", function () {
    it("should update contract URI", async function () {
      const { token, tokenOwner } = await loadFixture(deployTokenFixture);

      const newURI = "https://new-example.com/metadata";
      // setContractURI uses onlyOwner (token owner)
      await token.write.setContractURI([newURI], { account: tokenOwner.account });

      assert.strictEqual(await token.read.contractURI(), newURI);
    });
  });

  describe("Version", function () {
    it("should return version 1", async function () {
      const { token } = await loadFixture(deployTokenFixture);
      assert.strictEqual(await token.read.version(), 1n);
    });
  });
});
