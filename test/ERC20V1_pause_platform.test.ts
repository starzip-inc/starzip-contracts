/**
 * ERC20V1 pause must not brick platform rails.
 *
 * A business owner holds `pause()` on its own token AND its users' tokens sit inside
 * TradeSettlementV1 non-custodially. Before this carve-out, `pause()` made
 * `withdrawToken` / `batchWithdraw` / `emergencyWithdrawFor` revert with `EnforcedPause()`
 * while `settleOrders` (balance-only, no external calls) kept matching — users went on
 * buying ledger claims against an asset nobody could redeem.
 *
 * narrowed the carve-out to the FROM side. Exempting `to` as well let a thief keep using
 * the exchange as a laundering route while the token was paused — deposit stolen supply into
 * TradeSettlement, let `settleOrders` (balance-only, pause-blind) fill it, cash out in USDT —
 * and bought nothing, because every leg the carve-out exists for is outbound.
 *
 * These tests pin the resulting property set:
 *   - OUTBOUND platform legs (mint, from-platform) execute while paused;
 *   - INBOUND platform legs (deposits into settlement/escrow) are BLOCKED while paused —
 *     pause is a one-way valve, and the laundering route is shut;
 *   - ordinary user<->user transfers still do NOT execute — the exemption is no wider than needed;
 * - the blacklist carve-out is UNCHANGED (still FROM-side only) and still fail-closed
 *     when the platform registry is unreachable.
 *
 * Fixtures are local by design: `test/TradeSettlementV1_*.test.ts` must not be touched.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { loadFixture, getConnection, assertions } from "./helpers.js";
import { parseUnits, encodeFunctionData, zeroAddress, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { deploySimpleTokenFixture } from "./tokenFactoryHelpers.js";

describe("ERC20V1 pause carve-out for platform legs", function () {
  const TOTAL_SUPPLY = parseUnits("1000000", 18);
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

  const DEPOSIT = parseUnits("1000", 18);

  /**
   * Token issued through TokenFactory (so `_isPlatform` resolves against a REAL registry),
   * `alice` is the business / token owner, plus a TradeSettlementV1 proxy registered in that
   * registry with `bob` and `charlie` holding deposited balances.
   */
  async function deployFixture() {
    const { viem } = await getConnection();
    const [owner, alice, bob, charlie, feeRecipient] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);
    const { token, tokenFactory } = await deploySimpleTokenFixture({
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

    const usdt = await viem.deployContract("USDT", [owner.account.address, 18]);

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

    await settlement.write.setSupportedToken([token.address, true]);
    await settlement.write.setSupportedToken([usdt.address, true]);

    // Required for `_isPlatform(settlement) == true` — the registry starts at address(0).
    await tokenFactory.write.setTradeSettlement([settlement.address], { account: owner.account });

    // bob + charlie get tokens from the business, then deposit them into settlement
    // (all of this happens BEFORE any pause).
    for (const user of [bob, charlie]) {
      await token.write.transfer([user.account.address, DEPOSIT * 2n], { account: alice.account });
      await token.write.approve([settlement.address, DEPOSIT], { account: user.account });
      await settlement.write.depositToken([token.address, DEPOSIT], { account: user.account });
    }

    await usdt.write.mint([charlie.account.address, DEPOSIT]);
    await usdt.write.approve([settlement.address, DEPOSIT], { account: charlie.account });
    await settlement.write.depositToken([usdt.address, DEPOSIT], { account: charlie.account });

    return { token, tokenFactory, settlement, usdt, owner, alice, bob, charlie, publicClient };
  }

  /**
   * ERC20V1 deployed BY a `MockPlatformRegistry`, so `launchpad` — the mint authority and
   * the registry `_isPlatform` consults — is a mock the test can steer. Needed because a
   * factory-issued token can exercise neither edge: `TokenFactory` locks
   * `maxSupply == totalSupply` at issuance (no reachable post-issuance mint) and its
   * `isPlatformContract` never reverts (the fail-closed `catch` stays unreachable).
   * `deployer` is the token OWNER (pause / blacklist authority); the mock is the launchpad.
   */
  async function deployMockRegistryFixture() {
    const { viem } = await getConnection();
    const [deployer, user1, user2] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    const registry = await viem.deployContract("MockPlatformRegistry", []);
    const impl = await viem.deployContract("ERC20V1", []);
    const initData = encodeFunctionData({
      abi: impl.abi,
      functionName: "initialize",
      args: [deployer.account.address, "Mocked", "MCK", "ipfs://mocked"],
    });

    const hash = await registry.write.deployToken([impl.address, initData]);
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    // ERC1967Proxy's only constructor log is `Upgraded(implementation)`, emitted by the proxy.
    const tokenAddress = receipt.logs[0].address as `0x${string}`;
    const token = await viem.getContractAt("ERC20V1", tokenAddress);

    assert.strictEqual(
      ((await token.read.launchpad()) as string).toLowerCase(),
      registry.address.toLowerCase(),
    );
    // No maxSupply cap was ever set on this token, so `mint` stays reachable.
    assert.strictEqual((await token.read.maxSupply()) as bigint, 0n);

    await registry.write.mint([token.address, user1.account.address, DEPOSIT]);

    return { token, registry, deployer, user1, user2 };
  }

  // ===================================================================
  // 1. Core regression: a paused token must not trap balances already in settlement
  // ===================================================================
  describe("settlement withdrawals survive a business pause", function () {
    it("withdrawToken succeeds while the business has the token paused", async function () {
      const { token, settlement, alice, bob } = await loadFixture(deployFixture);

      await token.write.pause({ account: alice.account });
      assert.strictEqual(await token.read.paused(), true);

      const before = (await token.read.balanceOf([bob.account.address])) as bigint;
      await settlement.write.withdrawToken([token.address, DEPOSIT], { account: bob.account });
      const after = (await token.read.balanceOf([bob.account.address])) as bigint;

      assert.strictEqual(after - before, DEPOSIT);
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, token.address])) as bigint,
        0n,
      );
      // Pause is still on — the carve-out is per-leg, not a silent unpause.
      assert.strictEqual(await token.read.paused(), true);
    });

    it("batchWithdraw succeeds while paused (paused base leg + unpausable USDT leg)", async function () {
      const { token, settlement, usdt, alice, charlie } = await loadFixture(deployFixture);

      await token.write.pause({ account: alice.account });

      const tokenBefore = (await token.read.balanceOf([charlie.account.address])) as bigint;
      const usdtBefore = (await usdt.read.balanceOf([charlie.account.address])) as bigint;

      await settlement.write.batchWithdraw([[token.address, usdt.address]], {
        account: charlie.account,
      });

      assert.strictEqual(
        ((await token.read.balanceOf([charlie.account.address])) as bigint) - tokenBefore,
        DEPOSIT,
      );
      assert.strictEqual(
        ((await usdt.read.balanceOf([charlie.account.address])) as bigint) - usdtBefore,
        DEPOSIT,
      );
    });

    it("emergencyWithdrawFor (owner backstop) succeeds while paused", async function () {
      const { token, settlement, owner, alice, bob } = await loadFixture(deployFixture);

      await token.write.pause({ account: alice.account });

      const before = (await token.read.balanceOf([bob.account.address])) as bigint;
      await settlement.write.emergencyWithdrawFor([bob.account.address, token.address], {
        account: owner.account,
      });

      assert.strictEqual(
        ((await token.read.balanceOf([bob.account.address])) as bigint) - before,
        DEPOSIT,
      );
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, token.address])) as bigint,
        0n,
      );
    });
  });

  // ===================================================================
  // 1b. the INBOUND direction is blocked — pause is a one-way valve
  // ===================================================================
  describe("deposits into platform infra are BLOCKED while paused", function () {
    it("LAUNDERING ROUTE SHUT: depositToken of a paused token reverts with EnforcedPause", async function () {
      const { token, settlement, alice, bob } = await loadFixture(deployFixture);

      // The thief holds stolen supply outside the exchange (bob was funded DEPOSIT * 2 and
      // deposited DEPOSIT, so DEPOSIT remains in his wallet) and is pre-approved.
      await token.write.approve([settlement.address, DEPOSIT], { account: bob.account });

      // The business detects the theft and pulls the pause.
      await token.write.pause({ account: alice.account });

      // Step 1 of the laundering chain — getting the stolen supply INTO the exchange — now fails.
      // Everything downstream (settleOrders, the USDT cash-out, the buyer's withdrawal of the
      // stolen token) is unreachable because no new claim against the paused token can be created.
      await assertions.revertWithCustomError(
        settlement.write.depositToken([token.address, DEPOSIT], { account: bob.account }),
        token,
        "EnforcedPause",
      );

      // Containment holds: the settlement ledger did not grow, and the stolen supply is stuck.
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, token.address])) as bigint,
        DEPOSIT,
      );
      assert.strictEqual((await token.read.balanceOf([bob.account.address])) as bigint, DEPOSIT);
    });

    it("a raw transfer TO the settlement contract is equally blocked (not just the deposit entrypoint)", async function () {
      const { token, settlement, alice, bob } = await loadFixture(deployFixture);

      await token.write.pause({ account: alice.account });

      await assertions.revertWithCustomError(
        token.write.transfer([settlement.address, DEPOSIT], { account: bob.account }),
        token,
        "EnforcedPause",
      );
    });

    it("a transfer TO the TokenFactory (escrow funding leg) is blocked while paused", async function () {
      const { token, tokenFactory, alice, bob } = await loadFixture(deployFixture);

      // `isPlatformContract` returns true for the factory itself, so this is a genuine
      // `_isPlatform(to)` leg — and it must still be paused.
      await token.write.pause({ account: alice.account });

      await assertions.revertWithCustomError(
        token.write.transfer([tokenFactory.address, DEPOSIT], { account: bob.account }),
        token,
        "EnforcedPause",
      );
    });

    it("unpause restores deposits (the block is the pause, not a permanent rule)", async function () {
      const { token, settlement, alice, bob } = await loadFixture(deployFixture);

      await token.write.approve([settlement.address, DEPOSIT], { account: bob.account });
      await token.write.pause({ account: alice.account });
      await token.write.unpause({ account: alice.account });

      await settlement.write.depositToken([token.address, DEPOSIT], { account: bob.account });
      assert.strictEqual(
        (await settlement.read.getBalance([bob.account.address, token.address])) as bigint,
        DEPOSIT * 2n,
      );
    });
  });

  // ===================================================================
  // 2. The exemption is no wider than needed
  // ===================================================================
  describe("ordinary transfers stay paused", function () {
    it("user -> user transfer still reverts with EnforcedPause", async function () {
      const { token, alice, bob, charlie } = await loadFixture(deployFixture);

      await token.write.pause({ account: alice.account });

      await assertions.revertWithCustomError(
        token.write.transfer([charlie.account.address, DEPOSIT], { account: bob.account }),
        token,
        "EnforcedPause",
      );
    });

    it("the business that pressed pause is not itself exempt", async function () {
      const { token, alice, bob } = await loadFixture(deployFixture);

      await token.write.pause({ account: alice.account });

      await assertions.revertWithCustomError(
        token.write.transfer([bob.account.address, DEPOSIT], { account: alice.account }),
        token,
        "EnforcedPause",
      );
    });

    it("unpause restores ordinary transfers", async function () {
      const { token, alice, bob, charlie } = await loadFixture(deployFixture);

      await token.write.pause({ account: alice.account });
      await token.write.unpause({ account: alice.account });

      // charlie was funded with DEPOSIT * 2 and deposited DEPOSIT, so he holds DEPOSIT.
      await token.write.transfer([charlie.account.address, DEPOSIT], { account: bob.account });
      assert.strictEqual(
        (await token.read.balanceOf([charlie.account.address])) as bigint,
        DEPOSIT * 2n,
      );
    });
  });

  // ===================================================================
  // 3. Minting under pause — pinned decision: mints are a platform leg
  // ===================================================================
  describe("mint under pause (from == address(0))", function () {
    it("PINNED: mint succeeds while paused — a mint is a platform leg", async function () {
      const { token, registry, deployer, user2 } = await loadFixture(deployMockRegistryFixture);

      await token.write.pause({ account: deployer.account });

      await registry.write.mint([token.address, user2.account.address, DEPOSIT]);
      assert.strictEqual((await token.read.balanceOf([user2.account.address])) as bigint, DEPOSIT);
      assert.strictEqual(await token.read.paused(), true);
    });

    it("burn (to == address(0)) is NOT a platform leg and stays paused", async function () {
      const { token, deployer, user1 } = await loadFixture(deployMockRegistryFixture);

      await token.write.pause({ account: deployer.account });

      await assertions.revertWithCustomError(
        token.write.burn([DEPOSIT], { account: user1.account }),
        token,
        "EnforcedPause",
      );
    });
  });

  // ===================================================================
  // 4. `_isPlatform` stays fail-closed when the registry misbehaves
  // ===================================================================
  describe("fail-closed registry", function () {
    it("a reverting registry does not open the pause gate for a registered platform SENDER", async function () {
      const { token, registry, deployer, user1, user2 } =
        await loadFixture(deployMockRegistryFixture);

      // user1 (who holds the minted balance) IS registered platform infra: while the registry
      // answers, its OUTBOUND leg is exempt.
      await registry.write.setPlatform([user1.account.address, true]);
      await token.write.pause({ account: deployer.account });
      await token.write.transfer([user2.account.address, DEPOSIT / 2n], { account: user1.account });

      // Registry starts reverting -> `_isPlatform` catches and returns false -> pause bites again.
      await registry.write.setShouldRevert([true]);
      await assertions.revertWithCustomError(
        token.write.transfer([user2.account.address, DEPOSIT / 2n], { account: user1.account }),
        token,
        "EnforcedPause",
      );
    });

    it("a registered platform RECIPIENT gets no pause exemption even with a healthy registry", async function () {
      const { token, registry, deployer, user1, user2 } =
        await loadFixture(deployMockRegistryFixture);

      // user2 IS registered platform infra and the registry answers cleanly — under the old
      // `|| _isPlatform(to)` width this transfer went through. It must not any more.
      await registry.write.setPlatform([user2.account.address, true]);
      await token.write.pause({ account: deployer.account });

      await assertions.revertWithCustomError(
        token.write.transfer([user2.account.address, DEPOSIT / 2n], { account: user1.account }),
        token,
        "EnforcedPause",
      );
      assert.strictEqual((await token.read.balanceOf([user2.account.address])) as bigint, 0n);
    });

    it("a reverting registry keeps the blacklist enforced (fail-closed)", async function () {
      const { token, registry, deployer, user1, user2 } =
        await loadFixture(deployMockRegistryFixture);

      // user1 is registered platform infra AND blacklisted: the FROM-bypass applies...
      await registry.write.setPlatform([user1.account.address, true]);
      await token.write.addToBlacklist([user1.account.address], { account: deployer.account });
      await token.write.transfer([user2.account.address, DEPOSIT / 2n], { account: user1.account });

      // ...but once the registry reverts, the exemption is withheld, not granted.
      await registry.write.setShouldRevert([true]);
      await assertions.revertWithCustomError(
        token.write.transfer([user2.account.address, DEPOSIT / 2n], { account: user1.account }),
        token,
        "AccountBlacklisted",
      );
    });

    it("an unregistered TradeSettlement is not pause-exempt (registry drives the carve-out)", async function () {
      const { viem } = await getConnection();
      const [owner, alice, bob, , feeRecipient] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const chainId = await publicClient.getChainId();

      const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);
      const { token } = await deploySimpleTokenFixture({
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
        name: "Unregistered",
        symbol: "UNR",
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
      await settlement.write.setSupportedToken([token.address, true]);

      await token.write.transfer([bob.account.address, DEPOSIT], { account: alice.account });
      await token.write.approve([settlement.address, DEPOSIT], { account: bob.account });
      await settlement.write.depositToken([token.address, DEPOSIT], { account: bob.account });

      // `setTradeSettlement` was never called, so `isPlatformContract(settlement) == false`.
      await token.write.pause({ account: alice.account });
      await assertions.revertWithCustomError(
        settlement.write.withdrawToken([token.address, DEPOSIT], { account: bob.account }),
        token,
        "EnforcedPause",
      );
    });
  });

  // ===================================================================
  // 5. blacklist behaviour is UNCHANGED by the pause carve-out
  // ===================================================================
  describe("blacklist regression (unchanged)", function () {
    it("blacklisted user's withdrawToken still succeeds (platform FROM-bypass)", async function () {
      const { token, settlement, alice, bob } = await loadFixture(deployFixture);

      await token.write.addToBlacklist([bob.account.address], { account: alice.account });

      const before = (await token.read.balanceOf([bob.account.address])) as bigint;
      await settlement.write.withdrawToken([token.address, DEPOSIT], { account: bob.account });
      assert.strictEqual(
        ((await token.read.balanceOf([bob.account.address])) as bigint) - before,
        DEPOSIT,
      );
    });

    it("blacklisted user's depositToken still reverts — the TO side is NOT blacklist-exempt", async function () {
      const { token, settlement, alice, bob } = await loadFixture(deployFixture);

      await token.write.addToBlacklist([bob.account.address], { account: alice.account });
      await token.write.approve([settlement.address, DEPOSIT], { account: bob.account });

      await assertions.revertWithCustomError(
        settlement.write.depositToken([token.address, DEPOSIT], { account: bob.account }),
        token,
        "AccountBlacklisted",
      );
    });

    it("blacklisted user -> user transfer still reverts", async function () {
      const { token, alice, bob, charlie } = await loadFixture(deployFixture);

      await token.write.addToBlacklist([bob.account.address], { account: alice.account });

      await assertions.revertWithCustomError(
        token.write.transfer([charlie.account.address, DEPOSIT], { account: bob.account }),
        token,
        "AccountBlacklisted",
      );
    });

    it("blacklist + pause compose: blacklisted user's withdraw works, their transfer does not", async function () {
      const { token, settlement, alice, bob, charlie } = await loadFixture(deployFixture);

      await token.write.addToBlacklist([bob.account.address], { account: alice.account });
      await token.write.pause({ account: alice.account });

      await settlement.write.withdrawToken([token.address, DEPOSIT], { account: bob.account });

      await assertions.revertWithCustomError(
        token.write.transfer([charlie.account.address, DEPOSIT], { account: bob.account }),
        token,
        "AccountBlacklisted",
      );
    });
  });
});
