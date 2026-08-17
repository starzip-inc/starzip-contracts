/**
 * UpgradeableBeacon — 48h upgrade timelock .
 *
 * Before this change `upgradeTo` was a bare `onlyOwner` setter: ONE transaction from the
 * beacon owner rewrote the implementation of EVERY `BeaconProxy` pointing at it. Since every
 * ERC20V1 token is a `BeaconProxy` and `BeaconProxy._beacon` is immutable, that included
 * tokens sitting in the `TradeSettlementV1` escrow — and `recoverStuckTokens` keys recovery on
 * `IERC20(token).balanceOf(address(this)) - totalTracked[token]`, i.e. it asks the freshly
 * swapped token contract how much it holds. A malicious implementation reporting an inflated
 * balance therefore invents "recoverable excess" over user deposits, defeating the
 * ledger guard. TradeSettlementV1 already timelocks its own upgrades 48h; the asset layer
 * underneath it did not — same asymmetry, one layer down.
 *
 * The fix mirrors TradeSettlementV1's pattern exactly: `requestUpgrade` stages,
 * `upgradeTo` executes only the staged address and only after `UPGRADE_TIMELOCK_DELAY`,
 * staging is single-use, and `cancelUpgrade` aborts inside the window.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import {
  encodeFunctionData,
  getAddress,
  parseEventLogs,
  parseUnits,
  zeroAddress,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { deploySimpleTokenFixture } from "./tokenFactoryHelpers.js";

const FORTY_EIGHT_HOURS = 48n * 60n * 60n;
const SEVEN_DAYS = 7n * 24n * 60n * 60n;

describe("UpgradeableBeacon — 48h upgrade timelock", function () {
  async function deployBeaconFixture() {
    const { viem } = await getConnection();
    const [owner, attacker] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    // Three distinct, real implementation contracts: the live one plus two candidates.
    const implA = await viem.deployContract("ERC20V1", []);
    const implB = await viem.deployContract("ERC20V1", []);
    const implC = await viem.deployContract("ERC20V1", []);

    const beacon = await viem.deployContract("UpgradeableBeacon", [
      implA.address,
      owner.account.address,
    ]);

    // Stand-in for the payload an owner would actually want to pre-arm: an implementation that
    // forges balanceOf, i.e. the input TradeSettlementV1.recoverStuckTokens trusts.
    const evilLike = await viem.deployContract("MaliciousTokenImpl", []);

    return { viem, publicClient, owner, attacker, beacon, implA, implB, implC, evilLike };
  }

  describe("staging + delay", function () {
    it("exposes a 48 hour delay and starts with no staged upgrade", async function () {
      const { beacon, implA } = await loadFixture(deployBeaconFixture);

      assert.strictEqual(await beacon.read.UPGRADE_TIMELOCK_DELAY(), FORTY_EIGHT_HOURS);
      assert.strictEqual(await beacon.read.pendingImplementation(), zeroAddress);
      assert.strictEqual(await beacon.read.upgradeReadyAt(), 0n);
      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implA.address),
      );
    });

    it("1. upgradeTo without requestUpgrade reverts (no instant swap)", async function () {
      const { beacon, owner, implA, implB } = await loadFixture(deployBeaconFixture);

      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implB.address], { account: owner.account }),
        beacon,
        "NoPendingUpgrade",
      );

      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implA.address),
        "implementation must be untouched",
      );
    });

    it("2. upgradeTo before the 48h elapses reverts (incl. one second early)", async function () {
      const { beacon, owner, implA, implB } = await loadFixture(deployBeaconFixture);

      await beacon.write.requestUpgrade([implB.address], { account: owner.account });

      const readyAt = (await beacon.read.upgradeReadyAt()) as bigint;
      assert.strictEqual(
        getAddress((await beacon.read.pendingImplementation()) as `0x${string}`),
        getAddress(implB.address),
      );
      assert.strictEqual(readyAt, (await time.latest()) + FORTY_EIGHT_HOURS);

      // Immediately after staging.
      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implB.address], { account: owner.account }),
        beacon,
        "UpgradeNotReady",
      );

      // One second before maturity — the boundary the attacker would try to shave.
      await time.increaseTo(readyAt - 2n);
      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implB.address], { account: owner.account }),
        beacon,
        "UpgradeNotReady",
      );

      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implA.address),
        "implementation must still be the old one",
      );
    });

    it("3. succeeds after 48h, and the same staging cannot be reused", async function () {
      const { beacon, owner, implB } = await loadFixture(deployBeaconFixture);

      await beacon.write.requestUpgrade([implB.address], { account: owner.account });
      await time.increase(FORTY_EIGHT_HOURS);

      await beacon.write.upgradeTo([implB.address], { account: owner.account });
      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implB.address),
      );

      // Staging is single-use: consumed and cleared.
      assert.strictEqual(await beacon.read.pendingImplementation(), zeroAddress);
      assert.strictEqual(await beacon.read.upgradeReadyAt(), 0n);

      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implB.address], { account: owner.account }),
        beacon,
        "NoPendingUpgrade",
      );
    });

    it("4. upgradeTo with an implementation other than the staged one reverts", async function () {
      const { beacon, owner, implA, implB, implC } = await loadFixture(deployBeaconFixture);

      await beacon.write.requestUpgrade([implB.address], { account: owner.account });
      await time.increase(FORTY_EIGHT_HOURS);

      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implC.address], { account: owner.account }),
        beacon,
        "NoPendingUpgrade",
      );

      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implA.address),
      );
      // The mismatched attempt must not burn the legitimate staging.
      assert.strictEqual(
        getAddress((await beacon.read.pendingImplementation()) as `0x${string}`),
        getAddress(implB.address),
      );
    });

    it("re-staging overwrites the candidate and restarts the clock", async function () {
      const { beacon, owner, implB, implC } = await loadFixture(deployBeaconFixture);

      await beacon.write.requestUpgrade([implB.address], { account: owner.account });
      await time.increase(FORTY_EIGHT_HOURS);

      await beacon.write.requestUpgrade([implC.address], { account: owner.account });
      assert.strictEqual(
        getAddress((await beacon.read.pendingImplementation()) as `0x${string}`),
        getAddress(implC.address),
      );
      assert.strictEqual(
        await beacon.read.upgradeReadyAt(),
        (await time.latest()) + FORTY_EIGHT_HOURS,
      );

      // The old candidate's matured clock is gone with it.
      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implB.address], { account: owner.account }),
        beacon,
        "NoPendingUpgrade",
      );
      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implC.address], { account: owner.account }),
        beacon,
        "UpgradeNotReady",
      );
    });

    it("requestUpgrade rejects a non-contract implementation", async function () {
      const { beacon, owner, attacker } = await loadFixture(deployBeaconFixture);

      await assertions.revertWithCustomError(
        beacon.write.requestUpgrade([zeroAddress], { account: owner.account }),
        beacon,
        "BeaconInvalidImplementation",
      );
      await assertions.revertWithCustomError(
        beacon.write.requestUpgrade([attacker.account.address], { account: owner.account }),
        beacon,
        "BeaconInvalidImplementation",
      );
    });
  });

  describe("cancellation", function () {
    it("5. cancelUpgrade clears the staging so upgradeTo reverts", async function () {
      const { beacon, owner, implA, implB } = await loadFixture(deployBeaconFixture);

      await beacon.write.requestUpgrade([implB.address], { account: owner.account });
      await beacon.write.cancelUpgrade([], { account: owner.account });

      assert.strictEqual(await beacon.read.pendingImplementation(), zeroAddress);
      assert.strictEqual(await beacon.read.upgradeReadyAt(), 0n);

      // Even letting the original 48h pass does not resurrect it.
      await time.increase(FORTY_EIGHT_HOURS);
      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implB.address], { account: owner.account }),
        beacon,
        "NoPendingUpgrade",
      );
      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implA.address),
      );
    });

    it("cancelUpgrade with nothing staged reverts", async function () {
      const { beacon, owner } = await loadFixture(deployBeaconFixture);

      await assertions.revertWithCustomError(
        beacon.write.cancelUpgrade([], { account: owner.account }),
        beacon,
        "NoPendingUpgrade",
      );
    });
  });

  describe("access control", function () {
    it("6. non-owner cannot requestUpgrade / upgradeTo / cancelUpgrade", async function () {
      const { beacon, owner, attacker, implB } = await loadFixture(deployBeaconFixture);

      await assertions.revertWithCustomError(
        beacon.write.requestUpgrade([implB.address], { account: attacker.account }),
        beacon,
        "OwnableUnauthorizedAccount",
      );

      // Stage legitimately, then check the other two entry points as the attacker.
      await beacon.write.requestUpgrade([implB.address], { account: owner.account });

      await assertions.revertWithCustomError(
        beacon.write.cancelUpgrade([], { account: attacker.account }),
        beacon,
        "OwnableUnauthorizedAccount",
      );

      await time.increase(FORTY_EIGHT_HOURS);
      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implB.address], { account: attacker.account }),
        beacon,
        "OwnableUnauthorizedAccount",
      );

      // Ownership check runs before the timelock check: matured staging survives.
      assert.strictEqual(
        getAddress((await beacon.read.pendingImplementation()) as `0x${string}`),
        getAddress(implB.address),
      );
    });
  });

  /**
   * 7. THE REGRESSION: the exact audit scenario — a token deposited in TradeSettlementV1
   *    whose implementation the beacon owner swaps in a single transaction.
   */
  describe("regression: escrowed BeaconProxy tokens cannot be swapped in one tx", function () {
    const TOTAL_SUPPLY = parseUnits("1000000", 18);
    const DEPOSIT = parseUnits("1000", 18);
    const TEST_PRIVATE_KEY =
      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

    async function deployEscrowFixture() {
      const { viem } = await getConnection();
      const [owner, alice, feeRecipient] = await viem.getWalletClients();
      const publicClient = await viem.getPublicClient();
      const chainId = await publicClient.getChainId();

      const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);
      const { token, erc20Beacon, erc20Impl } = await deploySimpleTokenFixture({
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
      await settlement.write.setSupportedToken([token.address, true], { account: owner.account });

      // Alice escrows real tokens: this is the value the beacon owner must not be able to
      // put at risk with a single transaction.
      await token.write.approve([settlement.address, DEPOSIT], { account: alice.account });
      await settlement.write.depositToken([token.address, DEPOSIT], { account: alice.account });

      // The attacker's payload: an implementation that lies about balanceOf, which is exactly
      // the input `recoverStuckTokens` trusts.
      const evilImpl = await viem.deployContract("MaliciousTokenImpl", []);

      return { viem, owner, alice, token, erc20Beacon, erc20Impl, settlement, evilImpl };
    }

    it("beacon owner's one-tx implementation swap on escrowed tokens now fails", async function () {
      const { owner, alice, token, erc20Beacon, erc20Impl, settlement, evilImpl } =
        await loadFixture(deployEscrowFixture);

      // Precondition: real escrowed balance, honest implementation.
      assert.strictEqual((await token.read.balanceOf([settlement.address])) as bigint, DEPOSIT);
      assert.strictEqual(
        getAddress((await erc20Beacon.read.implementation()) as `0x${string}`),
        getAddress(erc20Impl.address),
      );

      // THE ATTACK, single transaction — must revert.
      await assertions.revertWithCustomError(
        erc20Beacon.write.upgradeTo([evilImpl.address], { account: owner.account }),
        erc20Beacon,
        "NoPendingUpgrade",
      );

      // Nothing moved: implementation, escrow balance and the ledger are all intact.
      assert.strictEqual(
        getAddress((await erc20Beacon.read.implementation()) as `0x${string}`),
        getAddress(erc20Impl.address),
      );
      assert.strictEqual((await token.read.balanceOf([settlement.address])) as bigint, DEPOSIT);
      assert.strictEqual(
        (await settlement.read.getBalance([alice.account.address, token.address])) as bigint,
        DEPOSIT,
      );
    });

    it("even staged, the swap is not executable for 48h and can be cancelled", async function () {
      const { owner, token, erc20Beacon, erc20Impl, settlement, evilImpl } =
        await loadFixture(deployEscrowFixture);

      await erc20Beacon.write.requestUpgrade([evilImpl.address], { account: owner.account });

      // Observable for 48h, and not executable during that window.
      await time.increase(FORTY_EIGHT_HOURS - 60n);
      await assertions.revertWithCustomError(
        erc20Beacon.write.upgradeTo([evilImpl.address], { account: owner.account }),
        erc20Beacon,
        "UpgradeNotReady",
      );

      // Defenders (owner / future multisig) abort inside the window.
      await erc20Beacon.write.cancelUpgrade([], { account: owner.account });
      await time.increase(FORTY_EIGHT_HOURS);
      await assertions.revertWithCustomError(
        erc20Beacon.write.upgradeTo([evilImpl.address], { account: owner.account }),
        erc20Beacon,
        "NoPendingUpgrade",
      );

      assert.strictEqual(
        getAddress((await erc20Beacon.read.implementation()) as `0x${string}`),
        getAddress(erc20Impl.address),
      );
      assert.strictEqual((await token.read.balanceOf([settlement.address])) as bigint, DEPOSIT);
    });

    it("counterfactual: the staged payload IS hostile once it lands (48h is the defense)", async function () {
      const { owner, alice, token, erc20Beacon, settlement, evilImpl } =
        await loadFixture(deployEscrowFixture);

      await erc20Beacon.write.requestUpgrade([evilImpl.address], { account: owner.account });
      await time.increase(FORTY_EIGHT_HOURS);
      await erc20Beacon.write.upgradeTo([evilImpl.address], { account: owner.account });

      // Proves the payload really does forge the number `recoverStuckTokens` reads —
      // i.e. the timelock is delaying a genuine drain vector, not a hypothetical one.
      const forged = (await token.read.balanceOf([settlement.address])) as bigint;
      const ledgered = (await settlement.read.getBalance([
        alice.account.address,
        token.address,
      ])) as bigint;
      assert.strictEqual(ledgered, DEPOSIT, "the real ledger still says 1000");
      assert.ok(forged > ledgered, "malicious impl must forge excess over the ledger");
    });
  });

  /**
   * a matured staging must EXPIRE.
   *
   * The 48h delay alone only guaranteed "one 48h announcement, ever": nothing consumed a matured
   * staging, so the owner could arm a payload while the chain was quiet, let the delay lapse
   * unobserved, and fire it in a single transaction at any later moment of their choosing. The
   * grace period converts the guarantee into "48h of RECENT notice before every execution".
   */
  describe("staging expires after the grace period", function () {
    it("exposes a 7 day grace period", async function () {
      const { beacon } = await loadFixture(deployBeaconFixture);
      assert.strictEqual(await beacon.read.UPGRADE_GRACE_PERIOD(), SEVEN_DAYS);
    });

    it("executes at the LAST second of the window", async function () {
      const { beacon, owner, implB } = await loadFixture(deployBeaconFixture);

      await beacon.write.requestUpgrade([implB.address], { account: owner.account });
      const readyAt = (await beacon.read.upgradeReadyAt()) as bigint;

      // Land the execution exactly on readyAt + GRACE — the inclusive boundary.
      await time.setNextBlockTimestamp(readyAt + SEVEN_DAYS);
      await beacon.write.upgradeTo([implB.address], { account: owner.account });

      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implB.address),
      );
    });

    it("reverts UpgradeExpired one second past the window", async function () {
      const { beacon, owner, implA, implB } = await loadFixture(deployBeaconFixture);

      await beacon.write.requestUpgrade([implB.address], { account: owner.account });
      const readyAt = (await beacon.read.upgradeReadyAt()) as bigint;

      await time.setNextBlockTimestamp(readyAt + SEVEN_DAYS + 1n);
      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implB.address], { account: owner.account }),
        beacon,
        "UpgradeExpired",
      );

      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implA.address),
        "implementation must be untouched",
      );
    });

    /** THE SCENARIO: pre-arm while nobody is watching, fire much later. */
    it("a pre-armed payload cannot be fired long after maturity (48h + 8 days)", async function () {
      const { beacon, owner, implA, evilLike } = await loadFixture(deployBeaconFixture);

      await beacon.write.requestUpgrade([evilLike.address], { account: owner.account });
      await time.increase(FORTY_EIGHT_HOURS + 8n * 24n * 60n * 60n);

      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([evilLike.address], { account: owner.account }),
        beacon,
        "UpgradeExpired",
      );
      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implA.address),
      );

      // The staging fields survive an expired attempt (nothing is consumed), but they are dead
      // weight: only a fresh requestUpgrade — a fresh public announcement — revives execution.
      assert.strictEqual(
        getAddress((await beacon.read.pendingImplementation()) as `0x${string}`),
        getAddress(evilLike.address),
      );
    });

    it("re-staging after expiry restarts the full 48h wait", async function () {
      const { beacon, owner, implB } = await loadFixture(deployBeaconFixture);

      await beacon.write.requestUpgrade([implB.address], { account: owner.account });
      await time.increase(FORTY_EIGHT_HOURS + 8n * 24n * 60n * 60n);

      await beacon.write.requestUpgrade([implB.address], { account: owner.account });
      const readyAt = (await beacon.read.upgradeReadyAt()) as bigint;
      assert.strictEqual(readyAt, (await time.latest()) + FORTY_EIGHT_HOURS);

      // Not "expired then immediately executable": the new window opens 48h out.
      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([implB.address], { account: owner.account }),
        beacon,
        "UpgradeNotReady",
      );

      await time.increase(FORTY_EIGHT_HOURS);
      await beacon.write.upgradeTo([implB.address], { account: owner.account });
      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implB.address),
      );
    });
  });

  /**
   * ownership handover must not pass an armed payload to the successor.
   */
  describe("ownership handover clears the staging", function () {
    it("acceptOwnership drops the outgoing owner's staged implementation", async function () {
      const { beacon, publicClient, owner, attacker, implA, evilLike } =
        await loadFixture(deployBeaconFixture);

      // Outgoing owner arms a payload, then hands the beacon over.
      await beacon.write.requestUpgrade([evilLike.address], { account: owner.account });
      await beacon.write.transferOwnership([attacker.account.address], { account: owner.account });

      // Nomination alone changes nothing — ownership has not moved yet.
      assert.strictEqual(
        getAddress((await beacon.read.pendingImplementation()) as `0x${string}`),
        getAddress(evilLike.address),
      );

      const hash = await beacon.write.acceptOwnership({ account: attacker.account });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      const cancelled = parseEventLogs({
        abi: beacon.abi,
        logs: receipt.logs,
        eventName: "UpgradeCancelled",
      });
      assert.strictEqual(cancelled.length, 1, "the drop must be observable off-chain");
      assert.strictEqual(
        getAddress(
          (cancelled[0] as unknown as { args: { cancelledImplementation: `0x${string}` } }).args
            .cancelledImplementation,
        ),
        getAddress(evilLike.address),
      );

      assert.strictEqual(await beacon.read.pendingImplementation(), zeroAddress);
      assert.strictEqual(await beacon.read.upgradeReadyAt(), 0n);

      // The inherited clock is gone with it: the new owner cannot execute what they never staged.
      await time.increase(FORTY_EIGHT_HOURS);
      await assertions.revertWithCustomError(
        beacon.write.upgradeTo([evilLike.address], { account: attacker.account }),
        beacon,
        "NoPendingUpgrade",
      );
      assert.strictEqual(
        getAddress((await beacon.read.implementation()) as `0x${string}`),
        getAddress(implA.address),
      );
    });

    it("handover with nothing staged is a clean no-op", async function () {
      const { beacon, publicClient, owner, attacker } = await loadFixture(deployBeaconFixture);

      await beacon.write.transferOwnership([attacker.account.address], { account: owner.account });
      const hash = await beacon.write.acceptOwnership({ account: attacker.account });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });

      assert.strictEqual(
        parseEventLogs({ abi: beacon.abi, logs: receipt.logs, eventName: "UpgradeCancelled" })
          .length,
        0,
        "no phantom cancellation when nothing was armed",
      );
      assert.strictEqual(
        getAddress((await beacon.read.owner()) as `0x${string}`),
        getAddress(attacker.account.address),
      );
    });
  });
});
