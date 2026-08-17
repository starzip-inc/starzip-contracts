/**
 * TokenVestingWallet — unit tests
 *
 * Covers:
 *   - ERC-7201 storage location derivation (release-blocker, deep-audit P1-1)
 *   - initialize / re-initialize guards
 *   - startVesting access control + idempotency (onlyLaunchpad, AlreadyStarted)
 *   - release access control (onlyOwner) + nonReentrant via OZ ReentrancyGuard
 *   - Cliff + linear vesting math
 *   - releasable() view across the timeline
 *   - start() sentinel value before startVesting (deep-audit P1-NEW)
 *   - external token donation/airdrop accounted in vested total
 *   - Ownable2Step transferOwnership semantics
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseUnits,
  getAddress,
  encodeFunctionData,
  zeroAddress,
  keccak256,
  toBytes,
  toHex,
  encodeAbiParameters,
  Address,
} from "viem";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";

describe("TokenVestingWallet", function () {
  const TOTAL_VEST_AMOUNT = parseUnits("1000000", 18); // 1M tokens
  const VESTING_DURATION = 365n * 24n * 3600n; // 365 days
  const CLIFF_DURATION = 30n * 24n * 3600n; // 30 days

  /**
   * Deploy a TokenVestingWallet implementation, wrap it in a Beacon, then
   * deploy a BeaconProxy clone and initialize it with the standard test
   * parameters. `launchpad_` is set to the dedicated `launchpadSigner` EOA so
   * that `startVesting` can be exercised directly from a test wallet.
   */
  async function deployWalletFixture() {
    const { viem } = await getConnection();
    const [owner, beneficiary, launchpadSigner, other] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    // Deploy a vesting token (USDT mock with 18 decimals)
    const token = await viem.deployContract("USDT", [owner.account.address, 18]);

    // Deploy implementation + beacon
    const walletImpl = await viem.deployContract("TokenVestingWallet", []);
    const beacon = await viem.deployContract("UpgradeableBeacon", [
      walletImpl.address,
      owner.account.address,
    ]);

    // Deploy BeaconProxy with init data
    const initData = encodeFunctionData({
      abi: walletImpl.abi,
      functionName: "initialize",
      args: [
        beneficiary.account.address,
        launchpadSigner.account.address,
        token.address,
        VESTING_DURATION,
        CLIFF_DURATION,
      ],
    });
    const proxy = await viem.deployContract("BeaconProxyTestWrapper", [beacon.address, initData]);
    const wallet = await viem.getContractAt("TokenVestingWallet", proxy.address);

    // Mint vesting tokens into the wallet
    await token.write.mint([wallet.address, TOTAL_VEST_AMOUNT]);

    return {
      wallet,
      walletImpl,
      beacon,
      token,
      owner,
      beneficiary,
      launchpadSigner,
      other,
      publicClient,
      viem,
    };
  }

  // =====================================================================
  // ERC-7201 storage location (release-blocker, deep-audit P1-1)
  // =====================================================================
  describe("ERC-7201 storage location", function () {
    it("STORAGE_LOCATION matches OZ-spec keccak256(abi.encode(uint256(keccak256(name)) - 1)) & ~0xff", async function () {
      const { wallet } = await loadFixture(deployWalletFixture);

      // Reference derivation per ERC-7201:
      //   inner   = keccak256("starzip.storage.TokenVestingWallet")
      //   middle  = uint256(inner) - 1
      //   outer   = keccak256(abi.encode(uint256(middle)))
      //   slot    = outer & ~bytes32(uint256(0xff))
      const inner = keccak256(toBytes("starzip.storage.TokenVestingWallet"));
      const innerNum = BigInt(inner) - 1n;
      const encoded = encodeAbiParameters([{ type: "uint256" }], [innerNum]);
      const outer = keccak256(encoded);
      const mask = (1n << 256n) - (1n << 8n); // ~0xff
      const expected = toHex(BigInt(outer) & mask, { size: 32 });

      const actual = (await wallet.read.STORAGE_LOCATION()) as `0x${string}`;
      assert.strictEqual(
        actual.toLowerCase(),
        expected.toLowerCase(),
        "ERC-7201 storage location must match OZ derivation exactly",
      );
    });

    it("STORAGE_LOCATION matches the hard-coded constant in the contract source", async function () {
      const { wallet } = await loadFixture(deployWalletFixture);
      const actual = (await wallet.read.STORAGE_LOCATION()) as `0x${string}`;
      assert.strictEqual(
        actual.toLowerCase(),
        "0x81f4d596baa013a867e83dd1bbbda068edbe5d743871475dd87b898bc68eb000",
      );
    });
  });

  // =====================================================================
  // Initialization
  // =====================================================================
  describe("initialize", function () {
    it("stores beneficiary, launchpad, token, duration, and cliff", async function () {
      const { wallet, beneficiary, launchpadSigner, token } =
        await loadFixture(deployWalletFixture);

      assert.strictEqual(await wallet.read.owner(), getAddress(beneficiary.account.address));
      assert.strictEqual(
        await wallet.read.launchpad(),
        getAddress(launchpadSigner.account.address),
      );
      assert.strictEqual(await wallet.read.token(), getAddress(token.address));
      assert.strictEqual(await wallet.read.duration(), VESTING_DURATION);
      assert.strictEqual(await wallet.read.cliff(), CLIFF_DURATION);
      assert.strictEqual(await wallet.read.released(), 0n);
      assert.strictEqual(await wallet.read.started(), false);
    });

    it("sets start sentinel to type(uint64).max before startVesting", async function () {
      const { wallet } = await loadFixture(deployWalletFixture);
      const start = (await wallet.read.start()) as bigint;
      const uint64Max = (1n << 64n) - 1n;
      assert.strictEqual(start, uint64Max, "start must be uint64.max sentinel before startVesting");
    });

    it("reverts when initialized a second time", async function () {
      const { wallet, beneficiary, launchpadSigner, token } =
        await loadFixture(deployWalletFixture);

      await assertions.revert(
        wallet.write.initialize([
          beneficiary.account.address,
          launchpadSigner.account.address,
          token.address,
          VESTING_DURATION,
          CLIFF_DURATION,
        ]),
      );
    });

    it("reverts when beneficiary is zero address", async function () {
      const { walletImpl, beacon, launchpadSigner, token, viem } =
        await loadFixture(deployWalletFixture);

      const initData = encodeFunctionData({
        abi: walletImpl.abi,
        functionName: "initialize",
        args: [
          zeroAddress,
          launchpadSigner.account.address,
          token.address,
          VESTING_DURATION,
          CLIFF_DURATION,
        ],
      });

      await assertions.revert(
        viem.deployContract("BeaconProxyTestWrapper", [beacon.address, initData]),
      );
    });

    it("reverts when launchpad is zero address", async function () {
      const { walletImpl, beacon, beneficiary, token, viem } =
        await loadFixture(deployWalletFixture);

      const initData = encodeFunctionData({
        abi: walletImpl.abi,
        functionName: "initialize",
        args: [
          beneficiary.account.address,
          zeroAddress,
          token.address,
          VESTING_DURATION,
          CLIFF_DURATION,
        ],
      });

      await assertions.revert(
        viem.deployContract("BeaconProxyTestWrapper", [beacon.address, initData]),
      );
    });

    it("reverts when token is zero address", async function () {
      const { walletImpl, beacon, beneficiary, launchpadSigner, viem } =
        await loadFixture(deployWalletFixture);

      const initData = encodeFunctionData({
        abi: walletImpl.abi,
        functionName: "initialize",
        args: [
          beneficiary.account.address,
          launchpadSigner.account.address,
          zeroAddress,
          VESTING_DURATION,
          CLIFF_DURATION,
        ],
      });

      await assertions.revert(
        viem.deployContract("BeaconProxyTestWrapper", [beacon.address, initData]),
      );
    });

    it("reverts when duration is zero", async function () {
      const { walletImpl, beacon, beneficiary, launchpadSigner, token, viem } =
        await loadFixture(deployWalletFixture);

      const initData = encodeFunctionData({
        abi: walletImpl.abi,
        functionName: "initialize",
        args: [beneficiary.account.address, launchpadSigner.account.address, token.address, 0n, 0n],
      });

      await assertions.revert(
        viem.deployContract("BeaconProxyTestWrapper", [beacon.address, initData]),
      );
    });

    it("reverts when cliff exceeds duration", async function () {
      const { walletImpl, beacon, beneficiary, launchpadSigner, token, viem } =
        await loadFixture(deployWalletFixture);

      const initData = encodeFunctionData({
        abi: walletImpl.abi,
        functionName: "initialize",
        args: [
          beneficiary.account.address,
          launchpadSigner.account.address,
          token.address,
          VESTING_DURATION,
          VESTING_DURATION + 1n, // cliff > duration
        ],
      });

      await assertions.revert(
        viem.deployContract("BeaconProxyTestWrapper", [beacon.address, initData]),
      );
    });
  });

  // =====================================================================
  // startVesting (onlyLaunchpad + idempotent)
  // =====================================================================
  describe("startVesting", function () {
    it("flips started flag and writes start/duration when called by launchpad", async function () {
      const { wallet, launchpadSigner } = await loadFixture(deployWalletFixture);

      const startTs = await time.latest();
      await wallet.write.startVesting([startTs, VESTING_DURATION], {
        account: launchpadSigner.account,
      });

      assert.strictEqual(await wallet.read.started(), true);
      assert.strictEqual((await wallet.read.start()) as bigint, startTs);
      assert.strictEqual(await wallet.read.duration(), VESTING_DURATION);
    });

    it("reverts NotLaunchpad when caller is not the launchpad", async function () {
      const { wallet, other } = await loadFixture(deployWalletFixture);

      const startTs = await time.latest();
      await assertions.revertWithCustomError(
        wallet.write.startVesting([startTs, VESTING_DURATION], { account: other.account }),
        wallet,
        "NotLaunchpad",
      );
    });

    it("reverts AlreadyStarted on second call", async function () {
      const { wallet, launchpadSigner } = await loadFixture(deployWalletFixture);

      const startTs = await time.latest();
      await wallet.write.startVesting([startTs, VESTING_DURATION], {
        account: launchpadSigner.account,
      });

      await assertions.revertWithCustomError(
        wallet.write.startVesting([startTs, VESTING_DURATION], {
          account: launchpadSigner.account,
        }),
        wallet,
        "AlreadyStarted",
      );
    });

    it("reverts InvalidDuration when duration_ is zero", async function () {
      const { wallet, launchpadSigner } = await loadFixture(deployWalletFixture);

      const startTs = await time.latest();
      await assertions.revertWithCustomError(
        wallet.write.startVesting([startTs, 0n], { account: launchpadSigner.account }),
        wallet,
        "InvalidDuration",
      );
    });

    it("reverts InvalidCliff when cliff > new duration", async function () {
      const { wallet, launchpadSigner } = await loadFixture(deployWalletFixture);

      // cliff was set at init = 30 days; pass duration=10 days → cliff > duration
      const startTs = await time.latest();
      await assertions.revertWithCustomError(
        wallet.write.startVesting([startTs, 10n * 24n * 3600n], {
          account: launchpadSigner.account,
        }),
        wallet,
        "InvalidCliff",
      );
    });
  });

  // =====================================================================
  // release access control + math
  // =====================================================================
  describe("release", function () {
    it("reverts NothingToRelease before startVesting (vested=0)", async function () {
      const { wallet, beneficiary } = await loadFixture(deployWalletFixture);

      // started=false → vested=0 → nothing to release
      await assertions.revertWithCustomError(
        wallet.write.release([], { account: beneficiary.account }),
        wallet,
        "NothingToRelease",
      );
    });

    it("reverts OwnableUnauthorizedAccount when called by non-beneficiary", async function () {
      const { wallet, launchpadSigner, other } = await loadFixture(deployWalletFixture);

      // Even after start, only owner can release
      const startTs = await time.latest();
      await wallet.write.startVesting([startTs, VESTING_DURATION], {
        account: launchpadSigner.account,
      });
      await time.increase(VESTING_DURATION);

      await assertions.revertWithCustomError(
        wallet.write.release([], { account: other.account }),
        wallet,
        "OwnableUnauthorizedAccount",
      );
    });

    it("returns 0 inside cliff window", async function () {
      const { wallet, launchpadSigner } = await loadFixture(deployWalletFixture);
      const startTs = await time.latest();
      await wallet.write.startVesting([startTs, VESTING_DURATION], {
        account: launchpadSigner.account,
      });

      // Move forward but stay inside cliff
      await time.increase(CLIFF_DURATION / 2n);
      const releasable = (await wallet.read.releasable()) as bigint;
      assert.strictEqual(releasable, 0n, "should return 0 during cliff");
    });

    it("releases linearly after cliff", async function () {
      const { wallet, launchpadSigner, beneficiary, token } =
        await loadFixture(deployWalletFixture);

      const startTs = await time.latest();
      await wallet.write.startVesting([startTs, VESTING_DURATION], {
        account: launchpadSigner.account,
      });

      // Advance to halfway of vesting (well past cliff)
      await time.increase(VESTING_DURATION / 2n);

      const releasableHalf = (await wallet.read.releasable()) as bigint;
      // Should be ~50% of TOTAL_VEST_AMOUNT (allow ±0.5% drift for block-time noise)
      const half = TOTAL_VEST_AMOUNT / 2n;
      const tolerance = half / 200n; // 0.5%
      assert.ok(
        releasableHalf >= half - tolerance && releasableHalf <= half + tolerance,
        `releasable should be ~50% (got ${releasableHalf}, expected ~${half})`,
      );

      const balBefore = (await token.read.balanceOf([beneficiary.account.address])) as bigint;
      await wallet.write.release([], { account: beneficiary.account });
      const balAfter = (await token.read.balanceOf([beneficiary.account.address])) as bigint;
      assert.ok(balAfter - balBefore > 0n, "beneficiary received tokens");
    });

    it("releases full amount after duration ends", async function () {
      const { wallet, launchpadSigner, beneficiary, token } =
        await loadFixture(deployWalletFixture);

      const startTs = await time.latest();
      await wallet.write.startVesting([startTs, VESTING_DURATION], {
        account: launchpadSigner.account,
      });

      await time.increase(VESTING_DURATION + 1n);

      const releasable = (await wallet.read.releasable()) as bigint;
      assert.strictEqual(releasable, TOTAL_VEST_AMOUNT);

      await wallet.write.release([], { account: beneficiary.account });

      assert.strictEqual(
        await token.read.balanceOf([beneficiary.account.address]),
        TOTAL_VEST_AMOUNT,
      );
      assert.strictEqual(await wallet.read.released(), TOTAL_VEST_AMOUNT);
    });

    it("partial then full release accumulates released() correctly", async function () {
      const { wallet, launchpadSigner, beneficiary, token } =
        await loadFixture(deployWalletFixture);

      const startTs = await time.latest();
      await wallet.write.startVesting([startTs, VESTING_DURATION], {
        account: launchpadSigner.account,
      });

      // 25% along
      await time.increase(VESTING_DURATION / 4n);
      await wallet.write.release([], { account: beneficiary.account });
      const released1 = (await wallet.read.released()) as bigint;
      assert.ok(released1 > 0n);

      // 75% along
      await time.increase(VESTING_DURATION / 2n);
      await wallet.write.release([], { account: beneficiary.account });
      const released2 = (await wallet.read.released()) as bigint;
      assert.ok(released2 > released1);

      // 100% (extra slack)
      await time.increase(VESTING_DURATION);
      await wallet.write.release([], { account: beneficiary.account });

      assert.strictEqual(await wallet.read.released(), TOTAL_VEST_AMOUNT);
      assert.strictEqual(
        await token.read.balanceOf([beneficiary.account.address]),
        TOTAL_VEST_AMOUNT,
      );
    });

    it("includes external donation/airdrop in vested total (OZ semantics)", async function () {
      const { wallet, launchpadSigner, beneficiary, token, owner } =
        await loadFixture(deployWalletFixture);

      const startTs = await time.latest();
      await wallet.write.startVesting([startTs, VESTING_DURATION], {
        account: launchpadSigner.account,
      });

      // Donate extra tokens after vesting starts
      const donation = parseUnits("500000", 18);
      await token.write.mint([wallet.address, donation], { account: owner.account });

      // Advance to end
      await time.increase(VESTING_DURATION + 1n);

      // total should be initial + donation
      const releasable = (await wallet.read.releasable()) as bigint;
      assert.strictEqual(releasable, TOTAL_VEST_AMOUNT + donation);

      await wallet.write.release([], { account: beneficiary.account });
      assert.strictEqual(
        await token.read.balanceOf([beneficiary.account.address]),
        TOTAL_VEST_AMOUNT + donation,
      );
    });
  });

  // =====================================================================
  // Ownable2Step ownership transfer
  // =====================================================================
  describe("Ownable2Step ownership transfer", function () {
    it("requires accept by new owner (2-step)", async function () {
      const { wallet, beneficiary, other } = await loadFixture(deployWalletFixture);

      // Step 1: propose
      await wallet.write.transferOwnership([other.account.address], {
        account: beneficiary.account,
      });

      // Owner is still beneficiary until step 2
      assert.strictEqual(await wallet.read.owner(), getAddress(beneficiary.account.address));
      assert.strictEqual(await wallet.read.pendingOwner(), getAddress(other.account.address));

      // Step 2: accept
      await wallet.write.acceptOwnership([], { account: other.account });

      assert.strictEqual(await wallet.read.owner(), getAddress(other.account.address));
      assert.strictEqual(await wallet.read.pendingOwner(), zeroAddress);
    });

    it("rejects acceptOwnership from non-pending caller", async function () {
      const { wallet, beneficiary, other } = await loadFixture(deployWalletFixture);

      await wallet.write.transferOwnership([other.account.address], {
        account: beneficiary.account,
      });

      // Original owner cannot accept (they are not pendingOwner)
      await assertions.revert(wallet.write.acceptOwnership([], { account: beneficiary.account }));
    });
  });

  // =====================================================================
  // Version / metadata
  // =====================================================================
  describe("version", function () {
    it("returns 1", async function () {
      const { wallet } = await loadFixture(deployWalletFixture);
      assert.strictEqual(await wallet.read.version(), 1n);
    });
  });
});
