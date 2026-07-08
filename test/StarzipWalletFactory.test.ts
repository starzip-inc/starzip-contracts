import { describe, it } from "node:test";
import assert from "node:assert";
import { getAddress, hexToBytes, Hex, zeroAddress } from "viem";
import { loadFixture, getConnection } from "./helpers.js";
import { passkeyPubCoords } from "./aa-helpers.js";

describe("StarzipWalletFactory", function () {
  // createAccount now validates the P256 pubkey is on-curve, so fixtures must be REAL
  // curve points. Deterministic test keys (scalars < n; NOT for production) — same as
  // StarzipWallet.test.ts.
  const { x: TEST_PUB_KEY_X, y: TEST_PUB_KEY_Y } = passkeyPubCoords(
    hexToBytes("0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex),
  );
  const { x: ALT_PUB_KEY_X, y: ALT_PUB_KEY_Y } = passkeyPubCoords(
    hexToBytes("0x519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464" as Hex),
  );

  async function deployFactoryFixture() {
    const { viem } = await getConnection();
    const [owner, user1] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    const mockEntryPoint = await viem.deployContract("MockEntryPoint", []);
    const factory = await viem.deployContract("StarzipWalletFactory", [mockEntryPoint.address]);

    return { factory, mockEntryPoint, owner, user1, publicClient, viem };
  }

  describe("Deployment", function () {
    it("should deploy with implementation address", async function () {
      const { factory } = await loadFixture(deployFactoryFixture);
      const impl = await factory.read.accountImplementation();
      assert.ok(impl !== zeroAddress, "Implementation should be deployed");
    });

    it("should store entryPoint", async function () {
      const { factory, mockEntryPoint } = await loadFixture(deployFactoryFixture);
      const ep = await factory.read.entryPoint();
      assert.strictEqual(getAddress(ep as string), getAddress(mockEntryPoint.address));
    });
  });

  describe("CREATE2 Determinism", function () {
    it("should deploy account to predicted address", async function () {
      const { factory, owner, publicClient } = await loadFixture(deployFactoryFixture);
      const salt = 0n;

      const predicted = await factory.read.getAddress([
        TEST_PUB_KEY_X,
        TEST_PUB_KEY_Y,
        owner.account.address,
        salt,
      ]);

      const hash = await factory.write.createAccount(
        [TEST_PUB_KEY_X, TEST_PUB_KEY_Y, owner.account.address, salt],
        { account: owner.account },
      );
      await publicClient.waitForTransactionReceipt({ hash });

      const code = await publicClient.getCode({ address: predicted as `0x${string}` });
      assert.ok(code && code !== "0x", "Account should exist at predicted address");
    });

    it("should be idempotent — second call returns same address", async function () {
      const { factory, owner, publicClient } = await loadFixture(deployFactoryFixture);
      const salt = 1n;

      const hash1 = await factory.write.createAccount(
        [TEST_PUB_KEY_X, TEST_PUB_KEY_Y, owner.account.address, salt],
        { account: owner.account },
      );
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      // Second call should succeed (returns existing)
      const hash2 = await factory.write.createAccount(
        [TEST_PUB_KEY_X, TEST_PUB_KEY_Y, owner.account.address, salt],
        { account: owner.account },
      );
      const receipt = await publicClient.waitForTransactionReceipt({ hash: hash2 });
      assert.ok(receipt.status === "success");
    });

    it("should produce different addresses for different pubkeys", async function () {
      const { factory, owner } = await loadFixture(deployFactoryFixture);
      const salt = 2n;

      const addr1 = await factory.read.getAddress([
        TEST_PUB_KEY_X,
        TEST_PUB_KEY_Y,
        owner.account.address,
        salt,
      ]);
      const addr2 = await factory.read.getAddress([
        ALT_PUB_KEY_X,
        ALT_PUB_KEY_Y,
        owner.account.address,
        salt,
      ]);

      assert.notStrictEqual(addr1, addr2, "Different keys should produce different addresses");
    });

    it("should produce different addresses for different owners", async function () {
      const { factory, owner, user1 } = await loadFixture(deployFactoryFixture);
      const salt = 3n;

      const addr1 = await factory.read.getAddress([
        TEST_PUB_KEY_X,
        TEST_PUB_KEY_Y,
        owner.account.address,
        salt,
      ]);
      const addr2 = await factory.read.getAddress([
        TEST_PUB_KEY_X,
        TEST_PUB_KEY_Y,
        user1.account.address,
        salt,
      ]);

      assert.notStrictEqual(addr1, addr2, "Different owners should produce different addresses");
    });

    it("should produce different addresses for different salts", async function () {
      const { factory, owner } = await loadFixture(deployFactoryFixture);

      const addr1 = await factory.read.getAddress([
        TEST_PUB_KEY_X,
        TEST_PUB_KEY_Y,
        owner.account.address,
        10n,
      ]);
      const addr2 = await factory.read.getAddress([
        TEST_PUB_KEY_X,
        TEST_PUB_KEY_Y,
        owner.account.address,
        20n,
      ]);

      assert.notStrictEqual(addr1, addr2, "Different salts should produce different addresses");
    });

    it("should initialize deployed account correctly", async function () {
      const { factory, owner, publicClient, viem } = await loadFixture(deployFactoryFixture);
      const salt = 4n;

      const hash = await factory.write.createAccount(
        [TEST_PUB_KEY_X, TEST_PUB_KEY_Y, owner.account.address, salt],
        { account: owner.account },
      );
      await publicClient.waitForTransactionReceipt({ hash });

      const accountAddr = (await factory.read.getAddress([
        TEST_PUB_KEY_X,
        TEST_PUB_KEY_Y,
        owner.account.address,
        salt,
      ])) as `0x${string}`;

      const account = await viem.getContractAt("StarzipWallet", accountAddr);
      assert.strictEqual(await account.read.publicKeyX(), TEST_PUB_KEY_X);
      assert.strictEqual(await account.read.publicKeyY(), TEST_PUB_KEY_Y);
      assert.strictEqual(
        getAddress((await account.read.owner()) as string),
        getAddress(owner.account.address),
      );
    });
  });
});
