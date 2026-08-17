/**
 * ERC20V1 — EIP-2612 `permit`.
 *
 * WHY THIS EXISTS. `TradeSettlementV1.depositToken` is gas-sponsorable, but the `approve` that must
 * precede it is a call to the TOKEN, not to the settlement contract, so it falls outside any
 * paymaster policy scoped to the settlement address. A user holding zero native balance could
 * therefore be sponsored for a deposit they were structurally unable to make. Adding `permit` moves
 * the approval into a signature, which the settlement can execute on the user's behalf inside
 * `depositWithPermit`.
 *
 * THE RISKY PART IS NOT THE FEATURE, IT IS THE STORAGE. ERC20V1 is deployed behind a
 * BEACON — one implementation swap applies to EVERY token ever issued at once — so a single
 * shifted slot would corrupt all of them simultaneously. The layout test below is therefore the
 * load-bearing one in this file: it reads the RAW storage slots of a live token and asserts that
 * `launchpad`, `maxSupply` and `blacklist` still live exactly where they lived before ERC20Permit
 * was inherited. That holds because `ERC20PermitUpgradeable` declares no state of its own and its
 * stateful bases (`EIP712Upgradeable`, `NoncesUpgradeable`) use ERC-7201 namespaced storage at
 * hash-derived absolute slots. Asserting it from storage rather than from that argument is the
 * point — the argument is exactly the kind of thing that is true right up until an OZ minor bump
 * makes it false.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { loadFixture, time, getConnection, assertions } from "./helpers.js";
import {
  parseUnits,
  keccak256,
  encodeAbiParameters,
  stringToHex,
  toHex,
  getAddress,
  type Hex,
} from "viem";
import { privateKeyToAccount, signTypedData } from "viem/accounts";
import { deploySimpleTokenFixture } from "./tokenFactoryHelpers.js";

describe("ERC20V1 EIP-2612 permit", function () {
  const TOTAL_SUPPLY = parseUnits("1000000", 18);
  const TEST_PRIVATE_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
  // Hardhat accounts #2 / #3. The wallet-client destructuring below MUST keep alice at index 2 and
  // bob at index 3 or these keys recover the wrong addresses.
  const ALICE_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;
  const BOB_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex;

  const TOKEN_NAME = "PermitToken";
  const DEAD = "0x000000000000000000000000000000000000dEaD" as const;

  const PERMIT_TYPES = {
    Permit: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
      { name: "value", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  } as const;

  async function deployFixture() {
    const { viem } = await getConnection();
    // Index 1 is skipped on purpose: alice/bob must sit at indices 2/3 to match ALICE_KEY/BOB_KEY.
    const [owner, , alice, bob, carol] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);
    // `business` = alice, so alice ends up holding the whole supply and can sign permits over it.
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
      name: TOKEN_NAME,
      symbol: "PMT",
    });

    return { token, tokenFactory, owner, alice, bob, carol, publicClient, chainId, viem };
  }

  async function signPermit(params: {
    pk: Hex;
    tokenAddress: `0x${string}`;
    owner: `0x${string}`;
    spender: `0x${string}`;
    value: bigint;
    nonce: bigint;
    deadline: bigint;
    chainId: number;
    name?: string;
  }): Promise<{ v: number; r: Hex; s: Hex }> {
    const sig = await signTypedData({
      privateKey: params.pk,
      domain: {
        name: params.name ?? TOKEN_NAME,
        version: "1",
        chainId: params.chainId,
        verifyingContract: params.tokenAddress,
      },
      types: PERMIT_TYPES,
      primaryType: "Permit",
      message: {
        owner: params.owner,
        spender: params.spender,
        value: params.value,
        nonce: params.nonce,
        deadline: params.deadline,
      },
    });
    return {
      r: `0x${sig.slice(2, 66)}` as Hex,
      s: `0x${sig.slice(66, 130)}` as Hex,
      v: parseInt(sig.slice(130, 132), 16),
    };
  }

  // ==========================================================================================
  // Storage layout — the beacon-wide risk
  // ==========================================================================================
  describe("storage layout is unshifted (BeaconProxy blast radius)", function () {
    it("launchpad / maxSupply / blacklist still occupy slots 1, 3 and 4 on a live token", async function () {
      const { token, tokenFactory, alice, publicClient } = await loadFixture(deployFixture);

      // Slot 0 = contractURI (string), 1 = launchpad, 2 = launchpadOwner, 3 = maxSupply,
      // 4 = blacklist, 5..54 = __gap. Read them RAW, not through the getters — a getter would
      // agree with a shifted layout because it shifts with it.
      const slot1 = (await publicClient.getStorageAt({
        address: token.address,
        slot: toHex(1, { size: 32 }),
      })) as Hex;
      assert.strictEqual(
        getAddress(`0x${slot1.slice(-40)}`),
        getAddress(tokenFactory.address),
        "slot 1 must still be `launchpad` (the deploying TokenFactory)",
      );

      const slot3 = (await publicClient.getStorageAt({
        address: token.address,
        slot: toHex(3, { size: 32 }),
      })) as Hex;
      assert.strictEqual(
        BigInt(slot3),
        TOTAL_SUPPLY,
        "slot 3 must still be `maxSupply` (locked to totalSupply at issuance)",
      );
      assert.strictEqual(BigInt(slot3), (await token.read.maxSupply()) as bigint);

      // `blacklist` is a mapping at slot 4: its entry lives at keccak256(key . slot). DEAD is used
      // as the key because addToBlacklist rejects both address(0) and the owner.
      await token.write.addToBlacklist([DEAD], { account: alice.account });
      const entrySlot = keccak256(
        encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [DEAD, 4n]),
      );
      const flag = (await publicClient.getStorageAt({
        address: token.address,
        slot: entrySlot,
      })) as Hex;
      assert.strictEqual(BigInt(flag), 1n, "slot 4 must still be the `blacklist` mapping");
    });

    it("the ERC-7201 EIP712 and Nonces namespaces are where OZ says they are, not in sequential slots", async function () {
      const { token, alice, publicClient, chainId } = await loadFixture(deployFixture);

      // openzeppelin.storage.Nonces — keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Nonces")) - 1)) & ~0xff
      const NONCES_NAMESPACE =
        "0x5ab42ced628888259c08ac98db1eb0cf702fc1501344311d8b100cd1bfe4bb00" as Hex;

      // Consume a nonce so the namespace slot is provably the one that changed.
      const deadline = (await time.latest()) + 3600n;
      const { v, r, s } = await signPermit({
        pk: ALICE_KEY,
        tokenAddress: token.address,
        owner: alice.account.address,
        spender: DEAD,
        value: 1n,
        nonce: 0n,
        deadline,
        chainId,
      });
      await token.write.permit([alice.account.address, DEAD, 1n, deadline, v, r, s], {
        account: alice.account,
      });

      // The nonce mapping lives at keccak256(owner . NONCES_NAMESPACE) — an absolute, hash-derived
      // location, NOT slot 5 (which is `__gap[0]`).
      const nonceSlot = keccak256(
        encodeAbiParameters(
          [{ type: "address" }, { type: "bytes32" }],
          [alice.account.address, NONCES_NAMESPACE],
        ),
      );
      const stored = (await publicClient.getStorageAt({
        address: token.address,
        slot: nonceSlot,
      })) as Hex;
      assert.strictEqual(BigInt(stored), 1n);
      assert.strictEqual((await token.read.nonces([alice.account.address])) as bigint, 1n);

      // And __gap[0] (slot 5) is untouched — permit state did not land in the reserved region.
      const gap0 = (await publicClient.getStorageAt({
        address: token.address,
        slot: toHex(5, { size: 32 }),
      })) as Hex;
      assert.strictEqual(BigInt(gap0), 0n, "__gap[0] must still be empty");
    });
  });

  // ==========================================================================================
  // permit behaviour
  // ==========================================================================================
  describe("permit", function () {
    it("binds the domain to the TOKEN's own name (so a wrong-name signature does not validate)", async function () {
      const { token, alice, bob, chainId } = await loadFixture(deployFixture);

      const deadline = (await time.latest()) + 3600n;
      const wrongName = await signPermit({
        pk: ALICE_KEY,
        tokenAddress: token.address,
        owner: alice.account.address,
        spender: bob.account.address,
        value: 1n,
        nonce: 0n,
        deadline,
        chainId,
        name: "NotThisToken",
      });

      await assertions.revertWithCustomError(
        token.write.permit(
          [
            alice.account.address,
            bob.account.address,
            1n,
            deadline,
            wrongName.v,
            wrongName.r,
            wrongName.s,
          ],
          { account: bob.account },
        ),
        token,
        "ERC2612InvalidSigner",
      );

      // Sanity: the DOMAIN_SEPARATOR is the one built from the real name.
      const expected = keccak256(
        encodeAbiParameters(
          [
            { type: "bytes32" },
            { type: "bytes32" },
            { type: "bytes32" },
            { type: "uint256" },
            { type: "address" },
          ],
          [
            keccak256(
              stringToHex(
                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
              ),
            ),
            keccak256(stringToHex(TOKEN_NAME)),
            keccak256(stringToHex("1")),
            BigInt(chainId),
            token.address,
          ],
        ),
      );
      assert.strictEqual((await token.read.DOMAIN_SEPARATOR()) as Hex, expected);
    });

    it("a RELAYER can submit the owner's signature — the owner sends no transaction", async function () {
      const { token, alice, bob, carol, chainId } = await loadFixture(deployFixture);

      const value = parseUnits("1234", 18);
      const deadline = (await time.latest()) + 3600n;
      const { v, r, s } = await signPermit({
        pk: ALICE_KEY,
        tokenAddress: token.address,
        owner: alice.account.address,
        spender: bob.account.address,
        value,
        nonce: 0n,
        deadline,
        chainId,
      });

      // carol (an unrelated relayer) submits it.
      await token.write.permit(
        [alice.account.address, bob.account.address, value, deadline, v, r, s],
        {
          account: carol.account,
        },
      );

      assert.strictEqual(
        (await token.read.allowance([alice.account.address, bob.account.address])) as bigint,
        value,
      );
      assert.strictEqual((await token.read.nonces([alice.account.address])) as bigint, 1n);

      // The allowance is a real one: bob can spend it.
      await token.write.transferFrom([alice.account.address, carol.account.address, value], {
        account: bob.account,
      });
      assert.strictEqual((await token.read.balanceOf([carol.account.address])) as bigint, value);
    });

    it("is single-use: replaying the same signature reverts on the bumped nonce", async function () {
      const { token, alice, bob, chainId } = await loadFixture(deployFixture);

      const value = parseUnits("10", 18);
      const deadline = (await time.latest()) + 3600n;
      const { v, r, s } = await signPermit({
        pk: ALICE_KEY,
        tokenAddress: token.address,
        owner: alice.account.address,
        spender: bob.account.address,
        value,
        nonce: 0n,
        deadline,
        chainId,
      });

      await token.write.permit(
        [alice.account.address, bob.account.address, value, deadline, v, r, s],
        {
          account: bob.account,
        },
      );
      await assertions.revertWithCustomError(
        token.write.permit([alice.account.address, bob.account.address, value, deadline, v, r, s], {
          account: bob.account,
        }),
        token,
        "ERC2612InvalidSigner",
      );
    });

    it("rejects an expired deadline with ERC2612ExpiredSignature", async function () {
      const { token, alice, bob, chainId } = await loadFixture(deployFixture);

      const deadline = (await time.latest()) - 1n;
      const { v, r, s } = await signPermit({
        pk: ALICE_KEY,
        tokenAddress: token.address,
        owner: alice.account.address,
        spender: bob.account.address,
        value: parseUnits("1", 18),
        nonce: 0n,
        deadline,
        chainId,
      });

      await assertions.revertWithCustomError(
        token.write.permit(
          [alice.account.address, bob.account.address, parseUnits("1", 18), deadline, v, r, s],
          { account: bob.account },
        ),
        token,
        "ERC2612ExpiredSignature",
      );
      assert.strictEqual(
        (await token.read.allowance([alice.account.address, bob.account.address])) as bigint,
        0n,
      );
    });

    it("does NOT bypass the blacklist: a permit-granted allowance still cannot move a blacklisted balance", async function () {
      const { token, alice, bob, carol, chainId } = await loadFixture(deployFixture);

      // bob receives supply and signs a permit for carol BEFORE being blacklisted. alice is the
      // token owner and therefore holds the blacklist key.
      const value = parseUnits("100", 18);
      await token.write.transfer([bob.account.address, value], { account: alice.account });

      const deadline = (await time.latest()) + 3600n;
      const { v, r, s } = await signPermit({
        pk: BOB_KEY,
        tokenAddress: token.address,
        owner: bob.account.address,
        spender: carol.account.address,
        value,
        nonce: 0n,
        deadline,
        chainId,
      });
      await token.write.permit(
        [bob.account.address, carol.account.address, value, deadline, v, r, s],
        {
          account: carol.account,
        },
      );
      assert.strictEqual(
        (await token.read.allowance([bob.account.address, carol.account.address])) as bigint,
        value,
      );

      await token.write.addToBlacklist([bob.account.address], { account: alice.account });

      // The allowance exists but the transfer gate still refuses it.
      await assertions.revertWithCustomError(
        token.write.transferFrom([bob.account.address, carol.account.address, value], {
          account: carol.account,
        }),
        token,
        "AccountBlacklisted",
      );
    });

    it("does NOT bypass pause: a permit-granted allowance still cannot move while paused", async function () {
      const { token, alice, bob, carol, chainId } = await loadFixture(deployFixture);

      const value = parseUnits("100", 18);
      await token.write.transfer([bob.account.address, value], { account: alice.account });

      const deadline = (await time.latest()) + 3600n;
      const { v, r, s } = await signPermit({
        pk: BOB_KEY,
        tokenAddress: token.address,
        owner: bob.account.address,
        spender: carol.account.address,
        value,
        nonce: 0n,
        deadline,
        chainId,
      });
      await token.write.permit(
        [bob.account.address, carol.account.address, value, deadline, v, r, s],
        {
          account: carol.account,
        },
      );

      await token.write.pause({ account: alice.account });

      // bob is an ordinary user, not platform infra, so the carve-out does not apply.
      await assertions.revertWithCustomError(
        token.write.transferFrom([bob.account.address, carol.account.address, value], {
          account: carol.account,
        }),
        token,
        "EnforcedPause",
      );

      // The allowance itself survives — permit grants approval, and approval is not a transfer.
      // This documents the boundary rather than asserting a bug.
      assert.strictEqual(
        (await token.read.allowance([bob.account.address, carol.account.address])) as bigint,
        value,
      );
    });
  });
});
