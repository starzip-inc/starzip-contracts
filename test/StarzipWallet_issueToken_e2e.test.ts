/**
 * E2E harness (member request, boss GO): prove that a StarzipWallet whose address
 * member derives off-chain (computeSalt) is the SAME address actually deployed by
 * StarzipWalletFactory, and that this passkey wallet can drive TokenFactory.issueToken
 * end-to-end via a real ERC-4337 EntryPoint.handleOps with a real WebAuthn P-256 signature.
 *
 *   factory.getAddress(x,y,owner,salt)  ==  factory.createAccount(...)         [address parity]
 *   EntryPoint.handleOps([userOp])  ->  StarzipWallet.validateUserOp (WebAuthn.verify, requireUV)
 *                                   ->  StarzipWallet.execute(TokenFactory, issueToken(...))
 *                                   ->  TokenIssued (token deployed)            [full E2E]
 *
 * permitSigner workaround: harness deploys TokenFactory with a test secp256k1 signer
 * (no real KMS 0xd814 in tests); IssuePermit is ECDSA-signed by that test key.
 *
 * owner note: member's spec used owner=address(0) (passkey-only). initialize REVERTS on a
 * zero-address EOA owner (see GAP-1); a passkey owner has no such analogue — the happy-path E2E
 * simply registers the passkey itself as the wallet's first (and only) owner, exactly as
 * StarzipWallet's multi-owner model intends (see StarzipWallet.sol's contract-level NatSpec).
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseUnits,
  parseEther,
  getAddress,
  encodeFunctionData,
  parseEventLogs,
  keccak256,
  toHex,
  hexToBytes,
  concatHex,
  zeroAddress,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { loadFixture, getConnection, time } from "./helpers.js";
import {
  passkeyPubCoords,
  webauthnSignature,
  buildUserOp,
  encodeAddressOwner,
  encodePasskeyOwner,
  encodeSignatureWrapper,
} from "./aa-helpers.js";
import {
  deployTokenFactoryCore,
  buildRatios,
  signIssuePermit,
  configureDefaultAllocationGuides,
  setLinkedLaunchpad,
} from "./tokenFactoryHelpers.js";

// secp256k1 test key as TokenFactory permitSigner (Hardhat account #0 key).
const PERMIT_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
// Deterministic P-256 passkey. Scalar < n.
const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const { x: PASSKEY_X, y: PASSKEY_Y } = passkeyPubCoords(PASSKEY_PRIV);
const FIRST_OWNER = encodePasskeyOwner(PASSKEY_X, PASSKEY_Y);

// member computeSalt: keccak256( keccak256("starzip.smartwallet.v1") || keccak256(uid) )
const SALT_DOMAIN_TAG = keccak256(toHex("starzip.smartwallet.v1"));
const TEST_UID = "test-user-001";
const MEMBER_SALT = keccak256(concatHex([SALT_DOMAIN_TAG, keccak256(toHex(TEST_UID))]));
const MEMBER_SALT_UINT = BigInt(MEMBER_SALT);

const TOTAL_SUPPLY = parseUnits("1000000", 18);

describe("StarzipWallet -> TokenFactory.issueToken (E2E, member request)", function () {
  async function deployFixture() {
    const { viem } = await getConnection();
    const [deployer, platformTreasury, beneficiary] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    const walletFactory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, zeroAddress]);

    // 4-bucket TokenFactory core (ERC20 beacon + TokenVestingWallet beacon + proxy).
    const permitSigner = privateKeyToAccount(PERMIT_PRIVATE_KEY);
    const core = await deployTokenFactoryCore(
      viem,
      deployer,
      platformTreasury.account.address,
      permitSigner.address,
    );
    const tokenFactory = core.tokenFactory;

    // Wire permissive allocation guides + a linkedLaunchpad pointer (both 2-day
    // timelocked) so issueToken passes 4-bucket validation. linkedLaunchpad is a
    // placeholder contract address — this E2E never exercises escrow release.
    const linkedLaunchpad = core.erc20Beacon.address;
    await configureDefaultAllocationGuides(tokenFactory, deployer);
    await setLinkedLaunchpad(tokenFactory, deployer, linkedLaunchpad);

    return {
      viem,
      publicClient,
      chainId,
      entryPoint,
      walletFactory,
      tokenFactory,
      deployer,
      beneficiary,
      platformTreasury,
      linkedLaunchpad,
    };
  }

  it("GAP-1 / SSA-16: getAddress(owner=0) reverts ZeroAddress instead of computing an undeployable phantom address", async function () {
    const { walletFactory, deployer } = await loadFixture(deployFixture);
    const zeroOwner = encodeAddressOwner(zeroAddress);
    // SSA-16: getAddress runs the same owner-set validation createAccount does
    // (StarzipWallet.validateOwnerBytes), so it rejects owner=0 with the same error.
    await assert.rejects(
      walletFactory.read.getAddress([[zeroOwner], MEMBER_SALT_UINT]) as Promise<Address>,
      /ZeroAddress/,
    );
    await assert.rejects(
      walletFactory.write.createAccount([[zeroOwner], MEMBER_SALT_UINT], {
        account: deployer.account,
      }),
      /ZeroAddress/,
    );
  });

  it("address parity: factory.getAddress == createAccount (member salt, passkey owner)", async function () {
    const { walletFactory, deployer, publicClient } = await loadFixture(deployFixture);
    const predicted = (await walletFactory.read.getAddress([
      [FIRST_OWNER],
      MEMBER_SALT_UINT,
    ])) as Address;
    const hash = await walletFactory.write.createAccount([[FIRST_OWNER], MEMBER_SALT_UINT], {
      account: deployer.account,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const created = parseEventLogs({
      abi: walletFactory.abi,
      logs: receipt.logs,
      eventName: "AccountCreated",
    })[0];
    const deployedCode = await publicClient.getCode({ address: predicted });
    assert.strictEqual(getAddress((created as any).args.account as Address), getAddress(predicted));
    assert.ok(deployedCode && deployedCode !== "0x", "predicted address must have code");
    console.log(`[PARITY] predicted == deployed == ${getAddress(predicted)} (salt=${MEMBER_SALT})`);
  });

  it("E2E: WebAuthn P-256 userOp via EntryPoint.handleOps issues a token", async function () {
    const {
      viem,
      publicClient,
      chainId,
      entryPoint,
      walletFactory,
      tokenFactory,
      deployer,
      beneficiary,
      platformTreasury,
      linkedLaunchpad,
    } = await loadFixture(deployFixture);

    // 1) deploy the passkey wallet at the member-derived address (passkey is the sole owner)
    const walletAddr = (await walletFactory.read.getAddress([
      [FIRST_OWNER],
      MEMBER_SALT_UINT,
    ])) as Address;
    await walletFactory.write.createAccount([[FIRST_OWNER], MEMBER_SALT_UINT], {
      account: deployer.account,
    });

    // 2) prefund for EntryPoint prefund
    await deployer.sendTransaction({ to: walletAddr, value: parseEther("2") });

    // 3) issueToken calldata with TEST-signer IssuePermit (businessAccount = wallet)
    const name = "StoreToken";
    const symbol = "STK";
    const contractURI = "ipfs://store-token-metadata";
    const deadline = (await time.latest()) + 3600n;
    const permitNonce = (await tokenFactory.read.nonces([walletAddr])) as bigint;

    // 14-field IssuePermit: launchpad 0 / liquidity 100% / owner 0 (3-bucket model).
    // Recipient must NOT be the businessAccount (the wallet) — route to platformTreasury.
    const ratios = buildRatios({
      launchpadBp: 0,
      liquidityBp: 10000,
      ownerBp: 0,
      liquidityRecipient: platformTreasury.account.address,
    });
    const issuePermitSig = await signIssuePermit({
      privateKey: PERMIT_PRIVATE_KEY,
      chainId,
      verifyingContract: tokenFactory.address,
      businessAccount: walletAddr,
      name,
      symbol,
      totalSupply: TOTAL_SUPPLY,
      contractURI,
      ratios,
      linkedLaunchpad,
      nonce: permitNonce,
      deadline,
    });
    const issueCalldata = encodeFunctionData({
      abi: tokenFactory.abi,
      functionName: "issueToken",
      args: [name, symbol, TOTAL_SUPPLY, contractURI, ratios, deadline, issuePermitSig],
    });

    // 4) wallet callData: execute(TokenFactory, 0, issueToken(...))
    const account = await viem.getContractAt("StarzipWallet", walletAddr);
    const callData = encodeFunctionData({
      abi: account.abi,
      functionName: "execute",
      args: [tokenFactory.address, 0n, issueCalldata],
    });

    // 5) PackedUserOperation (v0.8), hashed by the real EntryPoint, signed with the passkey
    const nonce = (await entryPoint.read.getNonce([walletAddr, 0n])) as bigint;
    const userOp = buildUserOp(walletAddr, nonce, callData);
    const userOpHash = (await entryPoint.read.getUserOpHash([userOp])) as Hex;
    userOp.signature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));

    // 6) submit
    const hash = await entryPoint.write.handleOps([[userOp], beneficiary.account.address], {
      account: deployer.account,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });

    // 7) assert a token was issued by the wallet
    const issued = parseEventLogs({
      abi: tokenFactory.abi,
      logs: receipt.logs,
      eventName: "TokenIssued",
    });
    assert.strictEqual(issued.length, 1, "exactly one TokenIssued expected");
    const tokenAddr = (issued[0] as any).args.tokenAddress as Address;
    assert.strictEqual(
      getAddress((issued[0] as any).args.businessAccount as Address),
      getAddress(walletAddr),
    );
    assert.strictEqual((await tokenFactory.read.getTokenCount()) as bigint, 1n);
    assert.strictEqual(await tokenFactory.read.isIssuedToken([tokenAddr]), true);

    const token = await viem.getContractAt("ERC20V1", tokenAddr);
    assert.strictEqual(await token.read.name(), name);
    assert.strictEqual(await token.read.symbol(), symbol);

    console.log(
      `[E2E] handleOps OK. wallet=${getAddress(walletAddr)} issued token=${getAddress(tokenAddr)} supply=${TOTAL_SUPPLY}`,
    );
  });
});
