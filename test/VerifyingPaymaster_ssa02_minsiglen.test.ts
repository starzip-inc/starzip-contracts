/**
 * SSA-02 follow-up: `minSigLen`.
 *
 * `VerifyingPaymaster.getHash` cannot cover `userOp.signature` (`paymasterAndData` is itself part
 * of `userOpHash`, so the sponsor signs before the wallet owner does, and a passkey WebAuthn
 * assertion's real byte length is unknown until the user authenticates). A wallet could therefore
 * quote a sponsor signature / `preVerificationGas` against a padded draft signature and submit a
 * shorter real one, pocketing the difference from the paymaster deposit.
 *
 * `minSigLen` is a `uint16` the sponsor signs alongside `validUntil`/`validAfter`, checked as
 * `userOp.signature.length < minSigLen => decline`, plus a hard decline of `minSigLen == 0`. This
 * file covers the paymaster side only; the wallet-side companion fix
 * (`StarzipWallet._decodeSignatureWrapper`) is exercised in test/StarzipWallet_adversarial.test.ts.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseEther,
  zeroAddress,
  encodeFunctionData,
  hexToBytes,
  concatHex,
  pad,
  toHex,
  type Hex,
  type Address,
} from "viem";
import { loadFixture, getConnection, assertions } from "./helpers.js";
import {
  passkeyPubCoords,
  webauthnSignature,
  buildUserOp,
  encodePasskeyOwner,
  encodeSignatureWrapper,
  paymasterAndDataFor,
  signPaymasterData,
  SPONSOR_SIGNER,
} from "./aa-helpers.js";

const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const { x: PK_X, y: PK_Y } = passkeyPubCoords(PASSKEY_PRIV);

describe("SSA-02: minSigLen binds a signed floor on userOp.signature.length", function () {
  async function fixture() {
    const { viem } = await getConnection();
    const [deployer, ownerWallet, policyManagerWallet, beneficiary] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    const entryPoint = await viem.deployContract("TestEntryPoint", []);
    const paymaster = await viem.deployContract(
      "VerifyingPaymaster",
      [entryPoint.address, policyManagerWallet.account.address, zeroAddress, SPONSOR_SIGNER],
      { client: { wallet: ownerWallet } },
    );
    const factory = await viem.deployContract("StarzipWalletFactory", [entryPoint.address, paymaster.address]);

    const owner = encodePasskeyOwner(PK_X, PK_Y);
    const salt = 555555n;
    await factory.write.createAccount([[owner], salt], { account: deployer.account });
    const walletAddr = (await factory.read.getAddress([[owner], salt])) as Address;
    const account = await viem.getContractAt("StarzipWallet", walletAddr);
    await deployer.sendTransaction({ to: walletAddr, value: parseEther("2") });

    async function ownerWrite(fn: string, args: unknown[] = []): Promise<void> {
      const hash = await (paymaster.write as any)[fn](args, { account: ownerWallet.account });
      await publicClient.waitForTransactionReceipt({ hash });
    }
    async function pmWrite(fn: string, args: unknown[] = []): Promise<void> {
      const hash = await (paymaster.write as any)[fn](args, { account: policyManagerWallet.account });
      await publicClient.waitForTransactionReceipt({ hash });
    }

    // Generous ceilings — this suite is about minSigLen, not the other caps.
    await ownerWrite("setMaxSponsoredOpCost", [parseEther("1")]);
    await ownerWrite("setMaxSponsoredFeePerGas", [200_000_000_000n]);
    await ownerWrite("setMaxSponsoredPreVerificationGas", [1_000_000n]);
    await ownerWrite("setGlobalDailyCapCeiling", [parseEther("1")]);
    await ownerWrite("setGlobalDailyBudget", [parseEther("1")]);
    await pmWrite("setSponsored", [walletAddr, true]);
    await pmWrite("setDailyCap", [walletAddr, parseEther("1")]);
    await ownerWrite("setSponsorPersonal", [walletAddr, true]);
    await ownerWrite("unpause");

    const depositHash = await deployer.sendTransaction({
      to: paymaster.address,
      value: parseEther("10"),
      data: "0xd0e30db0" as Hex, // deposit()
    });
    await publicClient.waitForTransactionReceipt({ hash: depositHash });

    return { viem, publicClient, entryPoint, paymaster, account, walletAddr, deployer, beneficiary };
  }

  // Builds and REAL-signs (the actual owner passkey — never padded) a no-op sponsored op at the
  // given nonce/preVerificationGas, then signs paymasterAndData with the given minSigLen. Returns
  // both the op and the length of the REAL signature actually produced (constant across calls:
  // the WebAuthn challenge is always a fixed-length base64url(32-byte hash), so clientDataJSON's
  // length — and therefore the whole assertion's length — does not vary with nonce/PVG/userOpHash
  // content, only with its fixed 32-byte SIZE).
  async function buildOp(ctx: any, nonce: bigint, preVerificationGas: bigint, minSigLen: bigint) {
    const callData = encodeFunctionData({
      abi: ctx.account.abi,
      functionName: "execute",
      args: [ctx.walletAddr, 0n, "0x"],
    });
    const userOp = buildUserOp(ctx.walletAddr, nonce, callData);
    userOp.preVerificationGas = preVerificationGas;
    // Pin the EFFECTIVE gas price to a CONSTANT `maxFeePerGas`, independent of Hardhat
    // auto-mine's per-block EIP-1559 base-fee drift: EntryPoint's `UserOperationLib.gasPrice` is
    // `min(maxFeePerGas, maxPriorityFeePerGas + block.basefee)`. Setting
    // `maxPriorityFeePerGas == maxFeePerGas` guarantees `priority + basefee >= maxFeePerGas`
    // (basefee is never negative), so the min always resolves to the constant `maxFeePerGas`
    // regardless of which block a given op mines in. Without this, comparing wei-denominated
    // deposit drain across TWO separate handleOps transactions (necessarily two different
    // blocks) is confounded by base-fee drift between them — observed directly: the naive
    // default gasFees (1 gwei priority / 100 gwei max) produced a NEGATIVE gap here on the first
    // run, purely from base-fee movement between the control and exploit transactions, not from
    // anything this test is actually trying to measure.
    userOp.gasFees = pad(toHex((100_000_000_000n << 128n) | 100_000_000_000n), { size: 32 });
    userOp.paymasterAndData = paymasterAndDataFor(ctx.paymaster.address, 200_000n, 100_000n);
    const chainId = BigInt(await ctx.publicClient.getChainId());
    userOp.paymasterAndData = await signPaymasterData({ userOp, chainId, minSigLen });
    const userOpHash = (await ctx.entryPoint.read.getUserOpHash([userOp])) as Hex;
    const realSignature = encodeSignatureWrapper(0n, webauthnSignature(userOpHash, PASSKEY_PRIV));
    userOp.signature = realSignature;
    return { userOp, realSigLen: BigInt(hexToBytes(realSignature).length) };
  }

  async function depositOf(ctx: any): Promise<bigint> {
    return (await ctx.entryPoint.read.balanceOf([ctx.paymaster.address])) as bigint;
  }

  it("minSigLen == 0 (an unset floor) hard-declines instead of silently sponsoring", async function () {
    // Historical note (this test previously measured the LIVE exploit here — a SHORT real
    // signature sponsored under a preVerificationGas quote padded 512 bytes past it, draining the
    // deposit by the overdeclared gas with zero extra real calldata sent). That exploit is no
    // longer reachable via `minSigLen == 0` at all: the paymaster now hard-declines before ever
    // reaching the signature-length comparison, so there is no drain left to measure — the
    // strongest form of this assertion is that the op is declined and the deposit never moves.
    const ctx = await loadFixture(fixture);

    // The sponsor was shown a draft padded 512 bytes past the real signature and sized
    // `preVerificationGas` for it (roughly 512 * 16 gas/nonzero-calldata-byte ~ 8,192 gas under
    // EIP-2028; +10,000 for margin/round numbers, same spirit as this repo's other gas-margin
    // constants), then — the bug this test used to exercise — forgot to bind `minSigLen` at all
    // (left it at its zero value) rather than sizing it for the padded draft.
    const paddedPVG = 60_000n + 10_000n;

    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const { userOp, realSigLen } = await buildOp(ctx, n0, paddedPVG, 0n);
    assert.ok(realSigLen > 0n, "sanity: a real signature was actually produced");

    const depositBefore = await depositOf(ctx);
    await assert.rejects(
      ctx.entryPoint.write.handleOps([[userOp], ctx.beneficiary.account.address], {
        account: ctx.deployer.account,
      }),
      /AA34/,
      "an op signed with minSigLen == 0 must hard-decline (AA34), never fall through to sponsorship",
    );
    assert.strictEqual(
      await depositOf(ctx),
      depositBefore,
      "a declined op must never touch the paymaster deposit — no overdeclared-gas extraction is possible with the floor unset",
    );
  });

  it("a short real signature declines when minSigLen was sized for the padded draft", async function () {
    const ctx = await loadFixture(fixture);
    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const { realSigLen } = await buildOp(ctx, n0, 60_000n, 0n);
    const paddedDraftLen = realSigLen + 512n;

    const n1 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const { userOp } = await buildOp(ctx, n1, 70_000n, paddedDraftLen);

    assert.ok(
      BigInt(hexToBytes(userOp.signature).length) < paddedDraftLen,
      "sanity: the actually-submitted signature really is shorter than the signed minSigLen",
    );

    const depositBefore = await depositOf(ctx);
    await assert.rejects(
      ctx.entryPoint.write.handleOps([[userOp], ctx.beneficiary.account.address], {
        account: ctx.deployer.account,
      }),
      /AA34/,
      "a submission shorter than the signed minSigLen must hard-decline (AA34), not drain the deposit",
    );
    assert.strictEqual(
      await depositOf(ctx),
      depositBefore,
      "a declined op must never touch the paymaster deposit",
    );
  });

  it("512 bytes of literal padding on userOp.signature is rejected by the WALLET itself (AA24), not by minSigLen", async function () {
    const ctx = await loadFixture(fixture);
    const n0 = (await ctx.entryPoint.read.getNonce([ctx.walletAddr, 0n])) as bigint;
    const { userOp } = await buildOp(ctx, n0, 60_000n, 0n);
    userOp.signature = concatHex([userOp.signature, ("0x" + "aa".repeat(512)) as Hex]);

    await assert.rejects(
      ctx.entryPoint.write.handleOps([[userOp], ctx.beneficiary.account.address], {
        account: ctx.deployer.account,
      }),
      /AA24/,
      "a literally-padded signature must decline at wallet-level signature validation",
    );
  });
});
