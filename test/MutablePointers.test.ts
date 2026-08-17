/**
 * Audit Finding 02 — Mutable infrastructure pointers break existing token workflows.
 *
 * Regression guard: an issued token's escrow-release authority and blacklist-exempt
 * launchpad are PINNED to the issuance-time binding (`tokenToLaunchpad`), not the
 * mutable global `linkedLaunchpad` pointer. After the platform rotates
 * `linkedLaunchpad` from A to B:
 *   - B CANNOT consume the legacy token's one-shot escrow (releaseEscrow authorizes
 *     only the issuance-time launchpad A) — the escrow stays intact.
 *   - A (the issuance-time launchpad) can still create + finalize the sale, which
 *     starts the owner vesting wallet whose immutable binding is A.
 *   - The pre-rotation launchpad A remains blacklist-exempt for the token
 *     (`isPlatformContract`).
 *   - Rotated-out trade settlement endpoints stay authorized for outstanding
 *     withdrawals (`authorizedTradeSettlements`).
 *
 * PoC ported from the audit doc, inverted to assert the FIXED behavior.
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import { encodeFunctionData, getAddress, parseUnits, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { assertions, getConnection, time } from "./helpers.js";
import {
  buildRatios,
  configureDefaultAllocationGuides,
  deployTokenFactoryCore,
  setEscrowTimeout,
  setLinkedLaunchpad,
  issueTokenWithRatios,
  CONFIG_DELAY,
} from "./tokenFactoryHelpers.js";

const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const DAY = 24n * 60n * 60n;

async function deployLaunchpadProxy(viem: any, args: readonly unknown[]): Promise<any> {
  const implMathLib = await viem.deployContract("LaunchpadMathLib", []);
  const impl = await viem.deployContract("LaunchpadV1", [], {
    libraries: { LaunchpadMathLib: implMathLib.address },
  });
  const initData = encodeFunctionData({ abi: impl.abi, functionName: "initialize", args });
  const proxy = await viem.deployContract("ERC1967Proxy", [impl.address, initData]);
  return viem.getContractAt("LaunchpadV1", proxy.address);
}

describe("Audit-02: mutable infra pointers pinned to issuance-time binding", () => {
  it("rotating linkedLaunchpad does not let B consume legacy escrow; A still finalizes owner vesting", async () => {
    const { viem } = await getConnection();
    const [owner, business, investor, feeRecipient, platformTreasury] =
      await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();
    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);

    const paymentToken = await viem.deployContract("USDT", [owner.account.address, 18]);
    const { tokenFactory } = await deployTokenFactoryCore(
      viem,
      owner,
      platformTreasury.account.address as Address,
      permitSigner.address,
    );
    await configureDefaultAllocationGuides(tokenFactory, owner);

    const launchpadA = await deployLaunchpadProxy(viem, [
      tokenFactory.address,
      paymentToken.address,
      feeRecipient.account.address,
      platformTreasury.account.address,
    ]);
    const launchpadB = await deployLaunchpadProxy(viem, [
      tokenFactory.address,
      paymentToken.address,
      feeRecipient.account.address,
      platformTreasury.account.address,
    ]);

    // Bootstrap: tokens issued now bind their vesting wallet + escrow authority to A.
    await setLinkedLaunchpad(tokenFactory, owner, launchpadA.address);
    await setEscrowTimeout(tokenFactory, owner, 7n * DAY);

    const totalSupply = parseUnits("1000000", 18);
    const ratios = buildRatios({
      launchpadBp: 9000,
      liquidityBp: 1,
      ownerBp: 999,
      liquidityRecipient: platformTreasury.account.address,
    });

    const { tokenAddress, vestingWallet } = await issueTokenWithRatios({
      tokenFactory,
      business,
      publicClient,
      chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: launchpadA.address,
      name: "Legacy Issuance Token",
      symbol: "LIT",
      totalSupply,
      ratios,
    });
    const wallet = await viem.getContractAt("TokenVestingWallet", vestingWallet);

    // Issuance-time binding is pinned to A.
    assert.strictEqual(getAddress(await wallet.read.launchpad()), getAddress(launchpadA.address));
    assert.strictEqual(
      getAddress(await tokenFactory.read.tokenToLaunchpad([tokenAddress])),
      getAddress(launchpadA.address),
    );
    assert.strictEqual(await wallet.read.started(), false);

    // Privileged, supported rotation: factory now authorizes B globally.
    await tokenFactory.write.proposeLinkedLaunchpadChange([launchpadB.address], {
      account: owner.account,
    });
    await time.increase(CONFIG_DELAY);
    await tokenFactory.write.executeLinkedLaunchpadChange([], { account: owner.account });
    assert.strictEqual(
      getAddress(await tokenFactory.read.linkedLaunchpad()),
      getAddress(launchpadB.address),
    );

    // Blacklist exemption for the legacy launchpad A is preserved despite rotation.
    assert.strictEqual(
      await tokenFactory.read.isPlatformContract([tokenAddress, launchpadA.address]),
      true,
    );

    const escrowBefore = (await tokenFactory.read.launchpadEscrow([tokenAddress])) as bigint;
    assert.ok(escrowBefore > 0n, "legacy token has unconsumed launchpad escrow");

    // FIX: B is the current global linkedLaunchpad but is NOT the token's issuance-time
    // launchpad, so releaseEscrow rejects it. The escrow stays intact.
    await launchpadB.write.setPreparationTime([3600n], { account: owner.account });
    await launchpadB.write.setLaunchpadDuration([DAY], { account: owner.account });
    await assertions.revertWithCustomError(
      launchpadB.write.createLaunchpad(
        [tokenAddress, parseUnits("1", 18), business.account.address, paymentToken.address, 0n, 0n],
        { account: business.account },
      ),
      tokenFactory,
      "NotLinkedLaunchpad",
    );
    const [escrowAfterB, , consumedB] = (await tokenFactory.read.getEscrowInfo([tokenAddress])) as [
      bigint,
      bigint,
      boolean,
    ];
    assert.strictEqual(consumedB, false, "escrow untouched by the rotated launchpad B");
    assert.strictEqual(escrowAfterB, escrowBefore);

    // The issuance-time launchpad A can still create and finalize the sale.
    await launchpadA.write.setPreparationTime([3600n], { account: owner.account });
    await launchpadA.write.setLaunchpadDuration([DAY], { account: owner.account });
    await launchpadA.write.createLaunchpad(
      [tokenAddress, parseUnits("1", 18), business.account.address, paymentToken.address, 0n, 0n],
      { account: business.account },
    );

    const info = (await launchpadA.read.getLaunchpadInfo([0n])) as {
      startTime: bigint;
      endTime: bigint;
      saleAmount: bigint;
    };
    assert.strictEqual(info.saleAmount, escrowBefore);
    assert.strictEqual(
      getAddress(await launchpadA.read.launchpadOwnerVestingWallet([0n])),
      getAddress(vestingWallet),
    );
    // Per-sale factory snapshot recorded.
    assert.strictEqual(
      getAddress(await launchpadA.read.launchpadTokenFactory([0n])),
      getAddress(tokenFactory.address),
    );

    // finalizeLaunchpad now reverts (does not auto-cancel) below the 20% softcap
    // — this test is about the owner-vesting/mutable-pointer fix, so the
    // participation must clear the floor for finalize to succeed as asserted below.
    const participationAmount = parseUnits("200000", 18);
    await paymentToken.write.mint([investor.account.address, participationAmount], {
      account: owner.account,
    });
    await paymentToken.write.approve([launchpadA.address, participationAmount], {
      account: investor.account,
    });
    await time.increaseTo(info.startTime);
    await launchpadA.write.participate([0n, participationAmount], { account: investor.account });
    await time.increaseTo(info.endTime + 1n);

    await launchpadA.write.finalizeLaunchpad([0n], { account: owner.account });

    // FIX: finalize reaches the owner vesting wallet whose immutable binding is A and starts it.
    assert.strictEqual(
      await wallet.read.started(),
      true,
      "owner vesting started via issuance-time launchpad",
    );
    assert.strictEqual(await launchpadA.read.ownerVestingTrigger([0n]), true);
  });

  it("rotating tradeSettlement keeps the old endpoint authorized for outstanding withdrawals", async () => {
    const { viem } = await getConnection();
    const [owner, business, feeRecipient, platformTreasury, oldSettlement, newSettlement] =
      await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();
    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);

    const { tokenFactory } = await deployTokenFactoryCore(
      viem,
      owner,
      platformTreasury.account.address as Address,
      permitSigner.address,
    );
    await configureDefaultAllocationGuides(tokenFactory, owner);

    const launchpadA = await deployLaunchpadProxy(viem, [
      tokenFactory.address,
      (await viem.deployContract("USDT", [owner.account.address, 18])).address,
      feeRecipient.account.address,
      platformTreasury.account.address,
    ]);
    await setLinkedLaunchpad(tokenFactory, owner, launchpadA.address);
    await setEscrowTimeout(tokenFactory, owner, 7n * DAY);

    const ratios = buildRatios({
      launchpadBp: 9000,
      liquidityBp: 1,
      ownerBp: 999,
      liquidityRecipient: platformTreasury.account.address,
    });
    const { tokenAddress } = await issueTokenWithRatios({
      tokenFactory,
      business,
      publicClient,
      chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: launchpadA.address,
      name: "Settlement Token",
      symbol: "SET",
      totalSupply: parseUnits("1000000", 18),
      ratios,
    });

    // Bootstrap settlement to S1, then timelock-rotate to S2.
    await tokenFactory.write.setTradeSettlement([oldSettlement.account.address], {
      account: owner.account,
    });
    assert.strictEqual(
      await tokenFactory.read.isPlatformContract([tokenAddress, oldSettlement.account.address]),
      true,
    );

    await tokenFactory.write.proposeTradeSettlementChange([newSettlement.account.address], {
      account: owner.account,
    });
    await time.increase(CONFIG_DELAY);
    await tokenFactory.write.executeTradeSettlementChange([], { account: owner.account });

    assert.strictEqual(
      getAddress(await tokenFactory.read.tradeSettlement()),
      getAddress(newSettlement.account.address),
    );
    // FIX: the rotated-out settlement remains authorized (historical withdrawals).
    assert.strictEqual(
      await tokenFactory.read.authorizedTradeSettlements([oldSettlement.account.address]),
      true,
    );
    assert.strictEqual(
      await tokenFactory.read.isPlatformContract([tokenAddress, oldSettlement.account.address]),
      true,
    );
    assert.strictEqual(
      await tokenFactory.read.isPlatformContract([tokenAddress, newSettlement.account.address]),
      true,
    );
  });
});
