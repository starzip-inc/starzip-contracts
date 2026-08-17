import { describe, it } from "node:test";
import assert from "node:assert";
import { parseUnits, encodeFunctionData, type Address, type Hex } from "viem";
import { loadFixture, time, getConnection } from "./helpers.js";
import { privateKeyToAccount } from "viem/accounts";
import {
  deployTokenFactoryCore,
  configureDefaultAllocationGuides,
  setLinkedLaunchpad,
  setEscrowTimeout,
  setResaleWait,
  issueTokenWithRatios,
  buildRatios,
} from "./tokenFactoryHelpers.js";

const TEST_PRIVATE_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

const BP = 10000n;
const SCHEDULE = [2000n, 1000n, 1000n, 2000n, 1000n, 1000n, 1000n, 1000n];

/**
 * arithmetic-dos lane probes. 6-decimal payment token (untested elsewhere in this repo:
 * every LaunchpadV1 fixture uses an 18-decimal USDT, so the 10**(18-d) scaling in
 * finalizeLaunchpad/claimVestedPayment has never been exercised).
 */
describe("AUDIT arithmetic-dos", function () {
  async function fixture(paymentDecimals: number) {
    const { viem } = await getConnection();
    const [owner, business, user1, user2, feeRecipient, platformTreasury] =
      await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();
    const chainId = await publicClient.getChainId();

    const pay = await viem.deployContract("USDT", [owner.account.address, paymentDecimals]);
    const permitSigner = privateKeyToAccount(TEST_PRIVATE_KEY);

    const { tokenFactory } = await deployTokenFactoryCore(
      viem,
      owner,
      platformTreasury.account.address,
      permitSigner.address,
    );
    await configureDefaultAllocationGuides(tokenFactory, owner);

    const launchpadImplMathLib = await viem.deployContract("LaunchpadMathLib", []);
    const launchpadImpl = await viem.deployContract("LaunchpadV1", [], {
      libraries: { LaunchpadMathLib: launchpadImplMathLib.address },
    });
    const initData = encodeFunctionData({
      abi: launchpadImpl.abi,
      functionName: "initialize",
      args: [
        tokenFactory.address,
        pay.address,
        feeRecipient.account.address,
        platformTreasury.account.address,
      ],
    });
    const proxy = await viem.deployContract("ERC1967Proxy", [launchpadImpl.address, initData]);
    const launchpad = await viem.getContractAt("LaunchpadV1", proxy.address);

    await setLinkedLaunchpad(tokenFactory, owner, launchpad.address);
    await setEscrowTimeout(tokenFactory, owner, 7n * 24n * 60n * 60n);
    await setResaleWait(tokenFactory, owner, 7n * 24n * 60n * 60n);

    return {
      viem,
      publicClient,
      chainId,
      launchpad,
      tokenFactory,
      pay,
      owner,
      business,
      user1,
      user2,
      feeRecipient,
      platformTreasury,
    };
  }

  async function fixture6() {
    return fixture(6);
  }
  async function fixture18() {
    return fixture(18);
  }

  async function makeSale(
    f: Awaited<ReturnType<typeof fixture>>,
    opts: { totalSupply: bigint; launchpadBp: number; ownerBp: number; tokenPrice: bigint },
  ) {
    const liquidityBp = 10000 - opts.launchpadBp - opts.ownerBp;
    const ratios = buildRatios({
      launchpadBp: opts.launchpadBp,
      liquidityBp,
      ownerBp: opts.ownerBp,
      liquidityRecipient: f.platformTreasury.account.address,
    });
    const { tokenAddress } = await issueTokenWithRatios({
      tokenFactory: f.tokenFactory,
      business: f.business,
      publicClient: f.publicClient,
      chainId: f.chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: f.launchpad.address,
      name: "T",
      symbol: "T",
      totalSupply: opts.totalSupply,
      contractURI: "",
      ratios,
    });
    await f.launchpad.write.createLaunchpad(
      [tokenAddress, opts.tokenPrice, f.business.account.address, f.pay.address, 0n, 0n],
      { account: f.business.account },
    );
    const info = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    return { tokenAddress, saleAmount: info.saleAmount as bigint, info };
  }

  // ---------------------------------------------------------------------------
  // P1: 3-way fund split — exact conservation + where the dust goes.
  // ---------------------------------------------------------------------------
  it("P1: fee + immediate + liquidity + vestingRemainder == totalRaised exactly (6-dec)", async function () {
    const f = await loadFixture(fixture6);
    const price = parseUnits("1", 18); // 1 payment unit per whole token
    const { saleAmount } = await makeSale(f, {
      totalSupply: parseUnits("1000000", 18),
      launchpadBp: 2000,
      ownerBp: 0,
      tokenPrice: price,
    });

    // deliberately "ugly" raise so both mulDiv floors leave a remainder
    const raise = 50_000_000_003n; // 50,000.000003 payment units (6 dec)
    await f.pay.write.mint([f.user1.account.address, raise * 10n]);
    await f.pay.write.approve([f.launchpad.address, raise * 10n], { account: f.user1.account });

    const info0 = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    await time.increaseTo(info0.startTime + 1n);
    await f.launchpad.write.participate([0n, raise], { account: f.user1.account });

    const info1 = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    await time.increaseTo(info1.endTime + 1n);

    const feeBefore = await f.pay.read.balanceOf([f.feeRecipient.account.address]);
    const bizBefore = await f.pay.read.balanceOf([f.business.account.address]);
    const liqBefore = await f.pay.read.balanceOf([f.platformTreasury.account.address]);

    await f.launchpad.write.finalizeLaunchpad([0n], { account: f.owner.account });

    const fee = (await f.pay.read.balanceOf([f.feeRecipient.account.address])) - feeBefore;
    const imm = (await f.pay.read.balanceOf([f.business.account.address])) - bizBefore;
    const liq = (await f.pay.read.balanceOf([f.platformTreasury.account.address])) - liqBefore;
    const locked = (await f.launchpad.read.lockedPaymentAmount([f.pay.address])) as bigint;
    const held = await f.pay.read.balanceOf([f.launchpad.address]);

    console.log({ saleAmount, raise, fee, imm, liq, locked, held });

    // exact conservation
    assert.strictEqual(fee + imm + liq + locked, raise, "3-way split does not sum to totalRaised");
    assert.strictEqual(held, locked, "held payment balance != locked");

    // dust destination: vesting residual is >= the clean vestingBp share
    const remaining = raise - fee;
    const cleanVesting = (remaining * 7158n) / BP;
    assert.ok(locked >= cleanVesting, "vesting residual lost dust");
    assert.ok(locked - cleanVesting <= 2n, "vesting residual absorbed more than 2 wei of dust");

    // vesting bookkeeping is scaled to 18 decimals
    const v = (await f.launchpad.read.getVestingInfo([0n])) as any;
    assert.strictEqual(v.totalAmount as bigint, locked * 10n ** 12n);
  });

  // ---------------------------------------------------------------------------
  // P2: 8-period vesting — equality at EVERY checkpoint, and the final total.
  // ---------------------------------------------------------------------------
  it("P2: per-period claims must sum to the vesting principal (equality, not <=)", async function () {
    const f = await loadFixture(fixture6);
    const price = parseUnits("1", 18);
    await makeSale(f, {
      totalSupply: parseUnits("1000000", 18),
      launchpadBp: 2000,
      ownerBp: 0,
      tokenPrice: price,
    });

    const raise = 50_000_000_003n;
    await f.pay.write.mint([f.user1.account.address, raise * 10n]);
    await f.pay.write.approve([f.launchpad.address, raise * 10n], { account: f.user1.account });
    const info0 = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    await time.increaseTo(info0.startTime + 1n);
    await f.launchpad.write.participate([0n, raise], { account: f.user1.account });
    const info1 = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    await time.increaseTo(info1.endTime + 1n);
    await f.launchpad.write.finalizeLaunchpad([0n], { account: f.owner.account });

    const principal = (await f.launchpad.read.lockedPaymentAmount([f.pay.address])) as bigint;
    const schedule = (await f.launchpad.read.getLaunchpadVestingSchedule([0n])) as any;
    const interval = schedule.vestingInterval as bigint;

    let cumBp = 0n;
    let paid = 0n;
    const bizStart = await f.pay.read.balanceOf([f.business.account.address]);
    for (let k = 0; k < 8; k++) {
      await time.increase(interval);
      cumBp += SCHEDULE[k];
      const before = await f.pay.read.balanceOf([f.business.account.address]);
      await f.launchpad.write.claimVestedPayment([0n], { account: f.business.account });
      const got = (await f.pay.read.balanceOf([f.business.account.address])) - before;
      paid += got;
      // checkpoint equality against the exact bp entitlement
      const expected = (principal * SCHEDULE[k]) / BP;
      console.log(`period ${k + 1}: got=${got} expectedFloor=${expected}`);
      assert.strictEqual(got, expected, `period ${k + 1} payout != floor(principal*bp/1e4)`);
    }
    const totalPaid = (await f.pay.read.balanceOf([f.business.account.address])) - bizStart;
    assert.strictEqual(paid, totalPaid);

    const lockedAfter = (await f.launchpad.read.lockedPaymentAmount([f.pay.address])) as bigint;
    const heldAfter = await f.pay.read.balanceOf([f.launchpad.address]);
    console.log({ principal, totalPaid, shortfall: principal - totalPaid, lockedAfter, heldAfter });

    // vesting is fully consumed on the books
    const vAfter = (await f.launchpad.read.getVestingInfo([0n])) as any;
    assert.strictEqual(vAfter.claimedAmount as bigint, vAfter.totalAmount as bigint);

    // A-1 (DEFECT, characterized): per-period claims do NOT sum to the principal.
    // The 18-dec bookkeeping says fully claimed, but 3 units never left the contract and
    // stay in lockedPaymentAmount forever (unclaimable AND unsweepable).
    // The naive "claimed <= total" predicate (LaunchpadInvariants.t.sol I3) cannot see this.
    assert.strictEqual(principal - totalPaid, 3n, "A-1: expected 3 stranded payment units");
    assert.strictEqual(lockedAfter, 3n, "A-1: stranded dust stays locked forever");
    assert.strictEqual(heldAfter, 3n, "A-1: stranded dust still held by the contract");
  });

  it("P2b [A-1]: claiming once at the end pays MORE than claiming every period", async function () {
    const f = await loadFixture(fixture6);
    const price = parseUnits("1", 18);
    await makeSale(f, {
      totalSupply: parseUnits("1000000", 18),
      launchpadBp: 2000,
      ownerBp: 0,
      tokenPrice: price,
    });
    const raise = 50_000_000_003n;
    await f.pay.write.mint([f.user1.account.address, raise * 10n]);
    await f.pay.write.approve([f.launchpad.address, raise * 10n], { account: f.user1.account });
    const info0 = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    await time.increaseTo(info0.startTime + 1n);
    await f.launchpad.write.participate([0n, raise], { account: f.user1.account });
    const info1 = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    await time.increaseTo(info1.endTime + 1n);
    await f.launchpad.write.finalizeLaunchpad([0n], { account: f.owner.account });

    const principal = (await f.launchpad.read.lockedPaymentAmount([f.pay.address])) as bigint;
    const schedule = (await f.launchpad.read.getLaunchpadVestingSchedule([0n])) as any;
    const vestingDuration = (schedule.vestingInterval as bigint) * BigInt(schedule.bps.length);
    await time.increase(vestingDuration + 1n);

    const before = await f.pay.read.balanceOf([f.business.account.address]);
    await f.launchpad.write.claimVestedPayment([0n], { account: f.business.account });
    const got = (await f.pay.read.balanceOf([f.business.account.address])) - before;
    console.log({ principal, singleClaim: got });
    assert.strictEqual(got, principal, "single terminal claim != principal");
  });

  // ---------------------------------------------------------------------------
  // P3: getVestingScheduleInfo (linear) vs the real non-uniform claim path.
  // ---------------------------------------------------------------------------
  it("P3: getVestingScheduleInfo.totalUnlocked must match getClaimableVesting", async function () {
    const f = await loadFixture(fixture18);
    const price = parseUnits("1", 18);
    await makeSale(f, {
      totalSupply: parseUnits("1000000", 18),
      launchpadBp: 2000,
      ownerBp: 0,
      tokenPrice: price,
    });
    const raise = parseUnits("50000", 18);
    await f.pay.write.mint([f.user1.account.address, raise * 10n]);
    await f.pay.write.approve([f.launchpad.address, raise * 10n], { account: f.user1.account });
    const info0 = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    await time.increaseTo(info0.startTime + 1n);
    await f.launchpad.write.participate([0n, raise], { account: f.user1.account });
    const info1 = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    await time.increaseTo(info1.endTime + 1n);
    await f.launchpad.write.finalizeLaunchpad([0n], { account: f.owner.account });

    const v = (await f.launchpad.read.getVestingInfo([0n])) as any;
    const schedule = (await f.launchpad.read.getLaunchpadVestingSchedule([0n])) as any;
    await time.increase((schedule.vestingInterval as bigint) + 1n);

    const claimable = (await f.launchpad.read.getClaimableVesting([0n])) as bigint;
    const sched = (await f.launchpad.read.getVestingScheduleInfo([0n])) as any[];
    const reportedUnlocked = sched[3] as bigint;
    // (FIXED): the view and the claim path now share `_unlockedBpThrough`, so they cannot
    // disagree. Before the fix the view computed mulDiv(total, currentPeriod, totalPeriods) — a
    // LINEAR model — while claims summed the non-uniform bp schedule, so at period 1 the view
    // reported 12.5% where the business could actually claim 20%: a 37.5% under-report that
    // re-converged only at the final period. No test referenced this view at all before.
    assert.strictEqual(
      reportedUnlocked,
      claimable,
      "the view must agree with the claim path",
    );
    assert.strictEqual(
      claimable,
      ((v.totalAmount as bigint) * 2000n) / BP,
      "and both must follow the real bp schedule, not a linear fraction",
    );
    assert.notStrictEqual(
      reportedUnlocked,
      (v.totalAmount as bigint) / 8n,
      "a linear 1/8 here would mean the old model is back",
    );
  });

  // ---------------------------------------------------------------------------
  // P4: fee-on-transfer / deflationary payment token vs participate()'s
  //     requested-amount (not measured-delta) credit.
  // ---------------------------------------------------------------------------
  it("P4: FoT payment token makes lockedPaymentAmount exceed the real balance (refund DoS)", async function () {
    const f = await loadFixture(fixture18);
    const fot = await (
      await getConnection()
    ).viem.deployContract("MockFeeOnTransferToken", [
      "FOT",
      "FOT",
      100n, // 1%
    ]);
    await f.launchpad.write.setAcceptedPaymentToken([fot.address, true], {
      account: f.owner.account,
    });

    const price = parseUnits("1", 18);
    await makeSale(f, {
      totalSupply: parseUnits("1000000", 18),
      launchpadBp: 2000,
      ownerBp: 0,
      tokenPrice: price,
    });
    // re-create the sale against the FoT token
    const ratios = buildRatios({
      launchpadBp: 2000,
      liquidityBp: 8000,
      ownerBp: 0,
      liquidityRecipient: f.platformTreasury.account.address,
    });
    const { tokenAddress } = await issueTokenWithRatios({
      tokenFactory: f.tokenFactory,
      business: f.business,
      publicClient: f.publicClient,
      chainId: f.chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: f.launchpad.address,
      name: "T2",
      symbol: "T2",
      totalSupply: parseUnits("1000000", 18),
      contractURI: "",
      ratios,
    });
    await f.launchpad.write.createLaunchpad(
      [tokenAddress, price, f.business.account.address, fot.address, 0n, 0n],
      { account: f.business.account },
    );

    const raise = parseUnits("1000", 18);
    await fot.write.mint([f.user1.account.address, raise * 10n]);
    await fot.write.approve([f.launchpad.address, raise * 10n], { account: f.user1.account });
    const info0 = (await f.launchpad.read.getLaunchpadInfo([1n])) as any;
    await time.increaseTo(info0.startTime + 1n);
    await f.launchpad.write.participate([1n, raise], { account: f.user1.account });

    const locked = (await f.launchpad.read.lockedPaymentAmount([fot.address])) as bigint;
    const held = await fot.read.balanceOf([f.launchpad.address]);
    const received = (raise * 9900n) / 10000n; // the mock takes 1%

    // (FIXED): participate() credits the MEASURED balance delta. Before the fix it credited
    // the requested `raise`, so `locked` exceeded `held` from the very first participation and the
    // launchpad promised more than it held.
    assert.strictEqual(
      locked,
      received,
      "locked must be the RECEIVED amount, not the requested one",
    );
    assert.strictEqual(held, locked, "the launchpad must hold exactly what it has promised");

    const participant = (await f.launchpad.read.getParticipantInfo([
      1n,
      f.user1.account.address,
    ])) as any;
    assert.strictEqual(
      participant.paymentAmount,
      received,
      "participant credit must be the measured delta",
    );

    // ...and therefore the refund path is solvent, where it used to revert ERC20InsufficientBalance.
    const info1 = (await f.launchpad.read.getLaunchpadInfo([1n])) as any;
    await time.increaseTo(info1.endTime + 1n);
    await f.launchpad.write.cancelUnderfundedLaunchpad([1n]);

    const before = await fot.read.balanceOf([f.user1.account.address]);
    await f.launchpad.write.refund([1n], { account: f.user1.account });
    const after = await fot.read.balanceOf([f.user1.account.address]);
    assert.ok(after > before, "refund must succeed and pay out");
    assert.strictEqual(
      (await f.launchpad.read.lockedPaymentAmount([fot.address])) as bigint,
      0n,
      "the payment lock must be fully released after the refund",
    );
  });

  it("P4b: recoverStuckTokens reverts with its declared error, never an unguarded-subtraction panic", async function () {
    const f = await loadFixture(fixture18);
    const fot = await (
      await getConnection()
    ).viem.deployContract("MockFeeOnTransferToken", ["FOT", "FOT", 100n]);
    await f.launchpad.write.setAcceptedPaymentToken([fot.address, true], {
      account: f.owner.account,
    });
    const price = parseUnits("1", 18);
    const ratios = buildRatios({
      launchpadBp: 2000,
      liquidityBp: 8000,
      ownerBp: 0,
      liquidityRecipient: f.platformTreasury.account.address,
    });
    const { tokenAddress } = await issueTokenWithRatios({
      tokenFactory: f.tokenFactory,
      business: f.business,
      publicClient: f.publicClient,
      chainId: f.chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: f.launchpad.address,
      name: "T3",
      symbol: "T3",
      totalSupply: parseUnits("1000000", 18),
      contractURI: "",
      ratios,
    });
    await f.launchpad.write.createLaunchpad(
      [tokenAddress, price, f.business.account.address, fot.address, 0n, 0n],
      { account: f.business.account },
    );
    const raise = parseUnits("1000", 18);
    await fot.write.mint([f.user1.account.address, raise * 10n]);
    await fot.write.approve([f.launchpad.address, raise * 10n], { account: f.user1.account });
    const info0 = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    await time.increaseTo(info0.startTime + 1n);
    await f.launchpad.write.participate([0n, raise], { account: f.user1.account });

    let msg = "";
    try {
      await f.launchpad.write.recoverStuckTokens([fot.address, f.owner.account.address, 1n], {
        account: f.owner.account,
      });
    } catch (e) {
      msg = String(e);
    }
    // Two things are pinned here at once:
    //   1. With the measured-delta credit, `locked` can no longer exceed the real balance via a
    //      fee-on-transfer token, so the whole locked amount is correctly protected — the sweep of
    //      even 1 wei is refused because there is no free balance.
    //   2. The refusal is the declared `TokenLockedInActiveLaunchpad` error. It must NEVER be
    //      `panic code 0x11`: the guard used to compute `balance - lockedAmount` unguarded, which
    //      turned a diagnosable insolvency into an opaque arithmetic panic and made the declared
    //      error unreachable in exactly the case an operator would be investigating.
    assert.ok(!msg.includes("panic code 0x11"), "must not panic on an unguarded subtraction");
    assert.ok(
      msg.includes("TokenLockedInActiveLaunchpad"),
      `expected the declared error, got: ${msg.slice(0, 300)}`,
    );
  });

  // ---------------------------------------------------------------------------
  // P5: TokenFactory 3-bucket allocation conservation at adversarial supply.
  // ---------------------------------------------------------------------------
  it("P5: TokenFactory buckets sum EXACTLY to totalSupply at odd bp/supply", async function () {
    const f = await loadFixture(fixture18);
    const totalSupply = 1_000_000_000_000_000_000_000_003n; // 1e21 + 3
    const ratios = buildRatios({
      launchpadBp: 3333,
      liquidityBp: 3333,
      ownerBp: 3334,
      liquidityRecipient: f.platformTreasury.account.address,
    });
    const { tokenAddress, vestingWallet } = await issueTokenWithRatios({
      tokenFactory: f.tokenFactory,
      business: f.business,
      publicClient: f.publicClient,
      chainId: f.chainId,
      permitPrivateKey: TEST_PRIVATE_KEY,
      linkedLaunchpad: f.launchpad.address,
      name: "T4",
      symbol: "T4",
      totalSupply,
      contractURI: "",
      ratios,
    });
    const { viem } = await getConnection();
    const tok = await viem.getContractAt("ERC20V1", tokenAddress);
    const escrow = (await f.tokenFactory.read.launchpadEscrow([tokenAddress])) as bigint;
    const liq = await tok.read.balanceOf([f.platformTreasury.account.address]);
    const own = await tok.read.balanceOf([vestingWallet]);
    console.log({ totalSupply, escrow, liq, own, sum: escrow + liq + own });
    assert.strictEqual(escrow + liq + own, totalSupply, "bucket sum != totalSupply");
    assert.strictEqual(await tok.read.balanceOf([f.tokenFactory.address]), escrow);
  });

  // ---------------------------------------------------------------------------
  // P6: softcap floor when _targetRaiseAmount() rounds to 0.
  // ---------------------------------------------------------------------------
  it("P6: a sale whose target would round to 0 is rejected at creation", async function () {
    const f = await loadFixture(fixture18);
    const price = parseUnits("1", 12); // MIN_TOKEN_PRICE
    // 1000-wei supply at 9000bp -> saleAmount 900 wei. targetRaise = 900 * 1e12 / 1e18 = 0.
    let msg = "";
    try {
      await makeSale(f, {
        totalSupply: 1000n,
        launchpadBp: 9000,
        ownerBp: 0,
        tokenPrice: price,
      });
    } catch (e) {
      msg = String(e);
    }
    // (FIXED): createLaunchpad now refuses a sale whose softcap target floors to zero.
    // Previously such a sale was creatable, and then `requiredRaise == 0` made
    // `totalRaised >= requiredRaise` vacuously true — the softcap silently stopped existing
    // and the permissionless `cancelUnderfundedLaunchpad` reverted `LaunchpadNotUnderfunded`
    // forever, leaving only expireLaunchpad's 14-day REFUND_GRACE as an exit. Rejecting at creation
    // is the only place this is catchable, since both consumers read the target after the sale has
    // already taken money.
    assert.ok(
      msg.includes("InvalidAmount"),
      `degenerate softcap target must be rejected at creation, got: ${msg.slice(0, 300)}`,
    );
  });

  it("P6b: a sale one notch above the degenerate threshold is still creatable", async function () {
    const f = await loadFixture(fixture18);
    const price = parseUnits("1", 12); // MIN_TOKEN_PRICE
    // Guards the guard: 2_000_000-wei supply at 9000bp -> saleAmount 1_800_000 wei, and
    // targetRaise = 1_800_000 * 1e12 / 1e18 = 1 > 0, so this must NOT be rejected. Without this,
    // an over-broad rejection in createLaunchpad would look like a passing P6.
    const { saleAmount } = await makeSale(f, {
      totalSupply: 2_000_000n,
      launchpadBp: 9000,
      ownerBp: 0,
      tokenPrice: price,
    });
    assert.strictEqual(saleAmount, 1_800_000n);
    const info = (await f.launchpad.read.getLaunchpadInfo([0n])) as any;
    assert.strictEqual(info.saleAmount, 1_800_000n);
  });
});
