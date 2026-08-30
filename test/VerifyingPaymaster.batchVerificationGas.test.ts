/**
 * VerifyingPaymaster — paymasterVerificationGasLimit vs. a MAX_BATCH_SIZE (32) batch.
 *
 * WHY: turned the business gate into a (target, inner selector) PAIR, so
 * `_validatePaymasterUserOp` -> `_extractBusinessOk` now performs, for an N-call `executeBatch`
 * with N DISTINCT targets, 2N cold SLOADs (`businessAllowlist[target]` +
 * `targetSelectorAllowlist[target][selector]`) instead of N. At N = 32 that is 64 cold SLOADs
 * (~134k gas) before any of the paymaster's own fixed costs. Every other paymaster test pins
 * `paymasterVerificationGasLimit` at 100_000, which silently only ever exercised 1-2 element
 * batches — this file is the missing boundary case.
 *
 * WHAT IS PINNED HERE:
 *   1. a 32-call batch over 32 distinct targets is NOT sponsorable at the 100k limit used
 *      everywhere else (the paymaster validation runs out of gas -> EntryPoint AA33/AA36);
 *   2. it IS sponsorable at BATCH32_PM_VERIFICATION_GAS below, which is the figure the frontend /
 *      bundler must supply for max-size batches;
 *   3. the 32-call batch over ONE repeated target (warm SLOADs) is still a small fraction of the
 *      distinct-target requirement — i.e. the requirement is driven by DISTINCT targets, not by
 *      batch length alone. UPDATE (SSA-02 per-op sponsor-signature verification): the FIXED
 *      per-op signing overhead this fix added applies once per `validatePaymasterUserOp` call
 *      regardless of batch content, and is now by itself large enough that even this same-target
 *      case no longer fits under the shared 100k baseline every other paymaster test uses — see
 *      SAME_TARGET_BATCH32_PM_VERIFICATION_GAS below. The DISTINCT-vs-SAME-target gap this file
 *      exists to measure is unchanged.
 *
 * The paymaster contract is NOT modified: this is a client-side gas-budgeting requirement.
 *
 * ITEM 4 ADDITION (T4.11): `selfSelectorAllowlist[selector]` is a ONE-level mapping (1 keccak, 1
 * SLOAD) versus the business path's TWO-level `businessAllowlist[target]` +
 * `targetSelectorAllowlist[target][selector]` (a 2-level mapping: 3 keccaks, 2 SLOADs) — see
 * VerifyingPaymaster.sol's header. The
 * self path therefore saves 1 SLOAD + 2 keccaks PER ELEMENT versus the business path measured
 * above. Two tests below MEASURE (not assume) that a 32-element self-batch and a 16/16 mixed
 * batch both sponsor well under the documented BATCH32_PM_VERIFICATION_GAS (250_000).
 */
import { describe, it } from "node:test";
import assert from "node:assert";
import {
  parseEther,
  parseEventLogs,
  hexToBytes,
  toFunctionSelector,
  encodeFunctionData,
  encodeAbiParameters,
  getAddress,
  pad,
  toHex,
  zeroAddress,
  type Address,
  type Hex,
  type Abi,
} from "viem";
import { loadFixture, getConnection } from "./helpers.js";
import {
  passkeyPubCoords,
  packU128Pair,
  buildExecuteBatchCallData,
  paymasterAndDataFor,
  execWithPaymaster,
  computeMaxCost,
  encodePasskeyOwner,
  SPONSOR_SIGNER,
} from "./aa-helpers.js";

const PASSKEY_PRIV = hexToBytes(
  "0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721" as Hex,
);
const SALT = 8032n;

const BATCH_N = 32; // StarzipWallet.MAX_BATCH_SIZE
const SEL = toFunctionSelector("someBusinessCall()");

// Gas profile. callGasLimit is sized for 32 inner calls + 32 `Executed` logs; the figure under
// test is PM_VAL_GAS.
const VER_GAS = 500_000n;
const CALL_GAS = 2_000_000n;
const PRE_VER_GAS = 50_000n;
const PM_POST_GAS = 100_000n; // > MIN_POSTOP_GAS (90_000)
const MAX_FEE_PER_GAS = 1_000_000_000n; // 1 gwei

/** The limit every other paymaster test uses — proven insufficient for a 32-distinct-target batch. */
const LEGACY_PM_VERIFICATION_GAS = 100_000n;
/**
 * Required `paymasterVerificationGasLimit` for a MAX_BATCH_SIZE batch over DISTINCT targets.
 * MEASURED by the "derives the threshold" test below over the real EntryPoint v0.8 handleOps
 * path. RE-MEASURED for SSA-02 (per-op sponsor-signature verification: 2 keccak256 + a 12-field
 * abi.encode + ecrecover + a cold SLOAD for the sponsor signer, added to every
 * `validatePaymasterUserOp` call): 230_000 fails, 235_000 is the first rung that sponsors — up
 * from the pre-SSA-02 (215_000 fails, 220_000 passes). Set at 270_000 for a ~15% margin (was
 * 250_000 / ~14%). Clients building batches MUST use at least this value; the fixed 100_000
 * every other paymaster test uses is no longer safe even for same-target batches — see
 * `SAME_TARGET_BATCH32_PM_VERIFICATION_GAS` below.
 */
const BATCH32_PM_VERIFICATION_GAS = 270_000n;
/**
 * Required `paymasterVerificationGasLimit` for a 32-call batch over a SINGLE (repeated, warm)
 * target — added for SSA-02. Before SSA-02, this fit comfortably under the shared
 * `LEGACY_PM_VERIFICATION_GAS` (100_000) baseline; the FIXED per-op signature-verification
 * overhead SSA-02 added (see `BATCH32_PM_VERIFICATION_GAS`'s comment) applies once per
 * `validatePaymasterUserOp` call regardless of batch size or target distinctness, and is now by
 * itself large enough to push even this warm/same-target case past 100_000. Bisected floor:
 * 109_000 fails, 110_000 is the first rung that sponsors. Set at 115_000 for headroom — still a
 * small fraction of `BATCH32_PM_VERIFICATION_GAS`, so the DISTINCT-target cost driver this file
 * exists to isolate is unchanged; only the flat floor moved.
 */
const SAME_TARGET_BATCH32_PM_VERIFICATION_GAS = 115_000n;

// n distinct, code-less addresses starting at `base`. A `call` into an account with no code
// always succeeds, so the inner business calls are free no-ops and the measurement isolates the
// paymaster's validation cost. Default base is well above the precompile range (0x01..0x0a).
const distinctAddrs = (n: number, base = 0x1000): Address[] =>
  Array.from({ length: n }, (_, i) => pad(toHex(BigInt(base + i)), { size: 20 }) as Address);
const distinctTargets = (n: number): Address[] => distinctAddrs(n, 0x1000);

const ADD_OWNER_ADDRESS_SEL = toFunctionSelector("addOwnerAddress(address)");

describe("VerifyingPaymaster batch verification gas", function () {
  async function fixture() {
    const { viem } = await getConnection();
    const [deployer, ownerWallet, policyManagerWallet, beneficiary] = await viem.getWalletClients();
    const publicClient = await viem.getPublicClient();

    const entryPoint = await viem.deployContract("TestEntryPoint", []);

    const paymaster = await viem.deployContract("VerifyingPaymaster", [
      entryPoint.address,
      policyManagerWallet.account.address,
      zeroAddress,
      SPONSOR_SIGNER,
    ]);
    await paymaster.write.transferOwnership([ownerWallet.account.address], {
      account: deployer.account,
    });
    await paymaster.write.acceptOwnership({ account: ownerWallet.account });

    const factory = await viem.deployContract("StarzipWalletFactory", [
      entryPoint.address,
      paymaster.address,
    ]);
    const { x, y } = passkeyPubCoords(PASSKEY_PRIV);
    const firstOwner = encodePasskeyOwner(x, y);
    await factory.write.createAccount([[firstOwner], SALT], { account: deployer.account });
    const walletAddr = (await factory.read.getAddress([[firstOwner], SALT])) as Address;
    const wallet = await viem.getContractAt("StarzipWallet", walletAddr);

    const asOwner = { account: ownerWallet.account };
    const asPm = { account: policyManagerWallet.account };

    if ((await wallet.read.trustedPaymaster()) !== getAddress(paymaster.address)) {
      throw new Error(`fixture: wallet ${walletAddr} not born trusting the deployed paymaster`);
    }

    // unpause() now refuses while any of the three per-op caps is unprovisioned (0).
    // Set generously so none of them is the thing this file's gas measurements are isolating —
    // the largest maxCost any test here reaches (BATCH32_PM_VERIFICATION_GAS profile) is on the
    // order of 0.003 ETH, well under the 1 ETH ceiling below.
    await paymaster.write.setMaxSponsoredOpCost([parseEther("1")], asOwner);
    await paymaster.write.setMaxSponsoredFeePerGas([MAX_FEE_PER_GAS], asOwner);
    await paymaster.write.setMaxSponsoredPreVerificationGas([PRE_VER_GAS], asOwner);
    await paymaster.write.unpause(asOwner);
    await paymaster.write.setGlobalDailyCapCeiling([parseEther("100")], asOwner);
    await paymaster.write.setGlobalDailyBudget([parseEther("100")], asOwner);
    await paymaster.write.setSponsored([walletAddr, true], asPm);
    await paymaster.write.setDailyCap([walletAddr, parseEther("10")], asPm);

    // Business gate: allowlist all 32 distinct targets + one shared target, each with SEL.
    const targets = distinctTargets(BATCH_N);
    await paymaster.write.setBusinessTargets([targets, true], asOwner);
    for (const t of targets) {
      await paymaster.write.setTargetSelector([t, SEL, true], asOwner);
    }

    // Item 4 (T4.11): self-selector gate for the all-self / mixed batch gas measurements below.
    await paymaster.write.setSelfSelector([ADD_OWNER_ADDRESS_SEL, true], asOwner);

    await paymaster.write.deposit({ value: parseEther("50"), account: deployer.account });
    await deployer.sendTransaction({ to: walletAddr, value: parseEther("1") });

    return {
      publicClient,
      entryPoint,
      paymaster,
      wallet,
      walletAddr,
      targets,
      deployer,
      beneficiary,
    };
  }

  /** Submit an N-call sponsored executeBatch with an explicit paymasterVerificationGasLimit. */
  async function submitBatch(
    f: Awaited<ReturnType<typeof fixture>>,
    dests: Address[],
    pmValGas: bigint,
  ) {
    const callData = buildExecuteBatchCallData(
      f.wallet.abi,
      dests,
      dests.map(() => 0n),
      dests.map(() => SEL),
    );
    return execWithPaymaster({
      publicClient: f.publicClient,
      entryPoint: f.entryPoint,
      walletAddr: f.walletAddr,
      callData,
      paymasterAndData: paymasterAndDataFor(f.paymaster.address, pmValGas, PM_POST_GAS),
      passkeyPriv: PASSKEY_PRIV,
      submitter: f.deployer,
      beneficiary: f.beneficiary.account.address,
      accountGasLimits: packU128Pair(VER_GAS, CALL_GAS),
      preVerificationGas: PRE_VER_GAS,
      gasFees: packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS),
    });
  }

  /**
   * Submit a sponsored executeBatch with EXPLICIT (dest, func) pairs — unlike {submitBatch},
   * which always calls the fixed no-arg `SEL` on every element. Used by the item-4 self-batch
   * measurements below, whose inner calls are real `addOwnerAddress` writes on the wallet itself,
   * not free no-op calls into codeless targets — hence the larger, overridable `callGas`.
   */
  async function submitCustomBatch(
    f: Awaited<ReturnType<typeof fixture>>,
    dests: Address[],
    funcs: Hex[],
    pmValGas: bigint,
    callGas: bigint = CALL_GAS,
  ) {
    const callData = buildExecuteBatchCallData(
      f.wallet.abi,
      dests,
      dests.map(() => 0n),
      funcs,
    );
    return execWithPaymaster({
      publicClient: f.publicClient,
      entryPoint: f.entryPoint,
      walletAddr: f.walletAddr,
      callData,
      paymasterAndData: paymasterAndDataFor(f.paymaster.address, pmValGas, PM_POST_GAS),
      passkeyPriv: PASSKEY_PRIV,
      submitter: f.deployer,
      beneficiary: f.beneficiary.account.address,
      accountGasLimits: packU128Pair(VER_GAS, callGas),
      preVerificationGas: PRE_VER_GAS,
      gasFees: packU128Pair(MAX_FEE_PER_GAS, MAX_FEE_PER_GAS),
    });
  }

  const sponsored = (f: Awaited<ReturnType<typeof fixture>>, receipt: { logs: unknown[] }) =>
    parseEventLogs({
      abi: f.paymaster.abi,
      logs: receipt.logs as never,
      eventName: "GasSponsored",
    }).length === 1;

  it("32 distinct targets: the 100k paymasterVerificationGasLimit used elsewhere is NOT enough", async function () {
    const f = await loadFixture(fixture);
    // maxCost stays inside dailyCap/budget at this profile, so a failure here can only be gas.
    assert.ok(
      computeMaxCost({
        verificationGasLimit: VER_GAS,
        callGasLimit: CALL_GAS,
        paymasterVerificationGasLimit: LEGACY_PM_VERIFICATION_GAS,
        paymasterPostOpGasLimit: PM_POST_GAS,
        preVerificationGas: PRE_VER_GAS,
        maxFeePerGas: MAX_FEE_PER_GAS,
      }) < parseEther("10"),
      "maxCost must stay under dailyCap so the only failure mode is gas",
    );
    await assert.rejects(
      submitBatch(f, f.targets, LEGACY_PM_VERIFICATION_GAS),
      /AA3[36]|out of gas|reverted/i,
    );
  });

  it("32 distinct targets: sponsored at the documented BATCH32_PM_VERIFICATION_GAS", async function () {
    const f = await loadFixture(fixture);
    const receipt = await submitBatch(f, f.targets, BATCH32_PM_VERIFICATION_GAS);
    assert.strictEqual(receipt.status, "success");
    assert.ok(sponsored(f, receipt), "GasSponsored must be emitted");
  });

  it("32 calls to ONE target still fits in a small fraction of the DISTINCT-target requirement — the cost driver is DISTINCT targets, not batch length (SSA-02 moved the flat floor past 100k for every batch, see SAME_TARGET_BATCH32_PM_VERIFICATION_GAS)", async function () {
    // Pre-SSA-02 this fit inside LEGACY_PM_VERIFICATION_GAS (100_000) — see
    // SAME_TARGET_BATCH32_PM_VERIFICATION_GAS's comment for the bisected floor (109_000 fails,
    // 110_000 passes) and why the fixed per-op signing overhead pushed it past 100_000 for every
    // batch, not just distinct-target ones. The finding this test exists to pin — SAME target
    // stays dramatically cheaper than DISTINCT targets — is unchanged.
    const f = await loadFixture(fixture);
    const same = Array.from({ length: BATCH_N }, () => f.targets[0]);
    const receipt = await submitBatch(f, same, SAME_TARGET_BATCH32_PM_VERIFICATION_GAS);
    assert.strictEqual(receipt.status, "success");
    assert.ok(sponsored(f, receipt), "GasSponsored must be emitted");
    assert.ok(
      SAME_TARGET_BATCH32_PM_VERIFICATION_GAS < BATCH32_PM_VERIFICATION_GAS,
      "the SAME-target floor must stay strictly below the DISTINCT-target requirement — that gap IS the finding",
    );
  });

  it("derives the threshold: the minimum viable limit sits between 100k and BATCH32_PM_VERIFICATION_GAS", async function () {
    // Coarse ladder rather than a binary search, so the evidence reads as a table.
    // RE-MEASURED for SSA-02 (per-op signature verification, see BATCH32_PM_VERIFICATION_GAS's
    // comment): 215k/220k/225k/230k all fail, 235k is the first rung that sponsors — up from the
    // pre-SSA-02 200k/205k/210k/215k fail, 220k passes.
    const ladder = [100_000n, 150_000n, 200_000n, 230_000n, 235_000n, 270_000n];
    const outcomes: Array<[bigint, boolean]> = [];
    for (const limit of ladder) {
      const g = await loadFixture(fixture);
      let ok = false;
      try {
        const r = await submitBatch(g, g.targets, limit);
        ok = r.status === "success" && sponsored(g, r);
      } catch {
        ok = false;
      }
      outcomes.push([limit, ok]);
    }
    const rendered = outcomes.map((o) => `${o[0]}:${o[1]}`).join(" ");
    const firstOk = outcomes.find(([, ok]) => ok);
    assert.ok(firstOk, `no ladder rung sponsored the batch: ${rendered}`);
    assert.ok(
      firstOk[0] > LEGACY_PM_VERIFICATION_GAS,
      `100k must NOT be sufficient — that is the finding (${rendered})`,
    );
    // Band assertion, not an exact equality: a solc/EntryPoint bump may move the rung a little,
    // but it must not silently drift past the constant clients are told to use.
    assert.ok(
      firstOk[0] > 230_000n && firstOk[0] <= BATCH32_PM_VERIFICATION_GAS,
      `threshold ${firstOk[0]} left the documented (230k, ${BATCH32_PM_VERIFICATION_GAS}] band (${rendered})`,
    );
    // Monotonic: once a limit works, every larger limit must work too.
    for (let i = outcomes.indexOf(firstOk); i < outcomes.length; i++) {
      assert.ok(outcomes[i][1], `limit ${outcomes[i][0]} regressed after ${firstOk[0]} passed`);
    }
  });

  // ============ Item 4 (T4.11): self path vs. business path, measured ============
  // MEASURED on this tree (same coarse-ladder method as "derives the threshold"
  // above; CALL_GAS_SELF sized for 32 REAL `addOwnerAddress` state-writing calls — cold
  // `ownerAtIndex`/`isOwnerBytes` SSTOREs — not the free no-op business calls the rest of this
  // file uses, so it does not itself constrain the finding, which is about
  // `paymasterVerificationGasLimit`):
  //   ALL-SELF (32x addOwnerAddress, 32 distinct owner arguments — a REPEATED argument reverts
  //     `AlreadyOwner` on the second occurrence): pre-SSA-02, 88_000 failed and 90_000 was the
  //     first rung that sponsored — INSIDE `LEGACY_PM_VERIFICATION_GAS` (100_000), so an all-self
  //     admin batch needed no client-side gas bump at all.
  //   MIXED (16x self `addOwnerAddress` + 16x business `SEL`): pre-SSA-02, 155_000 failed and
  //     160_000 was the first rung that sponsored — between the two pure cases, as expected.
  //   RE-MEASURED for SSA-02 (per-op signature verification, see
  //   `BATCH32_PM_VERIFICATION_GAS`'s comment — the FIXED per-op overhead applies here too, on
  //   top of the self/mixed-path SLOAD savings below, which are unchanged):
  //     ALL-SELF: 100_000 fails, 100_500 is the first rung that sponsors — the fixed overhead
  //       alone (~10.5k) is now enough to push this PAST the shared `LEGACY_PM_VERIFICATION_GAS`
  //       baseline too, so an all-self admin batch now DOES need a small client-side bump.
  //     MIXED: 168_000 fails, 169_000 is the first rung that sponsors.
  // Both confirm §0 of the plan: the self path is `selfSelectorAllowlist[sel]` (1 keccak, 1
  // SLOAD) versus the business path's `businessAllowlist[target]` +
  // `targetSelectorAllowlist[target][sel]` (3 keccaks, 2 SLOADs) — strictly cheaper per element.
  // `BATCH32_PM_VERIFICATION_GAS` does NOT need to move for item 4: these figures are LOWER than
  // the all-business case, never higher.
  const CALL_GAS_SELF = 2_500_000n; // sized for 32 real addOwnerAddress state writes
  const SELF_BATCH32_PM_VERIFICATION_GAS = 115_000n; // measured floor (100_000 fails, 100_500 passes); was 100_000 (== LEGACY), pre-SSA-02 floor 90_000
  const MIXED_BATCH32_PM_VERIFICATION_GAS = 170_000n; // measured floor (168_000 fails, 169_000 passes); was 160_000 (155_000 fails, pre-SSA-02)

  function selfCallData(walletAbi: Abi, newOwner: Address): Hex {
    return encodeFunctionData({
      abi: walletAbi,
      functionName: "addOwnerAddress",
      args: [newOwner],
    });
  }

  it("32-element ALL-SELF batch: sponsors AND executes (all 32 owners actually added) at SELF_BATCH32_PM_VERIFICATION_GAS", async function () {
    const f = await loadFixture(fixture);
    const newOwners = distinctAddrs(BATCH_N, 0x9000);
    const dests = Array.from({ length: BATCH_N }, () => f.walletAddr);
    const funcs = newOwners.map((o) => selfCallData(f.wallet.abi, o));

    const receipt = await submitCustomBatch(
      f,
      dests,
      funcs,
      SELF_BATCH32_PM_VERIFICATION_GAS,
      CALL_GAS_SELF,
    );
    assert.strictEqual(receipt.status, "success");
    assert.ok(sponsored(f, receipt), "GasSponsored must be emitted");
    for (const o of newOwners) {
      assert.strictEqual(
        await f.wallet.read.isOwnerBytes([encodeAbiParameters([{ type: "address" }], [o])]),
        true,
        `owner ${o} must have actually been added, not just sponsored`,
      );
    }
  });

  it("16-self/16-business MIXED batch: sponsors AND executes at MIXED_BATCH32_PM_VERIFICATION_GAS", async function () {
    const f = await loadFixture(fixture);
    const newOwners = distinctAddrs(16, 0x9000);
    const dests = [...Array.from({ length: 16 }, () => f.walletAddr), ...f.targets.slice(0, 16)];
    const funcs = [
      ...newOwners.map((o) => selfCallData(f.wallet.abi, o)),
      ...Array.from({ length: 16 }, () => SEL),
    ];

    const receipt = await submitCustomBatch(
      f,
      dests,
      funcs,
      MIXED_BATCH32_PM_VERIFICATION_GAS,
      CALL_GAS_SELF,
    );
    assert.strictEqual(receipt.status, "success");
    assert.ok(sponsored(f, receipt), "GasSponsored must be emitted");
    for (const o of newOwners) {
      assert.strictEqual(
        await f.wallet.read.isOwnerBytes([encodeAbiParameters([{ type: "address" }], [o])]),
        true,
      );
    }
  });

  it("derives the ALL-SELF threshold: sits at (100k, 115k], strictly below the business-path threshold (SSA-02 moved this band up from the pre-fix (85k, 100k])", async function () {
    const newOwners = distinctAddrs(BATCH_N, 0x9000);
    // RE-MEASURED for SSA-02 (per-op signature verification, see BATCH32_PM_VERIFICATION_GAS's
    // comment): 100_000 fails, 100_500 is the first rung that sponsors — pre-SSA-02 this was
    // 88_000 fails, 90_000 passes.
    const ladder = [
      85_000n,
      90_000n,
      95_000n,
      100_000n,
      100_500n,
      101_000n,
      SELF_BATCH32_PM_VERIFICATION_GAS,
    ];
    const outcomes: Array<[bigint, boolean]> = [];
    for (const limit of ladder) {
      const g = await loadFixture(fixture);
      const dests = Array.from({ length: BATCH_N }, () => g.walletAddr);
      const funcs = newOwners.map((o) => selfCallData(g.wallet.abi, o));
      let ok = false;
      try {
        const r = await submitCustomBatch(g, dests, funcs, limit, CALL_GAS_SELF);
        ok = r.status === "success" && sponsored(g, r);
      } catch {
        ok = false;
      }
      outcomes.push([limit, ok]);
    }
    const rendered = outcomes.map((o) => `${o[0]}:${o[1]}`).join(" ");
    const firstOk = outcomes.find(([, ok]) => ok);
    assert.ok(firstOk, `no ladder rung sponsored the all-self batch: ${rendered}`);
    assert.ok(
      firstOk[0] > 100_000n && firstOk[0] <= SELF_BATCH32_PM_VERIFICATION_GAS,
      `self-path threshold ${firstOk[0]} left the measured (100k, ${SELF_BATCH32_PM_VERIFICATION_GAS}] band (${rendered})`,
    );
    for (let i = outcomes.indexOf(firstOk); i < outcomes.length; i++) {
      assert.ok(outcomes[i][1], `limit ${outcomes[i][0]} regressed after ${firstOk[0]} passed`);
    }
  });

  it("derives the MIXED threshold: sits between the pure self and pure business thresholds", async function () {
    const newOwners = distinctAddrs(16, 0x9000);
    // RE-MEASURED for SSA-02 (per-op signature verification, see BATCH32_PM_VERIFICATION_GAS's
    // comment): 168_000 fails, 169_000 is the first rung that sponsors — pre-SSA-02 this was
    // 155_000 fails, 160_000 passes.
    const ladder = [
      130_000n,
      145_000n,
      150_000n,
      155_000n,
      165_000n,
      168_000n,
      169_000n,
      MIXED_BATCH32_PM_VERIFICATION_GAS,
    ];
    const outcomes: Array<[bigint, boolean]> = [];
    for (const limit of ladder) {
      const g = await loadFixture(fixture);
      const dests = [...Array.from({ length: 16 }, () => g.walletAddr), ...g.targets.slice(0, 16)];
      const funcs = [
        ...newOwners.map((o) => selfCallData(g.wallet.abi, o)),
        ...Array.from({ length: 16 }, () => SEL),
      ];
      let ok = false;
      try {
        const r = await submitCustomBatch(g, dests, funcs, limit, CALL_GAS_SELF);
        ok = r.status === "success" && sponsored(g, r);
      } catch {
        ok = false;
      }
      outcomes.push([limit, ok]);
    }
    const rendered = outcomes.map((o) => `${o[0]}:${o[1]}`).join(" ");
    const firstOk = outcomes.find(([, ok]) => ok);
    assert.ok(firstOk, `no ladder rung sponsored the mixed batch: ${rendered}`);
    assert.ok(
      firstOk[0] > 165_000n && firstOk[0] <= BATCH32_PM_VERIFICATION_GAS,
      `mixed threshold ${firstOk[0]} left the measured (165k, ${BATCH32_PM_VERIFICATION_GAS}] band (${rendered})`,
    );
    for (let i = outcomes.indexOf(firstOk); i < outcomes.length; i++) {
      assert.ok(outcomes[i][1], `limit ${outcomes[i][0]} regressed after ${firstOk[0]} passed`);
    }
  });
});
