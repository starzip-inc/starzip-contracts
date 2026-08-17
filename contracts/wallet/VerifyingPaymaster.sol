// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { IEntryPoint } from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { IPaymaster } from "@account-abstraction/contracts/interfaces/IPaymaster.sol";
import { BasePaymaster } from "@account-abstraction/contracts/core/BasePaymaster.sol";
import { PackedUserOperation } from "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { UserOperationLib } from "@account-abstraction/contracts/core/UserOperationLib.sol";
import { _packValidationData } from "@account-abstraction/contracts/core/Helpers.sol";
import { StarzipWallet } from "./StarzipWallet.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { IPaymasterSelectorPolicy } from "../interfaces/IPaymasterSelectorPolicy.sol";

/**
 * @title VerifyingPaymaster
 * @notice Policy-storage gas sponsorship paymaster: each wallet's sponsorship policy lives in
 *         this contract's OWN storage keyed by `userOp.sender`. No per-userOp backend signature
 *         and no external registry read during validation (strict ERC-7562 public-bundler safe
 *         WHILE STAKED — see the `unlockStake()` note below; `unlockStake()` voids that standing silently).
 * @dev Despite the name (kept deliberately — renaming would churn the deployments key, the
 *      S3-published ABI filename, and every test import for zero security gain; recorded as an
 *      accepted, closed decision), this
 *      contract verifies NO signature, unlike the canonical ERC-4337 `VerifyingPaymaster`
 *      sample it shares a name with. Self-disclosed in the header's "NO GLOBAL LATCH" note below
 *      ("despite the name, {_validatePaymasterUserOp} verifies NO signature") — this line exists
 *      so a reader does not have to reach that paragraph to learn it.
 * @dev Inherits BasePaymaster (Ownable2Step). Non-proxy, non-upgradeable — `entryPoint` is
 *      immutable; migration = fresh deploy at a new address. Storage slot table (subclass
 *      storage starts at slot 2; slots 0-1 are Ownable/Ownable2Step):
 *        slot 2: policyManager (address, 20B) | paused (bool, 1B)          — packed
 *        slot 3: globalDailyCapCeiling (uint128) | globalDailyBudget (uint128)
 *        slot 4: globalSpentToday (uint128) | globalLastSpentDay (uint32)
 *        slot 5: walletPolicy mapping base   (entry at keccak256(sender, 5))
 *        slot 6: businessAllowlist mapping base (entry at keccak256(target, 6))
 *        slot 7: maxSponsoredOpCost (uint128)
 *        slot 8: targetSelectorAllowlist mapping base
 *                (entry at keccak256(selector, keccak256(target, 8)))
 *        slot 9: maxSponsoredFeePerGas (uint128) | maxSponsoredPreVerificationGas (uint128)
 *        slot 10: selfSelectorAllowlist mapping base (entry at keccak256(selector, 10))
 *
 *      ERC-7562: `_validatePaymasterUserOp` NEVER reads `block.timestamp`/`block.number` and
 *      NEVER writes storage — all it does is a RAW check against stored day-indexed counters,
 *      deferring genuinely time-dependent decisions to the EntryPoint via `validAfter`. All day
 *      rollover + accrual happens in `_postOp` (execution phase, where the clock is allowed).
 *
 *      SECURITY — budget/cap are SOFT breakers, the deposit is the HARD cap:
 *      `globalDailyBudget` and every wallet's `dailyCap` are evaluated in `_validatePaymasterUserOp`
 *      against storage as it stood at the START of the bundle — ERC-7562 forbids writing storage
 *      during validation, so these counters cannot be checked atomically per-op within a single
 *      `handleOps` bundle. A single permissionless bundle can therefore push total sponsorship for
 *      that block past `globalDailyBudget` (bounded only by how many sponsorable ops a bundler
 *      chooses to include). These are best-effort spend breakers, NOT an EVM-enforced ceiling.
 *      The ONLY EVM-enforced hard cap on this paymaster's total loss is its EntryPoint **deposit**
 *      (`BasePaymaster.getDeposit`/`deposit`/`withdrawTo`) — once exhausted, the EntryPoint itself
 *      reverts sponsorship, no matter what the soft breakers say.
 *
 *      AUDIT C-B — the bundle-aggregation auto-unsponsor latch: THE LATCH BOUNDS REPETITION,
 *      NOT SIZE. Left as-is, the gap above compounds daily — `dailyCap` resets every UTC day, so a
 *      wallet whose owner (or a compromised session key on it) repeats "one over-cap bundle" once
 *      per day drains the deposit on a schedule, not just once. `_postOp` cannot prevent that
 *      single over-cap bundle from fully executing (by the time it runs for op i, ops i+1..N in
 *      the SAME bundle already cleared validation — see {_postOp}'s own NatSpec). What it DOES do:
 *      once a wallet's cumulative `spentToday` crosses `min(dailyCap, globalDailyCapCeiling)` —
 *      checked in the EXECUTION phase, where ERC-7562's storage-write ban does not apply — that
 *      wallet is auto-unsponsored (emits {SponsorshipRevoked}) and stays that way until
 *      `policyManager` explicitly calls {setSponsored} again. Pinned by
 *      test/VerifyingPaymaster.spendcap.test.ts, describe "bundle-aggregation auto-unsponsor
 *      latch" (the whole block, incl. the day-rollover and cap-raise negative controls).
 *
 *      SINGLE-BUNDLE WORST-CASE LOSS. The actual bound is per-BUNDLE (i.e. per-transaction),
 *      and the latch does not enter into it at all:
 *
 *          N_max           = floor(deposit / per-op prefund P)
 *          worst-case loss = N_max * per-op ACTUAL charge A     (<= deposit)
 *                           ~ deposit * (A / P)
 *
 *      THE MAXIMAND IS THE RATIO A/P, NOT N_max ALONE. Round 3 of this block argued an attacker
 *      LOWERS P so more ops fit the deposit, i.e. that P doesn't matter beyond N. That is backwards.
 *      Unspent prefund is REFUNDED to the paymaster, not lost (`refund = prefund - actualGasCost;
 *      _incrementDeposit(refundAddress, refund)`, EntryPoint.sol:879-880) — a cheap op that fits more
 *      copies into the deposit also refunds more per copy. `MIN_POSTOP_GAS` forces every op to
 *      declare >= 90,000 `paymasterPostOpGasLimit` while real `_postOp` execution costs at most
 *      ~61,441 gas (see that constant's own derivation above) — roughly 28,559 gas of IRREDUCIBLE
 *      WASTE W is pinned into every op regardless of P, so the ratio is approximately `1 - W/P`,
 *      INCREASING as P grows, not decreasing. Shrinking P to raise N_max shrinks the ratio at the
 *      same time; the two effects partly cancel, and — per the search below — the cancellation does
 *      NOT favor the cheap-op strategy.
 *
 *      THE BURN MECHANISM: `callGasLimit` is the field an attacker can turn into near-100%-ratio
 *      spend on demand, by pointing the sponsored call at a target that consumes every unit of gas
 *      forwarded to it (e.g. a contract whose entire runtime is an unconditional jump-to-self loop).
 *      `EntryPoint.innerHandleOp`'s `Exec.call(mUserOp.sender, 0, callData, callGasLimit)`
 *      (account-abstraction/contracts/core/EntryPoint.sol:403) forwards up to `callGasLimit`; if that
 *      call runs out of gas, `success = false`, `mode = opReverted` (:404-417) — but this does NOT
 *      abort the bundle or skip billing: `_postExecution` still runs (:421-422) and still invokes
 *      this contract's `postOp` and bills `actualGasCost` (`IPaymaster.postOp` runs for BOTH
 *      `opSucceeded` and `opReverted` by design — see {_postOp}'s own NatSpec). The attacker does not
 *      need the sponsored call to succeed, only to be ADMITTED, and this holds for ANY `callGasLimit`
 *      the attacker declares, not just a token minimum — round 3 found the "op need not succeed"
 *      property at `callGasLimit = 1` and missed that it holds, and is strictly MORE useful to the
 *      attacker, at arbitrarily large `callGasLimit` too.
 *
 *      THE OTHER FOUR FIELDS' FLOORS (bisected against a fresh wallet — i.e. nonce 0 — at every
 *      probe; see the note below on why a REUSED wallet under-measures these):
 *        - `verificationGasLimit` floor = 55,505 gas — the cost of StarzipWallet's P-256/WebAuthn
 *          `validateUserOp` PLUS EntryPoint's own per-op overhead (`_validatePrepayment` measures
 *          elapsed gas from before `_copyUserOpToMemory` through the nonce update, EntryPoint.sol:
 *          755-793 — NOT just the isolated account call), under the DEFAULT hardfork this harness
 *          resolves to (`osaka`, confirmed via `hre.network.connect()`'s own `networkConfig.hardfork`
 *          with no override), which DOES carry the EIP-7951 `P256VERIFY` precompile — the opposite of
 *          what an earlier version of this block claimed ("no RIP-7212 precompile available").
 *          Re-measured directly (standalone bisection: fresh StarzipWallet
 *          per probe, no paymaster involved, `hardfork: "cancun"`, `blockGasLimit` 200,000,000 —
 *          isolates the account+EntryPoint cost the same way the 55,505 figure above does) — the
 *          floor is 443,609 gas, 7.995x higher than the precompile-present number. An earlier
 *          version of this block claimed 394,059 (refuted: did not reproduce); a separate
 *          verification pass reported ~410,581 via a different procedure — neither figure is
 *          carried forward here. opBNB's own hardfork support determines which of these applies
 *          there; this harness's default is the precompile-present, cheaper number.
 *        - `paymasterVerificationGasLimit` floor = 26,835 gas in isolation (generous other fields),
 *          but 26,894 gas once composed with the REST of the REAL deploy-aa.ts config (the
 *          `maxSponsoredOpCost`/`maxSponsoredPreVerificationGas` checks this contract runs before the
 *          policy lookup add a small but real amount of gas over the unbounded-config measurement —
 *          isolated per-field floors are a LOWER bound on the real, fully-configured floor, not an
 *          exact one).
 *        - `callGasLimit` floor = 0 gas, not 1: at `callGasLimit = 0` the forwarded call still gets
 *          admitted (`Exec.call` with a 0 gas stipend still returns `success = false` cleanly, taking
 *          the same `opReverted` path above) — 1 was never actually the floor, just an unsearched
 *          assumption.
 *        - `paymasterPostOpGasLimit` floor = 90,000 = `MIN_POSTOP_GAS`, exactly — not a search
 *          result, `_validatePaymasterUserOp` hard-declines any op declaring less.
 *        - `preVerificationGas` has no on-chain floor (0 admits) and is bounded ABOVE only by
 *          deploy-aa.ts's `maxSponsoredPreVerificationGas` config (60,000) — a policy ceiling, not a
 *          gas-cost one.
 *      A NAIVELY-SUMMED PROFILE AT ALL FIVE FLOORS (55,505 + 0 + 26,894 + 90,000 + 60,000 = 232,399)
 *      DOES admit as a single, isolated op — round 2's specific claim that this combination reverts
 *      and needs 233,463 did NOT reproduce here. What IS real: inside a LARGE bundle, the FIRST op
 *      needs MORE `verificationGasLimit` than the same op tested alone — measured directly
 *      (bisection against the actual 180-op BURN bundle used below, reusing that scaffolding):
 *      the floor at N=180 is 55,952 gas, only 447 gas above the isolated 55,505 floor
 *      — NOT "several thousand" as an earlier version of this block claimed. `60,000` (used below)
 *      is therefore a comfortable margin over the measured floor, not a tightly-fitted value —
 *      `handleOps` allocates one `UserOpInfo` per op up front (EntryPoint.sol:65-66), and the
 *      resulting larger memory footprint raises the marginal memory-expansion cost paid by op #0's
 *      own validation call by that small amount. This is a BUNDLE-SIZE effect, not a "fields don't
 *      individually compose" effect — later ops in the SAME bundle are cheaper than op #0 (their
 *      nonce slot is already warm), never more expensive.
 *
 *      THE TX GAS CAP (EIP-7825): the default hardfork this harness resolves to enforces a
 *      2^24 = 16,777,216 gas cap on any SINGLE transaction (confirmed directly: requesting more from
 *      `handleOps` is rejected by the node itself, "Transaction gas limit is ... exceeds transaction
 *      gas cap of 16777216", independent of anything this contract does) — this is the real reason
 *      `BUNDLE_TX_GAS = 16,700,000` exists in the test file below. An EARLIER version of this block
 *      claimed `N_max` is "bounded by the DEPOSIT, not by the block gas limit", UNQUALIFIED — that is
 *      false whenever the tx cap binds first, which it does for large-`callGasLimit` burn profiles:
 *      at `callGasLimit` pinned so per-op prefund sits exactly at `maxSponsoredOpCost` (700,000
 *      gas-equivalent), the deposit alone would admit 71 ops, but only 32 fit in ONE transaction
 *      before AA95 "out of gas" aborts the bundle — the tx cap binds FIRST at that profile. This is a
 *      Hardhat/EDR default-hardfork property — and, critically (see MEASURED WORST CASE FOUND below),
 *      opBNB does NOT enforce it: EIP-7825 is osaka-specific, and opBNB has not adopted osaka. Verified
 *      two ways in this harness: `gas = 25,000,000` is REJECTED under the default `osaka` connection
 *      ("exceeds transaction gas cap of 16777216"), while the SAME `gas = 20,000,000` PASSES under
 *      `hardfork: "cancun"` (no such cap exists there). Do not read the deposit as the sole ceiling
 *      unconditionally IN THIS HARNESS's default (osaka) connection — but on opBNB, where the cap is
 *      absent, the deposit genuinely is the only per-bundle ceiling, and every figure below must be
 *      read with that regime difference in mind.
 *
 *      MEASURED WORST CASE FOUND — UNDER THIS HARNESS'S OSAKA DEFAULT, WHICH ENFORCES EIP-7825
 *      (own search — do not carry these numbers forward without re-deriving;
 *      and see WITHOUT THE TX GAS CAP below for the opBNB-relevant regime, where
 *      the shape of this whole analysis flips). EVERY PERCENTAGE FIGURE IN THIS PARAGRAPH IS UNDER
 *      THE TX-GAS-CAPPED HARNESS REGIME — none of them is the number to size an opBNB deposit from.
 *      Pinning `callGasLimit` so P sits AT the `maxSponsoredOpCost` ceiling is NOT the drain-
 *      maximizing move for a SINGLE bundle: it wastes the tx gas cap on very few, very large ops
 *      (that profile only fits 32 ops/bundle, 177.9% of `globalDailyBudget` — see the test for the
 *      exact figure). A 7-point coarse sweep of
 *      `callGasLimit` (0 / 5,000 / 20,000 / 50,000 / 100,000 / 200,000 / 463,106-at-the-cap), each
 *      point an ACTUAL bundle submitted to a real TestEntryPoint + StarzipWallet + a burner target,
 *      found a NON-MONOTONIC single-bundle-drain curve peaking well below the per-op cap; a second,
 *      narrower sweep (30,000-80,000) then a third (33,000-42,000) narrowed the peak to a plateau
 *      around `callGasLimit` ~ 40,000-41,000. THIS WAS NOT PROVEN TO BE THE GLOBAL OPTIMUM — only
 *      this one sweep, at verGas/pmValGas/pmPostGas/preVerGas pinned to their floors above, was
 *      searched; a different combination of those four could still do worse. Confirming that: a
 *      later, narrower probe found
 *      `verGas = 56,000` / `callGas = 38,000` gives N=184 -> 260.74% of budget (52.15% of deposit),
 *      marginally worse for the paymaster than the 40,000 profile below — still consistent with
 *      "not proven global optimum" above, not a reason to restate the search. The profile used below
 *      (`callGasLimit = 40,000`, a round number inside the measured plateau): per-op prefund =
 *      60,000 (verGas, bundle-padded) + 40,000 (callGas) + 26,894 (pmValGas) + 90,000 (pmPostGas) +
 *      60,000 (preVerGas) = 276,894 gas x 1 gwei = 0.000276894 BNB — only 39.6% of
 *      `maxSponsoredOpCost` (700,000 gas-equivalent), i.e. UNDER THIS TX-GAS-CAPPED HARNESS REGIME
 *      SPECIFICALLY, the per-op cap does NOT bind at the local worst case found here. That is NOT
 *      true once the tx gas cap is removed (opBNB) — see WITHOUT THE TX GAS CAP below, where the
 *      per-op cap DOES bind, exactly, at the boundary. N_max = floor(0.05 / 0.000276894) = 180 ops,
 *      which ALSO fits inside the 16,700,000 tx gas cap (measured `gasUsed` = 16,518,496) — deposit
 *      and tx-gas-cap are nearly co-binding at this point, consistent with it being close to a joint
 *      optimum. Measured: a single op's actual charge is 235,971 of 276,894 declared gas (ratio
 *      0.852); the full 180-op bundle drains 0.025858053 BNB = 51.72% OF THE DEPOSIT = 258.58% OF
 *      `globalDailyBudget` — BOTH FIGURES ARE HARNESS-REGIME NUMBERS, SEE BELOW FOR THE OPBNB ONES;
 *      `spentToday` ends at 23.06x `dailyCap`. Op #181 aborts the bundle with AA31. FOR COMPARISON,
 *      AT THE SAME verGas/pmValGas/pmPostGas/preVerGas but `callGasLimit = 0` (the "minimize P, only
 *      maximize N" strategy an earlier version of this block argued for) — N = 211, drain = 220.79%
 *      of budget: WORSE for the attacker than the burn profile above by ~38 points of budget, at
 *      matched methodology. That comparison, not either endpoint alone, is the evidence that the
 *      corrected objective function actually changes the answer, UNDER THIS HARNESS REGIME.
 *
 *      WITHOUT THE TX GAS CAP — THE OPBNB-RELEVANT REGIME. Everything above is shaped by EIP-7825
 *      wasting the tx cap on a bounded bundle size; opBNB does not enforce it (see THE TX GAS CAP
 *      above), and removing it changes which strategy wins. `MIN_POSTOP_GAS`'s waste W (~133,000-
 *      144,000 gas, nearly independent of P) means `drain = floor(deposit / P) x (P - W)`, which is
 *      MONOTONICALLY INCREASING in P — so, absent the tx cap, the drain-maximizing move is to push P
 *      to its own ceiling, `P = maxSponsoredOpCost` (700,000 gas-equivalent), not to the 40,000-plateau
 *      profile above. Round 1's `N_max = floor(deposit / maxSponsoredOpCost)`, discarded by round 3 as
 *      "wrong", was right for THIS regime all along — the per-op cap binds exactly, at the boundary.
 *      Constructed and run (method: a real
 *      bundle under `hardfork: "cancun"`, `blockGasLimit` 200,000,000, `P = 700,000`, `N = 71` — not
 *      extrapolated) at the real deploy-aa.ts deposit:
 *        - single wallet, 71 ops: 79.45% of the deposit / 397.25% of `globalDailyBudget` (tx
 *          `gasUsed` = 36,061,516).
 *        - 71 DISTINCT wallets, 1 op each: 87.12% of the deposit / 435.61% of `globalDailyBudget` (tx
 *          `gasUsed` = 40,056,013).
 *      An independent extrapolation from this harness's own osaka marginal costs agreed with the
 *      constructed figures within 1%, and reproduces the 86.66%/433.29% an earlier pass measured and
 *      that this block's earlier, capped-regime-only framing implicitly dismissed by never stating a
 *      regime at all. AN OPERATOR SIZING THE ENTRYPOINT DEPOSIT FOR OPBNB MUST USE THE ~87%-OF-DEPOSIT
 *      FIGURE ABOVE, NOT THE 51.72% HARNESS-CAPPED FIGURE a few paragraphs up — the 1.68x gap between
 *      them is exactly what this correction exists to close.
 *
 *      CROSS-WALLET, SAME SECTION — SPREADING THE SAME N OPS ACROSS DISTINCT WALLETS instead of
 *      reusing one (each wallet still individually within its OWN `dailyCap` — see the separate
 *      "gap ACROSS DIFFERENT wallets" note below for the multi-wallet-vs-budget angle) is base-
 *      dependent as a PERCENTAGE and therefore not the right way to frame it; the invariant
 *      is ABSOLUTE: +~55,000 gas per op
 *      (a cold `walletPolicy` SSTORE plus a cold nonce slot for each never-before-used sender), which
 *      is +9.9% on the cap-pinned (P = maxSponsoredOpCost) profile above and +38.3% on the 40,000-
 *      plateau burn profile — cross-checked against a 40-wallet/151-op bundle, where the measured
 *      premium (+14,292 gas/op) tracked the (40/151) x 55,000 gas/op prediction. UNDER THE TX GAS CAP
 *      SPECIFICALLY, cross-wallet is a net LOSS for the attacker, not a gain: it buys +55,000 drain/op
 *      at a cost of +57,000 tx gas/op (a 0.96 return), against a 1.565 return for simply extending the
 *      SAME wallet with more ops — which is exactly why the capped and uncapped regimes rank the
 *      cross-wallet strategy differently, and why regime-labeling (this finding) matters beyond just
 *      the headline percentages.
 *
 *      HOW THESE FIGURES WERE DERIVED, AND THE TWO EASY MISTAKES. Every figure in this block is
 *      measured directly against a real TestEntryPoint + StarzipWallet + a raw-bytecode burner
 *      contract; none is carried forward from an earlier estimate, and none should be carried
 *      forward from here without re-deriving it. Two things are easy to get wrong, and both were
 *      got wrong before being corrected: (1) `N_max = floor(deposit / maxSponsoredOpCost)` holds
 *      only in the NO-TX-CAP (opBNB) regime, so every figure must be regime-labeled or it means
 *      nothing; (2) MINIMIZING P does NOT maximize the drain — the burn mechanism above is what
 *      sets the optimization direction, and an argument about strategy needs the same measurement
 *      discipline as a raw number. Pinned by
 *      test/VerifyingPaymaster.spendcap.test.ts, describe "single-bundle worst-case loss at the
 *      real deploy constants": the tests assert LOWER bounds on the quantities that make the
 *      finding true (N_max, drain-vs-budget, drain-vs-deposit, spentToday-vs-cap) WITH margin below
 *      the measured numbers. THIS CATCHES A REGRESSION THAT MAKES THE TRUE WORST CASE SMALLER than
 *      what is pinned — the actual value would then fall below the margined floor and the assertion
 *      fails. IT DOES NOT, ON ITS OWN, CATCH THE OPPOSITE DIRECTION: a one-sided lower-bound assertion
 *      never fails when the true value GROWS, so these four assertions alone would pass silently even
 *      if a regression made the worst case WORSE (bigger N, bigger drain). Confirmed by mutation
 *      testing: under BOTH the M-h and M-i mutants (each of which widens the true worst case), these
 *      two lower-bound assertions PASSED. What actually kills those two mutants is a SEPARATE check each —
 *      the direct `MIN_POSTOP_GAS >= 90,000` pin (below) and the dedicated prefund-band test's own
 *      `maxSponsoredOpCost`-enforcement assertion, together with some pre-existing tests elsewhere in
 *      this file — see each assertion's own comment for which mutant it closes. The
 *      THIRD test (the blind re-sponsor loop) makes an orthogonal claim about repeated
 *      re-sponsoring and deliberately stays on the "standard" 550k profile — see that test's own
 *      comment for why the burn profile collapses its multi-round behavior into a single round; that
 *      comment also now distinguishes `globalSpentToday` (88.33% of budget) from the SAME bundle's
 *      actual deposit drain (103.45% of budget) — see the `actualGasCost` note below for why those two numbers differ.
 *      Plus the "DESIGN LIMITATION (honest pin)" test in the latch block referenced above.
 *
 *      => The EntryPoint deposit remains the ONLY EVM-enforced ceiling on total loss. Size it as
 *      what you can afford to lose in a SINGLE BLOCK. Operators MUST NOT auto-refill the deposit
 *      on a timer without alerting on {SponsorshipRevoked} — but note that event is a LOWER BOUND
 *      on the incident (see its own NatSpec) and fires only for the REPETITION case; the
 *      single-bundle drain above can happen with exactly one such event, or with none at all.
 *
 *      NO GLOBAL *LATCH* — DELIBERATE (hot/cold separation + global gap). This corrects a claim
 *      previously made here, which read as if no fleet-wide blackout existed at all — narrowly
 *      true of the LATCH specifically, but misleading about the outcome: a fleet-wide blackout
 *      ALREADY EXISTS through a DIFFERENT mechanism, the `globalDailyBudget` deferral a few
 *      paragraphs below (the `validAfter` computed from `globalLastSpentDay` once
 *      `globalSpentToday` crosses `globalDailyBudget`) — that deferral defers EVERY sponsored op,
 *      for EVERY wallet, not just the wallet that tripped it. What was considered and
 *      deliberately NOT added is narrower than "a blackout can happen at all": a global
 *      COUNTERPART TO THE PER-WALLET LATCH IN {_postOp} — i.e. a STICKY trigger that, once
 *      tripped, stays tripped until the COLD owner key explicitly re-enables it, mirroring
 *      {setSponsored}'s per-wallet re-grant. The existing `globalDailyBudget` deferral is not
 *      sticky: it self-heals at the next UTC midnight with no key involved at all. The rejected
 *      design would have turned "any one wallet can defer the fleet until tomorrow" into "any one
 *      wallet can defer the fleet until a human intervenes" — strictly worse availability for the
 *      same permissionless trigger, which is why it was not added. 50 sponsored wallets each
 *      independently repeating their own `dailyCap` (0.001/wallet/day at deploy-aa.ts's ceiling)
 *      sum to 0.05/day, nominally the entire deposit — but `globalDailyBudget` (0.01/day at
 *      deploy-aa.ts's config, 5x smaller) binds FIRST and defers the WHOLE FLEET once cumulative
 *      spend crosses it, long before any wallet could drain the deposit this way; see
 *      {setSponsored}'s own NatSpec ("`globalDailyBudget`, not the latch, is the only thing that
 *      bounds this loop") for the same bound stated from a different angle. The industry-standard
 *      fix is not an on-chain latch at all but an OFF-CHAIN PER-OP SIGNATURE GATE, which this
 *      paymaster does not have: despite the name, {_validatePaymasterUserOp} verifies NO
 *      signature (see the note near the top of this file) — sponsorship is decided purely from this
 *      contract's own `walletPolicy` storage, so anyone can permissionlessly push ops for a
 *      sponsored wallet (`handleOps` is public, `beneficiary` is attacker-chosen) and the
 *      on-chain caps are the only defense. Introducing that gate is a tracked follow-up, not a
 *      silent gap.
 *
 *      The gap ACROSS DIFFERENT wallets within one bundle (each individually within its OWN
 *      `dailyCap`, but collectively exceeding `globalDailyBudget`) is UNCHANGED by this latch —
 *      that remains a soft breaker only, exactly as described above.
 *
 *      BUSINESS GATE IS (target, inner selector) — the business path requires BOTH
 *      `businessAllowlist[target]` AND `targetSelectorAllowlist[target][innerSelector]`.
 *      Allowlisting a target alone no longer sponsors every function on it (e.g. a settlement
 *      contract's `cancelOrder`, an unbounded cold-SSTORE primitive, is not sponsored unless its
 *      selector is listed too). `sponsorPersonal` wallets still bypass BOTH lists by design — see
 *      {_validatePaymasterUserOp}.
 *
 *      SELF-CALL GATE IS A SEPARATE, REPLACEMENT ALLOWLIST (the lost-passkey path):
 *      `onlySelf`-gated wallet-administration calls arrive as `execute(sender, 0, <selector,
 *      args>)` / an `executeBatch` element with `target == sender` — the wallet calling itself.
 *      `businessAllowlist`/`targetSelectorAllowlist` can never sponsor these: a wallet's own
 *      address is per-user and counterfactual, so it can never be meaningfully allowlisted as a
 *      "business target". `_extractBusinessOk` therefore consults a THIRD mapping,
 *      `selfSelectorAllowlist[innerSelector]`, INSTEAD OF the business pair whenever
 *      `target == sender` — never a union of the two. A union would silently grant a wallet its
 *      full BUSINESS selector set on self-calls the instant any wallet's address happened to also
 *      be `businessAllowlist`-listed (impossible today, since wallet addresses are never
 *      allowlisted as business targets, but the replacement semantics make that impossibility
 *      structural rather than incidental). Populated ADD-ONLY: v1 provisions ONLY
 *      `addOwnerAddress`/`addOwnerPublicKey` (a lost passkey can gain a fresh owner gaslessly);
 *      `removeOwnerAtIndex` is deliberately EXCLUDED — see {removeOwnerAtIndex}'s own NatSpec on
 *      instant, timelock-free removal ("whichever key acts first wins outright"). Sponsoring
 *      removal would turn `executeBatch([(self, addOwnerAddress(attacker)),
 *      (self, removeOwnerAtIndex(0, legit))])` into a gas-free wallet takeover for anyone holding
 *      ONE compromised owner key. Re-enablable later with a single cold-key {setSelfSelector}
 *      call if that tradeoff is ever revisited. The per-element check (`target == sender`) MUST
 *      stay INSIDE the `executeBatch` decode loop — hoisting it out (computing `isSelf` once from
 *      element 0) reopens exactly the shape the token-listing gate closed: a batch of
 *      `[(self, addOwnerAddress(x)), (burner, addOwnerAddress(x))]` would skip the business check
 *      on the SECOND element and read `selfSelectorAllowlist[addOwnerAddress]` for a call into
 *      arbitrary, unvetted code. See {_extractBusinessOk} and
 *      test/VerifyingPaymaster.test.ts "selfSelectorAllowlist — item 4 (lost-passkey rotation,
 *      add-only)".
 *      This gate RIDES ON an unverified `sender` (`sender` is never verified as an unmodified `StarzipWallet`,
 *      tracked as a deferred finding): for a genuine wallet the risk is bounded by `sponsored` +
 *      `maxSponsoredOpCost` + the upgrade-selector denylist below — but ONLY against
 *      sponsored *execution* of an upgrade.
 *
 *      IMPORTANT — the denylist does NOT bound sponsored
 *      *cancellation* of a pending upgrade. `requestUpgrade`/`cancelUpgrade`/`upgradeToAndCall`
 *      are refused as {setSelfSelector} entries (see {ForbiddenSelfSelector}), but the two
 *      selectors this deploy actually DOES sponsor — `addOwnerAddress` and `addOwnerPublicKey`
 *      — each call `StarzipWallet._cancelPendingUpgradeOnOwnerChange()` internally (see that
 *      function's NatSpec, and {addOwnerAddress}/{addOwnerPublicKey}'s own), which produces the
 *      IDENTICAL effect as a direct call to the denylisted `cancelUpgrade()`. So
 *      `cancelUpgrade`'s EFFECT is reachable gas-free through a sponsored selector even though
 *      `cancelUpgrade` itself can never be sponsored directly — one third of this paragraph's
 *      stated bound is inoperative against that specific path.
 *
 *      ACCEPTED CONSEQUENCE (product decision, NOT fixed): an attacker holding a
 *      compromised owner key on a sponsored wallet can repeatedly cancel a staged recovery
 *      upgrade at no cost to themselves, stalling the honest owner's attempt to reclaim the
 *      wallet via {requestUpgrade}. Bounded by two things, neither of which is the
 *      denylist: (1) the defending owner can fold removal of the compromised owner AND
 *      re-staging the upgrade into ONE `executeBatch`, so a subsequent attacker userOp can no
 *      longer name a valid `ownerIndex`; (2) the operator can `setSponsored(wallet, false)` the
 *      moment repeated `UpgradeCancelled` events are observed, ending the free-cancellation
 *      loop for that one wallet without touching any other. See {setSponsored}'s own NatSpec
 *      for the incident-response gap this creates (disabling sponsorship also strands the
 *      LEGITIMATE owner's recovery path). This residual is accepted and tracked separately.
 *
 *      The compensating control for the unverified `sender` ITSELF (as opposed to this cancellation-effect
 *      residual) remains OPERATIONAL — every address ever passed to
 *      {setSponsored}/{setSponsoredBatch} MUST be verified off-chain as an actual
 *      `StarzipWalletFactory.getAddress(owners, salt)` output before being sponsored, never a
 *      hand-picked address.
 *
 *      GAS-PARAMETER CAPS: `dailyCap`/`globalDailyBudget` bound `maxCost`, but
 *      `maxCost` is itself attacker-declared (verificationGasLimit, callGasLimit,
 *      paymasterVerificationGasLimit, paymasterPostOpGasLimit, preVerificationGas, maxFeePerGas —
 *      every field the sender chose when constructing the op). Because `handleOps` is
 *      permissionless, an attacker who owns a legitimately sponsored wallet can call it directly
 *      with `beneficiary = self` and inflate these fields to be overpaid relative to actual gas
 *      consumption — `preVerificationGas` dominates, since the EntryPoint adds it to `preOpGas`
 *      (see the account-abstraction package's EntryPoint.sol) without it ever being spent.
 *      `maxSponsoredFeePerGas` caps `maxFeePerGas` — the field `EntryPoint._getRequiredPrefund`
 *      actually multiplies by (`requiredGas * mUserOp.maxFeePerGas`, EntryPoint.sol) and the one
 *      `UserOperationLib.gasPrice`'s `min(maxFeePerGas, maxPriorityFeePerGas + block.basefee)`
 *      caps the compensated rate at. The SAME cap is also checked against `maxPriorityFeePerGas`,
 *      but that second check is defense-in-depth, NOT an independent bound: because of that
 *      `min(...)`, a higher `maxPriorityFeePerGas` can only ever LOWER the effective paid rate
 *      toward `maxFeePerGas`, never raise it past it — once `maxFeePerGas` is capped, priority
 *      alone cannot reopen the drain (see the inline comment at the check site for why the guard
 *      is kept anyway). `maxSponsoredPreVerificationGas` caps the other, genuinely independent
 *      lever. for `maxSponsoredOpCost`/`maxSponsoredFeePerGas`/
 *      `maxSponsoredPreVerificationGas`, `0` blocks every op declaring a non-zero value in that
 *      field; an op declaring zero for a given field is admitted and costs nothing on that field
 *      specifically — see {maxSponsoredOpCost}'s NatSpec. This is the SAME shape `dailyCap`/`globalDailyBudget`/
 *      `globalDailyCapCeiling` below already use ("block", never "unlimited") — one convention
 *      across every cap on this contract, not two. See each field's own NatSpec for the exact
 *      predicate it blocks on.
 *
 *      RENOUNCE IS DISABLED: `Ownable2Step` only guards `transferOwnership` against
 *      mistakes; `renounceOwnership()` is inherited unchanged from `Ownable` and would set
 *      `owner() == address(0)`. Unlike `UpgradeableBeacon`/`TradeSettlementV1` (which only need to
 *      clear staged upgrade/recovery state on ownership handover), this contract has no recovery
 *      path once ownerless: `withdrawTo` (the only way to reclaim the EntryPoint deposit),
 *      `unlockStake`/`withdrawStake`, `unpause`, and every owner-only allowlist/budget/cap setter
 *      would be permanently unreachable. {renounceOwnership} is overridden to always revert.
 */
contract VerifyingPaymaster is BasePaymaster, IPaymasterSelectorPolicy {
    using UserOperationLib for PackedUserOperation;

    // ============ Constants ============
    /// @dev Empirically derived. Measured via `PostOpGasProbe` +
    ///      test/VerifyingPaymaster.postOpGas.test.ts: a direct call to `postOp` as the very
    ///      FIRST storage-touching op on a fresh paymaster instance — i.e. `walletPolicy[sender]`
    ///      and the global spent/day slot are both genuinely cold, AND the CALL into the
    ///      paymaster itself is cold (strictly worse than the real handleOps flow, where
    ///      `_validatePaymasterUserOp` already warms those slots earlier in the same
    ///      transaction). Re-derived after the latch + effective-cap clamp landed
    ///      (the clamp adds one `globalDailyCapCeiling` SLOAD, cold in the probe, warm in the real
    ///      flow). All four branches the probe can reach, measured by that test:
    ///        unprovisioned (COLD `!sponsored`, probe's own storage never touched)  **76,759** <- probe-only
    ///        sponsored, under cap (latch branch not taken)                          59,715
    ///        sponsored, over cap (latch fires: SSTORE + LOG2)                       61,441  <- reachable worst
    ///        VIP, over cap (latch fires — VIP is not exempt)                        61,441  <- reachable worst
    ///      The 76,759 NUMBER is unreachable in production, but do not read that as "the
    ///      `!p.sponsored` branch inside `_postOp` is unreachable" — it is NOT the same claim, and
    ///      the branch IS reachable. What is actually unreachable is the COLD-STORAGE COMBINATION
    ///      the probe measures: a wallet that was NEVER sponsored can never reach `_postOp` at all
    ///      (`_validatePaymasterUserOp` hard-declines `!p.sponsored` with AA34 before the op can
    ///      execute), so only `PostOpGasProbe` — which calls `postOp` directly with no validation
    ///      in front of it, on a wallet whose `walletPolicy` slot has never been written — can
    ///      produce that number. But a wallet that WAS sponsored and gets latched MID-BUNDLE (see
    ///      the "AUDIT C-B" note above: by the time `_postOp` runs for op i, ops i+1..N for the
    ///      SAME wallet in the SAME bundle already cleared validation) DOES reach `_postOp` with
    ///      `p.sponsored == false` in storage for those later ops — the branch executes in
    ///      production, just on WARM storage (the SAME wallet's slot, just written by an earlier
    ///      op in this very transaction), which is cheap, not 76,759. The REACHABLE worst case
    ///      across every combination this constant must cover remains the latched / VIP-latched
    ///      branch at 61,441, so the real margin is 90,000 - 61,441 = 28,559 gas = 46%, not the
    ///      13,241 gas / 17.3% the 76,759 pin implies. 76,759 is kept as the constant's derivation
    ///      on purpose — it is the conservative direction, and the probe test asserting it stays
    ///      the ceiling is what dies first if `_postOp` ever gets more expensive. The
    ///      probe test used to measure ONLY the unprovisioned case, so the latch branch was dead in
    ///      the one test guarding this constant; it now measures all four and asserts the
    ///      unprovisioned case remains the ceiling. A higher floor is strictly safer (it only means
    ///      a userOp must forward more `paymasterPostOpGasLimit`, not that `_postOp` actually costs
    ///      more) — if `_postOp`'s logic ever changes, re-run the probe test and re-derive this.
    uint128 public constant MIN_POSTOP_GAS = 90_000;

    /// @dev Mirrors StarzipWallet.MAX_BATCH_SIZE — caps the executeBatch decode loop. Duplicated,
    ///      unpinned (two separate `constant` declarations, not one shared source — see
    ///      StarzipWallet.sol's own `MAX_BATCH_SIZE` NatSpec for the full coupling analysis).
    ///      FAIL-CLOSED TODAY: this constant only bounds THIS
    ///      contract's own calldata parser when deciding whether to sponsor an `executeBatch` op
    ///      (the `n > MAX_BATCH_SIZE` bounds check inside {_extractBusinessOk}'s
    ///      `executeBatch` branch — a symbolic reference, not a line number, because this file's
    ///      line numbers move on every edit and a stale numeric pointer here has already gone
    ///      wrong once) — it never gates execution on the wallet itself, so a divergence between
    ///      the two copies degrades to a sponsorship mismatch, never an executed batch larger than
    ///      the wallet's own `BatchTooLarge` check actually allows.
    uint256 private constant MAX_BATCH_SIZE = 32;

    // ============ Structs ============
    struct WalletPolicy {
        // entry slot n (packed, 23 bytes)
        bool sponsored;
        bool sponsorPersonal; // false => business-only
        // Owner-granted. Bypasses the PER-OP `dailyCap` check in {_validatePaymasterUserOp} only.
        // It does NOT bypass `globalDailyBudget`, and — since the latch — it does NOT bypass the
        // CUMULATIVE daily spend latch in {_postOp} either: a VIP wallet is still auto-unsponsored
        // once `spentToday` crosses `min(dailyCap, globalDailyCapCeiling)`. "Unlimited" therefore
        // means "unlimited per op", never "unlimited per day". Pinned by
        // test/VerifyingPaymaster.spendcap.test.ts "VIP wallets ALSO trip the latch ...".
        bool vip;
        uint32 lastSpentDay; // set in postOp only
        // @dev SOFT breaker only (see contract header): checked in
        //      _validatePaymasterUserOp against pre-bundle storage, not atomically re-checked
        //      per-op within one handleOps bundle. Gas-cost wei; must be >0 for a non-vip wallet
        //      to be sponsored. The EntryPoint deposit — not this cap — is the hard loss ceiling.
        //      Also the CUMULATIVE latch threshold in {_postOp} (clamped there by
        //      `globalDailyCapCeiling`) — for VIP wallets too, which is why
        //      {setSponsoredUnlimited} refuses to grant VIP while this is 0.
        uint128 dailyCap;
        // entry slot n+1
        uint128 spentToday; // set in postOp only
    }

    // ============ State Variables ============
    // slot 2 (packed)
    address public policyManager;
    bool public paused;

    // slot 3 (packed)
    /// @dev Upper bound on every non-VIP wallet's effective `dailyCap`, re-applied on EVERY
    ///      validation as `min(dailyCap, globalDailyCapCeiling)` (see {_validatePaymasterUserOp}).
    ///      `0` = blocks ALL non-VIP sponsorship (`effectiveDailyCap` collapses to 0, so
    ///      `maxCost > 0` always hard-declines) — this is the OPPOSITE convention from
    ///      `maxSponsoredOpCost`/`maxSponsoredFeePerGas`/`maxSponsoredPreVerificationGas`, where
    ///      `0` means "no limit". See {setGlobalDailyCapCeiling}.
    uint128 public globalDailyCapCeiling;
    /// @dev SOFT breaker only (see contract header): checked in
    ///      _validatePaymasterUserOp against pre-bundle storage, not atomically re-checked
    ///      per-op within one handleOps bundle — a single bundle can push total sponsorship past
    ///      this figure. `0` = global sponsorship disabled (safe default). The EntryPoint
    ///      deposit — not this budget — is the EVM-enforced hard cap on total paymaster loss;
    ///      size the deposit as the acceptable max daily loss, not this budget.
    uint128 public globalDailyBudget;

    // slot 4 (packed)
    uint128 public globalSpentToday;
    uint32 public globalLastSpentDay;

    // slot 5
    mapping(address => WalletPolicy) private walletPolicy;

    // slot 6
    /// @dev COARSE gate. Necessary but NOT sufficient: the business path also requires
    ///      `targetSelectorAllowlist[target][innerSelector]`.
    mapping(address => bool) public businessAllowlist;

    // slot 7
    /// @dev Per-op cap on `maxCost`: bounds how much of the EntryPoint
    ///      deposit a single op can reserve, independent of the (soft) budget/cap breakers above.
    ///      `0` blocks every op declaring a non-zero `maxCost`; an op declaring
    ///      `maxCost == 0` is admitted and costs nothing — see {maxSponsoredOpCost}'s NatSpec.
    uint128 public maxSponsoredOpCost;

    // slot 8
    /// @inheritdoc IPaymasterSelectorPolicy
    /// @dev Appended AFTER `maxSponsoredOpCost` so slots 0-7 stay byte-identical (this contract is
    ///      non-upgradeable, so the append is discipline rather than a hard requirement — an
    ///      already-deployed paymaster cannot gain this gate and must be redeployed + reprovisioned).
    mapping(address => mapping(bytes4 => bool)) public override targetSelectorAllowlist;

    // slot 9 (packed)
    /// @dev Per-op cap on the declared `maxFeePerGas`: bounds what the userOp's
    ///      chosen `beneficiary` can be compensated for per unit of gas, independent of
    ///      `maxSponsoredOpCost`/`dailyCap`/`globalDailyBudget` (which all key off `maxCost`,
    ///      itself derived from these same attacker-declared fields). `maxFeePerGas` is the field
    ///      that actually bounds the paid rate — `EntryPoint._getRequiredPrefund` multiplies by
    ///      it directly, and `UserOperationLib.gasPrice`'s
    ///      `min(maxFeePerGas, maxPriorityFeePerGas + block.basefee)` caps the compensated rate at
    ///      it too. `maxPriorityFeePerGas` is ALSO checked against this same cap, but only as
    ///      defense-in-depth: that `min(...)` means a higher priority fee can only LOWER the
    ///      effective paid rate below `maxFeePerGas`, never raise it past it — so once
    ///      `maxFeePerGas` is capped, the priority check bounds nothing further on its own (see
    ///      the check site in {_validatePaymasterUserOp} for why it is kept regardless). Audit
    ///      `0` blocks every op declaring a non-zero `maxFeePerGas`/`maxPriorityFeePerGas`;
    ///      an op declaring both as zero is admitted and costs nothing — see {maxSponsoredOpCost}'s NatSpec, and the
    ///      contract header's GAS-PARAMETER CAPS note for the one convention shared by every cap
    ///      on this contract.
    uint128 public maxSponsoredFeePerGas;

    /// @dev Per-op cap on the declared `preVerificationGas`: this is the DOMINANT
    ///      lever in the measured drain — the EntryPoint adds the full declared value to
    ///      `preOpGas` even though none of it is actually consumed, so `maxSponsoredFeePerGas`
    ///      alone cannot bound this. `0` blocks every op declaring a non-zero
    ///      `preVerificationGas`; an op declaring `preVerificationGas == 0` is admitted and costs
    ///      nothing on this field — see {maxSponsoredOpCost}'s NatSpec.
    uint128 public maxSponsoredPreVerificationGas;

    // slot 10
    /// @dev Appended AFTER slot 9 (non-upgradeable, so — as with {targetSelectorAllowlist} — this
    ///      is discipline, not a hard requirement). Selectors sponsored on SELF-calls
    ///      (`execute`/`executeBatch` where `target == userOp.sender`) — see the contract header's
    ///      "SELF-CALL GATE IS A SEPARATE, REPLACEMENT ALLOWLIST" note for the full rationale.
    ///      REPLACES `businessAllowlist`/`targetSelectorAllowlist` on self-calls; never unioned
    ///      with them. Owner-only (cold) setters below refuse the three selectors reaching
    ///      StarzipWallet's upgrade surface — see {setSelfSelector}.
    mapping(bytes4 => bool) public selfSelectorAllowlist;

    // ============ Events ============
    event PolicyManagerChanged(address indexed previousManager, address indexed newManager);
    event Paused(address indexed by);
    event Unpaused(address indexed by);
    event GlobalDailyBudgetSet(uint128 budget);
    event GlobalDailyCapCeilingSet(uint128 ceiling);
    event MaxSponsoredOpCostSet(uint128 cost);
    event MaxSponsoredFeePerGasSet(uint128 fee);
    event MaxSponsoredPreVerificationGasSet(uint128 gas);
    event SponsoredSet(address indexed wallet, bool sponsored);
    event DailyCapSet(address indexed wallet, uint128 cap);
    event SponsorPersonalSet(address indexed wallet, bool sponsorPersonal);
    event VipSet(address indexed wallet, bool vip);
    event BusinessTargetSet(address indexed target, bool allowed);
    /// @dev Emitted when a single self-call selector's allowlist status changes — see
    ///      {selfSelectorAllowlist} and {setSelfSelector}.
    event SelfSelectorSet(bytes4 indexed selector, bool allowed);
    /// @notice Emitted once per batch update via {setSelfSelectors}.
    event SelfSelectorsBatchUpdated(uint256 count, bool allowed);
    event GasSponsored(
        address indexed wallet,
        uint256 actualGasCost,
        uint128 walletSpentTodayAfter,
        uint128 globalSpentTodayAfter
    );
    /// @dev Audit C-B: emitted when the bundle-aggregation auto-unsponsor latch fires (see
    ///      {_postOp}). Distinguishes "unsponsored because a bundle blew past the cap" from every
    ///      other reason an op can HARD_DECLINE (all currently collapse to the same AA34 at the
    ///      EntryPoint level — this event is the only on-chain way to tell them apart for now).
    /// @param wallet The wallet that was auto-unsponsored.
    /// @param spentToday LOWER BOUND on the incident, NOT its size. Emitted at the
    ///        CROSSING op; every later op in the SAME bundle was already admitted by the validation
    ///        phase and keeps accruing after this fires. Measured: 0.001035 emitted for a bundle
    ///        that finished at 0.004955 — a 4.8x under-report. Alert on
    ///        `getPolicy(wallet).spentToday` (post-tx) or the sum of {GasSponsored}`.actualGasCost`
    ///        in the same transaction; use this field only as "an incident happened", never as
    ///        "the incident was this big".
    /// @param effectiveDailyCap The threshold actually crossed: `min(dailyCap,
    ///        globalDailyCapCeiling)`, which is what validation enforces — NOT
    ///        necessarily the wallet's stored `dailyCap`.
    event SponsorshipRevoked(address indexed wallet, uint128 spentToday, uint128 effectiveDailyCap);

    // ============ Errors ============
    error ZeroAddress();
    error NotPolicyManager();
    error NotOwnerOrPolicyManager();
    error CapExceedsCeiling();
    error ZeroCapNotAllowed();
    error RenounceOwnershipDisabled();
    /// @dev {unpause} refuses while any of `maxSponsoredOpCost` /
    ///      `maxSponsoredFeePerGas` / `maxSponsoredPreVerificationGas` is still 0 (unprovisioned).
    error CapsNotProvisioned();
    /// @dev {setSelfSelector}/{setSelfSelectors} refuse `requestUpgrade(address)` /
    ///      `cancelUpgrade()` / `upgradeToAndCall(address,bytes)` — the three `onlySelf` selectors
    ///      that reach StarzipWallet's upgrade surface. See the contract header's "SELF-CALL GATE"
    ///      note for why sponsoring a self-upgrade must never be reachable, even by a future
    ///      owner-key mistake.
    error ForbiddenSelfSelector();

    // ============ Modifiers ============
    modifier onlyPolicyManager() {
        if (msg.sender != policyManager) revert NotPolicyManager();
        _;
    }

    /// @param _policyManager Hot backend key; owner may rotate it later via {setPolicyManager}.
    /// @dev Starts `paused = true` (safe bring-up) and `globalDailyBudget = 0` (disabled) until
    ///      the owner explicitly provisions them — see deploy-aa.ts bring-up order.
    constructor(IEntryPoint _entryPoint, address _policyManager) BasePaymaster(_entryPoint) {
        if (_policyManager == address(0)) revert ZeroAddress();
        policyManager = _policyManager;
        paused = true;
    }

    // ============ Owner (cold) ============
    function setPolicyManager(address m) external onlyOwner {
        if (m == address(0)) revert ZeroAddress();
        address prev = policyManager;
        policyManager = m;
        emit PolicyManagerChanged(prev, m);
    }

    /// @dev Lowering `ceiling` below an already-provisioned wallet's stored `dailyCap` does NOT
    ///      touch that wallet's storage — on-chain enumeration of every `walletPolicy` entry to
    ///      reclamp them is not possible (no on-chain wallet registry, and iterating an unbounded
    ///      off-chain list on every ceiling change is not safe to do atomically anyway). Instead,
    ///      `_validatePaymasterUserOp` re-derives `min(dailyCap, globalDailyCapCeiling)` on EVERY
    ///      validation (see the `effectiveDailyCap` comment there) — a lowered ceiling therefore
    ///      takes effect on a wallet's very next op, without any per-wallet migration.
    /// @dev KILL-SWITCH: `ceiling == 0` collapses every non-VIP wallet's `effectiveDailyCap` to 0,
    ///      which hard-declines every non-VIP op (`maxCost > 0` always exceeds it) — i.e. this is
    ///      one of several ceiling/cap-only ways to blanket-decline sponsorship, alongside {pause}
    ///      and `globalDailyBudget == 0`. See {setMaxSponsoredOpCost} /
    ///      {setMaxSponsoredFeePerGas} / {setMaxSponsoredPreVerificationGas}) added THREE more of
    ///      these — `maxSponsoredOpCost == 0`, `maxSponsoredFeePerGas == 0`, and
    ///      `maxSponsoredPreVerificationGas == 0` each now hard-decline every op that declares a
    ///      non-zero value in that field — so the FULL fleet-wide kill-switch inventory is SEVEN:
    ///      {pause}, `globalDailyBudget == 0`, this ceiling, the three per-op caps, and
    ///      `unlockStake()` (inherited from `BasePaymaster` — see the contract-level doc
    ///      comment at the top of this file).
    ///
    ///      VIP REACH DIFFERS PER SWITCH, and THIS ceiling is the odd one out: `!p.vip` skips the
    ///      ceiling-derived `effectiveDailyCap` check entirely in {_validatePaymasterUserOp}, so
    ///      `ceiling == 0` does NOT stop VIP spend. Every OTHER switch stops VIPs too — {pause}
    ///      and `globalDailyBudget == 0` are both checked unconditionally, and the three per-op caps
    ///      run even earlier, BEFORE `walletPolicy[sender]` is ever read (see
    ///      {_validatePaymasterUserOp}'s per-op gas-parameter caps, checked immediately after
    ///      `maxSponsoredOpCost`), so a VIP wallet gets no special treatment from them either. Use
    ///      {pause} or `globalDailyBudget = 0` (or any of the three per-op caps) if VIPs must be
    ///      blocked too; `unlockStake()` stops everyone, VIP included, since it acts at the
    ///      bundler-acceptance layer, not this contract's own policy checks — and unlike every
    ///      other switch here, it does so SILENTLY: it voids the staked-entity assumption
    ///      `_validatePaymasterUserOp` relies on for ERC-7562 public-bundler eligibility, with no
    ///      event and no `paused`/cap flag to read it off — a bundler simply stops accepting this
    ///      paymaster's ops.
    function setGlobalDailyCapCeiling(uint128 ceiling) external onlyOwner {
        globalDailyCapCeiling = ceiling;
        emit GlobalDailyCapCeilingSet(ceiling);
    }

    /// @dev `budget == 0` disables all global sponsorship (hard decline all) — safe default.
    function setGlobalDailyBudget(uint128 budget) external onlyOwner {
        globalDailyBudget = budget;
        emit GlobalDailyBudgetSet(budget);
    }

    /// @dev `cost == 0` blocks every op declaring a non-zero `maxCost`; an op
    ///      declaring `maxCost == 0` is admitted and costs nothing — see {maxSponsoredOpCost}'s NatSpec and
    ///      {maxSponsoredOpCost}. Kept accepting 0 deliberately (not reverted): 0 remains a
    ///      reachable, meaningful value with the same shape as `globalDailyBudget`/
    ///      `globalDailyCapCeiling`/`dailyCap` (all "0 = block"); the fail-open this
    ///      closes was in the VALIDATION path, not in what this setter accepts. {unpause} refuses
    ///      to bring the paymaster live while this is still 0.
    function setMaxSponsoredOpCost(uint128 cost) external onlyOwner {
        maxSponsoredOpCost = cost;
        emit MaxSponsoredOpCostSet(cost);
    }

    /// @dev `fee == 0` blocks every op declaring a non-zero `maxFeePerGas`/
    ///      `maxPriorityFeePerGas`; an op declaring both as zero is admitted — see {maxSponsoredOpCost}'s NatSpec and
    ///      {maxSponsoredFeePerGas}. Downside to record: unlike before this fix, `fee == 0` can no
    ///      longer be used as an operator "disable this cap" toggle — it is now a total,
    ///      indefinite blackout for any non-zero-fee op, sharpening the operator-panic direction
    ///      already flagged separately (a hardcoded, oracle-less 1 gwei ceiling). {unpause}
    ///      refuses to bring the paymaster live while this is still 0.
    function setMaxSponsoredFeePerGas(uint128 fee) external onlyOwner {
        maxSponsoredFeePerGas = fee;
        emit MaxSponsoredFeePerGasSet(fee);
    }

    /// @dev `gas == 0` blocks every op declaring a non-zero `preVerificationGas`; an
    ///      op declaring `preVerificationGas == 0` is admitted — see {maxSponsoredOpCost}'s NatSpec and
    ///      {maxSponsoredPreVerificationGas}. {unpause} refuses to bring the paymaster live while
    ///      this is still 0.
    function setMaxSponsoredPreVerificationGas(uint128 gas) external onlyOwner {
        maxSponsoredPreVerificationGas = gas;
        emit MaxSponsoredPreVerificationGasSet(gas);
    }

    /// @notice VIP: unlimited PER OP (bypasses the per-op `dailyCap` check in
    ///         {_validatePaymasterUserOp}). It does NOT bypass `globalDailyBudget`, and it does NOT
    ///         bypass the cumulative daily spend latch in {_postOp} — see {WalletPolicy}'s `vip`
    ///         field and {_postOp}'s NatSpec.
    /// @dev Granting VIP REQUIRES a non-zero `dailyCap` to already be provisioned.
    ///      Without this guard the natural provisioning path (`setSponsoredUnlimited` and nothing
    ///      else) left `dailyCap == 0`, so the C-B latch fired on the VIP wallet's very FIRST op —
    ///      i.e. "unlimited" silently meant "exactly one op, ever". `dailyCap` is the latch
    ///      threshold for VIPs too, so it must be set deliberately, not defaulted.
    ///      That guard only closes the `dailyCap == 0` path — it says nothing
    ///      about a wallet that already has a non-zero `dailyCap` AND has already spent close to it
    ///      TODAY. Before this fix, granting VIP wrote ONLY the `vip` flag, unlike its sibling
    ///      {setSponsored} (which also zeroes `spentToday`/`lastSpentDay`, the counter reset). Because VIP
    ///      is NOT exempt from the CUMULATIVE latch in {_postOp} (only from the PER-OP cap check),
    ///      the carried-forward `spentToday` meant the wallet's very next op — of any non-zero
    ///      cost — could immediately cross the latch threshold and auto-revoke sponsorship: the
    ///      SAME "unlimited silently means one op, ever" symptom that guard closed for the `dailyCap == 0`
    ///      case, reopened via a different path. Fixed by mirroring {setSponsored}'s reset on
    ///      GRANT only (never on revoke, so revocation stays unconditional and cannot be blocked).
    ///      This also makes all three grant paths (`setSponsored`, `setSponsoredBatch`,
    ///      `setSponsoredUnlimited`) write the same set of fields, closing the class rather than
    ///      the one instance. `globalSpentToday` is deliberately NOT reset here either, for the
    ///      same containment reason {setSponsored} does not reset it.
    ///      NOTE the key split this creates: granting VIP is `onlyOwner` (cold) while {setDailyCap}
    ///      and {setSponsored} are `onlyPolicyManager` (hot) — so the owner cannot provision, nor
    ///      later revive, a VIP on its own. That is the hot/cold separation working as
    ///      designed, but it does mean VIP provisioning is a TWO-key operation. Pinned by
    ///      test/VerifyingPaymaster.spendcap.test.ts "setSponsoredUnlimited(wallet, true) with an
    ///      unprovisioned dailyCap REVERTS ..." and the "setSponsoredUnlimited counter
    ///      reset" describe block.
    ///      Revoking VIP (`on == false`) is unconditional and does NOT reset the counters — the
    ///      guard must never be able to trap a wallet in VIP status, and a revoke is not a fresh
    ///      grant.
    function setSponsoredUnlimited(address wallet, bool on) external onlyOwner {
        if (wallet == address(0)) revert ZeroAddress();
        WalletPolicy storage p = walletPolicy[wallet];
        if (on && p.dailyCap == 0) revert ZeroCapNotAllowed();
        p.vip = on;
        if (on) {
            p.spentToday = 0;
            p.lastSpentDay = 0;
        }
        emit VipSet(wallet, on);
    }

    function setBusinessTarget(address target, bool allowed) external onlyOwner {
        if (target == address(0)) revert ZeroAddress();
        businessAllowlist[target] = allowed;
        emit BusinessTargetSet(target, allowed);
    }

    function setBusinessTargets(address[] calldata targets, bool allowed) external onlyOwner {
        uint256 len = targets.length;
        for (uint256 i = 0; i < len; ) {
            address target = targets[i];
            if (target == address(0)) revert ZeroAddress();
            businessAllowlist[target] = allowed;
            emit BusinessTargetSet(target, allowed);
            unchecked {
                ++i;
            }
        }
    }

    /// @inheritdoc IPaymasterSelectorPolicy
    /// @dev Owner-only (cold), mirroring {setBusinessTarget}: this is the fine-grained half of the
    ///      same business gate, so it must not be reachable from the hot policyManager key.
    function setTargetSelector(address target, bytes4 selector, bool allowed) external override onlyOwner {
        if (target == address(0)) revert ZeroAddress();
        targetSelectorAllowlist[target][selector] = allowed;
        emit TargetSelectorUpdated(target, selector, allowed);
    }

    /// @inheritdoc IPaymasterSelectorPolicy
    /// @dev Emits the per-entry {TargetSelectorUpdated} as well as the batch summary, so indexers
    ///      tracking only the singular event still see a complete record of every state change.
    function setTargetSelectors(address target, bytes4[] calldata selectors, bool allowed) external override onlyOwner {
        if (target == address(0)) revert ZeroAddress();
        uint256 len = selectors.length;
        for (uint256 i = 0; i < len; ) {
            bytes4 selector = selectors[i];
            targetSelectorAllowlist[target][selector] = allowed;
            emit TargetSelectorUpdated(target, selector, allowed);
            unchecked {
                ++i;
            }
        }
        emit TargetSelectorsBatchUpdated(target, len, allowed);
    }

    /// @dev Reverts `ForbiddenSelfSelector` for the three selectors on StarzipWallet's
    ///      upgrade surface — see the contract header's "SELF-CALL GATE" note and
    ///      {ForbiddenSelfSelector}'s own NatSpec. Every OTHER selector is accepted. StarzipWallet's
    ///      full `onlySelf` surface is SIX external selectors — `addOwnerAddress`,
    ///      `addOwnerPublicKey`, `removeOwnerAtIndex`, `requestUpgrade`, `cancelUpgrade`, and
    ///      `upgradeToAndCall` (its internal `_authorizeUpgrade` override is itself `onlySelf`, but
    ///      is not externally callable and so has no selector of its own to enumerate here) — of
    ///      which THIS check denies three (`requestUpgrade`/`cancelUpgrade`/`upgradeToAndCall`),
    ///      leaving three remaining selectors this check does not itself gate the meaning of:
    ///      `addOwnerAddress`, `addOwnerPublicKey`, `removeOwnerAtIndex` (whether they are ever
    ///      added to {selfSelectorAllowlist} is a provisioning decision, e.g. deploy-aa.ts's
    ///      `SELF_SPONSORED` — this check only forecloses the three that must NEVER be
    ///      sponsorable, on-chain, regardless of who calls the setter).
    function setSelfSelector(bytes4 selector, bool allowed) external onlyOwner {
        _requireNotForbiddenSelfSelector(selector);
        selfSelectorAllowlist[selector] = allowed;
        emit SelfSelectorSet(selector, allowed);
    }

    /// @dev Batch form of {setSelfSelector}. Emits the per-entry {SelfSelectorSet} as well as the
    ///      batch summary, mirroring {setTargetSelectors}.
    function setSelfSelectors(bytes4[] calldata selectors, bool allowed) external onlyOwner {
        uint256 len = selectors.length;
        for (uint256 i = 0; i < len; ) {
            bytes4 selector = selectors[i];
            _requireNotForbiddenSelfSelector(selector);
            selfSelectorAllowlist[selector] = allowed;
            emit SelfSelectorSet(selector, allowed);
            unchecked {
                ++i;
            }
        }
        emit SelfSelectorsBatchUpdated(len, allowed);
    }

    /// @dev Denylist check shared by {setSelfSelector}/{setSelfSelectors}. Selectors taken
    ///      from the declaring types themselves (never hardcoded bytes) — `StarzipWallet` for
    ///      `requestUpgrade`/`cancelUpgrade`, `UUPSUpgradeable` for the inherited, un-overridden
    ///      `upgradeToAndCall` — so a future rename of any of these three functions moves this
    ///      check with it instead of silently going stale.
    ///
    ///      DOES NOT close: `cancelUpgrade`'s cancellation EFFECT (as opposed to `cancelUpgrade`
    ///      itself) is still reachable, gas-free, through the two selectors this deploy DOES
    ///      sponsor — `addOwnerAddress`/`addOwnerPublicKey` each call
    ///      `_cancelPendingUpgradeOnOwnerChange()` internally. This check only forbids sponsoring
    ///      the three selectors directly; it was never meant to, and does not, bound that
    ///      residual. See the contract header's corrected "This gate RIDES ON an unverified `sender`" paragraph
    ///      (ACCEPTED and tracked separately) for the full accepted-risk record.
    function _requireNotForbiddenSelfSelector(bytes4 selector) private pure {
        if (
            selector == StarzipWallet.requestUpgrade.selector ||
            selector == StarzipWallet.cancelUpgrade.selector ||
            selector == UUPSUpgradeable.upgradeToAndCall.selector
        ) {
            revert ForbiddenSelfSelector();
        }
    }

    /// @dev Only the owner can resume sponsorship after a pause (policyManager cannot). Audit
    ///      Also refuses while any of the three per-op gas-parameter caps
    ///      (`maxSponsoredOpCost` / `maxSponsoredFeePerGas` / `maxSponsoredPreVerificationGas`) is
    ///      still 0. Before this check, the ONLY thing standing between an unprovisioned cap and a
    ///      live fail-open paymaster was the off-chain `throw` in `deploy-aa.ts:324-336` — a
    ///      TypeScript assertion that binds nothing on-chain and nothing outside that one script
    ///      path (e.g. a manual `unpause()` from a block explorer). This moves that same
    ///      precondition on-chain; the script-side throw stays as defense in depth, not as the
    ///      only guard. Deliberately does NOT also require `globalDailyBudget` /
    ///      `globalDailyCapCeiling` to be non-zero — those two already fail closed at their own 0
    ///      default (see their NatSpec above), so gating `unpause` on them too would redefine what
    ///      "unpaused" means rather than close a gap. `setMaxSponsored*` keep accepting 0 (see each
    ///      setter's NatSpec) — 0 remains a valid, reachable value, just not one `unpause()` will
    ///      launch with.
    function unpause() external onlyOwner {
        if (maxSponsoredOpCost == 0 || maxSponsoredFeePerGas == 0 || maxSponsoredPreVerificationGas == 0) {
            revert CapsNotProvisioned();
        }
        paused = false;
        emit Unpaused(msg.sender);
    }

    /// @notice Disabled — see contract header "RENOUNCE IS DISABLED". Unlike
    ///         `transferOwnership`, `Ownable2Step` does not guard `renounceOwnership()`; this
    ///         contract has no recovery path for `owner() == address(0)`, so the renounce itself
    ///         must be refused rather than merely discouraged.
    function renounceOwnership() public pure override {
        revert RenounceOwnershipDisabled();
    }

    // ============ PolicyManager (hot) ============
    /// @dev Re-sponsoring ALSO clears the wallet's spend record. Without this, the
    ///      "reactivate via {setSponsored}" recovery path advertised by {_postOp} did not actually
    ///      work: a latched wallet can never reach `_postOp` again (it hard-declines at
    ///      `!p.sponsored`), so its `spentToday`/`lastSpentDay` FREEZE at the revocation values.
    ///      On re-sponsor, the very next validation hit
    ///      `spentToday + maxCost > effectiveDailyCap` with a frozen, already-over-cap
    ///      `spentToday`, and deferred to `validAfter = (lastSpentDay + 1) * 1 days` — i.e. the
    ///      EntryPoint rejected every op with AA32 for up to 24h. Zeroing both counters puts the
    ///      wallet back in the same state as a brand-new one, so same-day recovery works.
    ///
    ///      This does NOT reopen the same-day decline. Its fix is the UNCONDITIONAL hard-decline
    ///      `maxCost > effectiveDailyCap` (and the global-budget twin), and NEITHER of the two
    ///      reads `spentToday` or `lastSpentDay` at all. Ordering, stated precisely: in
    ///      {_validatePaymasterUserOp} the PER-WALLET hard-decline runs before that wallet's
    ///      deferral arithmetic; the GLOBAL twin runs AFTER it, so a candidate `validAfter` may
    ///      already have been computed from `lastSpentDay` by the time the global decline fires.
    ///      That does not weaken the argument: both declines `return` a `sigFail=true`
    ///      validationData that carries NO `validAfter`, so a stale or zeroed counter can never
    ///      influence either one. A zeroed counter can therefore never uncap a SINGLE op: the most a
    ///      re-sponsor grants is one fresh `effectiveDailyCap`-worth of same-day spend, which is
    ///      exactly the intended semantics. `globalSpentToday` is deliberately NOT reset, so the
    ///      fleet-wide budget still binds a re-sponsored wallet. Pinned by
    ///      test/VerifyingPaymaster.spendcap.test.ts "setSponsored(true) restores sponsorship
    ///      SAME-DAY" plus the same-day-decline regression block (which must keep passing unchanged).
    ///
    ///      TRADEOFF, stated plainly: `policyManager` is the HOT key, and it can now zero a
    ///      wallet's on-chain spend record. In the current deployment `owner == policyManager`
    ///     , so the marginal privilege increase is small — but it is real, and it
    ///      becomes material the moment those roles are actually split.
    ///      OPERATIONAL WARNING: a backend that blindly re-runs `setSponsored(user, true)` in a
    ///      periodic sync/reconcile loop silently undoes the ENTIRE C-B latch — every latched
    ///      wallet gets a fresh cap on every sync tick, restoring the unbounded daily repetition
    ///      the latch exists to stop. MEASURED at the real deploy constants
    ///      (deposit 0.05, ceiling/dailyCap 0.001, globalDailyBudget 0.01, maxSponsoredOpCost
    ///      0.0007, 1 gwei; standard 550,000-gas profile => 0.00055 BNB prefund per op — same
    ///      derivation as the header's worst-case-loss block): re-sponsoring after every bundle got ONE wallet
    ///      **162 ops in ONE UTC day across 2 bundles** (90 then 72 — each bundle bounded by
    ///      `floor(remaining deposit / 0.00055)`), draining 0.018606486 BNB = 37.2% of the deposit
    ///      = 186% of `globalDailyBudget`. The THIRD bundle was finally rejected with AA32 by
    ///      `globalSpentToday`, which this function deliberately does NOT reset — i.e.
    ///      `globalDailyBudget`, not the latch, is the only thing that bounds this loop. That is
    ///      ~1.8x the per-wallet daily exposure before the counter reset (0.018606486 / 0.010344741,
    ///      the single-bundle figure in the header): the reset knowingly traded that increase for same-day
    ///      recovery — a decided tradeoff (see above), NOT a regression to undo. The latch's
    ///      remaining value depends on off-chain discipline (re-sponsor only after investigating a
    ///      {SponsorshipRevoked}) that this contract cannot enforce. Pinned by
    ///      test/VerifyingPaymaster.spendcap.test.ts "a blind setSponsored re-sponsor
    ///      loop is bounded only by globalSpentToday, and overshoots globalDailyBudget".
    ///
    ///      INCIDENT-RESPONSE GAP (recorded, not automated — see the contract header's
    ///      "This gate RIDES ON an unverified `sender`" paragraph for the abuse this closes): disabling a
    ///      compromised wallet's sponsorship with `setSponsored(wallet, false)` ALSO strands the
    ///      LEGITIMATE owner — their own recovery path, `addOwnerAddress`/`addOwnerPublicKey`, is
    ///      exactly what stops being free the instant sponsorship is turned off. There is no
    ///      on-chain way to tell "the compromised key is trying to add another attacker owner"
    ///      apart from "the legitimate owner is trying to add a fresh backup owner" — both are the
    ///      identical sponsored selector on the identical wallet. The response procedure this
    ///      implies, not written down anywhere else: (1) `setSponsored(wallet, false)` immediately
    ///      on suspected compromise; (2) verify the real owner OUT OF BAND (a support/KYC channel
    ///      already used by this business — NEVER an on-chain signal, since a compromised key can
    ///      produce on-chain signals too); (3) briefly `setSponsored(wallet, true)` so the
    ///      verified real owner can submit their own recovery/removal userOp gas-free; (4)
    ///      `setSponsored(wallet, false)` again once that op lands, closing the window. Step (3)
    ///      necessarily also re-arms the attacker's own sponsorship for as long as it stays open —
    ///      this sequence only works if step (2) genuinely excludes the attacker before step (3)
    ///      runs.
    function setSponsored(address wallet, bool on) external onlyPolicyManager {
        if (wallet == address(0)) revert ZeroAddress();
        WalletPolicy storage p = walletPolicy[wallet];
        p.sponsored = on;
        if (on) {
            p.spentToday = 0;
            p.lastSpentDay = 0;
        }
        emit SponsoredSet(wallet, on);
    }

    /// @dev `cap` must be in `1..globalDailyCapCeiling` — `0` is "not provisioned".
    function setDailyCap(address wallet, uint128 cap) external onlyPolicyManager {
        if (wallet == address(0)) revert ZeroAddress();
        if (cap == 0) revert ZeroCapNotAllowed();
        if (cap > globalDailyCapCeiling) revert CapExceedsCeiling();
        walletPolicy[wallet].dailyCap = cap;
        emit DailyCapSet(wallet, cap);
    }

    /// @dev GRANTING (`on == true`) is now `owner()`-only (cold). Before this fix the
    ///      whole function was `onlyPolicyManager` (hot), and `sponsorPersonal == true`
    ///      short-circuits {_validatePaymasterUserOp}'s
    ///      `if (!p.sponsorPersonal && !_extractBusinessOk(...))` check — so the HOT key alone
    ///      could void BOTH cold-key allowlists (`businessAllowlist`, `targetSelectorAllowlist`)
    ///      for any wallet. {setTargetSelector}'s NatSpec above states the invariant this restores:
    ///      "this is the fine-grained half of the same business gate, so it must not be reachable
    ///      from the hot policyManager key." Mirrors {setSponsoredUnlimited}'s asymmetry ("Revoking
    ///      VIP is unconditional — the guard must never be able to trap a wallet in VIP status")
    ///      and {pause}'s shape: a kill direction must never require the slow key, so REVOKING
    ///      (`on == false`) stays reachable by owner OR policyManager.
    ///      The deploy script contains ZERO `setSponsorPersonal` calls, so this restriction has no
    ///      operational cost today. Measured on-chain against the live opBNB testnet deployment:
    ///      `owner() == policyManager()`, one EOA — the hot/cold split this restores is
    ///      currently notional in production, which strengthens the case for enforcing it in code
    ///      rather than by convention.
    function setSponsorPersonal(address wallet, bool on) external {
        if (wallet == address(0)) revert ZeroAddress();
        if (on) {
            if (msg.sender != owner()) revert OwnableUnauthorizedAccount(msg.sender);
        } else if (msg.sender != owner() && msg.sender != policyManager) {
            revert NotOwnerOrPolicyManager();
        }
        walletPolicy[wallet].sponsorPersonal = on;
        emit SponsorPersonalSet(wallet, on);
    }

    /// @dev Batch form of {setSponsored} — including its counter reset, so the two paths
    ///      cannot diverge (a backend re-sponsoring in batches must get the same same-day recovery,
    ///      and the same operational warning applies verbatim). See {setSponsored}'s NatSpec.
    function setSponsoredBatch(address[] calldata wallets, bool on) external onlyPolicyManager {
        uint256 len = wallets.length;
        for (uint256 i = 0; i < len; ) {
            address wallet = wallets[i];
            if (wallet == address(0)) revert ZeroAddress();
            WalletPolicy storage p = walletPolicy[wallet];
            p.sponsored = on;
            if (on) {
                p.spentToday = 0;
                p.lastSpentDay = 0;
            }
            emit SponsoredSet(wallet, on);
            unchecked {
                ++i;
            }
        }
    }

    /// @notice Kill-switch: owner OR policyManager can stop the bleeding immediately.
    ///         Only the owner can {unpause}.
    function pause() external {
        if (msg.sender != owner() && msg.sender != policyManager) revert NotOwnerOrPolicyManager();
        paused = true;
        emit Paused(msg.sender);
    }

    // ============ Views ============
    function getPolicy(address wallet) external view returns (WalletPolicy memory) {
        return walletPolicy[wallet];
    }

    /// @dev Off-chain convenience: MAY use block.timestamp since this is a plain view call,
    ///      never invoked by the EntryPoint during validation.
    function effectiveSpentToday(address wallet) external view returns (uint128) {
        WalletPolicy storage p = walletPolicy[wallet];
        uint32 today = uint32(block.timestamp / 1 days);
        return p.lastSpentDay == today ? p.spentToday : 0;
    }

    // ============ Paymaster Logic ============
    /**
     * @dev Timestamp-free sponsorship decision. Two outcomes:
     *      HARD_DECLINE (sigFail=true, clock-independent policy/config "no") or SPONSOR
     *      (sigFail=false, non-empty context so `_postOp` always accrues, `validAfter` may be
     *      future to defer a time-dependent cap/budget decision to the EntryPoint's clock).
     *      MUST NOT read block.timestamp/block.number and MUST NOT write storage (ERC-7562).
     */
    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /*userOpHash*/,
        uint256 maxCost
    ) internal view override returns (bytes memory context, uint256 validationData) {
        if (paused) {
            return ("", _packValidationData(true, 0, 0));
        }

        uint128 postOpGas = uint128(
            bytes16(userOp.paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET:PAYMASTER_DATA_OFFSET])
        );
        if (postOpGas < MIN_POSTOP_GAS) {
            return ("", _packValidationData(true, 0, 0));
        }

        // per-op cap: bounds how much of the deposit a single op can reserve,
        // independent of the (soft) per-wallet/global breakers checked below. FAILS
        // CLOSED at 0 — `maxCost > 0` still declines a non-zero-cost op; only an op declaring
        // `maxCost == 0` is admitted at cap 0 (see {maxSponsoredOpCost}'s NatSpec).
        if (maxCost > maxSponsoredOpCost) {
            return ("", _packValidationData(true, 0, 0));
        }

        // per-op gas-parameter caps: a config-only "no", checked BEFORE the policy
        // lookup below, not a policy decision. Bounds what the userOp's (attacker-chosen)
        // `beneficiary` can be compensated for, independent of `maxCost` — `maxCost` is itself
        // derived from these same attacker-declared fields, so capping only `maxCost` (via
        // maxSponsoredOpCost/dailyCap/globalDailyBudget above) does not stop this class of abuse.
        // FAILS CLOSED at 0 — both comparisons below now run unconditionally, so
        // `maxFeePerGas`/`maxPriorityFeePerGas` > 0 still declines at cap 0; only a userOp
        // declaring `maxFeePerGas == maxPriorityFeePerGas == 0` is admitted (see {maxSponsoredOpCost}'s NatSpec).
        if (userOp.unpackMaxFeePerGas() > uint256(maxSponsoredFeePerGas)) {
            return ("", _packValidationData(true, 0, 0));
        }
        // Defense-in-depth, NOT an independent bound: the EntryPoint's compensated rate is
        // min(maxFeePerGas, maxPriorityFeePerGas + block.basefee) (UserOperationLib.gasPrice),
        // and `_getRequiredPrefund` multiplies by `maxFeePerGas` alone (EntryPoint.sol) — so a
        // higher `maxPriorityFeePerGas` can only ever LOWER the effective paid rate toward
        // `maxFeePerGas`, never raise it past it. Once `maxFeePerGas` is capped above, this
        // check bounds nothing further on its own; kept so a future EntryPoint/fork that
        // changes that formula doesn't silently reopen the drain.
        if (userOp.unpackMaxPriorityFeePerGas() > uint256(maxSponsoredFeePerGas)) {
            return ("", _packValidationData(true, 0, 0));
        }
        // FAILS CLOSED at 0 — `preVerificationGas > 0` still declines; only a userOp
        // declaring `preVerificationGas == 0` is admitted at cap 0 (see {maxSponsoredOpCost}'s NatSpec).
        if (userOp.preVerificationGas > uint256(maxSponsoredPreVerificationGas)) {
            return ("", _packValidationData(true, 0, 0));
        }

        address sender = userOp.sender;
        WalletPolicy memory p = walletPolicy[sender];

        if (!p.sponsored) {
            return ("", _packValidationData(true, 0, 0));
        }
        // `sponsorPersonal` is a deliberate per-wallet escape hatch: it bypasses BOTH halves of the
        // business gate (target AND selector), so such a wallet is bounded only by its `dailyCap`,
        // `maxSponsoredOpCost` and the global budget — never by the selector policy.
        if (!p.sponsorPersonal && !_extractBusinessOk(userOp.callData, sender)) {
            return ("", _packValidationData(true, 0, 0));
        }
        if (globalDailyBudget == 0) {
            return ("", _packValidationData(true, 0, 0));
        }
        if (!p.vip && p.dailyCap == 0) {
            return ("", _packValidationData(true, 0, 0));
        }

        // --- time-dependent caps: RAW check vs stored counters, NO block.timestamp ---
        uint48 validAfter = 0;

        // per-wallet cap (skipped for VIP; VIP still hits the global check below).
        //
        // A same-day-exceeded op must be DECLINED, not deferred, whenever `maxCost`
        // ALONE already exceeds the cap — no day rollover can ever rescue it. The deferral below
        // (`validAfter = (lastSpentDay + 1) * 1 days`) is computed from the STORED day index, so on
        // a stale counter (a brand-new wallet, where `lastSpentDay == 0`, or any wallet on the
        // first op of a new UTC day) that timestamp is already in the past — the EntryPoint would
        // then treat the op as immediately valid instead of rejecting it (EntryPoint.sol:
        // `outOfTimeRange = block.timestamp > validUntil || block.timestamp <= validAfter`),
        // silently uncapping `maxCost`. Hard-declining the maxCost-alone-exceeds-cap case removes
        // that opening while leaving the genuine "spentToday + maxCost > cap, but maxCost <= cap"
        // rollover case (a real day boundary) to defer exactly as before.
        //
        // `effectiveDailyCap` clamps the wallet's stored `dailyCap` to the CURRENT
        // `globalDailyCapCeiling`: `setDailyCap` only enforces `cap <= ceiling` at set-time, so if
        // the owner later LOWERS the ceiling, an already-provisioned wallet's stored `dailyCap`
        // survives above the new ceiling (on-chain enumeration to reclamp every wallet is not
        // possible — see {setGlobalDailyCapCeiling}). Re-deriving the effective cap at use-time,
        // every validation, closes that gap without needing to touch per-wallet storage.
        if (!p.vip) {
            uint128 effectiveDailyCap = p.dailyCap < globalDailyCapCeiling ? p.dailyCap : globalDailyCapCeiling;

            if (maxCost > uint256(effectiveDailyCap)) {
                return ("", _packValidationData(true, 0, 0));
            }
            if (uint256(p.spentToday) + maxCost > uint256(effectiveDailyCap)) {
                uint48 candidate = uint48((uint256(p.lastSpentDay) + 1) * 1 days);
                if (candidate > validAfter) validAfter = candidate;
            }
        }

        // same reasoning as the per-wallet cap above: maxCost alone exceeding the global
        // budget can never be rescued by a day rollover either.
        if (maxCost > uint256(globalDailyBudget)) {
            return ("", _packValidationData(true, 0, 0));
        }

        // global budget applies to ALL sponsored ops, INCLUDING VIP
        if (uint256(globalSpentToday) + maxCost > uint256(globalDailyBudget)) {
            uint48 candidate = uint48((uint256(globalLastSpentDay) + 1) * 1 days);
            if (candidate > validAfter) validAfter = candidate;
        }

        context = abi.encode(sender); // non-empty ALWAYS => postOp accrues (incl. VIP)
        return (context, _packValidationData(false, 0, validAfter));
    }

    /**
     * @dev Day rollover + accrual (execution phase; block.timestamp allowed here). Runs for both
     *      `opSucceeded` and `opReverted` (both pay gas — see IPaymaster.PostOpMode). No external
     *      calls => no reentrancy guard needed.
     *
     *      Audit C-B (bundle-aggregation): `_validatePaymasterUserOp` can only see PRE-BUNDLE
     *      storage (ERC-7562 forbids writing storage during validation — see the contract
     *      header's SECURITY note), so N ops for the SAME wallet inside ONE `handleOps` bundle all
     *      pass the per-wallet cap check against the identical, stale `spentToday`. That gap
     *      cannot be closed here — by the time `_postOp` runs for op i, ops i+1..N in the SAME
     *      bundle have ALREADY been admitted by validation (verified directly against
     *      the vendored account-abstraction v0.8 core/EntryPoint.sol:58-76: `handleOps`
     *      runs `_iterateValidationPhase` for the WHOLE batch, THEN a separate loop executes every
     *      op) — so this function cannot prevent a single over-cap bundle from fully executing.
     *      What it CAN do, because THIS phase has no storage-write restriction: once cumulative
     *      `spentToday` for the day has crossed the wallet's EFFECTIVE cap, auto-unsponsor the
     *      wallet so its NEXT op — starting with its next bundle — hard-declines immediately at the
     *      `if (!p.sponsored)` check in `_validatePaymasterUserOp`, before any cap arithmetic runs.
     *      This turns "drain this wallet's cap every single day, forever" into "drain it once, and
     *      it goes dark until policyManager calls {setSponsored} again" — there is no automatic
     *      recovery (not on day rollover, not on any timer): reactivation is an explicit hot-key
     *      decision, which is the actual bound this latch provides. Re-sponsoring also CLEARS the
     *      wallet's spend record so recovery takes effect the SAME day — see {setSponsored}, which
     *      documents both why that is required and the hot-key tradeoff it introduces.
     *
     *      The threshold is `min(dailyCap, globalDailyCapCeiling)` — the SAME
     *      `effectiveDailyCap` {_validatePaymasterUserOp} enforces, not the raw stored `dailyCap`.
     *      Comparing against the raw value made the latch LOOSEST exactly when an operator TIGHTENS
     *      the ceiling in response to an incident: with a stored cap of 0.001 and the ceiling
     *      lowered to 0.0007, the latch tolerated `spentToday` up to 1.47x the cap validation was
     *      actually enforcing (measured), and a 10x ceiling cut bought a 10x tolerance. Slot 3
     *      (`globalDailyCapCeiling`) is already warm from validation, so this costs ~100 gas.
     *      Pinned by test/VerifyingPaymaster.spendcap.test.ts
     *      "the latch threshold follows a LOWERED globalDailyCapCeiling ...".
     *
     *      {SponsorshipRevoked}'s `spentToday` is a LOWER BOUND on the incident, not its size: it
     *      is emitted at the CROSSING op, while the rest of the bundle (already admitted by the
     *      validation phase) keeps executing and accruing afterwards. Measured: emitted 0.001035
     *      against a bundle that finished at 0.004955 — an operator alerting on
     *      "event value vs dailyCap" would read a 395% incident as a 3% overage. The authoritative
     *      figure is `getPolicy(wallet).spentToday` after the transaction, or the sum of
     *      {GasSponsored}`.actualGasCost` over the same transaction. Pinned by
     *      "SponsorshipRevoked args ..." in the same test file.
     *
     *      `postOpReverted` — why this function must never revert. The EntryPoint wraps `postOp` in
     *      a try/catch (account-abstraction v0.8 core/EntryPoint.sol:849-856); on revert it
     *      re-enters `_postExecution` with `mode = postOpReverted`, which SKIPS the paymaster's
     *      `postOp` entirely (:848) while still charging `actualGasCost = prefund` in FULL
     *      (:868-871). A reverting `_postOp` would therefore mean maximum charge with NO accounting
     *      and NO latch — repeatable indefinitely, since `spentToday` would never move. The current
     *      body cannot revert (no external calls; the only arithmetic is a `uint128` accumulation
     *      of an `actualGasCost` bounded by `maxCost <= maxSponsoredOpCost`, itself a `uint128`).
     *      RE-DERIVED after item 1: this bound is TRUE and now UNCONDITIONAL — the
     *      per-op check in {_validatePaymasterUserOp} (`if (maxCost > maxSponsoredOpCost) return
     *      decline`) no longer carries the `maxSponsoredOpCost != 0 &&` conjunct that was removed, so
     *      EVERY admitted op satisfies `maxCost <= maxSponsoredOpCost` regardless of the cap's
     *      value, including at cap 0 (where only `maxCost == 0` is admitted — see
     *      {maxSponsoredOpCost}'s NatSpec). BEFORE
     *      item 1, `maxSponsoredOpCost == 0` meant "unlimited" and disabled that check entirely,
     *      which made this exact conclusion true only by coincidence, not by
     *      construction — the reasoning as originally written was false even though the
     *      conclusion happened to hold at HEAD. It is no longer a coincidence: the bound is
     *      structural. IF YOU EVER RESTORE A `!= 0` GUARD ON THAT CHECK, THIS PROPERTY DIES WITH
     *      IT — an admitted op could then carry an unbounded `actualGasCost`, `uint128` truncation
     *      stops being a no-op, and the whole latch this function implements rests on the bound
     *      staying true — so any future edit here, or to that check, MUST preserve it.
     *
     *      VIP wallets are NOT exempt from this latch, even though `_validatePaymasterUserOp`
     *      skips the PER-OP dailyCap check for VIP (`if (!p.vip) { ... }`). Those are deliberately
     *      different controls: the per-op check bounds a SINGLE op's `maxCost`; this latch bounds
     *      CUMULATIVE daily spend. Exempting VIP here would make VIP an unconditional, permanent
     *      bypass of the entire spend-latch system — the one thing standing between a compromised
     *      VIP wallet and unlimited repeated daily drain. A VIP wallet that genuinely needs
     *      unlimited-per-op, unbounded-per-day spend is not expressible in this model and must be
     *      handled operationally (e.g. a very high `dailyCap`). Because the threshold is the
     *      EFFECTIVE cap, a VIP is also latched after its first op whenever
     *      `globalDailyCapCeiling == 0` — the ceiling kill-switch does not stop a VIP's first op
     *      (VIP skips the per-op check at validation) but it does now latch the wallet immediately
     *      afterwards, which is the intended direction for a kill-switch. `dailyCap == 0` on a VIP
     *      is no longer reachable through the setters at all: {setSponsoredUnlimited} refuses to
     *      grant VIP without a provisioned cap and {setDailyCap} refuses to set 0.
     *
     *      DOCUMENTATION ONLY — this function's `actualGasCost` argument, and
     *      therefore every counter it accrues (`spentToday`, `globalSpentToday`), SYSTEMATICALLY
     *      UNDER-COUNTS the real EntryPoint deposit drain for the op. `actualGasCost` is computed
     *      BEFORE this call (EntryPoint.sol:846: `actualGasCost = actualGas * gasPrice`) — i.e.
     *      before `postOp`'s OWN gas, the unused-postOp-gas penalty, and `_postExecution`'s remaining
     *      overhead are added at :864-865 (`actualGas += preGas - gasleft() + postOpUnusedGasPenalty;
     *      actualGasCost = actualGas * gasPrice;`) to produce the FINAL amount actually deducted from
     *      the deposit. Measured at the worst-case profile above: a single op's real deposit
     *      drain is 235,971 gas while THIS function is called with `actualGasCost` = 182,061 gas — a
     *      22.8% under-count, i.e. `globalDailyBudget` and every wallet's `dailyCap` are effectively
     *      about 1.30x LOOSER than configured. This is a DIFFERENT, SMALLER-magnitude effect at the
     *      "standard" 550k profile the rest of this test suite uses (real drain 103.45% of budget vs
     *      `globalSpentToday` recording 88.33% for the same bundle — see the blind re-sponsor
     *      loop test). Re-derive the exact factor from your own profile; do not carry either number
     *      forward. This is NOT fixed here (accounting logic is unchanged) — it is recorded so an
     *      operator sizing `globalDailyBudget`/`dailyCap` from these counters knows they read LOW.
     */
    function _postOp(
        IPaymaster.PostOpMode /*mode*/,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 /*actualUserOpFeePerGas*/
    ) internal override {
        address sender = abi.decode(context, (address));
        uint32 today = uint32(block.timestamp / 1 days);

        WalletPolicy memory p = walletPolicy[sender];
        if (p.lastSpentDay != today) {
            p.spentToday = 0;
            p.lastSpentDay = today;
        }
        p.spentToday += uint128(actualGasCost);

        // Threshold is the SAME `effectiveDailyCap` validation enforces
        // (`min(dailyCap, globalDailyCapCeiling)`), not the raw stored `dailyCap` — otherwise
        // lowering the ceiling loosens the latch by exactly the factor it tightens validation by.
        // Slot 3 is already warm from `_validatePaymasterUserOp` in the same tx.
        uint128 latchCap = p.dailyCap < globalDailyCapCeiling ? p.dailyCap : globalDailyCapCeiling;
        if (p.sponsored && p.spentToday > latchCap) {
            p.sponsored = false;
            emit SponsorshipRevoked(sender, p.spentToday, latchCap);
        }

        walletPolicy[sender] = p;

        if (globalLastSpentDay != today) {
            globalSpentToday = 0;
            globalLastSpentDay = today;
        }
        globalSpentToday += uint128(actualGasCost);

        emit GasSponsored(sender, actualGasCost, p.spentToday, globalSpentToday);
    }

    /**
     * @dev Defensive decode of the wallet's exec surface (never revert; malformed => false).
     *      Returns true iff the op is a recognizable business call in which EVERY inner call is
     *      EITHER a self-call (`target == sender`) whose selector is in
     *      {selfSelectorAllowlist}, OR an allowlisted (target, inner selector) PAIR —
     *      `businessAllowlist[target]` AND `targetSelectorAllowlist[target][innerSelector]`
     *     . Self and business are a REPLACEMENT, never a union — see the contract
     *      header's "SELF-CALL GATE" note. Every calldata slice is bounds-checked BEFORE slicing —
     *      an out-of-range Solidity slice reverts, which in validation would be a hard AA33; we
     *      must avoid that. Reads only self storage + calldata (`sender` is the already-extracted,
     *      trusted `userOp.sender` the caller passes in — never re-derived from calldata).
     *
     *      An inner `func` shorter than 4 bytes carries NO selector (a bare value transfer, or a
     *      truncated call) and is fail-closed to `false` — neither path ever sponsors it. Such an
     *      op is still submittable self-paid, or via a `sponsorPersonal` wallet.
     *
     *      `isSelf` is recomputed PER ELEMENT inside the {executeBatch} loop below, never hoisted
     *      out of it — hoisting would let a business-only second element with a self-allowlisted
     *      selector slip through unsponsored-check on an arbitrary foreign target (see the header
     *      note; pinned by test/VerifyingPaymaster.test.ts T4.4/M4d).
     * @param sender The userOp's sender (`userOp.sender`), passed from the single call site in
     *        {_validatePaymasterUserOp} — defines which `target` value, if any, counts as "self".
     */
    function _extractBusinessOk(bytes calldata callData, address sender) internal view returns (bool) {
        if (callData.length < 4) return false;
        bytes4 sel = bytes4(callData[0:4]);

        if (sel == StarzipWallet.execute.selector) {
            // execute(address dest, uint256 value, bytes func)
            // head = sel(4) + 3 words(96) => min length 100 before following the `func` offset
            if (callData.length < 100) return false;
            address target = address(uint160(uint256(bytes32(callData[4:36]))));
            bool isSelf = target == sender;
            if (!isSelf && !businessAllowlist[target]) return false;

            uint256 offFunc = uint256(bytes32(callData[68:100])); // relative to callData[4]
            if (offFunc > callData.length - 36) return false; // room for a length word
            uint256 lenPos = 4 + offFunc; // no overflow: offFunc bounded above
            if (lenPos + 32 > callData.length) return false; // redundant but kept explicit
            uint256 funcLen = uint256(bytes32(callData[lenPos:lenPos + 32]));
            uint256 dataPos = lenPos + 32; // <= callData.length by the bound above
            if (funcLen < 4 || funcLen > callData.length - dataPos) return false;
            bytes4 innerSel = bytes4(callData[dataPos:dataPos + 4]);
            return isSelf ? selfSelectorAllowlist[innerSel] : targetSelectorAllowlist[target][innerSel];
        }

        if (sel == StarzipWallet.executeBatch.selector) {
            // executeBatch(address[] dest, uint256[] values, bytes[] funcs)
            // head = sel(4) + 3 offset words(96) => min length 100 before following any offset
            if (callData.length < 100) return false;
            uint256 offDest = uint256(bytes32(callData[4:36])); // offset relative to callData[4]
            if (offDest > callData.length - 36) return false; // room for a length word
            uint256 lenPos = 4 + offDest; // no overflow: offDest bounded above
            if (lenPos + 32 > callData.length) return false;
            uint256 n = uint256(bytes32(callData[lenPos:lenPos + 32]));
            if (n == 0 || n > MAX_BATCH_SIZE) return false; // also caps loop + arithmetic
            uint256 dataStart = lenPos + 32;
            if (dataStart + n * 32 > callData.length) return false; // n<=32 => no overflow

            // `funcs` array: length must match `dest`, and each element supplies the selector
            // paired with the dest at the same index.
            uint256 offFuncs = uint256(bytes32(callData[68:100]));
            if (offFuncs > callData.length - 36) return false;
            uint256 funcsLenPos = 4 + offFuncs;
            if (funcsLenPos + 32 > callData.length) return false;
            if (uint256(bytes32(callData[funcsLenPos:funcsLenPos + 32])) != n) return false;
            uint256 funcsHead = funcsLenPos + 32; // element offsets are relative to this
            if (funcsHead + n * 32 > callData.length) return false; // n>=1 => funcsHead+32 <= len

            for (uint256 i = 0; i < n; ) {
                uint256 w = i * 32; // n<=32 => no overflow
                address target = address(uint160(uint256(bytes32(callData[dataStart + w:dataStart + w + 32]))));
                // Recomputed EVERY iteration — never hoisted. See {_extractBusinessOk}'s own
                // NatSpec and the contract header's "SELF-CALL GATE" note for why a hoisted
                // `isSelf` would reopen that shape on a batch mixing a self element with a
                // foreign, non-allowlisted one sharing the same self-allowlisted selector.
                bool isSelf = target == sender;
                if (!isSelf && !businessAllowlist[target]) return false;

                uint256 elOff = uint256(bytes32(callData[funcsHead + w:funcsHead + w + 32]));
                if (elOff > callData.length - funcsHead - 32) return false; // room for a length word
                uint256 elLenPos = funcsHead + elOff;
                if (elLenPos + 32 > callData.length) return false;
                uint256 elLen = uint256(bytes32(callData[elLenPos:elLenPos + 32]));
                uint256 elDataPos = elLenPos + 32; // <= callData.length by the bound above
                if (elLen < 4 || elLen > callData.length - elDataPos) return false;
                bytes4 innerSel = bytes4(callData[elDataPos:elDataPos + 4]);
                bool elementOk = isSelf ? selfSelectorAllowlist[innerSel] : targetSelectorAllowlist[target][innerSel];
                if (!elementOk) return false;
                unchecked {
                    ++i;
                }
            }
            return true;
        }

        return false; // unknown selector => not a business call
    }
}
