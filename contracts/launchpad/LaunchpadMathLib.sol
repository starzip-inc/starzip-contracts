// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title LaunchpadMathLib
 * @notice Vesting, softcap-target, and raised-funds-split math extracted out of `LaunchpadV1`
 *         purely to reclaim EIP-170 deployed-bytecode headroom on that contract.
 * @dev Every function here is `external` (or `private`, called only from another `external`
 *      function in this same library) — DELIBERATELY, not `internal`. A Solidity `internal`
 *      library function is inlined into every caller's own bytecode and reclaims nothing; only
 *      `external`/`public` library functions get deployed once, in the library's own bytecode, and
 *      reached via DELEGATECALL — that is the only shape that actually shrinks `LaunchpadV1`.
 *
 *      All parameters are plain value types (never `storage` pointers): `external` library
 *      functions are called across a real message boundary, and Solidity does not allow a storage
 *      reference to cross one — only `internal`/`private` functions may accept `storage` params.
 *      `LaunchpadV1` therefore copies the relevant storage into memory/locals before calling in,
 *      and `block.timestamp` is passed explicitly as `nowTs` so every function here can be `pure`
 *      (and unit-testable without a chain).
 *
 *      ADMIN-CONFIGURABLE VESTING SCHEDULE (this change): the former fixed-8-period,
 *      duration/interval-ratio-gated design (`claimableVesting` + `_claimableVestingLinear` +
 *      `claimableTokensVested` + `_unlockedBpThroughMem`, each with its own near-duplicate
 *      period-walking logic) is replaced by ONE mechanism — {claimableAmount} — shared by both the
 *      business (USDT) and participant (token) vesting paths in `LaunchpadV1`. A schedule is now
 *      "a variable-length per-period bp array (`bps`, length == period count, sum ==
 *      `BASIS_POINTS`), a `vestingInterval`, and a `firstPeriodAtZero` flag": with
 *      `firstPeriodAtZero == false` (the business default's legacy shape) `bps[0]` unlocks after
 *      one full `vestingInterval` past vesting start; with `firstPeriodAtZero == true`
 *      (participant default / T+0 configurations) `bps[0]` unlocks immediately AT vesting start.
 *      There is no more "non-uniform schedule vs. equal-period linear fallback" split — a schedule
 *      is always a concrete bp array now (never all-zero: every launchpad gets one from
 *      `LaunchpadV1`'s create-time snapshot or, for an unconfigured participant, a fixed one-period
 *      100%-at-T+0 array built in memory — see `LaunchpadV1._calculateClaimableTokens`), so the
 *      dual-path branching this library used to need is gone.
 *
 *      The claim path and `LaunchpadV1.getVestingScheduleInfo` share one bp-summing helper so
 *      they can never disagree. That invariant holds here in a stronger form: {claimableAmount} and
 *      {vestingScheduleInfo} both resolve through the same `private` {_unlockedPeriods}/{_sumBps}
 *      helpers — literally the same deployed bytecode, not just the same source function.
 */
library LaunchpadMathLib {
    uint256 private constant BASIS_POINTS = 10000;

    /**
     * @dev Number of periods unlocked given `elapsed` time since vesting start (i.e. since
     *      `startTime + lockupDuration`). `firstPeriodAtZero == true` means period 0 unlocks at
     *      `elapsed == 0` (T+0); `false` means it unlocks only once a full `vestingInterval` has
     *      elapsed (the legacy business-schedule shape). Always capped to `periodCount`.
     */
    function _unlockedPeriods(
        uint256 elapsed,
        uint256 vestingInterval,
        bool firstPeriodAtZero,
        uint256 periodCount
    ) private pure returns (uint256) {
        if (vestingInterval == 0 || periodCount == 0) return 0;

        uint256 periodsElapsed = elapsed / vestingInterval;
        uint256 unlocked = firstPeriodAtZero ? periodsElapsed + 1 : periodsElapsed;

        return unlocked > periodCount ? periodCount : unlocked;
    }

    /// @dev Sum of the first `count` entries of `bps` (`count` is always the caller's own
    ///      `_unlockedPeriods` result, so it never exceeds `bps.length`).
    function _sumBps(uint256[] memory bps, uint256 count) private pure returns (uint256 total) {
        for (uint256 i = 0; i < count; ) {
            total += bps[i];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Claimable amount under a `bps`/`vestingInterval`/`firstPeriodAtZero` schedule.
     *         Shared by `LaunchpadV1._calculateClaimableVesting` (business, USDT) and
     *         `_calculateClaimableTokens` (participant, purchased tokens) — one mechanism, two
     *         callers.
     * @dev Mirrors the former `LaunchpadV1._calculateClaimableVesting`'s non-uniform-schedule
     *      branch (now the ONLY branch — see this library's top-level NatSpec).
     */
    function claimableAmount(
        uint256 totalAmount,
        uint256 claimedAmount,
        uint256 startTime,
        uint256 lockupDuration,
        uint256 vestingInterval,
        uint256[] memory bps,
        bool firstPeriodAtZero,
        uint256 nowTs
    ) external pure returns (uint256) {
        if (totalAmount == 0) return 0;
        if (nowTs < startTime + lockupDuration) return 0;

        uint256 elapsed = nowTs - (startTime + lockupDuration);
        uint256 periods = _unlockedPeriods(elapsed, vestingInterval, firstPeriodAtZero, bps.length);
        uint256 unlocked = Math.mulDiv(totalAmount, _sumBps(bps, periods), BASIS_POINTS);

        return unlocked > claimedAmount ? unlocked - claimedAmount : 0;
    }

    /**
     * @notice `(totalPeriods, amountPerPeriod, currentPeriod, totalUnlocked)` view tuple for a
     *         launchpad's business (USDT) vesting.
     * @dev Mirrors former `LaunchpadV1.getVestingScheduleInfo`'s body. Resolves
     *      `totalUnlocked` through the same {_unlockedPeriods}/{_sumBps} {claimableAmount} uses, so
     *      this view and the claim path cannot diverge. `amountPerPeriod` remains an
     *      equal-division-of-total FYI figure (as before), independent of the actual per-period bp
     *      weighting.
     */
    function vestingScheduleInfo(
        uint256 totalAmount,
        uint256 startTime,
        uint256 lockupDuration,
        uint256 vestingInterval,
        uint256[] memory bps,
        bool firstPeriodAtZero,
        uint256 nowTs
    )
        external
        pure
        returns (uint256 totalPeriods, uint256 amountPerPeriod, uint256 currentPeriod, uint256 totalUnlocked)
    {
        totalPeriods = bps.length;
        if (totalAmount == 0 || vestingInterval == 0 || totalPeriods == 0) {
            return (totalPeriods, 0, 0, 0);
        }

        amountPerPeriod = totalAmount / totalPeriods;

        if (nowTs < startTime + lockupDuration) {
            return (totalPeriods, amountPerPeriod, 0, 0);
        }

        uint256 elapsed = nowTs - (startTime + lockupDuration);
        currentPeriod = _unlockedPeriods(elapsed, vestingInterval, firstPeriodAtZero, totalPeriods);
        totalUnlocked = Math.mulDiv(totalAmount, _sumBps(bps, currentPeriod), BASIS_POINTS);
    }

    /**
     * @notice Current unlocked-period count for a launchpad's business (USDT) vesting.
     * @dev Mirrors former `LaunchpadV1.getCurrentVestingPeriod`'s body, generalized to a variable
     *      `periodCount`/`firstPeriodAtZero` instead of the fixed `VESTING_PERIOD_COUNT == 8`.
     */
    function currentVestingPeriod(
        uint256 totalAmount,
        uint256 startTime,
        uint256 lockupDuration,
        uint256 vestingInterval,
        bool firstPeriodAtZero,
        uint256 periodCount,
        uint256 nowTs
    ) external pure returns (uint256) {
        if (totalAmount == 0) return 0;
        if (nowTs < startTime + lockupDuration) return 0;

        uint256 elapsed = nowTs - (startTime + lockupDuration);
        return _unlockedPeriods(elapsed, vestingInterval, firstPeriodAtZero, periodCount);
    }

    // `targetRaiseAmount`/`requiredRaiseAmount`/`resolveFundSplit` (softcap target-raise math
    // and the finalize-time fee/3-way-split math) were tried here and REVERTED — measured
    // empirically, moving those small, few-line, many-parameter call sites out of `LaunchpadV1`
    // INCREASED its deployed size (24,112 -> 24,268 bytes) rather than shrinking it, because
    // `Math.mulDiv` stays embedded in `LaunchpadV1` regardless (still used directly in
    // `participate()`, deliberately never moved) and the ABI-encode/decode overhead of the extra
    // external calls cost more than the few lines of arithmetic they removed. See
    // `LaunchpadV1._targetRaiseAmount`'s own doc comment for the same note at its call site.
}
