// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/**
 * @title IPaymasterSelectorPolicy
 * @notice Interface for a paymaster-side sponsorship allowlist keyed on
 *         (target contract, function selector) instead of target alone.
 * @dev WHY THIS EXISTS:
 *
 *      `VerifyingPaymaster._extractBusinessOk` (contracts/wallet/VerifyingPaymaster.sol:370-404)
 *      currently allowlists by TARGET ONLY (`businessAllowlist[target]`, see
 *      VerifyingPaymaster.sol:301,377,391) — once a target such as the TradeSettlementV1
 *      proxy is allowlisted, EVERY function selector on it is sponsored identically.
 *      `cancelOrder` is an unbounded cold-SSTORE primitive that costs the same allowlisted
 *      target as `settleOrders`; a handful of sponsored wallets can exhaust the paymaster's
 *      daily gas budget by spamming the cheapest sponsored call instead of submitting real
 *      trades. Selector-granular sponsorship (this interface) lets the paymaster sponsor
 *      `settleOrders` while declining to sponsor `cancelOrder`, or price/cap them
 *      independently, without giving up target-level allowlisting entirely.
 *
 *      ERC-4337 VALIDATION-PHASE CONSTRAINT (binding on any implementation of this
 *      interface used from `validatePaymasterUserOp`):
 *      - The validation phase may only read the paymaster's OWN storage and the
 *        UserOperation's `calldata` — no external calls, no reads of other contracts'
 *        storage (ERC-4337 storage access rules).
 *      - Every calldata slice MUST be bounds-checked BEFORE slicing. An out-of-range
 *        Solidity calldata slice (e.g. `callData[a:b]` with `b > callData.length`) reverts,
 *        and a revert during validation is a hard AA33 — the bundler drops the
 *        UserOperation with no error surfaced to the user, rather than simply declining
 *        to sponsor it. Any selector/target extraction MUST fail closed (return false /
 *        not-sponsored) on malformed or short calldata instead of reverting. This mirrors
 *        the existing defensive-decode discipline in
 *        `VerifyingPaymaster._extractBusinessOk` (VerifyingPaymaster.sol:370-404), which
 *        bounds-checks every slice before taking it and never reverts on malformed input.
 *
 *      IMPLEMENTED BY: `contracts/wallet/VerifyingPaymaster.sol`. Its `_extractBusinessOk` now
 *      requires BOTH `businessAllowlist[target]` AND `targetSelectorAllowlist[target][sel]`
 *      for every inner call (`execute` and each `executeBatch` element), so target-only
 *      allowlisting no longer sponsors an entire contract surface. Note that a wallet with
 *      `sponsorPersonal = true` bypasses both lists by design.
 */
interface IPaymasterSelectorPolicy {
    /**
     * @notice Whether `selector` on `target` is currently sponsored.
     * @param target Contract address a UserOperation calls into (e.g. the TradeSettlementV1 proxy).
     * @param selector 4-byte function selector being invoked on `target`.
     */
    function targetSelectorAllowlist(address target, bytes4 selector) external view returns (bool);

    /**
     * @notice Allowlist or de-list a single (target, selector) pair.
     * @param target Contract address.
     * @param selector 4-byte function selector on `target`.
     * @param allowed True to sponsor calls matching this pair, false to stop sponsoring them.
     */
    function setTargetSelector(address target, bytes4 selector, bool allowed) external;

    /**
     * @notice Batch-set the allowlist status of multiple selectors on a single target.
     * @param target Contract address.
     * @param selectors 4-byte function selectors on `target`.
     * @param allowed True to sponsor all listed selectors, false to stop sponsoring them.
     */
    function setTargetSelectors(address target, bytes4[] calldata selectors, bool allowed) external;

    /// @notice Emitted when a single (target, selector) allowlist entry changes.
    event TargetSelectorUpdated(address indexed target, bytes4 indexed selector, bool allowed);

    /// @notice Emitted once per batch update via `setTargetSelectors`.
    event TargetSelectorsBatchUpdated(address indexed target, uint256 count, bool allowed);
}
