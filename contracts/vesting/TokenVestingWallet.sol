// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";

/**
 * @title TokenVestingWallet
 * @notice Per-token Owner Vesting wallet for the StarZip `TokenFactory` / `LaunchpadV1`
 *         Store Token distribution model.
 * @dev BeaconProxy-clone deployed by `TokenFactory` at `issueToken` time.
 *      Vesting is **deferred**: `start` is set to `type(uint64).max` at init
 *      and only flipped by `LaunchpadV1.finalizeLaunchpad` via `startVesting`.
 *
 * Two-role access control:
 *   - `owner()`     = beneficiary (business account). Can call `release()`.
 *   - `launchpad()` = the only address allowed to call `startVesting()`.
 *
 * @dev The wallet's `launchpad` binding is **permanently determined at initialize**.
 *      It cannot be changed post-init. Rotating the linked-launchpad binding requires
 *      the platform admin to call `TokenFactory.proposeLinkedLaunchpadChange`
 *      (2-day timelock) AND issue a new token with a fresh vesting wallet.
 *      This is by design — exposing a setter on the wallet
 *      itself created an Owner Vesting drain vector.
 *
 * @dev OZ v5.5 ships `ReentrancyGuard` as `@custom:stateless` (ERC-7201 namespaced
 *      slot, no constructor-set state collides with proxy storage). The Upgradeable
 *      variant has been removed from OZ v5.5 contracts-upgradeable; the non-
 *      upgradeable `ReentrancyGuard` is the OZ-recommended path for both regular
 *      and upgradeable contracts in v5.5+. See OZ v5.5 release notes — the
 *      stateless namespaced storage layout means no `__init` call is needed.
 *
 * Storage uses ERC-7201 namespaced layout (`starzip.storage.TokenVestingWallet`)
 * for clean Beacon upgrade safety.
 */
contract TokenVestingWallet is Initializable, Ownable2StepUpgradeable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ============ Namespaced Storage (ERC-7201) ============

    /// @custom:storage-location erc7201:starzip.storage.TokenVestingWallet
    struct VWStorage {
        address launchpad; // only address allowed to call startVesting()
        address token; // the ERC20 being vested
        uint64 start; // type(uint64).max until startVesting() flips it
        uint64 duration; // vesting duration in seconds
        uint64 cliff; // cliff in seconds (0 = no cliff)
        bool started; // canonical "vesting started" flag
        uint256 released; // cumulative released to beneficiary
    }

    /**
     * @dev keccak256(abi.encode(uint256(keccak256("starzip.storage.TokenVestingWallet")) - 1))
     *      & ~bytes32(uint256(0xff))
     *      Verified test vector.
     */
    bytes32 private constant VW_LOC = 0x81f4d596baa013a867e83dd1bbbda068edbe5d743871475dd87b898bc68eb000;

    function _v() private pure returns (VWStorage storage $) {
        assembly {
            $.slot := VW_LOC
        }
    }

    // ============ Events ============

    event Started(address indexed launchpad, uint64 startTimestamp, uint64 durationSeconds, uint64 cliffSeconds);
    event Released(address indexed token, address indexed beneficiary, uint256 amount);

    // ============ Errors ============

    error NotLaunchpad();
    error AlreadyStarted();
    error NothingToRelease();
    error ZeroAddress();
    error InvalidDuration();
    error InvalidCliff();

    // ============ Constructor ============

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ============ Initialization ============

    /**
     * @notice Initialize a freshly-deployed BeaconProxy clone.
     * @param beneficiary Owner / beneficiary (business account).
     * @param launchpad_ The launchpad address allowed to call `startVesting`.
     * @param token_ ERC20 being vested.
     * @param duration_ Total vesting duration in seconds.
     * @param cliff_ Cliff window inside the duration in seconds (0 = no cliff).
     */
    function initialize(
        address beneficiary,
        address launchpad_,
        address token_,
        uint64 duration_,
        uint64 cliff_
    ) external initializer {
        if (beneficiary == address(0) || launchpad_ == address(0) || token_ == address(0)) {
            revert ZeroAddress();
        }
        if (duration_ == 0) revert InvalidDuration();
        if (cliff_ > duration_) revert InvalidCliff();

        __Ownable_init(beneficiary);
        // ReentrancyGuard (OZ v5.5) uses ERC-7201 namespaced storage and is
        // marked `@custom:stateless`. No `__init` is required (the upgradeable
        // variant was removed in OZ v5.5).

        VWStorage storage $ = _v();
        $.launchpad = launchpad_;
        $.token = token_;
        $.duration = duration_;
        $.cliff = cliff_;
        $.start = type(uint64).max; // sentinel: not yet started
        // $.started = false (default)
        // $.released = 0 (default)
    }

    // ============ Launchpad-only: trigger vesting ============

    /**
     * @notice Flip the vesting wallet from "deferred" to "started".
     * @dev Only callable once, only by the configured launchpad.
     *      Hard-revert on retry: `ownerVestingTrigger` flag in LaunchpadV1 only
     *      flips after this call succeeds, ensuring idempotency on retry.
     * @param startTimestamp Vesting start time (typically `block.timestamp` at finalize).
     * @param duration_ Effective duration (overrides any factory-staged duration).
     */
    function startVesting(uint64 startTimestamp, uint64 duration_) external {
        VWStorage storage $ = _v();
        if (msg.sender != $.launchpad) revert NotLaunchpad();
        if ($.started) revert AlreadyStarted();
        if (duration_ == 0) revert InvalidDuration();
        if ($.cliff > duration_) revert InvalidCliff();

        $.start = startTimestamp;
        $.duration = duration_;
        $.started = true;

        emit Started($.launchpad, startTimestamp, duration_, $.cliff);
    }

    // ============ Owner-only: release vested tokens ============

    /**
     * @notice Release any currently-vested tokens to the beneficiary.
     * @dev `nonReentrant` defends against reentrant ERC20 callbacks.
     *      `onlyOwner` restricts release to the beneficiary.
     */
    function release() external nonReentrant onlyOwner {
        uint256 amt = releasable();
        if (amt == 0) revert NothingToRelease();

        VWStorage storage $ = _v();
        $.released += amt;
        IERC20($.token).safeTransfer(owner(), amt);

        emit Released($.token, owner(), amt);
    }

    // ============ Views ============

    function releasable() public view returns (uint256) {
        return _vestedAmount(uint64(block.timestamp)) - _v().released;
    }

    function _vestedAmount(uint64 ts) internal view returns (uint256) {
        VWStorage storage $ = _v();
        if (!$.started) return 0;
        if (ts < $.start) return 0;
        if (ts < $.start + $.cliff) return 0;

        // total = current balance + already-released = total ever held by this wallet
        uint256 total = IERC20($.token).balanceOf(address(this)) + $.released;
        if (ts >= uint256($.start) + uint256($.duration)) return total;
        return Math.mulDiv(total, ts - $.start, $.duration);
    }

    function start() external view returns (uint64) {
        return _v().start;
    }

    function duration() external view returns (uint64) {
        return _v().duration;
    }

    function cliff() external view returns (uint64) {
        return _v().cliff;
    }

    function released() external view returns (uint256) {
        return _v().released;
    }

    function token() external view returns (address) {
        return _v().token;
    }

    function launchpad() external view returns (address) {
        return _v().launchpad;
    }

    function started() external view returns (bool) {
        return _v().started;
    }

    /**
     * @notice Expose the namespaced storage slot constant for testing parity
     *         with the spec'd ERC-7201 derivation.
     */
    function STORAGE_LOCATION() external pure returns (bytes32) {
        return VW_LOC;
    }

    function version() external pure returns (uint256) {
        return 1;
    }
}
