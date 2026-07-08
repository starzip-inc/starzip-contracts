// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ERC20Upgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import { ERC20PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title ERC20V1
 * @notice ERC20 token issued through StarZip Launchpad
 * @dev UUPS upgradeable ERC20 with blacklist and max supply features
 *
 * Features:
 * - Pausable transfers
 * - Blacklist functionality
 * - Max supply limit (optional)
 * - Burn capability
 * - Launchpad owner management
 * - Fixed-supply model: `mint` is factory/launchpad-only (used exclusively for
 *   the initial issuance mint). `TokenFactory` calls `setMaxSupply` immediately
 *   after that mint, permanently capping supply at the issued amount — there is
 *   no post-issuance mint path (the former `mintWithApproval` subsystem was
 *   removed as dead code once supply is locked at issuance).
 */
contract ERC20V1 is
    Initializable,
    ERC20Upgradeable,
    ERC20PausableUpgradeable,
    Ownable2StepUpgradeable,
    UUPSUpgradeable
{
    // ============ Constants ============
    uint256 public constant MAX_BATCH_SIZE = 100;

    // ============ State Variables ============
    string public contractURI;
    address public launchpad;
    address public launchpadOwner; // Deprecated: replaced by real-time verification

    // Maximum supply (0 means unlimited)
    uint256 public maxSupply;

    // Blacklist mapping
    mapping(address => bool) public blacklist;

    // ============ Storage Gap ============
    // Reserved storage slots for future upgrades — do not reorder or reuse.
    uint256[50] private __gap;

    // ============ Events ============
    event Blacklisted(address indexed account);
    event RemovedFromBlacklist(address indexed account);
    event MaxSupplySet(uint256 maxSupply);
    event ContractURIUpdated(string oldURI, string newURI);
    event Burned(address indexed account, uint256 amount);
    event LaunchpadOwnerUpdated(address indexed oldOwner, address indexed newOwner);

    // ============ Errors ============
    error ExceedsMaxSupply();
    error ZeroAddress();
    error ZeroAmount();
    error LaunchpadNotSet();
    error NotLaunchpadOwner();
    error LaunchpadOwnerVerificationFailed();
    error AccountBlacklisted();
    error AccountNotBlacklisted();
    error BatchTooLarge();
    error MaxSupplyAlreadySet();
    error InvalidMaxSupply();
    error InvalidImplementation();
    error CannotBlacklistOwner();
    error NotLaunchpad();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ============ Initialization ============

    /**
     * @notice Initialize the ERC20 token
     * @param initialOwner Initial owner address
     * @param _name Token name
     * @param _symbol Token symbol
     * @param _contractURI Contract metadata URI
     */
    function initialize(
        address initialOwner,
        string memory _name,
        string memory _symbol,
        string memory _contractURI
    ) public initializer {
        // Validate inputs before any state modifications
        if (initialOwner == address(0)) revert ZeroAddress();
        if (bytes(_name).length == 0 || bytes(_symbol).length == 0) revert ZeroAmount();

        __ERC20_init(_name, _symbol);
        __ERC20Pausable_init();
        __Ownable_init(initialOwner);

        contractURI = _contractURI;
        launchpad = msg.sender;

        // Store launchpad owner address (set to address(0) if external call fails)
        // This is used as fallback in case of DoS
        try ILaunchpad(msg.sender).owner() returns (address _owner) {
            launchpadOwner = _owner;
        } catch {
            launchpadOwner = address(0);
        }
    }

    // ============ Modifiers ============

    /**
     * @dev Modifier restricting access to the launchpad/factory only.
     * @dev Used for the initial issuance mint (the only mint path).
     */
    modifier onlyLaunchpad() {
        if (msg.sender != launchpad) revert NotLaunchpad();
        _;
    }

    // ============ Blacklist Functions ============

    /**
     * @notice Add account to blacklist
     * @param account Account to blacklist
     * @dev Business owner (token owner) has full control for liability purposes
     */
    function addToBlacklist(address account) public onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        if (blacklist[account]) revert AccountBlacklisted();
        // Prevent blacklisting owner
        if (account == owner()) revert CannotBlacklistOwner();
        blacklist[account] = true;
        emit Blacklisted(account);
    }

    /**
     * @notice Remove account from blacklist
     * @param account Account to remove from blacklist
     * @dev Business owner (token owner) has full control for liability purposes
     */
    function removeFromBlacklist(address account) public onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        if (!blacklist[account]) revert AccountNotBlacklisted();
        blacklist[account] = false;
        emit RemovedFromBlacklist(account);
    }

    /**
     * @notice Add multiple accounts to blacklist
     * @param accounts Array of accounts to blacklist
     * @dev Business owner (token owner) has full control for liability purposes
     */
    function batchAddToBlacklist(address[] calldata accounts) external onlyOwner {
        if (accounts.length == 0 || accounts.length > MAX_BATCH_SIZE) revert BatchTooLarge();

        address _owner = owner();

        for (uint256 i = 0; i < accounts.length; ) {
            address account = accounts[i];
            // Skip zero address, already blacklisted, and owner
            if (account != address(0) && !blacklist[account] && account != _owner) {
                blacklist[account] = true;
                emit Blacklisted(account);
            }
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Remove multiple accounts from blacklist
     * @param accounts Array of accounts to remove from blacklist
     * @dev Business owner (token owner) has full control for liability purposes
     */
    function batchRemoveFromBlacklist(address[] calldata accounts) external onlyOwner {
        if (accounts.length == 0 || accounts.length > MAX_BATCH_SIZE) revert BatchTooLarge();
        for (uint256 i = 0; i < accounts.length; ) {
            address account = accounts[i];
            if (account != address(0) && blacklist[account]) {
                blacklist[account] = false;
                emit RemovedFromBlacklist(account);
            }
            unchecked {
                ++i;
            }
        }
    }

    // ============ Token Functions ============

    /**
     * @notice Mint new tokens (launchpad/factory only)
     * @param to Recipient address
     * @param amount Amount to mint
     * @dev Restricted to `onlyLaunchpad`. Used exclusively for the initial issuance
     *      mint `token.mint(address(this), totalSupply)` performed by the factory,
     *      which locks `maxSupply` to that exact amount immediately afterward —
     *      there is no other mint path, so supply is fixed after issuance.
     */
    function mint(address to, uint256 amount) public onlyLaunchpad {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();

        // Blacklist check
        if (blacklist[to]) revert AccountBlacklisted();

        // Max supply validation with overflow-safe check
        if (maxSupply > 0) {
            uint256 currentSupply = totalSupply();
            // Use subtraction to prevent overflow
            if (amount > maxSupply - currentSupply) {
                revert ExceedsMaxSupply();
            }
        }
        _mint(to, amount);
    }

    /**
     * @notice Burn tokens (holder burns their own tokens)
     * @param amount Amount to burn
     */
    function burn(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        // Blacklist check - blacklisted users cannot burn
        if (blacklist[msg.sender]) revert AccountBlacklisted();
        _burn(msg.sender, amount);
        emit Burned(msg.sender, amount);
    }

    /**
     * @notice Set maximum supply (can only be set once)
     * @param _maxSupply Maximum supply amount
     * @dev Business owner (token owner) has full control for liability purposes
     */
    function setMaxSupply(uint256 _maxSupply) external onlyOwner {
        if (maxSupply != 0) revert MaxSupplyAlreadySet();
        if (_maxSupply < totalSupply()) revert InvalidMaxSupply();
        maxSupply = _maxSupply;
        emit MaxSupplySet(_maxSupply);
    }

    /**
     * @notice Update contract URI
     * @param _newContractURI New contract URI
     * @dev Business owner (token owner) has full control for liability purposes
     */
    function setContractURI(string memory _newContractURI) external onlyOwner {
        string memory oldURI = contractURI;
        contractURI = _newContractURI;
        emit ContractURIUpdated(oldURI, _newContractURI);
    }

    // ============ Pausable Functions ============

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    // ============ Launchpad Owner Update ============

    /**
     * @notice Update cached launchpad owner (can only be called by launchpad)
     * @dev This updates the cached launchpadOwner value used as fallback
     */
    function updateLaunchpadOwner() external {
        if (msg.sender != launchpad) revert NotLaunchpadOwner();
        address oldOwner = launchpadOwner;
        address newOwner = ILaunchpad(launchpad).owner();
        launchpadOwner = newOwner;
        emit LaunchpadOwnerUpdated(oldOwner, newOwner);
    }

    /**
     * @notice Direct ownership transfer (bypasses 2-step for initial setup)
     * @param newOwner New owner address
     * @dev Can only be called by launchpad/factory during token issuance
     * @dev This is safe because launchpad is trusted and sets owner during creation
     */
    function transferOwnershipDirect(address newOwner) external {
        if (msg.sender != launchpad) revert NotLaunchpadOwner();
        if (newOwner == address(0)) revert ZeroAddress();
        _transferOwnership(newOwner);
    }

    // ============ View Functions ============

    /**
     * @notice Get contract version
     * @return Version number
     */
    function version() public pure returns (uint256) {
        return 1;
    }

    /**
     * @notice Get current launchpad owner (real-time from launchpad)
     * @return Current launchpad owner address
     * @dev Returns cached value if real-time call fails
     */
    function getCurrentLaunchpadOwner() external view returns (address) {
        if (launchpad == address(0)) return launchpadOwner;
        try ILaunchpad(launchpad).owner() returns (address _owner) {
            return _owner;
        } catch {
            return launchpadOwner;
        }
    }

    // ============ Internal Functions ============

    function _authorizeUpgrade(address newImplementation) internal view override onlyOwner {
        if (newImplementation == address(0)) revert ZeroAddress();
        if (newImplementation.code.length == 0) revert InvalidImplementation();
    }

    /**
     * @dev Consult the registry only when a blacklist entry would otherwise block (hot path
     *      stays at 2 SLOADs). Platform-originated legs (from == infra, or a mint) bypass blacklist
     *      so a business cannot grief claims / vesting releases / settlement withdrawals, nor block
     *      a blacklisted investor from RECEIVING a distribution. Ordinary user<->user transfers and
     *      user->platform deposits (to is platform, from an ordinary user) remain under the
     *      business blacklist.
     */
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20Upgradeable, ERC20PausableUpgradeable) {
        if (blacklist[from] || blacklist[to]) {
            if (from != address(0) && !_isPlatform(from)) {
                if (blacklist[from]) revert AccountBlacklisted();
                if (blacklist[to]) revert AccountBlacklisted();
            }
        }
        super._update(from, to, value);
    }

    /// @dev True if `who` is a platform contract for THIS token, per the factory registry.
    ///      `launchpad` holds the deploying TokenFactory address (set at initialize).
    function _isPlatform(address who) internal view returns (bool) {
        address factory = launchpad;
        if (factory == address(0) || who == address(0)) return false;
        try IPlatformRegistry(factory).isPlatformContract(address(this), who) returns (bool ok) {
            return ok;
        } catch {
            return false; // fail-closed: unknown registry ⇒ enforce blacklist
        }
    }
}

/**
 * @title ILaunchpad
 * @notice Interface for Launchpad contract
 */
interface ILaunchpad {
    function owner() external view returns (address);
}

/**
 * @title IPlatformRegistry
 * @notice Minimal interface for the TokenFactory blacklist-exemption registry.
 */
interface IPlatformRegistry {
    function isPlatformContract(address token, address who) external view returns (bool);
}
