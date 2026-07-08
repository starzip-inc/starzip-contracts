// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @dev Test-only ERC721 used to exercise StarzipWallet's ERC721Holder receiver callbacks.
contract MockERC721 is ERC721 {
    constructor() ERC721("MockNFT", "MNFT") {}

    /// @dev Safe mint — triggers the onERC721Received acceptance check on contract recipients.
    function safeMint(address to, uint256 tokenId) external {
        _safeMint(to, tokenId);
    }

    /// @dev Unsafe mint — no receiver check (used to seed transfer tests).
    function mint(address to, uint256 tokenId) external {
        _mint(to, tokenId);
    }
}
