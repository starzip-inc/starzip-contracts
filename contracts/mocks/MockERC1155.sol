// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import { ERC1155 } from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

/// @dev Test-only ERC1155 used to exercise StarzipWallet's ERC1155Holder receiver callbacks.
contract MockERC1155 is ERC1155 {
    constructor() ERC1155("") {}

    /// @dev Triggers onERC1155Received on contract recipients.
    function mint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }

    /// @dev Triggers onERC1155BatchReceived on contract recipients.
    function mintBatch(address to, uint256[] memory ids, uint256[] memory amounts) external {
        _mintBatch(to, ids, amounts, "");
    }
}
