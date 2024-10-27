// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract QuillToken is ERC20 {
    constructor(uint256 initialSupply) ERC20("QuillToken", "QT") {
        _mint(msg.sender, initialSupply);
    }
    function mint(address account, uint256 amount) public {
        _mint(account, amount);
    }
}
