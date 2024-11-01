// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
interface IQuillToken {
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
}
