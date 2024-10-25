// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
interface IQuillToken {
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
}
