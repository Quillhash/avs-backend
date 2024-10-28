// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Script.sol";
import {QuillToken} from "../src/QuillToken.sol";

contract Deploy is Script {
    function run() public {
        // Fetch the private key from the environment variables
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        // Log the deploying address
        console.log("Deploying contracts with address:", vm.addr(privateKey));

        // Begin broadcasting transactions
        vm.startBroadcast(privateKey);

        // Deploy the QuillToken contract
        QuillToken quillToken = new QuillToken(1000000000000000000000000);

        // Stop broadcasting transactions
        vm.stopBroadcast();

        // Log the deployed contract address
        console.log("QuillToken deployed at address:", address(quillToken));
    }
}
