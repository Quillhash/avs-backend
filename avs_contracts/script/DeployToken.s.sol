// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Script.sol";
import {HelloWorldServiceManager} from "../src/qsInsurance.sol";

contract Deploy is Script {
    function run() public {
        // Fetch the private key from the environment variables
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        // Log the deploying address
        console.log("Deploying contracts with address:", vm.addr(privateKey));

        // Begin broadcasting transactions
        vm.startBroadcast(privateKey);

        // Deploy the QuillToken contract
        HelloWorldServiceManager quillToken = new HelloWorldServiceManager(
            0x055733000064333CaDDbC92763c58BF0192fFeBf,
            address(0),
            0xAcc1fb458a1317E886dB376Fc8141540537E68fE,
            0xA44151489861Fe9e3055d95adC98FbD462B948e7
        );

        // Stop broadcasting transactions
        vm.stopBroadcast();

        // Log the deployed contract address
        console.log("QuillToken deployed at address:", address(quillToken));
    }
}
