import { ethers } from "ethers";
import * as dotenv from "dotenv";
const fs = require('fs');
const path = require('path');
dotenv.config();

// Setup env variables
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

/// TODO: Hack
let chainId = 31337;
const tokenAddress = "0x1613beB3B2C4f22Ee086B2b38C1476A3cE7f78E8";
const avsDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../avs_contracts/deployments/hello-world/${chainId}.json`), 'utf8'));
const helloWorldServiceManagerAddress = avsDeploymentData.addresses.helloWorldServiceManager;
const helloWorldServiceManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/HelloWorldServiceManager.json'), 'utf8'));
const quillTokenABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/QuillToken.json'), 'utf8'));

// Initialize contract objects from ABIs
const helloWorldServiceManager = new ethers.Contract(helloWorldServiceManagerAddress, helloWorldServiceManagerABI, wallet);
const quillTokenServiceManager = new ethers.Contract(tokenAddress, quillTokenABI, wallet);

async function createNewTask(address: string) {
  try {

    const mintTokens = await quillTokenServiceManager.mint(wallet, 10000);
    await mintTokens.wait();

    const approveTokens = await quillTokenServiceManager.approve(helloWorldServiceManagerAddress, 10000);
    await approveTokens.wait();

    try {

      const init = await helloWorldServiceManager.init(
        [
          "0x2F00fE0F316903e741179C628Ae5E4C744cf6F94",
          "0x12385F862e9E6e24310283323D4aDEf30553220B"
        ],
        2,
        tokenAddress
      );
      await init.wait();
    }catch (e) {
      console.log(e);
    }
    // Send a transaction to the createNewTask function
    const tx = await helloWorldServiceManager.createNewAuditTask(address);
    
    // Wait for the transaction to be mined
    const receipt = await tx.wait();
    
    console.log(`Transaction successful with hash: ${receipt.hash}`);
  } catch (error) {
    console.log(error);
    
    console.error('Error sending transaction:', error);
  }
}

// Start the process
createNewTask('0x7CBb95D1E1AB0740cD54726c4aad266e1aF2083b');
