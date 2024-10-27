import { ethers } from "ethers";
import * as dotenv from "dotenv";
import apiCallHelper from "./helpers/apiCallHelper";
const fs = require('fs');
const path = require('path');
dotenv.config();

// Check if the process.env object is empty
if (!Object.keys(process.env).length) {
    throw new Error("process.env object is empty");
}

// Setup env variables
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

/// TODO: Hack
let chainId = 31337;

const avsDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../avs_contracts/deployments/hello-world/${chainId}.json`), 'utf8'));
// Load core deployment data
const coreDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../avs_contracts/deployments/core/${chainId}.json`), 'utf8'));


const delegationManagerAddress = coreDeploymentData.addresses.delegation; // todo: reminder to fix the naming of this contract in the deployment file, change to delegationManager
const avsDirectoryAddress = coreDeploymentData.addresses.avsDirectory;
const helloWorldServiceManagerAddress = avsDeploymentData.addresses.helloWorldServiceManager;
const ecdsaStakeRegistryAddress = avsDeploymentData.addresses.stakeRegistry;



// Load ABIs
const delegationManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/IDelegationManager.json'), 'utf8'));
const ecdsaRegistryABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/ECDSAStakeRegistry.json'), 'utf8'));
const helloWorldServiceManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/HelloWorldServiceManager.json'), 'utf8'));
const avsDirectoryABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/IAVSDirectory.json'), 'utf8'));

// Initialize contract objects from ABIs
const delegationManager = new ethers.Contract(delegationManagerAddress, delegationManagerABI, wallet);
const helloWorldServiceManager = new ethers.Contract(helloWorldServiceManagerAddress, helloWorldServiceManagerABI, wallet);
const ecdsaRegistryContract = new ethers.Contract(ecdsaStakeRegistryAddress, ecdsaRegistryABI, wallet);
const avsDirectory = new ethers.Contract(avsDirectoryAddress, avsDirectoryABI, wallet);


const signAndRespondToTask = async (taskIndex: number, blockNumber: number, address: string, ipfs: string, createdBy: string) => {
    try {
        
    const messageHash = ethers.solidityPackedKeccak256(["string"], [address]);
    const messageBytes = ethers.getBytes(messageHash);
    const signature = await wallet.signMessage(messageBytes);

    console.log(`Signing and responding to task ${taskIndex}`);

    const operators = [await wallet.getAddress()];
    const signatures = [signature];
    const signedTask = ethers.AbiCoder.defaultAbiCoder().encode(
        ["address[]", "bytes[]", "uint32"],
        [operators, signatures, ethers.toBigInt(await provider.getBlockNumber())]
    );
    console.log({ contractAddress: address , taskCreatedBlock: blockNumber, createdBy },
        ipfs,
        taskIndex,
        signedTask,'--------------------');
    

    const tx = await helloWorldServiceManager.respondToAuditTask(
        { contractAddress: address , taskCreatedBlock: blockNumber, createdBy },
        ipfs,
        taskIndex,
        signedTask
    );
    await tx.wait();
    } catch (e: any) {
        console.log(e);        
        throw new Error(e.message);
    }
    // console.log(`Responded to task.`);
};

const registerOperator = async () => {
    
    // Registers as an Operator in EigenLayer.
    try {
        const tx1 = await delegationManager.registerAsOperator({
            __deprecated_earningsReceiver: await wallet.address,
            delegationApprover: "0x0000000000000000000000000000000000000000",
            stakerOptOutWindowBlocks: 0
        }, "");
        await tx1.wait();
        console.log("Operator registered to Core EigenLayer contracts");
    } catch (error) {
        console.error("Error in registering as operator:", error);
    }
    
    const salt = ethers.hexlify(ethers.randomBytes(32));
    const expiry = Math.floor(Date.now() / 1000) + 3600; // Example expiry, 1 hour from now

    // Define the output structure
    let operatorSignatureWithSaltAndExpiry = {
        signature: "",
        salt: salt,
        expiry: expiry
    };

    // Calculate the digest hash, which is a unique value representing the operator, avs, unique value (salt) and expiration date.
    const operatorDigestHash = await avsDirectory.calculateOperatorAVSRegistrationDigestHash(
        wallet.address, 
        await helloWorldServiceManager.getAddress(), 
        salt, 
        expiry
    );
    console.log(operatorDigestHash);
    
    // Sign the digest hash with the operator's private key
    console.log("Signing digest hash with operator's private key");
    const operatorSigningKey = new ethers.SigningKey(process.env.PRIVATE_KEY!);
    const operatorSignedDigestHash = operatorSigningKey.sign(operatorDigestHash);

    // Encode the signature in the required format
    operatorSignatureWithSaltAndExpiry.signature = ethers.Signature.from(operatorSignedDigestHash).serialized;

    console.log("Registering Operator to AVS Registry contract");

    
    // Register Operator to AVS
    // Per release here: https://github.com/Layr-Labs/eigenlayer-middleware/blob/v0.2.1-mainnet-rewards/src/unaudited/ECDSAStakeRegistry.sol#L49
    const tx2 = await ecdsaRegistryContract.registerOperatorWithSignature(
        operatorSignatureWithSaltAndExpiry,
        wallet.address
    );
    await tx2.wait();
    console.log("Operator registered on AVS successfully");
};

const monitorNewTasks = async () => {
    //console.log(`Creating new task "EigenWorld"`);
    //await helloWorldServiceManager.createNewTask("EigenWorld");
    
    helloWorldServiceManager.on("AuditTaskCreated", async (taskIndex: number, task: any) => {
            try {
            console.log(`New task detected -->> `, taskIndex, task);
            const audit = await apiCallHelper.apiCall(`${process.env.AUDIT_AGENT_URL}?address=${task[0]}`, 'GET');
            const ipfsUrl = await apiCallHelper.apiCall(`${process.env.IPFS_UPLOAD_AGENT_URL}`, 'POST', audit, {
                "pinata_api_key": `${process.env.PINATA_CLOUD_API_KEY}`,
                "pinata_secret_api_key": `${process.env.PINATA_CLOUD_SECRET_KEY}`,
            },);
            await signAndRespondToTask(taskIndex, task[1], task[0], ipfsUrl.IpfsHash, task[2]);
            
        } catch (e) {
            console.log(e);
            
        }
    });

    console.log("Monitoring for new tasks...");
};

const main = async () => {
    // await registerOperator();
    monitorNewTasks().catch((error) => {
        console.error("Error monitoring tasks:", error);
    });
};

main().catch((error) => {
    console.error("Error in main function:", error);
});

// signAndRespondToTask(1, 323232, '0x7CBb95D1E1AB0740cD54726c4aad266e1aF2083b')