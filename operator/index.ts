import { ethers } from "ethers";
import * as dotenv from "dotenv";
import apiCallHelper from "./helpers/apiCallHelper";
const fs = require('fs');
const path = require('path');
dotenv.config({path:'./operator/.env'});

// Check if the process.env object is empty
if (!Object.keys(process.env).length) {
    throw new Error("process.env object is empty");
}

// Setup env variables
const provider = new ethers.JsonRpcProvider(process.env.HOLESKY_RPC_URL);

const provider2 = new ethers.JsonRpcProvider(process.env.INFURA_RPC);


const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);

const wallet2 = new ethers.Wallet(process.env.PRIVATE_KEY!, provider2);

let chainId = 17000;

// const avsDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../avs_contracts/deployments/hello-world/${chainId}.json`), 'utf8'));
// // Load core deployment data
// const coreDeploymentData = JSON.parse(fs.readFileSync(path.resolve(__dirname, `../avs_contracts/deployments/core/${chainId}.json`), 'utf8'));


// const delegationManagerAddress = coreDeploymentData.addresses.delegation; // todo: reminder to fix the naming of this contract in the deployment file, change to delegationManager
// const avsDirectoryAddress = coreDeploymentData.addresses.avsDirectory;
// const helloWorldServiceManagerAddress = avsDeploymentData.addresses.helloWorldServiceManager;
// const ecdsaStakeRegistryAddress = avsDeploymentData.addresses.stakeRegistry;


const delegationManagerAddress = "0xA44151489861Fe9e3055d95adC98FbD462B948e7";
const avsDirectoryAddress = "0x055733000064333caddbc92763c58bf0192ffebf";


const helloWorldServiceManagerAddress = "0x719db00c33cf69e241398d9cb4762e3c9005ae7e";//"0x746cad9a83f22fbc14a5c0cef4092c416401093b"//"0x661908908815C004258dFbC9566108C39Eb7c8e2"

//"0x62a83b25bf17efd8975555cb32129b8884044d8f"//"0xfE49f3683808407899787725d12F78cC8417D085" //"0xa45f26b445e3229139885e245fb0c779e38b1981";//"0x4037550102436347fe003760bd125211158ca3dc";//"0x43765f5b25f73C1bb1F177b03d9546a5DE62F939"//"0x4037550102436347fe003760bd125211158ca3dc";//"0x1B931d39FD7b3ccED7e255BcF3f5B0e99383F533";
const ecdsaStakeRegistryAddress = "0x3F5B2Ec0a85598213BA3e181a802EE8290714CBf";

// Load ABIs
const delegationManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/IDelegationManager.json'), 'utf8'));
const ecdsaRegistryABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/ECDSAStakeRegistry.json'), 'utf8'));
const helloWorldServiceManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/HelloWorldServiceManager.json'), 'utf8'));
const avsDirectoryABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/IAVSDirectory.json'), 'utf8'));

// Initialize contract objects from ABIs
const delegationManager = new ethers.Contract(delegationManagerAddress, delegationManagerABI, wallet);
const helloWorldServiceManager = new ethers.Contract(helloWorldServiceManagerAddress, helloWorldServiceManagerABI, wallet);


const helloWorldServiceManager2 = new ethers.Contract(helloWorldServiceManagerAddress, helloWorldServiceManagerABI, wallet2);

const ecdsaRegistryContract = new ethers.Contract(ecdsaStakeRegistryAddress, ecdsaRegistryABI, wallet);
const avsDirectory = new ethers.Contract(avsDirectoryAddress, avsDirectoryABI, wallet);


const signAndRespondToTask = async (taskIndex: number, task: any, ipfs: string, score: string) => {
    try {


    const messageHash = ethers.solidityPackedKeccak256(["string"], [ipfs]);
    const messageBytes = ethers.getBytes(messageHash);
    const signature = await wallet.signMessage(messageBytes);

    const operators = [await wallet.getAddress()];
    const signatures = [signature];
    const signedTask = ethers.AbiCoder.defaultAbiCoder().encode(
        ["address[]", "bytes[]", "uint32"],
        [operators, signatures, ethers.toBigInt(await provider.getBlockNumber())]
    );


    console.log('Making TX')


    console.log({
        contractAddress: task[0],
        taskCreatedBlock: task[1],
        createdBy: task[2]
    },
    ipfs,
    taskIndex,
    signedTask,
    Math.ceil(100.0-parseFloat(score)));



    const tx = await helloWorldServiceManager2.respondToAuditTask(
        {
            contractAddress: task[0],
            taskCreatedBlock: task[1],
            createdBy: task[2]
        },
        ipfs,
        taskIndex,
        signedTask,
        Math.ceil(100.0-(parseFloat(score)))
    );

    console.log('Awaiting TX Confirmation')
    await tx.wait();
    console.log('TX Included')
    } catch (e: any) {
        console.log(e);
        throw new Error(e.message);
    }
};

const signAndRespondToVerifyAuditReport = async (taskIndex: number, task: any, approval: boolean) => {
    try {

    const taskStruct = {
        contractAddress: task[0],         // Address as string
        taskCreatedBlock: task[1],        // Block number, likely BigInt
        createdBy: task[2]                // Address as string
    };


    console.log('signed');
    // Call the verifyAuditReport function
    const tx = await helloWorldServiceManager2.verifyAuditReport(
        taskStruct,
        taskIndex,
        approval
    );
    console.log('transaction created and awaiting inclusion')

    await tx.wait();

    console.log('TX included');
    } catch (e: any) {
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
    helloWorldServiceManager.on("AuditTaskCreated", async (taskIndex: number, task: any) => {
            try {

            console.log(`New task detected -->> `, taskIndex, task);
            const audit = await apiCallHelper.apiCall(`${process.env.AUDIT_AGENT_URL}?address=${task[0]}`, 'GET');
            const ipfsUrl = await apiCallHelper.apiCall(`${process.env.IPFS_UPLOAD_AGENT_URL}`, 'POST', audit, {
                "pinata_api_key": `${process.env.PINATA_CLOUD_API_KEY}`,
                "pinata_secret_api_key": `${process.env.PINATA_CLOUD_SECRET_KEY}`,
            },);


            console.log(`This is the Audit Report\n\n`)
            console.log(audit);


            console.log('Audit Complete')
            await signAndRespondToTask(taskIndex, task, ipfsUrl.IpfsHash, audit?.auditReport?.securityScore || 1);
            
        } catch (e) {
            console.log(e);
            
        }
    });

    console.log("Monitoring for new tasks...");
};

const monitorVerifyAuditReport = async () => {
    
    helloWorldServiceManager.on("AuditTaskResponded", async (taskIndex: number, task: any, createdBy: string, ipfs: string) => {
            try {
            console.log(`Verify Audit Report Task Detected -->> `, taskIndex, task, createdBy, ipfs);
            const reAudit = await apiCallHelper.apiCall(`${process.env.AUDIT_AGENT_URL}?address=${task[0]}`, 'GET');
            
            // ToDo: approval logic to verify old ipfs report with new ipfs report

            const approval = true;
            
            await signAndRespondToVerifyAuditReport(taskIndex, task, approval);
            console.log('Verify Audit Report Responded');
            
        } catch (e) {
            console.log(e);
            
        }
    });

    console.log("Monitoring for Verify Audit Tasks...");
};

const main = async () => {
   // await registerOperator();
    monitorNewTasks().catch((error) => {
        console.error("Error monitoring tasks:", error);
    });
    // monitorVerifyAuditReport().catch((error) => {
    //     console.error("Error monitoring Verify Audit Tasks:", error);
    // });
 };

main().catch((error) => {
    console.error("Error in main function:", error);
});