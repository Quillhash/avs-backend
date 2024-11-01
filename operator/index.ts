import { ethers } from "ethers";
import dotenv from "dotenv";
import Web3 from "web3";
import apiCallHelper from "./helpers/apiCallHelper";
import fs from "fs";
import path from "path";

//load the environment variables
dotenv.config({path:'./operator/.env'});

//Use Web3.js along with Socket RPC for listening 
//Use Ethers.js with HTTPS RPC for Responding To Contract

// Check if the process.env object is empty
if (!Object.keys(process.env).length) {
    throw new Error("process.env object is empty");
}



// Loading Contract Addresses

const ServiceManagerImplementationAddress = process.env.AVS_SERVICE_MANAGER_IMPLEMENTATION_ADDRESS;
const ServiceManagerProxyAddress = process.env.AVS_SERVICE_MANAGER_PROXY_ADDRESS;


const DelegationManagerAddress = process.env.DELEGATION_MANAGER_ADDRESS;
const AVSDirectoryAddress = process.env.AVS_DIRECTORY_ADDRESS;
const ECDSARegistryAddress = process.env.ECDSA_STAKE_REGISTRY_ADDRESS;

// Setting up WebSocket and Http RPC providers

const httpProvider = new ethers.JsonRpcProvider(process.env.HTTP_RPC_PROVIDER);

console.log('Configured Provider');
const web3WebsocketProvider = new Web3(Web3.givenProvider || process.env.WEB_SOCKET_RPC!);

// Setting up Operator Wallet for initiating transactions

const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, httpProvider);

console.log('Configured Wallet');

// Loading ABIs for interaction

const QuillShieldServiceManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/QuillShieldServiceManager.json'), 'utf8'));
const DelegationManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/IDelegationManager.json'), 'utf8'));
const ECDSARegistryABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/ECDSAStakeRegistry.json'), 'utf8'));
const AVSDirectoryABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../abis/IAVSDirectory.json'), 'utf8'));

console.log('Loaded ABIs');


// Load Contracts

// Use this for listening to events
const ServiceManagerContractListener = new web3WebsocketProvider.eth.Contract(QuillShieldServiceManagerABI!, ServiceManagerImplementationAddress!);
//  Use this for contract interaction
const ServiceManagerContract = new ethers.Contract(process.argv[2] ? ServiceManagerProxyAddress! : ServiceManagerImplementationAddress!, QuillShieldServiceManagerABI, wallet);


const DelegationManagerContract = new ethers.Contract(DelegationManagerAddress!, DelegationManagerABI!, wallet);

const AVSDirectoryContract = new ethers.Contract(AVSDirectoryAddress!, AVSDirectoryABI!, wallet);
const ECDSARegistryContract = new ethers.Contract(ECDSARegistryAddress!, ECDSARegistryABI, wallet);





const signAndRespondToTask = async (taskIndex: number, task: any, ipfs: string, score: string) => {
    
    try {

    const messageHash = ethers.solidityPackedKeccak256(["string"], [ipfs]);
    const messageBytes = ethers.getBytes(messageHash);
    const signature = await wallet.signMessage(messageBytes);

    const operators = [await wallet.getAddress()];
    const signatures = [signature];
    const signedTask = ethers.AbiCoder.defaultAbiCoder().encode(
        ["address[]", "bytes[]", "uint32"],
        [operators, signatures, ethers.toBigInt(await httpProvider.getBlockNumber())]
    );


    console.log('Making TX')

    const tx = await ServiceManagerContract.respondToAuditTask(
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

/**
 * @Akshat 
 * - Mode 0 means we are performing a registering just to EigenLayer
 * - Mode 1 means we are performing a full registration (EigenLayer + AVS)
 * - Any other mode value would result in just AVS Registration
 * @param mode 
 * @returns 
 */
async function registerOperator(mode:Number){
    //performing complete operator registration (registers to eigenlayer as well)
     if(mode === 0 || mode === 1) {
            console.log(`***Registering to EigenLayer***`);
         // Registers as an Operator in EigenLayer.
            try {
                const tx1 = await DelegationManagerContract.registerAsOperator({
                    __deprecated_earningsReceiver: await wallet.address,
                    delegationApprover: "0x0000000000000000000000000000000000000000",
                    stakerOptOutWindowBlocks: 0
                }, "");
                await tx1.wait();
                console.log("Operator registered to Core EigenLayer contracts");
            } catch (error) {
                console.error("Error in registering as operator");
                console.error(error)
            }
        if(mode === 0)
        return;
     }


  

    console.log(`***Registering to AVS***`);
    
    const salt = ethers.hexlify(ethers.randomBytes(32));
    const expiry = Math.floor(Date.now() / 1000) + 3600; // Example expiry, 1 hour from now

    // Define the output structure
    let operatorSignatureWithSaltAndExpiry = {
        signature: "",
        salt: salt,
        expiry: expiry
    };

    // Calculate the digest hash, which is a unique value representing the operator, avs, unique value (salt) and expiration date.
    const operatorDigestHash = await AVSDirectoryContract.calculateOperatorAVSRegistrationDigestHash(
        wallet.address, 
        await ServiceManagerContract.getAddress(), 
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
    const tx2 = await ECDSARegistryContract.registerOperatorWithSignature(
        operatorSignatureWithSaltAndExpiry,
        wallet.address
    );
    await tx2.wait();
    console.log("Operator registered on AVS successfully");
}


const monitorNewTasks = async () => {

    // events.AuditTaskResponded({ fromBlock: 'latest' })
    // .on('data', (event) => {
    //     createEventCard(event, 'AuditTaskResponded');
    // })
    ServiceManagerContractListener.events
    .AuditTaskCreated({ fromBlock: 'latest' })
    .on('data', async (event) => {
       
        try {

            const data = event.returnValues as any;


            console.log(`New task detected -->> `, data.taskIndex, data.task);


            const taskContent = data.task as [string, ...any[]];;

            const audit = await apiCallHelper.apiCall(`${process.env.AUDIT_AGENT_URL}?address=${taskContent[0]}`, 'GET');
            const ipfsUrl = await apiCallHelper.apiCall(`${process.env.IPFS_UPLOAD_AGENT_URL}`, 'POST', audit, {
                "pinata_api_key": `${process.env.PINATA_CLOUD_API_KEY}`,
                "pinata_secret_api_key": `${process.env.PINATA_CLOUD_SECRET_KEY}`,
            },);


            console.log(`This is the Audit Report\n\n`)
            console.log(audit);


            console.log('Audit Complete')
            await signAndRespondToTask(data.taskIndex, data.task, ipfsUrl.IpfsHash, audit?.auditReport?.securityScore || 1);
        } catch (e) {
            console.log(e);
            
        }
    });
    

    console.log("Monitoring for new tasks...");
};

// Entrypoint to the AVS Client Node
async function main(){

    if(process.argv[2] === '--registerAVS'){
        await registerOperator(2);
    }
    if(process.argv[2] === '--registerEigen'){
        await registerOperator(0)
    }
    if(process.argv[2] === '--registerFull'){
        await registerOperator(1)
    }   

    // monitor for tasks when not in registration mode
    if(!process.argv[2]){
        // monitor new auditing tasks
        monitorNewTasks().catch((error) => {
            console.error("Error monitoring tasks:", error);
        });
    }

    
 
};

main().catch((error) => {
    console.error("Error in main function:", error);
});