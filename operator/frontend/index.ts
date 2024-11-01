import express, { Request, Response } from 'express';
import path from 'path';
import { ethers } from 'ethers';
const fs = require('fs');
import * as dotenv from "dotenv";

dotenv.config({path:'./operator/frontend/.env'});


const app = express();
const PORT = 3000;


const provider = new ethers.JsonRpcProvider(process.env.INFURA_RPC);
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY!, provider);


const helloWorldServiceManagerAddress = "0x719db00c33cf69e241398d9cb4762e3c9005ae7e";//"0x746cad9a83f22fbc14a5c0cef4092c416401093b"//"0x661908908815C004258dFbC9566108C39Eb7c8e2"
const helloWorldServiceManagerABI = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../abis/HelloWorldServiceManager.json'), 'utf8'));

const helloWorldServiceManager = new ethers.Contract(helloWorldServiceManagerAddress, helloWorldServiceManagerABI, wallet);


// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());



// Endpoint for verifyAuditReport
app.post('/api/verifyAuditReport', async (req: Request, res: Response) => {
    const { task, taskIndex } = req.body;

    console.log(task, taskIndex)
    const approval = true;

    try {
        console.log('Creating Transaction (verifyAuditReport)')
        const tx = await helloWorldServiceManager.verifyAuditReport(task, taskIndex, approval);
        console.log('Awaiting Inclusion (verifyAuditReport)')
        const receipt = await tx.wait();
        console.log('Included (verifyAuditReport)')
        res.json({ success: true, receipt });
    } catch (error) {
        console.log(error)
        res.status(500).json({ success: false, error: error! });
    }
});

// Endpoint for verifyInsurance
app.post('/api/verifyInsurance', async (req: Request, res: Response) => {
    const { task, taskIndex } = req.body;
    const approved = true;

    console.log('Creating Signature (Insurance Task')

    console.log(task, taskIndex)
    const messageHash = ethers.solidityPackedKeccak256(["bool"],[approved]);
    const messageBytes = ethers.getBytes(messageHash);
    const signature = await wallet.signMessage(messageBytes);

    const operators = [await wallet.getAddress()];
    const signatures = [signature];
    const signedTask = ethers.AbiCoder.defaultAbiCoder().encode(
        ["address[]", "bytes[]", "uint32"],
        [operators, signatures, ethers.toBigInt(await provider.getBlockNumber())]
    );


    console.log('Creating Transaction (respondToInsuranceTask)')
   

    try {
        const tx = await helloWorldServiceManager.respondToInsuranceTask(task, taskIndex, signedTask, approved);
        console.log('Awaiting Inclusion  (respondToInsuranceTask)')
        const receipt = await tx.wait();
        console.log('TX Included  (respondToInsuranceTask)')
        res.json({ success: true, receipt });
    } catch (error) {
        res.status(500).json({ success: false, error: error!});
    }
});



// Endpoint for verifyClaim
app.post('/api/verifyClaim', async (req: Request, res: Response) => {
    const { claimId } = req.body;
    
    try {
        console.log('Creating Transaction (processClaim)')
        const tx = await helloWorldServiceManager.processClaim(claimId);
        console.log('Awaiting Inclusion  (processClaim)')
        const receipt = await tx.wait();
        console.log('TX Included  (rprocessClaim)');
        res.json({ success: true, receipt });
    } catch (error) {
        res.status(500).json({ success: false, error: error! });
    }
});

// Serve index.html for the root route
app.get('/', (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});


