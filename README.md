## QuillShield AVS

<a href="https://quillshield-avs.vercel.app/audit">QuillShield</a> Provides Cryptoeconomically secured AI Powered Audits with Risk insured security. By running this client, you can join the QuillShield Network as an operator and perform audits on smart contracts, verify another operator's audit reports, process insurance requests and claims.




# Steps to build and deploy the project



## 1. Building the project 

Feel free to directly skip to step 5 unless you plan on creating and deploying your own version of the QuillShield Network

```
1. cd avs_contracts
2. forge build
3. cd ..
4. node utils/abis.js
5. npm i

```

## 2. Operator Registration 

If you're a new operator and have never registered to EigenLayer Core Contracts or AVSs before

```
npm run register:complete
```
This command initiates a complete registration 


To register exclusively to our AVS, you can use the following command

```
npm run register:avs
```



## 3. Operator Startup

Before you start the operator, make sure you have all the necessary environment variables in place, you can refer to .env.example for the complete information

To start your operator, you can run the following command

```
npm run start:operator
```


## 4. To do

- Introduce automated verification method for audit reports
- Explore intersubjective ways of AI Audit Verification
- Create a way for projects to claim the insurance of their contracts as they move from testnet to mainnet
- Explore intersubjective methods of insurance claim verification

