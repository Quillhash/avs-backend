## QuillShield AVS

QuillShield Provides Cryptoeconomically secured AI Powered Audits with a Premium Insurance Coverage






# Steps to build and deploy the project



```
1. cd avs_contracts
2. forge build
3. forge script script/DeployEigenLayerCore.s.sol --rpc-url http://localhost:8545 --broadcast 
4. forge script script/HelloWorldDeployer.s.sol --rpc-url http://localhost:8545 --broadcast
5. cd ..
6. node utils/abis.js


```