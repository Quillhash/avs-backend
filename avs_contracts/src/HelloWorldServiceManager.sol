// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import {ECDSAServiceManagerBase} from
    "@eigenlayer-middleware/src/unaudited/ECDSAServiceManagerBase.sol";
import {ECDSAStakeRegistry} from "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import {IServiceManager} from "@eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {ECDSAUpgradeable} from
    "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import {IERC1271Upgradeable} from "@openzeppelin-upgrades/contracts/interfaces/IERC1271Upgradeable.sol";

import {IHelloWorldServiceManager} from "./IHelloWorldServiceManager.sol";

import "@openzeppelin/contracts/utils/Strings.sol";
import "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title Primary entrypoint for procuring services from HelloWorld.
 * @author Eigen Labs, Inc.
 */
contract HelloWorldServiceManager is ECDSAServiceManagerBase, IHelloWorldServiceManager {


    using ECDSAUpgradeable for bytes32;

    uint32 public latestTaskNum;


    
    // mapping of task indices to all tasks hashes
    // when a task is created, task hash is stored here,
    // and responses need to pass the actual task,

    
    // which is hashed onchain and checked against this mapping
    mapping(uint32 => bytes32) public allTaskHashes; // taskIndex => taskHash



    // Mapping of task indices to the operator's response (signature)
    mapping(uint32 => bytes) public allTaskResponses; // taskIndex => response (signature)


    // maps user addresses to contract address to the ipfs hash of audits
    mapping(address => mapping(address => string)) public userAudits;


    // Mapping of task indices to the audit report's IPFS hash
    mapping(uint32 => string) public auditReports; // taskIndex => IPFS hash


    // Approval and disapproval counts per task index
    mapping(uint32 => uint256) public approvals; // taskIndex => approval count
    mapping(uint32 => uint256) public disapprovals; // taskIndex => disapproval count


    // Tracks if a verifier has already verified a task
    mapping(uint32 => mapping(address => bool)) public hasVerified; // taskIndex => verifier => bool

    modifier onlyOperator() {
        require(
            ECDSAStakeRegistry(stakeRegistry).operatorRegistered(msg.sender),
            "Operator must be the caller"
        );
        _;
    }

    constructor(
        address _avsDirectory,
        address _stakeRegistry,
        address _rewardsCoordinator,
        address _delegationManager

    )
        ECDSAServiceManagerBase(
            _avsDirectory,
            _stakeRegistry,
            _rewardsCoordinator,
            _delegationManager
        )
    {}

    /* FUNCTIONS */
    // NOTE: this function creates new audit task, assigns it a taskId
    function createNewAuditTask(
        address contractAddress
    ) external returns (Task memory) {
        // create a new task struct
        Task memory auditTask;
        auditTask.contractAddress = contractAddress;
        auditTask.taskCreatedBlock = uint32(block.number);
        auditTask.createdBy = msg.sender;

        // store hash of task onchain, emit event, and increase taskNum, this hash is later used to verify whether the responded task actually exists
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(auditTask));

        // emit audit task event
        emit AuditTaskCreated(latestTaskNum, auditTask);
        latestTaskNum += 1;

        return auditTask;
    }


    /* FUNCTIONS */
    // NOTE: this function creates new audit task, assigns it a taskId
    function createNewInsuranceTask(
        address contractAddress
    ) external returns (Task memory) {
        // create a new task struct
        Task memory insuranceTask;
        insuranceTask.contractAddress = contractAddress;
        insuranceTask.taskCreatedBlock = uint32(block.number);
        insuranceTask.createdBy = msg.sender;

        // store hash of task onchain, emit event, and increase taskNum
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(insuranceTask));
        emit InsuranceTaskCreated(latestTaskNum, insuranceTask);
        latestTaskNum += 1;

        return insuranceTask;
    }
    

    function respondToAuditTask(
        Task calldata task,
        string memory ipfs,
        uint32 referenceTaskIndex,
        bytes memory signature
    ) onlyOperator() external {
        
        //checks whether the task provided by the operator was actually created within the network
        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );

        //checks whether a response has already been given to the current task
        require(
            allTaskResponses[referenceTaskIndex].length == 0,
            "Operator has already responded to the task"
        );

        // checks whether the signature made on the ipfs is correct, by checking the signature on the hash of ipfs string provided by operator
        bytes32 messageHash = keccak256(abi.encode(ipfs));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;
        if (!(magicValue == ECDSAStakeRegistry(stakeRegistry).isValidSignature(ethSignedMessageHash,signature))){
            revert();
        }



        // Store the operator's response (signature)
        allTaskResponses[referenceTaskIndex] = signature;

        //store the ipfs hash of the audit report associated with task
        auditReports[referenceTaskIndex] = ipfs;


        // emitting event
        emit AuditTaskResponded(referenceTaskIndex, task, msg.sender, ipfs);
    }




    function respondToInsuranceTask(
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes memory signature,
        bool approved
    ) onlyOperator() external {
        // check that the task is valid, hasn't been responsed yet, and is being responded in time
        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );
        require(
            allTaskResponses[referenceTaskIndex].length == 0,
            "Operator has already responded to the task"
        );

        // // The message that was signed
        // bytes32 messageHash = keccak256(abi.encode(approved));
        // bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        // bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;
        // if (!(magicValue == ECDSAStakeRegistry(stakeRegistry).isValidSignature(ethSignedMessageHash,signature))){
        //     revert();
        // }


        
        // updating the storage with task responses
        allTaskResponses[referenceTaskIndex] = signature;


        if(approved){
            //logic for release of tokens
        }


       emit InsuranceTaskResponded(referenceTaskIndex, task, msg.sender, approved);
        // emitting event
        //emit AuditTaskResponded(referenceTaskIndex, task, msg.sender);
    }





    function verifyAuditReport(
        Task calldata task,
        uint32 referenceTaskIndex,
        address operator,
        bool approval,
        bytes memory signature
    ) external onlyOperator() {

        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );


        // Check if the operator has responded to this task
        require(
            bytes(auditReports[referenceTaskIndex]).length != 0,
            "Operator has not responded"
        );

        // Check if the verifier has already verified this operator's response
        require(
            !hasVerified[referenceTaskIndex][msg.sender],
            "Already verified"
        );


        // Mark as verified
        hasVerified[referenceTaskIndex][msg.sender] = true;

        //  // Verify signature
        // bytes32 taskHash = keccak256(abi.encode(task));
        // bytes32 messageHash = keccak256(
        //     abi.encodePacked(taskHash, operator, approval)
        // );
        // bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        // bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;

        // if (
        //     magicValue !=
        //     ECDSAStakeRegistry(stakeRegistry).isValidSignature(
        //         ethSignedMessageHash,
        //         signature
        //     )
        // ) {
        //     revert("Invalid signature");
        // }

        // Update approval or disapproval count
        if (approval) {
            approvals[referenceTaskIndex] += 1;
        } else {
            disapprovals[referenceTaskIndex] += 1;
        }

        // Emit verification event
        emit AuditReportVerified(
            referenceTaskIndex,
            task.contractAddress,
            operator,
            msg.sender,
            approval
        );

    }

    // Getter functions for approvals and disapprovals per task index (per audit report)
    function getApprovalCount(uint32 taskIndex)
        external
        view
        returns (uint256)
    {
        return approvals[taskIndex];
    }

    function getDisapprovalCount(uint32 taskIndex)
        external
        view
        returns (uint256)
    {
        return disapprovals[taskIndex];
    }

    // Function to get the audit report (IPFS hash) for a task index
    function getAuditReport(uint32 taskIndex)
        external
        view
        returns (string memory)
    {
        return auditReports[taskIndex];
    }
}