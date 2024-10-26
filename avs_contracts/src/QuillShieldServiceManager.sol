// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import {ECDSAServiceManagerBase} from
    "@eigenlayer-middleware/src/unaudited/ECDSAServiceManagerBase.sol";
import {ECDSAStakeRegistry} from "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import {IServiceManager} from "@eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {ECDSAUpgradeable} from
    "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import {IERC1271Upgradeable} from "@openzeppelin-upgrades/contracts/interfaces/IERC1271Upgradeable.sol";

import {IQuillShieldServiceManager} from "./IQuillShieldServiceManager.sol";

import "@openzeppelin/contracts/utils/Strings.sol";
import "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title Primary entrypoint for procuring services from HelloWorld.
 * @author Eigen Labs, Inc.
 */
contract QuillShieldServiceManager is ECDSAServiceManagerBase, IQuillShieldServiceManager {
    using ECDSAUpgradeable for bytes32;

    uint32 public latestTaskNum;

    uint256 public constant minApprovals = 1;
    uint256 public constant minDisapprovals = 1;



    // Enums, these are the statuses of reports 
    enum ReportStatus { Pending, Accepted, Rejected }

    // mapping of task indices to all tasks hashes
    // when a task is created, task hash is stored here,
    // and responses need to pass the actual task,

    // maps user addresses to contract address to the ipfs hash of audits
    mapping(address => mapping(address => string)) public userAudits;
    // which is hashed onchain and checked against this mapping
    mapping(uint32 => bytes32) public allTaskHashes;

    // mapping of task indices to hash of abi.encode(taskResponse, taskResponseMetadata)
    mapping(address => mapping(uint32 => bytes)) public allTaskResponses;


    event AuditReportVerified(
        uint32 indexed taskIndex,
        address indexed contractAddress,
        address indexed operator,
        address verifier,
        bool approved
    );

    event ReportStatusChanged(
        uint32 indexed taskIndex,
        bytes32 fingerprint,
        ReportStatus status
    );



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
        emit AuditTaskCreated(latestTaskNum, auditTask);
        latestTaskNum = latestTaskNum + 1;

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
        latestTaskNum = latestTaskNum + 1;

        return insuranceTask;
    }
    

    function respondToAuditTask(
        Task calldata task,
        string memory ipfs,
        uint32 referenceTaskIndex,
        bytes memory signature
    ) external {

        //checks whether the task provided by the operator was actually created within the network
        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );

        //checks whether a response has already been given to the current task
        require(
            allTaskResponses[msg.sender][referenceTaskIndex].length == 0,
            "Operator has already responded to the task"
        );

        // checks whether the signature made on the ipfs is correct, by checking the signature on the hash of ipfs string provided by operator
        bytes32 messageHash = keccak256(abi.encode(ipfs));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;
        if (!(magicValue == ECDSAStakeRegistry(stakeRegistry).isValidSignature(ethSignedMessageHash,signature))){
            revert();
        }

        // marks the task as done essentially
        allTaskResponses[msg.sender][referenceTaskIndex] = signature;

        //store the task against the opreator's id at a given contract address
        userAudits[task.createdBy][task.contractAddress] = ipfs;


        // emitting event
        emit AuditTaskResponded(referenceTaskIndex, task, msg.sender, ipfs);
    }




    function respondToInsuranceTask(
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes memory signature
    ) external {
        // check that the task is valid, hasn't been responsed yet, and is being responded in time
        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );
        require(
            allTaskResponses[msg.sender][referenceTaskIndex].length == 0,
            "Operator has already responded to the task"
        );

        // The message that was signed
        bytes32 messageHash = keccak256(abi.encodePacked("Hello, ", task.contractAddress));
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;
        if (!(magicValue == ECDSAStakeRegistry(stakeRegistry).isValidSignature(ethSignedMessageHash,signature))){
            revert();
        }

        // updating the storage with task responses
        allTaskResponses[msg.sender][referenceTaskIndex] = signature;

        // emitting event
        //emit AuditTaskResponded(referenceTaskIndex, task, msg.sender);
    }


    function getConfirmations(Task calldata task) external{

    }
}