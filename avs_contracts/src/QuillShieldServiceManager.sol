// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;
//   ____          _  _  _             _____   _   _        _                           _
//  / __ \        (_)| || |     /\    |_   _| | \ | |      | |                         | |
// | |  | | _   _  _ | || |    /  \     | |   |  \| |  ___ | |_ __      __  ___   _ __ | | __
// | |  | || | | || || || |   / /\ \    | |   | . ` | / _ \| __|\ \ /\ / / / _ \ | '__|| |/ /
// | |__| || |_| || || || |  / ____ \  _| |_  | |\  ||  __/| |_  \ V  V / | (_) || |   |   <
//  \___\_\ \__,_||_||_||_| /_/    \_\|_____| |_| \_| \___| \__|  \_/\_/   \___/ |_|   |_|\_\
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#**#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+-..+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*=.   =%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@#=.    :#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@#-      :#@@@@@@@@@@@%#+=--------==+*%@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@+.      .*@@@@@@@@@@@@@@@@@@@-.          .-+%@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@+        :%@@@@@@@@@@@@@@@@@@@@@@#-            :*@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@#.        :@@@@@@@@@@@@@@@@@@@@@@@@@@*             .#@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@=          #@@@@@@@@@@@@@@@@@@@@@@@@@@@=              #@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@+          :@@@@@@@@@@@@@@@@@@@@@@@@@@@@#               %@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@%           -@@@@%@@@@@@@@@@@@@@@@@%@@@@@*               -@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@=           :@@@@+.---------------:=@@@@@-                @@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@:            %@@@+                 =@@@@#                 @@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@-            -@@@+:+++++++++++++++-=@@@%.                =@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@*             =@@@@@@@@@@@@@@@@@@@@@@@%.                -@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@:             -@@@@@@@@@@@@@@@@@@@@@#                 =@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@%.             .%@@@@@@@@@@@@@@@@@@+                .#@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@=              =@@@@@@@@@@@@@@@%:               .*@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@#:             .+@@@@@@@@@@@@+               =#@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@#:             .+@@@@@@@@#.             -#@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@#-             .+@@@@%-           :+#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@*-             -*-        :=+#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#=:              .:=*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*=:          .=#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+-.         -*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+-:       :=#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#+=:.    :+#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*+=:. :=*%@@@@@@@@@@@@@@@@@@@@@@@@
// @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#*++*#@@@@@@@@@@@@@@@@@@@@@

import {ECDSAServiceManagerBase} from "@eigenlayer-middleware/src/unaudited/ECDSAServiceManagerBase.sol";
import {ECDSAStakeRegistry} from "@eigenlayer-middleware/src/unaudited/ECDSAStakeRegistry.sol";
import {IServiceManager} from "@eigenlayer-middleware/src/interfaces/IServiceManager.sol";
import {ECDSAUpgradeable} from "@openzeppelin-upgrades/contracts/utils/cryptography/ECDSAUpgradeable.sol";
import {IERC1271Upgradeable} from "@openzeppelin-upgrades/contracts/interfaces/IERC1271Upgradeable.sol";
import "@eigenlayer/contracts/libraries/BytesLib.sol";
import {IQuillShieldServiceManager} from "./interfaces/IQuillShieldServiceManager.sol";

import "@openzeppelin/contracts/utils/Strings.sol";
import "@eigenlayer/contracts/interfaces/IRewardsCoordinator.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {QuillInsurance} from "./QuillInsurance.sol";
import {OperatorAllowlist} from "./OperatorAllowlist.sol";
import "@openzeppelin-upgrades/contracts/proxy/utils/Initializable.sol";

/**
 * @title Primary entrypoint for procuring services from HelloWorld.
 * @author Eigen Labs, Inc.
 */
contract QuillShieldServiceManager is
    Initializable,
    OperatorAllowlist,
    ECDSAServiceManagerBase,
    QuillInsurance,
    IQuillShieldServiceManager
{
    using ECDSAUpgradeable for bytes32;
    using BytesLib for bytes;

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
    mapping(uint32 => string) public indexToAuditReports; // taskIndex => IPFS hash

    // Approval and disapproval counts per task index
    mapping(uint32 => uint256) public approvals; // taskIndex => approval count
    mapping(uint32 => uint256) public disapprovals; // taskIndex => disapproval count
    mapping(uint32 => bool) public insuranceTaskCheck;

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
        address __avsDirectory,
        address __stakeRegistry,
        address __rewardsCoordinator,
        address __delegationManager
    )
        ECDSAServiceManagerBase(
            __avsDirectory,
            __stakeRegistry,
            __rewardsCoordinator,
            __delegationManager
        )
    {}

    function initialize(
        address initialOwner_,
        address rewardsInitiator_,
        address allowlistManager_
    ) external initializer {
        __ServiceManagerBase_init(initialOwner_, rewardsInitiator_);
        __OperatorAllowlist_init(allowlistManager_, true);
    }

    /* FUNCTIONS */
    // NOTE: this function creates new audit task, assigns it a taskId
    function createNewAuditTask(
        address contractAddress
    ) external returns (Task memory) {
        latestTaskNum += 1;
        submitContract(contractAddress, false);
        // create a new task struct
        Task memory auditTask;
        auditTask.contractAddress = contractAddress;
        auditTask.taskCreatedBlock = uint32(block.number);
        auditTask.createdBy = msg.sender;

        // store hash of task onchain, emit event, and increase taskNum, this hash is later used to verify whether the responded task actually exists
        allTaskHashes[latestTaskNum] = keccak256(abi.encode(auditTask));

        // emit audit task event
        emit AuditTaskCreated(latestTaskNum, auditTask);

        return auditTask;
    }

    function respondToAuditTask(
        Task calldata task,
        string memory ipfs,
        uint32 referenceTaskIndex,
        bytes memory signature,
        uint8 riskScore
    ) external onlyOperator {
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
        // bytes32 messageHash = keccak256(abi.encodePacked(ipfs));
        // bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        // bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;
        // if (
        //     !(magicValue ==
        //         ECDSAStakeRegistry(stakeRegistry).isValidSignature(
        //             ethSignedMessageHash,
        //             signature
        //         ))
        // ) {
        //     revert();
        // }
        submitAuditReport(uint256(referenceTaskIndex), ipfs, riskScore);
        // Store the operator's response (signature)
        allTaskResponses[referenceTaskIndex] = signature;

        //store the ipfs hash of the audit report associated with task
        indexToAuditReports[referenceTaskIndex] = ipfs;

        // emitting event
        emit AuditTaskResponded(referenceTaskIndex, task, msg.sender, ipfs);
    }

    function verifyAuditReport(
        Task calldata task,
        uint32 referenceTaskIndex,
        bool approval
    ) external onlyOperator {
        require(
            keccak256(abi.encode(task)) == allTaskHashes[referenceTaskIndex],
            "supplied task does not match the one recorded in the contract"
        );

        // Check if the operator has responded to this task
        require(
            bytes(indexToAuditReports[referenceTaskIndex]).length != 0,
            "Operator has not responded"
        );

        // Check if the verifier has already verified this operator's response
        require(
            !hasVerified[referenceTaskIndex][msg.sender],
            "Already verified"
        );

        // Mark as verified
        hasVerified[referenceTaskIndex][msg.sender] = true;

        // Update approval or disapproval count
        if (approval) {
            approvals[referenceTaskIndex] += 1;
        } else {
            disapprovals[referenceTaskIndex] += 1;
        }

        // Emit verification event
        emit AuditReportVerified(
            task.contractAddress,
            referenceTaskIndex,
            // operator,
            // msg.sender,
            approval
        );
    }

    /* FUNCTIONS */
    // NOTE: this function creates new audit task, assigns it a taskId
    function createNewInsuranceTask(
        // address contractAddress
        uint256 _submissionId,
        uint256 _coverageAmount,
        uint256 _duration
    ) external returns (Task memory) {
        address contractAddress = getSubmission(_submissionId).contractAddress;
        createPolicy(_submissionId, _coverageAmount, _duration);
        payPremium(_submissionId);
        // create a new task struct
        Task memory insuranceTask;
        insuranceTask.contractAddress = contractAddress;
        insuranceTask.taskCreatedBlock = uint32(block.number);
        insuranceTask.createdBy = msg.sender;

        // store hash of task onchain, emit event, and increase taskNum
        // allTaskHashes[latestTaskNum] = keccak256(abi.encode(insuranceTask));
        // allTaskHashes[uint32(_submissionId)] = keccak256(
        //     abi.encode(insuranceTask)
        // );
        // emit InsuranceTaskCreated(latestTaskNum, insuranceTask);
        emit InsuranceTaskCreated(uint32(_submissionId), insuranceTask);
        // latestTaskNum += 1;

        return insuranceTask;
    }

    function respondToInsuranceTask(
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes memory signature,
        bool approved
    ) external onlyOperator {
        // check that the task is valid, hasn't been responsed yet, and is being responded in time
        require(
            policies[referenceTaskIndex].owner != address(0),
            "policy has not created"
        );

        // // The message that was signed
        // bytes32 messageHash = keccak256(abi.encode(approved));
        // bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
        // bytes4 magicValue = IERC1271Upgradeable.isValidSignature.selector;
        // if (!(magicValue == ECDSAStakeRegistry(stakeRegistry).isValidSignature(ethSignedMessageHash,signature))){
        //     revert();
        // }

        // updating the storage with task responses
        insuranceTaskCheck[referenceTaskIndex] = approved;

        if (!approved) {
            uint256 premium = getPolicy(uint256(referenceTaskIndex))
                .premiumAmount;
            address owner = getPolicy(uint256(referenceTaskIndex)).owner;
            //logic for release of tokens
            quillToken.transfer(owner, premium);
        }

        emit InsuranceTaskResponded(
            referenceTaskIndex,
            task,
            msg.sender,
            approved
        );
        // emitting event
        //emit AuditTaskResponded(referenceTaskIndex, task, msg.sender);
    }

    /**
     * @dev Allows the policy owner to file a claim.
     * @param _policyId ID of the policy.
     * @param _evidenceIPFSHash IPFS hash of the evidence supporting the claim.
     */
    function fileClaim(
        uint256 _policyId,
        string memory _evidenceIPFSHash
    ) public {
        require(
            insuranceTaskCheck[uint32(_policyId)],
            "operator not approved insurance"
        );
        Policy storage policy = policies[_policyId];
        // require(
        //     msg.sender == policy.owner,
        //     "Only policy owner can file a claim"
        // );
        // require(policy.status == PolicyStatus.Active, "Policy is not active");
        // require(block.timestamp <= policy.endTime, "Policy has expired");

        uint256 claimId = _policyId; // For simplicity, use policyId as claimId
        claims[claimId] = Claim({
            claimId: claimId,
            policyId: _policyId,
            evidenceIPFSHash: _evidenceIPFSHash,
            timestamp: block.timestamp,
            processed: false,
            approved: false
        });

        policy.status = PolicyStatus.ClaimFiled;

        emit ClaimFiled(claimId, _policyId, _evidenceIPFSHash, block.timestamp);
    }

    /**
     * @dev Allows the operator to process a claim.
     * @param _claimId ID of the claim.
     */
    function processClaim(uint256 _claimId) public onlyOperator {
        Claim storage claim = claims[_claimId];
        Policy storage policy = policies[claim.policyId];

        require(!claim.processed, "Claim already processed");

        claim.processed = true;
        claim.approved = true;

        policy.status = PolicyStatus.ClaimApproved;
        // Payout the coverage amount to the policy owner
        quillToken.transfer(policy.owner, policy.coverageAmount);

        emit Payout(policy.policyId, policy.owner, policy.coverageAmount);

        emit ClaimProcessed(_claimId, claim.policyId, true);
    }

    // Getter functions for approvals and disapprovals per task index (per audit report)
    function getApprovalCount(
        uint32 taskIndex
    ) external view returns (uint256) {
        return approvals[taskIndex];
    }

    function getDisapprovalCount(
        uint32 taskIndex
    ) external view returns (uint256) {
        return disapprovals[taskIndex];
    }

    // Function to get the audit report (IPFS hash) for a task index
    function getAuditReport(
        uint32 taskIndex
    ) external view returns (string memory) {
        return indexToAuditReports[taskIndex];
    }
}
