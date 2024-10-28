// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IHelloWorldServiceManager {

    event AuditTaskCreated(
        uint32 indexed taskIndex, 
        Task task
    );

    event AuditTaskResponded(
        uint32 indexed taskIndex, 
        Task task, 
        address operator, 
        string ipfs
    );


    event InsuranceTaskCreated(
        uint32 indexed taskIndex, 
        Task task
    );

    event InsuranceTaskResponded(
        uint32 indexed taskIndex, 
        Task task, 
        address operator,
        bool approved
    );

    event AuditReportVerified(
        uint32 indexed taskIndex,
        address indexed contractAddress,
        address verifier,
        bool approved
    );

    struct Task {
        address contractAddress;
        uint32 taskCreatedBlock;
        address createdBy;
    }

    function createNewAuditTask(
        address contractAddress
    ) external returns (Task memory);

    function createNewInsuranceTask(
        address contractAddress
    ) external returns (Task memory);

    function respondToAuditTask(
        Task calldata task,
        string memory ipfs,
        uint32 referenceTaskIndex,
        bytes memory signature
    ) external;

    function respondToInsuranceTask(
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes memory signature,
        bool approved
    ) external;
}