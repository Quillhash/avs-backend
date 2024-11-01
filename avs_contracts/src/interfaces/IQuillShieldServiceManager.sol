// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IQuillShieldServiceManager {
    event AuditTaskCreated(uint32 indexed taskIndex, Task task);

    event AuditTaskResponded(
        uint32 indexed taskIndex,
        Task task,
        address operator,
        string ipfs
    );

    event InsuranceTaskCreated(uint32 indexed taskIndex, Task task);

    event InsuranceTaskResponded(
        uint32 indexed taskIndex,
        Task task,
        address operator,
        bool approved
    );

    event AuditReportVerified(
        address indexed contractAddress,
        uint32 indexed taskIndex,
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
        // address contractAddress
        uint256 _submissionId,
        uint256 _coverageAmount,
        uint256 _duration
    ) external returns (Task memory);

    function respondToAuditTask(
        Task calldata task,
        string memory ipfs,
        uint32 referenceTaskIndex,
        bytes memory signature,
        uint8 riskScore
    ) external;

    function respondToInsuranceTask(
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes memory signature,
        bool approved
    ) external;
}
