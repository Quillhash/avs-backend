// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

interface IQuillShieldServiceManager {
    event AuditTaskCreated(uint32 indexed taskIndex, Task task);

    event AuditTaskResponded(uint32 indexed taskIndex, Task task, address operator);


    event InsuranceTaskCreated(uint32 indexed taskIndex, Task task);

    event InsuranceTaskResponded(uint32 indexed taskIndex, Task task, address operator);

    struct Task {
        address contractAddress;
        uint32 taskCreatedBlock;
        address createdBy;
    }

    function latestTaskNum() external view returns (uint32);

    function allTaskHashes(
        uint32 taskIndex
    ) external view returns (bytes32);

    function allTaskResponses(
        address operator,
        uint32 taskIndex
    ) external view returns (bytes memory);

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
        bytes calldata signature
    ) external;

    function respondToInsuranceTask(
        Task calldata task,
        uint32 referenceTaskIndex,
        bytes calldata signature
    ) external;
}