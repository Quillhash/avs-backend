// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IQuillAIReports {
    struct Submission {
        address owner;
        address contractAddress;
        bool proxyContract;
        uint256 timestamp;
        bool audited;
    }

    struct AuditReport {
        string reportIPFSHash;
        uint8 riskScore; // Risk score between 0-100
        uint256 timestamp;
    }
    function getAuditReport(
        uint256 _submissionId
    ) external view returns (AuditReport memory);
}
