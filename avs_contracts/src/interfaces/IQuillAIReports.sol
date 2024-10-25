// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
interface IQuillAIReports {
    function getAuditReport(
        uint256 _submissionId
    )
        external
        view
        returns (
            string memory reportIPFSHash,
            uint8 riskScore,
            uint256 timestamp
        );
}
