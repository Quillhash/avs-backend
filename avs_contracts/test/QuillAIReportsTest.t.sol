// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../src/QuillAIReports.sol";
import "lib/openzeppelin-contracts/contracts/access/AccessControl.sol";

contract QuillAIReportsTest is Test {
    QuillAIReports reports;
    address admin;
    address auditor1;
    address auditor2;
    address user1;
    address user2;
    address nonAuditor;

    event ContractSubmitted(
        uint256 indexed submissionId,
        address indexed owner,
        address contractAddress,
        bool proxyContract,
        uint256 timestamp
    );

    event AuditCompleted(
        uint256 indexed submissionId,
        string reportIPFSHash,
        uint8 riskScore,
        uint256 timestamp
    );
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);

    function setUp() public {
        // Set up test addresses
        admin = address(0x1);
        auditor1 = address(0x2);
        auditor2 = address(0x3);
        user1 = address(0x4);
        user2 = address(0x5);
        nonAuditor = address(0x6);

        // Deploy the QuillAIReports contract with admin as msg.sender
        vm.startPrank(admin);
        reports = new QuillAIReports();
        vm.stopPrank();

        // Grant AUDITOR_ROLE to auditor1
        vm.startPrank(admin);
        reports.addAuditor(auditor1);
        vm.stopPrank();
    }

    function testSubmitContract() public {
        // user1 submits a contract
        vm.startPrank(user1);
        reports.submitContract(address(0x100), false);

        // Check that submissionCounter increased
        uint256 submissionId = reports.submissionCounter();
        assertEq(submissionId, 1);

        // Retrieve the submission and check the details
        QuillAIReports.Submission memory submission = reports.getSubmission(
            submissionId
        );
        assertEq(submission.owner, user1);
        assertEq(submission.contractAddress, address(0x100));
        assertEq(submission.proxyContract, false);
        assertEq(submission.audited, false);
        vm.stopPrank();
    }

    function testSubmitAuditReport() public {
        // user1 submits a contract
        vm.startPrank(user1);
        reports.submitContract(address(0x100), false);
        uint256 submissionId = reports.submissionCounter();
        vm.stopPrank();

        // auditor1 submits an audit report
        vm.startPrank(auditor1);
        reports.submitAuditReport(submissionId, "QmTestHash", 50);
        vm.stopPrank();

        // Retrieve the audit report and check the details
        QuillAIReports.AuditReport memory report = reports.getAuditReport(
            submissionId
        );
        assertEq(report.reportIPFSHash, "QmTestHash");
        assertEq(report.riskScore, 50);

        // Check that the submission is marked as audited
        QuillAIReports.Submission memory submission = reports.getSubmission(
            submissionId
        );
        assertEq(submission.audited, true);
    }

    function testSubmitAuditReportByNonAuditor() public {
        // user1 submits a contract
        vm.startPrank(user1);
        reports.submitContract(address(0x100), false);
        uint256 submissionId = reports.submissionCounter();
        vm.stopPrank();

        // nonAuditor tries to submit an audit report
        vm.startPrank(nonAuditor);
        vm.expectRevert(
            abi.encodeWithSelector(
                AccessControlUnauthorizedAccount.selector,
                nonAuditor,
                reports.AUDITOR_ROLE()
            )
        );
        reports.submitAuditReport(submissionId, "QmTestHash", 50);
        vm.stopPrank();
    }

    function testAddAndRemoveAuditor() public {
        // admin adds auditor2
        vm.startPrank(admin);
        reports.addAuditor(auditor2);
        vm.stopPrank();

        // Check that auditor2 has the AUDITOR_ROLE
        bool hasRole = reports.hasRole(reports.AUDITOR_ROLE(), auditor2);
        assertTrue(hasRole);

        // admin removes auditor1
        vm.startPrank(admin);
        reports.removeAuditor(auditor1);
        vm.stopPrank();

        // Check that auditor1 no longer has the AUDITOR_ROLE
        hasRole = reports.hasRole(reports.AUDITOR_ROLE(), auditor1);
        assertFalse(hasRole);
    }

    function testGetAuditReportNotAvailable() public {
        // user1 submits a contract
        vm.startPrank(user1);
        reports.submitContract(address(0x100), false);
        uint256 submissionId = reports.submissionCounter();
        vm.stopPrank();

        // Try to get audit report before it's submitted
        vm.expectRevert("Audit report not yet available");
        reports.getAuditReport(submissionId);
    }

    function testRiskScoreBounds() public {
        // user1 submits a contract
        vm.startPrank(user1);
        reports.submitContract(address(0x100), false);
        uint256 submissionId = reports.submissionCounter();
        vm.stopPrank();

        // auditor1 tries to submit an audit report with invalid risk score (>100)
        vm.startPrank(auditor1);
        vm.expectRevert("Risk score must be between 0 and 100");
        reports.submitAuditReport(submissionId, "QmTestHash", 150);

        // auditor1 tries to submit an audit report with valid risk score
        reports.submitAuditReport(submissionId, "QmTestHash", 100);
        vm.stopPrank();
    }

    function testOnlyAdminCanAddAuditor() public {
        // non-admin tries to add auditor2
        vm.startPrank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AccessControlUnauthorizedAccount.selector,
                user1,
                reports.DEFAULT_ADMIN_ROLE()
            )
        );
        reports.addAuditor(auditor2);
        vm.stopPrank();
    }

    function testOnlyAdminCanRemoveAuditor() public {
        // non-admin tries to remove auditor1
        vm.startPrank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AccessControlUnauthorizedAccount.selector,
                user1,
                reports.DEFAULT_ADMIN_ROLE()
            )
        );
        reports.removeAuditor(auditor1);
        vm.stopPrank();
    }

    function testInvalidSubmissionId() public {
        // Try to submit an audit report for non-existing submission
        vm.startPrank(auditor1);
        vm.expectRevert("Invalid submission ID");
        reports.submitAuditReport(999, "QmTestHash", 50);
        vm.stopPrank();
    }

    function testAuditReportAlreadySubmitted() public {
        // user1 submits a contract
        vm.startPrank(user1);
        reports.submitContract(address(0x100), false);
        uint256 submissionId = reports.submissionCounter();
        vm.stopPrank();

        // auditor1 submits an audit report
        vm.startPrank(auditor1);
        reports.submitAuditReport(submissionId, "QmTestHash", 50);

        // Try to submit another audit report for the same submission
        vm.expectRevert("Audit report already submitted");
        reports.submitAuditReport(submissionId, "QmTestHash2", 60);
        vm.stopPrank();
    }

    function testContractSubmittedEvent() public {
        // user1 submits a contract
        vm.startPrank(user1);
        vm.expectEmit(true, true, true, true);
        emit ContractSubmitted(
            1,
            user1,
            address(0x100),
            false,
            block.timestamp
        );
        reports.submitContract(address(0x100), false);
        vm.stopPrank();
    }

    function testAuditCompletedEvent() public {
        // user1 submits a contract
        vm.startPrank(user1);
        reports.submitContract(address(0x100), false);
        uint256 submissionId = reports.submissionCounter();
        vm.stopPrank();

        // auditor1 submits an audit report
        vm.startPrank(auditor1);
        vm.expectEmit(true, true, true, true);
        emit AuditCompleted(submissionId, "QmTestHash", 50, block.timestamp);
        reports.submitAuditReport(submissionId, "QmTestHash", 50);
        vm.stopPrank();
    }
}
