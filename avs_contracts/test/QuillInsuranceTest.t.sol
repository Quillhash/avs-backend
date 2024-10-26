// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/QuillInsurance.sol";
import "../src/QuillToken.sol";
import "../src/QuillAIReports.sol";

contract QuillInsuranceTest is Test {
    QuillToken quillToken;
    QuillAIReports quillAIReports;
    QuillInsurance quillInsurance;

    address admin = address(0x1);
    address auditor = address(0x2);
    address contractOwner = address(0x3);
    address policyOwner = address(0x4);
    address insurer = address(0x5);

    function setUp() public {
        // Deploy QuillToken and mint tokens to policyOwner
        vm.startPrank(admin);
        quillToken = new QuillToken(1_000_000 ether);
        vm.stopPrank();

        // Deploy QuillAIReports
        vm.startPrank(admin);
        quillAIReports = new QuillAIReports();
        // Grant AUDITOR_ROLE to auditor
        quillAIReports.addAuditor(auditor);
        vm.stopPrank();

        // Simulate contractOwner submitting a contract for auditing
        vm.prank(contractOwner);
        quillAIReports.submitContract(address(0x1234), false);

        // Auditor submits audit report
        vm.prank(auditor);
        quillAIReports.submitAuditReport(1, "ipfs://hash", 50); // Risk score 50

        // Deploy QuillInsurance
        vm.startPrank(admin);
        quillInsurance = new QuillInsurance(
            address(quillToken),
            address(quillAIReports)
        );
        // Grant INSURER_ROLE to insurer
        quillInsurance.addInsurer(insurer);
        vm.stopPrank();

        vm.prank(admin);
        quillToken.transfer(address(policyOwner), 1000 ether);
    }

    function testCreatePolicy() public {
        // Policy owner creates a policy based on submission ID 1
        vm.prank(policyOwner);
        quillInsurance.createPolicy(1, 1000 ether, 30 days);

        // Retrieve the policy
        QuillInsurance.Policy memory policy = quillInsurance.getPolicy(1);

        // Check that the policy is created correctly
        assertEq(policy.policyId, 1);
        assertEq(policy.owner, policyOwner);
        assertEq(uint256(policy.riskScore), 50);
        assertGt(policy.premiumAmount, 0);
        assertEq(
            uint256(policy.status),
            uint256(QuillInsurance.PolicyStatus.Inactive)
        );
    }

    function testPayPremium() public {
        // Policy owner creates a policy
        vm.prank(policyOwner);
        quillInsurance.createPolicy(1, 1000 ether, 30 days);

        // Approve the quillInsurance contract to spend policyOwner's tokens
        vm.prank(policyOwner);
        quillToken.approve(address(quillInsurance), type(uint256).max);

        // Policy owner pays the premium
        vm.prank(policyOwner);
        quillInsurance.payPremium(1);

        // Retrieve the policy
        QuillInsurance.Policy memory policy = quillInsurance.getPolicy(1);

        // Check that the policy status is now Active
        assertEq(
            uint256(policy.status),
            uint256(QuillInsurance.PolicyStatus.Active)
        );

        // Check that the premium amount was deducted from policyOwner's balance
        uint256 expectedBalance = 1000 ether - policy.premiumAmount;
        assertEq(quillToken.balanceOf(policyOwner), expectedBalance);

        // Check that the QuillInsurance contract received the premium
        assertEq(
            quillToken.balanceOf(address(quillInsurance)),
            policy.premiumAmount
        );
    }

    function testFileClaim() public {
        // Set up the policy and pay the premium
        vm.prank(policyOwner);
        quillInsurance.createPolicy(1, 1000 ether, 30 days);

        vm.prank(policyOwner);
        quillToken.approve(address(quillInsurance), type(uint256).max);

        vm.prank(policyOwner);
        quillInsurance.payPremium(1);

        // Policy owner files a claim
        vm.prank(policyOwner);
        quillInsurance.fileClaim(1, "ipfs://evidence");

        // Retrieve the policy
        QuillInsurance.Policy memory policy = quillInsurance.getPolicy(1);

        // Check that the policy status is ClaimFiled
        assertEq(
            uint256(policy.status),
            uint256(QuillInsurance.PolicyStatus.ClaimFiled)
        );

        // Retrieve the claim
        QuillInsurance.Claim memory claim = quillInsurance.getClaim(1);

        // Check that the claim is recorded correctly
        assertEq(claim.claimId, 1);
        assertEq(claim.policyId, 1);
        assertEq(claim.evidenceIPFSHash, "ipfs://evidence");
        assertFalse(claim.processed);
    }

    function testProcessApprovedClaim() public {
        // Set up the policy and pay the premium
        vm.prank(policyOwner);
        quillInsurance.createPolicy(1, 1000 ether, 30 days);

        vm.prank(policyOwner);
        quillToken.approve(address(quillInsurance), type(uint256).max);

        vm.prank(policyOwner);
        quillInsurance.payPremium(1);

        // Transfer coverage amount to QuillInsurance contract so it can pay out
        vm.prank(admin);
        quillToken.transfer(address(quillInsurance), 1000 ether);

        // Policy owner files a claim
        vm.prank(policyOwner);
        quillInsurance.fileClaim(1, "ipfs://evidence");
        uint256 balPolOwnerBefore = quillToken.balanceOf(policyOwner);
        // Insurer processes the claim and approves it
        vm.prank(insurer);
        quillInsurance.processClaim(1, true);

        // Retrieve the claim
        QuillInsurance.Claim memory claim = quillInsurance.getClaim(1);

        // Check that the claim is processed and approved
        assertTrue(claim.processed);
        assertTrue(claim.approved);

        // Retrieve the policy
        QuillInsurance.Policy memory policy = quillInsurance.getPolicy(1);

        // Check that the policy status is ClaimApproved
        assertEq(
            uint256(policy.status),
            uint256(QuillInsurance.PolicyStatus.ClaimApproved)
        );

        assertEq(
            quillToken.balanceOf(policyOwner) - balPolOwnerBefore,
            1000 ether
        );

        assertEq(
            quillToken.balanceOf(address(quillInsurance)),
            policy.premiumAmount
        );
    }

    function testProcessDeniedClaim() public {
        // Set up the policy and pay the premium
        vm.prank(policyOwner);
        quillInsurance.createPolicy(1, 1000 ether, 30 days);

        vm.prank(policyOwner);
        quillToken.approve(address(quillInsurance), type(uint256).max);

        vm.prank(policyOwner);
        quillInsurance.payPremium(1);

        // Policy owner files a claim
        vm.prank(policyOwner);
        quillInsurance.fileClaim(1, "ipfs://evidence");

        // Insurer processes the claim and denies it
        vm.prank(insurer);
        quillInsurance.processClaim(1, false);

        // Retrieve the claim
        QuillInsurance.Claim memory claim = quillInsurance.getClaim(1);

        // Check that the claim is processed and denied
        assertTrue(claim.processed);
        assertFalse(claim.approved);

        // Retrieve the policy
        QuillInsurance.Policy memory policy = quillInsurance.getPolicy(1);

        // Check that the policy status is ClaimDenied
        assertEq(
            uint256(policy.status),
            uint256(QuillInsurance.PolicyStatus.ClaimDenied)
        );
    }

    function testCalculatePremium() public {
        uint8 riskScore = 50;
        uint256 coverageAmount = 1000 ether;
        uint256 duration = 30 days;

        uint256 premium = quillInsurance.calculatePremium(
            riskScore,
            coverageAmount,
            duration
        );

        // Manually calculate expected premium
        uint256 riskFactor = uint256(riskScore) * 1e16; // Convert to 18 decimals
        uint256 durationFactor = (duration * 1e18) / 31536000; // Seconds in a year

        uint256 expectedPremium = (coverageAmount *
            riskFactor *
            durationFactor) / 1e36;

        assertEq(premium, expectedPremium);
    }
}
