// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract ClaimApproval {
    mapping(uint256 => bool) public claimApprove;
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public requiredApprovals;

    // Tracks approvals for each claim: claimId => (owner => approved)
    mapping(uint256 => mapping(address => bool)) public OwnerApproval;
    // Counts the number of approvals for each claim
    mapping(uint256 => uint256) public approvalCounts;

    /**
     * @dev Allows an owner to approve a claim. When the number of approvals reaches the required threshold,
     * the claim becomes approved.
     * @param claimId The ID of the claim to approve.
     */
    function approveClaim(uint256 claimId) public {
        require(isOwner[msg.sender], "Caller is not an owner");
        require(
            !OwnerApproval[claimId][msg.sender],
            "Caller has already approved this claim"
        );
        require(!claimApprove[claimId], "Claim is already approved");

        OwnerApproval[claimId][msg.sender] = true;
        approvalCounts[claimId] += 1;

        if (approvalCounts[claimId] >= requiredApprovals) {
            claimApprove[claimId] = true;
        }
    }
}
