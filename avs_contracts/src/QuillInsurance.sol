// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// Importing OpenZeppelin's ERC20 interface and SafeERC20 library
// import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
// import "@openzeppelin/contracts/access/AccessControl.sol";
import {QuillAIReports} from "./QuillAIReports.sol";

contract QuillInsurance is QuillAIReports {
    // using SafeERC20 for IERC20;

    // bytes32 public constant INSURER_ROLE = keccak256("INSURER_ROLE");

    uint256 public policyCounter;

    enum PolicyStatus {
        Inactive,
        Active,
        ClaimFiled,
        ClaimApproved,
        ClaimDenied
    }

    struct Policy {
        uint256 policyId;
        address owner;
        uint256 submissionId;
        uint8 riskScore;
        uint256 coverageAmount;
        uint256 premiumAmount;
        uint256 startTime;
        uint256 endTime;
        PolicyStatus status;
    }

    struct Claim {
        uint256 claimId;
        uint256 policyId;
        string evidenceIPFSHash;
        uint256 timestamp;
        bool processed;
        bool approved;
    }

    mapping(uint256 => Policy) public policies;
    mapping(uint256 => Claim) public claims;

    event PolicyCreated(
        uint256 indexed policyId,
        address indexed owner,
        uint256 submissionId,
        uint256 coverageAmount,
        uint256 premiumAmount,
        uint256 startTime,
        uint256 endTime
    );

    event PremiumPaid(
        uint256 indexed policyId,
        address indexed owner,
        uint256 premiumAmount
    );

    event ClaimFiled(
        uint256 indexed claimId,
        uint256 indexed policyId,
        string evidenceIPFSHash,
        uint256 timestamp
    );

    event ClaimProcessed(
        uint256 indexed claimId,
        uint256 indexed policyId,
        bool approved
    );

    event Payout(
        uint256 indexed policyId,
        address indexed owner,
        uint256 payoutAmount
    );

    constructor() {
        // quillToken = IQuillToken(_quillTokenAddress);
        // _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        // _grantRole(INSURER_ROLE, msg.sender);
    }

    /**
     * @dev Creates a new insurance policy based on the audit report.
     * @param _submissionId ID of the audited contract submission.
     * @param _coverageAmount Desired coverage amount.
     * @param _duration Duration of the policy in seconds.
     */
    function createPolicy(
        uint256 _submissionId,
        uint256 _coverageAmount,
        uint256 _duration
    ) internal {
        // Retrieve audit report
        uint8 riskScore = getAuditReport(_submissionId).riskScore;

        // Calculate premium
        uint256 premiumAmount = calculatePremium(
            riskScore,
            _coverageAmount,
            _duration
        );

        policyCounter++;
        policies[policyCounter] = Policy({
            policyId: policyCounter,
            owner: msg.sender,
            submissionId: _submissionId,
            riskScore: riskScore,
            coverageAmount: _coverageAmount,
            premiumAmount: premiumAmount,
            startTime: block.timestamp,
            endTime: block.timestamp + _duration,
            status: PolicyStatus.Inactive
        });

        emit PolicyCreated(
            policyCounter,
            msg.sender,
            _submissionId,
            _coverageAmount,
            premiumAmount,
            block.timestamp,
            block.timestamp + _duration
        );
    }

    /**
     * @dev Allows the policy owner to pay the premium and activate the policy.
     * @param _policyId ID of the policy to activate.
     */
    function payPremium(uint256 _policyId) internal {
        Policy storage policy = policies[_policyId];
        require(
            msg.sender == policy.owner,
            "Only policy owner can pay the premium"
        );

        // Transfer Quill tokens as premium payment
        quillToken.transferFrom(
            msg.sender,
            address(this),
            policy.premiumAmount
        );

        policy.endTime = block.timestamp + (policy.endTime - policy.startTime);
        policy.startTime = block.timestamp;
        policy.status = PolicyStatus.Active;

        emit PremiumPaid(_policyId, msg.sender, policy.premiumAmount);
    }

    /**
     * @dev Calculates the premium based on risk score, coverage amount, and duration.
     * @param _riskScore Risk score from the audit.
     * @param _coverageAmount Desired coverage amount.
     * @param _duration Duration of the policy in seconds.
     * @return premium Premium amount to be paid.
     */
    function calculatePremium(
        uint8 _riskScore,
        uint256 _coverageAmount,
        uint256 _duration
    ) public pure returns (uint256 premium) {
        // Simplified premium calculation formula
        // Premium = (Risk Score %) * Coverage Amount * (Duration / 1 year)
        // Risk Score is between 0-100, so we divide by 100 to get percentage
        uint256 riskFactor = uint256(_riskScore) * 1e16; // Convert to 18 decimals
        uint256 durationFactor = (_duration * 1e18) / 31536000; // Seconds in a year

        premium = (_coverageAmount * riskFactor * durationFactor) / 1e36; // Adjusting decimals
        return premium;
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
        Policy storage policy = policies[_policyId];
        require(
            msg.sender == policy.owner,
            "Only policy owner can file a claim"
        );
        require(policy.status == PolicyStatus.Active, "Policy is not active");
        require(block.timestamp <= policy.endTime, "Policy has expired");

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
     * @dev Allows the insurer to process a claim.
     * @param _claimId ID of the claim.
     */
    function processClaim(uint256 _claimId) public {
        require(claimApprove[_claimId], "Claim is not approved");
        Claim storage claim = claims[_claimId];
        Policy storage policy = policies[claim.policyId];

        require(!claim.processed, "Claim already processed");

        claim.processed = true;
        claim.approved = true;

        if (true) {
            policy.status = PolicyStatus.ClaimApproved;
            // Payout the coverage amount to the policy owner
            quillToken.transfer(policy.owner, policy.coverageAmount);

            emit Payout(policy.policyId, policy.owner, policy.coverageAmount);
        } else {
            policy.status = PolicyStatus.ClaimDenied;
        }

        emit ClaimProcessed(_claimId, claim.policyId, true);
    }

    /**
     * @dev Allows the insurer to update policy status, e.g., set to expired.
     * @param _policyId ID of the policy.
     * @param _status New status of the policy.
     */
    function updatePolicyStatus(
        uint256 _policyId,
        PolicyStatus _status
    ) internal {
        Policy storage policy = policies[_policyId];
        policy.status = _status;
    }

    /**
     * @dev Retrieves policy details.
     * @param _policyId ID of the policy.
     * @return Policy struct containing policy details.
     */
    function getPolicy(uint256 _policyId) public view returns (Policy memory) {
        return policies[_policyId];
    }

    function getClaim(uint256 claimId) public view returns (Claim memory) {
        return claims[claimId];
    }

    // /**
    //  * @dev Assigns the INSURER_ROLE to an address.
    //  * @param _insurer Address to be assigned as an insurer.
    //  */
    // function addInsurer(address _insurer) public onlyRole(DEFAULT_ADMIN_ROLE) {
    //     grantRole(INSURER_ROLE, _insurer);
    // }

    // /**
    //  * @dev Revokes the INSURER_ROLE from an address.
    //  * @param _insurer Address to be revoked as an insurer.
    //  */
    // function removeInsurer(
    //     address _insurer
    // ) public onlyRole(DEFAULT_ADMIN_ROLE) {
    //     revokeRole(INSURER_ROLE, _insurer);
    // }
}
