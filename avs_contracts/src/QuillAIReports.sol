// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// Importing OpenZeppelin's AccessControl for role management
import "lib/openzeppelin-contracts/contracts/access/AccessControl.sol";

contract quillAIReports is AccessControl {
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

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

    // Mapping from submission ID to Submission details
    mapping(uint256 => Submission) public submissions;

    // Mapping from submission ID to AuditReport
    mapping(uint256 => AuditReport) public auditReports;

    uint256 public submissionCounter;

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

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AUDITOR_ROLE, msg.sender);
    }

    /**
     * @dev Allows a smart contract owner to submit their contract for auditing.
     * @param _contractAddress address of smart contract to be audited.
     * @param _proxyContract upgradable smart contrat or not.
     */
    function submitContract(
        address _contractAddress,
        bool _proxyContract
    ) public {
        submissionCounter++;
        submissions[submissionCounter] = Submission({
            owner: msg.sender,
            contractAddress: _contractAddress,
            proxyContract: _proxyContract,
            timestamp: block.timestamp,
            audited: false
        });

        emit ContractSubmitted(
            submissionCounter,
            msg.sender,
            _contractAddress,
            _proxyContract,
            block.timestamp
        );
    }

    /**
     * @dev Allows an auditor to submit an audit report.
     * @param _submissionId ID of the submission being audited.
     * @param _reportIPFSHash IPFS hash of the audit report.
     * @param _riskScore Risk score assigned to the contract.
     */
    function submitAuditReport(
        uint256 _submissionId,
        string memory _reportIPFSHash,
        uint8 _riskScore
    ) public onlyRole(AUDITOR_ROLE) {
        require(
            submissions[_submissionId].owner != address(0),
            "Invalid submission ID"
        );
        require(
            !submissions[_submissionId].audited,
            "Audit report already submitted"
        );
        require(_riskScore <= 100, "Risk score must be between 0 and 100");

        auditReports[_submissionId] = AuditReport({
            reportIPFSHash: _reportIPFSHash,
            riskScore: _riskScore,
            timestamp: block.timestamp
        });

        submissions[_submissionId].audited = true;

        emit AuditCompleted(
            _submissionId,
            _reportIPFSHash,
            _riskScore,
            block.timestamp
        );
    }

    /**
     * @dev Retrieves the audit report for a given submission.
     * @param _submissionId ID of the submission.
     * @return AuditReport containing the IPFS hash, risk score, and timestamp.
     */
    function getAuditReport(
        uint256 _submissionId
    ) public view returns (AuditReport memory) {
        require(
            submissions[_submissionId].audited,
            "Audit report not yet available"
        );
        return auditReports[_submissionId];
    }
    function getSubmission(
        uint256 _submissionId
    ) public view returns (Submission memory) {
        return submissions[_submissionId];
    }

    /**
     * @dev Assigns the AUDITOR_ROLE to an address.
     * @param _auditor Address to be assigned as an auditor.
     */
    function addAuditor(address _auditor) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(AUDITOR_ROLE, _auditor);
    }

    /**
     * @dev Revokes the AUDITOR_ROLE from an address.
     * @param _auditor Address to be revoked as an auditor.
     */
    function removeAuditor(
        address _auditor
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(AUDITOR_ROLE, _auditor);
    }
}
