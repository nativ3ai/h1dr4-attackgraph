// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Exact {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @notice USDC escrow and commitment layer for confidential vulnerability reports.
/// @dev Plaintext reports and decryption keys never enter this contract. Target ownership,
/// submission admission, validator verdicts, and key-release destinations are explicitly bound.
contract H1DR4ProofVault {
    enum SubmissionStatus { COMMITTED, VALIDATED, REJECTED, REWARD_RESERVED, PAID, EXPIRED }
    enum Severity { LOW, MEDIUM, HIGH, CRITICAL }

    struct Program {
        address owner;
        bytes32 targetHash;
        bytes32 scopeHash;
        uint64 authorizationEpoch;
        bool active;
        uint16 openSubmissions;
        uint16 maxOpenSubmissions;
        uint128 available;
        uint128 locked;
        uint128[4] rewards;
    }

    struct Submission {
        uint256 programId;
        address researcher;
        address owner;
        bytes32 targetHash;
        bytes32 reportCiphertextHash;
        bytes32 reportCommitment;
        bytes32 ownerKeyHash;
        bytes32 verdictHash;
        Severity severity;
        SubmissionStatus status;
        uint128 reservedMaximum;
        uint128 reward;
        uint64 submittedAt;
        uint64 decisionDeadline;
        uint64 authorizationEpoch;
        uint32 validatorSetId;
        bool exists;
    }

    IERC20Exact public immutable paymentToken;
    uint64 public immutable decisionWindow;
    address public immutable governor;
    bool public paused;
    uint32 public currentValidatorSetId;
    uint256 public nextProgramId = 1;
    uint256 public nextSubmissionId = 1;

    mapping(uint32 => mapping(address => bool)) public validators;
    mapping(uint32 => uint8) public validatorThresholds;
    mapping(uint32 => bool) public validatorSetDisabled;
    mapping(address => bytes32) public ownerKeyHashes;
    mapping(bytes32 => address) public targetOwners;
    mapping(bytes32 => uint64) public targetAuthorizationEpochs;
    mapping(uint256 => Program) public programs;
    mapping(uint256 => Submission) public submissions;
    mapping(uint256 => mapping(address => bool)) public validatorVoted;
    mapping(uint256 => mapping(bytes32 => uint8)) public verdictVotes;
    mapping(uint256 => mapping(bytes32 => bool)) public usedCommitments;
    mapping(bytes32 => uint64) public submissionPermits;
    mapping(uint256 => uint256) public privatePool;
    mapping(uint256 => mapping(address => uint256)) public privateContributions;
    mapping(uint256 => bool) public keyReleaseCompleted;

    uint256 private entered;

    error Unauthorized();
    error InvalidInput();
    error InvalidState();
    error InsufficientEscrow();
    error TransferFailed();
    error DuplicateVote();
    error DuplicateCommitment();
    error MessageTooLarge();
    error Paused();

    event GovernanceConfigured(address indexed governor);
    event PauseChanged(bool paused);
    event ValidatorSetConfigured(uint32 indexed validatorSetId, uint8 threshold, address[] validators);
    event ValidatorSetDisabled(uint32 indexed validatorSetId);
    event EncryptionKeyRegistered(address indexed owner, bytes32 indexed ownerKeyHash);
    event TargetOwnerAuthorized(
        bytes32 indexed targetHash, address indexed owner, uint64 authorizationEpoch
    );
    event TargetOwnerRevoked(
        bytes32 indexed targetHash, address indexed owner, uint64 authorizationEpoch
    );
    event SubmissionAuthorized(bytes32 indexed permitDigest, uint64 expiresAt);
    event SubmissionAuthorizationCancelled(bytes32 indexed permitDigest);
    event ProgramCreated(
        uint256 indexed programId,
        address indexed owner,
        bytes32 indexed targetHash,
        bytes32 scopeHash,
        uint16 maxOpenSubmissions
    );
    event ProgramFunded(uint256 indexed programId, address indexed funder, uint256 amount);
    event ProgramDeactivated(uint256 indexed programId);
    event ProgramFundsWithdrawn(uint256 indexed programId, address indexed owner, uint256 amount);
    event SubmissionCommitted(
        uint256 indexed submissionId,
        uint256 indexed programId,
        address indexed researcher,
        address owner,
        bytes32 targetHash,
        bytes32 reportCiphertextHash,
        bytes32 reportCommitment,
        uint64 decisionDeadline,
        uint32 validatorSetId,
        uint64 authorizationEpoch
    );
    event PrivateSubmissionFunded(
        uint256 indexed submissionId, address indexed funder, uint256 amount
    );
    event PrivateContributionRefunded(
        uint256 indexed submissionId, address indexed funder, uint256 amount
    );
    event ValidatorVote(
        uint256 indexed submissionId,
        address indexed validator,
        bytes32 indexed verdictDigest,
        bool valid,
        Severity severity,
        bytes32 verdictHash
    );
    event SubmissionValidated(
        uint256 indexed submissionId, Severity severity, bytes32 verdictHash
    );
    event SubmissionRejected(uint256 indexed submissionId, bytes32 verdictHash);
    event SubmissionExpired(uint256 indexed submissionId);
    event RewardReserved(uint256 indexed submissionId, address indexed researcher, uint256 amount);
    event RewardPaid(
        uint256 indexed submissionId,
        address indexed researcher,
        address indexed recipient,
        uint256 amount
    );
    event KeyReleaseDeferred(uint256 indexed submissionId, bytes32 indexed targetHash);
    event ReportOwnerRebound(
        uint256 indexed submissionId,
        address indexed previousOwner,
        address indexed currentOwner,
        uint64 authorizationEpoch
    );
    event KeyReleaseAuthorized(
        uint256 indexed submissionId, address indexed owner, bytes32 indexed ownerKeyHash
    );
    event EncryptedMessage(
        uint256 indexed submissionId,
        address indexed sender,
        address indexed recipient,
        bytes32 messageHash,
        bytes ciphertext
    );

    modifier onlyGovernor() {
        if (msg.sender != governor) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert Paused();
        _;
    }

    modifier nonReentrant() {
        if (entered == 1) revert InvalidState();
        entered = 1;
        _;
        entered = 0;
    }

    constructor(
        address token,
        address initialGovernor,
        address[] memory initialValidators,
        uint8 threshold,
        uint64 initialDecisionWindow
    ) {
        if (
            token == address(0) || token.code.length == 0 || initialGovernor == address(0)
                || initialGovernor.code.length == 0 || initialDecisionWindow < 1 hours
                || initialDecisionWindow > 30 days
        ) revert InvalidInput();
        paymentToken = IERC20Exact(token);
        decisionWindow = initialDecisionWindow;
        governor = initialGovernor;
        _configureValidatorSet(initialValidators, threshold);
        emit GovernanceConfigured(initialGovernor);
    }

    function setPaused(bool nextPaused) external onlyGovernor {
        paused = nextPaused;
        emit PauseChanged(nextPaused);
    }

    function configureValidatorSet(address[] calldata nextValidators, uint8 threshold)
        external
        onlyGovernor
        returns (uint32 validatorSetId)
    {
        validatorSetId = _configureValidatorSet(nextValidators, threshold);
    }

    function disableValidatorSet(uint32 validatorSetId) external onlyGovernor {
        if (validatorThresholds[validatorSetId] == 0 || validatorSetDisabled[validatorSetId]) {
            revert InvalidState();
        }
        validatorSetDisabled[validatorSetId] = true;
        emit ValidatorSetDisabled(validatorSetId);
    }

    function registerEncryptionKey(bytes32 ownerKeyHash) external {
        if (ownerKeyHash == bytes32(0)) revert InvalidInput();
        ownerKeyHashes[msg.sender] = ownerKeyHash;
        emit EncryptionKeyRegistered(msg.sender, ownerKeyHash);
    }

    function authorizeTargetOwner(bytes32 targetHash, address owner) external onlyGovernor {
        if (targetHash == bytes32(0) || owner == address(0)) revert InvalidInput();
        if (targetOwners[targetHash] == owner) revert InvalidState();
        uint64 authorizationEpoch = ++targetAuthorizationEpochs[targetHash];
        targetOwners[targetHash] = owner;
        emit TargetOwnerAuthorized(targetHash, owner, authorizationEpoch);
    }

    function revokeTargetOwner(bytes32 targetHash) external onlyGovernor {
        address owner = targetOwners[targetHash];
        if (owner == address(0)) revert InvalidState();
        delete targetOwners[targetHash];
        uint64 authorizationEpoch = ++targetAuthorizationEpochs[targetHash];
        emit TargetOwnerRevoked(targetHash, owner, authorizationEpoch);
    }

    function submissionPermitDigest(
        uint256 programId,
        address researcher,
        bytes32 reportCiphertextHash,
        bytes32 reportCommitment
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                programId,
                programs[programId].authorizationEpoch,
                currentValidatorSetId,
                decisionWindow,
                researcher,
                reportCiphertextHash,
                reportCommitment
            )
        );
    }

    function authorizeSubmission(bytes32 permitDigest, uint64 expiresAt) external onlyGovernor {
        if (permitDigest == bytes32(0) || expiresAt <= block.timestamp) revert InvalidInput();
        submissionPermits[permitDigest] = expiresAt;
        emit SubmissionAuthorized(permitDigest, expiresAt);
    }

    function cancelSubmissionAuthorization(bytes32 permitDigest) external onlyGovernor {
        if (submissionPermits[permitDigest] == 0) revert InvalidState();
        delete submissionPermits[permitDigest];
        emit SubmissionAuthorizationCancelled(permitDigest);
    }

    function createProgram(
        bytes32 targetHash,
        bytes32 scopeHash,
        uint128[4] calldata rewards,
        uint16 maxOpenSubmissions
    ) external returns (uint256 programId) {
        if (
            targetHash == bytes32(0) || scopeHash == bytes32(0)
                || targetOwners[targetHash] != msg.sender || maxOpenSubmissions == 0
                || maxOpenSubmissions > 64
        ) revert InvalidInput();
        bytes32 ownerKeyHash = ownerKeyHashes[msg.sender];
        if (ownerKeyHash == bytes32(0)) revert InvalidInput();
        if (
            rewards[0] == 0 || rewards[1] < rewards[0] || rewards[2] < rewards[1]
                || rewards[3] < rewards[2]
        ) revert InvalidInput();
        programId = nextProgramId++;
        Program storage program = programs[programId];
        program.owner = msg.sender;
        program.targetHash = targetHash;
        program.scopeHash = scopeHash;
        program.authorizationEpoch = targetAuthorizationEpochs[targetHash];
        program.active = true;
        program.maxOpenSubmissions = maxOpenSubmissions;
        program.rewards = rewards;
        emit ProgramCreated(programId, msg.sender, targetHash, scopeHash, maxOpenSubmissions);
    }

    function fundProgram(uint256 programId, uint128 amount)
        external
        whenNotPaused
        nonReentrant
    {
        Program storage program = programs[programId];
        if (!program.active || amount == 0 || !_isProgramAuthorized(program)) {
            revert InvalidState();
        }
        _pullExact(msg.sender, amount);
        program.available += amount;
        emit ProgramFunded(programId, msg.sender, amount);
    }

    function deactivateProgram(uint256 programId) external {
        Program storage program = programs[programId];
        if (msg.sender != program.owner && msg.sender != governor) revert Unauthorized();
        if (!program.active) revert InvalidState();
        program.active = false;
        emit ProgramDeactivated(programId);
    }

    function withdrawProgramFunds(uint256 programId, uint128 amount) external nonReentrant {
        Program storage program = programs[programId];
        if (msg.sender != program.owner) revert Unauthorized();
        if (program.active || amount == 0 || amount > program.available) revert InvalidState();
        program.available -= amount;
        _pushExact(msg.sender, amount);
        emit ProgramFundsWithdrawn(programId, msg.sender, amount);
    }

    function submitToProgram(
        uint256 programId,
        bytes32 reportCiphertextHash,
        bytes32 reportCommitment
    ) external whenNotPaused returns (uint256 submissionId) {
        Program storage program = programs[programId];
        if (
            !program.active || !_isProgramAuthorized(program)
                || program.openSubmissions >= program.maxOpenSubmissions
        ) {
            revert InvalidState();
        }
        if (usedCommitments[programId][reportCommitment]) revert DuplicateCommitment();
        bytes32 permitDigest = submissionPermitDigest(
            programId, msg.sender, reportCiphertextHash, reportCommitment
        );
        uint64 permitExpiry = submissionPermits[permitDigest];
        if (permitExpiry <= block.timestamp) revert Unauthorized();
        delete submissionPermits[permitDigest];
        usedCommitments[programId][reportCommitment] = true;

        uint128 maximum = program.rewards[uint256(Severity.CRITICAL)];
        if (program.available < maximum) revert InsufficientEscrow();
        program.available -= maximum;
        program.locked += maximum;
        ++program.openSubmissions;
        submissionId = _commit(
            programId,
            msg.sender,
            program.owner,
            program.targetHash,
            reportCiphertextHash,
            reportCommitment,
            maximum,
            uint64(block.timestamp) + decisionWindow,
            program.authorizationEpoch
        );
    }

    function submitPrivate(
        address owner,
        bytes32 targetHash,
        bytes32 reportCiphertextHash,
        bytes32 reportCommitment,
        uint64 refundAfter
    ) external whenNotPaused returns (uint256 submissionId) {
        if (owner == address(0) || owner == msg.sender || targetHash == bytes32(0)) {
            revert InvalidInput();
        }
        if (refundAfter < block.timestamp + 1 hours || refundAfter > block.timestamp + 30 days) {
            revert InvalidInput();
        }
        submissionId = _commit(
            0,
            msg.sender,
            owner,
            targetHash,
            reportCiphertextHash,
            reportCommitment,
            0,
            refundAfter,
            0
        );
    }

    function fundPrivateSubmission(uint256 submissionId, uint128 amount)
        external
        whenNotPaused
        nonReentrant
    {
        Submission storage submission = submissions[submissionId];
        if (
            !submission.exists || submission.programId != 0 || amount == 0
                || block.timestamp >= submission.decisionDeadline
                || (
                    submission.status != SubmissionStatus.COMMITTED
                        && submission.status != SubmissionStatus.VALIDATED
                )
        ) revert InvalidState();
        if (privatePool[submissionId] > type(uint128).max - amount) revert InsufficientEscrow();
        _pullExact(msg.sender, amount);
        privatePool[submissionId] += amount;
        privateContributions[submissionId][msg.sender] += amount;
        emit PrivateSubmissionFunded(submissionId, msg.sender, amount);
    }

    function refundPrivateContribution(uint256 submissionId) external nonReentrant {
        Submission storage submission = submissions[submissionId];
        if (!submission.exists || submission.programId != 0) revert InvalidState();
        if (
            submission.status != SubmissionStatus.REJECTED
                && submission.status != SubmissionStatus.EXPIRED
                && block.timestamp < submission.decisionDeadline
        ) revert InvalidState();
        if (
            submission.status == SubmissionStatus.REWARD_RESERVED
                || submission.status == SubmissionStatus.PAID
        ) revert InvalidState();
        uint256 amount = privateContributions[submissionId][msg.sender];
        if (amount == 0) revert InvalidState();
        privateContributions[submissionId][msg.sender] = 0;
        privatePool[submissionId] -= amount;
        _pushExact(msg.sender, amount);
        emit PrivateContributionRefunded(submissionId, msg.sender, amount);
    }

    function attest(
        uint256 submissionId,
        bool valid,
        Severity severity,
        bytes32 verdictHash
    ) external {
        Submission storage submission = submissions[submissionId];
        if (
            !submission.exists || submission.status != SubmissionStatus.COMMITTED
                || block.timestamp >= submission.decisionDeadline || verdictHash == bytes32(0)
                || validatorSetDisabled[submission.validatorSetId]
                || !validators[submission.validatorSetId][msg.sender]
        ) revert InvalidState();
        if (validatorVoted[submissionId][msg.sender]) revert DuplicateVote();
        if (
            submission.programId != 0
                && !_isProgramAuthorized(programs[submission.programId])
        ) revert Unauthorized();
        validatorVoted[submissionId][msg.sender] = true;
        bytes32 verdictDigest = keccak256(abi.encode(valid, severity, verdictHash));
        uint8 count = ++verdictVotes[submissionId][verdictDigest];
        emit ValidatorVote(submissionId, msg.sender, verdictDigest, valid, severity, verdictHash);
        if (count < validatorThresholds[submission.validatorSetId]) return;

        submission.verdictHash = verdictHash;
        submission.severity = severity;
        if (!valid) {
            submission.status = SubmissionStatus.REJECTED;
            _releaseFundedMaximum(submission);
            _closeFundedSubmission(submission);
            emit SubmissionRejected(submissionId, verdictHash);
            return;
        }
        submission.status = SubmissionStatus.VALIDATED;
        emit SubmissionValidated(submissionId, severity, verdictHash);
        if (submission.programId != 0) {
            _reserveFundedReward(submissionId, submission);
            _closeFundedSubmission(submission);
        }
    }

    function expireSubmission(uint256 submissionId) external {
        Submission storage submission = submissions[submissionId];
        if (
            !submission.exists || block.timestamp < submission.decisionDeadline
                || (
                    submission.status != SubmissionStatus.COMMITTED
                        && submission.status != SubmissionStatus.VALIDATED
                )
        ) revert InvalidState();
        submission.status = SubmissionStatus.EXPIRED;
        if (submission.programId != 0) {
            _releaseFundedMaximum(submission);
            _closeFundedSubmission(submission);
        }
        emit SubmissionExpired(submissionId);
    }

    function authorizePrivatePayout(uint256 submissionId) external {
        Submission storage submission = submissions[submissionId];
        if (
            !submission.exists || submission.programId != 0 || msg.sender != submission.owner
        ) revert Unauthorized();
        if (
            submission.status != SubmissionStatus.VALIDATED
                || block.timestamp >= submission.decisionDeadline
        ) revert InvalidState();
        uint256 amount = privatePool[submissionId];
        if (amount == 0 || amount > type(uint128).max) revert InsufficientEscrow();
        bytes32 ownerKeyHash = ownerKeyHashes[msg.sender];
        if (ownerKeyHash == bytes32(0)) revert InvalidInput();
        submission.ownerKeyHash = ownerKeyHash;
        submission.reward = uint128(amount);
        submission.status = SubmissionStatus.REWARD_RESERVED;
        emit RewardReserved(submissionId, submission.researcher, amount);
    }

    function claimReward(uint256 submissionId) external nonReentrant {
        _claimReward(submissionId, msg.sender);
    }

    /// @notice Claims an earned reward to a researcher-selected recipient.
    /// @dev This preserves liveness if the payment token cannot transfer to the researcher's
    /// address. Only the immutable submission researcher can choose the payout recipient.
    function claimRewardTo(uint256 submissionId, address recipient) external nonReentrant {
        if (recipient == address(0)) revert InvalidInput();
        _claimReward(submissionId, recipient);
    }

    function _claimReward(uint256 submissionId, address recipient) internal {
        Submission storage submission = submissions[submissionId];
        if (
            !submission.exists || msg.sender != submission.researcher
                || submission.status != SubmissionStatus.REWARD_RESERVED
                || submission.reward == 0
        ) revert InvalidState();
        uint128 amount = submission.reward;
        submission.status = SubmissionStatus.PAID;
        if (submission.programId != 0) {
            programs[submission.programId].locked -= amount;
        } else {
            privatePool[submissionId] = 0;
        }
        _pushExact(recipient, amount);
        emit RewardPaid(submissionId, msg.sender, recipient, amount);
        if (_isSubmissionReleaseAuthorized(submission)) {
            _authorizeKeyRelease(submissionId, submission);
        } else {
            emit KeyReleaseDeferred(submissionId, submission.targetHash);
        }
    }

    function rebindFundedReportOwner(uint256 submissionId) external onlyGovernor {
        Submission storage submission = submissions[submissionId];
        if (
            !submission.exists || submission.programId == 0 || keyReleaseCompleted[submissionId]
                || (
                    submission.status != SubmissionStatus.REWARD_RESERVED
                        && submission.status != SubmissionStatus.PAID
                )
        ) revert InvalidState();
        address currentOwner = targetOwners[submission.targetHash];
        uint64 authorizationEpoch = targetAuthorizationEpochs[submission.targetHash];
        bytes32 currentKeyHash = ownerKeyHashes[currentOwner];
        if (currentOwner == address(0) || currentKeyHash == bytes32(0)) revert InvalidInput();
        address previousOwner = submission.owner;
        submission.owner = currentOwner;
        submission.authorizationEpoch = authorizationEpoch;
        submission.ownerKeyHash = currentKeyHash;
        emit ReportOwnerRebound(
            submissionId, previousOwner, currentOwner, authorizationEpoch
        );
        if (submission.status == SubmissionStatus.PAID) {
            _authorizeKeyRelease(submissionId, submission);
        }
    }

    function sendEncryptedMessage(uint256 submissionId, bytes calldata ciphertext) external {
        Submission storage submission = submissions[submissionId];
        if (
            !submission.exists
                || (msg.sender != submission.researcher && msg.sender != submission.owner)
        ) revert Unauthorized();
        if (ciphertext.length == 0) revert InvalidInput();
        if (ciphertext.length > 2048) revert MessageTooLarge();
        address recipient =
            msg.sender == submission.researcher ? submission.owner : submission.researcher;
        emit EncryptedMessage(
            submissionId, msg.sender, recipient, keccak256(ciphertext), ciphertext
        );
    }

    function _configureValidatorSet(address[] memory nextValidators, uint8 threshold)
        internal
        returns (uint32 validatorSetId)
    {
        if (
            nextValidators.length < 2 || nextValidators.length > 32 || threshold < 2
                || threshold > nextValidators.length
        ) revert InvalidInput();
        validatorSetId = ++currentValidatorSetId;
        validatorThresholds[validatorSetId] = threshold;
        for (uint256 index; index < nextValidators.length; ++index) {
            address validator = nextValidators[index];
            if (validator == address(0) || validators[validatorSetId][validator]) {
                revert InvalidInput();
            }
            validators[validatorSetId][validator] = true;
        }
        emit ValidatorSetConfigured(validatorSetId, threshold, nextValidators);
    }

    function _commit(
        uint256 programId,
        address researcher,
        address owner,
        bytes32 targetHash,
        bytes32 reportCiphertextHash,
        bytes32 reportCommitment,
        uint128 reservedMaximum,
        uint64 decisionDeadline,
        uint64 authorizationEpoch
    ) internal returns (uint256 submissionId) {
        if (
            reportCiphertextHash == bytes32(0) || reportCommitment == bytes32(0)
                || decisionDeadline <= block.timestamp
                || validatorSetDisabled[currentValidatorSetId]
        ) revert InvalidInput();
        submissionId = nextSubmissionId++;
        bytes32 ownerKeyHash = ownerKeyHashes[owner];
        submissions[submissionId] = Submission({
            programId: programId,
            researcher: researcher,
            owner: owner,
            targetHash: targetHash,
            reportCiphertextHash: reportCiphertextHash,
            reportCommitment: reportCommitment,
            ownerKeyHash: ownerKeyHash,
            verdictHash: bytes32(0),
            severity: Severity.LOW,
            status: SubmissionStatus.COMMITTED,
            reservedMaximum: reservedMaximum,
            reward: 0,
            submittedAt: uint64(block.timestamp),
            decisionDeadline: decisionDeadline,
            authorizationEpoch: authorizationEpoch,
            validatorSetId: currentValidatorSetId,
            exists: true
        });
        emit SubmissionCommitted(
            submissionId,
            programId,
            researcher,
            owner,
            targetHash,
            reportCiphertextHash,
            reportCommitment,
            decisionDeadline,
            currentValidatorSetId,
            authorizationEpoch
        );
    }

    function _isProgramAuthorized(Program storage program) internal view returns (bool) {
        return targetOwners[program.targetHash] == program.owner
            && targetAuthorizationEpochs[program.targetHash] == program.authorizationEpoch;
    }

    function _isSubmissionReleaseAuthorized(Submission storage submission)
        internal
        view
        returns (bool)
    {
        if (submission.programId == 0) return true;
        return targetOwners[submission.targetHash] == submission.owner
            && targetAuthorizationEpochs[submission.targetHash] == submission.authorizationEpoch;
    }

    function _authorizeKeyRelease(uint256 submissionId, Submission storage submission) internal {
        if (keyReleaseCompleted[submissionId]) revert InvalidState();
        bytes32 releaseKeyHash = ownerKeyHashes[submission.owner];
        if (releaseKeyHash == bytes32(0)) revert InvalidInput();
        submission.ownerKeyHash = releaseKeyHash;
        keyReleaseCompleted[submissionId] = true;
        emit KeyReleaseAuthorized(submissionId, submission.owner, releaseKeyHash);
    }

    function _reserveFundedReward(uint256 submissionId, Submission storage submission) internal {
        Program storage program = programs[submission.programId];
        uint128 reward = program.rewards[uint256(submission.severity)];
        uint128 difference = submission.reservedMaximum - reward;
        program.locked -= difference;
        program.available += difference;
        submission.reservedMaximum = reward;
        submission.reward = reward;
        submission.status = SubmissionStatus.REWARD_RESERVED;
        emit RewardReserved(submissionId, submission.researcher, reward);
    }

    function _releaseFundedMaximum(Submission storage submission) internal {
        if (submission.programId == 0 || submission.reservedMaximum == 0) return;
        Program storage program = programs[submission.programId];
        program.locked -= submission.reservedMaximum;
        program.available += submission.reservedMaximum;
        submission.reservedMaximum = 0;
    }

    function _closeFundedSubmission(Submission storage submission) internal {
        if (submission.programId == 0) return;
        Program storage program = programs[submission.programId];
        if (program.openSubmissions == 0) revert InvalidState();
        --program.openSubmissions;
    }

    function _pullExact(address from, uint256 amount) internal {
        uint256 beforeBalance = paymentToken.balanceOf(address(this));
        _callToken(abi.encodeCall(IERC20Exact.transferFrom, (from, address(this), amount)));
        uint256 afterBalance = paymentToken.balanceOf(address(this));
        if (afterBalance < beforeBalance || afterBalance - beforeBalance != amount) {
            revert TransferFailed();
        }
    }

    function _pushExact(address to, uint256 amount) internal {
        uint256 vaultBefore = paymentToken.balanceOf(address(this));
        uint256 recipientBefore = paymentToken.balanceOf(to);
        _callToken(abi.encodeCall(IERC20Exact.transfer, (to, amount)));
        uint256 vaultAfter = paymentToken.balanceOf(address(this));
        uint256 recipientAfter = paymentToken.balanceOf(to);
        if (
            vaultAfter > vaultBefore || vaultBefore - vaultAfter != amount
                || recipientAfter < recipientBefore || recipientAfter - recipientBefore != amount
        ) revert TransferFailed();
    }

    function _callToken(bytes memory payload) internal {
        (bool ok, bytes memory result) = address(paymentToken).call(payload);
        if (
            !ok || (result.length != 0 && result.length != 32)
                || (result.length == 32 && !abi.decode(result, (bool)))
        ) revert TransferFailed();
    }
}
