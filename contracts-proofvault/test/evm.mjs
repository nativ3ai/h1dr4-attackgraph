import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

import ganache from 'ganache';
import solc from 'solc';
import {
  BrowserProvider,
  ContractFactory,
  keccak256,
  parseUnits,
  toUtf8Bytes,
  ZeroAddress,
} from 'ethers';

const vaultPath = new URL('../H1DR4ProofVault.sol', import.meta.url);
const vaultSource = fs.readFileSync(vaultPath, 'utf8');
const cryptoHelper = process.env.H1DR4_TEST_CRYPTO_HELPER;
function cryptoFixture(request) {
  const result = spawnSync(process.env.H1DR4_TEST_PYTHON, [cryptoHelper], {
    input: JSON.stringify(request), encoding: 'utf8', timeout: 30_000,
    env: process.env,
  });
  // Never print fixture stdin/stdout: it contains ephemeral test keys.
  assert.equal(result.status, 0, 'synthetic crypto fixture failed');
  return JSON.parse(result.stdout);
}
const encryptedFixture = cryptoHelper ? cryptoFixture({ operation: 'make' }) : null;
async function assertEncryptedRoundtrip(submissionId) {
  if (!encryptedFixture) return;
  const submission = await vault.submissions(submissionId);
  const result = cryptoFixture({
    operation: 'release', fixture: encryptedFixture, submission_id: submissionId,
    observed: {
      status: Number(submission.status), reward: Number(submission.reward),
      release_completed: await vault.keyReleaseCompleted(submissionId),
      ciphertext_hash: submission.reportCiphertextHash,
      commitment: submission.reportCommitment, owner_key_hash: submission.ownerKeyHash,
    },
  });
  assert.equal(result.roundtrip, true);
  assert.equal(result.wrong_owner_rejected, true);
  assert.equal(result.transport_contains_plaintext, false);
}
const tokenSource = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MockUSDC {
    string public constant name = "Mock USDC";
    string public constant symbol = "mUSDC";
    uint8 public constant decimals = 6;
    uint16 public feeBps;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function setFeeBps(uint16 nextFeeBps) external {
        require(nextFeeBps <= 1_000);
        feeBps = nextFeeBps;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount);
        allowance[from][msg.sender] = allowed - amount;
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount);
        balanceOf[from] -= amount;
        uint256 fee = amount * feeBps / 10_000;
        balanceOf[to] += amount - fee;
    }
}

contract MockGovernor {
    address public immutable owner;

    constructor(address initialOwner) {
        require(initialOwner != address(0));
        owner = initialOwner;
    }

    function execute(address target, bytes calldata data) external returns (bytes memory result) {
        require(msg.sender == owner);
        (bool ok, bytes memory returned) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(returned, 32), mload(returned))
            }
        }
        return returned;
    }
}
`;

function compile() {
  const input = {
    language: 'Solidity',
    sources: {
      'H1DR4ProofVault.sol': { content: vaultSource },
      'MockUSDC.sol': { content: tokenSource },
    },
    settings: {
      evmVersion: 'paris',
      viaIR: true,
      optimizer: { enabled: true, runs: 200 },
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } },
    },
  };
  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (output.errors || []).filter((item) => item.severity === 'error');
  if (errors.length) throw new Error(errors.map((item) => item.formattedMessage).join('\n'));
  return {
    vault: output.contracts['H1DR4ProofVault.sol'].H1DR4ProofVault,
    token: output.contracts['MockUSDC.sol'].MockUSDC,
    governor: output.contracts['MockUSDC.sol'].MockGovernor,
  };
}

async function expectRevert(promise, label) {
  let reverted = false;
  try {
    const tx = await promise;
    await tx.wait();
  } catch {
    reverted = true;
  }
  assert.equal(reverted, true, `${label} should revert`);
}

async function latestTimestamp(provider) {
  // Avoid ethers' short-lived block cache after local evm_increaseTime/evm_mine.
  return Number((await provider.send('eth_getBlockByNumber', ['latest', false])).timestamp);
}

async function increaseTime(provider, seconds) {
  await provider.send('evm_increaseTime', [seconds]);
  await provider.send('evm_mine', []);
}

const compiled = compile();
const eip1193 = ganache.provider({
  chain: { chainId: 8453 },
  logging: { quiet: true },
  wallet: { totalAccounts: 8, defaultBalance: 1_000 },
});
// This local chain changes state immediately between revert and success tests.
const provider = new BrowserProvider(eip1193, undefined, { cacheTimeout: -1 });
const [governor, owner, researcher, validatorA, validatorB, funder, outsider] =
  await Promise.all(Array.from({ length: 7 }, (_, index) => provider.getSigner(index)));
const addresses = await Promise.all(
  [governor, owner, researcher, validatorA, validatorB, funder, outsider].map((s) => s.getAddress()),
);
const [governorAddress, ownerAddress, researcherAddress, validatorAAddress, validatorBAddress, funderAddress, outsiderAddress] = addresses;

const token = await new ContractFactory(compiled.token.abi, compiled.token.evm.bytecode.object, governor).deploy();
await token.waitForDeployment();
const governorContract = await new ContractFactory(
  compiled.governor.abi,
  compiled.governor.evm.bytecode.object,
  governor,
).deploy(governorAddress);
await governorContract.waitForDeployment();
const governorContractAddress = await governorContract.getAddress();
const vaultFactory = new ContractFactory(compiled.vault.abi, compiled.vault.evm.bytecode.object, governor);

await expectRevert(
  vaultFactory.deploy(
    outsiderAddress,
    governorContractAddress,
    [validatorAAddress, validatorBAddress],
    2,
    3_600,
  ),
  'EOA payment token',
);
await expectRevert(
  vaultFactory.deploy(
    await token.getAddress(),
    outsiderAddress,
    [validatorAAddress, validatorBAddress],
    2,
    3_600,
  ),
  'EOA initial governor',
);
await expectRevert(
  vaultFactory.deploy(
    await token.getAddress(),
    governorContractAddress,
    [validatorAAddress],
    1,
    3_600,
  ),
  'single-validator governance',
);

const vault = await vaultFactory.deploy(
  await token.getAddress(),
  governorContractAddress,
  [validatorAAddress, validatorBAddress],
  2,
  3_600,
);
await vault.waitForDeployment();
const vaultAddress = await vault.getAddress();
const govCall = async (method, args = [], controller = governorContract) => {
  const data = vault.interface.encodeFunctionData(method, args);
  return controller.execute(vaultAddress, data);
};
await expectRevert(
  govCall('configureValidatorSet', [[validatorAAddress], 1]),
  'single-validator rotation',
);

const unit = (value) => parseUnits(String(value), 6);
await (await token.mint(ownerAddress, unit(1_000))).wait();
await (await token.mint(funderAddress, unit(1_000))).wait();
await (await token.connect(owner).approve(vaultAddress, unit(1_000))).wait();
await (await token.connect(funder).approve(vaultAddress, unit(1_000))).wait();

const targetHash = keccak256(toUtf8Bytes('https://authorized.example'));
const scopeHash = keccak256(toUtf8Bytes('web-and-api-v1'));
const ownerKey1 = keccak256(toUtf8Bytes('owner-key-v1'));
const ownerKey2 = encryptedFixture?.owner_key_hash ?? keccak256(toUtf8Bytes('owner-key-v2'));
await (await vault.connect(owner).registerEncryptionKey(ownerKey1)).wait();
await (await govCall('authorizeTargetOwner', [targetHash, ownerAddress])).wait();
assert.equal(await vault.targetOwners(targetHash), ownerAddress);
assert.equal(await vault.ownerKeyHashes(ownerAddress), ownerKey1);
await (await vault.connect(owner).createProgram(
  targetHash,
  scopeHash,
  [unit(10), unit(20), unit(30), unit(40)],
  2,
)).wait();
await expectRevert(
  vault.connect(owner).createProgram(
    keccak256(toUtf8Bytes('https://unverified.example')),
    scopeHash,
    [unit(10), unit(20), unit(30), unit(40)],
    2,
  ),
  'unverified target owner',
);
await (await vault.connect(owner).fundProgram(1, unit(100))).wait();

const cipher1 = encryptedFixture?.reports['1'].report_ciphertext_hash ?? keccak256(toUtf8Bytes('ciphertext-1'));
const commitment1 = encryptedFixture?.reports['1'].report_commitment ?? keccak256(toUtf8Bytes('report-1'));
await expectRevert(
  vault.connect(researcher).submitToProgram(
    1,
    keccak256(toUtf8Bytes('unpermitted-cipher')),
    keccak256(toUtf8Bytes('unpermitted-report')),
  ),
  'unpermitted funded submission',
);
const permit1 = await vault.submissionPermitDigest(1, researcherAddress, cipher1, commitment1);
await (await govCall('authorizeSubmission', [permit1, (await latestTimestamp(provider)) + 1_000])).wait();
await (await vault.connect(researcher).submitToProgram(1, cipher1, commitment1)).wait();
let program = await vault.programs(1);
assert.equal(program.available, unit(60));
assert.equal(program.locked, unit(40));
assert.equal(program.openSubmissions, 1n);

const replayCipher = keccak256(toUtf8Bytes('ciphertext-replay'));
const replayPermit = await vault.submissionPermitDigest(1, researcherAddress, replayCipher, commitment1);
await (await govCall('authorizeSubmission', [replayPermit, (await latestTimestamp(provider)) + 1_000])).wait();
await expectRevert(
  vault.connect(researcher).submitToProgram(1, replayCipher, commitment1),
  'duplicate report commitment',
);

const verdict1 = keccak256(toUtf8Bytes('valid-high-1'));
await (await vault.connect(validatorA).attest(1, true, 2, verdict1)).wait();
assert.equal((await vault.submissions(1)).status, 0n);
await (await vault.connect(validatorB).attest(1, true, 2, verdict1)).wait();
program = await vault.programs(1);
assert.equal(program.available, unit(70));
assert.equal(program.locked, unit(30));
assert.equal(program.openSubmissions, 0n);
assert.equal((await vault.submissions(1)).status, 3n);

await (await vault.connect(owner).registerEncryptionKey(ownerKey2)).wait();
const researcherBefore = await token.balanceOf(researcherAddress);
const claimReceipt = await (await vault.connect(researcher).claimReward(1)).wait();
assert.equal(await token.balanceOf(researcherAddress), researcherBefore + unit(30));
const submission1 = await vault.submissions(1);
assert.equal(submission1.status, 4n);
assert.equal(submission1.ownerKeyHash, ownerKey2);
const releaseLog = claimReceipt.logs
  .map((log) => {
    try { return vault.interface.parseLog(log); } catch { return null; }
  })
  .find((log) => log?.name === 'KeyReleaseAuthorized');
assert.equal(releaseLog.args.ownerKeyHash, ownerKey2);
assert.equal(releaseLog.args.owner, ownerAddress);
await assertEncryptedRoundtrip(1);

await expectRevert(
  vault.connect(validatorA).attest(999, true, 1, verdict1),
  'nonexistent submission attestation',
);

const cipher2 = keccak256(toUtf8Bytes('ciphertext-2'));
const commitment2 = keccak256(toUtf8Bytes('report-2'));
const permit2 = await vault.submissionPermitDigest(1, researcherAddress, cipher2, commitment2);
await (await govCall('authorizeSubmission', [permit2, (await latestTimestamp(provider)) + 1_000])).wait();
await (await vault.connect(researcher).submitToProgram(1, cipher2, commitment2)).wait();
const rejectedVerdict = keccak256(toUtf8Bytes('invalid-2'));
await (await vault.connect(validatorA).attest(2, false, 0, rejectedVerdict)).wait();
await (await vault.connect(validatorB).attest(2, false, 0, rejectedVerdict)).wait();
assert.equal((await vault.submissions(2)).status, 2n);
program = await vault.programs(1);
assert.equal(program.available, unit(70));
assert.equal(program.locked, 0n);
assert.equal(program.openSubmissions, 0n);

const cipher3 = keccak256(toUtf8Bytes('ciphertext-3'));
const commitment3 = keccak256(toUtf8Bytes('report-3'));
const permit3 = await vault.submissionPermitDigest(1, researcherAddress, cipher3, commitment3);
await (await govCall('authorizeSubmission', [permit3, (await latestTimestamp(provider)) + 1_000])).wait();
await (await vault.connect(researcher).submitToProgram(1, cipher3, commitment3)).wait();
await (await vault.connect(validatorA).attest(3, true, 2, keccak256(toUtf8Bytes('split-a')))).wait();
await (await vault.connect(validatorB).attest(3, false, 0, keccak256(toUtf8Bytes('split-b')))).wait();
await increaseTime(provider, 3_601);
await (await vault.connect(outsider).expireSubmission(3)).wait();
assert.equal((await vault.submissions(3)).status, 5n);
program = await vault.programs(1);
assert.equal(program.available, unit(70));
assert.equal(program.locked, 0n);
assert.equal(program.openSubmissions, 0n);

await (await govCall('configureValidatorSet', [[validatorAAddress, validatorBAddress], 2])).wait();
const privateDeadline = (await latestTimestamp(provider)) + 3_700;
const privateCipher = encryptedFixture?.reports['4'].report_ciphertext_hash ?? keccak256(toUtf8Bytes('private-cipher'));
const privateCommitment = encryptedFixture?.reports['4'].report_commitment ?? keccak256(toUtf8Bytes('private-report'));
await (await vault.connect(researcher).submitPrivate(
  ownerAddress,
  targetHash,
  privateCipher,
  privateCommitment,
  privateDeadline,
)).wait();
await (await vault.connect(funder).fundPrivateSubmission(4, unit(25))).wait();
await expectRevert(vault.connect(researcher).claimReward(4), 'private payout before validation');
assert.equal(await vault.keyReleaseCompleted(4), false);
const privateVerdict = keccak256(toUtf8Bytes('private-valid-medium'));
await (await vault.connect(validatorA).attest(4, true, 1, privateVerdict)).wait();
await (await vault.connect(validatorB).attest(4, true, 1, privateVerdict)).wait();
await expectRevert(vault.connect(researcher).claimReward(4), 'private payout before owner consent');
await expectRevert(vault.connect(outsider).authorizePrivatePayout(4), 'unrelated owner consent');
assert.equal(await vault.keyReleaseCompleted(4), false);
await (await vault.connect(owner).authorizePrivatePayout(4)).wait();
const privateResearcherBefore = await token.balanceOf(researcherAddress);
const privateClaimReceipt = await (await vault.connect(researcher).claimReward(4)).wait();
const privateReleaseLog = privateClaimReceipt.logs.map((log) => {
  try { return vault.interface.parseLog(log); } catch { return null; }
}).find((log) => log?.name === 'KeyReleaseAuthorized');
assert.equal(privateReleaseLog.args.ownerKeyHash, ownerKey2);
assert.equal(privateReleaseLog.args.owner, ownerAddress);
assert.equal(await token.balanceOf(researcherAddress), privateResearcherBefore + unit(25));
assert.equal((await vault.submissions(4)).status, 4n);
assert.equal(await vault.privatePool(4), 0n);
await assertEncryptedRoundtrip(4);
await expectRevert(vault.connect(researcher).claimReward(4), 'duplicate private payout');

const refundDeadline = (await latestTimestamp(provider)) + 3_700;
await (await vault.connect(researcher).submitPrivate(
  ownerAddress,
  targetHash,
  keccak256(toUtf8Bytes('refund-cipher')),
  keccak256(toUtf8Bytes('refund-report')),
  refundDeadline,
)).wait();
await (await vault.connect(funder).fundPrivateSubmission(5, unit(10))).wait();
const funderBeforeRefund = await token.balanceOf(funderAddress);
await increaseTime(provider, 3_701);
await (await vault.expireSubmission(5)).wait();
await (await vault.connect(funder).refundPrivateContribution(5)).wait();
assert.equal(await token.balanceOf(funderAddress), funderBeforeRefund + unit(10));
assert.equal(await vault.privatePool(5), 0n);

await (await token.setFeeBps(100)).wait();
await expectRevert(vault.connect(owner).fundProgram(1, unit(10)), 'fee-on-transfer funding');
assert.equal((await vault.programs(1)).available, unit(70));
await (await token.setFeeBps(0)).wait();

const payoutCipher = keccak256(toUtf8Bytes('fee-payout-cipher'));
const payoutCommitment = keccak256(toUtf8Bytes('fee-payout-report'));
const payoutPermit = await vault.submissionPermitDigest(
  1,
  researcherAddress,
  payoutCipher,
  payoutCommitment,
);
await (await govCall('authorizeSubmission', [payoutPermit, (await latestTimestamp(provider)) + 1_000])).wait();
await (await vault.connect(researcher).submitToProgram(1, payoutCipher, payoutCommitment)).wait();
const payoutVerdict = keccak256(toUtf8Bytes('fee-payout-valid-low'));
await (await vault.connect(validatorA).attest(6, true, 0, payoutVerdict)).wait();
await (await vault.connect(validatorB).attest(6, true, 0, payoutVerdict)).wait();
await (await token.setFeeBps(100)).wait();
await expectRevert(vault.connect(researcher).claimReward(6), 'fee-on-transfer payout');
assert.equal((await vault.submissions(6)).status, 3n);
assert.equal((await vault.programs(1)).locked, unit(10));
await (await token.setFeeBps(0)).wait();
await expectRevert(
  vault.connect(outsider).claimRewardTo(6, outsiderAddress),
  'nonresearcher payout redirect',
);
const outsiderBeforeRedirect = await token.balanceOf(outsiderAddress);
const routedClaimReceipt = await (
  await vault.connect(researcher).claimRewardTo(6, outsiderAddress, { gasLimit: 1_000_000 })
).wait();
assert.equal(await token.balanceOf(outsiderAddress), outsiderBeforeRedirect + unit(10));
assert.equal((await vault.submissions(6)).status, 4n);
assert.equal((await vault.programs(1)).locked, 0n);
const routedRewardEvent = routedClaimReceipt.logs.map((log) => {
  try { return vault.interface.parseLog(log); } catch { return null; }
}).find((log) => log?.name === 'RewardPaid');
assert.equal(routedRewardEvent.args.researcher, researcherAddress);
assert.equal(routedRewardEvent.args.recipient, outsiderAddress);

const disabledCipher = keccak256(toUtf8Bytes('disabled-set-cipher'));
const disabledCommitment = keccak256(toUtf8Bytes('disabled-set-report'));
const disabledPermit = await vault.submissionPermitDigest(
  1,
  researcherAddress,
  disabledCipher,
  disabledCommitment,
);
await (await govCall('authorizeSubmission', [disabledPermit, (await latestTimestamp(provider)) + 1_000])).wait();
await (await vault.connect(researcher).submitToProgram(1, disabledCipher, disabledCommitment)).wait();
await (await govCall('disableValidatorSet', [2])).wait();
await expectRevert(
  vault.connect(validatorA).attest(7, true, 1, keccak256(toUtf8Bytes('disabled-verdict'))),
  'disabled validator set',
);
await (await govCall('configureValidatorSet', [[validatorAAddress, validatorBAddress], 2])).wait();
await increaseTime(provider, 3_601);
await (await vault.expireSubmission(7)).wait();
assert.equal((await vault.submissions(7)).status, 5n);
assert.equal((await vault.programs(1)).locked, 0n);

await (await govCall('setPaused', [true])).wait();
await expectRevert(vault.connect(owner).fundProgram(1, unit(1)), 'paused funding');
await (await govCall('setPaused', [false])).wait();

const cancelledCipher = keccak256(toUtf8Bytes('cancelled-cipher'));
const cancelledCommitment = keccak256(toUtf8Bytes('cancelled-report'));
const cancelledPermit = await vault.submissionPermitDigest(
  1,
  researcherAddress,
  cancelledCipher,
  cancelledCommitment,
);
await (await govCall('authorizeSubmission', [cancelledPermit, (await latestTimestamp(provider)) + 1_000])).wait();
await (await govCall('cancelSubmissionAuthorization', [cancelledPermit])).wait();
assert.equal(await vault.submissionPermits(cancelledPermit), 0n);
await expectRevert(
  vault.connect(researcher).submitToProgram(1, cancelledCipher, cancelledCommitment),
  'cancelled submission permit',
);

const revocationPaidCipher = keccak256(toUtf8Bytes('revocation-paid-cipher'));
const revocationPaidCommitment = keccak256(toUtf8Bytes('revocation-paid-report'));
const revocationPaidPermit = await vault.submissionPermitDigest(
  1,
  researcherAddress,
  revocationPaidCipher,
  revocationPaidCommitment,
);
await (await govCall('authorizeSubmission', [
  revocationPaidPermit,
  (await latestTimestamp(provider)) + 1_000,
])).wait();
await (await vault.connect(researcher).submitToProgram(
  1,
  revocationPaidCipher,
  revocationPaidCommitment,
)).wait();
const revocationPaidVerdict = keccak256(toUtf8Bytes('revocation-paid-valid-low'));
await (await vault.connect(validatorA).attest(8, true, 0, revocationPaidVerdict)).wait();
await (await vault.connect(validatorB).attest(8, true, 0, revocationPaidVerdict)).wait();
assert.equal((await vault.submissions(8)).status, 3n);

const revokedCommittedCipher = keccak256(toUtf8Bytes('revoked-committed-cipher'));
const revokedCommittedCommitment = keccak256(toUtf8Bytes('revoked-committed-report'));
const revokedCommittedPermit = await vault.submissionPermitDigest(
  1,
  researcherAddress,
  revokedCommittedCipher,
  revokedCommittedCommitment,
);
await (await govCall('authorizeSubmission', [
  revokedCommittedPermit,
  (await latestTimestamp(provider)) + 1_000,
])).wait();
await (await vault.connect(researcher).submitToProgram(
  1,
  revokedCommittedCipher,
  revokedCommittedCommitment,
)).wait();

const staleCipher = keccak256(toUtf8Bytes('stale-permit-cipher'));
const staleCommitment = keccak256(toUtf8Bytes('stale-permit-report'));
const stalePermit = await vault.submissionPermitDigest(
  1,
  researcherAddress,
  staleCipher,
  staleCommitment,
);
await (await govCall('authorizeSubmission', [stalePermit, (await latestTimestamp(provider)) + 1_000])).wait();

await (await govCall('revokeTargetOwner', [targetHash])).wait();
assert.equal(await vault.targetOwners(targetHash), ZeroAddress);
await expectRevert(vault.connect(owner).fundProgram(1, unit(1)), 'revoked program funding');
await expectRevert(
  vault.connect(researcher).submitToProgram(1, staleCipher, staleCommitment),
  'stale permit after target revocation',
);
await expectRevert(
  vault.connect(validatorA).attest(
    9,
    true,
    0,
    keccak256(toUtf8Bytes('revoked-committed-verdict')),
  ),
  'attestation after target revocation',
);

const deferredClaim = await (await vault.connect(researcher).claimReward(8)).wait();
const deferredEvents = deferredClaim.logs.map((log) => {
  try { return vault.interface.parseLog(log); } catch { return null; }
}).filter(Boolean);
assert.equal(deferredEvents.some((log) => log.name === 'KeyReleaseAuthorized'), false);
assert.equal(deferredEvents.some((log) => log.name === 'KeyReleaseDeferred'), true);
assert.equal(await vault.keyReleaseCompleted(8), false);

const newOwnerKey = keccak256(toUtf8Bytes('replacement-owner-key'));
await (await vault.connect(outsider).registerEncryptionKey(newOwnerKey)).wait();
await (await govCall('authorizeTargetOwner', [targetHash, outsiderAddress])).wait();
const rebindReceipt = await (await govCall('rebindFundedReportOwner', [8])).wait();
const rebindEvents = rebindReceipt.logs.map((log) => {
  try { return vault.interface.parseLog(log); } catch { return null; }
}).filter(Boolean);
const reboundRelease = rebindEvents.find((log) => log.name === 'KeyReleaseAuthorized');
assert.equal(reboundRelease.args.owner, outsiderAddress);
assert.equal(reboundRelease.args.ownerKeyHash, newOwnerKey);
assert.equal(await vault.keyReleaseCompleted(8), true);
await expectRevert(govCall('rebindFundedReportOwner', [8]), 'duplicate report-key release');

await increaseTime(provider, 3_601);
await (await vault.expireSubmission(9)).wait();
assert.equal((await vault.submissions(9)).status, 5n);

assert.equal(await vault.governor(), governorContractAddress);
assert.equal(vault.interface.hasFunction('beginGovernanceTransfer'), false);
await (await govCall('setPaused', [true])).wait();
await (await govCall('setPaused', [false])).wait();

assert.notEqual(await token.getAddress(), ZeroAddress);
assert.ok(compiled.vault.evm.deployedBytecode.object.length / 2 < 24_576);

const result = {
  chain_id: 8453,
  contract_source_sha256: (await import('node:crypto')).createHash('sha256').update(vaultSource).digest('hex'),
  creation_bytecode_bytes: compiled.vault.evm.bytecode.object.length / 2,
  runtime_bytecode_bytes: compiled.vault.evm.deployedBytecode.object.length / 2,
  checks: {
    private_payout_requires_validation_and_owner_consent: true,
    duplicate_private_payout_rejected: true,
    exact_funded_payment_and_rotated_key_release: true,
    exact_private_pool_payment: true,
    expired_private_refund: true,
    unverified_target_rejected: true,
    unpermitted_and_duplicate_submission_rejected: true,
    split_quorum_expiry_recovery: true,
    nonexistent_submission_vote_rejected: true,
    fee_token_credit_rejected: true,
    fee_token_payout_and_release_rejected: true,
    disabled_validator_set_expires_safely: true,
    emergency_pause_blocks_new_value: true,
    cancelled_permit_rejected: true,
    target_revocation_blocks_funding_submission_and_attestation: true,
    revoked_owner_claim_pays_but_defers_key_release: true,
    report_rebound_to_current_owner_and_released_once: true,
    immutable_contract_wallet_governor_from_block_zero: true,
    validator_threshold_minimum_enforced_on_chain: true,
    researcher_directed_payout_recipient: true,
  },
  encrypted_fixture_integration: encryptedFixture ? {
    funded_report_roundtrip_after_local_evm_payout: true,
    private_report_roundtrip_after_local_evm_payout: true,
    wrong_owner_rejected: true,
    scope: 'Local EVM and mock USDC only; not a production key-release service',
  } : null,
};
console.log(JSON.stringify(result, null, 2));
