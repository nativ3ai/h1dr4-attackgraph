import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';

if ('SOLJSON_PATH' in process.env) {
  throw new Error('SOLJSON_PATH is forbidden in the release compiler');
}
const { default: solc } = await import('solc');
const compile = (input) => solc.compile(input);
const compilerVersion = solc.version();

const contractPath = path.resolve('H1DR4ProofVault.sol');
const source = fs.readFileSync(contractPath, 'utf8');
const input = {
  language: 'Solidity',
  sources: { 'H1DR4ProofVault.sol': { content: source } },
  settings: {
    evmVersion: 'paris',
    viaIR: true,
    optimizer: { enabled: true, runs: 200 },
    outputSelection: {
      '*': {
        '*': [
          'abi',
          'evm.bytecode.object',
          'evm.deployedBytecode.object',
          'evm.deployedBytecode.immutableReferences',
        ],
      },
    },
  },
};
const output = JSON.parse(compile(JSON.stringify(input)));
const errors = (output.errors || []).filter((item) => item.severity === 'error');
for (const item of output.errors || []) console.error(item.formattedMessage.trim());
if (errors.length) process.exit(1);
const contract = output.contracts['H1DR4ProofVault.sol'].H1DR4ProofVault;
if (!contract.evm.bytecode.object) throw new Error('empty bytecode');
if (!contract.evm.deployedBytecode.object) throw new Error('empty runtime bytecode');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const artifact = {
  schema: 'h1dr4.proofvault-build/v1',
  contract: 'H1DR4ProofVault',
  compiler: compilerVersion,
  settings: { evmVersion: 'paris', viaIR: true, optimizer: { enabled: true, runs: 200 } },
  source_sha256: sha256(source),
  abi_entries: contract.abi.length,
  creation_bytecode_bytes: contract.evm.bytecode.object.length / 2,
  creation_bytecode_sha256: sha256(Buffer.from(contract.evm.bytecode.object, 'hex')),
  runtime_template_bytes: contract.evm.deployedBytecode.object.length / 2,
  runtime_template_sha256: sha256(Buffer.from(contract.evm.deployedBytecode.object, 'hex')),
  runtime_immutable_references: contract.evm.deployedBytecode.immutableReferences,
};
if (artifact.runtime_template_bytes >= 24_576) throw new Error('runtime exceeds EIP-170');
fs.mkdirSync('artifacts', { recursive: true });
fs.writeFileSync(
  'artifacts/H1DR4ProofVault.build.json',
  `${JSON.stringify({ ...artifact, abi: contract.abi, bytecode: contract.evm.bytecode.object, runtime_template: contract.evm.deployedBytecode.object }, null, 2)}\n`,
  { mode: 0o600 },
);
console.log(JSON.stringify(artifact, null, 2));
