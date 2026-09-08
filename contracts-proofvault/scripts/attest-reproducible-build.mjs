import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const packageRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const buildInputs = [
  'H1DR4ProofVault.sol',
  'package.json',
  'package-lock.json',
  'scripts/compile.mjs',
];
const releaseInputs = [
  ...buildInputs,
  'scripts/attest-reproducible-build.mjs',
  'scripts/deploy-base.mjs',
  'test/evm.mjs',
];

const buildOnce = (ordinal) => {
  const buildRoot = fs.mkdtempSync(path.join(os.tmpdir(), `h1dr4-proofvault-repro-${ordinal}-`));
  try {
    for (const input of buildInputs) {
      const destination = path.join(buildRoot, input);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.copyFileSync(path.join(packageRoot, input), destination);
    }
    const install = spawnSync('npm', ['ci', '--ignore-scripts'], {
      cwd: buildRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (install.status !== 0) {
      throw new Error(`clean install ${ordinal} failed: ${install.stderr || install.stdout}`);
    }
    const compile = spawnSync('npm', ['run', 'compile'], {
      cwd: buildRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (compile.status !== 0) {
      throw new Error(`clean compile ${ordinal} failed: ${compile.stderr || compile.stdout}`);
    }
    return fs.readFileSync(path.join(buildRoot, 'artifacts', 'H1DR4ProofVault.build.json'));
  } finally {
    fs.rmSync(buildRoot, { recursive: true, force: true });
  }
};

const releaseArtifact = fs.readFileSync(
  path.join(packageRoot, 'artifacts', 'H1DR4ProofVault.build.json'),
);
const firstBuild = buildOnce(1);
const secondBuild = buildOnce(2);
if (!releaseArtifact.equals(firstBuild) || !releaseArtifact.equals(secondBuild)) {
  throw new Error('clean release builds are not byte-for-byte reproducible');
}

const inputDigests = Object.fromEntries(releaseInputs.map((input) => [
  input,
  sha256(fs.readFileSync(path.join(packageRoot, input))),
]));
const artifact = JSON.parse(releaseArtifact);
const attestation = {
  schema: 'h1dr4.proofvault-reproducible-build/v1',
  clean_builds: 2,
  install_command: 'npm ci --ignore-scripts',
  compile_command: 'npm run compile',
  node_version: process.version,
  compiler: artifact.compiler,
  compiler_settings: artifact.settings,
  release_inputs_sha256: inputDigests,
  source_sha256: artifact.source_sha256,
  artifact_sha256: sha256(releaseArtifact),
  creation_bytecode_sha256: artifact.creation_bytecode_sha256,
  runtime_template_sha256: artifact.runtime_template_sha256,
};
const attestationBytes = Buffer.from(`${JSON.stringify(attestation, null, 2)}\n`);
const attestationDir = path.join(packageRoot, 'attestations');
fs.mkdirSync(attestationDir, { recursive: true });
const attestationPath = path.join(attestationDir, 'reproducible-build.json');
fs.writeFileSync(attestationPath, attestationBytes, { mode: 0o600 });
console.log(JSON.stringify({
  ...attestation,
  attestation_sha256: sha256(attestationBytes),
  attestation_path: attestationPath,
}, null, 2));
