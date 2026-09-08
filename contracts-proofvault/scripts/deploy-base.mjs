import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import {
  Contract,
  ContractFactory,
  JsonRpcProvider,
  Transaction,
  Wallet,
  getAddress,
  getCreateAddress,
  keccak256,
} from 'ethers';

const BASE_CHAIN_ID = 8453n;
const BASE_USDC = getAddress('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const SENTINEL_MODULES = '0x0000000000000000000000000000000000000001';
const CONFIRMATION_WORD = 'DEPLOY';
const EXPECTED_COMPILER = '0.8.33+commit.64118f21.Emscripten.clang';
const MAX_RELEASE_FEE_PER_GAS = 100_000_000_000n;
const MAX_FINALITY_TIMEOUT_MS = 900_000;
const RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';
const VERIFY_RPC_URL = process.env.BASE_VERIFY_RPC_URL;
const ALLOWED_RPC_ENDPOINTS = new Map([
  ['https://mainnet.base.org/', 'Base public RPC operated under base.org'],
  ['https://base-mainnet.public.blastapi.io/', 'Blast public Base endpoint'],
]);
const ALLOWED_RPC_PAIR = ['https://mainnet.base.org/', 'https://base-mainnet.public.blastapi.io/'];

// Official runtime hashes from safe-global/safe-deployments.
const SAFE_SINGLETONS = new Map(Object.entries({
  '0xd9db270c1b5e3bd161e8c8503c55ceabee709552': {
    version: '1.3.0', codeHash: '0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e',
  },
  '0x69f4d1788e39c87893c980c06edf4b7f686e2938': {
    version: '1.3.0', codeHash: '0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e',
  },
  '0x3e5c63644e683549055b9be8653de26e0b4cd36e': {
    version: '1.3.0', codeHash: '0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f',
  },
  '0xfb1bffc9d739b8d520daf37df666da4c687191ea': {
    version: '1.3.0', codeHash: '0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f',
  },
  '0x41675c099f32341bf84bfc5382af534df5c7461a': {
    version: '1.4.1', codeHash: '0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4',
  },
  '0x29fcb43b46531bca003ddc8fcb67ffe91900c762': {
    version: '1.4.1', codeHash: '0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff',
  },
}));
const SAFE_PROXY_RUNTIME_HASHES = new Map([
  ['1.3.0', '0xb89c1b3bdf2cf8827818646bce9a8f6e372885f8c55e5c07acbd307cb133b000'],
  ['1.4.1', '0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c'],
]);
const SAFE_FALLBACK_HANDLERS = new Map(Object.entries({
  '1.3.0': new Map(Object.entries({
    '0xf48f2b2d2a534e402487b3ee7c18c33aec0fe5e4':
      '0x03e69f7ce809e81687c69b19a7d7cca45b6d551ffdec73d9bb87178476de1abf',
    '0x017062a1de2fe6b99be3d9d37841fed19f573804':
      '0x03e69f7ce809e81687c69b19a7d7cca45b6d551ffdec73d9bb87178476de1abf',
  })),
  '1.4.1': new Map(Object.entries({
    '0xfd0732dc9e303f09fcef3a7388ad10a83459ec99':
      '0x7c6007a5d711cea8dfd5d91f5940ec29c7f200fe511eb1fc1397b367af3c42f9',
  })),
}));
const SAFE_FALLBACK_HANDLER_SLOT =
  '0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5';
const SAFE_GUARD_SLOT =
  '0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8';
const SAFE_MODULE_GUARD_SLOT =
  '0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947';

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');
const requireAddress = (value, label) => {
  if (!value) throw new Error(`${label} is required`);
  return getAddress(value.trim());
};
const parsePositiveBigInt = (value, label) => {
  if (!value || !/^\d+$/.test(value)) throw new Error(`${label} must be an unsigned integer`);
  const parsed = BigInt(value);
  if (parsed <= 0n) throw new Error(`${label} must be positive`);
  return parsed;
};
const parsePositiveInteger = (value, label, maximum = Number.MAX_SAFE_INTEGER) => {
  const parsed = Number(parsePositiveBigInt(value, label));
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new Error(`${label} exceeds its release limit`);
  }
  return parsed;
};
const requireSha256 = (value, label, required = false) => {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) {
    if (required) throw new Error(`${label} is required`);
    return null;
  }
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error(`${label} must be a SHA-256 digest`);
  return normalized;
};
const hexToBuffer = (value, label) => {
  const normalized = value.startsWith('0x') ? value.slice(2) : value;
  if (!normalized || normalized.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error(`${label} is not valid bytecode`);
  }
  return Buffer.from(normalized, 'hex');
};
const storageAddress = (value) => getAddress(`0x${value.slice(-40)}`);
const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
};
const canonicalJson = (value) => JSON.stringify(canonicalize(value));
const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

let rpcRequestId = 0;
const rawRpc = async (url, method, params = []) => {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    let response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcRequestId, method, params }),
        redirect: 'error',
        signal: controller.signal,
      });
    } catch (error) {
      clearTimeout(timer);
      if (attempt === 3) throw new Error(`${method} network failure: ${error.message}`);
      await sleep(500 * (2 ** attempt));
      continue;
    }
    clearTimeout(timer);
    if (response.ok) {
      const body = await response.json();
      if (body.error) throw new Error(`${method} failed: ${body.error.message || 'RPC error'}`);
      return body.result;
    }
    if (![408, 429, 500, 502, 503, 504].includes(response.status) || attempt === 3) {
      throw new Error(`${method} failed with HTTP ${response.status}`);
    }
    await sleep(500 * (2 ** attempt));
  }
  throw new Error(`${method} exhausted RPC retries`);
};

if (!VERIFY_RPC_URL) throw new Error('BASE_VERIFY_RPC_URL is required');
const primaryUrl = new URL(RPC_URL);
const verifyUrl = new URL(VERIFY_RPC_URL);
for (const endpoint of [primaryUrl, verifyUrl]) {
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password
    || endpoint.search || endpoint.hash) {
    throw new Error('Base RPC endpoints must be credential-free exact HTTPS URLs');
  }
}
if (primaryUrl.href !== ALLOWED_RPC_PAIR[0] || verifyUrl.href !== ALLOWED_RPC_PAIR[1]) {
  throw new Error(`release RPC pair must be exactly ${ALLOWED_RPC_PAIR.join(' and ')}`);
}

const provider = new JsonRpcProvider(RPC_URL, Number(BASE_CHAIN_ID), { staticNetwork: true });
const verifyProvider = new JsonRpcProvider(VERIFY_RPC_URL, Number(BASE_CHAIN_ID), { staticNetwork: true });

const getCommonFinalizedBlock = async (pinnedBlock = null) => {
  const [primaryHead, verifyHead] = await Promise.all([
    rawRpc(RPC_URL, 'eth_getBlockByNumber', ['finalized', false]),
    rawRpc(VERIFY_RPC_URL, 'eth_getBlockByNumber', ['finalized', false]),
  ]);
  if (!primaryHead?.number || !primaryHead?.hash || !verifyHead?.number || !verifyHead?.hash) {
    throw new Error('both RPC endpoints must expose finalized Base blocks');
  }
  const primaryHeight = BigInt(primaryHead.number);
  const verifyHeight = BigInt(verifyHead.number);
  const selectedHeight = pinnedBlock ?? (primaryHeight < verifyHeight ? primaryHeight : verifyHeight);
  if (primaryHeight < selectedHeight || verifyHeight < selectedHeight) {
    throw new Error('pinned corroboration block is not finalized on both RPC endpoints');
  }
  const blockTag = `0x${selectedHeight.toString(16)}`;
  const [primaryBlock, verifyBlock] = await Promise.all([
    rawRpc(RPC_URL, 'eth_getBlockByNumber', [blockTag, false]),
    rawRpc(VERIFY_RPC_URL, 'eth_getBlockByNumber', [blockTag, false]),
  ]);
  if (!primaryBlock?.hash || primaryBlock.hash !== verifyBlock?.hash) {
    throw new Error('RPC endpoints disagree on the common finalized Base block');
  }
  return {
    number: selectedHeight,
    blockTag,
    hash: primaryBlock.hash,
    primaryFinalizedHeight: primaryHeight,
    verifyFinalizedHeight: verifyHeight,
  };
};

const [primaryChainHex, verifyChainHex] = await Promise.all([
  rawRpc(RPC_URL, 'eth_chainId'), rawRpc(VERIFY_RPC_URL, 'eth_chainId'),
]);
if (BigInt(primaryChainHex) !== BASE_CHAIN_ID || BigInt(verifyChainHex) !== BASE_CHAIN_ID) {
  throw new Error('both RPC endpoints must report Base mainnet chain ID 8453');
}
const pinnedCorroborationBlock = process.env.PROOFVAULT_CORROBORATION_BLOCK
  ? parsePositiveBigInt(process.env.PROOFVAULT_CORROBORATION_BLOCK, 'PROOFVAULT_CORROBORATION_BLOCK')
  : null;
const corroboration = await getCommonFinalizedBlock(pinnedCorroborationBlock);

const [primaryTokenCode, verifyTokenCode] = await Promise.all([
  rawRpc(RPC_URL, 'eth_getCode', [BASE_USDC, corroboration.blockTag]),
  rawRpc(VERIFY_RPC_URL, 'eth_getCode', [BASE_USDC, corroboration.blockTag]),
]);
if (primaryTokenCode === '0x' || primaryTokenCode !== verifyTokenCode) {
  throw new Error('independent RPCs do not agree on canonical Base USDC code');
}
const tokenAbi = ['function decimals() view returns (uint8)', 'function symbol() view returns (string)'];
const readToken = async (readProvider) => {
  const token = new Contract(BASE_USDC, tokenAbi, readProvider);
  return {
    decimals: Number(await token.decimals({ blockTag: corroboration.blockTag })),
    symbol: await token.symbol({ blockTag: corroboration.blockTag }),
  };
};
const [tokenReadback, verifyTokenReadback] = await Promise.all([readToken(provider), readToken(verifyProvider)]);
if (canonicalJson(tokenReadback) !== canonicalJson(verifyTokenReadback)
  || tokenReadback.decimals !== 6 || tokenReadback.symbol !== 'USDC') {
  throw new Error('canonical Base USDC metadata mismatch');
}

const packageRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const source = fs.readFileSync(path.join(packageRoot, 'H1DR4ProofVault.sol'));
const packageLock = fs.readFileSync(path.join(packageRoot, 'package-lock.json'));
const artifactPath = path.join(packageRoot, 'artifacts', 'H1DR4ProofVault.build.json');
const artifactBytes = fs.readFileSync(artifactPath);
const artifact = JSON.parse(artifactBytes);
const reproducibleBuildAttestationPath = path.join(
  packageRoot, 'attestations', 'reproducible-build.json',
);
const reproducibleBuildAttestationBytes = fs.existsSync(reproducibleBuildAttestationPath)
  ? fs.readFileSync(reproducibleBuildAttestationPath)
  : null;
const reproducibleBuildAttestation = reproducibleBuildAttestationBytes
  ? JSON.parse(reproducibleBuildAttestationBytes)
  : null;
const actualSourceSha256 = sha256(source);
const actualArtifactSha256 = sha256(artifactBytes);
if (artifact.schema !== 'h1dr4.proofvault-build/v1'
  || artifact.contract !== 'H1DR4ProofVault' || artifact.compiler !== EXPECTED_COMPILER
  || artifact.settings?.evmVersion !== 'paris' || artifact.settings?.viaIR !== true
  || artifact.settings?.optimizer?.enabled !== true || artifact.settings?.optimizer?.runs !== 200) {
  throw new Error('build artifact compiler/settings mismatch');
}
if (artifact.source_sha256 !== actualSourceSha256) throw new Error('stale build artifact');
const creationBytecode = hexToBuffer(artifact.bytecode, 'creation bytecode');
const runtimeTemplate = hexToBuffer(artifact.runtime_template, 'runtime template');
if (artifact.creation_bytecode_bytes !== creationBytecode.length
  || artifact.creation_bytecode_sha256 !== sha256(creationBytecode)
  || artifact.runtime_template_bytes !== runtimeTemplate.length
  || artifact.runtime_template_sha256 !== sha256(runtimeTemplate)
  || runtimeTemplate.length >= 24_576) throw new Error('build artifact bytecode integrity mismatch');
for (const entries of Object.values(artifact.runtime_immutable_references || {})) {
  for (const { start, length } of entries) {
    if (!Number.isInteger(start) || !Number.isInteger(length) || start < 0 || length < 1
      || start + length > runtimeTemplate.length) throw new Error('invalid immutable reference in build artifact');
  }
}

const expectedSourceSha256 = requireSha256(
  process.env.PROOFVAULT_EXPECTED_SOURCE_SHA256, 'PROOFVAULT_EXPECTED_SOURCE_SHA256',
);
const expectedArtifactSha256 = requireSha256(
  process.env.PROOFVAULT_EXPECTED_ARTIFACT_SHA256, 'PROOFVAULT_EXPECTED_ARTIFACT_SHA256',
);
const reproducibleBuildAttestationSha256 = requireSha256(
  process.env.PROOFVAULT_REPRODUCIBLE_BUILD_ATTESTATION_SHA256,
  'PROOFVAULT_REPRODUCIBLE_BUILD_ATTESTATION_SHA256',
);
if (expectedSourceSha256 && expectedSourceSha256 !== actualSourceSha256) {
  throw new Error('externally pinned source digest mismatch');
}
if (expectedArtifactSha256 && expectedArtifactSha256 !== actualArtifactSha256) {
  throw new Error('externally pinned build artifact digest mismatch');
}
if (reproducibleBuildAttestationSha256) {
  if (!reproducibleBuildAttestationBytes
    || sha256(reproducibleBuildAttestationBytes) !== reproducibleBuildAttestationSha256) {
    throw new Error('reproducible-build attestation file digest mismatch');
  }
  if (reproducibleBuildAttestation?.schema !== 'h1dr4.proofvault-reproducible-build/v1'
    || reproducibleBuildAttestation.clean_builds !== 2
    || reproducibleBuildAttestation.source_sha256 !== actualSourceSha256
    || reproducibleBuildAttestation.artifact_sha256 !== actualArtifactSha256
    || reproducibleBuildAttestation.release_inputs_sha256?.['package-lock.json']
      !== sha256(packageLock)
    || reproducibleBuildAttestation.release_inputs_sha256?.['scripts/deploy-base.mjs']
      !== sha256(fs.readFileSync(path.join(packageRoot, 'scripts', 'deploy-base.mjs')))
    || reproducibleBuildAttestation.release_inputs_sha256?.['test/evm.mjs']
      !== sha256(fs.readFileSync(path.join(packageRoot, 'test', 'evm.mjs')))) {
    throw new Error('reproducible-build attestation does not bind this release package');
  }
}
const securityScanId = process.env.PROOFVAULT_SECURITY_SCAN_ID?.trim() || null;
const securitySnapshotDigest = process.env.PROOFVAULT_SECURITY_SNAPSHOT_DIGEST?.trim() || null;
if (securityScanId && !/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(securityScanId)) {
  throw new Error('PROOFVAULT_SECURITY_SCAN_ID must be a scan UUID');
}
if (securitySnapshotDigest
  && !/^codex-security-snapshot\/v1:sha256:[0-9a-f]{64}$/.test(securitySnapshotDigest)) {
  throw new Error('PROOFVAULT_SECURITY_SNAPSHOT_DIGEST has an invalid format');
}

const initialGovernor = requireAddress(process.env.PROOFVAULT_GOVERNOR, 'PROOFVAULT_GOVERNOR');
const safeAbi = [
  'function VERSION() view returns (string)',
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function getModulesPaginated(address start,uint256 pageSize) view returns (address[] array,address next)',
];
const readSafeInterface = async (readProvider, blockTag) => {
  const safe = new Contract(initialGovernor, safeAbi, readProvider);
  const modulesPage = await safe.getModulesPaginated(SENTINEL_MODULES, 100, { blockTag });
  return {
    version: await safe.VERSION({ blockTag }),
    owners: (await safe.getOwners({ blockTag })).map(getAddress),
    threshold: Number(await safe.getThreshold({ blockTag })),
    modules: modulesPage[0].map(getAddress),
    modules_next: getAddress(modulesPage[1]),
  };
};
const readSafeRaw = async (url, blockTag) => {
  const [proxyCode, singletonSlot, fallbackSlot, guardSlot, moduleGuardSlot] = await Promise.all([
    rawRpc(url, 'eth_getCode', [initialGovernor, blockTag]),
    rawRpc(url, 'eth_getStorageAt', [initialGovernor, '0x0', blockTag]),
    rawRpc(url, 'eth_getStorageAt', [initialGovernor, SAFE_FALLBACK_HANDLER_SLOT, blockTag]),
    rawRpc(url, 'eth_getStorageAt', [initialGovernor, SAFE_GUARD_SLOT, blockTag]),
    rawRpc(url, 'eth_getStorageAt', [initialGovernor, SAFE_MODULE_GUARD_SLOT, blockTag]),
  ]);
  return {
    proxy_code: proxyCode,
    proxy_code_hash: proxyCode === '0x' ? null : keccak256(proxyCode),
    singleton: storageAddress(singletonSlot),
    fallback_handler: storageAddress(fallbackSlot),
    guard: storageAddress(guardSlot),
    module_guard: storageAddress(moduleGuardSlot),
  };
};
const verifySafeState = async (blockTag) => {
  let primaryInterface; let verifyInterface; let primaryRaw; let verifyRaw;
  try {
    [primaryInterface, verifyInterface, primaryRaw, verifyRaw] = await Promise.all([
      readSafeInterface(provider, blockTag), readSafeInterface(verifyProvider, blockTag),
      readSafeRaw(RPC_URL, blockTag), readSafeRaw(VERIFY_RPC_URL, blockTag),
    ]);
  } catch (error) {
    throw new Error(`initial governor does not pass the required Safe interface: ${error.message}`);
  }
  if (canonicalJson(primaryInterface) !== canonicalJson(verifyInterface)
    || canonicalJson(primaryRaw) !== canonicalJson(verifyRaw)) {
    throw new Error('RPC endpoints disagree on Safe governance state');
  }
  if (primaryRaw.proxy_code === '0x') throw new Error('Safe governor has no runtime code');
  const singletonPolicy = SAFE_SINGLETONS.get(primaryRaw.singleton.toLowerCase());
  if (!singletonPolicy || singletonPolicy.version !== primaryInterface.version) {
    throw new Error('Safe singleton is not an allowlisted official deployment');
  }
  const [primarySingletonCode, verifySingletonCode] = await Promise.all([
    rawRpc(RPC_URL, 'eth_getCode', [primaryRaw.singleton, blockTag]),
    rawRpc(VERIFY_RPC_URL, 'eth_getCode', [primaryRaw.singleton, blockTag]),
  ]);
  if (primarySingletonCode === '0x' || primarySingletonCode !== verifySingletonCode
    || keccak256(primarySingletonCode) !== singletonPolicy.codeHash) {
    throw new Error('Safe singleton runtime does not match the official deployment hash');
  }
  if (primaryRaw.proxy_code_hash !== SAFE_PROXY_RUNTIME_HASHES.get(primaryInterface.version)) {
    throw new Error(
      `Safe proxy runtime hash ${primaryRaw.proxy_code_hash} is not allowlisted for ${primaryInterface.version}`,
    );
  }
  if (primaryInterface.owners.length < 2
    || new Set(primaryInterface.owners).size !== primaryInterface.owners.length
    || primaryInterface.threshold < 2 || primaryInterface.threshold > primaryInterface.owners.length) {
    throw new Error('governor Safe must enforce at least a 2-of-N owner threshold');
  }
  if (primaryInterface.modules.length !== 0
    || primaryInterface.modules_next !== getAddress(SENTINEL_MODULES)
    || primaryRaw.guard !== ZERO_ADDRESS || primaryRaw.module_guard !== ZERO_ADDRESS) {
    throw new Error('governor Safe must have no modules, guard, or module guard');
  }
  let fallbackHandlerCodeHash = null;
  if (primaryRaw.fallback_handler !== ZERO_ADDRESS) {
    const fallbackPolicy = SAFE_FALLBACK_HANDLERS
      .get(primaryInterface.version)?.get(primaryRaw.fallback_handler.toLowerCase());
    if (!fallbackPolicy) throw new Error('Safe fallback handler is not allowlisted');
    const [primaryFallbackCode, verifyFallbackCode] = await Promise.all([
      rawRpc(RPC_URL, 'eth_getCode', [primaryRaw.fallback_handler, blockTag]),
      rawRpc(VERIFY_RPC_URL, 'eth_getCode', [primaryRaw.fallback_handler, blockTag]),
    ]);
    if (primaryFallbackCode === '0x' || primaryFallbackCode !== verifyFallbackCode
      || keccak256(primaryFallbackCode) !== fallbackPolicy) {
      throw new Error('Safe fallback handler runtime does not match the official deployment hash');
    }
    fallbackHandlerCodeHash = fallbackPolicy;
  }
  return {
    version: primaryInterface.version,
    owners: primaryInterface.owners,
    threshold: primaryInterface.threshold,
    singleton: primaryRaw.singleton,
    singleton_code_hash: singletonPolicy.codeHash,
    proxy_code_hash: primaryRaw.proxy_code_hash,
    modules: primaryInterface.modules,
    guard: primaryRaw.guard,
    module_guard: primaryRaw.module_guard,
    fallback_handler: primaryRaw.fallback_handler,
    fallback_handler_code_hash: fallbackHandlerCodeHash,
  };
};
const safeReadback = await verifySafeState(corroboration.blockTag);

const privateKey = process.env.DEPLOYER_PRIVATE_KEY?.trim();
const configuredDeployer = process.env.DEPLOYER_ADDRESS?.trim();
const wallet = privateKey ? new Wallet(privateKey, provider) : null;
const deployer = wallet ? wallet.address : requireAddress(configuredDeployer, 'DEPLOYER_ADDRESS for dry run');
if (configuredDeployer && getAddress(configuredDeployer) !== deployer) {
  throw new Error('DEPLOYER_PRIVATE_KEY does not match DEPLOYER_ADDRESS');
}
if (deployer === initialGovernor) throw new Error('raw deployer cannot be the governor');

const validators = (process.env.PROOFVAULT_VALIDATORS || '')
  .split(',').map((value) => value.trim()).filter(Boolean).map(getAddress);
if (validators.length < 2) throw new Error('at least two PROOFVAULT_VALIDATORS are required');
if (new Set(validators).size !== validators.length) throw new Error('duplicate validator');
const threshold = Number(process.env.PROOFVAULT_THRESHOLD || '');
if (!Number.isInteger(threshold) || threshold < 2 || threshold > validators.length) {
  throw new Error('PROOFVAULT_THRESHOLD must be 2..validator count');
}
const decisionWindow = Number(process.env.PROOFVAULT_DECISION_WINDOW || '');
if (!Number.isInteger(decisionWindow) || decisionWindow < 3_600 || decisionWindow > 2_592_000) {
  throw new Error('PROOFVAULT_DECISION_WINDOW must be 3600..2592000 seconds');
}

const readPendingNonce = async () => {
  const [primaryNonceHex, verifyNonceHex] = await Promise.all([
    rawRpc(RPC_URL, 'eth_getTransactionCount', [deployer, 'pending']),
    rawRpc(VERIFY_RPC_URL, 'eth_getTransactionCount', [deployer, 'pending']),
  ]);
  if (primaryNonceHex !== verifyNonceHex) throw new Error('independent RPCs disagree on deployer pending nonce');
  const nonce = Number(BigInt(primaryNonceHex));
  if (!Number.isSafeInteger(nonce)) throw new Error('deployer nonce exceeds JavaScript safe integer range');
  return nonce;
};

const factory = new ContractFactory(artifact.abi, artifact.bytecode);
const unsigned = await factory.getDeployTransaction(
  BASE_USDC, initialGovernor, validators, threshold, decisionWindow,
);
if (!unsigned.data) throw new Error('missing deployment init code');
const pendingNonce = await readPendingNonce();
const [primaryFinalizedNonceHex, verifyFinalizedNonceHex] = await Promise.all([
  rawRpc(RPC_URL, 'eth_getTransactionCount', [deployer, corroboration.blockTag]),
  rawRpc(VERIFY_RPC_URL, 'eth_getTransactionCount', [deployer, corroboration.blockTag]),
]);
if (primaryFinalizedNonceHex !== verifyFinalizedNonceHex) {
  throw new Error('independent RPCs disagree on deployer nonce at finalized block');
}
const estimatedGas = await provider.estimateGas({ data: unsigned.data, from: deployer });
const gasLimit = (estimatedGas * 120n + 99n) / 100n;
if (gasLimit > 10_000_000n) throw new Error('deployment gas limit exceeds release cap');
const feeData = await provider.getFeeData();
const proposedPriorityFee = feeData.maxPriorityFeePerGas || 1_000_000n;
const proposedMaxFee = feeData.maxFeePerGas || feeData.gasPrice;
if (!proposedMaxFee) throw new Error('primary RPC did not return EIP-1559 fee data');
const maxPriorityFeePerGas = process.env.PROOFVAULT_MAX_PRIORITY_FEE_PER_GAS_WEI
  ? parsePositiveBigInt(process.env.PROOFVAULT_MAX_PRIORITY_FEE_PER_GAS_WEI, 'PROOFVAULT_MAX_PRIORITY_FEE_PER_GAS_WEI')
  : proposedPriorityFee;
const maxFeePerGas = process.env.PROOFVAULT_MAX_FEE_PER_GAS_WEI
  ? parsePositiveBigInt(process.env.PROOFVAULT_MAX_FEE_PER_GAS_WEI, 'PROOFVAULT_MAX_FEE_PER_GAS_WEI')
  : proposedMaxFee;
if (maxFeePerGas < maxPriorityFeePerGas || maxFeePerGas > MAX_RELEASE_FEE_PER_GAS) {
  throw new Error('invalid or excessive EIP-1559 fee cap');
}
const estimatedMaxCost = gasLimit * maxFeePerGas;
const nativeBalance = await provider.getBalance(deployer);
const expectedContract = getCreateAddress({ from: deployer, nonce: pendingNonce });
const initCode = unsigned.data;
const basePlan = {
  schema: 'h1dr4.proofvault-deployment-plan/v3',
  chain_id: Number(BASE_CHAIN_ID),
  rpc_primary: { url: primaryUrl.href, identity: ALLOWED_RPC_ENDPOINTS.get(primaryUrl.href) },
  rpc_verify: { url: verifyUrl.href, identity: ALLOWED_RPC_ENDPOINTS.get(verifyUrl.href) },
  corroboration_block_number: Number(corroboration.number),
  corroboration_block_hash: corroboration.hash,
  payment_token: BASE_USDC,
  payment_token_code_keccak256: keccak256(primaryTokenCode),
  initial_governor: initialGovernor,
  initial_governor_safe: safeReadback,
  deployer,
  validators,
  threshold,
  decision_window_seconds: decisionWindow,
  compiler: artifact.compiler,
  compiler_settings: artifact.settings,
  package_lock_sha256: sha256(packageLock),
  build_artifact_sha256: actualArtifactSha256,
  externally_pinned_build_artifact_sha256: expectedArtifactSha256,
  source_sha256: actualSourceSha256,
  externally_pinned_source_sha256: expectedSourceSha256,
  reproducible_build_attestation_sha256: reproducibleBuildAttestationSha256,
  security_scan_id: securityScanId,
  security_snapshot_digest: securitySnapshotDigest,
  creation_bytecode_bytes: artifact.creation_bytecode_bytes,
  creation_bytecode_sha256: artifact.creation_bytecode_sha256,
  runtime_template_bytes: artifact.runtime_template_bytes,
  runtime_template_sha256: artifact.runtime_template_sha256,
  init_code_bytes: (initCode.length - 2) / 2,
  init_code_keccak256: keccak256(initCode),
  init_code_sha256: sha256(hexToBuffer(initCode, 'init code')),
  expected_contract: expectedContract,
  transaction_type: 2,
  nonce: pendingNonce,
  finalized_nonce: Number(BigInt(primaryFinalizedNonceHex)),
  value_wei: '0',
  estimated_gas: estimatedGas.toString(),
  gas_limit: gasLimit.toString(),
  max_fee_per_gas_wei: maxFeePerGas.toString(),
  max_priority_fee_per_gas_wei: maxPriorityFeePerGas.toString(),
  maximum_cost_wei: estimatedMaxCost.toString(),
};
const planSha256 = sha256(canonicalJson(basePlan));
const plan = {
  ...basePlan,
  plan_sha256: planSha256,
  deployer_native_balance_wei: nativeBalance.toString(),
  observed_finalized_heights: {
    primary: Number(corroboration.primaryFinalizedHeight),
    verify: Number(corroboration.verifyFinalizedHeight),
  },
  confirmation_required: `CONFIRM_BASE_MAINNET=${CONFIRMATION_WORD} and CONFIRM_PLAN_SHA256=${planSha256}`,
};

if (process.env.CONFIRM_BASE_MAINNET !== CONFIRMATION_WORD) {
  console.log(JSON.stringify({
    ...plan,
    status: 'dry_run',
    release_gate_complete: Boolean(expectedSourceSha256 && expectedArtifactSha256
      && reproducibleBuildAttestationSha256 && securityScanId && securitySnapshotDigest),
    repeat_with: {
      PROOFVAULT_MAX_FEE_PER_GAS_WEI: maxFeePerGas.toString(),
      PROOFVAULT_MAX_PRIORITY_FEE_PER_GAS_WEI: maxPriorityFeePerGas.toString(),
      PROOFVAULT_CORROBORATION_BLOCK: corroboration.number.toString(),
    },
  }, null, 2));
  process.exit(0);
}
if (!wallet) throw new Error('DEPLOYER_PRIVATE_KEY is required for confirmed deployment');
if (!process.env.PROOFVAULT_MAX_FEE_PER_GAS_WEI
  || !process.env.PROOFVAULT_MAX_PRIORITY_FEE_PER_GAS_WEI
  || !process.env.PROOFVAULT_CORROBORATION_BLOCK) {
  throw new Error('confirmed deployment requires explicit fee caps and corroboration block');
}
requireSha256(process.env.PROOFVAULT_EXPECTED_SOURCE_SHA256, 'PROOFVAULT_EXPECTED_SOURCE_SHA256', true);
requireSha256(process.env.PROOFVAULT_EXPECTED_ARTIFACT_SHA256, 'PROOFVAULT_EXPECTED_ARTIFACT_SHA256', true);
requireSha256(
  process.env.PROOFVAULT_REPRODUCIBLE_BUILD_ATTESTATION_SHA256,
  'PROOFVAULT_REPRODUCIBLE_BUILD_ATTESTATION_SHA256', true,
);
if (!securityScanId || !securitySnapshotDigest) {
  throw new Error('confirmed deployment requires an exact completed security scan and snapshot digest');
}
if (process.env.CONFIRM_PLAN_SHA256 !== planSha256) {
  throw new Error(`CONFIRM_PLAN_SHA256 mismatch; reviewed plan is ${planSha256}`);
}
if (nativeBalance < estimatedMaxCost) throw new Error('insufficient native balance for deployment');
if (await readPendingNonce() !== pendingNonce) throw new Error('deployer pending nonce changed after planning');
const preSignSafeReadback = await verifySafeState('latest');
if (canonicalJson(preSignSafeReadback) !== canonicalJson(safeReadback)) {
  throw new Error('Safe governance state changed after the reviewed plan');
}

const txRequest = {
  chainId: BASE_CHAIN_ID, type: 2, nonce: pendingNonce, gasLimit,
  maxFeePerGas, maxPriorityFeePerGas, value: 0n, data: initCode,
};
const signedTransaction = await wallet.signTransaction(txRequest);
const decodedTransaction = Transaction.from(signedTransaction);
if (decodedTransaction.from !== deployer || decodedTransaction.to !== null
  || decodedTransaction.chainId !== BASE_CHAIN_ID || decodedTransaction.type !== 2
  || decodedTransaction.nonce !== pendingNonce || decodedTransaction.gasLimit !== gasLimit
  || decodedTransaction.maxFeePerGas !== maxFeePerGas
  || decodedTransaction.maxPriorityFeePerGas !== maxPriorityFeePerGas
  || decodedTransaction.value !== 0n || decodedTransaction.data !== initCode) {
  throw new Error('signed transaction does not match reviewed deployment plan');
}

const receiptsDir = path.join(packageRoot, 'receipts');
fs.mkdirSync(receiptsDir, { recursive: true });
const journalPath = path.join(receiptsDir, `proofvault-base-${decodedTransaction.hash}.broadcast.json`);
const writeJournal = (status, extra = {}) => fs.writeFileSync(journalPath, `${JSON.stringify({
  schema: 'h1dr4.proofvault-broadcast-journal/v1',
  status,
  plan,
  transaction_hash: decodedTransaction.hash,
  signed_transaction_sha256: sha256(hexToBuffer(signedTransaction, 'signed transaction')),
  ...extra,
}, null, 2)}\n`, { mode: 0o600 });
writeJournal('signed_not_broadcast');

const deploymentTx = await provider.broadcastTransaction(signedTransaction);
if (deploymentTx.hash !== decodedTransaction.hash) throw new Error('broadcast transaction hash mismatch');
writeJournal('broadcast');
const txReceipt = await provider.waitForTransaction(deploymentTx.hash, 1, 180_000);
if (!txReceipt || txReceipt.status !== 1) throw new Error('deployment transaction failed');
if (txReceipt.contractAddress !== expectedContract || txReceipt.blockHash == null) {
  throw new Error('deployment address or block hash differs from plan');
}
writeJournal('mined_awaiting_finality', { block_number: txReceipt.blockNumber, block_hash: txReceipt.blockHash });
const verifyReceipt = await verifyProvider.waitForTransaction(deploymentTx.hash, 1, 180_000);
if (!verifyReceipt || verifyReceipt.status !== 1
  || verifyReceipt.blockNumber !== txReceipt.blockNumber || verifyReceipt.blockHash !== txReceipt.blockHash
  || verifyReceipt.contractAddress !== expectedContract) {
  throw new Error('independent RPC does not corroborate the deployment receipt');
}

const finalityTimeoutMs = process.env.PROOFVAULT_FINALITY_TIMEOUT_MS
  ? parsePositiveInteger(process.env.PROOFVAULT_FINALITY_TIMEOUT_MS, 'PROOFVAULT_FINALITY_TIMEOUT_MS', MAX_FINALITY_TIMEOUT_MS)
  : 600_000;
const waitForFinalizedInclusion = async () => {
  const deadline = Date.now() + finalityTimeoutMs;
  const deploymentHeight = BigInt(txReceipt.blockNumber);
  while (Date.now() <= deadline) {
    const [primaryHead, verifyHead] = await Promise.all([
      rawRpc(RPC_URL, 'eth_getBlockByNumber', ['finalized', false]),
      rawRpc(VERIFY_RPC_URL, 'eth_getBlockByNumber', ['finalized', false]),
    ]);
    if (primaryHead?.number && verifyHead?.number
      && BigInt(primaryHead.number) >= deploymentHeight && BigInt(verifyHead.number) >= deploymentHeight) {
      const blockTag = `0x${deploymentHeight.toString(16)}`;
      const [primaryBlock, verifyBlock] = await Promise.all([
        rawRpc(RPC_URL, 'eth_getBlockByNumber', [blockTag, false]),
        rawRpc(VERIFY_RPC_URL, 'eth_getBlockByNumber', [blockTag, false]),
      ]);
      if (primaryBlock?.hash !== txReceipt.blockHash || verifyBlock?.hash !== txReceipt.blockHash) {
        throw new Error('finalized deployment block hash differs from the mined receipt');
      }
      return {
        primary_finalized_height: Number(BigInt(primaryHead.number)),
        verify_finalized_height: Number(BigInt(verifyHead.number)),
      };
    }
    await sleep(5_000);
  }
  throw new Error(`deployment mined but did not finalize within ${finalityTimeoutMs} ms; inspect ${journalPath}`);
};
const finality = await waitForFinalizedInclusion();

const [primaryBlock, verifyBlock, sentTransaction, verifyTransaction] = await Promise.all([
  provider.getBlock(txReceipt.blockNumber), verifyProvider.getBlock(txReceipt.blockNumber),
  provider.getTransaction(deploymentTx.hash), verifyProvider.getTransaction(deploymentTx.hash),
]);
if (!primaryBlock || !verifyBlock || primaryBlock.hash !== txReceipt.blockHash
  || verifyBlock.hash !== txReceipt.blockHash || !sentTransaction || !verifyTransaction
  || sentTransaction.data !== initCode || verifyTransaction.data !== initCode
  || sentTransaction.nonce !== pendingNonce || verifyTransaction.nonce !== pendingNonce) {
  throw new Error('independent block or transaction corroboration failed');
}

const finalizedDeploymentBlockTag = `0x${BigInt(txReceipt.blockNumber).toString(16)}`;
const [runtimeHex, verifyRuntimeHex] = await Promise.all([
  rawRpc(RPC_URL, 'eth_getCode', [expectedContract, finalizedDeploymentBlockTag]),
  rawRpc(VERIFY_RPC_URL, 'eth_getCode', [expectedContract, finalizedDeploymentBlockTag]),
]);
if (runtimeHex === '0x' || runtimeHex !== verifyRuntimeHex) {
  throw new Error('independent RPCs do not agree on deployed runtime');
}
const runtime = hexToBuffer(runtimeHex, 'deployed runtime');
if (runtime.length !== runtimeTemplate.length) throw new Error('runtime byte length mismatch');
const maskedRuntime = Buffer.from(runtime);
const maskedTemplate = Buffer.from(runtimeTemplate);
for (const entries of Object.values(artifact.runtime_immutable_references || {})) {
  for (const { start, length } of entries) {
    maskedRuntime.fill(0, start, start + length);
    maskedTemplate.fill(0, start, start + length);
  }
}
if (!maskedRuntime.equals(maskedTemplate)) throw new Error('deployed runtime differs from build template');

const readContract = async (readProvider) => {
  const contract = new Contract(expectedContract, artifact.abi, readProvider);
  const callOptions = { blockTag: finalizedDeploymentBlockTag };
  const currentSetId = await contract.currentValidatorSetId(callOptions);
  const readbackValidators = [];
  for (const validator of validators) {
    readbackValidators.push({ validator, enabled: await contract.validators(currentSetId, validator, callOptions) });
  }
  return {
    payment_token: getAddress(await contract.paymentToken(callOptions)),
    governor: getAddress(await contract.governor(callOptions)),
    paused: await contract.paused(callOptions),
    decision_window_seconds: Number(await contract.decisionWindow(callOptions)),
    current_validator_set_id: Number(currentSetId),
    validator_threshold: Number(await contract.validatorThresholds(currentSetId, callOptions)),
    validators: readbackValidators,
  };
};
const [readback, verifyReadback, postDeploymentSafeReadback] = await Promise.all([
  readContract(provider), readContract(verifyProvider), verifySafeState(finalizedDeploymentBlockTag),
]);
if (canonicalJson(readback) !== canonicalJson(verifyReadback)
  || canonicalJson(postDeploymentSafeReadback) !== canonicalJson(safeReadback)
  || readback.payment_token !== BASE_USDC || readback.governor !== initialGovernor
  || readback.paused || readback.decision_window_seconds !== decisionWindow
  || readback.validator_threshold !== threshold || readback.validators.some(({ enabled }) => !enabled)) {
  throw new Error('post-deployment constructor or Safe readback mismatch');
}

const receipt = {
  ...plan,
  schema: 'h1dr4.proofvault-deployment-receipt/v3',
  status: 'confirmed_finalized',
  contract: expectedContract,
  transaction_hash: txReceipt.hash,
  signed_transaction_sha256: sha256(hexToBuffer(signedTransaction, 'signed transaction')),
  block_number: txReceipt.blockNumber,
  block_hash: txReceipt.blockHash,
  gas_used: txReceipt.gasUsed.toString(),
  effective_gas_price_wei: txReceipt.gasPrice?.toString() || null,
  actual_runtime_bytes: runtime.length,
  actual_runtime_sha256: sha256(runtime),
  immutable_masked_runtime_sha256: sha256(maskedRuntime),
  immutable_masked_template_sha256: sha256(maskedTemplate),
  independent_rpc_corroborated: true,
  finalized_on_both_rpc_endpoints: true,
  finality,
  post_deployment_safe_readback: postDeploymentSafeReadback,
  post_deployment_readback: readback,
};
const receiptPath = path.join(receiptsDir, `proofvault-base-${txReceipt.hash}.json`);
fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
writeJournal('confirmed_finalized', { receipt_path: receiptPath });
console.log(JSON.stringify({ ...receipt, receipt_path: receiptPath, journal_path: journalPath }, null, 2));
