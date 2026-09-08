# H1DR4 ProofVault contracts

`H1DR4ProofVault.sol` is the escrow and public commitment layer for confidential
vulnerability reports. The contract never receives report plaintext or a
decryption key. It stores commitments, admission permits, validator decisions,
escrow state, and encrypted chat events.

## Trust model

- The governor is an immutable Safe contract wallet from the first block. It
  authorizes target owners and exact funded-submission digests, rotates validator
  sets, can disable a compromised set, pauses new funding and submissions, and
  can deactivate a program. Safe owners can rotate under the Safe threshold, but
  the vault cannot later be pointed at a weaker governor.
- Every target authorization has a monotonically increasing epoch. Programs and
  permits bind that epoch, so revocation or reassignment invalidates stale
  funding, submission, and validator paths without iterating over old programs.
- Every validator set has at least two distinct validators and a threshold of at
  least two. Each submission snapshots one validator set. Changing the current set cannot
  rewrite an active or finalized submission; disabling a compromised set stops
  its votes and the submission can expire safely.
- A funded submission needs a one-use permit bound to chain ID, this contract,
  the program authorization epoch, current validator set, decision window,
  researcher, ciphertext hash, and report commitment. Duplicate commitments
  and excess pending submissions are rejected. The governor may cancel a permit
  before it is consumed.
- Target ownership is a governor-approved on-chain mapping. The portal must
  complete the real-world ownership check before calling `authorizeTargetOwner`.
- The payment token must transfer exact amounts. Incoming and outgoing balance
  deltas are checked before escrow credit or a key-release signal is accepted.

The release script accepts only allowlisted official Safe singleton, proxy, and
fallback-handler runtime hashes. At the release block the Safe must be at least
2-of-N and have no modules, guard, or module guard. This governance model is
intentionally conservative for the first mainnet beta.
A later release can replace on-chain permit transactions with expiring EIP-712
permits while preserving the same digest and replay invariants.

## State transitions

```text
funded: COMMITTED -> REWARD_RESERVED -> PAID
                  \-> REJECTED
                  \-> EXPIRED

private: COMMITTED -> VALIDATED -> owner authorizes -> REWARD_RESERVED -> PAID
                   \-> REJECTED / EXPIRED -> contributor refunds
```

Funded submission admission locks the configured critical reward. Validation
retains only the assessed reward; rejection or deadline expiry returns the full
reservation. `openSubmissions` is decremented exactly once at those terminal
validator/expiry transitions.

Private pools accept contributions only before their deadline. The named owner
must authorize a validated payout before that deadline; otherwise contributors
can refund and anyone can mark the submission expired.

`RewardPaid` and report-key release are deliberately separate. A researcher can
claim an earned funded reward after target-owner revocation, but the claim emits
`KeyReleaseDeferred` instead of releasing the report. The governor can later
call `rebindFundedReportOwner` only to the target's currently authorized owner;
an already-paid report is then released exactly once. Private reports keep their
explicit owner and release normally after exact payment.

If USDC cannot transfer to the researcher's original address, only that
researcher may call `claimRewardTo` and select a different nonzero recipient.
The report owner and key-release destination do not change with the payout route.

`KeyReleaseAuthorized` is emitted only after exact payout and a current target
authorization (or after a safe paid-report rebind). At release time the contract
refreshes the current owner's registered key hash. The off-chain release worker
must still wait for finality and verify chain ID, contract, payment token,
submission, target authorization epoch, recipient, amount, and owner key hash.

`sendEncryptedMessage` publishes ciphertext and metadata in a permanent public
event. Clients must use randomized authenticated encryption locally. Encoding
plaintext as hex is not encryption.

## Compile

The release compiler is `solc` 0.8.33 with the `paris` EVM target, optimizer
runs set to 200, and IR compilation enabled. Run from this directory:

```bash
npm ci
npm run compile
npm test
npm run attest:build
```

`SOLJSON_PATH` is forbidden. Compilation uses the lockfile-pinned compiler before
any signer secret is introduced. `attest:build` performs two clean installs and
requires their artifacts to match the release artifact byte-for-byte. Release
receipts bind externally reviewed source, artifact, reproducible-build, and
security-snapshot digests; the compiler settings; constructor arguments; creation
bytecode; deployed runtime; transaction hash; and post-deployment readback.
Immutable byte ranges are masked when comparing deployed code with the template.

The Base release path is deliberately narrow: `https://mainnet.base.org/` is
corroborated by `https://base-mainnet.public.blastapi.io/`, redirects are rejected,
the same finalized block and pending nonce must agree, and a confirmed deployment
is not sealed until both endpoints report the deployment block finalized. A
broadcast journal remains on disk if mining, finality, or readback fails.

## Mainnet release gate

Do not fund a deployment until all of the following are attached to one receipt:

1. a complete security scan of the exact source;
2. local EVM state-transition and adversarial-token tests;
3. verified Base chain ID and canonical USDC address;
4. an independently verified immutable Safe governor, validator addresses,
   threshold, and deadline policy;
5. an external source/artifact digest plus the clean-build attestation digest;
6. verified finalized runtime bytecode and constructor arguments;
7. H3RETIK job, Sibyl evidence, and notification receipts bound to the same
   workspace and engagement.
