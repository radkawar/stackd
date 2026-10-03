# KMS cryptography

KMS uses generated Smithy API contracts, service-owned typed key storage, and the
shared IAM evaluator. Symmetric encryption uses AES-GCM with authenticated key
identity and encryption context. Its local ciphertext envelope is not AWS's
proprietary symmetric ciphertext format. HMAC operations return standard raw MACs.
RSA operations use actual RSA keys, OAEP ciphertext and PKCS#1/PSS signatures.
ECC operations use ECDSA, Ed25519 and NIST ECDH with standard exported key formats.
ML-DSA supports all three parameter sets and external message representatives.
KMS remains partial.

## Capability priorities

Pinned SDK models supply the complete operation inventory. Primary AWS contracts
and native captures must establish key families, aliases, lifecycle,
cross-service uses, asymmetric encryption semantics, key states and replica
synchronization; operation registration alone establishes none of these.

Common application paths take priority: symmetric envelope encryption,
policies/grants, key lifecycle and rotation, and encryption used by other
services. SM2/China-only algorithms, custom HSM/external key stores, enclave
attestation and further specialist ML-DSA conformance remain in scope at lower
priority; they do not block progress on core services. Replica and imported-key
work should follow concrete application workflows.

`EnableKeyRotation`, `DisableKeyRotation`, `GetKeyRotationStatus`,
`RotateKeyOnDemand` and `ListKeyRotations` now rotate generated symmetric material
and preserve decryption of older ciphertext, including encrypted queue data keys.

[Grant behavior and evidence](kms-grants.md) cover IAM/STS principal binding,
session-policy composition, delegation, cross-account trust and encrypted queues.

The implemented key families are symmetric encryption, four HMAC sizes, three
RSA sizes, the three NIST curves, secp256k1, Ed25519 and all three ML-DSA sizes.
SM2 and the remaining shared lifecycle behavior still need implementation;
registration or a compatible SDK response alone does not complete them.

## HMAC keys and operations

| Key spec | Required usage | MAC algorithm | Key and MAC bytes |
| --- | --- | --- | --- |
| HMAC_224 | GENERATE_VERIFY_MAC | HMAC_SHA_224 | 28 |
| HMAC_256 | GENERATE_VERIFY_MAC | HMAC_SHA_256 | 32 |
| HMAC_384 | GENERATE_VERIFY_MAC | HMAC_SHA_384 | 48 |
| HMAC_512 | GENERATE_VERIFY_MAC | HMAC_SHA_512 | 64 |

One internal mapping owns the key-spec, algorithm and digest relationship. Key
creation generates the matching amount of cryptographic material and retains it
in the existing protected `KeyRecord`. HMAC metadata reports `MacAlgorithms`,
with no encryption algorithms or current symmetric-key material ID. Material
survives service reconstruction when the caller retains its storage backend.

`GenerateMac` computes the standard SHA-2 HMAC; `VerifyMac` compares it in constant
time. They use the generated message constraint of 1–4096 bytes and require the
algorithm matching the key spec. Repeated generation for the same key/message
returns the same bytes. Verification failure returns `KMSInvalidMacException`,
including a wrong-length MAC; it never returns a successful `MacValid: false`.

Disabled and pending-deletion keys reject MAC operations. A disabled key is
rejected before checking algorithm compatibility. `DryRun` still validates the
request: an incorrect MAC fails verification even when `DryRun` is true.
Successful dry runs return the modeled `DryRunOperationException`.

Requests use the existing KMS key-policy/IAM/Organizations authorization path,
including key ARN or alias ARN for cross-account requests. The requested
`kms:MacAlgorithm` and alias conditions reach that evaluator. A grant can permit
GenerateMac or VerifyMac independently; explicit denies still win and revocation
invalidates its tokens. HMAC grants permit CreateGrant, RetireGrant, DescribeKey,
GenerateMac and VerifyMac. Encryption operations and encryption-context
constraints are rejected for these keys.

## RSA keys and operations

`RSA_2048`, `RSA_3072` and `RSA_4096` require either `ENCRYPT_DECRYPT` or
`SIGN_VERIFY` usage. Private keys are stored as PKCS#8 DER in the existing typed
key repository. `GetPublicKey` exports X.509 SubjectPublicKeyInfo DER and reports
the key's actual algorithms. Reconstructing a provider over the same storage
preserves the private key. Disabled keys still allow public-key export;
pending-deletion keys reject it. Cryptographic operations require an enabled key.

Encryption supports `RSAES_OAEP_SHA_1` and `RSAES_OAEP_SHA_256`, using the same
digest for OAEP and MGF1. Ciphertexts are raw RSA values of 256, 384 or 512 bytes
and accept public-key encryption performed outside KMS. Plaintext limits follow
the RSA modulus and OAEP digest: 214/190, 342/318 and 470/446 bytes respectively.
An empty encryption context is accepted; a nonempty one is rejected. RSA
decryption requires an explicit key and the original algorithm. Invalid
ciphertext fails before a dry-run success is returned.

`ReEncrypt` decrypts and encrypts using independently selected source and
destination algorithms, supporting RSA-to-RSA and symmetric-to-RSA in both
directions. Symmetric sides authenticate their own encryption context. Material
IDs appear only for symmetric sides. Each side requires its own permission,
receives its actual `kms:EncryptionAlgorithm`, and evaluates
`kms:ReEncryptOnSameKey` against resolved key identity, including aliases.

Signing supports PKCS#1 v1.5 and PSS with SHA-256, SHA-384 and SHA-512. `RAW` is
the default message type and hashes the supplied message. `DIGEST` requires the
exact selected digest length and does not hash it again. PSS salt length equals
digest length, including during verification. Invalid signatures return
`KMSInvalidSignatureException`, including during dry runs. The evaluator receives
`kms:SigningAlgorithm` and the effective `kms:MessageType`. Public-key retrieval,
signing and verification are separate permissions and grant operations. RSA
grants reject encryption-context constraints and operations incompatible with
the key's usage.

`GenerateDataKeyPair` and `GenerateDataKeyPairWithoutPlaintext` generate all three
RSA sizes for external use. They wrap the PKCS#8 private key under a symmetric
KMS key and return its matching SPKI public key. They do not retain the pair as
a KMS resource. The latter operation omits plaintext private material; `Decrypt`
recovers it when supplied the original encryption context. The two operations
require separate permissions and propagate `kms:DataKeyPairSpec` and grant
constraints through the shared evaluator. The same operations now generate the
five supported ECC key-pair specifications too; SM2 and attestation recipients
remain open.

## Elliptic-curve keys and operations

| Key specification | Signing algorithms | Key agreement |
| --- | --- | --- |
| ECC_NIST_P256 | ECDSA_SHA_256 | ECDH |
| ECC_NIST_P384 | ECDSA_SHA_384 | ECDH |
| ECC_NIST_P521 | ECDSA_SHA_512 | ECDH |
| ECC_SECG_P256K1 | ECDSA_SHA_256 | Unsupported by AWS |
| ECC_NIST_EDWARDS25519 | ED25519_PH_SHA_512, ED25519_SHA_512 | Unsupported by AWS |

NIST keys require either `SIGN_VERIFY` or `KEY_AGREEMENT`; these usages cannot
be combined. secp256k1 and Ed25519 require `SIGN_VERIFY`. Signing and public-key
export share the existing RSA authorization and lifecycle paths. The provider
uses Go's `crypto.Signer` contract and stores standard PKCS#8 private keys.
The secp256k1 library supplies its curve, key generation and verification. Its
standard-library key conversion supplies randomized ECDSA signing; its native
RFC 6979 signer would produce deterministic signatures that differ from the
captured AWS repeat behavior. The small DER adapter supplies the standard
secp256k1 envelopes that `crypto/x509` does not support.

ECDSA signatures use ASN.1 DER, with RAW hashing and exact-length DIGEST input.
Ed25519's ordinary algorithm requires RAW input and produces a deterministic
signature. Its PH algorithm requires a 64-byte DIGEST input and performs another
SHA-512 prehash over those bytes, as AWS documents and its captured signatures
confirm. Algorithm/message-type mismatches fail before signing or verification.

`DeriveSharedSecret` accepts a same-curve peer SPKI key and returns the raw ECDH
secret: 32, 48 or 66 bytes for P256, P384 or P521. It accepts peers generated
outside KMS, including a key's own public key. Invalid DER, wrong key types and
curve mismatches fail with `ValidationException`; dry runs still validate peer
keys. Disabled/deleting keys reject derivation. Public-key export remains a
separate permission. Cross-account key policies, IAM policies, aliases,
`kms:KeyAgreementAlgorithm`, compatible grants, explicit denies and revocation
use the shared evaluator. Encryption-context grant constraints are rejected.

## ML-DSA keys and operations

`ML_DSA_44`, `ML_DSA_65` and `ML_DSA_87` require `SIGN_VERIFY` usage and support
`ML_DSA_SHAKE_256`. Their signatures contain 2420, 3309 and 4627 bytes respectively.
Signing uses fresh randomness. `RAW` is the default message type and accepts
1–4096 bytes. `EXTERNAL_MU` accepts exactly 64 bytes and skips computing the
message representative internally. `DIGEST` is incompatible with these keys.
Signatures created using RAW and its corresponding external representative
cross-verify in either mode. Invalid signatures return
`KMSInvalidSignatureException`, including during dry runs.

The provider uses the Go ML-DSA implementation from the pinned
[`metacubex/mldsa` backport](https://github.com/MetaCubeX/mldsa), which exposes
both external-μ signing and verification. The public Go ML-DSA API lacks the
latter operation; [Go issue 80272](https://github.com/golang/go/issues/80272)
tracks that limitation. The adapter uses the shared `crypto.Signer` path and
does not implement the cryptographic algorithm itself.

Public keys use SPKI DER with the RFC 9881 algorithm identifiers and absent
parameters. Private storage uses its standard PKCS#8 seed-only encoding, allowing
the typed repository to reconstruct the same key. Public-key export, signing,
verification and grants share existing key-policy/IAM authorization and key-state
checks. ML-DSA is not an AWS data-key-pair specification; the generated API layer
rejects it for those operations.

## Symmetric key rotation

The typed repository stores material versions in creation order, with the last
version current. Ciphertext headers authenticate both key ARN and material ID.
Encryption and data-key generation use current material; decryption selects the
version named by the ciphertext. `Decrypt.KeyMaterialId` and both material IDs in
`ReEncrypt` describe the versions actually used. Rotation preserves key identity,
policies, aliases and older material until key deletion. These semantics follow
[AWS's rotation contract](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html).

Automatic rotation accepts 90–2560 days, defaulting to 365. Repeating enable with
the same period, or omitting the period while already enabled, preserves the
schedule. Changing it schedules from the request time. Disabling rotation hides
period/date fields; enabling it again without a period defaults to 365. These
details are captured in `rotation.json`; the general API contract is
[EnableKeyRotation](https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html).

Pending-deletion status reports rotation disabled, while canceling deletion
restores the configuration. Disabled keys retain their schedule but skip
automatic rotation. Re-enabling an overdue key rotates once immediately and
starts a new period. An enabled key observed after multiple elapsed periods
retains each scheduled version. AWS-managed symmetric keys rotate every 365
days and reject customer rotation changes. See
[GetKeyRotationStatus](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html).

The fresh native AWS-managed SQS key reported `KeyRotationEnabled: false`, with
no period/date fields, including later reads. This differs from the API guide's
statement that AWS-managed status is always true. The local response matches
the capture, while its material follows the documented fixed annual schedule.
Status behavior for older managed keys still needs native evidence. The captured
SQS policy also supplies the service-mediated crypto/grant permissions and
account metadata-read permissions used by the local managed key.

On-demand requests retain their start time and complete after two minutes of
service time. Repeated requests while pending accept the existing request.
An accepted request completes even if the key is subsequently disabled or
scheduled for deletion, as the native capture confirms. Completion leaves the
automatic schedule intact. The provider enforces the documented 25 on-demand
rotations per key and rejects a new request within 20 minutes of the next
automatic rotation. See
[RotateKeyOnDemand](https://docs.aws.amazon.com/kms/latest/APIReference/API_RotateKeyOnDemand.html).

The shared scheduler applies due rotations without request traffic, using service
time and the same transition functions as key operations. Pending requests,
schedules and material history survive provider reconstruction over retained
storage. Failed commits publish neither a new version nor an accepted request.
Bounded drains advance each key set through one deadline per callback.
Lifecycle events and durable attempt records remain open; see
[scheduler ownership and verification](architecture.md#background-jobs).

Rotation history defaults to completed rotations. `ALL_KEY_MATERIAL` includes
the original version, which has no rotation date/type. Entries are chronological
and report `CURRENT` or `NON_CURRENT`; pagination preserves this order and key
scope. These fields follow
[ListKeyRotations](https://docs.aws.amazon.com/kms/latest/APIReference/API_ListKeyRotations.html).

All five operations reject aliases. Only rotation status supports cross-account
access, with key-policy and identity-policy permission. The shared evaluator
receives `kms:RotationPeriodInDays`, including 365 when the request omits it,
even if the already enabled key retains a shorter period. Native policy probes
confirm this default with `Null` and numeric conditions. HMAC status is false,
its rotation list is empty, and disabling rotation succeeds; enabling or
requesting rotation returns `UnsupportedOperationException`.

## Evidence

[`hmac.json`](../testdata/aws/kms/hmac.json) records commercial AWS KMS calls on
2026-09-12 in us-east-1. It covers all four key sizes, usage validation, metadata,
MAC lengths/repeatability, verification failures, algorithm mismatches, dry runs,
message bounds, incompatible encryption, grant compatibility, and disabled and
pending-deletion behavior. Synthetic messages were used. Key material was never
exported; grant tokens are omitted from the capture.

`scripts/aws/kms_hmac_probe.py` creates owned temporary keys, revokes its test
grants and schedules key deletion with the minimum seven-day window. The four
captured keys were confirmed PendingDeletion for 2026-09-19; scheduling is not
immediate deletion. The probe changes no preexisting keys or account policies.

SDK tests replay the captured outcomes and metadata. A separate SDK test uses
the independent RFC 4231 section 4.2 vectors through the real request/response
path and a reconstructed typed storage backend. Its standard fixture material
is supplied directly through that backend, not through an invented KMS API.
Root integration tests exercise cross-account key/identity policy intersections,
MacAlgorithm and RequestAlias conditions, verification-only grants, explicit
denies and revocation. These policy tests run locally; they are not a claim of
captured native coverage for every authorization combination.

[`rsa.json`](../testdata/aws/kms/rsa.json) records 255 commercial AWS observations
on 2026-09-12 in us-east-1, across one symmetric wrapping key and six RSA keys
(three sizes, two usages). It captures metadata, public keys, OAEP size bounds,
OpenSSL-to-AWS decryption, both directions of RSA/symmetric re-encryption,
RAW/DIGEST signing and verification, malformed ciphertext/signature errors,
dry runs, grants and public-key lifecycle behavior. Native data-key-pair private
material was checked with OpenSSL and decrypted by AWS, then discarded. The
capture retains public keys, synthetic-message ciphertext/signatures and private
field lengths, with normalized account/key IDs and no grant tokens or private
keys.

`scripts/aws/kms_rsa_probe.py` reproduces these scenarios with owned temporary
keys. It revokes test grants and schedules every key for deletion with a seven-day
window. All seven captured keys were confirmed PendingDeletion for 2026-09-19;
three were temporarily restored for supplementary cases and rescheduled. The
ten cleanup entries describe those seven keys, not ten distinct resources.

RSA SDK tests compare selected captured errors and algorithm metadata, exercise
all supported size/algorithm combinations, verify signatures independently with
Go's RSA implementation, accept externally encrypted ciphertext and externally
created signatures, and round-trip both data-key-pair outputs through KMS
decryption. They check private-key persistence after provider reconstruction.
Local integration tests cover cross-account key/identity policy intersections,
alias/algorithm/message-type conditions, verification/public-key grants,
constrained data-key-pair grants, explicit denies, revocation, and both sides of
re-encryption authorization. Same-key policy conditions and non-default PSS salt
rejection follow the primary contract; they were tested locally, not captured
against AWS in this probe.

[`ecc.json`](../testdata/aws/kms/ecc.json) records 164 native observations on
2026-09-12 in us-east-1, across eight ECC keys and one symmetric wrapping key.
The capture covers all five ECC specifications, NIST agreement usages, algorithm
metadata, RAW/DIGEST signatures and repeatability, message-type errors, grants,
public-key lifecycle, ECDH validation and both data-key-pair APIs. OpenSSL agreed
with all three native ECDH results and derived matching public keys from every
generated pair. Private key material and shared secrets are omitted.

Two immediate public-key reads after scheduling deletion succeeded; later reads
returned `KMSInvalidStateException`. The local provider currently enforces the
committed deletion state immediately, so this propagation gap remains open.
A supplementary native Go SDK probe confirmed that an empty, unmodeled
`ValidationException` message is surfaced as `UnknownError` by the SDK; the CLI
capture represents the same message as an empty string.

`scripts/aws/kms_ecc_probe.py` reproduces the main ECC scenarios, revokes its
grants and schedules owned keys for deletion. All nine keys were confirmed
PendingDeletion for 2026-09-19. The P256 agreement key was temporarily restored
for the Go SDK check and rescheduled; its updated cleanup entry is recorded.
SDK tests replay captured signing errors/metadata, verify native AWS signatures
through the production verifier, check randomized ECDSA and deterministic
Ed25519 behavior, and reconstruct providers over retained private material.
OpenSSL checks every local ECC data-key-pair private/public export; that test
requires the `openssl` executable. Local integration tests exercise ECDH
cross-account key/identity policies, aliases, algorithm conditions and grants.

[`mldsa.json`](../testdata/aws/kms/mldsa.json) records 87 native observations on
2026-09-12 in us-east-1 across all three ML-DSA sizes. It captures public keys,
RAW/external-μ signatures and cross-verification, randomized repeat signatures,
message bounds and type errors, algorithm mismatches, malformed signatures,
dry runs, grant compatibility and disabled/pending-deletion behavior. The probe
independently computes the FIPS 204 representative with Python SHAKE256 and
verifies it against AWS. Public keys and signatures over synthetic messages are
retained; private material is never exported and grant tokens are omitted.

`scripts/aws/kms_mldsa_probe.py` reproduces these scenarios, revokes test grants
and schedules its owned keys for deletion. All three keys were confirmed
PendingDeletion for 2026-09-19 with the minimum seven-day window.
SDK tests compare captured errors and metadata, verify native signatures through
the production verifier in both modes, and reconstruct providers over retained
private material. Local integration tests check cross-account key/identity
policies, algorithm/message-type/alias conditions, verification-only grants,
explicit denies and revocation. Those authorization combinations were exercised
locally, not captured against AWS in this probe.

[`rotation.json`](../testdata/aws/kms/rotation.json) retains 90 AWS responses and
one explicitly identified CLI validation rejection from 2026-09-12 in us-east-1.
Repeated identical polls are collapsed. One symmetric key supplies three actual
on-demand rotations, old-ciphertext decryption/re-encryption, history pagination,
schedule changes, disabled/deleting transitions and period-condition probes.
One HMAC key checks eligibility. Account/key IDs are normalized, opaque markers
are omitted, and retained ciphertext/plaintext uses synthetic data only.

`scripts/aws/kms_rotation_probe.py` reproduces the main and supplementary cases.
Both owned keys are PendingDeletion for 2026-09-19; the six cleanup records
include repeated scheduling of the symmetric key during supplementary captures.
The temporary alias was deleted and each temporary key policy restored.
An additional temporary encrypted SQS queue was deleted after capturing the
AWS-managed `alias/aws/sqs` key policy, status and mutation denials. That managed
key remains under AWS ownership and cannot be scheduled for customer deletion.

SDK tests replay selected native errors and fields, exercise real retained-key
decryption, reconstruction, copy isolation, failed commits, chronological
pagination and service-time rotation. Full-stack tests deliver SQS messages
encrypted on both sides of an automatic rotation while enforcing KMS permissions,
and exercise period conditions and cross-account status. Automatic multi-period
timing, managed-key recurrence, the 25-rotation quota and the near-schedule
conflict boundary follow primary documentation; they were not captured over
months or exhausted against AWS. The fixed two-minute delay models the captured
asynchronous transition, not AWS's variable completion/propagation timing.

Primary references:

- [HMAC keys](https://docs.aws.amazon.com/kms/latest/developerguide/hmac.html).
- [GenerateMac](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateMac.html).
- [VerifyMac](https://docs.aws.amazon.com/kms/latest/APIReference/API_VerifyMac.html).
- [KMS condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html#conditions-kms-mac-algorithm).
- [RFC 4231 vectors](https://www.rfc-editor.org/rfc/rfc4231.html#section-4.2).
- [RSA key specifications and algorithms](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html).
- [GetPublicKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html).
- [Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html).
- [GenerateDataKeyPair](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPair.html).
- [GenerateDataKeyPairWithoutPlaintext](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKeyPairWithoutPlaintext.html).
- [Re-encryption conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html#conditions-kms-reencrypt-on-same-key).
- [DeriveSharedSecret](https://docs.aws.amazon.com/kms/latest/APIReference/API_DeriveSharedSecret.html).
- [secp256k1 implementation](https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4).
- [ML-DSA verification and message types](https://docs.aws.amazon.com/kms/latest/APIReference/API_Verify.html).
- [ML-DSA key encoding](https://www.rfc-editor.org/rfc/rfc9881.html#section-6).

## Remaining completion work

Regional quotas, variable key/grant propagation, remaining authorization/error
precedence and noncommercial partition conformance need native evidence and
implementation. Remaining rotation timing/conformance, the SM2 key family and key agreement,
custom-store keys, attestation recipients, PostgreSQL and coordinated durable
recovery remain open. [Imports](kms-imports.md) and [SQLC-backed SQLite storage](sqlite-state.md)
now preserve actual material and typed lifecycle state. The implemented cryptography does not complete
those shared KMS capabilities.
[Multi-Region keys](kms-multi-region.md) now share cryptographic material and
rotation history with independent regional authorization and modeled lifecycles.
Their remaining conformance and native cleanup windows are documented there.
