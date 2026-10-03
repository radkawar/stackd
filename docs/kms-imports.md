# KMS imported material

`EXTERNAL` keys start in `PendingImport` without generated material. The generated
Smithy bindings expose `GetParametersForImport`, `ImportKeyMaterial` and
`DeleteImportedKeyMaterial`; these operations use the same IAM authorization,
typed storage and cryptographic consumers as generated KMS keys.

## Material and ownership

Supported imports are 32-byte symmetric keys, HMAC keys from the selected hash
size through 128 bytes, RSA 2048/3072/4096 private keys, NIST P256/P384/P521,
secp256k1 and Ed25519 private keys. RSA keys must have two primes and the declared
modulus size. ECC imports must use the declared named curve. Private keys use
PKCS8; RSA/ECC BER containers are normalized before validation and canonical
encoding. The native Ed25519 capture rejected an indefinite BER outer container.
ML-DSA `EXTERNAL` creation is rejected by AWS and locally.

Wrapping uses actual RSA OAEP with SHA-1/SHA-256, or RSA-wrapped AES-256 followed
by RFC 5649 unwrap for asymmetric material. OAEP authentication, AES wrap
integrity/length/padding and decoded private-key validity are checked before
state changes. RSA private keys require hybrid wrapping. Direct RSA-2048
wrapping is rejected for P521 and Ed25519. Deprecated PKCS#1 v1.5 wrapping is
rejected. These requirements follow the
[AWS import material guide](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-conceptual.html)
and [wrapping guide](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-encrypt-key-material.html);
the Ed25519 restriction is also captured live.

Each regional key retains its wrapping private keys and opaque import tokens.
Tokens last 24 service-time hours, bind the key/account/region and wrapping
algorithm, and remain reusable after an import or another parameter request.
Expired wrapping private bytes are cleared by the shared lifecycle scheduler or
a successful key transaction observing the deadline; token identity remains for
`ExpiredImportTokenException`. SQLite represents cleared private bytes as an
empty blob in its existing non-null column.
Key material and wrapping private bytes must be protected by the storage backend.

The shared key set owns material identity, bytes, descriptions and rotation
history. Regional records own import presence and expiration. Material IDs bind
the key ID and canonical bytes; the local SHA-256 construction is not a claim to
reproduce AWS's opaque identifier algorithm. Symmetric API responses expose IDs;
HMAC/asymmetric import responses do not. Removing the last regional import clears
the bytes while retaining used material identity for reimport. Imported master
and private key bytes and import tokens are omitted from conformance fixtures.
Synthetic plaintexts, public keys, signatures and derived outputs are retained
where they support cryptographic interoperability checks.

## Lifecycle and integrations

The first symmetric import becomes current. Later `NEW_KEY_MATERIAL` imports
stage one pending version; subsequent imports default to existing material.
Used material stays bound to the key, including after deletion or expiry.
Reimporting different bytes fails. Asymmetric/HMAC keys cannot change material.
Successful reimport enables a disabled key once all required versions are present.
Imported material supports on-demand symmetric rotation, with the existing
modeled two-minute completion delay; automatic rotation is unsupported.

AWS retains material pending rotation even after its `ValidTo` deadline. A live
capture accepted rotation to that expired material, made it current, and then
reported the key as `PendingImport`. Both encryption and decryption failed until
that material was reimported, after which old ciphertext decrypted successfully.
The local lifecycle now preserves pending versions through rotation and applies
expiry when the material becomes permanently associated with the key. Tests
cover expiry before a rotation request and while the accepted request is waiting,
including a replica whose copy does not expire.

Multi-Region replicas need their own wrapping parameters and imports. The
primary stages new material and owns its description; all replicas must import
that version before rotation is accepted. Descriptions and rotation history are
shared immediately in the local model. Deleting pending primary material removes
the pending version from all related keys. It does not cancel an already
accepted rotation request: AWS can rotate replacement material imported into
that pending slot before completion, without another `RotateKeyOnDemand` call.
If no pending version exists at completion, the request clears without creating
a rotation entry. Retained storage preserves the accepted request across these
mutations and service reconstruction.

Replica readiness is checked when rotation is requested. Native evidence shows
that deleting a replica's pending copy afterward does not cancel the primary
request. Rotation still makes that material current across regions; a region
missing its copy then becomes `PendingImport`. Reimport restores that region's
ability to decrypt ciphertext from a related key. The shared history and affected
regional states commit atomically, including when a regional backend write fails.
Replica material deletion and expiry otherwise leave other regions usable. Missing any used version makes that regional key
`PendingImport`, even if its current version is present. The current material ID
remains visible, but expiration metadata is omitted while the key awaits imports.

Expiry and accepted rotation run chronologically in service time during a KMS
transaction, driven by the shared scheduler and by requests observing due state.
State and regional material changes commit together; a failed write
rolls them back. Retained backends preserve material, wrapping parameters,
expiration and pending rotation across service reconstruction.
[SQLite storage](sqlite-state.md) now retains wrapping keys,
tokens, regional expiry and material history; the shared event journal remains open.

Tests exercise real HMAC bytes and OpenSSL public keys/signatures, RSA encryption,
ECDH shared secrets and the `EXTERNAL` response origin. They also cover corrupted
wrapping, BER reimport, previous ciphertext after rotation, conditional IAM
permissions, cross-account denial, regional token binding, failed regional
commits and promotion. An SQS integration loses access when imported material is
deleted after the data-key cache expires, then recovers the existing encrypted
message when the same material is reimported.

## Evidence and remaining scope

AWS documentation and owned AWS calls decide semantics. Primary API references:
[ImportKeyMaterial](https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html),
[GetParametersForImport](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetParametersForImport.html),
[DeleteImportedKeyMaterial](https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteImportedKeyMaterial.html)
and [RotateKeyOnDemand](https://docs.aws.amazon.com/kms/latest/APIReference/API_RotateKeyOnDemand.html).

Owned AWS captures from 2026-09-12 are in `testdata/aws/kms/`:

- `imports.json`: symmetric wrapping, token reuse, validation, rotation,
  deletion, disabled-key reimport and current-material expiry.
- `imports_families.json`: four HMAC sizes and eight asymmetric key families,
  actual MAC/signature/public-key outputs and BER reimport acceptance.
- `imports_multi_region.json`: shared material identity/descriptions, regional
  imports/expiry, pending-material deletion and rotation. Cases named
  `replica_first_import` and `replica_second_import` intentionally failed because
  they supplied a description. They are not evidence of successful import.
- `imports_edges.json`: wrong-key/corrupt tokens, corrupt ciphertext and
  mutation while on-demand rotation is in progress.
- `imports_expiry.json`: explicitly incomplete. Repeated `ListKeyRotations`
  calls continued to report expired pending material as `IMPORTED` for the
  bounded 15-minute observation period. The final state was not established;
  the probe timed out and successfully scheduled its key for deletion. The later
  activation probe below establishes behavior beyond this read-only observation.
- `imports_rotation_expiry.json`: rotation to expired pending material,
  subsequent cryptographic denial and successful reimport recovery. Deleting a
  different pending version during rotation removed it from history; the
  on-demand status eventually cleared without rotating the deleted version.
- `imports_rotation_replacement.json`: deleting pending material and importing
  a different replacement while rotation is running. The original accepted
  request rotated the replacement without another rotation request.
- `imports_rotation_replica.json`: deleting a replica's pending material after
  primary rotation was accepted. Rotation completed, the primary remained
  usable, and the replica awaited reimport of its newly current material.
- `imports_data_plane.json`: imported RSA encryption/decryption and ECDH key
  agreement. OpenSSL independently verified the native plaintext and shared
  secret; AWS reported `EXTERNAL` as the ECDH key origin. Deletion blocked these
  operations and reimport restored them.

The probes live under `scripts/aws/kms_imports*_probe.py`, use OpenSSL and the real
AWS CLI, and schedule every created key for deletion in `finally`. Successful
cleanup means scheduled deletion, not immediate physical removal. Imported probe
replicas have seven-day deletion windows; their primary waits for the replicas
and then its own window. The earlier KMS service-linked role remains in use by
owned multi-Region keys until actual deletion. These captures do not establish
complete KMS parity.

AWS metadata can lag actual expiry: a captured current key became `PendingImport`
while `ListKeyRotations` still reported its expired material as `IMPORTED`.
This differs from pending material, which remains eligible for rotation after
its deadline as demonstrated by the activation capture. Deleting pending material during an accepted rotation succeeded while
the immediately following status still contained the start date. The local
model keeps accepted requests until their modeled completion and applies
regional availability at that point. Variable propagation and remaining
import/rotation concurrency remain open.
Real 24-hour token expiry, full validation/error ordering and noncommercial
partition conformance also remain open. SM2/China-only material, custom stores
and attestation are explicitly lower priority; they remain in the full target.
