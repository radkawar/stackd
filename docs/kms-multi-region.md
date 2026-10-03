# KMS multi-Region keys

Commercial `AWS_KMS` keys support generated `CreateKey(MultiRegion=true)`,
`ReplicateKey` and `UpdatePrimaryRegion` requests. Related keys share their
`mrk-` identifier, cryptographic material, material history and rotation settings.
Policies, grants, aliases, descriptions, tags and enabled state belong to each
regional key. KMS remains a partial service.

Stackd follows the [AWS shared-property contract](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html),
including actual shared material and independent regional access controls.

## Regional operations and state

A replica starts in `Creating`, omits `CurrentKeyMaterialId`, and becomes
`Enabled` after five service-time seconds. Omitted description and tags are
empty; an omitted policy selects the destination account's default policy.
Primary policy, grants and aliases are not copied. Replication rejects duplicate
Regions, including replicas pending deletion, another partition, an unknown
Region, and an account-disabled opt-in Region. Account Management supplies
current opt-in state. Only an enabled primary can replicate.

Promotion requires an existing enabled replica and permissions on both affected
keys. The primary designation changes atomically; both keys enter `Updating`
for five service-time seconds and resume `Enabled`. Cryptographic operations
continue during `Updating`; enabling, disabling, replication and scheduling
key deletion are rejected. Promoting a disabled primary or replica returns
`DisabledException`. Updating the existing primary Region succeeds without a
transition. Other replicas retain their state and regional configuration.
See [ReplicateKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_ReplicateKey.html)
and [changing the primary Region](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-update.html).

Symmetric ciphertext produced in any related Region decrypts with the local
key and returns its local ARN. The original ciphertext header remains
authenticated. Implicit key lookup, the shared key ID and a local replica ARN
work; explicitly supplying the source Region's ARN returns
`IncorrectKeyException`. RSA, ECDSA and HMAC replicas use identical actual
material through the existing cryptographic implementations. Grant tokens and
grants retain regional ownership. Cross-account cryptography requires the
local replica's policy and the caller's permissions.

Rotation mutations apply only to the primary; replicas return
`UnsupportedOperationException`. Shared material history preserves old
ciphertext, including after promotion and service reconstruction. Disabling a
replica does not pause primary rotation. Disabling the primary does. The
existing [rotation behavior](kms-cryptography.md) applies to the shared history.

A primary with replicas enters `PendingReplicaDeletion` without a deletion
date and retains `PendingDeletionWindowInDays`. Its configured rotation status
still reports enabled when rotation was enabled. Replicas continue to work.
After the last replica is deleted, the primary enters `PendingDeletion`, starts
its own configured window, and reports rotation disabled. Advancing service time
past multiple deadlines preserves their original order: observing an expired
replica late does not extend the primary's waiting period. Canceling either
deletion state clears the window and leaves the key disabled.
`PutKeyPolicy` still works in both deletion states; tagging and untagging return
`KMSInvalidStateException`. The native capture establishes these distinctions.
The final deletion schedule follows the [AWS multi-Region deletion contract](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html#deleting-multi-region-keys).

## Authorization and ownership

The shared evaluator receives `kms:MultiRegion`, `kms:MultiRegionKeyType`,
`kms:ReplicaRegion` and `kms:PrimaryRegion` as applicable. Replication checks
`kms:ReplicateKey` against the source policy, `kms:CreateKey` in the destination
Region, and `kms:TagResource` there when tags are supplied. Promotion checks
`kms:UpdatePrimaryRegion` against both key policies. Explicit denies, session
limits and organization controls use the existing evaluator.

An omitted creation policy is service-owned and does not require the creator
to hold `kms:PutKeyPolicy`. Supplied policies still receive principal validation
and the policy-lockout safety check unless explicitly bypassed.

The first multi-Region key provisions the protected IAM role
`AWSServiceRoleForKeyManagementServiceMultiRegionKeys`, with captured trust,
description and managed-policy attachment. Missing-role creation requires
`iam:CreateServiceLinkedRole` for `mrk.kms.amazonaws.com`. Once the role exists,
even an explicit deny of that IAM action does not prevent KMS key creation.
The role belongs to IAM independently of individual KMS keys; provisioning does
not remove it if a subsequent key-storage commit fails.

The IAM deletion worker uses KMS's actual regional dependencies and reports
`Account owns one or more multi-Region keys` with resource usage. Creation and
deletion both acquire KMS before IAM; the worker releases IAM before calling
KMS. KMS holds its state stable through the final IAM decision. This uses the
existing service-linked role boundary and worker.
See [AWS's KMS service-role documentation](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-auth-slr.html).
Its prohibition on deleting the role needs qualification: the live API accepted
our deletion job, which subsequently failed because keys remained.

One typed `KeySetRecord` owns shared material, specification, usage, rotation and
primary/replica topology. Regional `KeyRecord` rows reference it by ID and retain
only regional state. The transaction adapter caches each shared record once,
commits related regional writes together, and deletes material only when the
last key is removed. Both single-Region and multi-Region keys use this model.
Storage remains replaceable through `storage/kms`; no opaque resource blobs or
parallel material copies are persisted per replica.

## AWS evidence and remaining work

[`multi_region.json`](../testdata/aws/kms/multi_region.json) contains 85 native
observations from 2026-09-12, plus initial primary metadata and cleanup records.
`scripts/aws/kms_multi_region_probe.py` reproduces replication, regional crypto,
rotation, promotion, deletion states and service-role behavior using owned keys.
The capture also includes supplementary deletion-state calls on the same keys.
The account had `ap-east-1` enabled, so that Region test created an additional
replica, which was included in cleanup.

[`multi_region_permissions.json`](../testdata/aws/kms/multi_region_permissions.json)
and `scripts/aws/kms_multi_region_permissions_probe.py` capture an owned IAM user
creating a multi-Region key with only `kms:CreateKey` allowed and
`iam:CreateServiceLinkedRole` explicitly denied after the role already existed.
Credential-propagation failures are retained separately from the successful call.

The September 22 follow-through records `NotFoundException` for the `us-east-1`
and `ap-east-1` replicas and the separate permissions-probe primary. Their actual
key identities were recovered from the original CloudTrail `CreateKey` events,
not inferred from normalized fixture identifiers. At that follow-through, the
promoted `us-west-2` primary was `PendingDeletion`, with no replicas and a deletion
date of `2026-09-28T10:12:34.124Z`. Its actual ID and then-current metadata remain
in `multi_region.json` under `cleanup_followup`. The temporary IAM user and access
key were deleted; the service-linked role was retained until the primary expired.

The October 3 shutdown pass observed `NotFoundException` for that key in all
three Regions. Deleting the original KMS service-linked role then reached
`SUCCEEDED`, followed by `GetRole` returning `NoSuchEntity`. This closes those
specific cleanup obligations; the earlier capture remains unchanged. The pass
did not observe the exact instant at which the primary expired.

Signed SDK tests cover regional crypto, negative authorization, independent
policies/grants, account isolation, opt-in Regions, shared rotation, promotion,
retained-storage recovery, transaction rollback and ordered deletion. The five-
second transitions are deterministic models, not AWS timing guarantees. Native
key absence and subsequent unused service-role cleanup have been observed; the
exact final primary-expiry timing was not captured.
Asymmetric/HMAC replica tests validate local interoperability against the AWS
shared-material contract; the multi-Region native crypto capture is symmetric.

Noncommercial multi-Region availability and service-role definitions, regional
quotas, remaining permission/error precedence and variable synchronization need
further conformance work. [Imported key material](kms-imports.md) now supports
regional expiry, shared material and rotation. [SQLite storage](sqlite-state.md)
retains these typed records. The shared scheduler now advances readiness, promotion,
rotation, expiry and ordered deletion without API traffic, using the same
transition functions as requests and dependency checks. Lifecycle events and
durable attempts remain kernel work; see [scheduler behavior](architecture.md#background-jobs).
Specialist SM2/China, custom stores and recipient
attestation remain lower-priority KMS work.
