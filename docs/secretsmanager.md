# Secrets Manager

The generated AWS JSON 1.1 frontend dispatches to typed secret, version, policy,
rotation and replication owners. `storage/secretsmanager.Repository` has shared-domain
memory and service-owned SQLC/SQLite implementations. Secret metadata, labels,
wrapped data keys, encrypted payloads and scheduled work are separate records;
there is no plaintext credential map or generic resource blob store.

This is an implemented application path, not a claim of complete AWS parity.
The operation inventory is in `services.json`; open behavior boundaries remain in
`../TODO.md`.

## State, authority and encryption

- Names, incarnations, versions and policies preserve partition/account/Region
  scope. Version tokens identify immutable payloads. Replaying a token with the
  same value can add explicitly supplied labels; changing its payload fails.
  `AWSCURRENT`, `AWSPREVIOUS`, custom stages and unlabeled versions have distinct
  transitions. Recovery-window deletion and physical removal use service time.
- Actual identity, resource, session, boundary and organization policy evaluation
  applies. Resource policies use the shared principal binder, not a second IAM
  evaluator. Tag changes enforce the native post-change authorization boundary.
  The canonical `secretsmanager:SecretId` condition is an ARN even for name input;
  omitting a version stage does not synthesize an `AWSCURRENT` request condition.
  `PutSecretValue` does not populate `secretsmanager:VersionStage`, even when its
  VersionStages list contains multiple labels; GetSecretValue and
  UpdateSecretVersionStage keep their scalar request-stage conditions. The
  [Parameter Store reference fixture](../testdata/aws/ssm/secret_references.json)
  includes an owned-role equality/inequality/Null/set-operator matrix proving
  this action-specific absence, without weakening shared IAM cardinality checks.
  Missing-name reads also evaluate authority before revealing absence, using a
  symbolic unknown-six-character suffix scope: broad suffix grants can reach
  ResourceNotFound, while exact/restricted suffix grants remain denied. No
  concrete suffix or secret resource is fabricated.
- `PutSecretValue` evaluates current authority before reporting modeled length,
  required-field or stage-list constraints. This rejection-only path binds the
  generated input without executing the invalid command. Captured incompatible
  JSON list/member types instead fail first with `SerializationException`.
  Authorized modeled-bound violations return `ValidationException`; an authorized
  write with neither value returns `InvalidRequestException`. Domain errors such
  as conflicting values or invalid stage ownership retain their distinct codes.
- Values use AES-GCM with real KMS-generated and wrapped data keys. The encryption
  context contains `SecretARN` and `SecretVersionId`. Custom-key admission performs
  the native validation operations. KMS access denial is not a cryptographic
  failure, and disabled/pending-deletion keys do not return stored plaintext.
- A fresh write can succeed without `kms:Decrypt`; same-token replay requires
  decryption to compare the immutable value. Changing the configured key retains
  old wrapping keys. Only current, previous and pending stages are candidates for
  re-encryption; other historical values remain under their previous keys.
  Native key changes can succeed despite old-key decrypt or new-key encrypt
  denial, without silently making the historical value decryptable by the new key.
- KMS commands use the same native command-savepoint boundary as their consumers.
  Rejected nested KMS calls can be handled without poisoning an enclosing secret
  transition. KMS joins the transaction before taking its working-set mutex,
  avoiding the scheduler/SQLite lock inversion exposed by this integration.

Replica creation, collision/overwrite, stage and metadata propagation, removal and
promotion use the regional KMS and account interfaces. Source decryption and
regional encryption are actual permission checks. A failed replica does not roll
back a successful primary write. Replica payloads remain readable while direct
replica metadata/policy mutation is rejected. The retained native capture also
returns an empty replica `ListSecretVersionIds` despite readable staged values.

## Rotation and consumers

Rotation validates actual Lambda invoke authority and executes the captured
`createSecret`, `setSecret`, `testSecret` and `finishSecret` protocol through the
real Lambda Runtime API. Customer code performs secret writes and label promotion;
the scheduler does not manufacture a successful rotation. Lambda invocation is
outside repository transactions. Claimed work is fenced against changed secret
incarnations, cancellation and replacement before completion is committed.

Rate/cron windows use the shared scheduler. Deferred test rotation, cancellation,
pending-version ownership and retry work are retained. Retry timing is a local
scheduler policy, not a claim that AWS uses the same backoff. Determinism stops at
the API/event edge of the real runtime.

[EventBridge Connections](eventbridge.md#connections-and-managed-credentials) use
this same service through a small consumer-owned interface. Their private values
live in `events!connection/...` secrets, protected by the actual API Destinations
service-linked role and KMS policy. Public callers cannot mutate those managed
secrets directly. Step Functions needs the Connection retrieval permission and
both `DescribeSecret` and `GetSecretValue`; it does not bypass secret authority.

## Events and evidence

Every routed operation contributes sanitized management events to the shared
journal. Secret strings/binary values and rotation tokens are excluded. Native
request-ARN resource attribution is distinct from name input and service-generated
batch reads. Batch retrieval emits its individual read outcomes as well as the
batch event. Configured CloudTrail/EventBridge consumers use the existing journal
and selectors; there is no parallel Secrets Manager event bus.

Native fixtures under `testdata/aws/secretsmanager/` retain requests, responses,
probe sources, scope and cleanup evidence:

| Fixture | Evidence |
| --- | --- |
| `lifecycle.json` | Immutable versions, stages, deletion/recovery, metadata and reads. |
| `authority.json` | Real IAM/session/resource policies, conditions, tags and KMS failures. |
| `encryption_audit.json` | Key changes, historical decryptability, permission controls and native management audit. |
| `rotation_replication.json` | Actual AWS Lambda callbacks, deferred rotation/cancellation and regional lifecycle. |
| `replication_authority.json` | Collision overwrite, replica metadata and source/destination KMS denial controls. |
| `metadata_authority.json` | Native managed-secret and replica metadata/policy mutation rejection. |
| `write_validation.json` | Thirty-six role/session-condition write admissions and immediate version readbacks, including malformed stages, tokens, IDs and values. Owned secret/role cleanup confirmed. |

`integration/secretsmanager_native_test.go` uses the real assembled services and
SDK-decoded requests on memory and SQLite. Docker rotation replay requires
`STACKD_LAMBDA_DOCKER=1` and the locally prepared, pinned Python 3.13 image documented
in [Lambda execution](lambda.md). It runs the captured ZIP and observes actual
CloudWatch callback output, not an in-process handler substitute. Native transient
polls do not specify local completion deadlines. Opaque identities, timestamps,
SDK metadata and AWS-owned descriptive prose are not compared as fixed strings.
The secret audit replay does not claim complete KMS subcall audit parity.

`integration/secretsmanager_admission_test.go` replays the captured admission
matrix and nonempty multi-stage conditions through signed SDK requests on both
stores. It checks exact error codes, retained values/stages and the final version
set; rejected writes must not create versions. It replaces the older hard-coded
stage-condition test. The
[executable comparison](../testdata/integration/secretsmanager_write_admission.json)
records 26 baseline discrepancies and zero after the fix across all 36 admission
cases, plus all 20 earlier stage-condition cases. Ten accepted writes retained
their exact bytes and tokens through the SQLite-backed executable. Generated
identities/timestamps and error wording are not pinned; unordered stage
collections are normalized. This capture establishes API behavior, not new
CloudTrail event-shape evidence.

Native probes cleaned up their owned secrets, replicas, Connections, functions,
logs and roles. Three probe CMKs remain in AWS's mandatory pending-deletion window;
the fixtures retain their identities and scheduled dates, not a false absence claim.

## Remaining boundaries

External secret partner ownership/synchronization and external partner rotation
are explicitly rejected, not treated as successful ordinary secrets. Exact AWS
rotation retry/propagation timing, the in-flight cancellation envelope, complete
scheduled-event causality and broader audit/quotas/error precedence still need
verification. The captured behavior does not establish all-service or all-Region
semantic completeness.

Primary references: [Secrets Manager API](https://docs.aws.amazon.com/secretsmanager/latest/apireference/Welcome.html),
[KMS encryption](https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html),
[rotation function](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html),
and [regional replication](https://docs.aws.amazon.com/secretsmanager/latest/userguide/replicate-secrets.html).
