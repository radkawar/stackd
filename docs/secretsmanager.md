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

## CloudFormation private ownership

`AWS::SecretsManager::Secret` retains its private creation claim independently
from the public tags. Resource policy, rotation schedule and target attachment
retain separate private edge claims. Native mutations and state changes commit
with those claims; recovery and stack mutations require the exact incarnation
and current native IAM authority. Direct Cloud Control updates and deletes still
use native authorization without converting public state into stack ownership.

Secrets Manager tag keys and values do **not** allow `:`. Legal lookalike tags
cannot forge or revoke a creation claim. The validation is unchanged from the
[native tagging contract](https://docs.aws.amazon.com/secretsmanager/latest/userguide/managing-secrets_tagging.html).
SQLite migration 375 adds typed claim columns; it does not promote legacy public
marker tags into authority.

Memory/SQLite fixtures cover exact recovery, foreign replacement, policy,
rotation and attachment edges. A source-built controller smoke creates an
encrypted secret in a mixed stack, reads its real plaintext through KMS, rejects
an invalid colon tag, accepts a legal lookalike tag, reopens SQLite, updates the
secret and deletes the actual owned resource. These checks do not claim complete
rotation scheduling or Secrets Manager parity.

## CloudFormation dynamic references

Resource Properties accept Secrets Manager's
[official reference pattern](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references-secretsmanager.html):

```text
{{resolve:secretsmanager:secret-name}}
{{resolve:secretsmanager:secret-name:SecretString:json-key}}
{{resolve:secretsmanager:secret-name:SecretString:json-key:version-stage}}
{{resolve:secretsmanager:secret-name:SecretString:json-key::version-id}}
```

The secret ID may be a name or ARN. Cross-account access requires the ARN and the
native Secrets Manager/resource-policy and KMS permissions; references do not
bypass those owners. `SecretString` is the only supported value field and is the
default when omitted. Omitting both selectors uses `AWSCURRENT`. Version stage
and version ID are mutually exclusive in the CloudFormation reference, even
though the native `GetSecretValue` API can accept both when they identify the
same version. JSON keys, stages and IDs cannot contain `:`. The native
[GetSecretValue contract](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)
defines version-ID/stage length and read/decrypt permissions.

Template parsing, read-only evaluation and change-set planning retain the
reference rather than decrypting it. Resolution happens outside CloudFormation
transactions through actual `GetSecretValue` commands under the retained caller
or current execution role. A selected service/version ID is retained only inside
the accepted operation while it needs retry or crash recovery. Retrying that
selected intent reads the same version and rechecks current permissions; no
resolved-value cache survives a request or controller restart. A changed staging
label cannot silently change an already selected retry. Published resource
images and completed operation images do not retain inferred Secrets Manager
version pins. SQLite migration 410 upgrades legacy ordinary SSM numeric selectors
to the typed pin format, including restoration images.

AWS documents that CloudFormation does not track the secret versions used by
previous deployments. New resource updates and rollback therefore evaluate the
template's requested `AWSCURRENT`, staging label or explicit version ID, not an
inferred version from a prior deployment. Rollback first resolves the old
template's selector and retains that fresh selection only for retry/recovery of
the accepted rollback intent. Rotating a secret alone, or updating an unrelated
stack description, does not refresh an unchanged resource.

Neither templates, retained deployment properties nor stack events are replaced
with decrypted text. Destination errors are scrubbed, including JSON/Go-escaped
values and modeled wire-error causes. Secret-bearing destination attributes are
masked before retention. The native destination may keep its legitimate secret
property: IAM stores a salted password verifier; RDS protects retained bootstrap
credentials and applies the real native-engine password.

AWS allows Secrets Manager references in all resource properties, warns that
identifier properties can expose plaintext, and disallows secure custom-resource
references. Its [general restrictions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html)
also disallow EC2 `UserData` and `AWS::CloudFormation::Init` dynamic references.
JSON-key references consume strings without JSON quoting. Native AWS
calibration with an `AWS::SSM::Parameter` String destination also confirms
number `42` becomes `"42"`, boolean `true` becomes `"true"`, object and array
values become compact JSON strings, and JSON null becomes `"null"`. Stackd
implements those observed conversions; a missing key fails rather than
creating an empty-string destination.

Stackd additionally returns `NotImplementedException` for secure identifier
properties/identity echoes and secure references outside resource Properties.
These are explicit emulator safety/coverage limits, not asserted AWS
invalid-input rules. Invalid JSON/missing keys and unsupported `SecretBinary`
reference consumption fail without exposing the secret.

Secret-bearing destination result attributes are retained only as a redacted
projection with separate typed redaction metadata on resources and operation
before/after/restoration images. Consuming a marked attribute through an
intrinsic (`Fn::GetAtt`, attribute `Fn::Sub`, or a composed expression), whether
for a downstream resource or a stack output, returns stackd
`NotImplementedException` instead of passing `****` as real data. Safe unmarked
attributes such as `Arn` still resolve. These guards and failure reasons survive
memory-controller and SQLite restarts, and late owner result refreshes preserve
the protected projection without reading the source again.
TODO: Comeback for real secure attribute consumption without persisting
plaintext; AWS does not generally prohibit this consumption. Direct references
used as native passwords remain supported.

The SDK regression
`TestCloudFormationSecureDynamicReferencesNativePasswordReplay` exercises
SecureString, complete SecretString, JSON-key, stage and explicit-version
consumption through real IAM password verification over memory and reopened
SQLite. It pauses a committed version selection before the effect, rotates the
source, revokes either the execution role's read or decrypt permission, and
checks retained CloudFormation state/history. The successful scenarios also
cover unchanged-resource behavior. A native-resource update failure then pauses
rollback: rotating before its fresh selection verifies selector-based rollback,
and rotating again after that selection/reopening verifies operation-local
retry without inferring a previous deployment's version. The assertions
distinguish `AWSCURRENT`, `AWSPREVIOUS`, explicit Secrets Manager IDs and retained
SSM versions. Published resources/completed operations must contain no inferred
Secrets Manager pins.
`TestCloudFormationSecretSourceNativeVersionAndStageRules` covers native default,
`AWSPREVIOUS`, version-ID/ARN reads and explicit binary rejection.
`TestCloudFormationSecretJSONKeyNativeCoercion` consumes all six captured JSON
value types into actual native SSM String parameters over memory/reopened SQLite,
checks reference/masked-attribute retention, and verifies missing-key rollback.
`TestCloudFormationSecureResultAttributesRejectConsumption` pauses after the
secure destination's result is retained, reopens memory/SQLite, and checks
downstream/output rejection, usable safe attributes, unchanged direct source
consumption, retained failure reasons and absence of plaintext in CFN state.

### Native PostgreSQL CLI smoke

This recipe requires Bash, AWS CLI v2, `psql`, a trusted local Docker daemon and
the installed PostgreSQL image from
[the existing RDS runtime setup](rds.md#running-the-native-engines).
Do not enable a metadata-only substitute. Build the integrated controller and
start one process against a dedicated SQLite file:

```sh
docker pull postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652
go build -o bin/stackd ./cmd/stackd
./bin/stackd -listen 127.0.0.1:4566 -database ./data/secure-reference-smoke.sqlite \
  -docker-host unix:///var/run/docker.sock -rds-runtime
```

In another terminal:

```sh
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
unset AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
bash scripts/cloudformation_secure_dynamic_references_smoke.sh
```

The script obtains the sandbox identity from STS, creates a real KMS key and
encrypted sources, provisions PostgreSQL through `AWS::RDS::DBInstance`, executes
SQL with the secure SSM password, verifies explicit version pinning across a
source rotation/resource update, then updates the same native database to a
Secrets Manager JSON-key password. Its final CLI checks reject plaintext in
GetTemplate/DescribeStackEvents output. Cleanup deletes the stack/engine, source
parameter and secret and schedules the key for deletion. Secrets used by the
smoke remain in private temporary files only until cleanup; do not run with shell
tracing enabled. The 2026-10-14 Linux CLI run completed this workflow against
actual PostgreSQL. It retained row `42` through both password-source updates,
found no resolved plaintext in the checked CloudFormation outputs, and deleted
the owned stack and sources. This is local engine evidence, not native AWS
PostgreSQL or complete CloudFormation parity.

