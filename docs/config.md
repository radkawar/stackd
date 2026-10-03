# AWS Config

AWS Config is a bounded recording kernel over the existing typed resource owners.
It is not complete Config parity. The generated `configservice` frontend covers
every modeled operation; unimplemented operations authorize the caller and return
`NotImplementedException` rather than acknowledging an effect.

IAM uses the [per-action Config resource associations](https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html):
supported resource-aware operations authorize the current recorder, rule,
aggregator or aggregation-authorization ARN. Account-wide actions retain `*`.
Batch rule reevaluation authorizes every selected rule before any mutation;
external recorder preflights reauthorize current state before commit.

## Ownership and transactions

`internal/services/configservice` owns recorders, delivery channels, immutable
configuration items, delivery work, rules, evaluation runs and aggregators. The
memory repository and `storage/sqlite/configservice` share the coordinated
transaction domain; schema `248_configservice.sql` keeps
controls in normalized tables. Only configuration and supplementary documents,
which are Config's own immutable observations, are stored as JSON text.

Resource owners remain authoritative. `configservice.NewRecorder` wraps the
shared API-completion recorder. After a successful, non-read-only management
completion from an initially supported owner it reads that owner's typed
repository in the same transaction (`integrations.ConfigResources`), compares the
latest retained observation and appends changed, discovered or deleted items,
their delivery work and rule runs. The owner mutation, its API event and Config
history commit or roll back together. Request parameters and responses are never
reinterpreted as configuration. SQS flushes staged queue state before recording
its successful completion so consumers read the candidate state of that command.

Initial owners are `AWS::SQS::Queue` and `AWS::S3::Bucket`, both changed only by
synchronous controls. `Service.CaptureResourceChanges` is the boundary for an
asynchronous owner transition; no asynchronous owner is currently connected.

Capture uses the recorder role's current authority, not the caller's: trust for
`config.amazonaws.com` with the recorder ARN as source, the role's identity
policies, and the owner's current resource policy/tags from
`ConfigResources.CapturePermission`. A handled denial marks the recorder
`LastStatus=Failure` and records nothing for that resource; it never rolls back
the source command. Restoring authority records the next observed change.

## Recording, history and discovery

Implemented: Put/Describe/Start/Stop/Delete recorder and recorder status,
Put/Describe/Delete delivery channel and status, `DeliverConfigSnapshot`,
`GetResourceConfigHistory`, `ListDiscoveredResources`, `BatchGetResourceConfig`
and `GetDiscoveredResourceCounts`. One customer-managed continuous recorder and
one channel exist per account and Region. Starting requires a channel; stopping
retains history; deleting a recorder does not erase history; a running recorder
blocks channel deletion. Start captures the current owner inventory.

Native calibration (`testdata/aws/configservice/`, us-west-2, owned resources):

- SQS resource IDs are canonical AWS queue URLs; `availabilityZone` is
  `Not Applicable`. Configuration attributes are strings, including Unix-second
  `CreatedTimestamp`/`LastModifiedTimestamp`; supplementary `Tags` is a JSON map.
- S3 IDs are bucket names with `Regional` AZ; configuration has name, owner,
  creation date and region. Supplementary documents include versioning, logging,
  policy, public access block, encryption, requester pays, acceleration, tagging,
  ABAC status and the double-encoded `AccessControlList` string.
- Deleted items keep ARN/ID, have `configuration` `null`, empty tags/supplements,
  and omit AZ/creation time. A deleted SQS item's `resourceName` is the queue URL.
- `GetResourceConfigHistory` bounds are inclusive for a nonzero range; a
  zero-width range returns no items; an inverted range returns
  `InvalidTimeRangeException` with an empty message.
- Native discovery is delayed by minutes; stackd records within the owner
  transaction. That timing difference is intentional determinism, not a native
  latency claim. Native S3 `creationDate` was observed to follow later control
  updates; stackd retains the owner's creation time.

## Delivery

Delivery work is retained and runs from the shared scheduler outside storage
transactions through `integrations.ConfigEffects`: the recorder role first and
the documented `config.amazonaws.com` fallback on denial, through ordinary S3
and SNS commands. Channel admission writes the native zero-byte
`AWSLogs/<account>/Config/ConfigWritabilityCheckFile`. Snapshot and history
objects are gzip JSON (`fileVersion` 1.0, `configurationItemVersion` 1.3,
numeric `configurationStateId`, `awsAccountId`, `ARN`) with SSE-S3 or the channel
KMS key and `bucket-owner-full-control`. Keys use unpadded date directories.
History files batch six hours of items. Periodic snapshots follow the channel
frequency.

SNS messages carry `ConfigurationItemChangeNotification` (record version 1.3,
with `configurationItemDiff` computed from retained items) and
`ConfigurationSnapshotDeliveryStarted/Completed` and
`ConfigurationHistoryDeliveryCompleted` (record version 1.1). Failed effects
retain error status and retry hourly; channel deletion cancels pending work.

## Rules and aggregation

Managed `REQUIRED_TAGS` evaluates retained items for its documented resource
types. `CUSTOM_LAMBDA` rules invoke the real Lambda owner synchronously with the
native invoking event; `PutEvaluations` accepts a result token only while its
invocation runs (15-minute crash deadline). `StartConfigRulesEvaluation` is
limited to once per minute. Explicit-account/Region aggregators read retained
source history and evaluations; cross-account sources need current
authorizations and revocation takes effect immediately.

## Resource tags and shared discovery

Customer-managed recorders, Config rules, configuration aggregators and
aggregation authorizations own their tags. Initial `Put*` tags are applied
atomically with creation; subsequent `Put*` calls ignore supplied tags, matching
the retained native capture. `TagResource` merges values, `UntagResource` removes
keys and deletion removes the owner's tags. Exceeding 50 distinct keys rejects
the whole mutation. Native `ListTagsForResource` returns the complete tag set
even with `Limit=1` and ignores `NextToken`; the generated input still enforces
the modeled `Limit` range of 0–100.

Commands evaluate current `config:*` authority, resource tags, request tags and
tag keys through the existing IAM owner. Tagged creation requires the dependent
`config:TagResource` permission; denial rolls back resource creation. Scope and
resource existence are checked against the current typed repository.

Schema 296 adds normalized, scoped Config tag rows. Native mutations, API
completion and previously-tagged membership commit together. Shared tagging
reads these live owner tags, routes mutations through native commands and
retains live resources after their final tag is removed. Resource Groups uses
the same owner snapshots, including recorders, rather than copied resource state.

The SDK model's `configservice.amazonaws.com` CloudTrail source is corrected to
native `config.amazonaws.com` through an evidence-backed generator correction.
The native capture matches events to original request IDs. This source identity
also selects the correct owner for shared membership reconciliation.

Verification includes eight signed SDK race workflows on memory/SQLite and an
actual SQLite process restart. The executable checks all four resource types,
current IAM, empty-tag membership, deletion cleanup and a request-matched
retained CloudTrail event.

Native calibration is narrower: IAM conditions use the official authorization
reference, cross-account behavior remains unmeasured, and bounded discovery
absence does not prove permanent ineligibility. Resource Groups accepted recorder
and rule filters after native cleanup; those empty responses do not establish
live membership parity. Local discovery checks are not native evidence.

## Evidence

- `scripts/aws/configservice_probe.py` and `testdata/aws/configservice/*.json`:
  native lifecycle errors, owned SQS/S3 discovery, change, deletion, snapshot and
  SNS shapes, time bounds and exact-owned cleanup (`cleanup.json`).
- `integration/configservice_native_test.go`: signed SDK replay of the native
  SQS item across memory/SQLite restart and Region isolation.
- `scripts/aws/configservice_executable_smoke.py`: signed workflow against the
  actual executable with real Lambda, S3/SNS delivery, IAM denial and restart.
- `testdata/integration/service255_executable.json`: combined executable proof
  of schema 244→255 retained S3/SQS/IAM state, Cloud Control owner changes,
  recorder-role denial without source rollback, restored capture, managed tag
  evaluation, gzip snapshot delivery and deletion capture across restart.
- `scripts/aws/configservice_tagging_probe.py` and
  [`testdata/aws/configservice/tagging.json`](../testdata/aws/configservice/tagging.json):
  native tag creation/update/listing limits, mutation errors, shared discovery,
  request-matched CloudTrail source and verified exact-owned cleanup.
- `integration/configservice_tagging_test.go`: signed SDK lifecycle, atomic
  rejection, current IAM, owner reflection, membership and retained restart.
- [TagResource contract](https://docs.aws.amazon.com/config/latest/APIReference/API_TagResource.html),
  [listing contract](https://docs.aws.amazon.com/config/latest/APIReference/API_ListTagsForResource.html),
  [authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html)
  and [CloudTrail source](https://docs.aws.amazon.com/config/latest/developerguide/log-api-calls.html).

## Explicit gaps

Service-linked/DAILY/overridden recorders, remaining resource
types and relationships, S3 notification/CORS/lifecycle/replication/website/
Object Lock supplements, asynchronous owner producers, advanced query,
conformance packs, remediation, organization rules/aggregators, AllAwsRegions,
periodic custom rules, proactive evaluation, custom policy rules, remaining
managed rules and late result-token calibration. Code locations carry
`TODO: Comeback`.
