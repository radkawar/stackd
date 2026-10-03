# Committed service events

The instance has one journal in the same transaction domain as typed resource
state. IAM/STS and Organizations publish lifecycle changes; implemented service
commands publish API completions and EC2 VPC lifecycle service events; EventBridge publishes accepted events;
SQS publishes accepted sends; Lambda publishes accepted asynchronous invocations;
Logs publishes accepted ingestion batches. EventBridge, Lambda, CloudTrail,
Logs subscriptions and CloudWatch alarms retain their own delivery/attempt state.
The journal provides committed history and causal links. Full replay,
consumer checkpoints and consistent snapshot/fork/restore remain open.

## Producer ownership

A source contributes at its existing command or lifecycle boundary through a
small append interface. It supplies its resource scope and captured service
instant. `internal/apievents.WithOrigin` supplies the request ID, causal parent,
caller ARN or trusted service principal. `apievents.Recorder` also constructs the
public caller/session identity and event ID for API completions. Sources own their
explicit typed request, response, error and resource projections. Their successful
completion records commit with the command; failures are recorded after the
rejected command rolls back. Authenticated generated-input rejections use those
same source projections; pre-authentication and early transport failures remain
outside the current producer contract.

`apievents.Reserve` gives each API call a fresh outcome ID before independently
committed child calls begin; it replaces any inherited reservation.
`apievents.EventID` lets the owner explicitly assign that ID to its own outcome.
Child recorders do not implicitly reuse it. Logs subscription preflight and
CloudTrail destination checks use this shared boundary instead of service-private
reservation keys; an independent child effect may therefore precede the parent's
success or failure record without sharing its identity.

The generated catalog preserves `aws.api#service.cloudTrailEventSource`, used by
the current producers. Public projections and management/data classification
remain service-owned: the models omit read-only traits on some reads and
sensitivity traits on some credentials/message bodies. `APIEventResource` retains
native `ARN`/`ARNPrefix` identities separately from LookupEvents aliases.
`apievents.CloudTrailRecord` owns the common native document for history,
EventBridge detail and gzip logs. Source-owned federation identity, shared-event
correlation and optional API version survive the same memory/SQLite path.
The optional typed `APICallEventType` preserves a documented source-specific
CloudTrail type through both stores; empty retains `AwsApiCall` or
`AwsServiceEvent`. RDS Data uses `Rds Data Service` and the generated corrected
source `rdsdataapi.amazonaws.com`. This identity is
[documentation-derived](../testdata/aws/rds/data_audit_documentation.json),
not a fresh native Aurora capture. SQL/schema/database values are masked and
bound parameters/results omitted; these `AWS::RDS::DBCluster` data events
require trail data selectors rather than appearing in `LookupEvents`.
The common `eventTime` is serialized as whole-second UTC, matching retained native
records; this does not reduce the journal's timestamp precision.
Service-generated observations retain their own classification/details and a
service actor rather than borrowing the caller's IAM identity. VPC creation and
deletion append those records with their default-resource changes, parented to
the reserved API outcome. They project as `AwsServiceEvent`, and configured
EventBridge delivery uses `AWS Service Event via CloudTrail`. The same event
identity reaches history and selected consumers; see [EC2 evidence](ec2.md#cloudtrail-and-eventbridge).
See [producer classifications and evidence](cloudtrail.md#history-and-api-producers)
for exact boundaries; API registration alone is not native conformance.

The owning repository callback's context must reach every related writer. An
append failure, resource failure, cancellation or rejected commit discards the
whole attempted transition. The journal never calls subscribers or performs
external I/O under that transaction. Standalone services can omit their sink;
full `stackd.New` assembly requires the coordinated `storage.Backends.Journal`.

EKS native Kubernetes audit admission is a separate typed source, not a fabricated
CloudTrail API completion. The capability-authenticated native webhook supplies
audit metadata; the current EKS owner supplies account/region/cluster incarnation.
Admission, GuardDuty findings and publication intent share the transaction.
The journal deduplicates scope/cluster/audit-ID/stage, including events admitted
while detection is disabled. SQL finding evidence references the immutable native
event instead of copying its payload. User groups occupy ordered child rows.
Successful native RBAC binding creates also retain typed role-reference columns
and ordered subject rows from the admitted response, never from a proposed request.
Deletion events retain effective options in typed `delete_options_observed` and
`dry_run` columns. Historical metadata-only rows remain unknown; absence of a
request body at `Metadata` level does not establish ordinary deletion options.
For request-level events, a decoded `DeleteOptions` body takes precedence over
the URI query. Findings expose these flags without claiming actual object deletion.
Full request/response objects and secret values are not part of this projection.
The webhook acknowledges only after source admission and original-byte spool
fsync. A failed spool append can retry without duplicating the committed
observation. CloudWatch logging enablement and its delivery cursor do not control
GuardDuty admission. Native audit time is retained separately from the
deterministic service admission time.

The default memory bundle shares one `memory.Domain`; SQLite adapters borrow one
native transaction across service-owned SQLC tables. Neither implementation is
a test-fork engine. SQLite owns commit and crash recovery; sequence values need
not be gap-free. Reopening retains committed history. A reconstructed memory
stack retains history only while its backend bundle remains alive.

## AWS consumers have distinct contracts

| Consumer | Source and behavior |
| --- | --- |
| CloudTrail event history | Reads management API and service-event records through `LookupEvents`, scoped by partition/account/region and a 90-day service-time window. API outcomes remain distinct from service-generated events and data events. |
| CloudTrail trails | Selects completed management/data records, retains shared source-event references and independently writes S3 gzip objects and individual Logs records outside the source transaction. |
| EventBridge | Matches accepted bus events and commits per-target work. Delivery uses the retained target role or rule service principal, current permissions and retained retry/DLQ state. Typed bus forwarding preserves native wire identity independently of each causal admission. Configured trails admit eligible API and service-generated events to the default bus under native rule-state distinctions. |
| SNS | Commits admitted publications, signed protocol variants, selected subscriber work and weighted metric samples. SQS/Lambda acceptance and DLQ effects run outside source transactions under the SNS principal; completed-minute metric publication joins consumption of retained samples. |
| CloudWatch metrics | Stores custom API samples, configured Logs metric-filter output and SNS service samples through typed publication. Samples join their owning transaction; API-call totals do not stand in for service-specific metrics. |
| CloudWatch alarms | Evaluates retained metric/composite configuration with the service clock; commits native default-bus events and ready action intents with state. Lambda/SNS acceptance runs outside storage under the alarm service principal. |
| CloudWatch Logs | Ingests actual SDK, Lambda, EventBridge and CloudTrail data through typed authorized commands. Metric filters publish accepted-message samples; Lambda-only subscriptions retain gzip work for real asynchronous Lambda acceptance. Audit JSON is not a substitute for runtime output. |

AWS CloudTrail history is available independently of a trail, while delivery of
CloudTrail events to EventBridge depends on a logging trail and the default bus.
Read-only management events also depend on rule state. Effective trail selection
now owns this admission; history availability alone never enables it. See
[AWS event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
and [CloudTrail events in EventBridge](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html).

EventBridge metrics distinguish ingestion, matches, attempts and terminal results;
SQS metrics distinguish accepted messages, FIFO duplicates, redelivery and current
queue state. The current acceptance records cannot supply all of them. Add the
required committed lifecycle facts or service-state reads with the corresponding
CloudWatch consumer, preserving AWS counting and publication semantics. See
[EventBridge metrics](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html)
and [SQS metrics](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html).

CloudWatch alarm evaluation joins the same service clock and scheduler.
State, native EventBridge acceptance and ready actions commit together; actions
run outside storage. Metric windows, missing-data treatment, composite
dependencies and suppression belong to CloudWatch, not the bus or scheduler.
AWS service-owned metric producers and remaining alarm engines/actions stay open.
Logs subscriptions now own their filter, encoding, destination permission and
retained delivery contracts; they use the shared scheduler, not callbacks under
the producer's resource lock. Kinesis and Firehose destinations remain open.
Logs owns pattern extraction, per-event defaults and configured dimensions.
CloudWatch owns the resulting metric identity, timestamp resolution and statistics.
Both repositories borrow the accepted ingestion transaction. Failed publication
cannot leave a committed source event without its configured metric sample;
internal publication neither reauthorizes the application as a CloudWatch caller
nor invents a `PutMetricData` audit record. See [Logs metric filters](logs.md#metric-filters)
and [CloudWatch](cloudwatch.md).

## Delivery and causality

EventBridge stores the accepted event, selected target role/input and delivery
intent with its acceptance journal row. Its source joins the shared deterministic
scheduler. The driver reads committed work, releases storage, invokes the target
through `internal/integrations.EventBridgeTargets`, and commits the outcome under the
retained delivery version. Retry deadlines and DLQ work survive SQLite restart.
The SQS command uses its ordinary authorization, validation and encryption path;
its message and acceptance row commit together.
Classic scheduled rules also commit the next source deadline with their native
event and selected deliveries. The journal producer is `events.amazonaws.com`,
not the caller advancing time or draining jobs. Source envelope time and acceptance
time remain distinct during deterministic catch-up; no public `PutEvents` audit
call is invented. See [scheduled rules](eventbridge.md#classic-scheduled-rules).

The SQS envelope's `parent_event_id` identifies the local EventBridge admission.
Service-principal delivery retains the source request ID; role-based commands
receive a distinct request ID while retaining the causal parent and service
origin. Resource, role and source ownership remain separate. The adapter consumes
the authoritative retained records through a small command interface; it owns no
second queue, transaction or retry mechanism. Same-region bus hops can preserve
one AWS envelope ID across several distinct admissions. The acceptance payload
therefore retains both `event_id` and `wire_event_id`; regional hops replace the
wire ID/time without rewriting original wire account/region.

Lambda commits its asynchronous payload and queue state with a
`lambda_invocation_accepted_v1` fact. Its separate request ID survives handler
retries, while `parent_event_id` retains the source EventBridge/alarm event or Logs batch.
A claimed worker leaves the shared scheduler before invoking customer code.
Lambda's retry and configuration-application deadlines survive restart; the
process and its effects are not checkpointed. See [Lambda](lambda.md) for the
observed contract and limits.

A crash after the target commits but before EventBridge commits the outcome can
redeliver. The two services do not claim an atomic external effect or exactly-once
execution. Retry/backoff is deterministic locally, not a claim of AWS's exact
distributed timing. Matching and native target authorization evidence are in
[EventBridge](eventbridge.md); API-history behavior is in [CloudTrail](cloudtrail.md).

CloudTrail admission commits selected event references with the source API fact,
and eligible EventBridge acceptance joins that transaction. Its worker later reads
the shared journal and independently writes real S3 objects and Logs records
outside the claim transaction. Actual S3/Logs calls and role assumptions record
their supported native API outcomes and causal parents.
Preflight S3 effects also commit independently: native CreateTrail can leave a
zero-byte destination marker even when the trail itself fails ACL validation.
Trail incarnation IDs prevent deleted/recreated trails from adopting stale work.
See [CloudTrail](cloudtrail.md) for batching, stop propagation, recursive logging,
native evidence and unimplemented destinations.

Logs commits source event rows, a `logs_batch_accepted_v1` fact and matching
subscription delivery work together, including partial admission. Rejected events
are not selected; an entirely rejected batch has no acceptance fact. The fact
retains batch ID, group ARN, stream and accepted count, not customer message bytes.
It is a service ingestion fact, not a CloudTrail `PutLogEvents` API record.
Logs' scheduler calls Lambda outside the source transaction. Its retained gzip
payload, parent/request identity, retry/expiry deadlines and filter incarnation
fence recovery and replacement. The external acceptance/progress gap permits
redelivery; it is not a cross-service exactly-once transaction.

CloudWatch owns native alarm configuration/state events separately from its
management API outcomes. The shared service publisher admits them to the default
bus without a trail. State changes retain immediate causal origins through
composite propagation, suppression deadlines and Lambda acceptance across restart.
Periodic metric evaluation currently roots in configuration, not per-sample
publication; metric observations do not yet retain those causes. See
[alarm behavior and evidence](cloudwatch.md#alarms).

For an active Lambda runtime, the gateway looks up the verified access-key ID
after authenticating the SDK request and adds only its invocation parent.
Asynchronous execution uses the accepted Lambda invocation ID; synchronous
execution uses the freshly reserved Invoke API outcome ID. Lambda's wrapper
clears attribution on completion, cancellation or shutdown; it grants no
authority, adds no headers and does not retain a previous warm invocation origin.
Thus `/_stackd/events` can expose the exact chain
`logs_batch_accepted_v1` → `lambda_invocation_accepted_v1` →
`sqs_message_accepted_v1` for a handler's real signed SQS send.
This is bounded active-runtime attribution, not OpenTelemetry/native X-Ray or
initialization/idle SDK causality. [Logs](logs.md#lambda-subscriptions) owns the
native capture, local batching/time choices and remaining destination gaps.
Runtime stdout/stderr has no trustworthy per-invocation delimiter. Its generation's
preparation context is not reused as the parent of later warm output; actual Logs
delivery does not by itself establish invocation-level log causality.

ECS task-role sessions retain their issuing task-command event with the typed IAM
credential. After signature verification, the gateway uses that stored parent;
active Lambda invocation attribution takes precedence when present. Cached task
credentials preserve ancestry across controller restart without an extra lookup
or task scan. Caller identity, signed region, current IAM evaluation and policy
context are unchanged. The origin is diagnostic journal metadata, not authority,
an AWS response label or an inferred session-name relationship. Only origins
recorded at issuance are used. [ECS execution evidence](ecs.md) includes a real
cached-credential restart, cross-region calls and live IAM denial.
ECS replica services retain deployment ancestry with their immutable definition
and task ownership. Scheduling transitions commit task intent and service/
deployment events together; real container work runs after commit. EventBridge
ECS targets call the same audited `RunTask` boundary as the frontend under the
selected invocation role. Their retained delivery ID supplies ECS's client token;
task-role SDK effects then use the credential ancestry described above. Neither
service adds a second runtime registry or retry ledger.
ECS service utilization is a separate runtime-observation contract, not a count
of those task commands. External counter reads precede acceptance into retained
task/window statistics; publishing those statistics and consuming their source
group joins the CloudWatch transaction. Neither collection nor publication
invents a customer API event. [ECS metrics](ecs.md#service-metrics) owns cadence,
aggregation and the physical-time boundary.


SQS and DynamoDB Streams use `lambda_source_batch_accepted_v1` to link one native
Invoke event to its ordered source record IDs and source/mapping ARNs. Invoke and
the typed batch fact commit together before customer code runs. A batch does not
choose an arbitrary single source record as its parent. Source bodies, receipts,
visibility and redrive remain source-owned; this fact is a causal link, not a
retry ledger. Lambda's separate typed stream state retains captured records,
checkpoints, retry boundaries and customer window state. An empty-record window
finalization can still invoke real customer code and produce a failure destination.
Actual customer SDK calls use the accepted Invoke event as their parent through
the existing authenticated runtime binding. Their execution does not occur inside
the source or Lambda transaction. See [SQS](lambda.md#sqs-event-source-mappings)
and [DynamoDB Streams](lambda.md#dynamodb-streams-event-source-mappings) evidence.

## Inspect history

```sh
curl 'http://127.0.0.1:4566/_stackd/events?after=0&limit=100'
```

`GET /_stackd/events` returns `events` and `next_after`. Use that cursor as `after`
for the next page. Limits are 1–1000, default 100; the initial cursor is zero.
An empty page preserves the supplied cursor. Invalid queries return HTTP 400;
unsupported methods return 405. Embedders use `Stack.Events(ctx, after, limit)`.
This operator view spans the instance's accounts and partitions and does not use
AWS credentials. CloudTrail's AWS endpoint separately enforces IAM and scope.

Each envelope has a global commit sequence, service-time `at`, partition, resource
account, region and originating request identity. Equal timestamps are legal.
Exactly one versioned payload describes the committed fact:

| Payload | Content |
| --- | --- |
| `session_issued_v1` | STS principal, issuer, session type and expiry. |
| `access_key_changed_v1` | Public key ID, owner ARN, action and applicable status. |
| `account_creation_changed_v1` | Organization, provisioning request, state and resulting account or failure. |
| `handshake_changed_v1` | Organization, handshake, target account, action, parent and state. |
| `effective_policy_changed_v1` | Organization, target, policy type and publication state. |
| `api_call_completed_v1` | Categorized API outcome, public identity and explicitly projected request/response/resource fields. |
| `eventbridge_accepted_v1` | Local admission ID, native wire event ID and event-bus ARN. |
| `lambda_invocation_accepted_v1` | Invocation ID and function ARN; no customer payload. |
| `lambda_source_batch_accepted_v1` | Invoke event ID, mapping/source ARNs and ordered source record IDs; no receipts or payloads. |
| `sqs_message_accepted_v1` | Message ID and queue ARN. |
| `logs_batch_accepted_v1` | Batch ID, log-group ARN, stream name and accepted event count; no customer messages. |

Payloads omit signing secrets, session tokens and private keys. API projections
can contain public caller IDs and the public fields AWS includes in its audit
record; they do not copy arbitrary request bodies. EventBridge detail, SQS
message bodies, Lambda invocation payloads and Logs messages/compressed subscription
payloads remain in their resource stores. A denied API can have a failure
observation while emitting no successful resource transition. Existing state is
not backfilled into invented historical events.

## Evidence and remaining work

Fixture suites replay native AWS observations through actual SDK requests and
decoded results. Integration tests under `integration/` cover mixed history,
pagination, causal delivery, secret exclusion, rollback and backend reconstruction.
Credential and Organizations subprocess tests exit inside uncommitted SQLite
transactions and verify native recovery. Fixtures add behavior cases; Go owns
setup and the transaction/process failure boundaries.

SQLite migrations 7/8 introduced session/key events; 10/11 retained provisioning
origins and outcomes; later migrations added handshake and policy publication.
Migration 20 adds API completions, causal/service-origin columns and typed bus/queue
acceptance. Migrations 21–23 store EventBridge resources, input projections,
bus policy bindings and retained delivery state.
Migrations 36/37 add typed Logs subscription configuration/retained work and
accepted ingestion facts in the same transaction domain.
Migrations 38/39 add CloudWatch metric identity/dimension/point tables and
Logs metric-filter configuration; publication shares the source Logs transaction.

Remaining work includes additional API/lifecycle producers, remaining trail
destinations and organization behavior, other AWS service events and EventBridge
target contracts, AWS service-owned metric producers and alarms, additional Logs destinations, journal retention, delivery checkpoints,
replay and snapshot/fork/restore. Current shared plumbing does not establish those
capabilities. No response fidelity labels or provenance headers are added.
