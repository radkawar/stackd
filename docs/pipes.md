# EventBridge Pipes

Pipes is a separate built-in service, not an EventBridge rule alias. Its generated
AWS frontend exposes CreatePipe, UpdatePipe, DescribePipe, DeletePipe, ListPipes,
StartPipe, StopPipe, TagResource, UntagResource, and ListTagsForResource. The main
runtime supplies its source engines, IAM authorization, target command registry,
shared clock, metrics, execution diagnostics, and optional KMS integration.

## Retained execution

Memory repositories participate in the shared memory transaction domain. SQLite
uses migrations `217_pipes.sql` and `222_pipes_kafka.sql` and SQLC queries.
Configuration is typed; tags, filters, target event resources, stream checkpoints,
work, Kafka connection/auth references, ordered bootstrap addresses, logging
configuration and encryption envelopes have dedicated tables. The SQLite
representation does not store an opaque serialized Pipe resource.

CloudFormation Pipe ownership is a private claim on the native Pipe incarnation,
not tag metadata. Migration `398_pipes_cloudformation_ownership.sql` leaves
existing rows unclaimed; trusted CFN/Cloud Control creation admits the claim in
the same transaction as the real configuration. Authorized lost-reply recovery
and mutations check that exact claim under current native IAM. Public tag edits
and ordinary native/Cloud Control updates preserve a surviving claim but cannot
adopt an unclaimed or recreated Pipe. Deletion/recreation starts a new lifetime
for ownership, source checkpoints and accepted work. This is bounded local
ownership coverage, not a claim of complete AWS/CloudFormation parity.

The shared `internal/scheduler` driver owns polling deadlines, lifecycle
transitions, batching windows, retries, and execution expiration. Target work
executes outside repository transactions, then commits its outcome. There is no
second event bus or private polling/timer loop. Lifecycle and accepted work survive
restart. STOPPED pipes do not acquire records; stopping drains already executing
effects and their successful source acknowledgments before settling. Failed or
unexecuted work stays retained without another target invocation. Stream successes
behind an unsuccessful earlier record retain their ordered checkpoint boundary
until the pipe is started again. Missing source engines on restoration stop a pipe
with a reason rather than report a running consumer that cannot consume.

An idle Kafka stop does not reconnect to the source merely to close its consumer:
only an eligible retained acknowledgment requires current source access. Thus
revoked source authority does not strand a drained pipe in STOPPING. Deleting an
owned MSK cluster first also permits subsequent generated-group pipe cleanup;
the absent cluster has no group left to remove. Authority failures are not
treated as absence. The [native-runtime regression](../testdata/integration/pipes_kafka_source_loss.json)
records both failures before the correction and the resulting STOPPED/absent
states afterward. This is local engine evidence, not fresh AWS lifecycle timing
calibration.

Delivery is at least once. A process failure after a target accepts an operation
but before its local outcome commits can cause redelivery. Pending work is retained
across role revocation, stopping, and reopening SQLite.

Orphan recovery reloads the current pipe and work inside the owning transaction.
Pipe version, work identity, attempt and deadline fence the selected snapshot;
committed acknowledgements and checkpoints cannot be overwritten with stale
`ready` work. Readiness reaches the scheduler's batch only after commit. This
prevents a local recovery race, not the documented at-least-once crash boundary.

## Sources, filtering, and ordering

The real SQS, Kinesis, and DynamoDB Streams owners supply consumer operations.
SQS uses real visibility receipts, deletion, and the queue's redrive policy.
Kinesis supports polling and existing enhanced-fan-out subscriptions. Stream
checkpoints and shard ancestry are retained. Work is batched by the configured
size/window; stream parallelization preserves partition-key ordering, and FIFO
queues preserve message-group ordering. A failed ordered prefix prevents its
checkpoint from advancing past the failure. Stream retry, maximum age, automatic
batch bisection, and SQS/SNS dead-letter destinations use retained work and genuine
target operations. Filter-rejected records are acknowledged, not delivered.

Filtering and dynamic JSON paths reuse EventBridge's event-pattern and input
transformation primitives. Pipes templates support reserved pipe identifiers,
event/ingestion-time variables, and implicit decoding of JSON SQS bodies,
base64-encoded JSON Kinesis data, and Kafka keys/values. Enrichment input
transformation precedes the real enrichment invocation; target transformation
follows it. Target dynamic parameters read the pre-target-transformation event.
Empty enrichment batches skip target invocation; target partial failures retry
through enrichment again.

MSK and self-managed Kafka use a separate Pipes-owned consumer interface, not the
SQS/Kinesis/DynamoDB contracts. Actual Kafka coordinator generations assign
partitions, share them with existing group members, and fence source commits.
Existing custom-group committed offsets take precedence over StartingPosition.
Default group IDs derive from the immutable pipe incarnation and are removed on
delete; caller-selected groups are borrowed and never removed. Source bytes,
partition offsets, group coordination and durable commits remain in native Kafka.

Each pipe also binds once to Kafka's native cluster ID and topic UUID, retained
in `pipes_kafka_identities` independently of mutable configuration. All retained
work and partition cursors belong to that binding. The authenticated native
adapter checks uncached Metadata before assignments, fetches, target leases and
commits; a changed identity rejects those operations and cancels the member's
active leases. A stopped pipe restarted after topic replacement reports
`START_FAILED` with a source-changed reason rather than replaying old work or
applying old cursors to the replacement. Running pipes retain the diagnostic
reason without discarding work. Recovery is explicit: delete/recreate the pipe.
Identity-less retained offsets cannot be rebound to the currently visible topic.

This requires Metadata v10+ and nonempty native cluster/topic IDs; older brokers
and brokers returning a zero topic UUID fail closed. kafka-go v0.4.49 (and v0.4.51)
only implements Metadata through v8, so a metadata-only franz-go v1.20.6 client
with generated kmsg v1.12.0 requests reuses the validated TLS/SASL settings. It
does not create another consumer group or replace coordinator ownership.

This is not an atomic fence against arbitrary concurrent broker administration:
Kafka 3.7's OffsetCommit addresses topic names, not UUIDs. A deletion/recreation
between the last Metadata response and broker processing of a commit can still
apply that in-flight commit to the replacement. Post-commit metadata detects a
visible replacement but cannot undo the commit. Metadata propagation also limits
instant detection, and an external target effect already in flight cannot be
rolled back. Post-fetch checks discard bytes if replacement becomes visible
during fetch; these checks are not a transactional guarantee across Kafka and
the target. Coordinate topic administration with pipe shutdown; completed topic
replacement before restart is covered by the durable identity fence.

Kafka work retains filtered records until the batch succeeds; neither matching
nor nonmatching offsets advance past a failed target effect. Any target failure
retries the whole Kafka batch. The Kafka `key` and `value` filters implement the
documented UTF-8/plain-text/JSON format distinctions; incompatible payload formats
fall back to metadata filtering. Input templates decode valid JSON, while a
non-JSON payload remains base64. Group revocation cancels the active target lease;
retained work must be reacquired under current ownership before acknowledgment.

Owned MSK sources resolve current cluster/control-policy authority under the
Pipes execution role and use the configured public broker mode without a weaker
authentication fallback. Self-managed sources support explicit plaintext, TLS,
SASL/PLAIN or SCRAM-SHA-256/512 over TLS, and unencrypted-PEM mTLS credentials.
Secrets Manager/KMS remain the current credential owners. Self-managed VPC
configuration, encrypted private keys and MSK mTLS/IAM data authentication are
explicit unsupported errors, not ignored connection options.

KPL aggregate bytes remain source-record payloads; native aggregate deaggregation
is not claimed. Amazon MQ and DocumentDB sources remain explicit errors until
their genuine consumer adapters are available.

## IAM and destinations

Create/update require the caller's Pipes permissions and `iam:PassRole`. Source
and target effects assume the configured role as `pipes.amazonaws.com`, carrying
the pipe ARN as the trusted source ARN. Real source and destination owners
reauthorize their operations, so later role or destination-policy changes affect
execution; accepting configuration does not permanently grant delivery authority.

Available target adapters invoke the existing SQS, SNS, Kinesis, Firehose,
EventBridge event-bus/API-destination, Lambda, Step Functions, CloudWatch Logs,
and ECS engines. Lambda, synchronous Step Functions and API destinations are
available enrichments.
Supported parameters are retained, target batch limits are enforced, and partial destination failures are
not acknowledged as complete success. CloudWatch Logs targets require an existing
log stream. Actual dependency availability is checked rather than substituted
with fake accepted deliveries.

API destination targets use the [EventBridge HTTPS owner](eventbridge.md#api-destinations),
not a second HTTP/credential implementation. The pipe role needs
`events:InvokeApiDestination`; target batch size is one. Retained `HttpParameters`
support static headers and dynamic path/query values resolved from the original
source event, before the target input template. The existing source retry owner
consumes the delivery owner's delay, stop and admission hints rather than
reinterpreting HTTP statuses. `Retry-After` remains a minimum across reopen;
admission does not consume the source retry budget. Terminal stream failures and
record-age exhaustion use the configured source DLQ (or the existing discard
policy when absent) before advancing the checkpoint. Failed SQS effects remain
unacknowledged: queue visibility and redrive remain authoritative, and renewed
receipts preserve the HTTP retry deadline and concurrent target completion
atomically. The signed executable SQLite workflow
observes exact HTTP parameters and payload, a failed first request, retry and
source acknowledgement. `TestPipesAPIDestination*` exercises actual TLS and
retained SQS effects on both stores; set `STACKD_KINESIS_DOCKER=1` for its real
Kafka-backed Kinesis retry, terminal-DLQ, admission and age-boundary scenarios.

API Gateway enrichment/targets, Batch,
Redshift Data, SageMaker, and Timestream targets remain explicitly unsupported by
this adapter set. Supporting those services elsewhere in the executable does
not imply that a Pipes adapter exists for them. Native service quotas, managed
networking, and the full AWS concurrency/throughput envelope are not emulated.

### API destination enrichment

Enrichment reuses the same current-role, Connection, credential, rate-limit and
five-second HTTPS exchange as target delivery. Source batch size must be one;
the endpoint receives a scalar source record or its input-template result, not
a one-element Lambda-style batch. HTTP parameters are retained separately from
target parameters. Enrichment header values, path values and query values resolve
against the original source event before template transformation. Connection
values win collisions. Header resolution follows the retained native capture,
which contradicts the documentation's exclusion; target headers have not been
generalized from that observation.

Successful JSON objects and array elements become target records. Empty bodies,
`null`, `""`, `{}` and `[]` suppress target invocation; `[{}]` delivers an empty
object. The HTTP owner decodes gzip and both zlib-wrapped and raw deflate before
JSON processing, including checksum/trailer validation. Its six-MiB wire bound
is separate from an explicit local 64-MiB expansion safety ceiling; exceeding
the latter returns unsupported, not a fabricated AWS quota error. Native upper
bounds remain uncalibrated. Rule/target invocations still discard response bytes
without allocating an enrichment buffer or requiring response decompression.

The [initial native summary](../testdata/aws/pipes/http_enrichment_summary.json) links
raw successful delivery and rejected batch-size captures. An owned HTTPS Lambda
endpoint performed arithmetic and uppercase conversion; downstream SQS contained
the actual results. Native empty-array/object responses produced bounded
non-delivery observations. Explicit empty HTTP parameters cleared readback, and
subsequent omission retained that empty configuration. Denied role/key windows,
fresh-marker recovery and one HTTP 503 were captured, but same-message retry,
retry timing, multi-item response fanout and large-response behavior were not.
Both resource sets, including their short-lived public URLs and Connection
secrets, were independently verified absent.

The subsequent [response capture](../testdata/aws/pipes/http_response_summary.json)
verifies gzip, zlib-wrapped deflate and raw deflate through actual transformed SQS
results, plus two distinct results from one source. The endpoint saw the advertised
`Accept-Encoding: gzip,deflate` and `Range: bytes=0-1048575`. A complete HTTP 200
response larger than one MiB succeeded despite that Range. Gzip responses expanding
to 6,291,456 and 6,291,457 bytes both delivered after a target template removed
padding, disproving the former six-MiB pre-template decoded-size check.
These cases establish neither a native maximum nor partial HTTP 206 semantics.
Both exact-owned resource sets were removed. Initial no-invocation windows,
setup failures and a send after cleanup are retained rather than reported as
codec failures; the separately reviewed rate-10 run proved all three encodings.

The [signed Go SDK executable workflow](../testdata/integration/pipes_http_enrichment_after.json)
exercises a real TLS transformation service, scalar/array responses, dynamic
parameters, template updates, current IAM denial, Connection credential rotation,
and empty-response source acknowledgments. An actual HTTP 503 survives
SQLite/controller restart and the same source record subsequently reaches SQS.
Both controllers exit zero and exact-owned resources are verified absent.
Same-message recovery is local execution evidence, not native timing parity.
The [unsupported baseline](../testdata/integration/pipes_http_enrichment_before.json)
retains the original errors and its cleanup recovery.

The [response executable proof](../testdata/integration/pipes_http_response_after.json)
matches all three codecs, two-result delivery and the measured greater-than-six-MiB
decoded result. Malformed/truncated/checksum-damaged bodies retain source work;
the same message succeeds after correction, including SQLite/controller restart.
It also exercises the local wire boundary. The 64-MiB expansion guard is covered
by a focused decoder regression, not by this executable fixture.
The [gzip failure baseline](../testdata/integration/pipes_http_response_before.json)
and [original-scenario regression](../testdata/integration/pipes_http_response_enrichment_regression.json)
retain actual HTTPS bytes or size/hash evidence, SDK results and cleanup.
All five controllers exited normally and all exact-owned controls were absent.
Native same-message retry timing, ultimate wire/expansion limits and other content
codings remain outside this evidence.
An isolated [HTTP 204 regression](../testdata/integration/pipes_http_response_no_content_after.json)
preserves source acknowledgement and target filtering when `Content-Encoding`
metadata accompanies no HTTP body. Its [failed-before capture](../testdata/integration/pipes_http_response_no_content_before.json)
retained the source with `ServiceUnavailable`; both additional controllers exited
zero and all exact-owned resources were absent. HEAD/bodyless decoding also has
a focused real-HTTP regression.


## Encryption and observations

Customer-managed keys use the real KMS owner under the execution role. KMS wraps
a data key; authenticated encryption protects filters and enrichment/target input
templates in retained storage. The context binds the envelope to its pipe ARN.
Disabling or revoking the key prevents later decryption; plaintext configuration
is not retained alongside its encrypted envelope. This does not claim encryption
of every source-record payload.

Execution diagnostics support configured levels and actual CloudWatch Logs,
Firehose, and S3 writes through their owners. Diagnostic failures do not acknowledge
or discard source records. Execution-data inclusion exposes the event payload
processed at the recorded stage. S3 execution logs support JSON; `plain` and `w3c`
are explicitly rejected pending native layout/encoding calibration. Complete
native log-document, truncation, and AWS request/response-field parity is not claimed.

Execution metrics publish to `AWS/EventBridge/Pipes`, including Invocations,
EventCount, Duration, EventSize, ExecutionFailed, and partial/skipped execution
outcomes. EventCount excludes filter-rejected records.
The native capture's corrected read-only metric queries observed EventCount=1,
Invocations=1, ExecutionFailed=0 (Unit None), and Duration=69 ms for the owned pipe.
Earlier wrong-namespace queries remain retained as query mistakes, not evidence
of native metric absence.

Management observations commit at the API transaction boundary through `apievents`.
The source-owned projection preserves native Pipes field casing, masks sensitive
filter/template/description/tag values, retains null read responses, and preserves the
captured mutation/error response shape. Successful lifecycle and Conflict/NotFound
observations are replayed from exact-request-ID native CloudTrail records in
`testdata/aws/scheduler_pipes/lifecycle_success.json`. Downstream SQS evidence is
not represented as invented native Pipes data events.

## Exercised service-local proof

- `go test ./internal/services/pipes` covers template/JSON-path boundaries,
  ordered work selection, transaction rollback, and captured native management
  projection replay.
- `go test ./internal/integrations -run TestPipesQueueFilteringCurrentRoleAndSQLiteRestart`
  runs real IAM and SQS owners: stopped source isolation, filtering and transformed
  target content, current-role denial without source acknowledgement, retained
  stopped work after closing/reopening SQLite, and successful resumed delivery
  after removing the denial. It also holds a genuine successful target result
  across StopPipe, then verifies source acknowledgment before STOPPED without
  replaying the target or acquiring a newer source message. This transition
  regression passed five consecutive race-enabled runs.
- `scripts/aws/msk_incarnation_smoke.py` exercises actual Kafka topic
  deletion/recreation across StopPipe and SQLite/controller restart, both with
  failed retained work and with only a cursor. The race-enabled executable
  reports source-changed failure, leaves replacement group offsets uncommitted,
  preserves the old identity/work, and reads the replacement from offset zero
  only after explicit pipe recreation. Borrowed groups survive pipe deletion.
  Before/after evidence is in `testdata/integration/msk_incarnation.json`.
- A throwaway standalone program independently ran the real IAM/SQS/Pipes owners
  and observed RUNNING, transformed target body `{"value":7}`, zero visible source
  messages, and zero source messages in flight. The smoke program was then removed.

## Integrated executable proof

[`scheduler_pipes_executable_smoke.py`](../scripts/aws/scheduler_pipes_executable_smoke.py)
runs official boto3 clients against the actual signed gateway and a fresh SQLite
state directory, with no AWS endpoint or credential fallback. The completed run
exercised:

- Scheduler group/tags, scope isolation, disabled/invalid schedules, auto-deletion,
  native omitted-input notification, universal SQS and SDK-named Logs targets,
  customer-KMS payloads, EventBridge delivery and a real Python 3.13 Lambda target;
- IAM-denied Scheduler delivery to a real DLQ, and an actual synchronous Lambda
  429 followed by successful retained Scheduler delivery after process restart;
- encrypted Pipes filters/templates, actual CloudWatch Logs execution payloads,
  stopped-source isolation, filtering/transformation, real Lambda enrichment and
  current-role denial/recovery across process restart;
- real Lambda partial-batch failure, retry of only the failed item, and source
  acknowledgment before STOPPED without replaying the successful item;
- actual Kinesis and DynamoDB Streams records, continuation after another process
  restart, and no replay of already acknowledged initial stream records;
- CloudTrail management source projections and retained CloudWatch sums:
  Scheduler InvocationAttemptCount=10 and Pipes EventCount=7.

All four controller processes exited normally. Owned functions and streams were
deleted through service APIs. Physical engine disposal uses IDs from the fresh
owned SQLite store, verifies full Docker ownership labels, and confirms no matching
containers or volumes remain. It never prunes shared engines or images.

The [combined-main executable capture](../testdata/integration/scheduler_pipes_main_runtime.json)
repeated this workflow after integration with SSM and RDS, using a race-enabled
binary and schema 217. It observed the same metric sums (10 and 7), four normal
controller exits and no cleanup errors; owned physical engine handles were absent.
The [215→217 upgrade capture](../testdata/integration/scheduler_pipes_main_upgrade.json)
separately retained decryptable SSM state, RDS metadata, SQS bytes and the exact
legacy CloudTrail event. Focused race tests, affected vet/staticcheck and AWS,
SQLC and coverage generation checks passed on the combined tree.

The proof requires the CLI's installed Docker images, Python 3.13 Lambda image,
and prebuilt Lambda telemetry binaries:

```sh
go build -o bin/stackd ./cmd/stackd
python3 -B scripts/aws/scheduler_pipes_executable_smoke.py \
  --binary bin/stackd --state-directory "$(mktemp -d)" \
  --telemetry-directory bin
```

The native lifecycle capture separately contains 25 Scheduler and 24 Pipes
exact-request management records, plus related records: 74 management and 95 SQS
data records in total. Exact-ID SQS data sentinels established trail readiness.
The empty-input request's missing audit record is bounded non-observation, not
native absence. All owned native resources were independently verified absent.
Capture-owner sanitization retains credential field presence with placeholders;
it is not attributed to native service redaction.

Primary contracts:
[enrichment and response filtering](https://docs.aws.amazon.com/eventbridge/latest/userguide/pipes-enrichment.html),
[batching and partial failures](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-batching-concurrency.html),
[Kinesis consumption](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-kinesis.html),
[input transformation](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-input-transformation.html),
[customer-managed keys](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-encryption-pipes-cmkey.html),
[MSK source/group/authentication](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-msk.html),
[self-managed Kafka](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-kafka.html),
[source filtering and acknowledgment](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-event-filtering.html),
[execution logs](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-logs.html),
[metrics](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-monitoring.html).
