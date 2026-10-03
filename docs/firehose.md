# Firehose streaming behavior

> In native capture references, `000000000000` is an anonymized account alias,
> not the AWS account originally used. See [capture privacy](behavior-references.md#publishing-sanitized-probe-captures).

Firehose has generated AWS JSON contracts and real DirectPut/Kinesis-source S3
workflows, Lambda transformation, Logs decompression/extraction, raw backup and
EventBridge/Logs/SNS producers.
This is a partial service, not complete Firehose parity. The ten
registered target operations cover stream creation/deletion/description/listing,
destination updates, tags, `PutRecord` and `PutRecordBatch`. Unsupported source,
destination and processing configurations return explicit protocol errors.

## Ownership and persistence

`internal/services/firehose` owns typed stream incarnations, lifecycle/version
transitions, admitted records, processing claims, destination buffers, source
checkpoints and pending metric samples. Consumer-defined interfaces separate
Lambda invocation, S3 writes, Kinesis reads, diagnostic Logs publication and
CloudWatch samples from resource state. `storage/firehose` is the injectable
repository contract. Memory joins the shared transaction domain; SQLC SQLite uses
service-owned tables in migrations 102–104 and 106, including ordered processors,
parameters, backup configuration and individual binary record rows. Neither
backend stores an opaque delivery-stream document.

Admission commits records, metric observations and the API event together.
Kinesis reads, real Lambda execution and S3 writes occur outside Firehose
transactions. A source checkpoint advances with its accepted buffer rows.
Processing completion atomically replaces the input claim with independent
primary, Lambda-failure, decompression-failure and raw-backup obligations. Sealed configuration/version
and prepared object identity survive retries and restart. Current role policies
still authorize every ordinary Kinesis/Lambda/S3/Logs command.

The shared service-role authority supplies Firehose's account ID as
`sts:ExternalId`, evaluates the actual trust policy and records the STS assumption.
Cached sessions are isolated by role, session name, service, source ARN and
external ID. Existing sessions do not copy mutable role policies. Caller
`iam:PassRole`, request tags and resource tags remain admission checks owned by
Firehose, not privileges inherited by its producer calls.

## Captured behavior

Native captures use account `000000000000`, `us-east-1`; each fixture retains its
capture timestamps.
The retained files in `testdata/aws/firehose` are gzip-compressed JSON, preserving
raw requests, results, native request IDs, bounds and verified cleanup. Compression
avoids storing tens of megabytes of repeated base64 boundary payloads as text.
Replay manifests select observations; they do not replace native results.

| Fixture | Evidence |
| --- | --- |
| `controls.json.gz` | 207 calls, 150 request-correlated management projections; lifecycle, defaults, version changes, tags, pagination, role/trust/bucket failures and caller authorization. |
| `s3_delivery.json.gz` | 144 calls and eight actual S3 objects; binary bytes, gzip/delimiters, record/batch limits, buffered prefix changes, denied writes and recovery, diagnostics and eventual metrics. |
| `kinesis_source.json.gz` | 183 calls; source admission, create-time read boundary, direct-put rejection, read denial/recovery, source deletion and bounded same-ARN recreation observation. |
| `metric_statistics.json.gz` | Ten read-only native metric queries resolving sample count, sum, minimum and maximum beyond the initial sum-only capture. |
| `data_audit.json.gz` | Nine exact S3-delivered producer events across success, missing resource, denial, empty blobs and an invalid empty batch; 192 bounded probe/marker calls including cleanup. |
| `formatting.json.gz` | 400 calls, 92 cases and 19 independently decoded S3 objects; compression framing, extensions, delimiters, timestamp expressions, time zones and prefix bounds. |
| `lambda_processing.json.gz` | 461 calls, 19 producer records, eight real invocations, 18 S3 objects, three diagnostics and 63 metric queries; defaults, statuses, failures, backup and permission recovery. |
| `eventbridge.json.gz` | 115 calls, five S3 objects and seven cleanup checks; target admission, payload selection, current-role denial/recovery and rule-Region execution. |
| `processing_boundaries.json.gz` | Retry budgets of one/three, distinct invocation IDs with stable record IDs, actual function timeout/oversized-response failures, repeated-Lambda rejection and plain/KPL source envelopes with deaggregated raw backup. |
| `logs_processing.json.gz` | Real Logs subscriptions, trusted-origin denial contrasts, stage defaults/order/update admission, exact extracted bytes and original gzip backup; real Kinesis malformed inputs and five correlated failure envelopes. |
| `multiblock.json.gz` | Three independently decoded 1,250,054-byte ZIP/Xerial Snappy/Hadoop Snappy objects, binary and empty producer records, and explicit cleanup of preceding rejected/incomplete probe attempts. |
| `sns.json.gz` | Owned standard/FIFO subscription admission, PassRole/trust distinctions, duplicate/update controls, correlated raw/wrapped S3 bytes, and native delivery-status errors proving SNS uses `PutRecordBatch` under `AWS-SNS`. |

### Lifecycle and ingestion

- Basic and extended S3 configurations describe both S3 destination views under
  `destinationId-000000000001`. Defaults include DirectPut, version `1`, disabled
  stream encryption, 5 MiB/300-second hints, UNCOMPRESSED, NoEncryption, disabled
  diagnostic logging and disabled S3 backup.
- Creation is observable as CREATING. Puts then return ResourceNotFoundException;
  update/delete return ResourceInUseException; tagging is accepted. Deletion is
  observable as DELETING; repeat delete succeeds, while new puts/tags/updates and
  duplicate creation reject according to the retained native cases.
- Empty/identical updates do not increment the version or create an update
  timestamp. Changed configuration does. Explicit empty prefixes remain distinct
  from omitted prefixes. Stale versions reject atomically.
- Lists and tags have lexical exclusive cursors. Duplicate tag keys take the last
  value; invalid missing values do not partially modify tags.
- Empty record data is accepted. The captured record boundary is 1,024,000 bytes;
  batches admit 1–500 records and at most 4,194,304 raw bytes. The oversized
  aggregate error differs from shape-validation errors. These limits do not
  establish complete throughput/quota behavior.

### S3 and source delivery

S3 consumes actual retained bytes through its authorized PutObject command.
Objects use `application/octet-stream`. GZIP uses `.gz`/`gzip`; ZIP uses a DEFLATE
entry with `.zip`/`zip`; Snappy uses Xerial snappy-java framing and
`.snappy`/`snappy-java`; HADOOP_SNAPPY uses Hadoop framing and
`.snappy`/`hadoop-snappy`. The captured Hadoop suffix differs from documentation
that describes `.hsnappy`. An explicit empty FileExtension restores the codec's
default suffix. Firehose NoEncryption omits SSE headers; S3's bucket default,
including a KMS key, remains authoritative.

Primary and raw backup independently retain destination KMS key ARNs. Delivery
uses ordinary S3 PutObject with `aws:kms`, the selected key and
`bucket-owner-full-control`, under the native `AWSFirehoseToS3` role session.
The S3/KMS owners enforce current permissions and retain actual encrypted bytes;
Firehose has no duplicate KMS evaluator. SQLC retains key selection in both the
current stream and sealed output configurations. Backup buffering has a native
60-second minimum; primary buffering may be zero.

`testdata/aws/firehose/encryption_replay.json.gz` selects native delivery and
permission-recovery evidence from
[`testdata/aws/s3/kms_evidence.json.gz`](../testdata/aws/s3/kms_evidence.json.gz).
Both repositories replay distinct primary/backup keys and denied-primary recovery.
The restarted executable also verifies NoEncryption/default-KMS inheritance,
CloudTrail outcomes and EventBridge/SQS consumers.
[S3 envelope encryption](cloudtrail.md#s3-envelope-encryption) owns the crypto,
native source/cleanup boundaries and remaining encryption limitations.

AppendDelimiterToRecord inserts LF between records, not after the last record.
AWS canonicalized supplied parameters to an empty list and retained duplicate
processors while applying the delimiter once. Disabled processing retains its
configuration without adding delimiters. Omitted Enabled inherits the previous
value; omitted Processors clears the list. Enabled processing requires 1–5
processors. Native batches were reordered and split across objects; replay
compares consumer bytes without promising input ordering or exact packing.

Prefix expressions implement Java-style numeric/text fields, quoting, optional
sections, padding, offsets and zone IDs. The capture includes Tokyo/New York
zones and second-precision timestamps even with nine fractional digits.
Long localized zone names outside UTC remain explicitly unsupported. A literal
512-character prefix is accepted even when its implicit timestamp expansion is
longer; explicit expression expansion remains bounded. Broader CLDR, DST,
week-year and non-ASCII counting behavior is not established by these cases.

A prefix update before sealing affects already buffered records. Destination
write denial does not reject producer acceptance or change ACTIVE status. The
prepared batch survives restart; restoring the role policy delivers retained and
new records. Configured diagnostics enter the ordinary Logs command under the
delivery role. Captured S3 diagnostics encode `deliveryStreamVersionId` as a JSON
string, while captured Kinesis diagnostics encode it as a number.

Kinesis-source streams describe their source ARN, role and delivery-start time,
and reject direct puts. Source reads begin at delivery-stream creation, including records
written before the first ACTIVE observation, while excluding the captured
pre-create marker. Reads use real Kinesis DescribeStream/GetShardIterator/
GetRecords commands over the configured Kafka data plane. Denied GetRecords does
not advance the checkpoint; policy recovery reads the retained interval. Source
deletion leaves Firehose ACTIVE and publishes Kinesis.ResourceNotFound rather
than silently substituting a new source.

The shared KPL decoder also serves Lambda's Kinesis consumer. Firehose deaggregates
before retaining input records; a source checkpoint commits with every child of
the outer record. Lambda receives the original outer sequence/shard/arrival,
inner partition key and zero-based subsequence. Raw backup contains deaggregated
originals, not the KPL transport envelope. This does not change Lambda event-source
mappings: their measured standard/EFO distinction and shard-range filtering remain
owned by Lambda.

Direct same-account/same-Region Logs subscriptions use the existing Logs filter,
role, gzip envelope and retry ownership. Their adapter calls Firehose's ordinary
PutRecord command. Actual CONTROL_MESSAGE and filtered DATA_MESSAGE payloads
reach S3. Native subscription/source-processing captures exercise these actual
producers and distinguish service origin from a user assuming the delivery role.
Logical/cross-account Firehose destinations remain explicitly unsupported.

### Logs decompression and extraction

Enabled Decompression accepts direct ingestion only from the trusted Logs service
adapter. Ordinary signed callers, including a session of the Logs delivery role,
receive InvalidSourceException; a role ARN or caller-controlled user agent cannot
forge service origin. Kinesis-source ingestion remains supported and supplies the
captured malformed-input cases.

Decompression defaults to exact `GZIP`. Extraction requires Decompression and an
explicit DataMessageExtraction boolean, canonicalized to lowercase. Disabled
configurations retain their stages. Native admission retains repeated source
stages and their declaration order. Runtime order is decompression, optional
message extraction, optional Lambda, then output delimiter/compression. Source
stages execute once; mixed repeated true/false extraction settings and repeated
stage execution are not established by the native capture.

Decompression without extraction validates and preserves the decompressed JSON
bytes. Extraction removes envelope metadata and emits every message followed by
LF, including empty messages. One original envelope remains one Lambda record;
CONTROL_MESSAGE becomes an empty record rather than being dropped. A declared
AppendDelimiterToRecord still inserts LF between output records only.

Malformed gzip/JSON and invalid extraction envelopes produce retained
`decompression-failed` objects, not Lambda-processing failures. The captured code
is `Decompression failed.`, with attemptsMade 1, original compressed rawData,
numeric millisecond times and no lambdaARN. Valid non-Logs JSON passes
decompression alone but fails extraction. Raw backup and Lambda failure rawData
also retain the original compressed input, never the derived Lambda input.
Derived bytes are not a second durable source of truth.

Enabling decompression on an existing stream requires currently enabled
decompression or Lambda processing. The captured disable/reenable and
attach-Lambda/remove/readd sequences are enforced from current configuration,
without a historical feature flag.

### Lambda processing and raw backup

The Lambda processor invokes the ordinary authorized RequestResponse command
through the real container runtime. It does not call a handler in process or hold
the shared scheduler drain while customer code runs. Defaults are three retries,
the destination role, a 1 MiB processing buffer and a 60-second interval.
Admission retains the canonical five parameters and checks caller PassRole for
the assigned processing/backup roles.

Lambda receives opaque record IDs distinct from public PutRecord IDs, base64
data and millisecond arrival timestamps. Empty data is the base64 string `""`,
never JSON null. `Ok` records contribute transformed primary bytes; `Dropped`
records contribute neither primary output nor success counters;
`ProcessingFailed` records retain original bytes in the error envelope.
Missing returned IDs fail the missing records; an invalid result enum or function
exception fails the batch. Error objects retain `rawData`, `errorCode`,
`errorMessage`, `attemptsMade`, numeric millisecond timestamps and `lambdaARN`,
matching the captured capitalization rather than the documentation's `lambdaArn`.
Configured error output works with raw backup disabled.

Enabled raw backup retains every original record, including dropped and failed
records, independently of transformed output. Once enabled it cannot be disabled.
After processing, primary and backup buffers use their own destination hints:
the capture's 60-second backup and 120-second primary hints produced separate
objects, not a single coupled write. A denied destination does not block the
other obligation. Completed processing is not rerun for S3 retries or restart.
An invocation interrupted before its completion transaction may run again after
restart; there is no exactly-once claim for customer side effects.

Captured retry budgets of one and three produced two and four real invocations.
Each attempt had a fresh invocationId, while record IDs and input bytes remained
stable. Duplicate returned IDs produced Lambda.DuplicatedRecordId; replacing an
ID produced Lambda.MissingRecordId. Invalid base64, a real function timeout and an
oversized runtime response produced Lambda.FunctionError. The oversized capture
establishes that failure, not an exact payload-size threshold. More than one
Lambda processor is rejected with InvalidArgumentException.

The local worker uses thirty-second service-time retries and a five-minute
invocation deadline. The captures do not establish a universal retry cadence,
exact permission propagation, the Firehose-level deadline error or alias
transitions. Other unsupported processor kinds return explicit errors.

### EventBridge producers

EventBridge targets require a role and a delivery-stream ARN. The adapter shares
the ordinary PutRecord consumer interface with Logs, rather than mutating
Firehose buffers. Native delivery used `firehose:PutRecord`, not PutRecordBatch.
Full envelopes, InputPath, static Input and InputTransformer payloads reach S3
without an added newline. Missing stream/role resources can pass target admission;
current authority and existence are checked during delivery.

An other-Region target ARN remains visible in ListTargets, but the captured call
used the rule's Region and the target's stream name. East-only permission allowed
delivery to the east stream for a west target ARN; west-only permission denied
the east resource. The retained target ARN remains unchanged in DLQ attributes.
Permission denial uses the existing NO_PERMISSIONS terminal/DLQ path; restored
PutRecord permission admits fresh events. Cross-account target admission rejects.

### SNS producers

Standard-topic Firehose subscriptions retain `SubscriptionRoleArn`. Subscribe
and role updates require caller `iam:PassRole` and a currently SNS-trusted role;
they do not require a present delivery stream or current producer permission.
FIFO subscriptions reject the Firehose protocol. Missing role resources produce
the captured PassRole authorization error even for a caller whose policy grants
PassRole over the owned role prefix. Duplicate subscriptions with identical
attributes preserve identity; conflicting attributes reject rather than mutate.

The SNS adapter uses the shared service-role authority and an ordinary authorized,
audited `PutRecordBatch` command under session name `AWS-SNS`. It never writes S3
directly, falls back to the SNS principal, or acknowledges a failed batch record.
Firehose owns buffering, destination-role authorization and S3 object delivery.
The native capture independently retrieved S3 objects after a role granting only
`firehose:PutRecordBatch`; settled PutRecord-only permissions instead produced
delivery-status errors naming `firehose:PutRecordBatch`. This observed action
differs from the SNS prerequisite guide's minimum-PutRecord statement. An early
publication delivered during policy transitions is not evidence that PutRecord
alone is sufficient.

Wrapped records contain Type, MessageId, TopicArn, optional Subject, Message,
Timestamp, UnsubscribeURL and supplied MessageAttributes, followed by LF.
Firehose notifications omit Signature, SignatureVersion and SigningCertURL.
Native number spelling and binary base64 values remain intact. Raw delivery is
exact body bytes, without metadata, attributes or an added delimiter. One native
object packed a wrapped record and a raw Unicode/newline body together; comparison
uses actual consumer bytes rather than promising object boundaries or order.

The SDK replay exercises both stores, SNS-owned pending fanout recovery and
Firehose-owned buffered recovery, subscription removal and topic deletion after
producer acceptance. Batch-only permission delivers; PutRecord-only permission
and revoked trust take SNS's real failure/dead-letter path rather than reaching
S3. Repaired authority admits fresh records across reopen.

The local adapter schedules one retained notification per batch and checks
current trust through the existing shared authority. These captures do not
establish native batching cardinality, aggregate Firehose metric equivalence,
role-session cache lifetimes, exact policy/trust propagation or long-tail retry
timing. A bounded missing-object window is not proof of eternal absence.
Exact-topic SourceArn plus SourceAccount trust passed admission and actual S3
delivery after propagation. Native trust revocation produced explicit
`SNS failed to assume subscription role` diagnostics; restoring trust recovered
fresh delivery. Other-Region and nonexistent-stream endpoint ARNs passed
admission. Unlike EventBridge, SNS's other-Region failure named the endpoint's
Region in the denied Firehose resource. Full cross-account/cross-Region delivery
and source-condition/session behavior remain outside this evidence.

The capture retains 183 calls and seven independently downloaded objects.
Cleanup deleted the four topics, then the stream before dependencies; separate
reads confirmed the stream and topics absent, all four roles missing, the bucket
absent after object removal, and no owned feedback log groups. Replay uses pinned
SNS v1.47.0 and Firehose v1.51.0 SDK clients.

### Audit and metrics

Eight supported controls emit management events. Describe/List/ListTags are
read-only; only successful Create includes response elements. Successful controls
omit embedded resources; captured rejections include the submitted stream once.
Lookup resource indexes remain empty.

PutRecord and PutRecordBatch emit **read-only Data events** with resource type
`AWS::KinesisFirehose::DeliveryStream`. Records and record IDs are not projected;
request parameters contain only the stream name, and response elements are null.
Denied/validation requests have null parameters; AccessDeniedException becomes
AccessDenied in the audit event. Configured advanced selectors, S3 trails and
EventBridge consume these real events; data events do not enter management
history. The producer capture arrived after propagation, so initial empty polls
are not evidence that Firehose lacks data-event support.

IncomingRecords/IncomingBytes contribute one sample per accepted producer call,
with batch count/raw byte total as the value, including accepted empty records.
Primary/error delivery and raw backup publish separate DeliveryToS3/BackupToS3
series. Successful record and byte counters use original record sizes, not the
transformed or compressed object size. SucceedProcessing counts only `Ok`, not
`Dropped`. The captured 51-byte Ok, 53-byte Dropped and 53-byte failed records
yielded DeliveryToS3 2/104, BackupToS3 3/157 and SucceedProcessing 1/51.
Object attempts contribute Success and failure samples through the existing
CloudWatch interface. Weighted pending samples survive restart and stream
deletion. Source and DataFreshness distributions remain incomplete; native totals
alone do not establish their sampling cadence.
SucceedProcessing is Lambda-specific; source-only decompression/extraction does
not manufacture those samples. Decompression-specific counters remain
unimplemented: native queries included inconsistencies against retained
envelopes, even after a later publication sweep.

## Local policies and remaining boundaries

- One-second lifecycle/source polling and thirty-second retries are local
  service-time policies, not AWS latency guarantees. Metric publication uses the
  completed UTC minute. Tests wait for observed state and completed publications.
- DirectPut retention is bounded at 24 hours; Kinesis buffers use source retention.
  A prepared mixed-age object expires as a batch at its oldest retained record's
  bound. Younger records may retire with it. Exact native mixed-age expiry and
  long-outage recovery require additional evidence.
- A recreated Kinesis ARN is not silently attached to an old source incarnation.
  Native observation found no replacement marker within 300 seconds; this does
  not establish permanent non-recovery.
- Stream SSE, other processor kinds, format conversion, dynamic
  partitioning, remaining Java/CLDR timestamp behavior, non-S3 destinations,
  MSK/database sources and provisioned DirectPut throughput remain open.
  Large binary codec captures verify consumer bytes, not a fixed chunk size,
  record order or universal object packing.
- Adaptive throughput/throttling, cross-account sources/destinations, native
  propagation and universal packing/retry/expiry behavior are not established by
  these captures. Registration remains `partial` in the generated inventory.

## Verification and references

SDK fixtures exercise memory and SQLite, real Kafka reads, real Lambda runtimes,
actual S3 bytes, role-denial recovery, diagnostics, metric distributions,
management history, selected S3/EventBridge audit delivery and retained restart
boundaries. Formatting replay independently decodes native and local objects.
Processing replay includes the empty-record regression discovered through the
executable, not just a serializer assertion.

Executable AWS CLI/SDK workflows exercised DirectPut/Kinesis/Logs → Firehose → S3
and EventBridge → Firehose → real Python Lambda → S3. The processing smoke denied
both outputs, restarted, recovered backup while primary remained denied,
restarted again and recovered primary without additional Lambda invocations.
It verified transformed/failed/dropped/empty records, external-ID trust, the
other-Region target distinction, Lambda denial and fresh-record recovery.
CloudWatch reported 12 incoming, 12 backup, 11 primary/error and five successfully
processed records for that workload. These are observed workflows, not complete
service conformance.

The source-processing executable workflow used actual Logs subscriptions,
reversed processor declarations and Python Lambda. Runtime inputs were one empty
CONTROL record and the exact extracted Unicode/newline message bytes. An ordinary
DirectPut caller was rejected. Five real Kinesis records included malformed gzip,
invalid JSON and non-Logs JSON. With S3 output denied, two SQLite process restarts
recovered raw backup first, then primary and three original-byte failure
envelopes, without rewriting the completed backup. All seven owned objects,
streams, functions, roles, log groups and local runtime/database artifacts were
removed after verification.

An integrated executable workflow deaggregated one Kafka-backed Kinesis KPL
record into three children. Backup succeeded under its own KMS key while primary
data-key generation was denied. After SQLite restart and policy repair, primary
delivery retained all three newline-delimited records under the other canonical
key; raw backup was not duplicated and denied KMS attempts remained in history.
The owned data resources, runtime, local database and smoke script were removed.

Primary references:

- [CreateDeliveryStream](https://docs.aws.amazon.com/firehose/latest/APIReference/API_CreateDeliveryStream.html), [PutRecordBatch](https://docs.aws.amazon.com/firehose/latest/APIReference/API_PutRecordBatch.html)
- [S3 delivery](https://docs.aws.amazon.com/firehose/latest/dev/basic-deliver.html), [delivery failures](https://docs.aws.amazon.com/firehose/latest/dev/retry.html), [object naming](https://docs.aws.amazon.com/firehose/latest/dev/s3-object-name.html)
- [Firehose access control](https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html)
- [Data transformation](https://docs.aws.amazon.com/firehose/latest/dev/data-transformation.html), [processor parameters](https://docs.aws.amazon.com/firehose/latest/APIReference/API_ProcessorParameter.html), [processing failures](https://docs.aws.amazon.com/firehose/latest/dev/data-transformation-failure-handling.html), [diagnostic errors](https://docs.aws.amazon.com/firehose/latest/dev/monitoring-with-cloudwatch-logs.html)
- [Logs subscription example](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html#FirehoseExample)
- [Logs decompression](https://docs.aws.amazon.com/firehose/latest/dev/writing-with-cloudwatch-logs-decompression.html), [message extraction](https://docs.aws.amazon.com/firehose/latest/dev/Message_extraction.html)
- [SNS Subscribe](https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html), [Firehose fanout](https://docs.aws.amazon.com/sns/latest/dg/sns-firehose-as-subscriber.html), [SNS role prerequisites](https://docs.aws.amazon.com/sns/latest/dg/prereqs-kinesis-data-firehose.html)
- [CloudTrail data resource table](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html), [advanced selectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html)

Wire contracts come from the SDK checkout's Smithy models; compatibility replay
uses the pinned Go v2 Firehose client v1.51.0.

Native AWS rejected both direct producer APIs for Kinesis-source delivery
streams; stackd follows the captured distinction between stream types.
