# CloudWatch Logs

Logs is a partial service with real ingestion, storage, Lambda output, metric filters and Lambda/Kinesis subscriptions. The
complete modeled operation inventory remains the target; registered operations
and captured examples are not a claim of service parity.

## Ownership and current behavior

`cmd/awsgen` maps `logs=cloudwatch-logs` to the SDK Smithy model. Generated routing,
request types, validation and response encoding remain authoritative. The service
registers group/stream creation, deletion and description; `ListLogGroups`;
`PutLogEvents`, `GetLogEvents`, `FilterLogEvents`; modern and legacy tags;
retention-policy mutation; Put/Describe/DeleteResourcePolicy;
`PutSubscriptionFilter`, `DescribeSubscriptionFilters` and `DeleteSubscriptionFilter`;
and `PutMetricFilter`, `DescribeMetricFilters`, `DeleteMetricFilter` and `TestMetricFilter`.
Other modeled operations return explicit errors.

`internal/services/logs` owns typed commands, IAM resource/condition context,
admission rules and paginated reads. The same `CreateLogGroup`, `CreateLogStream`
and `PutLogEvents` commands serve SDK requests and runtime delivery.
`storage/logs` exposes the service-owned repository contract. The default memory
adapter shares the existing transaction domain and uses persistent ordered
indexes; SQLC SQLite owns group, tag, stream, event, resource-policy, metric-filter, subscription and logical-destination
tables. Event order is (timestamp, ingestion time, sequence), scoped by
partition/account/region and
resource identity. Pagination uses scoped, expiring keyset tokens, not durable
cursor ledgers. Group and stream deletion remove their owned events.

Mutations and recorded management API outcomes commit in the shared transaction.
The producer set follows the [Logs CloudTrail reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/logging_cw_api_calls_cwl.html):
`PutLogEvents` and legacy tag mutations are not inferred to be CloudTrail records.
Selected management projections have exact-request-ID native captures and signed
SDK replay, described below. Customer messages remain Logs data, not generic
audit JSON or metrics.

## Native management audit

`testdata/aws/cloudtrail/logs_controls.json` retains 33 request-correlated native
events from owned group/stream, tag, retention, metric-filter and resource-policy
controls, empty reads, missing destinations/subscriptions and federated denials.
`scripts/aws/cloudtrail_service_probe.py --logs-controls` reuses the shared
fixture-driven probe and history collector; `--collect-only` harvests an already
cleaned capture without provisioning again. The earlier
`logs_controls_revision_attempt.json` preserves a probe binding failure:
`PutResourcePolicy.revisionId` is top-level, not inside `resourcePolicy`.
Both attempts cleaned their owned groups and scoped policies; neither published
custom metric data or changed an account-wide resource policy.

`testdata/aws/cloudtrail/logs_subscription_history.json` is a read-only harvest
of the already-cleaned subscription workflow: 136 exact matches from 137 eligible
management calls. The unobserved Lambda-destination `roleArn` rejection is a
bounded non-observation, not evidence that AWS never records it.
`logs_subscriptions_probe.py <existing-capture> --audit-output <new-output>`
uses the same request-ID collector rather than provisioning another Lambda.

Observed distinctions retained by the service:

- `apiVersion: "20140328"`, omitted on the captured IAM denials.
- Null read responses and ordinary empty mutation responses, but the actual
  `PutResourcePolicy` response including its top-level revision.
- Whole-request omission for successful and rejected `TestMetricFilter`, and
  for captured IAM denials. Denial audit code is `AccessDenied`; the SDK wire
  still reports `AccessDeniedException`.
- Source-owned group, stream and resource-policy event resources, independently
  of LookupEvents search names. A rejected subscription distribution enum keeps
  the group search term but has no event-resource array; semantic pattern/field
  rejections do retain that array.
- `ListLogGroups` includes the current account in its audit request. Native
  acceptance of a name-pattern alternative longer than 24 characters corrects
  the stale Smithy pattern through the reviewed generator manifest; the modeled
  overall length and alternative grammar remain enforced.
- IAM-user-issued federation retains its issuer ID, ARN and user name in the
  shared [CloudTrail session identity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html).

Signed memory/SQLite replay covers 32 stable control outcomes and three selected
subscription admission failures, not all 136 historical subscription outcomes.
The fresh capture returned an empty successful `GetLogEvents` immediately after
stream deletion; `ingestion.json` returned `ResourceNotFoundException` at that
boundary. The original capture diagnosis is retained, and replay does not pin a
fixed visibility delay or substitute one observation for a consistency guarantee.
Successful native destination provisioning and the remaining audit admission
branches are not established by these captures. Root federation issuer typing
follows the AWS identity contract, but root account aliases are not yet projected.

`testdata/integration/logs_audit_runtime.json` retains the actual SQLite
executable before/after comparison and cleanup. Configured management trail
delivery produced real S3 gzip log objects, and an EventBridge rule delivered
the same successful/rejected `TestMetricFilter` records to SQS, exactly matching
LookupEvents with their request contents omitted. Because these are read-only
management events, the rule uses
`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`. Native trail admission's
zero-byte directory marker is not a gzip log object. All owned local buckets,
trails, rules, queues, groups and users were removed; both controllers exited zero.

## Native evidence

`testdata/aws/logs/ingestion.json` comes from `scripts/aws/logs_ingestion_probe.py`.
The retained run contains 94 Logs requests across 13 operations, plus caller
identity, using one newly owned group and five streams. Cleanup was confirmed.
It records:

- Ignored omitted, arbitrary and stale sequence tokens; resubmitted batches remain
  observable duplicates rather than being deduplicated by the token.
- UTF-8 bytes plus 26 bytes per event against the 1 MiB batch budget, including
  exact admission and over-budget errors. The large admission probes used old
  events, so they do not prove large-event visibility.
- Valid-event ordering and the 24-hour span boundary; old/future per-event
  rejection outside the accepted range does not widen its valid span.
- Exclusive old/expired rejection end indices and inclusive future start indices.
- Inclusive Get start time, exclusive end time, equal-bound empty reads, and
  forward/backward pagination with duplicate messages and terminal tokens.
- Retention-policy/tag round trips and native missing/invalid resource errors.

AWS returned partial pages and stale stream metadata during bounded reads.
Local replay drains pages and compares stable observed records; it does not
manufacture permanent loss from an event absent during a short native capture.
The fixture records its timing, substitutions and limits.

`testdata/aws/logs/filters.json`, captured by `scripts/aws/logs_filters_probe.py`,
contains 90 `TestMetricFilter` patterns and a corpus of 89 messages. Forty-five
representative FilterLogEvents comparisons cover both matches and errors.
`internal/services/logs/filterpattern` owns the shared parsed matcher: text terms,
required/optional/excluded terms, JSON selectors and boolean expressions,
space-delimited fields, wildcard paths and the supported percent-regex language.
Native distinctions include substring matching, null versus missing, JSON number
lexemes versus quoted comparisons, repeated JSON keys and array-member matching.
The test-only native oracle does not register an otherwise unsupported operation.

`testdata/aws/logs/authentication.json` records rejected native DescribeLogGroups
requests. Invalid credentials returned `UnrecognizedClientException`; an explicit
federation session-policy deny returned `AccessDeniedException`. Both were HTTP
400, despite the generic [common-errors page](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/CommonErrors.html)
listing 403. No infrastructure was created or changed; temporary credentials are
not retained. SDK regression replay asserts the native code and status, not
incidental diagnostic wording.

Primary ingestion/retention contracts:
[PutLogEvents](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html),
[GetLogEvents](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetLogEvents.html),
[FilterLogEvents](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html),
[filter syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html),
[PutRetentionPolicy](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutRetentionPolicy.html)
and [DeleteRetentionPolicy](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteRetentionPolicy.html).
AWS permits increasing retention before physical deletion completes; retention
is not an irreversible high-water mark that rejects newly backfilled events after
policy deletion.

Physical event deletion runs through the shared service-time scheduler on memory
and SQLite. The job rechecks current policies inside its transaction; changing or
removing retention before deletion preserves still-stored events. Already-deleted
events cannot return after increasing/removing retention or restarting. Deletion
repairs retained-event counts and first/last timestamps without changing group
sequence identities or queued subscription payloads. Stream `storedBytes` retains
[AWS's documented zero behavior](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_LogStream.html); group accounting excludes expired events before
physical deletion.

The worker runs when events become older than the current retention cutoff.
This deterministic local scheduling does **not** reproduce AWS's variable
physical deletion latency (typically up to 72 hours, sometimes longer).
Memory/SQLite regressions cover exact cutoff, policy replacement/removal, rollback,
scope isolation and reopen. The [executable evidence](../testdata/integration/logs_retention.json)
records actual deletion, no resurrection, independent unlimited groups, repaired
stream summaries and controller restart with both controller exits zero.

## Actual Lambda output

`compute/lambda` attaches to Docker output before starting the process, forwards
actual stdout/stderr and keeps only a bounded Invoke tail. The Docker log driver
is disabled: a second persistent raw-output ledger is unnecessary. Lambda owns
its native group/stream environment values and a consumer-defined log writer.
`internal/integrations.LambdaLogs` resolves the execution-role credentials and
calls ordinary Logs commands with service timestamps and the trusted
`lambda:SourceFunctionArn` context. Current IAM is evaluated at ingestion; a root
invoker cannot lend its privileges to the runtime. Denied log writes are diagnosed
without failing an otherwise successful function invocation.

The adapter frames lines, preserves UTF-8 when splitting oversized output and
batches within Logs admission limits. Warm invocations share a stream. Normal
function deletion kills and drains the process before closing its Runtime API
and writer, retaining final partial output without injecting a runtime-client
shutdown traceback. Deleting a function does not delete the log group.

Fixture-based SDK tests exercise native ingestion, filter matching and pagination
on memory/SQLite, including reopen. `TestLambdaRuntimeLogDeliverySDK` uses actual
containers for allow/deny policies, cold/warm output, service time and exact bytes
through deletion. The native CLI smoke also retained 21,084 emitted UTF-8 bytes,
filtered stderr, retained logs after function deletion and recovered previously
stored events after restarting the SQLite-backed executable.


## Service destinations and resource policies

EventBridge enters ordinary Logs commands as `events.amazonaws.com`, with the
source rule ARN/account. Applicable ACCOUNT and RESOURCE policies are evaluated
together by the shared IAM engine; an explicit deny in either scope defeats an
allow in the other. These policies grant service-principal `CreateLogStream` and
`PutLogEvents`, not IAM user/role permissions. CloudTrail instead assumes its
configured IAM role, and Lambda uses its execution role. Neither borrows the
original API caller's privileges.

`testdata/aws/eventbridge/logs_destination.json` and `logs_policy_precedence.json`
come from `scripts/aws/events_logs_probe.py`. Their owned resources were cleaned
up. Native evidence establishes:

- ACCOUNT policies use names and ignore expected revisions. RESOURCE policies
  use a group ARN without `policyName`; supplying both is rejected.
- RESOURCE creation can omit a revision. Matching updates increment it; omitted
  or stale update revisions conflict, while a nonnumeric revision is invalid.
  Describe reports the current revision; failed writes preserve it. Deletion
  requires the current revision. Group deletion removes its scoped policy.
- RESOURCE policy lookup requires `policyScope=RESOURCE`. A resource ARN with
  default/ACCOUNT scope is invalid.
- Both directions of ACCOUNT/RESOURCE deny precedence produced correlated native
  `NO_PERMISSIONS` DLQ messages. Removing the deny restored actual log delivery.

EventBridge default delivery writes the full event envelope, with the event's
whole-second timestamp. A timestamp/message transformer writes the extracted
text, not the transformed object. CloudTrail writes individual native CloudTrail
records using delivery-time timestamps; it does not send the S3 gzip wrapper.
See [EventBridge target contracts](eventbridge.md#cloudwatch-logs-targets) and
[CloudTrail destination ownership](cloudtrail.md#cloudwatch-logs-destination).

Fixture replay covers policy revisions, actual delivery, denial/recovery and
SQLite reopen. The executable CLI smoke delivered default/transformed events,
observed deny precedence in both scopes, and compared the same CloudTrail record
in S3 gzip and Logs. Restart preserved delivered records, bucket tags and removed
trail configuration. These checks do not establish native stream allocation,
cross-account Logs delivery, exact distributed delays or throughput limits.

Primary contracts:
[PutResourcePolicy](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutResourcePolicy.html),
[DescribeResourcePolicies](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeResourcePolicies.html)
and [DeleteResourcePolicy](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteResourcePolicy.html).
The native RESOURCE no-name admission differs from the Put documentation's
required-name wording; captured wire behavior governs this boundary.

## Lambda subscriptions

`PutSubscriptionFilter`, `DescribeSubscriptionFilters` and
`DeleteSubscriptionFilter` implement same-account, same-Region Lambda destinations.
Logs owns typed filter configuration, matching and retained compressed delivery
work. `Config.Subscriptions` exposes `Check` and `Send`;
`internal/integrations.LogsSubscriptions` adapts these to Lambda's ordinary
`CheckInvoke` (DryRun) and `InvokeEvent` boundaries. Preflight runs outside Logs
storage and does not execute a synthetic handler or `CONTROL_MESSAGE`. Before
committing configuration, Logs rechecks current caller authority, group incarnation
and filter capacity. A failed replacement preserves the existing filter.

Both checks and sends use the trusted `logs.amazonaws.com` principal with the
current regional alias, `logs.<region>.amazonaws.com`, source account and source
group ARN **including `:*`**. IAM matches these aliases together in one decision,
so an explicit deny cannot be bypassed by trying another spelling. This is not a
grant of the API caller's authority; the handler subsequently uses its execution
role. Lambda destinations reject `RoleArn`.

Only the accepted portion of `PutLogEvents` enters matching. Stored source rows,
the typed `logs_batch_accepted_v1` journal fact and selected subscription work
commit in one memory/native SQLite transaction. The fact contains batch identity,
group ARN, stream and accepted count, not log message bodies; it is not a fake
CloudTrail `PutLogEvents` record. The shared scheduler selects retained work and
invokes Lambda outside the Logs transaction, then commits version-checked progress.
Replacement/deletion fences old filter work; group deletion removes owned work.
A crash after Lambda acceptance but before Logs progress commits may redeliver.

The actual Lambda input is `{"awslogs":{"data":"<base64 gzip>"}}`; decompression
produces `DATA_MESSAGE`, owner, log group/stream, subscription filter names and
matching event IDs, timestamps and unchanged messages. Requested system fields
appear in each event's `extractedFields`. Lambda success means asynchronous
acceptance, not handler success; Lambda owns subsequent handler retries.
The public [journal](event-journal.md#delivery-and-causality) links the accepted
Logs batch to Lambda acceptance and authenticated SDK side effects during execution.

### Native subscription evidence

[`testdata/aws/logs/subscriptions.json`](../testdata/aws/logs/subscriptions.json)
comes from `scripts/aws/logs_subscriptions_probe.py`: 380 actual AWS CLI requests
across two runs (220 current, including 48 supplemental, plus 160 prior), with a
real Python 3.12 Lambda forwarding decoded envelopes to an owned SQS collector.
All owned resources were independently cleaned. The retained observations contain
16 `DATA_MESSAGE` envelopes and no observed `CONTROL_MESSAGE`. This is bounded
observation, not proof that AWS never sends control traffic.

The capture establishes:

- Five filters per group, rejection of the sixth, and the matching Service Quotas
  value `L-87E7D306=5`, despite the stale Put API documentation's two-filter wording.
  Two regex terms per filter are admitted; three are rejected. Three filters with
  two terms each admitted **six total terms**. A five-total-term cap is not inferred;
  the combined metric/subscription regex quota remains unmeasured.
- Global and current regional Logs principals both admit configuration. Wrong
  source account/group and an exact source ARN without `:*` fail. Missing or denied
  destinations reject preflight without replacing the existing filter.
- Same-name replacement preserves `creationTime`. `ByLogStream` is the explicit
  default; `Random` is admitted and retained, invalid distributions fail. These
  Lambda observations do not establish Kinesis partition behavior.
- `applyOnTransformedLogs=true` is admitted and preserved without a transformer,
  but its correlated delivery was not observed in four bounded collector polls.
  Local matching uses original events; transformer execution and this native
  delivery edge are not established.
- `@aws.account`, `@aws.region` and `@source.log` are emitted in per-event
  `extractedFields`; `@source.log` is the group **name**, not ARN. Plain and JSON
  message bytes remain unchanged. Emitted fields are deduplicated.
- Account/region selectors admit equality, `!=`, AND/OR, parenthesized expressions
  and `IN`/`NOT IN` with **parenthesized lists**, using single or double quotes.
  Square-bracket lists shown in current documentation are rejected, as are unknown
  selector fields and `@source.log` selectors. Matching membership selectors
  produced actual delivery.
- Matching same-stream events were grouped; separate streams remained separate,
  and overlapping filters produced separate envelopes sharing event IDs.
  Pre-subscription, nonmatching, rejected old/future and post-removal events were
  absent from bounded collector output, not proven permanently lost.

`TestLogsSubscriptionsNativeSDK` replays the captured controls and positive
delivery records through SDK clients and real containers on memory/SQLite. Each
handler request ID must identify the exact accepted Lambda invocation parenting
its signed SQS effect; a previous warm invocation's parent cannot satisfy it.
`TestLogsSubscriptionDockerRecovery` covers source rollback, failed target
acceptance, retained delivery after source-stream deletion and SQLite reopen,
acknowledgement retirement, expiry and permission-revocation disable/skip recovery.

The AWS CLI also exercised the SQLite-backed executable: partial admission
delivered only matching accepted bytes, system fields preserved original messages,
and distinct warm invocations retained their own SDK parents. Restart preserved
disablement after permission restoration; advancing ten service-minutes resumed
new delivery without backfilling skipped arrivals. The public journal retained the
exact batch → accepted invocation → signed SQS chain. A direct synchronous Invoke
also linked its SDK effect to the reserved API outcome committed after execution.

### Modeled time and unmeasured behavior

Local batching is at most one accepted `PutLogEvents` batch per matching filter;
AWS's aggregation cadence and batch boundaries are not reproduced. Retained work
expires after 24 service-hours; retryable target errors use one-second exponential
backoff capped at five minutes. AWS documents retries for up to 24 hours, not this
exact cadence. Nonretryable errors, including access denial and missing targets,
drop the rejected batch and disable the filter for exactly ten service-minutes,
skipping new arrivals during disablement. AWS documents disablement for **up to**
ten minutes; native revoke/restore polling did not measure its actual deadline.

Subscription configuration activates immediately locally. The prior native run
observed stale configuration before the settled capture; propagation is an honest
gap, not modeled by this immediate cutover. High-entropy large batches and a single
event exceeding Lambda admission after gzip/base64 remain uncaptured. Stackd does
not guess chunk sizes or truncate data: real Lambda target errors remain delivery
errors under the current retry classification.

Primary contracts:
[PutSubscriptionFilter](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutSubscriptionFilter.html),
[DescribeSubscriptionFilters](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeSubscriptionFilters.html),
[DeleteSubscriptionFilter](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteSubscriptionFilter.html),
[subscriptions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Subscriptions.html),
[Lambda subscription workflow](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html)
and [regex limits](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/regex-expressions.html).
Captured native behavior governs the documented quota and selector disagreements.

## Kinesis and logical destinations

Direct Kinesis subscriptions require a same-account, same-Region stream and a
delivery role. `PutDestination`, `PutDestinationPolicy`, `DescribeDestinations`
and `DeleteDestination` implement typed logical destinations; the existing tag
APIs include them. A logical destination must share the source group's Region,
but its physical stream can be in another Region of the destination account.
Cross-account logical registration uses the destination policy and ordinary IAM
evaluation, not an authorization bypass.

`LogsSubscriptions` assumes the retained role through the shared service-role
issuer and calls Kinesis's ordinary typed `PutRecord`. Direct registration and
`PutDestination` preflight send a real gzip `CONTROL_MESSAGE`; no
`DescribeStream` permission is invented. Logical filter registration checks its
destination policy without sending another control record. The API caller needs
`iam:PassRole` where a role is supplied; the delivery role needs actual stream
write permission and Logs trust. `PutSubscriptionFilter` authorizes the bare
source group ARN, while service-role source context retains the `:*` suffix.

Data bytes use the same retained `DATA_MESSAGE` envelope as Lambda subscriptions,
without Lambda's outer `awslogs.data` wrapper. `ByLogStream` uses the hexadecimal
MD5 of `owner:logGroup:logStream`; `Random` uses UUID partition keys. Native control
records use owner `CloudwatchLogs`, empty group/stream/filter names and the
corresponding partition key. These are protocol values, not custom integrity
metadata.

Logical updates preserve creation identity, policy and omitted tags; supplied
tags merge. Updates select a new target only for future batches. Pending work
retains its original target, role/source authority, partition key and compressed
bytes through retry and SQLite reopen. Destination deletion does not delete its
source subscription metadata. The existing retry/disable model above remains
explicitly local rather than a measured AWS timing guarantee.

### Native destination policy and delivery evidence

[`kinesis-subscriptions.json`](../testdata/aws/logs/kinesis-subscriptions.json)
and [`kinesis-destination-tags.json`](../testdata/aws/logs/kinesis-destination-tags.json)
retain actual control/data bytes, role denial, distribution, logical-policy,
tag and deletion observations. `scripts/aws/logs_kinesis_probe.py` owns the
reproducible delivery experiment. The bounded restore windows do not establish
permanent loss or exact recovery timing.

[`destination-principals.json`](../testdata/aws/logs/destination-principals.json)
records the additional owned policy experiments through `scripts/aws/aws_cli.py`.
The current run contains 74 requests; all current and prior owned resources were
verified absent. Its original caller was an IAM user, with a separate owned
role session for authorization contrasts:

- ARN principals, including account-root ARNs, are rejected. Bare account IDs
  and arrays are admitted. Native admission also accepts immutable role IDs;
  this does not imply arbitrary ARN-to-ID binding.
- Condition keys are restricted to exactly `aws:PrincipalOrgID` and
  `aws:PrincipalOrgPaths`, including their spelling. Wildcard principals require
  organization conditions. The shared IAM parser/evaluator still owns policy
  grammar, operators and actual condition evaluation.
- Changing an existing account policy to organization conditions requires
  `forceUpdate=true`; later organization updates and returning to an account
  policy do not. This is caller acknowledgment, not a second migration workflow.
- A destination policy must exist. Once present, same-account identity allows
  remain sufficient even with a nonmatching principal or action in that policy.
  Matching explicit denies still reject both the original user and owned role.
  Cross-account registration still needs a resource-side grant.

`TestLogsKinesisNativeReplaySDK` replays these controls and real Kafka delivery
on memory and SQLite, including retained throttled work, target replacement,
source deletion, regional routing and source system fields. Its cross-account
workflow verifies local IAM isolation, not native cross-account conformance.
The executable also delivered Logs → Kinesis → real Python Lambda → SQS before
and after a SQLite-backed process restart.

Organization sender-role subscriptions across accounts remain explicitly
unsupported. Native same-account logical subscriptions preserve an optional
role without requiring sender `logs:PutLogEvents`; this does not establish the
service-generated cross-account contract described by AWS.

Primary contracts:
[PutDestination](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutDestination.html),
[PutDestinationPolicy](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutDestinationPolicy.html),
[destination creation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CreateDestination.html)
and [organization sender roles](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Cross-Account-Log_Subscription-Update-filter.html).

## Metric filters

Logs owns filter admission, matching, extracted values and configured dimensions.
Its consumer-defined `MetricPublisher` exposes CloudWatch's typed `Publish`
command through `Config.Metrics`; there is no second metric store or HTTP round trip.
CloudWatch owns identity, sample validation, resolution and aggregation. Accepted
source rows, ingestion facts, subscription work and metric samples commit together
in the existing memory/SQLite transaction. A metric-storage error rejects and
rolls back ingestion. The application needs `logs:PutLogEvents`, not
`cloudwatch:PutMetricData`; internal publication does not fabricate a CloudWatch
API outcome. See [CloudWatch metrics](cloudwatch.md).

Configuration retains one transformation per filter, creation time across
replacement, units, a constant or extracted numeric value, an optional default,
custom dimensions and requested system fields. Failed replacement leaves the
existing filter intact. Deletion and group removal delete configuration, not
previously published metrics. Describe uses scoped ordering by filter/group name
with expiring keyset pagination, including account-wide metric-name/namespace
selection.

The existing parsed matcher serves boolean filtering and extraction. JSON
selectors and named/positional space-delimited fields use the same parsed paths
and values rather than an independent matching language. Transformation
wildcards are rejected even though matching wildcards are supported. Missing,
compound or nonnumeric extracted values do not become zero. A matched message
with an invalid numeric value is skipped, not assigned its default. Native
defaults apply to each **nonmatching event**, not once per minute.

Samples retain the accepted event timestamp and configured unit. Custom
dimensions resolve from that event; `@aws.account`, `@aws.region` and
`@source.log` use source context. Native `@source.log` is the log group name.
Unit replacement affects later samples; a unit change does not erase earlier
periods from an unqualified metric query.

### Native metric-filter evidence

`testdata/aws/logs/metric_filters.json`, from
`scripts/aws/logs_metric_filters_probe.py`, retains 154 CLI observations
(153 AWS responses and one CLI validation error). It covers controls,
failed replacement, pagination, extraction and positive CloudWatch publication.
`testdata/aws/logs/metric_filter_extractors.json` adds 35 AWS responses for
transformation wildcards, undefined fields and system dimensions. Owned
infrastructure was cleaned up; admitted metric series remain under AWS retention.

Observed distinctions include one-based `TestMetricFilter` event numbers,
empty JSON extraction maps versus named space-field captures, five
regex-bearing metric filters per group with at most two terms per filter, and
prefix filtering ignored for account-wide metric-name/namespace selection.
Native admission permits undefined extraction fields; admission is not evidence
that such fields produce a sample.

Fixture replay compares actual positive buckets, not bounded non-observation.
AWS documents historical metric availability delays of hours; missing samples
in a finite polling run are not proof of permanent non-delivery. Targeted SDK
checks exercise both stores, failures after an actual metric append, source
rollback, retry, application IAM denial of direct CloudWatch publication,
cross-account reads, replacement/deletion and SQLite reopen. The executable CLI
also verified retained configuration/totals and Count-to-Bytes period selection.

`applyOnTransformedLogs` is retained as configuration, but transformed-event
production is not implemented; this path does not evaluate original messages
as if they were transformed. Transformer execution, native activation/visibility
cadence, combined subscription/metric regex quotas and cardinality-driven
disablement remain open.

Primary contracts:
[PutMetricFilter](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutMetricFilter.html),
[DescribeMetricFilters](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeMetricFilters.html),
[TestMetricFilter](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_TestMetricFilter.html),
[metric-filter extraction](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntaxForMetricFilters.html)
and [metric availability](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricData.html).

## Direct Firehose subscriptions

Same-account/same-Region Firehose streams are direct subscription destinations.
The existing filter, gzip envelope, preflight and retry owners call Firehose's
ordinary authorized PutRecord command under the Logs delivery role. Caller
PassRole, Logs service trust and current Firehose write permission remain real
checks. CONTROL_MESSAGE and filtered DATA_MESSAGE records reach actual S3 bytes;
configuration and accepted delivery work survive SQLite reopen.

This composition follows the official
[Firehose subscription example](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html#FirehoseExample).
SDK workflows and an executable Logs → Firehose → S3 run exercise it. They do not
establish every native Firehose-specific admission variation. Logical and
cross-account Firehose destinations remain unsupported; see
[Firehose evidence and boundaries](firehose.md).

## Remaining boundaries

Physical retention deletion is implemented; AWS deletion latency remains unmodeled.
KMS, linked accounts, other log classes,
deletion protection, entities, transformers, remaining metric-filter boundaries, query engines, exports,
logical/cross-account Firehose and organization sender-role subscriptions, and remaining Logs APIs stay open.
Cross-metric/subscription regex quotas and other destination contracts are not
established. Unsupported service paths must not become fake successful configuration.

Runtime framing currently merges stdout/stderr into one writer and flushes an
unterminated line on close or the size limit, not an idle deadline. Exact
per-stream framing, idle flushing and advanced Lambda logging need native
conformance. Docker output and the Runtime API response use independent
connections; complete output reaches Logs, but exact per-invocation tail
synchronization remains unfinished. Throttling, broad concurrent ingestion,
long-horizon propagation and uncaptured filter/regex limits remain open.

The generated API
model is `clones/aws-sdk-go-v2/codegen/sdk-codegen/aws-models/cloudwatch-logs.json`,
revision `113bc91bf12edc3af1d3aba1c70be28494d54c2a`. Primary AWS contracts and native
fixtures decide semantics; generated shapes do not establish behavioral parity.
