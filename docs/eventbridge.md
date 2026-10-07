# EventBridge buses and retained delivery

> In native capture references, `000000000000` is an anonymized account alias,
> not the AWS account originally used. See [capture privacy](behavior-references.md#publishing-sanitized-probe-captures).

EventBridge currently accepts custom events on account/region-scoped default and
custom buses, matches event-pattern rules, runs classic scheduled rules, archives
events and replays them through retained target work to SQS, SNS, real-container
Lambda, ECS tasks, CloudWatch Logs, Kinesis streams, Firehose, HTTPS API destinations
or another event bus.
The generated AWS JSON API includes
bus/rule/target controls, bus permissions, archive/replay controls, `PutEvents`,
`TestEventPattern`, Connections, API Destinations and resource tags. Source-owned ingestion and delivery samples
publish to CloudWatch and feed its alarms. This is a partial service implementation;
generated operations outside this slice return an explicit protocol error.

`PutEvents` authorizes each entry against its bus. A denied entry rejects the whole
request and rolls back admitted events and target work; malformed entries retain
AWS's per-entry results when authorization succeeds.
Malformed detail and reserved AWS sources fail. An accepted event on a nonexistent
bus receives an event ID and is dropped, matching native AWS behavior. Admission
uses the current enabled rules and captures each matching target's configuration.
Invalid rule replacements leave the existing rule intact. Rule updates and target
replacement semantics are replayed from native control-plane observations.

The pattern compiler supports typed literals, nested and dotted fields, arrays,
`$or`, numeric and CIDR conditions, existence, prefix/suffix, case-insensitive
matching, wildcard and `anything-but` operators. Native observations govern array
correlation, absent fields, duplicate paths and numeric equivalence. `TestEventPattern`
also validates the AWS event envelope. Wildcard admission follows the captured
byte-prefix complexity limit, including shared alternatives, negated sets and
`$or` branch grouping. Pattern support alone does not establish complete `PutRule`
admission parity; resource quotas and broader service settings remain separate.

Case-insensitive operators compile AWS's per-character upper/lower alternatives,
including Unicode expansions and the captured UTF-16 behavior. CIDR admission and
matching use native observations, including host-prefix rejection and lexical
address comparisons. Matching prepares each field's candidates once, then joins
their array positions; impossible fields reject before enumerating unrelated
arrays. Absence checks retain the same array scope as positive matches.

Kinesis targets use the existing selected-role assumption and a small record-writer
interface, not direct backend access. `PartitionKeyPath` selects from the original
event even when Input/InputPath/InputTransformer changes the record payload.
The native capture in `testdata/aws/eventbridge/kinesis_targets.json` establishes
JSON-encoded projection keys: string quotes are retained, missing/null becomes
`{}`, and numbers, booleans, objects and arrays use compact JSON. Without the
path, the key is the admitted event ID plus `_` and an opaque UUID suffix.
The local suffix belongs to the retained delivery; native retry-suffix stability
was not measured. Kinesis throughput errors enter existing retry/DLQ handling;
current IAM denial remains a nonretryable permission failure. Native captures
prove the eight key/payload cases, not exact AWS retry timing.

Firehose targets share a small PutRecord consumer interface with Logs producers.
Native admission requires a role and a delivery-stream ARN; delivery uses the
selected role's current `firehose:PutRecord` permission. Input/InputPath/
InputTransformer use the ordinary payload-selection path. An other-Region target
ARN is retained, but execution resolves the stream name in the rule's Region;
native east-only/west-only policies distinguish that behavior. NO_PERMISSIONS
uses the existing terminal/DLQ path. SDK replay and an executable
EventBridge → Firehose → real Lambda → S3 workflow exercise retained delivery and
permission recovery. See [Firehose evidence and boundaries](firehose.md#eventbridge-producers).

## Connections and managed credentials

Create, describe, list, update, deauthorize and delete use typed Connection
metadata on the shared memory/SQLite transaction boundary. Connection and secret
incarnations are distinct. Public metadata masks secret HTTP parameter values;
credentials exist only in the actual [Secrets Manager owner](secretsmanager.md).
No parallel Connection password or private-token table is retained.

The built-in adapter provisions and assumes
`AWSServiceRoleForAmazonEventBridgeApiDestinations` for
`apidestinations.events.amazonaws.com`. Its existing AWS-managed policy controls
the `events!connection/*` namespace and customer KMS keys. Connection ARN source
identity accompanies role use; IAM fences role deletion against retained
Connection usage. Metadata and managed-secret changes share a transaction.
Deauthorization clears public auth and, once settled, the public secret ARN, while
retaining internal ownership needed to remove credentials; reauthorization
creates a different secret incarnation.

Basic, API-key and OAuth client-credentials authorization produce real outbound
credentials. OAuth HTTPS acquisition runs outside transactions; completion checks
Connection incarnation/version. Expiry and provider 401 refresh use the current
credentials. Tokens are reacquired after restart rather than persisted as another
credential store. Private connectivity/resource associations remain explicitly
unsupported.

`ResolveConnection` remains the Step Functions HTTP consumer boundary. Its caller
needs `events:RetrieveConnectionCredentials`, `secretsmanager:DescribeSecret` and
`secretsmanager:GetSecretValue`; it does not borrow the linked role for invocation
reads. API destination delivery has a separate service-owned invocation boundary
described below. `Config.OutboundHTTP` injects the real network client used by
OAuth, API destinations and workflow HTTP requests; nil uses the standard client.

`testdata/aws/eventbridge/connections.json` and `connection_oauth_secret.json`
retain owned native lifecycle, masking, linked-role and managed-secret document
evidence with independent cleanup. `TestEventBridgeNativeConnections` and the
Step Functions HTTP replay exercise the assembled services on both stores and
across reopen. Native transitional deletion timing is not a fixed local deadline.
The executable SQLite smoke also performs authenticated HTTPS through the AWS CLI
before and after process restart.

Primary references:
[Connections](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-target-connection.html)
and the [service-linked role](https://docs.aws.amazon.com/eventbridge/latest/userguide/using-service-linked-roles.html).

## API destinations

Create, describe, list, update and delete retain scoped API destination metadata,
independent incarnation IDs, Connection references and rate admission in typed
memory/SQLC SQLite storage. Native-calibrated controls cover methods, endpoint
admission, default/explicit rates, filters, pagination, errors and Connection
state projection. Deauthorization makes referencing destinations inactive.
Deleting an active Connection clears its destination reference; deletion after
settled deauthorization retains the old reference, matching the captured native
outcomes. Recreating either name does not restore an old incarnation's authority.

Rule targets require a role with `events:InvokeApiDestination` on the destination.
The actual effect assumes that role and rechecks current IAM authority. The
destination owner then reads the current managed credentials through the
Connection's linked role and real Secrets Manager/KMS owners; it does not require
the target role to borrow Step Functions' credential-read permissions. Pending
and in-flight OAuth completion is fenced by current destination/Connection
versions and authority. A concurrent OAuth cache-refresh conflict before endpoint
invocation defers admission without consuming an HTTP attempt or losing the
original event; current mutation, incarnation and authority fences still apply.

Real HTTPS requests apply ordered, escaped wildcard path values, endpoint/target/
Connection query parameters, case-insensitive headers and JSON-object body
parameters, with Connection parameters taking precedence. Basic, API-key and
OAuth client credentials come from the existing credential owner. Service-owned
headers override caller parameters; redirects, ambient request credentials and
cookies are not forwarded. Each exchange has a five-second deadline.
Pipes [API destination enrichment](pipes.md#api-destination-enrichment) uses this
same exchange and authority boundary, decoding gzip and zlib/raw deflate successful
responses for downstream JSON delivery. A bounded reader distinguishes wire bytes
from decoded expansion and rejects damaged streams before target admission.
Rules and ordinary targets continue to discard response bytes without decoding.
Its separate native capture includes actual owned HTTPS effects; it does not
retroactively turn the earlier control-only capture below into a delivery proof.

2xx completes delivery. HTTP 401, 407, 409, 429 and 5xx, transport failures and
timeouts use the existing retained retry/age/DLQ engine; other HTTP statuses stop
retrying. Numeric and HTTP-date `Retry-After` values are minimum delays; a negative
numeric value stops retries. OAuth 401/407 refreshes credentials for the next
metered attempt rather than hiding a second endpoint request in one attempt.
Per-destination admission uses retained service-clock windows without counting a
blocked request as an HTTP attempt. This deterministic local admission is not a
claim of native burst timing or account-wide throughput quotas.

`testdata/aws/eventbridge/api-destinations.json` records owned native control,
Connection lifecycle, IAM and request-ID-correlated audit observations, including
cleanup and bounded audit non-observations. Audit projections preserve public
auth structure but redact credentials and all Connection HTTP parameter values.
The native run did **not** deliver to an HTTP receiver: no safe owned public
receiver was available. Native acceptance of a scheme-less endpoint is retained
verbatim; actual delivery requires explicit HTTPS, without inventing a native
scheme-normalization rule.

`TestEventBridgeNativeAPIDestinations` replays stable native projections on both
stores and across reopen, without pinning asynchronous propagation timing.
`TestEventBridgeAPIDestination*` exercises actual TLS bytes, authority, response
classification, rate admission, cancellation, OAuth fencing, retries and DLQs.
`scripts/aws/eventbridge_api_destinations_executable_smoke.py` launches the actual
executable with signed SDK requests, a loopback TLS receiver and SQLite; it proves
HTTP effects, a retained `Retry-After` across process restart, denial/recovery,
and [Pipes](pipes.md#iam-and-destinations) retry/acknowledgement through this owner.
The [combined deployment upgrade](../testdata/integration/cloudformation_api_destination_upgrade.json)
preserved schema-222 Connection identity and managed-secret references through
schema 224. A CloudFormation-owned rule then delivered exact header/path/query
parameters to an actual TLS receiver, and a post-restart stack update delivered
the new values. Existing Pipes/Rule work and audit history also survived; owned
controls were deleted and both controllers exited normally.
Private connectivity, resource associations, mTLS and native delivery-wire parity
remain outside this supported boundary.

Primary references:
[API destinations and retry behavior](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html),
[HTTP parameters](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_HttpParameters.html)
and [IAM actions/resources](https://docs.aws.amazon.com/service-authorization/latest/reference/list_events.html).

## Target discovery

[`ListRuleNamesByTarget`](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_ListRuleNamesByTarget.html)
reads existing target configuration through the typed
repository. It returns each matching rule once, including disabled rules and
configuration pointing at a deleted destination. Replacing a target ARN or
removing the last matching target changes membership; removing a duplicate does
not. Bus name/ARN forms resolve to the same scoped collection. Memory and SQLC
SQLite query the same retained metadata without a discovery table or a second
index.

Authorization checks `rule/<bus>/*` (`rule/*` for the default bus), not the
event-bus ARN or every returned rule. A rule-namespace resource-policy grant can
authorize discovery without an identity allow. Individual rule and destination
read permissions do not filter membership. Encrypted-bus discovery does not
require `kms:Decrypt`; it does not read encrypted rule patterns or target inputs.

Pages use current membership, preserve distinct rule names and bind continuation
to the resolved bus and target ARN. Changing the page limit or using the same
bus's ARN is accepted. Invalid target/token/limit inputs return protocol errors.
The API documentation's `Limit: 0` / empty-token example is not accepted by AWS.
`testdata/aws/eventbridge/target_lookup.json` retains native mutation, scope,
complete pagination and signed malformed-input observations. Its small lexical
orders do not establish a universal ordering or propagation-time guarantee;
token expiration was not measured. A single cross-bus-token HTTP 500 remains
evidence, not a deterministic rejection contract.

Lookup audits use the existing management-event journal and configured
CloudTrail/EventBridge consumers. They are read-only, so default-bus rules need
`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` to receive them.
`testdata/aws/eventbridge/target_lookup_authority.json` retains native
rule-namespace/session/resource-policy and KMS controls plus request-correlated
CloudTrail records. Access-denied wire responses retain `AccessDeniedException`;
the audit uses `AccessDenied`, null request/response documents and no API version.
A missing bus is `ResourceNotFoundException` on the wire but `UnknownError` in
CloudTrail. Invalid-token audits retain the submitted parameters and API version.
An unmatched bounded native validation sample is not evidence of nonlogging.

## Customer-managed bus encryption

Create/update/reset controls resolve customer KMS identifiers through the existing
audited KMS commands. Caller admission uses `DescribeKey` and, when installing a
key, `GenerateDataKeyWithoutPlaintext`; service processing uses
`events.amazonaws.com` with the bus ARN as source and encryption context.
Rule-pattern and target-configuration reads/mutations decrypt as the caller,
separately from asynchronous service authorization. Metadata-only target
discovery does not unwrap the configuration key.

Customer event detail, rule patterns, target input/transformers and destination
configuration are ciphertext in retained EventBridge rows. Routing identities
and retry state remain typed metadata. Accepted work retains its original wrapped
keys and encrypted configuration snapshots through key replacement and SQLite
reopen. Key changes migrate current configuration atomically, after KMS work
outside the repository transaction. Native API audit records still contain
submitted rule/target fields; encryption does not replace the authoritative audit
projection with blanket redaction.

AWS service-origin payloads are exempt from the bus's customer key. Their source
transaction copies encrypted rule/target snapshots without calling KMS; later
matching and delivery decrypt outside that transaction. A denied destination key
therefore does not roll back an already successful source API.

An encryption-failure bus DLQ receives one `aws.events` / `Encrypted Events`
record, not one ordinary target DLQ message per rule. Its encrypted payload uses
the AWS Encryption SDK v2 committed AES-GCM envelope. An executable/SQLite smoke
delivered a real SQS target message with `AWSTraceHeader`, disabled the key,
recovered the resulting DLQ payload through AWS Encryption SDK Python 4.0.7 and
the local KMS API, then restarted and verified cold failure and recovery.

`bus_kms_control.json` retains native control, denial, reuse and cleanup
observations; `bus_kms_envelope.json` supplies a locally re-sealed, account-anonymized
decryption vector with an explicit local wrapped-key identifier. It is a derivative
regression fixture, not unchanged AWS ciphertext.
Native warm encryption-key reuse was observed, but not a fleet-wide expiry
guarantee. The local cache uses thirty service seconds, is bounded to 1024 buses,
invalidates on key changes/reset/delete and reopens cold. Caller authorization
and delivery decryption are not cached. Native configuration transitions can
temporarily reject concurrent updates; the local migration is synchronous and
does not reproduce that timing. Both owned native KMS keys were independently
observed in seven-day `PendingDeletion`, not reported as immediately absent.

Primary contracts:
[customer-managed bus encryption](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-encryption-event-bus-cmkey.html)
and [encrypted-event DLQs](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-encryption-event-bus-dlq.html).

## Classic scheduled rules

`PutRule` accepts an event pattern, a schedule, or both. A nonempty trigger is
required. Omitted pattern, schedule and description fields clear their previous
values; explicit empty fields remain present in Describe/List responses when
another valid trigger exists. Tags retain their existing update semantics.
Any supplied schedule field, including an empty string, is rejected on a custom
bus. The all-management-events state accepts pattern-only rules on default and
custom buses, including an explicitly empty schedule on the default bus; a
nonempty schedule cannot use that state.

Classic rules use UTC cron or positive integer minute/hour/day rates, not the
separate EventBridge Scheduler service. `internal/awsschedule` shares calendar
selection with Organizations Backup policies while preserving each service's
admission dialect. Cron supports lists, wrapping ranges, increments, nearest
weekdays, last-day/weekday selectors and ordinal weekdays. Native admission also
accepts numeric/name suffixes, zero/oversized increments and years outside the
documented 1970–2199 range, up to the captured int32 boundary. Sparse year
progressions avoid materializing that range; impossible dates terminate without
searching indefinitely. Backup retains its separately captured whitespace,
field-count, year and increment restrictions.

Each enabled scheduled rule retains its next occurrence. Replacing an enabled
rule with the same expression preserves its cadence; a new/changed schedule or
disabled-to-enabled transition anchors a new recurrence. Disabling, deleting or
clearing the schedule removes pending source work. Attaching or removing targets
does not re-anchor the rule.

The local rate anchor is the current whole service second. Cron selects the next
matching minute strictly after the command time. These are deterministic logical
deadlines, not measured AWS first-invocation offsets or delivery-jitter promises.
Bounded draining consumes overdue occurrences in deadline order, preserving each
scheduled envelope time while using current processing time for acceptance and
target retry age. Current rules, targets and authority govern admission/delivery;
this does not reconstruct historical target state or claim AWS downtime replay.

A scheduled occurrence enters the default bus as `aws.events` / `Scheduled Event`,
with empty detail and the originating rule ARN in `resources`. Its own rule is
selected once independently of its event pattern; other matching bus rules also
receive it. A targetless rule still produces bus-visible events. Self-matching
does not deterministically select the same rule twice. This selection property
is not an exactly-once delivery guarantee.

The occurrence, selected target work, next deadline and acceptance journal fact
commit together. Existing adapters perform current IAM checks and destination
effects outside that transaction. No public `PutEvents` call is fabricated.
See AWS's [scheduled-rule contract](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html)
and [cron/rate reference](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html).

## Archives and replay

Archives retain matching events independently of the accepted-event history.
Each archive owns a native `Events-Archive-<name>` managed rule whose pattern
excludes events containing `replay-name`. Force-removing its actual target
disables the archive; an update repairs the rule/target and enables it again.
Managed ownership survives archive-creation failures that leave a targetless rule.
Deleting an archive removes its entries and managed rule atomically, but not
previous replay history. Recreation allocates a new incarnation; pending work
cannot write into or replay from the replacement.

Create authorizes both the archive and source bus. StartReplay independently
authorizes the replay, archive and destination bus; permission on one resource
does not substitute for the others. Updates authorize the archive. Customer
description, pattern and retention omission/replacement, managed controls,
source restrictions and filter-bound pagination follow the native fixtures.

Archive ingestion stores the event, increments counters and completes its
selected internal target work together. Retention uses the original bus
ingestion instant, not the customer event timestamp; zero days is indefinite.
Changing retention recomputes retained entry deadlines, and expiration deletes
payloads and decrements counters atomically. The native one-day archive replayed
a newly ingested event whose customer timestamp was two days old. That proves
event-age filtering is wrong, not the exact instant of AWS's eventual eviction.
Local `SizeBytes` counts event-envelope bytes; AWS's physical encoding and delayed
counter refresh are not reproduced.

Replay retains `STARTING`, `RUNNING`, `CANCELLING` and terminal states with a
versioned cursor. Only the source bus is a valid destination. Selected rules use
their current patterns, enablement and targets; an empty filter selects all.
Native timestamps are whole seconds. Delivery uses the half-open requested
interval `[start,end)`, while progress scans complete minute buckets and reports
the last scanned bucket, including excluded events. Replayed envelopes receive
fresh IDs and `replay-name`, preserving original time, account, region, resources
and detail. All matching targets share that replay admission's ID. Replay events
do not re-enter archives.

Cursor advancement, new admission, target work and journal publication share a
transaction. Cancellation fences future admissions, not target work already
accepted. Source deletion during `STARTING` is allowed; execution then fails with
`Archive resource not found.` rather than retaining an invented archive lease.
Local startup is one service minute, cancellation one service second, and terminal
history expires 90 days after completion. These are deterministic scheduling
choices, not AWS latency or exact history-deletion promises. Forwarding after
replay begins with fresh hop state; native multi-hop replay limits remain unmeasured.

### Customer-managed archive keys

The built-in adapter uses real KMS commands and IAM/key-policy evaluation.
Customer-key patterns and archived event payloads use AES-GCM with wrapped KMS
data keys. Caller forward-access admission requires DescribeKey and GenerateDataKey;
the service independently requires DescribeKey, GenerateDataKey and Decrypt.
Migration additionally enforces service ReEncryptFrom on the source and
ReEncryptTo on a customer destination. Ingress admission includes
`aws:events:rule:arn` for the managed rule; retained storage and native ReEncrypt
use only `aws:events:event-bus:arn`. The `kms:EncryptionContext:` prefix belongs
in the IAM condition, not the context map.
Native caller records additionally contain an AWS Encryption SDK public-key
context; that framing/context and cache behavior are not reproduced by local
AES-GCM envelopes. Public key identifier spelling remains the supplied UUID, ARN
or alias.

External KMS calls never run inside an EventBridge transaction. Configuration
versions fence their subsequent archive mutation. Service DescribeKey-denied
creation retains the observed targetless managed rule. Disabled or inaccessible
keys prevent decryption/replay; DescribeArchive still returns unencrypted
metadata and omits an unavailable pattern. No native KMS cache lifetime is claimed.
Audit records come from the actual KMS commands, without asserting that the
emulator's entire call sequence equals AWS's internal implementation.

Replacing a resolved key or explicitly resetting it with an empty identifier
returns `UPDATING` and schedules migration of retained payloads. Omitting the key
preserves it; changing only the identifier spelling of the same resolved key does
not migrate. Customer-key migration rewraps the existing data key without copying
or re-encrypting the event body. Reset removes customer-key wrapping under
ReEncryptFrom authority into the existing service-owned storage representation;
it does not invent an AWS-internal KMS key in the customer's catalog. Its KMS
audit record represents the source-side operation, not AWS's internal destination.
Archive and event-bus keys remain independent.

Archive-owned versions fence KMS preparation and commit, including ingestion and
replay already selected when a key changes. A retained-entry encryption generation
lets the scheduler select only remaining work, including late event timestamps.
Deletion/recreation cannot inherit pending work from an old incarnation.
Schema 137 preserves preexisting entries' authenticated managed-rule context;
new retained entries and migrated entries use the measured bus-only storage
context. Migration, failed state, and explicit retries survive SQLite reopen.

The 2026-09-22 captures in `archive_key_transitions.json`,
`archive_key_transition_denials.json`, `archive_key_transition_recovery.json`,
and `archive_key_transitions_audit.json` record successful replacement/reset,
real service ReEncrypt calls, old-key revocation, and retained replay observations.
An unconditional source ReEncryptFrom denial produces `UPDATE_FAILED`, rolls the
public key identifier back to the previous key, and retains events. The local
replacement keeps its newly prepared pattern encrypted under the proposed
destination. Binding reads/updates to the restored configured key reproduces the
native unavailable pattern and omitted-pattern validation failure. Reset keeps
its pattern readable. Restoring
key permissions alone did not clear the observed failed state; explicitly retrying
with the key and pattern succeeded. Native replays during the failed transition
were accepted and completed, rather than being rejected merely for archive state.
After recovery and disabling the old key, both the replacement and reset replays
delivered the original pre-update event and an event ingested during the
transition. These are received SQS envelopes, not an inference from a successful
UpdateArchive or terminal replay status.

Focused SDK replay covers both repositories. An actual executable smoke retained
an explicit retry across process restart, then replayed both historical phases to
SQS after replacement and reset with the respective old customer key disabled.
The destination bus used its own independent customer key.

Local migration starts after one service second and processes one retained
envelope per scheduler step; these are deterministic scheduling choices, not AWS
latency or counter-refresh promises. The captures bound rather than establish
native cache expiry, partial-file migration ordering, destination-ReEncryptTo
denial timing, or transition-specific caller session-policy precedence. Existing
`archive_keys.json` retains the caller/service admission negatives. Both probes
verified account `000000000000` and the expected `Delegated` caller before
mutation. Their six archives, two event buses and two SQS collectors were deleted
and absence-checked. The four owned KMS keys are `PendingDeletion` with seven-day
windows ending September 29, 2026; this is not physical deletion. Replay history
remains subject to normal service retention. No standing identities or
Organization configuration were changed.

Primary references are the AWS archive encryption guide and
[UpdateArchive](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_UpdateArchive.html).
See [archive encryption](https://docs.aws.amazon.com/eventbridge/latest/userguide/encryption-archives.html)
and [replay destination/time selection](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-replay-archived-event.html).

## Target command boundaries

Rules support up to five implemented targets in the same partition. SQS, SNS,
Lambda, ECS and Logs targets remain regional; event-bus targets can cross regions.
SQS/SNS/Lambda targets support the complete event envelope, static JSON `Input`,
`InputPath` or `InputTransformer`, retry limits and a standard SQS dead-letter
queue. ECS, Logs and buses have the restrictions below. FIFO SQS targets carry
`MessageGroupId` and require content-based deduplication.

Input projections implement the captured EventBridge path grammar, typed template
substitution, missing variables, quoted text, multiline output and reserved rule,
event and ingestion-time variables. Admission validates definitions; a template
that produces invalid JSON for an actual event creates a failed target delivery.
It does not reject `PutEvents`. The attempted body reaches the DLQ with
`INVALID_JSON` and no retry-exhaustion attributes. Target replacement removes
omitted input modes, while already admitted deliveries retain their selected body.
Empty static input and a missing standalone placeholder were accepted by AWS but
had no observed target or DLQ outcome within 90 seconds. The capture makes no
terminal-delivery claim for those two cases.

`internal/integrations.EventBridgeTargets` implements EventBridge's small delivery
interface through SQS's typed send command, SNS publication, Lambda's asynchronous
acceptance, ECS's audited `RunTask`, Logs ingestion and typed bus-forwarding commands. It establishes the
selected service principal or execution-role session, then runs the target's
current authorization and resource behavior. It does not authenticate as the
original `PutEvents` caller and owns no retry queue. Without a target role, native
SQS captures verify source ARN/account and service-principal conditions,
including the observed `aws:PrincipalType` value `User`.
Lambda acceptance, function-policy enforcement, its separate handler retry queue
and real EventBridge → Lambda → boto3 → SQS evidence are documented in
[Lambda](lambda.md#resource-policies-and-asynchronous-delivery). Lambda target
`SqsParameters` are retained but ignored during invocation, as captured from AWS.
SNS acceptance starts SNS-owned filtering, signing and subscriber delivery;
EventBridge does not insert subscriber queue messages itself. [SNS](sns.md)
owns downstream outcomes and its native evidence boundaries.
Without a target role, native SNS topic policies also receive the source rule ARN and account, but not
legacy `aws:SourceOwner`. SNS `AuthorizationError` and `KMSDisabled` failures
become EventBridge `NO_PERMISSIONS` DLQs; successful publication starts SNS's
independent work. Native `encryption_event_source_cache.json` verifies a warm rule
still delivering while a second rule and fresh-topic control produce disabled-key
DLQs, followed by repaired delivery. Unlike SQS's captured reuse below, SNS
retains source-rule separation in its publication cache.

Default SQS-managed encryption is exercised by native delivery captures. Customer
managed KMS targets use SQS's KMS command path, including producer data-key reuse;
the cold KMS request carries the EventBridge service principal and source rule ARN.
Native SQS reuses an authorized service data key across rules on the same queue
within its reuse period, so changing only the source rule does not establish a new
KMS requester. Current queue authorization still applies to each send. The
encrypted-delivery capture distinguishes cold permission checks from warm reuse.
Bus encryption and encrypted-DLQ conformance are separate, unfinished contracts. See
[SQS key management](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-key-management.html)
for the service-source key policy and reuse requirements.

### Execution roles

`PutRule.RoleArn` is retained and returned by describe/list operations. Admission
requires `iam:PassRole` and current EventBridge trust; omission clears the field.
It is not a fallback execution role for SQS, SNS, Lambda, ECS or event-bus targets.
`PutTargets` independently authorizes each supplied role with
`iam:PassedToService=events.amazonaws.com` and `iam:AssociatedResourceArn` equal to
the **rule ARN**. SQS/SNS/Lambda/ECS target admission does not require the role to
exist or trust EventBridge; invocation resolves that authority.

Selected work retains its target role even after target replacement or rule
deletion. Current role deletion, trust, identity policies, boundaries and resource
policies still govern execution. Role omission clears SQS/SNS/Lambda target roles;
ECS and bus targets require an explicit role, so omission rejects the update and
preserves the previous target. Explicit replacement clears other omitted optional fields.
Logs rejects `RoleArn`.

The shared IAM authority evaluates trust, issues a one-hour service-role session
and records successful STS issuance in one transaction. Trust receives the source
rule ARN and its bus's account, not the publishing account or rule creator.
Credentials belong to the resolved role account: a caller can create a rule on
another account's permitted bus and pass its own role for a bus target.
SQS/SNS role delivery has `PrincipalType=AssumedRole`, the IAM role
`PrincipalArn`, and `PrincipalIsAWSService=false`; source ARN/account and
`PrincipalServiceName` are absent. Lambda additionally receives the trusted
rule `aws:SourceArn` through its private invocation boundary, not through
caller-supplied event detail or a forged service identity.

An identity-policy deny is not rescued by a resource-policy grant to the
EventBridge service principal. Failed SQS/SNS/Lambda/ECS role assumption yields
`FAILED_TO_ASSUME_ROLE`; a bus-target role failure yields `NO_PERMISSIONS`.
Diagnostic text preserves the current authorization failure rather than hiding
the actor behind a generic target error. Native immediate post-mutation successes
and later denials are retained as propagation evidence; local attempts evaluate
current authority rather than inventing a credential-cache TTL.

### ECS tasks

An ECS target names a cluster ARN and requires `EcsParameters.TaskDefinitionArn`
and `RoleArn`. The definition must share the cluster's account and region.
Native admission accepts a family ARN without a revision and numeric revisions
including `0` and `01`; ECS resolves or rejects the identifier at invocation.
Omitted task count becomes one, and managed-tag/execute-command flags become
false in retained target readback. Static `Input` and `InputTransformer` produce
ECS task overrides; `InputPath` is rejected. Unknown override-object fields are
ignored by modeled decoding, rather than interpreted as a new event payload API.

The selected generated ECS parameters are copied into retained target/delivery
records, with typed SQLC storage. The adapter invokes the real ECS command with
the delivery ID as its client token and `events-rule/<rule-name>` as `startedBy`.
Current invocation-role policy must permit `ecs:RunTask`, applicable
`ecs:TagResource` tag-on-create authority and `iam:PassRole` for task/execution
roles. ECS owns runtime admission, task intent, metadata credentials, ENIs and
actual containers; EventBridge owns neither a second task store nor a task loop.

Successful `RunTask` acceptance completes EventBridge delivery; a later container
exit is an ECS outcome, not an EventBridge retry. Native captures distinguish
`NO_PERMISSIONS`, `FAILED_TO_ASSUME_ROLE` and invalid-override `INVALID_PARAMETER`
dead letters, retaining the transformed body without retry-exhaustion attributes
for those nonretryable cases. Public CloudTrail records come from the ECS command,
including assumed-role identity and source-owned request redaction.

`testdata/aws/eventbridge/ecs_targets.json` retains admission, real Fargate
overrides/tags, CloudTrail and SQS DLQ observations. SDK replay covers atomic
admission, current-policy changes, invalid overrides and reopen on both stores.
Actual CLI/SQLite delivery launched three Docker tasks: static and transformed
commands exited zero and published distinct task-role-authenticated SQS messages;
an unknown-object input used the definition's command and exited 17. Unsupported
ECS runtime settings remain real command errors, not simulated task success.
See [ECS execution](ecs.md) and AWS's
[ECS target parameters](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_EcsParameters.html).

### Event-bus forwarding

Bus targets require `RoleArn` even within the same account. They reject all input
projection modes, `RetryPolicy` and self-targeting; a standard SQS DLQ is allowed.
Region membership comes from the generated SDK partition/region catalogue.
Forwarded authorization sets `events:eventBusInvocation=true` and preserves the
original `events:source` and `events:detail-type`. Direct `PutEvents` sets the flag
false. Cross-account delivery also requires the destination bus's resource grant.

Same-region forwarding preserves envelope ID, time, original account/region,
resources and detail. A regional hop replaces envelope ID and time while retaining
the original account and region. Every local admission nevertheless gets a
distinct causal ID; native wire identity is not reused as a repository key.
The captured graph boundaries are:

- A second same-region bus hop fails with `THIRD_ACCOUNT_HOP_DETECTED`, including
  graphs wholly inside one account.
- A local hop followed by a regional hop succeeds. A regional hop followed by
  a local hop succeeds, including a different destination account.
- A second regional hop fails with `THIRD_REGION_HOP_DETECTED`, including a return
  to the original region/account through a fresh bus.

An authorized nonexistent same-account destination is acknowledged and dropped,
not created or converted into `NO_RESOURCE`. The missing-bus capture includes
665.978 seconds of source witnesses, real/denied controls and native invocation
counters. Missing samples are not measured zeros. The denied-role control also
published `SuccessfulInvocationAttempts`, so that counter alone is not delivery
proof, and the bounded observations do not establish universal future retry
behavior. The later [metric captures](#cloudwatch-metrics) distinguish bus
forwarding from its SQS dead-letter delivery.

### CloudWatch Logs targets

Logs targets name a log group, not a log stream. Native `PutTargets` rejects
`RoleArn`, static `Input` and `InputPath`; `InputTransformer` is accepted. The
default body is the complete event envelope with whole-second UTC `time`, used
as the Logs timestamp. A transformer uses a timestamp/message object: the
timestamp selects the event time and the string becomes the actual log message.
Missing timestamp was admitted in the capture but not exercised at delivery;
its exact native runtime diagnostic remains unverified.

The Logs service owns applicable resource-policy selection and IAM evaluation,
not EventBridge. ACCOUNT and RESOURCE allows combine, but explicit deny wins
across both scopes. Failure reaches the existing retained SQS DLQ path with the
native `NO_PERMISSIONS` code. Cross-account Logs targets return an explicit
unsupported error; exact stream allocation and delivery batching remain open.

`logs_destination.json` and `logs_policy_precedence.json` retain native default,
transformed, revoked and conflicting-policy deliveries with confirmed cleanup.
SDK replay uses those inputs and observed messages on memory/SQLite. Revocation
follows native delete-before-publication ordering: the automatic local worker can
legally finish an already admitted delivery before a later policy update.
Primary contracts are [resource-based permissions](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-resource-based.html)
and [input transformation](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html).

## Trace metadata

`PutEvents` selects an entry's `TraceHeader` before the HTTP `X-Amzn-Trace-Id`.
Entry presence wins even when empty or malformed: invalid selected metadata is
discarded without rejecting the event or falling back to the HTTP header.
Native component normalization retains valid roots, parents and sampling fields;
an unsampled header without a valid root gets one root at admission, shared by
its target and DLQ deliveries.

The retained header is separate from customer JSON, matching and journal causal
IDs. It survives live bus forwarding, retries and SQLite reopen. SQS targets and
DLQs receive `AWSTraceHeader`; asynchronous Lambda acceptance retains it through
execution and exposes producer-owned components to the real runtime. Archives
retain the customer envelope rather than this metadata, so replay omits the
original trace. This is propagation, not an X-Ray service or fabricated spans,
Lambda `Lineage`, or general OpenTelemetry export.

`testdata/aws/eventbridge/trace.json` retains native admission/normalization,
actual target/DLQ receipts, Python runtime observations, same-region forwarding
and archive replay. SDK scenarios cover memory/SQLite, pending delivery reopen,
retry retention and real warm Lambda invocations. Native cross-region forwarding
and retry timing are not established by that capture.

## CloudWatch metrics

EventBridge owns `AWS/Events` observations; CloudWatch owns their storage,
aggregation and alarm evaluation. `PutEvents` records one call, outcome, logical
request-size and latency sample per admitted request, not one sample per entry.
Entry counts retain each request's batch size and failed-entry count. HTTP 200
with every entry rejected is still a successful request. Captured empty/overlarge
batches and session-policy rejection instead produce call/failure/size samples,
without entry or latency samples. A missing destination bus is acknowledged,
not counted as a failed entry.

Logical size counts UTF-8 source, detail type, detail and resource bytes, plus
14 bytes for an explicit event time; bus names and trace headers do not add size.
Rejected shape binding uses the generated model without dispatching an invalid
command or placing unvalidated input in the API journal. The historical metric
aggregate windows stop before their retained Unicode/trace request; trace
propagation has separate native evidence and replay coverage above.

`MatchedEvents` counts a matching event once globally and once under its
Source-only dimension, plus once for each matching rule. `TriggeredRules`
retains one global sample whose value is the matching rule count. Custom-rule
series use `EventBusName` plus `RuleName`; default rules use only `RuleName`.
There is no invented bus-only series. `InvocationsCreated` is dimensionless
and retains one sample per created target invocation.

Legacy trigger/invocation/failure/DLQ counters preserve native zero minima and
unavailable percentiles through statistic sets; modern attempt/success counters
retain raw unit samples. Latencies use the native metric names
`IngestionToInvocationStartLatency`, `IngestionToInvocationCompleteLatency` and
`IngestionToInvocationSuccessLatency`, including the capital `To`. They measure
service time from current admission, not the original age of replayed archives.
Manual-clock replay compares sample counts and units; it does not reproduce
AWS's wall-clock latency values.

Successful event-bus forwarding emits legacy invocations but no modern attempt,
success or latency samples. A bus target's SQS DLQ delivery is the modern
measured attempt: successful DLQ delivery produces a successful attempt; denied
DLQ delivery produces an attempt and completion latency without success.
Without a DLQ, the captured hop failure has no modern samples. An ordinary SQS
target failure instead measures the target attempt, not a second DLQ attempt.
Hop failures use `FailedInvocations`, not `DeadLetterInvocations`.

`error_metrics.json` extends that boundary with cold, disabled customer-key SQS
targets, a missing SQS target, an unauthorized DLQ and a successful SQS control.
A disabled SQS key produces `NO_RESOURCE`, not `ERROR_FROM_TARGET`. Retry
allowances of zero and one both terminate immediately: the delivered diagnostic
is present, while `RETRY_ATTEMPTS` and `EXHAUSTED_RETRY_CONDITION` are absent.
These are nonretryable failures, not retry exhaustion.

Each failed target contributes one `InvocationAttempts`, one `Invocations` and
one `FailedInvocations`. Successful DLQ delivery adds `InvocationsSentToDlq`, not
another target attempt or `SuccessfulInvocationAttempts`. DLQ denial instead
adds `InvocationsFailedToBeSentToDlq`. The successful control has one successful
attempt. Rule-scoped statistics retain custom-bus dimensions, legacy zero minima
and first-attempt latency sample ownership. Correlated queue receipts and bounded
repeated CloudWatch reads establish these cases; an empty series in the capture
is not a promise of permanent absence from AWS's best-effort exporter.

The memory/SQLite SDK replay and an actual executable restart both preserve
these terminal outcomes after deleting the source rules and bus. The CLI smoke
checked native target/DLQ bodies and all 67 metric queries twice across further
service-time advances; focused race checks cover the same retained transition.

Pending weighted samples commit with their source transition. After their minute
completes, a retained job publishes them through CloudWatch's typed command and
removes them in the same transaction. Deleting the rule or bus does not erase
these observations. Restart and large manual-time advances preserve their
original timestamps; the public `PutMetricData` admission-age window is not
reapplied to retained service work. Native exporter lag/minute placement,
throttling/quotas, retry-exhaustion metrics, recovery after an actual retried
attempt and other target error families remain open. The terminal-key capture
does not establish native backoff or jitter.
The primary reference is [EventBridge monitoring](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-monitoring.html).

## Transactions, scheduling and causality

Admission commits the accepted event, selected target input, delivery intents and
typed `eventbridge_accepted_v1` journal row together. The shared memory transaction
domain and SQLite transaction both include related authorization and journal work.
SQLite migrations 21–23 store service-owned typed bus/rule/target/event/delivery
state, nullable input modes, named transformer paths and bus principal bindings.
Migrations 60–61 retain selected rule/target/delivery roles, original wire
identity/region, hop state and the journal's wire event ID. Older accepted events
backfill wire identity from their original admission ID and region. Customer
detail remains JSON payload. Migration 62 adds optional rule-field presence and
indexed whole-second schedule deadlines. Migration 63 adds typed archive metadata,
encrypted/raw event payloads, replay cursors/filters and incarnation routing.
Expiration deadlines use integer seconds/nanoseconds, preserving large retention
values without duration overflow. Migration 64 retains scoped pending metric
groups and weighted samples without bus/rule foreign keys. A rejected transaction
publishes no event or work; failed-request metric observations commit separately.

The shared scheduler reads committed deadlines, invokes the target outside the
transaction, and commits the outcome against the retained delivery version.
Retries use the service clock and deterministic jitter derived from retained
delivery identity; configuration defaults to 24 hours and 185 retries. Restarting
SQLite retains pending work and deadlines. Terminal failures send the attempted
target body to the configured DLQ with AWS delivery-error attributes. Immediate
permission denial omits retry-exhaustion attributes, as native AWS does. Exact AWS
backoff distributions and the full target/KMS error classification remain open.

The typed target request carries the retained delivery and accepted event, rather
than copying their fields through another command envelope. SQS commits its
message and `sqs_message_accepted_v1` row together, with `parent_event_id` linking
to the local EventBridge admission. Role-based target commands and Lambda
acceptance have distinct request IDs while retaining that parent. Forwarding
creates another admission, not a synthetic public `PutEvents` audit call.
A crash after target acceptance but before EventBridge records success can
redeliver; these independent effects do not claim exactly-once delivery.
Accepted-event and terminal-delivery retention remain unbounded.

The [shared journal](event-journal.md) is authoritative for producer ownership and
causal inspection. Configured [CloudTrail](cloudtrail.md) selectors now admit
eligible management/data API records to the default bus. Ordinary history
availability alone does not publish them. Read-only management events require
`ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`; ordinary enabled rules accept data
reads. The shared native detail retains the source request/event IDs while the
envelope receives a distinct EventBridge ID. CloudWatch metrics and Logs remain separate consumers
with AWS counting, publication and log-ingestion contracts, not aliases for the
journal or EventBridge event envelopes.
CloudWatch alarm-owned configuration/state events instead enter the default bus
through the same service publisher without requiring a trail. They commit with
the alarm transition and retain their own native document and causal origin;
they are not fabricated CloudTrail API calls. See [alarms](cloudwatch.md#alarms).

## Bus permissions

`PutPermission` shorthand upserts one statement ID; a full `Policy` replaces the
document. `RemovePermission` removes one statement or the whole policy. Full
policies use the shared IAM parser, evaluator and immutable principal bindings.
Deleting and recreating a role does not transfer its grant. Resubmitting an
unchanged policy preserves its bindings and modification time; removing and
re-adding the statement resolves the current role. Describe/list APIs render
current ARNs or deleted principal IDs inside the resource transaction.

Bus policies admit 15 EventBridge actions, covering event ingestion, bus
description, rule and target management, and resource tags. Native fixtures test
all 60 actions in the IAM authorization catalog; the remaining actions are invalid
in this policy surface even when IAM identity policies support them. Wildcards
must match an admitted action. Permission administration and bus deletion use
caller IAM authorization; an accepted wildcard bus-policy deny does not govern
those operations, as fresh native probes confirm.

Bus policies participate in ingestion and rule authorization alongside caller IAM
and Organizations restrictions. `events:source`, `events:detail-type` and
`events:eventBusInvocation` distinguish direct and forwarded event ingestion. Stored rule ownership
supplies `events:creatorAccount`; creation uses the authenticated caller's account.
Fresh isolated native captures verify strict equality on creation, including denial
when the policy requires a different creator. Cross-account
`PutTargets` permits only EventBus targets in AWS, so foreign callers cannot
register SQS/SNS/Lambda/Logs targets. Native foreign-created-rule fixtures verify
that role ownership, creator ownership and the source bus account remain distinct.

The default policy quota is 10,240 normalized bytes. The native probe account has
an applied quota of 30,720; its exact boundary observations are recorded with that
account setting and do not change the emulator default. Full policies validate
account principals against the authenticated bootstrap account and known IAM
account scopes. Shorthand accepts syntactic account IDs without an existence check,
matching AWS's different admission rules.

CloudFormation EventBus and EventBusPolicy ownership is private native metadata,
not resource tags or policy presentation. Each independently managed statement
has a scoped Sid/incarnation claim stored atomically with its policy in memory
or schema 391's service-owned SQLite rows. Public tag mutation and Describe/List
do not create, transfer or revoke that authority; legacy public markers are not
backfilled. Same-token admission/recovery and every mutation still check current
native IAM. Authorized ordinary in-place `PutPermission`, including complete
policy replacement, preserves the exact claim for each surviving Sid. Removing
a Sid through a single-statement removal, whole-policy removal or complete
policy replacement clears its claim: recreating the same Sid through the native
API leaves an unclaimed replacement that stale stack cleanup cannot delete.
CloudFormation and Cloud Control creation retain the admitted physical ID when
a native permission reply is lost, while still returning the original command
error. Recovery rechecks current native IAM and the private scoped claim;
same-token replay preserves an unchanged policy's incarnation and modification
time.

An inline EventBus policy cannot modify or remove independently claimed
statements. Native configuration and tag transactions fence the pending inline
policy against those private claims before their writes; unrelated bus updates,
including DLQ removal and configuration changes, retain both the policy and
its independent statement claims. Replacing or removing the whole inline policy
requires that its independently owned statements have first been removed by
their individual owners. These are controller ownership boundaries, not extra
restrictions on authorized ordinary native permission administration.

CloudFormation and Cloud Control `AWS::Events::Rule` admission stores a private
rule incarnation claim atomically with the new native rule row, in memory or
schema 392's typed SQLite column. Create never claims an existing unclaimed or
foreign rule, including one carrying copied legacy `stackd:cloudformation:*`
tags; rule tags are customer metadata and are neither emitted as markers nor
backfilled. A lost native rule reply retains the admitted physical ID and returns
the original command error; replay resumes native target reconciliation.
Lost-reply recovery and every controller update, state change,
target/tag change and deletion check current native IAM and then the exact
scoped claim inside the same native transaction. Authorized ordinary native
rule, state, target and tag changes preserve the claim; deleting the rule
clears it, so a same-name native recreation is unclaimed and a stale stack's
target or rule transaction cannot mutate it. This covers rule ownership only,
not broader EventBridge CloudFormation parity.

## Evidence and remaining workflows

`testdata/aws/eventbridge/patterns.json` contains native grammar, matching and
envelope observations. `control_plane.json` captures owned bus/rule/target and
event-admission behavior. `delivery.json` and `principal_types.json` capture native
EventBridge-to-SQS delivery or permission-denied DLQ outcomes. Fixture replay uses
actual SDK operations through the shared `internal/awstest.CallSDK` helper; service
tests cover transactional rollback, captured target input and retained delivery
recovery across memory and SQLite. These cases are evidence for their recorded
boundaries, not proof of full service parity.

`inputs.json` records 94 input scenarios and four same-target updates: 62 observed
target/DLQ bodies, 30 admission rejections and two bounded unobserved outcomes.
Fixture tests cover generated API constraints, semantic admission and actual SQS
delivery on memory and SQLite. Recovery tests retain projections across target
changes, rule deletion, service-time advances and retries. `permissions.json`
records policy administration, account/role authorization, principal lifetime and
policy-language admission. The probes delete their uniquely owned resources.

`testdata/aws/sns/eventbridge.json` records five topic policies: three actual
signed SNS-to-SQS notifications and two permission-denied EventBridge DLQs.
Replay compares the event body, subscriber envelope, source context and fixed DLQ
attributes through actual SDK commands on both stores. Native SNS signatures were
also checked. Dynamic SDK request identifiers are not pinned as error wording.

`target_roles.json` retains native role admission, PassRole condition keys,
trust/identity/resource-policy decisions, Lambda source context, omission and
mutation outcomes. Replay uses real SQS/SNS commands and Docker Lambda execution
on memory/SQLite; selected authority survives source mutation and database reopen.
`bus_forwarding.json` retains same-region, cross-account, regional and mixed
graphs, input/role admission, original-account matching and bounded missing-bus
evidence. Five disjoint foreign-created-rule cases also retain both accounts'
CloudTrail history: successful assumptions appear only in the role account as
`AWSService`; neither denied assumptions nor a second source-account record are
fabricated. The native probes removed their owned resources.

`role_audit.json` retains delivered S3 records plus read-only STS history.
Replay correlates service-issued access keys with actual SQS message IDs/MD5s,
preserves payload redaction and verifies that bus forwarding does not add public
`PutEvents` records. See [CloudTrail service-role evidence](cloudtrail.md#service-role-assumptions).
The executable CLI workflow also exercises role-authorized bus forwarding,
real Python Lambda output and Logs, selected CloudTrail gzip objects, current
permission denial and retained SQLite state.

`scheduled_rules.json` retains 441 native control observations from 2026-09-15,
including syntax, optional-field presence, custom-bus restrictions, replacements,
enable/disable and deletion. `scheduled_delivery.json` retains native calendar
and target bindings/bodies: ordinary bus observers, a targetless source, a hybrid
rule, self-matching, shared event IDs and input projections. SDK replay exercises
actual SQS delivery on memory and SQLite, including restart before the deadline.
The separately identified local lifecycle cases cover cadence, trigger removal,
bounded catch-up, restart after a source commit, and journal-write rollback.

The native lifecycle captures observed first delivery tens of seconds after the
envelope time; those offsets are not hardcoded. Nine calendar expressions
actually delivered at `2026-09-15T22:33:00Z`, including suffixes, zero/oversized
minute steps, `W`, `#` and `L-15`. Far-future execution and every zero-step cadence
were not observed. All owned native rules, buses and queues were removed.
The executable SQLite workflow also retained a scheduled event across restart,
forwarded it through a role-authorized bus to real Python Lambda and SQS,
published Lambda Logs/CloudWatch metrics and selected CloudTrail gzip records,
then sent the next occurrence to the DLQ after current role permission was revoked.
The delivered audit contained no synthetic public `PutEvents` record.

`archives.json` retains 263 SDK control steps; `replays.json` binds actual native
SQS receipts to replay names, event markers and destinations rather than polling
labels. `archive_keys.json` retains 92 selected key-policy, alias, caller-session,
encrypted-delivery and failure observations. A separately labelled local setup
uses the native clamped int32 retention maximum where the raw AWS input exceeded
the Go SDK's representable range. Projections do not erase public identifier
spelling, error classes, replay identity relationships or envelope fields.

The executable AWS CLI workflow retained a `STARTING` customer-key replay across
a process restart, then delivered the same fresh event ID to SQS and Logs. A
disabled key failed replay, re-enabling it recovered the original retained event,
and service-time expiry removed the entry without rearchival growth. CloudTrail
retained three StartReplay outcomes and actual service-principal KMS decrypts.
The owned native probes removed mutable buses, archives, rules, queues and roles;
their KMS key remains scheduled for AWS's minimum seven-day deletion. Native
terminal replay histories have no DeleteReplay API and remain for provider expiry.

`metrics.json` retains six native ingestion, rule, schedule, archive/replay,
session-denial and bus/DLQ scenarios from 2026-09-16 in `us-east-1` and `us-west-2`.
SDK replay runs their actual commands and scoped statistics against memory and
SQLite, reopening before final publication and draining again to detect duplicates.
Native legacy samples may occupy the preceding minute or split a request; the
comparison preserves aggregate statistics across each captured window rather
than hardcoding exporter phase. Unowned regional activity is not attributed to
the probe. All deletable probe resources were confirmed absent; accepted native
metric history and terminal replay history remain for provider expiry.

`error_metrics.json` retains the 2026-09-22 disabled-key/missing-target capture,
actual successful target and DLQ envelopes, complete DLQ attribute sets, failed
destination queue counts, bounded metric windows and independent cleanup reads.
SDK replay uses those real service commands on both stores, deletes the source
rule/bus before publishing its minute, and reopens with completed observations
and accepted queue bodies retained. Repeated publication checks distinguish
target attempts from destination acceptance and DLQ delivery. Its owned bus,
five rules and four queues were removed; the customer KMS key was scheduled for
the minimum seven-day deletion window and remains `PendingDeletion`, not absent.

The executable CLI/SQLite workflow delivered three events to SQS and three to
the failure DLQ, deleted the source rule/bus, restarted, then observed the retained
metrics drive one CloudWatch alarm through SNS into SQS. Other account/region
queries stayed empty; repeated drains did not republish. A separate 15-day
clock-jump regression failed on both stores before separating public timestamp
admission from retained service publication, and passed afterwards. Restarting
the executable against the same failing SQLite state recovered its old samples
while public publication of the same old timestamp still returned
`InvalidParameterValue`.

`pattern_admission.json` compares owned `PutRule` admission with `TestEventPattern`
and adds read-only complexity-boundary and equivalent-expression captures. The
admission implementation follows these deployed AWS observations, including
differences from newer Event Ruler state reuse and absent-field traversal.

The matcher was compared with
`/home/r/dev/minor/deceptiq/foundation/aws/eventmatcher` at revision
`ca2fb209747b66f94f76d0f7ab517798566a3ffa` and AWS's
[Event Ruler](https://github.com/aws/event-ruler) at revision
`6efe434fdd7473b77ab35a891813fbd4b18537b3`. They inform the language audit;
native fixtures resolve differences such as numeric strings, case alternatives
and array correlation. The official
[pattern operators](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html)
remain the language target.

`kms_delivery.json` captures customer-managed key policies scoped by SQS encryption
context, including service-only, rule/queue source ARN, missing source ARN and source
account conditions. Queue policies permit both owned rules throughout the capture.
The probe creates only owned resources, deletes its buses/rules/queues, and records
the KMS keys' scheduled seven-day deletion separately from immediate cleanup.

The SDK model input is revision `113bc91bf12edc3af1d3aba1c70be28494d54c2a`.
The custom-event → Lambda → CloudWatch Logs workflow has real runtime execution,
Lambda resource permissions and execution-role-authorized log ingestion.
SQS and direct Logs targets are also implemented; other integrations require
their own implemented consumers and behavioral evidence.

Remaining AWS service sources, archive physical byte accounting, partner events,
global endpoints, connections/API
destinations, bus logging, other target services and broader trace conformance
remain explicit implementation gaps. Primary contracts include
[PutEvents](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html),
[PutTargets](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutTargets.html),
[target retries](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-retry-policy.html)
and [dead-letter queues](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rule-dlq.html).
