# SQS delivery and tenant fairness

SQS remains a partial service. Standard/FIFO delivery, visibility, retention,
dead-letter transitions and redrive, authorization and encryption have real
implementations. Fairness uses delivery concurrency and retained tenant
classification. Sent/received/deleted CloudWatch counters are implemented; recent
processing-time share detection, remaining metrics, complete quota/timing
conformance, PostgreSQL and coordinated recovery remain open.
An optional [SQLite backend](sqlite-state.md) persists typed SQS state and accepted
redrive progress, with SDK restart and process-exit tests.

## Reference scope

AWS documentation supplies the tenant-fairness contract. Generated Smithy
bindings expose `MessageGroupId` on standard sends and receives.

AWS's [fair-queue guide](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-fair-queues.html)
uses `MessageGroupId` to identify standard-queue tenants without FIFO locking.
Its [detailed rules](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-fair-queues-detailed.html),
reviewed 2026-09-12, describe approximate concurrency detection at 30 in-flight
messages and a share greater than 10%, plus a separate recent processing-time
measure. Ungrouped messages are individual tenants. Quiet work takes priority;
noisy work can use remaining capacity, favoring the noisy tenant with fewer
in-flight messages. A tenant recovers when its backlog is consumed or after
five minutes without in-flight work.

## Current implementation

`internal/services/sqs/fairness.go` derives concurrency from current messages,
visibility and retention deadlines. It retains only noisy group identity and
the latest in-flight deadline in the typed `QueueMessages` storage contract.
Deletes and visibility changes update that deadline; natural expiry retains its
actual service-time endpoint, including when a manual clock jumps past it.
Removing all of a tenant's messages or purging the queue removes classification.
State is isolated by queue identity, account, region and partition.

Receive selection uses one transaction snapshot. Quiet candidates retain local
queue order, followed by noisy candidates ranked by concurrency. Each batch's
committed deliveries affect the next receive. Delayed messages are ineligible;
standard groups permit concurrent delivery. FIFO keeps its existing group locks,
deduplication and receive-attempt behavior.

Classification commits with messages and receipts. A failed transaction leaves
both unchanged. Reopening retained memory storage with the same clock preserves
the recovery period. The SQLite backend also persists this classification across
process exit. Recovery still requires the appropriate service clock; the planned
cross-service event journal remains open.

## Native observation and local verification

[The owned AWS capture](../testdata/aws/sqs/fairness.json) contains a standard
queue with 120 noisy messages. Sixty were held in flight before sending 20 quiet
messages and ten ungrouped messages. Subsequent receives returned the remaining
90 messages while the original deliveries stayed in flight. Group attributes
round-tripped; standard messages had no FIFO sequence or deduplication fields.

Native batches interleaved quiet and noisy work. The first six contended
deliveries were quiet or ungrouped, but another quiet message appeared at the
end. This finite run does not prove the exact detection thresholds or an ordering
guarantee. Local priority and recovery tests exercise the documented rules at
deterministic service-time snapshots; they do not reproduce AWS partition
sampling, approximate detection or undisclosed processing-time accounting.

`fairness_native_test.go` replays the send/receive sequence through the Go SDK
and compares per-message attributes and delivered contents, without equating
native order with local order. `fairness_test.go` checks quiet work, independent
ungrouped tenants, concurrency share, spare capacity, delayed work, noisy-tenant
balancing, scope, rollback, purge and five-minute recovery after natural expiry,
deletion, release and extension. Existing FIFO and DLQ tests exercise the shared
receive path.

Reproduce the live capture explicitly:

```sh
AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1 PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/aws/sqs_fairness_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID
```

The script creates one uniquely named queue, sends at most 150 synthetic
messages, bounds polling, deletes its queue and confirms native lookup fails.
The checked-in run completed and cleanup was confirmed. It changes no IAM
policies or other queues. Ordinary tests use only the checked-in capture and
local endpoints.

Complete processing-time detection and its measurement window using native
evidence before introducing accounting state. Add queue/quiet-group metrics
through an actual CloudWatch implementation. These gaps are marked at the
fairness decision in code; this work does not establish complete SQS parity.

## Redrive scheduling and recovery

Accepted redrive tasks use `internal/scheduler`, with a typed next deadline in
`MoveTaskRecord`. The task record is authoritative; per-task goroutines and their
duplicate mutable state have been removed. Equal deadlines use acceptance
sequence. Each bounded step commits message removal, any destination insertion,
moved count and next deadline together. FIFO duplicates consume the source
message without increasing the moved count. The starting `ToMove` estimate stays
fixed. Explicit rate limits retain elapsed progress across drains and service
reconstruction; periods with no available messages do not accumulate rate credit.

Closing stops execution without changing an accepted task into `CANCELLED`.
The next stack starts recovery after its dependencies are wired. Standalone
provider callers use `StartWorkers` to recover a retained repository. The normal
Start/Cancel APIs wake the driver after their transaction commits. `CANCELLING`
survives a failed completion commit and recovery; already moved messages remain
at the destination. Storage/server failures leave the current step pending for
retry. Permanent permission or dependency rejections publish `FAILED` against
the selected task/deadline. A deleted source's task cannot consume a replacement
queue sharing its ARN.

Shutdown cancels and joins redrive execution, long polls and pending encryption
preparation. KMS calls run outside queue locks and repository callbacks, so a
paused dependency cannot prevent cancellation from committing. The scheduler
uses typed task records persisted by the selected backend; SQLite supports
process recovery, while memory requires retaining the backend. The cross-service
event log remains open; optional manual time persists with SQLite. Each transaction
uses the current service-time snapshot; draining elapsed deadlines does not
reconstruct historical IAM policies or KMS state across a large clock advance.

[The native redrive capture](../testdata/aws/sqs/redrive.json), reproduced by
`scripts/aws/sqs_redrive_probe.py` with the same region environment as above,
used three owned standard queues and a custom destination. AWS kept the initial
count at 12 while moved counts progressed to 12. This agrees with the
[result-field contract](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ListMessageMoveTasksResultEntry.html).
The local/native test compares status, counters and task-handle presence at
matching progress, not wall-clock timing.

The cancellation capture progressed from `CANCELLING` to `CANCELLED` and moved
two additional messages while settling. Its starting estimate was eight despite
five new sends, illustrating approximate metadata. Local cancellation currently
stops further moves when its accepted intent is drained. It does not reproduce
AWS's cancellation lag or partial work already underway in the distributed
service. All three probe queues were deleted and native lookup confirmed absence.

The [AWS redrive guide](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-dead-letter-queue-redrive.html)
and the local SQS guide above supply the recovery workflows. Native startup,
cancellation and maximum-duration timing, optimized rates and remaining network/partition
forwarding behavior still need conformance work. The new tests establish
retained recovery, atomic rollback, cancellation recovery, current destination
policy enforcement, source incarnation checks and bounded ordering; they do not
establish complete redrive behavior.

## FIFO redrive and automatic dead-letter history

Consumer receives and redrive now share visibility and FIFO group selection.
An in-flight message blocks later messages in its group; available work from
other groups continues. Releasing or deleting the held message, or reaching its
visibility deadline, makes its group eligible. Redrive retains source order
within each group. Destination sends and transfers share sequence allocation
and the five-minute deduplication window, including queue or message-group scope.
A duplicate does not extend the original window. Message insertion and its
identity binding commit together and survive retained-backend reconstruction.

[The isolated FIFO capture](../testdata/aws/sqs/fifo_redrive.json), taken on
2026-09-12, used separate queue families for group locks, preexisting destination
duplicates and automatic dead-letter transfers. It recorded:

- Holding `a0` blocked redrive of `a1` in the same group while `b0` moved.
  Releasing `a0` allowed both messages to move in order.
- Explicit redrive assigned a new message ID and used the source message ID as
  the destination deduplication ID. Duplicate sends after destination deletion
  returned that same message ID and sequence without another delivery.
- A destination deduplication binding seeded before redrive suppressed the
  transfer even after the seed message was deleted. The task completed with
  zero moved messages and a starting estimate of one.
- Automatic DLQ entry retained the source message ID, sent timestamp and first
  receive timestamp. The first DLQ receive reported count two after one source
  receive. Its deduplication ID became the original message ID and its sequence
  changed. Duplicate sends after DLQ deletion reused that binding.
- Redrive back to the original source created a new ID, reset sent/first-receive
  history and delivered with count one. The DLQ source attribute was absent.

The [ReceiveMessage contract](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html)
counts deliveries across queues. Automatic transfer preserves that history;
explicit redrive creates a new message. The
[DLQ retention contract](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)
keeps the original retention start for standard queues and restarts it for FIFO.
`MessageRecord.RetentionStarted` therefore owns expiry independently of the
preserved `SentTimestamp`. Retention tests use this documented contract; the
native capture did not wait for retention expiry.

`move_fifo_test.go` compares native message identities, group ordering,
deduplication responses and collision completion through the Go SDK. It also
checks destination scope, window expiry, reconstruction and commit rollback.
`dead_letter_test.go` compares automatic/explicit transfer history and exercises
retention, another failure/redrive cycle and failed automatic-transfer commits.
These checks do not establish distributed timing or complete SQS parity.

Reproduce the isolated capture with:

```sh
AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1 PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/aws/sqs_fifo_redrive_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID
```

The run completed and deleted all eight owned queues, confirming native lookup
failure for each. An [earlier shared-queue capture](../testdata/aws/sqs/fifo_redrive_late_arrival.json)
recorded late arrivals reaching the custom destination after a task was reported
`COMPLETED`. That run could not isolate automatic DLQ inspection; an independent
destination receive located the message, and all three queues were deleted.
This is evidence of a remaining timing discrepancy, not a derived forwarding
algorithm. The local driver stops at completion. Native task completion/late
arrival behavior needs further measurement before modeling additional work.

## Forwarded authorization

Redrive has distinct admission and execution decisions. The native
[admission capture](../testdata/aws/sqs/forwarding_redrive.json) denied
`StartMessageMoveTask` when required receive/delete/send or queue-attribute
permissions were restricted to forwarded calls. Even these dependent admission
checks used the direct caller. The local Start/Cancel/List control paths keep
the caller's original request context.

The [accepted-task capture](../testdata/aws/sqs/forwarding_execution.json) first
held one message for 600 seconds and accepted redrive under unrestricted queue
policies. It then applied each restriction, verified that direct receive/send
calls were denied, and released the held message. Separate cases required
`CalledViaLast`, `CalledViaFirst`, membership in `CalledVia`, or `ViaAWSService`.
All four delivered and completed. Requiring `PrincipalIsAWSService=true`
prevented delivery and produced `FAILED` with `FailureReason=AccessDenied`.
Before release, even that denied task remained `RUNNING` with no messages moved.

The worker now adds the SQS forwarding hop to the retained caller, evaluates
receive/delete/attribute permissions and the selected destination, and commits
with IAM/Organizations and queue-policy reads in the same transaction. It does not reissue the
Start control action. With no eligible message it advances the retained wait
without making a delivery authorization decision. Current identity, boundary,
session, resource, SCP and RCP restrictions still govern delivery.

[The KMS capture](../testdata/aws/sqs/forwarding.json) used an owned customer key
with conditional denies. Direct data-key requests were denied. SQS send/receive
succeeded when the condition required `CalledViaLast=sqs.amazonaws.com` or
`ViaAWSService=true`; requiring an AWS service principal denied encryption.
`kms.WithViaService` now supplies the shared IAM forwarding chain alongside its
existing regional KMS condition. The SDK integration test uses an IAM user with
only the required queue and KMS permissions and compares these native outcomes.
The CLI's `KMS.AccessDeniedException` is the Smithy Query error alias for the
SDK's modeled `KmsAccessDenied`.

Reproduce the three captures explicitly:

```sh
AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1 PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/aws/sqs_forwarding_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID
AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1 PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/aws/sqs_forwarding_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID --redrive-details
AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1 PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/aws/sqs_forwarding_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID --accepted-task
```

All 42 queues from these runs were deleted, with native lookup failure confirmed.
The owned KMS key `a0a4d4b3-a38b-4d3c-8be6-b140d865ac2a` in `us-east-1` is
`PendingDeletion`, scheduled for 2026-09-19 13:09:05 UTC. Its ARN and deletion
response remain in the capture for cleanup follow-up; deletion is not yet final.
No IAM policies or preexisting queues/keys were changed by these probes.

These are commercial public-endpoint captures. They do not establish VPC
endpoint behavior, partition-specific service principals or policy propagation
bounds. Some completed native tasks still reported zero moved messages even
though a destination receive returned the message; comparisons use actual
delivery and terminal status, not an exact counter update time.

## Encryption preparation and commit

`key_work.go` owns request-local data-key preparation. A cache miss aborts the
provisional queue transaction before calling `EnsureServiceKey`, `GenerateDataKey`
or `Decrypt`. Once KMS returns, `authorizedUpdate` repeats queue authorization and
the operation from current typed state. A deleted/recreated queue fails by
incarnation ID; changed encryption settings select a new key request. Receives
reselect eligible messages and redrive rechecks its accepted task, so competing
receives, deletes and cancellation cannot commit an earlier message selection.

Prepared keys enter the process cache only after the message transaction commits.
Failed key results are retained only within that API command, preserving batch
entry errors without repeatedly calling a failing dependency for the same key.
Failed or unused prepared plaintext is erased when the command ends. Concurrent
cache misses may prepare independent keys; a KMS call is not rolled back when a
subsequent queue commit fails. No message mutation crosses the KMS boundary.

The final transaction samples service time after preparation for authorization,
message timestamps, delay and visibility deadlines. IAM/Organizations policy
reads join this transaction on both the default memory bundle and SQLite. A
permission revoked while a request waits for queue storage therefore denies its
send. Request cancellation and service shutdown cancel the KMS context; shutdown joins active preparations.
The KMS consumer contract requires cancellation support and caller-owned buffers.
Queue policy binding/rendering also borrows the owning context for current IAM
principal identities. The shared transaction domain adds no remote provider or
event journal.

`key_work_test.go` pauses actual consumer calls while SDK requests change queue
settings, policy, incarnation, receipts and redrive state. It checks independent
queue access, rollback, per-entry errors and all three KMS shutdown paths.
`clock_test.go` advances service time during preparation and verifies the eventual
message timestamps. Existing SDK integration tests continue to exercise the
built-in IAM and KMS implementations and the native forwarding captures above.
`integration/sqs_authority_transaction_integration_test.go` pauses queue storage acquisition,
revokes the sender's IAM policy, and checks denial with no published message on
memory and SQLite. Restoring permission permits the next send.

AWS's [key-management guide](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-key-management.html),
reviewed 2026-09-12, requires producers to have both GenerateDataKey and Decrypt
permissions when refreshing a data key, and consumers to have Decrypt permission.
The guide also distinguishes callers by IAM identity and session policy scope,
sharing role sessions that differ only by session name. The concurrency tests
establish the local storage boundary, not AWS's internal transaction or cache
implementation. Requester behavior has separate evidence below.

SQS passes the queue ARN under KMS encryption-context key `aws:sqs:arn`.
The [EventBridge encrypted-delivery fixture](../testdata/aws/eventbridge/kms_delivery.json)
verifies that spelling through actual policy conditions. Internal service delivery
shares URL-based sends' message loading, authorization, encryption and atomic
message/journal publication; it does not construct a synthetic HTTP request.

## KMS cache requester identity

Both producer and consumer caches use `key_requester.go`. The key includes the
partition/account, immutable principal and issuer IDs, whether a session policy
applies, inline policy documents and managed-policy ARN references. Assumed-role
sessions use the role's immutable ID, so changing a session name does not cause a
new KMS request. Deleting and recreating an IAM user or role cannot inherit the
previous identity's cached permission through a reused ARN.

Session tags and source identity do not separate requesters in the captured AWS
cases. Queue authorization still evaluates the actual session on every request;
KMS authorization occurs when its data key needs refreshing. A cached key can
therefore remain usable where a fresh direct KMS call would be denied. Adding
an unconditional KMS check to each SQS call would change that behavior.

[The expanded native capture](../testdata/aws/sqs/cache_scope.json) records 57
operations across 14 STS sessions, one owned role, two managed session policies,
a customer KMS key and separate warm/fresh queues. Conditional KMS denies on
session name, principal tag and source identity distinguish reuse from fresh
key access. It confirms:

| Change to the calling session | Result on the warm queue |
| --- | --- |
| Same role and policy scope, different session name | Reuses the permitted key for send and receive. |
| Same role/session name, limited inline or managed session policy | KMS denies send and receive. |
| Same scope, a tag or source identity that denies fresh KMS access | Reuses the permitted key; the fresh queue and direct KMS calls deny access. |
| Inline policy whitespace only | Reuses the key. |
| Reordered inline statements or managed-policy ARN list | Requires fresh KMS access; the probe's session-name condition denies it. |

The cache removes insignificant JSON whitespace and preserves supplied policy
and ARN order. It does not attempt general logical policy equivalence. The
[initial capture](../testdata/aws/sqs/cache_scope_initial.json) independently
records 42 operations for the basic scope, name, tag and source-identity cases.
These are finite public-endpoint observations, not a guarantee of cache placement,
request timing, arbitrary policy equivalence or every federation context.

`integration/sqs_cache_scope_integration_test.go` replays the expanded capture through the
real local IAM/STS/KMS/SQS providers and Go SDK. It checks modeled denial codes,
actual message delivery and reauthorization at the configured service-time reuse
deadline. `integration/sqs_cache_identity_integration_test.go` deletes and recreates users and
roles with the same names, proving old cached keys cannot authorize their
replacements. The existing grant-revocation and encryption-reconfiguration tests
exercise the same producer and consumer paths.

Reproduce the expanded capture explicitly:

```sh
AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1 PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/aws/sqs_cache_scope_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID
```

Both runs deleted their queues, roles and managed policies. Queue lookup failure
confirmed removal. The two owned `us-east-1` KMS keys are `PendingDeletion`:
`e47e4ed5-df4a-4ddb-b98d-1286e93dc3f4` at 2026-09-19 14:01:36 UTC and
`efa0174f-e819-45ed-a897-86b1fd8bdfc5` at 2026-09-19 14:05:14 UTC. Their ARNs and
native scheduling responses remain in the captures; deletion is not final.
Temporary credentials stayed in process memory and expire after 15 minutes.
No preexisting IAM policies, queues or keys were changed.

For EventBridge service deliveries, the requester includes the service name and
source account/partition. Native cold KMS calls enforce the rule's `SourceArn`,
but warm data-key reuse crosses rules on the same queue. The static-policy fixture
records cold rule B denial, rule A success, then warm B success. Queue policy
checks still apply to every send. See [the complete delivery path](eventbridge.md).

## CloudWatch queue metrics

SQS publishes into `AWS/SQS` with the sole dimension `QueueName`, in the queue
owner's account/region/partition. SDK requests and internal ARN-addressed
deliveries use the same producer. CloudWatch is a consumer-defined dependency;
publication joins the shared transaction without borrowing customer
`cloudwatch:PutMetricData` permission or fabricating another API call.

### Request observations

The [original counter capture](../testdata/aws/sqs/metrics.json) and
[extended request capture](../testdata/aws/sqs/request_metrics.json) distinguish
request contributions from periodic active-queue samples:

- A successful send/delete batch contributes one counter sample whose value is
  its successful-entry count, including zero when all entries fail. Accepted
  FIFO duplicates count as sends; repeated valid deletes and FIFO receive-attempt
  replays count again. These are not counts of unique resource transitions.
- A completed empty receive increments `NumberOfEmptyReceives`, not
  `NumberOfMessagesReceived`. A nonempty receive contributes its returned count.
  Internal long-poll wakeups and encryption preparation retries are not requests.
- Every successful FIFO send request contributes one
  `NumberOfDeduplicatedSentMessages` sample, including zero. Within-batch and
  previously accepted duplicates share the normal deduplication state.
- `SentMessageSize` records each accepted submitted message separately, including
  duplicates. It counts UTF-8 body, attribute name/full type and submitted string
  or raw binary bytes, before Number normalization. Native measurements also
  include `AWSTraceHeader` components; those remain excluded from payload limits.
- Whole-batch preflight failures can publish sizes without accepting messages.
  Captured duplicate entry IDs retain the last payload's size; invalid entry IDs,
  eleven-entry batches and missing/invalid FIFO parameters record all distinct
  submitted entries. Standard per-entry failures record only accepted sizes.
  This does not infer validation ordering for every unmeasured failure.
- FIFO explicit per-message delay zero is accepted. A nonzero FIFO delay rejects
  the whole batch, as do missing FIFO group/dedup parameters. Batch missing group
  is `InvalidParameterValue`; single-send missing group is `MissingParameter`.

For example, successful batch counts five and one produce Sum 6, SampleCount 2,
Minimum 1, Maximum 5 and Average 3. A successful single plus an all-failed batch
instead produces Sum 1, SampleCount 2 and Minimum 0. Request fixtures compare
isolated native buckets through the Go SDK, including modeled errors, failed-batch
non-delivery and retained publications after queue deletion/reopen. They do not
pin standard short-poll ordering or the timing of native periodic zeros.

Successful request samples commit with message state; authorization failures,
KMS preparation and rolled-back commands add no successful samples. Evidenced
preflight sizes commit with the failed API outcome, independently of the aborted
resource command. Completed-minute publication and pending-sample removal share
one transaction. Neither a receipt ledger nor a second retry system is involved.

### Backlog, age and activity

The [queue gauge capture](../testdata/aws/sqs/queue_metrics.json) records visible,
in-flight and delayed backlog; oldest-message age; FIFO in-flight group count;
and noisy/quiet-group measurements. GetQueueAttributes and CloudWatch share
delivery-state classification. FIFO group blocking does not make its otherwise
visible backlog in-flight.

Age includes in-flight work, excludes initial delay even after availability, and
restarts on automatic DLQ entry without rewriting wire message identity or
timestamps. `MessageRecord.AgeStarted` and `QueueReceives` retain those independent
facts. Three source deliveries did not exclude a newly entered DLQ from age;
its next wire receive still reported cumulative count four. Controlled standard
poison messages remained age-eligible after three deliveries and switched to
younger work after a fourth. Local exclusion uses that observed per-queue boundary;
AWS's approximate distributed reevaluation timing is not reproduced.

Active empty queues emit real zero gauges. They also emit periodic zero samples
for sent/received/deleted/empty counters; FIFO adds deduplicated sends. Size has no
idle sample, and standard queues do not emit FIFO deduplication samples.
The [AWS activity contract](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/monitoring-using-cloudwatch.html)
keeps queues active through messages/access and stops empty queues after six hours
without activity. Authenticated denied accesses reactivate existing queues too.
These private deadlines do not change `LastModifiedTimestamp`.

The shared scheduler samples current queue state once per modeled minute.
After a clock jump or restart it records the actual current snapshot, not invented
backlog history for skipped minutes. Sampling/publication/deadline advancement
are atomic. Deletion removes future sampling while retaining published history
and pending request observations. Older stores cannot reconstruct every original
delay/transfer instant; unknown age is omitted until those records leave.

Quiet gauges reuse the existing queue-owned noisy classification. The new native
40/60-held workloads emitted noisy-group **zero**, not a positive classification;
quiet exclusion and distributed threshold/recovery conformance therefore remain
open alongside processing-time-share detection. The capture's positive gauge
points each had SampleCount 1; this is evidence, not a universal AWS cadence claim.
See the [AWS metric reference](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-available-cloudwatch-metrics.html).

Actual CLI/SQLite execution produced visible 2/in-flight 1/age 60, a backlog alarm
in `ALARM`, FIFO duplicate size samples, and failed-batch sizes without insertion.
A six-hour jump produced no fabricated skipped backlog; a denied send then
reactivated zero gauges without changing queue modification time. A schema-58
queue upgraded to 59 retained its original message and producer timestamp while
reporting age 60 after three minutes with a two-minute initial delay.
