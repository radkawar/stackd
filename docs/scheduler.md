# EventBridge Scheduler

EventBridge Scheduler is a separate built-in service from EventBridge event buses
and Pipes. Its generated REST/JSON frontend implements all 12 schedule,
schedule-group and group-tag operations. Operation coverage is not a claim of
complete AWS parity.

## Scheduling and state

Schedules are isolated by partition, account, Region, group and name. The default
schedule group is materialized per scope and cannot be deleted. Group deletion
removes its schedules and retained delivery work, including retries whose schedule
was already automatically deleted. Tags belong to groups, not individual schedules.
Lists use deterministic scoped pagination; tokens cannot be reused in another
account, Region, operation or filter set.

CloudFormation Schedule and ScheduleGroup ownership is private native state,
admitted with the resource transaction. Public ClientToken values and group tags
cannot grant that claim. Cloud Control creates also retain an exact private claim
for authorized creation recovery; ordinary native/Cloud Control updates preserve
surviving claims without adopting unclaimed resources. Group deletion clears its
children, and each schedule binds the immutable native group incarnation.
Migration `394_scheduler_cloudformation_ownership.sql` assigns distinct native
identities to existing groups and binds their existing schedules, but leaves
all pre-cutover resources unclaimed. Recovery, no-op updates and cleanup enter
the current native IAM boundary; public tag edits do not revoke private ownership.
This is bounded local ownership behavior, not additional scheduling/AWS parity.

Supported expressions are `at(yyyy-mm-ddThh:mm:ss)`, positive `rate` expressions
using minutes, hours or days, and six-field Scheduler cron expressions. An omitted
time zone means UTC; named zones use the IANA database. Spring-forward cron gaps
are skipped and fall-back wall times occur once. Rate days remain 24 elapsed hours
across DST. The shared `internal/awsschedule` calendar still preserves the existing
EventBridge-rule, Backup and Application Auto Scaling dialects.

Recurring schedules honor start/end boundaries and ENABLED/DISABLED state. A rate
without StartDate starts immediately. One-time schedules ignore StartDate and
EndDate. UpdateSchedule replaces optional settings rather than patch-merging the
previous request. A completed one-time schedule remains visible unless
ActionAfterCompletion is DELETE. Automatic deletion does not destroy an admitted
retry: its immutable target snapshot survives independently of the schedule.

OFF windows dispatch at the retained nominal deadline. FLEXIBLE windows select a
retained second inside the configured window. Retry age starts at that selected
initial delivery deadline; retries do not extend it. These are local logical-time
choices, not a reproduction of AWS fleet jitter or throughput quotas. All deadlines
join the existing instance clock and bounded scheduler drain—there is no second
service timer loop or event bus.

The memory backend joins `memory.Domain`. SQLite migration `216_scheduler.sql`
and generated SQLC queries retain normalized groups, tags, schedules, targets,
ECS options and child collections, pending occurrences, delivery snapshots,
retry attempts, errors and expiration deadlines. Customer target input is payload,
not a serialized resource/request DTO. Pending work survives a database reopen.
Effects occur outside the source transaction and their result commits afterward.
A crash after a destination accepts an operation but before its result commits can
produce a duplicate: this is an at-least-once boundary, not invented exactly-once
execution.

## Real targets and authority

Templated targets call the existing owners for:

| Target | Actual operation |
| --- | --- |
| SQS | SendMessage |
| Lambda | asynchronous Invoke, using the real configured runtime path |
| EventBridge event bus | PutEvents, including per-entry failures |
| SNS | Publish |
| Step Functions | StartExecution |
| Kinesis | PutRecord |
| Firehose | PutRecord |
| ECS | RunTask, including returned task failures |
| CodeBuild | StartBuild |
| CodePipeline | StartPipelineExecution through the existing pipeline/artifact owner |

The target's own runtime/engine availability and authorization remain authoritative;
Scheduler cannot make an unavailable native engine execute. Inspector and
SageMaker templated targets are explicitly unsupported because those execution
owners are absent. ECS options are retained as typed fields and ordered
child records; ReferenceId remains distinct from task StartedBy attribution.
Invalid ECS overrides and non-object CodeBuild override payloads fail delivery
rather than being ignored or crashing the scheduler.
FIFO SQS delivery supplies MessageGroupId and relies on the queue's ordinary
content-based deduplication requirement.

CodePipeline templates derive the pipeline name from the target ARN and ignore
`Target.Input`, including JSON name/variable/source-revision/client-token overrides
and non-JSON text. They do not parse the payload as a pipeline request. Separate
occurrences with the same supplied input token still start separate executions.
The pipeline owner retains `StartPipelineExecution` attribution and the assumed
execution-role principal; this is not an EventBridge-rule `CloudWatchEvent`.
Use the direct API or a universal target for explicit execution parameters.

Universal ARNs use `arn:aws:scheduler:::aws-sdk:<sdk-service>:<action>`. They reuse
the assembled typed command owners, not a second operation registry or an ambient
AWS client. Admission rejects missing service/operation owners, event-stream
operations and documented excluded/read-only prefixes after normalizing the
operation's leading-letter spelling exactly as the command resolver does. Target Input
must be a valid SDK parameter document. Template parameters cannot be combined
with a universal ARN. The receiving owner performs its normal current IAM,
resource-policy, KMS, semantic validation and audit work.

Admission requires the caller's scheduler action and `iam:PassRole`, plus current
role trust for `scheduler.amazonaws.com`. Execution assumes that role afresh, with
the schedule-group ARN as source context, and does not retain the deployer's
permissions. Trust changes and target policy changes therefore affect pending
work. EventBridge templated targets reject cross-Region delivery as documented.
Other templated operations route through the target ARN's Region; cross-account
destinations still require their own resource authority. CodePipeline currently
accepts foreign-account ARN admission but rejects delivery explicitly, rather
than starting the execution role's same-named pipeline. Native foreign-account
and foreign-Region execution remain unmeasured.

Transient service failures and throttling use retained exponential backoff with
bounded jitter, retry count and age limits. Terminal failures and exhaustion can
send the payload and failure attributes to an actual standard SQS DLQ, using the
execution role and ordinary SQS authority. Failed DLQ delivery is recorded through
its failure metric; it is not reported as successful delivery. Existing admitted
work keeps its original target configuration when the schedule is updated.
CodePipeline failures send the translated `{"Name":"pipeline-name"}` request,
not the ignored input. Current pipeline-role denial is `AccessDeniedException`.
DLQ context uses `EXECUTION_ID` and `RETRY_ATTEMPTS` excludes the initial attempt.
Native payload-truncation and retry-exhaustion attributes remain unfinished.

Explicit Input supports `<aws.scheduler.schedule-arn>`,
`<aws.scheduler.scheduled-time>`, `<aws.scheduler.execution-id>` and
`<aws.scheduler.attempt-number>`. Execution IDs differ between target attempts;
the subsequent DLQ handoff preserves the failed attempt's context. Input is
limited to 256 KiB. Omitted Input produces the captured default notification:
version `0`, detail-type `Scheduled Event`, source `aws.scheduler`, source account
and Region, nominal scheduled time, the schedule ARN in resources, and **string**
detail `"{}"`. GetSchedule still omits Target.Input and materializes the default
RetryPolicy (185 retries / 86400 seconds), UTC time zone and NONE completion action.
Empty-string Input is rejected by generated model validation.

## Encryption, metrics and API observations

With a customer-managed key, only target input is envelope-encrypted. Admission
uses the caller's DescribeKey, GenerateDataKey and Decrypt authority, enforces a
same-Region symmetric ENCRYPT_DECRYPT key, and stores authenticated ciphertext
plus the wrapped data key. Reads use the current caller's Decrypt authority;
execution decrypts as the current role. The encryption context binds
`aws:scheduler:schedule:arn` to the schedule ARN. Wrong contexts, revoked permissions
and disabled keys do not return plaintext. No KMS grants are invented. Omitting
KmsKeyArn requires no customer KMS permission; AWS-owned physical storage encryption
is not independently reproduced by the local repository. Protect the state
filesystem as sensitive data.

Service-owned CloudWatch samples use `AWS/Scheduler` and ScheduleGroup dimensions:
InvocationAttemptCount, TargetErrorCount, TargetErrorThrottledCount,
InvocationDroppedCount, InvocationsSentToDeadLetterCount and
InvocationsFailedToBeSentToDeadLetterCount. They describe actual attempts and
terminal outcomes, commit through the existing metrics publisher, and do not
borrow the API caller's PutMetricData authority. The native lifecycle fixture
observes InvocationAttemptCount with Sum 1, unit `None`, and the ScheduleGroup
dimension; publication follows that unit. Native aggregation timing and complete
dimensional parity are not claimed.

A service-local executable smoke also dispatched an authorized real SQS target
and read the actual CloudWatch GetMetricStatistics result: namespace
`AWS/Scheduler`, InvocationAttemptCount, ScheduleGroup `default`, Sum 1, unit `None`.

API completion records join successful resource transactions through apievents;
rejections are recorded after rollback. Captured management projections omit
Target.Input, Tags and TagKeys entirely, format boundary dates as RFC3339,
materialize ListSchedules' effective default page size and omit apiVersion.
Successful creates/updates include their returned ARN; captured reads retain null
responseElements. The exact-request-ID S3-delivered management records are in
[`lifecycle_success.json`](../testdata/aws/scheduler_pipes/lifecycle_success.json).
The fixture's absent empty-input audit record is a bounded unobserved outcome,
not evidence that AWS never emits it. Destination services own their actual
operation audit projections; no Scheduler-native data-event category is invented.

The generated event-source correction points to the native CreateSchedule record
in that fixture. The [AWS Scheduler event reference](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-scheduler.html)
independently documents `scheduler.amazonaws.com` and EventBridge source
`aws.scheduler`.

## Exercised evidence

Focused permanent regressions cover:

- memory and SQLite retry snapshots across schedule replacement and repository
  restart, followed by a terminal error and DLQ transition;
- account-scoped resources and pagination, group cascading deletion, one-time
  ignored bounds, automatic deletion retaining pending retry, and flexible-window
  retry age;
- tuple-ordered schedule pagination across prefix-related group names on both
  memory and SQLite;
- fractional-clock immediate rates, DST gaps/folds, fixed elapsed rate days and
  calendar-dialect isolation;
- real IAM PassRole denial, service-role trust, actual SQS delivery, and a role
  policy revoked after schedule creation causing real SQS dead-letter delivery;
- uppercase excluded universal actions and invalid CodeBuild overrides producing
  a validation failure and actual SQS dead-letter delivery instead of a panic;
- real KMS caller and execution-role authority, authenticated payload encryption,
  wrong schedule contexts and disabled-key denial;
- fixture replay of native omitted-input notification delivery and GetSchedule
  readback from [`default_input.json`](../testdata/aws/scheduler_pipes/default_input.json).

A disposable generated-command executable also exercised complete pagination for
groups `a` and `a-`, uppercase ReceiveMessage admission rejection, and a `null`
CodeBuild override taking the actual job-driver/authorized SQS DLQ path.

The native fixtures retain identity, request IDs, owned resources, cleanup and
absence verification. The main lifecycle capture also establishes empty/absent
input admission, permissive `rate(1 minutes)`, disabled schedules in the past and
in a DST gap, ignored one-time bounds, real SQS delivery and automatic deletion.
Enabled one-time execution inside a nonexistent DST wall time remains uncalibrated:
the local calendar admits the expression but has no occurrence at that wall time.

A throwaway official AWS SDK for Go v2 executable smoke exercised generated HTTP
route/decode/response binding, group creation/tags/untags, schedule create/get/list/
update/delete, modeled invalid-cron rejection, SQLite database/service reopening,
retained encrypted occurrences decrypted by the current execution role and
delivered to actual SQS, a universal CreateQueue effect, omitted-input native
readback/default SQS notification and group deletion cascade.
Its HTTP fixture supplied a trusted local caller; this service-local run did not
verify gateway SigV4 authentication. The separate
[integrated executable proof](pipes.md#integrated-executable-proof) exercised signed
SDK requests, real Lambda throttling and retained retries across process restart.

### CodePipeline templated targets

The [native capture](../testdata/aws/scheduler/codepipeline_native_observed.json)
and [derived index](../testdata/aws/scheduler/codepipeline_summary.json) retain
actual S3 Source/Deploy executions, default variable bindings, latest source
versions and deployed ZIP bytes. Omitted input, JSON overrides, repeated supplied
tokens and plaintext input all reached the ARN-named pipeline. Current role
denial prevented a new execution and produced the translated request on SQS;
restoring permission recovered. Disabled foreign-account ARN admission succeeded;
a slash in the pipeline name failed admission. Those are not foreign execution
observations. Two earlier IAM/artifact-prefix setup failures remain retained,
with cleanup verified for all three native resource sets.

The [signed Go SDK executable workflow](../testdata/integration/scheduler_codepipeline_executable.json)
consumes actual extracted HTML, JSON, binary and empty files. A direct API
control honors variable/source overrides while the scheduled target ignores
them. Retained denied and successful occurrences survive SQLite/controller
restart; restored role authority admits delivery. All three controllers exit
zero and exact-owned resources are verified absent. Foreign account/Region cases
prove local isolation, not native equivalence. The
[unsupported baseline](../testdata/integration/scheduler_codepipeline_before.json)
and [denial-code mismatch](../testdata/integration/scheduler_codepipeline_denial_mismatch.json)
remain failed-before evidence, not passing workflows.

Scoped regression command:

```sh
go test ./internal/services/scheduler ./storage/sqlite/scheduler ./internal/integrations \
  -run 'TestScheduler|TestPendingDelivery|TestGroupScope|TestAtIgnores|TestRateStarts|TestFlexibleWindow'
```

## Sources and remaining bounds

- [Schedule types, time zones and DST](https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html)
- [CreateSchedule replacement fields and boundaries](https://docs.aws.amazon.com/scheduler/latest/APIReference/API_CreateSchedule.html)
- [Target input, FIFO queues and delivery parameters](https://docs.aws.amazon.com/scheduler/latest/APIReference/API_Target.html)
- [Templated targets](https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-templated.html)
- [Universal target ARN and excluded actions](https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-universal.html)
- [Target context attributes](https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-schedule-context-attributes.html)
- [KMS payload encryption and authority](https://docs.aws.amazon.com/scheduler/latest/UserGuide/encryption-rest.html)

Beyond the explicitly unsupported target owners, uncalibrated areas include
enabled one-time DST-gap execution, precise AWS retry jitter and retryable-error
classification, group deletion's asynchronous AWS visibility window, large-fleet
quotas/throttling, and API/target shapes beyond the specific retained native cases.
These are not inferred from generated models or operation counts. There is no
fallback to AWS or a simulated running target.

Relevant `TODO: Comeback` markers cover absent Inspector/SageMaker execution
owners, CodePipeline cross-account delivery, remaining native DLQ attributes and
enabled at-in-gap execution calibration. They do not hide accepted fake target effects.
