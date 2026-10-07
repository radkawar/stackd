# Step Functions execution kernel

> In native capture references, `000000000000` is an anonymized account alias,
> not the AWS account originally used. See [capture privacy](behavior-references.md#publishing-sanitized-probe-captures).

Step Functions uses the generated Smithy frontend, scoped IAM authorization,
typed repositories and the shared service scheduler. This is an implemented
workflow engine, not complete Step Functions parity. Registered operations and
native fixture counts do not establish semantic completion.

## Ownership and execution

`internal/services/stepfunctions` owns machine incarnations, immutable revisions,
versions, aliases, executions, frames, activity/task attempts and history.
Memory and SQLite repositories join the same transaction domain as other service
state. SQLite uses service-owned tables and SQLC queries, not opaque resource
blobs. An execution pins its admitted revision and alias/version identity;
later control changes do not rewrite that snapshot.

CloudFormation StateMachine and Activity claims live on their native incarnation
rows, alongside the existing private Version and Alias claims. Migration
`395_stepfunctions_top_level_ownership.sql` does not infer owners from existing
tags. Trusted creation admits a claim atomically; public tag edits and ordinary
native/Cloud Control configuration updates cannot adopt or transfer it.
Cloud Control creates can recover their own exact claim after a lost reply.
Recovery and no-op mutations still require current native IAM. Qualified rows
remain fenced by the actual machine ID, and retained executions continue to pin
immutable revisions after updates or parent deletion/recreation. These local
ownership guarantees do not establish complete CloudFormation or execution parity.

State transitions commit resource changes, history, deadlines and service
observations together. The scheduler discovers work from its resource owner.
Waits, retries, task/heartbeat expiry and execution retention use the injected
service clock. The current store is not a general MVCC fork, replay or time-travel
facility, and external effects do not become atomic with its transaction.

Task attempts retain their token, deadlines and accepted submission response.
External calls execute after commit through `internal/integrations` and the
same typed service command boundaries as public APIs. The generated command
input registry derives SDK operation names and shapes from the service models.
Execution roles and task-role overrides use actual STS/IAM authority; a workflow
does not borrow its creator's credentials. Interrupted external requests may
have ambiguous outcomes: recovery is not an exactly-once guarantee.

Lambda tasks run the configured official runtime container and Runtime API.
There is no in-process handler substitute. The determinism boundary is the
workflow/event edge, not customer code. A real CLI workflow has also exercised
S3 PutObject followed by SQS SendMessage, and an activity lease completed after
an actual SQLite-backed process restart.

Nested `.sync` admission assumes the execution role and configures the actual
regional EventBridge managed rule. Its retained deliveries release exact-child
subscriptions; reading retained execution state alone does not signal completion.
An executable SQLite workflow completed after both polling and EventBridge
permissions were removed. Removing the target instead left its parent RUNNING
after the child succeeded; granting DescribeExecution then completed it through
authorized polling. These local scenarios verify the two real completion paths,
not native crash/restart behavior after a previously delivered event is lost.

## Optimized ECS tasks

`ecs:runTask`, `.sync` and `.waitForTaskToken` call the real ECS owner through
the generated command boundary and execution-role authorization. ECS owns task
definitions, admission, container processes, networking, credentials and logs;
Step Functions does not emulate a second container lifecycle.

Request-response and TaskSubmitted return the RunTask envelope with actual SDK
metadata. Synchronous completion returns the bare stopped task, using the ECS
event projection and integer millisecond timestamps. Nonzero container exits
and TaskFailedToStart fail with `States.TaskFailed` and that task as the cause.
Ordinary API errors retain the `ECS.*` prefix. Per the
[AWS integration contract](https://docs.aws.amazon.com/step-functions/latest/dg/connect-ecs.html),
HTTP-200 nonempty Failures remain successful request-response output but fail
sync/callback tasks with `AmazonECS.Unknown`; this branch has documentation,
not a captured native failure payload.

Synchronous definitions reserve Count and StartedBy, including JSONPath member
expressions and static JSONata arguments. The integration supplies native
`StartedBy: AWS Step Functions`. Admission configures the actual
`StepFunctionsGetEventsForECSTaskRule` through execution-role EventBridge grants.
Its deliveries release task-specific observers; authorized DescribeTasks repairs
missed events. Callback tasks instead wait for their existing task-token owner;
container exit alone does not complete them.

Accepted response data is the recovery fence. Omitted ClientToken derives from
the committed task attempt and consumes ECS's own idempotency, without a second
request ledger. Parent abort/timeout attempts StopTask under renewed role
authority. Service shutdown interrupts observers without stopping accepted jobs.
Memory/SQLite real-container regressions exercise two-task request-response,
sync success/failure, event-only completion with DescribeTasks denied, reopen,
callback acknowledgement after container exit and parent cancellation. These
recovery and denied-polling cases are local integration evidence, not native
crash/cancellation/permission-removal observations.
An actual SQLite-backed executable restart during a running container also
completed with the same task ARN, one retained task and one TaskSubmitted event.

The September 24, 2026 Fargate probes left no running tasks; owned clusters were
inactive and owned machines, roles, security groups and managed rule were absent.
Task-definition deletion was accepted but still `DELETE_IN_PROGRESS` at the
post-cleanup read; physical registry disappearance is not claimed.

## Workflow tracing

Tracing uses the same retained history delivery cursor as Logs. Admission retains
the canonical public header and sampled workflow identity; history records retain
their frame, state-entry and redrive ownership. Projection reads those records
inside the repository transaction and publishes outside it. Memory and SQLite
preserve open span identities and timestamps across restart.

`internal/integrations/stepfunctions_tracing.go` is a client of the existing
X-Ray sampling and ingestion commands, authorized through the execution role.
Actual task commands produce API spans with their real request IDs and generated
wire-response sizes. X-Ray, not Step Functions, owns assembly and inferred
receivers. Publication failures are diagnostic and cannot fail or replay a task.
Entirely disabled, headerless tasks do not inject downstream trace headers.
Configured Distributed Map children have no workflow root; their actual SDK
edges carry independent unsampled context. Retained orphan API spans give the
captured empty X-Ray envelope without inventing a workflow segment.

## Native behavior retained in the implementation

- Pass, Choice, Wait, Task, Succeed, Fail, Parallel and Map execute transitions;
  JSONPath and JSONata do not share an invented common evaluation order.
- JSONPath `Assign` sees the native stage of state/task output. JSONata `Assign`
  and `Output` see the same entry variables. Child scope ownership is distinct
  from inherited bindings.
- Inline Map context supplies item index/value, not the fabricated
  `$$.Map.Item.Source = STATE_DATA`. A missing referenced context field fails
  with `States.Runtime`. Runtime failures terminate the execution rather than
  becoming catchable branch failures.
- Replacement inline iterations refer to the completed processor state's
  history event. Parallel branches can interleave differently; replay compares
  causal relationships rather than requiring AWS's thread ordering.
- State context exposes RetryCount for retry-capable state types; ordinary Pass
  states do not acquire it. Standard execution context exposes RedriveCount;
  the synthetic Express TestState context does not.
- An Assign operation counts serialized values, excluding variable names and
  object separators, against 256 KiB. Accumulated scopes can exceed that amount;
  execution-wide live variable storage is bounded at 10 MiB. History preserves
  assigned values and honors includeExecutionData.
- Native `$pad` allocation is bounded by newly added characters, not final
  string length or UTF-8 bytes. Concatenation, joining, and padding an existing
  string can produce larger intermediate strings. The evaluator uses its
  existing sequence-allocation guard; a separate global string cap would be
  incorrect. Its local time/recursion limits are not AWS allocator parity.
- Standard history terminates at the 25,000-event boundary with States.Runtime
  and the native history-limit cause. The terminal transition rolls back partial
  task/branch admission while retaining already admitted history. Express does
  not acquire the Standard history cap.
- Activity timeout and heartbeat clocks start at lease, not queue admission.
  Retried attempts have different tokens. Completion validity and an already
  issued heartbeat lease have distinct cancellation behavior.
- Omitted task timeout fields remain absent from scheduled history; the internal
  execution deadline is not exposed as an explicitly configured timeout.
- Execution timeout history/logs contain `States.Timeout`; the corresponding
  DescribeExecution and status-event error/cause remain absent/null. Those
  projections do not share an invented default error field.
- Lambda SDK Invoke returns its FunctionError envelope rather than failing the
  workflow automatically. Optimized/direct invocation propagates function
  errors. SDK text payloads, JSON objects, explicit JSON null and omitted bodies
  retain their different native meanings. Event invocation is acceptance, not
  synchronous function output.
- Deleting an active machine retains DELETING and its running executions until
  their next transition. New starts reject with StateMachineDeleting. A valid
  leased activity callback still acknowledges success; the next execution event
  is FAILED/States.Runtime with `State machine <name> has been deleted`, without
  ActivitySucceeded or a state-exit event. Wait behaves similarly when due.
  Physical deletion occurs only after executions terminate. Its worker latency
  is not pinned to captured AWS polling intervals.

## Customer-managed encryption

Machine revisions and Activities admit symmetric same-Region KMS keys through
the real KMS service. IDs, ARNs and aliases resolve to the retained key ARN.
Execution snapshots and published versions keep their original configuration
when a machine rotates to another key or returns to AWS-owned encryption.

`EncryptionKeys` separates forwarded API-caller authority from execution-role
authority. Caller operations use `kms:ViaService` for the regional states
service; execution roles call KMS directly, without that condition. State-machine
encryption context uses the unqualified machine ARN. Activity input uses the
Activity ARN/key, while role trust still uses the originating machine ARN.

Wrapped data keys and AES-GCM ciphertext protect retained definitions, execution
data, frame variables/arguments, task inputs/results and history payloads.
Metadata remains independently readable. Plaintext data keys are not persisted
in workflow repositories. Generated execution keys use the configured reuse
period; unwrapping authority is checked per transaction, with local reuse inside
that transaction rather than an assumed AWS worker-cache topology.

- Create needs caller DescribeKey/GenerateDataKey for a machine, but only
  DescribeKey for an Activity. Activities retain immutable encryption settings.
- Supplying an encryption configuration on Update requires a definition.
  Replacing an encrypted definition produces a revision even when its text is
  unchanged. A role-only update retains ciphertext without reading the old key.
- Ordinary metadata-only definition reads return `"{}"`; execution metadata
  omits input/output/error/cause and their data-detail fields. Labelled Map
  descriptions still decrypt and return their generated processor definition.
- History reads require Decrypt even with `includeExecutionData=false`.
  Activity workers require the Activity key, not the machine key.
- Populated callbacks encrypt under the execution role, not the callback caller.
  Empty failures and heartbeats need no caller KMS access. An accepted empty
  failure can still terminate with States.Runtime when the runtime cannot use
  the machine key; metadata-only reads hide that diagnostic.
- Runtime KMS failures terminate through the existing history, cancellation and
  observation owners. They do not leave the scheduler retrying inaccessible
  payloads indefinitely.

Workflow-CMK log delivery has a separate native boundary: the execution role
generates the log data key with `SourceArn = arn:<partition>:logs:<region>:<account>:*`
and `SourceAccount = <account>`; `delivery.logs.amazonaws.com` unwraps it.
Only the recovered plaintext enters Logs. A denied generation/decrypt remains
best-effort delivery failure, not execution failure. Log-group-at-rest encryption
is an independent Logs concern.

Native `encryption_admission.json` and `encryption_execution.json` fixtures cover
these authorities, updates, retained key references, disabled-key transitions,
callbacks and synchronous execution. Their SDK replays run against both stores
and reopen encrypted state and leases. An actual SQLite-backed CLI workflow also
sent an SQS message, recovered an Activity callback across restart, emitted CMK
logs and checked both log-key denial boundaries. SQL inspection confirmed empty
plaintext payload columns with retained ciphertext.

`encryption_logging.json` retains eight native logging cases, including direct
KMS denials and the two-entry Logs encryption context. Successful settled Express
controls delivered logs; the first immediate Express positive and negative
controls did not deliver during their bounded observation window. Settlement,
workflow duration and fresh-resource effects were not isolated. Replay checks
payloads and authority boundaries, not exact AWS delivery latency or KMS call
counts. Missing delivery-service Decrypt produced no Standard logs during a
729-second observation window; absence is not an unlimited-delivery guarantee.

`activity_missing.json` captures AWS terminating a task that references an absent
Activity with `States.Runtime`, after TaskStateEntered and without
ActivityScheduled. Both stores replay this boundary; missing metadata must not
leave the scheduler retrying a repository-not-found error.

## Authenticated HTTP Tasks

`arn:aws:states:::http:invoke` executes actual HTTPS through retained EventBridge
Connections and Secrets Manager. Admission evaluates `states:InvokeHTTPEndpoint`
with endpoint/method conditions under the execution role. Credential retrieval
independently requires the Connection and both secret permissions.

Connection headers/query/body parameters override exact task keys; header casing
is preserved through merge before HTTP canonicalization. JSON, raw bodies and the
four documented form-array encodings use the same request owner. Forbidden
headers, HTTP status failures, unsupported response content, invalid UTF-8,
payload limits, socket timeout and cancellation produce workflow failures, not
synthetic successful responses. The network deadline is bounded by AWS's
60-second HTTP Task ceiling and the task context. Retry/Catch remain workflow
state transitions. Optional OAuth 401 reauthorization is owned by the Connection.

`testdata/aws/stepfunctions/http_connections.json` retains native request
composition and immutable-role permission controls. Earlier mutable-role captures
are retained evidence, not proof of an IAM caching rule. Replay uses an actual
HTTPS/OAuth endpoint on memory and SQLite, including credential reacquisition
after reopen. A separate executable AWS CLI smoke verifies retained secret
versions and authenticated HTTP execution across a SQLite process restart.

See [Connection ownership](eventbridge.md#connections-and-managed-credentials)
and [AWS HTTP Task behavior](https://docs.aws.amazon.com/step-functions/latest/dg/call-https-apis.html).

## Account and Region admission

Public and in-process commands share nominal, per-account/Region API token
buckets replenished by service time. Standard and asynchronous Express
StartExecution use separate buckets; StartSyncExecution has no invented fixed
bucket. Admission rejects with HTTP 400 `ThrottlingException`, `Rate exceeded`.
Generated request decoding still precedes service admission. StartExecution
resolves and authorizes its machine before choosing the Standard/Express bucket;
the capture does not establish every IAM, lookup and validation precedence.

Standard state entries and retries share a regional transition bucket. A denied
entry retains a future frame deadline rather than failing the execution or
appending a false state-entry event. Express transitions bypass this bucket.
Task callbacks, Wait completion and execution deadlines are not new entries.
The scheduler uses scheduled service time, so advancing a manual clock can drain
transitions that became eligible during the elapsed interval.

Resource admission counts retained state in the same transaction as creation:
100,000 registered machines, 100,000 activities and 1,000,000 running Standard
executions per partition/account/Region. Idempotent requests do not consume a
new slot; DELETING machines retain theirs until removal. Closed and Express
executions do not consume Standard capacity. Public starts and redrives share
execution-capacity ownership with Distributed Map child admission. Pending
Standard children wait for capacity; a retained one-second service-time retry
allows unrelated executions to release slots. That interval is a local scheduling
choice, not measured AWS latency.

Fixture-driven SDK regressions exercise rejection, authorization, idempotency,
rollback, concurrent last-slot admission and recovery on both stores. Their
test-only occupied-count offsets avoid creating a million records; they do not
establish native quota-exhaustion precedence or exact native error messages.
Separately, the SQLite executable was reopened with 100,000 actual activity rows
derived from an SDK-created seed: it rejected the next activity, retained
idempotency, released/reused a deleted slot and isolated account/Region counts.

`api_throttling.json` retains a read-only AWS burst, semantic-invalid definitions
rejected while throttled, eventual successful recovery, applied quota reads and
complete default catalogues from us-west-2 and us-west-1. Native default values
override stale prose entries: DescribeActivity is 200/20, DescribeExecution
300/50 and RedriveExecution 800/150 in both captured Regions (capacity/refill
per second). Other regional tiers follow the
[published quota groups](https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html).

These process-local budgets reset on restart. They model published nominal
admission, not AWS's private fleet allocator, custom applied quotas or an exact
throttle ordinal. The native burst exceeded its nominal bucket; its success count
does not establish a replacement capacity. No resources were created by this
capture. Resource-count quotas and Map-run/HTTP-task dispatch budgets remain
separate work.

Verification: focused quota SDK checks passed on memory/SQLite, including
Standard/Express StartExecution separation. Deterministic scheduler regressions
cover retries, Wait completion, deadline priority, transactional metrics and
bounded parallel-branch retries. A SQLite-backed executable completed a
1,001-entry workflow after virtual-time refill and exposed 201 throttled entries
through the actual CloudWatch API. After shared discovery snapshots and prepared
workflow queries, the complete 25,000-history-event SQLite fixture passed in
43.11 seconds with `TMPDIR=/dev/shm`, retaining production SQL and
`synchronous=FULL`. An ordinary disk-backed run exceeded 180 seconds at 21,099
events; this is not a claim that disk-backed execution meets the same bound.
Reopening that retained state with fresh process-local admission budgets
completed in 6.36 seconds and matched the native terminal status, error and cause
at exactly 25,000 history events. Targeted cross-service/reopen checks and
scheduler/memory race checks passed; no full-repository verification cycle ran.

## Evidence and replay

Native captures are in `testdata/aws/stepfunctions/`. Each retains the actual
requests/results, probe source, scope and cleanup evidence. Probes used owned
resources in account `000000000000` and retain their Region: primarily
`us-west-2`, with ECS integration captures in `us-east-1`. Ordinary replay uses
explicit local credentials and needs no AWS account.

| Capture | Evidence / local verification boundary |
| --- | --- |
| `control_lifecycle.json`, `create_identity.json` | Native definition identity, first publication, versions/aliases, pinned snapshots and deletion visibility; SDK replay on memory/SQLite. Immediate alias reads allow an acknowledged old or new whole configuration, not mixed fields. |
| `dataflow_execution.json` | Native state language, nested scopes, intrinsics, context and causal history; SDK replay on both stores. |
| `callback_lifecycle.json` | All sixteen workflows replay on both stores, with SQLite reopen after leases: retries, token/output validation, heartbeat/task/execution deadlines, explicit stops, Parallel/Map sibling cancellation with and without Catch, the empty 60-second poll and resource cleanup. Ten consecutive complete local runs passed. Concurrent leases match payloads rather than worker order; token ownership and causal histories remain checked. |
| `test_state_mock.json` | Native TestState mock validation and inspection semantics, including actual captured rejected inputs; local SDK replay excludes account-throttled attempts that contain no state-evaluation result. |
| `api_throttling.json` | Native API throttle status/code/message, semantic-validation precedence, idle recovery and regional default/applied quota values. Deterministic local bucket boundaries are not a replay of AWS's exact fleet allocation. |
| `variable_limits.json` | Native assignment/scope limits and 25,000-event failure; local replay exercises the boundary, history projections and cleanup on both stores. |
| `expression_limits.json` | Six allocation probes distinguish padding growth from total string size; local TestState replay on both stores. No resources were created. |
| `lambda_integrations.json` | All 21 workflow executions and six direct Invokes replayed against real Python 3.12 runtime containers on memory/SQLite, including asynchronous delivery observed in actual logs. Optimized metadata retains status, service headers and consistent request IDs; only transport-specific fields and representation-dependent lengths are normalized. |
| `deletion_lifecycle.json` | Both stores replay active deletion, DELETING visibility, leased callback acknowledgement and exact failure history, actual EventBridge-to-SQS terminal delivery, SQLite reopen and eventual physical absence. Native resources were verified absent after capture. |
| `task_integrations.json` | Both stores replay 140 native observations and 24 histories through observation 163: actual S3/SQS effects, callback tokens, role/trust changes, nested `.sync`/`.sync:2`, managed-rule admission and retained configuration. Ten consecutive local runs passed. Transient polls, an unsettled IAM attempt and final cleanup are not semantic assertions. |
| `ecs_workflows.json`, `ecs_admission_attempt.json` | Owned Fargate captures establish request-response Count2, bare sync completion/failure, real task-role callback, managed-rule authority/pattern and millisecond task projections. The initial unsupported-Count attempt remains separately identified. Local real Docker workflows pass on memory/SQLite; they are not a field-for-field replay of every native task attribute. |
| `ecs_schema_admission.json`, `ecs_api_errors.json` | Native Count/StartedBy reservation, callback Count2 schema acceptance, ordinary `ECS.ClientException`, and TestState rejection of sync/callback patterns. SDK replay compares errors and diagnostic codes/locations without pinning diagnostic prose or generated request IDs. Missing task definition precedes missing cluster in the captured RunTask request. |
| `distributed_map.json` | Both stores replay all seven retained consumer cases: S3 readers/writers, child histories and definitions, batching, JSONata transformations, tolerated failures, pending cancellation, manifest/object bytes and counts. Running children and exported results survive SQLite reopen. |
| `observability.json` | Both stores replay eight captured executions through actual Logs, EventBridge-to-SQS, CloudWatch metrics and CloudTrail management history, with SQLite reopen and retained consumer checks. An immediate Express update observed the preceding revision; this is not evidence of a fixed propagation delay. Management-history absence is not a captured positive StartSyncExecution data-selector test. |
| `sdk_admission.json` | Twenty-five read-only native validation cases replay on both stores: SDK member casing, required streaming body, missing-parameter precedence, nested members, arbitrary map keys, deferred expressions, integer lexical types and boolean coercion boundaries. Earlier controls also have executable CLI checks. No AWS resources were created. |
| `sdk_requests.json` | Real TestState SDK calls write/read S3 objects and list their actual owners on both stores, with SQLite reopen before retained checksum reads. Captures distinguish default CRC32, supplied/computed SHA256, conflicting algorithms, invalid digests and boolean scalar conversions. Settled retries replace captured IAM-propagation failures; service diagnostic prose is not pinned. All owned native buckets and roles were confirmed absent after capture. |
| `redrive_execution.json` | 294 native observations, including the read-only metrics supplement. Both stores replay retained revision/input/state-entry context, selective Parallel/Inline Map recovery, retry reset, fresh callback leases, rejected stale tokens, terminal-state admission, idempotent token responses and causal history. SQLite is reopened before every redrive and token replay. CloudWatch comparisons retain counter statistics and first-attempt duration sample populations, not wall-clock duration values. |
| `redrive_map.json` | 821 observations retain all probe attempts; replay selects the settled Standard/role-denial and Express attempts. Both stores exercise actual S3 repair, selective Standard child redrive, Express processor restart, pending admission, execution-role StartExecution/RedriveExecution denial, retained child identities, immutable ResultWriter generations and cumulative success manifests. Native trust-confounded attempts remain evidence, not successful recovery assertions. |
| `tracing_control.json` | Both stores replay selected native Standard/Express configuration and header-admission cases, HTTP-header precedence, execution-role publication authority and pinned revisions. Open Wait trace identities survive SQLite reopen. Scoped zero-rate rules were not proven selected by AWS; their captures do not establish regional rule-matching parity. |
| `tracing_workflows.json` | Both stores compare actual workflow, state, Branch/Iteration and SDK SQS documents; inferred SQS/QueueTime receivers; retry/fault topology; received Root/deepest API Parent; Distributed Map child empty envelopes; and the unchanged original Activity trace after redrive. Open Activity spans survive SQLite reopen. Publication-lag samples and clock magnitudes are not pinned. |
| `tracing_sdk_headers.json` | Both stores replay actual SQS deliveries with supplied Sampled=0/1 and disabled/headerless executions. Bounded native X-Ray reads lacked a positive control and are not absence assertions. Owned native resources were independently confirmed absent. |

SDK task templates use generated model members with the Java SDK naming
convention. Admission requires top-level method arguments and streaming bodies;
it does not enforce nested service-required fields. Actual destination commands
still own their input validation and authorization. SDK streaming bodies preserve
the serialized JSON document; nonstream blobs use text bytes rather than treating
base64-looking strings as encoded input. Checksums cover the final actual body.

An explicitly supplied checksum suppresses the SDK's default CRC32, but an
explicit algorithm still requests its own checksum; conflicting checksum headers
remain a destination error. SDK boolean admission and binding share one coercion
owner: native string/integer conversions do not relax public AWS JSON decoding.
Native S3 listings verify whether owner fields are present after conversion,
including zero/nonzero integers, trimmed uppercase strings and empty/null strings.

An actual SQLite-backed CLI smoke exercised supplied SHA256 writes, owner-flag
conversions and both checksum failure classes. After process restart, TestState
HeadObject and a direct S3 GetObject retained the checksum and actual object bytes.
The CLI adds `sync-` to TestState endpoint hosts: the smoke used
`http://api.localhost:45231` with working `*.localhost` loopback DNS, rather than
a numeric host. Direct S3 CLI reads used the numeric path-style endpoint.

Replay compares task payloads and destination contents, not client scheduling
latency. After draining actual effects, task-fixture SQS receives use zero wait,
as the existing SQS metric fixtures do; this is not long-poll conformance evidence.
SQS batch boundaries and independent Parallel branch completion order can differ.
Branch histories retain their predecessor chains; joins bind to the owning
Parallel barrier rather than whichever branch happened to finish last.
CLI-implied S3 checksum retrieval and list URL encoding are explicit in Go SDK
replay. Empty S3 metadata maps have no HTTP representation; Go returns nil where
the CLI emits `{}`. Cross-field timestamp bindings allow the one-millisecond
loss caused by the Go Smithy epoch decoder, not arbitrary clock drift.

Optimized results retain `SdkHttpMetadata` and `SdkResponseMetadata` from the
actual command request ID and service-owned response encoder. Lambda preserves
its invocation-specific status/content type; SNS uses the same Query envelope
as its HTTP frontend. Nested StartExecution submission has metadata, while final
`.sync` results, direct Lambda ARNs and ordinary `aws-sdk` task outputs retain
their distinct native projections. No command is executed again to obtain headers.
`HttpHeaders` retains the last value from `AllHttpHeaders`, matching the
[AWS Java SDK metadata contract](https://raw.githubusercontent.com/aws/aws-sdk-java/master/aws-java-sdk-core/src/main/java/com/amazonaws/http/SdkHttpMetadata.java).

Native task, tracing and real-container Lambda replays compare these envelopes.
A fixture-derived SDK workflow selects metadata through ResultSelector and
checks encoded length against a public SQS response. An actual SQLite-backed CLI
workflow consumed SQS and SNS metadata: HTTP 200, matching request IDs across
both header maps, 106-byte SQS and 270-byte SNS response bodies, with the queued
message ID and payload matching its workflow result. These lengths describe that
smoke, not fixed service response sizes.

Redrive preserves the original execution ARN, input, revision, successful state
results and state-entry history. Standard children resume failed state frames;
Express Map children restart their processor with a new start time while keeping
their ARN. Query names for Express children include the Express execution ID;
context and ResultWriter names do not. Execution-role authority is checked
outside the state transaction before admitting or redriving Map children.

ResultWriter retains typed references to successfully written files. Redrives
write into `Redrive-N` directories, retain prior successful-file references and
replace failed/pending references with the current generation. A permission-denied
generation with prior successes still writes the observed empty success file.
Replay rereads earlier objects and reopens SQLite to check immutable bytes.

The Map capture includes a concurrency race: native item 3 completed before the
failure stopped admission, while it can remain pending locally. Replay permits
only that identified item to take the pending path, carries the difference
through counts and historical export generations, then checks its newly admitted
output against repaired S3 contents. Other child errors, ownership, redrive
counts and causal histories remain compared.

A SQLite-backed CLI smoke failed an Activity, restarted the process, changed the
machine definition and redrove the original execution. It retained the original
input/definition, obtained a fresh token and completed successfully. After another
process restart, replaying the client token returned the original redrive date
without another state entry or redrive event. Owned native roles, machines,
Activities, buckets and objects were confirmed absent; AWS retains completed
execution histories because there is no DeleteExecution API.

A second actual CLI smoke used the regenerated SQLite bootstrap and manual
service time. It verified that a combined Parallel output exceeding 256 KiB
fails with `States.DataLimitExceeded`, then reruns both formerly successful
branches on redrive and returns their repaired outputs. Signed raw HTTP calls
checked named-token retention across twelve tokenless redrives, last-ten-token
eviction, replay at 14m59s and expiry at 15m. An actual missing S3 ItemReader
object failed its Map Run; repairing the object and redriving reused that Map
ARN, reread the object and completed two child executions. These are local
behavior checks, not additional native-AWS observations.

An actual tracing-enabled CLI workflow leased an Activity before stopping the
SQLite-backed executable. After restart, the same open root/state IDs and start
times remained visible. Completing the retained token closed those spans and
sent a real SQS message whose trace Parent matched the deepest API span. That
span reported the generated SQS response's HTTP 200 and 106-byte body.

Primary references include the AWS [ASL specification](https://states-language.net/),
[variables](https://docs.aws.amazon.com/step-functions/latest/dg/workflow-variables.html),
[quotas](https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html),
[DeleteStateMachine](https://docs.aws.amazon.com/step-functions/latest/apireference/API_DeleteStateMachine.html),
[Lambda integration](https://docs.aws.amazon.com/step-functions/latest/dg/connect-lambda.html),
[nested executions](https://docs.aws.amazon.com/step-functions/latest/dg/connect-stepfunctions.html),
[RedriveExecution](https://docs.aws.amazon.com/step-functions/latest/apireference/API_RedriveExecution.html),
[state redrive behavior](https://docs.aws.amazon.com/step-functions/latest/dg/redrive-executions.html),
[Step Functions tracing](https://docs.aws.amazon.com/step-functions/latest/dg/concepts-xray-tracing.html),
[SQS trace propagation](https://docs.aws.amazon.com/xray/latest/devguide/xray-services-sqs.html),
[encryption at rest](https://docs.aws.amazon.com/step-functions/latest/dg/encryption-at-rest.html),
and [CloudTrail event categories](https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cloud-trail.html).

Focused verification:

```sh
go test ./integration -run '^TestStepFunctionsNative' -count=1 -timeout=10m
STACKD_LAMBDA_DOCKER=1 go test ./integration -run '^TestStepFunctionsNativeLambdaDocker$' -count=1 -timeout=10m
```

The second command requires the existing pinned Python image and Lambda telemetry
helper. Without the explicit Docker gate, the real-runtime test is skipped, not
counted as passing runtime evidence.

After tracing integration, the native Step Functions and X-Ray replays, SQS
tests and EventBridge-to-Step-Functions admission fixture passed under `-race`
in 2,301.857 seconds with `STACKD_LAMBDA_DOCKER=1`. This includes the
25,000-event history boundary, real Lambda execution, redrive, callback recovery,
distributed Map, observability, SDK/task integrations and all three tracing
captures. Affected service/integration/storage package race checks also passed.
Formatting, `go vet ./...`, `go tool staticcheck ./...` and
`make generate-check` passed. The whole-repository race suite was not rerun at
this checkpoint.

## Remaining boundaries

- Complete application-facing operation and recovery gaps before further quota
  refinement. Open Map Run limits, Map/HTTP dispatch rates, applied overrides and
  native fleet-allocation/precedence conformance remain open, not prerequisites
  for moving to the next service.
- Native redrive captures do not establish age/history/quota boundaries,
  15-minute token expiry/last-ten-token eviction, DataLimitExceeded composite
  restart, version/alias pinning or nonzero pending-redrive queue timing.
  The documented limits are not a claim of differential coverage.
- HTTP private connectivity depends on unimplemented Connection resource associations.
- Tracing still needs native evidence for scoped sampling-rule field selection,
  fleet quota timing, history-limit topology, trace-size freezing and SDK-task
  redrive beyond the captured Activity case. Best-effort observation is not
  complete tracing parity.
- AWS worker-cache placement and every in-flight key/policy transition are not
  established by isolated warm observations. Replay keeps cold/expired controls
  exact and explicitly bounds the two observed warm-admission cases.
- Internal optimized calls expose actual service response metadata, not AWS
  gateway Date/Connection/remapped headers. Those network-hop fields are not
  synthesized and are explicitly excluded from differential comparison.
- Express memory accounting is an estimate based on definition/data/parallelism,
  not AWS's private allocator. Exact billed-memory conformance remains open.
- Regional/account limits and external-effect crash ambiguity remain explicit
  work. Captured branch cancellation does not establish recovery from every
  interrupted external request or indefinitely accepted post-cancellation heartbeats.
