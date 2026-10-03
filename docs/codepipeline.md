# CodePipeline orchestration and artifact ownership

CodePipeline is a prerequisite for the existing AppConfig source integration,
not a whole-service parity claim. The generated AWS SDK model selects **all 44
operations**. The kernel owns scoped definitions, immutable versions, execution
and action history, tags, stage transitions, source revision bindings and S3
artifact references. S3 owns the bytes; CodeBuild owns actual build execution;
AppConfig owns configuration deployment and retrieval; Lambda owns real function
execution and its independent execution-role authority.

## Commands and execution semantics

The implemented command families are:

- `CreatePipeline`, `GetPipeline`, `ListPipelines`, `UpdatePipeline`,
  `DeletePipeline`: account/partition/region scope, independent version history,
  tags and immutable pipeline incarnations. With polling disabled, creation
  atomically admits the initial execution. Enabled sources instead independently
  admit executions after observing a source revision. Updating itself does not
  start an execution, but an enabled new/changed source can do so. A pending
  Manual approval becomes `Failed` with its token hidden in **GetPipelineState**,
  but the old pipeline/stage and **ListActionExecutions** retain `InProgress`.
  Its old approval token rejects as out of date. Native observation through
  127 seconds did not establish natural terminal cancellation. The kernel keeps
  polling admitted provider work, then parks old advancement without inventing a
  terminal outcome; explicit stop-abandon remains available. Natural settlement
  after definition updates remains an explicit gap.
- `StartPipelineExecution`: explicit execution, client-token replay, S3
  object-key/version overrides and pipeline variable overrides. A retained token
  returns the original execution even with changed valid overrides; shape,
  duplicate-variable and source-action validation still precede replay.
  An object-key override remains bound when its original version is resolved.
  [Scheduler templated targets](scheduler.md#codepipeline-templated-targets)
  invoke this same owner under current role authority, but ignore their
  `Target.Input`; they do not forward execution overrides or supplied tokens.
  Scheduler retains ordinary `StartPipelineExecution`/assumed-role attribution.
- `GetPipelineExecution`, `ListPipelineExecutions`, `ListActionExecutions`,
  `GetPipelineState`: actual retained execution/action outcomes, source revisions,
  provider handles, artifact locations, original and resolved configuration,
  native provider output variables and manual approval tokens.
  `ListActionExecutions.latestInPipelineExecution` selects the requested execution:
  `All` retains every started attempt; `Latest` retains the newest started attempt
  per action, including successful actions from before a later-stage retry.
  Unstarted retries do not hide the preceding attempt. Both execution selectors
  intersect when supplied together; the top-level execution must exist.
  Pagination binds account/region/partition, pipeline incarnation, execution and
  selection. Equivalent top-level and nested `All` filters share tokens.
- `EnableStageTransition`, `DisableStageTransition`: inbound/outbound holds.
- `StopPipelineExecution`: stop-and-wait preserves admitted actions and starts no
  subsequent actions; stop-and-abandon fences their results and marks them
  abandoned. Manual approval remains valid during stop-and-wait; abandon
  invalidates its token with `InvalidApprovalTokenException` and retains the
  cancellation summary. Abandon deliberately does **not** cancel a CodeBuild
  process or other underlying provider work.
- `RetryStageExecution`: failed/stopped current-version stages with
  `FAILED_ACTIONS` or `ALL_ACTIONS`. New attempts receive new action IDs and
  output locations; previous attempts remain history. The pipeline execution
  attempt increments on each retry, independently of each action's attempt.
  A newer execution entering the stage makes an older failed execution nonretryable.
- `RollbackStage`: an independent manual rollback execution runs only the selected
  stage, using the successful target's retained inputs and variables. It does not
  advance downstream stages; see [manual stage rollback](#manual-stage-rollback).
- `PutApprovalResult`: current token, approve/reject, terminal-token rejection,
  retained deadline and seven-day default timeout. Actual decisions retain the
  submitter ARN. History exposes the action UUID as the external execution ID;
  current Manual action state exposes neither that ID nor a completed token.
  Approval/rejection summaries do not fabricate SDK error details. The native
  rejected-action event's `JobFailed` classification belongs to the event owner.
- `PutJobSuccessResult`, `PutJobFailureResult`: retained Lambda job callbacks,
  continuation, output variables and idempotent exact replay; custom and
  third-party worker acquisition protocols remain unimplemented.
- `TagResource`, `UntagResource`, `ListTagsForResource`: current resource tags and
  request/resource tag IAM context, deterministic scoped pagination.

A stage admits actions by `runOrder`; equal run orders are one group and later
orders wait for success. `QUEUED` executions lock stages in order rather than
serializing the entire pipeline. `SUPERSEDED` replaces waiting executions, never
an action already admitted into a locked stage. `PARALLEL` executions do not share
stage locks. QUEUED and PARALLEL require V2. Pipeline updates stop advancement of
old definitions without changing their retained action inputs.

Supported action families are AWS S3 Source/Deploy, CodeBuild Build/Test, AppConfig
Deploy, Manual Approval and Lambda Invoke. S3 sources support retained source-change polling.
Use `PollForSourceChanges=false` for explicit starts or the EventBridge target
integration without duplicate polling triggers. No other action provider is
simulated. CodeBuild permits the
provider's 1–5 inputs and 0–5 outputs, not arbitrary generated artifacts.
The AppConfig guide labels `DeploymentStrategy` optional, but the observed native
AWS `ListActionTypes` provider catalog marks it `required:true` and supplies no
default. Admission follows that native catalog and requires the explicit strategy;
the guide/catalog discrepancy remains recorded rather than guessing a default.

### Manual stage rollback

[`RollbackStage`](https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_RollbackStage.html)
creates a new execution UUID with `executionType=ROLLBACK`, a `ManualRollback`
trigger and `rollbackMetadata.rollbackTargetPipelineExecutionId`. The target must
belong to this pipeline incarnation, use the current definition version and have
succeeded in the selected stage; a rollback execution cannot itself be a target.
Unknown stages/executions reject, changed definitions return
`PipelineExecutionOutdatedException`, and an active stage rejects with
`UnableToRollbackStageException`. The native captures completed manual rollbacks
in `SUPERSEDED`, `QUEUED` and `PARALLEL` modes.

Only the selected stage runs. Earlier and later stages keep their actual execution
owners, and a successful rollback does **not** deploy downstream. Non-source
actions consume the target's retained S3 artifact references and upstream action
variables, plus its resolved pipeline variables. New action IDs/output locations
belong to the rollback; source actions and their history are not copied into it.
Current execution-role IAM still authorizes the real provider effects. Failed or
stopped rollbacks use the existing stage retry owner; active rollbacks support
stop-and-wait/abandon without cancelling underlying provider work.

Schema 314 retains rollback target identity and the selected stage. Admission,
stage reservation and lifecycle events commit in the shared transaction, so
concurrent rollback admissions cannot both reserve one active stage. The scheduler
and retained typed histories recover execution and artifact lineage after restart.
No source bytes or generic snapshots become authoritative.

There is a measured documentation/API discrepancy:
the [rollback guide](https://docs.aws.amazon.com/codepipeline/latest/userguide/stage-rollback.html)
says source stages cannot roll back, but both native API captures accepted that
request. The detailed capture shows a source-only rollback reading the **current**
S3 revision into a new artifact, while execution-level revision history still
reports the target revision. Action history and current source state report the
actual newly read revision. This implementation follows that observed API behavior,
not a fabricated source-stage rejection. The
[manual rollback guide](https://docs.aws.amazon.com/codepipeline/latest/userguide/stage-rollback-manual.html)
also documents current-version eligibility and independent rollback execution IDs.

The [native summary](../testdata/aws/codepipeline/rollback_native_summary.json)
links two complete captures of IDs, history, stage ownership, variable/artifact
selection, invalid IDs, source-stage behavior, definition changes, active-stage
rejection, stop/abandon/retry and all three execution modes.
[Independent cleanup checks](../testdata/aws/codepipeline/rollback_native_cleanup.json)
verify both pipelines absent, all four buckets returning 404 and both roles
returning `NoSuchEntity`.

The [executable proof](../testdata/integration/codepipeline_rollback_executable.json)
deploys `v1`, then `v2`, permanently removes the original `v1` source object
version, restarts SQLite and rolls the live destination back to actual `v1` bytes
using the original artifact locator. The downstream `v2` object **and its version**
remain unchanged. It also verifies restored variables, rollback metadata,
stage-specific history/ownership, caller IAM denial without history mutation,
provider IAM failure/retry and outdated-target rejection. Four controllers exit
zero; the owned pipeline, three buckets, two roles and inline policies are removed.
Signed Go SDK regressions exercise memory/SQLite, removed source bytes, restart,
upstream/pipeline variables, current-role failure/retry, source-stage revision
splitting and region isolation. Kernel regressions cover concurrent admission,
stage-only completion and state/event transaction failure.

Automatic entry/success/failure conditions and rollback rules remain explicitly
unsupported. Native transition-disabled rollback, broad quotas/retention expiry,
cross-account/cross-region providers and complete error-precedence parity remain
uncalibrated; these captures do not establish those behaviors.


### S3 source-change polling

Omitting `PollForSourceChanges` enables polling. Native accepts nonempty strings:
case-insensitive `true` enables; measured `False`, `yes` and `1` disable. Empty
values fail generated map-value validation. Each source action owns a retained
version cursor; a new S3 VersionId triggers even when bytes and ETag are unchanged.
Two enabled source actions independently admit two initial executions, rather
than coalescing them. Execution attribution is `PollForSourceChanges` with the
source action name as `triggerDetail`.

The shared scheduler observes actual versioned S3 objects under current role
authority, outside transactions. Schema 281 retains per-action revision cursors,
claims, errors and deadlines. Cursor consumption and execution/event admission
commit atomically. Definition versions, generations and pipeline incarnations
fence stale observations. Shutdown leaves claims recoverable; restart does not
replay an already consumed revision.

Disabling polling preserves its cursor. First enable on a previously unpolled
source admits its existing revision; disabling/re-enabling an already observed
source does not repeat that revision. Changing bucket/key starts a fresh cursor.
Native unchanged-toggle observation lasted 395.6 seconds and was followed by a
positive fresh-version trigger; this is bounded evidence, not a claim about
unbounded timing.

Missing or denied sources do not consume their revision or invent an execution.
Their source-action state reports `ConfigurationError` or `PermissionError`
without action execution ID/current revision; previous stage execution history
remains intact. Restoring access admits the same previously denied revision.

Local polling uses one minute of service time with a 30-second recoverable claim
lease, not a claimed exact AWS cadence. The documented greater-than-30-day
no-execution rule disables polling and retains `metadata.pollingDisabledAt`.
Native reactivation after this automatic disable remains uncalibrated; the
timestamp is not silently cleared. Explicit executions and EventBridge remain
separate from polling.

### S3 deployment

The [S3 deployment provider](https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-S3Deploy.html)
reads the admitted input artifact's retained S3 version and writes actual objects
through the existing S3 owner under the current action role. One input and no
output artifacts are required. `Extract=false` uploads the original bytes;
`Extract=true` deploys ZIP members. `CacheControl`, `CannedACL` and
`KMSEncryptionKeyARN` reach actual S3 authorization, ACL and encryption behavior.
No archive paths are materialized on the host.

Native admission requires `BucketName` and `Extract`, rejects unknown configuration
keys, but permits noncanonical nonempty `Extract` values and a missing `ObjectKey`.
Execution accepts only literal `true`/`false`; false without an object key fails
with `ConfigurationError`. A malformed ZIP fails with `JobFailed`, and destination
write denial reports `PermissionError`. Explicit failed-action retry consumes the
same retained input artifact, not the source bucket's newest version.

Extraction preserves a leading slash, converts member backslashes to slashes,
skips directory entries and uploads symlink target bytes without following links.
Duplicate members produce sequential writes. `ObjectKey`, when provided during
extraction, is a literal prefix plus `/`; `prefix/` therefore produces
`prefix//member`. An encountered `../` fails with `ConfigurationError` **after**
earlier entries have been written. There is no synthetic object rollback.

Raw uploads use `application/octet-stream`. Extracted content types use a
deterministic table of native-observed extensions, without host MIME registries,
content sniffing or charset suffixes. Remaining extension mappings and native
encrypted-ZIP diagnostics remain uncalibrated. ZIP extraction has explicit local
limits of 512 MiB compressed/total expanded bytes and 100,000 entries, not claimed
AWS quotas. Encrypted members fail explicitly.

The [native summary](../testdata/aws/codepipeline/s3_deploy_native_summary.json)
links five complete, cleaned captures, including actual bytes, metadata,
admission/runtime distinctions, duplicate versions, partial writes and same-source
retry. The [executable evidence](../testdata/integration/codepipeline_s3_deploy_executable.json)
verifies raw customer-key-encrypted bytes, extracted website content and cache
metadata, current IAM denial/retry, immutable artifacts through source replacement
and restart, and corrupt-archive failure. Four controllers exit zero and all seven
owned resources are removed; the customer KMS key is verified absent after its
scheduled deletion deadline. Signed Go SDK coverage runs on memory and SQLite and
also verifies partial writes with a leading-slash key. The same scenario passes
under `GODEBUG=zipinsecurepath=0`.

### Lambda invocation and job callbacks

The [Lambda action](https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-Lambda.html)
invokes the actual Lambda owner asynchronously through its real runtime and
Runtime API. Ordinary function return does not complete a pipeline action.
`PutJobSuccessResult` and `PutJobFailureResult` authenticate the caller's current
authority and commit typed job receipts separately from execution advancement.
Schema 282 retains these jobs and output variables across controller restart.

Continuation issues a new job ID while retaining the action execution ID and
reserved artifact locations. Supplying continuation and output variables together
is rejected without consuming the job. Exact callback replay is idempotent;
changed or opposite terminal results fail with `InvalidJobStateException`.
Native accepts a late result after abandonment without reviving the action, and
accepts identical replay after pipeline deletion. Those receipts survive deletion.
Wrong-region and unknown job IDs return `JobNotFoundException`.

The function receives short-lived pipeline-role artifact credentials restricted
to its input/output objects, independently of its execution-role credentials
used for callbacks. Consumers read real S3 bytes under current IAM authority.
Success trusts the worker's reserved output locations: missing output fails in
the downstream consumer, not retroactively in Lambda. FunctionName is the native
external execution ID; callback-supplied external IDs and success summaries do
not replace it. Callback failure type projects into both surfaces. Failure text
appears in the history summary but in current-state error details, not its summary.

The [native evidence summary](../testdata/aws/codepipeline/lambda_native_summary.json)
links the successful transform/continuation/deploy capture and focused
abandon/delete replay capture. The initial capture retains an unsuccessful
prefix expectation; its resources were also cleaned. Native probes did not
measure timeout durations, wrong-account scope, the full credential action matrix
or output-variable size boundaries. The documented twenty-minute job deadline
and twenty-four-hour action bound use service time. Dispatch interrupted before
its accepted acknowledgment is committed remains at-least-once.

The signed Go SDK scenario runs on memory and SQLite with real Python Lambda
containers. The [executable proof](../testdata/integration/codepipeline_lambda_executable.json)
retains 81 successful API calls, three clean controller exits and ten successful
resource cleanup actions. It observes a pending job after ordinary return,
restarts before continuation, denies artifact credentials access to an unrelated
object, transforms the original retained ZIP despite source replacement, deploys
`{"value": 18}`, rejects changed replay and reopens terminal history. A subsequent
missing-function execution verifies the distinct history/current-state failure
fields and Lambda console link.

### Pipeline-level variables

V2 definitions retain ordered variable declarations, optional defaults and
descriptions. Each execution binds defaults and supplied values once; retries,
definition updates and restart never rebind historical execution values.
Unknown override names are ignored. Duplicate override names reject before token
replay. Missing required values admit a failed execution with HTTP 200 and no
resolved bindings or action attempts, including the initial creation execution.

`#{variables.Name}` is resolved once in non-Source action configuration; inserted
values are not recursively interpreted. Nonempty declarations reserve the
`variables` namespace; without declarations, an action may still own that name.
Omitted and explicitly empty declaration lists remain distinct through SQLite.
Resolved values use deterministic declaration order; native multi-variable order
is undocumented, so name/value maps—not incidental ordering—define conformance.

Schema 280 adds normalized declaration/binding tables and removes obsolete
request hashes. Omitted pipeline type with nonempty variables infers V2 from the
[documented V2-parameter rule](https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PipelineDeclaration.html);
the retained native omitted-type observation covers updating an existing V2
pipeline. Variable-bearing Manual `NotificationArn` follows documented non-Source
substitution and delegates the resolved target to real SNS; this particular
configuration field was not separately measured in the native capture.

### Manual approval notifications

`NotificationArn` publishes through the existing SNS owner using the pipeline/
action role's current authority. Subscribers receive real SNS delivery, including
SQS consumers that approve through `PutApprovalResult` using the notification
token. Resolved action configuration supplies optional custom data and review URLs.
Native payloads use Codesuite console/review links, minute-precision UTC expiry,
and explicit JSON nulls for omitted optional fields. Subject pipeline/action names
longer than 24 characters use their first 24 characters plus an ellipsis.

The retained action owns its token, deadline and private SNS publication ID.
Schema 279 persists publication completion; an ordinary reopen does not republish.
Effects run outside the resource transaction. A crash after SNS acceptance but
before completion commits can repeat the publication; this is an explicit
at-least-once window, not an exactly-once claim. Update, abandon, approval and
expiry fence late results. Stop-and-wait preserves admitted work and retains
its completed publication even when the scheduler generation changes.

Missing/currently denied publish authority settles as `PermissionError`; native
state hides the failed approval token while history retains the action UUID,
summary and error code. Approving that failed UUID returns
`ApprovalAlreadyCompletedException`. Granting permission alone does not restart
the action: explicit stage retry creates a new attempt and notification.
Malformed, wrong-service and wrong-region topic ARNs reject at admission.
FIFO and absent-topic declarations are admitted; their publication uses SNS's
actual authority/data plane. Existing FIFO and absent same-account topics settle
as `ConfigurationError`, with native state/history projections. Cross-account
publication succeeds with both the publisher's identity grant and the topic's
resource grant. Revoking the topic grant, or using an absent topic in that
existing account, produces `PermissionError` without delivery.
The separate invalid-account control uses `000000000000`: native CodePipeline returns
`SystemUnavailable`, while direct native SNS reports `InvalidClientTokenId` and
“No account found for the given parameters.” That identifier is a valid local
default account. This observation does not establish valid cross-account denial
semantics and does not justify an account-specific authorization shortcut.


## Transactions, restart and authorization

Memory repositories borrow `storage/memory.Domain`; SQLite uses the same shared
transaction/savepoint domain and generated SQLC bindings. Schema
`276_codepipeline.sql` stores definitions, stages, actions/configuration,
artifact declarations, transitions/tags, executions, source overrides/revisions,
action attempts, resolved configuration/output variables and artifact references
in normalized typed tables. There is no JSON resource store, shadow S3 bucket or
verification ledger.
Schemas 277–278 retain CodeBuild producer bindings and AppConfig's admitted
producer action identity in their existing service-owned repositories.

A scheduler claim commits before a provider effect. The claim retains the
pipeline incarnation, execution/action identity, definition version, generation,
provider handle, admitted API `ParentEventID` and next deadline. The executor runs
outside repository transactions and recovers the same external work using the
stable action ID. Ordinary audit causality survives controller replacement.
Completion rechecks current incarnation, action ownership and generation.
Abandon, updates and pipeline deletion fence stale completion. Successful manual
publication may commit across a stop-and-wait or scheduler wake when that same
approval is still live and has no prior completion. Shutdown cancellation leaves
retained work for recovery, not a fabricated provider failure.

Source resolution can first return `InProgress` with the real source revision
and native output variables. Those values commit before copying the exact bound
version into its reserved S3 artifact location. A later nil output-variable map
preserves the earlier map; it does not lose the original ETag or substitute the
copied artifact's ETag. Action namespaces substitute retained output variables
and `codepipeline.PipelineExecutionId`. Unknown variables fail the affected
action instead of silently passing template text to a provider.

API admissions use current IAM and tag context in the resource transaction.
Creation/update validate current pipeline-role existence and CodePipeline trust,
and require caller `iam:PassRole`, through the `Roles` consumer owner before
accepting state. An absent role owner fails honestly rather than bypassing trust.
The provider adapter issues a role session using current trust and reuses it
while it remains valid. Destination services evaluate current permissions on
every operation; successful earlier effects do not bypass later policy denial.
An optional action role is an ordinary STS chain from the pipeline role, not a
second direct service assumption. Cross-account and cross-region actions are
explicitly unsupported at this boundary.

Successful API records and admitted pipeline, stage and action state-change
events join the owning transaction. The `StateEvents` consumer callbacks are
transaction-bound and pass the immutable action declaration directly. Stage
events originate at actual stage entry, completion, failure, stop and retry
transitions—not from guesses based on action completion or current-state approval
projections. The retained stage state prevents repeated success events while an
outbound transition remains disabled. Stage events retain their own start time,
and stage-local last-retry time; pipeline retries retain the global attempt and
retry timestamp. Initial stage event attempts are 0 while pipeline/action
attempts are 1. After a retry, all event types use the global execution attempt,
including stages first entered after an earlier stage's retry. The native
two-stage capture verifies A retry=2, B initial=2 without a stage retry timestamp,
and B retry=3 with its own retry timestamp. Stage-local retry time clears on
advancing; the global attempt and last-retry time do not.
Immediate abandon emits both `STOPPING` and `STOPPED`. Provider API effects and
their own records belong to the downstream owner.

`ResolveAction(ctx, repository, scope, actionID)` resolves live authoritative
CodeBuild binding without a cyclic service dependency. `ResolveDeployment(ctx,
repository, scope, pipelineName, actionID)` resolves historical AppConfig action
inputs, including the **retained resolved ZIP member path**, optional artifact
version and original source revision. It does not authorize or read S3 itself.
CodeBuild binds the copied version when one exists. AppConfig follows the native
artifact ARN contract and reads the current object without a `VersionId`;
retaining metadata does not pin that read to an older object version.
Deletion removes the public pipeline and fences work but retains historical
artifact references; recreation cannot expose or continue old public execution
history. Artifact bytes are neither cached nor deleted by that metadata lookup.

## Native evidence and documentation

Primary semantics:

- [Execution modes, stage locks, supersession, stopping and approvals](https://docs.aws.amazon.com/codepipeline/latest/userguide/concepts-how-it-works.html)
- [Pipeline edits and running executions](https://docs.aws.amazon.com/codepipeline/latest/userguide/pipelines-edit.html)
- [AppConfig action reference](https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-AppConfig.html)
- [AppConfig and CodePipeline integration](https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-integration-codepipeline.html)
- [Action history filter](https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_ActionExecutionFilter.html)
  and [latest-execution selection](https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_LatestInPipelineExecutionFilter.html).
- [Manual approval SNS payload](https://docs.aws.amazon.com/codepipeline/latest/userguide/approvals-json-format.html).
- [Pipeline variable reference](https://docs.aws.amazon.com/codepipeline/latest/userguide/reference-variables.html),
  [declarations](https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PipelineVariableDeclaration.html)
  and [execution overrides](https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_StartPipelineExecution.html).
- [S3 source and polling contract](https://docs.aws.amazon.com/codepipeline/latest/userguide/action-reference-S3.html)
  and [inactive-pipeline metadata](https://docs.aws.amazon.com/codepipeline/latest/userguide/pipeline-requirements.html#metadata.pollingDisabledAt).

Retained captures under `testdata/aws/codepipeline/`:

- `polling_native.json` and `polling_native_summary.json`: actual version change,
  equal-ETag/new-version triggering, update controls, missing/denied source
  recovery and verified owned-resource cleanup. Supplemental
  `polling_native_controls.json`, `polling_native_action_identity.json`,
  `polling_native_missing_create.json` and `polling_native_enable_unchanged.json`
  retain independent-source admission, flag modes, action attribution and cursor
  lifecycle. Capture limitations explicitly identify an omitted aliased response
  and an empty-delete response whose absence was subsequently verified. The
  consolidated probe incorporates these measured controls; its entire final
  sequence was not rerun.

- `variables_native_paced.json`: defaults, required-value failures, overrides,
  retry retention, single-pass nested values, token-only replay with changed
  variable values and valid source revisions, and pre-replay validation.
  Owned-resource cleanup is verified. `variables_native_namespace.json` uses the
  same owned resources for conditional namespace reservation and omitted/empty
  declarations; its cleanup is recorded in the paced capture.

- `approval_notification_native_complete.json`: denied publication, failed-token
  rejection, permission grant plus stage retry, actual Detailed/Minimal SNS
  messages and payload-token approvals, then current-policy denial on a new run.
  `approval_notification_native_boundaries_ready.json` measures subject truncation
  and topic ARN admission; `approval_notification_native_grant_existing.json`
  verifies that granting permission alone does not republish a terminal failure.
  All three complete captures verify owned cleanup. Earlier failed captures
  remain retained honestly and also verify cleanup.
- `approval_notification_native_topic_errors.json`: existing FIFO and absent
  same-account topic execution failures, plus the distinct `SystemUnavailable`
  outcome for an absent `000000000000` account topic. That last case alone does
  not establish behavior for an existing topic/account. Owned cleanup is verified.
  `approval_notification_invalid_account_native.json` separately records direct
  SNS's `InvalidClientTokenId` for that same invalid native account, without
  creating resources.
- `approval_notification_native_cross_account_current.json`: actual notification
  receipt and approval across two real accounts, followed by topic-grant revocation
  and an absent-topic control in the existing secondary account. All three
  outcomes and both-account cleanup are verified. The earlier principal-visibility
  failure and historical-profile identity-fence record remain separate captures.
- `history_filter_native.json`: failed-only and all-action retries, cross-stage
  retries, old/new executions, selector intersection, missing IDs, validation and
  pagination. `history_filters_native.json` independently captures failed-only
  retries across two approval stages; both captures verify owned cleanup.
  Native cross-range pagination misuse returned `InternalFailure`; stackd
  deliberately uses the shared pagination owner's `InvalidNextTokenException`.
  This rejection-code divergence is retained, not claimed as native parity.
- `appconfig_source_ready_role_native.json` and
  `appconfig_source_history_native.json`: automatic initial execution, real source
  ZIP/artifact revision and AppConfig action execution identity.
- `codebuild_appconfig_stage_retry_native.json`: a completed successful pipeline,
  actual CodeBuild success, ZIP content transformed from value 17 to 18 and
  consumed through AppConfig, cleanup and request-ID-matched CloudTrail history.
  Its `complete=false` records the final deliberately unknown-version probe's
  unexpected modeled 500; it does not negate the successful build/deployment.
- `appconfig_artifact_authority_native.json`: artifacts use `aws:kms` encryption
  and empty `HeadObject.Metadata`; no source/name metadata is injected into S3.
  An AppConfig-only caller receives `BadRequestException` identifying the exact
  artifact bucket/key because it lacks S3 access. That reference still resolves
  after physical artifact/pipeline deletion in the captured denial boundary;
  this alone is not proof of authorized successful redeployment after deletion.
- `appconfig_removed_artifact_native.json`: the authorized caller also receives
  an empty-message modeled 500 after artifact removal, including after pipeline
  deletion. The capture completed, cleaned up and matched its request IDs.
  Retained locators are not cached configuration bytes or evidence of successful
  deployment after the underlying object has been removed.
- `eventbridge_native.json` and `retry_counters_native.json`: actual transformed
  EventBridge starts, literal numeric event values (`1.0`, not `1`), source
  revisions, approval identity, stage retry counters and request-matched history.
- `lifecycle_native.json`: definition updates, pending approvals, stop-and-wait,
  abandon, required AppConfig action configuration and exact cleanup. Retained
  visibility-failure captures are failures, not silently corrected fixtures.
- `appconfig_artifact_data_events_native.json` and
  `appconfig_forwarded_s3_nullable_native.json`: temporary native data trails
  captured the consumer's forwarded S3 access under its own assumed-role identity
  (`invokedBy: AWS Internal`). `StopLogging` encountered a transport error;
  subsequent `DeleteTrail`, `GetTrail` not-found and all resource removals
  succeeded. The fixture retains that cleanup error rather than erasing it.
- `appconfig_called_via_discovery_native.json`: bounded session-tag queries
  establish the exact `us-east-1` forwarding identifier `460678247002`, rather
  than the public `appconfig.amazonaws.com` service name. The capture includes
  the exact-match success, denied direct artifact read and verified cleanup.
- `appconfig_called_via_exact_native.json`: a separate, untagged consumer session
  succeeds with `CalledViaFirst` and `CalledViaLast` both equal to `460678247002`,
  a nonempty `CalledVia` set containing only that value and `ViaAWSService=true`.
  Direct S3 reads and public CodePipeline access remain denied.
- `appconfig_called_via_eu_west_1_native.json` rejects the US forwarding identity
  in `eu-west-1`; `appconfig_called_via_discovery_eu_west_1_native.json` discovers
  its distinct exact value `242796738427`. Both captures verify owned cleanup.
- `appconfig_called_via_exact_eu_west_1_native.json`: an independent untagged
  session confirms both endpoint keys and the complete nonempty `CalledVia` set
  use `242796738427` in `eu-west-1`, with direct reads denied and cleanup verified.
- `appconfig_called_via_discovery_us_west_2_ready_native.json` establishes
  `783816728759` in `us-west-2`.
  `appconfig_called_via_exact_us_west_2_ready_native.json` independently verifies
  the complete chain using an untagged consumer and captures its successful S3
  data event under the original caller with `AWS Internal` audit metadata.
  Direct S3 reads remain denied. The initial discovery failure and interrupted
  exact-chain attempt are retained separately. The successful capture retains a
  native trail-deletion transport failure; its linked
  `appconfig_called_via_exact_us_west_2_cleanup_native.json` verifies subsequent
  deletion and `TrailNotFoundException`. All owned resources were removed.

Native CodeBuild admission uses the input artifact S3 ARN as `sourceVersion`,
`artifactsOverride.type=CODEPIPELINE`, the output artifact S3 ARN as location,
`packaging=NONE` and `encryptionDisabled=false`. Its output is nonetheless a ZIP;
it must not use the ordinary unzipped S3-NONE artifact path.
`resolvedSourceVersion` is the **original source object's VersionId**, not the
copied artifact's version. CloudTrail masks environment overrides and the build
response has an empty environment-variable list; no hidden variable name is
inferred from that observation.

AppConfig location is `codepipeline://<pipeline-name>`, without a retrieval role.
ConfigurationVersion is the **Deploy action-execution UUID**, not the pipeline
execution ID; an authorized caller can reuse a completed version. The native
unknown action UUID returned modeled `InternalServerException`/500 with empty
message twice. This is a bounded observation, not a universal error fallback.

Artifact forwarding currently supports the calibrated `aws/us-east-1`,
`aws/us-west-2` and `aws/eu-west-1` identities. Other regions/partitions return an explicit
`NotImplementedException` instead of substituting a foreign identity or the public
service DNS name. This source boundary does not restrict hosted, S3, SSM or
Secrets Manager configuration sources.

## Remaining complete-service target

Every generated operation dispatches to owned behavior or an honest protocol
`NotImplementedException`. The following 25 modeled operations retain unimplemented
owners or worker/provider protocol paths; Lambda job callbacks described above
are implemented, but their custom-worker protocols remain incomplete:

`AcknowledgeJob`, `AcknowledgeThirdPartyJob`, `CreateCustomActionType`,
`DeleteCustomActionType`, `DeleteWebhook`, `DeregisterWebhookWithThirdParty`,
`GetActionType`, `GetJobDetails`, `GetThirdPartyJobDetails`, `ListActionTypes`,
`ListDeployActionExecutionTargets`, `ListRuleExecutions`, `ListRuleTypes`,
`ListWebhooks`, `OverrideStageCondition`, `PollForJobs`, `PollForThirdPartyJobs`,
`PutActionRevision`, `PutJobFailureResult`, `PutJobSuccessResult`,
`PutThirdPartyJobFailureResult`, `PutThirdPartyJobSuccessResult`, `PutWebhook`,
`RegisterWebhookWithThirdParty`, `UpdateActionType`.

Further prerequisite gaps remain within implemented command families:

- Additional source/build/deploy providers, custom/third-party workers and action
  registries; webhooks and third-party registration.
- Git trigger declarations, cross-region artifact stores, cross-account action
  ownership and native reactivation after automatic inactivity polling disable.
- Stage entry/success/failure conditions, rule execution, automatic rollback and
  stage retries; CodeBuild batch actions and command/environment declarations.
- Provider-specific action target/rule histories, broad quota/concurrency parity
  and complete rejection precedence/audit conformance beyond retained scenarios.

The code's `TODO: Comeback` markers are in `service.go` (remaining operation
owners), `definitions.go` (unsupported declaration/execution owners),
`polling.go` (inactivity reactivation calibration),
`codepipeline_s3_deploy.go` (remaining media types and encrypted-ZIP diagnostics),
`codepipeline_lambda_credentials.go` (complete native artifact-credential authority
matrix), and the integration's `appconfig_codepipeline.go` (remaining
regional/partition forwarding identities).
These are visible gaps, not a claim that operation registration completes
CodePipeline.

## Verification entry points

The scoped behavioral suites are:

```sh
go test ./internal/services/codepipeline ./storage/codepipeline ./storage/sqlite/codepipeline
go test ./integration -run '^TestCodePipeline' -count=1
go test ./internal/integrations -run '^TestAppConfigPipelineArtifactUsesRegionalCurrentAuthority$' -count=1
STACKD_LAMBDA_DOCKER=1 DOCKER_HOST=unix:///var/run/docker.sock go test ./integration -run '^TestCodePipelineLambdaDocker' -count=1
```

The kernel tests cover stage-mode boundaries, manual approval, stop/update
transitions, source-key/version binding, token replay and state/event rollback.
Native action-history replay covers both retry modes, selector precedence,
scoped pagination and immutable definition history. Signed SDK history pagination
also survives repository reopen.
Notification regressions cover publication claim interruption, expiry, concurrent
approval/update/abandon fences, stop-and-wait, failed-token rejection and retry.
The signed SDK scenario receives actual SNS/SQS messages, verifies no reopen
duplicate, and checks current-policy denial and explicit retry recovery.
The whole lowest-`runOrder` group is admitted before any provider effect. A
synchronous failure therefore cannot suppress its parallel peers; a failed group
never admits a later `runOrder`. The
[actual failure workflow](../testdata/integration/codepipeline_approval_failures.json)
exercises same-order FIFO and missing-topic failures through the real SNS owner.

The [approval executable evidence](../testdata/integration/codepipeline_approval_executable.json)
retains eight same-account SNS notifications consumed to approve real build/deployment
work, including explicit nullable fields and the native 25-character subject
boundary. A controller restart while awaiting approval preserves the token without
republishing; a later restart retains deployment bytes and filtered history.
The executable also verifies both notification configuration failures and their
distinct state/history projections. A ninth notification crosses accounts and
completes approval; restoring the original topic policy blocks the next run,
and an absent topic in that account also fails without delivery.
All three controller exits are zero and all 26 cleanup actions succeed.
The [focused cross-account restart evidence](../testdata/integration/codepipeline_approval_cross_account.json)
restarts while awaiting approval on a foreign topic, then consumes the original
token without republication. Current grant revocation and an absent foreign
topic both fail without delivery. It retains 54 signed SDK calls, an AWS CLI
state read, two zero-exit controllers and seven successful cleanup actions.
The [variable executable evidence](../testdata/integration/codepipeline_variables_executable.json)
uses a real CodeBuild environment override to transform source value 17 to 19
and returns those bytes through AppConfig. Changing the default to 3 and reopening
preserves the admitted override 2 and deployed bytes. Four controllers exit zero;
all 26 cleanup actions succeed. The
[populated 279→280 upgrade](../testdata/integration/codepipeline_variables_upgrade.json)
preserves an old execution, approval token and source revision while removing
request hashes, then verifies new variable bindings and token replay through
another reopen. All three controllers exit zero and five cleanup actions succeed.

The [polling executable evidence](../testdata/integration/codepipeline_polling_executable.json)
retains 67 signed SDK calls and five actual source-artifact reads. It exercises
initial observation, same-bytes/new-version detection, current IAM denial and
recovery, durable cursors through restart and disable/re-enable, and missing-source
recovery after deletion/recreation. All three controllers exit zero and all five
final owned-resource cleanup actions succeed.

Repository tests cover independent mutable values, rollback/savepoints,
account isolation, deletion/recreation fences and retained artifact/member
references across SQLite reopen. The signed SDK scenario exercises real
versioned S3 ZIP bytes, source output variables and namespace substitution,
manual approval across reopen, stop-and-wait, stage retry, token replay and
current-incarnation history.
The IAM regression also distinguishes absent request tags from a present tag set,
including an explicitly empty tag value.

The [history-filter executable evidence](../testdata/integration/codepipeline_history_executable.json)
checks one-row `All`/`Latest` pages after a real denied/retried deployment and a
newer execution, then checks the same action IDs and order after SQLite restart.
It also exercises the real container build, current IAM/KMS, artifact delivery
and owned cleanup; both controller exits are zero.
The [west-region executable evidence](../testdata/integration/codepipeline_history_west_executable.json)
combines history filtering with `us-west-2` forwarded-artifact authority and real
SNS/SQS approvals. It retains four delivered notifications, five `All` versus
four `Latest` actions after deployment retry, and stable history after restart.
All three controllers exit zero and all 22 owned-resource cleanup actions succeed.

The [retained executable evidence](../testdata/integration/codepipeline_executable.json)
records S3 → real CodeBuild → AppConfig: customer Python transformed value 17
to 18, AppConfig returned those bytes, and the build retained the original source
revision and actual exported variable. It also records EventBridge selection of
an older source version, current IAM and KMS denial followed by stage retry, lifecycle
events delivered to SQS, selected management/data events delivered as CloudTrail
gzip, deployed bytes surviving controller restart and artifact removal, and owned
resource cleanup. Both controller exits were zero. This is bounded workflow
evidence, not full-service parity.
The forwarding regression reuses the same consumer session while changing its
current S3 policy: the captured numeric forwarding identity permits deployment;
the public AppConfig service name does not. Direct S3 reads remain denied in both
cases. This exercises actual S3/KMS authorization, not a captured-context mock.
The [European executable evidence](../testdata/integration/codepipeline_eu_executable.json)
exercises the same build/deploy/restart workflow in `eu-west-1`, including rejection
of the US forwarding identity. Each regional run removed its 19 owned resources
and recorded two zero controller exits.
Both runs also verify delivered S3 audit records for admitted and denied
consumer reads: the original assumed-role issuer remains intact, the internal
invoker/source/user-agent are `AWS Internal`, and each downstream read has its
own request ID rather than reusing the AppConfig request ID. The read does not
invent a `VersionId`.

The [populated upgrade evidence](../testdata/integration/codepipeline_upgrade.json)
starts with the schema-275 executable, retains an IAM user, S3 bytes and a hosted
AppConfig version/deployment, then opens the same database with schema 278 and
restarts again. Signed API reads retain the original identity and content;
CodePipeline's new repository is available. All three controllers exit zero and
the owned resources are removed.
The [schema-278→279 approval upgrade](../testdata/integration/codepipeline_approval_upgrade.json)
retains a pending approval token, action identities, source history, IAM role and
encrypted S3 artifact bytes. The old token completes the original execution.
On the upgraded database, current SNS denial fails publication; granting
permission alone does not retry it. Explicit retry delivers the actual token
through SNS/SQS, and restart retains publication completion without another
message. All three controllers exit zero and all eight owned resources are removed.

Run the retained regression workflow with an existing Linux image containing
Python 3 and a Docker-enabled CLI:

```sh
python3 -B scripts/aws/codepipeline_executable_smoke.py \
  --binary /path/to/stackd \
  --state-directory /tmp/stackd-pipeline-proof \
  --build-image python:3.14.5-slim-trixie
```

For the calibrated European workflow, add `--region eu-west-1` and
`--forwarding-identity 242796738427` and use a distinct state directory.
For `us-west-2`, use `--region us-west-2 --forwarding-identity 783816728759`.

The state directory must not already exist. The runner preserves its report and
controller logs, cleans owned resources, and reports cleanup failures.

`scripts/aws/codepipeline_history_filter_probe.py --output <new-capture.json>`
is the single current native action-history probe. It covers both retry modes,
parallel actions, later-stage retries, selector validation and pagination.
Earlier capture files remain evidence; the superseded duplicate probe is removed.
