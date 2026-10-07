# SQLite state

The SQLite option persists the currently implemented Account, IAM/STS,
Organizations, KMS, SQS, EventBridge, Lambda, S3, CloudTrail, Logs, CloudWatch, SNS,
EC2, EBS snapshots, EC2 Auto Scaling, ECS, ECR, CodeBuild, CodePipeline, Glue, Athena, Application Auto Scaling,
DynamoDB, Kinesis, Firehose, X-Ray, Cognito user pools, SES v2, Resource Groups
Tagging API, SSM Parameter Store, RDS, MSK, ElastiCache, MemoryDB, OpenSearch,
CloudFormation, EventBridge Scheduler/Pipes and API Gateway REST/HTTP/WebSocket
control state together. DynamoDB items, Kinesis records, RDS
SQL data, MSK topics/groups, Valkey keys/snapshots and OpenSearch indices remain
in their native engines. Each service retains its typed repository and owns
relational tables; related callbacks share a native transaction. Optional manual
service time is retained in the same database.
The journal persists typed identity/Organizations transitions, captured API
completions and EventBridge/SQS/Lambda/Logs acceptance. EventBridge target work,
Lambda attempts and completed outcomes, CloudTrail log/publication stages, Logs
subscriptions and SNS subscriber deliveries retain their deadlines. SNS signing material, protocol variants,
SNS/Lambda/SQS/EventBridge weighted samples, ECS utilization windows and CloudWatch structured SNS actions share the database.
Broader event sources, service jobs and a PostgreSQL metadata repository remain unfinished.
This is not a whole-cloud snapshot or fork.

Schema `223_cloudformation.sql` adds scoped stacks and exports, immutable stack
IDs, physical resource generations, monotonically ordered stack events, change
sets with before/after property contexts, and retained operation steps/caller
authority. Per-step deletion-failure counts survive controller replacement.
Update commits its desired definition before irreversible cleanup; after three
failed old-resource deletions the physical resource is detached, with retained
`DELETE_FAILED` history and an `UPDATE_COMPLETE` warning, not falsely deleted or
recreated by rollback. Restart replays pending owner commands using the same
incarnation token; the target service remains authoritative for the actual resource.
Deleted stacks retain their history and ID-addressed inspection independently of
name reuse. Executed change sets are retained execution history, matching native
CloudFormation's refusal to delete executed change sets. Unexecuted change sets
are removed when superseded by execution, but remain ARN-addressable after stack
deletion until explicitly deleted, as observed in the rule migration capture.

Schema `303_cloudformation_rule_identity.sql` qualifies retained custom-bus
EventBridge rule physical IDs and references as `busName|ruleName`, preserving
default-bus bare names. It also upgrades operation before/after images and adds
`RuleName` attributes without changing owner tokens, generations or rule ARNs.
Full partner-name suffixes are preserved by migration, without implying partner
bus implementation. Historical events and rendered output/export snapshots are
not rewritten; the next stack operation reevaluates outputs from corrected refs.
The old-executable → upgraded-executable smoke verifies existing delivery,
bus migration, rollback, subsequent restart and deletion.

Schemas `204_ecr.sql` and `205_codebuild.sql` add ECR's actual encrypted
OCI payloads, token signing material, image/scan/lifecycle/replication state and
CodeBuild's projects, accepted build configuration, phases, output/log progress,
fleet incarnations and encrypted source credentials. Both use service-owned SQLC
repositories and the existing transaction domain. Docker containers are external
resources: closing a persistent controller detaches rather than terminating live
builds; a replacement controller reattaches by retained build identity. IAM
remains the session authority.
The integrated schema-205 executable preserved the same native build process
across controller SIGKILL/reopen and retained registry/artifact bytes. Its nine
owned builds exercised current-policy denials, failure, cancellation and a real
five-minute timeout; no owned containers remained. The
[integration capture](../testdata/integration/ecr_codebuild_main_integration.json)
records this local proof, not native AWS calibration.

Schemas 276–278 add [CodePipeline's retained execution and artifact ownership](codepipeline.md),
CodeBuild producer bindings and AppConfig deployment-action identities.
Definitions, attempts, source revisions, output variables and artifact locators
use normalized service-owned tables. S3 remains the artifact byte owner; real
builds and deployment effects run outside state transactions. The integrated
CLI workflow verifies deployment bytes and action history through reopen, current
IAM/KMS denial and stage retry, without caching source artifacts in AppConfig.
Schema 279 adds the private approval notification completion ID. The
[approval workflow](../testdata/integration/codepipeline_approval_executable.json)
consumes real SNS/SQS notifications and reopens a pending approval without
republishing a committed notification. Acceptance before the completion commit
remains an at-least-once crash window; the public approval ID never becomes an
SNS message ID.
The [populated 278→279 upgrade](../testdata/integration/codepipeline_approval_upgrade.json)
retains the pre-upgrade token and encrypted artifact, then verifies current-policy
denial, explicit retry and publication recovery across another controller restart.
Schema 280 retains ordered pipeline variable declarations and immutable execution
bindings, including nullable defaults/descriptions and omitted versus empty lists.
It removes obsolete request hashes: native client-token replay preserves the
original execution despite changed valid overrides.
The [populated 279→280 upgrade](../testdata/integration/codepipeline_variables_upgrade.json)
preserves old execution/source/approval identity and verifies new bindings across
reopen. The [real variable consumer](../testdata/integration/codepipeline_variables_executable.json)
passes the override through CodeBuild environment configuration into AppConfig
deployment bytes, then preserves both binding and bytes after a default change
and controller restart.
Schema 281 adds per-source polling revisions, recoverable observation claims,
deadlines and source-error projections, plus inactive-polling metadata. Source
reads run outside transactions; cursor advancement and execution/event admission
commit together. Disabled cursors survive re-enable, while changed source
locations and pipeline recreation get independent cursors. The
[polling executable workflow](../testdata/integration/codepipeline_polling_executable.json)
verifies actual source artifacts, current IAM denial/recovery and cursor retention
through controller restart. Automatic inactivity reactivation remains explicitly
uncalibrated.
Schema 282 retains typed Lambda invocation jobs, callback replay identity and
output variables independently of pipeline deletion. Continuations create new
jobs while preserving action/artifact identity; late abandoned results cannot
revive execution. [Real Lambda executable evidence](../testdata/integration/codepipeline_lambda_executable.json)
verifies pending-job restart, scoped artifact credentials, transformed deployment
bytes and retained terminal history through three clean controller lifetimes.
Schema 283 extends MQ into a standalone broker control plane: normalized immutable
configuration revisions, current/pending/history associations, effective/pending
users and groups, tags and scheduled maintenance intent. Legacy user rows preserve
native credentials rather than fabricating cleared passwords. Reboot promotion
follows actual engine application; stale results cannot consume newer mutations.
[Standalone MQ executable proof](../testdata/integration/mq_standalone_executable.json)
verifies direct JMS/AMQP effects, credentials and retained messages independently
of Lambda.
Schema 284 retains MQ maintenance-window adjustment counts with broker state.
Quota rejection rolls back the requested window and related pending changes.
The scheduled maintenance owner resets the budget only after successful native
application; controller restart, manual reboot, claiming and failed effects do
not clear it. Pre-counter databases start a fresh tracked budget without changing
retained native identity or configuration.
Schema 304 retains explicit Lambda MQ virtual-host presence separately from the
effective host. New explicit `/` survives credential rotation and restart.
Migration preserves nondefault hosts and does not invent explicit-root request
presence absent from older state. Broker acknowledgements remain native-owned;
[deployment evidence](lambda.md#cloudformation-amazon-mq-mappings) includes
retained SDK readback, real delivery and source-state migration verification.

Schemas 206–212 add Glue catalog, job, crawler, schema-registry and workflow
state, followed by Athena controls and retained queries. Service-owned SQLC
repositories share the existing transaction and event domain. Athena retains
the admitted caller's policies, session context and credential scope fields;
IAM remains authoritative for credentials. Native engines and S3 own execution
and result bytes outside resource transactions.

Schema `213_ssm_parameters.sql` adds Parameter Store metadata, encrypted immutable
versions, labels, resource policies and retained policy/image-validation work.
It shares the same transaction and job owners; compute consumers resolve current
SSM/KMS authority instead of persisting another plaintext parameter store.

Schema `214_rds.sql` adds typed instance/cluster and group metadata, encrypted
credentials, physical snapshot identities, parameter application modes and
retained lifecycle/health deadlines. The external PostgreSQL/MySQL runtime
owns actual SQL data, native authentication and offline physical snapshot bytes.
Schema `215_api_event_type.sql` retains the optional source-owned CloudTrail
event type; its empty default preserves existing management/service events.
Data API native transaction handles deliberately are not persisted or replayed.
The [race-enabled RDS executable capture](../testdata/integration/rds_runtime.json)
preserved actual PostgreSQL/MySQL rows across controller reopen, rolled back
unfinished Data API transactions and delivered pre-restart typed Data events to
selected S3 gzip logs. Both instance and writer-backed cluster snapshot restores
held independent native data; cleanup verified all owned containers/volumes gone.
The [212→215 CLI migration proof](../testdata/integration/service_schema_upgrade.json)
retained an existing IAM user, S3 object bytes and an identical legacy CloudTrail
record, then created/decrypted a new SecureString and exercised RDS parameter
groups. Owned resources were removed through their ordinary APIs.

Schemas `216_scheduler.sql` and `217_pipes.sql` add typed schedule groups,
occurrences, immutable retry targets, pipe configuration, accepted source work
and ordered stream checkpoints to the same transaction domain. Native target
effects remain outside transactions; accepted-but-uncommitted effects may repeat.
The [215→217 CLI migration proof](../testdata/integration/scheduler_pipes_main_upgrade.json)
retained a decryptable SecureString, an RDS parameter group, actual SQS message
bytes and an identical legacy CloudTrail record. The new executable then created
a Scheduler group and read the Pipes catalog. Both controllers exited normally;
owned resources were deleted through their service APIs.

Schemas `218_elasticache.sql` and `219_memorydb.sql` retain separate scoped
cluster/user/group/parameter/snapshot intent and native incarnation references.
Their shared Valkey adapter owns actual ACL application, native replication,
slots, RDB snapshots and AOF bytes outside SQLite transactions. Closing a durable
controller detaches; API deletion removes only the retained native incarnation.
Schema `220_opensearch.sql` retains domains, configuration, policies, immutable
principal bindings and tags. Modern and legacy control APIs share these rows;
the native engine owns mappings/documents/index data and actual query execution.

Schema `221_msk.sql` adds typed scoped clusters, immutable native incarnations,
configuration revisions, tags, resource policies, operation versions and SCRAM
secret references. Kafka passwords and record/group data are not copied into
these tables. Native effects run outside transactions; current authority and
retained versions gate their publication. Controller reopen reattaches the exact
owned brokers/volumes instead of constructing replacement payloads.

Schema `222_pipes_kafka.sql` adds typed Kafka source/authentication references,
ordered bootstrap addresses, a retained filtered-work bit, and one immutable
`pipes_kafka_identities` row (native cluster ID/topic UUID) per bound pipe.
Checkpoints and work rows share this source binding; configuration updates,
StopPipe and controller reopen never replace it. A changed native source rejects
old work and cursor reuse; DeletePipe cascades the binding so explicit pipe
recreation can consume the replacement. Native generations still fence partition
ownership. Matched and filtered records advance together only after successful
target effects, and custom groups survive DeletePipe. This does not make Kafka
3.7's name-based OffsetCommit atomic with a concurrent topic replacement; see
the [Pipes source boundary](pipes.md#sources-filtering-and-ordering).
The [actual Kafka workflows](behavior-references.md#msk-public-kafka-brokers)
verified native committed offsets, failed-target recovery and SQLite reopen;
`testdata/integration/msk_incarnation.json` captures native topic-recreation
failure before the fence and fail-closed retained-work/cursor restarts afterward.
The [217→222 executable upgrade](../testdata/integration/engine_schema_upgrade.json)
preserved decrypted Parameter Store/Secrets Manager bytes, a secret reference,
RDS parameters, a disabled schedule, a stopped SQS pipe and its queued message,
and the complete original management event. Starting the migrated pipe delivered
the original transformed payload and drained its real source acknowledgment.
Both controllers exited normally; owned resources were removed through APIs.
This is a schema/application-state upgrade, not a snapshot of native engine disks.

Schema `224_eventbridge_api_destinations.sql` adds typed API destination scope,
incarnation, Connection reference, endpoint/method, timestamps and retained rate
windows. Modeled HTTP parameter components persist on EventBridge target
configuration, accepted deliveries and Pipes target configuration; credentials
remain in the actual Secrets Manager owner, not these rows. The signed executable
API destination workflow reopens SQLite with pending `Retry-After` work and
observes no early HTTP attempt, then actual authenticated success at its deadline.
It also exercises persisted Pipes parameters through real HTTPS retry and source
acknowledgement. This proves controller restart/retained work, not native HTTP
wire or delivery timing parity; see [API destinations](eventbridge.md#api-destinations).

Schema `305_pipes_http_enrichment.sql` retains modeled enrichment HTTP
header/path/query components and explicit-empty presence independently of target
parameters. The [enrichment executable](../testdata/integration/pipes_http_enrichment_after.json)
reopens failed source work and actual HTTP parameter state before completing the
transformation and downstream SQS delivery.

The schema-222 combined race-enabled executable also exercised native
[Valkey data/ACL/TLS/snapshot workflows](../testdata/integration/valkey_main_runtime.json),
[OpenSearch indexing/query/authority/restart](../testdata/integration/opensearch_main_runtime.json),
and [Kafka/Pipes delivery, SCRAM, configuration and restart](../testdata/integration/msk_main_runtime.json).
The [Kafka incarnation workflow](../testdata/integration/msk_incarnation_main_runtime.json)
replaced actual topics with retained failed work and with cursor-only state:
both old pipes failed closed without advancing replacement offsets; explicitly
recreated pipes consumed the new bytes. Exact-owned native cleanup was observed.
These workflows do not establish AWS managed-infrastructure or whole-service parity.

The merged race-enabled executable exercised real Python/Spark → S3 →
crawler/catalog → Trino workflows, current-policy denials, cancellation,
in-flight restart, Hive DDL/Iceberg and actual observation consumers.
All 28 owned native handles were absent after graceful controller shutdown.
An independent official Go SDK v2 workflow upgraded an existing schema-205
database to 212, preserving S3 bytes and ECR metadata. It decoded Glue catalog
fields and modeled errors, Athena timestamps and paginated string/integer/
decimal/boolean results, then verified retained state and result bytes after
another controller reopen. See the
[integrated runtime capture](../testdata/integration/glue_athena_main_runtime.json)
and [SDK upgrade capture](../testdata/integration/glue_athena_sdk_upgrade.json).
These are bounded local workflows, not complete AWS service conformance.

Schema 187 adds the EBS-owned snapshot catalog, original creation arguments and
ordered tags, mutable tags, scoped ID counters, regional encryption defaults,
and separate block metadata/payload tables. Wrapped KMS keys and block/page-token
keys survive reopen. Parent references retain deleted layers while descendants
need them; completion, read readiness, timeout and deletion deadlines recover
through the existing scheduler. EC2 uses this owner rather than duplicating
snapshot state. The executable restored an encrypted ext4 filesystem after
parent deletion and process restart using pre-restart tokens; see
[snapshot behavior and remaining boundaries](ec2.md#ebs-direct-snapshot-data-plane).

Schemas 202–203 separate EC2's v1/v2 credential references and retain
`ec2RoleDelivery` with shared API events. IAM's existing typed session-context
storage remains authoritative for the condition value and all signing material;
EC2 stores references only. The actual guest SDK workflow upgraded schema 201,
reopened both variants and historical audit records without advancing service
time or rebooting the guest. See [delivery semantics and native evidence](ec2.md#imds-credential-delivery-versions).

Schemas 168–169 add Gateway APIs, routes/resources, methods, integrations,
authorizers, stages and immutable deployment snapshots. Deployed requests do
not follow live draft integration or authorizer rows. Memory and SQLite use
the same service-owned contracts exposed through `storage/apigateway` and
`storage/apigatewayv2`; actual Lambda execution occurs outside transactions.
Schemas 170–171 retain Lambda authorizer configuration and identity sources in
the live controls and deployed snapshots, plus stage/authorizer/identity-scoped
authorization results. Policy documents and typed JSON context remain domain
data, with expiry enforced against service time. Cache reset and resource
deletion use the owning transaction; Lambda invocation stays outside it.
There is no extra cache generation or fencing protocol: native regional
flush/reset itself does not guarantee linearizable invalidation.
Schemas 172–173 retain authorizer invocation-role ARNs in the live controls and
immutable deployed routes. Credential changes therefore follow the same
deployment boundary as the authorizer itself. STS service-role assumption and
Lambda invocation execute outside Gateway resource transactions; role trust and
invocation permission are evaluated through the shared IAM authority.

WebSocket REQUEST authorizers reuse the retained configuration and invocation
roles, but never use the REST/HTTP result-cache tables. Schema 175 retains the
live `IdentityValidationExpression` for control reads and updates; native
WebSocket execution does not apply that expression as an identity filter.

Schemas 176–177 retain integration credential ARNs (including REST's caller
forwarding sentinel) in service-owned integration and deployment-route columns.
Omitted v2 updates retain the prior value; explicit empty credentials clear it.
Changing the draft does not change a deployed invocation. WebSocket messages
resolve the current deployed integration, while their accepted authorizer
context remains connection-owned. Current IAM role trust/permissions and REST
forwarded caller authority are evaluated outside resource transactions, not
copied into a second Gateway credential store.

Schema 174 retains WebSocket protocol and route-selection controls, integration
timeouts/passthrough behavior, route-response selection expressions and the
route-response rows. Immutable deployments retain the route-selection expression
and each route's response-enabled flag and integration timeout. A deployed
`$default` route response activates replies even without a
`RouteResponseSelectionExpression`. Five route-response controls share the
service-owned memory/SQLite contract.
Live sockets, API-scoped connection IDs and activity times are process-local:
they are not persisted or restored on reopening. The owning WebSocket service
closes its sockets on shutdown. Connection idle/lifetime deadlines use service
time; integration execution deadlines use wall time. Reopening retains deployed
configuration for new connections, not continuation of old ones. See
[Gateway behavior and evidence](behavior-references.md#api-gateway-deployed-lambda-authorization-evidence).

## Use

The CLI retains identity, account, key and queue state across process restarts:

```sh
go run ./cmd/stackd -database ./stackd.sqlite
```

Queue URLs use the current endpoint; look them up after restarting on another
address. Bootstrap root credentials, IAM access keys and unexpired STS sessions
continue to work. Key status, session restrictions and current IAM/Organizations
permissions still apply. SSE-SQS messages retain their queue-owned encryption
key; SSE-KMS messages retain ciphertext alongside the KMS material needed to
decrypt it. Earlier unshipped builds used the incorrect `aws:sqs:queuearn` KMS
encryption context; encrypted messages written by those builds require recreating
their queues. Current sends and receives use the native `aws:sqs:arn` key.
KMS grants and policy bindings retain the same immutable IAM
identities. Recreating an IAM name does not recreate its previous identity.

Embedding applications select the same implementation through the existing
storage bundle:

```go
// Imports: stackd, stackd/storage/sqlite,
// sqlbackends "stackd/storage/sqlite/backends".
database, err := sqlite.Open(ctx, "stackd.sqlite")
if err != nil {
    return err
}
defer database.Close()
backends, err := sqlbackends.New(ctx, database)
if err != nil {
    return err
}
handler, err := stackd.New(stackd.Config{Storage: backends})
if err != nil {
    return err
}
defer handler.Close()
```

Close the stack before closing its database, so service workers and long polls
are joined first. One active stack owns the storage bundle and database.
Wall-time mode naturally accounts for elapsed downtime.

The storage bundle exposes one read snapshot for a complete scheduler selection
scan, avoiding a new SQLite transaction per source while retaining fresh
cross-service discovery. That snapshot closes before a job mutates state or
performs external effects. Step Functions queries use SQLC's prepared statements,
created before workers or transactions start and reused through `WithTx`.
Preparation inside a transaction would wait on SQLite's single pooled connection;
construction therefore returns preparation errors directly. The database owner
also owns those statements' lifetime.
Schema 162 adds a scoped partial index for running Standard execution counts,
avoiding scans of closed execution payloads during admission. Counts derive
from resource rows; there is no separate quota ledger.
Schema 163 retains ECS managed-rule dependency metadata alongside nested-sync
metadata, including encrypted revisions whose definitions are not opened during
role-only updates. Accepted task response JSON now owns submitted resource
identity; migration preserves legacy nested identity in that response and drops
the redundant child-execution column. Container effects remain outside SQL
transactions, and ECS's existing client token owns RunTask idempotency.

Schema 164 adds Cognito pool, client, user, ordered attribute, signing-key,
challenge and refresh-family tables through its service-owned SQLC adapter.
Password salts/verifiers and temporary-password deadlines are retained separately
from public user fields; access/ID signing keys are separate from pool metadata.
Refresh tokens are stored as digests, while app-client secrets and private keys
remain sensitive database contents, not KMS-encrypted material. Shared
transactions commit successful commands and journal outcomes together. Pool and
client deletion cascades through owned authentication state.
Schema 165 adds typed group fields and indexed user memberships. Foreign keys
cascade memberships when their pool, group or user is deleted, without deleting
users when a group is removed. Refresh queries current membership; it does not
retain a second copy of group authorization in session rows.
Schema 166 removes the session-to-user foreign key: deleting a user revokes but
retains existing refresh families, while removing attributes, memberships and
challenges. Rejected refresh calls can resolve a recreated username for native
audit attribution but cannot authenticate with its old family. Client/pool deletion
still removes those sessions. An actual executable upgrade from schema 165 retained
active/revoked families byte-for-byte and preserved their acceptance/rejection.
Schema 167 backfills historical refresh-token ownership and retains the current
generation origin, previous-token grace deadline and global-revocation state.
The executable upgrade from a schema-166 snapshot preserved three SDK-issued
active/revoked/deleted-user families and their original expiry. Historical
digests survive user deletion but cascade with their client/pool.
[Cognito behavior](cognito.md) distinguishes server-side token revocation from
offline JWT validation and records native evidence and remaining boundaries.

SQLite retains `synchronous=FULL`. Large write-heavy fixture replays include
physical commit latency: moving only temporary test files to a memory-backed
filesystem isolates query/execution cost without weakening production durability.
The unchanged workflow variable/history-limit SQLite replay passed in 43.11
seconds with `TMPDIR=/dev/shm`; the disk-backed run exceeded 180 seconds.
Neither result establishes power-loss recovery or a general throughput bound.

Schema 149 retains regional X-Ray segment identities, parentage, completion
state, native documents, receipt times and revisioned resource policies with
bound principal identities. Schema 151 retains sampling rules, attributes,
tags, client leases, closed-window reports and boost state. Schema 152 adds
trace discovery indexes, first-matching group memberships/tags and pending
group metrics. Segment admission/update and group-admission ordinals preserve
command order independently of clock precision. Completion arrival is separate
from the original receipt used for thirty-day retention.

Earlier segment schemas did not retain completion arrival or discovery history:
migration uses their receipt as completion and starts retained ordinals at one.
It does not invent older graph history. Inline and independent subsegments still
share the first-completion transition. The shared scheduler recovers expiry and
metric publication from typed state; no additional job ledger is needed.
Pending counts retain the group name without a group foreign key, so deleting a
group does not discard already-earned CloudWatch samples.
Daemon telemetry contributes to the existing API journal and selected delivery;
it does not add trace rows, sampling reports or a separate telemetry schema.

Schema 153 adds account-global CloudWatch dashboard rows and typed tag children.
The partition/account/name key deliberately has no region. Body, modification
time, reported size and the native-observable tag-metadata initialization flag
commit with API outcomes. Listing selects only metadata; it does not decode or
copy all dashboard bodies. The service-owned accounting and authority rules are
documented in [dashboards](cloudwatch.md#dashboards).

Schema 150 retains SNS's optional `TracingConfig`. Traced publications reuse the
existing typed publisher snapshot even without encryption.
[Tracing evidence](verification-kernel.md#x-ray-storage-and-audit) and
[SNS propagation](sns.md#x-ray-propagation) own those contracts.

## Manual service time

Initialize a paused timeline with an RFC3339 instant:

```sh
go run ./cmd/stackd -database ./stackd.sqlite -clock-start 2031-02-03T04:05:00Z
curl -H 'Content-Type: application/json' -d '{"advance":"2m"}' \
  http://127.0.0.1:4566/_stackd/clock
```

The CLI saves the initial instant and each acknowledged advance. Restarting with
the same database restores it automatically, even without `-clock-start`;
supplying another initial instant does not reset an existing timeline.
`GET /_stackd/clock` reads time. `POST` accepts a nonnegative Go duration and
returns the resulting time after notifying registered timers. It does not wait
for service jobs to finish. Wall-time instances reject advances with HTTP 409.
With neither a saved timeline nor `-clock-start`, the CLI uses wall time.

Embedders open the clock before constructing the stack, using the same database
as their storage bundle:

```go
// Imports: stackd/clock, sqlclock "stackd/storage/sqlite/clock".
source, err := clock.OpenManual(ctx, sqlclock.New(database), &initialTime)
if err != nil {
    return err
}
handler, err := stackd.New(stackd.Config{Storage: backends, Clock: source})
```

Pass a nil initial instant to restore only; an absent timeline then returns
`(nil, nil)`. Leave `Config.Clock` nil in that case to select wall time.
One active manual clock owns the stored timeline. Stop advances and close the
stack before closing the database. Advance outside resource transactions: its
own native commit must finish before publishing process-local time. A failed
write or canceled storage wait leaves visible time and timers unchanged.

Version 20 adds API completions, causal/service-origin metadata and typed
EventBridge/SQS acceptance events. Version 21 adds EventBridge resources and
delivery state. Version 22 migrates target input presence to nullable columns and
stores input paths/templates and their named paths. Version 23 stores bus policy
documents with immutable IAM principal bindings. Pending deliveries keep their
captured bodies through these migrations. CloudTrail reads management history directly from the journal;
there is no second CloudTrail history database.

Version 24 adds typed Lambda deployment rows with active/candidate slots, ZIP
artifacts and environment/tag child tables. Ready candidates replace active
deployments in one transaction; pending records resume only when an executor is
configured. Containers and active handler execution are external, not serialized
state. Normal close removes owned environments; crash-orphan reconciliation
remains open. See [Lambda state and execution](lambda.md).

Version 25 adds Lambda function policies and immutable principal bindings,
independent of deployment revisions. Version 26 adds asynchronous invocation
claims, payloads, retry counters/deadlines and separate visible/applied event
configuration. Version 27 adds the typed Lambda acceptance fact to the common
journal. Acceptance and its event commit together. Restart requeues in-flight
claims for legal at-least-once execution and retains pending configuration
deadlines; it cannot roll back customer side effects.

Version 28 adds S3 bucket ownership/policy bindings and object metadata, encryption
material and ciphertext. Version 29 adds CloudTrail trails, tags, ordered selector
children, effective stop deadlines, delivery status and retained source-event
references. Version 30 extends API records with native resource identities and
additional event data. Trail delivery reads those common records; it does not
duplicate history. Its S3 writes and preflight marker effects run outside the
CloudTrail transaction. See [trail delivery and evidence](cloudtrail.md).

Version 32 adds Logs groups, tags, streams and ordered event rows. Indexed
timestamp/ingestion/sequence cursors support forward and backward paging without
persisting cursor ledgers. Group/stream deletion owns its event rows; configured
retention filters reads and stored-byte accounting. Physical retention deletion
jobs remain open. Runtime output enters ordinary Logs commands outside the Lambda
resource transaction; execution-role authorization is evaluated at ingestion.
See [Logs storage and evidence](logs.md).

Version 33 adds typed ACCOUNT/RESOURCE Logs policies and scoped revision guards.
Version 34 separates CloudTrail S3 and Logs batches/status while preserving older
S3 rows and their shared journal references. Removing/replacing a Logs destination
retires only its pending Logs work/status; S3 progress and delivered history remain.
Version 35 adds relational S3 bucket tag rows with atomic replacement and removal.
Native fixture replay covers these transitions and SQLite reopen; the executable
smoke also retained identical Logs records, removed trail configuration and bucket
tags across process restart.

Version 36 adds typed Logs subscription configuration, ordered system-field child
rows and retained gzip delivery payloads. Work retains source scope, filter
incarnation, request/parent IDs, version, attempt count and due/expiry deadlines;
configuration retains creation time and disable-until state. Version 37 adds
`logs_batch_accepted_events`, a typed shared-journal payload with batch ID, group
ARN, stream and accepted count. Source log rows, this fact and matching delivery
work borrow the same transaction: an append or work-write failure rolls back all
three. Customer message bodies stay in source/delivery storage, not the journal.

The shared scheduler discovers committed work on reopen. Lambda permission checks
and asynchronous acceptance run outside the Logs transaction, followed by
version-checked progress. Replacement/deletion prevents old filter work from being
adopted by a new incarnation; group deletion cascades its owned filters/work.
A crash after target acceptance but before source progress can redeliver; SQLite
does not make the external effect exactly once. Once accepted, Lambda owns its
separate durable attempts. Runtime processes and active access-key origin mappings
are not persisted; each actual invocation reconstructs its bounded attribution.
Endpoint injection, rather than configuration rewriting, routes runtime SDK calls
when reopening on a different HTTP port.

Subscription configuration applies immediately locally. The 24-hour work expiry,
one-second exponential retry capped at five minutes and exact ten-minute
nonretryable-error disable/skip deadlines persist as service-time choices, not
measured AWS timing or modeled configuration propagation.
See [subscription evidence and gaps](logs.md#lambda-subscriptions); physical log
retention deletion, additional destinations and whole-cloud snapshotting remain open.

Version 38 adds scoped CloudWatch metric identities, canonical dimension rows
and typed observation points. Version 39 adds Logs metric filters, custom
dimension selectors and ordered system-field children. Publication joins the
accepted Logs transaction; an error after appending metric points rolls back
source rows, metric changes and accepted-batch facts. SDK regression replay
checks both stores, retries, authorization and SQLite reopen. Replacing/deleting
a filter changes future publication without rewriting retained samples.

Version 40 adds CloudWatch alarm configuration, metric queries, dependency/tag
children, state and evaluation origins, suppression deadlines, history and ready
action records. State, default-bus events and ready actions join the same native
transaction. History expires after thirty days on scoped history writes/reads and
outlives alarm deletion; accepted actions retain their own lifecycle. Reopening
during extension preserves the phase and causal chain before the real Lambda
action is accepted. See [alarm semantics and evidence](cloudwatch.md#alarms).

Version 41 adds typed SNS topics, bound policies, tags, subscriptions, retained
protocol payloads and delivery progress, signing material and weighted pending
metric samples. SNS metric publication joins CloudWatch insertion and pending
sample removal in one transaction; deleting a topic does not erase its pending
samples. Version 42 adds the accepted CloudWatch action Subject so restart or
alarm mutation cannot reconstruct a different SNS publication.

Version 43 removes unused SQS message-attribute and system-attribute digest
columns. Responses compute digests from their actual selected attributes instead.
An executable upgrade from version 42 retained a queued body and normalized
Number attribute, returned the native receive digest, preserved the SNS
certificate and verified earlier signed notifications and retained metric queries.

Version 44 adds Lambda destination settings, completed runtime responses,
independent destination/dead-letter routes and weighted pending metric samples.
Completed records do not depend on a live function row; source deletion cannot
erase pending delivery or metrics. The upgrade preserves old retry counts without
inventing response bodies that prior schemas did not retain. SDK replay upgrades
a version-43 pending retry and observes the remaining attempts and original
request identity. A separate real-runtime recovery scenario deletes the source
before reopening and delivers both completed routes without rerunning its handler.

Version 45 adds function-owned concurrency reservations, including explicit zero,
and a deployment revision independent of public metadata revisions. Existing
active/candidate rows retain their code identity on upgrade. Removing the former
one-in-flight index allows independently claimed attempts to share real admission
and pooled environments. Live permits and engines are not serialized; reopen
restores reservations and retries, not abandoned process counters.

Version 46 separates immutable scoped Lambda code archives from deployment
metadata and adds independent service signing material for code-download URLs.
The migration preserves current/candidate ZIPs and sizes before dropping the
inline code column. Matching digests share bytes; legacy creation time uses the
earliest retained deployment modification, not an invented original upload time.
Archive retention extends to the latest issued URL expiry and survives function
deletion/reopen. Deployment snapshots, layer catalog entries and retained layer
attachments prevent collection. Expired unreferenced archives are removed by the
shared scheduler; no URL receipt table, secondary integrity protocol or serialized
runtime is introduced.

Version 47 gives Lambda deployment rows explicit current/pending/published
ownership; older deployments remain version zero. Version 48
(`048_s3_object_versions.sql`) adds bucket versioning and replaces current-only
object tables with `s3_object_versions`, per-version metadata and encrypted data.
Existing objects migrate as `null` versions without changing their bytes,
encryption material or metadata. A stored sequence orders each key's history
independently of equal timestamps; delete markers are typed version rows rather
than payloads. Exact-version deletion cascades its metadata/data, not other
versions. S3 owns current-version selection, null replacement and bucket-empty
checks; Lambda does not maintain a second object history.

Version 110 (`110_s3_object_tags.sql`) adds tags keyed by the owning object version.
Earlier versions acquire an empty tag set without rewriting object rows.
Replacement/clear joins the source API outcome and notification work; deleting a
version cascades its tags. The executable 109→110 upgrade retained object history,
tag-conditioned IAM reads and both event routes across a second restart.
See [object tagging](cloudtrail.md#s3-object-tagging).

Version 112 (`112_s3_multipart.sql`) retains typed multipart initiations,
frozen metadata/tags/encryption context, ordered parts and independently encrypted
part data. Completed versions own their selected part rows and ciphertext
segments. Publication moves that ownership atomically with version visibility
and source events, without copying or re-encrypting the payload. Initiation
ordering is separate from mutation sequencing. Completed-version linkage serves
exact manifest retry; there is no independent completion-receipt/cursor table.
Both pending and completed uploads survive repository and executable restarts.
An actual schema 111→112 executable upgrade retained ordinary encrypted history,
tags, metadata, redirects and checksums, then published a multipart copy from an
old version and retained exact completion retry through a second restart.
See [multipart behavior](cloudtrail.md#s3-multipart-uploads-and-attributes).

All ten modeled checksum algorithms use these existing typed algorithm/digest
columns, not a new schema or parallel checksum store. The HTTPS executable
retained pending SSE-C XXHASH128 parts across restart, completed exact binary
reads and copied the result with a full-object XXHASH3 checksum. A second reopen
preserved the completed checksum, key requirement and original completion identity.

Version 119 (`119_s3_access_points.sql`) retains regional access-point identity,
aliases, bucket ownership, immutable network/public-access settings, policy
principal bindings and ordered tags in service-owned tables. A bucket foreign
key is deliberately absent: native foreign-owned APs survive bucket deletion.
Same-owner APs block bucket deletion; orphaned or owner-mismatched backing buckets
cannot supply data. AP deletion cascades only its policy bindings and tags.
Aliases, policy decisions and multipart uploads addressed through APs survive
repository and executable restarts without duplicating object storage.
See [regional access-point behavior](cloudtrail.md#s3-regional-access-points).

Version 123 (`123_s3_lifecycle.sql`) retains ordered typed Lifecycle rules,
filter tags, transition rows, optional action fields, the minimum-size policy
and each enabled bucket's next daily scan. Configuration and bucket deletion
cascade only their owned rows. Version mutations, notification/access-log intent
and deadline advancement commit together; external delivery remains separate.
Transitions update storage class and mutation sequence without rewriting payloads,
encryption state, completed parts or immutable creation order. An internal numeric
version cursor survives deletion of the last visited row. The executable retained
configuration, transitions, current markers and noncurrent-expiration work across
two process restarts with actual binary reads and SQS delivery. This is not an
AWS worker-latency measurement. See [Lifecycle behavior](cloudtrail.md#s3-lifecycle).

Version 124 (`124_s3_intelligent_tiering.sql`) retains typed configurations, ordered
tags and tiers, one daily bucket deadline, and access/archive metadata on existing
object versions. It does not duplicate ciphertext, completed parts or the restore
queue. Existing eligible versions begin a known access window at retained service
time (wall time when no timeline exists); LastModified cannot reconstruct prior
access. Access updates fence creation order and storage class, so detached reads
cannot retier replaced or Lifecycle-moved versions. Configuration admission owns
scan scheduling; repositories do not reimplement enabled-rule policy. The
executable retained access windows, archive state and pending permanent restoration
through SQLite process reopens, including website GET versus HEAD behavior and
unchanged binary bytes/checksums. See [tiering behavior](cloudtrail.md#s3-intelligent-tiering).

Version 125 (`125_s3_customer_encryption.sql`) adds bucket SSE-C blocking and
private salted-HMAC/response-MD5 columns beside existing object/upload encryption
metadata. Existing buckets retain the prior blocked behavior. Ciphertext and
completed multipart segments keep their existing ownership; customer keys are
never persisted. A completed-version bit retains explicit checksum initiation,
which owns native key admission on exact completion retries. The HTTPS executable
retained pending parts, blocked completion, exact retry, independently rekeyed
copies and pending permanent restoration across process reopens. Typed rows had
empty SSE-C encryption-key blobs and 32-byte salts/verifiers; the closed smoke
database contained neither submitted raw/base64 keys nor the plaintext block.
This checks these exercised paths, not arbitrary-process memory erasure.
See [customer-key behavior](cloudtrail.md#s3-customer-key-encryption).

Version 126 (`126_s3_request_metrics.sql`) retains bucket request-metric
configurations and ordered tag predicates, with bucket/configuration foreign-key
cascades. A bounded SQLC query loads selected configurations and their tags
together; replacement does not leave obsolete predicates. Metric samples belong
to the existing CloudWatch schema, not an S3 ledger. The executable retained
configurations, request/error/byte samples and percentiles across process restart;
the recovered alarm delivered its native event through EventBridge to SQS.
The local boundary run also exercised 1,000 configurations, rejection of the
1,001st, replacement at quota, ten-page listing and bucket-deletion cleanup.
See [request metric behavior](cloudtrail.md#s3-request-metrics).

Version 49 (`049_lambda_layers.sql`) adds scoped layer catalog/version allocation,
ordered compatible-runtime/architecture rows and version policies with immutable
principal bindings. `lambda_layer_version_allocations` outlives catalog deletion,
so deleting every version does not reset allocation for the name.
`lambda_function_layers` retains ordered attachment identity, archive scope,
digest and size for each current, pending or published deployment. It belongs to
the deployment, with deliberately no foreign key to the layer catalog. Deleting a
catalog entry removes its policy/compatibility rows but neither detaches existing
functions nor collects their retained archives. Archive collection checks both
catalog and attachment ownership, including cross-account attachment scopes.

Version 50 (`050_lambda_s3_sources.sql`) adds `lambda_function_s3_sources` with
the exact resolved bucket/key/version and `code_source_check_at` for each
deployment snapshot; an absent row denotes COPY. The SQLC source repository
recovers due Active, nonpending references, including published versions, ordered
by deadline and qualified ARN. S3 reads run outside Lambda transactions.
`SetCodeSourceState` changes the selected deployment's operational state/revision
and source deadline without rewriting immutable published code. The service
rechecks deployment identity, eligibility and deadline before committing a
completion, so an old check cannot replace a newer source decision.
The one-hour check interval and `DependencyError` source-loss reason are local
choices, not captured AWS timing or exact native reason-code evidence.

Version 51 (`051_lambda_logging.sql`) adds the typed `log_group` column to
`lambda_functions`. Custom Text logging destinations follow the same
current/pending/published snapshot ownership; empty storage selects the ordinary
function default. Runtime bytes still enter the existing execution-role-authorized
Logs sink outside Lambda transactions, not a new generic log or artifact store.

Version 52 (`052_lambda_duration_metrics.sql`) changes pending Lambda metric
values to SQLite `REAL`, preserving historical counters, sample counts and
qualified dimension keys. Runtime phase duration and extension overhead therefore
retain fractional milliseconds through the existing transactional publication
path. Process state, registration IDs and telemetry buffers remain ephemeral;
this migration does not pretend to checkpoint a running execution environment.

Version 53 (`053_lambda_function_urls.sql`) adds typed scoped Lambda URL records,
their opaque identity, desired/effective settings and the pending application
deadline. CORS field presence and nullable values are retained independently.
Ownership follows the base function, not an alias row: alias deletion retains
its URL, while whole-function deletion cascades. SQLite reopen preserves URL
identity and the original deterministic transition deadline; no running HTTP
connection or customer execution is serialized. See [Function URLs](lambda.md#function-urls).

Version 54 (`054_lambda_event_source_mappings.sql`) adds scoped SQS mapping
configuration, filter/metric/tag children and control transition deadlines.
Mappings are not function/alias foreign-key children: deleting their target
does not remove them. Poll workers, role-session caches and received batches
remain process-local; SQS owns visibility-based recovery of unacknowledged messages.

Version 55 (`055_lambda_sqs_batch_events.sql`) retains a typed Invoke-to-source
batch link and ordered message-ID children in the common journal transaction.
It stores neither receipts nor customer payloads and is not an execution ledger.
Version 56 (`056_lambda_event_source_metrics.sql`) adds independent mapping-UUID
metric identity while preserving prior function samples, dimensions and counts.
Neither function nor mapping deletion erases pending publications.
See [SQS mappings](lambda.md#sqs-event-source-mappings) for native controls,
real-runtime delivery and SQLite restart evidence.

Version 57 (`057_lambda_sqs_processing_status.sql`) removes the local-only SQS
`last_processing_result` column. Native SQS mapping observations omit that field;
source failures remain diagnosable through operation logs and invocation metrics.
Version 58 (`058_sqs_metric_publications.sql`) retains queue-scoped, count-valued
CloudWatch samples by UTC minute. Queue deletion does not cascade pending samples.
Publication and removal join the CloudWatch transaction, so a failed publication
cannot lose counts or commit a duplicate. Both stores replay native request
statistics after queue deletion and backend reopen.

Version 59 (`059_sqs_queue_metrics.sql`) adds indexed queue sampling/activity
deadlines and message age origins/per-queue delivery counts. Gauge publication
and deadline advancement join the queue transaction; deleted queues stop sampling
without deleting pending request samples or CloudWatch history. Initial delay,
DLQ entry and in-flight visibility no longer share an ambiguous age timestamp.
The migration derives age only where retained state proves its origin: unread
source messages retain initial availability, and FIFO DLQs retain entry through
their separate retention start. Older received source messages and standard DLQs
lack the necessary delay/transfer history, so their age is omitted until those
records leave. No current snapshot is backdated across skipped sampling minutes.

Version 60 (`060_eventbridge_forwarding.sql`) retains rule, target and selected
delivery roles, native event ID/region and local/regional hop state. Wire identity
is separate from each admission's causal ID; same-region forwarding cannot
collide with the source event's repository key. Version 61
(`061_eventbridge_forwarding_events.sql`) retains that wire ID in the shared
acceptance fact. Existing rows backfill from their original ID/region rather than
inventing a forwarding history. A real version-59 executable → version-61 restart
retained and delivered the old queued event, accepted a new role-authorized send,
and preserved both the event and journal identity backfills.

Version 62 (`062_eventbridge_schedules.sql`) retains optional rule-field presence
and the next classic scheduled occurrence. Schedule text is nullable; pattern and
description retain their existing columns with explicit presence flags. Released
rules backfill pattern presence and only previously visible nonempty descriptions,
without inventing a historical explicit-empty description. Future writes preserve
empty-versus-omitted values.

The indexed deadline is nullable integer UTC seconds, not a lexically ordered
variable-year timestamp. Deadline updates do not rewrite tags. Source selection
uses deadline then rule ARN order, matching memory storage. One transaction
advances the occurrence and commits the event, selected deliveries and journal
fact; destination effects remain separate. A real version-61 executable →
version-62 restart preserved both old rule observations, then retained a new
explicit-empty description and a schedule-only replacement. An impossible
calendar remained enabled without outstanding work. See
[scheduled-rule policy and evidence](eventbridge.md#classic-scheduled-rules).

Version 63 (`063_eventbridge_archives.sql`) retains archive metadata, incarnation
IDs, encrypted/raw event payloads, replay state/cursors and ordered rule filters.
Archive event-time scans and expiration use indexed integer seconds/nanoseconds.
Retention preserves the full modeled int32 day range without duration overflow.
Source deletion removes archive entries but deliberately preserves replay history;
orphan managed rules and already selected target work are not archive foreign keys.
Ingestion/counters and replay cursor/admission/journal changes each use one native
transaction. KMS effects run outside it. The executable CLI smoke retained a pending
encrypted replay across process restart and observed SQS/Logs delivery, current
key denial/recovery and expiration under restored service time.

Version 64 (`064_eventbridge_metrics.sql`) retains scoped pending minute groups
and weighted observations, including rule and Source dimensions. No bus/rule
foreign key deletes accepted samples with the source. Publication joins
CloudWatch's transaction and removes the group atomically. Native SDK replay
reopens before publication; the executable workflow deletes sources before
restart and then drives a real CloudWatch → SNS → SQS alarm. A 15-day service-time
advance preserves old sample timestamps without bypassing public API admission
rules for new customer metric data.

Versions 65–67 add typed ECS cluster/task-definition state, revision high-water
marks, EC2 networking resources and their ordered children, and DHCP defaults/options.
Version 68 retains service-generated audit classification and details alongside
API outcomes. Version 69 retains scoped route-table/ACL creation arguments and
ordered tags independently of resource lifetime, so deleted-resource token replay
cannot create a replacement. SDK fixtures and the actual CLI exercise these
controls across reopen; VPC default-resource/event append failures roll back
together. Definition removal, real task/service execution and their remaining
boundaries are described in [EC2](ec2.md) and [ECS](ecs.md).

Versions 70–71 retain internet gateways/attachments/tags and IPv4 network
interfaces, ordered groups/addresses/tags and supported nullable attributes.
ENI creation arguments have their own scoped rows and ordered children, with no
foreign-key dependency on the live interface: deleting an ENI cannot erase its
idempotency outcome. Gateway route-state transitions, address movement and subnet
capacity changes share the owning EC2 transaction and survive process restart.

Versions 72–73 retain typed ECS tasks, request tokens, runtime continuation and
managed EC2 task-network ownership. Version 74 retains task-command ancestry
with issued IAM credentials. Version 75 adds replica services, immutable
deployments, task ownership, observed progress and resolved executable images;
version 76 retains generated ECS target parameters on EventBridge targets and
already-selected deliveries. Service state, task intent and events share the
database transaction; Docker processes remain external. Real CLI recovery kept
a live replica's container and PID, then reconciled replacement/scaling without
reprovisioning the retained workload.

Version 77 retains ECS collection deadlines, deployment monitoring snapshots
and typed per-task/resolution window statistics. Pending observations have no
service-deletion cascade. Their CloudWatch publication and source removal join
one native transaction; external Engine counter reads happen before acceptance,
not under that transaction. CPU baselines remain process-local, so reopening
cannot invent measurements from server downtime. The actual CLI upgraded a
version-76 database, retained running containers and resumed configured
20-second publication. [ECS](ecs.md#service-metrics) owns aggregation and evidence.

Version 78 retains Application Auto Scaling targets, tags, typed step/target-tracking
configurations, managed alarm identities, schedules and capacity-completion
cooldowns. Target bounds, ECS desired capacity and their accepted command outcomes
join one transaction; actual container transitions remain ECS-owned external work.
The real CLI kept policy identities and the same running container PIDs across
SQLite process restart, then exercised multi-policy scale-in against real CPU and
memory observations. See [scaling behavior and evidence](ecs.md#application-auto-scaling).

Version 79 retains public ECS revision configuration only after its live
deployment snapshot relinquishes execution/rollback ownership. Live snapshots
remain authoritative; replacing active deployment rows does not cascade the
archive. Terminal service deletion clears revisions before name reuse.
Previously pruned snapshots cannot be reconstructed by migration.

Deployment archives, layer attachment/catalog mutations and successful API
outcomes use their owning native transaction. Prefetched S3 bytes do not authorize
a new attachment after catalog deletion: final admission rechecks catalog and
current Lambda state. S3 source reads have independent API outcomes and are not
rolled back with a failed Lambda mutation. Background source checks update typed
state without fabricating a public Lambda API call. These boundaries do not make
S3, Lambda and external runtime execution one atomic workflow.

The local CLI/Docker/SQLite artifact scenario retained ordered B-over-A layer
execution, byte-identical original ZIP downloads and custom Text logs. After
source-version and both layer-catalog deletions, latest `Layers=[]` did not alter
published version 1's B result; process/database restart retained that cold
published invocation and an already-issued download. A REFERENCE deployment
exposed Pending with an empty hash, then Active with its actual hash and exact S3
version, without a download Location. Revoking S3 service permission and advancing
local time one hour made REFERENCE Inactive while COPY stayed Active; policy
restoration plus a configuration update recovered a real invocation. These are
local recovery observations, not measurements of AWS source-loss timing.

Version 7 adds typed session event history. Version 8 adds access-key API mutation
events in the same sequence while preserving existing history; see
[the journal contract](event-journal.md).
Version 6 adds the clock row. Timer registrations remain process-local; each
service recovers work from its typed records and deadlines. An advance does not
commit pending resource transitions, impose a cross-service execution order or
persist external effects. These require the remaining scheduler/event work.

## Compute and scaling migrations

Schema 229 retains EC2 launch templates and ordered immutable version members;
the instance owner resolves them rather than copying launch state into another
service. Schema 230 retains ALB request/response metric windows until their
CloudWatch publication commits.

Schema 231 adds normalized EC2 Auto Scaling group, membership, activity, policy,
schedule, hook and lifecycle-action relations. Launch activities retain the
selected numeric template version, subnet, propagated tags, protection and
warmup independently of subsequent group edits. Their activity IDs are the
ordinary EC2 client tokens used after restart. Terminal activity history outlives
group deletion; unfinished launches and live members prevent premature group
removal. Hook tokens/deadlines and metric-publication time survive reopen.
Retained termination reuses these rows: hook abandonment commits the retained
membership state, clears unfinished termination intent and closes its activity
as cancelled. Manual or force release creates a fresh ordinary termination
activity and hook. Reopen does not revive the cancelled intent or destroy the
still-running guest. Live detach clears group ownership without retiring EC2.

ASG commands use savepoint attempts in the shared native transaction. A handled
EC2 dry-run result cannot poison its parent command. SNS publication and SQS
commands use the same attempt boundary: rejected delivery rolls back its own
message/outbox changes before the normal API recorder retains the rejection.
The caller may then commit its independent transition, or propagate the error
and roll back the enclosing transaction. Successful message state and its API
event still follow the enclosing commit; this is not an autonomous transaction.

Rejected child API records reserve distinct event identities and retain the
parent causal link after rollback, without retaining failed resource state.
Memory/SQLite contracts exercise typed reopen, scope/incarnation isolation,
pending launch recovery, history retention and handled/propagated rejection.
The [ASG behavior contract](ec2.md#ec2-auto-scaling) owns service evidence and limits.
These schemas do not introduce a second transaction protocol or claim copy-on-write
forks of running guests, containers or sockets.

Schema 232 retains native EC2 CPU/TAP counter cursors, unpublished monitoring
statistics and per-group contributions. Group membership changes do not split
the instance's network period into multiple scalar observations. Unsigned native
counters use the existing eight-byte SQLite representation, including defaults
for preexisting rows. The [actual schema-231 upgrade capture](../testdata/integration/ec2_performance_upgrade_verified.json)
opens the existing instance through the new executable and reads it through the
signed EC2 SDK; all five added unsigned counter defaults remain BLOB values.

Schema 233 retains Resource Groups Tagging API membership and asynchronous report
intent, not duplicate resource tags. Native owner writes reconcile membership
inside their existing transaction. Report jobs read published Organizations
policies and use retained caller context with current S3/KMS authorization;
object delivery happens outside the tagging transaction. The
[executable report capture](../testdata/integration/resource_tagging_verified.json)
verifies actual encrypted CSV bytes and a delivery denial retained across reopen.

Schema 234 retains SES identities, configuration sets, templates, service-owned
tags and accepted MIME messages. Capture workers write actual `.eml` files after
commit and acknowledge completed output through the same message repository.
Schema 235 retains Cognito verification/reset-code digests, expiry and attempts
under the owning user. Deleting an app client does not delete the user's email
code; deleting its user or pool does. Cognito user changes, code creation and SES
mail acceptance share a transaction, so failed delivery admission cannot leave a
successful signup or unrequested password reset behind.

Schema 236 retains EC2 hibernation configuration and observed guest readiness.
Schema 237 retains Auto Scaling warm-pool configuration, reuse policy and an
activity's selected warm destination state. The existing instance effect and
group reconciliation owners still own transitions; these are not new job ledgers.
Schema 238 retains EBS copy/hydration source references, admitted wrapped keys and
service grants, plus standalone volume-snapshot block work. Existing destination
block rows are the transfer cursor. Source references span destination accounts
and Regions, retain bytes after public deletion, and release obsolete blocks when
the final consumer completes or discards its work. Per-block commits keep bulk
transfer outside admission transactions and make partial work recoverable.
The [warm-guest executable capture](../testdata/integration/autoscaling_warm_pool_guest.json)
opens a populated schema-235 database with the schema-238 executable, retaining
the original group, image and ALB before exercising stop/start and hibernation.

Schema 296 adds normalized Config resource tags scoped by partition, account,
Region and resource ARN. Resource creation/deletion, tag rows, API completion and
shared previously-tagged membership use the existing transaction owner.
An actual executable restart retains all four taggable resource families after
their final tag is removed, then verifies current IAM and deletion cleanup.
The same restart retains the original request-correlated Config CloudTrail event.
See [Config ownership and evidence](config.md#resource-tags-and-shared-discovery).

Schema 297 adds `owner_stack_id`, `owner_logical_id` and `owner_token` to KMS
aliases. These private values commit with the actual alias and its API outcome;
they are not tags or caller-supplied AWS fields. Legacy rows retain empty owner
fields and cannot be adopted from CloudFormation history. Repository migration
and reopen regressions preserve scoped targets/timestamps and this distinction.
Fresh-process handler recovery and an actual executable restart verify
[owned alias recovery and foreign-replacement fencing](resourcegroups.md#kms-aliases-in-stack-queries).

Schema 298 retains the same three private ownership fields on Lambda aliases,
with empty defaults for legacy rows. Alias changes, ownership and API events
commit together. Routing changes also invalidate retained provisioned-pool
generations in that transaction; old runtime completions cannot satisfy new
target readiness. Real pools rewarm after controller restart. See
[Lambda alias ownership and evidence](lambda.md#cloudformation-aliases).

Schema 299 adds typed `lambda_version_owners` receipts, uniquely constrained by
scoped function/publication and scoped function/stack/logical/incarnation identity.
The receipt references the immutable version row with deletion cascade, and commits
with publication, allocation and the API event. Legacy publications are not adopted.
Reopen recovery returns the exact owned publication under current IAM even after
`$LATEST` changes; native delete/recreate cannot reuse its allocated version number.
See [version deployment and calibration](lambda.md#cloudformation-versions).

Schema 300 adds typed private owner columns to `lambda_layer_versions` with
default-empty legacy identities and a scoped partial unique index. Publication
commits archive, catalog row, ownership, monotonic allocation and API event
together. Exact-owner recovery rechecks current IAM without rereading COPY source
bytes. Catalog deletion removes ownership while attached functions retain their
archive. Migration, concurrent publication, rollback and fresh-process runtime
recovery are covered; see [layer deployment](lambda.md#cloudformation-layer-versions).

Schema 301 adds `lambda_layer_permission_owners`, keyed by scoped layer version
and statement ID, with a policy foreign key and deletion cascade. Private
stack/logical/incarnation identity commits with policy and API event; public
statement removal deletes its receipt without disturbing sibling grants.
Recreating an identical native statement cannot restore the old create receipt,
but does not prevent native same-ID deletion. Historical schema-300 policies
remain unowned. Memory/SQLite race regressions cover create recovery, concurrency,
native revision races and transaction rollback; see
[layer permission deployment](lambda.md#cloudformation-layer-permissions).

Schema 302 adds private `owner_stack_id`, `owner_logical_id` and `owner_token`
columns to `lambda_function_policies`. Empty defaults leave legacy policies
unowned. New full-policy deployment creates atomically require absence or the
exact private create identity; public whole-policy replacement clears it.
Statement mutations preserve it while the policy exists. Updates and deletion
follow native target-ARN identity rather than private-owner fencing.
Recovery, concurrent creation, policy/event rollback, qualifier isolation,
schema-301 migration and fresh-process invocation are covered; see
[full-policy deployment](lambda.md#cloudformation-function-resource-policies).

## Ownership and transactions

`storage/sqlite` owns connection setup, native transactions and schema migration.
It uses the Go-native `modernc.org/sqlite` database/sql driver, WAL mode and FULL
synchronization. Newly created database files use mode 0600. The one-connection
pool serializes callbacks and makes waiting for a connection cancellable.
SQLite owns locking, commit and crash recovery; there is no second commit protocol.
See the [driver contract](https://pkg.go.dev/modernc.org/sqlite),
[WAL behavior](https://www.sqlite.org/wal.html) and
[native transactions](https://sqlite.org/lang_transaction.html).

An owned transaction leases its native `sql.Conn` and closes that lease before
returning. This joins cancellation-triggered rollback: `Tx.Rollback` alone can
return `ErrTxDone` while `database/sql` is still finishing rollback on its
cancellation goroutine. Caller cancellation remains attached to `BeginTx`;
there is no detached transaction, cleanup retry or second shutdown protocol.
The [actual cancellation/reopen proof](../testdata/integration/sqlite_cancellation_shutdown.json)
cancels 64 writes, closes the database and starts another process: the committed
row remains and no cancelled row survives. A gated real-driver regression
exercises the asynchronous rollback ownership boundary deterministically.

The numbered SQL files in `storage/sqlite/schema` are the authoritative migration
sequence. Runtime upgrades and `cmd/sqlitegen` apply that same sequence through
`schema.Apply`; schema changes and `user_version` commit together.
`make generate-sql` derives a fresh-database bootstrap from the resulting native
SQLite definitions and seed rows, alongside the service-owned SQLC bindings.
`make generate-sql-check` checks both outputs without modifying them.

New databases execute this generated bootstrap instead of replaying historical
table rewrites. Existing databases still apply their pending migrations.
Bootstrap and any newer migrations share the ordinary initialization transaction;
WAL, FULL synchronization, rollback and unsupported-version rejection are unchanged.
The bootstrap contains no customer resource snapshot or alternate recovery protocol.

A three-sample workstation run of `sqlite.Open` at schema 89 measured 35–64 ms
for fresh initialization and 2.8–2.9 ms for reopening. The actual CLI reached its
listening log/port in 706 ms with a fresh database and 644 ms after retained restart;
those numbers include service setup, not just SQLite, and are not portable latency
guarantees. The restarted CLI recovered native DynamoDB items, manual service time
and an unpublished capacity sample; completed-minute publication combined that
retained sample with new reads without losing or duplicating consumption.

Schema 89 retains DynamoDB throttle metric identity through `Operation`,
`OperationType` and `Verb` columns in the sample key; older rows retain empty
operation dimensions. [DynamoDB behavior and evidence](behavior-references.md#dynamodb-engine-references)
owns the admission and metric semantics, including process-local admission balances.

Schema 92 retains scoped DynamoDB backup identities, native storage references,
source creation identity and typed backup/source configuration. There is no
source-table foreign key: deleting a source must not delete its backups.
CREATING and DELETED backup rows drive recoverable native copy/removal, while a
pending target's RestoreSummary owns its source reference until ACTIVE.
The native volume holds snapshot items; copying this SQLite file alone is not a
complete DynamoDB backup. Database retirement includes surviving backup
references, not just live tables and stream retention. Captured lifecycle and
actual interrupted-copy/restart evidence are recorded with the
[DynamoDB behavior](behavior-references.md#on-demand-backups-and-restores).

Schema 93 retains DynamoDB continuous-recovery intervals, typed keys and
postimages, ordered sequences, and pending native capture keys. Table rows own
the active interval and pending restore's interval/sequence cut. Nil postimages
are deletions; zero is a valid empty restore cut. A private DynamoDB Local table
holds each baseline. A retained compaction bound permits idempotent native
Put/Delete replay before rows are trimmed. Pending restores pin the original
baseline and its tombstones until ACTIVE. These records do not turn SQLite plus
the native engine into one atomic database; both stores are required for recovery.
Schema 94 adds indexed backup type/expiry projections. Expired SYSTEM backups
reject new reads/restores but remain physically retained for pending targets.
Memory and SQLite replay use the same public SDK lifecycle fixtures.

Schema 95 replaces recovery-only pending keys with shared native mutation
captures, typed source ownership and preimages. It migrates unresolved schema-93
captures through their retained recovery owners rather than dropping them.
Replica membership, settings intent, consumed cursors, first authorization-denial
time, ordered changes, conflict versions and bootstrap pins are service-owned
relational state. Independent monotonic capture and publication sequences survive
row deletion. Immutable bootstrap items remain in private native tables; their
source database is retained until observed native removal. There is no separate
receipt or integrity protocol. The public SDK fixtures exercise both stores,
including real native response loss, service restart, authorization repair and
regional data preservation after detachment.

Schemas 96–98 retain Kinesis stream/shard/consumer metadata and its native engine
identity, DynamoDB Kinesis destination work, and EventBridge's selected partition
key path on both target configuration and accepted delivery. Kafka remains the
record-byte owner. Copying SQLite alone is not a whole-stream snapshot.

Schema 99 renames the former DynamoDB-only Lambda settings and checkpoint tables
to the shared stream contract without dropping queued work, retry batches,
window state or accepted failure destinations. It adds `AT_TIMESTAMP` positions,
the adjacent merge parent and source-retention duration. Existing DynamoDB
checkpoints retain their 24-hour source retention. Live iterators and subscription
channels are reopened from retained positions rather than persisted as authority.

Schema 100 adds typed Logs logical destinations and tag child rows. Subscription
configuration retains the optional sender role; accepted delivery separately
retains its physical target, delivery role/source ARN and partition key alongside
the existing gzip bytes. Repointing or deleting a logical destination cannot
rewrite already accepted work. SDK workflows exercise retained throttled delivery,
source-stream deletion, target replacement and regional routing on both stores.
An actual SQLite-backed executable recovered the configured Logs → Kinesis →
real Python Lambda → SQS pipeline across process restart.

Schema 101 removes Kinesis's synthetic idle-metric deadline and its index.
Observed pending samples remain in the existing metric table and publish through
the shared CloudWatch transaction after their minute closes. No replacement
timer state is introduced. A real executable restart before that deadline retained
stream/shard sample distributions and consumer admission observations.

SQS owns `schema/001_sqs.sql`, `storage/sqlite/sqs/queries.sql` and its typed
repository mappings. Queue configuration, tags and policy principal bindings are
separate from messages, receipts, FIFO deduplication, receive attempts, tenant
classification and redrive tasks. Accepted caller metadata and its ordered policy,
forwarding and claim collections have explicit columns and tables. No whole
resource is serialized into a generic JSON blob. Unsigned domain counters use
ordered eight-byte columns, preserving their Go representation without signed
integer truncation. Timestamps preserve zero values and nanosecond precision.

Queue/message/task changes commit in one SQLite transaction. Queue deletion
cascades to its owned delivery rows, while tombstones and accepted redrive tasks
retain their independent lifecycles. Receipts and deduplication records can outlive
their referenced message. SQLC bindings use the actual transaction, so escaped
reader/writer handles cannot access state after the callback finishes. The
repository's `Context` carries the native transaction into related repositories
using the same database. Ordinary nested callbacks see staged records and commit
only with their owner; a caught nested write error, panic or cancellation aborts
that transaction. Read-only callbacks cannot acquire a writer. Each callback
context expires independently, including while its outer transaction remains active.

SQS write callbacks prepare each used SQLC statement once and close it before
the callback ends. Message and receipt rows reuse those native statements within
the existing transaction; there is no process-global cache or new durable state.
The [signed CLI measurement](../testdata/integration/sqs_sqlite_statement_reuse.json)
sent and individually deleted 243 captured audit payloads, checking every payload.
The observed drain fell from 111.99 to 72.81 seconds with race-enabled binaries;
both owned queues were deleted and both controllers exited normally. These are
local measurements, not AWS throughput or a benchmark guarantee. Whole delivery
sets still transition atomically and are rewritten; this change removes repeated
native SQL preparation, not aggregate write amplification.

An explicit `Attempt` owns a recoverable command boundary. Memory stages a child
branch of the touched typed stores; SQLite uses native `SAVEPOINT`, `ROLLBACK TO`
and `RELEASE`. A rejected command discards its participating changes without
poisoning the healthy parent. An accepted command still belongs to the parent's
commit and is discarded if that parent later fails. Existing parent readers see
accepted child changes through their authoritative typed state root.

ECS and CloudWatch public commands use this boundary for native forward-access
probes and service-linked-role fallback. Rejected child outcomes can coexist with
a successful parent's resource changes and audit history; this does not make
child API outcomes independent of a subsequently rejected parent. Scheduled
scaling uses the same boundary to consume a permanent failed occurrence without
committing partial capacity changes or blocking later jobs. This is neither a
second transaction protocol nor a snapshot/fork mechanism.

KMS preparation stays outside SQS callbacks. SQS action/tag authorization reads
current IAM and Organizations policies inside the queue callback, using its
transaction time. Waiting for queue storage cannot preserve a stale IAM allow.

KMS owns `schema/002_kms.sql`, `storage/sqlite/kms/queries.sql` and its mappings.
Material versions, rotation state and replica topology belong to a key set scoped
by partition/account. Regional keys own policies, immutable principal bindings,
tags, grants and import metadata. Grant tokens/constraints and wrapping keys have
separate relational rows. Key sets, regional transitions and aliases commit in
one native transaction. Regional deletion removes its owned rows while surviving
replicas retain shared material. Native foreign keys prevent deleting a material
set still referenced by regional keys.

Account owns `schema/003_account.sql`: scoped region deadlines, primary and
alternate contacts, and primary-email verification/publication intents.
Organizations owns `schema/004_organizations.sql`: its independent account
registry, organizations, roots, OUs, membership, policy types/documents/attachments,
tags, trusted services, delegations, root-access settings and account-creation
jobs. Its existing partition aggregate contract compares revisions and replaces
its relational children within one native transaction. Removed members remain
in the independent registry; failed writes restore both the graph and revision.
`schema/009_organizations_resource_policy.sql` adds each organization's typed
delegation policy; its tags remain ordinary tag rows in the same transaction.
Migration 10 retains the originating request, region and caller on provisioning
jobs; migration 11 adds typed account-creation event rows. Migrations 12 and 13
add typed invitations, staged tags and their journal payloads. Invitation joins
share IAM authority; expiry and retention recover through the shared scheduler.
Migrations 14/15 generalize invitations to handshakes and retain migration approval
state independently of child-history retention. IAM role inspection and feature
finalization join the same native transaction.
Revision-checked callbacks append inside the same transaction, including borrowed IAM authority.
Existing jobs retain their state and emit terminal events without invented
historical origins. See [event behavior and recovery](event-journal.md).
SDK tests verify creation/update/deletion rollback, revocation before commit and
reopening an existing schema-8 organization. See [delegation](organizations-delegation.md).

IAM owns `schema/005_iam.sql`: users, groups, roles and policy graphs, managed
versions, boundaries, instance profiles, account settings, password verifiers
and history, MFA bindings/counters, service credentials, certificates, OIDC/SAML
providers and private keys, outbound signing material, activity and report/job
snapshots. Optional records preserve presence independently of zero-valued fields.
Related maps and ordered collections have typed child tables. Credentials and
STS sessions retain signing material, expiry, key status, issuer identity,
current-policy references, session restrictions, verified claims, tags, source
identity and MFA age. No memory fallback implements part of a SQL repository.

The CLI selects Account, IAM and Organizations together. Their borrowed contexts
keep credential issuance, Organizations membership/access-role publication and
contact initialization atomic. KMS operation/authorization/service-role calls
and SQS policy-binding calls use the same database context. External effects,
including KMS preparation for SQS and email delivery, remain outside their
owning resource transactions. This does not turn an arbitrary multi-request
workflow into a single atomic command.

Database files contain credential secrets, MFA seeds and actual private
cryptographic material. Password and service-secret verifiers remain digests.
File and backup access is an operator boundary; this backend provides no separate
at-rest encryption. Keep database files and backups private.

Schema version 5 adds Account, Organizations and IAM tables through ordered
migrations using SQLite's `user_version`. Version 1 SQS and version 2 KMS data
remain intact. Upgrading cannot restore identity state that an earlier version
kept only in memory. Opening a newer schema fails with its version in the diagnosis.
Apply ordered migrations as service schemas change; do not drop/recreate state.
SQLC v1.31.1 generates checked-in query bindings. `make generate-sql` regenerates
them and `make generate-sql-check` checks drift using SQLC's native diff command.
Running the emulator requires neither SQLC nor the reference clones.

## Verification and limits

Repository tests cover complete state round trips after database close/reopen,
detached caller values, callback lifetime, cancellation, constraint failure,
rollback, parent deletion and schema version rejection. Related KMS/SQS repository
tests cover shared commit, nested failure rollback, expired callback handles and
read-only enforcement on both the default memory bundle and SQLite. SDK failure
tests verify that failed multi-Region key creation rolls back a newly provisioned
IAM service role while preserving an existing role. Queue tests revoke an IAM
permission while a send waits for storage and verify denial with no message. SDK tests cover FIFO
deduplication and visibility, receive-attempt retries, encrypted bodies and
accepted redrive recovery. A subprocess exits inside an uncommitted message
deletion; reopening recovers the committed message and its KMS key from the SQLite
files. KMS SDK tests recover signing/HMAC material, grant constraints and tokens,
import wrapping keys and expiry, and accepted multi-Region rotation. Failed
replication and promotion roll back topology and regional records together. The
existing native multi-Region scenario runs on both memory and SQLite.

Identity SDK restart tests exercise group permissions, boundaries and managed
policy versions, existing-session restrictions and expiry, password history,
MFA propagation/code reuse/authentication age, denied activity and immutable
reports, SAML signing/decryption material, and OIDC/SAML session claims.
Organizations recovery resumes accepted provisioning, publishes the access role
and copied contact, retains region deadlines and enforces OU SCPs on recovered
sessions. Shared memory/SQLite scenarios verify failed IAM renames, canceled or
failed STS issuance, role/membership rollback, concurrent service-role dependency
checks and Organizations report aggregation/cache behavior.

The same 57-operation AWS cache-scope capture runs through memory and SQLite.
Another IAM/STS/KMS/SQS test confirms that storing a redrive caller does not change
its cache identity: empty policy lists represent the same scope before and after
relational reconstruction. `CGO_ENABLED=0` builds the CLI with this backend.
A local AWS CLI run also recovered IAM credentials/policies, Organizations account
creation and access-key revocation across process restarts. Outbound JWTs issued
before and after restart verified with OpenSSL against the same public signing
key; the issuer and JWKS stayed stable on the retained endpoint. These checks
used explicit local credentials and created no AWS resources.

Clock tests reject an actual SQLite write and check cancellation while an advance
waits for a resource transaction, without blocking resource reads of time.
SDK restart tests restore the exact instant, resume pending account creation,
redeliver a message after its saved visibility deadline and expire retained STS
credentials at the saved time. A native AWS CLI run killed the server after
acknowledged advances, then restarted without an initial clock flag: exact
nanosecond time, account completion, message redelivery and STS expiry recovered.
It used only explicit local credentials and created no AWS resources.

The native SQLite transaction contract owns persistence here; AWS API semantics
use the evidence in [SQS delivery](sqs-delivery.md),
[KMS multi-Region behavior](kms-multi-region.md) and [KMS imports](kms-imports.md).

Recovery does not persist external effects. Durable scheduler
attempts, events for remaining transitions, delivery and cross-service snapshots remain in the
kernel delivery gates. The existing SQS
repository contract replaces a queue's complete delivery set on mutation; improve
that contract from measured workloads before making storage-throughput claims.

Organizations effective-policy publication uses typed account/type rows for cached
content, timestamps, pending deadlines and request origin (migrations 17 and 18).
Migration 19 stores validation errors, contributing-policy IDs and the evaluated
path in typed rows. Invalid evaluations retain the previous valid document; report
and content changes share the publication transaction. Older unvalidated tag/backup
views regenerate before they can be retained as valid content.
Attachment positions retain precedence within a target. Policy/hierarchy changes
commit publication intents and typed journal events together; workers atomically
publish the resulting view and event. [Effective-policy recovery](organizations-effective-policies.md)
covers restart, rollback, revision conflicts and legacy regeneration.

## Private CloudFormation creation claims

Migrations 375 and 376 retain Secrets Manager and AppConfig creation claims in
service-owned typed columns, committed with native state. Secrets Manager stores
independent owner/token pairs for the secret, policy, rotation and attachment;
attachment metadata remains typed. AppConfig stores owner/token pairs on each
native resource family, including immutable hosted versions.

Migrations 388–402 extend service-owned private claims and creation receipts for
Lambda event-source mappings; EC2 networking, instances, launch templates and key
pairs; EBS volumes and attachment slots; EventBridge rules and independent policy
statements; EKS resources; Scheduler groups and schedules; Step Functions machines
and activities; Pipes; Organizations accounts; and RAM permissions. Recovery
matches the scoped native object or relationship incarnation, not a same-name
replacement or a caller-supplied physical ID. EC2 termination tombstones are
retained only for authorized deletion stabilization, never new creation recovery.

Config recorder creation settings are nullable, typed private metadata, separate
from mutable recording status and public tags. Legacy and ordinary native rows
without a known `StartedOnCreate` setting do not acquire an invented value.

Ordinary authorized native and Cloud Control updates preserve existing private
claims. Removing a resource or relationship invalidates its claim; recreating the
same public name, ARN or statement ID does not transfer the old stack's authority.
Resource Groups stack membership resolves live private claims and canonical native
identities from ledger candidates; public tags are not a membership proof.

Lambda image retention stores the admitted source identity separately from its
actual Docker-derived snapshot identity and private lease (schemas 389 and 402).
Deployment and live execution roots drive collection outside repository
transactions. Durable native image labels make a late commit discoverable after a
lost response; cleanup removes only unreferenced owned artifacts, never a source
image, foreign user reference or daemon-wide image inventory.

Public tags on taggable resources are never backfilled into ownership authority.
The AppConfig hosted-version migration moves its historical internal marker
metadata because hosted versions are not public taggable resources. Recovery
still requires current native authorization and the exact claim; SQLite
persistence is not permission to adopt a same-name foreign row.
