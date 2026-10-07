# Architecture

Stackd is a Go-native implementation of a local AWS cloud. The full emulator goal
remains active and incomplete: the generated [operation inventory](services.json)
contains every operation in the pinned AWS SDK Smithy models for the explicitly
[chosen services](service-targets.json), including implemented prerequisites and
behavior across services. Selection sets service scope; models define protocol
contracts, not implementation completeness. CloudTrail Lake is excluded from the
behavioral target, remains model-known and returns honest unsupported errors.
SMTP, hardware MFA and specialty KMS remain deferred. Primary AWS documentation
and native captures define semantics.
No Python or cloud account is required for the Go control plane. Lambda, ECS,
DynamoDB Local and Kinesis execution require a separately configured per-instance
container runtime.

The accepted [kernel design](verification-kernel.md) adds coordinated typed state
and an append-only event log, deterministic service time and scheduling, consistent
test forks, reusable IAM decisions and real compute/engine adapters. Shared clock
injection, optional persistent manual time, committed identity/Organizations/API
events and joined IAM/Organizations/SQS/KMS/EventBridge/Lambda/CloudTrail/Logs/
CloudWatch/SNS execution are implemented. EventBridge and SNS commit accepted
publications and target intents together; target retries, DLQ work, Lambda
asynchronous attempts and completed outcomes, SNS/Lambda/SQS/EventBridge/API Gateway
metric groups, ECS utilization windows and CloudTrail S3 batches survive restart.
Broader service jobs and consistent forks remain priorities.
AWS responses do not acquire fidelity labels. CloudTrail history and selected
API outcomes from the implemented services feed actual S3 gzip logs and EventBridge delivery. Lambda executes
ZIP deployments in official runtime containers. Native workflows expose the next
IAM, storage and source/target dependencies; service-depth gaps remain explicit.

The [cross-service consistency audit](service-consistency.md) records shared
implementation invariants, inspected owner coverage, verified corrections and
remaining native-contract questions. Service-specific AWS differences are not
normalized merely to make sibling code look alike.

GuardDuty evaluates typed root-credential, password-policy attempt,
CloudTrail/S3 logging-change, S3 public-access-block, public bucket ACL and bounded
anonymous bucket-policy grant rules inside the API-event transaction. Evidence
comes from admitted S3 state; policy grants use the shared IAM action/resource
solver with nonempty 1024-byte object-key bounds, not `IsPublic` or request text.
Literal transport and anonymous principal conditions use the shared IAM
interpreter with separate HTTP and HTTPS contexts, preserving correlation with
grants and denies. Anonymous account identity and absent service-principal
context do not come from the signed policy writer.
Source outcome, observed evidence and finding publication intent commit together,
without a polling cursor or sample template. Conditional/variable policy proofs
and authenticated audiences remain incomplete, not Zelkova equivalence.
The scheduler publishes through EventBridge with source-event causality and
expires findings transactionally at the local 90-day creation cap. APIs hide
expired rows before sweeping; native retention timestamp calibration remains open.
S3 data-event protection gates the transactional S3 producer's authenticated
requests; enablement does not replay history. EKS native audit admission feeds a
separate typed journal source, metadata predicates and admitted anonymous RBAC
binding grants independently of CloudWatch logging. Ordered subject rows and
typed role references come from native successful responses, not proposed
requests or dry runs. Effective deletion options retain body/query precedence;
successful API access is not a claim that an object was deleted. Source-scoped
admission deduplication, observations and publication intent
share the EKS transaction. DNS/flow telemetry and remaining optional
protections remain unimplemented. See
[GuardDuty boundaries and evidence](guardduty.md).
GuardDuty IP-list intent and caller-authorized service-role grants commit together.
S3/KMS ingestion runs outside transactions; version-fenced completion retains
ACTIVE/ERROR state and normalized immutable IPv4 snapshots. API-event detection
queries active intervals in the source transaction, applies trusted precedence,
and retains matched threat-list names with observed findings.
GuardDuty publishing destinations validate through the current S3/KMS owners.
Finding transitions commit retained export payloads and publication cursors;
external encrypted writes run outside transactions with source-event causality.
Version/publication identity fences protect destination replacement and stale
completion. Scoped SQL deadline queries avoid reading every pending payload.
S3 excludes archived findings independently of EventBridge publication rules.
EC2 networking/key-pair controls and ECS controls, standalone tasks and replica services share the
typed memory/SQLite transaction boundary. Task/deployment intent, managed ENIs
and state events commit through service-owned integrations; real Docker processes
and native packet enforcement stay outside resource transactions. [ECS](ecs.md) owns the authoritative runtime
contract, dependency/credential/log behavior, restart reattachment and evidence.
[EC2](ec2.md) owns networking, key-pair, instance/image and EBS consumer intent;
QEMU/KVM supplies actual guest execution. Broader hardware and service dependencies
remain open.
[EKS](eks.md) retains scoped cluster/access/update intent in the same memory/SQLC
domain and performs native k3d effects outside transactions. Shared gateway
SigV4 verification authenticates current IAM credentials, while Kubernetes RBAC
enforces published access-policy rules and namespace scopes. Private native admin
credentials never enter user kubeconfigs. Stable TLS endpoints and real workloads
reattach after controller replacement; deletion requires exact native ownership.
Default nodes are real k3s workers, not fictional EC2 or managed node groups.
The initial ELBv2 owner retains scoped ALBs, listeners, ordered rules, target
groups, target incarnations and health/drain deadlines in its typed repository.
EC2 ENI allocation and the corresponding ALB attachment commit in one shared
transaction; native Docker nodes, sockets and packet-policy effects run outside it.
Per-resource workers keep slow health probes off the shared scheduler's serial
gate. Current EC2 target identities fence both probe results and forwarding;
in-flight requests retain their registration generation until drain completion.
IAM and ACM own certificate material and immutable certificate identities. ALB
listeners retain those identities, not private keys; deletion consults current
listener dependencies in the same transaction (all-region for IAM, regional for
ACM). Each ACM TLS handshake reads the current material version, so renewal
reaches existing listeners without replacing their resource identity. ECS
consumes the same target owner for deployment-specific registration,
health-gated rollout and drain-before-stop.
The shared UDP/TCP DNS endpoint delegates ALB resolution to that same owner;
it does not retain a second resource registry. Stable AWS-shaped names resolve
current EC2 addresses, survive restart and disappear on deletion. Resolver
configuration is explicit and does not change the host's DNS settings.
The [ALB evidence and limits](behavior-references.md#application-load-balancer-kernel)
describe its concrete packet path and unsupported service surface.
[Route 53](route53.md) attaches its typed hosted-zone/record authority to this same
endpoint after managed service namespaces. Atomic changes, negative answers,
wildcards, delegation, weighted/multivalue routing and owner-resolved aliases
read one retained state. Private VPC zones are rejected rather than exposed on
the public listener. [ACM](acm.md) uses actual CNAME wire queries against it,
performs DNS and cryptographic effects outside storage transactions, and commits
version-fenced certificates through the shared scheduler and repositories.
Its durable signing authority is explicitly local trust, not an AWS/public CA.
EBS owns typed snapshot/volume metadata, sparse block layers, sharing grants,
recipient-private tags and regional encryption/public-access settings; EC2's
consumer-defined `SnapshotControl` and `VolumeControl` delegate to that owner. Published Organizations
snapshot policy overrides use the existing management-policy publication owner.
KMS admission and grant mutations join the snapshot transaction, while an opted-in synchronous audit
scope retains sanitized child outcomes after a command savepoint fails. It does
not retain resource mutations or replay operations. Enclosing transactions remain
authoritative. Snapshot completion/readiness/timeout/deletion, sharing publication
and volume creation/modification/deletion deadlines join the shared driver. Resolved owner context supplies
paired audit recipients without post-write lookups or another metadata store.
EC2 copies materialize independent destination block layers while preserving
lineage. Typed copy provenance owns their completion event and causal origin;
no raw request or bearer URL is retained. Copy completion and native EventBridge
admission share one transaction. Real regional KMS grants separate caller
CreateGrant/key-generation authority from service cryptographic execution.
Bulk block transfer does not run inside API admission transactions. Snapshot
copies, snapshot-backed volumes and captures of standalone SQL-backed volumes
retain typed work and source references, then transfer detached 512-KiB blocks
through short transactions. Payload encryption runs outside those transactions.
Destination block rows are the restart cursor; no second progress ledger is
needed. Source references retain immutable bytes across deletion and native
volume handoff until the last admitted consumer finishes. Partial destinations
cannot become readable snapshots or available volumes. Snapshot completion and
readability deadlines start at actual payload completion, so delayed recovery
cannot publish a stale successful time-based-copy outcome.
Volume hydration transfers byte authority from typed blocks to one native qcow2
disk; subsequent guest writes are not mirrored in a second store. Snapshot capture
materializes independent immutable block layers from real disk bytes. Typed
provenance retains KMS volume context and block origins retain AEAD identity.
Native effects run outside resource transactions. EC2-owned attachment/lifecycle
state, EventBridge admissions and API records share the transaction domain.
Measured CPU-credit windows feed CloudWatch; typed credential scope reaches
CloudTrail through journal schema 196. This is not a whole-cloud MVCC fork.
EC2/VPC and related services share the existing compute owners. Glue/Athena,
ECR/CodeBuild, SSM parameters/managed execution, engine-backed RDS/RDS Data and EventBridge
Scheduler/Pipes are integrated. Parameter Store references use live Secrets Manager
authority and real compute consumers. Scheduler/Pipes share the clock and job
driver, retained retry/checkpoint state and existing source/target owners; real
effects remain outside transactions. Their signed executable proof includes
actual Lambda, source streams, IAM/KMS failures and controller restart.
Classic SES Query and SES v2 REST are two generated frontends of one email owner.
Their shared signer routes generated REST paths before the classic Query fallback,
independent of registration order. Identity verification, bound sending policies,
templates, configuration controls, actual MIME and capture-retry jobs use the same
typed memory/SQLC transaction domain consumed by Cognito. Current IAM conditions
use native `ses:ApiVersion` values `1`/`2`; successful API outcomes commit with
message admission and resolved source-identity ownership. Actual capture writes
remain post-commit effects, not simulated SMTP delivery. See [email behavior and
explicit owner gaps](cognito.md#classic-ses-and-shared-sending-authority).
CloudFormation now owns retained deployment operations and delegates physical
resource effects through an explicit version-one consumer-defined handler
boundary to the existing service commands. Schema 223 stores stack, change-set,
resource-incarnation, event, export and operation/action rows in the shared
memory/SQLC domain. Template expressions and property before-images are deployment
intent, not a second resource database. Intent commits before owner effects;
stable incarnation tokens and ownership claims fence recovery. Asynchronous
Lambda/source-mapping stabilization yields to the shared scheduler rather than
blocking the service jobs it awaits. Current caller policies or a freshly
assumed CloudFormation role govern every command. Unsupported effects fail
explicitly; [deployment boundaries](behavior-references.md#cloudformation-deployments)
remain narrower than all CloudFormation resource schemas.
Cloud Control reuses that handler registry and adds owner-authoritative resource
reads/lists rather than a parallel resource store. Its typed schema246 rows retain
asynchronous request identity, admitted update before/desired state and progress;
the shared driver runs owner commands outside transactions. Cancellation fences
future handler calls without fabricating rollback. Schema247 separately retains
CloudFormation's resolved SSM parameter values and change-set rollback preference,
so later parameter changes or controller replacement cannot rewrite admitted intent.
[AWS Config](config.md) observes successful S3/SQS owner transitions inside the
same transaction and retains immutable configuration items, not a competing
resource store. Current recorder-role checks use the existing IAM evaluator;
failed capture does not roll back the source command. S3/SNS delivery and real
Lambda rule effects run outside transactions through the shared scheduler.
[Resource Groups and AppRegistry](resourcegroups.md) retain application metadata,
group definitions and incarnation-fenced admitted transitions, not a second
resource catalog or tag store. Application tag effects use coordinated current
S3/SQS/SSM/CloudFormation owners. AppRegistry, managed groups, owner mutations and
successful API history share one transaction; grouping failures use isolated
attempts. Retained tag-sync jobs freshly assume current IAM roles. A one-second
lifecycle snapshot source publishes through transactional EventBridge, preserving
sequences across restart without pretending to reproduce AWS's internal capture
rules. Normalized application/group/task/snapshot state and stable S3/SSM
incarnations survive SQLite reopen.
[AppConfig](appconfig.md) owns immutable admitted configuration, rollout and
polling state in normalized schemas257/259. Source retrieval, KMS and actual
Lambda extension effects use consumer-defined owner interfaces outside state
transactions. SSM strategy replication joins the shared transaction; schema258
adds configuration document types to the existing SSM owner without changing
retained Command documents. Official Agent targeting stays in the real Agent.
[CodePipeline](codepipeline.md) owns scoped versioned definitions, execution and
action history, source revisions and artifact locators in typed repositories.
Its scheduler claims commit with state; S3 copies, real CodeBuild execution and
AppConfig deployment run outside transactions under current role authority.
CodeBuild and AppConfig resolve the same retained artifact owner, not synthetic
source archives or a parallel configuration store. EventBridge targets start
actual executions, and lifecycle notifications join the existing event owner.
EventBridge API Destination controls and authenticated HTTPS delivery share one
typed owner with Connections, retained rate admission and current IAM/KMS
authority. Rules and Pipes consume its delivery outcomes; Pipes retains source
retry/acknowledgement ownership, including HTTP minimum delays across restart.
CloudFormation delegates rule/target effects to EventBridge rather than keeping
a second destination allowlist or HTTP implementation. The combined schema
222→224 executable upgrade preserved existing identities, credentials, source
work and audit history, then deployed and updated a real HTTPS target across
restart. [Observed upgrade evidence](../testdata/integration/cloudformation_api_destination_upgrade.json)
records exact-owned cleanup and both normal controller exits.
Engine-backed OpenSearch owns actual native
domains; MSK owns public native Kafka clusters consumed by Pipes and Lambda
separately from Kinesis's private log. ElastiCache/MemoryDB share a pinned real
Valkey adapter while retaining separate typed service controls. Cross-service
CloudTrail calibration remains ongoing.
QEMU/KVM is the selected EC2 backend for firmware-booted HVM images behind an instance-lifecycle interface.
There is no direct-kernel or container fallback. Shared compute infrastructure
consumes the existing EC2 networking authority.
Lambda Runtime API execution, ECS task coordination and EC2 guest/disk lifecycle
remain distinct service contracts; no generic provider framework is added merely
to plan a second backend. [EC2 ownership](ec2.md#execution-and-shared-compute-ownership)
records prerequisites and the concrete extraction boundary.

Glue owns typed catalog, jobs, crawlers, schemas and workflow intent. Athena owns
workgroups, saved/prepared statements, effective query settings and retained query
state. Both join the existing memory/SQLite transaction, clock, scheduler and
API-event domain. External native processes run outside those transactions.
Source state changes and EventBridge admissions commit together; workflows use
the existing savepoint boundary for a handled child rejection.

Glue uses current IAM/STS service-role sessions for ordinary S3/KMS/Logs commands;
its native Python/Spark containers do not inherit host AWS credentials. Athena
forwards its admitted caller through ordinary Glue/S3 command boundaries, retaining
caller policies, conditions and public audit scope in typed query persistence.
Its private native callback capability is not a second AWS identity issuer.
Header signatures, aws-chunked framing and transfer checksums remain owned by the
same gateway implementation used by public S3 transport. Trino executes SQL;
Apache Spark's native parser supplies Hive-DDL syntax trees only, not query results.
Native process cancellation/recovery and resource transactions are not a single
atomic external transaction. See the [analytics evidence and limits](behavior-references.md#glue-and-athena-engines-evidence-and-boundaries).

Glue run inspection and cancellation resolve the job definition's current tags;
deleting the definition does not delete retained runs or remove their ordinary
IAM authorization. Connection audit projection has one redaction owner for the
base properties and all three compute-override maps, including rejected requests.
Password encryption remains on connection creation/update through KMS; encrypted
return controls stored-ciphertext projection, not an invented catalog migration.

Native Glue container ownership/process state is authoritative independently of
optional logs and Spark metrics. Observation failures persist in the existing
run log diagnostic field without changing process outcome or preventing
stop/removal; incomplete event-log counters are not published as complete metrics.
Log-publication failures append rather than overwrite those diagnostics.

Secrets Manager owns typed metadata, immutable versions, encrypted values,
policies, replication and rotation work within the same transaction domain.
KMS commands use native savepoints for handled nested rejections and join storage
before acquiring their working-set lock. EventBridge Connections own public
metadata and consume this secret owner through an interface; credentials are not
duplicated in EventBridge storage. Step Functions consumes the Connection
resolver and real HTTPS client with its existing caller credential-read boundary.
EventBridge API destinations instead own a service-managed invocation boundary,
rechecking target-role `InvokeApiDestination` and current Connection/secret/KMS
authority. Rule delivery and Pipes share that HTTP owner; each retains its existing
retry/acknowledgement engine. OAuth and Lambda rotation effects execute outside
transactions. [Secrets Manager](secretsmanager.md) records behavior and remaining
causality/partner boundaries; this is not a claim of general MVCC forks or complete
service parity.

SSM Parameter Store owns typed metadata, immutable encrypted versions, labels,
policies and pending image validation, not another KMS or Secrets Manager store.
KMS authority and the framed AWS Encryption SDK envelope serve standard/advanced
SecureString workflows. IAM path recursion and history remain operation-specific.
Policy deadlines and EC2 validation join the shared job driver; handled EC2
rejections use a savepoint before committing the terminal parameter result.
CodeBuild and ECS consume ordinary GetParameters under existing build/execution
roles; native container environments receive transient values only at creation.
The reserved Secrets Manager reference namespace is stateless pass-through to
that existing owner, preserving caller IAM/KMS authority and native dependency
error projection rather than materializing parameters or secret metadata.
See [Systems Manager evidence and boundaries](ssm.md).

SSM Command documents, managed-node health and Run Command own separate typed
repositories. Documents retain incarnation UUIDs and immutable executable versions;
commands snapshot admitted content and retain per-node/per-plugin outcomes.
Shared scheduling activates Creating/Updating versions, settles Pending
zero-target commands and drives delivery expiry, while the official EC2 guest agent owns
processes, stdout/stderr, cancellation and S3/CloudWatch uploads. Native signed
control channels consume existing instance-profile credentials, current IAM and
EC2 state; no SSH or second compute executor is introduced. Committed message IDs,
reply deduplication and the agent's durable state fence reconnect/restart retries.
The authoritative serialized execution payload also supplies native size admission:
oversized work cannot enter retained delivery state and poison a control channel.
Public API snapshots and CloudTrail projections share actual lifecycle state;
sensitive audit redaction never changes customer parameters or output bytes.
Run Command notification intents commit with command/invocation transitions.
Their separate scheduler publishes through the current SNS owner outside the SSM
transaction, rechecking the admitted role incarnation, current trust and publish
authority. Typed schema 311 retains configuration and pending/delivered intents
across controller restart. The 30-second retry cadence is local scheduling, not
measured AWS timing; a crash after SNS acceptance can produce duplicate delivery.
Run Command alarm polls use the current Systems Manager service-linked role and
CloudWatch owner outside the command transaction. Schema312 retains configuration,
role identity, poll revision/deadline and triggered state; the commit rechecks
command revision and terminal/cancellation state. Alarm failure stops pending
delivery and freezes public failure snapshots without cancelling an already-running
guest shell, as demonstrated by native and local guest marker readback. Current
document access is resolved again inside admission, and active monitoring joins
IAM's atomic role-deletion usage check. The five-second cadence is local scheduling.

RDS owns scoped instance/cluster intent, parameter and subnet groups, encrypted
master credentials, snapshots and retained generation-fenced lifecycle work.
Its memory/SQLC repositories share the existing transaction domain; PostgreSQL
and MySQL I/O, password changes and physical snapshot copies run outside it.
The caller-owned runtime retains native data and endpoint identity across
controller replacement. RDS Data API resolves only eligible available clusters,
authorizes each current caller, retrieves credentials through Secrets Manager
and executes native SQL through real drivers. Opaque transaction leases are
process-local and roll back at shutdown; restart invalidates their IDs.
Shared scheduling owns idle/hard deadlines. [RDS boundaries](rds.md) distinguish
these concrete engines from unimplemented AWS Aurora/VPC capabilities.

DocumentDB has its own typed cluster/member/snapshot repository and native
TLS/SCRAM document engine, while RDS composes their genuinely shared Query
namespace. Engine and current owner select mutations; authoritative owner
projections are unioned before list filtering/pagination. Generated typed
conversions reject incompatible fields instead of discarding effects. Both owners
share current IAM, protected RDS role usage, encrypted credentials and lifecycle
scheduling. DocumentDB's connection lookup supplies Lambda native endpoint/trust
and immutable incarnation without copied resource state or administrator secrets.
The same current-owner lookup reports writer readiness separately from identity:
Lambda mapping admission checks IAM, secrets and incarnation without connecting
to the engine; polling requires a ready writer and an authorized native watch.
CloudFormation preserves the creation namespace on updates, while direct Lambda
namespace-update parameters are rejected; neither path resets the resume token.
The pinned MongoDB backend provides real documents and change streams, not AWS
DocumentDB's distributed storage or complete semantics; [explicit boundaries](documentdb.md)
include the unsupported AWS-specific change-stream enablement controls.

OpenSearch owns typed scoped domain/configuration/policy/tag rows and
incarnation/version-fenced lifecycle work in that same memory/SQLC transaction
domain. Modern OpenSearch and legacy ES generated frontends share one service.
The consumer-owned runtime interface provisions one pinned native node per
incarnation, preserving bytes in an exact-owned volume; readiness, configuration
updates, measured metrics and deletion run outside transactions. Restart clears
unverified endpoint state and reattaches only after a real native response.
The gateway's provider-owned data route reuses current SigV4/STS authority before
the service evaluates current IAM, domain resource policy and tags. Native REST
bytes and errors pass through; indexing/search are not SQL control rows.
Before policy evaluation, the service rejects dot segments and redundant literal
trailing separators that native routing could normalize to another resource.
Trailing-separator validation uses the escaped URI, preserving encoded slashes
inside document IDs and the native root endpoint.
Only ordinary policy layers see native-calibrated old/new ES action aliases;
Organizations layers retain the actual requested action. Exact incarnation
paths fence stale endpoints after same-name recreation. Domain-management APIs
produce source-owned `es.amazonaws.com` audit events; engine data requests do
not fabricate CloudTrail events. [Evidence and boundaries](behavior-references.md#opensearch-engines-evidence-and-boundaries)
separate this single-node local engine from unsupported managed infrastructure.
ElastiCache and MemoryDB own users, user groups/ACLs, parameter and subnet groups,
cluster topology, snapshots and generation-fenced retained work in service-owned
memory/SQLC repositories. Both inject `engine/valkey` through their consumer-owned
runtime interfaces. ACL/password changes, native CONFIG application, topology,
RDB/AOF bytes and container lifecycle run outside repository transactions;
readiness observes actual engine roles, slots and replica links. SQLite shutdown
detaches rather than destroying durable data. Exact namespace/incarnation labels
guard native removal; ephemeral CLI shutdown disposes only retained owned IDs.
The shared API recorder projects redacted management calls; CloudWatch samples
actual native gauges. Subnet groups validate EC2-owned subnets without claiming
VPC attachment. Native TLS/ACL authentication is distinct from control-plane IAM.
[Valkey boundaries](behavior-references.md#elasticache-and-memorydb-native-valkey)
separate real local replication/durability from AWS-managed physical storage,
distributed MemoryDB logging, automatic failover and managed networking.

ECR owns typed repositories, image manifests, content-addressed layer bytes,
tokens, lifecycle work, scan results and replication work in the shared
memory/SQLite domain. Registry requests use current IAM and resource policies;
an authorization token is not a policy snapshot. KMS grants and per-payload
envelope keys reuse the KMS owner. Native Trivy execution happens outside storage
transactions; completion checks the current image/scan identity before committing
findings and the native EventBridge notification. Replication selects current work
and commits the destination bytes and outcome together, using a nested savepoint
to roll back rejected destination effects without overwriting newer work.

CodeBuild's controller and `compute/codebuild` are a service-specific Docker
boundary, not a generic executor or second credential authority. Accepted
configuration, state/phase history and events share the transaction domain;
source retrieval and customer commands run outside it. IAM owns role validation,
PassRole and expiring sessions. Authenticated container metadata refreshes those
sessions, while downstream calls evaluate current permissions. S3 owns source,
artifact and cache objects; Logs owns command output; Secrets Manager and KMS own
secrets and source-credential encryption. Public Git source authority is checked
before credential resolution, including retained builds. Terminal cleanup removes
exact namespace/build-owned staging even when no main execution exists, and
removal failures retain cleanup intent. Fleet identity includes its UUID
incarnation; retained admitted BuildRecords keep deleting fleets alive through
source/image preparation and cleanup without a second lease ledger. Native idle
capacity is observed before ACTIVE is published. Output archive selection skips
unrelated links without following them; source extraction remains strict.
See [evidence and explicit limits](behavior-references.md#ecr-and-codebuild).

Cognito user pools own typed pool/client/user/group configuration, memberships,
password verifiers, single-use challenges and refresh families in the shared transaction domain.
Schema 164 keeps private signing keys separate from pool descriptions, with
distinct access/ID JWT keys and public JWKS. Cognito token APIs check current
session state; offline signature verification alone does not observe revocation.
Generated public operations enter without IAM identity, resolve recipient scope
from actual resources and use service-owned client/user proofs. Resource ownership
never grants the public caller IAM authority. Signed administrative commands retain
ordinary IAM checks, including dependent `iam:PassRole` checks before group
mutation. Native role admission—not another service's integration—defines which
IAM condition keys are available. Schema 165 adds scoped relational groups and memberships;
token issuance reads current membership rather than copying roles into sessions.
Schema 166 retains revoked refresh-family metadata after user deletion without
retaining the user profile or memberships. Bearer-owned profile mutations reuse
the same schema, client-permission and transactional persistence owners as admin
commands; user lookup itself does not imply authentication or audit attribution.
Schema 167 retains historical refresh-token ownership, fixed retry grace and
generation origins, distinguishing family revocation from global sign-out.
[Cognito](cognito.md) owns the 47-operation application scope, native
login/group/profile/rotation/admission/audit evidence and unsupported delivery/authentication paths.

[Identity Store](identity-store.md) supplies typed directory membership to
[Identity Center](identity-center.md). Permission sets provision real IAM roles
through a trusted owner interface; public IAM mutations cannot take over those
roles, and ordinary SCP/RCP enforcement still applies. Current organization
eligibility is rechecked for account effects. OIDC device grants and SSO account
credentials retain their own lifecycle, with no copied IAM authorization engine.
[Cognito Identity](cognito-identity.md) resolves current user-pool proofs and role
mappings through the existing Cognito/STS owners.

[AppSync](appsync.md) owns schemas, resolvers, authentication configuration and
GraphQL execution. Consumer-owned source/authentication interfaces connect its
JavaScript runtime to DynamoDB, Lambda, HTTP, RDS Data, Cognito and IAM; those
owners retain data and authorization. The data endpoint and live subscription
sessions share retained API configuration without a second data-resource store.

DynamoDB keeps scoped table/index intent, policies and retained Streams in typed
Go repositories; the pinned native engine owns item storage, expressions and
item transactions. A per-database mutation gate brackets native writes with
stream ingestion. Copied records and their ingestion checkpoint commit together,
not with the external engine's item transaction. A TTL expiry retains its
conditional candidate and service-time origin before the native effect. Recovery
resolves that candidate before later native writes; its matching removal,
checkpoint and ownership clearance commit together. TTL origin is distinct from
the shared item capture used by continuous recovery and replication. The native
engine remains outside the Go transaction; service time owns TTL and public
stream retention. This is not a cross-engine MVCC snapshot or an
exactly-once Lambda source. See [DynamoDB evidence and remaining boundaries](behavior-references.md#dynamodb-engine-references).
On-demand backup admission commits a typed snapshot marker and its API outcome
under that same mutation gate. Before any later native mutation, including TTL
or physical deletion, the pending snapshot is copied into a private native table.
Paginated strongly consistent Scan alone is not snapshot isolation. Interrupted
copies replay against the unchanged source; their items stay in native storage,
without copy receipts in the Go repository. Backup references retain the engine after
source deletion. Restore keeps its source reference until native rows and indexes
are ready, then commits ACTIVE and service-time billing history. These scoped
copies do not provide a general store fork or cross-engine MVCC transaction.

Continuous recovery uses a private native baseline per enabled interval and a
service-owned typed item-postimage log. The shared mutation plans identify keys;
one database-scoped capture commits before native execution. Actual postimages,
PITR history, replica changes and capture removal commit together. Replication
also retains preimages to distinguish real changes from successful no-ops.
After an ambiguous native failure, actual reads settle those keys before another
mutation; customer update expressions are never replayed. TTL
retains its original accepted service time. Public Streams configuration is
independent. Restore admission pins time and sequence, including an empty cut,
so later writes at frozen time cannot enter a pending restore. Pending targets
also prevent baseline compaction: retry needs the original tombstones to remove
items from a partially populated native target. Retention folds expired images
outside repository transactions and commits trimming only after the fold.
PITR-enabled deletion creates a SYSTEM snapshot through the same backup owner,
using the final configuration at native deletion rather than API admission.
Control updates during DELETING first establish that the physical source still
exists. Expiry excludes new admissions but preserves already accepted restores.
Initial continuous-backup availability derives from the table incarnation's
creation time and actual creation/restore state, independently of PITR enablement.
Five service seconds model local registration; a still-CREATING target remains
unavailable after registration. This is not an AWS timing guarantee or another
persisted readiness workflow.

Version-2019 same-account replication owns membership and a typed change log,
not a second customer API dispatcher. Bootstrap takes an immutable private native
snapshot under the source gate, pins its consumed cursor and conflict versions,
then copies it under the destination gate. Ordinary delivery holds only the
destination gate, rechecks incarnation and current service-role permissions,
and applies absolute images through the existing native capture, Streams,
recovery and capacity owners. Incoming writes retain their original version and
do not echo. The logical pre-effect version order is an emulator choice, not
AWS's unpublished timestamp algorithm. Acknowledged cursors and unresolved
captures bound pruning. Normal final-member removal waits for surviving delivery;
authorization-expiry detachment retains each Region's current data instead.
Membership waits only for the admitted request's targets, avoiding cycles between
independent regional requests. Native data, SQLite and external runtimes still
do not form one MVCC transaction or a general replay/fork facility.
Completed removals may shrink an already-locked member set; deletion readiness
uses the current survivors, not the stale plan. Additions or changed incarnations
still require a new lock plan.

Provisioned replica admission consumes the small `ReplicaScaling` interface.
Application Auto Scaling remains authoritative for target/policy state, validates
the source table and GSI write prerequisites, and installs regional configurations
through its existing authorized, audited commands in the shared transaction.
Its capacity executor enters DynamoDB's regional `UpdateCapacity` command, not
the customer's globally propagating `UpdateTable`. Both share regional admission
and recording. Regional capacity commits metadata without taking engine gates
inside the scaling transaction; physical reconciliation remains outside it.
Global billing transitions use the same scaling owner. Entering on-demand leaves
targets, policies and tags registered. A switch back to provisioned removes old
policies through customer-authorized commands forwarded by DynamoDB; completed
native mode observation installs table/GSI defaults under the replication role.
Target identities, tags and suspension flags survive registration updates.
Policy/managed-alarm replacement joins the shared transaction; no parallel
configuration snapshot or scaling suspension state is retained by DynamoDB.
Replica/source-setting exclusions are recorded at the public command boundary,
before resource lookup and engine planning. Attribute definitions do not constitute
a separate operation; empty GSI update lists are rejected at that same boundary.
Replica-autoscaling APIs read current target/policy state through that same
consumer-defined interface. Update admission validates membership, billing and
field presence before any dependent mutation, then returns the pre-update
description. Dependent commands run outside the parent transaction: successful
siblings and target registration survive a later policy error, as on AWS.
Registration and policy installation use the replication SLR; service-owned
removal keeps customer attribution without requiring public autoscaling grants.
Policyless targets and on-demand settings retain their distinct public views.

Legacy global-table APIs remain separate from current replication. Native AWS
rejects new version-2017 groups even when the regional prerequisites are valid.
Their commands enforce the global ARN and named regional-resource permissions,
then the observed retirement/lookup rules; they never reinterpret current groups
as legacy resources. No second group repository, replication log or historical
data-plane state machine exists without a reachable creation command.

Kinesis keeps stream intent, shard ancestry, consumer registrations, policies and
pending metric samples in typed repositories. Apache Kafka owns the durable bytes,
offsets and timestamp index, with one isolated native log per stream incarnation.
A per-stream gate serializes routing, native appends, reads, resharding and
retirement; no Kafka call runs inside a repository transaction. Preparing native
partitions precedes publishing new topology. Parent partitions remain readable
until service-time retention removes their prefixes through Kafka's own API.
Metadata and native effects are not a distributed transaction or an MVCC fork.
An acknowledgment lost across that boundary can require a retry and duplicate a
record; no second payload store or bespoke commit protocol hides this distinction.

Registered consumer connections authorize once against the exact consumer ARN.
Bounded native reads feed the generated AWS event stream; cancellation, renewal,
service-time expiry and closed-parent child-shard frames own connection lifetime.
Empty subscriptions emit five-second heartbeats; newly available records do not
wait for that heartbeat deadline.
Record encryption uses actual KMS data keys outside transactions, with per-requester
bounded reuse and per-record wrapped-key metadata so old encrypted/plain records
remain readable after stream settings change. Stream observations commit with API
outcomes, then publish completed minute samples through CloudWatch's existing
transactional owner. Only observed requests and subscription frames create samples;
there is no periodic idle-zero job or per-stream idle metric deadline. Enhanced
shard byte samples retain individual record sizes, while stream samples aggregate
each put operation. Iterator age follows read backlog, including caught-up zeros.

Kinesis projects native audit detail and history aliases separately. Display-only
resource anomalies never replace the canonical resource used by IAM and command
lookup. Native fixture replay checks the configured S3/EventBridge consumers as
well as the source event projection.

MSK owns a separate generated `kafka` service and typed memory/SQLC repository
(`221_msk.sql`). Its consumer-owned runtime contract runs actual Kafka broker/
controller processes through the existing Docker client. Every broker, config/data
volume and isolated network belongs to the persisted scope and cluster incarnation.
Native readiness/configuration/reboot/delete run outside resource transactions;
retained versions fence their results. SQLite controller shutdown detaches,
whereas delete verifies exact ownership before retiring data. Public protocol
offsets, groups, retention and topics are Kafka's, never a second Go payload store
or the Kinesis service clock/retention contract.

Accepted public security modes are loopback plaintext, TLS, and TLS/SCRAM-SHA-512.
The private administrative listener uses SCRAM/TLS; broker/controller traffic uses
mutual TLS. Native ACLs protect cluster security administration while public clients
retain topic/group operations. MSK's IAM control/resource authority is distinct
from data-engine credentials. SCRAM associations read current Secrets Manager/KMS
credentials outside the transaction; scoped secret policy changes join the cluster
intent transaction, and native credential installation is a retained external
effect. No public IAM-data-authentication, VPC, managed encrypted volume, mTLS-client
or monitoring setting is returned as effective without its implementation.

Lambda's MSK adapter reuses that Kafka connector under the current function
execution role. Schema 240 retains mapping configuration and cluster/topic
identity, not another offset ledger. Actual synchronous function results govern
broker commits; retained retries must still pass current authority, source
identity and native retention checks. [Lambda](lambda.md#msk-event-source-mappings)
owns the payload, recovery evidence and remaining source-option boundaries.

DynamoDB's existing mutation capture snapshots Kinesis destination membership
alongside its other write consumers. Actual before/after images produce retained
destination work, preserving transaction-specific no-op behavior and incarnation
isolation. Current service-linked-role authority governs external Kinesis writes;
retry acknowledgment updates the typed outbox after the native effect.
EventBridge likewise retains its selected Kinesis target configuration and invokes
a consumer-defined record-writer interface under the existing target role.
Neither adapter bypasses Kinesis authorization, encryption, admission or audit.

Lambda's DynamoDB and Kinesis adapters implement consumer-owned stream interfaces.
One processor owns retained shard progress, per-key lanes, batching, retries,
partial acknowledgments, bisection and window state. Kinesis owns authorized
topology and opaque checkpoint creation; standard readers use ordinary generated
commands, while enhanced-fan-out readers own renewable subscription channels.
Source capture remains outside transactions. Independent ready shards execute
concurrently; descendants wait for all parents to drain. Record retention and
both merge parents are retained facts, not assumptions reconstructed from a
single-parent API response.

Logs shares one subscription matcher and compressed-work scheduler across Lambda
and Kinesis. Kinesis adapters assume the retained delivery role and call ordinary
`PutRecord`; admission sends a real control record without requiring unrelated
read permissions. Logical destinations own target, role, policy and tags.
Destination updates affect future batches; already accepted work keeps its
target, authority, partition key and bytes. IAM policy admission and destination
authorization are separate from the external record write.

Backup request budgets are separate from resource transitions and native data
capacity. A consumer-defined gateway interface invokes the provider after
authentication but before generated input validation; the provider owns scope,
rates and service-time refill. The gateway does not parse service policy or
dispatch a rejected command. Native prebinding throttle audits retain caller
context without binding the rejected input. These ephemeral request allowances
do not become a second durable ledger.

Source-owned capacity observations commit with API audit outcomes in the Go
repository, then publish into CloudWatch transactionally at completed-minute
boundaries. That publication is recoverable; the preceding native item effect
is not part of the Go transaction. Application Auto Scaling consumes the actual
metrics and changes native table/index capacity through its service-linked role.
Provisioned and configured on-demand admission share the native database data
gate with post-image accounting. Table/GSI read and write budgets use service
time and observed throughput;
an operation requires positive credit, then charges its actual completed cost.
A large admitted operation can overdraw the balance. There is no full-cost
five-minute ceiling: native fresh-table captures contradict that rule. All GSIs
participate in write backpressure, including unchanged projections. Known-cost
batch writes preview admission without changing real balances, validate the
original request before filtering, then execute only admitted members. Batch reads
keep one native call when credit covers the processed keys; under pressure, native
singleton batches preserve projections and charge each completed key. Unprocessed
keys retain their original read settings for retry. Transactions reject before
any member mutates. PartiQL keeps native statement errors rather than translating
a partial batch into a failed call.
No post-write quota rejection or compensating mutation is permitted.

The process-local admission model caps unused credit at five minutes of provisioned
capacity or an explicitly configured on-demand maximum and refills at that rate.
This is not AWS's private distributed/physical-partition allocator: sustained
native captures exceed that allowance, and exact throttle ordinals are not a
compatibility promise. Account-default on-demand and key-range admission remain
unimplemented. Go owns independent table/GSI maximum controls because the pinned
engine does not preserve their semantics. Cap-only updates commit synchronously;
native reconciliation preserves the Go-owned settings. Removing one limit clears
only its direction's budget; billing-mode transitions discard the old mode's limits.
Admission balances reset on service restart; pending consumption/throttle metric
distributions are retained. Throttled
request metrics retain the full operation identity, including PartiQL `Verb` and
`OperationType`, across memory/SQLite reopen and completed-minute publication.

Provisioned-throughput decrease quotas are retained control-plane state, not
those process-local data budgets. The last settled decrease timestamp dates the
UTC-day counter and hourly eligibility; table and GSI requests are validated
before staging any member of a combined update. A pending update retains its
acceptance time so provisional descriptions do not overwrite settled history.
Engine completion, not a timer, commits new capacities and history. Billing-mode
changes preserve table history; a GSI's reduction to zero on entering on-demand
mode is itself a recorded decrease. These differences survive SQLite reopen.
On-demand billing admission retains the last four entries per scoped table in
typed rows. Completed creation in on-demand mode consumes one entry at creation
time; later switches consume entries at observed completion. Requests that leave
the mode unchanged preserve history. The oldest retained entry determines the
rolling 24-hour deadline, independently of UTC midnight. History commits with the
completed table transition and is deleted with the table, not reconstructed from
the external engine. Pending descriptions expose target billing units while
admission continues using settled capacities until actual completion.

The local documentation checkout supplies expected service workflows and
cross-service scenarios. [Behavior references](behavior-references.md) records
its entry points, provenance and relationship to AWS models and live evidence.

## Shared service observations

[The event contract](event-journal.md) owns the common command-origin and journal
rules. Services supply typed facts inside their resource transactions. Shared
origin construction retains request identity, service principals, causal parents
and service time; generated API decoding remains the protocol authority.
CloudTrail reads native management projections and owns trail selection/delivery.
EventBridge owns matching and retained target work; Logs owns subscription
matching and retained gzip work. Workers invoke consumer-defined interfaces outside
transactions. `internal/integrations` adapts EventBridge to SQS/Lambda/ECS/Logs/SNS/Kinesis, its API destination HTTP owner and typed bus ingress,
CloudTrail to S3/Logs/SNS, SQS/S3 to KMS, DynamoDB destinations to Kinesis, Lambda pollers to SQS/DynamoDB Streams/Kinesis, actual Lambda/ECS output
to Logs, ECS task/service/deployment state to EventBridge, Logs subscriptions to Lambda/Kinesis, SNS notifications to SQS/Lambda/Firehose commands and actual HTTP/S consumers,
and Lambda outcomes to SQS/SNS/Lambda/EventBridge/S3. Lambda completion retains one result with independent
destination and legacy routes; its source role and payload outlive function deletion.
Targets enforce current policy/state. Shared service-role issuance joins actual
IAM trust evaluation, credentials and successful STS outcomes; role-based audit
origin does not replace the authenticated role with a service principal.
EventBridge retains selected target roles, but resolves current authority at
execution. Credential ownership follows the role account; trust source context
follows the source bus account, independently of the rule creator. Typed bus
forwarding preserves native wire identity separately from each local causal
admission and never fabricates a public `PutEvents` request.
Classic EventBridge rules retain source deadlines alongside rule state. Their
occurrences, matching target work and journal facts commit together before any
destination call. `internal/awsschedule` shares calendar selection with Organizations
Backup, Application Auto Scaling and Scheduler without merging their admission
dialects or time-zone rules.
[Scheduled-rule behavior](eventbridge.md#classic-scheduled-rules) owns timing,
bus-wide matching, recovery policy and native evidence.
Scheduler and Pipes have separate typed memory/SQLC SQLite owners and generated
service commands. Scheduler retains immutable target attempts independently of
schedule replacement or automatic deletion. Pipes retains accepted source batches,
checkpoints and generation-fenced completion; stopped pipes do not acquire records.
Their drivers join the same scheduler. IAM service sessions, KMS and concrete
target/source adapters own authority and effects outside source transactions.
Pipes API destination enrichment shares the EventBridge HTTPS/Connection owner,
with modeled HTTP parameters in schema 305 and bounded response processing before
target delivery. HTTP effects and current authority checks remain outside the
source transaction; source receipt completion follows actual downstream success.
Kinesis/DynamoDB adapters require their configured physical engines. Kafka uses a
Pipes-owned connector, actual native consumer-group assignments and generation-
fenced commits; failed target batches cannot advance native offsets. Retained
Kafka source/auth references and ordered bootstrap endpoints live in
`222_pipes_kafka.sql`, alongside the existing per-partition checkpoint/work state.
Default groups belong to the pipe incarnation; custom groups are borrowed and
never deleted. No second event bus or timer loop supplies synthetic records.
Native API projections and
CloudWatch samples remain service-owned; see [Scheduler](scheduler.md) and
[Pipes](pipes.md) for supported paths and explicit remaining bounds.
Archives use that same retained delivery path, with service-owned payloads and
ingestion-based expiration. Replay atomically advances its cursor with new bus
admissions and target intents. Customer-key preparation and data-key encryption
run through the KMS consumer adapter outside EventBridge transactions; archive
incarnations and configuration versions fence the subsequent commit.
CloudTrail preflight S3, SNS and Logs effects are independent of its own trail mutation,
matching native marker, validation-message and stream effects.
CloudTrail retains the canonical key from its real encrypted preflight write.
Pending S3 log attempts read the trail's current key, not an admission-time copy;
native recovery delivered an older failed-key event under a subsequently configured key.
Successful S3 delivery advances configured SNS notification work in the same
trail transaction. Publication runs outside it through ordinary SNS commands;
its status and failure completion do not undo S3 success or borrow S3 retries.
SNS owns subsequent subscriber delivery. [Notification evidence](cloudtrail.md#sns-log-file-notifications)
records the native recovery bounds and unresolved producer retry semantics.
S3 envelope encryption uses the same caller-preserving data-key adapter as SQS,
with service-specific KMS authorization. Bucket defaults retain literal identifiers;
object versions retain canonical key ARNs, wrapped keys and typed context rows.
KMS effects execute outside S3 transactions, preventing reversed lock ownership
and preserving failed-call observations. Object publication and success events
remain atomic; detached reads invoke KMS before producing plaintext. Firehose
calls ordinary S3 PutObject with independently retained primary/backup key choices,
not a second KMS authority. See [encrypted object behavior](cloudtrail.md#s3-envelope-encryption).
S3 notification configuration owns separate desired/applied snapshots and a retained
service-time adoption deadline. Object transitions commit immutable SNS/SQS/Lambda
work and trusted native EventBridge admission with the source API outcome.
Consumer adapters execute destination commands outside the source transaction;
accepted work does not disappear when a bucket or its configuration is removed.
Native object events and CloudTrail API projections remain distinct producers.
[Bucket notification behavior](cloudtrail.md#s3-bucket-notifications) records
authority, payload, propagation and producer-retry boundaries.
Object tags are separate version-owned state. Tag replacement/clear commits with
the source outcome and configured publications without rewriting object data,
metadata or version order. Reads resolve the selected version's tags and IAM
conditions in one repository snapshot; optional TagCount disclosure uses its
own tag-read authority. [Tagging behavior](cloudtrail.md#s3-object-tagging) records
the distinct ListBucket-controlled missing-object/marker disclosure boundary.
CopyObject detaches the selected source version, ciphertext, metadata and tags
before external KMS work. Destination authority, conditional publication,
copied state and object events share one final transaction. Native internal
source-read observations remain independent; success/error response encoding is
shared with HTTP output for actual audit byte counts, not regenerated estimates.
The same generated HTTP binding supports source-owned rejection observations
without dispatching invalid commands; S3 owns their resource scope and redaction.
[Object-copy behavior](cloudtrail.md#s3-object-copies) owns ordering and native bounds.
Multipart initiation freezes object metadata, tags, checksum negotiation and
encryption state in typed upload rows. Part replacement retains independent
ciphertext segments. Completion transfers selected segment/tag ownership to the
published version inside the source transaction rather than decrypting and
rewriting payloads. Initiation order and later mutation order remain distinct.
Ordinary reads, copies and copy parts consume that shared representation; exact
completion retry uses retained version/part metadata, not a receipt ledger.
Generated decoded requests borrow their bounded wire body for source-owned byte
and XML-attribute observations, without reserializing the DTO or copying payloads.
[Multipart behavior](cloudtrail.md#s3-multipart-uploads-and-attributes) owns the
native ordering, checksum, authorization and event boundaries.
Original bucket/object ownership and ACL grants live in typed records and ordered
SQL rows, including pending uploads. Enforced ownership and ignored public grants
are effective views, not destructive rewrites. Object authorization distinguishes
the bucket's resource account from the selected version's owner; S3 supplies ACL
grant facts to the shared IAM evaluator rather than implementing another policy
engine. Anonymous S3 follows that same authority path. The generated XML decoder
owns document grammar and S3 owns semantic errors/audit projections.
[Access-control behavior](cloudtrail.md#s3-ownership-acls-and-public-access) records
the measured authority distinctions and incomplete inheritance/classification.
Object Lock is typed bucket/version/upload state, not a separate payload store.
Creation applies effective defaults before IAM evaluation; multipart initiation
freezes the same metadata. Retention and legal-hold replacement preserve payload,
version identity and ordering while committing notification snapshots with state.
Independent metadata timestamps own CloudTrail observations; optional read-header
permissions cannot erase audit facts. Variable retention is an effective view of
the stored deadline floor, duration and service clock, not periodic row rewrites.
Deletion owns the shared version-protection guard, including per-member batch
outcomes. [Object Lock behavior](cloudtrail.md#s3-object-lock) records native
authority, delivery and remaining integration boundaries.
Storage class belongs to each version and multipart initiation. Archive restore
state is a separate typed version-owned row: copying bytes cannot copy a warm
cache, and deleting/replacing a version removes its restoration atomically.
The existing payload representation remains authoritative; reads and copy sources
apply conditions/ranges before checking archive availability. Restore commands
commit state, audit outcomes and notification snapshots together. Shared scheduler
jobs use their persisted completion/expiry deadlines, not an advanced drain
horizon, so crossing midnight in one clock step cannot extend a restored copy.
Expiry also gates reads before a worker drains. The ordinary notification publisher
owns classic and direct EventBridge envelopes and retained parent causality.
[Archive behavior](cloudtrail.md#s3-storage-classes-and-archive-restoration) separates
native observations, local scheduling choices and remaining archive-tier boundaries.
Live S3 replication retains admitted rule/role/destination snapshots beside
version-owned jobs and per-component outcomes. Configuration replacement cannot
silently rewrite accepted work. Shared IAM evaluates the actual S3 execution role;
KMS unwrap/rewrap runs outside the S3 transaction. Destination version metadata,
the existing ciphertext/part representation, source outcome, notifications and
metric counters commit together. Replicas preserve source version identity and
ordering, so sequence uniqueness belongs to admission, not to every stored copy.
Explicit source-version deletion removes its work in the same transaction.
Metadata replication uses those existing version records rather than a parallel
object store. Retries, RTC deadlines and metric publication use the shared
service-time scheduler; CloudWatch consumes typed statistics through its ordinary
service interface. [Replication behavior](cloudtrail.md#s3-live-replication) owns
the native evidence and remaining boundaries.
S3 Lifecycle owns ordered typed rules and one persisted daily scan deadline per
enabled bucket. It evaluates current tags, version history, protection and
replication status inside the same transaction as mutations, notification/log
intents and deadline advancement. Immutable creation-order cursors survive deletion;
the replaceable null slot is reselected before a stale noncurrent page entry can
act on it. Transitions update metadata without copying ciphertext or completed
parts. Restore and replication sources precede Lifecycle for equal local deadlines.
Shared calendar arithmetic owns both restore and Lifecycle day rounding; explicit
version reads never inherit the current-object expiration header.
[Lifecycle evidence](cloudtrail.md#s3-lifecycle) separates captured API behavior
from document-derived execution and local scheduling choices.
Intelligent-Tiering reuses these version records, object filters and bucket-scan
cursors. Only eligible versions retain an access instant and optional archive
tier; billing-only subtiers do not need another state machine. Successful data
reads update access without changing modification time or copying payloads.
Detached updates are fenced by version creation order and current storage class.
One typed configuration collection and daily deadline per bucket govern forward
archive transitions using current tags. Tier changes and classic/direct event
intent commit together; Lifecycle runs first at equal deadlines. Restore completion
returns an Intelligent-Tiering version permanently to active access and removes
its pending restore row, rather than creating a temporary-cache expiry.
[Intelligent-Tiering evidence](cloudtrail.md#s3-intelligent-tiering) distinguishes
native admission/authority captures from document-derived physical transitions.
Request-metric configurations reuse typed object predicates and stable configuration
cursors. The shared HTTP accounting observer owns actual transfer bytes, status and
latency; internal copy/replication reads contribute source counters without invented
network traffic. Successful tag mutations replace only the observation's candidate
tags; failed commands select against the prior object. Publication uses bucket-owner
scope and the existing CloudWatch interface, not customer `PutMetricData` authority.
CloudWatch owns individual samples, statistics, percentiles and alarms. S3 retains
no second metric ledger, activation timer or aggregation scheduler. See
[request metric behavior](cloudtrail.md#s3-request-metrics) for native populations
and explicit best-effort timing boundaries.
Inventory configurations retain their next occurrence and originating API event.
The scheduler reads a metadata snapshot, then encodes and publishes outside the
transaction through ordinary S3 `PutObject`; destination policy, ownership, KMS,
notifications, audit and metrics stay with their existing owners. Completion
compares the configuration's event identity and deadline, so replacement or
deletion cannot resurrect old work. There is no report receipt ledger. CSV/GZIP
and Parquet/Snappy use Go writers; the consumer-owned `InventoryORCEncoder`
interface imports Apache ORC in an explicit pinned container rather than a
partial Go format implementation. [Inventory behavior](cloudtrail.md#s3-inventory)
owns scheduling choices, native controls and physical-report evidence boundaries.
Bucket ABAC is one retained flag over the existing typed bucket-tag repository.
S3 Control and legacy tag APIs share those rows; creation writes tags with the
bucket. The shared IAM evaluator receives current bucket tags only when enabled.
Access-point authorization substitutes its own `aws:ResourceTag` set while
retaining separate bucket/access-point condition namespaces. Copy and multipart
paths reuse that authority boundary rather than retaining authorization snapshots.
Named STS session policy principals are validated through IAM's existing session
resolver, but remain ARN references; native role recreation preserves those grants.
Transfer acceleration is a typed bucket setting, not a second object store or
transport implementation. Regional endpoint and signing-scope admission are shared
with access points; accelerated requests enter the existing object, copy and IAM
commands. Never-configured and suspended buckets reject accelerated data requests
without disabling ordinary endpoints. Native management-event aliases and body
admission use the same audit transaction as other bucket controls.
The shared KMS adapter distinguishes a service's own call from forwarding another
principal. S3-owned Inventory calls lack `kms:ViaService`; S3 forwarding CloudTrail
retains it, as required by the captured native CloudTrail key-policy fixture.
SSE-C uses the existing encrypted payload and multipart representation. Only a
randomly salted HMAC verifier and response MD5 accompany a version/upload; the
customer key remains request-owned. Metadata listings omit private verification
material, and HEAD verifies possession without loading ciphertext. Independent
copy-source and destination keys decrypt/re-encrypt at the existing boundary.
Replication adopts ciphertext plus its verifier without recovering a customer
key. Current bucket blocking governs new publication/parts, not reads or
completion of admitted uploads. Completed versions retain explicit checksum
provenance because native retry admission differs even when the effective
algorithm/type are identical; there is no new completion ledger.
The public HTTP boundary owns actual TLS admission. Generated headers and
service-owned syntax/key checks preserve native conditional, partial and archive
read ordering. [Customer-key evidence](cloudtrail.md#s3-customer-key-encryption)
owns those distinctions and the audit projection that excludes key/key-MD5.

Bucket CORS and website configurations have typed repositories and normalized
SQL rows. Replacement and source management events commit together. The gateway
owns request identity; CORS observes bucket rules before authentication, decorates
actual responses and terminates preflight without granting resource access.
Website routing is a separate anonymous surface even when a caller supplies a
valid signature. It reuses S3's object selection, authorization and encryption
without inventing internal REST calls. Metadata and ciphertext are selected in
one repository snapshot. [Browser behavior](cloudtrail.md#s3-cors-and-static-websites)
owns the native configuration, serving and audit boundaries.
Requester payment is bucket admission state, separate from IAM authority. The
gateway preserves signed payer bindings; S3 owns account exemptions and charged
responses. Cross-account outcomes append distinct caller/owner projections in
the same source transaction, retaining shared correlation without disclosing
owner resource accounts in the caller projection.
Server access logging separates configuration from retained delivery snapshots.
The HTTP completion observer measures real response bytes and timing; internal
S3 commands reuse the formatter and queue without inventing network activity.
The shared scheduler publishes through S3's ordinary encrypted PutObject outside
the queue transaction, rechecking destination authority. Configuration changes
do not retarget accepted work. [S3 accounting](cloudtrail.md#s3-requester-payment-and-server-access-logging)
owns field semantics, native evidence and local delivery/retention bounds.
The shared generated encoder also supports source-owned public audit projections;
classification, response presence and native resource identity stay with each
service. [CloudTrail](cloudtrail.md#history-and-api-producers) owns the current
producer inventory, native evidence and remaining observation gaps.

CloudWatch Logs owns typed groups, streams, ingestion, resource policies,
retention policies, paginated/filter reads, metric filters and Lambda/Kinesis/direct Firehose subscriptions.
Applicable resource-policy documents compose in one IAM evaluation with explicit-deny
precedence. Lambda, ECS, EventBridge and CloudTrail enter the same authorized commands
as SDK ingestion under their respective native identities. Source log rows,
accepted-batch journal facts, selected subscription work and configured metric
samples share one transaction. Logs consumes CloudWatch's typed publication
interface; the application needs Logs ingestion permission, not an additional
`cloudwatch:PutMetricData` grant. CloudWatch owns metric identity, sample admission,
aggregation and query behavior. This path does not synthesize a CloudWatch API call.
EventBridge likewise owns request/delivery observations and pending minute
samples; publishing a completed group and removing its pending work share the
source transaction. Source deletion cannot erase accepted observations.
ECS uses this same publication boundary for retained per-task utilization
windows. Its runtime interface supplies actual counters outside transactions;
ECS owns task allocation, deployment-specific resolution and service-time
acceptance. Native counter baselines are process-local, not replayed CPU work.
See [ECS metric ownership](ecs.md#service-metrics).
ALB owns typed minute request/response samples and live-node health observations.
Target admission retains request counts before forwarding; target sockets and
response reads remain outside transactions. Completed windows publish through
CloudWatch's same source interface and disappear in that transaction, including
after restart or source deletion. Target-zone dimensions come from current EC2
target identity, not whichever relay accepted the connection. Application Auto
Scaling validates an ALB metric label against the current ECS service binding;
the source does not bypass the normal alarm and capacity-command owners.
Application Auto Scaling owns scoped target bounds, scheduled actions and policy
decisions. Consumer-defined resource and alarm interfaces enter real ECS and
CloudWatch commands under current caller or service-linked-role authority.
Accepted capacity intent is a retained `Pending` activity. The subsequent ECS
command and `InProgress` transition commit together; only ECS reconciles actual
containers. Completion observations, rather than API acceptance, start cooldowns.
Activity history outlives target/policy deletion and owns the public six-week
query window, instead of copying pending capacity state into each policy.
See [ECS scaling behavior](ecs.md#application-auto-scaling).
EC2 Auto Scaling owns groups, memberships, activities and lifecycle actions over
the same transaction domain, with consumer-defined EC2, ALB, role, event and
metric interfaces. Original-caller dry-run admission is separate from fresh
service-linked-role execution. Frozen launch activities use EC2 client tokens;
actual guest effects stay outside transactions and the shared scheduler gate.
Policy/schedule/hook decisions retain service-time deadlines; CloudWatch owns
alarms and samples, while ELB owns target health and draining. The
[EC2 Auto Scaling contract](ec2.md#ec2-auto-scaling) records native differences
and remaining producer/service gaps.

Public timestamp-age admission remains a CloudWatch API boundary, not a second
expiry check when already-accepted service samples publish after a clock advance.
Subscription preflight and delivery use trusted global/current-regional Logs
principal aliases together in one IAM decision, not separate fallback grants.
CloudWatch publication, statistics/math, SEARCH and Metrics Insights queries share
typed metric discovery and retained bucket ownership. Direct and SEARCH reads
allocate source time windows before expression evaluation; continuation carries
scoped source offsets, not another durable ledger. SQL aggregation merges the
same retained weighted summaries rather than introducing a parallel metric store.
Metric/composite alarms share that query engine and service clock; state changes,
native EventBridge events and ready Lambda/SNS action intents commit together.
Grouped Insights retains active contributors separately from parent alarm state,
using the same sample evaluator and metric repositories. History/action snapshots
outlive active rows and alarm deletion. Contributor events and ready SNS/Lambda
actions commit with contributor transitions; a parent reason-only update writes
history without manufacturing another state event or action.
Suppression and action retries retain deadlines; external acceptance runs outside
storage. Other AWS service-owned metrics, remaining alarm engines/actions,
logical Firehose destinations, organization sender-role subscriptions and transformers remain open.
See [CloudWatch ownership and evidence](cloudwatch.md).
Account-global dashboards use the same CloudWatch repository and API-event
transaction, with typed body/tag/metadata ownership rather than a separate CRUD
engine. Alarm and dashboard tagging share authority and mutation dispatch;
resource owners retain their different metadata semantics. Dashboard definitions
reference existing query/data-plane owners without executing them during storage.
API completion, event delivery, metrics and runtime log bytes have different AWS
contracts; a generic request logger cannot own all four. See [Logs](logs.md).
Add each producer at the existing command/lifecycle boundary with native fixtures,
then share its metadata and transaction plumbing through these same interfaces.

Firehose owns typed stream incarnations, versions, admitted records, processing
claims, independent primary/error/raw-backup buffers, source checkpoints and
pending samples. Its repository joins the shared memory transaction domain or
service-owned SQLC SQLite tables. Kinesis reads, real Lambda execution and S3
writes occur outside Firehose transactions and customer code does not hold the
joined scheduler drain. Checkpoints commit with admitted rows; processing
completion atomically replaces input work with destination obligations.
Prepared object identity/configuration survives retry and restart without
rerunning completed customer code. Consumer-owned interfaces call ordinary
authorized Kinesis, Lambda, S3 and Logs commands; EventBridge and Logs share the
ordinary Firehose PutRecord seam. Weighted CloudWatch publication joins the
source transaction. Shared role assumptions supply the native Firehose external
ID rather than weakening IAM trust. See [Firehose ownership and evidence](firehose.md).
Source decompression/extraction derives attempt-local bytes from retained originals;
only completed output obligations persist transformed bytes. Failed stages select
their own error prefix without replacing raw backup or failure data. Trusted Logs
origin comes from the existing internal role-request context, not a new header or
credential workflow. Firehose and Lambda share KPL binary decoding while retaining
their own deaggregation/filtering policy; source subsequences commit alongside
the outer Kinesis checkpoint.

SNS owns topic incarnations, subscription filtering, signed protocol variants and
retained delivery outcomes. Its weighted service metric samples join publication
or terminal-delivery transactions; the completed-minute job publishes through the
same internal CloudWatch interface and consumes its pending samples atomically.
This preserves percentiles without a lossy statistic-set cache or idle-zero
ledger. SNS does not borrow customer metric permissions or bypass destination
authorization. [SNS](sns.md) owns native evidence, source-specific projections
and remaining protocol/lifecycle boundaries.
HTTP/S confirmation uses service-owned retained tokens and the existing generated
Query decoder, not a second public API implementation. Partial signing material
never falls back to anonymous access; token possession does not become a
topic-owner identity. HTTP effects run outside transactions, while confirmation
state, throttling and retry deadlines use the same repository and service clock.
SNS Firehose delivery uses the subscription role through shared IAM/STS authority
and Firehose's ordinary `PutRecordBatch` command. Destination authorization,
buffering and final S3 delivery remain Firehose-owned.

X-Ray owns typed regional segments, trace revisions, groups, sampling state and
revisioned resource policies in the same transaction domain. Inline and
independent subsegments use one first-completion transition. Ingestion assigns
one trace revision per changed command; segment admission/completion ordinals
preserve graph history even when service time does not advance. Group membership
retains the first matching filter version, revision and admission instant.
The existing scheduler owns receipt-time retention, sampling expiry and pending
group-count publication. Earned metric counts survive group deletion and publish
through CloudWatch's internal transaction interface, not customer `PutMetricData`
permissions. Shared decoded trace topology serves selectors, causes and graphs;
wire encoders remain generated.

Accepted X-Ray API outcomes feed ordinary CloudTrail selection and EventBridge
routing. Daemon telemetry uses that same admission and journal boundary, not a
second health-counter repository or invented customer metrics. SNS reuses
retained publisher metadata for PassThrough context rather
than introducing a second trace envelope or queue. These AWS trace identifiers
do not replace journal causal identities or grant authority. [X-Ray storage and
audit](verification-kernel.md#x-ray-storage-and-audit) and [SNS propagation](sns.md#x-ray-propagation)
own native evidence and the sampled-service-span blocker.

Lambda uses the same CloudWatch publication boundary for actual invocation,
asynchronous acceptance/completion and destination-failure samples. Its service
owns native zero-sample and minute-aggregation distinctions, not the generic
publisher. Runtime metrics retain the execution-start instant across completion
and manual clock advances. [Lambda](lambda.md#asynchronous-outcomes-and-metrics)
owns the native record, role context, retry and metric contracts.

Lambda owns one process-local concurrency admission boundary and a pool of leased
real environments per function. Typed repositories retain scoped reservations and
separate code identity from public metadata revisions. Reservation changes cannot
reset warm state; deployment promotion retires old code without holding service or
storage locks across customer execution. Permits are released by their running
call, not persisted as a second recovery protocol. [Lambda concurrency](lambda.md#concurrency-and-runtime-ownership)
owns quota, zero-reservation, throttling and restart semantics.

Canonical schemas265–275 extend Lambda with self-managed Kafka, MQ and DocumentDB
source configuration, runtime controls, code-signing admission, durable execution,
managed-capacity intent and source identity. Existing DocumentDB schema245 remains
authoritative. Kafka offsets and MQ acknowledgements remain broker-owned;
DocumentDB resume tokens join source-incarnation checks in Lambda's typed store.
Native reads and runtime execution stay outside resource transactions.
CloudFormation MQ mappings use these same owners rather than creating queues.
Admission checks current broker identity, role, network permissions and secrets;
only polling opens a native consumer. Configuration updates retain queue identity
and do not acknowledge pending messages. [MQ deployment evidence](lambda.md#cloudformation-amazon-mq-mappings)
separates disabled AWS control captures from local AMQP/JMS and Runtime API effects.

MQ is an independent service, not a Lambda-owned broker mock. Schema 283 adds
typed configuration/revision, user/group and current/pending association state.
Schema 284 retains maintenance-window adjustment budgets; only successful
scheduled maintenance resets them, not restart or manual reboot.
Schema 295 separates ActiveMQ's public `5.18` label from the pinned native `5.18.7`
runtime, migrating only the former patch-qualified broker/configuration values.
It preserves native identity, journal ownership and pending reconciliation state.
The shared scheduler claims reboot/maintenance intent before applying native
configuration and credentials outside transactions, then fences result promotion
against the retained broker version. Actual RabbitMQ/ActiveMQ journals own
messages; Lambda remains an ordinary consumer of the broker owner's connection
contract. [MQ boundaries](mq.md) distinguish verified single-instance effects from
unimplemented replicated, private-network, storage and telemetry integrations.
ActiveMQ's optional persistent JMS scheduler also belongs to the real engine and
its journal volume. It uses engine time, not Go timers or deterministic
control-plane maintenance time; `schedulerSupport` and `maxSchedulerRepeatAllowed`
apply on broker reboot. The native scheduler rejects excessive repeat counts
through JMS rather than a control-plane proxy or emulated delivery path.
Schema 285 also retains effective/pending log flags and native source cursors.
ActiveMQ general/audit and RabbitMQ general files are read outside transactions;
Logs events and source positions commit together after broker-version fencing.
ActiveMQ delivery uses current MQ resource-policy grants. RabbitMQ instead assumes
the current protected service-linked role in the broker's scope, including from
callerless scheduler jobs, and can recreate its missing destination group.
RabbitMQ's retained reconciliation schedule also samples complete native queue
inventories outside transactions. Classic queue processes and live quorum Ra
FIFO state supply counters; absent management statistics never imply zero.
Pinned single-node Mnesia exchange keys include all vhosts/default exchanges;
AMQP process registries supply connection/channel counts without including the
collector's Erlang distribution connection. A lazy-absent registry requires real
listener/direct-channel supervision to prove an empty broker, not an assumed zero.
Readiness commits independently of sampling failures. Broker-version, native-ID
and observation-deadline checks fence batched publication into the CloudWatch
transaction owner. Standard-resolution metrics and history survive SQLite restart;
no second message ledger, synthetic catch-up or managed-capacity values exist.
ActiveMQ uses a separate typed snapshot from actual broker/destination JMX.
A bounded local HotSpot attach request reads the existing local connector inside
the owned container; no remote management connector is started. Broker identity,
complete destination inventories and required counters are checked before
publication. Queue/topic identity stays distinct even for equal physical names.
Both engines share observation fencing and the CloudWatch transaction owner.

Provisioned pools become ready only after actual Runtime API initialization.
Managed capacity delegates instance/volume/network lifecycle to EC2 and bootstraps
an authenticated guest agent through official SSM; it retains provider/function
intent, not a second EC2 resource store. Current operator and execution roles
govern effects, and service-linked-role usage retains the shared writable
transaction context. Signer owns local signing roots, profile/job identity and
revocation; Lambda consumes that authority for cryptographic ZIP admission.
Durable checkpoint/history/callback state uses the shared clock, scheduler and KMS
owner. [Lambda evidence](lambda.md) bounds these contracts and unsupported
combinations; no AWS-hosted fleet or cross-service exactly-once claim follows.

IAM condition presence is represented only by the context map: absent/nil values
are missing and nonnil empty slices are present empty sets. Only Lambda function
resource-policy binding opts into opaque federated literals; other resource
owners, including SES, keep strict defaults, and role trust retains strict
provider grammar and current provider validation.

Lambda shares mapping controls, role-session issuance, invocation admission,
source causal facts and metric publication across SQS and DynamoDB Streams.
`SQSSource`/`SQSConsumer` leave queue state, current authorization, visibility and
redrive with SQS. `DynamoDBSource`/`DynamoDBConsumer` leave stream generations,
records, retention and current read authorization with DynamoDB. Lambda owns
its consumed-sequence checkpoints, per-item lanes, queued records, retry batches,
window state and accepted failure documents in typed memory/SQLC repositories.
Captured records and their checkpoint commit together; completed batches retain
state, enabled counters and destination work together. Source reads, real customer
execution and destination commands occur outside those transactions.
Polls never block scheduler draining. Native Invoke and typed source-record facts
commit before customer code; metrics use the existing CloudWatch outbox.
`DynamoDBStreamTargets` reuses destination-owned commands and current role
authorization. No second queue, receipt ledger or cross-service exactly-once
protocol is added. A crash between an external effect and its completion can
repeat that effect; checkpoints must not skip retained work.

Lambda code retrieval separates immutable scoped ZIP archives from mutable
deployment metadata. Ordinary function reads do not copy ZIPs. Public downloads
reuse the gateway's SigV4 verifier and AWS SDK presigner with service-owned
signing material; IAM callers and execution roles do not own those capabilities.
Archive retention, deployment snapshots, layer catalog entries and retained
attachments preserve issued URLs and deployed bytes across replacement, deletion
and SQLite reopen without one ledger row per download. The shared scheduler
collects only expired, unreferenced archives. [Lambda retrieval](lambda.md#function-retrieval-and-deployment-downloads)
owns native evidence, URL lifetime and public-origin requirements.

Lambda Function URLs retain scoped configuration, stable route identity and
pending effective-setting deadlines separately from deployment/alias policies.
The PublicEndpoint HTTP route authenticates the original target before removing
its private prefix, then uses the shared invocation admission and real runtime
ownership boundary. Delivery cancellation does not cancel accepted execution.
[Function URLs](lambda.md#function-urls) owns the one-minute local transition,
HTTP mapping, native authorization/observability evidence and remaining limits.

Lambda owns the consumer-defined `CodeSource` interface and `S3ObjectReference`;
`internal/integrations/lambda_s3.go` implements it as `LambdaS3Code` over
`LambdaS3Commands`. It invokes the same S3 service's authorized `GetObject` and
`HeadObject` commands, which own version selection, encrypted bytes, bucket
region, current policies and API outcomes. COPY uses deploying-caller authority;
REFERENCE resolves an exact non-null version and separately reads with Lambda
service authority and the resource ARN as `aws:SourceArn`, not the execution
role. External source reads run outside Lambda transactions. Final deployment
admission rechecks current Lambda state and layer catalog eligibility; retained
archives cannot make a deleted catalog version newly attachable.

Layer catalog ownership is separate from immutable ordered deployment
attachments. Catalog/source deletion cannot erase bytes already attached to a
published snapshot. Own-code REFERENCE deployments also retain source-check
deadlines: `CodeSourceReader`/`CodeSourceWriter` recover checks through the shared
scheduler, call S3 outside storage, and recheck deployment identity and deadline
before changing operational state. One hour is a deterministic local interval,
not measured AWS reoptimization timing. These typed service repositories are not
a generic blob kernel or a cross-service snapshot/fork implementation.

Gateway control planes own retained regional account roles and typed stage,
method and route settings. Schemas 184–185 migrate existing metric overrides
without parallel metrics/logging maps. Resolvers supply immutable effective
settings to actual HTTP/WebSocket executions; deployment snapshots do not freeze
live stage logging configuration. Consumer-owned `LoggingConfiguration` and
`LogPublisher` interfaces connect to the existing IAM/STS and Logs owners.
HTTP admission joins caller-authorized vended delivery setup; publication uses
the destination's resource policy. REST/WebSocket use the current regional account
role. Runtime publication is best effort, outside configuration transactions,
without borrowing the API caller's authority or creating a second delivery ledger.
Ingress IDs/time are shared by payloads and log observations; Lambda returns its
actual invocation ID. REST/WebSocket share execution-record redaction and the
documented byte limit. [Gateway evidence](behavior-references.md#service-metrics-and-logging-prerequisites)
owns the captured protocol differences and remaining conformance boundaries.

`apievents.Reserve` assigns a fresh API outcome identity before independent child
calls; inherited reservations never make child outcomes reuse a parent's ID.
Lambda attributes SDK calls only while its runtime is actively invoking: the
gateway consults the public access-key mapping after signature verification and
adds a parent without changing caller authority. Synchronous invocation uses its
reserved outcome, asynchronous invocation its accepted invocation ID. Deferred
cleanup and a separate origin lock prevent stale warm-runtime attribution and
SDK/execution-lock deadlock. This is not a response-header protocol, SDK patch,
initialization/idle attribution or OpenTelemetry/native X-Ray implementation.

## Current boundaries

`cmd/stackd` owns flags, listening, logging and shutdown. `stackd.New` assembles an
isolated instance that can also run inside an application's Go tests.

`internal/gateway` owns the provider registry, protocol routing, request limits,
SigV4 authentication, request IDs and local account selection. `internal/identity`
resolves bootstrap root identities, IAM access keys and expiring STS sessions;
it records verified key use without exposing secrets. Providers declare
their implemented operations. The health response reports that declaration;
it does not claim complete service semantics.

Authentication reads the bounded network body before credential resolution can
wait on the shared store. Signature verification and protocol decoding reuse
those bytes, so a storage wait cannot cause a late read of an already-received
body. Request limits and signature rejection remain enforced.

**Behavioral breadth, not dispatch counts.** The selected-service operation target
is an API inventory. Generated decoding followed by `NotImplementedException` contributes
no implemented resource behavior. A registered handler is not evidence of complete
semantics either; actual workflows, negative cases and cross-service effects
remain the compatibility gate.

Keep AWS control-plane behavior in Go and real compute/database engines behind
explicit data-plane interfaces. Verify semantics against primary AWS contracts
and retained native evidence, not another implementation.

Do not introduce a generic resource framework merely to increase coverage counts.
We already share the memory transaction domain, service-owned SQLC repositories,
IAM evaluator, journal and deterministic scheduler. Extract another shared
mechanism only when concrete production consumers demonstrate the same behavior.
Generate repetitive typed records, queries and validation where authoritative
models supply sufficient facts; Smithy wire shapes do not supply CRUD semantics,
authorization, lifecycle or effects. No generated successful no-ops.

Keep the existing provider boundary and versioned extensions, with one resource
owner shared by public APIs, internal commands, event consumers and data-plane
endpoints. Never combine independent state stores through per-operation fallback.
`stackd.New` directly injects native services into consumers; replacing only an
HTTP handler would split ownership. This is a constraint on future changes, not
a commitment to build a new provider-selection framework.

Keep registration inventory separate from workflow/fixture evidence in current
service documents. No fidelity or provenance labels on AWS responses.

`cmd/awsgen` reads the local SDK's Smithy models and emits `internal/awscatalog`
and `internal/awsapi/<service>`: routing contracts, operations, typed request and
response models, input decoding/validation, and typed Query/JSON/REST output
bindings. REST JSON and REST XML share modeled HTTP labels, queries, headers and
payload routing. Lambda and S3 consume actual bytes rather than JSON/base64
round-trips. S3 XML supports modeled namespaces, attributes and flattened lists;
buffered payload support does not imply streaming backpressure or every protocol trait.
Descriptor tables compile separately in `internal/awscatalog/models/<service>`.
The shared catalog retains operation constants, immutable accessors and routing
indexes. This avoids combining every service's race-instrumented metadata into
one Go compiler object; descriptors remain generated Go values, not runtime JSON
parsing or a second model representation.

S3 checksum input views and output setters are generated from its checksum enum
and typed shape members for actual consumers. They preserve absent versus empty
fields without reflection or per-operation field lists. S3 owns selection,
syntax and multipart negotiation; `internal/awschecksum` owns digest computation.
Lambda REST JSON streaming outputs use generated typed event channels and the
AWS SDK event-stream encoder. Transport cancellation stops channel consumption
and socket writes; Lambda owns whether accepted execution continues independently.
Generated source carries exact revision/checksum provenance and can be checked for drift without writes.
Evidence-backed model corrections record their own manifest hash, preserve the
upstream checksum as provenance and fail regeneration when the target trait changes.
Native Lambda decimal truncation/saturation is an annotation on the observed
integer shape, not a handwritten service decoder or a global JSON coercion rule.
Generated error member names also bind REST JSON Message/Reason/Type fields.
The gateway invokes these generated bindings before provider dispatch and preserves
the typed input in request context. Account, Organizations, STS, KMS, SQS,
CloudTrail, EventBridge, Lambda and S3 consume generated inputs and output bindings.
Every implemented IAM operation now uses
generated output types and one generated response encoder. IAM's policy/version,
attachment and boundary handlers no longer marshal domain state as XML; their
projections preserve operation-specific field presence. Standalone IAM and the
gateway validate through the same generated request decoder before authorization
or state changes. User/group/membership, role, access-key, resource-tag,
managed-policy/version, inline-policy, attachment and boundary handlers consume
typed inputs. Shared identity/policy
lookups take names and ARNs; family handlers select their owner from the generated
input type and reuse the same domain mutations. Tag mutations share their merge,
quota and removal logic, preserving each resource's case and empty-input rules.
Providers can map generated validation failures to their native wire errors;
IAM owns that mapping for both standalone and gateway requests. Modeled bounds
remain authoritative, and their errors identify the failed constraint without
requiring a second bounds check. Query primitive parsing follows captured AWS
integer/boolean syntax and shares error classification across standalone IAM/STS
and the gateway; see [Query behavior and evidence](aws-query.md). IAM credential
conditions, all-user credential authorization, federation resources/discovery,
service-linked-role protection and instance-profile PassRole checks now consume
generated inputs. IAM pagination uses generated accessors over modeled
Marker/MaxItems members, including report APIs without SDK paginator traits.
Its shared paginator consumes typed controls and selections; domain callers own
effective filter defaults. Password preparation also reads generated inputs.
IAM request-tag, tag-key, policy-ARN, permissions-boundary and Organizations
policy-ID conditions use generated accessors on modeled input members. The shared
condition evaluator no longer reparses tags; generated validation owns structural
constraints and resource handlers own tag rules after authorization. Query lists
preserve positions and merge equivalent numeric index spellings. Native tag and
collection evidence is recorded in [Query behavior](aws-query.md).
IAM resource selection also consumes generated name/ARN accessors and typed
creation inputs. Current records own paths, tags, boundaries and credential
ownership. AWS-owned policies and commercial role templates resolve their numeric
service account for conditions in both ordinary and dependent permission checks. IAM handlers no longer receive Query maps, and gateway-bound requests
are not parsed a second time. Standalone IAM supplies the same generated input
boundary. Organizations also consumes generated inputs, authorization selectors,
request tags and pagination controls for every implemented operation. Its sole
response encoder runs before state publication; domain records carry no wire tags.
The service owns native validation reasons and operation-specific projections,
including hierarchy paths shared with IAM. See [Organizations API evidence](organizations-api.md).
Organizations resource-policy delegation uses the shared IAM evaluator, with explicit
management ownership for global member calls and dependent tag/target permissions.
Typed policy state and tags commit with the organization; revision conflicts
reauthorize prepared commands. Membership and trusted-service read grants are
account permissions in the shared evaluator; they remain subject to explicit
resource-policy denials. Global organization reads, delegation deletion and AWS
policy aliases resolve the current management account for IAM conditions. See
[delegation and native evidence](organizations-delegation.md).
The generator builds without
pre-existing generated files; its schema definitions are separate from the runtime
catalog. The shared AWS JSON error writer also uses these generated members:
Organizations' `Message` and `Reason` and KMS's `message` retain their modeled
wire names, so SDK callers receive service diagnostics.

`cmd/iamgen` generates `internal/iam/catalog` from the pinned AWS service
reference. It supplies action/resource types, all ARN forms, scalar/list context
types, applicable condition keys and action-last-access support. IAM resolves actual resource paths and
identities from its transaction before enforcing permissions. Policy reports
consider ARN forms as alternatives; they do not form a single comma-joined ARN
or a product of unrelated resource languages. See [catalog ownership and
refresh](../internal/iam/catalog/README.md).

`cmd/iamgen` also generates action-last-access tracking flags from AWS's public
service-reference metadata and all 455 report display names and default regions
from one owned AWS Organizations capture. The gateway records authenticated attempts, including denials, in the
same IAM transaction as credential-use bookkeeping. Trusted nested service calls
use that recorder without reauthenticating accepted work. Report permission
discovery shares current source traversal with simulation and context-key APIs;
its selectors remain separate from actual authorization. Organizations owns
management-account eligibility, resource-scoped read dependencies and detached
SCP/account selection. IAM intersects those SCP levels at the same resource and
aggregates account activity in its own transaction. Both report families share
typed job storage and the service-time scheduler. IAM's transaction context keeps
Organizations reads in the same transaction domain as the report snapshot. See
[last-access reporting](iam-last-access.md).

`cmd/simgen` generates IAM simulator action recognition and resource display
metadata from the checked-in AWS capture. These observations are separate from
the authorization reference: AWS simulation recognizes some action spellings
differently and returns its own aggregate ARN templates. The shared policy
matcher continues to own actual permission decisions. See
[simulation behavior](iam-simulation.md) for the observed contracts.

`cmd/awspolicies` captures authoritative AWS-managed policy documents and history.
The embedded snapshot is immutable; local attachment and boundary counters are
derived from account-owned identities. AWS-owned policy API authorization uses
the observed service-owned resource account for conditions while evaluating the
caller's identity, boundary, session and Organizations controls.

`internal/iam/roletemplates` embeds AWS's role-template definitions separately
from Smithy contracts. Acquisition renders typed role inputs and shares IAM's
ordinary role, policy and tag invariants. The source association stores version
and replacement parameters; reuse compares current configuration with that
immutable template. Underlying permission checks, roles, policy attachments and
the association share one IAM transaction. See [role templates](iam-role-templates.md).

IAM account properties use the same typed account settings and transaction.
Enabling Role Manager evaluates the account-property and service-linked-role
permissions before publishing its setting and role together. Existing owned roles
retain identity. Its usage adapter joins IAM's transaction, keeping the account
feature stable through modeled role deletion. AWS deletion conformance and the
new-account/Access Analyzer transition remain open; see
[account properties](iam-account-properties.md).

`internal/awswire` owns Query/XML, JSON 1.0/1.1 and REST JSON envelopes. SDK client output structs
are not blindly JSON marshaled: client model and wire representations differ.

`internal/awsctx` carries immutable request metadata. Global services scope state
by account and ignore region. Regional services must explicitly scope by account
and region. Global identity and Organizations state are isolated by partition; regional providers
include the region in their state scope. Issued credentials retain their partition.

Outbound identity federation stores account issuer configuration and signing
keys in IAM's typed settings. STS authorizes and signs under the existing IAM
session transaction; its Organizations snapshot pins membership alongside SCPs.
IAM commits ordered propagation changes with those settings; STS derives the
visible state at the transaction's service time, using a 10-second modeled delay.
No background delivery is needed for this visibility calculation.
The same typed boolean propagation model serves IAM's global STS token preference.
STS reads the credential owner's setting within its issuance transaction and
persists the resulting compatibility in each credential. Authentication uses a
generated default-region catalogue captured through AWS EC2 `DescribeRegions`.
Account Management separately owns commercial region opt-in state. Regional
request authentication checks the caller account; STS reads destination-account
eligibility inside credential publication using the authority timestamp. Typed
region transitions project ENABLING/DISABLING at a stored service-time deadline.
No background job is needed for a transition with no external completion effect.
Disabling a region denies access without deleting its resources. See
[region behavior and conformance limits](account-regions.md).
Account also owns typed primary and alternate contacts. It authorizes contact
operations inside its repository callback, including `account:AlternateContactTypes`.
The root assembly composes Account's primary-contact initialization with IAM's
initial roles and Organizations membership publication in the shared transaction.
No alternate contacts are inherited. See [contact behavior](account-contacts.md).
Account information reads Organizations' account registry and IAM's creation date
inside the shared transaction. Organizations owns name/state changes; IAM owns
the stable creation metadata used by root responses and credential reports.
Member provisioning writes that metadata with the initial roles. Account exposes
the captured whole-second date through its generated Smithy date-time format,
without reducing the precision of IAM's stored date. Name updates change registry
and membership views together and feed IAM's current account-name password rule.
See [account information](account-information.md).
Account's primary-email workflow retains verification intent in its typed
repository and delivers through an injected `EmailSender` after commit. OTP
acceptance schedules completion in service time; completion publishes the
Organizations registry, membership email and status in the shared transaction.
Delivery uses real network time and cancellation. The CLI can use a local SMTP
capture server. See [email behavior and conformance gaps](account-primary-email.md).
JWT publication adds no token ledger or credential row. Public discovery uses
an explicitly configured origin and routes to IAM before authenticated AWS
dispatch. OIDC/SAML-issued sessions retain the verified provider identity for
policy evaluation and outbound claims. See [outbound identity](iam-outbound-identity.md).

`internal/services/<service>` owns resource models, transitions, validation and
transport adapters for that service. Each provider operates through a service-owned typed repository interface;
the in-memory adapters return detached records and supply typed state to
`storage/memory.Store`. That engine implements synchronization, cancellation,
snapshot lifetime and commit/rollback once. `storage/memory.Domain` coordinates
Account, IAM, Organizations, KMS and SQS through a borrowed repository context.
Writes stage until the owning callback succeeds; ordinary nested failures and
cancellation roll back all participating state. Explicit command attempts can
isolate recoverable rejection without independently committing accepted work;
see [transaction ownership](sqlite-state.md#ownership-and-transactions).
Typed adapters still own resource schemas and cloning.
KMS service-role provisioning shares the key transaction. SQS prepares missing
data keys outside its locks and transactions, then repeats authorization and message selection from
current state before committing. Queue incarnation checks reject replacement
resources; prepared key caches publish after the successful state commit. See
[the encryption boundary](sqs-delivery.md#encryption-preparation-and-commit).
The default bundle also supplies a journal in this domain. STS credential
issuance and IAM access-key API mutations append typed events with credential
state. Organizations account-creation acceptance and terminal outcomes use the
revision-checked commit callback to append with job and account state. Retained
request identity correlates recovered work; reads expose committed history through `Stack.Events` and `GET /_stackd/events`. See
[event ownership and limits](event-journal.md). Memory state is not durable and
does not implement instance forks.

KMS shares one typed key-set record for cryptographic material, rotation and
regional topology. Regional keys own policies, grants, tags, aliases and enabled
state. Replication and promotion commit their affected records in one KMS
transaction; deletion of a replica cannot erase surviving material. Imported
material identity, description and rotation belong to the shared key set;
wrapping tokens, import presence and expiry belong to regional key records.
Real OAEP/RFC 5649 unwrapping and PKCS8 validation feed the existing cryptographic
operations. Expiry and accepted rotation advance in service time in the key
transaction; see [import behavior](kms-imports.md). IAM owns
the independently provisioned KMS service-linked role. Its deletion checker
uses KMS then IAM lock order to keep regional dependencies stable. See
[multi-Region behavior and evidence](kms-multi-region.md).

Organizations commits an accepted account-creation job before returning
`IN_PROGRESS`. Admission reserves an account ID and retains the role name and
tags. Its shared scheduler source completes the request after a modeled
one-second service delay. The typed record survives service reconstruction with retained storage.
Completion enforces the current organization account quota before supplying IAM
with the account's initial role request. Quotas count management and closed
members and default to ten. Validated `Config.OrganizationAccountQuotas` overrides
apply by management account and partition across all regions. Reopening retained
storage applies the configured quota to pending work without removing existing
members; admission and completion use the same quota source. Native Service
Quotas APIs and invitation reservations remain open. IAM opens the
shared authority and checks the management caller's dependency permission before
creating a missing Organizations service-linked role. Member provisioning also
installs the ordinary access role and administrator attachment. Organizations
checks and stages its partition revision before role writes; stale revisions
abort the attempt. Synchronous organization creation repeats authorization;
accepted account jobs retry against current membership. Errors and cancellation
discard both stores' completion writes, preserving accepted pending jobs. Existing owned service roles retain identity and description.
The service-linked deletion callback borrows that same transaction context,
keeping all-features membership stable through the final IAM decision. The
ordinary access role uses the existing STS trust and current policy evaluator.
See [account access](organizations-account-access.md) and
[service-linked roles](iam-service-linked-roles.md) for evidence and open work.

Public `iam/policy` parses policies and composes identity, boundary, inline/managed
session, resource and Organizations SCP/RCP permissions from immutable snapshots.
Its decision trace records sources and versions, hierarchy targets, statements,
principal bindings and reached conditions without request values. The internal
`authorization` adapter resolves current identities and trusted context, binds
resource principals and invokes that same public composition path. Providers
identify each actual action and resource before a state transition. See the
[library contract and verification](iam-evaluation.md).
IAM policy writes bind user/role principals to immutable IDs so deleting and
recreating an identity does not restore old trust. Simulation remains a separate
API whose coverage is tracked explicitly. Unsupported semantics fail closed.

IAM session authority uses the repository's native `Attempt` boundary. A rejected
authority command rolls back its writes without poisoning its enclosing write.
EKS Auth also owns an enclosing attempt for the complete source/target-role
exchange: issued credentials and successful STS outcomes commit together or are
discarded together. Rejected STS outcomes use the existing API-outcome retention
mechanism and are recorded after that exchange rolls back, preserving the
authorization error rather than replacing it with an audit-storage failure.

KMS grant resolution also binds assumed-role session names to the role's
immutable ID, and federated names to their account. Grants retain these bindings
across provider reconstruction and render deleted identities as unique IDs.
The public evaluator receives one `GrantPermissions` value with role/session
and caller-account trust distinctions. See [grant behavior](kms-grants.md).

Organizations resolves the resource owner's current organization path and RCP
hierarchy in one snapshot. Authorization uses that context for identity and
resource policies, and intersects RCPs before granting access. STS joins these
reads to the existing IAM authority transaction for signed and externally
verified federation sessions. Generated service/action applicability comes from
AWS's published RCP coverage; KMS and IAM own resource-specific exemptions.
See [RCP behavior and evidence](iam-resource-controls.md).

Virtual MFA keeps clock adjustment, accepted synchronization pairs and the recent
used TOTP counters in its typed IAM record. STS consumes a code in the credential
authority transaction, so concurrent requests and failed publication cannot
produce duplicate use or lose the ability to retry after rollback. Synchronization
history survives deactivation and is separate from STS code consumption: accepting
a pair neither spends an unused authentication code nor releases a used one.
The shared typed propagation model retains ordered IAM-to-STS binding changes;
IAM sees the current binding while STS sees the last
change whose service-time deadline has passed. Deletion hides the control resource
immediately and retains its preceding authentication binding until revocation
propagates. A device ARN's verification count and three-minute UTC window survive
seed replacement. Invalid authentication commits the attempt without issuing a
credential; storage failures and cancellation retain the rollback contract.
Successful IAM transactions reclaim retired records after both revocation and the
verification window expire. Recreation preserves pending visibility and
distinguishes consumed codes by seed. [The MFA audit](iam-mfa.md) records the AWS
evidence and remaining replacement-device, root and hardware/FIDO gaps.

## Service time

`Config.Clock` supplies one time source to identity, authorization, IAM, STS,
Organizations, KMS and SQS. Nil selects `clock.Real{}`. The public `clock.Clock`
contract provides `Now`, `NewTimer` and atomic absolute `NewTimerAt` registration;
timers expose `C()`, `Stop` and `Reset`. Authorization derives policy date keys
and MFA age from its evaluation instant. Credential expiry, resource timestamps,
IAM lifecycle checks, SQS visibility/retention and background waits use modeled
time. SQS long polls select the next message or request deadline and wake on
queue changes; IAM deletion workers and SQS redrive use the same timer source.
SQS captures one instant inside its write callback for action/tag authorization
and resource transitions. Current IAM, Organizations and queue policies use that
transaction's snapshot. A retry after KMS preparation captures a new instant.

`clock.NewManual(start)` returns a caller-controlled UTC clock. `Advance(d)`
rejects backward movement and fires registered due timers without invoking
service callbacks under the clock lock. It does not drain receiving goroutines
or recursively execute their newly scheduled work. Equal-deadline notifications
follow registration order; goroutine execution and transaction ordering remain
uncontrolled. `Pending` counts scheduled timers, and `WaitForTimers(ctx, n)`
observes at least `n` of them without identifying or reserving a particular
consumer's timer. Tests synchronize registration before advancing, then observe
the relevant request or worker completion.

The caller owns an injected clock. Closing a stack cancels and joins its waiters
but leaves the clock usable. Retained backends can be reopened with that source;
separate clocks give isolated timelines, while deliberately sharing one source
makes advances visible to all its consumers. `clock.OpenManual` can retain the
instant through its `clock.Storage` contract. The SQLite adapter commits each
advance before the process exposes the instant or delivers timers. It requires
its own transaction; a borrowed resource transaction could still roll back after
publication. Storage waits do not hold the mutex used by `Now` and timer
registration, so resource callbacks can read time while holding a transaction.
An overlapping resource operation can finish using its preceding captured time.
The clock update does not atomically execute resource transitions or jobs.

`Stack.ServiceTime` and `Stack.AdvanceTime` expose local controls through
`GET /_stackd/clock` and `POST /_stackd/clock` with `{"advance":"2m"}`. The CLI
restores a saved timeline automatically; `-clock-start` initializes one when
absent. See [SQLite time and ownership](sqlite-state.md#manual-service-time).
Timer registrations remain process-local. The clock API itself supplies neither
job execution nor seed capture or snapshot/fork facilities; background sources
use the ordered driver below.

Transport time remains separate: gateway SigV4 skew, outbound HTTPS certificate
validation and HTTP/context deadlines use wall time. Modeled validity checks for
IAM/ACM certificates and OIDC/JWT/SAML token checks use service time.
Explicit HTTP dependencies should share the instance source through
`NewHTTPOIDCDiscoveryWithClock(transport, source)` for cache lifetimes and
`OAuthHTTPConfig.Clock` for token expiry; their default constructors use real
time. Outbound TLS trust and network liveness retain wall time with either
configuration.

## Durable state and execution

Default state is in memory and is lost on restart. Credential, IAM, queue and
key transitions use typed transactional repositories. Organizations authorizes a
partition snapshot and commits it only when its revision is still current.
Repository failures and cancellation leave committed resource state unchanged.
Memory transactions support concurrent readers, serializable writers and
cancellation while waiting for a lock. Errors, panics and cancellation before
commit discard staged writes, and callbacks are never retried. Escaped repository
transactions reject reads and writes after their callback closes.
`Config.Storage` selects a complete `storage.Backends` bundle; `storage.NewMemory`
centralizes the default construction. The public `storage/<service>` packages
expose service-owned typed contracts and records to backend implementations.
Adapters retain record cloning because each schema owns its nested data; the
generic engine does not interpret resource records. The default bundle shares one
memory domain across all resource adapters and the event journal. Related callbacks borrow the owning
transaction; external effects run outside it.
IAM and credential rows share a transaction through a typed identity adapter;
issuing or renaming a key cannot commit separately from its IAM mutation.
`storage/sqlite` now supplies native transactions and schema setup for the
SQLC-backed Account, IAM, Organizations, KMS, SQS, EventBridge, Lambda, S3,
CloudTrail, Logs and CloudWatch adapters. IAM owns persistent
credentials and STS sessions alongside its policy graph and jobs. Account owns
contacts, region transitions and email intents; Organizations owns its registry,
hierarchy and account provisioning. Keys, grants and queue state share the database.
`-database` selects all resource adapters and the journal together; embedders use `Config.Storage`.
See [SQLite ownership and recovery](sqlite-state.md).
Their callback contexts carry the native transaction into related SQLite
repositories. Ordinary nested writes retain one owning commit and rollback;
explicit recoverable commands use the same native savepoint boundary as described
in [transaction ownership](sqlite-state.md#ownership-and-transactions).
S3 accounting storage reaches schema 117: request-payment state, logging
configuration and ordered grants coexist with independent queued access-log
records, destination/grant snapshots and due times. Reopen discovers pending
delivery even after source logging is disabled; it does not reconstruct records
from the bucket's current configuration.
Schema 127 retains typed Inventory destinations, optional-field presence and
ordered children, enabled deadlines and parent event identities. Bucket deletion
cascades configurations; compare-and-advance updates preserve replacement and
deletion through restart without a separate delivery state machine.
Schema 128 adds the bucket ABAC flag without copying or re-encoding tag rows.
Schema 129 adds acceleration status; the empty value preserves the distinction
between never configured and explicitly suspended.
Each adapter passes the context into related repositories. IAM credentials,
Organizations membership/access roles and Account contact initialization publish
in the same native transaction. SQS prepares KMS data keys outside its queue
transaction, then evaluates current IAM/Organizations and queue policies with the
resource transition. The same boundary applies to the default memory bundle.
Logs schema 36 retains typed filters, system-field children and gzip delivery work;
schema 37 adds the accepted-batch journal payload. Accepted source rows, facts and
work roll back together. Delivery invokes Lambda outside that transaction, so a
crash between target acceptance and source progress may duplicate execution.
Subscription replacement and deletion fence old work; restart retains deadlines
and discovers committed work, not runtime process state.
Schemas 38/39 add CloudWatch metric identities/dimensions/points and Logs metric
filters with their dimension/system-field children. Their typed repositories
join the same native transaction; a failed metric append rolls back source Logs
rows and accepted-batch facts as well. Filter deletion leaves published metrics.
Schema 40 adds typed alarm configurations, dependencies, tags, current state,
causal origins, thirty-day history and ready actions. Evaluation-only updates
preserve configuration; deletion leaves independently retained history/accepted
work. State, EventBridge acceptance and ready intent share a transaction.
Versioned work and suppression deadlines survive restart, not runtime processes.
The remaining durable implementation must coordinate service-owned relational
tables, events and jobs in one storage domain. PostgreSQL must preserve the same
transaction semantics.
Cross-service snapshots also include scheduler and delivery positions; external
engines require their own checkpoint adapters. A single database does not itself
provide cheap test forks. Avoid an opaque JSON resource bucket as the data model.
Persistence and fork claims require restart, rollback, isolation and worker-fencing
tests. External calls and event dispatch run outside storage transactions.

### Background jobs

`Stack.Close` cancels Organizations provisioning, SQS long polls, redrive workers,
pending KMS preparations and IAM background jobs. Provisioning joins before IAM is closed.
Service-linked deletion jobs bind immutable role IDs and recover from the typed
repository. Linked services hold their usage stable through the final IAM
transaction; credential issuance also verifies the current issuer identity in
that transaction domain. IAM credential generation records its intent in the
request transaction, then commits the complete CSV artifact from one account
snapshot. Last-access generation freezes permissions, membership IDs and actual
authenticated activity when accepting the request, then schedules availability of
that immutable snapshot. It does not add a separate integrity or receipt protocol.
These job sources, Organizations account creation, SQS redrive, KMS lifecycles and
EventBridge scheduled occurrences, archive expiration/replay and target delivery, Lambda attempts, Logs subscriptions, CloudTrail
delivery and CloudWatch alarms join one `internal/scheduler` execution during
instance assembly. Standalone service
constructors keep independent drivers; assembly joins them before startup. All
joined handles share wakeups, automatic execution, explicit drains and shutdown.
The driver merges persisted due times, resolves equal deadlines by source
registration then stable key, and serializes callbacks. `Stack.New` owns driver
registration order; each service owns its ordered sources. Concurrent API
admission and external completions remain outside this ordering guarantee.
Each selection scan reads all sources inside the storage bundle's shared read
snapshot. Nested typed readers borrow that context; KMS discovery has a read-only
reader rather than opening a write transaction. The snapshot ends before the
selected source runs, and each `Run` owns its mutation transaction. No results are
cached between scans: cross-service publications can create work without a
destination wake hint. Joining drivers does not combine separate AWS transitions.

`Stack.RunDueJobs(ctx, limit)` and `POST /_stackd/jobs/drain?limit=256` expose
bounded draining over this group. A positive limit bounds successful callbacks,
including stale selections. The drain captures its horizon after acquiring the
shared execution gate and includes newly created work due at that instant. It
does not advance time. Results contain `processed`, `more` and an optional `next`
deadline. Automatic work may finish first, leaving an explicit drain with zero
callbacks. An error stops the drain and preserves its processed count; HTTP
returns 400 for an invalid limit, 503 after shutdown and 500 for source errors.

External service-linked usage checks run as tracked, cancellable work outside
that drain; a slow checker does not block account reports. Draining schedules those checks
without waiting for their external completion. Wake hints happen after commit;
recovery discovers pending records when a backend is reopened. Storage failures
retry on shared-clock deadlines, and shutdown cancels and joins execution. These
records survive service reconstruction with retained memory backends and process
termination with the coordinated SQLite adapters. SQS redrive has typed deadlines and
atomic message/task progress; closing preserves accepted tasks for recovery.
Logs subscriptions likewise use the shared driver with retained expiry, retry and
disable deadlines. Their one-second exponential cadence, 24-hour work retention
and exact ten-minute disable/skip policy are local service-time choices within
documented bounds, not native measured deadlines. Subscription configuration
activates immediately locally; observed AWS propagation remains a gap. See
[the subscription timing boundary](logs.md#modeled-time-and-unmeasured-behavior).
Account primary-email work retains a separate execution driver because it waits
for SMTP outside its resource transaction. A grouped drain does not wait for
that driver or for external IAM usage-check completion. The
[SDK integration](../integration/jobs_integration_test.go) verifies source ordering and actual
report, account/access-role and redrive results on memory and SQLite, including
reopening with due work. This local ordering is not an AWS completion-time claim.

KMS derives deadlines from its existing typed key and material records, without
a second job-state table. Its source advances replica readiness, primary promotion,
generated/imported rotation, imported-material/wrapping-key expiry and ordered
replica/primary deletion. Requests and jobs share transition and deadline selection
functions. A job advances one key set through one deadline; later deadlines consume
later callbacks, preserving the bounded drain across large manual advances.
Discovery and stale selections do not rewrite keys. Key-set IDs and current
deadlines fence canceled or replaced work. Successful HTTP transactions wake the
worker; periodic scans also discover keys created by service consumers.
The [KMS SDK tests](../integration/kms_jobs_integration_test.go) verify automatic recovery without
KMS traffic, retained cryptographic use, regional rollback, expiry and deletion on
memory and SQLite. Deadline discovery currently scans stored key namespaces;
KMS lifecycle event publication and durable attempt records remain open.

An owned local CLI run on 2026-09-12 also passed pending-job recovery across a
process restart, restored manual time, the operator drain, member-role assumption
and redriven payload retrieval using AWS CLI commands and test credentials.
Broader durable job attempts, recurrence/cancellation and event recovery remain
planned. Lambda now runs real RIC containers and persists asynchronous attempts;
remaining Lambda behavior, streams and database engines must perform their
data-plane behavior. Control-plane CRUD is not service completion.

The [Step Functions kernel](stepfunctions.md) now retains immutable execution
revisions, frames, attempts, history and clock-owned deadlines in typed shared
repositories. Transition history and service observations commit with state;
actual SDK/optimized task commands and Lambda runtime effects occur outside
the transaction. Callback leases survive SQLite restart. Its scheduler discovers
work from resource state rather than a second job ledger. Native dataflow,
control, callback, variable/history-limit and real-runtime fixtures establish
specific behavior, not complete Step Functions or general MVCC replay parity.

Cross-service consumers define narrow interfaces. IAM credential resolution and
STS sessions are behind a shared identity boundary; authorization composes
identity and resource policies, permissions boundaries, session policies and
Organizations SCPs and RCPs. An allow from one layer is not permission to bypass another.

Organizations owns centralized root features alongside IAM trusted access and
delegation. IAM feature APIs authorize and stage Organizations changes inside
the shared authority transaction. AssumeRoot binds IAM session issuance to
Organizations eligibility in that domain. CredentialsManagement gates all three
IAM root tasks, while Sessions gates S3/SQS recovery. Trusted access cannot be
disabled while a delegate remains registered. Issued root credentials retain
their task permissions until expiry; eligibility changes gate new issuance.
Root task documents are deny-only ceilings,
with trusted `aws:AssumedRoot` context and target-account SCP enforcement. SQS
owns its queue-policy recovery exception; other actions retain normal resource
policy evaluation. See [root access](iam-root-access.md) for exact evidence limits.

Service credentials verify secret digests and current IAM identities through a
consumer-owned interface; downstream APIs still authorize their actions. OIDC
and SAML providers expose detached trust snapshots to token verifiers. Outbound
OIDC discovery is explicit through `Config.OIDCDiscovery`; the default performs
no network discovery. `NewHTTPOIDCDiscovery` constructs an optional HTTPS source
using real time; `NewHTTPOIDCDiscoveryWithClock` selects its cache clock explicitly.
Discovery runs between read-only authorization and an atomic reauthorization,
so a network request never holds the IAM repository lock. STS now verifies OIDC
JWTs or signed/encrypted SAML assertions and issues credentials in the same IAM
transaction that revalidates provider configuration and current role trust.
Verified session claims feed subsequent policy evaluation. Opaque social tokens
use an explicitly configured `Config.OAuthTokens` verifier. The trusted region for
unsigned federation is `Config.UnsignedRegion`, defaulting to `us-east-1`.
See [OIDC](oidc-federation.md) and [SAML](saml-federation.md) for behavior and evidence.

Signed `AssumeRole`, `AssumeRoot`, `GetSessionToken` and `GetFederationToken` run through an IAM
session authority. A single IAM `Update` binds current parent credentials,
role incarnation and trust, applicable identity/boundary/session policies,
managed-session-policy existence and MFA state to credential insertion. The
callback borrows the repository and one instant captured after acquiring storage;
MFA, policy dates, parent expiry and issued timestamps use that instant. Responses
are published only after the authority succeeds. Failed commits and canceled
callbacks return no credentials and persist no new session.

Caller metadata stays in the caller account and partition. Destination role and
AssumeRole managed-session-policy reads use the role's account; GetFederationToken
managed policies use the requesting user's account. `GetSessionToken` performs
authentication without an IAM/SCP permissions gate and skips Organizations.
For the other signed issuance operations, action/tag/source checks reuse one
decoded caller-account SCP hierarchy through `WithPolicySnapshot`. Its read joins
the IAM transaction context, keeping organization controls, membership and root
eligibility stable through publication. IAM root-feature changes use that same
authority and stage Organizations writes until commit. Standalone Organizations
snapshots still return detached values without holding a transaction for callers.
Replacement backends must preserve this borrowed-context contract.

### Lambda container execution

`Config.LambdaExecutor` injects the real `compute/lambda.Executor` consumed by the
Lambda control plane. The Docker implementation uses pinned official runtime
images and the Runtime API, not imported handlers or an RIE invocation proxy.
It checks actual engine capabilities and installed images; it does not pull them.
IAM and control-plane-only embedding remain independent of Docker.
The executable owns one `compute/docker.Client` constructed with `docker.New`.
CLI `-docker-host` selects transport only; `-lambda-runtime`, `-ecs-runtime`,
`-codebuild-runtime`, `-dynamodb-runtime`, `-kinesis-runtime` and
`-inventory-orc-runtime` independently opt in their actual owners and default to
false. Only requested ECS invokes its local rootful Linux/systemd/cgroup-v2 and
pinned toolkit admission. `Config.ComputeEndpoint` and `-compute-endpoint` select
the reachable execution AWS origin. Consumers own their environments; the caller
closes Engine transport after those consumers stop.
Native macOS controller builds are supported; opt-in Desktop Lambda/DynamoDB/
Kinesis use real Linux VM engines, not synthetic execution or implicit pulls.
Lambda storage helpers and static Linux telemetry execute inside the actual
daemon VM. Lambda VPC namespaces, bridges and nftables use daemon identity and
real shared `flock` ownership through daemon helpers; EC2/ECS/EKS/ALB retain the
original local Linux host-security contract. Explicit callback host
`host.docker.internal` uses Desktop container DNS without controller resolution
or a shadow host mapping. This intended Desktop contract is not an observed
macOS run or a promise of arbitrary remote-engine capabilities; see the
[deployment recipe](runtime-containers.md#native-macos-controller-with-docker-desktop).
Lambda shutdown removes its environments; ECS controller shutdown detaches for
reattachment, while task stop owns provider-native removal. The shared client does
not own AWS state or merge service lifecycle models; see [ECS ownership](ecs.md).
Runtime images are selected by the typed runtime/AWS-architecture pair; actual
image inspection and explicit Docker platform selection prevent cross-CPU
dispatch. Both Python 3.12 architectures have real execution evidence.
The default map also pins Python 3.13, Node.js 22 and `provided.al2023` images per architecture.
Python 3.13/x86_64 runs the captured Secrets Manager rotation callbacks through
the real Runtime API; its arm64 image is pinned but not exercised by that replay.

Lambda commits active and pending deployment slots through typed memory/SQLC
repositories. Real container/mount preparation occurs outside transactions and
drives activation or candidate promotion. Customer init runs during Invoke;
its failure does not turn a successfully deployed function into `Failed`.
Execution roles come from the same IAM authority and credential store that
authenticate customer SDK callbacks.
Function ZIPs are staged at `/var/task`; ordered layer ZIPs merge into the real
read-only `/opt` runtime volume, with later layers replacing earlier colliding
paths. Deployments retain the original archives rather than a merged substitute
for public downloads. Custom `LoggingConfig.LogGroup` with Text output uses the
existing `RuntimeLogsAPI` integration and execution-role-authorized Logs commands;
the executor supplies actual stdout/stderr and runtime log-group/stream variables.
Logs continues to own ingestion and stored log events, not the deployment archive
repository.
External Lambda extensions execute in the same resource-limited container and
participate in Init/Invoke/Shutdown. Function response is an early callback;
execution/admission and causal ownership last through full phase completion.
Subscribed Logs/Telemetry delivery uses that container's network namespace,
independently of execution-role-authorized CloudWatch Logs delivery. Shared
generated runtime contracts project the pinned API/schema versions.
Normal shutdown owns the exact environments created by the service.
Service time controls idle eviction and credential expiry, not customer clocks or
actual invocation deadlines.
Streaming response admission and execution completion are distinct boundaries.
The Runtime API reader has bounded memory and invocation-owned socket deadlines;
the generated frontend owns framing and transport cancellation. Lambda discards
delivery after client disconnect without cancelling the function. A separate
final-output consumer prevents buffered client delivery from retaining an
execution lease after the runtime/extension phase has completed.
Provider shutdown cancels active delivery independently of client behavior.
The completed execution report retains handler-error accounting even when native
streaming APIs omit `FunctionError`; it does not rewrite asynchronous routing.
Opt-in development directories belong to the Docker backend configuration,
keyed by the full unqualified function ARN. They do not enter service repositories,
replace uploaded ZIP metadata or affect immutable versions. Environment-owned
filesystem watches coalesce changes on wall time; the invocation gate owns
process reset and directory rebinding while the existing keeper retains `/tmp`.
This is a read-only live mount, not a second deployment or snapshot protocol.
Function policies use shared IAM evaluation and independent policy revisions.
Asynchronous acceptance commits payload/queue state and a typed journal fact
together. The shared driver claims work but does not run customer code under its
gate. Queue settings have separate API-visible and applied state, with persisted
service-time application deadlines; see the native timing evidence below.
Whole-function deletion detaches retained accepted-event settings from the removed
configuration owner. Schema313 also migrates historical queues whose function is
already absent. Same-name recreation resolves current runtime and IAM authority;
explicit replacement configuration application/reset rejoins queue settings to the
existing propagation owner, rather than freezing them for the event's lifetime.
The local application deadline is representative, not measured AWS queue convergence.
Logs-triggered invocations use the same real acceptance/execution boundary.
Authenticated active-runtime SDK calls retain that accepted invocation as their
causal parent without borrowing source-service authority.

[Lambda behavior and evidence](lambda.md) is authoritative for this implemented
slice, its live AWS capture, setup, reset semantics and remaining limitations.
Other imported data planes and the broader lifecycle/networking/trace work remain
targets in the [kernel backend map](verification-kernel.md#required-backend-map).

## Extensions

Providers register explicitly; routing does not depend on imports, reflection or
`init` hooks. The public `extension` package exposes a versioned service contract
through `stackd.Config.Extensions`, including capability reporting and request
scope. It rejects duplicate routing registrations and unknown API versions.
Process-based extensions still need startup, health, cancellation and shutdown semantics
and explicit local endpoints. Native Go shared-object plugins are not the API:
their compiler/ABI coupling is unsuitable for distributing extensions.

## Compatibility evidence

Tests send signed requests from the AWS SDK for Go v2 to a real local HTTP server,
then check decoded shapes, modeled errors, pagination and lifecycle invariants.
These establish SDK interoperability, not parity by themselves. Semantics are
checked against AWS documentation and should grow into replayable fixtures and
opt-in AWS differential tests. Offline checks must never fall back to AWS or
discover credentials from a developer's environment.

Primary references: [Google's Go style guide](https://google.github.io/styleguide/go/guide),
[AWS Query protocol](https://smithy.io/2.0/aws/protocols/aws-query-protocol.html),
[AWS request signing](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html),
and [the generated operation inventory](services.json), whose generation and
evidence boundaries are recorded in [behavior references](behavior-references.md).

Organizations handshake state uses partition-owned typed records so terminal
handshakes can outlive membership or organization deletion. Acceptance shares
the existing IAM/Organizations transaction and retains existing account settings.
Its scheduler sources order account creation before handshake expiry/retention
at equal deadlines. Handshake events commit with each transition; see
[invitation behavior](organizations-invitations.md) and [feature migration](organizations-features.md).
Migration approval state outlives child-handshake history. Role inspection and
management finalization share the IAM transaction, while generated encoding still
completes before Organizations publishes the transition.

Organizations management-policy inheritance preserves attachment order and keeps
per-account published views and pending deadlines alongside the policy hierarchy.
The shared scheduler publishes the latest hierarchy with its event in the native
transaction; reads retain the previous view until that commit. The resolver
uses a shared inheritance grammar, separate from IAM/SCP/RCP evaluation. Tag
policy validation includes generated AWS resource-support data; native captures
cover account ownership and actual STS session restrictions. See
[effective policies](organizations-effective-policies.md) for persistence,
evidence and the remaining service-specific execution and conformance work.
