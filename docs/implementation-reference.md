# stackd

> Preserved implementation and development reference from the former root
> README. Start with [Getting started](getting-started.md) for installation and
> use, or the [documentation index](README.md) for task-oriented guides.
> Commands below run from the repository root. Historical progress statements
> are retained; consult each service guide and the current
> [support inventory](services.json) for its present boundaries.

A Go-native local AWS cloud emulator under active construction. The full emulator
goal remains active and incomplete: real offline behavior, typed services and
AWS SDK for Go v2 compatibility across every modeled operation of the chosen services.

[Resource Groups Tagging API](behavior-references.md#resource-groups-tagging-api)
reads tags from the existing service owners and routes mutations through their
current IAM checks. Published Organizations tag policies drive compliance
summaries, required tags and retained reports delivered as actual S3 CSV objects,
including bucket-default KMS encryption. There is no second tag-value store.
[Resource Groups](resourcegroups.md) evaluates tag and CloudFormation queries
against those current owners, including deletion/recreation and deployment
incarnation checks. AppRegistry owns real application/attribute metadata and
application groups over S3/SQS/SSM/CloudFormation owners; retained tag-sync jobs
and lifecycle events use current IAM and actual EventBridge consumers. Native
existing-customer AppRegistry/GLE calibration and specialty group owners remain open.

[Classic SES, SES v2 and Cognito email](cognito.md#captured-email-delivery)
share identities, templates, current sending-policy authority and readable local
`.eml` messages, including private BCC envelopes and retained verification/reset
codes. Native IAM `ses:ApiVersion` values are `1`/`2`, not model dates.
This is actual MIME capture, not Internet SMTP delivery; all 71 classic operations
remain [honestly inventoried](services.json), with unsupported owners explicit.
[EC2 monitoring](ec2.md#native-cpu-and-network-monitoring) measures real guest
vCPU execution and TAP traffic, retains basic/detailed CloudWatch periods across
controller restart, and feeds Auto Scaling target tracking.

The current implementation covers Account Management, IAM, Organizations, STS,
KMS, [Secrets Manager](secretsmanager.md), [SSM parameters and managed execution](ssm.md),
SQS, S3 versioned object storage, copies and multipart uploads/attributes,
retained ownership/ACL/public-access controls, account-level S3 Control settings
with published Organizations overrides, regional access-point lifecycle/policies,
ARN/alias data access and independent bucket/AP authorization, retained
Object Lock defaults, fixed/variable retention and legal holds, general-purpose
storage classes and retained archive restoration, live version-preserving
replication with execution-role/KMS authority, retained Lifecycle expiration
and storage-class transitions, Intelligent-Tiering archive automation and permanent
restoration, bucket/object tags, all ten modeled [checksum families](cloudtrail.md#s3-checksums),
SSE-KMS/default and real SSE-C customer-key encryption, CORS and anonymous static websites, requester-payment admission and
retained server-access-log delivery, CloudTrail history, KMS-encrypted S3 logs,
SNS log-file notifications and CloudWatch Logs delivery,
EventBridge SQS/Lambda/ECS/Logs/SNS/Kinesis/API-destination delivery, classic scheduled rules, target roles and cross-account/region bus forwarding, real-container Lambda ZIP execution with
asynchronous retries, retained destinations/dead-letter delivery, native outcome
counters and reserved-concurrency admission with pooled real runtimes. Lambda
deployments include immutable versions, weighted aliases, S3 COPY/REFERENCE
packages and ordered layers retained independently of their catalog entries.
Real external extensions share the function container and phase deadlines; Logs
and Telemetry subscriptions receive actual runtime output through its namespace.
Pinned Python 3.12/3.13, Node.js 22 and `provided.al2023` images are selected by runtime
and architecture. Lambda streams real runtime bytes through generated AWS
event-stream responses without cancelling accepted execution on client disconnect.
Scoped [Function URLs](lambda.md#function-urls) expose real buffered/streamed
HTTP through current IAM/public policies, with retained configuration and explicit
native-evidence boundaries.
Opt-in local code/layer directories reload between invocations without mutating published ZIPs.
Function retrieval provides retained, independently expiring deployment ZIP
downloads. See [Lambda behavior and limits](lambda.md).
Lambda also owns real provisioned runtime pools, recursion controls, durable
execution/checkpoint/callback state, Signer-backed code admission and self-managed
Kafka/MQ/DocumentDB consumers. Its bounded managed-capacity backend boots actual
EC2 guests with SSM and the Runtime API, retaining ownership and current IAM
authority rather than substituting host containers. [Evidence and limits](lambda.md#managed-instances-and-capacity-providers)
separate local physical proof, native calibration and unimplemented combinations.
[Amazon MQ](mq.md) also operates independently of Lambda: real ActiveMQ and
RabbitMQ brokers, native JMS/AMQP clients, retained configuration revisions and
ActiveMQ user changes applied on reboot. Its real TLS web console supports
retained user access, queue/message browsing and sending. ActiveMQ general/audit
and RabbitMQ general logs flow from native files to CloudWatch Logs with durable
cursors. ActiveMQ uses resource-policy authority; RabbitMQ uses its current IAM
service-linked role. Native RabbitMQ exchange/connection/channel and
queue/message/consumer gauges feed scoped CloudWatch metrics, including live
quorum counters and retained history. ActiveMQ JMX supplies real broker
connection/message/consumer/producer gauges and distinct queue/topic series,
with transactional publication and SQLite-retained history.
Public single-instance execution is supported; private attachment, replicated
deployments, managed encrypted storage and remaining metric families are explicit
owner-integration gaps.
[GuardDuty](guardduty.md) retains detectors, samples, observed findings,
filters and tags with current IAM, protected service-linked roles and SQLite
restart. Structured API rules detect root-credential use, password-policy change
attempts, CloudTrail/S3 logging changes, S3 public-access-block disabling and
public ACL grants. Bounded anonymous bucket-policy grant proofs use admitted S3
state and shared IAM action/resource reasoning, not `IsPublic`; conditional,
variable-resource and authenticated-audience reasoning remain incomplete.
Observations commit with source events and reach real EventBridge/SQS consumers.
S3 data-event protection feeds the implemented rules from actual authenticated
S3 requests, with retained source configuration and no disabled-period replay.
Native EKS audit metadata feeds system-pod exec and bounded anonymous-access
rules; admitted RBAC binding responses establish anonymous-access grants.
Detection is independent of CloudWatch logging, with atomic source admission and
durable replay deduplication. Remaining EKS predicates need workload/privilege
policy context and threat telemetry, not sample findings.
Legacy trusted-IP and threat lists ingest real S3 objects under current IAM/KMS
authority. Trusted matches override API detection; custom threat reconnaissance
retains list evidence. Typed snapshots and activation recovery survive restart.
Findings expire under a shared-clock 90-day creation cap; the native timestamp
anchor remains uncalibrated.
DNS/flow telemetry, other optional protections and remaining operations are still
explicit gaps, not implied by `ENABLED` configuration.
[EventBridge Scheduler](scheduler.md) and [Pipes](pipes.md) are separate
service owners: Scheduler retains time-zone-aware occurrences, target retries and
DLQs; Pipes consumes actual SQS, Kinesis, DynamoDB Streams and Kafka/MSK sources
with retained checkpoints, filtering, transformations and real target effects.
Both use current execution-role authority, KMS and the shared clock/SQLite domain.
Unavailable source security/networking modes and target owners return errors.
Retained [EventBridge Connections](eventbridge.md#connections-and-managed-credentials)
own real Secrets Manager credentials and authenticated HTTPS/OAuth requests.
[Step Functions HTTP Tasks](stepfunctions.md#authenticated-http-tasks) enforce
execution-role, Connection and secret authority through those owners.
CloudFormation owns JSON/YAML template evaluation, retained stack/change-set work,
rollback and ordered resource events over the same real S3/SQS/SNS/IAM/Lambda/
EventBridge/SSM/ECR/KMS owners. Official `aws cloudformation deploy` uses the
generated Query frontend; the unmodified official CDK CLI also completes
[bootstrap, deployment and destroy](behavior-references.md#official-cdk-bootstrap-and-deployment)
with real file assets, data-plane effects, replacement, rollback and SQLite restart.
[Deployment behavior and boundaries](behavior-references.md#cloudformation-deployments)
distinguish implemented resource properties from explicitly unsupported macros,
StackSets, private registry extensions, nested stacks and custom-resource callbacks.
Cloud Control shares the resource adapters for live S3/SQS/Logs/SSM/ECR discovery and
retained asynchronous mutations, including direct-owner resources, current-role
authorization and actual data-plane effects. See its
[request contract and executable proof](behavior-references.md#cloud-control-resource-requests).
[AWS Config](config.md) records actual S3/SQS owner state in the source
transaction and delivers retained history/snapshots through S3/SNS. Managed tag
rules and real Lambda custom rules share current role authority and the scheduler.
[AppConfig and AppConfig Data](appconfig.md) deliver actual versioned bytes
from SSM, S3, Secrets Manager and hosted content, with real Lambda validation and
extension effects, current IAM/KMS checks, rollout and alarm rollback. The
unmodified official Agent consumes experiment assignments and restores baseline
flags after stop; retained sessions and customer-owned results survive restart.
[CodePipeline](codepipeline.md) connects versioned S3 sources, real CodeBuild
containers, manual approvals, real Lambda invocations/job callbacks and AppConfig
deployments through the shared scheduler. Artifact bytes stay in S3; retained execution metadata, current
IAM/KMS checks and EventBridge starts remain separate owners. Other action
providers and the remaining modeled operations are explicit gaps, not simulated
success.
[API Destinations](eventbridge.md#api-destinations) retain controls and deliver
actual authenticated HTTPS with current authority, rate admission, retries and
DLQs; Pipes reuses the same destination owner for HTTP effects and source acknowledgements.
The [S3 accounting contract](cloudtrail.md#s3-requester-payment-and-server-access-logging)
owns requester charge headers, paired caller/owner audit records, actual encrypted
server logs and their native best-effort delivery boundaries; S3 parity remains incomplete.
S3 request metrics publish actual request counters, bytes and individual latency
samples into CloudWatch without borrowing caller metric permissions or retaining
a parallel S3 sample store. [Request metric behavior](cloudtrail.md#s3-request-metrics)
owns configuration filters, native evidence and best-effort delivery boundaries.
S3 [Inventory](cloudtrail.md#s3-inventory) retains scheduled metadata exports
and delivers actual CSV/GZIP, ORC/ZLIB and Parquet/Snappy reports through ordinary
S3/KMS authorization, encryption and notifications.
Bucket [ABAC](cloudtrail.md#s3-bucket-abac) retains opt-in state and enforces
current bucket/access-point tag conditions through shared IAM, including ordinary
S3 Control tagging, creation tags and copy/multipart reauthorization.
Bucket [transfer acceleration](cloudtrail.md#s3-transfer-acceleration) retains
unset/enabled/suspended state and admits actual signed and presigned object
traffic through accelerated/dualstack endpoints, including access-point aliases.
CloudWatch Logs provides ingestion/filtering, resource policies,
execution-role-authorized runtime output with custom text log groups, retained Lambda subscriptions and metric
filters. SNS standard topics deliver through SQS, Lambda, real HTTP/S endpoints
and role-authorized Firehose; FIFO topics retain ordered SQS fanout. Both enforce
policies, encryption and filtering, with retained service metrics. HTTP confirmation,
retry work and Firehose buffers survive SQLite restart. EventBridge ingestion and delivery
metrics survive restart and feed CloudWatch alarms. CloudWatch stores custom metrics,
evaluates statistics/math, SEARCH and Metrics Insights queries, and retains metric/composite alarms with
suppression, native EventBridge events and real Lambda/SNS actions.
Classic [X-Ray traces and consumers](verification-kernel.md#x-ray-storage-and-audit)
provide ingestion/assembly, discovery filters, trace/service graphs, retained
groups and sampling rules/targets, with current IAM enforcement, CloudWatch
metrics, daemon telemetry admission and selected CloudTrail events. SNS
[PassThrough propagation](sns.md#x-ray-propagation) survives queued delivery
and restart. Sampled SNS-origin spans, Insights and broader account
controls remain unsupported; these consumers are not complete X-Ray parity.
[Step Functions](stepfunctions.md) executes retained Standard/Express
workflows, activities, retries, JSONPath/JSONata dataflow and nested branches
through the shared clock and typed memory/SQLite repositories. Tasks invoke
actual service commands and real Lambda runtimes. Native fixture replay covers
control identity, dataflow, callbacks and history/variable boundaries; remaining
task dependencies and service-parity gaps are explicit.
[Cognito user pools](cognito.md) provides 47 implemented pool/client/user/group/auth
operations behind a 132-operation modeled frontend. Real password and SRP login,
temporary-password challenges, distinct access/ID JWT signing keys, public JWKS
and retained refresh rotation/revocation share typed memory/SQLite storage.
Groups retain canonical memberships and issue current group/role claims at login
and refresh, including native precedence and deletion behavior. Assigning a group
role enforces `iam:PassRole`, including scoped session-policy denies.
Bearer-authorized profile updates, attribute removal and self-deletion enforce
current client permissions and retain revoked-family attribution without reviving
credentials when a username is recreated.
Unsigned APIs resolve recipient audit scope from actual resources without
acquiring IAM authority. Native login, admission and CloudTrail fixtures record
specific AWS behavior; delivery, MFA, federation, devices and hosted UI/OAuth
remain deferred. This is an application kernel, not complete Cognito.
[Cognito Identity](cognito-identity.md) consumes those real user-pool proofs
for enhanced-flow credentials. [Identity Store](identity-store.md) and
[Identity Center](identity-center.md) own directories, permission sets and
account assignments; unmodified AWS CLI device-code SSO login obtains usable
credentials through current IAM/Organizations authority. Reserved SSO roles are
protected IAM-owned records, not service-linked-role policy exemptions.
EC2 provides retained [RSA/Ed25519 key pairs](ec2.md#key-pairs), networking
prerequisites, IPv4 ENI allocation, internet gateways/routes, regional discovery
and native VPC service events. [Public IPv4 and Elastic IPs](ec2.md#public-ipv4-and-elastic-ips)
retain one EC2 address owner and implement real host-local guest/task inbound NAT
and assigned-address egress under current SG/NACL and IGW policy.
[EBS direct APIs](ec2.md#ebs-direct-snapshot-data-plane)
retain real sparse snapshot bytes, encrypted parent/child layers, scoped tokens,
asynchronous completion and shared EC2 snapshot/default-encryption controls.
Private sharing enforces current IAM/KMS authority, recipient-private tags and
token revocation; public-access controls consume published Organizations policy.
Independent snapshot copies preserve real bytes and lineage across account/Region
transfers, using constrained KMS service grants and native completion notifications.
Unattached volumes retain actual hydrated disk contents, modification state and
volume-derived snapshots, preserving KMS context and bytes after source deletion.
Native SDK fixtures and executable disk/sharing/copy/volume workflows exercise
SQLite restart, CloudTrail S3 records and EventBridge-to-SQS delivery. QEMU/KVM
guests consume real NVMe volumes, IMDSv2 and instance-role credentials.
[Profile changes and locally trusted identity signatures](ec2.md#instance-identity-signatures)
survive SQLite/controller restart without advancing manual service time.
[IMDSv1/v2 credentials](ec2.md#imds-credential-delivery-versions) retain
independent delivery context for cross-service IAM enforcement and CloudTrail;
requiring v2 does not revoke previously delivered v1 credentials.
[Instance-role origin conditions](ec2.md#instance-role-credential-origin)
retain the issuing instance, VPC and private IPv4 independently of the request's
network path, including through SQLite/controller restart.
Console screenshots capture real guest pixels; WakeUp injects actual keyboard
input rather than substituting an image or restarting the guest.
Retained stop/start and running-instance AMI creation preserve actual encrypted root/data
bytes; lifecycle events, CPU-credit metrics and audit records use the shared
service integrations. This remains a bounded kernel, not EC2 parity. ECS provides
retained cluster/task-definition controls, tags, real standalone Fargate tasks and
replica services with scaling, replacement, rolling deployment and circuit rollback.
Task-role credentials, logs, events, managed ENIs and live-container SQLite
reattachment share the same runtime. Real task CPU/memory observations publish
retained service metrics into CloudWatch at default or configured high resolution.
Application Auto Scaling retains ECS targets, schedules, step policies and
target-tracking alarms; real service-linked-role commands change ECS capacity.
Retained scaling activity histories follow actual completion, overrides and
failures rather than reporting desired-capacity acceptance as success.
[EC2 Auto Scaling](ec2.md#ec2-auto-scaling) has generated Query controls and
typed retained groups, memberships, activities, policies, schedules and lifecycle
actions. Original-caller EC2 admission is separate from service-linked execution;
EC2, ALB, EventBridge, SNS/SQS and CloudWatch remain the dependency owners.
Native fixtures distinguish protected scale-in, health replacement, hook waits
and observed force-delete behavior. Actual CLI captures exercise firmware guests,
ALB packets, restart, notification rejection and protected service-owned retirement.
Warm pools reuse the same EC2 lifecycle and hook owners. Actual guest CPU/network
samples feed CloudWatch; authoritative membership excludes warm guests from
active-group series. Advanced capacity families remain explicit gaps, not claimed
parity.
An initial IPv4 Application Load Balancer owner now runs real HTTP/HTTPS listeners,
rules, target health and draining through EC2-managed native nodes. ECS replica
deployments register exact task/ENI incarnations and gate readiness on target health.
Real routed requests retain minute `AWS/ApplicationELB` metrics through restart;
`ALBRequestCountPerTarget` target tracking drives actual ECS scaling through the
existing CloudWatch alarm owner, draining targets before native task retirement.
This is not Classic ELB, NLB or full ELBv2 parity; see the
[ALB behavior and limits](behavior-references.md#application-load-balancer-kernel).
[EC2](ec2.md) and [ECS](ecs.md) own their runtime contracts.
[Route 53](route53.md) publishes retained hosted zones and atomic record
changes through that same real UDP/TCP DNS server, including delegation,
weighted/multivalue answers and aliases to the actual ALB owner.
[ACM](acm.md) resolves its required CNAMEs through the DNS wire endpoint and
issues real, explicitly **locally trusted** certificates. Issuance, timeout,
renewal, in-use deletion and current TLS material share service time and typed
SQLite state; these certificates are not publicly trusted AWS certificates.
EC2/VPC work continues alongside Glue/Athena and ECR/CodeBuild.
[EKS](eks.md) now has a generated frontend, retained cluster/access controls
and real pinned k3d Kubernetes with IAM-token admission, native RBAC and
restart-preserved workloads. Managed node groups and broader integrations remain
open. [EC2 execution](ec2.md#execution-and-shared-compute-ownership)
uses QEMU/KVM for firmware-booted HVM guests through an injected contract, while
keeping networking authoritative and Lambda/ECS container backends unchanged.
Glue and Athena now have generated frontends, typed catalog/control state and
native job/query adapters. Glue jobs use actual Python or Spark processes;
Athena SQL uses Trino against the Glue catalog and S3, not synthesized query
results. See [analytics evidence and remaining boundaries](behavior-references.md#glue-and-athena-engines-evidence-and-boundaries).
Registered operations and native engine probes do not establish complete AWS parity.
[RDS and the RDS Data API](rds.md) use real PostgreSQL and MySQL engines.
Typed control state, retained lifecycle work, physical snapshots and real SQL
transactions are separate owners; Secrets Manager and current IAM remain the
credential authorities. Modeled Aurora clusters use an upstream-engine writer,
not simulated Aurora storage, readers, failover or cloud networking.
[DocumentDB](documentdb.md) shares the ordinary RDS Query endpoint and runs
an explicit pinned MongoDB compatibility backend with mandatory TLS/SCRAM, real
documents/change streams, retained native lifecycle and independent physical
snapshots. This is not the AWS DocumentDB storage engine or full behavioral
equivalence; AWS-specific change-stream controls and other differences are explicit.
OpenSearch uses a real pinned upstream engine behind generated modern/legacy
configuration APIs and the shared SigV4 gateway. Domain policy, live IAM/STS
authority and resource tags authorize every data request; documents are never
stored in a toy control-plane search implementation. See [native setup](#native-opensearch)
and [evidence and explicit boundaries](behavior-references.md#opensearch-engines-evidence-and-boundaries).
ElastiCache and MemoryDB use a shared pinned Valkey runtime with real native
replication, cluster slots, TLS, ACLs, AOF durability and independent RDB snapshots.
Their control planes own typed scoped intent, current IAM and retained lifecycle
work; they do not simulate AWS-managed networking, failover or MemoryDB's
distributed durable log. See [Valkey setup, evidence and boundaries](behavior-references.md#elasticache-and-memorydb-native-valkey).
DynamoDB uses pinned DynamoDB Local for items, expressions, transactions and
PartiQL. Go owns scoped table/index intent, IAM, service-time TTL, retained
Streams and table/GSI scaling bounds through the real service-linked role.
On-demand backups copy real items into retained private native tables; restores
survive source deletion and restart, rebuild selected indexes, and require
restore authority rather than CreateTable authority.
Continuous recovery retains private baselines and typed item history, including
transactions, PartiQL and TTL. Historical restores survive restart; deleting a
PITR-enabled source creates a real, service-time-expiring SYSTEM backup.
Initial continuous-backup registration follows service time and real restore
readiness rather than assuming every ACTIVE table is immediately ready.
Same-account version-2019 replicas copy real regional data and retain subsequent
item changes across restart. Current replication-role permissions govern delivery;
settings and TTL synchronize while tags, policies and PITR remain regional.
Provisioned replica creation requires table/GSI write autoscaling and copies
registered read/write scaling configurations. Application Auto Scaling capacity
changes remain regional, unlike ordinary customer table-setting updates.
Global billing transitions retain visible on-demand scaling configuration and
recreate provisioned defaults through the original scaling owner, preserving
target identities, tags and suspension flags.
Combined replica/settings operations reject before lookup or mutation.
Replica-autoscaling APIs reuse the scaling owner, preserve native partial effects
and pre-update responses, and retain their authority distinctions across restart.
Legacy global APIs enforce the observed retirement of new version-2017 groups;
their reads and removals do not expose or alter current-version replicas.
MRSC and multi-account replication remain incomplete.
Lambda consumes those Streams through execution-role-authorized commands, retained
shard checkpoints and retry/window state, with real runtime execution and SQS/SNS/S3
failure destinations. [Stream-source behavior](lambda.md#dynamodb-streams-event-source-mappings)
records the native evidence and remaining boundaries.
Source-owned capacity observations survive reopen and feed CloudWatch alarms
and actual utilization-driven table/GSI scaling. Provisioned admission rejects
before mutation, preserves partial batch outcomes and recovers through service
time and applied capacity changes. Configured on-demand maximums and retained
throughput-decrease/billing-switch quotas are enforced. Account-default on-demand
and physical-partition admission and exact physical-partition accounting remain incomplete;
[DynamoDB evidence and limits](behavior-references.md#dynamodb-engine-references)
records the measured behavior and remaining boundaries.
Kinesis uses pinned Apache Kafka for durable record bytes and native offset/time
lookup. Go owns scoped streams, shard ancestry, retention, IAM, real KMS
encryption, shared-throughput reads and SDK enhanced-fan-out event streams.
DynamoDB destinations reuse actual item-change capture and their replication
service-linked role; EventBridge targets use the retained target role and ordinary
Kinesis commands. Lambda consumes shared-throughput streams and enhanced-fan-out
consumers through one retained DynamoDB/Kinesis processing engine. Logs delivers
real gzip batches to direct Kinesis targets or policy-controlled logical
destinations. The executable Logs → Kinesis → real Python Lambda → SQS workflow
also survives SQLite process restart.
Native fixtures also exercise delivered control/data audits, denied and missing
resources, history aliases, per-record shard byte metrics, caught-up iterator age
and absent idle series on both stores. Enhanced readers preserve admitted leases
after consumer deregistration, use captured raw-data frame bounds, delay empty
heartbeats, and distinguish clean service EOF from client disconnects in metrics.
[Streaming evidence and boundaries](behavior-references.md#kinesis-streaming-dependency-evidence)
distinguishes measured AWS behavior from local timing and admission models.
MSK's generated `kafka` frontend provisions separate public Apache Kafka brokers,
not Kinesis's private log. Native Kafka owns topics, partitions, records and
consumer groups; typed scoped memory/SQLite state owns cluster lifecycles,
configuration revisions, resource policies and Secrets Manager SCRAM associations.
The installed-only `-msk-runtime` supports one to three real loopback brokers,
TLS, explicitly requested plaintext, or TLS/SCRAM-SHA-512. Unsupported VPC,
IAM/mTLS data authentication and managed-volume modes are rejected rather than
reported as running settings. [MSK setup, security and evidence](behavior-references.md#msk-public-kafka-brokers)
records the local admission contract and its differences from AWS networking.
Lambda [MSK event-source mappings](lambda.md#msk-event-source-mappings)
consume those actual brokers, retain source identity across restart, and commit
broker offsets only after filtering or successful real function execution.
Firehose retains DirectPut and Kinesis-source records for actual S3 delivery,
including native compression framing, KPL deaggregation, trusted Logs
decompression/extraction, real Lambda transformation, independent raw backup/error
output, diagnostics, current role authority and service-owned metrics.
Logs and EventBridge producers share its ordinary PutRecord command. Executable
producer → Firehose → Lambda → S3 workflows exercise byte delivery, permission
recovery and independent destination recovery across SQLite restart without
rerunning completed Lambda work. [Firehose behavior and limits](firehose.md)
separates these paths from unfinished processors, destinations and throughput.
API Gateway REST, HTTP and WebSocket control planes retain deployments for real
Lambda proxy execution, with `execute-api` IAM, REST Cognito, HTTP JWT and
REST/HTTP Lambda TOKEN/REQUEST and WebSocket REQUEST authorizers. Authorizer
policies use the shared IAM evaluator; configured invocation roles enforce
`iam:PassRole`, service trust and Lambda invocation permission. REST/HTTP
stage-scoped caches retain service-time expiry and explicit invalidation.
WebSocket authorization runs once per connection, without an identity cache;
later messages retain the accepted context.
WebSockets deliver deployed one-way/two-way routes and all three connection
management operations; live connections are API-scoped and are not persisted.
Integration credentials are retained in deployment snapshots. All three API
types can assume invocation roles; REST also forwards authenticated caller
credentials through the existing IAM forwarded-access context. Held WebSocket
messages use the currently deployed integration role, independently of their
connection's retained authorizer context.
REST API keys and usage plans retain scoped controls, memberships and quota
accounting. Deployed key requirements admit HEADER or authorizer-returned keys;
live key/plan changes govern subsequent requests. Plan and method throttles
compose, and quota state survives SQLite reopening.
REST/HTTP/WebSocket execution publishes retained `AWS/ApiGateway` metrics through
CloudWatch, with protocol-specific counters, detailed dimensions and actual runtime
latencies. Pending minute samples and stage settings survive SQLite reopening;
API deletion does not delete historical metrics.
Stage access logs and REST/WebSocket execution logs now reach CloudWatch Logs
through real destination authorization. HTTP uses vended resource-policy delivery;
REST/WebSocket use the retained regional account role. Request IDs correlate the
client, actual Lambda invocation and log records. Logging settings and history
survive SQLite reopening; delivery failures do not change execution responses.
Native fixture replay uses official runtime containers on memory and reopened
SQLite. These remain partial kernels: Marketplace plan associations, optional
CUSTOM-authorizer key semantics, quota calendar/offset calibration, literal
header spelling, mappings, non-Lambda integrations, remaining logging context/
delivery boundaries and metric byte/error calibration remain open.
See [Gateway evidence and boundaries](behavior-references.md#api-gateway-deployed-lambda-authorization-evidence).
[AppSync](appsync.md) executes GraphQL and APPSYNC_JS resolvers against
actual DynamoDB, Lambda, HTTP and PostgreSQL owners, including subscriptions and
API-key/IAM/Cognito/OIDC authorization. VTL and remaining execution/control
families remain explicit errors rather than metadata-only data sources.
Authenticated Lambda SDK calls retain their active invocation parent; ECS
task-role SDK calls retain their issued task ancestry across controller restart.
These remain partial services.
[TODO.md](../TODO.md) preserves the delivery scope and
[docs/services.json](services.json) records every operation in the pinned AWS
SDK Smithy models for the explicitly chosen services in
[docs/service-targets.json](service-targets.json), alongside actual built-in
health registrations. Registration is at most `partial`, never proof of semantic
completion. CloudTrail Lake is excluded from the behavioral target; its modeled
operations remain known and return honest unsupported errors. SMTP, hardware MFA
and specialty KMS remain deferred. AWS contracts and native evidence define
behavior. See [source and generation details](behavior-references.md#generated-operation-inventory).

The shared [event contract](event-journal.md) describes transaction ownership,
causal delivery and the distinct CloudTrail, EventBridge and CloudWatch boundaries.
[EventBridge](eventbridge.md) and [CloudTrail](cloudtrail.md) document the
implemented paths and remaining AWS behavior.
[Lambda](lambda.md) records the real Runtime API path, native AWS fixtures,
execution-role enforcement, container setup and remaining boundaries.
[CloudWatch Logs](logs.md) records native ingestion/filter fixtures, typed
storage, runtime/service delivery and remaining destination/query contracts.
[CloudWatch](cloudwatch.md) records publication, statistics/alarm evidence,
protocol interoperability, retained evaluation and remaining service boundaries.
[SNS](sns.md) records native filtering, protocol projections, signatures,
service metrics, real Lambda/SQS delivery and remaining service boundaries.
[EC2](ec2.md) and [ECS](ecs.md) record native fixtures, transactional
audit behavior, retained state and the implemented task/runtime boundaries.

Private ECR and CodeBuild now have generated SDK frontends, service-owned
memory/SQLite state and real data planes. ECR stores authenticated OCI manifest
and layer bytes, applies current IAM/repository/registry policies and KMS grants,
and runs lifecycle expiration, offline basic scanning and replication. CodeBuild
executes source/buildspec commands in isolated Docker containers and consumes the
existing IAM/STS, S3, Secrets Manager, KMS, Logs and EventBridge owners. These are
partial service implementations, not complete configuration parity; see
[ECR and CodeBuild evidence and boundaries](behavior-references.md#ecr-and-codebuild).
Public Git source types require their canonical provider authority at API
admission and retained preparation. Stopped source staging is reconciled after
controller crashes, deleting fleets drain admitted preparation and cleanup, and
unselected workspace links do not prevent regular-file artifact publication.

## Run

Requires Go 1.26.5 or newer. Module downloads are needed for the initial build;
by default, the running emulator and its tests do not contact AWS.
Control-plane-only use, including IAM embedding, requires no container runtime.
Lambda ZIP, ECS tasks/services, DynamoDB Local, Kinesis, ElastiCache/MemoryDB and
ORC inventory encoding use explicit per-instance Docker dependencies and locally installed images.
CLI `-docker-host` constructs these; build the pinned inventory encoder with
`docker build -t stackd/orc:2.2.2 engine/orc` before enabling that CLI option.
`make build` creates `bin/stackd` and the static Linux Lambda telemetry helpers
used by real execution. Install those artifacts together, or select their
directory with `-lambda-telemetry-directory`.
Lambda also requires the preinstalled disk-storage helper and daemon capabilities
listed in [temporary-storage setup](lambda.md#temporary-storage-and-crash-recovery);
its `/tmp` quota is disk-backed rather than charged to function memory.
ECS requires local rootful Linux Docker with systemd/cgroup v2 and the preinstalled
pinned `compute/docker.ToolkitImage`. `-compute-endpoint` selects the shared
container-reachable AWS endpoint.
ALB execution additionally requires a static relay executable:
`CGO_ENABLED=0 go build -o bin/stackd-elbv2-node ./cmd/stackd-elbv2-node`.
Select its absolute path with `-elbv2-node-executable` alongside `-docker-host`.
The relay uses the same rootful Docker/toolkit and EC2 bridge/policy owners.
ALB hostnames resolve through the real UDP/TCP endpoint selected by `-dns-listen`.
Without that flag, native ALB execution gets an ephemeral loopback DNS port printed
at startup. Clients must use that resolver explicitly; the host resolver is not changed.
Route 53 and ACM DNS validation use that same endpoint. For a DNS-only instance,
set `-dns-listen` explicitly; constructing the services does not bind another
listener. See [DNS scope and delegation](route53.md#dns-resolution-and-delegation-boundary)
and [certificate trust](acm.md#trust-boundary) before configuring clients.

CodeBuild also uses `-docker-host` and `-compute-endpoint`; build images must be
installed locally for offline use. `-codebuild-fleet-image` requires an explicit
local image ID or digest for real idle fleet containers. Basic ECR scans require
`-ecr-scanner /absolute/path/to/trivy` and `-ecr-scanner-cache /absolute/cache`:
Trivy 0.74.0 and a pre-provisioned schema-2 vulnerability database are explicit
inputs, never silently downloaded or replaced with clean findings.
Missing execution support never falls back to an in-process handler.
See [Lambda setup](lambda.md), [ECS setup and evidence](ecs.md),
the [pinned DynamoDB backend](behavior-references.md#dynamodb-engine-references)
and [Kinesis backend](behavior-references.md#imported-record-engine-experiments).
ElastiCache/MemoryDB execution separately requires `-valkey-runtime` plus
`-docker-host`, an installed immutable Valkey image, and a real certificate/key
pair for TLS-enabled resources. [Valkey setup](behavior-references.md#elasticache-and-memorydb-native-valkey)
lists the exact image and flags; no image is pulled implicitly.

Analytics execution is separately opt-in: `-docker-host` alone does not enable it.
Use `-glue-runtime` and/or `-athena-runtime` with the installed immutable images
listed in the [analytics evidence](behavior-references.md#glue-and-athena-engines-evidence-and-boundaries).
Image overrides are `-glue-spark-image`, `-glue-python-image`, `-athena-image` and
`-athena-hive-ddl-image`; adapters never pull images. Embedded callers inject
`Config.GlueRuntime` and `Config.AthenaRuntime`, and close caller-owned native
runtimes after the stack. Glue's AWS-library image is restricted to permitted
AWS-targeted development/testing, not general standalone or other-cloud use.
Its [exact upstream license](../compute/glue/AWS-GLUE-LICENSE.txt) is not Apache-2.0.

```sh
go run ./cmd/stackd
```

The endpoint listens on `127.0.0.1:4566`. `-listen` changes the address and
`-account-id` changes the account used by the `test` access key.
`-tls-cert ./cert.pem -tls-key ./key.pem` serves HTTPS; both flags are required
together and are validated before state opens. Clients must trust the certificate
(for AWS CLI, use `--ca-bundle`). SSE-C headers require actual TLS; forwarded
scheme headers do not satisfy it. HTTP remains the default for other requests.
`-database ./stackd.sqlite` persists resource state, the shared event journal and
EventBridge schedule deadlines, Scheduler occurrences/retries, Pipes consumer
checkpoints/work, EventBridge/Lambda/CloudTrail/Logs/SNS delivery and CloudWatch
alarm work in one SQLite database.
See [SQLite state and recovery limits](sqlite-state.md).
DynamoDB and Kinesis native containers and volumes are retained with SQLite.
Without `-database`, graceful CLI shutdown removes engines owned by its in-memory
repositories. Embedded callers inject `Config.DynamoDBRuntime` and
`Config.KinesisRuntime` and own runtime disposal; closing their stack does not
delete native storage.
`-clock-start 2031-02-03T04:05:00Z` initializes manual service time. With
`-database`, the saved instant takes precedence and is restored on subsequent
starts even without `-clock-start`. With no manual timeline configured, time
follows the wall clock.
`-public-endpoint` sets the advertised origin for identity federation, SNS
certificate/notification URLs and Lambda Function URLs/deployment downloads;
it defaults to the listener.

```sh
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
unset AWS_SESSION_TOKEN
aws --endpoint-url http://127.0.0.1:4566 sts get-caller-identity
aws --endpoint-url http://127.0.0.1:4566 iam create-user --user-name alice
aws --endpoint-url http://127.0.0.1:4566 organizations create-organization
curl http://127.0.0.1:4566/_stackd/health
curl 'http://127.0.0.1:4566/_stackd/events?after=0&limit=100'
```

Use a 12-digit access key, such as `123456789012`, with secret `test` to select
another local account. These bootstrap credentials represent local root identities.
IAM-issued access keys and STS-issued session credentials are also supported;
signatures, key status, expiry and session tokens are verified against local state.
Real AWS credentials are not accepted by the emulator. Implemented built-in API
operations enforce IAM identity and resource policies, permissions boundaries,
session policies and Organizations SCPs and RCPs. Resource controls follow the
resource owner's organization and restrict external callers too; see
[RCP enforcement and AWS evidence](iam-resource-controls.md).
IAM users start without permissions. The public `stackd/iam/policy` library
provides the same policy composition without the server or storage and returns
structured decision explanations; see [the library contract](iam-evaluation.md).
Virtual MFA devices generate real seeds and QR codes, validate TOTP codes and
record authentication age in `GetSessionToken` credentials. Role assumption
checks MFA during the trust decision. Non-MFA `GetSessionToken` credentials
cannot call IAM.

IAM also enforces instance-profile membership and PassRole, login passwords,
account password policies/history/expiry and account aliases. AWS-managed policy
documents and retained versions are embedded from an auditable AWS capture.
Service-specific credentials enforce reset, revocation and expiry. OIDC/SAML
providers store validated trust material behind typed interfaces. Service-linked
roles use protected ownership and asynchronous deletion with dependency checks;
commercial service templates are available for implemented dependencies.
Signing certificates, SSH public keys and server certificates have real
cryptographic verification and typed consumer interfaces. STS accepts OIDC and
signed/encrypted SAML federation, checks current provider configuration and role
trust atomically, and issues usable role credentials. See the
[OIDC](oidc-federation.md) and [SAML](saml-federation.md) behavior guides.
IAM remains the [active completion target](iam-completion.md).

IAM can inspect and acquire roles from five captured AWS-managed templates.
Acquisition enforces the underlying permissions, commits policies and the role
together, and reuses unchanged roles. See [role templates](iam-role-templates.md)
for mutation behavior and live AWS evidence. Account properties enforce namespace
conditions and atomically provision Role Manager's service-linked role when
enabled. See [account properties](iam-account-properties.md) for evidence,
the unresolved AWS probe cleanup and remaining Role Manager behavior.

Organizations account creation provisions a usable IAM access role with trust in
the management account and attached `AdministratorAccess`. The default name is
`OrganizationAccountAccessRole`; custom names are supported. Organization creation
and member provisioning also install the protected Organizations service-linked
role. Accepted account requests return `IN_PROGRESS`; service-time jobs commit
membership, roles and the copied primary contact together, with recovery on retained backends. All-features
membership prevents service-role deletion. Post-success initialization, billing
access and broader creation conformance remain open. See
[account access and AWS evidence](organizations-account-access.md).

Organizations invitations join existing accounts through IAM-authorized handshakes,
with staged tags, atomic service-role provisioning and inherited SCP enforcement.
Memory and SQLite retain the lifecycle, quota reservations, service-time expiry
and committed events. See [invitation behavior and remaining AWS conformance](organizations-invitations.md).

Standard all-features migration gathers invited-member consent, restores missing
Organizations service-linked roles and requires management finalization. Approval
state survives child-handshake cleanup and SQLite restart. See [workflow and
remaining AWS audit](organizations-features.md).

Organizations can resolve effective management policies from root, OU and account
attachments. Native tag-policy replay covers inheritance, defaults, validation,
STS restrictions and scheduled publication. Tag and backup validation reports retain
the previous valid document when an inherited update fails validation; diagnostics
and pending work survive SQLite restart. See
[effective-policy behavior and remaining scope](organizations-effective-policies.md).

Organizations defaults to ten accounts, including the management account and
closed members. Match an applied AWS quota with a scoped override:

```sh
go run ./cmd/stackd -organization-account-quota aws/000000000000=5000
```

Repeat the flag for other management accounts or partitions. Embedders use
`Config.OrganizationAccountQuotas`; the override applies across regions and to
recovered creation jobs. Existing accounts remain intact after a quota decrease.

IAM's global STS token preference affects issued credentials: legacy tokens fail
authentication in opt-in regions, while regional endpoints issue modern tokens.
Preference changes propagate in service time and preserve existing sessions.
See [STS token preferences](iam-sts-preferences.md). Account Management owns
commercial region opt-in: new accounts start with opt-in regions disabled;
`EnableRegion` and `DisableRegion` complete in modeled service time. Regional
requests check the caller account, and STS issuance checks the destination account.
Disabling access preserves regional resources. See [region behavior and AWS
evidence](account-regions.md), including Organizations delegation and the
remaining activation/propagation audit.

Account Management also stores primary and alternate contacts, enforces contact-type
IAM conditions, and copies the management account's primary contact when Organizations
creates a member. Updates replace stored values and preserve account isolation.
See [contact behavior and AWS evidence](account-contacts.md) for native
normalization, missing-contact errors and remaining validation work.
`GetAccountInformation` and `PutAccountName` share account identity with Organizations
and creation dates with IAM. Name changes also reach IAM's default password checks.
See [account information and native SDK behavior](account-information.md).
Primary-email updates deliver a real OTP through an explicit `EmailSender` or
CLI `-smtp-address` local relay, verify it, and publish the new Organizations email
in service time. See [setup, behavior and remaining native
conformance](account-primary-email.md).

IAM outbound federation and STS `GetWebIdentityToken` issue real RS256/ES384 JWTs
with public discovery/JWKS, current IAM and Organizations claims, permissions,
session expiry and payload limits. Feature enable/disable changes reach STS after
10 service-time seconds, preserving rapid toggle order. Embedders configure
`PublicEndpoint` to serve the issuer. See [outbound identity behavior](iam-outbound-identity.md).

Centralized root features use Organizations-owned state and IAM permissions.
STS `AssumeRoot` issues task-scoped member-root sessions with expiry and SCP
enforcement. Credentials management enables the three IAM root tasks; RootSessions
enables S3/SQS policy recovery independently. Root credential operations and SQS
policy recovery consume those sessions. See
[root access behavior and AWS evidence](iam-root-access.md).

IAM account reporting exposes current resource counts and enforced quotas, plus
the permission graph of users, groups, roles and managed policies. Authorization
details include memberships, policy documents and retained versions, boundaries,
tags and role instance profiles through generated response contracts. See the
[account reporting behavior guide](iam-account-reporting.md). Credential
reports generate an atomic CSV snapshot of actual passwords, MFA, keys and
certificates, retain it across mutations, and share the ordered IAM job driver
with service-linked deletion. See [credential reports](iam-credential-reports.md).

IAM last-access reports freeze actual authenticated activity and current policy
relationships, including denied attempts and KMS calls made by SQS. Report jobs
use service time and enforce generating-user/session ownership. Organizations
reports apply SCP hierarchies and aggregate attempts by account, with cached jobs
and asynchronous permission failures. Action coverage, service names and default
report regions are generated from AWS metadata and captures. See
[last-access behavior and evidence](iam-last-access.md).

IAM policy simulation evaluates current principal policy graphs, request policies,
boundaries, resource policies and SCPs, with statement positions and missing context
diagnostics. Exclusions affect only the hypothetical evaluation. See
[simulation behavior and live evidence](iam-simulation.md).

Signed STS `AssumeRole`, `AssumeRoot`, `GetSessionToken` and `GetFederationToken` validate
current IAM state and insert credentials in one IAM transaction, using the time
captured after acquiring storage. A failed commit or canceled authority returns
no credentials and leaves no issued session. `GetSessionToken` authenticates
the caller and optional MFA without an IAM/SCP permissions gate or Organizations
dependency. Assumption and federation permissions use one caller-account SCP
snapshot in the shared IAM/Organizations transaction domain.
Current role policies and managed session-policy versions continue to govern
existing sessions. Queue delivery uses this authorization path, including KMS
permissions for encrypted queues.

KMS grants bind IAM identities and named STS sessions, enforce delegation and
cross-account trust, and preserve old bindings after role recreation. Exact-session
grants can authorize encrypted queue delivery while session policies permit only
SQS. See [grant behavior and AWS evidence](kms-grants.md).

SQS standard fair queues prioritize quiet tenants from current delivery
concurrency, preserve spare capacity for noisy tenants and recover in service
time. Classification commits with message state and survives reuse of retained
backends. Processing-time detection and metrics remain open; see
[delivery behavior and AWS evidence](sqs-delivery.md).

KMS multi-Region keys share actual material and rotation history while preserving
regional policies, grants and enabled state. Replication and primary promotion
enforce regional IAM permissions and use modeled service-time transitions;
primary deletion waits for replicas. Imported symmetric, HMAC, RSA and ECC material
uses real RSA/OAEP or RSA/AES wrapping, regional expiry and reimport binding.
Imported symmetric versions rotate on demand and retain old ciphertext; see
[import behavior and AWS evidence](kms-imports.md). See [multi-Region behavior and native AWS
evidence](kms-multi-region.md), including outstanding AWS cleanup windows.


### Native OpenSearch

Install the pinned upstream image explicitly; the runtime never pulls images:

```sh
docker pull opensearchproject/opensearch@sha256:9e0b3b3b6805811bd63d9b9503ffe34a58ba33d03cc346000e318c6ff5c05bd9
go run ./cmd/stackd -listen 127.0.0.1:4566 -database ./search.db \
  -docker-host unix:///var/run/docker.sock \
  -compute-endpoint http://127.0.0.1:4566 -opensearch-runtime
```

`CreateDomain` defaults to the installed `OpenSearch_2.19` engine (upstream
2.19.4), not AWS's latest version. Omit instance type, EBS and managed security
settings: unsupported cloud infrastructure, encryption, TLS and fine-grained
authentication settings fail explicitly. A domain has one actual data node and
one durable native volume. Supported advanced options are
`indices.query.bool.max_clause_count` and
`rest.action.multi.allow_explicit_index`; updates change the actual engine.

Wait for `DescribeDomain.Processing=false`, then use the returned `Endpoint`
with the controller's HTTP(S) scheme. Its scoped path is part of the endpoint:
retain it in ordinary OpenSearch client `Addresses` and sign requests with
service `es` and the domain's Region. The official OpenSearch Go client's AWS v2
signer works without host rewriting or custom transport. Disable node discovery:
this managed endpoint is not a native cluster-node address.

Use native paths without redundant literal trailing slashes: `/catalog/_search/`
and `/catalog/_doc/id/` return `400 ValidationException`, rather than letting
native route normalization bypass an exact-resource policy denial. The root
`/` remains supported. Encoded document-ID slashes remain data: `id%2F` addresses
the distinct document `id/`, not `id`.

The gateway enforces current identity/resource policy and tag conditions,
including public/IP-based policy requests; basic/internal-user authentication
and managed TLS are not advertised. The private engine REST listener is bound
only to Docker-host loopback. Local host processes and Docker administrators
are trusted; the controller must share that network namespace. This is not a
hostile-local-user sandbox, VPC, outbound firewall or AWS EBS implementation.

SQLite shutdown detaches engines and preserves native bytes; restart reattaches
and verifies real protocol readiness. `DeleteDomain` removes only the exact
persisted incarnation's container, volume and network. Ephemeral CLI instances
clean up their owned engines at shutdown. The signed executable proof is:

```sh
go build -race -o /tmp/stackd-search ./cmd/stackd
go run ./scripts/opensearch_smoke /tmp/stackd-search
```

## Embed in Go tests

```go
source := clock.NewManual(time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)) // import "stackd/clock"
handler, err := stackd.New(stackd.Config{Clock: source})
if err != nil {
    t.Fatal(err)
}
server := httptest.NewServer(handler)
t.Cleanup(server.Close)
t.Cleanup(func() { _ = handler.Close() })
client := iam.New(iam.Options{
    Region:       "us-east-1",
    BaseEndpoint: aws.String(server.URL),
    Credentials:  credentials.NewStaticCredentialsProvider("test", "test", ""),
    HTTPClient:   server.Client(),
})
```

`Config.Clock` controls modeled time across identity, authorization, IAM, STS,
Organizations, KMS and SQS. Omit it to use `clock.Real{}`. A `clock.Manual` starts
at the supplied UTC instant and advances only when the caller requests it:

```go
if err := source.Advance(15 * time.Minute); err != nil {
    t.Fatal(err)
}
// Subsequent SDK requests observe the advanced credential and resource times.
```

`Advance` delivers due timer notifications; it does not wait for service
goroutines to finish or run timers they subsequently register. For asynchronous
tests, `source.WaitForTimers(ctx, n)` waits for at least `n` pending timers before
an advance; then wait for the relevant SDK request or worker result. This is a
count across every consumer of the clock, not a reservation of particular
timers. `source.Pending()` excludes stopped timers and delivered notifications.
Equal-deadline notifications use registration order, but goroutine execution
order is not controlled.

The local endpoint exposes the same controls:

```sh
curl http://127.0.0.1:4566/_stackd/clock
curl -H 'Content-Type: application/json' -d '{"advance":"15m"}' \
  http://127.0.0.1:4566/_stackd/clock
```

Responses contain the current instant as RFC3339, for example
`{"time":"2031-02-03T04:05:00Z"}`.
Advances use Go duration syntax (`2m`, `6h`), reject backward movement and require
a manual clock. Like `Advance`, a successful response does not wait for jobs to
finish. Embedders can call `Stack.ServiceTime()` and `Stack.AdvanceTime(ctx, d)`;
see [persistent clock setup](sqlite-state.md#manual-service-time) for SQLite.

To drain due lifecycle work, service deliveries, subscriptions and CloudWatch
alarm evaluation/actions, call `Stack.RunDueJobs(ctx, limit)` or the local endpoint:

```sh
curl -X POST 'http://127.0.0.1:4566/_stackd/jobs/drain?limit=256'
```

The drain returns `{"processed":3,"more":false}` and an optional `next` deadline.
It shares execution with the automatic worker, so `processed` can be zero when
that worker already finished the due work. `more` means the limit left work due
at the captured service instant. Draining does not advance time. Equal deadlines
use the fixed service/source order documented in [architecture](architecture.md#background-jobs).
Account email delivery and external service-role usage checks complete separately.

Injected clocks remain caller-owned. `Stack.Close` releases its service timers
without resetting or closing the clock, so it can be reused with retained
backends. Sharing a clock across stacks deliberately shares their time advances;
use separate manual clocks for independent timelines. SigV4 skew checks,
outbound HTTPS certificate checks and HTTP/context deadlines use wall time, so
ordinary SDK requests continue to work while modeled time is paused or advanced.
Modeled validity checks for IAM-uploaded and ACM-owned certificates use service time.

For configured HTTP identity providers, pass the same source to
`stackd.NewHTTPOIDCDiscoveryWithClock(transport, source)` and
`stackd.OAuthHTTPConfig{Clock: source}` when constructing discovery or OAuth
introspection. Their cache/token expiry must agree with `Config.Clock`; their
outbound TLS checks and network timeouts continue to use wall time. Test token timestamps
must match the chosen service epoch. The helpers that omit a clock use real time.

By default, typed service repositories use a shared in-memory transaction engine
with cancellable locking, snapshot reads and atomic commit/rollback;
typed service adapters detach records and retain their domain schemas. Account, IAM,
credentials, Organizations, KMS and SQS share one transaction domain. Related calls
commit or roll back with their owner. State is lost on process restart.
To select backends in one place, pass a complete `storage.Backends` bundle:

```go
backends := storage.NewMemory() // import "stackd/storage"
// Replace individual fields with implementations of storage/<service> contracts.
handler, err := stackd.New(stackd.Config{Storage: backends})
```

Injected backends remain caller-owned and can be reused after the previous stack
closes. Each bundle serves one active stack. Replacement repositories must join
related callbacks through their transaction context. SQS evaluates IAM and
Organizations policies inside its queue transaction; KMS service-role creation
rolls back if the key write fails. KMS data-key preparation runs outside queue
transactions.
Call `Close` to join queue long polls, redrive execution, IAM jobs and Organizations
account provisioning. Accepted redrive tasks remain pending in retained storage
and resume when the next stack starts its workers.
The implemented services also have [SQLC-backed SQLite implementations](sqlite-state.md),
selected together by the CLI option above. IAM owns persistent signing credentials
and STS sessions; Account and Organizations share its transaction. The
[committed event journal](event-journal.md) records STS credential issuance
and IAM access-key creation, status updates and deletion with their resource
transactions. Organizations account creation commits accepted and terminal
events with its job, membership, initial roles and contacts, retaining the
originating request across restart. The journal exposes local paginated history. Broader event
delivery, serverless execution and the remaining service families
are tracked in the backlog. Go extensions register through the versioned
[extension API](../extension/service.go) using `Config.Extensions`. They receive
verified requests and account/region scope. Conflicting registrations and unknown
API versions are rejected. Supervised process extensions remain on the backlog.

The accepted [kernel design](verification-kernel.md) prioritizes an atomic
event log, deterministic service time/scheduling, consistent test forks and a
reusable IAM evaluator. Shared clock injection, optional persistent manual time
and ordered draining of IAM, Organizations, SQS and KMS jobs are implemented, including
typed job recovery. Durable attempts, seeds, broader event delivery and forks
remain planned. Future compute and engine services use pinned real containers
under the single [execution lifecycle plan](verification-kernel.md#borrow-data-planes-and-run-real-compute):
actual readiness drives activation, with scoped backend API callbacks, isolated
DNS and enforced networking. Virtual time ends at customer-code API/event edges;
it does not control container clocks or threads. AWS responses carry no fidelity
labels. See the
[delivery gates](../TODO.md#kernel-delivery-gates).

## Develop

Use affected-package tests, focused native-fixture replays and actual SDK/runtime
smoke scenarios during development. After a failure, diagnose and rerun the
affected case rather than restarting the full suite.

```sh
go test ./internal/services/iam
make hooks
```

Run the full gate once against the combined, frozen integration tree—not after
each intermediate change or in separate overlapping worktrees:

```sh
make check
```

`make hooks` installs repository-local hooks, preserving the previous commit-message
hook. Pre-commit checks formatting of changed staged Go files without changing
files or staging edits. Pre-push runs `go vet` and pinned Staticcheck on changed Go
packages from the pushed commits, not the working tree. Module changes and a new
remote ref check all Go packages; deleted and build-ignored-only packages are
omitted. Check standalone build-ignored Go tools explicitly by filename with
`go build`, `go vet` and `go tool staticcheck`. Invalid buildable packages still fail.
Unchanged packages, full tests and generator drift are not part of the hook loop.
Run affected tests while editing and reserve `make check` for an integrated checkpoint.

`make check` verifies formatting and generation drift, runs `go vet` and Staticcheck,
and runs all tests with the race detector. Tests use pinned AWS SDK for Go v2 clients, local HTTP servers and explicit
credentials. They check concrete behavior; they do not claim untested AWS parity.
See [the architecture](architecture.md) and [contribution rules](../AGENTS.md).

## Generated AWS API layer

`make generate-aws` reads Smithy models from `clones/aws-sdk-go-v2` and generates typed
request/response declarations, operation dispatch, constraints and service routing
metadata for the implemented service families. Override the source with
`make generate-aws AWS_SDK_PATH=/path/to/aws-sdk-go-v2`. The clone is ignored by Git;
generated code is checked in and normal builds/tests do not require it.

`make generate-aws-check` detects stale output without modifying files. Every generated
contract records the source revision and model checksum. Reviewed model
corrections carry separate manifest provenance and fail generation if their
exact target traits change. The gateway decodes and
validates inputs through generated operation bindings, and rejects implemented
operation names absent from the upstream model. STS and the regional JSON providers use generated output bindings as well.
New IAM resource families, users/groups/roles, access keys and tag operations use generated
outputs. Service logic and the remaining IAM/Organizations response adapters are
handwritten; model generation does not implement AWS behavior.

`make generate-iam` reads the pinned AWS service reference and generates the typed
permission catalogue and last-access action metadata. It retains every ARN form
and applicable condition key across 455 service prefixes. Refresh the public
source explicitly with `python3 scripts/aws/iam_service_reference.py`, then
regenerate and review the diff. See [catalog ownership and native
verification](../internal/iam/catalog/README.md). Normal generation needs no clone,
AWS credentials or network.

`make generate-oidc` generates shared OIDC trust-policy controls from the pinned
official AWS table; its refresh script fetches updates only with an explicit
`--refresh-source`. `make generate-simulation` generates action recognition,
resource display metadata and resource-handling options from native IAM captures.

`make generate-lambda-runtime` generates extension/telemetry bindings and schema
version projections from pinned AWS specifications. Generation and staged checks
run offline; native request-schema corrections retain their capture references.

`go run ./cmd/awspolicies` refreshes the AWS-managed policy snapshot using real
AWS credentials. It is an explicit network operation; ordinary generation and
tests use checked-in data. The snapshot includes 1,575 commercial policies and
7,006 versions. Other partitions require authoritative captures with their own
credentials.

Observations from real AWS IAM and STS are stored in `testdata/aws` and service
fixture directories and replayed offline. Reproduction scripts in `scripts/aws`
use uniquely owned temporary IAM resources and verify cleanup. Fixture provenance
states which fields and behaviors are compared; the
[IAM audit](iam-completion.md) tracks what remains unverified.

The probes share typed CLI execution and response parsing in
[scripts/aws/aws_cli.py](../scripts/aws/aws_cli.py). Use `call` for required setup and
cleanup operations, `observe` for native JSON success/error observations, or
`run` and `result` for text errors and debug response details. Native JSON
errors are available on `AWSCLIError.details`; callers do not need to parse
exception strings. Endpoint and retry choices, credential handling, resource
ownership and fixture normalization remain with each probe.

Local executable probes share typed process ownership, health readiness and
shutdown evidence in [scripts/aws/stackd_process.py](../scripts/aws/stackd_process.py).
Callers retain command flags, explicit environments and exact resource cleanup.
Forced cleanup is explicit: it records the actual exit and still fails the probe;
it never turns a shutdown timeout into a successful verification.
Gateway readiness is not native-engine readiness: database and other asynchronous
owners must reach their own reported ready state before data-plane assertions.

Integration tests live in `integration/`; service tests remain beside their owners.
Native AWS observations live in `testdata/aws/`. Fixture suites invoke actual SDK
methods through `internal/awstest.CallSDK`; add data for new behavior cases and
reserve Go tests for resource setup, transaction failures and recovery boundaries.
