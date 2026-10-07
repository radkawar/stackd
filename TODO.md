# Work remaining

The goal remains a fully functional offline AWS cloud with our Go control planes
and real upstream engine/compute data planes. [The generated inventory](docs/services.json)
contains every operation in the pinned AWS SDK Smithy models for the explicitly
chosen services in [the service selection](docs/service-targets.json), including
implemented prerequisite services. None of these services is complete; a
registered handler is partial implementation, not semantic parity.

The selection defines service scope, Smithy defines the complete modeled
operation inventory and protocol shapes, and AWS defines behavior. CloudTrail
Lake is excluded from the behavioral target, but its model-known operations
remain visible and fail honestly when unsupported.

Prioritize usable service features and cross-service application paths over
exhaustive quota/rate-limit parity. Implement important admission boundaries,
record remaining gaps, and reuse compatible limiter mechanics as concrete
callers need them. Detailed fleet behavior and quota tuning do not block the next
service. [The shared design policy](docs/verification-kernel.md#iam-evaluation-and-strict-behavior)
keeps service-specific accounting and error semantics authoritative.

- [x] Generate the operation inventory from explicit service selection, pinned
  SDK Smithy models and actual built-in registrations. `make generate-coverage`
  refreshes `docs/services.json`; `make generate-coverage-check` and the explicit
  `make check` gate detect drift. Registered operations remain partial, not conformance.
- [x] Reconcile cross-service debt and implementation consistency across all 68
  service/execution owners; record the sampled boundaries and remaining work in
  [the consistency audit](docs/service-consistency.md). Correct inventory identity
  mismatches and include complete Signer/SSO/SSO OIDC prerequisite models.
  The current inventory has 127 services, 8,207 modeled operations, 2,290
  registered/partial operations and no registrations outside the selection.
- [x] Replace CloudFormation public ownership-marker authority with exact typed
  private incarnation claims, scoped creation receipts and current native IAM.
  Ordinary native/Cloud Control edits preserve claims; same-name recreations and
  copied customer tags do not adopt them. SQL schemas through 402 persist the
  new owner families without promoting legacy public tags.
  [Private creation-claim boundaries](docs/sqlite-state.md#private-cloudformation-creation-claims).
- [x] Add opt-in native gateway DNS, ordered explicit upstream forwarding with
  actual-peer ACL/loop protection, and managed Lambda/ECS/CodeBuild resolver
  selection without bypassing EC2 DHCP or packet policy. Owner-backed Lambda,
  API Gateway, SQS and OpenSearch hostnames preserve public/compute origins.
- [x] Add persistent scoped development CA issuance/public export, Engine-delivered
  customer trust, loopback diagnostics and host/container/Desktop/remote recipes.
  Real Lambda/ECS/CodeBuild commands resolve the gateway and publish signed,
  verified HTTPS SDK messages; customer CA overrides and EC2 DHCP/SG/NACL
  denial remain effective. CodeBuild credentials use its localhost proxy with
  independently verified HTTPS upstream trust, not disabled SDK verification.
  Standard AWS HTTPS routing is an isolated allowed-peer opt-in with unchanged
  signing bytes and current IAM; no global resolver/trust interception.
- [x] Add inclusive native SQL/document/Kafka/Valkey/MQ customer port pools with
  real socket reservations, explicit exhaustion and exact retained endpoint/data
  recovery outside changed pools. Actual Linux native protocol smokes cover all
  five families, including AMQP and OpenWire.
- [x] Add reversible explicit Linux/macOS host split DNS with durable ownership
  receipts and external-mutation preservation. Native Linux resolved 255 remote
  per-link lookup/restore/conflict cases pass; local automatic routing explicitly
  requires resolved 256+. macOS native behavior remains unexercised locally.
  See [networking boundaries and evidence](docs/networking.md).
- [x] Execute local Docker Lambda image deployment, retag isolation, publication,
  hot swap, SQLite reopen, accepted cold calls and actual native artifact cleanup.
  Real Python RIC/Kafka fixtures also verify LATEST checkpoints, batching windows,
  retry/bisect/age controls and SQS failure destinations on memory and SQLite;
  real FIFO partial-failure and cron/rate guest fixtures pass independently.
  These are local Linux observations, not AWS captures or Docker Desktop evidence.
  [Image lifetime and source-reference boundary](docs/lambda.md#container-image-deployments).
- [x] Cross-build the ordinary CLI for Darwin arm64 and amd64 without requiring
  Linux ECS cgroup setup for unrelated Lambda/native engines. The documented
  source-built endpoint recipe uses port 4567 and an explicit guest-reachable
  origin. Cross-compilation is not a macOS Docker runtime smoke.
- [x] Deploy a 67-resource application stack through the public endpoint on port 4567:
  CREATE_COMPLETE, UPDATE_COMPLETE, SQLite controller restart and DELETE_COMPLETE.
  Native SDK reads verify the owned resources and final absence. Real image and
  provided-runtime customer code exercises DynamoDB/GSI, Kafka/FIFO mappings,
  suffix-filtered S3 delivery, REST/HTTP proxy routes and asynchronous SQS failure
  delivery with zero retries. Reopen retains the original login/JWKS/refresh
  session and prior DynamoDB data. Actual HTTP integration deadlines return 504
  while accepted customer execution completes.
  This fixture establishes those local Linux paths, not hosted Google OAuth,
  public DNS, WebSocket message execution or macOS Docker behavior.
- [x] Record the first reported native macOS/Apple Silicon Docker Desktop run at
  `54c09a9`: 155-resource creation, real image/provided runtimes, DynamoDB/Kinesis,
  Cognito/JWKS and SQS/S3/rate delivery, image updates and clean teardown.
  [Desktop evidence](docs/runtime-containers.md#native-macos-controller-with-docker-desktop)
  is user-reported, not locally repeated platform execution; CORS readback and
  cron were not observed in that run.
- [x] Repair the Desktop report's B1–B8 compatibility boundaries: managed Lambda
  VPC execution permissions; exact Function/Mapping rejected-create recovery;
  Python 3.12 amd64 child-manifest pin; typed Cognito missing-SES errors; official
  Kinesis Streams endpoint name; native GetAZs/YAML; conditional lifecycle
  policies; generated-shape numeric parameter binding and numeric IpProtocol.
  Preserve resource failure events and shared-transaction IAM reads. Actual
  SQLite CLI/SDK and containerd Python RIC execution cover creation/update,
  rejected rollback, SES mailbox verification and policy changes across restart.
  Real managed-role Lambda/Kinesis endpoint/NAT packet cases pass on both stores.
- [x] Enable the existing native nested-stack handler in templates, with actual
  S3 template/child-output/queue update and exact deletion, plus memory/SQLite
  child failure and restart regressions. This does not implement arbitrary URLs
  or custom-resource callbacks.
- [x] Resolve the retained Kinesis native frame CRC mismatch in
  `TestKinesisEventStreamNativeFrames/settled-subscribe-split-parent-end`.
  Foreign-account reservation had rewritten the opaque zero-valued shard ID.
  Preserve hyphenated identifier boundaries and restore captured shard IDs;
  the original native CRCs validate without regeneration or decoder changes.
  Sanitizer regressions, actual publication CLI and full AWSAPI/Kinesis tests pass.
- [ ] Implement SSM/Secrets Manager dynamic references under current stack
  caller/execution-role authority, including version semantics and secret
  masking in retained events/intent. Keep rejecting them until real resolution
  and credential-safe persistence are implemented.
- [ ] Implement Cognito SOFTWARE_TOKEN_MFA enrollment, TOTP verification,
  challenge sessions, factor preferences and required/optional enforcement;
  accepting `EnabledMfas` without authentication behavior is not support.
- [ ] Execute Cognito LambdaConfig triggers through real Lambda runtimes with
  current invocation authority and documented event/response semantics; do not
  admit inert trigger metadata.
- [ ] Implement REST API Gateway BinaryMediaTypes with real content negotiation,
  binary/base64 Lambda proxy request/response handling and deployment persistence.
- [ ] Add an evidenced EC2 endpoint-service inventory independent of emulated
  providers, including known `bedrock-runtime` control-plane admission and
  `DescribeVpcEndpointServices` filtering/scope/pagination. Do not claim a
  Bedrock inference data plane. The current gap marker is in
  `internal/services/ec2/vpc_endpoints.go`.
- [x] Separate native probe accounts and private raw captures from published
  fixtures: explicit `--account` identity guards, valid distinct account aliases,
  recursive encoded/archive redaction and locally regenerated authenticated
  vectors. Preserve cross-account denials and opaque resource identifiers; local
  re-signing is not unchanged native cryptographic evidence.
- [x] Document source-built deployment of container/native engines, QEMU/KVM,
  k3d/EKS and managed Lambda guests, including dependency/image preparation,
  guest/worker import, reachable endpoints, TLS, readiness and retained-state
  shutdown. Built binaries and the local STS/S3/SQS SQLite restart path were
  exercised; this documentation update did not boot guests or start native engines.
- [ ] Resolve native subnet-route association replacement progress after
  delete-before-create retirement. Both `TestCloudFormationDeleteFirstReplacementRollback`
  and `TestCloudFormationRejectedExclusiveReplacementRestoresFreshNativeOwner`
  timed out on memory/SQLite; an actual SQLite CLI/public SDK smoke also stalled
  after the old association's `DELETE_COMPLETE`. The restoration result-read
  regression and affected package/static checks pass; they do not resolve this
  separate native replacement workflow failure.
- [ ] Resolve integration failures reproduced on the pre-anonymization snapshot:
  `TestCloudFormationKMSAliasStackDiscovery`, `TestCloudTrailKMSNativeReplay`,
  `TestServiceJobsSDKDrainAndRecovery`,
  `TestOrganizationAccountAndRoleRollbackTogetherSDK`,
  `TestOrganizationCreationEventsRollbackSDK`,
  `TestOrganizationAndServiceRoleRollbackTogetherSDK`, and intermittent
  `TestAutoScalingNativeControlsAcrossReopen` deletion visibility. Capture
  sanitization and deployment documentation do not establish a green full suite.
- [x] Correct Config resource-scoped IAM, Kinesis post-wait authority, Pipes
  acknowledgement recovery, AppConfig/Identity Center/SES continuation tokens,
  SSO Admin error status, EKS authenticator service time, ElastiCache disabled
  snapshot admission and Cloud Control recovered-handler error classification.
  Signed SDK, memory/SQLite, targeted race and real engine workflows establish
  these fixes, not whole-service completeness.
- [x] Run Lambda/ECS and borrowed engines behind explicit container dependencies
  with observed backend readiness, not in-process substitutes.
- [ ] Extend reusable native CloudTrail capture and local fixture replay
  across all implemented services, including EKS. Record verified cases
  separately from recorder wiring and operation registration.
- [x] Consolidate request-ID correlation, bounded collection and event comparison
  while preserving classification, request/response presence, identity/session
  context, failures and sensitive-field behavior.
- [x] Verify management read/write selection and data-event selectors separately;
  data-event evidence must include actual trail/S3 delivery, not LookupEvents.
  Retain unsupported or unverified categories explicitly; CloudTrail Lake stays
  excluded.
  The readiness-gated S3/SQS/Glue/Athena workflow captured all 32 native requests
  (11 data and 21 management); the actual CLI retained its records and real Trino
  result across SQLite restart. Selected fields, not exhaustive service parity,
  are documented in [CloudTrail evidence](docs/cloudtrail.md#native-capture-and-replay-practice).
- [x] Calibrate selected ECR/CodeBuild management audit projections against exact
  native request IDs; replay through signed SDKs on memory/SQLite and exercise
  actual embedded-server behavior. Preserve operation-specific resource/response
  presence and native masking rather than guessing from sensitivity traits.
  Successful CodeBuild start/terminal-stop audit responses are calibrated against
  native fixtures with an actual Docker/S3/CloudWatch workflow, retained build
  configuration, secret masking and UUID-only artifact namespaces. OAUTH runtime
  support remains open; this is not exhaustive build/audit parity.
- [x] Calibrate selected Logs management audit projections against native controls
  and retained subscription request IDs. Signed memory/SQLite replay covers
  resource/search-name distinctions, modeled versus semantic rejection,
  request privacy and federation issuers. Preserve the observed post-deletion
  visibility variation and unobserved request boundaries; this is not full Logs
  or subscription-audit parity. See [Logs evidence](docs/logs.md#native-management-audit).
- [x] Calibrate EKS catalog-pagination and absent-cluster management records
  against exact native request IDs. Generated-input fixture replay and actual
  signed executable before/after observations preserve query-number strings and
  omitted audit error messages. Other EKS audit projections remain unverified.
- [x] Build three isolated service workstreams alongside the CloudTrail work:
  SSM Parameter Store; RDS and RDS Data backed by real PostgreSQL/MySQL; and
  EventBridge Scheduler/Pipes using the existing clock, event and delivery owners.
  Each owner integrates generated APIs, typed memory/SQLite state, IAM,
  observability and actual SDK/application workflows before a verified merge.
  All three are integrated. Scheduler/Pipes passed the combined race-enabled
  executable workflow with real Lambda, SQS/Kinesis/DynamoDB Streams, current
  authority, partial failures and restart; schema 215→217 retained existing
  SSM/RDS/SQS state and legacy audit records. Service docs retain explicit gaps.
- [x] Defer CloudFormation until those three workstreams are integrated.
  This sequencing condition and the engine-backed service checkpoint are satisfied.
  CloudFormation now has retained JSON/YAML stack/change-set deployment, rollback,
  restart, exports/imports and explicit owner-backed resource handlers.
  Native-calibrated `NoEcho` stack-event projections preserve literal values,
  condition selection and historical masking across updates and restart.
  Native/executable evidence and bounded property support are recorded in
  [deployment behavior](docs/behavior-references.md#cloudformation-deployments).
  Whole-service completion remains open: StackSets, registry/custom resources,
  custom-resource callbacks, remote templates, broad transforms, drift, resource imports,
  stack policies/rollback alarms/notification controls and additional resources.
  EventBridge API Destination controls and authenticated HTTPS delivery are
  integrated. The combined executable upgraded schema 222→224, preserved
  existing IAM/SSM/Connection/Pipes/audit state, and deployed then updated a
  CloudFormation-owned HTTPS rule across restart. Native control evidence,
  consumer-owned retry hints and explicit delivery boundaries remain in
  [EventBridge](docs/eventbridge.md#api-destinations).
- [x] Implement engine-backed ElastiCache/MemoryDB with pinned real Valkey:
  generated controls, typed memory/SQLC state, current IAM, TLS/ACLs, native
  replication/slots, AOF reboot/restart, physical snapshot/copy/restore and
  measured native CloudWatch gauges. Signed official-SDK/native-client proof and
  exact-ID free AWS controls are retained in the [Valkey evidence](docs/behavior-references.md#elasticache-and-memorydb-native-valkey).
- [x] Integrate OpenSearch's pinned native single-node runtime, typed memory/SQLC
  lifecycle state, generated modern/legacy controls and signed/public data
  gateway. Actual document/index/mapping/query/bulk behavior, live IAM and
  resource policies, principal recreation, isolation, native configuration,
  controller/native restart and exact-owned deletion are exercised.
- [ ] OpenSearch `TODO: Comeback`: managed multi-node/capacity, VPC/EBS/KMS/TLS,
  fine-grained/internal-user security, snapshots, upgrades, packages, Dashboards,
  remaining control/admin/plugin operations, successful legacy response
  calibration and successful provision/update/tag audit calibration. Unsupported
  effects remain modeled errors. See [evidence and boundaries](docs/behavior-references.md#opensearch-engines-evidence-and-boundaries).
- [x] Add separate MSK `kafka` controls and real public Kafka brokers, native
  topics/partitions/groups, effective configuration/reboot, TLS/SCRAM and durable
  MSK/self-managed Kafka Pipes consumption. Preserve Kinesis's private engine
  contract. Replay 35 free native configuration/audit observations and signed
  executable workflows; see [MSK evidence](docs/behavior-references.md#msk-public-kafka-brokers).
- [ ] Complete MSK serverless, managed networking/storage/monitoring,
  IAM/client-mTLS data authentication, replication/multi-VPC and mutable fleet
  topology. Current unsupported effects are errors, not accepted inert fields.
- [ ] Continue EC2/VPC and related services while independent owners build
  Glue/Athena and ECR/CodeBuild in parallel. EKS follows the analytics path,
  then the remaining service roadmap. Build real EC2
  guest execution through a consumer-owned QEMU/KVM interface for firmware-booted
  HVM images, not a direct-kernel-only or container substitute. Share
  infrastructure and EC2-owned networking across compute consumers without a
  generic executor framework. See [EC2 priority and ownership](docs/ec2.md#next-service-priority).
- [ ] Build ECR and CodeBuild under one independent integration owner. Verify
  authenticated image push/pull and real build commands, logs and artifacts;
  reuse core IAM, storage, compute and observability interfaces. Merge only
  verified behavior, not registry/project CRUD or canned build success.
- [x] Boot a real Firecracker guest through its Unix-socket API, exercise
  pause/resume and disk retention across VMM replacement, and observe guest
  reboot exiting the VMM. Ordinary poweroff left this guest halted with VMM
  state `Running`; no general shutdown, AMI, networking or EC2 API parity is
  inferred. [The execution evidence](docs/ec2.md#exercised-guest-execution-boundary)
  records pinned upstream inputs and the concrete integration prerequisites.

- [x] Integrate [RDS and RDS Data](docs/rds.md) with generated official
  frontends, typed memory/SQLC state and real pinned PostgreSQL/MySQL engines.
  Signed executable workflows exercised native SQL/transactions, both instance
  and cluster snapshot/restore, password changes, IAM/secret denial, scope
  isolation, SQLite/controller restart, measured CloudWatch connections,
  EventBridge→SQS and selected CloudTrail Data→S3 delivery. Native calibration
  used four free owned parameter groups, not billable Aurora databases.
- [x] Apply and reset dynamic PostgreSQL/MySQL parameters on actual attached
  engines without interrupting held sessions; retain changes through restart.
- [ ] RDS compatibility boundaries remain: distributed Aurora/readers/failover,
  cloud storage/VPC enforcement, IAM database authentication, managed rotation,
  automated backups/PITR and
  native asynchronous cluster-group propagation. Exact `TODO: Comeback`
  ownership and evidence exclusions are recorded in [RDS boundaries](docs/rds.md).
- [ ] ElastiCache/MemoryDB boundaries remain: managed VPC/physical storage and
  customer KMS, distributed MemoryDB logging, multi-AZ/automatic failover,
  online resharding and replication-member changes, per-member reboot,
  serverless/global/multi-region controls, maintenance/automatic backups,
  IAM native authentication, SNS operational notifications and filtered native
  ACL introspection. Located `TODO: Comeback` owners and evidence exclusions
  remain in the [Valkey boundaries](docs/behavior-references.md#elasticache-and-memorydb-native-valkey).

## Next service priorities

Prioritize cross-service correctness, stale debt and inconsistent ownership before
another isolated service-depth expansion. The Auto Scaling rolling-refresh and
custom-termination guest workflows pass; their detailed backlog remains below.
The [2026-09-30 audit](docs/service-consistency.md) records all inspected owners,
rejected false positives and evidence boundaries. At that audit boundary,
production code retained 472 `TODO: Comeback` markers in 379 files; counts are
historical snapshots, not a conformance score.

- [x] Connect AppConfig to shared tagging discovery and native tag mutation
  authority without duplicating resource tags. Preserve captured nested-ARN
  filtering, distinct Resource Groups types, versioned extension identities,
  transactional membership and scope. Native captures cleaned all owned
  resources; memory/SQLite SDK race regressions and an actual executable
  restart verified owner reflection, current IAM and last-tag membership.
  [Evidence and remaining capture limits](docs/appconfig.md#shared-tag-discovery).

- [x] Implement Config resource tags through the typed memory/SQLite owner,
  atomic creation and current IAM; connect shared tagging and Resource Groups
  discovery without a second resource/tag store. Native captures establish
  update-tag omission, full tag listing and the corrected CloudTrail source.
  Eight signed SDK race workflows and an actual SQLite executable restart
  verify empty-tag membership, current authority, audit identity and deletion.
  [Evidence and native calibration limits](docs/config.md#resource-tags-and-shared-discovery).

- [x] Retain KMS alias-specific deployment ownership, recover exact-owned creates
  under current IAM, and reject mutations of same-name foreign replacements.
  Connect live aliases to Resource Groups stack queries without inventing tags.
  Schema-297 migration, memory/SQLite SDK race regressions and separate
  executable/handler process-restart smokes verify the boundaries.
  [Evidence and native calibration distinction](docs/resourcegroups.md#kms-aliases-in-stack-queries).

- [x] Implement `AWS::Lambda::Alias` through the existing Lambda owner, with
  private transactional ownership, weighted routing, real provisioned-capacity
  stabilization and Resource Groups stack-only discovery. Retain native
  deployment/runtime/cleanup evidence; verify SDK memory/SQLite, migration,
  current IAM, foreign replacement and actual controller-restart invocation.
  [Boundaries and calibration](docs/lambda.md#cloudformation-aliases) preserve
  missing CodeDeploy rollout orchestration.

- [x] Implement `AWS::Lambda::Version` with transactional scoped publication
  receipts, exact-owner recovery under current IAM, native-calibrated collision
  rejection, runtime/provisioned controls and current-owner stack discovery.
  Verify complete Function-Version-Alias deployment/replacement, numeric-pool
  consumption through aliases, pending referenced deletion and cleanup through
  SDK memory/SQLite race workflows and a real executable restart. Preserve
  [native capture failures and remaining calibration limits](docs/lambda.md#cloudformation-versions);
  schema 299 migration, rollback and retained publication recovery are covered.

- [x] Implement `AWS::Lambda::LayerVersion` through actual S3 archives and
  transactional scoped publication ownership. Verify native logical-ID naming,
  immutable replacement and retained function attachments; preserve the first
  capture's safety-check failure and exact-resource cleanup evidence. SDK
  memory/SQLite race workflows and an actual executable restart exercise
  layer-backed Function-Version-Alias imports, source-version pinning,
  replacement/retirement, current-owner stack discovery and cleanup. Schema 300
  migration, concurrent recovery, current IAM and state/event rollback are covered.
  [Calibration limits](docs/lambda.md#cloudformation-layer-versions) retain
  unmeasured native REFERENCE, cross-account/signing and private recovery behavior.

- [x] Implement `AWS::Lambda::LayerVersionPermission` through real layer policy
  grants and transactional statement-level ownership. Calibrate Ref/GetAtt Id,
  immutable replacement, retention and missing-resource deletion against native
  AWS, with exact-resource cleanup. Verify cross-account runtime imports, grant
  replacement, current IAM, same-ID foreign replacement and retained SQLite
  restart through signed SDK/race tests and an executable workflow. Schema 301
  migration and policy/receipt/event rollback preserve legacy ownership boundaries;
  recovery retains account-ID versus root-ARN `lambda:Principal` conditions.
  [Evidence and remaining calibration](docs/lambda.md#cloudformation-layer-permissions)
  distinguish local cross-account/private-recovery proof from native observations.

- [x] Implement `AWS::Lambda::ResourcePolicy` through the existing full-policy
  owner with atomic create admission/recovery, typed schema-302 ownership,
  full-document updates and qualifier replacement. Calibrate native initial
  conflicts, canonical `ResourceArn`, Ref and native-overwritten policy deletion;
  retain failed and successful captures with complete cleanup. Correct function
  and layer permission deletion to follow native same-Sid identity, not JSON
  equality or private create ownership; expose function permission `GetAtt Id`.
  Verify real cross-account invocation, explicit deny, policy replacement,
  current IAM, rollback, legacy migration and fresh-process SQLite recovery.
  [Evidence and calibration limits](docs/lambda.md#cloudformation-function-resource-policies)
  preserve the distinction between public native behavior and local recovery.

- [x] Connect CloudFormation Kinesis event-source mappings to the existing real
  stream consumer. Calibrate property removal, UUID/ARN outputs, alias retarget,
  same-source replacement conflicts and distinct-source replacement; retain
  failed and successful native captures with complete cleanup. Verify actual
  records through Python runtimes, filter-only updates/removal, current-role
  denial/recovery, checkpoint retention, Unix timestamp conversion, rollback
  and deletion on memory/SQLite under race and through a restarted executable.
  [Deployment evidence and remaining boundaries](docs/lambda.md#cloudformation-stream-mappings)
  retain other CloudFormation source families rather than claiming full mapping parity.

- [x] Connect CloudFormation DynamoDB stream mappings to the existing source owner.
  Retain native defaults/removal, alias retargeting, replacement conflicts,
  unsupported timestamp and deletion evidence with exact-owned cleanup. Correct
  the unused `ListStreams` preflight requirement against native no-grant,
  stream-scoped-grant and explicit-deny captures, preserving public API authority.
  Verify real old/new images, filtering, current-role denial/recovery, checkpoint
  retention, replacement rollback and deletion on memory/SQLite under race and
  through a restarted DynamoDB → Python → SQS executable application.
  [Evidence and remaining boundaries](docs/lambda.md#cloudformation-stream-mappings)
  distinguish native disabled-mapping admission from local actual delivery.

- [x] Calibrate CloudFormation encrypted-filter key and failure-destination
  transitions using exact-owned native resources. Preserve encryption on key
  omission, clear it with removed/empty criteria, and clear omitted/empty
  destination objects. Generate ARN string bounds from the registry and reject
  explicit empty strings during resource operations without mutating the mapping.
  Verify memory/SQLite SDK workflows under race, including current source/key
  authority, failure-destination switching/clearing and invalid-update rollback.
  The executable reproduced the old key-omission bug and verified real encrypted
  DynamoDB → Python → SQS delivery, disabled-key recovery and criteria/destination
  removal across a fresh SQLite controller restart.
  [Native capture, cleanup and runtime boundaries](docs/lambda.md#cloudformation-stream-mappings)
  distinguish the retained PendingDeletion KMS key from deleted resources.

- [x] Deploy CloudFormation self-managed Kafka mappings through existing Kafka,
  secrets, IAM and real Lambda owners. Calibrate source/group replacement,
  topic-update rollback, distinct public group plans, batch/window/filter/access
  removal and reintroduction, starting-position defaults and timestamp admission.
  Correct on-demand Kafka metrics admission and fractional-window reporting.
  Verify actual TLS/SCRAM Kafka → Python → SQS effects, current authority,
  qualified targets, rollback, source replacement and broker checkpoints across
  executable SQLite restart; retain native/local evidence and exact-owned cleanup.
  [Evidence and remaining source boundaries](docs/lambda.md#cloudformation-self-managed-kafka-mappings)
  distinguish native disabled control from local real delivery. Advanced Kafka
  owner options remain open.
- [x] Deploy CloudFormation MSK mappings through the existing Kafka source,
  current IAM and actual Lambda runtime. Retain native defaults, setting removal,
  qualified retargeting, distinct group planning/replacement, immutable topics
  and starting-position/timestamp replacement contracts. Verify real TLS/SCRAM
  broker → Python → SQS effects, source/secret authority recovery, rollback and
  broker checkpoints through retained SQLite restart. Keep native disabled-control
  evidence distinct from local delivery and unmeasured credential-removal behavior:
  [MSK deployment evidence](docs/lambda.md#cloudformation-msk-mappings).
- [x] Admit Kafka mappings without contacting their broker or requiring the topic
  to exist. Commit first native identity before delivery, preserve that fence
  across concurrent configuration updates, and reject stale workers. Verify
  late-topic delivery/restart and combined group/topic versus create-only
  replacement precedence; preserve failed-before and native/runtime evidence.
- [ ] Diagnose the separately observed native Kafka configuration-helper 404;
  final late-topic proof passed, but the earlier disappearance has no established
  cause. Keep [exact controller/cleanup evidence](testdata/integration/cloudformation_lambda_msk_late_topic_broker_failure.json).
- [x] Deploy CloudFormation DocumentDB mappings through the existing source,
  credentials, IAM and checkpoint owners. Calibrate namespace-update rejection
  versus deployment retention, FullDocument and credential omission, batch/window
  controls, qualified targets and create-before-delete rollback. Verify actual
  TLS/SCRAM Mongo-compatible changes, Python Lambda and SQS effects through signed
  Go SDK deployment and retained SQLite restart; preserve failed-before evidence
  and native/local engine distinctions in [deployment evidence](docs/lambda.md#cloudformation-documentdb-mappings).
- [x] Admit DocumentDB mappings before a database instance exists, preserving
  current authority and cluster identity independently of writer readiness.
  Verify late-writer delivery, checkpoint retention and recreated-source fencing;
  reject direct namespace updates and never round the initial 500ms window to zero.
- [ ] Extend DocumentDB deployment calibration to source-ARN replacement,
  successful position/timestamp replacement and omitted enablement. Existing
  disabled AWS captures do not establish native delivery or engine equivalence.
- [x] Deploy CloudFormation Amazon MQ mappings through existing broker, secret,
  IAM and acknowledgement owners. Calibrate both engines' queue immutability,
  batch/window/filter omission, credential reintroduction, qualified targets
  and rollback. Verify signed Go SDK deployment and real AMQP/JMS-to-Python-to-SQS
  effects, current authority, failed-invocation redelivery and retained restart.
  Preserve [native/local evidence and exact-owned cleanup](docs/lambda.md#cloudformation-amazon-mq-mappings).
- [x] Separate MQ admission from native queue/virtual-host connections. Verify
  late-source delivery and custom-host isolation, reject direct host updates and
  any ActiveMQ host parameter, retain explicit RabbitMQ root hosts in schema 304,
  and preserve credentials across omission/reintroduction and unrelated updates.
- [ ] Calibrate implicit RabbitMQ virtual-host output. The final bounded native
  control found its broker already deleted before mutation; explicit root/custom
  hosts are measured, but neither an implicit output shape nor old root-host
  request presence can be reconstructed from that evidence.

- [x] Implement native-calibrated CloudFormation EventBridge rule bus migration
  through the existing replacement/retirement lifecycle and EventBridge owner.
  Correct custom-bus Ref/physical IDs, expose RuleName, normalize equivalent
  bus names/ARNs with account scope, and migrate retained resource/step identities
  without rewriting historical events. Verify signed SDK memory/SQLite under
  race, target transfer, current-IAM and partial-effect rollback, foreign-rule
  preservation, old-executable state upgrade and actual routing after restart.
  Match native Conditional change-set reporting separately from execution-time
  identity decisions. Preserve ARN-addressable unexecuted plans after stack
  deletion, including restart and explicit plan deletion.
  [Native captures, cleanup and remaining boundaries](docs/behavior-references.md#cloudformation-rule-bus-migration)
  distinguish observed AWS behavior from private local ownership guards.

- [x] Classify the recorded `TODO: Comeback` markers and fix the three evidenced
  correctness defects: Lambda temporary-storage accounting, crashed runtime
  cleanup and ALB DNS names. The 2026-09-27 reconciliation accounts for 388
  remaining markers: 280 missing features and 108 fidelity details. This
  classification is not a claim that the implementation has no other bugs.
- [x] Integrate bounded Lambda provisioned runtime pools, recursion controls,
  Signer-backed code-signing enforcement, durable executions/checkpoints/history/
  callbacks and real EC2-backed capacity providers through canonical schemas265–275.
  Retain current IAM and shared service owners; [Lambda evidence](docs/lambda.md)
  distinguishes actual runtime effects from control admission and native parity.
- [ ] Complete and calibrate remaining Lambda managed-instance extensions/
  Telemetry, streaming/durable combinations, non-512-MB scratch, architecture/
  fleet behavior and manual runtime-version image authority. Existing extension
  and streaming implementation does not establish all managed combinations.
  Full physical race import timed out; production import and targeted
  concurrency checks remain separate evidence.
- [x] Deliver MSK event-source mappings through the existing real Kafka owner and
  Lambda runtime. Verify native record payloads, failed-batch offsets, restart,
  retention, topic replacement and current IAM/Secrets Manager/KMS authority;
  see [MSK mapping evidence and boundaries](docs/lambda.md#msk-event-source-mappings).
- [ ] Complete remaining MSK mapping options and native fleet differential
  coverage; the current AWS capture establishes admission only.
- [x] Add self-managed Kafka, Amazon MQ and DocumentDB Lambda sources with their
  real engines, current authority, retries and source-owned progress. Preserve
  native-admission-only bounds and the Mongo-compatible DocumentDB distinction.
- [ ] Complete remaining standalone Amazon MQ deployment/replication, security,
  operational integrations and broader configuration behavior. Broker/user
  lifecycle, direct protocol clients and retained control/data planes already
  have executable evidence; they are not whole-service parity. Keep every modeled
  operation and native-calibration gap visible without making MQ the default
  priority over shared correctness debt.
- [x] Add standalone MQ configuration revisions/tags, effective/pending ActiveMQ
  users and native reboot/maintenance effects in schema 283. Signed SDK plus
  ordinary JMS/AMQP clients verify actual ACL/password changes, retained message
  bytes through executable restart and exact native deletion. Readiness uses
  engine protocol negotiation rather than customer destination permissions.
- [x] Apply RabbitMQ's AWS zero/infinite consumer timeout through real advanced
  configuration; verify held AMQP deliveries, finite-timeout channel closure,
  default restoration, initial bootstrap and existing-broker container upgrade
  without losing credentials, messages or endpoints.
- [x] Retain MQ's four maintenance-window adjustment budget in schema 284; verify
  atomic concurrent admission, rollback/reopen, manual-reboot retention and
  successful scheduled native reboot resetting the budget with pending changes.
- [x] Calibrate MQ maintenance admission on an isolated native broker: unchanged
  requests preserve available budget but fail at exhaustion; manual reboot does
  not reset it. Correct and verify the executable; retain timed-out reset
  observation and completed exact-owned cleanup without claiming timing parity.
- [x] Expose the real ActiveMQ TLS web console with current/pending user access,
  native grant/revoke/delete/password enforcement, stable endpoints and
  journal-preserving old-container upgrade. Verify SDK lifecycle plus actual
  browser message viewing/sending and direct JMS consumption.
- [x] Apply ActiveMQ shared/individual/discarding dead-letter strategies through
  native configuration. Verify poison delivery, expired/nonpersistent handling,
  payload/original-destination retention, inactive pending policy across SQLite
  restart, policy replacement and retained DLQ journal across broker reboots.
- [x] Retain independent automatic configurations for new ActiveMQ brokers without
  an explicit revision. Commit creation atomically, preserve replay association,
  verify scoped SDK discovery and real reboot-applied ACLs across SQLite restart,
  and retain the configuration after broker deletion for explicit cleanup.
- [x] Deliver real ActiveMQ general/audit files to the existing CloudWatch Logs
  owner with caller-authorized groups, current MQ resource-policy authority and
  transactionally committed native cursors. Verify rollback, revocation/recovery,
  SQLite/controller restart, reboot-applied flags and real console/JMS payloads.
- [x] Exercise real ActiveMQ log rollover, seven-archive exhaustion and
  same-inode truncate/regrowth through native management actions. Verify ordered
  retained records, explicit prefix-loss reporting and recovery without replay.
- [x] Provision RabbitMQ's protected IAM service-linked role atomically with
  broker admission; reuse existing roles without creation permission and retain
  account-wide deletion dependencies through actual native removal. Verify
  signed denial/no-orphan behavior, role protection, SQLite restart and real
  broker cleanup; cover writable deletion-decision commit/rollback on both stores.
- [x] Deliver native RabbitMQ general logs through its current service-linked role
  and the existing transactional Logs owner; reject unsupported audit logging.
  Verify actual AMQP log bytes/timestamps, reboot-applied flags, SQLite cursor
  retention, no replay and deleted-group recovery through signed SDK controls.
  Current trust/policy denial and restoration are repository regressions, not
  claims of public API mutation of the protected role.
- [x] Apply RabbitMQ operator-policy editing restrictions and HTTP security-header
  controls through the real native management server. Verify signed immutable
  revisions, invalid-boolean rollback, pending/reboot application, false-to-true
  and omitted-default restoration, actual AMQP policy enforcement and retained
  policies/messages across SQLite/controller and native broker restart.
- [x] Correct RabbitMQ's omitted relaxed-quorum-redeclaration default to AWS's
  true value. Reproduce the old AMQP 406, then verify explicit strict/relaxed and
  omitted restoration through native declarations, pending SDK revisions,
  SQLite restart, unchanged queue type/durability and retained quorum messages.
- [x] Publish actual RabbitMQ queue/message/consumer gauges through CloudWatch:
  live classic/quorum counters, complete inventory reads, stale/deleted sample
  fencing and atomic metric batches. Verify signed queries, exact held/acked
  message states, unsupported-name exclusion, account/region isolation and
  retained history with new post-SQLite-restart observations.
- [x] Extend native RabbitMQ metrics with exchange/connection/channel inventories:
  include default exchanges across virtual hosts, use actual AMQP registries,
  reject unavailable counters and prove legitimate cold-start emptiness. Verify
  independent channel/connection closure, exchange deletion, exact SDK metric
  decreases, retained SQLite history and new post-restart native observations.
- [x] Publish ActiveMQ instantaneous broker and queue/topic gauges from actual
  local JMX through typed engine snapshots and existing transactional scheduling.
  Verify held JMS producers/consumers, persistent queue traffic, same-name
  queue/topic identity, decreases/zero transitions, signed CloudWatch dimensions
  and units, SQLite history/restart, isolation and exact-owned cleanup.
  Re-run the real RabbitMQ workflow after the snapshot cutover.
- [x] Publish ActiveMQ inactive durable-topic subscriber counts from complete JMX
  inventory with AWS's 2000-count ceiling. Verify real JMS disconnect, retained
  inactive state after controller reopen, same-identity reactivation and explicit
  unsubscribe through signed CloudWatch reads; preserve native durable consumer
  counts, retained history and account/region isolation.
- [x] Verify inactive durable-topic subscription and exact persistent topic
  payload retention across controller restart and actual native broker reboot.
  Observe a changed container start timestamp, fresh signed metric samples,
  message consumption after reactivation, unsubscribe and owned cleanup.
- [x] Calibrate MQ missing broker/configuration/revision and tag errors through
  read-only native requests. Preserve modeled ErrorAttribute through REST JSON;
  verify signed SDK errors on memory/SQLite and actual executable account/region
  isolation, owner configuration preservation and exact-owned deletion.
- [x] Calibrate MQ configuration revision pagination and numeric-ID boundaries
  using exact-owned native configurations without brokers. Preserve ascending
  append-visible continuation, empty terminal pages and modeled errors; verify
  signed SDK behavior on memory/SQLite and across actual controller restart.
  Retain broader XML-sanitization limits.
- [x] Share the native MQ omitted `MaxResults=20` default across page consumers;
  retain explicit limits and verify exact 20/1 configuration pages through
  memory/SQLite SDK calls, retained continuation and the executable.
- [x] Separate ActiveMQ public API release `5.18` from native runtime `5.18.7`;
  migrate retained broker/configuration labels without compatibility aliases.
  Verify modeled patch-label rejection and discovery through the SDK, plus
  prior/new executable restart retaining native container/volume identity and
  exact persistent JMS bytes; preserve native configuration-only calibration.
- [x] Generate ActiveMQ configuration membership from the retained official XSD;
  implement native-calibrated attribute/subtree/expression removal with modeled
  warnings, keeping unimplemented permitted settings explicit. Verify SDK
  revision retention and real native queue/ACL effects across reboot/restart;
  preserve primitive coercion, references and serialization gaps.
- [x] Apply ActiveMQ `schedulerSupport` through its real persistent engine;
  calibrate configuration admission and verify delayed/repeated JMS delivery
  across native reboot and controller restart, plus disabled scheduling and
  exact-owned cleanup. Keep native engine time separate from control-plane time.
- [x] Apply ActiveMQ `maxSchedulerRepeatAllowed` through retained configuration;
  calibrate native admission of limits two/zero and verify actual JMS producer
  rejection above the ceiling, exact allowed deliveries, enforcement across
  broker/controller restart, disabled-scheduler behavior and owned cleanup.
- [x] Calibrate MQ CreateBroker token replay and changed-password/console/tag/window/
  instance behavior, including replay after explicit mutations. Verify memory/
  SQLite isolation, real retained JMS bytes, unchanged active/pending credentials
  across restart, native reboot application and exact-owned cleanup. Use generated
  HTTP statuses, including CreateTags 204. Keep cross-name/remaining-field and
  post-deletion token semantics open rather than imposing a full-request hash.
- [x] Match native ActiveMQ engine spelling in broker descriptions and list
  summaries while preserving creation/catalog enums and internal runtime identity.
  Verify signed SDK discovery, retained restart and actual broker cleanup.
- [x] Apply ActiveMQ rejectDurableConsumers through native configuration/reboot;
  calibrate both boolean values and verify pending/effective admission, rejection
  of new/retained durable consumers, continued non-durable delivery, exact retained
  topic recovery after re-enabling, controller restart and owned cleanup.
- [x] Apply ActiveMQ allConsumersExclusiveByDefault through native destination
  policy. Calibrate both boolean values, then verify actual two-consumer sharing,
  exclusive ordered delivery, standby handoff, unmatched queues, pending/effective
  policy replacement, native reboot, controller restart and exact-owned cleanup.
- [x] Apply MQ sendFailIfNoSpace and sendFailIfNoSpaceAfterTimeout through
  native destination policies. Calibrate boolean and signed 64-bit timeout
  admission; verify actual persistent memory-pressure rejection, timed failure,
  exact payload/acknowledgement recovery in both delivery modes, unmatched queues,
  pending policy, native reboot, controller restart and owned cleanup.
- [x] Admit native MQ composite queue/topic forwarding. Capture both forwardOnly
  values; verify real two-queue/topic fanout, source delivery/suppression, exact
  persistent payloads and properties, pending revisions, queued copies across
  native reboot/controller restart, unchanged native identity and owned cleanup.
- [x] Implement filtered MQ queue/topic targets and sendWhenNotMatched precedence.
  Calibrate all flag combinations; verify native selectors, numeric comparisons,
  missing-property nonmatches, source fallback, retained filtered queue copies
  across reboot/restart, pending configuration and owned cleanup.
- [x] Implement custom MQ virtual-topic names, consumer queue prefixes/postfixes
  and selector awareness. Calibrate native admission and verify independent groups,
  shared group consumers, ordinary topic subscribers, mismatched names, filtered
  backlog, offline queue retention and policy changes across reboot/restart.
- [ ] Complete MQ virtual destination behavior: wildcard composite names,
  concurrent fanout, target-denial/resource-failure behavior, network-local routing,
  selector-cache persistence and replicated topology.
- [ ] Implement pending queue cursor configurations after calibrating native AWS
  backpressure semantics. AWS admits vmQueueCursor, but pinned upstream replaces
  destination SystemUsage with broker-wide usage; do not widen per-queue policies.
- [ ] Calibrate AWS ActiveMQ TotalMessageCount for offline durable-topic backlog:
  pinned upstream JMX excludes topic message counts even when the journal retains
  a deliverable persistent message. Do not infer an all-message total from it.
- [ ] Complete MQ deployment/replication, private attachments, managed encrypted
  storage, remaining metric families, engine rollouts, broader configuration semantics,
  remaining create-token conflict calibration and native maintenance edge semantics; preserve
  the complete inventory (24 partial operations and unimplemented Promote).
- [ ] Build GuardDuty next after MQ service-linked-role admission/protection:
  add its complete Smithy operation inventory, typed durable detector/finding
  owners, current IAM and usable application workflows; retain unsupported
  monitoring/protection dependencies explicitly rather than fabricating findings.
- [x] Generate GuardDuty's complete 102-operation Smithy contract and implement
  typed detector/sample-finding/filter/tag workflows through current IAM and
  memory/SQLC storage. Verify signed SDK samples, real EventBridge-to-SQS delivery,
  SQLite restart, scope isolation and protected-role deletion dependencies.
  These initial 20 operations remain partial; current support is generated in
  `docs/services.json`, not inferred from registration counts.
- [x] Add structured GuardDuty API rules for long-/short-term root credentials
  and CloudTrail stop/update/delete or associated bucket deletion. Commit typed
  observed findings with the source event, separate from samples; verify actual
  signed SDK activity, denial outcomes, EventBridge/SQS delivery, rollback,
  scope isolation, aggregation and SQLite restart without disabled-period replay.
- [x] Detect explicit S3 server-access logging disable requests through the same
  structured rules. Verify actual enabled configuration and denied disable
  produce no matching findings; successful disable identifies the bucket and caller.
- [x] Detect successful S3 bucket/account public-access-block disabling and
  deletion. Exclude enabled configurations and denied changes; verify partial
  disable, omitted account settings and actual affected targets through the SDK.
- [x] Detect IAM account password-policy update/delete attempts, including
  denials. Verify actual policy state, aggregation and latest audit errors through
  signed SDK calls without treating every update as proven policy weakening.
- [x] Enable GuardDuty S3 data-event protection through the transactional S3
  producer. Verify actual object reads, feature transitions, rejected-update
  rollback, no disabled-period replay and SQLite restart aggregation through the
  signed SDK executable; exclude unauthenticated requests from data-event rules.
- [x] Apply a local 90-day creation cap to GuardDuty findings using shared service
  time, pre-sweep API visibility and transactional expiry. Verify archived and
  suppressed findings, publication cutoff, stale jobs, SQLite restart and SDK
  Get/List/Statistics boundaries.
- [x] Add GuardDuty's ten legacy IPSet/ThreatIntelSet operations with typed
  memory/SQLite snapshots, real S3 ingestion, current caller/service-role IAM,
  owner checks, six formats, quotas, tags and fenced recovery. Verify native
  lifecycle fixtures and signed executable workflows through restart and cleanup.
- [x] Apply trusted-IP precedence and custom malicious-IP reconnaissance to
  actual API-event observations; retain threat-list evidence independently of
  mutable lists. Verify immutable ingestion, explicit reactivation and deletion
  through signed SDK requests with injected connection addresses.
- [x] Group GuardDuty finding-type statistics by the projected type for both
  observed detections and samples. Verify mixed-source counts, type filtering
  and signed SDK root/password-policy activity.
- [x] Implement GuardDuty publishing destination CRUD/tags, native-calibrated
  admission/token replay, typed memory/SQLite outboxes and actual SSE-KMS S3
  finding delivery. Verify signed SDK payload reads, archive exclusion, current
  policy denial/recovery, stale jobs and retained cadence across restart.
- [ ] Calibrate native GuardDuty S3 finding payloads/batching, object naming,
  export and failure/retry timing, concurrent-replacement errors, and
  explicit-prefix caller permissions (the caller-denial subcase is completed below). Native 120.56/600.907-second captures
  retained permission markers but no finding object; do not treat that as parity.
- [x] Calibrate GuardDuty explicit-prefix caller denial using a short-lived
  federated session denied S3/KMS: root destination succeeds, prefix create/update
  returns BadRequestException/400. Correct leaked S3 AccessDenied/403; verify
  SDK grant/revocation, list-only denial, retained state and native/local cleanup.
- [ ] Calibrate GuardDuty's native retention timestamp anchor and refreshed-finding
  expiry. AWS documents the maximum period, not whether aggregation resets it;
  keep the local creation-based cap explicit until native evidence resolves this.
- [x] Preserve every upstream GuardDuty finding in a versioned, provenance-pinned
  [204-type catalog](docs/guardduty-findings.json) and map source dependencies.
  Declaration scans are not behavioral coverage.
- [x] Extend custom threat matches to IAM unauthorized access and documented S3
  discovery/access operations, retaining real event bucket ARNs and threat-list
  names through SQLite restart. Verify signed SDK activity with an injected
  public transport peer, actual S3 ingestion and scoped predicate regressions.
- [x] Detect anonymous/authenticated public bucket ACL grants from actual admitted
  S3 state in the source transaction. Verify canned/header/XML inputs, denied and
  private exclusions, atomic rollback, distinct findings and SQLite restart
  through the signed SDK and executable.
- [x] Connect bounded anonymous GuardDuty bucket-policy grant evidence through the
  S3 owner and shared IAM solver, with valid nonempty 1024-byte object-key bounds.
  Verify deny coverage, transaction rollback, actual unsigned object reads,
  IAM-denied/private exclusions and signed finding retention across SQLite restart.
- [x] Extend anonymous policy proofs to literal `aws:SecureTransport` conditions
  through the shared IAM interpreter; preserve HTTP/HTTPS action/resource
  correlation and verify actual unsigned HTTP/HTTPS reads, matching/union deny
  exclusions, signed finding counts and SQLite restart across both listeners.
- [x] Extend anonymous policy proofs to literal `aws:PrincipalAccount` and
  `aws:PrincipalIsAWSService` conditions with documented anonymous/absent context;
  verify Bool/BoolIfExists/Null semantics, actual unsigned reads, signed finding
  counts and SQLite restart without borrowing the policy writer's identity.
- [ ] Complete GuardDuty bucket-policy reasoning for conditions, variables,
  additional anonymous-capable operations and authenticated audiences. The bounded
  proof does not implement AWS's Zelkova-based policy reasoning. Calibrate native
  public-grant event eligibility and grouping.
- [x] Connect native EKS audit admission to the transactional journal and GuardDuty
  independently of CloudWatch logging, with typed metadata, source-scope fencing,
  atomic findings/publication intent and durable audit-ID/stage deduplication.
- [x] Verify system-pod execution and bounded anonymous Kubernetes access through
  actual native requests, Go SDK finding reads and SQLite/controller restart.
  The race-instrumented workflow also verifies feature/detector gates without
  replay, non-system exec exclusion, disabled CloudWatch logging, scoped anonymous
  RBAC revocation, authentication restoration and exact-owned cleanup.
- [x] Verify anonymous-access grant detection from admitted native RoleBinding and
  ClusterRoleBinding responses, with ordered subjects, typed durable role
  references, denied/dry-run negatives, generated names and signed SDK restart
  evidence. Do not infer grants from proposed requests or binding names.
- [x] Reconcile changed native EKS audit policy on retained control planes, with
  applied-policy hashing, ownership checks and no restart for unchanged policy.
  Verify genuine metadata-only upgrade, unchanged server/pod identities and SDK
  finding continuity through the race-instrumented executable.
- [x] Retain effective native DeleteOptions body/query precedence in typed journal
  columns and finding evidence. Verify actual dry-run object survival, body-over-query
  deletion, SQLite restart and signed Go SDK projection.
- [ ] Calibrate native GuardDuty dry-run eligibility. Successful anonymous API
  access does not establish object deletion or an undocumented exclusion rule.
- [x] Match native EKS audit origins against actual S3-backed custom threat lists
  for credential reads, discovery and deletion APIs, preserving denied outcomes,
  trusted precedence and ordered evidence. Verify real k3d requests, signed Go
  SDK reads, deactivation/reactivation, rollback, scope isolation, durable dedup
  and SQLite restart; retain forwarded-origin limits and exact-owned cleanup.
- [ ] Extend EKS audit detection with genuine object/policy and threat telemetry;
  metadata predicates do not establish workload privilege or RBAC privilege analysis,
  private anomaly models or complete EKS Protection.
- [ ] Implement all 204 catalogued GuardDuty finding types with real telemetry
  and behavioral evidence: remaining API rules, DNS, VPC flow, EKS audit,
  Lambda network, runtime, EBS/Backup/S3 malware, RDS login, AI and attack
  sequences. Do not substitute samples, declaration counts or private-model
  parity claims for detection. See the source-owner map in docs/guardduty.md.
- [ ] Extend genuine GuardDuty detection to remaining API conditions and
  producers. Obtain actual DNS/traffic telemetry for network detections;
  foundational DNS/flow settings do not establish monitoring. Do not substitute
  samples for observations or claim reproduction of AWS's private anomaly models.
- [ ] Complete GuardDuty optional protections, organization/member workflows,
  entity sets, destinations, malware plans, investigations/custom rules,
  retention, missing typed criteria and native event calibration. Preserve
  [GuardDuty evidence and limits](docs/guardduty.md), including the exact-owned
  native linked role whose deletion returned terminal AWS internal errors.
- [ ] Complete Kafka provisioned polling/schema registries/finite failure handling
  and changed-VPC placement, MQ provisioned polling/expanded transactional
  concurrency, private MQ/DocumentDB attachments and other unsupported source
  options. Signer cross-account grants, non-Lambda platforms and SignPayload
  also remain open; no opaque success substitutes for these owners.
- [ ] Resolve remaining Lambda deleted-async-target contracts: whole-function
  deletion after handler failure, destination-only long-window behavior,
  retry-enabled deleted-alias legacy DLQs and exact native queue/configuration
  propagation timing. Calibrated cases are tracked separately below.
- [x] Recover exact-owned Lambda Docker resources after controller crashes and
  use independently quota-limited disk-backed `/tmp`. Native AWS capacity
  calibration and real Docker fill/reset/crash/handoff proof are recorded in
  [Lambda runtime evidence](docs/lambda.md#temporary-storage-and-crash-recovery).
- [x] Verify EKS `aws-auth` migration, wildcard namespace policies and authorized
  native Kubernetes impersonation through the actual executable, including
  current identity, revocation and controller restart.
- [x] Separate the native EKS control server from worker capacity. Exercise a
  real 1.32→1.33 control-plane upgrade without changing the worker version,
  node/pod identity, container ID or restart count. Verify real CoreDNS lookup,
  version rollout, failed-rollout restoration and removal; exercise Fargate
  selector isolation, current role trust, restart and native worker retirement.
- [ ] Deepen EKS managed node groups using Auto Scaling/launch templates,
  managed-worker upgrades, Pod Identity/EKS Auth credentials, additional add-ons
  and native Fargate conformance. Establish direct lifecycle-event payloads
  without fabricating a contract from event names.
- [x] Repair actual managed-worker transport: advertise the reachable native
  supervisor endpoint, complete inner VXLAN checksums before host NAT, and admit
  exact-peer kubelet HTTPS without bypassing AWS packet policy. Verify fresh
  cluster creation, retained-guest recovery and security-group deny/restore
  convergence with real workload traffic; full rollout depth remains above.
- [x] Complete a fresh real managed-worker 1.32→1.33 update through `Successful`,
  keeping the workload unchanged during the separate control-plane upgrade and
  serving real HTTP after EC2/node/pod replacement; remove its owned resources.
- [x] Replace the whole-update bootstrap timer with phase-owned capacity,
  per-worker bootstrap and eviction deadlines. The corrected real DEFAULT
  multi-batch update completed after 30 minutes, including a PDB-blocked
  controller restart and capacity restoration; prior failed updates stay failed.
- [x] Verify native DEFAULT/MINIMAL multi-batch availability, PDB rejection,
  reservation recovery and real forced-drain behavior. Finish the same MINIMAL
  update after correcting the probe's completed-termination count; preserve the
  failed observation and remove all owned managed-worker resources.
- [x] Stop DEFAULT node-group scale-down when an external autoscaler raises the
  live ASG target. Persist the phase's ASG scale-up counter before reductions and
  condition each reduction on that counter. Real QEMU/Kubernetes proof preserved
  an external desired/max increase from 4/5 to 5/6 across completion and another
  controller restart, with working workload HTTP and complete owned cleanup.
- [ ] Implement Fargate OS-patch eviction and scheduled termination through its
  actual worker/PDB owner and service time. The primary patching guide supplies
  this event's payload and retry semantics; direct add-on event payloads remain
  unestablished despite five owned captures (including `CREATE_FAILED`) and
  native schema-catalog queries.
- [x] Remove unsupported Pod Identity association condition keys; verify real IAM
  denies grants depending on them while documented tag conditions still work.
- [x] Verify official-agent Pod Identity authorization through real pod tokens and
  AWS CLI requests: six request tags, source/target TagSession, current policy
  and identity revocation, session intersection, and refresh/admission during
  cluster `UPDATING`. Roll back rejected target exchanges without leaked
  credentials or successful issuance history; retain the actual STS denial.
- [x] Supply EKS Auth's documented CloudTrail identity through model correction
  and regeneration. Verify actual source-filtered history, EventBridge-to-SQS
  delivery and the trail's S3 record at its owned service-time deadline.
- [x] Enforce default Fargate profile and label-pair quotas atomically, including
  competing final-slot requests and idempotent replay at capacity.
- [ ] Apply approved Service Quotas increases to EKS Fargate profile, selector
  and label-pair admission limits; currently enforce the documented AWS defaults.
- [x] Accept EKS `logging.clusterLogging` on create/update and deliver all five
  native control-plane categories to `/aws/eks/<cluster>/cluster`. Use the real
  k3s audit webhook and IAM authenticator, retain original source events and
  acknowledge the spool only after CloudWatch delivery. Exercise actual logging
  disable/re-enable and replay an observed out-of-order native audit frame.
  Actual `kubectl` audit records contain the mapped IAM identity.
- [x] Scope CoreDNS readiness to the observed Deployment and current ReplicaSet.
  Preserve the native stale-pod rollback failure, verify corrected restoration
  and unchanged failed history, then complete the retained workflow and cleanup.
- [x] Build [Route 53](docs/route53.md) with real UDP/TCP DNS and [ACM](docs/acm.md)
  validation through that owner; exercise actual ALB TLS, renewal, current-use
  protection and SQLite restart.
- [ ] Complete Route 53 private VPC/DNSSEC/health and remaining routing/control
  families, and ACM public-trust/CAA/CT/OCSP, email/private-CA and remaining
  certificate controls. Local CA certificates do not imply AWS public trust.
- [x] Build typed RAM sharing for advanced SSM parameters, EC2 subnets and
  CodeBuild projects with current IAM/Organizations authority, permissions,
  invitations and memory/SQLite state. Verify real shared-subnet guest traffic,
  fixture-driven parameter reads/revocation/restart, and RCP-constrained STS
  session tags with retained rejection history.
- [ ] Complete RCP action/context and native propagation conformance for every
  AWS-supported service. The current 62-namespace primary-backed catalog now
  governs implemented resource owners, including S3 and Secrets Manager; new
  resource owners must supply their actual authorization context to that engine.
- [x] Generate CloudFormation property contracts from the pinned official regional
  public registry archive, retaining the original twenty native `DescribeType`
  captures separately. Prove unmodified CDK bootstrap/deploy/update/replacement/
  rollback/destroy, real owner effects and SQLite restart. Cloud Control reuses
  registered authoritative resource owners for asynchronous mutations and reads;
  registry schema presence is not implementation evidence.
- [ ] Complete remaining CloudFormation/Cloud Control resource and operation
  semantics, existing-owner automatic import and durable rollback. Prove SAM
  serverless deployments (Lambda, API Gateway, DynamoDB, SQS and IAM), complete
  teardown, and real Terraform AWS provider apply/destroy including
  list/describe, pagination and tag reads. Preserve the explicit
  [deployment boundaries](docs/behavior-references.md#cloudformation-deployments).
- [ ] Finish the remaining depth in EC2, RDS, CloudFormation, API Gateway and
  API Gateway v2, ECS, CloudWatch Logs, Cognito user pools, SSM, SNS, S3 Control,
  MSK, Auto Scaling, ELBv2, ElastiCache, S3, DynamoDB, CloudTrail (not Lake),
  RDS Data, OpenSearch, Elasticsearch, SES v2 and remaining RAM resource families.
- [x] Build [DocumentDB](docs/documentdb.md) using actual TLS/SCRAM MongoDB
  compatibility engines, documents/change streams, independent snapshots,
  current IAM/secret authority and retained lifecycle. Ordinary RDS Query
  requests route by engine/current owner and union both owners' discovery.
- [ ] Complete DocumentDB's managed network/readers/failover/storage behavior,
  AWS-specific change-stream controls/retention and remaining engine/control
  semantics. MongoDB compatibility is not the AWS DocumentDB engine.
- [x] Build [AWS Config](docs/config.md) with transactional S3/SQS observation,
  retained history, S3/SNS delivery, managed REQUIRED_TAGS and actual Lambda
  custom-rule callbacks. Verify current authority, aggregation and restart.
- [ ] Complete Config resource families/relationships and asynchronous producers,
  recorder variants, remaining rules, conformance/remediation, organization
  controls, advanced queries and native delivery/propagation conformance.
- [x] Build [Identity Store](docs/identity-store.md), [Cognito Identity](docs/cognito-identity.md)
  and [Identity Center](docs/identity-center.md) through actual Cognito credentials
  and unmodified AWS CLI device-code SSO login. Current IAM/Organizations authority,
  membership/policy revocation, reserved-role ownership and SQLite restart apply
  to usable account credentials, not metadata-only assignments.
- [ ] Complete SSO CreateTokenWithIAM/apps/ABAC/trusted issuers/customer KMS,
  external identity/MFA/rich SCIM, Cognito classic/developer/external-provider paths
  and remaining native audit, propagation and authorization conformance.
- [x] Implement public-client S256 PKCE through retained one-use authorization
  codes, current Cognito/directory authority and the existing portal/STS owner.
  Unmodified AWS CLI default PKCE succeeds through actual Chromium and its
  loopback receiver; signed owner/member S3 writes, restart, policy/membership
  revocation, logout and credential expiry are verified. Browser CSP permits only
  self plus the validated registered callback origin.
- [x] Apply verified Cognito user-pool claims through durable per-provider
  principal-tag mappings to enhanced STS sessions. Native map semantics, signed
  Go SDK memory/SQLite regressions and actual S3 PrincipalTag authorization,
  TagSession denial, remapping/reset/revocation and process restart are verified.
  Existing issued sessions retain their admitted tags; classic/developer/external
  provider flows remain open.
- [x] Build [AppSync](docs/appsync.md) with actual GraphQL/APPSYNC_JS execution,
  DynamoDB/Lambda/HTTP/PostgreSQL effects, live subscriptions, API-key/IAM/
  Cognito/OIDC authorization and restart. Verify unmodified gql client requests
  and current-role denial without a native write.
- [ ] Complete AppSync VTL/AWS JavaScript utility compatibility, remaining source/
  auth/subscription controls, batching/caching/merged/private/custom-domain APIs,
  quotas, observability and native execution conformance.
- [x] Verify the combined schema 244→255 upgrade retains S3/SQS/IAM state and
  Cloud Control→S3/SQS→Config history, current-role denial, managed evaluation
  and gzip delivery across actual process restart. Retain observed
  [combined executable evidence](testdata/integration/service255_executable.json).
- [x] Build [Resource Groups](docs/resourcegroups.md) queries over current typed
  owners, native-calibrated validation, current IAM, CloudFormation incarnation
  fences, transactional audit and retained memory/SQLite state.
- [x] Build AppRegistry application/attribute/configuration owners, managed
  legacy/modern groups, current S3/SQS/SSM/CloudFormation application tags and
  grouping outcomes. Retain tag-sync work, current delegated IAM and lifecycle
  EventBridge delivery across executable restart; never use a second ARN catalog.
- [ ] Complete native existing-customer AppRegistry/tag-sync/GLE calibration,
  AppRegistry legacy `SyncResource` system-tag effects, remaining application
  resource owners and Resource Groups specialty configuration using actual EC2
  capacity/host, License Manager and Network Firewall effects; finish absent
  typed snapshots and noncommercial global-region calibration.
- [x] Build [AppConfig/AppConfig Data](docs/appconfig.md) source retrieval,
  versioned bytes, real Lambda validation/extensions, deployment/rollback,
  durable polling and experiments consumed by the unmodified official Agent.
- [x] Build AppConfig's real [CodePipeline artifact owner](docs/codepipeline.md)
  using versioned S3 sources, actual CodeBuild containers, retained execution
  history and current IAM/KMS rather than synthetic source artifacts.
  The assembled executable also verifies forwarded-only artifact access under
  current IAM, real build output, restart and cleanup; native captures retain the
  exact AppConfig `CalledVia` identity rather than assuming a service DNS name.
- [x] Implement native-calibrated CodePipeline `ListActionExecutions` `All`/`Latest`
  history selection, scoped pagination and selector intersection; verify signed
  SDK and executable results across retry and SQLite reopen. Cross-range token
  misuse retains a documented rejection-code divergence.
- [x] Deliver CodePipeline manual approvals through real SNS/SQS with current IAM,
  native payloads and failure projections, durable publication completion,
  explicit retry recovery and verified pending-approval restart. Preserve the
  documented at-least-once crash window. Native captures, signed SDK requests and
  the executable verify topic configuration failures, real cross-account delivery
  and current topic-grant revocation.
  Verify populated schema-278→279 migration, stop-and-wait publication completion,
  and atomic admission of parallel actions before synchronous provider failures.
- [x] Implement pipeline-level variable declarations/defaults and supplied values,
  binding them once per execution and retaining real provider substitutions
  through retries, definition changes and SQLite reopen. Native captures establish
  required-value failures and token-only replay precedence; signed SDK scenarios,
  real CodeBuild/AppConfig consumption and populated schema-279→280 upgrade pass.
- [x] Implement S3 source-change polling through current IAM and the shared
  deterministic scheduler, retaining source revisions and update/delete fences
  rather than adding wall-clock polling loops. Native captures establish version
  detection, independent source triggers and failure projections; signed SDK and
  executable artifact consumption verify cursor recovery across restart.
- [ ] Calibrate native polling reactivation after automatic inactivity disable;
  preserve `pollingDisabledAt` rather than inventing reset behavior.
- [x] Deploy CodePipeline artifacts to real S3 objects, including raw ZIP bytes,
  extraction, cache/ACL/KMS configuration and current-IAM failure/retry. Native
  captures establish deferred configuration errors and partial-write ZIP member
  semantics; signed SDK and executable workflows retain admitted bytes through
  source replacement and restart. All owned native/local resources are cleaned.
- [ ] Calibrate remaining S3 deploy media types, encrypted-ZIP diagnostics and
  broader provider failure precedence; retain explicit local archive limits.
- [x] Invoke real Lambda runtimes from CodePipeline with retained callback jobs,
  continuation, current IAM and scoped artifact credentials. Native captures
  establish callback replay and abandoned/deleted-job fencing. Memory/SQLite
  signed SDK scenarios and the executable transform actual admitted ZIP bytes
  into deployed output across restart; ordinary function return stays pending.
- [ ] Calibrate the full Lambda artifact-credential action matrix, timeout and
  output-variable boundaries and remaining callback rejection precedence.
- [x] Execute manual CodePipeline `RollbackStage` from retained target artifacts
  and variables, with independent history, current IAM, transactional stage
  reservation and SQLite recovery. Native captures and real S3 deployment prove
  selected-stage-only rollback after original source-version deletion; downstream
  bytes remain unchanged. Automatic stage conditions and rollback rules remain open.
- [ ] Complete CodePipeline's remaining operation owners, provider families,
  source triggers, cross-region/account artifacts, automatic stage conditions/rollback,
  worker/webhook protocols and remaining provider-specific histories; preserve all generated
  operations in the inventory.
- [ ] Calibrate AppConfig CodePipeline artifact forwarding in the remaining
  regions/partitions. `us-east-1`, `us-west-2` and `eu-west-1` have distinct captured identities;
  unknown identities must remain unsupported rather than borrowing another region.
- [x] Complete AppConfig's native signed encryption-context interoperability:
  real P-384 signing context, committing envelopes, current KMS policy evaluation,
  official Encryption SDK interoperability and retained SQLite recovery.
- [ ] Complete actual Agent Uplink/VendedMetrics transport. Do not substitute
  polling counts or synthetic source artifacts.
- [x] Build [SES v1 through the existing SES domain](docs/cognito.md#classic-ses-and-shared-sending-authority):
  generated Query frontend, shared identities/verification/sending policies,
  templates/configuration and actual simple/raw/template/bulk MIME. Native
  captures correct IAM API-version values to `1`/`2`; SDK/CLI/Cognito workflows
  preserve authority, envelopes, state and bytes through restart and exact cleanup.
  All 71 operations remain inventoried (28 partial, 43 unimplemented), not complete.
  Actual schema259→260 upgrade and a second restart retain verified identities,
  shared policy/configuration/templates and unchanged MIME. Final service races,
  generated checks and integrated Query/REST CLI consumption pass; delivery
  statistics remain explicitly unsupported rather than counting capture as delivery.
- [ ] Complete classic receipt/filter execution, custom verification templates,
  DNS/DKIM and MAIL FROM, actual feedback/event/tracking/reputation consumers,
  enforced quotas/statistics, broader delegated identity controls and remaining
  native successful-send/audit conformance. SMTP remains explicitly deferred.
- [x] Verify schema255→259 retains S3/SQS/SSM/IAM state, then drives live
  Resource Groups queries and AppConfig consumption with current-role denial,
  immutable admitted bytes, retained polling/cursors and real Agent targeting.
  Nine controller exits and the Agent exit are zero; exact-owned cleanup is
  recorded in [combined executable evidence](testdata/integration/service259_executable.json).
- [x] Share typed local-controller lifecycle in the Cloud Control, Config,
  AppSync and official CDK executable probes. Verify real data-plane workflows,
  HTTPS, restart, eight clean controller exits and rejected-startup cleanup.
  AppSync now waits for the RDS writer and cluster after reopen instead of
  treating gateway health as native database readiness.
- [x] Cut MSK/Valkey and inherited Kafka/Lambda/incarnation workflows over to
  that same process owner. Real broker offsets, policy/secret revocation,
  native bytes, retries, TLS/ACL/snapshots and restart remain exercised; eleven
  controller exits are zero and exact-owned native cleanup completes.
- [x] Reuse the same owner for RDS, its control/parameter consumers, DocumentDB
  and CloudFormation. Five executable workflows preserve native SQL/BSON,
  deployment effects, restart and exact cleanup; nine normal exits are zero.
  An actual stopped CLI exercises opt-in forced cleanup: exit -9 fails the
  probe, then SQLite reopen retains the committed SQS message.
- [x] Consolidate the remaining Analytics, ALB scaling, Scheduler/Pipes,
  EventBridge API destination, Resource Tagging and SES/Cognito controller
  lifecycles. Six actual workflows pass with fifteen zero controller exits,
  retained native effects and exact-owned cleanup. The ALB raw-header probe now
  uses the same explicit DNS resolver as its HTTP client; actual HTTP 408 and
  alarm-driven ECS scale-out/in pass without host resolver changes. Shared
  ownership preserves explicit crash/forced-shutdown contracts; the existing
  typed native CLI transport remains authoritative for AWS captures.
- [ ] Commit verified working-tree slices at coherent boundaries, preserving
  unrelated user changes and recording only exercised conformance evidence.

## Behavioral breadth

The selected services' modeled operations are a target inventory, not behavioral coverage.
Generated unsupported dispatch contributes no implemented resource behavior.
Continue building real Go-native service workflows; do not start a generic CRUD
or compatibility-provider framework merely to increase operation counts.
Reuse existing typed storage, IAM, event and scheduling owners; extract further
shared mechanics only for demonstrated production consumers. Generate facts
supported by authoritative models, not invented AWS semantics.
See [architecture](docs/architecture.md).

## Foundation and identity

- [x] Runnable HTTP endpoint and embeddable isolated instances.
- [x] AWS Query and JSON 1.0/1.1 transport, typed errors, request IDs and body limits.
- [x] Generated response types and one encoder for every implemented IAM operation,
  including policy versions, inline policies, attachments and boundaries. Remove
  hand-written XML response models and duplicate response-selection/decoding helpers.
- [x] One generated IAM request-validation boundary for standalone and gateway
  requests; typed user/group/membership inputs and name-based identity lookups.
  Native AWS name/path captures replay through both endpoints, including rejected
  updates preserving state. Correct the upstream path pattern through generation.
- [x] Generated managed-policy/version, inline-policy, attachment and boundary
  inputs; shared domain logic uses names and ARNs instead of Query maps. Native
  captures fix inline-name replacement/deletion, default entity usage filtering
  and absent-boundary errors. SQLite/SQS replay verifies current user/group/role
  permissions after differently cased policy writes, reopening and deletion.
- [x] Complete IAM's generated input migration, including authorization resource
  names/ARNs and creation paths. Remove Query arguments from all handlers, the
  modeled-field filter and repeated gateway Query parsing. Native resource-scoped
  replay retains stored paths, key ownership and denial after user path changes.
- [x] Complete Organizations' generated input/output migration; generated
  contracts alone do not establish semantic completion.
- [x] Generated role/access-key/resource-tag input consumers; one tag merge/removal
  implementation preserves resource case rules and atomic quotas. Native replay
  covers role description characters, omitted fields, duration errors, rejected
  access-key statuses and empty federation tagging. Signed SDK tests retain
  implicit credential ownership and isolate access-key/MFA continuation markers.
- [x] Generated IAM pagination accessors and typed selection binding across the
  shared paginator. Delete Query reconstruction and duplicate limit parsing;
  preserve report defaults/filter rules, implicit access-key/MFA ownership and
  canonical instance-profile names. Native SDK replay fixes boolean-equivalent
  continuation and covers page-size errors, size changes and ignored fields.
  Account-identity password preparation also consumes generated inputs.
- [x] Resolve the AWS resource-account condition for commercial role-template
  reads, including the dependent permission inside AcquireRole. Native replay
  verifies all five definitions, session restrictions, creation/reuse and
  authorization before missing-version lookup; noncommercial conformance remains open.
- [x] Generated IAM request-condition accessors for tags/tag keys, policy ARNs,
  boundaries and Organizations policy IDs. Remove the second Query tag parser
  and repeated modeled tag constraints. Native replay verifies last-value
  authorization for duplicate keys, semantic denial precedence, retained state,
  leading-zero/split indices, missing positions and sparse collection errors.
- [x] Generated REST JSON literal routes/document bodies and resource-bound Smithy
  operation closure for Account Management. Header/payload/label bindings remain open.
- [x] Header and query SigV4 verification against SDK-generated signatures.
- [x] Root local credentials, account selection and partition-aware STS identity.
- [x] IAM access-key lifecycle shared with gateway credential resolution.
- [x] STS GetSessionToken with expiry and principal identity.
- [x] Generated IAM STS token preferences with delayed propagation, immutable
  credential region compatibility, destination-account role selection and
  service-specific authentication errors, checked against real AWS.
- [x] Account Management commercial region opt-in with service-time transitions,
  typed shared storage, Organizations management/delegate access and IAM conditions.
  Regional authentication checks the caller; STS publication checks the destination
  account within the shared transaction. See [AWS evidence](docs/account-regions.md).
- [x] Account primary/alternate-contact storage and lifecycle, contact-type IAM
  conditions, and primary-contact inheritance in the Organizations creation
  transaction. See [native captures and limits](docs/account-contacts.md).
- [ ] Complete primary-contact country/address validation, normalization and
  bootstrap/partition conformance. Implement GovCloud associations,
  remaining regional/partition conformance,
  variable credential-recognition propagation and console-managed STS activation.
- [x] Account information/name APIs with generated timestamp formatting, shared
  Organizations identity, stable IAM creation metadata, native normalization and
  SDK error behavior. See [evidence](docs/account-information.md).
- [ ] Complete Account closure/suspension access, propagation and partition
  conformance alongside the Organizations account lifecycle.
- [x] Account primary-email reads and OTP workflow with explicit SMTP delivery,
  service-time expiry/completion, typed retained delivery intent and atomic
  Organizations email publication. See [behavior and evidence](docs/account-primary-email.md).
- [ ] Capture and complete native primary-email verification, replacement and
  retry limits, validation, expiry/status errors, delivery/propagation timing,
  competing ownership and in-flight membership/state transitions. Read-only
  captures and local SMTP tests do not establish complete workflow parity.
  Further SMTP/OTP work is explicitly deferred and does not block other services.
- [x] Organizations-owned IAM root features and STS AssumeRoot with actual task
  policy enforcement, target-account SCPs, root credential operations and SQS
  policy recovery. See [evidence and remaining audit](docs/iam-root-access.md).
- [x] Capture successful AWS root-feature/delegate transitions, the independent
  IAM versus S3/SQS task gates, root recovery profile/report fields, trusted-access
  constraints and continued use of issued sessions after revocation.
- [ ] Model transient regional STS eligibility after delegation/trusted-access
  changes and audit nonempty root key/certificate/MFA responses.
- [x] STS AssumeRole with bound trust principals, external/source identity, session
  policies, tags, role chaining, and GetFederationToken restrictions.
- [x] Coordinate signed `AssumeRole`, `GetSessionToken` and `GetFederationToken`
  current parent, role/trust, identity/boundary/session policies and MFA reads
  with credential insertion in one IAM authority transaction and callback time.
  Failed commits and canceled callbacks return no credentials or issued session.
- [x] Coordinate IAM and Organizations through one memory transaction domain.
  Signed action/tag/source checks and root eligibility remain stable through
  credential publication. Root feature writes roll back with IAM authority
  failures; `GetSessionToken` skips permissions and Organizations reads.
- [x] Signed OIDC and signed/encrypted SAML token validation, generated unsigned
  STS federation entry points, atomic current-provider/trust checks and usable
  role credentials with enforced session claims and policy restrictions.
- [x] Outbound IAM issuer lifecycle and STS GetWebIdentityToken with actual
  RS256/ES384 signatures, public discovery/JWKS, current identity/organization
  claims, permissions, session lifetime checks and AWS-captured payload limits.
  See [outbound identity evidence](docs/iam-outbound-identity.md).
- [x] AWS-captured IAM-to-STS outbound propagation, modeled as ordered changes
  visible after 10 service-time seconds, with rollback and reconstruction checks.
- [ ] Outbound signing-key rotation and retention, and remaining partition/context
  conformance.
- [x] IAM virtual MFA lifecycle, QR/seed generation, TOTP validation and STS MFA
  sessions with enforced authentication-age conditions.
- [x] Generated virtual MFA bindings, AWS-captured code windows and retained
  synchronization history, with atomic one-time code consumption during STS
  publication. See [MFA evidence](docs/iam-mfa.md).
- [x] AWS-captured authentication with both synchronization codes after enrollment,
  resynchronization and replacement; synchronization does not consume STS codes
  or release codes previously used for STS authentication.
- [x] Ordered IAM-to-STS MFA binding propagation, including deletion/recreation,
  rollback and retained code consumption across pending changes.
- [x] AWS-captured mandatory MFA for self-enrollment/deactivation after the first
  device, with administrator, resynchronization and last-device removal behavior.
- [x] AWS-captured MFA verification budgets and UTC-window recovery, including
  success counting, independent devices, same-ARN replacement and atomic denials.
- [ ] Remaining transient replacement-device authentication behavior; see the
  unresolved observations in the MFA evidence.
- [ ] Hardware/FIDO MFA is explicitly deferred and does not block other services.
- [ ] Remaining federation differential audits, trusted contexts, newer token APIs
  and precise packed-policy sizing.
- [x] Apply IAM identity/resource policies, session policies, boundaries and SCPs
  to implemented built-in service requests, including cross-account checks.
- [x] Enforce resource-owner RCPs through the shared evaluator for implemented
  eligible services, including S3, Secrets Manager, SQS, KMS and STS, external
  federation, required session actions, owner organization conditions and AWS
  exemptions. Replay owned AWS captures and exercise all 11 organization/policy
  mutations with real object/secret reads across CLI SQLite restart; see
  [RCP behavior](docs/iam-resource-controls.md). Complete action/context and
  propagation conformance remains part of the authorization audit below.
- [x] Public `iam/policy` library owning the built-in composition path, with
  immutable policy source/version snapshots, hierarchy targets and per-permission
  statement/principal/condition traces. See [the contract](docs/iam-evaluation.md).
- [ ] Complete dependent-action authorization diagnostics, policy-context coverage
  and simulation fidelity for every service action and resource combination.
- [x] Match AWS captures for mapped IPv4 requests, decimal CIDR syntax, IPv6
  network validation and malformed-IP comparisons. SDK
  replay checks TagUser mutations, stored policies and simulator decisions;
  real peer-IP conditions gate SQS sends. See [IP evidence](docs/iam-evaluation.md#ip-conditions).
- [x] Match captured AWS string comparisons and UTF-16 wildcard behavior across
  authorization, variables, ARN/resource selectors and policy discovery. Native
  IAM/STS captures replay through the SDK; current principal tags gate actual
  SQS publication. See [string evidence](docs/iam-evaluation.md#string-conditions-and-resource-wildcards).
- [x] IAM instance-profile lifecycle and role references, PassRole enforcement,
  login/password policies and verification, password history/expiry, and aliases.
- [x] IAM service-specific credential lifecycle for all six currently supported
  services, current-identity verification, expiry/reset/revocation and permissions.
- [x] Consume generated inputs in credential conditions/all-user authorization,
  federation resources/discovery, service-linked-role protection and instance-profile
  PassRole checks. Match native Query integer/boolean forms and error classification;
  SDK replay verifies canonical condition values and usable STS sessions.
- [x] OIDC/SAML provider administration, immutable trust snapshots, metadata/key
  validation, tags and an explicitly configured discovery interface.
- [x] Signing certificate, SSH public key and server certificate lifecycles,
  cryptographic credential verification and usable TLS material through typed
  internal consumer interfaces.
- [x] Service-linked role deletion state machine, usage locking, recovery, trusted
  SCP exemption and six sourced commercial templates.
- [ ] Complete authoritative service-linked role templates across partitions and
  actual usage dependencies as each linked service is implemented.
- [x] Custom/principal context-key reporting, generated role responses and role
  last-use records that survive session expiry/removal.
- [x] Generated role-template inspection and acquisition for the five captured
  commercial templates, including conditional policies, underlying permission
  enforcement, atomic creation and configuration-based reuse/restoration.
  See [live evidence and scope](docs/iam-role-templates.md).
- [x] Generated account-property APIs, captured namespace validation and permission
  conditions, dependent service-role permission and atomic provisioning with
  retained account state. See [AWS evidence](docs/iam-account-properties.md).
- [ ] Complete Role Manager deletion conformance and resolve the owned AWS role's
  failed cleanup; implement new-account onboarding and its Access Analyzer
  transition, delegation APIs and the remaining role-template
  noncommercial resource-account/partition/version audit.
  September 22 and October 3 retries verified the original disabled role and
  again ended in AWS's internal-error failure with no standing setting changed.
- [x] Generated IAM account summary and authorization details, with current
  resource counts, shared enforced quotas and paginated permission relationships.
- [x] Generated credential reports with atomic generation intents, cached CSV
  snapshots, scoped recovery and password/access-key usage windows.
- [x] Principal/custom simulation with current policy graphs, exclusions, typed
  context, resource/boundary/SCP composition and statement diagnostics. Preserve
  simulator-specific behavior separately from service authorization.
- [x] Captured simulator caller defaults and generated action recognition and
  resource display metadata, with SDK replay across default, single-resource
  and multiple-resource requests for the pinned action catalogue.
- [x] Service last-access reports and policy-grant discovery with actual
  authenticated attempts, frozen asynchronous snapshots, caller ownership,
  generated action tracking/service names and owned AWS differential fixtures.
  Service history uses a 400-day snapshot window; action history and frozen
  reports remain independent. No undocumented JobId expiry is invented.
- [x] Organizations access reports with management-account eligibility, SCP
  hierarchy/resource intersections, authenticated account activity, asynchronous
  failures, report reuse and generated output metadata.
- [ ] Complete the simulation and reporting action/resource/context differential
  audit; captured cases do not establish universal parity.
- [x] Capture all commercial AWS managed policies and retained versions with
  exact document provenance, immutable ownership and account-local usage counts.
- [ ] China/GovCloud managed-policy captures, remaining IAM resource families
  and quotas. [IAM completion audit](docs/iam-completion.md) remains open.
- [x] INVITE handshake operations with generated bindings, participant/IAM checks,
  atomic joins preserving existing account/IAM state, staged tags, invitation
  reservations, service-time expiry/retention and typed transactional events.
  Native replay captures email/account-ID differences, error-with-acceptance,
  cancellation/decline and received-list ownership. Memory/SQLite SDK tests cover
  dependency denials, rollback, recovery and inherited SCP enforcement against SQS.
  See [invitation behavior and remaining scope](docs/organizations-invitations.md).
- [ ] Native standalone acceptance and remaining invitation eligibility, tag-policy,
  notification, throttling and membership/deletion conformance;
  responsibility-transfer handshakes and remaining operations.
- [x] Standard all-features migration with invited-member consent, missing-role
  restoration, management finalization, membership/invitation coordination,
  90-day service-time expiry and approvals surviving child-history retention.
  IAM/Organizations transactions and multi-event commits preserve rollback;
  memory/SQLite SDK tests verify recovery and subsequent SCP enforcement.
  See [feature migration](docs/organizations-features.md).
- [ ] Native complete standard-migration capture, resend and exact error/transition
  conformance; consent notifications remain with deferred email delivery.
- [x] Effective management-policy inheritance using ordered attachments,
  assign/append/remove operators, child controls and retained generation time.
  Native tag-policy and STS session replay covers defaults, validation, ownership,
  reattachment precedence and memory/SQLite recovery. See
  [effective policies](docs/organizations-effective-policies.md).
- [x] Effective-policy publication through the shared service-time scheduler,
  retaining cached views and coalescing pending account/type work. Native tag
  probes cover delayed reads and disable/re-enable cache visibility. Typed events,
  memory/SQLite recovery, rollback, revision conflicts and membership changes are
  covered by SDK tests; legacy views regenerate through the ordinary worker.
- [x] Tag/backup effective-policy validation reports with generated SDK contracts,
  contributing policy IDs, deterministic pagination, tag size/required-key limits,
  backup admission and combined-plan diagnostics. Invalid updates retain the whole
  last valid document. Typed SQLite diagnostics publish with state/events and
  survive pending restart, rollback and retained-schema upgrades; native captures
  distinguish Organizations validation from downstream Backup service behavior.
- [ ] Complete remaining management-policy service schemas/defaults and validation
  reports, propagation for other types,
  downstream tag enforcement/compliance and actual Backup plan execution.
- [x] AI opt-out policy admission with generated AWS service names, native empty
  fragments/value/operator constraints, duplicate JSON-key rejection and atomic
  rejected updates through the SDK on memory/SQLite. Tag/backup captures confirm
  shared child-control validation. AI defaults, propagation and service effects
  remain part of the management-policy completion audit.
- [x] Chat policy admission from native captures and SDK identifier shapes, with
  separate source/published casing, empty-fragment pruning, peer merges and
  published validation report metadata. SDK replay checks updates/detachments
  and pending SQLite restart. Downstream chat configuration enforcement and the
  complete effective-document diagnostic limits remain in the completion audit.
- [x] Replace backup schedule selector shortcuts with service-time calendar
  evaluation against native cadence, archive, finite-year and rollover captures.
  Keep request-time admission separate from stored-policy normalization. Validate
  inherited continuous/archive and copy-action dependencies with exact native
  diagnostics; SDK replay covers multiple conflicts, repair and pending restart.
- [x] Organizations resource-policy lifecycle and actual member delegation through
  IAM/STS, boundaries, sessions and SCPs. Match native validation, dependent tags,
  global resource ownership and policy CRUD/attachment permissions; persist typed
  records and tags in memory/SQLite with rollback, revocation and migration tests.
  Delegated SCP changes govern SQS sends. See [evidence](docs/organizations-delegation.md).
- [x] Native delegation authority and transition audit: explicit policy denials
  override trusted-service and membership grants; global operations and AWS-owned
  Organizations policies resolve the management account for conditions. SDK replay
  retains those decisions through memory/SQLite recovery. Captured grant/revoke
  cycles observed updated decisions on their first samples; no timing SLA is claimed.
- [x] Organizations-created member access roles with default/custom names,
  management-account trust, actual administrator permissions and atomic
  account/role publication. See [behavior and evidence](docs/organizations-account-access.md).
- [x] Organizations service-linked role provisioning, management-account IAM
  dependency permission, protected ownership and membership-dependent deletion
  through the shared transaction domain. Existing owned roles retain identity.
- [x] Generated Organizations account-creation bindings, typed pending jobs,
  service-time completion, concurrent request limits and retained-backend recovery.
  Initial membership, roles and terminal success commit atomically; failed commits
  leave the accepted request pending. Live AWS duplicate-email failures are captured.
- [x] Enforce Organizations account-count quotas at admission and completion,
  including management/closed members, scoped applied-quota overrides and
  asynchronous failures when competing requests consume the remaining capacity.
  Capture AWS default/applied values and preserve existing accounts on decreases.
- [ ] Post-success account initialization, billing access, native Service Quotas
  integration, request throttling and remaining creation
  failure/timing conformance.
  Initial role provisioning alone does not complete account creation.
- [ ] Fresh AWS organization/billing-mode role-provisioning and deletion-diagnostic
  conformance; current role definitions are captured from existing accounts.
- [ ] Full partition scope isolation; remaining REST JSON/REST XML bindings and
  Smithy RPC; broader streaming, checksums, event streams and SigV4a as needed.
- [x] Typed replaceable in-memory repository interfaces, rollback/cancellation,
  detached records and shared IAM/credential transaction ownership.
- [x] Shared generic memory transaction engine and central typed backend injection
  through `Config.Storage`, with public service-owned storage contracts.
- [x] Borrowed transaction contexts join typed Account, IAM and Organizations repositories;
  nested writes stage together and callback failures/cancellation abort the domain.
- [x] Public `Config.Clock` injection across identity, authorization and current
  built-ins, with manual time and cancelable service timers.
- [ ] SQLC and SQLite persistence, schema migrations, crash recovery and snapshots;
  optional PostgreSQL with identical service semantics.
- [x] First durable adapter: SQS-owned SQLite tables and SQLC queries for queues,
  delivery state and accepted redrive callers/progress, with shared native
  transaction/schema setup, CLI selection and SDK process-exit recovery tests.
  The coordinated event journal remains open; see [SQLite state](docs/sqlite-state.md).
- [x] Reuse native SQLC statements within SQS SQLite write transactions instead
  of preparing every retained message/receipt row again. A signed race-enabled
  CLI drained all 243 captured audit payloads without loss or duplication;
  the observed drain fell from 111.99 to 72.81 seconds. The focused X-Ray
  CloudTrail/EventBridge consumer replay and queue rollback/cancellation tests
  passed under the race detector. Aggregate rewrites remain; these local timings
  are not an AWS throughput claim. See [SQLite evidence](docs/sqlite-state.md).
- [x] Generate fresh SQLite initialization from the authoritative migrations,
  including seed rows, without replaying historical table rewrites on empty
  databases. Preserve native transactional upgrades and verify retained queue,
  identity, event, S3 version and service-time state through SDK/CLI recovery.
- [x] KMS-owned SQLite tables and SQLC queries retain material history, regional
  state, policies, grants, wrapping keys/import expiry and multi-Region rotation.
  Version 1 queues migrate without data loss. SDK tests cover recovery, grant
  enforcement and atomic regional rollback. Coordinated event/clock recovery
  remains open.
- [x] Borrow native SQLite transactions through typed repository contexts;
  expire nested callbacks, reject read-to-write upgrades and roll back the owner
  after a caught nested write failure. KMS/SQS propagate the context through
  dependency calls.
- [x] Coordinated Account, IAM/credentials and Organizations SQLite adapters cover
  their existing typed contracts in service-owned relational schemas. The CLI
  selects all built-in adapters on one database. SDK restart tests retain IAM
  policy versions, session restrictions, MFA state, reports, federation trust,
  account provisioning and SCP enforcement; failure tests roll back credential
  publication and Organizations roles/membership together. Scheduler attempts
  and broader event recovery remain open; committed credential events are below.
- [x] Optional persistent manual service time, CLI restoration and local clock
  controls. Commit advances before exposing time or delivering timers; failed
  writes and canceled waits leave both unchanged. SDK restart tests cover pending
  account creation, SQS visibility and STS expiry on the restored timeline.
  Advances do not drain service jobs or impose cross-service execution order.
- [x] Versioned Go extension registration, scoped requests and conflict checks.
- [ ] Supervised process extensions and lifecycle hooks.

## Cognito user-pool application kernel

- [x] Generated 132-operation JSON frontend with `cognito-idp` signing and
  implemented pool/client/user/group/auth operations. Real password/SRP login,
  temporary-password challenges, access/ID JWTs, public JWKS, refresh rotation
  and server-side revocation use typed shared memory/SQLite storage (schemas 164–167),
  with private signing keys separate from public pool configuration.
- [x] Separate public Cognito credentials from IAM authority; resolve only recipient
  audit scope from the actual client or verified token. Administrative APIs retain
  signed IAM checks and outcomes use the shared transactional journal.
- [x] Retain native AWS login, admission and CloudTrail captures and bounded probe
  sources, including hidden-user SRP salt/username behavior, public/admin
  new-password challenge crossover and rejected alias collisions. Captures are
  evidence for their recorded cases, not a blanket replay or service-parity claim.
  [Cognito behavior and evidence](docs/cognito.md) is the authoritative current
  subject document and lists the intentional implementation markers.
- [x] Replay native login/admission/audit fixtures through Go SDK clients on memory
  and SQLite. Verify scoped IAM/account/Region isolation, exact local token-expiry
  boundaries and configured CloudTrail → EventBridge → SQS delivery. Independently
  complete SRP signup/login and retained-token workflows across a standalone
  process restart; keep deferred authentication and delivery paths explicit.
- [x] Capture native group membership, pagination, deletion and JWT role-precedence
  behavior, with all 100 calls correlated to CloudTrail by AWS response request ID.
- [x] Implement all nine group/membership operations through scoped IAM and typed
  memory/SQLite repositories. Replay native controls, current role claims, audit
  envelopes, pagination and deletion/recreation across reopening; verify actual
  signed login/refresh through standalone SQLite process restart.
- [x] Capture and replay native zero-limit rejection, identical-value group updates
  and simultaneous missing-user/group precedence. Bound native audit collection
  by individual captured request IDs, not only operation names.
- [x] Capture scoped STS session policies for group role assignment; enforce
  `iam:PassRole`, native condition-key availability and rejection precedence.
  Preserve federated audit identity while suppressing IAM-denied parameters.
- [x] Capture native credential reset/suspension, current app-client read permissions
  and paired client-deletion behavior, with owned-resource cleanup and bounded
  CloudTrail correlation.
- [x] Match retained access/refresh acceptance after temporary administrative
  password reset and native deleted-client errors. Replay the stable credential
  and attribute-permission contracts on memory and SQLite across reopening,
  without pinning unestablished propagation timing from one immediate
  post-delete success.
- [x] Implement bearer-authorized profile updates, attribute removal and self-deletion;
  replay 60 native calls and all 60 correlated CloudTrail events on both stores.
  Enforce current client writes, last-value duplicate validation, immutable/required
  attributes and native username-recreation errors. Retain revoked refresh metadata
  without restoring old credentials or memberships. Verify actual SQLite restart,
  schema-165 migration and configured CloudTrail → EventBridge → SQS delivery.
- [x] Deliver Cognito invitation, verification, resend, profile verification and
  password-recovery mail through actual SES MIME capture. User-owned codes survive
  app-client deletion; current developer-role authority and mail admission share
  user-state transactions. Verify ordinary linked-role dependency failure and
  deletion after pool removal/session expiry.
- [x] Generate SES v2 contracts and implement scoped email identities, verification,
  configuration sets, tags, templates and simple/raw/bulk MIME acceptance with
  typed retained storage. Verify current IAM/sandbox gates, real captured bytes,
  SQLite restart, native owner tagging and selected CloudTrail delivery to S3.
- [ ] Complete real SMTP/Internet delivery, SMS, MFA, federation, remembered
  devices, Lambda/custom challenges and hosted UI/OAuth before admitting their
  active configurations. SMTP/SMS success is never manufactured.
- [ ] Complete SES suppression/contact lists, event destinations, delivery
  analytics, DNS/DKIM domains, custom MAIL FROM, dedicated IPs, tenants, broader
  delegated identity control authority and full Handlebars evaluation. Capture native
  successful sending/Cognito delivery and their audit/transition boundaries;
  local captured mail and native validation errors are not complete SES parity.
- [ ] Complete remaining user-pool operations, advanced security/analytics,
  imported client secrets, customer-managed keys and broader schema/alias,
  authorization, quota, expiry, partition and audit conformance. Cognito Identity
  pools have their own implemented [enhanced-flow owner and explicit gaps](docs/cognito-identity.md).

## Kernel delivery gates

Current push: actual CloudTrail delivery, EventBridge routing, CloudWatch logs,
metrics/alarms and SNS fanout into SQS and real Lambda Runtime API execution.
Build and verify complete application paths while retaining explicit service-depth
gaps. The existing `clones/aws-lambda-runtime-interface-emulator` is a runtime
reference; customer handlers must run in real runtimes. IAM completion remains
tracked below.
CloudTrail Lake is explicitly excluded; its generated API recognition does not
create an implementation obligation.

- [x] Generate CloudTrail/EventBridge frontends and implement management-history lookup,
  custom/default buses, matching, rules and SQS targets over the common storage and
  scheduler. Replay native fixtures through SDK clients; service completion remains
  open. See [CloudTrail](docs/cloudtrail.md) and [EventBridge](docs/eventbridge.md).
- [x] Share API completion identity/origin construction; keep public request/response
  projections owned by services and append successful observations atomically.
- [x] Implement management-owned organization trails, current delegated/member
  authority, Account regional gates and IAM-owned service-linked roles. Retain
  account-separated S3/KMS/Logs/SNS work across membership/scope changes and
  restart; replay both stores without claiming native delivery timing.
  See [organization scope and evidence](docs/cloudtrail.md#organization-trails).
- [x] Deliver actual signed CloudTrail digest chains and public-key discovery through
  S3/KMS, with retained regional/account ownership and SQLite restart. The real
  AWS CLI validates the objects and detects log-byte corruption. Capture native
  admission, public keys and the empty starting interval; broader native
  delivery/backfill timing remains open.
- [x] Audit the complete documented EventBridge rule language against the richer
  matcher reference and native fixtures, including Unicode/CIDR behavior, correlated
  arrays and wildcard admission across alternatives and `$or` branches.
- [x] Implement target InputPath/InputTransformer admission and native rendering,
  including reserved variables and invalid-output DLQs. Persist definitions and
  freeze projected bodies across rule/target changes, retries and SQLite restart.
- [x] Implement bus policy administration and cross-account rule/event authorization,
  with immutable role bindings, native creator context, request-level batch denial
  and restart tests. Preserve separate account-wide IAM and bus-owner permissions.
- [x] Discover rule membership from retained target metadata, including duplicate
  targets, disabled rules, deleted destinations and current-state pagination.
  Enforce rule-namespace authorization without decrypting encrypted bus
  configuration; use the shared read-only management audit path.
- [x] Encrypt EventBridge customer events, rule patterns and target configuration
  with customer KMS keys; retain accepted key/configuration snapshots across
  replacement and restart. Preserve source transaction independence and recover
  actual encrypted bus DLQs through AWS Encryption SDK. The bounded local key
  reuse window and synchronous configuration migration are not AWS timing claims.
- [x] Retain EventBridge rule/target roles and enforce PassRole, current trust and
  destination authorization through the shared IAM/STS authority. Preserve selected
  roles across source changes/reopen; replay SQS/SNS and actual Docker Lambda
  contexts without a rule-role or service-principal fallback.
- [x] Forward to typed event-bus targets across accounts/regions with native wire
  identity, original account/region, hop limits and eventBusInvocation conditions.
  Retain independent causal admissions and replay mixed graphs, foreign-created
  rules, missing destinations and schema59→61 upgrades.
- [x] Correlate native EventBridge service assumptions and actual SQS outcomes
  through CloudTrail history/S3. Scope successful service-role records to the
  role account; do not fabricate denied customer assumptions or forwarded
  PutEvents API calls. Verify CLI → buses → real Lambda → SQS/Logs, current
  permission denial and SQLite restart.
- [x] Propagate native-selected EventBridge X-Ray headers through retained live
  forwarding, retries, SQS/DLQs and real asynchronous Lambda execution. Preserve
  metadata across SQLite restart and omit it from archive replay; do not invent
  customer JSON fields, spans or Lambda lineage.
- [x] Retain EventBridge archives, native managed rules, filtered replay cursors,
  cancellation and ingestion-based retention in memory/SQLC SQLite. Replay native
  SDK fixtures and actual encrypted SQS/Logs delivery after process restart.
- [x] Enforce archive/replay multi-resource IAM and real caller/service KMS
  authorization, preserving key identifier spelling and failure metadata. Record
  native management outcomes through CloudTrail; no synthetic replay PutEvents.
- [x] Migrate retained archive keys asynchronously through replacement/reset,
  native failure rollback and explicit retry. Preserve events across SQLite
  restart and replay them after old-key revocation through actual SQS delivery.
- [ ] Complete archive AWS physical SizeBytes accounting and
  propagation/counter-refresh conformance. See
  [archive boundaries](docs/eventbridge.md#archives-and-replay).
- [x] Publish EventBridge request, rule, target, schedule and archive/replay metrics
  through shared CloudWatch commands with retained weighted minute samples.
  Replay native bus/DLQ distinctions on both stores; verify source deletion,
  process restart, account/region isolation and actual alarm → SNS → SQS delivery.
- [x] Preserve original retained service-metric timestamps across large clock
  advances without weakening public CloudWatch timestamp admission.
- [x] Match native terminal disabled-key/missing SQS targets and denied DLQs,
  including `NO_RESOURCE`, absent retry-exhaustion attributes and exact attempt/
  failure/DLQ metric distributions. Verify native fixture replay and 67 CLI metric
  queries after source deletion and SQLite process restart.
- [ ] Complete EventBridge throttling/quota metrics, actual retry-exhaustion/
  recovery observations and additional target-error families.
  See [metric boundaries](docs/eventbridge.md#cloudwatch-metrics).
- [x] Add separate [Scheduler](docs/scheduler.md) and [Pipes](docs/pipes.md)
  generated services, typed memory/SQLC SQLite owners and shared-clock drivers.
  Retain schedule occurrences/retries and pipe source checkpoints/work, with
  current IAM/KMS authority and concrete source/enrichment/target adapters.
- [x] Capture owned native Scheduler/Pipes lifecycle/default-payload behavior,
  49 exact-request management projections and related actual SQS data records;
  replay signed official SDK contracts on both stores. Preserve failed preparation
  evidence and independently verify all owned native resources absent.
- [x] Connect Scheduler CodePipeline templated targets to the existing pipeline
  and S3 artifact owners. Native-calibrated ignored input, execution attribution,
  translated DLQ request and current-role denial/recovery are exercised through
  signed Go SDK calls, actual artifact consumption and SQLite restart. Preserve
  failed-before captures and exact-owned cleanup; see
  [Scheduler pipeline evidence](docs/scheduler.md#codepipeline-templated-targets).
- [ ] Complete Scheduler CodePipeline cross-account delivery and native DLQ
  payload-truncation/retry-exhaustion metadata. Foreign account/Region runtime
  behavior remains uncalibrated; local isolation guards are not AWS parity.
- [x] Connect Pipes API destination enrichment through the existing authenticated
  HTTPS owner, with retained HTTP parameters and native-calibrated scalar input,
  response filtering and dynamic-parameter precedence. Verify actual transformed
  SQS output, current IAM/Connection recovery and failed-work SQLite restart;
  preserve native capture limits and exact-owned cleanup in
  [enrichment evidence](docs/pipes.md#api-destination-enrichment).
- [x] Decode gzip and zlib/raw deflate Pipes enrichment responses through the shared
  HTTP owner. Capture actual request Range/Accept-Encoding, two-result fanout and
  gzip expansion beyond six MiB before target transformation; remove the contradicted
  decoded-size check. Verify malformed/checksum failure, retained source recovery
  and restart through real HTTPS and signed SDK calls.
- [ ] Complete native Pipes enrichment wire/expansion ceiling and partial-Range
  calibration, additional content codings and same-message retry timing. The local
  six-MiB wire bound and 64-MiB expansion safety ceiling are not native parity.
- [x] Consume actual MSK and self-managed Kafka through native consumer-group
  assignment and committed offsets. Retain filtered work until successful target
  effects; prove target-denial checkpoints, restart without replay, current secret
  authority, partition sharing and preservation of borrowed consumer groups.
- [x] Bind Kafka Pipes work/cursors to native cluster/topic IDs and reject
  replaced topics across retained-work and cursor-only restarts. Verify actual
  topic recreation through the signed executable; document the older-broker
  rejection and Kafka 3.7's non-atomic name-based commit boundary in `docs/pipes.md`.
- [ ] Complete remaining Scheduler target owners/native timing classification and
  Pipes MQ/DocumentDB and other target gaps, self-managed Kafka VPC/encrypted-key
  support, MSK client-mTLS, KPL aggregation and native vended-log format/delivery
  fidelity before claiming complete service parity. Unsupported paths remain
  protocol errors, not successful metadata-only resource creation.
- [x] Add generated Lambda REST labels, queries, headers, raw payloads and response
  bindings. Run direct ZIP create/configuration/list/delete/update and synchronous
  invoke through official Python 3.12 RIC containers with current IAM execution-role
  credentials. Replay native warm/error/timeout/update distinctions and real boto3
  SQS authorization on memory and SQLC SQLite. See [Lambda evidence](docs/lambda.md).
- [x] Enforce function resource policies with independent revisions and retained IAM
  principal bindings. Implement event-invoke configuration CRUD, delayed applied
  settings and durable asynchronous acceptance/retries through the shared scheduler.
  Replay native policy/configuration behavior and real EventBridge → Lambda → boto3
  → SQS, including wrong-rule DLQs, request-ID distinctions and SQLite recovery.
- [x] Retain actual Lambda terminal responses, independent asynchronous destinations
  and legacy dead-letter delivery through SQS/SNS/EventBridge/Lambda/S3 interfaces.
  Enforce execution-role admission and current target policies; publish native
  outcome counters through CloudWatch. Replay owned payload/permission/expiry
  fixtures, queued-retry schema upgrades and source-deleted completion recovery.
- [x] Implement scoped Lambda reservation/account controls and pooled real runtimes.
  Preserve running calls across reservation changes, retain zero/throttled async
  outcomes and publish native attempt counters. Replay signed numeric inputs,
  IAM/lookup ordering, metadata revisions and SQLite schema/restart boundaries.
- [x] Implement generated Lambda function retrieval and independently expiring ZIP
  downloads backed by scoped immutable archives and durable signing keys. Replay
  actual bytes/ranges across code replacement, deletion, expiry and SQLite reopen.
- [x] Implement atomic Lambda tag mutations, metadata-only revisions and current
  IAM resource/request-tag authorization. Replay native SDK/STS tag transitions
  and CloudTrail projection; retain warm customer state across successful no-ops.
- [x] Implement immutable numbered Lambda deployments, persistent version allocation,
  guarded publication and alias lifecycle/weighted routing. Preserve version-owned
  archives and runtime pools with function-wide capacity and live-tag authorization.
- [x] Resolve qualified policy/configuration scopes and retain accepted delivery
  settings and authority through alias/version deletion. Re-resolve aliases on each
  actual attempt without resetting the request identity or retry budget.
- [x] Implement all nine generated Lambda layer operations, scoped version policies,
  monotonic allocation, requested-layer IAM conditions and ordered real `/opt`
  overlays. Retain deployment contents after catalog deletion and SQLite reopen.
- [x] Resolve Lambda COPY/REFERENCE S3 packages through the ordinary S3 service,
  separating deploying-caller access from service-principal access. Retain exact
  source versions, dry-run semantics and independent deployment archives.
- [x] Recheck REFERENCE sources through deterministic jobs and recover inactive
  deployments after source access is restored. The one-hour local cadence is not
  an AWS timing guarantee; the native source-loss reason code remains unverified.
- [x] Persist custom Lambda text log groups across updates, published versions and
  SQLite reopen; deliver real output through execution-role-authorized Logs APIs.
- [x] Apply native Lambda LoggingConfig replacement and JSON/severity controls
  through official Python/Node runtime logging frames. Preserve published-version
  thresholds and custom destinations through SQLite and executable restart.
- [x] Own Invoke tails through the actual runtime output collector. Replay native
  byte truncation/UTF-8 repair, JSON whole-record eviction and pre-filter capture;
  verify cold/warm/error/timeout/stream boundaries and independent full Logs
  delivery through official Python/Node containers and the actual AWS CLI.
- [x] Retry exact-owned Docker cleanup after a canceled create completes late.
  A real Engine regression reproduces the retained in-use volume failure before
  the fix and verifies both containers and volume absent afterward.
- [x] Project native layer-management observations and S3 deployment-source fields
  into CloudTrail history and configured delivery without exposing ZIP bytes.
- [x] Generate Lambda extension/telemetry bindings and historical projections from
  pinned AWS specifications, with offline drift checks and native request deltas.
- [x] Separate function response from runtime/extension phase completion. Execute
  actual layer extensions, preserve concurrency/causal ownership after response,
  reset processes while retaining `/tmp`, and retain fractional phase metrics.
- [x] Deliver and replay historical Logs/Telemetry schemas through real HTTP/TCP
  collectors, including subscription/reset retention, platform state, batching,
  independent stdout/stderr lines, phase failures and SQLite metric recovery.
- [x] Select pinned runtime images by AWS architecture and replay actual Python
  x86_64/arm64 execution, code migrations, retained versions and alias retargets.
- [x] Add explicit function-scoped development code/layer directories. Reload real
  runtimes between invocations, preserve `/tmp`, discover replaced extensions and
  keep published artifacts immutable; verify through the executable and SDK.
- [x] Generate typed AWS event streams and run `InvokeWithResponseStream` through
  real Node.js/custom runtimes on x86_64/arm64, sharing invocation authorization,
  version selection and admission with ordinary `Invoke`.
- [x] Preserve accepted execution after disconnect, bounded response ownership,
  timeout prefixes/process replacement and shutdown with unread client output.
- [x] Replay isolated native streaming error metrics and actual asynchronous SQS
  outcomes: metric errors do not fabricate public `FunctionError` or failure
  routing; malformed response JSON produces the native delivered error context.
- [x] Implement the five Lambda Function URL control APIs and retained scoped
  configuration/identity, one-minute effective-setting transitions and SQLite
  recovery. Connect PublicEndpoint HTTP routes to real BUFFERED/RESPONSE_STREAM
  invocation, current IAM/public policies, CORS and shared concurrency admission.
  Preserve accepted execution after disconnect and native alias/URL lifecycle
  distinctions. See [Function URL evidence and limits](docs/lambda.md#function-urls).
- [x] Project native URL Invoke/management CloudTrail records and URL CloudWatch
  dimension/sparse-counter observations without inferring missing datapoints as
  zeros or bounded missing data delivery as universal omission.
- [ ] Resolve remaining Function URL transport and negative-case boundaries,
  including raw-header-case multiplicity lost by net/http, native empty-stream
  completion beyond bounded captures and broader authorization/metric dimensions.
- [x] Implement generated SQS event-source mapping controls, qualified identities,
  tags, execution-role admission and retained lifecycle state. Replay native
  null/empty distinctions, rejected updates, orphan/recreation and SQLite recovery.
- [x] Poll real SQS commands into official Lambda runtimes with batching/filtering,
  partial acknowledgement, FIFO exclusion and visibility-based restart recovery.
  Retain typed multi-message causal links and native mapping-UUID metric samples.
  Replay source records/counters/audit fixtures and verify actual CLI customer SDK
  sends, accepted execution after disable and configured S3/Logs trail delivery.
  See [SQS mapping behavior](docs/lambda.md#sqs-event-source-mappings).
- [x] Replay fresh source-role/resource-policy admission and runtime IAM context;
  distinguish throttled attempts from function errors, reject expired-lease
  retries after clock jumps, and remove invented SQS processing-result state.
  Native fixtures cover authority, visibility recovery and queue/ESM counters.
- [x] Run retained DynamoDB Streams through qualified real Lambda runtimes with
  current execution-role authority, per-item parallel lanes, retained retries,
  partial responses, bisecting and record-age limits.
- [x] Retain tumbling-window state and native failure documents; verify empty
  final-window S3 failures and state reset through the executable. Keep configured
  destination denial terminal without reinvoking the discarded source batch.
- [x] Encrypt SQS/DynamoDB/Kinesis mapping filters through current caller/service
  KMS authority; preserve redaction, replacement/reset and typed ciphertext state.
  Verify actual three-source Python delivery, caller denial and disabled-key
  recovery across executable SQLite restart. Already admitted polls may complete.
- [x] Add native Lambda filter signing context and shared signed AWS Encryption SDK
  envelopes, preserving exact function/source context, private mapping binding and
  current caller/service KMS authority. Retain legacy AES-GCM ciphertext through
  explicit-format SQLite migration; verify official SDK decryption and real runtime
  filtering. This does not claim native Lambda plaintext-envelope layout.
- [ ] Complete remaining source engines, broader cross-account/KMS authority,
  native late-revocation timing and full-scale polling conformance.
- [x] Put real subscription buffers/history/retries inside the function cgroup,
  preserving warm state, reset backlog and detached-process cleanup through a
  prebuilt container helper. Verify actual shutdown acknowledgment and memory use.
- [ ] Resolve remaining native extension resource costs. Disk-backed `/tmp`
  capacity and exact-owned crash recovery now have native/executable evidence;
  this does not establish identical AWS platform overhead.
- [x] Correct retry-enabled missing aliases before any handler entry for the
  captured destination-only configuration while the parent function still exists.
  Preserve accepted identity and handler retry budget across
  SQLite restart; expire with an atomic drop metric and no fabricated OnFailure
  record. Verify real replacement/version-two execution, exact alias metric deltas,
  retry-zero contrast and independent configuration-application controls through
  the [executable workflows](docs/lambda.md#resource-policies-and-asynchronous-delivery).
- [x] Calibrate and deliver retry-zero deleted-alias legacy DLQs: retain original
  bytes and accepted request ID, project native Number404 and qualified resource
  error without a handler response, and preserve independent OnFailure delivery.
  Verify current IAM denial and SQLite restart through real runtime/SDK workflows.
- [x] Calibrate published-version DLQ ownership with positive native delivery:
  after an applied root A→B change, fixed-version and alias failures still use
  published A. Verify queued alias/root B→C updates, exact bytes and immutable
  runtime identity across SQLite restart; preserve conflicting documentation and
  API-readback versus applied-delivery evidence in [Lambda](docs/lambda.md#dlq-deployment-ownership).
- [x] Preserve accepted asynchronous settings across whole-function deletion and
  same-name recreation until replacement configuration is applied or reset.
  Schema313 backfills historical absent-function queues without crossing scope;
  replacement runtime, IAM role and deployment DLQ remain current. Signed SDK,
  real Python runtimes and SQLite restart verify old/new routing, explicit reset,
  numeric-version isolation and current destination denial.
- [x] Verify six native-positive DLQ-enabled deletion cases: queued whole-function
  and fixed-version targets with retry0/retry1, plus fixed-version/alias deletion
  after a handler failure. OnFailure and legacy DLQ preserve accepted identity,
  count1/count2 and status404 without fabricated runtime output. Two executable
  workflows also preserve existing alias behavior; all 18 controllers exited zero,
  and owned resources, containers and volumes were independently removed.
- [ ] Resolve remaining native terminal delivery after deleting targets with retries
  enabled. Whole-function deletion after a handler failure has an additional
  aggregate drop but no destination/DLQ through598s; its drop minute precedes the
  age deadline, so missing-alias expiry cannot supply its scheduling or route fate.
  Earlier destination-only whole-function nonobservations remain scoped evidence,
  not disproved by the newer DLQ-enabled positive cases. DLQ-enabled missing-alias
  retry-one deletion has no observed terminal/additional drop through903.614s;
  local age180 DLQ429/drop remains a documented bounded mismatch, not parity.
  Mutable unqualified accepted-event DLQ selection, native DLQ update/removal
  propagation and exact recreation queue-setting selection timing remain open.
  Preserve [original deletion evidence](testdata/aws/lambda/async_deletion_analysis.json)
  and [the scoped newer capture](testdata/aws/lambda/async_deleted_targets_analysis.json).
- [ ] Reconcile native case-colliding tag-condition winner selection. The server
  uses deterministic scalar selection, not fabricated multivalued tags; native
  resource/request paths disagree on mixed-case precedence. See [IAM evaluation](docs/iam-evaluation.md#case-distinct-service-tags).
- [ ] Complete non-concurrency initialization/permission failure and DLQ projection,
  remaining service metric dimensions and encrypted-destination depth.
- [x] Generate S3 REST XML/HTTP bindings and implement the trail dependency's
  bucket/object commands with actual encrypted binary state on memory/SQLC SQLite.
  Preserve raw key paths, checksum/condition/range behavior and native owner/policy
  rules; multipart routes must not fall through to ordinary object overwrites.
  Preserve lowercase metadata keys on the actual HTTP wire, including AWS CLI
  decoding across retained version reads.
- [x] Implement enabled/suspended bucket versioning, null/version histories, delete
  markers, exact-version reads/deletes and deterministic version pagination.
  Preserve native conditional-deletion and IAM ordering on memory/SQLC SQLite.
- [x] Implement S3 envelope encryption and bucket defaults through ordinary KMS
  authorization, wrapped per-version keys and typed memory/SQLC state. Replay
  native alias, context, checksum, denial and precondition behavior on both stores.
- [x] Retain independent Firehose S3 destination keys; verify primary-denial/
  backup recovery, alias history and bucket-default inheritance across two
  executable restarts, with actual CloudTrail and EventBridge/SQS consumers.
- [x] Implement non-organization trail controls, basic/advanced selectors, native
  resource identities, effective stop deadlines and RecursiveLogging. Retain
  selected event references, write real gzip S3 objects outside source transactions
  and admit eligible records to EventBridge's default bus. Replay owned AWS
  fixtures, policy-revocation retry, restart and independent failed-create marker
  effects. See [CloudTrail/S3 evidence and limits](docs/cloudtrail.md).
- [x] Implement canonical CloudTrail KMS configuration through real S3 preflight,
  current-key retries and native encryption/error/audit semantics. Replay native
  admission and correlated delayed-delivery fixtures on memory/SQLite; verify
  encrypted gzip recovery and identical EventBridge/SQS records after process restart.
- [x] Deliver CloudTrail validation and log-file notifications through ordinary SNS
  publication with independent S3/SNS status and retained publication stages.
  Replay native authority/recovery fixtures across both stores; verify schema
  107→108 pending-log migration and encrypted S3 → SNS → SQS → real Lambda after restart.
- [ ] Establish CloudTrail-to-SNS transient and long-tail producer retry behavior.
  Bounded captures do not establish an infinite no-retry guarantee; subscriber
  retries remain SNS-owned. See [notification evidence](docs/cloudtrail.md#sns-log-file-notifications).
- [x] Implement retained S3 bucket notification replacement/adoption, native rule
  admission and SNS/SQS/Lambda/EventBridge object delivery through service interfaces.
  Replay owned native control, principal, quota and payload fixtures on both stores;
  verify schema 108→109 and real Python execution across executable restarts.
- [ ] Establish S3 transient-producer retry cadence/terminal budgets and malformed
  percent-escape delivery matching; extend event producers as their source operations
  become real. See [notification evidence](docs/cloudtrail.md#s3-bucket-notifications).
- [x] Implement version-owned S3 object tags, tagged writes, current/version IAM
  actions and tag conditions without rewriting object data or history.
  Replay native control/authority, marker disclosure, notification and delivered
  CloudTrail fixtures on both stores; verify executable schema 109→110 recovery,
  tag-conditioned reads and S3 → SQS/EventBridge publications after restart.
  See [tagging behavior](docs/cloudtrail.md#s3-object-tagging).
- [x] Implement atomic S3 object copies with version/tag authority, destination-owned
  encryption, metadata/redirect replacement and conditional publication.
  Replay native control, KMS, notification, generated-rejection and correlated
  internal-read audit fixtures on both stores; verify schema 110→111 executable
  recovery, actual error-response byte counts and concurrent-copy exclusion.
  See [copy behavior](docs/cloudtrail.md#s3-object-copies).
- [x] Implement retained S3 multipart uploads and copy parts, native completion
  ordering/retry, checksum matrices, version publication and object attributes.
  Reuse segmented encrypted state across reads/copies, preserve current IAM/KMS
  authority and emit source-owned notifications and delivered audit projections.
  Replay native SDK/raw fixtures on both stores; verify encrypted pending and
  completed recovery across executable restarts with actual SQS/EventBridge and
  gzip CloudTrail consumers. See [multipart behavior](docs/cloudtrail.md#s3-multipart-uploads-and-attributes).
- [x] Implement all ten modeled S3 checksum families, including canonical XXHash
  and native multipart initiation/header distinctions. Generate typed field
  projections, consolidate payload admission, replay native fixtures on both
  stores, and verify retained HTTPS binary reads, copy rehashing, chunked trailers
  and actual EventBridge/SQS/CloudTrail consumers.
  See [checksum behavior](docs/cloudtrail.md#s3-checksums).
- [x] Implement retained bucket/object ownership and ACLs, bucket public-access
  controls and policy status through shared IAM and generated REST XML.
  Replay native cross-account, session/boundary, reversible-mode, multipart-owner,
  raw XML and delivered audit fixtures on both stores. Verify executable schema
  112→113 recovery of encrypted versions/uploads, anonymous access and configured
  CloudTrail delivery across restart. See [access controls](docs/cloudtrail.md#s3-ownership-acls-and-public-access).
- [x] Generate the S3 Control frontend and retain account public-access settings
  in the S3 memory/SQLC repository. Apply bucket-owner account restrictions across
  ordinary ACL, policy, copy, batch and service-delivery paths without overwriting
  stored bucket settings. Replay native read-only account/host/audit evidence.
- [x] Enforce published Organizations S3 all/none overrides, protected account
  writes and retained-setting restoration through the existing policy scheduler.
  Verify SDK fixtures, schema 117→118, pending-publication process restart and
  actual CLI IAM denial plus CloudTrail S3/EventBridge/SQS event delivery.
- [x] Capture native unattached S3 policy admission without enabling the policy
  type. Match case-insensitive fields/operators, case-sensitive assignments,
  child controls and atomic rejection; retain original policy spelling. Replay
  all 62 captured admission outcomes through the executable and verify uppercase
  source publication into retained S3 account controls.
- [x] Implement retained ordinary regional S3 access points, generated control
  operations, policies/tags and ARN/alias object, copy, list and multipart access.
  Preserve independent bucket/AP authorization, public-access controls and foreign
  AP orphans. Replay native control/authority/multipart/audit fixtures on both
  stores and exercise retained CLI data, CloudTrail, EventBridge/SQS and access logs.
  See [regional access points](docs/cloudtrail.md#s3-regional-access-points).
- [x] Retain general-purpose bucket ABAC and unify S3 Control/legacy/creation tags.
  Enforce current bucket/access-point tag conditions through shared IAM, including
  independent copy and multipart authorization. Replay native controls, policies
  and named-session role recreation; verify executable data grants/revocations,
  unchanged metadata and CloudTrail history across SQLite process restart.
  See [bucket ABAC](docs/cloudtrail.md#s3-bucket-abac).
- [x] Reject duplicate bucket/access-point tag mutations atomically using native
  owner-specific errors. Replay fresh and quiet-interval evidence, preserve
  existing tags and failed-create absence, and verify actual CLI restart.
- [ ] Resolve connection/backend-correlated tag authorization visibility and
  transient post-removal quota recovery. Crossed client/credential observations
  rule out session identity alone, but do not define a cache owner or fixed TTL.
- [x] Retain S3 transfer acceleration and enforce accelerated/dualstack data
  admission through ordinary object and IAM commands. Replay native controls,
  current session/resource/tag authorization, regional routing, access-point
  aliases and 70 correlated management events through classic trail delivery.
  Verify SDK signed/presigned byte reads and flag/alias retention across an
  actual HTTPS SQLite process restart. See [acceleration](docs/cloudtrail.md#s3-transfer-acceleration).
- [x] Implement native conditional us-east-1 owned-bucket recreation and ACL reset
  without replacing retained state. Preserve current policy denial, absent
  resource-tag context and dependent ACL/ownership/lock permissions. Replay
  native controls and authority, all public-access flag conflicts and 30 delivered
  management records; verify actual SQLite restart and unchanged versioned data.
  See [bucket creation](docs/cloudtrail.md#s3-bucket-creation-and-recreation).
- [ ] Implement trusted VPC transport and the remaining access-point families.
  Capture broader native AP audit/server-access-log and propagation behavior;
  local AP log delivery is not a captured native delivery guarantee.
- [x] Implement retained S3 Object Lock defaults, fixed/variable version retention,
  legal holds, creation/copy/multipart snapshots and deletion guards through shared
  IAM and typed memory/SQLC state. Replay native controls, authority, notifications
  and delivered audit fixtures; verify executable restart, expiry, independent
  read-header permissions and actual SQS/CloudTrail delivery into protected objects.
  See [Object Lock behavior and evidence](docs/cloudtrail.md#s3-object-lock).
- [x] Implement general-purpose S3 storage classes and retained archive restoration
  with independent Restore/Get authority, native tier upgrades, calendar expiry,
  copy/multipart ownership and original-sequencer publications. Replay native
  controls and delivered events on both stores; verify real CLI binary reads,
  cross-midnight deadlines, two SQLite process restarts and CloudTrail/SQS delivery.
  See [archive behavior and evidence](docs/cloudtrail.md#s3-storage-classes-and-archive-restoration).
- [x] Implement generated Intelligent-Tiering controls, native quota/pagination and
  IAM precedence, retained access windows, forward archive tiers and permanent
  restoration. Replay native controls/authority and document-derived execution
  on both stores; verify real CLI/website access, pending SQLite recovery,
  unchanged binary bytes/checksums and classic/direct event delivery.
  See [Intelligent-Tiering behavior](docs/cloudtrail.md#s3-intelligent-tiering).
- [x] Implement generated S3 request-metric controls, typed filters and stable
  pagination on both stores. Publish actual object request/error/byte/latency
  samples through bucket-owner CloudWatch authority, preserving percentile
  populations and native copy/multipart/filter distinctions. Replay native
  controls, IAM and delivered audit/publication fixtures; verify executable
  quota boundaries, account/region isolation and retained alarm→EventBridge→SQS
  delivery after SQLite restart.
  See [request metric behavior](docs/cloudtrail.md#s3-request-metrics).
- [x] Implement generated S3 Inventory controls, optional-field IAM context,
  catalog-backed action/condition admission and retained memory/SQLC scheduling.
  Publish actual CSV/GZIP, native Apache ORC/ZLIB and Parquet/Snappy reports
  through S3/KMS and existing notification/audit/metric owners. Replay native
  admission/history and fixture-driven cancellation, weekly, key/policy recovery
  and cross-account ownership; verify independent readers, SQS completion and
  1,001-version page boundaries through actual SQLite executable restart.
  See [Inventory behavior](docs/cloudtrail.md#s3-inventory).
- [ ] Capture native physical Inventory reports, exact optional-cell/schema
  conventions, first/recurring delivery and failure/retry/propagation behavior.
- [x] Implement generated S3 analytics configuration controls with typed memory/SQLC
  state, IAM, atomic filter validation, quota/pagination and native management audit.
  Replay captured controls and UTF-16/character boundaries; verify actual CLI
  retention across SQLite process restart. Configuration is not report execution.
  See [analytics behavior](docs/cloudtrail.md#s3-storage-class-analytics).
- [ ] Capture physical native analytics exports and implement actual measurement,
  history, recommendations and daily CSV delivery through existing S3/KMS owners.
  Do not derive analytics populations from CloudWatch request metrics or claim
  report behavior from configuration round-trips.
- [ ] Capture native long-duration tiering transitions, archive expiration and
  broader storage/restore audit/log behavior.
- [x] Implement actual SSE-C encryption, bucket blocking, independent copy keys,
  retained multipart checksum/key admission and ciphertext-only replication.
  Replay native controls/data/partial-read/audit fixtures on both stores; verify
  trusted HTTPS CLI, blocked completion, exact retry and permanent restoration
  through process reopens without retaining customer keys. Preserve fractional
  retention headers and generated-catalog object-tag policy admission.
  See [customer-key behavior](docs/cloudtrail.md#s3-customer-key-encryption).
- [x] Implement retained live S3 replication with generated controls, real execution
  roles/KMS authority, version-preserving payload/metadata delivery, cross-account
  ownership and per-component outcomes. Replay native controls, filters, authority,
  partial failures, notifications/statistics and delivered CloudTrail gzip; verify
  populated old-binary SQLite upgrade, real reads and subsequent replication.
- [x] Separate RTC minute sampling from delayed CloudWatch publication. Retain
  pre-activation gauge/counter history, retry/threshold state and cancellation
  through reopen; verify actual KMS recovery and delivered SQS outcomes.
  See [replication behavior and evidence](docs/cloudtrail.md#s3-live-replication).
- [ ] Complete S3 Batch Replication and broader replication conflict/propagation,
  native RTC timing and audit/access-log projections through their owning services.
- [x] Implement retained S3 Lifecycle rules, expiration headers, current/noncurrent
  expiry and class transitions, marker cleanup and incomplete-upload aborts.
  Enforce Object Lock and replication barriers; commit notification/log intents
  with mutations without fabricating CloudTrail object APIs. Replay native control/
  header fixtures and document-derived workflows on both stores, including
  suspended-null replacement and deleted pagination anchors; verify real CLI
  bytes/checksums, SQS events and pending work through two SQLite process restarts.
  See [Lifecycle behavior and evidence](docs/cloudtrail.md#s3-lifecycle).
- [ ] Capture physical native Lifecycle execution, propagation, notifications and
  server-log fields; resolve broader archive-tier/replication interactions.
- [ ] Capture native Inventory protection-cell conformance and complete Object
  Lock interactions with Storage Lens; capture broader native propagation/audit/
  server-log delivery without treating missing records as proof.
- [x] Implement retained S3 CORS and anonymous static websites through the generated
  frontend, shared object authority and typed memory/SQLite stores. Replay native
  admission, retained rules, HTTP routing and delivered control events; verify
  schema 113→114, restart, real Chromium CORS enforcement and gzip CloudTrail delivery.
  See [browser behavior](docs/cloudtrail.md#s3-cors-and-static-websites).
- [x] Implement retained S3 requester-payment controls and account-based admission,
  signed payer bindings, charged success/error responses and paired caller/owner
  CloudTrail projections. Preserve hidden caller-side resource ownership and
  independent IAM checks; charge headers do not implement billing.
- [x] Deliver S3 server access logs as actual encrypted objects through ordinary
  service-principal PutObject, current source-conditioned policy/legacy ACL
  authority and shared retained scheduling. Preserve destination snapshots after
  disable/replacement and across SQLite restart; exercise midnight event dates,
  legacy ownership toggles, copy-source and internal log-publication producers.
  Schema 117 retains queued records/grants. See
  [accounting behavior and evidence](docs/cloudtrail.md#s3-requester-payment-and-server-access-logging).
- [x] Derive S3 ACL-required accounting from the shared IAM decision and one
  source-owned command flag. Verify ACL-only versus independent policy access,
  explicit denial, SQLite recovery and actual CloudTrail gzip delivery through
  the executable AWS CLI surface.
- [x] Replay native legacy log ownership/TargetGrants and BOE restoration,
  ACL-versus-policy 200/304/412 attribution, explicit private/BOFC uploads and
  compound copy records on memory/SQLite. Verify real CLI payloads, copy
  identities, presigned signature masking and retained delivery after restart.
- [x] Replay positively delivered native operation codes and all 27 fields for
  controls, unusual keys, requested versions, temporary presigning, multipart
  parts and per-member multi-delete records. Verify actual CLI compound
  correlations, selected sizes and retained delivery across SQLite restart.
- [ ] Capture other native server-access-log operation spellings, failed and
  ACL-dependent compound/grant details and broader cross-account projections.
  Unknown operation codes stay unavailable. Implement source-Region attribution and
  remaining logging destinations. Native propagation, batching,
  retry/retention and long-tail delivery bounds remain open; local five-minute
  scheduling/retry and 24-hour retention are not AWS guarantees.
- [ ] Complete native website configuration propagation/data-event projection,
  malformed browser-document audit projections and out-of-model CORS max ages.
- [ ] Complete compound public-policy trust inference and native account
  write/region/propagation behavior. Capture native Organizations S3 policy
  conflict/default/diagnostic and membership conformance.
- [ ] Complete S3's remaining operations/configuration, MFA delete,
  remaining notification producers, Bucket Keys/DSSE and native-region
  behavior; finish non-Lake CloudTrail operations, organization aggregation,
  Insights, additional destinations and propagation/throttling depth.
- [ ] Complete Lambda's remaining operation/configuration paths,
  API Gateway streaming, remaining event sources/destinations, provisioned-pool
  boundary coverage, scaling-rate limits and custom-runtime log framing,
  remaining runtime/host-platform coverage and full negative-case/lifecycle
  conformance. Disk-backed ephemeral quotas and exact-owned crash recovery are
  implemented with the documented native/runtime evidence and host prerequisites.
- [ ] Extend generated operation recognition beyond the currently registered models.
  Resolve shared signing names and multiple modeled protocols before registration;
  generate explicit unsupported dispatch for the remaining target services.
- [x] Emit management/data audit outcomes for every implemented STS, KMS, SQS,
  S3, EventBridge, Lambda, IAM, Account and Organizations operation, including
  equivalent internal service commands. Share generated public projections,
  identity/causality and native error mapping; preserve source-owned classifications,
  resources and transaction boundaries. Reads are not automatically management
  events, nor are read-only response elements universally null.
  Native fixture replay covers source classifications, redaction, rollback and
  actual S3/EventBridge/SQS delivery on memory/SQLite, plus Docker Lambda execution.
  Generated projections are shared; native per-operation conformance remains open.
- [ ] Complete audit projection depth beyond retained fixtures, global IAM history
  region routing, early transport/signature outcomes, Organizations asynchronous
  service-result events and remaining native cross-account/federation captures.
- [x] Implement classic EventBridge cron/rate rules with shared Backup calendar
  selection and service-specific admission. Retain optional fields and source
  deadlines; commit each occurrence, bus-wide matching, selected targets and
  journal fact atomically. Native SDK fixtures cover control semantics and real
  SQS delivery; local cases cover cadence, rollback and bounded recovery.
  The executable SQLite workflow reaches real Lambda, SQS, Logs, metrics and
  selected CloudTrail records, including current-role denial after restart.
  Deterministic deadlines do not claim native jitter or historical target replay.
- [ ] Add native non-CloudTrail service events into EventBridge and remaining
  targets and separate EventBridge Scheduler APIs, using native resources separate from LookupEvents aliases.
- [x] Generate the Logs frontend and implement scoped groups, streams, event
  ingestion, tags, retention policy and paginated reads on memory/SQLC SQLite.
  Replay native admission limits, rejection indices, filter patterns, pagination
  and authentication/authorization errors through actual SDK clients.
- [x] Connect real Lambda stdout/stderr through a consumer-owned Logs interface
  using execution-role credentials and service time. Preserve warm stream identity,
  output larger than Invoke's bounded tail and final bytes on normal deletion.
  Verify IAM denial does not fail invocation and logs survive function deletion
  and SQLite reopen. See [Logs evidence and boundaries](docs/logs.md).
- [x] Implement Logs ACCOUNT/RESOURCE policies with native revision rules and shared
  explicit-deny precedence. Deliver actual EventBridge default/transformed events
  and configured CloudTrail records through the ordinary Logs commands, preserving
  service-principal versus execution-role authorization. Retain independent S3/Logs
  delivery/status and replay permission failures, removal/replacement and reopen.
- [x] Implement the CloudTrail source dependency's S3 bucket tag get/replace/remove
  commands with typed storage, current IAM and committed management observations.
  Replay native limits, rejected-state preservation and SQLite recovery.
- [x] Implement Lambda subscription filter controls, native pattern/system-field
  selection and gzip delivery through ordinary Lambda permission preflight and
  asynchronous acceptance. Commit accepted Logs batches and retained delivery
  work with source events; replay native controls and real Docker SDK effects.
- [x] Preserve active-runtime SDK causality after signature verification using
  the environment's actual role key. Separate warm invocation parents and
  reserve synchronous API outcome IDs without custom headers or handler changes.
- [x] Deliver Logs subscriptions to real Kinesis through direct targets and
  typed logical destinations, current role authority, native gzip/partition keys
  and retained work. Enforce native destination-policy principal/condition
  restrictions, organization migration consent and ordinary same-account IAM
  precedence. Replay native controls and SDK delivery on memory/SQLite.
- [x] Deliver direct Logs subscriptions through Firehose PutRecord, retaining
  ordinary role/PassRole checks, filters and gzip envelopes through actual S3
  delivery. Verify both repositories and the executable multi-hop workflow.
- [ ] Complete Logs operations and dependencies: logical/cross-account Firehose
  and organization sender-role subscriptions, native configuration propagation and oversized/
  transformed-event behavior, native physical deletion latency, KMS, query engines,
  transformations, exports and linked-account observability. Finish runtime
  framing/flush and log-tail fidelity, cross-account destinations and native
  stream allocation.
- [x] Physically delete expired CloudWatch Logs events through transactional
  service-time jobs on memory/SQLite; recheck current retention, preserve exact
  cutoff, rollback and scope isolation, and prevent resurrection after deletion.
  Actual SDK/executable deletion and SQLite restart are verified. AWS's variable
  physical deletion latency is not reproduced.
- [x] Generate CloudWatch RPCv2-CBOR/Query/JSON contracts and implement typed
  custom metric publication, scoped listing, statistics and metric math over
  memory/SQLC SQLite. Verify real SDK gzip requests, modeled protocol errors,
  weighted samples, units, pagination and account isolation against native fixtures.
- [x] Implement Logs metric-filter controls, JSON/space extraction, per-event
  defaults, dimensions and configured publication through a consumer-owned
  interface. Commit metric points with accepted Logs rows/facts; verify rollback,
  application IAM boundaries, replacement/deletion and SQLite reopen.
- [x] Implement retained zero-count positive-bin fixed trims, zero-valued mass
  and winsor tail admission against independent native SDK/CLI fixtures.
- [x] Verify exact-adjacent inputs, subnormal through `2^360` magnitudes,
  mixed/all-negative fixed-range eligibility and ten-decimal statistic precision.
  Preserve native observations separately from inferred algorithms. See
  [current metric evidence and boundaries](docs/cloudwatch.md).
- [x] Implement retained SEARCH and Metrics Insights selection, weighted grouping
  and shared dense source-window allocation. Replay native fixtures through
  RPCv2-CBOR/Query on memory/SQLite; verify actual CLI retrieval, scalar query
  alarm transitions, region isolation and mixed-period pagination across restart.
- [x] Implement Metrics Insights contributor identity/history, rank displacement,
  parent reason-only updates and independent empty-query missing-data behavior.
  Reuse typed memory/SQLite repositories and scalar sample evaluation. Deliver
  actual contributor SNS/Lambda actions and EventBridge events; retain history
  across deletion/recreation. Fixture replay and actual CLI/runtime checks are
  recorded in [CloudWatch evidence](docs/cloudwatch.md).
- [ ] Implement resource-tag metric associations with the actual Observability
  Admin/Resource Explorer opt-in prerequisites, eligible producer identities and
  retained tag semantics. Do not infer historical association from current tags
  after resource deletion/recreation or treat custom absent-tag tests as proof.
- [x] Implement typed metric/composite alarm controls, scoped IAM/tagging, retained
  history, M-of-N/missing-data/percentile evaluation and shared metric math.
  Replay native controls, queryDate-anchored transitions, composite cycles and
  suppression on memory/SQLite; retain real AWS observations separately.
- [x] Commit alarm state, native EventBridge events and ready action intents
  together. Deliver through Lambda's real resource-policy/async boundary; verify
  denied actions, retryable acceptance, actual handler payloads and extension
  release/causal ancestry across SQLite process restart.
- [x] Emit native alarm management observations through the shared recorder and
  verify LookupEvents, configured S3 delivery and EventBridge/SQS consumers.
  Verify thirty-day history expiry and history after alarm deletion.
- [x] Preserve omitted DynamoDB missing-data defaults across scalar, direct and
  expression queries, honor explicit overrides and remove them on replacement.
  Account for unused mixed-namespace queries; replay native fixtures through the
  shared alarm workflow runner and verify actual CLI/SQLite restart behavior.
- [x] Implement account-global dashboard controls and shared resource tagging through
  typed memory/SQLC repositories. Replay native body/warning, atomic replacement/
  deletion, size/tag-history, global IAM/session and audit fixtures through generated
  RPCv2-CBOR/Query frontends. Verify real metric consumption and CloudTrail → S3 /
  EventBridge → SQS delivery. See [dashboard evidence](docs/cloudwatch.md#dashboards).
- [ ] Complete remaining alarm engines/actions: anomaly detection, PromQL, log
  alarms/contributors, warm-up/explicit windows, query-percentile low-sample
  behavior, cross-account observation and non-Lambda destinations. Preserve
  namespace-specific behavior and per-sample causality through owned integrations.
- [ ] Complete entity-associated metrics, native availability/retention behavior,
  remaining query expressions, widget-image rendering/streams and the remaining CloudWatch APIs.
- [ ] Build AWS service-owned metric publication from actual lifecycle facts.
  Preserve metric-specific counting, dimensions and cadence; do not derive
  every metric from API call totals. Alarm evaluation/state/action intents
  already join the shared clock and scheduler.

The accepted [design](docs/verification-kernel.md) prioritizes these foundations
within inside-out service completion. [Architecture](docs/architecture.md)
records the current code boundaries. Shared clock injection and optional manual
time persistence are implemented. IAM, Organizations, SQS, KMS, EventBridge, Lambda,
CloudTrail, Logs and CloudWatch join one ordered driver, exposed through
`Stack.RunDueJobs` and the local jobs drain API. Target attempts, Lambda
invocations, Logs subscriptions, trail batches and alarm work retain deadlines.
Broader recovery and consistent instance forks remain planned.
Do not add fidelity labels or provenance headers to AWS responses.

1. [x] Inject `Config.Clock` through identity, authorization, IAM, STS,
   Organizations, KMS and SQS. Keep SigV4 skew, outbound TLS checks and network
   deadlines on wall time; IAM server-certificate validity uses service time.
   Exercise exact credential expiry, MFA age, policy dates and queue deadlines
   through SDK requests and public manual-clock advances. `Advance` delivers
   timers without draining goroutines; tests synchronize registration and results.
2. [ ] Implement a deterministic scheduler with persisted typed jobs, stable
   equal-deadline ordering, cancellation/reset/recurrence, bounded draining and
   responsive shutdown. IAM report generation, service-linked deletion and Organizations account
   creation, handshake deadlines and effective-policy publication now use ordered, bounded draining over typed job records with
   after-commit wakeups and recovery. Add durable attempts/recurrence/cancellation records
   and integrate request-owned SQS waits before adding new asynchronous services.
   SQS redrive now uses retained deadlines and atomic message/task progress in
   the shared driver, including cancellation and failed-commit recovery.
   Instance assembly joins IAM, Organizations, SQS, KMS, EventBridge, Lambda and CloudTrail execution/shutdown;
   the bounded operator drain shares the automatic worker's gate. SDK tests
   verify equal-deadline ordering, actual report/account/access-role/message
   results and pending-job recovery on memory and SQLite. SMTP and external IAM
   usage-check completion remain separate, as explicitly deferred. KMS derives
   scheduled work from retained key/material records and shares transition logic
   with requests. SDK tests verify automatic recovery without KMS traffic, bounded
   rotation catch-up, replica/promotion completion, expiry, deletion and rollback.
   Discovery scans namespaces; lifecycle events and durable attempts remain open.
   Persist seeds and ID counters while retaining
   cryptographic entropy for security material.
3. [ ] Commit typed event journal/outbox rows with resource transitions and jobs.
   Coordinate service-owned SQLC tables in one storage domain. Verify rollback,
   crash windows, failed commits and detached event payloads. Dispatch outside
   locks. SQS KMS preparation now runs outside queue transactions, with fresh
   authorization, configuration and message selection before commit. The default
   memory bundle now joins Account, IAM/credentials, Organizations, KMS and SQS in
   one transaction domain, matching the existing SQLC SQLite boundary. Failed
   KMS key creation rolls back new IAM service roles. SQS evaluates current IAM,
   Organizations and queue policies inside its resource transaction; revocation
   while waiting for storage denies the command. STS credential issuance and IAM
   access-key creation, status updates and deletion append typed journal rows
   in the IAM transaction, with local paginated event history. Memory/SQLite
   tests cover credential and event rollback, mixed history, migration and recovery;
   session and provisioning subprocess tests verify native SQLite crash recovery.
   Organizations now commits acceptance and terminal account-creation events
   with job/membership/role/contact state. Original request identity survives
   recovery; revision conflicts, append failures, failed commits and cancellation
   leave no event from the rejected attempt. Existing jobs migrate without
   backfilled origins or acceptance events. Other
   event sources, retention and replay remain open. EventBridge admission now commits
   matched delivery intents and journal acceptance; SQS commits accepted sends
   with message state. Shared origin construction retains caller/service identity,
   request IDs and causal parents. Implemented service API completions
   feed scoped history, selected S3 logs and EventBridge default-bus admission;
   see [the journal contract](docs/event-journal.md).
4. [ ] Build delivery checkpoints, retries, batch/partial failure and DLQs from
   explicit per-edge contracts. Preserve causation and trace context through every
   hop, with optional OpenTelemetry export. Verify retry after delivery-before-ack
   crashes without claiming exactly-once external effects. EventBridge now retains
   SQS/Lambda delivery versions, retry deadlines, terminal results and DLQ work.
   Lambda retains asynchronous attempts and CloudTrail retains S3 batches;
   effects run outside source transactions. Other edge contracts remain open.
5. [ ] Add consistent snapshot/fork/restore across resources, credentials, clock,
   pending jobs, event cursors and delivery attempts. Fence old workers after
   restore. Run the same contract suite against memory and SQLite/PostgreSQL;
   benchmark actual fork cost. External engines need explicit checkpoint adapters.
6. [ ] Complete the public IAM library's action/resource/condition conformance
   and join dependent-action denial traces. The public composition path and
   per-permission source/version, statement, principal and condition traces are
   implemented. Retained snapshots preserve current-policy mutation behavior;
   AWS simulation keeps its distinct contract. Continue owned live resource and
   cross-account comparisons; see [the library contract](docs/iam-evaluation.md).
7. [ ] Add seeded service-specific fault profiles within documented AWS guarantees,
   exact throttle/retry errors and scoped quota overrides. Preserve S3 strong
   object read/list consistency. Report seed and causal history on test failure.
8. [ ] Pin and refresh protocol/schema inputs through reviewable generation and
   conformance CI. CloudFormation now pins native `us-east-1` DescribeType schemas
   for twenty resource adapters; `cmd/cfngen` and
   `generate-cloudformation-check` reproduce structural property contracts.
   Expand regional/schema coverage and CI refresh without inferring resource
   semantics from schemas. Unsupported behavior stays an explicit protocol
   error; schema-derived CRUD does not count as a completed resource or service.
9. [ ] Implement real Lambda Runtime API and extension execution in containers:
   official AWS base images and real RIC on x86_64/arm64, init/invoke/shutdown,
   configurable keepalive and forced cold starts, warm `/tmp` persistence,
   freeze/thaw, hot reload, limits, streaming, cancellation, credentials and logs.
   No microVM or in-process handler fallback. A missing runtime is an explicit
   compute configuration error; control-plane-only embedding needs no container.
   Determinism ends at customer-code API/event edges.
10. [ ] Inject per-instance Docker/containerd/Kubernetes handles and provision
    pinned real backends per resource. Own prepare/start, observed readiness,
    execute/stream, cancellation, limits, cleanup and capability checks. Activation
    follows actual backend readiness, not a service-time timer. Implement the
    [backend map](docs/verification-kernel.md#borrow-data-planes-and-run-real-compute):
    ECS Fargate by default, EKS k3d/k3s or existing kubeconfig, EC2 with QEMU/KVM,
    Batch/CodeBuild/Glue, real database/broker/search engines, DynamoDB Local and
    a Kinesis engine. Retain AWS lifecycle, placement and policy logic in Go.
    Route backend credentials/runtime/logs and AWS API calls back to the emulator;
    enforce reachability and endpoint policies at execution boundaries. Keep
    isolated DNS/local-CA integration opt-in and endpoint overrides supported;
    do not mutate host networking automatically.
11. [ ] Implement explicit external/local-model/recorded execution adapters with
    request matching, redaction, stream/cancellation behavior and CI offline
    enforcement. Never automatically forward unsupported calls or expose local
    credentials to AWS. Recorded outputs are evidence, not offline service completion.
12. [ ] Pin applicable SDK/Terraform/CDK/CFN scenarios and maintain differential
    fixtures that preserve errors, state, ordering and semantic timestamps. Bound
    live resources/costs and verify cleanup. Measure startup, memory, fork and
    replay budgets; keep Go embedding and standalone packaging as the core form.

## Step Functions workflow kernel

- [x] Generate the Step Functions frontend and typed cross-service command input
  registry from Smithy; route actual service commands through their existing
  authorization and mutation owners.
- [x] Retain scoped machines, immutable revisions, versions/aliases, executions,
  frames, tasks and history in shared memory/SQLC SQLite repositories. Replay
  native control identity, pinned snapshots and deletion visibility.
- [x] Execute the eight ASL state kinds with JSONPath/JSONata dataflow, variable
  scopes, clock-owned waits/retries, callbacks and branch/Map coordination.
  Replay native context and causal history, not just final happy-path outputs.
- [x] Enforce captured assignment/live-variable and Standard history limits;
  preserve assigned-variable history and reject fatal runtime errors globally.
- [x] Exercise actual Lambda Runtime API workflows on both stores: all 21 native
  workflow cases and six direct Invokes, with actual asynchronous log delivery.
  Optimized response metadata now shares service-owned response encoders.
- [x] Verify actual CLI S3-to-SQS task effects, CloudWatch Logs delivery and a
  leased activity completing after SQLite-backed process restart.
- [x] Replay native active-deletion, service observation, distributed Map and
  task-dependency replay across both repositories and restart.
- [x] Enforce native managed completion-rule admission and route nested `.sync`
  completion through actual EventBridge delivery with authorized polling.
- [x] Connect optimized ECS request-response, synchronous jobs and callbacks to
  actual container execution and native EventBridge managed completion rules.
  Retain accepted submission data across reopen, use ECS-owned idempotency,
  preserve jobs on service shutdown and authorize parent cancellation. Native
  Fargate/schema/error captures and memory/SQLite real-container regressions
  establish the [bounded integration contract](docs/stepfunctions.md#optimized-ecs-tasks).
- [x] Replay all sixteen native callback workflows, concurrent branch cancellation,
  execution deadlines, empty long polling and cleanup, with SQLite lease recovery.
- [x] Retain Standard execution and distributed Map redrive through memory/SQLite:
  pinned revisions, selective recovery, fresh task leases, retry/context/history
  ownership, token replay, execution-role admission and actual S3 ResultWriter
  generations. Replay settled native fixtures and CloudWatch transition metrics;
  verify Activity recovery and idempotency across actual CLI process restarts.
- [x] Publish retained workflow and actual SDK task traces through role-authorized
  X-Ray commands. Replay native header/configuration, retry/parallel/Map/fault
  documents and SQS trace propagation across memory/SQLite and retained spans.
  Scoped sampling, large-trace/history-limit behavior and broader redrive tracing
  remain explicit verification boundaries.
- [x] Execute authenticated HTTP Tasks through retained EventBridge Connections,
  actual managed Secrets Manager credentials, current IAM/KMS authority and real
  HTTPS/OAuth. Replay native composition and cold immutable-role controls on both
  stores; retain secret versions and workflow execution across CLI SQLite restart.
- [x] Implement customer-managed workflow/Activity encryption through real KMS,
  separate caller/execution/worker authority, retained ciphertext and pinned key
  references. Replay native admission/execution fixtures on both stores with
  targeted race coverage; verify actual CLI SQS effects, Activity recovery after
  SQLite restart, ciphertext at rest and both encrypted log-delivery authorities.
- [x] Capture native workflow API throttling, semantic-validation precedence and
  recovery; implement nominal account/Region API and Standard transition budgets
  using service time, preserving Express and synchronous admission distinctions.
- [x] Enforce transactional machine/activity/open-execution counts, retained
  idempotency and capacity recovery, including Standard Map child backpressure.
- [ ] Deferred quota refinement: open Map Run limits, Map/HTTP dispatch rates,
  applied overrides and native fleet-allocation/precedence conformance. Prioritize
  application-facing workflow and recovery gaps, then the next service.
- [x] Profile large-history workflow discovery; share read snapshots and prepare
  workflow queries without caching stale candidates. The complete SQLite fixture
  passes in 43.11 seconds on memory-backed temporary files with FULL sync;
  retained disk-state recovery also reaches the native 25,000-event failure.
- [ ] Reduce ordinary disk-backed large-history replay cost without weakening
  transaction durability or cross-service ordering. It still exceeds 180 seconds;
  memory-backed fixture timing is not an equivalent disk throughput claim.
- [ ] Complete targeted operations, unprobed redrive boundaries,
  Express memory accounting and external-effect recovery boundaries.
  [Current evidence and remaining boundaries](docs/stepfunctions.md) are
  authoritative; no Step Functions service-completion claim is made.

## Secrets Manager and Connection ownership

- [x] Generate Secrets Manager frontend/command contracts and implement typed
  metadata, encrypted versions, policies, tags, recovery, regional replication
  and scheduled rotation on shared memory/SQLC SQLite repositories.
- [x] Enforce actual KMS authority, historical wrapping-key retention and native
  identity/session/resource-policy conditions. Isolate handled KMS command
  rejections and fix shared-transaction/working-set lock ordering.
- [x] Execute captured four-stage/deferred Lambda rotation through real Python
  3.13 Runtime API containers; replay native lifecycle, encryption/audit,
  metadata ownership and replication authority on memory and SQLite.
- [x] Retain Connection lifecycle/public metadata separately from actual managed
  secrets; use the API Destinations linked role and current invocation permissions.
- [x] Match native secret-write authorization/validation precedence using generated
  rejection-only binding and current IAM authority. Replay captured malformed
  inputs and stage conditions on both stores, reject phantom versions, and verify
  all 56 captured outcomes through the SQLite-backed signed executable.
- [ ] Implement external secret partner ownership/synchronization and rotation.
- [ ] Complete scheduled secret-event causality, in-flight rotation cancellation
  and broader audit, quota, propagation/retry and failure-precedence verification.
- [x] Implement API Destination controls and actual authenticated HTTPS through the
  existing Connection/Secrets/IAM/KMS owners, shared rule retry/DLQ engine and
  Pipes target retry/acknowledgement path. Retain typed rate/HTTP parameter state,
  replay native controls/audit on both stores and prove executable SQLite restart,
  current-authority recovery and real TLS effects. See [evidence](docs/eventbridge.md#api-destinations).
- [ ] Implement Connection private connectivity/resource associations and expand
  native API Destination wire/throughput evidence. Management admission capture
  does not establish native request bytes, propagation deadlines or complete parity.

## RAM resource sharing ownership

- [x] Retain typed shares, invitations, organization associations and managed/
  customer permissions behind memory and SQLC SQLite repositories. Keep resource
  authority in the SSM, EC2 and CodeBuild owners and IAM in the shared evaluator.
- [x] Exercise actual CLI advanced-parameter sharing, permission replacement,
  historical reads and revocation with signed owner/consumer requests.
- [x] Boot an actual participant-owned guest in a shared owner subnet; preserve
  its packets and boot across controller restart and revocation, reject new
  placement, enforce live participant SG changes, and clean owned resources.
- [x] Enforce current permission/share ARN and tag authority before replacement,
  scoped listing and token replay. Verify the actual SDK denial/recovery workflow
  with required underlying SSM policy permissions and complete cleanup.
- [x] Calibrate omitted/supplied mutation tokens, current-state update replay,
  readable deleted versions, number reuse and active-only version quotas against
  owned AWS captures. Replay actual HTTP version transitions through SQLite
  restart without inaccessible omitted-token records or extra version ledgers.
- [x] Reassociate expired principals atomically without reviving old invitations.
  Advance actual service time, restart the executable, reject stale acceptance
  and withhold cross-account parameter access until fresh acceptance.
- [ ] Broaden resource-specific consumers beyond advanced SSM parameters, VPC
  subnets and CodeBuild project reads as their owners implement real behavior.
  Complete native propagation, quota and permission/error-precedence conformance;
  generated API registration and selected passing fixtures do not establish
  whole-service parity.
- [ ] Calibrate native successful invitation token omission, external-principal
  update replay and broader asynchronous replacement/promotion behavior without
  modifying standing organization settings or treating transient AWS 500s as a
  deterministic contract. See [the current RAM evidence](docs/behavior-references.md#ram-permission-lifecycle-and-authority).

## SSM Parameter Store ownership

- [x] Generate the SSM frontend and implement real Parameter Store value/version/
  label/tag/filter/path/history workflows with shared IAM, memory and SQLC SQLite.
  Preserve native StringList bytes, top-level aliases and observed type changes.
- [x] Use existing KMS authority for standard and advanced SecureString values;
  retain encrypted historical values without duplicating KMS or Secrets Manager.
- [x] Retain default tier, parameter policies, advanced resource-policy sharing
  and asynchronous EC2 image validation. Commit jobs, API observations and native
  EventBridge admissions through the shared transaction domain.
- [x] Execute CodeBuild project/buildspec and ECS container parameter references
  under their actual build/execution roles, including live KMS denial and regional
  ECS references. Keep resolved values out of retained control metadata.
- [x] Capture uniquely owned native SDK/API behavior, exact-ID CloudTrail events
  and EventBridge messages; replay selected public event projections and prove
  encrypted history/policy jobs across actual CLI SQLite process restart.
- [x] Resolve stateless Secrets Manager references through its existing command
  owner, including native version/stage/source projections and both layers of
  IAM/KMS authority. Exercise actual CodeBuild/ECS reserved-path consumers.
- [x] Connect shared-parameter discovery/promotion to the RAM owner; exercise
  signed cross-account sharing, history-permission replacement and revocation
  through the actual CLI.
- [ ] Connect reserved aws:ssm:integration parameters to their Systems Manager
  authority.
- [ ] Implement request quota admission before exposing high-throughput settings;
  broaden native policy-delivery/failure-precedence and public catalog
  evidence. Broader fleet and Session Manager remain separate workstreams.

See [Systems Manager contracts, evidence and boundaries](docs/ssm.md).

## SSM managed execution ownership

- [x] Retain Command document versions/defaults/hashes and creation tags separately
  from Parameter Store. Reuse generated public contracts and generate the private
  agent health shape from current official agent SDK source.
- [x] Execute customer Command schemas 1.2 and 2.0 alongside 2.2 using the official
  guest agent. Preserve original JSON/YAML content, hashes, legacy property lists
  and native-calibrated plugin/expiry/version rules. Signed memory/SQLite checks
  and actual guest execution verify success/failure, version selectors, current
  IAM and restart. Native admission captures do not establish native guest
  execution parity; additional plugins, engines and attachments remain open.
- [x] Admit immutable Run Command work under current document/instance IAM; persist
  per-node/plugin state in shared memory/SQLC SQLite. Fence concurrency, error
  budgets, cancellation, expiry and duplicate delivery/reply transitions.
- [x] Implement the real signed ssmmessages control channel and EC2-profile-bound
  Linux health reporting without an SSH, Docker-exec or in-process script adapter.
- [x] Capture native current-agent execution, failures, both timeout classes,
  cancellation, document history, same-session IAM changes and real output/reboot
  behavior; remove exact owned resources while retaining immutable command history.
- [x] Calibrate document/command/private-health CloudTrail against exact native
  request IDs; retain real document incarnations and Creating/Updating/Pending
  lifecycle transitions in shared durable service-clock jobs.
- [x] Match native serialized command-size boundaries before admission, including
  empty-list/escaping/output overhead; distinguish absent tags from empty values
  and bind the observed regional AWS-owned document account in current IAM.
- [x] Execute the current official agent inside a firmware-booted guest through the
  assembled signed CLI/SDK endpoint. Prove real output, both timeouts, cancellation,
  multi-plugin documents, current IAM denial, SQLite restart without replay,
  retained-byte guest reboot, agent reconnect and exact owned cleanup.
  The final follow-up verifies all 14 API audit families plus real private health,
  oversized-work rejection with a usable agent, literal-empty tag selection,
  provider-owned document authority and actual pending lifecycle snapshots.
  Native QMP path admission rejects the reproduced 108-byte configuration before
  guest creation; exact failed-run cleanup and the fresh short-path proof are retained.
  Integrated race-enabled execution repeated all 25 observations; its wrapper
  expired during cleanup, and same-database recovery verified all 14 absences.
  The interrupted boundary remains explicit in the retained evidence.
- [x] Implement version-aware SSM account/public document sharing and public-share
  blocking through the existing setting owner. Native grant/version semantics,
  current IAM and owner isolation, actual cross-account AppConfig bytes,
  revocation and SQLite restart are verified. Run Command proof covers shared
  document admission with zero targets, not official-agent execution.
- [ ] Add RAM document sharing, attachments and other document engines/plugins.
- [ ] Add hybrid/DHMC enrollment, other guest platforms and legacy transport.
- [ ] Implement Session Manager/data channels, State Manager, Automation, Patch,
  Inventory and Ops workflows through their actual owners.
- [x] Deliver Run Command Command/Invocation SNS notifications from transactional
  status transitions through current role, trust and topic authority. Native
  captures and an actual official-agent guest verify success, failure, cancellation,
  execution/delivery timeout, filters, denial/recovery and SQLite restart.
  Fifteen local cases delivered 23 SNS/SQS messages; owned resources were removed.
- [x] Resolve Run Command Resource Groups targets through current group membership
  and scoped ListGroupResources authority, retaining selected node incarnations
  and IAM checks. Native admission captures, memory/SQLite SDK checks and an
  official-agent guest verify tag changes, retained selection across query changes/
  restart and four Invocation SNS/SQS deliveries; owned resources were removed.
  Native concurrent membership-selection timing remains uncalibrated.
- [x] Monitor Run Command alarms through current CloudWatch and the protected
  Systems Manager service-linked role. Typed schema312 retains revision-fenced
  polls and triggered state across SQLite restart; admission revalidates current
  document authority inside the commit transaction. Native captures and two
  official-agent guests prove ALARM/UNKNOWN failures, stopped pending delivery,
  surviving running shells, ignored poll failures, notifications and recovery.
  SDK/race checks preserve cancellation and IAM usage/session deletion protection;
  owned guest, alarm, notification, network and IAM resources were removed.
- [ ] Implement managed-node telemetry persistence/export and broaden native
  health/expiry timing evidence. Alarm polling uses a documented local five-second
  cadence, not a claim of exact AWS timing.

## Compute control prerequisites

- [x] Generate ECS and EC2 Query frontends and schema-derived DTO copies; preserve
  native sparse-index and duplicate-query behavior without fake successful actions.
- [x] Retain scoped VPC/subnet/security-group/route-table/ACL/DHCP controls through
  typed memory and SQLC SQLite repositories. Replay native lifecycle, wire,
  pagination and token fixtures across reopen and the actual AWS CLI executable.
- [x] Resolve captured physical-zone metadata through Account-owned region
  enablement rather than invented zone IDs.
- [x] Retain ECS clusters, task-definition revisions and tags; enforce IAM/PassRole,
  native latest-active selection and deletion admission. Reap deleting definitions
  lazily after the deletion request and last active task reference age one
  service-clock hour; this is not AWS's precise removal cadence.
- [x] Commit EC2/ECS API outcomes and VPC service-generated events with resource
  state. Replay native CloudTrail/EventBridge/SQS envelopes; verify documented
  S3 delivery/selector behavior separately from uncaptured native S3 delivery.
- [x] Retain internet gateways, attachment dependencies and active/blackhole route
  transitions. Implement IPv4 ENI address ownership, reassignment, capacity,
  attribute/group mutation and creation outcomes in memory/SQLC SQLite. Enforce
  dependency-specific `ec2:Vpc` policy context; replay native SDK/audit fixtures
  and actual restarted CLI → CloudTrail/EventBridge → S3/SQS delivery.
- [x] Connect ECS linked-role provisioning to IAM with native best-effort denial,
  forwarded caller policy context and dependent audit outcomes. Retain all-region
  active-cluster deletion dependencies through memory/SQLC SQLite; verify native
  fixture replay, cross-account isolation, KMS rollback and executable restart.
- [ ] Resolve ECS regional role-discovery attempt cadence, native automatic
  service-role reclamation timing, global IAM audit-region routing and remaining
  partition templates. Retained captures bound these gaps; do not invent caches
  or immediate cleanup from incomplete observations.
- [x] Execute standalone ECS `RunTask`/`DescribeTasks`/`ListTasks`/`StopTask` with
  typed memory/SQLite task/token state, exact request replay, real dependency and
  health observations, reverse shutdown, task-role metadata credentials and current
  IAM policy. Connect actual logs, transactional EventBridge state events,
  EC2-managed ENIs and native SG/NACL enforcement. Verify real CLI/SDK execution
  and SQLite reattachment without replacing customer processes; see
  [the authoritative runtime contract and evidence](docs/ecs.md).
- [x] Retain Fargate replica service controls, immutable deployments, owned tasks
  and immutable engine image IDs; reconcile scaling, replacement, rolling updates and circuit
  rollback through real containers. Replay native service fixtures on memory/
  SQLite; verify same-PID process restart, two-task rolling replacement and real
  failing-container rollback. See [service boundaries](docs/ecs.md#replica-services).
- [x] Deliver retained EventBridge ECS targets through the real authorized and
  audited RunTask command. Replay native admission, current-role denial, override
  redaction and transformed DLQs; execute static/transformed tasks with actual
  task-role SQS effects. See [target boundaries](docs/eventbridge.md#ecs-tasks).
- [x] Publish real ECS service CPU/memory utilization and minute task counts through
  retained CloudWatch windows. Replay native monitoring admission/deployment
  fixtures, including empty-list model corrections; verify default/high/mixed/
  reset cadence, SQLite recovery, account/region isolation and actual alarm → SNS
  → SQS delivery. Reproduce and prevent late observations reopening closed windows.
  See [service metric evidence and limits](docs/ecs.md#service-metrics).
- [ ] Extend ECS metric evidence to heterogeneous task sizes and multiple
  containers; implement Container Insights and filesystem/Service Connect producers.
- [x] Finish the ECS-backed Application Auto Scaling gate: native target/policy/
  schedule and metric-identity replay, real ECS/CloudWatch linked-role commands,
  retained cooldowns and managed alarms, deployment scale-in exclusion, failed
  schedule progress, and actual container/restart verification. The current
  [behavior and evidence](docs/ecs.md#application-auto-scaling) does not imply full
  service parity.
- [x] Replay expanded native custom-metric ownership across both stores: scalar
  and sole-query equivalence, representation-specific units/dimensions, exact
  multi-query identity and rejected-write alarm preservation. Verify the actual
  CLI path, including empty-label rejection without partial resources.
- [x] Paginate ECS targets, policies and schedules through scoped next-key
  cursors, preserving named-policy traversal, native explicit-limit behavior
  and rejected filter changes. Replay SDK fixtures on both stores; verify
  actual CLI process restart, foreign scopes and deletion of a pending key.
- [x] Retain and expose ECS-backed scaling activities, pending execution,
  real completion/override/failure transitions, suppression and six-week history.
  Replay native SDK fixtures across memory/SQLite and restart; exercise actual
  CLI/container completion, failed scheduling, deletion retention and expiry.
- [x] Add the initial generated ELBv2 IPv4 ALB control/data-plane owner: real
  EC2-managed listener nodes, HTTP routing and target probes, retained health/drain
  state, current IAM, typed memory/SQLC storage and ECS replica target bindings.
  Native HTTP/rule and IAM-backed TLS captures accompany real Docker forwarding,
  unhealthy fail-open/recovery and health-gated deployment evidence.
  Integrated schema225→228 migration preserves an already-running ECS process;
  a separate assembled executable exercises real ALB→ECS forwarding, restart
  and HTTP408 behavior. Retained teardown evidence distinguishes desired state
  from actual task/ENI removal; recovered exact native cleanup passed.
- [x] Calibrate ELBv2 management events against 15 exact native SDK request IDs.
  Preserve query parameters, failures, API version and complete current attribute
  readback; make public creation output authoritative for audit projection.
  Memory/SQLite reopen replay and the actual executable's before/after evidence
  pass. Other ALB audit/identity and advanced attribute behavior remain unverified.
- [x] Retain real ALB request windows and health observations through the existing
  CloudWatch source publication boundary; admit ECS `ALBRequestCountPerTarget`
  policies against current target bindings. Calibrate healthy/fail-open/draining,
  zero-traffic/empty-target and target-zone behavior with bounded native traffic,
  request IDs and exact cleanup. Exercise actual ALB→ECS HTTP, restart-retained
  counts, managed alarms, two healthy replicas, idle scale-in and actual native
  task/ENI retirement in the assembled executable.
- [ ] Complete the remaining ELB enterprise surface: Classic/NLB/Gateway LB,
  IPv6/HTTP2/gRPC, advanced TLS and certificate sources, authenticated actions,
  stickiness, access logs, remaining metrics and distributed zonal behavior.
  Stable resolvable ALB names now use the shared UDP/TCP DNS endpoint, with
  actual hostname HTTP/TLS, subnet-address changes, SQLite reopen and deletion
  verified. Route 53 zones and ACM DNS-validated local certificates now use
  these owners; remaining service boundaries are explicit in their documents.
  Preserve the [bounded ALB contract](docs/behavior-references.md#application-load-balancer-kernel).
- [ ] Complete Application Auto Scaling resource namespaces and predictive
  scaling/forecasts through their owning dependencies.
  Establish native Unfulfilled activity transitions and exact alarm-signal
  freshness; resolve native empty initial target pages with small explicit limits.
- [ ] Complete ECS service dependencies, public revision registry digests and
  remaining placement/capacity branches,
  external volumes, ExecuteCommand and other rejected
  runtime settings. Enforce task disk quotas (the default 20 GiB is not enforced;
  custom quota requests are rejected), native blocking awslogs backpressure and
  broader network/recovery semantics; establish credential-vending SourceArn.
  The local Fargate default deliberately differs from native empty-strategy EC2.
- [x] Resolve ECS Linux S3 environment files and direct Secrets Manager values
  through current execution-role S3/KMS/secret authority. Real Docker tasks verify
  precedence/overrides, current and selected secret versions, denied initialization,
  new-task source updates, no stored plaintext and retained native-container
  reattachment across SQLite restart. External volumes and other rejected runtime
  dependencies remain open.
- [x] Attribute authenticated task-role SDK requests to retained task ancestry,
  including credentials cached by surviving containers across controller restarts.
  Store the origin with the issued credential, apply it only after signature
  verification, and preserve current IAM policy and active Lambda precedence.
- [x] Implement EC2 public IPv4/EIP allocation, association, live reassociation,
  lifecycle and current IAM through one typed memory/SQLC address owner. Reuse it
  for ECS managed ENIs, Describe/IMDS/DNS and native guest/task `/32` routing,
  inbound DNAT, return mapping and assigned-only egress. Exercise real firmware
  guests, native SG/NACL denial, SQLite reopen and exact cleanup; retain fresh
  native address captures separately from local packet evidence.
  Native IAM condition matrices and exact-request CloudTrail replay additionally
  cover explicit launch-field presence, allocation/public-IP authority, successful
  launch projections and EIP audit envelopes. Packet review proves private-flow
  conntrack preservation and both public/private overlap creation orders.
  Daemon-side lock-held admission and operation ownership survive controller
  SIGKILL/cancellation without stale helper mutation or in-flight bridge races.
  Corrected schema 224→225 executable migration preserves the original ECS
  container through public-address backfill and a second restart, with real
  private/public HTTP and retained IAM/SSM/EventBridge/CloudFormation/SQS state.
  The initial missing-native-chain failure and subsequent exact cleanup remain
  recorded separately from the passing upgrade.
- [x] Retain EC2 launch-template/version controls in typed memory/SQLC schema 229,
  including native inheritance, selectors, warnings, monotonic versions,
  idempotency, tags and exact-request management-audit replay. Consume resolved
  templates through ordinary RunInstances admission, current IAM/PassRole and
  protected launch-origin tags. GetLaunchTemplateData reads current owners and
  enforces documented dependent describe permissions. See [the boundaries and
  evidence](docs/ec2.md#launch-templates-and-instance-admission).
- [x] Complete the EC2 Auto Scaling kernel integration gate: generated Query
  transport, typed schema 231, current-caller EC2 admission, service-linked real
  launches, retained lifecycle actions, policy/schedule decisions and actual
  ALB/CloudWatch/EventBridge workflows across executable restart.
  Native control fixtures replay through signed SDKs on memory/SQLite; native
  lifecycle/failure captures calibrate the actual firmware-guest workflows.
  Reviewed suspension,
  notification rejection, zero-grace initialization health and protected
  retirement paths are exercised. Accepted capacity and registered operations
  still do not establish native completion or complete ASG parity.
- [x] Retain actual ASG guests after abandoned termination hooks, cancel the
  corresponding activity and replace excluded capacity. Re-enter hooks on
  manual/force release; enforce retention-aware force/protection/decrement
  admission and support live detach. Calibrate native total/retained gauges and
  audit exceptions; verify unchanged guest boot/root across SQLite restart,
  pre-hook ALB drain, actual replacement HTTP and final retirement/cleanup.
- [x] Implement generated warm-pool controls and typed schema 237 through the
  existing EC2, lifecycle, IAM, ALB and metric owners. Calibrate native sizing,
  suspended launch, reuse, retained hooks and force deletion. Exercise actual
  Stopped/Running/Hibernated guests, SQLite recovery, pre-hook target drain,
  instance-only warm CPU series and owned-resource cleanup.
- [ ] Calibrate retained multi-hook ordering, policy changes during a waiting
  action, unhealthy retained mutations and broader weighted metric behavior.
- [x] Implement scaling-activity lower/upper time filters from native owned
  histories, including timestamp/error and selection semantics. Fixture replay
  and an actual signed executable call pass. The changed-filter continuation
  boundary anomaly remains explicit in the ASG contract.
- [x] Implement the rolling instance-refresh kernel with typed schema 239,
  current EC2/IAM admission, retained rollout/rollback progress and configuration
  commit fencing. Exercise actual ALB-backed guests through replacement, baking,
  unchanged boot across SQLite restart, rollback, a subsequent successful
  rollout and complete owned-resource cleanup. Retire native DHCP leases before
  recycling guest addresses; do not duplicate the daemon's lease state in Go.
- [x] Run custom ASG termination policies through the real Lambda Runtime API,
  current execution authority and a two-second deadline. Verify empty/error/
  timeout/protected/foreign selections retain actual guests; after restart,
  current authority still denies selection. Preserve built-in ordering,
  lifecycle hooks, surviving guest traffic and unhealthy replacement behavior.
- [ ] Complete ASG mixed-instance/root-volume refresh, mixed/Spot capacity, predictive/metric-math
  policies, legacy launch configurations,
  Classic ELB/non-ELBv2 traffic-source dependencies, instance-derived creation,
  explicit zone-ID placement, allocation/launch-configuration termination policies,
  AZ rebalancing/failed-zone fallback. Calibrate
  sustained EC2 impairment before replacement and consume scheduled/application
  health signals when their EC2 owners exist.
  Actual EC2 CPU/network group series now drive predefined tracking; the
  telemetry fixtures below retain basic/detailed cadence and two-guest proof.
  [The ASG contract](docs/ec2.md#ec2-auto-scaling) owns evidence and exclusions.
- [ ] Complete EC2 instance execution, advanced attachment/connection controls,
  secondary-address/multi-ENI guest networking, public pool/recovery/transfer
  families, VPC DNS/nonlocal routing, overlapping bridge support, remaining
  route-target families, IPv6/IPAM and delegated prefixes.
  Implement true per-emulator native isolation across bridge, TAP, packet-policy
  and container identities together. Current ARN-derived sharing is not
  database isolation, and host CIDR overlap is not isolated VPC networking;
  native locking and IPAM consistency checks do not complete this boundary.
  Expand physical-zone/partition coverage; resolve creation-token lifetime,
  blank/case-only native anomalies,
  and unmeasured pagination scope/ordering. Core EC2 remains partial.
- [x] Implement EC2 key-pair generation/import/discovery/deletion with real RSA
  and Ed25519 material, PEM/PPK formats, native fingerprints and name-based IAM
  authority. Retain public metadata/tags in schema 186 without private keys.
  Replay native fixtures across memory/SQLite and exercise actual CLI restart
  with independent OpenSSH/PuTTY consumers; preserve rejected-upload audit
  confidentiality explicitly. See [key-pair behavior](docs/ec2.md#key-pairs).
- [x] Generate and implement the six EBS direct APIs with real sparse blocks,
  checksums, parent layers, scoped tokens, terminal states and typed schema 187.
  EC2 consumes one snapshot owner for describe/delete/tags and regional encryption
  defaults. Enforce request/parent/owner IAM and actual KMS data-key operations;
  retain child KMS audit outcomes across command rollback without retaining state.
  Replay native SDK fixtures and restore an encrypted ext4 filesystem after
  parent deletion and executable restart; inspect actual CloudTrail S3 data/
  management records and EventBridge SQS delivery. See
  [snapshot behavior](docs/ec2.md#ebs-direct-snapshot-data-plane).
- [x] Retain shared-snapshot permissions, recipient tag namespaces and publication
  in typed schema 188. Enforce current identity/session/KMS authority and actual
  owner conditions, owner-only direct writes/parents, public-read restrictions
  and token revocation/re-sharing. Add EC2 attribute/public-block controls and
  published Organizations snapshot overrides; retain native paired audit
  attribution without changing request resource-account fields. Capture native
  SDK behavior and exercise real cross-account bytes across executable restart.
- [x] Implement independent regional/cross-account EC2 snapshot copies through
  the shared EBS owner and schema 189. Preserve actual sparse bytes/lineage,
  source/destination IAM, destination tags and real constrained KMS service
  grants. Emit native transactional completion notifications and paired
  tag-redacted management records; retain bytes/tokens across executable restart.
- [x] Build actual EBS volume creation, snapshot hydration, retained disk contents,
  modification/deletion and volume-to-snapshot consumers through schema 190.
  Replay native lifecycle, IAM/KMS, token, initialization, event/audit and real-byte
  fixtures on memory/SQLite; verify source deletion, volume deletion, retained
  tokens, snapshot copying and delivery across executable restart. Guest
  attachments remain separate; opaque identifier encoding is deferred below.
- [x] Move EBS snapshot copy, volume hydration and standalone volume-snapshot
  payload work out of admission transactions. Retain typed source ownership and
  admitted KMS authority in schema 238; use destination block rows for restart.
  Preserve the capture edge across source deletion and native handoff, reject
  partial reads/boot, reclaim obsolete blocks and finish revoked-grant cleanup.
  Anchor snapshot readiness and deadline outcomes to actual payload completion.
  Signed memory/SQLite recovery fixtures and a standalone reopened-SQLite
  HTTP smoke recover exact bytes while an unrelated SQS mutation succeeds.
- [ ] Implement opaque native long snapshot-ID validity encoding when its general
  contract is established. Explicitly deferred by the user: 310 read-only/DryRun
  probes found digit-dependent rejection beyond public length/hex syntax but no
  safe decoder. Keep raw/derived identifier fixtures and the explicit replay skip;
  do not blacklist example IDs or report exact malformed-ID parity.
- [x] Retain typed AMI registration, discovery, attributes and private sharing in
  schema 191, with EBS-owned snapshot references and native SDK fixture replay.
  Registration is not proof that an arbitrary image can boot on the local hardware.
- [ ] Implement opaque AMI-ID validity encoding when its general contract is
  established. Explicitly deferred by the user; retain the native
  `images_sharing/describe-unknown-valid-id` discrepancy and its single replay
  skip rather than blacklisting the captured identifier.
- [x] Generate the regional instance-type catalog from retained native captures
  and replay selection/admission through the generated SDK frontend. Catalog
  facts do not imply that every architecture or hardware family executes locally.
- [x] Generate IMDS version/category gates from all 31 captured native versions;
  replay HTTP authentication/version precedence and current ENI-derived values.
  A real Ubuntu guest consumed its SSH key and cloud-config through required
  IMDSv2. Additional owner-backed metadata and signature work is recorded below.
- [x] Establish a single native mutable-volume byte authority after hydration.
  Real plaintext/LUKS sparse read/write and grouped-backup regressions preserve
  actual bytes after source deletion; one native session avoids per-block LUKS
  unlocks. Guest lifecycle and AMI workflow verification remain separate.
- [x] Execute firmware-booted EC2 guests through QEMU/KVM and retained instance/
  reservation/image state. Verify real Ubuntu cloud-init and SSH, profile-vended
  STS identity, encrypted hot attach/detach and live snapshots, controller restart,
  stop/start, both CreateImage reboot modes and derived-AMI boot after deleting
  the source instance. Deliver lifecycle events to SQS, measured CPU credits to
  CloudWatch and redacted/EC2-scoped audit records to CloudTrail S3 logs.
- [x] Exercise UEFI boot, explicit reboot and stop/start persistence through AWS
  SDK for Go v2 with an actual Ubuntu guest. Distinguish firmware flash from NVMe
  attachments using real QMP discovery; retain native startup diagnostics.
- [x] Implement launch-configured EC2 hibernation using real Linux S4 on encrypted
  EBS roots, guest-agent readiness and fresh firmware resume. Retain configuration
  in schema 236; calibrate native admission, ordinary-stop fallback and type
  mutation. Preserve an actual guest's boot ID, PID, RAM nonce/counter and root
  through warm-pool hibernation and controller restart, without a host VMState
  image. Preserve full disk/network attachment capacity with the guest agent.
- [x] Observe actual guest ARP, host attachment and live NVMe I/O health; retain
  continuous failure/recovery across SQLite/controller restart and contribute
  real minute CloudWatch status metrics. Exercise encrypted Ubuntu execution,
  SG-independent health, host-network loss, actual QEMU EIO and stop/start.
  Native captures establish NIC-loss/recovery and status request boundaries;
  local sampling does not reproduce AWS's delayed publication sequence.
- [x] Implement scoped EC2 instance-profile association/replacement/disassociation
  and discovery with generated native DryRun/page-size corrections, IAM/PassRole,
  retained delivery references and schema 198. Replay signed SDK fixtures across
  memory/SQLite and exercise actual Ubuntu role-specific S3/EC2 permissions,
  controller restart and credential removal after disassociation.
- [x] Expand generated IMDS history/leaf gates, HTTP methods and zero-TTL behavior;
  retain launch/start device metadata independently of hot attachments. Native
  secondary-device fixtures establish ebs1=sdf. Exercise actual guest tag/tag-set,
  historical path and stop/start behavior; restore listeners at controller startup
  without advancing manual service time or lifecycle deadlines.
- [x] Implement the user-approved local EC2 identity authority with real raw RSA
  and DSA/RSA CMS signatures, explicit public certificate export and retained
  schema-199 keys. Verify sanitized/local signatures independently with OpenSSL,
  reject changed documents/wrong certificates, and verify real Ubuntu identity
  across controller and guest restarts. These are not AWS-certified identities.
- [x] Expose actual QEMU VGA screenshots through generated GetConsoleScreenshot,
  current IAM/DryRun admission and native read-only audit projection. Exercise
  guest pixel changes, real WakeUp keyboard input, controller restart and
  transaction-bound IAM reads through the signed SDK.
- [x] Separate EC2 credential validity from profile publication: issue the observed
  6h35m service lifetime independently of IAM MaxSessionDuration, retain issued
  credentials through profile/trust changes, and enforce their own expiration.
  Commit empty/denied delivery state without aborting the shared transaction;
  exercise actual guest metadata/permissions and memory/SQLite recovery.
- [ ] Complete native EC2 profile/intrinsic credential lifetime distributions,
  publication and prior-key validity through lifecycle changes, intrinsic-info
  refresh, opaque association-ID admission and pagination-token binding.
  Initial deliveries do not establish native long-lived rotation timing.
- [x] Establish native tag-metadata publication behavior without inventing a
  second state owner: reuse current tags where AWS specifies no minimum lag.
  Replay settled update/add/remove/disable/re-enable/empty outcomes; verify real
  guest HTTP 404 versus empty tag-set behavior and pending metadata-option
  acceptance, including no-op requests.
- [x] Issue intrinsic instance credentials through shared IAM authority without
  fake role records, enforce native STS/SQS service restrictions independently
  of attached-profile grants, and retain native issuer/EC2 CloudTrail scope.
  Schemas 200/201 retain references, independent info time and typed credential
  origin. Exercise actual Ubuntu metadata, signatures, policy controls, expiry,
  controller restart and stop/start.
- [x] Implement IMDS-version-specific credential delivery and ec2:RoleDelivery
  policy/audit context through existing IAM authority, independent references
  and schemas 202/203. Replay native v1/v2 material and permission contrasts,
  retained-v1 validity after requiring v2 and 18 CloudTrail request-ID joins.
  Verify actual guest Go SDK calls, SQLite upgrade, frozen-clock restart and
  version-preserving expiry/refresh.
- [x] Carry attached-profile ec2:SourceInstanceARN,
  aws:Ec2InstanceSourceVpc and aws:Ec2InstanceSourcePrivateIPv4 through existing
  trusted IAM session context, without inventing VPC-endpoint request keys.
  Replay the native v1/v2 twelve-queue condition matrix in memory/SQLite and
  verify current/retained credentials from an actual Ubuntu Go SDK guest
  across controller restart. Reuse native probe CLI setup and retain the
  SQS resource-policy admission rejection separately.
- [x] Reconcile native transient-unit collection during EC2/ECS cleanup using
  the shared systemd stop boundary. Preserve command diagnostics and transport/
  helper-cleanup failures; verify actual native stop, collection race, surviving
  unit failure, cleanup failure and ownership rejection.
- [ ] Implement the documented intrinsic Instance Connect, GuardDuty, SSM,
  Lambda Managed Instances and AgentCore consumers.
- [ ] Complete conditional metadata owners for maintenance/Spot/Auto Scaling,
  IPv6 and multi-card networking. Historical tag lag and settled
  observations remain evidence, not a fixed propagation-delay requirement.
- [ ] Complete scheduled/application status checks, automatic recovery, native
  publication behavior and opaque long-instance-ID admission. The latter is a
  distinct gap from the explicitly deferred AMI/snapshot encodings.
- [ ] Complete remaining IMDS categories, additional architectures/hardware and
  unsupported launch/monitoring/network options before claiming broader EC2 parity.
- [x] Implement retained CPU-credit transitions across instance families and
  reduced accrual caps without resetting/clamping earned balances. Native
  T3/T3a/stopped M5/T2 captures exclude complete resets; actual local M5/nano
  execution verifies changed guest memory and a retained above-cap balance.
- [x] Publish actual EC2 vCPU/TAP measurements into CloudWatch with retained
  basic/detailed periods, isolated group dimensions and pre-retirement
  checkpoints. Replay native monitoring/IAM/DryRun transitions; verify actual
  guest traffic, controller reopen, CPU-driven desired-capacity growth and the
  schema-231 upgrade through signed SDKs.
- [ ] Complete remaining native EC2 disk/packet/EBS performance metrics and
  calibrate monitoring-subscription and subminute group-membership timing.
- [ ] Capture native above-cap conservation, seven-day credit expiry, running
  T2/fixed-performance detours and T4g/T8i transitions. Existing positive-balance
  captures do not establish exact conservation or these unmeasured boundaries.
- [ ] Complete volumes/attachment/AMI consumers, archive/lock/fast-restore,
  Outpost/Local Zone copy placement, noncommercial regional EC2 KMS grants,
  native disabled-key/cache propagation and asynchronous default-key admission.
  Six direct operations and regional copies are not full EBS/EC2 parity.

Current behavior and native provenance: [EC2](docs/ec2.md), [ECS](docs/ecs.md).

## Cross-service tag inventory

- [x] Generate Resource Groups Tagging API contracts and implement all nine
  modeled operations over existing service-owned tags, current dependent IAM,
  retained previously-tagged membership and native per-resource failures.
- [x] Consume published Organizations policies and account Region admission for
  compliance summaries/required tags; deliver retained reports through actual
  S3/KMS authority. Verify native owner round trips, mixed authorization,
  explicit deletion/recreation, encrypted CSV bytes and failed-report recovery
  across three executable controller starts.
- [x] Complete dependent SSM document tag controls and CodeBuild fleet tag updates
  through their native owners; preserve unsupported fleet compute transitions.
- [ ] Calibrate native organization-wide reports, compliance-cache timing and
  asynchronous-deletion/recreation indexing semantics. Current observations
  cover named native controls and local workflows, not exhaustive service parity.

## DynamoDB dependency kernel

- [x] Generate DynamoDB and Streams frontend contracts; route implemented table,
  item, transaction and PartiQL operations through generated SDK wire shapes.
- [x] Retain scoped control intent, tags and bound resource policies in typed
  memory/SQLC repositories. Map case-distinct names to opaque native identities.
- [x] Run pinned DynamoDB Local behind an injected runtime, observe actual
  readiness, retain native data across executable restart and own volume cleanup.
- [x] Dispose CLI-owned DynamoDB engines on graceful in-memory shutdown while
  retaining SQLite-backed engines. Verify actual container/volume removal and
  native item reads after a retained executable restart.
- [x] Replay selected native controls, conditional old items, transaction
  cancellation/rollback/token replay, fine-grained IAM and principal rebinding
  through SDK clients on memory and SQLite.
- [x] Delete expired native items using service time and conditional writes,
  ignoring wrong types, future timestamps and values more than five years old.
- [x] Apply table/GSI read/write scaling bounds through the real linked role and
  resource owner; observe actual completion and retain targets after table deletion.
- [x] Bind PartiQL continuations to the table generation, exact statement and
  ordered parameter values; allow changed limits and consistency, including
  continuation after retained-store reopen.
- [x] Own item-size, projected-index and transaction capacity accounting rather
  than trusting the backend's reported write totals. Replay retained original-size
  token charges, canceled request identity, numeric/default equivalence and
  conditional old-image charges across memory/SQLite reopen.
  PartiQL replay covers ordered evaluated pages, singleton-IN batch reads, mixed/
  all-failed writes and duplicate transaction charges without billing auxiliary reads.
- [x] Capture native table/read/write/key-range throttling and GSI backpressure,
  including unchanged index projections, mixed transactional/PartiQL failures,
  rejected-mutation absence and fresh provisioned large-item admission.
  Retain exact reasons/resource ARNs and cleanup; do not infer a fixed bucket
  or deterministic throttle ordinal from concurrent AWS observations.
- [x] Capture sustained fresh-table pressure beyond five minutes, native partial/
  all-throttled BatchWriteItem, transactional sibling effects, complete PartiQL
  metric dimensions and the original 16 MiB batch wire boundary.
- [x] Enforce bounded provisioned table/GSI admission under the native data gate,
  before mutation; permit positive-credit operations to overdraw rather than
  rejecting every large item. Preserve invalid/partial batch and transaction
  boundaries, GSI backpressure, service-time recovery and actual scaling changes.
  Retain operation/Verb/OperationType throttle metrics across memory/SQLite reopen.
  This process-local model is not AWS's private distributed/partition allocator;
  admission balances reset on restart.
- [x] Admit BatchGet keys within a table under pressure, preserving native whole-
  request validation and size boundaries. Retry original projection/consistency
  settings, charge only processed keys and preserve successful empty responses
  for processed missing items. Verify both stores and actual retained CLI metrics.
- [x] Own configured on-demand table/GSI maximums, independent read/write updates,
  removal and billing-mode transitions. Reuse the shared admission owner; preserve
  native scalar/transaction/PartiQL error distinctions and reason metrics.
  Capture native controls and rejected composite effects; verify both stores,
  actual executable recovery and retained CloudWatch counters/gauges.
- [x] Enforce independent provisioned table/GSI decrease quotas and atomic
  rejection of combined or unchanged updates. Retain settled counters/history
  across billing changes; distinguish the GSI reduction to zero from table history.
  Verify hourly/UTC-day service-time behavior and SQLite pending-update recovery
  with an actually paused native engine, without a second quota ledger.
- [x] Enforce retained rolling on-demand billing quotas, including the creation
  slot for on-demand-born tables. Preserve no-op history, native pending metadata,
  scoped resource lifetimes and service-time expiry across SQLite reopen.
- [x] Retain typed on-demand backup intent and source metadata while copying real
  native items under the mutation gate. Restore selected indexes and independent
  data after source deletion, stream expiry and memory/SQLite reopen; preserve
  duplicate backup identities and explicit-empty index exclusion.
- [x] Enforce backup/target restore authority without requiring CreateTable, keep
  pending restore references and the fifty-distinct-source concurrent limit across
  restart, and publish restored throughput/billing history at native completion.
  Actual CLI recovery preserves a multi-page snapshot through interrupted
  capture and restore rather than declaring metadata-only success.
- [x] Preserve native index renames while rejecting changed backed-up keys or
  projections without creating targets. Resolve backup metadata and deletion
  authority in the signed endpoint region, including altered-ARN pending restore
  protection and native response echo behavior.
- [x] Generate and validate native fourteen-digit/eight-hex backup identities.
  Preserve case-sensitive identity and literal restore-region admission while
  validating known ARN regions through the generated SDK partition catalog.
  Reuse table-name validation and preserve native foreign-account rejection
  precedence without inventing an additional account-format gate.
- [x] Replay native backup management audit documents and distinct LookupEvents
  aliases. Bind generated rejected DTOs only for service-owned redacted audit
  projection; invalid commands remain unadmitted.
- [x] Reject concurrent restores from an AVAILABLE but busy backup, preserve the
  source reservation across memory/SQLite reopen, distinguish a pending target,
  and release the source only after native restore completion.
- [x] Match native inclusive backup time bounds after millisecond normalization,
  including equal ranges and reversed-bound validation before backup-type filtering.
- [x] Publish captured base/index restore increase history independently at the
  observed read-capacity boundary, alongside native decrease counts and timestamps.
- [x] Enforce documented nominal backup control request rates in service time,
  before generated validation, with account/region/operation isolation. Preserve
  native throttled CloudTrail events without request fields, resources or API
  version, and prove recovery and concurrent admission through the executable.
- [x] Retain PITR interval baselines and real item postimages across memory and
  SQLite, including scalar, batch, transaction, PartiQL and TTL mutations.
  Resolve interrupted native writes from actual key reads, without replaying
  customer expressions; preserve TTL time across native-handle failure/reopen.
- [x] Restore historical data and indexes with current source capacity settings.
  Pin time and sequence for frozen-clock admissions, preserve pending-copy
  tombstones, and compact expired history without resurrecting shortened windows.
- [x] Produce real SYSTEM backups on PITR-enabled deletion, filter type before
  pagination, reject manual SYSTEM deletion, and retain expired snapshots while
  accepted restores complete. Verify independent USER snapshots and disabled
  source deletion.
- [x] Replay native continuous-backup and restore CloudTrail documents, including
  distinct document resources, lookup aliases and invalid-retention omission.
  Verify historical and deleted-source data through CLI after SQLite restart.
- [ ] Complete native cross-connection backup request allocation and
  cross-region KMS restoration.
- [x] Model initial continuous-backup registration independently of table ACTIVE.
  Reject valid enable and no-op disable while unavailable; retain generated
  validation precedence and distinguish registration from physical restore
  readiness. Verify passive service-time readiness and SQLite reopen.
- [ ] Complete physical scan/query-partition overhead and remaining admission:
  account-default on-demand and key-range limits.
  The pinned backend's topology and measured accounting are not an AWS oracle;
  native token expiry still follows real time, not the service clock.
  Native numeric-partition replay retains the observed three-unit versus local
  two-unit discrepancy; compound scan replay excludes physical scan charges.
  Data/pagination replay is not capacity-parity evidence.
- [x] Traverse ordered partition/range alternatives and unordered finite-key reads
  through native Query/GetItem calls, with typed ordering, branch-local filters,
  per-range accounting and a shared evaluated-item/megabyte page budget.
  Native fixture replay covers missing/duplicate keys and memory/SQLite reopen.
- [x] Share native query eligibility between PartiQL IAM and execution. Different
  compound conditions scan rather than intersecting into Query; repeated
  equivalent scalar conditions remain queries. Preserve absent FullTableScan
  context and native authorization/validation precedence, verified with scoped
  IAM fixture replay on both stores and actual executable requests.
- [x] Expose retained Streams with native record identities/images and atomic
  ingestion checkpoints; replay native rotation, disabled generations and reopen.
  Verify TTL identity and iterator/disabled-stream expiry through the executable.
- [x] Replay selected native audit projections through configured CloudTrail S3
  logs, EventBridge SQS delivery and Event History on memory and SQLite.
- [x] Retain TTL origin across the native-write/capture failure window; reproduce
  the old identity loss and verify real-native failure/reopen boundaries on both stores.
- [ ] Handle uncaptured native records lost during downtime beyond native retention.
- [x] Connect role-authorized Lambda stream delivery, retained checkpoints and
  source/outcome CloudWatch counters. Keep native metric absence distinct from
  a measured zero; see [DynamoDB source behavior](docs/lambda.md#dynamodb-streams-event-source-mappings).
- [x] Retain DynamoDB minute consumption and provisioned gauges, publish through
  CloudWatch without customer PutMetricData authority, and drive native-shaped
  table/GSI target-tracking and maintenance alarms through the linked role.
  Verify actual read-capacity scaling from two to five and retained-store recovery.
- [ ] Complete remaining producer/error and PartiQL pagination accounting
  boundaries before claiming full DynamoDB metering parity.
- [x] Capture native version-2019 replica creation, bidirectional item changes,
  regional settings overrides, demotion and verified cleanup in both Regions.
  Keep the failed unstabilized IAM follow-up separate from authorization evidence;
  see [native observations](docs/behavior-references.md#global-table-replica-observations).
- [x] Capture stabilized native replica permission contrasts with explicit CLI
  session credentials, and competing writes that distinguish successful no-ops
  from actual changes. Retain invalidated raw samples as such, not as IAM evidence.
- [x] Implement same-account version-2019 replica bootstrap, retained item delivery,
  settings/TTL propagation, regional overrides and independent regional controls.
  Reuse native mutation capture for transactions, batches, PartiQL and recovery;
  enforce current SLR authority and preserve native data through SQLite restart.
- [x] Exercise authorization repair and settled-replica twenty-hour detachment,
  no-op conflicts, independent membership transitions, and delivery before final
  normal member removal through fixture-based real-engine SDK workflows.
- [x] Capture all four inherited global-table stream views and provisioned scaling
  contrasts. Require table/GSI write policies for replica creation; copy registered
  read/write scaling through its owner, without a second scaling repository.
  Keep service-driven capacity changes regional and ordinary customer settings
  synchronized; preserve the shared transaction without engine-lock inversion.
- [x] Capture fresh global-table billing transitions and implement native scaling
  replacement through the existing owner. Preserve visible on-demand targets and
  policies; recreate provisioned defaults after real engine observation, with
  native customer-forwarded deletion and replication-role registration.
  Verify target identity/flags/tags, custom-policy replacement and retained reopens.
- [x] Enforce native combined replica/settings exclusions before resource lookup
  or either mutation. Preserve attribute-definition and empty-index-list semantics;
  exercise all three replica actions through SDK fixtures and actual CLI controls.
- [x] Observe settlement of the native combined-control probe, repeat rejected
  Update/Delete combinations while ACTIVE, and verify peer-first removal of both
  regional tables. Preserve the initially exhausted observation bound as history.
- [x] Implement replica-autoscaling descriptions and updates through the existing
  scaling owner. Preserve pre-update responses, policyless/on-demand views, target
  identity and suspension, replacement rather than merge, and dependent-command
  partial effects. Enforce replication-role configuration and customer-attributed
  removal without requiring the caller's public autoscaling authority.
  Replay the native contrasts on both stores and through actual CLI restarts;
  verify CloudTrail response projection and dependent actors.
- [x] Match native legacy-global retirement, global-plus-regional IAM admission,
  separate legacy enumeration, and management-event projection. Verify that
  rejected legacy calls leave current replicas and their data delivery intact
  through real engines, both stores and executable restart. Historical legacy
  state is not fabricated when AWS rejects every new legacy group.
- [x] Capture native Kinesis controls, record/consumer streams and DynamoDB
  destination admission/delivery. Verify transactional no-op distinctions,
  asynchronous failures, role-authorized retry and binary/timestamp envelopes.
  Exercise imported engines for crash recovery, large records and clock ownership;
  retain their failures and select pinned Kafka for durable Kinesis record bytes.
  See [streaming evidence](docs/behavior-references.md#kinesis-streaming-dependency-evidence).
  Implemented controls, data/consumer commands, KMS, source metrics and typed
  memory/SQLite metadata do not establish complete Kinesis semantics.
  DynamoDB destinations use actual mutation capture and their service-linked
  role; EventBridge targets use ordinary authorized Kinesis commands.
  Native fixture replay, real-engine recovery and executable workflow verification
  own evidence, not the operation-registration count.
- [x] Consume Kinesis streams and enhanced-fan-out consumers through the shared
  retained Lambda stream engine. Capture native authorization, KPL, filtering,
  retries, failure destinations, oversized batches and split/merge behavior.
  Keep independent shards concurrent and wait for both merge parents. The
  executable Logs → Kinesis → real Lambda → SQS chain recovers after restart.
- [x] Match delivered native Kinesis data events and consumer registration history,
  including selectors, payload omission and separate display/lookup resources.
  Replay observed metric distributions, idle absence and empty EFO minutes across
  memory/SQLite; remove synthetic idle deadlines. Verify real five-second frames
  and pending metric publication through an executable process restart.
- [x] Replay 142 delivered Kinesis control/data audit events and 130 native history
  observations, including monitoring/resharding responses, name/ARN aliases,
  deregistration, encryption key aliases and denied/missing-resource contrasts.
  Verify selected S3/EventBridge delivery after an executable SQLite restart.
- [x] Replay captured EFO frame boundaries, aged backlog, five-minute EOF and
  client-disconnect metrics with real Kafka across memory/SQLite. Preserve active
  reads after consumer deregistration while rejecting new admissions. Verify
  delayed first heartbeats, large frames, renewal, deregistration and stream
  deletion through the executable.
- [ ] Complete Kinesis metadata/routing propagation, adaptive on-demand capacity,
  universal EFO packing/burst bounds and account-setting/warm-throughput audits.
  Modeled-error/closed-shard terminal metric behavior and exact approximate-age
  rounding remain unmeasured; captured frame shapes do not establish these.
  Complete native cross-account/encryption consumer evidence through actual
  command owners; registration is not service parity.
- [x] Generate Firehose wire contracts and implement typed stream lifecycle,
  versioned S3 destinations, tags and direct ingestion over shared memory/SQLC
  SQLite. Enforce native role trust/external ID, PassRole and tag conditions.
- [x] Deliver retained DirectPut/Kinesis-source bytes through authorized S3;
  recover denied reads/writes and prepared buffers across restart. Reuse Logs
  diagnostics, direct subscription producers and weighted CloudWatch samples.
  Replay native record/batch boundaries and actual Kafka-backed source behavior.
- [x] Emit native Firehose management and read-only producer data events with
  payload omission, rejection distinctions and exact selector resource types.
  Verify retained S3/EventBridge delivery and management-history separation.
- [x] Replay captured Firehose compression framing, extensions, delimiter controls
  and timestamp expressions against independently decoded native S3 objects.
- [x] Run Firehose Lambda processing through real runtimes; retain independent
  primary/error/raw-backup obligations, original-byte metrics and permission
  recovery across SQLite restart without rerunning completed processing.
- [x] Deliver EventBridge payloads through authorized Firehose PutRecord, retaining
  the configured target ARN while resolving execution in the native rule Region.
- [x] Share KPL decoding while retaining Firehose child subsequences and the
  Lambda standard/EFO distinction. Commit deaggregated originals and their source
  checkpoint together; preserve original bytes through processing and backup.
- [x] Implement trusted Logs-origin admission, native decompression controls and
  fixed decompression/extraction/Lambda ordering. Retain independent source-failure,
  Lambda-failure and backup obligations. Verify the executable Logs/Kinesis paths
  with real Lambda and two SQLite restarts, recovering backup before other outputs.
- [x] Capture nonzero processing retries, fresh invocation IDs with stable record
  IDs, malformed responses, actual timeout/oversize failures, repeated-Lambda
  rejection and KPL source envelopes. Capture and independently decode large
  multiblock ZIP/Snappy objects and exact native Logs extraction/delimiter bytes.
- [ ] Complete remaining Firehose processors, Java/CLDR timestamp behavior,
  stream encryption, format conversion/dynamic partitioning, non-S3 destinations, other
  sources and throughput admission. Establish alias-transition and exact runtime
  limit behavior. Calibrate mixed-age expiry, source recreation,
  source/DataFreshness/decompression metrics and uncaptured propagation/packing.
  See [Firehose boundaries](docs/firehose.md).
- [ ] Complete MRSC, witness, multi-account and noncommercial replication;
  encryption; and authorization expiry during initial replica creation or
  partially applied settings transitions.
- [ ] Complete remaining lifecycle, AWS Backup, replication, encryption,
  audit-delivery and service-dependency behavior. Run the combined integration
  gate after integration, not as the development loop.

Evidence and current boundaries:
[DynamoDB references](docs/behavior-references.md#dynamodb-engine-references).

## Build complete offline application paths

Build from core dependencies outward. Finish state machines, authorization and
cross-service behavior for the active area before adding bespoke services. An API
handler or a successful SDK decode does not establish semantic parity.

IAM remains incomplete. The explicitly deferred SMTP/OTP and hardware/FIDO MFA
work does not block other core services. Prioritize common KMS application paths:
symmetric envelope encryption, policies/grants, key lifecycle and rotation, and
cross-service encryption. Use the primary AWS contracts and native evidence in
[the KMS guide](docs/kms-cryptography.md). SM2/China-only algorithms,
custom HSM/external key stores, enclave attestation and further specialist
ML-DSA conformance are lower priority and do not block core-service progress.
Existing partial IAM, SQS, STS and Organizations work
remains open and is not evidence of service completion.

SQS currently implements all modeled API operations, with actual standard/FIFO
delivery, visibility, retention, DLQs/redrive, policies and SSE-SQS/KMS encryption.
Standard fair queues prioritize quiet tenants using concurrency and retain noisy
classification through a service-time recovery period. It remains open for
processing-time fairness, metrics, quotas, timing fidelity and durable recovery.
See [delivery behavior and AWS evidence](docs/sqs-delivery.md).
KMS implements symmetric encryption, all four HMAC sizes and
RSA 2048/3072/4096 encryption, signatures and data-key pairs, with key state,
policies and grants. It also supports NIST P256/P384/P521 ECDSA/ECDH, secp256k1
ECDSA, Ed25519/Ed25519ph and their data-key pairs, plus all three ML-DSA sizes
with RAW/external-μ signing and verification. [Cryptography evidence](docs/kms-cryptography.md)
distinguishes native captures from local checks. Generated symmetric material
now rotates automatically and on demand while preserving old ciphertext and
queue data keys. Multi-Region keys share material and rotation, with regional
access controls, promotion and ordered deletion. Symmetric, HMAC, RSA and ECC
imports use actual key bytes, scoped wrapping parameters, expiry/reimport and
shared multi-Region rotation. SM2, durable
storage and remaining conformance are open.

- [x] KMS IAM/STS grant identities, exact-session versus role policy limits,
  immutable deletion/recreation bindings, principal filters, named retries and
  caller-account grant trust. Native captures verify delegation and cross-account
  retirement; SDK tests exercise retained storage and encrypted SQS delivery.
  See [grant evidence](docs/kms-grants.md).
- [ ] KMS service-principal grants and trusted SourceArn constraints with actual
  service consumers; grant propagation, quotas and remaining validation/error/
  partition conformance. Forwarded SQS callers retain their IAM/STS identity.
- [x] KMS HMAC key creation, GenerateMac/VerifyMac, compatible grants, IAM/key
  policies and alias conditions, with native captures and RFC 4231 SDK vectors.
- [ ] KMS HMAC regional quotas, variable key/grant propagation and remaining
  authorization/error precedence, alongside the other key-family lifecycles.
- [x] KMS RSA OAEP encryption/decryption, PKCS#1/PSS RAW/DIGEST signing and
  verification, public-key export, RSA/symmetric re-encryption, both RSA data-key
  pair APIs and compatible grants. Native captures cover all three sizes and
  their algorithms; SDK tests check interoperability and storage reconstruction.
- [x] Enforce RSA signing/message-type, data-key-pair-spec and per-side
  re-encryption algorithm conditions; resolve same-key re-encryption by key
  identity. Cross-account policy/grant tests cover the shared IAM path locally.
- [ ] KMS RSA regional quotas, variable key/grant propagation, remaining
  authorization/error precedence and noncommercial partition conformance.
- [x] KMS NIST ECDSA/ECDH, secp256k1 ECDSA, Ed25519/Ed25519ph and corresponding
  data-key pairs, with native signatures/metadata/error captures, OpenSSL
  interoperability and shared IAM/grant enforcement.
- [ ] KMS ECC quotas, key/grant propagation and remaining error/partition
  conformance. Native captures include successful public-key reads immediately
  after scheduling deletion that later fail; this propagation is not modeled.
- [x] KMS ML-DSA-44/65/87 signing and verification with RAW/external-μ input,
  public-key export, retained private material and shared IAM/grant enforcement.
  Native captures cover all three sizes; SDK tests verify native signatures and
  cross-verify RAW/external-μ inputs.
- [ ] KMS ML-DSA quotas, key/grant propagation and remaining authorization/error/
  partition conformance.
- [x] KMS generated symmetric rotation APIs, retained-material decryption,
  chronological history, pending-request reconstruction and shared-clock
  scheduling, with native transition/condition captures and encrypted-queue tests.
- [ ] KMS variable rotation timing/propagation, aged managed-key status (fresh
  native SQS keys report false), remaining automatic-rotation,
  quota/error precedence and partition conformance; commit lifecycle events and
  durable attempts with the scheduler's resource transactions. Continue ordinary key lifecycle and
  policy/grant conformance across common encryption workflows.
- [x] KMS multi-Region creation, replication, primary promotion, shared material
  and rotation, regional policies/grants, opt-in permissions, IAM service-role
  provisioning and ordered deletion. Native captures and SDK tests exercise
  recovery and failed regional commits. See [behavior](docs/kms-multi-region.md).
- [x] Observe native removal of both multi-Region replicas and the permissions-probe
  key. Retain actual cleanup identities recovered from CloudTrail creation records.
- [x] Confirm the promoted primary is absent after its September 28 deletion
  window and delete the unused KMS service role. October 3 reads returned
  `NotFoundException`; role deletion reached `SUCCEEDED` and `NoSuchEntity`.
- [ ] Complete noncommercial KMS multi-Region definitions, quotas, propagation
  and regional authorization conformance.
- [x] KMS symmetric, HMAC, RSA and ECC imported material, real RSA OAEP and
  RSA/AES RFC 5649 wrapping, PKCS8 validation, reusable regional import tokens,
  expiry/reimport, material history and on-demand multi-Region rotation.
  Expired pending material remains eligible for rotation; activation applies
  regional expiry, and reimport restores access to previous ciphertext.
  Accepted rotations survive pending-material deletion/replacement and replica
  material loss; completion updates shared history and regional usability together.
  SDK/OpenSSL tests cover cryptographic use, IAM conditions, retained storage,
  failed regional commits and encrypted queue recovery. See
  [native evidence and limits](docs/kms-imports.md).
- [ ] KMS import token expiry captures, import/rotation concurrency, variable
  expiry propagation and remaining import validation/partition conformance.
  The current service-time expiry model does not reproduce AWS metadata lag.
- [ ] Lower priority: KMS SM2 keys/data-key pairs/agreement, custom HSM/external
  key stores and enclave attestation. These remain in the full target but do not
  gate core-service progress.
- [x] SQS standard-queue fairness from actual in-flight concurrency, quiet and
  distinct ungrouped tenants, noisy-tenant spare capacity and service-time quiet
  recovery. Classification commits with message state and survives retained
  backend reconstruction. Native delivery captures verify group attributes and
  concurrent delivery; deterministic tests cover priority, recovery and rollback.
- [ ] SQS recent processing-time share detection and native threshold/recovery
  conformance. Captured AWS batches interleave tenants; new metric captures
  emitted noisy-group zero even with 40/60 held records. Exact distributed
  classification and positive quiet-group exclusion remain unverified.
- [x] Publish native SQS sent/received/deleted request samples into CloudWatch
  through the shared transaction and scheduler. Preserve batch statistics,
  accepted FIFO duplicates, repeated deletes/receives and pending publications
  across queue deletion and memory/SQLite reopen.
- [x] Publish remaining SQS request metrics and queue/fairness gauges through
  queue-owned activity/sampling deadlines. Replay native size, FIFO preflight,
  empty/zero-batch, delay/poison/DLQ-age and retained-backend transitions. Preserve
  documented denied-access activation and avoid fabricated skipped history.
  Actual CLI backlog alarms and schema-58-to-59 queue recovery are verified;
  approximate native sampling and noisy classification limits remain explicit.
- [x] Move SQS redrive onto the shared ordered driver with typed due times,
  bounded drains, atomic message/counter progress and retained cancellation.
  Shutdown preserves accepted work and interrupts context-aware dependencies;
  reconstruction resumes pending tasks. Native captures verify fixed starting
  counts and completion metadata; local tests cover rollback and recovery.
- [x] FIFO redrive group locking, destination deduplication and collision counts;
  automatic dead-letter receive history and distinct FIFO retention start.
  Isolated native captures cover identifiers, counters and return-to-source
  delivery; SDK tests cover retained storage and failed transfer commits.
- [x] Shared IAM forwarded-call context for SQS redrive and SQS-to-KMS delivery,
  preserving the IAM caller and direct control API checks. Native captures
  distinguish admission from accepted task execution and service principals.
- [x] SQS KMS preparation outside service locks and repository callbacks, with
  queue incarnation checks, current authorization/message selection and key
  cache publication after commit. SDK concurrency tests cover configuration,
  policy, competing receives/deletes, redrive cancellation and shutdown.
- [x] Scope SQS KMS reuse to immutable IAM identities and session policies,
  sharing role sessions that differ only by name, tags or source identity.
  Native captures distinguish whitespace from statement/managed-policy ordering;
  SDK replay covers producer/consumer authorization and service-time expiry,
  with separate identity replacement regressions. See
  [cache behavior and evidence](docs/sqs-delivery.md#kms-cache-requester-identity).
- [ ] Complete redrive optimized-rate, startup/cancellation/36-hour timing,
  forwarding after reported completion and network/partition conformance.
  AWS cancellation can keep moving messages while settling; the local driver currently stops new
  moves when it drains cancellation. Integrate durable jobs and event recovery.

- [x] SNS generated Query frontend and typed standard-topic controls, policies,
  tags and scoped subscriptions; unsupported generated commands reject explicitly.
- [x] Retain SNS protocol variants, real RSA signatures, filtered SQS/Lambda work
  and terminal DLQ transitions through memory/SQLite repository interfaces.
  Native fixtures cover Subject units, numeric spelling, structured bodies,
  malformed referenced/unreferenced attributes and topic incarnations.
- [x] Publish retained SNS service metrics through CloudWatch's internal interface;
  preserve weighted distributions, per-call batch samples, special filter reasons
  and terminal failure/redrive counts. Native percentile and real CLI restart
  replay prove more than metric API deserialization.
- [x] Exercise CloudWatch/EventBridge/SNS/SQS commands and real SNS-to-Lambda
  runtime delivery; retain native alarm payloads through source mutation/restart.
  Replay SNS management/data projections through history, selectors and S3 logs.
  See [SNS behavior and evidence](docs/sns.md).
- [x] Replay native EventBridge-to-SNS source ARN/account and legacy-owner policy
  distinctions, signed notifications and `NO_PERMISSIONS` DLQs on both stores.
- [x] Retain standard-topic SNS message groups through wrapped/raw SQS subscriptions
  and SQS-subscription dead letters. Replay native admission and partial batches;
  verify actual grouped delivery after SQLite process restart.
- [x] Implement SNS FIFO topic admission, five-minute deduplication and independent
  subscription/group ordering. Replay native fixtures on both stores; verify raw,
  wrapped and standard SQS fanout, retained duplicate identities and expiry through
  an actual SQLite executable restart.
- [x] Encrypt SNS standard/FIFO publications through actual caller-authorized KMS.
  Run KMS/body crypto outside source transactions; commit ciphertext, original
  wrapped keys and delivery intents together. Verify native authority/state
  errors, EventBridge producers, old-key FIFO recovery and executable restart.
- [x] Retain HTTP/S confirmation tokens, protected cancellation/reactivation and
  real signed/raw POST delivery, policies and SQS dead letters. Replay native
  payload/lifecycle fixtures on both stores; verify encrypted delivery, retries,
  retained confirmation and independent RSA verification after executable restart.
- [x] Calibrate SNS HTTP completion and CloudWatch counters against isolated native
  endpoint responses: per-attempt failures, confirmation metrics, HTTP 400
  completion without redrive, and exhausted HTTP 503 notification dead letters.
  Replay the retained fixture through real HTTP and SQS on both stores.
- [x] Deliver SNS through subscription-role-authorized Firehose `PutRecordBatch`.
  Replay native admission, PassRole/trust and raw/wrapped S3 payloads; verify
  retained buffers after SNS source deletion and SQLite executable restart.
- [x] Retain SNS feedback roles and optional sampling; enforce current PassRole,
  trust and Logs execution-role authority without changing notification outcomes.
  Replay native SQS/Lambda receipt identities, HTTP attempts/control messages and
  Firehose/S3 effects on both stores; verify actual CLI restart, CloudTrail role
  identity and handoff-time dwell independent of a slow consumer response.
- [x] Separate SNS publication reuse from retained encrypted delivery. Replay
  native disabled-key HTTP attempts and actual cold archive SNS KMS decisions;
  preserve empty Completed scans and original messages for fresh repaired replay.
  Verify source-bound archive authority, CloudTrail identity and SQLite CLI recovery.
- [x] Retain verified SNS publisher/session context and enforce current cold KMS
  authority without a private decrypt bypass. Replay native IAM caller denial,
  isolated archive-service denial and role-session restriction fixtures; verify
  IAM-user and tagged/session-restricted role recovery across actual SQLite restart.
- [x] Share SNS publication keys across evidenced equivalent AssumeRole sessions
  without sharing less-restricted authority. Replay native disabled-key receipts
  and fresh-topic controls through both stores and the actual executable.
- [x] Retain source-bound SNS KMS encryption context; preserve producer-specific
  EventBridge/CloudWatch versus CloudTrail validation audit identity. Replay native
  source-condition receipts/DLQs and verify cold HTTP delivery across CLI restart.
- [x] Calibrate encrypted S3 validation/object publications and asynchronous
  CloudTrail log notifications against native consumers and source-key records.
  Preserve original producer authority while projecting distinct SNS/CloudTrail
  audit actors; replay both paths and request-correlated notified S3 logs.
- [x] Calibrate SNS alias-retarget and EventBridge rule-source cache boundaries.
  Replay actual warm/cold/expired/repair outcomes; map SNS disabled-key target
  failures to native EventBridge NO_PERMISSIONS and preserve failed KMS audit.
  Verify alias recovery and all source-cache receipt/DLQ outcomes through the CLI.
- [x] Retain caller-owned cross-account SNS/SQS confirmation, protected deletion,
  recoverable Deleted state, non-resurrecting rejoin and FIFO control grouping. Replay
  native transitions and verify schema 146→147 protection plus original-token
  recovery through actual executable restarts.
- [x] Emit native paired SNS Subscribe/publication audits, compact owner identity,
  denied-publication redaction and caller-owned subscription resource projections.
  Replay both accounts' history/gzip records and verify retained trail documents
  reach each account's actual EventBridge/SQS consumer after SQLite restart.
- [x] Implement evidenced cross-account SNS/Lambda and SNS/Firehose ownership,
  real Lambda confirmation envelopes, owner-only metadata and physical deletion.
  Replay native invoke/write denial and repair through actual consumers on both
  stores; preserve pending/deleted tokens and Firehose S3 delivery across an
  executable SQLite restart. Firehose trust uses the topic owner's source account.
- [x] Preserve SNS confirmation-token identity after physical subscription deletion.
  Replay native requested-topic IAM/session limits, idempotent protection and
  replacement/incarnation errors. Verify schema 147→148 token backfill, restart,
  service-time expiry and actual cancelled-route isolation with a positive queue
  control; native probes independently removed all owned resources.
- [x] Calibrate signed/anonymous SNS confirmation and cancellation audit recipients,
  all nine topic controls and semantic publication failures against both native
  accounts. Preserve exact token redaction, paired owner identities and IAM-denial
  projection; authorize foreign missing-topic publications before exposing state.
  Replay all three audit fixtures on both stores and verify actual CloudTrail S3
  documents match EventBridge/SQS envelopes across executable SQLite restarts.
- [x] Retain SNS default/PassThrough trace context through raw/wrapped SQS and
  batch delivery without confusing transport headers with user attributes.
  Replay native controls and pending standard/FIFO work on both stores; verify
  actual SQLite restart while preserving explicit Active rejection.
- [x] Implement classic X-Ray segment ingestion/assembly and revisioned resource
  policies through generated contracts and typed memory/SQLC repositories.
  Replay native inline/independent completion, orphan traces, duration, IAM
  denial and management/data audit fixtures; verify selected S3/EventBridge/SQS
  delivery, executable recovery and deterministic thirty-day physical expiry.
- [ ] Capture positive SNS-origin sampled spans and implement Active tracing
  without invented segment structure or permission behavior. Existing native
  controls retrieved publisher/consumer spans but no SNS-origin span; see
  [tracing evidence](docs/sns.md#x-ray-propagation).
- [x] Implement retained X-Ray sampling rules/targets/statistics, trace discovery,
  filters/causes, graphs and groups/tags through generated contracts. Replay
  native completion/envelope histories and inferred documents on both stores;
  verify real CloudWatch publication and selected CloudTrail/EventBridge delivery
  across executable restart.
- [x] Admit real X-Ray daemon telemetry under IAM and the shared transactional
  API journal. Replay native counters, timestamp errors, null-record audit and
  session denials on both stores; verify official daemon upload/shutdown and
  selected S3/EventBridge/SQS delivery across executable restart.
- [x] Implement X-Ray historical time-series statistics through retained trace/
  group observations and current IAM. Native-calibrated service/edge selectors,
  minute endpoints, 60/300-second aggregation and negative inputs replay through
  the Go SDK on both stores. Verify actual executable IAM revocation and 1,001
  ordered buckets across SQLite/pagination-token restart; retain native and
  executable evidence in `testdata/aws/xray/time_series*.json` and
  `testdata/integration/xray_time_series.json`.
- [ ] Complete X-Ray Insights, forecast statistics and remaining account
  controls through real consumers. Historical time-series support is implemented;
  classic traces and query/sampling support
  are not Transaction Search or complete X-Ray parity.
- [ ] Confirm AWS-managed expiry of five older HTTP pending references and the
  additional Lambda pending reference recorded in [SNS evidence](docs/sns.md).
  Their topics and all billable receiver resources are independently absent.
- [ ] Establish other session-field, credential-class and service-source cache
  sharing, identifier/key-state propagation, HTTPS and other producer source-context
  behavior, terminal live key-failure expiry/retry/metrics, remaining failed producer
  audit, and provider-created FAS audit fields. Isolate
  disabled-key archive recovery, failed-call audit and native cache lifetime.
  See [encryption boundaries](docs/sns.md#encrypted-topic-publication-and-retained-delivery)
  and [archive limits](docs/sns.md#fifo-archive-and-replay).
- [x] Retain SNS FIFO archives and versioned replay cursors in memory/SQLite.
  Replay native controls, original consumer envelopes, current filters, exact
  bounds, pause/EOF and concurrent live delivery; preserve accepted work across
  restart and expire source without resurrecting it on retention extension.
- [x] Route SNS through regional SQS/Lambda consumers while retaining source
  identity and causality. Replay native opt-in principal aliases, condition keys,
  explicit denies, FIFO/raw receipts and permission repair on both stores; verify
  real Lambda, retained CLI delivery, archive replay and cross-account source
  conditions. See [regional evidence](docs/sns.md#regional-sqs-and-lambda-delivery).
- [ ] Implement legacy SNS data-protection Deny, Deidentify and Audit behavior.
  Native enrollment is closed in both tested regions; record this blocker rather
  than inferring enforcement from rejected writes and unchanged receipts.
- [ ] Calibrate native HTTP retry jitter, throttle bursts, policy propagation and
  successful HTTPS authentication handshakes; establish Firehose session reuse,
  batching and broader cross-account/region delivery. See [protocol evidence](docs/sns.md).
- [ ] Complete SNS platform/mobile and SMS delivery. SMTP/email remains explicitly
  deferred, not implemented.
- [ ] Calibrate SNS managed retry/deletion timing, regional single-valued actor
  context outside the captured routes and non-commercial principals.

1. S3 object data, SQS delivery/visibility, SNS subscriptions, DynamoDB Local behind
   our control plane, KMS operations, Secrets Manager and Systems Manager parameters.
2. Lambda packaging/runtime/execution, event source mappings and logs; API Gateway
   REST/HTTP/WebSocket invocation; EventBridge routes and Scheduler jobs.
   API Gateway follows the Cognito checkpoint, reusing the existing Lambda,
   Cognito, IAM and observability kernels. Cover REST/HTTP/WebSocket and
   Management API targets from the pinned coverage inventory: deployed-stage
   invocation, real Lambda integrations, Cognito/JWT and Lambda authorizers,
   `execute-api` IAM enforcement, request/response mapping and access logs.
   Use consumer-owned interfaces and native fixtures; route CRUD alone does not
   complete this application path.
   The first retained checkpoint implements 36 REST and 33 HTTP controls and
   real Lambda invocation with IAM/Cognito/JWT admission. Native Docker replay
   and fixture-driven deployment authorization transitions pass on memory and
   reopened SQLite. Native request-correlated CloudTrail replay now covers
   31 supported control outcomes; configured trail selectors and EventBridge/SQS
   delivery survive reopening. Real Lambda TOKEN/REQUEST authorizers now retain
   policy/simple responses, identity-keyed stage caches and service-time expiry.
   Invocation roles now enforce scoped `iam:PassRole`, service trust and real
   Lambda authority, with retained credentials and native deployment transitions.
   Deployed WebSocket Lambda proxy routes now execute actual one-way/two-way
   traffic, with five route-response controls and all three Management operations.
   Native lifecycle, management and REQUEST authorizer replay use official
   runtime containers on memory and reopened SQLite. WebSocket authorization
   is connect-only, uncached, and retains accepted context for later traffic.
   Schemas 174–175 retain controls and deployment snapshots, not live connections.
   Schemas 176–177 retain integration credentials in live controls and immutable
   deployments. All three API types enforce real integration-role authority;
   REST caller forwarding contributes `ViaAWSService`/`CalledVia` through the
   shared IAM context. Native replay covers PassRole, denied invocations,
   role/resource-policy selection, retained deployment changes and live held
   WebSocket messages. Integration-specific STS session/cache details and
   broader cross-account/region conformance remain unmeasured.
   Schemas 178–180 retain REST API keys, usage plans, memberships, daily quota
   counters, deployed key requirements/source and cached authorizer usage keys.
   Fifteen additional controls cover key/plan CRUD, membership and CSV import;
   rejected fail-on-warning imports retain earlier successful rows.
   Required requests enforce live key and stage membership. Optional HEADER
   requests with mapped keys still enforce plan limits, including disabled keys;
   unmapped known keys retain identity without plan admission. Quota accounting
   starts only while a quota is configured, and plan/method throttles compose.
   Schemas 181–183 retain Gateway metric samples and REST/V2 detailed settings.
   One Gateway publication owner feeds CloudWatch from actual REST/HTTP requests,
   WebSocket lifecycle/messages and management callbacks; closed service-time
   minutes preserve distributions, owner scope and history after API deletion.
   Schemas 184–185 retain regional logging roles, access destinations/formats and
   typed method/route settings, preserving prior metric overrides. Real REST,
   HTTP and WebSocket execution now emits access logs; REST/WebSocket also emit
   level/data-trace-controlled execution logs through the existing Logs owner.
   Native SDK/runtime replay covers admission, partial updates, removals, request/
   Lambda correlation and reopened storage. HTTP uses resource-policy delivery;
   REST/WebSocket enforce the current account role. GetAccount/UpdateAccount and
   V2 access-log/route-setting deletion are implemented.
   Complete Marketplace associations, optional CUSTOM-authorizer usage keys,
   quota calendar/offset calibration, opaque native connection-ID admission,
   literal header spelling, mappings/non-Lambda integrations, logging-role minimum
   permissions, stream allocation, Firehose access destinations, remaining
   authorizer/federation log context and HTTP byte/WebSocket failure-metric
   calibration next. Native short transitions do not establish logging
   propagation timing or route-precedence conformance; see
   [current evidence and limits](docs/behavior-references.md#api-gateway-deployed-lambda-authorization-evidence).
   EC2/VPC and the related instance, EBS, network, IAM/IMDS and dependent service
   workflows are the next priority after this Gateway checkpoint. QEMU/KVM
   guest execution consumes a service-owned interface and shared networking
   infrastructure without duplicating VPC semantics or replacing Lambda/ECS backends.
   Glue and Athena now proceed as an independently owned S3-backed analytics
   application path alongside EC2. Both Smithy frontends, typed memory/SQLite
   state and the retained operation inventory are integrated. Catalog/schema/
   workflow control and Athena service/repository regressions pass the assembled
   scoped gate. Keep the executable producer/consumer gate separate: registration,
   native engine probes and catalog CRUD do not establish complete runtime parity.
   Import pinned real engines in containers: evaluate AWS Glue's published Spark
   runtime images for Glue ETL jobs and Athena Spark sessions; evaluate Trino or
   another evidenced compatible SQL engine for Athena SQL. These are distinct
   execution modes, not one Spark substitute for every Athena query. Verify engine
   licensing, version/function/type compatibility and offline image availability
   before choosing a backend. AWS-specific IAM, catalog authorization, execution
   state, cancellation, encryption, result metadata and error behavior remain our
   Go control-plane responsibility. Prove an actual Glue → S3 → Athena query path
   with native fixtures, retained state and real result consumers. Unsupported
   jobs/queries return errors; catalog CRUD must never imply engine behavior.
   - [x] Generate Glue/Athena contracts and compose typed repositories, scoped
     IAM, audit/event boundaries and shared service-time scheduling.
   - [x] Capture bounded native catalog/schema/control, Python-shell, Athena
     query/result/denial/cancellation and EventBridge consumer behavior, with
     retained failed captures and verified owned cleanup.
   - [x] Finish and retain passing assembled executable proof for actual Glue
     Python/Spark -> S3 -> crawler/catalog -> Athena -> S3 consumers, current
     policy, encrypted data, cancellation/failure and controller restart.
     The complete race-enabled run also consumes Hive DDL/Iceberg, independent
     result permissions, actual Logs/metrics/EventBridge/CloudTrail and retained
     workflow execution. Direct PostgreSQL discovery additionally proves current
     password/KMS boundaries and retained catalog after restart; see the retained
     executable evidence in `testdata/athena/`. This does not close the umbrella.
   - [x] Correct pre-integration Glue run tag authorization, rejected
     compute-credential audit redaction and optional Spark-observation lifecycle
     failures. Focused before/after race-enabled executable proof retains actual
     IAM Deny/Allow, synthetic audit sentinels, malformed/truncated/oversized
     native events, cancellation, callback cleanup and successor execution.
     Explicit connection UpdateConnection/current-KMS transitions are proved;
     primary AWS docs do not establish retroactive encryption of old plaintext
     connections, so no migration or encryption-on-read mechanism was invented.
   - [x] Integrate the analytics pair with current EC2/IAM and ECR/CodeBuild
     owners using schemas 206–212. Verify the actual merged runtime workflow,
     official Go SDK decoded results/modeled errors, schema 205→212 upgrade and
     retained legacy S3/ECR state through controller reopen. Both bounded
     integration captures are retained in `testdata/integration/`.
   - [ ] Complete remaining enterprise modes, not just retained operation
     registrations: federated/Lake Formation catalog behavior, distributed/
     streaming/Ray jobs, bookmarks/dependency loading, native Python library
     bundles, continuous metrics/logs, additional crawler targets/configuration/
     encryption, full schema compatibility, EVENT workflows, Athena Spark,
     connectors/managed results/capacity/CSE_KMS, manifests, SQL prepared-state
     deltas, CTAS dialect properties and S3Tables prerequisites. Preserve the
     [precise evidence and boundaries](docs/behavior-references.md#glue-and-athena-engines-evidence-and-boundaries);
     do not mark this umbrella complete from a narrow successful query.
   - [x] Build the [EKS Kubernetes kernel](docs/eks.md): generated REST contracts,
     scoped memory/SQLC intent, real pinned k3d readiness and exact-owned cleanup,
     AWS CLI token-to-kubectl access, current IAM identity and namespace-scoped
     native RBAC, retained updates/tags and controller-restart workloads.
   - [x] Prove IRSA through real Kubernetes-issued tokens, native-calibrated
     admission, current IAM OIDC/trust evaluation and actual in-pod AWS CLI/SQS
     effects. Fresh and retained-cluster workflows cover restart, native upgrade,
     trust/provider denial, old native issuer acceptance and exact-owned cleanup.
     Recover native metrics discovery and namespace deletion using the actual
     kubelet address; retain before/after and native-server-restart evidence.
     Seven-day signing-key rotation remains open in the runtime owner.
   - [ ] Complete EKS managed node groups/scaling, external-cluster ownership,
     remaining authentication/upgrade conformance, VPC/CNI endpoints, ECR pulls,
     IRSA key rotation, remaining Pod Identity/EKS Auth conformance, additional
     add-ons and direct lifecycle events.
     CoreDNS, isolated Fargate workers, authentication migration, wildcard
     namespaces and native control-plane upgrades now have actual workflow
     evidence; this broader service umbrella remains open.
3. Step Functions execution, retries and callbacks; CloudFormation deployments,
   rollback, references, change sets and custom resources; Cloud Control.
4. Networking and compute execution: EC2, load balancers, Route 53, ECS/ECR/EKS,
   Batch and application scaling; expose actual local data plane endpoints.
5. Database engines and data APIs: RDS, ElastiCache, OpenSearch/ElasticSearch,
   DocumentDB, Neptune, MemoryDB, Redshift, Timestream and QLDB.
6. Complete the targeted operations and application behavior for every remaining
   service in docs/services.json, subject to the explicit behavioral exclusions.
7. Prove cross-service IAM/SCP effects, tenant isolation, resource tagging,
   limits, pagination, idempotency, asynchronous completion and cleanup.

### Independent ECR and CodeBuild boundary

- [x] Generate the pinned private-ECR and CodeBuild target frontends, retain
  per-operation native/source inventories, and expose partial—not complete—
  support in `docs/services.json`.
- [x] Implement service-owned memory/SQLite repositories and real authenticated
  OCI manifest/layer push and pull, current IAM/resource policies, KMS grants,
  lifecycle expiration, native offline basic scanning and cross-account
  replication with actual destination bytes.
- [x] Verify real scanner findings and scan-on-push failure, and deliver a native
  ECR scan EventBridge envelope through the existing SQS target owner.
- [x] Execute real isolated CodeBuild Docker processes with S3/native Git sources,
  authenticated IAM/STS container credentials, real artifacts/cache/log output,
  stateful buildspec 0.2, failure/finally/POST_BUILD, retries/run-as, actual
  image-owned runtime selection and shell-expanded primary artifact names.
- [x] Prove fleet incarnation safety and real idle capacity, source-credential
  admission, in-container boto3 role identity/current-policy denial, native
  command failure/cancellation/five-minute timeout, concurrent isolation and
  retained SQLite crash reattachment to the same live process.
- [x] Keep ECR linked-role usage and IAM deletion in the same write transaction;
  test configured refusal and deletion after configuration removal on memory
  and SQLite. Actual local replication sessions still impose IAM's active-session
  deletion guard; do not revoke them or call the blocked API deletion a success.
- [x] Match captured public-provider source authority admission and reject unsafe
  retained sources before credential resolution. Prove actual API Create/Update/
  Start rejection without importing provider tokens or executing a disclosure.
- [x] Reconcile credential-bearing native Git staging after StopBuild plus
  controller SIGKILL/reopen; retain cleanup intent on removal errors, then remove
  the owned process. Drain admitted source preparation before deleting fleets.
- [x] Publish selected ordinary S3 artifact bytes despite unrelated workspace
  symlinks; preserve strict source extraction and explicit selected-link refusal.
  Retain focused before/after diagnostics separately from unchanged broad proof.
- [ ] Complete ECR archive/storage-class behavior and Inspector-backed enhanced/
  continuous scanning. ECR Public is a separate service; newer pull-through and
  signing surfaces are not established by the private target.
- [x] Execute CodeBuild S3 ZIP secondary sources and S3 secondary artifacts through
  real Docker builds and current role authority. Seven builds verify independent
  object versions, source/artifact-list replacement, shell-expanded names, ZIP/NONE
  bytes/checksums, accepted configuration across active SQLite restart, live read/
  write denial and retained output evidence. All owned build containers were removed.
- [x] Consume primary and secondary S3 folders through current execution-role
  ListBucket/GetObject authority and real Docker builds. Nine builds verify
  nested bytes, 1,001-member pagination, missing/marker-only prefixes, collision
  rejection, live IAM denial and staged-source retention across SQLite restart.
  Native folder version admission and owned-resource cleanup are retained.
- [x] Calibrate and implement eager CodeBuild source-bucket existence admission.
  Native controls distinguish bucket existence from caller/execution-role S3
  authority and require revalidation on unrelated updates. Signed SDK memory/
  SQLite checks and executable restart prove rejection and atomic retained state;
  actual downloads continue to enforce current S3/KMS object authority.
- [x] Execute Git/provider secondary sources through current per-source credentials
  and retained build inputs. Native captures correct version-list replacement;
  thirteen Docker builds verify refs, submodules, shallow history, auth overrides,
  rotation/denial, imported credentials and SQLite restart. Preserve typed empty
  source directories without inventing Git refs; seven ZIP builds and nine folder
  builds verify archive correction and existing source behavior. Owned resources
  were removed; native private-provider authentication remains uncalibrated.
- [x] Execute manual CodeBuild RetryBuild from retained admitted configuration,
  preserving original overrides rather than current project defaults. Calibrate
  current retry-only authority, five-minute token replay and independent start/
  retry namespaces against native AWS. Verify actual Docker/S3 output, fresh
  primary/secondary bytes, role denial/recovery and SQLite restart; schema 315
  retains retry ancestry. Automatic whole-build and batch retries remain open.
- [ ] Complete the VPC consumer integration,
  privileged/non-Linux environments, whole-build automatic retries, advanced
  cache/artifact/fleet settings, runtime wildcard/dependency selection and
  CodeBuild batch/report/webhook/sandbox/public-sharing/provider-status paths.
- [ ] Add actual CodeCommit, CodeConnections, EFS and Inspector
  owners before claiming their dependent behaviors. Do not block independent
  S3/Git/Docker/IAM-backed paths on those missing owners.

See [native and executable evidence, reproduction and exact
boundaries](docs/behavior-references.md#ecr-and-codebuild). These checkpoints do
not close either full-service parity target.

## Distribution and verification

- [x] Replace the root implementation ledger with a runnable quickstart and
  task-oriented documentation index; preserve the old content in
  [the implementation reference](docs/implementation-reference.md).
  Document configuration, native prerequisites, safe shutdown and state retention.
  Exercise CLI S3/SQS, Python/Go SDK clients, SQLite restart, saved manual time
  and CA-verified HTTPS against a temporary controller, then stop it.
- [ ] Establish the repository license before public redistribution.
- [ ] Reproducible offline container/binary packaging and CI.
- [x] Fast repository hooks: staged Go formatting on commit; changed pushed-package
  vet/Staticcheck on push. Keep full race and generation drift in explicit `make check`
  checkpoints, outside the normal development loop.
- [x] Exclude build-ignored-only tool directories from pushed-package checks
  without hiding malformed/buildable packages. Verify ignored-only, mixed and
  malformed-package commits through the actual hook in an isolated Git repository.
- [x] Generate typed Account/IAM/Organizations/STS/KMS/SQS/CloudTrail/EventBridge API contracts and request bindings from
  SDK Smithy models, recording revision/checksums and detecting regeneration drift.
- [x] Replace handwritten input/output adapters for all implemented operations
  in the eight active providers with generated bindings. Organizations now shares
  generated selectors/pagination and native validation reasons across direct and
  gateway endpoints; [AWS replay](docs/organizations-api.md) covers update field
  presence, tag atomicity and hierarchy paths. New service protocols remain open.
- [ ] Provider extension SDK, version negotiation and extension compatibility tests.
- [x] Generated SDK operation inventory for the eight active service families.
- [x] Generate action/resource/condition and last-access
  metadata from the pinned AWS service reference; use it to select IAM authorization
  resources and condition keys, retain all ARN alternatives and share last-access
  tracking inputs. Native SDK replay covers API Gateway/Greengrass policy discovery.
- [x] Generate scalar/list context declarations from AWS metadata and carry them
  through ordinary authorization and federation trust. Native TagUser/STS
  captures and SDK replay cover list cardinality, empty values, set/scalar
  operators, variable expansion and deny/validation ordering. See
  [condition evidence](docs/iam-evaluation.md#condition-values-and-cardinality).
- [x] Native IAM/STS comparison and policy-validation captures: decimal and
  Boolean parsing, millisecond dates, failed conversions, malformed ARN
  operands, strict IAM storage and accepted STS session literals. SDK replay
  verifies subsequent authorization, simulator differences and stored-policy
  errors through the shared compiler. See
  [typed comparison evidence](docs/iam-evaluation.md#typed-comparisons-and-policy-validation).
- [x] Live IAM decision observations and STS managed-session-policy behavior
  replayed as offline SDK fixtures, with explicit provenance and comparison scope.
- [ ] Extend semantic coverage fixtures across all operations/service families.
- [ ] Optional live AWS differential runner with explicit resource ownership,
  cleanup and cost boundaries; ordinary tests remain fully local.
- [ ] Fault injection, persisted deterministic jobs/clock state, observability,
  snapshot/import and regional/partition deployment checks needed for enterprise-grade emulation.
- [ ] Completion audit for the full service list and application scenarios;
  operation counts and green narrow tests do not establish completion.

Exact code gaps are marked `// TODO: Comeback` and must be included in handoffs.
