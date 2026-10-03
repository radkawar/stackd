# Cross-service consistency and debt

## Scope of the 2026-09-30 pass

This is an entrypoint and sampled-invariant audit, not whole-service conformance.
The audit covered all 67 `internal/services/*/service.go` owners plus the
`apigatewayexec` execution owner. It reconciled every selected service with the
pinned model inventory. Unregistered services have no implementation to assess;
they have not been silently excluded from the target.

At the audit boundary, the corrected [inventory](services.json) contained **127
services and 8,207 modeled operations: 2,228 registered/partial and 5,979 unregistered**, with no additional
registrations outside the selection. The prior 118 additional registrations were
misclassified or omitted prerequisite services, not newly implemented behavior.
All 71 selected services with registrations now link to maintained guides or
retained behavioral evidence. Those links do not make an operation complete.

At the audit boundary, production `TODO: Comeback` inventory was **472 markers in 379 files**, down from
473 markers in 380 files at the start of this pass. Scope: `internal`, `compute`,
`engine`, `storage`, `iam`, `stackd.go`, `clock`, and `extension`; documentation,
SDK clones and generated operation counts are not included. The removed Auto
Scaling marker incorrectly claimed EC2 group CPU/network publication was absent;
`internal/integrations/ec2_metrics.go` already publishes those group dimensions.
The older 388-marker classification in [TODO.md](../TODO.md) is a historical
2026-09-27 snapshot, not today's debt count. Remaining markers are not all defects:
they include missing capabilities and unmeasured native behavior.

## Shared implementation rules

Use the existing [architecture](architecture.md) and
[verification kernel](verification-kernel.md), not a second service framework:

- Generated model names, provider IDs and explicit selection must agree. Retain
  complete modeled inventories and reject unsupported behavior honestly. Handler
  registration and decoding are not evidence of a working operation.
- Keep transport, typed resource ownership and IAM separate. Memory and SQLC
  repositories join the same transaction domain through the callback context;
  state and its committed event must not diverge.
- Resolve current identity, resource incarnation, policy and tags at the owning
  boundary. Recheck authority after an out-of-transaction wait before starting a
  new effect. Existing admitted connections retain their documented lifecycle;
  this rule does not invent per-frame authorization for established subscriptions.
- Select IAM resource and condition context from the action's AWS contract, not
  from a similar service or the operation's spelling. Account-wide `*` actions
  and resource-scoped actions are intentionally different.
- Commit intent before native I/O. Fence completion and crash recovery using
  current transactional rows, incarnation/version and attempt state. A stale
  scheduler selection must not revert an acknowledgement or checkpoint.
- Use service time for modeled decisions, deadlines and controller-produced
  events. Native runtime counters, source timestamps, transport durations and
  signature freshness have separate wall-clock contracts. Do not compare the
  two timelines or rewrite native Kubernetes records to hide an admission issue.
- Bind pagination to the effective scope, collection and filters. For ordered
  control lists, continue from stable identities rather than shifting offsets.
  Preserve native ordering and documented terminal-page behavior; opaque tokens
  are not a reason to impose one service's semantics on another.
- Prove transitions, denied mutations, restart and scope isolation with the SDK.
  Exercise changed native boundaries with real engines. Retain actual gaps
  rather than replacing them with fake success, labels or mirrored authority.

## Fixed and exercised

| Boundary | Correction | Retained regression / exercised surface |
| --- | --- | --- |
| Inventory | Canonical `cognitoidentity`, `configservice`, `ssoadmin` IDs; select full Signer/SSO/SSO OIDC models; reject duplicate model selections and generated-ID mismatches | `cmd/coveragegen/stack_test.go`; actual default-stack inventory generation and drift check |
| Generation gates | Include CloudFormation checking in `make check`; include GuardDuty findings in normal generation and check targets | Existing CloudFormation and GuardDuty generators passed their checks |
| Config IAM | Use each supported action's recorder/rule/aggregator/aggregation-authorization ARN; preserve account-wide actions; authorize every rule before batch mutation | `integration/configservice_authority_test.go`; memory/SQLite and signed SDK scoped allow/deny with retained resource after denial |
| Kinesis authority | Reauthorize current stream/consumer after the native gate, before append/read; retain incarnation and cancellation fences | `internal/services/kinesis/data_access_test.go`; `integration/kinesis_gate_authority_test.go` against actual Kafka on memory/SQLite |
| Pipes recovery | Reload current pipe/work transactionally before recovering an orphan; publish readiness only after commit | `internal/services/pipes/execution_test.go`; original-source overlay delivered the target twice, corrected race check delivers once and preserves checkpoint |
| AppConfig pagination | Bind all 11 lists to scope/action/effective parents/filters; stable ordered continuation, including hosted versions and prepended experiment events | `integration/appconfig_pagination_test.go`; experiment regressions; actual SDK cross-parent rejection and continuation after deletion |
| Identity Center pagination | Replace offset cursors with request-bound stable keys for administration and portal lists | `integration/identity_consistency_test.go`; memory/SQLite reconstruction, insertion/deletion before cursors, resource/filter isolation |
| SES pagination | Bind existing name cursors to partition/account/region, logical collection and classic identity filter | `integration/ses_pagination_test.go`; six classic/v2 list surfaces, retained continuation and scope/list rejection |
| Identity errors | Correct SSO Admin access denials to documented HTTP 400; preserve existing Identity Store and SSO Admin conflict/not-found 400 contracts | `integration/identity_consistency_test.go`; signed SDK status observations |
| EKS log time | Timestamp the local authenticator decision with service time; do not filter it against a native wall-clock enable watermark | Service/native logging regressions; actual k3d request at service time `2020-01-01T00:00:00Z` produced one CloudWatch denial record after previously producing none |
| ElastiCache admission | Allow the supported disabled snapshot-retention value, zero, on both modification APIs; still reject enabled automatic snapshots | `internal/services/elasticache/behavior_test.go`; real Valkey modifications, changed replication-group description, native PING and nonzero rejection |
| Cloud Control recovery errors | A missing recovered handler is `GeneralServiceException`, not the create-only-property update error `NotUpdatable` | `internal/services/cloudcontrol/jobs_test.go`; actual signed SDK observation of recovered CREATE failure before/after |

The combined executable Scheduler/Pipes workflow also passed with actual Lambda,
SQS, Kafka-backed Kinesis and DynamoDB Streams, role denial/recovery and SQLite
restart, with no cleanup errors. Relevant package tests, targeted race checks,
SDK integration tests, vet and staticcheck passed. Repository-wide tests and the
full native engine matrix were not rerun for this pass.

## Owner coverage and retained boundaries

Every owner is listed below. “Inspected” means entrypoints and sampled state,
authority, scheduling, persistence or effect boundaries; it does not mean every
operation or native transition was reverified. Existing owner guides and located
code markers retain the detailed unfinished work.

| Owners inspected | Result / limits retained |
| --- | --- |
| `iam`, `sts`, `organizations`, `account`, `kms`, `secretsmanager`, `cognitoidp`, `cognitoidentity`, `identitycenter`, `identitystore`, `signer`, `acm`, `ram` | Typed authority and shared owner boundaries retained. Identity Center fixes above. External directory provisioning, broader identity/application/OIDC flows, account-closure calibration, specialized KMS and remaining per-owner authorization semantics remain open. RAM request conditions remain per principal/resource, not a combined permissive context. |
| `lambda`, `ecs`, `ec2`, `ebs`, `autoscaling`, `applicationautoscaling`, `eks`, `elbv2` | Intent-before-runtime and version/incarnation completion fences inspected. EKS time fix and obsolete Auto Scaling debt removed. Native fleet/calibration work, managed-runtime combinations, guest/network/storage boundaries and full lifecycle matrices remain open. |
| `s3`, `dynamodb`, `rds`, `rdsdata`, `docdb`, `elasticache`, `memorydb`, `opensearch`, `kafka` | Typed control intent remains separate from real engine data. ElastiCache admission fixed. RDS Data transactions are process-local engine leases, not falsely durable SQL transactions. Broader topology, restore, data-plane IAM, encryption and native response calibration remain owner-specific gaps. |
| `sqs`, `sns`, `eventbridge`, `scheduler`, `pipes`, `kinesis`, `firehose`, `mq` | Delivery intent, due work, current role authority and source progress inspected. Pipes/Kinesis fixes above. MQ/DocumentDB Pipes consumers, broader Kafka networking/authentication, fleet limits and native audit/layout calibration remain open; this pass adds no MQ feature expansion. |
| `apigateway`, `apigatewayv2`, `apigatewaywebsocket`, `apigatewayexec`, `appsync`, `stepfunctions`, `cloudformation`, `cloudcontrol`, `codebuild`, `ecr`, `codepipeline` | Control ownership and native/handler effect boundaries inspected. API Gateway execution resolves deployed routes and current auth, outside control transactions. Cloud Control error fix above. Remaining registry types, callbacks, integrations and complete runtime failure/rollback matrices are not certified by this pass. |
| `appconfig`, `resourcegroups`, `resourcegroupstaggingapi`, `servicecatalogappregistry`, `configservice`, `ssm`, `ssmdocuments`, `ssmcommands`, `ssmfrontend`, `ssmmessages`, `route53` | Owner dispatch, transactions, clock, authority and resource/list boundaries inspected. AppConfig/Config fixes above. AppConfig treatment-traffic ingestion, Config recording/rule/resource variants, shared discovery breadth and remaining SSM native workflows stay explicit. |
| `logs`, `cloudwatch`, `cloudtrail`, `xray`, `guardduty`, `glue`, `athena`, `sesv2` | Observation/state ownership and sampled engine/delivery boundaries inspected. SES token fixes above. Query/transform/export capabilities, audit calibration, source detections and external delivery boundaries remain open. Athena's captured empty terminal page is intentionally preserved. |

Selected services with **no registered operations** remain in the generated target:
`acm-pca`, `amplify`, `backup`, `batch`, `bedrock`, `bedrock-agentcore`,
`bedrock-agentcore-control`, `bedrock-runtime`, `ce`, `cloudfront`,
`cloudfront-keyvaluestore`, `codeartifact`, `codecommit`, `codeconnections`,
`codedeploy`, `codestar-connections`, `dms`, `dsql`, `efs`, `elasticbeanstalk`,
`elastictranscoder`, `elb`, `emr`, `emr-serverless`, `fis`, `glacier`, `iot`,
`iot-data`, `iotwireless`, `kinesisanalytics`, `kinesisanalyticsv2`, `lakeformation`,
`managedblockchain`, `mediaconvert`, `mwaa`, `neptune`, `pinpoint`, `redshift`,
`redshift-data`, `route53resolver`, `s3files`, `s3tables`, `sagemaker`,
`sagemaker-runtime`, `serverlessrepo`, `servicediscovery`, `shield`, `support`,
`swf`, `textract`, `timestream-query`, `timestream-write`, `transcribe`, `transfer`,
`verifiedpermissions`, `wafv2`.

## Differences not mechanically normalized

- Athena's native `application_verified.json` captures a full final row page with
  a continuation token followed by an empty terminal page. Removing that token
  would regress the retained AWS behavior, despite looking simpler locally.
- Official Identity Store and SSO Admin references specify HTTP 400 for the
  audited client errors. Generated status hints are not sufficient evidence to
  rewrite them to 403/404/409.
- Cloud Control has **no service-specific condition keys**, despite sharing the
  `cloudformation` IAM prefix. Copying CloudFormation's `cloudformation:RoleArn`
  condition into Cloud Control would invent unsupported authority context.
  `iam:PassRole` remains its separate documented dependency.
- CloudWatch's published management-event list does not establish
  `DescribeAlarmContributors` logging. This pass did not invent that event.
- Logs `applyOnTransformedLogs` without a transformer needs delivery calibration;
  a sibling metric-filter implementation is not native evidence for dropping
  subscription messages.
- EC2 credit accrual versus real CPU elapsed time, wildcard `aws:ResourceAccount`
  context in EC2/ECS/EKS, Kafka out-of-scope lookup/error precedence, SSM's lazy
  default-setting materialization and DocumentDB default parameter reporting need
  their own contracts/captures before being labeled defects or standardized.

## Follow-on ownership correction

AppConfig now contributes live resource snapshots to shared tagging discovery;
tag mutations still execute the AppConfig owner's current IAM/transaction path.
The native capture distinguishes ARN-root tagging filters from Resource Groups'
nested CloudFormation types and establishes version-scoped extension tags.
Both missing discovery and the rejected versioned extension ARN were reproduced
through the signed Go SDK before correction. Memory/SQLite race regressions and
an actual SQLite executable restart verify the corrected paths.
See [the owner guide](appconfig.md#shared-tag-discovery) and
[retained native calls](../testdata/aws/resourcegroupstaggingapi/appconfig.json).
No operations were newly registered; the inventory totals above are unchanged.

The subsequent AppRegistry check found a stale missing-owner comment, not missing
discovery. The signed Go SDK against the executable discovered an application
through a Resource Groups tag query and observed native untagging immediately.
The comment now retains only the genuinely absent owner boundaries. This local
check does not replace the existing-customer native calibration gap.

Config now owns tags for recorders, rules, aggregators and aggregation
authorizations in normalized schema-296 rows, sharing native IAM and transaction
boundaries with tagging and Resource Groups discovery. A failed last-tag
membership regression exposed the SDK model's incorrect CloudTrail source;
request-matched native captures establish `config.amazonaws.com`. The
evidence-backed generator correction fixes audit identity and owner selection
together. Eight memory/SQLite SDK race workflows and an executable process
restart verify current authority, atomic rejection, durable membership and
deletion. Native Resource Groups membership and cross-account calibration remain
explicitly unproven in [the owner guide](config.md#resource-tags-and-shared-discovery).
The three newly registered tag operations bring the current inventory to
2,231 registered/partial and 5,976 unregistered; the full 8,207-operation target
is unchanged.

The next ownership correction retains KMS alias deployment identity in the KMS
transaction and exposes live, exact-owned aliases to Resource Groups stack
queries. It removes the alias-specific crash-after-create recovery marker,
preserves native alias untaggability and rejects same-name foreign replacements.
Memory/SQLite SDK race workflows, schema migration, an executable restart and a
separate fresh-process handler replay verify the local contract. No new operation
was registered. [Native documentation and local proof boundaries](resourcegroups.md#kms-aliases-in-stack-queries)
remain explicit; this is not a claim about AWS's private recovery implementation.

## Primary contracts

- [AWS Config action/resource associations](https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html)
- [Identity Store CreateUser errors](https://docs.aws.amazon.com/singlesignon/latest/IdentityStoreAPIReference/API_CreateUser.html)
- [SSO Admin CreatePermissionSet errors](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_CreatePermissionSet.html)
- [AppConfig hosted-version pagination](https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_ListHostedConfigurationVersions.html)
- [SES classic identity pagination](https://docs.aws.amazon.com/ses/latest/APIReference/API_ListIdentities.html)
- [SES v2 identity pagination](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_ListEmailIdentities.html)
- [ElastiCache disabled snapshot retention](https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_ModifyCacheCluster.html)
- [Cloud Control IAM resources and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudcontrol.html)
- [Resource-handler terminal error meanings](https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/resource-type-test-contract-errors.html)
- [CloudWatch operations recorded by CloudTrail](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/logging_cw_api_calls.html)
- [Retained native Athena result pages](../testdata/aws/athena/application_verified.json)
