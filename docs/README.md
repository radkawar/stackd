# Documentation

[Project overview](../README.md)

Start with the user guides. The service and engineering references below retain
the existing implementation details, native evidence and explicit limitations;
they are not a claim of complete AWS parity.

## User guides

| Guide | Use it for |
| --- | --- |
| [Getting started](getting-started.md) | Build from source, start the API, use AWS CLI/SDKs, exercise S3/SQS and restart. |
| [Configuration](configuration.md) | Credentials and IAM, accounts/regions, listener/advertised/compute endpoints, TLS, SQLite and manual time. |
| [Networking](networking.md) | Opt-in gateway/resource DNS, forwarding, scoped development CA/runtime trust, deployment recipes, native port pools, isolated AWS HTTPS routing and reversible host split DNS. |
| [Runtime overview](runtimes.md), [containers and engines](runtime-containers.md), [QEMU/KVM and k3d](runtime-vms.md) | Install dependencies/images, deploy real backends, configure networking, provision workloads and retain state. |
| [Operations](operations.md) | Diagnostics, shutdown, retained infrastructure, backups, resets and troubleshooting. |
| [Native probe privacy](behavior-references.md#publishing-sanitized-probe-captures) | Explicit account guards, private raw captures, sanitized publication and authenticated fixture limits. |

The original root README is preserved as the
[implementation and development reference](implementation-reference.md). Its
[embedding examples](implementation-reference.md#embed-in-go-tests),
[development workflow](implementation-reference.md#develop),
[generated API contracts](implementation-reference.md#generated-aws-api-layer)
and [OpenSearch example](implementation-reference.md#native-opensearch) remain
available at stable headings. Commands in these documents run from the repository
root unless stated otherwise.

## Service guides

Services share one AWS HTTP endpoint but have different behavior, resource
lifecycles and runtime prerequisites. A guide's verified examples establish
those examples—not every modeled operation or every AWS configuration.

### Identity, accounts and security

| Area | Entry points |
| --- | --- |
| IAM and STS | [IAM scope and completion](iam-completion.md), [policy evaluation](iam-evaluation.md), [resource controls](iam-resource-controls.md) |
| Account Management | [Contacts](account-contacts.md), [names/information](account-information.md), [primary email](account-primary-email.md), [region opt-in](account-regions.md) |
| Organizations | [API behavior](organizations-api.md), [account access](organizations-account-access.md), [invitations](organizations-invitations.md), [feature migration](organizations-features.md), [delegation](organizations-delegation.md), [effective policies](organizations-effective-policies.md) |
| Cognito | [User pools and email](cognito.md), [identity pools and principal tags](cognito-identity.md) |
| IAM Identity Center | [Login, permission sets and account roles](identity-center.md), [Identity Store](identity-store.md) |
| Federation | [OIDC](oidc-federation.md), [SAML](saml-federation.md), [outbound identities](iam-outbound-identity.md) |
| Secrets and encryption | [Secrets Manager](secretsmanager.md), [KMS cryptography](kms-cryptography.md), [grants](kms-grants.md), [imports](kms-imports.md), [multi-Region keys](kms-multi-region.md) |
| Certificates | [ACM DNS validation and local trust](acm.md) |
| Threat detection | [GuardDuty behavior and limits](guardduty.md), [pinned finding definitions](guardduty-findings.json) |

Specialized IAM/STS references:

- [Account properties](iam-account-properties.md), [account reporting](iam-account-reporting.md),
  [credential reports](iam-credential-reports.md), [last-access reports](iam-last-access.md).
- [Role templates](iam-role-templates.md), [service-linked roles](iam-service-linked-roles.md),
  [service credentials](iam-service-credentials.md), [certificates](iam-certificates.md).
- [MFA](iam-mfa.md), [root access](iam-root-access.md),
  [STS preferences](iam-sts-preferences.md), [policy simulation](iam-simulation.md).
- [Context keys](iam-context-keys.md), [OIDC trust controls](iam-oidc-trust-controls.md).

### Compute, networking and deployment

| Area | Entry points |
| --- | --- |
| Lambda | [Runtime API, deployment, invocation and event sources](lambda.md) |
| EC2, VPC, EBS and Auto Scaling | [Guest execution and networking](ec2.md) |
| ECS and Application Auto Scaling | [Tasks, services, credentials and recovery](ecs.md) |
| EKS | [Real Kubernetes, access and native ownership](eks.md) |
| Route 53 | [DNS data plane and delegation](route53.md) |
| Load balancing | [ALB execution and evidence](behavior-references.md#application-load-balancer-kernel) |
| ECR and CodeBuild | [Images, builds, source/artifact handling and prerequisites](behavior-references.md#ecr-and-codebuild) |
| CodePipeline | [Artifacts, actions, approvals and rollback](codepipeline.md) |
| CloudFormation and Cloud Control | [Deployment behavior](behavior-references.md#cloudformation-deployments), [Cloud Control requests](behavior-references.md#cloud-control-resource-requests), [CDK workflow](behavior-references.md#official-cdk-bootstrap-and-deployment) |
| Systems Manager | [Parameters, documents and managed execution](ssm.md) |

### Storage, databases and analytics

| Area | Entry points |
| --- | --- |
| S3 | [S3 behavior within the CloudTrail/S3 reference](cloudtrail.md#s3-dependency-scope) |
| DynamoDB | [Native backend, tables, items, streams and recovery](behavior-references.md#dynamodb-engine-references) |
| RDS and RDS Data | [Real PostgreSQL/MySQL execution](rds.md) |
| DocumentDB compatibility | [MongoDB-backed compatibility and differences](documentdb.md) |
| OpenSearch | [Native setup](implementation-reference.md#native-opensearch), [behavior and limits](behavior-references.md#opensearch-engines-evidence-and-boundaries) |
| ElastiCache and MemoryDB | [Valkey setup and behavior](behavior-references.md#elasticache-and-memorydb-native-valkey) |
| Glue and Athena | [Actual job/query engines and licensing](behavior-references.md#glue-and-athena-engines-evidence-and-boundaries) |
| Resource Groups and AppRegistry | [Owner-backed queries, membership and application groups](resourcegroups.md) |

### Messaging, APIs and application configuration

| Area | Entry points |
| --- | --- |
| SQS | [Delivery, visibility, FIFO, retries and fairness](sqs-delivery.md) |
| SNS | [Subscriptions, notifications and delivery](sns.md) |
| EventBridge | [Buses, rules, targets, connections and API Destinations](eventbridge.md) |
| Scheduler and Pipes | [Scheduler](scheduler.md), [Pipes](pipes.md) |
| Step Functions | [Execution, tasks and integrations](stepfunctions.md) |
| Kinesis and MSK | [Kinesis engine](behavior-references.md#kinesis-streaming-dependency-evidence), [MSK brokers](behavior-references.md#msk-public-kafka-brokers) |
| Amazon MQ | [ActiveMQ/RabbitMQ execution and limits](mq.md) |
| Firehose | [Ingestion, processing and delivery](firehose.md) |
| API Gateway | [Deployed APIs and authorization](behavior-references.md#api-gateway-deployed-lambda-authorization-evidence) |
| AppSync | [GraphQL, resolvers, data sources and subscriptions](appsync.md) |
| AppConfig and AppConfig Data | [Configuration delivery, deployment and Agent use](appconfig.md) |
| SES | [Local MIME capture and sending contracts](cognito.md#classic-ses-and-shared-sending-authority) |

### Observability and governance

- [CloudWatch Logs](logs.md), [CloudWatch metrics/alarms](cloudwatch.md).
- [CloudTrail and audit delivery](cloudtrail.md).
- [X-Ray traces and time-series behavior](verification-kernel.md#x-ray-storage-and-audit).
- [AWS Config recording and rules](config.md).

## Engineering and evidence

| Reference | Purpose |
| --- | --- |
| [Architecture](architecture.md) | Service owners, transport, authorization and real data-plane boundaries. |
| [Verification kernel](verification-kernel.md) | Shared transactional events, deterministic service time and reusable IAM. |
| [Event journal](event-journal.md) | Committed events, causality and delivery ownership. |
| [SQLite state](sqlite-state.md) | Durable schemas, migrations and recovery limits. |
| [AWS Query behavior](aws-query.md) | Generated protocol/decoder behavior and fixture evidence. |
| [Behavior references](behavior-references.md) | Primary AWS sources, retained native captures and executable evidence. |
| [Cross-service consistency](service-consistency.md) | Audited invariants and remaining mismatches. |
| [Service selection](service-targets.json) | Explicit modeled service scope. |
| [Operation inventory](services.json) | Generated registration status, not semantic coverage. |
| [Remaining work](../TODO.md) | Unfinished behavior and integration targets. |

Native observations are retained in [`testdata/aws/`](../testdata/aws/); local
executable evidence is in [`testdata/integration/`](../testdata/integration/).
Ordinary builds and local clients do not require native AWS access. Do not run
probe scripts indiscriminately: some create billable AWS resources. See the
[operational boundary](operations.md#real-aws-probes-are-a-separate-operational-boundary).
