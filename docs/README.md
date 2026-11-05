# Documentation

[Project overview](../README.md)

Use the guides below to install stackd, configure clients and run workloads.
Service references describe supported operations, setup requirements and limitations.

## User guides

| Guide | Use it for |
| --- | --- |
| [Getting started](getting-started.md) | Install stackd, make AWS CLI/SDK requests, and try S3 and SQS. |
| [Releases](releases.md#install-a-published-release) | Download packages and verify checksums. |
| [Configuration](configuration.md) | Accounts, credentials, endpoints, TLS, persistence and service time. |
| [Networking](networking.md) | DNS, forwarding, certificates, runtime ports and host integration. |
| [Runtime overview](runtimes.md), [containers and engines](runtime-containers.md), [QEMU/KVM and k3d](runtime-vms.md) | Install runtime dependencies and provision workloads. |
| [Operations](operations.md) | Diagnostics, shutdown, retained infrastructure, backups, resets and troubleshooting. |
| [Examples](../examples/README.md) | Run Terraform, CloudFormation and Lambda live-reload examples. |

For development, see the [build and test instructions](implementation-reference.md#develop),
[Go embedding examples](implementation-reference.md#embed-in-go-tests) and
[generated API reference](implementation-reference.md#generated-aws-api-layer).
Source-build commands run from the repository root unless stated otherwise.

## Service guides

Services share an AWS HTTP endpoint. Each guide describes the service's resource
lifecycle, runtime dependencies and differences from AWS.

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
| EKS | [Kubernetes clusters, access and lifecycle](eks.md) |
| Route 53 | [DNS data plane and delegation](route53.md) |
| Load balancing | [Application Load Balancers](behavior-references.md#application-load-balancer-kernel) |
| ECR and CodeBuild | [Images, builds, source/artifact handling and prerequisites](behavior-references.md#ecr-and-codebuild) |
| CodePipeline | [Artifacts, actions, approvals and rollback](codepipeline.md) |
| CloudFormation and Cloud Control | [Deployment behavior](behavior-references.md#cloudformation-deployments), [Cloud Control requests](behavior-references.md#cloud-control-resource-requests), [CDK workflow](behavior-references.md#official-cdk-bootstrap-and-deployment) |
| Systems Manager | [Parameters, documents and managed execution](ssm.md) |

### Storage, databases and analytics

| Area | Entry points |
| --- | --- |
| S3 | [S3 behavior within the CloudTrail/S3 reference](cloudtrail.md#s3-dependency-scope) |
| DynamoDB | [Native backend, tables, items, streams and recovery](behavior-references.md#dynamodb-engine-references) |
| RDS and RDS Data | [PostgreSQL and MySQL](rds.md) |
| DocumentDB compatibility | [MongoDB-backed compatibility and differences](documentdb.md) |
| OpenSearch | [Native setup](implementation-reference.md#native-opensearch), [behavior and limits](behavior-references.md#opensearch-engines-evidence-and-boundaries) |
| ElastiCache and MemoryDB | [Valkey setup and behavior](behavior-references.md#elasticache-and-memorydb-native-valkey) |
| Glue and Athena | [Job and query engines, setup and licensing](behavior-references.md#glue-and-athena-engines-evidence-and-boundaries) |
| Resource Groups and AppRegistry | [Queries, membership and application groups](resourcegroups.md) |

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
| [Architecture](architecture.md) | Services, transport, authorization and execution backends. |
| [Verification kernel](verification-kernel.md) | Shared transactional events, deterministic service time and reusable IAM. |
| [Event journal](event-journal.md) | Committed events, causality and delivery ownership. |
| [SQLite state](sqlite-state.md) | Durable schemas, migrations and recovery limits. |
| [AWS Query behavior](aws-query.md) | Generated protocol/decoder behavior and fixture evidence. |
| [Behavior references](behavior-references.md) | Primary AWS sources, retained native captures and executable evidence. |
| [Cross-service consistency](service-consistency.md) | Audited invariants and remaining mismatches. |
| [Service selection](service-targets.json) | Explicit modeled service scope. |
| [Operation inventory](services.json) | Generated registration status, not semantic coverage. |
| [Remaining work](../TODO.md) | Unfinished behavior and integration targets. |

AWS observations are stored in [`testdata/aws/`](../testdata/aws/), and local
integration results in [`testdata/integration/`](../testdata/integration/).
AWS probe scripts can create billable resources; review their
[usage precautions](operations.md#real-aws-probes-are-a-separate-operational-boundary)
and [capture privacy requirements](behavior-references.md#publishing-sanitized-probe-captures)
before running them. Ordinary builds and local clients do not need AWS access.
