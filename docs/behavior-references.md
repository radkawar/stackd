# Behavior references

Primary AWS documentation, pinned AWS SDK Smithy models and retained native
captures define the reference contract. The explicit [service selection](service-targets.json)
chooses service names and model files; the generated [inventory](services.json)
contains every operation in those models, including selected prerequisite
services. No reference checkout is needed at emulator runtime.

Use primary service guides to extract concrete operations, transitions,
dependencies, negative cases and application outcomes. Keep the full emulator
goal and active [IAM completion audit](iam-completion.md). CloudTrail Lake is
explicitly excluded from the behavioral target, but remains model-known and
returns honest unsupported errors. SMTP, hardware MFA and specialty KMS remain
deferred. Model membership and documentation examples identify work to
investigate, not proof of stackd service parity.

## Publishing sanitized probe captures

Native AWS probes require an explicit `--account` and check the current STS
caller before mutating resources. The flag is an account safety check, not a
credential source or permission grant. Configure credentials through the normal
AWS CLI/SDK credential chain; no account `.env` file is required. Cross-account
probes additionally require their documented `--member-account` or
`--secondary-account`. Existing ownership, regional, and actor restrictions still
apply.

Replace `YOUR_12_DIGIT_ACCOUNT_ID` below with the authorized account. This example
only reads IAM context-key behavior; other probes can create billed resources
and must be reviewed before execution.

```sh
python3 scripts/aws/iam_context_keys_probe.py \
  --account YOUR_12_DIGIT_ACCOUNT_ID \
  --output .stackd/probes/iam/context-keys.json
```

Raw capture defaults now live under ignored `.stackd/probes/`, not tracked
`testdata/`. Keep raw captures, cleanup manifests, tokens, and resource IDs private.
Never use an anonymized publication fixture as a native cleanup manifest. Explicit
`--output` flags can still select another destination; that does not make raw data
safe to commit.

Publish an account-redacted derivative explicitly:

```sh
python3 scripts/aws/sanitize_capture.py \
  --account YOUR_12_DIGIT_ACCOUNT_ID \
  --input .stackd/probes/iam/context-keys.json \
  --output testdata/aws/iam/context-keys-published.json

python3 scripts/aws/sanitize_capture.py \
  --account YOUR_12_DIGIT_ACCOUNT_ID \
  --input testdata/aws/iam/context-keys-published.json --check
```

The default replacement is the valid twelve-digit fixture account
`000000000000`. An existing foreign zero-account reference is moved to a separate
reserved fixture alias (normally `999000999000`) so anonymization does not turn a
cross-account denial into same-account access. Conflicting reserved aliases are
rejected; choose an unused `--replacement` instead. Longer opaque resource IDs
and numeric zero values are not account aliases.

The sanitizer handles direct references, account-bearing AWS identity prefixes,
masked suffixes, JSON strings, base64/base64url, PEM, gzip, ZIP members and supported
nested combinations. It preserves raw input and updates recognized payload
MD5/SHA-256 fields when their bytes change, without repairing deliberately invalid
checksum vectors. This is an
account-redaction tool, **not a general secret scanner**: review credentials,
customer data, unrelated accounts, and opaque encrypted payloads separately.

Published captures are anonymized derivatives of the observations, not byte-exact
native artifacts. Changing signed claims or authenticated ciphertext invalidates
their original authentication. Lambda signing and EC2 identity regression vectors
are explicitly locally re-signed; affected OIDC tokens use committed fixture
keys, and the EventBridge envelope is locally re-sealed. Their metadata and tests
identify the local trust/material. Production trust validation is unchanged.
Original account-bearing artifacts and history remain only in the private backup
and private workspaces. Do not claim that a modified signature authenticates
against AWS or that anonymization establishes additional conformance.

## Generated operation inventory

`cmd/coveragegen` combines the explicit service selection with every operation
from each selected pinned AWS SDK Smithy model and actual built-in capabilities
observed through an in-process stack's `/_stackd/health` endpoint.

Use `go run ./cmd/coveragegen` to write the inventory. `-sdk` selects the SDK
checkout (default `clones/aws-sdk-go-v2`), `-services` selects the explicit
service-name/model selection file (default `docs/service-targets.json`), `-out`
selects the output (default `docs/services.json`), and `-check` checks generation
drift without rewriting it. The SDK and selection are generation inputs, not
runtime dependencies. `make generate-coverage` regenerates the checked-in
inventory; `make generate-coverage-check` checks it.

A selected service can explicitly pin a historical model revision when its model
has been removed from the current SDK. Elastic Transcoder pins its last model at
`0715b3f166d60399fb9b82e1f11db84bd6a5bb5c`, before removal in
`99e064ec693d5166382eea34630b2e11fa0e3484`. For that selection, the generator reads
the model with `git show` at the declared revision; this is not a silent fallback.
The SDK checkout must therefore retain the required Git history and model
objects locally. A source archive or shallow checkout without those objects is
insufficient to regenerate the complete inventory.

The generated output records model provenance and operation registrations.
Every modeled operation of a selected service belongs in the inventory, not
just its implemented operations. Keep the existing chosen services and
implemented prerequisite services in the explicit selection; changing service
scope is a reviewed input change, not a side effect of handler registration.
Behavioral exclusions and deferrals do not erase modeled operations.

Selection IDs must match generated provider identities, while `model` retains
the SDK filename: for example, `configservice` / `config-service`,
`cognitoidentity` / `cognito-identity`, and `ssoadmin` / `sso-admin`.
The generator rejects mismatched identities and duplicate model selections
rather than misclassifying implemented operations as unimplemented plus extra
registrations. Signer, SSO and SSO OIDC are selected prerequisite services with
their complete modeled inventories, not just their registered operations.

Registration establishes at most `partial`; an unregistered operation is
`unimplemented`. These are registration statuses, not a behavioral coverage
score. Generated decoding followed by an unsupported error contributes no
implemented resource behavior. Native workflow/fixture evidence must establish
transitions, negative cases and cross-service boundaries separately. Do not
infer lifecycle, authorization, persistence or data-plane semantics from Smithy
shapes or successful dispatch.
The Go-native ownership and generation constraints live in
[architecture](architecture.md).

## Sources and responsibilities

| Source | Use |
| --- | --- |
| Explicit selection: `docs/service-targets.json` | Reviewed service-name/model mapping, including implemented prerequisites; no operation-level filtering |
| AWS SDK checkout: `clones/aws-sdk-go-v2` | Authoritative Smithy transport, operation and typed schema contracts; consumed by `cmd/awsgen` and `cmd/coveragegen` |
| AWS service reference: `internal/iam/catalog/data/service_reference.json.gz` | Pinned official action/resource/condition and last-access metadata; consumed by `cmd/iamgen` |
| IAM dataset: `clones/iam-dataset/aws` | Optional comparison material; draft mappings do not control authorization |
| Official AWS documentation and owned live probes | AWS validation, state transitions, authorization, response fields and error behavior; preserve evidence and replay locally |

Record the source path and revision when turning a documented scenario into an
implementation requirement or fixture. Capture the actor, account/partition/region,
permissions, operation sequence, observable state, denial behavior and cleanup.
Normalize generated identifiers and timestamps without erasing meaningful field
presence, ordering or errors. Ordinary tests use local endpoints and explicit test
credentials; a reference checkout or real account is not a runtime dependency.

## Current service entry points

The maintained guides below retain primary AWS citations and identify the
native evidence and remaining boundaries for each workflow.

| Area | Maintained guide or primary contract | Behavior to carry into the audit |
| --- | --- | --- |
| IAM identities and role sessions | [IAM completion audit](iam-completion.md) | User/access-key creation, changed caller identity, temporary credentials, role trust and current role permissions |
| Permission enforcement | [Architecture](architecture.md) | Deny before granting a policy, allow after granting it, policy composition and service-to-service authorization |
| Organizations controls | [Resource controls](iam-resource-controls.md) | Root/OU/account policy inheritance, cross-account source controls and management-account exemptions |
| Simulation and diagnostics | [IAM simulation](iam-simulation.md) | Principal simulation, complete result fields, policy provenance, implicit/explicit denial and dependent `iam:PassRole` permissions |
| Cryptography and messaging | [KMS](kms-cryptography.md), [SQS](sqs-delivery.md), [SNS](sns.md) | Actual cryptography, key lifecycle, queue visibility/dead-letter transitions, topic policies/filtering/signatures and real subscriber delivery |
| Event routing and audit | [EventBridge](eventbridge.md), [CloudTrail](cloudtrail.md) | Custom-event routing, rule language, target permissions/retries, management history and trail delivery; preserve Lambda and S3 dependencies |
| Metrics and runtime logs | [Event kernel](event-journal.md), [Logs](logs.md) | Service metric semantics, alarm state/actions, real Lambda log ingestion and subscription delivery to downstream services |
| DynamoDB data and streams | [DynamoDB Local notes](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.UsageNotes.html) | Table/index lifecycle, actual item expressions and transactions, Streams, TTL, IAM fine-grained access and throughput scaling; validate the pinned engine rather than assuming Local has AWS semantics |
| OpenSearch | [IAM rename contract](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html), [access control](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ac.html) | Native documents/mappings/query/bulk bytes, current policy/tag authority, modern/legacy controls on one domain, scoped durable engines and explicit unsupported managed effects |
| EC2 disk prerequisites | [EBS direct APIs](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-accessing-snapshot.html), [EC2/EBS evidence guide](ec2.md#ebs-direct-snapshot-data-plane) | Real sparse block bytes, parent lineage, encryption and IAM; native captures, actual ext4 restore and remaining volume/AMI boundaries |
| EC2 launch templates | [Version inheritance](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateLaunchTemplateVersion.html), [launch permissions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/use-launch-templates-to-control-launching-instances.html), [instance-data dependencies](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetLaunchTemplateData.html) | Scoped immutable versions, current IAM/PassRole, real RunInstances consumption and protected origin tags; [the EC2 evidence guide](ec2.md#launch-templates-and-instance-admission) distinguishes native controls, native instance observations and actual local guest execution |
| EC2 Auto Scaling | [Lifecycle hooks](https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html), [group metrics](https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-metrics.html) | Real EC2 ownership, original-caller admission, service-linked execution, hooks, protected replacement, schedules and ALB/CloudWatch dependencies; [the current contract](ec2.md#ec2-auto-scaling) preserves measured force-delete and absent-warm-pool differences |
| Scope and state | [Typed persistence](sqlite-state.md) | Account isolation, observable save/restore behavior and extension lifecycle expectations |

Exercise dependency paths such as SNS to SQS, EventBridge targets, API Gateway
integrations, Lambda execution roles and S3 notifications as each dependency
becomes available, following the inside-out service order. Inventory membership
does not establish that a dependency or integration is implemented.

The [Lambda behavior guide](lambda.md) records owned Python 3.12 captures and
official-image SDK replay paths on memory/SQLite, including timeout reset with
`/tmp` retention, version-keyed runtime ownership, current execution-role policy
changes and real customer boto3 SQS calls. Its evidence inventory covers immutable
versions, aliases/weighted routing, qualified IAM with live base tags, asynchronous
settings/retargeted retries, destinations, native audit identities and metric
dimensions, alongside the EventBridge → Lambda → SQS chain. It distinguishes
capture-only observations from implemented/replayed contracts and retains the
unresolved retry-two deletion terminal, propagation and runtime limits explicitly.

The [CloudTrail behavior guide](cloudtrail.md) also owns the S3 trail dependency
contract: binary objects, actual gzip records, native resource identities,
service-principal permission checks, selector admission and default-bus delivery.
Owned AWS fixtures retain HTTP outcomes, request-ID/event-ID correlation, bounded
timing evidence and cleanup. The `cmd/cloudtrailgen` vocabulary comes from AWS's
Data events table rather than a manually maintained per-service selector list.
The [encrypted trail contract](cloudtrail.md#kms-encrypted-trail-logs) owns native
KMS admission, marker side effects and current-key retry evidence. Its source-linked
fixtures distinguish observed late delivery from bounded missing records; they do
not turn local scheduler intervals into AWS guarantees.
The same guide owns [S3 requester payment and server access logging](cloudtrail.md#s3-requester-payment-and-server-access-logging),
including charge-header admission, paired caller/owner audit projections,
27-field public records and actual encrypted delivery from HTTP/internal commands.
The final `testdata/aws/s3/requester_payment_evidence.json.gz` and
`access_logging_evidence.json.gz` retain native request correlations and cleanup.
Positive log delivery is not proof of exact transition cutoffs, all-event
delivery or billing charges; legacy log ownership and copy-source operation
spelling are primary-documentation contracts, not new native-capture results.

The [SNS behavior guide](sns.md) owns standard-topic admission, policy/filter
semantics, signed SQS/Lambda projections and retained service metrics. Native
fixtures distinguish per-entry versus whole-request rejection, malformed
attribute filtering, weighted percentiles and terminal redrive counters. Real
official-runtime and CLI/SQLite replays exercise the actual subscriber commands.

The [Step Functions guide](stepfunctions.md) owns workflow state, task and
observation contracts. `testdata/aws/stepfunctions` retains native control,
dataflow, callback, task, Lambda, Map, quota and observation captures. Its evidence
table distinguishes captured behavior from actual local fixture/runtime replay.

## OpenSearch engines, evidence and boundaries

Wire contracts use AWS SDK model checkout
`113bc91bf12edc3af1d3aba1c70be28494d54c2a`. Real search behavior requires the
native engine, not a toy store or one native cluster shared between
domain/account/Region owners.

The installed-only image
`opensearchproject/opensearch@sha256:9e0b3b3b6805811bd63d9b9503ffe34a58ba33d03cc346000e318c6ff5c05bd9`
is upstream OpenSearch 2.19.4 (Apache-2.0). The observed root endpoint reported
distribution `opensearch`, build `e2e89961c9a327daf514a7ce1320a6189bfd08cd`.
Each domain uses one actual node, an exact-owned Docker volume/network and a
loopback-only private REST listener. Local host processes/Docker administrators
are trusted; this does not promise AWS VPC isolation, EBS capacity or encrypted
managed transport. Installation/setup and the public scoped endpoint contract
are in the [implementation reference](implementation-reference.md#native-opensearch).

Modern implemented controls are CreateDomain, DescribeDomain(s),
DescribeDomainConfig, UpdateDomainConfig, DeleteDomain, ListDomainNames,
ListVersions and AddTags/RemoveTags/ListTags. The legacy ES frontend shares these
owners for description/configuration/deletion, listings and tags; legacy engine
creation remains an explicit unsupported-engine error. Only
`OpenSearch_2.19` is advertised and admitted. Version changes, instance capacity,
multi-node/AZ topology, EBS, VPC, KMS, TLS, fine-grained/internal-user security,
snapshots, upgrades, packages and Dashboards are not inert accepted metadata:
unsupported supplied effects fail. Native global mutation, plugins and remote
reindex are blocked rather than bypassing their missing owners. Supported native
advanced options are `indices.query.bool.max_clause_count` and
`rest.action.multi.allow_explicit_index`; both were shown to change actual
native error/acceptance behavior without losing documents.

`scripts/aws/opensearch_controls_probe.py` retained **58 actual native calls and
58 exact-request-ID management audit matches** in
`testdata/aws/opensearch/controls.json`. This free control/IAM calibration used
account `000000000000`, `us-east-1`, and did not provision a paid search domain.
Both native domain inventories were empty. Both API generations report absent-domain
describe/config/delete as HTTP **404 ResourceNotFoundException**, not the model's
409. Invalid domain names return 400 ValidationException. Seven old/new-action
IAM allow/deny combinations, in two native rounds, showed symmetric permission
aliases and either explicit deny defeating either allow. The ordinary identity,
session, boundary and resource-policy layers apply those aliases; Organizations
layers use only the actual action, following the
[documented SCP exclusion](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/rename.html).
No native Organizations policy was mutated to test that exclusion.

Both API versions emit `es.amazonaws.com` management events while preserving
their actual legacy/modern event names. Wire AccessDeniedException becomes audit
AccessDenied with null parameters. Captured invalid-name events omit parameters;
missing-domain deletion records retain `{"isElasticsearchDomain":true}` despite
the failed request. Empty ListDomainNames inputs have null audit parameters.
The native fixture replay exercises error status/code, current same-session
rename policies and source audit fields on **memory and SQLite**, correlating
each local outcome to its own request ID and the retained native call label.
The owned native role and policy were deleted; final GetRole/GetRolePolicy
observed NoSuchEntity. Capture bounds, source links and cleanup request IDs remain
in the fixture and `documentation.json`.

`scripts/opensearch_smoke` launches the actual race-built executable with SQLite,
uses official OpenSearch/legacy/IAM/CloudWatch/CloudTrail SDKs and the normal
OpenSearch Go client with its AWS signer. It exercised strict mappings and
mapping conflicts, bulk partial errors, escaped document IDs, bool/range queries
with sorting/aggregation, current IAM/tag/resource-policy deny recovery,
immutable-principal binding after identity recreation, and account/Region/domain
isolation. Unsigned requests required current public/IP grants, and forged
forwarded-IP headers could not change authority. Controller and exact-owned
native-container restart preserved the
same query result. Real native statistics reached AWS/ES CloudWatch metrics,
and management outcomes appeared under the native source name. The smoke filters
its audit lookup by `UpdateDomainConfig` so routine lifecycle polling cannot push
the management evidence out of an unfiltered first page. Deleting and
recreating the same domain invalidated the stale endpoint and retained no old
documents. Final exact-namespace container/volume/network inventories were empty.
No AWS paid-domain/data-plane behavior is claimed by this local upstream proof.

The pinned 2.19.4
[PathTrie](https://github.com/opensearch-project/OpenSearch/blob/2.19.4/server/src/main/java/org/opensearch/common/path/PathTrie.java)
and [document route](https://github.com/opensearch-project/OpenSearch/blob/2.19.4/server/src/main/java/org/opensearch/rest/action/document/RestGetAction.java)
discard literal terminal path separators. Before the boundary correction,
the signed executable reproduced canonical `/catalog/_doc/secret` and
`/catalog/_search` denials (403), while their `/` and `///` suffixes returned
200 with the denied document or search results. This occurred with both exact
identity-policy and domain-resource-policy denies under a wider path allow.
The boundary now rejects these redundant literal separators with
`400 ValidationException`, rather than trimming decoded paths into another
resource. The executable's
`scripts/opensearch_smoke/testdata/path_authorization.json` regression exercises
both policy layers, ordinary allowed documents, root `/`, and a separate
`secret%2F` document whose native ID is `secret/` and whose source differs from
`secret`. Encoded-ID requests remain intact; adding a literal slash after the
encoded ID is rejected. This is pinned local-native evidence, not live AWS
managed-domain conformance.

`TODO: Comeback` markers remain for the managed/native capability gaps above,
successful legacy domain/config version-field calibration, and successful
provision/update/tag CloudTrail projection calibration. The free native version
list includes prefixed OpenSearch versions but does not establish every
successful legacy domain response. Audit projections for these successful
effects are source-owned modeled behavior pending that calibration. Native
search/index/bulk calls are **not** invented CloudTrail events:
[AWS documents configuration-only OpenSearch audit coverage](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-cloudtrailauditing.html).

## Glue and Athena engines, evidence and boundaries

The retained enterprise inventory is the target, not an operation-count parity
claim. `testdata/aws/glue/evidence_index.json` and
`testdata/aws/athena/evidence_index.json` distinguish canonical native captures,
failed attempts, recorder corrections and verified cleanup. Native AWS evidence
includes catalog/version/partition errors, schema compatibility/version lifecycle,
connections/classifiers/workflows/tags, actual Python-shell success/failure,
Athena workgroup/prepared controls, cancellation, typed results, current-policy
denial and EventBridge-to-SQS consumers.

The native AWS producer wrote real S3 rows `north,4`, `south,14`, `north,6`;
Athena produced and an independent S3 consumer read totals north=10/south=14.
This is AWS-reference evidence, not proof that the local executable matched it.
The campaign retained 760 CLI/raw calls, five accepted bounded Python-shell runs
and five distinct Athena queries. Owned cleanup is recorded, including recovery
captures; the conservative cost planning estimate below $0.10 is not a billing
measurement. No paid Spark jobs, crawler runs or EC2 instances were used.

Local imported-engine probes exercised real Glue DynamicFrames, decimal/date/null
Parquet round trips, Python SDK credential callbacks, Spark event-log counters,
process cancellation and actual Trino Glue/S3 reads. Typed repository tests and
native SQLite probes exercise scope, rollback and reopening. The reproducible
assembled gate is `scripts/aws/analytics_executable_smoke.py`, which launches an
owned CLI/SQLite stack and consumes actual S3, Logs, metrics, events and query
results. A passing engine probe or API fixture alone does not satisfy that gate.

`testdata/athena/runtime_executable_workflow.json` retains the passing complete
fresh-state executable run: Python producer and independent S3/API consumers;
actual SSE-KMS Spark Parquet and partitioned JSON crawlers; prepared EXECUTE;
native Hive DDL and Iceberg create/insert/read; current user/S3 and execution-role
denials; real job/query failure and cancellation; regional isolation; in-flight
workflow/job restart without relaunching the native container; retained result
bytes; and actual Logs, CloudWatch metrics, EventBridge-to-SQS and CloudTrail
consumption. Both race-enabled controllers exited zero, with no error or race
diagnostics. All tracked native containers were absent without forced cleanup.
The probe retains redacted CLI failure diagnostics and checks controller logs
and exit status rather than treating successful client output as sufficient.
Earlier failed runs remain documented, including the concurrent native removal
race fixed by joining execution-owned cleanup. This closes this assembled
workflow gate, not the enterprise gaps below.

`testdata/athena/runtime_postgresql_executable.json` records an actual PostgreSQL
16 crawler through the race-enabled executable: bigint/string/decimal/date
discovery, KMS-encrypted connection credentials, authorized plaintext projection,
rejection after changing the current password, restoration, and the same catalog
after SQLite/controller restart. Both controllers exited zero with clean logs.
The libpq child uses a private HOME and Kerberos credential paths, with GSS
encryption disabled; it does not borrow host client certificates or credentials.
This is direct PostgreSQL discovery, not a general JDBC/VPC or AWS crawler claim.

`testdata/athena/runtime_glue_review_corrections.json` retains focused
before/after executable proof for the pre-integration review, without replaying
the unchanged broad workflow above. Current job tags now govern `GetJobRun`,
`GetJobRuns` and `BatchStopJobRun`: actual IAM callers exercise both
`aws:ResourceTag` and `glue:ResourceTag` explicit Deny and conditional Allow,
including changed tags and intentionally retained runs after job deletion.
Rejected Create/UpdateConnection audit records omit synthetic password/token
sentinels from Athena, Spark and Python override maps through the existing
connection redaction owner while retaining nonsecret diagnostics.

The same record reproduces an exited Spark process stuck in RUNNING/STOPPING
because event-log parsing blocked lifecycle inspection. The corrected
race-enabled controller completes malformed/truncated-log jobs as SUCCEEDED
and an oversized-record cancellation as STOPPED, retaining observation errors
without publishing partial counters. All three release their credential
callbacks and native containers; each queued successor executes real Python.
Both corrected proof controllers exit zero with clean logs. The original stuck
baseline and its required owned-container force cleanup remain recorded rather
than presented as a successful cleanup.

#### Connection password settings: creation/update versus projection

AWS's [ConnectionPasswordEncryption contract](https://docs.aws.amazon.com/glue/latest/webapi/API_ConnectionPasswordEncryption.html)
describes encrypting the password “as part of `CreateConnection` or
`UpdateConnection`” and storing `ENCRYPTED_PASSWORD`. It requires those callers
to have `kms:Encrypt`; when encrypted return is enabled, passwords “remain
encrypted” in GetConnection/GetConnections responses. The
[encryption guide](https://docs.aws.amazon.com/glue/latest/dg/encrypt-connection-passwords.html)
states: “When the connection was created or updated, an option in the Data
Catalog settings determined whether the password was encrypted”.
These sources do not establish a retroactive rewrite or `kms:Encrypt` on reads.
The retained native controls fixture only observes encryption disabled; no
account-wide native setting was changed to infer an old-plaintext-row transition.
Accordingly, the review's retroactive-encryption premise is unestablished, not
a fixed projection bug, and no migration or read-time encryption was invented.

Focused local proof instead covers the supported explicit UpdateConnection
transition after enabling encryption, using the actual current IAM/KMS owners:
an Encrypt Deny rejects the update, replacement policy permits ciphertext
storage, and disabling encrypted return makes both retrieval APIs honor current
Decrypt permission. [HidePassword](https://docs.aws.amazon.com/glue/latest/webapi/API_GetConnection.html)
still permits metadata retrieval without decryption. The exact native response
for a pre-existing plaintext row immediately after a setting change remains
unobserved; the retained local response is not asserted as an AWS guarantee.

### Runtime versions and licensing

Installed-only defaults:

- Trino 476, Apache-2.0:
  `trinodb/trino@sha256:00125e40d063bc4816d165482f6044872b18b56026fb959d3b28ce1f96ffbbee`.
- Native Hive-DDL parser, Apache Spark 4.1.3:
  `apache/spark@sha256:9b0a6c2c860f5e7d18dd5270286fef32a09c7f5a7e2b0dbe5642de8a3a02ab3e`.
  It parses native syntax trees; it is not an alternative SQL execution engine.
- Glue 5 local-development image, Spark 3.5.4-amzn-0 / Python 3.11:
  `public.ecr.aws/glue/aws-glue-libs@sha256:a54bd25fb72c55a2f28d07656a3cda943a042f345cc25f4c2c170667be864f01`.
- Python-shell interpreter image, Python 3.9:
  `public.ecr.aws/lambda/python@sha256:6aa6ba1ae1662df3e7400a25d3293bc464c3a907da13370eec7637128c8eb0a3`.
  This is not the complete AWS Glue analytics-library bundle.

The Glue libraries' [Amazon Software License 1.0](../compute/glue/AWS-GLUE-LICENSE.txt)
is retained verbatim from the
[upstream license](https://raw.githubusercontent.com/awslabs/aws-glue-libs/master/LICENSE.txt).
Section 3.3 limits use to software used or intended for Amazon's services,
platforms or applications. AWS's
[local-development documentation](https://docs.aws.amazon.com/glue/latest/dg/develop-local-docker-image.html)
expressly describes developing and testing AWS Glue 5 jobs in this local Docker
image: “You can flexibly develop and test AWS Glue jobs in a Docker container.”
That is the supported AWS-targeted development/testing boundary here. Optional,
operator-owned installation does not waive the restriction. No image or Glue
library is redistributed, no general-purpose/other-cloud use permission is
claimed, and the image's other components retain their own licenses.
Athena's parser deliberately uses the available Apache image instead.

AWS documents local Glue-image limitations including job bookmarks, the
Glue-specific Parquet writer, Data Quality and Lake Formation credential vending.
Normal native Spark Parquet execution does not establish those features.
The [Python-shell guide](https://docs.aws.amazon.com/glue/latest/dg/add-job-python.html)
also records the native library versions, version-3 alias and logging groups.

### Remaining enterprise boundaries

Retain the following gaps rather than interpreting registration as completion:

- Glue federated/provisioned catalogs, Lake Formation transactions/governance,
  multidialect views and time-travel partition snapshots; local partition-index
  validation is not a native backfill timing or acceleration claim.
- Distributed worker shapes, streaming/Ray, custom dependency/connection loading,
  bookmarks and the native Python analytics bundle. Python-shell S3 security
  configuration is not implemented by inventing interception of arbitrary
  customer SDK writes. Spark metrics currently publish observed final counters,
  not the native continuous cadence; captured logs are bounded terminal output.
- Crawlers beyond S3 and direct PostgreSQL, VPC/custom JDBC drivers/certificates,
  crawler log encryption, Lake Formation/lineage, event/incremental recrawls,
  advanced configurations, large-object range sampling and the full classifier
  vocabulary. Native AWS crawler execution was not captured.
- Whole-catalog encryption; advanced JSON schema compatibility containment,
  protobuf scalar/oneof migrations and protobuf syntax diffs; workflow EVENT
  batching, delayed trigger notifications and data-quality encryption.
- Athena Spark/engine-v2, managed results, Identity Center, S3 Access Grants,
  capacity configuration, federated provisioning/connectors, CSE_KMS,
  DATA_MANIFEST and missing S3Tables prerequisites. SQL PREPARE/DEALLOCATE are
  explicitly rejected until native prepared-state changes can persist; API
  prepared statements are distinct. Athena CTAS-specific properties and exact
  Delta/Iceberg version/concurrency compatibility need separate proof.
- Buffered whole-query CSV results, local native resource bounds, and scan-limit
  accounting/cadence are not AWS service-capacity guarantees.


## DynamoDB engine references

The optional ExtendDB checkout was reviewed at
`cbf3452eedcb1cea08a38db47184e08d5480ae8b` (0.1.11, Apache-2.0).
Its `crates/core/src/expression`, numeric validation and item-size code are useful
comparison material. `crates/storage-sqlite/src/data/transactions.rs` and
`crates/storage-postgres/src/gsi_queue.rs` show item/stream/index-intent commits
and deferred index application. These are references, not a second stackd IAM,
storage or scheduling authority. Preserve Apache attribution if copying code.

DynamoDB Local remains the selected data plane. ExtendDB lacks PartiQL and
global tables; its whole server brings its own mandatory authentication,
catalog/bootstrap, wall-clock workers and production TLS. Backends are selected
at compile time, not through the draft runtime plugin design. Its SQLite backup
restore loses index definitions, and its live-AWS measurement claims have no
retained wire captures in this revision. None establishes AWS conformance.

An owned Docker probe of DynamoDB Local 3.3.1 at
`sha256:ff89bd48ff32cd8d9be5fee8873b65b8854dc408f1afe881be6eb00247bc0dab`
verified item transactions, PartiQL, Streams, namespace isolation and graceful
durable reopen. Unlike the current usage notes, this version honored PartiQL
`Limit` and retained billing/throughput metadata; throughput enforcement was not
established. Case-distinct table creation failed, and tags/PITR/backup operations
were unsupported. A startup banner and open port did not establish readiness:
incorrect volume ownership prevented database access until corrected. Engine
reopen observations alone do not establish crash durability or AWS conformance.

The Go control owner now maps case-distinct table names to opaque native names,
retains table/index intent in memory or SQLite, and activates resources only
after native readiness. Selected controls, item/transaction behavior, IAM
conditions and immutable policy-principal bindings replay through the AWS SDK
on both stores (`testdata/aws/dynamodb/replay.json`). Actual executable checks
also exercised SQLite restart, service-time TTL deletion and linked-role
table/GSI capacity changes with independent read/write targets.

Fresh `partiql_pagination.json` observations distinguish `NextToken` from
`LastEvaluatedKey`, projected/filtered keys, fan-out boundaries and request-bound
tokens. The pinned backend omits evaluated keys; its adapter now recovers the
physical key from its continuation for the selected replayed pages. SDK replay
across both store reopen paths and the actual executable now enforce exact
statement/ordered-parameter binding while accepting changed limits and
consistency. Exact continuation/exhaustion boundaries and cursor lifetime remain
open; recovering evaluated keys does not establish those semantics.

`capacity.json` retains 74 native calls and a separate pinned-backend comparison.
The backend undercounts empty Query and missing-key BatchGet reads, differs on
mixed batch/transaction totals, omits transaction directional fields, and omits
PartiQL capacity. The adapter corrects empty Query/Scan minima, processed
missing-key BatchGet charges and TransactGet directional fields. Source-owned
write accounting uses actual pre/post images under the native mutation gate;
`capacity_item_sizes.json` and `index_capacity.json` capture byte boundaries,
projected/sparse index transitions, key moves and transaction multipliers.
The table write charge doubles for transactions; index write charges do not.
`transaction_tokens.json` captures retained original-size replay reads after
items grow or disappear, canonical request equality, and canceled/invalid input
distinctions. The native token window still runs on the container's real clock,
not the service clock. These captures do not establish throughput enforcement.

`read_throttling.json`, `write_throttling.json` and
`fresh_provisioned_throttling.json` retain 440 native calls across four owned
tables, all deleted with absence observed. The read/write probes share signed
JSON error decoding; the write probe's `--fresh` case creates directly at
1 RCU/1 WCU rather than inheriting on-demand history.

- A fresh, ACTIVE table with provisioned and warm throughput of one accepted
  a 350-unit PutItem. Its next small UpdateItem against that large image
  throttled; concurrent updates mixed accepted 351-unit mutations with
  `TableWriteProvisionedThroughputExceeded` and
  `TableWriteKeyRangeThroughputExceeded`. Strong projected reads found every
  accepted marker and none of the rejected markers.
- The transitioned 1-RCU table returned 96/48 units for strong/eventual reads
  of projected 384 KiB items. One pressure request returned
  `TableReadProvisionedThroughputExceeded`; other calls in the same wave
  succeeded. Settled throughput metadata does not specify a deterministic
  admission threshold or prove that internal changes have fully propagated.
- A GSI at one WCU, with its base table at 32 WCU, returned
  `IndexWriteProvisionedThroughputExceeded` with the index ARN for both a
  projected update and an update leaving its INCLUDE projection unchanged.
  Neither mutation applied. A later sparse write succeeded, but pressure
  recovery prevents inferring an unconditional sparse-write exemption.
- TransactWriteItems and ExecuteStatement returned top-level
  `ProvisionedThroughputExceededException`; BatchExecuteStatement returned
  per-statement `ProvisionedThroughputExceeded` and `TransactionConflict`.
  Strong reads verified rejected mutations absent and successful siblings
  present. BatchWriteItem/BatchGetItem partial outcomes and ExecuteTransaction
  throttling were not reached by these bounded probes.

These captures establish error/mutation boundaries, not a quota algorithm.
AWS documents [best-effort burst capacity and physical partition limits](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/burst-adaptive-capacity.html);
neither a strict `300 × provisioned units` ceiling nor a fixed captured throttle
ordinal follows from that contract. Do not reject every request larger than
that proposed ceiling: the fresh-table capture contradicts that rule.
AWS's [2022 architecture paper, section 4.2](https://www.usenix.org/system/files/atc22-elhemali.pdf)
describes time-limited router tokens, estimated global consumption and separate
partition admission. It does not publish today's allocation constants or make
one globally exact counter the public contract. Do not reproduce distributed
router machinery merely to fit one observed request sequence.

`throughput_boundaries.json` adds 512 native calls across two further owned
tables, both deleted with absence observed. A fresh 1/1 table accepted 27 of 31
351-unit updates at 12-second cadence over 361 seconds, including successes after
five minutes; four throttled. The final strong read found all successful markers
and none of the rejected markers. This contradicts treating a five-minute global
balance as AWS's exact allocator, not merely a one-time oversized-request check.
The separate batch table transitioned from on-demand and retained higher warm
throughput; its observations must not be described as fresh-provisioned results.
Of 84 BatchWriteItem calls, ten returned partial outcomes and two failed wholly.
Every accepted small sibling in the partial outcomes was found; eight rejected
large deletes were verified unchanged and two verification reads throttled.
The 24 ExecuteTransaction calls included three successes, sixteen throughput
failures and five conflicts; strong reads verified both successful siblings and
the absence of rejected siblings. The 192 BatchGetItem calls produced 113
successes and 79 top-level throughput errors, but no partial response.

`throttle_metrics.json` retains subsequent CloudWatch requests/results.
`ExecuteTransaction` requires the `OperationType=Write` dimension: its published
request count was sixteen. `ExecuteStatement` with `Verb=PartiQLUpdate` published
six. The unqualified/empty series are not measured zeros. AWS documents these
[operation-specific dimensions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html).
`batch_request_size.json` records the original BatchWriteItem wire boundary:
16 MiB reached normal missing-table validation; one additional byte returned an
empty HTTP 413. Filtering/splitting a batch must not make an oversized original
request valid.

The shared provisioned/configured-on-demand admission owner holds the native data gate across
checking, execution and charging. Positive credit admits a scalar operation;
its completed cost may overdraw the balance. Unused credit is capped at five
minutes and refilled at the observed provisioned capacity or configured on-demand
maximum using service time, including actual table/GSI control changes.
This bounded model does not claim
the sustained native acceptance rate or private key-range allocation. Budgets
are process-local, not retained across restart. Table/GSI throttles carry their
full resource ARN and publish reason-specific events; top-level throughput
failures also publish operation-qualified request counts.

BatchWriteItem validates the complete original request before previewing known
put/delete costs and executing admitted members. BatchGetItem first validates the
complete original request and preserves the native unprocessed/response-size
boundary. When available credit covers its processed keys, that native response
is used directly. Under pressure, singleton native batches admit and charge each
key while preserving projection and consistency; the auxiliary whole-batch read
is not billed. Unprocessed keys can be retried verbatim after service-time
recovery. Missing items consume their minimum read units and can produce a
successful partial response with no returned items. This follows the documented
[within-table partial-result contract](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchGetItem.html),
not a captured throttle ordinal. Fixtures exercise projected and missing keys on
both stores; the retained CLI also verified accepted-only CloudWatch billing.
Transactions reject before mutation. Capacity-limited PartiQL batches
execute native singleton batches under the shared gate so each completed statement
informs the next admission decision while retaining native per-statement errors.
Post-image accounting never rejects an already-applied write; there are no
compensating writes or rejected-mutation Streams records. GSI admission does not
skip writes whose eventual index charge is zero.

`testdata/dynamodb/admission.json` exercises those local contracts through SDK
requests on memory and SQLite: invalid batches, partial/total throttles, rejected
effects and Streams, independent GSI pressure, service-time/scaling recovery,
retained maximum controls, and fully qualified pending metrics after reopen.
Pressure stops on the first actual rejection, not a captured native ordinal.
This fixture is not an AWS quota oracle. Account-default/key-range enforcement
and exact partition accounting remain open.

Configured on-demand behavior is retained in
`testdata/aws/dynamodb/on_demand_limits.json` and reproduced by
`scripts/aws/dynamodb_on_demand_probe.py`.
The primary capture, paced control supplement, composite-operation addendum and
GSI-creation boundary capture retain 1,159 native calls in the approved
account/region; every owned table was verified absent. These are separate
sequence namespaces, not a claim that the consolidated script was executed once
with identical timing. Primary contracts are the
[maximum-throughput guide](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/on-demand-capacity-mode-max-throughput.html)
and [CloudWatch metric definitions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html).

- Table and GSI maximums are independent, optional read/write settings. Partial
  updates retain positive settings in the other direction. Explicit `-1` removes
  a limit and appears in that response; a later update drops previously removed
  settings. Cap-only updates return `ACTIVE`. Billing-mode changes to provisioned
  clear both table and index maximums; switching back does not revive them.
- Table and index creation reject `-1`, including index creation through
  `UpdateTable`; updates of existing limits accept that removal sentinel or
  positive values. Exceeding the account's 40,000-unit table/index maximum produces
  `LimitExceededException`. Two independent empty table maximum updates produced
  `InternalFailure`/HTTP 500; empty index updates produced `ValidationException`.
- Table read/write and GSI read maximum failures use `ThrottlingException` and
  lowercase `throttlingReasons`. Captured scalar GSI writes instead use
  `ProvisionedThroughputExceededException` and capital `ThrottlingReasons`.
  GSI-write `TransactWriteItems` and `ExecuteTransaction` use the former
  `ThrottlingException` form, with no `CancellationReasons`. PartiQL batch UPDATE
  statements return `ThrottlingError` per statement. Rejected transactional
  updates and sibling inserts were absent in strong verification reads.
- All four `MaxOnDemandThroughputExceeded` reasons and their resource ARNs were
  observed, including unchanged-projection GSI backpressure and an independent
  uncapped index. Native CloudWatch published reason-specific table/index counters
  and configured table gauges of 37 read and 41 write units. GSI gauge values and
  removed/absent-limit gauge behavior were not captured. An absent series is not zero.

Native table-maximum composite write failures, maximum-throttled BatchWriteItem
and read-maximum PartiQL statement errors remain unreached in this capture.
Successful calls during other operations' pressure do not establish exemption
from throttling. Neither these observations nor the documented best-effort
maximum promises establish a private allocator, exact refill or throttle ordinal.

The pinned Local backend is not the owner of these controls: its partial table
updates fail, unrelated updates erase table settings, and index updates can ignore
them. Go validates and retains the generated settings, strips them from native
mutation inputs, and preserves them through native observation. Removing a
maximum clears only that direction's admission balance; another limited direction
keeps its debt. Configured gauges use the documented five-minute sampling cadence.
The actual retained executable verified scalar/transaction/statement error forms,
recovery after service-time advancement, surviving read-17/index-write-32 settings
and item data, and pending reason metrics plus updated gauges in CloudWatch after
restart. All smoke containers, volumes and temporary files were removed.

Provisioned decrease controls are captured by
`scripts/aws/dynamodb_decrease_probe.py` in
`testdata/aws/dynamodb/decrease_limits.json`: 338 native API calls, including the
approved-account identity check and verified owned-table deletion. The primary
contracts are the [throughput quota guide](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html)
and [throughput history fields](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ProvisionedThroughputDescription.html).

- Four consecutive decreases succeeded independently for the table and a GSI.
  Both-direction and mixed increase/decrease requests consumed one decrease.
  Fifth requests returned `LimitExceededException`; the error reported the next
  eligible time as the last settled decrease plus 3,600 seconds.
- Unchanged capacity returned `ValidationException`. A blocked or unchanged
  member rejected a combined request atomically, preserving eligible siblings.
  Increases remained available after exhausting decrease quota.
- Immediate update descriptions exposed old capacity/count with provisional
  timestamps; settled descriptions exposed new capacity/count and settlement
  timestamps. Mixed directional changes updated both timestamp fields.
- Billing transitions preserved the table's count and settled history, including
  reverting a provisional table increase timestamp on returning to provisioned.
  GSIs differed: entering on-demand reduced units to zero and counted a decrease,
  even for an already exhausted GSI. Restoring provisioned units advanced GSI
  increase history. Actual post-roundtrip decreases remained blocked.
  These conclusions require waiting for every GSI to become `ACTIVE`, not just
  the table: intermediate descriptions exposed different history.

The capture did not wait for hourly or UTC-day recovery. Local service-time
deadlines follow the returned error and the documented UTC-day counter; the
guide's available-credit wording does not establish idle-credit accumulation.
Pinned Local 3.3.1 accepted six consecutive table and GSI decreases and omitted
or zeroed their history. It also retained stale GSI units while on-demand, so
reconciliation omits already-applied native index members rather than triggering
an unchanged-capacity backend rejection during provisioned restoration.
`testdata/dynamodb/admission.json` verifies these controls on both stores. The
actual CLI blocked the fifth decrease, retained a provisional timestamp across
SQLite reopen with the real engine paused, then published the actual completion
timestamp after unpausing. Hourly eligibility and next-day visible counts were
also exercised locally; these are not claims of live AWS recovery observation.

Billing-mode admission is captured by
`scripts/aws/dynamodb_billing_mode_probe.py` in
`testdata/aws/dynamodb/billing_mode_limits.json`: 411 native calls and 31 update
attempts on two owned empty tables in the approved account and `us-east-1`.
Both tables were deleted and absence verified. The primary
[switching guide](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-switching-capacity-modes.html)
specifies four provisioned-to-on-demand switches per rolling 24 hours and
unrestricted switches back to provisioned.

- The provisioned-born table accepted four switches; the fifth returned
  `LimitExceededException`/400 without changing the table.
- Creation in on-demand mode consumed one slot: that table accepted only three
  subsequent switches before rejection. Its recovery deadline was creation time
  plus 24 hours. This creation detail is not stated by the guide's switch wording.
- Other recovery deadlines matched the oldest settled on-demand timestamp plus
  24 hours, not request acceptance or the most recent switch.
- Same-mode on-demand requests succeeded without changing history or consuming
  another slot. Explicit `PROVISIONED` requests without throughput returned
  `ValidationException`, even when already provisioned. Ordinary provisioned
  increases remained available after switch-quota exhaustion.
- Immediate descriptions exposed target mode and units while retaining the
  previous settled billing timestamp. Billing transitions exposed provisional
  base-table capacity timestamps, but preserved GSI timestamps until completion,
  also visible in `decrease_limits.json`.

The capture did not wait 24 hours to observe live recovery. The fixture-driven
local checks exercise creation participation, independent table quotas, rolling
expiry rather than midnight reset, no-op history and memory/SQLite reopen.
The actual executable retained a pending switch with its backend paused across
restart; completion after unpausing set the new timestamp at service time.
CLI calls exercised fifth-switch denial, midnight non-recovery, oldest-entry
expiry, the still-blocked next slot, same-name regional isolation and quota
removal on delete/recreate. All owned smoke tables, engines, volumes and
temporary files were removed.

The decrease and billing probes share `scripts/aws/dynamodb_probe.py` for typed
observations, incremental recording, real table/all-GSI readiness and verified
owned-table deletion, using the existing signed transport and CLI helpers.
The billing capture exercised the extracted helper against AWS; the older
338-call decrease capture was not rerun merely for this refactor.

`partiql_capacity.json` and `partiql_key_ordering.json` retain evaluated-byte
charges before projection/filtering, ordered pages, index fetches and accepted
key forms. Companion reads use the pinned engine's traversal under the same
mutation gate, not the filtered response size. Native scan and storage-partition
continuation overhead remain unmodeled; captures must not become hard-coded
partition counts. AWS explicitly permits a
[nonempty LastEvaluatedKey without remaining data](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ExecuteStatement.html).
Replay therefore follows an extra terminal continuation to verify it is empty
and terminates rather than asserting one captured end-page optimization.
Hash-only index page chains are compared as multisets, retaining per-page
charges, counts and continuation/key correspondence rather than pinning an
unspecified storage order. Global-index filters cannot reference unprojected
attributes. Local-index table fetch charges depend on requested projection
attributes, not on an unprojected filter alone.

Local ignores descending PartiQL traversal and fails some valid ordered
projections. Source-owned plans traverse disjoint native Query ranges and
full-primary-key GetItem points, retaining native PartiQL projection/filter
evaluation under the mutation gate. Branch-local filters remain attached to
their ranges. Original expression validation omits the ORDER BY clause owned by
this planner; auxiliary validation, projection and EOF-discovery reads are not
separate customer operations.

`partiql_ordered_partitions.json` and `partiql_ordered_ranges.json` capture typed
partition/sort ordering, IN and OR alternatives, missing-key charges, duplicate
and numerically equivalent range rejection, evaluated-item limits, filters,
projection and independent key/token presence. The same traversal owns
unordered disjoint alternatives. SDK replay covers memory and SQLite reopen.
The actual executable additionally exercised 53-bit-adjacent numeric keys,
negative/zero/exponent ordering, branch filters, disjoint intervals and a
22-item, 2.2 MB traversal: projected pages contained 10/10/2 items; an empty
filter retained all three evaluated pages and their charges.

`partiql_compound_predicates.json` establishes that query eligibility is not
logical key boundedness. Different AND conditions on the same key use a
full-table scan without ORDER BY and fail validation with it; they must not
be intersected into a narrower Query. Repeated equivalent scalar conditions
(including numeric spellings and singleton IN versus equality) remain queries,
but repeated multi-element IN conditions scan. Disjoint OR ranges remain
queries with or without ordering. Overlapping key ranges, including a key
alternative overlapping an unbounded non-key filter, fail validation; a pure
non-key OR remains one residual filter.

`partiql_scan_authorization.json` captures four scoped IAM policies against
those actual access paths. Scans set `dynamodb:FullTableScan=true` and omit
`dynamodb:LeadingKeys`, even when a logical simplification could bound the keys.
ORDER BY over a scan-only predicate omits both keys during authorization, then
fails validation if authorized. ORDER BY without WHERE fails before IAM.
The source computes this plan once for authorization and execution, retaining
the distinction between absent FullTableScan and false. SDK replay covers both
stores; executable CLI smoke also checks touching interval boundaries in both
clause orders, scan denials and missing-context versus validation precedence.
All three owned tables and four IAM users from these captures were deleted,
with absence recorded.

Capacity parity is not complete: numeric-partition capture row 82 reports three
units while logical evaluated-byte/missing-key accounting reports two. That
workflow compares native items and continuations, not capacity, and keeps the
original measurements intact. The compound scan workflow compares unordered
items and errors, not its captured physical scan charges. Storage-partition
continuation overhead and service-time cursor expiry remain open. Large
page/index/concurrent-mutation behavior has not been differentially established
by these captures; the executable's megabyte smoke is a local invariant check,
not a native conformance claim. All owned AWS probe tables were deleted and
their absence observed.

`partiql_duplicate_keys.json` captures whole-batch duplicate-key rejection with
unchanged item state, and omitted capacity for all-failed batches. Local checks
duplicate write keys too late, so the source rejects duplicates before native
execution. The adapter also corrects Local's scalar `DuplicateItem` error name
and transactional `ValidationError` classification to AWS's modeled identifiers.
The mixed-success follow-up observes aggregate capacity ten with accepted-write
Table capacity one for both a nine-unit DuplicateItem and conditional failure.
All owned native probe tables were deleted and their absence observed.

`capacity_metrics.json` records isolated scalar condition failures, canceled
transactions, successful writes/reads and identical-token replays, with actual
CloudWatch publication and explicit absent-versus-zero observations. Table and
GSI consumption have separate dimensions; LSI consumption belongs to the table.
Writes also appear with `Source=Customer`. Exporter sample counts are not request
counts. The source retains minute observations, then commits their removal with
CloudWatch ingestion. Native item effects remain outside that Go transaction;
this is not an exactly-once cross-engine accounting guarantee.

`transaction_failure_metrics.json` adds 23 isolated windows across two owned
tables. Failed and prepared transaction actions charge the old image, doubled
transactionally, not the attempted new image; grow/shrink, Update/Delete and
opposite statement orders are captured. Each failed condition increments the
condition counter once. Every failed window ultimately published a real read
sum of zero; unrelated absent series remain unknown, not zero.

`partiql_failure_metrics.json` retains ten additional isolated minute windows.
Duplicate INSERT and conditional UPDATE charge the existing 512/9216-byte image
(one/nine write units); all-failed batches consume ten units despite omitting
public capacity. Single-duplicate canceled transactions consume two/eighteen
units. Scalar conditional UPDATE publishes one failed-condition count; absent
duplicate/batch counters and the large-duplicate read series do not establish
zero. Captures retain that distinction, and replay skips unknown sums.

`applicationautoscaling/dynamodb_metrics.json` and
`applicationautoscaling/dynamodb_maintenance.json` capture the native alarm
families: consumed-capacity Sum/60-second alarms with two high and fifteen low
evaluations, plus provisioned-capacity Average/300-second maintenance alarms.
At the captured 70% target, the low threshold is 50% of current provisioned
capacity. Disabling scale-in removes that consumed-low alarm, not maintenance.
Observed provisioned-capacity changes replace the family while preserving its
policy action; an unchanged capacity does not churn alarm identities or create
a scaling activity. Actual local CLI requests and retained-store replay exercise
the data → CloudWatch → alarm → service-linked-role → native-capacity path,
including a read-capacity change from two to five. These observations do not
claim AWS publication latency or exhaustive target-value coverage.

The public Streams provider retains native generation/shard/record identity and
images, committing copied records with their ingestion checkpoint in the Go
repository. Actual SDK requests against the executable exercised
INSERT/MODIFY/REMOVE images, unchanged record IDs after SQLite restart, TTL
`Service` identity, disable/reenable generations, reads after table deletion,
15-minute iterator expiry and 24-hour disabled-stream expiry. Native item writes
remain outside Go transactions.

`TestDynamoDBTTLNativeRecovery` reproduces the post-delete source-identity loss
at `80f2b64` and passes after retained TTL ownership is introduced. It runs real
native item/stream effects with an injected unavailable handle, then reopens both
memory and SQLite repositories. It covers failures before deletion, after native
deletion and after a concurrent expiry refresh; unchanged IDs/sequences after a
second reopen; untagged subsequent customer deletes; and stream/table replacement.
Recovery preserves the prepared service-time origin, including a pre-write
attempt retried after reopen; this is a local deterministic recovery contract,
not evidence of AWS deletion latency. Uncaptured records lost beyond native
retention, cross-engine forks and Lambda stream delivery remain outside this proof.

`audit.json` also captures stream ARNs in the initial CREATING response and a
replacement ARN in the re-enable UPDATING response. Public identity is therefore
assigned at Go control admission; native readiness still gates activation.
The backend's `engine.json` proves native records and reopen continuity, not AWS
table response shapes such as TableId or the omitted disabled specification.

The `audit_replay.json` selection passes on both stores through actual configured
CloudTrail-to-S3 and EventBridge-to-SQS delivery, plus CloudTrail Event History.
It checks request-ID correlation, caller/account context, native key-only request
projections, omitted transaction client tokens, selectors and non-key redaction.
It validates every delivered copy and counts distinct selected requests, not
exactly-once delivery: both [CloudTrail log files](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html)
and [EventBridge targets](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-troubleshooting.html#eb-rule-triggered-more-than-once)
can contain duplicates. Reopening after a target commits but before its delivery
acknowledgment must not turn a valid redelivery into a failed conformance check.
Per the [EventBridge CloudTrail delivery contract](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html),
ENABLED rules match selected Data and write management, not read-only management.
Trails cannot use `eventSource Equals` to select management events; the replay
selects management events and compares the DynamoDB outcomes. Data remains absent
from Event History. Secondary-index resources, multi-table resource ordering,
cross-account recipient views and multi-region delivery remain unproven.

### On-demand backups and restores

`scripts/aws/dynamodb_backup_probe.py` reuses the shared probe transport and
ownership helpers. `testdata/aws/dynamodb/backups.json` records the approved
account's native source, duplicate-name snapshots, two restores, negative cases,
post-backup mutations and verified cleanup. Writes were separated from backup
admission by 65-second guards, rather than treating AWS's documented noncausal
backup envelope as an instantaneous cut. The
[backup API](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateBackup.html)
and [restore API](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_RestoreTableFromBackup.html)
own the external contract; DynamoDB Local's five backup operations all returned
`UnknownOperationException`, so forwarding those calls is not an implementation.

The retained AWS captures establish these selected behaviors:

- Backup names are not unique identities. Descriptions retain the source's
  identity, creation time and captured configuration after source deletion.
  Independent item scans and index queries establish the copied data, not lagging
  `ItemCount` or size metadata.
- Default restoration retains base/index schema and applicable capacity settings.
  Explicit empty index overrides exclude indexes and prune unused key attribute
  definitions. Tags, TTL and Streams are not inherited; the
  [restore guide](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Restore.Tutorial.html)
  also requires independent IAM, alarm and scaling configuration.
- A restored table has a new identity and creation time. Initial RestoreSummary
  uses backup creation time, not restore invocation, and disappears at ACTIVE.
  Initial GSI descriptions omit IndexStatus.
- `backup_on_demand_restore.json` retains table maxima 17/23 and GSI maxima 11/13.
  Initial decrease counters are absent; settled on-demand base count is zero
  and GSI count is one. The on-demand billing timestamp is completion time,
  unlike an ordinary on-demand table's creation timestamp.
- Explicit PROVISIONED restoration requires base throughput and inherited GSI
  overrides. A renamed GSI was accepted by AWS. This measured name behavior must
  not be rejected merely because the API prose says overrides should match
  existing indexes.
  `backup_index_overrides.json` rejects changing that existing GSI's key schema or
  projection with ValidationException, without creating either target. The
  restoration boundary compares backed-up keys/projection rather than names.
- `backup_restore_bootstrap.json` brackets initial CREATING and settled ACTIVE
  capacity histories. Provisioned tables and GSIs start with decrease count zero
  and no history timestamps, then settle with count one and a decrease timestamp.
  Base reads 2/3 omit an increase; 4/5/6/20/21 include it, independently of source
  reads 2/20 and the sampled writes 2/20. The index experiment independently
  confirms GSI 3/20 without an increase and 4/2 with one. A present increase equals
  that resource's decrease timestamp; native base/index completion times differ.
  The implementation uses this observed read boundary, not a claim to reproduce
  AWS's private bootstrap algorithm or unmeasured capacities.
- DescribeBackup resolves in the endpoint region while echoing an ARN's supplied
  region. Cross-region restore without an SSE override fails validation before a
  target collision. Foreign-account descriptions/restores were denied.
- `backup_delete_regions.json` confirms regional deletion isolation: the west
  endpoint cannot delete an east-region backup. Conversely, the east endpoint
  accepts an altered west-region ARN for its own backup, echoes that supplied ARN
  in DELETED, and retains the canonical east source ARN. Lookup and authorization
  therefore share endpoint-scoped identity; pending-restore checks use that
  resolved identity, not the untrusted ARN region. The capture also retains an
  initial fresh-ACTIVE-table ContinuousBackupsUnavailableException and the
  verified cleanup before repeating with backup-service readiness.
- `backup_arn_grammar.json` and `backup_arn_case.json` establish the public
  identifier's fourteen decimal digits and eight hexadecimal digits. Wrong
  widths or nonhexadecimal suffixes fail validation; zero and future timestamp
  components remain syntactically valid. Uppercase hexadecimal is valid syntax
  but a distinct identity: the original AVAILABLE backup remained readable
  before and after the uppercase-suffix lookup failed.
- Unknown ARN regions fail validation. Known region names accept different case,
  unlike the partition, service and resource-type keywords. This does not make
  restore's region comparison case-insensitive: an uppercase `US-WEST-2` ARN at
  the `us-west-2` endpoint still requires the cross-region SSE override. AWS
  rejected that request without creating its target. The generated SDK region
  catalog owns known-region validation; the input region remains literal for
  restore admission.
- The ARN's table component uses the normal table-name limits and character
  set. Native foreign-account rejection precedes service, partition, region,
  resource-kind and identifier validation. Short, nonnumeric and empty foreign
  account components remain AccessDeniedException, not a new account-format
  validation rule.
- An AVAILABLE backup remains exclusive to its pending restore. In
  `backup_restore_bootstrap.json`, the same second-target request fails with
  BackupInUseException while the first target is CREATING and succeeds after
  ACTIVE. Reusing the pending target with that source returns TableInUseException.
  Admission uses the retained RestoreSummary source reference; it adds no lock
  ledger and does not mistake backup readiness for restore availability.
- `backup_list_time_precision.json` uses signed raw JSON rather than an SDK's
  millisecond-truncating request serializer. Both bounds include equality.
  Offsets of 0.4 ms round to the backup time; offsets of 0.6 ms cross the boundary.
  Reversed microsecond bounds normalize to equality and succeed, whereas reversed
  millisecond bounds fail validation, even with BackupType SYSTEM. This differs
  from the [ListBackups API's exclusive-upper-bound wording](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_ListBackups.html).
  Backup creation retains millisecond precision; the service normalizes query
  bounds before ordering validation, and both repositories compare inclusively.

`backup_audit.json` retains twenty-one selected complete native CloudTrail documents
with their independently observed LookupEvents resources. All five operations
have null responseElements, including successes. Bound table names can identify
a table for CreateBackup/ListBackups; describe/delete/restore omit document resources.
LookupEvents aliases are absent except for restore's ordered backup ARN and target
table name, both typed `AWS::DynamoDB::Table`. Generated enum/range rejections
retain modeled request fields through service-owned redaction, without dispatching
the rejected command. Unobserved foreign-account denials are not evidence of a
universal CloudTrail omission rule.

The Go owner admits a snapshot marker under the native database mutation gate.
An engine experiment changed items between strongly consistent Scan pages and
observed mixed versions: Scan alone cannot implement an immutable backup. Pending
snapshots therefore finish real, bounded Scan/BatchWrite copies before subsequent
native mutations, including TTL and table deletion. Typed metadata retains the
private native table after the source and its public stream retention expire.
Restore copies native rows and builds indexes before exposing ACTIVE. Its
existing RestoreSummary is the pending source reference, not a second execution
ledger; backup deletion cannot pass an admitted pending restore.

`testdata/dynamodb/backups.json` replays 130 steps on memory and SQLite,
including sixteen native audit outcomes through public CloudTrail Event History.
The actual executable additionally preserved 100 original items exceeding 1.6 MB
through paused-engine capture admission, blocked/rejected subsequent writes,
process restart, source deletion and 25 hours of service time. A restore-only
principal was denied CreateTable but admitted restoration.
Real table scans and GSI queries recovered
the original data, and the first restore's billing timestamp reflected completion
430 service-time seconds after creation. All owned local tables, backup, IAM
principal, engine, volume and temporary state were removed. These are local
recovery invariants, not measurements of AWS restoration latency.
The follow-up executable check rejected changed index keys/projections without
creating targets and recovered the original item through a renamed index.
An altered-region ARN could not bypass a paused pending restore's source
reference; after completion, deletion returned the native ARN echo and removed
the endpoint's backup. The west endpoint never mutated the east backup.
Both smoke tables, snapshot, engine and volume were removed.
The identity follow-up used the actual executable and native engine to create an
AVAILABLE fourteen-digit/eight-hex snapshot, resolve and echo an uppercase region,
reject a changed-case suffix, malformed widths and an unknown region, and reject
the uppercase-region restore without creating a target. The original ARN restored
the captured item. Uppercase-region deletion echoed the request ARN and removed
the canonical snapshot; both tables were removed and the ephemeral CLI runtime
exited cleanly, disposing its native database.
A second executable run replayed fourteen native malformed-table and foreign-
account cases directly from the capture and matched their error codes, including
account rejection precedence. It created no resources.
The transition follow-up exercised raw signed submillisecond list bounds through
the executable, including reversed-range validation before an empty SYSTEM result.
Real restores independently reproduced base 2/20 with GSI 4/2 and base 4/2 with
GSI 3/20 histories, and both recovered the backed-up item.
The quota follow-up used 51 distinct AVAILABLE snapshots, rather than reusing a
busy source: fifty paused pending restores survived a SQLite process restart,
the next distinct source remained LimitExceededException, and reusing a pending
source or target returned BackupInUseException or TableInUseException respectively.
Pending-source deletion remained blocked; no rejected target was created. After
native completion released admission, the next restore succeeded and recovered
the original item. The fixture independently retains source exclusion across
memory and SQLite reopen, then verifies release after ACTIVE.
All 54 smoke tables and 51 snapshots were removed. Their native engine and volume
were disposed automatically; the CLI exited cleanly and temporary SQLite state
and executable were removed.

#### Backup request admission

The API references publish 50 CreateBackup calls/second, five ListBackups calls,
and ten calls each for DescribeBackup, DeleteBackup and RestoreTableFromBackup.
The [describe](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DescribeBackup.html)
and [delete](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_DeleteBackup.html)
references, alongside the create/list/restore references above, own those nominal
rates. The native captures distinguish those published limits from observed
transport-dependent admission:

- `backup_request_admission.json` retains the initial native probes and cleanup.
  Its invalid-width ARN cases are validation evidence, not missing-backup evidence;
  its transport failures are not AWS throttles.
- `backup_request_admission_sdk.json` records 4,064 burst requests over 64
  connections: 3,674 successes and 390 HTTP 400 ThrottlingException responses.
  Accepted throughput was about 164 requests/second, well above five in aggregate;
  all 32 paced recovery requests succeeded. Compact rows preserve every original
  timestamp, duration, connection trace, response header, body and modeled error.
- `backup_request_admission_single.json` records 604 successes and 496 throttles
  during 120 seconds on one reused HTTP/1.1 connection. Alternating table filters
  still shared throttling. Limit=0 reached native HTTP and alternated validation
  errors with throttles under load, so generated constraint validation cannot
  precede all admission. The mixed-operation phase stayed below each operation's
  nominal rate and does not prove successful DescribeBackup budget consumption.
- `backup_request_admission_pipeline.json` wrote each twenty-request batch before
  reading its responses. ListBackups repeatedly admitted five after idle.
  DescribeBackup returned twelve BackupNotFoundException outcomes in recovered
  batches, but response processing allowed refill; twelve is not an established
  instantaneous allowance. All 160 requests produced complete HTTP responses
  without retries, transport errors or resource mutations.
- `backup_request_admission_audit.json` exhausts 23 historical LookupEvents pages
  and joins every source request by its exact native request ID: 628 successes
  and 496 throttles, with no unmatched source request. Throttles have null request
  parameters and response elements and no document resources. The selected
  complete throttled documents also omit apiVersion. The fixture reuses one of
  those documents, not a locally invented expected audit event.

The provider enforces the documented nominal rates with one second of allowance,
separately by partition/account/region and operation. The authenticated gateway
invokes that service-owned boundary before generated decoding. Rejected commands
are not dispatched or rebound for audit; their native null-input projection is
retained. An admitted invalid request consumes its slot. Credits use service time,
not sleeps, and are ephemeral admission state rather than a durable resource
ledger. This deterministic nominal allowance does not reproduce AWS's unmeasured
multi-connection fleet allocation.

The race-instrumented executable admitted exactly five of 100 concurrent signed
ListBackups requests and returned modeled HTTP 400 ThrottlingException for 95.
It separately exercised all five operation rates, account/region isolation,
shared allowance across credentials in one account, and no refill from wall time.
Signed raw requests established the 199/200 ms boundary and invalid-input charging;
an invalid signature left a fresh account's full allowance untouched.
That smoke created no resources. The race-instrumented server exited cleanly;
its temporary executable, SDK probe and CLI inputs were removed.

Remaining boundaries: native cross-connection request admission, cross-region/KMS
restore and AWS Backup integration. The captures do not establish complete
backup/restore parity or a general cross-service MVCC snapshot.

### Continuous recovery and deleted-table backups

The approved account `000000000000`, `us-east-1`, was exercised through real
signed AWS requests. Primary contracts:
[continuous backup behavior](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html)
and [RestoreTableToPointInTime](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_RestoreTableToPointInTime.html).
The retained evidence distinguishes observed data from API admission:

- `testdata/aws/dynamodb/continuous_backup_controls.json`: ready tables report
  continuous backups ENABLED and PITR initially DISABLED. First
  enable defaults to 35 days; omitted retention on an enabled interval preserves
  its current value. Shrink/increase and disable/re-enable are distinct
  transitions. Missing/CREATING tables returned TableNotFoundException.
  Bounds disappeared when disabled. The extra unmodeled native
  PointInTimeRecoveryWindowDays field is not hand-added to generated responses.
- `point_in_time_recovery.json`: a historical restore returned
  old alpha, deleted beta and stable; latest returned updated alpha, new gamma
  and stable, including actual GSI reads. Both inherited capacity changed
  **after** the historical point. Concurrent same-source restores were accepted.
  Restored PITR was disabled; source tags and Streams were not inherited.
  RestoreSummary appeared while CREATING and disappeared at actual ACTIVE.
- Raw timestamp follow-ups normalized non-tie inputs to nearest milliseconds.
  A value 0.4 ms before the earliest bound rounded into the interval; 0.6 ms
  before it was rejected. Explicit points newer than advertised LatestRestorableDateTime
  were accepted: one was 216.993 seconds newer, but 30 seconds before the
  contemporaneous clock. A point 60 seconds into the future was rejected.
  This does not establish the precise native upper boundary, tie-breaking or
  recovered nonempty contents beyond the advertised latest point.
- The SYSTEM deletion experiment retained actual updated/inserted items and
  omitted a deleted item after restoring a deleted source. SYSTEM/ALL list filters
  returned it; USER did not. Its name was `source$DeletedTableBackup`.
  With retention **one day**, expiry was creation plus exactly 86,400 seconds,
  despite the guide's generic 35-day statement. DeleteBackup returned
  ValidationException and the automatic expiry. Other retention values and
  actual native expiration were not sampled. All owned tables were removed.
  Two AWS-managed SYSTEM backups remain, with recorded expiries
  `2026-09-19T15:13:54.369Z` and `2026-09-19T16:30:50.352Z`. AWS refused manual
  removal of the first; the same forbidden operation was not repeated for the
  second. The guide describes free SYSTEM retention; billing was not measured.
- Enabling PITR while the source remained DELETING succeeded and produced a
  SYSTEM backup. Disabling an already-enabled source during DELETING succeeded
  and left no SYSTEM backup. Snapshot ownership therefore follows the final
  configuration at physical deletion, not merely DeleteTable admission.
  A separate fresh-table attempt returned ContinuousBackupsUnavailableException
  after ACTIVE; continuous-backup readiness is independent of table readiness.
- `recovery_audit.json` retains eight selected native documents from 134 matched
  LookupEvents. DescribeContinuousBackups has a table document resource but no
  lookup alias. UpdateContinuousBackups uses the table name as its alias;
  modeled validation rejects omit document resources. Point-in-time restores
  list target then source document resources and no lookup aliases. Their
  responseElements are null and restore request timestamps use whole-second ISO.
- `continuous_backup_readiness.json` records 194 calls against three fresh tables.
  ACTIVE did not imply continuous backups ENABLED. Valid enable and no-op disable
  both returned ContinuousBackupsUnavailableException before readiness; invalid
  retention still failed generated validation. A passive table became ready
  without a successful update. Mature UPDATING tables accepted PITR changes, and
  mature DELETING tables sometimes accepted no-op disable. All owned tables and
  backups were verified absent.
- `continuous_backup_restore_readiness.json` records 335 calls covering actual
  on-demand and PITR restores. Initial CREATING targets returned TableNotFound
  for backup controls, then reported DISABLED and rejected valid changes while
  still CREATING. Source readiness did not initialize the target's readiness.
  The first ACTIVE samples were ready; this capture did not observe an
  ACTIVE-bracketed unavailable restore. RestoreSummary disappeared at completion.
  All three tables and the owned user backup were removed, with no retained
  SYSTEM backups or IAM changes.

Local registration uses five service seconds from the existing creation
timestamp, not a measured AWS deadline. A physical creation or restore that is
still pending remains unavailable after registration. No successful PITR update
is needed to become ready, and mature UPDATING is not an unavailability rule.
The 21-step readiness fixture checks fresh ACTIVE and held-CREATING restore
states, validation precedence, passive readiness, PITR enablement and retained
reopens on both stores. Actual CLI requests also verified initial rejection,
restart preservation, clock-driven readiness and successful enable/disable.

Go owns interval transitions and 1–35 day service-time retention. A native
baseline precedes later writes; scalar/batch/transaction/PartiQL plans feed
retained postimages without enabling or altering public Streams. Pending key
intents settle from actual native reads after interruption. TTL uses its
original owned timestamp, including a failed conditional candidate. Retention
cannot resurrect an earlier discarded window. Compaction folds images through
native Put/Delete, then trims history transactionally; it is suspended while
restores pin that baseline. Each target pins both time and sequence, so two
admissions at frozen time can legitimately recover different cuts.

The local latest bound uses a deterministic five-minute service-time lag,
bounded by the interval start. Explicit times normalize to milliseconds and
admit through current service time, reflecting the sampled acceptance envelope
rather than treating the advertised latest as a hard upper boundary. Cross-region
KMS recovery remains explicitly unsupported, not an unencrypted fallback.

`testdata/integration/dynamodb_recovery*.json` exercises public SDK behavior
against real DynamoDB Local on memory and SQLite. The fixtures cover frozen-time
cuts, all write APIs, typed nested/binary values, retention shrink/increase,
reopen, TTL without public Streams, independent USER/SYSTEM snapshots, expiry
while a restore is pending, and native audit projection. Additional cases cover
DELETING configuration changes, lost native delete responses, and native token
replays after a committed transaction's response is lost. A planning barrier
also exercises queued multi-item, multi-table transactions and PartiQL across
PITR enable/disable/re-enable. The existing native TTL failure test restores
before/after original TTL time across failed-handle reopen, including a
condition-invalidating native refresh. An actual CLI/SQLite
restart recovered a historical row at version 1 while the source held version 2
and a new item, then restored those latest contents from its deletion backup.
These are bounded recovery observations, not complete DynamoDB parity.

### Global table replica observations

`testdata/aws/dynamodb/global_tables_lifecycle.json` records 261 native calls
against an owned PAY_PER_REQUEST table in `000000000000`, `us-east-1` and
`us-east-2`. The primary contracts are
[global table behavior](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html)
and [global table security](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables-security.html).
These native observations bound the implementation described below; they are not
a complete global-table parity claim:

- Adding a replica exposed version `2019.11.21` and automatically enabled
  NEW_AND_OLD_IMAGES Streams on the previously disabled source. Descriptions listed only the other Region.
  MultiRegionConsistency was absent in the sampled responses.
  Ordinary same-account descriptions included settings mode
  `ENABLED_WITH_OVERRIDES`; that output is not evidence of multi-account support.
- Two identical Create entries in one UpdateTable succeeded with one replica.
  Creating in the source Region or creating an existing replica was rejected.
  Distinct multiple remote creates were not sampled.
- Initial contents copied, and subsequent Put, Update and Delete changes were
  read in both directions. This does not establish conflict resolution or a
  replication-latency guarantee.
- Global Streams could not be disabled. Tags and post-creation PITR were
  independent; TTL configuration synchronized. Source PITR initialization failed
  before replica creation, so initial PITR inheritance remains unsampled.
- PAY_PER_REQUEST rejected provisioned read overrides. On-demand maxima
  synchronized; a replica-only read override worked, and a later source update
  reset it. That capture did not sample provisioned capacity or GSI overrides;
  the later scaling capture below supplies those contrasts.
- Deleting the source while its new peer existed was refused by the 24-hour
  source restriction. Removing the peer demoted the source, retaining its items
  and Streams. Streams could then be disabled and the source deleted immediately.
  Both regional absences and empty SYSTEM-backup lists were verified.

The existing replication service-linked role retained the same RoleId and was
not modified. The separately owned temporary IAM role and policy were removed.
Its restricted-session follow-up ran against an absent table without proving
policy propagation; those failures do not establish dependent-action or ARN
requirements. No owned resources from this capture remain. Legacy global tables,
MRSC, witnesses, concurrent-write conflicts and cross-account replication are
outside this capture.

`global_tables_authorization.json` adds 311 calls with a stabilized owned role
and explicit AWS CLI session credentials. With the other documented prerequisites
granted, missing or source-only `CreateTableReplica`/`DeleteTableReplica` grants
were denied against the target Region's table ARN; target grants succeeded.
An independent identity-policy contrast denied target `Scan` after a GetItem
allow-to-deny propagation check. The remaining create prerequisites, and the
independent necessity of target `DeleteTable`, were not isolated. Existing-SLR
creation needed no IAM permission; the preexisting role remained unchanged.
Earlier raw calls used a stale pre-fix probe import that omitted the supplied
credential environment. Their native effects are real, but their role/session
attribution is explicitly invalidated; the later CLI contrasts are the permission
evidence. Both tables, the owned role and its policy were verified absent.

`global_tables_conflicts.json` retains 415 calls and eight competing-write trials.
Known successful same-value Put/Update and missing-key Delete produced no further
public stream records within the retained observation window. Three real local
same-value Puts and three missing-key Deletes did not defeat promptly preceding
remote changes; two actual-delete controls converged to absence. ALL_OLD responses
establish the local preimages, and four regional observation rounds retain the
outcomes. These samples support semantic no-op suppression, not an assertion
about AWS's internal replication representation, timestamp assignment or all
possible timing. Both owned tables were removed. Enabled-stream view changes
were rejected, including requesting the existing view; the later stream-view
capture below establishes creation from already-enabled sources.

`global_tables_stream_views.json` adds 638 native calls covering all four enabled
StreamViewTypes. Replica creation preserved each source's exact ARN and view;
the new peer inherited that view, including KEYS_ONLY. Actual INSERT/MODIFY records
in both Regions contained precisely the selected images, consistent with the
[public StreamRecord contract](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_StreamRecord.html).
An ordinary enabled-stream view change was still rejected. All eight owned
regional tables were verified absent. The representative NEW_IMAGE replay checks
the pre-creation source iterator, both regions' images, rejection and reopen;
the existing default-view fixtures are retained rather than copying four replays.

`global_tables_scaling.json` adds 718 calls with an owned provisioned table and
GSI, plus related CloudTrail records:

- Replica creation required a write scalable target and target-tracking policy
  for the table and each GSI. A target without its policy was insufficient; read
  scaling was optional.
- Creation copied registered read/write targets and policies into the peer:
  policy names, bounds, utilization targets, DisableScaleIn and RoleARN were
  retained, with new regional target/policy identities. Sampled suspended flags
  were false; omitted cooldowns stayed omitted.
- An ordinary accepted UpdateTable with an effective write change propagated
  both required capacity dimensions, replacing peer read overrides even when
  the source read fields were unchanged. An all-same request was rejected.
- Direct Application Auto Scaling changes did not propagate target/policy
  configuration. Its source write adjustment remained regional for 603.947
  seconds of observation; source read adjustments also preserved peer capacity.
  CloudTrail showed ordinary-shaped UpdateTable payloads under
  `dynamodb.application-autoscaling.amazonaws.com`, not ReplicaUpdates. This
  bounds regional service execution; it is not a universal latency claim.
- The sampled replica-autoscaling API coordinated shared write settings and
  peer-specific reads, unlike direct regional AAS calls. Its complete API
  behavior is not implemented.
- A provisioned/on-demand/provisioned round trip recreated scaling configuration
  after the probe explicitly deleted policies and deregistered targets. Those
  empty lists were not evidence of automatic on-demand invisibility. That table
  had provisioned history; the fresh-path capture below resolves the remaining
  admission and policy-replacement questions.

Both owned tables, all owned targets/policies and all 89 known managed alarms
were verified absent. Both preexisting service-linked roles retained their
RoleIds. Primary contracts include
[RegisterScalableTarget](https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html)
and [UpdateTableReplicaAutoScaling](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateTableReplicaAutoScaling.html);
the recorded regional contrasts qualify broad claims about synchronized scaling.

`global_tables_billing.json` adds 501 calls on a fresh originally on-demand
global table with one GSI:

- A first switch to provisioned R2/W2 succeeded without previous scaling
  registrations. Both Regions acquired read/write targets for the table and GSI,
  with minimum equal to requested capacity, maximum 40,000 and generated-name
  target-tracking policies at 70 percent.
- Entering on-demand retained visible targets, policies, suspension flags and
  accessible target tags. Policy deletion and target deregistration still worked;
  sampled target/policy configuration changes failed because on-demand is not
  scalable. This agrees with the CLI/SDK preservation distinction in the
  [capacity-mode guide](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-switching-capacity-modes.html).
- Returning to provisioned reset distinct regional bounds and policy settings
  to the generated defaults. Seven undeleted targets kept their ARNs, tags and
  suspension flags; a deleted peer-index target was recreated with a new identity
  and default flags. A custom-named policy was replaced, not preserved alongside
  the default policy.
- CloudTrail showed explicit policy deletion even where the eventual policy ARN
  was unchanged: the ARN includes the retained target identity. DeleteScalingPolicy
  used the customer IAM identity with `invokedBy: dynamodb.amazonaws.com`;
  RegisterScalableTarget and PutScalingPolicy used the DynamoDB replication SLR.
  Existing cooldowns and DisableScaleIn did not survive policy replacement.

The replay uses the existing scaling command owner and table quota, not a second
configuration store. Thirty-five fixture steps exercise fresh admission,
on-demand visibility, native rejection, deleted-target recovery and policy
replacement across memory/SQLite reopen with real engines. The executable also
verified retained target tags/flags and customer-forwarded CloudTrail deletion.
These observations cover one empty MREC table, one GSI and two Regions, not
metric-triggered scaling or the separate replica-autoscaling API. Actual native
capacity never exceeded six. Both regional tables, all known targets and policies,
and all 123 known managed alarms were removed; preexisting SLR identities were
preserved.

`global_tables_combined_controls.json` records 897 calls: the original 31
request-admission cases and a settled-state followup.

- Replica Create combined with table/index throughput, table class, deletion
  protection, stream enabling or structural GSI changes failed with
  ValidationException before either mutation. Even an invalid capacity value did
  not displace the combined-operation rejection.
- Combined Replica Update/Delete controls rejected while the owned native
  tables were UPDATING; standalone Replica Delete returned ResourceInUseException.
  Followup sequences 834–839 observed both tables ACTIVE and repeated the combined
  rejections without mutation. Standalone replica deletion then succeeded.
- On a missing table, ordinary settings plus Replica Create returned
  ValidationException; Replica Create alone returned ResourceNotFoundException.
  Adding nonempty AttributeDefinitions still reached ResourceNotFoundException:
  attributes are not an additional operation.
- An empty GSI update list with a replica action failed list validation. An empty
  GSI list alone, or attributes alone, failed because no operation was supplied.
  All these semantic checks preceded source lookup.
- Empty AttributeDefinitions with a peer read override was accepted and the
  requested table/GSI capacities became visible. Both regional TableStatus values
  remained UPDATING through the initial 5,021-second observation bound despite
  ACTIVE replica and GSI statuses. The later followup observed both tables and
  indexes ACTIVE; it does not establish their exact transition time.

The nineteen-step fixture replays supported admission contrasts and verifies
unchanged source/peer controls after rejected Create, Update and Delete requests.
It uses both repository implementations and a retained reopen. Actual executable
CLI requests verify the missing-source and field-presence distinctions separately.
Local engine readiness is not a native AWS transition-duration guarantee.

Native cleanup completed at `2026-09-18T23:13:59.779300Z`. After the accepted
transition settled, the `us-east-2` peer was removed and verified absent before
deleting the `us-east-1` source; sequences 891 and 897 establish both absences.
Owned scaling targets, policies and managed alarms were also verified absent;
existing SLRs were preserved. The initially rejected cleanup attempts remain
historical observations, not outstanding resources.

`replica_autoscaling_api.json` records 573 calls, including missing-table shape
followups; `replica_autoscaling_edges.json` records 421 focused controls. Both
use the approved account and the same two Regions. Primary contracts include
[AutoScalingSettingsUpdate](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_AutoScalingSettingsUpdate.html),
[RegisterScalableTarget](https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html)
and the
[replication-role managed policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/DynamoDBReplicationServiceRolePolicy.html).

- Describe requires a global-table member. Update validates supplied settings
  before lookup; enabled settings require bounds and a tracking policy. Disabled
  settings forbid those fields but ignore RoleARN. Missing index selectors
  produced InternalServerError rather than a fabricated successful no-op.
- Fresh on-demand settings contain Disabled=true and an empty policy list.
  Provisioned configured settings omit Disabled; a registered target without a
  policy again projects disabled and hides bounds/role. Suspension flags are
  independent of that projection. Returning to on-demand retains configured
  bounds, role and policies together with Disabled=true.
- Updates return the pre-update description. Table/GSI writes synchronize across
  members; read changes are regional. Custom names are honored, old policies are
  removed, and omitted cooldown/scale-in settings do not survive replacement.
  Target identity, creation time and suspension flags survive registration.
- Invalid member/index references reject before mutation. Dependent failures
  instead retain successful siblings. An invalid read tracking target removed
  its old policy but retained target registration and successful write changes.
  One initial mixed-error capture differed in its surviving read policy;
  repeated controls do not justify a general rollback or exact ordering claim.
- DynamoDB-authorized callers explicitly denied all public autoscaling actions
  can still describe, update and disable through DynamoDB. Configuration uses
  the replication SLR; deletion/deregistration retain the customer identity
  invoked by DynamoDB. Explicit default SLR use succeeds even with caller
  PassRole denied; a custom missing role fails the replication role's PassRole
  check. The
  [DynamoDB managed policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonDynamoDBFullAccess.html)
  supplies `application-autoscaling.amazonaws.com` as the pass-role service.
- CloudTrail retains successful update responseElements as the pre-update
  description; describe responseElements are null. Native child events use
  `autoscaling.amazonaws.com`, with replication-service or customer-forwarded
  actors according to the operation.

The 41-step replica-autoscaling fixture replays these observable distinctions
through real engines on memory and SQLite. The same steps passed through the
actual CLI with two executable restarts; CloudTrail reads separately verified
pre-update response contents and dependent actors. Both native captures removed
all owned tables, scaling targets/policies and managed alarms without changing
the shared SLR identities. These observations do not establish legacy/MRSC,
cross-account or noncommercial-Region parity.

The implemented same-account commercial-Region path uses native regional tables,
immutable bootstrap copies and a retained typed mutation log. Current SLR
permissions gate delivery and settings propagation. Source UpdateTable authority
does not require the caller to own peer UpdateTable authority; TTL changes require
caller permission in every member Region. Read overrides and ordinary synchronized
settings share the regional validator; tags, resource policies, protection and
PITR stay regional. Ordinary final-member removal preserves the survivor's
unacknowledged writes. Settled replicas denied replication for twenty service
hours detach with their current regional data, rather than deleting either table.

`testdata/integration/dynamodb_replication*.json` replays these selected contracts
on memory and SQLite using real DynamoDB Local: scalar, batch, transaction and
PartiQL writes; no-op conflicts; role-policy repair; TTL; regional controls;
independent membership transitions; and lost native responses followed by reopen.
The actual AWS CLI also exercised copied and reverse-written items, deletion
delivery, and new delivery after restarting the SQLite-backed executable at a
frozen service instant. This is not native replication latency or general
conflict-ordering evidence.
The scaling executable smoke also rejected missing write autoscaling, copied
regional policy/alarm configuration, recovered a pending minimum-capacity
adjustment after restart, preserved peer capacity during that adjustment, and
then propagated an ordinary customer update. Event History retained the actual
regional UpdateTable with the native service identity. This exposed and corrected
an engine-gate/shared-transaction inversion: regional capacity only commits
control metadata, leaving native effects to reconciliation.

An executable upgrade smoke reconstructed schema 93 with two retained capture
keys, then applied a real native Put and Delete while the service was stopped.
After the production upgrade, a restore inside the five-minute lag returned the
earlier baseline; advancing service time placed both effects in the restorable
window and recovered the inserted item and deletion. The owned source, restored
tables and engine storage were removed after verification.

Global TTL uses one deterministic eligible regional scanner; replication carries
its deletion to peers through the normal capacity and Streams path. Only the
origin has the [TTL service identity](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/time-to-live-ttl-streams.html);
the Streams API's nested identity uses
[`PrincipalId` and `Type`](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_streams_Identity.html).
Region selection and scan cadence are emulator scheduling, not AWS timing claims.
MRSC, witnesses, multi-account and noncommercial replication, encryption depth,
and denial expiry during creation or partially applied settings remain incomplete.

### Retired legacy global-table APIs

On 2026-09-19, two independent native experiments in account `000000000000`
confirmed that new version-2017.11.29 groups are no longer admitted.
`legacy_global_controls.json` retains 180 calls; `legacy_global_data.json`
retains 120 calls and scoped STS-session permission contrasts. Both used empty,
ACTIVE same-name tables with matching keys and `NEW_AND_OLD_IMAGES`; the second
also supplied matching GSIs. `CreateGlobalTable` still returned
`ValidationException` explaining that version 2017.11.29 is unsupported.
This differs from the still-published
[legacy creation procedure](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/globaltables_HowItWorks.html)
and [API description](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateGlobalTable.html).
Historical legacy item metadata, TTL behavior and membership transitions were
therefore not measurable through a new native group and are not fabricated.

- Create requires the global ARN and each supplied regional table ARN. Update
  requires the global ARN and each mentioned Create/Delete table ARN, not an
  unmentioned source ARN. Describe uses the named global ARN; List uses
  `arn:aws:dynamodb::ACCOUNT:global-table/*`. Authorization precedes retirement.
- Empty/malformed updates are validation errors. Create actions encounter the
  retirement guard; valid Delete-only actions reach `GlobalTableNotFoundException`.
  Legacy creation and Delete-only admission still distinguish the old eleven
  supported Regions from newer Regions such as `eu-north-1`.
- A real ACTIVE version-2019.11.21 group is absent from legacy Describe/List at
  member and nonmember endpoints. Rejected legacy removals do not delete or
  detach its regional tables. Current replication remains owned by UpdateTable.
- List has a minimum limit of one, not a maximum of 100. New commercial and known
  noncommercial Region filters are accepted; unknown or empty filters returned
  `InternalServerError`. The generated endpoint catalogue supplies recognized
  Region names. Empty results here are actual native results, not omitted rows.
- CloudTrail classifies all four APIs as management events; Describe/List are
  read-only. Response elements are null. Table-specific detail resources use
  the endpoint's regional table ARN, while Event History lookup aliases are
  empty. Authorization failures use `AccessDenied` with null request parameters
  and no detail resources. `legacy_global_audit.json` selects four unmodified
  envelopes from the controls capture for fixture replay.

The 30-step `dynamodb_replication_legacy.json` fixture passes with actual native
engines on memory and SQLite, including continued item replication and retained
current membership. All 30 steps also passed through AWS CLI with two executable
restarts; 21 CLI-generated management events verified the audit distinctions,
including five denied calls. All six native regional tables were verified absent;
neither experiment changed existing shared service-linked roles or policies.

## Kinesis streaming dependency evidence

The 2026-09-19 captures in account `000000000000` informed the Kafka-backed
Kinesis implementation and DynamoDB destination commands. They do not establish
complete service parity.
`testdata/aws/kinesis/controls.json` records 228 calls, `records.json` records
201 calls, and `testdata/aws/dynamodb/kinesis_destination.json` records 436
calls with 19 exact delivered records. Source revisions, actors, primary AWS
links, permissions and verified resource cleanup are retained in those files.

Kinesis rechecks current identity, resource policy/tags and exact stream/consumer
authority after acquiring the native engine gate, before a new append or read.
Replacement and cancellation fences remain in force; engine I/O holds no storage
transaction. Initial enhanced-fan-out admission follows the same rule, without
inventing per-frame authorization for established subscriptions.

Selected control and data contracts:

- Stream name and ARN selectors must agree. Old/new tag APIs share state but
  authorize distinct actions; create-time tags specifically require
  AddTagsToStream. Retention, monitoring, encryption and maximum-record-size
  changes have separately observed asynchronous and no-op behavior.
- ListStreams returns a continuation for a full page even if the following page
  is empty. On-demand summaries include `RecordDistributionStrategy` set to
  `USER_PARTITION_KEY`; provisioned summaries omit it. The pinned Smithy model
  lacks that response member, so the existing native-backed model-correction
  manifest supplies it to generation. No hand-written serializer or second
  stored copy of the mode-derived value is needed.
- Resource-policy storage visibility is not authorization visibility. An
  immediately readable Deny took several seconds to become effective; deleting
  it returned Policy `"{}"` before its denial stopped applying.
- Stream-mode switch admission survived deletion/recreation of the same
  name/ARN. Account commitments and paid warm-capacity changes were not enabled.
- SequenceNumberForOrdering is not an idempotency key or same-shard condition.
  Reuse, zero, and a sequence from another shard all admitted new records.
- ACTIVE topology can expose a closed parent before writes stop routing to it.
  Settled split, merge and shard-count changes were captured independently.
  Terminal GetRecords omits NextShardIterator and supplies ChildShards.
- Real SubscribeToShard worked over HTTP/1.1. Its wire starts with an
  `initial-response` event, then ordinary data/heartbeat events. Terminal frames
  omit ContinuationSequenceNumber despite modeled requiredness. Raw native
  frames and protocol CRCs are retained; no event-stream fixture was synthesized.
- Continuation sequence numbers checkpoint progress between records, rather than
  naming the last delivered record. The
  [subscription event contract](https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShardEvent.html)
  accepts both AT_SEQUENCE_NUMBER and AFTER_SEQUENCE_NUMBER on reconnect.
  Reusing a record's inclusive position would replay it; treating a checkpoint
  as the next record's position would skip that record in AFTER mode.

The [DynamoDB integration contract](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/kds.html)
has its own delivery and admission semantics, not a copy of public Streams:

- Missing, wrong-account, wrong-region, wrong-service and wrong-resource-type
  destinations were accepted as ENABLING before asynchronous failure. Failed
  destination entries remained listed alongside the active destination.
- Caller PutRecords denial caused asynchronous ENABLE_FAILED. After privileged
  activation, writes by that denied caller still delivered through
  AWSServiceRoleForDynamoDBKinesisDataStreamsReplication. A policy denying only
  that role stopped observed delivery; removing it recovered an older record
  after a newer record. Describe did not require the caller's Kinesis describe
  permissions despite the broader [IAM guide](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/kds_iam.html).
  The [managed replication-role policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/DynamoDBKinesisReplicationServiceRolePolicy.html)
  grants DescribeStream, not DescribeStreamSummary. Destination readiness uses
  the permitted command rather than widening the protected policy to fit code.
- Ordinary unchanged writes were suppressed in the measured windows. Identical
  transactional Put/Update and transactional PartiQL Update emitted equal-image
  MODIFY records. A universal unchanged-image suppression rule would lose them.
- Public DynamoDB Streams stayed unconfigured. Delivered envelopes include table
  name, record format, null user identity and both images; nested binary values
  are base64-encoded twice. Millisecond timestamps are integers without a precision
  field; microseconds include MICROSECOND. SizeBytes includes keys and all images.
- DISABLED was not an immediate delivery cutoff in the observed window. Reenable
  produced duplicate INSERT notifications with different event IDs and timestamp
  precision. These are bounded asynchronous observations, not exact delay claims.
- Repeating Disable while DISABLING succeeded without restarting the transition
  (calls 299–300); repeating it after DISABLED failed (322). Update while UPDATING
  remained invalid. Those states must not share a generic ACTIVE-only admission.

The native probes removed their tables, streams, consumers, owned IAM resources
and scoped policy changes. DynamoDB automatically created its previously absent
shared Kinesis-replication SLR; that role was deliberately preserved. No account
commitment or warm-capacity purchase was enabled. The original three captures did
not create a data-event trail; the later owned audit probe below did. TTL, KMS
failures, prolonged delivery exhaustion and actual cross-account resource access
remain outside the original captures.

### Follow-up native observations

- `dry_run.json` retains 96 calls. PutRecord, PutRecords, GetRecords,
  GetShardIterator and SubscribeToShard return DryRunOperationException after the
  measured authorization/lookup checks, without writing data or allocating a
  subscription. Iterator/subscription dry runs skip deep position validation.
  A valid iterator's GetRecords dry run still succeeds after stream deletion;
  shape validation precedes IAM and supplied-ARN authorization precedes iterator
  agreement. AccessDenied uses native uppercase `Message`, unlike ordinary
  lowercase `message`.
- `throughput.json` retains 21 data calls, 49 exact records and 62 MiB sent over
  105.90 seconds. Configured large and mixed batches were accepted. No throttling
  was observed: this capture does not validate an exact token-bucket allocator.
  Local admission models documented shared-read/control limits and provisioned
  write credit; it is not measured physical-shard or adaptive on-demand capacity.
- `topology.json` contains 50 CLI-decoded calls; `topology_raw.json` contains 38
  signed raw calls. A no-op UpdateShardCount succeeds without entering UPDATING.
  Uniform 2→3 scaling retains the binary split/merge ancestry; 3→1 succeeds,
  whereas a settled 1→3 exceeds the doubling limit. Missing and closed split
  shards have distinct errors. Matching NextToken+StreamName is accepted;
  conflicting names, token+creation-time and token+ShardFilter are rejected.
  AT_LATEST ignores an unrelated timestamp and applies an extra ShardId as an
  exclusive start. Timestamp filters reject future/pre-trim positions.
- The raw topology capture distinguishes ACTIVE metadata from routing/filter
  cutover: old parents remained visible in AT_LATEST five seconds after ACTIVE,
  while AT_TIMESTAMP selected the old topology; another 30 seconds produced the
  settled leaves. Local topology publishes one native-ready cutover, not that
  measured dual-phase interval. DescribeLimits counts provisioned open shards,
  not on-demand physical shards. Published regional defaults are not guarantees
  about a real account's applied/increased shard quota.
- `audit_data.json` preserves the owned S3 audit probe's 18-minute delivery bound.
  DescribeStreamConsumer arrived as read-only Management with its exact consumer
  resource and null response. The bounded trail did not deliver the selected
  data calls or ListShards. A later Event History query recovered ListShards by
  exact request ID: read-only Management, stream detail resource, null response,
  but an empty LookupEvents Resources list. Absence within the S3 window is not
  evidence that AWS never logs those operations. The owned trail, bucket,
  consumer and stream were deleted.
- `testdata/aws/eventbridge/kinesis_targets.json` retains sixteen records from
  eight original-event projection cases. Strings retain JSON quotes, empty
  strings become `\"\"`, absent/null becomes `{}`, and other values use compact
  JSON. Default keys have event-ID and opaque-UUID components. The transformed
  record omitted the projected field without changing its partition key. All
  owned EventBridge, IAM, SQS and Kinesis resources were deleted.

### Delivered audit and metric evidence

`testdata/aws/kinesis/audit_depth.json` retains 20 S3-delivered events and 14
management-history observations, correlated to actual SDK request IDs. Unlike the
earlier bounded delivery attempt, this capture received all five data operations
and their five `DryRun` counterparts:

- All ten data events report `readOnly: true`, including PutRecord and PutRecords.
  Their response elements are explicitly null. Write request parameters retain
  the resolved `streamARN` and supplied `dryRun`, not records, data, partition keys,
  explicit hash keys or sequence ordering.
- RegisterStreamConsumer identifies the parent stream in event detail, includes
  its creating consumer in response elements, and exposes three history aliases:
  stream ARN, consumer name and full consumer ARN. Its creation timestamp uses
  `Jan 2, 2006, 3:04:05 PM`, rather than the SDK's numeric timestamp.
- DescribeStreamConsumer selected by ARN retains its incarnation; selection by
  stream ARN and consumer name produces a versionless consumer detail ARN.
  Sampled read-only management calls have no history resource aliases.
- Name-selected stream calls exhibit AWS's audit-display anomaly:
  `arn:aws:kinesis:us-east-1:<streamName>:stream/null`, without `accountId`.
  Successful data events also identify the canonical stream. These are presentation fields,
  never authorization identities or resource lookup keys.

`control_audit.json` adds 402 recorded calls, 142 request-correlated S3 events and
130 history observations. It covers name/ARN selectors, stream controls,
monitoring, resharding, encryption, consumer deletion, resource policies and tags,
plus a constrained assumed role and missing resources:

- EnableEnhancedMonitoring, DisableEnhancedMonitoring and UpdateShardCount retain
  generated response elements. DescribeLimits and DescribeAccountSettings have
  null request/response elements and omit resources.
- Name-selected mutation history uses the stream name; ARN selection uses the
  ARN. Encryption operations additionally expose the supplied KMS key identifier
  in history, not in their event-detail resources. Resource-policy operations,
  resource tagging, UpdateMaxRecordSize and sampled read-only controls have no
  history aliases.
- Deregistration by consumer ARN retains that incarnation and its single alias.
  Stream-ARN/name selection uses versionless consumer detail with parent-stream
  and consumer-name history aliases.
- Authorization rejections use `AccessDenied` in the audit event, null request
  and response elements, and no history aliases. Name-selected denied writes
  retain only the display resource. Denied iterator-only GetRecords likewise
  displays its resolved stream name; an explicit ARN retains canonical detail.
- Missing PutRecord projects `arn:aws:kinesis:us-east-1:null:stream/null` in the
  request and as an additional display resource. The first resource preserves
  the supplied name-versus-ARN distinction. Other sampled missing controls
  retain their request fields and operation-specific history behavior.

Memory/SQLite replay uses actual SDK outcomes and request IDs, normalizing only
account, service time, consumer incarnation and opaque iterator values. It checks
S3 logs, EventBridge eligibility and history independently. An actual executable
restart before pending trail delivery retained the monitoring response,
name-selected deregistration/KMS aliases, denied/missing writes, and all seven
eligible events in the configured SQS target. Owned smoke/native audit resources
were removed. Account-setting changes and warm-throughput purchases were excluded;
the rejection matrix is representative, not exhaustive.

`metric_depth.json` retains 103 calls and 37 queried series. Six- and twelve-minute
publication-lag sweeps agreed. Six complete idle minutes had no samples across
those series; an inactive stream does not manufacture zero Success samples.
The three standard reads reported backlog `[60000, 0, 0]` and emitted all three
iterator-age observations. Caught-up age was zero even though the records were
about 69 seconds old. Three writes totaling 18 bytes produced different native
byte distributions:

| Dimension | SampleCount | Sum | Minimum | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Stream, two put operations | 2 | 18 | 4 | 14 |
| Enhanced shard, three records | 3 | 18 | 4 | 8 |

A successful enhanced-fan-out admission emitted `SubscribeToShard.RateExceeded=0`.
A complete empty subscription minute contained twelve frames and twelve zero
byte/record observations, approximately five seconds apart, with twelve successful
event samples. No SubscribeToShard or SubscribeToShardEvent latency series was
observed. The subsequent captures below add positive backlog and distinguish
service-owned EOF from explicit client disconnects.

The fixture-driven SDK replay covers data selectors, S3 delivery, EventBridge
eligibility, history aliases, metric distributions and absent series on memory
and SQLite with real Kafka. It reopens before pending publication/delivery drains.
An actual SQLite-backed executable retained stream/shard byte distributions,
consumer admission metrics and registration history across process restart before
the metric minute closed. Real-time empty frames arrived 5.000 and 5.003 seconds
apart. Owned native resources and executable smoke streams were deleted.

### Enhanced fan-out frame and lease evidence

The same-day `efo_backlog.json`, `efo_frame_budget.json`, `efo_natural_end.json`,
`efo_client_close.json` and `efo_termination.json` retain raw observations,
request IDs, metric rechecks and verified cleanup. They refine the earlier
empty-minute observations rather than treating every connection ending alike.

- Two independent empty subscriptions delivered 59 heartbeat frames, beginning
  about five seconds after admission, then clean EOF at about 300 seconds.
  Their terminal minutes had `SubscribeToShardEvent.Success` count/sum pairs
  `3/2` and `8/7`, while byte/record/lag sample counts remained `2` and `7`.
  Rechecks through 900 seconds retained that one additional zero-valued Success
  observation, without a corresponding data frame.
- Explicit client closes after one and seven decoded frames produced service
  Success counts of two and eight, all valued one. No terminal zero or later
  buckets appeared through the extended observation window. Service-side
  publication can exceed client-decoded frames; replay compares extrema and
  bucket absence, not an invented exact client-to-service count relationship.
- Repeated legal replacement and stream deletion ended old HTTP/1.1 responses
  with a zero-length chunk and clean EOF, not a modeled exception. Their final
  metric checkpoints also retained one extra zero-valued Success observation.
  Consumer deregistration alone did not end an admitted reader. In a separate
  control, a marker written only after DescribeStreamConsumer returned
  ResourceNotFoundException arrived on the original connection with its exact
  accepted sequence number. New admissions still require a current ACTIVE
  consumer.
- The 18-record, 9-MiB aged backlog arrived in frames of 16 and two records.
  The first frame contained 7.5 MiB of raw Data, reported 88,000 milliseconds
  behind, and was followed by caught-up zero despite old record timestamps.
  The last record in the first frame was about 88 seconds old at response
  headers, but only 4.276 seconds behind the last write. Lag follows approximate
  service-time age, not that record-to-tip distance. A full final frame in a
  separate capture still reported positive approximate lag; its exact terminal
  rounding/catch-up instant is not pinned.
- Three uniform workloads packed 640-KiB records twelve at a time, 900-KiB
  records eight at a time, and 499,900-byte records fifteen at a time. These
  distinguish raw-data packing from partition-key, 8-MiB and 8,000,000-byte
  budgets. The largest frame had 10,487,946 wire bytes and 10,485,792 base64
  characters, excluding a strict 10-MiB limit on either representation.
  A greedy raw-data cap in `[7,864,320, 7,998,400)` fits these captures; they do
  not establish a universal AWS cap or an exact burst/refill algorithm.

Stackd uses a compatible 7.5-MiB raw-data packing budget, independently of its
service-time throughput debt. Byte metrics still include partition keys.
Selection precedes decryption so only the returned page needs data-key work.
Accepted frames commit metrics before transport delivery. Natural expiry,
replacement and stream deletion record their own EOF sample; disconnect and
stack shutdown do not manufacture one. Expiry retains its actual service-time
deadline even when a manual clock jumps beyond it.

Fixture replay checks payloads, order, accepted sequence numbers, frame shapes,
positive record age, caught-up lag and byte/record/Success distributions, including
pending publication across SQLite reopen. The actual executable additionally
demonstrated no initial empty frame before clock advancement, twelve 640-KiB
records followed by one caught-up record, clean replacement/deletion EOF and
post-deregistration data delivery with new admission rejected. Its final Success
count/sum was `8/5`: five accepted frames and three service-owned endings.
Modeled-exception and closed-shard terminal metric behavior remains unmeasured.

### Local implementation and verification boundaries

Generated Smithy bindings recognize all 44 modeled operations; 39 have registered
commands. The five Channel operations remain model-known and return explicit
unsupported protocol errors. Registration is not a semantic-completeness claim.

Typed memory/SQLC SQLite repositories retain stream/topology/consumer intent,
resource policies, destination work and minute metric publication. Kinesis's
primary record bytes live in Kafka; downstream consumers retain accepted work
under their own delivery contracts. Create/reshard/consumer readiness depends on
the native log; retained metadata cannot manufacture a successful read or write. AES-GCM
record envelopes contain wrapped keys obtained through ordinary KMS commands.
Historical encryption follows each record, not the stream's current setting.
Five-minute key reuse is scoped by stream incarnation, key and requester.

The standalone SDK smoke exercised plaintext and mixed historical encryption,
dry-run nonmutation, custom-key reuse/expiry, enhanced-fan-out framing, splitting,
2-MiB records, reopen and physical deletion on both memory and SQLite. It exposed
and corrected a SQLite-only nested-authorization deadlock before subscription
headers. Destination replay exposed the same missing transaction-context join
in enable preparation and an incorrect DescribeStreamSummary dependency under
the actual replication policy; both paths were corrected without bypassing IAM.
Fixture-selected controls, subscriptions and cross-service tests retain observable
regressions rather than assertions about repository wiring. Retained test stacks
now register each instance's shutdown after its database cleanup registration,
so SQLite cannot close before a reopened instance's workers.
The real-engine integration replay passes on memory and SQLite: 112 selected
native control responses, retained EFO checkpoint replacement/resume, the
DynamoDB destination's native record envelopes and role-denial recovery, and
EventBridge's 16 native partition-key cases with retained retry and DLQ delivery.
The subscription workflow also reads published IncomingRecords through the
CloudWatch SDK. These results establish those exercised paths, not full Kinesis
conformance or exact unobserved production timing.

Local one-second lifecycle preparation, policy propagation, destination drain
overlap and retry backoff are explicit service-time models, not AWS SLA claims.
Native metadata-ahead-routing lag, exact on-demand scaling/burst allocation,
broad KMS failure/cache conformance, account-setting/warm-throughput audit
projections and universal EFO packing/burst bounds require further evidence/work.
[Lambda Kinesis sources](lambda.md#kinesis-event-source-mappings) now use the shared
retained stream processor, with native standard/EFO authority, envelopes,
aggregation and oversized-retry evidence. [Logs Kinesis subscriptions](logs.md#kinesis-and-logical-destinations)
use ordinary role-authorized record writes and native policy admission.
Memory/SQLite fixtures and an executable Logs → Kinesis → real Python Lambda → SQS
workflow, before and after process restart, exercise these edges. They do not
establish uncaptured cross-account, timing or full-service conformance.
[Firehose streaming evidence](firehose.md) covers retained S3 delivery from
DirectPut and Kinesis, independently decoded compression/prefix captures, real
Lambda transformation, raw backup, source/destination denial recovery and direct
Logs/EventBridge producers. Native evidence additionally covers retry identities,
actual function timeout/oversized-response errors, KPL source metadata, trusted
Logs origin, decompression/extraction ordering and large binary codec objects.
Processing statuses, original-byte metrics, error envelopes, rule-Region target
execution and audit projections remain fixture evidence rather than response
labels. Other processors, advanced destinations and throughput boundaries remain
explicit.

S3 SSE-KMS and Firehose destination encryption use the retained
[`kms_evidence.json.gz`](../testdata/aws/s3/kms_evidence.json.gz) captures and compact
SDK replay manifests. [Encrypted object behavior](cloudtrail.md#s3-envelope-encryption)
records native authorization/alias/checksum distinctions, source bounds, cleanup
and executable CloudTrail/EventBridge recovery. This evidence does not establish
Bucket Keys, DSSE, SSE-C, cross-account or native propagation/cache conformance.

S3 [object-copy evidence](cloudtrail.md#s3-object-copies) adds owned native source
version, metadata/tag, conditional-write and KMS controls, correlated CopyObject/
internal GetObject audit records and actual classic/EventBridge delivery. Compact
fixtures retain those distinctions across both repositories and executable restart;
they do not establish multipart, access-point or directory-bucket conformance.

S3 [multipart and attributes evidence](cloudtrail.md#s3-multipart-uploads-and-attributes)
adds eight retained native capture families for initiation/part/completion
ordering, checksums, IAM/KMS authority, frozen context, consumer reads, raw
admission and real notification/CloudTrail delivery. SDK/raw fixtures preserve
native field presence and distinguish SDK scalar representations from wire
contracts. The executable workflow verified encrypted pending/completed recovery,
corrupt-part rejection, metadata-only KMS enforcement and both event routes.
The attributes-audit capture retains 195 observations across two bounded runs;
undelivered requests and transport failures are not converted to absence claims.

S3 [Object Lock evidence](cloudtrail.md#s3-object-lock) adds native fixed/variable
retention, legal holds, version protection, shared creation defaults, IAM
conditions and independently delivered audit/notification payloads. Compact
fixtures reuse one typed SDK/raw replay across both stores. The executable proves
retained metadata and multipart recovery plus actual SQS and protected CloudTrail
objects. Unmatched audit calls, an isolated activation anomaly and a server-log
window without its positive control remain explicit evidence limits.

S3 [storage and restore evidence](cloudtrail.md#s3-storage-classes-and-archive-restoration)
adds native class admission, cold-read/copy behavior, restore transitions and
independent Restore/Get authority. Captured tier upgrades distinguish faster
requests from changed retention periods. Both stores replay the native API,
classic/direct notifications and delivered CloudTrail records; the executable
also verifies retained cross-midnight completion, expiry and permanent-copy
independence. CLI checksum/list transport defaults and current SDK marker types
are explicitly normalized, not mistaken for server behavior. Native expiration,
slow-tier completion and the admitted maximum Days deadline remain unmeasured.

S3 [ownership and public-access evidence](cloudtrail.md#s3-ownership-acls-and-public-access)
adds actual member-account ownership, same-account policy/ACL/session/boundary
composition, reversible effective ACLs, multipart ownership snapshots, 87 public
policy classifications and a shared native XML dialect. Retained fixtures distinguish
captured wire data from reconstructed SDK defaults. Current duplicate-create and
SourceOwner discrepancies with AWS documentation remain explicit; account-level
public-block inheritance and arbitrary policy satisfiability are not established.

S3 [browser evidence](cloudtrail.md#s3-cors-and-static-websites) adds CORS
configuration/preflight/actual-response captures, anonymous website routing and
configuration admission, and correlated delivered management events. Five native
supplemental runs distinguish required CORS/bucket-tagging checksums from accepted
checksum-free public-block, object-tagging, website, ownership and encryption
commands. The existing model-correction generator owns those differences.
Accepted website writes sometimes returned previous configurations on subsequent
reads; separate retained-rule fixtures preserve both the accepted rule language
and that visibility uncertainty. Chromium and an executable schema upgrade/restart
exercise actual stored objects and configured CloudTrail delivery.

### Imported record-engine experiments

`testdata/kinesis/engine_probe.json` records actual pinned-container experiments,
not SDK-deserialization-only checks:

- Kinesis Mock 0.6.2 lost an acknowledged write after immediate SIGKILL and
  same-volume reopen. A configured 10-MiB write was acknowledged but its subsequent
  GetRecords returned HTTP 500. Two-MiB read/write and real event-stream delivery
  worked. Its periodic JSON persistence and wall-clock iterator/closed-shard
  behavior cannot be treated as the desired kernel contract.
- Kinesalite 3.3.3 retained an acknowledged write across process termination
  using LevelDB, but hard limits remain 1 MiB per record and 168 hours retention.
  Its active wall-clock retention deletion has no service-clock override;
  consumer/event-stream operations are absent. Process-crash survival with
  default `sync:false` does not establish host-power-loss durability.

`testdata/kinesis/kafka_engine_probe.json` evaluates a different imported
record-engine option, Apache Kafka 3.7.1 at the retained image digest. With
native per-message flushing and automatic retention disabled, exact 10-MiB
binary records, explicitly supplied timestamps and an acknowledged final write
survived SIGKILL/reopen. Native timestamp lookup selected the expected offset;
native prefix deletion removed the old record without deleting later records.
This single-broker experiment is not AWS Kinesis conformance or a host-power-loss
test. The selected backend is Kafka: it owns durable record storage while Go owns
Kinesis routing, consumers, API semantics and service-time retention. This avoids
maintaining a fork of a Kinesis-specific server; the engine experiment alone does
not establish the service semantics implemented above.
All experiment containers, volumes and temporary client artifacts were removed.
The selected image is
`apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68`.
Install it locally before constructing `engine/kinesis.NewDocker`; the runtime
does not pull images. Inject it as `Config.KinesisRuntime`. Native automatic
retention is disabled; service-time prefix deletion owns expiry. Kafka's
timestamp representation requires positive Unix milliseconds in this adapter.
The single-broker configuration and process-crash proof do not establish
host-power-loss durability, production replication or cross-engine atomicity.
Set `STACKD_KINESIS_DOCKER=1` for real-backend integration tests; DynamoDB
destination tests also require the pinned DynamoDB Local image.

## Applying the reference to current tests

Existing tests already exercise parts of the documented workflows:

- [Authorization integration](../integration/authorization_integration_test.go) checks role
  trust, cross-account caller permission, session limits and current policy changes.
- [Cross-service integration](../integration/cross_service_test.go) checks KMS permissions
  during SQS delivery and Organizations SCP restrictions on member roots/users.
- [Storage integration](../integration/storage_integration_test.go) checks that injected
  IAM/credential, Organizations, KMS and SQS state survives service reconstruction,
  including atomic rollback. [SQLite SQS integration](../integration/sqlite_sqs_integration_test.go)
  additionally covers database reopening and process-exit recovery of committed
  delivery state and KMS keys. KMS restart tests also cover grants, imports,
  material history and regional transitions; see [SQLite state](sqlite-state.md).
  [SQLite identity recovery](../integration/sqlite_identity_integration_test.go) covers IAM
  policy/session restrictions, contact initialization and Organizations SCPs across
  database reopening; related tests cover MFA, reports and federation material.
  Manual service time also persists and restores expiry and delivery deadlines.
  KMS/IAM failure tests verify service-role rollback, and SQS/IAM concurrency tests
  reject a send after permission revocation while waiting for storage, on memory
  and SQLite. The [session event journal](event-journal.md) now preserves committed
  issuance history, including process-exit rollback. Broader event delivery
  remains open.
- [Joined jobs integration](../integration/jobs_integration_test.go) combines
  DLQ redrive with IAM report generation and Organizations account/access-role
  provisioning. It verifies due-work ordering, SDK-visible results and retained
  memory/SQLite recovery.
  AWS defines status-based retrieval for [IAM reports](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateServiceLastAccessedDetails.html),
  background [account creation](https://docs.aws.amazon.com/organizations/latest/APIReference/API_CreateAccount.html)
  with a management-account access role, and asynchronous
  [message move tasks](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_StartMessageMoveTask.html).
  The local one-second deadlines and cross-service source ordering are test
  controls, not AWS timing guarantees. Recovery uses native transactions and
  typed job records.

These tests are starting points for extending the scenario matrix. Full simulator
results, denial diagnostics, remaining IAM families and the comprehensive AWS
semantic audit remain in [the IAM completion audit](iam-completion.md).

[IP condition replay](../integration/iam_conditions_integration_test.go) uses native IAM tagging,
stored-policy and simulation captures to establish address/CIDR parsing and distinct
invalid-operand behavior. SDK requests additionally enforce the observed HTTP
peer's source-IP restriction during SQS sends. See
[the IP evidence](iam-evaluation.md#ip-conditions) for primary AWS references and
the precise comparison scope.

The [string comparison audit](iam-evaluation.md#string-conditions-and-resource-wildcards)
uses native AWS captures to establish contextual casing and UTF-16 wildcard behavior;
SDK replay and tag-controlled SQS delivery check the actual shared evaluator.

[Identity input replay](../internal/services/iam/identity_inputs_aws_test.go)
uses native AWS creation/update captures to verify name/path validation and unchanged
state after rejected updates through standalone IAM and the signed gateway.
The capture resolves a difference between the SDK path pattern and actual AWS
validation; see [the IAM audit](iam-completion.md) for the correction and primary
API references.

[Policy input and mutation replay](../internal/services/iam/policy_management_aws_test.go)
uses native IAM captures to establish inline-name matching, default policy-usage filters,
missing-boundary errors and attachment counts. [SQLite/SQS replay](../integration/iam_policy_names_integration_test.go)
checks the resulting permissions for users, group members and existing role
sessions before and after reopening the database; the [IAM audit](iam-completion.md)
records the exact evidence and remaining scope.

[Credential defaults and pagination](../internal/services/iam/credential_defaults_test.go)
exercise implicit ownership, current permissions and disabled/deleted
key rejection. [Role, credential and provider-tag replay](../internal/services/iam/resource_inputs_aws_test.go)
checks native character limits, preserved update fields, status transitions and
resource-specific tagging errors through standalone IAM and the gateway. The
[IAM audit](iam-completion.md) records the AWS capture and documentation differences.

The same credential and permission workflows inform [Query conformance](aws-query.md).
Native IAM/STS requests establish accepted integer/boolean forms; SDK replay checks
canonical credential-age conditions, account-wide versus self-list permissions,
expiration and usable issued sessions. These observations replace assumptions
derived from the decoder's internal JSON representation. A further 19 pagination
observations cover owned user/tag/credential listings, page-size forms, ignored
request fields and boolean-equivalent continuation. The shared paginator now
uses generated controls and typed selections; the SDK replay verifies complete
captured page sequences and nonoverlap through both endpoint paths. TagUser's
permission-gated mutation workflow now adds 60 administrator/conditional-actor
observations and 24 read-only policy collection requests. SDK replay verifies
retained tags after denials, last-value authorization for repeated keys, indexed
collection grammar and ignored nested fields; [Query evidence](aws-query.md)
records the precise scope. The resource-scoped workflow also supplies 24 native
resource-authorization requests;
[the IAM audit](iam-completion.md) records stored paths, case-varied names,
implicit callers, access-key ownership, creation-path denial and revocation
after a user path change. SDK replay exercises both endpoint paths. The
role-template audit adds 23 native condition-controlled reads/acquisitions,
covering the AWS resource account, all five captured definitions and authorization
before missing-version lookup; see [template evidence](iam-role-templates.md).

[Organizations API replay](organizations-api.md) uses owned native OU/unattached-policy
captures to establish optional update fields, Unicode bounds, tag mutation atomicity,
validation reasons and hierarchy path projections. The generated frontend now
serves every implemented Organizations operation through direct and gateway
endpoints. AWS's asynchronous creation contract governs the existing account
provisioning scheduler.

[Resource-policy delegation](organizations-delegation.md) uses native member IAM/STS
captures to establish delegated policy management and dependent
tag/target permissions. SDK tests apply a delegated SCP update to SQS publication
and verify revocation, rollback and memory/SQLite recovery. The authority and
transition evidence is recorded in that current behavior guide. Native
replay now checks how resource-policy denials restrict trusted-service and ordinary
membership reads, management resource ownership and recovery of those decisions.

## Behavioral contracts need explicit evidence

Verify conditional SCPs, management-account simulation and SCP denial
classification against the AWS simulation API. Enforcement and simulation have
distinct contracts even when they share policy evaluation code.

KMS key states, replica synchronization and cryptographic behavior require real
implementation and AWS verification; the explicit specialty-KMS deferrals remain
recorded in the delivery scope.
[Multi-Region behavior](kms-multi-region.md) now implements shared material and
rotation with independent regional access controls and records the observed AWS
Creating, Updating and PendingReplicaDeletion states.

Adopt developer capabilities through stackd's explicit Go interfaces and
extension boundaries while keeping AWS API semantics and the selected-service
Smithy operation inventory intact. Container execution and real engine selection
follow the [kernel backend map](verification-kernel.md#required-backend-map).

[Invitation handling](organizations-invitations.md) uses an owned AWS capture to
establish handshake validation, party/resource projections, received-list ownership and
terminal errors. SDK integration tests exercise actual joins, IAM dependencies,
SCP inheritance and recovery. Standalone AWS acceptance remains an explicit audit.

[Standard all-features migration](organizations-features.md) uses the AWS worked
workflow for consent, role restoration and policy-enforcement scenarios; the
current API prose has a documented parent/child action-name discrepancy. Native
owned-account probes establish already-enabled and member rejection, with the
full successful migration capture still open.

[Effective management policies](organizations-effective-policies.md) use primary
AWS inheritance examples and owned tag-policy captures to establish merge precedence,
child restrictions, account ownership and generation behavior. Publication probes
and SDK replay also cover delayed views, rapid updates and cache retention across
disable/re-enable, with pending SQLite recovery and atomic event publication. The AWS resource
support table supplies generated validation data; service enforcement and
compliance reporting remain separate implementation requirements.

Account creation retains `IN_PROGRESS` work, publishes membership and IAM roles
atomically, and uses service time for completion. Native effective-policy
polling governs cache visibility; local scheduling does not establish AWS
propagation timing.

## SDK transport diagnostics

Smithy-Go v1.28.1 has an intermittent fast-response transport failure: its
[closed request body's `WriteTo`](https://github.com/aws/smithy-go/blob/v1.28.1/transport/http/internal/io/safe.go)
returns `io.EOF`. When the HTTP transport checks for bytes beyond Content-Length
after response headers arrive, it treats that EOF as a request-write error and
closes the connection during response decoding. The result can be an HTTP 200
followed by `use of closed network connection` in an SDK call.

`go test ./internal/services/iam -run '^TestSimulateCustomPolicyAWSCatalog$' -count=1`
reproduced the failure on untouched commit `bd212aa`, on different fixture rows.
A temporary dependency copy returning `(0, nil)` for the closed `WriteTo` passed
three complete runs. The repository retains the upstream dependency; no retry,
server delay or test exemption masks the failure. The Kinesis consumer integration's
full race run passed integration and every package except SQS, where
`TestFairQueueDoesNotWaitForDelayedQuietWork` failed while decoding HTTP 200 with
the same closed-connection error. The separate real-container stream/subscription
race suite passed. This client decode failure does not establish an IAM or queue
semantic mismatch; upstream `main` still contains the closed-`WriteTo` behavior.

The subsequent Kinesis observability integration passed generated-artifact checks,
`go vet ./...`, `go tool staticcheck ./...` and the full `go test -race -timeout=120m
./...` run. Its separate real-Kafka/Lambda race regressions also passed, including
native audit/metric replay and retained Logs subscriptions. This passing run does
not claim to fix the intermittent upstream transport defect.

## API Gateway deployed Lambda authorization evidence

`testdata/aws/apigateway/deployed_lambda_authorization.json` records 59 SDK calls
and 29 actual HTTPS requests against owned regional REST and HTTP APIs on
2026-09-24. `scripts/aws/apigateway_probe.py` retains the capture source, real
Python Lambda handler, verified Cognito JWT projections and cleanup inventory.
Both APIs, the function, execution role, user pool and log group were deleted
and verified absent. The probe did not change account-wide Gateway settings.
The native capture alone is not coverage. `TestAPIGatewayNativeDeployedLambda`
now replays the deployed authorization/payload application with real official
Lambda containers on memory and reopened SQLite. This does not establish
complete API Gateway conformance.

- Before deployment, HTTP returned 404 and REST returned 403. Unknown deployed
  paths retained that distinction.
- Both IAM-protected routes rejected unsigned requests with 403 and accepted
  the native caller's SigV4 request with 200.
- HTTP JWT routes without scopes accepted ID and access tokens. A configured
  `aws.cognito.signin.user.admin` scope accepted the access token and rejected
  the ID token with 403. Missing and malformed JWTs returned 401.
- REST Cognito methods without scopes accepted the ID token but rejected the
  access token with 401. Scoped methods accepted the access token and rejected
  the ID token with 401. Do not share HTTP JWT admission rules with REST Cognito
  admission merely because both use the same RSA verification primitive.
- Revoking the Cognito refresh family made `GetUser` reject the access token,
  while both Gateways still accepted their previously valid ID/access-token
  paths. Gateway authorization must not call Cognito's live-session validator.
- HTTP payload 2.0 retained the raw query string and joined duplicate values
  with commas. REST preserved the value list and used the final value in its
  single-value map. Both decoded `%2B` into `+`.
- HTTP JWT `requestContext.authorizer.jwt.scopes` is null when the route does
  not require scopes, even when the accepted access token contains them.
  REST removes the verified SigV4 Authorization header before invoking Lambda;
  HTTP payload 2.0 forwards it. The native fixture defends both distinctions.
- HTTP `CreateRoute` rejected a literal `@connections` path segment against its
  path grammar. The subsequent HTTP request returned 404; that does not establish
  WebSocket Management API behavior.

The [HTTP Lambda payload contract](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html),
[HTTP JWT authorizer contract](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html)
and [REST Cognito integration contract](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-integrate-with-cognito.html)
remain the primary specifications. These original deployed routes do not
establish binary payloads, custom scopes, access logging or WebSocket semantics.
Lambda authorizer evidence and its separate boundaries are recorded below.

The REST/HTTP baseline implements 36 REST and 33 HTTP targeted operations,
plus the application-driven authorizer cache flush/reset commands, for typed
APIs, resources/routes, methods/integrations, authorizers, stages, deployments
and tags. WebSocket routing reuses the v2 controls and adds five route-response
controls and three Management operations, detailed below. SQL schemas 168–169
retain scoped configuration and deployment-owned
snapshots. Public invocation uses `/_stackd/execute-api/{api-id}/{stage}/{path}`;
HTTP `$default` stages omit the stage segment. Generated control routing shares
the `apigateway` signing name using Smithy HTTP routes. Public `execute-api`
SigV4 verification preserves the original signed URL.

`deployment_transitions.json` is explicitly a local regression fixture, not an
AWS capture. Ten transitions exercise draft authorization changes, explicit
redeployment, HTTP AutoDeploy and reopening. The actual Lambda-backed endpoint
continues using its old authorization until deployment changes, then enforces
the selected policy. This fixture and the native application replay pass under
the race detector on both backends.

JWT parsing and RSA verification share the STS primitives; service-specific
issuer/audience/scope admission remains separate. Cognito exposes public keys
without exposing private material or consulting current sessions. External
issuer discovery requires the existing explicit OIDC dependency.

The retained runtime replay exposed a Lambda scheduler lock inversion:
shared SQLite discovery held its transaction while waiting for the admission
mutex, and synchronous invocation held that mutex while waiting for SQLite.
Lifecycle flags are now atomic so discovery does not acquire the admission
mutex. Invocation admission and shutdown work registration remain mutex-owned.

`cloudtrail_deployed.json`, collected by
`scripts/aws/apigateway_cloudtrail_probe.py`, correlates all 33 Gateway SDK
observations with native management events by exact response request ID.
The bounded event-history lookup created no infrastructure. Both API families
use `apigateway.amazonaws.com`. REST records nested operation inputs and HAL
link objects, not merely SDK JSON. HTTP records lower-camel fields, masks stage
variables as `***`, and escapes path labels such as `$default` on updates.
The captured HTTP `CreateRoute` rejection has `responseElements.message`
without `errorMessage`; the missing HTTP API has a null response and no
`errorMessage`. REST's missing API does include `errorMessage`.
The real-container fixture replay now checks 31 supported control-call events
through CloudTrail `LookupEvents`, including API deletion and subsequent
not-found outcomes. The two captured `GetAccount` calls remain unsupported.
`TestAPIGatewaySelectedAuditDelivery` uses the explicitly local
`audit_delivery_workflow.json` to verify that read-only trail selectors exclude
REST/HTTP writes and write selectors deliver their native event shapes through
EventBridge into SQS after reopening. Both workflows pass under the race
detector on memory and SQLite.

### Native Lambda authorizer evidence

`rest_lambda_authorizers.json` and `http_lambda_authorizers.json` retain owned
native captures from `scripts/aws/apigateway_{rest,http}_authorizer_probe.py`.
The final runs contain 100 REST and 80 HTTP requests, with real authorizer input,
output and invocation UUIDs captured through function logs and backend context.
Earlier attempts remain explicitly separate. Both probes verified deletion and
absence of their API, function, execution role and log group; neither changed
account-wide Gateway settings.

Important measured distinctions:

- REST TOKEN rejects missing/empty headers and regex failures before invocation.
  REST REQUEST with an explicit identity-source list also rejects missing/empty
  sources at TTL zero; omitting that list at TTL zero lets the function decide.
- HTTP rejects missing configured identity headers/query parameters, but the
  captured present-empty values invoked the authorizer. Header names are
  case-insensitive; query names are case-sensitive.
- REST and HTTP authorizer payload 1.0 stringify scalar context values; the
  captured nested context is rejected. HTTP payload 2.0 preserves typed context,
  including arrays, objects and null, but strips `claims` from backend context.
  Simple-response and policy-response configurations are not interchangeable.
- Successful deny policies and false simple responses are cached. Unauthorized
  and malformed results are not. Cached exact-resource policies deny other
  routes without reinvoking Lambda; adding the route key to HTTP identity
  sources isolates the cache.
- Exact `/authorizers/{id}` Lambda permission is independent of integration
  permission. An otherwise working integration does not grant authorizer access.
- Native flush/reset acknowledgement does not establish global convergence.
  REST returned 202 and later alternated old/new invocation UUIDs; HTTP returned
  204 with fresh results for three sampled cache entries and an old result for
  another. The observed timings are not guaranteed invalidation delays.

The [REST authorizer contract](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html)
and [HTTP authorizer contract](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html)
remain primary references. In particular, the captured REST explicit-source
behavior at TTL zero is narrower than the documentation's general description
of uncached REQUEST authorizers. These captures alone do not establish local
implementation coverage.

`TestAPIGatewayNativeLambdaAuthorizers` replays 69 REST and 64 HTTP native
request outcomes against both memory and SQLite using real Lambda containers.
The replay checks authorization outcomes, error envelope fields, authorizer
event/context shapes and invocation identities for cache reuse and expiry.
It stops at the first successful native flush/reset: the subsequent regional
propagation samples are evidence, not a deterministic expected sequence.
Separate local requests prove cache invalidation and retained cache reuse after
reopening storage. Post-reset authorizer updates are not covered by this replay.
Native functions used Python 3.13; local replay uses the existing pinned Python
3.12 runtime image. Cross-account/stage behavior, additional identity/context
expressions, policy limits and regional propagation remain outside the replay's
evidence. Invocation roles are covered below. The targeted Gateway regression run
also covers deployed JWT/Cognito authorization and selected CloudTrail delivery
through EventBridge to SQS.

### Native authorizer invocation-role authority

The authorizer probes' `--credentials-roles` modes retain
`testdata/aws/apigateway/rest_authorizer_roles.json` and
`testdata/aws/apigateway/http_authorizer_roles.json`. The default native actor
was IAM user `Delegated`, not account root. Scoped STS callers retain their
session policies and actor identities; credential material is redacted. Each
owned run used at most one API, one Lambda, six roles and one log group.
Cleanup and absence checks passed for every run, including retained interrupted
HTTP captures and the REST supplemental fresh-role capture.

- REST TOKEN/REQUEST and HTTP policy/simple authorizers invoke through trusted
  credentials roles with `lambda:InvokeFunction`, without an authorizer-matching
  Lambda resource-policy grant. Backend-only grants deliberately exclude
  `/authorizers/{id}`. Missing permission, explicit invocation deny, wrong trust
  and omitted credentials without a resource grant produced HTTP 500.
- Fresh roles whose initial and only trust policy requires `Null=true` for both
  `aws:SourceArn` and `aws:SourceAccount` successfully invoke authorizers in both
  protocols. These service assumptions omit both keys. Earlier mutable-trust
  experiments do not independently establish this: previously issued sessions
  and regional propagation can confound their results.
- REST credential-role updates preserve deployed behavior until redeployment.
  HTTP invocation-permission repairs became effective without deployment;
  propagation was not uniform across policy/simple authorizers. The latest
  repaired simple-response sample remains inconclusive, not an expected
  format-dependent denial.
- Both protocols admit syntactically valid nonexistent role ARNs. REST also
  stored the sampled IAM user ARN. HTTP rejected the sampled Lambda-service ARN.
  Malformed credentials ARNs return `BadRequestException`.
- Empty credentials on creation are accepted and omitted by REST but rejected
  by HTTP. Empty replacement/update clears credentials in both. HTTP omission
  during update preserves the prior ARN. REST PATCH removal of
  `/authorizerCredentials` is rejected.
- Scoped callers without `iam:PassRole`, or with an explicit session-policy
  deny, receive `AccessDeniedException` when configuring invocation roles.
  Role-scoped permission conditioned on
  `iam:PassedToService=apigateway.amazonaws.com` admits configuration.
- The first HTTP capture accepted ten authorizers and rejected the eleventh with
  `ConflictException` and HTTP 429, rather than the model's usual conflict status.
  Creation enforces that observed per-API limit in the resource transaction.
  `TestAPIGatewayNativeAuthorizerQuota` reuses those recorded SDK observations;
  local extensions verify persistence across reopening, independent API capacity
  and capacity released by deletion on memory and SQLite. Quota adjustment has
  not been sampled or implemented.

The fixture replay now exercises 17 REST and 39 HTTP native execution outcomes
with real authorizer containers on memory and reopened SQLite. It also checks
the captured control-call errors, retained credential fields, scoped STS callers
and conditional `iam:PassRole`. The shared IAM evaluator permits service
assumptions without invented source-resource keys. Invocation roles use its
existing trust, session-policy and Lambda authorization paths.

Successful SDK readiness calls are replayed because they can establish sessions
or create resources needed by later observations. Transient failed readiness
calls and HTTP readiness samples are not deterministic semantic expectations.
Two fixture annotations exclude the unestablished REST post-denial GET and the
inconclusive HTTP repaired-simple propagation sample. The supplemental fresh
REST capture remains native evidence rather than a separate replay sequence.
TTL-zero requests must invoke again after reopening; REST credential updates
retain the previous deployed role until redeployment. This does not establish
native service credential-cache refresh timing.

Cross-account behavior, STS session-expiration behavior and organization policy/
permissions-boundary enforcement remain unsampled. Primary control contracts are
[REST CreateAuthorizer](https://docs.aws.amazon.com/apigateway/latest/api/API_CreateAuthorizer.html)
and [HTTP Authorizers](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-authorizers.html).

The read-only `apigateway_cloudtrail_probe.py --role-assumptions` mode correlates
118 native STS management events in
`testdata/aws/apigateway/cloudtrail_authorizer_roles.json` by exact created role
ARN and `apigateway.amazonaws.com` actor. It does not infer which HTTP request
caused an assumption. All 23 REST events use `BackplaneAssumeRoleSession` and
request 3,600-second sessions; all 95 HTTP events request 900-second sessions
with varying 19-digit decimal names. Both have CloudTrail identity type
`AWSService`; this does not independently establish the IAM `aws:PrincipalType`
condition value. Session tokens are redacted. Five lookup pages exhausted the
bounded window; no AWS resources were created. The existing management-capture
mode was also rerun and recovered all 33 original request-correlated events.

### Native service-assumption condition context

The same authorizer probes now expose `--service-context` and
`--principal-types`. Their four captures are
`rest_authorizer_service_context.json`, `http_authorizer_service_context.json`,
`rest_authorizer_principal_type.json` and `http_authorizer_principal_type.json`
under `testdata/aws/apigateway/`. Each run used one API, one function, six roles,
ten TTL-zero authorizers and one log group. The five candidate role trusts were
set at creation and never updated; the only Lambda resource-policy grant
admitted backend routes, not authorizers. Every run's owned resources were
deleted and observed absent.

Fresh `StringEquals` trust conditions positively establish
`aws:PrincipalType=AssumedRole` for REST TOKEN/REQUEST and HTTP policy/simple
authorizer role assumptions. This is not the CloudTrail identity label:
the captured audit identity is `AWSService`. `Service` and `AWSService` did not
admit these assumptions; neither did `Account`, `Anonymous` or a condition
requiring `aws:PrincipalType` to be absent. The successful unchanged
`AssumedRole` conditions provide the positive discriminator, rather than
inferring a value from bounded failed readiness attempts.

Read-only Organizations calls established that the native account was the
management account in an organization. Fresh `Null=true` trust conditions for
`aws:SourceOrgID` and `aws:SourceOrgPaths` each admitted both formats in both
protocols. These source-less assumptions do not inherit source-organization
keys from the account that owns the role. This evidence concerns these
assumptions, not every AWS service integration. See the primary
[principal condition-key contract](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
and [documented principal values](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable).

The local fixture replay recreates organization membership before replaying
the native calls. All four captures replay 30 semantic HTTP outcomes each on
memory and reopened SQLite with actual authorizer containers. The principal-type
and source-organization cases each failed before their corresponding fix.
Gateway role assumptions now supply the observed IAM principal type; the shared
IAM evaluator derives source-organization keys only from an originating service
resource, not merely from role-account membership. Native readiness samples
remain distinct from deterministic semantic expectations; backend log markers
are excluded from authorizer-result comparisons.

The read-only follow-up `cloudtrail_authorizer_service_context.json` retains
128 successful Gateway `AssumeRole` events for the four captures' exact owned
role ARNs: 39 REST events request 3,600 seconds with
`BackplaneAssumeRoleSession`; 89 HTTP events request 900 seconds with 19-digit
names. All audit identities remain `AWSService`, including the captures that
positively establish the different IAM condition value. Five lookup pages
exhausted the bounded window. A repeat lookup without the service-actor filter
matched those 128 Gateway events and ten successful Lambda assumptions across
the 24 owned roles, with no matching denied assumption event. That bounded
observation is not a guarantee that AWS never records denied service assumptions.
No resources were created by either lookup.

### API Gateway WebSocket evidence

The implemented WebSocket path resolves deployed Lambda `AWS_PROXY` routes for
`$connect`, selected message routes/`$default`, and `$disconnect`. It supports
`NONE`, `$connect` `AWS_IAM`, and connect-only Lambda REQUEST `CUSTOM` admission.
Real socket frames distinguish one-way successful Lambda invocation from
two-way response-body delivery. A deployed `$default` RouteResponse enables
the reply even when the route omits `RouteResponseSelectionExpression`; that
field alone is not the switch. Existing connections resolve current deployed
routes, while draft changes remain inactive until deployment.

The five additional controls are `CreateRouteResponse`, `GetRouteResponse`,
`GetRouteResponses`, `UpdateRouteResponse` and `DeleteRouteResponse`. The live
service implements `GetConnection`, `PostToConnection` and `DeleteConnection`.
Its registry is scoped by partition/account/region/API, not stage: another
existing stage of the same API can manage the connection. IAM still evaluates
the requested endpoint stage and verb against
`arn:{partition}:execute-api:{region}:{account}:{api-id}/{stage}/{VERB}/@connections/{connectionId}`,
where `{connectionId}` is the literal template suffix, not the live ID.

Schema 174 retains WebSocket controls, route responses and immutable deployment
snapshots; it does not persist live connections or activity times. Shutdown
closes owned sockets, and reopening requires new connections. The runtime
enforces ten-minute idle and two-hour lifetime deadlines using service time;
configured integration execution timeouts (50–29,000 milliseconds) and bounded
socket writes use wall time. Those deadline implementations do not imply native
timing/throughput calibration. See [SQLite state](sqlite-state.md).

Focused socket regressions passed 20 race-enabled repetitions: idle expiry,
activity postponement without extending maximum lifetime, and physical closure
of live peers during shutdown. These use a manual clock and real HTTP upgrades,
not native elapsed-time captures. An SDK smoke on both storage backends also
exercised route-response create/get/update/delete/list and confirmed that a
deleted response returns `NotFoundException` and disappears from listings.

#### Native WebSocket lifecycle

`scripts/aws/apigateway_websocket_probe.py` captures an owned WebSocket API
and real Python Lambda in `testdata/aws/apigateway/websocket_lifecycle.json`.
The successful capture contains 65 SDK observations, 165 socket observations
and 113 Lambda invocations. All 50 sent message scenarios have one correlated
Lambda log; received application replies match their logged invocation IDs.
The earlier bounded propagation failure remains under `prior_captures`.
Both captures verified deletion of their API, function, execution role and
log group, with no open probe sockets remaining.

The capture establishes these runtime contracts:

- `$connect` runs before handshake acceptance. A Lambda 403 rejects the upgrade
  with that status and body. Its event retains handshake headers and query
  parameters, including multi-value parameters; message events do not repeat
  those maps.
- `$request.body.action` selects the named route. Unmatched or missing actions
  and non-JSON text select `$default`, preserving the original message body.
- Lambda success alone produces no application reply on a one-way route.
  Configuring `$default` route responses takes effect after deployment; replies
  contain the Lambda response body, not the whole proxy response envelope.
- Undeployed route changes leave deployed behavior unchanged. After deployment
  propagation, existing connections use the new routes and responses: they are
  not permanently pinned to the deployment that accepted their handshake.
- Peer close codes and reasons appear in observed `$disconnect` events.
  Binary input closes with code 1003 and reason `Binary is not supported`.

Native deployment propagation was nonuniform. Consecutive positive samples
took approximately 75 and 83 seconds for the two changed deployments; later
receives still sometimes timed out despite logged successful invocations.
Readiness counts, `DEPLOYED`, and bounded receive timeouts are not guarantees
of global convergence or permanent absence. Disconnect delivery remains
best-effort even though every accepted connection in this capture had an
observed disconnect invocation.

`TestAPIGatewayNativeWebSocketLifecycle` replays 42 SDK controls, 61 socket
operations and 36 real Lambda log records, including seven one-way invocations,
on each of memory and reopened SQLite. Official Lambda runtime containers
execute the handler; correlated invocation logs prove the one-way work ran
rather than treating failed delivery as success. The replay uses the pinned
Python 3.12 image for the native Python 3.13 capture. Nondeterministic native
propagation/readiness samples remain excluded: this is not a latency,
permanent-silence, global-convergence or guaranteed-disconnect-delivery claim.

Primary references:
[WebSocket overview](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-overview.html),
[route responses](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-route-response.html),
and [WebSocket quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-execution-service-websocket-limits-table.html).
The native lifecycle capture does not establish idle/lifetime limits, throughput,
oversized-message behavior, authorizer behavior or management authorization.

#### Native connection management

`scripts/aws/apigateway_websocket_management_probe.py` captures the three
Management API operations, STS session-policy boundaries and actual socket
delivery in `testdata/aws/apigateway/websocket_management.json`. The final
capture contains 117 SDK observations, 54 socket observations and 26 Lambda
log records. Earlier attempts remain nested under `prior_captures`; all three
attempts verified removal of their API, function, log group and two roles.

The native management application's `$default` RouteResponse produces replies
without `RouteResponseSelectionExpression` on the route, establishing that the
response's presence—not that optional expression—activates two-way delivery.

- Live `GetConnection` returns connection time, activity time and source
  identity. Management posts and one-way client traffic advance `LastActiveAt`;
  a subsequent read without traffic does not. `ConnectedAt` remains unchanged.
- Successful `PostToConnection` returns HTTP 200. Successful deletion returns
  204 and a close frame with code 1000 and reason `Connection Closed Normally`.
  Closed and repeatedly deleted connections return `GoneException` 410.
- Management access is API-scoped, not isolated by the connection's original
  stage: another existing stage of the same API can get, post to and delete the
  connection. A nonexistent endpoint stage returns `ForbiddenException` 403.
- IAM checks the endpoint stage and verb with the literal resource suffix
  `/@connections/{connectionId}`. That template allows both target and peer
  connections; concrete connection-ID ARNs and bare `/@connections` do not.
  Missing or explicitly denied session authority produces
  `AccessDeniedException` 403. Unsigned live-connection calls return 403 with
  `Missing Authentication Token`.
- Outgoing management payloads arrive as text frames. Invalid UTF-8 bytes
  become replacement characters, not base64 text. Empty payloads are delivered.
  Posts of 32,768, 32,769 and 131,072 bytes succeed with complete reassembly;
  fragmentation boundaries vary and are not contractual. A 131,073-byte post
  returns an empty raw HTTP 413, sends no frame within the recorded two-second
  receive bound, and leaves the connection usable. Botocore reports numeric
  code `413`; the Go SDK reports `UnknownError` for the identical empty response.
  The replay compares the raw status/body and absence of modeled error/request-ID
  headers; it does not fabricate a modeled `PayloadTooLargeException`.

Two synthetic IDs returned `BadRequestException` 400 before authentication,
including one shaped from a native ID. These cases do not establish the
behavior of arbitrary never-issued but native-valid IDs. The fixture preserves
that uncertainty rather than treating syntactic resemblance as validity.
The final primary/peer disconnect log records were not observed within the
bound; close frames, Gone responses and resource absence independently prove
closure.

`TestAPIGatewayNativeWebSocketManagement` replays, on each of memory and reopened
SQLite, 86 SDK observations (58 Management calls, 57 semantic), all 54 socket
observations, three unsigned HTTP outcomes and nine live activity baselines.
Real official Lambda runtime containers supply the connected application.
Assertions compare complete reassembled payloads, text opcodes, close codes and
reasons, activity transitions, IAM boundaries and raw error envelopes rather
than promising native fragmentation boundaries. Ten opaque-ID observations are
excluded because the native validity of invented/mutated IDs is unestablished;
live and closed IDs, unsigned live rejection and repeated Gone outcomes remain
replayed. Propagation/evidence/cleanup samples are not deterministic execution
expectations. Native source counts above remain distinct from replay counts.

Primary reference:
[Use @connections commands](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-how-to-call-websocket-api-connections.html).

#### Native WebSocket REQUEST authorizers

`scripts/aws/apigateway_websocket_authorizer_admission_probe.py` records 196 SDK
observations in `websocket_authorizer_admission.json`. The retained-store replay
checks 180 Gateway control outcomes on both backends: complete field presence,
rejected-update atomicity, identity-source syntax, role clearing, referenced
deletion conflicts, and CUSTOM admission only on `$connect`. Explicit TTL,
payload-version and simple-response fields are rejected, including zero/false;
omitted identity sources are accepted. The SDK's contrary required trait is
corrected in generated server contracts. The admission replay removes only the
SDK CreateAuthorizer input validator, preserving its serializer and signing.

Native `UpdateRoute` returns HTTP 201, contrary to the pinned Smithy model and
the [published 200 response](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-routes-routeid.html).
An independent owned HTTP API capture establishes the same status outside
WebSockets; the correction belongs in generation, not a protocol-specific branch.

`scripts/aws/apigateway_websocket_authorizer_probe.py` records actual REQUEST,
CONNECT, MESSAGE and DISCONNECT events in `websocket_lambda_authorizers.json`.
The successful root timeline contains 38 authorizer and 82 integration
invocations. Separate `validation_expression_capture` and
`empty_request_shape_capture` timelines contain 16/48 and 4/12 respectively.
Their 26, 16 and 4 accepted sockets were closed, and API/function/role/log-group
absence was verified. A cleaned earlier capture remains under `prior_captures`;
its interrupted final log stabilization is not used as the replay oracle.
Additional `identity_context_capture` and `missing_stage_identity_capture`
timelines contain 80/241 and 11/33 authorizer/integration invocations, with all
80 and 11 sockets closed and resource absence verified. The separate
`stage_variable_update_capture` and `route_update_status_capture` use no Lambda
backend and verify stage/route/API deletion.

Observed contracts:

- Every new connection invokes its authorizer, even with identical identities.
  Existing sockets retain their accepted scalar context after new connections
  are denied or authorizer invocation permission is removed.
- Missing/empty configured header or query identities return 401. Duplicate
  query parameters use the last value; duplicate Authorization headers return
  unmodeled HTML 400. Literal header spelling remains a local limitation.
- REQUEST events use the `/{stage}/$connect` ARN and handshake context. Empty
  query and stage-variable maps are present as `{}`, not null or absent.
- Context identities `connectionId`, `connectedAt`, `requestTimeEpoch` and
  `routeKey`, plus a present stage variable, positively invoke. `eventType` and
  `messageDirection` instead settled to bounded 401 tails without observed
  invocations, despite those fields being present in REQUEST events; restored
  header controls positively invoked. The replay selects one final rejection
  per source, not its propagation sequence.
- A genuinely variable-free stage rejects the configured absent variable;
  adding it restores actual authorizer/application invocation. Stage-variable
  updates merge keys. An empty update is a no-op, not removal; both SDK update
  responses and subsequent reads retain previous keys.
- Missing/null `principalId` is omitted from integration context; empty remains
  empty, and numeric 7 becomes `"7"`. Scalar context values stringify, null
  values disappear, and nested/array context is rejected. Only CONNECT includes
  numeric `integrationLatency`.
- Allow, explicit/implicit deny, Unauthorized, malformed responses and missing
  Lambda authority produce distinct handshake outcomes. Error JSON carries
  connection/request IDs, without modeled error or request-ID headers.
- `IdentityValidationExpression` is retained but does not filter matching,
  nonmatching or substring-only identities. Missing identities still fail.
- A fresh invocation role positively invokes without an authorizer resource
  policy under trust conditions requiring absent SourceArn/SourceAccount and
  PrincipalType AssumedRole. Initial denied handshakes are not isolated,
  audit-backed proof of STS denial; no WebSocket session-name/duration is claimed.

`TestAPIGatewayNativeWebSocketAuthorizers` passes on memory and reopened SQLite
with official runtime containers: root 48 SDK/86 socket actions and 25/43
authorizer/integration logs; regex 28/14 and 3/9; empty-map 22/4 and 1/3.
Context-source replay adds 94 SDK/32 socket actions and 7/22 logs; genuine missing
stage identity adds 35/5 and 1/3. Control-only replay checks eight stage-map and
six HTTP route-status observations, including retained reads after reopening.
Readiness/propagation samples and one literal mixed-case header case are
explicitly excluded. All semantic actions remain, including a held-message
sample whose transient old stage map is compared with the acknowledged
configuration instead of reproducing regional lag; its original authorization
context is still asserted. The final held message observes updated stage
variables while retaining its original authorization. No global convergence,
latency, or guaranteed disconnect delivery follows from these observations.
See the [WebSocket authorizer contract](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-lambda-auth.html).

### Lambda integration credentials

`scripts/aws/apigateway_rest_integration_credentials_probe.py` captures REST
behavior in `testdata/aws/apigateway/rest_integration_credentials.json`:
217 SDK observations, 193 HTTP requests and 87 correlated backend invocations.
Its `caller_context_capture` adds 170 SDK observations, 21 HTTP requests and
18 correlated invocations. `scripts/aws/apigateway_v2_integration_credentials_probe.py`
records HTTP/WebSocket behavior in `testdata/aws/apigateway/v2_integration_credentials.json`:
224 SDK observations, 111 runtime scenarios and 65 correlated invocations;
`trust_context_capture` adds 82 SDK observations, 21 scenarios and 21 invocations.
Each capture retains its executed probe/handler source and SDK metadata. All
owned APIs, functions, roles and log groups were deleted and absence verified.
Earlier exploratory captures remain evidence, not the selected replay oracle.

Observed control and execution contracts:

- An assumed integration role can invoke without a Lambda resource policy.
  Missing permission, explicit invocation deny, untrusted or nonexistent roles
  fail without a matching backend invocation. A function resource grant does
  not override an explicit role denial. Current policy/trust repair can restore
  an existing deployment.
- Credential ARN updates are deployment snapshots. Replacing/removing a role
  does not affect the old deployment; deploying changes subsequent invocations.
  Held WebSocket connections use the new per-message integration authority,
  survive failed messages, and retain their separately accepted authorizer
  context. Captured propagation samples do not establish regional timing.
- REST `credentials` PATCH supports `replace`, including empty-string removal;
  `add` and `remove` reject. Literal wire-null `PutIntegration` selects resource
  permissions and omits credentials from the response. Earlier SDK `None`
  samples omitted the field; only the explicit-null wire capture establishes
  null behavior.
- HTTP/WebSocket empty credentials create/update normalize to absent output;
  omitted update preserves the role. Both protocols reject the caller-forwarding
  sentinel at create and update. Nonexistent role ARNs can be admitted but fail
  at execution. Rejected updates preserve prior controls.
- REST caller forwarding requires `AWS_IAM`. Incompatible integration mutation
  and method downgrade reject atomically. Sentinel assignment succeeds even
  with explicit `iam:PassRole` denial; ordinary ARN assignment requires PassRole,
  including `iam:PassedToService` evaluation. Caller Lambda denial blocks
  forwarding without blocking the same caller's role-backed integration.
- Forwarded REST Lambda authority has `aws:ViaAWSService=true` and includes
  `apigateway.amazonaws.com` in `aws:CalledVia`. False/absent conditions fail,
  with successful independent role-backed controls. This proves membership,
  not an exclusive or complete chain.
- Fresh conditional roles positively establish absent `aws:SourceArn` and
  `aws:SourceAccount`, and `aws:PrincipalType=AssumedRole`, for REST, HTTP,
  WebSocket connect and held-message integration assumptions. Session names,
  durations and credential caching are not established by these captures.
- REST invocation failures carry `InternalServerErrorException`; unsigned IAM
  requests carry `MissingAuthenticationTokenException`. Failed WebSocket
  integration handshakes include connection/request IDs and the correlated
  `x-amz-apigw-id`, without management-API error headers.

`TestAPIGatewayRESTIntegrationCredentialsNative` and
`TestAPIGatewayNativeV2IntegrationCredentials` replay the selected timelines and
supplements on memory and reopened SQLite using real official Lambda runtime
containers. They check SDK/HTTP/socket outcomes, credential field presence,
deployment isolation, caller/role authority, backend log correlation and denied
marker absence. Shared log pagination leaves typed decoding and correlation
with each replay. Readiness and independently identified API-authority
propagation failures are not replayed as deterministic timing requirements.

See the native contracts for
[REST integrations](https://docs.aws.amazon.com/apigateway/latest/api/API_PutIntegration.html)
and [v2 integrations](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-integrations.html).
Their general caller-forwarding description does not override the captured v2
Lambda integration rejection.

### REST API keys and usage plans

`scripts/aws/apigateway_api_keys_probe.py` and
`testdata/aws/apigateway/api_keys.json` capture key/plan controls and three scoped
IAM resource families. `scripts/aws/apigateway_api_key_runtime_probe.py` and
`testdata/aws/apigateway/api_key_runtime.json` capture deployed requests through
real Lambda handlers in account `000000000000`, `us-east-1`. Captured source,
actors, inputs, errors, invocation logs and owned-resource absence checks remain
with the evidence, including failed hypotheses and setup propagation.

The control checkpoint adds fifteen pinned operations: key CRUD/list/import,
plan CRUD/list and membership create/delete/get/list. Native observations cover
value uniqueness and projection, prefix filtering, pagination, atomic failed
patches, stage-overlap conflicts, deletion cascades and IAM denial. CSV overwrite
preserves the key identifier and memberships but replaces its dates; a
fail-on-warning rejection retains previously accepted rows. The CLI smoke also
exercises the documented single-quoted multi-plan CSV field with a following
column. Request-only Smithy query/label bindings do not suppress response-body
members: native pagination exposed this shared protocol boundary.

Runtime observations establish:

- Deployed method key requirements are distinct from live key enablement,
  memberships and plan configuration. Legacy `stageKeys` alone do not admit a
  required method. IAM and Lambda authorization remain independent gates.
- Required AUTHORIZER-source methods use the returned `usageIdentifierKey`,
  including its retained cached value, without falling back to a valid header.
- Optional HEADER methods expose a supplied unknown value without an ID;
  recognized unassigned keys expose both. Mapped keys still enforce limits,
  **even when disabled**. Required methods reject the same disabled key.
- Both aggregate plan and method limits apply. A looser method override does not
  escape the plan limit; independent keys/plans retain their own admission.
- Quota usage is shared across a key's stages but independent between keys.
  Pre-quota traffic is not retroactively charged. Removing the quota restores
  admission; deleting the key subsequently denies required requests.

`TestAPIGatewayAPIKeysNative` replays control contracts on memory and reopened
SQLite. `TestAPIGatewayAPIKeyRuntimeNative` packages the captured handler source
for its captured official Lambda runtime and replays selected execution
timelines. It checks key identity field presence, authorizer cache identity,
HTTP error classification, retained transitions and actual invocation logs.
Native denials are correlated by API Gateway request ID, not a reused probe
label. Readiness and independently identified stale deployment responses remain
documentary. A real admitted quota prerequisite is selected explicitly; counters
are not fabricated to reproduce a later denial.

The runtime bundle contains 597 execution requests, 249 invocation log records
and 68 successful owned-resource absence checks; 127 HTTP outcomes are selected
for replay. Incomplete log captures are not noninvocation evidence. Throttle
groups compare admitted/rejected outcome classes, not AWS refill timing or
exact accepted counts. Local burst buckets are process-local; quota counts are
durable and use service time. Weekly reset/initial-offset semantics, optional
CUSTOM-authorizer usage keys and Marketplace subscription authority remain open.
`GetUsage` is documentary only; it and `UpdateUsage` are outside the pinned
implementation scope. Broader quota rollover and cross-API calibration are not
established by these captures.

Primary references:
[usage plans](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html),
[CSV format](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-key-file-format.html),
[redeployment boundaries](https://docs.aws.amazon.com/apigateway/latest/developerguide/updating-api.html)
and [Smithy HTTP bindings](https://smithy.io/2.0/spec/http-bindings.html).

### Service metrics and logging prerequisites

Gateway execution now feeds one service-owned metric publisher through the
consumer-defined `apigatewayexec.Metrics` interface. REST and V2 controls retain
their own detailed settings; HTTP requests, WebSocket operations and management
callbacks report actual observations rather than synthetic invocations.
Schemas 181–183 retain typed sample distributions and settings. Pending samples
have no API-resource foreign key: deleting an API does not discard its metrics.
Closed UTC service-time minutes publish through `cloudwatch.Service.Publish`;
publication and pending-sample removal share the existing transaction. Scope
comes from the observed API owner, not the invoking caller's metric permissions.
Latency measures wall time; observation timestamps use service time. Disconnect
timestamps are captured before the close echo, independently of callback scheduling.

`testdata/aws/apigateway/rest_metrics.json` and `v2_metrics.json`, captured by
the corresponding `scripts/aws/apigateway_*_metrics_probe.py` probes on
2026-09-25 in account `000000000000`, `us-east-1`, retain SDK settings, request
traffic, bounded CloudWatch queries and actual Lambda invocation witnesses.
REST captured three six-request cohorts plus readiness. V2 captured eight
minute cohorts, fifteen HTTP requests and WebSocket lifecycle/message/callback
traffic. The V2 process was interrupted after three complete metric polls;
bounded log collection and exact owned-resource cleanup were recovered without
a second metric capture. Both fixtures confirm owned-resource absence.

Observed contracts:

- REST uses `ApiName`, `4XXError`/`5XXError`, `Count` units and optional
  `Stage`/`Method`/resource-template dimensions. Error statistics contain a
  zero/one sample for every counted request, not just failures. IAM rejection
  contributes request/error/latency statistics but no integration latency.
- HTTP uses `ApiId`, `4xx`/`5xx`; request/error units are `None`, latency is
  milliseconds and `DataProcessed` is bytes. An unmatched HTTP 404 produced no
  metric in the captured polls. The captured raised Python error returned 500,
  not the REST function-error mapping of 502.
- REST method-specific false overrides wildcard true. V2 stage-default true
  still emits detailed series when a route explicitly specifies false, for both
  HTTP and WebSocket. Settings are live stage state, not deployment snapshots.
  REST's captured invalid boolean string succeeded and stored false.
- Successful and Lambda-rejected WebSocket connects contribute `ConnectCount`
  and `MessageCount`. Two-way messages count both incoming and outgoing messages;
  error sample populations still count operations. Management callback metrics
  use the literal `POST /@connections/{connectionId}` route and have no
  integration latency.
- WebSocket proxy 503 and missing-alias failures produced `ExecutionError`, not
  `IntegrationError`. Unknown message routes produced `ClientError`, the native
  `Forbidden` response, and no message/integration/detailed-route series.
  A disconnect without an integration still contributed one message and zero
  error samples.

The shared fixture replay uses actual Python 3.13 containers, AWS SDK metrics,
memory and reopened SQLite, retained settings, caller-account isolation and
statistics after API deletion. REST/HTTP compare minute buckets; WebSocket
compares complete captured query windows because native one-way samples spilled
across publication-minute boundaries. Latencies compare population and measured
invariants, not environment-dependent exact values. Normal HTTP proxy-byte
statistics compare the actual Lambda response envelope, not only its client body.

Focused race-enabled replay passes for both fixtures and storage backends.
A separate real `cmd/stackd` smoke invoked the Python container, reopened SQLite
before closing the observed minute, advanced service time and read the retained
`Count` distribution through the AWS CLI after deleting the API. Pending samples
and detailed settings survived reopening. Publication is asynchronous; advancing
the clock does not make the first concurrent CloudWatch query a completion barrier.

Remaining metric boundaries are explicit: native pre-integration IAM
`DataProcessed` includes an unexplained internal envelope, so that sample is
omitted locally and its byte-query minute is excluded from replay. Nonempty
request-body accounting remains uncalibrated. Raised-runtime-error byte totals
vary with traceback paths; replay checks population and byte invariants.
Positive WebSocket `IntegrationError`, runtime `FunctionError`, rejected
management callbacks and additional admission/failure classes remain unmeasured.
These captures do not establish complete Gateway metric parity.

`http_logs.json` and `rest_websocket_logs.json` retain native logging admission
and actual request-correlated access/execution records. Both record owned-resource
cleanup; the regional account logging role was restored absent.
HTTP has request-correlated access rows and resource-policy admission evidence.
REST/WebSocket include actual access/execution rows, but short setting transitions
did not establish runtime convergence or logging-level precedence. WebSocket
execution logs use `/aws/apigateway/{apiId}/{stage}`, not REST's
`API-Gateway-Execution-Logs_{apiId}/{stage}`. A bounded recovery collected and
deleted the initially missed owned WebSocket group.

Capture sanitization also covers credential identifiers and security-token fields
embedded in CloudWatch message strings, including AWS-issued service credentials
that the probe did not create. These values use the existing hash redaction markers;
other diagnostic fields remain available. Historical embedded probe source records
what ran, not a claim that its original redaction covered these messages.

Gateway now retains regional `cloudwatchRoleArn`, access settings and typed
method/route logging settings in memory and SQLite (schemas 184–185). Those
settings share the existing detailed-metric records rather than parallel maps.
GetAccount/UpdateAccount enforce account-role admission; V2 access-log and route
settings support deletion. Live stage settings reach deployed execution without
requiring a new deployment.

The existing Logs service owns ingestion, resource policies and log storage.
HTTP setup uses caller-authorized `ConfigureServiceDelivery` inside the shared
configuration transaction; actual publication uses `delivery.logs.amazonaws.com`.
Automatically created resource policies use the captured `AWSLogDeliveryWrite1`
statement and `:log-stream:*` resource. Preconfigured policies remain authoritative.
REST/WebSocket use ordinary credentialed Logs commands under the current regional
account role. Caller PassRole, service trust and logging policy admission are real
IAM decisions, not resource existence checks. Delivery runs outside configuration
transactions; failures are diagnostic and do not alter client responses.

`http_log_settings.json` resolves the earlier successful-PATCH gap against AWS:
format-only preserves destination, destination-only preserves format, configured
`{}` preserves both, and empty format rejects without changing retained state.
DeleteAccessLogSettings omits the setting; fresh format-only rejects and complete
reenablement succeeds. This supplemental capture used one owned API and two
groups, no compute or account-role mutation; both scoped policies and all owned
resources were removed. Its executed source is retained in the fixture.

`TestAPIGatewayNativeHTTPLogging` and `TestAPIGatewayNativeRESTWebSocketLogging`
replay those controls and actual Python Lambda traffic on memory and reopened
SQLite. Client headers, Lambda event IDs, real Runtime API invocation IDs and log
rows are correlated, not independently fabricated. REST/WebSocket INFO/ERROR
execution records and opt-in data tracing consume actual execution observations;
shared formatting enforces the documented
[1024-byte execution-event limit](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html#api-gateway-known-issues-rest-and-websocket-apis).
Credential-bearing structured headers/query fields are redacted without changing
customer events; arbitrary application bodies remain sensitive when tracing is
enabled, as in AWS.

The native WebSocket `DEBUG` admission normalizes to `OFF`; a model correction
keeps this service-owned behavior out of generated closed-enum rejection.
HTTP rejects execution logging levels, including `OFF`. Access request epochs
are seconds for HTTP but milliseconds for REST/WebSocket. Integration IDs come
from actual Lambda invocation, and missing observations render `-`, not invented
values.

Remaining logging boundaries: minimum account-role actions/resource scopes,
native stream allocation/sharding, Firehose access destinations, complete
authorizer/federation/custom-domain/mTLS context and HTTP byte accounting.
The typed Lambda boundary has no AWS backend HTTP signing headers to log.
Short native setting transitions did not establish convergence or route-override
precedence; delayed records are replayed under stable enabled settings, not used
to claim immediate native disable semantics. These paths are not complete Gateway
logging or service parity.

Primary documentation requires separate REST, HTTP and WebSocket contracts:
[REST metrics](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-metrics-and-dimensions.html)
use `ApiName`, `4XXError`/`5XXError` and request-count statistics;
[HTTP metrics](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-metrics.html)
use `ApiId`, `4xx`/`5xx` and `DataProcessed`;
[WebSocket metrics](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-logging.html)
distinguish connection/message traffic and client/integration/execution failures.
The captured protocol differences above are intentional; one API type's metric
table must not be applied to the others.
[REST logging](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html)
requires a regional account role, while
[HTTP access logging](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging.html)
documents log-delivery/resource-policy permissions. Native probes must not
silently replace an existing account-wide logging role or policy.

### Remaining Gateway boundaries

These deployed application checkpoints do not establish complete Gateway or
service parity. Intentional gaps remain: literal incoming header spelling,
opaque native connection-ID admission, custom domains, imports/exports, VPC
links/private/edge endpoints, CORS/quick-create, Marketplace usage plans,
optional CUSTOM-authorizer key semantics, quota calendar/offset calibration,
models/validators and regional cache/deployment propagation,
mappings/non-Lambda integrations, configurable
REST/HTTP deadlines, binary REST negotiation, canaries, account/stage throttling,
access/execution logs and the metric boundaries above. Integration-specific STS session/cache behavior and
broader cross-account/region conformance remain unmeasured.
Unsupported active configurations return errors rather than inert
success. Captured management projections are calibrated; uncaptured operations,
optional-field combinations and other rejection classes still require native
evidence.

## ECR and CodeBuild

The selected-service inventory includes all pinned modeled private-ECR and
CodeBuild operations. `docs/services.json` distinguishes registrations from
unimplemented operations: handler presence, accepted configuration and complete
behavioral parity are different claims. The per-operation
[ECR inventory](../testdata/aws/ecr/semantic_inventory.json) and
[CodeBuild inventory](../testdata/aws/codebuild/semantic_inventory.json) retain
the source revisions, references, captures and unproven branches.

### Native AWS calibration

[ECR capture summary](../testdata/aws/ecr/capture_summary.json) records real OCI
layer upload/download bytes, digest and immutable-tag rejection, current
repository-policy denial through an already-issued token, lifecycle preview,
unsupported-image scan failure, manifest-list deletion protection and the two
native KMS grants. It does not prove AWS replication delivery, enhanced findings,
12-hour token expiration or a 24-hour lifecycle-expiration wait.

[CodeBuild capture summary](../testdata/aws/codebuild/capture_summary.json)
records four actual small Linux builds in the existing configured AWS account:
success, command failure, cancellation and a five-minute timeout. A failed BUILD
still ran `finally` and POST_BUILD and published its actual S3 artifact; a timeout
was overall FAILED with a TIMED_OUT BUILD phase, while cancellation was STOPPED.
The failed/protocol captures remain alongside successful captures rather than
being rewritten as success. Native builds used `aws/codebuild/standard:7.0`;
they did not exercise native reserved fleets, external Git credentials, ECR
custom images or native event delivery.

The fixtures verify removal of the owned build, project, IAM, S3 and Logs
resources, ECR repositories and automatic KMS grants. The owned AWS KMS key is
PendingDeletion with deletion scheduled for 2026-10-03; physical deletion was
not observed. The CodeBuild compute estimate is $0.045 for nine rounded minutes,
not an observed invoice. No additional paid AWS builds or fleet/standing
configuration changes were used for local completion.

The later [source authority admission capture](../testdata/aws/codebuild/stackd-source-authority-4cc3e6fa3b3d.json)
uses one new owned IAM role/project and imports no source credentials. AWS
CreateProject/UpdateProject/StartBuild reject foreign public-provider authorities.
Canonical GitHub, Bitbucket and GitLab URLs are accepted; GitHub's explicit
`:443`/`:8443`, uppercase authority, userinfo, suffix host and trailing dot are
rejected. Enterprise/self-managed source types explicitly accept their own HTTPS
authority, including the observed enterprise nondefault port. No build was
admitted by the three foreign-source StartBuild calls; owned role and project
absence was verified. These are native admission observations, not a credential
disclosure experiment or native Git delivery proof.

### Local architecture and executable boundaries

`internal/services/ecr` owns actual OCI bytes and transactional domain state.
Docker Distribution routing recognizes terminal operations, including repository
names containing `blobs/uploads` and `manifests`. Issued tokens identify the
caller; current IAM, repository and registry policies still gate access.
KMS-backed repositories use the shared KMS owner and grants, not an independent
key or IAM database. Lifecycle expiration has a real worker. Replication copies
real manifests/layers and tags under current destination authorization; selected
work and failed destination effects are fenced by the shared transaction and a
nested savepoint. Tests protect multi-tag accumulation and replacement work
against stale completion.

Basic scanning invokes the real Trivy executable with an explicit offline
database and consumes its findings. The retained
[native engine fixture](../engine/ecr/testdata/trivy-native.json) records Trivy
0.74.0, schema-2 database identity and actual Alpine 3.20.0 findings, including
busybox CVE-2023-42364. A missing scanner/database or unsupported image is not
reported as clean. The implementation publishes native `aws.ecr` Image Scan,
Image Action and Replication Action EventBridge envelopes transactionally;
it does not invent an ImageScanCompleted CloudTrail API operation. The local
Trivy/database result is not AWS scanner-database equivalence.

`internal/services/codebuild` uses a service-specific `compute/codebuild`
Docker adapter. It retrieves real S3 or native Git sources, runs actual commands,
publishes real S3 artifacts/cache objects and Logs output, and uses IAM-owned
temporary role sessions through authenticated container metadata. Source
credentials are encrypted through KMS; source authorization, secret resolution
and downstream calls use the existing service owners. The Bitbucket BASIC_AUTH
username restriction follows
[ImportSourceCredentials](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ImportSourceCredentials.html).
Native Git regressions exercise authenticated HTTP fetch, recursive submodules
and refusal to disclose origin credentials to another authority.

Buildspec 0.2 preserves a real shell's functions, variables, working directory and
options across successful command blocks; 0.1 isolates commands. A failed/exited
shell still permits `finally` and POST_BUILD while retaining the first failure.
ABORT/CONTINUE and retry-count/pattern combinations execute actual commands;
retry patterns currently use POSIX extended regular expressions. Global and
phase `run-as` execute with the selected native UID. A runtime selector executes
the image-owned `/codebuild/image/config/runtimes.yml` entry; it does not fabricate
installed versions. Inline JSON, which is valid YAML, is classified as a document
rather than a source filename. Shell-expanded primary artifact names come from
the final actual build shell.

Fleet ACTIVE requires an observed idle native container, not a row-only success.
Fleet ARNs include `name:UUID`; stale incarnations cannot select, delete or resume
a replacement. Docker isolation and cgroup limits are real, but they do not
claim dedicated EC2-host or macOS fleet equivalence.

The [local executable record](../testdata/integration/ecr_codebuild_completion.json)
separates successful workload observations from retained failed attempts. It
includes actual Docker push/pull through a nested repository name, both missing
and subsequently revoked cross-account replication grants, two destination tags,
downloaded destination layer hashes, 70 real Alpine findings and EventBridge-to-SQS
scan delivery. A package-less newly pushed image fails scanning rather than
receiving fabricated clean findings.

CodeBuild observations include actual artifact bytes and shell-expanded naming,
official Corretto selection, an in-container boto3 metadata credential provider,
STS assumed-role identity and an S3 call denied by a policy changed during that
same live build. Separate processes prove command exit 17, failure-time artifacts,
`finally`/POST_BUILD, cancellation exit 143, an actual five-minute timeout and
concurrent workspace isolation. SIGKILL/restart retains the same container ID,
native StartedAt and random process nonce; its refreshed role credentials and
final artifact/log bytes remain usable after reopening SQLite.

The [review-correction record](../testdata/integration/codebuild_review_corrections.json)
adds focused executable evidence without replaying the unchanged broad matrix:

- An ordinary regular artifact failed before the correction because an unrelated
  workspace symlink poisoned whole-tree extraction. Afterward its exact ZIP
  member/bytes reach S3; explicitly selecting the link still fails.
- Real Git waits at an explicitly configured owned HTTPS enterprise server with
  a fake fixture secret. StopBuild persists cancellation; an Engine transport
  gate holds native removal while the controller is SIGKILLed. Reopening the old
  executable published STOPPED and cleared cleanup despite the surviving staging
  container. The corrected executable retains cleanup on an actual transport
  removal error, then removes the running source process and all build-owned
  containers when removal becomes available.
- Deleting a fleet during admitted DOWNLOAD_SOURCE previously removed capacity
  and the build failed. That pre-fix attempt retained an erroneous diagnostic
  text assertion; its FAILED status was recovered from the actual EventBridge
  event, but detailed phase contexts were not retained. The corrected executable
  keeps DELETING through preparation, publishes the admitted build's actual
  artifact bytes successfully, and only then removes fleet capacity.
- Signed local API calls replay all 15 native source UpdateProject cases and
  foreign public-provider CreateProject/StartBuild rejection without provider
  credentials or remote source requests. Retained-build regression checks apply
  the same authority rule before either imported decryption or secret access.

The record retains failed probe setup/observation attempts rather than claiming
they passed. Local TLS keys, source repositories, images, processes and fixture
databases were removed after evidence capture. This is local Docker/controller
recovery evidence, not AWS fleet-deletion/crash calibration or symlink parity.

ECR's linked-role usage callback must use the shared write transaction so IAM
can persist its deletion decision. Memory/SQLite regression tests cover refusal
while configured and successful deletion after removing configuration without
active sessions. Following real local replication, the existing IAM authority
instead refuses deletion while its one-hour sessions are active. That API
deletion is **blocked**, not passed, and this guard was observed locally, not
calibrated against native AWS. The smoke stops owned workloads/fleets/scanners
and the controller before deleting its wholly owned local fixture, retaining
only public evidence. It neither revokes sessions nor adds a cleanup clock.

### Reproduction and unsupported configurations

`scripts/ecr_codebuild_smoke.py` starts the actual `bin/stackd` CLI with persistent
SQLite, uses SDK clients and the Docker registry client, and cleans up only its
owned resources. Optional `--sdk-image` must contain Python 3 and boto3;
`--runtime-image` supplies an actual CodeBuild image with its runtime manifest.
`--ecr-scanner`, `--ecr-scanner-cache` and `--scan-layout` supply explicit native
Trivy/database/OCI inputs. Nothing downloads a vulnerability database or invents
findings at runtime. Docker itself and the pinned networking toolkit must be
available as described in the main README.

For the focused review paths, run
`python3 -P scripts/codebuild_runtime_review_smoke.py --binary /absolute/path/bin/stackd --state-dir /tmp/stackd-buildowner-review-unique --port 18682`
with a newly owned directory and unused port. It uses installed busybox and the
pinned toolkit, derives an owned trusted-TLS Git image locally, and reuses the
existing smoke lifecycle. No scanner/SDK/runtime image download or AWS call is
needed. Source admission tests use the retained native fixture; they do not
import provider credentials or run a disclosure experiment.

The official runtime exercised locally was
`public.ecr.aws/codebuild/amazonlinux2-x86_64-standard:4.0`, local image ID
`sha256:1f0067d97323548e59834291ae23959242e5e3064afca26c07c7e37f8a15e414`.
Its actual runtime manifest selects `java: corretto17`, and the produced artifact
contains Corretto 17.0.20.10.1. This is not evidence for an uninstalled Corretto 11
selector or for the Ubuntu image used by the separate AWS captures.
The registry manifest used for the retrieved archive is
`sha256:00e3f8b9dae1675035ed8d5fcaf7f8d57752ecf5ee2c28db93bad19db2c759f8`;
its source config digest is
`sha256:fd1f2fabfc29d77975efe73083d4160f9f22108cc1fde9047a3fb96a206e6d85`.
These are registry/archive identities, distinct from the locally reported image
ID above. Direct Docker pulls encountered registry transfer failures; the same
official image was retrieved using Crane v0.20.6 and loaded into Docker.

After verification, the owned SDK/runtime images, scanner binary/database,
OCI inputs, temporary probes and local fixture databases were removed. Shared
base/toolkit images were left alone. The executable record retains input
identities and the SDK-image Dockerfile; reproduction must explicitly provision
those inputs again, not assume the recorded temporary paths still exist.

Remaining ECR gaps include archive/storage-class transitions and enhanced or
continuous scanning, which needs an Inspector owner. ECR Public is a separate
service outside this private-registry inventory; pull-through cache and newer
signing/storage-class surfaces are not claimed.

The subsequent [Parameter Store workstream](ssm.md) connects CodeBuild
`PARAMETER_STORE` and buildspec `env.parameter-store` references to the real
SSM/KMS owners. The signed Docker smoke exercises batch resolution, precedence,
masking and initialization failures without retaining resolved control metadata.

The [CodePipeline owner](codepipeline.md) now binds `CODEPIPELINE` builds to
retained source/action metadata and S3 artifacts. Named primary/secondary input
directories and output ZIPs belong to the real build workspace; the original S3
source revision remains distinct from a copied artifact's version.

Ordinary projects also accept S3 ZIP and Git `secondarySources`, S3
`secondaryArtifacts` and associated source revisions through create/update/read
and StartBuild overrides. Each source has its own `CODEBUILD_SRC_DIR_<identifier>` workspace;
only the primary source supplies the buildspec. Source identifiers follow the
[ProjectSource contract](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSource.html):
alphanumerics/underscores, fewer than 128 characters, unique within the build.
Version bindings must name a declared secondary source. StartBuild's secondary
version override replaces the entire project version list for that build: omitted
sources resolve their default revision/current object, while omitting the override
uses the project versions. Source/artifact-list overrides likewise replace their
corresponding project lists.

Each declared secondary artifact selects its matching
[`artifacts.secondary-artifacts` entry](https://docs.aws.amazon.com/codebuild/latest/userguide/sample-multi-in-out-create.html),
including its source-relative base directory and shell-expanded name. ZIP and
unpackaged S3 publication reuse primary-artifact naming, namespace and KMS
handling; ZIP checksums describe the exact stored bytes. Reads and writes use
current build-role S3/KMS authority. Accepted sources, versions and secondary
artifact configuration remain independent of later project changes. Schema 310
retains the typed secondary artifact configuration alongside existing build
output metadata for controller restart.

`scripts/codebuild_secondaries_smoke.py` supplies the executable local Docker
scenario (same binary/image/helper prerequisites as the ECR/CodeBuild smoke):
primary/secondary ZIP consumers, version and list overrides, unpackaged output,
live role denial, and active/completed SQLite restart evidence. Run with
`python3 -B -P scripts/codebuild_secondaries_smoke.py --binary /absolute/bin/stackd
--state-dir /tmp/stackd-buildowner-secondaries-unique --port 18489`.
`TestCodeBuildSecondaryProjectContracts` exercises official Go SDK admission,
rejected-update atomicity and retained project configuration. These are local
contracts and executable checks, not a fabricated native successful-build capture.
The [retained executable result](../testdata/integration/codebuild_secondaries_executable.json)
records seven actual Docker builds, including both denied dependency paths and
restored successful output. The active build retained its accepted configuration
across a controller restart and project mutation. All three controller lifecycles
shut down successfully; cleanup observed zero remaining owned build containers
and no errors, then removed the owned SQLite state while retaining the result.

The later [native Git-secondary capture](../testdata/aws/codebuild/stackd-cb-git-secondary-4c4fb322e510.json)
calibrates that version-list replacement, correcting the earlier local merge
assumption. One actual small Linux build cloned the public Hello-World and
Spoon-Knife repositories, printed their README bytes as base64, and resolved
commits `7fd1a60b01f91b314f59955a4e4d4e80d8edf11d` and
`f439fc5710cd87a4025247e8f75901cdadf5333d`. Overriding only `Test` returned only
that source's version and left `CODEBUILD_SOURCE_VERSION_Master` empty;
`CODEBUILD_SOURCE_VERSION_Test` contained `refs/heads/change-the-title`.
The [first, rejected attempt](../testdata/aws/codebuild/stackd-cb-git-secondary-a41b0d336641.json)
retains native rejection of identical secondary Git locations; it started no
build. Both captures independently verify deletion of their exact owned roles,
projects and log groups. Neither imports native source credentials.
The [recalibrated S3 executable result](../testdata/integration/codebuild_secondary_version_override_executable.json)
reruns all seven real Docker builds after this correction. Its partial version
override consumes a newly uploaded `Keep` object rather than the project's older
version; omission of the override still consumes retained project versions.
Active SQLite restart, exact artifact bytes/checksums and live read/write denial
continue to pass, with zero remaining owned containers and no cleanup errors.
The subsequent [ZIP-directory executable result](../testdata/integration/codebuild_secondary_directory_executable.json)
passes the same seven builds with explicit empty primary and secondary ZIP
directories consumed inside the real container.

Admission captures also reject `.git/` locations for GitHub, GitHub Enterprise and
Bitbucket, and enabled submodule fetching for GitLab/self-managed GitLab. These
checks are shared by primary and secondary sources; the S3 folder-version check
is S3-specific, not a rule for every slash-ending Git URL. CodeConnections and
provider-status publication remain unsupported, not implied by accepting a Git
provider type. Official contracts: [multiple inputs](https://docs.aws.amazon.com/codebuild/latest/userguide/sample-multi-in-out-create.html),
[source versions](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSourceVersion.html)
and [source environment variables](https://docs.aws.amazon.com/codebuild/latest/userguide/build-env-ref-env-vars.html).

Git secondary sources reuse the primary native Git checkout and credential
lookup, not a separate host subprocess implementation. GitHub, GitHub Enterprise,
Bitbucket, GitLab and self-managed GitLab configurations retain independent
locations, requested refs, clone depths and supported auth/submodule options.
Only the primary source supplies the buildspec. Per-build source/auth/depth
overrides and accepted version lists remain independent of later project updates
and survive SQLite restart. Imported credential decryption preserves the actual
build-role context through the existing KMS forwarding boundary; per-source
Secrets Manager reads likewise use current role authority.

`TestCodeBuildGitSecondaryProjectContracts` and
`TestCodeBuildGitSecondaryBuildOverrides` exercise signed Go SDK source admission,
rejected-update atomicity, version-list replacement and durable accepted build
state. `TestNativeGitSecondaryAdmission` replays the native admission capture.
The [real Git executable result](../testdata/integration/codebuild_git_secondary_executable.json)
records thirteen Docker builds against owned local HTTPS repositories:

- Distinct primary/secondary refs and exact S3 output bytes/checksums, native
  `git rev-parse` revisions, shallow/full history and recursive submodule bytes.
- Partial version overrides select the named ref while an omitted secondary
  resolves a different default commit and has an empty source-version variable.
- Missing-ref and authentication failures; per-build auth override and current
  secret-rotation recovery; live Secrets Manager and imported-credential KMS
  denials; imported credential deletion/reimport.
- An active container and its accepted per-source options/versions survive
  SQLite restart and a conflicting project update; a fresh subsequent build
  resolves current credentials and source again.

The [initial failure](../testdata/integration/codebuild_git_secondary_initial_failure.json)
exposed loss of authenticated identity during imported-credential KMS decryption.
The [next failure](../testdata/integration/codebuild_git_secondary_directory_failure.json)
exposed empty-directory loss during source staging: a valid detached Git
repository needs its empty `.git/refs` directory. Strict source TAR/ZIP readers
now retain typed directory entries through the existing archive writer, with
duplicate, file/directory collision, file-as-parent, traversal and special-file
checks. No artificial Git refs are inserted. `TestSourceArchivesPreserveEmptyDirectories`,
`TestFolderSourceWorkspaceBoundary` and the staged native-Git regression cover
that boundary. Artifact selection and S3 folder-marker semantics are unchanged.
Both failed runs and the passing run observed zero owned containers remaining
and no cleanup errors; owned local TLS material, Git repos/images, secrets, roles
and SQLite state were removed.

Reproduce with `python3 -B -P scripts/codebuild_git_secondary_smoke.py --binary
/absolute/bin/stackd --state-dir /tmp/stackd-buildowner-git-secondaries-unique
--port 18521`, using the installed pinned toolkit and telemetry helpers. The
native calibration used public GitHub repositories only; local authenticated
HTTPS fixtures do not claim native private-provider credential or CodeConnections
coverage.

Primary and secondary S3 sources also consume folders using the documented
`bucket/prefix/` location syntax (including `bucket/` for the bucket root).
The [ProjectSource contract](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSource.html)
distinguishes folders from ZIP objects; the
[source-version contract](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSourceVersion.html)
assigns S3 version IDs to input ZIP objects, not folders. The
[native execution capture](../testdata/aws/codebuild/stackd-cb-folder-1ca8154a9b13.json)
records a successful primary/secondary nested-folder build, missing-prefix
`DOWNLOAD_SOURCE` failure, successful marker-only empty folder with an inline
buildspec, and current execution-role list/read denials. The
[isolated admission capture](../testdata/aws/codebuild/stackd-cb-folder-admit-7e57b53393cf.json)
confirms root-folder acceptance and `InvalidInputException` for nonempty primary
or secondary folder versions at project update and build start. Both captures
include independently verified cleanup of the exact owned native resources.

Folder preparation exhausts paginated S3 owner listings, orders keys
deterministically, ignores folder-marker objects, and reads each current object
through the execution role's existing S3/KMS authority. A denied object fails the
whole preparation; no caller/task-role fallback or unsigned storage read is used.
Relative file paths pass the existing workspace safety boundary, with duplicate
and file/directory collisions rejected before container staging. Only the primary
source owns the buildspec. Accepted source configuration is retained separately
from current object bytes: fresh builds download current members, while an
already-staged active container keeps its source across controller restart.

`TestCodeBuildFolderProjectContracts` adds signed Go SDK admission, rejected-update
atomicity and SQLite persistence coverage; `TestFolderSourceWorkspaceBoundary`
covers traversal, aliases, collisions and special files. Run the real Docker
workflow with `python3 -B -P scripts/codebuild_folder_smoke.py --binary
/absolute/bin/stackd --state-dir /tmp/stackd-buildowner-folders-unique --port 18507`.
The [retained executable result](../testdata/integration/codebuild_folder_executable.json)
records nine builds: checked nested primary/secondary outputs, 1,001 paginated
secondary members, fresh source changes, independent operator reads during build-role
list/read denials, missing/empty prefixes, file/directory collision rejection,
accepted configuration and staged bytes across SQLite restart, and a fresh
post-restart download. Cleanup observed zero remaining owned containers and no
errors, then removed the owned state. An
[earlier fixture result](../testdata/integration/codebuild_folder_s3_boundary.json)
retains the S3 owner's rejection of a traversal-key upload before CodeBuild; its
six accepted builds were also cleaned up. Traversal runtime coverage is therefore
the focused regression, not a claimed executable upload/checkout.
The [directory-preserving runtime rerun](../testdata/integration/codebuild_folder_directory_executable.json)
repeats all nine builds after the shared TAR/ZIP directory correction, including
the unchanged missing/marker-only folder failures, IAM denials and restart.
It again observed zero remaining owned containers and no cleanup errors.

Calibration limits: native pagination, KMS-specific denial and unsafe-key checkout
were not probed by this folder slice; KMS reads reuse the existing object owner.
Project creation and updates now validate primary and secondary S3 bucket
existence through the partition-scoped typed S3 owner in the current transaction.
The [role-authority capture](../testdata/aws/codebuild/stackd-cb-source-15baed3a31e5491f.json)
and [caller-denial control](../testdata/aws/codebuild/stackd-cb-source-51143e720af345e9.json)
establish metadata-only admission: missing buckets fail, but absent ZIP objects,
empty folders and bucket-root sources are admitted even with explicit caller or
execution-role S3 denials. This does not grant object access; preparation still
uses current execution-role S3/KMS authority.
The [deleted-source update capture](../testdata/aws/codebuild/stackd-cb-source-104ba4096e17466c.json)
establishes that description-only updates also revalidate retained sources.
All three native probes created no builds and independently verified owned
project, bucket and role deletion. `TestCodeBuildSourceBucketAdmission` checks
modeled errors, independent S3 denial controls and atomic rejected updates on
memory and SQLite. The [executable proof](../testdata/integration/codebuild_source_admission.json)
adds SQLite restart and source deletion; both controllers exited zero.
Reproduce with `python3 -B scripts/codebuild_source_admission_smoke.py`.

### Manual build retries

[`RetryBuild`](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_RetryBuild.html)
starts a new execution from a completed build's admitted configuration, including
its original overrides, rather than the project's current defaults. The retained
role, source configuration and artifact destinations are reused; current source
bytes and execution-role authority are resolved again during preparation.
Unversioned S3 sources therefore consume current objects, not the original
workspace. Schema 315 retains retry ancestry separately from ordinary starts.

The [native admission capture](../testdata/aws/codebuild/stackd-cb-retry-1953a100a2bd.json)
records missing/in-progress rejection, completed-build retries, project mutation,
token replay and parameter mismatch. The
[source and authority capture](../testdata/aws/codebuild/stackd-cb-retry-c50cd1b441ca.json)
records primary/secondary source changes and retry-only caller authority.
Both captures completed and independently verified deletion of their owned
native resources.

Retry admission requires current project-scoped `codebuild:RetryBuild`, not an
additional `StartBuild` or `iam:PassRole` grant. Revocation and project deletion
are checked before replay. Its case-sensitive, five-minute token namespace is
separate from `StartBuild`; changing the request's ID spelling from build ID to
ARN with the same token is a parameter mismatch. A manual retry does not inherit
the original CodePipeline action's completion identity.

`TestCodeBuildRetryRetainedExecutionAndTokens` executes real Docker builds on
memory and SQLite, checking retained overrides, changed project defaults,
restart-safe replay, token separation and cross-account isolation. Enable it
with `STACKD_CODEBUILD_FLEET_TEST_IMAGE=busybox:1.38.0`.
The [executable evidence](../testdata/integration/codebuild_retry_executable.json)
records six builds, actual S3 artifact contents, fresh primary/secondary bytes,
project mutation and controller restart, retry-only caller access, current-role
denial/recovery and deleted-project rejection. Cleanup observed zero remaining
owned containers and no errors. Reproduce with `python3 -B
scripts/codebuild_retry_smoke.py --binary /absolute/bin/stackd --state-dir
/tmp/stackd-buildowner-retry-unique --port 18509`.

These fixtures do not establish every source/provider/version combination,
automatic whole-build retries or batch retries. Explicit source versions remain
in the admitted configuration; this slice's executable proof exercises
unversioned S3 refresh, not a complete retry version matrix.

### Remaining CodeBuild execution boundaries

Remaining CodeBuild gaps include VPC network consumption,
privileged and non-Linux environments, CodeCommit signing,
CodeConnections, EFS, report/batch/webhook/sandbox operations,
badges/public project sharing, automatic whole-build retries, local/dynamic
caches, artifact symlink/bucket-owner options, fleet scaling/proxy/custom compute
and remote-provider status/debug sessions. Phase retries are not whole-build
retries. Runtime `latest`/major wildcards, dependencies and conflicting selectors
are not implemented. Unsupported active configurations return errors, not inert
success. VPC is an unimplemented consumer integration, not an absent shared
network owner. CodeCommit, CodeConnections, EFS and Inspector
need their actual service owners; those dependencies do not block the independent
S3/Git/Docker/IAM-backed paths above.

### RAM project sharing and analytics boundaries

CodeBuild's RAM resource type is `codebuild:Project`. The existing project
repository remains authoritative: shared `BatchGetProjects`,
`ListBuildsForProject` and `BatchGetBuilds` resolve owner-account records and
return their actual configuration, phases, artifact locations and Logs metadata.
`ListSharedProjects` discovers current eligible projects; `ListProjects` remains
owner-local. A consumer supplies full owner ARNs, and foreign build history
returns fully scoped build ARNs. RAM does not copy project/build records or
issue authority to retrieve the referenced S3 objects or CloudWatch log bytes.
Those requests still pass the independent S3/KMS/Logs owners.

The [native managed-permission capture](../internal/services/ram/testdata/native-controls.json)
retains `AWSRAMDefaultPermissionCodeBuildProject` version 1 with exactly
`codebuild:BatchGetProjects`, `codebuild:BatchGetBuilds` and
`codebuild:ListBuildsForProject`. The
[CodeBuild sharing guide](https://docs.aws.amazon.com/codebuild/latest/userguide/project-sharing.html)
and [consumer permissions](https://docs.aws.amazon.com/codebuild/latest/userguide/project-sharing-perms.html)
limit consumers to inspection, not project editing or starting builds.
Project sharing requires current owner `codebuild:PutResourcePolicy` authority.
A project with retained builds must be unshared before `DeleteProject`; that
check reads current resource associations in the same owner transaction.
The [RAM resource capability table](https://docs.aws.amazon.com/ram/latest/userguide/shareable.html#shareable-codebuild)
permits account, organization/OU and IAM user/role principals; bound principal
identities and policy conditions are evaluated by the shared IAM evaluator.
Identity, boundary, session, SCP and applicable RCP denials are not bypassed.

Every read joins the owner's transaction and fetches current RAM policies.
After native dependency checks, project deletion revokes the existing RAM
associations in that same transaction. Recreating the same project ARN does not
reactivate a deleted association. Explicitly sharing the recreated project grants
the native project ARN, including retained build history for that project.
No additional project-incarnation fields or alternate history ledger are stored.
Owner regression coverage is in `internal/services/codebuild/sharing_test.go`.

`codebuild:ReportGroup` remains rejected: CodeBuild does not yet own report
groups, reports or test-case results. A native permission catalog entry is not a
resource owner. Likewise, Glue's existing catalogs, databases, tables and bound
catalog resource policies do **not** implement Lake Formation permissions or
its service-managed RAM grant workflow. AWS
[cross-account catalog sharing](https://docs.aws.amazon.com/lake-formation/latest/dg/sharing-catalog-resources.html)
requires Lake Formation grants and recipient-side permissions. Therefore
`glue:Catalog`, `glue:Database` and `glue:Table` are not advertised as supported
RAM owners; existing direct Glue catalog resource-policy access is unchanged.
No Lake Formation grant is synthesized from a RAM association.

## RAM permission lifecycle and authority

RAM owns shares, invitations, managed/customer permissions and pinned permission
versions in typed repositories. Resource state remains with the existing
[SSM parameter](ssm.md), [EC2 subnet](ec2.md) and CodeBuild project owners.
Replacing a permission authorizes both current permission ARNs before mutation
or token replay; scoped listings and `GetPermission` use their actual resource
ARNs and current tags. Resource-policy updates retain the underlying owner's
authorization, not just `ram:ReplacePermissionAssociations`.
The [actual scoped SDK workflow](../testdata/integration/ram_scoped_authorization.json)
records these denials, successful replacement and complete cleanup.

CloudFormation ownership of RAM permissions, shares and each registered
resource/principal/permission association is private native metadata admitted
with the corresponding row. Public tags cannot prove ownership and remain
customer configuration. Exact-incarnation recovery and no-op observation use
current native IAM; direct API and Cloud Control updates preserve surviving
claims, while deleting/recreating an edge or permission starts an unclaimed
native lifetime. Schema `397_ram_private_ownership.sql` stores permission and
receipt provenance without adopting old public markers.

The [native permission identity capture](../internal/services/ram/testdata/native-permission-identity.json)
retains the actual name-derived `permission/<Name>` ARN. A private UUID distinguishes
same-ARN object lifetimes and binds typed mutation receipts to their admitted
object; it is never substituted for the native public identifier. The regression
source runs real RAM and SSM owners over memory/SQLite with native IAM principals,
lost replies and same-ARN replacement. This is a local controller-safety boundary,
not evidence of unmeasured AWS same-ARN recreation/token-replay behavior. Public
contracts remain the
[RAM Permission resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ram-permission.html)
and [CreatePermission API](https://docs.aws.amazon.com/ram/latest/APIReference/API_CreatePermission.html).

The [native version capture](../internal/services/ram/testdata/native-permission-version-template-identity.json)
establishes readable `DELETED` versions, reuse of the highest deleted number,
active-only version quotas and duplicate-template rejection. A supplied token
for a deleted version resolves that tombstone; after the number is reused, the
same token resolves the replacement version. This is observed AWS behavior, not
a reason to invent a monotonic version allocator or another identity ledger.
The [actual 21-call HTTP replay](../testdata/integration/ram_permission_versions.json)
compares native semantic response bodies and modeled errors across a real
SQLite process restart after version deletion. ARN/account and timestamp
differences are normalized; successful cleanup is retained.

Fresh native [mutation](../internal/services/ram/testdata/native-mutation-tokens.json),
[boundary](../internal/services/ram/testdata/native-mutation-token-boundaries.json)
and [promotion](../internal/services/ram/testdata/native-promotion-tokens.json)
captures distinguish omitted and supplied tokens. Observed owner-side mutations
omit response tokens when the request omits them, despite API-reference
boilerplate describing server generation. Such requests do not create an
inaccessible replay record locally. Supplied tokens retain actual replay and
operation-specific mismatch behavior; permission association/disassociation use
`InvalidClientTokenException` for the captured changed-argument cases.

[Native update replay](../internal/services/ram/testdata/native-update-token-state.json)
also depends on current requested state: rename-away rejects an old update token,
and rename-back permits it again. This uses current share fields, not new
generation state. Native `allowExternalPrincipals` replay could not be calibrated
without organization configuration changes. Successful invitation token omission
also remains uncalibrated within the owner-only native capture scope; current
documented invitation behavior is retained separately. A captured promotion
`InternalFailure` is evidence of that request, not a deterministic local failure
contract. Native capture resources were deleted; no organization configuration
or external invitation was changed.

The [actual share-token workflow](../testdata/integration/ram_share_tokens.json)
exercises eleven signed calls, including distinct omitted-token creations,
immediate replay, rename-away rejection, rename-back recovery, explicit empty
token rejection and deletion without invented response tokens.
The [actual invitation workflow](../testdata/integration/ram_invitation_expiry.json)
advances service time twelve hours and restarts the SQLite-backed executable.
The expired invitation remains unusable; reassociation produces a new pending
invitation without restoring access. Only accepting that fresh invitation enables
the actual cross-account SSM value read. Both workflows remove owned resources.

## MSK public Kafka brokers

MSK is the generated `kafka` frontend. `internal/services/kafka` owns typed
memory/SQLC cluster/configuration/revision/policy state; `engine/kafka` supplies
actual public broker endpoints. It does not reuse or expose Kinesis's private
`Log`, and makes no change to Kinesis retention or service-time semantics.

### Explicit local admission and security

The installed-only runtime is Apache Kafka **3.7.1**:
`apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68`.
An image override must resolve to that same content, not merely claim the version.
`github.com/segmentio/kafka-go` remains pinned at `v0.4.49`; SCRAM adds
`xdg-go/scram v1.1.2`, `pbkdf2 v1.0.0` and `stringprep v1.0.4`.
The official control client used by the SDK regression/protocol probe is
`aws-sdk-go-v2/service/kafka v1.65.1`.

Enable with `-docker-host unix:///var/run/docker.sock -msk-runtime` and the usual
explicit compute endpoint/installed telemetry prerequisites from the README.
No image is pulled at startup. A durable `-database` retains metadata and native
incarnation ownership across controller exits. Without a database, CLI shutdown
disposes only resources listed in its own ephemeral repository.

CreateCluster/CreateClusterV2 provisioned admission requires `KafkaVersion=3.7.1`,
one to three actual broker processes, `BrokerNodeGroupInfo.InstanceType=kafka.local`
and an empty required `ClientSubnets` list. `kafka.local` is explicitly a local
execution selector, **not an AWS instance type**. It avoids accepting a claimed
EC2 fleet, VPC, security group or AZ placement that does not exist. Nonempty
subnets/security groups, managed EBS/storage modes, managed KMS volume encryption,
public/multi-VPC networking and enhanced/open monitoring/logging are rejected.
There are no invented ZooKeeper endpoints.

The public mode is TLS by default; explicit `ClientBroker=PLAINTEXT` with
unauthenticated access enables a plaintext listener. Enabling SCRAM with TLS
uses native SASL/SCRAM-SHA-512. IAM data authentication, client-certificate MSK
mTLS and mixed public listener modes are rejected. Broker/controller traffic is
mutually authenticated TLS even when public clients use plaintext. A separate
private SCRAM/TLS administrator owns security changes; native ACLs deny public
cluster security administration while leaving supported topic/group operations
native. This is not topic-level IAM data authorization.

Each cluster has its own retained CA. A local operator can export only its public
certificate from the **exact owned broker container**:
`docker cp <owned-container>:/stackd/config/ca.pem ./cluster-ca.pem`.
Use it as the Kafka client's trusted root; hostname verification remains enabled.
Do not export `material.json` or server configuration containing private material.
GetBootstrapBrokers returns only the genuinely enabled endpoint field; no extra
AWS response field or insecure trust fallback is added.

SCRAM secrets must use an `AmazonMSK_` name and a customer-managed KMS key, with
`{"username":"…","password":"…"}` values. The control caller needs current secret/
key-read and resource-policy permissions. Scoped Kafka read-policy statements
join the cluster intent transaction without replacing unrelated statements.
Native application reads the current secret/KMS authority outside transactions;
only references, never passwords, live in the MSK repository. Credential/security
changes restart the owned brokers, revoking existing native sessions. Controller
health reconciliation refreshes current credentials; this is not an instantaneous
cross-service transaction with the native engine.

Configuration revisions retain their original property bytes. Unknown properties
are rejected; known but invalid values can be stored, matching the native free
configuration API, but cannot be applied successfully to a running cluster.
Supported settings include topic creation/deletion, partition/replication defaults,
retention/cleanup/compression, segment/roll/record limits and group retention/
initial rebalance delay. Native Kafka owns precedence, including milliseconds
over hours for retention. Listener/authentication/quorum/path properties remain
runtime-owned. Updates become effective in actual broker configuration before
publishing the effective revision. RebootBroker accepts exactly one native broker
ID, retains the choice and transitions through HEALING.

### Evidence and source boundaries

`testdata/aws/kafka/controls.json` captures one uniquely owned **free configuration**
in account `000000000000`, `us-east-1`, on 2026-09-26. It includes revision
immutability, duplicate names, pagination, unknown properties, invalid-value
storage, empty revisions and deletion. All 35 requests have exact-request-ID
CloudTrail management matches. Deletion was independently confirmed by complete
ListConfigurations pagination; no AWS broker fleet, VPC, secret or billed key was
created. An initial cleanup probe expected NotFoundException; the retained native
response instead proves BadRequestException with an absent-configuration reason.
The corrected cleanup and continuation evidence remain in the fixture.

`integration/msk_native_test.go` replays the native controls and source-owned
management projection through signed official Go SDK requests on both stores.
It checks revision bytes, scoped isolation, modeled error parameters and audit
field presence rather than diagnostic wording. Native audit includes configuration
property bytes; these noncredential values are not incorrectly described as AWS
redaction. Uncalibrated MSK management operations remain partial.

The [retained executable observations](../testdata/integration/msk_runtime.json)
come from `scripts/aws/msk_executable_smoke.py`, which uses
`scripts/aws/msk_protocol_probe.go` for official Go SDK broker discovery and real
Kafka protocol effects. Observed two-broker metadata exposes three replicated
partitions and a real controller. The signed MSK → Pipes → SQS path delivered
filtered/transformed records, held native offsets during current-role target
denial, and resumed from retained checkpoints after controller/SQLite reopen.
An independent actual SCRAM/TLS self-managed source proved existing custom-group
offset precedence, partition sharing with another live group member, restart
without replay, current secret authority denial/recovery and preservation of the
borrowed group on DeletePipe. Native resources were removed by exact incarnation,
never by broad Docker pruning.

The corrected executable lifecycle continuation also observed a selected-broker
reboot preserving native bytes, actual `DescribeConfigs` values
`num.partitions=5`/`auto.create.topics.enable=true` on both brokers, and
Secrets Manager/KMS-backed SCRAM association with genuine TLS produce/read.
Wrong passwords and disassociated credentials both failed native authentication;
the unrelated secret policy statement survived association cleanup. All exact
owned containers/volumes/networks and local secrets/configurations were removed.
The disposable local KMS key entered its required seven-day PendingDeletion
window; no AWS KMS key was created.

Primary contracts:
[configuration APIs](https://docs.aws.amazon.com/msk/1.0/apireference/configurations.html),
[SCRAM and Secrets Manager](https://docs.aws.amazon.com/msk/latest/developerguide/msk-password-tutorial.html),
[single-broker reboot](https://docs.aws.amazon.com/msk/1.0/apireference/clusters-clusterarn-reboot-broker.html),
[Kafka broker properties](https://kafka.apache.org/37/configuration/broker-configs/),
[KRaft authorization](https://kafka.apache.org/37/security/authorization-and-acls/),
and [Pipes source/group semantics](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-msk.html).

Remaining MSK boundaries are serverless, managed VPC/networking, IAM/client-mTLS
data authentication, managed encrypted volumes, native monitoring/log sinks,
replication, multi-VPC connectivity and mutable fleet topology. Pipes additionally
rejects self-managed VPC settings and encrypted PKCS#8 client keys. These are
located `TODO: Comeback` items, not successful inert resource settings.

## ElastiCache and MemoryDB: native Valkey

### Runtime and ownership

Both generated control planes use `engine/valkey`, not an in-process Redis
implementation. The installed image is
`valkey/valkey@sha256:1cb6b20b70d927560cc4cc5397b5f045e74aa603ff7696274778880bb6fadc75`
(`valkey/valkey:8.1.6-alpine`, native version **8.1.6**). Redis 7.2 selectors
are an explicit protocol-compatibility mapping to that engine, not a claim
that a separate Redis distribution or AWS's changing default is installed.
MemoryDB's calibrated Valkey parameter family is `memorydb_valkey7`; that
control-family spelling does not change the local binary's actual version.

Go owns account/region-scoped users, password hashes, ACL/user groups, parameters,
validated EC2 subnet references, tags, snapshots and retained cluster jobs.
Memory and relational SQLC repositories participate in the existing transaction
domain. Native provisioning, ACL replacement, `CONFIG SET`, replication, RDB
copies and removal run outside transactions. A random incarnation prevents stale
work from mutating a same-name replacement. Ports, actual topology and private
controller credentials survive in the exactly owned native volume.

ElastiCache supports standalone cache clusters and provisioned replication groups;
MemoryDB supports provisioned sharded clusters. Each reported node is a real
Valkey process. Native cluster slots and replica links must become healthy
before availability. Replicas are read-only. Native AOF uses `appendfsync always`;
snapshots contain independent native RDB bytes and restore through AOF base files.
Copying a snapshot does not alias the source. Engine TTL uses native wall time;
the shared service clock governs control-plane jobs and observations.

TLS really disables plaintext listeners when enabled. Passwords are hashed
before metadata persistence, ACL rules apply to native commands/key patterns,
and modified credentials take effect on each attached node. The private
controller ACL is not exposed through public administrative commands. Control
IAM is separate from native password/ACL authentication; it is evaluated from
current policy, not cached create-time grants. Requested customer KMS keys and
unsupported networking, authentication or topology effects are rejected.
Native files contain sensitive plaintext data; this does not provide AWS-managed
physical-storage protection or assert that AWS KMS encrypted the local volumes.

ElastiCache create and modify both accept `SnapshotRetentionLimit=0`, the
documented disabled-backup value also returned by Describe. Nonzero automatic
snapshot retention remains explicitly unsupported. The consistency regression
exercised both modification APIs and a real Valkey PING after modification.

### Explicit setup

Provision the image yourself; the adapter never pulls:

```sh
docker pull valkey/valkey@sha256:1cb6b20b70d927560cc4cc5397b5f045e74aa603ff7696274778880bb6fadc75
```

Run stackd with `-docker-host unix:///var/run/docker.sock -valkey-runtime`.
TLS-enabled resources additionally require `-valkey-tls-cert /absolute/cert.pem`
and `-valkey-tls-key /absolute/key.pem`, with a valid certificate for `127.0.0.1`.
Trust that certificate/CA in the native client. MemoryDB defaults to TLS;
explicit plaintext is accepted only for the open-access ACL. Authenticated
ElastiCache resources require TLS. `-valkey-image` accepts an explicitly installed
immutable alternative, but the runtime still verifies the native version.
This local adapter requires Linux and a local Unix Docker daemon; endpoints bind
loopback rather than pretending to attach a container to an AWS VPC.

Embedded callers inject `Config.ValkeyRuntime` and own its close. SQLite-backed
CLI shutdown detaches, preserving native bytes and endpoints at the same database
path. Graceful in-memory CLI shutdown deletes its exact retained deployment and
snapshot IDs. Resource deletion checks namespace/incarnation labels before
removing containers or volumes. Shared images and other owners are untouched.

### Calibration and executable evidence

Generated models use the official SDK checkout
`113bc91bf12edc3af1d3aba1c70be28494d54c2a`.

[Native fixtures](../testdata/aws/valkey) retain exact request IDs and account
identity for bounded free parameter-group/user controls in account `000000000000`,
`us-east-1`. No billed cache/database cluster was launched. Every created user
and parameter group was deleted and its modeled absence observed. Native
asynchronous user propagation required explicit cleanup retries. The initial
collector's reversed ID mapping/wrong MemoryDB source was corrected by exact-ID
recollection, not interpreted as missing AWS events.

Native observations distinguish MemoryDB's `user-name` filter and 1–50 user
page bounds from ElastiCache's user/group positive page sizes. Selected
ElastiCache UserId ignores the page size. Native zero-size unfiltered
ElastiCache reads returned InternalFailure; those receipts are retained, not
copied into a fabricated local internal failure. Local zero-size unfiltered
pages are explicitly rejected. Changing cloud default versions and asynchronous
propagation timing are also excluded from local equivalence.

The shared CloudTrail collector records actual management events.
`memorydb.amazonaws.com` is the native event source. Observed user/password
redaction preserves a list of AWS-hidden markers; owner-sanitized input is
separately labeled. Calibrated mutation response fields are retained, while
Describe responseElements are null. This is not CloudTrail data-event evidence
for native commands, nor an invented direct lifecycle-event payload.

Reproduce the signed executable/native-client workflow with an owned empty state
directory and installed image:

```sh
go build -o /tmp/stackd-valkey-proof ./cmd/stackd
PYTHONPATH=scripts/aws python3 -B -P scripts/aws/valkey_executable_smoke.py \
  --binary /tmp/stackd-valkey-proof --state-directory /tmp/stackd-valkey-proof-unique
```

The script uses official boto3 controls and the image's `valkey-cli`, creates its
own certificate, strips ambient AWS credentials, records concrete observations
in `report.json` and checks exact owned container/volume absence after deletion.
`scripts/aws/valkey_controls_probe.py --output /owned/new-fixture.json` is a
separate, explicitly authorized **native AWS** free-control capture; it refuses
to overwrite evidence and never provisions a billed cluster.

The retained [successful executable receipt](../testdata/integration/valkey_executable_smoke.json)
replays 37 selected native SDK cases and their 37 exact-request management
projections. Real endpoints exercised strings, hashes, lists, sorted sets and TTL,
standalone reboot, a primary/replica ElastiCache group, and two MemoryDB shards
with one replica each and all 16,384 slots. It observed TLS/plaintext and
password/ACL denials, applied parameter and credential changes, independent
snapshot-copy restores for both services, regional isolation, current IAM
revocation, native CloudWatch memory, and data live during controller detachment.
The reopened SQLite controller retained the native endpoint and bytes. All owned
native containers, snapshot/data volumes and client containers were absent after
cleanup. [Earlier failed attempts](../testdata/integration/valkey_failed_attempts.json)
retain the actual observations and corrections rather than being counted as
successful proof.

### Remaining boundaries

Local replication/AOF is not MemoryDB's distributed durable log or AWS
multi-AZ failover. Automatic failover, live resharding, changing replication
membership, per-member ElastiCache reboot, managed maintenance, automatic backups
and multi-region/global/serverless controls remain explicit unsupported effects.
Subnet membership is validated, not network isolation; security groups, VPC
attachment, AWS-managed physical storage and customer-KMS encryption are not
claimed. Native IAM authentication, SNS operational notifications and AWS event
history require their real integration rather than metadata-only success.
ElastiCache has documented direct serverless events; this self-designed-cluster
implementation does not manufacture those payloads. Native filtered ACL
`GETUSER`/`LIST` projection remains unavailable to avoid exposing the private
controller identity. Implemented operation counts do not establish whole-service
or proprietary-engine parity.

Primary references:
[ElastiCache commands](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/SupportedCommands.html),
[MemoryDB restricted commands](https://docs.aws.amazon.com/memorydb/latest/devguide/restrictedcommands.html),
[MemoryDB CloudTrail](https://docs.aws.amazon.com/memorydb/latest/devguide/logging-using-cloudtrail.html),
[MemoryDB DescribeUsers](https://docs.aws.amazon.com/memorydb/latest/APIReference/API_DescribeUsers.html),
and [ElastiCache EventBridge events](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-elasticache.html).

## CloudFormation deployments

CloudFormation's generated Smithy Query frontend accepts official SDKs and
`aws cloudformation deploy`. The service owns JSON/YAML parsing, parameter
binding/constraints, pseudo parameters, conditions, selected dependency order,
outputs, exports/imports, change sets, operation tokens and deployment state.
Resource handlers invoke the existing typed owners: a stack resource record is
an incarnation/reference plus deployment intent, not an alternative S3 bucket,
queue, IAM role or Lambda implementation.

Supported expressions include `Ref`, `Fn::GetAtt`, `Fn::Sub`, `Fn::Join`,
`Fn::Split`, `Fn::Select`, `Fn::FindInMap`, `Fn::If`, condition boolean functions,
`Fn::ImportValue`, `Fn::Base64` and `AWS::NoValue`. The exact built-in
`AWS::LanguageExtensions` transform admits long-form `Fn::Length`; it does not
claim general macros, `Fn::ForEach` or `Fn::ToJsonString`.
`UsePreviousTemplate` with that transform is rejected until processed-template
storage exists. Unknown expressions, resource types, properties and meaningful
unsupported deployment options return errors rather than skipping effects.

Stack-event properties resolve `NoEcho` parameter references as `****` before
evaluating `Sub`, `Join`, `Base64` and other expressions; equal literal strings
are not redacted. Conditions still select the deployed branch using real
parameter values. A masked list becomes one masked element; an expression that
cannot then resolve, such as `Select` index 1 or a masked numeric index, produces
the native `{"****":"****"}` property sentinel. Event scalar values are strings.
Each resource incarnation and deployment before/after image retains this
projection for rollback and irreversible cleanup; each event freezes its own
copy. Later template/parameter or `NoEcho` changes do not rewrite history.
Actual owner properties and explicit outputs remain unchanged. This follows the
[NoEcho contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html)
and the native cases below; it is not blanket secret-value substitution.
Update cleanup and update-rollback deletion events omit `ResourceProperties`,
matching the retained native lifecycle/cleanup captures; ordinary stack deletion
and create rollback retain their projected properties.

Create/update and change-set execution retain intent before effects. Replacement
creates a distinct incarnation, reconnects dependents and retires the old
physical identity. Deletion follows reverse dependencies. `DeletionPolicy`
supports `Delete`, `Retain` and `RetainExceptOnCreate`; `UpdateReplacePolicy`
supports `Delete` and `Retain`. Snapshot policies remain unsupported. Forward
create/update failures roll back using retained before-images; cancellation and
continuation reuse the same operation machinery. Cleanup after
`UPDATE_COMPLETE_CLEANUP_IN_PROGRESS` is not rollback: removal from the desired
template (`DELETE`) and retirement of a replaced incarnation (`RETIRE`) each
attempt owner deletion up to three times. If deletion still fails, the old
resource is detached (`Current=false`) with `DELETE_FAILED` history and the
owner's failure reason. The stack keeps its new desired resources, template and
outputs, finishes `UPDATE_COMPLETE`, and publishes a stack warning. Cleanup does
not replay inverse deletes, recreate removed resources, or restore partially
removed targets/policies. `CancelUpdateStack` is rejected during cleanup: its
[API contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CancelUpdateStack.html)
permits only `UPDATE_IN_PROGRESS`. The detached physical resource may still exist
and must be inspected and deleted through its owning service.
This is the AWS
[removed-resource cleanup contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/troubleshooting.html#troubleshooting-errors-resource-removed-not-deleted),
not the retryable `DELETE_FAILED` contract for deleting an entire stack.
The shared scheduler yields between asynchronous Lambda/source-mapping
transitions. Memory and SQLite use the same typed contracts; current caller
policies or current service-role trust/permissions
are checked through existing authorization owners. `cloudformation:RoleArn`
uses the effective requested role, or the retained change-set role at execution.
`iam:PassRole` is checked only when a role is explicitly supplied, not when
operating an existing role-bound stack with its retained role, matching the
[service-role contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html).

Exports/imports are account/region scoped and constrain both committed and
pending consumers. Native export-in-use deletion is admitted asynchronously,
then canceled back to the previous stable stack status without deleting owners;
an in-use exported-value update instead rolls back to the previous template and
output. Historical deleted-stack outputs remain readable by stack ARN but are
not active exports.

Direct updates and change-set execution invalidate other unexecuted plans
atomically with admission while preserving immutable executed history. A canceled
create whose owner committed before its result was recorded first recovers its
physical identity using the retained
ownership token. If current authority prevents recovery, the stack remains
`UPDATE_ROLLBACK_FAILED`; continuation recovers and compensates the same intent
after authority is restored, rather than reporting success and abandoning it.
A recovered physical identity is checkpointed even when subsequent configuration
fails, so cleanup does not require successfully reprovisioning that resource.
Rollback restoration also retains its admitted identity when the post-stabilization
result read fails. That failure prevents publishing `UPDATE_COMPLETE` for the
restored resource and leaves the stack in `UPDATE_ROLLBACK_FAILED`.
A removed failed-create resource with no physical identity is detached without
calling its owner to create or delete anything, including an unrelated resource
that now has the same name.
Creation admission retains its submitted template and bound parameters even when
`DisableRollback` leaves a partially provisioned `CREATE_FAILED` stack. Later
update rollback uses that actual baseline, including non-default parameters;
resources without physical identities remain additions in subsequent plans.

### Owner-backed resources

| Resource | Implemented property/effect boundary |
| --- | --- |
| S3 Bucket | Name/tags, canned ACL except `AwsExecRead`, CORS, versioning, ownership/public-access controls, AES256/KMS default encryption, tag/prefix-filtered lifecycle expiration, SSE-C blocking, EventBridge and SQS/SNS/Lambda notifications with event/key filters; nonempty deletion fails |
| S3 BucketPolicy | Actual bucket policy installation/removal; changing the bucket replaces the policy resource |
| SQS Queue / QueuePolicy | Names, FIFO/content deduplication and message-group deduplication scope, `FifoThroughputLimit`, delay/visibility/retention/size/wait settings, encryption, DLQ/redrive and queue policies/tags; names/FIFO creation mode replace |
| SNS Topic / TopicPolicy / Subscription | Topic names/display/FIFO/encryption, supported delivery logging, tags/policies, SQS/Lambda inline subscriptions and same-account/Region SQS/Lambda/Firehose standalone subscriptions, filtering/raw delivery/DLQ where meaningful |
| IAM Role / Policy / ManagedPolicy | Actual trust, role inline/attached policies and permissions boundary; standalone inline policies target same-stack roles; managed-policy versions and role/user/group attachment; immutable names/paths/description replace as applicable |
| Lambda Function / Permission | Real inline or S3-backed ZIP, including `provided.al2023`, and explicitly installed local Docker images; configuration/code deployments, environment/layers/architecture/concurrency, native VpcConfig and permission statements, asynchronous stabilization and private incarnation recovery; [runtime and image boundary](lambda.md#container-image-deployments) |
| Lambda EventInvokeConfig | Qualified asynchronous retry/age controls and actual supported success/failure destinations through the Lambda owner; omitted controls return to native defaults |
| Cognito UserPool / UserPoolClient / UserPoolDomain / UserPoolUser / UserPoolIdentityProvider | Typed pool/user/provider configuration, native auth flows and token validity, signed local login/JWKS and OAuth client configuration; [external hosted UI/exchange limits](cognito.md) |
| IAM InstanceProfile | Actual scoped profile creation, role attachment/removal and private owner recovery through IAM |
| EC2 VPC / InternetGateway / VPCGatewayAttachment / Subnet / RouteTable / Route / SubnetRouteTableAssociation | Actual typed network resources and relationship slots; immutable creation receipts and current-IAM mutation fences, not tag adoption |
| EC2 EIP / NatGateway / VPCEndpoint / SecurityGroup / SecurityGroupIngress | Native addresses, NAT/endpoints and permission rules with owned deletion/recovery; [Linux Lambda packet-routing boundary](lambda.md) |
| WAFv2 WebACL / WebACLAssociation | Native rule configuration and association lifetime through WAF; unsupported rule settings fail before mutation |
| API Gateway REST RestApi / Deployment / Stage / Resource / Method / Authorizer | Native API graph, deployment snapshots, authorizers and actual Lambda proxy execution; stage method settings retain native wildcard/root/exact path semantics |
| API Gateway V2 Api / Stage / Authorizer / Route / RouteResponse / Integration / DomainName / ApiMapping | Native HTTP/WebSocket graph, Lambda proxy integrations, authorizers and domain/mapping ownership; actual HTTP Lambda execution and imported ACM certificate binding, not invented DNS provisioning |
| Lambda Alias | Real alias/routing changes over published function versions; qualified ARN outputs, current-IAM recovery, private incarnation ownership, provisioned runtime stabilization and stack-only discovery; no CodeDeploy rollout orchestration |
| Lambda Version | Immutable publication with transactional private receipt recovery; qualified Ref/FunctionArn and numeric Version; hash precondition, runtime/provisioned controls, scaling through the existing owner, replacement/retirement and alias-dependent deletion stabilization; [native calibration and limits](lambda.md#cloudformation-versions) |
| Lambda LayerVersion | Actual S3-backed publication with version pinning, private transactional recovery, logical-ID default naming, immutable replacement, current-owner discovery and retained function attachments after catalog deletion; [native calibration and runtime evidence](lambda.md#cloudformation-layer-versions) |
| Lambda LayerVersionPermission | Real layer policy grants with private create recovery, ARN#Sid Ref/Id, immutable replacement, revision-guarded native same-Sid deletion and cross-account runtime imports; [native calibration and limits](lambda.md#cloudformation-layer-permissions) |
| Lambda ResourcePolicy | Whole function policy creation with atomic absence/exact-create recovery, full-document updates, qualifier replacement and native-overwritten policy deletion; canonical ResourceArn and Ref, current IAM and real cross-account invocation; [native calibration and restart evidence](lambda.md#cloudformation-function-resource-policies) |
| Lambda EventSourceMapping | Actual SQS, Kinesis and DynamoDB Streams consumption with [source-specific controls and restart evidence](lambda.md#cloudformation-stream-mappings); [self-managed Kafka](lambda.md#cloudformation-self-managed-kafka-mappings) and [MSK deployment](lambda.md#cloudformation-msk-mappings) through real brokers/runtime, native-calibrated group planning/replacement, topic rejection and combined-property precedence, defaults/removal, current authority and broker-owned checkpoints; [DocumentDB deployment](lambda.md#cloudformation-documentdb-mappings) with namespace retention, real Mongo-compatible change streams, engine-independent admission, native resume tokens and restart/source-incarnation fencing; [Amazon MQ deployment](lambda.md#cloudformation-amazon-mq-mappings) with native queue immutability, credential retention, real AMQP/JMS delivery, broker-owned acknowledgements and retained runtime recovery |
| Events EventBus / Rule | Bus name/description/tags; event patterns/schedules, target reconciliation and EventBridge-owned target admissibility; input/transform/retry/DLQ/SQS/HTTP parameter admission; [native-calibrated bus migration](#cloudformation-rule-bus-migration) with physical replacement, retirement and rollback |
| Logs LogGroup | STANDARD groups, names, retention and tags |
| SSM Parameter | String/StringList values, names, descriptions, tags, type/data-type and allowed-pattern admission through the current SSM owner; SecureString remains outside the CloudFormation resource contract |
| ECR Repository | Actual repository creation, lifecycle/repository policies, image scanning/mutability/encryption and tags through ECR; nonempty deletion follows `EmptyOnDelete` |
| KMS Key / Alias | Actual key material, policy, description, enable/rotation controls, tags, alias target updates and scheduled key deletion; immutable key mode changes fail rather than replace |

Unknown properties are rejected even when a downstream service happens to store
them as inactive metadata. Resource adapters retain owner/incarnation claims on
typed native rows, separately from public tags. Public marker tags cannot
establish or revoke authority, and migrations do not promote legacy public tags
into claims. Recovery and stack mutations require the exact native incarnation
and current IAM authorization. Cloud Control updates and deletes retain ordinary
native authority without adopting a stack claim. SNS inline subscriptions follow the documented non-cascading deletion
boundary; use standalone Subscription resources when stack-owned unsubscription
is required.

The [Lambda alias workflow](lambda.md#cloudformation-aliases) retains native
deployment/routing/provisioned-runtime and stack-membership evidence separately
from local memory/SQLite recovery and foreign-replacement proofs.

REST stage method settings use the documented CloudFormation `ResourcePath: /*`
and `HttpMethod: *` wildcard, with `/` for root and `/~1...` for encoded paths,
then translate to native API patch keys. Omission clears prior writable settings;
reading them does not discard nested method models.
[CloudFormation MethodSetting contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-stage-methodsetting.html).

HTTP Lambda proxy integrations admit `TimeoutInMillis` from 50 through 30,000
and apply it to the actual backend request context; WebSocket admission retains
the 50–29,000 range.
[API Gateway V2 integration contract](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-integrations.html).
Pipes tags use the provider's string-map contract, unlike the tag arrays used by
many other resource families.
[CloudFormation Pipe contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-pipes-pipe.html).

SNS policy admission compares the native canonical default policy before taking
an unclaimed policy slot; private policy and topic-incarnation metadata remain
the mutation/recovery fence. Native policy writes relinquish the policy claim,
including equal-document writes. JSON formatting is not an ownership token.
Glue connection read models omit credentials. Unrelated edits preserve the
stored password/ciphertext; explicit removal from a previous writable model is
validated by the native owner and can transition to `SECRET_ID`, without sending
an invalid empty modeled password or exposing the retained secret.

### CloudFormation rule bus migration

[AWS::Events::Rule](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-rule.html)
deployment uses the existing EventBridge owner, current IAM and retained
CloudFormation replacement/retirement steps. A custom-bus rule's `Ref` and
physical ID are `busName|ruleName`; the default bus uses the bare rule name.
`GetAtt RuleName` returns the API name and `GetAtt Arn` identifies the actual
rule. Equivalent name/ARN spellings preserve identity, including account scope;
an ARN for a different account is not the same bus merely because names match.

The [migration capture](../testdata/aws/cloudformation/eventbridge_rule_migration.json)
retains actual native SQS delivery before and after a bus move, old-route
retirement, reverse migration, missing-bus rollback and an exact-owned collision.
The [identity capture](../testdata/aws/cloudformation/eventbridge_rule_migration_identity.json)
separately measures omitted/explicit default, default ARN, custom name and
equivalent custom ARN with a disabled targetless rule. Both captures verified
owned resource cleanup; deleted stack history remains addressable by ARN.
Neither exposes private provider API ordering or ownership tokens.

The [change-set capture](../testdata/aws/cloudformation/eventbridge_rule_migration_changesets.json)
reports `Replacement: Conditional` and `RequiresRecreation: Conditionally` for
both a proposed bus move and equivalent name-to-ARN spelling. Public planning
therefore remains distinct from execution's scoped identity decision. Native
unexecuted plans remained `AVAILABLE` and ARN-readable after stack deletion;
cleanup explicitly deleted both plans and verified `ChangeSetNotFound`.
The local deletion path now preserves those plans across SQLite restart.
Signed SDK race regressions verify retained plan reads and explicit deletion.
A separate executable scenario exercised Conditional plan fields, equivalent-ARN
execution without replacement, actual bus replacement, stack deletion, and
plan retrieval/deletion through a fresh controller process.

`integration/cloudformation_eventbridge_rule_migration_test.go` verifies
memory/SQLite under race: signed SDK deployment, actual SQS effects, transformed
target changes, current `PutRule` denial, partial creation followed by
`PutTargets` denial, rollback, retirement, restart and deletion. Foreign-rule
preservation is a local ownership boundary, not a claim about undocumented AWS
same-name adoption. A separately launched executable reproduced the rejected
bus update, upgraded its schema-302 state to 303, then verified migration,
missing-bus rollback and delivery after another controller restart.
The local stack, rules, buses and queue were removed.

Schema 303 corrects retained resource references and both operation images
without changing service-owned rules, incarnation tokens or emitted historical
events. Previously rendered output/export snapshots remain historical until
the next stack operation reevaluates them. Broader compute properties, partner
event buses and genuine custom-resource runtime/callback lifecycles remain
outside this evidence.

### Native calibration and limits

`testdata/aws/cloudformation/noecho_*.json` retains four additional native
calibrations: 220 API observations across four exact-owned stacks and eight
empty queues, all cleaned up. They cover masking/unmasking/remasking history,
literal collisions, primitive encoding, `Ref`/`Sub`/`Join`/`Base64`, actual
condition selection, and masked-list selection failure. The same fixture replay
uses official Go SDK requests against both repositories, including retained
event reads after reopening. Native wait timing and duplicate in-progress
notifications are not asserted as deterministic scheduling guarantees.
`testdata/integration/cloudformation_noecho_runtime.json` records the signed
executable comparison: the original eight-phase run had 44 mismatches; the
corrected ten-phase run had zero, including the additional conditional/list
cases. Four deleted-stack histories retained 36 exact event projections after
a real process restart. Actual queue tags and explicit outputs retained their
unmasked values, all eight local queues were absent after cleanup, and both
corrected controllers exited zero.

The native capture uses uniquely owned free SQS/SNS/IAM/S3 controls in
`000000000000`, `us-east-1`, never a billed compute fleet or standing stack.
`scripts/aws/cloudformation_probe.py` retains exact requests, modeled errors,
resource identities, ordered events and shared CloudTrail captures. Observed
behaviors include repeated create/execute tokens, no-change change sets,
create-only queue replacement, a real missing-dead-letter-queue failure and
owner-state rollback. CloudFormation omits template bodies and parameter values
from its management audit documents; failure records omit request/response
documents. Child service commands retain their own service projection and caller.
The complete request ledger is
`testdata/aws/cloudformation/lifecycle.json`. Native `AWS::SNS::Subscription`
`Ref` and `GetAtt Arn` both return the subscription ARN; the handler follows this
captured result rather than the conflicting logical-name prose in its reference.

`testdata/aws/cloudformation/cleanup.json` records removal and replacement cleanup
under an owned service role that denied deletion of exactly the two old queues.
Each old resource produced three `DELETE_IN_PROGRESS`/`DELETE_FAILED` pairs and
three request-ID-correlated denied `DeleteQueue` CloudTrail events. The stack
finished `UPDATE_COMPLETE` with “Update successful. One or more resources could
not be deleted.” Both detached queues remained real, and cancellation during
cleanup returned `ValidationError`. The probe explicitly deleted all four queues,
the stack, role and inline policy and checked their exact absence. All 177
requested CloudFormation audit IDs were observed; a broad owner-history query hit
its page cap, while the supplemental deletion query matched all six denied IDs.

Deleted stacks remain inspectable by unique stack ID. Native executed change
sets remain immutable execution history after stack deletion: `DeleteChangeSet`
rejects `EXECUTE_COMPLETE`/`EXECUTE_FAILED`. Cleanup therefore distinguishes
exact absence of active stacks, physical resources and unexecuted mutable sets
from retained deleted-stack execution history; it does not falsely report those
immutable records as absent.

The generated AWS SDK model is pinned with the other frontends.
`testdata/aws/cloudformation/resource_schemas.json`
retains twenty native regional `DescribeType` responses: sixteen original SDK
captures with request IDs and four CLI captures for SSM Parameter, ECR Repository,
KMS Key and KMS Alias, each with its capture tool, timestamp and registry metadata.
`go run ./cmd/cfngen` now consumes
`testdata/aws/cloudformation/resource_schemas_public.json`, the pinned official
regional public registry archive from
https://schema.cloudformation.us-east-2.amazonaws.com/CloudformationSchema.zip.
It generates deterministic nested object/required-property contracts, read-only
and create-only paths, primary/additional identifiers, tagging metadata and
per-handler permissions. `make generate-cloudformation-check` detects drift.
Public registry responses omit `DefaultVersionId`; the capture preserves that
absence rather than inventing a version. These schemas are not provisioning
strategies: adapters still explicitly reject unsupported properties/effects and
own native-calibrated reference, replacement and stabilization behavior.

The reusable schema admission APIs reject supplied read-only properties,
including nested properties and JSON Patch ancestor writes. Cloud Control
immutable mutations return a distinguishable create-only error rather than
silently replacing a resource. Writable projections strip observed read-only
fields without changing the owner response; primary identifiers follow the
registry order. These checks do not claim a complete JSON Schema validator:
supported values, coercion and effects still belong to the resource adapters.

Native resource readers and paginated owner discovery normalize resource
identifiers and reconstruct properties from current service commands.
Direct Cloud Control update/delete uses current service-owner authorization
without requiring a stack claim; updates retain private native claims, and
ordinary stack mutations and create recovery retain their incarnation checks.
There is no second resource-state database. S3 lifecycle supports tag/prefix
filtered current-object expiration, noncurrent-version cleanup and
incomplete-multipart abortion; unsupported actions remain explicit errors.

A disposable actual-owner command executable exercised all three direct-created
resource types through ARN normalization, read/list, mutation, public-tag
projection, retained private tags, denied current-authority mutation, stack
ownership rejection and deletion. The S3 run also applied and read the bootstrap
lifecycle rules. It exposed and fixed transport-body dependence in typed S3
ownership-control commands: the admitted structure now governs those commands,
while the native malformed/empty HTTP ownership replay still rejects invalid
requests on memory and SQLite. This is owner-boundary evidence, separate from
the public Cloud Control and unmodified CDK deployment workflows.

`testdata/integration/cloudformation_messaging.json` retains the separate local
CLI proof of all seven messaging adapters, actual S3→SNS→SQS delivery, mutable
configuration/filter changes, policy/subscription removal, unowned-name collision
rollback, SQLite restart and exact physical-resource cleanup. Its immediate
pre-activation S3 notification attempt is recorded separately from the successful
post-propagation delivery; CloudFormation does not bypass owner readiness rules.

`testdata/integration/cloudformation_compute.json` retains actual IAM policy and
managed-policy attachment/version changes, EventBus compensation, and enabled/
disabled SQS event-source-mapping stabilization across controller restart. A
preexisting execution role was assumed through current IAM/STS authority;
incorrect trust was denied, a new current-policy deny caused a real owner failure
and successful rollback, and restoring authority allowed the update to complete.
The mapping proof covers lifecycle/configuration, not message-consumption
delivery. Exact resource, execution-role and runtime artifact absence was checked.

Reproduce the signed real-runtime workflow with installed pinned Lambda images
and telemetry helpers:

```sh
go build -o /tmp/stackd-cloudformation ./cmd/stackd
python3 scripts/aws/cloudformation_executable_smoke.py \
  --binary /tmp/stackd-cloudformation \
  --state-directory /absolute/new-owned-proof-directory \
  --docker-host unix:///var/run/docker.sock \
  --telemetry-directory /absolute/stackd/bin
```

The script strips ambient AWS credentials, uses official AWSCLI/boto3 signatures,
checks real customer Lambda output and exact owner cleanup, and records both
controller exits. `testdata/integration/cloudformation_executable.json` retains
the successful run: official `aws cloudformation deploy`, actual SNS and
EventBridge delivery, Python Lambda reading S3 and sending SQS messages at three
updated stages, mutable/replacement change-set execution, current-policy denial,
cross-account/region isolation, owner-failure rollback, export constraints and
SQLite restart. Both controllers exited zero; physical resources and labeled
runtime artifacts were absent. The Go SDK fixture/consumer tests exercise both
repositories, not a mock resource handler.

`testdata/integration/cloudformation_review.json` retains the signed CLI
regression observations for role-conditioned admission, retained-role use without
`iam:PassRole`, stale-plan invalidation and the failed-create parameter baseline.
Older deletion-rollback, mapping-recreation and dependent-policy rebound
observations were removed after the authoritative cleanup correction.
The both-store SDK regressions preserve cancellation after actual `CreateQueue`
commit, a lost controller result, recovery-time permission denial, successful
continuation without orphaning the queue, and the failed-create template/parameter
baseline.

The cleanup consumer regressions cover removed and replaced SQS resources,
including three real denied owner deletion outcomes from the existing audit
journal, `DELETE_FAILED` history, successful update warnings and a restart after
the first checkpointed owner failure without resetting the three-attempt limit.
They check that the new desired resources and outputs remain current
and that the old physical queue survives even subsequent stack deletion before
explicit owner-API cleanup. A partial EventBridge rule deletion leaves the rule
detached with its targets removed, rather than replaying target installation.
Additional cases reject cancellation at a real owner deletion commit during
cleanup and remove a failed resource with no physical identity without deleting
an unrelated same-name queue.
`testdata/integration/cloudformation_cleanup.json` retains the actual signed
CLI counterpart under an owned service role: removal and replacement survived
controller restart after the first persisted failure, each emitted the three
native retry-event pairs, and completed with the native warning and both
detached owners still real. Cleanup cancellation was rejected. The probe then
explicitly deleted both orphaned queues and the remaining stack-owned resources
and role, verified exact absence, and observed two clean controller exits.

`testdata/integration/cloudformation_cleanup_order.json` records a real
failing-before/passing-after dependency-order case. A replaced S3 bucket policy
denied deletion of its old bucket. Forward-order retirement, or placing removed
resources before all retirements, orphaned the bucket. Ordering the entire
cleanup suffix by the original template's reverse dependencies deleted the
policy first, then the bucket, without warnings. Both replacement and mixed
removal/replacement paths were exercised through the signed CLI and both stores;
all probe buckets and caller identities were explicitly removed.

### Official CDK bootstrap and deployment

`testdata/integration/cloudformation_cdk.json` records the unmodified official
`aws-cdk` CLI **2.1143.0**, `aws-cdk-lib` **2.271.0** and `constructs` **10.8.1**
against the actual SQLite-backed executable. The ordinary application uses the
default synthesizer and an unmodified bootstrap template; no requests or templates
are translated by the smoke runner. Bootstrap provisions real S3, ECR, SSM and IAM
owner resources. Deploy publishes the exact file-asset bytes and provisions working
S3 objects, SQS messages and SSM values. Subsequent official deployments prove a
mutable queue update, a create-only replacement with old-queue removal, and an
owner failure with `UPDATE_ROLLBACK_COMPLETE` and restoration of prior data.
Restart preserves the stack identity, `BootstrapVersion` parameter key and
`ResolvedValue=32`, existing S3 bytes and a pending SQS message. Official
`cdk destroy` removes the app; exact-owned toolkit cleanup separately removes its
retained bucket and remaining resources. Both controller exits were zero and
cleanup completed without errors.

The runner strips ambient AWS credentials and configures a local trusted TLS
endpoint, `CDK_S3_FORCE_PATH_STYLE=true`, and the official
`AWS_ENDPOINT_URL_S3_FOR_CLOUDFORMATION=https://s3.us-east-1.amazonaws.com` override
for canonical S3 template URLs. CloudFormation reads those objects through the
local S3 owner, not the public network. The app opts out of CDK analytics via
`analyticsReporting:false`; this does not replace its synthesizer or bootstrap.
Reproduce with the pinned official packages:

```sh
npm install --prefix /tmp/stackd-cdk-tools \
  aws-cdk@2.1143.0 aws-cdk-lib@2.271.0 constructs@10.8.1
GOMAXPROCS=2 go build -p=2 -o /tmp/stackd-cfn-cloudcontrol ./cmd/stackd
python3 -B scripts/aws/cloudformation_cdk_smoke.py \
  --binary /tmp/stackd-cfn-cloudcontrol \
  --state-directory /absolute/new-owned-cdk-proof \
  --cdk /tmp/stackd-cdk-tools/node_modules/.bin/cdk \
  --node-path /tmp/stackd-cdk-tools/node_modules
```

SSM parameter keys and resolved values are retained separately in normalized
schema246 rows for stacks, change sets and operations. Supported parameter types
are `AWS::SSM::Parameter::Name` and the `Value<String>`, `Value<List<String>>` and
`Value<CommaDelimitedList>` forms. Template Rules implement boolean comparison
and member functions. `DeploymentConfig` supports real `STANDARD` stabilization;
`EXPRESS` remains unsupported. `ImportExistingResources` performs live discovery
for eligible static retained identifiers: absent targets use normal creation,
whereas existing targets return an explicit unsupported-import error without
adoption or retagging. Dynamic names follow the documented automatic-import
exclusions. Existing-resource adoption, other Rule functions, SecureString/dynamic
parameter references, arbitrary HTTP/document template sources and nested stacks
remain unsupported.

`testdata/aws/cloudformation/changeset_name_reuse.json` calibrates executed
change-set names against one exact-owned native SQS stack. Executed change sets
release their names and disappear from name lookup and listing; immutable ARN
history remains readable and cannot be deleted. The same name can be reused.
The native stack and queue were removed. Both-store SDK regressions cover this
distinction, resolved SSM snapshots and non-adoption of existing owner resources.
Primary contracts:
[ListChangeSets](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListChangeSets.html),
[CreateChangeSet](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html)
and [automatic import](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/import-resources-automatically.html).

### Cloud Control resource requests

Cloud Control's generated `awsJson1_0` frontend exposes all eight request/resource
operations for `AWS::S3::Bucket`, `AWS::SQS::Queue`, `AWS::Logs::LogGroup`,
`AWS::SSM::Parameter` and `AWS::ECR::Repository`.
Create/update/delete return retained asynchronous progress and execute the same
owner-backed handlers as CloudFormation. Reads and lists query the service owners,
including resources created outside Cloud Control; request-history models are
never used as a resource database. Service-owned SQLC schema245 stores only request
identity, caller authority, admitted before/desired state, phase and progress.
Accepted work and its management API completion commit together. Owner effects run
outside the request transaction and resume through the shared scheduler.

Update applies all six RFC6902 operations against a live owner model before
acceptance. A failed `test` or invalid/read-only path returns `ValidationException`;
create-only mutation returns `NotUpdatableException` without replacing the resource.
The handlers preserve existing private stack-incarnation tags, while public models
omit them. Every underlying command checks current owner permissions, using the
current caller or a freshly assumed CloudFormation service role. Pending requests
stop making owner calls after the documented 24-hour caller or 36-hour service-role
credential lifetime, returning `InvalidCredentials`; request history remains queryable.
An update failure does not invent a rollback: already-committed owner effects remain.
Unsupported downstream handlers, including a recovered request whose owner is no
longer registered, terminate with `GeneralServiceException`, not `NotUpdatable`.
The latter is reserved for updates to create-only properties. Cloud Control
retains its documented `*` IAM resource and absence of service-specific condition
keys; sharing CloudFormation's IAM prefix does not add `cloudformation:RoleArn`.

Client tokens retain idempotency for 36 service-time hours; conflicting intent
returns `ClientTokenConflictException`. Request status and scoped request listing
expire after seven days. Conflicting active operations on a known identifier are
rejected. Cancellation prevents subsequent handler calls but does not undo owner
effects or cancel another service's asynchronous execution. Delete checkpoints
existence before its owner effect: an initially missing resource fails `NotFound`,
whereas recovery after a committed delete can finish successfully.

`testdata/aws/cloudformation/cloudcontrol_lifecycle.json` retains 27 native API
observations for one exact-owned free LogGroup in `000000000000/us-east-1`, with
verified deletion. The native capture distinguishes synchronous immutable/read-only/
failed-test errors from asynchronous duplicate-create `AlreadyExists` and missing-
delete `NotFound`, and records terminal-cancellation rejection. The official Go v2
SDK regression runs against memory and SQLite, including progress and owner state
across reopening, cancellation, current resource data, request scope and expiry.

`testdata/integration/cloudcontrol_authority_lifetime.json` records the actual
executable's manual-clock boundary proof: caller authority fails at 24 hours,
role authority remains active then fails at 36 hours, and neither expired delete
removes its real LogGroup. Both groups and the role were explicitly removed.
These lifetimes follow the primary
[Cloud Control credentials contract](https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations.html#resource-operations-permissions).

`testdata/integration/cloudcontrol_executable.json` records the actual signed
executable workflow: all five resource types, live reads/lists, filtered request
pagination, real S3 bytes, SQS messages, Logs events and SSM values, mutable
ECR configuration, direct-owner resource discovery, current execution-role
denial/restoration, nonempty-bucket delete failure and
SQLite process restart. All owned resources and the execution role were removed;
both controllers exited zero. Reproduce without ambient credentials:

```sh
GOMAXPROCS=2 go build -p=2 -o /tmp/stackd-cfn-cloudcontrol ./cmd/stackd
python3 -B scripts/aws/cloudcontrol_executable_smoke.py \
  --binary /tmp/stackd-cfn-cloudcontrol \
  --state-directory /absolute/new-owned-cloudcontrol-proof
```

This is not all-resource Cloud Control parity. Other resource types, private
versions/extensions, hooks and nonempty list resource-model filters return explicit
unsupported errors. Public audit documents use the generated sensitivity contract;
their complete native CloudTrail field projection has not been calibrated.

The separate `testdata/integration/cloudformation_kms.json` executable capture
proves actual KMS encryption/decryption through a stack-created key/alias, mutable
description, stack deletion with an already-removed alias, `PendingDeletion`, and
physical removal at the owned seven-day service-time deadline. KMS key recovery
scans owner keys/tags under current permissions. Alias ownership is now retained
in the KMS transaction: exact-owned create recovery rechecks current authority,
and update/delete cannot mutate a same-name foreign replacement. Native alias
retargeting preserves the incarnation; delete/create resets it. Memory/SQLite
SDK regressions and separate executable/handler restart smokes verify
[alias ownership and stack discovery](resourcegroups.md#kms-aliases-in-stack-queries).
The new ownership transitions are local regression evidence, not additional
native AWS captures.

Remaining `TODO: Comeback` boundaries are located at the service dispatcher,
unsupported-input admission, template parser/intrinsic validation and individual
handler registries. StackSets, registry extension execution, SAM/custom macros,
nested stacks, custom-resource runtime/callback protocols, arbitrary remote HTTPS templates,
stack/resource imports, drift detection, refactoring, stack policies, rollback
alarms, notification delivery and unimplemented resource properties are explicit
errors. This is not whole-service or all-resource conformance.

Primary sources:
[CreateStack](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html),
[change sets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-changesets.html),
[events](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeStackEvents.html),
[exports/imports](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-importvalue.html),
[deletion policies](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-deletionpolicy.html),
[CloudTrail projection](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-api-logging-cloudtrail.html),
and the individual resource contracts in the
[AWS template reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-template-resource-type-ref.html).

## Application Load Balancer kernel

ELBv2's generated AWS Query frontend owns an initial IPv4 **Application** Load
Balancer implementation. It is not a declaration of whole-service conformance.
Resource state is partition/account/region scoped and retained through typed
memory and service-owned SQLC repositories (resource schema228; metric
migration230). Current IAM admission, resource tags, dependency errors and API
outcomes join the shared transaction
domain. Unsupported operations and settings remain explicit errors.

Each selected subnet receives an EC2-owned managed ENI and an exact-owned Docker
relay. ALB attachment intent and EC2 address/idempotency records commit together;
`CreateLoadBalancer` reserves the primary address before native node readiness,
matching the native provisioning response's already-present `DNSName`. Native
sockets and SG/NACL/public-address enforcement remain outside that transaction.
Internal listeners use private addresses; internet-facing listeners
require an actual EC2 public IPv4 binding and active route. The local public pool
is host-routed, not an Internet-advertised AWS address allocation. `DNSName`
publishes a stable AWS-shaped hostname whose current addresses come from the
existing EC2/ALB owners, not another DNS resource registry. Public ALB
`LoadBalancerAddresses` are not synthesized.

`compute/dns` serves real authoritative UDP and TCP queries through the
consumer-defined ELB DNS interface. `-dns-listen` / `Config.DNSListenAddress`
selects a literal IPv4 listener; a configured native ALB runtime otherwise gets
an ephemeral loopback port, exposed by `Stack.DNSAddress()` and the CLI startup
log. A records use current node addresses with TTL 60; unsupported AAAA addresses
return NODATA and deleted names return NXDOMAIN. The host resolver is never
changed. Point clients explicitly at this endpoint; the executable smoke's HTTP
helper preserves the hostname in Host, TLS SNI and certificate verification.
Service startup migrates retained IP-literal projections before native jobs or
API readiness; Describe does not mutate state.

`testdata/integration/alb_dns.json` proves real UDP/TCP resolution, hostname-based
HTTP and trusted TLS, stable names across SQLite restart, current address changes
after subnet replacement, deletion and survival of an unrelated ALB. Owned
resources were removed. `alb_dns_tls_policy_failure.json` retains the initial
smoke's unsupported default TLS-policy admission and successful cleanup; the
successful workflow explicitly selects the supported TLS policy.
Earlier `alb_create_address_verified.json` records the pre-DNS implementation's
address reservation and actual HTTP across reopen. Its literal-address contract
is superseded, not evidence of current hostname behavior. The isolated-state
IPAM collision in `alb_create_address.json` remains historical.

The relay opens real namespace listener and target sockets. Go's HTTP reverse
proxy supplies ordered host/path/header/method/query/source-IP rules, weighted
target-group forwarding, redirects and fixed responses. Existing
`X-Forwarded-For` values are appended to, not silently replaced. The configured
idle interval applies to activity on client and backend streams, including
already-open connections after an attribute update. HTTP/1 targets may use HTTP
or HTTPS; target certificate verification follows ALB's nonvalidating backend TLS
behavior. HTTPS listeners accept one account-owned IAM or same-region ACM
default certificate and the explicit `ELBSecurityPolicy-TLS13-1-2-Res-2021-06`
policy. Private keys stay in their certificate owner; immutable IDs preserve
binding across IAM rename and ACM renewal. Deleting a currently bound IAM
certificate returns `DeleteConflict`; ACM returns `ResourceInUseException`.
ACM-backed handshakes resolve the current owner material version without
requiring a listener change. [ACM's trust and validation contract](acm.md)
distinguishes real locally signed TLS from public AWS trust.

Idle expiry is HTTP-phase aware: a connected target that stalls before headers
produces HTTP504, and inactive incomplete client headers/uploads produce HTTP408
when an HTTP response is possible. Once response headers are sent, a stalled
stream is aborted rather than receiving a second invented response. TLS handshake
traffic and HTTP plaintext are tracked separately. Health probes use their own
configured timeout, independently of the forwarding idle interval.

Real HTTP probes implement initial admission, failure/recovery thresholds,
unhealthy fail-open and unused-target reasons. Versioned observations cannot
admit a replaced task/ENI. Deregistration excludes new requests immediately while
existing requests may finish until their retained drain deadline. Slow probes
run outside the shared scheduler gate. ECS replica deployments retain immutable
target bindings, register actual task private IPs, gate rollout on target health
and drain before native process/ENI removal. Even while draining, current
SG/NACL authority is refreshed; failure stops the native process without
discarding the outstanding target cleanup obligation.

### Request metrics and ECS target tracking

The ALB source retains minute request/response observations in its typed
repository. Target admission records `RequestCount` once a current target has
been selected, including failed target connections and target HTTP errors.
Health probes, fixed responses, redirects and requests rejected before selecting
a target do not increment it. Actual target responses, ELB failures, connection
failures and response-header latency supply their corresponding source metrics.
Neither target network effects nor response streaming runs inside a transaction.

`RequestCountPerTarget` uses healthy registered targets as its denominator,
falling back to non-draining registered targets when none are healthy.
Deregistered/draining targets are excluded. Its meaningful statistic is `Sum`,
unit `None`, not the `Count` unit used by ordinary request counters.
Live-node sampling emits zero request counts for idle registered targets,
including an all-unhealthy group; an empty group does not manufacture samples.
Health gauges retain node observations for `Average`/`Minimum`/`Maximum`.
Target-group dimensions use ARN suffixes. Request-per-target supports target
group alone or load-balancer/target-group, with optional **target** availability
zone; health gauges use load-balancer/target-group, optionally target zone.
Ingress relay placement does not rename a target's zone.

Completed windows publish through the existing CloudWatch source `Publish`
interface and are removed in the same shared transaction. A controller restart
or logical load-balancer deletion cannot erase already accepted observations.
After a pause, health sampling resumes from current native nodes rather than
inventing historical health windows. No caller `PutMetricData` permission,
synthetic API request or second telemetry delivery framework is involved.

The existing Application Auto Scaling ECS owner consumes this source through
ordinary managed CloudWatch alarms and current service-linked-role capacity
commands. `ALBRequestCountPerTarget` admission requires a syntactically shaped
resource label whose target group is currently attached to the ECS service.
Native AWS accepts a well-shaped missing load-balancer component for an attached
group; admission therefore does not invent an extra ALB-existence check.
The high alarm is `Sum`/60 seconds/three periods at the target; the low alarm is
fifteen periods at 90% of the target, both with unit `None`.

Native calibration establishes stable-window denominators and meaningful sums,
not AWS's internal per-node `SampleCount` or unsupported summary statistics.
Sub-minute denominator changes remain a `TODO: Comeback` calibration boundary;
the local coordinator normalizes each admitted request using current health.
The existing distributed health-consensus limitation also remains.

### Exercised evidence

- `testdata/aws/elbv2/target_group_native.json` retains successful native
  creation/idempotency, real subnet/outside-VPC target admission, unused health,
  unregistered health and exact deletion observations.
- `alb_native_success.json` retains an actual native ALB returning HTTP201 for
  path/header conditions, HTTP302 redirect and HTTP202 for combined
  host/query/method/source-IP conditions. Its immediate post-admission TLS
  connection failures are retained, not represented as successful TLS proof.
- `alb_native_tls_identity.json` separately records real HTTPS200 before and
  after successful IAM certificate rename, unchanged certificate ID, the original
  listener certificate ARN and native bound-delete conflict. Cleanup proves
  exact LB, certificate and security-group absence after managed ENIs disappear.
  These AWS CLI captures do not include response request IDs; resource/time
  correlation is not exact-request CloudTrail correlation.
- `management_audit.json` separately joins all 15 native SDK request IDs to
  management events, including missing-resource errors, target registration,
  health, tags and attribute changes. The sole unattached native target group
  was deleted and its absence verified; no ALB, compute or network was created.
  Fixture replay through signed SDKs on memory and SQLite, including reopen,
  preserves field presence, generated API version and current attribute values.
  `testdata/integration/elbv2_audit_runtime.json` retains the actual executable's
  17 before-fix differences and zero after-fix differences across those requests.
  Creation and idempotent creation now omit association lists in their public
  responses; subsequent descriptions retain them. The ordinary generated audit
  projection consumes that authoritative output, without a second omission rule.
  Attribute readback includes the captured fixed defaults; non-default advanced
  changes remain explicit errors, not a claim of DNS or advanced routing support.
- The actual local CLI, official signed Go SDK and two real ECS HTTP containers
  exercised round-robin forwarding, fixed/redirect rules, one/all unhealthy
  transitions, fail-open forwarding, recovery, health-gated blue-to-green
  replacement, and current IAM denial/grant/revocation and regional isolation.
  Explicit ECS health grace keeps deliberately unhealthy calibration backends
  alive; ordinary replica health replacement is not disabled in the service.
- Same-file SQLite CLI restarts preserved the exact ECS task/container identities
  and actual TLS certificate serial after IAM rename and reuse of the old ARN.
  Bound deletion remained denied, while deleting the unbound replacement
  succeeded. Scale-to-zero let an admitted two-second HTTP response finish before
  target, process and ENI removal. Exact-owned ALB/ECS containers and the VPC
  bridge were absent after public API cleanup.
- An actual CLI/native-socket workflow reproduced EOF instead of HTTP504 from a
  connected stalled target. After correction it observed HTTP504, incomplete
  header/upload HTTP408, and a truncated post-header stream without a second
  response. Three-second download and upload activity survived the one-second
  idle setting; an attribute update applied to an already-open native connection.
  HTTP and TLS regressions also cover an incomplete TLS handshake and graceful
  cleanup of a timed-out request body.
- A separate real HTTP socket workflow observed weighted forwarding 2:6 and
  preserved/appended forwarding headers. Slow-probe/drain and byte-stream
  inactivity regressions exercise the corresponding boundaries.
- The first local workflow used an unfinished schema228 draft. Its throwaway
  database received the new certificate-ID column before the final-schema
  restart; this is **not** released-schema upgrade evidence. Subsequent restart
  used the unchanged final schema. Separately,
  `testdata/integration/compute_services_upgrade.json` records the ordered
  schema225→228 integration: the same real ECS container, PID and start time
  survived migration and another controller restart, with actual private HTTP,
  retained IAM/SSM/EventBridge/CloudFormation/SQS/EIP state and clean deletion.
  New SSM document and zero-target command transitions ran on schema228;
  all three controllers exited normally.
- `testdata/integration/elbv2_runtime_workflow.json` exercises the assembled
  schema228 executable with a real ECS replica and native ALB: healthy IP target,
  public HTTP200 backend forwarding, HTTP201 fixed rule, identical task/container
  after controller restart and HTTP408 for an incomplete request header.
  Its first teardown incorrectly equated desired-status list omission with
  completed task termination. The retained recovery waits for actual `STOPPED`
  and ENI retirement before deleting dependencies; exact native task, ALB and VPC
  bridge absence then passed, with all three controllers exiting normally.
- Native adapter proofs exercised public DNAT/SNAT, route revocation, private
  flow preservation, current SG/NACL denials, same-container callback recovery,
  relay restart and exact Docker/policy/route cleanup.
- `testdata/aws/elbv2/metrics_scaling_native.json` retains bounded real native
  traffic, SDK request IDs and exact-ID management events. Twenty-four target
  requests, including twelve HTTP500 responses, produced request count 24 and
  request-per-target sum 12 with two healthy targets. Adding an unhealthy target
  preserved the healthy denominator (12/2 = 6). Deregistering both healthy targets
  while the remaining target refused connections produced eight HTTP502s,
  request-per-target sum 8 and eight target connection errors: draining targets
  did not inflate the fallback denominator. Idle healthy/unhealthy groups emitted
  zeros, while the never-registered group emitted no metric data. Dimension
  queries distinguish target zone from ingress zone and retain native health
  gauge observations. Its audit contains 82 matched events and no missing
  requested management IDs.
- `testdata/aws/applicationautoscaling/alb_policy_bound_native.json` retains real
  ECS target binding, native accepted/rejected resource labels, managed alarm
  configurations, exact-ID management events and successful cleanup calls.
  `alb_policy_native.json` preserves an earlier probe helper keyword-collision
  failure and its cleanup; it is not successful policy evidence.
  `testdata/aws/elbv2/create_bound_native.json` separately retains an exact-ID
  idempotent target-group creation while bound: the public result and native
  management event omit `LoadBalancerArns`.
- `testdata/integration/alb_metrics_scaling_workflow.json` records actual assembled
  executable/Docker HTTP, twelve real requests retained across controller restart,
  unchanged task/container PID and start time, and native-policy fixture replay.
  Repeated real request windows drove ordinary CloudWatch alarms and ECS
  scale-out from one to two healthy replicas; idle windows drove scale-in to one,
  draining and actual `STOPPED` tasks with deleted ENI attachments. Public API
  cleanup then proved task/ALB ENI retirement and exact native container/network
  absence. Both controllers exited normally. The same run observed twelve
  streamed chunks under a one-second idle setting and incomplete-header HTTP408.
  `alb_metrics_scaling_initial.json` and `alb_metrics_scaling_readiness.json`
  preserve earlier smoke failures caused by treating retained target health as
  proof of native ALB reattachment or DNS readiness. Both cleaned up exactly.
  The final workflow waits for actual HTTP after restart and retains transient
  connection refusals/HTTP503 rather than claiming uninterrupted availability.

The [Route 53/ACM executable workflow](../testdata/integration/route53_acm_smoke.json)
adds actual UDP/TCP alias resolution, locally trusted ACM HTTPS on a native ALB,
SQLite/controller restart and renewed material on an unchanged listener.
OpenSSL verifies the exact current leaf, hostname and chain at service time.
Wrong alias-zone IDs and deletion of the in-use certificate are rejected.
Managed DNS names cannot be shadowed by a customer-created hosted zone.
All exact-owned native nodes and resource dependencies were removed.

Remaining boundaries include distributed per-zone selection, full native cipher
preference, multiple/SNI certificate lists and mTLS, authenticated
actions, HTTP2/gRPC/IPv6, stickiness, advanced attributes, access logging, remaining
ALB metric families and Classic/NLB/Gateway Load Balancers.
The initial health coordinator selects an associated node rather than emulating
AWS's distributed health consensus. Local public routing is not Internet
advertisement. The metric calibration used one owned `t3.micro` and one ALB in an
existing VPC, without changing existing network policy. The first cleanup helper
failed after scalable-target removal; exact cleanup-only recovery observed the
instance terminated and ALB, owned ENIs, security group and root volume absent by
2026-09-27 04:48:05 UTC. The failure and successful recovery remain in the capture.

Primary semantics:
[listener rules](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-rules.html),
[health checks](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html),
[target-group attributes](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-target-group-attributes.html),
[idle timeout](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/edit-load-balancer-attributes.html),
[HTTP timeout outcomes](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-troubleshooting.html#load-balancer-http-error-codes),
[forwarded headers](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/x-forwarded-headers.html),
[HTTPS policies](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html),
[ALB metrics](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html),
[predefined scaling metrics](https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredefinedMetricSpecification.html),
and [ELBv2 authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_elbv2.html).

## Resource Groups Tagging API

The generated `resourcegroupstaggingapi` frontend uses the `tagging` signing
namespace and `tag:*` IAM actions. Inventory reads the existing typed resource
owners; there is no second authoritative tag database. Discovery spans current
EC2/EBS, messaging, storage, compute, identity, analytics and engine-backed service
resources, including SES identities/configuration sets, AppConfig and Config owners.
Missing native resource families are not invented merely because the Smithy frontend models them.

`GetResources` excludes never-tagged resources, including explicit
`ResourceARNList` lookups, but retains live previously-tagged resources with
`Tags: []`. Schema 233 retains only membership (and report work), never copied tag
values. Native successful management writes reconcile their own service's
membership within the same transaction as resource state and API completion;
reads do not need the resource service's list permissions. Deletion removes
membership when its owner publishes the transition. Native updates are visible
immediately locally; AWS's independently observed indexing lag is not a promise
of identical propagation timing.
Config's four taggable resource families use the same owner transaction and
current native authorization. Its generated CloudTrail source is corrected from
`configservice.amazonaws.com` to request-matched native `config.amazonaws.com`;
the source also selects Config for membership reconciliation. See
[Config tag contracts and calibration boundaries](config.md#resource-tags-and-shared-discovery).

Resource/tag filters, sorted cursor pagination, the 15-minute service-clock token
expiry, explicit-ARN/filter/pagination exclusions, reserved `aws:` tags and
per-resource mutation failures are enforced. `TagResources` and `UntagResources`
call native owner commands with the original caller's current authority, including
dependent service permissions and S3 read/merge/write admission. One rejected
resource cannot roll back a successful sibling's tags. Global IAM/Organizations
and CloudWatch dashboard history is not fragmented by endpoint Region; S3 buckets
remain scoped to their actual bucket Region despite Region-less ARNs.

`IncludeComplianceDetails` evaluates the Organizations owner's **published**
effective policy: key case, allowed value wildcards and
`report_required_tag_for`. It does not recompute policy inheritance or bypass
Organizations publication deadlines. Organization-wide summaries/report admission
consume real management-account membership, enabled tag policies, trusted access
and enabled Regions. Required-tag CloudFormation aliases come from the published
AWS supported-resource mapping, not guessed capitalization.
Summary filters are OR within each dimension and AND across dimensions; grouping
can use an account, OU or root target. Global resource ARNs are counted once per
account and reported in `us-east-1`. These are owner-backed evaluations at query
time, not a simulation of AWS's daily compliance cache.

Reports retain asynchronous intent/status in the shared store and run on the
shared service clock. Delivery uses actual S3 objects, existing encryption/KMS
handling and the accepted caller's **current** authority forwarded via
`tagpolicies.tag.amazonaws.com`; this is not an invented service identity.
Native S3 failures remain failed reports. Organization policy or IAM changes are
not silently replaced with empty compliance results.
Reports retain the accepted caller metadata and delivery outcome, not copied
resources or report bytes. Cancelled delivery resumes after a fenced one-minute
lease; completed status becomes `NO REPORT` after 90 service-clock days. The CSV
uses AWS's seven report columns, including uppercase compliance booleans.

Native SSM document tag commands now share the document owner with document
creation and IAM resource/request-tag conditions; Parameter Store remains its
separate typed owner. CodeBuild fleet tags use native `UpdateFleet` against the
real fleet owner. Tag replacement and overflow behavior updates are supported;
changed capacity, compute/environment type, role, image, and supplied custom
compute/proxy/scaling/VPC updates return `InvalidInputException` rather than
pretending an unimplemented fleet replacement occurred.

AppConfig discovery uses the same owner snapshot for tagging and Resource Groups.
Native Tagging API `appconfig:application` filters include nested environments and
profiles, while Resource Groups keeps their distinct CloudFormation types.
Extension tags use the exact versioned ARN, never an unversioned alias.
`testdata/aws/resourcegroupstaggingapi/appconfig.json` retains free control-resource
and extension/association captures, dependent mutation reflection, version
isolation, terminal untagging and exact-owned cleanup. Its extension capture
retains the initial incomplete cleanup and successful version-specific recovery;
deleting an extension without a version removes only its latest version.
See [AppConfig shared discovery](appconfig.md#shared-tag-discovery) for verification
and the native capture's resource-type limits.

### Native observations and executable checks

- `testdata/aws/resourcegroupstaggingapi/controls.json` captures 29 native
  observations over one exclusively owned free EC2 key pair, SQS queue and two
  standard SSM parameters. Explicit lookup excluded the never-tagged parameter;
  native removal of the last tag retained the previously-tagged parameter.
  Mixed mutation updated all three live native stores and returned
  `InvalidResourceId` for the absent parameter. Reserved tags and incompatible
  request options were rejected. All four resources were deleted and absence
  checked; no EC2 instance or standing identity/policy was changed.
- `boundaries.json` retains signed admission and read-only governance controls.
  An empty tag map and empty filter key produced `ValidationException`; an
  unknown syntactically valid resource type produced an empty result. With
  native trusted access disabled, `GetComplianceSummary` and
  `DescribeReportCreation` returned `ConstraintViolationException`, while
  `ListRequiredTags` returned the actual empty required-tag list.
- `dashboard.json` resolves the current documentation's alarm-only mutation
  boundary: native CloudWatch dashboard tagging succeeds and RGTA explicit
  discovery returns those tags, but RGTA mutation rejects the global dashboard
  ARN with a whole-request `InvalidParameterException`. The empty owned
  dashboard was deleted and native absence confirmed.
- `ssm_documents.json` records 17 native observations against one owned inert
  Command document. Overwrite, empty values, owned-ARN lookup, reserved-key and
  51st-tag rejection, idempotent missing-key removal and missing-resource errors
  are retained. The document was never executed; deletion and native absence
  were checked.
- `codebuild_fleets.json` preserves five free signed absent/malformed-ARN
  controls. Missing updates, including reserved or empty tag keys, returned
  `ResourceNotFoundException` before tag validation; malformed ARN returned
  `InvalidInputException`. No native fleet or reserved capacity was created.
- `integration/resource_tagging_ssm_documents_test.go` replays the native
  document controls through the shared SSM frontend and checks current IAM,
  native/tagging round trips and history after SQLite reopen.
  `integration/resource_tagging_codebuild_fleet_test.go` exercises tag updates on
  actual local Docker fleets, requiring the caller to select an installed
  linux/amd64 image with `STACKD_CODEBUILD_FLEET_TEST_IMAGE`; it does not create
  billable native AWS fleets.
- `integration/resourcegroupstaggingapi_test.go` replays selected observations
  through signed official SDKs, exercises EC2/SQS/SSM native round trips,
  current/dependent IAM denial, filters/cursors, account/Region isolation,
  previously-tagged state and memory/SQLite replacement. Its KMS regression
  covers native create-with-tags followed immediately by untagging before
  inventory reads, requiring API completion to observe flushed key state.
- `scripts/aws/resource_tagging_executable_smoke.py --binary bin/stackd
  --state-directory /absolute/fresh/owned-directory` runs real AWS CLI calls
  against the executable, observes native→inventory and inventory→native tags,
  mixed dependent-IAM success/current denial, and reopens SQLite to check history
  and explicit delete/recreate behavior. It also creates local Organizations tag
  policy state, reads actual summary/required tags, downloads the native
  KMS-encrypted S3 CSV, retains current-authority delivery failure across restart,
  and rejects a wrong-Region destination. It never uses ambient AWS credentials.
  Exercised on 2026-09-27 against `bin/stackd-services235-smoke`: the corrected
  [retained executable evidence](../testdata/integration/resource_tagging_verified.json)
  passed all assertions and three controller exits were zero. The original
  `/tmp/stackd-tagging235-smoke-b/compliance.csv` is the actual 315-byte
  downloaded object; native GetObject metadata reports `aws:kms`, and the SQS
  row is noncompliant for `workflow`. Summary counted that one queue and required
  tags resolved `AWS::SQS::Queue`. Current `s3:PutObject` denial became `FAILED`
  and survived reopen. The first attempt's CLI-only GetObject argument failure
  and successful cleanup remain in `/tmp/stackd-tagging235-smoke-a/`; the shared
  CLI helper now passes that command's required bucket/key options explicitly.
  Both attempts removed owned resources and scheduled local KMS key deletion
  with its native seven-day waiting period.

These captures calibrate the named behaviors, not exhaustive service parity.
Signed replay results are reported separately by the combined verification gate;
source presence alone is not successful execution evidence. Native organization-wide
reports were not generated by changing standing AWS organization policies.

Primary references:
[GetResources](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_GetResources.html),
[TagResources and dependent permissions](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_TagResources.html),
[supported resource boundaries](https://docs.aws.amazon.com/pdfs/resourcegroupstagging/latest/APIReference/resourcegrouptagging-api.pdf),
[organization-wide evaluation and S3 caller authority](https://docs.aws.amazon.com/tag-editor/latest/userguide/tag-policies-orgs.html),
[report creation](https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/API_StartReportCreation.html),
and [required-tag supported-resource aliases](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_supported-resources-enforcement.html).
AWS's [published CSV example](https://media.amazonwebservices.com/blog/2019/tag_report_1.png)
establishes the exact report headers.
The native owner contracts are
[SSM document tagging](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_AddTagsToResource.html)
and [CodeBuild UpdateFleet](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_UpdateFleet.html).

