# CloudTrail history and trail delivery

> In native capture references, `000000000000` is an anonymized account alias,
> not the AWS account originally used. See [capture privacy](behavior-references.md#publishing-sanitized-probe-captures).

CloudTrail uses generated AWS JSON bindings, typed trail repositories and the
shared transactional API journal. The current path includes management-event
history, account and organization trails, basic/advanced selectors, real S3 log objects,
CloudWatch Logs delivery, SNS log-file notifications and eligible API events on
EventBridge's default bus. These are partial service
implementations, not a claim of complete CloudTrail or S3 parity. **CloudTrail
Lake is explicitly excluded.** Its generated operations remain recognizable and
return unsupported protocol errors.

## History and API producers

`LookupEvents` is available without a trail. It selects management records in the
caller's partition/account/requested region over the preceding 90 days of service
time. It supports the eight AWS lookup attributes, one attribute per query,
inclusive time bounds, 1–50 results and newest-first ordering. Commit sequence
breaks equal-time ties. Tokens bind the scope, query window and committed prefix;
subsequent writes cannot shift an existing traversal. Old journal records are not
physically removed when they leave the history window. Publication delay and
per-account/region lookup throttling remain open.

Implemented services contribute source-owned API outcomes through the shared
recorder, including ECR, CodeBuild, Glue and Athena. Wiring is not per-operation
conformance; the evidence and unresolved boundaries below remain service-specific.
SQS encryption, EventBridge target sends, service execution-role assumptions and
CloudTrail S3/Logs/SNS effects use their actual commands, not a second request logger.
Private provisioning and background state changes do not fabricate public calls.
EventBridge archive/replay commands emit native management projections, while
internal archive ingestion and replay admissions do not invent public PutEvents.
`eventbridge_archives_replays.json` retains 89 source-owned audit observations:
creation/replay timestamps use native date-time strings; specific missing-source
failures use UnknownError; captured CreateArchive/StartReplay authorization
denials omit request parameters and apiVersion. KMS archive effects use audited
DescribeKey/GenerateDataKey/Decrypt operations outside archive transactions.
Organizations job-result `AwsServiceEvent` records remain separate unfinished work.

| Source | Classification and native distinctions |
| --- | --- |
| IAM | Management; explicit read and response-presence sets, policy-string representations and modeled error names. |
| STS | Management; `GetSessionToken` and `GetFederationToken` are writes, while `AssumeRole` is read-only. Federation, IAM cross-account caller/recipient records and service-role recipient records are distinct. |
| KMS | Management, including cryptographic calls. `Encrypt`, `Decrypt` and data-key generation are read-only; cryptographic outputs are suppressed. Retained SNS live decryption preserves the original caller and current authorization. SNS-forwarded audit is producer-specific: EventBridge/CloudWatch/S3 identify SNS, while CloudTrail validation and asynchronous notifications retain CloudTrail. See [forwarded audit evidence and limits](sns.md#encrypted-topic-publication-and-retained-delivery). |
| Account / Organizations | Management; source-owned field casing, public-field selection and response presence. Organizations lookup aliases are independent of its native organization resource. |
| SQS | Twelve documented data operations, including queue reads and receives; the other implemented operations are management. A batch produces one outcome; a long poll records only its final result. |
| S3 | Bucket controls are management; object calls and listings are data. `ListObjectsV2` retains native `ListObjects` spelling. |
| EventBridge | Public `PutEvents` is one data outcome per batch, including partial failures; private bus forwarding does not invent another call. Other implemented commands are management. Native `apiVersion` is retained. |
| Lambda | Versioned management event names; `Invoke` is data, and asynchronous execution records a separate service-principal `InvokeExecution` with shared correlation. |
| Logs | Captured management controls retain native version, request/response presence, resource identities, LookupEvents names and federated issuer context. `TestMetricFilter` and captured denials omit request contents; modeled and semantic subscription rejections differ in resource presence. `PutLogEvents` and legacy tag mutations are not inferred to be audit events. Runtime output remains separate Logs data. See [native Logs evidence and boundaries](logs.md#native-management-audit). |
| CloudWatch | Four implemented metric operations are data events with type-only `AWS::CloudWatch::Metric` resources; measurements are omitted. Twelve alarm/tagging operations are management events without invented resource entries. Both retain null response elements. See [native metric/alarm audit evidence](cloudwatch.md#native-audit-classification-and-projection). |
| SNS | Standard-topic management projections and Publish/PublishBatch data classification. Fourteen management records and one PublishBatch record have exact native request correlation; whole publication attributes are redacted. See [SNS audit evidence and limits](sns.md#api-observations). |
| EC2 | Networking management projections preserve native XML-name/set envelopes and `Client.` error codes. VPC default-resource creation/deletion also emit distinct `AwsServiceEvent` records. See [EC2 evidence and delivery boundaries](ec2.md). |
| ECS | Cluster/task-definition controls are management events; environment values are redacted, reads/errors have null responses, and captured rejected execution requests have null parameters. Recognized unsupported requests also retain failure outcomes. See [ECS evidence](ecs.md). |
| ECR | Captured management events have operation-specific response and repository-resource presence. Repository resources can omit `type`; credential/download responses are null. `PutImage` retains its manifest, while layer-upload bytes are omitted. |
| CodeBuild | Captured project mutations retain responses and ARN-normalized names. Buildspecs, environment-variable member strings, tags and encryption keys are masked; native source-auth resource selectors remain visible, including on rejected requests. |
| Glue / Athena | Selected native management controls, errors and assumed-role context are replayed on memory and SQLite. Glue request defaults and mutation resources follow captured records; Athena masks SQL. Ordinary Glue catalog calls are not Lake Formation table data events. |
| OpenSearch / legacy ES | Configuration APIs are management events from `es.amazonaws.com`, preserving the actual API operation name. Exact-request-ID fixtures cover absent-domain/validation/IAM-rename failures and empty listings. Denied events use `AccessDenied` with null parameters; missing-domain deletions retain `isElasticsearchDomain: true` despite HTTP 404. Native search/index/bulk requests are not CloudTrail data events. Successful managed provisioning/configuration/tag projections remain uncalibrated; see [OpenSearch evidence](behavior-references.md#opensearch-engines-evidence-and-boundaries). |

Authenticated generated-input failures and IAM credential restrictions use the
same source projections. Pre-authentication/signature failures, early body/checksum
rejections and unimplemented operations do not have universal audit coverage.
Domain acceptance facts alone are not CloudTrail API records.

`internal/apievents.Recorder` owns public caller/session identity and ordinary
completion-ID allocation. A source can reserve its event ID before an independent
service call so the child outcome retains its causal parent. Successful source
mutations commit their outcome with state. Failed source mutations roll back;
their error outcome is recorded separately. Signing secrets, session tokens,
object payloads and private encryption material never enter these projections.
SQS cancellation and Lambda synchronous completion have bounded post-command
recording independent of client disconnection. This never detaches a mutation's
native transaction. The canceled-receive regression verifies local persistence,
not a native AWS cancellation fixture.

Generated shape traversal is shared with the wire encoder. Services declare
field omission, redaction, names, JSON policy documents and timestamp formats;
map keys are not case-folded. Response presence is independent of read-only
classification. STS session tokens remain deliberately omitted even where native
CloudTrail includes them. Signing secrets, blobs and customer payloads are not
made safe merely by an upstream sensitivity trait.

`internal/apievents.CloudTrailRecord` is the single native-document projection for
history, gzip records and EventBridge detail. Lookup aliases are separate from
native `resources`: S3 object resources use `ARN`, while `ListObjectsV2` is recorded
as `ListObjects` and uses an object `ARNPrefix`. Native S3 resources retain bucket
ownership separately from the caller. Read response presence remains source-owned;
successful S3 `PutObject` retains the observed SSE response field. Additional data includes
known object size/status/encryption facts, not fabricated TLS or AWS latency.
Local transfer counters are not a reproduction of AWS transport overhead.

EC2 VPC service-generated records carry the EC2 service actor, source-owned
`serviceEventDetails`, and default-resource ARNs without inventing separate
customer CreateSecurityGroup/CreateRouteTable/CreateNetworkAcl calls. Native
EventBridge/SQS delivery and history share the same captured event bodies.
Their S3 delivery/selector scenario is documentation-backed, not a claim that
the bounded fresh-trail probe observed those particular S3 records.

### Native capture and replay practice

`scripts/aws/cloudtrail_events.py` owns bounded management-history pagination and
actual S3 gzip-record collection for native probes. Callers own resource lifecycle,
authentication and redaction. Response request IDs join calls to complete records;
event IDs deduplicate records without collapsing multiple events from one request.
Owned related events without an exact request ID retain `call_label: null`.
Collection failures retain partial records and provider diagnostics. Missing
records mean **not observed within the stated bounds**, never native non-emission.
`LookupEvents` establishes management observations only, not data-event coverage.

The ECR/CodeBuild captures in
`testdata/aws/cloudtrail/ecr_codebuild_history.json` and
`ecr_codebuild_source_auth.json` retain 68 exact-request native records. The
official-SDK replay in `integration/ecr_codebuild_audit_test.go` exercises selected
ECR repository/image and CodeBuild project/read/error paths on memory and SQLite.
An actual signed embedded-server smoke also exercised rejected-request masking,
native auth-selector retention and ECR response/resource projection.
The owned CodeBuild project and role were removed and absence was observed;
the fresh probe launched no builds.

`testdata/aws/cloudtrail/codebuild_build_history.json` retains 64 exact-request
records harvested from already-cleaned native builds; collection launched no new
AWS builds. Harvest deduplication is by service/request ID, so distinct successful
starts, failures, cancellation and terminal stops are not discarded.
Successful `StartBuild`/`StopBuild` audit responses now combine the generated
Build projection with the command's retained artifact/log configuration, including
overrides. Later project edits cannot change those records. Buildspecs, environment
variable names/types/values, exported variables and encryption keys use the native
masking rules; timestamps use UTC RFC3339.

`testdata/integration/codebuild_build_audit_runtime.json` records the actual
Docker/S3/CloudWatch workflow: exact successful start/terminal-stop response
comparison against native fixtures after binding local identities, timestamps,
the actual runtime phase timeline and physical artifact digests. It also covers
project edits after admission, real ZIP bytes at the native UUID-only `BUILD_ID`
namespace, and no-artifact builds. Native elapsed times and AWS image behavior
are not simulated or asserted identical to local customer execution.
See the primary [artifact location contract](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectArtifacts.html)
and [build initiator contract](https://docs.aws.amazon.com/codebuild/latest/APIReference/API_Build.html).

These captures do not establish exhaustive ECR/CodeBuild audit parity or data-event
absence. Native successful OAUTH source-resource updates are retained as evidence,
while the local runtime rejects that unsupported configuration. Rejected auth
requests are replayed; the successful update is not claimed compatible. See the primary
[ECR](https://docs.aws.amazon.com/AmazonECR/latest/userguide/logging-using-cloudtrail.html)
and [CodeBuild](https://docs.aws.amazon.com/codebuild/latest/userguide/understanding-service-name-entries.html)
CloudTrail contracts.

`testdata/aws/cloudtrail/service_controls_delivery.json` retains 21 exact-request
Glue/Athena management records, including reads, mutations, modeled failures and
an assumed role with source identity. `integration/analytics_audit_test.go`
replays the selected controls with official SDK clients on memory and SQLite.
Glue `GetDatabase` supplies `federateToSource: false`; successful database/table
mutations retain native resource lists and table requests retain native defaults.
Read operations do not acquire invented resource lists.

The first native read/write trail campaign processed 343 records from ten gzip
objects but observed none of its 32 workload request IDs within fifteen minutes.
Its final history call failed with a closed connection; a fresh bounded history
collection recovered all 21 Glue/Athena management records. Both facts are retained,
not interpreted as data-event absence or positive data-selector conformance.
All owned native resources were deleted. The replacement workflow establishes
positive exact-request trail delivery before starting the measured workload.

`scripts/aws/cloudtrail_service_probe.py` drives the SDK inputs in
`testdata/cloudtrail/audit/service_probe_cases.json`. Its readiness-gated capture,
`testdata/aws/cloudtrail/service_selectors_delivery.json`, observed all 32 workload
requests: 11 S3/SQS data records and 21 Glue/Athena management records. Twenty
records reached the read prefix and twelve the write prefix; history separately
matched all 21 management requests. Both collections retained complete records,
including uncorrelated owned readiness activity. Both trails and all other owned
resources were deleted without cleanup errors.

Run the authorized native workflow with:

```sh
env PYTHONPATH=scripts/aws python3 -B -P scripts/aws/cloudtrail_service_probe.py --account YOUR_12_DIGIT_ACCOUNT_ID \
  --output /tmp/cloudtrail-services.json --wait-seconds 900
```

Separately, `testdata/integration/cloudtrail_service_audit_runtime.json` records an
actual local CLI workflow: 32 signed S3/SQS/Glue/Athena operation records delivered
through separate read/write gzip objects, denied and missing-resource cases,
assumed-role source identity, and a real Trino query returning `7`. After SQLite
process restart, all 32 records and 21 management request IDs remained unchanged
and the query result remained readable. Owned local resources and both Trino
execution containers were removed. The eleven native data cases agree on
classification, operation/source, request/response fields, resources and error
codes after binding owned names, actual endpoints and generated identifiers.
SQS message-body digests agree without normalization. Diagnostic wording,
transport-specific fields and timing details are retained but not claimed
identical.

Primary contracts: [Glue](https://docs.aws.amazon.com/glue/latest/dg/monitor-cloudtrail.html),
[Athena](https://docs.aws.amazon.com/athena/latest/ug/monitor-with-cloudtrail.html),
and [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html).

Lambda's nine layer operations use the native `20181031` event-name suffix:
`PublishLayerVersion`, `GetLayerVersion`, `GetLayerVersionByArn`, `ListLayers`,
`ListLayerVersions`, `AddLayerVersionPermission`, `GetLayerVersionPolicy`,
`RemoveLayerVersionPermission` and `DeleteLayerVersion`. Reads have null response
elements; successful publish retains content metadata, including the observed
`uncompressedCodeSize: 0`, but omits `content.location`. Permission addition
retains its statement and revision. `GetLayerVersion` with an ARN input retains
that exact ARN as a native resource of type `layer`; a short name does not acquire
a synthesized resource. `GetLayerVersionByArn` likewise retains the supplied
version ARN and its owner account. These document resources are not LookupEvents
aliases. `internal/services/lambda/audit.go` and `layer_audit.go` own the projections.

The five SQS event-source mapping controls use `20150331` event-name suffixes,
including Get/List. Mapping UUID request spelling is `uUID`; read responses are
null. SQS-driven `Invoke` data events use the `lambda.amazonaws.com` AWSService
identity, exact runtime request ID, distinct shared event ID and mapping ARN
`sourceArn` (not the queue ARN). Their response is null; additional data retains
the empty customer ENI ID and selected function version. Native control/delivery
captures and real-runtime replay are linked from
[SQS mappings](lambda.md#sqs-event-source-mappings). Ordinary configured trails
deliver these same projections to S3 and Logs; no Lake dependency is introduced.

Function/layer source projections retain the submitted S3 bucket, key, version
and storage mode, and the resolved exact S3 identity where the response includes
it. ZIP blobs and download credentials are not audit payloads; function
environment values remain redacted. CreateFunction uses
`CreateFunction20150331`, and code updates use `UpdateFunctionCode20150331v2`.
The retained source-creation AccessDenied audit discrepancy remains unresolved;
local error outcomes are not suppressed to imitate a bounded native absence.

CloudTrail's Smithy models omit read-only traits on these controls. Their native
classification is source-owned, not inferred from a method prefix. Native
`LookupEvents` audit parameters use second-resolution ISO timestamps even when
its HTTP input contains fractional epochs. IAM modeled error names are also
projected deliberately: `NoSuchEntity` on the wire becomes
`NoSuchEntityException` in the audit record.

IAM capture currently retains the request region. Global IAM endpoint-to-history
region routing remains open; native IAM captures use `us-east-1`.
Trail region selection also applies to global-service activity: a single-region
trail in another region cannot capture it merely by enabling
`IncludeGlobalServiceEvents`. Regional STS calls are not global events; known
global STS endpoints retain native request details.

The gateway accepts the two observed CloudTrail target prefixes:
`CloudTrail_20131101` and
`com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101`. Neither alias changes
the signed header; unrelated namespaces and post-signing alias changes fail.

### Service-role assumptions

The shared service-role authority records successful `AssumeRole` issuance in the
same IAM transaction as its credentials. A failed audit append cannot publish a
usable credential. The customer record belongs to the **role account**, with
`userIdentity.type=AWSService`, `invokedBy` naming the service and a shared event
ID. The triggering resource's account is trust context, not a second caller
account. Ordinary IAM-user cross-account assumptions still have their distinct
caller and recipient projections.

Denied service assumptions do not fabricate customer-account STS records.
AWS [does not log denied cross-account STS requests in the target account](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html#cloudtrail-integration_apis).
The owned EventBridge capture used five disjoint rules created by one account on
another's bus. Both accounts' completed history queries found the three successful
assumptions only in their respective role accounts, with AWSService identities;
the two trust failures produced actual EventBridge DLQs but no customer STS
record. `testdata/aws/eventbridge/bus_forwarding.json` retains those exact records
and scope. Reusing one target across immediate role updates was confounded by
propagation and is not used as the trust-context oracle.

`testdata/aws/eventbridge/role_audit.json` contains native S3 records and a separate
STS history supplement. Assumptions use one-hour duration and opaque target-stable
session names. Actual SQS sends retain the assumed-role/session-issuer identity
and `invokedBy=events.amazonaws.com`; their canonical queue URLs, message IDs and
MD5s correlate with delivered messages. Bodies remain redacted. Source
`PutEvents` records remain distinct from typed bus forwarding, which creates no
synthetic public call. Native data selectors covered source/destination buses and
queues; the local replay also selects management events to deliver STS records
to S3. This is not a claim of an exact AWS credential-cache lifetime.

## Trails and selectors

The current controls are `CreateTrail`, `UpdateTrail`, `DeleteTrail`, `GetTrail`,
`DescribeTrails`, `ListTrails`, `StartLogging`, `StopLogging`, `GetTrailStatus`,
`GetEventSelectors`, `PutEventSelectors`, `AddTags`, `RemoveTags`, `ListTags` and
`LookupEvents`. Trails retain immutable incarnation IDs, home region, bucket/key
prefix, global/multi-region flags, tags, selectors and logging state. Writes use
the home region; read projections include multi-region shadows. Identity and
resource-tag authorization use the shared IAM evaluator.

Basic selectors retain management inclusion, read/write selection, excluded
management sources and data resource prefixes. Advanced selectors replace the
basic set. Selectors are ORed; fields within a selector are ANDed. Positive tests
within a field are alternatives; matching negative tests veto the field. Native
resource identities—not LookupEvents search aliases—drive resource conditions.
The service enforces selector limits and validates resource types against the
179 values generated from both AWS's CloudTrail table and EventBridge's service
table. The latter supplies event bus, endpoint and partner-source types missing
from the general table. Recognition does not imply an implemented producer.

For `AWS::Lambda::Function`, advanced `resources.ARN` `Equals` and `NotEquals`
require an unqualified function ARN. Native CloudTrail rejects version, alias
and `$LATEST` qualifiers, as well as invalid function-name characters. Prefix
operators remain literal string predicates: even a qualifier-shaped prefix is
accepted, although it cannot match an unqualified event resource.

`cmd/cloudtrailgen` refreshes that vocabulary from the primary documentation.
Repeat `-source` for each captured HTML input when working offline. Its dedicated
refresh/check commands require those sources; normal offline generation checks
do not fetch the web pages. Account's upstream event-source placeholder is
corrected by the existing reviewed Smithy correction manifest using native evidence.
Get selector output sorts advanced fields as observed natively; Put preserves the
submitted order. Network-activity selectors, console-session-specific fields and
Lake selectors are not implemented.

### Desired status and effective admission

`StartLogging` enables admission. `StopLogging` immediately reports
`IsLogging=false` but retains a stop deadline for **two service-time minutes**.
Repeated stops do not extend that deadline or restart a stopped trail. The
deadline survives SQLite reopen. Two minutes is a deterministic emulator choice,
not a measured AWS interval.

The native probe received both `PutObject` and read-only `GetObject` through
EventBridge after StopLogging succeeded and GetTrailStatus returned false. A
subsequent read-only check found no matching selector on the other logging trails
visible in the account. This supports propagation, but the snapshot was not an
atomic record of historical configuration and the exact cutoff was not measured.
The before-start receive window was bounded, not proof of global absence.
Selector replacement currently applies at the local API/event boundary; native
selector propagation timing has not been established.

`RecursiveLogging` defaults to true. False suppresses this trail's capture of
CloudTrail-generated S3 log writes and Logs stream creation. Native signed
Update/GetTrail calls retain both boolean values.
AWS CLI 2.36.28 omits the field from decoded output because its older model lacks
it; that omission must not remove the field from the server's current SDK output.

## Organization trails

Organization trails belong to the management account, including trails created
by a current delegated administrator. IAM still authorizes each command;
Organizations owns membership, all-features mode, trusted access and delegation,
and Account owns regional opt-in. Member and regional shadows are derived views,
not separately mutable copies. Members cannot mutate the management trail;
only management can convert between account and organization scope. Removing
CloudTrail trusted access converts retained organization trails to account trails;
reenabling access does not silently restore their former scope.

IAM owns `AWSServiceRoleForCloudTrail`, its captured trust/policy template and
protected lifecycle. Management creation checks `iam:CreateServiceLinkedRole`
when its role is missing. Delegated creation requires the management role to
exist already. Successful account creation and accepted membership consume the
existing typed Organizations journal boundary to provision member roles in the
same transaction. Departure removes the member role; deletion checks actual
organization-trail dependencies rather than rejecting every organization member.

Retained batches separate source accounts and preserve their selected organization
scope through departure, conversion and SQLite restart. S3 keys use
`AWSLogs/<organization-id>/<account-id>/CloudTrail/<region>/...`; records from
different accounts are not mixed. Existing S3/KMS, Logs and SNS commands retain
their independent delivery/retry paths. For delegated configuration, the Logs
group and delivery role belong to the calling account; the trail and source ARN
remain management-owned.

Successful lifecycle/delivery scenarios are derived from the
[organization trail prerequisites](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-an-organizational-trail-prepare.html)
and [delegated administrator contract](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-delegated-administrator.html).
The executable/SQLite scenario also provisions a member through the public API,
observes its real `CreateQueue` through the member's default EventBridge bus and
SQS target, restarts the process, and then reads the same request from actual
organization-prefixed gzip and CloudWatch Logs delivery.

SDK scenarios exercise both stores, joins/leaves, authority and regional
boundaries, encrypted gzip delivery, Logs/SNS and pending-work restart.
`testdata/aws/cloudtrail/organization_admission.json` is narrower native evidence:
guarded organization/SLR discovery and missing-bucket admission. No successful
native organization trail was created because that could provision standing
member identities. It does not establish native delivery timing or complete
organization conformance. CloudTrail-specific delegated-administrator APIs and
the other remaining non-Lake operations are still separate work.

## Log-file integrity validation

`EnableLogFileValidation` controls real hourly digest delivery, not a response
flag. Each account/Region chain references successfully written log objects and
hashes their uncompressed contents. Digest documents are gzip objects under
`CloudTrail-Digest`, signed with regional RSA keys; S3 metadata carries the
signature and algorithm. `ListPublicKeys` returns the corresponding PKCS#1 DER
and native-style fingerprint. Signing keys survive trail deletion and SQLite
reopen; private material stays in the CloudTrail repository.

Enabled chains emit empty hours, retain exact pending signed bytes on destination
failure, and preserve previous-digest linkage through restart. Stop/disable closes
the current interval; re-enable starts a new chain. Organization scopes use the
same current membership and regional authority as trail delivery. Existing S3
and KMS interfaces own authorization and actual object encryption; signatures
and writes happen outside resource transactions.

The AWS CLI `cloudtrail validate-logs` consumer verified three linked digest files
(starting, log-bearing and empty) and their actual log object against the
executable's SQLite-backed endpoint. Changing one byte of the decompressed log
caused the CLI to report an invalid hash while all digest signatures remained valid.
This independent check caught
and corrected the starting-digest canonicalization: a null previous signature
is signed as the literal `null`, not an empty string.

`digest_admission.json` was recaptured with SDK response metadata, including real
HTTP 204 for S3 bucket-policy updates. It covers rejected digest-prefix access,
unchanged state after a denied enable, marker effects and successful
enable/disable; its owned trail and bucket were independently absent after
cleanup. `digest_public_keys.json` records native key discovery.
`digest_starting.json` records two physical empty linked digests: the starting
interval ends at logging activation and begins one hour earlier; its successor
ends one hour after activation. AWS CLI `validate-logs` accepted both native
objects. The owned trail and bucket were independently absent after cleanup.
Local service time schedules the starting document immediately; this is not a
native delivery latency claim. The native capture did not deliver a selected log
object, so log-bearing native chains, stop propagation and backfill/redelivery
timing remain outside this evidence.

Primary contracts:
[digest structure](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html),
[signature calculation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html)
and [AWS CLI validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html).

## S3 destination and transaction boundaries

`internal/integrations.CloudTrailS3` invokes S3's actual `GetBucketAcl` and
`PutObject` commands through a small consumer-defined interface. It supplies
`cloudtrail.amazonaws.com`, the source trail ARN/account and
`bucket-owner-full-control`. Native preflight condition probes established
`aws:PrincipalType=AssumedRole` for both permissions, distinct from CloudTrail's
`userIdentity.type=AWSService`. The asynchronous log-writer condition value has
not been independently captured.

Preflight writes the native zero-byte marker at
`[prefix/]AWSLogs/account/CloudTrail/`, with `application/json`, `gzip` and SSE-S3
or configured SSE-KMS metadata. It is not a gzip log file. AWS left this marker after failed ACL checks
when PutObject was permitted; failed PutObject checks left none. Accordingly,
preflight S3 calls run **outside the CloudTrail transaction**, and both permission
paths are attempted. Independently successful S3 effects are not rolled back
when CreateTrail fails. CloudTrail's own mutation and API outcome still commit
together. The source API event ID links the independently committed child calls.

Bucket existence, source ARN/account conditions, current resource policy and
ownership/ACL rules are enforced by S3, not duplicated in CloudTrail. Revoked
permissions reject writes rather than producing fake log objects.

S3 [user-defined metadata keys are stored in lowercase](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html#UserMetadata).
The shared Smithy HTTP encoder preserves those keys in prefixed response headers
instead of applying MIME title casing. This matters to clients such as the AWS
CLI that expose the header suffix as the metadata map key. A wire regression and
actual versioned-object CLI reads across SQLite restart cover this boundary.

### Retained delivery and EventBridge

A source API transaction appends its event, evaluates effective trail selection,
and retains event-ID references for each matching trail. Eligible records also
enter the default EventBridge bus once, even when several trails select them.
The EventBridge envelope has its own ID; its detail retains the CloudTrail event
ID and API request ID. Envelope resources are empty while detail resources retain
native identities. Data reads match ordinary enabled rules; read-only management
records require `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`.

Batches retain their destination, object key, immutable trail identity and source
event references. They normally become due after five service-time minutes and
seal at delivery or the local 1,000-record boundary. The worker reads committed
journal records, creates real `{"Records":[...]}` gzip bytes and invokes S3 outside
its claim transaction. Success updates S3 status and either completes the batch or
advances it to its SNS publication stage in the same transaction. S3 failures
retain the fixed object key and event references, backing off from one minute to
a one-hour cap within a 30-day retry window. These intervals are local scheduling
choices, not AWS's exact distributed timing; SNS publication does not inherit them.

A crash after S3 commits but before completion is recorded can retry the write;
there is no exactly-once claim. SQLite reopen retains pending work and deadlines.
EventBridge-to-SQS delivery can likewise repeat a frozen record across restart;
conformance checks admitted identities and unchanged content, not exactly one
receipt. AWS also [documents duplicate CloudTrail events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html).
Deleting a trail removes its pending batches; recreating the same ARN cannot
adopt the previous incarnation's work. Existing accepted batches retain their
captured S3 bucket/prefix across later configuration changes; that particular native
configuration-race behavior has not been captured. Encryption instead uses the
trail's current canonical KMS key at each attempt. Logs replacement/removal
retires the old Logs work and status independently.

AWS's documented delivery cadence averages about five minutes, without a fixed
latency guarantee. The owned probe's first gzip arrived after roughly 6m48s.
Records generated during a revoked-policy phase arrived after restoration. The
bounded revoked phase did not establish AWS's exact retry interval or the time
at which a failed delivery attempt becomes visible in status.

### KMS-encrypted trail logs

`CreateTrail` and `UpdateTrail` accept key IDs, key ARNs, aliases and alias ARNs.
Successful preflight retains the canonical key ARN returned by the actual S3
write. Retargeting an alias alone does not change a trail; explicitly updating
with that alias resolves its new target. Omission retains the configured key;
an empty `KmsKeyId` restores SSE-S3. Rejected updates leave the trail unchanged.
The key must be in the bucket's Region. Bare identifiers expand in the trail's
home Region, so cross-Region buckets require the appropriate full key/alias ARN.

S3 owns data-key generation, object authorization and envelope encryption.
CloudTrail supplies its trusted principal, source ARN/account and
`aws:cloudtrail:arn` context; S3 adds the exact `aws:s3:arn` object context and
regional `kms:ViaService`. Native ordinary preflight succeeded with only
`GenerateDataKey` service permission, even with an explicit `DescribeKey` deny.
There is no extra metadata-read permission gate. Bucket Keys remain unsupported.
Missing well-formed keys/aliases produce `InsufficientEncryptionPolicyException`;
malformed/wrong-Region references produce `KmsKeyNotFoundException`; disabled
keys produce `KmsException`. The S3 adapter preserves KMS error identity internally
without adding wire fields or parsing diagnostic text.

The owned 2026-09-19 captures in `testdata/aws/cloudtrail/` are
`kms_controls_evidence.json.gz`, `kms_precedence_evidence.json.gz` and
`kms_delivery_evidence.json.gz`. Their compact replay files retain source call
sequences and native event IDs. They cover marker effects, canonical key retention,
error precedence and actual encrypted gzip consumers. The control captures include
`us-east-1` trails with `us-west-2` destinations; ordinary delivery used `us-east-1`.
All owned trails, buckets and aliases were removed; owned keys entered verified
seven-day pending deletion.

The delivery capture correlated a source `PutObject` request
`71T4CKBRBQJJN9ZZ` with event `5bfe4c82-7f1f-4d2c-b289-5a86e33d3fbd`.
It was accepted while key A was disabled, then delivered under key B after the
trail changed keys. Pending work therefore does not retain an admission-time
encryption key. `LatestDeliveryError` was exactly `KMS.DisabledException`;
logging remained enabled and the prior success time remained. A later success
cleared the error. Gzip generation and KMS effects stay outside trail transactions;
only the trail owns its configured key.

The first successful gzip arrived after about 476 seconds. The failed-key record
was absent during the initial 1,200-second recovery watch, but arrived later.
Two bucket-denied pre-update records were not captured within the separate
1,202-second post-restore watch. A later gzip appeared during audit collection
and was deleted without decoding; its key B audit does not identify its contents.
These bounds do not establish record loss or exact AWS retry/propagation timing.
The compact delivery replay selects the correlated key transition rather than
reproducing those wall-clock polling windows or claiming coverage of unseen records.

Memory/SQLite SDK replay and the real SQLite executable verify retained failures,
key replacement and decryption after restart. The executable delivered three gzip
records, matched each to its EventBridge/SQS detail, and observed six real KMS
outcomes with exact trail/object context. The older successful object stayed under
A; the pending and new records used B. All local smoke resources were removed.

Primary contracts: [KMS with CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/how-kms-works-with-cloudtrail.html),
[key policies](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html)
and [CLI encryption controls](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-encryption-cli.html).

## SNS log-file notifications

`NotificationDestination` is owned by CloudTrail. Its integration adapter calls
ordinary SNS `Publish`; SNS remains authoritative for topic policies, publication
admission, signing, metrics and subscriber delivery. No CloudTrail transaction
spans those effects, and CloudTrail does not insert directly into subscriber queues.

Create/update accepts a standard topic name or ARN. `SnsTopicName` preserves the
supplied spelling, including a full ARN; `SnsTopicARN` expands bare names in the
trail's home Region/account. A native cross-Region ARN update succeeded. That
control probe did not subscribe to the remote topic, so it is admission evidence,
not a captured cross-Region subscriber delivery.

Omitted update input retains and revalidates the topic. An empty string removes
it even when the old topic now denies publication: Update returns empty SNS
fields, while subsequent Get/Describe responses omit them. Malformed/FIFO
references produce `InvalidSnsTopicNameException` before S3 marker effects.
Missing topics and denied publication produce `InsufficientSnsTopicPolicyException`.
Those valid-reference failures occur after the independent S3 preflight marker;
a rejected update leaves trail configuration unchanged, not the marker untouched.

Successful preflight publishes the actual message `CloudTrail validation message.`
without a Subject. It can reach subscribers before logging starts, but does not
populate log-notification success or attempt timestamps. Native service authority
is independent of the caller's SNS permissions: an assumed caller explicitly
denied direct SNS Publish/GetTopicAttributes still configured the trail and
received the validation message. Preflight policy probes established
`aws:PrincipalType=AssumedRole`, `aws:PrincipalIsAWSService=true` and
`aws:PrincipalServiceName=cloudtrail.amazonaws.com`, with the trail's SourceArn
and SourceAccount. Log-publication condition context has not been independently
captured.

After a successful S3 log write, the retained batch advances to SNS work without
rewriting the object. The message is compact JSON:

```json
{"s3Bucket":"log-bucket","s3ObjectKey":["full/path/log.json.gz"]}
```

There is no Subject. The current implementation publishes one file key per
message; native evidence also contains one key per observed message, not a
universal prohibition on aggregation. The configured topic is selected when
publication executes. Native concurrent-retarget ownership is not established.
SQLite retains this pending stage, its object coordinates and source references;
deleting the trail cancels its remaining work.

S3 and SNS statuses are independent. A denied Publish records
`LatestNotificationError=AuthorizationError` while S3 delivery advances; previous
notification success timestamps remain. A native A-to-B UpdateTrail cleared the
error before another log notification succeeded, without advancing the prior
attempt/success timestamps. Restoring topic policy alone did not clear the error;
a subsequent new-file notification did.

The local publication attempt records its outcome and completes the SNS stage.
It does **not** borrow S3's 30-day retry budget. In both the retarget and same-topic
captures, an existing failed object received no notification during a 1,200-second
recovery watch plus a 120-second duplicate watch. The same-topic run produced a
successful notification for a different file containing distinct events. These
bounds do not establish that AWS never retries. CloudTrail producer retries for
transient failures and longer windows remain unresolved; SNS-to-subscriber
retries are a separate, already SNS-owned contract.

`sns_controls_evidence.json.gz` and `sns_delivery_evidence.json.gz` under
`testdata/aws/cloudtrail/` retain the owned 2026-09-19/20 captures, source sequences,
full notifications, correlated gzip records and verified resource cleanup.
Their compact replay fixtures cover memory/SQLite, marker effects, caller/service
authority, status transitions and reopen. Account/queue/request/time values are
rebound; one control queue's receive wait is zero for manual-clock observation.
The same-topic regression rejects the prototype's premature one-minute retry,
without claiming an infinite no-retry guarantee.

The real executable upgraded schema 107 with a pending encrypted log to schema
108, delivered it through SNS → SQS → a real Python Lambda Runtime API container,
and verified that the function decrypted the referenced S3 object with its own
execution role. The returned record retained the original source request ID.
Notification denial preserved the encrypted S3 file; process restart preserved
failure status, and a new file recovered notification and function execution.

Primary contracts: [configuration](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html),
[topic policies](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-permissions-for-sns-notifications.html),
[status](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html)
and [destination failures](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-troubleshooting.html).

## CloudWatch Logs destination

`internal/integrations.CloudTrailLogs` uses the ordinary IAM/STS service-role
issuer and typed Logs commands. Create/update evaluates `iam:PassRole`, role
trust and actual destination permissions. The issuing IAM transaction records
the STS outcome; Logs calls run outside it and outside the trail mutation.
Delivery authenticates the actual assumed role. Its trusted audit `invokedBy`
origin is separate from authorization: it does not turn a role into an AWS
service principal or a forward access session.

`logs_destination.json` and `logs_role_updates.json` were captured by
`scripts/aws/cloudtrail_logs_probe.py`, including failed runs and verified cleanup.
Their owner aliases use the existing CloudTrail replay account; other account
distinctions and field presence are preserved. Native evidence establishes:

- Nonempty group/role ARNs must be supplied together, including updates. The
  group ARN ends in `:*` and belongs to the trail's home region.
- Omitted fields preserve the destination. Either empty field alone, or both
  empty, removes both destination fields. An explicit empty/nonempty pair is
  rejected with the field-specific error and preserves the configured pair.
- Allowing `CreateLogStream` but denying `PutLogEvents` fails trail creation yet
  leaves its actual preflight stream. No synthetic log event is written merely
  to check Put permission; the Logs command owner supplies that check.
- Delivered messages are individual CloudTrail JSON records, not `Records`
  arrays or EventBridge envelopes. Logs timestamps represent delivery time,
  independently of the original `eventTime`. The native stream has the account,
  CloudTrail and region prefix; exact allocation/sharding is not reproduced.
- `LatestCloudWatchLogsDeliveryTime` and error fields are independent of S3 status.
  Removing the destination removes its Logs status without stopping S3 logging.

Admission retains separate S3/Logs batches referencing the same immutable journal
records. Delivery invokes each destination outside transactions; one failure
does not stall the other's progress. Logs replacement/removal atomically retires
only its pending work/status and fences stale completions. Already delivered
events remain in Logs. A crash after ingestion can redeliver; there is no
exactly-once claim. Local batching/retry intervals are not AWS timing guarantees.

SDK replay covers role denial, independent preflight effects, matching S3/Logs
record contents, delivery-time timestamps, removal/replacement and SQLite reopen.
The executable smoke also matched actual CLI-delivered gzip/Logs records and
preserved delivered events and removed configuration across process restart.
Native concurrent replacement races, credential reuse, throughput and exact
stream allocation remain uncaptured.

Primary contracts:
[sending trail events to Logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html),
[required role policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-required-policy-for-cloudwatch-logs.html),
[stream names](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudwatch-log-group-log-stream-naming-for-cloudtrail.html),
[UpdateTrail](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html)
and [service-role audit identity](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html).

## S3 dependency scope

The generated REST XML frontend recognizes all 112 operations in the pinned S3
model. Implemented bucket commands include create/delete/head/list/location,
ACL reads/replacement, policy put/get/delete/status, ownership-controls and
public-access-block get/put/delete, bucket tag get/replace/remove, bucket
versioning get/put, CORS and website get/put/delete, notification configuration
get/replace/clear, request-payment and server-access-logging get/put, Object
Lock configuration get/put, replication and Lifecycle configuration get/put/delete,
and Intelligent-Tiering/request-metric/Inventory configuration put/get/delete/list. Object
commands include put/copy/get/head/delete, current/version ACL get/replace,
multi-delete, object-tag get/replace/remove, multipart initiation/part upload/
part copy/completion/abort/listing, attributes, `ListObjects`, `ListObjectsV2`
and `ListObjectVersions`, retention get/put and legal-hold get/put. Other operations return protocol errors. The service is
not complete S3 parity.

Objects store actual AES-256-GCM ciphertext with per-object key material, MD5
ETags and supported checksums. Metadata and ciphertext have separate typed
repository operations and relational storage. Bucket names are partition-wide;
owner account/region remain explicit. Current behavior includes owner enforcement,
public-access restrictions, current policy evaluation, conditional/range reads,
strong read/list visibility and deterministic pagination. Original ownership and
ACLs survive enforced-owner and public-access masks; reads expose the effective
permissions rather than overwriting retained grants.

Versioning retains never-enabled, `Enabled` and `Suspended` bucket state.
Never-enabled writes replace the `null` version. Enabling preserves that null
history and gives later writes opaque non-null version IDs; suspending replaces
only the null version while retaining non-null history. An unqualified delete in
an enabled bucket adds a new delete marker; in a suspended bucket it replaces
the null version with a null marker. Exact-version deletion removes only that
version or marker, exposing the next retained version when appropriate. A bucket
with retained versions or markers is not empty even if current-object listing is.
Local version IDs are opaque local tokens, not AWS's private token encoding.

Current reads use `s3:GetObject`; explicit selections, including `versionId=null`,
use `s3:GetObjectVersion` and the `s3:VersionId` condition. Version deletion uses
`s3:DeleteObjectVersion`, distinct from unqualified `s3:DeleteObject`.
`ListObjectVersions` requires `s3:ListBucketVersions` and supplies prefix,
delimiter and max-keys conditions. Current policy and expected-owner checks still
apply. Native marker controls establish current-marker reads as 404 `NoSuchKey`
and exact-marker reads as 405 `MethodNotAllowed`, with marker/version metadata;
marker resolution precedes ordinary object-read authorization. Missing ordinary
current keys retain the ListBucket-dependent 403/404 distinction.

Version lists order keys lexically and each key's history newest first using a
stored sequence, so equal modification times do not scramble pages. Key/version
markers, prefixes, delimiter grouping, `IsLatest`, page limits and URL encoding
are handled together. A version marker requires a key marker. Common prefixes
count toward the page limit; native version-list URL encoding uses `+` for spaces
while preserving slashes. This is deterministic pagination, not a frozen snapshot
across concurrent object mutations.

Conditional deletion follows the native general-purpose-bucket boundary.
Single `DeleteObject` with both `VersionId` and `IfMatch` returns HTTP 501
`NotImplemented` before read authorization or ETag comparison. Its XML retains
`Header=If-Match` and `AdditionalMessage=Conditional delete operations are not
allowed when a version ID is included in the request parameters.` In
`DeleteObjects`, a `VersionId` plus `ETag` is a per-item `NotImplemented` error
with the native form-field message; eligible siblings still proceed. For a
current-object concrete ETag, `s3:GetObject` is required before comparison in
addition to delete permission. `*` skips that read-permission check, not delete
authorization or existence checking. A mismatch returns 412; an absent current
object or current marker returns 404 after the applicable permission checks.
Directory-bucket size/time conditions and MFA deletion remain unsupported.

Bucket tags have separate typed transaction-owned rows. Replacement/removal is
atomic, including authorization and management observations; empty replacement
removes the set, and an absent read returns `NoSuchTagSet`. Delete requires
`s3:PutBucketTagging`, not a separate IAM delete action. Tags alone do not enable
S3's separate [opt-in bucket ABAC feature](#s3-bucket-abac).

`testdata/aws/s3/bucket_tags.json` captures native replacement, rejection and
recovery with both owned buckets cleaned up. Sets are unordered; the limit is
50 tags, with UTF-16 key/value limits of 128/256. Duplicate keys and reserved
case-insensitive `aws:` key prefixes are rejected. Native probes distinguish
Unicode letters/numbers/separators from rejected controls, combining marks and
other punctuation. Expected-owner failures preserve stored tags. SDK replay
uses these cases on memory/SQLite, including persisted replacement/removal and
resource-policy grant/deny behavior. The singleton PutBucketTagging audit
projection has native evidence; multi-tag/empty-set audit projections remain
documentation-derived. See [bucket tagging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/tagging.html)
and [PutBucketTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html).

The HTTP layer handles path/virtual-host addressing, raw binary bodies, modeled
XML/header/query bindings, presigned SigV4 and authenticated `aws-chunked`
payloads/checksum trailers. S3 object keys retain trailing slashes and native list
URL encoding retains literal slashes. SDK-only `x-id` is not a routing requirement;
required model query bindings and otherwise-ambiguous required headers distinguish
copy and multipart routes. A missing attributes header still selects
GetObjectAttributes and reaches validation, rather than falling through to GetObject.
Buffering remains bounded by the endpoint request limit; this is not a streaming/backpressure
or 5-GB object-size claim.

Native presigned GET captures distinguish two superficially similar query fields:
`ExpectedBucketOwner` is enforced as a header-or-query alternative, and supplying
both is invalid even when equal. Query-only `ChecksumMode=ENABLED` is ignored by
AWS despite SDK presigners placing it there; a real header is required for checksum
output. The gateway therefore does not blindly turn every `x-amz-*` query into a
header. The native fixture also retains differing signed checksum query/header
behavior; full presigned conflict conformance remains open.

### S3 requester payment and server access logging

`GetBucketRequestPayment` and `PutBucketRequestPayment` retain `BucketOwner`
(the default) or `Requester`; `Owner` is not the wire enum. Replacement uses the
ordinary bucket authority and expected-owner checks, not an owner-only shortcut.
Rejected documents and failed authorization preserve the previous configuration.
The exemption is **account-based**: an IAM user or assumed role in the bucket
owner's account needs no payer acknowledgment but still needs permission.
An authenticated foreign caller needs the exact, case-sensitive value
`x-amz-request-payer: requester` on a Requester Pays bucket. Anonymous REST and
website requests cannot acknowledge payment. Restoring `BucketOwner` restores
ordinary public access without deleting the bucket's policy or website state.

Payment admission precedes ordinary IAM/object selection. Admitted foreign
requests receive `x-amz-request-charged: requester`, including subsequent
missing-object, explicit-deny and ACL-disabled errors; missing-payer and signature
rejections do not. An admitted replacement from `Requester` to `BucketOwner`
still carries the header. This is a response contract, **not actual billing**.
The gate covers implemented bucket controls, listings, object/version metadata,
tags/ACLs, multipart operations and both source and destination of a copy.
Raw HTTP carries the payer for controls and `DeleteObjectTagging` whose SDK
inputs omit `RequestPayer`. An ordinary copy destination does not inherit the
source bucket's payment requirement for a later abort.

Presigned SigV4 accepts the signed payer query parameter as an alternative to
the header; query tampering fails signature verification. Supplying both forms
is invalid even when equal. The gateway preserves the query's signing binding
before checking duplication; it does not blindly promote arbitrary `x-amz-*`
queries into headers. `request_payment.go`, `service.go` and the gateway's
`s3.go` own admission, charged responses and these bindings.

Cross-account S3 CloudTrail outcomes have distinct caller and bucket-owner
records, joined by `requestID` and `sharedEventID`, with separate event IDs and
`recipientAccountId` values. The caller retains its IAM/session identity; the
owner-side record uses `AWSAccount` with the foreign account and principal ID.
Caller-side resource ownership is `HIDDEN_DUE_TO_SECURITY_REASONS`, while the
owner-side resource retains the actual bucket account. Both records commit with
the source outcome through `commands.go`; ordinary trail selection/history
scope applies independently. Native paired denied Get/PutBucketRequestPayment
records establish the assumed-role versus AWSAccount distinction. This is not
proof of every cross-account operation's native projection.

#### Logging controls and destination authority

`GetBucketLogging` returns no `LoggingEnabled` by default. `PutBucketLogging`
replaces the destination, prefix, optional key format and target grants; empty
`BucketLoggingStatus` disables new admission. Controls use shared IAM, resource
policy and expected-owner checks. Missing destinations, different owners and
different Regions reject with their native errors. Rejected replacements preserve
state. Omitting the key format remains distinct from explicit `SimplePrefix` or
an empty `PartitionedPrefix`; the latter uses EventTime for delivery.
Populated target grants are rejected for `BucketOwnerEnforced` destinations.

Configuration acceptance does not prove deliverability: native S3 accepted
destinations without delivery permission and with Requester Pays enabled.
Actual local publication uses the ordinary encrypted `PutObject` command as
`logging.s3.amazonaws.com`, with the source bucket ARN/account supplied to
`aws:SourceArn` and `aws:SourceAccount` conditions. Current destination policy,
ownership/public-access rules and same-account/Region checks apply on every
attempt. Requester Pays and non-SSE-S3 destinations cannot receive these local
logs. No configuration call manufactures a successful delivery.

ACL-only delivery to legacy buckets requires both `WRITE` and `READ_ACP` for
`http://acs.amazonaws.com/groups/s3/LogDelivery`; an explicit bucket-policy deny
still wins. A bucket-policy grant can independently authorize the service.
Legacy log objects retain the log-delivery service as owner, bucket-owner
`FULL_CONTROL` and captured target grants. The opaque local service owner is
`canonicalID(partition, "logging.s3.amazonaws.com")`, not an invented AWS account
number or AWS canonical ID. Enforced ownership makes new logs bucket-owned and
masks prior owners/grants without destroying them. Reverting ownership restores
the retained legacy view. The native legacy capture verifies ACL-only and
policy-only delivery, configured canonical `READ` target grants, and reversible
BOE projection. It supplements
[AWS's logging permissions and ownership documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html);
unobserved delivery during the initial missing-permission windows is not proof
of a native non-delivery guarantee.

#### Records, retained delivery and evidence

Public HTTP completion observes actual status/error, response-body bytes,
request identity/URI, selected object size and applicable timing. It emits the
native 27-field space-delimited format with quoted fields and escaped framing
bytes, without storing request or response bodies in the observation. Zero bytes
sent render as `-`; HEAD/range body sizes are not substituted for full object
size. Total time is measured locally; turn-around availability follows the
captured operation classes, including selected management controls, 204 responses
and HeadBucket. HeadObject, conditional and error responses do not acquire an
invented turn-around measurement. Public version IDs are requested versions,
not newly allocated response versions. The key field uses the captured double
form encoding while preserving slashes; the request URI retains its original
wire encoding. Authentication and TLS fields come from the actual request;
HTTP does not acquire fabricated TLS. Presigned signatures are replaced with
`XXXXXXXX` without re-encoding the rest of the URI. Native long-term and
temporary-session captures retain the credential scope; the temporary-session
log also retains a nonempty security token. Published evidence redacts both
credential material and tokens independently of that native behavior.
Access-point requests retain the resolved AP ARN in the documented log column,
including source-copy and per-member delete records. Unidentified source Region
remains unavailable (`-`); signing Region is not evidence of a request's source Region.

Internal service commands use the same formatter, repository and scheduler,
but unavailable HTTP transport fields and timings remain `-`. Native copy source
reads produce `REST.COPY.OBJECT_GET` or `REST.COPY.PART_GET` under the source
configuration. They retain the outer request ID, extended ID, requester and
transport, while URI, referer, user agent, transferred bytes, requested version
and timings are bare `-`, including copies with explicit source versions.
The public destination record accounts for the actual reply and stored object
or part size. Multi-delete produces one `BATCH.DELETE.OBJECT` record per member
and one public `REST.POST.MULTI_OBJECT_DELETE` record with shared correlation.
Member outcomes remain distinct; no independent HTTP transfer, timing or version
measurement is fabricated. These shared server-log identities do not alter
CloudTrail's separate internal copy identity or batch audit ownership.
See [AWS's copy-log definition](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html#AdditionalLoggingforCopyOperations).
Log-object publications themselves are ordinary
internal S3 producers: enabling logging on the destination can recursively
produce more logs, including when source and destination are the same bucket.

The source snapshot freezes each record, event time, destination, prefix, key
format and grants. Later replacement/disable does not erase or retarget accepted
work. Schema 117 retains pending records and grants independently of the source
configuration; SQLite restart retains due times. The shared worker calls S3
outside its queue update and stores real AES256 `text/plain` objects. EventTime
keys use the source event's UTC date with zero hour/minute/second; DeliveryTime
keys use the successful attempt's UTC date/time. SimplePrefix uses delivery time
without the account/Region/source-bucket partition.

Locally, first delivery and rejected-attempt retries are scheduled every **five
service-time minutes**, with **24-hour retention from the event time**. Expired
work is removed. These are deterministic local bounds, not measured AWS latency,
retry or retention guarantees. A crash after publication but before queue removal
can repeat delivery; neither queueing nor restart implies exactly-once logging.
`logging.go`, `access_log_http.go`, `access_log_commands.go`,
`access_log_format.go` and `access_log_jobs.go` own these paths.

ACL-dependence accounting consumes the shared IAM evaluator's completed decision,
without parsing or evaluating a policy again. One source-owned `apiCall` flag
projects to CloudTrail `additionalEventData.aclRequired` and the server-log
`aclRequired` field. An independent policy grant avoids ACL dependence; an
explicit denial still rejects access. Native cross-account reads retain ACL
dependence for HTTP 200, 304 and 412; equivalent policy grants report `-`.
Successful ACL mutations follow the documented `Yes` contract. Native owner
PutObject requests with explicit `private` or `bucket-owner-full-control` report
`-`, as do both copy records and multipart initiation/completion with either
canned ACL. Do not generalize these observations to other grants.
Fixture replay and the actual AWS CLI/SQLite workflow exercise ACL-only
cross-account reads, independent policy reads, explicit denial and retained
delivery; the same source decisions reach actual CloudTrail gzip objects.

The final owned 2026-09-20 captures are
`testdata/aws/s3/requester_payment_evidence.json.gz` and
`testdata/aws/s3/access_logging_evidence.json.gz`. They retain signed/raw control
and payer responses, actual S3 log bytes and request correlations, CloudTrail
records, paired caller/owner observations and verified cleanup of owned resources.
Public native records include successful and denied object requests, HEAD,
conditional/range responses, website requests, IAM/assumed-role
requesters, and all 27 field positions. Actual delivered objects establish
SimplePrefix, EventTime, DeliveryTime, replacement-target and denied-then-recovered
delivery. The executable AWS CLI/SQLite workflow independently exercised retained
payment/configuration, denied delivery then recovery after restart and disable,
event dates across midnight, legacy grants/ownership toggles, copy-source records
and logging of internal log-object publications.

`testdata/aws/s3/access_logging_acl_evidence.json.gz` retains the separate legacy
capture: 113 actual objects, 121 parsed records, request-ID correlations, outgoing
ACL-header controls, object metadata/ACLs, ownership transitions and verified
absence of all twelve created buckets. The fixture replays distinct ACL/policy
200/304/412 paths, bucket listings, compound copies, private/BOFC writes and
multipart uploads on memory and SQLite. Target-grant access changes from success
to denial under BOE and back to success after restoration/reopen. An additional
canonical-grant write succeeded, but its record was not observed before cleanup.
The executable CLI smoke also verifies copied/completed bytes, shared copy
identities, presigned signature masking and delivery after disable/restart.

`testdata/aws/s3/access_logging_operations_evidence.json.gz` extends those
captures with 42 actual objects, 151 parsed records, their metadata/ACLs,
safe pre-sanitization descriptions of three presigned query samples, and
verified absence of both owned buckets. The compact replay selects 81 requests
and 87 positively delivered rows across 57 log codes, not absent-record
expectations. It covers controls, object metadata, versioned header/query reads,
copy and multipart pairs, and multi-delete members through all 27 log fields.
The executable CLI workflow verifies these compound correlations, stored part
and explicit-version deletion sizes, double-form key encoding and temporary
session query treatment after disable and SQLite process restart. The bounded
explicit canonical-grant write again lacked a delivered log; no `aclRequired`
value is inferred from its absence.

Native delivery is **best effort**. Positive delivered records do not establish
exact transition cutoffs, all-event delivery, exact retry intervals, no duplicates
or zero delivery after disable. Requester Pays destination acceptance was captured,
but its delivery incompatibility is documentation-backed, not demonstrated by
that transient native configuration. No invoice or billing charges were measured.
The foreign payer evidence uses one owner/member-account pair and general-purpose
buckets, not an unrelated-account, access-point or directory-bucket matrix.

Remaining accounting boundaries include unobserved native operation spellings,
failed/ACL-dependent compound requests and broader explicit-grant attribution.
Unknown spellings remain unavailable rather than mechanically derived API
names; the TODO in `access_log_format.go` tracks that work.
All cross-account audit projections, propagation/cutoffs, delivery batching and
long-tail failures remain incompletely captured. Source-Region inference and
server-log delivery to CloudWatch Logs/S3 Tables are not implemented.
S3's other operation and storage gaps remain open;
CloudTrail Lake stays excluded.

Primary contracts:
[Requester Pays](https://docs.aws.amazon.com/AmazonS3/latest/userguide/RequesterPaysBuckets.html),
[requester access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ObjectsinRequesterPaysBuckets.html),
[server access logging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html),
[log format](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html),
[ACL-dependent request accounting](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#aclrequired-s3),
and [PutBucketLogging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html).

### S3 ownership, ACLs and public access

Bucket and version ACLs retain typed owners and ordered canonical/group grants.
`PutBucketAcl`, `GetObjectAcl` and `PutObjectAcl` share the ownership and authority
used by ordinary reads, writes, copies, tags and multipart uploads. Explicit
versions use `GetObjectVersionAcl`/`PutObjectVersionAcl`; changing an ACL or
ownership mode does not create an object version or rewrite ciphertext.

`BucketOwnerEnforced` masks original owners/grants, and reverting restores them.
Objects created while enforced remain bucket-owned. `BucketOwnerPreferred`
transfers ownership on a bucket-owner-full-control creation, not on a later ACL
mutation. Multipart initiation freezes ownership/grants independently of later
bucket-mode changes. Enabling enforcement requires an owner-only full-control
bucket ACL; object grants do not block that transition. Current-marker ACL reads
return 404 with marker/version headers; current-marker ACL writes return 405 and
`Allow: DELETE` without those headers. Explicit marker selections return 405 with
both the marker/version headers and Allow.

Foreign-owned objects require resource-side authority from their actual owner.
Bucket-policy Allows do not grant access to them, but bucket-policy Denies still
apply. Canonical-account ACL grants retain IAM identity/session/boundary ceilings.
Measured same-account public ACL and `Principal: "*"` policy grants bypass
implicit ceilings, not explicit denials. Cross-account callers still need their
identity-side permission. Unsigned S3 requests use ordinary resource authorization;
partial signatures never downgrade to anonymous requests. A payload checksum
alone is not a credential. `Config.UnsignedRegion` selects the unsigned endpoint
region, shared with unsigned STS federation.

The four bucket public-access flags are independent. PUT replaces the configuration
instead of merging omitted flags; an empty configuration is rejected. Deletion is
idempotent and uses `s3:PutBucketPublicAccessBlock`. BlockPublicAcls rejects new
public grants without revoking existing ones; IgnorePublicAcls masks effective
reads and access without deleting stored grants. BlockPublicPolicy governs policy
admission, not existing grants. RestrictPublicBuckets blocks public/cross-account
policy access when the policy is public, including otherwise fixed cross-account
statements; it does not independently disable a public ACL on a bucket without
a public policy.

The generated S3 Control frontend implements account
`GetPublicAccessBlock`, `PutPublicAccessBlock` and `DeletePublicAccessBlock`
over the same S3 owner and repository. Account settings are partition/account
scoped, not regional; schema 118 retains their four typed flags. Absence returns
`NoSuchPublicAccessBlockConfiguration`, while an explicitly all-false configuration
remains present. PUT replaces the complete configuration; omitted flags are false.
Account PUT/DELETE return modeled HTTP 200 with empty bodies. Reads require
`s3:GetAccountPublicAccessBlock`; both mutations require
`s3:PutAccountPublicAccessBlock`. A caller cannot select a different account.

Ordinary S3 commands combine bucket settings with the **bucket owner's** effective
account settings once, without rewriting the retained bucket configuration.
Copies resolve each source/destination independently; batch members retain their
parent's effective settings. ACL projection, public-policy admission and restricted
cross-account access consume that same result. Verified AWS service principals
remain eligible under RestrictPublicBuckets, but ordinary explicit denials still
apply to their actual delivery commands.

Organizations publishes `S3_POLICY` through its existing inheritance resolver,
retained jobs and service clock. `all` and `none` override all four account flags,
including a previously restrictive account configuration, and prohibit account
PUT/DELETE while managed. They do not disable independent bucket restrictions.
Detachment or an empty effective policy restores the untouched account settings
after publication; disabling the policy type removes the override immediately.
S3 reads the published policy through a small consumer-defined interface inside
its existing transaction, without fabricating a public Organizations request.
See [the policy owner](organizations-effective-policies.md#s3-policies).

`testdata/aws/s3control/readonly_native_evidence.json.gz` retains 13 native signed
GETs across two accounts and two Regions, plus 11 correlated read-only management
events. Two SDK-only rejections and an unprefixed-host DNS failure are not HTTP
observations. On canonical AWS endpoints, the account hostname prefix is
authoritative even when `x-amz-account-id` is missing or disagrees. Native wrapped
errors retain AccountId where observed, plus RequestId/HostId. Local endpoint
overrides instead use the account header and generated route; an ordinary S3
object at the same path without that discriminator remains an S3 object.

The native account audit name is `GetAccountPublicAccessBlock`, with
`eventSource=s3.amazonaws.com`, Host-only request parameters and null response
elements. Account mutations use the documented corresponding `PutAccount…` and
`DeleteAccount…` names. Source outcomes commit with account mutations and feed
ordinary CloudTrail/eligible EventBridge consumers. Read-only management delivery
requires the rule's explicit `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` state.

SDK/raw fixtures cover native reads separately from documentation-backed account
mutation, four-flag enforcement, service delivery and Organizations scenarios on
memory and SQLite. The actual CLI executable upgraded schema 117→118, retained
object bytes/ACLs, resumed a pending organization override after restart, enforced
IAM denials and restored account settings after detachment. CloudTrail delivered
21 account-management records in two S3 gzip objects; EventBridge/SQS received
identical selected bodies, including five read/write/error outcomes after enabling
all management events. CLI transport used a loopback HTTP proxy to preserve the
SDK's account-prefixed host without external DNS; Go SDK fixtures use an immutable
local endpoint.

Successful native account GETs, sparse/empty PUT admission, DELETE idempotence,
write audit details, regional propagation and Organizations S3 publication/
enforcement conformance have not been captured. Unattached Organizations policy
admission is captured separately in
`testdata/aws/s3control/s3_policy_admission_evidence.json.gz`; every owned policy
was deleted. No real account security settings, policy attachments, enabled
policy types or memberships changed. Account changes are immediately visible
locally; the existing one-second Organizations publication delay is a
deterministic local contract, not an AWS timing guarantee. Regional access-point
operations are described below; other generated S3 Control operations remain unsupported.

Primary account contracts:
[GET](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_GetPublicAccessBlock.html),
[PUT](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_PutPublicAccessBlock.html),
[DELETE](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_DeletePublicAccessBlock.html)
and [account management audit names](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-account-level-tracking).

Public-policy classification uses the shared IAM parser, action/resource catalog
and selector algebra, with S3 trust anchors. The 87-case native matrix covers
fixed/wildcard principals, action/resource admission, negative selectors and
denials, trust conditions, policy variables, multivalue/presence distinctions and
IPv4/IPv6 prefix widths. Numeric account principals render as account-root ARNs.
Compound conditional-denial inference beyond these measured cases and native
region/propagation behavior remain incomplete; the matrix is not a proof of
arbitrary policy satisfiability.

The generated document decoder owns S3's measured XML dialect: local element
names without root/namespace enforcement, closed structure/list members,
singleton cardinality, empty scalar-child handling and permissive document
booleans (`true`, case-insensitive, or `1`; other strings are false). HTTP scalar
decoding is unchanged. The same behavior is observed for AES256 bucket-encryption
configuration; its BucketKeyEnabled flag is retained without pretending to
implement KMS bucket-key cryptography. S3 retains operation-specific empty-body,
schema and ACL errors. The bucket canned-ACL model correction leaves native
admission to the service, including bucket-owner-read/full-control values absent
from the pinned enum.

Native evidence in `testdata/aws/s3/`:

- `ownership_evidence.json.gz`: 1,076 calls, including the owned Organizations
  member-account role, version selection, copy/multipart ownership and raw ACL
  admission. `ownership*_replay.json` records SDK-derived checksum/encoding
  prerequisites separately because those request headers were not captured.
- `public_access_evidence.json.gz`: 709 calls and 87 policy classifications;
  `local_acl_authority_evidence.json.gz`: 495 native responses plus one separately
  classified transport failure, repeated settled authority matrices and creation
  controls. Stale propagation observations and the earlier signer pilot remain
  evidence, not replay expectations.
- `xml_dialect_evidence.json.gz`: 145 completed cases across four document APIs;
  SDK/raw replay retains state after rejected requests and proves accepted XML
  replacements rather than merely checking successful status.
- `access_controls_audit_evidence.json.gz`: a regional repeat correlated 36 of 37
  requests within 38 delivered records. The replay asserts 31 access-control
  management/data records through configured gzip delivery, exact parameter/
  response presence, effective ACL mutation markers and actual wire byte counts.
  Wrong-owner and initial anonymous non-delivery are bounded observations, not
  assertions that CloudTrail never logs them.

All native owned resources were removed; existing member roles and account/
organization controls were unchanged. The actual executable upgraded schema
112 to 113, retained two encrypted versions and a pending encrypted multipart
upload, completed that upload, exercised cross-account and anonymous access,
then restarted before delivering 23 management/data CloudTrail records.

References: [Object Ownership](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html),
[Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html),
[CreateBucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html).
Native fixed SourceOwner conditions classified public despite the guide; that
discrepancy does not establish every account/region's rollout behavior. Earlier
200 and 409 duplicate-create captures remain intact. The later controlled
[recreation matrix](#s3-bucket-creation-and-recreation) establishes the conditional
transition rather than treating either status as unconditional.

### S3 bucket creation and recreation

General-purpose `CreateBucket` authorizes the requested creation before resolving
an owned-bucket configuration conflict. An existing same-account bucket policy
participates, including explicit denial; existing bucket resource tags do not
become creation tag context, even when ABAC is enabled. Private ACLs and explicit
owner-full-control-only grants require no additional `s3:PutBucketAcl` grant.
Other grants require it. Explicit ownership requires
`s3:PutBucketOwnershipControls`; enabling Object Lock requires both
`s3:PutBucketObjectLockConfiguration` and `s3:PutBucketVersioning`.

The legacy us-east-1 success path is conditional. Requested region and lock state
must match. Nonempty current ownership must match the requested ownership, whose
omitted default is `BucketOwnerEnforced`. Current ABAC must be disabled. Nonempty
creation tags conflict, even if identical to existing tags. Current public-access
settings must be absent or match creation's all-true defaults: each individual
false flag was independently observed to reject. ACL validation still uses the
creation defaults, not relaxed current public-access settings.

Successful recreation replaces only the bucket ACL. Omitted ACL resets it to
owner full control; explicit admitted grants replace it. Object bytes, metadata,
versions, checksums, timestamps, creation date, tags, versioning, acceleration and
other retained settings survive. Absent ownership/public-access settings remain
absent. Matching us-west-2 creation still conflicts. Empty creation configuration
and empty creation tag lists are accepted; invalid location values retain
`InvalidLocationConstraint`, including modeled enum-validation failures.
`ListBuckets` exposes the captured bucket ARN alongside region and creation date.

`recreation_controls_evidence.json.gz` retains 297 observations, including the
independent public-access flag probe; its replay exercises 180 calls.
`recreation_authority_evidence.json.gz` supplies 277 replay calls across two
authority scenarios. A configured classic trail compares 30 positively
request-correlated native CreateBucket records: resources are absent, responses
are null, and native ownership/canned-ACL/custom-grant parameter shapes are
preserved. The Object Lock creation header is not projected. Native history
absence is not treated as an exclusion rule.

SDK fixtures exercise both stores. Provider dates/issued identities are bound;
later reads assert invariants. ACL grants compare captured fields one-to-one as
unordered collections, preserving omitted provider IDs and grant multiplicity.
The actual SQLite executable was restarted before recreation, then verified
ACL-only reset, unchanged versioned bytes/checksums/metadata/settings and
mutation-free rejection.
A separate AWS CLI read verified the bucket ARN projection.
Owned native buckets, versions and roles were removed; no standing controls or
identities changed. These captures do not establish complete S3 parity.

Primary contract: [CreateBucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html).

### S3 regional access points

The generated S3 Control frontend implements ordinary regional
`CreateAccessPoint`, `GetAccessPoint`, `ListAccessPoints`, `DeleteAccessPoint`,
`PutAccessPointPolicy`, `GetAccessPointPolicy`, `DeleteAccessPointPolicy`,
`GetAccessPointPolicyStatus`, `TagResource`, `UntagResource` and
`ListTagsForResource`. Typed S3 repositories own the records, policy principal
bindings and tags; schema 119 retains them with the common journal.

AP identity is partition/account/Region/name scoped. Bucket identity, network
origin and AP public-access flags are immutable after creation. Omitted AP public
access configuration enables all four blocks; an explicitly empty configuration
disables them. Alias identity survives policy/tag changes and restart, but not
deletion/recreation. Same-owner APs prevent bucket deletion; foreign-owned APs
survive as control-plane records and cannot read a missing backing bucket.
Control calls cannot select another caller's account. Native `GetAccessPoint`
authorization uses `Resource: "*"`, unlike AP-scoped lifecycle/policy actions.

Canonical AP hosts resolve to an ARN without changing the signed host/path;
aliases resolve through the same retained record. Existing object, list, copy,
multipart, tagging and ACL commands use the underlying bucket's storage, not a
second object namespace. Bucket and AP IAM/resource-policy decisions remain
independent. Cross-account delegation does not replace the caller's required
identity permissions on both ARN families. AP restrictions do not alter direct
bucket access. Shared conditions include `s3:DataAccessPointArn`,
`s3:DataAccessPointAccount` and `s3:AccessPointNetworkOrigin`; effective public
access restrictions retain account, bucket and AP ownership.

List/upload response bucket names identify the backing bucket. Continuations
and pending uploads can cross ARN/alias references without changing ownership.
Completion Locations preserve native addressing: an ARN uses the canonical
regional AP host; an alias uses its alias host. Copy source and destination
authority remain separate, including AP source denial and direct-source access.
Owned `us-east-1`/`us-west-2` captures show a directional distinction: an AP
**source** in another Region returns HTTP 403 `AccessDenied`, while a direct
bucket source in another Region succeeds with an AP destination. Both
`CopyObject` and `UploadPartCopy`, ARN/alias forms and final consumer bytes were
captured, with direct-bucket positive controls. The regional evidence retains
these observations separately. The
[CopySource contract](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html#API_CopyObject_RequestParameters)
carries a same-Region note; the fixtures distinguish source and destination APs
instead of applying it as a blanket prohibition. They do not establish behavior
for every partition or AP family.

Regional admission preserves the distinction measured in
`access_point_region_evidence.json.gz`: a correct regional AP/alias endpoint with
the wrong signing Region returns `AuthorizationHeaderMalformed`, or
`AuthorizationQueryParametersError` for presigning, with HTTP 400 and the expected
Region. An alias at the wrong regional endpoint instead returns HTTP 301
`PermanentRedirect` with its regional endpoint. Rejection does not rewrite
`aws:RequestedRegion` to manufacture an IAM permission. The raw replay keeps
Host and signing Region independent and does not follow redirects.

The native control, authority, multipart, regional and audit evidence/replay pairs under
`testdata/aws/s3control/access_point_*` distinguish actual HTTP observations from
SDK/signing failures and local restart transitions. They cover lifecycle,
reversible policy changes, public blocks, independent identity/resource grants,
foreign-owned APs, ordinary bucket controls addressed through APs, copy sources
and mixed-reference uploads. Native AP control responses and bucket policy/tag
HTTP status differences are corrections to the generated model, not separate
writer overrides. Audit outcomes retain the serialized response's actual status
and byte length, sharing the generated bytes with the response writer.

CloudTrail AP data selection uses `AWS::S3::AccessPoint` resources; management
selection remains separate. Native management history and positively delivered
S3 gzip data records back the audit replay, which reopens SQLite before delivery.
The executable CLI workflow retained aliases/tags, bytes, IAM decisions and a
pending multipart upload across restarts. Configured consumers delivered 30
CloudTrail records and 21 access-log lines, 16 with AP ARNs; 17 EventBridge/SQS
API bodies exactly matched their CloudTrail records. An alias write after
notification publication also delivered an ordinary S3 `Object Created` event.
These are local workflow observations, not native timing or completeness claims.

Positive VPC transport is not implemented: caller headers cannot establish VPC
provenance, so external requests to VPC APs are denied. VPC-origin policy
classification is retained independently of transport admission. Multi-Region,
Object Lambda, Outposts, directory-bucket, FSx and backup AP families remain
unsupported. Native AP server-access-log delivery, broader cross-account audit,
propagation and full regional behavior still require evidence.

References: pinned SDK models at
`113bc91bf12edc3af1d3aba1c70be28494d54c2a`;
[AP policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points-policies.html),
[restrictions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-points-restrictions-limitations-naming-rules.html)
and the [access-log format](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html).

### S3 CORS and static websites

The generated REST XML frontend implements `GetBucketCors`, `PutBucketCors`,
`DeleteBucketCors`, `GetBucketWebsite`, `PutBucketWebsite` and
`DeleteBucketWebsite`. Configurations use typed memory repositories and normalized
SQLite tables; schema 114 preserves existing ownership, encrypted versions and
pending multipart uploads. Replacements are atomic with source management events,
and deleting configuration leaves object bytes intact.

CORS retains rule order, optional IDs/max ages and origin/method/header lists.
Preflight evaluates the configured bucket rules before authentication; an allowed
preflight grants no object authority. Actual responses, including authentication
errors, receive matching CORS headers. No configuration means no implicit public
CORS rule. Request identity belongs to the gateway/website entrypoint, not a
second fallback inside the matcher.

Website endpoints are anonymous even when a caller supplies valid REST
credentials. Shared object authorization and encrypted reads serve index objects,
directory redirects, ordered routing rules, stored object redirects, custom error
documents, conditions, ranges and HEAD responses. Index/error selection does not
fabricate internal REST `GetObject` events. Empty and host-free redirect rules
remain retained; field absence is distinct from an explicitly empty value.
Known regional AWS host forms and corresponding `.localhost` website hosts use
the generated partition catalog.

Native requests establish that missing checksums are rejected for CORS and bucket
tagging, but accepted for public-access-block, object tagging, website, ownership
and encryption documents. Five evidence-backed corrections feed the existing
Smithy generator; supplied-checksum validation remains enforced. Malformed and
incomplete S3 authentication stays in the S3 XML error dialect.

Evidence under `testdata/aws/s3/`:

- `cors_evidence.json.gz` retains configuration, preflight/actual HTTP and delivered
  control-event observations. `website_evidence.json.gz` retains configuration,
  raw serving responses, object setup and delivered control events.
- `browser_boundaries_evidence.json.gz` contains five supplemental runs and 207
  calls. Accepted writes sometimes read back the previous website configuration,
  while other captures retained the same rule payload immediately and after
  bounded waits. Neither a fixed delay nor an endpoint-specific explanation is
  established. Raw admission fixtures do not misclassify those older reads as
  proof that accepted rules were discarded; SDK retained-rule fixtures also
  reopen SQLite and assert field presence/absence.
- Shared fixture runners exercise memory and SQLite without a second browser
  test framework. Source-owned CloudTrail projections retain document shape,
  rejection status and actual transferred byte counts.

The actual executable upgraded schema 113→114, retained two encrypted versions
and completed a preexisting multipart upload. After restart, Chromium observed
successful cross-origin JSON/ETag access, a blocked custom header, private-object
403, stored custom 404, directory redirect/index and a 206 range. A signed website
request still had anonymous authority. Configured gzip delivery contained 34
records, including all six control operations and a rejected website update.
These counts describe that workflow, not complete S3 conformance. All five
supplemental native buckets were deleted and independently returned HeadBucket 404.

Remaining bounds: configuration publication is immediate locally, rather than
modeling native website propagation; website data-event projections have not been
captured; malformed/unknown/duplicate/noninteger XML audit projections remain
incomplete. The generated SDK contract retains `int32` CORS max ages despite
native acceptance of larger integers. No full browser-surface parity is claimed.

Primary contracts: [CORS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cors.html),
[website hosting](https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html),
[website endpoints](https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html)
and [PutBucketWebsite](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html).

### S3 object tagging

`GetObjectTagging`, `PutObjectTagging` and `DeleteObjectTagging` use the generated
REST XML frontend. `PutObject` accepts the URL-encoded `x-amz-tagging` header.
Tags belong to the selected object version, not the key's current metadata:
replacement/removal does not rewrite bytes, encryption, ETag, LastModified,
version ID or history order. A new version starts with its supplied tags only;
never-versioned and suspended-null overwrites do not inherit the replaced tags.
Memory and SQLC repositories expose typed tag reads/replacement inside the same
transaction as source outcomes and configured publications. SQLite migration 110
adds version-owned relational rows; exact-version deletion cascades those rows.

Object tag sets are case-sensitive and unordered, with at most ten distinct
keys and UTF-16 key/value limits of 128/256. Unlike bucket tags, the reserved
`aws:` object-tag prefix is case-sensitive. Empty replacement clears the set;
empty reads succeed and repeated deletion succeeds. Native omitted-TagSet
requests also clear both object and bucket tags, recorded as a Smithy required-
trait correction rather than an alternate parser. Header decoding distinguishes
`+` from `%2B`, rejects malformed escapes and decoded duplicate/empty keys, and
shares tag-value validation with the XML commands.

Current operations use their respective `s3:GetObjectTagging`,
`s3:PutObjectTagging` and `s3:DeleteObjectTagging` actions. Explicit versions,
including `null`, use the corresponding `ObjectVersionTagging` action.
Nonempty tagged `PutObject` requires both `PutObject` and current
`PutObjectTagging`, even in an enabled bucket; an empty header does not add that
permission. Request tag values/keys participate in IAM conditions. Selected
existing tags participate in data reads and tag read/mutation authorization,
not overwrite/delete-object authorization. GetObject and HeadObject disclose a
nonzero TagCount only with matching current/version tag-read permission;
denying that permission does not deny an otherwise permitted data read.

Native counterprobes distinguish live-object authority from disclosure:
missing objects and delete markers require `ListBucket`, even for explicit
versions. Denying ListBucket returns 403 without marker headers. Permitting it
returns the appropriate missing-key/version 404 or marker 405, even when the
tagging action itself is denied. Marker responses carry `Allow: DELETE` and
marker/version headers, but no Last-Modified header. Live objects instead use
the selected tagging action and tag conditions.

Tag mutations commit classic `ObjectTagging:Put`/`ObjectTagging:Delete` work and
native EventBridge `Object Tags Added`/`Object Tags Deleted` events through the
existing notification interfaces. Payloads retain key, ETag and optional version,
but omit size, sequencer, reason and tag values. Same-value and empty PUTs and
already-empty DELETEs still publish. Tagged object creation emits its creation
event; the bounded native capture found no separate tagging publication.
CloudTrail classifies the tag APIs as data events. Request projections retain
`tagging`, bucket, Host, key and optional version without the XML tag body or
header values. Reads have null response elements; successful versioned mutations
retain the version response header. Failed requests retain their selected
version and native error classification without leaking tag values.

`object_tagging_controls_evidence.json.gz` and
`object_tagging_events_evidence.json.gz` under `testdata/aws/s3/` retain the owned
2026-09-20 captures in `000000000000`, `us-east-1`, including cleanup and source
correlations. The event run recovered actual CloudTrail S3 logs; its bounded
window observed 11 of 17 target audit calls, not a guarantee that the other calls
never arrive. Compact fixtures exercise controls, authority, exact notification
payloads and actual gzip trail delivery on memory and reopened SQLite. An
executable 109→110 upgrade and second restart retained old object bytes/versions,
tag-conditioned IAM access, both SQS event routes and delivered audit records.
Owned native and local resources were removed after verification.

Primary contracts: [object tagging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html),
[tag conditions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/tagging-and-policies.html),
[GetObjectTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html),
[PutObjectTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html)
and [DeleteObjectTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html).

### S3 bucket ABAC

`GetBucketAbac` and `PutBucketAbac` retain the general-purpose bucket's enabled
state alongside its existing tag rows. The default is `Disabled`. Repeated
enable/disable requests preserve tags, object bytes, metadata and modification
times. Enabled buckets reject legacy `PutBucketTagging` and
`DeleteBucketTagging` with `BadRequest`; reads remain available. Disabling ABAC
restores legacy mutations without deleting tags.

S3 Control `TagResource`, `UntagResource` and `ListTagsForResource` accept ordinary
`arn:aws:s3:::bucket` resources. They merge, remove and read the same typed tags
used by legacy APIs, with current account/region ownership checks and an atomic
50-tag combined quota. Bucket `TagResource` returns 204; the captured access-point
operation returns 200. Empty bucket mutations return `InvalidTag`, distinct from
access-point errors. The generated model correction removes the upstream ARN
pattern that rejects regionless bucket ARNs accepted by AWS. Generated binding
still owns wire constraints; resource owners own reserved/duplicate keys, quotas
and the resource-specific empty-request contract.

`CreateBucketConfiguration.Tags` creates general-purpose bucket tags atomically
with the bucket, including east-region configurations without a location
constraint. Actual creation tags require `s3:TagResource` as well as
`s3:CreateBucket`; `aws:RequestTag` and `aws:TagKeys` describe the submitted set.
Creation does not enable ABAC. Legacy replacement does not supply those request
condition keys.

Authorization reads current bucket tags only while ABAC is enabled. Bucket and
object operations, copy source/destination checks and multipart completion share
the existing IAM owner; there is no separate S3 policy evaluator. Native access
point captures distinguish the two authorization legs:

| Context | Bucket leg | Access-point leg |
| --- | --- | --- |
| `aws:ResourceTag/*` | Enabled bucket tags | Access-point tags |
| `s3:BucketTag/*` | Enabled bucket tags | Enabled bucket tags |
| `s3:AccessPointTag/*` | Access-point tags | Access-point tags |

The resource-tag sets are not unioned. Disabling bucket ABAC removes bucket tag
context but preserves access-point tags. Direct bucket requests have no
access-point tag context. Condition-key spelling is case-insensitive; tag values
and `aws:TagKeys` values remain case-sensitive. Captured `Project`/`project`
collisions agree with the shared evaluator's current winner, not a general AWS
collision-order guarantee.

The same captures exposed named STS session principals in resource policies.
Shared IAM validates the referenced role without requiring prior session issuance,
but retains the session ARN instead of binding the role's immutable ID. An owned
native delete/recreate experiment confirmed that this session grant survives role
recreation; ordinary IAM user/role principal bindings still do not.

`abac_controls_evidence.json.gz`, `abac_authorization_evidence.json.gz`,
`abac_principal_binding_evidence.json.gz` and `abac_admission_evidence.json.gz`
retain native sources, observations and cleanup. The admission probe created no
resources. Across 18 request-correlated records, absent-bucket `PutBucketAbac`
retained its XML and admitted byte count without an expected-owner header, but
omitted the document and reported zero admitted bytes with either the caller's or
a foreign account ID. Both valid and invalid statuses reproduced this boundary;
it is not a rule for existing buckets or all rejected requests.

Fixture replay covers state/authorization on memory and SQLite.
`abac_audit_replay.json` projects 108 request-correlated native management records
through a locally configured classic trail; the AWS captures used event history,
not a paid trail. XML element presence and repeated-query order are retained with
raw signed requests where SDK serialization differs. The executable smoke verifies
real data grants/revocations, unchanged object metadata, SQLite process restart and
retained CloudTrail history.

`abac_tag_transitions_evidence.json.gz` adds 77 native observations and 53 replay
calls from a fresh low-cardinality probe, including repeats after a quiet interval.
Duplicate `TagResource` keys reject with `InvalidTag` for both resource owners.
Duplicate access-point `UntagResource` keys also reject with `InvalidTag`;
bucket removal and duplicate creation tags repeatedly produced `InternalError`.
Rejection preserves every existing tag, including a distinct requested removal,
and failed creation leaves no bucket. These are captured rejection/post-state
contracts, not a promise that AWS will retain a server-error bug indefinitely.
Eight independent cleanup reads verified owned buckets, access point and role
absent. Actual CLI calls and SQLite process restart verified local atomic rejection.

Propagation remains incomplete. `abac_visibility_evidence.json.gz` separates
role-setup propagation from two tag transitions with two unchanged scoped roles:
fresh sessions observed new decisions while original sessions retained old ones.
`abac_session_cache_evidence.json.gz` crosses client transport and credentials to
resolve that confound. New clients using the exact original credentials saw the
new decision; original warmed sockets signed with fresh credentials retained the
old decision. This occurred for both grant and revoke. A session assumed before
mutation but unused for S3 until afterward saw current state on a new connection.
Credential identity or session creation time alone therefore does not explain the
observed divergence. At the roughly 15.6-second sample, the original SDK clients
had replaced their sockets and all variants agreed; elapsed time, connection
renewal and backend routing remain confounded. No cache owner or fixed TTL follows.
All three owned probe attempts were independently cleaned and verified absent;
the interrupted attempt and transport failure are not service responses.

The earlier transition capture also observed `TooManyTags` despite 49 visible tags,
followed by successful replacement roughly five seconds later. Replay asserts
settled decisions/capacity, not nondeterministic intervals. Local visibility
remains immediate; no guessed session cache, publication scheduler or transient
quota state was added.
Directory buckets remain outside this implementation. These fixtures do not complete S3.

Primary contracts: [bucket tagging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/buckets-tagging.html),
[enabling ABAC](https://docs.aws.amazon.com/AmazonS3/latest/userguide/buckets-tagging-enable-abac.html),
and [role-session principals](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html#principal-role-session).

### S3 transfer acceleration

`GetBucketAccelerateConfiguration` and `PutBucketAccelerateConfiguration` retain
general-purpose bucket status in typed memory/SQLC state. A fresh read omits
`Status`; explicitly setting `Suspended` preserves that value. Repeated changes
preserve object bytes, metadata and modification times. Native Put succeeds with
HTTP 200.

IAM uses `s3:GetAccelerateConfiguration` and `s3:PutAccelerateConfiguration`.
Current identity, session, bucket-resource and enabled ABAC conditions apply.
Bucket existence, expected owner, regional endpoint and authorization precede
payload validation. Denied malformed XML and bad-checksum requests remain denied.
Missing/empty status, invalid enum values, missing documents and checksum failures
retain their distinct captured error codes. Dotted bucket names reject writes.

Accelerated and dualstack endpoints share ordinary stored objects, checksums,
metadata, IAM and copy commands. Never-configured and suspended buckets return
`InvalidRequest` for accelerated data requests; ordinary endpoints remain usable.
Presigned requests check current state rather than retaining an earlier grant.
Access-point aliases use the underlying bucket's acceleration setting. Regional
misrouting returns the captured redirect, and accelerated signing scope must match
the bucket region. Raw native cross-region CopyObject succeeded; SDK endpoint
restrictions are not substituted for observed server admission.

Native management events are named `GetAccelerateConfiguration` and
`PutAccelerateConfiguration`. Parameters include `accelerate`, `bucketName` and
`Host`, never the configuration XML tree. Responses are null; missing-bucket events
omit bucket resources. Event-history indexed resources are empty. IAM/owner/route
and invalid-checksum admission can report zero consumed bytes; rejected XML/status
and mismatched valid digests retain admitted body bytes.

`acceleration_controls_evidence.json.gz`, `acceleration_data_evidence.json.gz`
and `acceleration_routing_evidence.json.gz` retain native requests, responses,
sources, uncertainties and cleanup. Controls replay 98 stable calls; data replay
59 calls; routing replay adds wrong signing scope, cross-region copy and
access-point alias transitions. The audit fixture compares 70 positively
request-correlated records through a local classic trail; native capture used
free history, not a paid trail. Unmatched history requests do not prove exclusion.
All replays exercise memory and SQLite. The actual trusted-HTTPS executable smoke
preserved flags, bytes and aliases across process restart, then verified
presigned reads, suspension revocation, unaffected ordinary reads and re-enabling.

The native probes' owned buckets, roles and access points were removed. One routing
capture stopped on a bare accelerator DNS failure; another lost in-memory response
rows after a cleanup connection failure. Their termination and recovered cleanup
are explicit, not reconstructed native responses. A separate completed alias probe
supplies the retained raw alias evidence.

This models endpoint admission, not CloudFront edge placement or transfer speed.
Native first polls admitted activation/suspension immediately; documented speed
warm-up is not modeled as an invented API delay. Accelerated repeated creation
uses the same [conditional bucket transition](#s3-bucket-creation-and-recreation)
as ordinary endpoints. S3 remains partial.

Primary contracts: [Put configuration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAccelerateConfiguration.html),
[Get configuration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAccelerateConfiguration.html)
and [transfer acceleration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/transfer-acceleration.html).

### S3 Object Lock

The generated frontend implements `Get/PutObjectLockConfiguration`,
`Get/PutObjectRetention` and `Get/PutObjectLegalHold`. Typed memory and SQLC
SQLite state retain bucket defaults, per-version retention/legal holds and
multipart initiation snapshots. Metadata replacement does not rewrite payloads,
ETags, object modification times or version ordering.

Bucket enablement is irreversible and requires enabled versioning for an
existing bucket. Create-time enablement authorizes bucket creation, versioning
and lock configuration together. Locked buckets cannot suspend versioning.
Removing a default rule does not disable the bucket or alter existing versions.
Default periods retain days/years; calendar-year deadlines include leap years.

Fixed and variable retention use the same version guard. An active event hold
returns the later of its stored date floor and the current service time plus
its duration. Shortening the duration freezes the previous effective deadline;
releasing the hold freezes the resulting fixed date. An omitted event-hold
field is distinct from explicit `OFF`. Expired metadata remains readable but
does not continue to prevent deletion.

Active COMPLIANCE cannot be shortened, removed or switched to another mode;
governance bypass does not defeat it. GOVERNANCE weakening/deletion requires
both the explicit bypass request and `s3:BypassGovernanceRetention`. A legal
hold independently blocks version deletion, including governance bypass.
Ordinary unversioned deletes can still create delete markers, which are not
protected versions. Batch deletion returns independent protected/successful
member outcomes. Prior null versions and selected markers use their captured
native metadata/error behavior.

Put, copy and multipart initiation share one creation rule: explicit retention
or legal-hold settings replace bucket defaults. In particular, explicit legal
hold `OFF` suppresses default retention. Copy does not inherit source retention;
multipart completion uses initiation-time settings despite later bucket changes.
Public retention-bearing uploads enforce the native checksum requirement;
trusted typed service writes do not fabricate HTTP checksum headers.

IAM uses effective request facts, including computed remaining days and
event-hold duration (years count as 365 days for the condition key).
Implicit defaults do not require a separate `PutObjectRetention` grant.
The guide says event-hold conditions do not apply to bucket defaults; isolated
native PutObject policies nevertheless matched implicit event-hold/duration
defaults. The implementation follows those captured request outcomes, not an
inferred rule for every producer. Payload access and optional Get/Head retention
and legal-hold headers have independent permissions; missing metadata authority
omits the corresponding headers rather than granting access or rejecting an
otherwise authorized payload read.

Explicit retention mutations commit native classic `ObjectRetention:Put`
version 2.6 and direct EventBridge `Object Retention Updated` snapshots.
Their retention blocks preserve mode, effective date, event hold and original
duration units without inventing a sequencer. CloudTrail uses native
`Get/PutBucketObjectLockConfiguration`, `Get/PutObjectLockRetention` and
`Get/PutObjectLockLegalHold` names. Retention/legal-hold modification timestamps
are independent stored facts, not object-write timestamps or optional response
headers. Native parent DeleteObjects audit records report zero transferred
bytes and bucket/Object-ARN-prefix resources rather than serialized batch sizes.

Owned `us-east-1` captures live in `testdata/aws/s3/object_lock_*_evidence.json.gz`:
control, authority, supplemental signed requests, delivered audit, notification
and server-log admission. The compact control/authority/delivery/audit fixtures
replay on memory and reopened SQLite. One isolated post-activation error is
retained as an exclusion, not turned into a deterministic restriction on null
versions. Unmatched audit requests are not evidence of suppression. All owned
native resources were verified absent; the supplemental immediate successful
HEAD and later confirmed absence are both retained without a propagation-cause
claim.

The executable workflow verified STS metadata separation, default/explicit
protection, compliance expiry, moving/frozen deadlines and pending multipart
recovery across process restart. It delivered three classic retention records
(plus the native configuration test event), three direct events and five audit
events through SQS. Those five audit identities also appeared in three actual
CloudTrail gzip objects; the destination's governance defaults protected the
internally written log objects.

The guide prohibits Object Lock buckets as server-access-log destinations, but
all captured configuration admissions returned 200. No source or positive-control
log was delivered during the 743-second window, so delivery support or suppression
is **not** established. No new admission prohibition or guessed log operation
spelling is added. Native propagation, broader audit/log projections, native
Inventory protection-cell conformance and Storage Lens interactions remain open.
Live replication carries retained protection metadata as described below;
these API/fixture results do not complete S3.

Primary contracts: [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html),
[management and variable retention](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html),
[retention API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectRetention.html),
[notification structure](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html)
and [direct event structure](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-events.html).
Wire contracts use `clones/aws-sdk-go-v2/codegen/sdk-codegen/aws-models/s3.json`
at `113bc91bf12edc3af1d3aba1c70be28494d54c2a`.

### S3 storage classes and archive restoration

General-purpose objects accept `STANDARD`, `STANDARD_IA`, `ONEZONE_IA`,
`INTELLIGENT_TIERING`, `GLACIER_IR`, `GLACIER`, `DEEP_ARCHIVE` and
`REDUCED_REDUNDANCY`. Object versions and pending uploads retain the chosen class.
The omitted class means `STANDARD`; copy does not inherit its source's class.
An omitted-class self-copy can therefore change an infrequent-access object to
`STANDARD`, while an unchanged implicit standard self-copy is rejected. Explicit
class headers alone contribute the `s3:x-amz-storage-class` IAM condition.
Nonstandard Put/Copy/Head/Get headers, listing classes and multipart inheritance
follow the native captures. Listings retain composite multipart checksum types.

`GLACIER` and `DEEP_ARCHIVE` payloads require a completed, unexpired restore.
HEAD, attributes and metadata remain available under their own permissions.
Read/copy conditions and ranges precede cold-payload rejection; future
If-Modified-Since dates are ignored. Native copy-source errors retain their
source-specific message and `StorageClass` XML member.

For `GLACIER` and `DEEP_ARCHIVE`, `RestoreObject` uses its own authorization,
not GetObject permission. New work
returns 202, duplicate pending work returns 409, and already-restored requests
return 200 while extending or shortening expiry. In-flight upgrades require a
faster tier and the original Days value; missing Days is malformed and changing
Days remains a conflict. The selected version, pending work, tier, deadline and
publication parent survive SQLite reopen. Restore never changes the archived
version's bytes, class, modification time or identity. A permanent copy owns its
own class and does not inherit the source's temporary restore state.

Local service-time completion delays are five minutes/four hours/twelve hours for
GLACIER Expedited/Standard/Bulk, and twelve/forty-eight hours for DEEP_ARCHIVE
Standard/Bulk. They are deterministic choices within documented retrieval ranges,
not AWS latency promises. Expiry adds Days to the persisted completion instant
and rounds up to UTC midnight. A later 200 request recalculates from request time.
One large clock advance and smaller advances use the same completion/expiry
boundaries. Expired bytes become unavailable even before the expiration job drains.

Classic Post/Completed publications preserve the original object sequencer.
Direct restore events omit that sequencer. Completion uses the native service
identity, source storage class and expiry fields; direct completion omits source
IP. Each measured 200 update emits another initiation publication. Restore API
outcomes are CloudTrail data events with the submitted XML RestoreRequest,
actual 200/202/409 accounting and null responseElements. Background completion
and expiry do not fabricate public RestoreObject calls.

`testdata/aws/s3/storage_class_evidence.json.gz` retains class and conditional-read
captures plus measured CLI checksum/list transport defaults.
`restore_evidence.json.gz` retains native controls, authority, completed plaintext
reads, positive classic/direct deliveries, delivered CloudTrail gzip and the
supplemental speed-upgrade experiment. Compact fixtures reuse the shared SDK/raw
replay on memory and SQLite. Credential-bearing debug logs are not retained.
All owned native objects, buckets, roles, queues and trails were removed; the
upgrade experiment's CLI-only GET failures are exclusions, not AWS responses.

The real executable verified a 162-byte binary restore, independent STS read
denial, multipart class/composite-checksum recovery and two SQLite process
restarts. A 23:59 completion drained after midnight still expired on the correct
day. Classic SQS, direct EventBridge-to-SQS and actual CloudTrail gzip delivered
the restore outcomes. Later expiry preserved a readable permanent copy and
allowed a new restore. Executable expiration checks follow the documented
contract: native expiration itself was not observed.

Native slow-tier and maximum-int32-Days completion remain unmeasured, as does
broader audit/access-log behavior. Active objects reject RestoreObject before
body validation; archived SELECT requests retain the measured 405 rejection
rather than pretending to execute a query. Intelligent-Tiering has the distinct
permanent restoration contract below. These prerequisites do not complete S3.

Primary contracts: [RestoreObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html),
[restore state and speed upgrades](https://docs.aws.amazon.com/AmazonS3/latest/userguide/restoring-objects.html),
[retrieval tiers](https://docs.aws.amazon.com/AmazonS3/latest/userguide/restoring-objects-retrieval-options.html),
[classic notifications](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html)
and [direct event structure](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-events.html).
Replication destination storage-class overrides reuse these version-owned
class/restore contracts rather than a second data plane.

### S3 Intelligent-Tiering

The generated `Put/Get/DeleteBucketIntelligentTieringConfiguration` and
`ListBucketIntelligentTieringConfigurations` operations retain typed configurations.
Native PUT/DELETE return 204; deleting a missing configuration returns
`NoSuchConfiguration`. IDs accept 1–64 ASCII letters/digits, hyphen, underscore
or period. Query/XML ID mismatch is malformed XML. The 1,000-configuration quota
allows replacement at capacity; lists return 100 lexically ordered entries per
page. GET with an absent/empty ID selects LIST; malformed mutation selectors
never fall through to bucket creation/deletion. Generated binding owns required
members/enums, while S3 owns native cross-field errors and configuration limits.

Get/List use `s3:GetIntelligentTieringConfiguration`; Put/Delete use
`s3:PutIntelligentTieringConfiguration`. Cross-account identity and bucket grants,
explicit denials and expected-owner checks use the shared evaluator.

Eligible versions are at least 128 KiB. Publication, successful GET, copy-source
access, completed multipart publication and restoration establish a new access
window. Website GET participates; HEAD, lists and tag reads do not. Live replication
does not touch the source's access window. The daily worker evaluates current
configuration/filter tags and moves idle objects into optional Archive Access
(90–730 days) or Deep Archive Access (180–730 days, later than Archive Access when
both occur in one configuration). Removing or disabling rules does not unarchive
existing objects. Versions, ciphertext, completed parts, checksums, ETag,
LastModified and `INTELLIGENT_TIERING` storage class remain unchanged.

HEAD exposes `ArchiveStatus`; archived GET/copy failures include `AccessTier` and
`StorageClass`. Archive restoration omits Days, uses the shared retrieval-tier
delays and returns permanently to active access. It has no temporary-copy expiry
or restore-deletion event. Active objects reject restoration before body
validation, including malformed tier/SELECT input, without borrowing GetObject
authority. Lifecycle eligibility also respects the current access tier: Archive
Instant excludes One Zone-IA, Archive Access permits Glacier/Deep Archive, and
Deep Archive Access permits only Deep Archive.

Archive transitions commit classic `s3:IntelligentTiering` event-version 2.3
publications and direct `Object Access Tier Changed` events with their destination
access tier. They do not fabricate CloudTrail API calls. Real API outcomes still
reach configured data selectors; the long-idle delivery workflow drains those
records before CloudTrail's retained delivery budget expires.

`intelligent_tiering_control_evidence.json.gz` and
`intelligent_tiering_authority_evidence.json.gz` under `testdata/aws/s3` retain
1,373 native observations; compact replays exercise 1,316 calls on memory and
SQLite. Seven document-derived workflows cover access windows, live filters,
versions, copy/multipart ownership, retrieval tiers, Lifecycle compatibility and
actual SQS/EventBridge/CloudTrail delivery. A real executable/CLI run retained a
131,072-byte binary object through SQLite reopens, verified website GET versus
HEAD aging, recovered pending restoration, and observed unchanged identity,
metadata, checksum and bytes without expiry or a deletion notification.

These local daily scans and retrieval delays are not measured AWS completion
SLAs. Native 90/180-day transitions, archived Intelligent-Tiering restore
completion and broader tiering audit/log projections remain unmeasured. All
owned native buckets, object versions/markers and the temporary authority role
were independently confirmed absent; existing organization roles were untouched.

Primary contracts:
[access and tiering](https://docs.aws.amazon.com/AmazonS3/latest/userguide/intelligent-tiering-overview.html),
[configuration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketIntelligentTieringConfiguration.html),
[restoration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html),
[Lifecycle compatibility](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-transition-general-considerations.html)
and [replication interaction](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-requirements.html#replication-and-intelligent-tiering).
The pinned SDK revision `113bc91bf12edc3af1d3aba1c70be28494d54c2a`
supplies the wire contracts.

### S3 request metrics

The four generated bucket metrics-configuration operations retain typed optional
prefix, tag, access-point and `And` filters. Replacement removes omitted filters;
bucket deletion removes configurations. Native fixtures establish ID syntax,
strict metrics XML roots, malformed-filter precedence, missing configurations,
expected-owner checks, explicit IAM denial and cross-account bucket-policy
authority. Get/list require `s3:GetMetricsConfiguration`; put/delete require
`s3:PutMetricsConfiguration`. Listings are ID-ordered, 100 configurations per
page, with stable cursors across earlier/marker deletions and later insertions.
The documented 1,000-configuration quota permits replacement at capacity; this
boundary was exercised locally, not by provisioning 1,001 native configurations.

The existing request-accounting observer measures actual S3 HTTP response status,
consumed request bytes, response bytes and first/total latency. Source-owned
publication uses `AWS/S3`, `BucketName` and `FilterId` in the bucket owner's
account/region. Callers need no CloudWatch permission. CloudWatch alone retains
samples and owns statistics, percentiles, math and alarm evaluation. Individual
samples preserve request populations; there is no S3 metric ledger or second
aggregation scheduler.
Only object operations and bucket-content lists are eligible; the primary
configuration contract excludes other bucket operations, including `HeadBucket`
and `GetBucketLocation`.

Native publication establishes:

- `AllRequests` and the applicable method/list counter count eligible requests;
  operation counters are sparse. `4xxErrors` and `5xxErrors` retain a zero or one
  sample per counted request, rather than emitting only failures.
- Any filter excludes bucket-content lists and multi-object deletes; `ListParts`
  remains single-key/filter eligible. Access-point predicates use the resolved
  access-point ARN, not the bucket name or caller account.
- Same-bucket copy includes its internal source GET in request populations.
  Internal copy reads contribute no invented network bytes or total-request
  latency, and do not inherit source tag-filter matches.
- Multipart initiation can select supplied tags. Parts, part lists, abort and
  completion do not match pending/completed object tags. The outer multi-delete
  counts once, but contributes neither its XML request nor response bytes.
- Missing/range failures contribute actual error-response bytes and total
  latency, not a successful first-byte sample. Successful tag mutation selects
  the accepted resulting tags; failure does not select uncommitted replacements.

Control events use CloudTrail's native list name `GetBucketMetricsConfiguration`,
correct read-only classification and the `metrics`/ID query markers. XML filter
payloads are not copied into request parameters; response elements are null.
Actual consumed control bytes are recorded after admission, so an explicitly
IAM-denied put records zero bytes rather than the submitted XML length.

`request_metrics_control_evidence.json.gz` retains the native configuration
capture; its compact replay executes 220 calls. The audit capture retains 318
native management-history records; its replay selects 77 calls and correlates
73 of those records through the local delivered trail.
`request_metrics_data_evidence.json.gz` retains 534 observed CloudWatch datapoints.
Fourteen publication phases check 189 metric expectations and 38 latency
populations on memory and SQLite, including a retained reopen. Explicit wire-byte
projections substitute actual local XML/error lengths without changing native
sample populations. The executable/CLI run separately verified scoped source
publication, denied direct metric writes, retained p50/p99 and statistics,
account/region isolation, quota/cascade behavior and real
alarm → EventBridge → SQS delivery after SQLite restart.
The metadata supplement retains 14 measured raw calls across three phases, with
61 positive metric expectations and 16 latency populations. It covers ACLs,
object tags, ordinary/exact-version deletion, multipart abort, attributes,
retention and legal holds, including duplicate-tag rejection with its native
`TagKey` error member. A captured
four-minute aggregate resolves shifted native success/error timestamps without
synthesizing statistics. Empty deletion-tag and other first-byte series are not
turned into omission guarantees.
All four replay projections regenerate offline from their retained captures.
Owned native buckets and the data probe's access point were independently
confirmed absent; existing organization roles were not modified.

Request metrics are opt-in and best effort. Accepted local configurations apply
immediately; native delayed publication, shifting timestamps and old-filter
points after replacement do not establish a deterministic activation/cutover
deadline. No artificial 15-minute timer or deletion tombstone is retained. Native
captures did not induce a positive server error. Daily storage/Storage Lens
metrics and unsupported Select data-plane counters are separate prerequisites,
not fabricated request samples.
The executable's unsupported Select call returns `NotImplemented` and contributes
`SelectRequests`/`5xxErrors`, not `PostRequests` or invented scanned/returned bytes.
This also reproduced and fixed canonical SigV4 query sorting: encoded names
must sort before their values, rather than sorting joined `name=value` strings.

Primary contracts:
[configuration API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketMetricsConfiguration.html),
[metric definitions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html),
[filters](https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-configurations-filter.html),
[request configuration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-configurations.html)
and [configuration deletion](https://docs.aws.amazon.com/AmazonS3/latest/userguide/delete-request-metrics-filter.html).
The pinned SDK revision `113bc91bf12edc3af1d3aba1c70be28494d54c2a` supplies
generated contracts.

### S3 Inventory

The generated `PutBucketInventoryConfiguration`,
`GetBucketInventoryConfiguration`, `ListBucketInventoryConfigurations` and
`DeleteBucketInventoryConfiguration` operations retain typed configurations on
memory and SQLC SQLite. Optional-field order/duplicates and absent versus empty
lists survive replacement and restart. The quota is 1,000 configurations per
bucket; lexical 100-item pages preserve insertion/deletion behavior at cursors.
Native fixtures cover required XML, strict boolean admission, IDs, error
precedence, destination/KMS ARN syntax, owner checks and cross-account authority.
Admission does not preflight destination existence, region, account or key use.

`s3:InventoryAccessibleOptionalFields` is the submitted multivalue PUT context;
DELETE has no field set. The existing generated IAM catalog also supplies
action/condition applicability for bucket policies: an explicit unsupported
action fails admission, while a wildcard can match a supported alternative.
Eight additional native policy probes cover this distinction, including
Inventory and `s3:prefix`; the owned probe bucket was independently absent
after cleanup.

Configurations and their API events commit together. Enabled configurations
retain a next-report deadline and parent event identity. Local first delivery is
the next UTC midnight; subsequent reports are daily or on Sunday UTC for weekly
configurations. AWS documents up to 48 hours for first delivery, not this exact
local schedule. Disable/delete cancel pending occurrences; replacement fences
old completion. An already-running snapshot can finish one final report.
Failures remain diagnosable in delivery logs and are retried at the next
occurrence; interruption leaves the selected occurrence eligible. These are
local scheduling/recovery choices, not captured AWS retry timing.

One repository view selects prefix-filtered Current or All-version metadata in
bounded pages, preserving null versions and latest/delete-marker identity across
page boundaries. This does not call List/Get APIs, decrypt payloads or change
access-tier clocks. Reports project retained ownership/original ACLs (including
under `BucketOwnerEnforced`), checksums, encryption, replication, storage/access
tier and protection metadata; expiration reuses Lifecycle's predicates/calendar.
Object Lock event-hold dates use the report instant rather than a stored stale
retention date.

CSV is real GZIP with URL-encoded keys. Parquet is real Snappy with ordered typed
columns, nulls and millisecond timestamps. ORC is Apache ORC 2.2.2 with ZLIB, run
as a short-lived, network-disabled Java 17 container through the small
`InventoryORCEncoder` interface. Build the installed image with:

```sh
docker build -t stackd/orc:2.2.2 engine/orc
```

CLI `-docker-host` constructs this dependency; embedding supplies
`stackd.Config.InventoryORC`. The driver resolves an installed immutable image,
copies metadata-only NDJSON, executes the upstream writer and removes its owned
container. It does not pull images at runtime or substitute another format.
Absent encoding support fails the report with a diagnostic, not an empty success.
The rejected pure-Go writer decoded sequentially but failed independent indexed
reads; the native writer passed PyArrow scans and PyORC seeks at 0, 1, 10,000 and
220,003 rows, including nulls, large integers, timestamps and unusual keys.

Data files, manifests, Hive symlinks and native MD5 manifest checksums are actual
S3 objects. Checksum publication is last. Each write uses `s3.amazonaws.com`,
the source ARN/account, bucket-owner-full-control and the originating event.
S3 owns current destination policy/ownership, encryption, notifications, audit
and metrics; Inventory adds only delivery-time same-region/account checks.
Destination defaults apply unless configuration encryption overrides them.
Customer-managed KMS policies can authorize the direct service principal.
AWS-managed `aws/s3` cannot: S3 using its own principal must not acquire
`kms:ViaService`. S3 forwarding an ordinary caller or the distinct CloudTrail
service principal retains that condition. This is fixed at the shared KMS context
boundary, not by special-casing key aliases in Inventory.

Native evidence and archive-only normalizers live in
`inventory_control_evidence.json.gz` and `inventory_audit_evidence.json.gz`.
Six control scenarios include quota/pagination and settled policy conditions;
the audit replay has 180 positively correlated expectations. LIST uses the
native `GetBucketInventoryConfiguration` history name. Inventory history is not
indexed by bucket resource name; responses are null. Parsed submitted XML,
namespace declarations, lexical scalar coercion and empty query-member presence
remain observable even for rejected documents.
`inventory_execution_replay.json` covers both stores through SDK consumers,
retained cancellation/replacement, weekly recurrence, policy/key recovery and
cross-account ownership. The actual executable delivered six empty/nonempty
CSV/ORC/Parquet reports through KMS and S3→SQS completion notifications.
After process restart, independent readers verified 1,005 All-version rows,
including a 1,001-version key crossing a metadata-page boundary, a replaced
Current report and persistent disable/delete cancellation.

No native physical Inventory report was captured. Exact optional-cell/null/schema
conventions, newer field physical types, eventual snapshots and broad
delivery/failure/propagation timing remain unverified against AWS. These
document-derived reports and native control fixtures do not establish complete
S3 parity.

Primary contracts:
[configuration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketInventoryConfiguration.html),
[Inventory contents](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory.html),
[files and manifests](https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory-location.html),
[ACL fields](https://docs.aws.amazon.com/AmazonS3/latest/userguide/objectacl.html),
and [KMS forward-access conditions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html#conditions-kms-via-service).
The pinned SDK revision `113bc91bf12edc3af1d3aba1c70be28494d54c2a` supplies
generated shapes, not native report guarantees.

### S3 storage-class analytics

The generated Put/Get/Delete/List analytics configuration operations retain typed
definitions in memory and SQLC storage. IAM and expected-owner checks precede
admission; malformed PUT bodies do not bypass authorization. Replacement is atomic,
the 1,000-configuration limit permits replacing an existing ID, and list pages hold
100 lexically ordered IDs with scoped continuation cursors. Missing reads and
deletes return `NoSuchConfiguration`, rather than treating deletion as success.

Filters preserve single-prefix, single-tag and ordered `And` predicates, including
duplicate or contradictory tag predicates. Native boundary captures require
nonempty tag keys/values with maxima of 128/256 UTF-16 units and the shared S3 tag
character grammar. Analytics accepts `aws:` keys; object-tag reserved-prefix and
duplicate-key rules therefore do not belong in this parser. Invalid replacement
leaves the preceding definition unchanged. Export destinations retain the supplied
ARN, optional account and prefix; configuration admission does not assert that the
destination exists or that later delivery will be authorized.

`analytics_controls_evidence.json.gz` and `analytics_controls_replay.json` cover
native admission, IAM, quota and pagination. `analytics_boundaries_evidence.json.gz`
adds 67 observations and 57 replay calls covering representative ASCII/BMP/astral
lengths, independently invalid key/value characters and replacement atomicity.
These are sampled Unicode contracts, not an exhaustive character-set capture.
Both stores replay the fixtures. The actual SQLite executable retained the full
definition across process restart, including duplicate predicates and an unresolved
destination, then verified deletion and missing-configuration errors.

`analytics_audit_replay.json` contains 30 positively correlated native management
records replayed through configured classic-trail selection and actual gzip
delivery. LIST uses the native `GetBucketAnalyticsConfiguration` history name.
Submitted query members retain repeated values; XML configuration bodies and
response elements are not projected into these records.

Analytics measurement, history, recommendations and daily CSV export are **not
implemented**. Native export capture is pending. Configuration and audit evidence
does not establish report populations, formulas, file layout or delivery timing.
CloudWatch request metrics are not a substitute for analytics measurement.

Primary contracts:
[configuration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAnalyticsConfiguration.html),
[filters](https://docs.aws.amazon.com/AmazonS3/latest/API/API_AnalyticsFilter.html),
and [storage-class analysis and export fields](https://docs.aws.amazon.com/AmazonS3/latest/userguide/analytics-storage-class.html).

### S3 live replication

The generated `PutBucketReplication`, `GetBucketReplication` and
`DeleteBucketReplication` operations retain ordered typed rules, filters,
priorities, execution roles and destination controls. Source/destination
versioning, ownership assertions, KMS selection, metrics and RTC admission use
native control fixtures. `iam:PassRole` is checked at configuration admission;
the role is assumed when accepted work runs. Configuration changes do not rewrite
already accepted jobs, and enabling a rule does not backfill existing objects.

New eligible versions, delete markers and metadata changes commit work with their
source mutation. Delivery preserves version ID, modification time, ordering,
actual payload/parts, supported checksums, tags and applicable Object Lock state.
Destination class and ownership overrides are independent. A replica does not
inherit a source's temporary archive-restoration state; a cold source is not
admitted merely because a replication rule exists. Ordinary replicas do not
chain into another replication rule. Replica-modification rules govern reverse
metadata changes.

Delivery uses a real S3 execution-role session and the shared IAM evaluator.
Source reads, ACLs, tags and protection metadata retain distinct permissions;
destination writes and cross-account bucket authority remain separate. SSE-KMS
uses real Decrypt/Encrypt data-key rewrapping outside the S3 transaction, not
GenerateDataKey or plaintext object copies. An initial tag denial can leave a
readable untagged replica and FAILED source while the object copy itself counts
as successful: it does not invent an OperationFailedReplication notification.
Tag predicates gate both initial admission and subsequent metadata updates.
Adding a matching tag to an initially excluded object does not invent backfill.

Per-component outcomes expose PENDING, COMPLETED, FAILED and REPLICA. Transient
dependency failures retain retry work; terminal denials do not silently resume
after policy repair. Explicit source-version removal cancels its outstanding
work. Classic replication failure/RTC notifications use the existing publisher;
they are not fabricated as direct EventBridge object events. Ordinary object
changes still produce their applicable classic/direct events. Changed ACLs emit
ObjectAcl:Put without size/sequencer; the captured exact-repeat ACL does not.

Metrics retain minute observations and processed/failure counts. Gauges use the
destination Region and source account; failed-operation counts use the source
Region/account. Native failed-operation statistics use the failure total as both
extrema while SampleCount counts processed operations; no arithmetic clamp
rewrites that observation. RTC delays publication for fifteen minutes after
enablement without dropping earlier samples. Retained scheduling separates that
visibility deadline from sampling and from the per-object RTC deadline.
Replacing configuration updates future unsampled/counterless schedules; already
accepted observations retain their publication deadline.

`replication_{control,flow,authority,read_alias,tag_alias,tag_filter}_replay.json`
replays the captured controls and data/authority transitions on memory and SQLite.
Corresponding gzip evidence retains raw observations; payload evidence includes
actual downloads rather than caller-supplied byte descriptions.
`replication_signals_replay.json` covers native failure payloads, partial-tag
outcomes and regional/statistic distinctions. The direct EventBridge negative
control in that replay is a local extension, not a captured native sink.
`replication_audit_replay.json` compares actual delivered CloudTrail gzip records
for internal role reads, writes, metadata, markers and a KMS-denied source read.
Its native records establish same-account/us-east-1 audit behavior, not complete
cross-account/Region audit fidelity or internal network/header encoding.

Fresh direct-object and replica tag-disclosure evidence verifies destination
tags exist before denied HEAD/GET requests: tag counts remain absent until the
bucket policy grants tagging authority. All twelve captured replica downloads
match the actual binary payload. One older uncorrelated GET reported TagCount
despite earlier denial. Its raw field remains preserved and explicitly excluded
from assertions; its cause is unresolved, not a permissionless replica exception.

The executable upgrade from the archive checkpoint preserves existing encrypted
versions, ACLs, tags, metadata, protection, completed parts, an unfinished upload
and a pending archive restore through schema 122 and two reopenings. The old
upload completes with its actual 5,244,661-byte payload; the restore completes
through the public clock control. A new replicated version retains identity and
decrypted bytes across restart. That workflow populated six rebuilt child tables.
A fresh old-binary SSE-KMS control also populates the encryption-context child:
the latest executable preserves its two context entries and exact 283-byte payload
through migration and another restart. The same executable withholds a real
failed-replication counter through 14m59s, publishes it at 15m with its original
minute timestamp, and does not duplicate it after another clock advance.
These upgrades are not backfill proofs.

The fifteen-minute missed/late and no-longer-tracked scenarios are explicit
document-derived local tests using a real KMS backend commit outage and recovery.
There is no positive native fifteen-minute RTC capture or AWS latency/exactly-once
claim. Batch Replication, native Inventory replication-cell conformance and broader
archive-tier interactions, conflict/propagation behavior, internal transport
accounting and additional native audit/server-log projections remain outside
this evidence.

Primary contracts: [replication scope](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-what-is-isnot-replicated.html),
[requirements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-requirements.html),
[KMS replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-config-for-kms-objects.html),
[metrics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/repl-metrics.html)
and [replication events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-metrics-events.html).

### S3 Lifecycle

The generated `PutBucketLifecycleConfiguration`,
`GetBucketLifecycleConfiguration` and `DeleteBucketLifecycle` frontend retains
ordered rules in typed memory and SQLC repositories. GET requires
`s3:GetLifecycleConfiguration`; replacement and deletion require
`s3:PutLifecycleConfiguration`. Expected-owner checks and cross-account identity
plus bucket-policy grants remain separate. Missing configuration returns
`NoSuchLifecycleConfiguration`; deletion is idempotent. Admission failure leaves
the previous configuration intact.

Native captures retain legacy Prefix versus modern Filter exclusivity, empty
filters, And/tag/size combinations, omitted generated IDs, rule ordering and the
1,000-rule limit. Size bounds are exclusive. Explicit false
`ExpiredObjectDeleteMarker` is accepted, but either boolean spelling excludes
tag/size filters, as does incomplete-upload abortion. Native AWS accepted
`NewerNoncurrentVersions=101` and single IA transitions below thirty days;
document-only stricter limits are not imposed. Same-rule expiration must be
later than its transition, and multi-transition class/spacing constraints remain
distinct. Replacing without the minimum-size header resets the default to
`all_storage_classes_128K`, including after `varies_by_storage_class`.

The daily executor applies to existing and future versions. Days are calendar
days followed by the next UTC midnight; Date actions use their admitted midnight.
It evaluates at each retained scan deadline, not the final advanced clock horizon.
Current unversioned objects expire permanently; versioned buckets acquire a new
marker, and suspended buckets replace the null slot. Noncurrent eligibility uses
the successor timestamp and optional newer-noncurrent count. Permanent deletion
takes precedence over transition, which precedes current marker creation.
Protection blocks permanent deletion, not marker creation or transition.
`PENDING` and `FAILED` replication block expiry and transition. The executor
does not impersonate public DeleteObject authority or replicate its new markers.
Expired sole markers and eligible incomplete uploads are removed by their owning
repository operations.

Transitions preserve version identity, modification time, encryption, completed
parts, checksums and bytes. The 128 KiB default, legacy archive-class exception and
explicit size-filter override use the retained configuration. Current-object
expiration headers cover matching writes, reads, copies and multipart completion;
explicit VersionId suppresses the header even when selecting the current or null
version. Current tags and rule replacement affect the header without requiring
GetLifecycleConfiguration permission. The earliest deadline wins; equal-deadline
rule-ID selection is not established by the native sample.

State changes, scan advancement and ordinary notification/access-log intents
commit together. Classic Lifecycle expiration/transition records use the
documented 2.3 shape, including nested
`lifecycleEventData.transitionEventData.destinationStorageClass`; direct
EventBridge emits Object Deleted or Object Storage Class Changed with the S3
requester, not a fabricated source IP. Internal changes do not create CloudTrail
DeleteObject, CopyObject or AbortMultipartUpload records. Access logs use the
documented `S3.EXPIRE.OBJECT`, `S3.CREATE.DELETEMARKER`, transition-class operations
and `S3.DELETE.UPLOAD`. Unmeasured internal caller/HTTP/timing fields remain `-`;
these are not captured native full-record projections.

`testdata/aws/s3/lifecycle_control_evidence.json.gz` and
`lifecycle_header_authority_evidence.json.gz` retain 539 observations and their
source revisions. Their compact manifests replay 442 selected calls, including
binary GETs, separate owner/member authority and retained rejected-write state.
Captures preserve propagation anomalies rather than treating immediate GET as
an authoritative settled write. One literal special-ID GET header differs from
the otherwise observed escaping and remains evidence-only. All owned native
buckets and the temporary role were removed and independently checked absent;
the existing member role was not modified.

`lifecycle_execution_replay.json` is explicitly document-derived: twelve SDK
scenarios and three retained delivery workflows cover version/null transitions,
live tags/size filters, lock and replication barriers, incomplete uploads,
archive reads/restoration, KMS/multipart bytes and actual SQS/EventBridge delivery.
CloudTrail gzip contains the real PutObject positive control but no invented
lifecycle object API. A suspended-history regression failed on both stores
before correcting stale null-slot selection. A separate 1,001-version scenario
checks deletion across the scan cursor. The actual SQLite-backed executable
retained configuration and pending work across two restarts, preserved binary
bytes/checksums through transition, then emitted transition, marker-created and
permanent-delete SQS events while removing the exact noncurrent version.

These execution checks are not native physical-completion observations, latency
guarantees or exactly-once claims. Native worker scheduling, broader propagation,
and full lifecycle access-log records remain incomplete. Intelligent-Tiering
archive automation is described above; these operations do not establish complete S3 parity.

Primary contracts: [rule elements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html),
[expiration](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-expire-general-considerations.html),
[transitions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-transition-general-considerations.html),
[conflicting rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-conflicts.html),
[other bucket features](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-and-other-bucket-config.html)
and [Lifecycle notifications](https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configure-notification.html).

### S3 object copies

`CopyObject` uses a detached snapshot of the selected source version, ciphertext,
metadata and tags. Source reads, KMS effects and the separately recorded internal
read occur outside the destination transaction. The final destination authority,
conditional-write check, new version, metadata, tags, API outcome and configured
object publications commit together. Failed copies leave destination bytes,
tags and version history unchanged.

Source selection distinguishes current reads from explicit versions, including
`versionId=null`, and applies the corresponding object/tag IAM actions. COPY
requires source tag-read authority when the selected version has tags; REPLACE
uses the supplied set, with an omitted set clearing tags. Nonempty destination
tags require `s3:PutObjectTagging` in addition to object-write authority. Metadata
COPY ignores replacement metadata; REPLACE clears omitted metadata and uses the
native binary content type when absent. Website redirects are explicit-only,
not inherited, and survive schema 111 storage/reopen. Checksums are retained or
recomputed for an explicitly selected algorithm.

Copy-source parsing separates the raw version query before one form decode:
spaces, literal plus signs, escaped question marks and fully escaped bucket/key
headers retain their native distinctions. Current delete markers return
`NoSuchKey`; explicit markers return `InvalidRequest`. Malformed version IDs
return `InvalidArgument`, while valid foreign, deleted, missing-key and absent
null versions return `NoSuchVersion`. Implicit null sources omit the source
version response header; explicit null selections retain it.

Implicit self-copy requires a qualifying change, including an omitted-class
change from a nonstandard source to STANDARD, metadata REPLACE, or explicit
encryption, storage class or redirect. Tag-only, checksum-only and
annotation-EXCLUDE-only requests do not qualify. Explicit current/older source versions
are permitted. Source ETag predicates take precedence over paired date predicates.
Destination predicates are admitted before source reads, then rechecked at
publication. Predicate rejection precedes source reads; an intervening destination
generation yields `ConditionalRequestConflict` at publication. This is not a
historical ABA-detection guarantee.

Destination encryption belongs to the destination bucket/defaults or explicit
request, not the source. GenerateDataKey precedes source authority/predicate
checks; source predicates precede Decrypt; source KMS failure precedes destination
PutObject denial. These independently committed KMS outcomes are not undone by
a failed copy. Source and destination checks retain the original caller and
their distinct S3 forward-access contexts.

Copies produce `ObjectCreated:Copy` classic notifications and native EventBridge
Object Created events, not synthetic PutObjectTagging calls. Captured classic
`hasObjectAnnotation` and EventBridge `has-object-annotation` are false. CloudTrail
receives the outer CopyObject and a separately identified AWS Internal GetObject
after destination-predicate admission, including source failures. The internal
read shares the outer HTTP extended request ID, not its request ID; classic
notification host IDs remain independent. Internal reads report zero transferred
bytes; failed reads also report zero object size. A source-predicate error can
retain internal HTTP 200 while the outer call returns 412. Outer success/error
byte counts use the actual serialized response.

Generated metadata, tagging, annotation and checksum enum rejections are also
delivered to matching object-scoped trails. S3 uses the generated HTTP binder
for an observation-only input; rejected commands are never admitted. Native
destination bucket/object resources, source header and Host are retained, while
directive values, tags and metadata remain redacted. Native InvalidArgument
responses retain ArgumentName/ArgumentValue. The five early-rejection controls
had no internal source read during the bounded native observation window.

The owned 2026-09-20 captures in `000000000000`, `us-east-1`, are
`copy_controls_evidence.json.gz`, `copy_encryption_evidence.json.gz`,
`copy_events_evidence.json.gz`, `copy_supplement_evidence.json.gz`,
`copy_self_version_evidence.json.gz`, `copy_missing_version_evidence.json.gz`
and `copy_rejections_evidence.json.gz` under `testdata/aws/s3/`.
Compact control, encryption, supplemental, delivery and
audit fixtures replay their correlated outcomes on memory and reopened SQLite.
The bounded encryption capture recovered GenerateDataKey observations but no
Decrypt observations; that does not establish that Decrypt is never logged.
An executable schema 110→111 upgrade and second restart retained encrypted
version selection, copied tags/metadata/redirects, conditional-write exclusion,
both SQS event routes and actual decompressed CloudTrail records.
An additional executable replay delivered source/destination predicate failures,
a missing source version and a generated enum rejection to the scoped trail;
their recorded response lengths matched the actual HTTP bodies.

Owned native buckets, versions, roles, queues, rules and trails were removed.
The copy probe's customer KMS key
`76668f72-b6d4-4073-89c0-64f6518de0e3` remains in AWS's required PendingDeletion
window, scheduled for 2026-09-27; the pre-existing `aws/s3` key was not changed.
Other access-point families, directory buckets, non-standard storage
classes and the other S3 gaps below remain unsupported rather than acquiring fake
copy behavior. Ordinary regional AP copy authority is described above.

Primary contracts: [CopyObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html),
[copying objects](https://docs.aws.amazon.com/AmazonS3/latest/userguide/copy-object.html)
and [conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html).

### S3 checksums

The shared payload paths implement CRC32, CRC32C, CRC64NVME, MD5, SHA1, SHA256,
SHA512, XXHASH64, XXHASH3 and XXHASH128. Smithy-derived typed checksum accessors
replace handwritten field switches across object writes, copies, multipart
commands, reads and attributes. S3 owns admission and negotiation; the shared
checksum package owns digest calculation over decoded plaintext bytes.
XXHash uses seed zero and canonical big-endian encoding; XXHASH128 is XXH3_128
with its high 64-bit half first.

PutObject infers the algorithm from a supplied checksum field when the SDK
algorithm header is absent. Multiple fields, a conflicting algorithm, and
present-empty or malformed values return `InvalidRequest`; a correctly encoded
incorrect digest returns `BadDigest`, without replacing the prior object.
GetObject/HeadObject checksum mode exposes the stored digest/type; ranges omit
them, while PartNumber reads expose the selected part checksum. Copies preserve
the source algorithm unless overridden and calculate a full-object checksum,
including when the source is multipart.

Multipart FULL_OBJECT supports CRC32, CRC32C and CRC64NVME. Other algorithms use
COMPOSITE: hash the concatenated binary part digests and append `-N`. An upload
without an initiation algorithm may verify/echo an UploadPart transport checksum,
but its listings do not expose that checksum and its completion manifest cannot
claim it as an initiated checksum. Without explicit initiation, completion
headers for MD5/SHA512/XXHash return `InvalidRequest`; legacy
CRC32/CRC32C/SHA1/SHA256 headers are accepted but ignored. Header admission and
per-part XML validation are separate contracts.

`checksum_algorithms_object_evidence.json.gz` and
`checksum_algorithms_multipart_evidence.json.gz` retain 354 native observations,
actual consumed response bytes/digests and capture/normalization sources.
Their 326-call SDK/raw fixtures run on memory and SQLite, including SSE-C,
existing AWS-managed S3 KMS encryption, copy replacement, two-part aggregation,
negative nonmutation and exact completion retries. CLI numeric pagination markers
normalize to the Go SDK's modeled strings. One CLI-transformed multipart error
retains its observed `InvalidPart` code without asserting an uncaptured wire
status. All five owned native buckets were independently confirmed absent.
Multipart scenarios retain the three captured bucket lifetimes rather than
recreating a full stack per algorithm; all 193 multipart consumer calls and their
assertions remain intact, with only 21 duplicated bucket-creation prerequisites
removed.

The trusted-HTTPS executable retained pending encrypted XXHASH128 parts through
restart, completed and read 5,242,900 exact bytes, and copied them to a full-object
XXHASH3 digest. Ordinary XXHash versions also retained their bytes/digests.
A second reopen preserved checksum/byte reads and explicit-checksum SSE-C key
admission; the exact completion retry returned the original identity without
checksum fields.
An authenticated `aws-chunked` trailer succeeded; a bad replacement was rejected
without mutation. Seven object outcomes reached EventBridge/SQS and 18 data
records were consumed from an actual CloudTrail S3 gzip log. These are exercised
workflows, not a claim of complete S3 conformance.

Primary contract: [S3 integrity and multipart checksum rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html).

### S3 multipart uploads and attributes

`CreateMultipartUpload`, `UploadPart`, `UploadPartCopy`,
`CompleteMultipartUpload`, `AbortMultipartUpload`, `ListMultipartUploads`,
`ListParts` and `GetObjectAttributes` use generated REST XML bindings and typed
repositories. An initiation freezes metadata, tags, encryption key/context and
checksum negotiation. Parts are independently encrypted and replace atomically;
rejected checksums do not replace an accepted part. Copy parts read the selected
source version/range with current source authority, then encrypt for the retained
destination upload. Pending uploads do not expose objects or creation events.

Completion validates the ordered manifest, selected ETags/checksums, nonfinal
minimum part size and negotiated checksum rules before publishing. The shared
[checksum contract](#s3-checksums) covers all ten modeled algorithms and their
composite/full-object combinations. An unconfigured upload retains native default
CRC64NVME behavior independently of a part request's transport checksum. Explicit
composite checksums require consecutive completed part numbers.

Selected ciphertext segments and their tags move to version ownership in the
publication transaction; completion does not decrypt/re-encrypt or concatenate
the payload. Metadata, version selection, part ownership, API outcome and
configured publications commit together. Reads, ranges, ordinary copies and copy
parts consume the same segmented data representation. CopyObject converts a
multipart source to an ordinary object's full-object checksum representation.
Schema 112 retains upload identity, ordered part metadata and ciphertext,
including reconstruction while an upload is pending and after completion.

Initiation ordering is distinct from later mutation ordering. With versioning,
completion retains the initiated version's order; an older initiation finishing
last does not become the newest object. Never-enabled/suspended histories preserve
the corresponding overwrite/delete distinction: an admitted older completion can
succeed and notify without replacing the currently visible object or deletion.
An exact successful manifest retry returns its retained version/ETag, omits the
completion checksum fields and does not republish. It uses the completed version
and part metadata, not a separate completion-receipt table. Missing/removed upload
identities and changed manifests retain native errors.

Upload and part listings preserve ordered markers, prefixes, delimiter grouping
and URL encoding. Valid upload markers remain usable after that initiation is
aborted. Ordering does not depend on different displayed initiation timestamps;
there is no cursor ledger. Ordinary version and multipart pagination are live
ordered views, not frozen snapshots across concurrent mutation.

Current IAM/session/resource policies apply at each command. Initiation with
nonempty tags needs tagging authority; later parts/completion do not repeat that
initiation-only permission. Initiator, bucket owner and delegated actors retain
their distinct native list/abort boundaries. KMS GenerateDataKey belongs to
initiation, outside S3 transactions. Part writes/copies require the retained key's
Decrypt authority. Default-checksum ListParts/completion differ from explicit
additional-checksum uploads, whose metadata paths require Decrypt. Key state,
alias retargeting and changed policies do not silently replace frozen encryption.

GetObject/HeadObject PartNumber selects the completed part ordinal, not a sparse
original upload number. GetObjectAttributes exposes requested fields only,
including component pagination and checksum-type distinctions; composite
attribute checksum values omit the completion/download part-count suffix.
Attribute access requires both the applicable current/version attributes action
and corresponding object-read action. For SSE-KMS, every selected attribute
subset requires Decrypt, even ETag-only requests; GenerateDataKey is not a read
permission. Current and explicit delete markers retain their native
404/405, version/delete-marker and Allow-header distinctions.

Only successful first completion produces classic
`ObjectCreated:CompleteMultipartUpload` and native EventBridge Object Created.
Parts, aborts and exact completion retries are not synthetic object creations.
UploadPartCopy records an independent AWS Internal source read. Multipart object
operations and GetObjectAttributes are data events; ListMultipartUploads is a
management read. Attribute audit parameters retain URI fields, not the requested
attribute or paging headers; response elements are null and objectSize is absent.
Completion retains an actual XML namespace declaration when present on the wire,
not an invented namespace reconstructed from the generated DTO.

An admitted InvalidPart can expose an unpublished version and SSE status only in
its audit response, without publishing an object or those HTTP headers. Error
audit byte accounting uses the actual local error serialization; HEAD accounts
for its logical error document despite an empty HTTP body. Native one-off
differences between delivered audit and wire byte counts do not establish a
universal adjustment. Request IDs, caller identity and public extended IDs remain
correlated without copying classic notification host IDs from the HTTP response.

The owned 2026-09-20 evidence under `testdata/aws/s3/` is
`multipart_controls_evidence.json.gz`, `multipart_authority_evidence.json.gz`,
`multipart_completion_evidence.json.gz`, `multipart_checksum_evidence.json.gz`,
`multipart_read_list_evidence.json.gz`, `multipart_events_evidence.json.gz`,
`multipart_attributes_kms_evidence.json.gz` and
`multipart_attributes_audit_evidence.json.gz`. Compact SDK/raw fixtures replay
controls, authority, exact consumer bytes, error argument presence and actual
notification/gzip delivery on memory and retained SQLite. The attributes capture
retains both bounded runs, transport failures and cleanup; an undelivered invalid
attribute request is not asserted permanently absent.

The actual executable retained a 5,242,905-byte encrypted multipart object across
pending and completed process restarts, rejected a corrupt replacement without
losing the original part, and enforced KMS on metadata-only attributes. Ordinary
copy and copy-part consumers read the retained segments. Three classic and three
EventBridge/SQS publications and 22 delivered CloudTrail records were observed.
These counts describe that workflow, not complete service/audit conformance.
An additional executable schema 111→112 upgrade retained three preexisting
encrypted versions/copies with exact bytes, checksums, tags, metadata, redirects
and wire-only HEAD encryption context. A new multipart copy consumed the old
encrypted version, preserved version order and retried completion after another
process restart.
Owned native buckets, objects, uploads, identities, rules, queues and trails were
removed; the authority and two attributes-probe customer keys remain in AWS's
seven-day PendingDeletion window, scheduled for 2026-09-27.

Primary contracts: [multipart overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html),
[completion](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html),
[part copy](https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html),
[checksums](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html)
and [attributes](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html).

### S3 bucket notifications

`GetBucketNotificationConfiguration` and `PutBucketNotificationConfiguration`
use the generated REST XML frontend. S3 owns configuration admission, event/filter
selection and retained work; `NotificationDestinations` adapts ordinary SNS
publication, SQS sends and asynchronous Lambda invocation. `NativeObjectEvents`
admits trusted `aws.s3` records to the bucket owner's default EventBridge bus,
without inventing customer `PutEvents` calls or conflating native object events
with CloudTrail API records.

Replacement validates every destination before changing the desired configuration.
SNS/SQS validation publishes real `s3:TestEvent` messages; Lambda checks invocation
authority without invoking customer code. A failed mixed replacement can therefore
send a valid destination's test message while preserving the previous configuration.
Skip-destination-validation bypasses only those external checks, not bucket authority,
rule syntax, region/FIFO restrictions, overlap checks or the shared 100-rule limit.
EventBridge enablement does not consume that limit. Filter names are case-insensitive
and GET returns `Prefix`/`Suffix`; the evidence-backed Smithy correction leaves that
validation with S3 rather than rejecting native-accepted names in the decoder.
Event tokens remain generated-model validated. Prefix/suffix values retain their
wire spelling and use decoded literal matching, not wildcard matching.

GET exposes the desired replacement immediately. A retained service-time deadline
adopts it for subsequent objects, preserving the previous applied configuration
until then. The current one-minute interval is a deterministic local choice,
**not an AWS propagation SLA**. Both configurations and the deadline survive
SQLite reopen. Object publication/deletion, its API observation, immutable classic
delivery snapshots and native EventBridge admission share the source transaction.
Destination commands execute outside it under the S3 service principal with the
bucket owner, `aws:SourceArn` and `aws:SourceAccount`. Current destination authority
is enforced independently; rejection cannot undo an accepted object write.
Accepted delivery work survives configuration replacement and bucket deletion.

The implemented producers are PutObject, CopyObject, first multipart completion,
DeleteObject, successful DeleteObjects members and object-tag replacement/removal. The owned captures use
classic event version `2.6`/S3 schema `1.0` and
EventBridge detail version `1.2`. Classic keys are form-escaped while preserving
slashes; EventBridge keys remain raw. Payloads correlate the source request,
object version, ETag and size where present. Delete-marker creation differs from
ordinary or exact-version deletion; missing-object deletes can still notify.
Multi-delete members share the request ID but receive ordered opaque sequencers.
Classic host IDs are not copied from the HTTP response: they differed in every
captured pair. Tests do not require exactly-once delivery or arrival order.

`testdata/aws/s3/notifications_controls_evidence.json.gz`,
`notifications_principal_evidence.json.gz`, `notifications_quota_evidence.json.gz`
and `notifications_delivery_evidence.json.gz` retain the owned AWS observations
and cleanup. Compact control/delivery manifests replay them on memory and SQLite,
including signed SNS fanout and real Python Lambda execution into SQS. An actual
executable verified schema 108→109, retained object reads, pending configuration
adoption, SNS/SQS/Lambda/EventBridge delivery, failed-replacement preservation and
pending removal across process restarts. Owned native and local resources were
removed after verification.

Transient producer retry cadence/terminal budgets and delivery matching for
admitted malformed percent escapes remain open. Current 5xx/429 attempts use
retained local backoff; other destination failures finish locally. The native
denial capture was bounded and does not establish an infinite no-retry guarantee.
Lifecycle producers are described above. Other unimplemented S3 operations do
not acquire fake producers merely because their event names are valid configuration.

Primary references: [configuration replacement](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketNotificationConfiguration.html),
[filtering](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-filtering.html),
[classic payloads](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-content-structure.html),
[native EventBridge payloads](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-events.html)
and [notification quotas](https://docs.aws.amazon.com/general/latest/gr/s3.html).

### S3 envelope encryption

PutObject, CopyObject and multipart uploads support SSE-S3 and SSE-KMS with actual AES-GCM object ciphertext.
SSE-KMS retains a KMS-wrapped data key, canonical key ARN and complete encryption
context per object version; aliases are resolved at write time, not read time.
Bucket encryption stores the configured identifier literally, including aliases
and nonexistent keys. Explicit object encryption overrides the bucket default.
Get/Put/DeleteBucketEncryption use the generated REST XML contract and the native
GetEncryptionConfiguration/PutEncryptionConfiguration IAM actions. Delete restores
AES256, disabled Bucket Keys and blocked SSE-C.

KMS owns key policies, IAM/session restrictions, grants and key state. The shared
service data-key adapter supplies regional `kms:ViaService` without replacing the
caller. S3 resolves the bucket before calling KMS outside its repository callback,
then authorizes and commits object publication and success audit together.
Conditional writes remain atomic. Native KMS failures precede PutObject policy,
checksum and precondition failures; GetObject preconditions precede Decrypt.
A denied PutObject can still produce a successful GenerateDataKey observation.
The failed S3 operation does not roll back that independently committed KMS attempt.

Native captures distinguish GetObject from HeadObject. Get, including ranges,
requires Decrypt. Head returns metadata without Decrypt unless checksums are
requested; denied or disabled-key checksum reads still return metadata but omit
checksums. GenerateDataKey denial does not prevent a permitted read. Supplied
context is Base64 JSON of string values; `aws:s3:arn` must equal the object ARN.
Native additional-context headers survive Put/Get/Head even where the SDK's
modeled output omits them; the implicit object ARN alone is not echoed. Explicit
BucketKeyEnabled:false is not echoed on object responses. SSE-KMS ETags are opaque,
not plaintext MD5; equal plaintext writes need not have equal ETags.

`testdata/aws/s3/kms_evidence.json.gz` retains three owned native runs in
`000000000000`, `us-east-1`, on 2026-09-19, plus conditional/checksum precedence,
management-history and cleanup-recovery captures. The third run includes 82
delivered S3/KMS events and actual primary/backup encrypted Firehose objects.
The first rejected backup interval zero; the second collector encountered
CloudTrail's empty prefix marker; the third encountered a transport failure
during cleanup. Separate recovery verified removal of owned trails, streams,
roles, aliases and buckets. Six owned customer keys remain in AWS's seven-day
PendingDeletion state; the pre-existing aws/s3 key was not modified.

Compact SDK replays exercise both repositories, current-role/session denials,
alias retargeting, default overrides, pending/disabled keys, failed-write
nonmutation and reconstruction of encrypted history. A fresh local account
creates its managed key through PutObject before the captured DescribeKey; the
native account already had that alias. The replay uses the same explicit
checksum-request policy as the native probe, not SDK-added request defaults.

The executable SQLite workflow delivered three primary and three backup records,
retained a denied primary while backup succeeded, recovered across two restarts
and inherited bucket KMS defaults under Firehose NoEncryption. Configured
CloudTrail delivered 306 records, including eight S3 PutObject outcomes and the
retained denied KMS attempt; EventBridge delivered nine matching events to SQS.
Native S3 forward-access KMS denials omit request parameters/resources. Their
service origin is retained without manufacturing AWS's opaque temporary FAS
credentials. Counts describe this workflow, not complete audit conformance.

References: [SSE-KMS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html),
[HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html),
[default encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html).
The observed Head checksum omission/GenerateDataKey distinction is narrower than
the generic permission guidance. Cross-account keys, native caching/propagation,
all negative bucket-configuration errors and opaque FAS session details remain
unverified; captured success/configuration cases do not establish those contracts.

### S3 customer-key encryption

SSE-C encrypts actual object/part bytes with the supplied 256-bit AES key. The
service retains a random salt, HMAC verifier and response MD5, never the customer
key. HEAD and attribute reads prove possession without loading payloads; GET and
copy decrypt only with the request key. Copy source/destination keys are
independent, including rekeying and overrides of a bucket's KMS default.
Customer-encrypted ETags are opaque, not plaintext MD5.

New buckets block SSE-C. `BlockedEncryptionTypes` admits exactly `NONE` or
`SSE-C`. Omitted blocking restores SSE-C blocking; an empty rule or deleting
encryption restores AES256 as well. Existing encrypted objects remain
readable. Blocking rejects new writes, initiations and parts, but does not reject
completion of an already-admitted upload. Real TLS is required when customer
encryption headers are present; the executable accepts paired `-tls-cert` and
`-tls-key` flags, and does not trust forwarded scheme headers.

Writes require AES256, a base64 32-byte key and matching MD5. Reads/copy sources
allow omitted MD5. Syntax admission precedes conditional evaluation, while a
well-formed wrong key can still produce `304` before possession is tested.
Ranges/part numbers are validated before key proof. Partial reads reject missing
keys and prove supplied keys before archive payload availability; full archived
GET instead returns `InvalidObjectState` before missing-key/key-proof failures.
These distinctions are measured, not a single generic decryption guard.
Native follow-up also established that retention response headers preserve
stored milliseconds, including deadlines supplied through retention XML.
`testdata/aws/s3/retention_precision_evidence.json.gz` distinguishes native
precision from CLI input conversion: the CLI truncates upload retention headers
to seconds before sending them, but retention XML and subsequent native response
headers retain milliseconds. Replays normalize the submitted CLI header, not
stored state or returned deadlines.

Basic multipart listing/completion can omit the key; a supplied wrong completion
key is rejected. Explicit-checksum uploads require it for listing, completion
and exact completed retries. Explicit FULL_OBJECT CRC64NVME and an implicit
default can expose the same checksum type/algorithm but have different native
key requirements, so completed versions retain initiation provenance.
Replication copies ciphertext/verifier metadata without a customer key. Native
replicas preserved version/ETag/bytes; destination blocking rejected new replicas
without breaking existing reads or tag replication. The local failure code uses
the existing destination-publication failure contract; that internal code was
not itself captured from an AWS failure notification.

`customer_encryption_{control,data,replication,boundaries}_evidence.json.gz`
under `testdata/aws/s3/` retain native captures in `000000000000`, `us-east-1`,
on 2026-09-21. Their fixture replays cover controls, IAM, binary reads,
copy/rekeying, multipart persistence, replication and partial-read boundaries.
The boundary captures contain 63 observations, including two independent bucket
absence checks; consumer-body expectations derive from submitted byte recipes
and requested ranges, not unrecorded native response hashes.
`customer_encryption_audit_replay.json` selects ten of twelve request-correlated
data records from 41 delivered native CloudTrail records. Actual local gzip
delivery preserves algorithm/SSEApplied/error/objectSize distinctions and omits
customer key and key-MD5 from request/response maps. Native HTTP-failure audit
delivery was not observed within the bounded collection window; no absence
guarantee is asserted.

The trusted-HTTPS CLI workflow retained a 131,072-byte binary payload, independent
rekeying, pending explicit-checksum parts, blocked completion and exact retry
across process reopens. It also retained archive state and pending keyless
Intelligent-Tiering restoration, then recovered identical bytes/version/metadata.
Archive aging/restoration here exercises the documented local scheduler, not a
native 90-day completion observation. Owned native buckets, versions, trails and
temporary replication roles were independently confirmed absent.

Primary contracts: [SSE-C](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html),
[headers](https://docs.aws.amazon.com/AmazonS3/latest/userguide/specifying-s3-c-encryption.html),
[blocking](https://docs.aws.amazon.com/AmazonS3/latest/userguide/blocking-unblocking-s3-c-encryption-gpb.html)
and [replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication-config-for-kms-objects.html).
SDK revision `113bc91bf12edc3af1d3aba1c70be28494d54c2a` supplies generated wire
contracts.

MFA delete, remaining AP families/directory buckets, KMS Bucket Keys/DSSE-KMS,
Batch Replication and remaining notification producers remain open. Native
long-duration Lifecycle/tiering conformance is tracked separately from their
implemented local execution.
Native-region redirects, public-block inheritance, broader policy classifications
and full audit projection depth also remain incomplete. Unsupported meaningful inputs must not
be treated as success.

## Evidence and remaining work

Native fixtures retain request/result distinctions and verified cleanup:

- `testdata/aws/cloudtrail/iam_history.json`, `lookup_validation.json` and
  `targets.json`: history, validation and target aliases; the existing IAM replay
  also checks scope, pagination, rollback, secret omission and reopen.
- `testdata/aws/s3/owned_object_delivery.json` and `owned_binary_headers.json`:
  real binary bytes, checksums, conditions, ranges, owner defaults and policies.
- `testdata/aws/s3/presigned_headers.json`: eight native signed GETs distinguish
  owner guards, duplicate owner bindings, query-only checksum omission and
  actual checksum headers. Captured native signing conflicts remain distinguishable
  from domain parameter errors.
- `testdata/aws/s3/versioning.json`, `versioning_null.json`,
  `version_policy_controls.json` and `marker_policy.json`: enabled/suspended/null
  histories, exact-version and marker reads/deletes, pagination and applied
  caller-policy controls. `conditional_versions.json` retains 51 single-delete
  cases and three batch cases, including native 501 XML details, per-item
  failures, deny precedence and surviving sibling effects. Recovered attempts
  and cleanup evidence remain in the capture; all owned resources were cleaned.
- `testdata/aws/lambda/layer_source_audit.json`: 36 exact request-ID-correlated
  events across all nine layer operations, including short-name versus ARN
  resources, source fields, response presence and download-field omission.
  Consumer replay exercises their history, gzip and EventBridge projections.
  This capture's tiny ZIP and same-account source permissions do not establish
  runtime or long-term source lifecycle behavior.
- `testdata/aws/lambda/function_s3_audit.json`: read-only history collection
  correlates 23 of 24 selected CreateFunction IDs from `s3_sources.json`;
  invalid-storage-mode validation is unobserved in the retained lookup window.
  It establishes source-code field presence and Pending response distinctions,
  not universal validation or AccessDenied audit coverage. The original
  interrupted capture and bounded source-creation audit discrepancy remain
  evidence, not a reason to suppress locally recorded errors.
- `testdata/aws/cloudtrail/owned_s3_delivery.json`: real gzip objects, 24 correlated
  data records, selector replacements, destination policy failures and restoration.
- `owned_selector_resource_types.json`: unknown and inappropriate resource-type
  rejection without replacing existing selectors.
- `lambda_resource_arns.json`: native exact/not-equal Lambda ARN rejection and
  literal prefix acceptance, with successful selector reads after each attempt.
  The owned ordinary trail and bucket were removed; no Lambda function or Lake
  resource was needed for these validation observations.
- `eventbridge_delivery.json`: eight real SQS messages for four S3 calls across
  both rule states, management-control events, post-stop delivery and raw current
  RecursiveLogging fields. Broad management-event forwarding was not enabled in
  the real account merely to test read-only delivery.
- `owned_service_principal.json`: 18 separately scoped preflight attempts,
  PrincipalType/Null distinctions, marker effects on failed creates, owned lookup
  timestamp projection and raw XML slash encoding. All owned trails/objects and
  three sequential lifecycles of the uniquely named bucket were cleaned up.
- `service_management_events.json` and `service_data_events.json`: 74 management
  and 35 data records drive implemented source replays for STS, KMS, IAM, Account,
  Organizations, SQS, EventBridge and Lambda. They retain classification,
  operation names, null/omitted fields, payload masking and batch distinctions.
  Uncaptured operations use documented projections, not claimed native verification.
  All newly owned data-probe resources were deleted; management capture required
  no resource changes.
- `testdata/cloudtrail/audit/management_selectors.json`: documented read/write
  selection and KMS exclusion, exercised through real SDK calls, independent
  history, gzip delivery and EventBridge/SQS consumers on memory and SQLite.
- `testdata/cloudtrail/region_selection.json`: documented global-versus-regional
  trail admission. These cases are documentation-derived, not new AWS captures.

Local SDK replays exercise memory and SQLite, actual gzip content and EventBridge
detail, policy-revocation retry, restart, atomic source mutation failure and
incarnation cancellation. The real endpoint smoke additionally exercised normal
SDK checksum handling, presigned checksum rejection, unsigned checksum trailers,
SDK-signed chunks and unchanged bytes after tampering. A real AWS CLI scenario
produced two source API events, two SQS deliveries and identical gzip records,
then verified stopped admission and retained binary/log objects after process
restart. The presigned owner mismatch reproduction changed from HTTP 200 to 403;
query-only checksum omission was confirmed against AWS rather than \"fixed\" away.
These are bounded evidence, not operation-wide conformance certification.

The audit CLI smoke exercised EventBridge → customer-KMS-encrypted SQS, internal
`GenerateDataKey` history, and selected `Encrypt`, `PutEvents` and service-principal
`SendMessage` outcomes. All three matched their actual gzip records; private
payloads were absent. SQLite process restart preserved history, log objects,
manual time and in-flight SQS messages, which redelivered the same native event
identities after visibility expiry. Docker-backed SDK replay separately exercises
Lambda invocation and execution audit records.

Insights, broader native log-integrity timing and backfill conformance,
remaining non-Lake operations and additional producers,
native propagation/throttling depth and other EventBridge source/target contracts
remain open. Service-owned metrics beyond SNS, remaining Logs subscription destinations,
journal retention/checkpoints, consistent snapshot/fork/restore and general replay
remain kernel work. No response fidelity labels or provenance headers are added.

Primary contracts:

- [Event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
  and [LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html).
- [Record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
  and [IAM/STS integration](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html).
- [Trail bucket policies](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)
  and [log file delivery](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html).
- [Data event types](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
  and [advanced selectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html).
- [CloudTrail events in EventBridge](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html)
  and [read-only management events](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail-management.html).
- [KMS audit classification](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html),
  [SQS data operations](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/logging-using-cloudtrail.html),
  [EventBridge data resources and redaction](https://docs.aws.amazon.com/eventbridge/latest/userguide/logging-using-cloudtrail.html),
  and [Lambda audit events](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html).
  Federation/AssumeRoot successes, multi-region KMS companion events, and repeated
  Lambda execution grouping are not all covered by fresh native captures.

The SDK model revision is `113bc91bf12edc3af1d3aba1c70be28494d54c2a`.
Object data events are not available through ordinary management-event history.
