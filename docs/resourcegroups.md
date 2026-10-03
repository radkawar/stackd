# Resource Groups

Resource Groups is routed through the generated `resourcegroups` Smithy API
(Boto3 service name `resource-groups`) and the shared typed command executor.
All 23 modeled operation names are registered. **This does not complete the full
selected-service target:** EC2 specialty groups and unavailable query owners
remain explicit prerequisites. Application tag synchronization and lifecycle
capture use actual owner state and current IAM authority, not metadata-only
success. Positive native AppRegistry/GLE parity is not claimed.

## Implemented behavior

Ordinary groups retain their scoped name/ARN, description, resource query and
tags in typed memory and SQLite repositories. Create, get, update, delete,
query get/update, group listing and tagging operate on the same owner state.
The common Resource Groups Tagging API discovers groups and dispatches its tag
and untag mutations to this owner. A query group can discover itself.

`SearchResources` and `ListGroupResources` evaluate current owner snapshots,
not a retained ARN catalog or the Tagging API's historical previously-tagged
view. Owner tag changes, deletion and recreation affect the next query. Query
results use the generated CloudFormation resource type names. The published
support table determines query eligibility, **not availability of an implemented
owner**; unsupported or absent owners are not synthesized from table rows.

The two query forms are:

* `TAG_FILTERS_1_0`: resource type union; distinct tag keys are ANDed, values
  within a key are ORed. Omitted/empty `Values` requires key presence. An empty
  string value matches an actual empty tag value. Native duplicate-key behavior
  uses the final filter for that key. JSON member names are case-sensitive;
  duplicate resource types, unknown members/types and malformed query documents
  are rejected.
* `CLOUDFORMATION_STACK_1_0`: the stack ARN resolves through the real
  CloudFormation repository, then through the current live resource owners.
  Direct current deployments participate; stale replacement/retention history
  does not. Where the deployment owner supplies ownership tags/tokens, those
  must still match: an out-of-band delete/recreate cannot impersonate the old
  CloudFormation resource. A missing stack produces
  `CLOUDFORMATION_STACK_NOT_EXISTING` in search results. Known
  `DELETE_COMPLETE`, `ROLLBACK_COMPLETE` and `CREATE_FAILED` stacks produce
  `CLOUDFORMATION_STACK_INACTIVE`. Creating/updating a query for a missing or
  inactive stack is rejected instead. `CREATE_IN_PROGRESS` is not itself an
  inactive status.

`ListGroups` filters group definitions: its `resource-type` filter does **not**
expand a definition's `AWS::AllSupported` into every resource type. Ordinary
groups do not support `DisplayName`, `Owner` or `Criticality` mutation; these
modeled fields are rejected rather than silently persisted. Empty descriptions
are omitted from group responses. `Tag` returns the submitted tag set, not the
entire merged set; `Untag` returns the submitted keys, including absent keys.

List/search pagination uses deterministic sorted keys and scoped, query-bound
continuation tokens. Changing the query or scope invalidates a token. Cursors
do not impose an unverified expiry or depend on process-local signing state.
They do not reproduce AWS's internal page layout or possible empty intermediate
pages. Owner evaluation is current on each page, not a historical snapshot of
changing remote resources.

### Systems Manager Run Command consumer

Run Command's `resource-groups:Name` and optional
`resource-groups:ResourceTypeFilters` consume this owner's current membership,
not a second group or tag store. The consumer checks
`resource-groups:ListGroupResources` on the scoped group, resolves the current
query in the shared transaction, and projects only eligible EC2 members onto
registered, running SSM nodes. Ordinary interactive query API authorization is
unchanged; native SSM does not additionally require `tag:GetResources`,
`GetGroup` or `GetGroupQuery`. SSM still checks its document and each selected
instance's `SendCommand` authority.

Tag/query changes affect subsequent admissions; already admitted invocations
keep their selection across controller restart. Missing groups are empty SSM
selections, while listing denial produces a failed command. This does not add
hybrid managed instances or executable support for other resource families.
See [SSM targeting and native calibration](ssm.md#run-command-resource-groups-targets)
for the syntax, timing and evidence boundaries.
The [actual official-agent guest workflow](../testdata/integration/ssm_resource_groups_guest.json)
observed selected stdout, tag exclusion, retained selection across query change
and SQLite/controller restart, restored membership and real SNS→SQS
notifications, with independent owned-resource cleanup.

### KMS aliases in stack queries

`AWS::KMS::Alias` is a
[stack-only resource type](https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.md).
Stack queries read the current scoped KMS alias rows and require the owner's
stack ID, logical ID and physical-incarnation token to match the current
deployment. Neither a matching name nor CloudFormation history proves ownership.
Aliases do not inherit key tags and are not added to tag-based discovery.

Schema 297 retains that private owner identity with the alias. CloudFormation
create recovery reuses only an exact owned alias under current KMS permissions;
update/delete reject a foreign replacement. Native `UpdateAlias` preserves the
incarnation, while native delete/create resets it. Legacy aliases without an
owner remain unclaimed; migration does not infer ownership from stack history.

`integration/cloudformation_kms_alias_test.go` verifies signed SDK stack queries,
scope, native retargeting, same-name recreation and foreign update/delete
rejection across memory/SQLite reopen. An actual SQLite executable restart
verifies these transitions and stack/alias cleanup. A separate fresh-process
handler smoke recovers an already-committed alias without changing its creation
timestamp. These are local ownership proofs, not a native AWS crash/recreation
capture; AWS's documented alias properties remain the
[public contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-alias.html).

### Lambda aliases in stack queries

`AWS::Lambda::Alias` likewise uses current, scoped Lambda alias rows and exact
stack/logical/incarnation matching, not inherited function tags. Native alias
retargeting preserves membership; delete/recreate removes it even if the name
and target are identical. Schema 298 retains the private identity across restart.
The [native capture](../testdata/aws/cloudformation/lambda_alias.json) returned
the actual alias from a stack-backed group and verified owned-resource cleanup.
The [provider workflow](lambda.md#cloudformation-aliases) adds signed SDK and
actual provisioned-runtime/restart proofs without claiming native recovery parity.

### Lambda versions in stack queries

`AWS::Lambda::Version` membership reads the current scoped publication receipt
and exact stack/logical/incarnation identity. Schema 299 retains that receipt
atomically with the immutable version; native and legacy publications cannot be
adopted from stack history. Deletion removes membership, and replacement admits
the new owned version rather than its retired predecessor. Versions do not inherit
function tags. The [native capture](../testdata/aws/cloudformation/lambda_version.json)
observed the qualified version ARN in a version-filtered stack-backed group.
[Deployment and runtime evidence](lambda.md#cloudformation-versions) distinguishes
public AWS behavior from the local private recovery contract.

### Lambda layer versions in stack queries

`AWS::Lambda::LayerVersion` membership reads the current layer publication and its
private stack/logical/incarnation owner. Replacement admits only the current owned
publication; catalog deletion removes membership even while functions retain the
old archive. Native and legacy rows cannot be adopted from CloudFormation history.
Layers are stack-only members, not inferred function-tag members. The
[native lifecycle capture](../testdata/aws/cloudformation/lambda_layer.json)
recorded a bounded membership miss rather than a permanent exclusion.
[Deployment and executable evidence](lambda.md#cloudformation-layer-versions)
covers layer-backed application replacement, retirement and SQLite restart.

## AppRegistry and application membership

The generated `servicecatalogappregistry` frontend (Boto3
`servicecatalog-appregistry`, IAM/ARN namespace `servicecatalog`) owns scoped
applications, JSON-object attribute groups, associations, tags and regional
tag-query configuration. Immutable create-token fingerprints prevent replays
after update/restart from reverting state. Deletion requires explicit
disassociation and never deletes customer resources. Lists use scoped,
operation/association-bound cursors.

An application has separate servicecatalog, legacy application-group and modern
application-group identities. **The modern Resource Groups ARN** is the
`awsApplication` tag value. Legacy groups contain actual stack/tag-query child
collections. Managed configuration and legacy metadata are protected; modern
`UpdateGroup` supports `DisplayName`, `Owner` and `Criticality` with real filters.

Application grouping currently admits S3 buckets, SQS queues, SSM parameters and
CloudFormation stacks. Managed application/tag-value queries explicitly name
these implemented owner types. `AssociateResource` accepts `CFN_STACK` and
`RESOURCE_TAG_VALUE`; ordinary resources use grouping or native owner tagging.
Omitted options mean SKIP. APPLY checks current dependent owner permissions;
failed associations roll back child groups, owner tags and admitted stack jobs.
The tag-value collection is a real query group, not a fabricated ARN. Its
deterministic local name is not claimed to reproduce native naming.

CloudFormation tag updates use the actual asynchronous stack owner. Pending
effects are not reported as completed, and failed grouping outcomes do not leave
prior success as the latest result. Stable owner incarnations fence status and
task cleanup after recreation. Terminal grouping history remains stable after
unrelated tag changes. Tag-value APPLY uses current matches; continuous
matching/removal belongs to a real tag-sync task.

The AppRegistry service-linked role uses current IAM trust/managed policy;
customer tag effects retain caller authority. Applications and unexpired role
sessions prevent role deletion. AppRegistry audit uses the captured hyphenated
event source, URI labels, missing-resource wildcards and native mutation error
bodies. Generated source metadata is corrected for both AppRegistry and Resource
Groups so configured CloudTrail/EventBridge consumers can accept those events.

Native credentials here cannot create applications or attribute groups because
of new-customer maintenance mode. `testdata/aws/appregistry/` retains 49 actual
observations and all 49 exact request-ID-matched CloudTrail events, unchanged
settings and exact attempted-name absence. Its `native-contracts.json` separates
documented positive contracts from captures. **Local positive workflows are not
successful native parity evidence.**


## Authority, persistence and audit

Groups are isolated by partition, account and region. Commercial global IAM
resources participate in the calibrated `us-east-1` query scope; noncommercial
global home-region behavior remains uncalibrated.

Every command uses current reusable IAM evaluation. Group calls provide the
current group's `aws:ResourceTag/*` values; tagging also supplies request tags
and tag keys. Create uses `resource-groups:CreateGroup` on `*` and additionally
checks `resource-groups:Tag` for a tagged prospective group. Tag queries check
the dependent `tag:GetResources` authority. Stack queries check
`cloudformation:DescribeStacks` and `cloudformation:ListStackResources`.
Changing a role policy or a group tag affects an already-issued role session's
next request.

The repositories share the existing memory/SQLite transaction domain.
Mutations and successful API records commit together; an error rolls back the
attempt and records the rejected outcome through the shared completion path.
SQLite uses normalized group, tag, grouping, task-owned membership, lifecycle
account and lifecycle snapshot tables with SQLC-generated queries and the
canonical generated bootstrap schema. Reopening the executable preserves task
selectors, due work, group incarnations and event sequences, while discovery
still consults current owners. Snapshots are detached observations, never a
second authoritative owner tag store.

The native-calibrated audit projection uses
`resource-groups.amazonaws.com`, **not** the unhyphenated Smithy metadata value.
Events are management `AwsApiCall` records. Get/List/Search are read-only and
omit response contents; mutations retain response contents, including native
`Message` error bodies. Request/response field names retain their modeled
capitalization. Tagging ARN request labels use native percent encoding.
Create/update/delete audit group objects include the native unmodeled `OwnerId`.
GetGroup, GetGroupQuery, GetGroupConfiguration and ListGroupResources supply
native event resources, including rejected lookups; lookup resource search
terms remain separate. Native captured errors have `errorCode` but omit
`errorMessage`. These projections do not change the public API response shapes.

## Tag synchronization and lifecycle capture

`StartTagSyncTask` requires a real modern application group, current
`resource-groups:StartTagSyncTask` and `resource-groups:CreateGroup` permissions,
and `iam:PassRole` on the supplied same-account role with
`iam:PassedToService=resource-groups.amazonaws.com`. Specify either a tag-based
`ResourceQuery` or both `TagKey` and `TagValue`; an empty tag value is meaningful.
The original selector is retained separately from the application's
`awsApplication` query. Public GLE enrollment is not imposed as an undocumented
prerequisite: the official Start API and AppRegistry tag-sync guide do not list it.

The shared deterministic driver scans current supported application owners.
Each effect freshly assumes the supplied role through its current trust policy,
checks grouping/tagging permissions and invokes the native owner tagging command.
Its tag mutation, incarnation-fenced task ownership and grouping observation
share one transaction. An owner failure rolls back that effect without undoing
effects already committed for other owners. Current trust or policy revocation
is visible as task `ERROR`; later successful scans restore `ACTIVE`.

Only tags actually applied by a task are candidates for its removal. Existing
direct application membership is not adopted, a later successful direct
grouping takes ownership, and a different application's tag is not overwritten
or removed. Deleting/recreating an owner cannot reuse an old task membership.
Pending CloudFormation tagging is not reported as a completed grouping.
`CancelTagSyncTask` checks cancellation and dependent deletion authority,
deletes the task and stops future effects. It leaves existing owner tags alone;
the published cancellation contract does not promise retroactive tag cleanup.
Already admitted asynchronous owner operations can still finish. Deleting the
owning group atomically removes its tasks.

GLE activation checks the documented caller dependencies and creates the actual
`AWSServiceRoleForResourceGroups` IAM role using the captured
`ResourceGroupsServiceRolePolicy`. Lifecycle scans assume this role with current
trust and permissions. `IN_PROGRESS` becomes `ACTIVE` only after a successful
initial capture; owner/authority failures are reported rather than represented
by an inert active flag. Disabling GLE stops capture and releases IAM role usage.
The role cannot be deleted while the account setting still requires it.

The local capture mechanism is a retained **one-second source snapshot scan**,
not a fabricated EventBridge managed rule or target. Initial activation
baselines existing groups. Subsequent observed creations, description/query/
configuration changes, deletions and membership transitions publish the
documented `aws.resource-groups` state/membership events through the existing
transactional EventBridge publisher to the default bus. Event sequence and group
UUID survive restart; same-name group replacement gets a new UUID and sequence.
Snapshot changes and event acceptance commit together. As with any sampled
snapshot, multiple changes between scans can coalesce; this is not a claim of
capturing every native tag/CloudFormation source event or reproducing AWS's
internal `Managed.ResourceGroups.TagChangeEvents` setup. Application owner
incarnations are fenced; other query-owner snapshots retain their existing
discovery boundaries.

The dedicated local executable probe is
`scripts/aws/resource_groups_sync_executable_smoke.py --binary <stackd-binary>
--state-directory <fresh-owned-directory>`. It exercises signed SDK task
admission, current delegated owner/trust denial and recovery, ownership-safe
removal/cancellation, SQLite restart, and actual lifecycle EventBridge-to-SQS
delivery. The exercised report is
`testdata/integration/resourcegroups_sync_executable.json`: three zero-exit
controller runs, six delivered events, retained sequence/UUID across restart,
new UUID after group replacement and exact cleanup. Role deletion waits for
real issued sessions to expire; disabling GLE does not delete its IAM role.

## Explicit remaining prerequisites

The full Resource Groups target remains open. The following are required real
work, not optional extensions or successfully implemented operations:

| Boundary | Current behavior | Missing owner/effect |
| --- | --- | --- |
| Capacity reservation pools | A structurally admissible configuration returns `NotImplementedException`; no group is created. | EC2 capacity-reservation ownership, applicable shared/RAM authority and real instance placement into pool capacity. |
| Dedicated Host management | Missing configuration is rejected; an admissible configuration reports `NotImplementedException`. | EC2 Dedicated Host allocation/release and License Manager host-management effects. |
| Network Firewall groups | Native instance-query configuration is recognized but returns `NotImplementedException`. Invalid/missing query forms are rejected. | Real Network Firewall rule-group ownership and updates from current associated EC2 instance addresses. |
| AppRegistry remaining depth | Real application/group/tag effects exist for the four named owners. `SyncResource` remains model-known unsupported, not an alias for `awsApplication`. | Native existing-customer calibration, legacy CloudFormation AppRegistry system tags, other application owners and older-application upgrades. |
| Native tag-sync/GLE conformance | Real retained task execution and lifecycle snapshot publication are implemented locally. | An eligible native account is needed to calibrate successful task timing, cancellation, managed capture setup and lifecycle event details; transient changes between local scans can coalesce. |
| Additional query owners | Absent owners contribute no phantom resources. | Current typed snapshots for nested-stack deployments and service-linked specialty resources. |
| Other partition global scopes | No unsupported home-region inference. | Native calibration for `aws-cn` and `aws-us-gov`. |

The captured native account rejects new lifecycle/tag-sync enrollment following
AWS's availability change. This is **not** implemented as a universal denial:
existing eligible customers remain part of the full target. The account-specific
refusal is retained in native fixtures, not used as a local admission rule.
Specialty-owner prerequisites remain in `configuration.go` and the current owner
discovery adapter.

## Evidence and reproduction

Native fixtures under `testdata/aws/resourcegroups/` retain request IDs and
positive/negative responses:

* `native.json`: 182 observations, including actual S3/SQS owners, group query
  selection, query/type/configuration validation and direct CloudFormation
  membership. Initial expected-selection annotations are retained even where
  disproven; `selection[].actual` is the observed result used by replay.
* `native-query-boundaries.json`: 32 observations covering case-sensitive
  query syntax, duplicate types, missing stack behavior, task filters and a
  real CREATE_IN_PROGRESS-to-CREATE_COMPLETE stack.
* `native-attributes.json`: 16 observations establishing ordinary-group
  attribute and definition-filter behavior.
* `native-audit.json`: 174 exact-owned-prefix CloudTrail events over six lookup
  pages, with every expected owned-prefix request ID observed. Unrelated events
  and credential fields are not retained. Completeness is limited to those
  request IDs; missing/late-event non-inference remains explicit.
* `native-contracts.json`: authoritative contracts and capture limitations.
* `supported_resource_types.json`: the pinned 1,204-row AWS support table,
  source digest and per-query eligibility. Its generator is offline by default;
  refreshing requires explicit `--refresh`.

All three mutating native captures verified exact-owned cleanup (57 cleanup and
absence observations in total). Their groups, buckets and queues are gone;
CloudFormation's provider-retained DELETE_COMPLETE history remains. Account
settings were read only and remained INACTIVE. No capacity reservation,
dedicated host, billed instance or firewall rule was provisioned, and successful
application/tag-sync effects are not claimed.

`integration/resourcegroups_sdk_test.go` replays actual native selections
through the official Go SDK over memory and SQLite, preserving group
self-selection while explicitly excluding native specialized groups whose
owners are absent locally. It covers owner deletion/recreation and current
tagging, query-bound pagination, invalid update rollback and reopen. The
native definition-filter regression was observed failing before the fix with
`AllSupported definition incorrectly treated as an explicit SQS type filter`;
the retained subtest then passes on both backends.

The local executable smoke uses Boto3 against an explicitly local endpoint and
test credentials, not ambient native credentials. It runs the actual
`cmd/stackd` binary over SQLite, reads real S3 object bytes and SQS messages,
checks current-role/tag revocation, exercises CloudFormation replacement and
out-of-band recreation fences, restarts the process, validates all 23 operation
outcomes and their CloudTrail history, and verifies cleanup. The captured report
is `testdata/integration/resourcegroups_executable.json`.

`scripts/aws/appregistry_executable_smoke.py` exercises signed application,
attribute, configured tag-value and stack APPLY/SKIP flows, rollback, modern
grouping, real owner data planes, current-role denial/recovery, restart and
owner/name reuse. It reads configured CloudTrail gzip objects from S3 and compares
reachable missing-owner events with native captures. The exercised local report
is `testdata/integration/appregistry_executable.json`; both controllers exit zero
and exact-owned cleanup succeeds. Focused SDK/memory/SQLite tests also cover
immutable create-token replay, cursor binding, attribute validation, coordinated
rollback and same-clock owner recreation.

The combined schema-260-to-264 executable upgrade is captured in
`testdata/integration/appregistry_upgrade.json`. Existing SES template state,
S3 bytes, an actual queued SQS message, an SSM parameter and a three-owner
Resource Groups query survive migration. The new AppRegistry application groups
those existing owners; its identity and membership survive another restart and
an SSM version update. All three controllers exit zero and all seven owned
resources are removed with absence checks. This verifies local upgrade behavior,
not successful native AppRegistry conformance or older AppRegistry application upgrades.

From the repository root (Go 1.26 and Boto3 installed):

```sh
go test -race ./storage/sqlite/resourcegroups ./integration -run '^(TestGroupsRemainAtomicScopedAndDetached|TestResourceGroupsNativeSelectionAndOwnerTransitions)$' -count=1 -v
go build -o /tmp/stackd-resourcegroups ./cmd/stackd
python3 -B scripts/aws/resource_groups_executable_smoke.py --binary /tmp/stackd-resourcegroups --state-directory /tmp/rg-fresh-owned-proof
python3 -B -P scripts/aws/resource_groups_types_capture.py --check
```

The smoke uses the shared `scripts/aws/stackd_process.py` controller, recording
real process exits and owned log/state paths. The state directory must be new
and empty. `resource_groups_capture.py` is a **native AWS** probe, unlike the
executable smoke; it verifies caller identity, owns unique resources and
requires explicit native credentials. Its `--query-boundaries`, `--attributes`
and read-only `--audit` modes correspond to the retained fixtures.

Authoritative references:

* [ResourceQuery](https://docs.aws.amazon.com/ARG/latest/APIReference/API_ResourceQuery.html)
* [Resource Groups IAM actions and conditions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_resource-groups.html)
* [Service-linked group configuration types](https://docs.aws.amazon.com/ARG/latest/userguide/about-slg-types.html)
* [Supported resource types](https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.html)
* [CloudTrail logging](https://docs.aws.amazon.com/ARG/latest/userguide/security_logging-monitoring.html)
* [Lifecycle-event availability change](https://docs.aws.amazon.com/ARG/latest/userguide/resource-groups-gle-availability-change.html)
* [StartTagSyncTask and selector/permission contracts](https://docs.aws.amazon.com/ARG/latest/APIReference/API_StartTagSyncTask.html)
* [CancelTagSyncTask permissions](https://docs.aws.amazon.com/ARG/latest/APIReference/API_CancelTagSyncTask.html)
* [AppRegistry resource tag-sync behavior and delegated role](https://docs.aws.amazon.com/servicecatalog/latest/arguide/app-tag-sync.html)
* [GLE activation prerequisites](https://docs.aws.amazon.com/ARG/latest/userguide/monitor-groups-turn-on.html)
* [Lifecycle event detail and group incarnation contract](https://docs.aws.amazon.com/ARG/latest/userguide/monitor-groups-syntax-detail.html)
* [Resource Groups service-linked role](https://docs.aws.amazon.com/ARG/latest/userguide/using-service-linked-roles.html)
* [Captured lifecycle managed policy v1](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ResourceGroupsServiceRolePolicy.html)
* [Turning off lifecycle events and role retention](https://docs.aws.amazon.com/ARG/latest/userguide/monitor-groups-turn-off.html)
* [AppRegistry native and documented contracts](../testdata/aws/appregistry/native-contracts.json)
