# Systems Manager

> In native capture references, `000000000000` is an anonymized account alias,
> not the AWS account originally used. See [capture privacy](behavior-references.md#publishing-sanitized-probe-captures).

Parameter Store, versioned documents and EC2 managed execution have separate typed
state owners behind the generated SSM JSON 1.1 frontend. They reuse shared IAM,
transactions, API observations, clocks and memory/SQLC SQLite repositories.
Managed execution uses the official agent inside the existing firmware-booted
EC2 guest, not SSH, Docker-exec or an in-process command runner. The generated
inventory remains partial; this is not full Systems Manager parity.

## Values, versions and authority

`PutParameter`, `GetParameter`, `GetParameters`, `GetParametersByPath`,
`GetParameterHistory`, `DescribeParameters`, both delete operations, both label
operations and Parameter tagging have real retained behavior:

- String, verbatim StringList (including spaces/empty comma-separated elements)
  and SecureString; overwrite creates a version even when the value is unchanged.
- Immutable version-specific type/key/description/pattern/policy metadata,
  mutable version labels, label moves and the ten-label limit. Up to 100 versions
  survive; a label on the oldest version prevents its eviction.
- Numeric and label selectors, top-level bare/slash aliases, sorted batch results
  and invalid-name lists, hierarchical reads, metadata/path filters and scoped,
  authenticated pagination tokens. Tokens are process-local and do not survive
  controller restart. Describe/path collections have deterministic local ordering;
  AWS's undocumented internal page scan order is not copied.
- Standard, Advanced and Intelligent-Tiering admission; size/count limits,
  promotion without downgrade and the retained default-tier service setting.
- Creation tags, independent tag replacement/removal, current resource/request
  tag conditions and account/region/partition isolation.

Standard SecureString values call the existing KMS `Encrypt`/`Decrypt` owner.
Advanced values call `GenerateDataKey` and use a real AES-GCM committing AWS
Encryption SDK envelope. EventBridge and Parameter Store share the envelope
implementation; they do not share resource state or encryption contexts.
`PARAMETER_ARN` binds encryption to the parameter ARN. `kms:ViaService`, current
caller identity/session/key policy and encryption-context conditions remain
live. `WithDecryption=false` returns actual base64 ciphertext without requiring
Decrypt. Neither Parameter Store nor its consumers copy KMS or Secrets Manager
state. The default key is the actual regional `alias/aws/ssm` managed key.

The local advanced envelope uses the interoperable unsigned committing 0x0478
suite. Native AWS ciphertext bytes, suite selection and AWS's internal encryption
SDK context/signature variation are not reproduced or imported. Different
customer-managed KeyId transitions were not included in the native capture;
local key authority and historical decryptability are independently exercised.

IAM checks are operation-specific. An allowed recursive `GetParametersByPath`
request authorizes its requested ancestor path, not each descendant: a deny on a
descendant's direct read does not remove it from an allowed ancestor traversal.
`GetParameterHistory` has its own authority and exposes historical values without
requiring `GetParameter`. Direct-ARN sharing uses advanced parameter resource
policies through the existing policy binder/evaluator; cross-account reads need
both sides' applicable authority. Resource policy IDs/hashes fence updates and
revocation takes effect immediately. Shared parameters cannot be mutated.

RAM shares add advanced-parameter discovery, invitation acceptance and managed
permission selection through the separate RAM owner. Its read-only permission
does not grant history; replacing it with the history permission changes the
next authorized read. Consumer identity permission remains required.
[`ram_parameter_sharing.json`](../testdata/integration/ram_parameter_sharing.json)
records signed CLI-server calls covering accepted sharing, permission replacement,
history and revocation, with owned cleanup. This is local executable evidence.
The [merged-runtime replay](../testdata/integration/ram_merge_parameter_runtime.json)
uses the shared parameter-access fixture for account and IAM-user principals on
both backends. Its 28 transitions verify exact values/history, discovery,
permission replacement, revocation and foreign-account isolation. SQLite cases
restart the actual process; memory cases keep the same process and make no
durability claim. All owned shares, parameters, identities and private state
were removed.

Replacing a RAM permission also requires the caller's current authority to update
the underlying parameter policy, as required by
[ReplacePermissionAssociations](https://docs.aws.amazon.com/ram/latest/APIReference/API_ReplacePermissionAssociations.html).
RAM authority alone does not bypass SSM `GetResourcePolicies`, `PutResourcePolicy`
or `DeleteResourcePolicy`. The
[missing-dependency capture](../testdata/integration/ram_scoped_authorization_missing_dependency.json)
retains the actual denial and cleanup. With those actions granted on the exact
parameter, the [scoped authorization workflow](../testdata/integration/ram_scoped_authorization.json)
verifies current permission tags, exact permission/share ARN denials, source and
target replacement denials without mutation, successful replacement and a newly
applied denial before token replay.

### CloudFormation ordinary dynamic references

CloudFormation resource properties support `{{resolve:ssm:parameter-name}}` and
`{{resolve:ssm:parameter-name:version}}` for String parameters, including strings
assembled with `Fn::Sub` or `Fn::Join`. Parsing, validation and change-set
planning retain references without reading Parameter Store. During resource
create/update execution, CloudFormation calls the actual SSM `GetParameters`
owner using its retained caller or current stack execution-role authority.

Unversioned references select the latest version for that resource operation.
Before native effects, a durable resolution intent retains only the selected
version, so retries reauthorize the pinned version instead of refreshing the
value. Subsequent resource updates select a new latest version; changing an SSM
parameter alone does not mutate an existing resource. The raw stack template,
retained resource properties and stack events never contain the fetched value.
Resolved values exist only in the native owner's resource input/state; owner
failure messages are redacted before CloudFormation retains them.

Plain `ssm` references reject SecureString without requesting decryption.
`ssm-secure`, Secrets Manager dynamic references, labels and cross-account
references remain unsupported. Missing parameters, missing versions and IAM
denials fail the operation rather than admitting a resource with reference text.
See [AWS plaintext dynamic references](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references-ssm.html)
for syntax and `ssm:GetParameters` permissions.

The combined SQLite CLI deployment resolves the reported Google `client_secret`
from a real String parameter and verifies the provider's exact value. AWS CLI
template/event reads contain no resolved value. Memory/SQLite owner fixtures
cover subsequent version selection, current authority, redacted errors and
actual KMS-encrypted SecureString rejection. These are local executable
observations, not native AWS CloudFormation captures.


## Stateless Secrets Manager references

`GetParameter` and `GetParameters` recognize
`/aws/reference/secretsmanager/<secret-name>[:selector]` and call the existing
Secrets Manager command using the original caller's live authority. They retain
no parameter, version, label, secret value or secret metadata. SSM permission is
still required against the reference's SSM resource ARN, followed by actual
Secrets Manager and KMS authorization.

Fresh native capture supersedes misleading details in the published examples:

- `WithDecryption=true` is required. A single read without it fails validation;
  a batch returns these names in `InvalidParameters` while preserving ordinary
  successful parameters.
- A canonical hyphenated UUID selector chooses a secret version ID. Other
  selectors choose stages, including numeric/compact-hex stages. Native accepts
  slash-containing stages, despite the user guide's narrower character warning.
  Multiple colon components and secret ARNs are not valid reference syntax.
- Secret names can contain their native `+/@/=` characters. The leading slash
  before `aws/reference/...` is optional; the response preserves that spelling.
- Successful references have type SecureString, version zero, the **secret ARN**,
  the secret version's creation time and no DataType. `SourceResult` uses native
  lowercase dependency-field names and a human-readable UTC `createdDate`, not
  the public Secrets Manager response encoding shown in the guide. Binary
  references have no outer Value; their SourceResult contains the observed
  signed-byte buffer representation.
- An authorized missing secret/stage becomes ParameterNotFound, or a batch
  InvalidParameters entry. Secret/KMS denial becomes the captured generic
  ValidationException and fails the entire batch; SSM denial remains
  AccessDeniedException. There is no successful partial response for a denied
  dependency.

Parameter history, metadata discovery and mutations do not operate on these
references. Public AWS-owned parameter catalogs are a separate unsupported
authority, not synthesized from this integration.

## Time, persistence and events

Migration 213 owns relational parameter metadata, tags, versions, separately
stored value/wrapped-key bytes, labels, current/historical policy attributes,
resource-policy principal bindings, settings and typed validation caller state.
The same transaction includes API observations and EventBridge admissions.
Policy deadlines and image-validation jobs survive SQLite restart; no second
scheduler or parameter-state ledger exists.

Expiration deletes the parameter and its versions. ExpirationNotification and
NoChangeNotification publish once per retained policy schedule. Omitted policies
survive updates; explicit `[]` clears them; a value update rearms inactivity
notification without moving expiration. The injected clock controls local
eligibility; AWS's nondeterministic background scan/delivery latency is not
claimed. Advancing manual time publishes the instant but does **not** wait for
workers: use `POST /_stackd/jobs/drain` as the completion barrier.

`aws:ec2:image` validation uses the real EC2 `DescribeImages` authority and visible
available image catalog. A successful Put only admits retained asynchronous work;
new parameters remain hidden, and existing parameters retain the previous active
value, until validation succeeds. A terminal rejection rolls back the child EC2
savepoint, removes pending work and publishes the failed Parameter Store Change
without poisoning the surrounding transaction. Failed versions are not history.

Native-calibrated `Parameter Store Change` events include creates, updates,
deletes and label transitions. Policy Action details satisfy AWS's published
EventBridge schema, including action status/type/content; that schema evidence
is distinct from an observed native delayed notification. Parameter Store API
CloudTrail projections redact **every** PutParameter value, not just SecureString.
Selected native modeled errors retain request/resource records but omit error
fields, while frontend validation/tag errors preserve their own conventions.
This unusual projection stays SSM-owned. Resources with no native type omit it.

## Existing consumers

CodeBuild project/start-build `PARAMETER_STORE` variables and buildspec
`env.parameter-store` resolve ordinary SSM GetParameters batches under the build
role. Existing precedence, exact-value masking and exported-variable protection
apply. ECS `containerDefinitions[].secrets` resolves SSM references under the
**execution** role, including ARN-selected regions. Parameters enter only newly
created native container environments; reattachment does not refetch them.
Values are not copied into retained ECS/CodeBuild control metadata. ECS customer
code can still print its own environment: no invented ECS log-redaction layer is
promised. Missing references and current SSM/KMS denial fail initialization.
Both consumers also accept the stateless secret-reference namespace; their
build/execution roles additionally need `secretsmanager:GetSecretValue` and
applicable KMS permission. ECS dedicated Secrets Manager ARN syntax is separate
and remains unsupported.

## Evidence and reproduction

`testdata/aws/ssm/evidence_index.json` indexes the September 26 native captures.
The original parameter fixtures have 126 semantic responses matched to 126
exact-request-ID CloudTrail events, plus
seven observed EventBridge messages. Capture verified account `000000000000` in
`us-east-1`, used only unique owned paths/rule/queue and synthetic values, and
confirmed all owned resources absent. No standing settings or KMS keys were
modified. The raw empty-value transport failure remains recorded separately;
the corrected JSON 1.1 fixture completes that observation.

The native fixtures establish, among other cases, String/SecureString conversion
in both directions (contrary to the API page's broad type-change warning),
StringList preservation, historical label/path selection, alias spelling,
policy validation and CloudTrail error omission. `policy_event_schema.json` is a
read-only AWS EventBridge registry capture, not a delayed policy-event capture.

`secret_references.json` separately records 243 native API responses/request IDs,
including 180 raw JSON responses, covering read/source/selector contracts,
restricted-role secret/KMS failures and direct-secret authority matrices. The
latter prove `PutSecretValue` does not expose the scalar
`secretsmanager:VersionStage` key at all; the owner no longer incorrectly inserts
its VersionStages list into that context. No shared IAM cardinality checks were
relaxed. All synthetic native secrets were force-deleted and every owned role
removed with absence checks. This follow-up records actual API request IDs and
raw JSON, not a new CloudTrail/CodeBuild/ECS native capture.
The final signed executable matched all 78 selected native reference reads,
including successful SourceResult bodies and downstream batch errors, with 27
creation-date projections independently checked against version timestamps.
Four supplemental selector boundaries and 17 missing-secret authority outcomes
also matched. Generated identities/timestamps and unordered stage collections
were normalized; native error wording is not pinned as a compatibility test.

The native probe `scripts/aws/ssm_secret_reference_probe.py --endpoint <loopback>
--output <new-file>` re-executes these uniquely owned scenarios and records local
responses. The first local CreateSecret uses the implicit default-key path to
initialize the real regional managed key rather than assuming the native
account's alias already exists. Optional selector, stage-condition,
validation-authority and missing-authorization modes isolate those additional
observations. The Secrets Manager owner now matches the supplemental empty-stage
authorization/validation outcomes; this is not a Parameter Store reference-input
branch. See [secret write admission](secretsmanager.md#state-authority-and-encryption)
for the expanded native matrix and executable comparison.

After starting an ordinary endpoint, replay native semantic contracts with:

```sh
env PYTHONPATH=scripts/aws python3 -B -P scripts/aws/ssm_parameter_store_probe.py --account 000000000000 \
  --endpoint http://127.0.0.1:4566 \
  --replay testdata/aws/ssm/parameter_store.json --output /tmp/ssm-replay.json
```

The selector/write/empty fixtures select their corresponding `--scenario`.
Native capture additionally requires the shared `cloudtrail_events.py` collector.
Replay never forwards ambient AWS credentials to the local endpoint.

`scripts/ssm_consumers_smoke.py` ran actual signed CodeBuild/ECS workflows against
a Docker-enabled SQLite CLI: batching, precedence, masking, cross-region reads,
missing references, independent task/execution roles and live SSM/KMS denials.
Official Go SDK integration tests cover KMS authority, sharing/revocation,
immutable history and policy/image jobs across memory/SQLite reopen, plus selected
CloudTrail and delivered EventBridge fixture projections. A separate actual CLI
process shutdown/reopen recovered encrypted values/labels and delivered retained
inactivity, expiration-notification and expiration events through SQS after
manual time/drain. The final executable also admitted a real EBS-backed EC2 image,
restarted with an unauthorized overwrite pending, and preserved the old active
value/history after terminal validation rejection. Owned local workflow resources
and processes were cleaned up; the consumer probe's local CMK deletion is
scheduled through the ordinary seven-day KMS path, not claimed physically final.

The combined main CLI replayed the native semantic fixture with SQLite schema
215 and delivered 23 local Parameter Store events through EventBridge/SQS.
[`ssm_main_integration.json`](../testdata/integration/ssm_main_integration.json)
records the successful decoded-output comparison and confirmed owned cleanup.
That local event count is not a claim that AWS delivered the same count.

The focused `scripts/ssm_consumers_smoke.py --secret-references` mode also ran real
Docker CodeBuild and ECS consumers against a CMK-backed secret's current/previous
versions. It proved exact CodeBuild masking, independent execution/task roles,
live Secrets Manager and KMS denial, restored successful execution, no retained
SSM reference metadata or consumer plaintext, and owned cleanup. This CMK
container proof is local; native KMS-denial capture used the pre-existing
AWS-managed Secrets Manager key without mutating it.
The combined main assembly repeated both ordinary-parameter and reference
consumer modes under the race-enabled CLI. The linked main capture includes
12-parameter CodeBuild and 14-parameter cross-region ECS reads, current/previous
secret stages, live denial/restoration and plaintext/reference-metadata checks.
Both modes cleaned their owned resources before controller shutdown.

RunCommand commands go to the official agent's native control channel.
Parameter Store browser CRUD uses ordinary APIs.
SDK model revisions are recorded by the generated frontend and fixture index.

## AppConfig document sources

The existing document owner also retains `ApplicationConfiguration` and
`ApplicationConfigurationSchema`; AppConfig reads their actual selected source
through SSM `GetDocument`, not a separate content store. Create, update, describe,
list/filter, default-version selection and deletion use the same version history,
current resource authority, tags and memory/SQLite transaction domain as Command
documents. Run Command rejects these non-executable document types.

Configuration content may be JSON or YAML. Schema documents are JSON-only on
create/update and must declare root `additionalProperties: false`. As observed
natively, schema keyword compilation is deferred until a configuration consumes
the schema. Invalid JSON/YAML, invalid schema keywords at consumption and schema
validation failures reject the write without consuming a version. The evaluator
uses JSON Schema draft 4 by default and resolves local schema references; it
does not fetch external schema URLs or host files.

`ApplicationConfiguration` creation requires exactly one `Requires` entry.
The entry's name or same-account ARN identifies an
`ApplicationConfigurationSchema`; omitted versions select its default, and
`$DEFAULT`/`$LATEST` resolve immediately to an immutable numeric version.
`RequireType` and `VersionName` inside that entry are rejected by native SSM.
Updates retain the pinned schema version. The owner stores the schema document's
incarnation as well as its name/version: deleting and recreating an identical
schema does not silently retarget an existing configuration.

Creation requires current `ssm:GetDocument` authority on the schema. Existing
configuration updates revalidate the pinned schema without a separate schema
read permission, and configuration reads require their own current
`ssm:GetDocument` authority. Schema deletion requires `Force`, including for an
unreferenced schema or a nondefault schema version. Forced deletion does not
erase already-admitted configuration bytes; subsequent configuration updates
fail when their schema is missing or has been recreated. Ordinary document
default-version deletion protection still applies.

Same-format `GetDocument` preserves the exact original bytes and selected
version; explicitly requested JSON/YAML conversion preserves the data, not AWS's
printer whitespace. The official SDK owner smoke exercised both backends,
SQLite reopen, raw JSON and YAML history, failed-schema atomicity, type filters,
describe/list/default/version deletion, and forced-schema-deletion behavior.
The retained [native capture](../testdata/aws/ssm/application_configuration_documents.json)
includes positive and negative dependency, format, incarnation and IAM cases,
request IDs for the SDK calls, and exact-owned cleanup. It is replayed against
both repositories by `TestApplicationConfigurationNativeDependencies`.

`DeploymentStrategy` documents use the same immutable content and authority
paths for AppConfig's `SSM_DOCUMENT` replication. Native SSM admits JSON or YAML
with schema version `1.0`, required integer nonnegative deployment duration and
growth factor from 1 through 100; description, nonnegative integer bake time and
`LINEAR`/`EXPONENTIAL` growth type are optional. Unknown fields are rejected.
Unlike AppConfig API inputs, direct SSM documents do not enforce a 1440-minute
duration/bake maximum or a 1024-character description maximum. Stored content is
not populated with AppConfig defaults and is never executable by Run Command.
The [native strategy-document capture](../testdata/aws/ssm/deployment_strategy_documents.json)
records these boundaries, original/default/latest source bytes and cleanup.
`TestDeploymentStrategyNativeDocuments` replays it on both repositories; an
official SDK owner smoke also verified exact source history, invalid-growth
atomicity, type filtering, deletion and SQLite reopen.

Sources: [SSM DocumentRequires](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DocumentRequires.html)
and [AppConfig JSON Schema validators](https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-creating-configuration-and-profile-validators.html).

## Document account sharing

`ModifyDocumentPermission` and paginated `DescribeDocumentPermission` retain
owner-managed account grants separately from IAM policies. Private grants select
`$DEFAULT` (also the omitted selector), `$LATEST`, or `$ALL`; adding an existing
recipient replaces its selector, and removal wins when an account occurs in both
lists. Removing `All` removes public access only, not private recipients.
Document deletion requires revoking its grants first. Nondefault version deletion
remains available, never reuses a version number, and deleted content is no longer
readable. Grants are tied to the document incarnation by cascading storage
ownership and are not inherited by a recreated document.

Recipients use the full, same-Region document ARN for `GetDocument`,
`DescribeDocument`, version listing and `SendCommand`. Version selection is
checked against the current grant before returning source bytes or constructing a
command. `ListDocuments` includes shared ARNs, with `Owner=Private` and
`Owner=Public` discovery and collision-free pagination alongside locally owned
documents. The account grant supplies only resource-side authorization: current
caller identity permission, explicit denials and other IAM restrictions still
apply. A share never gives a recipient update, tag, delete or re-sharing rights.
AppConfig's existing retrieval role and `ssm-document://` source path read these
same selected bytes through SSM; a revoked share or current role denial prevents
a new deployment without erasing already-deployed configuration snapshots.

Public `All` sharing exposes all document versions and cannot coexist with private
account grants. It is governed by the existing SSM service-setting owner:
`/ssm/documents/console/public-sharing-permission` accepts `Enable` and `Disable`
through `GetServiceSetting`, `UpdateServiceSetting` and `ResetServiceSetting`.
Its default is `Enable`; `Disable` blocks newly public documents but does not
revoke existing public grants. The setting, grants and content survive SQLite
restart and remain scoped to account and Region. Mutating the setting requires
its own IAM authorization on the `servicesetting/ssm/documents/console/public-sharing-permission`
ARN. Per-request account limits, private-recipient limits and public-document
limits are enforced. Document sharing through AWS RAM is not implemented.

The bounded [native capture](../testdata/aws/ssm/document_sharing.json) records
same-account selector replacement, removal precedence, `All` removal, shared
nondefault-version deletion, default-setting discovery and exact-owned cleanup;
it did not create public or third-party native grants. SDK integration coverage
includes separate-account content reads, IAM and revocation boundaries,
version/name selection, public blocking, AppConfig data-plane bytes and retained
SQLite reopening. `scripts/ssm_document_sharing_smoke.py` runs isolated real local
server processes, consumes shared configuration through AppConfig, reopens SQLite,
and exercises shared Run Command admission without inventing an agent.
The retained [executable proof](../testdata/integration/ssm_document_sharing_runtime.json)
records actual cross-account AppConfig bytes, process-restart retention, current
IAM/revocation failures and successful exact-owned cleanup. Run Command evidence
in this capture is zero-target admission, not shared-document guest execution.

Sources: [ModifyDocumentPermission](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ModifyDocumentPermission.html),
[DescribeDocumentPermission](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeDocumentPermission.html),
and [Sharing SSM documents](https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-ssm-sharing.html).

## Command documents and managed execution

`CreateDocument`, `UpdateDocument`, `UpdateDocumentDefaultVersion`,
`DeleteDocument`, `GetDocument`, `DescribeDocument`, `ListDocuments` and
`ListDocumentVersions` retain Command documents independently of parameters.
JSON/YAML input, immutable version contents/hashes, monotonically increasing
version IDs, default/latest/numeric selection, creation tags and version deletion
use current IAM authority. `AWS-RunShellScript` is the captured AWS-owned schema
1.2 document, not an invented local script template. Customer Command schemas
1.2, 2.0 and 2.2 admit the existing `aws:runShellScript` engine. Original JSON/YAML
content, hashes and schema metadata remain immutable; parameter defaults and
interpolation are executed by the official agent.

Create and update admit actual per-version `Creating` and `Updating` states.
Shared durable jobs activate those versions at the admission service-clock
instant when drained; this models the native asynchronous boundary, not its
wall-clock latency. Default/latest pointers remain independent: an Active
default version can coexist with an Updating latest version. SQLite reopen
recovers pending activation. Each document owns a durable UUIDv4 incarnation,
stable across updates and changed by deletion/recreation; CloudTrail's native
`documentId` comes from that state without inventing a public Smithy member.

`SendCommand`, `CancelCommand`, `ListCommands`, `ListCommandInvocations`,
`GetCommandInvocation` and `DescribeInstanceInformation` expose retained commands,
per-instance invocations and per-plugin results. Explicit IDs, EC2 tag targets
and current Resource Groups membership resolve registered, running instances
through their existing owners.
Document and instance IAM checks precede admission. Public document-version
selectors and submitted parameters are preserved, while executable content/hash
are snapshotted: changing or deleting a document cannot change admitted work.
Zero-target admission likewise returns and journals `Pending`; a retained
same-clock job settles Success / `NoInstancesInTag` without creating invocations
or executing agent work. Cancellation before draining consumes that eligibility
and cannot be undone after restart.

### Customer Command schemas 1.2 and 2.0

Schema 1.2 uses `runtimeConfig` and plugin `properties`; schemas 2.0 and 2.2 use
ordered `mainSteps` and `inputs`. The derived execution plan follows the official
agent rather than rewriting the customer's document:

- A legacy `aws:runShellScript` runtime entry produces **one invocation plugin**
  named `aws:runShellScript`, even when its properties contain several execution
  objects. Property `id` values are agent orchestration identifiers, not public
  `PluginName` values. Object, list and empty-list properties retain their native
  admission behavior. The agent owns execution and output aggregation.
- Schema 2.0 uses each step's `name` as its invocation plugin name. A `precondition`
  on a 2.0 step is rejected; 2.2 preconditions remain agent-owned. Native 1.2
  runtime/property precondition fields are admitted but are not translated into
  2.2 conditions. Likewise, legacy `commands` is not rewritten to `runCommand`.
- Native `UpdateDocument` rejects updates **from or to schema 1.2**, including a
  proposed migration to 2.2. Schema 2.0 supports immutable version updates and
  numeric/default/latest selection through the existing document owner.
- Delivery expiry uses the first legacy property only, but sums modern step
  timeouts. The official agent still executes all legacy properties. Omitted
  timeout parameters contribute 3600 seconds even if the document default differs;
  invalid unconstrained timeout values also fall back to 3600. Declared parameter
  constraints are checked first, so the built-in document still rejects values
  excluded by its `executionTimeout` constraint. No controller shell executor,
  synthetic agent result or schema migration is involved.

The reviewed native probes used exact-owned documents and unique zero-target tag
selectors in `000000000000/us-east-1`. The
[main capture](../testdata/aws/ssm/stackd-ssm-schema-668d4554581f.json) retains
Create/Get/Describe/Update/SendCommand admission for JSON/YAML, property IDs and
shapes, parameter constraints, interpolation metadata, schema-specific
preconditions and invalid combinations. The
[timeout-order capture](../testdata/aws/ssm/stackd-ssm-schema-33c3943e36e3-timeouts.json)
distinguishes first-property accounting from maximum/sum accounting.
The [initial throttled capture](../testdata/aws/ssm/stackd-ssm-schema-d5cb7fa34521.json)
is preserved, together with
[confirmed cleanup of its three throttled deletions](../testdata/aws/ssm/stackd-ssm-schema-d5cb7fa34521-cleanup.json).
Every exact-created native document was subsequently confirmed absent. Native
execution was **not** attempted; admission captures do not establish native
runtime, platform or legacy `ENV_VAR` behavior.

`TestNativeCommandSchemaAdmission` replays observed admission;
`TestCommandSchemaPluginIdentityAndDeliveryExpiry` protects plugin identity and
schema-specific deadline accounting. Signed SDK
`TestSSMCommandSchemasLifecycleAuthorityAndRestart` exercises memory and SQLite
source/hash retention, constraints, update rejection/selection and scoped IAM.
The [actual executable proof](../testdata/integration/ssm_command_schemas_guest_20261001_final.json)
boots an official Ubuntu image with official agent **3.3.5390.0-1**, executes
parameterized success and exit-7 failure for all three schemas in both JSON/YAML,
checks real plugin names and multiple legacy property outputs, retains selected
versions through two controller restarts, and checks document-scoped and
current-node IAM denial plus CloudTrail records. All seven local documents and
the owned guest, volume, network, image, snapshot and IAM resources were cleaned
and checked. The [first local capture](../testdata/integration/ssm_command_schemas_guest_20261001.json)
records an incorrect smoke expectation about the agent's extra newline between
property outputs; its resources were also cleaned. Only the smoke expectation
changed before the final run.

Reproduce with the existing firmware-booted official-agent prerequisites:

```sh
python scripts/ssm_command_schemas_guest_smoke.py \
  --binary bin/stackd \
  --raw-image /path/to/official-ubuntu.raw \
  --agent-package /path/to/amazon-ssm-agent.deb \
  --state-directory /tmp/new-owned-ssm-schema-state \
  --output /tmp/ssm-schema-proof.json
```

Sources: [document schemas and features](https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-schemas-features.html),
[shell plugin contracts](https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-command-ssm-plugin-reference.html#aws-runShellScript),
and the [official agent document parser](https://github.com/aws/amazon-ssm-agent/blob/mainline/agent/framework/docparser/docparser.go).
Additional plugins, document engines, attachments and non-Linux execution remain
explicit gaps; admitting these Command schemas does not claim those workflows.


### Run Command Resource Groups targets

`resource-groups:Name` selects one same-account, same-region group by name or
ARN. Optional `resource-groups:ResourceTypeFilters` must include
`AWS::EC2::Instance` or `AWS::SSM::ManagedInstance`; native AWS also admits other
types alongside a supported type, but they do not become executable nodes.
Only registered, running EC2 nodes use the official-agent execution path here.
Hybrid `mi-` enrollment remains unavailable; selecting only the managed-instance
type does not silently select EC2 nodes. Group targets cannot be mixed with
instance-ID or tag selectors. Duplicate keys/values and multiple group names
are rejected.

The Resource Groups owner resolves its current query and owner membership using
the shared transaction context; SSM does not scan an independent tag catalog or
retain another membership store. The caller requires current
`resource-groups:ListGroupResources` on the group, plus the existing document and
per-instance `ssm:SendCommand` authority. Native zero-target calibration shows
that `GetGroup`, `GetGroupQuery` and `tag:GetResources` are not additional
permissions for this consumer, even though the interactive Resource Groups
query APIs have their own authorization contract.

Missing and empty groups complete with `Success` / `NoInstancesInTag`. Group
listing denial admits a command with `Failed` / `AccessDenied`, rather than
fabricating an empty successful selection. Its terminal transition uses the
existing SNS notification owner. Local selection is fixed during admission:
later tag/query changes affect new commands, never previously retained
invocations, including after SQLite restart. AWS initially returns `Pending`
and resolves membership/denial asynchronously; this implementation does not
reproduce AWS's internal selection latency.

The reviewed [native admission/IAM capture](../testdata/aws/ssm/stackd-ssm-rg-3347d1af0988.json)
retains terminal outcomes as well as initial responses. The
[type/ARN boundary capture](../testdata/aws/ssm/stackd-ssm-rg-boundary-7f5ed62afe.json)
records mixed EC2/S3 acceptance and duplicate-value rejection. Both independently
verify exact-owned cleanup. The [first aborted probe](../testdata/aws/ssm/stackd-ssm-rg-251bef6f501c.json)
found the ownership-tagged group inside its own AllSupported query; its safety
gate prevented every SendCommand and deletion was verified. These are native
zero-target captures, not native guest membership-change/timing proof.
The independent [native official-agent evidence](../testdata/aws/ssm/managed_execution_summary.json)
already establishes real `ssmmessages` shell execution, current caller IAM,
guest reboot and exact-owned cleanup; it does not establish group-selection
timing under concurrent AWS membership changes.

The signed Go SDK regression
`TestSSMResourceGroupsCurrentMembershipAuthorityAndRetention` covers current
tag/query membership, stopped/unregistered exclusion, per-instance and group
IAM, account/region isolation and accepted selection across memory/SQLite
reopen. Its seeded owner state does not claim guest execution.
The actual [firmware-booted guest evidence](../testdata/integration/ssm_resource_groups_guest.json)
uses `scripts/ssm_resource_groups_guest_smoke.py` and the official SSM Agent:
group-selected commands returned actual stdout, removed tags excluded work,
an independent guest command proved the excluded marker never existed, and an
already-selected command completed after group-query change plus controller
restart. New commands observed the changed/restored membership. Real
Invocation `InProgress`/`Success` SNS→SQS notifications survived the same
restart. The group, notifications, guest attachments and owned control resources
all have independent cleanup receipts; reusable image/package inputs were
unchanged.

Primary contract: [Run commands at scale](https://docs.aws.amazon.com/systems-manager/latest/userguide/send-commands-multiple.html).

### Run Command SNS notifications

`NotificationConfig` and `ServiceRoleArn` use the existing IAM and SNS owners.
Admission checks the caller's `iam:PassRole` (including
`iam:PassedToService=ssm.amazonaws.com`), same-account role identity, and current
SSM service trust. The retained role incarnation prevents deleting/recreating the
same role ARN from granting an old command the replacement role's authority.
Publishing assumes that pinned role with current trust, then uses ordinary SNS
`Publish`: current role policies, topic policies, and SNS/KMS encryption authority
remain effective. Notification failures do not turn a successful guest command
into a failed command.

`NotificationType=Command` publishes changes to aggregate command status;
`Invocation` publishes changes to each actual managed-node invocation. Omitted
type defaults to `Command`, and omitted/empty events default to `All`, as observed
in the native capture. `All` or selected `InProgress`, `Success`, `Failed`,
`TimedOut`, and `Cancelled` filters apply to committed transitions only. Pending
and Cancelling are never notified. Neither empty-target commands nor an offline
agent fabricate an invocation/InProgress event. Aggregate status is not copied
from a plugin: with the default error budget, an execution timeout can notify
`Failed` for the command but `TimedOut` / `ExecutionTimedOut` for its invocation.

Messages use the native JSON projections and SNS subject
`EC2 Run Command Notification <region>`. Command messages include `commandId`,
`documentName`, directly requested `instanceIds` (an empty array for tag targeting),
`requestedDateTime`, `expiresAfter`, output bucket/prefix, `status`, and `eventTime`.
Invocation messages instead include `instanceId` and the natively observed
`detailedStatus`, without command-only target/output/deadline fields. Event time
is the observed transition time, not a retry's publish time. SNS owns the actual
notification envelope, signing and downstream subscription delivery.

Typed notification intents commit atomically with the command/invocation
transition. The shared scheduler publishes outside the SSM transaction and
retains SNS acceptance or the last delivery error. Failed handoffs retry after
30 service-clock seconds, including after SQLite/process restart. This is a
deterministic local recovery cadence, **not** a measured AWS retry schedule.
Delivery is at least once: a crash after SNS acceptance but before the SSM
acknowledgment commit can duplicate that transition. Pending intents remain
pending under denied or deleted authority; the controller does not fabricate
delivery success, silently drop them, or retarget a replacement role. SNS does
not promise ordering, and the native capture includes terminal messages received
before their InProgress message.

The [native official-agent capture](../testdata/aws/ssm/notifications_native_20261001.json)
retains 20 actual SNS/SQS messages covering both notification types, success,
failure, cancellation and execution timeout, plus successful commands excluded
by Failed-only filters. It also records omitted-event/type defaults and
missing-role/topic errors. The bounded probe created its own EC2 guest,
IAM roles/profile, network, output resources, topic, queue and subscription;
independent absence checks confirm cleanup. Immutable command history and
terminated EC2 tombstones are not claimed deleted.

The [final executable guest proof](../testdata/integration/ssm_notifications_guest_20261001_final.json)
uses the unmodified official agent `3.3.5390.0` inside a firmware-booted Ubuntu
QEMU/KVM EC2 guest. Fifteen notification cases delivered 23 real SNS/SQS messages:
both status projections, event filtering, current role/topic/trust denial and
recovery, and SQLite process restart with undelivered intents. An actual guest
agent outage produced only DeliveryTimedOut notifications, not invented
InProgress events; after reconnect, a guest filesystem check proved the expired
commands never executed. Every owned guest, image/snapshot, volume/ENI, network,
role/profile, topic, queue and subscription was removed with independent public
absence checks.

`TestSSMNotificationsAuthorityFiltersAndRecovery` exercises signed Go SDK
contracts on memory and SQLite, including PassRole/trust denial, empty-target
events, filtered/unobserved transitions, current role/topic recovery, restart and
role-incarnation fencing. The executable proof is separate from those
empty-target regressions and never injects agent status. Its initial
[failed observation](../testdata/integration/ssm_notifications_guest_20261001.json)
is retained: cancellation readiness incorrectly polled plugin status through
GetCommandInvocation while the real agent was already executing. The corrected
workflow uses the existing ListCommandInvocations readiness observation;
both runs independently cleaned their resources.

To reproduce with immutable official image/package inputs:

```sh
python3 scripts/ssm_notifications_guest_smoke.py \
  --binary bin/stackd \
  --raw-image /path/to/official-ubuntu.raw \
  --agent-package /path/to/amazon-ssm-agent.deb \
  --state-directory /tmp/ssm-notifications-new-owned-state \
  --output /tmp/ssm-notifications-new-proof.json
```

This reuses the existing managed guest workflow and requires its
QEMU/KVM/Docker/SeaBIOS prerequisites. Local credentials are synthetic; native AWS
credentials are never forwarded to the controller.

Sources: [notification configuration and permissions](https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-sns-notifications.html)
and [native JSON examples](https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-sns-examples.html).

### Run Command CloudWatch alarms

`SendCommand.AlarmConfiguration` retains one named CloudWatch metric or composite
alarm and `IgnorePollAlarmFailure` (default `false`). Empty lists, more than one
alarm, blank names and names longer than 255 characters return
`ValidationException`. An initial `ALARM` observation rejects admission even when
poll failures are ignored. `OK` and `INSUFFICIENT_DATA` permit execution. A missing
alarm or failed observation is `UNKNOWN`: admission rejects it unless
`IgnorePollAlarmFailure=true`.

Monitoring uses the current `AWSServiceRoleForAmazonSSM` service-linked role,
not the sending user's CloudWatch permissions or the optional SNS notification
role. The existing IAM owner provisions the role when needed, enforcing the
caller's `iam:CreateServiceLinkedRole` authority and `iam:AWSServiceName` condition.
Each observation assumes the current original role incarnation and enters the
CloudWatch owner's authorized `DescribeAlarms` boundary. Commands retain the role
ID, not credentials, trust documents or policy snapshots. Active monitors
participate transactionally in IAM's role-deletion usage check. Stopping
monitoring releases that usage but does not invalidate live IAM sessions.

Alarm polls are durable jobs in the existing shared scheduler. CloudWatch
observations occur outside the SSM write transaction; a revision/due/state fence
prevents an old observation from overwriting cancellation or terminal work.
Pending delivery waits for any due observation. Polls recur after five
service-clock seconds, including after SQLite restart. **This is a deterministic
local cadence, not measured AWS timing.** Ignored `UNKNOWN` observations remain
scheduled, so a subsequently created alarm can still stop pending work.

A later `ALARM` makes the command `Failed` / `FailedDueToAlarm`; a non-ignored
`UNKNOWN` makes it `Failed` / `FailedDueToUnknownAlarmState`. `TriggeredAlarms`
contains the alarm's name and observed `ALARM` or `UNKNOWN` state. Outstanding
invocations/plugins become `Failed` / `Terminated`, with response code `-1` and
no retained plugin output. They count as completed, not execution errors or
delivery timeouts. Ordinary cancellation, notifications and node-incarnation
handling remain with their existing owners.

Crucially, this alarm transition **does not send an agent cancellation message or
kill a running guest process**. The retained
[native lifecycle probe](../testdata/aws/ssm/alarms_native_lifecycle_20261001.json)
used two official-agent EC2 guests with concurrency one. After both an `ALARM`
and a non-ignored alarm deletion, the public invocation rows were
`Failed` / `Terminated`, but a later real command read `started\nfinished\n` from
the active guest's marker and `marker-absent\n` from the pending guest. With
ignored alarm deletion, both guests completed. These are measured shell-command
cases, not claims about every Systems Manager plugin or arbitrary application.
Late replies cannot replace those terminated public results.

The [native admission and caller-policy capture](../testdata/aws/ssm/alarms_native_20261001.json)
covers alarm list/name validation, all three CloudWatch states, missing alarms,
both ignore settings, and caller CloudWatch denial/revocation. The
[read-only native role capture](../testdata/aws/ssm/alarms_native_actor_20261001.json)
retains the existing service-linked role trust and `AmazonSSMServiceRolePolicy`
v17. Both compute probes verified account `000000000000` / `us-east-1`, used
exact-owned resources, and independently verified their cleanup; the preexisting
native service-linked role was read-only. Command history and terminated-instance
tombstones remain provider-owned history.

`TestSSMAlarmsAdmissionCurrentAuthorityAndRecovery` exercises signed Go SDK
admission, current IAM dependency authority, CloudWatch transitions, cancellation,
retained recovery and role-deletion usage on memory and SQLite.
`TestAlarmObservationCannotOverwriteConcurrentCancellation` covers the external
observation race, and `TestAlarmAdmissionRechecksDocumentAfterExternalObservation`
covers document deletion/replacement before admission commits.

The [passing executable proof](../testdata/integration/ssm_alarms_guest_20261001_final.json)
uses two firmware-booted Ubuntu QEMU/KVM EC2 guests with unmodified official SSM
agent `3.3.5390.0`. Actual commands execute in `OK` and `INSUFFICIENT_DATA` and
deliver their SNS notifications. An alarm raised while concurrency one leaves
one invocation pending reproduces the native terminated public results; real
marker readback proves the running shell finishes and the pending shell never
starts. Missing-alarm admission, ignored live deletion with both guests
succeeding, non-ignored live deletion with `UNKNOWN`, and process restart followed
by recovery of the retained monitor all use the current CloudWatch owner.

Independent public observations verify removal of both guests, both volumes and
ENIs, image/snapshot, network, roles/profile, alarms and SNS/SQS resources. Only
after guest/resource teardown, cleanup reopens the controller on its supported
manual timeline and advances the public service clock to expire outstanding IAM
sessions before deleting the monitoring service-linked role; it never edits
credential rows or bypasses IAM deletion protection.

The [initial startup failure](../testdata/integration/ssm_alarms_guest_20261001.json)
and [subsequent fixture failure](../testdata/integration/ssm_alarms_guest_20261001_staged.json)
are retained rather than rewritten. The fixture now separates EC2 provisioning
from the agent-registration deadline and avoids a method name that collided
with the inherited state-directory attribute. Neither failure established an
alarm-service or EC2 production defect.

To reproduce using immutable official image/package inputs:

```sh
python3 scripts/ssm_alarms_guest_smoke.py \
  --binary bin/stackd \
  --raw-image /path/to/official-ubuntu.raw \
  --agent-package /path/to/amazon-ssm-agent.deb \
  --state-directory /tmp/ssm-alarms-new-owned-state \
  --output /tmp/ssm-alarms-new-proof.json
```

Sources: [AlarmConfiguration](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_AlarmConfiguration.html),
[SendCommand](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html),
[Run Command parameters](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-param-runcommand.html),
[console alarm behavior](https://docs.aws.amazon.com/systems-manager/latest/userguide/running-commands-console.html),
and the [September 26, 2022 composite-alarm release](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-release-history.html).

### Managed-agent execution and evidence

Tag selection distinguishes a missing tag from a present empty value; both command
targeting and fleet filtering use current EC2 tag presence. `AWS-RunShellScript` in
`aws/us-east-1` carries the natively confirmed resource owner `187340769485` for
IAM conditions, while its public ARN remains account-less. Documents and commands
use the same authority; the caller's account is not substituted for that owner.
Empty **command target** values can select an explicitly empty-valued tag. Fleet
filter values themselves must be nonempty (also confirmed by the native request
in `managed_execution_fleet_empty_value.json`); use `tag-key` to discover those
empty-valued tags rather than bypassing the generated public constraint.

Command admission measures the actual agent execution payload and its parameter
representation against the observed **100000-byte** boundary (the provider error
calls this “97KB”). The calculation includes serialized list/escape overhead,
compact document content, document name and selected output fields. It reuses the
wire payload builder rather than a second parameter-size approximation. This
replaces the incorrect 64-KiB value-only heuristic and rejects permanently
unsendable work before command/invocation state can block the control channel.
Native boundary pairs cover ASCII, empty StringLists, NUL, HTML characters,
non-ASCII, S3/CloudWatch options and three versions of a customer document.

The official agent signs its private `UpdateInstanceInformation` request and
native `ssmmessages` Create/OpenControlChannel traffic with the existing EC2
instance-profile credentials. The gateway authenticates these requests; the
managed execution owner binds the signed origin to the exact instance and checks
current IAM and EC2 lifetime. Control-channel tokens are short-lived, one-use
and bound to the authenticated node/session. Reconnect replaces the old channel.
Native binary framing, message IDs, acknowledgments and durable reply deduplication
are separate from command state.

Delivery intent commits before network writes. Retries retain the same job and
message IDs; the official agent's durable execution state prevents repeated
customer side effects. Concurrency and error budgets gate queued invocations.
Cancellation distinguishes undelivered work from an agent-owned running process.
Controller expiry waits for a terminal agent reply, not merely a delivery ACK.
The agent alone supplies execution status, exit code, stdout/stderr, plugin
timestamps and actual S3/CloudWatch uploads under its current role. Output is not
redacted, replaced with a canned result or generated by the controller.

The official agent sends terminal document and plugin replies concurrently.
A terminal document reply can arrive before an individual plugin's result;
late plugin details are retained without reopening the terminal invocation.
The actual guest exposed this race, now covered across both repositories and
reopen. The agent's persisted-reply scan runs every two minutes: a short
delivery deadline can legitimately expire during a controller outage even when
the guest completed its side effect. Restart workflows therefore use a delivery
budget that covers that native retry cadence, not a synthetic immediate reply.

Fresh native captures under `testdata/aws/ssm/managed_execution_*.json` cover
official agent 3.3.5226.0, successful and nonzero execution, plugin cancellation,
execution/delivery timeout, output delivery, reboot, current same-session IAM
denial, immutable document history/defaults and validation. The current-agent
role explicitly denied `ec2messages:*`, establishing the `ssmmessages` path.
Native observations include:

- `executionTimeout=2` is admitted, but the agent falls back to its 3600-second
  plugin timeout; `5` really times out a 20-second process with response code 137.
- Execution timeout uses `ExecutionTimedOut`; a missing terminal reply expires as
  `DeliveryTimedOut`, including after delivery acknowledgment. With the default
  zero error budget, the captured execution-timeout command aggregates to Failed.
- A running EC2 instance with its agent stopped can accept a command while its
  last health report still says Online. A stopped EC2 instance cannot be targeted.
- Total delivery expiry includes document step execution budgets. Supplied
  timeout references contribute their values; omitted references contribute
  3600 seconds rather than the document's parameter default.
- A tag target matching no managed nodes finishes Success / `NoInstancesInTag`.

`scripts/aws/ssm_managed_execution_probe.py` owns native capture and exact cleanup.
All mutable native resources from these captures were removed; command history
and provider tombstones cannot be deleted through a fictitious DeleteCommand API.
Three sequential native guest lifetimes totalled 469.349 seconds, with at most one
guest alive at a time. No standing host-management setting was changed.
Memory/SQLite fixture replay and signed SDK/CLI document workflows cover immutable
selection, authority and restart. State-machine tests cover concurrency,
error-budget termination, duplicate replies, cancellation, expiry and instance
credential/lifetime fences; they do not execute fake customer programs.

The lossless `managed_execution_admission*.json.gz` fixtures add 331 cheap native
calls, including exact size boundaries and immutable federation-session policies
that resolve the built-in owner by bounded prefix partition and exact match.
Each batch first proved its unique tag had no EC2 or managed-node matches; none
executed on a native guest. The sole customer document was deleted and its absence
verified. There were no standing IAM/settings changes or new instances/IPs.
The 132 accepted zero-target command histories are intentionally retained because
AWS exposes no delete-command API; temporary federation credentials were redacted.

`managed_execution_audit.json` retains the bounded native CloudTrail collection:
615 tracked SSM request IDs, 611 correlated events plus 31 exact-owned agent
events. Four malformed fleet calls were **not observed within collection bounds**,
not declared absent. All eight document APIs and six command/fleet APIs use the
shared audit projection and CloudTrail serializer. Document contents and command
parameters are hidden in audit only; API/agent data and actual stdout/stderr remain
unchanged. Captured mutations retain response wrappers, reads omit result bodies,
and no invented resource rows are added. The 24 native private health events are
Management writes with null responses, exact lower-first-character SDK names,
present `iPAddress` replaced by `HIDDEN_DUE_TO_SECURITY_REASONS`, and present empty
`sSMConnectionChannel` retained. The private SDK generator preserves that field
presence instead of maintaining a second handwritten request model.
`managed_execution_admission_audit.json` separately correlates all 15 selected
new request IDs. Fourteen size rejections retain the full request projection
(parameters hidden), rather than falsely dropping the whole request; the exact
provider-owner policy success retains its initial Pending command snapshot.

[`managed_execution_local_guest.json`](../testdata/aws/ssm/managed_execution_local_guest.json)
records the successful assembled CLI/SDK/agent workflow: 20 observations,
including actual guest marker bytes, stdout/stderr, exit 7, execution timeout 137,
cancellation 137, two-version multi-plugin documents, AWS CLI document reads,
same-session current IAM denial, in-flight SQLite controller restart returning
exactly `once\n`, retained completed output, actual S3 objects/CloudWatch messages,
guest reboot with changed boot ID and retained bytes, offline delivery expiry,
and agent reconnect without an expired-command side effect. Fourteen exact
resource-absence checks passed before controller shutdown.

[`managed_execution_local_guest_audit.json.gz`](../testdata/aws/ssm/managed_execution_local_guest_audit.json.gz)
repeats the complete workflow on the final executable in dedicated account
`815602947104`: 25 observations in 429.07 seconds, 14 exact resource-absence
checks, no cleanup errors and no remaining exact-owned native bridge.
Its 87 request-correlated public CloudTrail records cover all 14 implemented
document/command/fleet APIs, alongside seven real official-agent health records.
The agent executes after rejecting the oversized empty StringList, never runs the
missing-tag command, executes the present empty-tag command, and honors the
captured provider-account IAM condition. Actual Creating/Updating/Pending API
snapshots match audit; durable jobs settle them, document UUIDs survive updates
and change on recreation, and in-flight controller restart still returns exactly
`once\n`. This is executable/SDK/guest evidence, not only serializer replay.

The reproducible workflow imports a read-only Ubuntu cloud image through signed
EBS APIs and installs the unmodified official Debian agent package:

```sh
python3 -B -P scripts/ssm_managed_guest_smoke.py \
  --binary /path/to/stackd \
  --raw-image /path/to/ubuntu-cloud-image.raw \
  --agent-package /path/to/amazon-ssm-agent.deb \
  --state-directory /tmp/new-unique-ssm-run \
  --output /tmp/ssm-guest-evidence.json
```

Each run defaults to a fresh local account and needs an unused subnet/gateway.
Use `--account`, `--cidr`, `--subnet` and `--gateway` to set these explicitly;
do not reuse another live controller's account plus deterministic VPC identity.
`managed_execution_local_gateway_bind_failure.json` preserves the failed
same-account bridge collision and its cleanup rather than misclassifying it as
an agent failure. `managed_execution_local_fleet_filter_failure.json.gz` retains
the subsequent SDK rejection of an invalid empty fleet filter value; the corrected
workflow uses native-valid `tag-key` discovery and literal-empty command targets.
`managed_execution_local_qmp_path_failure.json.gz` preserves a distinct native
108-byte QMP path failure, original pending/attaching state, exact cleanup after
an explicit short-path restart and the corrected CLI rejection. The native
constructor now rejects socket paths above 107 bytes before creating guest state;
choose a short `--state-directory` rather than waiting for agent registration.

The integrated race-enabled schema227 executable repeated all 25 observations in
account `815602947105`, including real S3/Logs output and retained guest execution.
[`ssm_managed_execution.json.gz`](../testdata/integration/ssm_managed_execution.json.gz)
preserves that run's distinct boundary: the 1,000-second wrapper deadline fired
during cleanup, after `TerminateInstances` was admitted. Restarting the same
executable and database completed the remaining cleanup in 31.91 seconds:
all 14 resource-absence checks passed, with no cleanup errors, remaining
exact-owned native bridge or controller listener. This is interrupted-and-recovered
evidence, not an uninterrupted workflow pass.

It requires the existing QEMU/KVM/Docker/SeaBIOS runtime. The bootstrap configures
a full MGS endpoint URL and guest-local S3 virtual-host DNS/certificates: the
official SDK does not force path-style S3 addressing for an IP endpoint.
Preserved local failure captures include those endpoint mistakes, the discovered
out-of-order reply regression, an insufficient restart delivery budget, and
systemd's default timer coalescing. The final outage uses explicit timer accuracy
and waits for graceful shutdown; it does not equate a scheduled stop with an
already offline agent. No native AWS credentials are forwarded to local replay.

Public contracts remain generated from the official AWS SDK model. The private
health request is generated from official `amazon-ssm-agent` SDK source at
`c8fa314de8050cd5dcb3740a29c3ce769f533dcd`:

```sh
make generate-ssm-agent-check SSM_AGENT_PATH=/path/to/amazon-ssm-agent
```

Primary contracts: [SendCommand](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html),
[Run Command status](https://docs.aws.amazon.com/systems-manager/latest/userguide/monitor-commands.html),
[agent permissions](https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-instance-permissions.html),
[native agent source](https://github.com/aws/amazon-ssm-agent).

## Explicit boundaries

- `aws:ssm:integration` enforces the observed reserved namespace but requires its
  separate Systems Manager integration authority; it never fabricates a resource.
- High-throughput service settings return UnsupportedOperation until request-quota
  admission exists. They are not retained as an ineffective success setting.
- Public AWS-maintained parameter catalogs are not synthesized; CloudFormation-
  owned parameter lifecycles belong to that separate resource owner.
- Managed execution is Linux EC2 instance-profile management using the current
  native control channel. Hybrid activations, intrinsic-identity/DHMC enrollment,
  Windows/macOS, legacy `ec2messages`, Session Manager/data channels, State Manager
  associations, Automation, Patch, Inventory and Ops workflows remain separate.
- Documents do not implement attachments or plugins/engines beyond the admitted
  Command shell-script subset and AppConfig source document types.
  Run Command notifications support standard SNS topics, not FIFO topics.
- Local readiness is a durable service-clock transition, not a reproduction of
  AWS's nondeterministic wall-clock latency. Some document error wording/source
  locations still differ; generated identity bindings do not suppress status,
  incarnation or response-shape comparisons.
- The built-in document's IAM resource-owner account is calibrated only for
  `AWS-RunShellScript` in `aws/us-east-1`. Other region/partition owner-condition
  values are unobserved and are not populated from a guessed global account.
- Agent telemetry frames are accepted independently of command outcomes but are
  not yet persisted/exported. Health age uses a deterministic local five-minute
  boundary; this is not a measured native detection deadline. Current role denial
  fences local channels immediately, within AWS's documented up-to-one-hour
  revocation envelope. Established native socket behavior at credential expiry
  was not exercised and is not claimed equivalent.
- Exact native policy delivery cadence, asynchronous validation latency and full
  cross-account/native failure-precedence combinations are not established by
  the selected evidence. Native captures never probe existing user parameters.

Primary contracts: [PutParameter](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html),
[SecureString/KMS](https://docs.aws.amazon.com/systems-manager/latest/userguide/secure-string-parameter-kms-encryption.html),
[parameter policies](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-policies.html),
[AMI validation](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-ec2-aliases.html),
[Parameter Store events](https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-cwe.html),
[Secrets Manager references](https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html).
