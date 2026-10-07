# AppConfig and AppConfig Data

AppConfig owns typed applications, environments, configuration profiles, immutable
hosted versions, deployment strategies, deployments, extensions, experiments and
polling sessions. Both generated REST JSON frontends share the native `appconfig`
SigV4 signing name; generated HTTP routes distinguish the control and data APIs.
Memory and normalized SQLC SQLite repositories use the shared transaction,
authorization, API-event and scheduler owners. This is not a claim of complete
native AppConfig parity; the explicit boundaries below remain important.

Control-list continuation tokens bind partition/account/region, operation and
effective parent/filter inputs. Stable ordered keys survive insertions/deletions
before the cursor and controller reconstruction; changing page size is allowed.
Experiment events use stable reverse ordinals rather than shifting slice offsets.
These are list tokens, separate from one-use AppConfig Data polling tokens.

## Configuration lifecycle

Applications, environments, profiles, custom strategies, hosted versions,
extensions and associations support their modeled create/read/update/list/delete
operations. Native built-in strategies are read-only. Resource names and IDs,
version numbers and labels, optimistic hosted-version creation, pagination,
scoped tags and child/deployment/association deletion blockers are retained.
Hosted content is actual binary data, not JSON-wrapped service state. Content
size admission runs again after a PRE_CREATE extension transforms the payload.
The default regional application quota is 100. Associations must be explicitly
detached before deleting their application, environment or profile.

`SSM_DOCUMENT` strategies create actual Systems Manager `DeploymentStrategy`
documents. Changed strategy content creates a new SSM document version without
moving its default version; deleting the strategy deletes the document. These
state-only owner calls join the AppConfig transaction, so a name collision or
current SSM permission denial cannot leave a strategy committed by itself.

Account deletion protection defaults to enabled with a 60-minute protection
period. Recent polling protects environments and profiles after the native
one-hour new-resource grace period. `APPLY`, `BYPASS` and account-default behavior
remain distinct. Account settings are scoped, durable and transactional.

### Shared tag discovery

Resource Groups Tagging API reads live AppConfig identities and tags through the
existing owner; it does not maintain copied tags. Native mutations reconcile
previously-tagged membership in the same transaction, including last-tag removal
without an intervening inventory read. Deletion removes membership. Shared
TagResources/UntagResources invoke AppConfig's normal commands with the caller's
current resource, resource-tag, request-tag and tag-key permissions.

Native `appconfig:application` discovery includes the application's nested
environments and profiles; `appconfig:environment` and
`appconfig:configurationprofile` match nothing. Resource Groups retains separate
CloudFormation types for those same snapshots, so a profile does not become an
application in a group query.

Extension tags belong to the exact versioned `extension/id/version` ARN.
Unversioned extension ARNs return `ResourceNotFoundException`; versions and
extension associations retain independent tags across restart and deletion.
The [native tagging capture](../testdata/aws/resourcegroupstaggingapi/appconfig.json)
measures applications, environments, profiles, custom strategies, extension
versions and associations, with verified cleanup and no extension invocation.
The source also exposes existing deployment and experiment owners; those types
were not included in this native tagging capture.

`integration/resource_tagging_appconfig_test.go` verifies memory/SQLite ownership,
IAM denial/revocation, scope isolation, both discovery classifications and retained
empty membership. Signed Go SDK workflows against the actual SQLite executable
also reproduced and corrected missing discovery/versioned-tag lookup, then
verified native-only tag removal, process restart, shared mutation and deletion.

### Validation and source owners

JSON schema validators use the native-calibrated draft-04 contract, including
its observed behavior when a schema declares a newer draft. External references
are not fetched. Lambda validators invoke the actual Lambda owner with the
AppConfig validation payload and timeout. A successful function response is not
substituted for execution; a function error rejects admission.

External sources read their current owners through a freshly assumed retrieval
role:

- SSM Parameter Store, including pinned historical versions;
- SSM `ApplicationConfiguration` documents and their pinned
  `ApplicationConfigurationSchema` requirements;
- exact S3 object versions;
- exact Secrets Manager version IDs.

Role trust, role permissions, source existence and KMS permissions are not copied
into AppConfig. Changing them affects subsequent validation/deployment attempts.
An admitted deployment retains its own immutable content; changing the source
does not silently change an existing deployment.

[CodePipeline](codepipeline.md) supplies a separate source owner for
`codepipeline://<pipeline-name>`, without a retrieval role. ConfigurationVersion
is the Deploy action-execution UUID. Retrieval resolves the retained artifact
location and resolved ZIP member, then reads real S3 bytes under the caller's
current authority. A previous successful deployment does not bypass later
S3/KMS denial or substitute cached source bytes after artifact removal.
The [native forwarding capture](../testdata/aws/codepipeline/appconfig_called_via_exact_native.json)
requires the numeric `CalledVia` identifier `460678247002`, not
`appconfig.amazonaws.com`, for the observed `us-east-1` artifact read.
The [European discovery](../testdata/aws/codepipeline/appconfig_called_via_discovery_eu_west_1_native.json)
finds `242796738427` in `eu-west-1`; the US identity is denied there.
The [independent west-region capture](../testdata/aws/codepipeline/appconfig_called_via_exact_us_west_2_ready_native.json)
establishes `783816728759` in `us-west-2` and records successful forwarded S3
access under the original caller. Its trail-deletion failure and subsequent
verified cleanup remain separate evidence.
Other regional/partition forwarding identities remain explicitly unsupported.

Hosted and deployed encryption uses real KMS `GenerateDataKey`/`Decrypt` and the
shared signed committing AWS Encryption SDK envelope (suite `0x0578`).
Encryption context binds hosted data to its full hosted-version ARN and
deployment data to its deployment ARN. A fresh P-384 signing key supplies the
`aws-crypto-public-key` context before requesting the data key; the same key signs
the complete encrypted header and body. Decryption passes the retained context
through current KMS authority and verifies commitment, frame tags and signature
before returning plaintext. Disabled keys, revoked decrypt authority, wrong
contexts and tampered ciphertext fail without a plaintext fallback.

The [native context capture](../testdata/aws/appconfig/kms_context_native.json)
establishes the resource/public-key fields. The
[algorithm-suite](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md)
and [footer](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-footer.md)
specifications define the interoperable encoding; native AppConfig ciphertext
itself was not captured. The [executable proof](../testdata/integration/appconfig_signed_envelope.json)
records official AWS Encryption SDK 4.0.3 reads of stored hosted/deployed bytes,
SDK-produced hosted ciphertext recovered after SQLite restart, frame boundaries,
application consumption and current-key denial/recovery. Previously persisted
unsigned content remains readable under its original context and current
authority. The parser is deliberately restricted to one KMS data key, the
expected resource context with optional signing key, and 4096-byte frames;
this is not a general ciphertext-import API.

## Rollout, rollback and polling

Deployments retain their admitted configuration, strategy, monitors and applied
extension actions. Shared-clock jobs implement linear/exponential rollout,
final bake, alarm rollback, stop and eligible completed-deployment revert.
Effects execute outside state transactions; admission revalidation, durable
effect leases and generation checks prevent stale work from committing over a
newer deployment or stop decision. A revert retains the original completion
timestamp and restores the previous configuration.

`StartConfigurationSession` resolves the application/environment/profile by name
or ID and creates a durable scoped session. `GetLatestConfiguration` returns real
bytes and the generated native content-type, next-token, next-poll and optional
version-label headers. Tokens are single-use, expire, survive SQLite reopening
and cannot be consumed concurrently twice. Early polling or a denied request
does not consume the token. No-change responses contain zero bytes, retain the
content type and omit the version label. Legacy `GetConfiguration` uses its own
client/version contract rather than inventing session tokens.

Current IAM is checked on every poll; possession of a previously issued token
does not preserve permission after revocation. Partition, account and region
scope are enforced. Application/profile/strategy operations retain their own
resource authorization targets; dependent `TagResource` authorization targets
the exact newly created resource, including the new deployment or experiment
run, rather than its parent.

## Extensions, feature flags and experiments

Extension versions retain actions and parameter definitions. Associations bind
extensions to actual AppConfig resources. Required parameters, dynamic values,
version conflicts and native idempotent create behavior are enforced. PRE/AT
Lambda actions execute synchronously; ON actions use Lambda's real durable
asynchronous invocation path. PRE_CREATE/PRE_START content changes become the
admitted bytes, and AT_DEPLOYMENT_TICK rollback directives affect the actual
deployment. SNS, SQS and EventBridge actions use their existing owner services.

`AWS.AppConfig.FeatureFlags` content has native-calibrated schema/admission,
metadata normalization and unchanged-entry timestamps. Plain data polling
returns the default variant projection. AppConfig does not invent an in-process
replacement for the Agent's targeting/evaluation language.

Experiment definitions, runs, updates, stop, events and list/filter operations
use typed normalized state and current IAM. Starting/updating/stopping a run
changes a managed deployment of the existing configuration version; it does not
create a fictitious hosted version. Agent requests negotiate binary Ion and
receive the native experiment metadata. The unmodified official AppConfig Agent
has exercised control/treatment overrides, audience exclusion, an updated
assignment and restoration of baseline content after stopping a run against the
actual local executable.
All eleven modeled experiment operations include definition archive/destroy
semantics and deletion dependencies: nonarchived definitions protect their
environment/profile, and every remaining definition protects its application.
Analytics and the supplied run `Result` remain customer-owned; stopping a run
does not synthesize experiment conclusions. SQLite restart preserves the result
and ordered run events. The executable Agent proof used version 2.0.212925.

## API observations and persistence

Control and data operations use the shared API observation path. Configuration
payloads and validator content are redacted; polling tokens are omitted.
AppConfig Data observations use `appconfig.amazonaws.com`, data-event
classification and the resolved configuration resource ARN. Successful state
mutations and their accepted observation join the same transaction; rejected
calls do not publish successful state changes.

SQLite stores typed resources, binary content, normalized collections, sessions,
rollout due times, generations, captured actions, experiment definitions/runs and
account settings. Restart does not require reconstructing authority from a
serialized SDK response. Existing IAM, Lambda, SSM, S3, Secrets Manager,
CloudWatch, KMS and CodePipeline services remain the authoritative owners.

## Explicit boundaries

- Enabling account `VendedMetrics` is explicitly rejected without changing
  account settings. Native Agent treatment traffic arrives in a compressed
  `Uplink-Payload` transport whose enablement/encoded-count contract has not been
  captured with the authorized native account unchanged. Poll counts are not
  fabricated as treatment counts, and an enabled flag is not reported without
  real CloudWatch publication. Disabling/reading the setting remains supported.
- Native proprietary rollout cohorts are not reproduced. Local deterministic
  monotone cohorts preserve rollout/rollback behavior; monitor/tick observation
  has a one-minute cadence and durable effects use a 30-second lease.
- The native capture accepted one initial-token replay despite the published
  single-use contract. Local tokens intentionally enforce the documented strict
  single-use behavior. The divergent native observation is retained as evidence.
- Native eventual propagation, undocumented page scan order and incidental
  upstream error-message/request-ID formatting are not claimed byte-for-byte.

## Exercised application proof

`scripts/aws/appconfig_executable_smoke.py` launches the actual controller with
SQLite, uses unmodified boto3 and AWS CLI, restarts the controller, and exercises
hosted bytes, session/error transitions, rollout/revert, real Lambda validation
and transformation (including rejected oversized output), current-role source
reads, pinned S3/Secrets/SSM versions, SSM strategy replication, KMS
denial/recovery, CloudWatch rollback and feature flags. It records controller
exit codes and exact-owned cleanup outcomes. Supply the normal installed
Python 3.13 Lambda image, Docker and built Lambda telemetry helpers:

```sh
python3 -B scripts/aws/appconfig_executable_smoke.py \
  --binary /absolute/path/to/stackd \
  --state-directory /absolute/path/to/fresh-owned-directory \
  --telemetry-directory /absolute/path/to/built-telemetry-helpers
```

The assembled schema255→259 [executable evidence](../testdata/integration/service259_executable.json)
also covers retained SSM source consumption, current retrieval-role denial,
immutable deployment bytes and polling after restart. Its official Agent run
observes control/treatment overrides, audience exclusion, changed assignment,
baseline restoration and retained customer results/run events.

Native fixtures are retained under `testdata/aws/appconfig`,
`testdata/appconfig`, and the SSM document fixtures. Native probes verify the STS
caller, create uniquely owned resources and record cleanup. One native KMS key
from encryption-context calibration is in its mandatory deletion window until
2026-10-05T13:15:02.961Z; no claim of immediate KMS deletion is made.

References: [AppConfig API](https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/Welcome.html),
[AppConfig Data API](https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_appconfigdata_GetLatestConfiguration.html),
[IAM operations/resources](https://docs.aws.amazon.com/service-authorization/latest/reference/list_appconfig.html),
[feature flag schema](https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-type-reference-feature-flags.html),
[experiment treatment traffic](https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-experimentation-observing-treatment-traffic.html).

## CloudFormation ownership and optional extension parameters

Applications, environments, configuration profiles, hosted versions, deployment
strategies, deployments, extensions, extension associations, experiments and
experiment runs retain private creation claims on their typed native rows.
Recovery requires the exact claim and current native IAM authority. Public tags
cannot establish, replace or revoke that claim; Cloud Control updates and deletes
retain ordinary native authorization rather than adopting a stack claim.

An extension with no parameters omits the optional `Parameters` map in
`CreateExtension` and parameterless updates. An explicitly empty map is not a
valid substitute: the native map has a minimum of one entry. Updates attempting
to clear an existing map continue to receive the native validation error.
See [CreateExtension](https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_CreateExtension.html)
and [UpdateExtension](https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_UpdateExtension.html).

The private-owner fixture exercises memory and SQLite, lost admission replies,
reopen recovery, foreign same-name rows and current-authority rejection. A
source-built controller smoke creates a six-resource stack with a parameterless
extension, restarts SQLite, updates its description and deletes the stack while
checking the actual AppConfig rows. This is scoped evidence, not full AppConfig
CloudFormation parity.
