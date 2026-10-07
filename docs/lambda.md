# Lambda execution

Lambda is a partial service, not a completed parity claim. The generated frontend
recognizes the pinned SDK model; unsupported operations and configuration paths
return protocol errors rather than metadata-only success.

## Current application path

`CreateFunction`, `GetFunction`, `GetFunctionConfiguration`, `ListFunctions`,
`DeleteFunction`, `UpdateFunctionCode`, `UpdateFunctionConfiguration`,
`PublishVersion`, `ListVersionsByFunction`, `CreateAlias`, `GetAlias`, `UpdateAlias`,
`DeleteAlias`, `ListAliases`, `ListTags`, `TagResource`, `UntagResource` and
synchronous/DryRun/Event `Invoke` run through generated REST JSON labels, queries,
headers, statuses and raw blob payload bindings. `InvokeWithResponseStream` uses
the generated streaming union and AWS event-stream framing described below.
Resource policies, concurrency and asynchronous controls are described below. The nine layer operations
`PublishLayerVersion`, `GetLayerVersion`, `GetLayerVersionByArn`,
`DeleteLayerVersion`, `ListLayerVersions`, `ListLayers`,
`AddLayerVersionPermission`, `GetLayerVersionPolicy` and
`RemoveLayerVersionPermission` use the same frontend.
Direct and S3-backed ZIP deployments use real official AWS runtime images and the
Runtime Interface Client (RIC). There is no imported-handler or RIE HTTP proxy
fallback. The default runtime images are pinned separately:

```text
python3.12 x86_64: public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3
python3.12 arm64:  public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e
python3.13 x86_64: public.ecr.aws/lambda/python@sha256:1db929eee2769af5a502cb0ac7409245a1f5b8f8cb37f43832e9983f7a0aed53
python3.13 arm64:  public.ecr.aws/lambda/python@sha256:48fb06e4f76b6512f055afe0659bffecb2439affd9d0a4d98afba0fdde7bc08f
nodejs22.x x86_64: public.ecr.aws/lambda/nodejs@sha256:0c33b7174dc800aaf810b3f6075aadec654aaf81d96b974a33f91cacf0bbe569
nodejs22.x arm64:  public.ecr.aws/lambda/nodejs@sha256:2f80915b7e49e3ae37a84be1110d313113d3e0c027d3564b489f46d10aae320a
provided.al2023 x86_64: public.ecr.aws/lambda/provided@sha256:0439bff81ff967d34c098fa6d23a0059ff90d339dc8984f1dda007bde039a44f
provided.al2023 arm64:  public.ecr.aws/lambda/provided@sha256:b501fd60cfbd920688576f5cfd6040bf3533a15ce160673758c77ca2dabd312e
```

The Python 3.12/x86_64 digest is its Linux/amd64 child manifest. The former
manifest-list digest could expose empty platform metadata in Docker's
containerd image store. The child pin was installed and ran an actual Python
RIC handler on Linux/amd64 with that image store; this does not independently
verify a new macOS run.

Pull the required platform explicitly before offline use. The executor never
pulls an image. `compute/lambda.DockerConfig.Images` is keyed by
`RuntimePlatform{Runtime, Architecture}`, using AWS's `x86_64` and `arm64` names.
Nil selects the listed defaults; an explicit map is an exact override. Each image must
contain the official entrypoint and actually match the requested Linux CPU
architecture. Python 3.12 execution is exercised on both architectures.
Python 3.13/x86_64 runs the native [Secrets Manager rotation](secretsmanager.md)
ZIP and callback workflow on memory and SQLite. Its arm64 digest is pinned from
the official multi-platform manifest but is not exercised by that replay.

```sh
docker pull --platform linux/amd64 public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3
docker pull --platform linux/arm64 public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e
docker pull nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61
docker pull ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
make build
./bin/stackd -listen 0.0.0.0:4566 -database ./stackd.sqlite \
  -docker-host unix:///var/run/docker.sock -lambda-runtime -lambda-keep-alive 10m
```

The CLI requires an explicit Docker endpoint and `-lambda-runtime`. Docker
transport alone enables no runtime; Lambda does not construct ECS or impose
ECS's local Linux/systemd/cgroup-v2 admission. The native macOS
[Docker Desktop recipe](runtime-containers.md#native-macos-controller-with-docker-desktop)
uses port 4567 and static Linux helpers, with ECS intentionally disabled.
A loopback-only AWS listener cannot be reached through Docker's Linux host
gateway; `-compute-endpoint` selects the reachable AWS origin.
`-lambda-callback-host` and `-lambda-runtime-listen` separately select the Runtime
API callback address and bind address. Docker Desktop's `host.docker.internal`
uses its built-in container DNS rather than a Linux host-gateway override.
No host DNS or trust roots are changed.

`make build` also produces static Linux `lambda-telemetry-amd64` and
`lambda-telemetry-arm64` helpers beside the executable. The CLI uses that
directory by default; `-lambda-telemetry-directory` selects another installation
directory, including when using `go run`. Embedders provide absolute local
artifact paths through `DockerConfig.TelemetryHelpers`, keyed by AWS architecture.
Preparation copies the matching helper through the Docker archive API, including
to remote engines; execution never builds or downloads it.

The disk-storage helper also requires the preinstalled Ubuntu digest above.
`-lambda-storage-image` / `DockerConfig.StorageImage` selects an explicit immutable
equivalent with util-linux and e2fsprogs. The Linux daemon must support privileged
storage helpers, loop devices, ext4, `fallocate`, direct I/O and a daemon `/dev`
bind. Function containers remain unprivileged. Missing capabilities fail
preparation; there is no tmpfs or unbounded-storage fallback.

Embedders must provide a stable, per-instance `DockerConfig.Namespace` and close
the returned `DockerExecutor` after closing the stack. The CLI owns that lifecycle
and derives the namespace from its instance configuration. Reuse the namespace
after a crash; a second live owner is rejected.

Provision application resources through an origin reachable from both the host
and its containers. For example, an SQS queue URL returned for a loopback API
endpoint still points at loopback inside Lambda; the Node.js SDK follows that
queue URL even when its default service endpoint is container-reachable.
Use the reachable origin for provisioning and for `-public-endpoint`, rather
than rewriting queue URLs or injecting a per-handler SDK shim.

Embedders inject `Config.LambdaExecutor`, the shared `Config.ComputeEndpoint` and
`Config.LambdaKeepAlive`. Zero keepalive forces cold invocations. The instance
clock governs warm-cache expiry and execution-role expiration; actual startup,
customer code and invocation deadlines remain on wall time. A nil executor does
not require Docker for IAM or other control-plane use, and cannot execute code.
Stack shutdown closes the environments it created, not the caller's executor.

## Container-image deployments

`PackageType=Image` accepts an explicitly installed local Docker tag such as
`local-unified:latest`, in addition to installed digest references. This local
image admission is deliberately broader than AWS's ECR-only registry admission;
it does not simulate an ECR push or invent an ECR repository digest.
`CreateFunction` and `UpdateFunctionCode` inspect the installed image and stage
an unstarted source-image container, then commit a namespace-labeled native
snapshot with a unique owned tag before committing deployment state. No customer
code runs while pinning. The original full Docker image configuration supplies
the commit configuration, preserving its command, entrypoint, environment,
working directory and platform. The derived image retains manifest/content even
with Docker's containerd image store; a config ID alone is not a content lease.
The actual admitted source config ID remains the public deployment identity;
the distinct Docker-created snapshot ID is retained privately for execution.
Retagging alone changes neither `$LATEST` nor a published version.
`UpdateFunctionCode --image-uri` resolves the new tag and deploys it through the
ordinary readiness and hot-swap lifecycle.
`GetFunction` returns the supplied `ImageUri` and actual `ResolvedImageUri`
(a repository digest when available, otherwise the local image ID), not a ZIP URL.
Image identities, owned references and configuration snapshots persist across
SQLite restart. Current, pending and published deployments retain their references,
as do accepted calls, deployment/provisioned preparation and warm execution slots.
Cold calls are rooted before Docker preparation begins. Reopening verifies native
ownership and identity without resolving the supplied mutable tag again. Deletion
and failed staging reconcile only unreferenced owned snapshot tags/artifacts and
staging containers. Final collection follows actual runtime/extension completion
and slot closure; a customer's SQS send is not a completion barrier. Shutdown joins
accepted work and releases successfully closed slots, but preserves deployment
roots for restart and roots whose native cleanup failed.
Native image labels are the durable inventory: a commit completing after a
transport failure or controller crash remains independently discoverable even
after its staging container has gone. An untagged interrupted commit is cleaned
only by its actual, labeled derived-image ID, never by the source-image ID.
Cleanup never removes the caller's source tag/image, deletes user-tagged
artifacts, forces image removal or prunes the daemon. Native cleanup failures
remain errors for retry. Missing or externally retagged retained images fail
honestly; there is no automatic pull or invented registry digest.

The CloudFormation Function adapter supports both packages, replaces a function
when `PackageType` changes, and exposes authoritative live read/list models.
List identifiers use the regional provider's `FunctionName` primary identifier,
not the native listing's function ARN. Code source properties remain write-only
in that model, following the regional provider schema. A private retained
stack/logical-resource/token claim fences stack commands against a same-name
native recreation even if its public discovery tags were copied. Public tags
neither establish nor satisfy that claim. Native and direct Cloud Control
updates can mutate existing functions without adopting their private claims.

Build x86_64 images with `docker build --platform linux/amd64`, including on
Darwin/arm64 Docker Desktop. The installed image must actually have that Linux
platform; a tag pointing at an arm64 image is not an amd64 deployment.
Image functions omit `Runtime` and `Handler`; the Docker image's `ENTRYPOINT`,
`CMD`, working directory and environment provide their defaults.
`ImageConfig.EntryPoint`, `Command` and `WorkingDirectory` override those
defaults through `CreateFunction` or `UpdateFunctionConfiguration`, without
re-resolving a mutable image tag. Arguments are passed literally, not through a
shell interpolator.

Use an official AWS Lambda runtime base image or install the official
[Runtime Interface Client](https://docs.aws.amazon.com/lambda/latest/dg/images-create.html)
in the image. The client connects directly to stackd's Runtime API through
`AWS_LAMBDA_RUNTIME_API`; the RIE is never executed as a fallback. The current
process/telemetry supervisor also requires `/bin/bash` and `/bin/sleep` in the
image, a writable `/tmp`, and code readable/executable by UID/GID `993`.
ZIP `provided.al2023` deployments execute their `/var/task/bootstrap` directly
in the official provided OS image, falling back to `/opt/bootstrap` only when
the package has no bootstrap. A missing or non-executable entrypoint returns
`Runtime.InvalidEntrypoint`. `_HANDLER` carries the configured handler name.
This follows the [custom-runtime contract](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html),
not the OS-only image's uninstalled `/var/runtime/bootstrap` language launcher.
The telemetry and bounded-storage helper prerequisites above apply to both
package types.

The opt-in local execution regression builds two real Python RIC images from
the installed pinned base, invokes them through the signed SDK, proves that
retagging does not change deployed code, updates code, invokes the old published
version, closes/recreates the executor under the same stable daemon namespace
while reopening SQLite, and drives a real SQS source into the image function and
out to an actual SQS output queue. A deterministic fence pauses an admitted cold
call before native Docker preparation while another call hot-swaps or deletes
its unpublished function; the accepted call must still execute its selected
image. It also checks that rejected admission and final function deletion
release owned native staging markers and image artifacts without deleting the
caller's source image tag:

```sh
STACKD_LAMBDA_DOCKER=1 go test ./integration \
  -run '^TestLambdaLocalImageDockerExecutionAndHotSwap$' -count=1
```

It requires the Docker CLI and the existing runtime/helper images. It is a local
behavior regression, not a fabricated native AWS capture.

The provided-runtime regression builds a real static Linux/amd64 Go bootstrap,
packages its executable mode into a ZIP, invokes the Runtime API implementation,
hot-swaps ZIP code, checks the old published version, and verifies
`Runtime.InvalidEntrypoint` for a non-executable bootstrap:

```sh
STACKD_LAMBDA_DOCKER=1 go test ./integration \
  -run '^TestLambdaProvidedAL2023DockerBootstrapAndHotSwap$' -count=1
```

It additionally needs the Go compiler and the installed pinned
`provided.al2023` amd64 OS image.
AWS's [image settings](https://docs.aws.amazon.com/lambda/latest/api/API_ImageConfig.html)
and [image deployment guide](https://docs.aws.amazon.com/lambda/latest/dg/nodejs-image.html)
define the override and tag-resolution contracts.

## Function VPC placement

Function `VpcConfig` is separate from an event source mapping's poller VPC.
Admission validates scoped subnets and security groups through the current
EC2 owner under the execution role. Runtime preparation allocates a real
EC2-owned ENI for that function incarnation and execution lease; the Docker
namespace uses its reserved IPv4 address, MAC, VPC bridge and DNS.
Current EC2 security-group/NACL policy is installed before customer execution
and refreshed while the environment lives. There is no metadata-only VPC or
permission-free network fallback.

The embedded `AWSLambdaVPCAccessExecutionRole` policy is sufficient for the
execution-role ENI boundary; it does not need an added
`ec2:DescribeSecurityGroups` grant. Function subnet selection checks
`DescribeSubnets` and actual `CreateNetworkInterface` authority while still
validating every subnet/group and VPC/account relationship. AWS documents
`DescribeSecurityGroups` and its other resource-verification permissions for
the **caller**, separately from execution-role permissions. This repair does not
expand the existing public CreateFunction caller-admission checks.
Source: [Lambda VPC permission split](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html).

VPC execution additionally requires the configured native function-network
runtime, the installed pinned networking toolkit, a rootful Linux Docker daemon
with bridge/veth and nftables capabilities, and execution-role EC2 network
permissions. Docker Desktop uses daemon-owned bridge locks and a Runtime API
callback relay; a private callback exemption does not bypass policy for arbitrary
customer traffic or the AWS endpoint. Dual-stack IPv6 is rejected explicitly.
Deleting an environment removes its customer/storage containers before releasing
the exact owned native policy and EC2 ENI.

Available EC2-owned VPC endpoints direct the corresponding customer SDKs through
real private-IP listeners and current endpoint-policy/IAM intersection, in
addition to security-group/NACL packet policy. Local endpoint URLs use
`http://private-ip:443`; this is not a claim of AWS public DNS names, trusted TLS,
or externally assigned public EIP identity. Private-subnet egress requires an
available public NAT, its retained EIP and an attached internet gateway through
the authoritative route topology; the daemon performs actual NAT forwarding.
The native dependency smoke exercises SQS and the pinned Kafka-backed Kinesis
runtime, including endpoint/SG/NACL/NAT withdrawal:

The official interface endpoint name
`com.amazonaws.<region>.kinesis-streams` is preserved by EC2 and maps to the same
real Kinesis packet destination and endpoint policy as the local Kinesis owner.
Managed-role packet success and policy/route withdrawal were exercised on memory
and SQLite, not just endpoint registration.

```sh
STACKD_LAMBDA_DOCKER=1 STACKD_KINESIS_DOCKER=1 go test ./integration \
  -run '^TestLambdaVpcDockerEndpointsPolicyAndPrivateNatPackets$' -count=1
```


## CloudFormation additional configurations

`AWS::Lambda::EventInvokeConfig`, `AWS::Lambda::Url`,
`AWS::Lambda::CodeSigningConfig` and `AWS::Lambda::CapacityProvider` use the
existing typed Lambda commands for create, update, delete and authoritative
Cloud Control read/list. No configuration state is stored in the CFN adapter.
Private incarnation claims persist in both memory and SQLite (migration 323);
retrying a create with the same owner recovers its original configuration.
Every command still checks current IAM. Native updates preserve private claims,
but deleting and recreating the same configuration does not transfer them.
Replacement cleanup uses the old physical identity, not desired properties.

Event-invoke retry limit `0` is preserved as an explicitly configured value.
Changing the function or qualifier replaces the resource; updates replace the
declared error-handling settings and remove omitted destinations. Function URLs
retain the actual HTTP endpoint and support IAM/NONE auth, CORS and buffered or
streaming invocation. Omitting CORS on update clears it; omitting InvokeMode
restores BUFFERED. URL creation requires the configured public endpoint.
URL and event-invoke discovery use paginated native configuration APIs and require
their native list filters (`TargetFunctionArn` and `FunctionName`, respectively).

Code-signing configurations support allowed publishers, Warn/Enforce policy,
description and tags; their IDs/ARNs are owner-generated. Code signing remains
ZIP-only and is rejected for image functions.
Capacity providers support native immutable instance/VPC/permissions/KMS
properties, mutable scaling/tag propagation and tags. Creation requires the real
managed EC2 backend; unsupported telemetry delivery or GPU policy requests fail
honestly in the owner. CFN observes actual provider state and deletion completion.
An empty deleting provider is removed by the native scheduler even when no
runtime or managed backend is installed: there are no guests to terminate.
Providers with retained guests still require the real backend for cleanup.
`Ref` returns the provider name; `GetAtt Arn` and `State` are live projections.
Native MicroVMImage, NetworkConnector and WebFunction-family resources have no
implemented Lambda owner and are not registered by this adapter.

Sources: [EventInvokeConfig](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventinvokeconfig.html),
[Url](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-url.html),
[CodeSigningConfig](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-codesigningconfig.html),
[CapacityProvider](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-capacityprovider.html).

## CloudFormation aliases

`AWS::Lambda::Alias` delegates creation, description/routing updates, replacement
and deletion to the real Lambda owner. `Ref` and `Fn::GetAtt AliasArn` return the
qualified alias ARN; changing `Name` or `FunctionName` replaces the resource.
The provider supports all six documented properties, including weighted routing
and `ProvisionedConcurrencyConfig`. Published function versions can come from
the native API or the [CloudFormation version provider](#cloudformation-versions).
[Layer versions](#cloudformation-layer-versions) supply real S3-backed archives.

The retained [native deployment capture](../testdata/aws/cloudformation/lambda_alias.json)
establishes these boundaries:

- Removing `RoutingConfig` clears the secondary version; removing `Description`
  preserves the prior description. An explicit empty description can clear it.
- An alias may target `$LATEST`; the native capture invoked it successfully.
  Provisioned concurrency still requires a published target.
- Provisioned capacity of one reached `READY` and executed a real provisioned
  runtime. Retargeting at unchanged capacity enters `IN_PROGRESS`, even when
  allocated/available counts still equal the requested amount. Completion must
  observe status, not infer readiness from those counts. Removing the property
  deletes the configuration while leaving the alias and function intact.
- Resource Groups admits aliases only in stack queries. Native stack membership
  returned the exact alias ARN, not its target function.

Schema 298 retains private stack/logical/incarnation identity with the alias and
its API event, never as tags. Exact-owned create recovery preserves current
routing/revision under current IAM. Native retargeting retains identity; native
delete/create clears it. Alias and provisioned-capacity mutations recheck this
constraint inside their transaction, so a foreign replacement cannot be adopted
between a read and a write. Legacy rows remain unowned.

Routing changes atomically invalidate the old provisioned generation; late old
initialization outcomes cannot mark the new target ready. Actual runtime pools
are rebuilt after controller restart. `integration/cloudformation_lambda_alias_test.go`
exercises signed SDK deployment, routing, real invocation, provisioned execution,
IAM revocation, stack-only discovery and memory/SQLite reopen. The executable
restart smoke additionally preserves the alias revision, rewarms the runtime and
proves a foreign alias remains invokable after rejected stack update/deletion.
Storage regressions cover rollback, journal coupling and historical migration.

The probe verified cleanup of its native stack, group, aliases, function/versions,
provisioned configuration and role. Native private recovery behavior, weight-only
provisioned timestamp changes and failed-pool recovery remain unmeasured; local
incarnation/generation fences are not claims about AWS internals. This resource
provider now reads aliases and lists aliases for a required `FunctionName` using
the live owner, including routing and provisioned settings. CodeDeploy
`UpdatePolicy` rollout orchestration remains unsupported.

Sources: [CloudFormation alias contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-alias.html),
[captured registry schemas](../testdata/aws/cloudformation/resource_schemas.json),
[probe](../scripts/aws/cloudformation_lambda_alias_probe.py).

## CloudFormation versions

`AWS::Lambda::Version` publishes through the real Lambda owner and supports
`FunctionName`, `CodeSha256`, `Description`, `RuntimePolicy`,
`ProvisionedConcurrencyConfig` and `FunctionScalingConfig`. `Ref` and
`Fn::GetAtt FunctionArn` return the qualified version ARN; `Fn::GetAtt Version`
returns the numeric version string. All publication properties require replacement;
only managed-instance scaling changes in place. Downstream capability restrictions
remain authoritative: scaling rejects ordinary on-demand functions, and Manual
runtime selection remains unsupported rather than inventing an executable image.

Schema 299 commits a scoped publication receipt with the immutable version,
allocation and API event. One stack/logical/incarnation identity owns one version
of a function. Exact-owner retries recover that publication even after `$LATEST`
changes, but recheck current IAM. Native and legacy publications remain unowned;
a new CloudFormation resource cannot adopt or delete them. Receipts cascade with
version deletion, and monotonic allocation prevents a recreated function from
impersonating the old numbered publication. Retrying a completed deletion reports
absence, not a foreign-owner denial.

The [native deployment capture](../testdata/aws/cloudformation/lambda_version.json)
and its linked attempts establish these public boundaries:

- Direct unchanged `PublishVersion` returns the existing version. A new
  CloudFormation resource rejects it, including another stack's publication.
  Description-only and provisioned-only replacement fail when the underlying
  function has not changed; rollback preserves the original version.
- A hash mismatch rejects publication without adopting a prepublished version.
  `Auto` and `FunctionUpdate` runtime modes were applied and read back.
- A [fresh provisioned version](../testdata/aws/cloudformation/lambda_version_provisioned_alias.json)
  reached `READY`; both numeric and alias invocation used its provisioned runtime.
  The alias still had no provisioned configuration of its own.
- Resource Groups returned the qualified version ARN from a version-filtered stack
  query. Membership reads the current receipt, not historical stack metadata or
  inherited function tags.
- [Referenced deletion](../testdata/aws/cloudformation/lambda_version_referenced_delete.json)
  remained pending while an external alias existed and completed after its removal.
  Local deletion uses the retained controller's stabilization path and rechecks
  current ownership and IAM on every attempt.

`integration/cloudformation_lambda_version_test.go` verifies complete
Function-Version-Alias deployment, real provisioned execution through both
qualifiers, collision/hash rollback, replacement/retirement, retained restart and
deletion dependencies on memory and SQLite. Storage regressions cover receipt/
state/journal rollback, legacy migration, current authority and exact-owner recovery.
The actual SQLite executable also reinitialized and invoked the provisioned version
after a fresh-process restart, replaced the version, retargeted the alias, retired
the predecessor and deleted the application successfully.
All four native captures record complete cleanup; earlier serialization and bounded
wait failures remain recorded rather than relabeled successful workflows.

Private AWS recovery tokens, Manual runtime mode, managed-instance scaling execution
and eventual failure timing with a permanently retained alias remain uncalibrated.
Cloud Control reads published versions and their runtime/scaling/provisioned
settings from the owner; version listing requires the native `FunctionName` filter
and excludes `$LATEST`.
Sources: [version resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-version.html),
[runtime policy](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-version-runtimepolicy.html),
[scaling contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-version-functionscalingconfig.html),
[probe](../scripts/aws/cloudformation_lambda_version_probe.py).

## CloudFormation layer versions

`AWS::Lambda::LayerVersion` publishes through the Lambda owner using actual S3
archives. It accepts all six configurable properties and the four documented
`Content` fields, including `S3ObjectVersion` and `S3ObjectStorageMode`. `Ref` and
`Fn::GetAtt LayerVersionArn` return the qualified layer ARN. Every property change
replaces the publication; omitted `LayerName` uses the logical ID without a stack
suffix. Identical bytes still allocate a new version for a new publication.

Schema 300 stores private stack/logical/incarnation ownership on the immutable
layer row with a scoped unique constraint. Exact-owner recovery precedes external
source/signature work and rechecks ownership and current IAM at commit. This
preserves COPY archives when the original S3 object changes or disappears.
Publication, archive, allocation, ownership and API event commit together.
Native and migrated legacy publications cannot be adopted by an unrelated stack.
Deletion removes the catalog row and stack membership, not existing function
attachments or their retained archive bytes.

The [main native capture](../testdata/aws/cloudformation/lambda_layer.json)
records repeated identical publication, description/content replacement, explicit
S3-version pinning, deletion while attached, and actual Python imports after
retirement. Its final generated-name probe stopped at an ownership safety check;
that failure remains recorded. The separate
[generated-name capture](../testdata/aws/cloudformation/lambda_layer_generated.json)
confirms logical-ID naming and same-name replacement. Both record complete
exact-resource cleanup. A bounded Resource Groups membership miss is not proof
of exclusion; local discovery uses the current typed layer owner.

`integration/cloudformation_lambda_layer_test.go` verifies the layer-backed
Function-Version-Alias lifecycle through signed SDK calls and real runtimes on
memory and SQLite under the race detector. The executable smoke also reopened
SQLite in a fresh process, imported the retained layer, replaced the layer and
function version, retargeted the alias, invoked the retired attachment, removed
the current layer natively, and cleaned up the stack. Storage regressions cover
schema migration, scope isolation, current IAM, concurrent recovery and
state/archive/allocation/event rollback.

Native private recovery, REFERENCE-mode stack publication, cross-account sharing,
signing and broader runtime/architecture combinations remain uncalibrated by these
captures. Cloud Control reads layer metadata and lists versions for the required
`LayerName` filter. Native-schema write-only `Content` is omitted: a download URL
is not an original S3 source. Stack-managed sharing uses the
[layer permission provider](#cloudformation-layer-permissions).
Sources: [resource contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-layerversion.html),
[content contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-layerversion-content.html),
[probe](../scripts/aws/cloudformation_lambda_layer_probe.py).

## CloudFormation layer permissions

`AWS::Lambda::LayerVersionPermission` creates real resource-policy statements
through the Lambda owner. All four configurable properties are supported and
require replacement. `Ref` and `Fn::GetAtt Id` return the qualified layer ARN
followed by `#` and the statement ID.

The [native lifecycle capture](../testdata/aws/cloudformation/lambda_layer_permission.json)
confirms that changing an account-ID principal to its equivalent root ARN still
replaces the statement. Retargeting another layer version removes the old grant.
Public duplicate Add conflicts; removing the last statement removes the policy;
CloudFormation deletion tolerates an already removed statement or layer.
Both Retain policies preserve the original and replacement grants through stack
deletion. The separate [attribute capture](../testdata/aws/cloudformation/lambda_layer_permission_getatt.json)
confirms `GetAtt Id`, which the prose resource reference does not describe.
Both captures retain complete exact-resource cleanup.

Schema 301 stores private statement-level ownership separately from public policy
JSON. Policy, receipt and API event commit together. An exact-owner retry recovers
the statement under current IAM; public deletion and recreation of the same
statement ID remove that receipt and cannot satisfy an old create retry.
Sibling statements retain their independent owners. Deleting a policy or layer
cascades receipt cleanup. Legacy statements remain unowned.
Recovery preserves the original `lambda:Principal` request form when stored
principal canonicalization is equivalent. Account-ID and root-ARN conditions have
separate regression coverage; changing the requested principal cannot recover a
different stored grant after its authority is revoked.

The provider creates with `AddLayerVersionPermission`. Deletion reads the current
policy and passes its revision to `RemoveLayerVersionPermission`. Deletion uses
the native statement ID, not the private create receipt. The
[same-ID replacement capture](../testdata/aws/cloudformation/function_resource_policy.json)
proves that deleting the old stack also deletes a natively recreated identical
statement. The native registry declares both delete permissions; handler-internal
lookup and least-privilege behavior were not observed.

`integration/cloudformation_lambda_layer_permission_test.go` verifies signed SDK
memory/SQLite workflows under race: an authorized foreign account imports a real
Python layer; another account is denied; replacement swaps admission; revocation
blocks new attachment while an existing function still runs after reopen.
Current-IAM denial prevents unauthorized deletion; native same-ID replacement
does not protect the replacement grant from authorized stack deletion. Storage
regressions cover concurrent create recovery, native revision races,
policy/receipt/event rollback and schema-300 migration. Earlier executable
restart coverage establishes retained imports and grantee replacement; its
private deletion fence was superseded by the native-calibrated SDK workflow.

Native cross-account consumption, organization/wildcard grants and private recovery
remain uncalibrated by these captures. Cloud Control reads current permission
statements and lists native representable grants for a required `LayerVersionArn`.
Sources: [resource contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-layerversionpermission.html),
[Add API](https://docs.aws.amazon.com/lambda/latest/api/API_AddLayerVersionPermission.html),
[Remove API](https://docs.aws.amazon.com/lambda/latest/api/API_RemoveLayerVersionPermission.html),
[probe](../scripts/aws/cloudformation_lambda_layer_permission_probe.py).

## CloudFormation function resource policies

`AWS::Lambda::ResourcePolicy` deploys whole function policies through the existing
Lambda owner. Its canonical properties are `ResourceArn` and object-valued
`PolicyDocument`; `Ref` and the physical ID are the target ARN. The captured
registry and successful native deployments use `ResourceArn`, despite the prose
reference's contradictory `FunctionResourceArn` property list. No compatibility
alias or speculative `GetAtt` attribute is provided.

The [native lifecycle capture](../testdata/aws/cloudformation/function_resource_policy_lifecycle.json)
establishes full-document updates, including removal of out-of-band
`AddPermission` statements. Changing a base, version or alias target replaces the
resource and deletes the previous target's policy. Deletion removes the current
policy even if native `PutResourcePolicy` overwrote it after deployment.
The [initial capture](../testdata/aws/cloudformation/function_resource_policy.json)
retains the rejected attempt to create over an existing policy; the separate
[read-only diagnosis](../testdata/aws/cloudformation/function_resource_policy_validation.json)
records `NAME_CONFLICT_VALIDATION`. All captures retain complete cleanup.

Schema 302 stores typed private create ownership with the policy row. Initial
creation atomically requires absence or an exact nonempty create receipt;
legacy/native policies cannot be adopted. Exact recovery rechecks current IAM
and returns the retained document/revision without rewriting or rebinding it.
Native full-policy writes clear the receipt; sibling statement mutations retain
it while the policy exists. Policy, receipt and API event commit together.
These local recovery guarantees are not claims about AWS private tokens.
Updates and deletion deliberately do not require the old create receipt.

The signed SDK workflow exercises existing-policy rejection without mutation,
real cross-account Python invocation, explicit deny, native statement replacement,
qualified-target isolation, retained memory/SQLite state, and native-overwritten
policy deletion. The SQLite executable passed a fresh-process restart, full
document update, version-target replacement, native overwrite, revocation and
exact-resource cleanup. Storage race regressions cover atomic competing creates,
current IAM, qualifier scope, receipt/event rollback, reopen and legacy migration.
Native cross-account invocation and private recovery remain uncalibrated; these
captures do not establish least-privilege handler permissions. Cloud Control
reads the current whole policy through `GetResourcePolicy`; native ResourcePolicy
has no list handler, so listing fails explicitly as unsupported.

`AWS::Lambda::Permission` also uses the statement ID for deletion, not JSON
equality. Native captures show deletion of both identical and changed same-ID
replacements; `Ref` and `Fn::GetAtt Id` return that statement ID. The SDK workflow
verifies revoked access after deleting a grant recreated for another account.
As AWS warns, do not reuse statement IDs when migrating permission resources to
a full resource policy: deleting the old resource can remove the new grant.
Cloud Control reads individual permissions from current native policy statements;
its identifier is the native compound `FunctionName|Id`, while stack `Ref`/`Id`
remain the statement ID. Listing requires `FunctionName`. Arbitrary deny,
multi-principal or unsupported-condition statements are not flattened into
individual permission resources; reading one fails explicitly as unsupported.

Sources: [ResourcePolicy contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-resourcepolicy.html),
[Permission migration warning](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-permission.html),
[Put API](https://docs.aws.amazon.com/lambda/latest/api/API_PutResourcePolicy.html),
[probe](../scripts/aws/cloudformation_lambda_resource_policy_probe.py).

## CloudFormation stream mappings

`AWS::Lambda::EventSourceMapping` deploys SQS, Kinesis and DynamoDB Streams mappings
through the existing Lambda source owners. Stream deployment requires
`StartingPosition`; DynamoDB supports `TRIM_HORIZON` and `LATEST`, not
`AT_TIMESTAMP`. Kinesis `StartingPositionTimestamp` uses Unix seconds at the
template boundary, converted to the internal SDK timestamp representation.
`Ref` and `GetAtt Id`
return the mapping UUID; `GetAtt EventSourceMappingArn` returns the owner ARN.
`FunctionName` updates can retarget published aliases without changing the UUID.

Mappings retain a typed private `MappingOwner` claim in the native record
(SQLite migration 388), admitted atomically with the UUID. Stack and Cloud
Control creates recover only that exact stack/logical-resource/token claim,
including after a lost admission reply; public tags neither grant nor revoke
ownership. Read, configuration mutation, tagging and deletion check current IAM
and, for stack requests, that native claim. Stale stack commands cannot affect
a recreated foreign mapping, even with copied public phase/discovery tags.
Ordinary Cloud Control update/delete commands use the existing native UUID
without adopting or replacing its private claim. Phase tags track admitted
configuration only and do not authorize resource discovery or mutation.

Kinesis and DynamoDB deployment accept batch/window and enabled controls, retry/age limits,
parallelization, bisection, tumbling windows, partial responses, filters, metrics,
failure destinations and filter encryption. `KmsKeyArn` is translated to the
Lambda API's `KMSKeyArn`; encryption and destinations stay with the existing
Lambda/KMS/source owners. SQS retains its source-specific scaling configuration.
Unknown properties and nested fields fail rather than being silently discarded.

The [native lifecycle capture](../testdata/aws/cloudformation/lambda_kinesis_mapping_lifecycle.json)
establishes that property removal is not equivalent to omission from the Lambda
update API. CloudFormation resets Kinesis batch size to 100, batching window to
0, parallelization to 1, retries/age to -1, bisection to false, and tumbling
window to 0. Removed filters disappear, response types become empty, and metrics
become an empty list. The [SQS contrast](../testdata/aws/cloudformation/lambda_kinesis_mapping_sqs_contrast.json)
establishes batch size 10 and removal of maximum-concurrency scaling, with the
same common resets; explicit `FilterCriteria: {}` is also accepted.

Changing the source ARN, starting position or starting timestamp requires
replacement. Replacing only a starting position/timestamp on the same source
and qualified function fails with Lambda `ResourceConflictException`, leaving
the original mapping after `UPDATE_ROLLBACK_COMPLETE`. Changing to another stream
creates a new UUID and deletes the old mapping. The
[initial capture](../testdata/aws/cloudformation/lambda_kinesis_mapping.json)
retains the rejected parallelization-2/tumbling-window-5 combination rather than
presenting it as a successful lifecycle. All three captures verify exact cleanup.

`integration/cloudformation_lambda_kinesis_mapping_test.go` passes memory/SQLite
workflows under race using real Kafka-backed Kinesis records and Python runtimes:
disabled backlog, enablement, filter-only updates and removal, execution-role
denial/recovery across reopen, alias retargeting, replacement-conflict rollback,
timestamp-based source replacement, and mapping deletion. Assertions identify
actual source, sequence, shard, payload and invoked function. Ordered checkpoint
markers establish that preceding business records committed before restart;
marker replay is permitted, not mislabeled as exactly-once delivery.
The executable also passed Kinesis → Python → SQS effects across a fresh
controller restart, filter removal, fractional Unix timestamp replacement and
cleanup of both native streams and the application.

The [DynamoDB deployment capture](../testdata/aws/cloudformation/lambda_dynamodb_mapping.json)
confirms the same stream-property resets, alias retargeting without UUID change,
same-source starting-position replacement rollback and distinct-stream replacement.
It also records rejection of DynamoDB `AT_TIMESTAMP`, and deletion of the mapping
while both native tables and the function survive.
The [source-authority capture](../testdata/aws/cloudformation/lambda_dynamodb_mapping_authority.json)
admits disabled mappings with no `ListStreams` grant, a stream-scoped grant, and
even an explicit `ListStreams` deny. The earlier local preflight incorrectly
required account-wide discovery. Known-stream consumers now authorize the reads
they perform; public `ListStreams` authorization remains unchanged. Retained IAM
simulation errors are not used as proof of Lambda admission.

`integration/cloudformation_lambda_dynamodb_mapping_test.go` passes memory/SQLite
under race with real DynamoDB Local streams and qualified Python invocation.
It verifies keys, old/new images, source identity, filters and their removal,
disabled backlog, source-denial recovery across reopen, replacement rollback,
distinct-stream replacement, and deletion without removing native prerequisites.
`ListStreams` stays explicitly denied throughout this local workflow. Ordered
same-key checkpoint markers distinguish committed business records from marker
replay. A separate executable passed DynamoDB → Python → SQS image delivery,
filter removal and stream replacement across a fresh SQLite controller restart,
then removed both native tables and the application.

The [encrypted-filter/destination capture](../testdata/aws/cloudformation/lambda_mapping_controls.json)
distinguishes key omission from filter removal. Removing `KmsKeyArn` while keeping
`FilterCriteria` retains the existing key and mapping UUID. Removing the filters,
or setting `FilterCriteria: {}`, clears both the criteria and key even when the
template still names the key. Removing `DestinationConfig`, setting it to `{}`,
or setting `OnFailure: {}` clears the failure destination. Explicit empty key or
destination strings instead fail native model validation and roll back unchanged;
the adapter applies registry-generated string bounds during resource operations,
not synchronous template validation. All 15 captured updates retained the UUID.
The exact-owned table, queue, function, mapping, log group and role were removed.
The KMS key is **PendingDeletion**, scheduled for 2026-10-07, not absent.

`integration/cloudformation_lambda_mapping_controls_test.go` passes memory/SQLite
under race with signed Go SDK calls and real DynamoDB Local/Python execution.
It verifies invalid-ARN rollback without replacement or mutation, encrypted
selective delivery and redaction, current key/source authority across reopen,
failure-destination switching and clearing (including empty nested objects), and
mapping deletion. Failure envelopes identify the actual request, source sequence,
qualified function version and unhandled error; ordered checkpoint records
establish progress beyond discarded failures without claiming exactly-once delivery.

The executable reproduced the old key-omission bug, then passed encrypted
DynamoDB → Python → SQS delivery across a fresh SQLite controller restart:
selective filtering, list redaction, actual handler-error destination metadata,
disabled-key blocking/recovery, retained encryption after key omission, empty
criteria clearing encryption, and progress without delivery after destination
removal. The old disabled key no longer blocks records once filters are cleared.

These native captures measure deployment control, not native record delivery,
cross-account sources, private recovery tokens or native-engine equivalence.
Enhanced fan-out deployment is not exercised by this workflow.
[Amazon MQ](#cloudformation-amazon-mq-mappings) and
[DocumentDB deployment](#cloudformation-documentdb-mappings) use their existing
native source adapters. Cloud Control reads and paginates actual mapping records,
including source-specific settings and live tags. Read-side filter-decryption
errors are surfaced rather than replaced by remembered template settings.

Sources: [resource contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html),
[Kinesis source contract](https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html),
[DynamoDB source contract](https://docs.aws.amazon.com/lambda/latest/dg/services-dynamodb-eventsourcemapping.html),
[Kinesis probe](../scripts/aws/cloudformation_lambda_kinesis_mapping_probe.py),
[DynamoDB probe](../scripts/aws/cloudformation_lambda_dynamodb_mapping_probe.py).

## CloudFormation self-managed Kafka mappings

`AWS::Lambda::EventSourceMapping` also deploys self-managed Kafka through the
existing Kafka consumer, IAM/Secrets Manager/KMS owners and real Lambda runtime.
The template's `SelfManagedEventSource.Endpoints.KafkaBootstrapServers` becomes
the Lambda API's `KAFKA_BOOTSTRAP_SERVERS`; no MSK ARN or second offset ledger is
introduced. The stack owns the mapping, not its external broker or function.
`Ref`, `GetAtt Id` and `GetAtt EventSourceMappingArn` identify the actual mapping.

The [native evidence summary](../testdata/aws/cloudformation/lambda_self_managed_kafka_mapping_summary.json)
links full requests, responses, registry schema and exact-owned cleanup:

- Batch-size omission resets to 100, but batching-window omission retains the
  configured value. The initial 500ms window is omitted from the integer-seconds
  response rather than incorrectly reported as an explicit zero window.
- Removed filters and resource tags clear. Removed source-access configuration
  remains effective; reintroducing it is ignored. Subsequent edits while the
  property remains present apply. The native authentication sequence changes
  SCRAM-512/256 with one secret; secret-URI changes are not calibrated.
- Consumer-group edits/removal plan as `Replacement: False` and
  `RequiresRecreation: Never`, yet execution requests physical replacement.
  Same-endpoint/function/topic collisions roll back to the original UUID.
  Topic changes/removal instead fail during the resource update without
  replacing or altering the actual source.
- Source and starting-position/timestamp changes use replacement. A changed
  endpoint creates a new UUID before deleting the old mapping. Same-source
  starting-position/timestamp replacements collide and roll back. Omitted
  starting position defaults to `TRIM_HORIZON` in the captured configured-group
  workflow; `AT_TIMESTAMP` requires its Unix timestamp.
- On-demand Kafka rejects `MetricsConfig: {Metrics: [EventCount]}` because it
  requires provisioned polling. A retained failed-before/passing-after Go
  regression covers this Lambda-owner admission correction. Provisioned polling
  remains unsupported, not a simulated metrics mode.

The [executable workflow](../scripts/aws/cloudformation_lambda_self_managed_kafka_smoke.py)
and [retained local report](../testdata/integration/cloudformation_lambda_self_managed_kafka.json)
verify two actual TLS/SCRAM brokers, signed SDK deployment, official Python
invocation and SQS effects. It exercises disabled backlog, filtering/removal,
batch/window/access omission and access reintroduction, current IAM/CA-secret/KMS
denial and recovery, uncommitted retry across SQLite controller restart, version
and alias targets distinct from `$LATEST`, and no replay of acknowledged records.
Endpoint replacement preserves broker-owned consumer-group progress while
replacing the mapping UUID. Group/topic/metrics failures preserve the live
mapping and subsequent delivery; group change-set planning is checked separately.
The final observed native broker offset is 16. Stack deletion leaves the external
broker/function intact, then exact-owned application and engine cleanup completes.
The existing direct-source executable also passed after sharing setup and
correcting its stale controller references.

Native captures kept every mapping disabled and function concurrency zero:
they establish deployment control, not AWS broker delivery, polling latency or
exactly-once execution. All six native mapping UUIDs, three functions/roles/secrets
and the unexecuted change set were verified absent; deleted stack history remains.
The metrics follow-up preserves its rejected setting and subsequent no-op-update
abort rather than claiming a completed lifecycle. Local KMS keys are
`PendingDeletion`; these smokes created no native AWS KMS key.
The runtime KMS scenario protects source-secret reads, not a native calibration
of Kafka filter encryption. Provisioned polling, schema registries, finite
retry/failure destinations and changed VPC placement retain their existing gaps.

Sources: [resource contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html),
[Kafka configuration](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-selfmanagedkafkaeventsourceconfig.html),
[native probe](../scripts/aws/cloudformation_lambda_self_managed_kafka_probe.py).

## CloudFormation MSK mappings

`AWS::Lambda::EventSourceMapping` deploys MSK mappings through the same Kafka,
IAM, secret and runtime owners, using `EventSourceArn`, `Topics` and
`AmazonManagedKafkaEventSourceConfig.ConsumerGroupId`. The stack owns the mapping,
not its external cluster or function. `Ref`/`GetAtt Id` return the UUID;
`GetAtt EventSourceMappingArn` returns the actual mapping ARN.

The [native contract index](../testdata/aws/cloudformation/lambda_msk_mapping_contracts.json)
links the full requests, responses, prerequisite provisioning and cleanup:

- A disabled mapping can be created before its topic exists. Omitted starting
  position becomes `TRIM_HORIZON`; batch size is 100 and the integer batching-window
  field is absent. Admission checks current control-plane authority, not broker
  connectivity. First successful polling retains the native cluster/topic identity
  transactionally before fetching, committing offsets or invoking a function.
- Batch omission resets to 100; window omission retains the explicit value;
  filter omission clears filters. Qualified alias retargets preserve the UUID.
- Group edits/removal publicly plan as `Replacement: False` with
  `RequiresRecreation: Never`, but execution attempts replacement. Same-source
  collisions roll back with the original UUID and broker progress intact.
- Topic edits/removal fail during resource update. A combined group/topic edit
  also fails topic validation before group replacement. A create-only position
  or timestamp change takes precedence and requests replacement.
- Omitted-to-explicit position changes replace even when both resolve to
  `TRIM_HORIZON`. Same-group replacements collide; changing position, group and
  topic together successfully replaces and removes the old UUID.
  `AT_TIMESTAMP` requires its Unix timestamp.
- Introducing source-access configuration when the prior template property was
  absent is ignored. The native response remained credential-free through its
  removal/reintroduction; this does **not** establish genuine MSK SCRAM credential
  removal/retention behavior.

The [executable workflow](../scripts/aws/cloudformation_lambda_msk_smoke.py) and
[current core report](../testdata/integration/cloudformation_lambda_msk_core_current.json)
verify actual TLS/SCRAM Kafka → official Python Lambda → SQS delivery, binary
records/headers/tombstones, filtering and property omission, current source/secret
IAM denial and recovery, version/alias targets, retry recovery and committed
offsets across two SQLite/controller restarts. Group/topic rollback preserves
subsequent delivery. The final broker offset is 15; stack deletion preserves the
external function, cluster bytes and group checkpoint.
The [default-position report](../testdata/integration/cloudformation_lambda_msk_default.json)
separately proves delivery of a record produced before mapping creation when
`StartingPosition` is omitted.

The [AWS SDK for Go v2 probe](../testdata/integration/cloudformation_lambda_msk_go_sdk.json)
creates the stack before topic creation, decodes CFN outputs and typed MSK mapping
fields, observes the modeled `ResourceNotFoundException` for a missing mapping,
and enables consumption through `UpdateEventSourceMapping`. The resulting actual
Python invocation delivers offset zero and commits one; stack deletion preserves
the independently executable function and broker data.

The [late-topic workflow](../testdata/integration/cloudformation_lambda_msk_late_topic.json)
disables broker auto-creation and observes missing-topic metadata before disabled
deployment. Explicit topic creation then delivers offset zero; a controller restart
delivers offset one and commits two. Combined group/topic mutation fails in-resource
without replacing the UUID. A subsequent `AT_TIMESTAMP`/new-group/new-topic change
replaces successfully, deletes the old UUID and commits one on the replacement group,
while the original group's offset remains two after stack deletion.
First-identity regressions reject stale disabled/updated/deleted workers and
competing topic identities; configuration updates retain concurrently bound identity.

The [shared self-managed regression](../testdata/integration/cloudformation_lambda_self_managed_kafka_admission.json)
also passed through offset 16 after admission stopped creating broker groups.
The [direct MSK regression](../testdata/integration/lambda_msk_admission.json)
preserves real topic-recreation fencing, retention recovery and current secret/KMS
denial/recovery. Its independent offset probe uses previously discovered loopback
brokers, not repeated control-plane bootstrap lookups during deliberate KMS denial.
The [earlier bootstrap-dependent failure](../testdata/integration/lambda_msk_admission_regression_failure.json)
remains retained.

The [failed-before admission report](../testdata/integration/cloudformation_lambda_msk_late_topic_before.json)
records the corrected `Unknown Topic Or Partition` creation rejection.
[Pristine-group probe failures](../testdata/integration/cloudformation_lambda_msk_unbound_offset_probe.json)
record why no offset fetch is asserted before a group exists; offset-zero delivery
and every subsequent native checkpoint remain mandatory.
A separate [Docker configuration-helper 404](../testdata/integration/cloudformation_lambda_msk_late_topic_broker_failure.json)
retains exact controller logs and cleanup evidence. Its cause is unproven; the final
late-topic workflow passed without adding production retries or suppressing errors.
Successful and failed local runs cleaned their exact-owned resources.

Every native mapping stayed disabled and function concurrency stayed zero:
this measures deployment control, not native Kafka delivery or timing.
The native stack/change set, both mapping UUIDs, function/version/aliases, role,
secret, cluster, VPC/subnets/security group and exact-created service-linked role
were verified absent. Local KMS keys remain `PendingDeletion`.
Omitted `Enabled`, genuine MSK credential-removal retention, native delivery,
provisioned polling, schema registries and remaining Kafka owner options are
not established by these workflows.

Sources: [resource contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html),
[MSK configuration](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-amazonmanagedkafkaeventsourceconfig.html),
[native probe](../scripts/aws/cloudformation_lambda_msk_probe.py).

## CloudFormation DocumentDB mappings

`AWS::Lambda::EventSourceMapping` deploys DocumentDB through the existing
database, Secrets Manager/KMS, IAM and Lambda owners. The stack owns the mapping,
not its independently created function, cluster, database instance or documents.
The mapping retains the cluster incarnation and existing typed native resume
token; deployment introduces neither a document journal nor a second cursor.

The [initial native capture](../testdata/aws/cloudformation/lambda_documentdb_mapping.json),
[lifecycle capture](../testdata/aws/cloudformation/lambda_documentdb_mapping_lifecycle.json)
and [nondefault/removal capture](../testdata/aws/cloudformation/lambda_documentdb_mapping_nondefault.json)
establish these bounded controls on a real DocumentDB 5.0 cluster:

- Disabled mapping creation succeeds without a database instance. Local admission
  likewise checks current source/secret authority and incarnation without opening
  the database engine. A ready writer is required for polling, not control admission.
- Omitted starting position becomes `LATEST`, batch size becomes 100 and
  `FullDocument` becomes `Default`. The native response omits the unspecified
  collection and initial fractional batching window rather than reporting zero.
  `Ref` and `GetAtt Id` identify the UUID; `GetAtt EventSourceMappingArn` identifies
  the actual Lambda mapping.
- Batch/window updates retain UUID. Removing them resets batch size to 100 while
  retaining the explicit window. Credential removal/reintroduction retains the
  existing `BASIC_AUTH` secret ARN. A secret short name is rejected and rolls back.
- CloudFormation namespace edits/removal leave the actual creation database and
  collection unchanged. The provider sends only mutable `FullDocument` settings
  to the Lambda update API. Direct Lambda updates reject database/collection
  parameters, including an unchanged database name. The schema's “No interruption”
  annotation is not evidence that namespace changes take effect.
- Explicit `FullDocument` updates work. Removing that property or the entire
  config after `UpdateLookup` retains `UpdateLookup` and the creation namespace.
- Unqualified, alias and numeric-version targets update in place. Starting-position
  or timestamp changes attempt create-before-delete replacement; the measured
  duplicate-source/function conflict rolls back and preserves the original UUID.
  No delete-first workaround hides that native conflict.

The [real-engine core capture](../testdata/integration/cloudformation_lambda_documentdb_core.json)
records TLS/SCRAM Mongo-compatible changes consumed by actual Python Lambda
runtimes into SQS: disabled backlog, both full-document modes, retained checkpoints
across SQLite/controller restart, current role/secret denial and recovery, and
alias/version targets. Its later namespace-redirection assertion failed and is
retained as failed-before evidence; native calibration established that the
namespace must not redirect. The [rollback capture](../testdata/integration/cloudformation_lambda_documentdb_rollback.json)
separately verifies replacement rollback, continued original-source delivery and
preservation of independent resources after stack deletion.

The corrected [settings workflow](../testdata/integration/cloudformation_lambda_documentdb_settings.json)
proves continued delivery from the creation namespace after template edits and
removal, retained `UpdateLookup` using actual update images, batch/window removal
and delivery with retained credentials. The [defaults workflow](../testdata/integration/cloudformation_lambda_documentdb_defaults_current.json)
proves database-wide `LATEST` delivery and omission of the fractional integer-window
field; the [earlier report](../testdata/integration/cloudformation_lambda_documentdb_defaults.json)
preserves the incorrect zero projection.

The [late-instance workflow](../testdata/integration/cloudformation_lambda_documentdb_late_instance.json)
deploys the disabled mapping before its writer exists, creates the actual engine,
then verifies delivery, retained restart/backlog and rejection of a recreated
same-ARN source without advancing the old checkpoint. The [failed-before report](../testdata/integration/cloudformation_lambda_documentdb_late_instance_before.json)
records the former engine-readiness admission failure. The [Go SDK helper](../scripts/aws/cloudformation_lambda_documentdb_sdk/main.go)
signs stack creation/readback, decodes mapping outputs and verifies modeled missing
mapping and namespace-update errors. All final focused runs and controller exits
passed; each removed its exact-owned resources. Isolated local KMS keys remain
`PendingDeletion`, distinct from native AWS cleanup.

All native mappings stayed disabled and functions had reserved concurrency zero.
These captures establish deployment control, not native DocumentDB delivery or
MongoDB/AWS engine equivalence. All three sequential native resource sets were
verified absent, including mappings and network dependencies. The first two
captures retain their harness failures rather than being presented as wholly
successful runs. Native source-ARN replacement, successful position replacement,
omitted enablement and private-network delivery were not measured. Remaining
DocumentDB engine/network features remain open.

Sources: [resource contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html),
[DocumentDB configuration](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-documentdbeventsourceconfig.html),
[Lambda update API](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateEventSourceMapping.html),
[native probe](../scripts/aws/cloudformation_lambda_documentdb_probe.py).

## CloudFormation Amazon MQ mappings

`AWS::Lambda::EventSourceMapping` deploys Amazon MQ sources through the existing
broker, Secrets Manager, IAM and native consumer owners. `Ref` and `GetAtt Id`
return the mapping UUID; `GetAtt EventSourceMappingArn` returns its Lambda ARN.
The source queue is immutable on updates: changing or removing `Queues` fails
and rolls back without consuming a different queue. Qualified function targets
update the existing mapping.

The [ActiveMQ control capture](../testdata/aws/cloudformation/lambda_mq_mapping_activemq.json)
and [RabbitMQ control capture](../testdata/aws/cloudformation/lambda_mq_mapping_rabbitmq.json)
measure disabled deployment on private AWS brokers with never-created queues.
Creation defaults to batch size 100; the initial 500ms window has no integer-seconds
output field. Removing an explicit batch size resets it to 100, whereas removing
an explicit batching window retains that window. Removing filters clears them.
Credential replacement applies while `SourceAccessConfigurations` remains present;
omission, reintroduction and subsequent unchanged template values retain the live
credential. Direct Lambda updates remain distinct: an explicit empty access list
is rejected. Queue edits are rejected by the deployment provider; an unknown
`Queues` field in a raw Lambda update is ignored, not applied.

The [RabbitMQ host control](../testdata/aws/cloudformation/lambda_mq_mapping_rabbitmq_virtual_host.json)
also admits a never-created custom virtual host without connecting to it.
Direct updates cannot include `VIRTUAL_HOST`, even unchanged; a BASIC_AUTH-only
rotation retains the host. ActiveMQ rejects any explicit host, including `/`.
RabbitMQ returns an explicitly configured `/`; typed schema 304 retains that
presence independently of the effective host used by AMQP. Migration preserves
known custom hosts and the old root-host projection: earlier state did not record
whether `/` was explicitly requested, so it cannot reconstruct that distinction.

Native CloudFormation accepts unchanged host settings on ordinary updates,
retains the host when it is removed from the template, and rolls back adding or
changing the host. The final [implicit-host probe](../testdata/aws/cloudformation/lambda_mq_mapping_rabbitmq_omitted_host.json)
found its broker already deleted before mutation, so implicit-host output remains
unmeasured. No third broker was created. The
[capture summary](../testdata/aws/cloudformation/lambda_mq_mapping_summary.json)
retains both initial service-linked-role cleanup failures and the verified
cleanup-only recoveries. All exact-owned native resources were ultimately absent.

The [executable workflow](../scripts/cloudformation_lambda_mq_smoke/smoke.py)
uses signed Go SDK deployment/readback and modeled errors, actual TLS AMQP/JMS
traffic, official Python Lambda runtimes and SQS application effects:

- [RabbitMQ core](../testdata/integration/cloudformation_lambda_mq_rabbit_core_current.json)
  and [ActiveMQ core](../testdata/integration/cloudformation_lambda_mq_active_core_current.json)
  prove disabled backlog, current IAM/secret denial and recovery, failed-invocation
  redelivery with native message IDs, retained SQLite/controller restart and
  successful native acknowledgement.
- [RabbitMQ settings](../testdata/integration/cloudformation_lambda_mq_rabbit_settings.json)
  and [ActiveMQ settings](../testdata/integration/cloudformation_lambda_mq_active_settings.json)
  prove actual two-record batches and version-qualified execution.
- [RabbitMQ source fencing](../testdata/integration/cloudformation_lambda_mq_rabbit_fence.json)
  and [ActiveMQ source fencing](../testdata/integration/cloudformation_lambda_mq_active_fence.json)
  preserve the old mapping's source ARN after same-name broker recreation.
  New brokers have different IDs/ARNs; independent protocol clients recover their
  untouched messages. This is not a claim of same-ARN broker recreation.
- [RabbitMQ controls](../testdata/integration/cloudformation_lambda_mq_rabbit_controls.json)
  and [ActiveMQ controls](../testdata/integration/cloudformation_lambda_mq_active_controls.json)
  verify immutable-queue rollback, source-access and batching omission, native
  acknowledgement of filtered messages, and delivery after filter removal.
- [ActiveMQ credential reintroduction](../testdata/integration/cloudformation_lambda_mq_active_reintroduce_current.json)
  and [RabbitMQ credential reintroduction](../testdata/integration/cloudformation_lambda_mq_rabbit_reintroduce.json)
  retain the live secret across later unrelated target/enablement updates.
- [Late queue](../testdata/integration/cloudformation_lambda_mq_rabbit_missing_current.json)
  and [late custom host](../testdata/integration/cloudformation_lambda_mq_rabbit_late_host.json)
  prove disabled admission before those native resources exist, followed by real
  delivery. [Custom-host isolation](../testdata/integration/cloudformation_lambda_mq_rabbit_custom_host.json)
  preserves the host across credential rotation and restart while leaving the
  same-name default-host queue untouched.
- [Explicit-root retention](../testdata/integration/cloudformation_lambda_mq_rabbit_default_host_current.json)
  proves schema-304 readback, host-removal retention, add/change rollback and
  retained restart with real backlog delivery. The
  [recovered ActiveMQ controller](../testdata/integration/cloudformation_lambda_mq_active_explicit_host_recovered.json)
  rejects explicit `/` and delivers the original retained backlog.
  The final [schema-304 ActiveMQ check](../testdata/integration/cloudformation_lambda_mq_active_explicit_host_schema304.json)
  also rejects explicit `/` while preserving actual delivery and native cleanup.

Each completed workflow verifies that deleting the stack preserves independent
functions, brokers and message bytes, then removes its exact-owned resources.
Native disabled control evidence does not establish native AWS message delivery,
private-network equivalence or whole-service parity.
AWS controls used ActiveMQ 5.19 and RabbitMQ 4.3; local data-plane evidence uses
ActiveMQ 5.18.7 and RabbitMQ 3.13.7. Failed-before reports remain retained,
including the first SDK assertion failure, absent-queue rejection, credential
reintroduction, explicit-host admission/projection and an intermediate preflight
panic. The crashed controller recovered its original SQLite/native state before
cleanup; those failed runs are not counted as passing workflows.

Sources: [resource contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html),
[source access contract](https://docs.aws.amazon.com/lambda/latest/api/API_SourceAccessConfiguration.html),
[Amazon MQ integration](https://docs.aws.amazon.com/lambda/latest/dg/with-mq.html).



## Response streaming

`InvokeWithResponseStream` shares function resolution, qualified version selection,
`lambda:InvokeFunction` authorization and concurrency admission with `Invoke`.
Generated Smithy streaming-union members are receive-only typed channels. The
shared REST JSON encoder uses the AWS SDK's event-stream framing implementation:
raw `PayloadChunk` bytes and JSON `InvokeComplete` events, with model-derived names.
Other streaming protocols and unsupported event bindings still fail explicitly.
HTTP uses `application/vnd.amazon.eventstream`; Lambda exposes the runtime's
content type separately as `x-amzn-remapped-content-type`.

Real Node.js `awslambda.streamifyResponse` handlers and custom Runtime API
bootstraps send chunked responses. The executor reads bounded chunks; the service
copies only the chunk crossing the channel ownership boundary. Backpressure uses
the actual invocation deadline. A disconnected client discards subsequent output,
not the accepted invocation. Runtime/extension completion still owns admission,
metrics and process reset; final buffered delivery cannot retain an execution lease.
Runtime read/write deadlines abort a stalled response exchange before its reader
is joined. Provider shutdown also cancels delivery, so an unread client socket
cannot retain `Stack.Close()`.

The owned [native fixture](../testdata/aws/lambda/streaming.json) and
[probe](../scripts/aws/lambda_streaming_probe.py) record Node.js 22,
`provided.al2023` explicit trailers, and timeout/recovery captures in `us-east-1`
on 2026-09-15. They deliberately retain these documentation differences:

- Streaming `InvocationType: DryRun` and `Event` both execute synchronously with
  HTTP 200. An evidence-backed model correction treats this ignored header as
  an open string, rather than adding an `Event` special case.
- Node streaming exceptions and explicitly declared runtime error trailers retain
  an empty/partial response without completion error fields. `/error` JSON is
  payload bytes in the streaming API; ordinary `Invoke` adds `FunctionError`.
- A timeout after streaming headers retains the prefix, or an empty body, and
  completes without a function-error marker. The execution report still records
  timeout, the process is replaced, and the following invocation can recover.
- `LogType: Tail` adds base64 `LogResult`; `None` produces an empty completion
  object.
- A 7 MiB response streams intact. Buffered `Invoke` instead returns the captured
  `Function.ResponseSizeTooLarge` error naming a 6 MiB + 100 byte limit.
- The 201 MiB native experiment forwarded 200 MiB + 1 byte and completed without
  an error. The local forward limit follows that observation and drains the
  remainder; one capture does not establish every AWS boundary variation.

The [isolated metric capture](../testdata/aws/lambda/streaming_metrics.json) records
one invocation per function: success emits `Errors=0`; exceptions before/after the
first byte and buffered overflow each emit `Errors=1`. These are explicit
datapoints, not inferred zeros. The executor's completed report owns that function
outcome separately from public `FunctionError` and runtime/extension phase status.

The [asynchronous destination capture](../testdata/aws/lambda/streaming_async.json)
drives ordinary `Invoke` with `InvocationType: Event` and zero retries. All three
Node cases, including both exceptions, deliver an OnSuccess record with condition
`Success`, count one and no `functionError`. Empty output omits `responsePayload`.
Binary success/partial output also omits it and instead carries
`deliveryError: {statusCode: 400, errorCode: "InvalidRequestContentException"}`.
The destination projection owns this JSON check; neither function response bytes
nor delivery routing are rewritten to pretend the handler returned a JSON error.
The additional fixtures retain exact setup, invocation, query and consumed-message
observations; the main streaming probe is not a reproduction of these extra runs.

The local streaming reader applies the documented uncapped first 6 MiB and
2 MiB/s thereafter using wall time. The native large response completed faster
than that documented rate; exact pacing and production network performance are
not conformance claims. [Function URLs](#function-urls) own a separate HTTP mapping
below; API Gateway streaming integrations and regional availability remain open.

Primary references: [streaming configuration](https://docs.aws.amazon.com/lambda/latest/dg/configuration-response-streaming.html),
[InvokeWithResponseStream](https://docs.aws.amazon.com/lambda/latest/api/API_InvokeWithResponseStream.html),
and [custom Runtime API streaming](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html#runtimes-custom-response-streaming).

## Function URLs

`CreateFunctionUrlConfig`, `GetFunctionUrlConfig`, `UpdateFunctionUrlConfig`,
`DeleteFunctionUrlConfig` and `ListFunctionUrlConfigs` use the generated frontend
and current IAM evaluation. Typed memory/SQLite records retain one configuration
per partition/account/region/function and optional alias. An unqualified function
selects `$LATEST`; explicit `$LATEST` and numeric-version URL qualifiers are
rejected. List takes an unqualified function and paginates its URL configurations.
URL configuration is separate from deployment revisions, aliases and resource
policies; it does not create a public permission implicitly.

The advertised address is `PublicEndpoint + /_stackd/lambda/urls/{id}/`, not an
AWS hostname or a local DNS requirement. Keep that public origin reachable and
stable across restart. URL identity survives configuration updates and SQLite
reopen. Update preserves omitted settings; an explicit empty CORS object clears
CORS. API readback changes immediately, while HTTP uses the prior effective
settings for one minute of service time. Pending settings and their original
deadline survive SQLite reopen. This deterministic local transition is **not an
AWS propagation-latency guarantee**; readback is not an applied-settings barrier.
Creation is locally effective immediately; URL deletion removes the local route
immediately rather than modeling an AWS edge-cache deletion delay.

Deleting an alias leaves its URL configuration readable/listable but removes its
policy and invocation target. Recreating that alias retains the same URL; it needs
a new applicable grant, and creating a second URL conflicts with the retained
configuration. Deleting a URL instead retains the function policy. Recreating
the URL assigns a new identity and can reuse those grants; the old URL does not
become the new route. Whole-function deletion removes owned URL configurations.
The bounded native lifecycle and control observations are retained verbatim in
[`testdata/aws/lambda/urls_control.json`](../testdata/aws/lambda/urls_control.json).

### Authorization and HTTP mapping

`AWS_IAM` verifies SigV4 against the original HTTP target, including the private
route prefix, before removing that prefix from the customer event. Invocation
uses the requested function/alias identity and current identity/resource policies
through the shared authorization and concurrency admission boundaries.
`NONE` is anonymous, not owner/root authority: a public resource-policy grant
is still required. `lambda:FunctionUrlAuthType` participates in URL authorization
and create/update policy conditions.

The [official access-control guide](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
says new URLs require both `lambda:InvokeFunctionUrl` and `lambda:InvokeFunction`
starting in October 2025. The owned September 2026 fixed-principal capture instead
allowed URL-only grants and enforced denies on `InvokeFunctionUrl`, without the
documented second-action check; public URL-only grants also worked. Stackd follows
that observed `InvokeFunctionUrl` decision, not a fabricated dual-action gate.
[`testdata/aws/lambda/urls_authorization.json`](../testdata/aws/lambda/urls_authorization.json)
retains fixed-policy users, a 90-second initial settle and three unchanged-policy
rounds. This is same-account evidence, not a claim about every AWS rollout,
cross-account role or Organizations/SCP combination.

HTTP becomes a payload-format-2.0 event: escaped/raw and decoded paths, raw query
and comma-joined duplicate query values, lowercase headers, cookies, text or
base64 binary body, transport context and authenticated IAM authorizer fields.
Anonymous event `requestContext.accountId` is `anonymous`; no IAM authorizer is
invented. Proxy headers are customer data, not identity or trusted transport
authority. HTTP request ID, event context and real runtime request ID join.
CORS configuration intercepts syntactic preflights before customer execution:
matching requests receive configured grants; rejected preflights return empty
200 without them. Ordinary responses merge configured and handler CORS fields
according to the retained observations.

`BUFFERED` maps ordinary handler proxy status/headers/cookies/body to HTTP,
including base64 bodies and implicit 200 JSON responses. Function errors become
502. `RESPONSE_STREAM` delivers real runtime bytes directly, not AWS event-stream
frames: HTTP integration metadata before the eight-NUL delimiter supplies
status/headers/cookies, followed by the streamed body. An ordinary nonstreaming
handler under this mode retains its original response bytes even when proxy
metadata supplies status and headers. Conversely, a real streaming handler under
`BUFFERED` is buffered: raw bytes are octet-stream, while the captured integration
metadata path supplies HTTP metadata without forwarding its subsequent body.
The modes are not interchangeable wrappers around the same JSON response.
HEAD and bodyless status handling belong to the HTTP transport.

Delivery cancellation stops socket writes and releases blocked/empty readers;
it does not cancel accepted customer execution. Runtime/extension completion
still owns capacity release, metrics and reset. Provider shutdown cancels
delivery rather than waiting forever on an unread socket. Native HTTP/1.1
requests, response modes, CORS, real runtime joins and disconnect continuation
are retained in
[`testdata/aws/lambda/urls_http.json`](../testdata/aws/lambda/urls_http.json).

The standalone CLI/SQLite smoke also sends a real SQS message from each buffered
and streaming URL invocation. HTTP, runtime event and message request IDs match;
the retained SQS API event points to the earlier URL `Invoke` event in the common
journal. This checks the causal edge separately from the native HTTP artifacts,
whose handlers make no nested SDK calls.

Two boundaries remain explicit:

- [`testdata/aws/lambda/urls_http_headers.json`](../testdata/aws/lambda/urls_http_headers.json)
  captures case-sensitive duplicate-header multiplicity. Go `net/http`
  canonicalizes request field names before Lambda sees them; native distinctions
  between repeated `X-Repeat` and mixed `X-Repeat`/`x-repeat` cannot be reproduced.
  No custom HTTP parser is introduced to conceal that limitation.
- The original empty real stream had no EOF through its 18-second receive window.
  [`testdata/aws/lambda/urls_http_empty.json`](../testdata/aws/lambda/urls_http_empty.json)
  extends that bounded observation to 90 seconds, not proof of an infinitely open
  AWS response. The original capture has runtime joins; the extra 90-second
  capture does not. Locally an empty real stream publishes 200/octet-stream and
  waits for delivery cancellation without retaining a completed runtime lease;
  no guessed AWS completion timer is installed.

These captures do not establish HTTP/2, IPv6, every malformed framing/header case,
URL-specific large-payload/throttle/timeout boundaries or all regional behavior.
Primary mapping references:
[URL invocation](https://docs.aws.amazon.com/lambda/latest/dg/urls-invocation.html),
[URL configuration](https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html)
and [custom runtime streaming](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html#runtimes-custom-response-streaming).

### Native URL observations

Configured CloudTrail data delivery records both buffered and real streamed URL
execution as `Invoke`, not `InvokeFunctionUrl` or `InvokeWithResponseStream`.
The captured request parameters are `functionName=<unqualified ARN>`,
`invocationType=RequestResponse`, `logType=None`; response elements are null.
Additional event data contains only `functionVersion=<ARN>:$LATEST`, without
`customerEniId`. The records contain the unqualified `AWS::Lambda::Function`
resource. Handler 400/500 and ordinary throw/HTTP 502 did not add CloudTrail error
fields. Anonymous identity is `AWSAccount`, `principalId=anonymous`,
`accountId=aws`, with `sharedEventID`; signed calls retain their IAM identity.
Request IDs join HTTP, event context, runtime and the delivered record.
The five management operations have no resources: Create/Update retain
lowerCamel configuration response elements; Get/List/Delete have null responses.

CloudWatch URL counters use `Count`, latency uses `Milliseconds`. The isolated
seven-request sequence (success, handler400, handler500, throw502, preflight,
unsigned denial, signed success) emitted seven request and latency samples.
Error counters are sparse: two `Url4xxCount=1` samples, only the handler500
`Url5xxCount=1` sample, and no URL 5xx datum for the throw502. Absence is not a zero
sample. Native `Invocations` had five samples; `Errors` had seven actual samples,
including zeros for preflight/denial and one for the throw. The observed URL
dimension sets were `FunctionName=name` and `FunctionName=name, Resource=name`,
not `Resource=name:$LATEST` or an `ExecutedVersion` triple. Alias/version
dimensions were not probed.

The retained evidence is
[`testdata/aws/lambda/urls_observability_http.json`](../testdata/aws/lambda/urls_observability_http.json),
[`testdata/aws/lambda/urls_observability_metrics.json`](../testdata/aws/lambda/urls_observability_metrics.json),
[`testdata/aws/lambda/urls_observability_dimensions.json`](../testdata/aws/lambda/urls_observability_dimensions.json),
[`testdata/aws/lambda/urls_observability_management.json`](../testdata/aws/lambda/urls_observability_management.json),
[`testdata/aws/lambda/urls_observability_delivery.json`](../testdata/aws/lambda/urls_observability_delivery.json)
and
[`testdata/aws/lambda/urls_observability_stream.json`](../testdata/aws/lambda/urls_observability_stream.json).
Missing denial/preflight data delivery through roughly 662/729 seconds is
inconclusive: neighboring executing controls also lacked delivery after more
than 731 seconds. It does not establish universal omission. Metric recovery
retains the initial transient lookup failure rather than erasing it.
The [URL monitoring guide](https://docs.aws.amazon.com/lambda/latest/dg/urls-monitoring.html)
describes broader event naming, 5xx counters and dimensions than these captures;
the local observed contract is not proof for every failure, alias or VPC case.
See also [Lambda CloudTrail logging](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html).

## SQS event-source mappings

`CreateEventSourceMapping`, `GetEventSourceMapping`, `ListEventSourceMappings`,
`UpdateEventSourceMapping` and `DeleteEventSourceMapping` use the generated
frontend, typed Lambda repositories and ordinary IAM evaluation. Mapping tags
use the existing tagging APIs. The source-specific sections below describe the
implemented engine paths and their authority and checkpoint boundaries.
Unsupported source configurations return explicit errors.

The native control corpus is
[`sqs_mapping_controls.json`](../testdata/aws/lambda/sqs_mapping_controls.json):
three owned runs, 396 ordered observations and 155 exact-request CloudTrail joins.
It covers qualified function identity, duplicate pairs, pagination, tags,
execution-role permissions, orphan/recreation behavior and rejected updates.
Base, alias and version mappings can coexist; List's function filter is exact.
Deleting a function or alias does not cascade its mappings. No-op/null updates
preserve configured values; supported empty objects/lists clear them.

Disabled creation is immediately `Disabled`. Enabled creation and subsequent
enable/disable/update/delete transitions settle after one local service-second;
that is a deterministic emulator schedule, not measured AWS latency. Busy
transitions reject conflicting mutations. Rejected updates leave retained state
unchanged. SQLite reopen preserves UUIDs, configuration and transition deadlines.
Native response-null member annotations drive the common generated JSON encoder;
they do not change request or audit-document omission rules.

Standard batches support 1–10,000 records; batches above ten require a nonzero
window. FIFO batches are at most ten with no batching window. Create checks
function timeout against queue visibility; an Update without `FunctionName`
does not repeat that timeout check. Maximum concurrency and provisioned poller
settings are mutually exclusive. The poller models documented capacity/ramp
bounds, including provisioned receive/byte budgets; the native captures do not
establish full-scale throughput or exact batching/poll timing.

`SQSSource` opens a queue-bound `SQSConsumer` under a renewable execution-role
session shared by the mapping's polls. Runtime and poller credentials have
different IAM context: polling omits `lambda:SourceFunctionArn`; actual customer
SDK calls retain it. SQS remains authoritative for current queue policy/KMS
access, message state, FIFO exclusion, visibility, receipt deletion and redrive.
No receipt/retry ledger or second queue implementation exists in Lambda.

[`sqs_mapping_authorization.json`](../testdata/aws/lambda/sqs_mapping_authorization.json)
retains fresh-policy experiments rather than relying on in-place IAM propagation.
Missing/denied `GetQueueAttributes`, execution-role denies and queue-policy
receive/delete denies reject admission. Source calls succeed when
`lambda:SourceFunctionArn` must be absent; requiring the function ARN rejects
source admission. Actual function SDK sends show the inverse context. Minimal
source and precreated-log-group permissions deliver and acknowledge real records.
The 18 memory/SQLite replay cases preserve those boundaries. Cross-account/KMS
depth and late permission revocation remain outside this capture.

Polling and customer execution run outside repository transactions and outside
scheduler draining. Service time governs polling, batching windows and backoff;
manual-clock callers must advance idle-poll deadlines as well as control
transitions. Real customer execution retains its wall-time boundary.
Each accepted batch uses the shared version selection, concurrency admission
and official runtime pool. Disable/delete stops further polling, not accepted
execution or its successful acknowledgements. After process exit, SQS visibility
expiry makes unacknowledged messages available again without reinsertion.

[`sqs_mapping_throttling.json`](../testdata/aws/lambda/sqs_mapping_throttling.json)
separates rejected concurrency attempts from actual runtime failures. Restored
capacity can resume the same visibility lease; restoration does not guarantee
AWS will do so before expiry. Expired leases recover through fresh SQS receives
of the original message IDs. A retry awakened by a large virtual-clock advance
checks expiry again before invoking; it cannot resume an expired receipt batch.
Ordinary function errors await visibility recovery rather than retrying the
retained batch. Native attempt counts and wall-clock retry delays are not local
scheduling contracts.

Eighty positive native source-authority/throttle `GetEventSourceMapping`
observations omit `LastProcessingResult`, including failure and success samples.
SQS mappings therefore expose no invented `OK` or durable error status. Source
failures use focused operator logs and existing attempt/invocation counters.
Schema 57 removes the local-only column; an actual SQLite upgrade preserved the
mapping and resumed delivery without reseeding.

[`sqs_mapping_delivery.json`](../testdata/aws/lambda/sqs_mapping_delivery.json)
retains 884 observations, 40 real runtime invocations and 52 SQS records.
Fixture-driven Docker SDK replay covers success, whole-error redelivery, partial
responses, malformed identifiers, filtering, FIFO order and message attributes on
both stores. Batch packing is not pinned to AWS's observed grouping. Stable
isolated captures establish partial acknowledgement and filter disposal; the
in-place propagation-sensitive primary observations are not special cases.
The native missing-member response `[{}]` was acknowledged in the bounded
capture, unlike empty/numeric/unknown identifiers or a nonarray failure list.

The shared EventBridge matcher evaluates the decoded body for filtering while
the delivered body remains unchanged. Nonmatching records, including the native
malformed-JSON filter case, are deleted without invocation. Event payloads retain
normalized number/binary attributes and delivery metadata, not the queue's
`SqsManagedSseEnabled` flag. Actual encoded records determine the 6 MiB limit.

`EventCount` uses only `EventSourceMappingUUID` as its metric dimension. Native
partial/filter/FIFO counts replay through CloudWatch; these are source event
counts, distinct from ordinary Lambda invocation/error metrics. Pending samples
outlive mapping deletion. Native service `Invoke` records carry the mapping ARN
as `sourceArn`, the exact runtime request ID and a distinct `sharedEventID`.
The [journal contract](event-journal.md#delivery-and-causality) owns the typed
multi-message source link committed before customer execution.

An executable AWS CLI/SQLite scenario delivered five exact source IDs through
real Node.js SDK sends, including retained messages after restart and accepted
execution after disable. All five child sends followed their committed Invoke
and batch facts. Source metric sums were 5/5/5 for polled/invoked/deleted records.
Configured S3 gzip and CloudWatch Logs delivery contained the same final native
Invoke document. This is local application evidence, not a native timing claim.

A second executable clock-jump scenario first reproduced two invocations using
expired first receipts, then confirmed fresh receives with count two after the
fix. The two original source IDs were acknowledged, with no reinsertion and no
invented processing-result field. Fixture replay also compares SQS's native queue
counters against ESM attempts, actual runtime starts and successful deletions;
see [queue counter semantics](sqs-delivery.md#cloudwatch-queue-counters).

Primary contracts:
[SQS integration](https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html),
[configuration](https://docs.aws.amazon.com/lambda/latest/dg/services-sqs-configure.html),
[filtering](https://docs.aws.amazon.com/lambda/latest/dg/with-sqs-filtering.html)
and [source-function IAM context](https://docs.aws.amazon.com/lambda/latest/dg/permissions-source-function-arn.html).

## KMS-encrypted event-source filters

The five mapping APIs retain encrypted filter criteria for SQS, DynamoDB Streams
and Kinesis. The configuring/retrieving caller performs KMS operations through
Lambda; source processing uses the regional Lambda service principal, mapping
source ARN and function/source encryption context, not the execution role.
Ciphertext and the KMS-wrapped data key replace plaintext filter rows in typed
memory/SQLite state. Mapping audit projections do not expose filter patterns.

List omits encrypted criteria. Get, unrelated Update and Delete can succeed with
`FilterCriteriaError` and no plaintext when caller decryption fails. Replacing
criteria does not require decrypting the old value; replacing/resetting the key
without replacement criteria does. Empty criteria remove the key. Polling
decrypts before admitting new source work; an already authorized long poll or
accepted invocation is not retroactively canceled by key revocation.

`testdata/aws/lambda/filter_kms_native.json` captures native controls, redaction,
caller denial, key replacement/reset and KMS audit identity/context. Its bounded
encrypted-SQS polling attempt did not deliver; it is not native evidence for
encrypted delivery or revocation latency. The local executable scenario does
exercise all three real source engines through official Python into SQS, with
disabled-key SQLite restart, recovery, replacement/reset and absence of plaintext
encrypted-filter rows.

New filter writes use the shared signed, committing AWS Encryption SDK v2
envelope (suite `0x0578`). KMS receives the native function/source ARN fields and
the ephemeral P-384 `aws-crypto-public-key`; policies requiring that field now
apply to both encryption and decryption. The exact expected resource context,
wrapped key, key ARN, header, frames and signature authenticate before plaintext
is released. An authenticated private plaintext prefix binds the mapping ARN
without adding an invented KMS context field.

SQLite migration 306 retains an explicit envelope format. Existing empty-format
AES-GCM rows remain readable without rewriting ciphertext or guessing from nonce
bytes; new rows use `aws-encryption-sdk-v2`. Unknown formats fail closed. Legacy
reads still use their original context and cannot bypass a newly imposed
public-key policy requirement.

The [executable signing capture](../testdata/integration/lambda_filter_signing_after.json)
records old-binary legacy recovery, signed create/rekey under a required-public-key
policy, list redaction, current caller denial, and actual filtered Python runtime
delivery. Official AWS Encryption SDK 4.0.3 decrypts the stored signed envelope
with exactly the three expected context fields and the private mapping binding.
This proves SDK message interoperability, not native Lambda ciphertext layout.
Its immediate key-revocation delivery assertion failed without retaining the
unexpected receipt payload; it does not establish a revocation latency contract.
Already-authorized receives remain outside new-poll authorization checks.

The separate [cold-admission runtime workflow](../testdata/integration/lambda_filter_signing_runtime.json)
stops the controller before each revocation check. Disabled or explicitly denied
keys leave the source message visible with no in-flight or downstream delivery;
restoring authority delivers the exact retained marker. Signed filters also
survive a further controller restart and still discard nonmatching messages.
The execution role is explicitly denied KMS throughout; decryption succeeds
through the regional Lambda principal, not borrowed role authority.

Native probe functions, mappings, queues and role were independently confirmed
absent; its two owned KMS keys were scheduled for their required seven-day deletion
window, not claimed deleted. Primary
[filter encryption contract](https://docs.aws.amazon.com/lambda/latest/dg/security-encryption-at-rest.html).

## DynamoDB Streams event-source mappings

The same generated mapping APIs select `DynamoDBSource`/`DynamoDBConsumer` for
stream ARNs. Admission checks the function execution role's `DescribeStream`,
`GetShardIterator` and `GetRecords` authority. Native admission does not require
`ListStreams`, even when denied; see the [deployment authority capture](#cloudformation-stream-mappings).
Actual reads use renewable role sessions and the stream owner's current resource/identity policies;
polling does not manufacture `lambda:SourceFunctionArn`. Source denial does not
disable the mapping or consume a function-error retry budget.

The [native source capture](../testdata/aws/lambda/dynamodb_source.json) retains
controls, qualified handler invocations, source permission denial/restoration,
retry identities and failure documents. Its completed root run is the replay
input; earlier exploratory runs remain evidence, not fallback implementations.
Native DynamoDB creation enters `Creating`, including disabled creation, then
settles to the requested state. Local control transitions use service time, not
measured AWS propagation latency. Native batch size 101 with zero batching window
is accepted; the SQS-specific greater-than-ten rule does not apply. Starting
positions are `TRIM_HORIZON` and `LATEST`, not `AT_TIMESTAMP`. A record-age setting
of `-1` disables the configured age limit, not the source's 24-hour retention;
configured limits are at least 60 seconds. Nonempty filters and parallelization
above one are rejected with tumbling windows; an empty filter container is accepted.
The destination metric capture also enables an admitted mapping after its queue
destination acquires an explicit deny. Updates that leave the function binding
and destination untouched do not reauthorize that destination at admission;
the actual delivery command still evaluates its current policy.

One DynamoDB/Kinesis processor retains normalized shard/parent progress, queued
records, per-key lanes, retry boundaries and window state. All initial `LATEST`
boundaries are captured before parent draining; checkpoints survive trimmed
source history and restart. Live iterators/subscriptions are renewable
optimizations, not persisted authority. Independent ready shards execute
concurrently; descendants wait for every parent. Parallel lanes preserve per-key
ordering; factor changes drain existing lanes before repartitioning.
These checkpoints are distinct from DynamoDB's native
ingestion checkpoint. No cross-engine snapshot or exactly-once claim is made.
Mapping deletion atomically removes its owned source state. A late accepted
completion cannot recreate those checkpoints, but may still commit independent
failure-destination work.

Capture publishes queued records and its source cursor only after the repository
transaction commits. A failed read or rolled-back page does not suspend previously
captured retry, record-age or failure-destination work, and cannot leak new records
into that work. Record age is measured from source arrival; an underfilled batch
reaches its age decision even when the configured batching window is longer.

Stream failure destinations require standard SQS queues or standard SNS topics
(S3 remains supported). FIFO destinations are rejected at create/update admission,
not accepted for an eventual failed delivery. Unrelated updates still do not
reauthorize an unchanged standard destination; delivery checks its current policy.
See the [OnFailure API](https://docs.aws.amazon.com/lambda/latest/api/API_OnFailure.html)
and its [standard destination contract](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html).

Valid partial responses acknowledge only the prefix preceding the lowest failed
sequence. An unchanged retry reuses its request ID; a failed suffix or bisected
child establishes a new batch and retry budget. Actual function errors and
invalid sequence identifiers fail the batch. Admission throttles do not spend
the function retry quota. `LastProcessingResult` describes processing, not the
discard decision: valid partial responses report `OK`, function exceptions report
`PROBLEM: Function call failed`, and pre-invocation expiry preserves
`No records processed`. A terminal discard must not overwrite that status with
`RetryAttemptsExhausted` or `RecordAgeExceeded`.

Record timestamps determine window membership. Later-window records, shard
completion and oversized state drive finalization. An idle window also finalizes
after its end plus the documented allowance of up to two minutes; the local
scheduler uses that upper bound in service time, not an exact measured AWS delay.
The [window capture](../testdata/aws/lambda/dynamodb_windows.json)
observed a state string of 1,048,640 characters followed by an empty-record
invocation with both final and early-termination flags, retaining the complete
oversized state. Later windows began with empty state.

SQS/SNS failure documents retain stream metadata. S3 additionally retains the
original invocation as an escaped JSON string in `payload`, with content type
`application/octet-stream`. Keys use
`aws/lambda/<mapping UUID>/<shard ID>/YYYY/MM/DD/YYYY-MM-DDTHH.MM.SS-<UUID>`.
Window failures include `timeWindowInfo`; a failed final invocation with
`Records=[]` still produces a destination document whose `DDBStreamBatchInfo`
contains only `shardId` and `streamArn`. Pre-invocation age expiry omits
`responseContext`. An executable SQLite scenario reproduced the missing
empty-record failure on the old worker, then delivered the native-shaped S3
object and verified subsequent window state reset on the corrected worker.
An additional real-runtime SQLite scenario held an accepted invocation behind
an S3 read barrier, deleted its mapping, then released the function to fail.
The original request identity and payload reached S3 without recreating source
checkpoints. Retained-store regressions cover deletion and late state writes.

The [destination metric capture](../testdata/aws/lambda/dynamodb_metrics.json)
records actual `EventSourceMappingUUID` dimensions. Three failed records delivered
successfully produced `OnFailureDestinationDeliveredEventCount=3`; an admitted
destination denied by current SQS policy produced `DroppedEventCount=3` and
function-level `DestinationDeliveryFailures=1`. After policy restoration, a new
record reached the destination. The original records were not observed there
during the remaining 980.641-second interval; this is not a universal claim about
all future native retries. Locally, a completed destination command is terminal,
including denial; shutdown or completion-transaction failure leaves replayable
work. Successful destination records are not also counted as dropped.

Native no-destination failures produced no dropped-event datapoints during that
capture. Missing data is not zero. The local no-destination counter follows the
documented dropped-record contract; that positive counter is not established by
this native run. Pre-invocation throttle metric totals, cross-account source
conformance, same-window continuation after early termination, full-scale shard
topology/parallelization and provider delivery retry limits remain outside these
captures. Customer-managed filter KMS encryption and other source engines remain
explicitly unsupported.

Primary contracts:
[DynamoDB integration](https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html),
[failure handling](https://docs.aws.amazon.com/lambda/latest/dg/services-dynamodb-errors.html),
[partial batches](https://docs.aws.amazon.com/lambda/latest/dg/services-ddb-batchfailurereporting.html),
[windows](https://docs.aws.amazon.com/lambda/latest/dg/services-ddb-windows.html),
[parameters](https://docs.aws.amazon.com/lambda/latest/dg/services-ddb-params.html),
[metrics](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html)
and [cross-account Streams](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/rbac-cross-account-access.html).

## Kinesis event-source mappings

The generated mapping APIs select `KinesisSource`/`KinesisConsumer` for stream
and registered-consumer ARNs. They use the same retained processor and failure
targets as DynamoDB, not a second poller or retry engine. Typed source adapters
own standard reads and renewable enhanced-fan-out connections; Kinesis owns
complete authorized topology, source retention and opaque `LATEST` checkpoints.
The source interfaces do not expose Kafka offsets or bypass stream policy.

Native deny-one-action contrasts distinguish admission:

| Source | Required source permissions in the measured admission |
| --- | --- |
| Stream ARN | `DescribeStream`, `GetRecords`, `GetShardIterator` |
| Consumer ARN | Parent `DescribeStreamSummary`, `GetRecords`, `GetShardIterator`, `ListShards`; consumer `SubscribeToShard` |

`DescribeStreamConsumer` is not required by either measured path. Standard
admission did not require `ListShards`/`DescribeStreamSummary`; enhanced fan-out
did not require `DescribeStream`. The actual runtime role remains authoritative
after admission and reopen. Permission failure pauses source capture without
spending the function retry budget; previously captured work continues its
retry/age processing. Changing the role or source retires its old connection.

`TRIM_HORIZON`, `LATEST` and `AT_TIMESTAMP` use actual source positions.
Split/merge ancestry retains both parents; sibling shards can invoke concurrently,
but the merged child waits for both. Shared and enhanced-fan-out records retain
their native sequence/partition identities. Enhanced-fan-out `eventSourceARN`
and failure `KinesisBatchInfo.streamArn` contain the full consumer ARN, not a
rewritten parent stream ARN.

Native KPL contrasts are intentionally not inferred from KCL: standard polling
delivered the opaque aggregate as one record. Enhanced fan-out deaggregated inner
records, preserving the same outer sequence and plain `shard:sequence` event ID
without an invented suffix. An out-of-range inner hash rejected the complete
aggregate in the captured enhanced-fan-out case. Filtering and durable source
progress occur around those measured decoding rules.

The buffered invocation limit includes base64 and event metadata. A 5-MiB raw
record produced an oversized event that never reached the handler. Native
`MaximumRetryAttempts=0` and `2` produced `RetryAttemptsExhausted` destinations
with `approximateInvokeCount=1` and `3`, respectively, no `responseContext`, and
successful delivery of the ordinary successor. Rejected payload attempts spend
the retry quota rather than stalling the shard until record age expires.

`scripts/aws/lambda_kinesis_probe.py` produced
[`kinesis_source.json`](../testdata/aws/lambda/kinesis_source.json),
[`kinesis_followup.json`](../testdata/aws/lambda/kinesis_followup.json),
[`kinesis_hash_range.json`](../testdata/aws/lambda/kinesis_hash_range.json),
[`kinesis_reshard.json`](../testdata/aws/lambda/kinesis_reshard.json),
[`kinesis_destination.json`](../testdata/aws/lambda/kinesis_destination.json),
[`kinesis_oversized.json`](../testdata/aws/lambda/kinesis_oversized.json) and
[`kinesis_oversized_retries.json`](../testdata/aws/lambda/kinesis_oversized_retries.json).
All nine retained runs, including superseded/confounded attempts, verified cleanup
of their owned resources. Corrected routing evidence, not the confounded initial
reshard observation, drives topology replay.

Real Kafka/Python SDK workflows cover memory/SQLite delivery, current
authorization and recovery, aggregation, partial responses, bisection, failure
destinations, oversized retries, concurrent ancestry and retained windows.
Both DynamoDB and Kinesis tumbling-window test files use platform-neutral names:
the former `_windows_test.go` suffix silently excluded them on Linux.
The executable Logs → Kinesis → Lambda → SQS workflow also delivers after process
restart. These checks do not establish native cross-account, encryption,
parallelization, tumbling-window or initially-disabled `LATEST` cutoff parity;
those boundaries remain outside the native captures.

Primary contracts:
[Kinesis integration](https://docs.aws.amazon.com/lambda/latest/dg/with-kinesis.html),
[windows](https://docs.aws.amazon.com/lambda/latest/dg/services-kinesis-windows.html)
and [large-record integration limits](https://docs.aws.amazon.com/streams/latest/dev/large-records.html).

## MSK event-source mappings

The five generated mapping APIs select `KafkaSource`/`KafkaConsumer` for MSK
cluster ARNs and consume the existing Kafka owner's real brokers. Schema 240
retains mapping configuration, the consumer-group identity and cluster/topic
incarnation; the broker alone owns offsets. There is no second message log or
offset ledger. One topic supports `TRIM_HORIZON`, `LATEST` or `AT_TIMESTAMP`,
batch size/window controls, filtering, enable/disable, update and deletion.
An existing consumer group's committed position takes precedence over its
configured starting position.

Actual record bytes produce the native `aws:kafka` envelope: topic/partition,
integer offsets and millisecond timestamps, base64 keys/values, null tombstones,
and ordered duplicate headers with byte-array values. Filter-only discards and
successful synchronous invocations advance broker positions. Function errors
retry the same batch without acknowledging it. Current broker log-start offsets
discard expired buffered records; surviving records are not acknowledged by that
recovery step. Disable/delete stops polling while already accepted invocations
may complete. Controller restart resumes from broker state.

The current function execution role needs `kafka:GetBootstrapBrokers` and either
`kafka:DescribeCluster` or `kafka:DescribeClusterV2`. The Kafka owner evaluates
those describe actions independently, including explicit denies and permission
boundaries; grants for different actions cannot be combined. Pipes retains its
own V2 requirement. TLS/SCRAM uses current Secrets Manager and KMS authority,
not a cached permission grant. The existing owner supports installed public
brokers; unavailable VPC, IAM broker authentication and mTLS modes are errors.

The real executable capture
[`lambda_msk.json`](../testdata/integration/lambda_msk.json) preserves payloads,
failed invocation IDs and unadvanced offsets, disable/reopen recovery, current
role denial, native `DeleteRecords` retention, topic recreation fencing, and
TLS/SCRAM secret/KMS denial and recovery. Legacy-only and V2-only describe grants
both delivered. Four controllers exited normally; mappings, functions/logs,
queues, roles, secrets and native Kafka resources were removed. The local KMS key
is `PendingDeletion`, not claimed absent. The initial failed smoke's cleanup
report is retained separately; its loopback-only callback and stale producer
timestamps were corrected rather than weakening service behavior.

`testdata/aws/lambda/msk_admission.json` captures cheap native admission, not a
native MSK fleet delivery comparison. Only the missing-topic, missing-timestamp
and queue-option cases reach the intended service boundary; other probe cases
are model or unavailable-cluster evidence. Owned function/role cleanup completed.

Explicit remaining boundaries: provisioned pollers, schema-registry
deserialization, mapping logging, finite retry/age budgets, bisection, partial
responses and failure destinations. Kafka's name-based OffsetCommit cannot
atomically fence a topic UUID; pre/post identity checks do not promise exactly-once
delivery or cross-engine transactions.
`EventCount` mapping metrics require provisioned polling and are rejected for the
implemented on-demand Kafka mode; ordinary function invocation metrics remain
separate. The [CloudFormation Kafka capture](#cloudformation-self-managed-kafka-mappings)
retains the native Lambda admission error.
Primary contracts:
[MSK integration](https://docs.aws.amazon.com/lambda/latest/dg/with-msk.html),
[execution-role permissions](https://docs.aws.amazon.com/lambda/latest/dg/with-msk-permissions.html),
[consumer groups](https://docs.aws.amazon.com/lambda/latest/dg/with-msk-configure.html)
and [Kafka filtering](https://docs.aws.amazon.com/lambda/latest/dg/kafka-filtering.html).

## Self-managed Kafka event-source mappings

`SelfManagedEventSource.Endpoints.KAFKA_BOOTSTRAP_SERVERS` selects the real Kafka
consumer without an MSK resource lookup. It is mutually exclusive with
`EventSourceArn`; self-managed mapping responses do not invent that ARN.
Bootstrap host/port pairs are normalized, sorted and retained with the consumer
group. Current execution-role Secrets Manager and KMS authority protects SCRAM,
PLAIN, client-certificate and custom-root-CA material; authentication is not
silently weakened when the selected credentials fail.

Native record bytes produce `eventSource: SelfManagedKafka` and
`bootstrapServers`, not the MSK `aws:kafka`/`eventSourceArn` envelope. The shared
consumer retains failed batches without acknowledging them; the Kafka broker,
not a Lambda message table, owns committed offsets. Filtering, successful
execution and controller restart use the same checkpoint contract as MSK.

The actual signed executable workflow in
`scripts/aws/lambda_self_managed_kafka_smoke.py` runs an installed TLS/SCRAM
broker and the Python Lambda runtime; its
[`retained capture`](../testdata/integration/lambda_self_managed_kafka.json)
includes the legacy-API effect and source checkpoints.
It exercised real SQS effects, failed
invocation retry across SQLite/controller restart, current CA-secret denial,
disabled-KMS-key denial, recovery, filtering and no replay after committed
offset six. The function role explicitly denied `kafka:*`; delivery did not
borrow MSK lookup authority. Exact-owned mappings, functions/logs, queues,
roles, secrets and native broker containers/volumes/networks were removed.
The local KMS key remains `PendingDeletion`; no native AWS Kafka fleet was used.

`testdata/aws/lambda/self_managed_kafka_admission.json` records native control
admission only, not a native broker-delivery comparison. The advanced polling,
schema and failure-handling gaps listed for MSK still apply. Replacing an
existing mapping's VPC placement is explicitly unsupported rather than changing
its persisted placement while leaving its previous network resources behind.

VPC-configured Kafka sources use a Lambda-owned EC2 network interface and a real
native source namespace. Broker fetches and offset commits traverse current
security-group/network-ACL packet policy; the function execution role's current
EC2 authority is rechecked rather than borrowed from the controller. This source
placement does not implement function `VpcConfig` or turn a loopback-only MQ or
DocumentDB endpoint into a private endpoint.

The [integrated VPC capture](../testdata/integration/lambda_source_network.json)
uses a private Apache Kafka 3.7.1 broker, Python Lambda and real SQS effects. It
observed denied ENI creation without a leak, security-group/network-ACL
denial and recovery, execution-role `DescribeNetworkInterfaces` revocation and
recovery, mapping-update preflight, and controller restart retaining the source
ENI and broker offset five. Exact mapping, ENI, namespace, packet-policy, broker,
volume, bridge, VPC, Lambda, SQS and IAM retirement completed, including recovery
of a retained deleting mapping under its delegated owner context.

Primary contracts:
[self-managed Kafka](https://docs.aws.amazon.com/lambda/latest/dg/with-kafka.html)
and [mapping setup](https://docs.aws.amazon.com/lambda/latest/dg/with-kafka-configure.html).

## Amazon MQ event-source mappings

The bounded Amazon MQ profile uses installed RabbitMQ 3.13.7 AMQP and
ActiveMQ 5.18.7 OpenWire/JMS brokers, not an in-process message substitute.
The signed MQ control service retains typed broker state and owns exact native
containers/volumes. Lambda resolves that authoritative broker and current
execution-role Secrets Manager/KMS authority before fetching, retrying or
acknowledging records. The broker owns delivery acknowledgements; SQLite retains
mapping configuration rather than a second message ledger.

Configure the CLI with `-mq-runtime`, a private `-mq-state-directory`, and
explicit `-mq-tls-certificate`/`-mq-tls-key` files valid for the loopback broker
endpoint. The ActiveMQ adapter also requires Java/Javac and OpenSSL; `-mq-java`
selects Java. Native runtime images must be installed explicitly.

`go build -race -o /tmp/stackd-lambda-mq-smoke ./scripts/lambda_mq_smoke` followed
by that executable exercised both engines: signed controls, secret/KMS/EC2
admission denials, live secret-role denial and recovery, failed real Python
invocations producing SQS effects with the same native message IDs, unacknowledged
redelivery after SQLite/controller restart, and no replay after successful
acknowledgement and another restart. The run reported no races and removed
its exact broker/runtime resources.

The Lambda data plane uses the bounded public, single-instance profile described
by the [MQ owner](mq.md); broker configuration, users, logs and metrics belong to
that service rather than Lambda. Private VPC attachment, standby/cluster brokers,
managed storage encryption/replication, provisioned MQ polling and expanded
ActiveMQ concurrency remain unsupported. The earlier
`testdata/aws/mq/admission.json` measures native admission errors only.
[Deployment evidence](#cloudformation-amazon-mq-mappings) distinguishes newer
native control captures from local real-engine delivery.

Primary contract:
[Amazon MQ integration](https://docs.aws.amazon.com/lambda/latest/dg/with-mq.html).

## DocumentDB event-source mappings

The DocumentDB source adapter resolves the database owner's real TLS/SCRAM
Mongo-compatible change stream and uses current execution-role Secrets Manager,
KMS and `rds:DescribeDBClusters` authority. Database and optional collection
selection define the native watch scope; different namespaces can share a cluster
ARN and qualified function. Source-specific duplicate checks run inside the same
transaction as the mapping write. The SQLite identity upgrade preserves source
checkpoints, credentials, tags and Kafka network placement while removing the
older ARN-only uniqueness restriction.
Database and collection are creation-time fields: direct Lambda updates reject
their presence, even for an unchanged name. Only `FullDocument` is mutable within
that source configuration. Control admission checks source identity and current
authority without requiring a database instance; native writer readiness and
the change stream are checked on polling. See the [deployment calibration](#cloudformation-documentdb-mappings).

The [local executable capture](../testdata/aws/lambda/documentdb_executable_local.json)
from `scripts/aws/lambda_documentdb_executable_smoke.py` records thirteen behavior
groups through real Python Lambda execution and SQS effects: payload/namespace
selection, whole-batch retries, disabling/restarting/resuming retained native
tokens, current role/secret/KMS denial and recovery, `Default` and `UpdateLookup`,
6-MiB oversized-record dropping, `TRIM_HORIZON`, `AT_TIMESTAMP`, database-wide
watches and source-incarnation fencing. Both controllers exited zero. Mappings,
checkpoints, functions, database controls, native containers/volumes, secrets,
roles and queues were removed; the isolated local KMS key was scheduled for
deletion.

This is a real compatible Mongo engine, not the proprietary AWS DocumentDB
engine. `TRIM_HORIZON` uses its oldest native oplog timestamp rather than AWS
DocumentDB's change-stream retention calculation, and the proof uses the native
owner's master credentials. No AWS database fleet or native AWS data-plane
delivery was exercised. The owner currently exposes a loopback TLS endpoint;
private VPC/security-group/network-ACL attachment remains explicitly unsupported,
without a host-network bypass. Event filters and partial-batch responses remain
rejected according to the retained native admission captures. Native history-loss
and invalidation handling and CloudWatch publication are outside this executable
proof's measured coverage.

Primary contracts: [Lambda DocumentDB integration](https://docs.aws.amazon.com/lambda/latest/dg/with-documentdb.html)
and [DocumentDB change streams](https://docs.aws.amazon.com/documentdb/latest/devguide/change_streams.html).

## Architecture selection

Image inspection verifies the locally installed image's actual OS/architecture,
then container creation and recreation use its retained owned snapshot reference
(verified against its actual derived native config ID), or the configured ZIP-runtime image ID,
and an explicit `linux/amd64` or `linux/arm64` platform. A runtime-only image mapping
cannot silently select the wrong CPU. Missing images, mismatches and unsupported
architectures are execution configuration errors.

The native [architecture capture](../testdata/aws/lambda/architectures.json),
produced by `scripts/aws/lambda_architectures_probe.py`, records default x86
creation, explicit ARM creation and a portable ZIP migrating x86 → ARM → x86.
Published versions retain their original architecture; aliases execute the
selected version's architecture. An architecture-only `UpdateFunctionCode`
without code fails with `InvalidParameterValueException` and preserves the
deployment. The memory/SQLite SDK replay compares real `platform.machine()`,
executed versions and invoked ARNs, not just configuration fields.

Primary contracts:
[architecture selection](https://docs.aws.amazon.com/lambda/latest/dg/foundation-arch.html),
[immutable versions](https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html)
and [code updates](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html).
The Docker API's
[platform selection](https://github.com/moby/moby/blob/v20.10.0/api/server/router/container/container_routes.go#L510-L535)
is available in the adapter's baseline API 1.41. The shared Docker transport
selects the lowest common API in its supported 1.41–1.44 range from the daemon's
advertised minimum and maximum. Docker 29.1.3 requires at least 1.44; pinning
1.41 caused the real managed guest agent to exit before listening. An unsupported
or inconsistent advertised range remains an explicit prerequisite error rather
than downgrading the daemon or reporting synthetic readiness.

ARM was exercised on this x86_64 Linux host through its already configured QEMU
binfmt interpreter, including a real external extension. Stackd does not install
emulators, change host registration or ignore architecture. Other host/emulator
combinations and Graviton performance are not established by this evidence.

## Local development directories

`DockerConfig.HotReload` maps exact, unqualified function ARNs to
`HotReloadDirectories{Code, Layers}`. These opt-in, read-only host directories
replace `$LATEST`'s `/var/task` and merged `/opt` trees respectively. Either can
be omitted to retain that part of the uploaded deployment. The full ARN preserves
account/region/partition isolation; published versions never use these overrides.

```sh
go run ./cmd/stackd -listen 0.0.0.0:4566 -docker-host unix:///var/run/docker.sock \
  -lambda-hot-reload-code 'arn:aws:lambda:us-east-1:000000000000:function:worker=/absolute/code' \
  -lambda-hot-reload-layers 'arn:aws:lambda:us-east-1:000000000000:function:worker=/absolute/merged-opt'
```

Repeat either flag for other functions. Directories must already exist and be
readable by runtime UID 993. Symlinks are resolved at configuration admission;
the same resolved paths must be visible to stackd and the Docker daemon. Stackd
never changes host ownership or grants the runtime write access to these trees.
`Layers` is a complete development `/opt` tree, not a new layer-catalog API.

Normal AWS deployment APIs still require and retain actual ZIPs. Downloads,
code digests and `PublishVersion` describe those uploaded archives, not the
mutable development directories. Deploy edited code through `UpdateFunctionCode`
when it should become a published artifact. There is no magic S3 bucket,
fabricated code hash or synthetic deployment update.

Each environment owns native filesystem watches through its existing lifetime.
After observed changes settle for 500 ms of wall time, the next invocation gate
resets the real customer processes, rebinds directories and reruns Init.
An active function and its participating extensions finish first. The existing
keeper preserves `/tmp` and the network namespace; extension discovery reads the
new customer mount, including a replaced directory or renamed extension.
Unchanged code retains warm runtime state. Syntax failures remain actual Runtime
API errors and corrected source can initialize again without losing `/tmp`.

This is a live development mount, not an atomic source snapshot: already-running
code that explicitly reads changed files can observe those writes. Compilation
and atomic file publication remain the developer's responsibility. Filesystem
notification delivery and customer execution are outside virtual service time.
NFS/SMB/FUSE notification coverage and polling fallback are not provided. Watch
errors fail execution explicitly; after repairing the filesystem/watch limit,
retire the environment through a code/configuration update or idle expiry.

Local fixture inputs live in `testdata/lambda/hot_reload.json`, separately from
native AWS captures.
The real-executable CLI smoke exercised both CPU architectures, read-only mounts,
busy-call isolation, code/layer/extension replacement, warm reuse, retained `/tmp`,
published aliases and syntax-error recovery. `TestLambdaHotReloadDockerSDK`
retains the ownership and directory-replacement regression.

## State, authority and execution

The Lambda-owned repository keeps active and candidate `$LATEST` deployments in
separate slots and published versions in immutable snapshots of the same typed
record. Scoped immutable archives own original ZIP bytes shared by function code,
layer catalogs, retained attachments and download capabilities. Deployment records
retain code digest/size, ordered layer attachments and configuration, including the
text-log destination. Aliases retain routing, not copied deployments.
Configuration, tags and environment variables are typed state, not serialized
resource JSON. Memory uses the shared transaction domain; SQLite schemas 24–27
and 44–47 use SQLC-owned tables for deployments, archives, qualified versions,
aliases, policies, asynchronous controls, function-wide reservations, accepted
attempts, completed outcomes and dimensioned pending metric samples. Schema 47
also retains accepted settings and delivery authority. An accepted update does not
overwrite the active deployment. Ordinary metadata reads do not copy ZIPs.
The deployment-artifact additions retain layer versions/policies/allocation
counters, ordered attachments, exact S3 references, source-check deadlines and
custom log groups in typed storage; [SQLite state](sqlite-state.md) owns schema
and migration details.

Create commits `Pending`, then prepares the real container, resource limits and
deployment mounts outside the transaction. Backend preparation drives `Active`
and candidate promotion; it does not run customer initialization. Updates return
`LastUpdateStatus = InProgress`, and the old deployment serves until promotion.
Failed backend preparation retains that old deployment. Customer runtime or
extension initialization failures instead fail Invoke and leave the deployed
function `Active/Successful`, as observed natively. Startup resumes committed
pending work. Runtime processes and active execution are not checkpointed.

Readiness transitions rotate public `RevisionId` independently of immutable
deployment identity. Snapshots published during create/update move from `Pending`
to the matching deployment's readiness result without changing their captured
code, configuration or publication modification time. `$LATEST` and the published
snapshot have their own public revisions.

Deployment checks the caller's Lambda permission, scoped `iam:PassRole` and current
role trust. Lambda's service principal subsequently assumes the role through the
shared IAM authority and credential store. Containers receive real expiring local
role sessions, never deploying/root credentials. Ordinary gateway authorization
checks current role policies, boundaries and Organizations controls. The
`lambda:SourceFunctionArn` session context survives signing and constrains actual
customer SDK calls. Warm sessions do not freeze copied policy documents.

The Docker backend installs the ZIP in an owned code volume, uses a non-root user,
read-only root/code filesystems, memory/swap limits and memory-proportional CFS CPU
allocation. Runtime API listeners correlate responses with the active invocation.
Consumer-owned runtime output supplies `LogType=Tail`; function errors remain
HTTP 200 with `X-Amz-Function-Error`, rather than becoming successful payloads.

A timeout resets the runtime and extensions without rewriting a function response
already returned to the client. A private, quota-limited disk-backed ext4 volume
stays mounted by the owned installer/keeper, so the next runtime loses process
globals but retains `/tmp`. Successful `$LATEST` updates
dispose of its old environments and `/tmp`, not published-version environments.
Version deletion retires that version's environments; whole-function deletion and
normal shutdown remove exact owned containers and volumes. No global pruning or
name-prefix deletion is used.

### Temporary storage and crash recovery

`EphemeralStorage.Size` reserves usable file capacity independently of the
function's memory cgroup. Fully allocated backing storage includes filesystem
metadata outside that budget; direct loop I/O avoids charging a second backing
page cache to the runtime. A small bounded filesystem headroom is not a claim of
byte-identical AWS filesystem geometry.

The exact-owned AWS capture
`testdata/aws/lambda/ephemeral_storage.json` used Python 3.12 at 128 MiB memory:
512 MiB configured storage had 538,333,184 available bytes and reached `ENOSPC`
after 538,329,088 written bytes; allocating/touching another 64 MiB succeeded.
The 10,240-MiB configuration exposed 10,738,335,744 available bytes. Both the
owned function and role were deleted and absence verified.
The local `scripts/lambda_storage_smoke` wrote 536,870,912 bytes under the same
128-MiB memory limit, then touched 64 MiB; its 10,240-MiB filesystem exposed
10,738,466,816 available bytes. Warm reuse and runtime reset retained file contents.
This replaces the reproduced tmpfs failure: a 192-MiB write previously caused
Docker `OOMKilled=true` at the 128-MiB memory setting.

A daemon-side native `flock`, held through an attached container, owns each
namespace. Controller disconnect releases it. Startup removes older owned
containers before dependent filesystem volumes, exact backing-inode loop devices
and backing volumes. Bounded real-time reconciliation catches older-controller
creates that finish after recovery, excluding the current generation. Native
Docker container references protect the owner volume during handoff; normal
shutdown removes it when unreferenced. There is no global prune or name-prefix
sweep. Resources predating the namespace label cannot be attributed safely and
are not swept.

The actual smoke exercised completed and mid-preparation controller `SIGKILL`,
late native container creation, normal cleanup and another live instance's
continued invocation. The native race regression also preserved the successor's
lock/storage after the disconnected predecessor closed. Unix Engine and HTTP
proxy transports ran from a non-root client; a separate remote physical host was
not exercised. These effects stay outside service-state transactions.

## Deployment sources and archives

`CreateFunction`, `UpdateFunctionCode` and `PublishLayerVersion` accept direct ZIP
bytes or `S3Bucket`/`S3Key` with optional `S3ObjectVersion`, not both sources.
`S3ObjectStorageMode` defaults to `COPY` on each code request; selecting
`REFERENCE` is not sticky across subsequent code updates.

- **COPY:** S3 reads use the deploying caller's authority: current-object requests
  require `s3:GetObject`, explicit versions require `s3:GetObjectVersion`.
  Lambda retains the fetched ZIP independently of subsequent source replacement,
  version deletion or policy changes. Downloads return that original archive.
- **REFERENCE:** caller-authorized source resolution selects an exact non-null
  S3 version, then Lambda's service principal reads that version. Bucket policy
  service access is separate from caller access and from the execution role.
  Service requests carry `aws:SourceArn` for the function or layer being deployed
  and `aws:SourceAccount`; they do not borrow the execution role's permissions.
  `GetFunction.Code` and layer `Content` return `ResolvedS3Object` with the exact
  bucket/key/version and omit `Location`. Overwriting the current key does not
  retarget an existing reference.

`internal/integrations.LambdaS3Code` crosses the ordinary S3 command boundary;
S3 owns object/version lookup, authorization and source-read audit outcomes.
Lambda owns deployment admission, retained runtime artifacts and readiness.
COPY requires a same-region bucket locally; REFERENCE allows cross-region reads.
Native cross-region COPY captures contain differing redirect details, including
`TemporaryRedirect` and `PermanentRedirect`; the common rejection does not establish
a universal message or a function-versus-layer distinction.

Direct ZIP uploads are limited to 50 MiB compressed; that limit does not apply to
S3 package retrieval. The shared archive validator checks decompressed sizes and
CRCs, rejects unsafe entry paths, and enforces the 250 MiB expanded package limit.
Function code plus every attached layer shares that expanded limit, including
overlapping files rather than only the final merged filesystem. Runtime extraction
preserves executable files, relative symlinks and archive order; a repeated regular
file entry uses the last entry. These behaviors do not establish arbitrary symlink,
directory/file-conflict or hostile-archive compatibility with AWS.

REFERENCE creation exposes an empty `CodeSha256` while `Pending/Creating` and the
actual digest after backend preparation; an in-progress REFERENCE code-update
response omits the digest. Locally, retained ZIPs are a runtime cache, not continuing
source authority or an AWS internal-storage representation. Active own-code
references, including published versions, have persisted source checks scheduled
every hour of service time. **One hour is an emulator cadence, not an AWS guarantee.**
Source loss marks the affected function version `Inactive` without terminating
already admitted work. The local `DependencyError` reason is not a verified native
source-loss reason code. Restoring access and updating `$LATEST` configuration
rechecks the exact source and prepares a real runtime; replacing code is another
update path. Published content remains immutable, not silently repaired by a
`$LATEST` update. Layer-source loss alone does not inactivate existing consumers.

Primary references:
[ZIP deployment](https://docs.aws.amazon.com/lambda/latest/dg/configuration-function-zip.html),
[self-managed S3 storage and lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/configuration-self-managed-storage.html)
and [Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html).

## Layers and retained attachments

Layer versions are immutable scoped catalog records. Every publication allocates
a new monotonically increasing version, even for identical bytes; deleting all
versions does not reset the name's counter. Get-by-name/version and Get-by-ARN
share `lambda:GetLayerVersion` authority and return the original ZIP download for
COPY, or resolved S3 metadata for REFERENCE. Version policies use the shared IAM
evaluator and immutable principal bindings, with independent revisions, guarded
add/remove, duplicate-Sid conflicts and not-found after the final statement is
removed. Grants do not replace the deploying caller's function permission.

`ListLayerVersions` lists descending versions with conjunctive runtime/architecture
filters. `ListLayers` filters the latest extant version, rather than searching older
versions for a match, following the retained native control despite the field name
`LatestMatchingVersion`. Filtered pages can be empty with a continuation marker.
Compatibility metadata is retained as supplied, including omitted versus empty
arrays; it is not an attachment-time runtime or architecture guarantee.

Functions accept at most five distinct layer names from their own partition and
region, each with an explicit version ARN. New or explicitly repeated attachments
require the caller's `lambda:GetLayerVersion` permission and an extant catalog
version at commit. REFERENCE layers additionally require current Lambda service
access to the source, using the consuming function's source ARN during attachment.
The execution role does not fetch layers.

Attachments retain ordered archive identities independently of the catalog.
The Docker installer merges them in order into a separate read-only `/opt` volume;
later layers replace overlapping paths, while disjoint files remain. The official
runtime uses its normal layer search paths, including Python's `/opt/python`.
Updating configuration with `Layers` replaces the list; omission retains it and
`Layers=[]` clears it. Published versions retain their own attachment order/bytes.
Deleting a catalog version or revoking access prevents new attachment, including
explicit reattachment, but does not break retained consumers, publication of those
attachments, unrelated configuration changes or cold preparation after restart.
Layer compatibility metadata mentioning `arm64` does not establish arm64 execution.

For `CreateFunction` and `UpdateFunctionConfiguration`, `lambda:Layer` contains
only ARNs explicitly requested in that call, **not retained attachments**. Omission
and an empty array both provide no condition values, although only the empty array
clears the deployment. IAM's empty-set rules therefore matter: `ForAllValues` alone
does not require a layer, `ForAnyValue` does not match an empty set, and `Null:false`
can require the key. Passing this condition does not grant independent layer-read
authority.

Primary references:
[adding and ordering layers](https://docs.aws.amazon.com/lambda/latest/dg/adding-layers.html),
[layer IAM conditions](https://docs.aws.amazon.com/lambda/latest/dg/permissions-user-layer.html)
and [layer storage](https://docs.aws.amazon.com/lambda/latest/dg/configuration-self-managed-storage.html#self-managed-storage-layers).

## Extensions and subscribed telemetry

Executable files in the merged `/opt/extensions` directory run as real processes
in the function's container: the same UID, network namespace, CPU/memory limits,
credentials and `/tmp`, not host-side plugins or imported handlers. External
launch excludes the ten runtime-only environment variables listed in the
[Extensions API guide](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-extensions-api.html#runtimes-extensions-registration-api-e).
The runtime starts after external registration. Registered internal extensions
participate in initialization/invocation but cannot subscribe to `SHUTDOWN`.

The Runtime API result and phase completion are distinct. Ordinary Invoke returns
the function response while extensions may still run. The execution lease,
reserved-concurrency occupancy and authenticated SDK-call causal parent remain
until the runtime and participating extensions finish. `LogType=Tail` waits for
that phase. A later extension crash or timeout does not replace an already
returned successful payload or an already successful asynchronous outcome.
Phase failure still contributes to Lambda's `Errors` metric.
Without pending extension work, response publication follows metric commit and
execution-lease release so sequential calls reuse the completed environment.
Failed asynchronous attempts also release their lease before scheduling a retry;
successful asynchronous destinations can still precede extension completion.

Cold initialization has the documented ten-second first attempt; failed
initialization retries in the invocation phase under the function timeout.
Backend container provisioning precedes that deadline; it is not customer Init.
Warm completion freezes the whole runtime container. Subsequent invocation
unfreezes it; failure replaces all runtime/extension processes while retaining
the telemetry owner and `/tmp`. Registration IDs change after reset. Shutdown has one shared
budget: zero without registrations, 500 ms for internal extensions, or two seconds
with external extensions. The runtime is stopped before external callbacks.
Native captures use lowercase `shutdownReason` values and omit the documented
`Lambda-Extension-Event-Identifier` response header; the implementation follows
those observed responses rather than synthesizing the header.

`/2020-08-15/logs` and `/2022-07-01/telemetry` subscriptions receive actual function
and extension output plus generated platform records. Logs schemas 2020-08-15 and
2021-03-18 and Telemetry schemas 2022-07-01, 2022-12-13 and 2025-01-29 have distinct
projections. Accepted subscription categories are `platform`, `function` and
`extension`; individual `platform.*` names are not subscription categories.
Stdout and stderr have independent line framing. Completed output feeds
subscribed telemetry, `LogType=Tail` and the ordinary CloudWatch sink.
Subscriptions are additive and owned by extension name. Reset invalidates the
old registration ID but retains subscriptions; repeated membership returns
`AlreadySubscribed` and emits the native `Already subscribed` platform state.
One registration cannot mix Logs and Telemetry, while different registrations
can use both.

Delivery uses the same container's loopback network, not the emulator host:
HTTP POST/PUT carries JSON arrays and TCP carries NDJSON. Output-stream closure
flushes pending batches. Bounded queues retry failed delivery and report dropped
logs rather than treating a listener outage as successful delivery. The local
retry cadence, queue capacity, framing limits and Docker transport overhead are
implementation choices, not measurements of AWS internals. Telemetry subscription
does not require CloudWatch Logs permissions; ordinary Logs delivery still does.
Actual subscription queues, initialization history and retry payloads live in a
static PID-1 helper inside the runtime's memory/CPU cgroup. The host bridge is
synchronous and retains no subscription backlog. Reset kills and reaps customer
processes, including detached descendants, without discarding that helper's
pending deliveries or changing the execution budget. No dummy allocations or
fixed memory reservation stand in for actual buffering. The real-process
regression observes cgroup consumption, warm reuse, reset `/tmp` retention,
backlog/drop delivery and external failure/spindown callbacks. Shutdown
acknowledgment requires a delivered event followed by readiness or process exit.
Exact AWS platform and extension overhead remains a separate limit; these
measurements do not establish identical native resource costs. Disk-backed
temporary capacity and its evidence are described above.
Native captures establish a 25 ms buffering minimum and actual 10,000-item
default batches, not just successful configuration requests.

Platform lifecycle status is separate from `FunctionError`: the captured handler
exception has successful `runtimeDone`/`report` status and still increments
`Errors`. Runtime response/overhead spans use measured Runtime API boundaries;
extension overhead uses the last participating readiness boundary. Phase duration
excludes shutdown and records an expired function deadline rather than host
scheduler lateness. `Duration` and `PostRuntimeExtensionsDuration` retain
fractional milliseconds. No-extension invocations omit the latter metric sample;
a real extension that finishes before the runtime contributes measured zero.
Timeout fault/end/report records are emitted after shutdown and remain queued
for the next generation's listener. The retained native capture delivers those
records during replacement Init; publishing them to the exiting process loses
that boundary.

`make generate-lambda-runtime` derives bindings and version metadata from pinned
AWS OpenAPI/JSON-schema documents under `compute/lambda/internal/*api/source`.
Source manifests retain URLs and snapshot revisions; `request-deltas.json`
records native corrections to the published request schemas. Generation is
offline and included in normal/staged checks. Generated shapes do not imply
SnapStart, managed-instance or other unimplemented lifecycle behavior.

Primary references: [Extensions lifecycle and API](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-extensions-api.html),
[Telemetry delivery and buffering](https://docs.aws.amazon.com/lambda/latest/dg/telemetry-api.html)
and [Telemetry schemas](https://docs.aws.amazon.com/lambda/latest/dg/telemetry-schema-reference.html).

## Versions and aliases

`PublishVersion` snapshots `$LATEST`; `CreateFunction` and `UpdateFunctionCode`
also support `Publish=true`. Direct unchanged republication returns the existing
last allocated version rather than allocating another, even when only a
publication description override was requested. Publication eligibility follows
successful deployment updates, not logical code/configuration equality:
same-value configuration updates, identical ZIP uploads and reverting to an older
configuration make a new snapshot publishable. Tag and reservation changes do not.
A standalone publication that creates a version rotates `$LATEST`'s public
revision; unchanged republication does not. `RevisionId` and `CodeSha256` guards
still apply to unchanged republication, with a stale revision checked before a
wrong hash. A publication-only description does not change `$LATEST`.

Version numbers increase within the scoped function name and are not reused after
version deletion or whole-function deletion/recreation. Deleting the highest
version makes the next publication allocate the next number, not reuse a
historical matching snapshot. `ListVersionsByFunction` includes `$LATEST` followed
by numeric versions; `ListFunctions(FunctionVersion=ALL)` includes snapshots.
Both support pagination and omit readiness fields from list projections.
Numeric versions reject code/configuration updates. Deleting an absent numeric
version on an existing function is idempotent; deleting explicit `$LATEST` is
invalid, and either primary or weighted-secondary alias references prevent version
deletion. Whole-function deletion removes its versions, aliases and scoped controls,
but not already accepted invocation/outcome state or unexpired download capabilities.

Deleting the extant last-allocated version rotates only `$LATEST`'s public
revision. Deleting a lower version, repeating an absent deletion, or deleting the
highest remaining version after that allocation was removed does not. Surviving
snapshots, deployment identity and `LastModified` stay unchanged. The native
`version_deletion.json` sequence checks stale publication/configuration guards and
subsequent unchanged publication: allocation continues beyond deleted versions.

Ordinary ZIP functions do not support `PublishTo=LATEST_PUBLISHED` publication.
The captured partial-failure `UpdateFunctionCode(Publish=true, PublishTo=LATEST_PUBLISHED)`
path commits the `$LATEST` update and readiness work before returning the
publication error; omitting `Publish=true` updates `$LATEST` without publication.
That ordinary-ZIP behavior is separate from
[managed-instance publication](#managed-instances-and-capacity-providers).

The changed deployment and its API error outcome commit in one local transaction.

Aliases have independent revisions and policies. Successful empty/same-value
`UpdateAlias` calls rotate the alias revision; a stale revision rejects atomically.
An unweighted alias may target `$LATEST`, as observed natively. Weighted routing
requires two distinct published versions with the same execution role and legacy
dead-letter target, with at most one additional version and a weight in `[0, 1]`.
Zero and one are retained, meaningful weights. Omitting `RoutingConfig` preserves
it; an empty object/map clears it. Promoting the secondary to primary requires
clearing the overlapping weight. `ListAliases(FunctionVersion=...)` filters the
primary, not secondary membership; deletion of an absent alias is idempotent.

Alias pagination uses an exclusive alias-name cursor, including names that were
not returned by a prior page. It does not inherit the documented 50-item cap of
version/function lists. The owned 53-alias capture returned all 53 by default and
with `MaxItems=10000`, and pages of 51/2 with `MaxItems=51`; it does not establish an
unbounded AWS default. Signed SDK requests beyond the modeled 1–10000 range return
`ValidationException` before lookup of a missing function.

Metadata reads resolve the primary without sampling weights, retaining the alias
in `FunctionArn` and returning the primary's `Version` and configuration.
Invocation selects the deployment separately: runtime `context.invoked_function_arn`
retains the requested identity, while `context.function_version` and
`X-Amz-Executed-Version` report the selected version. Routing uses a deterministic
request/attempt-based draw locally, not an AWS random-number or exact-distribution
guarantee. Numeric versions keep frozen code, environment, role and runtime
configuration while `$LATEST` changes.

Primary references:
[version lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html),
[PublishVersion](https://docs.aws.amazon.com/lambda/latest/api/API_PublishVersion.html),
[ListVersionsByFunction](https://docs.aws.amazon.com/lambda/latest/api/API_ListVersionsByFunction.html),
[DeleteFunction](https://docs.aws.amazon.com/lambda/latest/api/API_DeleteFunction.html),
[UpdateAlias](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateAlias.html),
[ListAliases](https://docs.aws.amazon.com/lambda/latest/api/API_ListAliases.html) and
[weighted aliases](https://docs.aws.amazon.com/lambda/latest/dg/configuring-alias-routing.html).

## Function retrieval and deployment downloads

`GetFunction` uses the generated frontend and current function authorization.
It returns the selected configuration and COPY code location or REFERENCE source.
Tags and the function-wide
reservation appear only for unqualified retrieval; explicit `$LATEST`, numeric
versions and aliases preserve the requested ARN but omit both. Alias downloads use
the primary's archive, not a weighted selection. GetFunction returns tags under
its own permission, including when an adjacent ListTags request is denied.
The SDK and CLI `function-active-v2` and `function-updated-v2` waiters can observe
backend deployment readiness through this operation, not customer-init success.

Code locations require the instance's trusted `PublicEndpoint`. They are
ten-minute S3-style presigned GET capabilities, issued with the AWS SDK signer
and checked by the same SigV4 implementation as the gateway. The private Lambda
archive path does not expose a customer S3 bucket. Signing material belongs to
Lambda, independently of callers and execution roles, and survives SQLite reopen.
Do not change the public origin while issued URLs need to remain usable.

An issued location continues returning its original ZIP after code replacement
and function deletion. New locations reference the replacement archive; their
expiry is independent. Service time drives expiry. GET and single byte ranges
return real bytes; using the GET signature for HEAD returns 403. Expired locations
return S3 XML `AccessDenied`, rather than looking up a deleted source function.
No AWS warehouse encryption or object-version headers are fabricated.

Retention is the latest issued expiry on each scoped archive, not a durable row
per URL. Current, pending and published deployments, layer catalog versions and
retained layer attachments keep referenced bytes alive. Deleting one owner cannot
collect bytes still referenced by another owner or an unexpired location.
The shared scheduler removes unreferenced expired archives;
it never serializes containers or live execution. Historical migration preserves
both deployment slots, using
their earliest retained modification time for archive creation because older
schemas did not retain original upload timestamps.

`function_download.json` retains the owned AWS sequence and actual HTTPS results.
`TestLambdaFunctionDownloadsNativeSDK` replays configuration/qualifier/reservation
transitions and ZIP/range identities, replacement, deletion, independent expiry
and stable-origin SQLite reopen. The native attempt to obtain a caller-issued URL
before revoking its permissions was inconclusive; no revocation claim is made.

A SQLite-backed executable smoke used the real AWS CLI and Docker runtime:
V2 waiters reached readiness, downloaded ZIP bytes matched the uploaded package,
tags survived code replacement, and the handler executed. Both old and new URLs
survived source deletion and process restart. Advancing service time expired the
old URL while the newer one remained valid, then expired the latter. The owned
function and role were removed and absence confirmed.

Primary reference: [GetFunction](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunction.html).

## Function tags and IAM

Function tags retain exact key casing. Generated input validation owns the ARN,
Unicode and length constraints; Lambda owns the reserved `aws:` prefix, merged
50-tag limit and atomic mutation. A rejected write leaves all tags and metadata
unchanged. Successful TagResource/UntagResource calls, including no-ops, rotate
the public revision and modification timestamp without replacing the deployment
revision or resetting a warm runtime. Mutations update current and pending
configuration together so a finishing code update cannot discard them.

The generated operations authorize the current resource tags, requested tags and
case-sensitive `aws:TagKeys` through the shared IAM evaluator. Authorization precedes
resource-existence and mutation validation. Only unqualified function ARNs support
these tagging operations. GetFunction's tag visibility does not introduce a hidden
ListTags permission dependency.

Qualified invocation and metadata authorization evaluate the requested ARN, not the
deployment an alias selects. An alias grant continues to authorize that alias after
retargeting without a separate grant on the new numeric version. Unqualified,
numeric and alias identity/resource-policy grants do not implicitly cover one
another. Every scope uses live base-function tags for resource-tag conditions,
not a publication-time snapshot. The native `qualified_tags.json` matrices cover
unqualified, explicit `$LATEST`, numeric and alias Invoke/GetFunction/
GetFunctionConfiguration, plus GetAlias, with real matching-tag successes and
denial reversal after a tag change. Those bounded observations do not establish
instantaneous AWS tag propagation or the winner for case-distinct IAM tag keys.

`function_tags.json` records native tag-state/revision transitions, current-role
permission changes with retained STS credentials and CloudTrail records. Its SDK
replay covers atomic limit errors, case-distinct storage, no-ops, qualifier errors,
request-tag and TagKeys conditions, GetFunction/ListTags permission independence
and native audit request/resource projection. A real-runtime scenario preserves a
module-global counter across tag writes and observes reset after a code update.

See [IAM case-distinct tag conditions](iam-evaluation.md#case-distinct-service-tags)
for the native collision matrix and its unresolved precedence boundary.


Primary references:
[TagResource](https://docs.aws.amazon.com/lambda/latest/api/API_TagResource.html),
[UntagResource](https://docs.aws.amazon.com/lambda/latest/api/API_UntagResource.html).

## Concurrency and runtime ownership

`GetFunctionConcurrency`, `PutFunctionConcurrency`, `DeleteFunctionConcurrency`
and `GetAccountSettings` use the generated frontend and current IAM evaluation.
Reservations belong to a partition/account/region and function, not an environment.
The current quota profile has 1,000 concurrent executions and preserves at least
100 for the unreserved pool; it does not model applied quota changes or new-account
quota profiles. Reservation replacement checks the scoped aggregate atomically.
Zero is a retained reservation, not absence. Deletion releases the reservation.
Account usage counts base functions. Managed code usage counts current and
published COPY function ZIP sizes plus extant COPY layer catalog versions,
excluding replacement candidates and REFERENCE sources. Archive deduplication
does not erase per-version usage; deleting a layer catalog version removes its
managed usage even when existing attachments still retain its bytes. The reported
managed-code limit is 300 GiB; this reporting does not establish aggregate
code-storage quota enforcement.

Reservation changes rotate public configuration revisions without changing
`LastModified`, code identity, warm globals or `/tmp`. Repeating the same reservation
or deleting an absent reservation is a no-op. Deployment identity has its own
retained revision so same-clock updates still replace code and metadata-only
changes cannot accidentally create a cold start.

One admission boundary counts synchronous and asynchronous calls against current
function, unreserved-pool and account capacity. A running call keeps its environment
when reservations change, including a change to zero. DryRun does not consume a
permit. Admission failures return native 429 `TooManyRequestsException`, including
the reserved/account reason and `Type=User`, before starting customer code.
Live permits are process-local; retained reservations and queued attempts survive
restart, but running engines do not.

Admitted calls lease independent real runtime environments. Warm pools are keyed
by resolved version; aliases selecting the same version share its pool, while
different versions do not share globals or `/tmp`. Capacity remains function-wide
across every version and alias. Idle environments can be reused; a busy environment
never serializes another admitted call behind it. `$LATEST` promotion and version
deletion retire only affected environments without waiting on customer code under
a service/storage lock. Already-running calls finish before their retired
environment is closed. Preparation and cleanup remain outside transactions.
Readiness and the prepared slot's availability publish atomically. Cleanup of old
idle environments cannot make the first post-update invocation prepare a second
replacement or send its next sequential call to an unused environment.

The native `ReservedConcurrentExecutions` JSON shape truncates decimal fractions
toward zero and saturates to signed 32-bit bounds before modeled validation, IAM,
lookup, quota checks and CloudTrail projection. An evidence-backed model correction
generates this shape annotation; it is not a Lambda-specific handwritten decoder
or a global relaxation of Smithy integer parsing. Boolean/string tokens remain
serialization errors; missing/null and values still negative after conversion
fail modeled validation.

## Provisioned execution and runtime controls

The provisioned-concurrency APIs allocate real qualifier-owned runtime pools.
Readiness follows actual runtime initialization, not a retained requested count.
Resizing retires or prepares real environments; controller restart restores the
desired allocation and initializes new runtimes. Only invocations occupying an
actual provisioned slot receive its reservation credit. An alias may use its
resolved numeric version's pool, with admission and release charged to that pool;
another alias's pool cannot be borrowed. On-demand calls receive no pool credit.

`GetFunctionRecursionConfig`/`PutFunctionRecursionConfig` retain `Terminate` or
`Allow`. Trusted invocation lineage, not a user-supplied counter, drives the
recursion decision. The signed local workflow and native capture both observed
16 executions under `Terminate` and the bounded 18-execution chain under `Allow`.

The runtime-management APIs retain `Auto`/`FunctionUpdate` policy. Execution still
uses operator-installed immutable runtime images; this is not an AWS automatic
runtime-rollout simulation. `Manual` runtime-version selection is explicitly
unsupported until an authoritative AWS runtime-version-to-executable-image
catalog is available; no fictitious `RuntimeVersionArn` is returned.

`scripts/aws/lambda_runtime_controls_smoke.py` exercised signed IAM denial and
scoped allowance, Python initialization producing an SQS effect before the first
handler, provisioned identity reuse, distinct unqualified on-demand execution,
resize from one to two initialized environments with concurrent handlers,
downsize, reserved-concurrency bounds, recursion, SQLite/controller restart,
deletion and recreation. Both controller exits were zero; function, queue,
role, caller, retained controls and exact runtime containers/volumes were removed.
Native observations are retained in
`testdata/aws/lambda/runtime_controls.json` and
`testdata/aws/lambda/recursion_execution.json`.

## Managed instances and capacity providers

Managed execution uses the existing EC2/EBS/VPC and SSM owners: a real
firmware-booted guest kernel, the official SSM agent and Docker inside that guest.
It is not a host-container substitute. The operator must supply a prepared AMI,
instance profile/type and installed digest-pinned runtime images with
`-lambda-managed-image-id`, `-lambda-managed-instance-profile`,
`-lambda-managed-instance-type` and repeatable
`-lambda-managed-runtime-image=runtime:architecture=image-reference`; the private
HTTPS agent port defaults to 9443. Missing prerequisites return an explicit
`NotImplementedException`, not a successful but inert provider.

The guest image must contain `stackd-lambda-agent`, official SSM, Docker and the
selected runtime images. Preparation and daemon startup require the
[EC2 isolation precautions](ec2.md#execution-and-shared-compute-ownership).
The exercised image boots through SeaBIOS and NVMe with Docker 29.1.3 and SSM
3.3.5226.0; Python 3.13 and provided-runtime images were actually executed inside
that guest with network disabled and pulling forbidden. That preparation proof
alone does not establish SSM registration or a managed Lambda invocation.

Provider controls retain desired scaling, typed guest/environment ownership and
current operator-role authority. Managed publication has a separate retained
`$LATEST.PUBLISHED` snapshot and function-scaling state; failed publication quota
checks do not overwrite it. Deleting a function or that snapshot removes its
scaling/deactivation state, so recreating the same name does not inherit an old
deactivation. Service regression coverage checks both transitions.

The guest Runtime API isolates environments with Docker cgroups, a read-only
root filesystem, real 512-MB ext4 temporary storage and per-environment network
identity. Execution-role credentials use an authenticated standard container
credential endpoint, not static key environment variables or the guest instance
profile. Guest management pins the certificate and verifies provider incarnation
and capability. Function output uses the ordinary role-authorized Lambda log
delivery path; this is distinct from provider `TelemetryConfig`, which remains
explicitly unsupported.

The bounded implementation requires integral vCPU allocations, at least 2,048 MB
of function memory and matching provider/function architecture. Python managed
instances require 3.13 or newer. The documented local image proof is x86_64; it
does not establish Graviton support or a native AWS managed-instance fleet.
Non-512-MB managed temporary storage, managed response streaming, managed durable
execution and extensions are not implemented. Ordinary provisioned execution
and durable workflows described elsewhere are separate paths, not evidence for
those combinations.

The [archived managed-runtime observations](../testdata/integration/lambda_managed_capacity_archived.json)
retain actual signed SDK and process results from the local KVM/QEMU workflow:
eight occupied workers across four environments and a ninth-call HTTP 429,
independent timeout survival, current execution/operator IAM denial and recovery,
controller restart preserving native instance/container and worker/tmp identities,
and 2,738.40-second natural credential renewal with unchanged warm workers and
four actual SQS effects. Measured CPU work scaled real environments from three to
four; idle work did not scale. The 412.09-second scaling scenario also exercised
physical scale-in. Disabled-key launch failures, encrypted-volume recovery and
measured security-group egress denial/restoration were observed separately.

All eight successful native guests, their eight root volumes and eight interfaces,
the provider/function and owned API dependencies were removed. The Lambda
service-linked role deletion succeeded after natural session expiry, with an
independent absence observation; no clock or credential mutation bypassed its
guard. Controller and artifact listeners closed. Key
`138ee74b-fc89-409f-a6fe-5765cbe01a60` remains `PendingDeletion` until
`2026-10-05T15:56:20.902488Z`; it was not cancelled or recreated.

The original temporary reports and production executable are no longer present
at MAIN integration time. The retained excerpts are original transcript results,
not reconstructed reports or new physical runs. The full race-instrumented image
import timed out at 900 seconds; the production import of the same 7,126 blocks
completed in 157.069 seconds. This is not a race-pass claim for the physical
workflow. It is local x86_64 evidence, not AWS-hosted fleet calibration.

Canonical schemas265–275 integrate these Lambda/source/runtime/Signer owners
without replacing the existing DocumentDB schema245 or later MAIN services.
The [MAIN assembly smoke](../testdata/integration/lambda_main_assembly.json)
ran actual Python 3.13 code and S3 effects through the combined CLI, including
AppConfig Lambda validation and current-policy denial/recovery, AppRegistry
retention, shared classic/v2 SES policies, Signer/CSC and recursion controls across
SQLite restart. Lambda accepted opaque federated policy literals while SES
rejected the same principal kind. Both controllers exited zero and owned resources
were removed; the Signer profile was cancelled, not falsely claimed deleted.

## Resource policies and asynchronous delivery

`AddPermission`, `GetPolicy` and `RemovePermission` use the shared IAM evaluator
and immutable principal bindings. Policy revisions are independent of deployment
revisions. A duplicate Sid wins over a stale revision; removing a missing Sid
returns not-found before checking its revision. Removing the final statement
removes the policy. Native source conditions use `ArnLike` for `AWS:SourceArn`
and `StringEquals` for `AWS:SourceAccount`. Existing resource actions evaluate
identity and function policy permissions together, including explicit denies.
Unqualified grants do not silently cover qualified invocation ARNs. Numeric
versions and aliases own separate policies; `AddPermission` rejects explicit
`$LATEST` rather than installing a policy there.

`GetResourcePolicy`, `PutResourcePolicy` and `DeleteResourcePolicy` expose
whole-document replacement with independent revision compare-and-swap. The
resource must be the exact function ARN, optionally qualified; these APIs admit
an explicit `$LATEST` policy independently of legacy `AddPermission`. Deletion
is idempotent. Wildcard principals are not unconditionally rejected as public
policies: current IAM/resource-policy evaluation still owns actual invocation.
Legacy Sid insertion/removal preserves the other statements' complete principal,
action, resource and condition structures rather than flattening arrays.

Native principal-condition captures also distinguish IAM admission for legacy
removal: an account selector supplies its canonical root ARN, not the short
account number; a multi-account selector supplies an empty scalar. Mixed
AWS/service selectors match neither scalar nor `ForAnyValue` operands, reject a
`Null:true` allowance and satisfy the captured `ForAllValues` condition. The
shared IAM evaluator uses one context map: absent or nil values are missing,
while a nonnil empty slice is a present empty set. Lambda has no separate
presence markers or condition interpreter.
These are observed policy decisions, not a claim about AWS's internal context
representation. A federated-only statement's legacy removal retains the observed
`ServiceException`; whole-document deletion remains available.

The native full-policy API also admits opaque `Federated` strings, including an
empty string, literal `*`, arbitrary text and nonexistent IAM provider ARNs, plus
nonempty arrays of strings. Null, nonstring and empty-list selectors are rejected.
[`resource_policy_federation_native.json`](../testdata/lambda/resource_policy_federation_native.json)
and [`resource_policy_federation_shapes_native.json`](../testdata/lambda/resource_policy_federation_shapes_native.json)
retain these accepted and rejected shapes and exact native cleanup. This
service-specific storage admission is **not** a federated login path or wildcard
grant: the shared evaluator matches federated selectors literally, not against
ordinary IAM credentials. Only Lambda function policies opt into this principal
kind in the authoritative binder; other services' default rejection and IAM role
trust's strict provider grammar/current provider validation remain unchanged.
Mixed AWS/federated selectors permit legacy removal, unlike the observed
federated-only failure above.

The [signed executable replay](../testdata/lambda/resource_policy_executable.json)
records the failed-before admission boundary and passing-after official SDK
workflow with real Python execution. It exercises public/source-bound grants,
revision replacement, array-preserving legacy mutations, current scoped-IAM
denial/recovery, qualified targets and idempotent deletion. Opaque federated
selectors, including `*` and the empty string, never grant the ordinary IAM
caller; adding and removing a real AWS principal changes actual invocation
authority without losing the opaque statement. Exact function, role, caller,
log-group and controller cleanup completed.

Event invocation commits its payload and queue state with
`lambda_invocation_accepted_v1` before returning HTTP 202 with an empty body.
`ClientContext` is ignored for asynchronous calls. EventBridge calls the same
authorized acceptance boundary through a small consumer interface, using either
the trusted `events.amazonaws.com` principal or its retained target execution
role. Both paths supply the rule ARN privately as `aws:SourceArn`; a role does not
become a service principal or inherit `aws:SourceAccount`. A wrong source rule
produces EventBridge's `NO_PERMISSIONS` DLQ outcome, not a handler invocation.
Rule-level roles are not fallback target roles; see [EventBridge role authority](eventbridge.md#execution-roles).
`SqsParameters` on a Lambda target are retained but do not affect Lambda delivery,
matching the native capture.

The deprecated `InvokeAsync` API enters this same real asynchronous queue.
It retains the native 256-KiB payload boundary and JSON errors, supports
qualified function targets and authorizes `lambda:InvokeFunction`, not the
similarly named `lambda:InvokeAsync` policy action. It does not propagate an
incoming X-Ray trace header. Request payload bytes are omitted from its audit
projection. `testdata/aws/lambda/invoke_async.json` captures the native action,
payload and qualified-target behavior; the signed self-managed Kafka executable
workflow also exercised actual legacy-API Python execution and SQS effects.

Logs subscriptions use that same acceptance path through
`internal/integrations.LogsSubscriptions`. `CheckInvoke` performs the permission
preflight as DryRun without executing code; `InvokeEvent` accepts the real
base64/gzip `awslogs` envelope. The trusted global Logs service principal and
current regional alias participate in one IAM decision, with explicit-deny
precedence, source account and the source group ARN including `:*`. No invocation
role is borrowed from the configuring caller. [Logs](logs.md#lambda-subscriptions)
owns filter configuration, pre-acceptance retries, native evidence and its
Lambda-only destination boundary. Once Lambda accepts, Lambda owns execution
retries rather than asking Logs to repeat a failed handler.

SNS subscriptions enter that same asynchronous boundary under the SNS service
principal and source topic. [SNS](sns.md) owns selected-protocol filtering,
signatures and retries before acceptance. Its native fixture replay provisions
the unchanged Python 3.12 collector, invokes the real official runtime and compares
actual SQS receipts, including null Subject and native attribute projections.

Lambda owns retries after acceptance; upstream acceptance does not mean handler
success. Default function-error retries run after one and two minutes of service
time, with the same Lambda request ID. System failures use exponential backoff
from one second, capped at five minutes; default maximum event age is six hours.
If the next function-error retry cannot begin before the event-age deadline,
the event completes immediately with `EventAgeExceeded`, retaining its last
actual response. Maximum event age limits queueing, not a handler already running.
Each attempt resolves the requested reference again, including current alias
routing, scoped applied settings and the selected deployment's execution role.
Retargeting does not reset the accepted event's retry budget or request ID.
Acceptance retains settings, role and legacy dead-letter target; if the requested
target is later deleted, prior retained controls and authority remain available
for failure delivery rather than disappearing with its configuration. A running
call can complete after alias/version deletion. Already accepted work is not
reauthorized against the original caller's subsequently changed policy.
Workers claim state in a short transaction and release the shared scheduler before
running customer code. They share the same current concurrency admission and
leased-environment pool as synchronous invocation.

`PutFunctionEventInvokeConfig`, `UpdateFunctionEventInvokeConfig`,
`GetFunctionEventInvokeConfig`, `DeleteFunctionEventInvokeConfig` and
`ListFunctionEventInvokeConfigs` retain optional settings separately from their
effective defaults. Put replaces settings; update preserves omitted settings.
Unqualified and `$LATEST` configuration refer to the same record. Numeric and
alias configurations are distinct, including aliases targeting `$LATEST`; missing
scoped settings use defaults, not the parent or alias target's configuration.
Update requires an existing configuration; List takes an
unqualified function and supports pagination across scopes.
API-visible changes precede queue application. Stackd applies changed settings
after two minutes of service time: a deterministic local representative,
**not an AWS fixed-latency guarantee or a per-scope propagation algorithm**.
Deletion hides the record immediately while a pending reset can retain old applied
settings. No-op effective
changes need no timer. Pending changes, original deadlines, payloads, retry counts
and invocation IDs survive SQLite reopen.

Native qualified hot updates delivered old and then new destinations from the same
warm runtime; configuration deletion also left one early alias delivery using the
old route. Stored API readback alone is therefore not an applied-settings barrier.
For deletion before dispatch, the positively completed native max-retries-zero
case reports `RetriesExhausted`, count one and status 404, with neither
`responsePayload` nor `executedVersion`; no handler error is invented.
Earlier retry-enabled captures observed service redispatch but no terminal
record through bounded windows; those audit records do not prove handler entry.

The [extended deletion analysis](../testdata/aws/lambda/async_deletion_analysis.json)
retains completed same-target retry-one/count-two and age-180/count-one controls
before lifecycle changes, real occupied-runtime admission barriers, runtime
markers, destinations and independently collected CloudWatch metrics.
For the deleted alias, the isolated metric dimensions contain one additional
`AsyncEventsDropped` beyond the two known controls, in the minute containing
the 180-second deadline. There was no additional runtime entry or destination
through more than six hours. This is positive aggregate drop evidence, **not**
a measured terminal condition/count/status, an exact timestamp or an AWS backoff
guarantee. Missing `DestinationDeliveryFailures` datapoints are not measured zero.

Stackd preserves the accepted request when a retry-enabled alias is missing,
its scoped parent still exists and no handler attempt has occurred. Failed alias
lookups consume neither handler retry budget nor a fabricated response. Existing
deterministic preparation backoff is bounded by the event-age deadline. If that
alias is still missing at expiry, completion and `AsyncEventsDropped` commit together
without a fabricated OnFailure destination record. The independent legacy DLQ
route remains separate; its deleted-alias fate and error projection are not
calibrated by this capture. The retry-zero captured 404 contract remains distinct.

Native alias recreation, alias retargeting and same-name whole-function recreation
executed the accepted payload in replacement deployment two, preserving its
request ID; qualified execution selected version two. Logical target resolution
therefore remains per attempt, not an unconditional accepted-incarnation fence.
The [whole/fixed/postfailure calibration](../testdata/aws/lambda/async_deleted_targets_analysis.json)
adds seven independently controlled targets, actual occupied-runtime barriers,
SQS markers, OnFailure records, legacy DLQs and scoped CloudWatch series:

| Deleted target | Actual handler entries | Native terminal |
| --- | ---: | --- |
| Whole function, queued, retry zero | 0 | `RetriesExhausted`, count 1, status 404 |
| Whole function, queued, retry one | 0 | `RetriesExhausted`, count 2, status 404 |
| Fixed version, queued, retry zero | 0 | `RetriesExhausted`, count 1, status 404 |
| Fixed version, queued, retry one | 0 | `RetriesExhausted`, count 2, status 404 |
| Fixed version, one failed handler, then deletion | 1 | `RetriesExhausted`, count 2, status 404 |
| Alias, one failed handler, then deletion | 1 | `RetriesExhausted`, count 2, status 404 |
| Whole function, one failed handler, then deletion | 1 | **Terminal routing/scheduling unproven** |

All six positive cases delivered both OnFailure and the original event bytes to
the legacy DLQ. Their 404 records omit `responsePayload` and `executedVersion`;
the missing-target response replaces the previous actual handler error when
there was one. DLQ `RequestID` matches admission, `ErrorCode` is numeric 404,
and `ErrorMessage` identifies the requested qualified resource. Unqualified
whole-function errors explicitly include `:$LATEST`.

The whole-function postfailure case has one additional aggregate
`AsyncEventsDropped` beyond its two completed controls, but neither terminal route
was observed through 598.506 seconds. Its extra drop minute precedes the age-90
deadline, so the missing-alias age-expiry rule **must not** be generalized to it.
The local legacy missing-target path remains uncalibrated for this case. Earlier
destination-only whole-function retry-one absence through six hours remains
retained; this new DLQ-enabled positive sample does not establish universal
deletion timing. Legacy missing-target rows are not rewritten into alleged
runtime attempts: their count cannot safely distinguish old charging from a
real prior handler entry.

The [ordered recreation experiment](../testdata/aws/lambda/async_recreation_order_analysis.json)
closes the unconditional-retention question. A pre-deletion accepted event entered
replacement deployment two/`$LATEST` under its original request ID and waited on a
real SQS gate. A fresh invocation then positively delivered to the **new**
destination before the old handler was released; that old accepted event also
delivered to the **new** destination. Together with the earlier **old**-destination
sample, this rules out a permanent accepted-event destination freeze. It does not
identify the native propagation instant or distinguish pre-entry propagation from
refresh during execution.

Locally, whole-function deletion detaches the last applied accepted-event queue
settings without deleting work or fencing the name. A replacement's absent or
not-yet-applied configuration cannot erase those retained controls. The existing
configuration-application job reattaches them; explicitly deleting configuration
restores defaults rather than reviving an old destination. Runtime selection,
execution role and deployment-owned DLQ resolve from the current replacement,
and delivery evaluates current IAM. Schema 313 retains this queue-control
transition across SQLite reopen and backfills pre-upgrade noncompleted work whose
scoped original function is already absent. Existing functions and completed
outcomes are not detached by migration. Published-version numbering remains
monotonic and a missing numeric version never redirects to replacement `$LATEST`.

Both new native experiments retained their complete ledgers, exact actor/account/
region checks and independent final absence inventories. No preexisting resource
was mutated; all owned functions, versions, aliases, queues and roles were removed.
The ordered probe's reported queue/API counts cover its observer, not handler-side
gate receives or marker sends. Its captured gate was bounded by wall time but
did not retain a combined receive-call total; that accounting limit is explicit
in the analysis. Future runs additionally cap gate receives per attempt and
reserve that allowance from the observer limit. No extra native run was made.

The retained [configured recreation baseline](../testdata/integration/lambda_async_deletion_configured.json)
already exercised the gap: `function-configured-recreate-before` executed the
replacement runtime but produced no destination receipt; its after-application
counterpart reached the new destination. The missing before-application route
was observational in that older smoke, not asserted as native behavior.

The [schema-313 executable proof](../testdata/integration/lambda_async_deleted_targets_20261001.json)
runs the parent-built `bin/stackd` with official Python 3.12 runtime containers,
signed SDK calls and retained SQLite state. Fifteen controller runs exercise
the six native-positive deleted-target terminals, actual failed-handler receipts,
same-name replacement with **old-before-application/new-after-application**
destinations, monotonic publication scope, explicit configuration reset and
current IAM denial of the retained old destination. The denied delivery has one
positive `DestinationDeliveryFailures` sample and no unauthorized SQS receipt;
customer code still executes in the replacement runtime. Original request IDs
and requested ARNs survive retries and restarts.

Retry-zero alias deletion, alias recreation/retargeting and real retry/age controls
also pass in that executable. Whole-function postfailure is deliberately labeled
`terminal-unproven`: the local legacy 404 delivery is retained as a diagnostic,
**not** promoted to a native expectation. All owned resources have independent
not-found reads; final Docker inventory contains no owned containers or volumes.
The SQLite files remain at the report's `state_retained_for_diagnostics` path.

A separate [same-binary alias preservation run](../testdata/integration/lambda_async_alias_preserved_20261001.json)
uses three schema-313 controllers. Retry-enabled missing-alias recreation retains
zero-handler lookups across restart, then executes replacement version two with
the original accepted ID. Expiry retains no invocation or outcome work and no
runtime/destination through local age 600; exact alias metric deltas remain
received +1, dropped +1, invocations +0, errors +0. All 18 controllers across
both runs exited zero, with independent owned-resource absence checks and empty
owned Docker inventories.

Permanent regressions include `TestLambdaAsyncSameNameRecreationNativeSDK`
(signed Go SDK and real runtime, memory/SQLite),
`TestLambdaAsyncDeletedTargetSettingsHistoricalUpgrade` (schema 312 migration),
`TestAsyncRecreationSettingsDetachAndApply`,
`TestAsyncDetachedConfigurationDeletionRestoresDefaults` and
`TestLambdaDeletedTargetDeadLetter` (qualified error fields and current IAM).

The [failed-before executable](../testdata/integration/lambda_async_deletion_missing_alias_before.json)
reproduced a fabricated `RetriesExhausted/count2/status404` at age 61 without
handler entry. The [corrected workflow](../testdata/integration/lambda_async_deletion_missing_alias_after_applied.json)
preserves zero handler attempts across missing lookups and SQLite restart, then
executes recreated version two with the original request ID and `Success/count1`.
It also exercises real handler retry/age controls, retry-zero deletion, configured
alias recreation/retargeting and positive whole-function recreation.
The [final-binary expiry proof](../testdata/integration/lambda_async_deletion_missing_alias_final_expiry.json)
observes queued work at age 179 and retirement at age 180, no runtime/destination
through local age 600, and exact alias CloudWatch deltas: received +1, dropped +1,
invocations +0, errors +0. These deterministic local windows are not native timing
guarantees. No legacy DLQ was configured.

The [first recreation smoke failure](../testdata/integration/lambda_async_deletion_missing_alias_after.json)
is retained: recreation executed correctly, but deleting the alias removed its
event-invoke configuration and the harness had not reapplied its destination.
The corrected harness proves the replacement route with an independent consumer
before releasing queued work, without changing accepted time or identity.
All four runs cleaned exact-owned API resources, containers and volumes; all
twelve controller lifetimes exited zero. Go v2 native SDK regressions separately
preserve handler retries, retry success and retry-zero accepted ownership on both
memory and SQLite.

In-flight claims are requeued on startup without consuming another retry. A
shutdown or crash can therefore repeat customer effects, as allowed by at-least-once
delivery; execution itself is not replayable. An EventBridge-triggered invocation
has its own Lambda request ID and retains the accepted EventBridge event as its
journal parent; a Logs-triggered invocation retains the accepted Logs batch.

## Asynchronous outcomes and metrics

Completion retains one invocation record with its original request bytes, actual
last response, execution count, completion time and role. Independent immutable
routes select the configured success/failure destination and, on failure, legacy
dead-letter target. Both routes can deliver; configuring one does not suppress
the other. They commit with completion and survive source-function deletion.
Delivery happens outside the source transaction. The last acknowledged route
collects the completed record; a crash after target acceptance but before that
acknowledgment can repeat delivery.

`internal/integrations.LambdaOutcomes` implements the service's small `Check`/`Send`
interface using ordinary SQS, SNS, Lambda, EventBridge and S3 commands. Preflight
checks current execution-role permissions without publishing a fake message.
Platform delivery assumes that role without `lambda:SourceFunctionArn`; actual
customer SDK calls retain that condition. Current explicit denies and resource
policies apply to each target. Failed configuration leaves prior settings and
function revisions intact.

Destination Put replaces settings. Update omission and an empty `OnSuccess` or
`OnFailure` object preserve that route; an explicit empty `Destination` clears it.
An empty `DestinationConfig` alone is not an update. Legacy `DeadLetterConfig`
omission or `{}` preserves its target; an explicit empty `TargetArn` clears it.
FIFO targets, invalid resource kinds and self-invocation destinations are rejected.
A permitted nonexistent EventBridge bus is admitted, matching native PutEvents
behavior; it does not create a bus.

SQS/SNS destinations receive the full version-1.0 invocation record. Lambda
destinations accept that record asynchronously, with a new request ID and their
own execution retries. EventBridge uses source `lambda`, the native result
detail type, and ordered destination/source resources. S3 accepts failure
destinations only, writes extensionless `aws/lambda/async/<function>/...` keys and
`application/octet-stream` content. Admission requires ListBucket and PutObject;
subsequent delivery requires PutObject, not another ListBucket.

Destination `requestContext.functionArn` retains the requested numeric or alias
qualification, independent of the selected deployment; an unqualified request is
represented there as `:$LATEST`. `responseContext.executedVersion` identifies the
actual responding deployment. Stackd retains cumulative dispatch/response counts.
Native all-failure stable and retargeted alias sequences each produced three
runtime entries and terminal count three with retry limit two. Two stable and two
retargeted failure-then-success controls each produced two runtime entries but
`Success` destination count one. Successful destination projection therefore uses
one; failure projection uses the retained count. Neither resets queue retry
accounting or the accepted request identity.

Legacy SQS/SNS messages preserve the original event bytes and typed `RequestID`,
`ErrorCode` and `ErrorMessage` attributes. Handler failures have numeric code 200.
Error messages truncate at 1,024 UTF-8 bytes with replacement of an incomplete
rune. SNS's supplementary-Unicode attribute rejection can fail the legacy route
while an independent SQS destination succeeds.

### Deleted-alias legacy DLQs

The [separate native DLQ capture](../testdata/aws/lambda/async_deleted_dlq_native.json)
configures both routes and completes same-target handler-failure and occupied-age
controls before deletion. With zero retries, the deleted-alias event reaches both
queues without entering a handler. Its legacy message preserves the original
bytes, `RequestID` as a String, `ErrorCode` as Number `404`, and `ErrorMessage` as
String `Function not found: <requested qualified ARN>`. The independent OnFailure
record remains `RetriesExhausted/count1/status404` without `responsePayload`.
The adapter projects this pre-execution error directly rather than decoding an
absent handler response.

The [failed-before executable](../testdata/integration/lambda_async_deleted_dlq_before.json)
produced `DeadLetterErrors +1` instead of the legacy message.
The [corrected SDK/runtime workflow](../testdata/integration/lambda_async_deleted_dlq_after_current_iam.json)
verifies exact legacy bytes/attributes across controller restart, delivery with
OnFailure disabled, and current IAM denial of only the legacy route: the denial
adds one `DeadLetterErrors` while OnFailure still delivers. Native and local owned
resources were independently verified absent; all final local controllers exited
zero. The [earlier root-target-change failure](../testdata/integration/lambda_async_deleted_dlq_after.json)
is retained as an uncalibrated assumption, not evidence that API readback changes
an already accepted deleted target's route. Published-version ownership is now
calibrated [below](#dlq-deployment-ownership); mutable unqualified accepted-event
selection and deleted-target propagation remain open.

**Retry-enabled legacy DLQ behavior is not matched.** With a DLQ configured,
native retry-one deletion produced no handler entry or either route through
903.614 seconds, and no additional measured dropped event. The local diagnostic
instead expires at age 180, emits its retained `429/Rate Exceeded.` legacy message
and records a drop. This bounded mismatch does not establish native pending state,
permanent loss or eventual terminal fate. It must not inherit the earlier
destination-only capture's positive drop conclusion. Native absent delivery-error
datapoints remain absent, not measured zero. The native final poll overran its
nominal 900-second observation bound by at most 3.83 seconds. The
[companion report](../testdata/aws/lambda/async_deleted_dlq_summary.json) preserves
that deviation and the subsequent locally exercised deadline correction; no
native rerun or alteration of raw evidence was used to conceal it.

### DLQ deployment ownership

The [native ownership capture](../testdata/aws/lambda/dlq_ownership_20261001.json)
separates API readback from actual delivery. Initially `$LATEST`, version 1 and an
alias to version 1 all deliver failures to DLQ-A. After changing only `$LATEST`
to DLQ-B, a positive `$LATEST` failure reaches B; subsequent version-1 and alias
failures still reach A. Their `GetFunctionConfiguration`, `GetFunction` and
`ListVersionsByFunction` metadata also retain A. Both independent OnFailure
records and runtime version markers are retained with the original request IDs.

This differs from the [retained-records guide's shared-DLQ sentence](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html#invocation-dlq).
The [versioning guide](https://docs.aws.amazon.com/lambda/latest/dg/configuration-versions.html)
lists DLQ configuration among publication-triggering snapshot settings.
The measured contract preserves the published deployment's DLQ; the selector
does not overlay mutable root settings on a published version.

The [real-runtime executable workflow](../testdata/integration/lambda_dlq_ownership_baseline_three_targets.json)
already matches that contract across SQLite/controller restart, including
immutable runtime environment/version selection and exact legacy bytes. A queued
alias accepted while the root uses B still executes version 1 and delivers to A
after a root-only change to C. Native independently records the same alias
outcome behind an actual occupied runtime slot. No selector change or fabricated
failed-before claim is needed.

API readiness is not an applied-delivery barrier: two native `$LATEST` control
events still delivered to A before the positive B control. Likewise, an immediate
failure after explicit root DLQ removal still delivered to C. Empty
`DeadLetterConfig: {}` preserves the configured target; `TargetArn: ""` removes
the root field from API readback, without changing published/alias readbacks.
Applied removal timing and queued mutable unqualified-root target selection
remain unmeasured. The emulator does not reproduce these native propagation
delays or generalize this alias sample to deleted targets.


### Lifecycle metrics

Lambda stages weighted `AWS/Lambda` samples with actual lifecycle transitions.
Completed-minute publication and pending-sample removal join CloudWatch's shared
transaction, without requiring customer metric permissions:

- `Invocations` and `Errors` count actual runtime responses at invocation start
  time; actual executions contribute Throttles=0, and successful ones Errors=0.
- Admission throttles contribute Throttles=1 and Errors=0, but no Invocations.
  A zero-reservation asynchronous discard contributes no attempt counters.
- `AsyncEventsReceived` counts original accepted events, not retries.
- `AsyncEventsDropped` contributes one terminal sample per original event:
  zero for success, one for retry/age exhaustion or zero-reservation discard.
- `DestinationDeliveryFailures` and `DeadLetterErrors` count independent target
  failures, aggregated into one sample per minute. Successful delivery and idle
  minutes do not fabricate zero samples for these failure counters.

Every sample has a `FunctionName` aggregate and a `FunctionName` + `Resource`
series. `Resource` is the requested name, including qualification: `name`,
`name:$LATEST`, `name:1` or `name:alias`. Actual execution samples additionally
use `ExecutedVersion` for aliases and explicit `$LATEST`; direct numeric references
do not add that third dimension. Throttles and other non-execution lifecycle samples
do not invent an executed version. Native populated invocation/error queries support
the numeric/alias distinction; the explicit `$LATEST` capture positively establishes
dimension presence, not exact sample counts for every counter.

Metric samples and completed routes outlive function deletion. These seven counters
do not imply Duration, AsyncEventAge, concurrency metrics or all AWS dimension sets.

## Invocation audit identity

Implemented Lambda commands publish management/data outcomes through the shared
[audit producer path](cloudtrail.md#history-and-api-producers). Invocation records
keep requested and selected identities separate: `resources` uses the base
function ARN, `requestParameters.functionName` retains requested qualification,
and qualified requests include `qualifier`. Successful `Invoke` records include
`additionalEventData.functionVersion` as the resolved ARN plus `:$LATEST` or a
numeric version, including DryRun without runtime entry. Asynchronous admission
does not freeze that selection for later attempts.

Asynchronous dispatch produces `AWSService` `InvokeExecution`, retaining the
requested ARN in both `functionName` and `sourceArn` and the resolved version in
`additionalEventData`. This also occurs for throttled dispatches, so it is not
proof of handler entry. A missing target instead emits `AWSService` `Invoke` with
null request parameters and no additional/error fields; the independently
delivered destination carries the native 404. Audit records exclude customer
payloads and runtime response bytes. Native trail-delivery bounds and missing
denial records are not claims that AWS never logs those calls.

Primary references:
[Lambda CloudTrail events](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)
and [metric dimensions](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-view.html).

## Authenticated invocation origin

During actual runtime execution, Lambda associates the runtime session's public
access-key ID with the active invocation origin. The gateway consults that mapping
only **after signature verification**, adding a causal parent without changing
authenticated identity or authorization. Customer SDKs need no changes or
provenance headers. A synchronous invocation uses its freshly reserved API outcome
ID; an asynchronous invocation uses its retained accepted invocation ID, including
handler retries.

The environment wrapper registers only around `Invoke`, clears the mapping with
deferred cleanup and uses a separate read/write lock so SDK callbacks do not wait
on the execution lock. Canceled contexts and shutdown do not provide an origin;
idle warm environments do not retain the prior invocation's attribution.
This links actual active-runtime authenticated SDK calls, not arbitrary customer
traces, initialization/idle SDK activity, OpenTelemetry spans or native X-Ray.
The [journal contract](event-journal.md#delivery-and-causality) owns the public
Logs batch → Lambda acceptance → SQS acceptance relationship.

## Native evidence and local replay

[`testdata/aws/lambda/container_execution.json`](../testdata/aws/lambda/container_execution.json)
records an owned Python 3.12/x86_64 AWS experiment in `us-east-1` on 2026-09-13.
The account-prefix guard matched the authorized account. The fixture contains
handler source, requests, native responses, chronological observations and cleanup
confirmation; the temporary function and role were deleted and subsequent reads
returned their native not-found errors.

Observed distinctions:

- Create returned `Pending`; readiness changed to `Active`.
- Synchronous invocation returned raw JSON, HTTP 200 and `$LATEST`; DryRun returned
  204 without executing the handler. Malformed JSON returned
  `InvalidRequestContentException`.
- Warm invocations retained Python globals and `/tmp`. Handler exceptions returned
  `Unhandled` and the real `ValueError` payload without resetting either.
- A two-second timeout returned `Unhandled`/`Sandbox.Timedout`. The next invocation
  reset globals to one but retained the `/tmp` counter.
- Code and configuration updates exposed `InProgress` then `Successful`, and reset
  both globals and `/tmp`. Reserved environment names were rejected.
- Native Invoke responses used `application/json`, despite the model's generic
  blob payload default. The Lambda response boundary preserves that observed
  exception without changing generic Smithy serialization.

The opt-in replay uses both memory and SQLite and real containers. It additionally
runs customer boto3 SQS calls, checks current-policy denial/restoration on a warm
runtime, scoped PassRole, source-function conditions and actual queue side effects.

```sh
STACKD_LAMBDA_DOCKER=1 go test ./integration -run '^TestLambdaDockerSDK$' -count=1 -timeout=10m
```

The AWS CLI also exercised a SQLite-backed server across process restarts:
control-plane reads worked without a configured executor and invocation returned
`NotImplementedException`; the persisted manual clock retained its advanced time.
With Docker enabled, a two-minute service-time idle expiry removed the exact
environment's containers and volumes. With `-lambda-keep-alive 0`, consecutive
invocations used distinct environments, each reported globals and `/tmp` counters
of one, and left no owned containers or volumes. `LogType=Tail` returned the
handler's actual `cli-runtime-log` output.

The additional owned captures
[`event_policy.json`](../testdata/aws/lambda/event_policy.json),
[`event_invocation.json`](../testdata/aws/lambda/event_invocation.json),
[`event_edge_cases.json`](../testdata/aws/lambda/event_edge_cases.json) and
[`event_config_timing.json`](../testdata/aws/lambda/event_config_timing.json)
record policy/configuration transitions, actual asynchronous effects, EventBridge
delivery and bounded configuration-propagation observations. All 16 owned
functions/roles/queues/rules were removed; no existing organization resources were
modified. CLI-local validation failures and the confounded first timing experiment
remain identified rather than being presented as AWS service behavior.

The uninterrupted paired timing experiment delivered both an old event and a new
event twice after Get reported retry count zero. Later unqualified and `$LATEST`
events each ran once. The fixture does not establish configuration snapshots at
acceptance or an exact propagation interval. Local replay preserves that distinction,
including a database reopen while application is pending. Native default retry gaps
were approximately 60 and 114 seconds; local 60/120 boundaries are modeled time,
not assertions about AWS's distributed timing.

```sh
STACKD_LAMBDA_DOCKER=1 go test ./integration \
  -run '^(TestLambdaPolicyNativeSDK|TestLambdaDockerAsyncNativeReplay|TestLambdaDockerConfigPropagation)$' \
  -count=1 -timeout=10m
```

These replays use captured ZIP inputs, typed SDK clients and real boto3 side
effects on memory and SQLite. The asynchronous replay also injects a journal
append failure to reject acceptance without publishing work or a committed fact.
Container endpoint injection lets persisted queue URLs continue working across
reopen without rewriting function configuration.

The owned destination captures in `testdata/aws/lambda/` retain original ZIPs,
policies, request bytes, native receipts, metric queries and cleanup:

| Fixture | Native observations |
| --- | --- |
| `outcomes_admission.json` | Destination/legacy admission, patch semantics, atomic denials and resource-policy authority |
| `outcomes_queues.json` | SQS/SNS records, independent legacy delivery, source-function context, UTF-8 truncation and delivery counters |
| `outcomes_events.json` | EventBridge records, missing-bus admission, actual Lambda collectors and destination retries |
| `outcomes_s3.json` | Native object keys/content, failure-only routing, ListBucket preflight versus PutObject delivery |
| `outcomes_expiry.json` | Immediate age exhaustion after a failed attempt; a separate reserved-concurrency experiment retained an unexecuted event's 429/no-response outcome |

Concurrency admission now retains that never-executed throttled event's count zero,
429 response context and absent `responsePayload`; its legacy message has code 429
and `Rate Exceeded.`. Zero-reservation asynchronous discard is distinct:
`ZeroReservedConcurrency`, count zero, no response context/payload and a legacy
message without ErrorCode. Other initialization/permission failure projections
remain open rather than being fabricated from a generic service error.

```sh
STACKD_LAMBDA_DOCKER=1 go test ./integration \
  -run '^Test(LambdaOutcome|LambdaDockerNativeEventBridgeAndLambdaDestinations|LambdaDockerNativeS3FailureDestinations)' \
  -count=1 -timeout=20m
```

Replay compares SDK-visible configuration and actual consumer records on memory
and SQLite. Recovery completes a real handler, deletes its source function,
reopens storage and delivers both retained routes without executing it again.
The asynchronous retry replay upgrades SDK-created version-43 state and checks
the remaining retry budget, request identity and real queue effects.

A SQLite-backed CLI smoke ran the captured 110-second handler while advancing
service time beyond its 60-second queue age. Success still delivered; invocation
metrics retained the start minute rather than the completion minute. A subsequent
failure produced both the destination record and original-byte legacy message.
Process restart preserved settings, manual time and all six metric queries.

The owned concurrency captures add:

| Fixture | Native observations |
| --- | --- |
| `concurrency_admission.json` | Reservation replacement/removal, quota floor, IAM/lookup ordering, qualified controls, public revisions and CloudTrail records |
| `concurrency_execution.json` | Cap-one/zero throttles, DryRun, running-call continuity, independent zero-reservation destination/DLQ records and CloudWatch counters |
| `concurrency_usage.json` | A 2,230-byte ZIP with 2,097,197 uncompressed bytes increases account code usage by exactly 2,230; deletion restores the baseline |
| `concurrency_numeric.json` | Signed fractional/exponent/overflow tokens, precision beyond float64, explicit denies, missing resources and rejected-state preservation |

All owned native functions, roles and queues were removed. Raw signed replay
exercises tokens the Go SDK's int32 input cannot express; ordinary typed SDK
reads verify retained state, and CloudTrail replay verifies the saturated value.
Real-runtime scenarios require both held handlers to enter before either is
released, then observe a third call throttled. SQLite scenarios cover reservation
recovery, same-clock deployments, queued throttle expiry and schema-44 upgrades.

```sh
STACKD_LAMBDA_DOCKER=1 go test -race ./integration \
  -run '^TestLambdaConcurrency' -count=1 -timeout=20m
```

A SQLite-backed CLI smoke also held two real handlers concurrently, observed 429
on a third call and 204 for DryRun, changed reservations through zero without
interrupting running calls, and received the native zero-reservation legacy message.
Restoring capacity preserved warm globals. Process restart preserved the reservation
but used a fresh runtime; deleting the function restored account code/count usage.

The qualified boundary has its own owned native evidence inventory:

| Fixture | Native observations and bounds |
| --- | --- |
| [`version_publication.json`](../testdata/aws/lambda/version_publication.json) | Publication guards, immutable downloads/runtime snapshots, readiness, deletion, monotonic allocation and pagination. Its `publication_eligibility` supplement distinguishes same-value deployment updates from unchanged direct republication. |
| [`version_deletion.json`](../testdata/aws/lambda/version_deletion.json) | Last-allocated versus highest-retained deletion, unchanged survivors, revision invalidation, stale guarded mutations and publication after allocation tombstones. |
| [`alias_routing.json`](../testdata/aws/lambda/alias_routing.json) | Alias CRUD/revisions, `$LATEST` primary, weighted eligibility and endpoint weights, primary metadata and requested-versus-executed runtime identity. Mixed samples are not an exact routing distribution. |
| [`alias_pagination.json`](../testdata/aws/lambda/alias_pagination.json) | Default and explicit pages over 53 aliases distinguish alias pagination from the 50-version cap. Signed SDK calls bypass client validation to capture range-error precedence after owned cleanup. |
| [`qualified_invocation.json`](../testdata/aws/lambda/qualified_invocation.json) | Real STS identity/resource grants, busy admission then alias retargeting, running deletion survival, destinations and populated native metric queries. Caller-revocation controls were throttled and did not establish IAM propagation. |
| [`qualified_config.json`](../testdata/aws/lambda/qualified_config.json) | Distinct scoped settings, paired configured/unconfigured delivery controls, hot updates/deletion on warm runtimes and new deployments. Destination absence is bounded; no exact propagation delay is inferred. |
| [`qualified_retries.json`](../testdata/aws/lambda/qualified_retries.json) | Stable and retargeted always-failing aliases retain one request ID and three total runtime entries/count three with retry limit two; actual terminal records establish exhaustion. |
| [`qualified_tags.json`](../testdata/aws/lambda/qualified_tags.json) | Repeated real-runtime and metadata IAM matrices establish live base-tag authority for all tested qualification forms. Case-distinct tag precedence is outside this capture. |
| [`qualified_audit.json`](../testdata/aws/lambda/qualified_audit.json) | Correlated delivered Invoke/InvokeExecution records, requested/base/resolved identity, explicit `$LATEST` metric dimensions and controlled deleted-alias dispatch. Retry-two terminal deletion behavior is unresolved. |
| [`qualified_deletion_retry.json`](../testdata/aws/lambda/qualified_deletion_retry.json) | Same-target applied retry/age controls precede deletion, with correlated service redispatch and bounded terminal absence. Two stable and two retargeted failure-then-success trials each execute twice but deliver `Success`/count one. |

The fixtures retain original requests, native outputs, runtime/consumer evidence
where measured, bounded absences and owned-resource cleanup. All owned capture
resources are confirmed absent. `TestLambdaVersionsNativeSDK`,
`TestLambdaAliasesNativeSDK` and the `TestLambdaQualified*NativeSDK` family use
memory/SQLite with real official containers, SDK pagination, queue markers,
S3-delivered CloudTrail records and CloudWatch queries. Capture recovery and
transport failures are not service transitions. Unspecified alias/configuration
inventory order and exact propagation delays are not replay contracts. Captured
success/failure destination counts are replayed without claiming a universal
undocumented counter algorithm.

```sh
STACKD_LAMBDA_DOCKER=1 go test -race ./integration \
  -run '^TestLambda(Qualified|VersionsNative|AliasesNative)' -count=1 -timeout=45m
```

A real CLI/Docker executable smoke retained published ZIP/configuration and issued
downloads across SQLite process restart. A weighted alias executed version two
while metadata selected primary version one; stale alias revisions rejected
without mutation. New publication rotated `$LATEST` revision, unchanged publication
did not. Rejected `PublishTo` retained the native code update and exactly one error
audit outcome without allocating a version. Deletion returned 204, and same-name
recreation continued allocation at version five while old versions remained absent.
The owned local function/role were removed and their absence confirmed.

The deployment-artifact evidence separates native observations from local behavior:

| Fixture | Evidence and bounds |
| --- | --- |
| [`layers.json`](../testdata/aws/lambda/layers.json) | Nine-operation catalog/policy observations, ordered real Python imports, deletion and never-invoked published attachment retention, original ZIP downloads, relative symlinks and duplicate archive members. Tiny packages do not probe the 50/250 MiB limits; compatibility labels do not prove native machine-code or arm64 loading. |
| [`s3_sources.json`](../testdata/aws/lambda/s3_sources.json) | Caller-versus-execution-role authority, current/explicit versions, COPY survival, REFERENCE service-policy admission and exact resolved version/no Location, a 53,477,728-byte S3 ZIP download/invocation, and bounded source-loss observations. It does not establish a cache TTL or exact native Inactive reason/timing. |
| [`layer_conditions_native.json`](../testdata/aws/lambda/layer_conditions_native.json) | Fresh native configuration-update controls establish request-only `lambda:Layer`: omission/clearing, positive/negative conditions, independent layer reads, and retained attachments outside the requested set. |
| [`layer_conditions.json`](../testdata/aws/lambda/layer_conditions.json) | SDK/runtime regression inputs combine those native controls with explicitly documentation-derived CreateFunction, mixed-set, missing independent layer-read permission and explicit-Deny extensions. Those extensions are not native captures. |
| [`layer_source_audit.json`](../testdata/aws/lambda/layer_source_audit.json) | Inline/COPY/REFERENCE layer publication and correlated management audit records, cross-region COPY rejection versus REFERENCE success, exact source versions and download-field differences. Redirect wording is capture-specific. |
| [`function_s3_audit.json`](../testdata/aws/lambda/function_s3_audit.json) | Read-only recovery of request-correlated native CreateFunction history from the source capture; preserves source-field/error projection without turning absent records into non-emission claims. |

Owned resources from these captures were cleaned up. Native catalog, conditional
S3 and all-nine-layer-operation audit consumer replays, plus real-container
layer/source-lifecycle/text-log scenarios, exercise selected contracts; they are
not a full Lambda gate or a claim about all native policy combinations.

Extension evidence is retained separately from deployment-artifact evidence:

| Fixture | Native observations and bounds |
| --- | --- |
| [`extensions_lifecycle.json`](../testdata/aws/lambda/extensions_lifecycle.json) | Early responses, occupied reserved concurrency, warm state, post-response failure, reset IDs, retained `/tmp`, environment exclusions and real SQS collection. |
| [`extensions_phase_metrics.json`](../testdata/aws/lambda/extensions_phase_metrics.json) | Invocation/phase error and extension-duration samples, including successful async outcome before a later phase timeout. The captured retry setting is zero. |
| [`extensions_failures.json`](../testdata/aws/lambda/extensions_failures.json) | Real executable crashes, explicit init/exit errors, init retries, deployed Active state, successful response preservation and recovery. An exit following `exit/error` does not establish what that API alone would do. |
| [`extensions_subscriptions.json`](../testdata/aws/lambda/extensions_subscriptions.json) and [`extensions_subscription_validation.json`](../testdata/aws/lambda/extensions_subscription_validation.json) | Registration/phase precedence, additive name-owned membership, version and buffering validation, actual HTTP/TCP delivery, and reset retention. An earlier collector TCP rebinding failure is not an AWS failure contract. |
| [`extensions_buffering.json`](../testdata/aws/lambda/extensions_buffering.json) | Actual 10,000-versus-1,000-event batches across Logs and Telemetry; bounded collection does not imply global completeness or ordering. |
| [`extensions_streams.json`](../testdata/aws/lambda/extensions_streams.json) | Interleaved partial stdout/stderr writes remain separate lines in native Tail and Telemetry API delivery. Cross-stream ordering is not asserted. |
| [`extensions_platform.json`](../testdata/aws/lambda/extensions_platform.json) and [`extensions_platform_metrics.json`](../testdata/aws/lambda/extensions_platform_metrics.json) | Paired historical schemas, individual-type rejection, handler-error versus timeout status, fractional durations and no-extension metric absence versus sampled extension durations. The refreshed native scenario uses a five-second timeout; replay does not require host performance to equal AWS. |

The `TestLambdaExtensions*NativeSDK` and `TestLambdaExtension*NativeSDK` replays
use these retained ZIPs and requests against real containers, SDKs and SQS
collectors. Captures retain owned-resource cleanup. The local executable smoke
also checks early/Tail response boundaries, occupied concurrency, reset `/tmp`,
environment exclusions and byte-for-byte-equivalent CloudWatch metric results
after reopening SQLite. Interleaved stream writes were reproduced on the older
executable and corrected across Tail, subscribed telemetry and retained
CloudWatch log events on the current executable. These are bounded workflows,
not complete Lambda parity.

A local AWS CLI/Docker/SQLite smoke observed layers B-over-A, custom text logs
and a byte-identical original ZIP download. After source-version and layer-catalog
deletion, clearing `$LATEST` layers left published version 1 returning B; a process
restart preserved both a cold published invocation and an already issued download.
REFERENCE moved from Pending with an empty hash to Active with its actual hash and
exact resolved S3 version, without Location. Revoking service source permission and
advancing local time one hour made REFERENCE Inactive while COPY remained Active.
Restoring policy and updating configuration recovered a real invocation. These
are local executable observations, not native reoptimization timing.

Ordinary test runs do not require Docker or live AWS. Primary references:
[CreateFunction](https://docs.aws.amazon.com/lambda/latest/api/API_CreateFunction.html),
[Invoke](https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html),
[Runtime API](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html),
[execution roles](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)
and [source function conditions](https://docs.aws.amazon.com/lambda/latest/dg/permissions-source-function-arn.html).
Policy and queue references:
[resource-based policies](https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html),
[AddPermission](https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html),
[asynchronous error handling](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-error-handling.html),
[asynchronous configuration](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-configuring.html),
[destination records and dead-letter queues](https://docs.aws.amazon.com/lambda/latest/dg/invocation-async-retain-records.html)
and [metric definitions](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html).
Concurrency references:
[PutFunctionConcurrency](https://docs.aws.amazon.com/lambda/latest/api/API_PutFunctionConcurrency.html)
and [Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html).
Follow the [reference conventions](behavior-references.md#sources-and-responsibilities).
`clones/aws-lambda-runtime-interface-emulator` informs the runtime protocol,
not the control-plane architecture.

The version/alias fixtures also pin the transport contract to
`github.com/aws/aws-sdk-go-v2/service/lambda v1.108.0`, sourced from
`clones/aws-sdk-go-v2/service/lambda`; native SDK captures identify their boto3/
botocore versions separately. Reference documentation and SDK shapes do not
themselves establish behavioral parity.

## Runtime log delivery

`LoggingConfig` supports Text/JSON, application/system severity and custom groups.
Omitting the whole object preserves the active configuration. A present object
replaces it: omitted format becomes Text, omitted group becomes the own default,
and JSON defaults both levels to INFO. Text rejects explicitly supplied levels.
Published versions snapshot all four controls; later `$LATEST` changes do not
redirect or reconfigure them. Schema 138 retains these controls across SQLite
restart, separately for pending, active and immutable published deployments.
Group-name shape validation does not guarantee Logs delivery: an `aws/` destination
can be accepted by Lambda but rejected when Logs creates the group.

Default streams use `YYYY/MM/DD/[<version>]<environment-guid>`; custom-group
streams use `YYYY/MM/DD/<function-name>[<version>][<environment-guid>]` so shared
groups retain function identity. `AWS_LAMBDA_LOG_GROUP_NAME` and
`AWS_LAMBDA_LOG_STREAM_NAME` identify the selected deployment's actual destination
and environment stream; a warm environment retains its stream.

The official Python 3.12 and Node.js 22 runtime loggers own JSON formatting,
request IDs, timestamps, Python extras and Node object/error serialization.
`AWS_LAMBDA_LOG_FORMAT` and `AWS_LAMBDA_LOG_LEVEL` are supplied by the deployment.
The published RIC framed-log protocol uses a dedicated descriptor and owned FIFO,
never magic-byte detection in customer stdout/stderr. Application thresholds
apply to framed severity and raw JSON `level` fields; ordinary text is INFO.
Already-JSON output is not double encoded. Text retains the existing byte stream.
Custom runtimes must implement their logging methods or emit structured stdout;
stackd does not invent JSON wrappers for unsupported logging libraries.

System JSON uses the Telemetry `time`/`type`/`record` envelope and AWS's documented
event-level mapping. INFO emits start/report; DEBUG additionally includes
successful init/runtime completion; WARN retains unsuccessful completion and
dropped-log events. Legacy `platform.end` is not a JSON system event. Runtime
version identifiers are not fabricated from Docker image names.
CloudWatch filtering does not filter the independently subscribed platform
Telemetry stream or relabel extension stdout as function output.

Owned native captures from 2026-09-22:
[`logging replacement`](../testdata/aws/lambda_logging_replacement.json) and
[`structured output`](../testdata/aws/lambda_structured_logging.json) retain
requests, Python/Node sources, Logs events, version snapshots and verified cleanup.
They establish two differences from generic documentation: raw JSON ERROR logs
without timestamps remain ERROR, and setting Python's logger to DEBUG does not
bypass the platform ERROR threshold. The first capture reset its destination and
therefore lacks JSON delivery evidence; the second explicitly retained its owned
destination. Neither capture establishes arbitrary custom-runtime log conventions.

`TestLambdaStructuredLoggingDockerSDK` uses the captured handlers with actual
official images, threshold updates, qualified snapshots and SQLite restart.
`TestLoggingCandidatePromotionAndPublicationSurviveSQLiteReopen` covers rollback
and slot isolation. Focused SDK checks passed with the official Python/Node images.
An actual executable smoke invoked Python before and after configuration changes,
reopened SQLite twice, and verified application/system thresholds and immutable
published-version logging through retained CloudWatch Logs events.

The existing resource-limited PID 1 helper owns separate stdout/stderr FIFOs and
the published Python/Node RIC frame descriptor. The private telemetry bridge
consumes their output synchronously; the same consumer sends full records to the
Logs writer and retains the bounded invocation tail. Runtime readiness and phase
completion drain a finite kernel-readable byte snapshot, not a sleep, injected
customer marker, file spool or subscriber-delivery acknowledgement. Background
writers cannot turn that snapshot into an unbounded drain. The path also works
with a remote Docker daemon and does not assume a shared host filesystem.
Lambda supplies native group/stream environment variables and execution-role
credentials for Logs, including `lambda:SourceFunctionArn` conditions. Deletion
kills/reaps customer processes, drains their output and closes the writer without
deleting the Logs group.

`TestLambdaRuntimeLogDeliverySDK` exercises real runtime output on memory/SQLite,
allowed/denied roles, service timestamps, UTF-8 output larger than the Invoke tail,
warm stream identity and exact emitted-byte preservation through deletion.
[Logs](logs.md) owns the ingestion contract and remaining delivery boundaries.

### Invoke log tails

[`invocation_tails.json`](../testdata/aws/lambda/invocation_tails.json) retains
75 native SDK calls using actual Python 3.12 and Node.js 22 functions, their source,
decoded/base64 output, independently queried CloudWatch events and absence checks
for both functions, their log groups and the uniquely owned IAM role. The capture
covers cold/warm execution, Text/JSON, source/backend filtering, Unicode overflow,
handler exceptions, two-second timeouts and recovery, `None`/`Tail`, asynchronous
acceptance and Node response-stream completion.

- Text returns the last 4096 **bytes**, then replaces each invalid UTF-8 byte.
  Cutting a four-byte emoji therefore yielded valid decoded tails of 4098,
  4100 and 4102 bytes. This is not a 4096-character limit.
- JSON keeps whole records within the byte window, including raw stdout records.
  An oversized record evicts preceding records but is not returned as partial
  JSON. The captured 8.8-KiB Unicode records left shorter tails containing following
  records; full records remained independently visible in CloudWatch.
- Tail captures actual runtime output **before backend application/system
  severity filtering**. Python's explicit DEBUG logger override remained in Tail
  under ERROR/WARN configuration while CloudWatch filtered it. Node's RIC filters
  console calls at their source, so suppressed calls appear in neither destination.
  JSON Tail also retains `platform.start`/`platform.runtimeDone` at WARN.
- Complete records belong to the active invocation; cold initialization is
  included only in that invocation and reset initialization in the recovery call.
  Ordinary stdout/stderr still use native line framing: an unterminated Python
  stdout fragment was absent from its first Tail and joined the next invocation's
  line. Node's raw stdout fragment remained separate from framed console output.
  It was absent from later invocation tails, including the timeout that reset its
  process, but appeared as an unfinished record in CloudWatch. Pipe close flushes
  that fragment to full-log consumers without attributing it to the active tail.
  This is an observed framing boundary, not previous completed-record leakage.
- Buffered `None` and asynchronous `Event` calls returned no LogResult.
  Streaming Tail was delivered on `InvokeComplete`, after post-`stream.end`
  handler output and the phase REPORT. Streaming `None` omitted it. Handler
  errors and timeouts retained actual preceding output and terminal records;
  recovery did not repeat completed records from the failed invocation.
- Existing extension lifecycle/failure fixtures establish inclusion of owned
  initialization and participating-extension output through phase completion.
  Tail does not wait for independently subscribed Telemetry delivery.

`TestInvocationTailNativeByteBoundaries` reconstructs overflow from the native
source and retained terminal records. `TestLambdaInvocationTailsNativeSDK` replays
meaningful lifecycle boundaries through official containers; pipe regressions
cover an immediate response after large output, warm isolation and unfinished
lines. These are bounded regressions, not a universal cross-stream ordering or
CloudWatch-delivery latency guarantee. Output written concurrently by detached
background tasks can fall on either side of the finite collection boundary.
Published RIC framing specifies message length, type and timestamp, but no
invocation flush marker; arbitrary custom runtime buffering is not inferred.

The native-tail SDK replay and affected structured/configuration logging,
extension lifecycle/stream framing, response-stream and full-log delivery checks
passed with the official runtime containers. Actual AWS CLI invocations exercised
both Python and Node Text/JSON cold, warm, exception, timeout, recovery and `None`
paths. Their Unicode tails included the captured 4098/4102-byte repair behavior;
full CloudWatch records remained intact and backend filtering stayed independent
from Tail. Runtime collector tests also passed under the race detector.

Primary reference:
[custom log groups, stream names and execution-role permissions](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-loggroups.html).
Structured controls follow [log formats](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-logformat.html),
[level mapping](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-log-level.html),
the [Python RIC sink](https://github.com/aws/aws-lambda-python-runtime-interface-client/blob/main/awslambdaric/bootstrap.py)
and [Node RIC logger](https://github.com/aws/aws-lambda-nodejs-runtime-interface-client/blob/main/src/LogPatch.js).

## Durable execution

Durable state stores SDK checkpoints, operation transitions, callbacks and
execution history, not a suspended customer process. A committed checkpoint
prevents replaying its completed effect; an interrupted external effect without
that checkpoint remains at-least-once. Typed memory/SQLite storage retains
execution claims, retry times, checkpoint tokens and encrypted payload envelopes.
The three-process storage proof reopens those records rather than rebuilding
them from an in-memory workflow.

The [native durable workflow](../testdata/aws/lambda/durable_audit_final_workflow.json)
uses the real Python durable SDK, SQS effects and a customer-managed KMS key.
It records callback success/failure, heartbeats, stop, repeated named invocation
and current KMS authorization. `GetDurableExecution` includes execution data by
default; `GetDurableExecutionHistory` omits it unless
`IncludeExecutionData=true`, retaining `Truncated=true` wrappers. Metadata-only
reads do not require decrypting customer payloads; requesting execution data
checks current KMS authority.
The [signed wire replay](../testdata/integration/lambda_durable_kms_http_status.json)
also verifies `KMSAccessDeniedException` with Lambda's modeled HTTP 502 for
payload reads, rather than forwarding KMS's upstream HTTP 400. The native
workflow established the error codes and inclusion defaults; its recorder did
not capture HTTP status. The status expectation comes from the
[Lambda error contract](https://docs.aws.amazon.com/lambda/latest/api/API_GetDurableExecution.html#API_GetDurableExecution_Errors),
and the retained before/after local captures show the corrected wire behavior.

`scripts/aws/lambda_durable_executable_smoke.py` exercised the real durable SDK
inside the installed Lambda runtime with signed APIs and SQS, both
[without](../testdata/integration/lambda_durable_runtime.json) and
[with a customer-managed key](../testdata/integration/lambda_durable_cmk_runtime.json).
Each run completed restart, callback-failure and
stop scenarios, verified external effects and checkpoint tokens, and observed
actual request-correlated data audit events. The CMK run inspected 79 encrypted
stored scalars and proved that a caller denied KMS decryption could still read
metadata-only history but not explicitly included payload data. Both controller
restarts and shutdowns exited cleanly; function, queue and IAM cleanup completed,
and exact function-owned runtime containers and volumes were absent. The local
CMK was disabled and scheduled for deletion.
These workflows use Python 3.13 and `aws-durable-execution-sdk-python` 2.0.1;
the smoke takes an explicit installed `--sdk-directory`, not a vendored or
download-on-invocation SDK. Other language SDKs and orchestration combinations
are not implied by this coverage. Durable response streaming is explicitly
rejected rather than converted to a buffered success.

The [native audit capture](../testdata/aws/lambda/durable_audit_final.json)
classifies checkpoint/state and callback/stop requests as data events. Stop and
callback failure use the unqualified function resource plus the qualified
`additionalEventData.functionVersion`; protected customer error data is hidden.
Transactional local regressions verify that rejected commits roll back both
durable state and audit events. Native probe functions, roles, queue, trail,
bucket and log groups were removed. KMS keys remain disabled and pending AWS's
minimum deletion dates: `163b62c2-b5bb-471d-bb36-6bba6e0f582e` until
2026-10-05T10:15:04.749Z and `eb0b1da5-3dad-4601-b333-7fec212ad81a` until
2026-10-05T10:47:49.918Z.

## Code signing and the local Signer authority

The code-signing configuration, attachment, listing and tagging APIs retain
typed state. `Warn`/`Enforce` admission applies to real function ZIPs and retained
layer bytes, with current publisher, expiry and revocation checks. Function and
layer responses preserve the signing profile-version and signing-job metadata.
Creation also evaluates the `lambda:CodeSigningConfigArn` IAM condition before
cryptographic work and again inside the committing transaction. Policy changes
cannot race an already-checked artifact into a different admission decision.

The Signer service performs real S3-versioned ZIP signing with retained
account/Region-scoped profiles and jobs. Lambda verifies detached native CMS
signatures using SHA-384/ECDSA-P384 and explicit trusted roots; local signatures
use the authoritative local Signer root and current retained revocation state.
An unknown imported AWS job does not become non-revoked merely because its
signature is cryptographically valid. No ambient native AWS credentials or
unconditional revocation fallback are used.

The signature authenticates AWS's canonical ZIP content, not every byte of its
compression/container representation. Native canonicalization has a documented
name/content concatenation ambiguity; recompression and ZIP timestamp changes
are not universally signature failures. Other algorithms, partitions and root
rotation require an explicitly supported authority rather than system-root
guessing. Cross-account Signer profile grants, non-Lambda signing platforms and
`SignPayload` remain explicit unsupported paths.

`testdata/lambda/code_signing_executable.json` records signed SDK controls and
actual local Signer/S3 ZIPs, Python execution and signed-layer imports producing
six verified SQS effects. Controller restart retained configuration, tags and
attachments. Revoked/expired artifacts were rejected under `Enforce` and ran
under `Warn`; CloudWatch recorded eleven `SignatureValidationErrors`, and
CloudTrail recorded the calibrated `VALID`, `MISMATCH`, `REVOKED` and `EXPIRED`
outcomes. Exact function/layer/configuration and native runtime cleanup completed.
Native fixture families cover actual AWS Signer/Lambda behavior; AWS's immutable
cancelled/revoked profile versions and signing-job histories are retained because
the native service provides no deletion operation.

## Remaining boundaries

Alexa permission paths, ECR packages and customer-key code encryption, source
profiles and customer-key filter-encryption combinations beyond those documented
above, managed-instance combinations outside the bounded profile, API Gateway
streaming integration, SnapStart, function VPC/EFS integrations, function
scaling-rate limits and remaining runtime/host-platform coverage remain open.
Broader causal execution tracing remains open beyond the authenticated
active-runtime attribution above.
Non-concurrency initialization/permission
destination/DLQ failures and encrypted-destination depth remain open beyond the
paths above. Qualified versions/aliases are implemented within the documented ZIP
and runtime boundary, not service-wide parity; retry-enabled deletion terminal
behavior and case-distinct IAM tag-condition precedence remain unresolved.
Function URLs implement the scoped control/HTTP path above, not every URL transport,
authorization, regional or observability boundary; raw-header casing and bounded
empty-stream/data-delivery observations remain explicit limitations.
AWS configuration/tag propagation and trail/metric
delivery have no exact local timing guarantee.
AWS `$LATEST` code updates invalidate its environments. Warm containers
freeze/thaw; opt-in development-directory reload is described above.

The [temporary-storage contract](#temporary-storage-and-crash-recovery) documents
disk quotas, namespace-owned recovery, host prerequisites and pre-cutover resource
limits. Its native/executable evidence supersedes the old tmpfs limitation.
Startup failure/error-code fidelity, credential-refresh coverage outside the
measured managed warm-worker path, configurable account quotas and broad
negative-case conformance remain open.
