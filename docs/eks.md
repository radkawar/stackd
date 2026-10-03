# EKS Kubernetes kernel

EKS owns typed, partition/account/Region-scoped cluster and access intent. A real
Kubernetes runtime owns workloads. The full SDK-derived EKS target remains open;
registered operations in [services.json](services.json) are **partial**, not a
claim of complete EKS behavior. EKS and EKS Auth wire contracts are generated from
the pinned AWS SDK Smithy checkout. The EKS Auth provider resolves pod-bound
credentials through the current EKS, IAM and STS owners, not fixed credentials.

## Explicit runtime selection

The built-in adapter requires operator-installed **k3d v5.8.3**, Docker, and the
exact images pinned in [`compute/eks/versions.go`](../compute/eks/versions.go).
The supported Kubernetes minors are `1.32` and `1.33`; other versions are
rejected rather than relabeling a different engine. The adapter does not install
binaries or use ambient kubeconfig, Docker contexts, Docker TLS environment,
or `DOCKER_HOST`.

The `1.33` control plane uses k3s `v1.33.5+k3s1`. Real addon deletion exposed
the previous patch's upstream lasso nil-cache panic and native restart loop.
The [upstream fix](https://github.com/rancher/lasso/commit/6f565c15d73bf26022eec04c31c7361aaf02aff5)
ships in the [1.33 backport](https://github.com/k3s-io/k3s/pull/12885).
The [retained-cluster recovery](../testdata/integration/eks_native_deletion_panic_recovery.json)
replaced the owned server binary, observed the actual new `/version` and passing
`/readyz`, and completed the original DaemonSet deletion without bypassing
finalizers. Independently imported CUSTOM worker images retain their actual
release version; the controller patch does not relabel their binaries.

```sh
stackd -listen 0.0.0.0:4566 -database /owned/state.db \
  -docker-host unix:///var/run/docker.sock \
  -eks-state-directory /owned/kubernetes \
  -eks-k3d /path/to/k3d-v5.8.3 \
  -eks-listen-host 127.0.0.1 -eks-endpoint-host 127.0.0.1
```

The runtime directory and SQLite database must be retained together. Each cluster
has a random incarnation, daemon-bound private ownership manifest, private native
admin kubeconfig and stable TLS proxy certificate/endpoint. Directories are
0700; private files are 0600. Ownership checks require retained random labels and
exact native IDs, not a matching name. Shutdown closes controller listeners but
preserves Kubernetes. Restart reattaches the same native server, pod UIDs and
workloads. Delete removes only owned containers, Docker network, image volume and
known files; unexpected files or foreign native objects are preserved and produce
an error. Interrupted deletion cannot recreate the cluster.

There is one **agentless k3s control-plane server** and one separate local k3s
worker, without k3d's load-balancer container or Traefik. Only the worker
registers a Kubernetes Node and runs Deployments, Services and pods. This
bootstrap worker is not AWS-managed EC2 capacity: it creates no fictional EC2
instance or managed node-group record. Its image and kubelet remain at the
cluster's initial version when the control plane upgrades.

The server entrypoint runs k3d's initialization hooks and then executes k3s
directly, without k3d's worker cordon/drain lifecycle. Its
`--egress-selector-mode=cluster` uses agent tunnels for Kubernetes service,
webhook and kubelet connections. Managed-worker overlay publication belongs to
the separate worker, not the control-plane container.

With `-eks-worker-advertise-host`, the native API server advertises that address
and its published port to agents. Advertising its Docker-private address instead
lets a guest join initially but breaks its supervisor tunnel when k3s discovers
the private endpoint. Direct kubelet HTTPS clients, including metrics-server,
use separate exact-peer TCP 10250 admission; `kubectl exec` uses the agent tunnel.
The [retained-guest recovery](../testdata/integration/eks_managed_workers_supervisor_recovery.json)
records the failed tunnel and restored exec; the
[fresh-create proof](../testdata/integration/eks_fresh_native_transport.json)
exercises the compiled creation arguments and an actual pod, then deletes its
owned API and native resources.

Managed-worker network reconciliation completes transmit checksums in software
on the owned bootstrap worker's VXLAN interface before host NAT. The retained
[packet failure](../testdata/integration/eks_managed_workers_retained_packet_failure.json)
showed guest UDP checksum rejection despite correct VNI, routes and permissive
AWS packet policy. This matches the upstream
[encapsulated-checksum NAT defect](https://lists.openwall.net/linux-kernel/2026/09/22/622).
Software generation restored cross-node HTTP without disabling receive checksum
validation or changing security-group, NACL, anti-spoof or NAT enforcement.
Outer UDP offload remains available; a pre-completion TAP capture alone is not
evidence of checksum failure. Guest rejection counters and successful workload
delivery distinguish real corruption from ordinary offload placeholders.

Security-group mutations commit before the EC2 observer applies native packet
policy. The [convergence proof](../testdata/integration/eks_managed_workers_sg_convergence.json)
records an initial allowed request under the old rule, then a fresh request
timing out with four packets counted by the new deny rule, followed by restored
HTTP delivery. Probes require bounded convergence and a remote workload timeout,
not an arbitrary Kubernetes control-plane error.

Nodegroup service-linked-role usage checks and IAM deletion share a writable
transaction, so the resource set cannot change between the check and deletion.
The [persisted failure/recovery workflow](../testdata/integration/eks_service_role_deletion_recovery.json)
exposed a read-only callback that left deletion `IN_PROGRESS`. Recovery now reaches
a terminal result. Active service sessions still prevent deletion, as required by
[IAM's deletion contract](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteServiceLinkedRole.html);
the isolated cleanup advanced service time beyond their recorded expiry and
submitted fresh tasks rather than reviving a failed task or bypassing the check.

Retained mixed server/worker clusters from the earlier runtime must be recreated;
recovery refuses to silently drain or upgrade their data plane. Exact-owned
deletion remains available. External kubeconfig adoption remains unsupported;
having `$HOME/.kube/config` confers no ownership or access.

### Fargate execution ownership

The EKS repository callback is authoritative for current Fargate selectors and
profile identity. Live service authorization owns ACTIVE/deletion state,
execution-role trust and immutable role-identity checks. Admission and native
reconciliation consume those owners; there are no signed policy ConfigMaps,
HMAC policy replicas or parallel compatibility paths.

Only currently eligible ACTIVE profiles participate in admission selection.
CREATING, DELETING and denied profiles cannot shadow an eligible match;
explicitly naming an ineligible profile does not bypass that boundary.

Profile admission enforces the AWS defaults of ten profiles per cluster and five
label pairs per selector. The profile count is checked in the same transaction
as creation; a rejected request does not consume a slot, and token replay does
not consume another slot at capacity. AWS's
[quota contract](https://docs.aws.amazon.com/general/latest/gr/eks.html#limits_eks)
and [read-only native quota capture](../testdata/aws/eks/fargate_default_quotas.json)
identify both as adjustable quotas. This implementation currently uses their
defaults, not account-specific approved increases.
The [actual CLI admission workflow](../testdata/integration/eks_admission_boundaries.json)
verified six-label rejection without state, five-label acceptance, exactly one
winner among two requests competing for the tenth profile, and replay at capacity.
It also exercised all four absent Pod Identity condition keys and the three
documented tag-condition families using real IAM users and policies.

The [preserved partial executable workflow](../testdata/integration/eks_depth_before_control_fix.json)
observed two distinct 61-byte native worker names, real isolated workloads,
current-role trust enforcement, restart retention, and profile deletion draining
pods and removing their native nodes. It also observed all five CloudWatch
control-plane log streams and the mapped IAM identity in a real audit event
before the later control-plane upgrade failure.

### Managed worker ownership

Managed node groups use the existing Auto Scaling, launch-template, EC2 and
network owners. Workers must boot real imported images and join Kubernetes before
they satisfy readiness; an instance record alone is not capacity. Configure the
QEMU/KVM backend, a guest-reachable HTTPS controller endpoint and
`-eks-worker-advertise-host`, then supply `-eks-node-images`: a JSON object keyed
by Kubernetes minor, with `imageId`, `releaseVersion` and `amiType` for each
operator-imported image. `scripts/eks_worker_image.py` prepares the image and
`scripts/eks_managed_workers_smoke.py` exercises its signed EBS import and public
image mapping. The controller does not silently fetch or substitute an image.

Worker preparation preserves digest-qualified references in additional OCI
archives, not just their tags, so containerd can resolve pinned Pod images
without a registry. It stages private archive copies and leaves inputs unchanged.
A [newly prepared guest](../testdata/integration/eks_fresh_worker_digest_images.json)
ran the pinned official Pod Identity agent and AWS CLI with `imagePullPolicy:
Never`, resolving their recorded registry digests without manual guest imports.
That check proves offline image consumption, not credential exchange.
Actual official-agent credential exchanges on another newly prepared 1.33 worker
are recorded in the [paired runtime profile](../testdata/integration/eks_pod_identity_timeout_profile.json).

Rollouts reserve eviction batches on existing worker rows before issuing
evictions. Absolute `maxUnavailable` and ceiling-rounded percentages bound
rollout-induced unavailability across restart. DEFAULT waits for the full Ready
surge, including replacement coverage in each occupied Availability Zone, before
cordoning old workers. It restores capacity one ASG slot at a time, waiting for
the remaining members to be Ready before the next reduction. MINIMAL first
cordons all old workers and excludes them from external load balancers, then
retires them within its availability budget before launching replacements.
PodDisruptionBudgets govern eviction; force changes that contract, not whether a
replacement is really ready. Native `unschedulable` is an observation, not a
second eviction-reservation authority.

Bootstrap deadlines belong to requested capacity and individual new workers,
not the entire update. Each worker retains its bootstrap start across batches
and controller recovery. Eviction has its own fifteen-minute deadline, followed
by the sixty-second termination delay, following the
[AWS update phases](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-update-behavior.html).
The [retained rollout chronology](../testdata/integration/eks_managed_workers_rollout_deadline_recovery.json)
and [independent failure](../testdata/integration/eks_clean_minor_upgrade_before_deadline_fix.json)
exposed the former whole-update deadline; failed update records remain failed.
The [fresh corrected workflow](../testdata/integration/eks_clean_minor_upgrade.json)
reached `Successful` for both control-plane and managed-worker 1.32→1.33 updates,
preserved the application during the control upgrade, then verified real HTTP
from its replacement pod on a different EC2 instance and node UID. All resources
owned by that workflow were removed.

The [DEFAULT continuation](../testdata/integration/eks_managed_workers_default_rollout.json)
completed a multi-batch update in 1,830.475 seconds without changing service time
or deadlines. Two PDB-blocked workers retained their reservations across a
controller restart. The live ASG baseline of desired 3 / maximum 5 in two
Availability Zones became 7 / 9 during the surge and returned to 3 / 5. Observed
Ready, InService, nonretiring capacity never fell below three; actual workload
HTTP passed before and after, not continuously. The earlier
[premature scale-down failure](../testdata/integration/eks_managed_workers_before_scale_down_readiness_fix.json)
remains recorded as a failure.

The [MINIMAL continuation and cleanup](../testdata/integration/eks_managed_workers_completion.json)
completed the original update without replay. All three old node incarnations
were cordoned before eviction; two UID-fenced reservations survived restart and
real PDB rejection. Native drain intervals establish at most two overlapping
evictions, with at least one Ready, InService, nonretiring worker. Three
replacement workers became Ready and served cross-node HTTP. The
[failed observer](../testdata/integration/eks_managed_workers_minimal_observer_failure.json)
had incorrectly counted completed ASG terminations as active evictions; its
failure and missing aggregate 429 samples remain explicit, not reconstructed.
The [phase-clock witness](../testdata/integration/eks_managed_workers_phase_clocks.json)
records timely individual bootstraps even for workers requested more than
fifteen minutes after update admission. Final cleanup removed the owned workers,
control plane, network resources and private state; only subsequent service-role
session cleanup advanced service time.

### Pod Identity

The official agent calls the generated EKS Auth endpoint. Admission and credential
refresh use the current cluster incarnation, association, worker and pod-bound
identity. ACTIVE and UPDATING clusters remain available; unavailable/deleting
lookup fails closed rather than admitting a pod without configured credentials.
An absent association remains distinct from unavailable lookup.
The [native admission-outage proof](../testdata/integration/eks_pod_identity_admission_outage.json)
created association-backed pods before and after a controller restart. While
the controller was terminated and native Kubernetes remained ready, the actual
`podidentity.stackd.eks` webhook rejected creation; no unmutated pod was admitted.
These pods exercise admission only, separately from the running official-agent
credential workflow. The owned cluster, association, roles and network resources
were removed.

The managed agent receives the endpoint's mounted CA through `SSL_CERT_FILE`.
The [official v0.1.37 client](https://github.com/aws/eks-pod-identity-agent/blob/d4dc0f3fedd795b26ac88755238867a2110c7460/internal/cloud/eksauth/service.go)
replaces the SDK HTTP client, discarding roots configured by `AWS_CA_BUNDLE`;
its replacement transport uses Go's system trust roots. The
[retained-worker diagnosis](../testdata/integration/eks_pod_identity_agent_ca_recovery.json)
observed working pod-to-agent and host-to-IMDS transport, then an upstream
`x509: certificate signed by unknown authority` failure. Replacing the environment
variable and rolling the official agent produced an authenticated EKS Auth
`ResourceNotFoundException` for a deliberately unassociated pod. TLS verification
remained enabled; this proves the trust-root repair, not a successful credential
exchange.

Use an ordinary production build for the official-agent latency gate and run
focused race checks separately. The pinned agent gives each upstream HTTP
attempt one second; the pinned AWS CLI container provider uses two seconds per
attempt. The [paired diagnostic profile](../testdata/integration/eks_pod_identity_timeout_profile.json)
observed an upstream cancellation under race instrumentation, while the same
three credential scenarios completed one exchange each with an ordinary build
and unchanged client deadlines. The authorization boundaries below were exercised
separately by the
[strict official-agent workflow](../testdata/integration/eks_pod_identity_strict_completion.json),
not by treating transport failures as denials.

Association creation supplies the documented request-tag and cluster-resource-tag
authorization context, not invented namespace, service-account or role-ARN
condition keys. The
[EKS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_eks.html)
lists `aws:RequestTag/${TagKey}`, `aws:ResourceTag/${TagKey}` and `aws:TagKeys` for
this action. `iam:PassRole` remains a separate authorization decision.

Tagged sessions require both `sts:AssumeRole` and `sts:TagSession`, with
`aws:RequestTag` context for `eks-cluster-arn`, `eks-cluster-name`,
`kubernetes-namespace`, `kubernetes-service-account`, `kubernetes-pod-name` and
`kubernetes-pod-uid`. Disabling session tags removes those tags and their
TagSession requirement. STS remains authoritative for target-role chaining and
current trust; EKS does not introduce a separate credential authority.

The strict workflow exercises namespace isolation, current node authority,
request-tag trust, source and transitive `sts:TagSession`, disabled tags,
session-policy intersection, token audience/binding, deleted pod/service-account
identities, role replacement, current target trust and association deletion.
Existing-pod refresh and new-pod admission were both bracketed by an actual
cluster `UPDATING` state.

IAM authority commands use native repository attempts, and EKS Auth rolls back
the complete exchange when target-role assumption fails. The real target
TagSession denial now returns `AccessDeniedException` through the official agent,
retains the rejected STS outcome after rollback, and leaves neither issued
credentials nor successful STS outcomes for the rejected sessions. Retained
successful-session controls distinguish this from cleanup erasing all records.
The captured pre-metadata-fix EKS Auth rows retain their empty event source and
the child rows' absent parent event IDs; the evidence does not invent either.

The SDK model omits EKS Auth's CloudTrail source. The existing model-correction
input supplies `eks-auth.amazonaws.com` from the
[AWS event-routing reference](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-eks-auth.html);
the generated catalog remains authoritative at runtime. The
[actual CLI delivery proof](../testdata/integration/eks_auth_event_source.json)
records the missing source before regeneration, then source-filtered CloudTrail
history and an `aws.eks-auth` rule delivering the rejected call to SQS. A separate
owned manual timeline verifies the same API's record in the trail's S3 gzip log
after its five-minute batch deadline. Both workflows removed their resources;
the earlier one-minute S3 probe window was too short, not a delivery failure.

### IAM roles for service accounts

IRSA uses the real Kubernetes service-account signer, not emulator-issued JWTs.
Each cluster incarnation advertises its scoped EKS-shaped OIDC issuer through
`DescribeCluster`. Public discovery and `/keys` expose that native issuer's
metadata and current signing keys. Unknown or deleted owned issuers fail locally;
they never fall back to a network request to AWS.

Annotate a Kubernetes service account with `eks.amazonaws.com/role-arn`, create
an IAM OIDC provider for the advertised issuer, and grant the role's trust policy
the intended `sub` and `aud`. Admission installs the projected token and ordinary
AWS SDK environment variables. Audience, token-expiration, regional-endpoint and
container-skip annotations follow the retained native admission cases. Existing
credential environment variables are preserved; an eligible Pod Identity
association takes precedence. IAM provider creation without supplied thumbprints
uses the actual configured frontend TLS certificate chain.

The existing STS federation evaluator verifies the real signature, issuer,
audience and expiry, then applies current provider and role trust. Revoking trust
denies a fresh exchange; it does not retroactively invalidate an already issued
session. Deleting a pod does not revoke its otherwise-valid JWT. Retained clusters
adopt the EKS issuer without replacing their signing key or rejecting their
previous native issuer. Controller restart and native control-plane upgrade
preserve issuer identity, keys and running workloads.

The [native AWS capture](../testdata/aws/eks/irsa_native.json) covers 27 admission
cases, public discovery, host-side Kubernetes TokenRequest-to-STS exchanges and
rejection boundaries.
Its [cleanup record](../testdata/aws/eks/irsa_native_lifecycle_success.json)
retains exact-owned cluster, IAM and network cleanup. The
[fresh-cluster proof](../testdata/integration/eks_irsa_runtime.json) and
[retained-cluster proof](../testdata/integration/eks_irsa_retained_runtime.json)
run the unmodified AWS CLI inside real pods, send and receive actual SQS messages,
exercise permission/trust/provider denial, and remove their owned resources.
The fresh workflow also advances Kubernetes 1.32 to 1.33 without replacing the pod.
Earlier failed attempts remain in those fixtures; these are successful
continuations, not uninterrupted initial runs.

Namespace cleanup exposed the packaged metrics server scraping the worker's
VXLAN-only external address as a kubelet endpoint. Native runtime reconciliation
now changes that package-owned default to prefer InternalIP, without taking
customer-owned arguments. Both workflows recover real node CPU/memory metrics,
delete the stuck namespace, restart the native server, and prove metrics and
new namespace deletion still work. Seven-day signing-key rotation and retirement
of expired verification keys remain explicitly unimplemented.

### Add-ons and control-plane logs

Public CoreDNS releases use AWS names such as `v1.12.3-eksbuild.1` and
`v1.12.1-eksbuild.2`; their installed upstream image versions are separate.
CoreDNS and Pod Identity resources use Kubernetes server-side field ownership.
NONE rejects conflicts, PRESERVE retains externally owned fields with
resource-version fencing, and OVERWRITE deliberately takes ownership. Failed
restoration terminates the update with its original and rollback diagnosis;
the five-minute local readiness deadline is not a claim about AWS timing.
The [native failure-boundary workflow](../testdata/integration/eks_addon_failure_boundaries.json)
verified modeled busy deletion without changing SQL or native objects. An actual
unschedulable rollout followed by an untolerated-taint restoration failure reached
terminal `UPDATE_FAILED`/`Failed`, retained both diagnoses and update parameters,
and did not claim the prior deployment had been restored. Advancing service time
another six minutes left that terminal state unchanged.

CoreDNS scheduling failures belong to the observed Deployment generation and its
current, UID-owned ReplicaSet. Deleting pods and superseded revisions cannot
terminate the current rollback. The
[merged-runtime failure and continuation](../testdata/integration/eks_ram_merge_runtime.json)
captured the previous race: generation 6 was restored while Kubernetes still
reported generation 5 and an old unschedulable pod. After the fix, an explicit
good update recovered the retained cluster; a new bad update failed only for its
own scheduling error and restored generation 8 with two available replicas.
The original failed update stayed unchanged. Remaining native workflow checks
and exact-owned cleanup passed; this was a continuation, not a retroactive
single-pass result.

Native Kubernetes audit admission also feeds
[GuardDuty EKS protection](guardduty.md#native-eks-audit-detection) independently
of CloudWatch logging configuration. The current EKS incarnation supplies AWS
scope; audit admission and findings share its transaction. Audit-ID/stage
deduplication survives restart and includes disabled detection periods.
The security projection retains metadata and effective/actor identities plus
admitted role references and subjects for successful native RBAC binding creates.
The audit policy selects `RequestResponse` for those creates and `Request` for
delete/deletecollection `DeleteOptions`; other operations remain at `Metadata`.
Secret resource bodies are not selected. The security projection keeps effective
delete-option flags, not full object bodies. CloudWatch delivery retains its
original-byte spool and independent cursor, including native RBAC request/response
records and deletion options.

Retained runtime state records the applied audit-policy SHA-256. A missing or
changed hash reloads the policy on the exact-owned control plane: bind-mounted
files are remounted by restarting that container; pre-mount installations receive
updated private copies. The workload agent, container identity, cluster endpoint
and native filesystem are retained. Unchanged policy does not trigger a restart.
The [retained policy workflow](../testdata/integration/guardduty_eks_audit_policy_executable.json)
verified unchanged-policy reattachment and a metadata-only-to-request/response
upgrade on the same server, with both pod UIDs retained and signed SDK findings.

Successful CloudWatch `PutLogEvents` responses acknowledge the batch even when
timestamp rejection information is present. Rejected events are skipped, accepted
events are not replayed, and other streams continue. API failures still propagate.
Logging updates prepare the committed configuration first, reconcile components,
then persist and apply the candidate native mask as the final effect. Persistence
failure leaves the committed mask and offsets authoritative; there is no separate
indefinite rollback phase. Native audit identities include the immutable IAM
principal UID and original caller ARN in `extra.arn`.

The [native logging failure workflow](../testdata/integration/eks_log_failure_boundaries.json)
replayed two unchanged Kubernetes audit events across the fourteen-day timestamp
boundary through the real audit bridge, spool and Logs owner. The accepted event
remained single after collector cycles and controller restart; all five streams
continued. A real checkpoint rename failure produced a terminal failed logging
update without changing `DescribeCluster` or the committed native mask. Restoring
the filesystem allowed successful disable/re-enable and resumed native delivery.
The separate future-timestamp rejection boundary was not exercised in this run.

The corrected managed-worker, official-agent and native control-plane workflows
have separate executable gates below; unit coverage alone does not establish
those runtime outcomes.


## AWS control lifecycle

CreateCluster requires a supported authentication mode and a current same-account
IAM role with `iam:PassRole`, and at least two distinct EC2-owned subnets spanning
two Availability Zones in one VPC. The existing service-role/STS owner checks
`eks.amazonaws.com` trust; the role's current EC2 permissions authorize subnet and
security-group inspection. The k3s CNI does **not** implement those VPCs or security
group packet policy, and private endpoints/public CIDR controls are rejected.

Creation intent, client-token request identity, tags and pending job are committed
before native effects. ACTIVE follows native API readiness, independently of
worker scheduling, not a timer. Native failures retain FAILED plus a health
diagnostic. Delete retains
DELETING until exact native cleanup succeeds; failed cleanup remains retryable.
One cancellable effect owner per cluster runs native work outside the shared
cross-service scheduler drain. In-flight clusters are skipped rather than
busy-polled; completion wakes the retained job source. Shutdown cancels and joins
effects without deleting workloads, and stale generation/incarnation completions
cannot overwrite newer intent.
Deletion protection changes use retained update IDs, InProgress/Successful/Failed
state and DescribeUpdate/ListUpdates. `UpdateClusterVersion` supports the pinned
`1.32` to `1.33` transition. It changes the actual API-server binary while
preserving the endpoint, CA, separate worker kubelets and application containers.
This follows the [AWS separation of control-plane and node upgrades](https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html);
existing Fargate pods likewise keep their node version until replaced.

Create/describe/list/delete, deletion-protection updates, cluster/access-entry
tags, standard access-entry controls, four policy associations and scoped sorted
pagination are implemented. Cluster and entry creation token replays check the
retained request. IAM and resource-tag checks run against current owners in the
command transaction. API completions use the shared journal/CloudTrail producer;
this slice does not invent EKS lifecycle EventBridge events.

Addon and node-group updates retain immutable supplied `Update.params` through
replay and restart. The `ClusterLogging` parameter contains its `clusterLogging`
JSON wrapper. Missing TagResource/UntagResource/ListTagsForResource targets use
modeled `NotFoundException`; a busy DeleteAddon uses `InvalidRequestException`,
not an error absent from that operation's generated contract.
The [signed executable API capture](../testdata/integration/eks_api_errors_versions.json)
observes all three missing-resource tag errors and both public CoreDNS release
names through the actual SQLite-backed HTTP endpoint.

Memory and schema `227_eks_kernel.sql` plus `241_eks_depth.sql` use the same typed
repository contracts. Dedicated columns retain cluster generation/deadline,
immutable IAM identity, access scopes, updates and per-worker drain reservations;
collection JSON contains only typed lists/maps, not
opaque resource documents. Command Attempt savepoints and journal writes share
the transaction domain. Cluster deletion respects its dependent-resource owners;
retained controls do not stand in for native cleanup. SQLite restart and
shared-journal rollback are exercised by the EKS storage tests.

## AWS CLI to authenticated Kubernetes

Use ordinary signed EKS commands, then:

```sh
aws --endpoint-url http://localhost:4566 eks update-kubeconfig --name example
kubectl get nodes
```

The kubeconfig contains the real endpoint/CA and the ordinary `aws eks get-token`
exec credential command. It contains **no permanent admin token or client key**.
The proxy decodes a bounded `k8s-aws-v1` presigned STS GetCallerIdentity request,
checks the official STS endpoint's signing region/partition and signed
`x-k8s-aws-id` cluster binding, then calls the shared gateway's SigV4 verifier and
current credential resolver. It never fetches the token URL. Global, other-region,
FIPS and dual-stack STS signatures are valid independently of cluster Region.
Native EKS token lifetime is fifteen minutes from its signed timestamp even though
AWS CLI signs `X-Amz-Expires=60`; ordinary AWS presigned URL expiry is unchanged.
Inactive/deleted keys, expired sessions/tokens, wrong cluster bindings and
unmatched current principals cannot authenticate. Federated-user sessions do not
inherit their issuing IAM user's access; only actual assumed-role sessions
canonicalize to the issuing role.

Access entries retain IAM user/role IDs, not just reusable ARNs. Deleting and
recreating an IAM identity cannot inherit its old access. Standard entries can
bind cross-account IAM identities explicitly; absent entries never inherit access
from another account or cluster. Direct Kubernetes access is separate from EKS
IAM API permissions: having an entry does not grant DescribeCluster, and denying
DescribeCluster does not independently remove Kubernetes permission.

The adapter impersonates only the authenticated, currently admitted username and
groups through its private native connection. It installs exact-owned ClusterRoles
from the published AWS `AmazonEKSClusterAdminPolicy`, `AmazonEKSAdminPolicy`,
`AmazonEKSEditPolicy` and `AmazonEKSViewPolicy` rules; it does not substitute
Kubernetes aggregate admin/edit/view roles. Policy grants use request-identity and
scope-derived groups. Removing/narrowing a policy stops sending the old group on
new requests even while its inert binding remains. Namespace-scoped RoleBindings
cannot grant cluster-scoped objects. Kubernetes performs real RBAC authorization;
there is no hand-written URL allowlist. Native SAR observes binding readiness
before forwarding a request, without replaying customer writes.

Custom Kubernetes groups also work with ordinary user-created RBAC bindings.
Namespaced policies may precede namespace creation. Custom usernames support
`{{SessionName}}` and `{{SessionNameRaw}}`. Caller impersonation requires explicit
delegation through Kubernetes RBAC; runtime-private groups cannot be specified
in an access entry. Existing long-running streams are not retroactively
reauthorized on every frame.

Authenticator decisions are controller-produced records and use the shared
service clock in both the JSON message and CloudWatch timestamp. The native spool
does not compare them against Kubernetes' wall-clock logging-enable watermark.
Actual Kubernetes audit/component records keep their original native timestamps;
signature freshness and transport deadlines likewise retain their wall-clock
contracts. The [cross-service clock regression](service-consistency.md) exercised
a real k3d denial with a service clock years behind wall time.

## Evidence and open boundaries

- [Owned native control-plane capture](../testdata/aws/eks/depth_native.json) and
  [owned native health capture](../testdata/aws/eks/depth_native_health.json)
  created and deleted isolated AWS clusters, IAM roles, VPCs, subnets and
  EventBridge/SQS capture resources. All recorded cleanup steps succeeded.
  They observed all five control-plane log categories, official pod-identity
  agent installation and an unschedulable CoreDNS add-on becoming `DEGRADED`
  with `InsufficientNumberOfReplicas`. The 180-second and 600-second capture
  windows retained 15 and 13 CloudTrail events respectively after filtering
  message bodies for the exact owned resource prefix. No prefix-attributable
  direct add-on lifecycle payload was retained. Events without that prefix
  cannot be attributed by this capture; neither the filter nor these bounded
  observations establish that AWS emits no such events.
  **TODO: Comeback** implement direct add-on lifecycle notifications when their
  native payload contract is available; the
  [primary event reference](https://docs.aws.amazon.com/eventbridge/latest/ref/events-ref-eks.html)
  supplies event names, not a complete payload schema. No speculative event
  adapter or empty-success publisher is retained.
  Fargate OS maintenance is different: the
  [primary patching guide](https://docs.aws.amazon.com/eks/latest/userguide/fargate-pod-patching.html)
  specifies `EKS Fargate Pod Scheduled Termination`, emitted after a failed patch
  eviction. Its detail includes cluster/profile/pod names, namespace, eviction
  error and scheduled termination time. AWS retries eviction at that time without
  another notification, then periodically deletes pods if eviction still fails.
  That maintenance lifecycle remains unimplemented; ordinary profile deletion
  must not emit a fabricated patch event.
  A [third owned capture](../testdata/aws/eks/addon_degraded_events_native.json)
  observed CoreDNS `v1.14.3-eksbuild.23` on Kubernetes 1.36 becoming `DEGRADED`.
  Its ten-minute capture retained four attributable CloudTrail events but no
  attributable direct event; owned-resource cleanup completed.
  [Read-only native schema queries](../testdata/aws/eks/direct_event_schema_catalog.json)
  likewise found no `aws.eks` direct add-on detail contract in the `aws.events`
  registry in `us-east-1`. The `aws.managedservices` EKS health schemas are a
  different source, not a substitute.
  A [healthy-worker capture](../testdata/aws/eks/addon_healthy_worker_events_native.json)
  then brought an actual `t3.small` managed worker and CoreDNS to ACTIVE,
  completed node-group configuration and add-on updates, and removed the add-on.
  The ten-minute event window retained ten attributable CloudTrail events, still
  no direct payload. Node group, worker role/policies, gateway, cluster and capture
  resources were cleaned. This fixture also records native `Update.params`:
  `LabelsToAdd` is a JSON object, `MaxUnavailable` is a numeric string, and
  `ConfigurationValues` retains the submitted JSON string.
  A [configuration-conflict capture](../testdata/aws/eks/addon_conflict_events_native.json)
  then exercised a genuine `CREATING` → `CREATE_FAILED` transition: an owned
  server-side-apply manager changed CoreDNS's Corefile, and `CreateAddon` with
  `resolveConflicts=NONE` reported `ConfigurationConflict`. This is distinct
  from an unschedulable but installed `DEGRADED` add-on. A five-minute
  post-failure observation plus cleanup retained six attributable CloudTrail
  events and no direct payload. All owned AWS resources were removed; the
  absence remains bounded evidence, not permission to invent the event detail.
- [Native pod-identity agent observation](../testdata/aws/eks/podidentity_native_agent.json)
  maps `v1.3.10-eksbuild.3` to the official `v0.1.37` agent. The health capture
  also distinguishes create-token replay from update-token reuse: a repeated
  update token with changed arguments applied the new arguments. Native
  Fargate profile calibration could not proceed because the account lacked
  `AWSServiceRoleForAmazonEKSForFargate`; no service-linked role was created or
  modified for the capture.
- [Native impersonation observation](../testdata/aws/eks/impersonation_native.json)
  distinguishes delegation from target authorization. An EKS-policy
  administrator whose native groups contained only `system:authenticated`
  successfully delegated to an unknown user; that target was then denied
  namespace access. Caller EKS grants can therefore authorize delegation,
  while the impersonated target receives only its own Kubernetes RBAC grants.
- [Retained local Fargate startup failure](../testdata/integration/eks_fargate_startup_failure.json)
  records the Docker daemon's `sethostname: invalid argument`: the old worker
  name was 76 bytes, beyond Linux's 64-byte hostname limit. Worker names now
  fit within the stricter 63-byte DNS-label limit without truncating pod slots;
  ownership and admission use the same name derivation. The Fargate probe
  retains profile health and native pod/node/events before failure cleanup.
- [Retained local control-plane upgrade failure](../testdata/integration/eks_control_upgrade_failure.json)
  records the original combined server's drain hook deleting a running
  application pod during version cutover. The upgrade workflow now retains
  before/after node versions, pod UIDs, container IDs, restart counts and start
  times, and requires the data plane to remain unchanged while the API version
  advances. Failure captures preserve native pods, nodes and events.
- [Retained chronological delivery failure](../testdata/integration/eks_log_delivery_failure.json)
  identifies an acknowledged 97-event audit frame whose concurrent enqueue order
  crossed a millisecond boundary backwards. The
  [original native frame](../testdata/integration/eks_out_of_order_audit.json)
  is retained unchanged. The CloudWatch boundary stably orders each bounded
  request by its original timestamp; it does not rewrite event messages, alter
  provider time or reorder the on-disk spool. Audit delivery still advances its
  durable byte cursor only after successful delivery. The integration regression
  replays that frame through the real IAM/Logs owners and checks every delivered
  message and timestamp for loss, duplication or alteration.
- [Native/document control fixture](../testdata/aws/eks/control_kernel.json): real
  AWS read-only policy catalog/pagination and absent-cluster error, plus primary
  control/auth references. No paid AWS cluster/node group/load balancer was
  created. These reads do not prove successful AWS cluster lifecycle parity.
- [Exact native management audit](../testdata/aws/eks/management_audit.json):
  read-only catalog pagination and absent-cluster requests matched by response
  request ID. The catalog query limit is a string in CloudTrail; the missing
  cluster record omits `errorMessage` while its API error retains a message.
  `internal/services/eks/audit_test.go` replays the generated inputs, and
  [actual executable before/after observations](../testdata/integration/eks_audit_runtime.json)
  verify both corrections through signed requests and local `LookupEvents`.
  These two read-only cases do not establish other operation projections.
- `internal/services/eks/service_test.go`: official Go SDK generated-REST replay,
  modeled absent-resource error, policy pagination, scoped cursor rejection and
  cross-account tag isolation.
- `internal/gateway/eks_test.go`: official SDK signatures, cached CLI-token lifetime,
  ordinary URL expiry, signed cluster rebinding and expired token rejection.
- `internal/services/eks/kubernetes_test.go`: official SDK-signed global,
  cross-region, FIPS and dual-stack STS tokens, endpoint/partition spoof rejection,
  cluster rebinding and federated-user versus assumed-role identity boundaries.
- `internal/services/eks/lifecycle_test.go`: real CloudWatch alarm deadline
  transition while native cluster readiness is fault-injected as blocked,
  followed by cancellation/join with pending creation intent preserved.
- `compute/eks/k3d_native_test.go`: real native Deployment/pod, authenticated watch
  and exec, AWS policy distinctions, namespace/grant denial, restart identity,
  private credential recovery, wrong-daemon/foreign-incarnation rejection and
  exact-owned cleanup.
- `integration/eks_runtime_smoke.py`: the
  [current actual executable proof](../testdata/integration/eks_review_control.json)
  exercises signed AWS CLI create/update-kubeconfig, running pod and Service
  output, global/regional/FIPS/dual-stack STS tokens, current credentials,
  recreated identities, aws-auth migration, wildcard namespaces and native
  impersonation. Mutable RBAC and revoked access are checked across retained
  SQLite/controller restart. The
  [earlier baseline](../testdata/integration/eks_runtime_workflow.json) remains
  historical evidence.
  Before readiness, pausing the exact-owned k3s server still permits the real
  CloudWatch alarm's scheduled ALARM transition. All five configured
  control-plane log streams reach CloudWatch; mapped IAM audit identities and
  original webhook payloads survive delivery and logging disable/re-enable.
  The separated control server advances from Kubernetes 1.32 to 1.33 while the
  worker remains at 1.32: node UID, pod UID, container ID, restart count and
  container start time remain unchanged, including after controller restart.
  Fargate selectors start two actual isolated workers, leave a nonmatching pod
  on the ordinary worker, enforce current role trust, survive restart and drain
  before native node removal. CoreDNS serves a real cluster DNS lookup; zero
  replicas, failed-rollout restoration, version rollout/restart, configuration
  conflict preservation and native removal are observed. Final cluster deletion
  leaves no owned Docker containers, networks or volumes.
  The review run also checks immutable IAM UID/`extra.arn`, supplied add-on update
  parameters, and NONE/PRESERVE behavior for externally edited Corefile and RBAC
  fields. It first exposed a [CoreDNS recreation failure](../testdata/integration/eks_coredns_recreation_failure.json):
  a partial apply after creation removed the same field manager's immutable
  selector. One complete managed manifest now serves create and reconcile.
  Continuation on the retained cluster reran the full add-on workflow from absent
  native resources, preserved the original application pod UID and Service bytes,
  completed current-identity/revocation checks, and deleted all owned Kubernetes
  resources. This continuation is recorded explicitly, not presented as an
  uninterrupted initial run.
- The [managed-worker pre-diagnostics attempt](../testdata/integration/eks_managed_workers_before_native_diagnostics.json)
  failed while creating the native control plane, before any EC2 worker or Pod
  Identity workflow ran. The original error discarded k3d's diagnosis. Cluster
  deletion succeeded and no owned native Kubernetes containers, networks or
  volumes remained. Cleanup also attempted an inline policy that had never been
  installed on the control role; that `NoSuchEntity` remains in the evidence.

Run the executable proof with an installed pinned k3d binary:

```sh
go build -o /tmp/stackd-eks ./cmd/stackd
python3 integration/eks_runtime_smoke.py --binary /tmp/stackd-eks \
  --k3d /path/to/k3d-v5.8.3 --evidence /tmp/eks-evidence.json
```

**TODO: Comeback** IRSA signing-key rotation, OIDC identity-provider association,
external-cluster adoption, full VPC/CNI and endpoint-policy semantics, encryption,
EKS Auto Mode and additional AWS access policies remain outside this runtime.
Unsupported operations/options return errors. These workflows do not establish
managed-node rollouts, private ECR pulls or Pod Identity runtime verification;
those have separate gates.
Access-entry update token history prevents an old replay from restoring revoked
groups. Exact AWS propagation timing remains open; local control consistency is
not Kubernetes scheduling determinism.

DEFAULT scale-down yields to a concurrent external ASG desired-capacity increase.
ASG owns a counter that advances only when desired capacity increases; EKS
persists the observed counter before its first reduction. Each reduction checks
the group incarnation and counter in the same transaction as the capacity
change. A later increase ends version-update scale-down and adopts the live ASG
minimum, maximum and desired capacity. It does not wait for new external capacity
or outstanding termination hooks; ordinary idle reconciliation retains ownership
of those workers. New version updates capture a new baseline.

The [real autoscaler coordination run](../testdata/integration/eks_autoscaler_scale_down.json)
replaced native EC2/QEMU workers, reached DEFAULT scale-down at desired/max 4/5,
restarted the controller, and submitted a public ASG increase to 5/6. The original
version update completed successfully without restoring its old 1/2 target.
A second restart retained 5/6 through twenty observations; real workload HTTP
still worked. Completion retained an outstanding `Terminating:Wait` worker.
The observed external-increase-to-completion interval was 139 seconds, not a
claim of AWS timing fidelity. Read-only SQLite observations checked the retained
phase; no database writes or clock advances drove the rollout. All owned native
resources and private state were removed. This local implementation evidence
exercises the [documented AWS stop condition](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-update-behavior.html),
not a captured AWS autoscaler experiment.

Operation and wire contracts come from the pinned AWS SDK Smithy models.
Primary AWS references in the fixture and
[AWS access-policy permissions](https://docs.aws.amazon.com/eks/latest/userguide/access-policy-permissions.html)
define semantics. Operation inventory comes from the selected pinned SDK Smithy
models; model membership does not establish Kubernetes execution or AWS parity.
Worker capacity must execute real workloads through its owning compute service;
ambient kubeconfig selection does not grant resource ownership.
