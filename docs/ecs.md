# ECS controls and task execution

ECS implements cluster/task-definition controls, resource tags, standalone tasks
and replica service controls through generated SDK Smithy contracts. Supported
Linux Fargate tasks and services run real containers; container instances and
other unimplemented branches remain explicit errors, not fabricated execution.
The generated [inventory](services.json) reports registered operations as partial,
not full ECS parity.

Container `secrets` resolve through the actual [Parameter Store](ssm.md) or
Secrets Manager owner with the execution role, never the task role. SSM names,
SSM ARNs, and `/aws/reference/secretsmanager/...` references remain supported.
Direct Secrets Manager ARNs support optional `:json-key:version-stage:version-id`
selectors; stage and version ID are mutually exclusive, and omitted selectors
use `AWSCURRENT`. A selected JSON key must contain a string; missing keys, binary
secrets and non-string JSON values fail initialization explicitly. Full secret
ARNs can select a different Region.

Linux Fargate `environmentFiles` support up to ten `s3` object references per
container, including container overrides. References must be S3 object ARNs
ending in `.env`. Files must be UTF-8, with `VARIABLE=VALUE` assignments and `#`
comments; CRLF and a UTF-8 BOM are accepted. Values preserve spaces, quotes and
literal shell syntax. Blank values are omitted, and malformed assignments and
NUL bytes fail without including file contents in diagnostics. The first file
value wins duplicate names. Explicit container environment values override
files, explicit environment overrides override the definition, and a supplied
override file list replaces the entire definition file list. Existing secret
and reserved runtime-variable precedence remains unchanged.

Both kinds of source resolve only when a native container is created, using
current execution-role S3/SSM/Secrets Manager and KMS authority. Reattaching an
existing container neither refetches sources nor changes its environment.
Updating files or rotating secrets affects newly created tasks. Resolved bytes
are not copied into ECS task state or management audit; they are necessarily
visible to the application and native container inspection. Missing references,
missing JSON keys and current authorization failures stop initialization, with
no task-role fallback. Registry credentials remain unsupported.

Semantics: [S3 environment files](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/use-environment-file.html)
and [Secrets Manager selectors](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html).
The focused SDK admission test is `TestECSEnvironmentFilesSDKAdmission`.
`scripts/aws/ecs_environment_sources_smoke.py` provisions a fresh local SQLite
controller and real Docker tasks, checks printed values, file updates, override
replacement, individual S3/Secrets Manager/KMS denials, missing sources, retained
container identity across restart and plaintext absence in ECS tables/audit:

```sh
python3 scripts/aws/ecs_environment_sources_smoke.py --binary bin/stackd \
  --state-directory /tmp/ecs-sources-UNIQUE --image busybox:1.36
```

The task image and ECS toolkit must already be installed. The script never
contacts native AWS, cleans up its exact-owned resources, and retains the
synthetic-value observations in its state directory's `report.json`.
The retained [local Docker proof](../testdata/integration/ecs_environment_sources.json)
used installed `busybox:1.36.1`: eleven task scenarios verified source precedence,
selectors, updates and initialization failures; restart preserved the same
container/PID under denied execution-role authority. All 17 ECS tables and 483
audit records contained no resolved source markers. Both controllers exited
cleanly and exact-owned cleanup reported no errors. These are local executable
observations, not a native AWS environment-file capture.

## Setup and supported execution

Control-plane-only embedding needs no Docker. Embedders provide
`Config.ECSExecutor` and the shared `Config.ComputeEndpoint`; the CLI's explicit
`-docker-host` constructs both ECS and Lambda executors around one caller-owned
`compute/docker.Client`. `-compute-endpoint` is the AWS API origin reachable from
both kinds of container. A loopback-only listener is not reachable through the
Linux host gateway; use a reachable listener/origin rather than rewriting SDK
resource URLs. Lambda-specific Runtime API callback options remain separate.

ECS requires local rootful Linux Docker without user-namespace remapping, with
systemd and cgroup v2. The pinned `compute/docker.ToolkitImage` and customer
images must already be installed: execution never pulls images or changes daemon
settings. Containerized controllers must share the daemon host's existing
`/run/lock` inode (read-only bind is sufficient); native bridge admission verifies
the daemon-host `/var/run/docker.sock` against the configured Engine identity.
These privileged helper mounts are not exposed to task containers.
The toolkit currently is:

```text
nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61
```

Install images before offline use, then start the shared runtime, for example:

```sh
docker pull nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61
go run ./cmd/stackd -listen 0.0.0.0:4566 -database ./stackd.sqlite \
  -docker-host unix:///var/run/docker.sock
```

Provision a cluster, EC2 VPC/subnet/security groups, applicable IAM roles and an
`awsvpc` task definition with installed images before `RunTask`. Supported tasks
use Linux Fargate platform `1.4.0` (`LATEST` selects it), valid task CPU/memory
combinations and inspected image architectures. Wrong-architecture or unavailable
images are real initialization failures, not simulated successes. Task-wide
CPU/memory limits use an owned native systemd slice containing the task's Docker
scopes. Per-container settings and real task-owned Docker volumes support shared
init/application data; external storage adapters are not implied.

The local empty launch strategy selects **Fargate**, deliberately unlike AWS's
captured default of EC2. Only the supported Fargate capacity provider is executed;
EC2, Spot interruption/capacity and managed-instance lifecycles are not supplied.

## API and retained state

`internal/services/ecs` owns admission, desired task/container state, dependency
gates, public versions/counters, IAM conditions, PassRole and audit projections.
Its typed repositories have coordinated memory and SQLC SQLite implementations.
They retain partition/account/region scope, definition revisions and high-water
marks, immutable admitted task definitions, task state, metadata capabilities,
log cursors, dependency waits and cluster-scoped client-token requests. Tags live
separately from task records. Generated DTO copies preserve nil versus empty
collections and request ordering instead of normalizing away token distinctions.

- `RunTask` admits one to ten tasks against an active definition and cluster,
  checks current caller authority, role admission and supported networking/runtime
  requirements, and commits task intent before external execution. It returns
  accepted task state, not a promise that every container has started.
- Exact client-token replay returns the original tasks with current status and
  tags, including stopped tasks. Changed presence, ordering or identifier spelling
  conflicts with the original task ARNs in `resourceIds`; definition eligibility
  and caller authority are checked before replay. Local token eligibility expires
  at the earlier of 24 service-clock hours after admission or one hour after all
  associated tasks have stopped. This does not erase retained task history.
- `DescribeTasks` accepts up to 100 identifiers, returns `MISSING` failures for
  absent tasks and includes current tags when requested. `ListTasks` paginates
  cluster-scoped desired-status queries (default `RUNNING`) with family,
  launch-type, service-name or exclusive `startedBy` filtering. Instance/daemon
  filters remain unsupported.
- `StopTask` commits desired status `STOPPED` and the user reason; observed
  shutdown and deprovisioning run asynchronously. Its result omits current tags,
  while description and token replay retain them. Stopped tasks cannot be tagged
  through the task-tag API.

Cluster controls retain native settings, capacity-provider strategy, tags and
status transitions. Definition registration allocates revisions transactionally;
a denial cannot consume a revision. Latest-active selection and deregistration's
previous-status distinction remain native-fixture-backed. Deletion admits
eligible revisions into `DELETE_IN_PROGRESS`, then reaps lazily on resource
access after the deletion request and the last active task or service-deployment
reference have each aged one service-clock hour. Tasks and deployments retain
their admitted definition. This is a local asynchronous removal rule, not a claim
about AWS's precise cadence.

## Replica services

`CreateService`, `DescribeServices`, `ListServices`, `UpdateService` and
`DeleteService` support Fargate `REPLICA` services with the ECS `ROLLING`
deployment controller. Admission applies current caller authorization and
PassRole, resolves an immutable definition revision, and retains service inputs,
deployments and event ancestry in typed memory/SQLC repositories. Exact
CreateService token replay does not create a new deployment or replace tags;
conflicting requests preserve the admitted service.
On creation, an omitted availability-zone rebalancing setting defaults to
`DISABLED` when maximum deployment capacity is 100%; explicit `ENABLED` is still
rejected there. Update omission preserves the existing setting.

The scheduler owns task creation, scale-in and replacement after stops, essential
exits or unhealthy observations. Task ownership uses internal service/deployment
fields, not caller-supplied `Group` or `StartedBy`. Scale changes reconcile the
current deployment; definition/network/target-group binding changes and forced
deployment create a new one. Deployment settings constrain minimum healthy and
maximum task counts, readiness, health-check grace, failure thresholds and rollback
to a completed deployment. Without either container or target-group health checks,
readiness waits 40 service seconds after observed `RUNNING`. Engine-resolved
immutable image IDs are retained per deployment for mutable image references,
separately from public image names and registry digests. Exact native
image-resolution retry timing is not established.

Service state, deployment progress, task intent and selected EventBridge service/
deployment events commit together. Docker work stays outside transactions.
Deletion enters `DRAINING`; forced deletion stops running tasks. The local
transition to `INACTIVE` follows one service second after tasks stop, not a
measured AWS cadence. Cluster counters/deletion dependencies, service-filtered
task lists, managed tags and definition retention use the same owned state.

Native `services.json` captures token behavior, defaults, errors, scoped controls,
circuit configuration and real Fargate replacement/scaling. The opt-in
`TestECSNativeReplicaServiceAdmissionAndLifecycle` executes its supported paths
through real Docker on memory and SQLite. A separate CLI/SQLite run preserved a
live container and PID across server restart, replaced a stopped replica, scaled
one → two → zero and rolled two live tasks. Four real exit-42 containers triggered
circuit rollback without replacing the healthy baseline. These observations do
not establish every scheduler race or AWS event emission cadence.

A mutable-image smoke reproduced failed scale-out after retagging an installed
image: a synthesized repository/digest reference no longer existed in Docker.
The corrected owner stores the observed immutable engine ID. Replacement and
scale-out now survive an incompatible retag on both fixture backends and a
SQLite process restart without rewriting the public container image name.

Load balancing supports up to five same-VPC ALB IP target groups for `awsvpc`
services. Each binding must select a defined container and its TCP port mapping;
classic load balancers and advanced traffic-shifting configurations remain
unsupported. An explicit empty `loadBalancers` update removes the bindings in a
new deployment, not from tasks belonging to an older deployment. Schema 228
retains these immutable deployment bindings through SQLite restart, revision
history and rollback.

The consumer-owned target lifecycle uses the current ECS service-linked role.
Only observed `RUNNING` tasks register, with their exact task ARN, attachment,
ENI identity and private IP/port. All bound targets and any required container
health check must become healthy before deployment availability; target failures
respect the health-check grace period and participate in circuit rollback.
Scale-in, replacement, deletion and explicit stops deregister the old task's
targets and wait for confirmed drain before normal process teardown and ENI
release. Target effects and health observations stay outside ECS transactions.

Draining is not an exemption from current EC2 SG/NACL authority. Every drain poll
refreshes the attached runtime's native packet policy, including retries after
target cleanup authorization fails. If current policy cannot be resolved or
installed, ECS immediately stops owned customer processes rather than waiting
for the load balancer or customer shutdown timeout. Stopping-controller recovery
without a policy-capable runtime attachment also fails closed by attaching only
to and stopping retained processes; it does not prepare a replacement runtime.
The ENI remains reserved until target drain completes even in these fail-closed
cases.

Service discovery/Service Connect, VPC Lattice, external/CodeDeploy controllers,
non-rolling strategies, deployment alarms/hooks/traffic shifts and other
unsupported dependencies reject admission. See AWS's
[rolling deployment](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-ecs.html)
and [circuit breaker](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-circuit-breaker.html)
contracts.

### Service revisions

`DescribeServiceRevisions` is an explicit dependency beyond the pinned inventory:
Application Auto Scaling uses it to verify high-resolution monitoring. Revision
ARNs use the numeric suffix of `ecs-svc/` deployment IDs. Active revisions derive
from existing immutable deployment snapshots; reconciliation archives only
snapshots relinquishing task/rollback ownership. Monitoring is revision-specific,
not copied from the latest service configuration.

[`service_revisions.json`](../testdata/aws/ecs/service_revisions.json) captures
the native zero-task configuration and batch boundaries: at most twenty ARNs for
one service, scoped account/region validation, `MISSING` revision failures and
native errors for absent services/clusters. Duplicate existing revisions return
the captured `ServerException`; duplicate missing revisions remain separate
failures. Revisions remain readable while the service is `DRAINING`, reject at
terminal `INACTIVE`, and do not reappear after same-name service recreation.

Readiness calls the authorized, audited `DescribeServices` and
`DescribeServiceRevisions` commands. The primary deployment must be completed
with the requested metric configured at twenty seconds; desired task count zero
does not bypass deployment completion. Revision history survives active-row
replacement and SQLite reopen. The migration cannot reconstruct snapshots pruned
before revision retention was introduced. Public revisions currently omit
observed registry digests; retag-safe engine image IDs are not registry digests.

## Service metrics

Real service tasks publish `AWS/ECS` `CPUUtilization`, `MemoryUtilization` and
`LiveTaskCount` with exact `ClusterName`/`ServiceName` dimensions in the owning
account and region. This uses CloudWatch's existing typed publication boundary,
not customer `PutMetricData` permission or a fabricated API audit record.

The runtime supplies native observation time, cumulative CPU time and
cache-adjusted working-set bytes through `Environment.Usage`. CPU utilization
uses successive native counter/time deltas divided by the task CPU allocation;
advancing service time does not create CPU work. Memory sums whole MiB per
container and divides by the Fargate task memory allocation, not its container
reservation. Values are not clamped to 100%. A fresh/reset CPU baseline omits
that CPU observation rather than manufacturing zero.

Collection runs every 20 service seconds. Default publication combines each
task's observations into one minute statistic set: `SampleCount` counts task
contributors, `Sum` sums their observation averages, and extrema retain actual
task/time minima and maxima. Two stable tasks therefore contribute count 2, not
6. Configured 20-second CPU/memory publication contributes count 2 per bucket
and count 6 to a complete minute rollup. `LiveTaskCount` remains one minute
gauge, with sample count 1, independently of utilization resolution. An empty
service emits none of these metrics; previously published history remains.

`monitoring.metricConfigurations` selects 20- or 60-second resolution separately
for CPU and memory. Changing the complete list creates a deployment; identical,
omitted or null configuration preserves it. An empty list resets defaults.
Create accepts an empty object, while Update's empty object returns the captured
native `ServerException`. Empty metric-name lists are accepted through an
evidence-backed Smithy correction; missing names, unsupported names, duplicate
names and other resolutions reject admission. The configuration belongs to the
immutable deployment, so old and new tasks retain their own resolution during
rollout. `DescribeServiceRevisions` exposes these immutable monitoring snapshots;
they are not invented as a field on the public Service response.

External counter reads happen outside transactions. Accepted observations are
assigned to service-time windows after those reads finish: a slow response
cannot reopen an already-published window. Typed pending task/window statistics
and collection deadlines survive SQLite restart; publication into CloudWatch
and removal of the pending group share one transaction. Service deletion does
not cascade pending samples. Native CPU baselines stay process-local, and
restart or a large clock advance does not backfill unobserved workload history.

`service_metrics.json` records bounded native Fargate Linux 1.4 observations:
one/two equal-sized tasks, actual allocated memory and busy CPU, metadata
counters, minute/high-resolution statistics, zero-task windows, monitoring
admission and deployment changes. Whole-MiB working sets of 107 and 203 over a
512-MiB task produced 20.8984375% and 39.6484375%, despite a 256-MiB container
reservation. AWS's [utilization guide](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_utilization.html)
and [high-resolution guide](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/target-tracking-faster-auto-scaling.html)
describe aggregation and defaults. The fixture also pins the public ECS agent
reference to `cfabccdd207f5a703125a8c2fc60de8136298888`; that code is not assumed
to be Fargate's implementation.

Local real-container CLI checks exercised default, high, mixed CPU20/memory60
and reset publication; retained deployment/runtime recovery; account/region
isolation; scale-to-zero without new samples; and CPU → CloudWatch alarm →
authorized SNS → SQS delivery, followed by missing-data recovery. The lifecycle
regression delays an actual Engine observation across a closed window: it fails
with pre-read timestamp assignment and passes with commit-time assignment on
memory and SQLite. Native running emission covered both metrics at 60 and 20;
mixed/reset native probes established admission/readback, not running emission.
Multi-container and heterogeneous-size aggregation, EC2/Container Insights and
filesystem/Service Connect metrics remain outside this evidence or producer
boundary. Native owned tasks, networking, logs and roles were removed;
task-definition deletion remained `DELETE_IN_PROGRESS`.


## Application Auto Scaling

The generated Application Auto Scaling frontend owns ECS
`service/cluster/service` targets with dimension `ecs:service:DesiredCount`.
Targets, tags, schedules, policies and scaling activities retain
partition/account/region scope through typed memory and SQLC repositories.
Deleting an ECS service removes its scaling target and owned alarms; recreating
the service name does not recover the old scaling authority.

ECS owns actual task execution. Application Auto Scaling accepts desired-capacity
changes through the same ECS command used by SDK callers, then observes real
running capacity to complete an activity and start its policy cooldown. Step
policies support change, exact and percentage adjustments, interval boundaries,
minimum adjustment magnitude and cooldown credit. Larger scale-outs retain the
capacity already credited within the active cooldown. Dynamic scale-in is
suppressed during ECS deployments; scale-out remains eligible unless suspended.

Target tracking supports CPU/memory predefined metrics, their explicit
high-resolution variants, ALB request count, custom metrics and supported
CloudWatch metric math.
CloudWatch owns query validation, alarm evaluation and delivery. Standard alarms
use 60-second periods with three high and fifteen low evaluations;
high-resolution alarms use 20-second periods with three high and thirty low
evaluations. The corresponding ECS monitoring must be fully enabled. Merely
changing ECS monitoring does not rewrite an existing policy's alarm contract.
Explicit policy updates preserve policy identity and creation time, but replace
managed alarm identities. `DisableScaleIn` creates only the high alarm.

`ALBRequestCountPerTarget` uses real retained `AWS/ApplicationELB`
`RequestCountPerTarget` samples: `Sum`, 60 seconds, unit `None`, and the
`LoadBalancer`/`TargetGroup` dimensions from its resource label. Admission checks
the current ECS service's target-group binding under current service-linked-role
authority. Native admission accepts a well-shaped missing load-balancer component
when the target group is actually attached; this does not manufacture metric data.
High alarms use three periods at the target; low alarms use fifteen periods at
90% of the target. Real HTTP traffic, restart-retained request observations,
managed alarms, scale-out to two healthy replicas and idle scale-in to actual
`STOPPED`/ENI retirement are captured in
`testdata/integration/alb_metrics_scaling_workflow.json`. See the
[ALB source contract](behavior-references.md#request-metrics-and-ecs-target-tracking)
for denominators, idle/empty-target behavior, native calibration and remaining
distributed-health limits.

Metric ownership is per target, not per policy name or target value. Scalar
custom specifications and sole `MetricStat` queries share the same primitive
identity: namespace, metric name, statistic and unordered dimensions. Units,
query IDs and nonempty labels do not distinguish that identity, including
cross-representation writes in either creation order. Empty query labels are
rejected before changing a policy or its alarms.

Multi-query specifications ignore outer query order but retain exact IDs,
expression text, labels, unit presence/value and nested dimension order.
Omitted `ReturnData` defaults to true at admission. Standard and high-resolution
CPU specifications remain distinct. Native
[`metric_identity_followup.json`](../testdata/aws/applicationautoscaling/metric_identity_followup.json)
and [`identity_edges.json`](../testdata/aws/applicationautoscaling/identity_edges.json)
retain the pairwise comparisons and rejected-write snapshots; SDK replay covers
both stores and SQLite reopen. CLI checks also preserve the existing policy and
alarm configurations after rejected creates and updates. Custom-period probes
were rejected by the native account's capability gate; those fields are absent
from the public Smithy request shapes and are not replayed as stripped requests.

Default list pages contain at most ten policies or fifty targets/schedules.
Continuation identifies the next unreturned key and survives SQLite reopen,
replay and deletion of that key; it does not require a token ledger or signing
key. Tokens bind operation, partition, account, region and filter membership,
not `MaxResults`. Named-policy traversal follows the caller's name order, with
duplicates using their first position. Reordering the same names can therefore
change the page resumed from an existing token.

Native [`continuation.json`](../testdata/aws/applicationautoscaling/continuation.json),
[`wide_pages.json`](../testdata/aws/applicationautoscaling/wide_pages.json) and
[`policy_page_boundaries.json`](../testdata/aws/applicationautoscaling/policy_page_boundaries.json)
capture the nonstandard explicit-limit behavior. Policy `MaxResults=10`
returns ten rows without a token; 11, 20 and 50 still return at most ten but
continue when more remain. Captured smaller continuation pages truncate without
another token. Changing an unfiltered policy token to a nonempty `PolicyNames`
filter consistently returned `InternalServiceException`, including existing,
missing and all-owned name selections. Initial target limits 1/2 over the
53-target native population returned empty pages with tokens; that unexplained
case remains unmodeled rather than becoming a population-specific branch.

Scale-in requires agreement from every scale-in-enabled target-tracking policy;
the largest required capacity wins. Current metric queries, not a stale alarm
transition reason, supply peer-policy measurements. Missing observations are
not zero. CloudWatch repeats scaling actions while an alarm remains `ALARM`,
using fresh delivery data without replacing the retained transition reason.
Native action captures require lowercase `recentDatapoints` and a fresh
`queryDate`; `evaluatedDatapoints` alone is insufficient. The current ten-second
freshness cutoff lies between an accepted 5.743-second observation and a rejected
15.603-second observation; it is not a measured exact AWS limit.

Scheduled `at`, `rate` and supported cron/timezone expressions use deterministic
service time. Suspended occurrences are not replayed on resumption. A scheduled
bound change and pending resource activity share one transaction. The subsequent
ECS command commits with its activity's `InProgress` transition, before external
container execution. A permanent rejected occurrence rolls back its effects,
retains a failed activity, consumes that occurrence and reports through the
scheduler error boundary, leaving later work runnable.
The common job boundary logs the rejected job key, due time and error before
returning it, including when the automatic worker owns the drain.

IAM remains enforced independently for each authority. Native forwarded ECS
probes may be denied without denying registration; a separately assumed
`AWSServiceRoleForApplicationAutoScaling_ECSService` verifies resource access.
Managed alarm writes/deletes likewise use the native linked-role fallback when
caller CloudWatch permission is denied. This never grants the caller direct ECS
or CloudWatch access. Scaling API audit uses native
`autoscaling.amazonaws.com` with `additionalEventData.service` equal to
`application-autoscaling`; child commands retain their own identities and outcomes.

[`testdata/aws/applicationautoscaling`](../testdata/aws/applicationautoscaling)
retains controls, scaling, permission, alarm, metric-math, high-resolution,
metric-identity, policy-name and real scale-in evidence. Native idle Fargate CPU
observations completed a high-resolution target-tracking change from two tasks
to one before cleanup. Local CLI/Docker checks exercised scheduled zero-to-one,
percentage step scaling up/down, actual CPU-driven target tracking, multi-policy
scale-in veto, suspended scheduling/dynamic actions, fresh unchanged-state alarm
repeats, and same-container/PID SQLite restart. Denied caller probes and successful
service-role alarm commands both appeared in local CloudTrail history.

Post-fix CLI checks held two real tasks during a stalled deployment and resumed
two-to-one scale-in after completion. Cooldown escalation completed
`1 → 2 → 3`, survived a SQLite process restart and stayed at three on the repeated
larger signal. A rejected one-sided scheduled bound left no partial minimum,
allowed the later maximum update, and produced one focused job-error log.
High-resolution policy admission rejected absent and unfinished monitoring,
then succeeded after actual rollout completion; a duplicate metric specification
preserved the existing policy. A genuinely retired revision also survived the
CLI SQLite restart. All owned local containers, targets, alarms, services,
networking, user credentials and linked roles were removed after verification.

Follow-up CLI checks retained seventeen policies and eight managed alarms across
a process restart, consumed policy pages `10 + 3` and target/schedule pages
`50 + 3`, and reused all three token families after another restart. Reordered
policy names selected the measured pending-name traversal; foreign accounts and
regions could not consume the tokens. Deleting the pending policy left exactly
the two surviving records on continuation. All fifty-three zero-capacity
services/targets, schedules, policies, alarms, networking and linked roles were
removed after those checks; no task was started by this follow-up.

### Scaling activity history

`DescribeScalingActivities` reads the same activity records that own accepted
capacity work and completed-policy cooldowns. A new resource change is retained
as `Pending`; execution and its ECS API event commit with `InProgress`.
Actual running capacity produces `Successful`. An external desired-count change
produces `Overridden`, retaining the original ID, start, cause and description.
Terminal command rejection produces `Failed` without a partial ECS mutation.
A scheduled bound update has its own completed activity and, when necessary,
a separate pending resource activity. Updating target bounds is not a claim that
containers have reached the requested capacity.

History survives target, policy and ECS resource deletion and SQLite restart.
The public query exposes the documented six-week window, newest start first;
repository insertion order resolves equal service-time instants. Continuations
are inclusive next-unreturned positions and bind scope, namespace and resource.
Native tokens permit changes to dimension and `IncludeNotScaledActivities`.
Default pages contain fifty rows with continuation; explicit limits up to fifty
truncate without another token, larger limits return at most fifty with
continuation, and zero/negative limits return empty results.

Captured max/min no-ops are `Failed`; exact-current no-ops are `Successful`.
All carry `NotScaledReasons`, omit end time/status message, and are hidden unless
`IncludeNotScaledActivities` is true. Exact-current reasons report desired
capacity, not running capacity. Repeated reasons retain the first activity,
including across policy changes and target deregistration/recreation.

[`activity_lifecycle.json`](../testdata/aws/applicationautoscaling/activity_lifecycle.json)
and [`activity_suppression.json`](../testdata/aws/applicationautoscaling/activity_suppression.json)
retain native histories, scoped pagination and cleanup evidence. SDK replay
covers both stores, placement-gated real execution, overrides, zero fulfillment,
scheduled bounds, suppressed reasons and reopened history/tokens. It does not
manufacture AWS's concurrent pending-update conflicts or duplicate retry counts.
The domain fixture covers accepted `Pending` intent before execution and recovery.
Native positive-capacity success and `Unfulfilled` timing were not established:
an independent capacity-starved activity remained `InProgress` after 1,801.6
seconds, with no end time. No timeout is inferred from the enum.

Actual CLI/SQLite checks kept a scale-out `InProgress` while its image was
unavailable, then completed the original activity after a real container ran.
A second unfinished scale-out and a rejected scheduled bound survived process
restart; an external zero update changed the original activity to `Overridden`.
Real CloudWatch actions produced a deduplicated exact-current no-op. Regional
isolation, history after target/service/cluster deletion and expiry after six
service weeks were also exercised. Six weeks comes from AWS's
[activity history contract](https://docs.aws.amazon.com/autoscaling/application/userguide/application-auto-scaling-scaling-activities.html),
not a six-week native probe.

This remains an ECS-backed slice, not complete Application Auto Scaling parity.
Other resource namespaces, predictive scaling and forecasts remain explicit
unsupported boundaries. Native `Unfulfilled` behavior remains unestablished.
Primary contracts are AWS's
[ECS scaling guide](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-auto-scaling.html),
[step scaling](https://docs.aws.amazon.com/autoscaling/application/userguide/step-scaling-policy-overview.html),
[target tracking](https://docs.aws.amazon.com/autoscaling/application/userguide/target-tracking-scaling-policy-overview.html)
and [scheduled scaling](https://docs.aws.amazon.com/autoscaling/application/userguide/scheduled-scaling-policy-overview.html).

## Runtime ownership, dependencies and recovery

`compute/ecs` owns actual Docker containers, task network namespaces, native
limits, volumes, packet rules, metadata listeners, logs and statistics. It reports
observed readiness, health, exits and attachment facts; it does not own ECS
lifecycle policy. The shared Docker client owns Engine transport only, and does
not merge Lambda invocation state with the ECS task state machine. Container
operations, socket binding and streaming happen outside resource transactions.

Container dependencies gate first start using actual `START`, `COMPLETE`,
`SUCCESS` and `HEALTHY` observations. A failed `SUCCESS` dependency stops the task
without starting its dependent; prepared-but-never-started containers may still
have native runtime IDs and image digests, but no exit code. Essential exits drive
standalone task stopping. Task health aggregates health-checked essential
containers; unchecked essential containers do not prevent healthy aggregation.
An unhealthy observation after a `HEALTHY` startup gate does not replace or stop a
standalone task as an ECS service scheduler might. Shutdown reverses the dependency
graph, stopping independent leaves concurrently with each container's stop timeout.

Service shutdown detaches controllers/listeners, leaving live ECS customer
processes for reattachment; it is not `StopTask`. With SQLite and the same Docker
host, startup resolves retained tasks against native ownership labels and
configuration, rebinds their metadata callback and resumes observation/log reads.
There is no second Docker resource registry. A process restart has preserved native
container IDs, PID and `StartedAt`; this does not establish host/daemon restart,
callback-port reassignment or arbitrary native-resource corruption recovery.

Provider-native removal discovers owned resources even after partial preparation.
Customer containers are removed before their namespace anchor, policy, task slice
and volumes; shared network release respects its remaining ownership. Native
removal precedes EC2 address reuse. ENI release, terminal task state and its state
event commit together. Failed external effects are not a successful cleanup claim.

## EC2 attachments and packet enforcement

EC2 owns retained requester-managed task ENIs, private and automatic public IPv4
reservations, attachment dependencies and network policy. The integration enters EC2 under the
ECS service-linked role, not the deploying caller's borrowed EC2 authority.
Attachment facts are exposed through ECS and EC2, and managed-interface mutation
restrictions remain enforced. Docker uses the allocated private IPv4/MAC rather
than inventing an unrelated task address.

Current SG/NACL policy is applied through native nftables outside the customer
namespace. Host-side veth guards enforce source identity and link-local isolation;
bridge hooks provide stateful security-group connection tracking. Ordered,
stateless NACL checks precede tracked-flow acceptance. The same-subnet bypass
excludes public DNAT, including host-local ingress and its return path.
The scoped metadata callback has an explicit exception. Policy replacement is one
native transaction; a failed replacement does not intentionally remove the old
rules. These mechanisms are narrower than a complete VPC data plane.

`assignPublicIp=ENABLED` now acquires a real automatic address from EC2's shared
owner; the ENI association exposes that address. The native packet path uses the
same owned public `/32`, inbound DNAT, return mapping and source enforcement as
QEMU guests. It requires both a current assignment and an active EC2 IGW route,
plus current SG/NACL admission; an IGW route alone does not enable public egress.
`StopTask` removes the native mapping before releasing its ENI/reservation.
Requester-managed ownership rejects customer EIP remaps of a live task ENI.
Public-address transitions preserve unrelated established private connections.
Native admission rejects intersecting public assignments and private bridge
pools in either creation order rather than allowing global DNAT to steal a
later private destination.
Native bridge, TAP, packet-policy and container identities use AWS resource
identity, not controller database isolation. Bridge reuse validates the current
pool and gateway before attaching. Independent controller databases on one
Engine must not reuse AWS resource identities: choose account, region and ID
seed explicitly and use nonoverlapping host pools. Overlapping host CIDRs are
not isolated VPC networking; true per-emulator native isolation remains backlog
across all native identities, not a bridge-only namespace.
See [public IPv4 execution and evidence](ec2.md#public-ipv4-and-elastic-ips).

Native policy recovery stages the current authoritative attachment policy before
public quarantine, atomically upgrading retained pre-public-network tables rather
than flushing chains they never had. The first schema-224-to-225 upgrade failed
this boundary and the runtime terminated its receiver; that negative observation
remains in `testdata/ec2/public_network_legacy_upgrade.json`. A separate live
legacy-rules regression keeps the same process and private TCP connection while
its new public route becomes reachable. It does not claim the already-removed
original receiver survived, or substitute container reprovisioning for recovery.

The `198.18.0.0/15` addresses are host-local, not Internet-advertised. External
destinations see the Docker host's routable source. Public mapping needs local
rootful Docker's iptables-nft `DOCKER-USER`/raw chains and the existing native
network toolkit. Arbitrary nonlocal routing, full VPC DNS for tasks and overlapping
Docker bridge CIDRs remain unsupported; default Docker IPAM rejects overlapping
pools even for separately named VPCs. Rootless, remote/Desktop, cgroupfs and
virtual-machine execution are not supported ECS runtime configurations.

## Credentials, logs and state events

Each task namespace exposes `169.254.170.2`. Persisted capabilities and source
checks scope the credentials path and per-container v4 metadata; namespace
separation alone is not credential authorization. `ECS_CONTAINER_METADATA_URI_V4`
provides container/task documents and real Docker container/task stats.
`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` vends expiring IAM-backed task-role
sessions to standard SDK credential providers. Execution-role credentials are
not exposed to customer metadata. `taskWithTags` is explicitly unsupported rather
than bypassing authorized tag APIs.

Task-role SDK requests use ordinary signed API authentication and **current IAM
policy**, not a cached admission grant. Execution-role sessions separately
initialize CloudWatch Logs destinations and authorize writes of actual
stdout/stderr, including final shutdown output. Native log cursors support
continuation after reattachment. This is not native blocking `awslogs` stdout
backpressure: Docker output collection and authorized Logs delivery are separate
boundaries, and full delivery under every failure is not established.

Task-role credentials retain their issuing task-command event in the typed IAM
record. After signature verification, the gateway adds that causal parent without
changing the caller, signed region or policy context. A surviving container's
cached credential therefore keeps its ancestry after SQLite/controller reopen.
No task scan, new token protocol or extra per-request storage lookup is required.
An active Lambda invocation parent still takes precedence for Lambda credentials.

A real Python SDK task froze its credentials, published SQS messages before and
after controller restart, and kept the same access-key ID, native PID and start
time. East-region SQS and west-region STS records retained their `RunTask` parent.
A current IAM denial still rejected publication and retained the authenticated
parent; an invalid signature was rejected. This establishes direct task-role SDK
ancestry, not inferred provenance for other credential-issuance flows.

Admission checks native-evidenced `ecs-tasks.amazonaws.com` trust with the literal
regional/account `task/*` source context. Runtime credential vending currently
uses the task ARN, but AWS's exact credential-vending `SourceArn` remains
unestablished. Broad-trust STS success does not establish full native trust fidelity
for restrictive source conditions.

Task versions, counters and native-shaped `ECS Task State Change` EventBridge
admissions commit in the same transaction as task state. Target delivery uses
EventBridge's retained work, not an external call inside the task transaction.
API outcomes also enter the shared audit journal. Native control fixtures establish
second-resolution definition audit times and environment-value redaction.
`ecs_targets.json` additionally establishes `AccessDenied` audit naming, command
redaction as `["***REDACTED***"]` in request overrides, and unredacted response
commands. Authorization/missing-resource execution failures omit parameters;
invalid-container `InvalidParameterException` retains sanitized parameters and
`dryrun: false`. `StartTask` remains unsupported.

## Linked-role ownership

Cluster creation attempts `AWSServiceRoleForECS` provisioning through IAM's
authority boundary. An explicit `iam:CreateServiceLinkedRole` denial leaves the
cluster active and role absent; retrying after permission changes can create it.
IAM evaluates the original caller with trusted `aws:ViaAWSService`/`aws:CalledVia`
context. Existing roles do not require creation permission.

Active clusters in every region of the same account/partition, including empty
clusters, block IAM role deletion through ECS's joined transaction interface.
Another account cannot satisfy provisioning or block deletion. Native fixtures
`service_linked_roles.json`, `service_role_forwarding.json` and
`service_linked_role_audit.json` retain fresh-member-account evidence, assumed
caller/session issuer, distinct request IDs and the captured
`aws-called-via-override.ecs.amazonaws.com` audit origin. Best-effort ECS rejection
does not poison the transaction; KMS still rolls back required role creation.

Regional discovery/cache cadence, native automatic role reclamation, global IAM
audit-region routing and noncommercial templates remain incomplete. AWS attempted
duplicate creation on first entry into a second region, unlike the current global
role lookup. AWS still retained the role at the bounded post-cluster-deletion
check; local deletion remains explicit, not invented immediate reclamation.

## Evidence and remaining boundaries

[`testdata/aws/ecs`](../testdata/aws/ecs) retains native controls, corrections,
CloudTrail records and Fargate execution observations. Native captures constrain
the implementation; they are not themselves local execution proof:

- `task_tokens.json` and `task_tags.json` establish exact-request replay,
  conflicts, eligibility-before-replay and mutable task-tag distinctions.
- `task_role_trust.json`, `task_role_source_context.json` and
  `task_role_vending.json` separate admission from runtime credentials. Broad-trust
  tasks obtained STS identities; restrictive source tests could be admitted but
  remain pending without log streams until explicitly stopped. Their runtime
  source ARN and cause of initialization delay remain unresolved.
- `task_dependency_transitions.json` captures failed `SUCCESS`, `HEALTHY`,
  initialization stop, reverse shutdown and standalone-task health behavior.
- `network_interfaces.json` captures real Fargate address consumption,
  requester-managed/in-use state, attachment ownership, mutation denials and
  ECS service-role CloudTrail identity.
- `task_state_change_schema.json` retains AWS's public version-2 schema. It omits
  observed fields including `capacityProviderName`, `enableExecuteCommand` and
  `ephemeralStorage`; it is not a complete event contract.
- The timeout rows in `controls.json` establish registration's explicit lower
  bound of two seconds. Fargate rejects `stopTimeout` above 120; EC2 accepts 121.
  AWS accepted Fargate `startTimeout: 121` despite the documented range; that
  admission result does not establish runtime handling above 120 seconds.

Actual local CLI execution has exercised an init/`SUCCESS` shared-volume task,
v4 task/stats, Python boto3 task-role STS/SQS, live IAM denial, stdout/stderr and
final SIGTERM logs, EventBridge-to-SQS transitions, identical native IDs/PID/
`StartedAt` through a SQLite process restart, exit code 7 and ENI cleanup.
The opt-in `TestECSRuntimeDockerSDK` passed memory/SQLite success,
failed-dependency, exited-`HEALTHY`-provider and wrong-architecture cases, including
modeled conflict task identities after reopen. The real Docker Lambda regression
passed with the shared transport. These are bounded results, not full-suite claims.

Recovery smoke reproduced stale security-group authority while Logs startup was
denied: the old executable still allowed new TCP connections after egress removal.
The corrected executable denied those connections both during retries and after
Logs recovered. A stopped metadata anchor also reproduced an indefinitely
`STOPPING` task; existing-only native process control now delivered SIGTERM,
retained exit code 7 and final Logs output, and removed owned containers, volumes,
network and ENI without requiring metadata readiness. Inclusive log timestamp
resumption may replay the last entry; it does not promise exactly-once delivery.

A retained SQLite CLI run also admitted definition deletion, reopened under
manual service time beyond the one-hour retention window, and observed the
definition disappear while its stopped task remained describable. Registering
the same family allocated revision 2 rather than reusing revision 1.

Earlier CLI control checks covered SQLite restart, revisions/tags,
deregistration/deletion admission, latest-active fallback, audit redaction,
linked-role denial/retry and forwarded IAM outcomes, KMS rollback, and east/west
cluster role-deletion dependencies. Native probes stopped their owned tasks and
removed clusters, roles, logs and networking resources. Definition deletion was
observed in progress, not claimed physically complete.

Remaining execution gaps include:

- Container-instance and EC2 instance execution, `StartTask`, `ExecuteCommand`,
  unsupported service dependencies described above, and remaining placement/
  capacity/account-setting branches.
- Private-registry credentials, FireLens, external or configured-at-launch
  volumes, accelerators, Windows, shared process namespaces,
  restart policies and unsupported host/Linux/container options. Registration of
  a modeled definition does not imply executable support for every field.
- Enforced task-wide disk quota: AWS's default 20 GiB quota is **not enforced**;
  local default storage fields are omitted, and custom quota requests are rejected
  at execution admission.
  Docker accepting a storage option did not prevent writes beyond its size in
  the retained mechanism experiment.
- Native blocking `awslogs` backpressure, the exact role credential-vending
  source context, and the network/runtime portability and recovery boundaries
  described above.

The strategy remains containers only, with no in-process or virtual-machine
fallback and no fidelity labels on AWS responses. CloudTrail Lake remains outside
the behavioral target, while its modeled operations remain known and honestly
unsupported. AWS semantics come from retained captures and the
[Amazon ECS API reference](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/Welcome.html).
