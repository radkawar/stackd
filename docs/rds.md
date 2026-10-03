# RDS and RDS Data: real PostgreSQL and MySQL

RDS owns scoped database, cluster, writer-member, snapshot, parameter-group,
subnet-group and tag state. PostgreSQL and MySQL own SQL execution, credentials,
transactions and durable database bytes. There is no SQLite SQL substitute,
result synthesizer, automatic AWS forwarding or fallback engine.

The generated frontends use the official AWS SDK Smithy models:
`rds.json` and `rds-data.json`, revision
`113bc91bf12edc3af1d3aba1c70be28494d54c2a`. An ordinary RDS instance does **not**
gain the Aurora Data API, and unsupported encryption or IAM authentication is not
accepted as a metadata-only success.

## Running the native engines

Install the exact upstream images explicitly; stackd does not pull them:

```sh
docker pull postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652
docker pull mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d

go build -o /tmp/stackd-rds ./cmd/stackd
/tmp/stackd-rds -listen 127.0.0.1:4566 \
  -database /tmp/owned-rds.sqlite \
  -docker-host unix:///var/run/docker.sock -rds-runtime \
  -compute-endpoint http://host.docker.internal:4566
```

These pins run PostgreSQL **17.11** and MySQL **8.4.11**. Image provenance is the
upstream `docker-library/repo-info` records for `postgres/remote/17-bookworm.md`
and `mysql/remote/8.4.md`, not an AWS engine release assertion. Explicit
`-rds-postgres-image` and `-rds-mysql-image` overrides must be installed immutable
images implementing the same native layout. `-rds-endpoint-host` supplies the
Docker host address visible to the caller; native ports bind daemon loopback.
The returned address/port is the real PostgreSQL/MySQL TCP endpoint, not an AWS
hostname simulated by an HTTP SQL proxy.

An embedder supplies `Config.RDSRuntime`, normally `engine/rds.NewDocker`, and
owns runtime closure. A stable, unique Docker namespace identifies one
controller's durable native resources. The CLI derives it from the absolute
SQLite path. Do not run two controllers against the same metadata file/namespace
or move the metadata without deliberately preserving native ownership.

Without `-rds-runtime`, metadata-only controls remain available, but database
creation cannot claim a running engine. With SQLite, controller shutdown detaches
from native databases rather than deleting data. Stop/start controls change the
actual process. Database/snapshot deletion removes exact namespace/incarnation
resources; the ephemeral CLI removes its native resources before losing its sole
in-memory metadata owner.

## Ownership and lifecycle

The public `storage/rds` contract has typed memory and SQLC SQLite backends in
the same transaction domain as IAM, KMS, the journal and downstream observation
intents. Incarnations and versions fence stale native completions. Retained
create/start/stop/modify/delete/backup work joins the existing scheduler; external
Docker operations, readiness authentication, counters and SQL never run inside
repository transactions. Availability is published only after native endpoint
readiness, not after a timer or successful container-create call.

The existing protected `AWSServiceRoleForRDS` and IAM session owner supply
legitimate recovery authority. KMS protects retained native bootstrap passwords;
there is no saved user access key, expired caller impersonation or plaintext
password column. This internal credential protection is **not cloud database
storage encryption**. The local Docker daemon and host remain trusted: native
initialization and database files necessarily contain engine credential material.

Clusters modeled as `aurora-postgresql` or `aurora-mysql` require an explicit
writer `CreateDBInstance`, matching the
[AWS cluster creation contract](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBCluster.html).
An empty cluster is not a usable SQL server. Only an eligible writer-backed,
HTTP-enabled cluster can resolve for the Data API. Additional readers, failover,
Multi-AZ and distributed Aurora topology are not fabricated.

Instance classes are modeled control identifiers, not a claim of AWS physical
hardware. Native engine versions are pinned, not silently selected from a
requested unsupported release. Parameter groups retain typed values and apply
methods; supported settings are native server parameters. Subnet-group controls
read real EC2-owned subnet/VPC/AZ records through the RDS role. Native VPC packet
policy is not implemented by a loopback database endpoint, so subnet/security
attachment requests that would imply that protection fail explicitly instead of
returning a fake security-group association.

Local parameter families are `postgres17`, `mysql8.4`,
`aurora-postgresql17` and modeled `aurora-mysql8.4`. Native AWS's
`aurora-mysql8.0` family is not relabeled as the actual upstream MySQL 8.4
engine. Supported dynamic settings on attached groups now use retained,
generation-fenced `immediate` work. PostgreSQL uses
[`ALTER SYSTEM` and configuration reload](https://www.postgresql.org/docs/17/sql-altersystem.html);
MySQL uses [`SET PERSIST`](https://dev.mysql.com/doc/refman/8.4/en/persisted-system-variables.html).
The native durable files preserve these values across engine restarts without
replacing the running process for a dynamic-only change. MySQL session variables
inherit new global defaults on **new connections**; existing sessions retain their
own values. PostgreSQL session overrides likewise remain native SQL behavior.

`pending-reboot` remains separate for both dynamic and static settings. Applying
one immediate setting does not apply another deferred setting. PostgreSQL
`max_connections`/`shared_buffers` and MySQL
`character_set_server`/`collation_server` still require `pending-reboot`.
Unknown names and static/immediate combinations return protocol errors without
partly committing a parameter batch. Native value errors cannot publish an
`in-sync` completion: retained work remains unapplied and the database reports
failure. Native effects and metadata commits are not one atomic transaction.
An edit to a stopped database does not start it; its next start applies the
retained group. `ResetAllParameters` resets dynamic values live while preserving
static values until restart, following the
[RDS reset contract](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ResetDBParameterGroup.html).

Controllers reattach using active parameter intent, not pending-reboot group
values. Existing native containers created by older versions with dynamic values
in immutable command arguments need one process replacement when first reconciled
into this durable configuration layout. Unattached local groups publish
atomically. AWS's transient asynchronous cluster-group propagation and its
pending-change reset rejection are not simulated with an invented delay.

## Snapshots are genuine offline backups

Snapshots cleanly stop the engine and copy its complete native directory into an
independent durable snapshot volume. MySQL slow shutdown is enforced before the
copy. Completed bytes are published atomically; incomplete work is not a usable
snapshot. Restoration makes a distinct volume containing the actual databases,
roles, schema and data; MySQL receives a new native server UUID. Password changes
and restoration retries observe actual native state instead of overwriting a
successfully restored target's subsequent writes.

**This interrupts client connections.** It is not an online Aurora storage
snapshot, a live-directory copy, point-in-time recovery or a cloud availability
guarantee. Unsupported external tablespaces/symlink layouts fail. The native
basis is [PostgreSQL file-system backups](https://www.postgresql.org/docs/17/backup-file.html)
and [MySQL InnoDB backups](https://dev.mysql.com/doc/refman/8.4/en/innodb-backup.html).

## RDS Data API

`ExecuteStatement`, `BatchExecuteStatement`, `BeginTransaction`,
`CommitTransaction` and `RollbackTransaction` operate on actual native SQL
connections/transactions. Named placeholders are lexically converted to native
bind positions; SQL literals, quoted identifiers, comments, PostgreSQL casts and
dollar quotes are preserved. Parameter values are bound, not interpolated or
used to synthesize query results. Native errors remain database errors.

The result boundary projects native column types, nulls, booleans, integers,
floating-point values, exact decimal strings, blobs, metadata and formatted JSON.
Engine-dependent semantics remain native: PostgreSQL and MySQL do not have the
same SQL grammar, coercion, implicit DDL-commit behavior or error text. Deprecated
`ExecuteSql`, unsupported schema selection, parameter arrays, multidimensional
result arrays and MySQL executable comments fail explicitly rather than change
the SQL meaning.

Each call checks current `rds-data` authority on the actual cluster (including
resource tags), separately retrieves the supplied secret through the existing
Secrets Manager/KMS owner, and authenticates the native database user. A secret's
host/port fields cannot redirect queries. Secret permission never grants cluster
permission, and a cluster ARN never grants secret permission. See
[AWS Data API authorization](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api.access.html).
Account, partition, region, cluster, secret and transaction ownership remain
separate boundaries.

Transactions are native live sessions with three-minute idle and 24-hour hard
limits driven by service time. Concurrent operations on a transaction do not
interleave. Expiry and shutdown cancel native execution and roll back. Controller
restart does not pretend to restore an in-flight database connection: previously
committed writes survive in native storage, while old transaction IDs are invalid
and uncommitted native work is rolled back. A crash around a native commit and
journal recording is not an exactly-once distributed transaction; SQL is not
replayed to manufacture certainty.

## Audit, events and metrics

RDS controls publish management outcomes through the existing source-owned
journal projection. Data API calls publish `Data` records with native resource
type `AWS::RDS::DBCluster`, event source `rdsdataapi.amazonaws.com` and optional
typed event type `Rds Data Service`. The common renderer retains its previous
`AwsApiCall`/`AwsServiceEvent` defaults for every other producer. SQLite retains
the optional type in its own column, not an arbitrary metadata map.

Data SQL/database/schema text is masked, parameter values and SQL results are not
retained, and database error details are sanitized only in audit (not replaced by
fake successful API results). Classification, source, event type and masking are
**documentation-derived**, from the
[AWS Data API CloudTrail guide](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/logging-using-cloudtrail-data-api.html).
Its example is dated 2019; this is not fresh native-success capture evidence.
Data events require actual trail data selectors and S3/Logs delivery; CloudTrail
`LookupEvents` is not a data-event verification mechanism.

Completed real lifecycle transitions admit documented RDS events to EventBridge,
which owns target delivery. Only mapped native event IDs are emitted, not an
invented event for every internal state. The mappings use the
[RDS event catalog](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Events.Messages.html),
[Aurora event catalog](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_Events.Messages.html)
and [documented EventBridge shape](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-cloud-watch-events.html).
CloudWatch receives measured `AWS/RDS` `DatabaseConnections` samples from real
native counters, excluding the monitoring connection. No synthetic CPU, storage
capacity, IOPS or replica lag is published.

## Evidence and remaining boundaries

`testdata/aws/rds/controls.json` is a fresh, request-ID-bearing native capture from
2026-09-26 in the authorized account/region. It contains 35 observations for four
uniquely owned free PostgreSQL/MySQL/Aurora parameter groups, duplicate/invalid
parameter errors, resets, missing resources and Data API missing-cluster
precedence. All four groups were deleted and their absence verified. **Zero
billable database engines were provisioned.** `scripts/aws/rds_controls_probe.py`
reproduces that safe-owned scope; it never mutates default parameter groups or
uses an existing database/secret.
`scripts/aws/rds_controls_replay.py` replays stable compatible cases through
signed official SDK calls against its own CLI. It reports, rather than hiding,
the excluded native Aurora MySQL 8.0 family and timing-dependent pending-change
cluster-group reset observation. These exclusions are compatibility boundaries,
not passing native-conformance cases.

Scoped native engine tests and throwaway executable probes exercised both pinned
engines: authenticated connections, wrong-password rejection, random binary and
UTF-8 data, real rollback, native parameter changes, stop/start, detach/reopen,
password rotation/retry, measured connections, genuine snapshot/independent
restore and exact-owned cleanup. Data API SDK native tests exercise both engine
families, bound values, commit/rollback, native errors, idle/hard limits,
secret/resource denial and shutdown transaction invalidation. These tests do not
establish AWS Aurora engine equivalence.

`TestNativeDynamicParametersPreserveSessionsAndRestart` exercises the actual
PostgreSQL and MySQL drivers under the race detector. A held connection retains
its temporary table while an immediate change takes effect for a new SQL client.
The test then starts the stopped native process directly, without controller
parameter reapplication, and observes the persisted value before testing reset.
During development the real MySQL server rejected quoted numeric `SET PERSIST`
arguments with error 1232; the adapter now emits validated integer expressions
(including conversion of supported binary startup suffixes), not string literals
or a metadata-only successful response.

The 2026-09-28 [signed parameter capture](../testdata/integration/rds_parameters.json)
uses `scripts/aws/rds_parameters_smoke.py` with the actual CLI, SQLite and both
pinned engines, for standalone instances and writer-backed clusters. Native SQL
observed immediate edits, selected resets and reset-all; process IDs/start times
remained unchanged. Deferred static values survived controller replacement
without being applied, then changed on explicit stop/start. Editing a stopped
database did not start it. Rejected unknown/static-immediate batches did not
partly change the SQL setting. Both controller exits were zero and exact-owned
native containers/volumes were absent after API cleanup. This is local engine
evidence, not a new AWS database capture; no billable AWS engines were created.

The [race-enabled CLI capture](../testdata/integration/rds_runtime.json) exercised
both engines through signed SDK requests and their returned native TCP endpoints.
Committed rows, exact decimal/blob/null values and real SQL errors survived
SQLite/controller restart; an unfinished transaction rolled back and its old ID
was rejected. Both standalone and writer-backed cluster snapshots restored
independent native databases. Password rotation rejected the old password.
Current IAM/secret denials, account/region isolation and stopped-cluster denial
were exercised, not inferred from provider registration.

Actual selected S3 gzip logs contained **46 Data records**, including all five
Data API operations, with the custom event type retained across restart and
SQL/values redacted. Management records still used `AwsApiCall`. Native RDS
events reached SQS through EventBridge, and CloudWatch observed a held native
transaction in `DatabaseConnections`. Both persistent-controller exits were
zero; all exact-owned native containers and volumes were absent after API
cleanup. A separate ephemeral-controller proof executed PostgreSQL `SELECT 123`
then shut down without API deletion and observed automatic native cleanup.
The compatible native-control replay matched 26 stable cases and explicitly
reported nine excluded observations described above.

The combined main assembly repeated this workflow after integrating Parameter
Store and renumbering the RDS/event-type migrations to 214/215.
[`rds_main_integration.json`](../testdata/integration/rds_main_integration.json)
records both actual engines, controller restart, independent instance/cluster
restores, current authorization failures, all five Data API operations in 46
delivered records, EventBridge delivery and measured connections. Its exact-owned
Docker containers and volumes were absent after cleanup; no AWS engines were used.
The official AWS SDK for Go v2 (`rds` v1.129.0, `rdsdata` v1.40.1) separately
replayed the 26 stable native control cases through an actual CLI, checking
decoded retained state, modeled errors and request correlation. The same nine
documented native-family/propagation exclusions remain explicit.

The reusable `scripts/aws/rds_executable_smoke.py` runs the complete local CLI
with signed official SDK calls, returned TCP endpoints, SQLite/controller
restart, IAM/secret denial, scope isolation, native snapshots, password changes,
and actual CloudTrail S3/EventBridge SQS/CloudWatch consumers. It requires `boto3`,
the two installed pinned images and an empty owned state directory. It does not
use ambient AWS credentials.

Unsupported cloud capabilities remain explicit errors: Aurora distributed
storage/readers/failover/global databases/serverless scaling, Multi-AZ, managed
storage allocation/IOPS/autoscaling/encryption, engine upgrades, VPC/security-group
packet enforcement, TLS certificate lifecycle, IAM database authentication,
managed-secret rotation, automated backups/PITR/export and the remaining RDS
operations. Upstream PostgreSQL/MySQL is a real local SQL data plane, **not the
Aurora storage service**. No ElastiCache, OpenSearch or MSK implementation is
included in this workstream.

## Intentional gap markers

- `internal/services/rds/service.go`: remaining cloud topology, managed
  storage/networking, automated backup, maintenance, replication, IAM database
  authentication, managed password rotation and proxy owners.
- `internal/services/rds/parameters.go`, `changeParameters`: independently
  visible native cluster-group propagation is not modeled; no invented delay.

The generated unsupported remainder is not implemented behavior. No database
operation is satisfied by a toy SQL parser or a canned query result.
