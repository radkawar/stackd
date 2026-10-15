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
The empty control resource reports `available` but has no SQL endpoint. Its native
writer first reports `creating`, then publishes an authenticated real endpoint.
Controller startup does not create a native process for a memberless cluster.
Only an eligible writer-backed, HTTP-enabled cluster can resolve for the Data API.
Additional readers, failover, Multi-AZ and distributed Aurora topology are not fabricated.

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

## Standalone Terraform capacity and username contract

`AllocatedStorage=20` is admitted for native standalone PostgreSQL and MySQL,
retained as typed requested GiB in SQLite, and returned by create/modify/describe.
Fresh standalone creation requires an explicit capacity; missing/zero values fail.
Manual snapshots preserve it and restores inherit it. Pre-migration databases
retain unknown capacity. Explicit requests use general-purpose **20–65536 GiB** bounds in
the [CreateDBInstance API](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html).
These bounds do not enable magnetic/provisioned-IOPS storage profiles.

This is **control-plane capacity metadata, not capacity enforcement**. Native
bytes reside in an ordinary, independently owned Docker volume on the daemon
host's filesystem. No requested GiB are reserved, quota-limited, preallocated or
resized, and no synthetic free-space/capacity metric proves otherwise. The host's
actual filesystem space and native SQL errors remain the physical boundary.
`StorageType`, positive IOPS, throughput, autoscaling and encryption requests still
fail explicitly; zero IOPS means no provisioned-IOPS request. It is accepted because
the pinned provider sends `Iops=0` when growing an instance without a storage profile.

Immediate capacity increases preserve the endpoint/process and committed SQL.
Shrinking is rejected; increases below ten percent are rounded up (integer GiB),
as described by [ModifyDBInstance](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBInstance.html).
Identical capacity is a no-op. A rounded increase exceeding the upper bound fails.
Deferred growth is explicitly rejected: there is no real maintenance-window
scheduler here. Set `apply_immediately=true`; the service does not pretend that a
deferred request has already been applied. Capacity survives controller and engine
restart. Aurora capacity requests remain unsupported.

`lindm_admin` is preserved verbatim and admitted for both supported engines.
The current [API reference](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html)
and [instance settings guide](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateDBInstance.Settings.html)
describe 1–16 ASCII letters/digits/underscores with a leading letter. That is the
local admission bound. AWS documentation is inconsistent: the
[CloudFormation DBInstance reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html#cfn-rds-dbinstance-masterusername)
and older SDK descriptions give PostgreSQL a 63-character maximum. The supplied
successful native AWS PostgreSQL deployment proves underscore admission, **not**
every engine/version length boundary or complete reserved-word parity. PostgreSQL
password lengths remain 8–128; MySQL remains 8–41 (with the existing forbidden
characters retained).

### Provider v6.68.0 call path

The cloned provider (`c9b83d813022cdd05fc955480b07e269c6e18023`) was read directly,
not downgraded or replaced. `internal/service/rds/instance.go`:

- Standalone create requires nonzero `allocated_storage` before calling
  `CreateDBInstance`; it sends capacity, username and explicit disabled controls.
- Creation, refresh and update waiters use `DescribeDBInstances` with
  `dbi-resource-id` after retaining `DbiResourceId`. This filter now matches the
  immutable resource identity within the current account/region, not the mutable
  public name. Flattening reads `AllocatedStorage` and `MasterUsername`.
- Capacity updates send `ModifyDBInstance` plus `ApplyImmediately`, and may send
  zero IOPS when the storage profile is absent. The local service retains the
  rounded capacity and accepts the genuinely disabled IOPS value.
- Destroy calls `DeleteDBInstance`, optionally creates a real final offline
  snapshot, then polls describe until absence. The recipe skips the final
  snapshot so exact-owned engine and data-volume deletion are sufficient.

### Runnable Terraform and psql proof

Use a fresh owned SQLite path and the native CLI/images above. Install Terraform,
provider **6.68.0** and host `psql`; the MySQL client below uses the installed pin.
Save this as `main.tf` in an empty proof directory (the fixture password and Terraform state
are local-only; this is not a production security configuration):

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.68.0"
    }
  }
}
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    rds = "http://127.0.0.1:4566"
    iam = "http://127.0.0.1:4566"
    sts = "http://127.0.0.1:4566"
  }
}
variable "capacity" {
  type    = number
  default = 20
}
resource "aws_db_instance" "proof" {
  for_each = { postgres = "17.11", mysql = "8.4.11" }

  identifier                 = "owned-capacity-proof-${each.key}"
  engine                     = each.key
  engine_version             = each.value
  instance_class             = "db.t3.micro"
  allocated_storage          = var.capacity
  username                   = "lindm_admin"
  password                   = "local-proof-password"
  db_name                    = "proof"
  apply_immediately          = true
  auto_minor_version_upgrade = false
  backup_retention_period    = 0
  storage_encrypted          = false
  publicly_accessible        = false
  skip_final_snapshot        = true
}
output "postgres_host" { value = aws_db_instance.proof["postgres"].address }
output "postgres_port" { value = aws_db_instance.proof["postgres"].port }
output "postgres_resource_id" { value = aws_db_instance.proof["postgres"].resource_id }
output "mysql_host" { value = aws_db_instance.proof["mysql"].address }
output "mysql_port" { value = aws_db_instance.proof["mysql"].port }
output "capacity" {
  value = { for name, db in aws_db_instance.proof : name => db.allocated_storage }
}
```

```sh
terraform init
terraform apply -auto-approve
# Match the absolute SQLite path used by the controller above.
RDS_NAMESPACE="stackd-rds-$(printf '%s' /tmp/owned-rds.sqlite | sha256sum | cut -c1-24)"
POSTGRES_ID="$(terraform output -raw postgres_resource_id)"
POSTGRES_CONTAINER="$(docker ps -q \
  --filter "label=stackd.rds.namespace=$RDS_NAMESPACE" \
  --filter "label=stackd.rds.id=${POSTGRES_ID#db-}" \
  --filter "label=stackd.rds.role=database")"
test -n "$POSTGRES_CONTAINER"
docker cp "$POSTGRES_CONTAINER:/var/lib/postgresql/data/security/ca.pem" ./postgres-ca.pem
export PGSSLROOTCERT="$PWD/postgres-ca.pem"
export PGPASSWORD=local-proof-password
psql "host=$(terraform output -raw postgres_host) port=$(terraform output -raw postgres_port) user=lindm_admin dbname=proof sslmode=verify-full" \
  -v ON_ERROR_STOP=1 <<'SQL'
SELECT current_user, current_setting('server_version');
CREATE TABLE capacity_proof (id integer PRIMARY KEY, note text NOT NULL);
BEGIN;
INSERT INTO capacity_proof VALUES (1, 'committed');
COMMIT;
BEGIN;
INSERT INTO capacity_proof VALUES (2, 'rolled back');
ROLLBACK;
SELECT * FROM capacity_proof;
SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();
SQL
MYSQL_PWD=local-proof-password docker run --rm --network host --env MYSQL_PWD \
  mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d \
  mysql --protocol=TCP --ssl-mode=DISABLED --get-server-public-key \
  --host="$(terraform output -raw mysql_host)" \
  --port="$(terraform output -raw mysql_port)" --user=lindm_admin proof \
  --execute="SELECT CURRENT_USER(), VERSION(); CREATE TABLE capacity_proof (id INTEGER PRIMARY KEY); START TRANSACTION; INSERT INTO capacity_proof VALUES (1); COMMIT; START TRANSACTION; INSERT INTO capacity_proof VALUES (2); ROLLBACK; SELECT * FROM capacity_proof;"
terraform apply -auto-approve -var=capacity=30
terraform plan -detailed-exitcode -var=capacity=30
```

Also repeat a `SELECT 1` with each native client using
`PGPASSWORD=wrong-proof-password` or `MYSQL_PWD=wrong-proof-password`.
Require PostgreSQL's `password authentication failed` or MySQL's
`Access denied for user`, not merely a connection error. Both initial SQL
queries must show only the committed row, not the rolled-back row.
MySQL's [`--get-server-public-key`](https://dev.mysql.com/doc/refman/8.4/en/connection-options.html#option_general_get-server-public-key)
allows the pinned `caching_sha2_password` plugin's full RSA password exchange over
this trusted loopback connection. Without it, a wrong password can fail earlier
with error 2061 (`Authentication requires secure connection`) rather than the
intended 1045 authentication rejection. This is not TLS or verified server identity.

Stop and restart only this owned controller using the same CLI flags, SQLite path
and Docker namespace, then repeat `terraform plan -detailed-exitcode -var=capacity=30` and query the
committed row through the refreshed outputs. Finish with
`terraform destroy -auto-approve -var=capacity=30`; do not prune shared Docker
resources. Both detailed-exitcode plans must exit **0** (`No changes`).
SQL proves real authentication/commit/rollback/durable bytes; Terraform proves
retained requested capacity, not physical capacity allocation.

**Executed local acceptance, 2026-10-14:** Terraform **1.15.9** and AWS provider
**6.68.0** ran this two-engine standalone lifecycle against an owned CLI at
`127.0.0.1:14669` with fresh SQLite state. Provider initialization used the existing
local 6.68.0 mirror and its checksum lock; offline init reported the mirror as
`unauthenticated`, rather than performing a new registry-signature verification.
Apply added both instances with capacity **20** and username `lindm_admin`.
Native `psql` and the pinned MySQL client reported **17.11** and **8.4.11**,
committed row 1 and rolled back row 2. Both engines rejected the wrong password.
The initial MySQL negative check hit error 2061; after the documented public-key
client option was added, it produced the required native **1045** denial.

The growth apply changed both instances to **30**. Refresh/no-op plans before and
after controller restart exited **0**, descriptions retained capacity/username,
and the original endpoints and committed rows survived. Destroy removed both
instances; exact namespace `stackd-rds-cc570d1ed657a3540c9716fa` had no containers
or volumes afterward. All three owned controller exits were **0**; no other
controller was restarted. Commands, stdout/stderr, provider request/response logs,
controller logs and observations are retained under
`.stackd/rds-provider-proof/`, with `report.json`, `main.tf` and the focused
`run.py`/`--resume` runner. No native AWS calls were used. PostgreSQL reported
`pg_stat_ssl=false`; this remains local SQL/capacity-metadata evidence, not TLS,
storage quota enforcement or production RDS security evidence.

The permanent provider6.68.0 workflow is
[`examples/terraform-storage`](../examples/terraform-storage/rds.py).
It starts from fresh Terraform cluster/primary-writer resources, not SDK bootstrap.
It also declares standalone instances, parameter groups, real manual snapshots,
restores and Secrets Manager credentials. Native PostgreSQL/MySQL clients verify
immediate settings, password rotation, retained transactions and snapshot cuts.
The same native Aurora-compatible engines serve real bound RDS Data API
transactions, with native CLI reads as independent consumers.

```sh
python3 examples/terraform-storage/run.py --services rds \
  --provider-mirror /absolute/path/to/provider/mirror
```

The TLS-enabled fixture run completed initial provider creation, native SQL,
Data API, password rejection and PostgreSQL TLS checks. Its ordinary retained
plan returned zero, but the strict refresh-only plan returned exit 2 at the
known Terraform Core boundary. Cleanup completed through the normal fixture
path. This is **not** a full lifecycle pass: later SDK parameter transitions,
updates, imports, snapshots and controller reopen were not reached in that run.
[`rds-limits.json`](../examples/terraform-storage/rds-limits.json) lists exact
prerequisites and resource/settings gaps. Neither this fixture nor registered
API counts establish support for all provider resources.


### PostgreSQL TLS and remaining production security controls

PostgreSQL 17.11 and the Aurora PostgreSQL 17-compatible runtime now use real
TLS 1.2/1.3. Each native database incarnation has a retained local CA and server
certificate for its configured endpoint host. The CA is not an AWS/public trust
root. Export only `security/ca.pem` from the exact-owned container, as above;
never export the server private key. Public trust is retained in typed SQLite
state and supplied to readiness, password, statistics and RDS Data connections.
Internal clients verify the certificate chain and hostname without plaintext
fallback. MySQL transport is unchanged.

`rds.force_ssl` defaults to **1** for both supported version-17 families.
[Native AWS metadata](../testdata/aws/rds/postgres_tls_defaults.json)
reports `ApplyType=dynamic`, `DataType=boolean`, allowed values `0,1`, and
`Source=system`. Default and fresh unattached groups read back
`ApplyMethod=pending-reboot`; the two temporary probe groups were deleted.
Immediate changes update and reload actual PostgreSQL HBA
policy without replacing the process or existing sessions. Explicit
`pending-reboot` changes remain deferred until reboot. Reset restores default 1.
Value 0 permits plaintext clients but leaves verified TLS available; value 1
rejects new plaintext connections. This is an RDS policy translation, not an
invented PostgreSQL GUC. SCRAM password hashing alone does not enforce TLS.

Native tests exercised both engine names, verified TLS 1.2/1.3, wrong CA,
hostname and password rejection, dynamic policy transitions with a retained
session, binary SQL snapshot/restore and independent restored trust. A separate
old-CLI-to-new-CLI upgrade preserved the database's native system identifier,
ARN, resource ID, port and committed binary row while enabling TLS. A second
SQLite/controller reopen retained trust and bytes; normal deletion removed the
owned database container and volume. The earlier `pg_stat_ssl=false` report
remains valid historical evidence, not evidence of the new TLS implementation.

The TLS-enabled API-controls Terraform run also exercised actual PostgreSQL
GraphQL consumers through create, eight imports, update and SQLite/controller
reopen. Ordinary no-change plans returned zero. Its final strict refresh-only
plan hit the same Terraform Core exit-2 boundary despite a no-change report;
the runner then completed Terraform destroy and SDK prerequisite cleanup.
This run is not reported as a full fixture pass.

Managed CA selection, certificate rotation and AWS database-role equivalence
remain outside this local TLS contract. The Docker daemon and host remain
trusted. See the official [RDS PostgreSQL TLS rules](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html)
and [Aurora PostgreSQL TLS rules](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraPostgreSQL.Security.html).

The other report controls remain explicit rejection, not silent metadata:

- `StorageEncrypted=true` needs an actual encrypted data/snapshot volume owner,
  key lifecycle and verified at-rest bytes; KMS bootstrap-password sealing is not it.
- `ManageMasterUserPassword=true` needs real Secrets Manager/KMS secret ownership,
  generated native credentials and fenced rotation/recovery of the SQL password.
- VPC/security groups need real placement/routing and EC2-owned packet enforcement
  on the database listener; host loopback publication is not a VPC association.
- Positive backup retention needs scheduled genuine backups, retention deletion,
  recoverable engine logs/PITR and restore verification; manual offline snapshots
  do not supply automated-backup semantics.

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
storage/readers/failover/global replication/serverless scaling, Multi-AZ,
managed physical storage allocation/IOPS/autoscaling/encryption, engine upgrades, VPC/security-group
packet enforcement, managed TLS CA selection/rotation, IAM database authentication,
managed-secret rotation, automated backups/PITR/export and the remaining RDS
operations. Upstream PostgreSQL/MySQL is a real local SQL data plane, **not the
Aurora storage service**. No ElastiCache, OpenSearch or MSK implementation is
included in this workstream.

## Intentional gap markers

- `internal/services/rds/service.go`: remaining cloud topology, managed
  storage/networking, automated backup, maintenance, replication, IAM database
  authentication, managed password rotation and proxy owners.
- `internal/services/rds/storage.go`: actual quota/resize and maintenance-window
  owners are prerequisites for physical capacity and deferred growth.
- `internal/services/rds/parameters.go`, `changeParameters`: independently
  visible native cluster-group propagation is not modeled; no invented delay.

The generated unsupported remainder is not implemented behavior. No database
operation is satisfied by a toy SQL parser or a canned query result.
