# DocumentDB controls and a real document compatibility backend

DocumentDB owns scoped cluster, single-writer instance, snapshot, tag and retained
lifecycle intent. A pinned **MongoDB 7.0.43** process owns BSON documents, indexes,
queries, SCRAM authentication and native replica-set change streams. There is no
in-memory document store, canned query result, automatic AWS forwarding or engine
fallback. **MongoDB is not the AWS DocumentDB engine.** The implemented boundary
is a local compatibility backend, not distributed DocumentDB storage or complete
MongoDB/DocumentDB behavioral equivalence.

## Native setup

Install the immutable Docker Official Image explicitly:

```sh
docker pull mongo@sha256:84c4a18b60a0e73d1577112b0a600b46cab477c64cfe0ff36d0647bbca055bd0
go build -o /tmp/stackd-docdb ./cmd/stackd
/tmp/stackd-docdb -listen 127.0.0.1:4566 \
  -database /tmp/owned-docdb.sqlite -docker-host unix:///var/run/docker.sock \
  -docdb-runtime -compute-endpoint http://host.docker.internal:4566
```

The pin comes from the upstream
[`mongo:7.0.43-jammy` source](https://github.com/docker-library/mongo/tree/8d9ef3e640d2925aa11c50524f656f7fc8b4d4f7/7.0).
`-docdb-image` accepts an explicitly installed immutable compatible override; the
runtime never pulls. `Config.DocumentDBRuntime` supplies the same caller-owned
engine contract to embedders. A stable namespace derived from the SQLite path
owns containers and volumes. Persistent shutdown detaches; ephemeral shutdown
removes its exact-owned native resources. Never run two controllers against the
same metadata/namespace.

Create a `docdb` cluster and then a `CreateDBInstance` writer. An empty cluster is
not an available document server. The current control contract selects engine
family `5.0`; this does **not** relabel the binary, whose native `buildInfo` remains
MongoDB 7.0.43. Instance classes are control identifiers, not AWS hardware capacity.

The returned endpoint binds Docker-host **loopback only**. TLS is mandatory;
clients explicitly trust the owner-generated CA and authenticate against `admin`
with their database credentials. Native replica discovery advertises
`localhost:<the same published port>`, replica-set name `stackd`. Use
`retryWrites=false`. The API does not invent a CA field in AWS response shapes:
embedders/source adapters obtain public trust material through the authoritative
connection lookup; a local operator can read `/data/db/security/ca.pem` from its
exact-owned container. The host/Docker daemon remain trusted. Remote Docker needs
an explicit localhost tunnel preserving the port; this is not AWS VPC networking.
Requests attaching subnet groups/security groups or claiming managed encryption,
serverless scaling, maintenance/backup schedules and managed secrets fail rather
than becoming inert metadata.

## One shared RDS Query namespace

The authoritative SDK models give RDS and DocumentDB the same signing name,
endpoint prefix, API version, XML namespace and `arn:...:rds:...` resource namespace.
Ordinary `aws rds`, `aws docdb`, boto3 and Go v2 SDK clients therefore use the same
local endpoint. There is no user-agent classifier or invented service hostname.

RDS composes the public Query boundary: `Engine=docdb` selects the document owner;
identifier/ARN commands resolve the current retained owner; clusters, instances
and cluster snapshots are unioned before existing filtering/pagination. A marker
from one official SDK works in the other. The owner repositories share the
transaction domain and prevent duplicate public identifiers; there is no second
resource registry. Model-generated typed projections reject RDS-only fields for a
DocumentDB command instead of silently dropping requested effects. The generator
runs with `make generate-aws` and its drift check.

This follows the documented
[RDS cross-engine list](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusters.html)
and [DocumentDB shared management/filter contract](https://docs.aws.amazon.com/documentdb/latest/APIReference/API_DescribeDBClusters.html).
Resource authority is `rds:<operation>` with current IAM/resource/request tags.
The existing protected RDS service-linked role and KMS credential cipher protect
retained master credentials. DocumentDB resources also prevent that role's
premature deletion. This internal credential encryption is **not** database-volume
storage encryption.

## Retention, transitions and snapshots

Typed memory/SQLC repositories persist cluster/instance/snapshot intent,
incarnations, generation-fenced work, encrypted credentials and public CA bytes.
Native effects happen after repository transactions close. Create, start, stop,
reboot, password change, deletion, snapshot and restore join the shared job driver.
Readiness is actual authenticated native readiness, not a timer or successful
container allocation. Controller replacement reattaches retained data and trust
material before publishing availability. Stop closes the real listening process;
start retains documents. Old master credentials fail after native password change.
A failed native writer can be deleted even while its failed operation retains a
retry deadline. Deletion supersedes that intent with generation-fenced retirement;
an in-progress healthy creation cannot be canceled through this failed-state path.
Unlike AWS's managed seven-day automatic restart, a stopped local cluster
currently stays stopped until `StartDBCluster`; that retained deadline remains
an explicit lifecycle gap.

Snapshots are **cold physical copies** of the complete native database directory.
They briefly stop client connections and restart the source. A restored cluster
requires its own writer, native volume, endpoint/trust identity and control-plane
incarnation. Snapshot credentials and bytes survive source password changes and
source deletion; subsequent source writes are not part of an earlier snapshot.
This is not an online AWS snapshot, automated backup or point-in-time recovery.
Deletion requires explicit `SkipFinalSnapshot`; callers create a supported manual
snapshot first instead of receiving a fake final backup.

`Service.ResolveCluster(ctx, arn)` is the authoritative Lambda source boundary:
current `rds:DescribeDBClusters` authority, an available writer, immutable
`RuntimeID`, native address/port/replica-set and public CA. It returns no password.
Lambda owns current Secrets Manager/KMS retrieval, polling, batching, retries and
opaque resume tokens. It must bind tokens to the immutable incarnation rather
than copying cluster state or treating a replaced name as the same source.
Source lookup passes its reader's transaction context into current IAM policy
evaluation, joining the shared SQLite read rather than opening a second connection.
The durable source regression exercises a real assumed-role allow followed by
policy revocation; retained source identity never caches the earlier grant.

## Evidence

`testdata/aws/docdb_controls.json` captures six fresh native observations in the
authorized account/region on 2026-09-28, each with its native request ID. The probe
verified STS identity and made **zero mutations**: three absent-resource errors,
a missing parameter group, invalid list page size and native engine-version
metadata. No AWS database, subnet, role or other billable resource was provisioned;
there was nothing to clean up. Native version metadata and the unsupported
parameter-group observation are evidence, not local parity claims.

`scripts/aws/docdb_executable_smoke.py` launches the actual CLI and uses signed
boto3 requests, official Go v2 decoded controls/modeled errors, and a real PyMongo
client at the returned endpoint. It exercises trusted TLS, wrong-password,
untrusted/plaintext transport rejection, BSON insert/query/change stream,
password rotation, stop/start, SQLite/controller restart, resume-token continuity,
independent physical snapshot/restore and survival after source deletion. Current
IAM denial, cross-region absence, source-filtered snapshots, RDS SDK engine
filtering, shared-name collision, and rejected-control CloudTrail history are
exercised. Exact-owned Docker containers and volumes are checked absent and both
controller exits are zero. Observed reports are retained in
[`testdata/integration/docdb_runtime.json`](../testdata/integration/docdb_runtime.json),
including a final native PostgreSQL/MySQL application regression and a separate
ephemeral CLI shutdown that removed its active database and physical snapshot.

Run the reproducible local workflow with installed `boto3` and `pymongo`:

```sh
go build -o /tmp/docdb-sdk-smoke ./scripts/docdb_sdk_smoke
python3 -B scripts/aws/docdb_executable_smoke.py \
  --binary /tmp/stackd-docdb --sdk-binary /tmp/docdb-sdk-smoke \
  --state-directory /tmp/new-owned-docdb-proof
```

`--with-rds` additionally requires the pinned SQL images documented in
[RDS](rds.md) and exercises shared public-name rejection. Engine-native race tests
also exercise container replacement, change-stream resume, password retry,
foreign-resource refusal and actual physical snapshot independence. The durable
repository regression proves source identity/credential/audit rollback, restart
and account isolation. A signed Go SDK regression proves mixed-owner pagination,
engine filtering, cross-SDK markers, owner mutation and RDS-only-field rejection.
These are bounded workflows, not exhaustive service conformance.

## Explicit differences and remaining operations

The [AWS functional differences](https://docs.aws.amazon.com/documentdb/latest/devguide/functional-differences.html)
and [change-stream guide](https://docs.aws.amazon.com/documentdb/latest/devguide/change_streams.html)
remain the reference, not generic MongoDB documentation:

- Native MongoDB change streams are available from its replica-set oplog. AWS's
  `modifyChangeStreams` enable/disable command, default-disabled collection state,
  managed retention and DocumentDB-specific token/error behavior are **not
  implemented**. The backend returns a real unsupported-command error for that
  AWS-specific command; it does not fake enabling a feed. Native oplog tokens and
  resume behavior are not asserted identical to AWS tokens.
- MongoDB supports capabilities AWS DocumentDB rejects, including retryable writes
  and certain commands/operators/admin databases. Those remain native MongoDB
  semantics outside the supported compatibility boundary, not a claimed AWS
  validation layer. Implicit multi-document atomicity, query plans, index rules,
  cursor timing and transaction limits are not calibrated as AWS-equivalent.
- Managed distributed storage, readers/failover/Multi-AZ, global clusters,
  elastic/serverless capacity, cloud VPC/SG/NACL enforcement, AWS CA rotation,
  IAM database authentication and customer-managed storage encryption are absent.
- Parameter/subnet groups, automated backups/PITR, snapshot sharing/copy/export,
  scheduled maintenance, engine upgrades, managed secret rotation, event
  subscriptions and the remaining generated control operations return explicit
  unsupported errors. No successful billable native DocumentDB lifecycle capture
  is claimed. Audit projection is generated/documentation-derived, not a new
  successful-management native audit calibration.

Intentional `TODO: Comeback` owners are
`internal/services/docdb/service.go` for the remaining managed/native-contract
capabilities and `internal/services/docdb/lifecycle.go` for seven-day automatic
restart. RDS's separate remaining boundaries stay in [RDS](rds.md).
