# Deploying container and native engines

This guide deploys the **source-built host controller**, not a published stackd server image. It covers every container/native-engine option in the [runtime matrix](runtimes.md). For QEMU/EC2, k3d/EKS and managed-Lambda guests, use [VM and Kubernetes deployment](runtime-vms.md). Commands below are operator preparation instructions, not actions performed automatically by stackd. Run from the repository root unless noted.

## Shared Docker host

Use a dedicated, trusted **Linux host with rootful Docker Engine, systemd and cgroup v2**, without Docker user-namespace remapping. These requirements apply even to a database-only deployment: `-docker-host` constructs **both Lambda and ECS**, plus the shared CodeBuild, DynamoDB, Kinesis and ORC adapters. Docker Desktop, rootless Docker, an arbitrary remote daemon or a different container engine is not this host contract.

Install Go **1.26.5 or newer** using the [official Go instructions](https://go.dev/doc/install). Install Docker Engine using the official instructions for [Ubuntu](https://docs.docker.com/engine/install/ubuntu/) or [Debian](https://docs.docker.com/engine/install/debian/); follow their repository/key setup before installing `docker-ce`, `docker-ce-cli`, `containerd.io` and `docker-buildx-plugin`. Use the distribution's systemd service, not rootless setup. Review Docker's [post-install privilege warning](https://docs.docker.com/engine/install/linux-postinstall/) and [cgroup-v2 requirements](https://docs.docker.com/engine/containers/runmetrics/). Docker-socket access is effectively host-root access.

After installation, these are useful host checks (they do not start customer workloads):

```sh
uname -s
ps -p 1 -o comm=
systemctl is-active docker
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
docker -H unix:///var/run/docker.sock info --format \
  'OS={{.OSType}} Cgroup={{.CgroupVersion}} Driver={{.CgroupDriver}} Security={{json .SecurityOptions}} Root={{.DockerRootDir}}'
test -S /var/run/docker.sock
test -d /run/lock
test -e /dev/loop-control
cat /proc/filesystems
df -h . /var/lib/docker
```

Expect Linux, PID 1 `systemd`, an active daemon, `cgroup2fs`, cgroup version `2`, and no `rootless`/`userns` security option. The controller's user must be able to access the local socket and retain files in its state directory. Inspect the configured daemon rather than assuming the default Docker context is the right one. The following preparation commands consistently select that daemon:

```sh
export DOCKER_HOST=unix:///var/run/docker.sock
umask 077
mkdir -p bin data
make build
```

`make build` builds `bin/stackd` and the static Linux `lambda-telemetry-amd64` and `lambda-telemetry-arm64` helpers. A bare `go build -o bin/stackd ./cmd/stackd` builds only the controller. Install the helpers beside the executable or pass `-lambda-telemetry-directory /absolute/helper/directory`. Initial Go builds can download modules; prepare the module cache and binaries before disconnecting.

Install both shared helper images explicitly:

```sh
docker pull nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61
docker pull ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
```

The first pin is [`compute/docker.ToolkitImage`](../compute/docker/helper.go), used for privileged host networking/systemd helpers. The second is [`compute/lambda.StorageImage`](../compute/lambda/docker_storage.go), which supplies util-linux/e2fsprogs for disk-backed Lambda `/tmp`. The daemon host must support privileged helpers, loop devices, ext4, `fallocate`, direct I/O and a daemon `/dev` bind. Function/task containers do not inherit those setup privileges. Allocate real disk space for images, volumes and Lambda ephemeral-storage quotas; this storage is not a memory-backed tmpfs. See [Lambda storage/recovery](lambda.md#temporary-storage-and-crash-recovery) and [ECS admission](ecs.md#setup-and-supported-execution). If you arrange your own containerized controller, it must share the daemon host's **existing `/run/lock` inode**; this guide does not supply such an image or deployment.

### Explicit online preparation and offline import

Pull only the additional engines you intend to use, using the exact commands below. Images must match the execution architecture; pulling an arm64 Lambda manifest onto an amd64 host does not install CPU emulation. Use a matching native host unless you have separately prepared and validated emulation.

Runtime adapters inspect installed images; **they do not auto-pull**. An image override is not an installer. For an offline machine, prepare on a connected machine of the same architecture, export images, transfer the archive, and load it on the target. For example:

```sh
docker image save -o stackd-shared-images.tar \
  nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61 \
  ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
# On the target, after transferring the archive:
docker image load -i stackd-shared-images.tar
docker image inspect nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61
docker image inspect ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
```

Repeat save/load for the service images you selected and for `stackd/orc:2.2.2` after building it. Preserve the required digest-qualified identity, not merely a convenient tag: Docker archive/Engine versions can differ in preservation of repository-digest metadata. **If the exact `image inspect repository@sha256:...` fails after load, the import is not ready.** Resolve this during connected preparation with an Engine/image transfer method that preserves the required reference; do not silently replace fixed pins with mutable tags. Retain the binaries, module/dependency caches needed for any further builds, MQ JDK/OpenSSL and scanner DB separately. Offline runtime does not block application-code egress; enforce that with host/network policy.

### Endpoint routing and controller launch

For a host-only API emulator without execution, use `-listen 127.0.0.1:4566`. Normal containers cannot reach that listener through their own loopback. The simplest shared-runtime launch deliberately binds all IPv4 interfaces:

```sh
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock
```

The CLI derives `http://host.docker.internal:4566` as the execution-facing endpoint. Restrict inbound traffic with your host/network firewall **before** using this listener. For URLs that containers later consume (for example SQS queue URLs), use an origin reachable from both host clients and containers when creating resources. A hostname such as `stackd.local` must already resolve to the reachable host IPv4 address in both places; it is not installed by stackd. Then an explicit launch is:

```sh
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock \
  -public-endpoint http://stackd.local:4566 \
  -compute-endpoint http://stackd.local:4566
```

`-public-endpoint` advertises resource URLs; `-compute-endpoint` selects the execution AWS origin; neither changes the listener. A loopback listener without an explicit compute endpoint is rejected with Docker enabled. Explicitly overriding that check with a loopback origin does not make container connectivity work. Lambda Runtime API callbacks are separate: `-lambda-runtime-listen` defaults to `0.0.0.0:0`, and empty `-lambda-callback-host` uses Linux host-gateway. Permit only the intended Docker networks to reach callback ports. Athena also has its own callback listener described below.

All later launch snippets are **alternatives**, not controllers to run concurrently against the same SQLite file. Combine desired flags into one controller. Boolean engine flags default to false; empty image overrides select the pinned defaults below. Use an absolute, stable SQLite path: native ownership is derived from it. Do not run two controllers with that same database/namespace or move the database independently of owned native state.

### Local API readiness and resource provisioning

Starting stackd enables adapters; it does **not** create customer functions, tasks, tables, databases or brokers. Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) or use an AWS SDK, always with an explicit local endpoint and local-only credentials:

```sh
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_PAGER=
unset AWS_SESSION_TOKEN AWS_PROFILE
aws --endpoint-url http://127.0.0.1:4566 sts get-caller-identity
```

The local account is `000000000000`. This checks API access, not engine readiness. Use each service's Describe/Get status and a real native operation before treating its resource as ready. The service sections link the supported provisioning contracts; a container-create response or elapsed sleep is not readiness. If your workflow consumes advertised resource URLs from containers, substitute your shared reachable origin for the host-only endpoint in **all** provisioning calls.

## Lambda

Prepare the shared helpers and telemetry binaries first. These are the complete default ZIP-function runtime mappings in [`compute/lambda/docker.go`](../compute/lambda/docker.go), using [official AWS Lambda base images](https://docs.aws.amazon.com/lambda/latest/dg/images-create.html). Pull the mappings needed by your functions; installing all eight is not required. AWS calls the architectures `x86_64` and `arm64`; Docker calls them `amd64` and `arm64`.

```sh
# python3.12 / x86_64
docker pull --platform linux/amd64 public.ecr.aws/lambda/python@sha256:a89893d9c93a9ffbf9e35ca32d7cadc635cbf3a9aec94480c75ed07150a05daa
# python3.12 / arm64
docker pull --platform linux/arm64 public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e
# python3.13 / x86_64
docker pull --platform linux/amd64 public.ecr.aws/lambda/python@sha256:1db929eee2769af5a502cb0ac7409245a1f5b8f8cb37f43832e9983f7a0aed53
# python3.13 / arm64
docker pull --platform linux/arm64 public.ecr.aws/lambda/python@sha256:48fb06e4f76b6512f055afe0659bffecb2439affd9d0a4d98afba0fdde7bc08f
# nodejs22.x / x86_64
docker pull --platform linux/amd64 public.ecr.aws/lambda/nodejs@sha256:0c33b7174dc800aaf810b3f6075aadec654aaf81d96b974a33f91cacf0bbe569
# nodejs22.x / arm64
docker pull --platform linux/arm64 public.ecr.aws/lambda/nodejs@sha256:2f80915b7e49e3ae37a84be1110d313113d3e0c027d3564b489f46d10aae320a
# provided.al2023 / x86_64
docker pull --platform linux/amd64 public.ecr.aws/lambda/provided@sha256:0439bff81ff967d34c098fa6d23a0059ff90d339dc8984f1dda007bde039a44f
# provided.al2023 / arm64
docker pull --platform linux/arm64 public.ecr.aws/lambda/provided@sha256:b501fd60cfbd920688576f5cfd6040bf3533a15ce160673758c77ca2dabd312e
```

Use the shared controller launch; there is no separate `-lambda-runtime` boolean. Deploy an IAM execution role and ZIP code through `CreateFunction`, wait for function readiness via `GetFunctionConfiguration`, then `Invoke`; [Lambda's current application path](lambda.md#current-application-path) specifies supported packaging, roles and invocation behavior. `provided.al2023` needs your executable `bootstrap` implementing the Lambda Runtime API; the base image alone is not your handler. `-lambda-keep-alive` defaults to `10m`; `0` forces cold invocations. Optional `-lambda-storage-image` must be an installed immutable compatible storage helper. Hot-reload code/layer flags are development mounts, not durable deployment storage. Managed-instance Lambda uses guest-installed images and an agent instead: follow [VM deployment](runtime-vms.md), not these host-container commands.

## ECS and CodeBuild

Use the same shared launch and toolkit image. Install **your** task/build image explicitly from its publisher by digest, or build your Dockerfile and retain the resulting immutable local image ID. There is no universal stackd application image. For a repository containing your chosen Dockerfile, preparation is:

```sh
docker build -t local/stackd-workload:prepared /absolute/path/to/your/build-context
docker image inspect --format '{{.Id}}' local/stackd-workload:prepared
```

Use that emitted `sha256:...` image ID in the task definition/build configuration. Transfer a built image with `docker image save -o workload.tar local/stackd-workload:prepared` and `docker image load -i workload.tar`, then inspect it on the destination. A CodeBuild image needs the shell/tools your buildspec actually invokes; it is not enough to install an arbitrary runtime-only base image.

For ECS, create the cluster, EC2 VPC/subnet/security groups, applicable IAM roles and `awsvpc` task definition through the local APIs before `RunTask`/`CreateService`. Supported execution is Linux Fargate `1.4.0` (`LATEST` selects it), supported task CPU/memory pairs and matching installed image architecture, not EC2 or Spot capacity. Follow [ECS setup and supported execution](ecs.md#setup-and-supported-execution) and [task state/readiness](ecs.md#api-and-retained-state); check `DescribeTasks` and the real application listener/logs. Shared `/run/lock`, systemd slice ownership and packet-rule admission are required even if you are not launching ECS tasks yet.

CodeBuild uses real S3/native Git sources and real build commands. Create a service role and project, then `StartBuild`; inspect `BatchGetBuilds` and logs. Supported controls/buildspecs are in [ECR and CodeBuild](behavior-references.md#ecr-and-codebuild). Pull/build all project images and dependencies before offline work; builds that fetch Git/package dependencies still need those sources available. Real idle fleet capacity additionally requires an immutable installed image:

```sh
FLEET_IMAGE=$(docker image inspect --format '{{.Id}}' local/stackd-workload:prepared)
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -codebuild-fleet-image "$FLEET_IMAGE"
```

The flag supplies capacity's image; create the actual fleet through CodeBuild APIs. AMI names/mutable tags are not a substitute for a pinned local fleet image.

## DynamoDB and Kinesis

Install the shared helpers plus these pinned native backends:

```sh
docker pull amazon/dynamodb-local@sha256:ff89bd48ff32cd8d9be5fee8873b65b8854dc408f1afe881be6eb00247bc0dab
docker pull apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock
```

There are no separate DynamoDB/Kinesis CLI opt-in booleans. The implementations use [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html) and [Apache Kafka](https://kafka.apache.org/37/getting-started/quickstart/), respectively; Kafka storage is not a claim that AWS Kinesis uses Kafka. Pins are in [`engine/dynamodb`](../engine/dynamodb/docker.go) and [`engine/kinesis`](../engine/kinesis/docker.go).

With the local credentials above, a small real table workflow is:

```sh
aws --endpoint-url http://127.0.0.1:4566 dynamodb create-table \
  --table-name deployment-check --billing-mode PAY_PER_REQUEST \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --key-schema AttributeName=id,KeyType=HASH
aws --endpoint-url http://127.0.0.1:4566 dynamodb wait table-exists --table-name deployment-check
aws --endpoint-url http://127.0.0.1:4566 dynamodb put-item \
  --table-name deployment-check --item '{"id":{"S":"ready"}}'
aws --endpoint-url http://127.0.0.1:4566 dynamodb get-item \
  --table-name deployment-check --key '{"id":{"S":"ready"}}' --consistent-read
aws --endpoint-url http://127.0.0.1:4566 dynamodb delete-table --table-name deployment-check
```

For Kinesis, create the stream with `CreateStream`, wait for `DescribeStreamSummary` to report `ACTIVE`, then use `PutRecord`, `GetShardIterator` and `GetRecords`; see [Kinesis provisioning and boundaries](behavior-references.md#kinesis-streaming-dependency-evidence). [DynamoDB engine references](behavior-references.md#dynamodb-engine-references) distinguish the native data engine from modeled controls. Retain exact-owned Docker volumes alongside SQLite.

## S3 ORC inventory

The encoder is a separately built helper image, not a controller image:

```sh
docker build -t stackd/orc:2.2.2 engine/orc
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock
```

[`engine/orc/Dockerfile`](../engine/orc/Dockerfile) pins the Maven build base to `maven:3.9.12-eclipse-temurin-17@sha256:a0603aab698040d9c94259f379ec0487da1678560748d6c7508483034033c53d` and final JRE to `eclipse-temurin:17.0.18_8-jre-jammy@sha256:642d45bf22d3cb9face159181732ed9fa70873b2681e50445eff7d4785c176bb`. The explicit build downloads [Apache ORC](https://orc.apache.org/) tools `2.2.2` through Maven; build/export this image before going offline. There is no ORC CLI enable flag beyond Docker. Configure S3 inventory with ORC format and the appropriate destination bucket/policy through the local S3 APIs, then inspect the delivered manifest and real ORC object as described in [inventory delivery](cloudtrail.md). Merely building the image does not schedule inventory.

## Glue and Athena

Read the [retained AWS Glue license](../compute/glue/AWS-GLUE-LICENSE.txt) **before** installing the Glue image. Its Amazon Software License restriction permits the documented AWS-targeted development/testing use; this is not permission for general standalone or other-cloud use or redistribution. See AWS's [local Glue development guide](https://docs.aws.amazon.com/glue/latest/dg/develop-local-docker-image.html). Skip Glue entirely if that boundary does not fit your use.

```sh
# Glue 5 Spark and Python-shell interpreter (both required by Glue adapter setup)
docker pull public.ecr.aws/glue/aws-glue-libs@sha256:a54bd25fb72c55a2f28d07656a3cda943a042f345cc25f4c2c170667be864f01
docker pull public.ecr.aws/lambda/python@sha256:6aa6ba1ae1662df3e7400a25d3293bc464c3a907da13370eec7637128c8eb0a3
# Athena Trino engine and Apache Spark Hive-DDL parser
docker pull trinodb/trino@sha256:00125e40d063bc4816d165482f6044872b18b56026fb959d3b28ce1f96ffbbee
docker pull apache/spark@sha256:9b0a6c2c860f5e7d18dd5270286fef32a09c7f5a7e2b0dbe5642de8a3a02ab3e
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -glue-runtime -athena-runtime
```

Enable either boolean independently and omit the other engine's pulls if unused. The defaults are Glue Spark 3.5.4-amzn-0/Python 3.11, Python-shell Python 3.9 (not the full Glue analytics library bundle), Trino 476 and Spark 4.1.3 used **only** as a native Hive-DDL parser. Upstream installation references: [Trino Docker](https://trino.io/docs/current/installation/containers.html), [Apache Spark](https://spark.apache.org/docs/latest/). Immutable installed overrides are `-glue-spark-image`, `-glue-python-image`, `-athena-image` and `-athena-hive-ddl-image`.

Athena defaults: `-athena-endpoint-host 127.0.0.1` is the controller-visible Docker-host SQL address; `-athena-callback-listen 0.0.0.0:0` and `-athena-callback-host host.docker.internal` expose owned Glue/S3 callbacks to engine containers. Permit these callback connections without exposing them to untrusted networks. They do not replace the main compute/public endpoints.

Provision S3 scripts/data/output locations and IAM roles, then Glue `CreateJob`/`StartJobRun` or Athena `StartQueryExecution`. Poll `GetJobRun`/`GetQueryExecution` and retrieve real output rather than treating API acceptance as completion. The [analytics service guide](behavior-references.md#glue-and-athena-engines-evidence-and-boundaries) covers supported catalogs, job types and SQL boundaries. AWS-specific bookmarks, Lake Formation vending, Glue Parquet writer and Data Quality are not established by running ordinary Spark/Trino. SQLite keeps control state; preserve S3 data/output and native state too.

## RDS

```sh
docker pull postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652
docker pull mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -rds-runtime
```

These Docker Official Images run PostgreSQL 17.11 and MySQL 8.4.11; see their upstream [PostgreSQL](https://hub.docker.com/_/postgres) and [MySQL](https://hub.docker.com/_/mysql) image contracts. `-rds-postgres-image`/`-rds-mysql-image` are immutable installed overrides with the required native layout. `-rds-endpoint-host` defaults to `127.0.0.1`; database ports bind daemon loopback, so native clients belong on this host unless you deliberately provide a secure forwarding arrangement. Changing the advertised host does not change that bind.

Create the supported instance/cluster through RDS APIs; wait for its Describe status and connect using the returned real PostgreSQL/MySQL endpoint and credentials. [RDS native setup](rds.md#running-the-native-engines), [lifecycle](rds.md#ownership-and-lifecycle) and [Data API](rds.md#rds-data-api) define supported provisioning and SQL operations. This is not AWS managed storage, topology or engine parity. Preserve database and snapshot Docker volumes; SQLite alone does not contain SQL bytes. Stop/start APIs affect native processes; delete APIs remove owned data.

## DocumentDB compatibility

```sh
docker pull mongo@sha256:84c4a18b60a0e73d1577112b0a600b46cab477c64cfe0ff36d0647bbca055bd0
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -docdb-runtime
```

This is the [Docker Official MongoDB image](https://hub.docker.com/_/mongo), version 7.0.43, **not AWS DocumentDB's engine**. `-docdb-image` is an installed immutable compatibility-image override, not a way to install AWS's proprietary engine. Follow [DocumentDB native setup](documentdb.md#native-setup) to create the cluster/instance, wait for native readiness and connect using the returned TLS endpoint/CA. Keep the exact-owned engine/snapshot volumes together with SQLite. [Explicit differences](documentdb.md#explicit-differences-and-remaining-operations) delimit the supported MongoDB/change-stream behavior and unimplemented cloud capabilities.

## OpenSearch

For Linux host setup, follow the [official Docker requirements](https://docs.opensearch.org/docs/latest/install-and-configure/install-opensearch/docker/), including `vm.max_map_count` of at least `262144`. On the dedicated host, inspect with `sysctl vm.max_map_count`; if needed, an administrator can set `sudo sysctl -w vm.max_map_count=262144` and persist it using the distribution's sysctl configuration. Do not change a shared host blindly.

```sh
docker pull opensearchproject/opensearch@sha256:9e0b3b3b6805811bd63d9b9503ffe34a58ba33d03cc346000e318c6ff5c05bd9
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -opensearch-runtime
```

The pin runs OpenSearch 2.19.4; admitted engine selection is `OpenSearch_2.19`. Create a domain through `CreateDomain`, inspect `DescribeDomain` until native readiness, and use its scoped HTTP endpoint for supported search requests. See [native OpenSearch provisioning](implementation-reference.md#native-opensearch) and [engine boundaries](behavior-references.md#opensearch-engines-evidence-and-boundaries). Each domain owns a real single node, volume/network and loopback private REST listener. Multi-node/AZ, VPC, EBS, KMS, TLS, fine-grained security and Dashboards are not supplied by this local mapping. Local host processes and Docker administrators remain trusted.

## MSK

```sh
docker pull apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -msk-runtime
```

This is Apache Kafka 3.7.1, the same installed pin used by Kinesis. `-msk-image` must resolve to the expected content; `-msk-endpoint-host` defaults to `127.0.0.1` for operator-local public-client listeners. Follow [MSK public Kafka brokers](behavior-references.md#msk-public-kafka-brokers): create a provisioned cluster with `KafkaVersion=3.7.1`, one to three brokers, `BrokerNodeGroupInfo.InstanceType=kafka.local` and an empty required `ClientSubnets` list. `kafka.local` is a local selector, not an AWS instance type. Poll `DescribeCluster`/`DescribeClusterV2`, retrieve `GetBootstrapBrokers`, then use a real Kafka producer/consumer and the configured authentication mode. No invented ZooKeeper endpoints, managed VPC/AZ/EBS or AWS network isolation is promised. Retain each broker's exact-owned volumes with SQLite.

## Valkey and local TLS

Install the [official Valkey image](https://valkey.io/topics/installation/):

```sh
docker pull valkey/valkey@sha256:1cb6b20b70d927560cc4cc5397b5f045e74aa603ff7696274778880bb6fadc75
```

TLS resources require a PEM certificate/key covering **IP `127.0.0.1`**. For a private local development instance, the following [OpenSSL](https://docs.openssl.org/3.0/man1/openssl-req/) command creates a self-signed trust anchor/server certificate usable by both Valkey and MQ. Install OpenSSL through your distribution first. Use a new private directory; do not overwrite a certificate belonging to retained resources.

```sh
umask 077
mkdir -p data/tls
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -keyout data/tls/local.key -out data/tls/local.crt \
  -subj '/CN=stackd-local' \
  -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign' \
  -addext 'extendedKeyUsage=serverAuth'
chmod 600 data/tls/local.key
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -valkey-runtime \
  -valkey-tls-cert "$PWD/data/tls/local.crt" \
  -valkey-tls-key "$PWD/data/tls/local.key"
```

Trust `local.crt` explicitly in native clients (for example `valkey-cli --tls --cacert /absolute/path/local.crt -h 127.0.0.1 -p PORT` using the API-returned port and required credentials). Do not disable certificate verification. Keep the private key on the host and retain the certificate for clients/restarts; this development self-signed setup is not a public PKI deployment. Plan rotation before expiry rather than regenerating files under live resources.

Create ElastiCache/MemoryDB resources, users and ACLs through their APIs, poll Describe status, then issue a real native command. [Valkey setup](behavior-references.md#explicit-setup) and its surrounding service contract give the supported topology/authentication/version choices. MemoryDB defaults to TLS; plaintext is only admitted for the open-access ACL, and authenticated ElastiCache requires TLS. `-valkey-image` is an immutable installed override still subject to native-version checking. The runtime requires a local Unix daemon; native endpoints bind loopback, not an AWS VPC. Preserve owned data/snapshot volumes with SQLite.

## Amazon MQ

Prepare the shared Docker helpers, the TLS files above and both broker images:

```sh
docker pull rabbitmq@sha256:87178a0ee3e2f52980ba356d38646ed1056705ff2d5ff281f8965456eaa0c1e3
docker pull apache/activemq-classic@sha256:65814d0a18a16bef9096ce7829fcb27e501e281e0ef1064857b9eded4927508c
```

Install a **Java 11+ JDK**, not just a JRE, from your distribution or [Eclipse Temurin's official installation instructions](https://adoptium.net/installation/). Install OpenSSL too. Set `JAVA_HOME` to that installed JDK; `java` and `javac` must be matching siblings. These checks are useful before launch:

```sh
"$JAVA_HOME/bin/java" -version
"$JAVA_HOME/bin/javac" -version
openssl version
mkdir -p data/mq
chmod 700 data/mq
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -mq-runtime \
  -mq-state-directory "$PWD/data/mq" \
  -mq-tls-certificate "$PWD/data/tls/local.crt" \
  -mq-tls-key "$PWD/data/tls/local.key" \
  -mq-java "$JAVA_HOME/bin/java"
```

The controller extracts JMS/OpenWire JARs from the **already installed ActiveMQ image** and compiles its embedded bridge with the installed `javac`; it does not fetch Maven dependencies at runtime. The JDK must also support `--release 11` for the native metrics reader. The private MQ state directory contains generated configuration, keystores, compiled helpers and sensitive credentials; it must be local to the daemon because the runtime bind-mounts it. Retain it, the TLS material, broker data volumes and SQLite together.

Pins run RabbitMQ 3.13.7 and ActiveMQ Classic 5.18.7. Upstream engine references: [RabbitMQ installation](https://www.rabbitmq.com/docs/download), [ActiveMQ Classic Docker](https://activemq.apache.org/components/classic/documentation/docker). Create brokers through `CreateBroker` with the supported **public `SINGLE_INSTANCE`, `mq.t3.micro`, SIMPLE authentication** configuration and pinned engine version; RabbitMQ also needs the modeled service-linked-role authority. Poll `DescribeBroker` for `RUNNING`, then use the returned local TLS AMQP/OpenWire endpoint with the trusted certificate and your broker user. Java clients need the appropriate JMS client libraries/trust store as well; stackd's internal bridge is not a general client installation.

[MQ execution and durable ownership](mq.md#actual-execution-and-durable-ownership) details supported creation, configuration, authentication, readiness and deletion. Public here means operator-local loopback listeners, not Internet-accessible AWS DNS. ActiveMQ native readiness does not prove a particular customer's ACL grants JMS operations; test that user's real connection/destination permissions. No replicated fleet, private VPC isolation or AWS encrypted managed storage is implied.

## ALB relay

ALB execution needs the shared Docker host plus SQLite and the shared EC2 bridge/policy owners; for host networking/guest setup see [VM deployment](runtime-vms.md) and [EC2 networking](ec2.md). Build a static **Linux** relay matching the daemon host architecture. On this Linux source-build host:

```sh
CGO_ENABLED=0 go build -o bin/stackd-elbv2-node ./cmd/stackd-elbv2-node
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock \
  -elbv2-node-executable "$PWD/bin/stackd-elbv2-node" \
  -dns-listen 127.0.0.1:5353
```

The relay is mounted into owned toolkit containers; pass its absolute installed path and retain it across reattachment. There is no separate ALB server image to pull. Create EC2 VPC/subnets/security groups, an application load balancer, target group, registered targets and listener through the local APIs. Inspect load-balancer state and target health and make a real request to the returned hostname. [EC2](ec2.md) and [DNS resolution/delegation](route53.md#dns-resolution-and-delegation-boundary) define networking and supported routing. Configure clients to use stackd's authoritative UDP **and TCP** DNS listener; ordinary system DNS will not automatically resolve these names. With no `-dns-listen`, ALB chooses an ephemeral loopback DNS port printed at startup. Port 5353 here is an explicit local example and must be free. The main API port is not the ALB data listener or DNS port.

## ECR scanner

Basic vulnerability scanning needs **Trivy 0.74.0** and a separately prepared **schema-2 vulnerability DB**, not Docker. Download the matching binary from the [official immutable release](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0). The following connected preparation example is for Linux amd64 (for arm64 select the release's `Linux-ARM64` archive):

```sh
mkdir -p tools/trivy data/trivy-cache
curl -fL -o tools/trivy/trivy_0.74.0_Linux-64bit.tar.gz \
  https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz
curl -fL -o tools/trivy/trivy_0.74.0_checksums.txt \
  https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_checksums.txt
(cd tools/trivy && sha256sum --check --ignore-missing trivy_0.74.0_checksums.txt)
tar -xzf tools/trivy/trivy_0.74.0_Linux-64bit.tar.gz -C tools/trivy trivy
./tools/trivy/trivy --version
./tools/trivy/trivy image --cache-dir "$PWD/data/trivy-cache" \
  --db-repository ghcr.io/aquasecurity/trivy-db:2 --download-db-only
```

Verify the release's published signatures according to [Trivy installation guidance](https://trivy.dev/latest/getting-started/installation/) for your supply-chain policy; checksums alone are not independent publisher authentication. Follow [Trivy air-gapped operation](https://trivy.dev/latest/advanced/air-gap/) when transferring the binary and complete cache (`db/trivy.db` and `db/metadata.json`) to an offline host. The DB changes independently of the pinned executable: record its metadata and refresh explicitly during connected maintenance. Startup does not download it.

```sh
./bin/stackd -listen 127.0.0.1:4566 -database "$PWD/data/stackd.sqlite" \
  -ecr-scanner "$PWD/tools/trivy/trivy" \
  -ecr-scanner-cache "$PWD/data/trivy-cache"
```

This scanner-only launch needs no `-docker-host`. To combine it with native compute, add the two scanner flags to the shared Docker launch instead. Create an ECR repository and upload a real supported OCI/Docker image's manifest/config/layers through the supported registry/API path, request `StartImageScan`, and poll `DescribeImageScanFindings`. [ECR and CodeBuild](behavior-references.md#ecr-and-codebuild) documents the upload/scan contract and supported image boundary. Missing DB/executable, wrong version or unsupported image must not be interpreted as a clean scan. Results are from this local Trivy/DB combination, not AWS scanner-database equivalence.

## Shutdown and retained state

Use Ctrl-C/SIGTERM for graceful controller shutdown. Do not treat it as a universal infrastructure stop: Lambda environments close, but with SQLite the database, broker, ECS and other durable engines have service-specific detach/reattach behavior. Stop or delete resources through the relevant service APIs when that is your intent, and inspect their terminal state before retiring metadata. Deletion can destroy native bytes; a stop is not a delete.

Keep the stable SQLite path, Docker's exact-owned volumes/networks, MQ state/TLS files, installed helper paths and any external source/output data together. SQLite is control state, not a backup of all native engine bytes. Back up using the service's supported snapshot/backup path and retain ownership metadata. With in-memory repositories, graceful CLI shutdown attempts deletion of the native engines it owns; this does not cover every workload, crashes or SIGKILL. Never use blanket `docker system prune`, volume removal or unrelated-container cleanup as stackd shutdown.

These are real engines and real customer-code execution with privileged setup components. The API's IAM model is not a host firewall or a hardened multi-tenant security boundary. Restrict API/callback/DNS/data listeners, trust local administrators and Docker users, avoid ambient cloud credentials, and isolate untrusted applications on an appropriate separate host/network. Continue with [Operations](operations.md), [SQLite limits](sqlite-state.md) and each service's lifecycle section for inventories, safe restarts and ownership recovery.
