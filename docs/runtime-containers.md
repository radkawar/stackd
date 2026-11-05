# Deploying container and native engines

Install a [published release](releases.md#install-a-published-release) or build
from source, then prepare the container and engine dependencies you need below.
For QEMU/EC2, k3d/EKS and managed-Lambda guests, use
[VM and Kubernetes deployment](runtime-vms.md). Commands that build stackd or
helper images run from the repository root. The launch examples use `bin/stackd`;
place the package executables in `bin/` or substitute the installed path.

## Shared Docker host

`-docker-host` selects the Docker Engine connection. Enable the services you need
with `-lambda-runtime`, `-ecs-runtime`, `-codebuild-runtime`, `-dynamodb-runtime`,
`-kinesis-runtime` or `-inventory-orc-runtime`; all six default to false.
Other services have their own opt-in flags. Images must be installed beforehand.

ECS, EC2, EKS and ALB require a trusted Linux host with local rootful Docker
Engine, systemd and cgroup v2, without user-namespace remapping.
ECS admission and toolkit requirements do not apply to database-only or
Lambda-only launches.

For source builds, install Go **1.26.5 or newer** using the
[official instructions](https://go.dev/doc/install). Install Docker Engine using
the official [Ubuntu](https://docs.docker.com/engine/install/ubuntu/) or
[Debian](https://docs.docker.com/engine/install/debian/) instructions, including
repository and key setup for `docker-ce`, `docker-ce-cli`, `containerd.io` and
`docker-buildx-plugin`. Use the distribution's systemd service, not rootless
setup. Review Docker's [privilege warning](https://docs.docker.com/engine/install/linux-postinstall/)
and [cgroup-v2 requirements](https://docs.docker.com/engine/containers/runmetrics/).
For native macOS controllers, use the [Desktop recipe](#native-macos-controller-with-docker-desktop).

Check the Linux host before continuing:

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

Expect Linux, PID 1 `systemd`, an active Docker daemon, `cgroup2fs`, cgroup
version `2` and no `rootless`/`userns` security option. The controller user needs
access to the local socket and persistent files in its state directory.
Inspect the selected daemon rather than relying on the default Docker context.
Use that daemon consistently in preparation commands:

```sh
export DOCKER_HOST=unix:///var/run/docker.sock
umask 077
mkdir -p bin data
```

For a source build, also run:

```sh
make build
```

`make build` produces `bin/stackd` and static Linux `lambda-telemetry-amd64` and
`lambda-telemetry-arm64` helpers. For non-Lambda use, building only the controller
with `go build -o bin/stackd ./cmd/stackd` is sufficient.

For `-lambda-runtime`, install the helpers beside the executable or set
`-lambda-telemetry-directory /absolute/helper/directory`. Initial Go builds may
download modules; prepare the module cache and binaries before disconnecting.

Install the helper images your services need. The toolkit supports ECS and native
networking; the storage image supports Lambda:

```sh
docker pull nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61
docker pull ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
```

The toolkit pin is [`compute/docker.ToolkitImage`](../compute/docker/helper.go),
used for networking and ECS privileged host/systemd helpers. The storage pin is
[`compute/lambda.StorageImage`](../compute/lambda/docker_storage.go), which supplies
util-linux/e2fsprogs for disk-backed Lambda `/tmp`.

For Lambda storage, the Linux daemon must support privileged helpers, loop
devices, ext4, `fallocate`, direct I/O and a daemon `/dev` bind. On Docker Desktop,
these facilities must be available inside its Linux VM. Reserve disk space for
images, volumes and Lambda ephemeral-storage quotas; `/tmp` is not a tmpfs.
Function and task containers do not inherit helper privileges.

Lambda uses a kernel `flock` in a daemon-owned volume to coordinate ownership.
VPC helpers configure network namespaces, bridges and nftables in that same
daemon/VM and check daemon identity and shared lock ownership. Remote,
rootless or user-namespace-remapped engines are not supported by this recipe.

EC2, ECS, EKS and ALB require the local Linux host setup described above.
A containerized controller for these services must share the daemon host's
existing `/run/lock` inode. See [Lambda storage/recovery](lambda.md#temporary-storage-and-crash-recovery)
and [ECS admission](ecs.md#setup-and-supported-execution).

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

Repeat save/load for your selected service images and for `stackd/orc:2.2.2`
after building it. Preserve digest-qualified references: Docker archive and
Engine versions differ in how they retain repository-digest metadata.
Confirm that `docker image inspect repository@sha256:...` succeeds after load.
If it fails, prepare a transfer method that preserves the reference while still
connected; do not replace fixed pins with mutable tags.

Transfer binaries, any module/dependency caches needed for further builds,
the MQ JDK/OpenSSL and the scanner DB separately. To prevent application-code
egress during offline operation, enforce host/network policy.

### Endpoint routing and controller launch

For a host-only API emulator without execution, use `-listen 127.0.0.1:4566` and omit runtime flags. Normal containers cannot reach that listener through their own loopback. This Lambda-only runtime launch deliberately binds all IPv4 interfaces:

```sh
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -lambda-runtime
```

The CLI derives `http://host.docker.internal:4566` as the execution-facing endpoint. Restrict inbound traffic with your host/network firewall **before** using this listener. For URLs that containers later consume (for example SQS queue URLs), use an origin reachable from both host clients and containers when creating resources. A hostname such as `stackd.local` must already resolve to the reachable host IPv4 address in both places; it is not installed by stackd. Then an explicit launch is:

```sh
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -lambda-runtime \
  -public-endpoint http://stackd.local:4566 \
  -compute-endpoint http://stackd.local:4566
```

`-public-endpoint` advertises resource URLs; `-compute-endpoint` selects the
execution AWS origin. Neither changes the listener. Lambda, ECS, CodeBuild,
Glue and EC2 guest execution reject a loopback listener when using the default
compute origin. Transport-only and DynamoDB/Kinesis-only launches do not require
this check. A manually configured compute origin must still be reachable from
the workloads.

Lambda Runtime API callbacks use a separate listener. `-lambda-runtime-listen`
defaults to `0.0.0.0:0`; an empty `-lambda-callback-host` uses Linux host-gateway.
Setting it to `host.docker.internal` uses Docker Desktop's container DNS, without
controller-side resolution or an injected host mapping. Allow only intended
Docker networks to reach callback ports. Athena has its own callback listener,
described below.

Alternatively configure an explicit native gateway namespace, runtime resolver
and scoped development CA using the [networking recipes](networking.md).
Runtime DNS does not install host DNS or bypass EC2 DHCP/SG/NACL policy; public
CA delivery uses Engine archives rather than a controller-directory bind mount.
Explicit DNS replaces Desktop's special resolver, so numeric reachable Runtime
API callbacks are required in that mode. `-native-ports FIRST-LAST` optionally
pools new automatic customer SQL/document/Kafka/Valkey/MQ TCP allocations;
retained and explicitly requested ports stay exact outside a changed pool.

All later launch snippets are **alternatives**, not controllers to run concurrently against the same SQLite file. Combine desired flags into one controller. Boolean engine flags default to false; empty image overrides select the pinned defaults below. Use an absolute, stable SQLite path: native ownership is derived from it. Do not run two controllers with that same database/namespace or move the database independently of owned native state.

### Native macOS controller with Docker Desktop

Native macOS controllers support opt-in Lambda, DynamoDB and Kinesis through
Docker Desktop's Linux VM. ECS, EC2, EKS and ALB still require their local Linux
host setup and are not covered by this recipe.

This recipe has user-reported results on Apple Silicon with Darwin 24.6.0,
Docker Desktop Engine 29.8.1, the containerd image store and amd64 Rosetta
execution. Those reports cover Lambda ZIP/image invocations and updates,
DynamoDB indexes/TTL/streams, Kinesis, event mappings, scheduled delivery,
Cognito login, S3 notifications/CORS and stack cleanup. They do not establish
WebSocket message execution. See
[CloudFormation deployments](behavior-references.md#cloudformation-deployments)
for workflow details and limitations.

Lambda's privileged networking helper uses `/run/lock` inside the Docker VM,
creating the directory if needed; no manual VM setup is required.
Only trusted setup helpers receive the writable daemon-host `/run` mount,
not function containers. Docker-socket access grants host-root authority.
The helper checks daemon identity and holds the shared network lock while
changing packet policy.

Per-endpoint MAC configuration requires Docker API 1.44 or newer. The client
negotiates a common supported API up to 1.44; see
[Docker's API version history](https://docs.docker.com/reference/api/engine/version-history/).

Do not add `-ec2-state-directory` to the Desktop launch. The EC2 control-plane
APIs work without it, but QEMU guest and native disk execution require a local
Linux controller.

On Apple Silicon, build the controller for Darwin/arm64 and its Lambda helpers for Linux, not Darwin:

```sh
mkdir -p bin data
GOOS=darwin GOARCH=arm64 go build -trimpath -o bin/stackd ./cmd/stackd
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -o bin/lambda-telemetry-amd64 ./compute/lambda/cmd/telemetry-buffer
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
  -o bin/lambda-telemetry-arm64 ./compute/lambda/cmd/telemetry-buffer
# On Intel macOS, use GOARCH=amd64 for the controller instead.
```

Select the **actual Desktop socket**, not an assumed `/var/run/docker.sock`. Inspect the active Docker context and respect an explicit `DOCKER_HOST` override:

```sh
docker context show
docker context inspect "$(docker context show)" --format '{{.Endpoints.docker.Host}}'
DESKTOP_DOCKER_HOST="${DOCKER_HOST:-$(docker context inspect "$(docker context show)" --format '{{.Endpoints.docker.Host}}')}"
export DOCKER_HOST="$DESKTOP_DOCKER_HOST"
docker info --format 'OS={{.OSType}} Architecture={{.Architecture}} Security={{json .SecurityOptions}}'
```

Use the discovered `unix://<actualDesktopSocket>` endpoint, replacing the
placeholder with the absolute socket path. This recipe requires Desktop's VM
routing and privileged storage/network helpers; it does not cover remote daemons.

Install the pinned Lambda storage image and the DynamoDB/Kinesis images below
on this Engine. Add the toolkit for Lambda VPC networking and the official
Lambda runtime images needed by your ZIP functions.

For an image function, build your application with a Lambda RIC or Runtime API
bootstrap. An `x86_64` function on Apple Silicon needs a Linux/amd64 image:

```sh
# Your Dockerfile/build context must contain the real application and RIC/bootstrap.
docker build --platform linux/amd64 -t local-unified:latest /absolute/path/to/your/build-context
docker image inspect local-unified:latest --format '{{.Os}}/{{.Architecture}} {{.Id}}'
# Platform-specific images are separate prerequisites. A --platform argument does
# not install CPU emulation; amd64 on Apple Silicon needs working Desktop emulation.
# Use linux/arm64 only when both the function architecture and installed image agree.
```

Create the function with `PackageType=Image`, `Architectures=["x86_64"]` and
`Code.ImageUri=local-unified:latest`, omitting ZIP-only `Runtime`/`Handler`.
Stackd resolves the installed tag to an immutable image ID without pulling it.
See [image-function packaging](lambda.md).

The host API and container Lambda recipe is:

```sh
./bin/stackd -listen 0.0.0.0:4567 -database "$PWD/data/stackd.sqlite" \
  -public-endpoint http://127.0.0.1:4567 \
  -compute-endpoint http://host.docker.internal:4567 \
  -docker-host "$DESKTOP_DOCKER_HOST" \
  -lambda-runtime -dynamodb-runtime -kinesis-runtime \
  -lambda-callback-host host.docker.internal \
  -lambda-runtime-listen 0.0.0.0:0 \
  -lambda-telemetry-directory "$PWD/bin"
```

`"$DESKTOP_DOCKER_HOST"` selects the discovered Desktop socket. `"$PWD/bin"`
must contain both static Linux helpers. This launch uses:

- Host AWS API and host-only advertised URLs: `http://127.0.0.1:4567`.
- Function SDK calls: `http://host.docker.internal:4567`.
- Host listener: all IPv4 interfaces on port **4567**.

The origin flags do not bind or forward ports. The controller runs on the host,
so it needs no Docker `-p` mapping.

The RIC/bootstrap reads `AWS_LAMBDA_RUNTIME_API` to reach the separate
[Lambda Runtime API](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html),
not the AWS API on port 4567. `-lambda-runtime-listen 0.0.0.0:0` allocates a
callback port per environment. `-lambda-callback-host host.docker.internal`
advertises it through [Desktop's container-to-host DNS](https://docs.docker.com/desktop/features/networking/networking-how-tos/);
it installs no host-side DNS or `/etc/hosts` entry.

Allow the Desktop backend to reach both the host API and allocated callback
ports. Restrict these all-interface listeners to trusted networks. Changing the
API port alone does not configure callback reachability.

Lambda containers on Docker's default `bridge` network run inside Desktop's
Linux VM. Use `host.docker.internal` to reach host-published services; container
loopback does not reach the host controller.

The host-only public origin above is **not** suitable for returned URLs later consumed inside containers. For that topology, configure a shared hostname (for example `stackd.local`) to resolve to a reachable Mac-host IPv4 address from both host clients and containers before provisioning resources. Desktop's special `host.docker.internal` DNS name alone does not configure host-client DNS. With that prerequisite satisfied, replace the launch's two origin flags with:

```sh
  -public-endpoint http://stackd.local:4567 \
  -compute-endpoint http://stackd.local:4567
```

Keep `-listen 0.0.0.0:4567` and the Desktop callback flags unchanged. Use
`http://stackd.local:4567` in provisioning clients, and configure its DNS and
firewall access yourself. Missing images, VM capabilities or CPU emulation cause
execution to fail. After checking API readiness, invoke a function to check
container execution and callback routing.

### Local API readiness and resource provisioning

Starting stackd enables adapters; it does **not** create customer functions, tasks, tables, databases or brokers. Install the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) or use an AWS SDK, always with an explicit local endpoint and local-only credentials:

```sh
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_PAGER=
unset AWS_SESSION_TOKEN AWS_PROFILE
aws --endpoint-url http://127.0.0.1:4566 sts get-caller-identity
```

Fresh instances generate a random 12-digit account ID. Use `--account-id` to
choose it at creation; SQLite retains it across restarts. Read the ID through
STS, then provision resources using the service sections below. Check the service
status and a data-plane operation before using each resource.
If containers consume advertised resource URLs, use the shared reachable origin
in all provisioning calls.

## Lambda

Prepare the Lambda storage helper, static Linux telemetry binaries and, for VPC networking, the toolkit image first; ECS's systemd/cgroup-v2 admission is not a Lambda prerequisite. These are the complete default ZIP-function runtime mappings in [`compute/lambda/docker.go`](../compute/lambda/docker.go), using [official AWS Lambda base images](https://docs.aws.amazon.com/lambda/latest/dg/images-create.html). Pull the mappings needed by your functions; installing all eight is not required. AWS calls the architectures `x86_64` and `arm64`; Docker calls them `amd64` and `arm64`.

```sh
# python3.12 / x86_64
docker pull --platform linux/amd64 public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3
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

The Python 3.12/x86_64 pin is the **Linux/amd64 child manifest**, not its former
multi-platform index. With the containerd image store, inspecting an index can
return empty OS/architecture fields even after a platform pull. Install the
child digest shown above; platform validation remains strict and execution
still never pulls images.

Use the shared Lambda-only launch with `-lambda-runtime`. Create an IAM execution
role and ZIP function through `CreateFunction`, wait for readiness with
`GetFunctionConfiguration`, then call `Invoke`. See
[Lambda's current application path](lambda.md#current-application-path) for
supported packaging, roles and invocation behavior.

The container's RIC/bootstrap communicates with stackd's Runtime API; execution
does not use an RIE invocation proxy. For `provided.al2023`, supply an executable
`bootstrap` implementing that API.

`-lambda-keep-alive` defaults to `10m`; use `0` for cold invocations.
`-lambda-storage-image` accepts an installed immutable compatible storage helper.
Hot-reload code/layer mounts are for development, not durable deployment storage.
For managed-instance Lambda, prepare guest images and an agent using
[VM deployment](runtime-vms.md) instead.

## ECS and CodeBuild

Enable ECS with `-docker-host unix:///var/run/docker.sock -ecs-runtime`, or
CodeBuild with `-docker-host unix:///var/run/docker.sock -codebuild-runtime`.
Include `-lambda-runtime` only if you also need Lambda.

ECS requires the local Linux host setup and toolkit. CodeBuild does not enable
ECS or require Lambda telemetry/storage helpers. Install each task/build image
from its publisher by digest, or build it and retain its immutable local image
ID. To prepare your own Dockerfile:

```sh
docker build -t local/stackd-workload:prepared /absolute/path/to/your/build-context
docker image inspect --format '{{.Id}}' local/stackd-workload:prepared
```

Use that emitted `sha256:...` image ID in the task definition/build configuration. Transfer a built image with `docker image save -o workload.tar local/stackd-workload:prepared` and `docker image load -i workload.tar`, then inspect it on the destination. A CodeBuild image needs the shell/tools your buildspec actually invokes; it is not enough to install an arbitrary runtime-only base image.

For ECS, create a cluster, EC2 VPC/subnet/security groups, applicable IAM roles
and an `awsvpc` task definition before calling `RunTask` or `CreateService`.
Execution supports Linux Fargate `1.4.0` (`LATEST` selects it), supported CPU/memory
pairs and matching installed image architectures. EC2 and Spot capacity are
unsupported.

Follow [ECS setup](ecs.md#setup-and-supported-execution) and
[task state/readiness](ecs.md#api-and-retained-state). Check `DescribeTasks`,
application listeners and logs. ECS startup requires shared `/run/lock`,
systemd slice ownership and packet-rule admission even before tasks are launched.

For CodeBuild, create a service role and project, call `StartBuild`, then inspect
`BatchGetBuilds` and logs. Builds use S3 or Git sources and execute build commands;
see [ECR and CodeBuild](behavior-references.md#ecr-and-codebuild) for supported
controls and buildspecs. Before offline work, prepare project images and any Git
or package dependencies. Idle fleet capacity also requires an installed immutable
image:

```sh
FLEET_IMAGE=$(docker image inspect --format '{{.Id}}' local/stackd-workload:prepared)
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -codebuild-runtime \
  -codebuild-fleet-image "$FLEET_IMAGE"
```

The flag supplies capacity's image; create the actual fleet through CodeBuild APIs. AMI names/mutable tags are not a substitute for a pinned local fleet image.

## DynamoDB and Kinesis

Install these pinned native backends on the selected Engine; neither needs Lambda telemetry/storage helpers or ECS admission:

```sh
docker pull amazon/dynamodb-local@sha256:ff89bd48ff32cd8d9be5fee8873b65b8854dc408f1afe881be6eb00247bc0dab
docker pull apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -dynamodb-runtime -kinesis-runtime
```

`-dynamodb-runtime` enables [DynamoDB Local](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html);
`-kinesis-runtime` enables stackd's [Apache Kafka](https://kafka.apache.org/37/getting-started/quickstart/)-backed
Kinesis implementation. Enable either independently and omit unused images.
Pins are in [`engine/dynamodb`](../engine/dynamodb/docker.go) and
[`engine/kinesis`](../engine/kinesis/docker.go).

Using the local credentials above, create, write, read and delete a test table:

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
  -docker-host unix:///var/run/docker.sock -inventory-orc-runtime
```

[`engine/orc/Dockerfile`](../engine/orc/Dockerfile) pins:

- Maven build base: `maven:3.9.12-eclipse-temurin-17@sha256:a0603aab698040d9c94259f379ec0487da1678560748d6c7508483034033c53d`.
- Final JRE: `eclipse-temurin:17.0.18_8-jre-jammy@sha256:642d45bf22d3cb9face159181732ed9fa70873b2681e50445eff7d4785c176bb`.

The build downloads [Apache ORC](https://orc.apache.org/) tools `2.2.2` through
Maven. Build and export the image before going offline.

With `-inventory-orc-runtime` enabled, configure S3 inventory in ORC format and
its destination bucket/policy through the local S3 APIs. Check the delivered
manifest and ORC object using [inventory delivery](cloudtrail.md). Building the
image alone does not enable or schedule inventory.

## Glue and Athena

Read the [AWS Glue license](../compute/glue/AWS-GLUE-LICENSE.txt) before installing
the image. Its Amazon Software License permits the documented AWS-targeted
development/testing use, not general standalone or other-cloud use or
redistribution. Install Glue only if your use meets those terms. See
[AWS's local Glue development guide](https://docs.aws.amazon.com/glue/latest/dg/develop-local-docker-image.html).

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

Enable Glue or Athena independently and omit unused engine images. Defaults are:

- Glue: Spark 3.5.4-amzn-0/Python 3.11 and Python-shell Python 3.9. The Python-shell
  image does not contain the full Glue analytics library bundle.
- Athena: Trino 476 and Spark 4.1.3, used only to parse Hive DDL.

Installed immutable overrides are `-glue-spark-image`, `-glue-python-image`,
`-athena-image` and `-athena-hive-ddl-image`. Upstream setup references:
[Trino Docker](https://trino.io/docs/current/installation/containers.html) and
[Apache Spark](https://spark.apache.org/docs/latest/).

Athena checks whether the controller and Docker daemon share Linux loopback at
startup. A local rootful Linux daemon uses host networking with Trino bound to
`127.0.0.1` on an allocated port; it does not publish port 8080 or create query
bridges. Stackd verifies the Trino process identity before submitting SQL.
A port conflict fails startup.

Remote daemons, rootless/user-namespace engines and non-Linux controllers use
bridge mode. A Unix socket alone does not establish that a daemon is local.
`-athena-endpoint-host` applies only to bridge mode.

Local callbacks default to `127.0.0.1:0` and host `127.0.0.1`. Explicit
`-athena-callback-listen` and `-athena-callback-host` values remain unchanged,
including an existing container-reachable host address. Other daemons retain
loopback-published bridge SQL (`-athena-endpoint-host 127.0.0.1` by default),
`-athena-callback-listen 0.0.0.0:0`, and
`-athena-callback-host host.docker.internal`. Remote operators must provide
controller-to-daemon SQL routing and daemon-to-controller callback routing.
Permit callbacks without exposing them to untrusted networks; these endpoints
do not replace the main compute/public endpoints.

Athena allows one active query per adapter and keeps a Trino engine warm for
each partition/account/region, with a two-minute idle timeout. There is no result
cache. Each query receives separate callback authorization and fresh
Hive/Iceberg/Delta catalogs. Previous callback authorization is revoked before
the next query. Customer SQL can use catalogs but cannot create/drop them or
read the private JMX probe.

Stackd checks engine ownership, image, endpoint and process identity before
reuse and at teardown. Failed identity checks retire the engine; cleanup
failures are reported as infrastructure errors and retain recovery metadata.

An explicit Glue catalog keeps its name and semantics when it collides with an
internal connector alias. Only the private redirect aliases move; customer SQL
is not rewritten.

Dynamic catalogs use file storage in container tmpfs. Engines retire after
64 queries or a changed workgroup scan limit, in addition to the idle timeout.
The workgroup physical-byte limit is a cluster setting that customer sessions
cannot raise.

Cancellation targets the native query ID. Ambiguous transport or cancellation
results retire the engine before reuse. Completed or legacy cancellation
handles cannot remove a later query's engine.

Preserve Athena's ownership directory alongside controller state. The CLI uses
`<database>.athena` with SQLite; memory-only controllers use the user cache
directory under `stackd/athena-<daemon-and-configured-listener-hash>`.
The directory stores fsynced creation receipts, and an exclusive kernel lock
prevents overlapping controllers.

Embedded callers must provide a private, durable `DockerConfig.StateDirectory`
and close the runtime after the stack. On reopening, cleanup matches engine/parser
names, random owner labels and immutable image identities. Interrupted SQL is
neither adopted nor replayed.

Graceful close cancels active work and removes idle engines, waiting up to
30 seconds. If a callback remains active, the ownership lock stays held until
background cleanup finishes, preventing a replacement controller from racing it.

Use a trusted host, not an untrusted multi-tenant host. Trino's host networking
allows access to host-network services even with capabilities dropped. The
Hive-DDL parser uses a separate `none` network.

Trino query history contains the ephemeral callback capability in dynamic
catalog SQL. This is not an AWS credential; it is revoked at query completion.

For background on local networking, see
[issue #9](https://github.com/radkawar/stackd/issues/9). Upstream references:
[Trino 476 image tools](https://github.com/trinodb/trino/blob/476/core/docker/Dockerfile),
[Airlift 336 bind configuration](https://github.com/airlift/airlift/blob/336/node/src/main/java/io/airlift/node/NodeConfig.java),
[actual HTTP bind](https://github.com/airlift/airlift/blob/336/http-server/src/main/java/io/airlift/http/server/HttpServer.java),
and [Trino JMX node identity](https://github.com/trinodb/trino/blob/476/plugin/trino-jmx/src/main/java/io/trino/plugin/jmx/JmxRecordSetProvider.java).

To check Athena networking, engine reuse, callback isolation, cancellation and
cleanup, run these tests on a quiet, dedicated Linux Docker host with both
pinned images installed:

```sh
go test ./engine/athena -run '^(TestDockerNetwork|TestWarmEngine)' -count=1 -timeout 2m
go test -race ./engine/athena -run '^(TestDockerNetwork|TestWarmEngine)' -count=1 -timeout 3m
STACKD_ATHENA_NETWORK_DOCKER_HOST=unix:///var/run/docker.sock \
  go test ./engine/athena -run '^(TestDockerNetworkNative|TestWarmEngineNativeLifecycle)$' -count=1 -timeout 15m -v
```

Pinned upstream support and cautions:
[Trino 476 catalog management](https://github.com/trinodb/trino/blob/476/docs/src/main/sphinx/admin/properties-catalog.md),
[CREATE CATALOG syntax](https://github.com/trinodb/trino/blob/476/docs/src/main/sphinx/sql/create-catalog.md),
and [catalog owner/all access modes](https://github.com/trinodb/trino/blob/476/lib/trino-plugin-toolkit/src/main/java/io/trino/plugin/base/security/CatalogAccessControlRule.java).
Dynamic catalog management is experimental in Trino 476; use the pinned engine.
Query timeouts and result-cache behavior are unchanged by engine reuse.
The file catalog store reads `etc/catalog-store.properties` from the launcher
data directory, separately from the main server configuration.
Stackd configures both paths.

Provision S3 script, data and output locations and IAM roles. For Glue, call
`CreateJob`/`StartJobRun` and poll `GetJobRun`. For Athena, call
`StartQueryExecution` and poll `GetQueryExecution`. Retrieve the output to confirm
completion.

See the [analytics service guide](behavior-references.md#glue-and-athena-engines-evidence-and-boundaries)
for supported catalogs, job types and SQL. AWS-specific bookmarks, Lake Formation
vending, Glue Parquet writer and Data Quality require separate compatibility
validation; ordinary Spark/Trino execution does not validate them.
Preserve S3 data/output and engine state alongside SQLite control state.

## RDS

```sh
docker pull postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652
docker pull mysql@sha256:0744ee5ef89ce6ccfa13de3e579fe6b9e27f93dd70da9c06d2c908b1b193fb8d
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -rds-runtime
```

The Docker Official Images run PostgreSQL 17.11 and MySQL 8.4.11. See the
[PostgreSQL](https://hub.docker.com/_/postgres) and
[MySQL](https://hub.docker.com/_/mysql) image requirements. Installed immutable
overrides `-rds-postgres-image` and `-rds-mysql-image` must retain the required
engine layout.

Configure SQL access with:

- `-rds-endpoint-host`: advertised address and PostgreSQL certificate identity;
  defaults to `127.0.0.1`.
- `-rds-publish-address`: daemon-side SQL bind/reservation address; defaults to
  `127.0.0.1` for loopback-only access.

For trusted EKS pods routed to the host bridge, set both to the bridge IP, such
as `172.17.0.1`. Restrict non-loopback SQL access with the host firewall.
A wildcard bind such as `0.0.0.0` is not an endpoint or certificate SAN.
Existing containers must match the configured bind address; endpoint changes
must still verify against retained trust.

Export the per-incarnation PostgreSQL public CA and connect with
`sslmode=verify-full`. Publication settings do not enable MySQL TLS or VPC
security-group enforcement. `-native-ports` applies only to new automatic
allocations: omit an explicit RDS port to use the pool.

Create an instance/cluster through RDS APIs, wait for its Describe status and
connect to the returned PostgreSQL/MySQL endpoint with its credentials.
See [setup](rds.md#running-the-native-engines),
[lifecycle](rds.md#ownership-and-lifecycle) and [Data API](rds.md#rds-data-api)
for supported provisioning and SQL operations. AWS managed storage and topology
are unsupported; engine compatibility is limited to the documented operations.

Preserve database and snapshot Docker volumes alongside SQLite, which does not
contain SQL data. Stop/start controls engine processes; deletion removes owned
data.

## DocumentDB compatibility

```sh
docker pull mongo@sha256:84c4a18b60a0e73d1577112b0a600b46cab477c64cfe0ff36d0647bbca055bd0
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -docdb-runtime
```

The [Docker Official MongoDB image](https://hub.docker.com/_/mongo) runs version
7.0.43, not AWS DocumentDB's engine. `-docdb-image` accepts an installed immutable
MongoDB compatibility image; it cannot install AWS's proprietary engine.

Follow [DocumentDB setup](documentdb.md#native-setup) to create a cluster/instance,
wait for readiness and connect using the returned TLS endpoint and CA.
Preserve engine and snapshot volumes alongside SQLite. See
[compatibility differences](documentdb.md#explicit-differences-and-remaining-operations)
for supported MongoDB/change-stream behavior and unsupported cloud capabilities.

## OpenSearch

Follow the [OpenSearch Docker requirements](https://docs.opensearch.org/docs/latest/install-and-configure/install-opensearch/docker/).
On Linux, inspect `sysctl vm.max_map_count`; it must be at least `262144`.
An administrator can set `sudo sysctl -w vm.max_map_count=262144` and persist it
in the distribution's sysctl configuration. Coordinate changes on shared hosts.

```sh
docker pull opensearchproject/opensearch@sha256:9e0b3b3b6805811bd63d9b9503ffe34a58ba33d03cc346000e318c6ff5c05bd9
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -opensearch-runtime
```

The image runs OpenSearch 2.19.4; select `OpenSearch_2.19` when creating a domain.
Call `CreateDomain`, poll `DescribeDomain` for readiness, then use the domain's
scoped HTTP endpoint for search requests. See
[provisioning](implementation-reference.md#native-opensearch) and
[supported operations](behavior-references.md#opensearch-engines-evidence-and-boundaries).

Each domain has one node, a volume/network and a private loopback REST listener.
Multi-node/AZ, VPC, EBS, KMS, TLS, fine-grained security and Dashboards are
unsupported. Deploy only where local host processes and Docker administrators
are trusted.

## MSK

```sh
docker pull apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock -msk-runtime
```

The image runs Apache Kafka 3.7.1 and is shared with Kinesis.
`-msk-image` must resolve to the expected content. `-msk-endpoint-host` defaults
to `127.0.0.1` for operator-local public-client listeners.

Create a provisioned cluster with:

- `KafkaVersion=3.7.1`.
- One to three brokers.
- `BrokerNodeGroupInfo.InstanceType=kafka.local`, a local selector rather than
  an AWS instance type.
- The required `ClientSubnets` field set to an empty list.

Poll `DescribeCluster`/`DescribeClusterV2`, retrieve `GetBootstrapBrokers`, then
connect a Kafka producer/consumer using the configured authentication mode.
See [MSK public Kafka brokers](behavior-references.md#msk-public-kafka-brokers).
ZooKeeper endpoints, managed VPC/AZ/EBS and AWS network isolation are unsupported.
Preserve each broker's volumes alongside SQLite.

## Valkey and local TLS

Install the [official Valkey image](https://valkey.io/topics/installation/):

```sh
docker pull valkey/valkey@sha256:1cb6b20b70d927560cc4cc5397b5f045e74aa603ff7696274778880bb6fadc75
```

TLS resources need a PEM certificate and key covering **IP `127.0.0.1`**.
Install OpenSSL through your distribution. For private local development, this
[OpenSSL command](https://docs.openssl.org/3.0/man1/openssl-req/) creates a
self-signed trust anchor/server certificate for Valkey and MQ.
Use a new private directory; do not overwrite certificates used by retained
resources.

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

Configure clients to trust `local.crt`, for example with
`valkey-cli --tls --cacert /absolute/path/local.crt -h 127.0.0.1 -p PORT`.
Use the API-returned port and required credentials, with certificate verification
enabled. Keep the private key on the host and retain the certificate for clients
and restarts. This self-signed setup is for development; plan rotation before
expiry rather than replacing files under live resources.

Create ElastiCache/MemoryDB resources, users and ACLs through their APIs. Poll
Describe status, then connect and issue a Valkey command. See
[Valkey setup](behavior-references.md#explicit-setup) for supported topology,
authentication and versions.

MemoryDB defaults to TLS and permits plaintext only with the open-access ACL.
Authenticated ElastiCache requires TLS. `-valkey-image` accepts an installed
immutable image subject to version checking. The runtime requires a local Unix
daemon and exposes loopback endpoints, not an AWS VPC. Preserve data and snapshot
volumes alongside SQLite.

## Amazon MQ

Prepare the TLS files above and both broker images; an MQ-only launch does not need Lambda telemetry/storage helpers or ECS admission:

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

The controller extracts JMS/OpenWire JARs from the installed ActiveMQ image and
compiles its bridge with `javac`, without runtime Maven downloads. The JDK must
support `--release 11` for the metrics reader.

The MQ state directory contains configuration, keystores, compiled helpers and
sensitive credentials. It must be private and local to the daemon for bind
mounting. Retain it with TLS material, broker data volumes and SQLite.

The images run RabbitMQ 3.13.7 and ActiveMQ Classic 5.18.7. Upstream references:
[RabbitMQ installation](https://www.rabbitmq.com/docs/download) and
[ActiveMQ Classic Docker](https://activemq.apache.org/components/classic/documentation/docker).

Call `CreateBroker` with the pinned engine version and public `SINGLE_INSTANCE`,
`mq.t3.micro`, SIMPLE authentication configuration. RabbitMQ also requires the
modeled service-linked-role authority. Poll `DescribeBroker` for `RUNNING`,
then connect to the returned TLS AMQP/OpenWire endpoint using the trusted
certificate and broker user.

Java clients need their own JMS libraries and trust store; the internal bridge
does not install them. Test the intended user's connection and destination
permissions, since broker readiness does not validate that user's ACL.
See [MQ execution and lifecycle](mq.md#actual-execution-and-durable-ownership)
for configuration, authentication and deletion.

Public endpoints here are operator-local loopback listeners, not Internet-facing
AWS DNS. Replicated fleets, private VPC isolation and AWS encrypted managed
storage are unsupported.

## ALB relay

ALB requires the shared Linux Docker host, SQLite and EC2 bridge/policy management.
See [VM deployment](runtime-vms.md) and [EC2 networking](ec2.md) for host setup.
Build a static Linux relay matching the daemon host architecture. On a Linux
source-build host:

```sh
CGO_ENABLED=0 go build -o bin/stackd-elbv2-node ./cmd/stackd-elbv2-node
./bin/stackd -listen 0.0.0.0:4566 -database "$PWD/data/stackd.sqlite" \
  -docker-host unix:///var/run/docker.sock \
  -elbv2-node-executable "$PWD/bin/stackd-elbv2-node" \
  -dns-listen 127.0.0.1:5353
```

Pass the relay's absolute installed path and retain it for reattachment.
Stackd mounts it into toolkit containers; no separate ALB server image is needed.

Through the local APIs, create EC2 VPC/subnets/security groups, an application
load balancer, target group, targets and listener. Check load-balancer state and
target health, then send a request to the returned hostname. See
[EC2](ec2.md) and [DNS routing](route53.md#dns-resolution-and-delegation-boundary).

Configure clients to use stackd's authoritative DNS listener over both UDP and
TCP; system DNS does not automatically resolve these names. Without
`-dns-listen`, ALB allocates a loopback DNS port and prints it at startup.
The example uses port 5353, which must be free. The main API, DNS and ALB data
listeners use separate ports.

## ECR scanner

Basic vulnerability scanning requires **Trivy 0.74.0** and a separately prepared
**schema-2 vulnerability DB**; Docker is not required. Download the binary from
the [official release](https://github.com/aquasecurity/trivy/releases/tag/v0.74.0).
This connected preparation example uses Linux amd64. For arm64, choose the
release's `Linux-ARM64` archive.

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

Verify published signatures using [Trivy's installation guidance](https://trivy.dev/latest/getting-started/installation/)
and your supply-chain policy. Checksums detect corruption but do not independently
authenticate the publisher.

For offline use, transfer the binary and complete cache, including `db/trivy.db`
and `db/metadata.json`, following [Trivy's air-gap instructions](https://trivy.dev/latest/advanced/air-gap/).
Record the DB metadata and refresh it during connected maintenance; the database
changes independently of the pinned executable. Startup does not download it.

```sh
./bin/stackd -listen 127.0.0.1:4566 -database "$PWD/data/stackd.sqlite" \
  -ecr-scanner "$PWD/tools/trivy/trivy" \
  -ecr-scanner-cache "$PWD/data/trivy-cache"
```

This scanner-only launch needs no `-docker-host`. To combine scanning with
compute, add both scanner flags to the shared Docker launch.

Create an ECR repository, upload a supported OCI/Docker image's manifest,
configuration and layers, call `StartImageScan`, then poll
`DescribeImageScanFindings`. See [ECR and CodeBuild](behavior-references.md#ecr-and-codebuild)
for supported uploads and image formats.

A missing DB/executable, wrong version or unsupported image is a scan failure,
not a clean result. Findings reflect the installed Trivy version and DB, which
can differ from AWS's scanner database.

## Shutdown and retained state

Use Ctrl-C/SIGTERM for graceful controller shutdown. Lambda environments close;
durable database, broker, ECS and other engines have service-specific
detach/reattach behavior with SQLite. To stop or delete resources, use their
service APIs and inspect terminal state before retiring metadata. Deletion can
destroy engine data; stopping does not delete it.

Retain the stable SQLite path, owned Docker volumes/networks, MQ state/TLS files,
helper paths and external source/output data together. SQLite stores control
state, not all engine data. Use service snapshot/backup operations and retain
ownership metadata.

With in-memory repositories, graceful CLI shutdown attempts to delete owned
engines. This does not cover every workload or cleanup after crashes/SIGKILL.
Do not use blanket `docker system prune`, volume removal or unrelated-container
cleanup as stackd shutdown.

Privileged setup helpers and Docker access require trusted operators.
The API's IAM model does not isolate host processes or provide hardened
multi-tenancy. Restrict API, callback, DNS and data listeners; avoid ambient cloud
credentials; and run untrusted applications on a separate host/network.
See [Operations](operations.md), [SQLite limits](sqlite-state.md) and each
service's lifecycle section for restart and recovery instructions.
