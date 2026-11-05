# Optional runtimes

Start with [Getting started](getting-started.md) to run the API emulator without
Docker. Add execution runtimes when you need functions, containers, databases or
virtual machines. Each runtime has separate prerequisites and opt-in flags.

## Choose a deployment recipe

Start with an installation and provisioning walkthrough, then use the flag
reference below to combine the backends you need in one controller:

- [Container and engine deployment](runtime-containers.md): selected Docker
  helper/runtime images, Lambda/ECS/CodeBuild, native databases, analytics,
  messaging engines, TLS, ALB helpers, offline scanning, and a native macOS
  controller / Docker Desktop recipe for opt-in Lambda/DynamoDB/Kinesis.
- [VM and Kubernetes deployment](runtime-vms.md): QEMU/KVM host preparation,
  firmware and guest-image import, pinned k3d/k3s installation, local EKS access,
  and the additional EC2 worker-image/network setup for managed node groups.

Prepare the backends you need, then start one controller with their combined
flags and stable state paths. Stop any previous controller before reusing its
database. There is no bundled VM image catalog or “enable everything” option.

## Build first, provision dependencies separately

Install a [published release](releases.md#install-a-published-release), or build
from source with Go 1.26.5 or newer:

Run from the repository root:

```sh
mkdir -p bin data
go build -o bin/stackd ./cmd/stackd
./bin/stackd -listen 127.0.0.1:4566 -database ./data/stackd.sqlite
```

The initial source build downloads Go modules unless cached. Install the required
engine images for your execution architecture before starting a runtime:
adapters use installed images and do not pull missing ones. Image override flags
do not install images or enable runtimes.

For Lambda source builds, use `make build` to produce `bin/stackd` and the static
Linux `lambda-telemetry-amd64` and `lambda-telemetry-arm64` helpers. Install the
helpers beside the controller, or set `-lambda-telemetry-directory`.
Published-release installation instructions cover the packaged artifacts.

Prepare binaries, images and dependencies before disconnecting for offline use.
Default API operation does not contact AWS, but application code and configured
HTTP/SMTP integrations can make outbound requests. Use host/network policy to
restrict egress.

## Shared Docker opt-in

`-docker-host` selects the Docker Engine connection; it does not enable runtimes.
Enable Lambda, ECS, CodeBuild, DynamoDB, Kinesis and ORC inventory separately with
`-lambda-runtime`, `-ecs-runtime`, `-codebuild-runtime`, `-dynamodb-runtime`,
`-kinesis-runtime` and `-inventory-orc-runtime`. All default to false.
Other services use the selectors in the table below.

ECS requires local rootful Linux Docker, systemd, cgroup v2, no user-namespace
remapping and the pinned `compute/docker.ToolkitImage`; see
[ECS setup](ecs.md#setup-and-supported-execution). ECS, EC2, EKS and ALB require
that local Linux host setup, not Docker Desktop, rootless Docker or a remote
daemon. Containerized controllers must share the daemon host's existing
`/run/lock` inode. Task containers do not receive helper privileges or mounts.

Lambda requires the storage image and static Linux telemetry helpers, plus a
Linux daemon supporting privileged storage helpers, loop devices, ext4,
`fallocate`, direct I/O and a daemon `/dev` bind. Function containers remain
unprivileged. Their `/tmp` quota uses disk, not memory-backed tmpfs.
VPC networking uses daemon-host namespaces, bridges and nftables with a shared
kernel lock. On Docker Desktop these facilities run inside the Linux VM.
Native macOS controllers support opt-in Lambda, DynamoDB and Kinesis through
Desktop; arbitrary remote engines are not supported by this recipe.
See the [Desktop recipe](runtime-containers.md#native-macos-controller-with-docker-desktop),
[Lambda setup](lambda.md#current-application-path) and
[storage/recovery](lambda.md#temporary-storage-and-crash-recovery).

For ORC inventory encoding, explicitly build the existing encoder image before use:

```sh
docker build -t stackd/orc:2.2.2 engine/orc
```

This prepares that encoder only; enable it with `-docker-host <actual-engine-url> -inventory-orc-runtime`. It is not a stackd server image and does not install or enable other runtimes.

## Networking before execution

The baseline API URL `http://127.0.0.1:4566` is for host-only clients. A normal Docker container cannot reach the host's loopback listener through its own `127.0.0.1`.

After installing the Lambda prerequisites, this Lambda-only launch binds the API on all IPv4 interfaces and lets the CLI derive `http://host.docker.internal:4566` as its container-facing compute endpoint:

```sh
./bin/stackd -listen 0.0.0.0:4566 -database ./data/stackd.sqlite \
  -docker-host unix:///var/run/docker.sock -lambda-runtime
```

Binding to `0.0.0.0` exposes the API on all IPv4 interfaces. Restrict access to
trusted clients. When containers consume returned resource URLs, provision
resources through an address reachable from both the host and containers.
For example, a queue URL containing `127.0.0.1` points back to the container
when used inside Lambda, regardless of the SDK's default endpoint.

Configure the addresses separately:

- `-listen` sets the API bind address.
- `-public-endpoint` sets the address in advertised resource URLs.
- `-compute-endpoint` sets the AWS API address used by execution runtimes.

Lambda, ECS, CodeBuild, Glue and EC2 guest execution require a reachable compute
endpoint. Without an explicit setting, a loopback listener prevents selection of
that endpoint. Docker configuration alone and DynamoDB/Kinesis-only launches do
not impose this check. Setting a loopback URL explicitly does not make it
reachable from containers.

Lambda Runtime API callbacks use a separate server. `-lambda-runtime-listen`
sets its bind address, and `-lambda-callback-host` sets the hostname used by the
function's runtime client. Set `host.docker.internal` for Docker Desktop; leaving
it empty uses Linux host-gateway. Desktop resolves the hostname inside the
container, without a controller-side DNS lookup or host mapping.

For HTTPS, configure matching certificate names and trusted CA certificates in
each client. These endpoint flags do not modify host DNS or trust stores.

## Execution selection and prerequisites

Boolean runtime flags below default to `false`. Supplying `-docker-host` alone does **not** enable the separately gated engines.

| Workload | Flags and prerequisites | Setup guide |
| --- | --- | --- |
| Lambda ZIP/image functions | `-docker-host -lambda-runtime`; installed official ZIP runtime images or customer image, Linux telemetry helpers and storage helper; toolkit for VPC networking. | [Lambda](lambda.md#current-application-path) |
| Lambda managed instances | QEMU/EC2 plus a guest AMI containing official SSM, Docker, pinned runtimes and the compiled managed agent; explicit instance profile/type and runtime mappings. | [Managed guest deployment](runtime-vms.md#managed-instance-lambda) |
| ECS tasks/services | `-docker-host -ecs-runtime`; local Linux host admission, pinned toolkit, installed customer images, supported Linux Fargate/`awsvpc` configuration and IAM/network resources. | [ECS setup](ecs.md#setup-and-supported-execution) |
| CodeBuild | `-docker-host -codebuild-runtime` and reachable compute endpoint; installed build images. `-codebuild-fleet-image` supplies an immutable local image for idle fleet capacity. | [ECR and CodeBuild](behavior-references.md#ecr-and-codebuild) |
| DynamoDB / Kinesis | `-docker-host` plus `-dynamodb-runtime` and/or `-kinesis-runtime`; installed native DynamoDB Local / Apache Kafka images, not Lambda/ECS helpers. | [DynamoDB](behavior-references.md#dynamodb-engine-references), [Kinesis](behavior-references.md#imported-record-engine-experiments) |
| S3 ORC inventory | `-docker-host -inventory-orc-runtime`; explicitly build the encoder above. | [S3 inventory](cloudtrail.md) |
| Glue / Athena | `-glue-runtime` and/or `-athena-runtime`, plus Docker and the documented immutable images. | [Analytics engines and licensing](behavior-references.md#glue-and-athena-engines-evidence-and-boundaries) |
| RDS | `-rds-runtime`, Docker, installed pinned PostgreSQL/MySQL images. | [RDS setup](rds.md#running-the-native-engines) |
| DocumentDB compatibility | `-docdb-runtime`, Docker, installed pinned MongoDB compatibility image; this is not AWS DocumentDB's engine. | [DocumentDB setup](documentdb.md#native-setup) |
| OpenSearch | `-opensearch-runtime`, Docker, installed pinned OpenSearch image. | [Search engines and boundaries](behavior-references.md#opensearch-engines-evidence-and-boundaries) |
| MSK | `-msk-runtime`, Docker, installed pinned Kafka image for supported public clusters. | [MSK public brokers](behavior-references.md#msk-public-kafka-brokers) |
| ElastiCache / MemoryDB | `-valkey-runtime`, local Docker, installed immutable Valkey image; certificate and key for TLS resources. | [Valkey setup](behavior-references.md#explicit-setup) |
| Amazon MQ | `-mq-runtime`, Docker, `-mq-state-directory`, explicit `-mq-tls-certificate` and `-mq-tls-key`; installed broker engines and Java/JMS dependencies. | [MQ execution and ownership](mq.md#actual-execution-and-durable-ownership) |
| EC2 / EBS guest execution | `-ec2-state-directory`, SQLite, local Docker, QEMU/KVM tools, firmware and prepared guest images. | [EC2](ec2.md) |
| EKS | `-eks-state-directory`, SQLite, Docker, installed pinned k3d and node images; EC2 workers need their own guest setup. | [EKS runtime selection](eks.md#explicit-runtime-selection) |
| ALB execution | `-elbv2-node-executable`, SQLite, Docker and shared EC2 bridge/policy owners; explicitly build the static Linux relay below. | [EC2 networking](ec2.md), [DNS](route53.md#dns-resolution-and-delegation-boundary) |
| ECR basic vulnerability scans | `-ecr-scanner` plus `-ecr-scanner-cache`: Trivy 0.74.0 and pre-provisioned schema-2 vulnerability DB. | [ECR scanning](behavior-references.md#ecr-and-codebuild) |

Build the ALB relay explicitly and pass its **absolute path** to `-elbv2-node-executable`:

```sh
CGO_ENABLED=0 go build -o bin/stackd-elbv2-node ./cmd/stackd-elbv2-node
```

ALB hostnames use the authoritative UDP/TCP listener selected with `-dns-listen`, or an ephemeral loopback DNS port printed at startup. Clients must explicitly use that resolver.

Glue's AWS-library image has a separate [upstream license](../compute/glue/AWS-GLUE-LICENSE.txt), restricted to permitted AWS-targeted development/testing, not general standalone or other-cloud use. Check that license independently before using or redistributing the image.

## Runtime flag reference

The table lists exact CLI defaults. “Empty override” means the adapter selects its pinned default; consult its service guide for the current image, rather than treating an empty string as an image reference. Image overrides do not implicitly enable a runtime.

| Flags | Defaults and purpose |
| --- | --- |
| `-docker-host`, `-compute-endpoint` | Empty; explicit Docker Engine URL and reachable AWS origin. Compute default selection is described above. |
| `-lambda-runtime`, `-ecs-runtime`, `-codebuild-runtime`, `-dynamodb-runtime`, `-kinesis-runtime`, `-inventory-orc-runtime` | All `false`; enable the corresponding runtimes and require `-docker-host`. |
| `-lambda-callback-host` | Empty uses Linux host-gateway; explicit `host.docker.internal` preserves Desktop's container DNS without host resolution/mapping. Requires `-lambda-runtime`. |
| `-lambda-runtime-listen` | `0.0.0.0:0`; Runtime API bind address. |
| `-lambda-telemetry-directory` | Empty uses the stackd executable's directory; contains static Linux helpers, including for a native macOS controller. Requires `-lambda-runtime` when supplied. |
| `-lambda-keep-alive` | `10m`; warm idle lifetime in service time; `0` forces cold invocations. |
| `-lambda-storage-image` | Empty override; installed immutable disk-storage helper. Requires `-lambda-runtime` when supplied. |
| `-lambda-hot-reload-code`, `-lambda-hot-reload-layers` | Repeatable `unqualified-function-arn=/absolute/path`; no mappings by default; requires `-docker-host -lambda-runtime`. Development source directories, not deployment persistence. |
| `-lambda-managed-image-id`, `-lambda-managed-instance-profile`, `-lambda-managed-instance-type` | Empty disables managed capacity; select a prepared AMI, guest instance-profile ARN and supported EC2 guest type. |
| `-lambda-managed-runtime-image` | Repeatable `runtime:architecture=image@sha256:digest` installed inside the guest; no default mappings. |
| `-lambda-managed-agent-port` | `9443`; private guest HTTPS management port, requiring controller-to-guest admission. |
| `-codebuild-fleet-image` | Empty; installed local image ID/digest for idle fleet capacity. Requires `-codebuild-runtime`. |
| `-ecr-scanner`, `-ecr-scanner-cache` | Both empty; executable and offline vulnerability DB cache, required together. |
| `-glue-spark-image`, `-glue-python-image` | Empty immutable image overrides; require `-glue-runtime`. |
| `-athena-image`, `-athena-hive-ddl-image` | Empty immutable Trino / Apache Spark DDL-parser image overrides; require `-athena-runtime`. |
| `-athena-endpoint-host` | `127.0.0.1`; Docker host address reachable by the controller for SQL requests. |
| `-athena-callback-listen`, `-athena-callback-host` | `0.0.0.0:0`, `host.docker.internal`; owned Glue/S3 callback bind and container-facing hostname. |
| `-rds-postgres-image`, `-rds-mysql-image` | Empty immutable overrides; require `-rds-runtime`. |
| `-rds-endpoint-host` | `127.0.0.1`; Docker host address visible to native database clients. Native ports bind daemon loopback. |
| `-docdb-image` | Empty immutable compatibility-engine override; requires `-docdb-runtime`. |
| `-msk-image`, `-msk-endpoint-host` | Empty immutable Kafka override, `127.0.0.1` public-client loopback IP; image override requires `-msk-runtime`. |
| `-valkey-image`, `-valkey-tls-cert`, `-valkey-tls-key` | Empty image override and PEM TLS paths; require `-valkey-runtime`. Certificate must cover `127.0.0.1` for native TLS endpoints. |
| `-mq-state-directory`, `-mq-tls-certificate`, `-mq-tls-key`, `-mq-java` | Empty; private native state, certificate covering `127.0.0.1`, matching key, and installed Java executable with matching `javac`. MQ settings require `-mq-runtime`; state and TLS paths are required when enabled. |
| `-elbv2-node-executable` | Empty disables native ALB sockets; installed static relay path enables them and requires SQLite/Docker. |

Guest and Kubernetes configuration is deliberately explicit:

| Flags | Defaults and purpose |
| --- | --- |
| `-ec2-state-directory` | Empty disables QEMU/KVM; nonempty requires SQLite and local Docker. |
| `-ec2-bios`, `-ec2-uefi-code`, `-ec2-uefi-vars` | Empty; operator-installed legacy BIOS, UEFI code, and per-instance-copy UEFI variable-store template. |
| `-ec2-dns-upstream` | No forwarders by default (local names only); repeat for explicit IPv4 DNS forwarders. |
| `-eks-state-directory` | Empty disables k3d; nonempty requires SQLite and Docker. |
| `-eks-k3d` | Empty selects `k3d`; the pinned version is required. |
| `-eks-listen-host`, `-eks-endpoint-host` | Both `127.0.0.1`; Kubernetes API bind and client-facing address. |
| `-eks-worker-advertise-host` | Empty; explicit host IP reachable by EC2 workers. |
| `-eks-node-images` | Empty; optional JSON file mapping Kubernetes minor versions to imported worker `imageId`, `releaseVersion`, `amiType`; see [EKS](eks.md). This is a specific mapping input, not a general stackd configuration file. |
| `-lambda-managed-image-id`, `-lambda-managed-instance-profile`, `-lambda-managed-instance-type` | Empty; prepared EC2 AMI with SSM/Docker/stackd-lambda-agent, instance profile ARN, installed guest type. |
| `-lambda-managed-agent-port` | `9443`; private guest HTTPS agent port. |
| `-lambda-managed-runtime-image` | Repeatable `runtime:architecture=digest-pinned-reference`, installed in the guest; no mappings by default. |

The EC2 CLI finds `qemu-system-x86_64`, `qemu-img`, `qemu-nbd`, `qemu-io`,
`dnsmasq` and `dhcp_release` on PATH. Prepare firmware, disks, networking and
guest images before launching instances. Managed Lambda also requires SQLite,
the EC2 runtime, all three managed image/profile/type settings, at least one
installed runtime mapping and a valid agent port. See
[managed Lambda capacity](lambda.md#managed-instances-and-capacity-providers).

## Isolation, shutdown and retained state

Execution runtimes run application code and engine processes with access to host
resources. Use a trusted host: Docker administrators, local processes and
privileged setup helpers are outside API IAM controls.

Lambda uses containers and disk-backed temporary storage. ECS manages task
network namespaces, cgroups, volumes and packet rules. Database and search
listeners commonly bind Docker-host loopback, so clients must be able to reach
that host.

SQLite stores control-plane state. Retain engine volumes, guest disks,
configuration directories and cluster state separately.

Graceful shutdown closes Lambda environments. Persistent ECS workloads,
databases, EC2 guests and EKS clusters can remain running after stackd exits.
See [ECS recovery](ecs.md#runtime-ownership-dependencies-and-recovery),
[RDS lifecycle](rds.md#ownership-and-lifecycle),
[EKS ownership](eks.md#explicit-runtime-selection) and [SQLite state](sqlite-state.md).

Without SQLite, the CLI attempts graceful cleanup of the DynamoDB, Kinesis,
RDS, DocumentDB, OpenSearch, MSK, MQ and Valkey resources tracked in memory.
This cleanup is not guaranteed after a crash or SIGKILL. With SQLite, those
engines are retained when the controller exits.

Stop or delete workloads through their service APIs. Do not use blanket Docker
pruning to shut down stackd; it can remove unrelated resources and stored data.
Follow [Operations](operations.md) for shutdown, backups and restart procedures.
Go embedders must also close runtimes they supply to the stack.
