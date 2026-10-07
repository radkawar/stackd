# Optional runtimes

The basic stackd API emulator needs **no Docker**. Start with [Getting started](getting-started.md) and [Configuration](configuration.md). Add native dependencies only for the execution paths you need. This guide describes the existing CLI, not a new deployment package or an automatic installer.

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

There is no implicit “enable everything” mode or bundled VM image catalog.
Prepare each selected backend, stop the previous controller, and start one
controller with the combined flags and stable state paths. The
[README deployment examples](../README.md#deploy-execution-runtimes) show the
main launch shapes.

## Build first, provision dependencies separately

The baseline source build is:

```sh
mkdir -p bin data
go build -o bin/stackd ./cmd/stackd
./bin/stackd -listen 127.0.0.1:4566 -database ./data/stackd.sqlite
```

Go 1.26.5 or newer is required. The initial build may download Go modules. That is separate from running the emulator: default operation does not contact AWS. Likewise, pulling or building an execution image is an explicit preparation step that may need network access. Runtime adapters consume **already installed images**; they do not silently pull missing images. Prepare dependencies before disconnecting for offline use. Application code or explicitly configured HTTP/SMTP integrations may themselves make network requests; “offline” is not an outbound firewall.

There is no implied published stackd Docker image or prebuilt release in these instructions. Use the source build. For Lambda, `go build` alone does not produce the telemetry helpers: `make build` additionally builds static Linux `lambda-telemetry-amd64` and `lambda-telemetry-arm64` next to `bin/stackd`. Install those artifacts together, or point `-lambda-telemetry-directory` at their directory.

Install the exact engine/helper images documented by each service, for the architecture you will execute. An override flag does not install an image. Missing runtime support, incompatible images or unsupported capabilities fail explicitly, rather than falling back to simulated successful execution.

## Shared Docker opt-in

`-docker-host` defaults to empty and selects Engine transport only when supplied. It does **not** enable Lambda, ECS, CodeBuild, DynamoDB, Kinesis or ORC inventory. Their independent flags are `-lambda-runtime`, `-ecs-runtime`, `-codebuild-runtime`, `-dynamodb-runtime`, `-kinesis-runtime` and `-inventory-orc-runtime`, all defaulting to false. Each constructs only its own real boundary; there is no implicit compatibility shim or image pull. The other service-specific selectors remain unchanged.

Only when `-ecs-runtime` is requested does ECS require local rootful Linux Docker, without user-namespace remapping, with systemd and cgroup v2, and the installed pinned `compute/docker.ToolkitImage`. See [ECS setup](ecs.md#setup-and-supported-execution). Containerized controllers for the original local-host consumers must share the daemon host's existing `/run/lock` inode; helper privileges/mounts are not exposed to task containers. ECS/EC2/EKS/ALB retain that local Linux host-security contract; it is not a promise of Docker Desktop, rootless Docker or arbitrary remote-engine support for those consumers.

Lambda requires its preinstalled storage image and static Linux telemetry helpers, plus a real Linux daemon supporting privileged storage helpers, loop devices, ext4, `fallocate`, direct I/O and a daemon `/dev` bind. Function containers remain unprivileged. Its `/tmp` quota is disk-backed, not tmpfs charged against function memory. On Docker Desktop these helpers execute **inside the actual Linux VM**, not on macOS. Lambda VPC networking uses real daemon/VM network namespaces, bridges and nftables with daemon identity and shared kernel `flock` ownership; it does not borrow a macOS host lock to pretend to own VM packet policy. Native macOS controller builds are supported, and opt-in Desktop Lambda/DynamoDB/Kinesis is the intended real-VM contract; no actual macOS run was observed for this documentation change. See the [Desktop recipe](runtime-containers.md#native-macos-controller-with-docker-desktop), [Lambda setup](lambda.md#current-application-path) and [storage/recovery](lambda.md#temporary-storage-and-crash-recovery). Missing capabilities fail explicitly; arbitrary remote engines are not promised.

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

This deliberately broadens network exposure; restrict the host/network boundary to trusted clients. Host tools may still use `http://127.0.0.1:4566` for local-only calls, but that origin is unsuitable for resource URLs that a container must later consume. For such workflows, choose an origin reachable from both host and containers, provision resources through that origin, and set `-public-endpoint` and `-compute-endpoint` to the corresponding reachable origins. For example, a queue URL created through a loopback endpoint can still direct an SDK inside Lambda back to container loopback, even when its default endpoint is correct. Do not patch returned URLs or inject per-handler SDK shims to conceal a routing mistake.

`-public-endpoint` controls advertised URLs; `-compute-endpoint` controls the execution-facing AWS endpoint; neither changes where `-listen` binds. Lambda, ECS, CodeBuild, Glue and EC2 guest execution request a default compute origin: without an explicit compute endpoint, a loopback listener fails that selection. `-docker-host` alone and DynamoDB/Kinesis-only launches do not impose this check. An explicit loopback URL does **not** make it reachable from a container. Some host-side engine guides use explicit loopback origins for controller-only access; that is not a general Lambda/ECS networking recipe.

Lambda Runtime API callbacks are a fourth, separate connection: `-lambda-runtime-listen` binds the callback server and `-lambda-callback-host` advertises where its actual container RIC/bootstrap reaches that server. Explicit `host.docker.internal` uses Desktop's container DNS without controller-side resolution or a shadow host mapping; empty callback host uses Linux host-gateway. Engine-specific settings below do not replace the main AWS API endpoint. HTTPS requires matching names and trusted CA material for every client; stackd does not rewrite host DNS or trust stores.

## Execution selection and prerequisites

Boolean runtime flags below default to `false`. Supplying `-docker-host` alone does **not** enable the separately gated engines.

| Workload | Opt-in and additional preparation | Detailed contract |
| --- | --- | --- |
| Lambda ZIP/image functions | `-docker-host -lambda-runtime`; installed official ZIP runtime images or customer image, Linux telemetry helpers and storage helper; toolkit for VPC networking. | [Lambda](lambda.md#current-application-path) |
| Lambda managed instances | QEMU/EC2 plus a guest AMI containing official SSM, Docker, pinned runtimes and the compiled managed agent; explicit instance profile/type and runtime mappings. | [Managed guest deployment](runtime-vms.md#managed-instance-lambda) |
| ECS tasks/services | `-docker-host -ecs-runtime`; local Linux host admission, pinned toolkit, installed customer images, supported Linux Fargate/`awsvpc` configuration and IAM/network resources. | [ECS setup](ecs.md#setup-and-supported-execution) |
| CodeBuild | `-docker-host -codebuild-runtime` and reachable compute endpoint; installed build images. `-codebuild-fleet-image` supplies an immutable local image for real idle fleet capacity. | [ECR and CodeBuild](behavior-references.md#ecr-and-codebuild) |
| DynamoDB / Kinesis | `-docker-host` plus `-dynamodb-runtime` and/or `-kinesis-runtime`; installed native DynamoDB Local / Apache Kafka images, not Lambda/ECS helpers. | [DynamoDB](behavior-references.md#dynamodb-engine-references), [Kinesis](behavior-references.md#imported-record-engine-experiments) |
| S3 ORC inventory | `-docker-host -inventory-orc-runtime`; explicitly build the encoder above. | [S3 inventory](cloudtrail.md) |
| Glue / Athena | `-glue-runtime` and/or `-athena-runtime`, plus Docker and the documented immutable images. | [Analytics engines and licensing](behavior-references.md#glue-and-athena-engines-evidence-and-boundaries) |
| RDS | `-rds-runtime`, Docker, installed pinned PostgreSQL/MySQL images. | [RDS setup](rds.md#running-the-native-engines) |
| DocumentDB compatibility | `-docdb-runtime`, Docker, installed pinned MongoDB compatibility image; this is not AWS DocumentDB's engine. | [DocumentDB setup](documentdb.md#native-setup) |
| OpenSearch | `-opensearch-runtime`, Docker, installed pinned OpenSearch image. | [Search engines and boundaries](behavior-references.md#opensearch-engines-evidence-and-boundaries) |
| MSK | `-msk-runtime`, Docker, installed pinned Kafka image for supported public clusters. | [MSK public brokers](behavior-references.md#msk-public-kafka-brokers) |
| ElastiCache / MemoryDB | `-valkey-runtime`, local Docker, installed immutable Valkey image; real certificate/key for TLS resources. | [Valkey setup](behavior-references.md#explicit-setup) |
| Amazon MQ | `-mq-runtime`, Docker, `-mq-state-directory`, explicit `-mq-tls-certificate` and `-mq-tls-key`; installed broker engines and Java/JMS dependencies. | [MQ execution and ownership](mq.md#actual-execution-and-durable-ownership) |
| EC2 / EBS guest execution | `-ec2-state-directory`, SQLite, local Docker, QEMU/KVM tools, firmware and prepared guest images. | [EC2](ec2.md) |
| EKS | `-eks-state-directory`, SQLite, Docker, operator-installed pinned k3d and node images; real EC2 workers need their own guest setup. | [EKS runtime selection](eks.md#explicit-runtime-selection) |
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
| `-lambda-runtime`, `-ecs-runtime`, `-codebuild-runtime`, `-dynamodb-runtime`, `-kinesis-runtime`, `-inventory-orc-runtime` | All `false`; independently enable their real owners and require `-docker-host`. |
| `-lambda-callback-host` | Empty uses Linux host-gateway; explicit `host.docker.internal` preserves Desktop's container DNS without host resolution/mapping. Requires `-lambda-runtime`. |
| `-lambda-runtime-listen` | `0.0.0.0:0`; Runtime API bind address. |
| `-lambda-telemetry-directory` | Empty uses the stackd executable's directory; contains static Linux helpers, including for a native macOS controller. Requires `-lambda-runtime` when supplied. |
| `-lambda-keep-alive` | `10m`; warm idle lifetime in service time; `0` forces cold invocations. |
| `-lambda-storage-image` | Empty override; installed immutable disk-storage helper. Requires `-lambda-runtime` when supplied. |
| `-lambda-hot-reload-code`, `-lambda-hot-reload-layers` | Repeatable `unqualified-function-arn=/absolute/path`; no mappings by default; requires `-docker-host -lambda-runtime`. Development source directories, not deployment persistence. |
| `-lambda-managed-image-id`, `-lambda-managed-instance-profile`, `-lambda-managed-instance-type` | Empty disables usable managed capacity; select an imported prepared AMI, guest instance-profile ARN and real EC2 guest type. |
| `-lambda-managed-runtime-image` | Repeatable `runtime:architecture=image@sha256:digest` installed inside the guest; no default mappings. |
| `-lambda-managed-agent-port` | `9443`; private guest HTTPS management port, requiring controller-to-guest admission. |
| `-codebuild-fleet-image` | Empty; explicit installed local image ID/digest for real idle fleet capacity. Requires `-codebuild-runtime`. |
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

The EC2 CLI discovers `qemu-system-x86_64`, `qemu-img`, `qemu-nbd`, `qemu-io`, `dnsmasq` and `dhcp_release` on PATH. Installing binaries alone does not prepare firmware, disks, networking or guest images. Managed Lambda capacity additionally requires persistent SQLite, the real EC2 runtime, all three managed image/profile/type settings, at least one installed runtime mapping and a valid agent port. Follow [managed Lambda capacity](lambda.md#managed-instances-and-capacity-providers), not an ordinary host-container recipe.

## Isolation, shutdown and retained state

Native execution is real customer code and real engine processes, not a safe substitute for a security boundary:

- Lambda functions use real runtime containers and disk-backed temporary storage. ECS owns real task network namespaces, cgroup limits, volumes and packet rules. Privileged setup helpers and access to Docker make the host/operator trusted; do not expose this to untrusted users as a hardened multi-tenant service.
- Native database/search listeners commonly bind Docker-host loopback. The controller and relevant native clients must satisfy that network contract. Local host processes and Docker administrators remain trusted; an API IAM policy is not a host-local engine firewall.
- SQLite retains control state, not a serialization of running processes or all native bytes. Separate volumes, guest disks, configuration directories and cluster state must be retained with it.
- Graceful shutdown closes owned Lambda environments. Persistent ECS workloads, database engines, EC2 guests and EKS clusters have service-specific retention/reattachment behavior; **stopping stackd is not “stop all infrastructure.”** See [ECS recovery](ecs.md#runtime-ownership-dependencies-and-recovery), [RDS lifecycle](rds.md#ownership-and-lifecycle), [EKS ownership](eks.md#explicit-runtime-selection) and [SQLite limits](sqlite-state.md).
- With no SQLite database, the CLI attempts graceful cleanup of native resources owned by its in-memory repositories, including DynamoDB, Kinesis, RDS, DocumentDB, OpenSearch, MSK, MQ and Valkey. Do not generalize this to every workload or to crashes/SIGKILL. With SQLite, those retained engines are not deleted merely because the controller exits.
- Stop workloads through their service APIs when supported; distinguish stopping a process from deleting a resource and its data. Never use blanket Docker prune/removal as stackd shutdown. Preserve disks and volumes unless their deletion is intended and exact ownership is established.

For practical shutdown, inventories, safe restart and sharing an instance, continue with [Operations](operations.md). Embedders own injected runtime disposal separately from closing the stack; see each runtime's contract rather than assuming CLI lifecycle applies to library callers.
