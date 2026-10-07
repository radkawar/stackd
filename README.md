# stackd

stackd is a local AWS emulator with Go control planes, AWS-compatible HTTP APIs,
optional SQLite persistence, and real runtime/engine backends for supported
compute and database workflows. Use it from AWS CLI, AWS SDKs, or Go tests.

**Under active development; not complete AWS parity.** An API appearing in the
[operation inventory](docs/services.json) does not mean its behavior is complete.
Read the relevant service guide before depending on a workflow. Unsupported
operations and unavailable runtime dependencies return errors, not fake success.

Licensed under [Apache-2.0](LICENSE). Vendored dependencies retain their own
license and attribution notices.

## Quick start

Requirements: **Go 1.26.5 or newer**. AWS CLI v2 and `curl` are useful for the
examples. The basic control plane requires neither Docker nor an AWS account.
The first build downloads Go dependencies; runtime images are separate,
explicit prerequisites for compute and engine workloads.

From the repository root:

```sh
go build -o bin/stackd ./cmd/stackd
mkdir -p data
./bin/stackd -listen 127.0.0.1:4566 -database ./data/stackd.sqlite
```

Leave the process running. In another terminal, use **local fixture credentials**:

```sh
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
export AWS_PAGER=""
unset AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE

curl --fail http://127.0.0.1:4566/_stackd/health
aws --endpoint-url http://127.0.0.1:4566 sts get-caller-identity
aws --endpoint-url http://127.0.0.1:4566 s3api create-bucket --bucket hello-stackd
```

The default local account is `000000000000`. `test`/`test` is a local bootstrap
root identity, **not an AWS credential or a secure multi-user login**. Keep the
listener on loopback. Do not expose the API or local diagnostic endpoints to
untrusted networks.

Press **Ctrl-C** to stop the controller. Start it again with the same database
path to retain supported control-plane state. External runtimes have their own
storage and shutdown rules; stopping the controller is not always enough to stop
their containers or guests.

## Deploy execution runtimes

The quick start runs the API control plane only. Real functions, tasks, databases,
virtual machines, and Kubernetes workloads require their native backends.
**Use a dedicated, trusted Linux host** for the full runtime setup: rootful Docker,
systemd/cgroup v2, and KVM for accelerated guests. The API controller also supports
a native macOS build; opt-in Lambda/DynamoDB/Kinesis on Docker Desktop use its real
Linux VM, not ECS's local-host contract. A user-reported Apple Silicon/Desktop
run is recorded with its exact scope in the [Desktop recipe](docs/runtime-containers.md#native-macos-controller-with-docker-desktop).
An API-only deployment needs no Docker.

| Deployment | Prepare first | Enable in the controller |
| --- | --- | --- |
| Lambda, ECS, CodeBuild, DynamoDB, Kinesis | [Docker host, selected helpers, and installed images](docs/runtime-containers.md#shared-docker-host) | `-docker-host` plus, respectively, `-lambda-runtime`, `-ecs-runtime`, `-codebuild-runtime`, `-dynamodb-runtime`, `-kinesis-runtime` |
| RDS, DocumentDB compatibility, OpenSearch, Kafka/MSK, Valkey, MQ, Glue/Athena | [Per-engine images, TLS, and state](docs/runtime-containers.md) | Docker plus the service's runtime flag |
| Real EC2/EBS guests | [QEMU/KVM, firmware, networking, and imported guest images](docs/runtime-vms.md#qemukvm-ec2) | Docker, SQLite, and `-ec2-state-directory` |
| EKS Kubernetes clusters | [Pinned k3d and k3s images](docs/runtime-vms.md#k3d-eks) | Docker, SQLite, and `-eks-state-directory` |
| EKS managed EC2 workers | [Prepared worker AMIs and worker routing](docs/runtime-vms.md#k3d-eks) | Both EC2 and EKS runtimes |
| Lambda managed-instance guests | [Guest Docker, SSM, runtime images, and Lambda agent](docs/runtime-vms.md#managed-instance-lambda) | EC2 plus the managed-Lambda selectors |
| ALB sockets, ORC inventory, ECR scanning | [Relay/encoder/scanner preparation](docs/runtime-containers.md) | ALB/scanner helper flags; `-docker-host -inventory-orc-runtime` for ORC |

Build the native controller (and, with `make build`, the static Linux helpers needed only by Lambda):

```sh
make build
mkdir -p data
```

After following the linked installation/image preparation steps, choose one of
these foreground launches. **Stop the previous controller first**; these are
alternatives, not three processes sharing a database. Flags can be combined on
one controller when all corresponding dependencies are prepared.

### Docker-backed Lambda execution

```sh
./bin/stackd -listen 0.0.0.0:4566 -database ./data/stackd.sqlite \
  -docker-host unix:///var/run/docker.sock -lambda-runtime
```

`-docker-host` selects Engine transport only; it does not enable any execution
owner or pull images. The five flags listed above and `-inventory-orc-runtime`
default to false; each enables only its own real boundary. ECS's local
Linux/rootful/systemd/cgroup-v2 admission applies only when ECS is requested.
Other engines retain their service-specific opt-ins, such as `-rds-runtime`.
See the [container recipes](docs/runtime-containers.md), including the
[native macOS / Docker Desktop recipe](docs/runtime-containers.md#native-macos-controller-with-docker-desktop).

### QEMU/KVM guests

On Linux x86-64, with QEMU tools, KVM access, firmware, and Docker prerequisites installed:

```sh
./bin/stackd -listen 0.0.0.0:4566 -database ./data/stackd.sqlite \
  -docker-host unix:///var/run/docker.sock \
  -ec2-state-directory ./data/ec2 \
  -ec2-bios /usr/share/seabios/bios-256k.bin \
  -ec2-uefi-code /usr/share/OVMF/OVMF_CODE_4M.fd \
  -ec2-uefi-vars /usr/share/OVMF/OVMF_VARS_4M.fd
```

Those firmware paths are Debian/Ubuntu examples; verify your installed paths.
There are no preloaded EC2 AMIs: follow the [guest image import and launch
instructions](docs/runtime-vms.md#qemukvm-ec2) before calling `RunInstances`.

### k3d Kubernetes

After installing k3d v5.8.3 and the pinned node/helper images:

```sh
./bin/stackd -listen 0.0.0.0:4566 -database ./data/stackd.sqlite \
  -docker-host unix:///var/run/docker.sock \
  -eks-state-directory ./data/eks \
  -eks-k3d "$PWD/bin/k3d-v5.8.3" \
  -eks-listen-host 127.0.0.1 -eks-endpoint-host 127.0.0.1
```

Create and access clusters through the local EKS API; do not manually create
similarly named k3d clusters and expect stackd to adopt them. Managed EC2 workers
also need the QEMU runtime, prepared worker images, and host routing. See
[EKS deployment and access](docs/runtime-vms.md#k3d-eks).

These examples broaden the API listener beyond loopback. Restrict network access,
and configure origins reachable by both your host clients and workloads before
provisioning resources; container loopback is not the host. See
[runtime networking](docs/runtimes.md#networking-before-execution).
Dependencies are prepared explicitly, not downloaded at execution time.
Stopping the controller does **not** necessarily stop persistent guests, clusters,
or engines; follow [owned-infrastructure shutdown](docs/operations.md#stop-all-infrastructure-belonging-to-one-instance).

## Documentation

| Need | Guide |
| --- | --- |
| Install, start, make requests, and try S3/SQS | [Getting started](docs/getting-started.md) |
| Configure credentials, endpoints, TLS, persistence, and service time | [Configuration](docs/configuration.md) |
| Deploy containers, databases, QEMU/KVM guests, and k3d clusters | [Runtime deployment overview](docs/runtimes.md), [container recipes](docs/runtime-containers.md), [VM/Kubernetes recipes](docs/runtime-vms.md) |
| Restart, back up, inspect, troubleshoot, and shut down | [Operations](docs/operations.md) |
| Find service-specific support and setup | [Documentation index](docs/README.md) |
| Embed stackd in Go tests | [Embedding reference](docs/implementation-reference.md#embed-in-go-tests) |
| Develop, generate contracts, and run verification | [Development reference](docs/implementation-reference.md#develop) |

## What to expect

- Point every client at your local endpoint; ordinary AWS CLI/SDK defaults target
  real AWS. Examples use explicit endpoint overrides and local credentials.
- Memory-only state is lost on exit. `-database` selects SQLite-backed state;
  native engine volumes, guest disks, and other sidecars are additional state.
- Real Lambda/container/database execution requires explicitly configured
  runtimes and installed images. Start with the control-plane quick start, then
  follow the [runtime guide](docs/runtimes.md) for your workload.
- Normal builds use checked-in generated contracts. You do not need the AWS SDK
  source checkout or native AWS credentials just to run the emulator.
- Local development defaults, diagnostic endpoints, and Docker/guest access are
  not a production security boundary.

The former README is preserved in the
[implementation and development reference](docs/implementation-reference.md).
Detailed service documentation, native evidence, the
[architecture](docs/architecture.md), and the [remaining backlog](TODO.md) remain
available; the new entry points do not replace or remove them.
