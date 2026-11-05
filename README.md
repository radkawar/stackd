# stackd

stackd is a local AWS emulator for application development and testing. It exposes
AWS-compatible APIs for use with the AWS CLI, SDKs, Terraform and CloudFormation.
The server is written in Go, with optional SQLite persistence. Compute and
database services use separately configured containers, virtual machines and
database engines.

stackd is under active development. Service and operation support varies; consult
the [service documentation](docs/README.md) for supported workflows and limitations.

## Installation

Download a Linux or macOS archive from [GitHub Releases](https://github.com/radkawar/stackd/releases).
See the [installation instructions](docs/releases.md#install-a-published-release)
for platform selection, checksum verification and package layout.

To build from source, install Go 1.26.5 or later:

```sh
git clone https://github.com/radkawar/stackd.git
cd stackd
go build -o bin/stackd ./cmd/stackd
export PATH="$PWD/bin:$PATH"
```

Docker and an AWS account are not required to start the API server. Workloads
that execute functions, containers or database queries need additional
[runtime dependencies](docs/runtimes.md).

## Quick start

Start the server with SQLite persistence:

```sh
mkdir -p data
stackd -listen 127.0.0.1:4566 -database ./data/stackd.sqlite
```

In another terminal, configure local credentials and make a request with AWS CLI v2:

```sh
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_EC2_METADATA_DISABLED=true
export AWS_PAGER=""
unset AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE

aws --endpoint-url http://127.0.0.1:4566 sts get-caller-identity
aws --endpoint-url http://127.0.0.1:4566 s3api create-bucket --bucket hello-stackd
```

Use the endpoint override on every request; without it, AWS clients normally
connect to AWS. The `test` credentials provide local administrative access.
Keep the server on a trusted network and do not use production AWS credentials.

Each new instance receives a random 12-digit account ID. Set
`--account-id 123456789012` when creating an instance to choose one. The account
ID is retained in SQLite; restarting with a different ID returns an error.

Press Ctrl-C to stop the server. Restart it with the same database path to retain
state, or omit `-database` for an in-memory instance. Runtime containers and guest
disks have separate storage and shutdown requirements; see [Operations](docs/operations.md).

The [getting-started guide](docs/getting-started.md) continues with S3 and SQS
examples, persistence and cleanup.

## Deploy execution runtimes

Install the dependencies for the services you need, then enable them with the
corresponding runtime flags. Selecting a Docker host does not enable services or
pull images.

| Workload | Setup guide |
| --- | --- |
| Lambda, ECS, CodeBuild, databases and analytics | [Containers and engines](docs/runtime-containers.md) |
| EC2 virtual machines and EKS clusters | [Virtual machines and Kubernetes](docs/runtime-vms.md) |
| Endpoints, DNS, TLS and container connectivity | [Networking](docs/networking.md) |

Full runtime deployments require a trusted Linux host. macOS supports the API
server and selected Docker Desktop workloads; see the
[platform requirements](docs/runtime-containers.md#native-macos-controller-with-docker-desktop).

## Examples and documentation

- [Terraform and CloudFormation examples](examples/README.md)
- [Lambda live reload](examples/lambda-hot-reload/README.md)
- [Configuration](docs/configuration.md): accounts, credentials, endpoints and persistence
- [Operations](docs/operations.md): backups, diagnostics and shutdown
- [Service guides](docs/README.md)
- [Embedding in Go tests](docs/implementation-reference.md#embed-in-go-tests)

## Development

See the [development reference](docs/implementation-reference.md#develop) for
build, code-generation and test commands. The [architecture](docs/architecture.md)
describes the implementation, and [TODO.md](TODO.md) tracks remaining work.
Bug reports and feature requests are welcome on
[GitHub Issues](https://github.com/radkawar/stackd/issues).

## License

stackd is licensed under the [Apache License, Version 2.0](LICENSE).
Third-party components retain their respective licenses and notices.
