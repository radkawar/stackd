# Examples

Run local applications against stackd using Terraform, CloudFormation or the AWS
SDK. Runners provision resources, check application results and remove the
resources they created. Most start their own server; exceptions are noted below.

## Prepare once

Run commands from the repository root. Install Python 3.10 or later and build
stackd with the Go version specified in `go.mod`:

```sh
EXAMPLE_VENV="$(mktemp -d /tmp/stackd-example-venv.XXXXXX)"
python3 -m venv "$EXAMPLE_VENV"
"$EXAMPLE_VENV/bin/python" -m pip install -r examples/requirements.txt
make build
export EXAMPLE_PYTHON="$EXAMPLE_VENV/bin/python"
```

Alternatively, use an installed [release package](../docs/releases.md) and pass
`--stackd /absolute/path/to/stackd` to the runner. Keep its Lambda telemetry
helpers beside the executable. The example scripts still require this checkout.

Additional requirements depend on the example:

- Terraform examples need Terraform and the AWS provider. The basic and EIP
  examples use provider **6.68.0** and accept Terraform >= 1.5, < 2. Other groups
  have exact version requirements documented in their guides.
- Lambda and engine examples need Docker and preinstalled images.
- EC2 and EKS examples need the host, firmware and guest setup described in
  [runtime deployment](../docs/runtimes.md).
- Some groups have additional Python requirements; install the requirements file
  listed in their guide into the same virtual environment.

The shared requirements pin boto3, botocore, PyMongo and PyArrow. AWS CLI is not
required by the basic runners. Downloads of Python packages, Go modules,
Terraform providers and runtime images require network access. For offline use,
prepare these dependencies and a provider mirror beforehand.

## Run in fresh owned state

Start with one of these examples; none requires Docker:

```sh
"$EXAMPLE_PYTHON" examples/terraform/run.py --port 14661
"$EXAMPLE_PYTHON" examples/cloudformation/run.py --port 14662
"$EXAMPLE_PYTHON" examples/terraform-eip/run.py --port 14664
```

| Example | What it does |
| --- | --- |
| [Terraform application](terraform/README.md) | Provisions S3, SQS and SSM; transfers an object through a queue manifest; checks a no-change plan; destroys the application. |
| [CloudFormation application](cloudformation/README.md) | Creates the same application, updates its SSM parameter and deletes the stack. |
| [Elastic IPs](terraform-eip/README.md) | Allocates two addresses, checks attribute pagination and refresh, then releases them. |
| [Lambda live reload](lambda-hot-reload/README.md) | Edits a mounted Python source file and checks subsequent function output without redeployment. |
| [VPC Flow Logs](terraform/vpc-flow-logs/README.md) | Sends UDP/TCP traffic and checks CloudWatch Logs and S3 text/Parquet delivery. |

Use `--help` to inspect a runner's options. Runners using the shared helper accept:

| Option | Purpose |
| --- | --- |
| `--stackd PATH` | Server executable; defaults to `bin/stackd`. |
| `--port PORT` | Unused local API port. |
| `--work-parent PATH` | Existing parent directory for a new run directory. |

The shared helper prints the working directory and server command. It uses a
new SQLite database, unique resource names and a dedicated server process,
without connecting to an existing server or the repository's `data/` database.
Restart checks reuse only that run's database and port.

The [Auto Scaling example](terraform-compute/autoscaling/README.md) instead
requires a caller-managed local server and prepared AMI. The
[Flow Logs runner](terraform/vpc-flow-logs/README.md) manages its own server but
uses separate `--binary` and `--state-directory` options.

## Service-specific Terraform workflows

These examples require additional setup. Read the corresponding guide before
running a group; some include containers, guests or workflows with known gaps.

| Group | Scope |
| --- | --- |
| [Identity](terraform-identity/README.md) | IAM, accounts and credentials |
| [Identity extensions](terraform-identity-extensions/README.md) | Federation, keys, secret rotation and TLS |
| [API](terraform-api/README.md) | API deployment and requests |
| [API controls](terraform-api-controls/README.md) | REST, WebSocket, GraphQL, authorizers and DNS |
| [Application controls](terraform-application-controls/README.md) | Authentication, jobs and deployment pipelines |
| [Messaging](terraform-messaging/README.md) | Queues, topics, routing and scheduling |
| [Storage](terraform-storage/README.md) | Objects, tables, block storage and databases |
| [Storage controls](terraform-storage-controls/README.md) | S3, DynamoDB and guest-backed EBS controls |
| [Engines](terraform-engines/README.md) | Caches, brokers and search |
| [Compute](terraform-compute/README.md) | Functions, containers, Kubernetes and guests |
| [Analytics](terraform-analytics/README.md) | Queries, streams and jobs |
| [Analytics catalog](terraform-analytics-catalog/README.md) | Catalog and query configuration |
| [Governance](terraform-governance/README.md) | Organizations, sharing, SSO and resource groups |
| [Observability](terraform-observability/README.md) | Logs, metrics, audit and delivery |

A failed assertion or unexpected Terraform plan fails the runner. Consult each
guide's limitations and retained reports before depending on a workflow.

## Local credentials and networking

The shared helper uses local account `738492615083` unless a runner selects
another account. The account remains the same across restarts. These fixed
example identities do not change stackd's random account selection for ordinary
new instances. Use distinct fixture accounts for concurrent native runs sharing
host networking.

SDK clients use loopback endpoints, `test` credentials and region `us-east-1`.
The controller and Terraform subprocesses discard inherited AWS credentials,
endpoint overrides, Terraform arguments and proxy settings. Terraform uses a
private CLI configuration, a local backend and endpoints for each required AWS
service. HTTPS examples supply and verify their own certificates.

The shared helper does not accept an AWS endpoint or an existing server. This
does not restrict outbound connections made by application code or downloaded
tools; use host/network controls for egress isolation. Lambda examples bind the
API and callback listeners beyond loopback so containers can connect. Restrict
inbound access to trusted clients before running them.

## Cleanup and evidence

On success, runners delete their application resources. Runners using the shared
helper also stop their server; they attempt cleanup on failure and retain the
failure. A nonzero server exit fails the run. A shutdown timeout reports the
live process ID rather than force-killing it. Caller-managed servers remain
running.

Run directories are retained for inspection. Depending on the example they
contain `stackd.log`, SQLite state, Terraform plans/state, outputs and result
reports. The shared helper appends server logs across restarts; individual
runners may also save or rotate logs. These files can contain credentials or
private keys. Do not commit or publish the run directory.

After checking cleanup completed, remove only the exact directory printed by
your run:

```sh
# Replace this path with the directory printed by the runner.
rm -r -- /tmp/stackd-terraform-EXACT_RUN_SUFFIX
```

Do not use global Docker pruning to clean up an example. Runtime images remain
installed for subsequent runs. Remove the Python environment when no runner is
using it:

```sh
rm -r -- "$EXAMPLE_VENV"
```

## Terraform Core refresh-only correction (opt-in)

Official Terraform 1.15.9 and 1.16.6 can print `No changes` but return exit 2 for
refresh-only plans containing unchanged data resources. This also reproduces
with Terraform's built-in remote-state data source, without the AWS provider or
stackd. Some larger examples encounter this issue; their assertions are not
relaxed to accept it.

The [retained patch](../third_party/terraform-core/refresh-only-managed-resources.patch)
targets Terraform v1.16.6 at commit
`7b8f1669b95119ac6021e05c9d10eae7cf75f60b`. It corrects
`ManagedResourcesEqual` to compare managed resources rather than data resources
and data-only modules, while preserving managed-object and output drift checks.
This is a local patch, not an official release or an upstream-merged fix.
Terraform retains its [BUSL-1.1 license](../third_party/terraform-core/LICENSE);
no Terraform binary is bundled with stackd.

To build it without replacing your installed Terraform:

```sh
STACKD_ROOT="$PWD"
TF_WORK="$(mktemp -d)"
git clone --depth 1 --branch v1.16.6 https://github.com/hashicorp/terraform.git "$TF_WORK/src"
test "$(git -C "$TF_WORK/src" rev-parse HEAD)" = 7b8f1669b95119ac6021e05c9d10eae7cf75f60b
git -C "$TF_WORK/src" apply "$STACKD_ROOT/third_party/terraform-core/refresh-only-managed-resources.patch"
go -C "$TF_WORK/src" test ./internal/states
mkdir "$TF_WORK/bin"
go -C "$TF_WORK/src" build \
  -ldflags='-X github.com/hashicorp/terraform/version.dev=no' \
  -o "$TF_WORK/bin/terraform" .
# After preparing the API-controls prerequisites:
PATH="$TF_WORK/bin:$PATH" "$EXAMPLE_PYTHON" examples/terraform-api-controls/run.py \
  --stackd "$STACKD_ROOT/bin/stackd"
```

The linker flag satisfies the example's version check; it does not make the
binary an official release. Record the patch and binary checksum with results.
The [API-controls run report](../testdata/terraform-core/refresh-only.json)
records a completed lifecycle with this patched build, including imports,
updates, restart, refresh and cleanup. It does not establish results for other
groups or official Terraform binaries.
