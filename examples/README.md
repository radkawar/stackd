# Local application examples

These are executable, assertion-bearing examples, not claims of AWS parity:

- [Terraform](terraform/README.md): init, apply, consume outputs, transfer real
  binary S3 bytes through an SQS message, read SSM, require a no-change plan,
  repeat apply, destroy, and verify resource absence.
- [Terraform EIPs with AWS provider 6.68.0](../docs/ec2.md#run-the-current-provider-lifecycle):
  allocate two EIPs, verify signed attribute pagination, refresh without drift,
  destroy, and assert resource absence in a fresh owned controller.
- [CloudFormation](cloudformation/README.md): create the same application, consume
  stack outputs, exercise its data plane, update SSM in place, reject an identical
  update as a no-op, delete the stack, and verify resource absence.
- [Docker Python Lambda live reload](lambda-hot-reload/README.md): invoke a real
  runtime, edit its read-only host-mounted source, observe different subsequent
  output and a new Init, while retaining function/deployment identity and `/tmp`.

## Service-specific Terraform workflows

These runners cover larger service groups. Read each runner's options and its
adjacent configuration before starting it; the basic example's prerequisites
are not sufficient for every group. They create real runtime resources and
perform destructive cleanup of their own resources.

| Runner | Scope |
| --- | --- |
| [Identity](terraform-identity/run.py) | IAM, account and credential lifecycles |
| [Identity extensions](terraform-identity-extensions/README.md) | Federation, keys, secret rotation and TLS consumers |
| [API](terraform-api/run.py) | API deployment and request consumers |
| [API controls](terraform-api-controls/README.md) | REST/WebSocket/GraphQL requests, authorizers and DNS |
| [Messaging](terraform-messaging/run.py) | Queues, topics, routing, scheduling and configuration consumers |
| [Storage](terraform-storage/run.py) | Object, table, block and native database consumers |
| [Storage controls](terraform-storage-controls/run.py) | S3, DynamoDB and guest-backed EBS controls |
| [Engines](terraform-engines/run.py) | Native cache, broker and search consumers |
| [Compute](terraform-compute/compute.py) | Native function, container, Kubernetes and guest workflows |
| [Analytics](terraform-analytics/run.py) | Real query, streaming and job execution |
| [Analytics catalog](terraform-analytics-catalog/run.py) | Catalog and query configuration lifecycles |
| [Governance](terraform-governance/run.py) | Organizations, sharing, SSO and resource groups |
| [Observability](terraform-observability/run.py) | Logs, metrics, audit, security and delivery workflows |

Presence here is not a passing coverage claim. The runners keep strict plan and
native-consumer assertions; some workflows still fail on documented service or
Terraform gaps. Retained lifecycle reports and service guides define the tested
boundaries. Do not disable protection defaults or ignore drift to obtain a pass.

## Prepare once

Run from the repository root. Install Python 3.10+ and Go as required by `go.mod`.
The basic Terraform example requires Terraform >= 1.5 and < 2; service-specific
fixtures may require a newer version and a pinned AWS provider. Docker is required
for Lambda and container-backed engine workflows. Guest-backed workflows also
need their documented host, image and firmware prerequisites. An AWS CLI
installation is optional: the runners use signed boto3 requests, not unsigned
HTTP health checks. Use a disposable virtual environment outside the checkout:

```sh
EXAMPLE_VENV="$(mktemp -d /tmp/stackd-example-venv.XXXXXX)"
python3 -m venv "$EXAMPLE_VENV"
"$EXAMPLE_VENV/bin/python" -m pip install -r examples/requirements.txt
make build
export EXAMPLE_PYTHON="$EXAMPLE_VENV/bin/python"
```

The shared requirements pin boto3/botocore for the exercised AWS API models and
PyMongo for native DocumentDB TLS/BSON consumers. These are example-client
dependencies, not dependencies of the Go controller.

`make build` also produces both static **Linux** Lambda telemetry helpers beside
`bin/stackd`; building just the controller is insufficient for Lambda. Installing
SDK packages, Go modules, Terraform providers and Docker images is explicit
online preparation. The AWS application requests themselves remain local.
For offline use, prepare the Python environment and provider mirror/cache and
images before disconnecting; see the individual guides. No downloaded binary,
provider, image, state, or real credential belongs in this checkout.

## Run in fresh owned state

```sh
"$EXAMPLE_PYTHON" examples/terraform/run.py --port 14661
"$EXAMPLE_PYTHON" examples/cloudformation/run.py --port 14662
"$EXAMPLE_PYTHON" examples/terraform-eip/run.py --port 14664
# Prepare the pinned Docker images before following the Lambda guide.
```

Each runner starts **its own** controller, rejects an occupied port, creates a
unique directory with its own SQLite database/logs, provisions unique resource
names, and stops only its own process. It does not connect to the repository's
`data/` database or an existing server. Choose other unused unprivileged ports
with `--port`; `--stackd /absolute/path/to/stackd` selects a prepared binary.
`--work-parent /existing/directory` changes the parent of the new run directory.
Reopen checks stop the owned process before they reuse its port and SQLite file.
Closed TCP connections in `TIME_WAIT` do not block that restart; a live listener
still causes the runner to fail.

The shared controller helper defaults to fixture account `738492615083`.
Runners can pass an explicit `account=` value; signed STS discovery must match
that value. Keep the same account when reopening the owned SQLite database.
Use distinct accounts for concurrent native runs that share host networking.
These IDs are local fixture identities, not AWS credentials. Every SDK client has
an explicit loopback endpoint, static `test` / `test` credentials, region
`us-east-1`, disabled proxies, and no credential-chain fallback. HTTP is the
default. HTTPS examples must pass their owned certificate, key and CA to the
shared controller helper and trust that CA explicitly in SDK/provider clients.
They do not disable certificate or hostname verification. The
controller/Terraform subprocess environment drops inherited AWS credentials,
endpoint overrides, Terraform arguments, and proxy settings. Terraform also
uses a private CLI configuration, the local backend, and explicit endpoints for
every provider service used here (EC2, IAM, STS, S3, SQS, SSM). There is no option to
point these lifecycle runners at AWS or somebody else's running controller.

This guards against accidental production provisioning; it is not an egress
sandbox. For isolation from arbitrary application code or compromised tools,
use host/network policy. Lambda deliberately binds the AWS API and Runtime API
callbacks on non-loopback interfaces so containers can connect: review that
example's firewall and Docker trust boundary first.

## Cleanup and evidence

On success the application resources are deleted through signed APIs and their
absence is asserted; the controller exits gracefully. No `docker prune`, broad
container removal, repository reset, or deletion of user-owned state is used.
The fresh run directory is intentionally retained, including `stackd.log`,
SQLite state, IaC outputs/state where applicable, and Lambda `evidence.json`.
Its exact absolute path is printed before work starts. Delete **only that
printed directory** after inspection:

```sh
# Replace with the exact newly created directory printed by your run.
rm -r -- /tmp/stackd-terraform-EXACT_RUN_SUFFIX
# Or the printed stackd-cloudformation-* / stackd-lambda-reload-* directory.
```

On an assertion/API error, cleanup still attempts the owned deployment deletion
and graceful controller shutdown; errors are not converted into passing results.
Keep the printed directory and log to diagnose failures. A shutdown timeout
reports the specific live PID rather than force-killing it and claiming that
runtime cleanup succeeded. Do not run global Docker cleanup to hide such a
failure. Remove the disposable Python environment only when no runner uses it:

```sh
rm -r -- "$EXAMPLE_VENV"
```

The runners are designed to be executed by the integrating developer. Merely
checking in these examples does not establish that a particular host, provider
version, Docker VM, or service combination has passed them.
