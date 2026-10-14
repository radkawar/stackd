# Local application examples

These are executable, assertion-bearing examples, not claims of AWS parity:

- [Terraform](terraform/README.md): init, apply, consume outputs, transfer real
  binary S3 bytes through an SQS message, read SSM, require a no-change plan,
  repeat apply, destroy, and verify resource absence.
- [CloudFormation](cloudformation/README.md): create the same application, consume
  stack outputs, exercise its data plane, update SSM in place, reject an identical
  update as a no-op, delete the stack, and verify resource absence.
- [Docker Python Lambda live reload](lambda-hot-reload/README.md): invoke a real
  runtime, edit its read-only host-mounted source, observe different subsequent
  output and a new Init, while retaining function/deployment identity and `/tmp`.

## Prepare once

Run from the repository root. Install Python 3.10+, Go as required by `go.mod`,
Terraform >= 1.5 and < 2 for its example, and Docker only for Lambda. An AWS CLI
installation is optional: the runners use signed boto3 requests, not unsigned
HTTP health checks. Use a disposable virtual environment outside the checkout:

```sh
EXAMPLE_VENV="$(mktemp -d /tmp/stackd-example-venv.XXXXXX)"
python3 -m venv "$EXAMPLE_VENV"
"$EXAMPLE_VENV/bin/python" -m pip install -r examples/requirements.txt
make build
export EXAMPLE_PYTHON="$EXAMPLE_VENV/bin/python"
```

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
# Prepare the pinned Docker images before following the Lambda guide.
```

Each runner starts **its own** controller, rejects an occupied port, creates a
unique directory with its own SQLite database/logs, provisions unique resource
names, and stops only its own process. It does not connect to the repository's
`data/` database or an existing server. Choose other unused unprivileged ports
with `--port`; `--stackd /absolute/path/to/stackd` selects a prepared binary.
`--work-parent /existing/directory` changes the parent of the new run directory.

The local fixture account is explicitly `738492615083`; signed STS discovery
must return that account. It is not a real AWS credential. Every SDK client has
an explicit `http://127.0.0.1:PORT` endpoint, static `test` / `test` credentials,
region `us-east-1`, disabled proxies, and no credential-chain fallback. The
controller/Terraform subprocess environment drops inherited AWS credentials,
endpoint overrides, Terraform arguments, and proxy settings. Terraform also
uses a private CLI configuration, the local backend, and explicit endpoints for
every provider service used here (IAM, STS, S3, SQS, SSM). There is no option to
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
