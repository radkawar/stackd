# Terraform observability and application protection

## Purpose

Manage CloudWatch Logs/metrics, CloudTrail, Config, GuardDuty, WAFv2, X-Ray,
SSM, ACM and Signer resources, then independently consume actual log bytes,
audit/config delivery, encrypted parameters, certificates and signed artifacts.
`inventory.json` separates fixture scope, unsupported families and unverified
branches; a listed provider operation is not runtime proof.

## Prerequisites

Complete the shared [Python environment and build setup](../README.md#prepare-once)
and export `EXAMPLE_PYTHON`. Shared Python requirements suffice. Install Terraform
and OpenSSL on `PATH`. The configuration accepts **>= 1.5, < 2.0**; the runner's
prerequisite message recommends **1.15.9**, not an exact version gate. AWS provider
**6.68.0** is pinned. Prepare registry access or an AWS provider filesystem mirror.
Default mode requires no Docker.

For `--stream-runtime`, additionally prepare Docker CLI/Engine and the real
[Kinesis backend](../../docs/runtime-containers.md#dynamodb-and-kinesis):

```sh
docker pull apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68
```

Images must already exist on the selected daemon; runtime startup does not
install them. No Lambda helper is needed for this Kinesis-only mode.

## Run

From the repository root:

```sh
# Local control/data consumers without native stream execution:
"$EXAMPLE_PYTHON" examples/terraform-observability/run.py --port 14741

# Alternative: also consume real Logs subscription records from Kinesis:
"$EXAMPLE_PYTHON" examples/terraform-observability/run.py \
  --port 14751 --stream-runtime --docker-host unix:///var/run/docker.sock
```

Reserve three consecutive unused unprivileged ports: `--port` for the controller,
`port + 1` for authoritative UDP/TCP DNS, and `port + 2` for the owned HTTP
upstream. Select a base port no greater than 65533. `--docker-host` defaults to
`unix:///var/run/docker.sock` and is only used with `--stream-runtime`.
`--stackd /absolute/path/to/stackd` selects a prepared controller;
`--work-parent /existing/directory` selects the parent of a new unique workspace.
`--provider-mirror /absolute/path/to/mirror` selects the pinned provider from an
existing filesystem mirror without direct fallback; omit it for registry access.
Do not apply these files directly to a shared endpoint or account.

## Expected results

The runner creates resources, independently consumes outputs, imports supported
owners, updates protection/revision settings, requires normal and refresh-only
no-op plans, stops/reopens the owned SQLite controller, checks retained bytes
and protection, then destroys and verifies absence. Stream mode additionally
reads actual compressed Logs subscription records from native Kinesis.
Success prints `Completed observability lifecycle stages` with the completed
stage list; an exception/nonzero exit is not success even if cleanup ran.

The printed private workspace retains `stackd.sqlite`, full `stackd.log`,
Terraform state/variables/plans, certificates/private keys, unsigned/signed ZIP
artifacts and `evidence.json` with completed stages, consumers, errors and cleanup
status. Terraform command output is normally printed to the terminal. Retained
state and PEM/parameter material are sensitive; do not publish the directory.

## Cleanup

Each import first saves `before-import.tfstate`; a failed import restores that
state ownership before ordinary cleanup, rather than leaving an orphaned owner.

The runner explicitly disables log deletion protection before Terraform destroy,
removes its exact SDK-created standalone WAF ACL, and checks signed absence and
empty resource state on the success path. Its HTTP upstream and controller stop
on exit. Signer profiles are canceled; immutable successful job history remains
and is checked rather than falsely reported erased. A cleanup error remains a
failure. Inspect evidence before removing only the exact printed workspace,
after owned processes stop. Never remove shared Docker state or the repo database.

## Limitations

SSM document controls do not execute an official SSM agent. This does not add
OTel, malware scanning or unsupported alarm/runtime owners. Default mode does
not claim Logs-to-Kinesis delivery; only explicit stream mode consumes it.
See the inventory for the remaining service-specific boundaries.

Strict plan exit 2 remains failure. Official Terraform may exhibit the shared
[refresh-only Core issue](../README.md#terraform-core-refresh-only-correction-opt-in).
The optional correction is a locally patched consumer, not an official release;
its API-controls result does not verify observability. Keep source/patch/binary
checksums and official versus patched run evidence separate.
