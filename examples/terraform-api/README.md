# Terraform API, GraphQL and DNS

## Purpose

Deploy REST and HTTP APIs, AppSync resolvers and Route53 records with Terraform,
then consume real Lambda responses, verified TLS custom-domain routing, GraphQL
and UDP/TCP DNS. `coverage.json` records per-type scope; this is not a full API
Gateway, AppSync or Route53 compatibility claim.

## Prerequisites

Complete the shared [Python environment and build setup](../README.md#prepare-once)
and export `EXAMPLE_PYTHON`. Shared Python requirements suffice. Install
Terraform **exactly 1.15.9** (`main.tf` enforces it), Docker CLI/Engine, OpenSSL
and BIND `dig`. AWS provider **6.68.0** is pinned; initial installation needs
registry access or a prepared filesystem mirror.

Prepare the [Docker host and Lambda storage facilities](../../docs/runtime-containers.md).
The runner requires `lambda-telemetry-amd64` beside the selected controller and
the installed Linux amd64 runtime. Other architectures require separately
prepared execution support; the runner has no architecture switch.
Install these exact images before running (the runner only inspects them):

```sh
docker pull ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc
docker pull --platform linux/amd64 public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3
```

## Run

All commands run from the repository root:

```sh
"$EXAMPLE_PYTHON" examples/terraform-api/run.py --port 14703 --dns-port 15703
```

Use unused distinct unprivileged ports. `--stackd /absolute/path/to/stackd`
selects a prepared binary; `--work-parent /existing/directory` changes the parent
of the new unique workspace. `--provider-mirror /absolute/path/to/mirror`
selects the pinned AWS provider from a filesystem mirror with no direct fallback;
omitting it allows registry installation. `--docker-host` defaults to
`DOCKER_HOST`, otherwise `unix:///var/run/docker.sock`, and must be a local Unix
socket. The controller listens on all interfaces for runtime callbacks: use a
trusted, firewalled host. Application SDK requests remain on the owned local
HTTPS endpoint, with the generated CA explicitly trusted; no host DNS changes
or TLS-verification bypass are needed.

## Expected results

The runner creates unique resources, consumes the first revision, checks that
draft edits do not bypass deployment, imports six retained owners, reconciles
only the exact imported GraphQL schema transition, requires strict no-op plans,
updates and consumes the second revision, then destroys and verifies absence.
Success prints `Current-provider API lifecycle complete`.

The printed private directory retains `stackd.sqlite`, `stackd.log`, Terraform
state/backups/plans, provider configuration and generated CA/TLS keys.
`evidence.json` is written after successful teardown/absence checks, not as an
incremental failure report. Do not publish these sensitive artifacts.

## Cleanup

The runner attempts Terraform destroy and removes its exact SDK-created Lambda,
IAM role and ACM prerequisite on exit from the resource lifecycle. It checks
API/zone absence, DNS refusal and empty Terraform resource state on the success
path. Its controller stops on exit; the workspace is deliberately retained.
Inspect failures before removing only the exact printed directory, after owned
processes stop. Do not run `main.tf` against a shared account or existing server.

## Limitations

This runner does not perform a controller database-reopen phase. Native GraphQL
schema is write-only to the provider importer, so a narrowly inspected saved
plan restores that schema; replacement or unrelated changes fail. Strict plan
exit 2 is not success. Official Terraform can exhibit the shared
[refresh-only Core issue](../README.md#terraform-core-refresh-only-correction-opt-in);
the optional locally patched 1.16.6 consumer is **not** compatible with this
fixture's exact 1.15.9 version pin. Do not silently substitute it or downgrade
the provider. Use [API controls](../terraform-api-controls/README.md) for the
separate extended authorizer, WebSocket and database-backed workflows.
