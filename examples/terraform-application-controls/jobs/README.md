# Terraform jobs and pipelines

## Purpose

Manage CodeBuild projects, CodePipeline and Step Functions, then consume actual
S3 ZIP/artifact bytes and activity-worker executions, including immutable workflow
versions and aliases. Opt in to real CodeBuild container processes; project
lifecycle alone is not build-execution support. `inventory.json` records the
supported subset and remaining branches.

## Prerequisites

Complete the shared [Python environment and build setup](../../README.md#prepare-once)
and export `EXAMPLE_PYTHON`. Shared Python requirements suffice. Install Terraform
on `PATH`: `main.tf` permits **>= 1.5, < 2.0**, while the runner's prerequisite
message recommends **1.15.9** rather than enforcing that exact version. AWS
provider **6.68.0** is pinned; prepare registry access or a filesystem mirror.
Default mode requires no Docker and starts no builds.

For `--docker`, prepare Docker CLI/Engine and the
[CodeBuild host prerequisites](../../../docs/runtime-containers.md#ecs-and-codebuild).
Install a Linux image containing `/bin/sh` and `python3` on `PATH` (Python 3.14
is suitable), including any needed dependencies beforehand. Select its immutable
`sha256:...` image ID or `repository@sha256:...` digest; mutable tags are refused.
The runner does not build or pull the image. No Lambda helper is needed.

## Run

From the repository root:

```sh
# Actual Step Functions and S3 source-to-destination pipeline; no CodeBuild jobs:
"$EXAMPLE_PYTHON" examples/terraform-application-controls/jobs/run.py --port 14731

# Alternative: real build processes and S3 -> CodeBuild -> S3 artifact pipeline.
# Set JOBS_IMAGE to an installed immutable image ID or repository digest first:
: "${JOBS_IMAGE:?Set JOBS_IMAGE to the prepared immutable Linux image reference}"
"$EXAMPLE_PYTHON" examples/terraform-application-controls/jobs/run.py \
  --port 14732 --docker --build-image "$JOBS_IMAGE" \
  --docker-host unix:///var/run/docker.sock
```

`--build-image` is valid only with explicit `--docker`. That mode binds the
controller on all interfaces for callbacks; use a trusted, firewalled host and
an existing local daemon. `--docker-host` defaults to `unix:///var/run/docker.sock`.
`--port` selects an unused unprivileged controller port;
`--stackd /absolute/path/to/stackd` selects a prepared binary;
`--work-parent /existing/directory` selects the new unique workspace's parent.
`--provider-mirror /absolute/path/to/mirror` uses AWS 6.68.0 from a filesystem
mirror with no direct fallback; omit it to allow registry installation.

## Expected results

The runner creates and consumes `v1`, imports six native owners, updates to `v2`,
checks new and retained immutable workflow publications, and consumes S3 pipeline
bytes. Docker mode additionally reads actual build outputs. It requires strict
refresh/normal plans, reopens the same database, checks retained execution
history and consumes fresh workflow/pipeline/build effects before teardown.
Success prints `Jobs lifecycle and actual consumers complete`.

The private printed directory retains `stackd.sqlite`, full `stackd.log`,
`stackd-before-reopen.log`, numbered `terraform-*.log`, state, import backup,
plans plus plan JSON and incremental `evidence.json`. Inspect failures and
cleanup separately from completed stages. Artifact bytes, configuration and
credentials in this directory are private; do not publish them.

## Cleanup

The runner waits for admitted CodeBuild/pipeline work to reach terminal states
before ordinary Terraform destroy removes projects, roles and artifact buckets.
It checks signed absence/empty state and stops its controller. Each import saves
a state backup and restores ownership on import failure so normal cleanup can
still destroy the resource. A failed cleanup is not a passed lifecycle. Remove
only the exact printed workspace after all owned processes stop and its evidence
is no longer needed; never broadly prune Docker state.

## Limitations

Non-Docker mode exercises real S3 source/deploy bytes and Step Functions but
never executes or simulates CodeBuild. Docker mode only establishes the declared
shell/Python build path, not all AWS build environments or pipeline actions.
Unsupported branches remain in `inventory.json`.

A strict detailed-exitcode 2 remains a final failure even when independent
reopen consumers and cleanup finish. The optional
[Terraform Core correction](../../README.md#terraform-core-refresh-only-correction-opt-in)
is a locally patched 1.16.6 consumer, not an official release. Its API-controls
result does not verify jobs; keep source/patch/binary checksums and patched
versus official run results separate.
