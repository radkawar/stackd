# Terraform analytics

## Purpose

Create and update an S3-backed Glue catalog, query it through Athena, and consume Kinesis/Firehose delivery. The runner also imports selected resources, checks refresh/no-change plans, reopens its SQLite-backed controller, and destroys its resources. An optional Glue Python-shell job consumes the configured data.

## Prerequisites

Complete the [shared example setup](../README.md) first: build `bin/stackd`, activate the Python environment, and prepare Terraform and AWS provider **6.68.0**. Use Terraform **1.15.9** for the documented workflow; the configuration accepts `>= 1.5.0, < 2.0.0` and the runner does not enforce an exact Terraform release. Follow [container deployment](../../docs/runtime-containers.md) for Docker permissions and image installation.

Install the exact Trino, Spark and Kafka digests in [`run.py`'s `IMAGES`](run.py); images are inspected, never pulled by the runner. For `--glue-job`, also install both `GLUE_IMAGES` and review/accept [the Glue license](../../compute/glue/AWS-GLUE-LICENSE.txt) under the deployment instructions. Missing dependencies fail the run rather than skipping consumers.

Use a prepared local Linux Docker host reachable by the controller. The runner binds the controller on all IPv4 interfaces so container consumers can reach it: restrict inbound access on this trusted development host. The default Docker socket is `unix:///var/run/docker.sock`; `--docker-host` selects another supported local daemon.

## Run

Run from the repository root; substitute an existing absolute provider mirror path:

```sh
python3 examples/terraform-analytics/run.py \
  --provider-mirror /absolute/path/to/provider-mirror
# Include the Glue Python-shell consumer after preparing its dependencies:
python3 examples/terraform-analytics/run.py \
  --provider-mirror /absolute/path/to/provider-mirror --glue-job
```

The default port is **14705**. Common overrides are `--port`, `--stackd`, and `--work-parent` (an existing directory). Each invocation creates a new retained workspace, never reusing a running controller. It enables `-athena-runtime -kinesis-runtime`, plus `-glue-runtime` only with `--glue-job`. Omitting `--provider-mirror` allows Terraform's normal provider installation; the mirror form above avoids that download.

## Expected results

The runner prints the owned directory, controller command and `Completed:` stages. A successful invocation exits zero after query/delivery consumers, import/update/reopen checks and cleanup. The retained `report.json` records completed stages, Terraform commands and assertion failures; consult it together with the process exit status. Strict refresh failures remain failures even when later cleanup completes. These instructions describe the workflow, not a newly executed result.

## Cleanup

The runner attempts Terraform destroy and SDK cleanup before stopping its controller. Keep the printed workspace if any assertion or cleanup fails; its SQLite database, Terraform state, plans and logs are needed to inspect the exact owned resources. A second invocation creates a different workspace and is not recovery for the first. Do not run blanket Docker prune or remove objects by name prefix.

After successful cleanup and controller shutdown, remove only the exact printed run directory if its artifacts are no longer needed. Treat state, variables, query results and logs as private; review reports before sharing them. Source [`coverage.json`](coverage.json) is an inventory and must not be deleted as run output.

## Limitations

`--glue-job` is opt-in; the default invocation does not exercise that job. Selected import types and consumers are defined in `run.py`; other catalog/runtime operations listed in `coverage.json` are not implied by a successful run. Container images and providers must be prepared separately for disconnected execution.
