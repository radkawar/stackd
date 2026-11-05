# Terraform analytics catalog

## Purpose

Exercise Glue catalog resources, connections, crawlers, jobs/workflows, schema-registry records and resource policies together with PostgreSQL, Athena and Kinesis consumers. The runner applies two revisions, imports selected resources, checks refresh/no-change plans, reopens its controller, verifies retained data and destroys owned resources.

## Prerequisites

Complete the [shared example setup](../README.md) and [container deployment](../../docs/runtime-containers.md). Prepare Terraform **1.15.9**, AWS provider **6.68.0**, Docker CLI and host `psql`, then install the group's extra Python dependencies:

```sh
python3 -m pip install -r examples/terraform-analytics-catalog/requirements.txt
```

Install all exact digests in [`run.py`'s `IMAGES`](run.py): the sibling analytics runner's Trino, Spark, Kafka and both Glue images, plus PostgreSQL. Review/accept [the Glue license](../../compute/glue/AWS-GLUE-LICENSE.txt) following deployment instructions. This runner has no reduced-runtime mode. It inspects images and starts PostgreSQL with `--pull=never`.

Use a local Linux Docker host whose published loopback ports are reachable from the controller and `psql`. `--docker-host` defaults to `unix:///var/run/docker.sock`. The controller binds all IPv4 interfaces for container access; restrict inbound access to this trusted development host. PostgreSQL is published on a dynamically selected loopback port and uses a generated password retained privately in the workspace.

## Run

From the repository root:

```sh
python3 examples/terraform-analytics-catalog/run.py \
  --provider-mirror /absolute/path/to/provider-mirror
```

Default API port: **14715**. Common overrides are `--port`, `--stackd`, and `--work-parent` (an existing directory). The runner owns a fresh controller/database and enables `-athena-runtime -kinesis-runtime -glue-runtime` with the selected Docker host. Without `--provider-mirror`, Terraform may download the provider during initialization.

## Expected results

The console prints the owned workspace and completed stages. `report.json` records completed catalog/password/workflow/PostgreSQL/schema/policy consumers and lifecycle stages, plus assertion failures. Success requires a zero exit status, including strict plan assertions and cleanup; a partial report is not a successful run. No execution result is claimed by this README.

## Cleanup

The runner attempts to remove its probe resources and Terraform resources, stops its controller, and removes its exact PostgreSQL container. Keep the workspace after any failure: it contains SQLite, Terraform state/plans, controller logs (including `stackd-before-reopen.log`) and PostgreSQL credentials. Do not publish these files or remove containers/volumes belonging to other runs. A new invocation does not recover a failed prior workspace.

After confirmed successful cleanup and shutdown, delete only the exact printed workspace if desired. Review `report.json` before sharing it. Preserve the checked-in [`coverage.json`](coverage.json), which is an operation inventory rather than generated output.

## Limitations

The runner tests its declared connection/workflow/schema revisions and selected imports, not every Glue operation in the inventory. PostgreSQL initialization and job/crawler consumers require all dependencies even when only one stage is of interest. Image installation, provider downloads and license acceptance are separate preparation steps.
