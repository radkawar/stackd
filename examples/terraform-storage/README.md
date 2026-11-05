# Terraform storage

## Purpose

Run selected S3, DynamoDB and EBS Direct API data consumers, or PostgreSQL/MySQL RDS and Mongo-backed DocDB lifecycle consumers. Modules apply, update and import resources, exercise current IAM authority, check unchanged plans, reopen the same controller/database, and destroy their resources.

## Prerequisites

Complete the [shared example setup](../README.md). This runner requires exact Terraform **1.15.9**, AWS provider **6.68.0**, and an existing filesystem provider mirror: direct provider installation is disabled. Install the shared Python dependencies, including `pymongo` when selecting DocDB.

| Selection | Additional preparation |
| --- | --- |
| `s3,ebs` | No Docker or QEMU needed; EBS here uses snapshot block APIs, not attached guest disks. |
| `dynamodb` | Local Linux Docker at **`unix:///var/run/docker.sock`** and the pinned DynamoDB Local image in [`limits.json`](limits.json). |
| `rds` | Same local Docker socket, host `psql`, and exact PostgreSQL/MySQL images in [`rds.py`](rds.py). An Oracle MySQL CLI is optional; the pinned MySQL image supplies the fallback client. |
| `docdb` | Same local Docker socket, `pymongo`, and the Mongo image in [`docdb-limits.json`](docdb-limits.json). |

Follow [container deployment](../../docs/runtime-containers.md) to prepare images; the runner does not pull them. Database consumers require controller/host access to Docker-published loopback ports. There is no `--docker-host` override in this runner; remote Docker/Desktop routing is not this recipe.

## Run

All commands run from the repository root with the Python environment active:

```sh
# Default cohort: S3 + DynamoDB + EBS Direct APIs
python3 examples/terraform-storage/run.py \
  --provider-mirror /absolute/path/to/provider-mirror
# Host-only subset
python3 examples/terraform-storage/run.py --services s3,ebs \
  --provider-mirror /absolute/path/to/provider-mirror
# PostgreSQL and MySQL lifecycle
python3 examples/terraform-storage/run.py --services rds \
  --provider-mirror /absolute/path/to/provider-mirror
# DocDB must run alone
python3 examples/terraform-storage/run.py --services docdb \
  --provider-mirror /absolute/path/to/provider-mirror
```

`--services` accepts unique comma-separated `s3,dynamodb,ebs,rds,docdb` without spaces; DocDB cannot be combined with another service. Default port: **14704**. `--port`, `--stackd` and `--work-parent` (an existing directory) override shared defaults.

The runner enables only selected `-dynamodb-runtime`, `-rds-runtime` and/or `-docdb-runtime` flags. DocDB starts service time at `2031-01-01T08:59:00Z` and advances it for backup/expiry scenarios; other cohorts use wall time. Each invocation creates a fresh owned workspace/controller.

## Expected results

The runner prints the retained workspace and finishes with `Completed actual storage stages; controller stopped` only on success. Private `report.json` contains `status`, completed module stages, and command return codes. Terraform stdout/stderr are retained in numbered files instead of echoed because they may contain passwords. The scripts define these checks; this README does not claim they have been run.

## Cleanup

Module cleanup destroys Terraform resources, removes consumer data and checks state/resource absence. For runtime services, the runner also waits for exactly owned Docker containers/volumes to retire. The controller is stopped but SQLite, state, variables, plans, passwords and logs remain in the printed directory.

Keep that exact directory after failures for recovery; rerunning creates a different database and does not clean the original resources. Do not use broad Docker pruning or prefix-based deletion. After successful cleanup and shutdown, remove only the printed workspace if no longer needed. Never share raw state, variables or logs; inspect even `report.json` before sharing it. Keep source [`inventory.json`](inventory.json), [`limits.json`](limits.json), [`rds-limits.json`](rds-limits.json) and [`docdb-limits.json`](docdb-limits.json).

## Limitations

The `ebs` module does not boot a guest or test attachment: use [storage controls](../terraform-storage-controls/README.md) for that workflow. RDS capacity changes are configuration intent, not physical disk-quota proof. PostgreSQL TLS checks and MySQL's explicitly non-TLS client path differ; see `rds.py` for their exact assertions. DocDB backup/expiry checks deliberately use manual service time and therefore run separately. Inventories include operations beyond this runner's selected consumers.
