# Terraform VPC Flow Logs

## Purpose

The Terraform configuration creates VPC/subnet/ENI flow-log subscriptions with CloudWatch Logs, gzip text S3 and typed Parquet S3 destinations. Its runnable entrypoint is [`scripts/native/vpc_flow_logs.py`](../../../scripts/native/vpc_flow_logs.py), not the basic `examples/terraform/run.py`. That consumer launches ECS UDP listeners and payload-free TCP connections, verifies allowed and SG/NACL-denied traffic, checks records across graceful controller restart, updates Terraform tags, checks unchanged plans and destroys owned resources.

## Prerequisites

Complete the [shared example setup](../../README.md), [container deployment](../../../docs/runtime-containers.md) and [flow-log host setup](../../../docs/ec2.md#vpc-flow-logs). Prepare Terraform (the retained workflow uses **1.15.9**), pinned AWS provider **6.68.0**, Python `boto3`, and PyArrow with GZIP support using the shared requirements.

Use a trusted local **rootful Linux Docker** host, without rootless mode or user-namespace remapping, and the ECS systemd/cgroup-v2/network prerequisites. Preinstall the digest-pinned toolkit image from container deployment and **`python:3.12-alpine`** (or a compatible installed Python 3 image selected by `--image`). No images are pulled by the consumer. Host private-network access and an unused private `/24` are required. Docker Desktop and arbitrary remote Docker hosts are not this recipe.

The flow collector and temporary TCP witness use packet-capture capabilities. The TCP witness shares the exact source task's network namespace and retains header-only observations; helper loss or incomplete capture fails assertions. The runner does not change host packet-offload settings.

## Run

Run from the repository root. `--state-directory` must name a **new, nonexistent** directory; choose a unique private path, not a shared directory or existing checkout:

```sh
umask 077
python3 scripts/native/vpc_flow_logs.py --binary bin/stackd \
  --state-directory /tmp/stackd-flow-logs-UNIQUE \
  --provider-mirror /absolute/path/to/provider-mirror \
  --remove-owned-capture
```

Replace `UNIQUE` before each invocation. `--docker-host` defaults to `DOCKER_HOST` or `unix:///var/run/docker.sock`. Default `--cidr` is `10.254.244.0/24`; override it if occupied. `--port 0` selects an available API port; `--publication-timeout` defaults to **480 real seconds**. Unlike shared example runners, this entrypoint uses `--binary` and `--state-directory`, not `--stackd`/`--work-parent`.

The consumer launches its owned controller with `-ecs-runtime`, `-compute-endpoint http://host.docker.internal:PORT`, `-vpc-flow-logs-runtime docker` and a unique `-vpc-flow-logs-namespace`. It binds all IPv4 interfaces for container access: restrict inbound traffic on the trusted host. `--provider-mirror` disables direct provider downloads; without it initialization may access the provider registry.

## Expected results

`report.json` in the chosen directory records packet/record assertions, owned native identities, checkpoint/restart observations, CloudWatch events, S3 text/Parquet objects and cleanup. Success requires process exit zero, `completed: true` and verified cleanup without errors. Records use actual aggregation/publication time; do not shorten the run by advancing service time. These commands describe how to execute the checks, not a newly observed result. See [EC2 flow-log documentation](../../../docs/ec2.md#vpc-flow-logs) for the preserved integration evidence and its exact scope.

## Cleanup

The consumer attempts API/task/Terraform cleanup and stops the controller in `finally`. `--remove-owned-capture` additionally requests exact-owned collector removal through its native idle receipt, only after successful cleanup. Without that option the collector is deliberately retained and identified in the report. Do not infer that it is idle from labels alone, or force-remove it while unread capture may remain.

SQLite, Terraform state, logs, report and captured artifacts remain in the supplied directory. Retain that directory on any failure; another invocation uses a different namespace and is not recovery. Inspect `report.json` cleanup errors and exact identities rather than pruning Docker or deleting by prefix. Remove only the exact directory after verified cleanup/shutdown and after resolving any retained collector. Keep raw captures, state and logs private; review reports before sharing them. Preserve checked-in source and integration evidence inventories.

## Limitations

Restart checks cover ordinary graceful shutdown and retained checkpoints, not crash exactly-once delivery. S3 admission-marker objects are not flow records. This declared UDP/TCP scenario and destination/schema assertions do not establish every protocol or arbitrary topology. Manual Terraform apply alone does not generate the traffic, capture or record-consumption checks supplied by the Python consumer.
