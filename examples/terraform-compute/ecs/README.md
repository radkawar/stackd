# Terraform ECS

## Purpose

Create an ECS service and standalone tasks, consume task HTTP responses and Docker output, exercise service/application scaling and updates, verify controller reopen, and destroy the owned deployment.

## Prerequisites

Complete the [shared setup](../../README.md), [compute prerequisites](../README.md#prerequisites) and [ECS host setup](../../../docs/ecs.md#setup-and-supported-execution). Use local rootful Linux Docker with systemd/cgroup v2 and no user-namespace remapping. Prepare the toolkit image from [container deployment](../../../docs/runtime-containers.md) and installed **Linux/amd64 `busybox:1.36.1`** with `httpd`. A different installed image can be selected with `--image`, but must satisfy the same shell/httpd and architecture requirements.

## Run

From the repository root:

```sh
python3 examples/terraform-compute/ecs/run.py \
  --provider-mirror /absolute/path/to/provider-mirror
```

The runner enables `-ecs-runtime` with `--docker-host` (default `unix:///var/run/docker.sock`). Default API port is **14707**; shared overrides are `--port`, `--stackd` and `--work-parent`. It must own its controller: do not supply `--endpoint`. The listener binds all IPv4 interfaces for workload access; restrict inbound traffic on the trusted host.

## Expected results

Console messages identify consumed task PIDs, Docker output and HTTP revision bytes. Successful completion requires lifecycle/import/plan/reopen checks and destroy with empty managed state, not just a task reaching `RUNNING`. No run result is claimed here.

## Cleanup

The runner retires its tasks/service/scaling resources and destroys its Terraform state before stopping the controller. Keep the printed private directory (state, SQLite, plans and logs) on failure; rerunning does not recover it. Remove only that exact directory after successful cleanup/shutdown. Never prune unrelated Docker resources; preserve group inventories.

## Limitations

This fixture requires host reachability to private task addresses and a supported Linux host; it is not a Desktop/remote-daemon example. The BusyBox consumer tests its declared task/service scenario, not arbitrary application images. Review artifacts before sharing them.
