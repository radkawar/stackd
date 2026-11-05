# Terraform network and ALB

## Purpose

Exercise Terraform VPC/network resources alone, or include an ALB relay and HTTP target consumers across two revisions. The full mode creates its own ECS target unless prepared target variables are supplied, checks forwarding and lifecycle plans, and destroys its deployment.

## Prerequisites

Complete the [shared setup](../../README.md) and [compute prerequisites](../README.md#prerequisites): Terraform **1.15.9 or later**, AWS provider **6.68.0** and Python dependencies.

`--network-only` needs no Docker target or relay executable. Full mode requires the supported local rootful Linux Docker/network host, the installed toolkit image, and:

- A static Linux relay matching the daemon host, built/installed following [ALB relay deployment](../../../docs/runtime-containers.md#alb-relay).
- An installed native HTTP desync adapter linked to the pinned official library. See [`adapter/Makefile`](../../../compute/elbv2/desync/adapter/Makefile) for Rust/Cargo, cbindgen, C toolchain and pinned source preparation/install requirements. Pass the installed executable, not a substitute classifier.
- For the default owned target, installed **Linux/amd64 `busybox:1.36.1`** with `httpd`; `--image` can select another compatible installed image.

## Run

From the repository root:

```sh
# Network resource lifecycle only
python3 examples/terraform-compute/network-alb/run.py --network-only \
  --provider-mirror /absolute/path/to/provider-mirror
# ALB with an owned ECS HTTP target
python3 examples/terraform-compute/network-alb/run.py \
  --provider-mirror /absolute/path/to/provider-mirror \
  --elbv2-node-executable "$PWD/bin/stackd-elbv2-node" \
  --desync-executable /absolute/path/to/stackd-http-desync-guardian
```

Full mode supplies `-elbv2-node-executable`, `-elbv2-desync-executable` and an available loopback `-dns-listen` address, plus `-ecs-runtime` for the owned target. `--docker-host` defaults to `unix:///var/run/docker.sock`. It binds the controller on all IPv4 interfaces for workloads; restrict inbound traffic. Network-only mode omits these flags and uses a loopback controller. Default API port: **14707**; common overrides are `--port`, `--stackd` and `--work-parent`.

Advanced `--variables /absolute/path/to/variables.json` accepts a JSON object matching [`main.tf`](main.tf). Prepared `targets` require the exact `expected_target_body`; the runner forbids overriding its lifecycle ownership fields. Prepared target servers remain caller-owned. Do not use invented endpoints or assume system DNS automatically resolves the ALB hostname.

## Expected results

Full mode checks target process/HTTP bytes, ALB forwarding and revision changes; network-only mode does not execute ALB packets. Terraform output/consumer artifacts are retained in the printed workspace, including `outputs.json`. Success requires zero exit status through strict no-change assertions and cleanup. This README does not claim a run result.

## Cleanup

The runner retires its owned ECS target when used and destroys its Terraform network/ALB resources before stopping the controller. Caller-supplied target servers are not deleted. Keep SQLite, state, variables, outputs, plans and logs after failure; a new run is not recovery. After verified successful cleanup/shutdown, remove only that exact workspace if desired. Do not prune unrelated Docker resources. Treat artifacts as private and preserve [`inventory.json`](inventory.json) and [`procedure.json`](procedure.json).

## Limitations

`--network-only` intentionally omits ALB consumers. Full forwarding requires both installed helper executables and a compatible host. External topology variables must describe reachable prepared targets. The source inventory lists additional operations beyond these configured consumers.
