# Terraform compute

## Purpose

Independent runners cover [Lambda/ECR](lambda-ecr/README.md), [ECS](ecs/README.md), [EKS](eks/README.md), [Auto Scaling](autoscaling/README.md), and [network/ALB](network-alb/README.md). There is no top-level `run.py`: choose the child runner matching your prepared host and runtime.

## Prerequisites

Start with the [shared example setup](../README.md), including Python dependencies and `bin/stackd`. All five runners require Terraform **1.15.9 or later** and pin AWS provider **6.68.0**. Supply an existing provider filesystem mirror with `--provider-mirror` to avoid provider downloads.

Prepare only the runtime you select using [container deployment](../../docs/runtime-containers.md) and [VM/Kubernetes deployment](../../docs/runtime-vms.md). ECS, EKS, Auto Scaling guests and ALB need the supported local rootful Linux host, not a remote Docker daemon or Docker Desktop. Lambda has a separate Desktop route. Images must already be installed; the runners do not pull them. Image overrides do not prepare host networking, storage or CPU emulation.

## Run

All commands are from the repository root. Follow the linked child guide before running:

```sh
python3 examples/terraform-compute/lambda-ecr/run.py --provider-mirror /absolute/path/to/provider-mirror
python3 examples/terraform-compute/ecs/run.py --provider-mirror /absolute/path/to/provider-mirror
python3 examples/terraform-compute/eks/run.py --provider-mirror /absolute/path/to/provider-mirror
python3 examples/terraform-compute/autoscaling/run.py --endpoint http://127.0.0.1:4566 \
  --image-id ami-YOUR_IMPORTED_IMAGE --provider-mirror /absolute/path/to/provider-mirror
python3 examples/terraform-compute/network-alb/run.py --network-only \
  --provider-mirror /absolute/path/to/provider-mirror
```

Default owned-controller port is **14707**, so run sequentially or select distinct `--port` values. Common options include `--stackd`, `--work-parent` (an existing directory) and `--provider-mirror`. ECS, EKS and Lambda/ECR require a fixture-owned controller for reopen despite the parsers exposing `--endpoint`; only Auto Scaling uses a caller-owned controller. Network/ALB always owns its controller.

## Expected results

Runners print the owned workspace and checks as they complete. Success means zero exit status through their consumers, strict plan assertions and cleanup. Outputs differ by child; do not assume a uniform report format or infer execution of other children. The commands here have not been certified by a documentation-only edit.

## Cleanup

Each runner destroys its owned Terraform resources and stops controllers it started. Auto Scaling leaves its caller-owned controller and imported base image intact. Retained workspaces contain SQLite, Terraform state/plans, authentication files and logs; keep them on failure, since another invocation creates a different owner. Remove only the exact printed workspace after successful cleanup and shutdown, and never prune all Docker objects or delete by prefix. Treat raw artifacts as private.

Preserve [`resources.json`](resources.json), [`procedure.json`](procedure.json) and child inventory/support/procedure JSON files: they are source inventories, not disposable run output.

## Limitations

`--network-only` omits ALB forwarding and target execution. Auto Scaling requires an already running EC2/QEMU controller and imported compatible guest image; it cannot prepare those for you. See child guides for architecture, host and helper requirements, runtime flags and specific consumer scope.
