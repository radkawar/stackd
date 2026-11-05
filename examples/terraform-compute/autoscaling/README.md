# Terraform Auto Scaling

## Purpose

Launch cloud-init HTTP guests through an Auto Scaling group, execute a SimpleScaling policy, update the launch template and desired capacity, verify replacement guests and unchanged plans, then retire the group and instances.

## Prerequisites

Complete the [shared example setup](../../README.md) and [compute prerequisites](../README.md#prerequisites). Follow [VM deployment](../../../docs/runtime-vms.md) to prepare the local Linux QEMU/KVM host, Docker/network toolkit, firmware and controller EC2 state directory. Start a caller-owned controller reachable at an explicit IPv4 loopback API endpoint, with a workload-reachable compute endpoint and its matching local account.

Import a compatible Linux HVM/cloud-init guest image with **Python 3** into that exact controller first. `--image-id` must identify its available imported image; an arbitrary AWS AMI ID is not sufficient. The host must reach guest private HTTP addresses. Choose an unused private subnet for this run.

## Run

From the repository root, substitute the existing endpoint and imported image ID:

```sh
python3 examples/terraform-compute/autoscaling/run.py \
  --endpoint http://127.0.0.1:4566 --image-id ami-YOUR_IMPORTED_IMAGE \
  --subnet-cidr 10.220.0.0/24 \
  --provider-mirror /absolute/path/to/provider-mirror
```

The default fixture account is the local account in `examples/local.py`; if the caller-owned controller uses another account, pass its twelve-digit `--account-id`. The runner checks the signed account identity. `--subnet-cidr` is optional; without it a private subnet is randomly selected, so explicit unused addressing is preferable on shared hosts. Shared `--stackd`/`--port` do not start a controller for this required `--endpoint` mode. The runner does not add runtime flags to the existing controller; prepare the EC2/QEMU firmware/state/compute-endpoint configuration before invocation.

## Expected results

The consumer checks actual guest console markers and independent HTTP bytes, one-to-two guest scaling, replacement on revision update, Terraform data sources and strict unchanged plans. Success requires zero exit status through destroy and instance retirement; no execution result is claimed here.

## Cleanup

The runner cleans its scaling resources and destroys the owned Terraform deployment. It deliberately leaves the caller-owned controller and imported base image running/present. Stop that controller separately only when its other users no longer need it, using the deployment guide. Retain the printed workspace (Terraform state, plans and logs) if cleanup fails; another run does not recover it. Delete only that exact workspace after successful cleanup. Never remove unrelated guests, networks or Docker objects.

## Limitations

This child cannot run without `--endpoint` and cannot prepare/import its own guest image. It does not reopen the caller-owned controller. Initial provider convergence of zero cooldown is checked explicitly rather than treated as an unchanged initial plan. Preserve group inventories and keep raw state/logs private.
