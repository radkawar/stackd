# Terraform EKS

## Purpose

Create an EKS-backed k3d cluster, exercise TLS/token authentication and Terraform-managed IAM access, deploy two workload revisions, and consume service DNS/HTTP from an independent pod. The lifecycle also checks imports, unchanged plans, controller reopen and deletion.

## Prerequisites

Complete the [shared setup](../../README.md), [compute prerequisites](../README.md#prerequisites) and [VM/Kubernetes deployment](../../../docs/runtime-vms.md). Use the supported local rootful Linux Docker host. Install pinned **k3d v5.8.3** at `bin/k3d-v5.8.3` or select it with `--k3d`. Prepare the k3d/k3s images required by the deployment guide and the installed workload image **`busybox:1.36.1`** with `httpd` and `wget`. The runner imports the workload image into the owned cluster and uses `imagePullPolicy: Never`; it does not install missing images for you.

## Run

From the repository root:

```sh
python3 examples/terraform-compute/eks/run.py \
  --provider-mirror /absolute/path/to/provider-mirror \
  --k3d "$PWD/bin/k3d-v5.8.3"
```

Optional `--pod-image` selects a compatible installed workload image. `--docker-host` defaults to `unix:///var/run/docker.sock`; default API port is **14707**. Shared overrides are `--port`, `--stackd` and `--work-parent`. Do not pass `--endpoint`: reopen requires an owned controller.

The runner supplies an owned `-eks-state-directory`, `-eks-k3d`, `-eks-listen-host 127.0.0.1` and `-eks-endpoint-host 127.0.0.1`; there is no additional `-eks-runtime` flag in this command. The AWS controller listener binds all IPv4 interfaces for containers; restrict inbound access. Kubernetes is exposed through its owned loopback TLS endpoint.

## Expected results

Console messages cover rejected malformed/wrong-host tokens and pod-consumed service bytes for the configured revisions. Zero exit status requires the complete lifecycle and cleanup, not just cluster creation. Retained failure diagnostics and authentication artifacts are private; this README asserts no new execution result.

## Cleanup

The runner removes its workload/authentication and Terraform resources and checks owned cluster/node retirement before stopping the controller. Preserve the printed workspace, owned state and logs on failure. A new run does not recover the old one. After verified cleanup/shutdown, remove only that directory if no longer needed; never remove unrelated k3d clusters or prune Docker globally. Preserve group inventories.

## Limitations

This is the declared local k3d/k3s topology and workload, not a hosted Kubernetes control plane. Image architecture must match the prepared host/cluster. Docker Desktop and remote-daemon routing are outside this Linux host recipe.
