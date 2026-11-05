# Terraform Lambda and ECR

## Purpose

Deploy a Python ZIP function and layer, consume Lambda invocations and telemetry, publish binary OCI layers/manifests through ECR APIs, update revisions, check IAM/authentication and lifecycle plans, reopen the controller and destroy the deployment.

## Prerequisites

Complete the [shared setup](../../README.md) and [compute prerequisites](../README.md#prerequisites). This runner requires Terraform **1.15.9 or later** and AWS provider **6.68.0**. Prepare [Lambda container/storage dependencies](../../../docs/runtime-containers.md), including the exact `STORAGE` image and architecture-specific `RUNTIMES` digest in [`run.py`](run.py). Install the matching `lambda-telemetry-amd64` or `lambda-telemetry-arm64` helper beside the selected stackd executable (`make build` builds the helpers).

The Docker daemon must support the documented privileged storage helpers, loop devices and ext4. Use matching native CPU architecture; choosing `--architecture arm64` does not install emulation. A native macOS controller can use the documented Docker Desktop recipe and `--desktop`; this is not support for a remote arbitrary daemon.

## Run

From the repository root:

```sh
python3 examples/terraform-compute/lambda-ecr/run.py \
  --provider-mirror /absolute/path/to/provider-mirror --architecture x86_64
# On the prepared arm64 Docker Desktop setup instead:
python3 examples/terraform-compute/lambda-ecr/run.py \
  --provider-mirror /absolute/path/to/provider-mirror \
  --architecture arm64 --desktop --docker-host unix:///absolute/path/to/docker.sock
```

The default Docker socket is `unix:///var/run/docker.sock`, overridden by `DOCKER_HOST` or `--docker-host`. Default port: **14707**; shared options are `--port`, `--stackd` and `--work-parent`. Despite an exposed `--endpoint` parser option, this lifecycle requires its own controller for reopen; do not pass that option.

The runner enables `-lambda-runtime`, points `-lambda-telemetry-directory` beside the executable and sets `-compute-endpoint http://host.docker.internal:PORT`. `--desktop` adds `-lambda-callback-host host.docker.internal`. The controller binds all IPv4 interfaces for container access; restrict inbound traffic. Images are inspected rather than pulled.

## Expected results

Consumers and Terraform commands print their stages. Zero exit status requires invocation/registry/authentication assertions, strict plan checks, reopen and deletion, not merely an uploaded function. Source [`support.json`](support.json) records scope and is not a generated pass report. No execution result is claimed by these instructions.

## Cleanup

The runner removes its invocation/authentication resources and destroys the Terraform deployment before stopping the controller. Its printed workspace retains private state, credentials, plans, packaged functions and logs. Preserve it after failures; another invocation is not recovery. After successful cleanup/shutdown, remove only that exact workspace if desired. Never globally prune Docker or publish raw state/keys/logs. Preserve `support.json` and the compute group inventories.

## Limitations

This runner uses its pinned Python runtime and declared ZIP/layer and OCI API consumers; an ECR blob/manifest round trip alone does not establish arbitrary container-image execution support. Architecture and Desktop flags require separately prepared host/image dependencies. Provider installation may use the network if no mirror is supplied.
