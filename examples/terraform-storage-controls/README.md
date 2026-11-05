# Terraform storage controls

## Purpose

Exercise S3 storage controls, DynamoDB recovery/stream controls, and optional EBS guest attachment, resize, snapshot and restore. Each module applies and updates Terraform resources, checks imports and unchanged plans, verifies retained state across controller reopen, and performs owned cleanup.

## Prerequisites

Complete the [shared example setup](../README.md). Prepare exact Terraform **1.15.9**, AWS provider **6.68.0**, the shared Python dependencies and a filesystem provider mirror. Direct provider installation is disabled.

- **S3:** host-only workflow; review [`s3-limits.json`](s3-limits.json) for the selected lifecycle/tiering/control behavior.
- **DynamoDB:** local rootful Linux Docker, installed pinned DynamoDB Local **and Kafka** images, and the dependencies in [`dynamodb-limits.json`](dynamodb-limits.json). This module enables both DynamoDB and Kinesis runtimes.
- **EBS:** prepare the [Linux QEMU/KVM host and guest](../../docs/runtime-vms.md), including local rootful Docker, toolkit image, firmware and raw **x86_64 Linux HVM** disk with cloud-init, Python 3 and NVMe support. Review [`ebs-limits.json`](ebs-limits.json). The runner imports its own copy of the prepared guest image; it does not download an OS. Firmware must match the selected boot mode. Choose a short existing `--work-parent` path so QEMU's Unix sockets fit the host limit.

Install images using [container deployment](../../docs/runtime-containers.md); nothing is pulled during the run. `--docker-host` defaults to `unix:///var/run/docker.sock`; use a supported local daemon, not a remote endpoint. EBS binds the controller on all IPv4 interfaces for guest access: restrict inbound access on this trusted host.

## Run

From the repository root:

```sh
# Default modules: S3 + DynamoDB (including Kinesis)
python3 examples/terraform-storage-controls/run.py \
  --provider-mirror /absolute/path/to/provider-mirror
# Host-only S3 controls
python3 examples/terraform-storage-controls/run.py --services s3 \
  --provider-mirror /absolute/path/to/provider-mirror
# EBS guest workflow, legacy BIOS example
python3 examples/terraform-storage-controls/run.py --services ebs \
  --provider-mirror /absolute/path/to/provider-mirror \
  --work-parent /tmp --guest-image /absolute/path/to/guest.raw \
  --guest-boot-mode legacy-bios --ec2-bios /absolute/path/to/bios.bin
```

For UEFI replace the BIOS options with `--guest-boot-mode uefi --ec2-uefi-code /absolute/path/to/code.fd --ec2-uefi-vars /absolute/path/to/vars.fd`. Optional EBS settings are `--guest-instance-type` (default `t3.small`) and `--ebs-vpc-cidr` (an unused guest `/24`). `--services` accepts unique comma-separated `s3,dynamodb,ebs` without spaces. `--account-id` selects a twelve-digit local owner.

Default port: **14714**; shared overrides are `--port`, `--stackd`, and `--work-parent`. DynamoDB adds `-dynamodb-runtime -kinesis-runtime`; EBS adds its owned `-ec2-state-directory` and the selected firmware flags. All cohorts start manual service time at `2031-01-01T00:00:00Z`; reopening resumes saved time. S3's tiering consumer advances it by 92 days, after other retained-data checks.

## Expected results

Success exits zero after module checks, controller reopen and cleanup. The console prints the private workspace; `report.json` contains `status`, completed stages, command metadata and owned runtime identities. Numbered Terraform output files retain diagnostics privately. Strict no-change failures are not ignored. This README documents the executable workflows, not an execution result.

## Cleanup

The runner attempts reverse-order module cleanup and Terraform destroy, checks owned resource absence, and waits for exactly identified DynamoDB/Kinesis Docker objects to retire. EBS cleanup includes its guest, disks, snapshots, network and bootstrap resources. It stops the controller but retains SQLite, guest state, Terraform state/plans, variables, credentials and logs.

On any failure keep the exact printed workspace; a fresh invocation is not recovery. Never prune Docker globally or delete objects by prefix. Remove only that workspace after successful cleanup and shutdown, and do not share raw state, variables, disks or logs. Review reports before sharing. Preserve source `inventory.json` and all `*-limits.json` files.

## Limitations

EBS requires a prepared compatible guest and actual QEMU/KVM host; it is not the host-only [EBS Direct API example](../terraform-storage/README.md). Manual service time affects lifecycle and backup semantics, not host runtime execution speed. Source inventories list additional settings and operations beyond the selected module checks.
