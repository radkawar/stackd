# Terraform application

## Purpose

Provision an S3 bucket, SQS queue and SSM parameter. Send an object manifest
through the queue, retrieve the referenced object, check a no-change Terraform
plan and destroy the application.

## Prerequisites

Complete [shared preparation](../README.md#prepare-once). Install Terraform
>= 1.5, < 2. Docker is not required. The AWS provider is pinned to **6.68.0**;
the checked-in lock file contains publisher-verified checksums for Linux and
macOS on amd64 and arm64.

## Run

From the repository root:

```sh
"$EXAMPLE_PYTHON" examples/terraform/run.py --port 14661
```

Use `--stackd PATH` for an installed server or `--work-parent PATH` to select
the parent of the new run directory. The runner copies the configuration and
lock file into that directory and starts its own server.

## Expected results

The runner performs `init`, `apply`, a saved no-change `plan`, another `apply`
and `destroy`. It fails if the plan exits with an error or reports drift.

Application checks read the SSM parameter, upload binary bytes to S3, send a
JSON manifest through SQS, and compare the received message and downloaded
object with the originals. The message and object are deleted after each check.
`outputs.json` records the bucket, queue URL and parameter name.

## Cleanup

The runner destroys the application, checks that its resources are absent and
that Terraform state is empty, then stops the server. It attempts destroy even
if application checks fail. Files remain in the printed run directory; follow
[shared cleanup](../README.md#cleanup-and-evidence) after inspection.

## Limitations

This example uses local administrative credentials. It does not exercise
restricted IAM roles. Every provider service has a local endpoint; add the
corresponding endpoint when extending the configuration with another service.

## Lock updates and offline preparation

When changing the provider version, update `main.tf`, then generate a lock in a
scratch directory and review the signed checksums before committing it:

```sh
TF_PREP="$(mktemp -d /tmp/stackd-tf-prep.XXXXXX)"
cp examples/terraform/main.tf "$TF_PREP/"
terraform -chdir="$TF_PREP" providers lock \
  -platform=linux_amd64 -platform=linux_arm64 \
  -platform=darwin_amd64 -platform=darwin_arm64
```

For offline execution, create an archive-layout provider mirror while connected:

```sh
TF_MIRROR="$(mktemp -d /tmp/stackd-tf-mirror.XXXXXX)"
terraform -chdir="$TF_PREP" providers mirror \
  -platform=linux_amd64 -platform=linux_arm64 \
  -platform=darwin_amd64 -platform=darwin_arm64 "$TF_MIRROR"
"$EXAMPLE_PYTHON" examples/terraform/run.py --port 14661 \
  --provider-mirror "$TF_MIRROR"
```

Transfer the mirror to the offline host and pass its absolute path. Mirror mode
has no direct-download fallback. The runner ignores inherited Terraform CLI
configuration and development-provider overrides, and verifies the selected
provider against the copied lock without modifying the source lock.

Remove your scratch directories when finished. Do not commit provider binaries,
mirrors, plans, state or generated outputs.
