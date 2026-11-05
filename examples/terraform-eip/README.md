# Terraform Elastic IPs

## Purpose

Allocate two VPC Elastic IP addresses, read their address attributes through
Terraform and the AWS SDK, verify refresh without drift, then release them.

## Prerequisites

Complete [shared preparation](../README.md#prepare-once). Install Terraform
>= 1.5, < 2. The AWS provider is pinned to **6.68.0**. Docker is not required.

## Run

From the repository root:

```sh
"$EXAMPLE_PYTHON" examples/terraform-eip/run.py --port 14664
```

Use `--stackd PATH` to select an installed server, `--work-parent PATH` to
choose the parent of the new run directory, or `--provider-mirror PATH` to use a
prepared filesystem provider mirror without a direct-download fallback.

The runner starts its own server and initializes Terraform in a new directory.
Terraform verifies the provider package and writes the dependency lock there.

## Expected results

- Two different allocation IDs, with public IPs matching SDK responses.
- `DescribeAddressesAttribute` pagination returns both allocations.
- New addresses have no custom PTR record or pending PTR update.
- Refresh-only and ordinary plans report no changes.
- After destroy, address and attribute requests report the allocations missing,
  and Terraform state contains no resources.

## Cleanup

The runner attempts `terraform destroy` even if checks fail, then stops its
server. The printed run directory retains logs, SQLite state, Terraform files
and `outputs.json`. Follow [shared cleanup](../README.md#cleanup-and-evidence)
after inspecting the results.

## Limitations

This example checks address allocation and attributes, not instance association,
packet routing or custom reverse-DNS updates. See the
[EC2 guide](../../docs/ec2.md#run-the-current-provider-lifecycle) for service details.
