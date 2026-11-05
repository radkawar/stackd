# Terraform messaging

## Purpose

Provision SQS, SNS, EventBridge, Scheduler, Pipes and AppConfig, then consume
actual queue messages, authenticated HTTPS deliveries and hosted configuration
bytes. Check current IAM authorization, DLQ behavior and retained SQLite state.
`coverage.json` preserves detailed scope and historical evidence; the fixture
is not a complete messaging-service compatibility claim.

## Prerequisites

Complete the shared [Python environment and build setup](../README.md#prepare-once)
and export `EXAMPLE_PYTHON`. Shared Python dependencies suffice. Install
Terraform **>= 1.15.9, < 2.0.0** and OpenSSL on `PATH`. AWS provider **6.68.0**
is pinned with a checked-in checksum lock. No Docker or native engine is needed.
Registry installation needs network access unless a provider mirror is prepared.

## Run

From the repository root:

```sh
"$EXAMPLE_PYTHON" examples/terraform-messaging/run.py --port 14702
```

`--port` selects an unused unprivileged controller port. An owned HTTPS receiver
uses a separate OS-selected loopback port and a generated certificate trusted
only for this run. `--stackd /absolute/path/to/stackd` selects a prepared binary;
`--work-parent /existing/directory` selects the parent of the new workspace.
`--provider-mirror /absolute/path/to/mirror` uses the official AWS 6.68.0 package
from an existing filesystem mirror, without direct-download fallback. Omit it
to permit registry installation. The runner owns its controller and fresh
SQLite state; never apply this configuration to a shared endpoint/account.

## Expected results

A complete run exercises both revisions of SNS filtering/delivery, EventBridge
SQS/HTTPS routing and archive admission, Pipes source acknowledgement, AppConfig
Data token/byte semantics and completion notifications, Scheduler current-role
revocation/recovery, and SQS visibility/redrive. It imports cohort resources,
requires normal no-op plans, reopens the same SQLite timeline, repeats consumers
and performs ordered teardown. Success prints `Messaging lifecycle complete`.

The private printed workspace retains `stackd.sqlite`, the full `stackd.log`,
Terraform state, saved plans, `before-import.tfstate`, provider configuration,
`import-provider.log`, and receiver TLS material. Terraform output normally goes
to the terminal; this runner does not write an incremental `evidence.json`.
Keep the directory private, including connection API keys and state.

## Cleanup

The runner attempts teardown in the lifecycle's `finally` block: it applies a
deletion-only plan for ordinary resources, verifies only the service-linked role
remains, advances owned service time beyond that role's maximum session duration,
then applies the final deletion plan. It checks native absence and empty state,
closes its HTTPS receiver and stops its controller. Failures remain failures even
when cleanup succeeds. Remove only the exact printed workspace after processes
stop and its evidence is no longer needed; do not broadly delete Docker or data.

## Limitations

Mobile/SMS/email SNS delivery, EventBridge global failover, full native fleet
throughput, and several Pipes adapters are outside this example; see
`coverage.json` for specific unsupported and merely unexercised branches.
Imported EventBridge connections cannot expose the API-key value, so the runner
reapplies the original private credential. SQS import identity is derived from
signed QueueArn metadata while transport remains explicitly local.

A semantic no-op detailed-exitcode 2 is retained as terminal failure, even when
independent imports/update/reopen/cleanup complete. The optional
[Terraform Core correction](../README.md#terraform-core-refresh-only-correction-opt-in)
is a locally patched consumer, not an official binary. Keep those results and
checksums separate; do not weaken no-op assertions or downgrade the provider.
