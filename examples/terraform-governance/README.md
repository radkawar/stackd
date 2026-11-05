# Terraform governance

## Purpose

Run Organizations and governance controls together: organizational units/member
accounts, current SCPs, RAM sharing, CloudFormation/Cloud Control, resource
groups, AppRegistry and Identity Center. Consume real cross-account SSM and S3
bytes and Cognito-authenticated portal/role credentials. The `organization/`
and `controls/` configurations form one ordered workflow, not independent
examples. `coverage.json` records detailed scope and bounded prior evidence.

## Prerequisites

Complete the shared [Python environment and controller build](../README.md#prepare-once)
and export `EXAMPLE_PYTHON`. Shared Python dependencies suffice; no Docker,
external browser or AWS CLI is required. Install Terraform **>= 1.5.0, < 2.0.0**
on `PATH` (historical evidence used **1.15.9**). Both configurations pin AWS
provider **6.68.0**. Registry access or a prepared filesystem mirror is needed
for initial provider installation.

Use the current built controller, including generated CloudFormation support;
normal users should follow the repository build rather than apply fixtures to
an existing account. The runner creates local member/external accounts and
credentials solely inside its fresh owned controller.

## Run

From the repository root:

```sh
"$EXAMPLE_PYTHON" examples/terraform-governance/run.py --port 14708
```

`--port` selects an unused unprivileged loopback port;
`--stackd /absolute/path/to/stackd` selects a prepared binary;
`--work-parent /existing/directory` selects the new workspace's parent.
`--provider-mirror /absolute/path/to/mirror` uses AWS 6.68.0 from that filesystem
mirror with no direct fallback; omit it to permit registry installation.
All SDK/provider requests target the owned local controller. The HTTP portal
consumer submits real Cognito login forms; it does not require or claim AWS CLI
SSO/browser parity.

## Expected results

The runner bootstraps the organization from its actual default policy state,
creates dependency seeds and controls, consumes current cross-account authority,
revokes/restores directory membership, imports 11 selected owners, updates and
reconsumes resources, reopens the database and repeats consumers. Successful
strict refresh/normal plan gates and cleanup end with `Governance lifecycle
complete`.

The printed mode-0700 workspace contains `stackd.sqlite`, full `stackd.log`,
`terraform.rc`, and separate `organization/` and `controls/` Terraform states,
variables, import backups and numbered strict plans. Terraform command output is
printed to the terminal. `evidence.json` is written after final cleanup; earlier
failures may have only terminal output and retained plans/state. Treat state
and issued external credentials as sensitive and do not publish them.

## Cleanup

Dependency order matters: revoke the owner's RAM SSM resource grant before
removing the external accepter, destroy controls before Organizations, then
remove exact SDK seeds. Failure cleanup preserves prerequisites if dependent
controls cannot be removed, rather than pretending successful cleanup. The
runner verifies signed absence, empty states and RAM `DELETED` tombstones, and
stops its controller. Removed local member/external accounts are not physically
erased accounts. After all owned processes stop and evidence is no longer
needed, remove only the exact printed workspace.

## Limitations

The coverage inventory distinguishes supported subsets from unimplemented
resource families; passing this workflow does not establish full Organizations,
CloudFormation, SSO or cross-account parity. The provider requires staged
organization bootstrap to avoid redundantly enabling the native default SCP;
no provider errors or actual drift are ignored.

Historical official Terraform 1.15.9 evidence completed consumers, imports,
updates, reopen and cleanup, but refresh-only plans returned 2 despite semantic
no-ops. The runner records those failures, continues independent proofs, and
still exits nonzero after cleanup. Ordinary plan changes and real drift abort.
The optional [Core correction](../README.md#terraform-core-refresh-only-correction-opt-in)
is a separately built locally patched 1.16.6 consumer, not an official release;
its successful API-controls evidence does not verify this group. Keep binary
checksums and official/patched results distinct.
