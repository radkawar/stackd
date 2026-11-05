# Terraform authentication and captured email

## Purpose

Manage Cognito user/identity pools and SES resources, then independently consume
password authentication, RS256 JWT/JWKS verification, refresh tokens, issued IAM
role credentials and real locally captured classic/v2 SES MIME. Exercise real
verification/recovery links and codes from the captured messages, not invented
challenge data. `inventory.json` describes bounded provider-type scope.

## Prerequisites

Complete the shared [Python environment and build setup](../../README.md#prepare-once)
and export `EXAMPLE_PYTHON`. Install Terraform **>= 1.15.9, < 2.0.0** on `PATH`;
AWS provider **6.68.0** is pinned. Prepare registry access or a provider mirror.
This mode needs no Docker, OpenSSL executable, external SMTP or AWS credentials.
Install the extra Python package from the repository root:

```sh
"$EXAMPLE_PYTHON" -m pip install cryptography==50.0.1
```

## Run

From the repository root:

```sh
"$EXAMPLE_PYTHON" examples/terraform-application-controls/auth/run.py --port 14783
```

`--port` selects an unused unprivileged loopback port;
`--stackd /absolute/path/to/stackd` selects a prepared binary;
`--work-parent /existing/directory` changes the new unique workspace's parent.
`--provider-mirror /absolute/path/to/mirror` selects the pinned provider from an
existing filesystem mirror with no direct fallback; omit it for registry access.
No existing endpoint or shared state is adopted.

## Expected results

The runner applies, consumes actual SES verification mail, performs Cognito
password recovery, verifies signed and forged JWT cases, uses Identity-issued
role credentials for authorized mail and checks denied operations. It imports
every managed resource, reconciles write-only passwords, updates, requires
strict no-op plans, gracefully reopens the same SQLite database and repeats
recovery/authentication/mail consumers. Successful teardown ends with
`Auth lifecycle complete`.

The printed mode-0700 directory retains `stackd.sqlite`, full `stackd.log`,
`stackd.before-reopen.log`, Terraform state/plans and `before-import.tfstate`,
`imports.json`, `outputs.json`, and incremental `evidence.json`. Actual MIME is
under `mail/`. Terraform command output goes to the terminal. Inspect status,
errors, completed consumer stages and cleanup separately. All passwords, codes,
tokens, mail bodies and state are sensitive; do not commit or publish them.

## Cleanup

The runner attempts ordinary Terraform destroy on lifecycle failure as well as
success, verifies signed absence and empty state, and stops its controller.
Before each import it saves a state backup and restores ownership if import
fails, allowing normal cleanup to find the resource. Mail capture is retained,
not delivered to an external mailbox. After owned processes stop and evidence
is no longer needed, remove only the exact printed directory.

## Limitations

This is not complete Cognito/SES parity, an SMTP integration or a simulated MFA
workflow. Write-only passwords cannot be reconstructed by native import and
are reapplied from private fixture configuration.

Strict refresh-only or ordinary plan exit 2 remains a terminal failure, even
when independent reopened consumers and cleanup finish. The shared
[Core correction](../../README.md#terraform-core-refresh-only-correction-opt-in)
is an optional locally patched Terraform 1.16.6 consumer, not an official
release. Its successful API-controls evidence does not verify auth; preserve
source/patch/binary checksums and distinguish official from patched runs.
