# Terraform application controls

## Purpose

Choose an independently runnable application workflow:

- [Authentication and email](auth/README.md): Cognito password/JWT/Identity
  credentials and actual locally captured SES MIME, including recovery mail.
- [Jobs and pipelines](jobs/README.md): Step Functions activity execution and
  S3 pipeline bytes; opt in to actual CodeBuild container processes.

Each child owns its own runner, configuration and `inventory.json`. There is no
combined root runner; inventory presence is not proof of complete AWS support.

## Prerequisites

Complete the shared [Python environment and build setup](../README.md#prepare-once)
and export `EXAMPLE_PYTHON`. Both children pin AWS provider **6.68.0**. Read the
selected child guide for Terraform constraints, auth's extra cryptography
package, and optional jobs Docker/image prerequisites. Default jobs and auth
modes need no Docker or native AWS credentials.

## Run

From the repository root, run either workflow after its prerequisites:

```sh
"$EXAMPLE_PYTHON" examples/terraform-application-controls/auth/run.py --port 14783
"$EXAMPLE_PYTHON" examples/terraform-application-controls/jobs/run.py --port 14731
```

The child guides document provider mirrors, binary/workspace selection, modes
and ports. Each invocation starts a fresh private owned controller/database,
not an existing service or the repository's working database.

## Expected results

Each child requires real consumers, native imports, revision updates, SQLite
controller reopen, strict no-op plans and ordinary destroy/absence checks.
Only a successful process exit and its complete evidence establish a passing
run; completed cleanup alone is not success. Logs, state and `evidence.json`
remain in each printed private workspace.

## Cleanup

Both runners attempt cleanup of their owned resources and stop their own
controllers. Jobs first waits for admitted work to reach terminal states;
auth preserves private mail capture for inspection. Remove only the exact
printed workspace after its owned processes stop and evidence is no longer
needed. Do not publish state, passwords, tokens, MIME or credentials.

## Limitations

These workflows do not establish full Cognito/SES/CodeBuild/CodePipeline/Step
Functions parity. Non-Docker jobs does not execute CodeBuild, and auth does not
use external SMTP. Strict Terraform plan failures remain failures; child guides
explain the distinction between official Terraform and the optional locally
patched Core consumer.
