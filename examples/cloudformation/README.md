# CloudFormation application

## Purpose

Create an S3 bucket, SQS queue and SSM parameter from a CloudFormation template,
use them from an application, update the parameter and delete the stack.

## Prerequisites

Complete [shared preparation](../README.md#prepare-once). Neither Terraform nor
Docker is required.

## Run

From the repository root:

```sh
"$EXAMPLE_PYTHON" examples/cloudformation/run.py --port 14662
```

Use `--stackd PATH` to select an installed server or `--work-parent PATH` to
select the parent of the new run directory. The runner starts a server with a
new SQLite database and generates unique stack and resource names.

## Expected results

1. `CreateStack` reaches `CREATE_COMPLETE` and returns the application outputs.
2. SDK requests read SSM value `v1`, upload binary bytes to S3, send a manifest
   through SQS and compare the received message and object with the originals.
3. `UpdateStack` changes the SSM value to `v2` without replacing the resources.
   The application checks run again with new object and message contents.
4. An identical update returns `ValidationError` with `No updates`.
5. `DeleteStack` reaches `DELETE_COMPLETE`, and SDK requests confirm that the
   bucket, queue and parameter are absent.

A failed or rolled-back stack, unexpected output or data mismatch fails the run.

## Cleanup

The runner removes objects before deleting the stack and attempts stack deletion
if an application check fails. It stops the server and retains `template.json`,
`stack-id.txt`, `outputs.json`, the SQLite database and `stackd.log` in the printed
run directory. Follow [shared cleanup](../README.md#cleanup-and-evidence) to
remove that directory after inspection.

## Limitations

This example covers three resource types, parameters, `Fn::Sub`, `Ref`, outputs
and an in-place update. It does not exercise change sets, nested stacks,
rollback, service roles or resource replacement.

AWS references: [CreateStack](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html),
[UpdateStack](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_UpdateStack.html),
[DeleteStack](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DeleteStack.html)
and [template outputs](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html).
