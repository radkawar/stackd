# CloudFormation: create, update, delete with data-plane assertions

Complete [shared preparation](../README.md) first. Neither Terraform nor Docker
is required. This template uses existing `AWS::S3::Bucket`, `AWS::SQS::Queue`
and `AWS::SSM::Parameter` resource owners, not custom-resource stand-ins.

```sh
"$EXAMPLE_PYTHON" examples/cloudformation/run.py --port 14662
```

The runner owns a fresh controller/database and unique stack/resource names.
Every CloudFormation, STS, S3, SQS and SSM SDK client uses that controller's
explicit loopback endpoint and signs requests with fixture credentials. It:

1. Submits `template.json` with `CreateStack`, `Name=<unique name>`, and
   `Revision=v1`, then polls `DescribeStacks` for `CREATE_COMPLETE`. Any terminal
   failure/rollback is an error, not a successful readiness response.
2. Consumes `DescribeStacks.Outputs`: `Bucket`, `QueueUrl`, `ParameterName`.
   Reads SSM `v1`; puts binary object bytes; sends a manifest through SQS;
   receives and checks the actual message identity/body; retrieves and compares
   object bytes and SHA-256; deletes the message and object.
3. Calls `UpdateStack` with `UsePreviousTemplate`, retains `Name`, changes
   `Revision` to `v2`, and waits for `UPDATE_COMPLETE`. Outputs must remain
   identical, proving the update did not replace these resource identities.
   It repeats the signed data-plane assertions with `v2` and new payload bytes.
4. Submits an identical update and requires the modeled `ValidationError`
   containing `No updates`, not a pretend successful update.
5. Calls `DeleteStack`, polls the unique stack ID for `DELETE_COMPLETE`, then
   requires the bucket, queue and parameter to be absent through their owning
   service APIs. Objects are explicitly removed before stack deletion.

The template is also ordinary JSON for SDK/CLI deployment; the safe runner is
the complete runnable example because it owns endpoints, credentials, unique
names, polling, assertions and teardown. It retains `template.json`,
`stack-id.txt`, `outputs.json`, SQLite state and the controller log in the
printed run directory. See [cleanup](../README.md#cleanup-and-evidence).

CloudFormation does not become a general AWS parity claim because this stack
works. This example exercises these three resource types, basic parameter/
`Fn::Sub`/`Ref` evaluation, outputs, an in-place SSM update and lifecycle cleanup.
It does not claim change-set, nested-stack, rollback, service-role authorization
or resource-replacement coverage.

Primary contracts: [CreateStack](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html),
[UpdateStack](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_UpdateStack.html),
[DeleteStack](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DeleteStack.html),
[template outputs](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/outputs-section-structure.html).
