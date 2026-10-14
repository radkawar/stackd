"""Create, verify, update, verify again, and delete a local CloudFormation stack."""

import json
from pathlib import Path
import sys
import time
import uuid

from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (arguments, client, controller, require, verify_application,
                   verify_deleted, workspace)


def wait_stack(cfn, stack_id, status):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        current = stack["StackStatus"]
        if current == status:
            return stack
        require(current.endswith("_IN_PROGRESS"),
                f"Stack reached {current}, expected {status}: {json.dumps(stack, default=str)}")
        time.sleep(0.5)
    raise RuntimeError(f"Stack {stack_id} did not reach {status}")


def outputs_of(stack):
    values = {item["OutputKey"]: item["OutputValue"] for item in stack["Outputs"]}
    return {"bucket": values["Bucket"], "queue_url": values["QueueUrl"],
            "parameter_name": values["ParameterName"]}


def main():
    args = arguments(__doc__, 14662).parse_args()
    root = workspace(args, "cloudformation")
    template = (Path(__file__).resolve().parent / "template.json").read_text()
    (root / "template.json").write_text(template)
    name = "stackd-cfn-" + uuid.uuid4().hex[:12]
    with controller(args, root) as endpoint:
        cfn = client("cloudformation", endpoint)
        stack_id = None
        outputs = None
        try:
            response = cfn.create_stack(StackName=name, TemplateBody=template, Parameters=[
                {"ParameterKey": "Name", "ParameterValue": name},
                {"ParameterKey": "Revision", "ParameterValue": "v1"}])
            stack_id = response["StackId"]
            (root / "stack-id.txt").write_text(stack_id + "\n")
            created = wait_stack(cfn, stack_id, "CREATE_COMPLETE")
            outputs = outputs_of(created)
            (root / "outputs.json").write_text(json.dumps(outputs, indent=2) + "\n")
            verify_application(endpoint, outputs, "v1")
            cfn.update_stack(StackName=stack_id, UsePreviousTemplate=True, Parameters=[
                {"ParameterKey": "Name", "UsePreviousValue": True},
                {"ParameterKey": "Revision", "ParameterValue": "v2"}])
            updated = wait_stack(cfn, stack_id, "UPDATE_COMPLETE")
            require(outputs_of(updated) == outputs, "In-place update changed resource identities")
            verify_application(endpoint, outputs_of(updated), "v2")
            try:
                cfn.update_stack(StackName=stack_id, UsePreviousTemplate=True, Parameters=[
                    {"ParameterKey": "Name", "UsePreviousValue": True},
                    {"ParameterKey": "Revision", "UsePreviousValue": True}])
            except ClientError as error:
                require(error.response["Error"]["Code"] == "ValidationError"
                        and "No updates" in error.response["Error"]["Message"], str(error))
                print("Verified identical CloudFormation update reports no updates", flush=True)
            else:
                raise RuntimeError("CloudFormation accepted an identical update instead of reporting no updates")
        finally:
            if stack_id is not None:
                cfn.delete_stack(StackName=stack_id)
                # Deleted stacks remain addressable by unique stack ID.
                wait_stack(cfn, stack_id, "DELETE_COMPLETE")
        if outputs is not None:
            verify_deleted(endpoint, outputs)
    print(f"CloudFormation lifecycle complete; controller stopped. Retained only owned artifacts: {root}")


if __name__ == "__main__":
    main()
