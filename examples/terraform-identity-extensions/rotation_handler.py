"""Run all four rotation steps inside the installed official Lambda Python RIC.

The password consumer is an owned local application, not an AWS authentication
emulator. setSecret changes its actual retained password; testSecret authenticates.
"""
import hashlib
import json
import os
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import boto3
from botocore.exceptions import ClientError

HTTP = build_opener(ProxyHandler({}))


def application(path, payload):
    request = Request(os.environ["FIXTURE_APPLICATION"] + path,
                      data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
    with HTTP.open(request, timeout=10) as response:
        return json.load(response)


def invoke(event, context):
    secret_id = event.get("SecretId", os.environ["FIXTURE_SECRET"])
    if secret_id != os.environ["FIXTURE_SECRET"]:
        raise ValueError("Callback selected a different secret")
    secrets = boto3.client("secretsmanager")
    identity = boto3.client("sts").get_caller_identity()
    expected = f"arn:aws:sts::{identity['Account']}:assumed-role/{os.environ['FIXTURE_ROLE']}/"
    if not identity["Arn"].startswith(expected):
        raise ValueError("Callback did not receive the current Lambda execution role")
    if event.get("Probe"):
        current = secrets.get_secret_value(SecretId=secret_id)
        authenticated = application("/authenticate", json.loads(current["SecretString"]))
        return {"version": current["VersionId"], "authenticated": authenticated["authenticated"],
                "execution_arn": identity["Arn"]}
    token, step = event["ClientRequestToken"], event["Step"]
    description = secrets.describe_secret(SecretId=secret_id)
    stages = description.get("VersionIdsToStages", {})
    if token not in stages or not {"AWSPENDING", "AWSCURRENT"}.intersection(stages[token]):
        raise ValueError("Callback token does not own a retained rotation version")

    def value(version=None, stage="AWSCURRENT"):
        arguments = {"SecretId": secret_id, "VersionStage": stage}
        if version is not None:
            arguments["VersionId"] = version
        return json.loads(secrets.get_secret_value(**arguments)["SecretString"])

    if step == "createSecret":
        try:
            pending = value(token, "AWSPENDING")
        except ClientError as error:
            if error.response["Error"]["Code"] not in {"ResourceNotFoundException", "DecryptionFailure", "InvalidRequestException"}:
                raise
            current = value()
            pending = {
                "username": current["username"],
                "password": hashlib.sha256((secret_id + token).encode()).hexdigest() + "aA!7",
                "revision": os.environ["FIXTURE_REVISION"], "token": token,
                "execution_arn": identity["Arn"],
            }
            secrets.put_secret_value(SecretId=secret_id, ClientRequestToken=token,
                                     SecretString=json.dumps(pending, sort_keys=True),
                                     VersionStages=["AWSPENDING"], RotationToken=event["RotationToken"])
        if pending.get("token") != token:
            raise ValueError("A different credential already occupies the pending token")
    elif step == "setSecret":
        pending = value(token, "AWSPENDING")
        try:
            application("/authenticate", pending)
        except HTTPError as error:
            if error.code != 401:
                raise
            current = value()
            application("/change-password", {
                "username": current["username"], "password": current["password"],
                "new_password": pending["password"],
            })
    elif step == "testSecret":
        pending = value(token, "AWSPENDING")
        if not application("/authenticate", pending)["authenticated"]:
            raise ValueError("The real application rejected its pending password")
    elif step == "finishSecret":
        if "AWSCURRENT" not in stages[token]:
            previous = next((identifier for identifier, labels in stages.items() if "AWSCURRENT" in labels), None)
            arguments = {"SecretId": secret_id, "VersionStage": "AWSCURRENT", "MoveToVersionId": token}
            if previous is not None:
                arguments["RemoveFromVersionId"] = previous
            secrets.update_secret_version_stage(**arguments)
    else:
        raise ValueError("Unknown rotation callback step")
    print(json.dumps({"rotation_step": step, "token": token, "execution_arn": identity["Arn"]}), flush=True)
    return {"step": step, "token": token, "executed": True}
