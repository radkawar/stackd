#!/usr/bin/env python3
"""Exercise local Signer -> S3 -> Lambda ZIP/layer admission and real SQS effects.

Use prepare then verify after restarting the same retained stackd database.
Cleanup uses only the exact resource identities recorded in the state file.
"""
import argparse
import base64
from datetime import datetime, timedelta
import io
import json
from pathlib import Path
import time
import uuid
import urllib.request
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

HANDLER = '''import json, os
import boto3

def handler(event, context):
    body = {'signed_runtime': True, 'nonce': event['nonce']}
    if event.get('layer'):
        import proof_layer
        body['layer'] = proof_layer.value()
    boto3.client('sqs', endpoint_url=os.environ['PROOF_ENDPOINT']).send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(body))
    return body
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--proof-endpoint", required=True)
    parser.add_argument("--access-key", required=True)
    parser.add_argument("--secret-key", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--phase", choices=("prepare", "verify", "cleanup"), required=True)
    parser.add_argument("--advance-expiry", action="store_true", help="Advance an isolated manual-clock instance by 25h")
    args = parser.parse_args()
    session = boto3.Session(aws_access_key_id=args.access_key, aws_secret_access_key=args.secret_key, region_name="us-east-1")
    cfg = Config(retries={"max_attempts": 0}, s3={"addressing_style": "path"})
    clients = {name: session.client(name, endpoint_url=args.endpoint, config=cfg) for name in ("sts", "iam", "s3", "sqs", "lambda", "signer", "cloudwatch", "cloudtrail")}
    sts, iam, s3, sqs, lam, signer = (clients[name] for name in ("sts", "iam", "s3", "sqs", "lambda", "signer"))
    account = sts.get_caller_identity()["Account"]
    path = Path(args.state)
    state = json.loads(path.read_text()) if path.exists() else {"name": "stackd-next-code-signing-"+uuid.uuid4().hex[:12], "layers": [], "configs": [], "evidence": []}
    name = state["name"]

    def save():
        path.write_text(json.dumps(state, indent=2)+"\n")

    def observed(label, **data):
        state["evidence"].append({"case": label, **data})
        save()

    def rejected(label, code, call, **kwargs):
        try:
            call(**kwargs)
        except ClientError as error:
            actual = error.response["Error"]["Code"]
            if actual != code: raise AssertionError((label, actual, code)) from error
            observed(label, error=actual)
            return
        raise AssertionError(label+" unexpectedly accepted")

    def settle():
        lam.get_waiter("function_updated_v2").wait(FunctionName=name, WaiterConfig={"Delay": 1, "MaxAttempts": 120})

    def sign(code, retain=True):
        version = s3.put_object(Bucket=name, Key="unsigned.zip", Body=code)["VersionId"]
        job = signer.start_signing_job(source={"s3":{"bucketName":name,"key":"unsigned.zip","version":version}}, destination={"s3":{"bucketName":name,"prefix":"signed/"}}, profileName=state["profile"], clientRequestToken=uuid.uuid4().hex)["jobId"]
        if retain:
            state["job"] = job; save()
        deadline = time.monotonic()+120
        while True:
            status = signer.describe_signing_job(jobId=job)
            if status["status"] != "InProgress": break
            if time.monotonic() >= deadline: raise RuntimeError("Signer job deadline")
            time.sleep(0.1)
        assert status["status"] == "Succeeded", status
        location = status["signedObject"]["s3"]
        if retain:
            state["signedBucket"], state["signedKey"] = location["bucketName"], location["key"]; save()
        return s3.get_object(Bucket=location["bucketName"], Key=location["key"])["Body"].read()

    def invoke(label, layer=False):
        nonce = uuid.uuid4().hex
        reply = lam.invoke(FunctionName=name, Payload=json.dumps({"nonce": nonce, "layer": layer}).encode())
        body = json.loads(reply["Payload"].read())
        expected = {"signed_runtime": True, "nonce": nonce}
        if layer:
            expected["layer"] = "trusted-layer"
        assert "FunctionError" not in reply and body == expected, reply
        messages = sqs.receive_message(QueueUrl=state["queue"], WaitTimeSeconds=5, MaxNumberOfMessages=10).get("Messages", [])
        assert any(json.loads(message["Body"]) == body for message in messages), messages
        for message in messages:
            sqs.delete_message(QueueUrl=state["queue"], ReceiptHandle=message["ReceiptHandle"])
        observed(label, runtime=body, external_effect="SQS message received and deleted")

    def cleanup():
        if state.get("function"):
            lam.delete_function(FunctionName=name)
            state.pop("function"); save()
        for version in list(state["layers"]):
            lam.delete_layer_version(LayerName=name, VersionNumber=version)
            state["layers"].remove(version); save()
        for arn in list(state["configs"]):
            lam.delete_code_signing_config(CodeSigningConfigArn=arn)
            state["configs"].remove(arn); save()
        if state.get("profile"):
            signer.cancel_signing_profile(profileName=state["profile"])
            state.pop("profile"); save()
        if state.get("bucket"):
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=state["bucket"]):
                versions = [{"Key": obj["Key"], "VersionId": obj["VersionId"]} for field in ("Versions", "DeleteMarkers") for obj in page.get(field, [])]
                if versions:
                    result = s3.delete_objects(Bucket=state["bucket"], Delete={"Objects": versions})
                    assert not result.get("Errors"), result
            s3.delete_bucket(Bucket=state["bucket"])
            state.pop("bucket"); save()
        if state.get("queue"):
            sqs.delete_queue(QueueUrl=state["queue"])
            state.pop("queue"); save()
        if state.get("role"):
            iam.delete_role_policy(RoleName=name, PolicyName="proof")
            iam.delete_role(RoleName=name)
            state.pop("role"); save()
        observed("cleanup", retained="cancelled Signer profile/job history only")

    if args.phase == "cleanup":
        cleanup()
        print(json.dumps(state["evidence"]))
        return
    if args.phase == "verify":
        config = lam.get_code_signing_config(CodeSigningConfigArn=state["config"])["CodeSigningConfig"]
        assert config["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"] == "Enforce"
        assert lam.get_function_code_signing_config(FunctionName=name)["CodeSigningConfigArn"] == state["config"]
        assert lam.list_tags(Resource=state["config"])["Tags"]["owner"] == name
        unsigned = base64.b64decode(state["unsigned"])
        signed = s3.get_object(Bucket=state["signedBucket"], Key=state["signedKey"])["Body"].read()
        rejected("reopened-unsigned-enforce", "CodeVerificationFailedException", lam.update_function_code, FunctionName=name, ZipFile=unsigned)
        invoke("reopened-signed-layer-runtime", layer=True)
        lam.update_function_configuration(FunctionName=name, Layers=[]); settle()
        signer.revoke_signature(jobId=state["job"], reason="owned runtime revocation proof")
        rejected("revoked-enforce", "CodeVerificationFailedException", lam.update_function_code, FunctionName=name, ZipFile=signed)
        lam.update_code_signing_config(CodeSigningConfigArn=state["config"], CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Warn"})
        lam.update_function_code(FunctionName=name, ZipFile=signed); settle()
        invoke("revoked-warn-runtime")
        if args.advance_expiry:
            fresh = sign(unsigned)
            lam.update_code_signing_config(CodeSigningConfigArn=state["config"], CodeSigningPolicies={"UntrustedArtifactOnDeployment":"Enforce"})
            lam.update_function_code(FunctionName=name, ZipFile=fresh); settle()
            request = urllib.request.Request(args.endpoint+"/_stackd/clock", data=b'{"advance":"25h"}', headers={"Content-Type":"application/json"})
            with urllib.request.urlopen(request) as response:
                assert response.status == 200
            rejected("expired-enforce", "CodeVerificationFailedException", lam.update_function_code, FunctionName=name, ZipFile=fresh)
            lam.update_code_signing_config(CodeSigningConfigArn=state["config"], CodeSigningPolicies={"UntrustedArtifactOnDeployment":"Warn"})
            lam.update_function_code(FunctionName=name, ZipFile=fresh); settle()
            invoke("expired-warn-runtime")
            # Flush retained samples and close the final five-minute query bucket.
            request = urllib.request.Request(args.endpoint+"/_stackd/clock", data=b'{"advance":"6m"}', headers={"Content-Type":"application/json"})
            with urllib.request.urlopen(request) as response:
                now = datetime.fromisoformat(json.load(response)["time"].replace("Z","+00:00"))
            request = urllib.request.Request(args.endpoint+"/_stackd/jobs/drain?limit=256", data=b"")
            with urllib.request.urlopen(request) as response:
                assert response.status == 200
            metric = clients["cloudwatch"].get_metric_statistics(Namespace="AWS/Lambda", MetricName="SignatureValidationErrors", Dimensions=[{"Name":"FunctionName","Value":name}], StartTime=now-timedelta(days=2), EndTime=now, Period=300, Statistics=["Sum"])
            total = sum(point["Sum"] for point in metric["Datapoints"])
            assert total == 11, metric
            observed("validation-metrics", signature_validation_errors=total)
        events = clients["cloudtrail"].lookup_events(LookupAttributes=[{"AttributeKey":"ResourceName","AttributeValue":name}], MaxResults=50)["Events"]
        statuses = {json.loads(event["CloudTrailEvent"]).get("additionalEventData",{}).get("signatureStatus") for event in events}
        assert {"VALID","MISMATCH","REVOKED"}.issubset(statuses), statuses
        if args.advance_expiry:
            assert "EXPIRED" in statuses, statuses
        observed("signature-audit", statuses=sorted(status for status in statuses if status))
        lam.delete_function_code_signing_config(FunctionName=name)
        assert not lam.get_function_code_signing_config(FunctionName=name).get("CodeSigningConfigArn")
        observed("detach", retained_code="still executable")
        cleanup()
        print(json.dumps(state["evidence"]))
        return

    save()
    try:
        s3.create_bucket(Bucket=name)
        state["bucket"] = name; save()
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
        queue = sqs.create_queue(QueueName=name)["QueueUrl"]
        state["queue"] = queue; save()
        role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps({"Version":"2012-10-17", "Statement":[{"Effect":"Allow", "Principal":{"Service":"lambda.amazonaws.com"}, "Action":"sts:AssumeRole"}]}))["Role"]["Arn"]
        state["role"] = role; save()
        iam.put_role_policy(RoleName=name, PolicyName="proof", PolicyDocument=json.dumps({"Version":"2012-10-17", "Statement":[{"Effect":"Allow", "Action":"sqs:SendMessage", "Resource":f"arn:aws:sqs:us-east-1:{account}:{name}"}]}))
        profile = name.replace("-", "_")
        profile_arn = signer.put_signing_profile(profileName=profile, platformId="AWSLambda-SHA384-ECDSA", signatureValidityPeriod={"value":1,"type":"DAYS"})["profileVersionArn"]
        state["profile"] = profile; state["publisher"] = profile_arn; save()
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z: z.writestr("handler.py", HANDLER)
        unsigned = archive.getvalue(); state["unsigned"] = base64.b64encode(unsigned).decode(); save()
        signed = sign(unsigned)
        config = lam.create_code_signing_config(AllowedPublishers={"SigningProfileVersionArns":[profile_arn]}, CodeSigningPolicies={"UntrustedArtifactOnDeployment":"Enforce"}, Tags={"owner":name})["CodeSigningConfig"]["CodeSigningConfigArn"]
        state["configs"].append(config); state["config"] = config; save()
        other = lam.create_code_signing_config(AllowedPublishers={"SigningProfileVersionArns":[profile_arn]})["CodeSigningConfig"]["CodeSigningConfigArn"]
        state["configs"].append(other); save()
        listed = []
        for page in lam.get_paginator("list_code_signing_configs").paginate(PaginationConfig={"PageSize":1}): listed.extend(c["CodeSigningConfigArn"] for c in page["CodeSigningConfigs"])
        assert config in listed and other in listed
        rejected("invalid-marker", "InvalidParameterValueException", lam.list_code_signing_configs, Marker="invalid")
        lam.tag_resource(Resource=config, Tags={"temporary":"remove"})
        lam.untag_resource(Resource=config, TagKeys=["temporary"])
        assert lam.list_tags(Resource=config)["Tags"] == {"owner":name}
        lam.create_function(FunctionName=name, Runtime="python3.12", Handler="handler.handler", Role=role, Code={"ZipFile":signed}, CodeSigningConfigArn=config, Timeout=15, Environment={"Variables":{"PROOF_ENDPOINT":args.proof_endpoint,"QUEUE_URL":queue}})
        state["function"] = True; save()
        lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay":1,"MaxAttempts":120})
        invoke("signed-enforce-runtime")
        rejected("config-in-use", "ResourceConflictException", lam.delete_code_signing_config, CodeSigningConfigArn=config)
        rejected("unsigned-enforce", "CodeVerificationFailedException", lam.update_function_code, FunctionName=name, ZipFile=unsigned)
        changed = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(signed)) as source, zipfile.ZipFile(changed,"w") as target:
            for entry in source.infolist():
                data = source.read(entry)
                if entry.filename == "handler.py": data += b"# tampered\n"
                target.writestr(entry, data)
        rejected("tampered-enforce", "CodeVerificationFailedException", lam.update_function_code, FunctionName=name, ZipFile=changed.getvalue())
        layer_source = io.BytesIO()
        with zipfile.ZipFile(layer_source, "w") as package:
            package.writestr("python/proof_layer.py", "def value(): return 'trusted-layer'\n")
        signed_layer = sign(layer_source.getvalue(), retain=False)
        layer = lam.publish_layer_version(LayerName=name, Content={"ZipFile":signed_layer})
        state["layers"].append(layer["Version"]); save()
        assert layer["Content"]["SigningProfileVersionArn"] == profile_arn
        lam.update_function_configuration(FunctionName=name, Layers=[layer["LayerVersionArn"]]); settle()
        invoke("signed-layer-runtime", layer=True)
        bad_layer = lam.publish_layer_version(LayerName=name, Content={"ZipFile":unsigned})
        state["layers"].append(bad_layer["Version"]); save()
        rejected("unsigned-layer-enforce", "CodeVerificationFailedException", lam.update_function_configuration, FunctionName=name, Layers=[bad_layer["LayerVersionArn"]])
        mismatch = profile_arn.rsplit("/",1)[0]+"/0000000000"
        lam.update_code_signing_config(CodeSigningConfigArn=config, AllowedPublishers={"SigningProfileVersionArns":[mismatch]})
        rejected("publisher-mismatch-enforce", "CodeVerificationFailedException", lam.update_function_code, FunctionName=name, ZipFile=signed)
        lam.update_code_signing_config(CodeSigningConfigArn=config, AllowedPublishers={"SigningProfileVersionArns":[profile_arn]})
        lam.update_code_signing_config(CodeSigningConfigArn=config, CodeSigningPolicies={"UntrustedArtifactOnDeployment":"Warn"})
        rejected("tampered-warn", "CodeVerificationFailedException", lam.update_function_code, FunctionName=name, ZipFile=changed.getvalue())
        lam.update_function_code(FunctionName=name, ZipFile=unsigned); settle()
        invoke("unsigned-warn-runtime")
        lam.update_function_code(FunctionName=name, ZipFile=signed); settle()
        lam.update_code_signing_config(CodeSigningConfigArn=config, CodeSigningPolicies={"UntrustedArtifactOnDeployment":"Enforce"})
        observed("prepared-for-restart", config=config, publisher=profile_arn)
        print(json.dumps(state["evidence"]))
    except BaseException:
        save()
        raise


if __name__ == "__main__": main()
