#!/usr/bin/env python3
"""Reviewed exact-owned CodeBuild folder admission probe with an empty bucket."""
import argparse
import json
from pathlib import Path
import secrets
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--account', required=True)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
name = 'stackd-cb-folder-admit-' + secrets.token_hex(6)
path = args.output or Path('.stackd/probes/codebuild/' + name + '.json')
path.parent.mkdir(parents=True, exist_ok=True)
data = {'owner': name, 'observations': [], 'cleanup': []}
session = boto3.Session(region_name='us-east-1')
clients = {s: session.client(s, config=Config(retries={'max_attempts': 0}, connect_timeout=5, read_timeout=15)) for s in ('sts', 'iam', 'codebuild', 's3')}
owned = set()
def call(service, operation, **args):
    row = {'service': service, 'operation': operation, 'input': args}
    data['observations'].append(row)
    try:
        result = getattr(clients[service], operation)(**args)
        result.pop('ResponseMetadata', None)
        row['output'] = result
        return result
    except ClientError as error:
        row['error'] = error.response['Error']
        return None
    finally:
        path.write_text(json.dumps(data, indent=2, default=str) + '\n')
try:
    identity = call('sts', 'get_caller_identity')
    if identity['Account'] != args.account:
        raise RuntimeError('unexpected AWS account')
    trust = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Principal': {'Service': 'codebuild.amazonaws.com'}}]})
    role = call('iam', 'create_role', RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{'Key': 'stackd-owner', 'Value': name}])
    assert role
    owned.add('role')
    assert call('s3', 'create_bucket', Bucket=name) is not None
    owned.add('bucket')
    call('s3', 'put_bucket_tagging', Bucket=name, Tagging={'TagSet': [{'Key': 'stackd-owner', 'Value': name}]})
    time.sleep(12)
    primary = {'type': 'S3', 'location': name + '/primary/'}
    secondary = [{'type': 'S3', 'location': name + '/aux/', 'sourceIdentifier': 'Aux'}]
    project = call('codebuild', 'create_project', name=name, serviceRole=role['Role']['Arn'], source=primary, secondarySources=secondary, artifacts={'type': 'NO_ARTIFACTS'}, environment={'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0', 'computeType': 'BUILD_GENERAL1_SMALL'}, timeoutInMinutes=5, queuedTimeoutInMinutes=5, logsConfig={'cloudWatchLogs': {'status': 'DISABLED'}}, tags=[{'key': 'stackd-owner', 'value': name}])
    assert project
    owned.add('project')
    call('codebuild', 'update_project', name=name, sourceVersion='nonexistent')
    call('codebuild', 'update_project', name=name, sourceVersion='', secondarySourceVersions=[{'sourceIdentifier': 'Aux', 'sourceVersion': 'nonexistent'}])
    call('codebuild', 'update_project', name=name, source={'type': 'S3', 'location': name + '/'}, secondarySourceVersions=[])
    call('codebuild', 'update_project', name=name, source=primary, sourceVersion='', secondarySourceVersions=[])
    started = call('codebuild', 'start_build', projectName=name, secondarySourcesVersionOverride=[{'sourceIdentifier': 'Aux', 'sourceVersion': 'nonexistent'}])
    if started:
        identifier = started['build']['id']
        call('codebuild', 'stop_build', id=identifier)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = call('codebuild', 'batch_get_builds', ids=[identifier])
            if result['builds'][0].get('buildComplete'):
                break
            time.sleep(3)
        else:
            raise RuntimeError('owned build did not stop within bound')
finally:
    if 'project' in owned:
        call('codebuild', 'delete_project', name=name)
    if 'bucket' in owned:
        call('s3', 'delete_bucket', Bucket=name)
    if 'role' in owned:
        call('iam', 'delete_role', RoleName=name)
    call('codebuild', 'batch_get_projects', names=[name])
    call('iam', 'get_role', RoleName=name)
    call('s3', 'head_bucket', Bucket=name)
    print(path)
