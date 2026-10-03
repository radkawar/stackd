#!/usr/bin/env python3
"""Reviewed exact-owned, one-build Git secondary admission and runtime capture."""
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
name = 'stackd-cb-git-secondary-' + secrets.token_hex(6)
path = args.output or Path('.stackd/probes/codebuild/' + name + '.json')
path.parent.mkdir(parents=True, exist_ok=True)
data = {'owner': name, 'observations': [], 'cleanup_verified': False}
clients = {s: boto3.client(s, region_name='us-east-1', config=Config(retries={'max_attempts': 0}, connect_timeout=5, read_timeout=15)) for s in ('sts', 'iam', 'codebuild', 'logs')}
owned = set()
build_id = None

def call(service, operation, **args):
    row = {'service': service, 'operation': operation, 'input': args}
    data['observations'].append(row)
    try:
        result = getattr(clients[service], operation)(**args)
        metadata = result.pop('ResponseMetadata', {})
        row['request_id'] = metadata.get('RequestId')
        row['output'] = result
        return result
    except ClientError as error:
        row['error'] = error.response['Error']
        row['request_id'] = error.response.get('ResponseMetadata', {}).get('RequestId')
        return None
    finally:
        path.write_text(json.dumps(data, indent=2, default=str) + '\n')

try:
    if call('sts', 'get_caller_identity')['Account'] != args.account:
        raise RuntimeError('unexpected AWS account')
    trust = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole', 'Principal': {'Service': 'codebuild.amazonaws.com'}}]})
    role = call('iam', 'create_role', RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{'Key': 'stackd-owner', 'Value': name}])
    assert role
    owned.add('role')
    assert call('logs', 'create_log_group', logGroupName=name, tags={'stackd-owner': name}) is not None
    owned.add('logs')
    policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': 'arn:aws:logs:us-east-1:' + args.account + ':log-group:' + name + ':*'}]}
    assert call('iam', 'put_role_policy', RoleName=name, PolicyName='owned', PolicyDocument=json.dumps(policy)) is not None
    time.sleep(12)
    spec = json.dumps({'version': '0.2', 'phases': {'build': {'commands': ['printf "MASTER_VERSION=%s TEST_VERSION=%s\\n" "$CODEBUILD_SOURCE_VERSION_Master" "$CODEBUILD_SOURCE_VERSION_Test"', 'printf "MASTER_README="; base64 -w0 "$CODEBUILD_SRC_DIR_Master"/README*; echo', 'printf "TEST_README="; base64 -w0 "$CODEBUILD_SRC_DIR_Test"/README*; echo', 'git -C "$CODEBUILD_SRC_DIR_Master" rev-parse HEAD', 'git -C "$CODEBUILD_SRC_DIR_Test" rev-parse HEAD']}}})
    primary = {'type': 'NO_SOURCE', 'buildspec': spec}
    repo = 'https://github.com/octocat/Hello-World.git'
    sources = [{'type': 'GITHUB', 'location': location, 'sourceIdentifier': identifier, 'gitCloneDepth': 1} for identifier, location in [('Master', repo), ('Test', 'https://github.com/octocat/Spoon-Knife.git')]]
    versions = [{'sourceIdentifier': 'Master', 'sourceVersion': 'refs/heads/master'}, {'sourceIdentifier': 'Test', 'sourceVersion': 'refs/heads/master'}]
    assert call('codebuild', 'create_project', name=name, serviceRole=role['Role']['Arn'], source=primary, secondarySources=sources, secondarySourceVersions=versions, artifacts={'type': 'NO_ARTIFACTS'}, environment={'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0', 'computeType': 'BUILD_GENERAL1_SMALL'}, timeoutInMinutes=5, queuedTimeoutInMinutes=5, logsConfig={'cloudWatchLogs': {'status': 'ENABLED', 'groupName': name, 'streamName': 'owned'}}, tags=[{'key': 'stackd-owner', 'value': name}])
    owned.add('project')
    for provider, url in [('GITHUB', repo + '/'), ('GITHUB_ENTERPRISE', 'https://enterprise.example.invalid/owner/repo.git/'), ('BITBUCKET', 'https://bitbucket.org/owner/repo.git/'), ('GITLAB', 'https://gitlab.com/owner/repo.git/'), ('GITLAB_SELF_MANAGED', 'https://gitlab.example.invalid/owner/repo.git/')]:
        call('codebuild', 'update_project', name=name, secondarySources=[{'type': provider, 'location': url, 'sourceIdentifier': 'Master', 'gitCloneDepth': 2, 'gitSubmodulesConfig': {'fetchSubmodules': True}}], secondarySourceVersions=[versions[0]])
    assert call('codebuild', 'update_project', name=name, secondarySources=sources, secondarySourceVersions=versions)
    started = call('codebuild', 'start_build', projectName=name, secondarySourcesVersionOverride=[{'sourceIdentifier': 'Test', 'sourceVersion': 'refs/heads/change-the-title'}])
    assert started
    build_id = started['build']['id']
    deadline = time.monotonic() + 420
    while time.monotonic() < deadline:
        result = call('codebuild', 'batch_get_builds', ids=[build_id])
        if result and result['builds'][0].get('buildComplete'):
            data['native_terminal_status'] = result['builds'][0]['buildStatus']
            break
        time.sleep(5)
    logs = call('logs', 'filter_log_events', logGroupName=name)
    data['runtime_output_observed'] = bool(logs and any('MASTER_README=' in event['message'] for event in logs.get('events', [])))
finally:
    if build_id:
        status = call('codebuild', 'batch_get_builds', ids=[build_id])
        if status and not status['builds'][0].get('buildComplete'):
            call('codebuild', 'stop_build', id=build_id)
            for _ in range(30):
                status = call('codebuild', 'batch_get_builds', ids=[build_id])
                if status and status['builds'][0].get('buildComplete'):
                    break
                time.sleep(3)
            assert status and status['builds'][0].get('buildComplete'), 'owned build did not stop'
    if 'project' in owned:
        call('codebuild', 'delete_project', name=name)
    if 'logs' in owned:
        call('logs', 'delete_log_group', logGroupName=name)
    if 'role' in owned:
        call('iam', 'delete_role_policy', RoleName=name, PolicyName='owned')
        call('iam', 'delete_role', RoleName=name)
    projects = call('codebuild', 'batch_get_projects', names=[name])
    role = call('iam', 'get_role', RoleName=name)
    role_absent = role is None and data['observations'][-1].get('error', {}).get('Code') == 'NoSuchEntity'
    groups = call('logs', 'describe_log_groups', logGroupNamePrefix=name)
    data['cleanup_verified'] = bool(projects is not None and not projects.get('projects') and role_absent and groups is not None and not any(g['logGroupName'] == name for g in groups['logGroups']))
    path.write_text(json.dumps(data, indent=2, default=str) + '\n')
    print(path)
    assert data['cleanup_verified'], 'native cleanup incomplete'
