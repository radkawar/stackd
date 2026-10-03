#!/usr/bin/env python3
"""Reviewed zero-target native SSM Resource Groups admission capture."""
import argparse
import json
from pathlib import Path
import secrets
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--account", required=True)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
name = 'stackd-ssm-rg-' + secrets.token_hex(6)
path = args.output or Path('.stackd/probes/ssm/' + name + '.json')
path.parent.mkdir(parents=True, exist_ok=True)
data = {'owner': name, 'observations': [], 'cleanup': {}}
session = boto3.Session(region_name='us-east-1')
clients = {s: session.client(s, config=Config(retries={'max_attempts': 0}, connect_timeout=5, read_timeout=20)) for s in ('sts', 'iam', 'ssm', 'resource-groups')}
owned = set()
def call(service, operation, client=None, **args):
    row = {'service': service, 'operation': operation, 'input': args}
    data['observations'].append(row)
    try:
        result = getattr(client or clients[service], operation)(**args)
        result.pop('ResponseMetadata', None)
        row['output'] = result
        return result
    except ClientError as error:
        row['error'] = error.response['Error']
        return None
    finally:
        path.write_text(json.dumps(data, indent=2, default=str) + '\n')
def target(key, *values):
    return {'Key': key, 'Values': list(values)}
def send(label, targets, client=None):
    data['case'] = label
    result = call('ssm', 'send_command', client=client, DocumentName='AWS-RunShellScript', Targets=targets, Parameters={'commands': ['printf calibration']}, TimeoutSeconds=30, Comment=label)
    if result:
        assert result['Command']['TargetCount'] == 0, result
    return result
try:
    identity = call('sts', 'get_caller_identity')
    if identity['Account'] != args.account:
        raise RuntimeError('Unexpected native account')
    query = {'Type': 'TAG_FILTERS_1_0', 'Query': json.dumps({'ResourceTypeFilters': ['AWS::AllSupported'], 'TagFilters': [{'Key': 'stackd-member', 'Values': [name]}]})}
    assert call('resource-groups', 'create_group', Name=name, ResourceQuery=query, Tags={'stackd-owner': name})
    owned.add('group')
    members = call('resource-groups', 'list_group_resources', Group=name)
    assert members is not None and not members.get('ResourceIdentifiers') and not members.get('Resources')
    group = target('resource-groups:Name', name)
    cases = [
        ('name', [group]),
        ('ec2', [group, target('resource-groups:ResourceTypeFilters', 'AWS::EC2::Instance')]),
        ('ssm', [group, target('resource-groups:ResourceTypeFilters', 'AWS::SSM::ManagedInstance')]),
        ('all', [group, target('resource-groups:ResourceTypeFilters', 'AWS::AllSupported')]),
        ('s3', [group, target('resource-groups:ResourceTypeFilters', 'AWS::S3::Bucket')]),
        ('ec2-ssm', [group, target('resource-groups:ResourceTypeFilters', 'AWS::EC2::Instance', 'AWS::SSM::ManagedInstance')]),
        ('missing', [target('resource-groups:Name', name + '-absent')]),
        ('tag-mix', [group, target('tag:stackd-owner', name)]),
        ('id-mix', [group, target('InstanceIds', 'i-00000000000000000')]),
        ('two-names', [target('resource-groups:Name', name, name + '-absent')]),
        ('duplicate-name', [group, group]),
        ('filter-alone', [target('resource-groups:ResourceTypeFilters', 'AWS::EC2::Instance')]),
    ]
    # A type-only target has no owned group safety boundary; capture validation
    # only for mixed owned-group requests instead of risking broad selection.
    cases.pop()
    for label, targets in cases:
        send(label, targets)
    trust = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': identity['Arn']}, 'Action': 'sts:AssumeRole'}]})
    role = call('iam', 'create_role', RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{'Key': 'stackd-owner', 'Value': name}])
    assert role
    owned.add('role')
    policy = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['ssm:SendCommand', 'resource-groups:*', 'tag:GetResources'], 'Resource': '*'}]})
    assert call('iam', 'put_role_policy', RoleName=name, PolicyName='probe', PolicyDocument=policy) is not None
    time.sleep(15)
    for denied in ('none', 'resource-groups:GetGroup', 'resource-groups:GetGroupQuery', 'resource-groups:ListGroupResources', 'tag:GetResources'):
        statements = [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]
        if denied != 'none':
            statements.append({'Effect': 'Deny', 'Action': denied, 'Resource': '*'})
        # Never retain STS credential material in capture.
        assumed = clients['sts'].assume_role(RoleArn=role['Role']['Arn'], RoleSessionName='probe', Policy=json.dumps({'Version': '2012-10-17', 'Statement': statements}))['Credentials']
        client = session.client('ssm', aws_access_key_id=assumed['AccessKeyId'], aws_secret_access_key=assumed['SecretAccessKey'], aws_session_token=assumed['SessionToken'], config=Config(retries={'max_attempts': 0}, connect_timeout=5, read_timeout=20))
        send('deny-' + denied, [group], client)
    deadline = time.monotonic() + 90
    for row in data['observations']:
        if row['operation'] != 'send_command' or 'output' not in row:
            continue
        while True:
            result = clients['ssm'].list_commands(CommandId=row['output']['Command']['CommandId'])
            result.pop('ResponseMetadata', None)
            row['completion'] = result
            path.write_text(json.dumps(data, indent=2, default=str) + '\n')
            if result['Commands'] and result['Commands'][0]['Status'] in ('Success', 'Failed', 'Cancelled', 'TimedOut'):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('native command did not reach a terminal outcome within bound')
            time.sleep(2)
finally:
    if 'role' in owned:
        call('iam', 'delete_role_policy', RoleName=name, PolicyName='probe')
        call('iam', 'delete_role', RoleName=name)
        assert call('iam', 'get_role', RoleName=name) is None
        data['cleanup']['role'] = data['observations'][-1].get('error', {}).get('Code') == 'NoSuchEntity'
    if 'group' in owned:
        call('resource-groups', 'delete_group', Group=name)
        assert call('resource-groups', 'get_group', Group=name) is None
        data['cleanup']['group'] = data['observations'][-1].get('error', {}).get('Code') == 'NotFoundException'
    path.write_text(json.dumps(data, indent=2, default=str) + '\n')
    print(path)
    assert all(data['cleanup'].values())
