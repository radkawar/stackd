#!/usr/bin/env python3
"""Bounded exact-owned native CodeBuild folder calibration; review required before use."""
import argparse
import datetime
import json
from pathlib import Path
import secrets
import time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    name = 'stackd-cb-folder-' + secrets.token_hex(6)
    capture = {'owner': name, 'account': args.account, 'region': 'us-east-1', 'observations': [], 'cleanup': []}
    path = args.output or Path('.stackd/probes/codebuild/' + name + '.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    config = Config(retries={'max_attempts': 0}, connect_timeout=5, read_timeout=20)
    session = boto3.Session(region_name='us-east-1')
    clients = {s: session.client(s, config=config) for s in ('sts', 'iam', 's3', 'codebuild')}
    owned, builds = set(), []
    deadline = time.monotonic() + 720
    def save():
        path.write_text(json.dumps(capture, indent=2, default=str) + '\n')
    def call(service, operation, **kwargs):
        record = {'service': service, 'operation': operation, 'input': kwargs}
        capture['observations'].append(record)
        try:
            out = getattr(clients[service], operation)(**kwargs)
            out.pop('ResponseMetadata', None)
            record['output'] = out
            return out
        except ClientError as error:
            record['error'] = error.response['Error']
            raise
        finally:
            save()
    def build(label, **overrides):
        capture['case'] = label
        try:
            out = call('codebuild', 'start_build', projectName=name, **overrides)['build']
        except ClientError:
            return
        builds.append(out['id'])
        while not out.get('buildComplete') and time.monotonic() < deadline:
            time.sleep(5)
            out = call('codebuild', 'batch_get_builds', ids=[out['id']])['builds'][0]
        capture.setdefault('cases', []).append({'case': label, 'build': out})
        save()
        if not out.get('buildComplete'):
            raise RuntimeError('native calibration deadline reached')
    try:
        identity = call('sts', 'get_caller_identity')
        if identity['Account'] != capture['account']:
            raise RuntimeError('unexpected AWS account')
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'codebuild.amazonaws.com'}, 'Action': 'sts:AssumeRole', 'Condition': {'StringEquals': {'aws:SourceAccount': capture['account']}}}]}
        role = call('iam', 'create_role', RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{'Key': 'stackd-owner', 'Value': name}])['Role']['Arn']
        owned.add('role')
        call('s3', 'create_bucket', Bucket=name)
        owned.add('bucket')
        call('s3', 'put_bucket_tagging', Bucket=name, Tagging={'TagSet': [{'Key': 'stackd-owner', 'Value': name}]})
        call('s3', 'put_bucket_versioning', Bucket=name, VersioningConfiguration={'Status': 'Enabled'})
        policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['s3:GetObject', 's3:GetObjectVersion', 's3:GetBucketLocation', 's3:ListBucket'], 'Resource': ['arn:aws:s3:::' + name, 'arn:aws:s3:::' + name + '/*']}]}
        call('iam', 'put_role_policy', RoleName=name, PolicyName='owned-source', PolicyDocument=json.dumps(policy))
        owned.add('policy')
        spec = json.dumps({'version': '0.2', 'phases': {'build': {'commands': ['test "$(cat nested/a.txt)" = primary', 'test "$(cat "$CODEBUILD_SRC_DIR_Aux/deep/b.txt")" = secondary']}}})
        call('s3', 'put_object', Bucket=name, Key='primary/buildspec.yml', Body=spec)
        version = call('s3', 'put_object', Bucket=name, Key='primary/nested/a.txt', Body='primary')['VersionId']
        call('s3', 'put_object', Bucket=name, Key='aux/deep/b.txt', Body='secondary')
        call('s3', 'put_object', Bucket=name, Key='empty/', Body='')
        time.sleep(12)
        call('codebuild', 'create_project', name=name, serviceRole=role, source={'type': 'S3', 'location': name + '/primary/'}, secondarySources=[{'type': 'S3', 'location': name + '/aux/', 'sourceIdentifier': 'Aux'}], artifacts={'type': 'NO_ARTIFACTS'}, environment={'type': 'LINUX_CONTAINER', 'computeType': 'BUILD_GENERAL1_SMALL', 'image': 'aws/codebuild/standard:7.0'}, timeoutInMinutes=5, queuedTimeoutInMinutes=5, logsConfig={'cloudWatchLogs': {'status': 'DISABLED'}, 's3Logs': {'status': 'DISABLED'}}, tags=[{'key': 'stackd-owner', 'value': name}])
        owned.add('project')
        build('folders')
        build('folder-version', sourceVersion=version, secondarySourcesVersionOverride=[{'sourceIdentifier': 'Aux', 'sourceVersion': 'nonexistent'}])
        build('missing-prefix', sourceLocationOverride=name + '/missing/', buildspecOverride='version: 0.2\nphases:\n  build:\n    commands: ["true"]\n')
        build('empty-prefix', sourceLocationOverride=name + '/empty/', buildspecOverride='version: 0.2\nphases:\n  build:\n    commands: ["true"]\n')
        for label, action, resource in [('deny-list', 's3:ListBucket', 'arn:aws:s3:::' + name), ('deny-read', 's3:GetObject', 'arn:aws:s3:::' + name + '/aux/*')]:
            changed = dict(policy, Statement=policy['Statement'] + [{'Effect': 'Deny', 'Action': action, 'Resource': resource}])
            call('iam', 'put_role_policy', RoleName=name, PolicyName='owned-source', PolicyDocument=json.dumps(changed))
            time.sleep(5)
            build(label)
    finally:
        for identifier in builds:
            try:
                out = call('codebuild', 'batch_get_builds', ids=[identifier])['builds'][0]
                if not out.get('buildComplete'):
                    call('codebuild', 'stop_build', id=identifier)
            except Exception as error:
                capture['cleanup'].append({'stop': identifier, 'error': str(error)})
        actions = []
        if 'project' in owned:
            actions.append(('codebuild', 'delete_project', {'name': name}))
        if 'bucket' in owned:
            for page in clients['s3'].get_paginator('list_object_versions').paginate(Bucket=name):
                for row in page.get('Versions', []) + page.get('DeleteMarkers', []):
                    call('s3', 'delete_object', Bucket=name, Key=row['Key'], VersionId=row['VersionId'])
            actions.append(('s3', 'delete_bucket', {'Bucket': name}))
        if 'policy' in owned:
            actions.append(('iam', 'delete_role_policy', {'RoleName': name, 'PolicyName': 'owned-source'}))
        if 'role' in owned:
            actions.append(('iam', 'delete_role', {'RoleName': name}))
        for service, operation, args in actions:
            try:
                call(service, operation, **args)
                capture['cleanup'].append({'operation': operation, 'success': True})
            except Exception as error:
                capture['cleanup'].append({'operation': operation, 'error': str(error)})
        for service, operation, args in [('iam', 'get_role', {'RoleName': name}), ('s3', 'head_bucket', {'Bucket': name}), ('codebuild', 'batch_get_projects', {'names': [name]})]:
            try:
                out = call(service, operation, **args)
                capture['cleanup'].append({'independent_check': operation, 'output': out})
            except ClientError as error:
                capture['cleanup'].append({'independent_check': operation, 'error': error.response['Error']})
        capture['completed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        print(path)

if __name__ == '__main__':
    main()
