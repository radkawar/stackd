#!/usr/bin/env python3
"""Exact-owned, no-build native CodeBuild S3 source admission calibration."""
import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import time
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True, help='Native AWS account ID that must match the STS caller')
    parser.add_argument('--update-boundary', action='store_true', help='Probe retained-source revalidation after deleting the owned source bucket.')
    args = parser.parse_args()
    account = args.account
    os.umask(0o077)
    name = 'stackd-cb-source-' + uuid.uuid4().hex[:16]
    missing = name + '-absent'
    output = Path('.stackd/probes/codebuild/' + name + '.json')
    output.parent.mkdir(parents=True, exist_ok=True)
    data = {'owner': name, 'captured_at': datetime.now(timezone.utc).isoformat(),
            'scope': 'Native CreateProject/UpdateProject admission only; no builds or object reads.',
            'sources': ['https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ProjectSource.html',
                        'https://docs.aws.amazon.com/codebuild/latest/APIReference/API_CreateProject.html'],
            'observations': [], 'cleanup': {}}
    session = boto3.Session(region_name='us-east-1')
    config = Config(ignore_configured_endpoint_urls=True, retries={'total_max_attempts': 1},
                    connect_timeout=5, read_timeout=15)
    clients = {service: session.client(service, config=config) for service in ('sts', 'iam', 's3', 'codebuild')}
    started = time.monotonic()
    owned = set()
    cleaning = False

    def save():
        output.write_text(json.dumps(data, indent=2, default=str) + '\n')

    def call(label, service, operation, **request):
        if not cleaning and (len(data['observations']) >= 55 or time.monotonic() - started > 300):
            raise RuntimeError('native probe bound reached')
        if len(data['observations']) >= 70:
            raise RuntimeError('native cleanup call bound reached')
        row = {'case': label, 'service': service, 'operation': operation, 'input': request}
        data['observations'].append(row)
        try:
            value = getattr(clients[service], operation)(**request)
            value.pop('ResponseMetadata', None)
            row['output'] = {key: result for key, result in value.items() if key != 'Credentials'}
            return value
        except ClientError as error:
            row['error'] = error.response['Error']
            return None
        finally:
            save()

    def required(label, service, operation, **request):
        value = call(label, service, operation, **request)
        if value is None:
            raise RuntimeError('prerequisite failed: ' + label)
        return value

    no_source = {'type': 'NO_SOURCE', 'buildspec': 'version: 0.2\nphases:\n  build:\n    commands: [true]\n'}
    try:
        identity = required('identity', 'sts', 'get_caller_identity')
        if identity['Account'] != account:
            raise RuntimeError('unexpected native account')
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'codebuild.amazonaws.com', 'AWS': identity['Arn']}, 'Action': 'sts:AssumeRole'}]}
        role = required('create-role', 'iam', 'create_role', RoleName=name,
                        AssumeRolePolicyDocument=json.dumps(trust), Tags=[{'Key': 'stackd-owner', 'Value': name}])
        owned.add('role')
        required('create-bucket', 's3', 'create_bucket', Bucket=name)
        owned.add('bucket')
        required('tag-bucket', 's3', 'put_bucket_tagging', Bucket=name,
                 Tagging={'TagSet': [{'Key': 'stackd-owner', 'Value': name}]})
        # IAM propagation is only a setup delay, not evidence that any authority applied.
        time.sleep(12)
        request = dict(name=name, serviceRole=role['Role']['Arn'], source=no_source,
                       artifacts={'type': 'NO_ARTIFACTS'},
                       environment={'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0', 'computeType': 'BUILD_GENERAL1_SMALL'},
                       timeoutInMinutes=5, queuedTimeoutInMinutes=5,
                       logsConfig={'cloudWatchLogs': {'status': 'DISABLED'}},
                       tags=[{'key': 'stackd-owner', 'value': name}])
        if args.update_boundary:
            source = {'type': 'S3', 'location': name + '/source/'}
            required('create-existing-source', 'codebuild', 'create_project', **dict(request, source=source))
            owned.add('project')
            required('remove-source-bucket', 's3', 'delete_bucket', Bucket=name)
            owned.remove('bucket')
            call('update-omitted-source-after-deletion', 'codebuild', 'update_project', name=name, description='source omitted')
            call('update-explicit-source-after-deletion', 'codebuild', 'update_project', name=name, source=source)
            data['complete'] = True
            return
        # Failed creation cannot be hidden by an already admitted project.
        for label, location in [('missing-zip', missing + '/source.zip'), ('missing-folder', missing + '/source/'), ('existing-folder', name + '/source/')]:
            result = call('create-' + label, 'codebuild', 'create_project', **dict(request, source={'type': 'S3', 'location': location}))
            if result is not None:
                owned.add('project')
                required('delete-probe-project', 'codebuild', 'delete_project', name=name)
                owned.remove('project')
        required('create-control-project', 'codebuild', 'create_project', **request)
        owned.add('project')
        for mode in ('no-s3-grant', 's3-grant', 'explicit-s3-deny'):
            if mode != 'no-s3-grant':
                policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow' if mode == 's3-grant' else 'Deny', 'Action': ['s3:ListBucket', 's3:GetBucketLocation', 's3:GetObject'], 'Resource': ['arn:aws:s3:::' + name, 'arn:aws:s3:::' + name + '/*', 'arn:aws:s3:::' + missing, 'arn:aws:s3:::' + missing + '/*']}]}
                required('role-' + mode, 'iam', 'put_role_policy', RoleName=name, PolicyName='source', PolicyDocument=json.dumps(policy))
                owned.add('policy')
                time.sleep(10)
            for label, location in [('existing-zip', name + '/source.zip'), ('existing-folder', name + '/source/'), ('existing-root', name + '/'), ('missing-zip', missing + '/source.zip'), ('missing-folder', missing + '/source/')]:
                call(mode + '-primary-' + label, 'codebuild', 'update_project', name=name,
                     source={'type': 'S3', 'location': location}, secondarySources=[])
            for label, location in [('existing-folder', name + '/secondary/'), ('missing-folder', missing + '/secondary/')]:
                call(mode + '-secondary-' + label, 'codebuild', 'update_project', name=name,
                     source=no_source, secondarySources=[{'type': 'S3', 'location': location, 'sourceIdentifier': 'Aux'}])
        policy['Statement'].extend([
            {'Effect': 'Allow', 'Action': ['codebuild:UpdateProject', 'codebuild:BatchGetProjects'], 'Resource': 'arn:aws:codebuild:us-east-1:' + account + ':project/' + name},
            {'Effect': 'Allow', 'Action': 'iam:PassRole', 'Resource': role['Role']['Arn']}])
        required('caller-policy', 'iam', 'put_role_policy', RoleName=name, PolicyName='source', PolicyDocument=json.dumps(policy))
        time.sleep(10)
        assumed = required('assume-caller', 'sts', 'assume_role', RoleArn=role['Role']['Arn'], RoleSessionName='source-admission')
        credentials = assumed['Credentials']
        for service in ('s3', 'codebuild'):
            clients['restricted-' + service] = session.client(service, config=config,
                aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'])
        call('caller-s3-denial-control', 'restricted-s3', 'head_bucket', Bucket=name)
        if data['observations'][-1].get('error', {}).get('Code') != '403':
            raise RuntimeError('caller S3 denial was not observed')
        for label, location in [('existing', name + '/source/'), ('missing', missing + '/source/')]:
            call('caller-s3-denied-' + label, 'restricted-codebuild', 'update_project', name=name,
                 source={'type': 'S3', 'location': location}, secondarySources=[])
        data['complete'] = True
    finally:
        cleaning = True
        if 'project' in owned:
            call('cleanup-project', 'codebuild', 'delete_project', name=name)
        if 'bucket' in owned:
            call('cleanup-bucket', 's3', 'delete_bucket', Bucket=name)
        if 'policy' in owned:
            call('cleanup-policy', 'iam', 'delete_role_policy', RoleName=name, PolicyName='source')
        if 'role' in owned:
            call('cleanup-role', 'iam', 'delete_role', RoleName=name)
        projects = call('verify-project-absent', 'codebuild', 'batch_get_projects', names=[name])
        data['cleanup']['project_absent'] = projects is not None and projects.get('projects') == [] and name in projects.get('projectsNotFound', [])
        call('verify-bucket-absent', 's3', 'head_bucket', Bucket=name)
        data['cleanup']['bucket_absent'] = data['observations'][-1].get('error', {}).get('Code') in ('404', 'NoSuchBucket')
        call('verify-role-absent', 'iam', 'get_role', RoleName=name)
        data['cleanup']['role_absent'] = data['observations'][-1].get('error', {}).get('Code') == 'NoSuchEntity'
        save()
        print(output)
        if not all(data['cleanup'].values()):
            raise RuntimeError('native owned cleanup incomplete; inspect retained exact identifiers')


if __name__ == '__main__':
    main()
