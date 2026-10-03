#!/usr/bin/env python3
"""Local executable S3 source admission and retained-update proof; no builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from aws.stackd_process import StackdProcess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, default=Path('bin/stackd'))
    parser.add_argument('--output', type=Path, default=Path('testdata/integration/codebuild_source_admission.json'))
    args = parser.parse_args()
    state = Path(tempfile.mkdtemp(prefix='stackd-source-admission-'))
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    endpoint = f'http://127.0.0.1:{port}'
    command = [str(args.binary.resolve()), '-listen', f'127.0.0.1:{port}', '-public-endpoint', endpoint,
               '-database', str(state / 'state.sqlite')]
    environment = {key: value for key, value in os.environ.items() if not key.startswith('AWS_')}
    environment['AWS_EC2_METADATA_DISABLED'] = 'true'
    process = StackdProcess(state)
    config = Config(ignore_configured_endpoint_urls=True, retries={'total_max_attempts': 1}, connect_timeout=5, read_timeout=20)
    clients = {name: boto3.client(name, endpoint_url=endpoint, region_name='us-east-1',
               aws_access_key_id='test', aws_secret_access_key='test', config=config) for name in ('iam', 's3', 'codebuild')}
    report = {'scope': 'Local executable only; project admission, role S3 deny, SQLite restart and atomic updates; no builds.',
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(), 'observations': [], 'controllers': process.runs}
    owned = set()
    name = 'source-admission'

    def call(label, service, operation, expected='Success', **request):
        row = {'case': label, 'operation': operation, 'expected': expected}
        report['observations'].append(row)
        try:
            out = getattr(clients[service], operation)(**request)
            out.pop('ResponseMetadata', None)
            row.update(code='Success', output=out)
        except ClientError as error:
            out = None
            row.update(code=error.response['Error']['Code'], error=error.response['Error'])
        row['matches'] = row['code'] == expected
        return out

    try:
        process.start(command, endpoint, environment=environment)
        role = call('create-role', 'iam', 'create_role', RoleName=name, AssumeRolePolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'codebuild.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}))
        if role is None:
            raise RuntimeError('role creation failed')
        owned.add('role')
        call('deny-role-s3', 'iam', 'put_role_policy', RoleName=name, PolicyName='deny', PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny', 'Action': 's3:*', 'Resource': '*'}]}))
        owned.add('policy')
        no_source = {'type': 'NO_SOURCE', 'buildspec': 'version: 0.2\nphases:\n  build:\n    commands: [true]\n'}
        base = dict(name=name, serviceRole=role['Role']['Arn'], artifacts={'type': 'NO_ARTIFACTS'},
                    environment={'type': 'LINUX_CONTAINER', 'computeType': 'BUILD_GENERAL1_SMALL', 'image': 'busybox:1.38.0'})
        for suffix in ('missing.zip', 'empty/'):
            out = call('create-missing-' + suffix, 'codebuild', 'create_project', expected='InvalidInputException', **base, source={'type': 'S3', 'location': 'absent-source/' + suffix})
            if out is not None:
                owned.add('project')
                call('remove-unexpected-project', 'codebuild', 'delete_project', name=name)
                owned.remove('project')
        out = call('create-missing-secondary', 'codebuild', 'create_project', expected='InvalidInputException', **base, source=no_source,
                   secondarySources=[{'type': 'S3', 'location': 'absent-source/aux/', 'sourceIdentifier': 'Aux'}])
        if out is not None:
            owned.add('project')
            call('remove-unexpected-secondary-project', 'codebuild', 'delete_project', name=name)
            owned.remove('project')
        if call('create-source-bucket', 's3', 'create_bucket', Bucket=name) is None:
            raise RuntimeError('bucket creation failed')
        owned.add('bucket')
        if call('create-empty-source', 'codebuild', 'create_project', **base, source={'type': 'S3', 'location': name + '/empty/'}) is None:
            raise RuntimeError('existing source admission failed')
        owned.add('project')
        call('update-missing-secondary', 'codebuild', 'update_project', expected='InvalidInputException', name=name, source=no_source,
             secondarySources=[{'type': 'S3', 'location': 'absent-source/aux/', 'sourceIdentifier': 'Aux'}])
        call('update-existing-secondary', 'codebuild', 'update_project', name=name, source=no_source,
             secondarySources=[{'type': 'S3', 'location': name + '/aux/', 'sourceIdentifier': 'Aux'}])
        process.stop()
        process.start(command, endpoint, environment=environment)
        restored = call('restored-source', 'codebuild', 'batch_get_projects', names=[name])
        report['restored_source'] = restored is not None and restored['projects'][0]['secondarySources'][0]['location'] == name + '/aux/'
        call('delete-source-bucket', 's3', 'delete_bucket', Bucket=name)
        owned.remove('bucket')
        call('update-omitted-deleted-source', 'codebuild', 'update_project', expected='InvalidInputException', name=name, description='must not commit')
        current = call('read-rejected-update', 'codebuild', 'batch_get_projects', names=[name])
        report['atomic_update'] = current is not None and current['projects'][0].get('description') != 'must not commit'
    finally:
        try:
            if process.process is not None:
                if 'project' in owned:
                    call('cleanup-project', 'codebuild', 'delete_project', name=name)
                if 'bucket' in owned:
                    call('cleanup-bucket', 's3', 'delete_bucket', Bucket=name)
                if 'policy' in owned:
                    call('cleanup-role-policy', 'iam', 'delete_role_policy', RoleName=name, PolicyName='deny')
                if 'role' in owned:
                    call('cleanup-role', 'iam', 'delete_role', RoleName=name)
                missing = call('verify-project-absent', 'codebuild', 'batch_get_projects', names=[name])
                report['project_absent'] = missing is not None and missing.get('projects', []) == [] and name in missing.get('projectsNotFound', [])
                call('verify-role-absent', 'iam', 'get_role', expected='NoSuchEntity', RoleName=name)
                call('verify-bucket-absent', 's3', 'head_bucket', expected='404', Bucket=name)
        finally:
            try:
                process.stop()
            finally:
                report['status'] = 'passed' if all(row['matches'] for row in report['observations']) and all(report.get(key) for key in ('restored_source', 'atomic_update', 'project_absent')) and all(run.get('exit') == 0 for run in process.runs) else 'failed'
                args.output.write_text(json.dumps(report, indent=2, default=str) + '\n')
                print(args.output, report['status'])
    if report['status'] != 'passed':
        raise RuntimeError('source admission smoke failed; see retained observations')


if __name__ == '__main__':
    main()
