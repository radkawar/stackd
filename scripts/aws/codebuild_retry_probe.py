#!/usr/bin/env python3
"""Exact-owned RetryBuild calibration with bounded short builds and source/IAM cases."""
import argparse
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import time
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True, help='Native AWS account ID that must match the STS caller')
    parser.add_argument('--source-versions', action='store_true')
    args = parser.parse_args()
    account = args.account
    os.umask(0o077)
    name = 'stackd-cb-retry-' + uuid.uuid4().hex[:12]
    path = Path('.stackd/probes/codebuild/' + name + '.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {'owner': name, 'captured_at': datetime.now(timezone.utc).isoformat(),
            'sources': ['https://docs.aws.amazon.com/codebuild/latest/APIReference/API_RetryBuild.html'],
            'bounds': {'builds': 3 if args.source_versions else 8, 'wall_seconds': 1800, 'api_calls': 300, 'cost_ceiling_usd': 1},
            'observations': [], 'cleanup': {}, 'builds': []}
    config = Config(ignore_configured_endpoint_urls=True, retries={'total_max_attempts': 1},
                    connect_timeout=5, read_timeout=20)
    session = boto3.Session(region_name='us-east-1')
    clients = {s: session.client(s, config=config) for s in ('sts', 'iam', 'codebuild', 'logs', 's3')}
    owned = set()
    cleaning = False
    started = time.monotonic()

    def save():
        path.write_text(json.dumps(data, indent=2, default=str) + '\n')

    def call(label, service, operation, **request):
        if not cleaning and (time.monotonic() - started >= 1800 or len(data['observations']) >= 240):
            raise RuntimeError('native calibration bound reached')
        if len(data['observations']) >= 300:
            raise RuntimeError('native cleanup call bound reached')
        if operation in ('start_build', 'retry_build') and len(data['builds']) >= data['bounds']['builds']:
            raise RuntimeError('native build bound reached')
        row = {'case': label, 'service': service, 'operation': operation, 'input': request}
        data['observations'].append(row)
        try:
            out = getattr(clients[service], operation)(**request)
            row['request_id'] = out.pop('ResponseMetadata', {}).get('RequestId')
            row['output'] = {key: value for key, value in out.items() if key != 'Credentials'}
            if operation in ('start_build', 'retry_build'):
                build = out['build']['id']
                if build not in data['builds']:
                    data['builds'].append(build)
            return out
        except ClientError as error:
            row['error'] = error.response['Error']
            row['request_id'] = error.response.get('ResponseMetadata', {}).get('RequestId')
            return None
        finally:
            save()
            print(label + ': ' + row.get('error', {}).get('Code', 'Success'), flush=True)

    def required(label, service, operation, **request):
        out = call(label, service, operation, **request)
        if out is None:
            raise RuntimeError('prerequisite failed: ' + label)
        return out

    def settle(label):
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            out = required(label, 'codebuild', 'batch_get_builds', ids=data['builds'])
            if all(b.get('buildComplete') for b in out['builds']):
                return out
            time.sleep(10)
        raise RuntimeError('owned builds did not settle within bound')

    def spec(marker, failed=False):
        commands = ['printf "RETRY_PROOF=%s VALUE=%s EXTRA=%s ID=%s\\n" ' + marker + ' "$VALUE" "$EXTRA" "$CODEBUILD_BUILD_ID"']
        if failed:
            commands.append('exit 9')
        return json.dumps({'version': '0.2', 'phases': {'build': {'commands': commands}}})

    def calibrate_versions(role_arn, environment):
        required('source-bucket', 's3', 'create_bucket', Bucket=name)
        owned.add('bucket')
        required('source-versioning', 's3', 'put_bucket_versioning', Bucket=name, VersioningConfiguration={'Status': 'Enabled'})
        required('source-tags', 's3', 'put_bucket_tagging', Bucket=name, Tagging={'TagSet': [{'Key': 'stackd-owner', 'Value': name}]})
        policy['Statement'].extend([
            {'Effect': 'Allow', 'Action': ['s3:GetObject', 's3:GetObjectVersion', 's3:GetBucketLocation', 's3:ListBucket'], 'Resource': ['arn:aws:s3:::' + name, 'arn:aws:s3:::' + name + '/*']},
            {'Effect': 'Allow', 'Action': 'codebuild:RetryBuild', 'Resource': 'arn:aws:codebuild:us-east-1:' + account + ':project/' + name},
            {'Effect': 'Deny', 'Action': 'codebuild:StartBuild', 'Resource': '*'}])
        required('source-retry-authority', 'iam', 'put_role_policy', RoleName=name, PolicyName='owned', PolicyDocument=json.dumps(policy))
        for revision in ('old', 'new'):
            for source in ('primary', 'secondary'):
                archive = io.BytesIO()
                with zipfile.ZipFile(archive, 'w') as zipped:
                    zipped.writestr('value.txt', source + '-' + revision + '\n')
                required('source-' + source + '-' + revision, 's3', 'put_object', Bucket=name, Key=source + '.zip', Body=archive.getvalue())
            if revision == 'old':
                commands = ['printf PRIMARY=; cat value.txt', 'printf SECONDARY=; cat "$CODEBUILD_SRC_DIR_Secondary/value.txt"', 'printf "REVISION=%s SECONDARY_REVISION=%s\\n" "$CODEBUILD_RESOLVED_SOURCE_VERSION" "$CODEBUILD_SOURCE_VERSION_Secondary"']
                buildspec = json.dumps({'version': '0.2', 'phases': {'build': {'commands': commands}}})
                required('source-project', 'codebuild', 'update_project', name=name,
                         source={'type': 'S3', 'location': name + '/primary.zip', 'buildspec': buildspec},
                         secondarySources=[{'type': 'S3', 'location': name + '/secondary.zip', 'sourceIdentifier': 'Secondary'}])
                first = required('source-original', 'codebuild', 'start_build', projectName=name)['build']
                settle('source-original-terminal')
        environment['environmentVariables'] = [{'name': 'EXTRA', 'value': 'new-only', 'type': 'PLAINTEXT'}]
        required('source-project-mutation', 'codebuild', 'update_project', name=name, environment=environment,
                 source={'type': 'NO_SOURCE', 'buildspec': spec('changed-project')}, secondarySources=[])
        required('source-retry', 'codebuild', 'retry_build', id=first['id'], idempotencyToken='source-retry')
        credentials = required('retry-actor', 'sts', 'assume_role', RoleArn=role_arn, RoleSessionName='retry-only', DurationSeconds=900)['Credentials']
        clients['retryactor'] = session.client('codebuild', config=config, aws_access_key_id=credentials['AccessKeyId'],
                                              aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'])
        call('denied-start-control', 'retryactor', 'start_build', projectName=name)
        required('retry-only-authority', 'retryactor', 'retry_build', id=first['id'], idempotencyToken='restricted-retry')
        settle('source-retry-terminal')

    try:
        identity = required('identity', 'sts', 'get_caller_identity')
        if identity['Account'] != account:
            raise RuntimeError('unexpected native account')
        data['identity'] = identity
        trust = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'codebuild.amazonaws.com', 'AWS': identity['Arn']}, 'Action': 'sts:AssumeRole'}]}
        role = required('role', 'iam', 'create_role', RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{'Key': 'stackd-owner', 'Value': name}])
        owned.add('role')
        required('logs', 'logs', 'create_log_group', logGroupName=name, tags={'stackd-owner': name})
        owned.add('logs')
        policy = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': 'arn:aws:logs:us-east-1:' + account + ':log-group:' + name + ':*'}]}
        required('log-authority', 'iam', 'put_role_policy', RoleName=name, PolicyName='owned', PolicyDocument=json.dumps(policy))
        time.sleep(12)
        environment = {'type': 'LINUX_CONTAINER', 'image': 'aws/codebuild/standard:7.0', 'computeType': 'BUILD_GENERAL1_SMALL',
                       'environmentVariables': [{'name': 'VALUE', 'value': 'project-old', 'type': 'PLAINTEXT'}]}
        required('project', 'codebuild', 'create_project', name=name, serviceRole=role['Role']['Arn'],
                 source={'type': 'NO_SOURCE', 'buildspec': spec('project-old')}, artifacts={'type': 'NO_ARTIFACTS'},
                 environment=environment, timeoutInMinutes=5, queuedTimeoutInMinutes=5,
                 logsConfig={'cloudWatchLogs': {'status': 'ENABLED', 'groupName': name, 'streamName': 'owned'}},
                 tags=[{'key': 'stackd-owner', 'value': name}])
        owned.add('project')
        if args.source_versions:
            calibrate_versions(role['Role']['Arn'], environment)
        else:
            call('missing-id', 'codebuild', 'retry_build')
            call('missing-build', 'codebuild', 'retry_build', id=name + ':' + str(uuid.uuid4()))
            original = required('start-original', 'codebuild', 'start_build', projectName=name,
                                buildspecOverride=spec('accepted-override'), idempotencyToken='original',
                                environmentVariablesOverride=[{'name': 'VALUE', 'value': 'accepted-override', 'type': 'PLAINTEXT'}])['build']
            call('retry-in-progress', 'codebuild', 'retry_build', id=original['id'], idempotencyToken='active')
            settle('settle-original')
            environment['environmentVariables'] = [{'name': 'VALUE', 'value': 'project-new', 'type': 'PLAINTEXT'}, {'name': 'EXTRA', 'value': 'new-only', 'type': 'PLAINTEXT'}]
            required('update-project', 'codebuild', 'update_project', name=name, environment=environment,
                     source={'type': 'NO_SOURCE', 'buildspec': spec('project-new')})
            retried = required('retry-completed', 'codebuild', 'retry_build', id=original['id'], idempotencyToken='completed')['build']
            call('retry-replay', 'codebuild', 'retry_build', id=original['id'], idempotencyToken='completed')
            call('retry-arn-same-token', 'codebuild', 'retry_build', id=original['arn'], idempotencyToken='completed')
            call('retry-id-mismatch', 'codebuild', 'retry_build', id=retried['id'], idempotencyToken='completed')
            call('start-retry-token', 'codebuild', 'start_build', projectName=name, idempotencyToken='completed')
            failed = required('start-failed', 'codebuild', 'start_build', projectName=name, buildspecOverride=spec('failed-override', True))['build']
            settle('settle-retries')
            call('retry-failed-arn', 'codebuild', 'retry_build', id=failed['arn'], idempotencyToken='failed')
            settle('settle-failed-retry')
            required('delete-project', 'codebuild', 'delete_project', name=name)
            owned.remove('project')
            call('retry-deleted-project', 'codebuild', 'retry_build', id=original['id'])
            call('retry-replay-deleted-project', 'codebuild', 'retry_build', id=original['id'], idempotencyToken='completed')
        required('runtime-logs', 'logs', 'filter_log_events', logGroupName=name, limit=1000)
        data['capture_complete'] = True
    finally:
        cleaning = True
        if data['builds']:
            out = required('cleanup-build-state', 'codebuild', 'batch_get_builds', ids=data['builds'])
            for build in out['builds']:
                if not build.get('buildComplete'):
                    required('cleanup-stop', 'codebuild', 'stop_build', id=build['id'])
            settle('cleanup-settle')
            required('cleanup-builds', 'codebuild', 'batch_delete_builds', ids=data['builds'])
            left = required('cleanup-build-absence', 'codebuild', 'batch_get_builds', ids=data['builds'])
            data['cleanup']['builds_absent'] = not left['builds']
        if 'bucket' in owned:
            versions = required('cleanup-source-versions', 's3', 'list_object_versions', Bucket=name)
            objects = [{'Key': item['Key'], 'VersionId': item['VersionId']} for item in versions.get('Versions', []) + versions.get('DeleteMarkers', [])]
            if objects:
                required('cleanup-source-objects', 's3', 'delete_objects', Bucket=name, Delete={'Objects': objects})
            required('cleanup-bucket', 's3', 'delete_bucket', Bucket=name)
            absent = call('cleanup-bucket-absence', 's3', 'head_bucket', Bucket=name)
            data['cleanup']['bucket_absent'] = absent is None and data['observations'][-1].get('error', {}).get('Code') == '404'
        if 'project' in owned:
            required('cleanup-project', 'codebuild', 'delete_project', name=name)
        if 'logs' in owned:
            required('cleanup-logs', 'logs', 'delete_log_group', logGroupName=name)
        if 'role' in owned:
            call('cleanup-policy', 'iam', 'delete_role_policy', RoleName=name, PolicyName='owned')
            required('cleanup-role', 'iam', 'delete_role', RoleName=name)
        projects = required('cleanup-project-absence', 'codebuild', 'batch_get_projects', names=[name])
        groups = required('cleanup-log-absence', 'logs', 'describe_log_groups', logGroupNamePrefix=name)
        role = call('cleanup-role-absence', 'iam', 'get_role', RoleName=name)
        data['cleanup']['project_absent'] = not projects['projects']
        data['cleanup']['logs_absent'] = not any(g['logGroupName'] == name for g in groups['logGroups'])
        data['cleanup']['role_absent'] = role is None and data['observations'][-1].get('error', {}).get('Code') == 'NoSuchEntity'
        data['cleanup_verified'] = all(data['cleanup'].values())
        save()
        print(path)
        if not data['cleanup_verified']:
            raise RuntimeError('native cleanup incomplete; inspect retained exact-owned IDs')


if __name__ == '__main__':
    main()
