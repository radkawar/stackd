#!/usr/bin/env python3
"""Real local ECS/Docker S3 environment-file and Secrets Manager source proof.

Run against a fresh, script-owned SQLite controller; never contacts native AWS:
  python3 scripts/aws/ecs_environment_sources_smoke.py --binary bin/stackd \
    --state-directory /tmp/ecs-sources-UNIQUE --image busybox:1.36
Images and the documented ECS toolkit must already be installed. The JSON report
contains synthetic source values and observed container output, not real secrets.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
import uuid

import boto3
from botocore.config import Config

from stackd_process import StackdProcess


def require(value, message):
    if not value:
        raise AssertionError(message)


class Proof:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=False)
        self.prefix = 'ecs-sources-' + uuid.uuid4().hex[:10]
        self.database = self.state / 'state.sqlite'
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        self.endpoint = f'http://127.0.0.1:{self.port}'
        self.controller = StackdProcess(self.state)
        self.clients = {name: boto3.client(name, endpoint_url=self.endpoint,
            region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test',
            config=Config(retries={'total_max_attempts': 1}, s3={'addressing_style': 'path'}))
            for name in ('ecs', 'ec2', 'iam', 's3', 'kms', 'secretsmanager', 'cloudtrail')}
        self.tasks = []
        self.definitions = []
        self.roles = []
        self.objects = []
        self.cluster = self.vpc = self.subnet = self.secret = self.kms = None
        self.bucket = None
        self.markers = [uuid.uuid4().hex for _ in range(4)]
        self.report = {'scope': 'Local real Docker and SDK behavior; not native AWS observation',
            'prefix': self.prefix, 'cases': {}, 'controllers': self.controller.runs}

    def start(self):
        environment = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
        environment['AWS_EC2_METADATA_DISABLED'] = 'true'
        command = [str(Path(self.args.binary).resolve()), '-listen', f'0.0.0.0:{self.port}',
            '-public-endpoint', self.endpoint, '-database', str(self.database),
            '-docker-host', self.args.docker_host, '-ecs-runtime',
            '-compute-endpoint', f'http://host.docker.internal:{self.port}']
        self.controller.start(command, self.endpoint, environment=environment, timeout=90)

    def docker(self, *arguments):
        return subprocess.run(['docker', '--host', self.args.docker_host, *arguments],
            check=True, capture_output=True, text=True, timeout=30).stdout.strip()

    def policy(self, deny=None):
        statements = [{'Effect': 'Allow', 'Action': ['s3:GetObject', 'secretsmanager:GetSecretValue', 'kms:Decrypt'], 'Resource': '*'}]
        if deny:
            statements.append({'Effect': 'Deny', 'Action': deny, 'Resource': '*'})
        self.clients['iam'].put_role_policy(RoleName=self.roles[0], PolicyName='sources',
            PolicyDocument=json.dumps({'Version': '2012-10-17', 'Statement': statements}))

    def put(self, name, body):
        self.clients['s3'].put_object(Bucket=self.bucket, Key=name, Body=body.encode() if isinstance(body, str) else body,
            ServerSideEncryption='aws:kms', SSEKMSKeyId=self.kms)
        if name not in self.objects:
            self.objects.append(name)

    def provision(self):
        self.docker('image', 'inspect', self.args.image)
        iam, ec2, ecs = (self.clients[x] for x in ('iam', 'ec2', 'ecs'))
        role_arns = []
        trust = json.dumps({'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow',
            'Principal': {'Service': 'ecs-tasks.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]})
        for suffix in ('execution', 'task'):
            name = self.prefix + '-' + suffix
            role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)['Role']
            self.roles.append(name)
            role_arns.append(role['Arn'])
            iam.put_role_policy(RoleName=name, PolicyName='sources', PolicyDocument=json.dumps({
                'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}))
        self.execution_role, self.task_role = role_arns
        self.policy()
        self.kms = self.clients['kms'].create_key()['KeyMetadata']['Arn']
        self.bucket = self.prefix
        self.clients['s3'].create_bucket(Bucket=self.bucket)
        self.put('first.env', f'# comment\nDUP=first\nEXPLICIT=file\nFILE_TOKEN={self.markers[0]}\nONLY_DEFINITION=yes\nBLANK=\nLITERAL= "quoted" $HOME\\n \n')
        self.put('second.env', 'DUP=second\nSECOND=two\nEXPLICIT=second\n')
        self.put('override.env', f'DUP=override\nFILE_TOKEN={self.markers[3]}\n')
        created = self.clients['secretsmanager'].create_secret(Name=self.prefix, KmsKeyId=self.kms,
            SecretString=json.dumps({'token': self.markers[1]}))
        self.secret, self.old_version = created['ARN'], created['VersionId']
        self.clients['secretsmanager'].put_secret_value(SecretId=self.secret,
            SecretString=json.dumps({'token': self.markers[2]}))
        self.vpc = ec2.create_vpc(CidrBlock='10.247.0.0/24')['Vpc']['VpcId']
        self.subnet = ec2.create_subnet(VpcId=self.vpc, CidrBlock='10.247.0.0/24', AvailabilityZone='us-east-1a')['Subnet']['SubnetId']
        self.cluster = ecs.create_cluster(clusterName=self.prefix)['cluster']['clusterArn']
        self.definition = self.register('app', self.secret + ':token::')

    def file(self, name):
        return {'type': 's3', 'value': f'arn:aws:s3:::{self.bucket}/{name}'}

    def register(self, suffix, token):
        command = 'printf "%s\\n" "DUP=$DUP" "EXPLICIT=$EXPLICIT" "SECOND=${SECOND-unset}" "ONLY_DEFINITION=${ONLY_DEFINITION-unset}" "BLANK=${BLANK-unset}" "LITERAL=${LITERAL-unset}" "FILE_TOKEN=$FILE_TOKEN" "TOKEN=$TOKEN" "FULL=$FULL" "PREVIOUS=$PREVIOUS" "VERSION=$VERSION"; sleep 600'
        out = self.clients['ecs'].register_task_definition(family=self.prefix + '-' + suffix,
            executionRoleArn=self.execution_role, taskRoleArn=self.task_role, cpu='256', memory='512',
            networkMode='awsvpc', requiresCompatibilities=['FARGATE'], containerDefinitions=[{
                'name': 'app', 'image': self.args.image, 'essential': True,
                'entryPoint': ['/bin/sh', '-c'], 'command': [command],
                'environment': [{'name': 'EXPLICIT', 'value': 'definition'}],
                'environmentFiles': [self.file('first.env'), self.file('second.env')],
                'secrets': [{'name': 'TOKEN', 'valueFrom': token},
                    {'name': 'FULL', 'valueFrom': self.secret},
                    {'name': 'PREVIOUS', 'valueFrom': self.secret + ':token:AWSPREVIOUS:'},
                    {'name': 'VERSION', 'valueFrom': self.secret + ':token::' + self.old_version}] if token is not None else []}])
        arn = out['taskDefinition']['taskDefinitionArn']
        self.definitions.append(arn)
        return arn

    def wait(self, arn, status):
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            out = self.clients['ecs'].describe_tasks(cluster=self.cluster, tasks=[arn])
            require(not out.get('failures') and len(out['tasks']) == 1, 'task disappeared')
            task = out['tasks'][0]
            if task['lastStatus'] == status:
                return task
            require(task['lastStatus'] != 'STOPPED', f'unexpected stopped task: {task}')
            time.sleep(.2)
        raise TimeoutError(f'{arn} did not reach {status}')

    def run(self, name, expected=None, overrides=None, definition=None):
        request = dict(cluster=self.cluster, taskDefinition=definition or self.definition,
            launchType='FARGATE', networkConfiguration={'awsvpcConfiguration': {'subnets': [self.subnet]}})
        if overrides is not None:
            request['overrides'] = overrides
        out = self.clients['ecs'].run_task(**request)
        require(not out.get('failures') and len(out['tasks']) == 1, f'RunTask failed: {out}')
        arn = out['tasks'][0]['taskArn']
        self.tasks.append(arn)
        if expected is None:
            task = self.wait(arn, 'STOPPED')
            require(task.get('stopCode') == 'TaskFailedToStart' and not task.get('startedAt'), 'denied source started a task')
            self.report['cases'][name] = {'task': arn, 'stopCode': task.get('stopCode'), 'reason': task.get('stoppedReason')}
            return arn
        self.wait(arn, 'RUNNING')
        container = self.container(arn)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            output = self.docker('logs', container['Id'])
            if 'VERSION=' in output:
                break
            time.sleep(.1)
        values = dict(line.split('=', 1) for line in output.splitlines())
        for key, value in expected.items():
            require(values.get(key) == value, f'{name}: {key} expected {value!r}, got {values.get(key)!r}')
        self.report['cases'][name] = {'task': arn, 'container': container['Id'], 'pid': container['State']['Pid'], 'output': values}
        return arn

    def container(self, arn):
        ids = self.docker('ps', '-aq', '--filter', 'label=stackd.ecs.task=' + arn,
            '--filter', 'label=stackd.ecs.role=container').split()
        require(len(ids) == 1, f'expected one application container for {arn}: {ids}')
        row = json.loads(self.docker('inspect', ids[0]))[0]
        require(row['Config']['Labels']['stackd.ecs.task'] == arn, 'container ownership mismatch')
        return row

    def retained_plaintext(self):
        # S3 owns the original file bytes. Only ECS state and API audit must not
        # copy resolved contents; scanning the entire object database is wrong.
        with sqlite3.connect(f'file:{self.database}?mode=ro', uri=True) as db:
            tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ecs_%'")]
            require(tables, 'no ECS storage tables found')
            for table in tables:
                for row in db.execute('SELECT * FROM "' + table.replace('"', '""') + '"'):
                    require(not any(marker in repr(row) for marker in self.markers), f'resolved bytes leaked into {table}')
        events = 0
        for page in self.clients['cloudtrail'].get_paginator('lookup_events').paginate():
            for event in page.get('Events', []):
                require(not any(marker in event['CloudTrailEvent'] for marker in self.markers), 'resolved bytes leaked into audit')
                events += 1
        require(events > 0, 'audit history was empty')
        self.report['retained_state'] = {'ecs_tables': tables, 'audit_events_checked': events, 'plaintext_absent': True}

    def exercise(self):
        expected = {'DUP': 'first', 'EXPLICIT': 'definition', 'SECOND': 'two', 'ONLY_DEFINITION': 'yes',
            'BLANK': 'unset', 'LITERAL': ' "quoted" $HOME\\n ', 'FILE_TOKEN': self.markers[0],
            'TOKEN': self.markers[2], 'FULL': json.dumps({'token': self.markers[2]}),
            'PREVIOUS': self.markers[1], 'VERSION': self.markers[1]}
        original = self.run('definition-and-selectors', expected)
        replacement = dict(expected, DUP='override', EXPLICIT='override-explicit', SECOND='unset',
            ONLY_DEFINITION='unset', LITERAL='unset', FILE_TOKEN=self.markers[3])
        self.run('override-replaces-files', replacement, {'containerOverrides': [{'name': 'app',
            'environmentFiles': [self.file('override.env')], 'environment': [{'name': 'EXPLICIT', 'value': 'override-explicit'}]}]})
        self.put('first.env', f'DUP=updated\nFILE_TOKEN={self.markers[3]}\n')
        self.policy(['s3:GetObject', 'secretsmanager:GetSecretValue', 'kms:Decrypt'])
        before = self.container(original)
        self.controller.stop(timeout=90)
        self.start()
        self.wait(original, 'RUNNING')
        after = self.container(original)
        require(before['Id'] == after['Id'] and before['State']['Pid'] == after['State']['Pid'], 'restart recreated the native task')
        self.report['restart'] = {'same_container_and_pid': True, 'execution_role_denied': True}
        self.run('denied-execution-role-no-task-role-fallback')
        for action in ('s3:GetObject', 'secretsmanager:GetSecretValue', 'kms:Decrypt'):
            self.policy(action)
            self.run('denied-' + action)
        files_only = self.register('files-only', None)
        self.run('denied-s3-kms-without-secret-source', definition=files_only)
        self.policy()
        self.run('updated-file-new-task', dict(expected, DUP='updated', FILE_TOKEN=self.markers[3], ONLY_DEFINITION='unset', LITERAL='unset'))
        missing = self.register('missing-json-key', self.secret + ':missing::')
        self.run('missing-json-key', definition=missing)
        self.run('missing-object', overrides={'containerOverrides': [{'name': 'app', 'environmentFiles': [self.file('missing.env')]}]})
        self.put('invalid.env', b'VALUE=\xff')
        self.run('invalid-utf8', overrides={'containerOverrides': [{'name': 'app', 'environmentFiles': [self.file('invalid.env')]}]})
        self.retained_plaintext()

    def cleanup(self):
        errors = []
        def attempt(fn, **kwargs):
            try:
                return fn(**kwargs)
            except Exception as error:
                errors.append(str(error))
        if self.controller.process is not None:
            for arn in self.tasks:
                attempt(self.clients['ecs'].stop_task, cluster=self.cluster, task=arn)
                try:
                    self.wait(arn, 'STOPPED')
                except Exception as error:
                    errors.append(str(error))
            for arn in self.definitions:
                attempt(self.clients['ecs'].deregister_task_definition, taskDefinition=arn)
            if self.cluster:
                attempt(self.clients['ecs'].delete_cluster, cluster=self.cluster)
            if self.subnet:
                attempt(self.clients['ec2'].delete_subnet, SubnetId=self.subnet)
            if self.vpc:
                attempt(self.clients['ec2'].delete_vpc, VpcId=self.vpc)
            if self.secret:
                attempt(self.clients['secretsmanager'].delete_secret, SecretId=self.secret, ForceDeleteWithoutRecovery=True)
            if self.bucket:
                for key in self.objects:
                    attempt(self.clients['s3'].delete_object, Bucket=self.bucket, Key=key)
                attempt(self.clients['s3'].delete_bucket, Bucket=self.bucket)
            if self.kms:
                attempt(self.clients['kms'].schedule_key_deletion, KeyId=self.kms, PendingWindowInDays=7)
            for role in self.roles:
                attempt(self.clients['iam'].delete_role_policy, RoleName=role, PolicyName='sources')
                attempt(self.clients['iam'].delete_role, RoleName=role)
        try:
            self.controller.stop(timeout=90)
        except Exception as error:
            errors.append(str(error))
        self.report['cleanup_errors'] = errors
        (self.state / 'report.json').write_text(json.dumps(self.report, indent=2))
        require(not errors, 'owned cleanup failed: ' + '; '.join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--image', default='busybox:1.36')
    parser.add_argument('--docker-host', default=os.environ.get('DOCKER_HOST', 'unix:///var/run/docker.sock'))
    args = parser.parse_args()
    proof = Proof(args)
    try:
        proof.start()
        proof.provision()
        proof.exercise()
        print(json.dumps(proof.report, indent=2))
    finally:
        proof.cleanup()


if __name__ == '__main__':
    main()
