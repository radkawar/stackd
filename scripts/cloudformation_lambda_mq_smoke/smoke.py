#!/usr/bin/env python3
"""Local signed CFN -> real RabbitMQ/ActiveMQ -> official Python Lambda -> SQS.

Run with prebuilt stackd and Go helper; never uses ambient AWS credentials.
Retains isolated SQLite/native/controller files and reports, including failures.
"""
import argparse
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.request
import urllib.parse
import uuid
import zipfile

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


HANDLER = '''import boto3, json, os

def invoke(event, context):
    failed = os.environ['FAIL'] == '1'
    observation = {'event': event, 'failed': failed, 'request_id': context.aws_request_id,
                   'function_version': context.function_version, 'invoked_function_arn': context.invoked_function_arn}
    boto3.client('sqs', endpoint_url=os.environ['PROOF_ENDPOINT']).send_message(
        QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(observation))
    if failed:
        raise RuntimeError('owned MQ whole-batch native redelivery proof')
    return {'ok': True}
'''


def require(value, message):
    if not value:
        raise AssertionError(message)


class Proof:
    def __init__(self, args):
        self.args = args
        self.state = Path(args.state_directory).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.database = self.state / 'mq.sqlite'
        require(not self.database.exists(), 'fresh exact-owned state directory required')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.endpoint = f'http://127.0.0.1:{self.port}'
        self.compute = f'http://host.docker.internal:{self.port}'
        self.prefix = 'mq-cfn-proof-' + uuid.uuid4().hex[:10]
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('AWS_')}
        self.env['AWS_EC2_METADATA_DISABLED'] = 'true'
        self.process = self.log = None
        self.starts = 0
        self.broker = self.broker_arn = self.stack = self.mapping = self.function = None
        self.role = self.secret = self.queue = self.configuration = None
        self.policies = set()
        self.pending = []
        self.effects = []
        self.sent = {}
        self.properties = None
        self.source_queue = 'owned.source'
        self.virtual_host = 'owned.custom' if args.scenario in ('custom-host', 'late-host') else '/'
        self.extra_secrets = []
        self.extra_mappings = []
        self.username = 'proofuser'
        self.password = 'Proof-' + uuid.uuid4().hex
        self.report = {'command': shlex.join([sys.executable, *sys.argv]), 'engine': args.engine,
            'scenario': args.scenario, 'prefix': self.prefix, 'endpoint': self.endpoint,
            'state_directory': str(self.state), 'observations': {}, 'cleanup': {},
            'limitations': ['Local executable integration, not native AWS lifecycle evidence.',
                'Native broker queue lifecycle and JMS dynamic destination creation are engine behavior, not CFN namespace translation.',
                'No native AWS fleet or external AWS endpoints are used.']}
        self.cfn, self.functions, self.mq, self.sqs, self.iam, self.secrets, self.logs = [self.client(service)
            for service in ('cloudformation', 'lambda', 'mq', 'sqs', 'iam', 'secretsmanager', 'logs')]

    def client(self, service):
        return boto3.client(service, endpoint_url=self.endpoint, region_name='us-east-1',
            aws_access_key_id='test', aws_secret_access_key='test',
            config=Config(retries={'total_max_attempts': 1}, connect_timeout=5, read_timeout=120))

    def save(self):
        self.report['effects'] = self.effects
        Path(self.args.report).write_text(json.dumps(self.report, indent=2, default=str) + '\n')
        (self.state / 'report.json').write_text(json.dumps(self.report, indent=2, default=str) + '\n')

    def observe(self, label, row):
        self.report['observations'][label] = row
        self.save()

    def wait(self, fn, label, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = fn()
            if row:
                return row
            time.sleep(.2)
        raise TimeoutError(label)

    def start(self):
        self.starts += 1
        self.log = (self.state / f'controller-{self.starts}.log').open('wb')
        command = [str(Path(self.args.binary).resolve()), '-listen', f'0.0.0.0:{self.port}',
            '-public-endpoint', self.endpoint, '-compute-endpoint', self.compute,
            '-database', str(self.database), '-docker-host', 'unix:///var/run/docker.sock', '-lambda-runtime',
            '-lambda-telemetry-directory', str(Path(self.args.telemetry_directory).resolve()),
            '-mq-runtime', '-mq-state-directory', str(self.state / 'native'),
            '-mq-tls-certificate', str(self.state / 'cert.pem'), '-mq-tls-key', str(self.state / 'key.pem')]
        self.process = subprocess.Popen(command, env=self.env, stdout=self.log, stderr=self.log)
        self.wait(self.health, 'controller readiness')

    def health(self):
        require(self.process.poll() is None, 'controller exited; inspect retained log')
        try:
            with urllib.request.urlopen(self.endpoint + '/_stackd/health', timeout=1) as response:
                return response.status == 200
        except OSError:
            return False

    def stop(self):
        if self.process:
            self.process.terminate()
            status = self.process.wait(timeout=90)
            self.report.setdefault('controllers', []).append({'start': self.starts, 'exit_status': status})
            self.process = None
            require(status == 0, 'controller shutdown failed')
        if self.log:
            self.log.close()
            self.log = None

    def absent(self, client, method, code, **request):
        try:
            getattr(client, method)(**request)
            return False
        except ClientError as error:
            require(error.response['Error']['Code'] == code, str(error))
            return True

    def broker_ready(self):
        row = self.mq.describe_broker(BrokerId=self.broker)
        require(row['BrokerState'] not in ('CREATION_FAILED', 'CRITICAL_ACTION_REQUIRED'), str(row))
        return row if row['BrokerState'] == 'RUNNING' else None

    def native(self, operation, body=b'', identifier='', queue=None, virtual_host=None):
        address = next(endpoint for instance in self.description['BrokerInstances'] for endpoint in instance['Endpoints']
                       if endpoint.startswith('amqps://' if self.args.engine == 'RABBITMQ' else 'ssl://'))
        certificate = (self.state / 'cert.pem').read_text()
        if self.args.engine == 'RABBITMQ':
            request = dict(Address=address, Username=self.username, Password=self.password,
                Queue=queue or self.source_queue, Certificate=certificate, Operation=operation,
                ID=identifier, Body=base64.b64encode(body).decode(), VirtualHost=virtual_host or self.virtual_host)
            command = [str(Path(self.args.sdk_helper).resolve()), '-mode', 'rabbit']
            stdin = json.dumps(request)
        else:
            drivers = list((self.state / 'native').glob('jms-5.18.7-*'))
            require(len(drivers) == 1, 'exact installed native JMS driver not found')
            command = ['java', '-cp', str(drivers[0] / '*'), str(Path(__file__).with_name('BrokerMQ.java').resolve())]
            fields = [address, self.username, self.password, queue or self.source_queue, certificate,
                      operation, base64.b64encode(body).decode()]
            stdin = '\t'.join(base64.b64encode(value.encode()).decode() for value in fields) + '\n'
        result = subprocess.run(command, input=stdin, text=True, capture_output=True, timeout=60, env=self.env)
        require(result.returncode == 0, f'native {operation} failed: {result.stderr} {result.stdout}')
        return json.loads(result.stdout)

    def create_virtual_host(self):
        endpoint = urllib.parse.urlsplit(self.description['BrokerInstances'][0]['ConsoleURL'])
        require(endpoint.scheme == 'https' and endpoint.hostname == '127.0.0.1',
                'native Rabbit management must use explicit owned loopback TLS')
        base = urllib.parse.urlunsplit((endpoint.scheme, endpoint.netloc, '', '', ''))
        context = ssl.create_default_context(cafile=str(self.state / 'cert.pem'))
        authorization = 'Basic ' + base64.b64encode((self.username + ':' + self.password).encode()).decode()
        inventory = urllib.request.Request(base + '/api/vhosts', headers={'Authorization': authorization})
        with urllib.request.urlopen(inventory, context=context, timeout=10) as response:
            existing = json.loads(response.read())
        require(self.virtual_host not in {row['name'] for row in existing}, 'custom host existed before owned native creation')
        self.observe('native-host-absent-before-creation', existing)
        host = urllib.parse.quote(self.virtual_host, safe='')
        user = urllib.parse.quote(self.username, safe='')
        observations = []
        for path, body in [('/api/vhosts/' + host, {}),
                           ('/api/permissions/' + host + '/' + user, {'configure': '.*', 'write': '.*', 'read': '.*'})]:
            request = urllib.request.Request(base + path, data=json.dumps(body).encode(), method='PUT',
                headers={'Authorization': authorization, 'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, context=context, timeout=10) as response:
                require(response.status in (201, 204), 'native Rabbit vhost/permission creation rejected')
                observations.append({'path': path, 'status': response.status, 'body': response.read().decode()})
        self.observe('owned-native-custom-host', observations)

    def publish(self, label, queue=None, virtual_host=None, payload=None):
        # Include binary NUL/non-UTF8, all byte values and Unicode; compare complete bytes after delivery.
        body = payload if payload is not None else label.encode() + b'\x00\xff' + bytes(range(256)) + '\u96ea\U0001f642'.encode()
        row = self.native('publish', body, label, queue, virtual_host)
        identifier = row['message_id'] if self.args.engine == 'RABBITMQ' else row['published']['message_id']
        self.sent[label] = {'id': identifier, 'body': base64.b64encode(body).decode(), 'native_publish': row}
        self.observe('publish-' + label, self.sent[label])
        return identifier

    def environment(self, failed):
        return {'Variables': {'FAIL': str(int(failed)), 'PROOF_ENDPOINT': self.compute,
            'QUEUE_URL': self.queue.replace(self.endpoint, self.compute)}}

    def function_ready(self):
        row = self.functions.get_function_configuration(FunctionName=self.function)
        return row if row['State'] == 'Active' and row.get('LastUpdateStatus', 'Successful') == 'Successful' else None

    def policy(self, name, actions):
        self.iam.put_role_policy(RoleName=self.role, PolicyName=name, PolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{'Effect': 'Deny' if name == 'deny-source' else 'Allow',
                                                'Action': actions, 'Resource': '*'}]}))
        self.policies.add(name)

    def remove_policy(self, name):
        self.iam.delete_role_policy(RoleName=self.role, PolicyName=name)
        self.policies.discard(name)

    def setup(self):
        tls = subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(self.state / 'key.pem'), '-out', str(self.state / 'cert.pem'),
            '-days', '1', '-subj', '/CN=owned-cfn-mq-proof', '-addext', 'subjectAltName=IP:127.0.0.1'],
            capture_output=True, text=True, timeout=30)
        require(tls.returncode == 0, tls.stderr)
        self.start()
        created = self.mq.create_broker(BrokerName=self.prefix, EngineType=self.args.engine,
            EngineVersion='3.13.7' if self.args.engine == 'RABBITMQ' else '5.18',
            DeploymentMode='SINGLE_INSTANCE', HostInstanceType='mq.t3.micro', PubliclyAccessible=True,
            AutoMinorVersionUpgrade=False, Users=[{'Username': self.username, 'Password': self.password}])
        self.broker, self.broker_arn = created['BrokerId'], created['BrokerArn']
        self.description = self.wait(self.broker_ready, 'real broker running', 240)
        self.configuration = self.description.get('Configurations', {}).get('Current', {}).get('Id')
        self.observe('broker', self.description)
        self.queue = self.sqs.create_queue(QueueName=self.prefix)['QueueUrl']
        self.role = self.prefix
        role = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=json.dumps({
            'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'},
                                                'Action': 'sts:AssumeRole'}]}))['Role']['Arn']
        self.policy('source-target', ['mq:DescribeBroker', 'secretsmanager:GetSecretValue', 'kms:Decrypt',
            'ec2:CreateNetworkInterface', 'ec2:DeleteNetworkInterface', 'ec2:DescribeNetworkInterfaces',
            'ec2:DescribeSecurityGroups', 'ec2:DescribeSubnets', 'ec2:DescribeVpcs',
            'sqs:SendMessage', 'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'])
        self.secret = self.secrets.create_secret(Name=self.prefix,
            SecretString=json.dumps({'username': self.username, 'password': self.password}))['ARN']
        package = io.BytesIO()
        with zipfile.ZipFile(package, 'w') as archive:
            archive.writestr('entry.py', HANDLER)
        self.function = self.prefix
        self.functions.create_function(FunctionName=self.function, Role=role, Runtime='python3.12',
            Handler='entry.invoke', Timeout=20, MemorySize=128, Code={'ZipFile': package.getvalue()},
            Environment=self.environment(False))
        self.wait(self.function_ready, 'official Python Lambda function')
        self.version = self.functions.publish_version(FunctionName=self.function)['Version']
        self.alias = self.functions.create_alias(FunctionName=self.function, Name='live', FunctionVersion=self.version)['AliasArn']
        if self.args.scenario == 'custom-host':
            require(self.args.engine == 'RABBITMQ', 'custom vhosts apply only to RabbitMQ')
            self.create_virtual_host()
            self.publish('default-host-independent', virtual_host='/')
        if self.args.scenario not in ('missing-queue', 'late-host'):
            self.observe('native-queue-created', self.native('declare'))
            self.publish('disabled-backlog')

    def template(self, properties):
        return {'AWSTemplateFormatVersion': '2010-09-09', 'Resources': {
            'Mapping': {'Type': 'AWS::Lambda::EventSourceMapping', 'Properties': properties}}, 'Outputs': {
            'MappingUUID': {'Value': {'Ref': 'Mapping'}}, 'MappingId': {'Value': {'Fn::GetAtt': ['Mapping', 'Id']}},
            'MappingArn': {'Value': {'Fn::GetAtt': ['Mapping', 'EventSourceMappingArn']}}}}

    def stack_ready(self, expected):
        row = self.cfn.describe_stacks(StackName=self.stack)['Stacks'][0]
        status = row['StackStatus']
        if status == expected:
            return row
        if expected == 'UPDATE_ROLLBACK_COMPLETE' and status in ('UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS'):
            return None
        if 'FAILED' in status or 'ROLLBACK' in status or status.endswith('_COMPLETE'):
            raise AssertionError('CloudFormation ' + status + ': ' + json.dumps(
                self.cfn.describe_stack_events(StackName=self.stack)['StackEvents'], default=str))
        return None

    def projection(self, stack):
        outputs = {row['OutputKey']: row['OutputValue'] for row in stack['Outputs']}
        identifier = outputs['MappingUUID']
        require(str(uuid.UUID(identifier)) == identifier and outputs['MappingId'] == identifier, 'CFN UUID projection mismatch')
        row = self.functions.get_event_source_mapping(UUID=identifier)
        require(row['EventSourceArn'] == self.broker_arn and row['EventSourceMappingArn'] == outputs['MappingArn'],
                'CFN source/mapping ARN mismatch')
        resource = self.cfn.describe_stack_resource(StackName=self.stack, LogicalResourceId='Mapping')['StackResourceDetail']
        require(resource['PhysicalResourceId'] == identifier, 'CFN physical identifier differs from live Lambda mapping')
        return identifier, row, outputs

    def mapping_state(self, state):
        row = self.functions.get_event_source_mapping(UUID=self.mapping)
        return row if row['State'] == state else None

    def deploy(self):
        self.properties = {'FunctionName': self.alias, 'EventSourceArn': self.broker_arn,
            'Queues': [self.source_queue], 'Enabled': False, 'BatchSize': 1,
            'MaximumBatchingWindowInSeconds': 1,
            'SourceAccessConfigurations': [{'Type': 'BASIC_AUTH', 'URI': self.secret}]}
        if self.virtual_host != '/' or self.args.scenario == 'default-host':
            self.properties['SourceAccessConfigurations'].append({'Type': 'VIRTUAL_HOST', 'URI': self.virtual_host})
        if self.args.scenario == 'defaults':
            self.properties.pop('BatchSize')
            self.properties.pop('MaximumBatchingWindowInSeconds')
        self.stack = self.prefix + '-stack'
        template = self.state / 'go-sdk-template.json'
        template.write_text(json.dumps(self.template(self.properties)))
        result = subprocess.run([str(Path(self.args.sdk_helper).resolve()), '-endpoint', self.endpoint,
            '-stack', self.stack, '-template', str(template)], capture_output=True, text=True, timeout=200, env=self.env)
        self.observe('go-sdk-deployment', {'exit_status': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        require(result.returncode == 0, 'signed Go SDK deployment failed: ' + result.stderr)
        decoded = json.loads(result.stdout)
        self.mapping, mapping, outputs = self.projection(self.wait(lambda: self.stack_ready('CREATE_COMPLETE'), 'CFN creation'))
        require(decoded['outputs'] == outputs, 'Go/Python output projections differ')
        self.wait(lambda: self.mapping_state('Disabled'), 'disabled mapping')
        self.observe('deployment', mapping)

    def update(self, label, remove=(), **changes):
        properties = copy.deepcopy(self.properties)
        properties.update(changes)
        for key in remove:
            properties.pop(key, None)
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_COMPLETE'), 'CFN ' + label)
        identifier, mapping, outputs = self.projection(stack)
        require(identifier == self.mapping, label + ': mutable update replaced mapping')
        self.properties = properties
        self.wait(lambda: self.mapping_state('Enabled' if properties.get('Enabled', True) else 'Disabled'), label)
        self.observe(label, {'mapping': mapping, 'outputs': outputs})
        return mapping

    def rejected_update(self, label, remove=(), **changes):
        before = self.functions.get_event_source_mapping(UUID=self.mapping)
        properties = copy.deepcopy(self.properties)
        properties.update(changes)
        for key in remove:
            properties.pop(key, None)
        self.cfn.update_stack(StackName=self.stack, TemplateBody=json.dumps(self.template(properties)))
        stack = self.wait(lambda: self.stack_ready('UPDATE_ROLLBACK_COMPLETE'), 'CFN rollback ' + label)
        identifier, after, outputs = self.projection(stack)
        require(identifier == self.mapping, label + ': rollback replaced mapping identity')
        for key in ('UUID', 'FunctionArn', 'EventSourceArn', 'Queues', 'SourceAccessConfigurations',
                    'BatchSize', 'MaximumBatchingWindowInSeconds', 'FilterCriteria', 'State'):
            require(before.get(key) == after.get(key), label + ': rollback changed ' + key)
        self.observe(label, {'before': before, 'after': after, 'outputs': outputs,
            'events': self.cfn.describe_stack_events(StackName=self.stack)['StackEvents']})

    def receive(self):
        messages = self.sqs.receive_message(QueueUrl=self.queue, MaxNumberOfMessages=10, WaitTimeSeconds=1).get('Messages', [])
        rows = []
        for message in messages:
            self.sqs.delete_message(QueueUrl=self.queue, ReceiptHandle=message['ReceiptHandle'])
            rows.append(json.loads(message['Body']))
        self.effects.extend(rows)
        return rows

    def records(self, row):
        event = row['event']
        expected_source = 'aws:rmq' if self.args.engine == 'RABBITMQ' else 'aws:mq'
        require(event['eventSource'] == expected_source and event['eventSourceArn'] == self.broker_arn, 'native source envelope mismatch')
        if self.args.engine == 'ACTIVEMQ':
            return event['messages']
        namespace = self.source_queue + '::' + self.virtual_host
        require(set(event['rmqMessagesByQueue']) == {namespace}, 'Rabbit queue/vhost namespace mismatch')
        return event['rmqMessagesByQueue'][namespace]

    def record_id(self, row):
        return row.get('messageID') or row.get('basicProperties', {}).get('messageId')

    def take(self, label, failed=False):
        self.pending.extend(self.receive())
        for i, row in enumerate(self.pending):
            records = self.records(row)
            if row['failed'] == failed and any(self.record_id(record) == self.sent[label]['id'] for record in records):
                row = self.pending.pop(i)
                record = next(record for record in records if self.record_id(record) == self.sent[label]['id'])
                require(record['data'] == self.sent[label]['body'], label + ': full binary payload mismatch')
                require(row['request_id'], 'real Lambda runtime request ID missing')
                return row
        return None

    def delivered(self, label, failed=False):
        row = self.wait(lambda: self.take(label, failed), 'real Lambda SQS effect ' + label, 100)
        if not failed:
            self.wait(lambda: self.runtime_completed(row['request_id']), 'official runtime completion ' + label, 30)
            self.wait(lambda: self.functions.get_event_source_mapping(UUID=self.mapping).get('LastProcessingResult') == 'OK',
                      'mapping native ACK completion ' + label, 30)
        self.observe(('failed-' if failed else 'delivered-') + label, row)
        return row

    def runtime_completed(self, request_id):
        group = '/aws/lambda/' + self.function
        streams = self.logs.describe_log_streams(logGroupName=group).get('logStreams', [])
        for stream in streams:
            events = self.logs.get_log_events(logGroupName=group, logStreamName=stream['logStreamName']).get('events', [])
            for event in events:
                if 'REPORT RequestId: ' + request_id in event['message']:
                    return event
        return None

    def quiet(self, label):
        time.sleep(3)
        require(not self.receive() and not self.pending, label + ': unexpected Lambda SQS effect')

    def count(self, expected, label):
        row = self.wait(lambda: self.queue_count(expected), label, 60)
        self.observe(label, row)
        return row

    def queue_count(self, expected):
        row = self.native('inspect')
        return row if row['messages'] == expected else None

    def disable(self, label):
        self.update(label, Enabled=False)

    def deny(self, label, revoke, restore):
        revoke()
        def problem():
            row = self.functions.get_event_source_mapping(UUID=self.mapping)
            return row if row.get('LastProcessingResult', '').startswith('PROBLEM:') else None
        blocked = self.wait(problem, label + ' current authority rejection', 90)
        self.publish(label)
        self.quiet(label)
        self.count(1, label + '-native-retained')
        restore()
        recovered = self.delivered(label)
        self.observe(label, {'blocked': blocked, 'recovered': recovered})
        self.disable(label + '-disable')
        self.count(0, label + '-native-ack')
        self.update(label + '-reenable', Enabled=True)

    def core(self):
        self.quiet('disabled deployment')
        self.count(1, 'disabled-native-backlog')
        self.update('enable', Enabled=True)
        first = self.delivered('disabled-backlog')
        require(first['function_version'] == self.version and first['invoked_function_arn'] == self.alias,
                'published alias target not preserved')
        self.disable('disable-before-restart')
        self.count(0, 'initial-native-ack')
        self.publish('disabled-before-restart')
        self.quiet('disabled before restart')
        self.stop()
        self.publish('controller-stopped')
        self.start()
        self.description = self.wait(self.broker_ready, 'retained broker after restart')
        self.wait(lambda: self.mapping_state('Disabled'), 'retained disabled mapping')
        self.quiet('disabled after SQLite/controller restart')
        self.count(2, 'restart-retained-native-backlog')
        self.update('enable-after-restart', Enabled=True)
        self.delivered('disabled-before-restart')
        self.delivered('controller-stopped')
        self.disable('disable-after-restart-drain')
        self.count(0, 'restart-native-ack')
        self.update('enable-authority', Enabled=True)
        self.deny('iam-denial', lambda: self.policy('deny-source', ['mq:DescribeBroker']),
                  lambda: self.remove_policy('deny-source'))
        self.deny('secret-denial', lambda: self.policy('deny-source', ['secretsmanager:GetSecretValue']),
                  lambda: self.remove_policy('deny-source'))
        self.disable('disable-before-failure')
        self.functions.update_function_configuration(FunctionName=self.function, Environment=self.environment(True))
        self.wait(self.function_ready, 'failure function version')
        failed_version = self.functions.publish_version(FunctionName=self.function)['Version']
        self.functions.update_alias(FunctionName=self.function, Name='live', FunctionVersion=failed_version)
        self.publish('failed-unacked')
        self.update('enable-failing-target', Enabled=True)
        first_failed = self.delivered('failed-unacked', True)
        second_failed = self.delivered('failed-unacked', True)
        require(first_failed['request_id'] != second_failed['request_id'], 'failed message was not retried by runtime')
        self.disable('disable-failed-target')
        self.count(1, 'failed-native-unacked')
        self.pending.clear()
        self.receive()
        self.functions.update_alias(FunctionName=self.function, Name='live', FunctionVersion=self.version)
        self.stop()
        self.start()
        self.description = self.wait(self.broker_ready, 'broker restart after failed invocation')
        self.wait(lambda: self.mapping_state('Disabled'), 'disabled failure retained')
        self.count(1, 'failed-native-retained-restart')
        self.update('enable-recovered-alias', Enabled=True)
        recovered = self.delivered('failed-unacked')
        record = next(record for record in self.records(recovered) if self.record_id(record) == self.sent['failed-unacked']['id'])
        require(record['redelivered'], 'native broker did not mark failed invocation redelivery')
        require(recovered['function_version'] == self.version, 'alias recovery ignored current published version')
        self.disable('disable-after-recovery')
        self.count(0, 'recovery-native-ack')
        self.observe('failed-invocation-native-redelivery', {'first': first_failed, 'retry': second_failed, 'recovered': recovered})

    def settings(self):
        self.update('batch-window-update', BatchSize=2, MaximumBatchingWindowInSeconds=2)
        self.publish('second-batch-record')
        self.update('enable-batch', Enabled=True)
        first = self.delivered('disabled-backlog')
        ids = {self.record_id(row) for row in self.records(first)}
        require(ids == {self.sent['disabled-backlog']['id'], self.sent['second-batch-record']['id']}, 'configured native whole-batch delivery mismatch')
        for row in self.records(first):
            expected = next(item for item in self.sent.values() if item['id'] == self.record_id(row))
            require(row['data'] == expected['body'], 'batch full payload bytes mismatch')
        self.disable('disable-settings')
        self.count(0, 'batch-native-ack')
        qualified = self.functions.get_function_configuration(FunctionName=self.function)['FunctionArn'] + ':' + self.version
        self.update('qualified-version-target', FunctionName=qualified)
        self.publish('qualified-version')
        self.update('enable-qualified-version', Enabled=True)
        delivered = self.delivered('qualified-version')
        require(delivered['invoked_function_arn'] == qualified and delivered['function_version'] == self.version,
                'qualified version target changed')
        self.disable('disable-qualified-version')
        self.count(0, 'qualified-native-ack')

    def defaults(self):
        row = self.functions.get_event_source_mapping(UUID=self.mapping)
        require(row['BatchSize'] == 100 and 'MaximumBatchingWindowInSeconds' not in row,
                'MQ default batch size or fractional-window projection differs from measured native defaults')
        self.observe('native-calibrated-create-defaults', row)
        self.update('enable-default-batching', Enabled=True)
        self.delivered('disabled-backlog')
        self.disable('disable-default-batching')
        self.count(0, 'default-window-native-ack')

    def controls(self):
        self.observe('native-control-calibration', {
            'fixture': 'testdata/aws/cloudformation/lambda_mq_mapping_' + self.args.engine.lower() + '.json',
            'scope': 'Native provider update/admission measurements; message filtering/ACK evidence below is local real-engine execution.'})
        replacement = self.secrets.create_secret(Name=self.prefix + '-replacement',
            SecretString=json.dumps({'username': self.username, 'password': self.password}))['ARN']
        self.extra_secrets.append(replacement)
        self.update('explicit-controls-batch-window', BatchSize=3, MaximumBatchingWindowInSeconds=2)
        self.publish('unchanged-other-queue', queue='owned.other')
        self.rejected_update('immutable-queue-change', Queues=['owned.other'])
        self.rejected_update('immutable-queue-omission', remove=('Queues',))
        self.rejected_update('atomic-queue-auth-batch-rollback', Queues=['owned.other'], BatchSize=7,
            SourceAccessConfigurations=[{'Type': 'BASIC_AUTH', 'URI': replacement}])
        self.rejected_update('unsupported-starting-position-rollback', StartingPosition='LATEST')
        changed = self.update('replace-basic-auth', SourceAccessConfigurations=[{'Type': 'BASIC_AUTH', 'URI': replacement}])
        require({item['Type']: item['URI'] for item in changed['SourceAccessConfigurations']}.get('BASIC_AUTH') == replacement,
                'CFN BASIC_AUTH replacement not applied')
        omitted = self.update('omit-source-access', remove=('SourceAccessConfigurations',))
        require(omitted['SourceAccessConfigurations'] == changed['SourceAccessConfigurations'],
                'CFN source-access omission did not retain replacement credential')
        try:
            self.functions.update_event_source_mapping(UUID=self.mapping, SourceAccessConfigurations=[])
        except ClientError as error:
            require(error.response['Error']['Code'] == 'InvalidParameterValueException', str(error))
            self.observe('direct-empty-access-rejected', error.response)
        else:
            raise AssertionError('direct empty source access unexpectedly accepted')
        omitted = self.update('omit-batch-window', remove=('BatchSize', 'MaximumBatchingWindowInSeconds'))
        require(omitted['BatchSize'] == 100 and omitted['MaximumBatchingWindowInSeconds'] == 2,
                'omission must reset BatchSize=100 but retain explicit window=2')
        self.quiet('disabled rollback and omission')
        self.count(1, 'rollback-original-native-backlog-retained')
        self.update('enable-after-rollback-and-omission', Enabled=True)
        self.delivered('disabled-backlog')
        self.disable('disable-after-rollback-and-omission')
        self.count(0, 'rollback-recovery-native-ack')
        self.update('add-data-filter', FilterCriteria={'Filters': [{'Pattern': json.dumps({'data': {'probe': ['keep']}})}]})
        self.publish('filter-drop', payload=json.dumps({'probe': 'drop', 'label': 'filter-drop'}).encode())
        self.publish('filter-keep', payload=json.dumps({'probe': 'keep', 'label': 'filter-keep'}).encode())
        self.update('enable-filter', Enabled=True)
        matched = self.delivered('filter-keep')
        require([self.record_id(row) for row in self.records(matched)] == [self.sent['filter-keep']['id']],
                'filtered native record leaked into runtime invocation')
        self.disable('disable-filter')
        self.count(0, 'filtered-and-delivered-native-ack')
        self.quiet('filtered native message')
        removed = self.update('omit-filter-clears', remove=('FilterCriteria',))
        require(not removed.get('FilterCriteria', {}).get('Filters'), 'filter omission retained criteria')
        self.publish('removed-filter-delivers-drop', payload=json.dumps({'probe': 'drop', 'label': 'removed-filter'}).encode())
        self.update('enable-after-filter-removal', Enabled=True)
        self.delivered('removed-filter-delivers-drop')
        self.disable('disable-controls-final')
        self.count(0, 'removed-filter-native-ack')
        untouched = self.native('consume', queue='owned.other')
        record = untouched if self.args.engine == 'RABBITMQ' else untouched['message']
        require(untouched['present'] and record['message_id'] == self.sent['unchanged-other-queue']['id']
                and record['body'] == self.sent['unchanged-other-queue']['body'], 'queue rollback consumed independent destination')
        self.observe('immutable-queue-other-destination-retained', untouched)

    def reintroduce_access(self):
        replacement = self.secrets.create_secret(Name=self.prefix + '-retained',
            SecretString=json.dumps({'username': self.username, 'password': self.password}))['ARN']
        self.extra_secrets.append(replacement)
        self.update('access-reintroduction-rotate', SourceAccessConfigurations=[{'Type': 'BASIC_AUTH', 'URI': replacement}])
        self.update('access-reintroduction-omit', remove=('SourceAccessConfigurations',))
        row = self.update('access-reintroduction-original', SourceAccessConfigurations=[{'Type': 'BASIC_AUTH', 'URI': self.secret}])
        require({item['Type']: item['URI'] for item in row['SourceAccessConfigurations']}.get('BASIC_AUTH') == replacement,
                'native provider reintroduction must retain prior live secret after property omission')
        qualified = self.functions.get_function_configuration(FunctionName=self.function)['FunctionArn'] + ':' + self.version
        target = self.update('qualified-target-after-access-reintroduction', FunctionName=qualified)
        require(target['SourceAccessConfigurations'] == row['SourceAccessConfigurations'],
                'unrelated qualified target update replayed unchanged template access')
        enabled = self.update('enable-after-access-reintroduction', Enabled=True)
        require(enabled['SourceAccessConfigurations'] == row['SourceAccessConfigurations'],
                'unrelated Enabled update replayed unchanged template access')
        delivered = self.delivered('disabled-backlog')
        self.disable('disable-after-access-reintroduction')
        require(self.functions.get_event_source_mapping(UUID=self.mapping)['SourceAccessConfigurations'] == row['SourceAccessConfigurations'],
                'unrelated disable update changed retained live access')
        self.count(0, 'retained-access-native-ack')
        self.observe('reintroduced-template-access-is-not-live-access', {'template_access': self.properties['SourceAccessConfigurations'],
            'live_access': row['SourceAccessConfigurations'], 'actual_delivery': delivered})

    def explicit_host(self):
        require(self.args.engine == 'ACTIVEMQ', 'explicit default-host rejection targets ActiveMQ')
        self.native('declare', queue='owned.invalid-host')
        request = {'FunctionName': self.alias, 'EventSourceArn': self.broker_arn, 'Queues': ['owned.invalid-host'],
            'Enabled': False, 'BatchSize': 1, 'SourceAccessConfigurations': [
                {'Type': 'BASIC_AUTH', 'URI': self.secret}, {'Type': 'VIRTUAL_HOST', 'URI': '/'}]}
        try:
            admitted = self.functions.create_event_source_mapping(**request)
        except ClientError as error:
            require(error.response['Error']['Code'] == 'InvalidParameterValueException', str(error))
            self.observe('activemq-explicit-default-host-rejected', {'request': request, 'error': error.response})
        else:
            self.extra_mappings.append(admitted['UUID'])
            self.observe('activemq-explicit-default-host-unexpectedly-admitted', {'request': request, 'mapping': admitted})
            raise AssertionError('ActiveMQ admitted explicit VIRTUAL_HOST / contrary to measured native API')
        self.update('enable-after-rejected-host-create', Enabled=True)
        self.delivered('disabled-backlog')
        self.disable('disable-after-rejected-host-create')
        self.count(0, 'rejected-host-no-side-effect-native-ack')

    def missing_queue(self):
        self.observe('missing-queue-disabled-admission', self.functions.get_event_source_mapping(UUID=self.mapping))
        self.publish('late-native-queue')
        self.update('enable-late-native-queue', Enabled=True)
        self.delivered('late-native-queue')
        self.disable('disable-late-queue')
        self.count(0, 'late-queue-native-ack')

    def late_host(self):
        require(self.args.engine == 'RABBITMQ', 'late vhost admission targets RabbitMQ')
        self.observe('disabled-mapping-before-native-host-exists', self.functions.get_event_source_mapping(UUID=self.mapping))
        self.create_virtual_host()
        self.publish('late-host-default-independent', virtual_host='/')
        self.publish('late-custom-host-payload')
        self.quiet('late-created custom host mapping still disabled')
        self.direct_enabled('direct-enable-late-custom-host', True)
        self.delivered('late-custom-host-payload')
        self.direct_enabled('direct-disable-late-custom-host', False)
        self.count(0, 'late-custom-host-native-ack')
        untouched = self.native('consume', virtual_host='/')
        require(untouched['present'] and untouched['message_id'] == self.sent['late-host-default-independent']['id']
                and untouched['body'] == self.sent['late-host-default-independent']['body'],
                'late host admission rebound to independent default vhost')
        self.observe('late-host-default-vhost-independent-consumption', untouched)

    def default_host(self):
        require(self.args.engine == 'RABBITMQ', 'explicit default-host projection targets RabbitMQ')
        created = self.functions.get_event_source_mapping(UUID=self.mapping)
        expected = [{'Type': 'BASIC_AUTH', 'URI': self.secret}, {'Type': 'VIRTUAL_HOST', 'URI': '/'}]
        expected_access = {item['Type']: item['URI'] for item in expected}
        require({item['Type']: item['URI'] for item in created['SourceAccessConfigurations']} == expected_access,
                'explicit default VIRTUAL_HOST / was omitted from mapping output')
        self.observe('explicit-default-host-projection', created)
        removed = self.update('remove-explicit-host-retains-live-host', SourceAccessConfigurations=[{'Type': 'BASIC_AUTH', 'URI': self.secret}])
        require({item['Type']: item['URI'] for item in removed['SourceAccessConfigurations']} == expected_access,
                'omitting VIRTUAL_HOST removed its live configuration')
        self.rejected_update('readding-explicit-host-rollback', SourceAccessConfigurations=expected)
        self.rejected_update('changing-explicit-host-rollback', SourceAccessConfigurations=[
            {'Type': 'BASIC_AUTH', 'URI': self.secret}, {'Type': 'VIRTUAL_HOST', 'URI': 'owned.other'}])
        self.quiet('default-host provider rollback')
        self.count(1, 'default-host-rollback-native-backlog')
        self.stop()
        self.start()
        self.description = self.wait(self.broker_ready, 'retained explicit default-host broker')
        retained = self.wait(lambda: self.mapping_state('Disabled'), 'retained explicit default-host mapping')
        require({item['Type']: item['URI'] for item in retained['SourceAccessConfigurations']} == expected_access,
                'explicit default-host projection was lost across SQLite restart')
        self.observe('explicit-default-host-retained-restart', retained)
        self.count(1, 'explicit-default-host-restart-native-backlog')
        self.update('enable-retained-explicit-default-host', Enabled=True)
        self.delivered('disabled-backlog')
        self.disable('disable-retained-explicit-default-host')
        self.count(0, 'default-host-native-ack')

    def direct_enabled(self, label, enabled):
        row = self.functions.update_event_source_mapping(UUID=self.mapping, Enabled=enabled)
        self.wait(lambda: self.mapping_state('Enabled' if enabled else 'Disabled'), label)
        self.observe(label, row)

    def custom_host(self):
        self.quiet('custom host disabled CFN deployment')
        self.count(1, 'custom-host-disabled-native-backlog')
        self.direct_enabled('direct-enable-custom-host', True)
        self.delivered('disabled-backlog')
        self.direct_enabled('direct-disable-custom-host', False)
        self.count(0, 'custom-host-initial-native-ack')
        replacement = self.secrets.create_secret(Name=self.prefix + '-rotated',
            SecretString=json.dumps({'username': self.username, 'password': self.password}))['ARN']
        self.extra_secrets.append(replacement)
        rotated = self.functions.update_event_source_mapping(UUID=self.mapping,
            SourceAccessConfigurations=[{'Type': 'BASIC_AUTH', 'URI': replacement}])
        self.wait(lambda: self.mapping_state('Disabled'), 'direct BASIC_AUTH-only rotation')
        def current():
            row = self.functions.get_event_source_mapping(UUID=self.mapping)
            access = {item['Type']: item['URI'] for item in row['SourceAccessConfigurations']}
            require(access == {'BASIC_AUTH': replacement, 'VIRTUAL_HOST': self.virtual_host},
                    'BASIC_AUTH-only update reset or changed custom virtual host')
            return row
        self.observe('direct-basic-auth-only-preserves-host', {'update': rotated, 'read': current()})
        try:
            self.functions.update_event_source_mapping(UUID=self.mapping,
                SourceAccessConfigurations=[{'Type': 'VIRTUAL_HOST', 'URI': self.virtual_host}])
        except ClientError as error:
            require(error.response['Error']['Code'] == 'InvalidParameterValueException', str(error))
            self.observe('direct-unchanged-host-update-rejected', error.response)
        else:
            raise AssertionError('direct Update accepted forbidden VIRTUAL_HOST type')
        current()
        self.publish('custom-after-secret-rotation')
        self.direct_enabled('direct-enable-rotated-custom-host', True)
        self.delivered('custom-after-secret-rotation')
        self.direct_enabled('direct-disable-rotated-custom-host', False)
        self.count(0, 'custom-host-rotated-native-ack')
        self.stop()
        self.publish('custom-host-controller-stopped')
        self.start()
        self.description = self.wait(self.broker_ready, 'retained custom-vhost native broker')
        self.wait(lambda: self.mapping_state('Disabled'), 'retained disabled custom-vhost mapping')
        current()
        self.quiet('custom-vhost disabled retained restart')
        self.count(1, 'custom-host-retained-native-backlog')
        default = self.native('inspect', virtual_host='/')
        require(default['messages'] == 1, 'custom-host mapping consumed same-name default-host queue')
        self.observe('default-host-independent-retained', default)
        self.direct_enabled('direct-enable-custom-host-after-restart', True)
        self.delivered('custom-host-controller-stopped')
        self.direct_enabled('direct-disable-custom-host-after-restart', False)
        self.count(0, 'custom-host-restart-native-ack')
        independent = self.native('consume', virtual_host='/')
        require(independent['present'] and independent['message_id'] == self.sent['default-host-independent']['id']
                and independent['body'] == self.sent['default-host-independent']['body'],
                'custom host isolation lost independent default-host identity or complete bytes')
        self.observe('custom-host-isolation-independent-consumption', independent)

    def source_fence(self):
        self.update('enable-before-source-recreation', Enabled=True)
        self.delivered('disabled-backlog')
        previous = {'broker_id': self.broker, 'broker_arn': self.broker_arn, 'mapping_uuid': self.mapping}
        self.mq.delete_broker(BrokerId=self.broker)
        self.wait(lambda: self.absent(self.mq, 'describe_broker', 'NotFoundException', BrokerId=self.broker),
                  'old exact-owned source deletion')
        self.broker = None
        if self.configuration:
            self.mq.delete_configuration(ConfigurationId=self.configuration)
            self.configuration = None
        created = self.mq.create_broker(BrokerName=self.prefix, EngineType=self.args.engine,
            EngineVersion='3.13.7' if self.args.engine == 'RABBITMQ' else '5.18',
            DeploymentMode='SINGLE_INSTANCE', HostInstanceType='mq.t3.micro', PubliclyAccessible=True,
            AutoMinorVersionUpgrade=False, Users=[{'Username': self.username, 'Password': self.password}])
        self.broker, self.broker_arn = created['BrokerId'], created['BrokerArn']
        require(self.broker != previous['broker_id'] and self.broker_arn != previous['broker_arn'],
                'same broker name reused native incarnation')
        self.description = self.wait(self.broker_ready, 'same-name independently recreated native source', 240)
        self.configuration = self.description.get('Configurations', {}).get('Current', {}).get('Id')
        self.publish('recreated-native-source')
        def fenced():
            row = self.functions.get_event_source_mapping(UUID=self.mapping)
            require(row['EventSourceArn'] == previous['broker_arn'], 'old mapping silently rebound to same-name broker')
            return row if row.get('LastProcessingResult', '').startswith('PROBLEM:') else None
        mapping = self.wait(fenced, 'old source mapping fence')
        self.quiet('old mapping against same-name recreated broker')
        self.count(1, 'new-incarnation-native-message-retained')
        consumed = self.native('consume')
        record = consumed if self.args.engine == 'RABBITMQ' else consumed['message']
        require(consumed['present'] and record['message_id'] == self.sent['recreated-native-source']['id']
                and record['body'] == self.sent['recreated-native-source']['body'], 'recreated source bytes changed')
        self.observe('source-incarnation-fence', {'previous': previous, 'new_broker': self.description,
            'old_mapping': mapping, 'independent_native_consumption': consumed,
            'scope': 'Different broker IDs/ARNs, not a CFN queue namespace update or claim that a removed Rabbit queue is recreated.'})

    def delete_stack(self):
        identifier = self.mapping
        self.cfn.delete_stack(StackName=self.stack)
        self.wait(lambda: self.absent(self.cfn, 'describe_stacks', 'ValidationError', StackName=self.stack), 'stack deletion')
        self.stack = None
        if identifier:
            self.wait(lambda: self.absent(self.functions, 'get_event_source_mapping', 'ResourceNotFoundException', UUID=identifier),
                      'mapping deletion')
        self.mapping = None

    def deletion_proof(self):
        self.publish('independent-after-stack', queue='owned.independent')
        self.publish('source-after-stack')
        self.delete_stack()
        broker = self.mq.describe_broker(BrokerId=self.broker)
        function = self.functions.get_function_configuration(FunctionName=self.function)
        self.quiet('deleted mapping')
        source = self.native('consume')
        independent = self.native('consume', queue='owned.independent')
        for label, row in [('source-after-stack', source), ('independent-after-stack', independent)]:
            require(row['present'], 'stack deletion removed independently owned native message')
            record = row if self.args.engine == 'RABBITMQ' else row['message']
            require(record['message_id'] == self.sent[label]['id'] and record['body'] == self.sent[label]['body'],
                    'stack deletion changed native message identity or full bytes')
        self.observe('deletion-preserves-independent-resources', {'broker': broker, 'function': function,
            'source_message': source, 'independent_message': independent})

    def cleanup(self):
        if self.process is None:
            self.start()
        def action(label, fn):
            try:
                fn()
                self.report['cleanup'][label] = 'ok'
            except Exception as error:
                self.report['cleanup'][label] = repr(error)
        if self.stack:
            action('stack', self.delete_stack)
        for identifier in self.extra_mappings:
            action('extra-mapping-' + identifier,
                   lambda identifier=identifier: self.functions.delete_event_source_mapping(UUID=identifier))
            action('extra-mapping-absent-' + identifier,
                   lambda identifier=identifier: self.wait(lambda: self.absent(self.functions,
                       'get_event_source_mapping', 'ResourceNotFoundException', UUID=identifier), 'extra mapping deletion'))
        if self.function:
            action('function', lambda: self.functions.delete_function(FunctionName=self.function))
            action('logs', lambda: self.logs.delete_log_group(logGroupName='/aws/lambda/' + self.function)
                if not self.absent(self.logs, 'describe_log_streams', 'ResourceNotFoundException', logGroupName='/aws/lambda/' + self.function) else None)
        if self.secret:
            action('secret', lambda: self.secrets.delete_secret(SecretId=self.secret, ForceDeleteWithoutRecovery=True))
        for secret in self.extra_secrets:
            action('extra-secret-' + secret.rsplit(':', 1)[-1],
                   lambda secret=secret: self.secrets.delete_secret(SecretId=secret, ForceDeleteWithoutRecovery=True))
        for name in list(self.policies):
            action('policy-' + name, lambda name=name: self.remove_policy(name))
        if self.role:
            action('role', lambda: self.iam.delete_role(RoleName=self.role))
        if self.queue:
            action('sqs', lambda: self.sqs.delete_queue(QueueUrl=self.queue))
        if self.broker:
            action('broker', lambda: self.mq.delete_broker(BrokerId=self.broker))
            action('broker-absent', lambda: self.wait(lambda: self.absent(self.mq, 'describe_broker', 'NotFoundException', BrokerId=self.broker), 'native broker deletion'))
        if self.configuration:
            action('configuration', lambda: self.mq.delete_configuration(ConfigurationId=self.configuration))
        action('controller', self.stop)
        namespace_hash = hashlib.sha256(str(self.database).encode()).hexdigest()[:24]
        for kind in ('mq', 'lambda'):
            key = 'stackd.mq.namespace' if kind == 'mq' else 'io.stackd.lambda.instance'
            label = f'{key}=stackd-{kind}-{namespace_hash}'
            for resource, command in [('containers', ['docker', 'ps', '-aq']),
                                      ('volumes', ['docker', 'volume', 'ls', '-q'])]:
                result = subprocess.run([*command, '--filter', 'label=' + label],
                    capture_output=True, text=True, timeout=30)
                observed = {'exit_status': result.returncode, 'remaining': result.stdout.split(), 'owner_filter': label}
                self.report['cleanup'][kind + '-' + resource] = observed
                if result.returncode or result.stdout.strip():
                    observed['error'] = result.stderr or 'owned native resources remain'

    def run(self):
        try:
            self.setup()
            self.deploy()
            if self.args.scenario == 'core':
                self.core()
            elif self.args.scenario == 'settings':
                self.settings()
            elif self.args.scenario == 'missing-queue':
                self.missing_queue()
            elif self.args.scenario == 'source-fence':
                self.source_fence()
            elif self.args.scenario == 'custom-host':
                self.custom_host()
            elif self.args.scenario == 'defaults':
                self.defaults()
            elif self.args.scenario == 'controls':
                self.controls()
            elif self.args.scenario == 'explicit-host':
                self.explicit_host()
            elif self.args.scenario == 'reintroduce-access':
                self.reintroduce_access()
            elif self.args.scenario == 'late-host':
                self.late_host()
            elif self.args.scenario == 'default-host':
                self.default_host()
            self.deletion_proof()
            self.report['result'] = 'PASS'
        except BaseException as error:
            self.report['result'] = 'FAIL'
            self.report['error'] = repr(error)
            self.report['traceback'] = traceback.format_exc()
            if self.stack and self.process and self.process.poll() is None:
                try:
                    self.report['failure_stack_events'] = self.cfn.describe_stack_events(StackName=self.stack)['StackEvents']
                except Exception as diagnostic:
                    self.report['diagnostic_error'] = repr(diagnostic)
            raise
        finally:
            try:
                self.cleanup()
                if not all(value == 'ok' if isinstance(value, str) else not value.get('error')
                           for value in self.report['cleanup'].values()):
                    self.report['result'] = 'FAIL'
                    self.report['cleanup_error'] = 'exact-owned cleanup failed'
            except BaseException as error:
                self.report['result'] = 'FAIL'
                self.report['cleanup_error'] = repr(error)
                raise
            finally:
                self.save()
        require('cleanup_error' not in self.report, self.report.get('cleanup_error', ''))
        print(json.dumps({'report': self.args.report, 'result': self.report['result'], 'cleanup': self.report['cleanup']}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='bin/stackd')
    parser.add_argument('--sdk-helper', default='bin/cloudformation_lambda_mq_smoke')
    parser.add_argument('--telemetry-directory', default='bin')
    parser.add_argument('--engine', required=True, choices=['RABBITMQ', 'ACTIVEMQ'])
    parser.add_argument('--scenario', default='core', choices=['core', 'settings', 'missing-queue', 'source-fence', 'custom-host', 'defaults', 'controls', 'explicit-host', 'reintroduce-access', 'late-host', 'default-host'])
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--report', required=True)
    Proof(parser.parse_args()).run()


if __name__ == '__main__':
    main()
